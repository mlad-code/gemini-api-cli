// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package envruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSingleflightDoAndDoChan(t *testing.T) {
	var sf Singleflight
	var runs atomic.Int32
	gate := make(chan struct{})

	var wg sync.WaitGroup
	var sharedCount atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			val, shared, err := sf.Do("k1", func() (any, error) {
				runs.Add(1)
				<-gate
				return "v1", nil
			})
			if err != nil || val != "v1" {
				t.Errorf("sf.Do() = (%v, %v), want (\"v1\", nil)", val, err)
			}
			if shared {
				sharedCount.Add(1)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()

	if runs.Load() != 1 || sharedCount.Load() != 4 {
		t.Errorf("sf.Do runs=%d sharedCount=%d, want runs=1 sharedCount=4", runs.Load(), sharedCount.Load())
	}

	// Sequential call after completion is unshared.
	val, shared, err := sf.Do("k1", func() (any, error) { return "v2", nil })
	if err != nil || val != "v2" || shared {
		t.Errorf("sequential sf.Do() = (%v, %v, %v), want (\"v2\", false, nil)", val, shared, err)
	}

	// DoChan deduplication & error propagation.
	gate2 := make(chan struct{})
	boom := errors.New("provision boom")
	ch1 := sf.DoChan("k2", func() (any, error) {
		<-gate2
		return nil, boom
	})
	ch2 := sf.DoChan("k2", func() (any, error) {
		return "unexpected", nil
	})
	close(gate2)
	r1, r2 := <-ch1, <-ch2
	if !errors.Is(r1.Err, boom) || !errors.Is(r2.Err, boom) || !r1.Shared || !r2.Shared {
		t.Errorf("DoChan results = (%+v, %+v), want shared boom errors", r1, r2)
	}
}

func TestShellCommandProvisionerAndStatelessPoller(t *testing.T) {
	if _, args := ResolveProvisionShell("linux", "echo ok"); len(args) != 2 {
		t.Errorf("ResolveProvisionShell(linux) args = %v", args)
	}
	emptyProv := NewShellCommandProvisioner("")
	if err := emptyProv.ProvisionAndDispatch(t.Context(), ProvisionInput{InteractionID: "i1", EnvironmentID: "e1"}); err == nil {
		t.Error("ProvisionAndDispatch(empty cmd) = nil, want error")
	}

	outFile := filepath.Join(t.TempDir(), "stdin.json")
	t.Setenv("GEMINI_API_KEY", "secret-must-scrub")
	okProv := NewShellCommandProvisioner(`if [ -n "$GEMINI_API_KEY" ]; then exit 9; fi; cat > ` + outFile)
	if err := okProv.ProvisionAndDispatch(t.Context(), ProvisionInput{
		InteractionID:     "int_p1",
		EnvironmentID:     "env_p1",
		LeaseToken:        "tok_secret_123",
		ServerURL:         "https://generativelanguage.googleapis.com",
		EnvironmentConfig: json.RawMessage(`{"network_mode":"OFF"}`),
	}); err != nil {
		t.Fatalf("ProvisionAndDispatch(ok) failed: %v", err)
	}
	written, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile(outFile) failed: %v", err)
	}
	var gotIn ProvisionInput
	if err := json.Unmarshal(written, &gotIn); err != nil || gotIn.SchemaVersion != WorkerProvisionSchemaVersionV1 || gotIn.InteractionID != "int_p1" {
		t.Errorf("ProvisionInput stdin = (%+v, %v)", gotIn, err)
	}

	// Verify LeaseToken is redacted from stderr on failure.
	failProv := NewShellCommandProvisioner(`echo "leaked tok_secret_999" >&2; exit 2`)
	err = failProv.ProvisionAndDispatch(t.Context(), ProvisionInput{
		InteractionID: "int_f",
		EnvironmentID: "env_f",
		LeaseToken:    "tok_secret_999",
	})
	if err == nil || strings.Contains(err.Error(), "tok_secret_999") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Errorf("ProvisionAndDispatch(stderr redaction) = %v, want [REDACTED] without tok_secret_999", err)
	}

	// StatelessPoller: handoff heartbeat ShouldCancel aborts slow ProvisionFunc, and recordDispatchFailure evicts >10m entries.
	var hbCalls atomic.Int32
	provisionAborted := make(chan error, 1)
	var polledOnce atomic.Bool
	pollerCtx, cancelPoller := context.WithCancel(t.Context())
	defer cancelPoller()

	sp := NewStatelessPoller(StatelessPollerConfig{
		Client: &fakeEnvClient{
			leaseFn: func(_ context.Context, _ *LeaseInteractionsRequest) (*LeaseInteractionsResult, error) {
				if !polledOnce.Swap(true) {
					return &LeaseInteractionsResult{
						Leases: []LeasedInteraction{{
							InteractionID: "int_cancel_me",
							EnvironmentID: "env_c",
							LeaseToken:    "tok_c",
						}},
					}, nil
				}
				return &LeaseInteractionsResult{}, nil
			},
		},
		Heartbeat: func(context.Context, string, string, string, string) (*HeartbeatResult, error) {
			if hbCalls.Add(1) >= 2 {
				return &HeartbeatResult{ShouldCancel: true}, nil
			}
			return &HeartbeatResult{Renewed: true}, nil
		},
		ProvisionFunc: func(ctx context.Context, _ ProvisionInput) error {
			<-ctx.Done()
			provisionAborted <- ctx.Err()
			return ctx.Err()
		},
		PollInterval:             15 * time.Millisecond,
		HandoffHeartbeatInterval: 15 * time.Millisecond,
		ProvisionTimeout:         5 * time.Second,
		Logger:                   log.New(io.Discard, "", 0),
	})

	// Seed an expired failure entry (>10m old) to verify recordDispatchFailure evicts it.
	sp.failures["stale_int"] = &statelessFailureState{
		consecutive: 1,
		cooldownEnd: time.Now().Add(-11 * time.Minute),
	}

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- sp.Run(pollerCtx)
	}()

	select {
	case abortErr := <-provisionAborted:
		if !errors.Is(abortErr, context.Canceled) {
			t.Errorf("ProvisionFunc abort err = %v, want context.Canceled", abortErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Heartbeat ShouldCancel to abort ProvisionFunc")
	}
	cancelPoller()
	_ = <-runErrCh

	sp.mu.Lock()
	_, staleStillPresent := sp.failures["stale_int"]
	sp.mu.Unlock()
	if staleStillPresent {
		t.Error("recordDispatchFailure did not evict >10m stale failure entry")
	}
}

func TestDirectCommandProvisionerAndConfigConversion(t *testing.T) {
	if _, err := NewDirectCommandProvisioner("   ", ""); err == nil {
		t.Error("NewDirectCommandProvisioner(empty) = nil, want error")
	}

	dir := t.TempDir()
	provScript := filepath.Join(dir, "prov.sh")
	suspScript := filepath.Join(dir, "susp.sh")
	suspLog := filepath.Join(dir, "suspended.json")

	if err := os.WriteFile(provScript, []byte("#!/bin/sh\ncat >/dev/null\necho '{\"uri\":\"http://127.0.0.1:9001\",\"worker_id\":\"w-99\",\"headers\":{\"X-Auth\":\"ok\"}}'\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(provScript) failed: %v", err)
	}
	if err := os.WriteFile(suspScript, []byte("#!/bin/sh\ncat > "+suspLog+"\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(suspScript) failed: %v", err)
	}

	dcp, err := NewDirectCommandProvisioner(provScript, suspScript)
	if err != nil {
		t.Fatalf("NewDirectCommandProvisioner() failed: %v", err)
	}
	if _, err := dcp.ProvisionWorker(t.Context(), WorkerProvisionRequest{}); err == nil {
		t.Error("ProvisionWorker(empty EnvironmentID) = nil, want error")
	}
	resp, err := dcp.ProvisionWorker(t.Context(), WorkerProvisionRequest{
		EnvironmentID: "env_d1",
		InteractionID: "int_d1",
	})
	if err != nil || resp.URI != "http://127.0.0.1:9001" || resp.WorkerID != "w-99" || resp.SchemaVersion != WorkerProvisionSchemaVersionV1 {
		t.Fatalf("ProvisionWorker() = (%+v, %v)", resp, err)
	}

	if err := dcp.SuspendWorker(t.Context(), WorkerSuspendRequest{}); err == nil {
		t.Error("SuspendWorker(empty ids) = nil, want error")
	}
	if err := dcp.SuspendWorker(t.Context(), WorkerSuspendRequest{
		EnvironmentID: "env_d1",
		WorkerID:      "w-99",
		IdleDuration:  "65s",
	}); err != nil {
		t.Fatalf("SuspendWorker() failed: %v", err)
	}
	if rawSusp, err := os.ReadFile(suspLog); err != nil || !strings.Contains(string(rawSusp), `"w-99"`) {
		t.Errorf("suspended.json = (%s, %v)", rawSusp, err)
	}

	if ConvertToProvisionEnvironmentConfig(nil) != nil {
		t.Error("ConvertToProvisionEnvironmentConfig(nil) != nil")
	}
	if ConvertToProvisionEnvironmentConfig(&EnvironmentConfig{}) != nil {
		t.Error("ConvertToProvisionEnvironmentConfig(empty) != nil")
	}
	parsed := ParseEnvironmentConfig(json.RawMessage(`{
		"network_mode": "ALLOWLIST",
		"allowlist_domains": ["a.example.com"],
		"network_allowlist": [{"domain": "b.example.com"}, {"domain": "bad.example.com", "mode": "deny"}],
		"network_denylist": ["evil.example.com"],
		"env": {"K1": "V1"},
		"env_vars": {"K2": {"value": "V2"}},
		"sources": [{"type": "inline", "target": "main.py", "content": "print(1)"}]
	}`))
	conv := ConvertToProvisionEnvironmentConfig(parsed)
	if conv == nil || len(conv.AllowlistDomains) != 2 || len(conv.DenylistDomains) != 2 || conv.Env["K2"] != "V2" || len(conv.Sources) != 1 {
		t.Errorf("ConvertToProvisionEnvironmentConfig() = %+v", conv)
	}
}

type fakeWorkerProvisioner struct {
	mu          sync.Mutex
	provisions  int
	suspensions []WorkerSuspendRequest
	provFn      func(req WorkerProvisionRequest) (*WorkerProvisionResponse, error)
}

func (f *fakeWorkerProvisioner) ProvisionWorker(_ context.Context, req WorkerProvisionRequest) (*WorkerProvisionResponse, error) {
	f.mu.Lock()
	f.provisions++
	fn := f.provFn
	f.mu.Unlock()
	if fn != nil {
		return fn(req)
	}
	return &WorkerProvisionResponse{
		SchemaVersion: WorkerProvisionSchemaVersionV1,
		URI:           "worker://" + req.EnvironmentID,
		WorkerID:      "wk-" + req.EnvironmentID,
		Headers:       map[string]string{"X-Worker": "1"},
	}, nil
}

func (f *fakeWorkerProvisioner) SuspendWorker(_ context.Context, req WorkerSuspendRequest) error {
	f.mu.Lock()
	f.suspensions = append(f.suspensions, req)
	f.mu.Unlock()
	return nil
}

type fakeWorkerRPCClient struct {
	startFn func(req *StartWorkRequest, headers map[string]string) (*StartWorkResponse, error)
	idleFn  func() (*IdleStatus, error)
	closed  atomic.Bool
}

func (f *fakeWorkerRPCClient) StartWork(_ context.Context, req *StartWorkRequest, headers map[string]string) (*StartWorkResponse, error) {
	return f.startFn(req, headers)
}

func (f *fakeWorkerRPCClient) GetIdleStatus(_ context.Context, _ map[string]string) (*IdleStatus, error) {
	if f.idleFn != nil {
		return f.idleFn()
	}
	return &IdleStatus{Running: false, IdleDuration: 2 * time.Minute}, nil
}

func (f *fakeWorkerRPCClient) Close() error {
	f.closed.Store(true)
	return nil
}

func TestTier2PollerSingleflightPoisonPillSweepAndDrain(t *testing.T) {
	if _, err := NewTier2Poller(Tier2PollerConfig{}); err == nil {
		t.Error("NewTier2Poller(missing Client) = nil, want error")
	}
	dummyClient := &fakeEnvClient{leaseFn: func(context.Context, *LeaseInteractionsRequest) (*LeaseInteractionsResult, error) {
		return &LeaseInteractionsResult{}, nil
	}}
	if _, err := NewTier2Poller(Tier2PollerConfig{Client: dummyClient}); err == nil {
		t.Error("NewTier2Poller(missing Provisioner) = nil, want error")
	}
	if _, err := NewTier2Poller(Tier2PollerConfig{Client: dummyClient, Provisioner: &fakeWorkerProvisioner{}}); err == nil {
		t.Error("NewTier2Poller(missing DialWorker) = nil, want error")
	}

	nowMu := sync.Mutex{}
	fakeNow := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	getNow := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return fakeNow
	}
	advanceNow := func(d time.Duration) {
		nowMu.Lock()
		fakeNow = fakeNow.Add(d)
		nowMu.Unlock()
	}

	prov := &fakeWorkerProvisioner{}
	var dials atomic.Int32
	var accepted atomic.Int32
	rpcConn := &fakeWorkerRPCClient{
		startFn: func(req *StartWorkRequest, headers map[string]string) (*StartWorkResponse, error) {
			if req.InteractionID == "int_poison" {
				return nil, errors.New("worker rejected start_work")
			}
			if headers["X-Worker"] != "1" {
				return nil, errors.New("missing worker header")
			}
			accepted.Add(1)
			return &StartWorkResponse{Status: WorkerStatusAccepted}, nil
		},
	}

	var pollStep atomic.Int32
	client := &fakeEnvClient{
		leaseFn: func(_ context.Context, _ *LeaseInteractionsRequest) (*LeaseInteractionsResult, error) {
			switch pollStep.Add(1) {
			case 1:
				// Two concurrent interactions in the SAME environment + one poison interaction!
				return &LeaseInteractionsResult{
					Leases: []LeasedInteraction{
						{InteractionID: "int_ok_1", EnvironmentID: "env_shared", LeaseToken: "tok_1"},
						{InteractionID: "int_ok_2", EnvironmentID: "env_shared", LeaseToken: "tok_2"},
						{InteractionID: "int_poison", EnvironmentID: "env_poison", LeaseToken: "tok_bad"},
					},
					PollBackoff: 20 * time.Millisecond,
				}, nil
			default:
				return &LeaseInteractionsResult{PollBackoff: 20 * time.Millisecond}, nil
			}
		},
	}

	tp, err := NewTier2Poller(Tier2PollerConfig{
		Client:              client,
		Provisioner:         prov,
		DialWorker:          func(string) (WorkerRPCClient, error) { dials.Add(1); return rpcConn, nil },
		ControlPlaneURL:     "https://generativelanguage.googleapis.com",
		GRPCTarget:          "generativelanguage.googleapis.com:443",
		MaxHandoffRetries:   2,
		HandoffRetryBackoff: 5 * time.Millisecond,
		PoisonCooldown:      30 * time.Second,
		IdleTimeout:         60 * time.Second,
		ResumeGracePeriod:   3 * time.Second,
		PollInterval:        20 * time.Millisecond,
		SweepInterval:       1 * time.Hour,
		DrainTimeout:        2 * time.Second,
		Now:                 getNow,
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewTier2Poller() failed: %v", err)
	}

	if _, err := tp.PollOnce(t.Context()); err != nil {
		t.Fatalf("PollOnce() failed: %v", err)
	}
	tp.WaitHandoffs()

	if accepted.Load() != 2 {
		t.Errorf("accepted = %d, want 2", accepted.Load())
	}
	if tp.InFlightCount() != 0 || len(tp.HandoffLeases()) != 0 {
		t.Errorf("InFlightCount=%d HandoffLeases=%v, want 0", tp.InFlightCount(), tp.HandoffLeases())
	}
	if !tp.IsDeadLettered("int_poison") || !tp.InCooldown("int_poison") || tp.FailureCount("int_poison") != 2 {
		t.Errorf("int_poison state: dead=%v cooldown=%v failures=%d", tp.IsDeadLettered("int_poison"), tp.InCooldown("int_poison"), tp.FailureCount("int_poison"))
	}

	// Within ResumeGracePeriod (0s elapsed < 3s), SweepOnce must NOT suspend active workers.
	if err := tp.SweepOnce(t.Context()); err != nil {
		t.Fatalf("SweepOnce(grace period) failed: %v", err)
	}
	prov.mu.Lock()
	if len(prov.suspensions) != 0 {
		t.Errorf("suspensions during grace period = %v, want empty", prov.suspensions)
	}
	prov.mu.Unlock()

	// Advance clock past ResumeGracePeriod & PoisonCooldown -> SweepOnce suspends idle workers!
	advanceNow(40 * time.Second)
	if tp.InCooldown("int_poison") {
		t.Error("InCooldown(int_poison) = true after 40s, want false")
	}
	if err := tp.SweepOnce(t.Context()); err != nil {
		t.Fatalf("SweepOnce(after grace) failed: %v", err)
	}
	prov.mu.Lock()
	suspCount := len(prov.suspensions)
	prov.mu.Unlock()
	if suspCount == 0 {
		t.Error("SweepOnce(idle) did not suspend any provisioned worker")
	}

	// Run() + graceful shutdown & Close().
	runCtx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- tp.Run(runCtx)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Errorf("tp.Run() = %v, want nil", err)
	}
	if !rpcConn.closed.Load() {
		t.Error("expected Close() to close cached WorkerRPCClient")
	}
}
