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
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func startH2CServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: handler, Protocols: &protos}
	go func() {
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return "http://" + ln.Addr().String()
}

type failingWriter struct {
	err error
}

func (f failingWriter) Write([]byte) (int, error) {
	return 0, f.err
}

func TestIdentifiersSecretsRedactorAndParsers(t *testing.T) {
	for _, valid := range []string{"int_123", "env-abc.1:2"} {
		if !IsValidIdentifier(valid) {
			t.Errorf("IsValidIdentifier(%q) = false, want true", valid)
		}
	}
	for _, invalid := range []string{"", ".", "..", "a..b", "a/b", "bad id"} {
		if IsValidIdentifier(invalid) {
			t.Errorf("IsValidIdentifier(%q) = true, want false", invalid)
		}
	}

	if err := ValidateHeaderSecret("--key", "clean_secret_123"); err != nil {
		t.Errorf("ValidateHeaderSecret(clean) = %v, want nil", err)
	}
	for _, bad := range []string{"a\nb", "a\rb", "a\x00b", "a\x7fb"} {
		if err := ValidateHeaderSecret("--key", bad); err == nil {
			t.Errorf("ValidateHeaderSecret(%q) = nil, want error", bad)
		}
	}

	if id := DefaultRuntimeID("worker"); !strings.HasPrefix(id, "worker-") {
		t.Errorf("DefaultRuntimeID(worker) = %q, want prefix worker-", id)
	}

	te1 := &TransportError{Op: "LeaseInteractions", StatusCode: 403, Body: " forbidden "}
	if got := te1.Error(); got != "LeaseInteractions: HTTP 403: forbidden" {
		t.Errorf("te1.Error() = %q", got)
	}
	te2 := &TransportError{StatusCode: 503}
	if got := te2.Error(); !strings.Contains(got, "HTTP 503") {
		t.Errorf("te2.Error() = %q", got)
	}
	te3 := &TransportError{Message: "stream closed"}
	if got := te3.Error(); got != "stream closed" {
		t.Errorf("te3.Error() = %q", got)
	}

	var redBuf bytes.Buffer
	red := NewLeaseTokenRedactor(&redBuf)
	sample := `{"leases":[{"lease_token":"tok_\"secret\"_1"},{"lease_token": "tok_2"}]}`
	if n, err := red.Write([]byte(sample)); err != nil || n != len(sample) {
		t.Fatalf("redactor.Write() = (%d, %v)", n, err)
	}
	if strings.Contains(redBuf.String(), "tok_") || strings.Count(redBuf.String(), "[REDACTED]") != 2 {
		t.Errorf("redacted output = %q", redBuf.String())
	}
	wErr := errors.New("disk full")
	if _, err := NewLeaseTokenRedactor(failingWriter{err: wErr}).Write([]byte(`{"lease_token":"x"}`)); !errors.Is(err, wErr) {
		t.Errorf("redactor write error = %v, want %v", err, wErr)
	}

	if n, err := ParseProtoInt64(json.RawMessage(`"42"`)); err != nil || n != 42 {
		t.Errorf("ParseProtoInt64(string) = (%d, %v)", n, err)
	}
	if n, err := ParseProtoInt64(json.RawMessage(`99`)); err != nil || n != 99 {
		t.Errorf("ParseProtoInt64(number) = (%d, %v)", n, err)
	}
	if n, err := ParseProtoInt64(json.RawMessage(`null`)); err != nil || n != 0 {
		t.Errorf("ParseProtoInt64(null) = (%d, %v)", n, err)
	}
	if got := ParseInt64Raw(json.RawMessage(`""`), json.RawMessage(`"17"`)); got != 17 {
		t.Errorf("ParseInt64Raw() = %d, want 17", got)
	}

	if d := ParseDurationRaw(json.RawMessage(`"3s"`), time.Second); d != 3*time.Second {
		t.Errorf("ParseDurationRaw(string) = %v, want 3s", d)
	}
	if d := ParseDurationRaw(json.RawMessage(`{"seconds":2,"nanos":500000000}`), time.Second); d != 2500*time.Millisecond {
		t.Errorf("ParseDurationRaw(obj) = %v, want 2.5s", d)
	}
	if d := ParseDurationRaw(json.RawMessage(`1.5`), time.Second); d != 1500*time.Millisecond {
		t.Errorf("ParseDurationRaw(float) = %v, want 1.5s", d)
	}
	if d := ParseDurationRaw(json.RawMessage(`"bad"`), 4*time.Second); d != 4*time.Second {
		t.Errorf("ParseDurationRaw(fallback) = %v, want 4s", d)
	}

	// LeasedInteraction JSON marshal/unmarshal & ParseEnvironmentConfig variants.
	rawLease := `{
		"interaction_id": "int_1",
		"environment_id": "env_1",
		"lease_token": "tok_1",
		"lease_generation": "7",
		"lease_expiration_time": "2026-10-26T12:00:00Z",
		"environment_config": {
			"network_mode": "ALLOWLIST",
			"network_allowlist": {"allowlist": [{"domain": "api.github.com"}]},
			"env": {"PLAIN": "v1"},
			"env_vars": {"CRED_KEY": {"credential": "cred_ref"}}
		}
	}`
	var lease LeasedInteraction
	if err := json.Unmarshal([]byte(rawLease), &lease); err != nil {
		t.Fatalf("json.Unmarshal(LeasedInteraction) failed: %v", err)
	}
	if lease.LeaseGeneration != 7 || lease.EnvironmentConfig == nil || len(lease.EnvironmentConfig.NetworkAllowlist) != 1 {
		t.Fatalf("parsed lease = %+v", lease)
	}
	if lease.EnvironmentConfig.Env["PLAIN"] != "v1" || lease.EnvironmentConfig.Env["CRED_KEY"] != "cred_ref" {
		t.Errorf("parsed Env = %v", lease.EnvironmentConfig.Env)
	}
	marshaled, err := json.Marshal(lease)
	if err != nil || !strings.Contains(string(marshaled), `"api.github.com"`) {
		t.Errorf("json.Marshal(LeasedInteraction) = (%s, %v)", marshaled, err)
	}

	malformedCfg := ParseEnvironmentConfig(json.RawMessage(`"not-an-object"`))
	if malformedCfg == nil || string(malformedCfg.RawJSON) != `"not-an-object"` {
		t.Errorf("ParseEnvironmentConfig(malformed) = %+v", malformedCfg)
	}
	domainCfg := ParseEnvironmentConfig(json.RawMessage(`{"network_allowlist":["example.com"]}`))
	if domainCfg == nil || len(domainCfg.NetworkAllowlist) != 1 || domainCfg.NetworkAllowlist[0].Domain != "example.com" {
		t.Errorf("ParseEnvironmentConfig(domains) = %+v", domainCfg)
	}

	// Status & retry helpers.
	for _, code := range []int{0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 99} {
		httpStatus := GRPCCodeToHTTPStatus(code)
		_ = HTTPStatusToGRPCCode(httpStatus)
	}
	if !IsNonRetryableError(&TransportError{StatusCode: http.StatusUnauthorized}) {
		t.Error("IsNonRetryableError(401) = false, want true")
	}
	if IsNonRetryableError(&TransportError{StatusCode: http.StatusServiceUnavailable}) {
		t.Error("IsNonRetryableError(503) = true, want false")
	}
	if d := RetryBackoff(2*time.Second, 20); d != 30*time.Second {
		t.Errorf("RetryBackoff(capped) = %v, want 30s", d)
	}
}

func TestHTTPClientLeaseHeartbeatPreviewAndStream(t *testing.T) {
	var heartbeatFrames atomic.Int32
	srvURL := startH2CServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1beta/environments:leaseInteractions":
			if r.Header.Get(EnvironmentKeyHeader) == "ek_403" {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.Header().Set("Content-Type", "application/json")
			if body["worker_id"] == "hb-conflict" {
				http.Error(w, "conflict", http.StatusConflict)
				return
			}
			if body["worker_id"] == "hb-empty" {
				_, _ = w.Write([]byte(`{"leases":[]}`))
				return
			}
			if body["worker_id"] == "hb-null" {
				_, _ = w.Write([]byte(`{"leases":[null]}`))
				return
			}
			if body["worker_id"] == "pending-fallback" {
				_, _ = w.Write([]byte(`{"pending_interaction_ids":["int_p1"],"poll_backoff":"1.5s"}`))
				return
			}
			_, _ = w.Write([]byte(`{"leases":[{"interaction_id":"int_hb","lease_token":"tok_hb"}]}`))

		case "/google.learning.gemini.api.interactions.v1beta.InteractionsService/CreateInteractionBidiStreamByEnvironmentKey":
			if r.Header.Get(LeaseTokenHeader) == "tok_grpc_hdr_err" {
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Grpc-Status", "7")
				w.Header().Set("Grpc-Message", "permission%20denied")
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Header.Get(LeaseTokenHeader) == "tok_grpc_trailer_err" {
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				w.Header().Set("Grpc-Status", "14")
				w.Header().Set("Grpc-Message", "backend%20unavailable")
				return
			}
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			flusher := w.(http.Flusher)
			flusher.Flush()

			// Read initial frame + at least one in-band heartbeat empty frame.
			for {
				frame, err := GRPCReadFrame(r.Body)
				if err != nil {
					return
				}
				if len(frame) == 0 {
					if heartbeatFrames.Add(1) >= 1 {
						_ = GRPCWriteFrame(w, MarshalServerEventBatch(&ServerEventBatch{
							InteractionCompleted: &InteractionCompletedEvent{},
						}))
						flusher.Flush()
						return
					}
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))

	var debugBuf bytes.Buffer
	client := NewHTTPClient(HTTPClientConfig{
		BaseURL:                     srvURL + "/",
		EnvironmentKey:              "ek_live",
		UserProject:                 "proj-1",
		APIRevision:                 "rev-1",
		Headers:                     map[string]string{"X-Extra": "v"},
		Debug:                       true,
		DebugOut:                    NewLeaseTokenRedactor(&debugBuf),
		ProbePlainHTTPOnStreamError: true,
	})
	if client.ServerURL() != srvURL {
		t.Errorf("ServerURL() = %q, want %q", client.ServerURL(), srvURL)
	}

	// PendingInteractionIDs fallback + PollBackoff.
	res, err := client.LeaseInteractions(t.Context(), &LeaseInteractionsRequest{
		WorkerID:           "pending-fallback",
		MaxNewInteractions: 2,
	})
	if err != nil || len(res.Leases) != 1 || res.Leases[0].InteractionID != "int_p1" || res.PollBackoff != 1500*time.Millisecond {
		t.Fatalf("LeaseInteractions(pending-fallback) = (%+v, %v)", res, err)
	}

	// RequireCredentialsOnLease check.
	strictNoCred := NewHTTPClient(HTTPClientConfig{BaseURL: srvURL, RequireCredentialsOnLease: true})
	if _, err := strictNoCred.LeaseSimple(t.Context(), "w1", 1); err == nil {
		t.Error("LeaseSimple(RequireCredentialsOnLease without creds) = nil, want error")
	}

	// Heartbeat outcomes: renewed, empty->cancel, [null]->neither, 409->cancel.
	hbOK, err := client.HeartbeatInteraction(t.Context(), "hb-ok", "int_hb", "env_1", "tok_hb")
	if err != nil || !hbOK.Renewed || hbOK.ShouldCancel {
		t.Errorf("HeartbeatInteraction(ok) = (%+v, %v)", hbOK, err)
	}
	hbEmpty, err := client.HeartbeatInteraction(t.Context(), "hb-empty", "int_hb", "env_1", "tok_hb")
	if err != nil || hbEmpty.Renewed || !hbEmpty.ShouldCancel {
		t.Errorf("HeartbeatInteraction(empty) = (%+v, %v)", hbEmpty, err)
	}
	hbNull, err := client.HeartbeatInteraction(t.Context(), "hb-null", "int_hb", "env_1", "tok_hb")
	if err != nil || hbNull.Renewed || !hbNull.ShouldCancel {
		t.Errorf("HeartbeatInteraction(null) = (%+v, %v), want ShouldCancel=true", hbNull, err)
	}
	hbConflict, err := client.HeartbeatInteraction(t.Context(), "hb-conflict", "int_hb", "env_1", "tok_hb")
	if err != nil || hbConflict.Renewed || !hbConflict.ShouldCancel {
		t.Errorf("HeartbeatInteraction(409) = (%+v, %v)", hbConflict, err)
	}

	// 403 TransportError on LeaseSimple.
	deniedClient := NewHTTPClient(HTTPClientConfig{BaseURL: srvURL, EnvironmentKey: "ek_403"})
	if _, err := deniedClient.LeaseSimple(t.Context(), "w1", 1); err == nil || !IsNonRetryableError(err) {
		t.Errorf("LeaseSimple(403) = %v, want non-retryable TransportError", err)
	}

	// PreviewConnect invokes HTTPDoer without live gRPC framing.
	var previewPath string
	previewClient := NewHTTPClient(HTTPClientConfig{
		BaseURL:        srvURL,
		EnvironmentKey: "ek_prev",
		HTTPDoer: httpDoerFunc(func(req *http.Request) (*http.Response, error) {
			previewPath = req.URL.Path
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
	})
	if err := previewClient.PreviewConnect(t.Context(), "tok_prev"); err != nil || !strings.Contains(previewPath, "CreateInteractionBidiStreamByEnvironmentKey") {
		t.Errorf("PreviewConnect() = %v, path=%q", err, previewPath)
	}

	// ConnectInteraction with in-band HeartbeatStream, gRPC header error, and gRPC trailer error.
	stream, err := client.ConnectInteraction(t.Context(), &ConnectInteractionRequest{
		InteractionID:     "int_live",
		LeaseToken:        "tok_secret_stream",
		WorkerID:          "w-live",
		HeartbeatInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ConnectInteraction() failed: %v", err)
	}
	if err := stream.Send(t.Context(), &ClientEventBatch{
		ReconnectInteraction: &ReconnectInteractionEvent{InteractionID: "int_live", ClientID: DefaultEnvironmentClientID},
	}); err != nil {
		t.Fatalf("stream.Send() failed: %v", err)
	}
	evBatch, err := stream.Recv(t.Context())
	if err != nil || evBatch.InteractionCompleted == nil {
		t.Fatalf("stream.Recv() = (%+v, %v), want InteractionCompleted", evBatch, err)
	}
	_ = stream.CloseSend()
	_ = stream.Close()
	if heartbeatFrames.Load() < 1 {
		t.Errorf("heartbeatFrames = %d, want >= 1", heartbeatFrames.Load())
	}
	if strings.Contains(debugBuf.String(), "tok_secret_stream") {
		t.Errorf("debug output leaked lease_token: %q", debugBuf.String())
	}

	if _, err := client.ConnectInteraction(t.Context(), &ConnectInteractionRequest{
		InteractionID: "int_hdr",
		LeaseToken:    "tok_grpc_hdr_err",
	}); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("ConnectInteraction(Grpc-Status header 7) = %v, want permission denied", err)
	}

	trStream, err := client.ConnectInteraction(t.Context(), &ConnectInteractionRequest{
		InteractionID: "int_tr",
		LeaseToken:    "tok_grpc_trailer_err",
	})
	if err != nil {
		t.Fatalf("ConnectInteraction(trailer setup) failed: %v", err)
	}
	if _, err := trStream.Recv(t.Context()); err == nil || !strings.Contains(err.Error(), "backend unavailable") {
		t.Errorf("trStream.Recv(Grpc-Status trailer 14) = %v, want backend unavailable", err)
	}
	_ = trStream.Close()
}

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (f httpDoerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}
