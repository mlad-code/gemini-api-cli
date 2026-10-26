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
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type scriptedStream struct {
	mu       sync.Mutex
	sent     []*ClientEventBatch
	recvFn   func(call int) (*ServerEventBatch, error)
	sendFn   func(call int, batch *ClientEventBatch) error
	recvCall int
	sendCall int
	closed   bool
}

func (s *scriptedStream) Send(_ context.Context, batch *ClientEventBatch) error {
	s.mu.Lock()
	s.sendCall++
	call := s.sendCall
	s.sent = append(s.sent, batch)
	fn := s.sendFn
	s.mu.Unlock()
	if fn != nil {
		return fn(call, batch)
	}
	return nil
}

func (s *scriptedStream) Recv(ctx context.Context) (*ServerEventBatch, error) {
	s.mu.Lock()
	s.recvCall++
	call := s.recvCall
	fn := s.recvFn
	s.mu.Unlock()
	if fn != nil {
		return fn(call)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *scriptedStream) CloseSend() error { return nil }

func (s *scriptedStream) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

type fakeEnvClient struct {
	leaseFn   func(ctx context.Context, req *LeaseInteractionsRequest) (*LeaseInteractionsResult, error)
	connectFn func(ctx context.Context, req *ConnectInteractionRequest) (InteractionStream, error)
}

func (f *fakeEnvClient) LeaseInteractions(ctx context.Context, req *LeaseInteractionsRequest) (*LeaseInteractionsResult, error) {
	return f.leaseFn(ctx, req)
}

func (f *fakeEnvClient) ConnectInteraction(ctx context.Context, req *ConnectInteractionRequest) (InteractionStream, error) {
	return f.connectFn(ctx, req)
}

type hookHandlerFunc func(ctx context.Context, req *CallHookRequest) (*CallHookResponse, error)

func (f hookHandlerFunc) CallHook(ctx context.Context, req *CallHookRequest) (*CallHookResponse, error) {
	return f(ctx, req)
}

func TestPullWorkerReconnectReplayHooksYieldAndOversizedResult(t *testing.T) {
	var toolCalls atomic.Int32
	var hookCalls atomic.Int32
	var connectReqs []*ConnectInteractionRequest
	var mu sync.Mutex

	tools := NewToolDispatcher(ToolDispatcherConfig{
		ShellExec: func(_ context.Context, cmd, _ string, _ time.Duration) (string, string, int, error) {
			if cmd == "huge" {
				return strings.Repeat("Z", MaxToolResultWireBytes+8192), "", 0, nil
			}
			toolCalls.Add(1)
			return "ran:" + cmd, "", 0, nil
		},
	})

	var attempt atomic.Int32
	client := &fakeEnvClient{
		connectFn: func(_ context.Context, req *ConnectInteractionRequest) (InteractionStream, error) {
			mu.Lock()
			reqCopy := *req
			connectReqs = append(connectReqs, &reqCopy)
			mu.Unlock()

			switch attempt.Add(1) {
			case 1:
				// Attempt 1: transient connect error -> retried because RetryConnectErrors=true.
				return nil, errors.New("transient dial error")
			case 2:
				// Attempt 2: delivers Step.ToolCall("call_1"), Send fails on tool response -> rolls back seq while caching executedCalls["call_1"]!
				return &scriptedStream{
					sendFn: func(call int, _ *ClientEventBatch) error {
						if call == 1 {
							return errors.New("broken pipe during tool reply")
						}
						return nil
					},
					recvFn: func(call int) (*ServerEventBatch, error) {
						if call == 1 {
							return &ServerEventBatch{
								Events: []*ServerEvent{
									nil,
									{Payload: nil},
									{
										SeqNum: 1,
										Payload: &EventPayload{
											Step: &Step{
												ToolCall: &ToolCallStep{
													ID:           "call_1",
													FunctionCall: &FunctionCallStep{Name: "execute_bash", Arguments: map[string]any{"command": "once"}},
												},
											},
										},
									},
								},
							}, nil
						}
						return nil, io.EOF
					},
				}, nil
			case 3:
				// Attempt 3: server replays "call_1", sends CallHookRequest + FunctionInvocation("huge") + ReconnectionRequired.
				return &scriptedStream{
					recvFn: func(call int) (*ServerEventBatch, error) {
						switch call {
						case 1:
							return &ServerEventBatch{
								InteractionReconnected: &InteractionReconnectedEvent{NextInputSeqNum: 5},
								Events: []*ServerEvent{
									{
										SeqNum: 1,
										Payload: &EventPayload{
											Step: &Step{
												ToolCall: &ToolCallStep{
													ID:           "call_1",
													FunctionCall: &FunctionCallStep{Name: "execute_bash", Arguments: map[string]any{"command": "once"}},
												},
											},
										},
									},
									{
										SeqNum: 2,
										Payload: &EventPayload{
											CallHookRequest: &CallHookRequest{RequestID: "hk_1", Name: "audit"},
										},
									},
									{
										SeqNum: 3,
										Payload: &EventPayload{
											FunctionInvocation: &FunctionInvocation{
												CallID:    "fi_big",
												Name:      "execute_bash",
												Arguments: map[string]any{"command": "huge"},
											},
										},
									},
								},
								ReconnectionRequired: &ReconnectionRequiredEvent{},
							}, nil
						default:
							return nil, io.EOF
						}
					},
				}, nil
			default:
				// Attempt 4: server replays hk_1 (cached!), sends Yield{NextInputSeqNum: 8}, worker sends Disconnect and exits cleanly!
				var s *scriptedStream
				s = &scriptedStream{
					recvFn: func(call int) (*ServerEventBatch, error) {
						if call == 1 {
							return &ServerEventBatch{
								Events: []*ServerEvent{{
									SeqNum:  2,
									Payload: &EventPayload{CallHookRequest: &CallHookRequest{RequestID: "hk_1", Name: "audit"}},
								}},
								Yield: &YieldEvent{NextInputSeqNum: 8},
							}, nil
						}
						return nil, io.EOF
					},
				}
				return s, nil
			}
		},
	}

	worker := NewPullWorker(PullWorkerConfig{
		Client: client,
		Tools:  tools,
		Hooks: hookHandlerFunc(func(_ context.Context, req *CallHookRequest) (*CallHookResponse, error) {
			hookCalls.Add(1)
			return &CallHookResponse{RequestID: req.RequestID, EmptyResult: true}, nil
		}),
		EnvironmentKey:        "ek_w",
		WorkerID:              "w-1",
		RetryConnectErrors:    true,
		InBandStreamHeartbeat: true,
		HeartbeatInterval:     time.Second,
		Logger:                log.New(io.Discard, "", 0),
	})

	if err := worker.ServeInteraction(t.Context(), LeasedInteraction{
		InteractionID: "int_replay",
		LeaseToken:    "tok_replay",
	}); err != nil {
		t.Fatalf("ServeInteraction() failed: %v", err)
	}

	if got := toolCalls.Load(); got != 1 {
		t.Errorf("side-effecting tool execution count = %d, want 1 (replay cache must prevent duplicate execution)", got)
	}
	if got := hookCalls.Load(); got != 1 {
		t.Errorf("hook execution count = %d, want 1 (replay cache must prevent duplicate hook run)", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(connectReqs) != 4 {
		t.Fatalf("len(connectReqs) = %d, want 4", len(connectReqs))
	}
	// Attempt 3 followed failed Send on attempt 2, so AckOutputSeqNum must have rolled back to 0!
	if connectReqs[2].AckOutputSeqNum != 0 || connectReqs[2].NextOutputSeqNum != 1 {
		t.Errorf("attempt 3 seq after rolled-back Send = (ack=%d, next=%d), want (0, 1)", connectReqs[2].AckOutputSeqNum, connectReqs[2].NextOutputSeqNum)
	}
	// Attempt 4 followed acked seq 3, so AckOutputSeqNum=3, NextOutputSeqNum=4!
	if connectReqs[3].AckOutputSeqNum != 3 || connectReqs[3].NextOutputSeqNum != 4 {
		t.Errorf("attempt 4 seq = (ack=%d, next=%d), want (3, 4)", connectReqs[3].AckOutputSeqNum, connectReqs[3].NextOutputSeqNum)
	}
}

func TestPullWorkerValidationServeLeasesAndActiveLeaseRenewal(t *testing.T) {
	// 1. ServeInteraction identifier validation.
	wVal := NewPullWorker(PullWorkerConfig{Logger: log.New(io.Discard, "", 0)})
	for _, bad := range []LeasedInteraction{
		{},
		{InteractionID: "a..b"},
		{InteractionID: "int_ok", EnvironmentID: "bad/env"},
	} {
		if err := wVal.ServeInteraction(t.Context(), bad); err == nil {
			t.Errorf("ServeInteraction(%+v) = nil, want validation error", bad)
		}
	}

	// 2. ServeLeases: InteractionCompleted finishes cleanly; transport error propagates.
	var connectCalls atomic.Int32
	errClient := &fakeEnvClient{
		connectFn: func(_ context.Context, req *ConnectInteractionRequest) (InteractionStream, error) {
			connectCalls.Add(1)
			if req.InteractionID == "int_broken" {
				return nil, errors.New("stream broken")
			}
			return &scriptedStream{
				recvFn: func(call int) (*ServerEventBatch, error) {
					if call == 1 {
						return &ServerEventBatch{
							InteractionCompleted: &InteractionCompletedEvent{
								Status: &RPCStatus{Code: 13, Message: "model failed"},
							},
						}, nil
					}
					return nil, io.EOF
				},
			}, nil
		},
	}
	wErr := NewPullWorker(PullWorkerConfig{
		Client:    errClient,
		NoRetries: true,
		Logger:    log.New(io.Discard, "", 0),
	})
	if err := wErr.ServeLeases(t.Context(), []*LeasedInteraction{
		nil,
		{InteractionID: "int_done", LeaseToken: "tok"},
		{InteractionID: "int_broken", LeaseToken: "tok2"},
	}); err == nil || !strings.Contains(err.Error(), "stream broken") {
		t.Errorf("ServeLeases(int_done, int_broken) = %v, want stream broken error", err)
	}
	if got := connectCalls.Load(); got != 2 {
		t.Errorf("connectCalls = %d, want 2", got)
	}

	// 3. TrackActiveLeases=true mode: RegisterEnvironment + active lease renewal + lost-lease cancellation!
	streamStarted := make(chan struct{})
	streamCanceled := make(chan struct{})
	var leasePollCount atomic.Int32
	var sawActiveRenewal atomic.Bool

	activeClient := &fakeEnvClient{
		leaseFn: func(_ context.Context, req *LeaseInteractionsRequest) (*LeaseInteractionsResult, error) {
			n := leasePollCount.Add(1)
			switch n {
			case 1:
				return &LeaseInteractionsResult{
					Leases: []LeasedInteraction{{
						InteractionID: "int_active_1",
						EnvironmentID: req.EnvironmentID,
						LeaseToken:    "tok_v1",
					}},
					PollBackoff: 15 * time.Millisecond,
				}, nil
			case 2:
				if len(req.ActiveLeases) == 1 && req.ActiveLeases[0].LeaseToken == "tok_v1" {
					sawActiveRenewal.Store(true)
				}
				return &LeaseInteractionsResult{
					Leases: []LeasedInteraction{{
						InteractionID: "int_active_1",
						EnvironmentID: req.EnvironmentID,
						LeaseToken:    "tok_v2_rotated",
					}},
					PollBackoff: 15 * time.Millisecond,
				}, nil
			default:
				// Omit int_active_1 -> worker must cancel lost session!
				return &LeaseInteractionsResult{PollBackoff: 15 * time.Millisecond}, nil
			}
		},
		connectFn: func(_ context.Context, _ *ConnectInteractionRequest) (InteractionStream, error) {
			return &scriptedStream{
				recvFn: func(call int) (*ServerEventBatch, error) {
					if call == 1 {
						close(streamStarted)
					}
					// Block until sessionCtx is canceled when lease is lost on poll 3!
					return nil, errWaitContext
				},
			}, nil
		},
	}
	// Replace recvFn with a context-aware stream so we observe sessionCtx cancellation directly.
	activeClient.connectFn = func(_ context.Context, _ *ConnectInteractionRequest) (InteractionStream, error) {
		return &ctxBlockingStream{started: streamStarted, canceled: streamCanceled}, nil
	}

	runCtx, cancelRun := context.WithCancel(t.Context())
	defer cancelRun()

	wActive := NewPullWorker(PullWorkerConfig{
		Client:            activeClient,
		TrackActiveLeases: true,
		PollInterval:      15 * time.Millisecond,
		LeaseTTL:          45 * time.Millisecond,
		NoRetries:         true,
		RegisterEnvironment: func(context.Context) (string, string, error) {
			return "env_registered", "ek_registered", nil
		},
		Logger: log.New(io.Discard, "", 0),
	})

	runDone := make(chan error, 1)
	go func() {
		runDone <- wActive.Run(runCtx)
	}()

	select {
	case <-streamStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for active-lease session stream to start")
	}
	select {
	case <-streamCanceled:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for lost lease to cancel session stream")
	}
	cancelRun()
	if err := <-runDone; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("wActive.Run() = %v, want nil or context.Canceled", err)
	}
	if wActive.EnvironmentID() != "env_registered" || wActive.EnvironmentKey() != "ek_registered" {
		t.Errorf("registered env = (%q, %q)", wActive.EnvironmentID(), wActive.EnvironmentKey())
	}
	if !sawActiveRenewal.Load() {
		t.Error("sawActiveRenewal = false, want ActiveLeases sent on poll 2")
	}
}

var errWaitContext = errors.New("wait context")

type ctxBlockingStream struct {
	started  chan struct{}
	canceled chan struct{}
	once     sync.Once
	cancOnce sync.Once
}

func (s *ctxBlockingStream) Send(context.Context, *ClientEventBatch) error { return nil }

func (s *ctxBlockingStream) Recv(ctx context.Context) (*ServerEventBatch, error) {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	s.cancOnce.Do(func() { close(s.canceled) })
	return nil, ctx.Err()
}

func (s *ctxBlockingStream) CloseSend() error { return nil }
func (s *ctxBlockingStream) Close() error     { return nil }
