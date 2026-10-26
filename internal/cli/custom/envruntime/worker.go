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
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultMaxStreamReconnects is the default maximum stream reconnect attempts per leased interaction.
	DefaultMaxStreamReconnects = 3

	// MaxToolResultWireBytes bounds a single serialized ClientEvent below MaxGRPCFrameBytes.
	MaxToolResultWireBytes = MaxGRPCFrameBytes - 4096
)

// PullWorkerConfig configures a PullWorker for single-node polling, active-lease renewal, or one-shot serve execution.
type PullWorkerConfig struct {
	Client                EnvironmentClient
	Tools                 *ToolDispatcher
	FS                    *SandboxFS
	Shell                 *SandboxShell
	Hooks                 HookHandler
	Observer              Observer
	EnvironmentID         string
	EnvironmentKey        string
	WorkerID              string
	RegisterEnvironment   func(ctx context.Context) (envID, envKey string, err error)
	DirectInteractionID   string
	DirectLeaseToken      string
	MaxConcurrent         int
	PollInterval          time.Duration
	LeaseTTL              time.Duration
	HeartbeatInterval     time.Duration
	CommandTimeout        time.Duration
	DisableBash           bool
	Labels                map[string]string
	TrackActiveLeases     bool
	InBandStreamHeartbeat bool
	RetryConnectErrors    bool
	NoRetries             bool
	MaxReconnectAttempts  int
	NonRetryableCheck     func(error) bool
	Logger                *log.Logger
}

type activeWorkerSession struct {
	interactionID string
	leaseToken    string
	cancel        context.CancelFunc
}

// PullWorker leases pending interactions from the control plane and executes tools and hooks over bidirectional streams.
type PullWorker struct {
	cfg               PullWorkerConfig
	client            EnvironmentClient
	tools             *ToolDispatcher
	hooks             HookHandler
	observer          Observer
	workerID          string
	maxConcurrent     int
	pollInterval      time.Duration
	leaseTTL          time.Duration
	heartbeatInterval time.Duration
	maxReconnects     int
	logger            *log.Logger

	mu             sync.Mutex
	environmentID  string
	environmentKey string
	activeSessions map[string]*activeWorkerSession
	slotReleasedCh chan struct{}
}

// NewPullWorker constructs a PullWorker from cfg.
func NewPullWorker(cfg PullWorkerConfig) *PullWorker {
	workerID := strings.TrimSpace(cfg.WorkerID)
	if workerID == "" {
		workerID = DefaultRuntimeID("worker")
	}
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		if cfg.TrackActiveLeases {
			maxConcurrent = 1
		} else {
			maxConcurrent = 4
		}
	}
	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		if cfg.TrackActiveLeases {
			pollInterval = DefaultPollBackoff
		} else {
			pollInterval = 2 * time.Second
		}
	}
	leaseTTL := cfg.LeaseTTL
	if leaseTTL <= 0 {
		leaseTTL = DefaultLeaseTTL
	}
	hbInterval := cfg.HeartbeatInterval
	if hbInterval <= 0 && cfg.InBandStreamHeartbeat {
		hbInterval = DefaultHeartbeatInterval
	}
	cmdTimeout := cfg.CommandTimeout
	if cmdTimeout <= 0 && !cfg.TrackActiveLeases {
		cmdTimeout = 2 * time.Minute
	}
	tools := cfg.Tools
	if tools == nil {
		tools = NewToolDispatcher(ToolDispatcherConfig{
			FS:                          cfg.FS,
			Shell:                       cfg.Shell,
			DisableBash:                 cfg.DisableBash,
			CommandTimeout:              cmdTimeout,
			DefaultWriteToFileOverwrite: !cfg.TrackActiveLeases,
			EnableExtendedFSTools:       cfg.TrackActiveLeases,
			RespectWaitMsBeforeAsync:    cfg.TrackActiveLeases,
		})
	}
	maxReconnects := cfg.MaxReconnectAttempts
	if maxReconnects <= 0 {
		maxReconnects = DefaultMaxStreamReconnects
	}
	if cfg.NoRetries {
		maxReconnects = 0
	}
	obs := cfg.Observer
	if obs == nil {
		obs = NopObserver{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}

	return &PullWorker{
		cfg:               cfg,
		client:            cfg.Client,
		tools:             tools,
		hooks:             cfg.Hooks,
		observer:          obs,
		workerID:          workerID,
		maxConcurrent:     maxConcurrent,
		pollInterval:      pollInterval,
		leaseTTL:          leaseTTL,
		heartbeatInterval: hbInterval,
		maxReconnects:     maxReconnects,
		logger:            logger,
		environmentID:     strings.TrimSpace(cfg.EnvironmentID),
		environmentKey:    strings.TrimSpace(cfg.EnvironmentKey),
		activeSessions:    make(map[string]*activeWorkerSession),
		slotReleasedCh:    make(chan struct{}, 1),
	}
}

// EnvironmentID returns the worker's current environment identifier.
func (w *PullWorker) EnvironmentID() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.environmentID
}

// EnvironmentKey returns the worker's current environment key.
func (w *PullWorker) EnvironmentKey() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.environmentKey
}

func (w *PullWorker) isNonRetryable(err error) bool {
	if IsNonRetryableError(err) {
		return true
	}
	return w.cfg.NonRetryableCheck != nil && w.cfg.NonRetryableCheck(err)
}

// ServeInteraction validates lease identifiers and executes a single pre-leased interaction session.
func (w *PullWorker) ServeInteraction(ctx context.Context, lease LeasedInteraction) error {
	interactionID := strings.TrimSpace(lease.InteractionID)
	if interactionID == "" {
		return &PathError{Kind: PathErrInvalidArgument, Message: "interaction_id is required"}
	}
	if !IsValidIdentifier(interactionID) {
		return &PathError{Kind: PathErrInvalidArgument, Message: "interaction_id contains invalid characters"}
	}
	if envID := strings.TrimSpace(lease.EnvironmentID); envID != "" && !IsValidIdentifier(envID) {
		return &PathError{Kind: PathErrInvalidArgument, Message: "environment_id contains invalid characters"}
	}
	lease.InteractionID = interactionID
	if lease.HeartbeatInterval <= 0 {
		if w.heartbeatInterval > 0 {
			lease.HeartbeatInterval = w.heartbeatInterval
		} else if lease.EnvironmentKey == "" && w.EnvironmentKey() == "" && lease.LeaseToken != "" {
			lease.HeartbeatInterval = DefaultHeartbeatInterval
		}
	}
	return w.ExecuteLease(ctx, &lease)
}

// ServeLeases executes each pre-leased interaction sequentially, logging attachment and completion.
func (w *PullWorker) ServeLeases(ctx context.Context, leases []*LeasedInteraction) error {
	for _, lease := range leases {
		if lease == nil {
			continue
		}
		w.logger.Printf("[%s] Attached interaction session", lease.InteractionID)
		if err := w.ExecuteLease(ctx, lease); err != nil {
			return err
		}
		w.logger.Printf("[%s] Completed interaction session", lease.InteractionID)
	}
	return nil
}

// Run executes the pull-mode worker loop until ctx is canceled or a fatal non-retryable error occurs.
func (w *PullWorker) Run(ctx context.Context) error {
	if w.cfg.TrackActiveLeases {
		return w.runTrackedLoop(ctx)
	}
	return RunLeasePollLoop(ctx, LeasePollLoopConfig{
		Client:            w.client,
		CallerID:          w.workerID,
		EnvironmentID:     w.EnvironmentID(),
		EnvironmentKey:    w.EnvironmentKey(),
		MaxSlots:          w.maxConcurrent,
		PollInterval:      w.pollInterval,
		NoRetries:         w.cfg.NoRetries,
		NonRetryableCheck: w.isNonRetryable,
		Logger:            w.logger,
		Observer:          w.observer,
		ErrLabel:          "LeaseInteractions error",
		StartMsg:          fmt.Sprintf("Worker %s polling (maxConcurrent=%d)", w.workerID, w.maxConcurrent),
	}, func(ctx context.Context, item *LeasedInteraction) {
		w.logger.Printf("[%s] Claimed interaction lease (env=%s)", item.InteractionID, firstNonEmpty(item.EnvironmentID, "default"))
		if err := w.ExecuteLease(ctx, item); err != nil && ctx.Err() == nil {
			w.logger.Printf("[%s] session ended with error: %v", item.InteractionID, err)
			return
		}
		if ctx.Err() == nil {
			w.logger.Printf("[%s] Completed interaction session", item.InteractionID)
		}
	})
}

func (w *PullWorker) runTrackedLoop(ctx context.Context) error {
	if w.cfg.RegisterEnvironment != nil && w.EnvironmentKey() == "" {
		envID, envKey, err := w.cfg.RegisterEnvironment(ctx)
		if err != nil {
			return fmt.Errorf("failed to register environment on startup: %w", err)
		}
		w.mu.Lock()
		w.environmentID = envID
		w.environmentKey = envKey
		w.mu.Unlock()
		w.logger.Printf("PullWorker registered environment %q", envID)
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	if w.cfg.DirectInteractionID != "" {
		w.startTrackedSession(ctx, &wg, LeasedInteraction{
			InteractionID:  w.cfg.DirectInteractionID,
			EnvironmentID:  w.EnvironmentID(),
			LeaseToken:     w.cfg.DirectLeaseToken,
			EnvironmentKey: w.EnvironmentKey(),
		})
	}
	if w.EnvironmentKey() == "" && w.cfg.DirectInteractionID != "" {
		wg.Wait()
		return nil
	}

	backoff := w.pollInterval
	for {
		if ctx.Err() != nil {
			w.cancelTrackedSessions()
			return nil
		}
		nextBackoff, err := w.leaseTrackedOnce(ctx, &wg)
		if err != nil {
			if ctx.Err() != nil {
				w.cancelTrackedSessions()
				return nil
			}
			w.logger.Printf("PullWorker lease cycle failed: %v", err)
			nextBackoff = w.pollInterval
		}
		if nextBackoff <= 0 {
			nextBackoff = backoff
		}

		timer := time.NewTimer(nextBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			w.cancelTrackedSessions()
			return nil
		case <-w.slotReleasedCh:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (w *PullWorker) leaseTrackedOnce(ctx context.Context, wg *sync.WaitGroup) (time.Duration, error) {
	w.mu.Lock()
	envID := w.environmentID
	envKey := w.environmentKey
	activeLeases := make([]LeaseEntry, 0, len(w.activeSessions))
	sentWithToken := make(map[string]bool, len(w.activeSessions))
	for id, sess := range w.activeSessions {
		activeLeases = append(activeLeases, LeaseEntry{
			InteractionID: id,
			LeaseToken:    sess.leaseToken,
		})
		if sess.leaseToken != "" {
			sentWithToken[id] = true
		}
	}
	availSlots := max(w.maxConcurrent-len(w.activeSessions), 0)
	w.mu.Unlock()

	if availSlots == 0 && len(activeLeases) == 0 {
		return w.pollInterval, nil
	}

	leaseRes, err := w.client.LeaseInteractions(ctx, &LeaseInteractionsRequest{
		EnvironmentID:      envID,
		EnvironmentKey:     envKey,
		WorkerID:           w.workerID,
		ActiveLeases:       activeLeases,
		MaxNewInteractions: int32(availSlots),
		RequestedLeaseTTL:  w.leaseTTL,
		Labels:             w.cfg.Labels,
	})
	if err != nil {
		w.observer.LeasePolled(0, err)
		return 0, err
	}
	w.observer.LeasePolled(len(leaseRes.Leases), nil)

	granted := make(map[string]LeasedInteraction, len(leaseRes.Leases))
	for _, lease := range leaseRes.Leases {
		if lease.InteractionID != "" {
			granted[lease.InteractionID] = lease
		}
	}

	w.mu.Lock()
	for id, sess := range w.activeSessions {
		if updated, ok := granted[id]; ok {
			if updated.LeaseToken != "" {
				sess.leaseToken = updated.LeaseToken
			}
			continue
		}
		if sentWithToken[id] {
			w.logger.Printf("PullWorker lease lost for interaction %q; canceling local execution", id)
			sess.cancel()
			delete(w.activeSessions, id)
		}
	}
	w.mu.Unlock()

	if availSlots > 0 {
		for _, lease := range leaseRes.Leases {
			if lease.InteractionID != "" {
				w.startTrackedSession(ctx, wg, lease)
			}
		}
	}
	return leaseRes.PollBackoff, nil
}

func (w *PullWorker) startTrackedSession(parentCtx context.Context, wg *sync.WaitGroup, lease LeasedInteraction) {
	w.mu.Lock()
	if _, exists := w.activeSessions[lease.InteractionID]; exists || len(w.activeSessions) >= w.maxConcurrent {
		w.mu.Unlock()
		return
	}
	sessCtx, cancel := context.WithCancel(parentCtx)
	w.activeSessions[lease.InteractionID] = &activeWorkerSession{
		interactionID: lease.InteractionID,
		leaseToken:    lease.LeaseToken,
		cancel:        cancel,
	}
	w.mu.Unlock()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			cancel()
			w.mu.Lock()
			delete(w.activeSessions, lease.InteractionID)
			w.mu.Unlock()
			select {
			case w.slotReleasedCh <- struct{}{}:
			default:
			}
		}()
		cp := lease
		if err := w.ExecuteLease(sessCtx, &cp); err != nil && sessCtx.Err() == nil {
			w.logger.Printf("PullWorker session for interaction %q ended with error: %v", lease.InteractionID, err)
		}
	}()
}

func (w *PullWorker) cancelTrackedSessions() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for id, sess := range w.activeSessions {
		sess.cancel()
		delete(w.activeSessions, id)
	}
}

type sessionState struct {
	interactionID string
	mu            sync.Mutex
	lastAckSeq    int64
	nextClientSeq int64
	executedCalls map[string]*EventPayload
}

func (s *sessionState) ackSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAckSeq
}

// ExecuteLease attaches to lease's bidirectional interaction stream, handling reconnects, tools, hooks, and Yield.
func (w *PullWorker) ExecuteLease(ctx context.Context, lease *LeasedInteraction) (retErr error) {
	if lease == nil {
		return &PathError{Kind: PathErrInvalidArgument, Message: "lease is required"}
	}
	w.observer.InteractionStarted(lease.InteractionID)
	defer func() {
		w.observer.InteractionFinished(lease.InteractionID, retErr)
	}()

	state := &sessionState{
		interactionID: lease.InteractionID,
		nextClientSeq: 1,
		executedCalls: make(map[string]*EventPayload),
	}

	envKey := firstNonEmpty(lease.EnvironmentKey, w.EnvironmentKey())
	envID := firstNonEmpty(lease.EnvironmentID, w.EnvironmentID())
	streamHB := lease.HeartbeatInterval
	if streamHB <= 0 && !w.cfg.InBandStreamHeartbeat {
		if w.heartbeatInterval > 0 {
			streamHB = w.heartbeatInterval
		} else if envKey == "" && lease.LeaseToken != "" {
			streamHB = DefaultHeartbeatInterval
		}
	}

	for attempt := 0; attempt <= w.maxReconnects; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		leaseToken := lease.LeaseToken
		w.mu.Lock()
		if sess, ok := w.activeSessions[lease.InteractionID]; ok && sess.leaseToken != "" {
			leaseToken = sess.leaseToken
		}
		w.mu.Unlock()

		ack := state.ackSeq()
		reqHB := streamHB
		if w.cfg.InBandStreamHeartbeat {
			reqHB = 0
		}
		stream, err := w.client.ConnectInteraction(ctx, &ConnectInteractionRequest{
			InteractionID:     lease.InteractionID,
			EnvironmentID:     envID,
			EnvironmentKey:    envKey,
			LeaseToken:        leaseToken,
			WorkerID:          w.workerID,
			ClientID:          DefaultEnvironmentClientID,
			NextOutputSeqNum:  ack + 1,
			AckOutputSeqNum:   ack,
			HeartbeatInterval: reqHB,
		})
		if err != nil {
			if !w.cfg.RetryConnectErrors || w.isNonRetryable(err) || attempt >= w.maxReconnects {
				if !w.cfg.RetryConnectErrors {
					return fmt.Errorf("ConnectInteraction(%q) failed: %w", lease.InteractionID, err)
				}
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(RetryBackoff(200*time.Millisecond, attempt+1)):
				continue
			}
		}

		reconnect, runErr := w.consumeStream(ctx, stream, state)
		_ = stream.Close()
		if runErr != nil {
			if !w.cfg.RetryConnectErrors || w.isNonRetryable(runErr) || attempt >= w.maxReconnects {
				return runErr
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(RetryBackoff(200*time.Millisecond, attempt+1)):
				continue
			}
		}
		if !reconnect {
			return nil
		}
	}
	return fmt.Errorf("exceeded max stream reconnect attempts (%d) for interaction %q", w.maxReconnects, lease.InteractionID)
}

func (w *PullWorker) consumeStream(ctx context.Context, stream InteractionStream, state *sessionState) (bool, error) {
	if w.cfg.InBandStreamHeartbeat && w.heartbeatInterval > 0 {
		stopHB := make(chan struct{})
		hbDone := make(chan struct{})
		go func() {
			defer close(hbDone)
			ticker := time.NewTicker(w.heartbeatInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopHB:
					return
				case <-ticker.C:
					_ = stream.Send(ctx, &ClientEventBatch{AckOutputSeqNum: state.ackSeq()})
				}
			}
		}()
		defer func() {
			close(stopHB)
			<-hbDone
		}()
	}

	for {
		batch, err := stream.Recv(ctx)
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}

		if batch.InteractionReconnected != nil {
			state.mu.Lock()
			if batch.InteractionReconnected.NextInputSeqNum > state.nextClientSeq {
				state.nextClientSeq = batch.InteractionReconnected.NextInputSeqNum
			}
			state.mu.Unlock()
		}

		state.mu.Lock()
		pendingAck := state.lastAckSeq
		startClientSeq := state.nextClientSeq
		state.mu.Unlock()

		var outEvents []*ClientEvent
		ackUpdated := false
		for _, ev := range batch.Events {
			if ev == nil {
				continue
			}
			if ev.SeqNum > pendingAck {
				pendingAck = ev.SeqNum
				ackUpdated = true
			}
			if respPayload := w.handleServerEvent(ctx, ev, state); respPayload != nil {
				state.mu.Lock()
				seq := state.nextClientSeq
				state.nextClientSeq++
				state.mu.Unlock()
				outEvents = append(outEvents, &ClientEvent{
					SeqNum:          seq,
					TimestampMicros: time.Now().UnixMicro(),
					Payload:         respPayload,
				})
			}
		}

		if len(outEvents) > 0 || ackUpdated {
			if err := stream.Send(ctx, &ClientEventBatch{
				AckOutputSeqNum: pendingAck,
				Events:          outEvents,
			}); err != nil {
				state.mu.Lock()
				state.nextClientSeq = startClientSeq
				state.mu.Unlock()
				return false, err
			}
			state.mu.Lock()
			state.lastAckSeq = pendingAck
			state.mu.Unlock()
		}

		if batch.InteractionCompleted != nil {
			_ = stream.CloseSend()
			return false, nil
		}
		if batch.ReconnectionRequired != nil {
			return true, nil
		}
		if batch.Yield != nil {
			state.mu.Lock()
			nextSeq := state.nextClientSeq
			lastAck := state.lastAckSeq
			state.mu.Unlock()
			if len(outEvents) == 0 || batch.Yield.NextInputSeqNum >= nextSeq {
				_ = stream.Send(ctx, &ClientEventBatch{
					AckOutputSeqNum: lastAck,
					Disconnect:      &DisconnectEvent{},
				})
				_ = stream.CloseSend()
				drainCtx, cancelDrain := context.WithTimeout(ctx, 2*time.Second)
				_, _ = stream.Recv(drainCtx)
				cancelDrain()
				return false, nil
			}
		}
	}
}

func (w *PullWorker) handleServerEvent(ctx context.Context, ev *ServerEvent, state *sessionState) *EventPayload {
	if ev.Payload == nil {
		return nil
	}

	if fi := ev.Payload.FunctionInvocation; fi != nil {
		callKey := "fn:" + firstNonEmpty(fi.CallID, fmt.Sprintf("seq-%d", ev.SeqNum))
		if cached := w.loadCachedCall(state, callKey); cached != nil {
			return cached
		}
		w.logger.Printf("[%s] Executing function %s", state.interactionID, fi.Name)
		resMap, isErr := w.tools.Dispatch(ctx, fi.Name, fi.Arguments)
		out := &EventPayload{
			FunctionResult: &FunctionResultEvent{
				CallID:  fi.CallID,
				Name:    fi.Name,
				IsError: isErr,
				Result:  resMap,
			},
		}
		if exceedsMaxToolResultWire(out) {
			out = &EventPayload{
				FunctionResult: &FunctionResultEvent{
					CallID:  fi.CallID,
					Name:    fi.Name,
					IsError: true,
					Result: map[string]any{
						"error": fmt.Sprintf("tool %q result exceeds maximum frame size (%d bytes); narrow the query or specify start_line and end_line", fi.Name, MaxGRPCFrameBytes),
					},
				},
			}
		}
		w.storeCachedCall(state, callKey, out)
		return out
	}

	if ev.Payload.Step != nil && ev.Payload.Step.ToolCall != nil && ev.Payload.Step.ToolCall.FunctionCall != nil {
		tc := ev.Payload.Step.ToolCall
		fnCall := tc.FunctionCall
		callKey := "step:" + firstNonEmpty(tc.ID, fmt.Sprintf("seq-%d", ev.SeqNum))
		if cached := w.loadCachedCall(state, callKey); cached != nil {
			return cached
		}
		w.logger.Printf("[%s] Executing tool %s", state.interactionID, fnCall.Name)
		resMap, isErr := w.tools.Dispatch(ctx, fnCall.Name, fnCall.Arguments)
		out := &EventPayload{
			Step: &Step{
				ToolResult: &ToolResultStep{
					CallID: tc.ID,
					FunctionResult: &FunctionResultStep{
						Name:    fnCall.Name,
						IsError: isErr,
						Result:  resMap,
					},
				},
			},
		}
		if exceedsMaxToolResultWire(out) {
			out = &EventPayload{
				Step: &Step{
					ToolResult: &ToolResultStep{
						CallID: tc.ID,
						FunctionResult: &FunctionResultStep{
							Name:    fnCall.Name,
							IsError: true,
							Result: map[string]any{
								"error": fmt.Sprintf("tool %q result exceeds maximum frame size (%d bytes); narrow the query or specify start_line and end_line", fnCall.Name, MaxGRPCFrameBytes),
							},
						},
					},
				},
			}
		}
		w.storeCachedCall(state, callKey, out)
		return out
	}

	if hr := ev.Payload.CallHookRequest; hr != nil && w.hooks != nil {
		callKey := "hook:" + firstNonEmpty(hr.RequestID, fmt.Sprintf("seq-%d", ev.SeqNum))
		if cached := w.loadCachedCall(state, callKey); cached != nil {
			return cached
		}
		resp, err := w.hooks.CallHook(ctx, hr)
		if err != nil {
			resp = &CallHookResponse{
				RequestID:    hr.RequestID,
				ErrorMessage: err.Error(),
			}
		} else if resp == nil {
			resp = &CallHookResponse{
				RequestID:   hr.RequestID,
				EmptyResult: true,
			}
		}
		out := &EventPayload{CallHookResponse: resp}
		w.storeCachedCall(state, callKey, out)
		return out
	}

	return nil
}

func (w *PullWorker) loadCachedCall(state *sessionState, key string) *EventPayload {
	state.mu.Lock()
	defer state.mu.Unlock()
	if cached, ok := state.executedCalls[key]; ok {
		return cached.Clone()
	}
	return nil
}

func (w *PullWorker) storeCachedCall(state *sessionState, key string, payload *EventPayload) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.executedCalls[key] = payload.Clone()
}

func exceedsMaxToolResultWire(payload *EventPayload) bool {
	return len(MarshalClientEvent(&ClientEvent{
		SeqNum:          1,
		TimestampMicros: 1,
		Payload:         payload,
	})) > MaxToolResultWireBytes
}
