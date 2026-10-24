//! Attached control and watch stream ownership across client transports.
//!
//! This module keeps same-process and HTTP/2 receiver behavior aligned while
//! the parent client module owns request dispatch and wire decoding.

use super::*;
use std::collections::VecDeque;

type InProcessLifecycleCommandFuture =
    Pin<Box<dyn Future<Output = Result<SendResponse, ControlClientError>> + Send + 'static>>;
type InProcessLifecycleCommandSend =
    Arc<dyn Fn(SendRequest) -> InProcessLifecycleCommandFuture + Send + Sync>;

/// Same-process observation interface implemented by server-owned stream adapters.
pub trait LocalWatchStream: Send + Sync {
    /// Returns metadata captured at attach time.
    fn attached(&self) -> &Attached;

    /// Receives the next event without serializing its typed payload.
    ///
    /// # Errors
    ///
    /// Returns a streaming error when the bounded event tail lags.
    fn recv_event(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<StreamingEventFrame>, StreamingApiError>> + Send + '_,
        >,
    >;

    /// Receives the next coalesced live state update.
    fn recv_state_update(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Option<StreamingStateUpdateFrame>> + Send + '_>>;
}

/// Same-process command interface implemented by server-owned control streams.
pub trait LocalControlStream: LocalWatchStream {
    /// Dispatches a typed command through its owning actor.
    ///
    /// # Errors
    ///
    /// Returns a streaming error if dispatch or acknowledgement fails.
    fn send_command(
        &self,
        command_id: u64,
        command: SessionCommand,
    ) -> Pin<Box<dyn Future<Output = Result<SendResponse, StreamingApiError>> + Send + '_>>;
}

/// Attached bidirectional `Control` stream returned by a [`ControlClient`].
pub enum ClientControlStream {
    /// Same-process stream over the session actor mailbox and event-log hub.
    InProcess(Box<dyn LocalControlStream>),
    /// Same-process stream whose commands return through the lifecycle registry.
    InProcessLifecycle(InProcessLifecycleControlStream),
    /// HTTP/2 RPC stream.
    Rpc(RpcControlStream),
}

impl ClientControlStream {
    /// Returns the attach metadata emitted at stream start.
    #[must_use]
    pub fn attached(&self) -> &Attached {
        match self {
            Self::InProcess(stream) => stream.attached(),
            Self::InProcessLifecycle(stream) => stream.attached(),
            Self::Rpc(stream) => stream.attached(),
        }
    }

    /// Receives the next API event frame from replay or live tail.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the underlying transport fails, the
    /// RPC event frame is malformed, or the in-process event-log stream lags.
    pub async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, ControlClientError> {
        match self {
            Self::InProcess(stream) => stream.recv_event().await.map_err(ControlClientError::from),
            Self::InProcessLifecycle(stream) => {
                stream.recv_event().await.map_err(ControlClientError::from)
            }
            Self::Rpc(stream) => stream.recv_event().await,
        }
    }

    /// Receives the next live run-state update.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the underlying transport fails or an
    /// RPC state-update frame is malformed. Superseded state updates are
    /// coalesced on both transports.
    pub async fn recv_state_update(
        &mut self,
    ) -> Result<Option<StreamingStateUpdateFrame>, ControlClientError> {
        match self {
            Self::InProcess(stream) => Ok(stream.recv_state_update().await),
            Self::InProcessLifecycle(stream) => Ok(stream.recv_state_update().await),
            Self::Rpc(stream) => stream.recv_state_update().await,
        }
    }

    /// Dispatches one command envelope through this control stream.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when command dispatch is rejected by the
    /// streaming layer or by the RPC transport.
    pub async fn send_command(
        &self,
        command_id: u64,
        command: SessionCommand,
    ) -> Result<SendResponse, ControlClientError> {
        match self {
            Self::InProcess(stream) => stream
                .send_command(command_id, command)
                .await
                .map_err(ControlClientError::from),
            Self::InProcessLifecycle(stream) => stream.send_command(command_id, command).await,
            Self::Rpc(stream) => stream.send_command(command_id, command).await,
        }
    }
}

/// Same-process lifecycle `Control` stream routed through its owning registry.
///
/// This wrapper preserves event and state receivers from the attached stream,
/// while every command returns through the lifecycle registry. That registry
/// owns actor joins, so a backend failure is reported as its typed actor error
/// instead of being flattened into a closed-mailbox error.
pub struct InProcessLifecycleControlStream {
    stream: Box<dyn LocalControlStream>,
    command_send: InProcessLifecycleCommandSend,
}

impl InProcessLifecycleControlStream {
    /// Builds a lifecycle stream with commands delegated to its owning registry.
    #[must_use]
    pub fn new<C, Fut>(stream: Box<dyn LocalControlStream>, command_send: C) -> Self
    where
        C: Fn(SendRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<SendResponse, ControlClientError>> + Send + 'static,
    {
        let command_send: InProcessLifecycleCommandSend = Arc::new(move |request| {
            Box::pin(command_send(request))
                as Pin<
                    Box<
                        dyn Future<Output = Result<SendResponse, ControlClientError>>
                            + Send
                            + 'static,
                    >,
                >
        });
        Self {
            stream,
            command_send,
        }
    }

    fn attached(&self) -> &Attached {
        self.stream.attached()
    }

    async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, StreamingApiError> {
        self.stream.recv_event().await
    }

    async fn recv_state_update(&mut self) -> Option<StreamingStateUpdateFrame> {
        self.stream.recv_state_update().await
    }

    async fn send_command(
        &self,
        command_id: u64,
        command: SessionCommand,
    ) -> Result<SendResponse, ControlClientError> {
        let session = self.stream.attached().session;
        (self.command_send)(SendRequest::new(session, command_id, command)).await
    }
}

/// Attached read-only `Watch` stream returned by a [`ControlClient`].
pub enum ClientWatchStream {
    /// Same-process stream over the session event-log hub.
    InProcess(Box<dyn LocalWatchStream>),
    /// HTTP/2 RPC stream.
    Rpc(RpcWatchStream),
}

impl ClientWatchStream {
    /// Returns the attach metadata emitted at stream start.
    #[must_use]
    pub fn attached(&self) -> &Attached {
        match self {
            Self::InProcess(stream) => stream.attached(),
            Self::Rpc(stream) => stream.attached(),
        }
    }

    /// Receives the next API event frame from replay or live tail.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the underlying transport fails, the
    /// RPC event frame is malformed, or the in-process event-log stream lags.
    pub async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, ControlClientError> {
        match self {
            Self::InProcess(stream) => stream.recv_event().await.map_err(ControlClientError::from),
            Self::Rpc(stream) => stream.recv_event().await,
        }
    }

    /// Receives the next live run-state update.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the underlying transport fails or an
    /// RPC state-update frame is malformed. Superseded state updates are
    /// coalesced on both transports.
    pub async fn recv_state_update(
        &mut self,
    ) -> Result<Option<StreamingStateUpdateFrame>, ControlClientError> {
        match self {
            Self::InProcess(stream) => Ok(stream.recv_state_update().await),
            Self::Rpc(stream) => stream.recv_state_update().await,
        }
    }
}

/// Attached HTTP/2 RPC `Control` stream.
pub struct RpcControlStream {
    body: Box<RpcControlStreamBody>,
    // The box is destroyed before its original allocation loan is returned.
    _storage: crucible_engine::owned_decode::DecodeScratch,
}

struct RpcControlStreamBody {
    attached: Attached,
    events: RpcStreamingEventReceiver,
    client: RpcControlClient,
}

impl RpcControlStream {
    pub(super) fn new(
        attached: Attached,
        events: RpcStreamingEventReceiver,
        client: RpcControlClient,
        budget: &crucible_engine::owned_decode::DecodeBudget,
    ) -> Result<Self, ControlClientError> {
        let (body, storage) = boxed_stream_body(
            RpcControlStreamBody {
                attached,
                events,
                client,
            },
            budget,
        )?;
        Ok(Self {
            body,
            _storage: storage,
        })
    }

    /// Returns the attach metadata emitted at stream start.
    #[must_use]
    pub const fn attached(&self) -> &Attached {
        &self.body.attached
    }

    /// Receives the next API event frame from replay or live tail.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the HTTP/2 response stream fails or
    /// the next event frame cannot be decoded.
    pub async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, ControlClientError> {
        self.body.events.recv_event().await
    }

    /// Receives the next live run-state update.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the HTTP/2 response stream fails or
    /// the next state-update frame cannot be decoded.
    pub async fn recv_state_update(
        &mut self,
    ) -> Result<Option<StreamingStateUpdateFrame>, ControlClientError> {
        self.body.events.recv_state_update().await
    }

    /// Dispatches one command envelope over the RPC control stream.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the RPC command endpoint rejects the
    /// request or the response cannot be decoded.
    pub async fn send_command(
        &self,
        command_id: u64,
        command: SessionCommand,
    ) -> Result<SendResponse, ControlClientError> {
        self.body
            .client
            .control_send(SendRequest::new(
                self.body.attached.session,
                command_id,
                command,
            ))
            .await
    }
}

/// Attached HTTP/2 RPC `Watch` stream.
pub struct RpcWatchStream {
    body: Box<RpcWatchStreamBody>,
    // Allocation credit outlives the actual boxed receiver body.
    _storage: crucible_engine::owned_decode::DecodeScratch,
}

struct RpcWatchStreamBody {
    attached: Attached,
    events: RpcStreamingEventReceiver,
}

impl RpcWatchStream {
    pub(super) fn new(
        attached: Attached,
        events: RpcStreamingEventReceiver,
        budget: &crucible_engine::owned_decode::DecodeBudget,
    ) -> Result<Self, ControlClientError> {
        let (body, storage) = boxed_stream_body(RpcWatchStreamBody { attached, events }, budget)?;
        Ok(Self {
            body,
            _storage: storage,
        })
    }

    /// Returns the attach metadata emitted at stream start.
    #[must_use]
    pub const fn attached(&self) -> &Attached {
        &self.body.attached
    }

    /// Receives the next API event frame from replay or live tail.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the HTTP/2 response stream fails or
    /// the next event frame cannot be decoded.
    pub async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, ControlClientError> {
        self.body.events.recv_event().await
    }

    /// Receives the next live run-state update.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the HTTP/2 response stream fails or
    /// the next state-update frame cannot be decoded.
    pub async fn recv_state_update(
        &mut self,
    ) -> Result<Option<StreamingStateUpdateFrame>, ControlClientError> {
        self.body.events.recv_state_update().await
    }
}

// The returned loan outlives the box, including its allocator deallocation.
fn boxed_stream_body<T>(
    body: T,
    budget: &crucible_engine::owned_decode::DecodeBudget,
) -> Result<(Box<T>, crucible_engine::owned_decode::DecodeScratch), ControlClientError> {
    let storage = budget
        .reserve_scratch_bytes(std::mem::size_of::<T>() as u64)
        .map_err(|source| {
            client_output_admission(crucible_control_api::admitted_output::admission(source))
        })?;

    Ok((Box::new(body), storage))
}

pub(super) struct RpcStreamingEventReceiver {
    frames: mpsc::Receiver<Result<RpcStreamingFrame, ControlClientError>>,
    pending_events: VecDeque<StreamingEventFrame>,
    pending_state_updates: VecDeque<StreamingStateUpdateFrame>,
    skipped_events: u64,
    last_state_sequence: Option<u64>,
    _event_storage: crucible_engine::owned_decode::DecodeScratch,
    _state_storage: crucible_engine::owned_decode::DecodeScratch,
}

impl RpcStreamingEventReceiver {
    pub(super) fn new(
        frames: mpsc::Receiver<Result<RpcStreamingFrame, ControlClientError>>,
        budget: &crucible_engine::owned_decode::DecodeBudget,
    ) -> Result<Self, ControlClientError> {
        let (pending_events, event_storage) =
            pending_storage(budget, RPC_STREAM_PENDING_FRAME_CAPACITY)?;
        let (pending_state_updates, state_storage) = pending_storage(budget, 1)?;
        Ok(Self {
            frames,
            pending_events,
            pending_state_updates,
            skipped_events: 0,
            last_state_sequence: None,
            _event_storage: event_storage,
            _state_storage: state_storage,
        })
    }

    async fn recv_event(&mut self) -> Result<Option<StreamingEventFrame>, ControlClientError> {
        if self.skipped_events > 0 {
            let skipped = std::mem::take(&mut self.skipped_events);
            return Err(ControlClientError::from(
                StreamingApiError::EventStreamLagged { skipped },
            ));
        }
        if let Some(frame) = self.pending_events.pop_front() {
            return Ok(Some(frame));
        }

        loop {
            match self.frames.recv().await {
                Some(Ok(RpcStreamingFrame::Event(frame))) => return Ok(Some(frame)),
                Some(Ok(RpcStreamingFrame::StateUpdate(frame))) => {
                    self.push_pending_state_update(frame);
                }
                Some(Err(error)) => return Err(error),
                None => return Ok(None),
            }
        }
    }

    async fn recv_state_update(
        &mut self,
    ) -> Result<Option<StreamingStateUpdateFrame>, ControlClientError> {
        let mut latest = self.pending_state_updates.pop_back();
        self.pending_state_updates.clear();
        while latest.is_none() {
            match self.frames.recv().await {
                Some(Ok(RpcStreamingFrame::StateUpdate(frame))) => {
                    if self.state_sequence_is_newer(frame.sequence) {
                        latest = Some(frame);
                    }
                }
                Some(Ok(RpcStreamingFrame::Event(frame))) => {
                    self.push_pending_event(frame);
                }
                Some(Err(error)) => return Err(error),
                None => return Ok(None),
            }
        }

        loop {
            match self.frames.try_recv() {
                Ok(Ok(RpcStreamingFrame::StateUpdate(frame))) => {
                    if latest
                        .as_ref()
                        .is_none_or(|current| frame.sequence > current.sequence)
                        && self.state_sequence_is_newer(frame.sequence)
                    {
                        latest = Some(frame);
                    }
                }
                Ok(Ok(RpcStreamingFrame::Event(frame))) => self.push_pending_event(frame),
                Ok(Err(error)) => return Err(error),
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }

        if let Some(frame) = &latest {
            self.last_state_sequence = Some(frame.sequence);
        }
        Ok(latest)
    }

    fn push_pending_event(&mut self, frame: StreamingEventFrame) {
        if self.pending_events.len() >= RPC_STREAM_PENDING_FRAME_CAPACITY {
            let _dropped = self.pending_events.pop_front();
            self.skipped_events = self.skipped_events.saturating_add(1);
        }
        self.pending_events.push_back(frame);
    }

    fn push_pending_state_update(&mut self, frame: StreamingStateUpdateFrame) {
        if !self.state_sequence_is_newer(frame.sequence)
            || self
                .pending_state_updates
                .back()
                .is_some_and(|pending| pending.sequence >= frame.sequence)
        {
            return;
        }
        self.pending_state_updates.clear();
        self.pending_state_updates.push_back(frame);
    }

    fn state_sequence_is_newer(&self, sequence: u64) -> bool {
        self.last_state_sequence
            .is_none_or(|delivered| sequence > delivered)
    }
}

fn pending_storage<T>(
    budget: &crucible_engine::owned_decode::DecodeBudget,
    capacity: usize,
) -> Result<(VecDeque<T>, crucible_engine::owned_decode::DecodeScratch), ControlClientError> {
    let bytes = capacity
        .checked_mul(std::mem::size_of::<T>())
        .ok_or_else(|| {
            client_output_admission(crucible_control_api::admitted_output::admission(
                crucible_engine::owned_decode::DecodeAdmissionError::new(std::fmt::Error),
            ))
        })?;
    let loan = budget
        .reserve_scratch_bytes(bytes as u64)
        .map_err(|source| {
            client_output_admission(crucible_control_api::admitted_output::admission(source))
        })?;
    let mut queue = VecDeque::new();
    queue.try_reserve_exact(capacity).map_err(|source| {
        client_output_admission(crucible_control_api::admitted_output::admission(
            crucible_engine::owned_decode::DecodeAdmissionError::new(source),
        ))
    })?;
    Ok((queue, loan))
}

#[cfg(test)]
#[path = "streaming_receiver_tests.rs"]
mod streaming_receiver_tests;

#[cfg(test)]
mod storage_tests;
