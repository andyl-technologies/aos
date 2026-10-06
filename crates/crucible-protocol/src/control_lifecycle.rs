//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Ordered control lifecycle validation and stateful host/plugin streams.
//!
//! The lifecycle couples handshake, setup, shared-memory RUN and terminal Quit
//! to committed frame I/O. Failed writes never publish a candidate transition;
//! runtime control traffic remains restricted to the terminal shutdown frame.

use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

use thiserror::Error;

use crate::{
    ControlDirection, ControlTag, FrameDecodeError, FrameIoError, HandshakeError,
    HostHandshakeConfig, HostMsg, NegotiatedHandshake, PluginHandshakeConfig, PluginMsg,
    SETUP_ACK_STATUS_READY, SETUP_ACK_STATUS_SETUP_FAILED, SchedulableNodeSetup,
    SetupCompletionError, control_decode_host_msg, control_decode_plugin_msg,
    control_encode_host_msg, control_encode_plugin_msg, control_frame_tag,
    host_negotiate_handshake, host_validate_setup_ack, plugin_send_setup_ack,
    plugin_validate_handshake_ack, read_control_frame, write_control_frame,
};
#[cfg(unix)]
use crate::{
    DescriptorHandoverError, ReceivedSetup, SetupDescriptorFds, recv_setup_with_descriptors,
    send_setup_with_descriptors,
};

/// Protocol lifecycle state for one host/plugin control socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ControlLifecycleState {
    /// No per-node control socket has been connected yet.
    #[default]
    Disconnected,
    /// A connected Unix stream socket pair exists for this node.
    Connected,
    /// The plugin has sent `Hello`.
    HelloSent,
    /// The host has replied with `HelloAck`.
    HelloAcknowledged,
    /// The host has sent `Setup` with the shmem and wake descriptors.
    SetupSent,
    /// The plugin has replied with `SetupAck(status = 0)`.
    SetupAcknowledged,
    /// Runtime synchronization is flowing through shared memory, not control frames.
    RunningViaSharedMemory,
    /// The host has sent `Quit` to end the run.
    QuitSent,
}

/// A lifecycle event observed on one host/plugin control socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlLifecycleEvent {
    /// The host created and connected an `AF_UNIX`/`SOCK_STREAM` socket pair.
    ConnectUnixStreamSocketPair,
    /// The plugin sent a `Hello` frame.
    PluginHello,
    /// The host sent a `HelloAck` frame.
    HostHelloAck,
    /// The host sent a `Setup` frame with the setup descriptors.
    HostSetup,
    /// The plugin sent a `SetupAck` frame.
    PluginSetupAck {
        /// The `SetupAck.status` byte.
        status: u8,
    },
    /// The node performed runtime synchronization through shared memory.
    RunViaSharedMemory,
    /// The host sent a `Quit` frame.
    HostQuit,
}

impl ControlLifecycleEvent {
    /// Returns the lifecycle event represented by a decoded plugin message.
    #[must_use]
    pub const fn from_plugin_msg(message: &PluginMsg) -> Self {
        match message {
            PluginMsg::Hello { .. } => Self::PluginHello,
            PluginMsg::SetupAck { status } => Self::PluginSetupAck { status: *status },
        }
    }

    /// Returns the lifecycle event represented by a decoded host message.
    #[must_use]
    pub const fn from_host_msg(message: &HostMsg) -> Self {
        match message {
            HostMsg::HelloAck { .. } => Self::HostHelloAck,
            HostMsg::Setup { .. } => Self::HostSetup,
            HostMsg::Quit => Self::HostQuit,
        }
    }

    /// Returns the control tag carried by this event, when it is a control frame.
    #[must_use]
    pub const fn control_tag(self) -> Option<ControlTag> {
        match self {
            Self::ConnectUnixStreamSocketPair | Self::RunViaSharedMemory => None,
            Self::PluginHello => Some(ControlTag::Hello),
            Self::HostHelloAck => Some(ControlTag::HelloAck),
            Self::HostSetup => Some(ControlTag::Setup),
            Self::PluginSetupAck { .. } => Some(ControlTag::SetupAck),
            Self::HostQuit => Some(ControlTag::Quit),
        }
    }
}

/// Canonical normal lifecycle for one host/plugin control socket.
pub const NORMAL_CONTROL_LIFECYCLE: [ControlLifecycleEvent; 7] = [
    ControlLifecycleEvent::ConnectUnixStreamSocketPair,
    ControlLifecycleEvent::PluginHello,
    ControlLifecycleEvent::HostHelloAck,
    ControlLifecycleEvent::HostSetup,
    ControlLifecycleEvent::PluginSetupAck {
        status: SETUP_ACK_STATUS_READY,
    },
    ControlLifecycleEvent::RunViaSharedMemory,
    ControlLifecycleEvent::HostQuit,
];

/// Typed errors returned by control lifecycle validation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ControlLifecycleError {
    /// A lifecycle event was observed before its prerequisites completed.
    #[error("control lifecycle event {event:?} is invalid in state {state:?}")]
    UnexpectedEvent {
        /// Lifecycle state when the event was observed.
        state: ControlLifecycleState,
        /// Event that violated lifecycle order.
        event: ControlLifecycleEvent,
    },
    /// A non-ready `SetupAck` tried to enter the run lifecycle.
    #[error("setup acknowledgement status {status} does not enter the run lifecycle")]
    NonReadySetupAck {
        /// Nonzero `SetupAck.status` byte.
        status: u8,
    },
    /// A control frame was observed after the run entered the shared-memory hot path.
    #[error("control frame {tag:?} with direction {direction:?} was observed during run")]
    ControlFrameDuringRun {
        /// Tag observed during the run.
        tag: ControlTag,
        /// Direction registered for the tag.
        direction: ControlDirection,
    },
    /// The trace ended before the normal lifecycle reached `Quit`.
    #[error("control lifecycle ended incomplete in state {state:?}")]
    IncompleteLifecycle {
        /// Final state reached by the trace.
        state: ControlLifecycleState,
    },
}

/// Typed errors returned by lifecycle-aware control stream operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ControlLifecycleIoError {
    /// The operation violated the control lifecycle.
    #[error("control lifecycle violation")]
    Lifecycle {
        /// Underlying lifecycle error.
        source: ControlLifecycleError,
    },
    /// A control-frame read or write failed.
    #[error("control lifecycle I/O failed")]
    Io {
        /// Underlying frame I/O error.
        source: FrameIoError,
    },
    /// A control frame failed byte-level decoding.
    #[error("control lifecycle frame decode failed")]
    Decode {
        /// Underlying frame decode error.
        source: FrameDecodeError,
    },
    /// A handshake operation failed.
    #[error("control lifecycle handshake failed")]
    Handshake {
        /// Underlying handshake error.
        source: HandshakeError,
    },
    /// A setup-completion operation failed.
    #[error("control lifecycle setup completion failed")]
    SetupCompletion {
        /// Underlying setup-completion error.
        source: SetupCompletionError,
    },
    /// A setup descriptor handover operation failed.
    #[cfg(unix)]
    #[error("control lifecycle setup descriptor handover failed")]
    DescriptorHandover {
        /// Underlying descriptor handover error.
        source: DescriptorHandoverError,
    },
}

impl From<ControlLifecycleError> for ControlLifecycleIoError {
    fn from(source: ControlLifecycleError) -> Self {
        Self::Lifecycle { source }
    }
}

impl From<FrameIoError> for ControlLifecycleIoError {
    fn from(source: FrameIoError) -> Self {
        Self::Io { source }
    }
}

impl From<FrameDecodeError> for ControlLifecycleIoError {
    fn from(source: FrameDecodeError) -> Self {
        Self::Decode { source }
    }
}

impl From<HandshakeError> for ControlLifecycleIoError {
    fn from(source: HandshakeError) -> Self {
        Self::Handshake { source }
    }
}

impl From<SetupCompletionError> for ControlLifecycleIoError {
    fn from(source: SetupCompletionError) -> Self {
        Self::SetupCompletion { source }
    }
}

#[cfg(unix)]
impl From<DescriptorHandoverError> for ControlLifecycleIoError {
    fn from(source: DescriptorHandoverError) -> Self {
        Self::DescriptorHandover { source }
    }
}

/// A validator for the ordered control lifecycle of one node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControlLifecycle {
    state: ControlLifecycleState,
}

impl ControlLifecycle {
    /// Returns a new lifecycle validator in the disconnected state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ControlLifecycleState::Disconnected,
        }
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ControlLifecycleState {
        self.state
    }

    /// Applies one observed lifecycle event.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleError`] when the event is out of order, when a
    /// nonzero `SetupAck` tries to enter the run lifecycle, or when any control
    /// frame other than `Quit` is observed after the run has moved to shared
    /// memory.
    pub fn observe(
        &mut self,
        event: ControlLifecycleEvent,
    ) -> Result<ControlLifecycleState, ControlLifecycleError> {
        let state = next_lifecycle_state(self.state, event)?;
        self.state = state;
        Ok(state)
    }
}

/// A control stream coupled to the normal host/plugin lifecycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlLifecycleStream<S> {
    stream: S,
    lifecycle: ControlLifecycle,
}

impl<S> ControlLifecycleStream<S> {
    /// Wraps a connected Unix stream socket pair endpoint.
    ///
    /// The caller owns construction of the `AF_UNIX`/`SOCK_STREAM` socket pair;
    /// this method records the lifecycle connect event before any frame I/O is
    /// permitted.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] if the connect event is invalid for a
    /// newly-created lifecycle.
    pub fn connected_unix_stream(stream: S) -> Result<Self, ControlLifecycleIoError> {
        let mut lifecycle = ControlLifecycle::new();
        lifecycle.observe(ControlLifecycleEvent::ConnectUnixStreamSocketPair)?;
        Ok(Self { stream, lifecycle })
    }

    /// Restores an authenticated replacement stream directly into RUN.
    ///
    /// A hot-fork child does not replay the template's setup handshake. Its
    /// child reinitializer first authenticates and installs a fresh private
    /// control endpoint, then uses this constructor so the only accepted frame
    /// remains the terminal host `Quit`. Callers must not use this constructor
    /// for an unvalidated or template-shared endpoint.
    #[must_use]
    pub fn restored_run_via_shared_memory(stream: S) -> Self {
        Self {
            stream,
            lifecycle: ControlLifecycle {
                state: ControlLifecycleState::RunningViaSharedMemory,
            },
        }
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ControlLifecycleState {
        self.lifecycle.state()
    }

    /// Returns the wrapped stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Borrows the setup-phase stream for plugin setup failure reporting.
    ///
    /// Descriptor mapping, wake-fd arming, and callback registration can fail
    /// after the lifecycle has accepted `Setup` but before the ready
    /// acknowledgement is committed. Those paths must send a nonzero
    /// `SetupAck` through the same socket without pretending that the node
    /// entered the run lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] unless the lifecycle is waiting for
    /// `Setup` or has consumed it and is waiting for the plugin acknowledgement.
    pub fn plugin_setup_io_mut(&mut self) -> Result<&mut S, ControlLifecycleIoError> {
        match self.lifecycle.state() {
            ControlLifecycleState::HelloAcknowledged | ControlLifecycleState::SetupSent => {
                Ok(&mut self.stream)
            }
            state => Err(ControlLifecycleError::UnexpectedEvent {
                state,
                event: ControlLifecycleEvent::HostSetup,
            }
            .into()),
        }
    }

    /// Records a ready `SetupAck` already written by plugin setup code.
    ///
    /// This is the lifecycle counterpart to [`Self::plugin_setup_io_mut`] for
    /// setup code that must validate callback and wake-fd ownership before it
    /// can choose between a ready or failure acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] unless the lifecycle is waiting for
    /// setup acknowledgement.
    pub fn plugin_commit_ready_setup_ack(&mut self) -> Result<(), ControlLifecycleIoError> {
        self.lifecycle
            .observe(ControlLifecycleEvent::PluginSetupAck {
                status: SETUP_ACK_STATUS_READY,
            })
            .map(|_state| ())
            .map_err(ControlLifecycleIoError::from)
    }
}

#[cfg(unix)]
impl<S> AsRawFd for ControlLifecycleStream<S>
where
    S: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

impl<S> ControlLifecycleStream<S>
where
    S: Read + Write,
{
    /// Runs the host side of `Hello`/`HelloAck` through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the frame I/O fails, when the
    /// decoded message is invalid for the handshake, or when the observed
    /// lifecycle event is out of order.
    pub fn host_accept_handshake(
        &mut self,
        config: HostHandshakeConfig,
    ) -> Result<NegotiatedHandshake, ControlLifecycleIoError> {
        let frame = read_control_frame(&mut self.stream)?;
        let message = control_decode_plugin_msg(&frame)?;
        self.lifecycle
            .observe(ControlLifecycleEvent::from_plugin_msg(&message))?;

        let negotiated = host_negotiate_handshake(message, config)?;
        let ack = HostMsg::HelloAck {
            proto_version: negotiated.proto_version,
            abi_version: negotiated.abi_version,
            slot_index: negotiated.slot_index,
            node_count: negotiated.node_count,
        };
        let ack = control_encode_host_msg(&ack);
        write_control_frame(&mut self.stream, &ack)?;
        self.lifecycle
            .observe(ControlLifecycleEvent::HostHelloAck)?;
        Ok(negotiated)
    }

    /// Runs the plugin side of `Hello`/`HelloAck` through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the frame I/O fails, when the
    /// decoded host acknowledgement is invalid, or when the observed lifecycle
    /// event is out of order.
    pub fn plugin_start_handshake(
        &mut self,
        config: PluginHandshakeConfig,
    ) -> Result<NegotiatedHandshake, ControlLifecycleIoError> {
        let mut lifecycle = self.lifecycle.clone();
        lifecycle.observe(ControlLifecycleEvent::PluginHello)?;
        let hello = PluginMsg::Hello {
            proto_version: config.proto_version,
            abi_version: config.abi_version,
        };
        let hello = control_encode_plugin_msg(&hello);
        write_control_frame(&mut self.stream, &hello)?;
        self.lifecycle = lifecycle;

        let frame = read_control_frame(&mut self.stream)?;
        let message = control_decode_host_msg(&frame)?;
        let negotiated = plugin_validate_handshake_ack(message.clone(), config)?;
        self.lifecycle
            .observe(ControlLifecycleEvent::from_host_msg(&message))?;
        Ok(negotiated)
    }
}

impl<S> ControlLifecycleStream<S>
where
    S: Read,
{
    /// Reads and validates the host-side `SetupAck` through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the frame cannot be read or
    /// decoded, when the decoded message is not a ready `SetupAck`, or when the
    /// lifecycle is not waiting for setup completion.
    pub fn host_accept_setup_ack(
        &mut self,
    ) -> Result<SchedulableNodeSetup, ControlLifecycleIoError> {
        ensure_waiting_for_setup_ack(self.lifecycle.state())?;
        let frame = read_control_frame(&mut self.stream)?;
        let message = control_decode_plugin_msg(&frame)?;
        let setup = host_validate_setup_ack(message.clone())?;
        self.lifecycle
            .observe(ControlLifecycleEvent::from_plugin_msg(&message))?;
        Ok(setup)
    }

    /// Reads one host-side control frame while the node is running via shared memory.
    ///
    /// The host is the side that initiates `Quit`, so any inbound frame observed
    /// by the host during the run is a run-phase protocol fault.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when reading or decoding fails, when
    /// the lifecycle is not in the run phase, or when any control frame is
    /// observed.
    pub fn host_read_run_control_frame(
        &mut self,
    ) -> Result<ControlLifecycleState, ControlLifecycleIoError> {
        ensure_running_via_shared_memory(self.lifecycle.state())?;
        let frame = read_control_frame(&mut self.stream)?;
        let tag = control_frame_tag(&frame)?;
        Err(ControlLifecycleError::ControlFrameDuringRun {
            tag,
            direction: tag.direction(),
        }
        .into())
    }

    /// Reads one plugin-side control frame while the node is running via shared memory.
    ///
    /// `Quit` from the host transitions out of the run. Any other valid control
    /// frame is a run-phase protocol fault because runtime traffic must stay in
    /// shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when reading or decoding fails, when
    /// the lifecycle is not in the run phase, or when the next frame is any
    /// control frame other than host `Quit`.
    pub fn plugin_read_run_control_frame(
        &mut self,
    ) -> Result<ControlLifecycleState, ControlLifecycleIoError> {
        ensure_running_via_shared_memory(self.lifecycle.state())?;
        let frame = read_control_frame(&mut self.stream)?;
        let tag = control_frame_tag(&frame)?;
        if tag != ControlTag::Quit {
            return Err(ControlLifecycleError::ControlFrameDuringRun {
                tag,
                direction: tag.direction(),
            }
            .into());
        }

        let message = control_decode_host_msg(&frame)?;
        self.lifecycle
            .observe(ControlLifecycleEvent::from_host_msg(&message))
            .map_err(ControlLifecycleIoError::from)
    }
}

impl<S> ControlLifecycleStream<S>
where
    S: Write,
{
    /// Sends a terminal non-ready `SetupAck` without entering the run lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when setup has not begun or the
    /// failure acknowledgement cannot be written.
    pub fn plugin_send_setup_failure_ack(&mut self) -> Result<(), ControlLifecycleIoError> {
        match self.lifecycle.state() {
            ControlLifecycleState::HelloAcknowledged | ControlLifecycleState::SetupSent => {}
            state => {
                return Err(ControlLifecycleError::UnexpectedEvent {
                    state,
                    event: ControlLifecycleEvent::PluginSetupAck {
                        status: SETUP_ACK_STATUS_SETUP_FAILED,
                    },
                }
                .into());
            }
        }
        plugin_send_setup_ack(&mut self.stream, SETUP_ACK_STATUS_SETUP_FAILED)?;
        Ok(())
    }

    /// Sends a ready `SetupAck` through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the stream write fails or when
    /// the lifecycle is not waiting for setup completion.
    pub fn plugin_send_ready_setup_ack(&mut self) -> Result<(), ControlLifecycleIoError> {
        let mut lifecycle = self.lifecycle.clone();
        lifecycle.observe(ControlLifecycleEvent::PluginSetupAck {
            status: SETUP_ACK_STATUS_READY,
        })?;
        plugin_send_setup_ack(&mut self.stream, SETUP_ACK_STATUS_READY)?;
        self.lifecycle = lifecycle;
        Ok(())
    }

    /// Sends `Quit` through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when `Quit` is attempted before the
    /// shared-memory run starts, or when writing the frame fails.
    pub fn host_send_quit(&mut self) -> Result<(), ControlLifecycleIoError> {
        self.host_send_quit_with_writer(write_control_frame)
    }

    /// Sends `Quit` through an injected bounded full-frame writer.
    ///
    /// The writer receives the existing canonical frame and must retain its
    /// cursor across partial writes and polling retries. Lifecycle ownership
    /// commits only after the complete write succeeds. An uncertain write must
    /// fail and must not be restarted from the beginning of the frame.
    ///
    /// # Errors
    /// Refuses teardown before shared-memory RUN or propagates a writer error
    /// without advancing lifecycle state.
    pub fn host_send_quit_with_writer(
        &mut self,
        writer: impl FnOnce(&mut S, &[u8]) -> Result<(), FrameIoError>,
    ) -> Result<(), ControlLifecycleIoError> {
        let mut lifecycle = self.lifecycle.clone();
        lifecycle.observe(ControlLifecycleEvent::HostQuit)?;
        let quit = control_encode_host_msg(&HostMsg::Quit);
        writer(&mut self.stream, &quit)?;
        self.lifecycle = lifecycle;
        Ok(())
    }
}

impl<S> ControlLifecycleStream<S> {
    /// Enters the shared-memory run phase after ready setup acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when setup has not completed
    /// successfully.
    pub fn enter_run_via_shared_memory(&mut self) -> Result<(), ControlLifecycleIoError> {
        self.lifecycle
            .observe(ControlLifecycleEvent::RunViaSharedMemory)
            .map(|_| ())
            .map_err(ControlLifecycleIoError::from)
    }
}

#[cfg(unix)]
impl<S> ControlLifecycleStream<S>
where
    S: AsRawFd,
{
    /// Sends `Setup` and its fixed-order descriptors through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the lifecycle is not waiting for
    /// setup, or when `sendmsg` fails to transfer the frame and descriptors.
    pub fn host_send_setup_with_descriptors(
        &mut self,
        region_len: u64,
        descriptors: SetupDescriptorFds,
    ) -> Result<(), ControlLifecycleIoError> {
        let mut lifecycle = self.lifecycle.clone();
        lifecycle.observe(ControlLifecycleEvent::HostSetup)?;
        send_setup_with_descriptors(self.stream.as_raw_fd(), region_len, descriptors)?;
        self.lifecycle = lifecycle;
        Ok(())
    }

    /// Receives `Setup` and its fixed-order descriptors through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the lifecycle is not waiting for
    /// setup, or when descriptor handover fails.
    pub fn plugin_recv_setup_with_descriptors(
        &mut self,
    ) -> Result<ReceivedSetup, ControlLifecycleIoError> {
        let mut lifecycle = self.lifecycle.clone();
        lifecycle.observe(ControlLifecycleEvent::HostSetup)?;
        let setup = recv_setup_with_descriptors(self.stream.as_raw_fd())?;
        self.lifecycle = lifecycle;
        Ok(setup)
    }
}

/// Validates an ordered control lifecycle trace and returns the final state.
///
/// # Errors
///
/// Returns [`ControlLifecycleError`] when any event violates the normal control
/// lifecycle or when a control frame is observed during the shared-memory run.
pub fn validate_control_lifecycle_trace(
    events: impl IntoIterator<Item = ControlLifecycleEvent>,
) -> Result<ControlLifecycleState, ControlLifecycleError> {
    let mut lifecycle = ControlLifecycle::new();
    for event in events {
        lifecycle.observe(event)?;
    }
    Ok(lifecycle.state())
}

/// Validates that an ordered control lifecycle trace reaches `Quit`.
///
/// # Errors
///
/// Returns [`ControlLifecycleError`] when any event violates lifecycle order,
/// when a control frame is observed during the shared-memory run, or when the
/// trace ends before `Quit`.
pub fn validate_complete_control_lifecycle(
    events: impl IntoIterator<Item = ControlLifecycleEvent>,
) -> Result<(), ControlLifecycleError> {
    let state = validate_control_lifecycle_trace(events)?;
    if state == ControlLifecycleState::QuitSent {
        Ok(())
    } else {
        Err(ControlLifecycleError::IncompleteLifecycle { state })
    }
}

fn next_lifecycle_state(
    state: ControlLifecycleState,
    event: ControlLifecycleEvent,
) -> Result<ControlLifecycleState, ControlLifecycleError> {
    if state == ControlLifecycleState::RunningViaSharedMemory {
        return match event {
            ControlLifecycleEvent::RunViaSharedMemory => {
                Ok(ControlLifecycleState::RunningViaSharedMemory)
            }
            ControlLifecycleEvent::HostQuit => Ok(ControlLifecycleState::QuitSent),
            _ => match event.control_tag() {
                Some(tag) => Err(ControlLifecycleError::ControlFrameDuringRun {
                    tag,
                    direction: tag.direction(),
                }),
                None => Err(ControlLifecycleError::UnexpectedEvent { state, event }),
            },
        };
    }

    match (state, event) {
        (
            ControlLifecycleState::Disconnected,
            ControlLifecycleEvent::ConnectUnixStreamSocketPair,
        ) => Ok(ControlLifecycleState::Connected),
        (ControlLifecycleState::Connected, ControlLifecycleEvent::PluginHello) => {
            Ok(ControlLifecycleState::HelloSent)
        }
        (ControlLifecycleState::HelloSent, ControlLifecycleEvent::HostHelloAck) => {
            Ok(ControlLifecycleState::HelloAcknowledged)
        }
        (ControlLifecycleState::HelloAcknowledged, ControlLifecycleEvent::HostSetup) => {
            Ok(ControlLifecycleState::SetupSent)
        }
        (
            ControlLifecycleState::SetupSent,
            ControlLifecycleEvent::PluginSetupAck {
                status: SETUP_ACK_STATUS_READY,
            },
        ) => Ok(ControlLifecycleState::SetupAcknowledged),
        (ControlLifecycleState::SetupSent, ControlLifecycleEvent::PluginSetupAck { status }) => {
            Err(ControlLifecycleError::NonReadySetupAck { status })
        }
        (ControlLifecycleState::SetupAcknowledged, ControlLifecycleEvent::RunViaSharedMemory) => {
            Ok(ControlLifecycleState::RunningViaSharedMemory)
        }
        _ => Err(ControlLifecycleError::UnexpectedEvent { state, event }),
    }
}

fn ensure_running_via_shared_memory(
    state: ControlLifecycleState,
) -> Result<(), ControlLifecycleError> {
    if state == ControlLifecycleState::RunningViaSharedMemory {
        Ok(())
    } else {
        Err(ControlLifecycleError::UnexpectedEvent {
            state,
            event: ControlLifecycleEvent::RunViaSharedMemory,
        })
    }
}

fn ensure_waiting_for_setup_ack(state: ControlLifecycleState) -> Result<(), ControlLifecycleError> {
    if state == ControlLifecycleState::SetupSent {
        Ok(())
    } else {
        Err(ControlLifecycleError::UnexpectedEvent {
            state,
            event: ControlLifecycleEvent::PluginSetupAck {
                status: SETUP_ACK_STATUS_READY,
            },
        })
    }
}
