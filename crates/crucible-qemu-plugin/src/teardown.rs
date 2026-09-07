//! Teardown coordination for the QEMU plugin.
//!
//! The teardown core accepts only two shutdown proofs: the shared-memory
//! `shutdown_requested` flag or a `Quit` frame read through the control-protocol
//! lifecycle stream. Once either proof is consumed, the plugin marks its node
//! done, seals subsequent shared-memory access through this coordinator, and
//! invokes the QEMU shutdown hook supplied by the ABI layer.

use std::io::Read;

use thiserror::Error;

use crucible_protocol::{ControlLifecycleIoError, ControlLifecycleState, ControlLifecycleStream};
use crucible_shmem::{NodeSlot, RegionHeader};

use crate::shmem_ordering::PluginShmemOrdering;

/// Shutdown trigger accepted by the plugin teardown path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginTeardownTrigger {
    /// The shared-memory header's `shutdown_requested` flag was observed.
    ShutdownRequested,
    /// The host sent `Quit` on the control channel after the run began.
    HostQuit,
    /// The plugin rejected an unsolicited or malformed run-phase control frame.
    RunControlFault,
}

/// Proof that the shared-memory header requested shutdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginShutdownRequested {
    _private: (),
}

impl PluginShutdownRequested {
    /// Builds a shutdown proof from an acquire-loaded region header flag.
    ///
    /// # Errors
    ///
    /// Returns [`PluginTeardownError::ShutdownNotRequested`] when the header has
    /// not yet requested shutdown.
    pub fn from_region_header(header: &RegionHeader) -> Result<Self, PluginTeardownError> {
        if PluginShmemOrdering::observe_shutdown_requested(header) {
            Ok(Self { _private: () })
        } else {
            Err(PluginTeardownError::ShutdownNotRequested)
        }
    }
}

/// Proof that the host sent the control-channel `Quit` frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginHostQuit {
    _private: (),
}

impl PluginHostQuit {
    /// Reads host `Quit` from a lifecycle-validated run control stream.
    ///
    /// # Errors
    ///
    /// Returns [`PluginTeardownError::ControlQuit`] when the control stream does
    /// not yield a valid run-phase `Quit`.
    pub fn read_from_run_control<S>(
        control: &mut ControlLifecycleStream<S>,
    ) -> Result<Self, PluginTeardownError>
    where
        S: Read,
    {
        let state = control
            .plugin_read_run_control_frame()
            .map_err(|source| PluginTeardownError::ControlQuit { source })?;
        Self::from_quit_state(state)
    }

    #[cfg(test)]
    const fn test_quit() -> Self {
        Self { _private: () }
    }

    fn from_quit_state(state: ControlLifecycleState) -> Result<Self, PluginTeardownError> {
        if state == ControlLifecycleState::QuitSent {
            Ok(Self { _private: () })
        } else {
            Err(PluginTeardownError::HostQuitNotObserved { state })
        }
    }
}

/// Proof that plugin teardown has completed for this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginTeardownComplete {
    trigger: PluginTeardownTrigger,
}

impl PluginTeardownComplete {
    /// Returns the trigger that completed teardown.
    #[must_use]
    pub const fn trigger(self) -> PluginTeardownTrigger {
        self.trigger
    }
}

/// Scoped proof that the plugin may still touch shared memory.
#[derive(Debug)]
pub struct PluginShmemAccess<'a> {
    _teardown: &'a PluginTeardown,
}

/// Plugin-side hook used to initiate orderly QEMU shutdown.
pub trait PluginQemuShutdown {
    /// Starts QEMU's orderly shutdown path.
    ///
    /// # Errors
    ///
    /// Returns [`PluginQemuShutdownError`] when the hook cannot request QEMU
    /// shutdown.
    fn initiate_orderly_qemu_shutdown(&mut self) -> Result<(), PluginQemuShutdownError>;
}

impl<F> PluginQemuShutdown for F
where
    F: FnMut() -> Result<(), PluginQemuShutdownError>,
{
    fn initiate_orderly_qemu_shutdown(&mut self) -> Result<(), PluginQemuShutdownError> {
        self()
    }
}

/// Error returned by a plugin-side QEMU shutdown hook.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{operation} failed: {message}")]
pub struct PluginQemuShutdownError {
    /// Operation being attempted.
    pub operation: &'static str,
    /// Human-readable failure detail.
    pub message: String,
}

impl PluginQemuShutdownError {
    /// Creates a shutdown-hook error.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
        }
    }
}

/// Teardown state for one plugin instance.
#[derive(Debug, Default)]
pub struct PluginTeardown {
    completed: Option<PluginTeardownTrigger>,
}

impl PluginTeardown {
    /// Returns a new running teardown coordinator.
    #[must_use]
    pub const fn new() -> Self {
        Self { completed: None }
    }

    /// Returns the completed teardown trigger, if teardown has already run.
    #[must_use]
    pub const fn completed_trigger(&self) -> Option<PluginTeardownTrigger> {
        self.completed
    }

    /// Returns a shared-memory access token while teardown has not completed.
    ///
    /// # Errors
    ///
    /// Returns [`PluginTeardownError::ShmemAccessAfterTeardown`] after either
    /// shutdown trigger has completed teardown.
    pub fn shmem_access(&self) -> Result<PluginShmemAccess<'_>, PluginTeardownError> {
        if let Some(trigger) = self.completed {
            Err(PluginTeardownError::ShmemAccessAfterTeardown { trigger })
        } else {
            Ok(PluginShmemAccess { _teardown: self })
        }
    }

    /// Teardown after observing the shared-memory shutdown flag.
    ///
    /// # Errors
    ///
    /// Returns [`PluginTeardownError`] when teardown has already completed or
    /// the QEMU shutdown hook fails.
    pub fn teardown_after_shutdown_requested<S>(
        &mut self,
        _shutdown_requested: PluginShutdownRequested,
        slot: &NodeSlot,
        shutdown: &mut S,
    ) -> Result<PluginTeardownComplete, PluginTeardownError>
    where
        S: PluginQemuShutdown,
    {
        self.complete_teardown(PluginTeardownTrigger::ShutdownRequested, slot, shutdown)
    }

    /// Teardown after observing host `Quit` on the control channel.
    ///
    /// # Errors
    ///
    /// Returns [`PluginTeardownError`] when teardown has already completed or
    /// the QEMU shutdown hook fails.
    pub fn teardown_after_host_quit<S>(
        &mut self,
        _host_quit: PluginHostQuit,
        slot: &NodeSlot,
        shutdown: &mut S,
    ) -> Result<PluginTeardownComplete, PluginTeardownError>
    where
        S: PluginQemuShutdown,
    {
        self.complete_teardown(PluginTeardownTrigger::HostQuit, slot, shutdown)
    }

    /// Teardown after rejecting run-phase control I/O.
    ///
    /// # Errors
    ///
    /// Returns [`PluginTeardownError`] when teardown has already completed or
    /// the fail-loud QEMU shutdown hook fails.
    pub fn teardown_after_run_control_fault<S>(
        &mut self,
        slot: &NodeSlot,
        shutdown: &mut S,
    ) -> Result<PluginTeardownComplete, PluginTeardownError>
    where
        S: PluginQemuShutdown,
    {
        self.complete_teardown(PluginTeardownTrigger::RunControlFault, slot, shutdown)
    }

    fn complete_teardown<S>(
        &mut self,
        trigger: PluginTeardownTrigger,
        slot: &NodeSlot,
        shutdown: &mut S,
    ) -> Result<PluginTeardownComplete, PluginTeardownError>
    where
        S: PluginQemuShutdown,
    {
        if let Some(completed_trigger) = self.completed {
            return Err(PluginTeardownError::AlreadyComplete {
                trigger: completed_trigger,
            });
        }

        PluginShmemOrdering::mark_done_after_shutdown(slot);
        self.completed = Some(trigger);
        shutdown
            .initiate_orderly_qemu_shutdown()
            .map_err(|source| PluginTeardownError::QemuShutdown { source })?;
        Ok(PluginTeardownComplete { trigger })
    }
}

/// Errors produced by plugin teardown coordination.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginTeardownError {
    /// The shared-memory shutdown flag was not set.
    #[error("shared-memory shutdown flag is not requested")]
    ShutdownNotRequested,
    /// The control lifecycle has not observed host `Quit`.
    #[error("host Quit was not observed; lifecycle state is {state:?}")]
    HostQuitNotObserved {
        /// Lifecycle state that was checked.
        state: ControlLifecycleState,
    },
    /// Reading host `Quit` from the run control stream failed.
    #[error("control-channel Quit was not observed")]
    ControlQuit {
        /// Underlying lifecycle or frame I/O error.
        source: ControlLifecycleIoError,
    },
    /// Teardown has already completed for this node.
    #[error("plugin teardown already completed after {trigger:?}")]
    AlreadyComplete {
        /// Trigger that completed teardown first.
        trigger: PluginTeardownTrigger,
    },
    /// Shared-memory access was requested after teardown completed.
    #[error("shared-memory access after plugin teardown completed for {trigger:?}")]
    ShmemAccessAfterTeardown {
        /// Trigger that completed teardown.
        trigger: PluginTeardownTrigger,
    },
    /// The QEMU shutdown hook failed.
    #[error("QEMU shutdown hook failed")]
    QemuShutdown {
        /// Underlying shutdown-hook error.
        source: PluginQemuShutdownError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::fs::File;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;

    #[cfg(unix)]
    use crucible_protocol::{
        HostMsg, PluginHandshakeConfig, SetupDescriptorFds, control_encode_host_msg,
        read_control_frame,
    };
    use crucible_shmem::{
        KIND_VM, NodeSlot, RegionConfig, RegionHeader, RegionLayout, STATUS_DONE,
    };

    #[test]
    fn teardown_shutdown_requested_marks_done_shutdowns_qemu_and_blocks_shmem_access() {
        let header = header();
        let slot = NodeSlot::new(KIND_VM);
        let mut teardown = PluginTeardown::new();
        let mut shutdown = RecordingShutdown::default();

        assert!(teardown.shmem_access().is_ok());
        header
            .request_shutdown([&slot])
            .unwrap_or_else(|error| panic!("shutdown request should publish: {error}"));
        let shutdown_requested = PluginShutdownRequested::from_region_header(&header)
            .unwrap_or_else(|error| panic!("shutdown proof should build: {error}"));

        let complete = teardown
            .teardown_after_shutdown_requested(shutdown_requested, &slot, &mut shutdown)
            .unwrap_or_else(|error| panic!("teardown should complete: {error}"));

        assert_eq!(complete.trigger(), PluginTeardownTrigger::ShutdownRequested);
        assert_eq!(
            teardown.completed_trigger(),
            Some(PluginTeardownTrigger::ShutdownRequested)
        );
        assert_eq!(slot.snapshot().status, STATUS_DONE);
        assert_eq!(shutdown.calls, 1);
        assert_shmem_blocked(&teardown, PluginTeardownTrigger::ShutdownRequested);
    }

    #[test]
    fn teardown_host_quit_marks_done_shutdowns_qemu_and_blocks_shmem_access() {
        let slot = NodeSlot::new(KIND_VM);
        let mut teardown = PluginTeardown::new();
        let mut shutdown = RecordingShutdown::default();
        let host_quit = PluginHostQuit::test_quit();

        let complete = teardown
            .teardown_after_host_quit(host_quit, &slot, &mut shutdown)
            .unwrap_or_else(|error| panic!("teardown should complete: {error}"));

        assert_eq!(complete.trigger(), PluginTeardownTrigger::HostQuit);
        assert_eq!(slot.snapshot().status, STATUS_DONE);
        assert_eq!(shutdown.calls, 1);
        assert_shmem_blocked(&teardown, PluginTeardownTrigger::HostQuit);
    }

    #[test]
    fn teardown_rejects_missing_shutdown_trigger_proofs() {
        let header = header();

        assert_eq!(
            PluginShutdownRequested::from_region_header(&header),
            Err(PluginTeardownError::ShutdownNotRequested)
        );
        assert_eq!(
            PluginHostQuit::from_quit_state(ControlLifecycleState::RunningViaSharedMemory),
            Err(PluginTeardownError::HostQuitNotObserved {
                state: ControlLifecycleState::RunningViaSharedMemory,
            })
        );
    }

    #[test]
    fn teardown_is_single_shot_and_does_not_touch_shmem_again() {
        let slot = NodeSlot::new(KIND_VM);
        let mut teardown = PluginTeardown::new();
        let mut shutdown = RecordingShutdown::default();
        let first = PluginHostQuit::test_quit();
        teardown
            .teardown_after_host_quit(first, &slot, &mut shutdown)
            .unwrap_or_else(|error| panic!("first teardown should complete: {error}"));
        let after_first = slot.snapshot();
        let second = PluginHostQuit::test_quit();

        assert_eq!(
            teardown.teardown_after_host_quit(second, &slot, &mut shutdown),
            Err(PluginTeardownError::AlreadyComplete {
                trigger: PluginTeardownTrigger::HostQuit,
            })
        );

        assert_eq!(slot.snapshot().publish_gen, after_first.publish_gen);
        assert_eq!(shutdown.calls, 1);
    }

    #[test]
    fn teardown_shutdown_hook_failure_still_blocks_shmem_access() {
        let slot = NodeSlot::new(KIND_VM);
        let mut teardown = PluginTeardown::new();
        let mut shutdown = RecordingShutdown {
            calls: 0,
            fail: true,
        };
        let host_quit = PluginHostQuit::test_quit();

        assert_eq!(
            teardown.teardown_after_host_quit(host_quit, &slot, &mut shutdown),
            Err(PluginTeardownError::QemuShutdown {
                source: PluginQemuShutdownError::new("test shutdown", "injected failure"),
            })
        );

        assert_eq!(slot.snapshot().status, STATUS_DONE);
        assert_eq!(shutdown.calls, 1);
        assert_shmem_blocked(&teardown, PluginTeardownTrigger::HostQuit);
    }

    #[cfg(unix)]
    #[test]
    fn teardown_host_quit_proof_reads_real_run_control_quit() {
        let (mut host_socket, plugin_socket) =
            UnixStream::pair().unwrap_or_else(|error| panic!("socket pair should open: {error}"));
        let mut plugin = plugin_running_lifecycle_stream(plugin_socket, &mut host_socket);

        host_socket
            .write_all(&control_encode_host_msg(&HostMsg::Quit))
            .unwrap_or_else(|error| panic!("host Quit write should succeed: {error}"));
        let host_quit = PluginHostQuit::read_from_run_control(&mut plugin)
            .unwrap_or_else(|error| panic!("host Quit proof should read: {error}"));

        assert_eq!(host_quit, PluginHostQuit::test_quit());
        assert_eq!(plugin.state(), ControlLifecycleState::QuitSent);
    }

    #[derive(Default)]
    struct RecordingShutdown {
        calls: u32,
        fail: bool,
    }

    impl PluginQemuShutdown for RecordingShutdown {
        fn initiate_orderly_qemu_shutdown(&mut self) -> Result<(), PluginQemuShutdownError> {
            self.calls += 1;
            if self.fail {
                Err(PluginQemuShutdownError::new(
                    "test shutdown",
                    "injected failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    fn header() -> RegionHeader {
        RegionHeader::new(layout())
    }

    fn layout() -> RegionLayout {
        RegionLayout::for_config(RegionConfig::new(2, 8, 0))
            .unwrap_or_else(|error| panic!("test region layout should be valid: {error}"))
    }

    fn assert_shmem_blocked(teardown: &PluginTeardown, trigger: PluginTeardownTrigger) {
        assert!(matches!(
            teardown.shmem_access(),
            Err(PluginTeardownError::ShmemAccessAfterTeardown {
                trigger: actual,
            }) if actual == trigger
        ));
    }

    #[cfg(unix)]
    fn plugin_running_lifecycle_stream(
        stream: UnixStream,
        peer: &mut UnixStream,
    ) -> ControlLifecycleStream<UnixStream> {
        let mut plugin = ControlLifecycleStream::connected_unix_stream(stream)
            .unwrap_or_else(|error| panic!("lifecycle stream should connect: {error}"));

        peer.write_all(&control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: 2,
            abi_version: 1,
            slot_index: 0,
            node_count: 1,
        }))
        .unwrap_or_else(|error| panic!("HelloAck should write: {error}"));
        plugin
            .plugin_start_handshake(PluginHandshakeConfig {
                proto_version: 2,
                abi_version: 1,
            })
            .unwrap_or_else(|error| panic!("plugin handshake should complete: {error}"));
        let _ = read_control_frame(peer)
            .unwrap_or_else(|error| panic!("plugin Hello should read: {error}"));

        let shmem =
            File::open("/dev/null").unwrap_or_else(|error| panic!("shmem fd should open: {error}"));
        let wake =
            File::open("/dev/zero").unwrap_or_else(|error| panic!("wake fd should open: {error}"));
        crucible_protocol::send_setup_with_descriptors(
            peer.as_raw_fd(),
            4096,
            SetupDescriptorFds {
                shmem_fd: shmem.as_raw_fd(),
                wake_fd: wake.as_raw_fd(),
                plugin_setup_plan_fd: shmem.as_raw_fd(),
            },
        )
        .unwrap_or_else(|error| panic!("setup descriptors should send: {error}"));
        let _ = plugin
            .plugin_recv_setup_with_descriptors()
            .unwrap_or_else(|error| panic!("setup descriptors should receive: {error}"));
        plugin
            .plugin_send_ready_setup_ack()
            .unwrap_or_else(|error| panic!("ready setup ack should send: {error}"));
        let _ = read_control_frame(peer)
            .unwrap_or_else(|error| panic!("SetupAck should read: {error}"));
        plugin
            .enter_run_via_shared_memory()
            .unwrap_or_else(|error| panic!("run lifecycle should enter: {error}"));

        assert_eq!(
            plugin.state(),
            ControlLifecycleState::RunningViaSharedMemory
        );
        plugin
    }
}
