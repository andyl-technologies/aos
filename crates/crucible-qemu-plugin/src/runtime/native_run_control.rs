//! Retained bounded RUN-control prefixes for the original fixed-root worker.
//!
//! Each nonblocking socket read occurs under the actual modeled worker gate and
//! writes into installed process-lifetime custody. A partially received length
//! or body never lives only on a worker stack. The original typed RUN lifecycle
//! is preserved through its I/O adapter, so only the genuine terminal Quit is
//! accepted. This is one worker's storage, not whole-root input or Ready proof.

use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use crucible_protocol::{
    ControlLifecycleState, ControlLifecycleStream, FRAME_LENGTH_PREFIX_SIZE, MAX_FRAME_SIZE,
};
use thiserror::Error;

use super::LiveRuntimeTeardownTrigger;
use crate::PluginHostQuit;

const STORAGE_BYTES: usize = FRAME_LENGTH_PREFIX_SIZE + MAX_FRAME_SIZE as usize;

/// Supplies a real socket with model-only RUN lifecycle setup for custody tests.
#[cfg(test)]
pub(crate) fn test_running_pair() -> (UnixStream, ControlLifecycleStream<UnixStream>) {
    super::tests::running_plugin_control_pair()
}

/// Refuses an incomplete native worker cut without abandoning original socket bytes.
#[derive(Debug, Error)]
pub(crate) enum NativeRunControlError {
    #[error("original run-control owner is busy or poisoned")]
    Ownership,
    #[error("original control lifecycle is not RUN")]
    NotRunning,
    #[error("original run-control socket failed")]
    Socket(#[from] io::Error),
}

struct StoredControl {
    socket: UnixStream,
    socket_identity: (u64, u64),
    bytes: [u8; STORAGE_BYTES],
    received: usize,
    expected: Option<usize>,
    terminal: Option<StoredTerminal>,
}

#[derive(Clone)]
enum StoredTerminal {
    Quit(PluginHostQuit),
    Fault(String),
}

struct OriginalReadCursor {
    original: Arc<Mutex<StoredControl>>,
    offset: usize,
}

impl Read for OriginalReadCursor {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        let original = self
            .original
            .try_lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let available = original.received.saturating_sub(self.offset);
        let count = available.min(destination.len());
        destination[..count].copy_from_slice(&original.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

/// Owns the same actual socket, typed lifecycle and every partial original prefix.
pub(crate) struct NativeRunControlCustody {
    original: Arc<Mutex<StoredControl>>,
    lifecycle: Mutex<ControlLifecycleStream<OriginalReadCursor>>,
}

/// Retains original endpoint custody even when preparation is refused.
pub(crate) struct NativeRunControlPreparation {
    /// Owns the real stream and every future consumed prefix.
    pub(crate) owner: Arc<NativeRunControlCustody>,
    /// Refuses preparation without substituting a RUN lifecycle or dropping the owner.
    pub(crate) status: Result<(), NativeRunControlError>,
}

/// Copies one bounded original prefix without reading or changing its actual owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeRunControlSnapshot {
    /// Identifies the real original endpoint device and inode.
    pub(crate) socket_identity: (u64, u64),
    /// Preserves the complete fixed backing storage, including unused bytes.
    pub(crate) backing: [u8; STORAGE_BYTES],
    /// Counts the actual consumed prefix within that backing storage.
    pub(crate) received: usize,
    /// Preserves the original declared extent once its entire prefix was received.
    pub(crate) expected: Option<usize>,
    /// Preserves the same typed lifecycle without manufacturing another RUN owner.
    pub(crate) lifecycle: ControlLifecycleState,
    /// Reports that an original terminal disposition is retained, without native effect proof.
    pub(crate) terminal: bool,
}

impl NativeRunControlCustody {
    /// Retains the actual endpoint and reports preparation status separately.
    ///
    /// A refused non-RUN or unconfigured socket remains owned by the returned
    /// object. The installed runtime stores that owner before handling failure;
    /// refusal never silently closes or drops consumed/unread original material.
    pub(crate) fn prepare(
        control: ControlLifecycleStream<UnixStream>,
    ) -> NativeRunControlPreparation {
        let mut status = if control.state() == ControlLifecycleState::RunningViaSharedMemory {
            Ok(())
        } else {
            Err(NativeRunControlError::NotRunning)
        };
        let (lifecycle, original) = control.map_stream_with_context(|socket| {
            let metadata = socket
                .as_fd()
                .try_clone_to_owned()
                .and_then(|descriptor| std::fs::File::from(descriptor).metadata());
            let identity = match metadata {
                Ok(metadata) => (metadata.dev(), metadata.ino()),
                Err(error) => {
                    status = Err(NativeRunControlError::Socket(error));
                    (0, 0)
                }
            };
            if let Err(error) = socket.set_nonblocking(true) {
                status = Err(NativeRunControlError::Socket(error));
            }
            let storage = Arc::new(Mutex::new(StoredControl {
                socket,
                socket_identity: identity,
                bytes: [0; STORAGE_BYTES],
                received: 0,
                expected: None,
                terminal: None,
            }));
            (
                OriginalReadCursor {
                    original: Arc::clone(&storage),
                    offset: 0,
                },
                storage,
            )
        });
        let owner = Arc::new(Self {
            original,
            lifecycle: Mutex::new(lifecycle),
        });
        NativeRunControlPreparation { owner, status }
    }

    /// Returns the original descriptor for non-owning readiness polling.
    ///
    /// # Errors
    /// Refuses busy or poisoned original custody.
    pub(crate) fn descriptor(&self) -> Result<i32, NativeRunControlError> {
        use std::os::fd::AsRawFd;
        Ok(self
            .original
            .try_lock()
            .map_err(|_| NativeRunControlError::Ownership)?
            .socket
            .as_raw_fd())
    }

    /// Retains one bounded physical prefix before interpreting any terminal effect.
    ///
    /// The only installed reader calls this under admission obtained before
    /// nonblocking receive. A source cut holds that same worker gate first.
    ///
    /// # Errors
    /// Refuses busy/poisoned original ownership. Socket and format faults become
    /// retained terminal diagnostics with the actual prefix still available.
    pub(crate) fn receive_step(
        &self,
    ) -> Result<Option<LiveRuntimeTeardownTrigger>, NativeRunControlError> {
        let mut lifecycle = self
            .lifecycle
            .try_lock()
            .map_err(|_| NativeRunControlError::Ownership)?;
        let mut original = self
            .original
            .try_lock()
            .map_err(|_| NativeRunControlError::Ownership)?;
        if original.terminal.is_none()
            && lifecycle.state() != ControlLifecycleState::RunningViaSharedMemory
        {
            return Err(NativeRunControlError::NotRunning);
        }
        if let Some(terminal) = &original.terminal {
            return Ok(Some(terminal.trigger()));
        }
        let target = original.expected.unwrap_or(FRAME_LENGTH_PREFIX_SIZE);
        if original.received < target {
            let received = original.received;
            let StoredControl { socket, bytes, .. } = &mut *original;
            match socket.read(&mut bytes[received..target]) {
                Ok(0) => {
                    original.terminal = Some(StoredTerminal::Fault(
                        "original run-control ended before a complete terminal frame".into(),
                    ))
                }
                Ok(count) => original.received += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(None);
                }
                Err(error) => {
                    original.terminal = Some(StoredTerminal::Fault(format!(
                        "original run-control read failed: {error}"
                    )))
                }
            }
        }
        if original.received == FRAME_LENGTH_PREFIX_SIZE
            && original.expected.is_none()
            && original.terminal.is_none()
        {
            let length = u32::from_be_bytes(
                original.bytes[..FRAME_LENGTH_PREFIX_SIZE]
                    .try_into()
                    .map_err(|_| NativeRunControlError::Ownership)?,
            );
            if length == 0 || length > MAX_FRAME_SIZE {
                original.terminal = Some(StoredTerminal::Fault(
                    "original run-control extent violates its finite frame bound".into(),
                ));
            } else {
                original.expected = Some(FRAME_LENGTH_PREFIX_SIZE + length as usize);
            }
        }
        if original.terminal.is_none() && original.expected != Some(original.received) {
            return Ok(None);
        }
        if original.terminal.is_none() {
            drop(original);
            let terminal = match PluginHostQuit::read_from_run_control(&mut lifecycle) {
                Ok(quit) => StoredTerminal::Quit(quit),
                Err(error) => StoredTerminal::Fault(error.to_string()),
            };
            original = self
                .original
                .try_lock()
                .map_err(|_| NativeRunControlError::Ownership)?;
            original.terminal = Some(terminal);
        }
        Ok(original.terminal.as_ref().map(StoredTerminal::trigger))
    }

    /// Copies actual retained storage without receiving another byte or admitting effects.
    ///
    /// # Errors
    /// Refuses busy or poisoned custody. Worker/reader fencing is a separate obligation.
    pub(crate) fn snapshot(&self) -> Result<NativeRunControlSnapshot, NativeRunControlError> {
        self.try_snapshot()?.ok_or(NativeRunControlError::Ownership)
    }

    /// Copies the same original storage using nonblocking ownership attempts.
    ///
    /// # Errors
    /// Refuses poison. None reports only a concurrently owned original prefix.
    pub(crate) fn try_snapshot(
        &self,
    ) -> Result<Option<NativeRunControlSnapshot>, NativeRunControlError> {
        let lifecycle = self.lifecycle.try_lock();
        let lifecycle = match lifecycle {
            Ok(lifecycle) => lifecycle,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(NativeRunControlError::Ownership);
            }
        };
        let original = match self.original.try_lock() {
            Ok(original) => original,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(NativeRunControlError::Ownership);
            }
        };
        Ok(Some(NativeRunControlSnapshot {
            socket_identity: original.socket_identity,
            backing: original.bytes,
            received: original.received,
            expected: original.expected,
            lifecycle: lifecycle.state(),
            terminal: original.terminal.is_some(),
        }))
    }
}

impl StoredTerminal {
    fn trigger(&self) -> LiveRuntimeTeardownTrigger {
        match self {
            Self::Quit(quit) => LiveRuntimeTeardownTrigger::HostQuit(*quit),
            Self::Fault(diagnostic) => LiveRuntimeTeardownTrigger::RunControlFault {
                diagnostic: diagnostic.clone(),
            },
        }
    }
}

/// Receives through the actual modeled gate, keeping every partial prefix in custody.
pub(super) fn run_reader(
    custody: Arc<NativeRunControlCustody>,
    sender: impl Into<super::teardown_channel::TeardownSender>,
    workers: Arc<super::worker_quiescence::LiveWorkerQuiescence>,
) -> bool {
    use super::worker_quiescence::WORKER_RUN_CONTROL;
    let sender = sender.into();
    let descriptor = match custody.descriptor() {
        Ok(descriptor) => descriptor,
        Err(error) => {
            return sender
                .send(LiveRuntimeTeardownTrigger::RunControlFault {
                    diagnostic: error.to_string(),
                })
                .is_ok();
        }
    };
    loop {
        let idle = workers.idle(WORKER_RUN_CONTROL);
        let mut poll = libc::pollfd {
            fd: descriptor,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: The actual installed owner retains this descriptor and writable
        // scalar pollfd throughout the wait. No modeled clock is read or changed.
        let result = unsafe { libc::poll(&mut poll, 1, -1) };
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            drop(idle);
            continue;
        }
        // Hold admission precedes every physical nonblocking read. Already
        // consumed bytes belong to custody, not the idle worker's stack.
        let operation = idle.enter_before_nonblocking_receive();
        let trigger = if result < 0 || poll.revents & libc::POLLNVAL != 0 {
            Some(LiveRuntimeTeardownTrigger::RunControlFault {
                diagnostic: "original run-control readiness failed".into(),
            })
        } else {
            match custody.receive_step() {
                Ok(trigger) => trigger,
                Err(error) => Some(LiveRuntimeTeardownTrigger::RunControlFault {
                    diagnostic: error.to_string(),
                }),
            }
        };
        if let Some(trigger) = trigger {
            // Send remains inside original worker accounting. The sole teardown
            // owner admits its effect separately and may stay held indefinitely.
            let delivered = sender.send(trigger).is_ok();
            drop(operation);
            return delivered;
        }
        drop(operation);
    }
}

#[cfg(test)]
#[path = "native_run_control_tests.rs"]
mod tests;
