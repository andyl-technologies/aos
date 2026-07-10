//! Setup completion for the QEMU plugin control protocol.
//!
//! The setup path consumes the `Setup` descriptors, maps the shared-memory
//! region for exactly the advertised byte length, validates the region header,
//! and arms the wake fd for later event-loop registration. The caller then
//! proves plugin callback ownership, registers the wake fd, and sends
//! `SetupAck(0)` with the returned completion token.
//! Descriptor validity comes from the fixed SCM_RIGHTS handoff; mmap lifetime is owned by the returned
//! [`PluginSetupCompletion`] token.

#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

use thiserror::Error;

#[cfg(unix)]
use crucible_protocol::{
    DescriptorHandoverError, ReceivedSetup, SETUP_ACK_STATUS_READY, SETUP_ACK_STATUS_SETUP_FAILED,
    SetupCompletionError, plugin_send_setup_ack, recv_setup_with_descriptors,
};
#[cfg(unix)]
use crucible_shmem::{
    MappedSetupRegion, RegionSetupValidationError, SetupRegionMapError, ValidatedSetupRegion,
    mmap_setup_region,
};

#[cfg(unix)]
use crate::{
    PluginCallbackCapabilities, PluginControlHandshake, QemuRegisterWakeFdFn,
    RequiredOwnedCallbacksRegistered, shmem_ordering::PluginShmemOrdering,
};

#[cfg(unix)]
mod boot_barrier;
#[cfg(unix)]
pub use boot_barrier::PluginSetupBootBarrierError;
#[cfg(unix)]
mod failure_ack;
#[cfg(unix)]
pub use failure_ack::{PluginSetupFailureStage, send_callback_registration_failure_ack};

/// An eventfd descriptor armed for setup-complete wake handling.
#[cfg(unix)]
#[derive(Debug)]
pub struct ArmedWakeFd {
    fd: OwnedFd,
}

#[cfg(unix)]
impl ArmedWakeFd {
    /// Arms an owned wake fd for run-loop integration.
    ///
    /// The current implementation configures close-on-exec and nonblocking
    /// operation on the descriptor received through the validated setup handoff.
    /// Linux exposes no stable descriptor-identity query for eventfd, so the
    /// implementation proves non-semaphore eventfd behavior by writing counters
    /// one and two, reading the aggregated value three, and proving the counter
    /// empty again. Non-Linux builds retain only the empty nonblocking-descriptor
    /// check for portable model tests; production QEMU activation remains Linux.
    /// Call [`Self::register_with_qemu`] before sending `SetupAck(0)`.
    ///
    /// # Errors
    ///
    /// Returns [`WakeFdArmError`] when descriptor flags cannot be read or
    /// updated.
    pub fn arm(fd: OwnedFd) -> Result<Self, WakeFdArmError> {
        set_close_on_exec(fd.as_raw_fd())?;
        set_nonblocking(fd.as_raw_fd())?;
        validate_wake_descriptor(fd.as_raw_fd())?;
        Ok(Self { fd })
    }

    /// Returns the raw descriptor number for QEMU registration.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Registers the armed wake fd with QEMU's main-loop wake surface.
    ///
    /// # Errors
    ///
    /// Returns [`WakeFdRegisterError::Rejected`] when QEMU rejects the armed
    /// descriptor.
    pub fn register_with_qemu(
        &self,
        register_wake_fd: QemuRegisterWakeFdFn,
    ) -> Result<RegisteredWakeFd, WakeFdRegisterError> {
        let status = register_wake_fd(self.as_raw_fd());
        if status == 0 {
            Ok(RegisteredWakeFd {
                fd: self.as_raw_fd(),
            })
        } else {
            Err(WakeFdRegisterError::Rejected { status })
        }
    }
}

/// Typed evidence that an armed wake fd was registered with QEMU.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredWakeFd {
    fd: RawFd,
}

#[cfg(unix)]
impl RegisteredWakeFd {
    /// Returns the registered descriptor number.
    #[must_use]
    pub const fn as_raw_fd(self) -> RawFd {
        self.fd
    }
}

/// Typed evidence that the plugin completed setup before acknowledging readiness.
///
/// The mapped shared-memory region stays live while this token is live; callers
/// keep it for the plugin process lifetime before any callback touches shmem.
#[cfg(unix)]
pub struct PluginSetupCompletion {
    mapped_region: MappedSetupRegion,
    validated_region: ValidatedSetupRegion,
    wake_fd: ArmedWakeFd,
    registered_wake_fd: Option<RegisteredWakeFd>,
}

#[cfg(unix)]
impl PluginSetupCompletion {
    /// Returns the mapped shared-memory region.
    #[must_use]
    pub const fn mapped_region(&self) -> &MappedSetupRegion {
        &self.mapped_region
    }

    /// Returns mutable access to the owned mapping for disjoint typed views.
    pub(crate) fn mapped_region_mut(&mut self) -> &mut MappedSetupRegion {
        &mut self.mapped_region
    }

    /// Returns the validated setup region header token.
    #[must_use]
    pub const fn validated_region(&self) -> ValidatedSetupRegion {
        self.validated_region
    }

    /// Returns the armed wake fd token.
    #[must_use]
    pub const fn wake_fd(&self) -> &ArmedWakeFd {
        &self.wake_fd
    }

    /// Returns evidence that the wake fd was registered with QEMU.
    #[must_use]
    pub const fn registered_wake_fd(&self) -> Option<RegisteredWakeFd> {
        self.registered_wake_fd
    }
}

/// Typed evidence that the ready `SetupAck(0)` was sent.
#[derive(Debug)]
pub struct PluginReadySetupAck {
    _private: (),
}

impl PluginReadySetupAck {
    const fn acknowledged(_owned_callbacks: &RequiredOwnedCallbacksRegistered) -> Self {
        Self { _private: () }
    }

    #[cfg(test)]
    pub(crate) const fn test_acknowledged() -> Self {
        Self { _private: () }
    }
}

/// Receives the setup frame and its fixed-order shared-memory and wake descriptors.
///
/// # Errors
///
/// Returns [`PluginSetupError::ReceiveSetup`] when the control socket does not
/// carry a valid `Setup` frame with exactly two `SCM_RIGHTS` descriptors, or
/// [`PluginSetupError::SendFailureAck`] when that setup failure cannot be
/// acknowledged.
#[cfg(unix)]
pub fn receive_setup_with_descriptors<S>(stream: &mut S) -> Result<ReceivedSetup, PluginSetupError>
where
    S: AsRawFd + Write,
{
    match recv_setup_with_descriptors(stream.as_raw_fd()) {
        Ok(setup) => Ok(setup),
        Err(source) => {
            send_setup_failure_ack(stream, PluginSetupFailureStage::ReceiveSetup)?;
            Err(PluginSetupError::ReceiveSetup { source })
        }
    }
}

/// Receives and prepares setup using the negotiated handshake assignment.
///
/// # Errors
///
/// Returns [`PluginSetupError`] when descriptor handover, mapping, header
/// validation, handshake/header cross-checking, wake-fd arming, or failure
/// acknowledgement fails.
#[cfg(unix)]
pub fn receive_and_prepare_setup_completion<S>(
    stream: &mut S,
    handshake: PluginControlHandshake,
) -> Result<PluginSetupCompletion, PluginSetupError>
where
    S: AsRawFd + Write,
{
    let setup = receive_setup_with_descriptors(stream)?;
    prepare_setup_completion(stream, setup, handshake)
}

/// Prepares plugin setup completion before callback registration and ready ack.
///
/// On success, this function has mapped the shared-memory descriptor for
/// exactly `Setup.region_len`, validated the shmem ABI marker and geometry, and
/// armed the wake fd after cross-checking the mapped region against the
/// negotiated handshake assignment. It intentionally defers QEMU wake-fd
/// registration and does not send `SetupAck(0)`; callers must first prove plugin
/// callback ownership, register the wake fd, and then call [`send_ready_setup_ack`].
/// On setup failure before callback registration, it
/// attempts to send a nonzero `SetupAck` before returning the setup error.
///
/// # Errors
///
/// Returns [`PluginSetupError`] when mapping, validation, handshake/header slot
/// consistency, wake-fd arming, or failure-acknowledgement I/O fails.
#[cfg(unix)]
pub fn prepare_setup_completion<W>(
    writer: &mut W,
    setup: ReceivedSetup,
    handshake: PluginControlHandshake,
) -> Result<PluginSetupCompletion, PluginSetupError>
where
    W: Write,
{
    let region_len = setup.region_len;
    let shmem_fd = setup.descriptors.shmem_fd;
    let wake_fd = setup.descriptors.wake_fd;

    // The mmap lifetime is carried by `MappedSetupRegion`; no raw pointer to
    // shmem escapes setup without that owner and the validated-region token.
    let mapped_region = match mmap_setup_region(shmem_fd.as_fd(), region_len) {
        Ok(mapped_region) => mapped_region,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::MapRegion)?;
            return Err(PluginSetupError::MapRegion { source });
        }
    };

    let header_snapshot = PluginShmemOrdering::setup_header_snapshot(&mapped_region);
    let validated_region = match PluginShmemOrdering::validate_setup_header(&mapped_region) {
        Ok(validated_region) => validated_region,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ValidateRegion)?;
            return Err(PluginSetupError::ValidateRegion { source });
        }
    };

    validate_setup_handshake_slot(writer, handshake, header_snapshot.node_count)?;

    let wake_fd = match ArmedWakeFd::arm(wake_fd) {
        Ok(wake_fd) => wake_fd,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ArmWakeFd)?;
            return Err(PluginSetupError::ArmWakeFd { source });
        }
    };
    Ok(PluginSetupCompletion {
        mapped_region,
        validated_region,
        wake_fd,
        registered_wake_fd: None,
    })
}

#[cfg(unix)]
fn validate_setup_handshake_slot<W>(
    writer: &mut W,
    handshake: PluginControlHandshake,
    region_node_count: u32,
) -> Result<(), PluginSetupError>
where
    W: Write,
{
    if handshake.node_count() != region_node_count {
        send_setup_failure_ack(writer, PluginSetupFailureStage::CrossCheckSlot)?;
        return Err(PluginSetupError::NodeCountMismatch {
            handshake_node_count: handshake.node_count(),
            region_node_count,
        });
    }

    if handshake.slot_index() >= region_node_count {
        send_setup_failure_ack(writer, PluginSetupFailureStage::CrossCheckSlot)?;
        return Err(PluginSetupError::SlotOutsideRegionNodeCount {
            slot_index: handshake.slot_index(),
            region_node_count,
        });
    }

    Ok(())
}

/// Sends `SetupAck(0)` after setup preparation and callback registration.
///
/// # Errors
///
/// Returns [`PluginSetupError::SendReadyAck`] when the ready acknowledgement
/// cannot be written and flushed.
#[cfg(unix)]
pub fn send_ready_setup_ack<W>(
    writer: &mut W,
    _callbacks: &PluginCallbackCapabilities,
    owned_callbacks: &RequiredOwnedCallbacksRegistered,
) -> Result<PluginReadySetupAck, PluginSetupError>
where
    W: Write,
{
    if owned_callbacks.setup().registered_wake_fd.is_none() {
        send_setup_failure_ack(writer, PluginSetupFailureStage::RegisterWakeFd)?;
        return Err(PluginSetupError::WakeFdNotRegistered);
    }
    plugin_send_setup_ack(writer, SETUP_ACK_STATUS_READY)
        .map_err(|source| PluginSetupError::SendReadyAck { source })?;
    Ok(PluginReadySetupAck::acknowledged(owned_callbacks))
}

#[cfg(unix)]
fn send_setup_failure_ack<W>(
    writer: &mut W,
    stage: PluginSetupFailureStage,
) -> Result<(), PluginSetupError>
where
    W: Write,
{
    plugin_send_setup_ack(writer, SETUP_ACK_STATUS_SETUP_FAILED)
        .map_err(|source| PluginSetupError::SendFailureAck { stage, source })
}

#[cfg(unix)]
fn set_close_on_exec(fd: RawFd) -> Result<(), WakeFdArmError> {
    // SAFETY: `fd` comes from an owned setup wake descriptor borrowed by
    // `ArmedWakeFd::arm`; `fcntl(F_GETFD)` reads descriptor flags only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(WakeFdArmError::Fcntl {
            operation: "read wake fd descriptor flags",
            errno: last_errno(),
        });
    }

    // SAFETY: `fd` is the same live owned setup wake descriptor, and
    // `fcntl(F_SETFD)` updates only descriptor flags.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(WakeFdArmError::Fcntl {
            operation: "mark wake fd close-on-exec",
            errno: last_errno(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn set_nonblocking(fd: RawFd) -> Result<(), WakeFdArmError> {
    // SAFETY: `fd` comes from an owned setup wake descriptor borrowed by
    // `ArmedWakeFd::arm`; `fcntl(F_GETFL)` reads descriptor status flags only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(WakeFdArmError::Fcntl {
            operation: "read wake fd status flags",
            errno: last_errno(),
        });
    }

    // SAFETY: `fd` is the same live owned setup wake descriptor, and
    // `fcntl(F_SETFL)` updates only descriptor status flags.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result < 0 {
        return Err(WakeFdArmError::Fcntl {
            operation: "mark wake fd nonblocking",
            errno: last_errno(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_wake_descriptor(fd: RawFd) -> Result<(), WakeFdArmError> {
    validate_empty_wake_descriptor(fd)?;
    #[cfg(target_os = "linux")]
    validate_eventfd_counter_semantics(fd)?;
    Ok(())
}

#[cfg(unix)]
fn validate_empty_wake_descriptor(fd: RawFd) -> Result<(), WakeFdArmError> {
    let mut value = 0_u64;
    loop {
        // SAFETY: `value` is writable for eight bytes and `fd` is owned by the
        // caller. Nonblocking mode guarantees this validation cannot park.
        let result = unsafe {
            libc::read(
                fd,
                (&mut value as *mut u64).cast::<libc::c_void>(),
                core::mem::size_of::<u64>(),
            )
        };
        if result > 0 {
            return Err(WakeFdArmError::NotEmpty {
                bytes_read: result as usize,
            });
        }
        if result == 0 {
            return Err(WakeFdArmError::EndOfFile);
        }
        let errno = last_errno();
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            return Ok(());
        }
        if errno == libc::EINTR {
            continue;
        }
        return Err(WakeFdArmError::Read { errno });
    }
}

#[cfg(target_os = "linux")]
fn validate_eventfd_counter_semantics(fd: RawFd) -> Result<(), WakeFdArmError> {
    write_eventfd_probe(fd, 1)?;
    write_eventfd_probe(fd, 2)?;

    let mut observed = 0_u64;
    let bytes_read = loop {
        // SAFETY: `observed` is writable for the exact eventfd counter width and
        // `fd` remains owned by the caller for this validation.
        let result = unsafe {
            libc::read(
                fd,
                (&mut observed as *mut u64).cast::<libc::c_void>(),
                core::mem::size_of::<u64>(),
            )
        };
        if result >= 0 {
            break result as usize;
        }
        let errno = last_errno();
        if errno != libc::EINTR {
            return Err(WakeFdArmError::EventFdProbeRead { errno });
        }
    };
    if bytes_read != core::mem::size_of::<u64>() || observed != 3 {
        return Err(WakeFdArmError::EventFdCounterSemantics {
            bytes_read,
            observed,
        });
    }
    validate_empty_wake_descriptor(fd)
}

#[cfg(target_os = "linux")]
fn write_eventfd_probe(fd: RawFd, value: u64) -> Result<(), WakeFdArmError> {
    loop {
        // SAFETY: `value` is readable for the exact eventfd counter width and
        // `fd` remains owned by the caller for this validation.
        let result = unsafe {
            libc::write(
                fd,
                (&value as *const u64).cast::<libc::c_void>(),
                core::mem::size_of::<u64>(),
            )
        };
        if result == core::mem::size_of::<u64>() as isize {
            return Ok(());
        }
        if result >= 0 {
            return Err(WakeFdArmError::EventFdProbeWriteSize {
                bytes_written: result as usize,
            });
        }
        let errno = last_errno();
        if errno != libc::EINTR {
            return Err(WakeFdArmError::EventFdProbeWrite { errno });
        }
    }
}

#[cfg(unix)]
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// An error produced while arming the setup wake fd.
#[cfg(unix)]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WakeFdArmError {
    /// A descriptor flag syscall failed.
    #[error("{operation} failed with errno {errno}")]
    Fcntl {
        /// The operation being attempted.
        operation: &'static str,
        /// Raw OS errno value.
        errno: i32,
    },
    /// The descriptor already contained a wake value.
    #[error("wake fd was not empty; read {bytes_read} pending bytes")]
    NotEmpty {
        /// Bytes consumed while detecting the invalid pending wake.
        bytes_read: usize,
    },
    /// The descriptor reports permanent EOF instead of an empty wake queue.
    #[error("wake fd reports end-of-file instead of an empty wake queue")]
    EndOfFile,
    /// Reading the nonblocking descriptor failed unexpectedly.
    #[error("validating empty wake fd failed with errno {errno}")]
    Read {
        /// Raw OS errno value.
        errno: i32,
    },
    /// Writing a Linux eventfd counter probe failed.
    #[error("writing eventfd counter probe failed with errno {errno}")]
    EventFdProbeWrite {
        /// Raw OS errno value.
        errno: i32,
    },
    /// A Linux eventfd counter probe produced a short write.
    #[error("eventfd counter probe wrote {bytes_written} bytes instead of 8")]
    EventFdProbeWriteSize {
        /// Number of bytes accepted by the descriptor.
        bytes_written: usize,
    },
    /// Reading a Linux eventfd counter probe failed.
    #[error("reading eventfd counter probe failed with errno {errno}")]
    EventFdProbeRead {
        /// Raw OS errno value.
        errno: i32,
    },
    /// The descriptor did not aggregate two writes like a non-semaphore eventfd.
    #[error(
        "wake descriptor lacks eventfd counter semantics: read {bytes_read} bytes with value {observed}"
    )]
    EventFdCounterSemantics {
        /// Number of bytes returned by the counter read.
        bytes_read: usize,
        /// Counter value returned after writing one and two.
        observed: u64,
    },
}

/// An error produced while registering the armed wake fd with QEMU.
#[cfg(unix)]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WakeFdRegisterError {
    /// The descriptor was already registered for this setup completion.
    #[error("QEMU wake fd was already registered")]
    AlreadyRegistered,
    /// QEMU rejected the descriptor.
    #[error("QEMU wake-fd registration rejected descriptor with status {status}")]
    Rejected {
        /// Raw QEMU status code.
        status: i32,
    },
}

/// An error produced while completing plugin setup.
#[cfg(unix)]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginSetupError {
    /// Receiving the setup frame and descriptors failed.
    #[error("receiving setup descriptors failed")]
    ReceiveSetup {
        /// Underlying descriptor-handover error.
        source: DescriptorHandoverError,
    },
    /// Mapping the setup shared-memory descriptor failed.
    #[error("setup shared-memory mmap failed")]
    MapRegion {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// Validating the mapped region header failed.
    #[error("setup shared-memory validation failed")]
    ValidateRegion {
        /// Underlying validation error.
        source: RegionSetupValidationError,
    },
    /// The handshake node count disagrees with the mapped shared-memory header.
    #[error(
        "setup node_count mismatch: handshake {handshake_node_count}, region {region_node_count}"
    )]
    NodeCountMismatch {
        /// Node count accepted during `Hello`/`HelloAck`.
        handshake_node_count: u32,
        /// Node count read from the mapped region header.
        region_node_count: u32,
    },
    /// The negotiated slot does not fit in the mapped shared-memory region.
    #[error("handshake slot {slot_index} is outside setup region node_count {region_node_count}")]
    SlotOutsideRegionNodeCount {
        /// Slot accepted during `Hello`/`HelloAck`.
        slot_index: u32,
        /// Node count read from the mapped region header.
        region_node_count: u32,
    },
    /// Arming the setup wake fd failed.
    #[error("setup wake fd arming failed")]
    ArmWakeFd {
        /// Underlying wake-fd arming error.
        source: WakeFdArmError,
    },
    /// Registering the setup wake fd with QEMU failed.
    #[error("setup wake fd registration failed")]
    RegisterWakeFd {
        /// Underlying wake-fd registration error.
        source: WakeFdRegisterError,
    },
    /// Ready acknowledgement was attempted before QEMU wake registration.
    #[error("setup wake fd is not registered with QEMU")]
    WakeFdNotRegistered,
    /// The ready `SetupAck(0)` could not be sent.
    #[error("sending ready SetupAck failed")]
    SendReadyAck {
        /// Underlying frame I/O error.
        source: SetupCompletionError,
    },
    /// The failure `SetupAck(nonzero)` could not be sent.
    #[error("sending failure SetupAck failed after {stage:?}")]
    SendFailureAck {
        /// Setup stage whose failure could not be acknowledged.
        stage: PluginSetupFailureStage,
        /// Underlying frame I/O error.
        source: SetupCompletionError,
    },
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    use std::cell::{Cell, RefCell};
    use std::fs::{File, OpenOptions};
    use std::io::{Cursor, Read, Write};
    use std::os::fd::FromRawFd;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crucible_protocol::{
        CONTROL_PROTOCOL_VERSION, DescriptorHandoverError, HostMsg, NegotiatedHandshake, PluginMsg,
        ReceivedSetup, ReceivedSetupDescriptors, SETUP_ACK_STATUS_READY,
        SETUP_ACK_STATUS_SETUP_FAILED, SetupDescriptorFds, control_decode_plugin_msg,
        control_encode_host_msg, read_control_frame, send_setup_with_descriptors,
    };
    use crucible_shmem::{
        ABI_VERSION, DEFAULT_QUEUE_CAPACITY, FRAME_ENTRY_SIZE, NODE_SLOT_SIZE,
        REGION_HEADER_ABI_VERSION_OFFSET, REGION_HEADER_ENTRY_STRIDE_OFFSET,
        REGION_HEADER_ICOUNT_SHIFT_OFFSET, REGION_HEADER_MAGIC_OFFSET,
        REGION_HEADER_NODE_COUNT_OFFSET, REGION_HEADER_QUEUE_CAPACITY_OFFSET,
        REGION_HEADER_REGION_SIZE_OFFSET, REGION_HEADER_RING_COUNT_OFFSET,
        REGION_HEADER_RING_DATA_OFF_OFFSET, REGION_HEADER_RING_HDR_OFF_OFFSET, REGION_HEADER_SIZE,
        REGION_MAGIC, RESERVED_SLOTS, RING_HEADER_SIZE, RegionConfig, RegionLayout,
    };

    use crate::{
        CoverageCapabilities, PluginArgs, PluginRegistrationSequence, PluginRegistrationStep,
        RequiredOwnedCallbacksRegistered, validate_plugin_handshake,
    };

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn prepare_setup_maps_validates_and_arms_wake_fd_before_ready_ack() {
        let layout = valid_layout();
        let setup = ReceivedSetup {
            region_len: layout.region_size,
            descriptors: ReceivedSetupDescriptors {
                shmem_fd: valid_region_file(layout).into(),
                wake_fd: wake_fd().into(),
            },
        };
        let mut io = ScriptedIo::default();

        let completion = match prepare_setup_completion(
            &mut io,
            setup,
            plugin_handshake(1, layout.node_count),
        ) {
            Ok(completion) => completion,
            Err(error) => panic!("valid setup should complete: {error}"),
        };

        assert_eq!(completion.mapped_region().region_len(), layout.region_size);
        assert_eq!(completion.validated_region().region_len, layout.region_size);
        assert_nonblocking(completion.wake_fd().as_raw_fd());
        assert_eq!(completion.registered_wake_fd(), None);
        assert!(io.written().is_empty());
        assert_eq!(io.flush_count(), 0);

        let callbacks = callback_capabilities();
        let mut owned_callbacks = owned_callbacks(1, completion);
        owned_callbacks
            .register_wake_fd_after_callbacks(&mut io, accept_wake_fd_registration)
            .unwrap_or_else(|error| panic!("wake registration should succeed: {error}"));
        assert_eq!(
            owned_callbacks
                .setup()
                .registered_wake_fd()
                .map(RegisteredWakeFd::as_raw_fd),
            Some(last_registered_wake_fd())
        );
        if let Err(error) = send_ready_setup_ack(&mut io, &callbacks, &owned_callbacks) {
            panic!("ready setup acknowledgement should send: {error}");
        }
        assert_eq!(
            decode_single_setup_ack(io.written()),
            SETUP_ACK_STATUS_READY
        );
        assert_eq!(io.flush_count(), 1);
    }

    #[test]
    fn prepare_setup_sends_nonzero_ack_when_region_validation_fails() {
        let region_len = REGION_HEADER_SIZE as u64;
        let setup = ReceivedSetup {
            region_len,
            descriptors: ReceivedSetupDescriptors {
                shmem_fd: zeroed_region_file(region_len).into(),
                wake_fd: wake_fd().into(),
            },
        };
        let mut io = ScriptedIo::default();

        assert!(matches!(
            prepare_setup_completion(&mut io, setup, plugin_handshake(0, 1)),
            Err(PluginSetupError::ValidateRegion { .. })
        ));
        assert_eq!(
            decode_single_setup_ack(io.written()),
            SETUP_ACK_STATUS_SETUP_FAILED
        );
        assert_eq!(io.flush_count(), 1);
    }

    #[test]
    fn receive_setup_sends_nonzero_ack_when_descriptor_count_is_wrong() {
        let (mut host, mut plugin) = setup_socket_pair();
        let frame = control_encode_host_msg(&HostMsg::Setup {
            region_len: REGION_HEADER_SIZE as u64,
        });
        if let Err(error) = host.write_all(&frame) {
            panic!("setup frame write should succeed: {error}");
        }

        let error = receive_setup_with_descriptors(&mut plugin)
            .err()
            .unwrap_or_else(|| panic!("missing descriptors should fail"));
        assert!(matches!(
            error,
            PluginSetupError::ReceiveSetup {
                source: DescriptorHandoverError::WrongDescriptorCount { count: 0 },
            }
        ));
        assert_eq!(
            decode_single_setup_ack_from_stream(&mut host),
            SETUP_ACK_STATUS_SETUP_FAILED
        );
    }

    #[test]
    fn receive_and_prepare_setup_receives_descriptors_and_cross_checks_handshake() {
        let layout = valid_layout();
        let region_file = valid_region_file(layout);
        let wake_file = wake_fd();
        let (mut host, mut plugin) = setup_socket_pair();
        if let Err(error) = send_setup_with_descriptors(
            host.as_raw_fd(),
            layout.region_size,
            SetupDescriptorFds {
                shmem_fd: region_file.as_raw_fd(),
                wake_fd: wake_file.as_raw_fd(),
            },
        ) {
            panic!("setup descriptor send should succeed: {error}");
        }

        let handshake = plugin_handshake(1, layout.node_count);
        let completion = receive_and_prepare_setup_completion(&mut plugin, handshake)
            .unwrap_or_else(|error| panic!("setup should complete: {error}"));

        assert_eq!(completion.validated_region().region_len, layout.region_size);
        assert_nonblocking(completion.wake_fd().as_raw_fd());
        let callbacks = callback_capabilities();
        let mut owned_callbacks = owned_callbacks(1, completion);
        owned_callbacks
            .register_wake_fd_after_callbacks(&mut plugin, accept_wake_fd_registration)
            .unwrap_or_else(|error| panic!("wake registration should succeed: {error}"));
        send_ready_setup_ack(&mut plugin, &callbacks, &owned_callbacks)
            .unwrap_or_else(|error| panic!("ready ack should send: {error}"));
        assert_eq!(
            decode_single_setup_ack_from_stream(&mut host),
            SETUP_ACK_STATUS_READY
        );
    }

    #[test]
    fn prepare_setup_sends_nonzero_ack_when_handshake_node_count_disagrees() {
        let layout = valid_layout();
        let setup = ReceivedSetup {
            region_len: layout.region_size,
            descriptors: ReceivedSetupDescriptors {
                shmem_fd: valid_region_file(layout).into(),
                wake_fd: wake_fd().into(),
            },
        };
        let mut io = ScriptedIo::default();
        let handshake = plugin_handshake(1, layout.node_count + 1);

        let error = prepare_setup_completion(&mut io, setup, handshake)
            .err()
            .unwrap_or_else(|| panic!("node-count mismatch should fail"));
        assert_eq!(
            error,
            PluginSetupError::NodeCountMismatch {
                handshake_node_count: layout.node_count + 1,
                region_node_count: layout.node_count,
            }
        );
        assert_eq!(
            decode_single_setup_ack(io.written()),
            SETUP_ACK_STATUS_SETUP_FAILED
        );
    }

    #[test]
    fn prepare_setup_sends_nonzero_ack_when_handshake_slot_exceeds_region() {
        let layout = valid_layout();
        let setup = ReceivedSetup {
            region_len: layout.region_size,
            descriptors: ReceivedSetupDescriptors {
                shmem_fd: valid_region_file(layout).into(),
                wake_fd: wake_fd().into(),
            },
        };
        let mut io = ScriptedIo::default();
        let handshake = plugin_handshake(layout.node_count, layout.node_count + 1);

        let error = prepare_setup_completion(&mut io, setup, handshake)
            .err()
            .unwrap_or_else(|| panic!("slot beyond region should fail"));
        assert_eq!(
            error,
            PluginSetupError::NodeCountMismatch {
                handshake_node_count: layout.node_count + 1,
                region_node_count: layout.node_count,
            }
        );
        assert_eq!(
            decode_single_setup_ack(io.written()),
            SETUP_ACK_STATUS_SETUP_FAILED
        );
    }

    #[test]
    fn wake_fd_arm_sets_nonblocking_on_descriptor() {
        let fd = wake_fd();

        let armed = match ArmedWakeFd::arm(fd.into()) {
            Ok(armed) => armed,
            Err(error) => panic!("wake fd should arm: {error}"),
        };

        assert_nonblocking(armed.as_raw_fd());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wake_fd_arm_rejects_pipe_socket_and_regular_file() {
        let (pipe_read, _pipe_write) = wake_pipe();
        assert!(ArmedWakeFd::arm(pipe_read.into()).is_err());

        let (socket, _socket_peer) = std::os::unix::net::UnixStream::pair()
            .unwrap_or_else(|error| panic!("wake socket pair should open: {error}"));
        assert!(ArmedWakeFd::arm(socket.into()).is_err());

        assert!(ArmedWakeFd::arm(temp_region_file().into()).is_err());
    }

    #[test]
    fn wake_fd_registers_armed_descriptor_with_qemu() {
        let fd = wake_fd();
        let raw_fd = fd.as_raw_fd();
        let armed = ArmedWakeFd::arm(fd.into())
            .unwrap_or_else(|error| panic!("wake fd should arm: {error}"));

        let registered = armed
            .register_with_qemu(accept_wake_fd_registration)
            .unwrap_or_else(|error| panic!("QEMU should accept wake fd: {error}"));
        assert_eq!(registered.as_raw_fd(), raw_fd);
        assert_eq!(last_registered_wake_fd(), raw_fd);
    }

    #[test]
    fn wake_fd_registration_rejects_qemu_failure_status() {
        let fd = wake_fd();
        let armed = ArmedWakeFd::arm(fd.into())
            .unwrap_or_else(|error| panic!("wake fd should arm: {error}"));

        assert_eq!(
            armed.register_with_qemu(reject_wake_fd_registration),
            Err(WakeFdRegisterError::Rejected { status: -1 })
        );
    }

    #[test]
    fn prepare_setup_sends_nonzero_ack_when_wake_fd_registration_fails() {
        let layout = valid_layout();
        let setup = ReceivedSetup {
            region_len: layout.region_size,
            descriptors: ReceivedSetupDescriptors {
                shmem_fd: valid_region_file(layout).into(),
                wake_fd: wake_fd().into(),
            },
        };
        let mut io = ScriptedIo::default();

        let completion =
            prepare_setup_completion(&mut io, setup, plugin_handshake(1, layout.node_count))
                .unwrap_or_else(|error| panic!("local setup should succeed: {error}"));
        let mut owned_callbacks = owned_callbacks(1, completion);
        let error = owned_callbacks
            .register_wake_fd_after_callbacks(&mut io, reject_wake_fd_registration)
            .err()
            .unwrap_or_else(|| panic!("wake-fd registration rejection should fail setup"));

        assert_eq!(
            error,
            PluginSetupError::RegisterWakeFd {
                source: WakeFdRegisterError::Rejected { status: -1 },
            }
        );
        assert_eq!(
            decode_single_setup_ack(io.written()),
            SETUP_ACK_STATUS_SETUP_FAILED
        );
    }

    #[derive(Default)]
    struct ScriptedIo {
        output: Vec<u8>,
        flush_count: usize,
    }

    impl ScriptedIo {
        fn written(&self) -> &[u8] {
            &self.output
        }

        fn flush_count(&self) -> usize {
            self.flush_count
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flush_count += 1;
            Ok(())
        }
    }

    fn valid_layout() -> RegionLayout {
        match RegionLayout::for_config(RegionConfig::new(2, DEFAULT_QUEUE_CAPACITY, 3)) {
            Ok(layout) => layout,
            Err(error) => panic!("valid region layout should build: {error}"),
        }
    }

    fn valid_region_file(layout: RegionLayout) -> File {
        let mut bytes = vec![0; layout.region_size as usize];
        write_u64(&mut bytes, REGION_HEADER_MAGIC_OFFSET, REGION_MAGIC);
        write_u32(&mut bytes, REGION_HEADER_ABI_VERSION_OFFSET, ABI_VERSION);
        write_u32(
            &mut bytes,
            REGION_HEADER_NODE_COUNT_OFFSET,
            layout.node_count,
        );
        write_u32(
            &mut bytes,
            REGION_HEADER_QUEUE_CAPACITY_OFFSET,
            layout.queue_capacity,
        );
        write_u32(
            &mut bytes,
            REGION_HEADER_RING_COUNT_OFFSET,
            2 * RESERVED_SLOTS as u32 * 2,
        );
        write_u64(
            &mut bytes,
            REGION_HEADER_RING_HDR_OFF_OFFSET,
            layout.ring_hdr_off,
        );
        write_u64(
            &mut bytes,
            REGION_HEADER_RING_DATA_OFF_OFFSET,
            layout.ring_data_off,
        );
        write_u64(
            &mut bytes,
            REGION_HEADER_ENTRY_STRIDE_OFFSET,
            FRAME_ENTRY_SIZE as u64,
        );
        write_u64(
            &mut bytes,
            REGION_HEADER_REGION_SIZE_OFFSET,
            layout.region_size,
        );
        write_u32(
            &mut bytes,
            REGION_HEADER_ICOUNT_SHIFT_OFFSET,
            layout.icount_shift,
        );
        assert_eq!(
            layout.ring_hdr_off,
            REGION_HEADER_SIZE as u64 + u64::from(layout.node_count) * NODE_SLOT_SIZE as u64
        );
        assert_eq!(
            layout.ring_data_off,
            layout.ring_hdr_off + u64::from(layout.ring_count) * RING_HEADER_SIZE as u64
        );
        region_file_from_bytes(&bytes)
    }

    fn plugin_handshake(slot_index: u32, node_count: u32) -> PluginControlHandshake {
        let args = PluginArgs::parse(&format!("simfd=3,slot={slot_index}"))
            .unwrap_or_else(|error| panic!("test plugin args should parse: {error}"));
        let negotiated = NegotiatedHandshake {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index,
            node_count,
        };
        validate_plugin_handshake(&args, negotiated)
            .unwrap_or_else(|error| panic!("test handshake should validate: {error}"))
    }

    fn callback_capabilities() -> PluginCallbackCapabilities {
        let mut sequence = PluginRegistrationSequence::new();
        for step in [
            PluginRegistrationStep::ParseArguments,
            PluginRegistrationStep::ControlHandshake,
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::ReceiveSetup,
            PluginRegistrationStep::MapSharedMemory,
            PluginRegistrationStep::ArmWakeFd,
        ] {
            if let Err(error) = sequence.record_step(step) {
                panic!("callback prerequisite {step:?} should record: {error}");
            }
        }
        let args = PluginArgs::parse("simfd=3,slot=0")
            .unwrap_or_else(|error| panic!("test plugin args should parse: {error}"));
        sequence
            .register_callbacks_for_test(
                &args,
                Some(setup_test_deadline),
                Some(setup_test_direct_advance),
                CoverageCapabilities::none(),
            )
            .unwrap_or_else(|error| panic!("test callbacks should register: {error}"))
    }

    fn owned_callbacks(
        slot: u32,
        completion: PluginSetupCompletion,
    ) -> RequiredOwnedCallbacksRegistered {
        let args = PluginArgs::parse(&format!("simfd=3,slot={slot}"))
            .unwrap_or_else(|error| panic!("test plugin args should parse: {error}"));
        RequiredOwnedCallbacksRegistered::for_test(&args, completion)
    }

    extern "C" fn setup_test_deadline() -> i64 {
        777
    }

    extern "C" fn setup_test_direct_advance(_target_virtual_ns: i64) -> std::os::raw::c_int {
        0
    }

    thread_local! {
        static LAST_REGISTERED_WAKE_FD: Cell<i32> = const { Cell::new(-1) };
        static WAKE_PEERS: RefCell<Vec<File>> = const { RefCell::new(Vec::new()) };
    }

    fn last_registered_wake_fd() -> i32 {
        LAST_REGISTERED_WAKE_FD.with(Cell::get)
    }

    extern "C" fn accept_wake_fd_registration(fd: i32) -> i32 {
        LAST_REGISTERED_WAKE_FD.with(|last| last.set(fd));
        0
    }

    extern "C" fn reject_wake_fd_registration(_fd: i32) -> i32 {
        -1
    }

    fn setup_socket_pair() -> (
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ) {
        std::os::unix::net::UnixStream::pair()
            .unwrap_or_else(|error| panic!("failed to create setup socket pair: {error}"))
    }

    fn zeroed_region_file(region_len: u64) -> File {
        region_file_from_bytes(&vec![0; region_len as usize])
    }

    fn region_file_from_bytes(bytes: &[u8]) -> File {
        let mut file = temp_region_file();
        if let Err(error) = file.set_len(bytes.len() as u64) {
            panic!("failed to size temporary setup region: {error}");
        }
        if let Err(error) = file.write_all(bytes) {
            panic!("failed to write temporary setup region: {error}");
        }
        file
    }

    #[cfg(target_os = "linux")]
    fn wake_fd() -> File {
        // SAFETY: `eventfd` returns a new descriptor or -1. The successful fd is
        // uniquely wrapped in `File`.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if fd < 0 {
            panic!("failed to create eventfd: errno {}", last_errno());
        }
        // SAFETY: `fd` is newly created and uniquely owned here.
        unsafe { File::from_raw_fd(fd) }
    }

    #[cfg(target_os = "linux")]
    fn wake_pipe() -> (File, File) {
        let mut fds = [-1; 2];
        // SAFETY: `fds` has room for both descriptors returned by `pipe`.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            panic!("failed to create wake pipe: errno {}", last_errno());
        }
        // SAFETY: successful `pipe` returned a uniquely owned read descriptor.
        let read_end = unsafe { File::from_raw_fd(fds[0]) };
        // SAFETY: successful `pipe` returned a distinct uniquely owned writer.
        let write_end = unsafe { File::from_raw_fd(fds[1]) };
        (read_end, write_end)
    }

    #[cfg(not(target_os = "linux"))]
    fn wake_fd() -> File {
        let mut fds = [-1; 2];
        // SAFETY: `fds` has room for both descriptors returned by `pipe`.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            panic!("failed to create wake pipe: errno {}", last_errno());
        }
        // SAFETY: successful `pipe` returned a uniquely owned read descriptor.
        let wake = unsafe { File::from_raw_fd(fds[0]) };
        // SAFETY: successful `pipe` returned a distinct uniquely owned writer.
        let peer = unsafe { File::from_raw_fd(fds[1]) };
        WAKE_PEERS.with(|peers| peers.borrow_mut().push(peer));
        wake
    }

    fn assert_nonblocking(fd: RawFd) {
        // SAFETY: `fcntl(F_GETFL)` reads descriptor status flags for a live fd.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            panic!("failed to read descriptor flags: errno {}", last_errno());
        }
        assert_ne!(flags & libc::O_NONBLOCK, 0);
    }

    fn decode_single_setup_ack(bytes: &[u8]) -> u8 {
        let mut cursor = Cursor::new(bytes);
        decode_single_setup_ack_from_stream(&mut cursor)
    }

    fn decode_single_setup_ack_from_stream<R>(stream: &mut R) -> u8
    where
        R: Read,
    {
        let frame = match read_control_frame(stream) {
            Ok(frame) => frame,
            Err(error) => panic!("setup ack frame should decode: {error}"),
        };
        match control_decode_plugin_msg(&frame) {
            Ok(PluginMsg::SetupAck { status }) => status,
            Ok(message) => panic!("expected SetupAck, got {message:?}"),
            Err(error) => panic!("setup ack message should decode: {error}"),
        }
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn temp_region_file() -> File {
        let path = temp_region_path();
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) => panic!("failed to create temporary setup region: {error}"),
        };
        if let Err(error) = std::fs::remove_file(&path) {
            panic!("failed to unlink temporary setup region: {error}");
        }
        file
    }

    fn temp_region_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "crucible-qemu-plugin-setup-{}-{}",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        path
    }
}
