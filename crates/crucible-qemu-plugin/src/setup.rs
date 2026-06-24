//! Setup completion for the QEMU plugin control protocol.
//!
//! The setup path consumes the `Setup` descriptors, maps the shared-memory
//! region for exactly the advertised byte length, validates the region header,
//! and arms the wake fd for event-loop use. The caller then registers plugin
//! callbacks before sending `SetupAck(0)` with the returned completion token.

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
use crate::{PluginCallbackCapabilities, PluginControlHandshake};

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
    /// operation. The QEMU FFI registration added later consumes this token
    /// rather than a raw descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`WakeFdArmError`] when descriptor flags cannot be read or
    /// updated.
    pub fn arm(fd: OwnedFd) -> Result<Self, WakeFdArmError> {
        set_close_on_exec(fd.as_raw_fd())?;
        set_nonblocking(fd.as_raw_fd())?;
        Ok(Self { fd })
    }

    /// Returns the raw descriptor number for QEMU registration.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Typed evidence that the plugin completed setup before acknowledging readiness.
#[cfg(unix)]
pub struct PluginSetupCompletion {
    mapped_region: MappedSetupRegion,
    validated_region: ValidatedSetupRegion,
    wake_fd: ArmedWakeFd,
}

#[cfg(unix)]
impl PluginSetupCompletion {
    /// Returns the mapped shared-memory region.
    #[must_use]
    pub const fn mapped_region(&self) -> &MappedSetupRegion {
        &self.mapped_region
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
/// negotiated handshake assignment. It intentionally does not send
/// `SetupAck(0)`; callers must first register plugin callbacks and then call
/// [`send_ready_setup_ack`]. On setup failure before callback registration, it
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

    let mapped_region = match mmap_setup_region(shmem_fd.as_fd(), region_len) {
        Ok(mapped_region) => mapped_region,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::MapRegion)?;
            return Err(PluginSetupError::MapRegion { source });
        }
    };

    let header_snapshot = mapped_region.header_snapshot();
    let validated_region = match mapped_region.validate_header() {
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
    _completion: &PluginSetupCompletion,
    _callbacks: &PluginCallbackCapabilities,
) -> Result<(), PluginSetupError>
where
    W: Write,
{
    plugin_send_setup_ack(writer, SETUP_ACK_STATUS_READY)
        .map_err(|source| PluginSetupError::SendReadyAck { source })
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
    // SAFETY: `fcntl(F_GETFD)` reads descriptor flags for a live fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(WakeFdArmError::Fcntl {
            operation: "read wake fd descriptor flags",
            errno: last_errno(),
        });
    }

    // SAFETY: `fcntl(F_SETFD)` updates descriptor flags for a live fd.
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
    // SAFETY: `fcntl(F_GETFL)` reads descriptor status flags for a live fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(WakeFdArmError::Fcntl {
            operation: "read wake fd status flags",
            errno: last_errno(),
        });
    }

    // SAFETY: `fcntl(F_SETFL)` updates descriptor status flags for a live fd.
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
}

/// Setup stage whose failure triggered a nonzero `SetupAck`.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginSetupFailureStage {
    /// Receiving the setup frame or descriptors failed.
    ReceiveSetup,
    /// Mapping the shared-memory region failed.
    MapRegion,
    /// Validating the mapped shared-memory header failed.
    ValidateRegion,
    /// Cross-checking the handshake assignment against the mapped header failed.
    CrossCheckSlot,
    /// Arming the wake fd failed.
    ArmWakeFd,
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

    use std::fs::{File, OpenOptions};
    use std::io::{Cursor, Read, Write};
    use std::os::fd::FromRawFd;
    #[cfg(not(target_os = "linux"))]
    use std::os::fd::IntoRawFd;
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
        validate_plugin_handshake,
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
        assert!(io.written().is_empty());
        assert_eq!(io.flush_count(), 0);

        let callbacks = callback_capabilities();
        if let Err(error) = send_ready_setup_ack(&mut io, &completion, &callbacks) {
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
        send_ready_setup_ack(&mut plugin, &completion, &callbacks)
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
            .register_callbacks_with_exact_deadline(
                &args,
                Some(setup_test_deadline),
                Some(setup_test_direct_advance),
                CoverageCapabilities::none(),
            )
            .unwrap_or_else(|error| panic!("test callbacks should register: {error}"))
    }

    extern "C" fn setup_test_deadline() -> i64 {
        777
    }

    extern "C" fn setup_test_direct_advance(_target_virtual_ns: i64) {}

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

    #[cfg(not(target_os = "linux"))]
    fn wake_fd() -> File {
        let (wake, peer) = match std::os::unix::net::UnixStream::pair() {
            Ok(pair) => pair,
            Err(error) => panic!("failed to create wake fd pair: {error}"),
        };
        drop(peer);
        // SAFETY: ownership moves from `UnixStream` into `File`.
        unsafe { File::from_raw_fd(wake.into_raw_fd()) }
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
