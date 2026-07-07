//! Host-side QEMU plugin setup handoff.
//!
//! This module consumes the Linux spawn descriptors, initializes the shared
//! memory memfd with the typed Crucible region image, runs the blocking
//! `Hello`/`Setup`/`SetupAck` protocol over a real Unix socket, and retains the
//! descriptors needed by later scheduler/runtime code. It intentionally stops
//! before deterministic guest execution.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, ControlLifecycleIoError, ControlLifecycleState,
    ControlLifecycleStream, HostHandshakeConfig, NegotiatedHandshake, SchedulableNodeSetup,
    SetupDescriptorFds,
};
use crucible_shmem::{
    ABI_VERSION, RegionAllocation, RegionConfig, RegionLayoutError, RegionSerializationError,
    RegionSetupValidationError, ValidatedSetupRegion, validate_setup_region_header,
};
use thiserror::Error;

use crate::{QemuNodeChannelError, QemuPluginIpcControlChannel, QemuSpawnSetupResources};

/// Completed host-side setup state for one QEMU plugin node.
#[derive(Debug)]
pub struct QemuHostPluginSetup {
    control: ControlLifecycleStream<UnixStream>,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
    negotiated: NegotiatedHandshake,
    setup_ack: SchedulableNodeSetup,
    region: ValidatedSetupRegion,
}

impl QemuHostPluginSetup {
    /// Returns the host control lifecycle state after setup.
    #[must_use]
    pub fn control_state(&self) -> ControlLifecycleState {
        self.control.state()
    }

    /// Returns the negotiated `Hello`/`HelloAck` values.
    #[must_use]
    pub const fn negotiated_handshake(&self) -> NegotiatedHandshake {
        self.negotiated
    }

    /// Returns the accepted ready setup acknowledgement.
    #[must_use]
    pub const fn setup_ack(&self) -> SchedulableNodeSetup {
        self.setup_ack
    }

    /// Returns the validated shared-memory setup region token.
    #[must_use]
    pub const fn region(&self) -> ValidatedSetupRegion {
        self.region
    }

    /// Returns the retained host shared-memory descriptor.
    #[must_use]
    pub fn shmem_fd(&self) -> RawFd {
        self.shmem_fd.as_raw_fd()
    }

    /// Returns the retained host wake event descriptor.
    #[must_use]
    pub fn wake_fd(&self) -> RawFd {
        self.wake_fd.as_raw_fd()
    }
}

impl QemuPluginIpcControlChannel for QemuHostPluginSetup {
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.control.host_send_quit().map_err(|source| {
            QemuNodeChannelError::new("send plugin control Quit", source.to_string())
        })
    }
}

/// Runs host-side setup over real spawn descriptors and enters shmem run state.
///
/// The function initializes the spawn-created memfd with the region described
/// by `config`, accepts the plugin handshake for `slot_index`, sends the memfd
/// and wake eventfd via `SCM_RIGHTS`, accepts `SetupAck(0)`, and advances the
/// host lifecycle into the shared-memory run phase. It does not execute any
/// guest instructions or assert replay determinism.
///
/// # Errors
///
/// Returns [`QemuHostPluginSetupError`] when region allocation or serialization
/// fails, when the spawn memfd length does not match the computed layout, when
/// memfd initialization fails, or when the control protocol rejects the
/// handshake, descriptor handoff, ready acknowledgement, or run transition.
pub fn complete_qemu_host_plugin_setup(
    resources: QemuSpawnSetupResources,
    config: RegionConfig,
    slot_index: u32,
) -> Result<QemuHostPluginSetup, QemuHostPluginSetupError> {
    let allocation = RegionAllocation::new(config)
        .map_err(|source| QemuHostPluginSetupError::RegionLayout { source })?;
    let layout = allocation.layout();
    if resources.region_len() != layout.region_size {
        return Err(QemuHostPluginSetupError::RegionLengthMismatch {
            spawn_region_len: resources.region_len(),
            layout_region_len: layout.region_size,
        });
    }

    let bytes = allocation
        .setup_region_bytes()
        .map_err(|source| QemuHostPluginSetupError::RegionSerialization { source })?;
    write_shmem_setup_region(resources.shmem_fd(), &bytes)?;
    let region = validate_setup_region_header(allocation.header().snapshot(), layout.region_size)
        .map_err(|source| QemuHostPluginSetupError::RegionValidation { source })?;

    let (control_socket, shmem_fd, wake_fd, region_len) = resources.into_parts();
    let mut control = ControlLifecycleStream::connected_unix_stream(control_socket)
        .map_err(|source| QemuHostPluginSetupError::Control { source })?;
    let negotiated = control
        .host_accept_handshake(HostHandshakeConfig {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index,
            node_count: layout.node_count,
        })
        .map_err(|source| QemuHostPluginSetupError::Control { source })?;
    control
        .host_send_setup_with_descriptors(
            region_len,
            SetupDescriptorFds {
                shmem_fd: shmem_fd.as_raw_fd(),
                wake_fd: wake_fd.as_raw_fd(),
            },
        )
        .map_err(|source| QemuHostPluginSetupError::Control { source })?;
    let setup_ack = control
        .host_accept_setup_ack()
        .map_err(|source| QemuHostPluginSetupError::Control { source })?;
    control
        .enter_run_via_shared_memory()
        .map_err(|source| QemuHostPluginSetupError::Control { source })?;

    Ok(QemuHostPluginSetup {
        control,
        shmem_fd,
        wake_fd,
        negotiated,
        setup_ack,
        region,
    })
}

fn write_shmem_setup_region(fd: RawFd, bytes: &[u8]) -> Result<(), QemuHostPluginSetupError> {
    let mut written = 0;
    while written < bytes.len() {
        let offset = libc::off_t::try_from(written).map_err(|_error| {
            setup_io_error(
                "compute shmem setup write offset",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "setup region write offset cannot fit off_t",
                ),
            )
        })?;
        let result = unsafe {
            // SAFETY: `fd` is a live memfd retained by setup resources, the
            // source slice is valid for the requested byte count, and `pwrite`
            // does not mutate Rust-managed memory.
            libc::pwrite(
                fd,
                bytes[written..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - written,
                offset,
            )
        };
        if result < 0 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(setup_io_error("write setup region to shmem memfd", source));
        }
        let count = usize::try_from(result).map_err(|_error| {
            setup_io_error(
                "convert shmem setup write count",
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "setup region pwrite returned an invalid byte count",
                ),
            )
        })?;
        if count == 0 {
            return Err(setup_io_error(
                "write setup region to shmem memfd",
                io::Error::new(
                    io::ErrorKind::WriteZero,
                    "setup region pwrite wrote zero bytes",
                ),
            ));
        }
        written += count;
    }
    Ok(())
}

fn setup_io_error(operation: &'static str, source: io::Error) -> QemuHostPluginSetupError {
    QemuHostPluginSetupError::Io { operation, source }
}

/// An error produced while running host-side plugin setup.
#[derive(Debug, Error)]
pub enum QemuHostPluginSetupError {
    /// The requested shared-memory layout could not be allocated.
    #[error("setup shared-memory layout failed")]
    RegionLayout {
        /// Underlying region layout error.
        source: RegionLayoutError,
    },
    /// The spawn-created memfd length did not match the requested layout.
    #[error(
        "spawn shared-memory length {spawn_region_len} does not match setup layout length {layout_region_len}"
    )]
    RegionLengthMismatch {
        /// Byte length used to size the spawn-created memfd.
        spawn_region_len: u64,
        /// Byte length computed from the setup region configuration.
        layout_region_len: u64,
    },
    /// The setup region image could not be serialized.
    #[error("setup shared-memory serialization failed")]
    RegionSerialization {
        /// Underlying serialization error.
        source: RegionSerializationError,
    },
    /// A host-side descriptor or memfd write operation failed.
    #[error("{operation} failed: {source}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Underlying OS error.
        source: io::Error,
    },
    /// The locally initialized setup region failed ABI validation.
    #[error("setup shared-memory validation failed")]
    RegionValidation {
        /// Underlying region validation error.
        source: RegionSetupValidationError,
    },
    /// The control-protocol lifecycle failed.
    #[error("setup control lifecycle failed")]
    Control {
        /// Underlying lifecycle error.
        source: ControlLifecycleIoError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;
    use std::os::fd::AsFd;
    use std::thread;

    use crucible_protocol::{
        CONTROL_PROTOCOL_VERSION, PluginHandshakeConfig, SETUP_ACK_STATUS_READY,
    };
    use crucible_shmem::{ABI_VERSION, RegionLayout, mmap_setup_region};

    use crate::spawn::create_test_spawn_resource_pair;

    const EVENTFD_WAKE_PROBE: u64 = 7;

    #[test]
    fn qemu_host_plugin_setup_wires_real_socket_descriptors_and_memfd() -> Result<(), Box<dyn Error>>
    {
        let config = RegionConfig::new(1, 4, 0);
        let layout = RegionLayout::for_config(config)?;
        let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
        let plugin_peer = thread::spawn(move || plugin_peer_complete_setup(plugin_socket));

        let mut setup =
            complete_qemu_host_plugin_setup(resources.into_setup_resources(), config, 0)?;

        assert_eq!(
            setup.control_state(),
            ControlLifecycleState::RunningViaSharedMemory
        );
        assert_eq!(
            setup.negotiated_handshake(),
            NegotiatedHandshake {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: ABI_VERSION,
                slot_index: 0,
                node_count: layout.node_count,
            }
        );
        assert_eq!(setup.setup_ack().setup_ack_status(), SETUP_ACK_STATUS_READY);
        assert!(setup.setup_ack().can_schedule());
        assert_eq!(
            setup.region(),
            ValidatedSetupRegion {
                region_len: layout.region_size,
                abi_version: ABI_VERSION,
            }
        );
        assert_fd_open(setup.shmem_fd())?;
        assert_fd_open(setup.wake_fd())?;
        assert_eq!(read_eventfd_counter(setup.wake_fd())?, EVENTFD_WAKE_PROBE);
        QemuPluginIpcControlChannel::send_quit(&mut setup)?;
        assert_eq!(setup.control_state(), ControlLifecycleState::QuitSent);

        let plugin_region = match plugin_peer.join() {
            Ok(Ok(region)) => region,
            Ok(Err(error)) => return Err(error.into()),
            Err(_panic) => return Err("plugin setup peer panicked".into()),
        };
        assert_eq!(plugin_region, setup.region());

        Ok(())
    }

    #[test]
    fn qemu_host_plugin_setup_rejects_spawn_region_length_mismatch_before_protocol()
    -> Result<(), Box<dyn Error>> {
        let config = RegionConfig::new(1, 4, 0);
        let layout = RegionLayout::for_config(config)?;
        let (resources, _plugin_socket) =
            create_test_spawn_resource_pair(layout.region_size + 4096)?;

        let error = complete_qemu_host_plugin_setup(resources.into_setup_resources(), config, 0)
            .err()
            .ok_or("setup should reject mismatched spawn region length")?;

        assert!(matches!(
            error,
            QemuHostPluginSetupError::RegionLengthMismatch {
                spawn_region_len,
                layout_region_len,
            } if spawn_region_len == layout.region_size + 4096
                && layout_region_len == layout.region_size
        ));

        Ok(())
    }

    fn plugin_peer_complete_setup(
        plugin_socket: UnixStream,
    ) -> Result<ValidatedSetupRegion, String> {
        let mut plugin = ControlLifecycleStream::connected_unix_stream(plugin_socket)
            .map_err(|error| error.to_string())?;
        let negotiated = plugin
            .plugin_start_handshake(PluginHandshakeConfig {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: ABI_VERSION,
            })
            .map_err(|error| error.to_string())?;
        if negotiated.slot_index != 0 {
            return Err(format!(
                "expected slot 0 from host handshake, got {}",
                negotiated.slot_index
            ));
        }

        let setup = plugin
            .plugin_recv_setup_with_descriptors()
            .map_err(|error| error.to_string())?;
        let mapped = mmap_setup_region(setup.descriptors.shmem_fd.as_fd(), setup.region_len)
            .map_err(|error| error.to_string())?;
        let validated = mapped
            .validate_header()
            .map_err(|error| error.to_string())?;
        assert_fd_open(setup.descriptors.wake_fd.as_raw_fd()).map_err(|error| error.to_string())?;
        write_eventfd_counter(setup.descriptors.wake_fd.as_raw_fd(), EVENTFD_WAKE_PROBE)
            .map_err(|error| error.to_string())?;

        plugin
            .plugin_send_ready_setup_ack()
            .map_err(|error| error.to_string())?;
        plugin
            .enter_run_via_shared_memory()
            .map_err(|error| error.to_string())?;
        plugin
            .plugin_read_run_control_frame()
            .map_err(|error| error.to_string())?;

        Ok(validated)
    }

    fn assert_fd_open(fd: RawFd) -> Result<(), io::Error> {
        let result = unsafe {
            // SAFETY: `fcntl` validates the descriptor number and reads flags only.
            libc::fcntl(fd, libc::F_GETFD)
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn write_eventfd_counter(fd: RawFd, value: u64) -> Result<(), io::Error> {
        let bytes = value.to_ne_bytes();
        let result = unsafe {
            // SAFETY: `fd` is expected to be a live eventfd, and `bytes` points
            // at the required eight-byte eventfd counter value.
            libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len())
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result != bytes.len() as libc::ssize_t {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "eventfd counter write was short",
            ));
        }
        Ok(())
    }

    fn read_eventfd_counter(fd: RawFd) -> Result<u64, io::Error> {
        let mut bytes = [0; 8];
        let result = unsafe {
            // SAFETY: `fd` is expected to be a live eventfd, and `bytes` points
            // at eight writable bytes for the eventfd counter value.
            libc::read(fd, bytes.as_mut_ptr().cast::<libc::c_void>(), bytes.len())
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result != bytes.len() as libc::ssize_t {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eventfd counter read was short",
            ));
        }
        Ok(u64::from_ne_bytes(bytes))
    }
}
