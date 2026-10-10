//! Plugin-side single-VM fingerprint sampler.
//!
//! When single-VM fingerprint sampling is enabled at setup, the plugin reads
//! the guest's exact black-box state at a scheduler boundary and publishes it
//! into the shared-memory [`FingerprintSample`] slot for the host to compare
//! run-to-run. This module owns the boundary-time capture: it wraps the patched
//! QEMU's aggregate immutable capture export in safe Rust and assembles its
//! logical RAM root and admitted read-only device/volatile projection outputs with the per-vCPU register
//! digests and round-robin cursor already gathered by
//! [`PluginNvcpuFingerprintInputs`].
//!
//! The capture is observation-only: it reads guest state without mutating
//! scheduling, virtual time, or the guest, exactly like the register and cursor
//! introspection it composes.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd as _, FromRawFd, RawFd};
use std::os::raw::{c_int, c_void};

use crucible_shmem::{
    FINGERPRINT_DIGEST_BYTES, FINGERPRINT_SAMPLE_MAX_VCPUS, FingerprintSample,
    FingerprintSampleError, FingerprintSampleVcpu,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const QEMU_PLUGIN_CRUCIBLE_CAPTURE_FINGERPRINT_V2_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_capture_fingerprint_v2\0";

use crate::{
    PluginNvcpuFingerprintInputs, PluginVcpuIntrospector, PluginVcpuRegisterDigest,
    VcpuIntrospectionError, resolve_qemu_read_vcpu_regs_symbol, resolve_qemu_rr_cursor_symbol,
};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct QemuFingerprintCaptureV2 {
    pub(crate) schema: u32,
    pub(crate) logical_edition: u32,
    pub(crate) ram_scope: u32,
    pub(crate) reserved: u32,
    pub(crate) ram_digest: [u8; FINGERPRINT_DIGEST_BYTES],
    pub(crate) ram_bytes: u64,
    pub(crate) device_fd: c_int,
    pub(crate) device_material_length: u64,
    pub(crate) device_bytes: u64,
    pub(crate) device_schema_digest: [u8; FINGERPRINT_DIGEST_BYTES],
    pub(crate) device_schema_sections: u64,
}

impl Default for QemuFingerprintCaptureV2 {
    fn default() -> Self {
        Self {
            schema: 0,
            logical_edition: 0,
            ram_scope: 0,
            reserved: 0,
            ram_digest: [0; FINGERPRINT_DIGEST_BYTES],
            ram_bytes: 0,
            device_fd: -1,
            device_material_length: 0,
            device_bytes: 0,
            device_schema_digest: [0; FINGERPRINT_DIGEST_BYTES],
            device_schema_sections: 0,
        }
    }
}

/// QEMU's aggregate exact-boundary logical-root and device capture export.
pub(crate) type QemuCaptureFingerprintMaterialFn =
    extern "C" fn(*mut QemuFingerprintCaptureV2) -> c_int;

/// One QEMU-allocated immutable fingerprint preimage.
#[derive(Debug)]
struct CapturedFingerprintMaterial {
    file: File,
    material_length: u64,
}

impl CapturedFingerprintMaterial {
    fn digest(
        mut self,
        component: &'static str,
        workspace: &mut [u8; 65_536],
    ) -> Result<[u8; FINGERPRINT_DIGEST_BYTES], FingerprintSamplerError> {
        digest_device_material(&mut self.file, self.material_length, component, workspace)
    }
}

// The declared workspace preserves the original read transcript. In particular,
// a short read reduces the next request by only the actual bytes read, and an
// Interrupted read neither updates the hash nor consumes the remaining extent.
fn digest_device_material(
    reader: &mut impl Read,
    material_length: u64,
    component: &'static str,
    workspace: &mut [u8; 65_536],
) -> Result<[u8; FINGERPRINT_DIGEST_BYTES], FingerprintSamplerError> {
    let mut hasher = Sha256::new();
    let mut remaining = material_length;

    while remaining != 0 {
        let requested = remaining.min(workspace.len() as u64) as usize;
        match reader.read(&mut workspace[..requested]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(0) | Err(_) => {
                return Err(FingerprintSamplerError::DigestRead {
                    component,
                    remaining_bytes: remaining,
                });
            }
            Ok(read) => {
                hasher.update(&workspace[..read]);
                remaining -= read as u64;
            }
        }
    }
    Ok(hasher.finalize().into())
}

/// An exact-coordinate sample whose device projection digest remains pending.
///
/// The control callback captures this value at the quiesced exact boundary,
/// then transfers it to the dedicated digest worker. Its buffers are immutable
/// and detached from guest memory; the logical RAM root is already complete.
/// The callback waits for ordered digest
/// publication before acknowledging the boundary or resuming guest execution.
#[derive(Debug)]
pub(crate) struct CapturedFingerprintSample {
    sample: FingerprintSample,
    device: CapturedFingerprintMaterial,
}

impl CapturedFingerprintSample {
    #[cfg(test)]
    pub(crate) fn test_empty() -> Self {
        Self {
            sample: FingerprintSample::default(),
            device: CapturedFingerprintMaterial {
                file: File::open("/dev/null").unwrap(),
                material_length: 0,
            },
        }
    }

    /// Digests the detached device projection and preserves the coherent RAM root.
    ///
    /// # Errors
    ///
    /// Returns an error if detached component bytes cannot be read completely.
    /// Failed material must not be published or acknowledge an exact request.
    pub(crate) fn digest(
        mut self,
        workspace: &mut [u8; 65_536],
    ) -> Result<FingerprintSample, FingerprintSamplerError> {
        let device = self.device.digest("device state", workspace)?;
        self.sample.device_state_digest = device;
        Ok(self.sample)
    }
}

/// The resolved capability set the plugin needs to sample fingerprints live.
///
/// It pairs the per-vCPU register/RR-cursor introspector with one aggregate
/// logical-root/device capture. Both are `dlsym`-resolved from the loaded QEMU, so
/// the value proves the running QEMU carries the complete current observer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PluginFingerprintSampling {
    introspector: PluginVcpuIntrospector,
    capture: QemuCaptureFingerprintMaterialFn,
}

impl PluginFingerprintSampling {
    /// Binds deterministic exports for callback integration tests.
    #[cfg(test)]
    pub(crate) const fn from_test_exports(
        introspector: PluginVcpuIntrospector,
        capture: QemuCaptureFingerprintMaterialFn,
    ) -> Self {
        Self {
            introspector,
            capture,
        }
    }

    /// Resolves the complete fingerprint sampling capability from loaded QEMU.
    ///
    /// Returns `None` (fail closed) when any register, RR-cursor, or digest
    /// export is absent, so the plugin never publishes a partial fingerprint
    /// against a QEMU build missing the required fingerprint exports.
    #[must_use]
    pub(crate) fn resolve() -> Option<Self> {
        let introspector = PluginVcpuIntrospector::require(
            resolve_qemu_read_vcpu_regs_symbol(),
            resolve_qemu_rr_cursor_symbol(),
        )
        .ok()?;
        let capture = resolve_capture_symbol()?;
        Some(Self {
            introspector,
            capture,
        })
    }

    /// Captures one exact-coordinate sample for asynchronous component digestion.
    ///
    /// Register and RR-cursor introspection, the static schema digest, and the
    /// incremental logical RAM root and immutable device projection happen at
    /// the boundary. The device SHA-256 operation does not; callers transfer the returned value and request
    /// identity to the digest worker, which publishes and acknowledges the sample
    /// after the boundary callback has released the vCPU thread.
    /// # Errors
    ///
    /// Returns [`FingerprintSamplerError`] when introspection or capture fails,
    /// QEMU returns an invalid RAM identity or sealed device descriptor, the register set exceeds the fixed
    /// slot capacity, or the sample metadata fails shared-memory validation.
    pub(crate) fn capture(
        &self,
        current_icount: u64,
        vcpu_count: u32,
    ) -> Result<CapturedFingerprintSample, FingerprintSamplerError> {
        let inputs = self
            .introspector
            .read_nvcpu_fingerprint_inputs(vcpu_count)
            .map_err(FingerprintSamplerError::Introspection)?;
        let mut captured = QemuFingerprintCaptureV2::default();
        let status = (self.capture)(&mut captured);
        if status != 0 {
            close_returned_fd(captured.device_fd);
            return Err(FingerprintSamplerError::Capture { status });
        }
        if let Err(error) = validate_capture_evidence(&captured) {
            close_returned_fd(captured.device_fd);
            return Err(error);
        }
        let device = capture_file(
            captured.device_fd,
            captured.device_material_length,
            "device state",
        )?;
        let mut sample = sample_metadata(current_icount, &inputs, captured.device_schema_digest)?;
        sample.ram_bytes = captured.ram_bytes;
        sample.ram_digest = captured.ram_digest;
        sample.device_state_bytes = captured.device_bytes;
        sample.device_state_sections = captured.device_schema_sections;
        let captured = CapturedFingerprintSample { sample, device };
        captured
            .sample
            .validate()
            .map_err(FingerprintSamplerError::Slot)?;
        Ok(captured)
    }
}

fn validate_capture_evidence(
    captured: &QemuFingerprintCaptureV2,
) -> Result<(), FingerprintSamplerError> {
    if captured.schema != 2
        || captured.logical_edition != crucible_ram::LOGICAL_ENCODING_EDITION
        || captured.ram_scope != 0
        || captured.reserved != 0
        || captured.ram_bytes == 0
        || captured.ram_digest.iter().all(|byte| *byte == 0)
        || captured.device_bytes == 0
        || captured.device_schema_digest.iter().all(|byte| *byte == 0)
        || captured.device_schema_sections == 0
    {
        return Err(FingerprintSamplerError::InvalidCaptureEvidence);
    }

    Ok(())
}

fn close_returned_fd(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: a nonnegative returned descriptor transfers one owned handle.
        drop(unsafe { File::from_raw_fd(fd) });
    }
}

fn capture_file(
    fd: RawFd,
    material_length: u64,
    component: &'static str,
) -> Result<CapturedFingerprintMaterial, FingerprintSamplerError> {
    if fd < 0 {
        return Err(FingerprintSamplerError::InvalidCaptureDescriptor { component });
    }
    // SAFETY: QEMU transfers ownership of each successful capture descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|_| FingerprintSamplerError::InvalidCaptureDescriptor { component })?;
    // SAFETY: `file` owns a valid descriptor and `lseek` does not retain it.
    let offset = unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_CUR) };
    // SAFETY: `file` owns a valid descriptor and `fcntl` does not retain it.
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    // SAFETY: `file` owns a valid descriptor and `fcntl` does not retain it.
    let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    let required_seals =
        libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if !metadata.file_type().is_file()
        || metadata.len() != material_length
        || material_length == 0
        || offset != 0
        || seals != required_seals
        || descriptor_flags < 0
        || descriptor_flags & libc::FD_CLOEXEC == 0
    {
        return Err(FingerprintSamplerError::InvalidCaptureDescriptor { component });
    }
    Ok(CapturedFingerprintMaterial {
        file,
        material_length,
    })
}

fn sample_metadata(
    current_icount: u64,
    nvcpu_inputs: &PluginNvcpuFingerprintInputs,
    device_state_schema_digest: [u8; FINGERPRINT_DIGEST_BYTES],
) -> Result<FingerprintSample, FingerprintSamplerError> {
    let registers = nvcpu_inputs.vcpu_registers();
    if registers.len() > FINGERPRINT_SAMPLE_MAX_VCPUS {
        return Err(FingerprintSamplerError::TooManyVcpus {
            requested: registers.len(),
            capacity: FINGERPRINT_SAMPLE_MAX_VCPUS,
        });
    }
    let cursor = nvcpu_inputs.rr_cursor();
    let mut sample = FingerprintSample {
        sample_icount: current_icount,
        vcpu_count: registers.len() as u32,
        rr_current_vcpu: cursor.current_vcpu() as u32,
        rr_position_in_quantum: cursor.cursor_position(),
        rr_switch_quantum: cursor.rr_switch_quantum(),
        component_failures: 0,
        ram_bytes: 0,
        ram_digest: [0; FINGERPRINT_DIGEST_BYTES],
        device_state_bytes: 0,
        device_state_sections: 0,
        device_state_digest: [0; FINGERPRINT_DIGEST_BYTES],
        device_state_schema_digest,
        vcpus: [FingerprintSampleVcpu::default(); FINGERPRINT_SAMPLE_MAX_VCPUS],
    };
    for (slot, register) in sample.vcpus.iter_mut().zip(registers) {
        *slot = vcpu_from_register_digest(register);
    }
    Ok(sample)
}

#[cfg(unix)]
fn resolve_capture_symbol() -> Option<QemuCaptureFingerprintMaterialFn> {
    let symbol = resolve_symbol_address(QEMU_PLUGIN_CRUCIBLE_CAPTURE_FINGERPRINT_V2_SYMBOL_C)?;
    // SAFETY: the address resolved the patched fingerprint capture export,
    // whose declaration matches `QemuCaptureFingerprintMaterialFn` exactly.
    Some(unsafe { std::mem::transmute::<*mut c_void, QemuCaptureFingerprintMaterialFn>(symbol) })
}

#[cfg(not(unix))]
fn resolve_capture_symbol() -> Option<QemuCaptureFingerprintMaterialFn> {
    None
}

#[cfg(unix)]
fn resolve_symbol_address(name_c: &[u8]) -> Option<*mut c_void> {
    // SAFETY: every caller supplies a static NUL-terminated symbol name.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name_c.as_ptr().cast()) };
    (!symbol.is_null()).then_some(symbol)
}

fn vcpu_from_register_digest(register: &PluginVcpuRegisterDigest) -> FingerprintSampleVcpu {
    FingerprintSampleVcpu {
        register_digest: *register.register_digest(),
        register_file_bytes: register.register_file_bytes() as u64,
        retired_instruction_count: register.retired_instruction_count(),
    }
}

/// Error produced while assembling a plugin fingerprint sample.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub(crate) enum FingerprintSamplerError {
    /// More vCPU register digests were supplied than the slot can carry.
    #[error("fingerprint sampler saw {requested} vcpus but the slot holds {capacity}")]
    TooManyVcpus {
        /// vCPU count observed from the register inputs.
        requested: usize,
        /// Fixed fingerprint slot capacity.
        capacity: usize,
    },
    /// Reading the per-vCPU registers or round-robin cursor failed.
    #[error("fingerprint vCPU introspection failed: {0}")]
    Introspection(VcpuIntrospectionError),
    /// QEMU could not capture a coherent RAM root and detached device projection.
    #[error("QEMU fingerprint material capture failed with status {status}")]
    Capture {
        /// Negative errno-style status returned by the patched QEMU export.
        status: c_int,
    },
    /// QEMU reported an empty RAM, device, or schema observation.
    #[error("QEMU fingerprint capture returned empty component evidence")]
    InvalidCaptureEvidence,
    /// QEMU returned an invalid, unsealed, or wrongly positioned memfd.
    #[error("QEMU fingerprint capture returned an invalid {component} descriptor")]
    InvalidCaptureDescriptor {
        /// Stable component name used in the diagnostic.
        component: &'static str,
    },
    /// Immutable component material could not be read completely.
    #[error("fingerprint {component} read failed with {remaining_bytes} bytes remaining")]
    DigestRead {
        /// Stable component name used in the diagnostic.
        component: &'static str,
        /// Declared component bytes not yet consumed.
        remaining_bytes: u64,
    },
    /// The assembled sample failed shared-memory slot validation.
    #[error("assembled fingerprint sample is invalid: {0}")]
    Slot(FingerprintSampleError),
}

#[cfg(test)]
#[path = "fingerprint_sampler/tests.rs"]
mod tests;
