//! Plugin-side single-VM fingerprint sampler.
//!
//! When single-VM fingerprint sampling is enabled at setup, the plugin reads
//! the guest's exact black-box state at a scheduler boundary and publishes it
//! into the shared-memory [`FingerprintSample`] slot for the host to compare
//! run-to-run. This module owns the boundary-time capture: it wraps the patched
//! QEMU digest exports (writable RAM, serialized non-RAM VMState, and the VMState
//! schema) in safe Rust and assembles them together with the per-vCPU register
//! digests and round-robin cursor already gathered by
//! [`PluginNvcpuFingerprintInputs`].
//!
//! The capture is observation-only: it reads guest state without mutating
//! scheduling, virtual time, or the guest, exactly like the register and cursor
//! introspection it composes.

use std::os::raw::{c_int, c_void};
use std::ptr::NonNull;

use crucible_shmem::{
    FINGERPRINT_DIGEST_BYTES, FINGERPRINT_SAMPLE_MAX_VCPUS, FingerprintSample,
    FingerprintSampleError, FingerprintSampleVcpu,
};
use thiserror::Error;

/// NUL-terminated writable-RAM digest export name for `dlsym`.
const QEMU_PLUGIN_CRUCIBLE_GUEST_RAM_SHA256_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_guest_ram_sha256\0";
/// NUL-terminated device-state VMState digest export name for `dlsym`.
const QEMU_PLUGIN_CRUCIBLE_DEVICE_STATE_SHA256_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_device_state_sha256\0";
/// NUL-terminated device-state schema digest export name for `dlsym`.
const QEMU_PLUGIN_CRUCIBLE_DEVICE_STATE_SCHEMA_SHA256_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_device_state_schema_sha256\0";
/// NUL-terminated immutable fingerprint-material capture export name for `dlsym`.
const QEMU_PLUGIN_CRUCIBLE_FINGERPRINT_CAPTURE_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_fingerprint_capture\0";
/// NUL-terminated immutable-buffer SHA-256 export name for `dlsym`.
const QEMU_PLUGIN_CRUCIBLE_SHA256_BYTES_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_sha256_bytes\0";
/// NUL-terminated fingerprint-material release export name for `dlsym`.
const QEMU_PLUGIN_CRUCIBLE_FINGERPRINT_CAPTURE_FREE_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_fingerprint_capture_free\0";

use crate::{
    PluginNvcpuFingerprintInputs, PluginVcpuIntrospector, PluginVcpuRegisterDigest,
    VcpuIntrospectionError, resolve_qemu_read_vcpu_regs_symbol, resolve_qemu_rr_cursor_symbol,
};

/// Required QEMU export that digests length-framed writable guest RAM.
pub const QEMU_PLUGIN_CRUCIBLE_GUEST_RAM_SHA256_SYMBOL: &str =
    "qemu_plugin_crucible_guest_ram_sha256";
/// Required QEMU export that digests serialized non-RAM VMState.
pub const QEMU_PLUGIN_CRUCIBLE_DEVICE_STATE_SHA256_SYMBOL: &str =
    "qemu_plugin_crucible_device_state_sha256";
/// Required QEMU export that digests the registered non-RAM VMState schema.
pub const QEMU_PLUGIN_CRUCIBLE_DEVICE_STATE_SCHEMA_SHA256_SYMBOL: &str =
    "qemu_plugin_crucible_device_state_schema_sha256";
/// Required QEMU export that captures immutable fingerprint preimages.
pub const QEMU_PLUGIN_CRUCIBLE_FINGERPRINT_CAPTURE_SYMBOL: &str =
    "qemu_plugin_crucible_fingerprint_capture";
/// Required QEMU export that digests an immutable capture buffer.
pub const QEMU_PLUGIN_CRUCIBLE_SHA256_BYTES_SYMBOL: &str = "qemu_plugin_crucible_sha256_bytes";
/// Required QEMU export that releases an immutable capture buffer.
pub const QEMU_PLUGIN_CRUCIBLE_FINGERPRINT_CAPTURE_FREE_SYMBOL: &str =
    "qemu_plugin_crucible_fingerprint_capture_free";

/// Component-failure bit set when the writable-RAM digest read fails.
pub const FINGERPRINT_FAILURE_RAM: u32 = 1 << 0;
/// Component-failure bit set when the device-state VMState digest read fails.
pub const FINGERPRINT_FAILURE_DEVICE_STATE: u32 = 1 << 1;
/// Component-failure bit set when the device-state schema digest read fails.
pub const FINGERPRINT_FAILURE_DEVICE_STATE_SCHEMA: u32 = 1 << 2;
/// Component-failure bit set when the gate-only synchronous oracle disagrees.
pub const FINGERPRINT_FAILURE_ORACLE_MISMATCH: u32 = 1 << 3;

/// QEMU's side-effect-free 32-byte digest export.
///
/// The patched adapter writes a SHA-256 digest into `digest_out`, stores an
/// associated length or section count in `count_out`, and returns zero on
/// success.
pub type QemuDigestFn = extern "C" fn(*mut u8, *mut u64) -> c_int;

/// QEMU's exact-boundary immutable fingerprint capture export.
pub type QemuFingerprintCaptureFn =
    extern "C" fn(*mut *mut u8, *mut u64, *mut u64, *mut *mut u8, *mut u64, *mut u64) -> c_int;

/// QEMU's worker-safe immutable-buffer SHA-256 export.
pub type QemuSha256BytesFn = extern "C" fn(*const u8, u64, *mut u8) -> c_int;

/// QEMU's release export for an immutable fingerprint capture buffer.
pub type QemuFingerprintCaptureFreeFn = extern "C" fn(*mut c_void);

/// A component digest and the byte or section count it covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DigestReading {
    digest: [u8; FINGERPRINT_DIGEST_BYTES],
    count: u64,
    ok: bool,
}

/// Resolved exports used to copy exact-boundary material and digest it later.
#[derive(Clone, Copy, Debug)]
struct PluginFingerprintCaptureExports {
    capture: QemuFingerprintCaptureFn,
    sha256_bytes: QemuSha256BytesFn,
    free: QemuFingerprintCaptureFreeFn,
}

impl PluginFingerprintCaptureExports {
    fn resolve() -> Option<Self> {
        Some(Self {
            capture: resolve_capture_symbol()?,
            sha256_bytes: resolve_sha256_bytes_symbol()?,
            free: resolve_capture_free_symbol()?,
        })
    }
}

/// One QEMU-allocated immutable fingerprint preimage.
#[derive(Debug)]
struct CapturedFingerprintMaterial {
    data: NonNull<u8>,
    material_length: u64,
    observed_bytes: u64,
    free: QemuFingerprintCaptureFreeFn,
}

// SAFETY: the QEMU capture export returns a detached `g_malloc` allocation.
// No QEMU object aliases or mutates it after capture returns, and the matching
// release export is `g_free`, which may be invoked by the digest worker.
unsafe impl Send for CapturedFingerprintMaterial {}

impl CapturedFingerprintMaterial {
    fn digest(&self, sha256_bytes: QemuSha256BytesFn) -> DigestReading {
        let mut digest = [0_u8; FINGERPRINT_DIGEST_BYTES];
        let status = sha256_bytes(
            self.data.as_ptr(),
            self.material_length,
            digest.as_mut_ptr(),
        );
        DigestReading {
            digest,
            count: self.observed_bytes,
            ok: status == 0,
        }
    }
}

impl Drop for CapturedFingerprintMaterial {
    fn drop(&mut self) {
        (self.free)(self.data.as_ptr().cast());
    }
}

/// An exact-coordinate sample whose large component digests remain pending.
///
/// The vCPU callback captures this value under QEMU's dirty-tracked observation
/// boundary, then transfers it to the dedicated digest worker. Its buffers are
/// immutable and detached from guest memory, so guest execution may resume
/// while [`Self::digest`] hashes them.
#[derive(Debug)]
pub(crate) struct CapturedFingerprintSample {
    sample: FingerprintSample,
    ram: CapturedFingerprintMaterial,
    device: CapturedFingerprintMaterial,
    sha256_bytes: QemuSha256BytesFn,
    synchronous_oracle: Option<FingerprintSample>,
}

impl CapturedFingerprintSample {
    /// Digests the detached component preimages and produces the final sample.
    pub(crate) fn digest(mut self) -> FingerprintSample {
        let ram = self.ram.digest(self.sha256_bytes);
        let device = self.device.digest(self.sha256_bytes);
        if !ram.ok {
            self.sample.component_failures |= FINGERPRINT_FAILURE_RAM;
        }
        if !device.ok {
            self.sample.component_failures |= FINGERPRINT_FAILURE_DEVICE_STATE;
        }
        self.sample.ram_digest = ram.digest;
        self.sample.device_state_digest = device.digest;
        if self
            .synchronous_oracle
            .as_ref()
            .is_some_and(|oracle| oracle != &self.sample)
        {
            self.sample.component_failures |= FINGERPRINT_FAILURE_ORACLE_MISMATCH;
        }
        self.sample
    }
}

/// Handle to the patched QEMU RAM and device-state digest exports.
#[derive(Clone, Copy, Debug)]
pub struct PluginFingerprintDigester {
    guest_ram_sha256: QemuDigestFn,
    device_state_sha256: QemuDigestFn,
    device_state_schema_sha256: QemuDigestFn,
}

impl PluginFingerprintDigester {
    /// Binds the patched QEMU RAM, device-state, and schema digest exports.
    #[must_use]
    pub const fn new(
        guest_ram_sha256: QemuDigestFn,
        device_state_sha256: QemuDigestFn,
        device_state_schema_sha256: QemuDigestFn,
    ) -> Self {
        Self {
            guest_ram_sha256,
            device_state_sha256,
            device_state_schema_sha256,
        }
    }

    /// Resolves the patched QEMU digest exports from the loaded process.
    ///
    /// Returns `None` when any of the three exports is absent (fail closed), so
    /// the plugin only samples fingerprints against a QEMU build that carries
    /// the fingerprint helper patch.
    #[must_use]
    pub fn resolve() -> Option<Self> {
        Some(Self::new(
            resolve_digest_symbol(QEMU_PLUGIN_CRUCIBLE_GUEST_RAM_SHA256_SYMBOL_C)?,
            resolve_digest_symbol(QEMU_PLUGIN_CRUCIBLE_DEVICE_STATE_SHA256_SYMBOL_C)?,
            resolve_digest_symbol(QEMU_PLUGIN_CRUCIBLE_DEVICE_STATE_SCHEMA_SHA256_SYMBOL_C)?,
        ))
    }

    fn read(function: QemuDigestFn) -> DigestReading {
        let mut digest = [0_u8; FINGERPRINT_DIGEST_BYTES];
        let mut count = 0_u64;
        // SAFETY: the patched QEMU export writes exactly FINGERPRINT_DIGEST_BYTES
        // into `digest` and a single u64 into `count`; both point at live local
        // storage of the correct size for the duration of the call.
        let status = function(digest.as_mut_ptr(), &mut count);
        DigestReading {
            digest,
            count,
            ok: status == 0,
        }
    }
}

/// Assembles the shared-memory fingerprint sample from all boundary inputs.
///
/// `current_icount` is the aggregate icount the sample is stamped with;
/// `nvcpu_inputs` supplies the per-vCPU register digests and round-robin cursor;
/// the digester supplies the guest-RAM, device-state, and schema digests.
///
/// # Errors
///
/// Returns [`FingerprintSamplerError`] when the register set exceeds the fixed
/// slot capacity or the resulting sample fails shared-memory validation.
pub fn assemble_fingerprint_sample(
    current_icount: u64,
    nvcpu_inputs: &PluginNvcpuFingerprintInputs,
    digester: &PluginFingerprintDigester,
) -> Result<FingerprintSample, FingerprintSamplerError> {
    let registers = nvcpu_inputs.vcpu_registers();
    if registers.len() > FINGERPRINT_SAMPLE_MAX_VCPUS {
        return Err(FingerprintSamplerError::TooManyVcpus {
            requested: registers.len(),
            capacity: FINGERPRINT_SAMPLE_MAX_VCPUS,
        });
    }

    let ram = PluginFingerprintDigester::read(digester.guest_ram_sha256);
    let device = PluginFingerprintDigester::read(digester.device_state_sha256);
    let schema = PluginFingerprintDigester::read(digester.device_state_schema_sha256);

    let mut component_failures = 0_u32;
    if !ram.ok {
        component_failures |= FINGERPRINT_FAILURE_RAM;
    }
    if !device.ok {
        component_failures |= FINGERPRINT_FAILURE_DEVICE_STATE;
    }
    if !schema.ok {
        component_failures |= FINGERPRINT_FAILURE_DEVICE_STATE_SCHEMA;
    }

    let cursor = nvcpu_inputs.rr_cursor();
    let mut sample = FingerprintSample {
        sample_icount: current_icount,
        vcpu_count: registers.len() as u32,
        rr_current_vcpu: cursor.current_vcpu() as u32,
        rr_position_in_quantum: cursor.cursor_position(),
        rr_switch_quantum: cursor.rr_switch_quantum(),
        component_failures,
        ram_bytes: ram.count,
        ram_digest: ram.digest,
        device_state_bytes: device.count,
        device_state_digest: device.digest,
        device_state_schema_digest: schema.digest,
        vcpus: [FingerprintSampleVcpu::default(); FINGERPRINT_SAMPLE_MAX_VCPUS],
    };
    for (slot, register) in sample.vcpus.iter_mut().zip(registers) {
        *slot = vcpu_from_register_digest(register);
    }

    sample.validate().map_err(FingerprintSamplerError::Slot)
}

/// The resolved capability set the plugin needs to sample fingerprints live.
///
/// It pairs the per-vCPU register/RR-cursor introspector with the RAM and
/// device-state digesters. Both are `dlsym`-resolved from the loaded QEMU, so a
/// value of this type is proof the running QEMU carries the full fingerprint
/// helper patch surface.
#[derive(Clone, Copy, Debug)]
pub struct PluginFingerprintSampling {
    introspector: PluginVcpuIntrospector,
    digester: PluginFingerprintDigester,
    capture: PluginFingerprintCaptureExports,
}

impl PluginFingerprintSampling {
    /// Resolves the complete fingerprint sampling capability from loaded QEMU.
    ///
    /// Returns `None` (fail closed) when any register, RR-cursor, or digest
    /// export is absent, so the plugin never publishes a partial fingerprint
    /// against a QEMU build missing the helper patch.
    #[must_use]
    pub fn resolve() -> Option<Self> {
        let introspector = PluginVcpuIntrospector::require(
            resolve_qemu_read_vcpu_regs_symbol(),
            resolve_qemu_rr_cursor_symbol(),
        )
        .ok()?;
        let digester = PluginFingerprintDigester::resolve()?;
        let capture = PluginFingerprintCaptureExports::resolve()?;
        Some(Self {
            introspector,
            digester,
            capture,
        })
    }

    /// Captures one fingerprint sample for `vcpu_count` at `current_icount`.
    ///
    /// This is the boundary-time entry point: it reads every vCPU's registers
    /// and the RR cursor, digests guest RAM and device state, and assembles the
    /// shared-memory [`FingerprintSample`] the host reads after the quantum.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintSamplerError`] when introspection fails or the
    /// assembled sample exceeds the slot capacity or fails validation.
    pub fn sample(
        &self,
        current_icount: u64,
        vcpu_count: u32,
    ) -> Result<FingerprintSample, FingerprintSamplerError> {
        let inputs = self
            .introspector
            .read_nvcpu_fingerprint_inputs(vcpu_count)
            .map_err(FingerprintSamplerError::Introspection)?;
        assemble_fingerprint_sample(current_icount, &inputs, &self.digester)
    }

    /// Captures one exact-coordinate sample for asynchronous component digestion.
    ///
    /// Register and RR-cursor introspection, the static schema digest, and the
    /// immutable RAM/device preimage copies happen at the boundary. The large
    /// SHA-256 operations do not; callers transfer the returned value to the
    /// digest worker and may resume guest execution immediately.
    /// `synchronous_oracle` is a gate-only mode that also runs the former
    /// synchronous digest path and marks the eventual sample failed unless both
    /// results are byte-identical.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintSamplerError`] when introspection or capture fails,
    /// QEMU returns invalid capture pointers, the register set exceeds the fixed
    /// slot capacity, or the sample metadata fails shared-memory validation.
    pub(crate) fn capture(
        &self,
        current_icount: u64,
        vcpu_count: u32,
        synchronous_oracle: bool,
    ) -> Result<CapturedFingerprintSample, FingerprintSamplerError> {
        let inputs = self
            .introspector
            .read_nvcpu_fingerprint_inputs(vcpu_count)
            .map_err(FingerprintSamplerError::Introspection)?;
        let schema = PluginFingerprintDigester::read(self.digester.device_state_schema_sha256);
        let mut sample = sample_metadata(current_icount, &inputs, schema)?;

        let mut ram_data = std::ptr::null_mut();
        let mut ram_material_length = 0_u64;
        let mut ram_bytes = 0_u64;
        let mut device_data = std::ptr::null_mut();
        let mut device_material_length = 0_u64;
        let mut device_bytes = 0_u64;
        let status = (self.capture.capture)(
            &mut ram_data,
            &mut ram_material_length,
            &mut ram_bytes,
            &mut device_data,
            &mut device_material_length,
            &mut device_bytes,
        );
        if status != 0 {
            return Err(FingerprintSamplerError::Capture { status });
        }
        let ram_data =
            NonNull::new(ram_data).ok_or(FingerprintSamplerError::NullCaptureBuffer {
                component: "guest RAM",
            })?;
        let device_data = match NonNull::new(device_data) {
            Some(data) => data,
            None => {
                (self.capture.free)(ram_data.as_ptr().cast());
                return Err(FingerprintSamplerError::NullCaptureBuffer {
                    component: "device state",
                });
            }
        };
        sample.ram_bytes = ram_bytes;
        sample.device_state_bytes = device_bytes;
        let mut captured = CapturedFingerprintSample {
            sample,
            ram: CapturedFingerprintMaterial {
                data: ram_data,
                material_length: ram_material_length,
                observed_bytes: ram_bytes,
                free: self.capture.free,
            },
            device: CapturedFingerprintMaterial {
                data: device_data,
                material_length: device_material_length,
                observed_bytes: device_bytes,
                free: self.capture.free,
            },
            sha256_bytes: self.capture.sha256_bytes,
            synchronous_oracle: None,
        };
        if synchronous_oracle {
            captured.synchronous_oracle = Some(assemble_fingerprint_sample(
                current_icount,
                &inputs,
                &self.digester,
            )?);
        }
        captured
            .sample
            .validate()
            .map_err(FingerprintSamplerError::Slot)?;
        Ok(captured)
    }
}

fn sample_metadata(
    current_icount: u64,
    nvcpu_inputs: &PluginNvcpuFingerprintInputs,
    schema: DigestReading,
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
        component_failures: if schema.ok {
            0
        } else {
            FINGERPRINT_FAILURE_DEVICE_STATE_SCHEMA
        },
        ram_bytes: 0,
        ram_digest: [0; FINGERPRINT_DIGEST_BYTES],
        device_state_bytes: 0,
        device_state_digest: [0; FINGERPRINT_DIGEST_BYTES],
        device_state_schema_digest: schema.digest,
        vcpus: [FingerprintSampleVcpu::default(); FINGERPRINT_SAMPLE_MAX_VCPUS],
    };
    for (slot, register) in sample.vcpus.iter_mut().zip(registers) {
        *slot = vcpu_from_register_digest(register);
    }
    Ok(sample)
}

/// Resolves one patched QEMU digest export by NUL-terminated name.
#[cfg(unix)]
fn resolve_digest_symbol(name_c: &[u8]) -> Option<QemuDigestFn> {
    let symbol = resolve_symbol_address(name_c)?;
    // SAFETY: the address resolved one of the patched QEMU digest exports,
    // whose declaration matches `QemuDigestFn` exactly.
    Some(unsafe { std::mem::transmute::<*mut c_void, QemuDigestFn>(symbol) })
}

/// Resolves one patched QEMU digest export by NUL-terminated name.
#[cfg(not(unix))]
fn resolve_digest_symbol(_name_c: &[u8]) -> Option<QemuDigestFn> {
    None
}

#[cfg(unix)]
fn resolve_capture_symbol() -> Option<QemuFingerprintCaptureFn> {
    let symbol = resolve_symbol_address(QEMU_PLUGIN_CRUCIBLE_FINGERPRINT_CAPTURE_SYMBOL_C)?;
    // SAFETY: the address resolved the patched fingerprint capture export,
    // whose declaration matches `QemuFingerprintCaptureFn` exactly.
    Some(unsafe { std::mem::transmute::<*mut c_void, QemuFingerprintCaptureFn>(symbol) })
}

#[cfg(not(unix))]
fn resolve_capture_symbol() -> Option<QemuFingerprintCaptureFn> {
    None
}

#[cfg(unix)]
fn resolve_sha256_bytes_symbol() -> Option<QemuSha256BytesFn> {
    let symbol = resolve_symbol_address(QEMU_PLUGIN_CRUCIBLE_SHA256_BYTES_SYMBOL_C)?;
    // SAFETY: the address resolved the patched immutable-buffer digest export,
    // whose declaration matches `QemuSha256BytesFn` exactly.
    Some(unsafe { std::mem::transmute::<*mut c_void, QemuSha256BytesFn>(symbol) })
}

#[cfg(not(unix))]
fn resolve_sha256_bytes_symbol() -> Option<QemuSha256BytesFn> {
    None
}

#[cfg(unix)]
fn resolve_capture_free_symbol() -> Option<QemuFingerprintCaptureFreeFn> {
    let symbol = resolve_symbol_address(QEMU_PLUGIN_CRUCIBLE_FINGERPRINT_CAPTURE_FREE_SYMBOL_C)?;
    // SAFETY: the address resolved the patched capture release export, whose
    // declaration matches `QemuFingerprintCaptureFreeFn` exactly.
    Some(unsafe { std::mem::transmute::<*mut c_void, QemuFingerprintCaptureFreeFn>(symbol) })
}

#[cfg(not(unix))]
fn resolve_capture_free_symbol() -> Option<QemuFingerprintCaptureFreeFn> {
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
pub enum FingerprintSamplerError {
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
    /// QEMU could not capture immutable RAM and device-state material.
    #[error("QEMU fingerprint material capture failed with status {status}")]
    Capture {
        /// Negative errno-style status returned by the patched QEMU export.
        status: c_int,
    },
    /// QEMU reported success without returning a required capture buffer.
    #[error("QEMU fingerprint capture returned a null {component} buffer")]
    NullCaptureBuffer {
        /// Stable component name used in the diagnostic.
        component: &'static str,
    },
    /// The assembled sample failed shared-memory slot validation.
    #[error("assembled fingerprint sample is invalid: {0}")]
    Slot(FingerprintSampleError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{PluginRoundRobinCursor, PluginVcpuRegisterDigest};

    extern "C" fn ram_digest(out: *mut u8, count: *mut u64) -> c_int {
        fill(out, count, 0xA0, 64 * 1024 * 1024);
        0
    }

    extern "C" fn device_digest(out: *mut u8, count: *mut u64) -> c_int {
        fill(out, count, 0xB0, 4096);
        0
    }

    extern "C" fn schema_digest(out: *mut u8, count: *mut u64) -> c_int {
        fill(out, count, 0xC0, 12);
        0
    }

    extern "C" fn failing_digest(out: *mut u8, count: *mut u64) -> c_int {
        fill(out, count, 0, 0);
        1
    }

    extern "C" fn captured_digest(data: *const u8, length: u64, out: *mut u8) -> c_int {
        if data.is_null() || out.is_null() || length != 1 {
            return 1;
        }
        // SAFETY: this test supplies one readable seed byte and a writable
        // 32-byte digest buffer.
        let seed = unsafe { *data };
        // SAFETY: `out` names the live fixed-width digest buffer created by
        // `CapturedFingerprintMaterial::digest`.
        unsafe {
            for index in 0..FINGERPRINT_DIGEST_BYTES {
                *out.add(index) = seed.wrapping_add(index as u8);
            }
        }
        0
    }

    extern "C" fn free_captured(data: *mut c_void) {
        // SAFETY: `captured_material` allocates this pointer with `libc::malloc`
        // and transfers exactly one owning reference into the material.
        unsafe { libc::free(data) };
    }

    fn fill(out: *mut u8, count: *mut u64, seed: u8, value: u64) {
        // SAFETY: tests pass live 32-byte digest buffers and a live u64.
        unsafe {
            for index in 0..FINGERPRINT_DIGEST_BYTES {
                *out.add(index) = seed.wrapping_add(index as u8);
            }
            *count = value;
        }
    }

    fn digest_bytes(seed: u8) -> [u8; FINGERPRINT_DIGEST_BYTES] {
        let mut out = [0_u8; FINGERPRINT_DIGEST_BYTES];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        out
    }

    fn inputs() -> PluginNvcpuFingerprintInputs {
        let registers = vec![
            match PluginVcpuRegisterDigest::new(0, &[1, 2, 3, 4], 100_000) {
                Ok(register) => register,
                Err(error) => panic!("vcpu 0 register digest: {error}"),
            },
            match PluginVcpuRegisterDigest::new(1, &[5, 6, 7, 8], 100_000) {
                Ok(register) => register,
                Err(error) => panic!("vcpu 1 register digest: {error}"),
            },
        ];
        let cursor = match PluginRoundRobinCursor::new(1, 17, 4096, 2) {
            Ok(cursor) => cursor,
            Err(error) => panic!("rr cursor: {error}"),
        };
        match PluginNvcpuFingerprintInputs::new(registers, cursor) {
            Ok(inputs) => inputs,
            Err(error) => panic!("nvcpu inputs: {error}"),
        }
    }

    fn captured_material(seed: u8, observed_bytes: u64) -> CapturedFingerprintMaterial {
        // SAFETY: allocating one byte is sufficient for the test digest export.
        let data = unsafe { libc::malloc(1) }.cast::<u8>();
        let data = NonNull::new(data).unwrap_or_else(|| panic!("test allocation failed"));
        // SAFETY: `data` points at the live one-byte allocation above.
        unsafe { data.as_ptr().write(seed) };
        CapturedFingerprintMaterial {
            data,
            material_length: 1,
            observed_bytes,
            free: free_captured,
        }
    }

    fn captured_sample(oracle: FingerprintSample) -> CapturedFingerprintSample {
        let schema = PluginFingerprintDigester::read(schema_digest);
        let mut sample = sample_metadata(100_000, &inputs(), schema)
            .unwrap_or_else(|error| panic!("sample metadata should assemble: {error}"));
        sample.ram_bytes = 64 * 1024 * 1024;
        sample.device_state_bytes = 4096;
        CapturedFingerprintSample {
            sample,
            ram: captured_material(0xA0, 64 * 1024 * 1024),
            device: captured_material(0xB0, 4096),
            sha256_bytes: captured_digest,
            synchronous_oracle: Some(oracle),
        }
    }

    #[test]
    fn assembles_every_component_into_the_slot_sample() {
        let digester = PluginFingerprintDigester::new(ram_digest, device_digest, schema_digest);
        let sample = match assemble_fingerprint_sample(100_000, &inputs(), &digester) {
            Ok(sample) => sample,
            Err(error) => panic!("sample should assemble: {error}"),
        };

        assert_eq!(sample.sample_icount, 100_000);
        assert_eq!(sample.vcpu_count, 2);
        assert_eq!(sample.rr_current_vcpu, 1);
        assert_eq!(sample.rr_position_in_quantum, 17);
        assert_eq!(sample.rr_switch_quantum, 4096);
        assert_eq!(sample.component_failures, 0);
        assert_eq!(sample.ram_bytes, 64 * 1024 * 1024);
        assert_eq!(sample.ram_digest, digest_bytes(0xA0));
        assert_eq!(sample.device_state_bytes, 4096);
        assert_eq!(sample.device_state_digest, digest_bytes(0xB0));
        assert_eq!(sample.device_state_schema_digest, digest_bytes(0xC0));
        assert_eq!(sample.vcpus[0].retired_instruction_count, 100_000);
        assert_eq!(sample.vcpus[1].retired_instruction_count, 100_000);
        assert_ne!(
            sample.vcpus[0].register_digest,
            sample.vcpus[1].register_digest
        );
    }

    #[test]
    fn resolve_fails_closed_without_the_patched_qemu() {
        // The fingerprint digest exports exist only inside patched QEMU, so a
        // standalone test process cannot resolve them and must get no digester.
        assert!(PluginFingerprintDigester::resolve().is_none());
        // The full sampling capability likewise fails closed.
        assert!(PluginFingerprintSampling::resolve().is_none());
    }

    #[test]
    fn records_component_failures_without_aborting() {
        let digester = PluginFingerprintDigester::new(ram_digest, failing_digest, schema_digest);
        let sample = match assemble_fingerprint_sample(50_000, &inputs(), &digester) {
            Ok(sample) => sample,
            Err(error) => panic!("failed component should still assemble: {error}"),
        };
        assert_eq!(sample.component_failures, FINGERPRINT_FAILURE_DEVICE_STATE);
        assert_eq!(sample.device_state_bytes, 0);
    }

    #[test]
    fn synchronous_oracle_accepts_identity_and_marks_mismatch() {
        let digester = PluginFingerprintDigester::new(ram_digest, device_digest, schema_digest);
        let oracle = assemble_fingerprint_sample(100_000, &inputs(), &digester)
            .unwrap_or_else(|error| panic!("oracle should assemble: {error}"));
        let matching = captured_sample(oracle).digest();
        assert_eq!(matching.component_failures, 0);

        let mut mismatching_oracle = assemble_fingerprint_sample(100_000, &inputs(), &digester)
            .unwrap_or_else(|error| panic!("oracle should assemble: {error}"));
        mismatching_oracle.ram_digest[0] ^= 1;
        let mismatch = captured_sample(mismatching_oracle).digest();
        assert_eq!(
            mismatch.component_failures,
            FINGERPRINT_FAILURE_ORACLE_MISMATCH
        );
    }
}
