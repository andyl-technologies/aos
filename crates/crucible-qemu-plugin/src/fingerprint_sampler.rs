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

use std::os::raw::c_int;

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

use crate::{PluginNvcpuFingerprintInputs, PluginVcpuRegisterDigest};

/// Required QEMU export that digests length-framed writable guest RAM.
pub const QEMU_PLUGIN_CRUCIBLE_GUEST_RAM_SHA256_SYMBOL: &str =
    "qemu_plugin_crucible_guest_ram_sha256";
/// Required QEMU export that digests serialized non-RAM VMState.
pub const QEMU_PLUGIN_CRUCIBLE_DEVICE_STATE_SHA256_SYMBOL: &str =
    "qemu_plugin_crucible_device_state_sha256";
/// Required QEMU export that digests the registered non-RAM VMState schema.
pub const QEMU_PLUGIN_CRUCIBLE_DEVICE_STATE_SCHEMA_SHA256_SYMBOL: &str =
    "qemu_plugin_crucible_device_state_schema_sha256";

/// Component-failure bit set when the writable-RAM digest read fails.
pub const FINGERPRINT_FAILURE_RAM: u32 = 1 << 0;
/// Component-failure bit set when the device-state VMState digest read fails.
pub const FINGERPRINT_FAILURE_DEVICE_STATE: u32 = 1 << 1;
/// Component-failure bit set when the device-state schema digest read fails.
pub const FINGERPRINT_FAILURE_DEVICE_STATE_SCHEMA: u32 = 1 << 2;

/// QEMU's side-effect-free 32-byte digest export.
///
/// The patched adapter writes a SHA-256 digest into `digest_out`, stores an
/// associated length or section count in `count_out`, and returns zero on
/// success.
pub type QemuDigestFn = extern "C" fn(*mut u8, *mut u64) -> c_int;

/// A component digest and the byte or section count it covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DigestReading {
    digest: [u8; FINGERPRINT_DIGEST_BYTES],
    count: u64,
    ok: bool,
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

/// Resolves one patched QEMU digest export by NUL-terminated name.
#[cfg(unix)]
fn resolve_digest_symbol(name_c: &[u8]) -> Option<QemuDigestFn> {
    // SAFETY: `name_c` is a static NUL-terminated symbol name and `dlsym`
    // returns either null or a process symbol address. Every patched QEMU digest
    // export shares the `int fn(uint8_t[32], uint64_t*)` ABI of `QemuDigestFn`;
    // the caller fails closed when a symbol is absent.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name_c.as_ptr().cast()) };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null address resolved a patched QEMU digest export
        // whose declaration matches `QemuDigestFn` exactly.
        Some(unsafe { std::mem::transmute::<*mut std::os::raw::c_void, QemuDigestFn>(symbol) })
    }
}

/// Resolves one patched QEMU digest export by NUL-terminated name.
#[cfg(not(unix))]
fn resolve_digest_symbol(_name_c: &[u8]) -> Option<QemuDigestFn> {
    None
}

fn vcpu_from_register_digest(register: &PluginVcpuRegisterDigest) -> FingerprintSampleVcpu {
    FingerprintSampleVcpu {
        register_digest: *register.register_digest(),
        register_file_bytes: register.register_file_bytes() as u64,
        retired_instruction_count: register.retired_instruction_count(),
    }
}

/// Error produced while assembling a plugin fingerprint sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FingerprintSamplerError {
    /// More vCPU register digests were supplied than the slot can carry.
    #[error("fingerprint sampler saw {requested} vcpus but the slot holds {capacity}")]
    TooManyVcpus {
        /// vCPU count observed from the register inputs.
        requested: usize,
        /// Fixed fingerprint slot capacity.
        capacity: usize,
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
}
