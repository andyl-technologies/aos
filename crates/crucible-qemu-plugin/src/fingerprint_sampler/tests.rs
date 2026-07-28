//! Fingerprint sampler unit tests.

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
