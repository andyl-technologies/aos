//! Host consumer for plugin-published shared-memory fingerprint samples.
//!
//! The Rust control plugin publishes each single-VM fingerprint boundary into a
//! [`FingerprintSample`] slot: per-vCPU register digests indexed `0..vcpu_count`,
//! the round-robin cursor, and the writable-RAM and current non-RAM VMState
//! digests. This module maps one such slot snapshot onto the canonical
//! [`SingleVmNvcpuFingerprintMaterial`] the single-VM fingerprint stream folds
//! and compares, so the host runner consumes the Rust plugin's own fingerprint
//! rather than an imported C-trace stream.

use crucible_shmem::{FINGERPRINT_SAMPLE_MAX_VCPUS, FingerprintSample};

use super::{
    SingleVmFingerprintGateError, SingleVmNvcpuFingerprintMaterial, SingleVmRoundRobinCursor,
    SingleVmVcpuRegisterDigest,
};

/// Converts a plugin-published shared-memory sample into canonical N-vCPU material.
///
/// The per-vCPU register digest at slot index `i` is attributed to vCPU `i`,
/// matching the plugin's ascending-vCPU publication order. The writable-RAM
/// digest becomes the guest-memory digest and the serialized non-RAM VMState
/// digest becomes the device-state digest.
///
/// # Errors
///
/// Returns [`SingleVmFingerprintGateError`] when the sample recorded any
/// component capture failure, reports more vCPUs than the slot can carry, or
/// produces material that fails canonical validation (digest widths, contiguous
/// vCPU set, round-robin cursor).
pub fn nvcpu_material_from_shmem_sample(
    sample: &FingerprintSample,
) -> Result<SingleVmNvcpuFingerprintMaterial, SingleVmFingerprintGateError> {
    if sample.component_failures != 0 {
        return Err(
            SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                reason: "plugin fingerprint sample recorded a component capture failure",
            },
        );
    }
    let vcpu_count = sample.vcpu_count as usize;
    if vcpu_count > FINGERPRINT_SAMPLE_MAX_VCPUS {
        return Err(
            SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                reason: "plugin fingerprint sample reports more vCPUs than the slot carries",
            },
        );
    }

    let mut vcpu_registers = Vec::with_capacity(vcpu_count);
    for (index, vcpu) in sample.vcpus.iter().take(vcpu_count).enumerate() {
        vcpu_registers.push(SingleVmVcpuRegisterDigest::new(
            index as u64,
            vcpu.register_digest.to_vec(),
            vcpu.register_file_bytes as usize,
            vcpu.retired_instruction_count,
        )?);
    }

    let rr_cursor = SingleVmRoundRobinCursor::new(
        u64::from(sample.rr_current_vcpu),
        sample.rr_position_in_quantum,
        sample.rr_switch_quantum,
        vcpu_count,
    )?;

    SingleVmNvcpuFingerprintMaterial::new(
        vcpu_registers,
        rr_cursor,
        sample.ram_digest.to_vec(),
        sample.device_state_digest.to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crucible_shmem::{FINGERPRINT_DIGEST_BYTES, FingerprintSampleVcpu};

    fn digest(seed: u8) -> [u8; FINGERPRINT_DIGEST_BYTES] {
        let mut out = [0_u8; FINGERPRINT_DIGEST_BYTES];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        out
    }

    fn sample() -> FingerprintSample {
        let mut sample = FingerprintSample {
            sample_icount: 100_000,
            vcpu_count: 2,
            rr_current_vcpu: 1,
            rr_position_in_quantum: 17,
            rr_switch_quantum: 4096,
            component_failures: 0,
            ram_bytes: 64 * 1024 * 1024,
            ram_digest: digest(0x10),
            device_state_bytes: 4096,
            device_state_digest: digest(0x20),
            device_state_schema_digest: digest(0x30),
            vcpus: [FingerprintSampleVcpu::default(); FINGERPRINT_SAMPLE_MAX_VCPUS],
        };
        sample.vcpus[0] = FingerprintSampleVcpu {
            register_digest: digest(0x40),
            register_file_bytes: 512,
            retired_instruction_count: 100_000,
        };
        sample.vcpus[1] = FingerprintSampleVcpu {
            register_digest: digest(0x50),
            register_file_bytes: 512,
            retired_instruction_count: 100_000,
        };
        sample
    }

    #[test]
    fn maps_every_component_onto_canonical_material() {
        let material = match nvcpu_material_from_shmem_sample(&sample()) {
            Ok(material) => material,
            Err(error) => panic!("valid sample should convert: {error}"),
        };
        assert_eq!(material.vcpu_registers().len(), 2);
        assert_eq!(material.vcpu_registers()[0].vcpu_id(), 0);
        assert_eq!(material.vcpu_registers()[0].register_digest(), digest(0x40));
        assert_eq!(material.vcpu_registers()[1].vcpu_id(), 1);
        assert_eq!(material.rr_cursor().current_vcpu(), 1);
        assert_eq!(material.rr_cursor().position_in_quantum(), 17);
        assert_eq!(material.guest_memory_digest(), digest(0x10));
        assert_eq!(material.device_state_digest(), digest(0x20));
    }

    #[test]
    fn rejects_a_sample_with_a_component_failure() {
        let mut failed = sample();
        failed.component_failures = 1;
        assert!(matches!(
            nvcpu_material_from_shmem_sample(&failed),
            Err(SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial { .. })
        ));
    }
}
