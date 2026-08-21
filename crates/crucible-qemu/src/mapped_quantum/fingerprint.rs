//! Canonical black-box execution-fingerprint construction.

use super::*;

const BLACK_BOX_EXECUTION_FINGERPRINT_DOMAIN: &str =
    "crucible.qemu.black-box-execution-fingerprint.v1";

pub(crate) fn black_box_execution_fingerprint(
    node: &crucible::NodeId,
    sample: &FingerprintSample,
) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
    sample
        .validate()
        .map_err(|source| QemuNodeChannelError::new("execution_fingerprint", source.to_string()))?;
    if sample.component_failures != 0 {
        return Err(QemuNodeChannelError::new(
            "execution_fingerprint",
            format!(
                "black-box fingerprint sample has component failure mask {:#x}",
                sample.component_failures
            ),
        ));
    }
    if sample.vcpu_count == 0 {
        return Err(QemuNodeChannelError::new(
            "execution_fingerprint",
            "black-box fingerprint sample contains no vCPU state",
        ));
    }

    let mut material = vec![
        format!("node={}", node.name),
        format!("sample_icount={}", sample.sample_icount),
        format!("vcpu_count={}", sample.vcpu_count),
        format!("rr_current_vcpu={}", sample.rr_current_vcpu),
        format!("rr_position_in_quantum={}", sample.rr_position_in_quantum),
        format!("rr_switch_quantum={}", sample.rr_switch_quantum),
    ];
    for (index, vcpu) in sample
        .vcpus
        .iter()
        .take(sample.vcpu_count as usize)
        .enumerate()
    {
        material.push(format!(
            "vcpu[{index}].register_digest={}",
            lowercase_hex(&vcpu.register_digest)
        ));
        material.push(format!(
            "vcpu[{index}].register_file_bytes={}",
            vcpu.register_file_bytes
        ));
        material.push(format!(
            "vcpu[{index}].retired_instruction_count={}",
            vcpu.retired_instruction_count
        ));
    }
    material.extend([
        format!("ram_bytes={}", sample.ram_bytes),
        format!("ram_digest={}", lowercase_hex(&sample.ram_digest)),
        format!("device_state_bytes={}", sample.device_state_bytes),
        format!(
            "device_state_digest={}",
            lowercase_hex(&sample.device_state_digest)
        ),
        format!(
            "device_state_schema_digest={}",
            lowercase_hex(&sample.device_state_schema_digest)
        ),
    ]);
    Ok(ExecutionFingerprint {
        hash: crucible::ContentHash::from_canonical_material(
            BLACK_BOX_EXECUTION_FINGERPRINT_DOMAIN,
            &material.join("\n"),
        ),
    })
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
