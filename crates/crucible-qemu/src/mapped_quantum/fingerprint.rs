//! Canonical black-box execution-fingerprint construction.

use super::*;

use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};

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
    if sample.ram_bytes == 0
        || sample.device_state_bytes == 0
        || sample.device_state_sections == 0
        || sample
            .device_state_schema_digest
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(QemuNodeChannelError::new(
            "execution_fingerprint",
            "black-box fingerprint sample contains incomplete component evidence",
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
        format!("device_state_sections={}", sample.device_state_sections),
        format!(
            "device_state_digest={}",
            lowercase_hex(&sample.device_state_digest)
        ),
        format!(
            "device_state_schema_digest={}",
            lowercase_hex(&sample.device_state_schema_digest)
        ),
    ]);
    let fingerprint = ExecutionFingerprint {
        hash: crucible::ContentHash::from_canonical_material(
            BLACK_BOX_EXECUTION_FINGERPRINT_DOMAIN,
            &material.join("\n"),
        ),
    };
    report_fingerprint_components(node, &fingerprint, &material);
    Ok(fingerprint)
}

// Sampling already owns these validated components. Diagnostics issue no
// control request and never alter the fingerprint or checkpoint envelope.
fn report_fingerprint_components(
    node: &crucible::NodeId,
    fingerprint: &ExecutionFingerprint,
    material: &[String],
) {
    static REMAINING: OnceLock<AtomicU16> = OnceLock::new();
    let remaining = REMAINING.get_or_init(|| {
        let maximum = std::env::var("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or_default()
            .min(64);
        AtomicU16::new(maximum)
    });
    if remaining
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_sub(1)
        })
        .is_err()
    {
        return;
    }
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        fingerprint_component_diagnostic(node, fingerprint, material)
    );
}

fn fingerprint_component_diagnostic(
    node: &crucible::NodeId,
    fingerprint: &ExecutionFingerprint,
    material: &[String],
) -> String {
    // Numeric and digest components have fixed protocol bounds (eight vCPUs).
    // Escape and bound the only caller-authored string independently.
    let node_prefix = node.name.chars().take(160).collect::<String>();
    format!(
        "CRUCIBLE-QEMU-FINGERPRINT-V1 host_process_id={} node={node_prefix:?} fingerprint={} components={:?}",
        std::process::id(),
        fingerprint.hash.to_hex(),
        material.get(1..).unwrap_or_default(),
    )
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

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn component_diagnostic_bounds_and_escapes_node_names() {
        let node = crucible::NodeId {
            name: format!("quoted\"\n{}suffix", "x".repeat(160)),
        };
        let fingerprint = ExecutionFingerprint {
            hash: crucible::ContentHash::from_bytes(b"diagnostic"),
        };
        let material = vec![
            format!("node={}", node.name),
            String::from("sample_icount=0"),
            String::from("ram_digest=0123456789abcdef"),
        ];

        let diagnostic = fingerprint_component_diagnostic(&node, &fingerprint, &material);

        assert_eq!(diagnostic.lines().count(), 1);
        assert!(diagnostic.contains("quoted\\\"\\n"));
        assert!(!diagnostic.contains("suffix"));
        assert!(diagnostic.contains(&fingerprint.hash.to_hex()));
        assert!(diagnostic.contains("sample_icount=0"));
        assert!(diagnostic.contains("ram_digest=0123456789abcdef"));
    }
}
