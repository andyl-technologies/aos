//! Canonical black-box execution-fingerprint construction.

use super::*;

use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};

const BLACK_BOX_EXECUTION_FINGERPRINT_DOMAIN: &str =
    "crucible.qemu.black-box-execution-fingerprint.v2";

/// Checks the exact sample returned to an identity or raw-sample caller.
pub(crate) fn validate_black_box_fingerprint_sample(
    sample: &FingerprintSample,
) -> Result<(), QemuNodeChannelError> {
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

    Ok(())
}

pub(crate) fn black_box_execution_fingerprint(
    node: &crucible_engine::NodeId,
    sample: &FingerprintSample,
) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
    validate_black_box_fingerprint_sample(sample)?;

    let fingerprint = ExecutionFingerprint {
        hash: hash_black_box_material(node, sample)?,
    };
    report_fingerprint_components(node, sample, &fingerprint);
    Ok(fingerprint)
}

fn hash_black_box_material(
    node: &crucible_engine::NodeId,
    sample: &FingerprintSample,
) -> Result<crucible_engine::ContentHash, QemuNodeChannelError> {
    crucible_engine::ContentHash::from_canonical_display(
        BLACK_BOX_EXECUTION_FINGERPRINT_DOMAIN,
        &FingerprintMaterial { node, sample },
    )
    .map_err(|source| match source {
        crucible_engine::EngineError::ArtifactDecodeAdmission { source } => {
            QemuNodeChannelError::artifact_decode_admission("execution_fingerprint", source)
        }
        source => QemuNodeChannelError::new("execution_fingerprint", source.to_string()),
    })
}

/// Borrows the already validated sample and emits its existing canonical recipe.
struct FingerprintMaterial<'a> {
    node: &'a crucible_engine::NodeId,
    sample: &'a FingerprintSample,
}

impl std::fmt::Display for FingerprintMaterial<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "node={}", self.node.name)?;
        visit_fingerprint_components(self.sample, |component| write!(formatter, "\n{component}"))
    }
}

/// Visits only fixed ASCII labels, decimal integers and lowercase digests.
///
/// The hash recipe and diagnostic list share this ordering. The node name is
/// separate because it is the only authored string requiring debug escaping.
fn visit_fingerprint_components(
    sample: &FingerprintSample,
    mut component: impl FnMut(std::fmt::Arguments<'_>) -> std::fmt::Result,
) -> std::fmt::Result {
    component(format_args!("sample_icount={}", sample.sample_icount))?;
    component(format_args!("vcpu_count={}", sample.vcpu_count))?;
    component(format_args!("rr_current_vcpu={}", sample.rr_current_vcpu))?;
    component(format_args!(
        "rr_position_in_quantum={}",
        sample.rr_position_in_quantum
    ))?;
    component(format_args!(
        "rr_switch_quantum={}",
        sample.rr_switch_quantum
    ))?;

    for (index, vcpu) in sample
        .vcpus
        .iter()
        .take(sample.vcpu_count as usize)
        .enumerate()
    {
        component(format_args!(
            "vcpu[{index}].register_digest={}",
            LowercaseHex(&vcpu.register_digest),
        ))?;
        component(format_args!(
            "vcpu[{index}].register_file_bytes={}",
            vcpu.register_file_bytes,
        ))?;
        component(format_args!(
            "vcpu[{index}].retired_instruction_count={}",
            vcpu.retired_instruction_count,
        ))?;
    }

    component(format_args!("ram_bytes={}", sample.ram_bytes))?;
    component(format_args!(
        "ram_digest={}",
        LowercaseHex(&sample.ram_digest)
    ))?;
    component(format_args!(
        "device_state_bytes={}",
        sample.device_state_bytes
    ))?;
    component(format_args!(
        "device_state_sections={}",
        sample.device_state_sections
    ))?;
    component(format_args!(
        "device_state_digest={}",
        LowercaseHex(&sample.device_state_digest),
    ))?;
    component(format_args!(
        "device_state_schema_digest={}",
        LowercaseHex(&sample.device_state_schema_digest),
    ))
}

struct LowercaseHex<'a>(&'a [u8]);

impl std::fmt::Display for LowercaseHex<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
fn owned_component_material(
    node: &crucible_engine::NodeId,
    sample: &FingerprintSample,
) -> Vec<String> {
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
    material
}

// Sampling already owns these validated components. Diagnostics issue no
// control request and never alter the fingerprint or checkpoint envelope.
fn report_fingerprint_components(
    node: &crucible_engine::NodeId,
    sample: &FingerprintSample,
    fingerprint: &ExecutionFingerprint,
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
        FingerprintComponentDiagnostic {
            node,
            sample,
            fingerprint
        },
    );
}

/// Streams the existing one-line record without constructing owned fields.
struct FingerprintComponentDiagnostic<'a> {
    node: &'a crucible_engine::NodeId,
    sample: &'a FingerprintSample,
    fingerprint: &'a ExecutionFingerprint,
}

impl std::fmt::Display for FingerprintComponentDiagnostic<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = &self.node.name;
        let prefix_end = name
            .char_indices()
            .nth(160)
            .map_or(name.len(), |(offset, _)| offset);
        let node_prefix = &name[..prefix_end];
        write!(
            formatter,
            concat!(
                "CRUCIBLE-QEMU-FINGERPRINT-V1 host_process_id={} node={:?}",
                " fingerprint={} components={:?}",
            ),
            std::process::id(),
            node_prefix,
            LowercaseHex(&self.fingerprint.hash.bytes),
            FingerprintComponents(self.sample),
        )
    }
}

struct FingerprintComponents<'a>(&'a FingerprintSample);

impl std::fmt::Debug for FingerprintComponents<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = formatter.debug_list();
        visit_fingerprint_components(self.0, |component| {
            list.entry(&QuotedComponent(component));
            Ok(())
        })?;
        list.finish()
    }
}

/// Adds string-debug quotes to the visitor's exclusively safe ASCII fields.
/// Authored node text never reaches this wrapper.
struct QuotedComponent<'a>(std::fmt::Arguments<'a>);

impl std::fmt::Debug for QuotedComponent<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "\"{}\"", self.0)
    }
}

#[cfg(test)]
fn owned_fingerprint_component_diagnostic(
    node: &crucible_engine::NodeId,
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

#[cfg(test)]
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
    fn borrowed_fingerprint_hash_matches_owned_recipe_without_material_allocations()
    -> Result<(), Box<dyn std::error::Error>> {
        use crucible_host_resources::test_support::TestAllocationObserver;

        for name in [
            "",
            "vm-a",
            "é水\nquoted\"node",
            "1234567",
            "12345678",
            "123456789",
        ] {
            let node = crucible_engine::NodeId { name: name.into() };
            for count in 1..=crucible_qemu_shmem::FINGERPRINT_SAMPLE_MAX_VCPUS {
                let mut sample = FingerprintSample {
                    sample_icount: u64::MAX,
                    vcpu_count: count as u32,
                    rr_current_vcpu: (count - 1) as u32,
                    rr_position_in_quantum: u64::MAX - 1,
                    rr_switch_quantum: u64::MAX,
                    ram_bytes: u64::MAX,
                    ram_digest: [0; 32],
                    device_state_bytes: u64::MAX,
                    device_state_sections: u64::MAX,
                    device_state_digest: [0xff; 32],
                    device_state_schema_digest: [0x9a; 32],
                    ..FingerprintSample::default()
                };
                for (index, vcpu) in sample.vcpus.iter_mut().enumerate() {
                    *vcpu = crucible_qemu_shmem::FingerprintSampleVcpu {
                        register_digest: [index as u8; 32],
                        register_file_bytes: u64::MAX - index as u64,
                        retired_instruction_count: 0,
                    };
                }
                validate_black_box_fingerprint_sample(&sample)?;
                let owned = owned_component_material(&node, &sample).join("\n");
                let expected = crucible_engine::ContentHash::from_canonical_material(
                    BLACK_BOX_EXECUTION_FINGERPRINT_DOMAIN,
                    &owned,
                );

                let (actual, counts) =
                    TestAllocationObserver::count(|| hash_black_box_material(&node, &sample));

                assert_eq!(actual?, expected);
                assert_eq!(counts.allocations, 0);
                assert_eq!(counts.reallocations, 0);
                assert!(!counts.overflow);
                assert_eq!(
                    FingerprintMaterial {
                        node: &node,
                        sample: &sample
                    }
                    .to_string(),
                    owned
                );
            }
        }
        Ok(())
    }

    #[test]
    fn sticky_fingerprint_admission_retains_its_actual_cause_without_formatting()
    -> Result<(), Box<dyn std::error::Error>> {
        use crucible_engine::owned_decode::DecodeAdmissionError;
        use crucible_host_resources::test_support::TestAllocationObserver;
        use std::error::Error;

        let node = crucible_engine::NodeId {
            name: "finite-node".into(),
        };
        let mut sample = FingerprintSample {
            vcpu_count: 1,
            rr_switch_quantum: 4096,
            ram_bytes: 4096,
            device_state_bytes: 512,
            device_state_sections: 1,
            device_state_schema_digest: [1; 32],
            ..FingerprintSample::default()
        };
        sample.vcpus[0].register_file_bytes = 256;
        validate_black_box_fingerprint_sample(&sample)?;
        let scope = crucible_engine::test_support::fixture_decode_scope(512)?;
        assert!(crucible_engine::owned_decode::charge_bytes(1024).is_err());
        let expected = scope
            .check()
            .expect_err("the same actual finite account refused");

        let (result, counts) = TestAllocationObserver::count(|| {
            hash_black_box_material(&node, &sample).map_err(|channel| {
                let node = crate::QemuNodeError::from_channel(
                    crate::QemuNodeChannelPlane::ShmemHotPath,
                    channel.clone(),
                );
                (channel, node)
            })
        });

        let (channel, node) = result.expect_err("sticky admission must remain refused");
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(channel.artifact_decode_admission_source(), Some(&expected));
        assert_eq!(
            node.source()
                .and_then(|source| source.downcast_ref::<DecodeAdmissionError>()),
            Some(&expected)
        );
        assert!(!channel.is_retryable());
        assert!(channel.bounded_timeout().is_none());

        // Scheduler retention still uses its existing shared carrier; its birth
        // is outside this conversion-only allocation measurement.
        let scheduler = crucible_engine::BackendError::from(node);
        assert_eq!(
            scheduler.operational_kind(),
            Some(crucible_engine::BackendOperationalFailureKind::Unavailable)
        );
        match scheduler {
            crucible_engine::BackendError::RetainedOperationalFailure { source, .. } => {
                let original = source
                    .source()
                    .and_then(|cause| cause.downcast_ref::<crate::QemuNodeError>());
                assert!(matches!(
                    original,
                    Some(crate::QemuNodeError::ChannelDecodeAdmission { source, .. })
                        if source == &expected
                ));
            }
            other => panic!("actual operational cause was erased: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn component_diagnostic_streams_the_exact_record_without_material_allocations()
    -> Result<(), Box<dyn std::error::Error>> {
        use crucible_host_resources::test_support::TestAllocationObserver;
        use std::fmt::Write as _;

        for name in [
            String::new(),
            String::from("é水\nquoted\"node\\\t\0"),
            "é水\n\"\\".repeat(80),
        ] {
            let node = crucible_engine::NodeId { name };
            for count in 1..=crucible_qemu_shmem::FINGERPRINT_SAMPLE_MAX_VCPUS {
                let mut sample = FingerprintSample {
                    sample_icount: u64::MAX,
                    vcpu_count: count as u32,
                    rr_current_vcpu: (count - 1) as u32,
                    rr_position_in_quantum: u64::MAX - 1,
                    rr_switch_quantum: u64::MAX,
                    ram_bytes: u64::MAX,
                    ram_digest: [0; 32],
                    device_state_bytes: u64::MAX,
                    device_state_sections: u64::MAX,
                    device_state_digest: [0xff; 32],
                    device_state_schema_digest: [0x9a; 32],
                    ..FingerprintSample::default()
                };
                for (index, vcpu) in sample.vcpus.iter_mut().enumerate() {
                    vcpu.register_digest = [index as u8; 32];
                    vcpu.register_file_bytes = u64::MAX - index as u64;
                }
                validate_black_box_fingerprint_sample(&sample)?;
                let fingerprint = ExecutionFingerprint {
                    hash: hash_black_box_material(&node, &sample)?,
                };
                let expected = owned_fingerprint_component_diagnostic(
                    &node,
                    &fingerprint,
                    &owned_component_material(&node, &sample),
                );
                let mut rendered = String::with_capacity(expected.len());

                let (result, counts) = TestAllocationObserver::count(|| {
                    write!(
                        rendered,
                        "{}",
                        FingerprintComponentDiagnostic {
                            node: &node,
                            sample: &sample,
                            fingerprint: &fingerprint,
                        }
                    )
                });

                result?;
                assert_eq!(rendered, expected);
                assert_eq!(counts.allocations, 0, "{counts:?}");
                assert_eq!(counts.reallocations, 0, "{counts:?}");
                assert!(!counts.overflow);
                assert_eq!(rendered.lines().count(), 1);
            }
        }
        Ok(())
    }

    #[test]
    fn component_diagnostic_bounds_and_escapes_node_names() {
        let node = crucible_engine::NodeId {
            name: format!("quoted\"\n{}suffix", "x".repeat(160)),
        };
        let fingerprint = ExecutionFingerprint {
            hash: crucible_engine::ContentHash::from_bytes(b"diagnostic"),
        };
        let sample = FingerprintSample {
            ram_digest: [0xab; 32],
            ..FingerprintSample::default()
        };
        let diagnostic = FingerprintComponentDiagnostic {
            node: &node,
            sample: &sample,
            fingerprint: &fingerprint,
        }
        .to_string();

        assert_eq!(diagnostic.lines().count(), 1);
        assert!(diagnostic.contains("quoted\\\"\\n"));
        assert!(!diagnostic.contains("suffix"));
        assert!(diagnostic.contains(&fingerprint.hash.to_hex()));
        assert!(diagnostic.contains("sample_icount=0"));
        assert!(diagnostic.contains("ram_digest=abababab"));
    }
}
