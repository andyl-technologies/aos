//! Independent instruction/register/RAM/device fingerprint observation.

use std::fs;
use std::path::Path;

use crucible::ContentHash;
use serde_json::Value;

use super::{
    GATE_DOMAIN, GUEST_POST_IO_PC, LoadedQemuCoverageGateConfig, LoadedQemuCoverageGateError,
};

const FNV1A64_OFFSET: u64 = 14_695_981_039_346_656_037;
const FNV1A64_OFFSET_HEX: &str = "cbf29ce484222325";
const FNV1A64_PRIME: u64 = 1_099_511_628_211;
const EXPECTED_VCPUS: u64 = 1;
const EXPECTED_GUEST_RAM_BYTES: u64 = 64 * 1024 * 1024;

struct TraceProvenance {
    launch: String,
    qemu: String,
    plugin: String,
}

pub(super) fn trace_plugin_argument(
    config: &LoadedQemuCoverageGateConfig,
    trace_path: &Path,
) -> String {
    let provenance = trace_provenance(config);
    format!(
        "{},out={},cadence={},extended=on,mem_events=on,post_boundary=on,required_pc={},rr_switch_events=on,vcpus=1,launch_digest={},qemu_build_digest={},plugin_build_digest={}",
        config.trace_plugin.display(),
        trace_path.display(),
        config.horizon_icount,
        GUEST_POST_IO_PC,
        provenance.launch,
        provenance.qemu,
        provenance.plugin,
    )
}

fn trace_provenance(config: &LoadedQemuCoverageGateConfig) -> TraceProvenance {
    let launch_material = format!(
        "qemu={}\nplugin={}\ntrace_plugin={}\nkernel={}\nroot_image={}\nhorizon_icount={}",
        config.qemu_executable.display(),
        config.plugin.display(),
        config.trace_plugin.display(),
        config.kernel.display(),
        config.root_image.display(),
        config.horizon_icount,
    );
    TraceProvenance {
        launch: ContentHash::from_canonical_material(GATE_DOMAIN, &launch_material).to_hex(),
        qemu: ContentHash::from_canonical_material(
            GATE_DOMAIN,
            &format!("qemu={}", config.qemu_executable.display()),
        )
        .to_hex(),
        plugin: ContentHash::from_canonical_material(
            GATE_DOMAIN,
            &format!("trace_plugin={}", config.trace_plugin.display()),
        )
        .to_hex(),
    }
}

pub(super) fn read_trace_sample(
    trace_path: &Path,
    config: &LoadedQemuCoverageGateConfig,
    mode: &'static str,
) -> Result<Value, LoadedQemuCoverageGateError> {
    let trace = fs::read_to_string(trace_path).map_err(|source| {
        LoadedQemuCoverageGateError::TraceRead {
            mode,
            path: trace_path.to_owned(),
            source,
        }
    })?;
    let mut exact_sample = None;
    for line in trace.lines().filter(|line| !line.trim().is_empty()) {
        let value: Value = serde_json::from_str(line)
            .map_err(|source| LoadedQemuCoverageGateError::TraceDecode { mode, source })?;
        if value.get("retired").and_then(Value::as_u64) == Some(config.horizon_icount)
            && value.get("observer_icount").and_then(Value::as_u64) == Some(config.horizon_icount)
            && value.get("final").and_then(Value::as_bool) == Some(false)
            && value.get("post_boundary_sample").and_then(Value::as_bool) == Some(true)
        {
            if exact_sample.is_some() {
                return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                    mode,
                    reason: "the exact post-boundary trace sample was duplicated",
                });
            }
            exact_sample = Some(value);
        }
    }
    let sample = exact_sample.ok_or(LoadedQemuCoverageGateError::TraceSampleMissing {
        mode,
        horizon_icount: config.horizon_icount,
    })?;
    validate_trace_sample(&sample, config, mode)?;
    Ok(sample)
}

fn validate_trace_sample(
    sample: &Value,
    config: &LoadedQemuCoverageGateConfig,
    mode: &'static str,
) -> Result<(), LoadedQemuCoverageGateError> {
    for (field, expected) in [
        ("schema", "crucible.qemu.trace-fingerprint.v2"),
        ("rr_cursor_source", "live_instruction"),
    ] {
        if sample.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "trace schema or RR cursor source is invalid",
            });
        }
    }
    for field in [
        "rr_cursor_valid",
        "device_event_capture",
        "memory_events_enabled",
        "post_boundary_sample",
    ] {
        if sample.get(field).and_then(Value::as_bool) != Some(true) {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "RR, RAM, device, or post-boundary observation was disabled",
            });
        }
    }
    if sample.get("final").and_then(Value::as_bool) != Some(false)
        || sample.get("stop_requested").and_then(Value::as_bool) != Some(false)
        || u64_field(sample, "stop_at") != Some(0)
        || u64_field(sample, "retired") != Some(config.horizon_icount)
        || u64_field(sample, "observer_icount") != Some(config.horizon_icount)
    {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "the trace was not sampled once at the exact post-execution boundary",
        });
    }
    let required_pc_first_retired = u64_field(sample, "required_pc_first_retired").unwrap_or(0);
    if u64_field(sample, "required_pc") != Some(GUEST_POST_IO_PC)
        || sample.get("required_pc_seen").and_then(Value::as_bool) != Some(true)
        || required_pc_first_retired == 0
        || required_pc_first_retired > config.horizon_icount
    {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "the standalone guest did not reach its known post-I/O basic block",
        });
    }
    // Count the inclusive guest instruction range and the exact-boundary state sample.
    let expected_trajectory_steps = config
        .horizon_icount
        .checked_sub(required_pc_first_retired)
        .and_then(|steps| steps.checked_add(2));
    if u64_field(sample, "trajectory_steps") != expected_trajectory_steps {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "the per-instruction guest trajectory did not cover every instruction after the post-I/O boundary",
        });
    }
    for field in ["sample_register_failures", "register_read_failures"] {
        if u64_field(sample, field) != Some(0) {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "one or more vCPU register reads failed",
            });
        }
    }
    if u64_field(sample, "tracked_vcpus") != Some(EXPECTED_VCPUS)
        || u64_field(sample, "rr_current_vcpu") != Some(0)
        || !rr_cursor_is_bounded(sample)
    {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "vCPU topology or round-robin cursor coverage is incomplete",
        });
    }
    validate_register_arrays(sample, config.horizon_icount, mode)?;
    let ram_bytes = u64_field(sample, "ram_bytes").ok_or(
        LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "RAM byte coverage is absent",
        },
    )?;
    if ram_bytes != EXPECTED_GUEST_RAM_BYTES {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "RAM hashing did not cover exactly the configured 64 MiB guest memory",
        });
    }
    let memory_events = u64_field(sample, "memory_events").unwrap_or(0);
    let io_events = u64_field(sample, "io_events").unwrap_or(0);
    if memory_events == 0 || io_events == 0 || io_events > memory_events {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "the guest did not produce a complete memory and device-I/O trajectory",
        });
    }
    for field in [
        "stream_hash",
        "register_hash",
        "trajectory_hash",
        "memory_event_hash",
        "ram_hash",
        "device_event_hash",
        "extended_hash",
    ] {
        require_nonzero_hex(sample, field, 16, mode)?;
    }
    for field in [
        "launch_definition_digest",
        "qemu_build_digest",
        "trace_plugin_build_digest",
    ] {
        require_nonzero_hex(sample, field, 64, mode)?;
    }
    let provenance = trace_provenance(config);
    if sample
        .get("launch_definition_digest")
        .and_then(Value::as_str)
        != Some(provenance.launch.as_str())
        || sample.get("qemu_build_digest").and_then(Value::as_str) != Some(provenance.qemu.as_str())
        || sample
            .get("trace_plugin_build_digest")
            .and_then(Value::as_str)
            != Some(provenance.plugin.as_str())
    {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "trace provenance differs from the immutable gate inputs",
        });
    }
    if sample.get("memory_event_hash").and_then(Value::as_str) == Some(FNV1A64_OFFSET_HEX)
        || sample.get("device_event_hash").and_then(Value::as_str) == Some(FNV1A64_OFFSET_HEX)
    {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "memory or device-I/O hash remained at its empty initial value",
        });
    }
    validate_extended_hash(sample, mode)?;
    Ok(())
}

fn validate_register_arrays(
    sample: &Value,
    horizon_icount: u64,
    mode: &'static str,
) -> Result<(), LoadedQemuCoverageGateError> {
    let counts = u64_array(sample, "register_counts");
    let bytes = u64_array(sample, "register_file_bytes");
    let retired = u64_array(sample, "register_retired");
    if counts
        .as_deref()
        .is_none_or(|values| values.len() != 1 || values[0] == 0)
        || bytes
            .as_deref()
            .is_none_or(|values| values.len() != 1 || values[0] == 0)
        || retired
            .as_deref()
            .is_none_or(|values| values != [horizon_icount])
    {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "register counts, canonical bytes, or retired vectors are incomplete",
        });
    }
    for field in ["register_hashes", "register_schema_hashes"] {
        let Some(values) = sample.get(field).and_then(Value::as_array) else {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "a per-vCPU register hash vector is absent",
            });
        };
        if values.len() != 1
            || values
                .iter()
                .any(|value| !is_nonzero_lower_hex(value.as_str(), 16))
        {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "a per-vCPU register hash vector is malformed or empty",
            });
        }
    }
    Ok(())
}

fn validate_extended_hash(
    sample: &Value,
    mode: &'static str,
) -> Result<(), LoadedQemuCoverageGateError> {
    let mut expected = FNV1A64_OFFSET;
    for value in [
        parsed_hex_field(sample, "stream_hash"),
        parsed_hex_field(sample, "register_hash"),
        parsed_hex_field(sample, "ram_hash"),
        Some(1),
        parsed_hex_field(sample, "device_event_hash"),
        u64_field(sample, "rr_current_vcpu"),
        u64_field(sample, "rr_cursor_position"),
        u64_field(sample, "rr_switch_quantum"),
        Some(1),
        Some(0),
        u64_field(sample, "tracked_vcpus"),
        u64_field(sample, "stop_at"),
        parsed_hex_field(sample, "trajectory_hash"),
        parsed_hex_field(sample, "memory_event_hash"),
        Some(1),
        u64_field(sample, "observer_icount"),
        u64_field(sample, "required_pc"),
        Some(1),
        u64_field(sample, "required_pc_first_retired"),
    ] {
        let Some(value) = value else {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "an extended-hash component has the wrong type",
            });
        };
        expected = fnv1a_u64(expected, value);
    }
    if parsed_hex_field(sample, "extended_hash") != Some(expected) {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "the extended hash is inconsistent with its component fields",
        });
    }
    Ok(())
}

fn rr_cursor_is_bounded(sample: &Value) -> bool {
    let Some(position) = u64_field(sample, "rr_cursor_position") else {
        return false;
    };
    let Some(quantum) = u64_field(sample, "rr_switch_quantum") else {
        return false;
    };
    quantum > 0 && position < quantum
}

fn require_nonzero_hex(
    sample: &Value,
    field: &'static str,
    width: usize,
    mode: &'static str,
) -> Result<(), LoadedQemuCoverageGateError> {
    if is_nonzero_lower_hex(sample.get(field).and_then(Value::as_str), width) {
        Ok(())
    } else {
        Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "a required fingerprint hash is malformed or empty",
        })
    }
}

fn is_nonzero_lower_hex(value: Option<&str>, width: usize) -> bool {
    value.is_some_and(|value| {
        value.len() == width
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && value.bytes().any(|byte| byte != b'0')
    })
}

fn parsed_hex_field(sample: &Value, field: &str) -> Option<u64> {
    u64::from_str_radix(sample.get(field)?.as_str()?, 16).ok()
}

fn u64_field(sample: &Value, field: &str) -> Option<u64> {
    sample.get(field)?.as_u64()
}

fn u64_array(sample: &Value, field: &str) -> Option<Vec<u64>> {
    sample
        .get(field)?
        .as_array()?
        .iter()
        .map(Value::as_u64)
        .collect()
}

fn fnv1a_u64(mut hash: u64, value: u64) -> u64 {
    for byte in value.to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn extended_hash_rejects_a_component_mismatch() {
        let sample = json!({
            "stream_hash": "0000000000000001",
            "register_hash": "0000000000000002",
            "ram_hash": "0000000000000003",
            "device_event_hash": "0000000000000004",
            "rr_current_vcpu": 0,
            "rr_cursor_position": 1,
            "rr_switch_quantum": 1024,
            "tracked_vcpus": 1,
            "stop_at": 0,
            "trajectory_hash": "0000000000000005",
            "memory_event_hash": "0000000000000006",
            "observer_icount": 32768,
            "required_pc": 1050624,
            "required_pc_first_retired": 2048,
            "extended_hash": "0000000000000007"
        });

        assert!(matches!(
            validate_extended_hash(&sample, "coverage-on"),
            Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                reason: "the extended hash is inconsistent with its component fields",
                ..
            })
        ));
    }

    #[test]
    fn register_validation_rejects_zero_count_placeholder_vectors() {
        let sample = json!({
            "register_counts": [0],
            "register_file_bytes": [512],
            "register_retired": [32768],
            "register_hashes": ["0000000000000001"],
            "register_schema_hashes": ["0000000000000002"]
        });

        assert!(validate_register_arrays(&sample, 32_768, "coverage-on").is_err());
    }

    #[test]
    fn fingerprint_hash_validation_rejects_uppercase_and_empty_values() {
        assert!(!is_nonzero_lower_hex(Some("0000000000000000"), 16));
        assert!(!is_nonzero_lower_hex(Some("000000000000000A"), 16));
        assert!(is_nonzero_lower_hex(Some("000000000000000a"), 16));
    }
}
