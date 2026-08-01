//! Independent instruction/register/RAM/device fingerprint observation.

use std::fs;
use std::path::Path;
use std::time::Instant;

use crucible::ContentHash;
use serde_json::{Map, Value};

use super::{
    GATE_DOMAIN, GUEST_POST_IO_PC, LoadedQemuCoverageGateConfig, LoadedQemuCoverageGateError,
};

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
    read_trace_sample_with_wait(trace_path, config, mode, super::wait_for_poll_interval)
}

// crucible-lint: allow clippy-disallowed-method -- loaded-gate host timeout bounds trace publication only.
#[allow(clippy::disallowed_methods)]
fn read_trace_sample_with_wait(
    trace_path: &Path,
    config: &LoadedQemuCoverageGateConfig,
    mode: &'static str,
    mut wait_for_poll: impl FnMut(),
) -> Result<Value, LoadedQemuCoverageGateError> {
    let started = Instant::now();
    loop {
        if let Some(sample) = try_read_trace_sample(trace_path, config, mode)? {
            validate_trace_sample(&sample, config, mode)?;
            return Ok(canonical_acceptance_sample(&sample));
        }
        if started.elapsed() >= config.completion_timeout {
            return Err(LoadedQemuCoverageGateError::TraceSampleMissing {
                mode,
                horizon_icount: config.horizon_icount,
            });
        }
        wait_for_poll();
    }
}

fn try_read_trace_sample(
    trace_path: &Path,
    config: &LoadedQemuCoverageGateConfig,
    mode: &'static str,
) -> Result<Option<Value>, LoadedQemuCoverageGateError> {
    let trace = match fs::read_to_string(trace_path) {
        Ok(trace) => trace,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(LoadedQemuCoverageGateError::TraceRead {
                mode,
                path: trace_path.to_owned(),
                source,
            });
        }
    };
    let mut exact_sample = None;
    let complete_trace = trace
        .rsplit_once('\n')
        .map_or("", |(complete, _partial)| complete);
    for line in complete_trace
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let value: Value = serde_json::from_str(line)
            .map_err(|source| LoadedQemuCoverageGateError::TraceDecode { mode, source })?;
        if value.get("observed_icount").and_then(Value::as_u64) == Some(config.horizon_icount)
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
    Ok(exact_sample)
}

/// Projects a validated trace sample onto cryptographic acceptance fields.
fn canonical_acceptance_sample(sample: &Value) -> Value {
    let mut projection = Map::new();
    for field in [
        "schema",
        "retired",
        "vcpu",
        "final",
        "tracked_vcpus",
        "stop_at",
        "stop_requested",
        "trigger",
        "event_boundary",
        "observed_icount",
        "post_boundary_sample",
        "trajectory_steps",
        "trajectory_digest",
        "required_pc",
        "required_pc_seen",
        "required_pc_first_retired",
        "rr_current_vcpu",
        "rr_cursor_position",
        "rr_switch_quantum",
        "rr_cursor_valid",
        "rr_cursor_source",
        "launch_definition_digest",
        "qemu_build_digest",
        "trace_plugin_build_digest",
        "register_digests",
        "register_counts",
        "register_file_bytes",
        "register_schema_digests",
        "register_retired",
        "ram_digest",
        "ram_status",
        "ram_bytes",
        "device_state_digest",
        "device_state_schema_digest",
        "device_state_sections",
        "device_state_bytes",
        "device_state_status",
        "device_state_schema_status",
        "device_state_complete",
        "memory_events",
        "io_events",
        "memory_events_enabled",
        "sample_register_failures",
        "register_read_failures",
        "device_state_failures",
        "trajectory_digest_failures",
    ] {
        if let Some(value) = sample.get(field) {
            projection.insert(field.to_owned(), value.clone());
        }
    }
    Value::Object(projection)
}

fn validate_trace_sample(
    sample: &Value,
    config: &LoadedQemuCoverageGateConfig,
    mode: &'static str,
) -> Result<(), LoadedQemuCoverageGateError> {
    for (field, expected) in [
        ("schema", "crucible.qemu.trace-fingerprint.v6"),
        ("process_argv_encoding", "raw-unix-argv-v2"),
        ("rr_cursor_source", "live_instruction"),
    ] {
        if sample.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "trace schema or RR cursor source is invalid",
            });
        }
    }
    if u64_field(sample, "process_argv_status") != Some(0)
        || u64_field(sample, "process_argv_attestation_version") != Some(2)
        || u64_field(sample, "process_argv_argc").is_none_or(|argc| argc == 0)
        || u64_field(sample, "process_argv_raw_bytes").is_none_or(|bytes| bytes == 0)
    {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "QEMU process argv self-attestation is incomplete",
        });
    }
    require_nonzero_hex(sample, "process_argv_digest", 64, mode)?;
    for field in [
        "rr_cursor_valid",
        "device_state_complete",
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
    let retired =
        u64_field(sample, "retired").ok_or(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "the trace omitted its aggregate retired-instruction count",
        })?;
    if sample.get("final").and_then(Value::as_bool) != Some(false)
        || sample.get("stop_requested").and_then(Value::as_bool) != Some(false)
        || u64_field(sample, "stop_at") != Some(0)
        || u64_field(sample, "observed_icount") != Some(config.horizon_icount)
        || retired > config.horizon_icount
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
        || required_pc_first_retired > retired
    {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "the standalone guest did not reach its known post-I/O basic block",
        });
    }
    // Count the inclusive guest instruction range and the exact-boundary state sample.
    let expected_trajectory_steps = retired
        .checked_sub(required_pc_first_retired)
        .and_then(|steps| steps.checked_add(2));
    if u64_field(sample, "trajectory_steps") != expected_trajectory_steps {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "the per-instruction guest trajectory did not cover every instruction after the post-I/O boundary",
        });
    }
    for field in [
        "sample_register_failures",
        "register_read_failures",
        "ram_status",
        "device_state_failures",
        "device_state_status",
        "device_state_schema_status",
        "trajectory_digest_failures",
    ] {
        if u64_field(sample, field) != Some(0) {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "one or more register, RAM, or device-state observations failed",
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
    validate_register_arrays(sample, retired, mode)?;
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
    if u64_field(sample, "device_state_bytes").is_none_or(|bytes| bytes == 0) {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "serialized non-RAM VMState byte coverage is absent",
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
        "trajectory_digest",
        "ram_digest",
        "device_state_digest",
        "device_state_schema_digest",
    ] {
        require_nonzero_hex(sample, field, 64, mode)?;
    }
    if u64_field(sample, "device_state_sections").is_none_or(|sections| sections == 0) {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "serialized non-RAM VMState schema coverage is absent",
        });
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
    for field in ["register_digests", "register_schema_digests"] {
        let Some(values) = sample.get(field).and_then(Value::as_array) else {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "a per-vCPU register digest vector is absent",
            });
        };
        if values.len() != 1
            || values
                .iter()
                .any(|value| !is_nonzero_lower_hex(value.as_str(), 64))
        {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "a per-vCPU register digest vector is malformed or empty",
            });
        }
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

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    #[test]
    fn acceptance_projection_excludes_noncryptographic_diagnostics() {
        let sample = json!({
            "stream_hash": "0000000000000001",
            "trajectory_hash": "0000000000000002",
            "memory_event_hash": "0000000000000003",
            "device_event_hash": "0000000000000004",
            "diagnostic_extended_fnv": "0000000000000005",
            "trajectory_digest": "11".repeat(32),
            "ram_digest": "22".repeat(32),
            "device_state_digest": "33".repeat(32)
        });
        let projection = canonical_acceptance_sample(&sample);

        assert!(projection.get("stream_hash").is_none());
        assert!(projection.get("trajectory_hash").is_none());
        assert!(projection.get("memory_event_hash").is_none());
        assert!(projection.get("device_event_hash").is_none());
        assert!(projection.get("diagnostic_extended_fnv").is_none());
        assert_eq!(projection["trajectory_digest"], sample["trajectory_digest"]);
    }

    #[test]
    fn register_validation_rejects_zero_count_placeholder_vectors() {
        let sample = json!({
            "register_counts": [0],
            "register_file_bytes": [512],
            "register_retired": [32768],
            "register_digests": ["0000000000000000000000000000000000000000000000000000000000000001"],
            "register_schema_digests": ["0000000000000000000000000000000000000000000000000000000000000002"]
        });

        assert!(validate_register_arrays(&sample, 32_768, "coverage-on").is_err());
    }

    #[test]
    fn fingerprint_hash_validation_rejects_uppercase_and_empty_values() {
        assert!(!is_nonzero_lower_hex(
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
            64
        ));
        assert!(!is_nonzero_lower_hex(
            Some("000000000000000000000000000000000000000000000000000000000000000A"),
            64
        ));
        assert!(is_nonzero_lower_hex(
            Some("000000000000000000000000000000000000000000000000000000000000000a"),
            64
        ));
    }

    #[test]
    fn trace_polling_waits_for_creation_and_a_complete_json_line()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = test_trace_path("partial");
        let config = test_config()
            .with_horizon_icount(16)
            .with_completion_timeout(Duration::from_secs(1));
        let _ = fs::remove_file(&path);

        let record = serde_json::to_string(&valid_trace_sample(&config, 12))?;
        fs::write(&path, &record[..record.len() / 2])?;
        let reader_path = path.clone();
        let (poll_observed_tx, poll_observed_rx) = mpsc::channel();
        let (publish_tx, publish_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            read_trace_sample_with_wait(&reader_path, &config, "coverage-off", || {
                poll_observed_tx
                    .send(())
                    .unwrap_or_else(|error| panic!("publish poll observation: {error}"));
                publish_rx
                    .recv()
                    .unwrap_or_else(|error| panic!("wait for trace publication: {error}"));
            })
        });
        poll_observed_rx.recv()?;
        fs::write(&path, format!("{record}\n"))?;
        publish_tx.send(())?;
        let sample = reader
            .join()
            .map_err(|_| "trace reader thread panicked")??;
        assert_eq!(sample["retired"], 12);

        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn trace_polling_rejects_duplicate_complete_target_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = test_trace_path("duplicate");
        let config = test_config().with_horizon_icount(16);
        let record = r#"{"observed_icount":16,"final":false,"post_boundary_sample":true}"#;
        fs::write(&path, format!("{record}\n{record}\n"))?;

        assert!(matches!(
            try_read_trace_sample(&path, &config, "coverage-off"),
            Err(LoadedQemuCoverageGateError::TraceSampleIncomplete { .. })
        ));

        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn trace_polling_bounds_an_absent_trace_file() {
        let path = test_trace_path("absent");
        let config = test_config()
            .with_horizon_icount(16)
            .with_completion_timeout(Duration::ZERO);
        let _ = fs::remove_file(&path);

        assert!(matches!(
            read_trace_sample(&path, &config, "coverage-off"),
            Err(LoadedQemuCoverageGateError::TraceSampleMissing {
                horizon_icount: 16,
                ..
            })
        ));
    }

    #[test]
    fn trace_validation_separates_logical_icount_from_retired_instructions() {
        let config = test_config().with_horizon_icount(16);
        let sample = valid_trace_sample(&config, 12);
        assert!(validate_trace_sample(&sample, &config, "coverage-off").is_ok());

        let mut overrun = sample.clone();
        overrun["retired"] = Value::from(17);
        assert!(validate_trace_sample(&overrun, &config, "coverage-off").is_err());

        let mut register_mismatch = sample.clone();
        register_mismatch["register_retired"] = json!([16]);
        assert!(validate_trace_sample(&register_mismatch, &config, "coverage-off").is_err());

        let mut trajectory_mismatch = sample;
        trajectory_mismatch["trajectory_steps"] = Value::from(14);
        assert!(validate_trace_sample(&trajectory_mismatch, &config, "coverage-off").is_err());
    }

    fn test_config() -> LoadedQemuCoverageGateConfig {
        LoadedQemuCoverageGateConfig::new(
            "qemu",
            "plugin",
            "trace-plugin",
            "kernel",
            "root-image",
            "coverage-off",
            "coverage-on",
        )
    }

    fn test_trace_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "crucible-live-coverage-trace-{label}-{}.jsonl",
            std::process::id()
        ))
    }

    fn valid_trace_sample(config: &LoadedQemuCoverageGateConfig, retired: u64) -> Value {
        let provenance = trace_provenance(config);
        let mut sample = json!({
            "schema": "crucible.qemu.trace-fingerprint.v6",
            "retired": retired,
            "vcpu": 0,
            "final": false,
            "tracked_vcpus": 1,
            "stop_at": 0,
            "stop_requested": false,
            "trigger": "periodic",
            "event_boundary": null,
            "observed_icount": config.horizon_icount,
            "post_boundary_sample": true
        });
        let execution = json!({
            "trajectory_steps": retired - 4 + 2,
            "trajectory_digest": "11".repeat(32),
            "required_pc": GUEST_POST_IO_PC,
            "required_pc_seen": true,
            "required_pc_first_retired": 4,
            "rr_current_vcpu": 0,
            "rr_cursor_position": 3,
            "rr_switch_quantum": 4,
            "rr_cursor_valid": true,
            "rr_cursor_source": "live_instruction",
            "launch_definition_digest": provenance.launch,
            "qemu_build_digest": provenance.qemu,
            "trace_plugin_build_digest": provenance.plugin,
            "process_argv_attestation_version": 2,
            "process_argv_encoding": "raw-unix-argv-v2",
            "process_argv_argc": 2,
            "process_argv_raw_bytes": 16,
            "process_argv_digest": "22".repeat(32),
            "process_argv_status": 0
        });
        let state = json!({
            "register_digests": ["33".repeat(32)],
            "register_counts": [16],
            "register_file_bytes": [128],
            "register_schema_digests": ["44".repeat(32)],
            "register_retired": [retired],
            "ram_digest": "55".repeat(32),
            "ram_status": 0,
            "ram_bytes": EXPECTED_GUEST_RAM_BYTES,
            "device_state_digest": "66".repeat(32),
            "device_state_schema_digest": "77".repeat(32),
            "device_state_sections": 2,
            "device_state_bytes": 128,
            "device_state_status": 0,
            "device_state_schema_status": 0,
            "device_state_complete": true,
            "device_event_capture": true,
            "memory_events": 8,
            "io_events": 2,
            "memory_events_enabled": true,
            "sample_register_failures": 0,
            "register_read_failures": 0,
            "device_state_failures": 0,
            "trajectory_digest_failures": 0
        });
        if let (Some(sample), Some(execution), Some(state)) = (
            sample.as_object_mut(),
            execution.as_object(),
            state.as_object(),
        ) {
            sample.extend(execution.clone());
            sample.extend(state.clone());
        }
        sample
    }
}
