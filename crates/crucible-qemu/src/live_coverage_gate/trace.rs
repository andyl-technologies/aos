//! Independent instruction/register/RAM/device fingerprint observation.

use std::fs;
use std::path::Path;

use crucible::ContentHash;
use serde_json::Value;

use super::{GATE_DOMAIN, LoadedQemuCoverageGateConfig, LoadedQemuCoverageGateError};

pub(super) fn trace_plugin_argument(
    config: &LoadedQemuCoverageGateConfig,
    trace_path: &Path,
) -> String {
    let launch_material = format!(
        "qemu={}\nplugin={}\ntrace_plugin={}\nkernel={}\nroot_image={}\nhorizon_icount={}",
        config.qemu_executable.display(),
        config.plugin.display(),
        config.trace_plugin.display(),
        config.kernel.display(),
        config.root_image.display(),
        config.horizon_icount,
    );
    let launch_digest = ContentHash::from_canonical_material(GATE_DOMAIN, &launch_material);
    let qemu_digest = ContentHash::from_canonical_material(
        GATE_DOMAIN,
        &format!("qemu={}", config.qemu_executable.display()),
    );
    let trace_plugin_digest = ContentHash::from_canonical_material(
        GATE_DOMAIN,
        &format!("trace_plugin={}", config.trace_plugin.display()),
    );
    format!(
        "{},out={},cadence={},extended=on,mem_events=on,rr_switch_events=on,vcpus=1,launch_digest={},qemu_build_digest={},plugin_build_digest={}",
        config.trace_plugin.display(),
        trace_path.display(),
        config.horizon_icount,
        launch_digest.to_hex(),
        qemu_digest.to_hex(),
        trace_plugin_digest.to_hex(),
    )
}

pub(super) fn read_trace_sample(
    trace_path: &Path,
    horizon_icount: u64,
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
        if value.get("retired").and_then(Value::as_u64) == Some(horizon_icount)
            && value.get("final").and_then(Value::as_bool) == Some(false)
        {
            exact_sample = Some(value);
        }
    }
    let sample = exact_sample.ok_or(LoadedQemuCoverageGateError::TraceSampleMissing {
        mode,
        horizon_icount,
    })?;
    validate_trace_sample(&sample, mode)?;
    Ok(sample)
}

fn validate_trace_sample(
    sample: &Value,
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
    ] {
        if sample.get(field).and_then(Value::as_bool) != Some(true) {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "RR, RAM, or device observation was disabled",
            });
        }
    }
    for field in ["sample_register_failures", "register_read_failures"] {
        if sample.get(field).and_then(Value::as_u64) != Some(0) {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "one or more vCPU register reads failed",
            });
        }
    }
    if sample.get("tracked_vcpus").and_then(Value::as_u64) != Some(1)
        || sample.get("ram_bytes").and_then(Value::as_u64) == Some(0)
        || sample.get("ram_bytes").and_then(Value::as_u64).is_none()
    {
        return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
            mode,
            reason: "vCPU topology or RAM coverage is incomplete",
        });
    }
    for field in [
        "stream_hash",
        "register_hash",
        "register_hashes",
        "register_counts",
        "register_file_bytes",
        "register_schema_hashes",
        "register_retired",
        "ram_hash",
        "device_event_hash",
        "extended_hash",
    ] {
        if sample.get(field).is_none() || sample.get(field) == Some(&Value::Null) {
            return Err(LoadedQemuCoverageGateError::TraceSampleIncomplete {
                mode,
                reason: "a required instruction/register/RAM/device component is absent",
            });
        }
    }
    Ok(())
}
