//! Handler for the private `aos-package-runtime _test-systemd-client` command.
//!
//! A thin JSON wrapper over [`aos_systemd::SystemdClient`], used only by the
//! fleet test `tests/fleet/apm-systemd-client.nix`. Not a stable interface —
//! the `_` prefix marks it internal.
//!
//! Output contract (consumed by the fleet test's `json.loads`):
//!
//! - **Success** → one JSON object on **stdout**, exit 0. Each op tags itself
//!   with `"op": "<name>"`.
//! - **Unit-lifecycle ops always exit 0**, even when the systemd job result is
//!   `failed` / `timeout` / `dependency`: the job *ran*, and its outcome is
//!   data, not an error. The result lands in the `"result"` field.
//! - **Transport / protocol failure** (bus unreachable, sender dropped) → one
//!   JSON object `{"op": "...", "error": "..."}` on **stderr**, exit 1.

use anyhow::Result;
use serde_json::json;

use aos_core::output::Printer;
use aos_systemd::{JobOutcome, OwnedValue, SystemdClient, Value};

use crate::TestSystemdClientOp;

/// Entry point: dispatch one op, print its JSON result, map transport errors to
/// a JSON error on stderr + exit 1.
pub async fn run(op: &TestSystemdClientOp, _printer: &Printer) -> Result<()> {
    match dispatch(op).await {
        Ok(value) => {
            println!("{value}");
            Ok(())
        }
        Err(err) => {
            // Emit the error structure as JSON on stderr and exit non-zero.
            // (Job results that are failed/timeout/dependency are NOT errors —
            // `dispatch` returns them as data with exit 0.) We exit directly
            // rather than returning `Err` so stderr carries only this JSON, not
            // also `main.rs`'s human-formatted error line.
            let payload = json!({"op": op_label(op), "error": err.to_string()});
            eprintln!("{payload}");
            std::process::exit(1);
        }
    }
}

/// Open one client, run the op, and build its success JSON. Any `?` here is a
/// transport/protocol error routed to the error branch in [`run`].
async fn dispatch(op: &TestSystemdClientOp) -> Result<serde_json::Value> {
    let client = SystemdClient::connect().await?;

    let value = match op {
        TestSystemdClientOp::Start { unit } => {
            job_json("start", unit, client.start_unit(unit).await?)
        }
        TestSystemdClientOp::Stop { unit } => job_json("stop", unit, client.stop_unit(unit).await?),
        TestSystemdClientOp::Restart { unit } => {
            job_json("restart", unit, client.restart_unit(unit).await?)
        }
        TestSystemdClientOp::Reload { unit } => {
            job_json("reload", unit, client.reload_unit(unit).await?)
        }
        TestSystemdClientOp::Isolate { unit } => {
            job_json("isolate", unit, client.isolate_unit(unit).await?)
        }
        TestSystemdClientOp::DaemonReload => {
            client.daemon_reload().await?;
            json!({"op": "daemon-reload", "status": "ok"})
        }
        TestSystemdClientOp::ResetFailed { unit } => {
            match unit {
                Some(u) => client.reset_failed_unit(u).await?,
                None => client.reset_failed().await?,
            }
            json!({"op": "reset-failed", "status": "ok"})
        }
        TestSystemdClientOp::IsActive { unit } => {
            let active = client.is_active(unit).await?;
            json!({"op": "is-active", "unit": unit, "active": active})
        }
        TestSystemdClientOp::ListUnits { pattern, state } => {
            // `list_units_by_patterns` takes `&[&str]`; an absent filter is the
            // empty slice (systemd treats that as "no filter").
            let states: Vec<&str> = state.as_deref().into_iter().collect();
            let patterns: Vec<&str> = pattern.as_deref().into_iter().collect();
            let units = client.list_units_by_patterns(&states, &patterns).await?;
            json!({"op": "list-units", "units": serde_json::to_value(&units)?})
        }
        TestSystemdClientOp::Property { unit, name } => {
            let value = client.unit_property(unit, name).await?;
            json!({
                "op": "property",
                "unit": unit,
                "name": name,
                "value": value_to_json(&value),
            })
        }
        TestSystemdClientOp::FailedUnits => {
            let report = client.failed_units().await?;
            json!({"op": "failed-units", "failed": serde_json::to_value(&report.failed)?})
        }
        TestSystemdClientOp::Settle => {
            let drained = client.settle().await?;
            json!({"op": "settle", "messages_drained": drained as u64})
        }
    };

    Ok(value)
}

/// JSON for a unit-lifecycle op: the submitted job's path + its classified
/// result. `result` is serialised via `JobResult`'s label
/// (`done`/`failed`/`timeout`/`dependency`/<raw>).
fn job_json(op: &str, unit: &str, outcome: JobOutcome) -> serde_json::Value {
    json!({
        "op": op,
        "unit": unit,
        "job_path": outcome.job_path.as_str(),
        "result": outcome.result.label(),
    })
}

/// The op's stable label, used for the error payload's `"op"` field (so the
/// label is available even when the op's own call fails before producing one).
fn op_label(op: &TestSystemdClientOp) -> &'static str {
    match op {
        TestSystemdClientOp::Start { .. } => "start",
        TestSystemdClientOp::Stop { .. } => "stop",
        TestSystemdClientOp::Restart { .. } => "restart",
        TestSystemdClientOp::Reload { .. } => "reload",
        TestSystemdClientOp::Isolate { .. } => "isolate",
        TestSystemdClientOp::DaemonReload => "daemon-reload",
        TestSystemdClientOp::ResetFailed { .. } => "reset-failed",
        TestSystemdClientOp::IsActive { .. } => "is-active",
        TestSystemdClientOp::ListUnits { .. } => "list-units",
        TestSystemdClientOp::Property { .. } => "property",
        TestSystemdClientOp::FailedUnits => "failed-units",
        TestSystemdClientOp::Settle => "settle",
    }
}

/// Render a unit property's `OwnedValue` as a JSON scalar. The only property
/// the fleet test reads is `ActiveState` (a string); the other scalar arms are
/// defensive, and any compound value (`Array`/`Dict`/`Structure`/…) falls back
/// to its `Debug` form. Every embedded value is a primitive, `&str`, or `bool`,
/// so the `json!` expansion is conversion-impl-agnostic.
fn value_to_json(v: &OwnedValue) -> serde_json::Value {
    match &**v {
        Value::Bool(b) => json!(*b),
        Value::Str(s) => json!(s.as_str()),
        Value::U8(n) => json!(*n),
        Value::I16(n) => json!(*n),
        Value::U16(n) => json!(*n),
        Value::I32(n) => json!(*n),
        Value::U32(n) => json!(*n),
        Value::I64(n) => json!(*n),
        Value::U64(n) => json!(*n),
        Value::F64(n) => json!(*n),
        Value::ObjectPath(p) => json!(p.as_str()),
        other => json!(format!("{other:?}")),
    }
}
