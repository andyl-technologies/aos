//! Strict advisory stop-caller rows from the exact child's owned stderr.
//!
//! Region fields describe the caller's cached observation, never an execution
//! receipt or authority to stop a VM.

use super::{unsigned, value};

/// Checks the exact diagnostic grammar and retained child PID without adding authority.
pub(super) fn valid_row(row: &str, child_process_id: u32) -> bool {
    if row.len() >= 512 || child_process_id == 0 {
        return false;
    }
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-CHECKPOINT-STOP-V1") {
        return false;
    }
    let phase = value(&mut fields, "phase=");
    if !matches!(
        phase,
        Some("claimed-before-pause" | "before-request" | "after-request")
    ) || value(&mut fields, "pid=")
        .filter(|pid| unsigned::<u32>(pid))
        .and_then(|pid| pid.parse::<u32>().ok())
        != Some(child_process_id)
    {
        return false;
    }

    let mut unavailable = 0;
    for key in ["device=", "inode=", "length=", "slot=", "generation="] {
        let Some(field) = value(&mut fields, key) else {
            return false;
        };
        if field == "unavailable" {
            unavailable += 1;
        } else if !(if key == "slot=" {
            unsigned::<u32>(field)
        } else {
            unsigned::<u64>(field)
        }) {
            return false;
        }
    }
    if !matches!(unavailable, 0 | 5) {
        return false;
    }
    let caller = value(&mut fields, "caller=");
    if !matches!(
        caller,
        Some(
            "selectable-sim-publication"
                | "campaign-marker-sim-publication"
                | "network-output"
                | "vcpu-idle-wait"
                | "vcpu-idle"
                | "vcpu-resume"
                | "sim-publication"
                | "progress-publication"
                | "block-wait"
                | "control-boundary"
                | "max-advance"
                | "block-poll"
                | "ninep-poll"
                | "ninep-burst-done"
                | "accelerator-poll"
        )
    ) || (phase == Some("claimed-before-pause")
        && !matches!(
            caller,
            Some("selectable-sim-publication" | "campaign-marker-sim-publication")
        ))
    {
        return false;
    }
    for key in ["raw_icount=", "logical_ps="] {
        if !value(&mut fields, key).is_some_and(unsigned::<u64>) {
            return false;
        }
    }
    if !value(&mut fields, "token=").is_some_and(unsigned::<u32>) {
        return false;
    }
    let status = value(&mut fields, "status=");
    let valid_status = if phase == Some("after-request") {
        status.is_some_and(|status| {
            let digits = status.strip_prefix('-').unwrap_or(status);
            unsigned::<u32>(digits) && status.parse::<i32>().is_ok()
        })
    } else {
        status == Some("unavailable")
    };
    valid_status && fields.next().is_none()
}
