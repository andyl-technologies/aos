//! Strict advisory admitted-control stage rows, independent of control outcomes.

use super::{unsigned, value};

/// Checks the exact diagnostic grammar and retained child PID without adding authority.
pub(super) fn valid_row(row: &str, child_process_id: u32) -> bool {
    if row.len() >= 256 || child_process_id == 0 {
        return false;
    }
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-CONTROL-STAGE-V1") {
        return false;
    }
    let phase = value(&mut fields, "phase=");
    if !matches!(
        phase,
        Some("settle-enter" | "settle-return" | "pause-enter" | "pause-return")
    ) || value(&mut fields, "pid=")
        .filter(|pid| unsigned::<u32>(pid))
        .and_then(|pid| pid.parse::<u32>().ok())
        != Some(child_process_id)
        || !value(&mut fields, "callback=").is_some_and(unsigned::<u64>)
        || !value(&mut fields, "token=").is_some_and(unsigned::<u32>)
        || !value(&mut fields, "raw=").is_some_and(unsigned::<u64>)
    {
        return false;
    }

    let mut unavailable = 0;
    for key in ["dev=", "ino=", "slot=", "gen="] {
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
    if !matches!(unavailable, 0 | 4) {
        return false;
    }
    let result = value(&mut fields, "result=");
    let valid_result = match phase {
        Some("settle-enter" | "pause-enter") => result == Some("unavailable"),
        _ => matches!(result, Some("true" | "false" | "error")),
    };
    valid_result && fields.next().is_none()
}
