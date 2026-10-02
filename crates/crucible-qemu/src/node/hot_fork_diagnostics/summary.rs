//! Bounded advisory control rows from the exact child's private stderr capture.
//!
//! Native log-file traces remain a separate artifact. A matching callback PID
//! filters unrelated records but is not an execution or provenance receipt.

use std::collections::VecDeque;

const MAXIMUM_ROWS: usize = 32;
const MAXIMUM_ROW_BYTES: usize = 512;

pub(super) fn control_diagnostics_summary(bytes: &[u8], child_process_id: u32) -> String {
    let mut rows = VecDeque::with_capacity(MAXIMUM_ROWS);
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let incomplete = !bytes.is_empty() && !bytes.ends_with(b"\n");

    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let Some(line) = line.strip_suffix(b"\n") else {
            continue;
        };
        if !line.starts_with(b"CRUCIBLE-CONTROL-CALLBACK-V1 ")
            && !line.starts_with(b"CRUCIBLE-RR-CONTROL-DEFER-V1 ")
            && !line.starts_with(b"crucible_sim_rr_control_")
        {
            continue;
        }
        let row = std::str::from_utf8(line).ok().filter(|row| {
            row.len() <= MAXIMUM_ROW_BYTES
                && row
                    .bytes()
                    .all(|byte| byte == b' ' || byte.is_ascii_graphic())
                && (valid_callback_row(row, child_process_id)
                    || valid_defer_row(row)
                    || crate::spawn::valid_rr_control_boundary_row(row)
                    || (crate::spawn::valid_control_delivery_row(row)
                        && row
                            .split_ascii_whitespace()
                            .next_back()
                            .and_then(|field| field.strip_prefix("pid="))
                            .and_then(|pid| pid.parse::<i64>().ok())
                            == Some(i64::from(child_process_id))))
        });
        let Some(row) = row else {
            rejected += 1;
            continue;
        };
        accepted += 1;
        if rows.len() == MAXIMUM_ROWS {
            rows.pop_front();
        }
        rows.push_back(row.to_owned());
    }

    format!(
        "retained_bytes={} accepted_rows={accepted} rejected_rows={rejected} tail_rows={} omitted_rows={} incomplete_last_row={incomplete}\n{}",
        bytes.len(),
        rows.len(),
        accepted - rows.len(),
        rows.into_iter().collect::<Vec<_>>().join("\n")
    )
}

fn value<'a>(fields: &mut std::str::SplitAsciiWhitespace<'a>, key: &str) -> Option<&'a str> {
    fields.next()?.strip_prefix(key)
}

fn unsigned<T: std::str::FromStr>(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<T>().is_ok()
}

fn valid_callback_row(row: &str, child_process_id: u32) -> bool {
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-CONTROL-CALLBACK-V1") {
        return false;
    }
    let phase = value(&mut fields, "phase=");
    let reason = value(&mut fields, "reason=");
    if !matches!(
        (phase, reason),
        (Some("entry"), Some("native-delivery"))
            | (Some("admitted"), Some("guard-open"))
            | (
                Some("rejected"),
                Some(
                    "hot-fork-held"
                        | "teardown-closed"
                        | "teardown-and-hot-fork"
                        | "shared-shutdown"
                )
            )
            | (
                Some("exit"),
                Some("pending" | "acknowledged" | "no-request" | "error")
            )
    ) || value(&mut fields, "pid=").and_then(|value| value.parse::<u32>().ok())
        != Some(child_process_id)
        || !value(&mut fields, "raw_icount=").is_some_and(unsigned::<u64>)
    {
        return false;
    }
    let expected_kind = if matches!(phase, Some("entry" | "rejected")) {
        "cached"
    } else {
        "observed"
    };
    if value(&mut fields, "token_kind=") != Some(expected_kind) {
        return false;
    }
    for key in ["token_before=", "token_after="] {
        if !value(&mut fields, key)
            .is_some_and(|value| value == "unavailable" || unsigned::<u32>(value))
        {
            return false;
        }
    }
    fields.next().is_none()
}

fn valid_defer_row(row: &str) -> bool {
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-RR-CONTROL-DEFER-V1") {
        return false;
    }
    if !value(&mut fields, "reason=").is_some_and(|reason| {
        matches!(
            reason,
            "pump-through-frontier-pending"
                | "publication-backpressure"
                | "command-frontier-unsettled"
        )
    }) {
        return false;
    }
    for (key, wide) in [
        ("raw_icount=", true),
        ("token_before=", false),
        ("token_after=", false),
        ("fault_command_frontier=", true),
    ] {
        if !value(&mut fields, key).is_some_and(|value| {
            if wide {
                unsigned::<u64>(value)
            } else {
                unsigned::<u32>(value)
            }
        }) {
            return false;
        }
    }
    fields.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn callback(token: u32) -> String {
        format!(
            "CRUCIBLE-CONTROL-CALLBACK-V1 phase=exit reason=pending pid=153 raw_icount=5859612126 token_kind=observed token_before={token} token_after={token}\n"
        )
    }

    #[test]
    fn latest_rows_survive_unrelated_and_malformed_stderr() {
        let mut bytes = b"unrelated private payload\n".to_vec();
        for token in 1..=45 {
            bytes.extend_from_slice(callback(token).as_bytes());
        }
        for malformed in [
            callback(46).replace("pid=153", "pid=132"),
            callback(46).replace("reason=pending", "reason=unknown"),
            callback(46).replace("raw_icount=5859612126", "raw_icount=-1"),
            callback(46).replace("token_kind=observed", "token_kind=cached"),
            callback(46).replace("token_after=46", "token_after=4294967296"),
            callback(46).replace("\n", " extra=untrusted\n"),
            callback(46).replace("\n", "\x1b\n"),
            format!("CRUCIBLE-CONTROL-CALLBACK-V1 {}\n", "x".repeat(512)),
        ] {
            bytes.extend_from_slice(malformed.as_bytes());
        }
        bytes.extend_from_slice(b"CRUCIBLE-CONTROL-CALLBACK-V1 incomplete");

        let summary = control_diagnostics_summary(&bytes, 153);
        assert!(summary.contains(
            "accepted_rows=45 rejected_rows=8 tail_rows=32 omitted_rows=13 incomplete_last_row=true"
        ));
        assert_eq!(summary.lines().count(), 33);
        assert_eq!(summary.lines().nth(1), Some(callback(14).trim_end()));
        assert!(summary.ends_with(callback(45).trim_end()));
        assert!(!summary.contains("unrelated private payload"));
        assert!(!summary.contains("untrusted"));
        assert!(summary.len() <= 32 * MAXIMUM_ROW_BYTES + 256);
    }

    #[test]
    fn shares_native_advisory_schemas_and_accepts_actual_defer_reasons() {
        let boundary = "crucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x2 state=5";
        let native = "crucible_sim_rr_control_delivery phase=registered-return request=2 ack=2 complete=2 rr_token=0x0 token=0x0 deferred=0 state=5 runstate=4 owner=0 pid=153";
        for reason in [
            "pump-through-frontier-pending",
            "publication-backpressure",
            "command-frontier-unsettled",
        ] {
            let deferred = format!(
                "CRUCIBLE-RR-CONTROL-DEFER-V1 reason={reason} raw_icount=18446744073709551615 token_before=4498 token_after=4498 fault_command_frontier=18446744073709551615"
            );
            let summary = control_diagnostics_summary(
                format!("{boundary}\n{native}\n{deferred}\n").as_bytes(),
                153,
            );
            assert!(summary.contains("accepted_rows=3 rejected_rows=0"));
            assert!(summary.ends_with(&deferred));
        }
        let invalid = control_diagnostics_summary(format!("{native} extra=1\n").as_bytes(), 153);
        assert!(invalid.contains("accepted_rows=0 rejected_rows=1"));
        for pid in ["132", "-1"] {
            let foreign = native.replace("pid=153", &format!("pid={pid}"));
            let summary = control_diagnostics_summary(format!("{foreign}\n").as_bytes(), 153);
            assert!(summary.contains("accepted_rows=0 rejected_rows=1"));
            assert_eq!(summary.lines().count(), 1);
        }
    }
}
