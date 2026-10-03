//! Bounded advisory control rows from the exact child's private stderr capture.
//!
//! Native log-file traces remain a separate artifact. A matching callback PID
//! filters unrelated records but is not an execution or provenance receipt.

use std::collections::VecDeque;

#[path = "checkpoint_stop.rs"]
mod checkpoint_stop;

#[path = "control_stage.rs"]
mod control_stage;

#[path = "network_output_context.rs"]
mod network_output_context;

#[path = "native_stop_context.rs"]
mod native_stop_context;

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
        if !line.starts_with(b"CRUCIBLE-CHECKPOINT-STOP-V1 ")
            && !line.starts_with(b"CRUCIBLE-CONTROL-STAGE-V1 ")
            && !line.starts_with(b"CRUCIBLE-NATIVE-STOP-CONTEXT-V1 ")
            && !line.starts_with(b"CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 ")
            && !line.starts_with(b"CRUCIBLE-CONTROL-CALLBACK-V1 ")
            && !line.starts_with(b"CRUCIBLE-CONTROL-LAST-V1 ")
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
                && (checkpoint_stop::valid_row(row, child_process_id)
                    || control_stage::valid_row(row, child_process_id)
                    || native_stop_context::valid_row(row, child_process_id)
                    || network_output_context::valid_row(row, child_process_id)
                    || valid_callback_row(row, child_process_id)
                    || valid_last_callback_row(row, child_process_id)
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

fn valid_last_callback_row(row: &str, child_process_id: u32) -> bool {
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-CONTROL-LAST-V1") {
        return false;
    }
    let kind = value(&mut fields, "kind=");
    if !matches!(kind, Some("last-callback" | "last-admitted"))
        || value(&mut fields, "phase=") != Some("after-drain")
        || !matches!(
            value(&mut fields, "teardown="),
            Some("host-quit" | "shared-shutdown" | "run-control-fault")
        )
        || value(&mut fields, "pid=").and_then(|pid| pid.parse::<u32>().ok())
            != Some(child_process_id)
    {
        return false;
    }
    for key in ["device=", "inode=", "length="] {
        if !value(&mut fields, key).is_some_and(unsigned::<u64>) {
            return false;
        }
    }
    if !value(&mut fields, "slot=").is_some_and(unsigned::<u32>)
        || !value(&mut fields, "generation=").is_some_and(unsigned::<u64>)
        || !value(&mut fields, "final_token=").is_some_and(unsigned::<u32>)
    {
        return false;
    }
    if fields.clone().next() == Some("observation=unavailable") {
        fields.next();
        return fields.next().is_none();
    }
    if !value(&mut fields, "callback=").is_some_and(unsigned::<u64>) {
        return false;
    }
    let Some(raw) = value(&mut fields, "raw_icount=") else {
        return false;
    };
    let Some(phase) = value(&mut fields, "callback_phase=") else {
        return false;
    };
    let Some(reason) = value(&mut fields, "reason=") else {
        return false;
    };
    if kind == Some("last-admitted") && !matches!(phase, "admitted" | "exit") {
        return false;
    }
    let expected_mask = match (phase, reason) {
        ("rejected", "hot-fork-held") => "1",
        ("rejected", "teardown-closed") => "2",
        ("rejected", "teardown-and-hot-fork") => "3",
        ("rejected", "shared-shutdown") => "4",
        _ => "0",
    };
    if value(&mut fields, "rejection_mask=") != Some(expected_mask) {
        return false;
    }
    let remaining = fields.collect::<Vec<_>>().join(" ");
    // Reuse the existing exact callback grammar; region fields add no authority.
    valid_callback_row(
        &format!(
            "CRUCIBLE-CONTROL-CALLBACK-V1 phase={phase} reason={reason} pid={child_process_id} raw_icount={raw} {remaining}"
        ),
        child_process_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_callback_public_vector_is_retained_only_for_owned_pid_and_exact_schema() {
        // Matches the GPL-side real callback emitter's public diagnostic vector.
        let row = "CRUCIBLE-CONTROL-LAST-V1 kind=last-callback phase=after-drain teardown=host-quit pid=191 device=1 inode=2 length=4096 slot=0 generation=2 final_token=3 callback=1 raw_icount=7 callback_phase=exit reason=acknowledged rejection_mask=0 token_kind=observed token_before=2 token_after=3";
        let summary = control_diagnostics_summary(format!("{row}\n").as_bytes(), 191);
        assert!(summary.contains("accepted_rows=1 rejected_rows=0"));
        assert!(summary.contains(row));
        for invalid in [
            row.replace("pid=191", "pid=192"),
            row.replace("rejection_mask=0", "rejection_mask=2"),
            row.replace("token_kind=observed", "token_kind=cached"),
            row.replace("length=4096", "length=-1"),
            row.replace("phase=after-drain", "phase=before-drain"),
            format!("{row} unexpected=1"),
        ] {
            let summary = control_diagnostics_summary(format!("{invalid}\n").as_bytes(), 191);
            assert!(summary.contains("accepted_rows=0 rejected_rows=1"));
        }
    }

    #[test]
    fn final_rejection_and_unavailable_rows_preserve_existing_tail_limits() {
        let row = "CRUCIBLE-CONTROL-LAST-V1 kind=last-callback phase=after-drain teardown=host-quit pid=191 device=1 inode=2 length=4096 slot=0 generation=2 final_token=4510 callback=100 raw_icount=5859612126 callback_phase=rejected reason=hot-fork-held rejection_mask=1 token_kind=cached token_before=4509 token_after=unavailable";
        assert!(valid_last_callback_row(row, 191));
        assert!(!valid_last_callback_row(
            &row.replace("kind=last-callback", "kind=last-admitted"),
            191
        ));
        let unavailable = "CRUCIBLE-CONTROL-LAST-V1 kind=last-admitted phase=after-drain teardown=run-control-fault pid=191 device=1 inode=2 length=4096 slot=0 generation=2 final_token=4510 observation=unavailable\n";
        let summary = control_diagnostics_summary(unavailable.repeat(40).as_bytes(), 191);
        assert!(summary.contains("accepted_rows=40 rejected_rows=0 tail_rows=32 omitted_rows=8"));
    }

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

    #[test]
    fn late_native_stop_context_uses_existing_child_tail_bound() {
        let mut bytes = Vec::new();
        for generation in 0..40 {
            let row = format!(
                "CRUCIBLE-NATIVE-STOP-CONTEXT-V1 phase=stopped pid=153 gen={generation} request=7 ack=6 complete=6 state=2 runstate=4 flush=0 shutdown=0 advance=0 fd=7 scope=unavailable pc=unavailable coord=unavailable\n"
            );
            bytes.extend_from_slice(row.as_bytes());
        }
        for malformed in [
            "CRUCIBLE-NATIVE-STOP-CONTEXT-V1 phase=stopped pid=132 gen=40 request=7 ack=6 complete=6 state=2 runstate=4 flush=0 shutdown=0 advance=0 fd=7 scope=unavailable pc=unavailable coord=unavailable\n".to_owned(),
            format!("CRUCIBLE-NATIVE-STOP-CONTEXT-V1 {}\n", "x".repeat(512)),
        ] {
            bytes.extend_from_slice(malformed.as_bytes());
        }
        bytes.extend_from_slice(b"CRUCIBLE-NATIVE-STOP-CONTEXT-V1 incomplete");

        let summary = control_diagnostics_summary(&bytes, 153);
        assert!(summary.contains(
            "accepted_rows=40 rejected_rows=2 tail_rows=32 omitted_rows=8 incomplete_last_row=true"
        ));
        assert_eq!(summary.lines().count(), 33);
        assert!(
            summary
                .lines()
                .nth(1)
                .is_some_and(|row| row.contains("gen=8 "))
        );
        assert!(
            summary
                .lines()
                .last()
                .is_some_and(|row| row.contains("gen=39 "))
        );
        assert!(!summary.contains("pid=132"));
        assert!(summary.len() <= 32 * MAXIMUM_ROW_BYTES + 256);
    }
}

#[cfg(test)]
#[path = "stop_notice_tests.rs"]
mod stop_notice_tests;
