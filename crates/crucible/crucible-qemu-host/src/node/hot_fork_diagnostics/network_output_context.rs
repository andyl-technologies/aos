//! Strict advisory rows identifying an original failed network-output stop.
//!
//! These diagnostics do not participate in canonical control receipts. The
//! child's PID must match the exact owned capture; an arm PID may name its
//! parent when the observation was copied by fork. Admission is a returned
//! native SDK status, not proof of paused native runstate.

pub(super) fn valid_row(row: &str, child_process_id: u32) -> bool {
    if row.len() > 512
        || !row
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return false;
    }
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1") {
        return false;
    }
    let Some(phase) = value(&mut fields, "phase=") else {
        return false;
    };
    if !matches!(
        phase,
        "vcpu-idle"
            | "vcpu-resume"
            | "control-boundary"
            | "sim-publication"
            | "progress-publication"
            | "device-current"
            | "network-tx-direct"
            | "network-tx-pending"
            | "idle-advance-completion"
    ) {
        return false;
    }
    if value(&mut fields, "pid=").and_then(unsigned::<u32>) != Some(child_process_id)
        || !value(&mut fields, "arm_pid=")
            .and_then(unsigned::<u32>)
            .is_some_and(|pid| pid != 0)
        || !matches!(
            value(&mut fields, "origin="),
            Some("direct-tx" | "idle-advance-completion")
        )
    {
        return false;
    }
    for key in [
        "original_ps=",
        "original_raw=",
        "observed_ps=",
        "observed_raw=",
        "write_frontier=",
    ] {
        if value(&mut fields, key).and_then(unsigned::<u64>).is_none() {
            return false;
        }
    }
    let Some(admission) = value(&mut fields, "admission=") else {
        return false;
    };
    if admission != "unavailable"
        && (!admission
            .strip_prefix('-')
            .unwrap_or(admission)
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            || admission.starts_with('+')
            || admission.parse::<i32>().is_err())
    {
        return false;
    }
    fields.next().is_none()
}

fn value<'a>(fields: &mut std::str::SplitAsciiWhitespace<'a>, key: &str) -> Option<&'a str> {
    fields.next()?.strip_prefix(key)
}

fn unsigned<T: std::str::FromStr>(value: &str) -> Option<T> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW: &str = "CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 phase=vcpu-resume pid=42 arm_pid=41 origin=direct-tx original_ps=664411328350 original_raw=5963742274 observed_ps=664411332050 observed_raw=5963742348 write_frontier=2 admission=0";

    #[test]
    fn exact_owned_failure_context_is_advisory_and_strict() {
        assert!(valid_row(ROW, 42));
        assert!(!valid_row(ROW, 41));
        for (old, new) in [
            ("phase=vcpu-resume", "phase=unknown"),
            ("origin=direct-tx", "origin=replacement"),
            (
                "original_raw=5963742274",
                "original_raw=18446744073709551616",
            ),
            ("arm_pid=41", "arm_pid=0"),
            ("arm_pid=41", "arm_pid=4294967296"),
            ("admission=0", "admission=2147483648"),
            ("admission=0", "admission=+0"),
            ("admission=0", "admission=-"),
        ] {
            assert!(!valid_row(&ROW.replace(old, new), 42), "{new}");
        }
        assert!(valid_row(&ROW.replace("admission=0", "admission=-114"), 42));
        assert!(valid_row(
            &ROW.replace("admission=0", "admission=unavailable"),
            42
        ));
        assert!(!valid_row(&format!("{ROW} extra=1"), 42));
        assert!(!valid_row(&format!("{ROW}{}", " ".repeat(512)), 42));
        assert!(!valid_row(&ROW.replace(" pid=", "\tpid="), 42));
    }

    #[test]
    fn mixed_capture_retains_failure_under_original_row_and_line_caps() {
        let mut bytes = Vec::new();
        for token in 0..36 {
            bytes.extend_from_slice(format!("CRUCIBLE-CONTROL-CALLBACK-V1 phase=exit reason=pending pid=42 raw_icount=7 token_kind=observed token_before={token} token_after={token}\n").as_bytes());
        }
        bytes.extend_from_slice(format!("{ROW}\n").as_bytes());
        bytes.extend_from_slice(format!("{}\n", ROW.replace("pid=42", "pid=43")).as_bytes());
        bytes.extend_from_slice(b"CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 incomplete");

        let summary = super::super::control_diagnostics_summary(&bytes, 42);

        assert!(summary.contains(
            "accepted_rows=37 rejected_rows=1 tail_rows=32 omitted_rows=5 incomplete_last_row=true"
        ));
        assert!(summary.ends_with(ROW));
    }
}
