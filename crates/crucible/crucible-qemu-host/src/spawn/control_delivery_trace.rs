//! Strict admission of advisory native control-delivery trace rows.
//!
//! These records share the bounded diagnostic tail with boundary rows. They
//! never enter the canonical boundary receipt parser or control decisions.
//!
//! ```text
//! crucible_sim_rr_control_delivery phase=request request=1 ack=0 complete=0 rr_token=0x0 token=0x0 deferred=0 state=2 runstate=4 owner=1 pid=42
//! ```

const PHASES: [&str; 10] = [
    "request",
    "defer",
    "rearm",
    "complete-bh",
    "callback-enter",
    "registered-enter",
    "registered-return",
    "cancel",
    "advance-settled",
    "wake-stopped",
];

/// Checks the exact native advisory schema without constructing a receipt.
pub(crate) fn valid_control_delivery_row(row: &str) -> bool {
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("crucible_sim_rr_control_delivery") {
        return false;
    }
    let Some(phase) = value(&mut fields, "phase=") else {
        return false;
    };
    if !PHASES.contains(&phase) {
        return false;
    }
    for key in ["request=", "ack=", "complete="] {
        if !value(&mut fields, key).is_some_and(unsigned::<u64>) {
            return false;
        }
    }
    for key in ["rr_token=0x", "token=0x"] {
        if !value(&mut fields, key).is_some_and(|token| {
            !token.is_empty()
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && u64::from_str_radix(token, 16).is_ok()
        }) {
            return false;
        }
    }
    if !matches!(value(&mut fields, "deferred="), Some("0" | "1")) {
        return false;
    }
    for key in ["state=", "runstate="] {
        if !value(&mut fields, key).is_some_and(unsigned::<u32>) {
            return false;
        }
    }
    if !value(&mut fields, "owner=").is_some_and(unsigned::<u64>) {
        return false;
    }
    let Some(pid) = value(&mut fields, "pid=") else {
        return false;
    };
    let digits = pid.strip_prefix('-').unwrap_or(pid);
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && pid.parse::<i64>().is_ok()
        && fields.next().is_none()
}

fn value<'a>(fields: &mut std::str::SplitAsciiWhitespace<'a>, key: &str) -> Option<&'a str> {
    fields.next()?.strip_prefix(key)
}

fn unsigned<T: std::str::FromStr>(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<T>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW: &str = "crucible_sim_rr_control_delivery phase=request request=18446744073709551615 ack=0 complete=0 rr_token=0xffffffffffffffff token=0x0 deferred=1 state=4294967295 runstate=0 owner=0 pid=-9223372036854775808";

    #[test]
    fn admits_all_declared_phases_and_native_integer_limits() {
        for phase in PHASES {
            assert!(valid_control_delivery_row(
                &ROW.replace("phase=request", &format!("phase={phase}"))
            ));
        }
        assert!(valid_control_delivery_row(
            &ROW.replace("pid=-9223372036854775808", "pid=9223372036854775807")
        ));
    }

    #[test]
    fn rejects_unknown_reordered_extra_and_malformed_fields() {
        for (original, replacement) in [
            ("control_delivery", "control_boundary"),
            ("phase=request", "phase=unknown"),
            (
                "request=18446744073709551615",
                "request=18446744073709551616",
            ),
            ("ack=0 complete=0", "complete=0 ack=0"),
            ("ack=0", "ack=+0"),
            (
                "rr_token=0xffffffffffffffff",
                "rr_token=0x10000000000000000",
            ),
            ("token=0x0", "token=0xA"),
            ("deferred=1", "deferred=2"),
            ("state=4294967295", "state=4294967296"),
            ("runstate=0", "runstate=-1"),
            ("owner=0", "owner="),
            ("pid=-9223372036854775808", "pid=-9223372036854775809"),
            ("pid=-9223372036854775808", "pid=+1"),
        ] {
            assert!(
                !valid_control_delivery_row(&ROW.replace(original, replacement)),
                "{replacement}"
            );
        }
        assert!(!valid_control_delivery_row(&format!("{ROW} reason=retry")));
        for (index, _) in ROW.split_ascii_whitespace().enumerate() {
            let missing = ROW
                .split_ascii_whitespace()
                .enumerate()
                .filter_map(|(position, field)| (position != index).then_some(field))
                .collect::<Vec<_>>()
                .join(" ");
            assert!(!valid_control_delivery_row(&missing));
        }
    }
}
