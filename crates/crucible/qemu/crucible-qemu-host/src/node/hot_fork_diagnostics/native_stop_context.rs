//! Strict advisory native stop records from the already-owned stderr capture.
//!
//! A matching PID binds only the diagnostic row to its retained child stream.
//! CPU scope and unavailable fields describe observation custody; no field
//! authenticates a runtime outcome or admits a control operation.

use super::value;

/// Validates a bounded advisory row for the exact retained child process.
pub(super) fn valid_row(row: &str, child_process_id: u32) -> bool {
    if row.len() >= 512 || child_process_id == 0 {
        return false;
    }
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-NATIVE-STOP-CONTEXT-V1")
        || !matches!(
            value(&mut fields, "phase="),
            Some(
                "async-admitted"
                    | "control-admitted"
                    | "stopped"
                    | "rearm-no-cpu"
                    | "rearm-shutdown"
                    | "rearm-advance"
                    | "rearm-no-owner"
                    | "reader-drained"
                    | "reader-eof"
                    | "reader-error"
            )
        )
        || value(&mut fields, "pid=")
            .filter(|value| super::unsigned::<u32>(value))
            .and_then(|value| value.parse::<u32>().ok())
            != Some(child_process_id)
    {
        return false;
    }

    for key in ["gen=", "request=", "ack=", "complete="] {
        if !value(&mut fields, key).is_some_and(super::unsigned::<u64>) {
            return false;
        }
    }
    if !value(&mut fields, "state=").is_some_and(|value| bounded_unsigned(value, 3))
        || !value(&mut fields, "runstate=")
            .is_some_and(|value| value == "unavailable" || bounded_unsigned(value, 15))
        || !value(&mut fields, "flush=").is_some_and(signed::<i32>)
        || !matches!(
            value(&mut fields, "shutdown="),
            Some("0" | "1" | "unavailable")
        )
        || !value(&mut fields, "advance=").is_some_and(boolean)
        || !value(&mut fields, "fd=").is_some_and(signed::<i32>)
    {
        return false;
    }

    match value(&mut fields, "scope=") {
        Some("unavailable") => {
            if value(&mut fields, "pc=") != Some("unavailable") {
                return false;
            }
        }
        Some("callback" | "stopped") => {
            if !value(&mut fields, "cpu=").is_some_and(super::unsigned::<i32>) {
                return false;
            }
            for key in ["running=", "stop=", "stopped="] {
                if !value(&mut fields, key).is_some_and(boolean) {
                    return false;
                }
            }
            if !value(&mut fields, "halted=").is_some_and(super::unsigned::<u32>)
                || !value(&mut fields, "high=").is_some_and(signed::<i16>)
                || !value(&mut fields, "low=").is_some_and(super::unsigned::<u16>)
                || !value(&mut fields, "next=").is_some_and(|value| hexadecimal(value, 8))
                || !value(&mut fields, "budget=").is_some_and(signed::<i64>)
                || !value(&mut fields, "pc=").is_some_and(|value| hexadecimal(value, 16))
            {
                return false;
            }
        }
        _ => return false,
    }

    value(&mut fields, "coord=") == Some("unavailable") && fields.next().is_none()
}

fn bounded_unsigned(value: &str, maximum: u32) -> bool {
    super::unsigned::<u32>(value) && value.parse::<u32>().is_ok_and(|parsed| parsed <= maximum)
}

fn boolean(value: &str) -> bool {
    matches!(value, "0" | "1")
}

fn signed<T: std::str::FromStr>(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<T>().is_ok()
}

fn hexadecimal(value: &str, maximum_digits: usize) -> bool {
    value.strip_prefix("0x").is_some_and(|digits| {
        !digits.is_empty()
            && digits.len() <= maximum_digits
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

#[cfg(test)]
mod tests {
    use super::valid_row;

    const UNAVAILABLE: &str = "CRUCIBLE-NATIVE-STOP-CONTEXT-V1 phase=rearm-shutdown pid=244 gen=3 request=12830 ack=12829 complete=12829 state=2 runstate=unavailable flush=0 shutdown=unavailable advance=0 fd=7 scope=unavailable pc=unavailable coord=unavailable";
    const OWNED: &str = "CRUCIBLE-NATIVE-STOP-CONTEXT-V1 phase=async-admitted pid=244 gen=3 request=12830 ack=12829 complete=12829 state=1 runstate=9 flush=0 shutdown=0 advance=0 fd=7 scope=callback cpu=0 running=1 stop=1 stopped=0 halted=0 high=-1 low=74 next=0xffffffff budget=91 pc=0x1234 coord=unavailable";

    #[test]
    fn admitted_and_unavailable_native_rows_keep_original_scope_and_pid() {
        assert!(valid_row(UNAVAILABLE, 244));
        assert!(valid_row(OWNED, 244));
        assert!(valid_row(
            &OWNED.replace("scope=callback", "scope=stopped"),
            244
        ));
        assert!(!valid_row(OWNED, 245));
    }

    #[test]
    fn malformed_context_is_rejected_before_retention() {
        for (original, replacement) in [
            ("phase=async-admitted", "phase=unknown"),
            ("pid=244", "pid=+244"),
            ("gen=3", "gen=18446744073709551616"),
            ("request=12830", "request=-1"),
            ("state=1", "state=4"),
            ("runstate=9", "runstate=16"),
            ("shutdown=0", "shutdown=2"),
            ("advance=0", "advance=-1"),
            ("fd=7", "fd=2147483648"),
            ("cpu=0", "cpu=-1"),
            ("running=1", "running=2"),
            ("high=-1", "high=-32769"),
            ("low=74", "low=65536"),
            ("next=0xffffffff", "next=0x100000000"),
            ("budget=91", "budget=9223372036854775808"),
            ("pc=0x1234", "pc=0xABC"),
            ("coord=unavailable", "coord=0"),
        ] {
            assert!(!valid_row(&OWNED.replace(original, replacement), 244));
        }
        assert!(!valid_row(&format!("{OWNED} extra=1"), 244));
        assert!(!valid_row(
            &UNAVAILABLE.replace("pc=unavailable", "pc=0x0"),
            244
        ));
        assert!(!valid_row(&OWNED.repeat(2), 244));
    }
}
