//! Fixture-only admission of bounded advisory native cancellation summaries.
//!
//! The fields are independently sampled and never authorize a guest outcome.
//! `scope=before-cancel` describes the original cleanup seam, not deadline state.

const PHASES: [&str; 12] = [
    "request",
    "coalesce",
    "claim",
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

/// Checks only the original bounded text schema, without constructing a receipt.
pub(super) fn valid_row(row: &str) -> bool {
    if row.len() > 511
        || row.trim() != row
        || row.contains("  ")
        || !row
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return false;
    }
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-NATIVE-CONTROL-SUMMARY-V1")
        || fields.next() != Some("scope=before-cancel")
    {
        return false;
    }
    let Some(kind) = value(&mut fields, "kind=") else {
        return false;
    };
    if !matches!(kind, "current" | "latest") {
        return false;
    }
    let Some(phase) = value(&mut fields, "phase=") else {
        return false;
    };
    if !PHASES.contains(&phase) || (kind == "current" && phase != "cancel") {
        return false;
    }
    if !value(&mut fields, "pid=")
        .is_some_and(|pid| canonical_decimal(pid) && pid.parse::<i32>().is_ok_and(|pid| pid > 0))
    {
        return false;
    }
    for key in ["sample=", "request=", "ack=", "complete="] {
        if !value(&mut fields, key)
            .is_some_and(|value| canonical_decimal(value) && value.parse::<u64>().is_ok())
        {
            return false;
        }
    }
    for key in ["rr_token=0x", "token=0x"] {
        if !value(&mut fields, key).is_some_and(|value| {
            !value.is_empty()
                && (value.len() == 1 || !value.starts_with('0'))
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && u64::from_str_radix(value, 16).is_ok()
        }) {
            return false;
        }
    }
    if !matches!(value(&mut fields, "deferred="), Some("0" | "1")) {
        return false;
    }
    for key in ["state=", "runstate="] {
        if !value(&mut fields, key)
            .is_some_and(|value| canonical_decimal(value) && value.parse::<u32>().is_ok())
        {
            return false;
        }
    }
    value(&mut fields, "owner=")
        .is_some_and(|value| canonical_decimal(value) && value.parse::<u64>().is_ok())
        && fields.next().is_none()
}

fn value<'a>(fields: &mut std::str::SplitAsciiWhitespace<'a>, key: &str) -> Option<&'a str> {
    fields.next()?.strip_prefix(key)
}

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && (value.len() == 1 || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[test]
fn native_summary_admits_original_scope_and_refuses_false_or_malformed_context() {
    let row = "CRUCIBLE-NATIVE-CONTROL-SUMMARY-V1 scope=before-cancel kind=latest phase=claim pid=9900 sample=14 request=3 ack=2 complete=2 rr_token=0x3 token=0x4 deferred=0 state=2 runstate=4 owner=0";
    for phase in PHASES {
        assert!(valid_row(
            &row.replace("phase=claim", &format!("phase={phase}"))
        ));
    }
    assert!(valid_row(&row.replace(
        "kind=latest phase=claim",
        "kind=current phase=cancel"
    )));
    for (old, new) in [
        ("scope=before-cancel", "scope=active"),
        ("kind=latest", "kind=receipt"),
        ("phase=claim", "phase=unknown"),
        ("pid=9900", "pid=0"),
        ("pid=9900", "pid=-1"),
        ("pid=9900", "pid=2147483648"),
        ("sample=14", "sample=014"),
        ("request=3", "request=18446744073709551616"),
        ("ack=2 complete=2", "complete=2 ack=2"),
        ("rr_token=0x3", "rr_token=0x03"),
        ("token=0x4", "token=0xA"),
        ("deferred=0", "deferred=2"),
        ("state=2", "state=4294967296"),
        ("owner=0", "owner=-1"),
    ] {
        assert!(!valid_row(&row.replace(old, new)), "{new}");
    }
    assert!(!valid_row(&row.replace("kind=latest", "kind=current")));
    assert!(!valid_row(&format!("{row} extra=1")));
    assert!(!valid_row(&format!("{row}\n")));
    assert!(!valid_row(&row.replace(' ', "\t")));
    assert!(!valid_row(&format!("{}{}", row, "x".repeat(512))));
    for index in 0..row.split_ascii_whitespace().count() {
        let missing = row
            .split_ascii_whitespace()
            .enumerate()
            .filter_map(|(position, value)| (position != index).then_some(value))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!valid_row(&missing));
    }
}

#[test]
fn native_summary_service_boundary_uses_canonical_opt_in_and_clears_streams()
-> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    const ROLE: &str = "CRUCIBLE_TEST_NATIVE_SUMMARY_SERVICE_ROLE";
    const EXPECTED: &str = "CRUCIBLE_TEST_NATIVE_SUMMARY_SERVICE_EXPECTED";
    const SETTING: &str = "CRUCIBLE_NATIVE_CONTROL_DELIVERY_SUMMARY";
    const STREAMS: [&str; 5] = [
        "CRUCIBLE_CONTROL_CALLBACK_WITNESS",
        "CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN",
        "CRUCIBLE_RR_CLAMP_TAIL",
        "CRUCIBLE_PHASE7_IDLE_TRACE",
        "CRUCIBLE_TIME_OWNERSHIP_WITNESS",
    ];
    if std::env::var(ROLE).as_deref() == Ok("observer") {
        let expected = std::env::var(EXPECTED)?;
        assert_eq!(
            std::env::var_os(SETTING),
            (expected == "1").then(|| std::ffi::OsString::from("1"))
        );
        for stream in STREAMS {
            assert!(std::env::var_os(stream).is_none(), "{stream}");
        }
        assert_eq!(
            std::env::var("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS")?,
            "256"
        );
        return Ok(());
    }

    let test = format!(
        "{}::native_summary_service_boundary_uses_canonical_opt_in_and_clears_streams",
        module_path!()
            .split_once("::")
            .ok_or("missing libtest module owner")?
            .1
    );
    if std::env::var(ROLE).as_deref() == Ok("builder") {
        let mut child = Command::new(std::env::current_exe()?);
        child.args(["--exact", &test]).env(ROLE, "observer");
        child.env(SETTING, "seeded-invalid");
        for stream in STREAMS {
            child.env(stream, "1");
        }
        super::configure_flight_diagnostics(
            &mut child,
            super::FlightDiagnostics::Materialization {
                pending_min_token: None,
            },
        );
        assert!(child.spawn()?.wait()?.success());
        return Ok(());
    }

    for (setting, expected) in [(None, "absent"), (Some("1"), "1"), (Some("01"), "absent")] {
        let mut builder = Command::new(std::env::current_exe()?);
        builder
            .args(["--exact", &test])
            .env(ROLE, "builder")
            .env(EXPECTED, expected);
        builder.env_remove(SETTING);
        if let Some(setting) = setting {
            builder.env(SETTING, setting);
        }
        assert!(builder.spawn()?.wait()?.success(), "setting={setting:?}");
    }
    Ok(())
}
