//! Admitted diagnostic configuration and retained materialization attestations.

use super::*;

pub(super) fn report_recent_host_wait_observations(service: &CampaignServiceChild) {
    // Retain before-cancellation polling evidence even if callback records push
    // it outside the ordinary stderr tail: <=64 rows of <=2048 bytes each.
    match service.stderr_recent_lines_with_prefix("CRUCIBLE-HOST-WAIT-V1 ", 64, 2048) {
        Ok(records) => {
            for record in records {
                let _write_result = writeln!(std::io::stderr().lock(), "{record}");
            }
        }
        Err(error) => {
            let _write_result = writeln!(
                std::io::stderr().lock(),
                "host wait observation unavailable: {error}"
            );
        }
    }
}

pub(super) fn configure_flight_diagnostics(
    invocation: &mut Command,
    diagnostics: FlightDiagnostics,
) {
    if matches!(diagnostics, FlightDiagnostics::Disabled) {
        return;
    }

    // The daemon rejects values outside 1..=256 by disabling tier notices.
    // Runtime progress shares this opt-in and also admits the same bound.
    invocation.env("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS", "256");
    if matches!(diagnostics, FlightDiagnostics::ControlCallback) {
        invocation.env("CRUCIBLE_CONTROL_CALLBACK_WITNESS", "1");
        invocation.env("CRUCIBLE_RR_CLAMP_TAIL", "1");
    }
}

#[test]
fn diagnostic_flights_request_admitted_materialization_events() {
    for diagnostics in [
        FlightDiagnostics::Materialization,
        FlightDiagnostics::ControlCallback,
    ] {
        let witness = matches!(diagnostics, FlightDiagnostics::ControlCallback);
        let mut invocation = Command::new("unused-fixture-program");
        configure_flight_diagnostics(&mut invocation, diagnostics);
        let environment = invocation.get_envs().collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment.get(std::ffi::OsStr::new(
                "CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS"
            )),
            Some(&Some(std::ffi::OsStr::new("256")))
        );
        assert_eq!(
            environment.contains_key(std::ffi::OsStr::new("CRUCIBLE_CONTROL_CALLBACK_WITNESS")),
            witness
        );
        assert_eq!(
            environment.contains_key(std::ffi::OsStr::new("CRUCIBLE_RR_CLAMP_TAIL")),
            witness
        );
        assert_eq!(environment.len(), if witness { 3 } else { 1 });
    }

    let mut disabled = Command::new("unused-fixture-program");
    configure_flight_diagnostics(&mut disabled, FlightDiagnostics::Disabled);
    assert_eq!(disabled.get_envs().count(), 0);
}

#[test]
fn materialization_capture_preserves_one_shot_record_outside_the_recent_tail()
-> Result<(), Box<dyn Error>> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    assert!(wait_for_exit(&mut child, Duration::from_secs(5))?.success());
    let mut service = CampaignServiceChild {
        child,
        #[cfg(feature = "packaged-midpoint-flight")]
        daemon_url: String::new(),
        stderr: NamedTempFile::new()?,
        kill_on_drop: false,
    };
    let attempt = "synthetic-capture-regression-attempt";
    let attestation = format!("{MATERIALIZATION_DIAGNOSTIC_PREFIX}attempt={attempt} tier=HotFork");
    writeln!(service.stderr, "{attestation}")?;
    for record in 0..70 {
        writeln!(
            service.stderr,
            "CRUCIBLE-HOST-WAIT-V1 phase=advance-pending slot=0 record={record}"
        )?;
    }
    for token in 0..1024 {
        writeln!(
            service.stderr,
            "CRUCIBLE-CONTROL-CALLBACK-V1 phase=exit reason=acknowledged pid=1 raw_icount={token} token_kind=observed token_before={token} token_after={}",
            token + 1
        )?;
    }
    service.stderr.flush()?;
    assert!(service.stderr.as_file().metadata()?.len() > MAX_CAMPAIGN_SERVICE_STDERR_BYTES);
    assert!(
        !service
            .stderr_tail()
            .contains(MATERIALIZATION_DIAGNOSTIC_PREFIX)
    );

    let events = capture_materialization_events(&service)?;
    assert_eq!(events, [attestation]);
    assert_materialization_tier(&events, attempt, "HotFork")?;
    assert!(assert_materialization_tier(&events, attempt, "ThinReplay").is_err());
    assert!(assert_materialization_tier(&events, "different-attempt", "HotFork").is_err());
    let waits = service.stderr_recent_lines_with_prefix("CRUCIBLE-HOST-WAIT-V1 ", 64, 2048)?;
    assert_eq!(waits.len(), 64);
    assert!(
        waits
            .first()
            .is_some_and(|record| record.ends_with("record=6"))
    );
    assert!(
        waits
            .last()
            .is_some_and(|record| record.ends_with("record=69"))
    );
    assert!(!service.stderr_tail().contains("CRUCIBLE-HOST-WAIT-V1 "));
    Ok(())
}
