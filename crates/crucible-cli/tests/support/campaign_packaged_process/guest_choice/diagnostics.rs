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

pub(super) fn report_recent_callback_context(service: &CampaignServiceChild) {
    // Each exact prefix retains <=32 rows of <=512 bytes. Context and final
    // callback summaries survive unrelated rows outside the ordinary tail.
    for prefix in [
        "CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 ",
        "CRUCIBLE-CONTROL-LAST-V1 ",
    ] {
        match service.stderr_recent_lines_with_prefix(prefix, 32, 512) {
            Ok(records) => {
                for record in records {
                    let _write_result = writeln!(std::io::stderr().lock(), "{record}");
                }
            }
            Err(error) => {
                let _write_result = writeln!(
                    std::io::stderr().lock(),
                    "callback context unavailable for {prefix}: {error}"
                );
            }
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
    let output_context = "CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 phase=vcpu-resume pid=42 arm_pid=42 origin=direct-tx original_ps=100 original_raw=2 observed_ps=150 observed_raw=3 write_frontier=1 admission=0";
    let callback_context = "CRUCIBLE-CONTROL-LAST-V1 kind=last-admitted phase=after-drain teardown=host-quit pid=42 device=1 inode=2 length=4096 slot=0 generation=2 final_token=3 callback=1 raw_icount=7 callback_phase=exit reason=acknowledged rejection_mask=0 token_kind=observed token_before=2 token_after=3";
    writeln!(service.stderr, "{output_context}")?;
    writeln!(service.stderr, "{callback_context}")?;

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
    assert_eq!(
        service.stderr_recent_lines_with_prefix("CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 ", 32, 512)?,
        [output_context]
    );
    assert_eq!(
        service.stderr_recent_lines_with_prefix("CRUCIBLE-CONTROL-LAST-V1 ", 32, 512)?,
        [callback_context]
    );
    assert!(
        !service
            .stderr_tail()
            .contains("CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 ")
    );
    assert!(!service.stderr_tail().contains("CRUCIBLE-CONTROL-LAST-V1 "));

    Ok(())
}
