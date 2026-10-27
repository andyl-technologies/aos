//! Admitted diagnostic configuration and retained materialization attestations.

use super::*;

#[path = "diagnostics/native_control_summary.rs"]
mod native_control_summary;

// Static fixture stages describe completed operations only. The original
// authenticated guest/checkpoint assertions remain the qualification oracle.
pub(super) fn report_maintenance_stage(stage: &'static str) {
    let _write_result = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-PACKAGED-STAGE-V1 diagnostic_only=true stage={stage}"
    );
}

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

/// Retains the original capped idle-plan rows before owner cancellation.
pub(super) fn report_recent_idle_plan_observations(service: &CampaignServiceChild) {
    match recent_idle_plan_rows(service) {
        Ok(records) => {
            for record in records {
                let _write_result = writeln!(std::io::stderr().lock(), "{record}");
            }
        }
        Err(error) => {
            let _write_result = writeln!(
                std::io::stderr().lock(),
                "idle plan observation unavailable: {error}"
            );
        }
    }
}

fn recent_idle_plan_rows(service: &CampaignServiceChild) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(service
        .stderr_recent_lines_with_prefix("CRUCIBLE-IDLE-PLAN-V1 ", 64, 511)?
        .into_iter()
        .filter(|row| {
            row.bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic())
        })
        .collect())
}

pub(super) fn report_recent_callback_context(service: &CampaignServiceChild) {
    match recent_native_control_summary_rows(service) {
        Ok(records) => {
            for record in records {
                let _write_result = writeln!(std::io::stderr().lock(), "{record}");
            }
        }
        Err(error) => {
            let _write_result = writeln!(
                std::io::stderr().lock(),
                "native control summary unavailable: {error}"
            );
        }
    }
    // Each exact prefix retains <=32 rows of <=512 bytes. Context and final
    // callback summaries survive unrelated rows outside the ordinary tail.
    for (prefix, maximum_bytes) in [
        ("CRUCIBLE-NATIVE-STOP-CONTEXT-V1 ", 512),
        ("CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 ", 512),
        ("CRUCIBLE-CONTROL-LAST-V1 ", 512),
        ("CRUCIBLE-CONTROL-SETTLEMENT-LAST-V1 ", 512),
        ("CRUCIBLE-CONTROL-PENDING-V1 ", 511),
        ("CRUCIBLE-CHECKPOINT-STOP-V1 ", 511),
        ("CRUCIBLE-CONTROL-STAGE-V1 ", 255),
    ] {
        match recent_callback_context_rows(service, prefix, maximum_bytes) {
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

// This accepts text only. Independent fields never authenticate delivery or ACK.
fn recent_native_control_summary_rows(
    service: &CampaignServiceChild,
) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(service
        .stderr_recent_lines_with_prefix("CRUCIBLE-NATIVE-CONTROL-SUMMARY-V1 ", 32, 511)?
        .into_iter()
        .filter(|row| native_control_summary::valid_row(row))
        .collect())
}

// The aggregate service stream can contain several owned QEMU processes.
// This transport bounds text only; the private child parser owns PID validation.
fn recent_callback_context_rows(
    service: &CampaignServiceChild,
    prefix: &str,
    maximum_bytes: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(service
        .stderr_recent_lines_with_prefix(prefix, 32, maximum_bytes)?
        .into_iter()
        .filter(|row| {
            row.bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic())
        })
        .collect())
}

pub(super) fn configure_flight_diagnostics(
    invocation: &mut Command,
    diagnostics: FlightDiagnostics,
) {
    // Admit only canonical1; ordinary FC initializers leave this setting absent.
    // This opt-in does not enable routine callback or native trace streams.
    if std::env::var("CRUCIBLE_NATIVE_CONTROL_DELIVERY_SUMMARY").as_deref() == Ok("1") {
        invocation.env("CRUCIBLE_NATIVE_CONTROL_DELIVERY_SUMMARY", "1");
    } else {
        invocation.env_remove("CRUCIBLE_NATIVE_CONTROL_DELIVERY_SUMMARY");
    }
    if matches!(diagnostics, FlightDiagnostics::Disabled) {
        return;
    }

    // The daemon rejects values outside 1..=256 by disabling tier notices.
    // Runtime progress shares this opt-in and also admits the same bound.
    invocation.env("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS", "256");
    if matches!(diagnostics, FlightDiagnostics::Materialization { .. }) {
        // Fixed failure observations use the aggregate opt-in independently.
        // A caller's routine trace selections must not turn this profile into
        // a per-quantum stderr or native-file producer.
        for setting in [
            "CRUCIBLE_CONTROL_CALLBACK_WITNESS",
            "CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN",
            "CRUCIBLE_RR_CLAMP_TAIL",
            "CRUCIBLE_PHASE7_IDLE_TRACE",
            "CRUCIBLE_TIME_OWNERSHIP_WITNESS",
        ] {
            invocation.env_remove(setting);
        }
    }
    if let FlightDiagnostics::Materialization {
        pending_min_token: Some(minimum),
    } = diagnostics
    {
        // This explicit in-guest profile reaches late pending requests without
        // enabling callback stages or native per-quantum traces.
        // Keep the aggregate budget: seal phases and the tier receipt share it.
        invocation.env(
            "CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN",
            minimum.to_string(),
        );
    }
    if let FlightDiagnostics::ControlCallback { stage_min_token } = diagnostics {
        invocation.env("CRUCIBLE_CONTROL_CALLBACK_WITNESS", "1");
        invocation.env("CRUCIBLE_RR_CLAMP_TAIL", "1");
        invocation.env(
            "CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN",
            stage_min_token.to_string(),
        );
    }
}

#[test]
fn diagnostic_flights_request_admitted_materialization_events() {
    for diagnostics in [
        FlightDiagnostics::Materialization {
            pending_min_token: None,
        },
        FlightDiagnostics::Materialization {
            pending_min_token: Some(50_000),
        },
        FlightDiagnostics::ControlCallback {
            stage_min_token: 4400,
        },
        FlightDiagnostics::ControlCallback {
            stage_min_token: 10400,
        },
    ] {
        let minimum = match diagnostics {
            FlightDiagnostics::ControlCallback { stage_min_token } => {
                Some(stage_min_token.to_string())
            }
            FlightDiagnostics::Materialization { pending_min_token } => {
                pending_min_token.map(|token| token.to_string())
            }
            FlightDiagnostics::Disabled => None,
        };
        let witness = matches!(diagnostics, FlightDiagnostics::ControlCallback { .. });
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
            environment.get(std::ffi::OsStr::new("CRUCIBLE_CONTROL_CALLBACK_WITNESS")),
            Some(&witness.then_some(std::ffi::OsStr::new("1")))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new("CRUCIBLE_RR_CLAMP_TAIL")),
            Some(&witness.then_some(std::ffi::OsStr::new("1")))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new(
                "CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN"
            )),
            Some(&minimum.as_deref().map(std::ffi::OsStr::new))
        );
        assert_eq!(environment.len(), if witness { 5 } else { 7 });
    }

    let mut disabled = Command::new("unused-fixture-program");
    configure_flight_diagnostics(&mut disabled, FlightDiagnostics::Disabled);
    assert_eq!(disabled.get_envs().count(), 1);
}

#[test]
fn aggregate_service_profile_clears_explicit_streams_and_preserves_other_environment() {
    let mut invocation = Command::new("unused-fixture-program");
    for setting in [
        "CRUCIBLE_CONTROL_CALLBACK_WITNESS",
        "CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN",
        "CRUCIBLE_RR_CLAMP_TAIL",
        "CRUCIBLE_PHASE7_IDLE_TRACE",
        "CRUCIBLE_TIME_OWNERSHIP_WITNESS",
    ] {
        invocation.env(setting, "1");
    }
    invocation.env("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS", "512");
    invocation.env("OTHER_SERVICE_OWNER", "original-value");

    configure_flight_diagnostics(
        &mut invocation,
        FlightDiagnostics::Materialization {
            pending_min_token: None,
        },
    );

    let environment = invocation.get_envs().collect::<BTreeMap<_, _>>();
    assert_eq!(
        environment.get(std::ffi::OsStr::new("OTHER_SERVICE_OWNER")),
        Some(&Some(std::ffi::OsStr::new("original-value")))
    );
    assert_eq!(
        environment.get(std::ffi::OsStr::new(
            "CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS"
        )),
        Some(&Some(std::ffi::OsStr::new("256")))
    );
    assert_eq!(
        environment.values().filter(|value| value.is_none()).count(),
        6
    );
    assert_eq!(environment.len(), 8);
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
        live_progress: None,
        kill_on_drop: false,
    };
    use std::os::unix::fs::MetadataExt as _;
    let original_file = service.stderr.as_file().metadata()?;
    let attempt = "synthetic-capture-regression-attempt";
    let attestation = format!("{MATERIALIZATION_DIAGNOSTIC_PREFIX}attempt={attempt} tier=HotFork");
    writeln!(service.stderr, "{attestation}")?;
    let output_context = "CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 phase=vcpu-resume pid=42 arm_pid=42 origin=direct-tx original_ps=100 original_raw=2 observed_ps=150 observed_raw=3 write_frontier=1 admission=0";
    let callback_context = "CRUCIBLE-CONTROL-LAST-V1 kind=last-admitted phase=after-drain teardown=host-quit pid=42 device=1 inode=2 length=4096 slot=0 generation=2 final_token=3 callback=1 raw_icount=7 callback_phase=exit reason=acknowledged rejection_mask=0 token_kind=observed token_before=2 token_after=3";
    writeln!(service.stderr, "{output_context}")?;
    writeln!(service.stderr, "{callback_context}")?;
    let settlement_context = "CRUCIBLE-CONTROL-SETTLEMENT-LAST-V1 phase=after-drain teardown=host-quit pid=42 device=1 inode=2 length=4096 slot=0 generation=2 final_token=2 callback=7 raw=8 token=2 frontier=6 reason=pump-active";
    writeln!(service.stderr, "{settlement_context}")?;
    let pending_context = "CRUCIBLE-CONTROL-PENDING-V1 phase=return pid=42 callback=7 raw=8 token=54008 device=1 inode=2 length=4096 slot=0 generation=2 frontier=6 capture=0 reason=pump-active";
    writeln!(service.stderr, "{pending_context}")?;
    let native_context = "CRUCIBLE-NATIVE-STOP-CONTEXT-V1 phase=rearm-shutdown pid=42 gen=3 request=12830 ack=12829 complete=12829 state=2 runstate=4 flush=0 shutdown=1 advance=0 fd=7 scope=unavailable pc=unavailable coord=unavailable";
    writeln!(service.stderr, "{native_context}")?;
    let delivery_context = "CRUCIBLE-NATIVE-CONTROL-SUMMARY-V1 scope=before-cancel kind=current phase=cancel pid=42 sample=7 request=3 ack=2 complete=2 rr_token=0x3 token=0x3 deferred=1 state=2 runstate=4 owner=0";
    writeln!(service.stderr, "{delivery_context}")?;
    writeln!(
        service.stderr,
        "{}",
        delivery_context.replace("scope=before-cancel", "scope=active")
    )?;
    writeln!(service.stderr, "{delivery_context} extra=1")?;

    let stop_prefix = "CRUCIBLE-CHECKPOINT-STOP-V1 ";
    let stage_prefix = "CRUCIBLE-CONTROL-STAGE-V1 ";
    for token in 4400..4440 {
        writeln!(
            service.stderr,
            "{stop_prefix}phase=after-request pid=42 device=1 inode=2 length=4096 slot=0 generation=2 caller=vcpu-idle raw_icount=7 logical_ps=100 token={token} status=0"
        )?;
        writeln!(
            service.stderr,
            "{stage_prefix}phase=settle-return pid=43 callback=7 token={token} raw=7 dev=1 ino=2 slot=0 gen=2 result=false"
        )?;
    }

    for record in 0..70 {
        writeln!(
            service.stderr,
            "CRUCIBLE-IDLE-PLAN-V1 phase=plan pid=42 current_ps=100 record={record}"
        )?;
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

    assert_eq!(
        recent_callback_context_rows(&service, "CRUCIBLE-CONTROL-SETTLEMENT-LAST-V1 ", 512)?,
        [settlement_context]
    );
    assert_eq!(
        recent_callback_context_rows(&service, "CRUCIBLE-CONTROL-PENDING-V1 ", 511)?,
        [pending_context]
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
    let idle_plans = recent_idle_plan_rows(&service)?;
    assert_eq!(idle_plans.len(), 64);
    assert!(
        idle_plans
            .first()
            .is_some_and(|row| row.ends_with("record=6"))
    );
    assert!(
        idle_plans
            .last()
            .is_some_and(|row| row.ends_with("record=69"))
    );
    assert!(!service.stderr_tail().contains("CRUCIBLE-IDLE-PLAN-V1 "));

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
    assert_eq!(
        service.stderr_recent_lines_with_prefix("CRUCIBLE-NATIVE-STOP-CONTEXT-V1 ", 32, 512)?,
        [native_context]
    );
    assert!(
        !service
            .stderr_tail()
            .contains("CRUCIBLE-NATIVE-STOP-CONTEXT-V1 ")
    );

    assert_eq!(
        recent_native_control_summary_rows(&service)?,
        [delivery_context]
    );
    assert!(
        !service
            .stderr_tail()
            .contains("CRUCIBLE-NATIVE-CONTROL-SUMMARY-V1")
    );

    let stop_rows = recent_callback_context_rows(&service, stop_prefix, 511)?;
    let stage_rows = recent_callback_context_rows(&service, stage_prefix, 255)?;
    for rows in [&stop_rows, &stage_rows] {
        assert_eq!(rows.len(), 32);
        assert!(rows.first().is_some_and(|row| row.contains("token=4408 ")));
        assert!(rows.last().is_some_and(|row| row.contains("token=4439 ")));
    }
    // Separate PIDs remain in the aggregate stream; no modeled PID authority
    // is added by the CLI forwarding layer.
    assert!(stage_rows.iter().all(|row| row.contains("pid=43 ")));
    assert!(!service.stderr_tail().contains(stage_prefix));
    let retained_file = service.stderr.as_file().metadata()?;
    assert_eq!(retained_file.dev(), original_file.dev());
    assert_eq!(retained_file.ino(), original_file.ino());

    writeln!(service.stderr, "{stage_prefix}non-ascii=é")?;
    writeln!(service.stderr, "CRUCIBLE-UNKNOWN-V1 token=4440")?;
    service.stderr.flush()?;
    let rows = recent_callback_context_rows(&service, stage_prefix, 255)?;
    assert_eq!(rows.len(), 31);
    assert!(rows.iter().all(|row| row.is_ascii()));
    assert!(rows.iter().all(|row| !row.contains("UNKNOWN")));

    writeln!(service.stderr, "{stage_prefix}{}", "x".repeat(256))?;
    service.stderr.flush()?;
    assert!(recent_callback_context_rows(&service, stage_prefix, 255).is_err());

    writeln!(service.stderr, "CRUCIBLE-IDLE-PLAN-V1 non-ascii=é")?;
    service.stderr.flush()?;
    assert!(
        recent_idle_plan_rows(&service)?
            .iter()
            .all(|row| row.is_ascii())
    );
    writeln!(service.stderr, "CRUCIBLE-IDLE-PLAN-V1 {}", "x".repeat(512))?;
    service.stderr.flush()?;
    assert!(recent_idle_plan_rows(&service).is_err());
    // Advisory read failure has not changed the retained file or process owner.
    assert_eq!(
        service.stderr.as_file().metadata()?.ino(),
        original_file.ino()
    );
    assert!(service.child.try_wait()?.is_some());
    Ok(())
}
