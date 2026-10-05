//! Exercises the original pre-OUT whitebox callback across native stop/resume.
//!
//! A tiny ROM reuses one RAM buffer for canonical registration, setup, semantic
//! marker and selectable request frames. The production plugin decodes those
//! frames through its original register and guest-memory readers. This test
//! isolates TCG callback replay. A separate Linux entry exercises the original
//! SDK in CPL3, with and without a static no-SDK child process.
//!
//! ```text
//! crucible-qemu-whitebox-out-resume firmware OUTPUT [normal|late-register]
//! crucible-qemu-whitebox-out-resume run QEMU PLUGIN ROM CGROUP_ROOT RUN_ROOT MODE
//! crucible-qemu-whitebox-out-resume run-linux QEMU PLUGIN KERNEL INITRD FIRMWARE CGROUP_ROOT RUN_ROOT PROFILE
//! ```

#![forbid(unsafe_code)]

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, Icount, ObservableEvent, ObservableEventPayload, SimulationBackend, VirtualTime,
};
use crucible_protocol::selectable_catalog_plan::{
    SELECTABLE_NATIVE_HANDOFF_TICKS_PS, SelectableCatalogPlan, SelectablePlanContinuation,
    SelectablePlanDeclaration, SelectablePlanLimits, SelectablePlanPhase, SelectablePlanPresence,
};
use crucible_protocol::{SelectionReply, SelectionReplyStatus};
use crucible_qemu::{
    LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory, QemuCrashCause,
    QemuLaunchPluginSwitch, QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig, QemuNode,
    QemuNodeError, QemuNodeRunStatus, QemuProductionFreshLaunchAdmission, QemuShutdownReport,
    QemuShutdownRung, launch_qemu_production_fresh_node,
};

#[path = "crucible-qemu-whitebox-out-resume/firmware.rs"]
mod firmware;

#[path = "crucible-qemu-whitebox-out-resume/linux.rs"]
mod linux;

const NODE: &str = "whitebox-out-resume";
const SELECTABLE: &str = "out.ready";
const BUFFER: u64 = 0x5000;
const CEILING_PS: u64 = 10_000_000;
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Normal,
    LateRegister,
}

impl Mode {
    fn parse(value: &Path) -> Result<Self, Box<dyn Error>> {
        match value.to_str() {
            Some("normal") => Ok(Self::Normal),
            Some("late-register") => Ok(Self::LateRegister),
            _ => Err("expected normal or late-register".into()),
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-whitebox-out-resume: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    match arguments.as_slice() {
        [command, output, mode] if command == Path::new("firmware") => {
            firmware::write(output, Mode::parse(mode)?)
        }
        [command, qemu, plugin, rom, cgroup, root, mode] if command == Path::new("run") => {
            flight(qemu, plugin, rom, cgroup, root, Mode::parse(mode)?)
        }
        [command, qemu, plugin, kernel, initrd, firmware, cgroup, root, profile]
            if command == Path::new("run-linux") =>
        {
            linux::flight(
                qemu,
                plugin,
                linux::BootArtifacts { kernel, initrd, firmware },
                cgroup,
                root,
                profile,
            )
        }
        _ => Err("expected firmware OUTPUT MODE, run QEMU PLUGIN ROM CGROUP_ROOT RUN_ROOT MODE, or run-linux QEMU PLUGIN KERNEL INITRD FIRMWARE CGROUP_ROOT RUN_ROOT PROFILE".into()),
    }
}

#[derive(Clone, Copy)]
struct ProbePolicy {
    ceiling_ps: u64,
    completion_timeout: Duration,
    fixed_buffer: Option<u64>,
    profile: &'static str,
}

const ROM_POLICY: ProbePolicy = ProbePolicy {
    ceiling_ps: CEILING_PS,
    completion_timeout: COMPLETION_TIMEOUT,
    fixed_buffer: Some(BUFFER),
    profile: "real-mode-rom-shared-buffer",
};

fn catalog() -> Result<SelectableCatalogPlan, Box<dyn Error>> {
    Ok(SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 2, 2)?,
        vec![SelectablePlanDeclaration::new(
            SELECTABLE,
            vec![1],
            vec![1],
            vec!["readiness".into()],
            SelectablePlanPresence::Required,
        )?],
        SelectablePlanContinuation::cold(),
    )?)
}

fn flight(
    qemu: &Path,
    plugin: &Path,
    rom: &Path,
    cgroup: &Path,
    root: &Path,
    mode: Mode,
) -> Result<(), Box<dyn Error>> {
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, rom, rom, root)
        .with_firmware_boot()
        .with_vm_shape(64, 1)
        .with_whitebox(QemuLaunchPluginSwitch::On)
        .with_selectable_catalog_plan(catalog()?)
        .with_completion_timeout(COMPLETION_TIMEOUT);
    run_owned(qemu, cgroup, root, mode, config, ROM_POLICY)
}

fn run_owned(
    qemu: &Path,
    cgroup: &Path,
    root: &Path,
    mode: Mode,
    config: QemuLiveNodeStepGateConfig,
    policy: ProbePolicy,
) -> Result<(), Box<dyn Error>> {
    let host = LinuxQemuAttemptHostConfig::new(
        cgroup,
        root,
        NODE,
        23_800,
        1,
        65534,
        65534,
        64,
        4096,
        Duration::from_secs(15),
    )?;
    let mut factory = LinuxQemuAttemptHostFactory::open(host)?;
    let mut owner = factory.begin(1, 512 * 1024 * 1024, 1024 * 1024 * 1024)?;
    let mut directory = owner.prepare_generation_run_directory(config.resource_requirements())?;
    directory.prepare_fresh_artifacts_guarded(qemu, None, owner.process_contract()?)?;
    let launch = config.with_run_directory(directory.path());
    let mut node = launch_qemu_production_fresh_node(
        &launch,
        QemuProductionFreshLaunchAdmission::admit(
            &launch,
            &directory,
            owner.process_contract()?,
            QemuLiveNodeIdentity::new(NODE, "out-router", "out-crash"),
        )?,
    )?;

    let result = drive(&mut node, mode, policy);
    let shutdown = node.shutdown_child();
    drop(node);
    drop(directory);
    let finish = owner.finish();
    let refused_shutdown = match result {
        Ok(report) => report,
        Err(error) => {
            eprintln!("cleanup: shutdown={shutdown:?}; finish={finish:?}");
            return Err(error);
        }
    };
    let shutdown = shutdown?;
    finish?;
    if !shutdown.reaped || shutdown.leaked || !shutdown.failures.is_empty() {
        return Err(format!("owned cleanup incomplete: {shutdown:?}").into());
    }

    if let Some(report) = refused_shutdown {
        require_refusal_cleanup(&report)?;
    }

    println!("PASS");
    println!(
        "mode={}",
        if mode == Mode::Normal {
            "normal"
        } else {
            "late-register"
        }
    );
    println!("guest_profile={}", policy.profile);
    println!("native_stop_resume=original-selectable-handoff");
    println!("owned_cleanup=complete");
    Ok(())
}

fn drive(
    node: &mut QemuNode,
    mode: Mode,
    policy: ProbePolicy,
) -> Result<Option<QemuShutdownReport>, Box<dyn Error>> {
    let (first, buffer) = boundary(node, 2, "first", policy, policy.fixed_buffer)?;
    require_marker(&first, "first")?;
    let [setup, marker_event] = first.as_slice() else {
        return Err("first boundary must retain setup and one semantic frame".into());
    };
    if !matches!(setup.payload(), ObservableEventPayload::GuestMarker { retired_icount, node, marker }
        if node.name == NODE && marker.name == "lifecycle.setup_complete"
            && retired_icount.retired == setup.at().ticks
            && setup.at().ticks < marker_event.at().ticks)
    {
        return Err(
            "setup was not the original authenticated marker before the first frame".into(),
        );
    }
    let plan = node
        .selectable_catalog_plan()
        .ok_or("host catalog absent")?;
    let continuation = plan.continuation();
    if continuation.phase() != SelectablePlanPhase::Frozen
        || continuation.last_registration_sequence() != Some(1)
        || continuation.registered().len() != 1
        || !continuation.registered().contains(SELECTABLE)
        || continuation.total_completed_requests() != 0
    {
        return Err("first boundary did not retain exactly the original registration".into());
    }

    if mode == Mode::LateRegister {
        // The VM result also requires the original fatal catalog-refusal row.
        // A generic step error alone is not the negative control's authority.
        let error = match node.advance_to_ceiling(Icount {
            retired: policy.ceiling_ps,
        }) {
            Ok(_) => return Err("late registration unexpectedly advanced".into()),
            Err(error) => error,
        };
        let QemuNodeError::Crashed { status, shutdown } = error else {
            return Err(error.into());
        };
        require_refusal_crash_status_with_budget(&status, policy.completion_timeout)?;
        // The public crash type carries exit/timeout context, not the plugin's
        // fatal error. The gate separately requires that exact original row.
        eprintln!("late-register crash: status={status:?}; shutdown={shutdown:?}");
        println!("late_register_step_refused=true");
        return Ok(Some(*shutdown));
    }

    let (second, _) = boundary(node, 3, "second", policy, Some(buffer))?;
    require_marker(&second, "second")?;
    if second.len() != 1 {
        return Err("second boundary replayed an earlier observable frame".into());
    }
    let plan = node
        .selectable_catalog_plan()
        .ok_or("resumed host catalog absent")?;
    let continuation = plan.continuation();
    if continuation.last_registration_sequence() != Some(1)
        || continuation.last_completed_request_sequence() != Some(2)
        || continuation.total_completed_requests() != 1
        || continuation.registered().len() != 1
    {
        return Err("resumed catalog duplicated or lost a callback effect".into());
    }
    println!("registration_sequence=1");
    println!("request_sequences=2,3");
    println!("distinct_semantic_frames=first,second");
    println!("same_guest_buffer={buffer}");
    Ok(None)
}

// The driver reports the remaining budget at the original bounded wait,
// rather than promising the full configured budget in its crash payload.
#[cfg(test)]
fn require_refusal_crash_status(status: &QemuNodeRunStatus) -> Result<(), Box<dyn Error>> {
    require_refusal_crash_status_with_budget(status, COMPLETION_TIMEOUT)
}

fn require_refusal_crash_status_with_budget(
    status: &QemuNodeRunStatus,
    completion_timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let QemuNodeRunStatus::Crashed(crashed) = status else {
        return Err(format!("late registration did not retain a crash status: {status:?}").into());
    };
    let expected_cause = match &crashed.cause {
        QemuCrashCause::UnexpectedChildExit(exit) => {
            exit.code == Some(1) && exit.signal.is_none() && !exit.success
        }
        QemuCrashCause::BoundedAwaitTimeout(timeout) => {
            timeout.operation == "advance completion"
                && !timeout.timeout.is_zero()
                && timeout.timeout <= completion_timeout
        }
        _ => false,
    };
    if crashed.node_id != "out-crash" || !expected_cause {
        return Err(format!("unexpected refusal crash status: {status:?}").into());
    }
    Ok(())
}

// Fatal plugin shutdown can close its polite channels before host escalation.
// Only the original channel failures are admissible; signal/reap failures and
// repeated or unrelated channel errors remain failures.
fn require_refusal_cleanup(report: &QemuShutdownReport) -> Result<(), Box<dyn Error>> {
    let mut control_closed = false;
    let mut qmp_closed = false;
    let allowed = report.failures.iter().all(|failure| {
        match (
            failure.rung,
            failure.source.operation,
            failure.source.message.as_str(),
        ) {
            (
                QemuShutdownRung::ControlQuit,
                "send plugin control Quit",
                "control lifecycle I/O failed",
            ) if !control_closed => {
                control_closed = true;
                true
            }
            (QemuShutdownRung::QmpQuit, "qmp", "write QMP request failed with BrokenPipe")
                if !qmp_closed =>
            {
                qmp_closed = true;
                true
            }
            _ => false,
        }
    });
    if !report.reaped || report.leaked || !allowed {
        return Err(format!("frozen-catalog refusal cleanup incomplete: {report:?}").into());
    }
    Ok(())
}

fn boundary(
    node: &mut QemuNode,
    sequence: u64,
    instance: &str,
    policy: ProbePolicy,
    expected_buffer: Option<u64>,
) -> Result<(Vec<ObservableEvent>, u64), Box<dyn Error>> {
    let observed = SimulationBackend::step_to(
        node,
        VirtualTime {
            ticks: policy.ceiling_ps,
        },
    )?;
    let AdvanceOutcome::Paused { at } = observed.outcome else {
        return Err("guest did not reach an original selectable pause".into());
    };
    let events = SimulationBackend::drain_observable_events(node)?;
    let requests = node.drain_pending_selectable_requests()?;
    let [pending] = requests.as_slice() else {
        return Err("boundary did not carry exactly one callback request".into());
    };
    let request = pending.request();
    if request.sequence() != sequence
        || request.selectable_id() != SELECTABLE
        || request.instance_key() != instance
        || request.reply_capacity() != 128
        || request.narrowed_domain().is_some()
        || pending.vcpu_index() != 0
        || !buffer_matches(expected_buffer, pending.guest_virtual_address())
        || observed.reached.ticks != at.retired
        || at.retired
            != pending
                .trap_tick_ps()
                .checked_add(SELECTABLE_NATIVE_HANDOFF_TICKS_PS)
                .ok_or("stop coordinate overflow")?
    {
        return Err(format!("original request/OUT stop identity changed: {pending:?}").into());
    }
    if node.logical_time_calibration()?.logical_icount != at.retired {
        return Err("native stop calibration differs from its original boundary".into());
    }
    if sequence == 2 {
        let reply = SelectionReply::rejected(
            sequence,
            SelectionReplyStatus::Unavailable,
            [0; 32],
            [0; 32],
        )?;
        node.enqueue_selectable_reply(pending, &reply)?;
    }
    Ok((events, pending.guest_virtual_address()))
}

fn buffer_matches(expected: Option<u64>, observed: u64) -> bool {
    observed != 0 && expected.is_none_or(|address| address == observed)
}

fn require_marker(events: &[ObservableEvent], expected: &str) -> Result<(), Box<dyn Error>> {
    let mut markers = events.iter().filter_map(|event| match event.payload() {
        ObservableEventPayload::GuestSemanticMarker {
            node,
            marker,
            instance,
            details,
            retired_icount,
        } if node.name == NODE
            && marker == "out.frame"
            && details.is_empty()
            && retired_icount.retired == event.at().ticks =>
        {
            Some(instance.as_str())
        }
        _ => None,
    });
    if markers.next() != Some(expected) || markers.next().is_some() {
        return Err(format!("expected exactly one original semantic frame {expected}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{COMPLETION_TIMEOUT, require_refusal_cleanup, require_refusal_crash_status};
    use crucible_qemu::{
        QemuBoundedAwaitTimeout, QemuCrashCause, QemuCrashedNodeStatus, QemuNodeRunStatus,
        QemuProcessExit, QemuShutdownFailure, QemuShutdownReport, QemuShutdownRung,
        QemuShutdownTargetError,
    };
    use std::time::Duration;

    fn crashed(cause: QemuCrashCause) -> QemuNodeRunStatus {
        QemuNodeRunStatus::Crashed(QemuCrashedNodeStatus::new("out-crash", cause))
    }

    fn timeout(operation: &str, remaining: Duration) -> QemuCrashCause {
        QemuCrashCause::BoundedAwaitTimeout(QemuBoundedAwaitTimeout::new(operation, remaining))
    }

    fn plugin_exit() -> QemuProcessExit {
        QemuProcessExit {
            code: Some(1),
            signal: None,
            success: false,
            display: "exit status: 1".into(),
        }
    }

    #[test]
    fn refusal_crash_retains_original_exit_or_remaining_wait_budget() {
        for remaining in [
            COMPLETION_TIMEOUT,
            Duration::from_nanos(4_995_050_723),
            Duration::from_nanos(1),
        ] {
            assert!(
                require_refusal_crash_status(&crashed(timeout("advance completion", remaining,)))
                    .is_ok()
            );
        }
        assert!(
            require_refusal_crash_status(&crashed(QemuCrashCause::UnexpectedChildExit(
                plugin_exit()
            ),))
            .is_ok()
        );
    }

    #[test]
    fn unrelated_or_outside_policy_crashes_remain_failures() {
        for cause in [
            timeout("advance completion", Duration::ZERO),
            timeout(
                "advance completion",
                COMPLETION_TIMEOUT + Duration::from_nanos(1),
            ),
            timeout("prime guest", COMPLETION_TIMEOUT),
        ] {
            assert!(require_refusal_crash_status(&crashed(cause)).is_err());
        }
        let mut wrong_code = plugin_exit();
        wrong_code.code = Some(2);
        let mut signaled = plugin_exit();
        signaled.signal = Some(9);
        let mut successful = plugin_exit();
        successful.success = true;
        for exit in [wrong_code, signaled, successful] {
            assert!(
                require_refusal_crash_status(&crashed(QemuCrashCause::UnexpectedChildExit(exit),))
                    .is_err()
            );
        }
    }

    #[test]
    fn refusal_crash_authenticates_the_original_owner_and_status() {
        let wrong_owner = QemuNodeRunStatus::Crashed(QemuCrashedNodeStatus::new(
            "other-owner",
            timeout("advance completion", COMPLETION_TIMEOUT),
        ));
        for status in [
            wrong_owner,
            QemuNodeRunStatus::Running,
            QemuNodeRunStatus::Idle,
            QemuNodeRunStatus::Done,
        ] {
            assert!(require_refusal_crash_status(&status).is_err());
        }
    }

    fn report(failures: Vec<QemuShutdownFailure>) -> QemuShutdownReport {
        QemuShutdownReport {
            attempts: Vec::new(),
            failures,
            reaped: true,
            leaked: false,
        }
    }

    fn closed_control() -> QemuShutdownFailure {
        QemuShutdownFailure {
            rung: QemuShutdownRung::ControlQuit,
            source: QemuShutdownTargetError::new(
                "send plugin control Quit",
                "control lifecycle I/O failed",
            ),
        }
    }

    fn closed_qmp() -> QemuShutdownFailure {
        QemuShutdownFailure {
            rung: QemuShutdownRung::QmpQuit,
            source: QemuShutdownTargetError::new("qmp", "write QMP request failed with BrokenPipe"),
        }
    }

    #[test]
    fn frozen_refusal_accepts_only_original_closed_channel_reports() {
        for failures in [
            Vec::new(),
            vec![closed_control()],
            vec![closed_qmp()],
            vec![closed_control(), closed_qmp()],
        ] {
            assert!(require_refusal_cleanup(&report(failures)).is_ok());
        }
    }

    #[test]
    fn unrelated_or_repeated_shutdown_failures_remain_failures() {
        let mut wrong_operation = closed_control();
        wrong_operation.source.operation = "poll QEMU child exit";
        let mut wrong_message = closed_qmp();
        wrong_message.source.message = "write QMP request failed with PermissionDenied".into();
        for failures in [
            vec![closed_control(), closed_control()],
            vec![closed_qmp(), closed_qmp()],
            vec![wrong_operation],
            vec![wrong_message],
        ] {
            assert!(require_refusal_cleanup(&report(failures)).is_err());
        }
        for rung in [
            QemuShutdownRung::Sigterm,
            QemuShutdownRung::Sigkill,
            QemuShutdownRung::Reap,
        ] {
            let mut wrong_rung = closed_control();
            wrong_rung.rung = rung;
            assert!(require_refusal_cleanup(&report(vec![wrong_rung])).is_err());
        }
    }

    #[test]
    fn channel_refusal_never_substitutes_for_reap_or_leak_freedom() {
        let mut not_reaped = report(vec![closed_control(), closed_qmp()]);
        not_reaped.reaped = false;
        assert!(require_refusal_cleanup(&not_reaped).is_err());

        let mut leaked = report(Vec::new());
        leaked.leaked = true;
        assert!(require_refusal_cleanup(&leaked).is_err());
    }
}
