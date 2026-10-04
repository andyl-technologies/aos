//! Validates authenticated fresh-guest clock returns under withheld host grants.
//!
//! This mode uses the original production node, selectable barriers, native
//! idle wait and timer publication. It neither restores a child nor installs a
//! clock fault. Linux return equivalence is narrower than absolute timekeeper
//! calibration: the latter requires a separate RTC/kernel affine proof.

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, GuestMeasurementValue, GuestSemanticMarkerDetail, Icount, ObservableEvent,
    ObservableEventPayload, SimulationBackend, VirtualTime,
};
use crucible_protocol::selectable_catalog_plan::{
    SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanDeclaration,
    SelectablePlanLimits, SelectablePlanPresence,
};
use crucible_protocol::{SelectionReply, SelectionReplyStatus};
use crucible_qemu::{
    LinuxQemuAttemptHostFactory, QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig, QemuNode,
    QemuProductionFreshLaunchAdmission, launch_qemu_production_fresh_node,
};
use serde::Serialize;

const CLOCKS: [&str; 4] = ["realtime", "monotonic", "gettimeofday", "tsc"];
const BEFORE: &str = "clock.read.before";
const AFTER: &str = "clock.read.after";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ReadReceipt {
    instance: String,
    before_ps: u64,
    after_ps: u64,
    seconds: i64,
    fraction: i64,
    value: u64,
    unit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    vvar: Option<Vec<u64>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Boundary {
    sequence: u64,
    logical_ps: u64,
    raw_instructions: u64,
    trap_ps: u64,
}

#[derive(Clone, Serialize)]
struct RunEvidence {
    pid: u32,
    reads: Vec<ReadReceipt>,
    boundaries: Vec<Boundary>,
    idle_ps: u64,
    idle_raw: u64,
    wake_ps: u64,
    timer_generation: u64,
    // Retain original public payloads, including all return details, rather
    // than publishing only the validator's derived comparison booleans.
    events: Vec<(u64, ObservableEventPayload)>,
}

pub(super) fn selectable_catalog_plan(
    clock_read_flight: bool,
) -> Result<SelectableCatalogPlan, Box<dyn Error>> {
    let declaration = SelectablePlanDeclaration::new(
        super::READINESS_SELECTABLE_ID,
        vec![1],
        vec![1],
        vec![String::from("readiness")],
        SelectablePlanPresence::Required,
    )?;
    // The clock payload reuses readiness for boot and both read batches.
    let requests = if clock_read_flight { 3 } else { 1 };
    Ok(SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, requests, requests)?,
        vec![declaration],
        SelectablePlanContinuation::cold(),
    )?)
}

pub(super) fn requested() -> Result<bool, Box<dyn Error>> {
    mode(
        std::env::var_os("CRUCIBLE_GUEST_CLOCK_READ_FLIGHT").as_deref(),
        std::env::var_os(super::TIME_OWNERSHIP_ENVIRONMENT).as_deref(),
    )
}

fn mode(
    value: Option<&std::ffi::OsStr>,
    ownership: Option<&std::ffi::OsStr>,
) -> Result<bool, Box<dyn Error>> {
    match value {
        None => Ok(false),
        Some(value) if value == "1" && ownership.is_some_and(|setting| setting == "1") => Ok(true),
        _ => Err(
            "guest clock-read flight requires exact mode=1 and original ownership observer=1"
                .into(),
        ),
    }
}

pub(super) fn run(
    factory: &mut LinuxQemuAttemptHostFactory,
    config: &QemuLiveNodeStepGateConfig,
    qemu: &Path,
    evidence_output: &Path,
) -> Result<(), Box<dyn Error>> {
    let runtime_anchor = match std::env::var_os("CRUCIBLE_GUEST_CLOCK_RUNTIME_ANCHOR") {
        None => false,
        Some(value) if value == "1" => true,
        _ => return Err("guest clock runtime anchor requires exact mode=1".into()),
    };
    let reference = run_once(factory, config, qemu, false, runtime_anchor)?;
    let hostile = run_once(factory, config, qemu, true, runtime_anchor)?;
    compare(&reference, &hostile)?;
    std::fs::write(
        evidence_output,
        serde_json::to_vec_pretty(&[reference, hostile])?,
    )?;
    println!("PASS");
    println!("diagnostic_mode=guest-clock-read-equivalence");
    println!("actual_guest_clock_returns_restart_identical=true");
    println!("tsc_original_read_brackets_valid=true");
    println!("idle_hold_clock_unchanged=true");
    println!("authorized_exact_timer_wake_raw_unchanged=true");
    if runtime_anchor {
        println!("published_kernel_runtime_anchor_retained=true");
    }
    println!("absolute_linux_clock_calibration_qualified=false");
    println!("fork_child_clock_ownership_qualified=false");
    Ok(())
}

fn compare(reference: &RunEvidence, hostile: &RunEvidence) -> Result<(), Box<dyn Error>> {
    if reference.pid == hostile.pid
        || reference.reads != hostile.reads
        || reference.events != hostile.events
        || reference.boundaries != hostile.boundaries
        || reference.timer_generation != hostile.timer_generation
        || (reference.idle_ps, reference.idle_raw, reference.wake_ps)
            != (hostile.idle_ps, hostile.idle_raw, hostile.wake_ps)
    {
        let changed = reference
            .reads
            .iter()
            .zip(&hostile.reads)
            .find(|(left, right)| left != right);
        return Err(format!("guest clock return/grant equivalence refused: original_pids={}/{} first_changed_read={changed:?}", reference.pid, hostile.pid).into());
    }
    Ok(())
}

fn run_once(
    factory: &mut LinuxQemuAttemptHostFactory,
    config: &QemuLiveNodeStepGateConfig,
    qemu: &Path,
    hostile: bool,
    runtime_anchor: bool,
) -> Result<RunEvidence, Box<dyn Error>> {
    let mut owner = factory.begin(4, super::MEMORY_BYTES, super::DISK_BYTES)?;
    let mut directory = owner.prepare_generation_run_directory(config.resource_requirements())?;
    directory.prepare_fresh_artifacts_guarded(qemu, None, owner.process_contract()?)?;
    let launch = config.clone().with_run_directory(directory.path());
    let mut node = launch_qemu_production_fresh_node(
        &launch,
        QemuProductionFreshLaunchAdmission::admit(
            &launch,
            &directory,
            owner.process_contract()?,
            QemuLiveNodeIdentity::new(
                super::FLIGHT_NODE_ID,
                "plugin-flight-router",
                "plugin-flight-crash",
            ),
        )?,
    )?;
    let pid = node.process_id();
    let (boot, boot_boundary) = barrier(&mut node, 2, "boot", true)?;
    super::authenticate_readiness_marker(
        &boot,
        Icount {
            retired: boot_boundary.logical_ps,
        },
    )?;
    let (first, first_boundary) = barrier(&mut node, 3, "clock-0", false)?;
    let mut reads = validate_batch_mode(&first, 0, runtime_anchor)?;
    let mut events = retained(&boot);
    events.extend(retained(&first));

    let halted = node.advance_to_next_idle(Icount {
        retired: super::READINESS_ADMISSION_CEILING,
    })?;
    let AdvanceOutcome::Paused { at } = halted else {
        return Err("clock-read guest did not enter its original all-vCPU idle wait".into());
    };
    if !SimulationBackend::drain_observable_events(&mut node)?.is_empty()
        || !node.selectable_reply_is_checkpoint_quiescent()
    {
        return Err(
            "clock-read idle boundary retained unexpected events or an unconsumed reply".into(),
        );
    }
    let idle = node.idle_state()?;
    let deadline = idle
        .next_deadline
        .ok_or("clock-read idle deadline missing")?;
    let armed = node.logical_time_calibration()?;
    if idle.current_icount != at || deadline <= at || armed.logical_icount != at.retired {
        return Err("clock-read idle coordinates do not bind the original completion".into());
    }
    let prior = node.virtual_timer_fire_witness()?;
    if hostile {
        // The adversary withholds an original grant. It supplies no timestamp
        // to QEMU or the guest and does not issue a QMP stop/resume.
        std::thread::sleep(Duration::from_millis(200));
    }
    super::time_ownership::hold(&mut node, armed)?;
    let wake = SimulationBackend::step_to(
        &mut node,
        VirtualTime {
            ticks: deadline.retired,
        },
    )?;
    let after = node.logical_time_calibration()?;
    let timer = node
        .virtual_timer_fire_witness()?
        .ok_or("actual timer callback witness missing")?;
    if wake.reached.ticks != deadline.retired
        || after.logical_icount != deadline.retired
        || after.raw_icount != armed.raw_icount
        || prior.is_some_and(|old| old.generation == timer.generation)
        || timer.completed != 1
        || timer.reserved != 0
        || timer.deadline_tick != deadline.retired
        || timer.armed_raw_icount != armed.raw_icount
        || timer.fired_raw_icount != armed.raw_icount
        || timer.fired_expire_ps != timer.deadline_ps
        || timer.fired_virtual_ps != deadline.retired
    {
        return Err(
            "clock-read timer wake did not authenticate the original raw/logical transition".into(),
        );
    }
    if !SimulationBackend::drain_observable_events(&mut node)?.is_empty() {
        return Err("guest executed clock reads before the exact timer-wake boundary".into());
    }

    let (second, second_boundary) = barrier(&mut node, 4, "clock-1", false)?;
    reads.extend(validate_batch_mode(&second, 1, runtime_anchor)?);
    events.extend(retained(&second));
    validate_forward_returns(&reads)?;
    let shutdown = node.shutdown_child()?;
    if !shutdown.reaped || shutdown.leaked {
        return Err("clock-read guest was not cleanly reaped by its original owner".into());
    }
    drop(node);
    drop(directory);
    owner.finish()?;
    Ok(RunEvidence {
        pid,
        reads,
        boundaries: vec![boot_boundary, first_boundary, second_boundary],
        idle_ps: armed.logical_icount,
        idle_raw: armed.raw_icount,
        wake_ps: deadline.retired,
        timer_generation: timer.generation,
        events,
    })
}

fn barrier(
    node: &mut QemuNode,
    sequence: u64,
    instance: &str,
    release: bool,
) -> Result<(Vec<ObservableEvent>, Boundary), Box<dyn Error>> {
    let observation = SimulationBackend::step_to(
        node,
        VirtualTime {
            ticks: super::READINESS_ADMISSION_CEILING,
        },
    )?;
    let AdvanceOutcome::Paused { at } = observation.outcome else {
        return Err("clock-read guest missed its authenticated selectable barrier".into());
    };
    let events = SimulationBackend::drain_observable_events(node)?;
    let pending = node.drain_pending_selectable_requests()?;
    let [pending] = pending.as_slice() else {
        return Err("clock-read barrier must contain exactly one selectable request".into());
    };
    let request = pending.request();
    if at.retired
        != pending
            .trap_tick_ps()
            .checked_add(50)
            .ok_or("barrier overflow")?
        || observation.reached.ticks != at.retired
        || pending.vcpu_index() != 0
        || request.sequence() != sequence
        || request.selectable_id() != "flight.ready"
        || request.instance_key() != instance
        || request.reply_capacity() != 128
        || request.narrowed_domain().is_some()
    {
        return Err("clock-read barrier differs from the original declared request".into());
    }
    let calibration = node.logical_time_calibration()?;
    if calibration.logical_icount != at.retired {
        return Err(
            "clock-read original stop calibration differs from its authenticated boundary".into(),
        );
    }
    let boundary = Boundary {
        sequence,
        logical_ps: at.retired,
        raw_instructions: calibration.raw_icount,
        trap_ps: pending.trap_tick_ps(),
    };

    // Batch 0 must release into the Linux timer; the final batch is retained
    // until owned shutdown so the guest cannot publish unvalidated extras.
    if release || sequence == 3 {
        let reply = SelectionReply::rejected(
            sequence,
            SelectionReplyStatus::Unavailable,
            [0; 32],
            [0; 32],
        )?;
        node.enqueue_selectable_reply(pending, &reply)?;
    }
    Ok((events, boundary))
}

fn retained(events: &[ObservableEvent]) -> Vec<(u64, ObservableEventPayload)> {
    events
        .iter()
        .map(|event| (event.at().ticks, event.payload().clone()))
        .collect()
}

#[cfg(test)]
fn validate_batch(events: &[ObservableEvent], batch: u64) -> Result<Vec<ReadReceipt>, String> {
    validate_batch_mode(events, batch, false)
}

fn validate_batch_mode(
    events: &[ObservableEvent],
    batch: u64,
    runtime_anchor: bool,
) -> Result<Vec<ReadReceipt>, String> {
    if events.len() != CLOCKS.len() * 2 {
        return Err("clock-read batch must contain exactly four original read pairs".into());
    }
    let mut result = Vec::with_capacity(CLOCKS.len());
    for (index, clock) in CLOCKS.into_iter().enumerate() {
        let instance = format!("{batch}-{clock}");
        let (before_ps, before) = marker(&events[index * 2], BEFORE, &instance)?;
        let (after_ps, after) = marker(&events[index * 2 + 1], AFTER, &instance)?;
        if before.len() != 1
            || unsigned(before, 0, "cpu")? != 0
            || after.len() != if runtime_anchor { 6 } else { 5 }
            || unsigned(after, 0, "cpu")? != 0
            || before_ps >= after_ps
            || result
                .last()
                .is_some_and(|old: &ReadReceipt| old.after_ps >= before_ps)
        {
            return Err("clock-read pair order, CPU or original bracket is invalid".into());
        }
        let seconds = signed(after, 2, "seconds")?;
        let fraction = signed(after, 1, "fraction")?;
        let value = unsigned(after, 4, "value")?;
        let unit = match &after[3] {
            GuestSemanticMarkerDetail {
                key,
                value: GuestMeasurementValue::Enumerated(unit),
            } if key == "unit" => unit,
            _ => return Err("clock-read unit is not an original typed enumeration".into()),
        };
        let expected = match clock {
            "tsc" => "cycles",
            "gettimeofday" => "microseconds",
            _ => "nanoseconds",
        };
        if unit != expected {
            return Err("clock-read unit differs from the closed clock vocabulary".into());
        }
        if clock == "tsc" {
            let lower = value
                .checked_mul(250)
                .ok_or("TSC scale multiplication overflow")?;
            let upper = lower
                .checked_add(249)
                .ok_or("TSC scale interval overflow")?;
            if seconds != 0 || fraction != 0 || lower > after_ps || upper < before_ps {
                return Err(format!(
                    "original TSC read bracket refused: instance={instance} value={value} interval=[{lower},{upper}] original_ps=[{before_ps},{after_ps}]"
                ));
            }
        } else {
            let bound = if clock == "gettimeofday" {
                1_000_000
            } else {
                1_000_000_000
            };
            if seconds < 0 || !(0..bound).contains(&fraction) || value != 0 {
                return Err("Linux clock return is not a normalized original API tuple".into());
            }
        }
        let vvar = if runtime_anchor {
            match &after[5] {
                GuestSemanticMarkerDetail {
                    key,
                    value: GuestMeasurementValue::UnsignedVector(words),
                } if key == "vvar"
                    && words.len() == 16
                    && words[0] == 1
                    && words[1] & 1 == 0
                    && words[2] == 1
                    && words[14] < 16
                    && words[15] == words[1] =>
                {
                    Some(words.clone())
                }
                _ => return Err("published kernel runtime anchor is missing or unsupported".into()),
            }
        } else {
            None
        };
        result.push(ReadReceipt {
            instance,
            before_ps,
            after_ps,
            seconds,
            fraction,
            value,
            unit: unit.clone(),
            vvar,
        });
    }
    Ok(result)
}

// The legacy Icount-shaped semantic-marker field contains the logical ps
// coordinate in this public mapper, not raw architectural retirement.
fn marker<'a>(
    event: &'a ObservableEvent,
    expected: &str,
    expected_instance: &str,
) -> Result<(u64, &'a [GuestSemanticMarkerDetail]), String> {
    match event.payload() {
        ObservableEventPayload::GuestSemanticMarker {
            retired_icount,
            node,
            marker,
            instance,
            details,
        } if node.name == super::FLIGHT_NODE_ID
            && marker == expected
            && instance == expected_instance
            && retired_icount.retired == event.at().ticks =>
        {
            Ok((event.at().ticks, details))
        }
        _ => Err("clock-read event is not the original node's expected typed marker".into()),
    }
}

fn signed(details: &[GuestSemanticMarkerDetail], index: usize, name: &str) -> Result<i64, String> {
    match &details[index] {
        GuestSemanticMarkerDetail {
            key,
            value: GuestMeasurementValue::Signed(value),
        } if key == name => Ok(*value),
        _ => Err(format!("clock-read {name} is not an original signed value")),
    }
}

fn unsigned(
    details: &[GuestSemanticMarkerDetail],
    index: usize,
    name: &str,
) -> Result<u64, String> {
    match &details[index] {
        GuestSemanticMarkerDetail {
            key,
            value: GuestMeasurementValue::Unsigned(value),
        } if key == name => Ok(*value),
        _ => Err(format!(
            "clock-read {name} is not an original unsigned value"
        )),
    }
}

fn validate_forward_returns(reads: &[ReadReceipt]) -> Result<(), String> {
    if reads.len() != 8 {
        return Err("both original clock-read batches are required".into());
    }
    for index in 0..4 {
        let (first, second) = (&reads[index], &reads[index + 4]);
        if first.after_ps >= second.before_ps
            || (index == 3 && first.value >= second.value)
            || (index != 3 && (first.seconds, first.fraction) >= (second.seconds, second.fraction))
        {
            return Err(
                "guest clock returns did not advance across the authorized timer wake".into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "guest_clock_reads/tests.rs"]
mod tests;
