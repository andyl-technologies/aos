//! Proves the native RR control boundary for one real block completion.
//!
//! The flight boots the retained Linux block-write guest through the production
//! node-step stack, services its one write through an explicitly fault-free
//! coordinator, and retains QEMU's fixed RR transition trace after reap. The
//! block proof binds a distinct even-to-odd shared NodeSlot acknowledgement to
//! the visible sector bytes. Separately, the full native trace proves ordered
//! request/ack/complete generations and includes a completed wake-pending
//! request; its terminal generation is trace evidence, not the NodeSlot token.

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use crucible::{AdvanceOutcome, ObservableEventPayload, SimulationBackend, VirtualTime};
#[cfg(target_os = "linux")]
use crucible_device::block::{BaseImage, BlockDurabilityConfig};
#[cfg(target_os = "linux")]
use crucible_qemu::{
    LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory, QemuLiveNodeIdentity,
    QemuLiveNodeStepGateConfig, QemuNode, QemuProductionFreshLaunchAdmission,
    QemuRrControlBoundaryTracePhase, QemuRrControlBoundaryTraceRecord, QemuShutdownReport,
    QemuShutdownRung, launch_qemu_production_fresh_node, parse_qemu_rr_control_boundary_trace,
};

#[cfg(target_os = "linux")]
const DEVICE_BYTES: u64 = 4 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MEMORY_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(target_os = "linux")]
const WRITABLE_BYTES: u64 = 1024 * 1024 * 1024;
#[cfg(target_os = "linux")]
const COMPLETION_CEILING: u64 = 100_000_000_000;
#[cfg(target_os = "linux")]
const RR_SWITCH_QUANTUM: u64 = 4096;
#[cfg(target_os = "linux")]
const BLOCK_COMPLETE_MARKER: &[u8] = b"CRUCIBLE_BLOCK_WRITE_COMPLETE";

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-rr-control-boundary-device-flight: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn Error>> {
    let arguments = env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let [
        qemu,
        plugin,
        kernel,
        initrd,
        firmware,
        cgroup_root,
        run_root,
    ] = arguments.as_slice()
    else {
        return Err("expected QEMU PLUGIN KERNEL INITRD FIRMWARE CGROUP_ROOT RUN_ROOT".into());
    };

    let host = LinuxQemuAttemptHostConfig::new(
        cgroup_root,
        run_root,
        "rr-control-boundary-device-flight",
        24_000,
        1,
        65_534,
        65_534,
        32,
        RR_SWITCH_QUANTUM,
        Duration::from_secs(30),
    )?;
    let mut factory = LinuxQemuAttemptHostFactory::open(host)?;
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_root)
        .with_initrd(initrd)
        .with_vm_shape(128, 1)
        .with_rr_switch_quantum(RR_SWITCH_QUANTUM)
        .with_fault_free_shmem_block(
            BaseImage::new(vec![0; usize::try_from(DEVICE_BYTES)?]),
            BlockDurabilityConfig::write_through(DEVICE_BYTES),
        )
        .with_console_capture()
        .with_rr_control_boundary_trace()
        .with_completion_timeout(Duration::from_secs(60));

    let mut owner = factory.begin(1, MEMORY_BYTES, WRITABLE_BYTES)?;
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
                "rr-control-boundary-device-node",
                "rr-control-boundary-device-router",
                "rr-control-boundary-device-crash",
            ),
        )?,
    )?;
    let primary = exercise_block_completion(&mut node);
    let shutdown = node.shutdown_child().map_err(|error| error.to_string());
    drop(node);
    let proven_reap = matches!(&shutdown, Ok(report) if report.reaped && !report.leaked);
    let retained_trace = if proven_reap {
        directory
            .retain_rr_control_boundary_trace_after_reap()
            .map_err(|error| error.to_string())
    } else {
        Err(String::from(
            "trace unavailable because QEMU reap was not proven",
        ))
    };
    let native = retained_trace
        .as_ref()
        .map_err(ToString::to_string)
        .and_then(|trace| {
            parse_qemu_rr_control_boundary_trace(trace)
                .map_err(|error| error.to_string())
                .and_then(|records| {
                    authenticate_native_completions(&records).map_err(|error| error.to_string())
                })
        });
    drop(directory);
    let finish = owner.finish().map_err(|error| error.to_string());

    let mut errors = Vec::new();
    if let Err(error) = &primary {
        errors.push(format!("block-completion proof: {error}"));
    }
    match &shutdown {
        Ok(report) if shutdown_is_graceful(report) => {}
        Ok(report) => errors.push(format!("QEMU did not reap cleanly: {report:?}")),
        Err(error) => errors.push(format!("explicit shutdown/reap: {error}")),
    }
    if let Err(error) = &retained_trace {
        errors.push(format!("trace retention: {error}"));
    }
    if let Err(error) = &native {
        errors.push(format!("native trace authentication: {error}"));
    }
    if let Err(error) = &finish {
        errors.push(format!("attempt-owner finish: {error}"));
    }
    if !errors.is_empty() {
        if let Ok(trace) = &retained_trace {
            errors.push(format!("retained native RR trace:\n{trace}"));
        }
        return Err(errors.join("\n").into());
    }

    let block = primary.map_err(|error| error.to_string())?;
    let native = native.map_err(|error| error.to_string())?;

    println!("PASS");
    println!("gate=gate:rr-control-boundary-device-flight");
    println!("block_request_frames={}", block.frames_processed);
    println!("block_write_frames={}", block.write_frames_processed);
    println!("block_completion_frames={}", block.frames_delivered);
    println!("node_slot_control_request={}", block.control_token);
    println!("node_slot_control_ack={}", block.control_token + 1);
    println!("node_slot_control_request_derived=true");
    println!("native_request_generation={}", native.request.request);
    println!("native_schedule_token={}", native.complete.schedule_token);
    println!("native_terminal_request_state={}", native.request.state);
    println!("native_terminal_ack_state={}", native.ack.state);
    println!("native_terminal_complete_state={}", native.complete.state);
    println!("native_completed_wake_pending_request=true");
    println!("native_ack_complete_state_contract=true");
    println!(
        "native_shutdown_suffix={}",
        if native.shutdown_canceled {
            "cancel"
        } else {
            "none"
        }
    );
    println!("native_lifecycle_trace_exact=true");
    println!("native_control_sequence_exact=true");
    println!("trace_retained_after_reap=true");
    println!("visible_guest_write_exact=true");
    Ok(())
}

#[cfg(target_os = "linux")]
fn shutdown_is_graceful(report: &QemuShutdownReport) -> bool {
    report.reaped
        && !report.leaked
        && report.failures.is_empty()
        && report.attempts.iter().all(|attempt| {
            !matches!(
                attempt.rung,
                QemuShutdownRung::Sigterm | QemuShutdownRung::Sigkill
            )
        })
}

#[cfg(target_os = "linux")]
fn exercise_block_completion(
    node: &mut QemuNode,
) -> Result<AuthenticatedBlockCompletion, Box<dyn Error>> {
    let settled_time = node.now();
    let settled = SimulationBackend::step_to(&mut *node, settled_time)?;
    if settled.reached != settled_time {
        return Err(format!("same-coordinate baseline did not remain settled: {settled:?}").into());
    }
    let priming_events = SimulationBackend::drain_observable_events(&mut *node)?;
    if priming_events.iter().any(|event| {
        matches!(
            event.payload(),
            ObservableEventPayload::ConsoleOutput { bytes, .. }
                if bytes.windows(BLOCK_COMPLETE_MARKER.len()).any(|window| window == BLOCK_COMPLETE_MARKER)
        )
    }) {
        return Err("block completion was already visible at the measurement baseline".into());
    }
    let baseline = node
        .block_io_diagnostics()
        .ok_or("live block diagnostics were not installed")?;
    if baseline.frames_processed != 0
        || baseline.write_frames_processed != 0
        || baseline.frames_delivered != 0
        || baseline.last_device_io_active
        || baseline.last_active_control_boundary_ack.is_some()
        || baseline.last_control_boundary_ack & 1 == 0
    {
        return Err(format!("block baseline was not settled and empty: {baseline:?}").into());
    }

    let observation = SimulationBackend::step_to(
        node,
        VirtualTime {
            ticks: COMPLETION_CEILING,
        },
    );
    let observation = match observation {
        Ok(observation) => observation,
        Err(source) => {
            let diagnostics = node.block_io_diagnostics();
            let console = SimulationBackend::drain_observable_events(node)
                .map(|events| {
                    events
                        .iter()
                        .filter_map(|event| match event.payload() {
                            ObservableEventPayload::ConsoleOutput { bytes, .. } => {
                                Some(bytes.as_slice())
                            }
                            _ => None,
                        })
                        .flat_map(|bytes| bytes.iter().copied())
                        .collect::<Vec<_>>()
                })
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
            return Err(format!(
                "block write advance failed: source={source}; diagnostics={diagnostics:?}; console={console:?}"
            )
            .into());
        }
    };
    if observation.requested_ceiling.ticks != COMPLETION_CEILING
        || observation.reached.ticks <= settled_time.ticks
        || observation.reached.ticks >= COMPLETION_CEILING
        || !matches!(
            observation.outcome,
            AdvanceOutcome::Paused { at } if at.retired == observation.reached.ticks
        )
    {
        return Err(format!(
            "block flight did not return one exact completed pause: baseline={baseline:?}, observation={observation:?}"
        )
        .into());
    }
    let events = SimulationBackend::drain_observable_events(node)?;
    let marker_count = events
        .iter()
        .filter_map(|event| match event.payload() {
            ObservableEventPayload::ConsoleOutput { bytes, .. } => Some(bytes.as_slice()),
            _ => None,
        })
        .flat_map(|bytes| bytes.iter().copied())
        .collect::<Vec<_>>()
        .windows(BLOCK_COMPLETE_MARKER.len())
        .filter(|window| *window == BLOCK_COMPLETE_MARKER)
        .count();
    if marker_count != 1 {
        return Err(format!(
            "guest block-write completion marker cardinality was {marker_count}, expected 1"
        )
        .into());
    }

    let final_diagnostics = node
        .block_io_diagnostics()
        .ok_or("live block diagnostics disappeared")?;
    if final_diagnostics.last_current_icount != observation.reached.ticks
        || final_diagnostics.max_current_icount != observation.reached.ticks
        || final_diagnostics.last_device_io_active
    {
        return Err(format!(
            "block completion did not settle at the returned pause: observation={observation:?}, diagnostics={final_diagnostics:?}"
        )
        .into());
    }
    let control_token = authenticate_block_completion(baseline, final_diagnostics)?;
    let device = node
        .shared_block_device()
        .ok_or("live block device disappeared")?;
    let visible = device.inspect_storage_visible(0, 512)?;
    let expected = (0..512)
        .map(|index| (index as u8) ^ 0x37)
        .collect::<Vec<_>>();
    if visible != expected {
        return Err("visible block bytes differ from the guest write".into());
    }
    Ok(control_token)
}

#[cfg(target_os = "linux")]
fn authenticate_block_completion(
    baseline: crucible_qemu::BlockIoDiagnosticsSnapshot,
    final_state: crucible_qemu::BlockIoDiagnosticsSnapshot,
) -> Result<AuthenticatedBlockCompletion, Box<dyn Error>> {
    let frames_processed = final_state
        .frames_processed
        .checked_sub(baseline.frames_processed)
        .ok_or("block request count regressed")?;
    let write_frames_processed = final_state
        .write_frames_processed
        .checked_sub(baseline.write_frames_processed)
        .ok_or("block write count regressed")?;
    let frames_delivered = final_state
        .frames_delivered
        .checked_sub(baseline.frames_delivered)
        .ok_or("block completion count regressed")?;
    if frames_processed == 0 || write_frames_processed != 1 || frames_delivered != frames_processed
    {
        return Err(format!(
            "block completion cardinality changed unexpectedly: baseline={baseline:?}, final={final_state:?}"
        )
        .into());
    }
    let request = baseline.last_control_boundary_ack.wrapping_add(1);
    if baseline.last_control_boundary_ack == 0
        || baseline.last_control_boundary_ack & 1 == 0
        || request == 0
        || request & 1 != 0
        || final_state.last_control_boundary_ack
            != baseline.last_control_boundary_ack.wrapping_add(2)
        || final_state
            .last_active_control_boundary_ack
            .is_some_and(|observed| observed != request)
    {
        return Err(format!(
            "NodeSlot control acknowledgement is not exact: baseline={baseline:?}, final={final_state:?}"
        )
        .into());
    }
    Ok(AuthenticatedBlockCompletion {
        frames_processed,
        write_frames_processed,
        frames_delivered,
        control_token: request,
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct AuthenticatedBlockCompletion {
    frames_processed: usize,
    write_frames_processed: usize,
    frames_delivered: usize,
    control_token: u32,
}

#[cfg(target_os = "linux")]
fn authenticate_native_completions(
    records: &[QemuRrControlBoundaryTraceRecord],
) -> Result<AuthenticatedNativeCompletion, Box<dyn Error>> {
    let mut request_generation = 0_u64;
    let mut ack_generation = 0_u64;
    let mut complete_generation = 0_u64;
    let mut requests = Vec::new();
    let mut active_ack = None;
    let mut active_token_released = false;
    let mut terminal = None;
    let mut completed_pending_request = false;
    let mut shutdown_canceled = false;
    let mut last_completed_schedule_token = 0;

    for (index, record) in records
        .iter()
        .copied()
        .filter(|record| {
            matches!(
                record.phase,
                QemuRrControlBoundaryTracePhase::Request
                    | QemuRrControlBoundaryTracePhase::Ack
                    | QemuRrControlBoundaryTracePhase::Complete
                    | QemuRrControlBoundaryTracePhase::Cancel
            )
        })
        .enumerate()
    {
        if shutdown_canceled {
            return Err("native cancellation was not the terminal trace row".into());
        }

        match record.phase {
            QemuRrControlBoundaryTracePhase::Request => {
                let next_request = request_generation
                    .checked_add(1)
                    .ok_or("native request generation overflowed")?;
                let startup_request = index == 0
                    && next_request == 1
                    && record.request == 1
                    && record.ack == 0
                    && record.complete == 0
                    && record.schedule_token == 0
                    && matches!(record.state, 0 | 1);
                let token_is_valid = if ack_generation == complete_generation {
                    record.schedule_token == 0
                } else if Some(ack_generation) == complete_generation.checked_add(1) {
                    let acknowledged_token = active_ack
                        .as_ref()
                        .map(|ack: &QemuRrControlBoundaryTraceRecord| ack.schedule_token)
                        .ok_or("native request observed an unowned acknowledged generation")?;
                    record.schedule_token == 0 || record.schedule_token == acknowledged_token
                } else {
                    return Err("native request exceeded the bounded generation frontier".into());
                };
                if request_generation != ack_generation
                    || record.request != next_request
                    || record.ack != ack_generation
                    || record.complete != complete_generation
                    || !token_is_valid
                    || !(startup_request || matches!(record.state, 2..=6))
                {
                    return Err(format!(
                        "native trace row {} has an invalid request transition: {record:?}",
                        index + 1
                    )
                    .into());
                }

                request_generation = next_request;
                requests.push(record);
                if active_ack.is_some() && record.schedule_token == 0 {
                    active_token_released = true;
                }
            }
            QemuRrControlBoundaryTracePhase::Ack => {
                let expected_request = ack_generation
                    .checked_add(1)
                    .ok_or("native acknowledgement generation overflowed")?;
                if request_generation != expected_request
                    || ack_generation != complete_generation
                    || active_ack.is_some()
                    || record.request != request_generation
                    || record.ack != request_generation
                    || record.complete != complete_generation
                    || record.schedule_token == 0
                    || record.schedule_token <= last_completed_schedule_token
                    || !matches!(record.state, 2 | 4 | 5)
                {
                    return Err(format!(
                        "native trace row {} has an invalid acknowledgement transition: {record:?}",
                        index + 1
                    )
                    .into());
                }

                ack_generation = request_generation;
                active_ack = Some(record);
                active_token_released = false;
            }
            QemuRrControlBoundaryTracePhase::Complete => {
                let expected_ack = complete_generation
                    .checked_add(1)
                    .ok_or("native completion generation overflowed")?;
                let acknowledged =
                    active_ack.ok_or("native completion had no active acknowledgement")?;
                let request_is_current_or_nested = request_generation == ack_generation
                    || Some(request_generation) == ack_generation.checked_add(1);
                if ack_generation != expected_ack
                    || !request_is_current_or_nested
                    || record.request != request_generation
                    || record.ack != ack_generation
                    || record.complete != ack_generation
                    || record.schedule_token < acknowledged.schedule_token
                    || (active_token_released
                        && record.schedule_token == acknowledged.schedule_token)
                    || !matches!(record.state, 2 | 4 | 5)
                {
                    return Err(format!(
                        "native trace row {} has an invalid completion transition: {record:?}",
                        index + 1
                    )
                    .into());
                }

                let request_index = usize::try_from(ack_generation - 1)?;
                let request = *requests
                    .get(request_index)
                    .ok_or("native completion referenced an absent request")?;
                completed_pending_request |= request.state == 5;
                terminal = Some(AuthenticatedNativeCompletion {
                    request,
                    ack: acknowledged,
                    complete: record,
                    shutdown_canceled: false,
                });
                complete_generation = ack_generation;
                last_completed_schedule_token = record.schedule_token;
                active_ack = None;
                active_token_released = false;
            }
            QemuRrControlBoundaryTracePhase::Cancel => {
                let token_is_valid =
                    active_ack
                        .as_ref()
                        .map_or(record.schedule_token == 0, |ack| {
                            record.schedule_token == 0
                                || (!active_token_released
                                    && record.schedule_token == ack.schedule_token)
                        });
                if request_generation <= complete_generation
                    || record.request != request_generation
                    || record.ack != request_generation
                    || record.complete != request_generation
                    || !token_is_valid
                    || record.state > 6
                {
                    return Err(format!(
                        "native trace row {} has an invalid lifecycle cancellation: {record:?}",
                        index + 1
                    )
                    .into());
                }
                shutdown_canceled = true;
            }
            _ => continue,
        }
    }

    if !shutdown_canceled
        && (request_generation != ack_generation
            || ack_generation != complete_generation
            || active_ack.is_some()
            || active_token_released)
    {
        return Err("native trace ended with an unmarked incomplete generation".into());
    }

    if !completed_pending_request {
        return Err("native trace never completed a request published from WAKE_PENDING".into());
    }
    let mut terminal = terminal.ok_or_else(|| {
        Box::<dyn Error>::from("native control trace contained no completed generation")
    })?;
    terminal.shutdown_canceled = shutdown_canceled;
    Ok(terminal)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct AuthenticatedNativeCompletion {
    request: QemuRrControlBoundaryTraceRecord,
    ack: QemuRrControlBoundaryTraceRecord,
    complete: QemuRrControlBoundaryTraceRecord,
    shutdown_canceled: bool,
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    const COMPLETE_AND_CANCEL: &str = "crucible_sim_rr_control_boundary phase=request request=1 ack=0 complete=0 token=0x0 state=5\ncrucible_sim_rr_control_boundary phase=ack request=1 ack=1 complete=0 token=0x1 state=5\ncrucible_sim_rr_control_boundary phase=complete request=1 ack=1 complete=1 token=0x1 state=5\ncrucible_sim_rr_control_boundary phase=request request=2 ack=1 complete=1 token=0x0 state=2\ncrucible_sim_rr_control_boundary phase=cancel request=2 ack=2 complete=2 token=0x0 state=2\n";
    const NESTED_COMPLETIONS: &str = "crucible_sim_rr_control_boundary phase=request request=1 ack=0 complete=0 token=0x0 state=5\ncrucible_sim_rr_control_boundary phase=ack request=1 ack=1 complete=0 token=0x1 state=2\ncrucible_sim_rr_control_boundary phase=request request=2 ack=1 complete=0 token=0x1 state=5\ncrucible_sim_rr_control_boundary phase=complete request=2 ack=1 complete=1 token=0x1 state=4\ncrucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x2 state=5\ncrucible_sim_rr_control_boundary phase=complete request=2 ack=2 complete=2 token=0x2 state=2\n";

    #[test]
    fn native_automaton_accepts_complete_pending_request_and_shutdown_cancel() {
        let records = parse_qemu_rr_control_boundary_trace(COMPLETE_AND_CANCEL)
            .unwrap_or_else(|error| panic!("fixture trace should parse: {error}"));
        let terminal = authenticate_native_completions(&records)
            .unwrap_or_else(|error| panic!("fixture trace should authenticate: {error}"));

        assert_eq!(terminal.complete.request, 1);
        assert_eq!(terminal.complete.schedule_token, 1);
        assert!(terminal.shutdown_canceled);
    }

    #[test]
    fn native_automaton_accepts_complete_stream_without_cancel_suffix() {
        let trace = COMPLETE_AND_CANCEL
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let records = parse_qemu_rr_control_boundary_trace(&trace)
            .unwrap_or_else(|error| panic!("complete trace should parse: {error}"));
        let terminal = authenticate_native_completions(&records)
            .unwrap_or_else(|error| panic!("complete trace should authenticate: {error}"));

        assert_eq!(terminal.complete.request, 1);
        assert!(!terminal.shutdown_canceled);
    }

    #[test]
    fn native_automaton_accepts_acknowledged_shutdown_cancel() {
        let trace = COMPLETE_AND_CANCEL.replace(
            "crucible_sim_rr_control_boundary phase=cancel request=2 ack=2 complete=2 token=0x0 state=2\n",
            "crucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x2 state=5\ncrucible_sim_rr_control_boundary phase=cancel request=2 ack=2 complete=2 token=0x2 state=5\n",
        );
        let records = parse_qemu_rr_control_boundary_trace(&trace)
            .unwrap_or_else(|error| panic!("acknowledged cancel trace should parse: {error}"));
        let terminal = authenticate_native_completions(&records)
            .unwrap_or_else(|error| panic!("acknowledged cancel should authenticate: {error}"));

        assert_eq!(terminal.complete.request, 1);
        assert!(terminal.shutdown_canceled);

        let cleared_token = trace.replace(
            "phase=cancel request=2 ack=2 complete=2 token=0x2",
            "phase=cancel request=2 ack=2 complete=2 token=0x0",
        );
        let records =
            parse_qemu_rr_control_boundary_trace(&cleared_token).unwrap_or_else(|error| {
                panic!("cleared-token acknowledged cancel should parse: {error}")
            });
        assert!(authenticate_native_completions(&records).is_ok());
    }

    #[test]
    fn native_automaton_accepts_request_nested_between_ack_and_complete() {
        let records = parse_qemu_rr_control_boundary_trace(NESTED_COMPLETIONS)
            .unwrap_or_else(|error| panic!("nested trace should parse: {error}"));
        let terminal = authenticate_native_completions(&records)
            .unwrap_or_else(|error| panic!("nested trace should authenticate: {error}"));

        assert_eq!(terminal.request.request, 2);
        assert_eq!(terminal.ack.schedule_token, 2);
        assert_eq!(terminal.complete.schedule_token, 2);
        assert!(!terminal.shutdown_canceled);
    }

    #[test]
    fn native_automaton_accepts_deferred_completion_and_cleared_nested_token() {
        let trace = "crucible_sim_rr_control_boundary phase=request request=1 ack=0 complete=0 token=0x0 state=5\ncrucible_sim_rr_control_boundary phase=ack request=1 ack=1 complete=0 token=0x1 state=2\ncrucible_sim_rr_control_boundary phase=request request=2 ack=1 complete=0 token=0x0 state=5\ncrucible_sim_rr_control_boundary phase=complete request=2 ack=1 complete=1 token=0x2 state=4\ncrucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x3 state=5\ncrucible_sim_rr_control_boundary phase=complete request=2 ack=2 complete=2 token=0x4 state=2\n";
        let records = parse_qemu_rr_control_boundary_trace(trace)
            .unwrap_or_else(|error| panic!("deferred trace should parse: {error}"));
        let terminal = authenticate_native_completions(&records)
            .unwrap_or_else(|error| panic!("deferred trace should authenticate: {error}"));

        assert_eq!(terminal.ack.schedule_token, 3);
        assert_eq!(terminal.complete.schedule_token, 4);
        assert!(!terminal.shutdown_canceled);
    }

    #[test]
    fn native_automaton_accepts_nested_request_canceled_with_active_token() {
        let completed_pending = COMPLETE_AND_CANCEL
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n");
        let trace = format!(
            "{completed_pending}\ncrucible_sim_rr_control_boundary phase=request request=2 ack=1 complete=1 token=0x0 state=2\ncrucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x2 state=5\ncrucible_sim_rr_control_boundary phase=request request=3 ack=2 complete=1 token=0x2 state=5\ncrucible_sim_rr_control_boundary phase=cancel request=3 ack=3 complete=3 token=0x2 state=2\n"
        );
        let records = parse_qemu_rr_control_boundary_trace(&trace)
            .unwrap_or_else(|error| panic!("nested cancel trace should parse: {error}"));
        let terminal = authenticate_native_completions(&records)
            .unwrap_or_else(|error| panic!("nested cancel should authenticate: {error}"));

        assert_eq!(terminal.complete.complete, 1);
        assert!(terminal.shutdown_canceled);

        let cleared_token = trace.replace(
            "phase=cancel request=3 ack=3 complete=3 token=0x2",
            "phase=cancel request=3 ack=3 complete=3 token=0x0",
        );
        let records = parse_qemu_rr_control_boundary_trace(&cleared_token)
            .unwrap_or_else(|error| panic!("cleared-token nested cancel should parse: {error}"));
        assert!(authenticate_native_completions(&records).is_ok());

        let released_before_nested_request = cleared_token.replace(
            "phase=request request=3 ack=2 complete=1 token=0x2",
            "phase=request request=3 ack=2 complete=1 token=0x0",
        );
        let records = parse_qemu_rr_control_boundary_trace(&released_before_nested_request)
            .unwrap_or_else(|error| panic!("released nested cancel should parse: {error}"));
        assert!(authenticate_native_completions(&records).is_ok());

        let token_reappeared = released_before_nested_request.replace(
            "phase=cancel request=3 ack=3 complete=3 token=0x0",
            "phase=cancel request=3 ack=3 complete=3 token=0x2",
        );
        let records = parse_qemu_rr_control_boundary_trace(&token_reappeared)
            .unwrap_or_else(|error| panic!("reappearing-token cancel should parse: {error}"));
        assert!(authenticate_native_completions(&records).is_err());

        let wrong_token = trace.replace(
            "phase=cancel request=3 ack=3 complete=3 token=0x2",
            "phase=cancel request=3 ack=3 complete=3 token=0x3",
        );
        let records = parse_qemu_rr_control_boundary_trace(&wrong_token)
            .unwrap_or_else(|error| panic!("wrong-token nested cancel should parse: {error}"));
        assert!(authenticate_native_completions(&records).is_err());
    }

    #[test]
    fn native_automaton_accepts_independent_settled_and_wake_arming_trace_states() {
        let completed_pending = COMPLETE_AND_CANCEL
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n");
        for (request_state, ack_state, complete_state) in [(4, 2, 4), (2, 4, 5), (6, 5, 2)] {
            let trace = format!(
                "{completed_pending}\ncrucible_sim_rr_control_boundary phase=request request=2 ack=1 complete=1 token=0x0 state={request_state}\ncrucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x2 state={ack_state}\ncrucible_sim_rr_control_boundary phase=complete request=2 ack=2 complete=2 token=0x2 state={complete_state}\n"
            );
            let records = parse_qemu_rr_control_boundary_trace(&trace)
                .unwrap_or_else(|error| panic!("mixed-state fixture should parse: {error}"));
            let terminal = authenticate_native_completions(&records)
                .unwrap_or_else(|error| panic!("mixed-state fixture should authenticate: {error}"));

            assert_eq!(terminal.complete.request, 2);
            assert_eq!(terminal.ack.state, ack_state);
            assert_eq!(terminal.complete.state, complete_state);
        }

        for request_state in [0, 1] {
            let trace = format!(
                "{completed_pending}\ncrucible_sim_rr_control_boundary phase=request request=2 ack=1 complete=1 token=0x0 state={request_state}\ncrucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x2 state=2\ncrucible_sim_rr_control_boundary phase=complete request=2 ack=2 complete=2 token=0x2 state=2\n"
            );
            let records = parse_qemu_rr_control_boundary_trace(&trace)
                .unwrap_or_else(|error| panic!("startup-state fixture should parse: {error}"));

            assert!(authenticate_native_completions(&records).is_err());
        }
    }

    #[test]
    fn native_automaton_accepts_only_exact_startup_request_states() {
        for startup_state in [0, 1] {
            let trace = format!(
                "crucible_sim_rr_control_boundary phase=request request=1 ack=0 complete=0 token=0x0 state={startup_state}\ncrucible_sim_rr_control_boundary phase=ack request=1 ack=1 complete=0 token=0x1 state=2\ncrucible_sim_rr_control_boundary phase=complete request=1 ack=1 complete=1 token=0x1 state=2\ncrucible_sim_rr_control_boundary phase=request request=2 ack=1 complete=1 token=0x0 state=5\ncrucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x2 state=2\ncrucible_sim_rr_control_boundary phase=complete request=2 ack=2 complete=2 token=0x2 state=2\n"
            );
            let records = parse_qemu_rr_control_boundary_trace(&trace)
                .unwrap_or_else(|error| panic!("startup trace should parse: {error}"));
            let terminal = authenticate_native_completions(&records)
                .unwrap_or_else(|error| panic!("startup trace should authenticate: {error}"));

            assert_eq!(terminal.complete.request, 2);

            let malformed = trace.replacen("token=0x0", "token=0x1", 1);
            let records = parse_qemu_rr_control_boundary_trace(&malformed)
                .unwrap_or_else(|error| panic!("malformed startup trace should parse: {error}"));
            assert!(authenticate_native_completions(&records).is_err());
        }
    }

    #[test]
    fn native_automaton_rejects_unmarked_or_invalid_lifecycle_endings() {
        for trace in [
            COMPLETE_AND_CANCEL.replace("phase=cancel", "phase=complete"),
            COMPLETE_AND_CANCEL.replace("request=2 ack=1", "request=3 ack=1"),
            COMPLETE_AND_CANCEL.replace("token=0x1 state=5", "token=0x1 state=3"),
            COMPLETE_AND_CANCEL.replacen(
                "phase=complete request=1 ack=1 complete=1 token=0x1 state=5",
                "phase=complete request=1 ack=1 complete=1 token=0x1 state=3",
                1,
            ),
            COMPLETE_AND_CANCEL.replace("phase=request request=1", "phase=request request=1")
                + "crucible_sim_rr_control_boundary phase=request request=3 ack=2 complete=2 token=0x0 state=2\n",
        ] {
            let records = parse_qemu_rr_control_boundary_trace(&trace).unwrap_or_else(|error| {
                panic!("malformed lifecycle fixture should parse: {error}")
            });
            assert!(authenticate_native_completions(&records).is_err());
        }
    }

    #[test]
    fn native_automaton_rejects_reused_or_decreasing_schedule_tokens() {
        let first = COMPLETE_AND_CANCEL
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n");
        let second = "crucible_sim_rr_control_boundary phase=request request=2 ack=1 complete=1 token=0x0 state=5\ncrucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x1 state=5\ncrucible_sim_rr_control_boundary phase=complete request=2 ack=2 complete=2 token=0x1 state=5\n";
        let reused = format!("{first}\n{second}");
        let records = parse_qemu_rr_control_boundary_trace(&reused)
            .unwrap_or_else(|error| panic!("reused-token fixture should parse: {error}"));
        assert!(authenticate_native_completions(&records).is_err());

        let first = first.replace("token=0x1", "token=0x2");
        let decreasing = format!("{first}\n{second}");
        let records = parse_qemu_rr_control_boundary_trace(&decreasing)
            .unwrap_or_else(|error| panic!("decreasing-token fixture should parse: {error}"));
        assert!(authenticate_native_completions(&records).is_err());
    }

    #[test]
    fn native_automaton_rejects_invalid_nested_generation_transitions() {
        let bad_nested_token = NESTED_COMPLETIONS.replacen(
            "phase=request request=2 ack=1 complete=0 token=0x1",
            "phase=request request=2 ack=1 complete=0 token=0x0",
            1,
        );
        let stale_complete_request = NESTED_COMPLETIONS.replacen(
            "phase=complete request=2 ack=1 complete=1 token=0x1",
            "phase=complete request=1 ack=1 complete=1 token=0x1",
            1,
        );
        let request_before_ack = NESTED_COMPLETIONS.replacen(
            "phase=ack request=1 ack=1 complete=0 token=0x1 state=2\ncrucible_sim_rr_control_boundary phase=request request=2 ack=1 complete=0 token=0x1 state=5",
            "phase=request request=2 ack=0 complete=0 token=0x0 state=5\ncrucible_sim_rr_control_boundary phase=ack request=1 ack=1 complete=0 token=0x1 state=2",
            1,
        );

        for trace in [bad_nested_token, stale_complete_request, request_before_ack] {
            let records = parse_qemu_rr_control_boundary_trace(&trace)
                .unwrap_or_else(|error| panic!("invalid nested trace should parse: {error}"));
            assert!(authenticate_native_completions(&records).is_err());
        }
    }

    #[test]
    fn native_automaton_rejects_invalid_deferred_token_transitions() {
        let complete_before_ack = "crucible_sim_rr_control_boundary phase=request request=1 ack=0 complete=0 token=0x0 state=5\ncrucible_sim_rr_control_boundary phase=ack request=1 ack=1 complete=0 token=0x2 state=2\ncrucible_sim_rr_control_boundary phase=complete request=1 ack=1 complete=1 token=0x1 state=2\n";
        let next_ack_before_completion_epoch = "crucible_sim_rr_control_boundary phase=request request=1 ack=0 complete=0 token=0x0 state=5\ncrucible_sim_rr_control_boundary phase=ack request=1 ack=1 complete=0 token=0x1 state=2\ncrucible_sim_rr_control_boundary phase=complete request=1 ack=1 complete=1 token=0x3 state=2\ncrucible_sim_rr_control_boundary phase=request request=2 ack=1 complete=1 token=0x0 state=5\ncrucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x2 state=2\ncrucible_sim_rr_control_boundary phase=complete request=2 ack=2 complete=2 token=0x3 state=2\n";
        let arbitrary_nested_token = NESTED_COMPLETIONS.replacen(
            "phase=request request=2 ack=1 complete=0 token=0x1",
            "phase=request request=2 ack=1 complete=0 token=0x2",
            1,
        );
        let request_only_token = COMPLETE_AND_CANCEL.replacen(
            "phase=request request=2 ack=1 complete=1 token=0x0",
            "phase=request request=2 ack=1 complete=1 token=0x2",
            1,
        );

        for trace in [
            complete_before_ack.to_owned(),
            next_ack_before_completion_epoch.to_owned(),
            arbitrary_nested_token,
            request_only_token,
        ] {
            let records = parse_qemu_rr_control_boundary_trace(&trace)
                .unwrap_or_else(|error| panic!("invalid deferred trace should parse: {error}"));
            assert!(authenticate_native_completions(&records).is_err());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-rr-control-boundary-device-flight requires Linux");
}
