//! Actual child supervision while the mapped quantum origin is unavailable.

#![cfg(test)]

use super::publication_access::MappedPublication;
use super::*;
use crate::{QemuAsyncCrashEscalationTarget, QemuAsyncNodeStepTarget, QemuShmemHotPathChannel};
use std::io::{Read, Write};
use std::process::{Command, Stdio};

struct OwnedMappedTarget {
    child: crate::QemuNodeChild,
    channel: crate::QemuMappedQuantumShmemHotPath,
    starts: usize,
    published: usize,
    finishes: usize,
}

impl QemuAsyncCrashEscalationTarget for OwnedMappedTarget {
    fn shutdown_after_crash(
        &mut self,
    ) -> Result<crate::QemuShutdownReport, crate::QemuAsyncDriverTargetError> {
        self.child
            .force_kill_and_reap_failed_helper(Duration::from_secs(1))
            .map_err(|error| {
                crate::QemuAsyncDriverTargetError::new(
                    "reap mapped owner fixture",
                    error.to_string(),
                )
            })?;
        Ok(crate::QemuShutdownReport {
            attempts: Vec::new(),
            failures: Vec::new(),
            reaped: self.child.reaped(),
            leaked: !self.child.reaped(),
        })
    }
}

impl QemuAsyncNodeStepTarget for OwnedMappedTarget {
    type PendingQuantum = crate::QemuNodePendingQuantum;

    fn child_exit_status(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, crate::QemuAsyncDriverTargetError> {
        self.child.try_wait_natural_exit().map_err(|error| {
            crate::QemuAsyncDriverTargetError::new("poll mapped owner fixture", error.to_string())
        })
    }

    fn start_quantum(
        &mut self,
        horizon: crucible::ExecutionHorizon,
    ) -> Result<Self::PendingQuantum, crate::QemuNodeChannelError> {
        self.starts += 1;
        let pending = self
            .channel
            .start_quantum(horizon, crate::QemuQuantumStopCondition::Ceiling)?;
        self.published += 1;
        Ok(pending)
    }

    fn advance_initial_state(
        &self,
        pending: &Self::PendingQuantum,
    ) -> Option<crate::QemuNodeIdleState> {
        pending.initial_state()
    }

    fn finish_quantum(
        &mut self,
        pending: &mut Self::PendingQuantum,
    ) -> Result<crate::QemuAsyncQuantumCompletion, crate::QemuNodeChannelError> {
        self.finishes += 1;
        self.channel.poll_quantum(pending)
    }

    fn retain_completed_quantum_boundary(
        &mut self,
        pending: &mut Self::PendingQuantum,
        boundary: Option<crate::QemuCompletedQuantumBoundary>,
    ) -> Result<(), crate::QemuNodeChannelError> {
        pending.completed_boundary = boundary;
        Ok(())
    }
}

fn owner_fixture(
    channel: crate::QemuMappedQuantumShmemHotPath,
) -> Result<(OwnedMappedTarget, std::process::ChildStdin), Box<dyn std::error::Error>> {
    // The pinned AOS Bash child has only builtins and no descendant processes.
    let mut child = Command::new("bash")
        .args(["-c", "printf R; IFS= read -r release; exit 1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let input = child.stdin.take().ok_or("owned input missing")?;
    let mut output = child.stdout.take().ok_or("owned output missing")?;
    let child = crate::QemuNodeChild::new(child);
    let mut ready = [0];
    output.read_exact(&mut ready)?;
    assert_eq!(ready, *b"R");
    Ok((
        OwnedMappedTarget {
            child,
            channel,
            starts: 0,
            published: 0,
            finishes: 0,
        },
        input,
    ))
}

#[test]
fn actual_owned_exit_is_observed_before_and_after_quantum_publication()
-> Result<(), Box<dyn std::error::Error>> {
    for after_start in [false, true] {
        let mapped = MappedPublication::new()?;
        let before = mapped.producer.node_slot(0)?.snapshot();
        if !after_start {
            mapped.set_producer_sequence(before.publish_gen + 1)?;
        }
        let MappedPublication {
            file,
            layout,
            producer,
            channel,
            mut runtime,
            ..
        } = mapped;
        let (mut target, mut release) = owner_fixture(channel)?;
        release.write_all(b"exit\n")?;
        let budget = Duration::from_secs(5);
        let policy = crate::QemuAsyncDriverPolicy::new(budget, budget, budget, budget);
        let report = crate::async_driver::run_bounded_qemu_node_step_with_start_hook(
            &mut target,
            &mut runtime,
            policy,
            &crate::QemuCrashDetector::new("mapped-owner"),
            MappedPublication::horizon(),
            |_target, _pending| {
                // The alternate case interrupts the same mapped publisher
                // after the real channel has issued its one scheduler ceiling.
                use std::os::unix::fs::FileExt;
                file.write_all_at(
                    &(before.publish_gen + 1).to_ne_bytes(),
                    layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64,
                )
                .map_err(|error| {
                    crate::QemuNodeChannelError::new(
                        "interrupt mapped fixture publisher",
                        error.to_string(),
                    )
                })
            },
        )?;
        let crate::QemuAsyncNodeStepOutcome::Crashed {
            status: crate::QemuNodeRunStatus::Crashed(status),
            shutdown,
        } = report.outcome
        else {
            panic!("odd publication must not forge a boundary");
        };
        assert!(
            matches!(status.cause, crate::QemuCrashCause::UnexpectedChildExit(ref exit) if exit.code == Some(1) && !exit.success)
        );
        assert!(shutdown.reaped && !shutdown.leaked && target.child.reaped());
        assert_eq!(target.published, usize::from(after_start));
        assert_eq!(target.finishes, 0);
        assert!(report.final_state.is_none() && report.completed_boundary.is_none());
        assert!(producer.node_slot(0)?.try_snapshot().is_none());
    }
    Ok(())
}

#[test]
fn unavailable_initial_origin_expires_original_budget_without_a_run()
-> Result<(), Box<dyn std::error::Error>> {
    let mapped = MappedPublication::new()?;
    let before = mapped.producer.node_slot(0)?.snapshot();
    mapped.set_scheduler_sequence(1)?;
    let MappedPublication {
        file,
        layout,
        producer,
        channel,
        mut runtime,
        ..
    } = mapped;
    let (mut target, _hold_open) = owner_fixture(channel)?;
    let budget = Duration::from_millis(200);
    let policy = crate::QemuAsyncDriverPolicy::new(budget, budget, budget, budget);

    let report = crate::run_bounded_qemu_node_step(
        &mut target,
        &mut runtime,
        policy,
        &crate::QemuCrashDetector::new("mapped-owner"),
        MappedPublication::horizon(),
    )?;

    let crate::QemuAsyncNodeStepOutcome::Crashed {
        status: crate::QemuNodeRunStatus::Crashed(status),
        shutdown,
    } = report.outcome
    else {
        panic!("unavailable source cannot complete");
    };
    assert_eq!(
        status.cause,
        crate::QemuCrashCause::BoundedAwaitTimeout(crate::QemuBoundedAwaitTimeout::new(
            "advance completion",
            budget
        ))
    );
    assert!(shutdown.reaped && !shutdown.leaked && target.child.reaped());
    assert_eq!(target.published, 0);
    assert_eq!(target.finishes, 0);
    use std::os::unix::fs::FileExt;
    file.write_all_at(
        &before.advance_publication_sequence.to_ne_bytes(),
        layout.node_slots_off
            + crucible_shmem::NODE_SLOT_ADVANCE_PUBLICATION_SEQUENCE_OFFSET as u64,
    )?;
    assert_eq!(producer.node_slot(0)?.try_snapshot(), Some(before));
    Ok(())
}

/// Runs the original driver and real mapped channel; guest and native control
/// publication are explicit providers, not an executed QEMU or QMP command.
fn drive_checkpoint_publication(
    initial_checkpoint: bool,
    fresh_coordinate: u64,
) -> Result<(crate::QemuAsyncNodeStepReport, usize), Box<dyn std::error::Error>> {
    use std::os::fd::AsFd;

    let mapped = MappedPublication::new()?;
    let slot = mapped.producer.node_slot(0)?;
    slot.arm_external_state_restore_ceiling(1000)?;
    slot.publish_reached_icount(100)?;
    if initial_checkpoint {
        slot.publish_pause_quiesced(100, 2)?;
    }
    let mut notifications = mapped.notifications;
    notifications.set_nonblocking(false)?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
    let responder =
        crucible_shmem::mmap_setup_region(mapped.file.as_fd(), mapped.layout.region_size)?;
    let (mut target, _hold_open) = owner_fixture(mapped.channel)?;
    let mut runtime = mapped.runtime;
    let budget = Duration::from_millis(200);
    let policy = crate::QemuAsyncDriverPolicy::new(budget, budget, budget, budget);

    let writer = std::thread::spawn(move || -> Result<(), String> {
        let slot = responder.node_slot(0).map_err(|error| error.to_string())?;
        loop {
            let mut counter = [0_u8; 8];
            match notifications.read_exact(&mut counter) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error.to_string()),
            }
            if u64::from_ne_bytes(counter) != 1 {
                return Err("unexpected mapped doorbell".into());
            }
            let snapshot = slot.snapshot();
            if snapshot.control_boundary_ack & 1 == 0 {
                // Model the original native completion of the requested clamp,
                // preserving the guest's already published pause coordinate.
                slot.publish_control_boundary(
                    snapshot.current_icount,
                    snapshot.logical_time_raw_icount,
                )
                .map_err(|error| error.to_string())?;
                slot.acknowledge_control_boundary();
                if snapshot.max_advance_icount == snapshot.current_icount {
                    return Ok(());
                }
            }
        }
    });

    let result = crate::async_driver::run_bounded_qemu_node_step_with_start_hook(
        &mut target,
        &mut runtime,
        policy,
        &crate::QemuCrashDetector::new("checkpoint-origin"),
        crucible::ExecutionHorizon {
            icount: crucible::Icount { retired: 1000 },
        },
        |_target, _pending| {
            // The resumed guest can run and pause again before the first host
            // completion poll. A new generation at the old coordinate alone
            // is deliberately insufficient in the negative control.
            slot.publish_reached_icount(fresh_coordinate)
                .and_then(|()| slot.publish_pause_quiesced(fresh_coordinate, fresh_coordinate / 50))
                .map_err(|error| {
                    crate::QemuNodeChannelError::new("model post-start pause", error.to_string())
                })
        },
    );
    // Reap the one owned builtin-only child even if the driver returned an
    // error; the responder has its own bounded read and cannot outlive a join.
    let cleanup = target.shutdown_after_crash();
    let writer_result = writer.join().map_err(|_| "modeled responder panicked")?;
    writer_result.map_err(std::io::Error::other)?;
    let cleanup = cleanup?;
    assert!(cleanup.reaped && !cleanup.leaked);
    Ok((result?, target.finishes))
}

#[test]
fn fresh_pause_before_first_poll_does_not_replace_original_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    for initial_checkpoint in [false, true] {
        let (report, finishes) = drive_checkpoint_publication(initial_checkpoint, 200)?;

        assert!(matches!(
            report.outcome,
            crate::QemuAsyncNodeStepOutcome::Completed { .. }
        ));
        assert_eq!(finishes, 1);
        let boundary = report.completed_boundary.ok_or("original clamp missing")?;
        assert_eq!(boundary.idle_state().current_icount.retired, 200);
        assert_eq!(
            boundary.idle_state().next_deadline,
            Some(crucible::Icount { retired: 200 })
        );
    }
    Ok(())
}

#[test]
fn same_coordinate_republication_does_not_release_original_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let (report, finishes) = drive_checkpoint_publication(true, 100)?;

    assert!(matches!(
        report.outcome,
        crate::QemuAsyncNodeStepOutcome::Crashed {
            status: crate::QemuNodeRunStatus::Crashed(ref status),
            ..
        } if status.cause == crate::QemuCrashCause::BoundedAwaitTimeout(
            crate::QemuBoundedAwaitTimeout::new("advance completion", Duration::from_millis(200))
        )
    ));
    assert_eq!(finishes, 0);
    assert!(report.completed_boundary.is_none());
    Ok(())
}
