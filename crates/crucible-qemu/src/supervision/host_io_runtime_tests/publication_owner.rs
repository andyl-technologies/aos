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

    fn finish_quantum(
        &mut self,
        pending: &mut Self::PendingQuantum,
    ) -> Result<crate::QemuAsyncQuantumCompletion, crate::QemuNodeChannelError> {
        self.finishes += 1;
        self.channel.poll_quantum(pending)
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
