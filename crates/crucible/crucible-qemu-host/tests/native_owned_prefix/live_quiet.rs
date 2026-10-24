//! Actual same-Child source retirement, half-open quiet steps and due-source refusal.

use super::{original, position, reaction, watchdog::OriginalDeadline};
use crucible_node_format::{InputBatch, Position, U64};
use crucible_qemu_host::native_node_control::owned_operation::{
    Archive, NativeLiveProgress, NativeLiveSession, NativeOwnedPrefixOperation, TurnoverState,
};
use crucible_qemu_protocol::node_control::{
    BoundaryPolicy, ExecutionKind, NativeEffectCompute, NativeQuietCommand, NativeQuietStatus,
};
use std::{error::Error, path::Path, time::Duration};

pub(super) fn exercise(
    driver: NativeOwnedPrefixOperation,
    first: &NativeEffectCompute,
    archive_path: &Path,
    initial_path: &Path,
    pid: u32,
) -> Result<(), Box<dyn Error>> {
    eprintln!("native_live_checkpoint=converting_completed_effect_to_live sequence=1");
    let original_initial = std::fs::read(initial_path)?;
    let mut live = match NativeLiveSession::from_prefix(driver) {
        Ok(live) => live,
        Err(mut failure) => {
            failure.dispose(Duration::from_secs(5))?;
            return Err("source live conversion refused, same child reaped".into());
        }
    };
    assert_eq!(live.process_id(), pid);
    assert!(!live.reaped());
    // Explicit reconciliation retains the same pending original. The source
    // must either recover its original reply or remain pending, never rerun.
    eprintln!("native_live_checkpoint=first_retirement_poll sequence=1");
    let first_poll = live.poll()?;
    assert_eq!(first_poll, NativeLiveProgress::Pending);
    live.request_original_again()?;
    eprintln!("native_live_checkpoint=waiting_first_retirement_after_reconciliation sequence=1");
    await_stopped(&mut live)?;
    assert!(matches!(
        live.archive().state(),
        TurnoverState::RetirementCommitted { sequence: 1, .. }
    ));
    for (sequence, start, limit, settle, expected) in [
        (
            2,
            position(151),
            position(175),
            false,
            NativeQuietStatus::Completed,
        ),
        (
            3,
            position(175),
            reaction(175),
            true,
            NativeQuietStatus::Completed,
        ),
        (
            4,
            reaction(175),
            position(199),
            false,
            NativeQuietStatus::Completed,
        ),
        (
            5,
            position(199),
            position(201),
            false,
            NativeQuietStatus::NeedsEvaluation,
        ),
    ] {
        let predecessor = live
            .committed()
            .ok_or("missing actual native committed predecessor")?
            .digest();
        let command = quiet(sequence, start, limit, settle, predecessor, first)?;
        assert!(live.retire_quiet().is_err());
        live.begin_quiet(command.clone())?;
        assert!(live.begin_quiet(command).is_err());
        eprintln!("native_live_checkpoint=waiting_quiet_result sequence={sequence}");
        let deadline = OriginalDeadline::after(Duration::from_secs(5));
        loop {
            deadline.check()?;
            match live.poll()? {
                NativeLiveProgress::QuietRetained(status) => {
                    assert_eq!(status, expected);
                    break;
                }
                NativeLiveProgress::Pending => deadline.wait_pending()?,
                NativeLiveProgress::Stopped => {
                    return Err("quiet request was not evaluated by source".into());
                }
            }
        }
        eprintln!("native_live_checkpoint=quiet_result_retained sequence={sequence}");
        let result = live
            .quiet_result()
            .ok_or("missing actual source no-evaluation result")?;
        assert_eq!(result.before()?.position()?, start);
        assert_eq!(result.before()?.raw()?, 3);
        assert_eq!(result.after()?.raw()?, 3);
        assert_eq!(
            result.after()?.position()?,
            if expected == NativeQuietStatus::Completed {
                limit
            } else {
                start
            }
        );
        assert_eq!(&result.before()?.bytes()[80..88], &200u64.to_be_bytes());
        assert_eq!(&result.after()?.bytes()[80..88], &200u64.to_be_bytes());
        assert_eq!(live.process_id(), pid);
        live.retire_quiet()?;
        eprintln!("native_live_checkpoint=waiting_quiet_retirement sequence={sequence}");
        await_stopped(&mut live)?;
        assert!(
            matches!(live.archive().state(), TurnoverState::RetirementCommitted { sequence: actual, .. } if actual == sequence)
        );
        assert!(live.failure().is_none());
    }
    eprintln!("native_live_checkpoint=all_five_retirements_committed");
    assert_eq!(std::fs::read(initial_path)?, original_initial);
    live.dispose(Duration::from_secs(5))?;
    assert!(live.reaped());
    assert!(live.poll().is_err());
    drop(live);
    // This reopens only correlated archive DATA after real Child reap. It does
    // not restore native state, Source ownership, an epoch or a Ready capability.
    let mut restored = Archive::restore(
        archive_path,
        first.command.scope.identity_digest()?,
        first.effect_preparation,
        crucible_qemu_host::native_node_control::owned_operation::ArchiveBudget {
            lifetime_bytes: 65_536 * 5 + 136,
            lifetime_commands: 5,
            maximum_prefixes: 2,
        },
    )?;
    assert!(matches!(
        restored.state(),
        TurnoverState::RetirementCommitted { sequence: 5, .. }
    ));
    let first_history = restored.historical(1)?;
    assert!(first_history.terminal.is_some());
    assert!(first_history.quiet_terminal.is_none());
    assert!(first_history.native_commit.is_some());
    for sequence in 2..=5 {
        let history = restored.historical(sequence)?;
        assert!(history.terminal.is_none());
        assert!(history.quiet_terminal.is_some());
        assert!(history.native_receipt.is_some());
        assert!(history.native_commit.is_some());
    }
    eprintln!(
        "native_live_quiet=sourceRR,raw3,151to175,175boundaryToReaction,175reactionTo199,due200refused,retired5,reaped"
    );
    Ok(())
}

fn quiet(
    sequence: u64,
    start: Position,
    limit: Position,
    settle: bool,
    predecessor: [u8; 32],
    first: &NativeEffectCompute,
) -> Result<NativeQuietCommand, Box<dyn Error>> {
    let mut command = original(sequence, start.time_ps.get(), limit.time_ps.get());
    command.kind = if settle {
        ExecutionKind::BoundarySettle { start, limit }
    } else {
        ExecutionKind::ExactRun {
            start,
            limit,
            boundary_policy: BoundaryPolicy::HorizonPark,
        }
    };
    command.closed_input_prefix = limit;
    let empty = InputBatch {
        schema_version: 1,
        execution_owner_id: command.scope.owner.clone(),
        input_epoch: command.input_epoch.clone(),
        batch_id: command.input_batch.clone(),
        batch_sequence: U64::new(sequence),
        events: Vec::new(),
        extensions: Default::default(),
    };
    command.input_batch_hash = empty.identity()?;
    Ok(NativeQuietCommand {
        command,
        preparation: first.effect_preparation,
        predecessor_commit: predecessor,
        input_batch_sequence: U64::new(sequence),
    })
}

fn await_stopped(live: &mut NativeLiveSession) -> Result<(), Box<dyn Error>> {
    let deadline = OriginalDeadline::after(Duration::from_secs(5));
    let mut observed_archive = None;
    loop {
        deadline.check()?;
        let progress = live.poll()?;
        let archive = live.archive().state();
        if observed_archive != Some(archive) {
            eprintln!("native_live_checkpoint=retirement_archive state={archive:?}");
            observed_archive = Some(archive);
        }
        match progress {
            NativeLiveProgress::Stopped => return Ok(()),
            NativeLiveProgress::Pending => deadline.wait_pending()?,
            NativeLiveProgress::QuietRetained(_) => {
                return Err("unexpected quiet result during native retirement".into());
            }
        }
    }
}
