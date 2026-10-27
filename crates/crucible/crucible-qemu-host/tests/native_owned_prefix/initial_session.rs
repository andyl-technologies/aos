//! Exercises the same actual preparation owner before command reservation.
//!
//! The native initial facts and consumed ACK remain durable across a unique
//! Session-to-operation move. This scenario supplies no common Ready or restore
//! authority and preserves the original five-second initial protocol deadline.

// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, path::Path, process::Child, time::Duration};

use crucible_qemu_host::native_node_control::{
    NativeAdministrationTransport,
    owned_operation::{
        Archive, InitialEvidenceBudget, NativeOwnedPrefixOperation, NativeOwnedPrefixSession,
        OriginalPreparationProgress, TurnoverState,
    },
};
use crucible_qemu_protocol::node_control::{NativeEffectCompute, NativeInitializationReceipt};

use super::{position, watchdog::OriginalDeadline};

pub(super) fn prepare_and_consume(
    child: Child,
    endpoint: NativeAdministrationTransport,
    archive: Archive,
    path: &Path,
    initialization: NativeInitializationReceipt,
    command: NativeEffectCompute,
    quiet_limit: Option<crucible_node_format::Position>,
    observe_stopped: bool,
) -> Result<NativeOwnedPrefixOperation, Box<dyn Error>> {
    let original_pid = child.id();
    let prefix = endpoint
        .prefix_preparation()
        .ok_or("missing original prefix preparation")?
        .clone();
    let mut session = match NativeOwnedPrefixSession::create(
        child,
        endpoint,
        archive,
        path,
        initialization.clone(),
        InitialEvidenceBudget {
            lifetime_bytes: 65_536,
        },
    ) {
        Ok(session) => session,
        Err(mut failure) => {
            failure.dispose(Duration::from_secs(5))?;
            return Err("original initial file creation refused; child retained and reaped".into());
        }
    };
    assert_eq!(session.process_id(), original_pid);
    assert_eq!(session.archive_state(), TurnoverState::Vacant);
    assert!(session.facts().is_none());

    assert!(session.begin_stopped_cut().is_err());
    await_initial(&mut session, OriginalPreparationProgress::FactsRetained)?;
    let facts = session
        .facts()
        .ok_or("missing original initial facts")?
        .clone();
    let observation = facts.observe_original(&prefix, &initialization)?;
    assert_eq!(observation.initial, position(0));
    assert_eq!(&facts.canonical_bytes()[560..568], &[0u8; 8]);
    assert_eq!(observation.next_cpu_deadline_ps.get(), 50);
    if let (Some(limit), Some(timer)) = (quiet_limit, &observation.first_timer) {
        // This completion fixture cannot hide a due timer as CPU-only work.
        // Preserve the partial-prefix control's original preparation checks.
        assert!(timer.evaluation >= limit);
    }
    assert_eq!(session.archive_state(), TurnoverState::Vacant);

    await_initial(
        &mut session,
        OriginalPreparationProgress::AcknowledgementConsumed,
    )?;
    assert_eq!(session.process_id(), original_pid);
    assert_eq!(session.archive_state(), TurnoverState::Vacant);
    assert!(!session.reaped());
    let initial_bytes = std::fs::read(path)?;
    let stopped = if observe_stopped {
        session.begin_stopped_cut()?;
        assert!(session.poll().is_err());
        let deadline = OriginalDeadline::after(Duration::from_secs(5));
        loop {
            deadline.check()?;
            if session.poll_stopped_cut()? {
                break;
            }
            deadline.wait_pending()?;
        }
        let observed = session
            .stopped_cut()
            .ok_or("missing source stopped cut")?
            .clone();
        assert_eq!(observed.process_id()?, u64::from(original_pid));
        assert!(observed.thread_id()? > 0);
        assert_eq!(observed.position()?, position(0));
        assert_eq!(observed.raw_count()?, 0);
        assert_eq!(observed.next_cpu()?.time_ps.get(), 50);
        session.begin_stopped_cut()?;
        assert!(session.poll_stopped_cut()?);
        assert_eq!(session.stopped_cut(), Some(&observed));
        Some(observed)
    } else {
        assert!(session.begin_stopped_cut().is_err());
        None
    };

    let operation = match session.into_operation(command) {
        Ok(operation) => operation,
        Err(mut failure) => {
            failure.dispose(Duration::from_secs(5))?;
            return Err(
                "original consuming conversion refused; full owner retained and reaped".into(),
            );
        }
    };
    assert_eq!(operation.process_id(), original_pid);
    let evidence = operation
        .initial_evidence()
        .ok_or("initial history lost during move")?;
    assert_eq!(evidence.facts(), Some(&facts));
    assert_eq!(
        evidence.offered_acknowledgement(),
        evidence.consumed_acknowledgement()
    );
    assert!(evidence.consumed_acknowledgement().is_some());
    assert_eq!(evidence.store().initialization(), &initialization);
    assert!(evidence.store().complete());
    assert_eq!(evidence.stopped_cut(), stopped.as_ref());
    assert_eq!(std::fs::read(path)?, initial_bytes);
    Ok(operation)
}

pub(super) fn retained_bytes(
    operation: &NativeOwnedPrefixOperation,
    initial_contract: bool,
) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    if initial_contract {
        let evidence = operation
            .initial_evidence()
            .ok_or("missing original initial evidence")?;
        assert!(evidence.store().complete());
        Ok(Some(std::fs::read(evidence.store().path())?))
    } else {
        assert!(operation.initial_evidence().is_none());
        Ok(None)
    }
}

fn await_initial(
    session: &mut NativeOwnedPrefixSession,
    expected: OriginalPreparationProgress,
) -> Result<(), Box<dyn Error>> {
    let deadline = OriginalDeadline::after(Duration::from_secs(5));
    loop {
        deadline.check()?;
        let progress = session.poll()?;
        deadline.check()?;
        if progress == expected {
            return Ok(());
        }
        deadline.wait_pending()?;
    }
}
