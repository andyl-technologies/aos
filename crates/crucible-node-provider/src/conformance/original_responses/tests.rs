//! Exercises journal credit and unresolved-original retention as data models.

#![cfg(test)]

use super::*;
use crucible_node_contract::U64;

fn peer() -> Result<EndpointMeasurement, ProviderError> {
    Ok(EndpointMeasurement {
        peer_pid: U64::new(1),
        peer_uid: U64::new(1),
        executable: canonical::content_ref(b"model-only", "application/octet-stream")?,
    })
}

#[test]
fn exact_credit_retains_original_and_returns_only_unused_frame_bytes() -> Result<(), ProviderError>
{
    let (journal, originals) = Journal::new(2, 16)?;
    let index = journal.reserve(&peer()?, 16)?;
    assert_eq!(
        originals.records()?[0].state(),
        OriginalProbeResponseState::Pending
    );
    journal.complete(index, 16, Some(b"{}".to_vec()), false)?;
    assert_eq!(originals.records()?[0].bytes(), b"{}");
    let next = journal.reserve(&peer()?, 14)?;
    journal.complete(next, 14, None, false)?;
    assert_eq!(originals.records()?.len(), 2);
    Ok(())
}

#[test]
fn undercredit_refuses_before_row_and_fences_smaller_allowance() -> Result<(), ProviderError> {
    let (journal, originals) = Journal::new(2, 16)?;
    assert!(journal.reserve(&peer()?, 17).is_err());
    assert!(originals.records()?.is_empty());
    assert!(journal.reserve(&peer()?, 1).is_err());
    Ok(())
}

#[test]
fn pending_unwind_keeps_original_slot_and_fences_future_receive() -> Result<(), ProviderError> {
    let (journal, originals) = Journal::new(2, 32)?;
    journal.reserve(&peer()?, 16)?;
    assert!(journal.reserve(&peer()?, 16).is_err());
    assert_eq!(originals.records()?.len(), 1);
    assert_eq!(
        originals.records()?[0].state(),
        OriginalProbeResponseState::Pending
    );
    Ok(())
}

#[test]
fn failed_read_keeps_original_failure_without_replacement() -> Result<(), ProviderError> {
    let (journal, originals) = Journal::new(2, 32)?;
    let index = journal.reserve(&peer()?, 16)?;
    journal.complete(index, 16, None, true)?;
    assert!(journal.reserve(&peer()?, 16).is_err());
    assert_eq!(
        originals.records()?[0].state(),
        OriginalProbeResponseState::Failed
    );
    Ok(())
}

#[test]
fn wrong_completion_keeps_pending_original_and_no_body() -> Result<(), ProviderError> {
    let (journal, originals) = Journal::new(2, 32)?;
    let index = journal.reserve(&peer()?, 16)?;
    assert!(
        journal
            .complete(index + 1, 16, Some(b"{}".to_vec()), false)
            .is_err()
    );
    assert_eq!(
        originals.records()?[0].state(),
        OriginalProbeResponseState::Pending
    );
    assert!(originals.records()?[0].bytes().is_empty());
    Ok(())
}
