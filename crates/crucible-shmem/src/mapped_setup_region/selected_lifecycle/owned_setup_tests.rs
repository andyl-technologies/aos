//! Actual mapping-allocation custody across in-place selection.

use super::super::tests::original_aliases;
use super::*;
use crate::SelectedRingAdmissionBudget;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn ordinary_owner_preserves_views_and_reversible_ring_release() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    let address = first.mapping_start();
    let mut owner = OwnedSetupMapping::new(first);

    assert_eq!(owner.mapping().mapping_start(), address);
    assert_eq!(owner.ordinary_mapping_mut()?.mapping_start(), address);
    owner.mapping().hold_hot_fork_ring_io()?;
    assert_eq!(alias.release_hot_fork_ring_io()?.held_rings(), 0);
    assert!(owner.selected_mut().is_err());
    Ok(())
}

#[test]
fn whole_selection_preserves_the_same_owner_allocation_and_views() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let address = first.mapping_start();
    let mut owner = OwnedSetupMapping::new(first);
    let allocation = match &owner.owner {
        MappingOwner::Ordinary(mapping) => Arc::as_ptr(mapping),
        MappingOwner::Selected(_) => return Err("unexpected initial selection".into()),
    };

    owner.select_whole(7)?;

    let selected = owner.selected_mut()?;
    assert_eq!(Arc::as_ptr(&selected.mapping), allocation);
    assert_eq!(Arc::strong_count(&selected.mapping), 1);
    selected.selection_status()?;
    assert_eq!(owner.mapping().mapping_start(), address);
    assert!(owner.ordinary_mapping_mut().is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn failed_selection_retains_the_same_owner_before_any_retry_or_drop() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut owner = OwnedSetupMapping::new(first);
    let allocation = match &owner.owner {
        MappingOwner::Ordinary(mapping) => Arc::as_ptr(mapping),
        MappingOwner::Selected(_) => return Err("unexpected initial selection".into()),
    };

    assert_eq!(
        owner.select_whole(0),
        Err(WholeMappingCustodyError::ZeroEpoch)
    );

    assert_eq!(Arc::as_ptr(&owner.selected_mut()?.mapping), allocation);
    assert_eq!(owner.selected_mut()?.epoch(), 0);
    assert_eq!(
        owner.select_whole(7),
        Err(WholeMappingCustodyError::Selected)
    );
    assert!(owner.ordinary_mapping_mut().is_err());
    drop(owner);
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn an_additional_real_owner_refuses_unique_ordinary_mutation() -> TestResult {
    let (_file, first, _alias) = original_aliases()?;
    let mut owner = OwnedSetupMapping::new(first);
    let extra_owner = match &owner.owner {
        MappingOwner::Ordinary(mapping) => Arc::clone(mapping),
        MappingOwner::Selected(_) => return Err("unexpected initial selection".into()),
    };

    assert!(matches!(
        owner.ordinary_mapping_mut(),
        Err(WholeMappingCustodyError::Busy)
    ));

    drop(extra_owner);
    assert!(owner.ordinary_mapping_mut().is_ok());
    Ok(())
}

#[test]
fn two_balanced_local_loans_keep_the_same_selected_world_mapping() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let address = first.mapping_start();
    let mut owner = OwnedSetupMapping::new(first);
    owner.select_whole(7)?;
    let selected = owner.selected_mut()?;

    for sequence in 1..=2 {
        // This models the caller's native proof; it asserts only real local
        // paired balance and does not qualify a native stopped/result/ACK cut.
        let (_, completion) = selected.with_paired_selected_scope(
            7,
            sequence,
            0x1000 + sequence as usize,
            SelectedRingAdmissionBudget {
                producer_attempts: 0,
                consumer_attempts: 0,
            },
            |mapping| Ok::<_, std::io::Error>(mapping.mapping_start()),
        )??;
        selected.retire_paired_scope(7, sequence, 0x1000 + sequence as usize, completion)?;
    }

    assert_eq!(owner.mapping().mapping_start(), address);
    assert!(owner.ordinary_mapping_mut().is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}
