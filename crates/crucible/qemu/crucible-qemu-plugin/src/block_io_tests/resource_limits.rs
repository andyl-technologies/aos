//! Exact authored completed-history limit regressions.

use super::*;
use crate::{
    HARD_STORAGE_COMPLETED_HISTORY_EPOCHS, HARD_STORAGE_COMPLETED_HISTORY_GAPS, PluginArgs,
};

fn limits(epochs: u64, gaps: u64) -> PluginStorageHistoryLimits {
    let raw = format!(
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs={epochs},storage_completed_history_gaps={gaps}"
    );
    PluginArgs::parse(&raw)
        .unwrap_or_else(|error| panic!("resource-limit args should parse: {error}"))
        .storage_history_limits()
}

#[test]
fn completed_identity_history_compacts_contiguous_ids_and_retains_gaps() {
    let mut history = CompletedIdentityHistory::default();
    let third = BlockRequestIdentity::new(7, 2);
    history
        .ensure_record_capacity(third, PluginStorageHistoryLimits::compiled_maximum())
        .unwrap_or_else(|error| panic!("history should admit a gap: {error}"));
    history.record(third);
    assert!(history.contains(third));
    assert_eq!(history.gaps, 1);

    for request_id in [0, 1] {
        let identity = BlockRequestIdentity::new(7, request_id);
        history
            .ensure_record_capacity(identity, PluginStorageHistoryLimits::compiled_maximum())
            .unwrap_or_else(|error| panic!("history should admit prefix: {error}"));
        history.record(identity);
    }

    assert_eq!(history.gaps, 0);
    assert_eq!(history.epochs[&7].contiguous_exclusive, 3);
    assert!(
        (0..=2).all(|request_id| { history.contains(BlockRequestIdentity::new(7, request_id)) })
    );
    assert!(!history.contains(BlockRequestIdentity::new(7, 3)));

    history.clear();
    assert!(!history.contains(third));
    assert_eq!(history.gaps, 0);
}

#[test]
fn completed_history_refuses_epochs_and_gaps_at_exact_authored_coordinates() {
    let limits = limits(1, 1);
    let mut history = CompletedIdentityHistory::default();

    history
        .ensure_record_capacity(BlockRequestIdentity::new(7, 0), limits)
        .unwrap_or_else(|error| panic!("first epoch should fit: {error}"));
    history.record(BlockRequestIdentity::new(7, 0));
    assert_eq!(
        history.ensure_record_capacity(BlockRequestIdentity::new(8, 0), limits),
        Err(BlockIoError::CompletedHistoryResourceLimit {
            field: "storage_completed_history_epochs",
            current: 1,
            requested: 1,
            configured: 1,
            hard: HARD_STORAGE_COMPLETED_HISTORY_EPOCHS,
        })
    );

    history
        .ensure_record_capacity(BlockRequestIdentity::new(7, 2), limits)
        .unwrap_or_else(|error| panic!("first gap should fit: {error}"));
    history.record(BlockRequestIdentity::new(7, 2));
    assert_eq!(
        history.ensure_record_capacity(BlockRequestIdentity::new(7, 4), limits),
        Err(BlockIoError::CompletedHistoryResourceLimit {
            field: "storage_completed_history_gaps",
            current: 1,
            requested: 1,
            configured: 1,
            hard: HARD_STORAGE_COMPLETED_HISTORY_GAPS,
        })
    );
}

#[test]
fn transport_restore_admits_history_counts_before_owned_decode() {
    let source = PluginBlockIo::new(0, 8, 9);
    source.request_epoch.set(9);
    {
        let mut history = source.completed_identities.borrow_mut();
        for identity in [
            BlockRequestIdentity::new(7, 0),
            BlockRequestIdentity::new(8, 0),
        ] {
            history
                .ensure_record_capacity(identity, PluginStorageHistoryLimits::compiled_maximum())
                .unwrap_or_else(|error| panic!("source history should fit: {error}"));
            history.record(identity);
        }
    }
    let encoded = source
        .encode_transport_continuation()
        .unwrap_or_else(|error| panic!("source continuation should encode: {error}"));
    let restored = PluginBlockIo::new_with_history_limits(0, 8, 9, limits(1, 1));

    assert_eq!(
        restored.restore_transport_continuation(&encoded, 9, 0),
        Err(BlockIoError::CompletedHistoryResourceLimit {
            field: "storage_completed_history_epochs",
            current: 0,
            requested: 2,
            configured: 1,
            hard: HARD_STORAGE_COMPLETED_HISTORY_EPOCHS,
        })
    );
    assert!(restored.completed_identities.borrow().epochs.is_empty());
}
