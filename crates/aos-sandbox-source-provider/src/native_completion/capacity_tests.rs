//! Exercises native full-width capacity with the real protected journal owner.
//!
//! These records are capacity-only projections, not a fabricated complete
//! Provider graph or an installed peer/session qualification. The runtime
//! separately requires strict graph validation of real rows before append.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt as _;

use aos_sandbox::{Journal, JournalLimits, JournalRecord};

use super::*;

fn capacity_request() -> GlobalCapacityReservationRequestV1 {
    GlobalCapacityReservationRequestV1 {
        purpose: PURPOSE,
        owner_namespace: RecordNamespace::SourceProviderAuthority,
        owner_id: [1; 32],
        owner_digest: [2; 32],
        operation_id: [3; 16],
        artifact_digest: [4; 32],
        checkpoint_digest: [5; 32],
        chain_head_digest: [6; 32],
        terminal_records: DISPATCH_TERMINAL_RECORDS,
        terminal_bytes: DISPATCH_TERMINAL_BYTES,
        poison_records: DISPATCH_TERMINAL_RECORDS,
        poison_bytes: DISPATCH_TERMINAL_BYTES,
    }
}

fn open(directory: &std::path::Path, limits: JournalLimits) -> Journal {
    Journal::open_protected_at_uid(
        directory,
        "native-capacity.journal",
        limits,
        rustix::process::geteuid().as_raw(),
    )
    .unwrap()
    .0
}

fn full_owner_cut(id: u8) -> JournalTransaction {
    let bounds = aos_sandbox_source_provider_ledger::ledger::format::NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2;
    let records = bounds
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                vec![id, index as u8],
                vec![id; bytes],
            )
        })
        .collect();
    JournalTransaction::new([id; 16], records).unwrap()
}

#[test]
fn native_capacity_preserves_full_width_cleanup_floor_after_active_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let limits = JournalLimits {
        maximum_journal_bytes: 2 * DISPATCH_TERMINAL_BYTES + 4096,
        ..JournalLimits::default()
    };
    let request = capacity_request();
    assert_eq!(request.terminal_records, 7);
    assert!(request.terminal_bytes > TERMINAL_BYTES);
    let mut journal = open(directory.path(), limits);
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let prepared = owner
        .prepare_global_capacity_reservation_v1(request, [7; 16])
        .unwrap();
    let admission = JournalTransaction::new(
        [7; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                b"requested-projection".to_vec(),
                vec![7; 16],
            ),
            prepared.record().clone(),
        ],
    )
    .unwrap();
    let preflight = owner
        .preflight_global_capacity_reservation_v1(&prepared, &admission)
        .unwrap();
    let (_, reservation) = owner
        .commit_global_capacity_reservation_v1(&preflight, prepared, &admission)
        .unwrap();
    let reservation_id = reservation.reservation_id();
    let active = full_owner_cut(8);
    owner.commit(&active).unwrap();
    assert_eq!(
        owner
            .recover_global_capacity_reservation_v1(reservation_id)
            .unwrap()
            .request(),
        request
    );
    let before = owner.snapshot().unwrap();
    let excessive = JournalTransaction::new(
        [9; 16],
        vec![JournalRecord::put(
            RecordNamespace::SourceProviderAuthority,
            b"unrelated".to_vec(),
            vec![9; 8192],
        )],
    )
    .unwrap();
    assert!(owner.preflight_transactions(&[excessive]).is_err());
    owner.validate_snapshot_for_effect(&before).unwrap();
    drop(owner);
    drop(journal);

    let mut journal = open(directory.path(), limits);
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let reservation = owner
        .recover_unique_global_capacity_reservation_v1(&binding(request))
        .unwrap();
    assert_eq!(reservation.reservation_id(), reservation_id);
    owner
        .validate_global_capacity_reservation_set_v1(&BTreeSet::from([reservation_id]))
        .unwrap();
    let mut records = full_owner_cut(8).records().to_vec();
    records.push(reservation.settlement_record());
    let terminal = JournalTransaction::new([10; 16], records).unwrap();
    let preflight = owner
        .preflight_reserved_terminal_v1(&reservation, &terminal)
        .unwrap();
    owner
        .commit_reserved_terminal_v1(&preflight, reservation, &terminal)
        .unwrap();
    owner
        .validate_global_capacity_reservation_set_v1(&BTreeSet::new())
        .unwrap();
}

#[test]
fn native_capacity_refuses_ordered_suffix_before_dispatch_without_spending_floor() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let limits = JournalLimits {
        maximum_journal_bytes: DISPATCH_TERMINAL_BYTES + 4096,
        ..JournalLimits::default()
    };
    let request = capacity_request();
    let mut journal = open(directory.path(), limits);
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let prepared = owner
        .prepare_global_capacity_reservation_v1(request, [11; 16])
        .unwrap();
    let admission = JournalTransaction::new(
        [11; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                b"requested-projection".to_vec(),
                vec![11; 16],
            ),
            prepared.record().clone(),
        ],
    )
    .unwrap();
    let preflight = owner
        .preflight_global_capacity_reservation_v1(&prepared, &admission)
        .unwrap();
    let (_, reservation) = owner
        .commit_global_capacity_reservation_v1(&preflight, prepared, &admission)
        .unwrap();
    let before = owner.snapshot().unwrap();
    let accepted = JournalTransaction::new([12; 16], vec![JournalRecord::put(
        RecordNamespace::SourceProviderAuthority, b"prepared-projection".to_vec(),
        vec![12; aos_sandbox_source_provider_ledger::ledger::format::MAXIMUM_NATIVE_ACQUIRE_CARRIER_MUTATION_BYTES_V2],
    )]).unwrap();
    assert!(
        owner
            .preflight_transactions(&[accepted, full_owner_cut(13)])
            .is_err()
    );
    owner.validate_snapshot_for_effect(&before).unwrap();
    assert_eq!(
        owner
            .recover_global_capacity_reservation_v1(reservation.reservation_id())
            .unwrap()
            .request(),
        request
    );
    let mut changed = binding(request);
    changed.checkpoint_digest = [14; 32];
    assert!(
        owner
            .recover_unique_global_capacity_reservation_v1(&changed)
            .is_err()
    );
    // Old body-6 geometry is a different exact reservation, never an
    // implicitly upgraded floor for the additional original-clock block.
    let mut old_geometry = binding(request);
    old_geometry.terminal_bytes -= 56;
    old_geometry.poison_bytes -= 56;
    assert!(
        owner
            .recover_unique_global_capacity_reservation_v1(&old_geometry)
            .is_err()
    );
    owner
        .validate_global_capacity_reservation_set_v1(&BTreeSet::from(
            [reservation.reservation_id()],
        ))
        .unwrap();
}
