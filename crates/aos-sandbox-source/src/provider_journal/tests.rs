//! Preserves the existing Source-provider protected-scope and capacity tests.
//!
//! These fixtures exercise the real Source journal and its same common native
//! mechanisms. They do not supply fixed production ancestry or qualify a live
//! Source/Session, original native loan or installed runtime.

use super::*;
use super::scope::ProtectedAuthorityScope;
use aos_sandbox_broker::canonical_journal::RecoveryReport;
use aos_sandbox_core::OperationId;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "aos-sandbox-source-journal-{label}-{}-{}",
            std::process::id(),
            OperationId::new()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn transaction(id: u8, records: Vec<JournalRecord>) -> JournalTransaction {
    JournalTransaction::new([id; 16], records).unwrap()
}

fn protected_open(directory: &Path) -> Result<(Journal, RecoveryReport), JournalError> {
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    let uid = fs::metadata(directory).unwrap().uid();
    Journal::open_protected_at_uid(directory, "protected.journal", JournalLimits::default(), uid)
}

fn source_provider_capacity_request() -> GlobalCapacityReservationRequestV1 {
    GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
        owner_namespace: RecordNamespace::SourceProviderAuthority,
        owner_id: [1; 32],
        owner_digest: [2; 32],
        operation_id: [3; 16],
        artifact_digest: [4; 32],
        checkpoint_digest: [5; 32],
        chain_head_digest: [6; 32],
        future_transactions: 1,
        terminal_records: 3,
        terminal_bytes: 4096,
        poison_records: 3,
        poison_bytes: 4096,
    }
}

#[test]
fn source_held_readonly_scope_refuses_legacy_factories_and_effects() {
    // This local protected-open fixture tests scope refusal only. It is
    // not the fixed production location or a qualified Security Session.
    let directory = TestDirectory::new("source-held-readonly-scope");
    let (mut journal, _) = protected_open(&directory.0).unwrap();
    let before = (
        journal.native_view().state().clone(),
        journal.native_view().next_sequence(),
        journal.native_view().committed_transactions(),
        journal.native_view().metadata().unwrap().len(),
    );
    let request = source_provider_capacity_request();
    let binding = GlobalCapacityReservationRecoveryBindingV1 {
        purpose: request.purpose,
        operation_id: request.operation_id,
        artifact_digest: request.artifact_digest,
        checkpoint_digest: request.checkpoint_digest,
        chain_head_digest: request.chain_head_digest,
        future_transactions: request.future_transactions,
        terminal_records: request.terminal_records,
        terminal_bytes: request.terminal_bytes,
        poison_records: request.poison_records,
        poison_bytes: request.poison_bytes,
    };
    let change = transaction(
        1,
        vec![JournalRecord::put(
            RecordNamespace::SourceProviderAuthority,
            b"forbidden".to_vec(),
            vec![1],
        )],
    );
    {
        let mut view = ProtectedJournalAuthority {
            journal: &mut journal,
            namespace: RecordNamespace::SourceProviderAuthority,
            scope: ProtectedAuthorityScope::SourceProviderHeldReadOnly,
        };
        let snapshot = view.snapshot().unwrap();

        // Immutable Security artifact factories use these unchanged
        // purpose checks, not a generic readable snapshot as authority.
        assert!(matches!(
            view.validate_source_provider_authority(),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        assert!(matches!(
            view.validate_source_provider_authority_snapshot(&snapshot),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        assert!(view.validate_fixed_source_provider_storage().is_err());
        assert!(view.fixed_source_provider_session_handoff().is_err());
        assert!(matches!(
            view.validate_snapshot_for_effect(&snapshot),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        assert!(matches!(
            view.prepare_global_capacity_reservation_v1(request, [2; 16]),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        assert!(matches!(
            view.recover_unique_global_capacity_reservation_v1(&binding),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        assert!(matches!(
            view.preflight_transactions(std::slice::from_ref(&change)),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        let preflight = super::ProtectedJournalPreflight {
            snapshot: view.snapshot().unwrap(),
            transaction_digest: super::authority_preflight_digest(std::slice::from_ref(
                &change,
            )),
        };
        assert!(matches!(
            view.validate_preflight_for_effect(&preflight, std::slice::from_ref(&change)),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        assert!(matches!(
            view.commit(&change),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
    }
    assert_eq!(
        before,
        (
            journal.native_view().state().clone(),
            journal.native_view().next_sequence(),
            journal.native_view().committed_transactions(),
            journal.native_view().metadata().unwrap().len(),
        )
    );
    journal.ensure_healthy().unwrap();
}

#[test]
fn source_held_readonly_claim_requires_actual_fixed_physical_custody() {
    let directory = TestDirectory::new("source-held-readonly-location");
    let (mut journal, _) = protected_open(&directory.0).unwrap();
    assert!(journal.claim_source_provider_held_readonly_v1().is_err());
    journal.ensure_healthy().unwrap();
    assert!(journal.native_view().state().is_empty());
}

#[test]
fn source_provider_native_capacity_replays_and_settles_under_fixed_purpose() {
    let directory = TestDirectory::new("source-provider-native-capacity");
    let request = source_provider_capacity_request();
    let (mut journal, _) = protected_open(&directory.0).unwrap();
    let reservation_id = {
        let mut authority = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        authority.validate_source_provider_authority().unwrap();

        let prepared = authority
            .prepare_global_capacity_reservation_v1(request, [7; 16])
            .unwrap();
        assert_eq!(prepared.record().value().unwrap()[11], 3);
        let reservation_id = prepared.reservation_id();
        let admission = transaction(
            7,
            vec![
                JournalRecord::put(
                    RecordNamespace::SourceProviderAuthority,
                    b"owner".to_vec(),
                    b"admitted".to_vec(),
                ),
                prepared.record().clone(),
            ],
        );
        let preflight = authority
            .preflight_global_capacity_reservation_v1(&prepared, &admission)
            .unwrap();
        let (_, committed_reservation) = authority
            .commit_global_capacity_reservation_v1(&preflight, prepared, &admission)
            .unwrap();
        assert_eq!(committed_reservation.reservation_id(), reservation_id);
        assert_eq!(
            authority.get(b"owner").unwrap(),
            Some(b"admitted".as_slice())
        );
        assert_eq!(authority.records().unwrap().count(), 1);
        authority
            .commit(&transaction(
                9,
                vec![JournalRecord::put(
                    RecordNamespace::SourceProviderAuthority,
                    b"ordinary".to_vec(),
                    b"retained".to_vec(),
                )],
            ))
            .unwrap();
        reservation_id
    };
    drop(journal);

    let (mut reopened, _) = protected_open(&directory.0).unwrap();
    let mut authority = reopened
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    authority
        .validate_global_capacity_reservation_set_v1(&[reservation_id].into())
        .unwrap();
    let reservation = authority
        .recover_global_capacity_reservation_by_binding_v1(
            reservation_id,
            &GlobalCapacityReservationRecoveryBindingV1 {
                purpose: request.purpose,
                operation_id: request.operation_id,
                artifact_digest: request.artifact_digest,
                checkpoint_digest: request.checkpoint_digest,
                chain_head_digest: request.chain_head_digest,
                future_transactions: request.future_transactions,
                terminal_records: request.terminal_records,
                terminal_bytes: request.terminal_bytes,
                poison_records: request.poison_records,
                poison_bytes: request.poison_bytes,
            },
        )
        .unwrap();
    let terminal = transaction(
        8,
        vec![
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                b"owner".to_vec(),
                b"settled".to_vec(),
            ),
            reservation.settlement_record(),
        ],
    );
    let preflight = authority
        .preflight_reserved_terminal_v1(&reservation, &terminal)
        .unwrap();
    authority
        .commit_reserved_terminal_v1(&preflight, reservation, &terminal)
        .unwrap();
    authority
        .validate_global_capacity_reservation_set_v1(&Default::default())
        .unwrap();
    assert_eq!(
        authority.get(b"owner").unwrap(),
        Some(b"settled".as_slice())
    );
}

#[test]
fn source_provider_native_capacity_rejects_foreign_purpose_and_namespace() {
    let directory = TestDirectory::new("source-provider-native-isolation");
    let (mut journal, _) = protected_open(&directory.0).unwrap();
    let mut authority = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let mut wrong_purpose = source_provider_capacity_request();
    wrong_purpose.purpose = GlobalCapacityReservationPurposeV1::RuntimeExecution;
    assert!(matches!(
        authority.prepare_global_capacity_reservation_v1(wrong_purpose, [1; 16]),
        Err(JournalError::ForeignAuthorityNamespace)
    ));

    let prepared = authority
        .prepare_global_capacity_reservation_v1(source_provider_capacity_request(), [2; 16])
        .unwrap();
    let foreign_admission = transaction(
        2,
        vec![
            JournalRecord::put(RecordNamespace::Effect, b"foreign".to_vec(), vec![1]),
            prepared.record().clone(),
        ],
    );
    assert!(matches!(
        authority.preflight_global_capacity_reservation_v1(&prepared, &foreign_admission),
        Err(JournalError::ForeignAuthorityNamespace)
    ));
    let generic_capacity = transaction(3, vec![prepared.record().clone()]);
    assert!(matches!(
        authority.commit(&generic_capacity),
        Err(JournalError::ForeignAuthorityNamespace)
    ));
    let foreign_generic = transaction(
        4,
        vec![JournalRecord::put(
            RecordNamespace::Effect,
            b"foreign".to_vec(),
            vec![1],
        )],
    );
    assert!(matches!(
        authority.commit(&foreign_generic),
        Err(JournalError::ForeignAuthorityNamespace)
    ));
    drop(authority);

    let generic = journal
        .claim_protected_authority(RecordNamespace::SourceProviderAuthority)
        .unwrap();
    assert!(matches!(
        generic.prepare_global_capacity_reservation_v1(
            source_provider_capacity_request(),
            [5; 16]
        ),
        Err(JournalError::ForeignAuthorityNamespace)
    ));
}

#[test]
fn source_provider_native_claim_rejects_foreign_state_and_deleted_history() {
    for (label, delete_foreign) in [("retained", false), ("deleted", true)] {
        let directory = TestDirectory::new(label);
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        journal
            .commit(&transaction(
                21,
                vec![JournalRecord::put(
                    RecordNamespace::Effect,
                    b"foreign".to_vec(),
                    vec![1],
                )],
            ))
            .unwrap();
        if delete_foreign {
            journal
                .commit(&transaction(
                    22,
                    vec![JournalRecord::delete(
                        RecordNamespace::Effect,
                        b"foreign".to_vec(),
                    )],
                ))
                .unwrap();
            assert!(journal.records(RecordNamespace::Effect).next().is_none());
        }

        assert!(matches!(
            journal.claim_source_provider_native_terminal_authority_v1(),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        drop(journal);

        let (mut reopened, _) = protected_open(&directory.0).unwrap();
        assert!(matches!(
            reopened.claim_source_provider_native_terminal_authority_v1(),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
    }
}

#[test]
fn source_provider_native_capacity_checks_postimage_materialized_bytes_on_commit() {
    let directory = TestDirectory::new("source-provider-capacity-postimage-bytes");
    let request = source_provider_capacity_request();
    let (mut journal, _) = protected_open(&directory.0).unwrap();
    {
        let mut authority = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        let prepared = authority
            .prepare_global_capacity_reservation_v1(request, [11; 16])
            .unwrap();
        let admission = transaction(
            11,
            vec![
                JournalRecord::put(
                    RecordNamespace::SourceProviderAuthority,
                    b"owner".to_vec(),
                    b"admitted".to_vec(),
                ),
                prepared.record().clone(),
            ],
        );
        let preflight = authority
            .preflight_global_capacity_reservation_v1(&prepared, &admission)
            .unwrap();
        authority
            .commit_global_capacity_reservation_v1(&preflight, prepared, &admission)
            .unwrap();
    }

    // Leave one byte beyond the held promise, then grow the owner by two.
    // The owner alone fits, but its postimage plus the promise must not.
    journal.held.replace_limits_for_fixture_v1(JournalLimits {
        maximum_materialized_bytes: journal.native_view().materialized_bytes()
            + usize::try_from(request.terminal_bytes).unwrap() + 1,
        ..journal.native_view().limits()
    });
    let before_sequence = journal.snapshot_sequence();
    let before_length = journal.native_view().metadata().unwrap().len();
    let competing = transaction(
        12,
        vec![JournalRecord::put(
            RecordNamespace::SourceProviderAuthority,
            b"owner".to_vec(),
            b"admitted++".to_vec(),
        )],
    );
    let mut authority = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();

    assert!(matches!(
        authority.preflight_transactions(std::slice::from_ref(&competing)),
        Err(JournalError::LimitExceeded(
            "outstanding global capacity reservations"
        ))
    ));
    assert!(matches!(
        authority.commit(&competing),
        Err(JournalError::LimitExceeded(
            "outstanding global capacity reservations"
        ))
    ));
    assert_eq!(
        authority.get(b"owner").unwrap(),
        Some(b"admitted".as_slice())
    );
    drop(authority);

    assert_eq!(journal.snapshot_sequence(), before_sequence);
    assert_eq!(journal.native_view().metadata().unwrap().len(), before_length);
    assert!(journal.ensure_healthy().is_ok());
}

#[test]
fn source_provider_native_capacity_preserves_near_limit_terminal_space() {
    let mut request = source_provider_capacity_request();
    request.terminal_records = 2;
    request.poison_records = 2;
    let limits_with_terminal_slots = |slots: usize| JournalLimits {
        // Admission retains one owner and one reservation row. The held
        // terminal branch needs two further slots until settlement.
        maximum_materialized_records: 2 + slots,
        ..JournalLimits::default()
    };
    let admission = |prepared: &super::PreparedGlobalCapacityReservationV1| {
        transaction(
            11,
            vec![
                JournalRecord::put(
                    RecordNamespace::SourceProviderAuthority,
                    b"owner".to_vec(),
                    b"admitted".to_vec(),
                ),
                prepared.record().clone(),
            ],
        )
    };

    let too_small = TestDirectory::new("source-provider-capacity-one-terminal-slot");
    fs::set_permissions(&too_small.0, fs::Permissions::from_mode(0o700)).unwrap();
    let uid = fs::metadata(&too_small.0).unwrap().uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        &too_small.0,
        "protected.journal",
        limits_with_terminal_slots(1),
        uid,
    )
    .unwrap();
    let authority = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let prepared = authority
        .prepare_global_capacity_reservation_v1(request, [11; 16])
        .unwrap();
    assert!(matches!(
        authority.preflight_global_capacity_reservation_v1(&prepared, &admission(&prepared)),
        Err(JournalError::LimitExceeded(
            "outstanding global capacity reservations"
        ))
    ));
    assert_eq!(authority.records().unwrap().count(), 0);
    drop(authority);
    assert_eq!(journal.snapshot_sequence(), 1);
    drop(journal);

    let enough = TestDirectory::new("source-provider-capacity-two-terminal-slots");
    fs::set_permissions(&enough.0, fs::Permissions::from_mode(0o700)).unwrap();
    let uid = fs::metadata(&enough.0).unwrap().uid();
    let limits = limits_with_terminal_slots(2);
    let (mut journal, _) =
        Journal::open_protected_at_uid(&enough.0, "protected.journal", limits, uid).unwrap();
    let mut authority = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let prepared = authority
        .prepare_global_capacity_reservation_v1(request, [11; 16])
        .unwrap();
    let admission = admission(&prepared);
    let preflight = authority
        .preflight_global_capacity_reservation_v1(&prepared, &admission)
        .unwrap();
    let (_, reservation) = authority
        .commit_global_capacity_reservation_v1(&preflight, prepared, &admission)
        .unwrap();
    let competing = transaction(
        12,
        vec![JournalRecord::put(
            RecordNamespace::SourceProviderAuthority,
            b"competing".to_vec(),
            vec![1],
        )],
    );
    assert!(matches!(
        authority.commit(&competing),
        Err(JournalError::LimitExceeded(
            "outstanding global capacity reservations"
        ))
    ));
    assert_eq!(authority.get(b"competing").unwrap(), None);

    let terminal = transaction(
        13,
        vec![
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                b"owner".to_vec(),
                b"settled".to_vec(),
            ),
            reservation.settlement_record(),
        ],
    );
    let preflight = authority
        .preflight_reserved_terminal_v1(&reservation, &terminal)
        .unwrap();
    authority
        .commit_reserved_terminal_v1(&preflight, reservation, &terminal)
        .unwrap();
    drop(authority);
    drop(journal);

    let (mut reopened, _) =
        Journal::open_protected_at_uid(&enough.0, "protected.journal", limits, uid).unwrap();
    let authority = reopened
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    authority
        .validate_global_capacity_reservation_set_v1(&Default::default())
        .unwrap();
    assert_eq!(
        authority.get(b"owner").unwrap(),
        Some(b"settled".as_slice())
    );
    assert_eq!(authority.get(b"competing").unwrap(), None);
}
