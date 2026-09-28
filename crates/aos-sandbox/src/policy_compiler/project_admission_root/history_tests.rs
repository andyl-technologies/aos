//! Synthetic Controller claims joined to actual protected Source/Root terminals.
//!
//! These fixtures qualify historical row, signature, capacity, and cold-replay
//! semantics only. They do not qualify the installed Controller issuer, Source
//! genesis/antirollback, fixed peer transport, or public Create completion.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};
use ed25519_dalek::SigningKey;

use super::*;
use crate::journal::{
    GlobalCapacityReservationPurposeV1, JournalLimits, JournalRecord,
    SourceProjectAdmissionReservationV1,
};
use crate::lifecycle::protected_journal_join::source_domain_journal_limits;
use crate::policy_compiler::controller_project_terminal_readback::sign_synthetic_controller_project_terminal_v1;
use crate::policy_compiler::source_project_admission_readback::sign_test_source_project_completed_terminal_readback_v1;
use crate::policy_compiler::{
    RootProjectReservationCancellationProofV1, encode_controller_hold_signer_credential_v1,
    encode_source_hold_readback_signer_credential_v1,
};
use crate::reconciler::project_admission::AcceptedControllerProjectTerminalV1;

const CONTROLLER_UID: u32 = 811;
const CONTROLLER_GENERATION: u64 = 4;
const SOURCE_GENERATION: u64 = 5;

struct Fixture {
    source_directory: tempfile::TempDir,
    root_directory: tempfile::TempDir,
    source: Journal,
    root: Journal,
    uid: u32,
    claims: AcceptedControllerProjectTerminalV1,
    controller_key: SigningKey,
    source_key: SigningKey,
}

impl Fixture {
    fn canceled() -> Self {
        Self::canceled_with_root_limits(super::super::policy_authority_journal_limits(), |_, _| {})
    }

    fn canceled_with_root_limits(
        limits: JournalLimits,
        before_decision: impl FnOnce(&mut Journal, SourceProjectAdmissionReservationV1),
    ) -> Self {
        let source_directory = tempfile::tempdir().unwrap();
        let root_directory = tempfile::tempdir().unwrap();
        for directory in [source_directory.path(), root_directory.path()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let uid = fs::metadata(root_directory.path()).unwrap().uid();
        let (mut source, _) = Journal::open_protected_at_uid(
            source_directory.path(),
            "source-domains-v1.journal",
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        let (mut root, _) = Journal::open_protected_at_uid(
            root_directory.path(),
            "policy-authority-v1.journal",
            limits,
            uid,
        )
        .unwrap();
        let controller_key = SigningKey::from_bytes(&[11; 32]);
        let source_key = SigningKey::from_bytes(&[12; 32]);
        let controller_pin = encode_controller_hold_signer_credential_v1(
            CONTROLLER_GENERATION,
            &controller_key.verifying_key(),
        )
        .unwrap();
        let source_pin = encode_source_hold_readback_signer_credential_v1(
            SOURCE_GENERATION,
            &source_key.verifying_key(),
        )
        .unwrap();
        root.commit(
            &JournalTransaction::new(
                [1; 16],
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        super::super::CONTROLLER_HOLD_PIN_KEY.to_vec(),
                        controller_pin.to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        super::super::SOURCE_HOLD_PIN_KEY.to_vec(),
                        source_pin.to_vec(),
                    ),
                ],
            )
            .unwrap(),
        )
        .unwrap();

        let operation = OperationId::from_bytes([13; 16]);
        let source_commitment = ObjectDigest::from_bytes([14; 32]);
        let client_nonce =
            super::super::project_admission_client_nonce_v1(operation, source_commitment);
        let project = ProjectId::from_bytes([15; 16]);
        let names = source.protected_writer_physical_names_v1().unwrap();
        let reservation = source
            .preview_source_project_admission_reservation_v1(client_nonce, project, names)
            .unwrap();
        let intent =
            intent::prepare_test_retirement_intent_with_journal(&mut root, reservation).unwrap();
        assert_eq!(intent.capacity_request().future_transactions, 2);
        assert_eq!(
            source
                .record_source_project_admission_reservation_v1(client_nonce, project, names)
                .unwrap(),
            reservation
        );
        before_decision(&mut root, reservation);
        let marker =
            super::super::cancel_root_project_reservation_with_journal_v1(reservation, &mut root)
                .unwrap();
        source
            .settle_source_project_admission_reservation_v1(
                reservation,
                RootProjectReservationCancellationProofV1::from_test_marker(marker),
            )
            .unwrap();
        let decided = intent::current_intent(&mut root).unwrap().unwrap();
        assert_eq!(decided.capacity_request().future_transactions, 1);
        assert_eq!(decided.decision(), marker.record_digest());

        Self {
            source_directory,
            root_directory,
            source,
            root,
            uid,
            claims: AcceptedControllerProjectTerminalV1 {
                operation,
                sandbox: SandboxId::from_bytes([16; 16]),
                project,
                source_commitment,
                admission_revision: ObjectDigest::from_bytes([17; 32]),
                admission_generation: 1,
                accepted_metadata: ObjectDigest::from_bytes([18; 32]),
                reservation,
                challenge: None,
                root_terminal: marker.record_digest(),
                kind: RootProjectHistoryTerminalKindV1::CanceledReservation,
            },
            controller_key,
            source_key,
        }
    }

    fn controller_packet(
        &self,
    ) -> [u8; crate::policy_compiler::CONTROLLER_PROJECT_TERMINAL_READBACK_BYTES_V1] {
        sign_synthetic_controller_project_terminal_v1(
            &self.claims,
            CONTROLLER_UID,
            99,
            CONTROLLER_GENERATION,
            &self.controller_key,
        )
        .unwrap()
    }

    fn source_packet(
        &self,
    ) -> [u8; crate::policy_compiler::SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1] {
        sign_test_source_project_completed_terminal_readback_v1(
            &self.source,
            SOURCE_GENERATION,
            &self.source_key,
        )
        .unwrap()
    }

    fn retire(&mut self) -> Result<RootProjectHistoryFloorV1, PolicyDeploymentHeadErrorV1> {
        let controller = self.controller_packet();
        let source = self.source_packet();
        retire_root_project_history_with_journal(
            &mut self.root,
            &controller,
            &source,
            CONTROLLER_UID,
        )
    }

    fn reopen_root(&mut self) {
        self.reopen_root_after(|_| {});
    }

    fn reopen_root_after(&mut self, crash: impl FnOnce(&std::path::Path)) {
        // Replace only this owned writer. The fixture source directory/FD stays
        // retained, so reopening Root cannot manufacture another Source cut.
        let placeholder = Journal::open_protected_at_uid(
            self.root_directory.path(),
            "fixture-placeholder.journal",
            super::super::policy_authority_journal_limits(),
            self.uid,
        )
        .unwrap()
        .0;
        let old = std::mem::replace(&mut self.root, placeholder);
        drop(old);
        crash(
            &self
                .root_directory
                .path()
                .join("policy-authority-v1.journal"),
        );
        self.root = Journal::open_protected_at_uid(
            self.root_directory.path(),
            "policy-authority-v1.journal",
            super::super::policy_authority_journal_limits(),
            self.uid,
        )
        .unwrap()
        .0;
    }
}

#[test]
fn history_optional_stage_and_unrelated_writes_cannot_spend_terminal_suffix() {
    let mut limits = super::super::policy_authority_journal_limits();
    // Pins, intent, decision, floor: every guaranteed transaction fits exactly.
    // A stage and an unrelated append must each be refused before consuming it.
    limits.maximum_transactions = 4;
    let mut fixture = Fixture::canceled_with_root_limits(limits, |root, reservation| {
        let intent = intent::current_intent(root).unwrap().unwrap();
        let before = root.snapshot_sequence();
        // This synthetic stage uses the same fixed digests as the fixture
        // intent. It tests ordinary append accounting, not positive authority.
        let mut stage = RootProjectAdmissionStageV1 {
            client_nonce: reservation.client_nonce(),
            root_nonce: [83; 16],
            cut: zero_digest(),
            project: reservation.project(),
            packet_digest: ObjectDigest::from_bytes([21; 32]),
            input_digest: ObjectDigest::from_bytes([22; 32]),
            deployment_digest: ObjectDigest::from_bytes([23; 32]),
            prior_packet_digest: zero_digest(),
            prior_input_digest: zero_digest(),
            source_reservation_digest: reservation.record_digest(),
            issued_at: 10,
            expires_at: 30,
        };
        stage.cut = stage.expected_cut();
        assert!(
            root.claim_protected_authority(RecordNamespace::DesiredState)
                .unwrap()
                .commit(&super::super::stage_transaction(stage).unwrap())
                .is_err()
        );
        let unrelated = JournalTransaction::new(
            [84; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"unrelated".to_vec(),
                vec![1],
            )],
        )
        .unwrap();
        assert!(root.commit(&unrelated).is_err());
        assert_eq!(root.snapshot_sequence(), before);
        assert!(root.get(RecordNamespace::DesiredState, STAGE_KEY).is_none());
        assert_eq!(
            root.recover_global_capacity_reservation_v1(intent.capacity_id())
                .unwrap()
                .request()
                .future_transactions,
            2
        );
    });
    let floor = fixture.retire().unwrap();
    assert_eq!(
        floor.kind(),
        RootProjectHistoryTerminalKindV1::CanceledReservation
    );
    assert!(
        fixture
            .root
            .records(RecordNamespace::GlobalCapacityReservation)
            .next()
            .is_none()
    );
}

#[test]
fn history_torn_floor_cut_keeps_terminal_and_exact_retirement_capacity() {
    let mut fixture = Fixture::canceled();
    let path = fixture
        .root_directory
        .path()
        .join("policy-authority-v1.journal");
    let prefix = fs::read(&path).unwrap();
    let prior = intent::current_intent(&mut fixture.root).unwrap().unwrap();
    let floor = fixture.retire().unwrap();
    let complete = fs::read(&path).unwrap();
    let tail = &complete[prefix.len()..];

    // Exercise incomplete framing, a partial record set, and a missing final
    // commit byte. No partially written deletion may spend the final suffix.
    for cut in [1, tail.len() / 2, tail.len() - 1] {
        fixture.reopen_root_after(|path| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .unwrap();
            file.write_all(&prefix).unwrap();
            file.write_all(&tail[..cut]).unwrap();
            file.sync_data().unwrap();
        });
        assert_eq!(fs::read(&path).unwrap(), prefix);
        assert!(
            fixture
                .root
                .get(RecordNamespace::DesiredState, KEY)
                .is_none()
        );
        assert_eq!(
            intent::current_intent(&mut fixture.root).unwrap(),
            Some(prior)
        );
        assert!(
            fixture
                .root
                .get(
                    RecordNamespace::DesiredState,
                    &reservation_cancellation_key(fixture.claims.reservation.record_digest())
                )
                .is_some()
        );
        assert_eq!(
            fixture
                .root
                .recover_global_capacity_reservation_v1(prior.capacity_id())
                .unwrap()
                .request()
                .future_transactions,
            1
        );
        assert_eq!(fixture.retire().unwrap(), floor);
        assert_eq!(fs::read(&path).unwrap(), complete);
    }
}

#[test]
fn history_cancellation_floor_is_atomic_and_lost_reply_replays_exactly() {
    let mut fixture = Fixture::canceled();
    let reservation = fixture.claims.reservation;
    let before = fixture.root.snapshot_sequence();
    let floor = fixture.retire().unwrap();
    assert_eq!(
        floor.kind(),
        RootProjectHistoryTerminalKindV1::CanceledReservation
    );
    assert_eq!(floor.reservation_digest(), reservation.record_digest());
    assert_eq!(
        floor.controller_acceptance_digest(),
        fixture.claims.accepted_metadata
    );
    assert!(fixture.root.snapshot_sequence() > before);
    assert!(
        fixture
            .root
            .get(RecordNamespace::DesiredState, intent::KEY)
            .is_none()
    );
    assert!(
        fixture
            .root
            .get(
                RecordNamespace::DesiredState,
                &reservation_cancellation_key(reservation.record_digest())
            )
            .is_none()
    );
    assert!(
        fixture
            .root
            .records(RecordNamespace::GlobalCapacityReservation)
            .next()
            .is_none()
    );

    // The actual Source terminal alone remains fenced. Neither a Root floor
    // nor the synthetic Controller signature replaces the held Controller ACK.
    assert!(
        fixture
            .source
            .preview_source_project_admission_reservation_v1(
                reservation.client_nonce(),
                reservation.project(),
                reservation.names(),
            )
            .is_err()
    );
    fixture.reopen_root();
    let cut = fixture.root.snapshot_sequence();
    assert_eq!(fixture.retire().unwrap(), floor);
    assert_eq!(fixture.root.snapshot_sequence(), cut);
    assert_eq!(
        RootProjectHistoryFloorV1::from_record_bytes(&floor.record_bytes()).unwrap(),
        floor
    );
    assert!(fixture.source_directory.path().exists());
}

#[test]
fn history_rejects_validly_resigned_controller_equivocation_and_foreign_pin() {
    let mut fixture = Fixture::canceled();
    let cut = fixture.root.snapshot_sequence();
    let accepted = fixture.claims.accepted_metadata;
    fixture.claims.root_terminal = ObjectDigest::from_bytes([77; 32]);
    assert!(fixture.retire().is_err());
    assert_eq!(fixture.root.snapshot_sequence(), cut);
    fixture.claims.root_terminal = intent::current_intent(&mut fixture.root)
        .unwrap()
        .unwrap()
        .decision();
    let floor = fixture.retire().unwrap();

    fixture.claims.accepted_metadata = ObjectDigest::from_bytes([78; 32]);
    assert!(
        fixture.retire().is_err(),
        "equal issue with changed accepted metadata is not replay"
    );
    fixture.claims.accepted_metadata = accepted;
    fixture.source_key = SigningKey::from_bytes(&[79; 32]);
    assert!(
        fixture.retire().is_err(),
        "Root independently retains its Source role pin"
    );
    assert_eq!(
        fixture.root.get(RecordNamespace::DesiredState, KEY),
        Some(floor.record_bytes().as_slice())
    );
}

#[test]
fn history_suffix_cannot_be_consumed_by_arbitrary_desired_state_settlement() {
    let mut fixture = Fixture::canceled();
    let intent = intent::current_intent(&mut fixture.root).unwrap().unwrap();
    let reservation = fixture
        .root
        .recover_global_capacity_reservation_v1(intent.capacity_id())
        .unwrap();
    let transaction = JournalTransaction::new(
        [81; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                b"foreign-history".to_vec(),
                vec![1],
            ),
            reservation.settlement_record(),
        ],
    )
    .unwrap();
    let before = fixture.root.snapshot_sequence();
    let capacity = fixture
        .root
        .claim_global_capacity_reservation_authority(
            GlobalCapacityReservationPurposeV1::RootProjectAdmission,
        )
        .unwrap();
    assert!(
        capacity
            .preflight_reserved_terminal_v1(&reservation, &transaction)
            .is_err()
    );
    drop(capacity);
    assert_eq!(fixture.root.snapshot_sequence(), before);
    assert!(
        fixture.retire().is_ok(),
        "the exact terminal suffix remains available"
    );
}
