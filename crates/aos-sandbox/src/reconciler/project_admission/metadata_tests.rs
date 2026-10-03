//! Canonical retained metadata and nonauthorizing Effect-envelope regressions.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::RevocationScopeId;

use super::*;
use crate::journal::Journal;
use crate::lifecycle::protected_journal_join::source_domain_journal_limits;
use crate::reconciler::effect::{EffectLedgerRecord, EffectState, decode_effect, encode_effect};

fn metadata() -> ProjectAdmissionMetadata {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let uid = fs::metadata(directory.path()).unwrap().uid();
    let (journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "source-domains-v1.journal",
        source_domain_journal_limits(),
        uid,
    )
    .unwrap();
    let project = ProjectId::from_bytes([0x91; 16]);
    let names = journal.protected_writer_physical_names_v1().unwrap();
    let reservation = journal
        .preview_source_project_admission_reservation_v1([1; 16], project, names)
        .unwrap();
    ProjectAdmissionMetadata {
        admission_revision: ObjectDigest::from_bytes([2; 32]),
        admission_generation: 1,
        source_commitment: ObjectDigest::from_bytes([3; 32]),
        sandbox: SandboxId::from_bytes([4; 16]),
        project,
        reservation,
        capacity_id: [5; 32],
        phase: ProjectAdmissionPhase::Prepared,
        challenge: None,
        terminal: None,
        retired_floor: None,
        source_heads: HistoricalCreateProjectSourceHeadsV1 {
            projection_revision: ObjectDigest::from_bytes([6; 32]),
            publisher_generation: 1,
            publisher_digest: ObjectDigest::from_bytes([7; 32]),
            cache_domain_head: ObjectDigest::from_bytes([8; 32]),
            revocation_scope: RevocationScopeId::from_bytes([9; 16]),
            revocation_generation: 1,
            revocation_head: ObjectDigest::from_bytes([10; 32]),
        },
        // The codec retains bytes but intentionally cannot authenticate or
        // validate an original projection. The parent's full graph must do so.
        original_projection: vec![11, 12, 13],
    }
}

#[test]
fn metadata_canonical_bytes_reject_every_field_change_and_torn_row() {
    let metadata = metadata();
    let bytes = metadata.encode().unwrap();
    assert_eq!(ProjectAdmissionMetadata::decode(&bytes).unwrap(), metadata);
    for offset in [
        0, 8, 10, 11, 12, 16, 48, 56, 88, 104, 120, 152, 288, 520, 832, 992, 1024,
    ] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            ProjectAdmissionMetadata::decode(&changed).is_err(),
            "changed offset {offset}"
        );
    }
    for length in [0, 16, FIXED_BODY_BYTES, bytes.len() - 1] {
        assert!(ProjectAdmissionMetadata::decode(&bytes[..length]).is_err());
    }
    let mut padded = bytes;
    padded.push(0);
    assert!(ProjectAdmissionMetadata::decode(&padded).is_err());
}

#[test]
fn metadata_phase_cannot_substitute_terminal_or_retirement_authority() {
    let mut row = metadata();
    row.phase = ProjectAdmissionPhase::DispatchAuthorized;
    assert!(row.encode().is_ok());
    row.phase = ProjectAdmissionPhase::AcceptedRootTerminal;
    assert!(
        row.encode().is_err(),
        "accepted phase requires exact terminal bytes"
    );
    let cancellation =
        crate::policy_compiler::test_root_project_reservation_cancellation_v1(row.reservation);
    row.terminal = Some(RetainedRootProjectTerminal::Cancellation(cancellation));
    let accepted = row.acceptance_digest().unwrap();
    row.phase = ProjectAdmissionPhase::RootRetired;
    assert!(
        row.encode().is_err(),
        "retired phase requires an exact floor digest"
    );
    row.retired_floor = Some(ObjectDigest::from_bytes([14; 32]));
    assert_eq!(row.acceptance_digest().unwrap(), accepted);
    assert!(row.encode().is_ok());
    row.phase = ProjectAdmissionPhase::Prepared;
    assert!(
        row.encode().is_err(),
        "prepared cannot carry a terminal or historical floor"
    );
}

#[test]
fn project_effect_version_retains_legacy_bytes_and_never_completes_create() {
    let plan = crate::reconciler::tests::live_create_sandbox_plan(0xd1).effects[0].clone();
    let mut effect = EffectLedgerRecord {
        plan,
        state: EffectState::Planned,
        dispatch: None,
        project_admission: None,
    };
    let legacy = encode_effect(&effect).unwrap();
    assert_eq!(legacy[0], 3);
    assert_eq!(
        encode_effect(&decode_effect(&legacy).unwrap()).unwrap(),
        legacy
    );
    effect.project_admission = Some(metadata());
    let retained = encode_effect(&effect).unwrap();
    assert_eq!(retained[0], 5);
    assert_eq!(decode_effect(&retained).unwrap(), effect);
    effect.state = EffectState::PermanentlyBlocked {
        attempt: 1,
        diagnostic: "history is not completion".to_owned(),
    };
    assert!(encode_effect(&effect).is_err());
    let mut removed = retained;
    removed[0] = 3;
    assert!(
        decode_effect(&removed).is_err(),
        "legacy envelope cannot hide retained metadata"
    );
}
