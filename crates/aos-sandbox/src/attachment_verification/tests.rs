//! Durable verification codec and resource-commitment regressions.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use super::*;
use aos_sandbox_core::{IncarnationId, SandboxId};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use crate::{
    EffectFailure, EffectObservation, EffectPlan, EffectReceipt, JournalLimits, Reconciler,
    SingleNodeEffectExecutor,
};

struct NoEffects;

impl SingleNodeEffectExecutor for NoEffects {
    fn observe(
        &mut self,
        _: aos_sandbox_core::OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        panic!("verification tests must not observe effects")
    }

    fn apply(
        &mut self,
        _: aos_sandbox_core::OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        panic!("verification tests must not apply effects")
    }
}

fn open_journal() -> (tempfile::TempDir, Journal) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Journal::open_protected_at_uid(
        directory.path(),
        "controller.journal",
        JournalLimits::default(),
        std::fs::metadata(directory.path()).unwrap().uid(),
    )
    .unwrap()
    .0;
    (directory, journal)
}

fn record() -> Record {
    let mut record = Record {
        attachment_id: AttachmentId::from_bytes([1; 16]),
        desired_generation: 2,
        desired_record_digest: [3; 32],
        namespace_target: DurableNamespaceTargetReferenceV1::from_parts(
            SandboxId::from_bytes([4; 16]),
            IncarnationId::from_bytes([5; 16]),
            6,
            [7; 32],
            8,
            [9; 32],
        ),
        assignment_epoch: 10,
        assignment_generation: 11,
        assignment_digest: [12; 32],
        inventory_snapshot_digest: [13; 32],
        inventory_request_id: [14; 16],
        mount_handle: [15; 32],
        resource_revision: 16,
        resource_kernel_boot_id: [17; 16],
        recipe_digest: [18; 32],
        resource_digest: [19; 32],
        observation: ObservationRecord {
            unique_mount_id: 20,
            parent_mount_id: 21,
            mount_namespace_id: 22,
            device_major: 8,
            device_minor: 1,
            superblock_magic: 0xef53,
            superblock_flags: 23,
            mount_attributes: 24,
            propagation: 25,
            root: b"/source/root".to_vec(),
            mount_point: b"/destination/view".to_vec(),
            identity_map_digest: [26; 32],
        },
        digest: [0; 32],
    };
    record.digest = record.compute_digest();
    record
}

#[test]
fn codec_preserves_complete_post_attach_evidence() {
    let record = record();
    let encoded = record.encode();
    let decoded = Record::decode(&encoded).unwrap();

    assert_eq!(decoded, record);
    assert_eq!(encoded.len(), record.encoded_len());
    assert_eq!(record.key().len(), 24);
    record.validate_contents().unwrap();
}

#[test]
fn codec_rejects_every_changed_or_truncated_byte() {
    let encoded = record().encode();

    for index in 0..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        assert!(Record::decode(&changed).is_err(), "changed byte {index}");
        assert!(Record::decode(&encoded[..index]).is_err(), "length {index}");
    }
}

#[test]
fn observation_rejects_sentinel_and_unsafe_paths() {
    let mut candidate = record();
    candidate.observation.unique_mount_id = 0;
    candidate.digest = candidate.compute_digest();
    assert!(candidate.validate_contents().is_err());

    let mut candidate = record();
    candidate.observation.mount_point.push(0);
    candidate.digest = candidate.compute_digest();
    assert!(candidate.validate_contents().is_err());
}

#[test]
fn one_generation_replays_only_byte_exact_verification() {
    let record = record();
    let history = History {
        records: BTreeMap::from([(
            (record.attachment_id, record.desired_generation),
            record.clone(),
        )]),
        retained_bytes: record.encoded_len(),
    };
    assert_eq!(
        history.outcome(&record).unwrap(),
        Some(AttachmentVerificationOutcomeV1::Replay)
    );

    let mut changed = record;
    changed.observation.mount_attributes ^= 1;
    changed.digest = changed.compute_digest();
    assert!(matches!(
        history.outcome(&changed),
        Err(AttachmentVerificationError::Conflict)
    ));
}

#[test]
fn missing_cross_references_and_corruption_block_reconciliation() {
    let (_directory, mut journal) = open_journal();
    let record = record();
    journal.commit(&record.transaction().unwrap()).unwrap();
    assert!(matches!(
        validate_namespace(&mut journal),
        Err(AttachmentVerificationError::NamespaceTarget(error))
            if matches!(*error, NamespaceTargetError::CorruptState)
    ));

    let (_directory, mut journal) = open_journal();
    journal
        .commit(
            &JournalTransaction::new(
                [99; 16],
                vec![JournalRecord::put(NAMESPACE, vec![1; 24], vec![1])],
            )
            .unwrap(),
        )
        .unwrap();
    let mut reconciler = Reconciler::new(journal, NoEffects);
    assert!(matches!(
        reconciler.reconcile_next(),
        Err(crate::ReconcilerError::AttachmentVerification(error))
            if matches!(*error, AttachmentVerificationError::CorruptState)
    ));
}
