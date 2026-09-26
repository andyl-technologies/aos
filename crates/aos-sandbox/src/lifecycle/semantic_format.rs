//! Canonical method-family semantic fact encoding for current AOSLIF03 records,
//! with strict AOSLIF01/AOSLIF02 decoding.
//!
//! ```text
//! kind:1 | reserved:3 | read-count:4 | write-count:4 |
//! assignment-count:4 | reservation-count:4 | retention-count:4 |
//! fixed-method-evidence:936 (legacy:856/872) | method-header | reads | writes |
//! assignments | reservations | retention-acknowledgements
//! ```
//!
//! The fixed evidence area persists coordination/writer/dataset/thaw plus the
//! exact manifest and post-retention ledger, suspend, boot, and initial-
//! incarnation commitments.

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, ObjectDigest,
    OperationId, ResourceId, Revision, SandboxId, SnapshotId,
};

use super::LifecycleTimeV1;
use super::coordination::{
    LifecycleCoordinationPhaseV1, LifecycleDatasetTransactionDigestV1, LifecycleQuiesceDigestV1,
    LifecycleRetentionLedgerReceiptV1, LifecycleSuspendObservationDigestV1,
    LifecycleSuspendObservationV1, LifecycleThawCompensationDigestV1, LifecycleWriterFenceDigestV1,
};
use super::evidence::{
    LifecycleBootCommitFactV1, LifecycleBootRecordDigestV1, LifecycleCoordinationCommitFactV1,
    LifecycleCoordinationRecordDigestV1, LifecycleIncarnationCommitFactV1,
    LifecycleIncarnationOriginV1, LifecycleRetentionCommitFactV1, LifecycleRetentionLedgerDigestV1,
    LifecycleSemanticEvidenceV1,
};
use super::intent::{DesiredStateCasV1, LifecycleResourceV1, ResourceExpectedStateV1};
use super::intent::{DesiredStateFenceV1, LiveRuntimeFenceV1};
use super::model::{
    DesiredStateCasDigestV1, LifecycleResourceStateDigestV1, LifecycleSemanticCommitV1,
    MAXIMUM_LIFECYCLE_EXPECTATIONS,
};
use super::semantic::{
    LifecycleAssignmentCommitFactV1, LifecycleCascadePlanDigestV1, LifecycleCascadeTombstonePlanV1,
    LifecycleCommittedResourceV1, LifecycleDependencyEdgeV1, LifecycleMethodSemanticCommitV1,
    LifecycleReadCommitFactV1, LifecycleReservationCommitFactV1,
    LifecycleRetentionAcknowledgementV1, LifecycleRetentionClaimDigestV1,
    LifecycleSemanticCommitFactV1, LifecycleSnapshotManifestDigestV1,
    LifecycleSnapshotRetentionReleaseV1, LifecycleTransactionIdV1,
};
use super::snapshot::LifecycleSnapshotTombstoneDigestV1;

const MAXIMUM_SEMANTIC_FACT_BYTES: usize = 2 * 1024 * 1024;
const LEGACY_SEMANTIC_EVIDENCE_BYTES: usize = 856;
const HOST_BOOT_SEMANTIC_EVIDENCE_BYTES: usize = 872;
const CURRENT_SEMANTIC_EVIDENCE_BYTES: usize = 936;
const LIVE_FENCE_BYTES: usize = 104;

use super::LifecycleModelError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifecycleSemanticFactLayoutV1 {
    LegacyWithoutHostBoot,
    HostBootWithoutCoordinationBindings,
    Current,
}

impl LifecycleSemanticFactLayoutV1 {
    const fn has_host_boot(self) -> bool {
        !matches!(self, Self::LegacyWithoutHostBoot)
    }

    const fn has_coordination_bindings(self) -> bool {
        matches!(self, Self::Current)
    }
}

pub(super) fn encode_semantic_fact(
    value: &LifecycleMethodSemanticCommitV1,
) -> Result<Vec<u8>, LifecycleModelError> {
    encode_semantic_fact_with_layout(value, LifecycleSemanticFactLayoutV1::Current)
}

pub(super) fn encode_semantic_fact_with_layout(
    value: &LifecycleMethodSemanticCommitV1,
    layout: LifecycleSemanticFactLayoutV1,
) -> Result<Vec<u8>, LifecycleModelError> {
    if layout.has_coordination_bindings()
        && value
            .evidence()
            .coordination()
            .is_some_and(|fact| fact.manifest().is_none() || fact.retention_ledger().is_none())
    {
        return Err(LifecycleModelError::InvalidModel);
    }
    let mut bytes = Vec::new();
    let (kind, reads, writes, assignments, reservations, retention) = match value.facts() {
        LifecycleSemanticCommitFactV1::DesiredState {
            reads,
            resources,
            assignments,
            reservations,
            ..
        } => (
            1,
            reads,
            resources,
            assignments.as_slice(),
            reservations.as_slice(),
            &[][..],
        ),
        LifecycleSemanticCommitFactV1::Snapshot {
            reads,
            resources,
            assignments,
            reservations,
            retention,
            ..
        } => (
            2,
            reads,
            resources,
            assignments.as_slice(),
            reservations.as_slice(),
            retention.as_slice(),
        ),
        LifecycleSemanticCommitFactV1::DeleteSnapshot {
            reads, resources, ..
        } => (4, reads, resources, &[][..], &[][..], &[][..]),
        LifecycleSemanticCommitFactV1::CascadeDelete {
            reads,
            resources,
            assignments,
            reservations,
            ..
        } => (
            3,
            reads,
            resources,
            assignments.as_slice(),
            reservations.as_slice(),
            &[][..],
        ),
    };
    let variant_bytes = match value.facts() {
        LifecycleSemanticCommitFactV1::DesiredState { .. } => 0,
        LifecycleSemanticCommitFactV1::Snapshot { .. } => 48,
        LifecycleSemanticCommitFactV1::DeleteSnapshot { .. } => 176,
        LifecycleSemanticCommitFactV1::CascadeDelete { cascade, .. } => 200_usize
            .checked_add(
                cascade
                    .dependency_edges()
                    .len()
                    .checked_mul(34)
                    .ok_or(LifecycleModelError::InvalidModel)?,
            )
            .and_then(|total| total.checked_add(cascade.postorder().len().checked_mul(17)?))
            .ok_or(LifecycleModelError::InvalidModel)?,
    };
    let evidence_bytes = match layout {
        LifecycleSemanticFactLayoutV1::LegacyWithoutHostBoot => LEGACY_SEMANTIC_EVIDENCE_BYTES,
        LifecycleSemanticFactLayoutV1::HostBootWithoutCoordinationBindings => {
            HOST_BOOT_SEMANTIC_EVIDENCE_BYTES
        }
        LifecycleSemanticFactLayoutV1::Current => CURRENT_SEMANTIC_EVIDENCE_BYTES,
    };
    let length = 24_usize
        .checked_add(evidence_bytes)
        .and_then(|total| total.checked_add(variant_bytes))
        .and_then(|total| total.checked_add(reads.len().checked_mul(68)?))
        .and_then(|total| total.checked_add(writes.len().checked_mul(148)?))
        .and_then(|total| total.checked_add(assignments.len().checked_mul(40)?))
        .and_then(|total| total.checked_add(reservations.len().checked_mul(56)?))
        .and_then(|total| total.checked_add(retention.len().checked_mul(193)?))
        .filter(|total| *total <= MAXIMUM_SEMANTIC_FACT_BYTES)
        .ok_or(LifecycleModelError::InvalidModel)?;
    bytes
        .try_reserve_exact(length)
        .map_err(|_| LifecycleModelError::Allocation)?;
    bytes.push(kind);
    bytes.extend_from_slice(&[0; 3]);
    for count in [
        reads.len(),
        writes.len(),
        assignments.len(),
        reservations.len(),
        retention.len(),
    ] {
        push_count(&mut bytes, count);
    }
    encode_semantic_evidence(&mut bytes, value.evidence(), layout);
    match value.facts() {
        LifecycleSemanticCommitFactV1::DesiredState { .. } => {}
        LifecycleSemanticCommitFactV1::Snapshot {
            snapshot, manifest, ..
        } => {
            bytes.extend_from_slice(snapshot.as_bytes());
            bytes.extend_from_slice(manifest.digest().as_bytes());
        }
        LifecycleSemanticCommitFactV1::DeleteSnapshot {
            snapshot,
            tombstone,
            retention_release,
            ..
        } => {
            bytes.extend_from_slice(snapshot.as_bytes());
            bytes.extend_from_slice(tombstone.digest().as_bytes());
            bytes.extend_from_slice(retention_release.holder().as_bytes());
            bytes.extend_from_slice(&retention_release.predecessor_revision().get().to_be_bytes());
            bytes.extend_from_slice(&retention_release.successor_revision().get().to_be_bytes());
            bytes.extend_from_slice(retention_release.predecessor_ledger().digest().as_bytes());
            bytes.extend_from_slice(retention_release.successor_ledger().digest().as_bytes());
            bytes.extend_from_slice(retention_release.release().as_bytes());
        }
        LifecycleSemanticCommitFactV1::CascadeDelete { root, cascade, .. } => {
            bytes.extend_from_slice(root.as_bytes());
            bytes.extend_from_slice(cascade.transaction().get().as_bytes());
            bytes.extend_from_slice(cascade.plan().digest().as_bytes());
            bytes.extend_from_slice(cascade.dependency_snapshot().as_bytes());
            bytes.extend_from_slice(cascade.coordination_record().digest().as_bytes());
            bytes.extend_from_slice(cascade.dataset_transaction().digest().as_bytes());
            bytes.extend_from_slice(cascade.manifest().digest().as_bytes());
            push_count(&mut bytes, cascade.dependency_edges().len());
            push_count(&mut bytes, cascade.postorder().len());
            for edge in cascade.dependency_edges() {
                encode_resource(&mut bytes, edge.dependent());
                encode_resource(&mut bytes, edge.dependency());
            }
            for resource in cascade.postorder() {
                encode_resource(&mut bytes, *resource);
            }
        }
    }
    for read in reads {
        encode_expected_resource(&mut bytes, read.resource(), read.expected());
    }
    for write in writes {
        encode_expected_resource(&mut bytes, write.resource(), write.predecessor());
        bytes.extend_from_slice(&write.successor_revision().get().to_be_bytes());
        bytes.extend_from_slice(write.successor_state().digest().as_bytes());
        bytes.push(u8::from(write.desired_state_transition().is_some()));
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(
            write
                .desired_state_transition()
                .map_or(ObjectDigest::from_bytes([0; 32]), |digest| digest.digest())
                .as_bytes(),
        );
    }
    for assignment in assignments {
        bytes.extend_from_slice(assignment.sandbox().as_bytes());
        bytes.extend_from_slice(assignment.assignment().as_bytes());
        bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
    }
    for reservation in reservations {
        bytes.extend_from_slice(reservation.reservation().as_bytes());
        bytes.extend_from_slice(&reservation.revision().get().to_be_bytes());
        bytes.extend_from_slice(reservation.state().digest().as_bytes());
    }
    for acknowledgement in retention {
        bytes.extend_from_slice(&acknowledgement.claim_index().to_be_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(acknowledgement.snapshot().as_bytes());
        encode_resource(&mut bytes, acknowledgement.resource());
        bytes.extend_from_slice(acknowledgement.holder().as_bytes());
        bytes.extend_from_slice(acknowledgement.claim().digest().as_bytes());
        bytes.extend_from_slice(&acknowledgement.revision().get().to_be_bytes());
        bytes.extend_from_slice(acknowledgement.ledger().digest().as_bytes());
        bytes.extend_from_slice(acknowledgement.claim_receipt().as_bytes());
        bytes.extend_from_slice(acknowledgement.receipt().digest().as_bytes());
    }
    if bytes.len() != length {
        return Err(LifecycleModelError::InvalidModel);
    }
    Ok(bytes)
}

pub(super) fn preflight_semantic_fact_with_layout(
    bytes: &[u8],
    layout: LifecycleSemanticFactLayoutV1,
) -> Result<(), LifecycleModelError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() > MAXIMUM_SEMANTIC_FACT_BYTES {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let mut remaining = bytes;
    let kind = take::<1>(&mut remaining)?[0];
    if take::<3>(&mut remaining)? != [0; 3] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let reads = bounded_fact_count(&mut remaining)?;
    let writes = bounded_fact_count(&mut remaining)?;
    let assignments = bounded_fact_count(&mut remaining)?;
    let reservations = bounded_fact_count(&mut remaining)?;
    let retention = bounded_fact_count(&mut remaining)?;
    take_slice(
        &mut remaining,
        match layout {
            LifecycleSemanticFactLayoutV1::LegacyWithoutHostBoot => LEGACY_SEMANTIC_EVIDENCE_BYTES,
            LifecycleSemanticFactLayoutV1::HostBootWithoutCoordinationBindings => {
                HOST_BOOT_SEMANTIC_EVIDENCE_BYTES
            }
            LifecycleSemanticFactLayoutV1::Current => CURRENT_SEMANTIC_EVIDENCE_BYTES,
        },
    )?;
    match kind {
        1 => {}
        2 => {
            take_slice(&mut remaining, 48)?;
        }
        3 => {
            take_slice(&mut remaining, 192)?;
            let edges = bounded_fact_count(&mut remaining)?;
            let postorder = bounded_fact_count(&mut remaining)?;
            let graph_bytes = edges
                .checked_mul(34)
                .and_then(|value| value.checked_add(postorder.checked_mul(17)?))
                .ok_or(LifecycleModelError::CorruptEncoding)?;
            take_slice(&mut remaining, graph_bytes)?;
        }
        4 => {
            take_slice(&mut remaining, 176)?;
        }
        _ => return Err(LifecycleModelError::CorruptEncoding),
    }
    let variable = reads
        .checked_mul(68)
        .and_then(|value| value.checked_add(writes.checked_mul(148)?))
        .and_then(|value| value.checked_add(assignments.checked_mul(40)?))
        .and_then(|value| value.checked_add(reservations.checked_mul(56)?))
        .and_then(|value| value.checked_add(retention.checked_mul(193)?))
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    take_slice(&mut remaining, variable)?;
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(LifecycleModelError::CorruptEncoding)
    }
}

pub(super) fn decode_semantic_fact_with_layout(
    bytes: &[u8],
    witness: Option<LifecycleSemanticCommitV1>,
    layout: LifecycleSemanticFactLayoutV1,
) -> Result<Option<(LifecycleSemanticCommitFactV1, LifecycleSemanticEvidenceV1)>, LifecycleModelError>
{
    if bytes.is_empty() {
        return Ok(None);
    }
    let witness = witness.ok_or(LifecycleModelError::CorruptEncoding)?;
    let cas = witness.desired_state_cas();
    let mut remaining = bytes;
    let kind = take::<1>(&mut remaining)?[0];
    if take::<3>(&mut remaining)? != [0; 3] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let read_count = bounded_fact_count(&mut remaining)?;
    let write_count = bounded_fact_count(&mut remaining)?;
    let assignment_count = bounded_fact_count(&mut remaining)?;
    let reservation_count = bounded_fact_count(&mut remaining)?;
    let retention_count = bounded_fact_count(&mut remaining)?;
    let evidence = decode_semantic_evidence(&mut remaining, layout)?;
    let snapshot = if kind == 2 {
        Some((
            SnapshotId::from_bytes(take(&mut remaining)?),
            LifecycleSnapshotManifestDigestV1::from_stored(ObjectDigest::from_bytes(take(
                &mut remaining,
            )?))?,
        ))
    } else {
        None
    };
    let cascade = if kind == 3 {
        let root = SandboxId::from_bytes(take(&mut remaining)?);
        let transaction =
            LifecycleTransactionIdV1::new(ResourceId::from_bytes(take(&mut remaining)?))
                .map_err(|_| LifecycleModelError::CorruptEncoding)?;
        let stored_plan = LifecycleCascadePlanDigestV1::from_stored(ObjectDigest::from_bytes(
            take(&mut remaining)?,
        ))?;
        let dependency_snapshot = ObjectDigest::from_bytes(take(&mut remaining)?);
        if dependency_snapshot.as_bytes() == &[0; 32] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        let coordination_record = LifecycleCoordinationRecordDigestV1::from_stored(
            ObjectDigest::from_bytes(take(&mut remaining)?),
        )?;
        let dataset_transaction = LifecycleDatasetTransactionDigestV1::from_stored(
            ObjectDigest::from_bytes(take(&mut remaining)?),
        )?;
        let manifest = LifecycleSnapshotManifestDigestV1::from_stored(ObjectDigest::from_bytes(
            take(&mut remaining)?,
        ))?;
        let edge_count = bounded_fact_count(&mut remaining)?;
        let postorder_count = bounded_fact_count(&mut remaining)?;
        let mut dependency_edges = Vec::new();
        dependency_edges
            .try_reserve_exact(edge_count)
            .map_err(|_| LifecycleModelError::Allocation)?;
        for _ in 0..edge_count {
            dependency_edges.push(
                LifecycleDependencyEdgeV1::new(
                    decode_resource(&mut remaining)?,
                    decode_resource(&mut remaining)?,
                )
                .map_err(|_| LifecycleModelError::CorruptEncoding)?,
            );
        }
        let mut postorder = Vec::new();
        postorder
            .try_reserve_exact(postorder_count)
            .map_err(|_| LifecycleModelError::Allocation)?;
        for _ in 0..postorder_count {
            postorder.push(decode_resource(&mut remaining)?);
        }
        let cascade = LifecycleCascadeTombstonePlanV1::new(
            transaction,
            dependency_snapshot,
            coordination_record,
            dataset_transaction,
            manifest,
            dependency_edges,
            postorder,
        )
        .map_err(|_| LifecycleModelError::CorruptEncoding)?;
        if cascade.plan() != stored_plan {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        Some((root, cascade))
    } else {
        None
    };
    let snapshot_deletion = if kind == 4 {
        let snapshot = SnapshotId::from_bytes(take(&mut remaining)?);
        let tombstone = LifecycleSnapshotTombstoneDigestV1::from_stored(ObjectDigest::from_bytes(
            take(&mut remaining)?,
        ))?;
        Some((
            LifecycleSnapshotRetentionReleaseV1::from_stored(
                snapshot,
                ResourceId::from_bytes(take(&mut remaining)?),
                Revision::new(u64::from_be_bytes(take(&mut remaining)?)),
                Revision::new(u64::from_be_bytes(take(&mut remaining)?)),
                LifecycleRetentionLedgerDigestV1::from_stored(ObjectDigest::from_bytes(take(
                    &mut remaining,
                )?))?,
                LifecycleRetentionLedgerDigestV1::from_stored(ObjectDigest::from_bytes(take(
                    &mut remaining,
                )?))?,
                ObjectDigest::from_bytes(take(&mut remaining)?),
            )?,
            tombstone,
        ))
    } else {
        None
    };
    let mut reads = Vec::new();
    reads
        .try_reserve_exact(read_count)
        .map_err(|_| LifecycleModelError::Allocation)?;
    for _ in 0..read_count {
        let (resource, expected) = decode_expected_resource(&mut remaining)?;
        reads.push(LifecycleReadCommitFactV1::new(resource, expected));
    }
    let mut writes = Vec::new();
    writes
        .try_reserve_exact(write_count)
        .map_err(|_| LifecycleModelError::Allocation)?;
    for _ in 0..write_count {
        let (resource, predecessor) = decode_expected_resource(&mut remaining)?;
        let revision = Revision::new(u64::from_be_bytes(take(&mut remaining)?));
        let state = LifecycleResourceStateDigestV1::from_stored(ObjectDigest::from_bytes(take(
            &mut remaining,
        )?))?;
        let desired_present = take::<1>(&mut remaining)?[0];
        if desired_present > 1 || take::<7>(&mut remaining)? != [0; 7] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        let desired_digest = ObjectDigest::from_bytes(take(&mut remaining)?);
        let desired_state_transition = match desired_present {
            0 if desired_digest.as_bytes() == &[0; 32] => None,
            1 => Some(DesiredStateCasDigestV1::from_stored(desired_digest)?),
            _ => return Err(LifecycleModelError::CorruptEncoding),
        };
        writes.push(
            LifecycleCommittedResourceV1::new(
                resource,
                predecessor,
                revision,
                state,
                desired_state_transition,
            )
            .map_err(|_| LifecycleModelError::CorruptEncoding)?,
        );
    }
    let mut assignments = Vec::new();
    assignments
        .try_reserve_exact(assignment_count)
        .map_err(|_| LifecycleModelError::Allocation)?;
    for _ in 0..assignment_count {
        assignments.push(
            LifecycleAssignmentCommitFactV1::new(
                SandboxId::from_bytes(take(&mut remaining)?),
                ResourceId::from_bytes(take(&mut remaining)?),
                AssignmentEpoch::new(u64::from_be_bytes(take(&mut remaining)?)),
            )
            .map_err(|_| LifecycleModelError::CorruptEncoding)?,
        );
    }
    let mut reservations = Vec::new();
    reservations
        .try_reserve_exact(reservation_count)
        .map_err(|_| LifecycleModelError::Allocation)?;
    for _ in 0..reservation_count {
        reservations.push(
            LifecycleReservationCommitFactV1::new(
                ResourceId::from_bytes(take(&mut remaining)?),
                Revision::new(u64::from_be_bytes(take(&mut remaining)?)),
                LifecycleResourceStateDigestV1::from_stored(ObjectDigest::from_bytes(take(
                    &mut remaining,
                )?))?,
            )
            .map_err(|_| LifecycleModelError::CorruptEncoding)?,
        );
    }
    let mut retention = Vec::new();
    retention
        .try_reserve_exact(retention_count)
        .map_err(|_| LifecycleModelError::Allocation)?;
    for _ in 0..retention_count {
        let claim_index = u32::from_be_bytes(take(&mut remaining)?);
        if take::<4>(&mut remaining)? != [0; 4] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        retention.push(
            LifecycleRetentionAcknowledgementV1::from_stored(
                claim_index,
                SnapshotId::from_bytes(take(&mut remaining)?),
                decode_resource(&mut remaining)?,
                ResourceId::from_bytes(take(&mut remaining)?),
                LifecycleRetentionClaimDigestV1::from_stored(ObjectDigest::from_bytes(take(
                    &mut remaining,
                )?))?,
                Revision::new(u64::from_be_bytes(take(&mut remaining)?)),
                LifecycleRetentionLedgerDigestV1::from_stored(ObjectDigest::from_bytes(take(
                    &mut remaining,
                )?))?,
                ObjectDigest::from_bytes(take(&mut remaining)?),
                LifecycleRetentionLedgerReceiptV1::from_stored(ObjectDigest::from_bytes(take(
                    &mut remaining,
                )?))?,
            )
            .map_err(|_| LifecycleModelError::CorruptEncoding)?,
        );
    }
    if !remaining.is_empty() {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let facts = match (kind, snapshot, cascade, snapshot_deletion) {
        (1, None, None, None) if retention.is_empty() => {
            LifecycleSemanticCommitFactV1::DesiredState {
                cas,
                reads,
                resources: writes,
                assignments,
                reservations,
            }
        }
        (2, Some((snapshot, manifest)), None, None) => LifecycleSemanticCommitFactV1::Snapshot {
            cas,
            reads,
            snapshot,
            manifest,
            resources: writes,
            assignments,
            reservations,
            retention,
        },
        (3, None, Some((root, cascade)), None) if retention.is_empty() => {
            LifecycleSemanticCommitFactV1::CascadeDelete {
                cas,
                reads,
                root,
                cascade,
                resources: writes,
                assignments,
                reservations,
            }
        }
        (4, None, None, Some((retention_release, tombstone)))
            if retention.is_empty() && assignments.is_empty() && reservations.is_empty() =>
        {
            LifecycleSemanticCommitFactV1::DeleteSnapshot {
                cas,
                reads,
                snapshot: retention_release.snapshot(),
                tombstone,
                resources: writes,
                retention_release,
            }
        }
        _ => return Err(LifecycleModelError::CorruptEncoding),
    };
    Ok(Some((facts, evidence)))
}

fn encode_semantic_evidence(
    bytes: &mut Vec<u8>,
    value: &LifecycleSemanticEvidenceV1,
    layout: LifecycleSemanticFactLayoutV1,
) {
    if let Some(fact) = value.coordination() {
        encode_presence(bytes, true);
        bytes.extend_from_slice(fact.transaction().get().as_bytes());
        bytes.extend_from_slice(fact.sandbox().as_bytes());
        bytes.push(fact.phase() as u8);
        bytes.extend_from_slice(&[0; 7]);
        encode_live_fence(bytes, fact.fence());
        encode_optional_raw_digest(bytes, fact.quiesce().map(|value| value.digest()));
        encode_optional_raw_digest(bytes, fact.writer_fence().map(|value| value.digest()));
        encode_optional_raw_digest(
            bytes,
            fact.dataset_transaction().map(|value| value.digest()),
        );
        bytes.extend_from_slice(fact.thaw_compensation().digest().as_bytes());
        if layout.has_coordination_bindings() {
            bytes.extend_from_slice(
                fact.manifest()
                    .map_or(ObjectDigest::from_bytes([0; 32]), |value| value.digest())
                    .as_bytes(),
            );
            bytes.extend_from_slice(
                fact.retention_ledger()
                    .map_or(ObjectDigest::from_bytes([0; 32]), |value| value.digest())
                    .as_bytes(),
            );
        }
        bytes.extend_from_slice(fact.record().digest().as_bytes());
    } else {
        bytes.extend_from_slice(&[0; 312]);
        if layout.has_coordination_bindings() {
            bytes.extend_from_slice(&[0; 64]);
        }
    }
    if let Some(fact) = value.retention() {
        encode_presence(bytes, true);
        bytes.extend_from_slice(&fact.revision().get().to_be_bytes());
        bytes.extend_from_slice(fact.record().digest().as_bytes());
    } else {
        bytes.extend_from_slice(&[0; 48]);
    }
    if let Some(record) = value.suspend() {
        encode_presence(bytes, true);
        bytes.extend_from_slice(record.operation().as_bytes());
        bytes.extend_from_slice(&record.operation_revision().get().to_be_bytes());
        bytes.extend_from_slice(record.operation_record().digest().as_bytes());
        encode_live_fence(bytes, record.fence());
        if layout.has_host_boot() {
            bytes.extend_from_slice(&record.host_boot());
        }
        bytes.extend_from_slice(record.observation().digest().as_bytes());
        bytes.extend_from_slice(&record.observed_at().get().to_be_bytes());
    } else {
        bytes.extend_from_slice(&[0; 208]);
        if layout.has_host_boot() {
            bytes.extend_from_slice(&[0; 16]);
        }
    }
    if let Some(fact) = value.boot() {
        encode_presence(bytes, true);
        encode_live_fence(bytes, fact.fence());
        bytes.extend_from_slice(&fact.observed_at().get().to_be_bytes());
        bytes.extend_from_slice(fact.record().digest().as_bytes());
    } else {
        bytes.extend_from_slice(&[0; 152]);
    }
    if let Some(fact) = value.incarnation() {
        encode_presence(bytes, true);
        let (kind, snapshot) = match fact.origin() {
            LifecycleIncarnationOriginV1::Created => (1, None),
            LifecycleIncarnationOriginV1::Forked(snapshot) => (2, Some(snapshot)),
            LifecycleIncarnationOriginV1::Restored(snapshot) => (3, Some(snapshot)),
        };
        bytes.push(kind);
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(
            snapshot
                .map_or(SnapshotId::from_bytes([0; 16]), |snapshot| snapshot)
                .as_bytes(),
        );
        encode_live_fence(bytes, fact.fence());
    } else {
        bytes.extend_from_slice(&[0; 136]);
    }
}

fn decode_semantic_evidence(
    bytes: &mut &[u8],
    layout: LifecycleSemanticFactLayoutV1,
) -> Result<LifecycleSemanticEvidenceV1, LifecycleModelError> {
    let coordination = if decode_presence(bytes)? {
        let transaction = LifecycleTransactionIdV1::new(ResourceId::from_bytes(take(bytes)?))
            .map_err(|_| LifecycleModelError::CorruptEncoding)?;
        let sandbox = SandboxId::from_bytes(take(bytes)?);
        let phase = decode_coordination_phase(take::<1>(bytes)?[0])?;
        if take::<7>(bytes)? != [0; 7] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        let fence = decode_live_fence(bytes)?;
        if sandbox.as_bytes() == &[0; 16] || fence.sandbox() != sandbox {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        let quiesce = decode_optional_raw_digest(bytes)?
            .map(LifecycleQuiesceDigestV1::from_stored)
            .transpose()?;
        let writer_fence = decode_optional_raw_digest(bytes)?
            .map(LifecycleWriterFenceDigestV1::from_stored)
            .transpose()?;
        let dataset_transaction = decode_optional_raw_digest(bytes)?
            .map(LifecycleDatasetTransactionDigestV1::from_stored)
            .transpose()?;
        let thaw_compensation =
            LifecycleThawCompensationDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
        let (manifest, retention_ledger) = if layout.has_coordination_bindings() {
            (
                Some(LifecycleSnapshotManifestDigestV1::from_stored(
                    ObjectDigest::from_bytes(take(bytes)?),
                )?),
                Some(LifecycleRetentionLedgerDigestV1::from_stored(
                    ObjectDigest::from_bytes(take(bytes)?),
                )?),
            )
        } else {
            (None, None)
        };
        let evidence_shape = match phase {
            LifecycleCoordinationPhaseV1::Admitted => {
                quiesce.is_none() && writer_fence.is_none() && dataset_transaction.is_none()
            }
            LifecycleCoordinationPhaseV1::Frozen => {
                quiesce.is_some() && writer_fence.is_some() && dataset_transaction.is_none()
            }
            LifecycleCoordinationPhaseV1::Compensated => {
                quiesce.is_some() && writer_fence.is_some()
            }
            LifecycleCoordinationPhaseV1::DatasetCommitted
            | LifecycleCoordinationPhaseV1::Thawed => {
                quiesce.is_some() && writer_fence.is_some() && dataset_transaction.is_some()
            }
        };
        if !evidence_shape {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        Some(LifecycleCoordinationCommitFactV1::from_stored(
            transaction,
            sandbox,
            fence,
            phase,
            quiesce,
            writer_fence,
            dataset_transaction,
            thaw_compensation,
            manifest,
            retention_ledger,
            LifecycleCoordinationRecordDigestV1::from_stored(ObjectDigest::from_bytes(take(
                bytes,
            )?))?,
        ))
    } else {
        require_zero(bytes, 304)?;
        if layout.has_coordination_bindings() {
            require_zero(bytes, 64)?;
        }
        None
    };
    let retention = if decode_presence(bytes)? {
        let revision = Revision::new(u64::from_be_bytes(take(bytes)?));
        if revision.get() == 0 || revision.get() == u64::MAX {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        Some(LifecycleRetentionCommitFactV1::from_stored(
            revision,
            LifecycleRetentionLedgerDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?,
        ))
    } else {
        require_zero(bytes, 40)?;
        None
    };
    let suspend = if decode_presence(bytes)? {
        let operation = OperationId::from_bytes(take(bytes)?);
        let revision = Revision::new(u64::from_be_bytes(take(bytes)?));
        let record =
            super::LifecycleRecordDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
        let fence = decode_live_fence(bytes)?;
        let host_boot = layout.has_host_boot().then(|| take(bytes)).transpose()?;
        let observation = LifecycleSuspendObservationDigestV1::from_stored(
            ObjectDigest::from_bytes(take(bytes)?),
        )?;
        let observed_at = LifecycleTimeV1::from_stored(u64::from_be_bytes(take(bytes)?))?;
        Some(match host_boot {
            Some(host_boot) => LifecycleSuspendObservationV1::from_stored(
                operation,
                revision,
                record,
                fence,
                host_boot,
                observation,
                observed_at,
            )?,
            None => LifecycleSuspendObservationV1::from_legacy_stored(
                operation,
                revision,
                record,
                fence,
                observation,
                observed_at,
            )?,
        })
    } else {
        require_zero(
            bytes,
            match layout {
                LifecycleSemanticFactLayoutV1::LegacyWithoutHostBoot => 200,
                LifecycleSemanticFactLayoutV1::HostBootWithoutCoordinationBindings
                | LifecycleSemanticFactLayoutV1::Current => 216,
            },
        )?;
        None
    };
    let boot = if decode_presence(bytes)? {
        Some(LifecycleBootCommitFactV1::from_stored(
            decode_live_fence(bytes)?,
            LifecycleTimeV1::from_stored(u64::from_be_bytes(take(bytes)?))?,
            LifecycleBootRecordDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?,
        ))
    } else {
        require_zero(bytes, 144)?;
        None
    };
    let incarnation = if decode_presence(bytes)? {
        let kind = take::<1>(bytes)?[0];
        if take::<7>(bytes)? != [0; 7] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        let snapshot = SnapshotId::from_bytes(take(bytes)?);
        let origin = match kind {
            1 if snapshot.as_bytes() == &[0; 16] => LifecycleIncarnationOriginV1::Created,
            2 if snapshot.as_bytes() != &[0; 16] => LifecycleIncarnationOriginV1::Forked(snapshot),
            3 if snapshot.as_bytes() != &[0; 16] => {
                LifecycleIncarnationOriginV1::Restored(snapshot)
            }
            _ => return Err(LifecycleModelError::CorruptEncoding),
        };
        Some(LifecycleIncarnationCommitFactV1::new(
            origin,
            decode_live_fence(bytes)?,
        ))
    } else {
        require_zero(bytes, 128)?;
        None
    };
    Ok(LifecycleSemanticEvidenceV1::new(
        coordination,
        retention,
        suspend,
        boot,
        incarnation,
    ))
}

fn encode_presence(bytes: &mut Vec<u8>, present: bool) {
    bytes.push(u8::from(present));
    bytes.extend_from_slice(&[0; 7]);
}

fn encode_optional_raw_digest(bytes: &mut Vec<u8>, value: Option<ObjectDigest>) {
    bytes.extend_from_slice(
        value
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
}

fn decode_optional_raw_digest(
    bytes: &mut &[u8],
) -> Result<Option<ObjectDigest>, LifecycleModelError> {
    let digest = ObjectDigest::from_bytes(take(bytes)?);
    Ok((digest.as_bytes() != &[0; 32]).then_some(digest))
}

fn decode_presence(bytes: &mut &[u8]) -> Result<bool, LifecycleModelError> {
    let present = take::<1>(bytes)?[0];
    if present > 1 || take::<7>(bytes)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    Ok(present == 1)
}

fn require_zero(bytes: &mut &[u8], count: usize) -> Result<(), LifecycleModelError> {
    if take_slice(bytes, count)?.iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        Err(LifecycleModelError::CorruptEncoding)
    }
}

fn encode_live_fence(bytes: &mut Vec<u8>, fence: LiveRuntimeFenceV1) {
    let desired = fence.desired();
    bytes.push(desired.resource().code());
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(desired.resource().as_bytes());
    bytes.extend_from_slice(&desired.expected_generation().get().to_be_bytes());
    bytes.extend_from_slice(&desired.resource_revision().get().to_be_bytes());
    bytes.extend_from_slice(desired.resource_state().digest().as_bytes());
    bytes.extend_from_slice(fence.incarnation().as_bytes());
    bytes.extend_from_slice(&fence.assignment_epoch().get().to_be_bytes());
    bytes.extend_from_slice(&fence.namespace_generation().get().to_be_bytes());
}

fn decode_live_fence(bytes: &mut &[u8]) -> Result<LiveRuntimeFenceV1, LifecycleModelError> {
    let resource_code = take::<1>(bytes)?[0];
    if take::<7>(bytes)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let resource = LifecycleResourceV1::from_code(resource_code, take(bytes)?)?;
    let desired = DesiredStateFenceV1::new(
        resource,
        DesiredGeneration::new(u64::from_be_bytes(take(bytes)?)),
        Revision::new(u64::from_be_bytes(take(bytes)?)),
        LifecycleResourceStateDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?,
    )
    .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    let sandbox = match resource {
        LifecycleResourceV1::Sandbox(sandbox) => sandbox,
        _ => return Err(LifecycleModelError::CorruptEncoding),
    };
    LiveRuntimeFenceV1::new(
        sandbox,
        desired,
        IncarnationId::from_bytes(take(bytes)?),
        AssignmentEpoch::new(u64::from_be_bytes(take(bytes)?)),
        NamespaceGeneration::new(u64::from_be_bytes(take(bytes)?)),
    )
    .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn decode_coordination_phase(
    value: u8,
) -> Result<LifecycleCoordinationPhaseV1, LifecycleModelError> {
    match value {
        1 => Ok(LifecycleCoordinationPhaseV1::Admitted),
        2 => Ok(LifecycleCoordinationPhaseV1::Frozen),
        3 => Ok(LifecycleCoordinationPhaseV1::DatasetCommitted),
        4 => Ok(LifecycleCoordinationPhaseV1::Thawed),
        5 => Ok(LifecycleCoordinationPhaseV1::Compensated),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}

fn encode_resource(bytes: &mut Vec<u8>, resource: LifecycleResourceV1) {
    bytes.push(resource.code());
    bytes.extend_from_slice(resource.as_bytes());
}

fn decode_resource(bytes: &mut &[u8]) -> Result<LifecycleResourceV1, LifecycleModelError> {
    LifecycleResourceV1::from_code(take::<1>(bytes)?[0], take(bytes)?)
}

pub(super) fn encode_expected_resource(
    bytes: &mut Vec<u8>,
    resource: LifecycleResourceV1,
    expected: ResourceExpectedStateV1,
) {
    bytes.push(resource.code());
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(resource.as_bytes());
    match expected {
        ResourceExpectedStateV1::Absent => bytes.extend_from_slice(&[0; 48]),
        ResourceExpectedStateV1::Present {
            revision,
            state_digest,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 7]);
            bytes.extend_from_slice(&revision.get().to_be_bytes());
            bytes.extend_from_slice(state_digest.digest().as_bytes());
        }
    }
}

pub(super) fn decode_expected_resource(
    bytes: &mut &[u8],
) -> Result<(LifecycleResourceV1, ResourceExpectedStateV1), LifecycleModelError> {
    let kind = take::<1>(bytes)?[0];
    if take::<3>(bytes)? != [0; 3] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let resource = LifecycleResourceV1::from_code(kind, take(bytes)?)?;
    let present = take::<1>(bytes)?[0];
    if take::<7>(bytes)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let revision = u64::from_be_bytes(take(bytes)?);
    let digest = ObjectDigest::from_bytes(take(bytes)?);
    let expected = match (present, revision, digest.as_bytes() == &[0; 32]) {
        (0, 0, true) => ResourceExpectedStateV1::Absent,
        (1, value, false) => ResourceExpectedStateV1::Present {
            revision: Revision::new(value),
            state_digest: LifecycleResourceStateDigestV1::from_stored(digest)?,
        },
        _ => return Err(LifecycleModelError::CorruptEncoding),
    };
    Ok((resource, expected))
}

fn bounded_fact_count(bytes: &mut &[u8]) -> Result<usize, LifecycleModelError> {
    let count = usize_from_u32(&take::<4>(bytes)?)?;
    if count > MAXIMUM_LIFECYCLE_EXPECTATIONS {
        Err(LifecycleModelError::CorruptEncoding)
    } else {
        Ok(count)
    }
}

fn push_count(bytes: &mut Vec<u8>, count: usize) {
    let encoded = count.to_be_bytes();
    bytes.extend_from_slice(&encoded[encoded.len() - 4..]);
}

fn usize_from_u32(bytes: &[u8]) -> Result<usize, LifecycleModelError> {
    usize::try_from(u32::from_be_bytes(
        <[u8; 4]>::try_from(bytes).map_err(|_| LifecycleModelError::CorruptEncoding)?,
    ))
    .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], LifecycleModelError> {
    let value = bytes
        .get(..length)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    *bytes = bytes
        .get(length..)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    Ok(value)
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], LifecycleModelError> {
    let value = <[u8; N]>::try_from(take_slice(bytes, N)?)
        .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    Ok(value)
}
