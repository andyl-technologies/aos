//! Canonical reconstructing codecs for lifecycle auxiliary projections.
//!
//! ```text
//! auxiliary-payload := coordination | retention-ledger | suspend-observation |
//!                      boot-inventory | cancellation-resolution
//! ```
//!
//! Payloads retain complete model values. Typed digests are never accepted as
//! substitutes for omitted state, and every variable count/length is
//! preflighted before allocation.

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, ObjectDigest,
    OperationId, PrincipalId, ProjectId, ResourceId, Revision, SandboxId,
};

use super::{
    DesiredStateFenceV1, LifecycleAuxiliaryKindV1, LifecycleBootInventoryDigestV1,
    LifecycleBootInventoryV1, LifecycleCancelIdempotencyDigestV1, LifecycleCancelOutcomeV1,
    LifecycleCancelRequestV1, LifecycleCancellationRecordV1, LifecycleCoordinationPhaseV1,
    LifecycleCoordinationTransactionV1, LifecycleDatasetTransactionDigestV1, LifecycleModelError,
    LifecycleOperationV1, LifecycleQuiesceDigestV1, LifecycleRecordDigestV1, LifecycleResourceV1,
    LifecycleRetentionLedgerDigestV1, LifecycleRetentionLedgerEntryV1, LifecycleRetentionLedgerV1,
    LifecycleSnapshotManifestDigestV1, LifecycleStepResultDigestV1,
    LifecycleSuspendObservationDigestV1, LifecycleSuspendObservationV1,
    LifecycleThawCompensationDigestV1, LifecycleTimeV1, LifecycleTransactionIdV1,
    LifecycleWriterFenceDigestV1, LiveRuntimeFenceV1, MAXIMUM_LIFECYCLE_EXPECTATIONS,
    decode_operation_record_v1, encode_operation_record_v1,
};

/// Maximum canonical bytes retained by one auxiliary payload.
pub const MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// Stores one complete reconstructing lifecycle auxiliary value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleAuxiliaryPayloadV1 {
    /// Stores the exact operation snapshot made visible by an atomic join.
    Operation(LifecycleOperationV1),
    /// Stores complete coordination state.
    Coordination(LifecycleCoordinationTransactionV1),
    /// Stores one complete retention-ledger revision.
    RetentionLedger(LifecycleRetentionLedgerV1),
    /// Stores an exact suspended-runtime observation.
    SuspendObservation(LifecycleSuspendObservationV1),
    /// Stores an operation-bound post-commit boot inventory.
    BootInventory(LifecycleBootInventoryV1),
    /// Stores one stable cancellation-idempotency resolution.
    Cancellation(LifecycleCancellationRecordV1),
}

impl LifecycleAuxiliaryPayloadV1 {
    /// Returns the closed auxiliary family.
    #[must_use]
    pub const fn kind(&self) -> LifecycleAuxiliaryKindV1 {
        match self {
            Self::Operation(_) => LifecycleAuxiliaryKindV1::Operation,
            Self::Coordination(_) => LifecycleAuxiliaryKindV1::Coordination,
            Self::RetentionLedger(_) => LifecycleAuxiliaryKindV1::RetentionLedger,
            Self::SuspendObservation(_) => LifecycleAuxiliaryKindV1::SuspendObservation,
            Self::BootInventory(_) => LifecycleAuxiliaryKindV1::BootInventory,
            Self::Cancellation(_) => LifecycleAuxiliaryKindV1::Cancellation,
        }
    }

    /// Returns the payload's inherent lineage revision when one exists.
    #[must_use]
    pub const fn inherent_revision(&self) -> Option<Revision> {
        match self {
            Self::Operation(value) => Some(value.record_revision()),
            Self::RetentionLedger(value) => Some(value.revision()),
            Self::SuspendObservation(value) => Some(value.operation_revision()),
            Self::BootInventory(value) => Some(value.operation_revision()),
            Self::Cancellation(value) => Some(value.operation().record_revision()),
            Self::Coordination(_) => None,
        }
    }

    /// Returns the operation identity intrinsically bound by the payload.
    #[must_use]
    pub const fn operation(&self) -> Option<OperationId> {
        match self {
            Self::Operation(value) => Some(value.operation_id()),
            Self::SuspendObservation(value) => Some(value.operation()),
            Self::BootInventory(value) => Some(value.operation()),
            Self::Cancellation(value) => Some(value.operation().operation_id()),
            Self::Coordination(_) | Self::RetentionLedger(_) => None,
        }
    }
}

/// Encodes one complete lifecycle auxiliary payload.
///
/// # Errors
///
/// Returns [`LifecycleModelError`] for an unrepresentable length, a fixed
/// ceiling violation, or checked allocation failure.
pub fn encode_lifecycle_auxiliary_payload_v1(
    payload: &LifecycleAuxiliaryPayloadV1,
) -> Result<Vec<u8>, LifecycleModelError> {
    let capacity = payload_encoded_length(payload)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| LifecycleModelError::Allocation)?;
    match payload {
        LifecycleAuxiliaryPayloadV1::Operation(value) => {
            let operation = encode_operation_record_v1(value)?;
            push_length(&mut bytes, operation.len())?;
            bytes.extend_from_slice(&operation);
        }
        LifecycleAuxiliaryPayloadV1::Coordination(value) => {
            bytes.extend_from_slice(value.transaction().get().as_bytes());
            bytes.extend_from_slice(value.sandbox().as_bytes());
            encode_live_fence(&mut bytes, value.live_fence());
            push_count(&mut bytes, value.dependencies().len())?;
            for dependency in value.dependencies() {
                encode_resource(&mut bytes, *dependency);
            }
            push_count(&mut bytes, value.dependency_edges().len())?;
            for edge in value.dependency_edges() {
                encode_resource(&mut bytes, edge.dependent());
                encode_resource(&mut bytes, edge.dependency());
            }
            push_count(&mut bytes, value.postorder().len())?;
            for resource in value.postorder() {
                encode_resource(&mut bytes, *resource);
            }
            bytes.extend_from_slice(value.dependency_snapshot().as_bytes());
            bytes.extend_from_slice(value.manifest().digest().as_bytes());
            bytes.extend_from_slice(value.retention_ledger().digest().as_bytes());
            for digest in [
                value.quiesce().map(|digest| digest.digest()),
                value.writer_fence().map(|digest| digest.digest()),
                value.dataset_transaction().map(|digest| digest.digest()),
            ] {
                encode_optional_digest(&mut bytes, digest);
            }
            bytes.extend_from_slice(value.thaw_compensation().digest().as_bytes());
            bytes.push(value.phase() as u8);
            bytes.extend_from_slice(&[0; 7]);
        }
        LifecycleAuxiliaryPayloadV1::RetentionLedger(value) => {
            bytes.extend_from_slice(&value.revision().get().to_be_bytes());
            encode_optional_digest(&mut bytes, value.predecessor());
            push_count(&mut bytes, value.entries().len())?;
            for entry in value.entries() {
                encode_resource(&mut bytes, entry.resource());
                bytes.extend_from_slice(entry.holder().as_bytes());
                bytes.push(entry.purpose() as u8);
                bytes.extend_from_slice(entry.receipt().as_bytes());
            }
        }
        LifecycleAuxiliaryPayloadV1::SuspendObservation(value) => {
            bytes.extend_from_slice(value.operation().as_bytes());
            bytes.extend_from_slice(&value.operation_revision().get().to_be_bytes());
            bytes.extend_from_slice(value.operation_record().digest().as_bytes());
            encode_live_fence(&mut bytes, value.fence());
            bytes.extend_from_slice(value.observation().digest().as_bytes());
            bytes.extend_from_slice(&value.observed_at().get().to_be_bytes());
        }
        LifecycleAuxiliaryPayloadV1::BootInventory(value) => {
            bytes.extend_from_slice(value.operation().as_bytes());
            bytes.extend_from_slice(&value.operation_revision().get().to_be_bytes());
            bytes.extend_from_slice(value.operation_record().digest().as_bytes());
            bytes.extend_from_slice(&value.step().to_be_bytes());
            bytes.extend_from_slice(value.step_result().digest().as_bytes());
            encode_live_fence(&mut bytes, value.fence());
            for digest in [
                value.domains().runtime(),
                value.domains().mounts(),
                value.domains().storage(),
                value.domains().network(),
                value.domains().cache(),
                value.domains().transfers(),
            ] {
                bytes.extend_from_slice(digest.as_bytes());
            }
            push_count(&mut bytes, value.resources().len())?;
            for resource in value.resources() {
                encode_resource(&mut bytes, *resource);
            }
            bytes.extend_from_slice(value.inventory().digest().as_bytes());
            bytes.extend_from_slice(&value.observed_at().get().to_be_bytes());
        }
        LifecycleAuxiliaryPayloadV1::Cancellation(value) => {
            let request = value.request();
            bytes.extend_from_slice(request.caller().as_bytes());
            bytes.extend_from_slice(request.project().as_bytes());
            bytes.extend_from_slice(request.operation_id().as_bytes());
            bytes.extend_from_slice(&request.expected_revision().get().to_be_bytes());
            bytes.extend_from_slice(request.expected_record().digest().as_bytes());
            bytes.extend_from_slice(request.idempotency().digest().as_bytes());
            bytes.extend_from_slice(&request.requested_at().get().to_be_bytes());
            let outcome = match value.outcome() {
                LifecycleCancelOutcomeV1::CanceledBeforeCommit(_) => 1,
                LifecycleCancelOutcomeV1::AlreadyCommitted(_) => 2,
                LifecycleCancelOutcomeV1::AlreadyTerminal(_) => 3,
                LifecycleCancelOutcomeV1::Conflict => {
                    return Err(LifecycleModelError::InvalidModel);
                }
            };
            bytes.push(outcome);
            bytes.extend_from_slice(&[0; 7]);
            let operation = encode_operation_record_v1(value.operation())?;
            push_length(&mut bytes, operation.len())?;
            bytes.extend_from_slice(&operation);
        }
    }
    if bytes.is_empty()
        || bytes.len() != capacity
        || bytes.len() > MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES
    {
        return Err(LifecycleModelError::InvalidModel);
    }
    Ok(bytes)
}

fn payload_encoded_length(
    payload: &LifecycleAuxiliaryPayloadV1,
) -> Result<usize, LifecycleModelError> {
    let length = match payload {
        LifecycleAuxiliaryPayloadV1::Operation(value) => {
            encode_operation_record_v1(value)?.len().checked_add(4)
        }
        LifecycleAuxiliaryPayloadV1::Coordination(value) => value
            .dependencies()
            .len()
            .checked_mul(17)
            .and_then(|dependencies| 404_usize.checked_add(dependencies))
            .and_then(|length| {
                value
                    .dependency_edges()
                    .len()
                    .checked_mul(34)
                    .and_then(|edges| length.checked_add(edges))
            })
            .and_then(|length| {
                value
                    .postorder()
                    .len()
                    .checked_mul(17)
                    .and_then(|postorder| length.checked_add(postorder))
            }),
        LifecycleAuxiliaryPayloadV1::RetentionLedger(value) => value
            .entries()
            .len()
            .checked_mul(66)
            .and_then(|entries| 52_usize.checked_add(entries)),
        LifecycleAuxiliaryPayloadV1::SuspendObservation(_) => Some(200),
        LifecycleAuxiliaryPayloadV1::BootInventory(value) => value
            .resources()
            .len()
            .checked_mul(17)
            .and_then(|resources| 432_usize.checked_add(resources)),
        LifecycleAuxiliaryPayloadV1::Cancellation(value) => {
            encode_operation_record_v1(value.operation())?
                .len()
                .checked_add(140)
        }
    }
    .filter(|length| *length > 0 && *length <= MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES)
    .ok_or(LifecycleModelError::InvalidModel)?;
    Ok(length)
}

/// Decodes one complete lifecycle auxiliary payload.
///
/// # Errors
///
/// Returns [`LifecycleModelError`] for malformed canonical bytes, exhausted
/// bounds, or a reconstructed model that violates its closed invariants.
pub fn decode_lifecycle_auxiliary_payload_v1(
    kind: LifecycleAuxiliaryKindV1,
    encoded: &[u8],
) -> Result<LifecycleAuxiliaryPayloadV1, LifecycleModelError> {
    if encoded.is_empty() || encoded.len() > MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    preflight(kind, encoded)?;
    let mut bytes = encoded;
    let payload = match kind {
        LifecycleAuxiliaryKindV1::Operation => {
            let length = read_length(&mut bytes)?;
            LifecycleAuxiliaryPayloadV1::Operation(decode_operation_record_v1(take_slice(
                &mut bytes, length,
            )?)?)
        }
        LifecycleAuxiliaryKindV1::Coordination => {
            let transaction =
                LifecycleTransactionIdV1::new(ResourceId::from_bytes(take(&mut bytes)?))
                    .map_err(|_| LifecycleModelError::CorruptEncoding)?;
            let sandbox = SandboxId::from_bytes(take(&mut bytes)?);
            let fence = decode_live_fence(&mut bytes)?;
            let count = read_count(&mut bytes)?;
            let mut dependencies = Vec::new();
            dependencies
                .try_reserve_exact(count)
                .map_err(|_| LifecycleModelError::Allocation)?;
            for _ in 0..count {
                dependencies.push(decode_resource(&mut bytes)?);
            }
            let edge_count = read_count(&mut bytes)?;
            let mut dependency_edges = Vec::new();
            dependency_edges
                .try_reserve_exact(edge_count)
                .map_err(|_| LifecycleModelError::Allocation)?;
            for _ in 0..edge_count {
                dependency_edges.push(super::LifecycleDependencyEdgeV1::new(
                    decode_resource(&mut bytes)?,
                    decode_resource(&mut bytes)?,
                )?);
            }
            let postorder_count = read_count(&mut bytes)?;
            let mut postorder = Vec::new();
            postorder
                .try_reserve_exact(postorder_count)
                .map_err(|_| LifecycleModelError::Allocation)?;
            for _ in 0..postorder_count {
                postorder.push(decode_resource(&mut bytes)?);
            }
            let dependency_snapshot = ObjectDigest::from_bytes(take(&mut bytes)?);
            let manifest = LifecycleSnapshotManifestDigestV1::from_stored(
                ObjectDigest::from_bytes(take(&mut bytes)?),
            )?;
            let retention = LifecycleRetentionLedgerDigestV1::from_stored(
                ObjectDigest::from_bytes(take(&mut bytes)?),
            )?;
            let quiesce = decode_optional_digest(&mut bytes)?
                .map(LifecycleQuiesceDigestV1::from_stored)
                .transpose()?;
            let writer = decode_optional_digest(&mut bytes)?
                .map(LifecycleWriterFenceDigestV1::from_stored)
                .transpose()?;
            let dataset = decode_optional_digest(&mut bytes)?
                .map(LifecycleDatasetTransactionDigestV1::from_stored)
                .transpose()?;
            let thaw = LifecycleThawCompensationDigestV1::from_stored(ObjectDigest::from_bytes(
                take(&mut bytes)?,
            ))?;
            let phase = decode_coordination_phase(take::<1>(&mut bytes)?[0])?;
            if take::<7>(&mut bytes)? != [0; 7] {
                return Err(LifecycleModelError::CorruptEncoding);
            }
            LifecycleAuxiliaryPayloadV1::Coordination(
                LifecycleCoordinationTransactionV1::from_stored(
                    transaction,
                    sandbox,
                    fence,
                    dependencies,
                    dependency_edges,
                    postorder,
                    dependency_snapshot,
                    manifest,
                    retention,
                    quiesce,
                    writer,
                    dataset,
                    thaw,
                    phase,
                )
                .map_err(|_| LifecycleModelError::CorruptEncoding)?,
            )
        }
        LifecycleAuxiliaryKindV1::RetentionLedger => {
            let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
            let predecessor = decode_optional_digest(&mut bytes)?;
            let count = read_count(&mut bytes)?;
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(count)
                .map_err(|_| LifecycleModelError::Allocation)?;
            for _ in 0..count {
                entries.push(LifecycleRetentionLedgerEntryV1::new(
                    decode_resource(&mut bytes)?,
                    ResourceId::from_bytes(take(&mut bytes)?),
                    match take::<1>(&mut bytes)?[0] {
                        1 => super::LifecycleRetentionPurposeV1::Snapshot,
                        2 => super::LifecycleRetentionPurposeV1::Cascade,
                        3 => super::LifecycleRetentionPurposeV1::Transfer,
                        _ => return Err(LifecycleModelError::CorruptEncoding),
                    },
                    ObjectDigest::from_bytes(take(&mut bytes)?),
                )?);
            }
            LifecycleAuxiliaryPayloadV1::RetentionLedger(
                LifecycleRetentionLedgerV1::new(revision, predecessor, entries)
                    .map_err(|_| LifecycleModelError::CorruptEncoding)?,
            )
        }
        LifecycleAuxiliaryKindV1::SuspendObservation => {
            LifecycleAuxiliaryPayloadV1::SuspendObservation(
                LifecycleSuspendObservationV1::from_stored(
                    OperationId::from_bytes(take(&mut bytes)?),
                    Revision::new(u64::from_be_bytes(take(&mut bytes)?)),
                    LifecycleRecordDigestV1::from_stored(ObjectDigest::from_bytes(take(
                        &mut bytes,
                    )?))?,
                    decode_live_fence(&mut bytes)?,
                    LifecycleSuspendObservationDigestV1::from_stored(ObjectDigest::from_bytes(
                        take(&mut bytes)?,
                    ))?,
                    LifecycleTimeV1::from_stored(u64::from_be_bytes(take(&mut bytes)?))?,
                )?,
            )
        }
        LifecycleAuxiliaryKindV1::BootInventory => {
            let operation = OperationId::from_bytes(take(&mut bytes)?);
            let operation_revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
            let operation_record =
                LifecycleRecordDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?;
            let step = u32::from_be_bytes(take(&mut bytes)?);
            let step_result = LifecycleStepResultDigestV1::from_stored(ObjectDigest::from_bytes(
                take(&mut bytes)?,
            ))?;
            let fence = decode_live_fence(&mut bytes)?;
            let domains = super::LifecycleBootInventoryDomainsV1::new(
                ObjectDigest::from_bytes(take(&mut bytes)?),
                ObjectDigest::from_bytes(take(&mut bytes)?),
                ObjectDigest::from_bytes(take(&mut bytes)?),
                ObjectDigest::from_bytes(take(&mut bytes)?),
                ObjectDigest::from_bytes(take(&mut bytes)?),
                ObjectDigest::from_bytes(take(&mut bytes)?),
            )
            .map_err(|_| LifecycleModelError::CorruptEncoding)?;
            let count = read_count(&mut bytes)?;
            let mut resources = Vec::new();
            resources
                .try_reserve_exact(count)
                .map_err(|_| LifecycleModelError::Allocation)?;
            for _ in 0..count {
                resources.push(decode_resource(&mut bytes)?);
            }
            LifecycleAuxiliaryPayloadV1::BootInventory(LifecycleBootInventoryV1::new(
                operation,
                operation_revision,
                operation_record,
                step,
                step_result,
                fence,
                domains,
                resources,
                LifecycleBootInventoryDigestV1::from_stored(ObjectDigest::from_bytes(take(
                    &mut bytes,
                )?))?,
                LifecycleTimeV1::from_stored(u64::from_be_bytes(take(&mut bytes)?))?,
            )?)
        }
        LifecycleAuxiliaryKindV1::Cancellation => {
            let request = LifecycleCancelRequestV1::new(
                PrincipalId::from_bytes(take(&mut bytes)?),
                ProjectId::from_bytes(take(&mut bytes)?),
                OperationId::from_bytes(take(&mut bytes)?),
                Revision::new(u64::from_be_bytes(take(&mut bytes)?)),
                LifecycleRecordDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?,
                LifecycleCancelIdempotencyDigestV1::from_stored(ObjectDigest::from_bytes(take(
                    &mut bytes,
                )?))?,
                LifecycleTimeV1::from_stored(u64::from_be_bytes(take(&mut bytes)?))?,
            )?;
            let outcome_kind = take::<1>(&mut bytes)?[0];
            if take::<7>(&mut bytes)? != [0; 7] {
                return Err(LifecycleModelError::CorruptEncoding);
            }
            let length = read_length(&mut bytes)?;
            let operation = decode_operation_record_v1(take_slice(&mut bytes, length)?)?;
            let outcome = match outcome_kind {
                1 => LifecycleCancelOutcomeV1::CanceledBeforeCommit(operation.clone()),
                2 => LifecycleCancelOutcomeV1::AlreadyCommitted(
                    operation
                        .method_semantic_commit()
                        .cloned()
                        .ok_or(LifecycleModelError::CorruptEncoding)?,
                ),
                3 => LifecycleCancelOutcomeV1::AlreadyTerminal(
                    operation
                        .terminal_result()
                        .ok_or(LifecycleModelError::CorruptEncoding)?,
                ),
                _ => return Err(LifecycleModelError::CorruptEncoding),
            };
            LifecycleAuxiliaryPayloadV1::Cancellation(
                LifecycleCancellationRecordV1::new(request, operation, outcome)
                    .map_err(|_| LifecycleModelError::CorruptEncoding)?,
            )
        }
    };
    if !bytes.is_empty() {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    Ok(payload)
}

fn preflight(kind: LifecycleAuxiliaryKindV1, encoded: &[u8]) -> Result<(), LifecycleModelError> {
    let mut bytes = encoded;
    match kind {
        LifecycleAuxiliaryKindV1::Operation => {
            let length = read_length(&mut bytes)?;
            take_slice(&mut bytes, length)?;
        }
        LifecycleAuxiliaryKindV1::Coordination => {
            take_slice(&mut bytes, 16 + 16 + 104)?;
            let count = read_count(&mut bytes)?;
            take_slice(
                &mut bytes,
                count
                    .checked_mul(17)
                    .ok_or(LifecycleModelError::CorruptEncoding)?,
            )?;
            let edge_count = read_count(&mut bytes)?;
            take_slice(
                &mut bytes,
                edge_count
                    .checked_mul(34)
                    .ok_or(LifecycleModelError::CorruptEncoding)?,
            )?;
            let postorder_count = read_count(&mut bytes)?;
            take_slice(
                &mut bytes,
                postorder_count
                    .checked_mul(17)
                    .ok_or(LifecycleModelError::CorruptEncoding)?,
            )?;
            take_slice(&mut bytes, 32 * 3 + 40 * 3 + 32 + 8)?;
        }
        LifecycleAuxiliaryKindV1::RetentionLedger => {
            take_slice(&mut bytes, 8 + 40)?;
            let count = read_count(&mut bytes)?;
            take_slice(
                &mut bytes,
                count
                    .checked_mul(66)
                    .ok_or(LifecycleModelError::CorruptEncoding)?,
            )?;
        }
        LifecycleAuxiliaryKindV1::SuspendObservation => {
            take_slice(&mut bytes, 16 + 8 + 32 + 104 + 32 + 8)?;
        }
        LifecycleAuxiliaryKindV1::BootInventory => {
            take_slice(&mut bytes, 16 + 8 + 32 + 4 + 32 + 104 + 32 * 6)?;
            let count = read_count(&mut bytes)?;
            take_slice(
                &mut bytes,
                count
                    .checked_mul(17)
                    .and_then(|length| length.checked_add(40))
                    .ok_or(LifecycleModelError::CorruptEncoding)?,
            )?;
        }
        LifecycleAuxiliaryKindV1::Cancellation => {
            take_slice(&mut bytes, 16 * 3 + 8 + 32 * 2 + 8 + 8)?;
            let length = read_length(&mut bytes)?;
            take_slice(&mut bytes, length)?;
        }
    }
    if bytes.is_empty() {
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
    let code = take::<1>(bytes)?[0];
    if take::<7>(bytes)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let resource = LifecycleResourceV1::from_code(code, take(bytes)?)?;
    let LifecycleResourceV1::Sandbox(sandbox) = resource else {
        return Err(LifecycleModelError::CorruptEncoding);
    };
    let desired = DesiredStateFenceV1::new(
        resource,
        DesiredGeneration::new(u64::from_be_bytes(take(bytes)?)),
        Revision::new(u64::from_be_bytes(take(bytes)?)),
        super::LifecycleResourceStateDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?,
    )?;
    LiveRuntimeFenceV1::new(
        sandbox,
        desired,
        IncarnationId::from_bytes(take(bytes)?),
        AssignmentEpoch::new(u64::from_be_bytes(take(bytes)?)),
        NamespaceGeneration::new(u64::from_be_bytes(take(bytes)?)),
    )
    .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn encode_resource(bytes: &mut Vec<u8>, resource: LifecycleResourceV1) {
    bytes.push(resource.code());
    bytes.extend_from_slice(resource.as_bytes());
}

fn decode_resource(bytes: &mut &[u8]) -> Result<LifecycleResourceV1, LifecycleModelError> {
    LifecycleResourceV1::from_code(take::<1>(bytes)?[0], take(bytes)?)
}

fn encode_optional_digest(bytes: &mut Vec<u8>, value: Option<ObjectDigest>) {
    bytes.push(u8::from(value.is_some()));
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(
        value
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
}

fn decode_optional_digest(bytes: &mut &[u8]) -> Result<Option<ObjectDigest>, LifecycleModelError> {
    let present = take::<1>(bytes)?[0];
    if take::<7>(bytes)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let digest = ObjectDigest::from_bytes(take(bytes)?);
    match present {
        0 if digest.as_bytes() == &[0; 32] => Ok(None),
        1 if digest.as_bytes() != &[0; 32] => Ok(Some(digest)),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}

fn push_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), LifecycleModelError> {
    bytes.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| LifecycleModelError::InvalidModel)?
            .to_be_bytes(),
    );
    Ok(())
}

fn read_count(bytes: &mut &[u8]) -> Result<usize, LifecycleModelError> {
    let count = usize::try_from(u32::from_be_bytes(take(bytes)?))
        .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    if count > MAXIMUM_LIFECYCLE_EXPECTATIONS {
        Err(LifecycleModelError::CorruptEncoding)
    } else {
        Ok(count)
    }
}

fn push_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), LifecycleModelError> {
    bytes.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| LifecycleModelError::InvalidModel)?
            .to_be_bytes(),
    );
    Ok(())
}

fn read_length(bytes: &mut &[u8]) -> Result<usize, LifecycleModelError> {
    let length = usize::try_from(u32::from_be_bytes(take(bytes)?))
        .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    if length == 0 || length > MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES {
        Err(LifecycleModelError::CorruptEncoding)
    } else {
        Ok(length)
    }
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

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], LifecycleModelError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], LifecycleModelError> {
    let (head, tail) = bytes
        .split_at_checked(length)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    *bytes = tail;
    Ok(head)
}
