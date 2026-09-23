//! Dormant complete lifecycle inventory projected by the protected Storage owner.
//!
//! The sole [`StorageAdmissionCoordinator`] reloads and authenticates the
//! physical catalog and all committed operation records after live workspace
//! observation. The explicit dormant composition appends these rows to the
//! exact response body before broker-session signing. The installed service
//! remains unchanged, and no public row or inventory constructor exists.

use aos_proto::aos::sandbox::local::v1::{
    InventoryStorageResourcesResponse, StorageAtomicSnapshotCheckpoint,
    StorageLifecycleInventoryRecord, StorageLifecycleTransitionRecord,
};
use aos_sandbox::lifecycle::{
    LifecyclePhase6ErrorV1, LifecycleResourceV1, LifecycleStorageInventoryKindV1,
    LifecycleStorageTransitionKindV1,
};
use aos_sandbox_core::{ObjectDigest, OperationId, ResourceId, SandboxId, SnapshotId};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::catalog_transition::{VerifiedPhysicalDatasetV1, VerifiedPhysicalSnapshotV1};
use crate::state::{VerifiedStorageResolverJournalV1, VerifiedStorageResolverOperationV1};
use crate::{CatalogPlanV1, StorageAdmissionCoordinator};

/// Enriches an owner-produced Storage inventory response with the complete
/// protected five-family catalog and exact transition history.
///
/// The response metadata and launch rows have already been produced by the
/// live Storage runtime. This function rereads the independently authenticated
/// resolver journal under the same runtime owner immediately before the body is
/// returned to broker-session signing.
pub(crate) fn attach_complete_lifecycle_inventory(
    coordinator: &StorageAdmissionCoordinator,
    response_bytes: &[u8],
) -> Result<Vec<u8>, LifecyclePhase6ErrorV1> {
    let mut response = InventoryStorageResourcesResponse::decode_from_slice(response_bytes)
        .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
    if response.encode_to_vec().as_slice() != response_bytes
        || !response.lifecycle_source.is_empty()
        || !response.lifecycle_resources.is_empty()
        || !response.lifecycle_transitions.is_empty()
        || response.lifecycle_source_version != 0
        || !response.lifecycle_catalog_head.is_empty()
        || response.lifecycle_catalog_generation != 0
        || !response.atomic_snapshot_checkpoints.is_empty()
    {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }

    let journal = coordinator
        .lifecycle_inventory_journal()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    let atomic = coordinator
        .atomic_dataset_snapshot_inventory()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    response.lifecycle_source = journal.genesis().digest().as_bytes().to_vec();
    response.lifecycle_source_version = 3;
    response.lifecycle_catalog_head = journal.physical().binding().digest().as_bytes().to_vec();
    response.lifecycle_catalog_generation = journal.physical().binding().generation();
    response.lifecycle_resources = project_complete_rows(&journal, &atomic)?;
    response.lifecycle_transitions = project_transitions(&journal, &atomic)?;
    response.atomic_snapshot_checkpoints = project_atomic_checkpoints(&journal, &atomic)?;

    let encoded = response.encode_to_vec();
    aos_sandbox_protocol::decode_storage_resource_inventory_response(
        &encoded,
        aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES,
    )
    .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
    Ok(encoded)
}

fn project_atomic_checkpoints(
    journal: &VerifiedStorageResolverJournalV1,
    atomic: &[crate::state::AtomicDatasetSnapshotInventoryV1],
) -> Result<Vec<StorageAtomicSnapshotCheckpoint>, LifecyclePhase6ErrorV1> {
    let mut checkpoints = Vec::new();
    for record in atomic {
        let program = record.program();
        if record.phase() != crate::state::AtomicDatasetSnapshotPhaseV1::Committed
            || program.format_version() != 2
        {
            continue;
        }
        let observation = record
            .observation()
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let post_head = record
            .post_head()
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if program.catalog_source() != journal.genesis().digest()
            || program.catalog_generation().checked_add(1) != Some(post_head.generation())
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        checkpoints.push(StorageAtomicSnapshotCheckpoint {
            operation_id: program.operation().to_vec(),
            request_id: record.request_id().to_vec(),
            request_digest: record.transport_digest().as_bytes().to_vec(),
            program: program.commitment().as_bytes().to_vec(),
            observation: observation.as_bytes().to_vec(),
            catalog_source: program.catalog_source().as_bytes().to_vec(),
            pre_catalog_generation: program.catalog_generation(),
            pre_catalog_head: program.catalog_head().as_bytes().to_vec(),
            post_catalog_generation: post_head.generation(),
            post_catalog_head: post_head.digest().as_bytes().to_vec(),
            ..Default::default()
        });
    }
    checkpoints.sort_unstable_by(|left, right| left.operation_id.cmp(&right.operation_id));
    if !checkpoints
        .windows(2)
        .all(|pair| pair[0].operation_id < pair[1].operation_id)
    {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(checkpoints)
}

fn project_complete_rows(
    journal: &VerifiedStorageResolverJournalV1,
    atomic: &[crate::state::AtomicDatasetSnapshotInventoryV1],
) -> Result<Vec<StorageLifecycleInventoryRecord>, LifecyclePhase6ErrorV1> {
    let physical = journal.physical();
    let mut rows = Vec::new();
    rows.try_reserve_exact(
        physical
            .datasets()
            .len()
            .saturating_mul(3)
            .saturating_add(physical.snapshots().len())
            .saturating_add(physical.holds().len()),
    )
    .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;

    for dataset in physical.datasets() {
        let identity = dataset_identity(dataset);
        let authority = dataset
            .created_by()
            .and_then(|operation| journal.operation(&operation));
        let (resource, effect_subject, effect_request, lifecycle_operation) =
            dataset_authority(authority, identity)?;
        rows.push(inventory_record(
            LifecycleStorageInventoryKindV1::Dataset,
            resource,
            effect_subject,
            effect_request,
            lifecycle_operation,
            None,
            identity,
        ));

        if dataset.origin().is_some() {
            rows.push(inventory_record(
                LifecycleStorageInventoryKindV1::Clone,
                resource,
                effect_subject,
                effect_request,
                lifecycle_operation,
                None,
                clone_identity(dataset),
            ));
        }
        if dataset.space().is_some() || dataset.aggregate().is_some() {
            let quota_authority = latest_quota_authority(journal, dataset).or(authority);
            let (resource, effect_subject, effect_request, lifecycle_operation) =
                dataset_authority(quota_authority, identity)?;
            rows.push(inventory_record(
                LifecycleStorageInventoryKindV1::Quota,
                resource,
                effect_subject,
                effect_request,
                lifecycle_operation,
                None,
                quota_identity(dataset),
            ));
        }
    }

    for snapshot in physical.snapshots() {
        let identity = snapshot_identity(snapshot);
        let atomic_authority = atomic.iter().find_map(|record| {
            (record.phase() == crate::state::AtomicDatasetSnapshotPhaseV1::Committed)
                .then(|| {
                    record
                        .program()
                        .members()
                        .iter()
                        .enumerate()
                        .find_map(|(index, member)| {
                            (member.destination_name() == snapshot.name()
                                && member.source_guid() == snapshot.source_guid()
                                && record
                                    .member_guids()
                                    .is_none_or(|guids| guids.get(index) == Some(&snapshot.guid())))
                            .then_some(member)
                        })
                })
                .flatten()
                .map(|member| (record, member))
        });
        let (resource, effect_subject, effect_request, lifecycle_operation) =
            if let Some((record, member)) = atomic_authority {
                (
                    LifecycleResourceV1::Snapshot(SnapshotId::from_bytes(
                        record.program().snapshot(),
                    )),
                    member.storage_handle(),
                    record.program().effect(),
                    Some(OperationId::from_bytes(record.program().operation())),
                )
            } else {
                let authority = snapshot
                    .created_by()
                    .and_then(|operation| journal.operation(&operation));
                snapshot_authority(journal, snapshot, authority, identity)?
            };
        rows.push(inventory_record(
            LifecycleStorageInventoryKindV1::Snapshot,
            resource,
            effect_subject,
            effect_request,
            lifecycle_operation,
            None,
            identity,
        ));
    }

    // A grouped snapshot is deliberately outside the singular catalog reducer.
    // Its protected Committed record contains the program and the observation
    // that proved the complete physical group. Project any member not already
    // present in the ordinary physical snapshot rows from that sole-owner
    // record; Prepared/Ambiguous records never become physical inventory.
    for record in atomic
        .iter()
        .filter(|record| record.phase() == crate::state::AtomicDatasetSnapshotPhaseV1::Committed)
    {
        let program = record.program();
        if program.format_version() == 2 {
            // V3 groups live in the protected physical catalog; never invent
            // a current row from an old committed result after later removal.
            continue;
        }
        let observation = record
            .observation()
            .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
        for member in program.members() {
            if physical.snapshots().iter().any(|snapshot| {
                snapshot.name() == member.destination_name()
                    && snapshot.source_guid() == member.source_guid()
            }) {
                continue;
            }
            let identity = ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(b"aos.sandbox.storage.atomic-snapshot-physical-row.v1\0")
                    .chain_update(program.commitment().as_bytes())
                    .chain_update(member.physical_identity().as_bytes())
                    .chain_update(member.destination_name().as_bytes())
                    .chain_update(member.source_guid().to_be_bytes())
                    .chain_update(observation.as_bytes())
                    .finalize()
                    .into(),
            );
            rows.push(inventory_record(
                LifecycleStorageInventoryKindV1::Snapshot,
                LifecycleResourceV1::Snapshot(SnapshotId::from_bytes(program.snapshot())),
                member.storage_handle(),
                program.effect(),
                Some(OperationId::from_bytes(program.operation())),
                None,
                identity,
            ));
        }
    }

    for (snapshot_guid, hold_id) in physical.holds() {
        let snapshot = physical
            .snapshots()
            .iter()
            .find(|snapshot| snapshot.guid() == *snapshot_guid)
            .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
        let identity = hold_identity(snapshot, *hold_id);
        let authority = latest_hold_authority(journal, *snapshot_guid, *hold_id);
        let (resource, effect_subject, effect_request, lifecycle_operation) = match authority {
            Some(authority) => (
                snapshot_resource(journal, snapshot)?,
                authority
                    .result()
                    .immutable_version_handle()
                    .map(ObjectDigest::from_bytes)
                    .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?,
                authority.request_digest(),
                Some(OperationId::from_bytes(authority.result().operation_id())),
            ),
            None => (quarantined_resource(identity), identity, identity, None),
        };
        rows.push(inventory_record(
            LifecycleStorageInventoryKindV1::Hold,
            resource,
            effect_subject,
            effect_request,
            lifecycle_operation,
            Some(ResourceId::from_bytes(*hold_id)),
            identity,
        ));
    }
    rows.sort_unstable_by(|left, right| {
        inventory_record_key(left).cmp(&inventory_record_key(right))
    });
    if !rows
        .windows(2)
        .all(|pair| inventory_record_key(&pair[0]) < inventory_record_key(&pair[1]))
    {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    Ok(rows)
}

fn project_transitions(
    journal: &VerifiedStorageResolverJournalV1,
    atomic: &[crate::state::AtomicDatasetSnapshotInventoryV1],
) -> Result<Vec<StorageLifecycleTransitionRecord>, LifecyclePhase6ErrorV1> {
    let mut transitions = Vec::new();
    for (_, operation) in journal.operations() {
        let (kind, resource, effect_subject, hold_id) = match operation.catalog().plan() {
            CatalogPlanV1::CreateWorkspace { .. } => (
                LifecycleStorageTransitionKindV1::CreateWorkspace,
                LifecycleResourceV1::Sandbox(SandboxId::from_bytes(operation.sandbox_id())),
                result_storage_handle(operation)?,
                None,
            ),
            CatalogPlanV1::Snapshot { .. } => (
                LifecycleStorageTransitionKindV1::Snapshot,
                quarantined_resource(operation.request_digest()),
                result_version_handle(operation)?,
                None,
            ),
            CatalogPlanV1::HoldSnapshot { snapshot, hold_id } => (
                LifecycleStorageTransitionKindV1::HoldSnapshot,
                snapshot_resource_by_version(journal, snapshot.version_handle())?,
                ObjectDigest::from_bytes(snapshot.version_handle()),
                Some(ResourceId::from_bytes(hold_id.as_bytes())),
            ),
            CatalogPlanV1::ReleaseHold { snapshot, hold_id } => (
                LifecycleStorageTransitionKindV1::ReleaseHold,
                snapshot_resource_by_version(journal, snapshot.version_handle())?,
                ObjectDigest::from_bytes(snapshot.version_handle()),
                Some(ResourceId::from_bytes(hold_id.as_bytes())),
            ),
            CatalogPlanV1::Clone { .. } => (
                LifecycleStorageTransitionKindV1::Clone,
                LifecycleResourceV1::Sandbox(SandboxId::from_bytes(operation.sandbox_id())),
                result_storage_handle(operation)?,
                None,
            ),
            CatalogPlanV1::SetQuota { dataset, .. } => (
                LifecycleStorageTransitionKindV1::SetQuota,
                LifecycleResourceV1::Sandbox(SandboxId::from_bytes(operation.sandbox_id())),
                ObjectDigest::from_bytes(dataset.storage_handle()),
                None,
            ),
            CatalogPlanV1::DestroyDataset { dataset } => (
                LifecycleStorageTransitionKindV1::DestroyDataset,
                LifecycleResourceV1::Sandbox(SandboxId::from_bytes(operation.sandbox_id())),
                ObjectDigest::from_bytes(dataset.storage_handle()),
                None,
            ),
            CatalogPlanV1::DestroySnapshot { snapshot } => (
                LifecycleStorageTransitionKindV1::DestroySnapshot,
                snapshot_resource_by_version(journal, snapshot.version_handle())?,
                ObjectDigest::from_bytes(snapshot.version_handle()),
                None,
            ),
        };
        let identity = transition_identity(
            kind,
            resource,
            effect_subject,
            operation.request_digest(),
            hold_id,
        );
        transitions.push(transition_record(
            kind,
            resource,
            effect_subject,
            operation.request_digest(),
            hold_id,
            identity,
        ));
    }
    for record in atomic {
        if record.phase() != crate::state::AtomicDatasetSnapshotPhaseV1::Committed {
            continue;
        }
        let program = record.program();
        for member in program.members() {
            let kind = LifecycleStorageTransitionKindV1::Snapshot;
            let resource =
                LifecycleResourceV1::Snapshot(SnapshotId::from_bytes(program.snapshot()));
            let effect_subject = member.storage_handle();
            let effect_request = program.effect();
            let identity = ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(b"aos.sandbox.storage.atomic-snapshot-transition.v1\0")
                    .chain_update(program.commitment().as_bytes())
                    .chain_update(member.physical_identity().as_bytes())
                    .chain_update([record.phase() as u8])
                    .chain_update(
                        record
                            .observation()
                            .unwrap_or(ObjectDigest::from_bytes([0; 32]))
                            .as_bytes(),
                    )
                    .finalize()
                    .into(),
            );
            transitions.push(transition_record(
                kind,
                resource,
                effect_subject,
                effect_request,
                None,
                identity,
            ));
        }
    }
    transitions.sort_unstable_by(|left, right| {
        transition_record_key(left).cmp(&transition_record_key(right))
    });
    if !transitions
        .windows(2)
        .all(|pair| transition_record_key(&pair[0]) < transition_record_key(&pair[1]))
    {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    Ok(transitions)
}

fn inventory_record(
    kind: LifecycleStorageInventoryKindV1,
    resource: LifecycleResourceV1,
    effect_subject: ObjectDigest,
    effect_request: ObjectDigest,
    lifecycle_operation: Option<OperationId>,
    hold_id: Option<ResourceId>,
    identity: ObjectDigest,
) -> StorageLifecycleInventoryRecord {
    let (resource_kind, resource_id) = resource_wire(resource);
    StorageLifecycleInventoryRecord {
        kind: kind as u32,
        resource_kind,
        resource_id: resource_id.to_vec(),
        effect_subject: effect_subject.as_bytes().to_vec(),
        effect_request: effect_request.as_bytes().to_vec(),
        lifecycle_operation: lifecycle_operation
            .map_or_else(Vec::new, |value| value.into_bytes().to_vec()),
        hold_id: hold_id.map_or_else(Vec::new, |value| value.into_bytes().to_vec()),
        identity: identity.as_bytes().to_vec(),
        ..Default::default()
    }
}

fn transition_record(
    kind: LifecycleStorageTransitionKindV1,
    resource: LifecycleResourceV1,
    effect_subject: ObjectDigest,
    effect_request: ObjectDigest,
    hold_id: Option<ResourceId>,
    identity: ObjectDigest,
) -> StorageLifecycleTransitionRecord {
    let (resource_kind, resource_id) = resource_wire(resource);
    StorageLifecycleTransitionRecord {
        kind: kind as u32,
        resource_kind,
        resource_id: resource_id.to_vec(),
        effect_subject: effect_subject.as_bytes().to_vec(),
        effect_request: effect_request.as_bytes().to_vec(),
        hold_id: hold_id.map_or_else(Vec::new, |value| value.into_bytes().to_vec()),
        identity: identity.as_bytes().to_vec(),
        ..Default::default()
    }
}

fn inventory_record_key(record: &StorageLifecycleInventoryRecord) -> (u32, &[u8], &[u8]) {
    (record.kind, &record.resource_id, &record.identity)
}

fn transition_record_key(record: &StorageLifecycleTransitionRecord) -> (u32, &[u8], &[u8]) {
    (record.kind, &record.resource_id, &record.identity)
}

fn resource_wire(resource: LifecycleResourceV1) -> (u32, [u8; 16]) {
    match resource {
        LifecycleResourceV1::Sandbox(value) => (1, value.into_bytes()),
        LifecycleResourceV1::Execution(value) => (2, value.into_bytes()),
        LifecycleResourceV1::Snapshot(value) => (3, value.into_bytes()),
        LifecycleResourceV1::View(value) => (4, value.into_bytes()),
        LifecycleResourceV1::Attachment(value) => (5, value.into_bytes()),
        LifecycleResourceV1::Capability(value) => (6, value.into_bytes()),
        LifecycleResourceV1::Environment(value) => (7, value.into_bytes()),
        LifecycleResourceV1::Project(value) => (8, value.into_bytes()),
        LifecycleResourceV1::Other(value) => (9, value.into_bytes()),
    }
}

fn dataset_authority(
    authority: Option<&VerifiedStorageResolverOperationV1>,
    fallback: ObjectDigest,
) -> Result<
    (
        LifecycleResourceV1,
        ObjectDigest,
        ObjectDigest,
        Option<OperationId>,
    ),
    LifecyclePhase6ErrorV1,
> {
    let Some(authority) = authority else {
        return Ok((
            LifecycleResourceV1::Other(ResourceId::from_bytes(digest_identity(fallback))),
            fallback,
            fallback,
            None,
        ));
    };
    let handle = authority
        .result()
        .storage_handle()
        .map(ObjectDigest::from_bytes)
        .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
    Ok((
        LifecycleResourceV1::Sandbox(SandboxId::from_bytes(authority.sandbox_id())),
        handle,
        authority.request_digest(),
        Some(OperationId::from_bytes(authority.result().operation_id())),
    ))
}

fn snapshot_authority(
    journal: &VerifiedStorageResolverJournalV1,
    snapshot: &VerifiedPhysicalSnapshotV1,
    authority: Option<&VerifiedStorageResolverOperationV1>,
    fallback: ObjectDigest,
) -> Result<
    (
        LifecycleResourceV1,
        ObjectDigest,
        ObjectDigest,
        Option<OperationId>,
    ),
    LifecyclePhase6ErrorV1,
> {
    let Some(authority) = authority else {
        return Ok((
            LifecycleResourceV1::Other(ResourceId::from_bytes(digest_identity(fallback))),
            fallback,
            fallback,
            None,
        ));
    };
    let handle = authority
        .result()
        .immutable_version_handle()
        .map(ObjectDigest::from_bytes)
        .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
    Ok((
        snapshot_resource(journal, snapshot)?,
        handle,
        authority.request_digest(),
        Some(OperationId::from_bytes(authority.result().operation_id())),
    ))
}

fn snapshot_resource(
    journal: &VerifiedStorageResolverJournalV1,
    snapshot: &VerifiedPhysicalSnapshotV1,
) -> Result<LifecycleResourceV1, LifecyclePhase6ErrorV1> {
    let (Some(operation_id), Some(metadata)) = (snapshot.created_by(), snapshot.metadata()) else {
        return Ok(LifecycleResourceV1::Other(ResourceId::from_bytes(
            digest_identity(snapshot_identity(snapshot)),
        )));
    };
    if metadata.operation_id() != operation_id || metadata.snapshot_guid() != snapshot.guid() {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    let operation = journal
        .operation(&operation_id)
        .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
    if !matches!(operation.catalog().plan(), CatalogPlanV1::Snapshot { .. }) {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(quarantined_resource(operation.request_digest()))
}

fn snapshot_resource_by_version(
    journal: &VerifiedStorageResolverJournalV1,
    version_handle: [u8; 32],
) -> Result<LifecycleResourceV1, LifecyclePhase6ErrorV1> {
    let mut matching = journal.operations().filter_map(|(_, operation)| {
        matches!(operation.catalog().plan(), CatalogPlanV1::Snapshot { .. })
            .then_some(operation)
            .filter(|operation| {
                operation.result().immutable_version_handle() == Some(version_handle)
            })
    });
    let Some(operation) = matching.next() else {
        return Ok(LifecycleResourceV1::Other(ResourceId::from_bytes(
            digest_identity(ObjectDigest::from_bytes(version_handle)),
        )));
    };
    if matching.next().is_some() {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(quarantined_resource(operation.request_digest()))
}

fn quarantined_resource(authority: ObjectDigest) -> LifecycleResourceV1 {
    LifecycleResourceV1::Other(ResourceId::from_bytes(digest_identity(authority)))
}

fn result_storage_handle(
    operation: &VerifiedStorageResolverOperationV1,
) -> Result<ObjectDigest, LifecyclePhase6ErrorV1> {
    operation
        .result()
        .storage_handle()
        .map(ObjectDigest::from_bytes)
        .ok_or(LifecyclePhase6ErrorV1::InvalidInput)
}

fn result_version_handle(
    operation: &VerifiedStorageResolverOperationV1,
) -> Result<ObjectDigest, LifecyclePhase6ErrorV1> {
    operation
        .result()
        .immutable_version_handle()
        .map(ObjectDigest::from_bytes)
        .ok_or(LifecyclePhase6ErrorV1::InvalidInput)
}

fn transition_identity(
    kind: LifecycleStorageTransitionKindV1,
    resource: LifecycleResourceV1,
    effect_subject: ObjectDigest,
    effect_request: ObjectDigest,
    hold_id: Option<ResourceId>,
) -> ObjectDigest {
    let resource_bytes = match resource {
        LifecycleResourceV1::Sandbox(value) => value.into_bytes(),
        LifecycleResourceV1::Execution(value) => value.into_bytes(),
        LifecycleResourceV1::Snapshot(value) => value.into_bytes(),
        LifecycleResourceV1::View(value) => value.into_bytes(),
        LifecycleResourceV1::Attachment(value)
        | LifecycleResourceV1::Capability(value)
        | LifecycleResourceV1::Environment(value)
        | LifecycleResourceV1::Other(value) => value.into_bytes(),
        LifecycleResourceV1::Project(value) => value.into_bytes(),
    };
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.storage.lifecycle.transition.v1\0")
            .chain_update([kind as u8])
            .chain_update(resource_bytes)
            .chain_update(effect_subject.as_bytes())
            .chain_update(effect_request.as_bytes())
            .chain_update(hold_id.map_or([0; 16], ResourceId::into_bytes))
            .finalize()
            .into(),
    )
}

fn latest_quota_authority<'journal>(
    journal: &'journal VerifiedStorageResolverJournalV1,
    dataset: &VerifiedPhysicalDatasetV1,
) -> Option<&'journal VerifiedStorageResolverOperationV1> {
    journal
        .operations()
        .filter_map(|(_, operation)| match operation.catalog().plan() {
            CatalogPlanV1::SetQuota {
                dataset: target, ..
            } if target.name() == dataset.name() && target.guid() == dataset.guid() => {
                Some(operation)
            }
            _ => None,
        })
        .max_by_key(|operation| operation.catalog().generation())
}

fn latest_hold_authority<'journal>(
    journal: &'journal VerifiedStorageResolverJournalV1,
    snapshot_guid: u64,
    hold_id: [u8; 16],
) -> Option<&'journal VerifiedStorageResolverOperationV1> {
    journal
        .operations()
        .filter_map(|(_, operation)| match operation.catalog().plan() {
            CatalogPlanV1::HoldSnapshot {
                snapshot,
                hold_id: candidate,
            } if snapshot.guid() == snapshot_guid && candidate.as_bytes() == hold_id => {
                Some(operation)
            }
            _ => None,
        })
        .max_by_key(|operation| operation.catalog().generation())
}

pub(crate) fn dataset_identity(dataset: &VerifiedPhysicalDatasetV1) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.storage.lifecycle.dataset.v1\0")
        .chain_update(dataset.name().as_bytes())
        .chain_update(dataset.guid().to_be_bytes())
        .chain_update(dataset.root().pool().as_bytes())
        .chain_update(dataset.root().dataset_prefix().as_bytes())
        .chain_update(dataset.root().guid().to_be_bytes())
        .chain_update(dataset.domains().disclosure().as_bytes())
        .chain_update(dataset.domains().encryption().as_bytes())
        .chain_update(dataset.domains().accounting().as_bytes())
        .chain_update(dataset.domains().retention().as_bytes());
    if let Some(operation) = dataset.created_by() {
        hasher = hasher.chain_update([1]).chain_update(operation);
    } else {
        hasher = hasher.chain_update([0]);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn clone_identity(dataset: &VerifiedPhysicalDatasetV1) -> ObjectDigest {
    let (origin_name, origin_guid) = dataset.origin().unwrap_or(("", 0));
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.storage.lifecycle.clone.v1\0")
            .chain_update(dataset_identity(dataset).as_bytes())
            .chain_update(origin_name.as_bytes())
            .chain_update(origin_guid.to_be_bytes())
            .finalize()
            .into(),
    )
}

fn quota_identity(dataset: &VerifiedPhysicalDatasetV1) -> ObjectDigest {
    let (refquota, reservation) = dataset.space().unwrap_or((0, None));
    let (quota, filesystems, snapshots) = dataset.aggregate().unwrap_or((0, 0, 0));
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.storage.lifecycle.quota.v1\0")
            .chain_update(dataset_identity(dataset).as_bytes())
            .chain_update(refquota.to_be_bytes())
            .chain_update(reservation.unwrap_or(0).to_be_bytes())
            .chain_update(quota.to_be_bytes())
            .chain_update(filesystems.to_be_bytes())
            .chain_update(snapshots.to_be_bytes())
            .finalize()
            .into(),
    )
}

fn snapshot_identity(snapshot: &VerifiedPhysicalSnapshotV1) -> ObjectDigest {
    let metadata = snapshot
        .metadata()
        .map(|record| record.record_digest())
        .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]));
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.storage.lifecycle.snapshot.v1\0")
            .chain_update(snapshot.name().as_bytes())
            .chain_update(snapshot.guid().to_be_bytes())
            .chain_update(snapshot.source_name().as_bytes())
            .chain_update(snapshot.source_guid().to_be_bytes())
            .chain_update(metadata.as_bytes())
            .finalize()
            .into(),
    )
}

fn hold_identity(snapshot: &VerifiedPhysicalSnapshotV1, hold_id: [u8; 16]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.storage.lifecycle.hold.v1\0")
            .chain_update(snapshot_identity(snapshot).as_bytes())
            .chain_update(hold_id)
            .finalize()
            .into(),
    )
}

fn digest_identity(digest: ObjectDigest) -> [u8; 16] {
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest.as_bytes()[..16]);
    identity
}
