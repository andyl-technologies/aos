//! Protected resolution for coordinated lifecycle dataset snapshots.
//!
//! The lifecycle layer supplies an opaque plan committed to the exact current
//! operation, SnapshotId, closed dependency set, Storage inventory head, and
//! stable member set. This module rereads the protected physical catalog and
//! proves exact equality with every owned Dataset row before any backend may
//! receive the single grouped transaction.

use std::collections::BTreeSet;

use aos_sandbox::lifecycle::{
    LifecycleAtomicDatasetSnapshotPlanV1, LifecyclePhase6ErrorV1, LifecycleResourceV1,
};
use aos_sandbox_core::{ObjectDigest, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::StorageAdmissionCoordinator;
use crate::catalog_transition::VerifiedPhysicalDatasetV1;
use crate::state::{VerifiedStorageResolverJournalV1, VerifiedStorageResolverOperationV1};

/// Retains a single protected grouped snapshot program after exact catalog reread.
///
/// Private source names and GUIDs are deliberately not exposed. Only Storage's
/// fixed backend adapter may consume the value and cross the mutation boundary.
#[derive(Clone)]
pub struct DormantAtomicDatasetSnapshotV1 {
    operation: [u8; 16],
    snapshot: [u8; 16],
    plan: ObjectDigest,
    effect: ObjectDigest,
    catalog_generation: u64,
    catalog_source: ObjectDigest,
    members: Vec<ProtectedAtomicDatasetSnapshotMemberV1>,
    commitment: ObjectDigest,
}

impl DormantAtomicDatasetSnapshotV1 {
    /// Returns the number of datasets passed to the one grouped mutation.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Returns the complete protected grouped-program commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }

    pub(crate) fn members(&self) -> &[ProtectedAtomicDatasetSnapshotMemberV1] {
        &self.members
    }

    pub(crate) const fn operation(&self) -> [u8; 16] {
        self.operation
    }

    pub(crate) const fn snapshot(&self) -> [u8; 16] {
        self.snapshot
    }

    pub(crate) const fn plan(&self) -> ObjectDigest {
        self.plan
    }

    pub(crate) const fn effect(&self) -> ObjectDigest {
        self.effect
    }

    pub(crate) const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    pub(crate) const fn catalog_source(&self) -> ObjectDigest {
        self.catalog_source
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, LifecyclePhase6ErrorV1> {
        let count =
            u16::try_from(self.members.len()).map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
        let mut bytes = Vec::with_capacity(160 + self.members.len() * 192);
        bytes.extend_from_slice(b"AOSASG01");
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&self.operation);
        bytes.extend_from_slice(&self.snapshot);
        bytes.extend_from_slice(self.plan.as_bytes());
        bytes.extend_from_slice(self.effect.as_bytes());
        bytes.extend_from_slice(&self.catalog_generation.to_be_bytes());
        bytes.extend_from_slice(self.catalog_source.as_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        for member in &self.members {
            encode_text(&mut bytes, &member.source_name)?;
            bytes.extend_from_slice(&member.source_guid.to_be_bytes());
            encode_text(&mut bytes, &member.destination_name)?;
            bytes.extend_from_slice(member.storage_handle.as_bytes());
            bytes.extend_from_slice(member.physical_identity.as_bytes());
        }
        bytes.extend_from_slice(self.commitment.as_bytes());
        Ok(bytes)
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LifecyclePhase6ErrorV1> {
        let mut bytes = bytes;
        if take(&mut bytes, 8)? != b"AOSASG01"
            || take_array::<2>(&mut bytes)? != 1_u16.to_be_bytes()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let operation = take_array(&mut bytes)?;
        let snapshot = take_array(&mut bytes)?;
        let plan = ObjectDigest::from_bytes(take_array(&mut bytes)?);
        let effect = ObjectDigest::from_bytes(take_array(&mut bytes)?);
        let catalog_generation = u64::from_be_bytes(take_array(&mut bytes)?);
        let catalog_source = ObjectDigest::from_bytes(take_array(&mut bytes)?);
        let count = usize::from(u16::from_be_bytes(take_array(&mut bytes)?));
        if operation == [0; 16]
            || snapshot == [0; 16]
            || plan.as_bytes() == &[0; 32]
            || effect.as_bytes() == &[0; 32]
            || catalog_generation == 0
            || catalog_source.as_bytes() == &[0; 32]
            || count == 0
            || count > aos_sandbox::lifecycle::MAXIMUM_LIFECYCLE_EXPECTATIONS
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            members.push(ProtectedAtomicDatasetSnapshotMemberV1 {
                source_name: decode_text(&mut bytes)?,
                source_guid: u64::from_be_bytes(take_array(&mut bytes)?),
                destination_name: decode_text(&mut bytes)?,
                storage_handle: ObjectDigest::from_bytes(take_array(&mut bytes)?),
                physical_identity: ObjectDigest::from_bytes(take_array(&mut bytes)?),
            });
        }
        let commitment = ObjectDigest::from_bytes(take_array(&mut bytes)?);
        if !bytes.is_empty()
            || members.iter().any(|member| {
                member.source_guid == 0
                    || member.storage_handle.as_bytes() == &[0; 32]
                    || member.physical_identity.as_bytes() == &[0; 32]
                    || member
                        .destination_name
                        .as_bytes()
                        .get(member.source_name.len())
                        != Some(&b'@')
                    || !member.destination_name.starts_with(&member.source_name)
            })
            || !members.windows(2).all(|pair| {
                (pair[0].storage_handle, pair[0].physical_identity)
                    < (pair[1].storage_handle, pair[1].physical_identity)
            })
            || commitment
                != grouped_program_commitment_fields(
                    plan,
                    effect,
                    catalog_generation,
                    catalog_source,
                    &members,
                )
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            operation,
            snapshot,
            plan,
            effect,
            catalog_generation,
            catalog_source,
            members,
            commitment,
        })
    }
}

#[derive(Clone)]
pub(crate) struct ProtectedAtomicDatasetSnapshotMemberV1 {
    source_name: String,
    source_guid: u64,
    destination_name: String,
    storage_handle: ObjectDigest,
    physical_identity: ObjectDigest,
}

impl ProtectedAtomicDatasetSnapshotMemberV1 {
    pub(crate) fn source_name(&self) -> &str {
        &self.source_name
    }

    pub(crate) const fn source_guid(&self) -> u64 {
        self.source_guid
    }

    pub(crate) fn destination_name(&self) -> &str {
        &self.destination_name
    }

    pub(crate) const fn storage_handle(&self) -> ObjectDigest {
        self.storage_handle
    }

    pub(crate) const fn physical_identity(&self) -> ObjectDigest {
        self.physical_identity
    }
}

pub(crate) fn prepare_atomic_dataset_snapshot(
    coordinator: &StorageAdmissionCoordinator,
    plan: &LifecycleAtomicDatasetSnapshotPlanV1,
) -> Result<DormantAtomicDatasetSnapshotV1, LifecyclePhase6ErrorV1> {
    let journal = coordinator
        .lifecycle_inventory_journal()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    let physical = journal.physical();
    if physical.binding().generation() != plan.inventory_generation()
        || physical.binding().digest() != plan.inventory_source()
    {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }

    let closed = plan
        .closed_resources()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut expected = Vec::new();
    for dataset in physical.datasets() {
        let Some(authority) = dataset
            .created_by()
            .and_then(|operation| journal.operation(&operation))
        else {
            continue;
        };
        let logical = LifecycleResourceV1::Sandbox(SandboxId::from_bytes(authority.sandbox_id()));
        if !closed.contains(&logical) {
            continue;
        }
        expected.push(resolve_member(
            dataset,
            authority,
            plan.snapshot().into_bytes(),
        )?);
    }
    expected.sort_unstable_by(|left, right| {
        (left.storage_handle, left.physical_identity)
            .cmp(&(right.storage_handle, right.physical_identity))
    });
    if expected.is_empty()
        || !expected.windows(2).all(|pair| {
            (pair[0].storage_handle, pair[0].physical_identity)
                < (pair[1].storage_handle, pair[1].physical_identity)
        })
        || expected.len() != plan.members().len()
    {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    for expected in &expected {
        let authority = expected_authority_for_handle(&journal, expected.storage_handle)?;
        let creating_operation = journal
            .operation(&authority)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let resource =
            LifecycleResourceV1::Sandbox(SandboxId::from_bytes(creating_operation.sandbox_id()));
        let matching = plan.members().iter().filter(|supplied| {
            supplied.resource() == resource
                && supplied.storage_handle() == expected.storage_handle
                && supplied.physical_identity() == expected.physical_identity
                && supplied.creating_request() == creating_operation.request_digest()
        });
        if matching.count() != 1 {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
    }
    let commitment = grouped_program_commitment(plan, &expected);
    Ok(DormantAtomicDatasetSnapshotV1 {
        operation: plan.operation().into_bytes(),
        snapshot: plan.snapshot().into_bytes(),
        plan: plan.commitment(),
        effect: plan.effect_commitment(),
        catalog_generation: plan.inventory_generation(),
        catalog_source: plan.inventory_source(),
        members: expected,
        commitment,
    })
}

fn resolve_member(
    dataset: &VerifiedPhysicalDatasetV1,
    authority: &VerifiedStorageResolverOperationV1,
    snapshot: [u8; 16],
) -> Result<ProtectedAtomicDatasetSnapshotMemberV1, LifecyclePhase6ErrorV1> {
    let storage_handle = authority
        .result()
        .storage_handle()
        .map(ObjectDigest::from_bytes)
        .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
    let physical_identity = super::lifecycle_inventory::dataset_identity(dataset);
    let destination_name = format!("{}@aos-{}", dataset.name(), lowercase_hex(snapshot));
    Ok(ProtectedAtomicDatasetSnapshotMemberV1 {
        source_name: dataset.name().to_owned(),
        source_guid: dataset.guid(),
        destination_name,
        storage_handle,
        physical_identity,
    })
}

fn expected_authority_for_handle(
    journal: &VerifiedStorageResolverJournalV1,
    handle: ObjectDigest,
) -> Result<[u8; 16], LifecyclePhase6ErrorV1> {
    let mut matches = journal
        .operations()
        .filter_map(|(operation_id, operation)| {
            (operation.result().storage_handle() == Some(*handle.as_bytes()))
                .then_some(*operation_id)
        });
    let authority = matches
        .next()
        .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
    if matches.next().is_some() {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(authority)
}

fn grouped_program_commitment(
    plan: &LifecycleAtomicDatasetSnapshotPlanV1,
    members: &[ProtectedAtomicDatasetSnapshotMemberV1],
) -> ObjectDigest {
    grouped_program_commitment_fields(
        plan.commitment(),
        plan.effect_commitment(),
        plan.inventory_generation(),
        plan.inventory_source(),
        members,
    )
}

fn grouped_program_commitment_fields(
    plan: ObjectDigest,
    effect: ObjectDigest,
    inventory_generation: u64,
    inventory_source: ObjectDigest,
    members: &[ProtectedAtomicDatasetSnapshotMemberV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.storage.lifecycle-atomic-snapshot-program.v1\0")
        .chain_update(plan.as_bytes())
        .chain_update(effect.as_bytes())
        .chain_update(inventory_generation.to_be_bytes())
        .chain_update(inventory_source.as_bytes())
        .chain_update((members.len() as u32).to_be_bytes());
    for member in members {
        hasher = hasher
            .chain_update(member.storage_handle.as_bytes())
            .chain_update(member.physical_identity.as_bytes())
            .chain_update(member.source_guid.to_be_bytes())
            .chain_update(member.source_name.as_bytes())
            .chain_update([0])
            .chain_update(member.destination_name.as_bytes())
            .chain_update([0]);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
pub(crate) fn sample_atomic_snapshot_program_for_test() -> DormantAtomicDatasetSnapshotV1 {
    let plan = ObjectDigest::from_bytes([3; 32]);
    let effect = ObjectDigest::from_bytes([4; 32]);
    let catalog_source = ObjectDigest::from_bytes([5; 32]);
    let members = vec![ProtectedAtomicDatasetSnapshotMemberV1 {
        source_name: "tank/aos/dataset".to_owned(),
        source_guid: 6,
        destination_name: "tank/aos/dataset@aos-01".to_owned(),
        storage_handle: ObjectDigest::from_bytes([7; 32]),
        physical_identity: ObjectDigest::from_bytes([8; 32]),
    }];
    let commitment = grouped_program_commitment_fields(plan, effect, 9, catalog_source, &members);
    DormantAtomicDatasetSnapshotV1 {
        operation: [1; 16],
        snapshot: [2; 16],
        plan,
        effect,
        catalog_generation: 9,
        catalog_source,
        members,
        commitment,
    }
}

fn encode_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), LifecyclePhase6ErrorV1> {
    let length = u16::try_from(value.len()).map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
    if value.is_empty() || value.as_bytes().contains(&0) {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_text(bytes: &mut &[u8]) -> Result<String, LifecyclePhase6ErrorV1> {
    let length = usize::from(u16::from_be_bytes(take_array(bytes)?));
    let value = take(bytes, length)?;
    if value.is_empty() || value.contains(&0) {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    String::from_utf8(value.to_vec()).map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], LifecyclePhase6ErrorV1> {
    if bytes.len() < length {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    let (value, rest) = bytes.split_at(length);
    *bytes = rest;
    Ok(value)
}

fn take_array<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], LifecyclePhase6ErrorV1> {
    take(bytes, N)?
        .try_into()
        .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)
}

fn lowercase_hex(bytes: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
