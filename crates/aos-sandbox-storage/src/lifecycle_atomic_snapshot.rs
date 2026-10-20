//! Protected resolution for coordinated lifecycle dataset snapshots.
//!
//! The lifecycle layer supplies an opaque plan committed to the exact current
//! operation, SnapshotId, closed dependency set, Storage inventory head, and
//! stable member set. This module rereads the protected physical catalog and
//! proves exact equality with every owned Dataset row before any backend may
//! receive the single grouped transaction.

use std::collections::BTreeSet;

use aos_sandbox::lifecycle::{LifecycleAtomicDatasetSnapshotPlanV1, LifecyclePhase6ErrorV1};
use aos_sandbox_core::{ObjectDigest, SandboxId};
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1;
use sha2::{Digest as _, Sha256};

use crate::StorageAdmissionCoordinator;
use crate::catalog_transition::VerifiedPhysicalDatasetV1;
use crate::state::{VerifiedStorageResolverJournalV1, VerifiedStorageResolverOperationV1};

/// Keeps the actual partially encoded program through a later text rejection.
///
/// This inert owner supplies no authority or payment. Selected callers pay
/// reached program capacity through their genuine State stage before entry.
pub(crate) struct AtomicProgramEncodingOriginalV1 {
    bytes: Option<Vec<u8>>,
    count: Option<Result<u16, LifecyclePhase6ErrorV1>>,
    text: Option<Result<(), LifecyclePhase6ErrorV1>>,
    entered: bool,
    completed: bool,
}

impl AtomicProgramEncodingOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self { bytes: None, count: None, text: None, entered: false, completed: false }
    }

    pub(crate) fn failure(&self) -> Option<&LifecyclePhase6ErrorV1> {
        self.count.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.text.as_ref().and_then(|result| result.as_ref().err()))
    }
}

/// Retains a single protected grouped snapshot program after exact catalog reread.
///
/// Private source names and GUIDs are deliberately not exposed. Only Storage's
/// fixed backend adapter may consume the value and cross the mutation boundary.
#[derive(Clone)]
pub struct DormantAtomicDatasetSnapshotV1 {
    format_version: u16,
    operation: [u8; 16],
    snapshot: [u8; 16],
    plan: ObjectDigest,
    effect: ObjectDigest,
    catalog_generation: u64,
    catalog_source: ObjectDigest,
    catalog_head: ObjectDigest,
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

    pub(crate) const fn catalog_head(&self) -> ObjectDigest {
        self.catalog_head
    }

    pub(crate) const fn format_version(&self) -> u16 {
        self.format_version
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, LifecyclePhase6ErrorV1> {
        let mut original = AtomicProgramEncodingOriginalV1::new();
        self.canonical_bytes_retaining_v1(&mut original)
    }

    pub(crate) fn canonical_bytes_retaining_v1(
        &self,
        original: &mut AtomicProgramEncodingOriginalV1,
    ) -> Result<Vec<u8>, LifecyclePhase6ErrorV1> {
        if original.entered {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        original.entered = true;
        original.count = Some(u16::try_from(self.members.len())
            .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput));
        let count = match original.count.as_ref() {
            Some(Ok(count)) => *count,
            Some(Err(cause)) => return Err(*cause),
            None => std::process::abort(),
        };
        original.bytes = Some(Vec::with_capacity(192 + self.members.len() * 192));
        let Some(bytes) = original.bytes.as_mut() else {
            std::process::abort();
        };
        bytes.extend_from_slice(b"AOSASG01");
        bytes.extend_from_slice(&self.format_version.to_be_bytes());
        bytes.extend_from_slice(&self.operation);
        bytes.extend_from_slice(&self.snapshot);
        bytes.extend_from_slice(self.plan.as_bytes());
        bytes.extend_from_slice(self.effect.as_bytes());
        bytes.extend_from_slice(&self.catalog_generation.to_be_bytes());
        bytes.extend_from_slice(self.catalog_source.as_bytes());
        if self.format_version == 2 {
            bytes.extend_from_slice(self.catalog_head.as_bytes());
        }
        bytes.extend_from_slice(&count.to_be_bytes());
        for member in &self.members {
            original.text = Some(encode_text(bytes, &member.source_name));
            if let Some(Err(cause)) = original.text.as_ref() {
                return Err(*cause);
            }
            bytes.extend_from_slice(&member.source_guid.to_be_bytes());
            original.text = Some(encode_text(bytes, &member.destination_name));
            if let Some(Err(cause)) = original.text.as_ref() {
                return Err(*cause);
            }
            bytes.extend_from_slice(member.storage_handle.as_bytes());
            bytes.extend_from_slice(member.physical_identity.as_bytes());
        }
        bytes.extend_from_slice(self.commitment.as_bytes());
        original.completed = true;
        match original.bytes.take() {
            Some(bytes) => Ok(bytes),
            None => std::process::abort(),
        }
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LifecyclePhase6ErrorV1> {
        let mut bytes = bytes;
        if take(&mut bytes, 8)? != b"AOSASG01" {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let format_version = u16::from_be_bytes(take_array(&mut bytes)?);
        if !matches!(format_version, 1 | 2) {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let operation = take_array(&mut bytes)?;
        let snapshot = take_array(&mut bytes)?;
        let plan = ObjectDigest::from_bytes(take_array(&mut bytes)?);
        let effect = ObjectDigest::from_bytes(take_array(&mut bytes)?);
        let catalog_generation = u64::from_be_bytes(take_array(&mut bytes)?);
        let catalog_source = ObjectDigest::from_bytes(take_array(&mut bytes)?);
        let catalog_head = if format_version == 2 {
            ObjectDigest::from_bytes(take_array(&mut bytes)?)
        } else {
            catalog_source
        };
        let count = usize::from(u16::from_be_bytes(take_array(&mut bytes)?));
        if operation == [0; 16]
            || snapshot == [0; 16]
            || plan.as_bytes() == &[0; 32]
            || effect.as_bytes() == &[0; 32]
            || catalog_generation == 0
            || catalog_source.as_bytes() == &[0; 32]
            || catalog_head.as_bytes() == &[0; 32]
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
                    format_version,
                    plan,
                    effect,
                    catalog_generation,
                    catalog_source,
                    catalog_head,
                    &members,
                )
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            format_version,
            operation,
            snapshot,
            plan,
            effect,
            catalog_generation,
            catalog_source,
            catalog_head,
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
        || physical.binding().digest() != plan.inventory_head()
        || journal.genesis().digest() != plan.inventory_source()
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
        format_version: 2,
        operation: plan.operation().into_bytes(),
        snapshot: plan.snapshot().into_bytes(),
        plan: plan.commitment(),
        effect: plan.effect_commitment(),
        catalog_generation: plan.inventory_generation(),
        catalog_source: plan.inventory_source(),
        catalog_head: plan.inventory_head(),
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
        2,
        plan.commitment(),
        plan.effect_commitment(),
        plan.inventory_generation(),
        plan.inventory_source(),
        plan.inventory_head(),
        members,
    )
}

fn grouped_program_commitment_fields(
    format_version: u16,
    plan: ObjectDigest,
    effect: ObjectDigest,
    inventory_generation: u64,
    inventory_source: ObjectDigest,
    inventory_head: ObjectDigest,
    members: &[ProtectedAtomicDatasetSnapshotMemberV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(if format_version == 2 {
            b"aos.sandbox.storage.lifecycle-atomic-snapshot-program.v2\0".as_slice()
        } else {
            b"aos.sandbox.storage.lifecycle-atomic-snapshot-program.v1\0".as_slice()
        })
        .chain_update(plan.as_bytes())
        .chain_update(effect.as_bytes())
        .chain_update(inventory_generation.to_be_bytes())
        .chain_update(inventory_source.as_bytes());
    if format_version == 2 {
        hasher = hasher.chain_update(inventory_head.as_bytes());
    }
    hasher = hasher.chain_update((members.len() as u32).to_be_bytes());
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

pub(crate) fn atomic_snapshot_observation_digest(
    program: &DormantAtomicDatasetSnapshotV1,
    member_guids: &[u64],
) -> Result<ObjectDigest, LifecyclePhase6ErrorV1> {
    if member_guids.len() != program.member_count() || member_guids.contains(&0) {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    let mut observed = program
        .members()
        .iter()
        .zip(member_guids)
        .map(|(member, guid)| (member.destination_name(), *guid))
        .collect::<Vec<_>>();
    observed.sort_unstable();
    if !observed.windows(2).all(|pair| pair[0].0 < pair[1].0) {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    let count = observed.len();
    Ok(observation_rows_digest(program.commitment(), count, observed))
}

/// Retains the actual sorted observation slots through a semantic rejection.
///
/// Each slot keeps a private index into the separately retained immutable
/// program instead of a borrowed name, avoiding a self-referential owner.
pub(crate) struct AtomicObservationDigestOriginalV1 {
    observed: Option<Vec<(usize, u64)>>,
    input: Option<Result<(), LifecyclePhase6ErrorV1>>,
    unique: Option<Result<(), LifecyclePhase6ErrorV1>>,
    entered: bool,
    completed: bool,
}

impl AtomicObservationDigestOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self {
            observed: None,
            input: None,
            unique: None,
            entered: false,
            completed: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&LifecyclePhase6ErrorV1> {
        self.input.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.unique.as_ref().and_then(|result| result.as_ref().err()))
    }

    pub(crate) fn calculate_retaining_v1(
        &mut self,
        program: &DormantAtomicDatasetSnapshotV1,
        member_guids: &[u64],
    ) -> Result<ObjectDigest, LifecyclePhase6ErrorV1> {
        if self.entered {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        self.entered = true;
        self.input = Some(if member_guids.len() != program.member_count()
            || member_guids.contains(&0)
        {
            Err(LifecyclePhase6ErrorV1::InvalidInput)
        } else {
            Ok(())
        });
        if let Some(Err(cause)) = self.input.as_ref() {
            return Err(*cause);
        }
        self.observed = Some(program.members().iter().enumerate().zip(member_guids)
            .map(|((index, _), guid)| (index, *guid)).collect());
        let Some(observed) = self.observed.as_mut() else {
            std::process::abort();
        };
        observed.sort_unstable_by(|left, right| {
            observation_name(program, left.0).cmp(observation_name(program, right.0))
                .then_with(|| left.1.cmp(&right.1))
        });
        self.unique = Some(if observed.windows(2).all(|pair| {
            observation_name(program, pair[0].0) < observation_name(program, pair[1].0)
        }) {
            Ok(())
        } else {
            Err(LifecyclePhase6ErrorV1::InvalidInput)
        });
        if let Some(Err(cause)) = self.unique.as_ref() {
            return Err(*cause);
        }
        let digest = observation_rows_digest(
            program.commitment(), observed.len(), observed.iter().map(|(index, guid)| {
                (observation_name(program, *index), *guid)
            }),
        );
        self.completed = true;
        Ok(digest)
    }
}

// Both slot adapters use this one exact existing byte/hash recipe. The ordinary
// owned iterator ends before finalize, while selected slots stay on their owner.
fn observation_rows_digest<'name>(
    commitment: ObjectDigest,
    count: usize,
    observed: impl IntoIterator<Item = (&'name str, u64)>,
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.storage.atomic-snapshot-observation.v1\0")
        .chain_update(commitment.as_bytes())
        .chain_update((count as u32).to_be_bytes());
    for (name, guid) in observed {
        hasher = hasher
            .chain_update(name.as_bytes())
            .chain_update([0])
            .chain_update(guid.to_be_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn observation_name(program: &DormantAtomicDatasetSnapshotV1, index: usize) -> &str {
    match program.members().get(index) {
        Some(member) => member.destination_name(),
        // All private indices came from enumerating this same immutable input.
        None => std::process::abort(),
    }
}

/// Prices the actual reached index slots and their complete result owner.
///
/// # Errors
///
/// Returns checked memory or metadata overflow before any observation slots grow.
pub(crate) fn observation_digest_receiving_shape_v1(
    members: usize,
) -> Result<(usize, usize), aos_sandbox_core::AccountingError> {
    use aos_sandbox_core::{AccountingError, ResourceDimension};
    let bytes = members.max(4).checked_mul(std::mem::size_of::<(usize, u64)>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<AtomicObservationDigestOriginalV1>()))
        .ok_or(AccountingError::ArithmeticOverflow { dimension: ResourceDimension::MemoryBytes })?;
    let cells = members.checked_mul(2)
        .and_then(|cells| cells.checked_add(5))
        .and_then(|cells| cells.checked_mul(3))
        .and_then(|cells| cells.checked_add(6))
        .ok_or(AccountingError::ArithmeticOverflow { dimension: ResourceDimension::MetadataEntries })?;
    Ok((bytes, cells))
}

#[cfg(test)]
pub(crate) fn sample_atomic_snapshot_program_for_test() -> DormantAtomicDatasetSnapshotV1 {
    let plan = ObjectDigest::from_bytes([3; 32]);
    let effect = ObjectDigest::from_bytes([4; 32]);
    let catalog_source = ObjectDigest::from_bytes([5; 32]);
    let catalog_head = ObjectDigest::from_bytes([9; 32]);
    let members = vec![ProtectedAtomicDatasetSnapshotMemberV1 {
        source_name: "tank/aos/dataset".to_owned(),
        source_guid: 6,
        destination_name: "tank/aos/dataset@aos-01".to_owned(),
        storage_handle: ObjectDigest::from_bytes([7; 32]),
        physical_identity: ObjectDigest::from_bytes([8; 32]),
    }];
    let commitment = grouped_program_commitment_fields(
        2,
        plan,
        effect,
        9,
        catalog_source,
        catalog_head,
        &members,
    );
    DormantAtomicDatasetSnapshotV1 {
        format_version: 2,
        operation: [1; 16],
        snapshot: [2; 16],
        plan,
        effect,
        catalog_generation: 9,
        catalog_source,
        catalog_head,
        members,
        commitment,
    }
}

#[cfg(test)]
pub(crate) fn atomic_snapshot_program_for_catalog_test(
    generation: u64,
    catalog_source: ObjectDigest,
    catalog_head: ObjectDigest,
    source_name: &str,
    source_guid: u64,
) -> DormantAtomicDatasetSnapshotV1 {
    let plan = ObjectDigest::from_bytes([71; 32]);
    let effect = ObjectDigest::from_bytes([72; 32]);
    let members = vec![ProtectedAtomicDatasetSnapshotMemberV1 {
        source_name: source_name.to_owned(),
        source_guid,
        destination_name: format!("{source_name}@aos-{}", "02".repeat(16)),
        storage_handle: ObjectDigest::from_bytes([73; 32]),
        physical_identity: ObjectDigest::from_bytes([74; 32]),
    }];
    let commitment = grouped_program_commitment_fields(
        2,
        plan,
        effect,
        generation,
        catalog_source,
        catalog_head,
        &members,
    );
    DormantAtomicDatasetSnapshotV1 {
        format_version: 2,
        operation: [71; 16],
        snapshot: [2; 16],
        plan,
        effect,
        catalog_generation: generation,
        catalog_source,
        catalog_head,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_program_retains_legacy_head_source_without_upgrading_it() {
        let current = sample_atomic_snapshot_program_for_test();
        let encoded = current.canonical_bytes().unwrap();
        let decoded = DormantAtomicDatasetSnapshotV1::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(decoded.format_version(), 2);
        assert_eq!(decoded.catalog_source(), current.catalog_source());
        assert_eq!(decoded.catalog_head(), current.catalog_head());

        let mut legacy = current;
        legacy.format_version = 1;
        legacy.catalog_head = legacy.catalog_source;
        legacy.commitment = grouped_program_commitment_fields(
            1,
            legacy.plan,
            legacy.effect,
            legacy.catalog_generation,
            legacy.catalog_source,
            legacy.catalog_head,
            &legacy.members,
        );
        let encoded = legacy.canonical_bytes().unwrap();
        let decoded = DormantAtomicDatasetSnapshotV1::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(decoded.format_version(), 1);
        assert_eq!(decoded.catalog_head(), decoded.catalog_source());
    }
}

#[cfg(test)]
mod encoding_custody_tests {
    use super::*;

    #[test]
    fn rejected_later_member_text_keeps_the_actual_partial_program_and_cause() {
        let mut program = sample_atomic_snapshot_program_for_test();
        program.members[0].destination_name.clear();
        let mut original = AtomicProgramEncodingOriginalV1::new();

        assert_eq!(program.canonical_bytes_retaining_v1(&mut original),
            Err(LifecyclePhase6ErrorV1::InvalidInput));

        let partial = original.bytes.as_ref().unwrap();
        assert!(partial.starts_with(b"AOSASG01"));
        assert!(partial.windows(program.members[0].source_name.len())
            .any(|window| window == program.members[0].source_name.as_bytes()));
        assert!(partial.ends_with(&program.members[0].source_guid.to_be_bytes()));
        assert!(!original.completed);
        let cause = original.failure().unwrap() as *const LifecyclePhase6ErrorV1;
        let partial_pointer = partial.as_ptr();
        let partial_length = partial.len();

        assert_eq!(program.canonical_bytes_retaining_v1(&mut original),
            Err(LifecyclePhase6ErrorV1::InvalidTransition));
        assert_eq!(original.failure().unwrap() as *const LifecyclePhase6ErrorV1, cause);
        assert_eq!(original.bytes.as_ref().unwrap().as_ptr(), partial_pointer);
        assert_eq!(original.bytes.as_ref().unwrap().len(), partial_length);
        assert_eq!(program.canonical_bytes(), Err(LifecyclePhase6ErrorV1::InvalidInput));
    }
}

#[cfg(test)]
mod observation_digest_custody_tests {
    use super::*;

    fn two_members(duplicate_name: bool) -> DormantAtomicDatasetSnapshotV1 {
        let mut program = sample_atomic_snapshot_program_for_test();
        let mut second = program.members[0].clone();
        if !duplicate_name {
            second.source_name = "tank/aos/another".to_owned();
            second.destination_name = "tank/aos/another@aos-01".to_owned();
        }
        second.source_guid = 81;
        second.storage_handle = ObjectDigest::from_bytes([82; 32]);
        second.physical_identity = ObjectDigest::from_bytes([83; 32]);
        program.members.push(second);
        program.commitment = grouped_program_commitment_fields(
            program.format_version, program.plan, program.effect, program.catalog_generation,
            program.catalog_source, program.catalog_head, &program.members,
        );
        DormantAtomicDatasetSnapshotV1::from_canonical_bytes(
            &program.canonical_bytes().unwrap(),
        ).unwrap()
    }

    #[test]
    fn index_slots_preserve_the_existing_name_guid_digest_order() {
        let program = two_members(false);
        let guids: [u64; 2] = [84, 85];
        let mut previous_pairs = program.members().iter().zip(&guids)
            .map(|(member, guid)| (member.destination_name(), *guid)).collect::<Vec<_>>();
        previous_pairs.sort_unstable();
        let mut previous = Sha256::new()
            .chain_update(b"aos.sandbox.storage.atomic-snapshot-observation.v1\0")
            .chain_update(program.commitment().as_bytes())
            .chain_update((previous_pairs.len() as u32).to_be_bytes());
        for (name, guid) in previous_pairs {
            previous = previous.chain_update(name.as_bytes()).chain_update([0])
                .chain_update(guid.to_be_bytes());
        }
        let expected = ObjectDigest::from_bytes(previous.finalize().into());
        let mut selected = AtomicObservationDigestOriginalV1::new();

        assert_eq!(selected.calculate_retaining_v1(&program, &guids).unwrap(), expected);
        assert_eq!(atomic_snapshot_observation_digest(&program, &guids).unwrap(), expected);
        assert!(selected.completed);
        assert_eq!(selected.observed.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn duplicate_names_keep_the_actual_sorted_slots_and_first_error() {
        let program = two_members(true);
        let mut original = AtomicObservationDigestOriginalV1::new();

        assert_eq!(original.calculate_retaining_v1(&program, &[86, 87]),
            Err(LifecyclePhase6ErrorV1::InvalidInput));

        assert_eq!(original.observed.as_ref().unwrap().len(), 2);
        assert!(!original.completed);
        let pointer = original.observed.as_ref().unwrap().as_ptr();
        let cause = original.failure().unwrap() as *const LifecyclePhase6ErrorV1;
        assert_eq!(original.calculate_retaining_v1(&program, &[88, 89]),
            Err(LifecyclePhase6ErrorV1::InvalidTransition));
        assert_eq!(original.observed.as_ref().unwrap().as_ptr(), pointer);
        assert_eq!(original.failure().unwrap() as *const LifecyclePhase6ErrorV1, cause);
        assert_eq!(atomic_snapshot_observation_digest(&program, &[86, 87]),
            Err(LifecyclePhase6ErrorV1::InvalidInput));
    }
}
