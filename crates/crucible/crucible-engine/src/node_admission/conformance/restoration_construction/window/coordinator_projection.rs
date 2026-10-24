//! Projects finite future scope/preparation JSON without constructing authority.
//!
//! The selected constructor uses the actual values after the four-owner proof
//! and real readiness exist. These borrowed range projections only dominate
//! their closed strings, containers and encoded extents before Prepare.

use super::*;
use crate::node_contract::{
    HostSchedulingSource, OriginalLineageRuntimeRecord, SavedRuntimeOperation, SavedRuntimeResult,
};
use crucible_node_format::{HashRef, U64};
use crucible_node_transport::reference_packet::control::PacketControlSelection;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

pub(super) const COORDINATOR_FORMAT: &str = "crucible/coordinator-original-restoration-prepared/1";
pub(super) const CONTEXT_FORMAT: &str = "crucible/original-lineage-restoration-context/1";
const DIGEST: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

#[derive(Serialize)]
pub(super) struct FutureHash {
    algorithm: &'static str,
    domain: &'static str,
    digest: &'static str,
}

impl FutureHash {
    pub(super) fn scheduling() -> Self {
        Self {
            algorithm: "blake3-256",
            domain: "cnp.scheduler-continuation.v1",
            digest: DIGEST,
        }
    }
}

#[derive(Serialize)]
pub(super) struct FutureReference {
    hash: FutureHash,
    media_type: &'static str,
    length: U64,
}

impl FutureReference {
    pub(super) fn json() -> Self {
        Self {
            hash: FutureHash {
                algorithm: "blake3-256",
                domain: "cnp.blob.v1",
                digest: DIGEST,
            },
            media_type: "application/json",
            length: U64::new(u64::MAX),
        }
    }
}

pub(super) struct FutureScope<'a> {
    pub(super) archive: &'a CompleteOriginalRestorationSource,
    pub(super) record: &'a OriginalLineageRuntimeRecord,
    pub(super) target: &'a ActivationRecord,
}

impl Serialize for FutureScope<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OriginalLineageNativeScope", 9)?;
        state.serialize_field("coordinator_schema", &7u16)?;
        state.serialize_field("source_record", self.archive.runtime_object())?;
        state.serialize_field("source_capture", &self.record.source_activation)?;
        state.serialize_field("target", &TargetProjection(self.target))?;
        state.serialize_field(
            "owners",
            &FutureMappings {
                record: self.record,
                target: self.target,
            },
        )?;
        state.serialize_field("first_scopes", &FutureFirstScopes(self.record))?;
        state.serialize_field(
            "journals",
            &FutureJournals {
                archive: self.archive,
                record: self.record,
            },
        )?;
        state.serialize_field(
            "input_acknowledgements",
            &FutureAcknowledgements {
                record: self.record,
                target: self.target,
            },
        )?;
        state.serialize_field("proof", &FutureReference::json())?;
        state.end()
    }
}

struct FutureMappings<'a> {
    record: &'a OriginalLineageRuntimeRecord,
    target: &'a ActivationRecord,
}

impl Serialize for FutureMappings<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.record.owners.len()))?;
        for original in &self.record.owners {
            let target = target_owner(self.target, &original.identity.owner)
                .ok_or_else(|| serde::ser::Error::custom("missing actual target owner"))?;
            seq.serialize_element(&MappingProjection {
                source: &original.identity,
                target,
            })?;
        }
        seq.end()
    }
}

struct FutureFirstScopes<'a>(&'a OriginalLineageRuntimeRecord);

impl Serialize for FutureFirstScopes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut count = 0usize;
        for input in &self.0.inputs {
            if input.lineage.is_some() {
                count += 1;
            }
        }
        let mut seq = serializer.serialize_seq(Some(count))?;
        for input in &self.0.inputs {
            if let Some(lineage) = &input.lineage {
                seq.serialize_element(&lineage.source)?;
            }
        }
        seq.end()
    }
}

struct FutureJournals<'a> {
    archive: &'a CompleteOriginalRestorationSource,
    record: &'a OriginalLineageRuntimeRecord,
}

impl Serialize for FutureJournals<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(4))?;
        let mut previous: Option<&Id> = None;
        for _ in 0..4 {
            let mut next: Option<&Id> = None;
            for owner in self.archive.archive().owners() {
                let [node] = owner.participants.as_slice() else {
                    continue;
                };
                if previous.is_none_or(|last| last < node)
                    && next.is_none_or(|current| node < current)
                {
                    next = Some(node);
                }
            }
            let node =
                next.ok_or_else(|| serde::ser::Error::custom("incomplete actual node roster"))?;
            seq.serialize_element(&FutureJournal {
                record: self.record,
                node,
            })?;
            previous = Some(node);
        }
        seq.end()
    }
}

struct FutureJournal<'a> {
    record: &'a OriginalLineageRuntimeRecord,
    node: &'a Id,
}

impl Serialize for FutureJournal<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OriginalLineageJournal", 5)?;
        state.serialize_field("node", self.node)?;
        state.serialize_field(
            "operations",
            &FutureOperationIds {
                record: self.record,
                node: self.node,
                kind: JournalPartition::All,
            },
        )?;
        state.serialize_field(
            "pending_operations",
            &FutureOperationIds {
                record: self.record,
                node: self.node,
                kind: JournalPartition::Pending,
            },
        )?;
        state.serialize_field(
            "acknowledged_operations",
            &FutureOperationIds {
                record: self.record,
                node: self.node,
                kind: JournalPartition::Acknowledged,
            },
        )?;
        state.serialize_field(
            "input_stages",
            &FutureStageIds {
                record: self.record,
                node: self.node,
            },
        )?;
        state.end()
    }
}

#[derive(Clone, Copy)]
enum JournalPartition {
    All,
    Pending,
    Acknowledged,
}

impl JournalPartition {
    fn contains(self, operation: &SavedRuntimeOperation) -> bool {
        match self {
            Self::All => true,
            Self::Pending => matches!(operation.result, SavedRuntimeResult::Pending),
            Self::Acknowledged => matches!(operation.result, SavedRuntimeResult::Acknowledged(_)),
        }
    }
}

struct FutureOperationIds<'a> {
    record: &'a OriginalLineageRuntimeRecord,
    node: &'a Id,
    kind: JournalPartition,
}

impl Serialize for FutureOperationIds<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut count = 0usize;
        for row in &self.record.operations {
            if &row.route.node == self.node && self.kind.contains(row) {
                count += 1;
            }
        }
        let mut seq = serializer.serialize_seq(Some(count))?;
        for row in &self.record.operations {
            if &row.route.node == self.node && self.kind.contains(row) {
                seq.serialize_element(&row.operation)?;
            }
        }
        seq.end()
    }
}

struct FutureStageIds<'a> {
    record: &'a OriginalLineageRuntimeRecord,
    node: &'a Id,
}

impl Serialize for FutureStageIds<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut count = 0usize;
        for row in &self.record.inputs {
            if &row.node == self.node {
                count += 1;
            }
        }
        let mut seq = serializer.serialize_seq(Some(count))?;
        for row in &self.record.inputs {
            if &row.node == self.node {
                seq.serialize_element(&row.stage_operation)?;
            }
        }
        seq.end()
    }
}

struct FutureAcknowledgements<'a> {
    record: &'a OriginalLineageRuntimeRecord,
    target: &'a ActivationRecord,
}

impl Serialize for FutureAcknowledgements<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut count = 0usize;
        for input in &self.record.inputs {
            if input.acknowledgement.is_some() {
                count += 1;
            }
        }
        let mut seq = serializer.serialize_seq(Some(count))?;
        for input in &self.record.inputs {
            let Some(original) = &input.acknowledgement else {
                continue;
            };
            seq.serialize_element(&FutureAcknowledgement {
                stage_operation: &original.stage_operation,
                batch: &original.batch,
                node: &original.node,
                owners: FutureInputOwners {
                    source: &input.owners,
                    target: self.target,
                },
                cutoff: original.cutoff,
                inventory: &original.inventory,
                proof_ref: FutureReference::json(),
            })?;
        }
        seq.end()
    }
}

struct FutureInputOwners<'a> {
    source: &'a [crate::node_contract::OwnerIdentity],
    target: &'a ActivationRecord,
}

impl Serialize for FutureInputOwners<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.source.len()))?;
        for original in self.source {
            let target = target_owner(self.target, &original.owner)
                .ok_or_else(|| serde::ser::Error::custom("missing actual ACK target"))?;
            seq.serialize_element(target)?;
        }
        seq.end()
    }
}

#[derive(Clone, Copy)]
pub(super) struct FuturePreparedNode<'a> {
    node: &'a Id,
    owner: &'a crate::node_contract::OwnerIdentity,
    binding_hash: &'a HashRef,
    prepared_token: &'a Id,
    boundary: crucible_node_format::Position,
}

impl<'a> FuturePreparedNode<'a> {
    pub(super) fn native(
        selection: &'a PacketControlSelection,
        target: &'a ActivationRecord,
    ) -> Result<Self, RuntimeError> {
        let [descriptor] = selection.realization.descriptors.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let [owner] = selection.realization.owners.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let [owner_binding] = selection.realization.owner_bindings.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let [binding] = owner_binding.node_bindings.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        if owner_binding.owner != *owner || binding.node_id != descriptor.id {
            return Err(RuntimeError::ForeignAuthority);
        }
        let owner = target_owner(target, &owner.id).ok_or(RuntimeError::ForeignAuthority)?;
        Ok(Self {
            node: &descriptor.id,
            owner,
            binding_hash: &binding.binding_hash,
            prepared_token: &selection.prepared_token,
            boundary: target.boundary,
        })
    }

    pub(super) fn host(
        source: &'a HostSchedulingSource,
        target: &'a ActivationRecord,
    ) -> Result<Self, RuntimeError> {
        let selection = source.selection();
        let [binding] = selection.owner.node_bindings.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        if binding.node_id != selection.descriptor.id {
            return Err(RuntimeError::ForeignAuthority);
        }
        let owner = target_owner(target, &selection.owner.owner.id)
            .ok_or(RuntimeError::ForeignAuthority)?;
        Ok(Self {
            node: &selection.descriptor.id,
            owner,
            binding_hash: &binding.binding_hash,
            prepared_token: source.prepared_token(),
            boundary: target.boundary,
        })
    }
}

#[derive(Serialize)]
struct FutureReadiness<'a> {
    owners: [&'a crate::node_contract::OwnerIdentity; 1],
    boundary: crucible_node_format::Position,
    state_inventory: FutureReference,
    ready_receipt: FutureReference,
}

#[derive(Serialize)]
pub(super) struct FuturePreparedOwner<'a> {
    owner_id: &'a Id,
    incarnation_id: &'a Id,
    owner_generation: U64,
    binding_hashes: [&'a HashRef; 1],
    prepared_token: &'a Id,
    ready_receipt: FutureReference,
    extensions: crucible_node_format::Extensions,
}

impl FuturePreparedNode<'_> {
    pub(super) fn owner(&self) -> FuturePreparedOwner<'_> {
        FuturePreparedOwner {
            owner_id: &self.owner.owner,
            incarnation_id: &self.owner.incarnation,
            owner_generation: self.owner.generation,
            binding_hashes: [self.binding_hash],
            prepared_token: self.prepared_token,
            ready_receipt: FutureReference::json(),
            extensions: Default::default(),
        }
    }
}

impl Serialize for FuturePreparedNode<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ValidatedNodePreparation", 3)?;
        state.serialize_field("node", self.node)?;
        state.serialize_field(
            "readiness",
            &FutureReadiness {
                owners: [self.owner],
                boundary: self.boundary,
                state_inventory: FutureReference::json(),
                ready_receipt: FutureReference::json(),
            },
        )?;
        state.serialize_field("prepared_owners", &[self.owner()])?;
        state.end()
    }
}

pub(super) struct FuturePreparedNodes<'a>(pub(super) [FuturePreparedNode<'a>; 4]);

impl Serialize for FuturePreparedNodes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(4))?;
        let mut previous: Option<&Id> = None;
        for _ in 0..4 {
            let mut next: Option<&FuturePreparedNode<'_>> = None;
            for node in &self.0 {
                if previous.is_none_or(|last| last < node.node)
                    && next.is_none_or(|current| node.node < current.node)
                {
                    next = Some(node);
                }
            }
            let next =
                next.ok_or_else(|| serde::ser::Error::custom("duplicate actual prepared node"))?;
            seq.serialize_element(next)?;
            previous = Some(next.node);
        }
        seq.end()
    }
}

pub(super) struct FuturePreparedOwners<'a>(pub(super) &'a FuturePreparedNodes<'a>);

impl Serialize for FuturePreparedOwners<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(4))?;
        let mut previous: Option<&Id> = None;
        for _ in 0..4 {
            let mut next: Option<&FuturePreparedNode<'_>> = None;
            for node in &self.0.0 {
                if previous.is_none_or(|last| last < &node.owner.owner)
                    && next.is_none_or(|current| node.owner.owner < current.owner.owner)
                {
                    next = Some(node);
                }
            }
            let next =
                next.ok_or_else(|| serde::ser::Error::custom("duplicate actual prepared owner"))?;
            seq.serialize_element(&next.owner())?;
            previous = Some(&next.owner.owner);
        }
        seq.end()
    }
}

/// Borrows only the established target-five representation for selected data.
pub(super) struct TargetProjection<'a>(pub(super) &'a ActivationRecord);

impl Serialize for TargetProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let target = self.0;
        (
            &target.generation,
            &target.activation_id,
            &target.world_binding_hash,
            &target.owners,
            &target.boundary,
        )
            .serialize(serializer)
    }
}

pub(super) fn serialize_target<S: Serializer>(
    target: &ActivationRecord,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    TargetProjection(target).serialize(serializer)
}

pub(super) struct ActualScopeProjection<'a>(
    pub(super) &'a crate::node_contract::OriginalLineageNativeScope,
);

impl Serialize for ActualScopeProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let crate::node_contract::OriginalLineageNativeScope {
            coordinator_schema,
            source_record,
            source_capture,
            target,
            owners,
            first_scopes,
            journals,
            input_acknowledgements,
            proof,
        } = self.0;
        let mut state = serializer.serialize_struct("OriginalLineageNativeScope", 9)?;
        state.serialize_field("coordinator_schema", coordinator_schema)?;
        state.serialize_field("source_record", source_record)?;
        state.serialize_field("source_capture", source_capture)?;
        state.serialize_field("target", &TargetProjection(target))?;
        state.serialize_field("owners", &ActualMappings(owners))?;
        state.serialize_field("first_scopes", first_scopes)?;
        state.serialize_field("journals", &ActualJournals(journals))?;
        state.serialize_field("input_acknowledgements", input_acknowledgements)?;
        state.serialize_field("proof", proof)?;
        state.end()
    }
}

struct ActualMappings<'a>(&'a [crate::node_contract::OriginalLineageOwnerMapping]);

impl Serialize for ActualMappings<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for mapping in self.0 {
            let crate::node_contract::OriginalLineageOwnerMapping { source, target } = mapping;
            seq.serialize_element(&MappingProjection { source, target })?;
        }
        seq.end()
    }
}

struct ActualJournals<'a>(&'a [crate::node_contract::OriginalLineageJournal]);

impl Serialize for ActualJournals<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for journal in self.0 {
            let crate::node_contract::OriginalLineageJournal {
                node,
                operations,
                pending_operations,
                acknowledged_operations,
                input_stages,
            } = journal;
            seq.serialize_element(&ActualJournalProjection {
                node,
                operations,
                pending_operations,
                acknowledged_operations,
                input_stages,
            })?;
        }
        seq.end()
    }
}

#[derive(Serialize)]
struct MappingProjection<'a> {
    source: &'a crate::node_contract::OwnerIdentity,
    target: &'a crate::node_contract::OwnerIdentity,
}

#[derive(Serialize)]
struct FutureAcknowledgement<'a> {
    stage_operation: &'a Id,
    batch: &'a Id,
    node: &'a Id,
    owners: FutureInputOwners<'a>,
    cutoff: crucible_node_format::Position,
    inventory: &'a ContentRef,
    proof_ref: FutureReference,
}

#[derive(Serialize)]
struct ActualJournalProjection<'a> {
    node: &'a Id,
    operations: &'a [Id],
    pending_operations: &'a [Id],
    acknowledged_operations: &'a [Id],
    input_stages: &'a [Id],
}

fn target_owner<'a>(
    target: &'a ActivationRecord,
    id: &Id,
) -> Option<&'a crate::node_contract::OwnerIdentity> {
    for owner in &target.owners {
        if &owner.owner == id {
            return Some(owner);
        }
    }
    None
}

// This defining roster names the direct borrowed projections and concrete
// cursors. Serializer implementation work is separately priced by Core's
// actual serialization counter; recursive/compiler frames are not inferred.
pub(super) fn projection_counter_scratch_data() -> usize {
    use crate::node_contract::{
        OriginalLineageInputRecord, OriginalLineageJournal, OriginalLineageOwnerMapping,
        OwnerIdentity, SavedRuntimeOwner,
    };
    use std::mem::size_of;
    size_of::<FutureScope<'static>>()
        + size_of::<FutureMappings<'static>>()
        + size_of::<MappingProjection<'static>>()
        + size_of::<FutureFirstScopes<'static>>()
        + size_of::<FutureJournals<'static>>()
        + size_of::<FutureJournal<'static>>()
        + size_of::<FutureOperationIds<'static>>()
        + size_of::<FutureStageIds<'static>>()
        + size_of::<JournalPartition>()
        + size_of::<FutureAcknowledgements<'static>>()
        + size_of::<FutureAcknowledgement<'static>>()
        + size_of::<FutureInputOwners<'static>>()
        + size_of::<FuturePreparedNode<'static>>()
        + size_of::<FutureReadiness<'static>>()
        + size_of::<FuturePreparedOwner<'static>>()
        + size_of::<FuturePreparedNodes<'static>>()
        + size_of::<FuturePreparedOwners<'static>>()
        + size_of::<TargetProjection<'static>>()
        + size_of::<ActualScopeProjection<'static>>()
        + size_of::<ActualMappings<'static>>()
        + size_of::<ActualJournals<'static>>()
        + size_of::<ActualJournalProjection<'static>>()
        + size_of::<FutureHash>()
        + size_of::<FutureReference>()
        + size_of::<(
            &U64,
            &Id,
            &HashRef,
            &Vec<OwnerIdentity>,
            &crucible_node_format::Position,
        )>()
        + size_of::<std::slice::Iter<'static, OwnerIdentity>>()
        + size_of::<std::slice::Iter<'static, SavedRuntimeOwner>>()
        + size_of::<std::slice::Iter<'static, OriginalLineageInputRecord>>()
        + size_of::<std::slice::Iter<'static, SavedRuntimeOperation>>()
        + size_of::<std::slice::Iter<'static, OriginalLineageOwnerMapping>>()
        + size_of::<std::slice::Iter<'static, OriginalLineageJournal>>()
        + size_of::<std::slice::Iter<'static, crate::node_state::NativeOwnerState>>()
        + size_of::<std::slice::Iter<'static, FuturePreparedNode<'static>>>()
        + size_of::<Option<&Id>>()
        + size_of::<Option<&OwnerIdentity>>()
        + size_of::<Result<&OwnerIdentity, RuntimeError>>()
        + size_of::<Option<&FuturePreparedNode<'static>>>()
        + size_of::<Result<FuturePreparedNode<'static>, RuntimeError>>()
        + size_of::<[FuturePreparedNode<'static>; 4]>()
        + size_of::<[FuturePreparedOwner<'static>; 1]>()
        + size_of::<usize>()
        + size_of::<bool>()
        + size_of::<u16>()
}
