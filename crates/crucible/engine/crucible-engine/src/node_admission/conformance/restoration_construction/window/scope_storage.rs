//! Prices the actual complete scope and context copies before Prepare.
//!
//! The source record and target are genuine retained inputs. Native proof
//! identities are not known before Commit, so their closed fixed byte arrays
//! use the maximal u8 JSON spelling for the same later projection. No request,
//! proof, context, owner clone or permission is created by this DATA walk.

use super::*;
use crate::node_contract::runtime_owned_counter::OwnedStorage;
use crate::node_contract::{
    OriginalLineageJournal, OriginalLineageNativeScope, OriginalLineageOwnerMapping,
    OriginalLineageRestoration, OriginalLineageRuntimeRecord, SavedOriginalInputScope,
};
use serde::Serialize;
use std::mem::size_of_val;

pub(super) const SCOPE_PROOF_MEDIA: &str = "application/json";
pub(super) const SCOPE_PROOF_FORMAT: &str = "source-owned.complete-restoration-scope/1";

#[derive(Serialize)]
pub(super) struct OriginalRestorationScopeProofProjection<'a> {
    pub(super) schema: &'static str,
    pub(super) source_artifact: &'a ContentRef,
    pub(super) source_runtime: &'a ContentRef,
    #[serde(serialize_with = "super::coordinator_projection::serialize_target")]
    pub(super) target: &'a ActivationRecord,
    pub(super) native_held_reference_identities: [[u8; 32]; 3],
}

#[derive(Clone, Copy)]
pub(super) struct OriginalRestorationFinalConstructionData {
    pub(super) scope_peak_bytes: usize,
    pub(super) context_peak_bytes: usize,
}

impl OriginalRestorationFinalConstructionData {
    pub(super) fn quote(
        archive: &CompleteOriginalRestorationSource,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        let record = archive.original_runtime_record_data()?;
        if record.owners.len() != 4
            || activation.owners.len() != 4
            || archive.archive().owners().len() != 4
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        // The source roster supplies exact node identifiers. The installed
        // collector separately matches them to the actual four runtime nodes.
        let mut scope = checked_sum(
            &[
                // A separate stable target clone binds later coordinator/common DATA.
                activation.owned_storage()?,
                4 * size_of::<OriginalLineageOwnerMapping>(),
                4 * size_of::<OriginalLineageJournal>(),
                record.source_activation.owned_storage()?,
                activation.owned_storage()?,
                NodeRuntime::capture_reference_storage(archive.runtime_object())?,
            ],
            maximum,
        )?;
        for owner in &record.owners {
            let target = activation
                .owners
                .iter()
                .find(|target| target.owner == owner.identity.owner)
                .ok_or(RuntimeError::ForeignAuthority)?;
            scope = checked_sum(
                &[
                    scope,
                    owner.identity.owned_storage()?,
                    target.owned_storage()?,
                ],
                maximum,
            )?;
        }
        for owner in archive.archive().owners() {
            let [node] = owner.participants.as_slice() else {
                return Err(RuntimeError::UnsupportedFacet);
            };
            scope = checked_sum(&[scope, node.allocated_capacity()], maximum)?;
        }
        for operation in &record.operations {
            // Every operation appears once in the complete journal and once
            // more only in its actual pending or acknowledged partition.
            let partitions = match operation.result {
                crate::node_contract::SavedRuntimeResult::Pending
                | crate::node_contract::SavedRuntimeResult::Acknowledged(_) => 2,
                _ => 1,
            };
            scope = checked_sum(
                &[
                    scope,
                    partitions * size_of::<Id>(),
                    operation
                        .operation
                        .allocated_capacity()
                        .checked_mul(partitions)
                        .ok_or(RuntimeError::ResourceLimit)?,
                ],
                maximum,
            )?;
        }
        let proof_children =
            "blake3-256".len() + "cnp.blob.v1".len() + 64 + SCOPE_PROOF_MEDIA.len();
        // The final scope retains its own proof reference, independent of every
        // fresh ACK reference and of the canonical proof body's owning bank.
        scope = checked_sum(&[scope, proof_children], maximum)?;
        for input in &record.inputs {
            scope = checked_sum(
                &[
                    scope,
                    size_of::<Id>(),
                    input.stage_operation.allocated_capacity(),
                ],
                maximum,
            )?;
            if let Some(lineage) = &input.lineage {
                scope = checked_sum(
                    &[
                        scope,
                        size_of::<SavedOriginalInputScope>(),
                        lineage.source.owned_storage()?,
                    ],
                    maximum,
                )?;
            }
            if let Some(acknowledgement) = &input.acknowledgement {
                // These are unchanged actual stage/batch/cut/inventory facts.
                // Fresh ownership and proof have their own new constructor.
                scope = checked_sum(
                    &[
                        scope,
                        size_of::<crate::node_scheduling::NativeInputAcknowledgement>(),
                        acknowledgement.stage_operation.allocated_capacity(),
                        acknowledgement.batch.allocated_capacity(),
                        acknowledgement.node.allocated_capacity(),
                        acknowledgement.inventory.owned_storage()?,
                        proof_children,
                        input
                            .owners
                            .len()
                            .checked_mul(size_of::<crate::node_contract::OwnerIdentity>())
                            .ok_or(RuntimeError::ResourceLimit)?,
                    ],
                    maximum,
                )?;
                for original in &input.owners {
                    let target = activation
                        .owners
                        .iter()
                        .find(|target| target.owner == original.owner)
                        .ok_or(RuntimeError::ForeignAuthority)?;
                    scope = checked_sum(&[scope, target.owned_storage()?], maximum)?;
                }
            }
        }
        let projection = OriginalRestorationScopeProofProjection {
            schema: SCOPE_PROOF_FORMAT,
            source_artifact: archive.archive().artifact(),
            source_runtime: archive.runtime_object(),
            target: activation,
            native_held_reference_identities: [[u8::MAX; 32]; 3],
        };
        let proof = NodeRuntime::original_runtime_constructor_serialization_storage_data(
            &projection,
            maximum,
        )?;
        let scope_peak_bytes = checked_sum(
            &[
                scope,
                proof,
                size_of::<OriginalLineageNativeScope>(),
                size_of::<serde_json::Value>(),
                size_of::<Vec<u8>>(),
                size_of::<ContentRef>(),
                proof_children,
            ],
            maximum,
        )?;
        // The existing opaque context owns independent record/scope copies.
        // Scheduler identity hashes the real retained scheduling projection.
        let scheduling = &archive.original_host_record_data()?.scheduling;
        let context_peak_bytes = checked_sum(
            &[
                size_of::<OriginalLineageRestoration<'static>>(),
                2 * size_of::<Id>(),
                "cnp-activate-".len() + activation.activation_id.as_str().len(),
                "cnp-world-activate-".len() + activation.activation_id.as_str().len(),
                archive.original_installed_context_validation_storage_data(maximum)?,
                NodeRuntime::capture_runtime_record_storage(record)?,
                scope,
                NodeRuntime::capture_reference_storage(archive.runtime_object())?,
                NodeRuntime::original_runtime_constructor_serialization_storage_data(
                    scheduling, maximum,
                )?,
                "blake3-256".len() + "cnp.scheduler-continuation.v1".len() + 64,
            ],
            maximum,
        )?;
        Ok(Self {
            scope_peak_bytes,
            context_peak_bytes,
        })
    }

    pub(super) fn requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        self.scope_peak_bytes
            .checked_add(self.context_peak_bytes)
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<Self>() + size_of::<Result<Self, RuntimeError>>()
            + super::scope_owner::OriginalRestorationScopeOwner::counter_scratch_data()
            + super::coordinator_projection::projection_counter_scratch_data()
            + size_of::<Result<OriginalLineageRestoration<'static>, RuntimeError>>()
            + size_of::<Result<&OriginalLineageRuntimeRecord, RuntimeError>>()
            + size_of::<Result<&OriginalLineageNativeScope, RuntimeError>>()
            + CompleteOriginalRestorationSource::original_installed_context_validation_counter_scratch_data()
            + size_of::<OriginalRestorationScopeProofProjection<'static>>()
            + size_of::<Result<serde_json::Value, serde_json::Error>>()
            + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
            + size_of::<Result<ContentRef, crucible_node_format::ContractError>>()
            + size_of::<blake3::Hasher>() + size_of::<blake3::Hash>()
            + size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
            + size_of::<[u8; 32]>() + size_of::<[[u8; 32]; 3]>()
            + size_of::<[usize; 8]>() + size_of::<std::slice::Iter<'static, crate::node_contract::SavedRuntimeOperation>>()
            + size_of::<std::slice::Iter<'static, crate::node_contract::OriginalLineageInputRecord>>()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            // The pinned U64 serializer's actual bounded formatter bank.
            + 20
    }
}
