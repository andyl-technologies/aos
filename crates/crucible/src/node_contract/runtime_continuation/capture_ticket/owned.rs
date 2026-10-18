//! Counts requested heap extents of the actual typed core snapshot storage.
//!
//! Inline fields occupy their containing vector/box slots. This traversal counts
//! each owned allocation independently; equality of content or IDs is not shared
//! storage. Shared backing may be conservatively charged once per retained view.

use std::collections::BTreeMap;
use std::mem::size_of;

use super::*;
use crate::node_contract::NodeRuntime;

#[path = "host_node_owned.rs"]
mod host_node_owned;
#[path = "lineage_owned.rs"]
mod lineage_owned;
#[path = "opaque_owned.rs"]
mod opaque_owned;
pub use opaque_owned::{RetainedCoreOwnerStorage, RetainedCoreSharedAllocation};

pub(crate) trait OwnedStorage {
    fn owned_storage(&self) -> Result<usize, RuntimeError>;
}

impl OwnedStorage for String {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        Ok(self.capacity())
    }
}

impl OwnedStorage for Id {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        Ok(self.allocated_capacity())
    }
}

impl<T: OwnedStorage> OwnedStorage for Vec<T> {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let slots = self
            .capacity()
            .checked_mul(size_of::<T>())
            .ok_or(RuntimeError::ResourceLimit)?;
        self.iter().try_fold(slots, |bytes, value| {
            storage::add(bytes, value.owned_storage()?)
        })
    }
}

impl<T: OwnedStorage> OwnedStorage for Option<T> {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        self.as_ref().map_or(Ok(0), OwnedStorage::owned_storage)
    }
}

impl<T: OwnedStorage> OwnedStorage for Box<T> {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        storage::add(size_of::<T>(), self.as_ref().owned_storage()?)
    }
}

macro_rules! no_owned_storage {
    ($($type:ty),* $(,)?) => {
        $(impl OwnedStorage for $type {
            fn owned_storage(&self) -> Result<usize, RuntimeError> {
                Ok(0)
            }
        })*
    };
}

no_owned_storage!(bool, u8, u16, u32, u64, usize, U64, Position);

macro_rules! owned_fields {
    ($type:ty; $($field:ident),* $(,)?) => {
        impl OwnedStorage for $type {
            fn owned_storage(&self) -> Result<usize, RuntimeError> {
                let mut bytes = 0usize;
                $(bytes = storage::add(bytes, self.$field.owned_storage()?)?;)*
                Ok(bytes)
            }
        }
    };
}

owned_fields!(crucible_node_contract::HashRef; algorithm, domain, digest);
owned_fields!(ContentRef; hash, media_type);
owned_fields!(InputPayload; reference, bytes);
owned_fields!(crucible_node_contract::Endpoint; node_id, port_id, lane_id);
owned_fields!(crucible_node_contract::SchemaRef; id, definition, extensions);
owned_fields!(crate::node_contract::NativeStateKey; implementation, profile, schema);
owned_fields!(crucible_node_contract::OwnerRef; id, participant_ids, state_domain_ids);
owned_fields!(crucible_node_contract::NodeDescriptor;
    id, roles, model_ref, configuration_ref, initialization_ref, ports, extensions);
owned_fields!(crucible_node_contract::PortDescriptor;
    id, lanes, interface_id, features, configuration_ref, extensions);
owned_fields!(crucible_node_contract::LaneDescriptor; id, payload_schema, extensions);
owned_fields!(crucible_node_contract::NodeBinding; compatibility, authority, extensions);
owned_fields!(crucible_node_contract::OwnerBinding;
    owner, owner_roles, node_bindings, ownership_ref, extensions);
owned_fields!(crucible_node_contract::BindingCompatibility;
    node_id, descriptor_hash, implementation, profile_ref, configuration_ref,
    operating_contract, execution_owner, capture_owner, capabilities_ref,
    guarantees_ref, qualification_refs, extensions);
owned_fields!(crucible_node_contract::OperatingContract;
    ordering_profile, policy_ref, facets, extensions);
owned_fields!(crucible_node_contract::ImplementationIdentity;
    implementation_id, artifacts, model_definitions, formats, extensions);
owned_fields!(crucible_node_contract::LiveAuthority;
    session_id, incarnation_id, realization_id, activation_id, input_epoch,
    host_receipt, extensions);
owned_fields!(crucible_node_contract::NodeBindingRef; node_id, binding_hash, extensions);
owned_fields!(crucible_node_contract::FacetSelection;
    id, configuration_ref, guarantees_ref, extensions);
owned_fields!(crucible_node_contract::ArtifactIdentity; id, role, content, extensions);
owned_fields!(crucible_node_contract::GuaranteeProfile; limitations_ref, extensions);

owned_fields!(crate::node_contract::HostSchedulingConnectionDomain; connection, domain);
owned_fields!(crate::node_contract::HostSchedulingDomains; coordinator, connections);
owned_fields!(crate::node_contract::HostSchedulingSelection;
    descriptor, binding, owner, domains, operating_policy, guarantees);
owned_fields!(crate::node_contract::HostSchedulingContinuationRecord;
    source, runtime, scheduling, objects);

impl OwnedStorage for crate::node_contract::HostSchedulingRuntimeRecord {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::OriginalLineage(record) => record.owned_storage(),
            Self::Legacy(_) => Err(RuntimeError::UnsupportedFacet),
        }
    }
}

impl OwnedStorage for crate::node_scheduling::ExecutionPolicy {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::Exact {
                execution_proof_ref,
                boundary_settlement_ref,
                ceiling,
                ..
            } => {
                let bytes = storage::add(
                    execution_proof_ref.owned_storage()?,
                    boundary_settlement_ref.owned_storage()?,
                )?;
                match ceiling {
                    crate::node_scheduling::ExactCeiling::InputBlocked { proof_ref } => {
                        storage::add(bytes, proof_ref.owned_storage()?)
                    }
                    _ => Ok(bytes),
                }
            }
            Self::Quantized {
                window_proof_ref, ..
            } => window_proof_ref.owned_storage(),
        }
    }
}

owned_fields!(crate::node_contract::OwnerIdentity; owner, incarnation);
owned_fields!(crate::node_contract::NodeRoute; node, owners);
owned_fields!(crate::node_contract::SavedRuntimeActivation; activation_id, world_binding_hash, owners);
owned_fields!(crate::node_contract::ActivationRecord; activation_id, world_binding_hash, owners);
owned_fields!(OriginalLineageRuntimeRecord; source_activation, owners, operations, inputs);

owned_fields!(crate::node_contract::SavedRuntimeOwner; identity, operation, domains);
owned_fields!(crate::node_contract::SavedSchedulingCommit; node, operation, retained_outputs);
owned_fields!(crate::node_contract::SavedRuntimeOperation;
    operation, route, request, input_batch, result, close_submission,
    submission_effects, scheduling_commit);
owned_fields!(crate::node_contract::OriginalLineageProvenanceRecord;
    node, stage_operation, batch, inventory, roots, objects);
owned_fields!(crate::node_contract::OriginalLineageInputRecord;
    node, stage_operation, batch, owners, inventory, deliveries, payloads,
    provenance, lineage, acknowledgement, failure);

owned_fields!(crate::node_scheduling::SavedOwner; owner, incarnation);
owned_fields!(crate::node_scheduling::SavedProducer; node);
owned_fields!(crate::node_scheduling::SavedExternalPrefix; endpoint);
owned_fields!(crate::node_scheduling::SavedNativeSequence; endpoint);
owned_fields!(crate::node_scheduling::SavedPayload; reference, bytes);
owned_fields!(crate::node_scheduling::SavedPosition; owner);
owned_fields!(crate::node_scheduling::SavedReservation;
    operation, node, owner, permission, input_batch);
owned_fields!(crate::node_scheduling::SavedInputBatch;
    owner, node, stage_operation, batch, owners, inventory, deliveries, payloads,
    acknowledgement, activated_by, consumed);

owned_fields!(crate::node_contract::OperationFailure; reason, effects);
owned_fields!(crate::node_contract::OperationOutcome;
    operation, node, owners, progress, retained_outputs, scheduling);
owned_fields!(crate::node_scheduling::NativeInputAcknowledgement;
    stage_operation, batch, node, owners, inventory, proof_ref);
owned_fields!(crate::node_scheduling::InputIdentity; producer);
owned_fields!(crate::node_scheduling::event::Delivery;
    connection_id, connection_policy_ref, external_root, provenance_ref,
    publication_id, producer, consumer, producer_endpoint, consumer_endpoint,
    causal_parents, payload);
owned_fields!(crate::node_scheduling::NativeProducerBound; producer, proof_ref);
owned_fields!(crate::node_scheduling::NativeInputProgress; batch, consumed, proof_ref);
owned_fields!(crate::node_scheduling::NativePublication;
    publication_id, endpoint, causal_parents, payload, payload_bytes);
owned_fields!(crate::node_contract::SavedOriginalInputScope;
    source_activation, node, stage_operation, batch, owners, inventory);
owned_fields!(crate::node_contract::SavedOriginalPublication;
    origin, published, objects, rows);
owned_fields!(crate::node_contract::SavedOriginalInputLineage; source, publications);
owned_fields!(crate::node_contract::OriginalPublicationOrigin;
    owner_binding_hash, execution_owner_id, session_id, world_binding_hash,
    activation_id, incarnation_id, operation_id, grant_id, observation_batch,
    stop_receipt, measurement);
owned_fields!(crate::node_contract::OriginalLineageRow; object, dependencies);

impl OwnedStorage for crate::node_contract::OperationRequest {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::ExactRun { .. }
            | Self::BoundarySettle { .. }
            | Self::Pause
            | Self::Observe
            | Self::Capture
            | Self::Shutdown => Ok(0),
            Self::QuantumBegin {
                window,
                input_batch,
                ..
            } => storage::add(window.owned_storage()?, input_batch.owned_storage()?),
            Self::QuantumClose { window } => window.owned_storage(),
            Self::FaultInjectionV1(request) => request.owned_storage(),
            Self::DebugConditionV1(request) => request.owned_storage(),
            Self::FinalizeAssertions { barrier, receipt } => {
                storage::add(barrier.owned_storage()?, receipt.owned_storage()?)
            }
        }
    }
}

impl OwnedStorage for crate::node_contract::ProgressEvidence {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::Exact { .. } | Self::Administrative => Ok(0),
            Self::Quantized {
                window, closure, ..
            } => storage::add(window.owned_storage()?, closure.owned_storage()?),
            Self::Paused { stop_receipt, .. } => stop_receipt.owned_storage(),
            Self::AssertionsFinalized {
                barrier, report, ..
            } => storage::add(barrier.owned_storage()?, report.owned_storage()?),
            Self::FaultMutationApplied {
                receipt, program, ..
            } => storage::add(receipt.owned_storage()?, program.owned_storage()?),
            Self::DebugConditionAppliedV1 {
                stop_operation,
                barrier,
                report,
                control,
                ..
            } => {
                let bytes =
                    storage::add(stop_operation.owned_storage()?, barrier.owned_storage()?)?;
                let bytes = storage::add(bytes, report.owned_storage()?)?;
                storage::add(bytes, control.owned_storage()?)
            }
        }
    }
}

owned_fields!(crate::node_scheduling::NativeSchedulingObservation;
    node, owners, bounds, publications, input_progress, external_inputs, proof_ref);

impl OwnedStorage for crate::node_contract::SavedRuntimeResult {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::Pending => Ok(0),
            Self::Complete(outcome) | Self::Acknowledged(outcome) => outcome.owned_storage(),
            Self::Failed(failure) => failure.owned_storage(),
        }
    }
}

impl OwnedStorage for crate::node_scheduling::SavedPermission {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::ExactRun { .. } | Self::BoundarySettle { .. } => Ok(0),
            Self::Quantum {
                window,
                input_batch,
                ..
            } => storage::add(window.owned_storage()?, input_batch.owned_storage()?),
            Self::FaultInjectionV1 { request } => request.owned_storage(),
        }
    }
}

impl OwnedStorage for crate::node_scheduling::SchedulingSnapshot {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        if self.original_epochs.is_some() || !self.external_closed_prefixes.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut bytes = self.ordering_profile.owned_storage()?;
        macro_rules! field {
            ($($name:ident),* $(,)?) => {
                $(bytes = storage::add(bytes, self.$name.owned_storage()?)?;)*
            };
        }
        field!(
            world_binding_hash,
            source_activation_id,
            source_owners,
            positions,
            producers,
            native_sequences,
            external_closed_prefixes,
            payload_objects,
            pending_deliveries,
            used_operations,
            reservations,
            input_batches,
            used_input_batches
        );
        Ok(bytes)
    }
}

impl OwnedStorage for serde_json::Value {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::String(value) => value.owned_storage(),
            Self::Array(values) => values.owned_storage(),
            Self::Object(values) => {
                let nodes = values
                    .len()
                    .max(1)
                    .checked_mul(value_layout::map_node_bytes())
                    .ok_or(RuntimeError::ResourceLimit)?;
                values.iter().try_fold(nodes, |bytes, (key, value)| {
                    let bytes = storage::add(bytes, key.owned_storage()?)?;
                    storage::add(bytes, value.owned_storage()?)
                })
            }
            // The bound serde_json default/std Number is an inline enum, without
            // arbitrary_precision's owned decimal string representation.
            Self::Null | Self::Bool(_) | Self::Number(_) => Ok(0),
        }
    }
}

impl OwnedStorage for BTreeMap<String, serde_json::Value> {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let nodes = self
            .len()
            .max(1)
            .checked_mul(value_layout::map_node_bytes())
            .ok_or(RuntimeError::ResourceLimit)?;
        self.iter().try_fold(nodes, |bytes, (key, value)| {
            let bytes = storage::add(bytes, key.owned_storage()?)?;
            storage::add(bytes, value.owned_storage()?)
        })
    }
}

owned_fields!(crate::node_contract::Refusal; reason);

impl OwnedStorage for crate::node_contract::Submission {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::Refused(refusal) => refusal.owned_storage(),
            Self::Accepted => Ok(0),
            Self::Uncertain(effects) => effects.owned_storage(),
        }
    }
}

impl OwnedStorage for crate::node_contract::EffectKnowledge {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::CommittedPrefix(operations) => operations.owned_storage(),
            Self::None | Self::MayHaveProgressed | Self::Unknown => Ok(0),
        }
    }
}

owned_fields!(crucible_node_contract::CaptureManifest;
    capture_id, world_binding_hash, scenario_ref, preservation_contract,
    ordering_profile, guarantees_ref, coordinator_state_ref, owners,
    immutable_refs, provenance_ref, extensions);
owned_fields!(crucible_node_contract::CapturedOwner;
    capture_owner_id, participant_ids, state_domain_ids, binding_hashes,
    state_schema, state_ref, retained_source_ref, dependencies, capture_receipt,
    extensions);
owned_fields!(crate::node_contract::RuntimeOriginalCaptureJournal; attempts);
owned_fields!(crate::node_contract::OriginalCaptureAttemptRecord;
    capture_id, source_runtime, source_activation, owners);
owned_fields!(crate::node_contract::OriginalCaptureOwnerRecord;
    owner, participants, operation, state);

impl OwnedStorage for crate::node_contract::OriginalCaptureOwnerState {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::Settled { snapshot, journal } => {
                storage::add(snapshot.owned_storage()?, journal.owned_storage()?)
            }
            Self::Reserved | Self::Submitted | Self::Uncertain => Ok(0),
        }
    }
}

impl crate::node_contract::NodeRuntime {
    /// Bounds every inline container/boxed value reachable through the closed
    /// complete Host2 record. This is a layout bound, never a wire or source key.
    pub(crate) fn capture_closed_inline_storage() -> usize {
        [
            size_of::<crucible_node_contract::HashRef>(),
            size_of::<ContentRef>(),
            size_of::<InputPayload>(),
            size_of::<crucible_node_contract::Endpoint>(),
            size_of::<crucible_node_contract::SchemaRef>(),
            size_of::<crucible_node_contract::OwnerRef>(),
            size_of::<crucible_node_contract::NodeDescriptor>(),
            size_of::<crucible_node_contract::PortDescriptor>(),
            size_of::<crucible_node_contract::LaneDescriptor>(),
            size_of::<crucible_node_contract::NodeBinding>(),
            size_of::<crucible_node_contract::OwnerBinding>(),
            size_of::<crucible_node_contract::BindingCompatibility>(),
            size_of::<crucible_node_contract::OperatingContract>(),
            size_of::<crucible_node_contract::ImplementationIdentity>(),
            size_of::<crucible_node_contract::LiveAuthority>(),
            size_of::<crucible_node_contract::NodeBindingRef>(),
            size_of::<crucible_node_contract::FacetSelection>(),
            size_of::<crucible_node_contract::ArtifactIdentity>(),
            size_of::<crucible_node_contract::GuaranteeProfile>(),
            size_of::<crate::node_contract::HostSchedulingConnectionDomain>(),
            size_of::<crate::node_contract::HostSchedulingDomains>(),
            size_of::<crate::node_contract::HostSchedulingSelection>(),
            size_of::<crate::node_contract::HostSchedulingContinuationRecord>(),
            size_of::<crate::node_contract::OwnerIdentity>(),
            size_of::<crate::node_contract::NodeRoute>(),
            size_of::<crate::node_contract::SavedRuntimeActivation>(),
            size_of::<crate::node_contract::ActivationRecord>(),
            size_of::<OriginalLineageRuntimeRecord>(),
            size_of::<crate::node_contract::SavedRuntimeOwner>(),
            size_of::<crate::node_contract::SavedSchedulingCommit>(),
            size_of::<crate::node_contract::SavedRuntimeOperation>(),
            size_of::<crate::node_contract::OriginalLineageProvenanceRecord>(),
            size_of::<crate::node_contract::OriginalLineageInputRecord>(),
            size_of::<crate::node_scheduling::SavedOwner>(),
            size_of::<crate::node_scheduling::SavedProducer>(),
            size_of::<crate::node_scheduling::SavedExternalPrefix>(),
            size_of::<crate::node_scheduling::SavedNativeSequence>(),
            size_of::<crate::node_scheduling::SavedPayload>(),
            size_of::<crate::node_scheduling::SavedPosition>(),
            size_of::<crate::node_scheduling::SavedReservation>(),
            size_of::<crate::node_scheduling::SavedInputBatch>(),
            size_of::<crate::node_contract::OperationFailure>(),
            size_of::<crate::node_contract::OperationOutcome>(),
            size_of::<crate::node_scheduling::NativeInputAcknowledgement>(),
            size_of::<crate::node_scheduling::InputIdentity>(),
            size_of::<crate::node_scheduling::event::Delivery>(),
            size_of::<crate::node_scheduling::NativeProducerBound>(),
            size_of::<crate::node_scheduling::NativeInputProgress>(),
            size_of::<crate::node_scheduling::NativePublication>(),
            size_of::<crate::node_contract::SavedOriginalInputScope>(),
            size_of::<crate::node_contract::SavedOriginalPublication>(),
            size_of::<crate::node_contract::SavedOriginalInputLineage>(),
            size_of::<crate::node_contract::OriginalPublicationOrigin>(),
            size_of::<crate::node_contract::OriginalLineageRow>(),
            size_of::<crucible_node_contract::CaptureManifest>(),
            size_of::<crucible_node_contract::CapturedOwner>(),
            size_of::<crate::node_contract::RuntimeOriginalCaptureJournal>(),
            size_of::<crate::node_contract::OriginalCaptureAttemptRecord>(),
            size_of::<crate::node_contract::OriginalCaptureOwnerRecord>(),
            size_of::<crate::node_contract::HostSchedulingRuntimeRecord>(),
            size_of::<crate::node_contract::OperationRequest>(),
            size_of::<crate::node_contract::ProgressEvidence>(),
            size_of::<crate::node_contract::SavedRuntimeResult>(),
            size_of::<crate::node_scheduling::SavedPermission>(),
            size_of::<crate::node_scheduling::NativeSchedulingObservation>(),
            size_of::<crate::node_scheduling::SchedulingSnapshot>(),
            size_of::<crate::node_contract::EffectKnowledge>(),
            size_of::<crate::node_contract::OriginalCaptureOwnerState>(),
            size_of::<serde_json::Value>(),
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
    }

    pub(crate) fn capture_runtime_record_storage(
        record: &OriginalLineageRuntimeRecord,
    ) -> Result<usize, RuntimeError> {
        storage::add(
            size_of::<OriginalLineageRuntimeRecord>(),
            record.owned_storage()?,
        )
    }

    pub(crate) fn capture_scheduling_record_storage(
        record: &crate::node_scheduling::SchedulingSnapshot,
    ) -> Result<usize, RuntimeError> {
        storage::add(
            size_of::<crate::node_scheduling::SchedulingSnapshot>(),
            record.owned_storage()?,
        )
    }

    pub(crate) fn capture_owner_geometry_storage(
        row: &crate::node_state::CompleteOriginalOwnerCaptureGeometry,
    ) -> Result<usize, RuntimeError> {
        storage::add(
            row.owner.owned_storage()?,
            row.participants.owned_storage()?,
        )
    }

    /// Counts actual prepared native output metadata, excluding enclosing roots.
    ///
    /// # Errors
    /// Refuses overflow in the same actual typed owner/participant/key walk.
    pub(crate) fn capture_native_output_metadata_storage_data(
        owner: &crucible_node_contract::Id,
        participants: &Vec<crucible_node_contract::Id>,
        key: &crate::node_contract::NativeStateKey,
    ) -> Result<usize, RuntimeError> {
        storage::add(
            storage::add(owner.owned_storage()?, participants.owned_storage()?)?,
            key.owned_storage()?,
        )
    }

    /// Bounds a native output metadata clone from its actual borrowed fields.
    ///
    /// The defining walk includes source spare backing conservatively. A clone
    /// cannot use this DATA as permission or replace the original Source roster.
    ///
    /// # Errors
    /// Refuses checked requested-layout overflow in the full typed metadata.
    pub(crate) fn capture_native_output_metadata_clone_storage_data(
        owner: &crucible_node_contract::Id,
        participants: &Vec<crucible_node_contract::Id>,
        implementation: &crucible_node_contract::Id,
        profile: &crucible_node_contract::Id,
        schema: &crucible_node_contract::SchemaRef,
    ) -> Result<usize, RuntimeError> {
        [
            owner.owned_storage()?,
            participants.owned_storage()?,
            implementation.owned_storage()?,
            profile.owned_storage()?,
            schema.owned_storage()?,
        ]
        .into_iter()
        .try_fold(0, storage::add)
    }

    pub(crate) fn capture_native_key_storage(
        key: &crate::node_contract::NativeStateKey,
    ) -> Result<usize, RuntimeError> {
        key.owned_storage()
    }

    pub(crate) fn capture_reference_storage(value: &ContentRef) -> Result<usize, RuntimeError> {
        value.owned_storage()
    }

    pub(crate) fn capture_hash_storage(
        value: &crucible_node_contract::HashRef,
    ) -> Result<usize, RuntimeError> {
        value.owned_storage()
    }

    pub(crate) fn capture_manifest_storage(
        value: &crucible_node_contract::CaptureManifest,
    ) -> Result<usize, RuntimeError> {
        value.owned_storage()
    }

    pub(crate) fn capture_host_selection_storage(
        value: &crate::node_contract::HostSchedulingSelection,
    ) -> Result<usize, RuntimeError> {
        storage::add(
            std::mem::size_of::<crate::node_contract::HostSchedulingSelection>(),
            value.owned_storage()?,
        )
    }

    pub(crate) fn capture_host_record_storage(
        value: &crate::node_contract::HostSchedulingContinuationRecord,
    ) -> Result<usize, RuntimeError> {
        value.owned_storage()
    }

    pub(crate) fn capture_admin_attempt_storage(
        value: &crate::node_contract::OriginalCaptureAttemptRecord,
    ) -> Result<usize, RuntimeError> {
        storage::add(
            std::mem::size_of::<crate::node_contract::OriginalCaptureAttemptRecord>(),
            value.owned_storage()?,
        )
    }

    pub(crate) fn capture_admin_storage(
        value: &crate::node_contract::RuntimeOriginalCaptureJournal,
    ) -> Result<usize, RuntimeError> {
        value.owned_storage()
    }

    pub(crate) fn capture_shared_allocation_storage<T>() -> usize {
        storage::shared_allocation::<T>()
    }

    pub(crate) fn capture_future_decode_storage(
        value: &impl serde::Serialize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        super::serialization::future_decode_allocations(value, maximum)
    }

    pub(crate) fn capture_serialization_storage(
        value: &impl serde::Serialize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        super::serialization::value_allocations(value, maximum)
    }

    pub(crate) fn capture_map_node_storage<K, V>() -> usize {
        value_layout::map_node_bytes_for::<K, V>()
    }

    /// Bounds actual protocol tree nodes under the pinned compiler layout.
    ///
    /// Inputs come from the same borrowed typed metadata walk. The caller adds
    /// this term to all other retained and transient terms before admission.
    ///
    /// # Errors
    /// Refuses inconsistent container facts, invalid alignment, arithmetic
    /// overflow or a tree term exceeding the supplied remaining ceiling.
    pub(crate) fn capture_protocol_tree_storage(
        containers: usize,
        entries: usize,
        maximum_key_value_bytes: usize,
        maximum_entry_alignment: usize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        value_layout::protocol_tree_storage(
            containers,
            entries,
            maximum_key_value_bytes,
            maximum_entry_alignment,
            maximum,
        )
    }

    /// Bounds shared metadata headers independently of observed payload bytes.
    ///
    /// # Errors
    /// Refuses invalid nonempty alignment, arithmetic overflow or a header term
    /// exceeding the supplied remaining ceiling.
    pub(crate) fn capture_protocol_shared_header_storage(
        views: usize,
        maximum_data_alignment: usize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        storage::protocol_shared_header_storage(views, maximum_data_alignment, maximum)
    }
}

#[path = "retained_typed.rs"]
mod retained_typed;

impl NodeRuntime {
    pub(crate) fn capture_serialization_counter_scratch_data() -> usize {
        super::serialization::counter_scratch_data()
    }
}

/// Names the actual fixed descriptor bank used while the owning walk borrows it.
pub(crate) fn opaque_owner_counter_scratch_data() -> usize {
    size_of::<opaque_owned::RetainedCoreOwnerStorage<'_>>()
}

impl OwnedStorage for crate::node_contract::RuntimeSnapshot {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self {
            schema_version: _,
            source_activation,
            capture_cut: _,
            capture_ordinal: _,
            owners,
            operations,
            inputs,
            terminal,
            condition_stop,
        } = self;
        // The closed portless Clock family has no native input restorations.
        // Keep capacity of an empty original bank; unknown nonempty rows refuse.
        if !inputs.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let slots = inputs
            .capacity()
            .checked_mul(size_of::<crate::node_contract::SavedRuntimeInput>())
            .ok_or(RuntimeError::ResourceLimit)?;
        [
            source_activation.owned_storage()?,
            owners.owned_storage()?,
            operations.owned_storage()?,
            slots,
            terminal.owned_storage()?,
            condition_stop.owned_storage()?,
        ]
        .into_iter()
        .try_fold(0, storage::add)
    }
}

impl NodeRuntime {
    pub(crate) fn original_runtime_constructor_serialization_storage_data(
        value: &impl serde::Serialize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        super::serialization::original_constructor_value_allocations(value, maximum)
    }
}

impl NodeRuntime {
    pub(crate) fn original_restoration_coordinator_serialization_geometry_data(
        value: &impl serde::Serialize,
        maximum_decode_slot: usize,
        maximum: usize,
    ) -> Result<(usize, usize), RuntimeError> {
        super::serialization::original_constructor_and_decode_geometry(
            value,
            maximum_decode_slot,
            maximum,
        )
    }
}

// Test fixture construction intentionally fails immediately on invalid static DATA.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod submission_storage_tests {
    use super::*;
    use crate::node_contract::{
        EffectKnowledge, NodeRoute, Refusal, RuntimeSnapshot, SavedRuntimeActivation,
        SavedRuntimeOperation, SavedRuntimeResult, Submission,
    };
    use crucible_node_contract::{Phase, canonical};

    fn snapshot() -> RuntimeSnapshot {
        let reference = canonical::content_ref(b"activation", "application/octet-stream").unwrap();
        let at = Position::new(U64::new(1), U64::new(1), Phase::Publication);
        let operation = SavedRuntimeOperation {
            operation: Id::new("operation").unwrap(),
            route: NodeRoute {
                node: Id::new("node").unwrap(),
                owners: Vec::new(),
            },
            request: crate::node_contract::OperationRequest::Observe,
            input_batch: None,
            result: SavedRuntimeResult::Pending,
            close_submission: None,
            submission_effects: None,
            scheduling_commit: None,
        };
        let mut operations = Vec::with_capacity(4);
        operations.push(operation);

        RuntimeSnapshot {
            schema_version: 1,
            source_activation: SavedRuntimeActivation {
                generation: U64::new(1),
                activation_id: Id::new("activation").unwrap(),
                world_binding_hash: reference.hash,
                owners: Vec::new(),
                boundary: at,
            },
            capture_cut: at,
            capture_ordinal: U64::new(1),
            owners: Vec::new(),
            operations,
            inputs: Vec::new(),
            terminal: None,
            condition_stop: None,
        }
    }

    fn prefix_with_spare_capacity(slots: usize, identifier_capacity: usize) -> (Vec<Id>, usize) {
        let mut prefix = Vec::with_capacity(slots);
        for value in ["first", "second"] {
            let mut identifier = String::with_capacity(identifier_capacity);
            identifier.push_str(value);
            prefix.push(Id::new(identifier).unwrap());
        }
        assert!(prefix.capacity() > prefix.len());
        assert!(
            prefix
                .iter()
                .all(|id| id.allocated_capacity() > id.as_str().len())
        );

        let bytes = prefix.capacity() * size_of::<Id>()
            + prefix.iter().map(Id::allocated_capacity).sum::<usize>();
        (prefix, bytes)
    }

    #[test]
    fn refused_close_counts_reason_spare_capacity_in_bounded_snapshot_walk()
    -> Result<(), RuntimeError> {
        let mut snapshot = snapshot();
        let baseline =
            NodeRuntime::original_snapshot_requested_storage_data(&snapshot, usize::MAX)?;
        let mut reason = String::with_capacity(4096);
        reason.push_str("original close refused");
        let backing = reason.capacity();
        assert!(backing > reason.len());
        snapshot.operations[0].close_submission = Some(Submission::Refused(Refusal { reason }));

        let exact = baseline + backing;
        assert_eq!(
            NodeRuntime::original_snapshot_requested_storage_data(&snapshot, exact)?,
            exact
        );
        assert_eq!(
            NodeRuntime::original_snapshot_requested_storage_data(&snapshot, exact - 1),
            Err(RuntimeError::ResourceLimit)
        );
        let Some(Submission::Refused(refusal)) = &snapshot.operations[0].close_submission else {
            panic!("observation changed the original submission");
        };
        assert_eq!(refusal.reason, "original close refused");
        assert_eq!(refusal.reason.capacity(), backing);
        Ok(())
    }

    #[test]
    fn uncertain_close_and_dispatch_prefixes_keep_independent_spare_backing()
    -> Result<(), RuntimeError> {
        let mut snapshot = snapshot();
        let baseline =
            NodeRuntime::original_snapshot_requested_storage_data(&snapshot, usize::MAX)?;
        let (close_prefix, close_backing) = prefix_with_spare_capacity(8, 256);
        let (dispatch_prefix, dispatch_backing) = prefix_with_spare_capacity(12, 512);
        assert_eq!(close_prefix, dispatch_prefix);
        assert_ne!(close_prefix.as_ptr(), dispatch_prefix.as_ptr());
        snapshot.operations[0].close_submission = Some(Submission::Uncertain(
            EffectKnowledge::CommittedPrefix(close_prefix),
        ));
        snapshot.operations[0].submission_effects =
            Some(EffectKnowledge::CommittedPrefix(dispatch_prefix));

        let exact = baseline + close_backing + dispatch_backing;
        assert_eq!(
            NodeRuntime::original_snapshot_requested_storage_data(&snapshot, exact)?,
            exact
        );
        assert_eq!(
            NodeRuntime::original_snapshot_requested_storage_data(&snapshot, exact - 1),
            Err(RuntimeError::ResourceLimit)
        );
        // A failed observation does not release either retained original prefix.
        assert_eq!(
            NodeRuntime::original_snapshot_requested_storage_data(&snapshot, exact)?,
            exact
        );

        snapshot.operations[0].close_submission = Some(Submission::Accepted);
        snapshot.operations[0].submission_effects = Some(EffectKnowledge::Unknown);
        assert_eq!(
            NodeRuntime::original_snapshot_requested_storage_data(&snapshot, baseline)?,
            baseline
        );
        for effects in [EffectKnowledge::None, EffectKnowledge::MayHaveProgressed] {
            assert_eq!(Submission::Uncertain(effects).owned_storage()?, 0);
        }
        Ok(())
    }
}

#[path = "decoded_node17.rs"]
mod decoded_node17;

#[path = "decoded_initial15.rs"]
mod decoded_initial15;
