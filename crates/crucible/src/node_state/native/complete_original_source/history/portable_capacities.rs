//! Records exact portable children retained by a complete original Source.
//!
//! Exhaustive patterns keep the historical capacity walk tied to the defining
//! DTO. Inline scalar facts stay in the value stream; String, Vec, tree and Box
//! backing receive separate rows. Unsupported runtime families fail closed.

use crate::node_contract::RuntimeError;
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityRow, OriginalRestoredOwnerCapacityWalk,
};
use crucible_node_contract::U64;

// These are borrowed typed values. No owner, token or runtime is reconstructed.
macro_rules! fields {
    ($ty:ty; $($owned:ident),*; $($inline:ident),* $(,)?) => {
        impl OriginalRestoredOwnerCapacityWalk for $ty {
            fn capacities(
                &self,
                depth: usize,
                sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
            ) -> Result<(), RuntimeError> {
                let Self { $($owned,)* $($inline: _,)* } = self;
                $($owned.capacities(depth, sink)?;)*
                Ok(())
            }
        }
    };
}

fields!(crucible_node_contract::SchemaRef; id, definition, extensions; version);

fields!(crate::node_contract::NativeStateKey; implementation, profile, schema; );

fields!(crucible_node_contract::OwnerRef; id, participant_ids, state_domain_ids; );

fields!(crucible_node_contract::NodeDescriptor; id, roles, model_ref, configuration_ref, initialization_ref, ports, extensions; schema_version);

fields!(crucible_node_contract::PortDescriptor; id, lanes, interface_id, features, configuration_ref, extensions; );

fields!(crucible_node_contract::LaneDescriptor; id, payload_schema, extensions; direction, maximum_payload_bytes, maximum_pending_events);

fields!(crucible_node_contract::NodeBinding; compatibility, authority, extensions; );

fields!(crucible_node_contract::OwnerBinding; owner, owner_roles, node_bindings, ownership_ref, extensions; schema_version);

fields!(crucible_node_contract::BindingCompatibility; node_id, descriptor_hash, implementation, profile_ref, configuration_ref, operating_contract, execution_owner, capture_owner, capabilities_ref, guarantees_ref, qualification_refs, extensions; schema_version);

fields!(crucible_node_contract::OperatingContract; ordering_profile, policy_ref, facets, extensions; schema_version, mode, scheduling_role, resolution_ps, phase_ps);

fields!(crucible_node_contract::ImplementationIdentity; implementation_id, artifacts, model_definitions, formats, extensions; schema_version);

fields!(crucible_node_contract::LiveAuthority; session_id, incarnation_id, realization_id, activation_id, input_epoch, host_receipt, extensions; schema_version, world_generation, owner_generation);

fields!(crucible_node_contract::NodeBindingRef; node_id, binding_hash, extensions; );

fields!(crucible_node_contract::FacetSelection; id, configuration_ref, guarantees_ref, extensions; version);

fields!(crucible_node_contract::ArtifactIdentity; id, role, content, extensions; );

fields!(crucible_node_contract::GuaranteeProfile; limitations_ref, extensions; schema_version, repeatability, capture_scope, continuation, durable_restart, isolated_fork, conditional_replay);

fields!(crate::node_contract::HostSchedulingConnectionDomain; connection, domain; );

fields!(crate::node_contract::HostSchedulingDomains; coordinator, connections; );

fields!(crate::node_contract::HostSchedulingSelection; descriptor, binding, owner, domains, operating_policy, guarantees; );

fields!(crate::node_contract::HostSchedulingContinuationRecord; source, runtime, scheduling, objects; schema_version);

fields!(crate::node_contract::SavedRuntimeActivation; activation_id, world_binding_hash, owners; generation, boundary);

fields!(crate::node_contract::SavedRuntimeOwner; identity, operation, domains; lifecycle);

fields!(crate::node_contract::SavedSchedulingCommit; node, operation, retained_outputs; );

fields!(crate::node_contract::SavedRuntimeOperation; operation, route, request, input_batch, result, scheduling_commit, close_submission, submission_effects; );

fields!(crate::node_contract::OriginalLineageProvenanceRecord; node, stage_operation, batch, inventory, roots, objects; schema_version);

fields!(crate::node_contract::OriginalLineageInputRecord; node, stage_operation, batch, owners, inventory, deliveries, payloads, provenance, lineage, acknowledgement, failure; cutoff, committed, coordinator_committed);

fields!(crate::node_scheduling::SavedOwner; owner, incarnation; generation);

fields!(crate::node_scheduling::SavedProducer; node; bound, closed_prefix, next_sequence);

fields!(crate::node_scheduling::SavedExternalPrefix; endpoint; closed_before);

fields!(crate::node_scheduling::SavedNativeSequence; endpoint; last_sequence);

fields!(crate::node_scheduling::SavedPayload; reference, bytes; );

fields!(crate::node_scheduling::SavedPosition; owner; position);

fields!(crate::node_scheduling::SavedReservation; operation, node, owner, permission, input_batch; );

fields!(crate::node_scheduling::SavedInputBatch; owner, node, stage_operation, batch, owners, inventory, deliveries, payloads, acknowledgement, activated_by, consumed; cutoff, custody_edition, consumer_committed);

fields!(crate::node_contract::SavedOriginalInputScope; source_activation, node, stage_operation, batch, owners, inventory; cutoff);

fields!(crate::node_contract::SavedOriginalPublication; origin, published, objects, rows; );

fields!(crate::node_contract::SavedOriginalInputLineage; source, publications; schema_version);

fields!(crate::node_contract::OriginalPublicationOrigin; owner_binding_hash, execution_owner_id, session_id, world_binding_hash, activation_id, incarnation_id, operation_id, grant_id, observation_batch, stop_receipt, measurement; world_generation, owner_generation);

fields!(crate::node_contract::OriginalLineageRow; object, dependencies; );

fields!(crucible_node_contract::CaptureManifest; capture_id, world_binding_hash, scenario_ref, preservation_contract, ordering_profile, guarantees_ref, coordinator_state_ref, owners, immutable_refs, provenance_ref, extensions; schema_version, cut, event_ordinal);

fields!(crucible_node_contract::CapturedOwner; capture_owner_id, participant_ids, state_domain_ids, binding_hashes, state_schema, state_ref, retained_source_ref, dependencies, capture_receipt, extensions; representation);

fields!(crate::node_contract::RuntimeOriginalCaptureJournal; attempts; schema_version, maximum_attempts);

fields!(crate::node_contract::OriginalCaptureAttemptRecord; capture_id, source_runtime, source_activation, owners; sequence, cut, ordinal);

fields!(crate::node_contract::OriginalCaptureOwnerRecord; owner, participants, operation, state; );

fields!(crate::node_contract::OriginalLineageRuntimeRecord; source_activation, owners, operations, inputs; schema_version, capture_cut, capture_ordinal);

impl OriginalRestoredOwnerCapacityWalk for crate::node_scheduling::SchedulingSnapshot {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let Self {
            schema_version: _,
            original_epochs,
            ordering_profile,
            world_binding_hash,
            source_activation_id,
            source_generation: _,
            source_boundary: _,
            capture_cut: _,
            capture_ordinal: _,
            source_owners,
            maximum_microsteps: _,
            positions,
            producers,
            native_sequences,
            external_closed_prefixes,
            payload_objects,
            pending_deliveries,
            used_operations,
            reservations,
            input_batches,
            used_input_batches,
        } = self;
        // Complete OriginalLineage sources accept this saved family only. The
        // distinct epoch family needs its own defining traversal, never omission.
        if original_epochs.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        ordering_profile.capacities(depth, sink)?;
        world_binding_hash.capacities(depth, sink)?;
        source_activation_id.capacities(depth, sink)?;
        source_owners.capacities(depth, sink)?;
        positions.capacities(depth, sink)?;
        producers.capacities(depth, sink)?;
        native_sequences.capacities(depth, sink)?;
        external_closed_prefixes.capacities(depth, sink)?;
        payload_objects.capacities(depth, sink)?;
        pending_deliveries.capacities(depth, sink)?;
        used_operations.capacities(depth, sink)?;
        reservations.capacities(depth, sink)?;
        input_batches.capacities(depth, sink)?;
        used_input_batches.capacities(depth, sink)
    }
}

impl OriginalRestoredOwnerCapacityWalk for crate::node_contract::HostSchedulingRuntimeRecord {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::OriginalLineage(record) => record.capacities(depth, sink),
            Self::Legacy(_) => Err(RuntimeError::UnsupportedFacet),
        }
    }
}

impl OriginalRestoredOwnerCapacityWalk for crate::node_contract::SavedRuntimeResult {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::Pending => Ok(()),
            Self::Complete(outcome) | Self::Acknowledged(outcome) => {
                outcome.capacities(depth, sink)
            }
            Self::Failed(failure) => failure.capacities(depth, sink),
        }
    }
}

impl OriginalRestoredOwnerCapacityWalk for crate::node_contract::EffectKnowledge {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::CommittedPrefix(operations) => operations.capacities(depth, sink),
            Self::None | Self::MayHaveProgressed | Self::Unknown => Ok(()),
        }
    }
}

fields!(crate::node_contract::Refusal; reason;);

impl OriginalRestoredOwnerCapacityWalk for crate::node_contract::Submission {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::Refused(refusal) => refusal.capacities(depth, sink),
            Self::Accepted => Ok(()),
            Self::Uncertain(effects) => effects.capacities(depth, sink),
        }
    }
}

impl OriginalRestoredOwnerCapacityWalk for crate::node_contract::OriginalCaptureOwnerState {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::Settled { snapshot, journal } => {
                snapshot.capacities(depth, sink)?;
                journal.capacities(depth, sink)
            }
            Self::Reserved | Self::Submitted | Self::Uncertain => Ok(()),
        }
    }
}

impl OriginalRestoredOwnerCapacityWalk for crate::node_scheduling::SavedPermission {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::ExactRun {
                start: _,
                limit: _,
                input_blocked_park: _,
            }
            | Self::BoundarySettle { start: _, limit: _ } => Ok(()),
            Self::Quantum {
                window,
                start: _,
                end: _,
                input_batch,
                host_budget_ns: _,
            } => {
                window.capacities(depth, sink)?;
                input_batch.capacities(depth, sink)
            }
            Self::FaultInjectionV1 { request: _ } => Err(RuntimeError::UnsupportedFacet),
        }
    }
}

impl OriginalRestoredOwnerCapacityWalk for crate::node_scheduling::ExecutionPolicy {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::Exact {
                schema_version: _,
                execution_proof_ref,
                ceiling,
                boundary_settlement_ref,
            } => {
                execution_proof_ref.capacities(depth, sink)?;
                match ceiling {
                    crate::node_scheduling::ExactCeiling::StrictPredecessor => {}
                    crate::node_scheduling::ExactCeiling::InputBlocked { proof_ref } => {
                        proof_ref.capacities(depth, sink)?;
                    }
                }
                boundary_settlement_ref.capacities(depth, sink)
            }
            Self::Quantized {
                schema_version: _,
                quantum_ps: _,
                phase_ps: _,
                host_budget_ns: _,
                window_proof_ref,
            } => window_proof_ref.capacities(depth, sink),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows;
    use crate::node_contract::{
        EffectKnowledge, NodeRoute, OperationRequest, Refusal, SavedRuntimeOperation,
        SavedRuntimeResult, Submission,
    };
    use crucible_node_contract::{Id, Phase, Position, U64};

    #[test]
    fn saved_operation_preserves_refused_and_committed_submission_backing() {
        let mut reason = String::with_capacity(251);
        reason.push_str("original refused submission");
        let reason_capacity = reason.capacity();
        let mut committed = Vec::with_capacity(7);
        committed.push(Id::new("previous-real-operation").unwrap());
        let committed_capacity = committed.capacity();
        let operation = SavedRuntimeOperation {
            operation: Id::new("retained-operation").unwrap(),
            route: NodeRoute {
                node: Id::new("producer").unwrap(),
                owners: Vec::new(),
            },
            request: OperationRequest::BoundarySettle {
                start: Position::new(U64::new(4), U64::new(0), Phase::BoundaryControl),
                limit: Position::new(U64::new(5), U64::new(0), Phase::BoundaryControl),
            },
            input_batch: None,
            result: SavedRuntimeResult::Pending,
            close_submission: Some(Submission::Refused(Refusal { reason })),
            submission_effects: Some(EffectKnowledge::CommittedPrefix(committed)),
            scheduling_commit: None,
        };

        let rows = serde_json::to_value(OriginalRestoredOwnerCapacityRows(&operation)).unwrap();
        let rows = rows.as_array().unwrap();
        assert!(rows.iter().any(|row| {
            row["kind"] == "string"
                && row["capacity"] == reason_capacity
                && row["length"] == "original refused submission".len()
        }));
        assert!(rows.iter().any(|row| {
            row["kind"] == "vector" && row["capacity"] == committed_capacity && row["length"] == 1
        }));
        assert!(rows.iter().any(|row| {
            row["kind"] == "string" && row["length"] == "previous-real-operation".len()
        }));
        assert!(matches!(operation.result, SavedRuntimeResult::Pending));
    }
}

/// Names the direct exhaustive field loans and concrete saved-vector cursors.
///
/// Generic tree/Box traversal views are conjoined from the common defining
/// counter. These headers are independent of encoded or retained heap extents.
pub(super) fn counter_scratch_data() -> usize {
    let terms = [
        std::mem::size_of::<(&String,)>(),
        std::mem::size_of::<&crate::node_contract::Refusal>(),
        std::mem::size_of::<&crate::node_contract::Submission>(),
        std::mem::size_of::<&crate::node_contract::EffectKnowledge>(),
        std::mem::size_of::<&Vec<crucible_node_contract::Id>>(),
        std::mem::size_of::<&crate::node_contract::OperationOutcome>(),
        std::mem::size_of::<&crate::node_contract::OperationFailure>(),
        std::mem::size_of::<&crate::node_contract::SavedRuntimeResult>(),
        std::mem::size_of::<&crate::node_contract::HostSchedulingRuntimeRecord>(),
        std::mem::size_of::<&Box<crate::node_contract::OriginalLineageRuntimeRecord>>(),
        std::mem::size_of::<&crate::node_contract::OriginalCaptureOwnerState>(),
        std::mem::size_of::<(
            &crucible_node_contract::ContentRef,
            &Box<crucible_node_contract::ContentRef>,
        )>(),
        std::mem::size_of::<&crate::node_scheduling::SavedPermission>(),
        std::mem::size_of::<(&crucible_node_contract::Id, &crucible_node_contract::Id)>(),
        std::mem::size_of::<&crate::node_scheduling::ExecutionPolicy>(),
        std::mem::size_of::<&crate::node_scheduling::ExactCeiling>(),
        std::mem::size_of::<(
            &u16,
            &crucible_node_contract::ContentRef,
            &crate::node_scheduling::ExactCeiling,
            &Option<crucible_node_contract::ContentRef>,
        )>(),
        std::mem::size_of::<(
            &u16,
            &crucible_node_contract::U64,
            &crucible_node_contract::U64,
            &crucible_node_contract::U64,
            &crucible_node_contract::ContentRef,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Version,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::SchemaRef,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::IdSet,
            &'static crucible_node_contract::IdSet,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Version,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::IdSet,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::ContentRef,
            &'static Vec<crucible_node_contract::PortDescriptor>,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crucible_node_contract::PortDescriptor>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static Vec<crucible_node_contract::LaneDescriptor>,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::IdSet,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crucible_node_contract::LaneDescriptor>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Direction,
            &'static crucible_node_contract::SchemaRef,
            &'static crucible_node_contract::U64,
            &'static crucible_node_contract::U64,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::BindingCompatibility,
            &'static crucible_node_contract::LiveAuthority,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Version,
            &'static crucible_node_contract::OwnerRef,
            &'static crucible_node_contract::IdSet,
            &'static Vec<crucible_node_contract::NodeBindingRef>,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crucible_node_contract::NodeBindingRef>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Version,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::HashRef,
            &'static crucible_node_contract::ImplementationIdentity,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::OperatingContract,
            &'static crucible_node_contract::OwnerRef,
            &'static crucible_node_contract::OwnerRef,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::ContentRef,
            &'static Vec<crucible_node_contract::ContentRef>,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crucible_node_contract::ContentRef>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Version,
            &'static crucible_node_contract::OperatingMode,
            &'static crucible_node_contract::SchedulingRole,
            &'static String,
            &'static crucible_node_contract::ContentRef,
            &'static Option<U64>,
            &'static Option<U64>,
            &'static Vec<crucible_node_contract::FacetSelection>,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crucible_node_contract::FacetSelection>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Version,
            &'static crucible_node_contract::Id,
            &'static Vec<crucible_node_contract::ArtifactIdentity>,
            &'static Vec<crucible_node_contract::ContentRef>,
            &'static Vec<crucible_node_contract::SchemaRef>,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crucible_node_contract::ArtifactIdentity>>(),
        std::mem::size_of::<std::slice::Iter<'static, crucible_node_contract::SchemaRef>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Version,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static Option<crucible_node_contract::Id>,
            &'static crucible_node_contract::U64,
            &'static crucible_node_contract::U64,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::HashRef,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Version,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Version,
            &'static crucible_node_contract::Repeatability,
            &'static crucible_node_contract::CaptureScope,
            &'static crucible_node_contract::Continuation,
            &'static bool,
            &'static bool,
            &'static bool,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static Vec<crate::node_contract::HostSchedulingConnectionDomain>,
        )>(),
        std::mem::size_of::<
            std::slice::Iter<'static, crate::node_contract::HostSchedulingConnectionDomain>,
        >(),
        std::mem::size_of::<(
            &'static crucible_node_contract::NodeDescriptor,
            &'static crucible_node_contract::NodeBinding,
            &'static crucible_node_contract::OwnerBinding,
            &'static crate::node_contract::HostSchedulingDomains,
            &'static crate::node_scheduling::ExecutionPolicy,
            &'static crucible_node_contract::GuaranteeProfile,
        )>(),
        std::mem::size_of::<(
            &'static u16,
            &'static crate::node_contract::HostSchedulingSelection,
            &'static crate::node_contract::HostSchedulingRuntimeRecord,
            &'static crate::node_scheduling::SchedulingSnapshot,
            &'static Vec<crate::node_scheduling::InputPayload>,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crate::node_scheduling::InputPayload>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::U64,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::HashRef,
            &'static Vec<crate::node_contract::OwnerIdentity>,
            &'static crucible_node_contract::Position,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crate::node_contract::OwnerIdentity>>(),
        std::mem::size_of::<(
            &'static crate::node_contract::OwnerIdentity,
            &'static crate::node_contract::Lifecycle,
            &'static Option<crucible_node_contract::Id>,
            &'static Vec<crucible_node_contract::Id>,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crucible_node_contract::Id>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static Vec<crucible_node_contract::Id>,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crate::node_contract::NodeRoute,
            &'static crate::node_contract::OperationRequest,
            &'static Option<crucible_node_contract::Id>,
            &'static crate::node_contract::SavedRuntimeResult,
            &'static Option<crate::node_contract::Submission>,
            &'static Option<crate::node_contract::EffectKnowledge>,
            &'static Option<crate::node_contract::SavedSchedulingCommit>,
        )>(),
        std::mem::size_of::<(
            &'static u16,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::ContentRef,
            &'static Vec<crucible_node_contract::ContentRef>,
            &'static Vec<crucible_node_contract::ContentRef>,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static Vec<crate::node_contract::OwnerIdentity>,
            &'static crucible_node_contract::Position,
            &'static crucible_node_contract::ContentRef,
            &'static Vec<crate::node_scheduling::event::Delivery>,
            &'static Vec<crucible_node_contract::ContentRef>,
            &'static Option<crate::node_contract::OriginalLineageProvenanceRecord>,
            &'static Option<crate::node_contract::SavedOriginalInputLineage>,
            &'static Option<crate::node_scheduling::NativeInputAcknowledgement>,
            &'static Option<crate::node_contract::OperationFailure>,
            &'static bool,
            &'static bool,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crate::node_scheduling::event::Delivery>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::U64,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crate::node_scheduling::SavedBound,
            &'static crucible_node_contract::Position,
            &'static Option<U64>,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Endpoint,
            &'static crucible_node_contract::Position,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Endpoint,
            &'static crucible_node_contract::U64,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::ContentRef,
            &'static Vec<u8>,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, u8>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Position,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crate::node_scheduling::SavedPermission,
            &'static Option<crucible_node_contract::Id>,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static Vec<crate::node_contract::OwnerIdentity>,
            &'static crucible_node_contract::Position,
            &'static crucible_node_contract::ContentRef,
            &'static Vec<crate::node_scheduling::event::Delivery>,
            &'static Vec<crate::node_scheduling::InputPayload>,
            &'static Option<crate::node_scheduling::NativeInputAcknowledgement>,
            &'static Option<u16>,
            &'static bool,
            &'static Option<crucible_node_contract::Id>,
            &'static Vec<crate::node_scheduling::InputIdentity>,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crate::node_scheduling::event::Delivery>>(),
        std::mem::size_of::<std::slice::Iter<'static, crate::node_scheduling::InputIdentity>>(),
        std::mem::size_of::<(
            &'static crate::node_contract::EffectKnowledge,
            &'static String,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static Vec<crate::node_contract::OwnerIdentity>,
            &'static crucible_node_contract::Position,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::ContentRef,
        )>(),
        std::mem::size_of::<(
            &'static crate::node_contract::SavedRuntimeActivation,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static Vec<crate::node_contract::OwnerIdentity>,
            &'static crucible_node_contract::Position,
            &'static crucible_node_contract::ContentRef,
        )>(),
        std::mem::size_of::<(
            &'static crate::node_contract::OriginalPublicationOrigin,
            &'static crucible_node_contract::ContentRef,
            &'static Vec<crucible_node_contract::ContentRef>,
            &'static Vec<crate::node_contract::OriginalLineageRow>,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crate::node_contract::OriginalLineageRow>>(),
        std::mem::size_of::<(
            &'static u16,
            &'static crate::node_contract::SavedOriginalInputScope,
            &'static Vec<crate::node_contract::SavedOriginalPublication>,
        )>(),
        std::mem::size_of::<
            std::slice::Iter<'static, crate::node_contract::SavedOriginalPublication>,
        >(),
        std::mem::size_of::<(
            &'static crucible_node_contract::HashRef,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::HashRef,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::U64,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::U64,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::ContentRef,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::ContentRef,
            &'static Vec<crucible_node_contract::ContentRef>,
        )>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Version,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::HashRef,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::Position,
            &'static crucible_node_contract::U64,
            &'static String,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::ContentRef,
            &'static Vec<crucible_node_contract::CapturedOwner>,
            &'static Vec<crucible_node_contract::ContentRef>,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crucible_node_contract::CapturedOwner>>(),
        std::mem::size_of::<(
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::IdSet,
            &'static crucible_node_contract::IdSet,
            &'static Vec<crucible_node_contract::HashRef>,
            &'static crucible_node_contract::SchemaRef,
            &'static crucible_node_contract::CaptureRepresentation,
            &'static Option<crucible_node_contract::ContentRef>,
            &'static Option<crucible_node_contract::ContentRef>,
            &'static crucible_node_contract::IdSet,
            &'static crucible_node_contract::ContentRef,
            &'static crucible_node_contract::Extensions,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crucible_node_contract::HashRef>>(),
        std::mem::size_of::<(
            &'static u16,
            &'static crucible_node_contract::U64,
            &'static Vec<crate::node_contract::OriginalCaptureAttemptRecord>,
        )>(),
        std::mem::size_of::<
            std::slice::Iter<'static, crate::node_contract::OriginalCaptureAttemptRecord>,
        >(),
        std::mem::size_of::<(
            &'static crucible_node_contract::U64,
            &'static crucible_node_contract::Id,
            &'static crucible_node_contract::ContentRef,
            &'static crate::node_contract::SavedRuntimeActivation,
            &'static crucible_node_contract::Position,
            &'static crucible_node_contract::U64,
            &'static Vec<crate::node_contract::OriginalCaptureOwnerRecord>,
        )>(),
        std::mem::size_of::<
            std::slice::Iter<'static, crate::node_contract::OriginalCaptureOwnerRecord>,
        >(),
        std::mem::size_of::<(
            &'static crate::node_contract::OwnerIdentity,
            &'static Vec<crucible_node_contract::Id>,
            &'static crucible_node_contract::Id,
            &'static crate::node_contract::OriginalCaptureOwnerState,
        )>(),
        std::mem::size_of::<(
            &'static u16,
            &'static crate::node_contract::SavedRuntimeActivation,
            &'static crucible_node_contract::Position,
            &'static crucible_node_contract::U64,
            &'static Vec<crate::node_contract::SavedRuntimeOwner>,
            &'static Vec<crate::node_contract::SavedRuntimeOperation>,
            &'static Vec<crate::node_contract::OriginalLineageInputRecord>,
        )>(),
        std::mem::size_of::<std::slice::Iter<'static, crate::node_contract::SavedRuntimeOwner>>(),
        std::mem::size_of::<std::slice::Iter<'static, crate::node_contract::SavedRuntimeOperation>>(
        ),
        std::mem::size_of::<
            std::slice::Iter<'static, crate::node_contract::OriginalLineageInputRecord>,
        >(),
    ];
    let array_bytes = std::mem::size_of_val(&terms);
    let mut iterator = terms.into_iter();
    let iterator_bytes = std::mem::size_of_val(&iterator);
    array_bytes
        .checked_add(iterator_bytes)
        .and_then(|initial| iterator.try_fold(initial, usize::checked_add))
        .unwrap_or(usize::MAX)
}

fields!(crate::node_contract::RestoredHostSemanticAncestor; node, object; );

fields!(crate::node_contract::RestoredHostAncestry17; parent_archive_index, first_host, first_semantic; );

fields!(crate::node_contract::RestoredHostAdmissionPolicy17; ; maximum_nodes, maximum_owners, maximum_operations, maximum_retained_outputs);

fields!(crate::node_contract::HostSchedulingRestoredContinuationRecord17; source, runtime, scheduling, objects, ancestry, admission_policy; schema_version);
