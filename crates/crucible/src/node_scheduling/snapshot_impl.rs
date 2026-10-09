//! Paused coordinator extraction and fail-closed fresh-authority reconstruction.

use super::*;
use crate::node_contract::ActivationRecord;
use crate::node_scheduling::{
    RuntimeInputBatch, SavedBound, SavedExternalPrefix, SavedInputBatch, SavedNativeSequence,
    SavedOwner, SavedPayload, SavedPermission, SavedPosition, SavedProducer, SavedReservation,
    SchedulingSnapshot,
};
use crucible_node_contract::{MAX_ARRAY_ELEMENTS, Validate};

/// Retains a fully checked inactive coordinator pending complete world activation.
///
/// This value cannot issue grants. Native owners and the surrounding world cut
/// must already be independently verified before preparation is requested.
pub struct PreparedSchedulingRestore {
    target: ActivationRecord,
    snapshot: SchedulingSnapshot,
    input_acknowledgements: Vec<crate::node_scheduling::NativeInputAcknowledgement>,
    epochs: Option<super::super::SchedulingEpochEvidence>,
}

impl PreparedSchedulingRestore {
    /// Validates unresolved original operations under mandatory native continuation proof.
    ///
    /// # Errors
    /// Refuses changed source inventories or fresh staging evidence that does not
    /// bind the exact original batch and every current target owner incarnation.
    pub(crate) fn prepare_with_native_custody(
        graph: &AdmittedGraph,
        target: &ActivationRecord,
        snapshot: SchedulingSnapshot,
        verified: &crate::node_contract::VerifiedNativeContinuation,
    ) -> Result<Self, SchedulingError> {
        validate_snapshot(graph, target, &snapshot)?;
        let source_hash = snapshot.continuation_hash()?;
        if verified.target_activation() != target
            || verified.source_scheduler_hash() != &source_hash
        {
            return Err(SchedulingError::ForeignActivation);
        }
        if verified.scheduler_reservations() != snapshot.reservations
            || verified.scheduler_input_batches() != snapshot.input_batches
        {
            return Err(SchedulingError::UnresolvedCustody);
        }
        verified.proof().validate()?;
        let acknowledgements = verified.restored_input_acknowledgements();
        if acknowledgements.len()
            != snapshot
                .input_batches
                .iter()
                .filter(|batch| batch.acknowledgement.is_some())
                .count()
        {
            return Err(SchedulingError::UnresolvedCustody);
        }
        let mut ids = BTreeSet::new();
        for ack in acknowledgements {
            let batch = snapshot
                .input_batches
                .iter()
                .find(|batch| batch.batch == ack.batch && batch.acknowledgement.is_some())
                .ok_or(SchedulingError::UnresolvedCustody)?;
            let route: BTreeSet<_> = batch
                .owners
                .iter()
                .map(|owner| owner.owner.clone())
                .collect();
            let fresh: Vec<_> = target
                .owners
                .iter()
                .filter(|owner| route.contains(&owner.owner))
                .cloned()
                .collect();
            ack.proof_ref.validate()?;
            if !ids.insert(ack.batch.clone())
                || ack.stage_operation != batch.stage_operation
                || ack.node != batch.node
                || ack.inventory != batch.inventory
                || ack.cutoff != batch.cutoff
                || ack.owners != fresh
            {
                return Err(SchedulingError::UnresolvedCustody);
            }
        }
        Ok(Self {
            target: target.clone(),
            snapshot,
            input_acknowledgements: acknowledgements.to_vec(),
            epochs: verified.restored_scheduling_epochs().cloned(),
        })
    }

    /// Binds the checked coordinator to the original complete fresh activation.
    ///
    /// # Errors
    /// Refuses a different graph or activation than the staged target record.
    pub(crate) fn activate(
        self,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
    ) -> Result<CausalScheduler, SchedulingError> {
        if activation.record() != &self.target {
            return Err(SchedulingError::ForeignActivation);
        }
        let mut scheduler = CausalScheduler::new(graph, activation.clone())?;
        scheduler.load_snapshot(self.snapshot)?;
        scheduler.restored_epochs = self.epochs;
        for state in scheduler.input_batches.values_mut() {
            if state.acknowledgement.is_some() {
                state.acknowledgement = Some(
                    self.input_acknowledgements
                        .iter()
                        .find(|ack| ack.batch == state.batch.batch)
                        .ok_or(SchedulingError::UnresolvedCustody)?
                        .clone(),
                );
            }
        }
        Ok(scheduler)
    }
}

impl CausalScheduler {
    /// Extracts represented coordinator state under a trusted paused world cut.
    ///
    /// Calling this does not establish native suspension or a coherent world
    /// capture. The capture facade must independently retain that proof for all
    /// owners before publishing this record as part of a complete artifact.
    ///
    /// # Errors
    /// Refuses an unrepresentable budget or an unsupported retained permission
    /// before publishing a partial coordinator continuation record.
    pub(crate) fn snapshot(
        &self,
        capture_cut: Position,
        capture_ordinal: U64,
    ) -> Result<SchedulingSnapshot, SchedulingError> {
        let record = self.activation.record();
        let mut reservations = Vec::with_capacity(self.operations.len());
        for (operation, reservation) in &self.operations {
            let permission = match &reservation.request {
                OperationRequest::ExactRun {
                    start,
                    limit,
                    boundary_policy,
                } => SavedPermission::ExactRun {
                    start: *start,
                    limit: *limit,
                    input_blocked_park: *boundary_policy == ExactBoundaryPolicy::InputBlockedPark,
                },
                OperationRequest::BoundarySettle { start, limit } => {
                    SavedPermission::BoundarySettle {
                        start: *start,
                        limit: *limit,
                    }
                }
                OperationRequest::QuantumBegin {
                    window,
                    start,
                    end,
                    input_batch,
                    host_budget,
                } => SavedPermission::Quantum {
                    window: window.clone(),
                    start: *start,
                    end: *end,
                    input_batch: input_batch.clone(),
                    host_budget_ns: U64::new(
                        u64::try_from(host_budget.as_nanos())
                            .map_err(|_| SchedulingError::InvalidSnapshot)?,
                    ),
                },
                _ => return Err(SchedulingError::InvalidSnapshot),
            };
            reservations.push(SavedReservation {
                operation: operation.clone(),
                node: reservation.node.clone(),
                owner: reservation.owner.clone(),
                permission,
                input_batch: reservation.input_batch.clone(),
            });
        }
        let original_epochs = self.retained_epoch_rows(&reservations)?;
        Ok(SchedulingSnapshot {
            schema_version: if original_epochs.is_some() { 2 } else { 1 },
            original_epochs,
            ordering_profile: "superdense-v1".into(),
            world_binding_hash: record.world_binding_hash.clone(),
            source_activation_id: record.activation_id.clone(),
            source_generation: record.generation,
            source_boundary: record.boundary,
            capture_cut,
            capture_ordinal,
            source_owners: record
                .owners
                .iter()
                .map(|owner| SavedOwner {
                    owner: owner.owner.clone(),
                    incarnation: owner.incarnation.clone(),
                    generation: owner.generation,
                })
                .collect(),
            maximum_microsteps: self.maximum_microsteps,
            positions: self
                .owners
                .iter()
                .map(|(owner, schedule)| SavedPosition {
                    owner: owner.clone(),
                    position: schedule.cursor,
                })
                .collect(),
            producers: self
                .bounds
                .iter()
                .map(|(node, bound)| SavedProducer {
                    node: node.clone(),
                    bound: match bound {
                        OutputBound::Unknown => SavedBound::Unknown,
                        OutputBound::At(position) => SavedBound::At {
                            position: *position,
                        },
                        OutputBound::AfterInstant(time_ps) => {
                            SavedBound::AfterInstant { time_ps: *time_ps }
                        }
                    },
                    next_sequence: self.sequences.next(node),
                    closed_prefix: self.closed_prefixes[node],
                })
                .collect(),
            external_closed_prefixes: self
                .external_closed_prefixes
                .iter()
                .map(|(endpoint, closed_before)| SavedExternalPrefix {
                    endpoint: endpoint.clone(),
                    closed_before: *closed_before,
                })
                .collect(),
            native_sequences: self
                .native_sequences
                .iter()
                .map(|(endpoint, sequence)| SavedNativeSequence {
                    endpoint: endpoint.clone(),
                    last_sequence: *sequence,
                })
                .collect(),
            payload_objects: self
                .payloads
                .iter()
                .map(|(reference, bytes)| SavedPayload {
                    reference: reference.clone(),
                    bytes: bytes.clone(),
                })
                .collect(),
            pending_deliveries: self.pending.values().cloned().collect(),
            used_operations: self.used_operations.iter().cloned().collect(),
            reservations,
            input_batches: self
                .input_batches
                .iter()
                .map(|(owner, state)| SavedInputBatch {
                    owner: owner.clone(),
                    node: state.batch.node.clone(),
                    stage_operation: state.batch.stage_operation.clone(),
                    batch: state.batch.batch.clone(),
                    owners: state.batch.owners.clone(),
                    cutoff: state.batch.cutoff,
                    inventory: state.batch.inventory.clone(),
                    deliveries: state.batch.deliveries.clone(),
                    payloads: state.batch.payloads.clone(),
                    acknowledgement: state.acknowledgement.clone(),
                    activated_by: state.activated_by.clone(),
                    consumed: state.consumed.clone(),
                })
                .collect(),
            used_input_batches: self.used_input_batches.iter().cloned().collect(),
        })
    }

    pub(super) fn load_snapshot(
        &mut self,
        snapshot: SchedulingSnapshot,
    ) -> Result<(), SchedulingError> {
        for saved in snapshot.positions {
            self.owners
                .get_mut(&saved.owner)
                .ok_or(SchedulingError::InvalidSnapshot)?
                .cursor = saved.position;
        }
        for saved in snapshot.producers {
            let bound = match saved.bound {
                SavedBound::Unknown => OutputBound::Unknown,
                SavedBound::At { position } => OutputBound::At(position),
                SavedBound::AfterInstant { time_ps } => OutputBound::AfterInstant(time_ps),
            };
            self.bounds.insert(saved.node.clone(), bound);
            self.sequences
                .restore_next(saved.node.clone(), saved.next_sequence);
            self.closed_prefixes.insert(saved.node, saved.closed_prefix);
        }
        self.pending = snapshot
            .pending_deliveries
            .into_iter()
            .map(|delivery| (delivery.key(), delivery))
            .collect();
        self.used_operations = snapshot.used_operations.into_iter().collect();
        self.external_closed_prefixes = snapshot
            .external_closed_prefixes
            .into_iter()
            .map(|saved| (saved.endpoint, saved.closed_before))
            .collect();
        self.native_sequences = snapshot
            .native_sequences
            .into_iter()
            .map(|saved| (saved.endpoint, saved.last_sequence))
            .collect();
        self.payloads = snapshot
            .payload_objects
            .into_iter()
            .map(|saved| (saved.reference, saved.bytes))
            .collect();
        self.used_input_batches = snapshot.used_input_batches.into_iter().collect();
        for saved in snapshot.reservations {
            let request = saved_request(&saved.permission);
            self.owners
                .get_mut(&saved.owner)
                .ok_or(SchedulingError::InvalidSnapshot)?
                .reserved = Some(saved.operation.clone());
            self.operations.insert(
                saved.operation,
                Reservation {
                    node: saved.node,
                    owner: saved.owner,
                    request,
                    input_batch: saved.input_batch,
                },
            );
        }
        for saved in snapshot.input_batches {
            let owners = self
                .node_routes
                .get(&saved.node)
                .ok_or(SchedulingError::InvalidSnapshot)?
                .clone();
            let acknowledgement = saved.acknowledgement;
            let batch = RuntimeInputBatch {
                activation: self.activation.clone(),
                node: saved.node,
                stage_operation: saved.stage_operation,
                batch: saved.batch,
                owners,
                cutoff: saved.cutoff,
                inventory: saved.inventory,
                deliveries: saved.deliveries,
                payloads: saved.payloads,
            };
            self.input_batches.insert(
                saved.owner,
                InputBatchState {
                    batch,
                    acknowledgement,
                    activated_by: saved.activated_by,
                    consumed: saved.consumed,
                },
            );
        }
        Ok(())
    }
}

fn saved_request(permission: &SavedPermission) -> OperationRequest {
    match permission {
        SavedPermission::ExactRun {
            start,
            limit,
            input_blocked_park,
        } => OperationRequest::ExactRun {
            start: *start,
            limit: *limit,
            boundary_policy: if *input_blocked_park {
                ExactBoundaryPolicy::InputBlockedPark
            } else {
                ExactBoundaryPolicy::HorizonPark
            },
        },
        SavedPermission::BoundarySettle { start, limit } => OperationRequest::BoundarySettle {
            start: *start,
            limit: *limit,
        },
        SavedPermission::Quantum {
            window,
            start,
            end,
            input_batch,
            host_budget_ns,
        } => OperationRequest::QuantumBegin {
            window: window.clone(),
            start: *start,
            end: *end,
            input_batch: input_batch.clone(),
            host_budget: Duration::from_nanos(host_budget_ns.get()),
        },
    }
}

#[path = "snapshot_validation.rs"]
mod validation;

pub use validation::validate_saved_source;
use validation::validate_snapshot;
#[cfg(test)]
pub(super) use validation::validate_structure;
