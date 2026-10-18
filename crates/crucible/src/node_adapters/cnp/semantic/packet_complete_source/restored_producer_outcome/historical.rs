//! Maps authenticated immutable Producer receipts without live owner reconstruction.
//!
//! These DATA projections share the live mapping algorithms. They neither
//! authenticate a signed archive nor issue a Source, World or operation grant.

use super::*;
use crucible_node_contract::{HashRef, Id, U64};

/// Borrows the exact original immutable Producer installation facts.
#[derive(Clone, Copy)]
pub(crate) struct OriginalRestoredProducerHistoricalInstallationData<'a> {
    pub(crate) descriptor: &'a NodeDescriptor,
    pub(crate) owner: &'a Id,
    pub(crate) incarnation: &'a Id,
    pub(crate) generation: U64,
    pub(crate) world_binding: &'a HashRef,
    pub(crate) program: &'a crucible_node_provider::reference_packet::PacketProgramDefinition,
}

/// Borrows an already checked grant-free common admission's historical facts.
pub(crate) struct OriginalRestoredProducerHistoricalAdmissionData<'a> {
    pub(crate) operation: &'a Id,
    pub(crate) route: &'a NodeRoute,
    pub(crate) request: &'a OperationRequest,
    pub(crate) world_binding: &'a HashRef,
    pub(crate) activation_owners: &'a [OwnerIdentity],
}

impl PacketCompleteSemanticSource {
    /// Maps a completed historical native Producer result to common DATA.
    ///
    /// # Errors
    /// Refuses invalid immutable inventory, unsupported operation shape, changed
    /// grant/route/World lineage, or an unrepresentable publication allocation.
    pub(crate) fn original_restored_producer_historical_mapped_outcome_data(
        original: OriginalRestoredProducerHistoricalAdmissionData<'_>,
        install: OriginalRestoredProducerHistoricalInstallationData<'_>,
        restored: &crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredRecord,
        producer: &crucible_node_provider::reference_packet::control::PacketNativeRecord,
        measurement: &ContentRef,
    ) -> Result<OperationOutcome, RuntimeError> {
        PacketSemanticSource::original_restored_producer_historical_inventory_data(
            install.program,
            producer,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        restored
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if restored.physical_gate_held || producer.inventory.gate_closed {
            return Err(RuntimeError::InvalidReceipt);
        }
        let (start, limit) = match original.request {
            OperationRequest::ExactRun {
                start,
                limit,
                boundary_policy: ExactBoundaryPolicy::HorizonPark,
            }
            | OperationRequest::BoundarySettle { start, limit } => (*start, *limit),
            _ => return Err(RuntimeError::UnsupportedFacet),
        };
        let grant = producer
            .grant
            .as_ref()
            .ok_or(RuntimeError::InvalidReceipt)?;
        if !grant.complete
            || grant.operation != *original.operation
            || grant.start != start
            || grant.limit != limit
            || grant.inventory != producer.inventory
            || producer.inventory.reached < start
            || producer.inventory.reached > limit
            || grant.newborn != producer.inventory.retained_outputs
            || producer.original.operation_id.0.as_ref() != Some(original.operation)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let route = original.route;
        if route.node != install.descriptor.id
            || route.owners.len() != 1
            || route.owners[0].owner != *install.owner
            || route.owners[0].incarnation != *install.incarnation
            || route.owners[0].generation != install.generation
            || *original.world_binding != *install.world_binding
            || !original.activation_owners.contains(&route.owners[0])
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let [port] = install.descriptor.ports.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let [lane] = port.lanes.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let mut publications = Vec::new();
        publications
            .try_reserve_exact(grant.newborn.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for output in &grant.newborn {
            publications.push(NativePublication {
                publication_id: output.event.clone(),
                endpoint: Endpoint {
                    node_id: route.node.clone(),
                    port_id: port.id.clone(),
                    lane_id: lane.id.clone(),
                },
                native_sequence: output.sequence,
                publication: output.publication,
                evaluation: Some(output.evaluation),
                causal_parents: Vec::new(),
                payload: canonical::content_ref(
                    output.payload.as_slice(),
                    "application/octet-stream",
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?,
                payload_bytes: output.payload.as_slice().to_vec(),
            });
        }
        let future_output = producer
            .inventory
            .pending
            .iter()
            .filter(|event| event.payload.is_some())
            .map(|event| event.completion)
            .min();
        let bound =
            future_output
                .map(NativeOutputBound::At)
                .unwrap_or(NativeOutputBound::AfterInstant(
                    producer.inventory.reached.time_ps,
                ));
        let stop = if producer.inventory.reached == limit {
            StopReason::HorizonPark
        } else {
            // The separate native transition validator establishes that this is
            // the first still-pending payload callback, with no skipped effect.
            if !producer.inventory.pending.iter().any(|event| {
                event.payload.is_some()
                    && event.evaluation == producer.inventory.reached
                    && event.evaluation < limit
            }) {
                return Err(RuntimeError::InvalidReceipt);
            }
            StopReason::Output
        };
        let retained_outputs = publications
            .iter()
            .map(|publication| publication.publication_id.clone())
            .collect();
        let scheduling = NativeSchedulingObservation {
            node: route.node.clone(),
            owners: route.owners.clone(),
            reached: producer.inventory.reached,
            closed_prefix: producer.inventory.reached,
            bounds: vec![NativeProducerBound {
                producer: route.node.clone(),
                bound,
                proof_ref: measurement.clone(),
            }],
            publications,
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: measurement.clone(),
        };
        Ok(OperationOutcome {
            operation: original.operation.clone(),
            node: route.node.clone(),
            owners: route.owners.clone(),
            progress: ProgressEvidence::Exact {
                reached: producer.inventory.reached,
                stop,
            },
            retained_outputs,
            scheduling: Some(scheduling),
        })
    }

    /// Maps a retired historical checkpoint without constructing a World.
    ///
    /// # Errors
    /// Refuses invalid inventory, an outstanding grant/output, or changed
    /// original owner generation and archived World binding.
    pub(crate) fn original_restored_producer_historical_checkpoint_scheduling_data(
        world_binding: &HashRef,
        activation_owners: &[OwnerIdentity],
        install: OriginalRestoredProducerHistoricalInstallationData<'_>,
        restored: &crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredRecord,
        producer: &crucible_node_provider::reference_packet::control::PacketNativeRecord,
        measurement: &ContentRef,
    ) -> Result<NativeSchedulingObservation, RuntimeError> {
        PacketSemanticSource::original_restored_producer_historical_inventory_data(
            install.program,
            producer,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        restored
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if restored.physical_gate_held
            || producer.inventory.gate_closed
            || producer.grant.is_some()
            || !producer.inventory.retained_outputs.is_empty()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let mut owner = None;
        for candidate in activation_owners {
            if candidate.owner == *install.owner {
                if owner.replace(candidate).is_some() {
                    return Err(RuntimeError::ForeignAuthority);
                }
            }
        }
        let owner = owner.ok_or(RuntimeError::ForeignAuthority)?;
        if *world_binding != *install.world_binding
            || owner.incarnation != *install.incarnation
            || owner.generation != install.generation
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let bound = producer
            .inventory
            .pending
            .iter()
            .filter(|event| event.payload.is_some())
            .map(|event| event.completion)
            .min()
            .map(NativeOutputBound::At)
            .unwrap_or(NativeOutputBound::AfterInstant(
                producer.inventory.reached.time_ps,
            ));
        Ok(NativeSchedulingObservation {
            node: install.descriptor.id.clone(),
            owners: vec![owner.clone()],
            reached: producer.inventory.reached,
            closed_prefix: producer.inventory.reached,
            bounds: vec![NativeProducerBound {
                producer: install.descriptor.id.clone(),
                bound,
                proof_ref: measurement.clone(),
            }],
            publications: Vec::new(),
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: measurement.clone(),
        })
    }
}
