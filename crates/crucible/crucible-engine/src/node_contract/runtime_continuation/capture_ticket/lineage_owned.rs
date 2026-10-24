//! Counts actual typed lineage owners without issuing input or capture authority.

use super::{OwnedStorage, RuntimeError, storage};
use crate::node_contract::{NodeRuntime, OriginalPublicationClaim, SavedOriginalInputScope};
use crate::node_scheduling::RuntimeInputBatch;

impl OwnedStorage for crucible_node_format::Event {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let mut bytes = self.id.owned_storage()?;
        for next in [
            self.source.owned_storage()?,
            self.destination.owned_storage()?,
            self.causal_parent_ids.owned_storage()?,
            self.payload.owned_storage()?,
            self.provenance_ref.owned_storage()?,
            self.extensions.owned_storage()?,
        ] {
            bytes = storage::add(bytes, next)?;
        }
        Ok(bytes)
    }
}

impl OwnedStorage for OriginalPublicationClaim {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let mut bytes = self.event.owned_storage()?;
        for next in [
            self.origin.owned_storage()?,
            self.published.owned_storage()?,
            self.objects.owned_storage()?,
            self.rows.owned_storage()?,
        ] {
            bytes = storage::add(bytes, next)?;
        }
        Ok(bytes)
    }
}

impl NodeRuntime {
    pub(crate) fn capture_original_scope_storage(
        value: &SavedOriginalInputScope,
    ) -> Result<usize, RuntimeError> {
        value.owned_storage()
    }

    pub(crate) fn capture_original_claim_storage(
        value: &OriginalPublicationClaim,
    ) -> Result<usize, RuntimeError> {
        value.owned_storage()
    }

    /// Counts independent batch heaps, excluding its borrowed activation backing.
    ///
    /// WorldActivation owns its record clone here. Its authority, validated-node
    /// and prepared-publication Rc backing are shared with the actual Runtime;
    /// their aliases are inline and their owning Core banks are separate terms.
    pub(crate) fn capture_lineage_batch_storage(
        value: &RuntimeInputBatch,
    ) -> Result<usize, RuntimeError> {
        let mut bytes = value.activation.record().owned_storage()?;
        for next in [
            value.node.owned_storage()?,
            value.stage_operation.owned_storage()?,
            value.batch.owned_storage()?,
            value.owners.owned_storage()?,
            value.inventory.owned_storage()?,
            value.deliveries.owned_storage()?,
            value.payloads.owned_storage()?,
        ] {
            bytes = storage::add(bytes, next)?;
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_claim_storage_counts_body_spare_capacity_without_changing_identity()
    -> Result<(), RuntimeError> {
        use crate::node_contract::OriginalPublicationOrigin;
        use crate::node_scheduling::InputPayload;
        use crucible_node_format::{
            Endpoint, Event, EventStage, Extensions, Id, Phase, Position, U64, canonical,
        };

        let id = Id::new("original").map_err(|_| RuntimeError::InvalidReceipt)?;
        let reference = canonical::content_ref(b"x", "application/octet-stream")
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let endpoint = Endpoint {
            node_id: id.clone(),
            port_id: id.clone(),
            lane_id: id.clone(),
        };
        let at = Position::new(U64::new(1), U64::new(1), Phase::Publication);
        let event = Event {
            schema_version: 1,
            id: id.clone(),
            source: endpoint.clone(),
            destination: endpoint,
            position: at,
            stage: EventStage::Publication,
            publication_position: at,
            delivery_position: None,
            source_sequence: U64::new(1),
            causal_parent_ids: Vec::new(),
            payload: reference.clone(),
            provenance_ref: reference.clone(),
            extensions: Extensions::new(),
        };
        let origin = OriginalPublicationOrigin {
            owner_binding_hash: reference.hash.clone(),
            execution_owner_id: id.clone(),
            session_id: id.clone(),
            world_binding_hash: reference.hash.clone(),
            activation_id: id.clone(),
            world_generation: U64::new(1),
            incarnation_id: id.clone(),
            owner_generation: U64::new(1),
            operation_id: id.clone(),
            grant_id: id,
            observation_batch: reference.clone(),
            stop_receipt: reference.clone(),
            measurement: reference.clone(),
        };
        let mut claim = OriginalPublicationClaim {
            event,
            origin,
            published: reference.clone(),
            objects: vec![InputPayload {
                reference,
                bytes: b"x".to_vec(),
            }],
            rows: Vec::new(),
        };
        let before = claim.owned_storage()?;
        let old_capacity = claim.objects[0].bytes.capacity();
        let identity = claim.objects[0].reference.clone();
        claim.objects[0].bytes.reserve(8192);
        let added = claim.objects[0].bytes.capacity() - old_capacity;

        assert!(added >= 8192);
        assert_eq!(claim.owned_storage()?, before + added);
        assert_eq!(claim.objects[0].reference, identity);
        Ok(())
    }

    #[test]
    fn exact_input_blocked_ceiling_keeps_independent_spare_proof_strings()
    -> Result<(), RuntimeError> {
        use crate::node_scheduling::{ExactCeiling, ExecutionPolicy};
        use crucible_node_format::canonical;

        let proof = canonical::content_ref(b"execution", "application/octet-stream")
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let mut blocked = canonical::content_ref(b"input barrier", "application/octet-stream")
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        blocked.media_type.reserve(8192);
        let independent = blocked.owned_storage()?;
        assert!(independent >= 8192);
        let ordinary = ExecutionPolicy::Exact {
            schema_version: 1,
            execution_proof_ref: proof.clone(),
            ceiling: ExactCeiling::StrictPredecessor,
            boundary_settlement_ref: None,
        };
        let stopped = ExecutionPolicy::Exact {
            schema_version: 1,
            execution_proof_ref: proof,
            ceiling: ExactCeiling::InputBlocked { proof_ref: blocked },
            boundary_settlement_ref: None,
        };

        assert_eq!(
            stopped.owned_storage()?,
            ordinary.owned_storage()? + independent
        );
        Ok(())
    }
}
