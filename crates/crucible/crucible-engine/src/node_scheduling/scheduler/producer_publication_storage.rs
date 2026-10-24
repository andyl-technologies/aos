//! Prices real common scheduling publication from actual current target routes.
//!
//! The selected Producer emits at most its one declared payload event. Current
//! scheduler maps, original histories and queued payloads stay independent from
//! the new update, its fanout, final map nodes and post-retirement observation.
//! These projections produce DATA, never a SchedulingReceipt or commit.

use super::*;
use crate::node_contract::{
    NodeRuntime, RuntimeError, runtime_owned_counter::RetainedRuntimeCounter,
};
use serde::Serialize;
use std::mem::{align_of, size_of};

const MAXIMUM_EVENT_ID: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const MAXIMUM_DIGEST: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

#[derive(Serialize)]
struct FutureHash {
    algorithm: &'static str,
    domain: &'static str,
    digest: &'static str,
}

#[derive(Serialize)]
struct FutureReference {
    hash: FutureHash,
    length: U64,
    media_type: &'static str,
}

impl FutureReference {
    fn new(media_type: &'static str) -> Self {
        Self {
            hash: FutureHash {
                algorithm: "blake3-256",
                domain: "cnp.blob.v1",
                digest: MAXIMUM_DIGEST,
            },
            length: U64::new(u64::MAX),
            media_type,
        }
    }
}

fn future_position() -> Position {
    Position::new(U64::new(u64::MAX), U64::new(u64::MAX), Phase::Reaction)
}

#[derive(Serialize)]
struct FutureDelivery<'a> {
    connection_id: Option<&'a Id>,
    connection_policy_ref: Option<&'a crucible_node_format::ContentRef>,
    external_root: Option<&'a Endpoint>,
    provenance_ref: FutureReference,
    publication_id: &'static str,
    producer: &'a Id,
    consumer: &'a Id,
    producer_endpoint: &'a Endpoint,
    consumer_endpoint: &'a Endpoint,
    source_sequence: U64,
    native_sequence: U64,
    evaluation: Option<Position>,
    causal_parents: [Position; 0],
    publication: Position,
    delivery: Position,
    payload: FutureReference,
}

#[derive(Serialize)]
struct FutureKey<'a> {
    position: Position,
    consumer_node_id: &'a Id,
    producer_node_id: &'a Id,
    source_sequence: U64,
}

impl CausalScheduler {
    pub(crate) fn original_restored_producer_publication_construction_data(
        &self,
        node: &Id,
        port: &Id,
        lane: &Id,
        maximum_newborn: usize,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        if maximum_newborn > 1 {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let owner = self
            .node_owners
            .get(node)
            .ok_or(RuntimeError::UnknownNode)?;
        let mut current = RetainedRuntimeCounter::new(maximum);
        self.charge_original_retained_storage(&mut current)?;
        // One complete existing scheduler bank dominates the five disjoint map/
        // sequence clones in ObservationUpdate, including independent strings.
        // Another complete bank remains committed after apply_observation. No
        // current bank or shared address is subtracted from either new term.
        let mut retained = current.bytes();
        let mut transient = current.bytes();
        let mut fanout = 0usize;
        let mut delivery_heap = 0usize;
        for route in self.routing.values() {
            let endpoint = &route.descriptor.producer;
            if &endpoint.node_id != node || &endpoint.port_id != port || &endpoint.lane_id != lane {
                continue;
            }
            if matches!(
                route.policy.visibility,
                crate::node_admission::VisibilityConversion::Adapter { .. }
            ) {
                return Err(RuntimeError::UnsupportedFacet);
            }
            fanout = fanout
                .checked_add(maximum_newborn)
                .ok_or(RuntimeError::ResourceLimit)?;
            let delivery = FutureDelivery {
                connection_id: Some(&route.descriptor.id),
                connection_policy_ref: Some(&route.descriptor.policy_ref),
                external_root: None,
                provenance_ref: FutureReference::new("application/json"),
                publication_id: MAXIMUM_EVENT_ID,
                producer: node,
                consumer: &route.descriptor.consumer.node_id,
                producer_endpoint: endpoint,
                consumer_endpoint: &route.descriptor.consumer,
                source_sequence: U64::new(u64::MAX),
                native_sequence: U64::new(u64::MAX),
                evaluation: Some(future_position()),
                causal_parents: [],
                publication: future_position(),
                delivery: future_position(),
                payload: FutureReference::new("application/octet-stream"),
            };
            let key = FutureKey {
                position: future_position(),
                consumer_node_id: &route.descriptor.consumer.node_id,
                producer_node_id: node,
                source_sequence: U64::new(u64::MAX),
            };
            let (geometry, _) =
                NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
                    &(delivery, key),
                    size_of::<super::super::event::Delivery>()
                        .max(size_of::<crucible_node_format::EventKey>()),
                    maximum,
                )?;
            delivery_heap = delivery_heap
                .checked_add(
                    geometry
                        .checked_mul(maximum_newborn)
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        let mut members = 0usize;
        let mut members_heap = 0usize;
        for (member, member_owner) in &self.node_owners {
            if member_owner == owner {
                members = members.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
                members_heap = members_heap
                    .checked_add(member.allocated_capacity())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        // New payload bodies are independent of Source/native publication
        // buffers. The selected defining program permits one <=32-byte payload.
        let payload = (
            FutureReference::new("application/octet-stream"),
            [255u8; 32],
        );
        let (payload_geometry, _) =
            NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
                &payload,
                size_of::<(crucible_node_format::ContentRef, Vec<u8>)>(),
                maximum,
            )?;
        let payload_geometry = payload_geometry
            .checked_mul(maximum_newborn)
            .ok_or(RuntimeError::ResourceLimit)?;
        let pending_count = self
            .pending
            .len()
            .checked_add(fanout)
            .ok_or(RuntimeError::ResourceLimit)?;
        let payload_count = self
            .payloads
            .len()
            .checked_add(maximum_newborn)
            .ok_or(RuntimeError::ResourceLimit)?;
        let native_count = self
            .native_sequences
            .len()
            .checked_add(maximum_newborn)
            .ok_or(RuntimeError::ResourceLimit)?;
        let prefix_count = self
            .closed_prefixes
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        let sequence_count = self
            .sequences
            .original_retained_entry_count_data()
            .checked_add(maximum_newborn)
            .ok_or(RuntimeError::ResourceLimit)?;
        let trees = [
            NodeRuntime::capture_protocol_tree_storage(
                1,
                pending_count,
                size_of::<(
                    crucible_node_format::EventKey,
                    super::super::event::Delivery,
                )>(),
                align_of::<(
                    crucible_node_format::EventKey,
                    super::super::event::Delivery,
                )>(),
                maximum,
            )?,
            NodeRuntime::capture_protocol_tree_storage(
                1,
                payload_count,
                size_of::<(crucible_node_format::ContentRef, Vec<u8>)>(),
                align_of::<(crucible_node_format::ContentRef, Vec<u8>)>(),
                maximum,
            )?,
            NodeRuntime::capture_protocol_tree_storage(
                1,
                native_count,
                size_of::<(Endpoint, U64)>(),
                align_of::<(Endpoint, U64)>(),
                maximum,
            )?,
            NodeRuntime::capture_protocol_tree_storage(
                1,
                prefix_count,
                size_of::<(Id, Position)>(),
                align_of::<(Id, Position)>(),
                maximum,
            )?,
            NodeRuntime::capture_protocol_tree_storage(
                1,
                sequence_count,
                size_of::<(Id, Option<U64>)>(),
                align_of::<(Id, Option<U64>)>(),
                maximum,
            )?,
            NodeRuntime::capture_protocol_tree_storage(
                1,
                maximum_newborn,
                size_of::<Id>(),
                align_of::<Id>(),
                maximum,
            )?,
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })?;
        // Prefix/bound replacement, producer sequence and native endpoint keys.
        let (key_geometry, _) =
            NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
                &(node, node, port, lane, MAXIMUM_EVENT_ID),
                size_of::<Endpoint>(),
                maximum,
            )?;
        retained = retained
            .checked_add(delivery_heap)
            .and_then(|bytes| bytes.checked_add(payload_geometry))
            .and_then(|bytes| bytes.checked_add(trees))
            .and_then(|bytes| bytes.checked_add(key_geometry))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        let vectors = [
            NodeRuntime::original_restored_producer_collect_storage_data::<Id>(members, maximum)?,
            NodeRuntime::original_restored_producer_collect_storage_data::<Id>(members, maximum)?,
            NodeRuntime::original_restored_producer_collect_storage_data::<Id>(
                maximum_newborn,
                maximum,
            )?,
            NodeRuntime::original_restored_producer_collect_storage_data::<
                super::super::event::Delivery,
            >(fanout, maximum)?,
            NodeRuntime::original_restored_producer_collect_storage_data::<&RoutingConnection>(
                fanout, maximum,
            )?,
            NodeRuntime::original_restored_producer_collect_storage_data::<
                &super::super::event::Delivery,
            >(fanout, maximum)?,
            NodeRuntime::original_restored_producer_collect_storage_data::<U64>(
                fanout.max(maximum_newborn),
                maximum,
            )?,
            NodeRuntime::original_restored_producer_collect_storage_data::<(
                crucible_node_format::ContentRef,
                Vec<u8>,
            )>(maximum_newborn, maximum)?,
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })?;
        transient = transient
            .checked_add(delivery_heap)
            .and_then(|bytes| bytes.checked_add(payload_geometry))
            .and_then(|bytes| bytes.checked_add(vectors))
            .and_then(|bytes| bytes.checked_add(members_heap.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(key_geometry))
            .and_then(|bytes| bytes.checked_add(owner.allocated_capacity()))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        let scratch = Self::original_restored_producer_publication_counter_scratch_data();
        retained
            .checked_add(transient)
            .and_then(|bytes| bytes.checked_add(scratch))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok((retained, transient, scratch))
    }

    pub(crate) fn original_restored_producer_publication_counter_scratch_data() -> usize {
        NodeRuntime::capture_serialization_counter_scratch_data()
            + size_of::<RetainedRuntimeCounter>()
            + size_of::<FutureHash>() * 2
            + size_of::<FutureReference>() * 2
            + size_of::<FutureDelivery<'static>>()
            + size_of::<FutureKey<'static>>()
            + size_of::<(FutureDelivery<'static>, FutureKey<'static>)>()
            + size_of::<(FutureReference, [u8; 32])>()
            + size_of::<(&Id, &Id, &Id, &Id, &str)>()
            + size_of::<[usize; 6]>()
            + size_of::<std::array::IntoIter<usize, 6>>()
            + size_of::<[usize; 8]>()
            + size_of::<std::array::IntoIter<usize, 8>>()
            + size_of::<std::collections::btree_map::Values<'static, Id, RoutingConnection>>()
            + size_of::<std::collections::btree_map::Iter<'static, Id, Id>>()
            + size_of::<&RoutingConnection>()
            + size_of::<&Endpoint>()
            + size_of::<&Id>() * 4
            + size_of::<Option<&Id>>()
            + size_of::<Result<&Id, RuntimeError>>()
            + size_of::<(usize, usize)>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<usize>>()
    }
}
