//! Prices the exact actual settled Scheduling1 constructor without allocating.
//!
//! Every field is borrowed from the same real scheduler. This serializer mirrors
//! SchedulingSnapshot's closed edition one, including pending delivery bytes,
//! complete input ACK/consumption history and all used identities. It does not
//! derive a new queue or omit the passive Host's initial producer entry.

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};
use crate::node_scheduling::{
    InputIdentity, InputPayload, NativeInputAcknowledgement, RuntimeInputBatch, SavedBound,
    SavedReservation,
};
use crucible_node_format::{ContentRef, Id, Position, U64};
use serde::ser::{Serialize, SerializeStruct, Serializer};

struct Sequence<I>(I);

impl<I> Serialize for Sequence<I>
where
    I: Iterator + Clone,
    I::Item: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.clone())
    }
}

struct SnapshotView<'a> {
    scheduler: &'a CausalScheduler,
    cut: Position,
    ordinal: U64,
}

#[derive(serde::Serialize)]
struct OwnerView<'a> {
    owner: &'a Id,
    incarnation: &'a Id,
    generation: U64,
}

#[derive(serde::Serialize)]
struct PositionView<'a> {
    owner: &'a Id,
    position: Position,
}

#[derive(serde::Serialize)]
struct ProducerView<'a> {
    node: &'a Id,
    bound: crate::node_scheduling::SavedBound,
    closed_prefix: Position,
    next_sequence: Option<U64>,
}

#[derive(serde::Serialize)]
struct ExternalPrefixView<'a> {
    endpoint: &'a crucible_node_format::Endpoint,
    closed_before: Position,
}

#[derive(serde::Serialize)]
struct NativeSequenceView<'a> {
    endpoint: &'a crucible_node_format::Endpoint,
    last_sequence: U64,
}

#[derive(serde::Serialize)]
struct PayloadView<'a> {
    reference: &'a ContentRef,
    bytes: &'a Vec<u8>,
}

#[derive(serde::Serialize)]
struct InputView<'a> {
    owner: &'a Id,
    node: &'a Id,
    stage_operation: &'a Id,
    batch: &'a Id,
    owners: &'a Vec<crate::node_contract::OwnerIdentity>,
    cutoff: Position,
    inventory: &'a ContentRef,
    deliveries: &'a Vec<crate::node_scheduling::event::Delivery>,
    payloads: &'a Vec<InputPayload>,
    acknowledgement: &'a Option<NativeInputAcknowledgement>,
    custody_edition: Option<u16>,
    #[serde(skip_serializing_if = "is_false")]
    consumer_committed: bool,
    activated_by: &'a Option<Id>,
    consumed: &'a Vec<InputIdentity>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl Serialize for SnapshotView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let scheduler = self.scheduler;
        let source = scheduler.activation.record();
        // original_epochs=None is omitted by SchedulingSnapshot's exact codec.
        let mut record = serializer.serialize_struct("SchedulingSnapshot", 20)?;
        record.serialize_field("schema_version", &1u16)?;
        record.serialize_field("ordering_profile", "superdense-v1")?;
        record.serialize_field("world_binding_hash", &source.world_binding_hash)?;
        record.serialize_field("source_activation_id", &source.activation_id)?;
        record.serialize_field("source_generation", &source.generation)?;
        record.serialize_field("source_boundary", &source.boundary)?;
        record.serialize_field("capture_cut", &self.cut)?;
        record.serialize_field("capture_ordinal", &self.ordinal)?;
        record.serialize_field(
            "source_owners",
            &Sequence(source.owners.iter().map(|owner| OwnerView {
                owner: &owner.owner,
                incarnation: &owner.incarnation,
                generation: owner.generation,
            })),
        )?;
        record.serialize_field("maximum_microsteps", &scheduler.maximum_microsteps)?;
        record.serialize_field(
            "positions",
            &Sequence(
                scheduler
                    .owners
                    .iter()
                    .map(|(owner, schedule)| PositionView {
                        owner,
                        position: schedule.cursor,
                    }),
            ),
        )?;
        record.serialize_field(
            "producers",
            &Sequence(scheduler.bounds.iter().map(|(node, bound)| ProducerView {
                node,
                bound: match bound {
                    OutputBound::Unknown => SavedBound::Unknown,
                    OutputBound::At(position) => SavedBound::At {
                        position: *position,
                    },
                    OutputBound::AfterInstant(time_ps) => {
                        SavedBound::AfterInstant { time_ps: *time_ps }
                    }
                },
                closed_prefix: scheduler.closed_prefixes[node],
                next_sequence: scheduler.sequences.next(node),
            })),
        )?;
        record.serialize_field(
            "external_closed_prefixes",
            &Sequence(scheduler.external_closed_prefixes.iter().map(
                |(endpoint, closed_before)| ExternalPrefixView {
                    endpoint,
                    closed_before: *closed_before,
                },
            )),
        )?;
        record.serialize_field(
            "native_sequences",
            &Sequence(
                scheduler
                    .native_sequences
                    .iter()
                    .map(|(endpoint, sequence)| NativeSequenceView {
                        endpoint,
                        last_sequence: *sequence,
                    }),
            ),
        )?;
        record.serialize_field(
            "payload_objects",
            &Sequence(
                scheduler
                    .payloads
                    .iter()
                    .map(|(reference, bytes)| PayloadView { reference, bytes }),
            ),
        )?;
        record.serialize_field("pending_deliveries", &Sequence(scheduler.pending.values()))?;
        record.serialize_field(
            "used_operations",
            &Sequence(scheduler.used_operations.iter()),
        )?;
        record.serialize_field("reservations", &[] as &[SavedReservation])?;
        record.serialize_field(
            "input_batches",
            &Sequence(scheduler.input_batches.iter().map(|(owner, state)| {
                let batch = &state.batch;
                InputView {
                    owner,
                    node: &batch.node,
                    stage_operation: &batch.stage_operation,
                    batch: &batch.batch,
                    owners: &batch.owners,
                    cutoff: batch.cutoff,
                    inventory: &batch.inventory,
                    deliveries: &batch.deliveries,
                    payloads: &batch.payloads,
                    acknowledgement: &state.acknowledgement,
                    custody_edition: Some(1),
                    consumer_committed: state.consumer_committed,
                    activated_by: &state.activated_by,
                    consumed: &state.consumed,
                }
            })),
        )?;
        record.serialize_field(
            "used_input_batches",
            &Sequence(scheduler.used_input_batches.iter()),
        )?;
        record.end()
    }
}

impl CausalScheduler {
    /// Prices complete future typed Scheduling1 and its actual constructor work.
    ///
    /// This requires the genuine eligible issuer to have closed all native
    /// reservations. Pending future deliveries and retained input batches remain
    /// represented exactly, including bytes already ACKed by a native producer.
    ///
    /// # Errors
    /// Refuses unsupported epochs, an unresolved permission, malformed source
    /// cursor maps, checked layout overflow or the independent constructor cap.
    pub(crate) fn restored17_snapshot_construction_data(
        &self,
        cut: Position,
        ordinal: U64,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.restored17_snapshot_geometry_data(cut, ordinal, maximum)
            .map(|(requested, _)| requested)
    }

    /// Returns the same constructor demand and complete encoded-bank ceiling.
    ///
    /// Both axes come from the defining serializer over the same actual
    /// scheduler. The encoded extent is DATA for a separately reserved bounded
    /// writer, never an allocation allowance or a new eligible cut.
    ///
    /// # Errors
    /// Refuses the same unresolved scheduler owners, malformed producer maps or
    /// independent constructor ceiling as the construction-only wrapper.
    pub(crate) fn restored17_snapshot_geometry_data(
        &self,
        cut: Position,
        ordinal: U64,
        maximum: usize,
    ) -> Result<(usize, usize), RuntimeError> {
        if self.restored_epochs.is_some() || !self.operations.is_empty() {
            return Err(RuntimeError::OutstandingObligations);
        }
        if self
            .bounds
            .keys()
            .any(|node| !self.closed_prefixes.contains_key(node))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let view = SnapshotView {
            scheduler: self,
            cut,
            ordinal,
        };
        NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
            &view,
            NodeRuntime::capture_closed_inline_storage(),
            maximum,
        )
    }

    /// Names the second result-axis header in addition to existing quote scratch.
    pub(crate) const fn restored17_snapshot_geometry_additional_counter_scratch_data() -> usize {
        std::mem::size_of::<(usize, usize)>() - std::mem::size_of::<usize>()
    }
}

#[cfg(test)]
mod tests {
    // Actual scheduler fixture serialization is compared with its defining DTO.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_node_format::{Endpoint, Phase, canonical};

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn fixture() -> CausalScheduler {
        let proof = canonical::content_ref(b"fixture-proof", "application/octet-stream").unwrap();
        super::super::tests::fixture(
            ExecutionPolicy::Exact {
                schema_version: 1,
                execution_proof_ref: proof.clone(),
                boundary_settlement_ref: Some(proof),
                ceiling: ExactCeiling::StrictPredecessor,
            },
            50,
            None,
        )
    }

    fn check_pair(scheduler: &CausalScheduler) -> usize {
        let cut = Position::new(9.into(), 0.into(), Phase::BoundaryControl);
        let ordinal = 17.into();
        let snapshot = scheduler.snapshot(cut, ordinal).unwrap();
        let view = SnapshotView {
            scheduler,
            cut,
            ordinal,
        };
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::to_value(snapshot).unwrap()
        );
        let (requested, encoded_upper) = scheduler
            .restored17_snapshot_geometry_data(cut, ordinal, usize::MAX)
            .unwrap();
        assert_eq!(
            scheduler
                .restored17_snapshot_construction_data(cut, ordinal, usize::MAX)
                .unwrap(),
            requested,
        );
        let canonical = canonical::canonical_json(&serde_json::to_value(&view).unwrap()).unwrap();
        assert!(encoded_upper >= canonical.len());
        assert_eq!(
            CausalScheduler::restored17_snapshot_geometry_additional_counter_scratch_data(),
            std::mem::size_of::<usize>(),
        );
        assert_eq!(
            scheduler
                .restored17_snapshot_construction_data(cut, ordinal, requested)
                .unwrap(),
            requested
        );
        assert!(
            scheduler
                .restored17_snapshot_construction_data(cut, ordinal, requested - 1)
                .is_err()
        );
        requested
    }

    #[test]
    fn actual_borrowed_settled_view_preserves_empty_producer_entries_and_exact_credit() {
        let scheduler = fixture();
        check_pair(&scheduler);
        assert_eq!(scheduler.sequences.next(&id("A")), Some(0.into()));
        assert_eq!(scheduler.bounds.get(&id("A")), Some(&OutputBound::Unknown));
    }

    #[test]
    fn actual_borrowed_settled_view_preserves_pending_payload_input_ack_and_consumption() {
        let mut scheduler = fixture();
        let before = check_pair(&scheduler);
        let bytes = vec![0x5a; 4096];
        let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
        let producer_endpoint = Endpoint {
            node_id: id("Z"),
            port_id: id("out"),
            lane_id: id("lane"),
        };
        let consumer_endpoint = Endpoint {
            node_id: id("A"),
            port_id: id("in"),
            lane_id: id("lane"),
        };
        let delivery = crate::node_scheduling::event::Delivery {
            connection_id: None,
            connection_policy_ref: None,
            external_root: None,
            provenance_ref: reference.clone(),
            publication_id: id("publication/17"),
            producer: id("Z"),
            consumer: id("A"),
            producer_endpoint: producer_endpoint.clone(),
            consumer_endpoint,
            source_sequence: 7.into(),
            native_sequence: 23.into(),
            evaluation: None,
            causal_parents: vec![],
            publication: Position::new(10.into(), 0.into(), Phase::Publication),
            delivery: Position::new(10.into(), 0.into(), Phase::Delivery),
            payload: reference.clone(),
        };
        scheduler.pending.insert(delivery.key(), delivery.clone());
        scheduler.payloads.insert(reference.clone(), bytes.clone());
        scheduler
            .native_sequences
            .insert(producer_endpoint, 23.into());
        scheduler.used_operations.insert(id("completed-operation"));
        scheduler.used_input_batches.insert(id("retained-batch"));
        let owners = vec![scheduler.activation.record().owners[0].clone()];
        let cutoff = Position::new(11.into(), 0.into(), Phase::BoundaryControl);
        let acknowledgement = NativeInputAcknowledgement {
            stage_operation: id("retained-stage"),
            batch: id("retained-batch"),
            node: id("A"),
            owners: owners.clone(),
            cutoff,
            inventory: reference.clone(),
            proof_ref: reference.clone(),
        };
        scheduler.input_batches.insert(
            id("owner/A"),
            InputBatchState {
                batch: RuntimeInputBatch {
                    activation: scheduler.activation.clone(),
                    node: id("A"),
                    stage_operation: id("retained-stage"),
                    batch: id("retained-batch"),
                    owners,
                    cutoff,
                    inventory: reference.clone(),
                    deliveries: vec![delivery],
                    payloads: vec![InputPayload { reference, bytes }],
                },
                acknowledgement: Some(acknowledgement),
                consumer_committed: true,
                activated_by: Some(id("original-operation")),
                consumed: vec![InputIdentity {
                    producer: id("Z"),
                    source_sequence: 7.into(),
                }],
            },
        );
        let after = check_pair(&scheduler);
        assert!(after > before);
        assert_eq!(scheduler.pending.len(), 1);
        assert!(scheduler.input_batches[&id("owner/A")].consumer_committed);

        scheduler
            .input_batches
            .get_mut(&id("owner/A"))
            .unwrap()
            .consumer_committed = false;
        check_pair(&scheduler);
    }
}
