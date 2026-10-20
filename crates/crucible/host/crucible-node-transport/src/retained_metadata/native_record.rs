//! Observes actual retained native journal and Oracle record fields.
//!
//! The closed borrowed variants cover only known original typed families. Outer
//! Oracle/record Vec element headers, encoded byte buffers and fullref clones
//! are caller-owned terms; equal values in separate owners receive no discount.

use super::*;
use crate::input_commit::CommittedDeliveryV1;
use crate::reference_packet::connected::{
    PacketCommitRecord, PacketConnectedGrant, PacketConnectedInventory,
    PacketConnectedNativeRecord, PacketConnectedPublication, PacketDeliveredInput,
    PacketPendingPublication, PacketReaction, PacketStageRecord,
};
use crate::reference_packet::control::PacketNativeRecord;
use crate::reference_packet::input::PacketInputCut;
use crate::reference_packet::{PacketGrant, PacketInventory, PacketPublication};

/// Borrows a closed actual native journal record or independently owned effect.
#[derive(serde::Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum RetainedPacketNativeRecord<'a> {
    /// Borrows one original producer record.
    Producer(&'a PacketNativeRecord),
    /// Borrows one original reactive record.
    Reactive(&'a PacketConnectedNativeRecord),
    /// Borrows one actual staged-input record.
    Stage(&'a PacketStageRecord),
    /// Borrows one actual committed-input record.
    Commit(&'a PacketCommitRecord),
    /// Borrows an independently retained delivered-input effect.
    DeliveredInput(&'a PacketDeliveredInput),
    /// Borrows an independently retained native reaction effect.
    Reaction(&'a PacketReaction),
    /// Borrows an independently retained connected publication effect.
    Publication(&'a PacketConnectedPublication),
}

impl RetainedPacketNativeRecord<'_> {
    /// Reports actual nested backing, including spare original Vec capacity.
    ///
    /// Inline root layout is excluded: the caller separately charges the real
    /// containing Vec/enum allocation. No encoded length or callback is used.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow or finite traversal/depth exhaustion.
    pub fn observe_retained_metadata(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_historical_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }
}

fields!(
    PacketInventory,
    reached,
    gate_closed,
    pending,
    retained_outputs,
    private_mutations,
    packet_effects
);
fields!(
    PacketPublication,
    event,
    operation,
    sequence,
    evaluation,
    publication,
    payload
);
fields!(
    PacketGrant,
    operation,
    start,
    limit,
    inventory,
    newborn,
    complete
);
fields!(
    PacketReaction,
    input_event,
    input_producer,
    input_sequence,
    stage_operation,
    commit_request,
    payload,
    parent,
    evaluation
);
fields!(PacketDeliveredInput, reaction, delivery_operation);
fields!(
    PacketPendingPublication,
    event,
    reaction,
    reaction_operation,
    publication
);
fields!(PacketConnectedPublication, output, pending);
fields!(
    PacketConnectedInventory,
    reached,
    gate_closed,
    reactions,
    delivered_inputs,
    publications,
    retained_outputs,
    reactions_completed,
    packet_effects,
    stages,
    commits
);
fields!(
    PacketConnectedGrant,
    operation,
    start,
    limit,
    inventory,
    newborn,
    complete
);
fields!(
    PacketStageRecord,
    schema,
    native_pid,
    original,
    cut,
    batch,
    deliveries,
    payloads,
    inventory
);
fields!(
    PacketCommitRecord,
    schema,
    native_pid,
    original,
    staged_record,
    staging_receipt,
    cut,
    reactions,
    reached
);
fields!(
    PacketConnectedNativeRecord,
    schema,
    native_pid,
    original,
    inventory,
    grant
);
fields!(
    PacketNativeRecord,
    schema,
    native_pid,
    original,
    inventory,
    grant
);
fields!(
    PacketInputCut,
    schema_version,
    session_id,
    incarnation_id,
    node_id,
    execution_owner_id,
    owner_generation,
    activation_id,
    world_generation,
    world_binding_hash,
    stage_operation_id,
    batch_id,
    batch_sequence,
    input_epoch,
    batch_hash,
    delivery_inventory,
    cutoff
);
fields!(
    CommittedDeliveryV1,
    connection_id,
    connection_policy_ref,
    external_root,
    provenance_ref,
    publication_id,
    producer,
    consumer,
    producer_endpoint,
    consumer_endpoint,
    source_sequence,
    native_sequence,
    evaluation,
    causal_parents,
    publication,
    delivery,
    payload
);
fields!(
    InputBatch,
    schema_version,
    execution_owner_id,
    input_epoch,
    batch_id,
    batch_sequence,
    events,
    extensions
);
fields!(
    Event,
    schema_version,
    id,
    source,
    destination,
    position,
    stage,
    publication_position,
    delivery_position,
    source_sequence,
    causal_parent_ids,
    payload,
    provenance_ref,
    extensions
);

impl ObserveMetadata for EventStage {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::Publication | Self::Delivery => Ok(()),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "asserts actual independently retained record capacities"
)]
mod tests {
    use super::*;

    #[test]
    fn reaction_clones_are_measured_from_each_actual_payload_owner() {
        let mut bytes = Vec::with_capacity(97);
        bytes.extend_from_slice(b"payload");
        let reaction = PacketReaction {
            input_event: Id::new("event").unwrap(),
            input_producer: Id::new("producer").unwrap(),
            input_sequence: U64::new(0),
            stage_operation: Id::new("stage").unwrap(),
            commit_request: Id::new("commit").unwrap(),
            payload: Bytes::new(bytes),
            parent: Position::new(U64::new(1), U64::new(0), Phase::Delivery),
            evaluation: Position::new(U64::new(1), U64::new(0), Phase::Reaction),
        };
        let clone = reaction.clone();

        let original = RetainedPacketNativeRecord::Reaction(&reaction)
            .observe_retained_metadata()
            .unwrap();
        let copied = RetainedPacketNativeRecord::Reaction(&clone)
            .observe_retained_metadata()
            .unwrap();

        assert_eq!(
            original.vector_capacity_bytes,
            reaction.payload.allocation_capacity()
        );
        assert_eq!(
            copied.vector_capacity_bytes,
            clone.payload.allocation_capacity()
        );
        assert!(original.vector_capacity_bytes >= 97);
        assert_eq!(original.vector_banks, 1);
        assert_eq!(copied.vector_banks, 1);
        assert_eq!(original.boxed_value_bytes, 0);
        assert_eq!(original.shared_value_bytes, 0);
    }
}

impl RetainedPacketNativeRecord<'_> {
    fn observe_historical_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Producer(value) => observer.observe(*value)?,
            Self::Reactive(value) => observer.observe(*value)?,
            Self::Stage(value) => observer.observe(*value)?,
            Self::Commit(value) => observer.observe(*value)?,
            Self::DeliveredInput(value) => observer.observe(*value)?,
            Self::Reaction(value) => observer.observe(*value)?,
            Self::Publication(value) => observer.observe(*value)?,
        }
        Ok(())
    }

    /// Records every actual nested capacity in independently precharged banks.
    ///
    /// Clears only the supplied banks. Partial rows remain after exhaustion;
    /// neither the walk nor serialization invokes a live backend or grants rights.
    ///
    /// # Errors
    /// Refuses arithmetic/depth overflow or either finite bank's original extent.
    pub fn record_historical_metadata_data(
        &self,
        records: &mut crate::retained_metadata::records::MetadataRecordBank,
        aliases: &mut crate::retained_metadata::aliases::MetadataAliasBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        self.observe_historical_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Names fixed inert historical writer and record-bank loan layouts.
    pub fn historical_counter_scratch_data() -> usize {
        crate::retained_metadata::historical_serialization_counter_scratch_data()
            + std::mem::size_of::<Self>()
            + std::mem::size_of::<&Self>()
            + std::mem::size_of::<MetadataObserver<'static>>()
            + std::mem::size_of::<RetainedProtocolMetadataFacts>()
            + std::mem::size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
            + std::mem::size_of::<&mut crate::retained_metadata::records::MetadataRecordBank>()
            + std::mem::size_of::<&mut crate::retained_metadata::aliases::MetadataAliasBank>()
    }
}

impl RetainedPacketNativeRecord<'_> {
    /// Bounds actual Bytes base64 encoding work separately from output storage.
    ///
    /// Each encoding temporary is dropped after its serialize_str call. This
    /// bound covers the largest one using the exhaustive actual capacity walk;
    /// callers independently admit serializer output, DOM and canonical banks.
    ///
    /// # Errors
    /// Refuses the metadata walk's finite bound or base64 extent overflow.
    pub fn historical_serialization_transient_bytes_data(&self) -> Result<usize, ProviderError> {
        crate::retained_metadata::historical_serialization_transient_data(
            self.observe_retained_metadata()?,
        )
    }
}
