//! Counts actual semantic5 heaps, including spare capacities and partial reads.
//!
//! Saved capacity hints and prospective decoder extents are not this census.
//! Each separately decoded tree and typed owner is charged independently.

use super::{PacketCompleteArchivedSemantics, data::*};
use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_contract::{ContentRef, Id, Position, U64};
use crucible_node_provider::{
    bodies::*,
    retained_metadata::{RetainedCommonProtocolData, RetainedProtocolMetadataFacts},
};
use std::{collections::BTreeMap, mem::size_of};

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct Census {
    bytes: usize,
    maximum: usize,
}

impl Census {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn new(
        maximum: usize,
    ) -> Self {
        Self { bytes: 0, maximum }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn remaining(
        &self,
    ) -> usize {
        self.maximum - self.bytes
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn add(
        &mut self,
        bytes: usize,
    ) -> Result<(), RuntimeError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn charge<T: Owned>(
        &mut self,
        value: &T,
    ) -> Result<(), RuntimeError> {
        value.charge(self)
    }

    fn metadata(&mut self, facts: &RetainedProtocolMetadataFacts) -> Result<(), RuntimeError> {
        self.add(super::super::PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(facts, self.remaining())?)
    }
}

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) trait Owned {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError>;
}

impl Owned for String {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        census.add(self.capacity())
    }
}

impl Owned for Id {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        census.add(self.allocated_capacity())
    }
}

impl Owned for ContentRef {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        census.add(NodeRuntime::capture_reference_storage(self)?)
    }
}

impl<T: Owned> Owned for Option<T> {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        if let Some(value) = self {
            census.charge(value)?;
        }
        Ok(())
    }
}

impl<T: Owned> Owned for Vec<T> {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        census.add(
            self.capacity()
                .checked_mul(size_of::<T>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for value in self {
            census.charge(value)?;
        }
        Ok(())
    }
}

impl<K: Owned, V: Owned> Owned for BTreeMap<K, V> {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        // The pinned conservative tree layout charges at least one node even
        // for an empty map. This is requested-layout admission, not a report of
        // allocator rounding or resident bytes.
        census.add(
            self.len()
                .max(1)
                .checked_mul(NodeRuntime::capture_map_node_storage::<K, V>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for (key, value) in self {
            census.charge(key)?;
            census.charge(value)?;
        }
        Ok(())
    }
}

impl<A: Owned, B: Owned> Owned for (A, B) {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        census.charge(&self.0)?;
        census.charge(&self.1)
    }
}

macro_rules! scalar {
    ($($ty:ty),* $(,)?) => {$(impl Owned for $ty {
        fn charge(&self, _: &mut Census) -> Result<(), RuntimeError> {
            fn require_copy<T: Copy>(_: &T) {}
            require_copy(self);
            Ok(())
        }
    })*};
}
scalar!(bool, usize, U64, Position);
macro_rules! core {
    ($ty:ty, $getter:ident) => {
        impl Owned for $ty {
            fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
                census.add(NodeRuntime::$getter(self, census.remaining())?)
            }
        }
    };
}
core!(serde_json::Value, capture_initial15_json_storage_data);
core!(
    crate::node_contract::OwnerIdentity,
    capture_initial15_owner_storage_data
);
core!(
    crate::node_contract::SavedRuntimeActivation,
    capture_initial15_activation_storage_data
);
core!(
    crucible_node_contract::PreparedOwner,
    capture_initial15_prepared_storage_data
);
core!(
    crate::node_contract::NodeRoute,
    capture_initial15_route_storage_data
);
core!(
    crate::node_contract::OperationRequest,
    capture_initial15_request_storage_data
);
core!(
    crate::node_contract::OperationOutcome,
    capture_initial15_outcome_storage_data
);
core!(
    crate::node_contract::OperationFailure,
    capture_initial15_failure_storage_data
);
core!(
    crate::node_scheduling::InputPayload,
    capture_initial15_payload_storage_data
);
core!(
    crate::node_scheduling::NativeInputAcknowledgement,
    capture_initial15_ack_storage_data
);
core!(
    crate::node_scheduling::NativeSchedulingObservation,
    capture_initial15_observation_storage_data
);
core!(
    crucible_node_contract::Event,
    capture_initial15_event_storage_data
);
core!(
    crate::node_contract::SavedOriginalInputScope,
    capture_initial15_scope_storage_data
);
core!(
    crate::node_contract::OriginalPublicationOrigin,
    capture_initial15_origin_storage_data
);
core!(
    crate::node_contract::OriginalLineageRow,
    capture_initial15_lineage_storage_data
);
core!(
    crate::node_scheduling::event::Delivery,
    capture_initial15_delivery_storage_data
);

macro_rules! provider {
    ($ty:ty, $variant:ident) => {
        impl Owned for $ty {
            fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
                let facts = RetainedCommonProtocolData::$variant(self)
                    .observe_retained_metadata()
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                census.metadata(&facts)
            }
        }
    };
}
provider!(BeginRequest, Begin);
provider!(InputRequest, InputRequest);
provider!(InputResult, InputResult);
provider!(WorldActivateResult, WorldActivate);
macro_rules! fields {
    ($ty:ty; $($field:ident),+ $(,)?) => {impl Owned for $ty {
        fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
            let Self { $($field),+ } = self;
            $(census.charge($field)?;)+
            Ok(())
        }
    }};
}
fields!(
    ArchivedReady;
    owners,
    boundary,
    state_inventory,
    ready_receipt,
);
fields!(
    ArchivedBatch;
    activation,
    node,
    stage_operation,
    batch,
    owners,
    cutoff,
    inventory,
    deliveries,
    payloads,
);
fields!(
    ArchivedCommit;
    activation,
    node,
    stage_operation,
    batch,
    inventory,
    cutoff,
);
fields!(
    ArchivedCommitment;
    original,
    request_id,
    extensions,
    context,
    response,
);
fields!(
    ArchivedInput;
    original,
    acknowledgement,
    watermark,
    request,
    commitment,
    response,
);
fields!(
    ArchivedOperation;
    operation,
    route,
    request,
    activation,
    inputs,
    begin,
    outcome,
    failure,
    polls,
    begin_acknowledged,
    cancellation,
    acknowledged,
    retirement,
);
fields!(
    ArchivedSemanticCustody;
    schema,
    arm_attempt,
    ready,
    prepared_owner,
    activate_response,
    observe_sequence,
    activation_attempt,
    active,
    inputs,
    operations,
    watermark,
    observation,
    reclaimed,
    retained_credit,
    quarantined,
);

impl<Object: Owned> Owned for ArchivedPublication<Object> {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        let Self {
            event,
            origin,
            published,
            objects,
            rows,
        } = self;
        census.charge(event)?;
        census.charge(origin)?;
        census.charge(published)?;
        census.charge(objects)?;
        census.charge(rows)?;
        Ok(())
    }
}

impl<Object: Owned> Owned for ArchivedLineage<Object> {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        let Self {
            source_scope,
            original,
            publications,
        } = self;
        census.charge(source_scope)?;
        census.charge(original)?;
        census.charge(publications)?;
        Ok(())
    }
}

impl<Object: Owned> Owned for ArchivedAncestryRecord<Object> {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        let Self { schema, lineages } = self;
        census.charge(schema)?;
        census.charge(lineages)?;
        Ok(())
    }
}

impl Owned for ArchivedAncestry {
    fn charge(&self, census: &mut Census) -> Result<(), RuntimeError> {
        match self {
            Self::Inline(record) => census.charge(record),
            Self::References(record) => census.charge(record),
        }
    }
}

impl PacketCompleteArchivedSemantics {
    /// Counts this actual immutable decoded owner's independent requested heaps.
    ///
    /// # Errors
    /// Refuses visitor/layout overflow or the complete caller-supplied bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            semantic,
            ancestry,
            reserved_decoder_bytes: _,
        } = self;
        let mut census = Census::new(maximum);
        census.add(size_of::<Self>())?;
        census.charge(semantic)?;
        census.charge(ancestry)?;
        Ok(census.bytes())
    }

    /// Reports the concrete fixed counter and Provider observer view headers.
    pub(crate) fn retained_counter_scratch_data() -> usize {
        use crucible_node_provider::protocol_snapshot::owned11::native::outer::SealedHistoricalNativeState;
        use std::collections::btree_map;
        size_of::<Census>()
            + size_of::<RetainedCommonProtocolData<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<RetainedProtocolMetadataFacts, crucible_node_provider::ProviderError>>(
            )
            + size_of::<&ArchivedSemanticCustody>()
            + size_of::<&ArchivedAncestry>()
            + size_of::<&ArchivedLineage<ContentRef>>()
            + size_of::<&ArchivedPublication<ContentRef>>()
            + size_of::<(&Id, &ArchivedInput)>()
            + size_of::<(&Id, &ArchivedOperation)>()
            + size_of::<std::slice::Iter<'static, ArchivedLineage<ContentRef>>>()
            + size_of::<
                std::slice::Iter<'static, ArchivedLineage<crate::node_scheduling::InputPayload>>,
            >()
            + size_of::<std::slice::Iter<'static, ArchivedPublication<ContentRef>>>()
            + size_of::<
                std::slice::Iter<
                    'static,
                    ArchivedPublication<crate::node_scheduling::InputPayload>,
                >,
            >()
            + size_of::<std::slice::Iter<'static, crate::node_contract::OriginalLineageRow>>()
            + size_of::<std::slice::Iter<'static, crate::node_scheduling::event::Delivery>>()
            + size_of::<btree_map::Iter<'static, Id, ArchivedInput>>()
            + size_of::<btree_map::Iter<'static, Id, ArchivedOperation>>()
            + size_of::<std::array::IntoIter<usize, 9>>()
            + SealedHistoricalNativeState::original_retained_metadata_counter_scratch_data()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn inert_semantic_data() -> PacketCompleteArchivedSemantics {
        PacketCompleteArchivedSemantics {
            semantic: ArchivedSemanticCustody {
                schema: "source-owned.packet-semantic-custody/5".into(),
                arm_attempt: None,
                ready: None,
                prepared_owner: None,
                activate_response: None,
                observe_sequence: U64::new(0),
                activation_attempt: None,
                active: None,
                inputs: BTreeMap::new(),
                operations: BTreeMap::new(),
                watermark: U64::new(0),
                observation: None,
                reclaimed: None,
                retained_credit: 0,
                quarantined: false,
            },
            ancestry: ArchivedAncestry::References(ArchivedAncestryRecord {
                schema: "source-owned.packet-original-ancestry/12".into(),
                lineages: Vec::new(),
            }),
            reserved_decoder_bytes: 0,
        }
    }

    #[test]
    fn actual_spare_backing_and_one_byte_short_credit_are_observed() {
        // This unactivated DATA fragment is not a qualifying archive or grant.
        let mut data = inert_semantic_data();
        let before = data.retained_requested_storage_data(usize::MAX).unwrap();
        let old_capacity = data.semantic.schema.capacity();

        data.semantic.schema.reserve_exact(4096);
        let added = data.semantic.schema.capacity() - old_capacity;
        let actual = data.retained_requested_storage_data(usize::MAX).unwrap();

        assert_eq!(actual, before + added);
        assert_eq!(
            data.retained_requested_storage_data(actual).unwrap(),
            actual
        );
        assert!(data.retained_requested_storage_data(actual - 1).is_err());
    }

    #[test]
    fn original_credit_hints_cannot_replace_the_decoded_heap_census() {
        let mut data = inert_semantic_data();
        let before = data.retained_requested_storage_data(usize::MAX).unwrap();

        data.reserved_decoder_bytes = usize::MAX;
        data.semantic.retained_credit = usize::MAX;
        data.semantic.observe_sequence = U64::new(u64::MAX);

        assert_eq!(
            data.retained_requested_storage_data(usize::MAX).unwrap(),
            before
        );
    }

    #[test]
    fn empty_lineage_vector_spare_capacity_remains_owned() {
        let mut data = inert_semantic_data();
        let before = data.retained_requested_storage_data(usize::MAX).unwrap();
        let ArchivedAncestry::References(ancestry) = &mut data.ancestry else {
            panic!("references DATA fixture expected");
        };

        ancestry.lineages.reserve_exact(37);
        let added = ancestry.lineages.capacity() * size_of::<ArchivedLineage<ContentRef>>();

        assert_eq!(
            data.retained_requested_storage_data(usize::MAX).unwrap(),
            before + added
        );
    }
}
