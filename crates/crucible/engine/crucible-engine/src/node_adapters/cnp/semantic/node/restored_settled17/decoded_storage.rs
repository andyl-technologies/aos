//! Counts actual newly decoded Node17 owners, including retained refusal products.
//!
//! Historical `capacities` rows are immutable evidence. Their numbers never
//! replace this actual walk of the decoder's own Vec/String/tree/Box backing.
//! Independently allocated equal values are visited independently; no successful
//! output or failed partial is discounted against another retained owner.

use super::{CnpRestoredNode17DecodeAttempt, CnpRestoredSettledValidatedNode17, record::*};
use crate::{
    node_adapters::cnp::semantic::PacketCompleteSemanticSource,
    node_contract::{NodeRuntime, RuntimeError},
};
use crucible_node_format::{ContentRef, HashRef, Id};
use crucible_node_transport::{
    bodies::*,
    reference_packet::service::complete_restore::activation::HistoricalRestorationActivationData,
    retained_metadata::{RetainedCommonProtocolData, RetainedProtocolMetadataFacts},
};
use std::{
    collections::BTreeMap,
    mem::{align_of, size_of},
};

struct Census {
    bytes: usize,
    maximum: usize,
}

impl Census {
    fn new(maximum: usize) -> Self {
        Self { bytes: 0, maximum }
    }

    fn remaining(&self) -> usize {
        self.maximum - self.bytes
    }

    fn add(&mut self, bytes: usize) -> Result<(), RuntimeError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    fn charge<T: Owned>(&mut self, value: &T) -> Result<(), RuntimeError> {
        value.charge(self)
    }

    fn metadata(&mut self, facts: &RetainedProtocolMetadataFacts) -> Result<(), RuntimeError> {
        self.add(
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                facts,
                self.remaining(),
            )?,
        )
    }
}

trait Owned {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError>;
}

impl Owned for String {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        counter.add(self.capacity())
    }
}

impl Owned for Id {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        counter.add(self.allocated_capacity())
    }
}

impl<T: Owned> Owned for Vec<T> {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        counter.add(
            self.capacity()
                .checked_mul(size_of::<T>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for value in self {
            counter.charge(value)?;
        }
        Ok(())
    }
}

impl<T: Owned> Owned for Option<T> {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        if let Some(value) = self {
            counter.charge(value)?;
        }
        Ok(())
    }
}

impl<T: Owned> Owned for Box<T> {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        counter.add(size_of::<T>())?;
        counter.charge(self.as_ref())
    }
}

impl<T: Owned, const N: usize> Owned for [T; N] {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        for value in self {
            counter.charge(value)?;
        }
        Ok(())
    }
}

impl<A: Owned, B: Owned> Owned for (A, B) {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        counter.charge(&self.0)?;
        counter.charge(&self.1)
    }
}

impl<K: Owned, V: Owned> Owned for BTreeMap<K, V> {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        let slot = size_of::<K>()
            .checked_add(size_of::<V>())
            .ok_or(RuntimeError::ResourceLimit)?;
        counter.add(NodeRuntime::capture_protocol_tree_storage(
            1,
            self.len(),
            slot,
            align_of::<K>().max(align_of::<V>()),
            counter.remaining(),
        )?)?;
        for (key, value) in self {
            counter.charge(key)?;
            counter.charge(value)?;
        }
        Ok(())
    }
}

impl Owned for serde_json::Value {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::value_storage_with_error;
        counter.add(value_storage_with_error::<RuntimeError>(
            self,
            0,
            counter.remaining(),
        )?)
    }
}

macro_rules! fields {
    ($ty:ty; [$($owned:ident),* $(,)?]; [$($inline:ident),* $(,)?]) => {
        impl Owned for $ty {
            fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
                // Exhaustive destructuring makes a new defining field require
                // an explicit ownership decision in the decoded-owner census.
                let Self { $($owned,)* $($inline: _,)* } = self;
                $(counter.charge($owned)?;)*
                Ok(())
            }
        }
    };
}

macro_rules! core {
    ($ty:ty,$method:ident) => {
        impl Owned for $ty {
            fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
                counter.add(NodeRuntime::$method(self, counter.remaining())?)
            }
        }
    };
}

impl Owned for u8 {
    fn charge(&self, _: &mut Census) -> Result<(), RuntimeError> {
        Ok(())
    }
}

fields!(
    HashRef;
    [algorithm, domain, digest];
    []
);

fields!(
    ContentRef;
    [hash, media_type];
    [length]
);

fields!(
    crate::node_scheduling::InputPayload;
    [reference, bytes];
    []
);

core!(
    crate::node_contract::SavedRuntimeActivation,
    capture_decoded_node17_saved_activation_storage_data
);

core!(
    crate::node_contract::OwnerIdentity,
    capture_decoded_node17_owner_identity_storage_data
);

core!(
    crate::node_contract::OperationRequest,
    capture_decoded_node17_operation_request_storage_data
);

core!(
    crate::node_scheduling::event::Delivery,
    capture_decoded_node17_delivery_storage_data
);

core!(crate::node_contract::NodeRoute, capture_route_storage_data);

core!(
    crucible_node_format::PreparedOwner,
    capture_prepared_owner_storage_data
);

core!(
    crate::node_contract::OperationOutcome,
    capture_outcome_storage_data
);

core!(
    crate::node_contract::OperationFailure,
    capture_failure_storage_data
);

core!(
    crate::node_scheduling::NativeInputAcknowledgement,
    capture_input_ack_storage_data
);

core!(
    crate::node_scheduling::NativeSchedulingObservation,
    capture_scheduling_observation_storage_data
);

macro_rules! provider {
    ($ty:ty,$variant:ident) => {
        impl Owned for $ty {
            fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
                let facts = RetainedCommonProtocolData::$variant(self)
                    .observe_retained_metadata()
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                counter.metadata(&facts)
            }
        }
    };
}

provider!(BeginRequest, Begin);

provider!(InputRequest, InputRequest);

provider!(InputResult, InputResult);

provider!(WorldActivateResult, WorldActivate);

fields!(
    NodeRecord17;
    [
        schema,
        base,
        base_activate_response_history,
        activation,
        original_operations,
        original_inputs,
        commands,
        completed,
        world_manifest,
        world_value,
        world_bytes,
        observation_completed,
        observation,
        observation_return,
        current_observations,
        producer_pending,
        producer_attempts,
        capacities,
        restored_families,
    ];
    [
        install_started,
        installed,
        observation_attempted,
        original_operations_capacity,
        original_inputs_capacity,
        producer_attempts_capacity,
    ]
);

fields!(
    BaseRecord17;
    [
        schema,
        arm_attempt,
        ready,
        prepared_owner,
        activate_response,
        activation_attempt,
        active,
        inputs,
        operations,
        observation,
        reclaimed,
    ];
    [observe_sequence, watermark, retained_credit, quarantined]
);

fields!(
    Readiness17;
    [owners, state_inventory, ready_receipt];
    [boundary]
);

fields!(
    WorldRecord17;
    [record, nodes, preparation];
    []
);

fields!(
    NodePreparation17;
    [node, readiness, prepared_owners];
    []
);

fields!(
    WorldPublication17;
    [nodes, owners, coordinator];
    []
);

fields!(
    AdmissionRecord17;
    [operation, route, request, activation, inputs];
    []
);

fields!(
    BatchRecord17;
    [
        activation,
        node,
        stage_operation,
        batch,
        owners,
        inventory,
        deliveries,
        payloads,
    ];
    [cutoff]
);

fields!(
    OriginalBatch17;
    [
        activation,
        node,
        stage_operation,
        batch,
        owners,
        inventory,
        deliveries,
        payloads,
    ];
    [cutoff]
);

fields!(
    OriginalOperation17;
    [
        operation,
        route,
        request,
        activation,
        inputs,
        begin,
        outcome,
        failure,
        cancellation,
        retirement,
    ];
    [polls, begin_acknowledged, acknowledged]
);

fields!(
    OriginalInput17;
    [original, acknowledgement, request, commitment, response];
    [watermark]
);

fields!(
    InputCommitment17;
    [original, request_id, extensions, context, response];
    []
);

fields!(
    InputCommit17;
    [activation, node, stage_operation, batch, inventory];
    [cutoff]
);

fields!(
    CurrentObservation17;
    [retained, returned];
    [ordinal]
);

fields!(
    ProducerAttempt17;
    [admission, retained, returned, scheduling, scheduling_return, stage];
    [slot]
);

fields!(
    ActivationOwnerWrapper17;
    [capacities, aliases, value];
    []
);

fields!(
    ResponseWrapper17;
    [capacities, aliases, value];
    []
);

fields!(
    RestoredFamilies17;
    [
        schema,
        inherited,
        imported_operations,
        base_operations,
        producer_operations,
        imported_inputs,
        base_inputs,
    ];
    [started, installed]
);

fields!(
    CommonCapacity17;
    [kind];
    [length, capacity, element_bytes, alignment, shared_group]
);

macro_rules! inline_enum {
    ($ty:ty;$($variant:ident),+ $(,)?) => {
        impl Owned for $ty {
            fn charge(&self, _: &mut Census) -> Result<(), RuntimeError> {
                match self { $(Self::$variant => {},)+ }
                Ok(())
            }
        }
    };
}

inline_enum!(
    CommonCapacityKind17;
    String,
    Vector,
    Tree,
    Shared,
);

inline_enum!(
    ProviderCapacityKind17;
    String,
    Vector,
    Tree,
    Shared,
    Boxed,
);

inline_enum!(
    ProducerStage17;
    Beginning,
    Begun,
    Polling,
    Completed,
    Retiring,
    Retired,
    Observing,
    Verified,
    Failed,
);

inline_enum!(
    ProviderSharedKind17;
    NativeRestoredPhysicalHold,
    NativeRestoreCommitAttempt,
    NativeRestoreInputCustody,
    NativeRestorationObservationAttempt,
    NativeRestoredSuffixObservationAttempt,
    NativeRestoredProducerAttempt,
    ProtocolOwner,
    RegistrarEpoch,
    RegistrarGate,
    SelectedExtensions,
    Codec,
    NativePolicy,
    HelloBank,
    ContentBytes,
    FrameBank,
    NativeBoot,
    PrivateBootstrapBank,
    InstalledRegistry,
    NativeSupervisor,
    BlobLedger,
    HostSupervisor,
    OperationalDeadline,
    ArchivedMapping,
    NativeControlIdentity,
    NativeFreshReportAttempt,
    NativeRestorePrepareAttempt,
    NativeRestorationActivationAttempt,
    NativeRestorationUploadAttempt,
);

impl Owned for ProviderCapacity17 {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        let Self(kind, _length, _capacity, _element_bytes) = self;
        counter.charge(kind)
    }
}

impl Owned for ProviderAlias17 {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        let Self(kind, _group) = self;
        counter.charge(kind)
    }
}

impl Owned for HistoricalWorld17 {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        match self {
            Self::World(value) => counter.charge(value),
        }
    }
}

impl Owned for HistoricalAdmission17 {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        match self {
            Self::Admission(value) => counter.charge(value),
        }
    }
}

impl Owned for HistoricalBatch17 {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        match self {
            Self::InputBatch(value) => counter.charge(value),
        }
    }
}

impl Owned for ActivateRequest {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        let Self {
            admission_id,
            activation_id,
            world_generation: _,
            prepared_token,
            world_binding_hash,
            gate_id,
            extensions,
        } = self;
        counter.charge(admission_id)?;
        counter.charge(activation_id)?;
        counter.charge(prepared_token)?;
        counter.charge(world_binding_hash)?;
        counter.charge(gate_id)?;
        counter.charge(extensions)
    }
}

impl Owned for WorldActivateRequest {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        let Self {
            transaction_id,
            activation_id,
            world_generation: _,
            prepared_token,
            world_binding_hash,
            gate_id,
            activation_manifest,
            extensions,
        } = self;
        counter.charge(transaction_id)?;
        counter.charge(activation_id)?;
        counter.charge(prepared_token)?;
        counter.charge(world_binding_hash)?;
        counter.charge(gate_id)?;
        counter.charge(activation_manifest)?;
        counter.charge(extensions)
    }
}

impl Owned for Command17 {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        match self {
            Self::Arm(value) => counter.charge(value),
            Self::WorldActivate(value) => counter.charge(value),
        }
    }
}

impl Owned for ActivationOwner17 {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        match self {
            Self::Command(value) => counter.charge(value),
            Self::WorldResult(value) => counter.charge(value),
            Self::Manifest(value) => counter.metadata(
                &HistoricalRestorationActivationData::Manifest(value)
                    .retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            ),
        }
    }
}

impl Owned for ResponseRecord17 {
    fn charge(&self, counter: &mut Census) -> Result<(), RuntimeError> {
        let Self { body } = self;
        let facts = crucible_node_transport::retained_metadata::historical_response_body_data(body)
            .and_then(|view| view.retained_metadata_data())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter.metadata(&facts)
    }
}

impl CnpRestoredSettledValidatedNode17 {
    /// Counts this actual decoded output's root and independently owned backing.
    ///
    /// This observes inert data only. Historical capacities are not allocation
    /// budgets, and another retained decoder attempt is counted independently.
    ///
    /// # Errors
    /// Refuses unsupported defining layouts, checked overflow or the maximum.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            reference,
            route,
            record,
        } = self;
        let mut counter = Census::new(maximum);
        counter.add(size_of::<Self>())?;
        counter.charge(reference)?;
        counter.charge(route)?;
        counter.charge(record)?;
        Ok(counter.bytes)
    }

    /// Names the independent fixed traversal scratch; the walk allocates no heap.
    pub(crate) fn counter_scratch_data() -> usize {
        counter_scratch_data() + size_of::<&Self>()
    }

    /// Reports zero temporary heap allocation for this borrowed typed walk.
    pub(crate) const fn maximum_simultaneous_transient_bytes_data() -> usize {
        0
    }
}

impl CnpRestoredNode17DecodeAttempt {
    /// Counts every actually retained decode product at its present phase.
    ///
    /// Success may move reference/route/record to a separate output. Remaining
    /// DOMs/canonical/reencoded products stay counted here, as do all refusal
    /// products. Prospective construction numbers do not stand in for owners.
    ///
    /// # Errors
    /// Refuses unsupported defining layouts, checked overflow or the maximum.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            construction: _,
            reference,
            route,
            value,
            canonical,
            record,
            reencoded,
        } = self;
        let mut counter = Census::new(maximum);
        counter.add(size_of::<Self>())?;
        counter.charge(reference)?;
        counter.charge(route)?;
        counter.charge(value)?;
        counter.charge(canonical)?;
        counter.charge(record)?;
        counter.charge(reencoded)?;
        Ok(counter.bytes)
    }

    /// Names the independent fixed traversal scratch; the walk allocates no heap.
    pub(crate) fn counter_scratch_data() -> usize {
        counter_scratch_data() + size_of::<&Self>()
    }

    /// Reports zero temporary heap allocation for this borrowed typed walk.
    pub(crate) const fn maximum_simultaneous_transient_bytes_data() -> usize {
        0
    }
}

fn counter_scratch_data() -> usize {
    size_of::<Census>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, crucible_node_transport::ProviderError>>()
        + size_of::<&NodeRecord17>()
        + size_of::<&serde_json::Value>()
        + size_of::<std::collections::btree_map::Iter<'static, Id, OriginalOperation17>>()
        + size_of::<std::collections::btree_map::Iter<'static, Id, OriginalInput17>>()
        + size_of::<std::slice::Iter<'static, ProducerAttempt17>>()
        + crate::node_contract::opaque_owner_counter_scratch_data()
        + crucible_node_transport::retained_metadata::historical_response_body_counter_scratch_data(
        )
        + HistoricalRestorationActivationData::historical_counter_scratch_data()
        + RetainedCommonProtocolData::admit_response_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::NodeRoute;
    use crucible_node_format::{U64, canonical};

    fn text(capacity: usize) -> String {
        let mut value = String::with_capacity(capacity);
        value.push('x');
        value
    }

    fn record() -> NodeRecord17 {
        NodeRecord17 {
            schema: text(4096),
            base: BaseRecord17 {
                schema: text(1024),
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
            base_activate_response_history: None,
            install_started: false,
            installed: false,
            activation: None,
            original_operations: Vec::with_capacity(13),
            original_inputs: Vec::with_capacity(17),
            commands: [None, None],
            completed: [None, None],
            world_manifest: None,
            world_value: None,
            world_bytes: None,
            observation_attempted: false,
            observation_completed: None,
            observation: None,
            observation_return: None,
            current_observations: Vec::with_capacity(19),
            producer_pending: None,
            producer_attempts: Vec::with_capacity(23),
            original_operations_capacity: usize::MAX,
            original_inputs_capacity: usize::MAX,
            producer_attempts_capacity: usize::MAX,
            capacities: vec![CommonCapacity17 {
                kind: CommonCapacityKind17::Vector,
                length: usize::MAX,
                capacity: Some(usize::MAX),
                element_bytes: usize::MAX,
                alignment: usize::MAX,
                shared_group: Some(usize::MAX),
            }],
            restored_families: None,
        }
    }

    #[test]
    fn decoded_output_counts_actual_spare_buffers_and_ignores_historical_numeric_budgets() {
        // This deliberately inert fixture tests storage only. It is never passed
        // to the strict reader and supplies no valid live/archive permission.
        let record = record();
        let expected_spare = record.schema.capacity()
            + record.base.schema.capacity()
            + record.original_operations.capacity() * size_of::<HistoricalAdmission17>()
            + record.original_inputs.capacity() * size_of::<HistoricalBatch17>()
            + record.current_observations.capacity() * size_of::<CurrentObservation17>()
            + record.producer_attempts.capacity() * size_of::<ProducerAttempt17>();
        let output = CnpRestoredSettledValidatedNode17 {
            reference: canonical::content_ref(b"independent Node body", "application/json")
                .unwrap(),
            route: NodeRoute {
                node: Id::new("node").unwrap(),
                owners: Vec::new(),
            },
            record,
        };
        let retained = output.retained_requested_storage_data(usize::MAX).unwrap();
        assert!(retained >= size_of::<CnpRestoredSettledValidatedNode17>() + expected_spare);
        assert_eq!(
            output.retained_requested_storage_data(retained).unwrap(),
            retained
        );
        assert!(
            output
                .retained_requested_storage_data(retained - 1)
                .is_err()
        );
        assert_eq!(
            CnpRestoredSettledValidatedNode17::maximum_simultaneous_transient_bytes_data(),
            0
        );
        assert!(CnpRestoredSettledValidatedNode17::counter_scratch_data() > 0);
    }

    #[test]
    fn retained_partial_decoder_counts_every_independent_product_after_output_move() {
        let reference = canonical::content_ref(b"{}", "application/json").unwrap();
        let route = NodeRoute {
            node: Id::new("node").unwrap(),
            owners: Vec::new(),
        };
        let construction = super::super::CnpRestoredNode17DecodeConstructionData::quote(
            &reference,
            b"{}",
            &route,
            usize::MAX,
        )
        .unwrap();
        let mut partial = CnpRestoredNode17DecodeAttempt {
            construction,
            reference: None,
            route: None,
            value: None,
            canonical: None,
            record: None,
            reencoded: None,
        };
        assert_eq!(
            partial.retained_requested_storage_data(usize::MAX).unwrap(),
            size_of::<CnpRestoredNode17DecodeAttempt>()
        );
        let mut canonical = Vec::with_capacity(8192);
        canonical.push(b'x');
        let canonical_capacity = canonical.capacity();
        let value = text(4096);
        let reencoded = text(4096);
        let text_capacity = value.capacity() + reencoded.capacity();
        partial.value = Some(serde_json::Value::String(value));
        partial.reencoded = Some(serde_json::Value::String(reencoded));
        partial.canonical = Some(canonical);
        let retained = partial.retained_requested_storage_data(usize::MAX).unwrap();
        assert_eq!(
            retained,
            size_of::<CnpRestoredNode17DecodeAttempt>() + text_capacity + canonical_capacity
        );
        assert_eq!(
            partial.retained_requested_storage_data(retained).unwrap(),
            retained
        );
        assert!(
            partial
                .retained_requested_storage_data(retained - 1)
                .is_err()
        );

        // Failure before the final move also retains each typed original; quote
        // numbers stay inline DATA and do not replace these actual owners.
        partial.reference = Some(reference);
        partial.route = Some(route);
        partial.record = Some(record());
        assert!(partial.retained_requested_storage_data(usize::MAX).unwrap() > retained);
        assert_eq!(
            CnpRestoredNode17DecodeAttempt::maximum_simultaneous_transient_bytes_data(),
            0
        );
        assert!(CnpRestoredNode17DecodeAttempt::counter_scratch_data() > 0);
    }
}
