//! Borrows complete model allocations as historical data, including failed partials.
//!
//! Capacity and alias banks are independently preadmitted by the caller. No
//! socket, physical hold, Control identity or restoration permission is decoded
//! or manufactured here. The surrounding settled17 graph remains mandatory.
//!
//! ```text
//! {schema, capacities, aliases, capacity_rows, data: {defining owner fields}}
//! ```

use super::*;
use crate::retained_metadata::{
    MetadataObserver, ObserveMetadata, RetainedProtocolMetadataFacts, aliases::MetadataAliasBank,
    records::MetadataRecordBank,
};
use serde::ser::SerializeStruct;
use std::mem::size_of;

pub(crate) struct ModelHistory<'a, T> {
    data: T,
    records: &'a MetadataRecordBank,
    aliases: &'a MetadataAliasBank,
    facts: RetainedProtocolMetadataFacts,
}

impl<T> ModelHistory<'_, T> {
    /// Returns the exact recorded owner's backing and population facts as DATA.
    pub(crate) fn retained_metadata_data(&self) -> RetainedProtocolMetadataFacts {
        self.facts
    }

    /// Bounds one actual Bytes encoder temporary independently of output banks.
    ///
    /// # Errors
    /// Refuses checked encoded-extent overflow. This is not allocation permission.
    pub(crate) fn historical_serialization_transient_bytes_data(
        &self,
    ) -> Result<usize, ProviderError> {
        self.facts
            .vector_capacity_bytes
            .div_ceil(3)
            .checked_mul(4)
            .ok_or(ProviderError::ResourceExhausted(
                "model history Bytes encoding extent",
            ))
    }
}

impl<T: Serialize> Serialize for ModelHistory<'_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ModelOwnerHistory", 5)?;
        state.serialize_field("schema", "source-private.packet-model-owner-history/17")?;
        state.serialize_field("capacities", self.records)?;
        state.serialize_field("aliases", self.aliases)?;
        state.serialize_field("capacity_rows", &self.facts.capacity_records)?;
        state.serialize_field("data", &self.data)?;
        state.end()
    }
}

pub(crate) fn borrow<'a, T: ObserveMetadata, V: Serialize>(
    owner: &T,
    data: V,
    records: &'a mut MetadataRecordBank,
    aliases: &'a mut MetadataAliasBank,
) -> Result<ModelHistory<'a, V>, ProviderError> {
    let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
    observer.observe(owner)?;
    let facts = observer.finish();

    Ok(ModelHistory {
        data,
        records,
        aliases,
        facts,
    })
}

pub(crate) fn counter_scratch_data<T>() -> usize {
    size_of::<ModelHistory<'static, T>>()
        + size_of::<Result<ModelHistory<'static, T>, ProviderError>>()
        + size_of::<&ModelHistory<'static, T>>()
        + size_of::<&T>()
        + size_of::<ModelRecordLoans<'static>>()
        + size_of::<ModelCapacityLoans<'static>>()
        + size_of::<ProducerStateLoans<'static>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<String>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<&MetadataRecordBank>()
        + size_of::<&mut MetadataRecordBank>()
        + size_of::<&MetadataAliasBank>()
        + size_of::<&mut MetadataAliasBank>()
        + size_of::<&usize>()
        + size_of::<Result<(), ProviderError>>()
}

type ModelRecordLoans<'a> = (
    &'a String,
    &'a PacketModelKind,
    &'a U64,
    &'a ContentRef,
    &'a Position,
    &'a ModelCapacities,
    &'a serde_json::Value,
);
type ModelCapacityLoans<'a> = (
    &'a usize,
    &'a usize,
    &'a usize,
    &'a usize,
    &'a usize,
    &'a usize,
);
type ProducerStateLoans<'a> = (
    &'a Vec<PacketEvent>,
    &'a usize,
    &'a Position,
    &'a bool,
    &'a Vec<PacketPublication>,
    &'a BTreeMap<Id, PacketGrant>,
    &'a u64,
    &'a u64,
    &'a BTreeMap<Id, Vec<Id>>,
    &'a bool,
);

macro_rules! fields {
    ($ty:ty, $($field:ident),+ $(,)?) => {
        impl ObserveMetadata for $ty {
            fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
                let Self { $($field),+ } = self;
                $(observer.observe($field)?;)+
                Ok(())
            }
        }
    };
}

fields!(
    ModelCapacities,
    events,
    reactions,
    delivered_inputs,
    publications,
    outputs,
    stages
);
fields!(
    ModelRecord,
    schema,
    kind,
    captured_process,
    configuration,
    cut,
    capacities,
    state
);
fields!(PacketDecodedModelSnapshot, record);
fields!(
    ProducerState,
    events,
    next_event,
    reached,
    gate_closed,
    outputs,
    grants,
    private_mutations,
    packet_effects,
    retired,
    failed
);

impl ObserveMetadata for PacketModelKind {
    fn observe_metadata(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Producer | Self::Reactive => Ok(()),
        }
    }
}

/// Borrows every producer model field, substituting only a socket-role label.
pub(crate) struct ProducerProgramHistory<'a>(&'a PacketProgram);

impl PacketProgram {
    pub(crate) fn borrowed_settled_model_data(&self) -> ProducerProgramHistory<'_> {
        ProducerProgramHistory(self)
    }

    pub(crate) fn settled_model_counter_scratch_data() -> usize {
        counter_scratch_data::<ProducerProgramHistory<'static>>()
            + size_of::<ProducerProgramHistory<'static>>()
            + size_of::<&PacketProgram>()
            + size_of::<Option<&PacketProgram>>()
            + size_of::<Option<ProducerProgramHistory<'static>>>()
            + size_of::<(
                &UnixDatagram,
                &Vec<PacketEvent>,
                &usize,
                &Position,
                &bool,
                &Vec<PacketPublication>,
                &BTreeMap<Id, PacketGrant>,
                &u64,
                &u64,
                &BTreeMap<Id, Vec<Id>>,
                &bool,
            )>()
    }
}

impl Serialize for ProducerProgramHistory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketProgram {
            effect_socket: _,
            events,
            next_event,
            reached,
            gate_closed,
            outputs,
            grants,
            private_mutations,
            packet_effects,
            retired,
            failed,
        } = self.0;
        let mut state = serializer.serialize_struct("ProducerProgramHistory", 11)?;
        state.serialize_field("effect_socket_role", "model-effect-socket")?;
        state.serialize_field("events", events)?;
        state.serialize_field("next_event", next_event)?;
        state.serialize_field("reached", reached)?;
        state.serialize_field("gate_closed", gate_closed)?;
        state.serialize_field("outputs", outputs)?;
        state.serialize_field("grants", grants)?;
        state.serialize_field("private_mutations", private_mutations)?;
        state.serialize_field("packet_effects", packet_effects)?;
        state.serialize_field("retired", retired)?;
        state.serialize_field("failed", failed)?;
        state.end()
    }
}

impl ObserveMetadata for PacketProgram {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let PacketProgram {
            effect_socket: _,
            events,
            next_event,
            reached,
            gate_closed,
            outputs,
            grants,
            private_mutations,
            packet_effects,
            retired,
            failed,
        } = self;
        observer.observe(events)?;
        observer.observe(next_event)?;
        observer.observe(reached)?;
        observer.observe(gate_closed)?;
        observer.observe(outputs)?;
        observer.observe(grants)?;
        observer.observe(private_mutations)?;
        observer.observe(packet_effects)?;
        observer.observe(retired)?;
        observer.observe(failed)
    }
}

impl PacketDecodedModelSnapshot {
    pub(crate) fn borrowed_settled_model_data(&self) -> impl Serialize + '_ {
        &self.record
    }
}
