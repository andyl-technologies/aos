//! Reads prepared, adoption and displaced model owners as inert historical DATA.
//!
//! Fields follow the defining Model10 writers, including contradictory failed
//! partials. One caller-owned Ledger crosses all children without reset. This
//! component never constructs a Program, physical Hold or socket. The enclosing
//! graph validates the shared Hold and each actual Control relation separately.
//!
//! ```text
//! data = {schema,creator,thread,hold_role,control,model,producer,reactive,
//!         original_program,displaced_producer,displaced_reactive,
//!         original_producer,original_reactive,restored_producer,
//!         restored_reactive,effect_socket_role}
//! ```
//!
//! This is the bare `data` loan from `borrowed_settled_model_data`, not a new
//! independent ModelHistory envelope or a replacement for aggregate admission.

use super::super::super::connected::continuation::settled_reader::prepared::{
    ReactiveAdoption17Data, ReactiveProgram17Data,
};
use super::*;
use crate::protocol_snapshot::owned11::typed::historical_struct;
use crate::reference_packet::connected::{
    PacketConnectedPublication, PacketDeliveredInput, PacketPendingPublication, PacketReaction,
};
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};
use serde::ser::SerializeStruct;

/// Requires the defining inert ControlRecord reader, never an unvalidated DOM.
///
/// The actual Control reader implements this marker beside its owning grammar.
/// There is deliberately no blanket implementation for arbitrary Value input.
pub(crate) trait PreparedControlHistory17:
    HistoricalType + ObserveMetadata + Serialize
{
}

macro_rules! scalar_role {
    ($name:ident, $literal:literal) => {
        pub(in crate::reference_packet) struct $name;

        impl HistoricalType for $name {
            fn read(
                input: &[u8],
                _: &mut Ledger<'_, '_, '_>,
                build: bool,
            ) -> Result<Option<Self>, ProviderError> {
                if plain_string(input)? != $literal {
                    return Err(invalid());
                }
                Ok(build.then_some(Self))
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str($literal)
            }
        }

        impl ObserveMetadata for $name {
            fn observe_metadata(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
                Ok(())
            }
        }
    };
}

scalar_role!(SocketRole, "model-effect-socket");
scalar_role!(ThreadRole, "same-original-thread-history-only");
scalar_role!(HoldRole, "native-complete-restore-physical-hold");
scalar_role!(
    PreparedSchema,
    "source-private.packet-prepared-model-history/17"
);

macro_rules! inert_fields {
    ($name:ident { $($field:ident : $child:ty),+ $(,)? }) => {
        #[derive(Serialize)]
        pub(in crate::reference_packet) struct $name { $($field: $child),+ }

        historical_struct!($name { $($field: $child),+ });

        impl ObserveMetadata for $name {
            fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
                $(observer.observe(&self.$field)?;)+
                Ok(())
            }
        }
    };
}
pub(in crate::reference_packet) use inert_fields;

historical_struct!(ModelCapacities {
    events: usize,
    reactions: usize,
    delivered_inputs: usize,
    publications: usize,
    outputs: usize,
    stages: usize,
});
historical_struct!(ModelRecord {
    schema: String,
    kind: PacketModelKind,
    captured_process: U64,
    configuration: ContentRef,
    cut: Position,
    capacities: ModelCapacities,
    state: serde_json::Value,
});

impl HistoricalType for PacketModelKind {
    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let kind = match plain_string(input)? {
            "producer" => Self::Producer,
            "reactive" => Self::Reactive,
            _ => return Err(invalid()),
        };
        Ok(build.then_some(kind))
    }
}

impl HistoricalType for ProducerState {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_producer_fields(input, ledger, build, false)
    }
}

pub(in crate::reference_packet) struct ProducerProgram17Data(ProducerState);

impl HistoricalType for ProducerProgram17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Ok(read_producer(input, ledger, build)?.map(Self))
    }
}

impl ObserveMetadata for ProducerProgram17Data {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        // The wrapper represents the original program, not an extra child.
        self.0.observe_metadata(observer)
    }
}

impl Serialize for ProducerProgram17Data {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ProducerState {
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
        } = &self.0;
        let mut fields = serializer.serialize_struct("InertProducerProgram17", 11)?;
        fields.serialize_field("effect_socket_role", "model-effect-socket")?;
        fields.serialize_field("events", events)?;
        fields.serialize_field("next_event", next_event)?;
        fields.serialize_field("reached", reached)?;
        fields.serialize_field("gate_closed", gate_closed)?;
        fields.serialize_field("outputs", outputs)?;
        fields.serialize_field("grants", grants)?;
        fields.serialize_field("private_mutations", private_mutations)?;
        fields.serialize_field("packet_effects", packet_effects)?;
        fields.serialize_field("retired", retired)?;
        fields.serialize_field("failed", failed)?;
        fields.end()
    }
}

inert_fields!(ProducerAdoption17Data {
    snapshot: Option<ModelRecord>,
    effect_socket_role: Option<SocketRole>,
    state: Option<ProducerState>,
    events: Vec<PacketEvent>,
    outputs: Vec<PacketPublication>,
    completed: Option<ProducerProgram17Data>,
    ready: bool,
});

/// Retains the actual old NativeProgram discriminant without creating one.
enum OriginalProgram17Data {
    Producer(ProducerProgram17Data),
    Reactive(ReactiveProgram17Data),
    RestorationInProgress,
}

impl HistoricalType for OriginalProgram17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let kind = plain_string(fields.named("kind")?)?;
        let data = fields.named("data")?;
        fields.finish()?;
        match kind {
            "producer" => Ok(ledger
                .read::<ProducerProgram17Data>(data, build)?
                .map(Self::Producer)),
            "reactive" => Ok(ledger
                .read::<ReactiveProgram17Data>(data, build)?
                .map(Self::Reactive)),
            "restoration_in_progress" if data == b"null" => {
                Ok(build.then_some(Self::RestorationInProgress))
            }
            _ => Err(invalid()),
        }
    }
}

impl ObserveMetadata for OriginalProgram17Data {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Producer(data) => observer.observe(data),
            Self::Reactive(data) => observer.observe(data),
            Self::RestorationInProgress => Ok(()),
        }
    }
}

impl Serialize for OriginalProgram17Data {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("InertOriginalProgram17", 2)?;
        match self {
            Self::Producer(data) => {
                fields.serialize_field("kind", "producer")?;
                fields.serialize_field("data", data)?;
            }
            Self::Reactive(data) => {
                fields.serialize_field("kind", "reactive")?;
                fields.serialize_field("data", data)?;
            }
            Self::RestorationInProgress => {
                fields.serialize_field("kind", "restoration_in_progress")?;
                fields.serialize_field("data", &None::<()>)?;
            }
        }
        fields.end()
    }
}

/// Keeps every independent prepared-model owner; no field confers live rights.
#[derive(Serialize)]
pub(crate) struct PacketSettledPreparedModel17Data<C> {
    schema: PreparedSchema,
    creator: u32,
    thread: ThreadRole,
    hold_role: HoldRole,
    control: Option<C>,
    model: Option<ModelRecord>,
    producer: Option<ProducerAdoption17Data>,
    reactive: Option<ReactiveAdoption17Data>,
    original_program: Option<OriginalProgram17Data>,
    displaced_producer: Option<ProducerState>,
    displaced_reactive: Option<ReactiveModel17Data>,
    original_producer: Option<ProducerProgram17Data>,
    original_reactive: Option<ReactiveProgram17Data>,
    restored_producer: Option<ProducerProgram17Data>,
    restored_reactive: Option<ReactiveProgram17Data>,
    effect_socket_role: Option<SocketRole>,
}

/// Reads the Prepared Model10 field roster beneath the whole graph admission.
///
/// `hold_view` and its exact capacity span refer to the separately validated
/// shared Hold object, encoded once in the aggregate graph. This consumes its
/// alias edge at the defining field position, without resetting either bank.
/// The caller retains raw input before build and the completed return before
/// checking cross-owner Control/Hold/model relationships. Failed and pending
/// partials are represented, not excluded by settled-route eligibility.
///
/// # Errors
/// Refuses malformed roles/fields, invalid defining Control data, a mismatched
/// shared Hold edge, exhausted ledger bounds or unavailable exact backing.
pub(crate) fn read_settled_prepared_model17_data<C: PreparedControlHistory17>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    hold_view: &[u8],
    hold_capacity_rows: &[u8],
) -> Result<Option<PacketSettledPreparedModel17Data<C>>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let schema = ledger.read::<PreparedSchema>(fields.named("schema")?, build)?;
    let creator = ledger.read::<u32>(fields.named("creator")?, build)?;
    let thread = ledger.read::<ThreadRole>(fields.named("thread")?, build)?;
    let hold_role = ledger.read::<HoldRole>(fields.named("hold_role")?, build)?;
    let hold_extent = ledger.row_aligned(
        crate::retained_metadata::records::MetadataRecordKind::Shared,
        std::mem::size_of::<crate::reference_packet::control::PacketCompleteRestorePhysicalHold>(),
        std::mem::align_of::<crate::reference_packet::control::PacketCompleteRestorePhysicalHold>(),
    )?;
    if hold_extent != 1 {
        return Err(invalid());
    }
    ledger.shared(
        crate::retained_metadata::aliases::MetadataSharedKind::NativeRestoredPhysicalHold,
        std::mem::size_of::<crate::reference_packet::control::PacketCompleteRestorePhysicalHold>(),
        hold_view,
        hold_capacity_rows,
    )?;
    let control = ledger.read::<Option<C>>(fields.named("control")?, build)?;
    let model = ledger.read::<Option<ModelRecord>>(fields.named("model")?, build)?;
    let producer =
        ledger.read::<Option<ProducerAdoption17Data>>(fields.named("producer")?, build)?;
    let reactive =
        ledger.read::<Option<ReactiveAdoption17Data>>(fields.named("reactive")?, build)?;
    let original_program =
        ledger.read::<Option<OriginalProgram17Data>>(fields.named("original_program")?, build)?;
    let displaced_producer =
        ledger.read::<Option<ProducerState>>(fields.named("displaced_producer")?, build)?;
    let displaced_reactive =
        ledger.read::<Option<ReactiveModel17Data>>(fields.named("displaced_reactive")?, build)?;
    let original_producer =
        ledger.read::<Option<ProducerProgram17Data>>(fields.named("original_producer")?, build)?;
    let original_reactive =
        ledger.read::<Option<ReactiveProgram17Data>>(fields.named("original_reactive")?, build)?;
    let restored_producer =
        ledger.read::<Option<ProducerProgram17Data>>(fields.named("restored_producer")?, build)?;
    let restored_reactive =
        ledger.read::<Option<ReactiveProgram17Data>>(fields.named("restored_reactive")?, build)?;
    let effect_socket_role =
        ledger.read::<Option<SocketRole>>(fields.named("effect_socket_role")?, build)?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(PacketSettledPreparedModel17Data {
        schema: schema.ok_or_else(invalid)?,
        creator: creator.ok_or_else(invalid)?,
        thread: thread.ok_or_else(invalid)?,
        hold_role: hold_role.ok_or_else(invalid)?,
        control: control.ok_or_else(invalid)?,
        model: model.ok_or_else(invalid)?,
        producer: producer.ok_or_else(invalid)?,
        reactive: reactive.ok_or_else(invalid)?,
        original_program: original_program.ok_or_else(invalid)?,
        displaced_producer: displaced_producer.ok_or_else(invalid)?,
        displaced_reactive: displaced_reactive.ok_or_else(invalid)?,
        original_producer: original_producer.ok_or_else(invalid)?,
        original_reactive: original_reactive.ok_or_else(invalid)?,
        restored_producer: restored_producer.ok_or_else(invalid)?,
        restored_reactive: restored_reactive.ok_or_else(invalid)?,
        effect_socket_role: effect_socket_role.ok_or_else(invalid)?,
    }))
}

impl<C: ObserveMetadata> ObserveMetadata for PacketSettledPreparedModel17Data<C> {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        // The Hold is an inert role here. Its independently retained definition
        // and shared allocation are observed by the whole graph exactly once.
        observer.observe(&self.creator)?;
        observer.observe(&self.control)?;
        observer.observe(&self.model)?;
        observer.observe(&self.producer)?;
        observer.observe(&self.reactive)?;
        observer.observe(&self.original_program)?;
        observer.observe(&self.displaced_producer)?;
        observer.observe(&self.displaced_reactive)?;
        observer.observe(&self.original_producer)?;
        observer.observe(&self.original_reactive)?;
        observer.observe(&self.restored_producer)?;
        observer.observe(&self.restored_reactive)
    }
}

impl<C: PreparedControlHistory17> PacketSettledPreparedModel17Data<C> {
    /// Returns the captured creator scalar for the enclosing archived identity join.
    /// This never authenticates the current process or revives an originating owner.
    pub(crate) fn historical_creator_data(&self) -> u32 {
        self.creator
    }

    /// Borrows the actual retained defining inert Control child, when present.
    pub(crate) fn control_data(&self) -> Option<&C> {
        self.control.as_ref()
    }

    /// Borrows every retained partial for independently priced graph comparisons.
    pub(crate) fn borrowed_partial_data(&self) -> impl Serialize + '_ {
        self
    }

    /// Appends this completed inert owner's actual backing without clearing banks.
    ///
    /// # Errors
    /// Refuses exhausted metadata banks, traversal bounds or checked overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(self)
    }

    /// Counts this typed root and backing, excluding separately held graph roles.
    ///
    /// # Errors
    /// Refuses traversal/size overflow or a total beyond the admitted maximum.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        observer.observe(self)?;
        std::mem::size_of::<Self>()
            .checked_add(
                crate::retained_metadata::requested_metadata_backing_storage_data(
                    &observer.finish(),
                )?,
            )
            .filter(|bytes| *bytes <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "prepared model typed backing",
            ))
    }
}

/// Names the defining parser, simultaneous field owners and direct result views.
/// The actual inert Control child contributes its defining counter separately.
pub(crate) fn settled_prepared_model17_counter_scratch_data<C: PreparedControlHistory17>() -> usize
{
    use std::mem::size_of;
    macro_rules! field_views {
        ($($ty:ty),+ $(,)?) => { 0usize $(
            + size_of::<Option<$ty>>()
            + size_of::<Result<Option<$ty>, ProviderError>>()
            + size_of::<Result<$ty, ProviderError>>()
            + size_of::<&$ty>()
        )+ };
    }
    super::settled_model17_counter_scratch_data()
        + super::super::super::connected::continuation::settled_reader::counter_scratch_data()
        + size_of::<PacketSettledPreparedModel17Data<C>>()
        + size_of::<Option<PacketSettledPreparedModel17Data<C>>>()
        + size_of::<Result<Option<PacketSettledPreparedModel17Data<C>>, ProviderError>>()
        + size_of::<&PacketSettledPreparedModel17Data<C>>()
        + size_of::<Option<&C>>()
        + size_of::<ProducerAdoption17Data>()
        + size_of::<OriginalProgram17Data>()
        + size_of::<ProducerProgram17Data>()
        + size_of::<ReactiveAdoption17Data>()
        + size_of::<ReactiveProgram17Data>()
        + size_of::<Fields<'static>>()
        + size_of::<&mut Ledger<'static, 'static, 'static>>()
        + 3 * size_of::<&[u8]>()
        + size_of::<&str>()
        + size_of::<bool>()
        + size_of::<usize>()
        + size_of::<crate::retained_metadata::MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<(), ProviderError>>()
        + field_views!(
            PreparedSchema, u32, ThreadRole, HoldRole, Option<C>, Option<ModelRecord>,
            Option<ProducerAdoption17Data>, Option<ReactiveAdoption17Data>,
            Option<OriginalProgram17Data>, Option<ProducerState>, Option<ReactiveModel17Data>,
            Option<ProducerProgram17Data>, Option<ReactiveProgram17Data>,
            Option<ProducerProgram17Data>, Option<ReactiveProgram17Data>, Option<SocketRole>,
            ModelRecord, ModelCapacities, PacketModelKind, String, U64, ContentRef, Position,
            serde_json::Value, Option<ProducerState>, Vec<PacketEvent>, Vec<PacketPublication>,
            Option<ProducerProgram17Data>, bool, Option<SocketRole>, Option<ModelRecord>,
            ProducerProgram17Data, ReactiveProgram17Data,
            Option<ModelRecord>, Option<SocketRole>, Option<ReactiveModel17Data>,
            Vec<PacketReaction>, Vec<PacketDeliveredInput>, Vec<PacketPendingPublication>,
            Vec<PacketConnectedPublication>, Option<ReactiveProgram17Data>, bool,
        )
        + super::super::super::connected::continuation::settled_reader::prepared::counter_scratch_data()
}

// crucible-lint: allow panic-shortcut -- genuine inert adoption controls intentionally assert exact retained data.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "assertions inspect actual inert adopter failures and completion"
)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};

    fn limits() -> HistoricalJsonLimits {
        HistoricalJsonLimits {
            maximum_input_bytes: 262_144,
            maximum_nodes: 16_384,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 64 * 1024 * 1024,
            maximum_tree_entries: 4096,
        }
    }

    fn original() -> PacketProgram {
        let (effect, _peer) = UnixDatagram::pair().unwrap();
        let mut payload = Vec::with_capacity(31);
        payload.extend_from_slice(b"adoption payload");
        PacketProgram::new(
            vec![PacketEvent {
                id: Id::new("prepared-reader-event").unwrap(),
                evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(5), U64::new(0), Phase::Publication),
                payload: Some(Bytes::new(payload)),
            }],
            effect,
        )
        .unwrap()
    }

    fn snapshot(original: &PacketProgram) -> PacketDecodedModelSnapshot {
        let captured = original.capture_state(original.reached, 262_144).unwrap();
        decode_packet_model_snapshot(captured.bytes(), captured.reference(), 262_144).unwrap()
    }

    fn roundtrip(actual: &PacketProducerModelAdoption) -> ProducerAdoption17Data {
        let bytes = serde_json::to_vec(&actual.borrowed_settled_model_data()).unwrap();
        let mut bank = MetadataRecordBank::reserve(1024).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        observer.observe(actual).unwrap();
        let facts = observer.finish();
        let encoded = serde_json::to_vec(&bank).unwrap();
        let records =
            ValidatedMetadataRecords::validate(&encoded, facts.capacity_records, 64 * 1024 * 1024)
                .unwrap();
        let mut preflight = Ledger::new(records.rows(), limits());
        assert!(
            preflight
                .read::<ProducerAdoption17Data>(&bytes, false)
                .unwrap()
                .is_none()
        );
        assert!(preflight.rows.next().is_none());

        let mut construction = Ledger::new(records.rows(), limits());
        let retained = Some(
            construction
                .read::<ProducerAdoption17Data>(&bytes, true)
                .unwrap()
                .unwrap(),
        );
        assert!(construction.rows.next().is_none());
        let decoded = retained.unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
        let mut observed = MetadataObserver::new();
        observed.observe(&decoded).unwrap();
        assert_eq!(observed.finish(), facts);

        let mut short_rows = serde_json::to_value(&bank).unwrap();
        short_rows.as_array_mut().unwrap().pop().unwrap();
        let short_bytes = serde_json::to_vec(&short_rows).unwrap();
        let short = ValidatedMetadataRecords::validate(
            &short_bytes,
            facts.capacity_records - 1,
            64 * 1024 * 1024,
        )
        .unwrap();
        let mut short_ledger = Ledger::new(short.rows(), limits());
        assert!(
            short_ledger
                .read::<ProducerAdoption17Data>(&bytes, false)
                .is_err()
        );
        decoded
    }

    #[test]
    fn actual_failed_adopter_keeps_raw_snapshot_and_independent_failed_typed_state() {
        let original = original();
        let mut decoded = snapshot(&original);
        decoded.record.state["failed"] = serde_json::Value::Bool(true);
        let mut incoming = Some(decoded);
        let mut attempt = None;

        assert!(
            PacketProgram::prepare_model_state_retained_into(&mut incoming, &mut attempt).is_err()
        );
        assert!(incoming.is_none());
        let decoded = roundtrip(attempt.as_ref().unwrap());

        assert!(decoded.snapshot.is_some());
        assert!(decoded.state.as_ref().unwrap().failed);
        assert!(!decoded.state.as_ref().unwrap().events.is_empty());
        assert!(decoded.events.is_empty());
        assert!(decoded.completed.is_none());
        assert!(!decoded.ready);
    }

    #[test]
    fn actual_completed_adopter_keeps_snapshot_and_completed_model_without_socket_reconstruction() {
        let original = original();
        let mut incoming = Some(snapshot(&original));
        let mut attempt = None;
        PacketProgram::prepare_model_state_retained_into(&mut incoming, &mut attempt).unwrap();
        let prepared = roundtrip(attempt.as_ref().unwrap());
        assert!(prepared.ready);
        assert!(!prepared.events.is_empty());
        assert!(prepared.state.as_ref().unwrap().events.is_empty());
        assert!(prepared.completed.is_none());

        let (effect, _peer) = UnixDatagram::pair().unwrap();
        let mut effect = Some(effect);
        attempt
            .as_mut()
            .unwrap()
            .bind_original_socket(&mut effect)
            .unwrap();
        let completed = roundtrip(attempt.as_ref().unwrap());

        assert!(effect.is_none());
        assert!(completed.snapshot.is_some());
        assert!(completed.state.is_none());
        assert!(completed.events.is_empty());
        assert_eq!(
            completed.completed.as_ref().unwrap().0.events,
            original.events
        );
        assert!(completed.effect_socket_role.is_none());
    }
}

/// Retains a prepared owner and its exact separately defined physical Hold group.
pub(crate) struct CurrentPreparedModel17Data<C> {
    pub(crate) hold_group: usize,
    pub(crate) data: PacketSettledPreparedModel17Data<C>,
}

/// Reads the current bare prepared payload using the same aggregate ledger.
///
/// # Errors
/// Refuses another field roster, mismatched native Shared rows or an undefined Hold.
pub(crate) fn read_current_prepared_model17_data<C: PreparedControlHistory17>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<CurrentPreparedModel17Data<C>>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let schema = ledger.read::<PreparedSchema>(fields.named("schema")?, build)?;
    let creator = ledger.read::<u32>(fields.named("creator")?, build)?;
    let thread = ledger.read::<ThreadRole>(fields.named("thread")?, build)?;
    let hold_role = ledger.read::<HoldRole>(fields.named("hold_role")?, build)?;
    let hold_group =
        crate::protocol_snapshot::restored_settled17::current_shared::read_reference17(
            ledger,
            crate::retained_metadata::aliases::MetadataSharedKind::NativeRestoredPhysicalHold,
            (
                std::mem::size_of::<
                    crate::reference_packet::control::PacketCompleteRestorePhysicalHold,
                >(),
                std::mem::align_of::<
                    crate::reference_packet::control::PacketCompleteRestorePhysicalHold,
                >(),
            ),
        )?;
    let control = ledger.read::<Option<C>>(fields.named("control")?, build)?;
    let model = ledger.read::<Option<ModelRecord>>(fields.named("model")?, build)?;
    let producer =
        ledger.read::<Option<ProducerAdoption17Data>>(fields.named("producer")?, build)?;
    let reactive =
        ledger.read::<Option<ReactiveAdoption17Data>>(fields.named("reactive")?, build)?;
    let original_program =
        ledger.read::<Option<OriginalProgram17Data>>(fields.named("original_program")?, build)?;
    let displaced_producer =
        ledger.read::<Option<ProducerState>>(fields.named("displaced_producer")?, build)?;
    let displaced_reactive =
        ledger.read::<Option<ReactiveModel17Data>>(fields.named("displaced_reactive")?, build)?;
    let original_producer =
        ledger.read::<Option<ProducerProgram17Data>>(fields.named("original_producer")?, build)?;
    let original_reactive =
        ledger.read::<Option<ReactiveProgram17Data>>(fields.named("original_reactive")?, build)?;
    let restored_producer =
        ledger.read::<Option<ProducerProgram17Data>>(fields.named("restored_producer")?, build)?;
    let restored_reactive =
        ledger.read::<Option<ReactiveProgram17Data>>(fields.named("restored_reactive")?, build)?;
    let effect_socket_role =
        ledger.read::<Option<SocketRole>>(fields.named("effect_socket_role")?, build)?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(CurrentPreparedModel17Data {
        hold_group,
        data: PacketSettledPreparedModel17Data {
            schema: schema.ok_or_else(invalid)?,
            creator: creator.ok_or_else(invalid)?,
            thread: thread.ok_or_else(invalid)?,
            hold_role: hold_role.ok_or_else(invalid)?,
            control: control.ok_or_else(invalid)?,
            model: model.ok_or_else(invalid)?,
            producer: producer.ok_or_else(invalid)?,
            reactive: reactive.ok_or_else(invalid)?,
            original_program: original_program.ok_or_else(invalid)?,
            displaced_producer: displaced_producer.ok_or_else(invalid)?,
            displaced_reactive: displaced_reactive.ok_or_else(invalid)?,
            original_producer: original_producer.ok_or_else(invalid)?,
            original_reactive: original_reactive.ok_or_else(invalid)?,
            restored_producer: restored_producer.ok_or_else(invalid)?,
            restored_reactive: restored_reactive.ok_or_else(invalid)?,
            effect_socket_role: effect_socket_role.ok_or_else(invalid)?,
        },
    }))
}

/// Retains a decoded model record without any live program or adoption handle.
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct CurrentDecodedModelRecord17Data(ModelRecord);

impl HistoricalType for CurrentDecodedModelRecord17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        ledger
            .read::<ModelRecord>(input, build)
            .map(|record| record.map(Self))
    }
}

impl ObserveMetadata for CurrentDecodedModelRecord17Data {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        observer.observe(&self.0)
    }
}

// The new17 owning path keeps typed children in the outer attempt on errors.
#[path = "prepared/retained.rs"]
pub(in crate::reference_packet) mod retained;
