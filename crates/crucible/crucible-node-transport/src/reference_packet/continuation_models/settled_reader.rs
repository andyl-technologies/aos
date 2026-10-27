//! Reads current model state as inert DATA beneath the native17 whole graph.
//!
//! The paired writer emits `["producer",{fields}]` or `["reactive",{fields}]`
//! in its defining typed order. One aggregate capacity/alias ledger is passed
//! through every child without reset. A failed build may drop an unfinished
//! inert field; the caller must retain raw input and its spent attempt. Completed
//! typed output is installed by the caller before semantic correspondence checks.
//! No decoder in this module creates a Program, socket, Hold or execution right.

use super::super::connected::continuation::settled_reader::ReactiveModel17Data;
use super::*;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};

#[path = "settled_reader/vocabulary.rs"]
mod vocabulary;

#[path = "settled_reader/prepared.rs"]
pub(crate) mod prepared;

#[path = "settled_reader/adoption18.rs"]
pub(crate) mod adoption18;

/// Keeps the complete current logical model, without a live effect descriptor.
pub(crate) struct PacketSettledModel17Data {
    state: CurrentModel,
}

enum CurrentModel {
    Producer(ProducerState),
    Reactive(ReactiveModel17Data),
}

/// Reads the closed kind and every typed field using the caller's same ledger.
///
/// `build=false` validates the complete capacity prefix without allocation.
/// The whole native17 owner separately admits all tree layout and work, retains
/// raw bytes before build, and retains the returned typed owner before checking
/// it against Control, proof inventory, current cut and immutable definition.
///
/// # Errors
/// Refuses an unknown kind or socket role, malformed fields, an exhausted
/// caller ledger, mismatched capacity rows or unavailable exact backing.
pub(crate) fn read_settled_model17_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<PacketSettledModel17Data>, ProviderError> {
    let mut array = Fields::array(input)?;
    let kind = plain_string(array.next_value()?.ok_or_else(invalid)?)?;
    let body = array.next_value()?.ok_or_else(invalid)?;
    array.finish()?;
    let state = match kind {
        "producer" => read_producer(body, ledger, build)?.map(CurrentModel::Producer),
        "reactive" => {
            ReactiveModel17Data::read_current(body, ledger, build)?.map(CurrentModel::Reactive)
        }
        _ => return Err(invalid()),
    };
    Ok(state.map(|state| PacketSettledModel17Data { state }))
}

impl PacketSettledModel17Data {
    /// Derives the current boundary from the same decoded inventory fields.
    ///
    /// This is not the immutable first restoration boundary. The installer
    /// independently admits validation, formatter and canonical hash work before
    /// entry, then retains this result before moving the current model. Failed
    /// and incomplete originals remain DATA and acquire no replay permission.
    ///
    /// # Errors
    /// Refuses inconsistent current fields, invalid positions or serialization.
    pub(crate) fn installation_boundary18_data(
        &self,
    ) -> Result<PacketModelCaptureBoundaryData, ProviderError> {
        self.authenticate_current_data()?;
        match &self.state {
            CurrentModel::Producer(state) => {
                let pending = state.events.get(state.next_event..).ok_or_else(invalid)?;
                let inventory = ProducerInventoryData {
                    reached: state.reached,
                    gate_closed: state.gate_closed,
                    pending,
                    retained_outputs: &state.outputs,
                    private_mutations: U64::new(state.private_mutations),
                    packet_effects: U64::new(state.packet_effects),
                };
                Ok(PacketModelCaptureBoundaryData {
                    local_cursor: state.reached,
                    gate_closed: state.gate_closed,
                    retained_outputs: state.outputs.len(),
                    earliest_pending_completion: pending.iter().map(|event| event.completion).min(),
                    inventory_hash: canonical::json_hash(
                        "source-owned.packet-inventory.v1",
                        &inventory,
                    )?,
                })
            }
            CurrentModel::Reactive(state) => state.installation_boundary18_data(),
        }
    }

    pub(crate) fn kind_data(&self) -> PacketModelKind {
        match &self.state {
            CurrentModel::Producer(_) => PacketModelKind::Producer,
            CurrentModel::Reactive(_) => PacketModelKind::Reactive,
        }
    }

    pub(crate) fn current_position_data(&self) -> Position {
        match &self.state {
            CurrentModel::Producer(state) => state.reached,
            CurrentModel::Reactive(state) => state.current_position_data(),
        }
    }

    /// Appends the actual decoded owner's fields to the whole caller's bank.
    ///
    /// No bank is cleared or replaced. Failed/incomplete logical fields remain
    /// fully observed; route eligibility is a different explicit predicate.
    ///
    /// # Errors
    /// Refuses an exhausted record/alias/traversal bank or checked overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match &self.state {
            CurrentModel::Producer(state) => observer.observe(state),
            CurrentModel::Reactive(state) => state.observe_settled_history_metadata_data(observer),
        }
    }

    /// Counts this typed root and its actual independently retained backing.
    ///
    /// Raw protocol bytes, decode/canonical transients and other graph owners
    /// remain separate. Equal shared values receive no identity-based discount.
    ///
    /// # Errors
    /// Refuses traversal/layout overflow or a total beyond the supplied maximum.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_settled_history_metadata_data(&mut observer)?;
        let facts = observer.finish();
        std::mem::size_of::<Self>()
            .checked_add(crate::retained_metadata::requested_metadata_backing_storage_data(&facts)?)
            .filter(|total| *total <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "current model typed backing",
            ))
    }

    /// Checks local current-model consistency after the typed owner is retained.
    /// The whole graph must still correlate each actual Control original and proof.
    ///
    /// # Errors
    /// Refuses invalid local positions, definitions or namespace relationships.
    pub(crate) fn authenticate_current_data(&self) -> Result<(), ProviderError> {
        match &self.state {
            CurrentModel::Producer(state) => authenticate_producer(state),
            CurrentModel::Reactive(state) => state.authenticate_current_data(),
        }
    }

    /// Checks the separate settled route's current-model eligibility.
    ///
    /// Failed or incomplete logical state remains valid inert history. It cannot
    /// be adopted through this settled route; the live writer must establish the
    /// same restriction before publication in addition to its effect/frontier
    /// checks. A reader predicate never substitutes for that genuine live check.
    ///
    /// # Errors
    /// Refuses inconsistent data, a failed model or an incomplete retained grant.
    pub(crate) fn authenticate_settled_adoption_eligibility_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.authenticate_current_data()?;
        match &self.state {
            CurrentModel::Producer(state) => {
                if state.failed || state.grants.values().any(|grant| !grant.complete) {
                    return Err(invalid());
                }
                Ok(())
            }
            CurrentModel::Reactive(state) => state.authenticate_settled_adoption_eligibility_data(),
        }
    }

    /// Compares one actual retained native proof with this exact typed model.
    /// The enclosing graph supplies and independently authenticates the original
    /// and captured PID; neither is promoted to permission by this comparison.
    ///
    /// # Errors
    /// Refuses another original, PID, model kind, grant or current inventory.
    pub(crate) fn authenticate_record_data(
        &self,
        record: &crate::reference_packet::control::PacketNative5UnderlyingRecord,
        original: &crate::envelope::Envelope,
        expected_pid: U64,
        expectation: PacketModelRecordExpectation,
    ) -> Result<(), ProviderError> {
        use crate::reference_packet::control::PacketNative5UnderlyingRecord;
        self.authenticate_current_data()?;
        original.validate()?;
        match (&self.state, record) {
            (CurrentModel::Producer(state), PacketNative5UnderlyingRecord::Producer(record)) => {
                if record.schema != "source-owned.packet-native/2"
                    || record.native_pid != expected_pid
                    || &record.original != original
                {
                    return Err(invalid());
                }
                match expectation {
                    PacketModelRecordExpectation::CompletedGrant => {
                        let grant = record.grant.as_ref().ok_or_else(invalid)?;
                        super::record_history::authenticate_grant_request(
                            original,
                            &grant.operation,
                            grant.start,
                            grant.limit,
                        )?;
                        if !grant.complete
                            || state.grants.get(&grant.operation) != Some(grant)
                            || record.inventory != grant.inventory
                        {
                            return Err(invalid());
                        }
                    }
                    PacketModelRecordExpectation::FinalObservation => {
                        let inventory = &record.inventory;
                        if original.method != crate::envelope::Method::Observe
                            || record.grant.is_some()
                            || inventory.reached != state.reached
                            || inventory.gate_closed != state.gate_closed
                            || inventory.pending.as_slice() != &state.events[state.next_event..]
                            || inventory.retained_outputs != state.outputs
                            || inventory.private_mutations != U64::new(state.private_mutations)
                            || inventory.packet_effects != U64::new(state.packet_effects)
                        {
                            return Err(invalid());
                        }
                        crate::bodies::decode_request(original.method, &original.body)?;
                    }
                }
                Ok(())
            }
            (CurrentModel::Reactive(state), PacketNative5UnderlyingRecord::Reactive(record)) => {
                state.authenticate_record_data(record, original, expected_pid, expectation)
            }
            _ => Err(invalid()),
        }
    }

    /// Borrows the exact complete current fields for later definition/proof joins.
    pub(crate) fn borrowed_current_data(&self) -> impl Serialize + '_ {
        CurrentModelView(self)
    }
}

impl PacketSettledModel17Data {
    /// Borrows the exact current program tuple, including its inert socket role.
    pub(crate) fn borrowed_program17_data(&self) -> impl Serialize + '_ {
        CurrentProgram17View(self)
    }
}

struct CurrentProgram17View<'a>(&'a PacketSettledModel17Data);
struct CurrentProgram17Body<'a>(&'a CurrentModel);

impl Serialize for CurrentProgram17View<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let kind = match &self.0.state {
            CurrentModel::Producer(_) => "producer",
            CurrentModel::Reactive(_) => "reactive",
        };
        (kind, CurrentProgram17Body(&self.0.state)).serialize(serializer)
    }
}

impl Serialize for CurrentProgram17Body<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        match self.0 {
            CurrentModel::Reactive(state) => state.serialize_program17_data(serializer),
            CurrentModel::Producer(state) => {
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
                } = state;
                let mut fields =
                    serializer.serialize_struct("InertCurrentProducerProgram17", 11)?;
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
    }
}

struct CurrentModelView<'a>(&'a PacketSettledModel17Data);
impl Serialize for CurrentModelView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0.state {
            CurrentModel::Producer(state) => state.serialize(serializer),
            CurrentModel::Reactive(state) => state.borrowed_current_data().serialize(serializer),
        }
    }
}

fn read_producer(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<ProducerState>, ProviderError> {
    read_producer_fields(input, ledger, build, true)
}

fn read_producer_fields(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    program: bool,
) -> Result<Option<ProducerState>, ProviderError> {
    let mut fields = Fields::object(input)?;
    if program && plain_string(fields.named("effect_socket_role")?)? != "model-effect-socket" {
        return Err(invalid());
    }
    let events = ledger.read::<Vec<PacketEvent>>(fields.named("events")?, build)?;
    let next_event = ledger.read::<usize>(fields.named("next_event")?, build)?;
    let reached = ledger.read::<Position>(fields.named("reached")?, build)?;
    let gate_closed = ledger.read::<bool>(fields.named("gate_closed")?, build)?;
    let outputs = ledger.read::<Vec<PacketPublication>>(fields.named("outputs")?, build)?;
    let grants = ledger.read::<BTreeMap<Id, PacketGrant>>(fields.named("grants")?, build)?;
    let private_mutations = ledger.read::<u64>(fields.named("private_mutations")?, build)?;
    let packet_effects = ledger.read::<u64>(fields.named("packet_effects")?, build)?;
    let retired = ledger.read::<BTreeMap<Id, Vec<Id>>>(fields.named("retired")?, build)?;
    let failed = ledger.read::<bool>(fields.named("failed")?, build)?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(ProducerState {
        events: events.ok_or_else(invalid)?,
        next_event: next_event.ok_or_else(invalid)?,
        reached: reached.ok_or_else(invalid)?,
        gate_closed: gate_closed.ok_or_else(invalid)?,
        outputs: outputs.ok_or_else(invalid)?,
        grants: grants.ok_or_else(invalid)?,
        private_mutations: private_mutations.ok_or_else(invalid)?,
        packet_effects: packet_effects.ok_or_else(invalid)?,
        retired: retired.ok_or_else(invalid)?,
        failed: failed.ok_or_else(invalid)?,
    }))
}

fn authenticate_producer(state: &ProducerState) -> Result<(), ProviderError> {
    state.reached.validate()?;
    super::super::validate_packet_program_definition(&state.events)?;
    if state.next_event > state.events.len()
        || state.grants.len() > MAXIMUM_OPERATIONS
        || state.retired.len() > state.grants.len()
        || state.outputs.len() > MAXIMUM_EVENTS
        || state
            .grants
            .iter()
            .any(|(id, grant)| id != &grant.operation)
        || state
            .retired
            .keys()
            .any(|id| !state.grants.contains_key(id))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Names the fixed current-model parser, typed result and direct child views.
pub(crate) fn settled_model17_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<CurrentProgram17View<'static>>()
        + size_of::<CurrentProgram17Body<'static>>()
        + size_of::<PacketSettledModel17Data>()
        + size_of::<CurrentModel>()
        + size_of::<ProducerState>()
        + size_of::<CurrentModelView<'static>>()
        + size_of::<Fields<'static>>()
        + size_of::<&mut Ledger<'static, 'static, 'static>>()
        + 3 * size_of::<&[u8]>()
        + size_of::<&str>()
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<Result<Fields<'static>, ProviderError>>()
        + size_of::<Option<&[u8]>>()
        + size_of::<Result<Option<&[u8]>, ProviderError>>()
        + size_of::<Option<PacketSettledModel17Data>>()
        + size_of::<Result<Option<PacketSettledModel17Data>, ProviderError>>()
        + size_of::<Option<ProducerState>>()
        + size_of::<Result<Option<ProducerState>, ProviderError>>()
        + size_of::<&crate::envelope::Envelope>()
        + size_of::<&crate::reference_packet::control::PacketNative5UnderlyingRecord>()
        + size_of::<&PacketGrant>()
        + size_of::<Option<&PacketGrant>>()
        + size_of::<PacketModelRecordExpectation>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<crate::retained_metadata::MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<&mut crate::retained_metadata::MetadataObserver<'static>>()
        + size_of::<&crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + 3 * size_of::<usize>()
        + vocabulary::counter_scratch_data()
        + super::super::connected::continuation::settled_reader::counter_scratch_data()
        + crate::protocol_snapshot::owned11::typed::historical_bytes_counter_scratch_data()
        + size_of::<Option<Vec<PacketEvent>>>()
        + size_of::<Result<Option<Vec<PacketEvent>>, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<Option<usize>, ProviderError>>()
        + size_of::<Option<Position>>()
        + size_of::<Result<Option<Position>, ProviderError>>()
        + size_of::<Option<bool>>()
        + size_of::<Result<Option<bool>, ProviderError>>()
        + size_of::<Option<Vec<PacketPublication>>>()
        + size_of::<Result<Option<Vec<PacketPublication>>, ProviderError>>()
        + size_of::<Option<BTreeMap<Id, PacketGrant>>>()
        + size_of::<Result<Option<BTreeMap<Id, PacketGrant>>, ProviderError>>()
        + size_of::<Option<u64>>()
        + size_of::<Result<Option<u64>, ProviderError>>()
        + size_of::<Option<u64>>()
        + size_of::<Result<Option<u64>, ProviderError>>()
        + size_of::<Option<BTreeMap<Id, Vec<Id>>>>()
        + size_of::<Result<Option<BTreeMap<Id, Vec<Id>>>, ProviderError>>()
        + size_of::<Option<bool>>()
        + size_of::<Result<Option<bool>, ProviderError>>()
}

// crucible-lint: allow panic-shortcut -- inert model history controls assert actual typed data.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual paired model writer and strict reader observations"
)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::retained_metadata::{
        MetadataObserver,
        records::{MetadataRecordBank, ValidatedMetadataRecords},
    };

    fn original() -> PacketProgram {
        let (effect, _peer) = UnixDatagram::pair().unwrap();
        let mut payload = Vec::with_capacity(31);
        payload.extend_from_slice(b"current payload");
        PacketProgram::new(
            vec![PacketEvent {
                id: Id::new("strict-current-model-event").unwrap(),
                evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(5), U64::new(0), Phase::Publication),
                payload: Some(Bytes::new(payload)),
            }],
            effect,
        )
        .unwrap()
    }

    fn limits() -> HistoricalJsonLimits {
        HistoricalJsonLimits {
            maximum_input_bytes: 65_536,
            maximum_nodes: 8192,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 64 * 1024 * 1024,
            maximum_tree_entries: 4096,
        }
    }

    #[test]
    fn defining_current_writer_roundtrips_nonempty_payload_and_spare_capacity() {
        let actual = original();
        let input =
            serde_json::to_vec(&("producer", actual.borrowed_settled_model_data())).unwrap();
        let mut bank = MetadataRecordBank::reserve(256).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        observer.observe(&actual).unwrap();
        let facts = observer.finish();
        let encoded_rows = serde_json::to_vec(&bank).unwrap();
        let rows = ValidatedMetadataRecords::validate(
            &encoded_rows,
            facts.capacity_records,
            64 * 1024 * 1024,
        )
        .unwrap();

        let mut preflight = Ledger::new(rows.rows(), limits());
        assert!(
            read_settled_model17_data(&input, &mut preflight, false)
                .unwrap()
                .is_none()
        );
        assert!(preflight.rows.next().is_none());
        let mut reconstruction = Ledger::new(rows.rows(), limits());
        let decoded = read_settled_model17_data(&input, &mut reconstruction, true)
            .unwrap()
            .unwrap();
        assert!(reconstruction.rows.next().is_none());
        decoded.authenticate_current_data().unwrap();
        let backing = decoded.retained_requested_storage_data(usize::MAX).unwrap();
        assert_eq!(
            decoded.retained_requested_storage_data(backing).unwrap(),
            backing
        );
        assert!(
            decoded
                .retained_requested_storage_data(backing - 1)
                .is_err()
        );

        let CurrentModel::Producer(state) = &decoded.state else {
            panic!("expected actual producer data");
        };
        assert_eq!(state.events, actual.events);
        assert_eq!(state.events.capacity(), actual.events.capacity());
        assert_eq!(state.outputs.capacity(), actual.outputs.capacity());
        let captured_payload = state.events[0].payload.as_ref().unwrap();
        assert_eq!(
            captured_payload.allocation_capacity(),
            actual.events[0]
                .payload
                .as_ref()
                .unwrap()
                .allocation_capacity()
        );
        assert_eq!(decoded.kind_data(), PacketModelKind::Producer);
        assert_eq!(decoded.current_position_data(), actual.reached);
    }

    #[test]
    fn short_bank_and_unknown_role_refuse_before_build_but_failed_typed_data_remains() {
        let mut actual = original();
        let input =
            serde_json::to_vec(&("producer", actual.borrowed_settled_model_data())).unwrap();
        let empty = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
        let mut short = Ledger::new(empty.rows(), limits());
        assert!(read_settled_model17_data(&input, &mut short, false).is_err());
        let mut unknown = Ledger::new(empty.rows(), limits());
        assert!(read_settled_model17_data(br#"["unknown",{}]"#, &mut unknown, false).is_err());
        let wrong_role = input
            .windows(b"model-effect-socket".len())
            .position(|bytes| bytes == b"model-effect-socket")
            .unwrap();
        let mut changed = input.clone();
        changed[wrong_role] = b'x';
        let mut wrong = Ledger::new(empty.rows(), limits());
        assert!(read_settled_model17_data(&changed, &mut wrong, false).is_err());

        actual.failed = true;
        let failed =
            serde_json::to_vec(&("producer", actual.borrowed_settled_model_data())).unwrap();
        let mut bank = MetadataRecordBank::reserve(256).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        observer.observe(&actual).unwrap();
        let facts = observer.finish();
        let encoded_rows = serde_json::to_vec(&bank).unwrap();
        let rows = ValidatedMetadataRecords::validate(
            &encoded_rows,
            facts.capacity_records,
            64 * 1024 * 1024,
        )
        .unwrap();
        let mut reconstruction = Ledger::new(rows.rows(), limits());
        let retained = Some(
            read_settled_model17_data(&failed, &mut reconstruction, true)
                .unwrap()
                .unwrap(),
        );
        retained
            .as_ref()
            .unwrap()
            .authenticate_current_data()
            .unwrap();
        assert!(
            retained
                .as_ref()
                .unwrap()
                .authenticate_settled_adoption_eligibility_data()
                .is_err()
        );
        let CurrentModel::Producer(state) = &retained.as_ref().unwrap().state else {
            panic!("expected failed inert producer");
        };
        assert!(state.failed);
        assert_eq!(state.events, actual.events);
    }

    #[test]
    fn incomplete_current_grant_roundtrips_as_data_but_cannot_enter_settled_route() {
        let mut actual = original();
        let operation = Id::new("inert-incomplete-current-grant").unwrap();
        let inventory = actual.inventory();
        // An inert retained-unknown field fixture creates no execution grant.
        actual.grants.insert(
            operation.clone(),
            PacketGrant {
                operation: operation.clone(),
                start: actual.reached,
                limit: Position::new(U64::new(6), U64::new(0), Phase::BoundaryControl),
                inventory,
                newborn: Vec::new(),
                complete: false,
            },
        );
        let input =
            serde_json::to_vec(&("producer", actual.borrowed_settled_model_data())).unwrap();
        let mut bank = MetadataRecordBank::reserve(512).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        observer.observe(&actual).unwrap();
        let facts = observer.finish();
        let encoded_rows = serde_json::to_vec(&bank).unwrap();
        let rows = ValidatedMetadataRecords::validate(
            &encoded_rows,
            facts.capacity_records,
            64 * 1024 * 1024,
        )
        .unwrap();

        let mut preflight = Ledger::new(rows.rows(), limits());
        assert!(
            read_settled_model17_data(&input, &mut preflight, false)
                .unwrap()
                .is_none()
        );
        assert!(preflight.rows.next().is_none());
        let mut build = Ledger::new(rows.rows(), limits());
        let retained = Some(
            read_settled_model17_data(&input, &mut build, true)
                .unwrap()
                .unwrap(),
        );
        assert!(build.rows.next().is_none());
        retained
            .as_ref()
            .unwrap()
            .authenticate_current_data()
            .unwrap();
        assert!(
            retained
                .as_ref()
                .unwrap()
                .authenticate_settled_adoption_eligibility_data()
                .is_err()
        );
        let CurrentModel::Producer(state) = &retained.as_ref().unwrap().state else {
            panic!("expected actual inert producer fields");
        };
        assert_eq!(state.grants.get(&operation), actual.grants.get(&operation));
        assert!(!state.grants[&operation].complete);
        assert_eq!(state.events, actual.events);
    }
}

// The new17 owning path keeps typed children in the outer attempt on errors.
#[path = "settled_reader/retained.rs"]
pub(in crate::reference_packet) mod retained;

#[path = "settled_reader/output_pair17.rs"]
mod output_pair17;
