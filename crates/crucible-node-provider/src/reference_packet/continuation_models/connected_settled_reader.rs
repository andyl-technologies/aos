//! Reads current reactive state without creating a live actor or input authority.

use super::*;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, historical_struct, invalid, plain_string,
};

pub(in crate::reference_packet) struct ReactiveModel17Data(ConnectedState);

#[path = "connected_settled_reader/prepared.rs"]
pub(in crate::reference_packet) mod prepared;

historical_struct!(OriginalStage {
    record: PacketStageRecord,
    record_ref: ContentRef,
    reply: PacketInputReply,
    commit: Option<OriginalCommit>,
});

historical_struct!(OriginalCommit {
    record: PacketCommitRecord,
    record_ref: ContentRef,
    reply: PacketInputReply,
});

impl ReactiveModel17Data {
    /// Reads every defining reactive field with the caller's unchanged ledger.
    ///
    /// # Errors
    /// Refuses malformed fields/role, mismatched rows or insufficient backing.
    pub(in crate::reference_packet) fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_fields(input, ledger, build, true)
    }

    pub(in crate::reference_packet) fn read_fields(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
        program: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let definition =
            ledger.read::<PacketConnectedDefinition>(fields.named("definition")?, build)?;
        let native_pid = ledger.read::<u32>(fields.named("native_pid")?, build)?;
        let reached = ledger.read::<Position>(fields.named("reached")?, build)?;
        let gate_closed = ledger.read::<bool>(fields.named("gate_closed")?, build)?;
        let reactions = ledger.read::<Vec<PacketReaction>>(fields.named("reactions")?, build)?;
        let delivered_inputs =
            ledger.read::<Vec<PacketDeliveredInput>>(fields.named("delivered_inputs")?, build)?;
        let publications =
            ledger.read::<Vec<PacketPendingPublication>>(fields.named("publications")?, build)?;
        let outputs =
            ledger.read::<Vec<PacketConnectedPublication>>(fields.named("outputs")?, build)?;
        let stages = ledger.read::<Vec<OriginalStage>>(fields.named("stages")?, build)?;
        let grants =
            ledger.read::<BTreeMap<Id, PacketConnectedGrant>>(fields.named("grants")?, build)?;
        let retired = ledger.read::<BTreeMap<Id, Vec<Id>>>(fields.named("retired")?, build)?;
        let reactions_completed =
            ledger.read::<u64>(fields.named("reactions_completed")?, build)?;
        let packet_effects = ledger.read::<u64>(fields.named("packet_effects")?, build)?;
        let failed = ledger.read::<bool>(fields.named("failed")?, build)?;
        if program && plain_string(fields.named("effect_socket_role")?)? != "model-effect-socket" {
            return Err(invalid());
        }
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self(ConnectedState {
            definition: definition.ok_or_else(invalid)?,
            native_pid: native_pid.ok_or_else(invalid)?,
            reached: reached.ok_or_else(invalid)?,
            gate_closed: gate_closed.ok_or_else(invalid)?,
            reactions: reactions.ok_or_else(invalid)?,
            delivered_inputs: delivered_inputs.ok_or_else(invalid)?,
            publications: publications.ok_or_else(invalid)?,
            outputs: outputs.ok_or_else(invalid)?,
            stages: stages.ok_or_else(invalid)?,
            grants: grants.ok_or_else(invalid)?,
            retired: retired.ok_or_else(invalid)?,
            reactions_completed: reactions_completed.ok_or_else(invalid)?,
            packet_effects: packet_effects.ok_or_else(invalid)?,
            failed: failed.ok_or_else(invalid)?,
        })))
    }

    pub(in crate::reference_packet) fn current_position_data(&self) -> Position {
        self.0.reached
    }

    pub(in crate::reference_packet) fn borrowed_current_data(&self) -> impl Serialize + '_ {
        &self.0
    }

    /// Appends actual reactive typed fields without resetting the whole bank.
    ///
    /// # Errors
    /// Refuses the caller's remaining finite record/alias/traversal allowance.
    pub(in crate::reference_packet) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.0)
    }

    /// Checks inert local relationships without excluding failed logical state.
    ///
    /// # Errors
    /// Refuses invalid positions, definitions, namespaces or stage/reply content.
    pub(in crate::reference_packet) fn authenticate_current_data(
        &self,
    ) -> Result<(), ProviderError> {
        let state = &self.0;
        state.reached.validate()?;
        super::super::validate_connected_program_definition(&state.definition)?;
        if state.native_pid == 0
            || state.grants.len() > MAXIMUM_OPERATIONS
            || state.retired.len() > state.grants.len()
            || state.stages.len() > MAXIMUM_BATCHES
            || state.reactions.len() > MAXIMUM_EVENTS
            || state.delivered_inputs.len() > MAXIMUM_EVENTS
            || state.publications.len() > MAXIMUM_EVENTS
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
        for stage in &state.stages {
            verify_record(&stage.record_ref, &stage.record)?;
            verify_reply(&stage.reply)?;
            if let Some(commit) = &stage.commit {
                verify_record(&commit.record_ref, &commit.record)?;
                verify_reply(&commit.reply)?;
                if commit.record.staged_record != stage.record_ref
                    || commit.record.cut != stage.record.cut
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }

    /// Checks the additional settled route predicate without issuing adoption.
    ///
    /// # Errors
    /// Refuses inconsistent data, a failed model or an incomplete retained grant.
    pub(in crate::reference_packet) fn authenticate_settled_adoption_eligibility_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.authenticate_current_data()?;
        if self.0.failed || self.0.grants.values().any(|grant| !grant.complete) {
            return Err(invalid());
        }
        Ok(())
    }

    /// Compares the actual original proof with this retained current model.
    ///
    /// # Errors
    /// Refuses changed original/PID, grant, inventory or staged/committed roots.
    pub(in crate::reference_packet) fn authenticate_record_data(
        &self,
        record: &PacketConnectedNativeRecord,
        original: &crate::envelope::Envelope,
        expected_pid: U64,
        expectation: crate::reference_packet::continuation_models::PacketModelRecordExpectation,
    ) -> Result<(), ProviderError> {
        use crate::reference_packet::continuation_models::{
            PacketModelRecordExpectation, record_history::authenticate_grant_request,
        };
        let state = &self.0;
        if record.schema != "source-owned.packet-native/4"
            || record.native_pid != expected_pid
            || record.native_pid.get() != u64::from(state.native_pid)
            || &record.original != original
        {
            return Err(invalid());
        }
        match expectation {
            PacketModelRecordExpectation::CompletedGrant => {
                let grant = record.grant.as_ref().ok_or_else(invalid)?;
                authenticate_grant_request(original, &grant.operation, grant.start, grant.limit)?;
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
                    || inventory.reactions != state.reactions
                    || inventory.delivered_inputs != state.delivered_inputs
                    || inventory.publications != state.publications
                    || inventory.retained_outputs != state.outputs
                    || inventory.reactions_completed != U64::new(state.reactions_completed)
                    || inventory.packet_effects != U64::new(state.packet_effects)
                    || !inventory
                        .stages
                        .iter()
                        .eq(state.stages.iter().map(|stage| &stage.record_ref))
                    || !inventory
                        .commits
                        .iter()
                        .eq(state.stages.iter().filter_map(|stage| {
                            stage.commit.as_ref().map(|commit| &commit.record_ref)
                        }))
                {
                    return Err(invalid());
                }
                crate::bodies::decode_request(original.method, &original.body)?;
            }
        }
        Ok(())
    }
}

pub(in crate::reference_packet) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<ReactiveModel17Data>()
        + size_of::<ConnectedState>()
        + size_of::<Option<ReactiveModel17Data>>()
        + size_of::<Result<Option<ReactiveModel17Data>, ProviderError>>()
        + size_of::<&ConnectedState>()
        + size_of::<&PacketConnectedNativeRecord>()
        + size_of::<&PacketConnectedGrant>()
        + size_of::<Option<&PacketConnectedGrant>>()
        + size_of::<std::slice::Iter<'static, OriginalStage>>()
        + size_of::<Option<&OriginalStage>>()
        + size_of::<Option<&OriginalCommit>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Option<PacketConnectedDefinition>>()
        + size_of::<Result<Option<PacketConnectedDefinition>, ProviderError>>()
        + size_of::<Option<u32>>()
        + size_of::<Result<Option<u32>, ProviderError>>()
        + size_of::<Option<Position>>()
        + size_of::<Result<Option<Position>, ProviderError>>()
        + size_of::<Option<bool>>()
        + size_of::<Result<Option<bool>, ProviderError>>()
        + size_of::<Option<Vec<PacketReaction>>>()
        + size_of::<Result<Option<Vec<PacketReaction>>, ProviderError>>()
        + size_of::<Option<Vec<PacketDeliveredInput>>>()
        + size_of::<Result<Option<Vec<PacketDeliveredInput>>, ProviderError>>()
        + size_of::<Option<Vec<PacketPendingPublication>>>()
        + size_of::<Result<Option<Vec<PacketPendingPublication>>, ProviderError>>()
        + size_of::<Option<Vec<PacketConnectedPublication>>>()
        + size_of::<Result<Option<Vec<PacketConnectedPublication>>, ProviderError>>()
        + size_of::<Option<Vec<OriginalStage>>>()
        + size_of::<Result<Option<Vec<OriginalStage>>, ProviderError>>()
        + size_of::<Option<BTreeMap<Id, PacketConnectedGrant>>>()
        + size_of::<Result<Option<BTreeMap<Id, PacketConnectedGrant>>, ProviderError>>()
        + size_of::<Option<BTreeMap<Id, Vec<Id>>>>()
        + size_of::<Result<Option<BTreeMap<Id, Vec<Id>>>, ProviderError>>()
        + size_of::<Option<u64>>()
        + size_of::<Result<Option<u64>, ProviderError>>()
        + size_of::<Option<u64>>()
        + size_of::<Result<Option<u64>, ProviderError>>()
        + size_of::<Option<bool>>()
        + size_of::<Result<Option<bool>, ProviderError>>()
}

// crucible-lint: allow panic-shortcut -- inert reactive field roundtrip assertions.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual paired reactive writer and capacity observations"
)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::reference_packet::continuation_models::settled_reader::read_settled_model17_data;
    use crate::retained_metadata::{
        MetadataObserver,
        records::{MetadataRecordBank, ValidatedMetadataRecords},
    };

    #[test]
    fn paired_reactive_current_writer_preserves_inbox_payload_and_all_fields() {
        let (effect, _peer) = UnixDatagram::pair().unwrap();
        let endpoint = |node| Endpoint {
            node_id: Id::new(node).unwrap(),
            port_id: Id::new("packet-port").unwrap(),
            lane_id: Id::new("packet-lane").unwrap(),
        };
        let definition = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".to_owned(),
            connections: vec![PacketInputConnection {
                id: Id::new("logical-reader-connection").unwrap(),
                policy: canonical::content_ref(b"logical policy", "application/json").unwrap(),
                producer: endpoint("reader-producer"),
                consumer: endpoint("reader-reactive"),
                delay_ps: U64::new(0),
            }],
            output: None,
        };
        let mut actual = PacketConnectedProgram::new(definition, effect).unwrap();
        let mut payload = Vec::with_capacity(29);
        payload.extend_from_slice(b"inert inbox bytes");
        // This is a writer/reader DATA control, not a staged input authority.
        actual.reactions.push(PacketReaction {
            input_event: Id::new("logical-input-event").unwrap(),
            input_producer: Id::new("reader-producer").unwrap(),
            input_sequence: U64::new(0),
            stage_operation: Id::new("logical-stage").unwrap(),
            commit_request: Id::new("logical-commit").unwrap(),
            payload: Bytes::new(payload),
            parent: Position::new(U64::new(5), U64::new(0), Phase::Delivery),
            evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
        });
        let input =
            serde_json::to_vec(&("reactive", actual.borrowed_settled_model_data())).unwrap();
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
        let limits = HistoricalJsonLimits {
            maximum_input_bytes: 65_536,
            maximum_nodes: 8192,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 64 * 1024 * 1024,
            maximum_tree_entries: 4096,
        };

        let mut preflight = Ledger::new(rows.rows(), limits);
        assert!(
            read_settled_model17_data(&input, &mut preflight, false)
                .unwrap()
                .is_none()
        );
        assert!(preflight.rows.next().is_none());
        let mut build = Ledger::new(rows.rows(), limits);
        let decoded = ReactiveModel17Data::read_current(
            serde_json::to_vec(&actual.borrowed_settled_model_data())
                .unwrap()
                .as_slice(),
            &mut build,
            true,
        )
        .unwrap()
        .unwrap();
        assert!(build.rows.next().is_none());
        decoded.authenticate_current_data().unwrap();
        assert_eq!(decoded.0.definition, actual.definition);
        assert_eq!(decoded.0.reactions, actual.reactions);
        assert_eq!(decoded.0.reactions.capacity(), actual.reactions.capacity());
        assert_eq!(
            decoded.0.reactions[0].payload.allocation_capacity(),
            actual.reactions[0].payload.allocation_capacity()
        );
        assert_eq!(
            decoded.0.delivered_inputs.capacity(),
            actual.delivered_inputs.capacity()
        );
        assert_eq!(
            decoded.0.publications.capacity(),
            actual.publications.capacity()
        );
        assert_eq!(decoded.0.outputs.capacity(), actual.outputs.capacity());
        assert_eq!(decoded.0.stages.capacity(), actual.stages.capacity());
    }
}

// The new17 owning path keeps typed children in the outer attempt on errors.
#[path = "connected_settled_reader/retained.rs"]
pub(in crate::reference_packet) mod retained;

#[path = "connected_settled_reader/output_pair17.rs"]
mod output_pair17;
