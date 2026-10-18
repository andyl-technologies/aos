//! Checks a late omitted/null refusal after real earlier banks are owned.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};
use crucible_node_contract::Phase;

#[expect(
    clippy::unwrap_used,
    reason = "assertions construct the actual archived DATA fixture"
)]
mod controls {
    use super::*;
    fn record() -> ControlRecord {
        let (_, _, selection, _) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let mut bytes = Vec::with_capacity(53);
        bytes.extend_from_slice(b"actual-content");
        let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
        let mut content = Vec::with_capacity(7);
        content.push((reference, bytes));
        let mut originals = Vec::with_capacity(4);
        let response = Map::from_iter([(
            "partial".to_owned(),
            Value::String(String::with_capacity(29)),
        )]);
        let mut evidence = Vec::with_capacity(3);
        let mut evidence_bytes = Vec::with_capacity(31);
        evidence_bytes.extend_from_slice(b"proof");
        evidence.push((
            canonical::content_ref(&evidence_bytes, "application/octet-stream").unwrap(),
            evidence_bytes,
        ));
        originals.push(OriginalRecord {
            request: Id::new("old-request").unwrap(),
            identity: selection.world.clone(),
            response_body: response,
            evidence,
        });
        ControlRecord {
            schema: SCHEMA.to_owned(),
            captured_process: U64::new(42),
            administrative_cut: Position::new(U64::new(5), U64::new(0), Phase::BoundaryControl),
            local_cursor: Position::new(U64::new(4), U64::new(0), Phase::BoundaryControl),
            model: serde_json::json!({"failed":true}),
            control: ControlState {
                selection,
                originals,
                begins: BTreeMap::new(),
                begin_requests: BTreeMap::new(),
                content,
                content_bytes: 14,
                realized: true,
                admitted: false,
                staged: None,
                active: None,
                fenced: true,
                native_effect_attempted: true,
                immediate: false,
                current_operation: None,
                terminals: BTreeMap::new(),
                common_coordinator: None,
                world_coordinator: None,
                connected_coordinator: None,
                complete_coordinator: None,
                complete_storage: None,
                complete_capture_profile: None,
                complete_confirmation_selection: None,
                complete_ack_emitter_selection: None,
                complete_protocol_metadata_limits: None,
                complete_protocol_metadata_birth_facts: None,
                complete_restore_selection: None,
                complete_restore_input_emitter_selection: None,
                complete_capture_allocation_selection: None,
            },
        }
    }

    fn limits() -> HistoricalJsonLimits {
        HistoricalJsonLimits {
            maximum_input_bytes: 1024 * 1024,
            maximum_nodes: 65536,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 64 * 1024 * 1024,
            maximum_tree_entries: 16384,
        }
    }

    #[test]
    fn omitted_selection_null_error_keeps_prior_original_and_content_banks() {
        let actual = record();
        let input = serde_json::to_vec(&actual).unwrap();
        assert!(input.ends_with(b"}}"));
        let mut changed = input[..input.len() - 2].to_vec();
        changed.extend_from_slice(b",\"complete_restore_selection\":null}}");
        let mut bank = MetadataRecordBank::reserve(8192).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        actual
            .observe_settled_history_metadata_data(&mut observer)
            .unwrap();
        let facts = observer.finish();
        let encoded = serde_json::to_vec(&bank).unwrap();
        let rows = ValidatedMetadataRecords::validate(
            &encoded,
            facts.capacity_records,
            limits().maximum_owned_backing_bytes,
        )
        .unwrap();
        let mut ledger = Ledger::new(rows.rows(), limits());
        ledger
            .begin_native17_targets_data(limits().maximum_owned_backing_bytes)
            .unwrap();
        ledger.native17_target_embedded_root_data().unwrap();
        let mut attempt = PacketSettledControlRecord17ReadAttempt::default();
        assert!(
            PacketSettledControlRecord17Data::read_into_data(&changed, &mut ledger, &mut attempt)
                .is_err()
        );
        let state = attempt
            .record
            .fields
            .tail
            .tail
            .tail
            .tail
            .tail
            .head
            .child
            .child_data()
            .unwrap();
        let content = state
            .fields
            .tail
            .tail
            .tail
            .tail
            .head
            .output
            .as_ref()
            .unwrap();
        assert_eq!(content.capacity(), 7);
        assert_eq!(content[0].1.capacity(), 53);
        let pointer = content[0].1.as_ptr();
        let originals = state.fields.tail.head.output.as_ref().unwrap();
        assert_eq!(originals.capacity(), 4);
        assert_eq!(originals[0].evidence.capacity(), 3);
        assert_eq!(originals[0].evidence[0].1.capacity(), 31);
        let mut observer = MetadataObserver::new();
        PacketSettledControlRecord17Data::observe_attempt_data(&attempt, &mut observer).unwrap();
        let retained = observer.finish();
        let consumed = ledger.rows.encoded_position();
        assert!(
            PacketSettledControlRecord17Data::read_into_data(&input, &mut ledger, &mut attempt)
                .is_err()
        );
        assert_eq!(ledger.rows.encoded_position(), consumed);
        let state = attempt
            .record
            .fields
            .tail
            .tail
            .tail
            .tail
            .tail
            .head
            .child
            .child_data()
            .unwrap();
        assert_eq!(
            state
                .fields
                .tail
                .tail
                .tail
                .tail
                .head
                .output
                .as_ref()
                .unwrap()[0]
                .1
                .as_ptr(),
            pointer
        );
        let mut observer = MetadataObserver::new();
        PacketSettledControlRecord17Data::observe_attempt_data(&attempt, &mut observer).unwrap();
        assert_eq!(observer.finish(), retained);
    }
}
