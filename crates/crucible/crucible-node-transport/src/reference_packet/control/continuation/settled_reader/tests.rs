//! Exercises actual raw ControlRecord serialization and the shared capacity reader.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};
use crucible_node_format::Phase;

// crucible-lint: allow panic-shortcut -- inert fixture decoding and assertions are test observations.
#[expect(
    clippy::unwrap_used,
    reason = "bounded historical DATA fixture assertions"
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
            maximum_nodes: 32768,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 64 * 1024 * 1024,
            maximum_tree_entries: 16384,
        }
    }

    fn roundtrip(actual: &ControlRecord) -> PacketSettledControlRecord17Data {
        let input = serde_json::to_vec(actual).unwrap();
        let mut bank = MetadataRecordBank::reserve(8192).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        actual
            .observe_settled_history_metadata_data(&mut observer)
            .unwrap();
        let facts = observer.finish();
        let encoded = serde_json::to_vec(&bank).unwrap();
        let rows =
            ValidatedMetadataRecords::validate(&encoded, facts.capacity_records, 64 * 1024 * 1024)
                .unwrap();
        let mut passive = Ledger::new(rows.rows(), limits());
        assert!(
            passive
                .read::<PacketSettledControlRecord17Data>(&input, false)
                .unwrap()
                .is_none()
        );
        assert!(passive.rows.next().is_none());
        let mut building = Ledger::new(rows.rows(), limits());
        let owner = building
            .read::<PacketSettledControlRecord17Data>(&input, true)
            .unwrap()
            .unwrap();
        assert!(building.rows.next().is_none());
        assert_eq!(serde_json::to_vec(&owner).unwrap(), input);
        owner
    }

    #[test]
    fn actual_failed_record_roundtrips_nonempty_independent_banks_and_spares() {
        let actual = record();
        let cold = roundtrip(&actual);
        assert!(cold.0.control.fenced && cold.0.control.native_effect_attempted);
        assert!(!cold.0.control.admitted);
        assert_eq!(
            cold.0.control.content.capacity(),
            actual.control.content.capacity()
        );
        assert_eq!(cold.0.control.content[0].1.capacity(), 53);
        assert_eq!(cold.0.control.originals.capacity(), 4);
        assert_eq!(cold.0.control.originals[0].evidence.capacity(), 3);
        assert_eq!(cold.0.control.originals[0].evidence[0].1.capacity(), 31);
    }

    #[test]
    fn actual_allocation_edition_preserves_optional_selection_and_rejects_null() {
        let mut actual = record();
        actual.schema = CAPTURE_ALLOCATION_SCHEMA.to_owned();
        actual.control.complete_capture_allocation_selection =
            Some(PacketNative5CaptureAllocationSelection::OriginalObserve12);
        actual.control.complete_restore_selection =
            Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12);
        actual.control.complete_restore_input_emitter_selection =
            Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12);
        let _ = roundtrip(&actual);
        let bytes = serde_json::to_vec(&actual).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let explicit_null = text.replace(
            "\"complete_restore_selection\":\"SourceSignedTransfer12\"",
            "\"complete_restore_selection\":null",
        );
        assert_ne!(explicit_null, text);
        let mut bank = MetadataRecordBank::reserve(8192).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        actual
            .observe_settled_history_metadata_data(&mut observer)
            .unwrap();
        let facts = observer.finish();
        let encoded = serde_json::to_vec(&bank).unwrap();
        let rows =
            ValidatedMetadataRecords::validate(&encoded, facts.capacity_records, 64 * 1024 * 1024)
                .unwrap();
        let mut ledger = Ledger::new(rows.rows(), limits());
        assert!(
            ledger
                .read::<PacketSettledControlRecord17Data>(explicit_null.as_bytes(), false)
                .is_err()
        );
        actual.schema = SCHEMA.to_owned();
        let mut ledger = Ledger::new(rows.rows(), limits());
        assert!(
            ledger
                .read::<PacketSettledControlRecord17Data>(
                    &serde_json::to_vec(&actual).unwrap(),
                    false
                )
                .is_err()
        );
    }

    #[test]
    fn absent_capacity_rows_refuse_without_creating_a_control_owner() {
        let actual = record();
        let input = serde_json::to_vec(&actual).unwrap();
        let empty = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
        let mut ledger = Ledger::new(empty.rows(), limits());
        assert!(
            ledger
                .read::<PacketSettledControlRecord17Data>(&input, true)
                .is_err()
        );
        assert_eq!(actual.control.content[0].1.as_slice(), b"actual-content");
    }
}
