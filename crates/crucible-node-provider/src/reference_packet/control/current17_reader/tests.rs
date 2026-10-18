//! Exercises the actual finite-model Control writer and strict inert reader.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::protocol_snapshot::restored_settled17::aliases::{
    RestoredSettledNative17AliasSummary, ValidatedRestoredSettledNative17Aliases,
};
use crate::retained_metadata::{
    aliases::MetadataAliasBank,
    records::{MetadataRecordBank, ValidatedMetadataRecords},
};

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 4 * 1024 * 1024,
        maximum_nodes: 131072,
        maximum_depth: 64,
        maximum_owned_backing_bytes: 64 * 1024 * 1024,
        maximum_tree_entries: 32768,
    }
}

// The existing complete constructors create the real private capture identity
// and finite producer/reactive model. Failed Control state is then retained as
// historical DATA; this fixture never constructs native restoration tokens.
fn actual_control(reactive: bool) -> PacketControl {
    let mut actual = super::super::native5::current_control17_fixture_data(reactive).unwrap();

    let mut payload = Vec::with_capacity(53);
    payload.extend_from_slice(b"actual-control-content");
    let reference = canonical::content_ref(&payload, "application/quoted\"type\\suffix").unwrap();
    let mut proof = Vec::with_capacity(31);
    proof.extend_from_slice(b"partial-evidence");
    let proof_ref = canonical::content_ref(&proof, "application/octet-stream").unwrap();
    let mut evidence = Vec::with_capacity(7);
    evidence.push((proof_ref, proof));
    let body = Map::from_iter([("unfinished".to_owned(), Value::Bool(true))]);
    let request_hash = canonical::json_hash("cnp.request.v1", &body).unwrap();
    let originals = BTreeMap::from([(
        Id::new("current-control17-original").unwrap(),
        (request_hash, PacketControlReply { body, evidence }),
    )]);

    actual.originals = originals;
    actual.content = BTreeMap::from([(reference, payload)]);
    actual.content_bytes = 22;
    actual.restoration_activation_required = true;
    actual.realized = true;
    actual.admitted = false;
    actual.fenced = true;
    actual.native_effect_attempted = true;
    actual.immediate = false;
    actual.current_operation = Some(Id::new("unfinished-operation").unwrap());
    actual.terminals = BTreeMap::from([(
        Id::new("unfinished-operation").unwrap(),
        Map::from_iter([(
            "partial".to_owned(),
            Value::String(String::with_capacity(29)),
        )]),
    )]);
    actual
}

struct Captured {
    input: Vec<u8>,
    capacities: Vec<u8>,
    aliases: Vec<u8>,
}

fn capture(actual: &PacketControl) -> Captured {
    let input =
        serde_json::to_vec(&actual.borrowed_restored_settled_history_data().unwrap()).unwrap();
    let mut records = MetadataRecordBank::reserve(16384).unwrap();
    let mut aliases = MetadataAliasBank::reserve(1024).unwrap();
    let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
    actual
        .observe_settled17_root_hold_metadata_data(&mut observer)
        .unwrap();
    actual
        .observe_restored_settled_history_metadata_data(&mut observer)
        .unwrap();
    let _ = observer.finish();
    Captured {
        input,
        capacities: serde_json::to_vec(&records).unwrap(),
        aliases: serde_json::to_vec(&aliases).unwrap(),
    }
}

fn read(captured: &Captured, build: bool) -> Result<Option<CurrentControl17Data>, ProviderError> {
    let records =
        ValidatedMetadataRecords::validate(&captured.capacities, 16384, 64 * 1024 * 1024)?;
    let mut summaries = vec![RestoredSettledNative17AliasSummary::default(); 1024];
    let mut aliases =
        ValidatedRestoredSettledNative17Aliases::validate(&captured.aliases, &mut summaries, 1024)?;
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
    ledger.native17_target_inline_root_data::<CurrentControl17Data>()?;
    ledger.settled_aliases = Some(aliases.views()?);
    let group =
        read_current_control_identity17_data(br#""current-native-control-identity""#, &mut ledger)?;
    let result = ledger.read::<CurrentControl17Data>(&captured.input, build)?;
    if ledger.rows.next().is_some() {
        return Err(invalid());
    }
    ledger.finish_aliases()?;
    ledger.finish_native17_targets_data()?;
    if let Some(data) = &result {
        assert_eq!(data.capture_identity_group_data(), group);
    }
    Ok(result)
}

#[test]
fn actual_producer_and_reactive_writers_roundtrip_every_control_field_and_spare() {
    for reactive in [false, true] {
        let actual = actual_control(reactive);
        let captured = capture(&actual);
        assert!(read(&captured, false).unwrap().is_none());
        let data = read(&captured, true).unwrap().unwrap();
        assert_eq!(serde_json::to_vec(&data).unwrap(), captured.input);
        data.authenticate_local_groups_data().unwrap();
        assert!(data.fenced && data.native_effect_attempted && !data.admitted);
        assert!(data.restoration_activation_required);
        assert_eq!(data.originals.0.len(), 1);
        assert_eq!(
            data.originals
                .0
                .values()
                .next()
                .unwrap()
                .1
                .evidence
                .capacity(),
            7
        );
        assert_eq!(
            data.originals.0.values().next().unwrap().1.evidence[0]
                .1
                .capacity(),
            31
        );
        assert_eq!(data.content.0.values().next().unwrap().capacity(), 53);
        assert_eq!(
            data.terminals.values().next().unwrap()["partial"]
                .as_str()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            data.model_data().unwrap().kind_data(),
            if reactive {
                crate::reference_packet::continuation_models::PacketModelKind::Reactive
            } else {
                crate::reference_packet::continuation_models::PacketModelKind::Producer
            }
        );
    }
}

#[test]
fn raw_schema_order_roles_and_missing_fields_are_not_normalized() {
    let captured = capture(&actual_control(false));
    let text = std::str::from_utf8(&captured.input).unwrap();
    for changed in [
        text.replace(CONTROL_SCHEMA, "source-owned.packet-native-control/11"),
        text.replace(
            "current-native-control-identity",
            "portable-native-control-identity",
        ),
        text.replace("\"complete_restored_evidence\":null,", ""),
        text.replace(
            "\"complete_restored_evidence\":null,\"complete_restored_hold\":null",
            "\"complete_restored_hold\":null,\"complete_restored_evidence\":null",
        ),
        text.replace("\"model-effect-socket\"", "\"live-socket\""),
    ] {
        assert_ne!(changed.as_bytes(), captured.input);
        let altered = Captured {
            input: changed.into_bytes(),
            capacities: captured.capacities.clone(),
            aliases: captured.aliases.clone(),
        };
        assert!(read(&altered, false).is_err());
    }
}

#[test]
fn source_tree_rows_are_required_and_short_rows_cannot_be_replayed() {
    let actual = actual_control(false);
    let captured = capture(&actual);
    let mut rows: Vec<Value> = serde_json::from_slice(&captured.capacities).unwrap();
    rows.pop().unwrap();
    let short = Captured {
        input: captured.input.clone(),
        capacities: serde_json::to_vec(&rows).unwrap(),
        aliases: captured.aliases.clone(),
    };
    assert!(read(&short, false).is_err());

    let mut rows: Vec<Value> = serde_json::from_slice(&captured.capacities).unwrap();
    let original_layout = size_of::<Id>() + size_of::<(HashRef, PacketControlReply)>();
    let row = rows
        .iter_mut()
        .find(|row| row[0] == "tree" && row[1] == 1 && row[2] == original_layout)
        .unwrap();
    row[0] = Value::String("vector".to_owned());
    let substituted = Captured {
        input: captured.input,
        capacities: serde_json::to_vec(&rows).unwrap(),
        aliases: captured.aliases,
    };
    assert!(read(&substituted, false).is_err());
}

#[test]
fn restoration_in_progress_preserves_a_real_partial_control_without_model() {
    let mut actual = actual_control(false);
    actual.program = NativeProgram::RestorationInProgress;
    let captured = capture(&actual);
    let data = read(&captured, true).unwrap().unwrap();
    assert!(data.model_data().is_none());
    assert_eq!(serde_json::to_vec(&data).unwrap(), captured.input);
}

#[test]
fn escaped_content_order_and_duplicate_keys_refuse_without_temporary_owners() {
    let mut actual = actual_control(false);
    let mut second = actual.content.keys().next().unwrap().clone();
    second.media_type.push('z');
    actual.content.insert(second, Vec::with_capacity(17));
    let captured = capture(&actual);
    let _ = read(&captured, true).unwrap().unwrap();
    let mut fields = Fields::object(&captured.input).unwrap();
    let mut content_bytes = None;
    while let Some((name, value)) = fields.pair().unwrap() {
        if plain_string(name).unwrap() == "content" {
            content_bytes = Some(value);
        }
    }
    let content_bytes = content_bytes.unwrap();
    let mut rows = Fields::array(content_bytes).unwrap();
    let first = std::str::from_utf8(rows.next().unwrap().unwrap()).unwrap();
    let second = std::str::from_utf8(rows.next().unwrap().unwrap()).unwrap();
    rows.finish().unwrap();
    for changed_content in [format!("[{second},{first}]"), format!("[{first},{first}]")] {
        let changed = std::str::from_utf8(&captured.input).unwrap().replace(
            std::str::from_utf8(content_bytes).unwrap(),
            &changed_content,
        );
        assert_ne!(changed.as_bytes(), captured.input);
        let altered = Captured {
            input: changed.into_bytes(),
            capacities: captured.capacities.clone(),
            aliases: captured.aliases.clone(),
        };
        assert!(read(&altered, false).is_err());
    }
}
