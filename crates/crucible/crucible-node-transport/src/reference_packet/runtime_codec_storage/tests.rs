//! Measures real pinned Content backing and checks the independent quote boundary.

use super::*;
use serde::__private228::de::{Content, ContentRefDeserializer, ContentVisitor};
use serde::de::DeserializeSeed;
use serde_json::{Value, json};

#[test]
fn codec_quote_requires_the_whole_independent_row() {
    for frame in [1, 2, 43, 4096, 65_536] {
        let row = storage_data(frame, usize::MAX).unwrap();
        let requested = row[0].checked_add(row[1]).unwrap();

        assert_eq!(storage_data(frame, requested).unwrap(), row);
        assert!(storage_data(frame, requested - 1).is_err());
        assert_eq!(row[1], counter_scratch_data());
        assert!(row[0] > frame);
    }
    for frame in [0, 65_537, usize::MAX] {
        assert!(storage_data(frame, usize::MAX).is_err());
    }
}

#[test]
fn actual_content_buffers_fit_each_independently_priced_tag_level() {
    for length in [0, 1, 2, 3, 4, 7, 8, 31, 127, 1024, 2048] {
        let values = vec![json!({"": [0, "x"]}); length];
        let value = json!({"action": "input", "context": {"action": "stage", "cut": values}});
        let encoded = serde_json::to_vec(&value).unwrap();
        assert!(encoded.len() <= 65_536);
        let first = ContentVisitor::new().deserialize(&value).unwrap();
        let second = ContentVisitor::new()
            .deserialize(ContentRefDeserializer::<serde_json::Error>::new(&first))
            .unwrap();
        let each = buffered_forest_storage_data(
            encoded.len(),
            serde_decode_layout::content_pair_bytes_data(),
        )
        .unwrap();

        assert!(content_backing(&first) <= each, "first tag, {length}");
        assert!(content_backing(&second) <= each, "nested tag, {length}");
        assert!(content_backing(&first) + content_backing(&second) <= 2 * each);
    }
}

#[test]
fn closed_graph_prices_nested_envelopes_and_input_context_buffers() {
    use crate::envelope::Envelope;
    use crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreCommitRequest;
    use crate::reference_packet::service::restored_input_reactive17::PacketRestoredInputReactive17Artifact;
    use fields::CodecField;

    assert_eq!(fields::TAG_LEVELS, 2);
    assert_eq!(PacketRestoredInputReactive17Artifact::TAG_LEVELS, 2);
    assert!(PacketCompleteRestoreCommitRequest::controls() > Envelope::controls());
    assert!(fields::control_bytes() > PacketCompleteRestoreCommitRequest::controls());

    // This rejected prefix still reaches base64's three-byte output estimate
    // while its one-byte input String is live. Successful 43-byte digests alone
    // cannot establish the decoder's failed-prefix population.
    assert_eq!(base64::decoded_len_estimate(1), 3);
    assert!(serde_json::from_value::<crucible_node_format::Bytes>(json!("A")).is_err());
}

#[test]
fn validation_prices_actual_positional_prepare_and_nested_commit_serialization() {
    use crate::reference_packet::service::complete_restore::transfer::{
        PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION, PacketCompleteRestoreCommitRequest,
        PacketCompleteRestorePrepareRequest,
    };
    use crucible_node_format::{Bytes, Id};

    let prepare = prepare_request();
    let named = serde_json::to_value(&prepare).unwrap();
    let fields = [
        "schema",
        "restoration",
        "host_protocol",
        "native_protocol",
        "native_control",
        "native_anchor",
        "transaction_id",
        "generation",
        "allocation",
    ];
    let positional = Value::Array(fields.iter().map(|name| named[*name].clone()).collect());
    let frame = serde_json::to_vec(&positional).unwrap().len();
    let decoded: PacketCompleteRestorePrepareRequest = serde_json::from_value(positional).unwrap();

    decoded.validate_data().unwrap();
    assert!(serde_json::to_vec(&named).unwrap().len() > frame);
    assert_validation_window(&named, frame);

    for population in [0, 1, 31, 512] {
        let mut terminal = crate::envelope::tests::request();
        terminal.extensions.insert(
            "literal".into(),
            json!({"rows": vec![json!({"": [0, "text"]}); population]}),
        );
        let commit = PacketCompleteRestoreCommitRequest {
            schema: PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION.to_owned(),
            prepare: prepare_request(),
            capture_terminal: terminal,
            prepare_request_id: Id::new("prepare/1").unwrap(),
            prepare_request_sequence: 3.into(),
            prepare_request_digest: Bytes::new(vec![9; 32]),
            prepare_response_sequence: 4.into(),
            prepare_response_digest: Bytes::new(vec![10; 32]),
            transfer_token: Bytes::new(vec![11; 32]),
        };
        commit.validate_data().unwrap();

        let value = serde_json::to_value(&commit).unwrap();
        let frame = serde_json::to_vec(&value).unwrap().len();
        assert!(frame <= 65_536);
        assert_validation_window(&value, frame);
    }

    use fields::CodecField;
    assert_eq!(
        <[crucible_node_format::ContentRef; 2]>::NAME_BYTES,
        2 * crucible_node_format::ContentRef::NAME_BYTES,
    );
}

fn assert_validation_window(value: &Value, frame: usize) {
    use crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data;
    use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
    use crucible_node_format::canonical;

    let extent_bytes = validation::serialized_extent_data(frame).unwrap();
    let extent = original_json_value_storage_extent_data(extent_bytes).unwrap();
    let encoded = canonical::canonical_json(value).unwrap();
    let mut observer = MetadataObserver::new();
    observer.observe(value).unwrap();
    let backing = requested_metadata_backing_storage_data(&observer.finish()).unwrap();

    assert!(serde_json::to_vec(value).unwrap().len() <= extent_bytes);
    assert!(backing <= extent.value_dom_requested_bytes);
    assert!(encoded.capacity() <= extent.canonical_output_requested_bytes);
    assert!(validation::storage_data(frame).unwrap() >= backing + encoded.capacity());
}

fn prepare_request()
-> crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestorePrepareRequest
{
    use crate::reference_packet::service::complete_restore::{
        PACKET_COMPLETE_RESTORE_FEATURE, PacketCompleteRestoreRequest,
        complete_restore_request_schema,
        transfer::{
            PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION, PacketCompleteRestoreInputAllocation,
            PacketCompleteRestorePrepareRequest,
        },
    };
    use crucible_node_format::{Bytes, Id, Phase, Position, Tick, canonical};

    let reference = canonical::content_ref(b"{}", "application/json").unwrap();
    PacketCompleteRestorePrepareRequest {
        schema: PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION.to_owned(),
        restoration: PacketCompleteRestoreRequest {
            schema: PACKET_COMPLETE_RESTORE_FEATURE.to_owned(),
            archive_index: reference.clone(),
            capture_manifest: reference.clone(),
            owner_state: reference.clone(),
            journal: reference.clone(),
            source_runtime: reference.clone(),
            backend_implementation: reference.clone(),
            backend_schema: complete_restore_request_schema().unwrap(),
            archived_cut: Position::new(Tick::new(0), 0.into(), Phase::BoundaryControl),
            archived_ordinal: 0.into(),
            target_world: canonical::hash("cnp.world-binding.v1", b"fresh").unwrap(),
            target_owner: Id::new("owner/0").unwrap(),
            target_owner_binding: canonical::hash("cnp.owner-binding.v1", b"fresh").unwrap(),
            target_activation: Id::new("activation/fresh").unwrap(),
            target_generation: 1.into(),
            target_owner_generation: 1.into(),
            mapping: reference.clone(),
            nonce: Bytes::new(vec![1; 32]),
        },
        host_protocol: reference.clone(),
        native_protocol: reference.clone(),
        native_control: reference.clone(),
        native_anchor: reference,
        transaction_id: Id::new("restore/transaction").unwrap(),
        generation: 1.into(),
        allocation: PacketCompleteRestoreInputAllocation {
            maximum_known_requested_bytes: (64 * 1024 * 1024).into(),
            maximum_input_bytes: (8 * 1024 * 1024).into(),
            maximum_nodes: 65536.into(),
            maximum_depth: 32.into(),
            maximum_owned_backing_bytes: (8 * 1024 * 1024).into(),
            maximum_tree_entries: 4096.into(),
            maximum_metadata_rows: 16384.into(),
            maximum_literal_backing_bytes: (8 * 1024 * 1024).into(),
            maximum_content_transfers: 1024.into(),
            maximum_content_objects: 1024.into(),
            maximum_content_groups: 1024.into(),
            maximum_content_bytes: (8 * 1024 * 1024).into(),
            maximum_content_metadata_bytes: (1024 * 1024).into(),
            maximum_model_bytes: (1024 * 1024).into(),
        },
    }
}

fn content_backing(value: &Content<'_>) -> usize {
    match value {
        Content::String(value) => value.capacity(),
        Content::ByteBuf(value) => value.capacity(),
        Content::Some(value) | Content::Newtype(value) => {
            size_of::<Content<'_>>() + content_backing(value)
        }
        Content::Seq(values) => {
            values.capacity() * size_of::<Content<'_>>()
                + values.iter().map(content_backing).sum::<usize>()
        }
        Content::Map(values) => {
            values.capacity() * size_of::<(Content<'_>, Content<'_>)>()
                + values
                    .iter()
                    .map(|(key, value)| content_backing(key) + content_backing(value))
                    .sum::<usize>()
        }
        Content::Bool(_)
        | Content::U8(_)
        | Content::U16(_)
        | Content::U32(_)
        | Content::U64(_)
        | Content::I8(_)
        | Content::I16(_)
        | Content::I32(_)
        | Content::I64(_)
        | Content::F32(_)
        | Content::F64(_)
        | Content::Char(_)
        | Content::Str(_)
        | Content::Bytes(_)
        | Content::None
        | Content::Unit => 0,
    }
}
