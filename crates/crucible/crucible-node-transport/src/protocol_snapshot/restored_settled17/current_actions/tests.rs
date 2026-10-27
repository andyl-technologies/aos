//! Checks reconstruction boundaries against the actual raw-first action writer.

use super::*;
use crate::{
    envelope::{Method, Nullable},
    protocol_snapshot::owned11::json_value::HistoricalJsonLimits,
    reference_packet::service::{
        native_startup::NativeRestoredSettledActionAttempt,
        restored_settled_capture::RESTORED_SETTLED_CAPTURE_FEATURE,
    },
    retained_metadata::{
        MetadataObserver,
        records::{MetadataRecordBank, ValidatedMetadataRecords},
    },
};
use crucible_node_format::Id;

fn original_capture(method: Method) -> Result<Envelope, Box<dyn std::error::Error>> {
    let mut original = crate::envelope::tests::request();
    original.method = method;
    original.node_id = Nullable(Some(Id::new("current-action-node")?));
    original.operation_id = Nullable(None);
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(Some(Id::new("current-action-capture")?));
    original.extensions.clear();
    let feature = if method == Method::Begin {
        RESTORED_SETTLED_CAPTURE_FEATURE
    } else {
        RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE
    };
    original.extensions.insert(feature.into(), Value::Null);
    Ok(original)
}

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 65_536,
        maximum_nodes: 8192,
        maximum_depth: 32,
        maximum_owned_backing_bytes: 2 * 1024 * 1024,
        maximum_tree_entries: 8192,
    }
}

fn recorded(
    attempt: &NativeRestoredSettledActionAttempt,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let input = serde_json::to_vec(attempt)?;
    let mut rows = MetadataRecordBank::reserve(8192)?;
    let mut observer = MetadataObserver::recording(&mut rows);
    attempt.observe_settled_history_metadata_data(&mut observer)?;
    observer.finish();
    Ok((input, serde_json::to_vec(&rows)?))
}

#[test]
fn actual_input_raw_and_failed_prefixes_reconstruct_with_complete_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    // Preserve the accepted raw roster while making a typed field fail. The
    // fixture's proof is DATA here; no Source authentication is performed.
    let mut raw =
        crate::reference_packet::service::restored_input_reactive17::tests::sealed_fixture(
            &[73; 32],
        )?;
    raw.body
        .insert("owner_generation".into(), Value::Bool(false));
    let mut attempt = NativeRestoredSettledActionAttempt::new_data(7);
    attempt.retain_original_data(raw.clone())?;

    for failed in [false, true] {
        if failed {
            assert!(attempt.decode_body_data(65_536).is_err());
        }
        let (input, rows) = recorded(&attempt)?;
        let records = ValidatedMetadataRecords::validate(&rows, 8192, 2 * 1024 * 1024)?;
        let mut borrowed = Ledger::new(records.rows(), limits());
        assert!(
            borrowed
                .read::<HistoricalRestoredAction17>(&input, false)?
                .is_none()
        );
        assert!(borrowed.rows.next().is_none());

        let mut owning = Ledger::new(records.rows(), limits());
        let restored = owning
            .read::<HistoricalRestoredAction17>(&input, true)?
            .ok_or_else(invalid)?;
        let selected = restored.selected.ok_or_else(invalid)?;

        assert_eq!(restored.ordinal, 7);
        assert!(restored.original.is_none());
        assert!(!restored.decoded);
        assert_eq!(restored.failed, failed);
        assert_eq!(selected.input_reactive.ordinal, 7);
        assert_eq!(selected.input_reactive.original.as_ref(), Some(&raw));
        assert!(selected.input_reactive.body.is_none());
        assert!(selected.input_reactive.arguments.is_none());
        assert!(selected.input_reactive.artifact.is_none());
        assert!(selected.input_reactive.context.is_none());
        assert!(selected.input_reactive.checkpoint.is_none());
        assert!(selected.input_reactive.terminal.is_none());
        assert!(selected.input_reactive.prepared_reply.is_none());
        assert!(selected.input_reactive.observation.is_none());
        assert!(matches!(
            (selected.input_reactive.stage, failed),
            (CurrentAttemptStage17::Raw, false) | (CurrentAttemptStage17::Failed, true)
        ));
        assert!(owning.rows.next().is_none());
    }
    Ok(())
}

#[test]
fn actual_capture_and_upload_prefixes_preserve_existing_reader_restrictions()
-> Result<(), Box<dyn std::error::Error>> {
    for method in [
        Method::Begin,
        Method::BlobBegin,
        Method::BlobChunk,
        Method::BlobFinish,
    ] {
        let raw = original_capture(method)?;
        let mut attempt = NativeRestoredSettledActionAttempt::new_data(11);
        attempt.retain_original_data(raw.clone())?;

        for failed in [false, true] {
            if failed {
                assert!(attempt.decode_body_data(65_536).is_err());
            }
            assert_eq!(attempt.original_data()?, &raw);
            let (input, rows) = recorded(&attempt)?;
            let records = ValidatedMetadataRecords::validate(&rows, 8192, 2 * 1024 * 1024)?;
            let mut borrowed = Ledger::new(records.rows(), limits());
            assert!(
                borrowed
                    .read::<HistoricalRestoredAction17>(&input, false)?
                    .is_none()
            );
            assert!(borrowed.rows.next().is_none());

            let mut owning = Ledger::new(records.rows(), limits());
            assert!(
                owning
                    .read::<HistoricalRestoredAction17>(&input, true)
                    .is_err()
            );
        }
    }
    Ok(())
}

fn selected_capture_data(input: &[u8]) -> Result<&[u8], ProviderError> {
    let mut wrapper = Fields::object(input)?;
    wrapper.named("ordinal")?;
    wrapper.named("original")?;
    let selected = wrapper.named("selected")?;
    wrapper.named("decoded")?;
    wrapper.named("failed")?;
    wrapper.finish()?;

    let mut selected = Fields::object(selected)?;
    assert_eq!(plain_string(selected.named("family")?)?, "capture");
    let data = selected.named("data")?;
    selected.finish()?;
    Ok(data)
}

#[test]
fn actual_capture_prefixes_borrow_without_registration_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut attempt = NativeRestoredSettledActionAttempt::new_data(11);
    attempt.retain_original_data(original_capture(Method::Begin)?)?;

    for failed in [false, true] {
        if failed {
            assert!(attempt.decode_body_data(65_536).is_err());
        }
        let (input, rows) = recorded(&attempt)?;
        let records = ValidatedMetadataRecords::validate(&rows, 8192, 2 * 1024 * 1024)?;
        let mut historical = Ledger::new(records.rows(), limits());
        assert!(
            historical
                .read::<HistoricalRestoredAction17>(&input, false)?
                .is_none()
        );
        assert!(historical.rows.next().is_none());

        let mut owning = Ledger::new(records.rows(), limits());
        assert!(
            owning
                .read::<HistoricalRestoredAction17>(&input, true)
                .is_err()
        );

        // The actual writer now includes both absent slots. Reading that DATA
        // does not supply the registration required by archive authentication.
        let mut current = Ledger::new(records.rows(), limits());
        let borrowed =
            super::super::current_capture17_borrowed::read_current_capture17_borrowed_data(
                selected_capture_data(&input)?,
                &mut current,
            )?;
        assert!(borrowed.registration.is_none());
        assert!(current.rows.next().is_none());
    }
    Ok(())
}

#[test]
fn previous_full_capture_grammar_remains_independently_validated()
-> Result<(), Box<dyn std::error::Error>> {
    let mut attempt = NativeRestoredSettledActionAttempt::new_data(11);
    attempt.retain_original_data(original_capture(Method::Begin)?)?;
    let (input, rows) = recorded(&attempt)?;
    let data = selected_capture_data(&input)?;
    let records = ValidatedMetadataRecords::validate(&rows, 8192, 2 * 1024 * 1024)?;

    // The actual writer supplies the closed current roster. Removing its two
    // absent slots reproduces the previous history grammar without inventing
    // registration, a confirmation receipt or live Capture permission.
    let full = String::from_utf8(data.to_vec())?;
    let previous = full.replacen(",\"registration\":null", "", 1).replacen(
        ",\"confirmation_receipt\":null",
        "",
        1,
    );
    assert_ne!(full, previous);
    let mut previous_ledger = Ledger::new(records.rows(), limits());
    assert!(
        previous_ledger
            .read::<CurrentCaptureAttempt17>(previous.as_bytes(), false)?
            .is_none()
    );
    assert!(previous_ledger.rows.next().is_none());
    let mut historical = Ledger::new(records.rows(), limits());
    assert!(
        historical
            .read::<CurrentCaptureAttempt17>(full.as_bytes(), false)?
            .is_none()
    );
    assert!(historical.rows.next().is_none());

    let mut current = Ledger::new(records.rows(), limits());
    let borrowed = super::super::current_capture17_borrowed::read_current_capture17_borrowed_data(
        full.as_bytes(),
        &mut current,
    )?;
    assert!(borrowed.registration.is_none());
    assert!(current.rows.next().is_none());
    let mut owning = Ledger::new(records.rows(), limits());
    assert!(
        owning
            .read::<CurrentCaptureAttempt17>(full.as_bytes(), true)
            .is_err()
    );
    Ok(())
}

#[test]
fn ordinary_capture_history_requires_exact_fields_and_source_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let mut attempt = NativeRestoredSettledActionAttempt::new_data(11);
    attempt.retain_original_data(original_capture(Method::Begin)?)?;
    let (input, rows) = recorded(&attempt)?;
    let data = selected_capture_data(&input)?;
    let records = ValidatedMetadataRecords::validate(&rows, 8192, 2 * 1024 * 1024)?;
    let empty = ValidatedMetadataRecords::validate(b"[]", 1, 2 * 1024 * 1024)?;
    let mut missing_metadata = Ledger::new(empty.rows(), limits());
    assert!(
        missing_metadata
            .read::<CurrentCaptureAttempt17>(data, false)
            .is_err()
    );

    let mut unknown = data[..data.len() - 1].to_vec();
    unknown.extend_from_slice(br#","unsupported":null}"#);
    let text = String::from_utf8(data.to_vec())?;
    let missing = text.replacen("\"ordinal\":11,", "", 1);
    let stage = text.replacen("\"stage\":\"raw\"", "\"stage\":\"unsupported\"", 1);
    assert_ne!(missing, text);
    assert_ne!(stage, text);
    for mutation in [&unknown[..], missing.as_bytes(), stage.as_bytes()] {
        let mut ledger = Ledger::new(records.rows(), limits());
        assert!(
            ledger
                .read::<CurrentCaptureAttempt17>(mutation, false)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn partially_decoded_capture_retains_its_actual_typed_body_on_failure()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::bodies::{BeginKind, BeginRequest};
    use crucible_node_format::{U64, canonical};

    let mut original = original_capture(Method::Begin)?;
    let body = BeginRequest {
        kind: BeginKind::Capture,
        binding_hash: canonical::hash("cnp.owner-binding.v1", b"typed-capture-data")?,
        owner_generation: U64::new(1),
        activation_id: Nullable(Some(Id::new("typed-capture-activation")?)),
        world_generation: U64::new(1),
        arguments: Map::new(),
        extensions: Default::default(),
    };
    original.body = serde_json::to_value(body)?
        .as_object()
        .ok_or_else(invalid)?
        .clone();
    let mut attempt = NativeRestoredSettledActionAttempt::new_data(13);
    attempt.retain_original_data(original)?;

    // The complete Begin DTO is installed before its null Source artifact is
    // decoded. This genuine failed prefix therefore retains a typed child.
    assert!(attempt.decode_body_data(65_536).is_err());
    let (input, rows) = recorded(&attempt)?;
    let data = selected_capture_data(&input)?;
    let mut fields = Fields::object(data)?;
    fields.named("ordinal")?;
    fields.named("original")?;
    assert_ne!(fields.named("body")?, b"null");

    let records = ValidatedMetadataRecords::validate(&rows, 8192, 2 * 1024 * 1024)?;
    let mut historical = Ledger::new(records.rows(), limits());
    assert!(
        historical
            .read::<HistoricalRestoredAction17>(&input, false)?
            .is_none()
    );
    assert!(historical.rows.next().is_none());
    let mut owning = Ledger::new(records.rows(), limits());
    assert!(
        owning
            .read::<HistoricalRestoredAction17>(&input, true)
            .is_err()
    );
    Ok(())
}

#[test]
fn typed_capture_artifacts_arguments_and_contexts_survive_source_mac_failure()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::reference_packet::service::restored_settled_capture::{
        PacketRestoredSettledCaptureArtifact, PacketRestoredSettledCaptureContext,
        restored_settled_capture_assigned_request_digest_data,
        restored_settled_capture_context_schema_data, restored_settled_capture_proof_data,
    };
    use crucible_node_format::Bytes;

    let (request, mut original) =
        crate::reference_packet::service::restored_settled_capture::capture_history_fixture_data()?;
    let context = PacketRestoredSettledCaptureContext {
        schema: restored_settled_capture_context_schema_data().into(),
        request: request.clone(),
        assigned_request: Bytes::new(
            restored_settled_capture_assigned_request_digest_data(&original, 65_536)?.to_vec(),
        ),
    };
    let key = [41; 32];
    let artifact = PacketRestoredSettledCaptureArtifact {
        request,
        proof: restored_settled_capture_proof_data(&key, &context)?,
    };
    original.extensions.insert(
        RESTORED_SETTLED_CAPTURE_FEATURE.into(),
        serde_json::to_value(artifact)?,
    );

    // A fixture MAC is DATA. Neither its success nor these raw-first attempts
    // supply a Source ticket, installed Boot, registration or Capture action.
    for valid_key in [true, false] {
        let mut attempt = NativeRestoredSettledActionAttempt::new_data(17);
        attempt.retain_original_data(original.clone())?;
        attempt.decode_body_data(65_536)?;

        for authenticated in [false, true] {
            if authenticated {
                let result = attempt
                    .capture_data_mut()?
                    .authenticate_capture_source_data(
                        if valid_key { &key } else { &[42; 32] },
                        65_536,
                    );
                assert_eq!(result.is_ok(), valid_key);
                if !valid_key {
                    attempt.interrupt_data();
                }
            }
            let (input, rows) = recorded(&attempt)?;
            let value: Value = serde_json::from_slice(&input)?;
            let data = &value["selected"]["data"];
            assert!(data["body"].is_object());
            assert!(data["arguments"].is_object());
            assert!(data["capture"].is_object());
            assert_eq!(data["capture_context"].is_object(), authenticated);
            assert_eq!(value["failed"], authenticated && !valid_key);

            let records = ValidatedMetadataRecords::validate(&rows, 8192, 2 * 1024 * 1024)?;
            let mut historical = Ledger::new(records.rows(), limits());
            assert!(
                historical
                    .read::<HistoricalRestoredAction17>(&input, false)?
                    .is_none()
            );
            assert!(historical.rows.next().is_none());
            let mut owning = Ledger::new(records.rows(), limits());
            assert!(
                owning
                    .read::<HistoricalRestoredAction17>(&input, true)
                    .is_err()
            );
        }
    }
    Ok(())
}
