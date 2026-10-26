//! Checks baseline record entry points, including nested tagged responses.

fn refuses_sequence_before_reading_fields<T: serde::de::DeserializeOwned>() {
    let mut read = false;
    let input = std::iter::once_with(|| {
        read = true;
        0u8
    });
    let decoder = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(input);

    assert!(T::deserialize(decoder).is_err());
    assert!(
        !read,
        "{} visited a positional field",
        std::any::type_name::<T>()
    );
}

#[test]
fn every_baseline_wire_record_refuses_sequences_before_reading_fields() {
    refuses_sequence_before_reading_fields::<crate::envelope::Envelope>();
    refuses_sequence_before_reading_fields::<crate::handshake::ResumeSession>();
    refuses_sequence_before_reading_fields::<crate::handshake::HelloRequest>();
    refuses_sequence_before_reading_fields::<crate::handshake::Limits>();
    refuses_sequence_before_reading_fields::<crate::handshake::ResumedOperation>();
    refuses_sequence_before_reading_fields::<crate::handshake::HelloResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::GrantContext>();
    refuses_sequence_before_reading_fields::<crate::bodies::ExactRunArguments>();
    refuses_sequence_before_reading_fields::<crate::bodies::QuantumBeginArguments>();
    refuses_sequence_before_reading_fields::<crate::bodies::PauseArguments>();
    refuses_sequence_before_reading_fields::<crate::bodies::CaptureArguments>();
    refuses_sequence_before_reading_fields::<crate::bodies::PrepareRestoreArguments>();
    refuses_sequence_before_reading_fields::<crate::bodies::ShutdownArguments>();
    refuses_sequence_before_reading_fields::<crate::bodies::ExactRunResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::QuantumBeginResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::PauseResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::CaptureResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::PrepareRestoreResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::ShutdownResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::DiscoverRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::AdmitRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::InputRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::ObserveRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::BeginRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::PollRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::CancelRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::QuantumCloseRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::WorldActivateRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::AbortRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::RetireRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::BlobBeginRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::BlobChunkRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::BlobFinishRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::ReleaseRequest>();
    refuses_sequence_before_reading_fields::<crate::bodies::ErrorRecord>();
    refuses_sequence_before_reading_fields::<crate::bodies::NotificationBody>();
    refuses_sequence_before_reading_fields::<crate::bodies::DiscoverResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::RealizeResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::AdmitResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::ActivateResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::InputResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::ObserveResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::BeginAccepted>();
    refuses_sequence_before_reading_fields::<crate::bodies::PollResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::CancelResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::QuantumCloseResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::WorldActivateResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::AbortResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::RetireResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::BlobBeginResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::BlobChunkResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::BlobFinishResult>();
    refuses_sequence_before_reading_fields::<crate::bodies::ReleaseResult>();
    refuses_sequence_before_reading_fields::<crate::handshake::ExtensionOfferV1>();
    refuses_sequence_before_reading_fields::<crate::handshake::ExtensionSelectionV1>();
}

#[test]
fn tagged_response_cannot_accept_a_positional_error_record()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::bodies::{ErrorRecord, ResponseShape};
    use serde::Deserialize;
    use serde_json::json;

    let original = json!({
        "status":"error", "operation_state":"not_started",
        "error":{
            "code":"RESOURCE_EXHAUSTED", "message":"bounded refusal",
            "effect":"not_started", "retryable":false,
            "details":{"literal":[1, null, {"$serde_json::private::RawValue":"ordinary DATA"}]}
        },
        "extensions":{}
    });
    let bytes = serde_json::to_vec(&original)?;
    let borrowed = ResponseShape::deserialize(&original)?;
    let owned: ResponseShape = serde_json::from_value(original.clone())?;
    let streamed: ResponseShape = serde_json::from_slice(&bytes)?;
    assert_eq!(borrowed, owned);
    assert_eq!(borrowed, streamed);
    assert_eq!(serde_json::to_value(&borrowed)?, original);

    let record = &original["error"];
    let positional = json!([
        record["code"],
        record["message"],
        record["effect"],
        record["retryable"],
        record["details"]
    ]);
    assert!(ErrorRecord::deserialize(&positional).is_err());
    let mut invalid = original;
    invalid["error"] = positional;

    assert!(ResponseShape::deserialize(&invalid).is_err());
    assert!(ResponseShape::deserialize(invalid.clone()).is_err());
    assert!(serde_json::from_slice::<ResponseShape>(&serde_json::to_vec(&invalid)?).is_err());
    assert!(super::super::object::<ResponseShape>(invalid.as_object().unwrap()).is_err());
    Ok(())
}

#[test]
fn hello_requires_an_object_for_the_shared_receiving_limits()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::handshake::{HelloRequest, Limits};
    use crucible_node_format::{Bytes, Validate};
    use serde::Deserialize;
    use serde_json::json;

    let original = json!({
        "versions":["CNP/1"], "session_id":"session",
        "controller_nonce":Bytes::new(vec![3;32]),
        "required_features":["cnp.core/1"], "optional_features":[],
        "limits":{
            "frame_bytes":"65536", "nesting":"64", "requests":"16",
            "journal_entries":"64", "blob_chunk_bytes":"4096"
        },
        "admission_token":Bytes::new(vec![7;32]), "extensions":{}
    });
    let bytes = serde_json::to_vec(&original)?;
    let decoded = HelloRequest::deserialize(&original)?;
    decoded.validate()?;
    assert_eq!(serde_json::to_value(&decoded)?, original);
    assert_eq!(
        serde_json::to_value(serde_json::from_slice::<HelloRequest>(&bytes)?)?,
        original
    );

    let limits = &original["limits"];
    let positional = json!([
        limits["frame_bytes"],
        limits["nesting"],
        limits["requests"],
        limits["journal_entries"],
        limits["blob_chunk_bytes"]
    ]);
    assert!(Limits::deserialize(&positional).is_err());
    assert!(Limits::deserialize(positional.clone()).is_err());
    assert!(serde_json::from_slice::<Limits>(&serde_json::to_vec(&positional)?).is_err());
    let mut invalid = original.clone();
    invalid["limits"] = positional;
    assert!(HelloRequest::deserialize(&invalid).is_err());
    assert!(HelloRequest::deserialize(invalid.clone()).is_err());
    assert!(serde_json::from_slice::<HelloRequest>(&serde_json::to_vec(&invalid)?).is_err());

    for field in [
        "frame_bytes",
        "nesting",
        "requests",
        "journal_entries",
        "blob_chunk_bytes",
    ] {
        let mut missing = limits.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(Limits::deserialize(&missing).is_err());
    }
    let mut unknown = limits.clone();
    unknown["unknown"] = json!(0);
    assert!(Limits::deserialize(&unknown).is_err());
    Ok(())
}
