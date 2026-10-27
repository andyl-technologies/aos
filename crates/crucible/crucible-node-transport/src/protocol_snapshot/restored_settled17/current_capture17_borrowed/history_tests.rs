//! Matches output-pair history framing to the actual retained Capture writer.

use super::*;
use crate::envelope::{Method, Nullable};
use crate::reference_packet::service::native_startup::NativeRestoredSettledActionAttempt;
use crucible_node_format::Id;

fn actual_history(failed: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut original = crate::envelope::tests::request();
    original.method = Method::Begin;
    original.node_id = Nullable(Some(Id::new("history-node")?));
    original.operation_id = Nullable(None);
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(Some(Id::new("history-capture")?));
    original.extensions.clear();
    // A raw Source-bearing occurrence selects the real Capture writer. This
    // incomplete proof cannot authenticate a Capture or completed output pair.
    original
        .extensions
        .insert(RESTORED_SETTLED_CAPTURE_FEATURE.into(), Value::Null);
    let mut attempt = NativeRestoredSettledActionAttempt::new_data(1);
    attempt.retain_original_data(original)?;
    if failed {
        assert!(attempt.decode_body_data(65_536).is_err());
    }

    let encoded = serde_json::to_vec(&attempt)?;
    let mut wrapper = Fields::object(&encoded)?;
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
    Ok(data.to_vec())
}

// The previous writer omitted these absent slots. Preserve that exact saved
// grammar as compatibility DATA, independently of the repaired current writer.
fn previous_history(input: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let input = String::from_utf8(input.to_vec())?;
    let previous = input.replacen(",\"registration\":null", "", 1).replacen(
        ",\"confirmation_receipt\":null",
        "",
        1,
    );
    assert_ne!(previous, input);
    Ok(previous)
}

#[test]
fn native17_output_history_recognizes_the_actual_ordinary_capture_writer()
-> Result<(), Box<dyn std::error::Error>> {
    for failed in [false, true] {
        let raw = actual_history(failed)?;
        let value: Value = serde_json::from_slice(&raw)?;
        assert_eq!(value.as_object().unwrap().len(), 17);
        let fields = historical_capture17_cut_fields_data(&raw)?.unwrap();
        assert_eq!(fields.registration, b"null");
        assert_eq!(fields.confirmation_receipt, b"null");

        let previous = previous_history(&raw)?;
        assert!(historical_capture17_cut_fields_data(previous.as_bytes())?.is_none());
    }
    Ok(())
}

#[test]
fn native17_output_history_rejects_partial_or_unknown_cut_decorations()
-> Result<(), Box<dyn std::error::Error>> {
    let ordinary = previous_history(&actual_history(false)?)?;
    let with_registration = ordinary.replacen(
        ",\"checkpoint\":",
        ",\"registration\":null,\"checkpoint\":",
        1,
    );
    let with_receipt = ordinary.replacen(
        ",\"stage\":",
        ",\"confirmation_receipt\":null,\"stage\":",
        1,
    );
    let full = with_registration.replacen(
        ",\"stage\":",
        ",\"confirmation_receipt\":null,\"stage\":",
        1,
    );
    assert_ne!(ordinary, with_registration);
    assert_ne!(ordinary, with_receipt);

    // The compatibility roster is DATA only. Null registration cannot pass the
    // output-pair join's separate identity and exact signed-request comparison.
    let cut = historical_capture17_cut_fields_data(full.as_bytes())?.unwrap();
    assert_eq!(cut.registration, b"null");
    assert_eq!(cut.confirmation_receipt, b"null");
    assert!(historical_capture17_cut_fields_data(with_registration.as_bytes()).is_err());
    assert!(historical_capture17_cut_fields_data(with_receipt.as_bytes()).is_err());

    for raw in [&ordinary, &full] {
        let mut unknown = raw.as_bytes()[..raw.len() - 1].to_vec();
        unknown.extend_from_slice(br#","unknown":null}"#);
        assert!(historical_capture17_cut_fields_data(&unknown).is_err());
        let mut duplicate = raw.as_bytes()[..raw.len() - 1].to_vec();
        duplicate.extend_from_slice(br#","ordinal":1}"#);
        assert!(historical_capture17_cut_fields_data(&duplicate).is_err());
    }
    assert!(
        historical_capture17_cut_counter_scratch_data()
            > historical_capture17_counter_scratch_data()
    );
    Ok(())
}
