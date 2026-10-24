//! Exercises closed Snapshot17 framing using real inert output-bank owners.

use super::*;
use crate::envelope::Nullable;
use crate::reference_packet::service::native_snapshot::PacketNativeRestoredSettled17SnapshotPlan;
use serde::Serialize;
use serde_json::json;

fn fixture() -> Result<
    (
        NativeRestoredSettledCaptureOutputs,
        CaptureArguments,
        Envelope,
    ),
    ProviderError,
> {
    // No Source signature or live native owner is constructed. These generic
    // completed banks test only the independently consumed outer framing path.
    let mut banks = std::array::from_fn(|_| Output::default());
    for bank in &mut banks {
        bank.bytes
            .try_reserve_exact(65536)
            .map_err(|_| exhausted())?;
    }
    let mut outputs = NativeRestoredSettledCaptureOutputs {
        banks,
        limits: [65536; 5],
        records: [None, None],
        aliases: [None, None],
        reserved: true,
        failed: false,
    };
    outputs.write_data(
        NativeRestoredSettledCaptureOutput::Control,
        &json!({"test_control": "inert"}),
    )?;
    outputs.write_data(
        NativeRestoredSettledCaptureOutput::Before,
        &json!({"test_before": "inert"}),
    )?;
    let arguments = CaptureArguments {
        capture_id: Id::new("capture-1")?,
        participant_ids: vec![Id::new("node-1")?],
        cut_id: Id::new("cut-1")?,
        cut: Position::new(U64::new(50), U64::new(1), Phase::BoundaryControl),
        event_ordinal: U64::new(17),
        ordering_profile: "superdense-v1".into(),
        preservation_contract: Id::new("contract-1")?,
    };
    let mut original = crate::envelope::tests::request();
    original.method = Method::Begin;
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(Some(Id::new("capture-owner-1")?));
    original.body = json!({"kind": "capture", "arguments": arguments})
        .as_object()
        .ok_or_else(refused)?
        .clone();
    original
        .extensions
        .insert(RESTORED_SETTLED_CAPTURE_FEATURE.into(), Value::Null);
    Ok((outputs, arguments, original))
}

#[derive(Serialize)]
struct IndependentOuter<'a> {
    capture: &'a CaptureArguments,
    capture_request: &'a Envelope,
    control: &'a Value,
    control_reference: Value,
    protocol: (&'static str, Value, usize, BorrowedCompactBytes<'a>),
    schema: &'static str,
}

// Build each expected leaf through the independent canonical encoder, rather
// than reusing the production borrowed reference wrapper or its field order.
fn canonical_reference(reference: &ContentRef) -> Result<Value, ProviderError> {
    let raw = canonical_reference_bytes(reference)?;
    serde_json::from_slice(&raw)
        .map_err(|error| crucible_node_format::ContractError::from(error).into())
}

fn canonical_reference_bytes(reference: &ContentRef) -> Result<Vec<u8>, ProviderError> {
    let value =
        serde_json::to_value(reference).map_err(crucible_node_format::ContractError::from)?;
    canonical::canonical_json(&value).map_err(Into::into)
}

#[test]
fn closed_writer_matches_independent_serializer_and_defining_parser() -> Result<(), ProviderError> {
    let (mut outputs, capture, original) = fixture()?;
    let control = &outputs.banks[1];
    let before = &outputs.banks[2];
    let control_value: Value = serde_json::from_slice(&control.bytes)
        .map_err(crucible_node_format::ContractError::from)?;
    let expected = serde_json::to_vec(&IndependentOuter {
        capture: &capture,
        capture_request: &original,
        control: &control_value,
        control_reference: canonical_reference(control.reference.as_ref().ok_or_else(refused)?)?,
        protocol: (
            "source-private.native-before-protocol/17",
            canonical_reference(before.reference.as_ref().ok_or_else(refused)?)?,
            before.bytes.capacity(),
            BorrowedCompactBytes::new(&before.bytes),
        ),
        schema: "source-owned.packet-native-continuation/17",
    })
    .map_err(crucible_node_format::ContractError::from)?;
    let row = outputs.quote_snapshot17_data(&capture, &original, usize::MAX)?;
    let exact = usize::try_from(row.row_data().requested_peak_data()?).map_err(|_| exhausted())?;
    assert!(
        outputs
            .quote_snapshot17_data(&capture, &original, exact)
            .is_ok()
    );
    assert!(
        outputs
            .quote_snapshot17_data(&capture, &original, exact - 1)
            .is_err()
    );
    let capacity = outputs.banks[0].bytes.capacity();

    outputs.write_snapshot17_data(&capture, &original, &row)?;

    let (reference, actual) =
        outputs.completed_data(NativeRestoredSettledCaptureOutput::Snapshot)?;
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), row.encoded_bytes_data());
    assert_eq!(outputs.banks[0].bytes.capacity(), capacity);
    reference.verify(actual)?;
    let plan = PacketNativeRestoredSettled17SnapshotPlan::validate(actual, actual.len(), 65536)?;
    assert_eq!(
        plan.control_reference_bytes(),
        canonical_reference_bytes(outputs.banks[1].reference.as_ref().ok_or_else(refused)?)?
    );
    assert_eq!(
        plan.before().reference_bytes(),
        canonical_reference_bytes(outputs.banks[2].reference.as_ref().ok_or_else(refused)?)?
    );
    assert_eq!(plan.control_bytes(), outputs.banks[1].bytes);
    assert_eq!(
        plan.before().original_capacity(),
        outputs.banks[2].bytes.capacity()
    );
    plan.before()
        .authenticate_original_bytes(&outputs.banks[2].bytes)?;

    // Equal reference DATA with the public DTO's different hash-field order
    // must still fail the closed historical grammar, for either output leaf.
    for bank in [&outputs.banks[1], &outputs.banks[2]] {
        let reference = bank.reference.as_ref().ok_or_else(refused)?;
        let canonical = canonical_reference_bytes(reference)?;
        let ordinary =
            serde_json::to_vec(reference).map_err(crucible_node_format::ContractError::from)?;
        assert_ne!(ordinary, canonical);
        assert_eq!(
            serde_json::from_slice::<Value>(&ordinary)
                .map_err(crucible_node_format::ContractError::from)?,
            serde_json::from_slice::<Value>(&canonical)
                .map_err(crucible_node_format::ContractError::from)?
        );
        let offset = actual
            .windows(canonical.len())
            .position(|bytes| bytes == canonical)
            .ok_or_else(refused)?;
        let mut changed = actual.to_vec();
        changed.splice(offset..offset + canonical.len(), ordinary);
        assert!(
            PacketNativeRestoredSettled17SnapshotPlan::validate(&changed, changed.len(), 65536)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn changed_body_or_full_reference_and_short_output_limit_are_refused() -> Result<(), ProviderError>
{
    let (mut outputs, capture, mut original) = fixture()?;
    original
        .body
        .get_mut("arguments")
        .and_then(Value::as_object_mut)
        .ok_or_else(refused)?
        .insert("event_ordinal".into(), Value::String("018".into()));
    assert!(
        outputs
            .quote_snapshot17_data(&capture, &original, usize::MAX)
            .is_err()
    );
    original.body.insert(
        "arguments".into(),
        serde_json::to_value(&capture).map_err(crucible_node_format::ContractError::from)?,
    );
    let storage = outputs.quote_snapshot17_data(&capture, &original, usize::MAX)?;
    outputs.limits[0] = storage.encoded_bytes_data() - 1;
    assert!(
        outputs
            .quote_snapshot17_data(&capture, &original, usize::MAX)
            .is_err()
    );
    outputs.limits[0] = 65536;
    outputs.banks[1]
        .reference
        .as_mut()
        .ok_or_else(refused)?
        .length = U64::new(1);
    assert!(
        outputs
            .quote_snapshot17_data(&capture, &original, usize::MAX)
            .is_err()
    );
    assert!(!outputs.failed);
    assert!(!outputs.banks[0].attempted);
    Ok(())
}

#[test]
fn changed_plan_and_short_bank_poison_actual_once_owner_without_growth() -> Result<(), ProviderError>
{
    let (mut outputs, capture, mut original) = fixture()?;
    let storage = outputs.quote_snapshot17_data(&capture, &original, usize::MAX)?;
    original.sequence = U64::new(2);
    assert!(
        outputs
            .write_snapshot17_data(&capture, &original, &storage)
            .is_err()
    );
    assert!(outputs.failed);
    assert!(outputs.banks[0].attempted);
    assert!(outputs.banks[0].bytes.is_empty());
    assert!(
        outputs
            .write_snapshot17_data(&capture, &original, &storage)
            .is_err()
    );

    let (mut short, capture, original) = fixture()?;
    let storage = short.quote_snapshot17_data(&capture, &original, usize::MAX)?;
    short.banks[0].bytes = Vec::new();
    assert!(
        short
            .write_snapshot17_data(&capture, &original, &storage)
            .is_err()
    );
    assert_eq!(short.banks[0].bytes.capacity(), 0);
    assert!(short.failed);
    assert!(short.banks[0].attempted);
    assert!(short.banks[0].reference.is_none());
    Ok(())
}

#[test]
fn partial_snapshot_bytes_survive_refusal_and_cannot_be_retried() -> Result<(), ProviderError> {
    let (mut outputs, capture, original) = fixture()?;
    let storage = outputs.quote_snapshot17_data(&capture, &original, usize::MAX)?;
    outputs.banks[0]
        .bytes
        .extend_from_slice(b"retained partial");
    assert!(
        outputs
            .write_snapshot17_data(&capture, &original, &storage)
            .is_err()
    );
    assert_eq!(outputs.banks[0].bytes, b"retained partial");
    assert!(outputs.failed);
    assert!(outputs.banks[0].attempted);
    assert!(
        outputs
            .quote_snapshot17_data(&capture, &original, usize::MAX)
            .is_err()
    );
    Ok(())
}

#[test]
fn closed_parser_refuses_old_schema_and_protocol_tags() -> Result<(), ProviderError> {
    let (mut outputs, capture, original) = fixture()?;
    let storage = outputs.quote_snapshot17_data(&capture, &original, usize::MAX)?;
    outputs.write_snapshot17_data(&capture, &original, &storage)?;
    let (_, bytes) = outputs.completed_data(NativeRestoredSettledCaptureOutput::Snapshot)?;
    let value: Value =
        serde_json::from_slice(bytes).map_err(crucible_node_format::ContractError::from)?;
    for (key, replacement) in [
        ("schema", "source-owned.packet-native-continuation/16"),
        ("protocol", "source-private.native-before-protocol/16"),
    ] {
        let mut changed = value.clone();
        if key == "schema" {
            changed[key] = Value::String(replacement.into());
        } else {
            changed[key][0] = Value::String(replacement.into());
        }
        let literal =
            serde_json::to_vec(&changed).map_err(crucible_node_format::ContractError::from)?;
        assert!(
            PacketNativeRestoredSettled17SnapshotPlan::validate(&literal, literal.len(), 65536)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn bounded_writer_retains_literal_prefix_on_real_write_limit_error() -> Result<(), ProviderError> {
    let (outputs, capture, original) = fixture()?;
    let shape = shape_data(&capture, &original, &outputs.banks[1], &outputs.banks[2])?;
    let mut partial = Vec::new();
    partial.try_reserve_exact(64).map_err(|_| exhausted())?;
    let capacity = partial.capacity();
    let mut writer = Bounded {
        output: &mut partial,
        maximum: 32,
    };

    assert!(write_shape_data(&mut writer, &shape).is_err());

    assert!(!partial.is_empty());
    assert!(partial.starts_with(b"{\"capture\":"));
    assert!(partial.len() <= 32);
    assert_eq!(partial.capacity(), capacity);
    Ok(())
}
