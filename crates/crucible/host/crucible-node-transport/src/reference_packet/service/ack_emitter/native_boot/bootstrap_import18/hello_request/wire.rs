//! Borrows initial Hello claims from the actual retained strict Value tree.
//!
//! No envelope, body, token String or feature roster is copied. The exact
//! versioned offer remains a separate typed decode and installed-registry check.

use base64::Engine;
use crucible_node_format::{Id, MAX_ARRAY_ELEMENTS, U64};
use serde_json::{Map, Value};
use std::mem::size_of;

use crate::ProviderError;
use crate::handshake::{EXTENSION_NEGOTIATION_V1, Limits};
use crate::operational_time::OperationalDeadline;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::PacketNativeImport18HelloSelectionData;

/// Retains scalar request claims without a connection or native permission.
#[derive(Clone, Copy)]
pub(in super::super::super) struct Claims {
    /// Retains the actual decoded controller challenge.
    pub(in super::super::super) controller_nonce: [u8; 32],
    /// Retains the intersection fixed by the original launch declaration.
    pub(in super::super::super) limits: Limits,
}

/// Borrows the same unverified offer beside its checked scalar request claims.
pub(super) struct Inspected<'a> {
    /// Contains the scalar claims extracted from the same original tree.
    pub(super) claims: Claims,
    /// Borrows the exact versioned offer for its separately admitted decoder.
    pub(super) offer: &'a Value,
}

/// Checks initial correlation, token custody, features and receiving limits.
///
/// The caller supplies its actual current launch, roster and original cut under
/// whole-owner guards. Successful inspection does not validate the versioned
/// offer, issue a connection lease, finish Hello or allow response publication.
///
/// # Errors
/// Refuses malformed/unknown fields, resumed or foreign correlation, invalid
/// identifiers, duplicate versions, unavailable features, token mismatch,
/// changed receiving intersection or expiration of the original cut.
pub(super) fn inspect_data<'a>(
    value: &'a Value,
    launch: &PacketNative5SourceLaunch,
    selection: &PacketNativeImport18HelloSelectionData,
    cut: OperationalDeadline,
) -> Result<Inspected<'a>, ProviderError> {
    current(cut)?;
    let root = object(value, &ENVELOPE_FIELDS)?;
    if text(root, "protocol")? != "CNP/1"
        || text(root, "message")? != "request"
        || text(root, "method")? != "hello"
        || text(root, "sequence")? != "1"
    {
        return Err(refused());
    }
    for field in [
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "operation_id",
    ] {
        if !root.get(field).is_some_and(Value::is_null) {
            return Err(refused());
        }
    }
    if !Id::is_valid_str(text(root, "request_id")?) {
        return Err(refused());
    }

    // Resumption belongs to a different live-incarnation transaction. The
    // initial-only body has exactly these eight fields, including extensions.
    let body = object(root.get("body").ok_or_else(refused)?, &BODY_FIELDS)?;
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    if text(body, "session_id")? != binding.authority.session_id.as_str()
        || !body
            .get("extensions")
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
    {
        return Err(refused());
    }
    versions(body.get("versions").ok_or_else(refused)?, cut)?;
    let required = ids(body.get("required_features").ok_or_else(refused)?, cut)?;
    let optional = ids(body.get("optional_features").ok_or_else(refused)?, cut)?;
    if !contains(required, "cnp.core/1") {
        return Err(refused());
    }
    for feature in required {
        current(cut)?;
        let feature = feature.as_str().ok_or_else(refused)?;
        if !selection
            .0
            .iter()
            .any(|selected| selected.as_str() == feature)
        {
            return Err(refused());
        }
    }
    for feature in &selection.0 {
        current(cut)?;
        if !contains(required, feature.as_str()) && !contains(optional, feature.as_str()) {
            return Err(refused());
        }
    }

    let token = octets32(text(body, "admission_token")?)?;
    let expected = launch.admission_token.as_slice();
    if expected.len() != token.len()
        || token
            .iter()
            .zip(expected)
            .fold(0u8, |difference, (actual, expected)| {
                difference | (actual ^ expected)
            })
            != 0
    {
        return Err(refused());
    }
    let controller_nonce = octets32(text(body, "controller_nonce")?)?;
    let limits = limits(body.get("limits").ok_or_else(refused)?)?;
    if !launch.limits.is_valid_data()
        || limits.frame_bytes < launch.limits.frame_bytes
        || limits.nesting < launch.limits.nesting
        || limits.requests < launch.limits.requests
        || limits.journal_entries < launch.limits.journal_entries
        || limits.blob_chunk_bytes < launch.limits.blob_chunk_bytes
    {
        return Err(refused());
    }

    let extensions = object(
        root.get("extensions").ok_or_else(refused)?,
        &[EXTENSION_NEGOTIATION_V1],
    )?;
    let offer = extensions
        .get(EXTENSION_NEGOTIATION_V1)
        .ok_or_else(refused)?;
    current(cut)?;
    Ok(Inspected {
        claims: Claims {
            controller_nonce,
            limits: launch.limits,
        },
        offer,
    })
}

const ENVELOPE_FIELDS: [&str; 13] = [
    "protocol",
    "message",
    "session_id",
    "incarnation_id",
    "node_id",
    "execution_owner_id",
    "capture_owner_id",
    "request_id",
    "operation_id",
    "sequence",
    "method",
    "body",
    "extensions",
];

const BODY_FIELDS: [&str; 8] = [
    "versions",
    "session_id",
    "controller_nonce",
    "required_features",
    "optional_features",
    "limits",
    "admission_token",
    "extensions",
];

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, ProviderError> {
    let object = value.as_object().ok_or_else(refused)?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(refused());
    }
    Ok(object)
}

fn text<'a>(value: &'a Map<String, Value>, field: &str) -> Result<&'a str, ProviderError> {
    value.get(field).and_then(Value::as_str).ok_or_else(refused)
}

fn ids(value: &Value, cut: OperationalDeadline) -> Result<&[Value], ProviderError> {
    let values = value.as_array().ok_or_else(refused)?;
    if values.len() > MAX_ARRAY_ELEMENTS {
        return Err(refused());
    }
    let mut previous: Option<&str> = None;
    for value in values {
        current(cut)?;
        let text = value.as_str().ok_or_else(refused)?;
        if !Id::is_valid_str(text) || previous.is_some_and(|previous| previous >= text) {
            return Err(refused());
        }
        previous = Some(text);
    }
    Ok(values)
}

fn contains(values: &[Value], id: &str) -> bool {
    values
        .binary_search_by(|value| value.as_str().cmp(&Some(id)))
        .is_ok()
}

fn versions(value: &Value, cut: OperationalDeadline) -> Result<(), ProviderError> {
    let versions = value.as_array().ok_or_else(refused)?;
    if versions.is_empty() || versions.len() > MAX_ARRAY_ELEMENTS {
        return Err(refused());
    }
    let mut baseline = false;
    for (index, version) in versions.iter().enumerate() {
        current(cut)?;
        let version = version.as_str().ok_or_else(refused)?;
        if !Id::is_valid_str(version) {
            return Err(refused());
        }
        baseline |= version == "CNP/1";
        for earlier in &versions[..index] {
            // Version advertisements need not be sorted. Check the original
            // cut during duplicate comparisons too, without an auxiliary set.
            current(cut)?;
            if earlier.as_str() == Some(version) {
                return Err(refused());
            }
        }
    }
    if !baseline {
        return Err(refused());
    }
    Ok(())
}

/// Decodes one canonical 32-byte claim into fixed caller-owned controls.
///
/// # Errors
/// Refuses another spelling width, invalid base64 or another decoded extent.
pub(in super::super) fn octets32(encoded: &str) -> Result<[u8; 32], ProviderError> {
    if encoded.len() != 43 {
        return Err(refused());
    }
    // The decoder's conservative final-chunk estimate may need a 33rd byte;
    // only an exact canonical 32-byte result reaches the retained claim.
    let mut decoded = [0u8; 33];
    let length = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(encoded, &mut decoded)
        .map_err(|_| refused())?;
    if length != 32 {
        return Err(refused());
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&decoded[..32]);
    Ok(result)
}

fn decimal(value: &Map<String, Value>, field: &str) -> Result<U64, ProviderError> {
    let text = text(value, field)?;
    if text.is_empty()
        || text.len() > 20
        || text.len() > 1 && text.starts_with('0')
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(refused());
    }
    text.parse::<u64>().map(U64::new).map_err(|_| refused())
}

fn limits(value: &Value) -> Result<Limits, ProviderError> {
    let value = object(
        value,
        &[
            "frame_bytes",
            "nesting",
            "requests",
            "journal_entries",
            "blob_chunk_bytes",
        ],
    )?;
    let limits = Limits {
        frame_bytes: decimal(value, "frame_bytes")?,
        nesting: decimal(value, "nesting")?,
        requests: decimal(value, "requests")?,
        journal_entries: decimal(value, "journal_entries")?,
        blob_chunk_bytes: decimal(value, "blob_chunk_bytes")?,
    };
    if !limits.is_valid_data() {
        return Err(refused());
    }
    Ok(limits)
}

fn current(cut: OperationalDeadline) -> Result<(), ProviderError> {
    if cut.is_expired() {
        return Err(refused());
    }
    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 initial Hello request")
}

/// Names the actual borrowed claim, cursor, token decoder and limits controls.
pub(super) fn counter_scratch_data() -> usize {
    crucible_node_format::Bytes::slice_decoding_counter_scratch_data()
        + Limits::validation_counter_scratch_data()
        + size_of::<std::array::IntoIter<&'static str, 6>>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<std::iter::Zip<std::slice::Iter<'static, u8>, std::slice::Iter<'static, u8>>>()
        + size_of::<std::slice::Iter<'static, Id>>()
        + size_of::<std::cmp::Ordering>()
        + size_of::<Claims>() * 2
        + size_of::<Inspected<'static>>() * 2
        + size_of::<Result<Inspected<'static>, ProviderError>>()
        + size_of::<Limits>() * 3
        + size_of::<OperationalDeadline>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&PacketNativeImport18HelloSelectionData>()
        + size_of::<&Map<String, Value>>() * 5
        + size_of::<&Value>() * 3
        + size_of::<&[Value]>() * 3
        + size_of::<&str>() * 8
        + size_of::<Option<&str>>() * 3
        + size_of::<std::slice::Iter<'static, Value>>() * 3
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Value>>>()
        + size_of::<std::str::Bytes<'static>>() * 2
        + size_of::<[u8; 33]>()
        + size_of::<[u8; 32]>() * 4
        + size_of::<Result<usize, base64::DecodeSliceError>>()
        + size_of::<base64::DecodeSliceError>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<usize>() * 8
        + size_of::<bool>() * 4
        + size_of::<Result<(), ProviderError>>() * 5
}

// Exhaustive field patterns tie the initial projection to the real wire DTOs.
// The single resumed-only body field is deliberately absent from BODY_FIELDS.
const _: fn(&crate::envelope::Envelope) = |value| {
    let crate::envelope::Envelope {
        protocol: _,
        message: _,
        session_id: _,
        incarnation_id: _,
        node_id: _,
        execution_owner_id: _,
        capture_owner_id: _,
        request_id: _,
        operation_id: _,
        sequence: _,
        method: _,
        body: _,
        extensions: _,
    } = value;
};

const _: fn(&crate::handshake::HelloRequest) = |value| {
    let crate::handshake::HelloRequest {
        versions: _,
        session_id: _,
        controller_nonce: _,
        required_features: _,
        optional_features: _,
        limits: _,
        admission_token: _,
        resume_session: _,
        extensions: _,
    } = value;
};

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::reference_packet::service::complete_restore::import18::{
        hello::native_import18_hello_declaration_data, inert_bootstrap_fixtures,
    };
    use crucible_node_format::{Bytes, Validate};
    use serde_json::json;
    use std::time::Duration;

    pub(in super::super) fn fixture(
        reactive: bool,
    ) -> (
        PacketNative5SourceLaunch,
        PacketNativeImport18HelloSelectionData,
        Value,
    ) {
        let selected = inert_bootstrap_fixtures::initial_selected_launch(reactive);
        let launch: PacketNative5SourceLaunch =
            serde_json::from_value(selected["launch"].clone()).unwrap();
        let declaration = native_import18_hello_declaration_data(&launch).unwrap();
        let mut selection = None;
        declaration
            .retain_selection_into_data(&mut selection)
            .unwrap();
        let selection = selection.unwrap();
        let session = &launch.selection.realization.bindings[0]
            .authority
            .session_id;
        let value = json!({
            "protocol": "CNP/1", "message": "request", "sequence": "1", "method": "hello",
            "session_id": null, "incarnation_id": null, "node_id": null,
            "execution_owner_id": null, "capture_owner_id": null, "operation_id": null,
            "request_id": "hello/first",
            "body": {
                "versions": ["CNP/1"], "session_id": session,
                "controller_nonce": Bytes::new(vec![19; 32]),
                "required_features": selection.0, "optional_features": [],
                "limits": launch.limits, "admission_token": launch.admission_token,
                "extensions": {},
            },
            "extensions": { EXTENSION_NEGOTIATION_V1: {
                "format": "1", "required": [], "optional": [],
            }},
        });
        (launch, selection, value)
    }

    #[test]
    fn actual_initial_claims_match_both_real_body_decoders_without_copying_the_offer() {
        for reactive in [false, true] {
            let (launch, selection, mut value) = fixture(reactive);
            value["body"]["versions"] = json!(["CNP/2", "CNP/1"]);
            value["body"]["optional_features"] = json!(["vendor.unselected/1"]);
            let envelope: crate::envelope::Envelope =
                serde_json::from_value(value.clone()).unwrap();
            envelope.validate().unwrap();
            let body: crate::handshake::HelloRequest =
                serde_json::from_value(Value::Object(envelope.body)).unwrap();
            body.validate().unwrap();

            let inspected = inspect_data(
                &value,
                &launch,
                &selection,
                OperationalDeadline::after(Duration::from_secs(5)).unwrap(),
            )
            .unwrap();
            assert_eq!(inspected.claims.controller_nonce, [19; 32]);
            assert_eq!(inspected.claims.limits, launch.limits);
            assert!(std::ptr::eq(
                inspected.offer,
                &value["extensions"][EXTENSION_NEGOTIATION_V1]
            ));
        }
    }

    #[test]
    fn each_closed_initial_field_and_original_token_remains_required() {
        let (launch, selection, original) = fixture(false);
        for field in ENVELOPE_FIELDS {
            let mut changed = original.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(
                inspect_data(
                    &changed,
                    &launch,
                    &selection,
                    OperationalDeadline::after(Duration::from_secs(5)).unwrap()
                )
                .is_err(),
                "missing envelope {field}"
            );
        }
        for field in BODY_FIELDS {
            let mut changed = original.clone();
            changed["body"].as_object_mut().unwrap().remove(field);
            assert!(
                inspect_data(
                    &changed,
                    &launch,
                    &selection,
                    OperationalDeadline::after(Duration::from_secs(5)).unwrap()
                )
                .is_err(),
                "missing body {field}"
            );
        }
        for (pointer, replacement) in [
            ("/sequence", json!("2")),
            ("/message", json!("response")),
            ("/method", json!("native_import18_bootstrap")),
            ("/protocol", json!("CNP/2")),
            ("/request_id", json!(null)),
            ("/session_id", json!("session/other")),
            ("/incarnation_id", json!("incarnation/old")),
            ("/node_id", json!("node/early")),
            ("/execution_owner_id", json!("owner/early")),
            ("/capture_owner_id", json!("capture/early")),
            ("/operation_id", json!("operation/early")),
            ("/body/session_id", json!("session/other")),
            ("/body/admission_token", json!(Bytes::new(vec![8; 32]))),
            ("/body/controller_nonce", json!(Bytes::new(vec![19; 31]))),
            ("/body/versions", json!(["CNP/1", "CNP/1"])),
            ("/body/versions", json!(["CNP/2"])),
            ("/body/required_features", json!([])),
            ("/body/optional_features", json!(["z/1", "a/1"])),
            ("/body/limits/frame_bytes", json!("065536")),
            ("/body/limits/nesting", json!("65")),
            ("/body/limits/requests", json!("1")),
            ("/body/limits/journal_entries", json!("0")),
            ("/body/limits/blob_chunk_bytes", json!("1048577")),
            ("/body/extensions", json!({"unregistered/1":{}})),
            ("/extensions", json!({})),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                inspect_data(
                    &changed,
                    &launch,
                    &selection,
                    OperationalDeadline::after(Duration::from_secs(5)).unwrap()
                )
                .is_err(),
                "changed {pointer}"
            );
        }
        for pointer in ["", "/body", "/body/limits", "/extensions"] {
            let mut changed = original.clone();
            changed
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".into(), Value::Null);
            assert!(
                inspect_data(
                    &changed,
                    &launch,
                    &selection,
                    OperationalDeadline::after(Duration::from_secs(5)).unwrap()
                )
                .is_err(),
                "extra {pointer}"
            );
        }
        for resume in [Value::Null, json!({})] {
            let mut changed = original.clone();
            changed["body"]["resume_session"] = resume;
            assert!(
                inspect_data(
                    &changed,
                    &launch,
                    &selection,
                    OperationalDeadline::after(Duration::from_secs(5)).unwrap()
                )
                .is_err()
            );
        }
        assert!(
            inspect_data(
                &original,
                &launch,
                &selection,
                OperationalDeadline::expired_fixture()
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_octet_decoder_preserves_the_actual_canonical_bytes_contract() {
        for bytes in [[0u8; 32], [7; 32], [255; 32]] {
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            assert_eq!(octets32(&encoded).unwrap(), bytes);
            assert!(octets32(&(encoded.clone() + "=")).is_err());
        }
        assert!(octets32(&"/".repeat(43)).is_err());
        assert!(octets32(&"A".repeat(42)).is_err());
        let mut noncanonical = "A".repeat(42);
        noncanonical.push('B');
        assert!(octets32(&noncanonical).is_err());
    }
}
