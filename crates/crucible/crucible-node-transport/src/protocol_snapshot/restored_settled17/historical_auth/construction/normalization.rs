//! Quotes retained ACK normalization and its closed expected JSON producers.
//!
//! Input Values are already retained and remain borrowed. This leaf visits
//! their actual geometry and projects the future policy/registration objects
//! without constructing a Value or invoking U64/Bytes custom serialization.
//! The policy remains alive through the per-role registration comparisons.

use std::mem::size_of;

use crucible_node_format::{ContentRef, ExtensionSelection, HashRef, SemanticVersion};
use serde_json::Value;

use super::super::HistoricalAckBindings17;
use crate::ProviderError;
use crate::handshake::Limits;
use crate::protocol_snapshot::owned11::state::HistoricalAuthority;
use crate::retained_metadata::RetainedProtocolMetadataFacts;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
    actual_serialization_storage_data, original_serialization_counter_scratch_data,
};

/// Separates dynamic normalization work, fixed counters and actual selector extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalAckNormalizationWindow17 {
    /// Bounds requested dynamic backing through the complete normalization window.
    pub(super) requested_storage_bytes: usize,
    /// Names the explicit counter/result/producer work views independently.
    pub(super) declared_counter_scratch_bytes: usize,
    /// Bounds the actual retained birth source selector's complete JSON encoding.
    pub(super) selection_encoded_bytes: usize,
}

#[derive(Clone, Copy)]
struct Phase {
    dynamic: usize,
    retained_value: usize,
    encoded: usize,
}

impl Phase {
    fn from_data(data: OriginalSerializationStorageData) -> Result<Self, ProviderError> {
        Ok(Self {
            dynamic: data
                .requested_total()?
                .checked_sub(data.declared_counter_scratch_bytes)
                .ok_or_else(refused)?,
            retained_value: data
                .retained_value_backing_bytes
                .checked_sub(size_of::<Value>())
                .ok_or_else(refused)?,
            encoded: data.maximum_encoded_bytes,
        })
    }
}

/// Prices actual normalization and both expected role objects without allocating.
///
/// The closed expected grammar is independent of later equality checks: it uses
/// the actual retained birth source_binding and actual authority fields. A
/// mismatching normalized policy/registration still pays for the complete
/// expected object before comparison can refuse. The existing five input Value
/// banks themselves are not charged again.
///
/// # Errors
/// Refuses missing birth/source selector or host identity fields, absent actual
/// selected extensions, traversal/geometry overflow, or a window above maximum.
pub(crate) fn normalized_ack_window_data(
    bindings: &HistoricalAckBindings17<'_>,
    maximum: usize,
) -> Result<HistoricalAckNormalizationWindow17, ProviderError> {
    let source_binding = bindings
        .birth_association
        .get("source_binding")
        .ok_or_else(refused)?;
    let selection = source_binding
        .get("selection")
        .filter(|value| value.is_object())
        .ok_or_else(refused)?;
    let birth_id_encoded = bindings
        .birth_association
        .get("birth_id")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    // Match base640.22.1 GeneralPurposeEstimate: decode allocates the whole
    // estimate and then truncates length, retaining any final spare byte.
    let birth_id_backing = (birth_id_encoded.len() / 4)
        .checked_add(usize::from(birth_id_encoded.len() % 4 != 0))
        .and_then(|quads| quads.checked_mul(3))
        .ok_or_else(refused)?;
    let host_connection = bindings
        .host_registration
        .get("connection_id")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    let actual = [
        value_phase(bindings.birth_association, maximum)?,
        value_phase(bindings.kernel_binding, maximum)?,
        value_phase(bindings.policy_binding, maximum)?,
        value_phase(bindings.host_registration, maximum)?,
        value_phase(bindings.native_registration, maximum)?,
    ];
    let selection = value_phase(selection, maximum)?;
    let policy = policy_phase(source_binding, bindings.authority, maximum)?;
    let scalars = scalar_window_data(bindings, policy.retained_value, maximum)?;
    let host = registration_phase("controller", host_connection, bindings.authority, maximum)?;
    let native = registration_phase(
        "native",
        bindings.authority.connection.as_str(),
        bindings.authority,
        maximum,
    )?;

    // canonical_bytes(actual) returns its output before the expected side is
    // constructed. Sum both complete phase bounds to preserve that first bank.
    let policy_comparison = sum(&[policy.retained_value, actual[2].dynamic, policy.dynamic])?;
    let host_comparison = sum(&[
        policy.retained_value,
        host_connection.len(),
        host.retained_value,
        actual[3].dynamic,
        host.dynamic,
    ])?;
    let native_comparison = sum(&[
        policy.retained_value,
        host_connection.len(),
        native.retained_value,
        actual[4].dynamic,
        native.dynamic,
    ])?;
    let digest = actual
        .iter()
        .map(|phase| phase.dynamic)
        .max()
        .ok_or_else(refused)?;
    // host_id is an independently deserialized String retained after the role
    // loop; the expected policy is also still in scope during all five digests.
    let normalized_digests = sum(&[policy.retained_value, host_connection.len(), digest])?;
    // The scalar branch includes the encoded birth String while decode is in
    // progress; all branches include its eventual Vec's conservative capacity.
    // Later Id/ContentRef refusal can retain that birth bank in the same scope.
    let requested_storage_bytes = policy
        .dynamic
        .max(selection.dynamic)
        .max(scalars)
        .max(policy_comparison)
        .max(host_comparison)
        .max(native_comparison)
        .max(normalized_digests)
        .checked_add(birth_id_backing)
        .ok_or_else(refused)?;
    let declared_counter_scratch_bytes = counter_scratch_data();
    if sum(&[requested_storage_bytes, declared_counter_scratch_bytes])? > maximum {
        return Err(refused());
    }
    Ok(HistoricalAckNormalizationWindow17 {
        requested_storage_bytes,
        declared_counter_scratch_bytes,
        selection_encoded_bytes: selection.encoded,
    })
}

/// Prices scalar constructors against their actual retained input shapes.
///
/// ContentRef may hold three decoded HashRef Strings while its arbitrary length
/// String is parsed, before later fields/validation can refuse. A Value-only
/// geometry visit includes every actual nested String/key and map/array bank;
/// it is a conservative full clone/canonical phase, wider than those String
/// clones without assuming a valid ContentRef or Id. No typed decode runs here.
fn scalar_window_data(
    bindings: &HistoricalAckBindings17<'_>,
    retained_policy: usize,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let birth = bindings.birth_association;
    let encoded_birth = birth.get("birth_id").ok_or_else(refused)?;
    let encoded_length = encoded_birth.as_str().ok_or_else(refused)?.len();
    let mut peak = sum(&[encoded_length, value_phase(encoded_birth, maximum)?.dynamic])?;

    for value in [
        birth.get("private_launch").ok_or_else(refused)?,
        birth.get("host_executable").ok_or_else(refused)?,
        bindings
            .kernel_binding
            .get("native")
            .and_then(|native| native.get("uid"))
            .ok_or_else(refused)?,
        bindings
            .kernel_binding
            .get("native")
            .and_then(|native| native.get("executable"))
            .ok_or_else(refused)?,
    ] {
        peak = peak.max(value_phase(value, maximum)?.dynamic);
    }
    // Unlike earlier scalar checks, host_id is decoded after the policy Value
    // has been constructed and must preserve it even when Id validation fails.
    let host_id = bindings
        .host_registration
        .get("connection_id")
        .ok_or_else(refused)?;
    peak = peak.max(sum(&[
        retained_policy,
        value_phase(host_id, maximum)?.dynamic,
    ])?);
    Ok(peak)
}

fn value_phase(value: &Value, maximum: usize) -> Result<Phase, ProviderError> {
    // Value serialization visits stored strings/numbers directly. It contains
    // no typed custom Bytes or decimal U64 formatter that could allocate here.
    Phase::from_data(actual_serialization_storage_data(
        value,
        RetainedProtocolMetadataFacts::default(),
        maximum,
    )?)
}

fn policy_phase(
    source_binding: &Value,
    authority: &HistoricalAuthority,
    maximum: usize,
) -> Result<Phase, ProviderError> {
    let mut projection = OriginalSerializationStorageProjection::new(maximum)?;
    projection.add_object()?;
    projection.add_field("schema")?;
    projection.add_string("source-owned.packet-canonical-ack-policy-binding/5")?;
    projection.add_field("source_binding")?;
    projection.add_value(source_binding)?;
    projection.add_field("negotiated")?;
    projection.add_object()?;
    negotiated_fields(&mut projection, authority)?;
    Phase::from_data(projection.finish(maximum)?)
}

fn registration_phase(
    role: &str,
    connection: &str,
    authority: &HistoricalAuthority,
    maximum: usize,
) -> Result<Phase, ProviderError> {
    let mut projection = OriginalSerializationStorageProjection::new(maximum)?;
    projection.add_object()?;
    for (name, value) in [
        ("schema", "source-owned.packet-canonical-ack-registration/5"),
        ("role", role),
        ("connection_id", connection),
        ("session_id", authority.session.as_str()),
        ("incarnation_id", authority.incarnation.as_str()),
    ] {
        projection.add_field(name)?;
        projection.add_string(value)?;
    }
    negotiated_fields(&mut projection, authority)?;
    Phase::from_data(projection.finish(maximum)?)
}

fn negotiated_fields(
    projection: &mut OriginalSerializationStorageProjection,
    authority: &HistoricalAuthority,
) -> Result<(), ProviderError> {
    projection.add_field("limits")?;
    projection.add_object()?;
    let Limits {
        frame_bytes: _,
        nesting: _,
        requests: _,
        journal_entries: _,
        blob_chunk_bytes: _,
    } = authority.limits;
    for name in [
        "frame_bytes",
        "nesting",
        "requests",
        "journal_entries",
        "blob_chunk_bytes",
    ] {
        projection.add_field(name)?;
        decimal(projection)?;
    }
    projection.add_field("features")?;
    projection.add_array_extent(authority.features.len())?;
    for feature in &authority.features {
        projection.add_string(feature.as_str())?;
    }
    projection.add_field("extensions")?;
    let extensions = authority.extensions.as_deref().ok_or_else(refused)?;
    projection.add_array_extent(extensions.len())?;
    for extension in extensions {
        selected_extension(projection, extension)?;
    }
    projection.add_field("envelope_extensions")?;
    projection.add_array_extent(authority.envelope_extensions.len())?;
    for extension in &authority.envelope_extensions {
        projection.add_string(extension)?;
    }
    Ok(())
}

fn selected_extension(
    projection: &mut OriginalSerializationStorageProjection,
    extension: &ExtensionSelection,
) -> Result<(), ProviderError> {
    let ExtensionSelection {
        declaration,
        identifier,
        semantic_version,
        schema_digest,
    } = extension;
    projection.add_object()?;
    projection.add_field("declaration")?;
    content_reference(projection, declaration)?;
    projection.add_field("identifier")?;
    projection.add_string(identifier.as_str())?;
    projection.add_field("semantic_version")?;
    projection.add_object()?;
    let SemanticVersion {
        major: _,
        minor: _,
        patch: _,
        prerelease,
        build,
    } = semantic_version;
    for name in ["major", "minor", "patch"] {
        projection.add_field(name)?;
        decimal(projection)?;
    }
    projection.add_field("prerelease")?;
    optional_string(projection, prerelease.as_deref())?;
    projection.add_field("build")?;
    optional_string(projection, build.as_deref())?;
    projection.add_field("schema_digest")?;
    hash_reference(projection, schema_digest)
}

fn content_reference(
    projection: &mut OriginalSerializationStorageProjection,
    reference: &ContentRef,
) -> Result<(), ProviderError> {
    let ContentRef {
        hash,
        length: _,
        media_type,
    } = reference;
    projection.add_object()?;
    projection.add_field("hash")?;
    hash_reference(projection, hash)?;
    projection.add_field("length")?;
    decimal(projection)?;
    projection.add_field("media_type")?;
    projection.add_string(media_type)
}

fn hash_reference(
    projection: &mut OriginalSerializationStorageProjection,
    reference: &HashRef,
) -> Result<(), ProviderError> {
    let HashRef {
        algorithm,
        domain,
        digest,
    } = reference;
    projection.add_object()?;
    for (name, value) in [
        ("algorithm", algorithm),
        ("domain", domain),
        ("digest", digest),
    ] {
        projection.add_field(name)?;
        projection.add_string(value)?;
    }
    Ok(())
}

fn decimal(projection: &mut OriginalSerializationStorageProjection) -> Result<(), ProviderError> {
    // U64's canonical decimal string has at most 20 unescaped ASCII bytes. Do
    // not call its allocating Serialize implementation during this prequote.
    projection.add_unescaped_ascii_extent(20)
}

fn optional_string(
    projection: &mut OriginalSerializationStorageProjection,
    value: Option<&str>,
) -> Result<(), ProviderError> {
    match value {
        Some(value) => projection.add_string(value),
        None => projection.add_value(&()),
    }
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, next| {
        total.checked_add(*next).ok_or_else(refused)
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("historical ACK normalization construction")
}

/// Names explicit projection/visitor rows, local counters and future Value headers.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<HistoricalAckNormalizationWindow17>()
        + size_of::<Result<HistoricalAckNormalizationWindow17, ProviderError>>()
        + size_of::<[Phase; 5]>()
        + 4 * size_of::<Phase>()
        + size_of::<[(&str, &str); 5]>()
        + size_of::<[(&str, &String); 3]>()
        + size_of::<[&str; 5]>()
        + 2 * size_of::<&Value>()
        + size_of::<&str>()
        + size_of::<[usize; 5]>()
        + size_of::<OriginalSerializationStorageProjection>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<Result<Phase, ProviderError>>()
        + size_of::<std::slice::Iter<'static, Phase>>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<std::slice::Iter<'static, ExtensionSelection>>()
        + size_of::<std::collections::btree_set::Iter<'static, String>>()
        + original_serialization_counter_scratch_data()
        + size_of::<RetainedProtocolMetadataFacts>()
        + 3 * size_of::<Value>()
        + 2 * size_of::<Vec<u8>>()
        + 12 * size_of::<usize>()
        // Two Bytes decode banks, four ContentRef String fields, the length
        // decoder String and an error bank have independent partial headers.
        + size_of::<[Vec<u8>; 8]>()
        // Generated HashRef/ContentRef field Options retain these String views
        // before a later numeric field or unknown-field error can refuse.
        + size_of::<[String; 4]>()
        + size_of::<[&Value; 4]>()
        + size_of::<std::array::IntoIter<&'static Value, 4>>()
        + 2 * size_of::<ContentRef>()
        + size_of::<crucible_node_format::Id>()
        + size_of::<crucible_node_format::Bytes>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Bytes, Id, U64};
    use serde::Deserialize;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn authority() -> Result<HistoricalAuthority, ProviderError> {
        Ok(HistoricalAuthority {
            connection: Id::new("native")?,
            session: Id::new("session")?,
            incarnation: Id::new("incarnation")?,
            epoch: U64::new(1),
            limits: Limits {
                frame_bytes: U64::new(65536),
                nesting: U64::new(64),
                requests: U64::new(16),
                journal_entries: U64::new(128),
                blob_chunk_bytes: U64::new(4096),
            },
            features: vec![Id::new("feature")?],
            envelope_extensions: BTreeSet::from(["extension".to_owned()]),
            extensions: Some(Arc::from([ExtensionSelection {
                declaration: crucible_node_format::canonical::content_ref(
                    b"declaration",
                    "application/json",
                )?,
                identifier: Id::new("extension")?,
                semantic_version: SemanticVersion {
                    major: U64::new(u64::MAX),
                    minor: U64::new(2),
                    patch: U64::new(3),
                    prerelease: Some("candidate.1".to_owned()),
                    build: None,
                },
                schema_digest: crucible_node_format::canonical::hash("cnp.blob.v1", b"schema")?,
            }])),
        })
    }

    #[test]
    fn closed_policy_and_registration_cover_the_actual_expected_value_grammar() -> TestResult {
        let authority = authority()?;
        let source_binding = serde_json::json!({"selection":{"escaped":"\\\"\n","items":[{},1]}});
        let policy = serde_json::json!({
            "schema":"source-owned.packet-canonical-ack-policy-binding/5",
            "source_binding":source_binding,
            "negotiated":{
                "limits":authority.limits,"features":authority.features,
                "extensions":authority.extensions.as_deref(),
                "envelope_extensions":authority.envelope_extensions,
            },
        });
        let projected = policy_phase(&source_binding, &authority, usize::MAX)?;
        let actual = value_phase(&policy, usize::MAX)?;
        assert!(projected.dynamic >= actual.dynamic);
        assert!(projected.retained_value >= actual.retained_value);
        assert!(projected.encoded >= actual.encoded);

        for (role, connection) in [("controller", "host"), ("native", "native")] {
            let registration = serde_json::json!({
                "schema":"source-owned.packet-canonical-ack-registration/5",
                "role":role,"connection_id":connection,"session_id":authority.session,
                "incarnation_id":authority.incarnation,"limits":authority.limits,
                "features":authority.features,"extensions":authority.extensions.as_deref(),
                "envelope_extensions":authority.envelope_extensions,
            });
            let projected = registration_phase(role, connection, &authority, usize::MAX)?;
            let actual = value_phase(&registration, usize::MAX)?;
            assert!(projected.dynamic >= actual.dynamic);
            assert!(projected.retained_value >= actual.retained_value);
            assert!(projected.encoded >= actual.encoded);
        }
        Ok(())
    }

    #[test]
    fn window_preserves_policy_and_prices_real_selector_even_when_normalization_differs()
    -> TestResult {
        let authority = authority()?;
        let birth = serde_json::json!({
            "birth_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "private_launch":"launch",
            "host_executable":{
                "hash":{"algorithm":"blake3-256","domain":"cnp.blob.v1","digest":"0".repeat(64)},
                "length":"1","media_type":"application/octet-stream",
            },
            "source_binding":{"selection":{"profiles":["longer","selector"]}},
        });
        let decoded_birth: crucible_node_format::Bytes =
            serde_json::from_value(birth["birth_id"].clone())?;
        assert_eq!(decoded_birth.as_slice().len(), 32);
        assert_eq!(decoded_birth.allocation_capacity(), 33);
        let kernel = serde_json::json!({"kernel":"retained", "native":{
            "uid":"1", "executable":birth["host_executable"],
        }});
        let policy = serde_json::json!({"mismatching_policy":[1,2,3]});
        let host = serde_json::json!({"connection_id":"host"});
        let native = serde_json::json!({"different_registration":true});
        let executable = crucible_node_format::canonical::content_ref(
            b"executable",
            "application/octet-stream",
        )?;
        let bindings = HistoricalAckBindings17 {
            birth_association: &birth,
            kernel_binding: &kernel,
            policy_binding: &policy,
            host_registration: &host,
            native_registration: &native,
            authority: &authority,
            controller_pid: U64::new(1),
            controller_uid: U64::new(1),
            controller_executable: &executable,
            hello_request_literal: &[],
            hello_response_literal: &[],
        };
        let row = normalized_ack_window_data(&bindings, usize::MAX)?;
        let selection = value_phase(&birth["source_binding"]["selection"], usize::MAX)?;
        assert_eq!(row.selection_encoded_bytes, selection.encoded);
        let expected_policy = policy_phase(&birth["source_binding"], &authority, usize::MAX)?;
        let expected_registration = registration_phase("native", "native", &authority, usize::MAX)?;
        let actual_registration = value_phase(&native, usize::MAX)?;
        assert!(
            row.requested_storage_bytes
                >= sum(&[
                    expected_policy.retained_value,
                    "host".len(),
                    expected_registration.retained_value,
                    actual_registration.dynamic,
                    expected_registration.dynamic,
                ])?
        );
        let exact = row
            .requested_storage_bytes
            .checked_add(row.declared_counter_scratch_bytes)
            .ok_or_else(refused)?;
        assert_eq!(normalized_ack_window_data(&bindings, exact)?, row);
        assert!(normalized_ack_window_data(&bindings, exact - 1).is_err());

        // Decode allocates its entire output estimate before discovering the
        // first invalid symbol. The borrowed source remains unchanged on error.
        let mut malformed_birth = birth.clone();
        malformed_birth["birth_id"] = Value::String("!".repeat(8193));
        let malformed_bindings = HistoricalAckBindings17 {
            birth_association: &malformed_birth,
            ..bindings
        };
        let malformed_row = normalized_ack_window_data(&malformed_bindings, usize::MAX)?;
        let encoded = malformed_birth["birth_id"].as_str().ok_or_else(refused)?;
        let estimated = (encoded.len() / 4 + usize::from(encoded.len() % 4 != 0)) * 3;
        assert!(malformed_row.requested_storage_bytes >= encoded.len() + estimated);
        assert!(Bytes::deserialize(&malformed_birth["birth_id"]).is_err());
        assert_eq!(
            malformed_birth["birth_id"].as_str().map(str::len),
            Some(8193)
        );

        let mut malformed_birth = birth.clone();
        malformed_birth["private_launch"] = Value::String("!".repeat(16384));
        malformed_birth["host_executable"]["hash"]["algorithm"] = Value::String("a".repeat(16384));
        malformed_birth["host_executable"]["length"] = Value::String("invalid".repeat(4096));
        let malformed_bindings = HistoricalAckBindings17 {
            birth_association: &malformed_birth,
            ..bindings
        };
        let scalar = scalar_window_data(
            &malformed_bindings,
            expected_policy.retained_value,
            usize::MAX,
        )?;
        assert!(scalar >= value_phase(&malformed_birth["private_launch"], usize::MAX)?.dynamic);
        assert!(scalar >= value_phase(&malformed_birth["host_executable"], usize::MAX)?.dynamic);
        assert!(Id::deserialize(&malformed_birth["private_launch"]).is_err());
        assert!(ContentRef::deserialize(&malformed_birth["host_executable"]).is_err());
        assert!(
            normalized_ack_window_data(&malformed_bindings, usize::MAX)?.requested_storage_bytes
                >= scalar + 33
        );
        Ok(())
    }
}
