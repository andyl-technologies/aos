//! Prices the old mapping/12 normalization from the real planned registration.
//!
//! This prebirth DATA contains no lease, nonce, mapping, target or installation
//! permission. The Source retains the exact planned registration and compares
//! it with the actual post-Hello authority before signing the existing route.
//!
//! ```text
//! [mapping/12, controller_ref, native_ref, controller/11, connection/11,
//!  invocation_connection/15, invocation_service/15,
//!  [authority/11, connection, session, incarnation, epoch, limits, features,
//!   envelope_extensions, extensions, retained_registration_marker],
//!  nonce32, retained_cut_marker]
//! ```

use super::*;
use crate::protocol_snapshot::owned11::json_value::{
    borrowed_json_string_storage_counter_scratch_data, borrowed_json_string_storage_data,
};
use crate::protocol_snapshot::owned11::{
    OriginalOwned11Fields as Fields, original_owned11_plain_string as plain_string,
    original_owned11_unsigned as unsigned,
};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};
use crucible_node_contract::canonical;
use std::mem::size_of;

/// Retains the independently derived old normalization bank and constructor axes.
///
/// These private numeric fields describe one future Value/canonical/hash pass.
/// They are not an admission token or proof that any future registration or
/// normalization belongs to the Source. The genuine caller preserves its actual
/// target, ticket, archive and planned-registration associations independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Initial15MappingNormalizationConstructionData {
    maximum_encoded: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl Initial15MappingNormalizationConstructionData {
    /// Returns the selected encoded bound derived from the actual field grammar.
    pub const fn normalization_maximum_bytes_data(&self) -> usize {
        self.maximum_encoded
    }

    /// Returns independent bank, constructor and fixed workspace requests.
    ///
    /// The retained term bounds the canonical output bank and its new fullref.
    /// The transient term independently covers the Value/JCS/hash construction;
    /// it does not reuse the retained bank or any prior archive decoder credit.
    pub const fn requested_storage_data(&self) -> [usize; 3] {
        [self.retained, self.transient, self.scratch]
    }
}

struct Registration<'a> {
    connection: &'a [u8],
    envelope_extensions: &'a [u8],
    extensions: &'a [u8],
    features: &'a [u8],
    incarnation: &'a [u8],
    limits: &'a [u8],
    session: &'a [u8],
}

impl PreparedArchivedProtocolMapping {
    /// Names the exact prebirth span, projection, hash and result controls.
    ///
    /// This is admitted before the borrowed registration walk. It neither
    /// serializes values nor creates a registration, mapping or byte bank.
    pub fn initial15_normalization_counter_scratch_data() -> usize {
        Fields::counter_scratch_data()
            + borrowed_json_string_storage_counter_scratch_data()
            + original_serialization_counter_scratch_data()
            + 5 * size_of::<Fields<'static>>()
            + 5 * size_of::<Result<Fields<'static>, ProviderError>>()
            + size_of::<Registration<'static>>()
            + size_of::<Result<Registration<'static>, ProviderError>>()
            + size_of::<Projection>()
            + size_of::<OriginalSerializationStorageData>()
            + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
            + size_of::<Initial15MappingNormalizationConstructionData>()
            + size_of::<Result<Initial15MappingNormalizationConstructionData, ProviderError>>()
            // project_mapping's formats and project_authority's actual ID spans.
            + size_of::<[&str; 4]>()
            + size_of::<std::array::IntoIter<&'static str, 4>>()
            + size_of::<[&[u8]; 3]>()
            + size_of::<std::array::IntoIter<&'static [u8], 3>>()
            // The limits loop and the distinct hash/version field loops.
            + size_of::<[&str; 5]>()
            + size_of::<std::array::IntoIter<&'static str, 5>>()
            + 2 * size_of::<[&str; 3]>()
            + 2 * size_of::<std::array::IntoIter<&'static str, 3>>()
            + size_of::<(&mut Projection, &[u8])>()
            + size_of::<fn(&mut Projection, &[u8]) -> Result<(), ProviderError>>()
            // Full-row sum inputs and the constructor's independent scalar locals.
            + size_of::<[usize; 3]>()
            + size_of::<[usize; 7]>()
            + size_of::<[usize; 5]>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(usize, usize), ProviderError>>()
            + size_of::<Option<&[u8]>>()
            + size_of::<Result<Option<&[u8]>, ProviderError>>()
            + size_of::<Result<u64, ProviderError>>()
            + size_of::<std::num::ParseIntError>()
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<std::ops::Range<usize>>()
            + size_of::<crucible_node_contract::ContentRef>()
            + size_of::<crucible_node_contract::HashRef>()
            + size_of::<Result<crucible_node_contract::HashRef, ProviderError>>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + hash_hex_header_bytes()
            + size_of::<[u8; 20]>()
            + size_of::<Result<(), ProviderError>>()
            + normalization_serializer_counter_scratch_data()
    }

    /// Declares the formatter floor before constructing the prospective row.
    ///
    /// The projection walks borrowed spans and plain primitive scalars. The
    /// twenty-byte decimal window also covers older U64 formatter implementations;
    /// no Bytes serializer or base64 formatter is invoked by this prequote.
    pub fn initial15_normalization_prewalk_data() -> (usize, usize) {
        (20, Self::initial15_normalization_counter_scratch_data())
    }

    /// Quotes mapping/12 before constructing the actual fresh Controller or lease.
    ///
    /// `registration` is the genuine target Source's retained canonical planned
    /// controller registration. Its actual IDs, limits, feature names, complete
    /// extension selections and envelope names determine the projection. The
    /// supported Source route requires `selected_extensions() == Some(...)`,
    /// including an empty selected roster: its post-Hello registration validator
    /// refuses None before any mapping construction. Plain-Handshake mappings
    /// with None are outside this row's scope. The eventual authority epoch uses
    /// its defining U64 decimal extent, and each
    /// of the fixed thirty-two nonce bytes uses its u8 decimal extent. Neither
    /// bound is an invented future value or portable authority constructor.
    ///
    /// The caller first admits the prewalk, then independently admits this full
    /// row alongside every existing owner. It must bind both references to the
    /// actual archived controller/native loans, preserve the same target Source,
    /// and later enforce the unchanged mapping/12 authentication and byte bound.
    ///
    /// # Errors
    /// Refuses a different planned registration grammar, malformed closed field,
    /// overflow, demand above `maximum_requested`, or a derived encoded bound
    /// outside the unchanged one-through-65536 mapping grammar.
    pub fn initial15_normalization_construction_data(
        archive_protocol: &ContentRef,
        native_protocol: &ContentRef,
        registration: &[u8],
        maximum_requested: usize,
    ) -> Result<Initial15MappingNormalizationConstructionData, ProviderError> {
        let planned = registration_fields(registration)?;
        let mut projection = Projection::new(maximum_requested)?;
        project_mapping(&mut projection, archive_protocol, native_protocol, &planned)?;
        let geometry = projection.finish(maximum_requested)?;
        if geometry.maximum_encoded_bytes == 0 || geometry.maximum_encoded_bytes > 65_536 {
            return Err(exhausted());
        }

        // The complete canonical output and its independently allocated fullref
        // remain in the future Source bank. Hash strings are fixed by cnp.blob.v1.
        let reference_backing =
            "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len();
        let retained = sum(&[
            geometry.canonical_output_requested_bytes,
            size_of::<ContentRef>(),
            reference_backing,
        ])?;
        let transient = sum(&[
            geometry.requested_total()?,
            size_of::<serde_json::Value>(),
            size_of::<ContentRef>(),
            size_of::<crucible_node_contract::HashRef>(),
            reference_backing,
            size_of::<blake3::Hasher>(),
            size_of::<blake3::Hash>(),
        ])?;
        let scratch = Self::initial15_normalization_counter_scratch_data();
        if sum(&[retained, transient, scratch])? > maximum_requested {
            return Err(exhausted());
        }
        Ok(Initial15MappingNormalizationConstructionData {
            maximum_encoded: geometry.maximum_encoded_bytes,
            retained,
            transient,
            scratch,
        })
    }
}

fn registration_fields(input: &[u8]) -> Result<Registration<'_>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let connection = fields.named("connection_id")?;
    let envelope_extensions = fields.named("envelope_extensions")?;
    let extensions = fields.named("extensions")?;
    let features = fields.named("features")?;
    let incarnation = fields.named("incarnation_id")?;
    let limits = fields.named("limits")?;
    if fields.named("role")? != br#""controller""#
        || fields.named("schema")? != br#""source-owned.packet-canonical-ack-registration/5""#
    {
        return Err(invalid());
    }
    let session = fields.named("session_id")?;
    fields.finish()?;
    Ok(Registration {
        connection,
        envelope_extensions,
        extensions,
        features,
        incarnation,
        limits,
        session,
    })
}

fn project_mapping(
    projection: &mut Projection,
    archive: &ContentRef,
    native: &ContentRef,
    registration: &Registration<'_>,
) -> Result<(), ProviderError> {
    use owned11::{native::outer as native_formats, outer};
    projection.add_array_extent(10)?;
    projection.add_string("source-private.archived-protocol-mapping/12")?;
    projection.add_value(archive)?;
    projection.add_value(native)?;
    for format in [
        outer::COMPLETE_CONTROLLER_FORMAT,
        outer::COMPLETE_CONNECTION_FORMAT,
        native_formats::COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT,
        native_formats::COMPLETE_NATIVE_INVOCATION_SERVICE_FORMAT,
    ] {
        projection.add_string(format)?;
    }
    project_authority(projection, registration)?;
    // A nonce is exactly [u8;32], serialized as thirty-two JSON integers. Count
    // every numeric slot independently at its type maximum; construct no nonce.
    projection.add_array_extent(32)?;
    for _ in 0..32 {
        projection.add_value(&u8::MAX)?;
    }
    projection.add_string("original-fresh-request-cut-retained")
}

fn project_authority(
    projection: &mut Projection,
    registration: &Registration<'_>,
) -> Result<(), ProviderError> {
    projection.add_array_extent(10)?;
    projection.add_string("source-private.connection-authority/11")?;
    for value in [
        registration.connection,
        registration.session,
        registration.incarnation,
    ] {
        project_string(projection, value)?;
    }
    // A future actual lease epoch is unavailable prebirth. Its fixed U64 type
    // admits at most twenty unescaped decimal digits; no lease is fabricated.
    projection.add_unescaped_ascii_extent(20)?;
    project_limits(projection, registration.limits)?;
    project_array(projection, registration.features, project_string)?;
    project_array(projection, registration.envelope_extensions, project_string)?;
    project_array(projection, registration.extensions, project_extension)?;
    projection.add_string("original-registration-backing-retained-by-opaque-source")
}

fn project_limits(projection: &mut Projection, input: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(input)?;
    projection.add_object()?;
    for name in [
        "blob_chunk_bytes",
        "frame_bytes",
        "journal_entries",
        "nesting",
        "requests",
    ] {
        projection.add_field(name)?;
        project_decimal(projection, fields.named(name)?)?;
    }
    fields.finish()
}

fn project_extension(projection: &mut Projection, input: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(input)?;
    projection.add_object()?;
    projection.add_field("declaration")?;
    project_reference(projection, fields.named("declaration")?)?;
    projection.add_field("identifier")?;
    project_string(projection, fields.named("identifier")?)?;
    projection.add_field("schema_digest")?;
    project_hash(projection, fields.named("schema_digest")?)?;
    projection.add_field("semantic_version")?;
    project_version(projection, fields.named("semantic_version")?)?;
    fields.finish()
}

fn project_reference(projection: &mut Projection, input: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(input)?;
    projection.add_object()?;
    projection.add_field("hash")?;
    project_hash(projection, fields.named("hash")?)?;
    projection.add_field("length")?;
    project_decimal(projection, fields.named("length")?)?;
    projection.add_field("media_type")?;
    project_string(projection, fields.named("media_type")?)?;
    fields.finish()
}

fn project_hash(projection: &mut Projection, input: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(input)?;
    projection.add_object()?;
    for name in ["algorithm", "digest", "domain"] {
        projection.add_field(name)?;
        project_string(projection, fields.named(name)?)?;
    }
    fields.finish()
}

fn project_version(projection: &mut Projection, input: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(input)?;
    projection.add_object()?;
    projection.add_field("build")?;
    project_optional_string(projection, fields.named("build")?)?;
    for name in ["major", "minor", "patch"] {
        projection.add_field(name)?;
        project_decimal(projection, fields.named(name)?)?;
    }
    projection.add_field("prerelease")?;
    project_optional_string(projection, fields.named("prerelease")?)?;
    fields.finish()
}

fn project_optional_string(projection: &mut Projection, input: &[u8]) -> Result<(), ProviderError> {
    if input == b"null" {
        projection.add_value(&())
    } else {
        project_string(projection, input)
    }
}

fn project_decimal(projection: &mut Projection, input: &[u8]) -> Result<(), ProviderError> {
    let text = plain_string(input)?;
    unsigned(text.as_bytes())?;
    project_string(projection, input)
}

fn project_string(projection: &mut Projection, input: &[u8]) -> Result<(), ProviderError> {
    let (decoded, encoded) = borrowed_json_string_storage_data(input)?;
    projection.add_verified_json_string_extent_data(decoded, encoded)
}

fn project_array(
    projection: &mut Projection,
    input: &[u8],
    element: fn(&mut Projection, &[u8]) -> Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut count = 0usize;
    while fields.next()?.is_some() {
        count = count.checked_add(1).ok_or_else(exhausted)?;
    }
    fields.finish()?;
    projection.add_array_extent(count)?;

    let mut fields = Fields::array(input)?;
    while let Some(value) = fields.next()? {
        element(projection, value)?;
    }
    fields.finish()
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(exhausted)
    })
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("Initial15 planned normalization registration grammar")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("Initial15 planned normalization construction")
}

fn hash_hex_header_bytes() -> usize {
    fn layout<T>(_: fn(&blake3::Hash) -> T) -> usize {
        size_of::<T>()
    }
    layout(blake3::Hash::to_hex)
}

// The normalization has at most six nested containers: root tuple, authority
// tuple, extensions, selection, declaration and hash. The private serde Value
// serializer's actual associated control types can be named without cloning it.
fn normalization_serializer_counter_scratch_data() -> usize {
    use crucible_node_contract::ContractError;
    use serde::Serializer;
    use serde_json::{Value, value::Serializer as ValueSerializer};
    use std::collections::BTreeMap;
    type Sequence = <ValueSerializer as Serializer>::SerializeSeq;
    type Tuple = <ValueSerializer as Serializer>::SerializeTuple;
    type Structure = <ValueSerializer as Serializer>::SerializeStruct;
    6 * (size_of::<Sequence>()
        + size_of::<Tuple>()
        + size_of::<Structure>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<&Value>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<BTreeMap<Vec<u16>, (&str, &Value)>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Value>>>()
        + size_of::<
            std::iter::Enumerate<
                std::collections::btree_map::Values<
                    'static,
                    Vec<u16>,
                    (&'static str, &'static Value),
                >,
            >,
        >()
        + size_of::<serde_json::map::Iter<'static>>())
        + size_of::<std::str::EncodeUtf16<'static>>()
        + size_of::<std::vec::Vec<u16>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, u8>>>()
        + size_of::<String>()
        + size_of::<Result<String, serde_json::Error>>()
        + size_of::<Result<Vec<u8>, ContractError>>()
        + size_of::<Result<ContentRef, ContractError>>()
        + size_of::<Result<crucible_node_contract::HashRef, ContractError>>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<(), ContractError>>()
        // The shared defining helper names actual pinned aligned sort storage,
        // controls and Ryu; this closed5-member shape is not called driftsort.
        + canonical::canonical_json_counter_scratch_bytes_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::MetadataObserver;
    use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;
    use crucible_node_contract::{ExtensionSelection, Id, SemanticVersion, U64};

    fn reference(body: &[u8]) -> ContentRef {
        canonical::content_ref(body, "application/json").unwrap()
    }

    #[test]
    fn real_closed_fields_bound_full_mapping_serializer_without_a_lease() {
        let archive = reference(b"actual archived controller bytes");
        let native = reference(b"actual archived native bytes");
        let declaration = reference(b"actual complete extension definition");
        let selections = [ExtensionSelection {
            declaration: declaration.clone(),
            identifier: Id::new("example.extension/1").unwrap(),
            semantic_version: SemanticVersion {
                major: U64::new(1),
                minor: U64::new(2),
                patch: U64::new(3),
                prerelease: Some("preview.4".into()),
                build: Some("actual.5".into()),
            },
            schema_digest: declaration.hash.clone(),
        }];
        let features = [
            Id::new("cnp.core/1").unwrap(),
            Id::new("example.feature/1").unwrap(),
        ];
        let envelope = ["example.extension/1", "example.other/2"];
        let limits = crate::handshake::Limits {
            frame_bytes: U64::new(65536),
            nesting: U64::new(64),
            requests: U64::new(16),
            journal_entries: U64::new(4096),
            blob_chunk_bytes: U64::new(4096),
        };
        let registration = serde_json::json!({
            "schema":"source-owned.packet-canonical-ack-registration/5", "role":"controller",
            "connection_id":"actual/connection", "session_id":"actual/session",
            "incarnation_id":"actual/incarnation", "limits":limits, "features":features,
            "extensions":selections, "envelope_extensions":envelope,
        });
        let bytes = canonical::canonical_json(&registration).unwrap();
        let row = PreparedArchivedProtocolMapping::initial15_normalization_construction_data(
            &archive,
            &native,
            &bytes,
            256 * 1024 * 1024,
        )
        .unwrap();

        for (epoch, nonce) in [(0, [0u8; 32]), (u64::MAX, [u8::MAX; 32])] {
            use owned11::{native::outer as native_formats, outer};
            // This is inert serializer test DATA, not ConnectionAuthority.
            let authority = (
                "source-private.connection-authority/11",
                "actual/connection",
                "actual/session",
                "actual/incarnation",
                U64::new(epoch),
                limits,
                &features,
                &envelope,
                Some(&selections),
                "original-registration-backing-retained-by-opaque-source",
            );
            let value = (
                "source-private.archived-protocol-mapping/12",
                &archive,
                &native,
                outer::COMPLETE_CONTROLLER_FORMAT,
                outer::COMPLETE_CONNECTION_FORMAT,
                native_formats::COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT,
                native_formats::COMPLETE_NATIVE_INVOCATION_SERVICE_FORMAT,
                authority,
                nonce,
                "original-fresh-request-cut-retained",
            );
            let encoded =
                canonical::canonical_json(&serde_json::to_value(&value).unwrap()).unwrap();
            let observer = MetadataObserver::new();
            // This exact tuple contains no Bytes serializer. Its known primitive
            // formatter row therefore has no byte-bank metadata occurrences.
            let actual =
                actual_serialization_storage_data(&value, observer.finish(), usize::MAX).unwrap();
            let [retained, transient, scratch] = row.requested_storage_data();

            assert!(encoded.len() <= row.normalization_maximum_bytes_data());
            assert!(actual.maximum_encoded_bytes <= row.normalization_maximum_bytes_data());
            assert!(actual.requested_total().unwrap() <= transient);
            assert!(encoded.capacity() <= retained);
            assert!(scratch >= PreparedArchivedProtocolMapping::initial15_normalization_counter_scratch_data());
        }
    }

    #[test]
    fn missing_unknown_wrong_role_and_overlong_actual_fields_refuse() {
        let reference = reference(b"same actual reference");
        let make = || {
            serde_json::json!({
                "schema":"source-owned.packet-canonical-ack-registration/5", "role":"controller",
                "connection_id":"a", "session_id":"b", "incarnation_id":"c",
                "limits":{"frame_bytes":"65536","nesting":"64","requests":"16",
                    "journal_entries":"4096","blob_chunk_bytes":"4096"},
                "features":[], "extensions":[], "envelope_extensions":[],
            })
        };
        let quote = |value: serde_json::Value| {
            let raw = canonical::canonical_json(&value).unwrap();
            PreparedArchivedProtocolMapping::initial15_normalization_construction_data(
                &reference,
                &reference,
                &raw,
                256 * 1024 * 1024,
            )
        };
        let mut missing = make();
        missing.as_object_mut().unwrap().remove("limits");
        let mut unknown = make();
        unknown["unexpected"] = serde_json::json!(true);
        let mut role = make();
        role["role"] = serde_json::json!("native");
        let mut oversized = make();
        oversized["connection_id"] = serde_json::json!("x".repeat(65536));

        assert!(quote(missing).is_err());
        assert!(quote(unknown).is_err());
        assert!(quote(role).is_err());
        assert!(quote(oversized).is_err());
        assert!(quote(make()).is_ok());
    }
}
