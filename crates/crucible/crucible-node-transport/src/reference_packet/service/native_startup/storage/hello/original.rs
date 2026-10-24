//! Separates the original Hello's retained owners and returning work phases.
//!
//! Arbitrary input retains the unchanged 64 KiB raw parser. Only the actual
//! locally generated result uses a closed projection. The constructor drops
//! typed claims before publication and all Hello locals before policy birth.

use super::super::*;
use crate::handshake::{HelloRequest, HelloResult, ResumeSession};

use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};
use crucible_node_format::{ExtensionSelection, Id};

pub(super) struct HelloStorage {
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
}

fn generated_result(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let feature_count = hello_selection::feature_count_bound(&launch.selection.provider)?;
    let mut result = Projection::new(maximum)?;
    result.add_object()?;
    for field in [
        "version",
        "session_id",
        "incarnation_id",
        "controller_nonce",
        "provider_nonce",
        "selected_features",
        "limits",
        "resume_token",
        "provider_identity",
        "resumed_operations",
    ] {
        result.add_field(field)?;
    }
    result.add_string("CNP/1")?;
    result.add_value(&binding.authority.session_id)?;
    result.add_value(&binding.authority.incarnation_id)?;
    result.add_unescaped_ascii_extent(43)?;
    result.add_unescaped_ascii_extent(43)?;
    result.add_array_extent(feature_count)?;
    for _ in 0..feature_count {
        result.add_string_extent(128)?;
    }
    result.add_value(&launch.limits)?;
    result.add_value(&Option::<bool>::None)?;
    result.add_value(&launch.selection.provider)?;
    result.add_array_extent(0)?;
    result.finish(maximum)
}

pub(super) fn project(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<HelloStorage, ProviderError> {
    project_with_raw(
        input.launch,
        input.host_registration,
        original_json_value_storage_extent_data(NATIVE_HELLO_BYTES)?,
        maximum,
    )
}

pub(super) fn project_with_raw(
    launch: &PacketNative5SourceLaunch,
    registration_bytes: &[u8],
    raw: crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
    maximum: usize,
) -> Result<HelloStorage, ProviderError> {
    let result = generated_result(launch, maximum)?;
    // Request arrays contain String/Id; arbitrary extensions retain complete
    // Value geometry. Resume is inline, not a full DTO per raw token.
    let element = size_of::<String>()
        .max(size_of::<Id>())
        .max(size_of::<serde_json::Value>());
    let slots = raw
        .maximum_value_nodes
        .checked_mul(4)
        .and_then(|n| n.checked_add(4 * 64))
        .ok_or_else(refused)?;
    let typed_request = sum(
        &[
            raw.value_dom_requested_bytes,
            slots.checked_mul(element).ok_or_else(refused)?,
            raw.maximum_decoded_string_bytes
                .checked_mul(8)
                .ok_or_else(refused)?,
            size_of::<HelloRequest>(),
            size_of::<ResumeSession>(),
        ],
        maximum,
    )?;
    let mut validation = MetadataObserver::new();
    validation.tree::<&Id, ()>(raw.maximum_value_nodes)?;
    validation.tree::<&String, ()>(raw.maximum_value_nodes)?;
    validation.vector::<&Id>(slots)?;
    let validation = sum(
        &[
            requested_metadata_backing_storage_data(&validation.finish())?,
            4096,
        ],
        maximum,
    )?;
    // Actual decode_bounded checks aggregate roster cardinality BEFORE typed
    // extension decoding. Malformed partial fields still get 256 full slots
    // and every possible raw string byte. No expected-peer equality is assumed.
    let extensions = sum(
        &[
            crate::handshake::MAXIMUM_NEGOTIATED_EXTENSIONS
                .checked_mul(4)
                .and_then(|n| n.checked_mul(size_of::<ExtensionSelection>()))
                .ok_or_else(refused)?,
            raw.maximum_decoded_string_bytes
                .checked_mul(8)
                .ok_or_else(refused)?,
            size_of::<crate::handshake::ExtensionOfferV1>(),
            size_of::<crate::handshake::ExtensionSelectionV1>(),
        ],
        maximum,
    )?;
    // The full actual registration DOM dominates Id/String/Vec/Set backing;
    // explicit authority headers remain counted independently of phase roots.
    let registration = decoded::quote(
        registration_bytes,
        size_of::<crate::handshake::ConnectionAuthority>(),
        size_of::<serde_json::Value>(),
        maximum,
    )?
    .typed_backing;
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let feature_count = hello_selection::feature_count_bound(&launch.selection.provider)?;
    let roster_capacity = feature_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(4))
        .ok_or_else(refused)?;
    let mut rosters = MetadataObserver::new();
    for _ in 0..6 {
        rosters.vector::<Id>(roster_capacity)?;
    }
    let retained = sum(
        &[
            registration.checked_mul(11).ok_or_else(refused)?,
            requested_metadata_backing_storage_data(&rosters.finish())?,
            feature_count.checked_mul(6 * 128).ok_or_else(refused)?,
            metadata_backing(&launch.selection.provider)?,
            metadata_backing(&binding.compatibility.guarantees_ref)?,
            128, // Independent Admit Id; the nonce clone is transient below.
        ],
        maximum,
    )?;

    let dom = raw.value_dom_requested_bytes;
    // First canonical argument drops before the first typed request exists.
    let normalization = sum(&[raw.canonical_pass_requested_bytes()?, dom], maximum)?;
    // Three independent DOMs plus actual typed claims and generated result.
    let negotiation = sum(
        &[
            dom,
            dom,
            dom,
            typed_request,
            validation,
            extensions,
            result.requested_total()?,
            result.retained_value_backing_bytes,
            3 * (32 + 43),
            raw.maximum_canonical_encoded_bytes,
        ],
        maximum,
    )?;
    // Typed claims are explicitly dropped after all guards and before publish.
    // The outer/request/response/projected response Value banks persist here.
    let publication = sum(
        &[
            dom,
            dom,
            dom,
            dom,
            raw.canonical_work_requested_bytes,
            raw.canonical_output_requested_bytes,
            result.requested_total()?,
            result.requested_total()?,
            size_of::<crate::ProviderError>(),
            size_of::<std::io::Error>(),
        ],
        maximum,
    )?;
    let transient = normalization.max(negotiation).max(publication);
    let scratch = sum(
        &[
            size_of::<HelloStorage>(),
            hello_selection::counter_scratch_data(),
            size_of::<
                crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
            >(),
            size_of::<HelloRequest>(),
            size_of::<HelloResult>(),
            size_of::<Projection>(),
            size_of::<OriginalSerializationStorageData>(),
            2 * size_of::<MetadataObserver<'static>>(),
            2 * size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>(),
            size_of::<[usize; 19]>(),
            crate::handshake::Handshake::original_native_hello_reuse_counter_scratch_data(),
        ],
        maximum,
    )?;
    Ok(HelloStorage {
        retained,
        transient,
        scratch,
    })
}

mod hello_selection {
    use super::*;
    use crucible_node_format::ProviderManifest;
    /// Bounds the old compiled subset and the invocation's actual declaration.
    ///
    /// # Errors
    /// Refuses overflow while adding the two independently required core features.
    pub(super) fn feature_count_bound(provider: &ProviderManifest) -> Result<usize, ProviderError> {
        provider
            .extensions_supported
            .len()
            .checked_add(2)
            .map(|count| count.max(19))
            .ok_or_else(refused)
    }

    fn refused() -> ProviderError {
        ProviderError::Correlation(
            "native invocation Hello registration differs from installed declaration",
        )
    }
    pub(super) fn counter_scratch_data() -> usize {
        crate::reference_packet::service::server::complete::hello_selection::counter_scratch_data()
    }
}
