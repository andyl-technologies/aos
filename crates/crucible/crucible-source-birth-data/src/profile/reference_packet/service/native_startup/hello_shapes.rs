//! Shares original Hello storage arithmetic over real portable inputs.
//!
//! Original-capacity records are independently captured/committed by the parent;
//! equal decoded content cannot reconstruct them. Fixed layouts come from the
//! genuine upper types. No numeric report grants a connection, Source or native
//! owner, authenticates an observation or changes negotiation selection.

use crate::ProviderError;
use crate::profile::reference_packet::service::PacketNative5LaunchValidationFields;
use crate::profile::serialization_storage::{
    OriginalJsonValueStorageExtentData, OriginalSerializationStorageData,
    OriginalSerializationStorageProjection as Projection, RetainedProtocolMetadataFacts,
};
use crucible_node_format::{Id, ProviderManifest};
use std::mem::size_of;

/// Reports the original three separately counted Hello components.
pub struct HelloStorage {
    /// Counts the independently retained Hello owner components.
    pub retained: usize,
    /// Bounds the original simultaneous returning Hello work phases.
    pub transient: usize,
    /// Reports the original counter terms plus genuine new helper controls.
    pub scratch: usize,
}

/// Bounds each peer's complete exact definition roster.
pub const MAXIMUM_NEGOTIATED_EXTENSIONS: usize = 256;

/// Carries widths of actual private upper Hello representations.
///
/// These are compiled facts, not Rust layout replicas, observed capacities or
/// final resource rows. The actual parent independently remeasures this input.
#[derive(Clone, Copy)]
pub struct HelloHeaderLayoutData {
    /// Gives the genuine HelloRequest width.
    pub hello_request_bytes: usize,
    /// Gives the genuine inline ResumeSession width.
    pub resume_session_bytes: usize,
    /// Gives the genuine ExtensionOfferV1 width.
    pub extension_offer_bytes: usize,
    /// Gives the genuine ExtensionSelectionV1 width.
    pub extension_selection_bytes: usize,
    /// Gives the genuine ConnectionAuthority width.
    pub connection_authority_bytes: usize,
    /// Gives the genuine HelloResult width.
    pub hello_result_bytes: usize,
    /// Gives the genuine upper MetadataObserver width.
    pub metadata_observer_bytes: usize,
}

/// Joins genuine private headers with the two original fixed-counter getters.
///
/// Both counter values are static compiled header calculations. They are not
/// dynamic backing measurements or a supplied final Hello retained/work row.
/// Job/input/code binding and same-original remeasurement remain upper duties.
pub struct HelloFixedLayoutData {
    /// Carries only genuine compiled upper header widths.
    pub headers: HelloHeaderLayoutData,
    /// Carries the original hello_selection::counter_scratch_data result.
    pub hello_selection_counter_scratch_bytes: usize,
    /// Carries the original Handshake reuse-counter result.
    pub hello_reuse_counter_scratch_bytes: usize,
}

/// Bounds the old compiled subset and the invocation's actual declaration.
///
/// # Errors
/// Refuses overflow while adding the two independently required core features.
pub fn feature_count_bound(provider: &ProviderManifest) -> Result<usize, ProviderError> {
    provider
        .extensions_supported
        .len()
        .checked_add(2)
        .map(|count| count.max(19))
        .ok_or_else(feature_count_refused)
}

fn feature_count_refused() -> ProviderError {
    ProviderError::Correlation(
        "native invocation Hello registration differs from installed declaration",
    )
}

/// Projects the actual locally generated Hello result grammar.
///
/// # Errors
/// Preserves the original binding, feature, projection-limit and overflow errors.
pub fn generated_result(
    launch: &PacketNative5LaunchValidationFields<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let feature_count = feature_count_bound(&launch.selection.provider)?;
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
    result.add_value(launch.limits)?;
    result.add_value(&Option::<bool>::None)?;
    result.add_value(&launch.selection.provider)?;
    result.add_array_extent(0)?;
    result.finish(maximum)
}

/// Counts the original three fresh validation populations and fixed4096 phase.
///
/// This performs no observation of input capacities or owner authentication.
///
/// # Errors
/// Preserves original metadata arithmetic and requested-storage ceiling errors.
pub fn validation_backing(
    nodes: usize,
    slots: usize,
    maximum: usize,
) -> Result<usize, ProviderError> {
    use std::mem::align_of;
    let mut facts = RetainedProtocolMetadataFacts::default();
    let entries = nodes;
    size_of::<&Id>()
        .checked_add(size_of::<()>())
        .ok_or(crate::profile::metadata_population::overflow())?;
    crate::profile::metadata_population::record_unprofiled_data(&mut facts)?;
    let observed: Result<(), ProviderError> =
        crate::source_birth_metadata_tree_population!(facts, entries, &Id, ());
    observed?;
    size_of::<&String>()
        .checked_add(size_of::<()>())
        .ok_or(crate::profile::metadata_population::overflow())?;
    crate::profile::metadata_population::record_unprofiled_data(&mut facts)?;
    let observed: Result<(), ProviderError> =
        crate::source_birth_metadata_tree_population!(facts, entries, &String, ());
    observed?;
    let capacity = slots;
    crate::profile::metadata_population::record_unprofiled_data(&mut facts)?;
    let observed: Result<(), ProviderError> =
        crate::source_birth_metadata_vector_population!(facts, capacity, &Id);
    observed?;
    sum(
        &[
            crate::profile::requested_storage::requested_metadata_backing_storage_data(&facts)?,
            4096,
        ],
        maximum,
    )
}

/// Counts the original six independently retained Id roster banks.
///
/// # Errors
/// Preserves the original metadata population and backing overflow errors.
pub fn roster_backing(capacity: usize) -> Result<usize, ProviderError> {
    let mut facts = RetainedProtocolMetadataFacts::default();
    for _ in 0..6 {
        crate::profile::metadata_population::record_unprofiled_data(&mut facts)?;
        let observed: Result<(), ProviderError> =
            crate::source_birth_metadata_vector_population!(facts, capacity, Id);
        observed?;
    }
    crate::profile::requested_storage::requested_metadata_backing_storage_data(&facts)
}

/// Applies the original checked Hello component sum at its original phase.
///
/// # Errors
/// Refuses the same checked overflow or supplied requested-storage ceiling.
pub fn sum(values: &[usize], maximum: usize) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(*bytes)
            .filter(|total| *total <= maximum)
            .ok_or_else(refused)
    })
}

/// Constructs the original native baseline requested-storage refusal.
pub fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native baseline requested storage")
}

/// Expands the sole original Hello arithmetic at its real query positions.
///
/// Expression slots preserve the actual upper observer and fixed-getter calls;
/// lower DATA uses committed primitive observations at those exact same slots.
/// This is source sharing, not an erased callback, wire descriptor or authority.
#[macro_export]
macro_rules! source_birth_native_hello_storage {
    ($launch:ident, $registration_bytes:ident, $raw:ident, $maximum:ident, $fixed:ident, $binding:ident,
     $generated_result:expr, $provider_backing:expr, $guarantees_backing:expr,
     $selection_scratch:expr, $reuse_scratch:expr, $additional_scratch:expr) => {{
        use ::crucible_node_format::{ExtensionSelection, Id};
        use ::std::mem::size_of;
        use $crate::profile::reference_packet::service::native_startup::hello_shapes as shared;
        use $crate::profile::serialization_storage::{
            OriginalJsonValueStorageExtentData, OriginalSerializationStorageData,
            OriginalSerializationStorageProjection as Projection, RetainedProtocolMetadataFacts,
        };
        use $crate::{ProviderError, decoded_occurrences as decoded};

        let result = $generated_result;
        // Request arrays contain String/Id; arbitrary extensions retain complete
        // Value geometry. Resume is inline, not a full DTO per raw token.
        let element = size_of::<String>()
            .max(size_of::<Id>())
            .max(size_of::<serde_json::Value>());
        let slots = $raw
            .maximum_value_nodes
            .checked_mul(4)
            .and_then(|n| n.checked_add(4 * 64))
            .ok_or_else(shared::refused)?;
        let typed_request = shared::sum(
            &[
                $raw.value_dom_requested_bytes,
                slots.checked_mul(element).ok_or_else(shared::refused)?,
                $raw.maximum_decoded_string_bytes
                    .checked_mul(8)
                    .ok_or_else(shared::refused)?,
                $fixed.hello_request_bytes,
                $fixed.resume_session_bytes,
            ],
            $maximum,
        )?;
        let validation = shared::validation_backing($raw.maximum_value_nodes, slots, $maximum)?;
        // Actual decode_bounded checks aggregate roster cardinality BEFORE typed
        // extension decoding. Malformed partial fields still get 256 full slots
        // and every possible raw string byte. No expected-peer equality is assumed.
        let extensions = shared::sum(
            &[
                shared::MAXIMUM_NEGOTIATED_EXTENSIONS
                    .checked_mul(4)
                    .and_then(|n| n.checked_mul(size_of::<ExtensionSelection>()))
                    .ok_or_else(shared::refused)?,
                $raw.maximum_decoded_string_bytes
                    .checked_mul(8)
                    .ok_or_else(shared::refused)?,
                $fixed.extension_offer_bytes,
                $fixed.extension_selection_bytes,
            ],
            $maximum,
        )?;
        // The full actual registration DOM dominates Id/String/Vec/Set backing;
        // explicit authority headers remain counted independently of phase roots.
        let registration = decoded::quote(
            $registration_bytes,
            $fixed.connection_authority_bytes,
            size_of::<serde_json::Value>(),
            $maximum,
        )?
        .typed_backing;
        let [$binding] = $launch.selection.realization.bindings.as_slice() else {
            return Err(shared::refused());
        };
        let feature_count = shared::feature_count_bound(&$launch.selection.provider)?;
        let roster_capacity = feature_count
            .checked_mul(2)
            .and_then(|count| count.checked_add(4))
            .ok_or_else(shared::refused)?;
        let rosters = shared::roster_backing(roster_capacity)?;
        let retained = shared::sum(
            &[
                registration.checked_mul(11).ok_or_else(shared::refused)?,
                rosters,
                feature_count
                    .checked_mul(6 * 128)
                    .ok_or_else(shared::refused)?,
                $provider_backing,
                $guarantees_backing,
                128, // Independent Admit Id; the nonce clone is transient below.
            ],
            $maximum,
        )?;

        let dom = $raw.value_dom_requested_bytes;
        // First canonical argument drops before the first typed request exists.
        let normalization = shared::sum(&[$raw.canonical_pass_requested_bytes()?, dom], $maximum)?;
        // Three independent DOMs plus actual typed claims and generated result.
        let negotiation = shared::sum(
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
                $raw.maximum_canonical_encoded_bytes,
            ],
            $maximum,
        )?;
        // Typed claims are explicitly dropped after all guards and before publish.
        // The outer/request/response/projected response Value banks persist here.
        let publication = shared::sum(
            &[
                dom,
                dom,
                dom,
                dom,
                $raw.canonical_work_requested_bytes,
                $raw.canonical_output_requested_bytes,
                result.requested_total()?,
                result.requested_total()?,
                size_of::<ProviderError>(),
                size_of::<std::io::Error>(),
            ],
            $maximum,
        )?;
        let transient = normalization.max(negotiation).max(publication);
        let scratch = shared::sum(
            &[
                size_of::<shared::HelloStorage>(),
                $selection_scratch,
                size_of::<OriginalJsonValueStorageExtentData>(),
                $fixed.hello_request_bytes,
                $fixed.hello_result_bytes,
                size_of::<Projection>(),
                size_of::<OriginalSerializationStorageData>(),
                $fixed
                    .metadata_observer_bytes
                    .checked_mul(2)
                    .ok_or_else(shared::refused)?,
                2 * size_of::<RetainedProtocolMetadataFacts>(),
                size_of::<[usize; 19]>(),
                $reuse_scratch,
                $additional_scratch,
            ],
            $maximum,
        )?;
        Ok(shared::HelloStorage {
            retained,
            transient,
            scratch,
        })
    }};
}

/// Runs the same Hello arithmetic over genuine committed original observations.
///
/// These records do not authenticate provenance. The actual parent binds all
/// inputs to its original Job and remeasures every field before acceptance.
/// No fresh decoded owner's capacities replace original observed capacities.
///
/// # Errors
/// Preserves the original guard, metadata, decoded-shape and limit refusals;
/// refuses absent guarantees only after the original singleton binding guard.
pub fn project_with_raw(
    launch: &PacketNative5LaunchValidationFields<'_>,
    registration_bytes: &[u8],
    raw: OriginalJsonValueStorageExtentData,
    layouts: &HelloFixedLayoutData,
    provider: &RetainedProtocolMetadataFacts,
    guarantees: Option<&RetainedProtocolMetadataFacts>,
    maximum: usize,
) -> Result<HelloStorage, ProviderError> {
    let fixed = &layouts.headers;
    crate::source_birth_native_hello_storage!(
        launch,
        registration_bytes,
        raw,
        maximum,
        fixed,
        _binding,
        generated_result(launch, maximum)?,
        crate::profile::requested_storage::requested_metadata_backing_storage_data(provider)?,
        crate::profile::requested_storage::requested_metadata_backing_storage_data(
            guarantees.ok_or_else(refused)?
        )?,
        layouts.hello_selection_counter_scratch_bytes,
        layouts.hello_reuse_counter_scratch_bytes,
        additional_counter_scratch_data()
    )
}

/// Counts the genuine new helper controls without private layout stand-ins.
///
/// Old scratch terms remain independent. The Fields adapter family is only
/// used by upper generated_result; lower inputs and metadata facts keep their
/// separate real loans. This conservative union contains no backing allowance.
pub const fn additional_counter_scratch_data() -> usize {
    3 * size_of::<PacketNative5LaunchValidationFields<'static>>()
        + 2 * size_of::<&PacketNative5LaunchValidationFields<'static>>()
        + size_of::<&crate::profile::reference_packet::service::PacketNative5SourceLaunch>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + 2 * size_of::<&HelloHeaderLayoutData>()
        + 2 * size_of::<RetainedProtocolMetadataFacts>()
        + 2 * size_of::<&mut RetainedProtocolMetadataFacts>()
        + 2 * size_of::<Result<(), ProviderError>>()
        + 3 * size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        // Separate by-value nodes, slots and maximum helper inputs.
        // The caller raw/slots/maximum remain live; none is a donor.
        + 3 * size_of::<usize>()
        + size_of::<[usize; 2]>()
        + size_of::<usize>()
        + size_of::<&HelloFixedLayoutData>()
        + size_of::<&RetainedProtocolMetadataFacts>()
        + size_of::<Option<&RetainedProtocolMetadataFacts>>()
}

/// Counts only the new fixed-layout export initializer/return/retained windows.
///
/// The operational parent export must admit this actual header family before
/// reading the two original fixed getters; this value grants no Source loan.
pub const fn fixed_layout_export_counter_scratch_data() -> usize {
    3 * size_of::<HelloFixedLayoutData>()
        + size_of::<HelloHeaderLayoutData>()
        + 2 * size_of::<usize>()
}
