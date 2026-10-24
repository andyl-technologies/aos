//! Projects the original report literal shapes from actual nonsecret fields.
//!
//! These counters own no DOM, native state, socket or admission token. Unknown
//! future identifiers and counters retain the original closed wire extents.
//! Upper consumers retain model queries and evaluation order; these numeric
//! reports do not authenticate a launch or grant Source/native construction.

use crate::ProviderError;
use crate::profile::reference_packet::service::capture_allocation::*;
use crate::profile::reference_packet::service::{
    PacketConnectedSourceProgram, PacketNative5LaunchValidationFields,
};
use crate::profile::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
};

type Projection = OriginalSerializationStorageProjection;

/// Reports the six independent original Observe publication shapes.
pub struct OriginalObserveStartupShapes {
    /// Bounds the original Observe request.
    pub original: OriginalSerializationStorageData,
    /// Bounds the original completed Observe response.
    pub terminal: OriginalSerializationStorageData,
    /// Bounds the original native receipt and selected optional fields.
    pub receipt: OriginalSerializationStorageData,
    /// Bounds the original receipt and allocation-reference wrapper.
    pub wrapper: OriginalSerializationStorageData,
    /// Bounds the original capture allocation report.
    pub report: OriginalSerializationStorageData,
    /// Bounds the separately projected stopped or untouched raw inventory.
    pub raw: OriginalSerializationStorageData,
}

/// Owns the same raw inventory grammar without a model or native owner.
pub mod raw;

/// Counts one object and its actual fixed field names.
///
/// # Errors
/// Refuses the original tuple mismatch, projection limit or checked overflow.
pub fn object(projection: &mut Projection, keys: &[&str]) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in keys {
        projection.add_field(key)?;
    }
    Ok(())
}

/// Counts the original maximum decimal integer string.
///
/// # Errors
/// Refuses the original tuple mismatch, projection limit or checked overflow.
pub fn decimal(projection: &mut Projection) -> Result<(), ProviderError> {
    projection.add_unescaped_ascii_extent(20)
}

/// Counts the original admitted identifier extent.
///
/// # Errors
/// Refuses the original tuple mismatch, projection limit or checked overflow.
pub fn id(projection: &mut Projection) -> Result<(), ProviderError> {
    // Id::new accepts only [A-Za-z0-9][A-Za-z0-9._:/-]*, at most128 bytes.
    // Every admitted identifier therefore encodes without JSON escaping.
    projection.add_unescaped_ascii_extent(128)
}

/// Counts the original stopped inventory position.
///
/// # Errors
/// Refuses the original tuple mismatch, projection limit or checked overflow.
pub fn position(projection: &mut Projection) -> Result<(), ProviderError> {
    object(projection, &["time_ps", "microstep", "phase"])?;
    decimal(projection)?;
    decimal(projection)?;
    projection.add_value(&crucible_node_format::Phase::Reaction)
}

fn hash(projection: &mut Projection, domain: &str) -> Result<(), ProviderError> {
    object(projection, &["algorithm", "domain", "digest"])?;
    projection.add_string("blake3-256")?;
    projection.add_string(domain)?;
    projection.add_unescaped_ascii_extent(2 * blake3::OUT_LEN)
}

/// Counts the original content reference and media type.
///
/// # Errors
/// Refuses the original tuple mismatch, projection limit or checked overflow.
pub fn reference(projection: &mut Projection, media: &str) -> Result<(), ProviderError> {
    object(projection, &["hash", "length", "media_type"])?;
    hash(projection, "cnp.blob.v1")?;
    decimal(projection)?;
    projection.add_string(media)
}

fn envelope(
    projection: &mut Projection,
    launch: &PacketNative5LaunchValidationFields<'_>,
    response: bool,
) -> Result<(), ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    object(
        projection,
        &[
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
        ],
    )?;
    projection.add_string("CNP/1")?;
    projection.add_value(&if response {
        crate::profile::envelope::MessageKind::Response
    } else {
        crate::profile::envelope::MessageKind::Request
    })?;
    projection.add_string(binding.authority.session_id.as_str())?;
    projection.add_string(binding.authority.incarnation_id.as_str())?;
    projection.add_string(binding.compatibility.node_id.as_str())?;
    // A maximum-length Id also dominates explicit null, including its Value
    // slot. This does not assign an execution/capture/operation scope.
    for _ in 0..4 {
        id(projection)?;
    }
    decimal(projection)?;
    projection.add_value(&crate::profile::envelope::Method::Observe)
}

/// Counts the original Observe request grammar.
///
/// # Errors
/// Refuses the original tuple mismatch, projection limit or checked overflow.
pub fn original(
    projection: &mut Projection,
    launch: &PacketNative5LaunchValidationFields<'_>,
) -> Result<(), ProviderError> {
    envelope(projection, launch, false)?;
    object(
        projection,
        &[
            "binding_hash",
            "owner_generation",
            "after_observation_sequence",
            "maximum_items",
            "extensions",
        ],
    )?;
    hash(projection, "cnp.owner-binding.v1")?;
    for _ in 0..3 {
        decimal(projection)?;
    }
    projection.add_object()?;
    projection.add_object()
}

fn birth_metadata(projection: &mut Projection) -> Result<(), ProviderError> {
    object(projection, &["before", "after"])?;
    for _ in 0..2 {
        object(
            projection,
            &[
                "selected_rows",
                "record_capacity",
                "record_bytes",
                "alias_row_capacity",
                "alias_lookup_capacity",
                "alias_row_bytes",
                "alias_lookup_bytes",
            ],
        )?;
        for _ in 0..7 {
            decimal(projection)?;
        }
    }
    Ok(())
}

/// Counts the original receipt and selected optional metadata.
///
/// # Errors
/// Refuses the original tuple mismatch, projection limit or checked overflow.
pub fn receipt(
    projection: &mut Projection,
    launch: &PacketNative5LaunchValidationFields<'_>,
) -> Result<(), ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    object(
        projection,
        &[
            "schema",
            "native_pid",
            "original",
            "binding_hash",
            "session",
            "incarnation",
            "node",
            "owner",
            "owner_generation",
            "input_epoch",
            "world",
            "native_record",
            "storage_selection",
            "capture_profile",
            "protocol_metadata_birth_facts",
        ],
    )?;
    projection.add_string("source-owned.packet-receipt/5")?;
    decimal(projection)?;
    original(projection, launch)?;
    hash(projection, "cnp.owner-binding.v1")?;
    for value in [
        &binding.authority.session_id,
        &binding.authority.incarnation_id,
        &binding.compatibility.node_id,
        &binding.compatibility.capture_owner.id,
    ] {
        projection.add_string(value.as_str())?;
    }
    decimal(projection)?;
    projection.add_string(binding.authority.input_epoch.as_str())?;
    projection.add_value(&launch.selection.world)?;
    reference(projection, "application/json")?;
    object(projection, &["storage", "limits"])?;
    projection.add_value(launch.storage)?;
    projection.add_value(launch.limits)?;
    projection.add_value(launch.capture_profile)?;
    birth_metadata(projection)?;
    macro_rules! optional {
        ($field:ident, $key:literal) => {
            if let Some(value) = &launch.$field {
                projection.add_field($key)?;
                projection.add_value(value)?;
            }
        };
    }
    optional!(confirmation_selection, "confirmation_selection");
    optional!(ack_emitter_selection, "ack_emitter_selection");
    optional!(complete_restore_selection, "complete_restore_selection");
    optional!(protocol_metadata_limits, "protocol_metadata_limits");
    optional!(
        restore_input_emitter_selection,
        "restore_input_emitter_selection"
    );
    Ok(())
}

/// Counts the original completed Observe response grammar.
///
/// # Errors
/// Refuses the original tuple mismatch, projection limit or checked overflow.
pub fn terminal(
    projection: &mut Projection,
    launch: &PacketNative5LaunchValidationFields<'_>,
) -> Result<(), ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let [owner] = launch.selection.realization.owners.as_slice() else {
        return Err(refused());
    };
    envelope(projection, launch, true)?;
    object(
        projection,
        &["status", "operation_state", "result", "extensions"],
    )?;
    projection.add_string("completed")?;
    projection.add_value(&crate::profile::envelope::OperationState::Completed)?;
    object(
        projection,
        &[
            "observations",
            "next_sequence",
            "complete",
            "inventory_hash",
        ],
    )?;
    projection.add_array_extent(1)?;
    object(
        projection,
        &[
            "schema_version",
            "execution_owner_id",
            "owner_binding_hash",
            "world_binding_hash",
            "activation_id",
            "world_generation",
            "owner_generation",
            "operation_id",
            "grant_id",
            "first_sequence",
            "last_sequence",
            "events",
            "visibility",
            "measurement_ref",
            "extensions",
        ],
    )?;
    projection.add_value(&1u16)?;
    projection.add_string(owner.id.as_str())?;
    hash(projection, "cnp.owner-binding.v1")?;
    projection.add_value(&launch.selection.world)?;
    id(projection)?;
    decimal(projection)?;
    projection.add_value(&binding.authority.owner_generation)?;
    id(projection)?;
    projection.add_value(&())?;
    projection.add_value(&crucible_node_format::U64::new(0))?;
    projection.add_value(&crucible_node_format::U64::new(0))?;
    projection.add_array_extent(0)?;
    projection.add_value(&crucible_node_format::Visibility::Staged)?;
    reference(projection, "application/json")?;
    projection.add_object()?;
    projection.add_value(&crucible_node_format::U64::new(1))?;
    projection.add_value(&true)?;
    hash(
        projection,
        match launch.program {
            PacketConnectedSourceProgram::Producer { .. } => "source-owned.packet-inventory.v1",
            PacketConnectedSourceProgram::Reactive { .. } => {
                "source-owned.packet-connected-inventory/4"
            }
        },
    )?;
    projection.add_object()?;
    projection.add_object()
}

/// Counts the original capture allocation report grammar.
///
/// # Errors
/// Refuses the original tuple mismatch, projection limit or checked overflow.
pub fn report(
    projection: &mut Projection,
    launch: &PacketNative5LaunchValidationFields<'_>,
) -> Result<(), ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    object(
        projection,
        &[
            "schema",
            "scope",
            "before",
            "after",
            "metadata_banks",
            "retained_requested_bytes",
            "shared_edges",
            "unique_roots",
            "growth",
            "transients",
        ],
    )?;
    projection.add_string(PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT)?;
    object(
        projection,
        &[
            "native_pid",
            "observe_request",
            "observe_sequence",
            "observe_hash",
            "session",
            "incarnation",
            "node",
            "owner",
            "binding_hash",
            "world",
            "activation",
            "world_generation",
            "owner_generation",
            "model_cursor",
            "control_originals_before",
            "endpoint_records_before",
            "provider_next_sequence_before",
        ],
    )?;
    decimal(projection)?;
    id(projection)?;
    decimal(projection)?;
    hash(projection, NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN)?;
    for value in [
        &binding.authority.session_id,
        &binding.authority.incarnation_id,
        &binding.compatibility.node_id,
        &binding.compatibility.capture_owner.id,
    ] {
        projection.add_string(value.as_str())?;
    }
    hash(projection, "cnp.owner-binding.v1")?;
    projection.add_value(&launch.selection.world)?;
    id(projection)?;
    decimal(projection)?;
    projection.add_value(&binding.authority.owner_generation)?;
    position(projection)?;
    for _ in 0..3 {
        decimal(projection)?;
    }
    for _ in 0..2 {
        object(
            projection,
            &[
                "encoded_capacity",
                "literal_and_descriptor_bytes",
                "current_encoded_bytes",
            ],
        )?;
        for _ in 0..3 {
            decimal(projection)?;
        }
    }
    birth_metadata(projection)?;
    for _ in 0..3 {
        decimal(projection)?;
    }
    object(
        projection,
        &[
            "observe_publication_bytes",
            "capture_request_bytes",
            "capture_publication_bytes",
            "after_confirmation_bytes",
        ],
    )?;
    for _ in 0..4 {
        decimal(projection)?;
    }
    object(
        projection,
        &[
            "observe_encoding_bytes",
            "model_control_encoding_bytes",
            "native_before_encoding_bytes",
            "native_after_encoding_bytes",
            "quote_scratch_bytes",
        ],
    )?;
    for _ in 0..5 {
        decimal(projection)?;
    }
    Ok(())
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("compiled native report startup storage")
}

fn refused() -> ProviderError {
    ProviderError::Correlation("compiled native report startup tuple")
}
