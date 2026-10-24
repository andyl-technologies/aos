//! Projects literal shapes of the actual unopened initial CNP lifecycle.
//!
//! This borrows original nonsecret fields. No raw launch, DOM, socket, model,
//! native owner, member or receipt is constructed. Its numeric reports grant
//! no method invocation, Source binding, initial state or native admission.

use crate::errors::ProviderError;
use crate::profile::reference_packet::service::{
    PacketConnectedSourceProgram, PacketNative5LaunchValidationFields,
};
use crate::profile::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};

/// Selects one closed original initial wire shape without authorizing a method.
#[derive(Clone, Copy)]
pub enum InitialShapeKindData {
    /// Describes an unopened Discover request/response.
    Discover,
    /// Describes an unopened Realize request/response.
    Realize,
    /// Describes an unopened once-Admit request/response.
    Admit,
}

fn object(p: &mut Projection, keys: &[&str]) -> Result<(), ProviderError> {
    p.add_object()?;
    for key in keys {
        p.add_field(key)?;
    }
    Ok(())
}

fn decimal(p: &mut Projection) -> Result<(), ProviderError> {
    p.add_unescaped_ascii_extent(20)
}

fn id(p: &mut Projection) -> Result<(), ProviderError> {
    p.add_unescaped_ascii_extent(128)
}

fn hash(p: &mut Projection, domain: &str) -> Result<(), ProviderError> {
    object(p, &["algorithm", "domain", "digest"])?;
    p.add_string("blake3-256")?;
    p.add_string(domain)?;
    p.add_unescaped_ascii_extent(64)
}

fn reference(p: &mut Projection) -> Result<(), ProviderError> {
    object(p, &["hash", "length", "media_type"])?;
    hash(p, "cnp.blob.v1")?;
    decimal(p)?;
    p.add_string("application/json")
}

fn envelope(
    p: &mut Projection,
    launch: &PacketNative5LaunchValidationFields<'_>,
    kind: InitialShapeKindData,
    response: bool,
) -> Result<(), ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    object(
        p,
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
    p.add_string("CNP/1")?;
    p.add_value(&if response {
        crate::profile::envelope::MessageKind::Response
    } else {
        crate::profile::envelope::MessageKind::Request
    })?;
    p.add_string(binding.authority.session_id.as_str())?;
    p.add_string(binding.authority.incarnation_id.as_str())?;
    p.add_string(binding.compatibility.node_id.as_str())?;
    p.add_string(binding.compatibility.execution_owner.id.as_str())?;
    p.add_value(&())?;
    id(p)?;
    p.add_value(&())?;
    decimal(p)?;
    p.add_value(&match kind {
        InitialShapeKindData::Discover => crate::profile::envelope::Method::Discover,
        InitialShapeKindData::Realize => crate::profile::envelope::Method::Realize,
        InitialShapeKindData::Admit => crate::profile::envelope::Method::Admit,
    })
}

fn original(
    p: &mut Projection,
    launch: &PacketNative5LaunchValidationFields<'_>,
    kind: InitialShapeKindData,
) -> Result<(), ProviderError> {
    envelope(p, launch, kind, false)?;
    match kind {
        InitialShapeKindData::Discover => {
            object(p, &["profile_ids", "cursor", "extensions"])?;
            p.add_array_extent(1)?;
            id(p)?;
            p.add_value(&())?;
            object(p, &[])?;
        }
        InitialShapeKindData::Realize => p.add_value(&launch.selection.realize)?,
        InitialShapeKindData::Admit => {
            object(
                p,
                &[
                    "bindings",
                    "world_binding_hash",
                    "admission_receipt",
                    "extensions",
                ],
            )?;
            p.add_value(&launch.selection.realization.bindings)?;
            p.add_value(&launch.selection.world)?;
            p.add_value(&launch.selection.admission_receipt)?;
            object(p, &[])?;
        }
    }
    if matches!(kind, InitialShapeKindData::Admit) {
        use super::super::ack_emitter::{
            PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM, PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
        };
        object(p, &[PACKET_CANONICAL_ACK_ADMISSION_FEATURE])?;
        object(p, &["schema", "algorithm", "context_digest", "mac"])?;
        p.add_string(PACKET_CANONICAL_ACK_ADMISSION_FEATURE)?;
        p.add_string(PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM)?;
        p.add_unescaped_ascii_extent(43)?;
        p.add_unescaped_ascii_extent(43)
    } else {
        object(p, &[])
    }
}

/// Projects the unopened once-Admit request without issuing an admission.
///
/// # Errors
/// Refuses the original target/serialization errors, checked overflow or maximum.
pub fn admit_projection(
    launch: &PacketNative5LaunchValidationFields<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    request(launch, InitialShapeKindData::Admit, maximum)
}

/// Projects the original closed request literal shape.
///
/// # Errors
/// Refuses the original target/serialization errors, checked overflow or maximum.
pub fn request(
    launch: &PacketNative5LaunchValidationFields<'_>,
    kind: InitialShapeKindData,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    original(&mut p, launch, kind)?;
    p.finish(maximum)
}

fn position(p: &mut Projection) -> Result<(), ProviderError> {
    object(p, &["time_ps", "microstep", "phase"])?;
    decimal(p)?;
    decimal(p)?;
    p.add_value(&crucible_node_format::Phase::BoundaryControl)
}

fn inventory(
    p: &mut Projection,
    launch: &PacketNative5LaunchValidationFields<'_>,
) -> Result<(), ProviderError> {
    match launch.program {
        PacketConnectedSourceProgram::Producer { program } => {
            object(
                p,
                &[
                    "reached",
                    "gate_closed",
                    "pending",
                    "retained_outputs",
                    "private_mutations",
                    "packet_effects",
                ],
            )?;
            position(p)?;
            p.add_value(&true)?;
            p.add_array_extent(program.events.len())?;
            for event in &program.events {
                object(p, &["id", "evaluation", "completion", "payload"])?;
                p.add_string(event.id.as_str())?;
                position(p)?;
                position(p)?;
                if let Some(bytes) = &event.payload {
                    p.add_unescaped_ascii_extent(
                        bytes
                            .as_slice()
                            .len()
                            .div_ceil(3)
                            .checked_mul(4)
                            .ok_or_else(refused)?,
                    )?;
                } else {
                    p.add_value(&())?;
                }
            }
            // The actual unopened constructor has no publication/grant owner.
            p.add_array_extent(0)?;
            decimal(p)?;
            decimal(p)
        }
        PacketConnectedSourceProgram::Reactive { .. } => {
            object(
                p,
                &[
                    "reached",
                    "gate_closed",
                    "reactions",
                    "delivered_inputs",
                    "publications",
                    "retained_outputs",
                    "reactions_completed",
                    "packet_effects",
                    "stages",
                    "commits",
                ],
            )?;
            position(p)?;
            p.add_value(&true)?;
            for _ in 0..4 {
                p.add_array_extent(0)?;
            }
            decimal(p)?;
            decimal(p)?;
            p.add_array_extent(0)?;
            p.add_array_extent(0)
        }
    }
}

/// Projects the original closed raw record literal shape.
///
/// # Errors
/// Refuses the original target/serialization errors, checked overflow or maximum.
pub fn raw_record(
    launch: &PacketNative5LaunchValidationFields<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    object(
        &mut p,
        &["schema", "native_pid", "original", "inventory", "grant"],
    )?;
    p.add_string(match launch.program {
        PacketConnectedSourceProgram::Producer { .. } => "source-owned.packet-native/2",
        PacketConnectedSourceProgram::Reactive { .. } => "source-owned.packet-native/4",
    })?;
    decimal(&mut p)?;
    original(&mut p, launch, InitialShapeKindData::Realize)?;
    inventory(&mut p, launch)?;
    p.add_value(&())?;
    p.finish(maximum)
}

/// Projects the original closed receipt literal shape.
///
/// # Errors
/// Refuses the original target/serialization errors, checked overflow or maximum.
pub fn receipt(
    launch: &PacketNative5LaunchValidationFields<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let mut p = Projection::new(maximum)?;
    object(
        &mut p,
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
            "confirmation_selection",
            "ack_emitter_selection",
            "complete_restore_selection",
            "protocol_metadata_limits",
            "protocol_metadata_birth_facts",
            "restore_input_emitter_selection",
        ],
    )?;
    p.add_string("source-owned.packet-receipt/5")?;
    decimal(&mut p)?;
    original(&mut p, launch, InitialShapeKindData::Realize)?;
    hash(&mut p, "cnp.owner-binding.v1")?;
    for id in [
        &binding.authority.session_id,
        &binding.authority.incarnation_id,
        &binding.compatibility.node_id,
        &binding.compatibility.capture_owner.id,
    ] {
        p.add_string(id.as_str())?;
    }
    decimal(&mut p)?;
    p.add_string(binding.authority.input_epoch.as_str())?;
    p.add_value(&launch.selection.world)?;
    reference(&mut p)?;
    object(&mut p, &["storage", "limits"])?;
    p.add_value(launch.storage)?;
    p.add_value(launch.limits)?;
    p.add_value(launch.capture_profile)?;
    p.add_value(&launch.confirmation_selection)?;
    p.add_value(&launch.ack_emitter_selection)?;
    p.add_value(&launch.complete_restore_selection)?;
    p.add_value(&launch.protocol_metadata_limits)?;
    object(&mut p, &["before", "after"])?;
    for _ in 0..2 {
        object(
            &mut p,
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
            decimal(&mut p)?;
        }
    }
    p.add_value(&launch.restore_input_emitter_selection)?;
    p.finish(maximum)
}

/// Projects the original closed terminal literal shape.
///
/// # Errors
/// Refuses the original target/serialization errors, checked overflow or maximum.
pub fn terminal(
    launch: &PacketNative5LaunchValidationFields<'_>,
    kind: InitialShapeKindData,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    envelope(&mut p, launch, kind, true)?;
    object(
        &mut p,
        &["status", "operation_state", "result", "extensions"],
    )?;
    p.add_string("completed")?;
    p.add_value(&crate::profile::envelope::OperationState::Completed)?;
    match kind {
        InitialShapeKindData::Discover => {
            object(
                &mut p,
                &[
                    "provider_manifest",
                    "profiles",
                    "facet_schemas",
                    "complete",
                    "next_cursor",
                ],
            )?;
            p.add_value(&launch.selection.provider)?;
            p.add_value(&launch.selection.provider.supported_profiles)?;
            p.add_value(&launch.selection.provider.implementation.formats)?;
            p.add_value(&true)?;
            p.add_value(&())?;
        }
        InitialShapeKindData::Realize => {
            object(
                &mut p,
                &[
                    "realization_manifest",
                    "prepared_token",
                    "closed_gate_receipt",
                ],
            )?;
            p.add_value(&launch.selection.realization)?;
            p.add_string(launch.selection.prepared_token.as_str())?;
            reference(&mut p)?;
        }
        InitialShapeKindData::Admit => {
            object(&mut p, &["accepted_binding_hashes", "admission_id"])?;
            p.add_array_extent(1)?;
            hash(&mut p, "cnp.node-binding.v1")?;
            p.add_string(launch.selection.admission.as_str())?;
        }
    }
    object(&mut p, &[])?;
    object(&mut p, &[])?;
    p.finish(maximum)
}

/// Borrows only the common initial wire grammar, independently of native rows.
pub struct OriginalHostInitialLifecycleShapes {
    /// Retains the three original Discover/Realize/Admit request reports.
    pub requests: [OriginalSerializationStorageData; 3],
    /// Retains the three corresponding original terminal reports.
    pub responses: [OriginalSerializationStorageData; 3],
}

/// Projects original host request/response shape banks without creating owners.
///
/// # Errors
/// Refuses original target/serialization errors, checked overflow or maximum.
pub fn original_host_initial_lifecycle_shapes_data(
    launch: &PacketNative5LaunchValidationFields<'_>,
    maximum: usize,
) -> Result<OriginalHostInitialLifecycleShapes, ProviderError> {
    let mut requests = [
        request(launch, InitialShapeKindData::Discover, maximum)?,
        request(launch, InitialShapeKindData::Realize, maximum)?,
        request(launch, InitialShapeKindData::Admit, maximum)?,
    ];
    let mut responses = [
        terminal(launch, InitialShapeKindData::Discover, maximum)?,
        terminal(launch, InitialShapeKindData::Realize, maximum)?,
        terminal(launch, InitialShapeKindData::Admit, maximum)?,
    ];
    // The common native projector spells node/owner scope as actual Id values.
    // Core's initial Discover/Realize may use null instead. An Id's shortest
    // JSON string is three bytes; each of seven nullable fields can therefore
    // need at most one extra byte. Null adds no heap child or serde event.
    for data in requests.iter_mut().chain(responses.iter_mut()) {
        data.maximum_encoded_bytes = data
            .maximum_encoded_bytes
            .checked_add(7)
            .ok_or_else(refused)?;
        data.canonical_output_requested_bytes = data
            .canonical_output_requested_bytes
            .checked_add(14)
            .ok_or_else(refused)?;
        if data.requested_total()? > maximum {
            return Err(refused());
        }
    }
    Ok(OriginalHostInitialLifecycleShapes {
        requests,
        responses,
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native baseline requested storage")
}
