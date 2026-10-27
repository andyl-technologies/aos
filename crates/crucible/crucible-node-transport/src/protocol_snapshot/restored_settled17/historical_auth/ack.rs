//! Binds ACK MAC data to complete retained birth, registration and Hello inputs.

use super::shared::*;
use super::*;
use crate::envelope::Method;
use crate::reference_packet::service::ack_emitter::{
    MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES, NativeAckBoot,
    PACKET_CANONICAL_ACK_ADMISSION_FEATURE, verify_canonical_ack_admission_proof_data,
};
use crucible_node_format::{Bytes, ContentRef, ContractError, Id, Validate};
use serde::{Deserialize, Serialize};

/// Checks the actual assigned ACK, terminal and complete normalized birth inputs.
///
/// The private key is borrowed from the same retained historical Boot. These
/// predicates authenticate DATA only; the parent independently joins actual
/// SDK outputs and the original Source/native/Control group identities.
///
/// # Errors
/// Refuses changed normalized inputs, registration, literal Hello, assigned
/// original, typed body, correlated completed terminal, proof or birth key.
pub(crate) fn authenticate_historical_ack_data(
    key: &[u8; 32],
    data: &HistoricalAck17<'_>,
    maximum_frame: usize,
) -> Result<(), ProviderError> {
    let original = data.pair.original;
    completed_pair(data.pair, Method::Admit, maximum_frame)?;
    data.context.validate_data()?;
    data.proof.validate_data()?;
    if original.extensions.len() != 1 || data.native_pid.get() == 0 {
        return Err(invalid());
    }
    extension(
        original,
        PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
        data.proof,
        MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES,
    )?;

    let empty_extensions = crucible_node_format::Extensions::new();
    let expected = HistoricalAdmitBody17 {
        bindings: &data.selection.realization.bindings,
        world_binding_hash: &data.selection.world,
        admission_receipt: &data.selection.admission_receipt,
        extensions: &empty_extensions,
    };
    same_value(&original.body, &expected, maximum_frame)?;
    authenticate_inputs(data, maximum_frame)?;

    let mut assigned = serde_json::to_value(original).map_err(ContractError::from)?;
    assigned
        .get_mut("extensions")
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?
        .remove(PACKET_CANONICAL_ACK_ADMISSION_FEATURE);
    value_digest(&data.context.assigned_admit, &assigned, maximum_frame)?;
    verify_canonical_ack_admission_proof_data(key, data.context, data.proof)
}

#[derive(Serialize)]
struct HistoricalAdmitBody17<'a> {
    bindings: &'a [crucible_node_format::NodeBinding],
    world_binding_hash: &'a crucible_node_format::HashRef,
    admission_receipt: &'a ContentRef,
    extensions: &'a crucible_node_format::Extensions,
}

fn authenticate_inputs(
    data: &HistoricalAck17<'_>,
    maximum_frame: usize,
) -> Result<(), ProviderError> {
    let bindings = &data.bindings;
    let limits = NativeAckBoot::historical_ack_context_limits17_data();
    for (value, maximum) in [
        (bindings.birth_association, limits[0]),
        (bindings.kernel_binding, limits[1]),
        (bindings.policy_binding, limits[2]),
        (bindings.host_registration, limits[3]),
        (bindings.native_registration, limits[3]),
    ] {
        crate::connection::serialized_credit(value, maximum)?;
    }

    let birth = object(
        bindings.birth_association,
        &[
            "schema",
            "birth_id",
            "private_launch",
            "host_executable",
            "source_binding",
            "expected_host_registration",
        ],
    )?;
    if birth["schema"] != "source-owned.packet-canonical-ack-birth-association/5" {
        return Err(invalid());
    }
    let birth_id = Bytes::deserialize(&birth["birth_id"]).map_err(ContractError::from)?;
    if birth_id.as_slice().len() != 32 {
        return Err(invalid());
    }
    Id::deserialize(&birth["private_launch"])
        .map_err(ContractError::from)?
        .validate()?;
    ContentRef::deserialize(&birth["host_executable"])
        .map_err(ContractError::from)?
        .validate()?;
    same_value(
        &birth["host_executable"],
        bindings.controller_executable,
        limits[1],
    )?;
    same_value(
        &birth["expected_host_registration"],
        bindings.host_registration,
        limits[3],
    )?;
    same_value(
        birth["source_binding"]
            .get("selection")
            .ok_or_else(invalid)?,
        data.selection,
        limits[0],
    )?;

    let kernel = object(bindings.kernel_binding, &["schema", "controller", "native"])?;
    if kernel["schema"] != "source-owned.packet-canonical-ack-kernel-binding/5" {
        return Err(invalid());
    }
    let controller = object(&kernel["controller"], &["pid", "uid", "executable"])?;
    let native = object(&kernel["native"], &["pid", "uid", "executable"])?;
    same_value(&controller["pid"], &bindings.controller_pid, limits[1])?;
    same_value(&controller["uid"], &bindings.controller_uid, limits[1])?;
    same_value(
        &controller["executable"],
        bindings.controller_executable,
        limits[1],
    )?;
    same_value(&native["pid"], &data.native_pid, limits[1])?;
    U64::deserialize(&native["uid"]).map_err(ContractError::from)?;
    ContentRef::deserialize(&native["executable"])
        .map_err(ContractError::from)?
        .validate()?;

    let authority = bindings.authority;
    let extensions = authority.extensions.as_deref().ok_or_else(invalid)?;
    let policy = serde_json::json!({
        "schema":"source-owned.packet-canonical-ack-policy-binding/5",
        "source_binding":birth["source_binding"],
        "negotiated":{"limits":authority.limits,"features":authority.features,
            "extensions":extensions,"envelope_extensions":authority.envelope_extensions},
    });
    same_value(bindings.policy_binding, &policy, limits[2])?;
    let host = object(
        bindings.host_registration,
        &[
            "schema",
            "role",
            "connection_id",
            "session_id",
            "incarnation_id",
            "limits",
            "features",
            "extensions",
            "envelope_extensions",
        ],
    )?;
    let host_id = Id::deserialize(&host["connection_id"]).map_err(ContractError::from)?;
    host_id.validate()?;
    for (role, connection, actual) in [
        ("controller", &host_id, bindings.host_registration),
        (
            "native",
            &authority.connection,
            bindings.native_registration,
        ),
    ] {
        let expected = serde_json::json!({
            "schema":"source-owned.packet-canonical-ack-registration/5","role":role,
            "connection_id":connection,"session_id":authority.session,"incarnation_id":authority.incarnation,
            "limits":authority.limits,"features":authority.features,"extensions":extensions,
            "envelope_extensions":authority.envelope_extensions,
        });
        same_value(actual, &expected, limits[3])?;
    }
    if data.pair.original.session_id.0.as_ref() != Some(&authority.session)
        || data.pair.original.incarnation_id.0.as_ref() != Some(&authority.incarnation)
    {
        return Err(invalid());
    }

    for (digest, value, maximum) in [
        (
            &data.context.source_birth,
            bindings.birth_association,
            limits[0],
        ),
        (
            &data.context.kernel_binding,
            bindings.kernel_binding,
            limits[1],
        ),
        (
            &data.context.policy_binding,
            bindings.policy_binding,
            limits[2],
        ),
        (
            &data.context.host_registration,
            bindings.host_registration,
            limits[3],
        ),
        (
            &data.context.native_registration,
            bindings.native_registration,
            limits[3],
        ),
    ] {
        value_digest(digest, value, maximum)?;
    }
    digest_matches(
        &data.context.hello_request,
        &hello_digest(bindings.hello_request_literal, maximum_frame)?,
    )?;
    digest_matches(
        &data.context.hello_response,
        &hello_digest(bindings.hello_response_literal, maximum_frame)?,
    )
}

fn object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, ProviderError> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(object)
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<HistoricalAdmitBody17<'static>>()
        + size_of::<crucible_node_format::Extensions>()
        + 2 * size_of::<crucible_node_format::Id>()
        + size_of::<ContentRef>()
        + size_of::<Bytes>()
        + size_of::<[usize; 5]>()
        + size_of::<[(&Value, usize); 5]>()
}
