//! Borrows exact prepare/commit extension grammar without constructing a DTO.
//!
//! This projection checks syntax and finite wire extents only. The genuine boot
//! issuer derives and authenticates fresh key/context/literal associations before
//! constructing its separate private prepare or commit token.

use super::complete_restore_projection::{
    content, digest, field, identifier, integer, invalid, object, request, text,
};
use crate::reference_packet::service::complete_restore::{
    PACKET_COMPLETE_RESTORE_ALGORITHM, transfer::*,
};
use crate::{
    ProviderError,
    envelope::{Envelope, MessageKind, Method},
};
use serde_json::Value;

pub(crate) enum CompleteRestoreTransferProjection<'a> {
    Request {
        phase: PacketCompleteRestoreTransferPhase,
        request: &'a Value,
        proof: &'a Value,
    },
    Receipt {
        phase: PacketCompleteRestoreTransferPhase,
        receipt: &'a Value,
    },
}

impl<'a> CompleteRestoreTransferProjection<'a> {
    pub(crate) fn from_envelope(envelope: &'a Envelope) -> Result<Self, ProviderError> {
        Self::from_envelope_inner(envelope, false)
    }

    /// Adds the separately selected Fresh binding to the unchanged transfer proof.
    pub(crate) fn from_envelope_with_fresh_binding_data(
        envelope: &'a Envelope,
    ) -> Result<Self, ProviderError> {
        use crate::reference_packet::service::fresh_restore_allocation::{
            PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING, policy,
        };
        let binding = envelope
            .extensions
            .get(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
            .ok_or_else(invalid)?;
        policy::validate_prepare_binding_value(binding)?;
        Self::from_envelope_inner(envelope, true)
    }

    fn from_envelope_inner(
        envelope: &'a Envelope,
        fresh_binding: bool,
    ) -> Result<Self, ProviderError> {
        if envelope.method != Method::Begin
            || envelope.node_id.0.is_none()
            || envelope.request_id.0.is_none()
            || envelope
                .body
                .get("extensions")
                .and_then(Value::as_object)
                .is_none_or(|v| !v.is_empty())
        {
            return Err(invalid());
        }
        for phase in [
            PacketCompleteRestoreTransferPhase::Prepare,
            PacketCompleteRestoreTransferPhase::Commit,
        ] {
            match envelope.message {
                MessageKind::Request
                    if envelope.extensions.len() == 2 + usize::from(fresh_binding)
                        && (!fresh_binding
                            || phase == PacketCompleteRestoreTransferPhase::Prepare)
                        && envelope.extensions.contains_key(phase.request_extension()) =>
                {
                    let data = envelope
                        .extensions
                        .get(phase.request_extension())
                        .ok_or_else(invalid)?;
                    let proof = envelope
                        .extensions
                        .get(phase.proof_extension())
                        .ok_or_else(invalid)?;
                    if envelope.body.get("kind").and_then(Value::as_str) != Some("prepare_restore")
                    {
                        return Err(invalid());
                    }
                    match phase {
                        PacketCompleteRestoreTransferPhase::Prepare => prepare(data)?,
                        PacketCompleteRestoreTransferPhase::Commit => commit(data)?,
                    }
                    proof_data(proof, phase)?;
                    return Ok(Self::Request {
                        phase,
                        request: data,
                        proof,
                    });
                }
                MessageKind::Response
                    if !fresh_binding
                        && envelope.extensions.len() == 1
                        && envelope.extensions.contains_key(phase.receipt_extension()) =>
                {
                    let receipt = envelope
                        .extensions
                        .get(phase.receipt_extension())
                        .ok_or_else(invalid)?;
                    receipt_data(receipt, phase)?;
                    return Ok(Self::Receipt { phase, receipt });
                }
                _ => {}
            }
        }
        Err(invalid())
    }

    pub(crate) fn phase(&self) -> PacketCompleteRestoreTransferPhase {
        match self {
            Self::Request { phase, .. } | Self::Receipt { phase, .. } => *phase,
        }
    }
}

fn positive(value: &Value) -> Result<u64, ProviderError> {
    let n = integer(value)?;
    if n == 0 {
        return Err(invalid());
    }
    Ok(n)
}

fn allocation(value: &Value) -> Result<(), ProviderError> {
    let fields = object(
        value,
        &[
            "maximum_known_requested_bytes",
            "maximum_input_bytes",
            "maximum_nodes",
            "maximum_depth",
            "maximum_owned_backing_bytes",
            "maximum_tree_entries",
            "maximum_metadata_rows",
            "maximum_literal_backing_bytes",
            "maximum_content_transfers",
            "maximum_content_objects",
            "maximum_content_groups",
            "maximum_content_bytes",
            "maximum_content_metadata_bytes",
            "maximum_model_bytes",
        ],
    )?;
    let total = positive(field(fields, "maximum_known_requested_bytes")?)?;
    if total > 512 * 1024 * 1024 {
        return Err(invalid());
    }
    for key in [
        "maximum_input_bytes",
        "maximum_owned_backing_bytes",
        "maximum_literal_backing_bytes",
        "maximum_content_bytes",
        "maximum_content_metadata_bytes",
        "maximum_model_bytes",
    ] {
        if positive(field(fields, key)?)? > total {
            return Err(invalid());
        }
    }
    for key in [
        "maximum_nodes",
        "maximum_tree_entries",
        "maximum_content_transfers",
        "maximum_content_objects",
        "maximum_content_groups",
    ] {
        if positive(field(fields, key)?)? > 512 * 1024 * 1024 {
            return Err(invalid());
        }
    }
    if positive(field(fields, "maximum_depth")?)? > 64
        || positive(field(fields, "maximum_metadata_rows")?)? > 131_072
    {
        return Err(invalid());
    }
    Ok(())
}

fn prepare(value: &Value) -> Result<(), ProviderError> {
    let fields = object(
        value,
        &[
            "schema",
            "restoration",
            "host_protocol",
            "native_protocol",
            "native_control",
            "native_anchor",
            "transaction_id",
            "generation",
            "allocation",
        ],
    )?;
    if text(fields, "schema")? != PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION {
        return Err(invalid());
    }
    request(field(fields, "restoration")?)?;
    for key in [
        "host_protocol",
        "native_protocol",
        "native_control",
        "native_anchor",
    ] {
        content(field(fields, key)?)?;
    }
    identifier(text(fields, "transaction_id")?)?;
    positive(field(fields, "generation")?)?;
    allocation(field(fields, "allocation")?)?;
    super::serialized_credit(value, MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES)?;
    Ok(())
}

fn commit(value: &Value) -> Result<(), ProviderError> {
    let fields = object(
        value,
        &[
            "schema",
            "prepare",
            "prepare_request_id",
            "prepare_request_sequence",
            "prepare_request_digest",
            "prepare_response_sequence",
            "prepare_response_digest",
            "transfer_token",
            "capture_terminal",
        ],
    )?;
    if text(fields, "schema")? != PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION {
        return Err(invalid());
    }
    prepare(field(fields, "prepare")?)?;
    identifier(text(fields, "prepare_request_id")?)?;
    for key in ["prepare_request_sequence", "prepare_response_sequence"] {
        positive(field(fields, key)?)?;
    }
    for key in [
        "prepare_request_digest",
        "prepare_response_digest",
        "transfer_token",
    ] {
        digest(field(fields, key)?)?;
    }
    terminal(field(fields, "capture_terminal")?)?;
    super::serialized_credit(value, MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES)?;
    Ok(())
}

fn terminal(value: &Value) -> Result<(), ProviderError> {
    let fields = object(
        value,
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
    if text(fields, "protocol")? != "CNP/1"
        || text(fields, "message")? != "response"
        || text(fields, "method")? != "begin"
    {
        return Err(invalid());
    }
    positive(field(fields, "sequence")?)?;
    for key in [
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
    ] {
        match field(fields, key)? {
            Value::Null => {}
            Value::String(id) => identifier(id)?,
            _ => return Err(invalid()),
        }
    }
    if !field(fields, "body")?.is_object() || !field(fields, "extensions")?.is_object() {
        return Err(invalid());
    }
    Ok(())
}

fn proof_data(
    value: &Value,
    phase: PacketCompleteRestoreTransferPhase,
) -> Result<(), ProviderError> {
    let fields = object(value, &["schema", "algorithm", "context_digest", "mac"])?;
    if text(fields, "schema")? != phase.proof_extension()
        || text(fields, "algorithm")? != PACKET_COMPLETE_RESTORE_ALGORITHM
    {
        return Err(invalid());
    }
    for key in ["context_digest", "mac"] {
        digest(field(fields, key)?)?;
    }
    super::serialized_credit(value, MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES)?;
    Ok(())
}

fn receipt_data(
    value: &Value,
    phase: PacketCompleteRestoreTransferPhase,
) -> Result<(), ProviderError> {
    use PacketCompleteRestoreTransferPhase::{Commit, Prepare};
    let fields = match phase {
        Prepare => object(
            value,
            &[
                "schema",
                "algorithm",
                "prepare_digest",
                "context_digest",
                "input_roster",
                "transfer_token",
                "generation",
                "native_sequence",
                "assigned_response",
                "mac",
            ],
        ),
        Commit => object(
            value,
            &[
                "schema",
                "algorithm",
                "commit_digest",
                "context_digest",
                "installed_mapping",
                "transfer_token",
                "native_sequence",
                "assigned_response",
                "mac",
            ],
        ),
    }?;
    if text(fields, "schema")? != phase.receipt_extension()
        || text(fields, "algorithm")? != PACKET_COMPLETE_RESTORE_ALGORITHM
    {
        return Err(invalid());
    }
    for key in [
        "context_digest",
        "transfer_token",
        "assigned_response",
        "mac",
    ] {
        digest(field(fields, key)?)?;
    }
    positive(field(fields, "native_sequence")?)?;
    match phase {
        Prepare => {
            positive(field(fields, "generation")?)?;
            digest(field(fields, "prepare_digest")?)?;
            digest(field(fields, "input_roster")?)?;
        }
        Commit => {
            content(field(fields, "installed_mapping")?)?;
            digest(field(fields, "commit_digest")?)?;
        }
    }
    super::serialized_credit(value, MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)?;
    Ok(())
}

// crucible-lint: allow panic-shortcut -- closed parser conjunctions are tested without any live issuer or grant.
#[cfg(test)]
mod fresh_binding_tests {
    use super::*;
    use crate::envelope::Nullable;
    use crate::reference_packet::service::{
        complete_restore::PACKET_COMPLETE_RESTORE_FEATURE, fresh_restore_allocation::*,
    };
    use crucible_node_format::{Bytes, Id, U64, canonical};

    #[test]
    fn explicit_fresh_prepare_keeps_full_transfer_proof_and_legacy_parser_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        // These full reference/hash values identify inert test DATA. No native
        // boot, installed policy, source action or completed query is created.
        let content = canonical::content_ref(b"transfer syntax data", "application/json")?;
        let allocation =
            canonical::content_ref(b"report syntax data", PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)?;
        let digest = Bytes::new(vec![0; 32]);
        let world = canonical::hash("cnp.world-binding.v1", b"world data")?;
        let mut limits = serde_json::Map::new();
        for key in [
            "maximum_known_requested_bytes",
            "maximum_input_bytes",
            "maximum_nodes",
            "maximum_depth",
            "maximum_owned_backing_bytes",
            "maximum_tree_entries",
            "maximum_metadata_rows",
            "maximum_literal_backing_bytes",
            "maximum_content_transfers",
            "maximum_content_objects",
            "maximum_content_groups",
            "maximum_content_bytes",
            "maximum_content_metadata_bytes",
            "maximum_model_bytes",
        ] {
            limits.insert(
                key.into(),
                serde_json::to_value(U64::new(if key == "maximum_known_requested_bytes" {
                    1024
                } else {
                    1
                }))?,
            );
        }
        let restoration = serde_json::json!({
            "schema":PACKET_COMPLETE_RESTORE_FEATURE,
            "archive_index":&content, "capture_manifest":&content, "owner_state":&content,
            "journal":&content, "source_runtime":&content, "backend_implementation":&content,
            "backend_schema":{"id":"schema-data","version":1,"definition":&content,"extensions":{}},
            "archived_cut":{"time_ps":"1","microstep":"0","phase":0}, "archived_ordinal":"1",
            "target_world":&world, "target_owner":"owner-data", "target_owner_binding":&world,
            "target_activation":"activation-data", "target_generation":"1", "target_owner_generation":"1",
            "mapping":&content, "nonce":&digest,
        });
        let request = serde_json::json!({
            "schema":PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION, "restoration":restoration,
            "host_protocol":&content,"native_protocol":&content,"native_control":&content,"native_anchor":&content,
            "transaction_id":"transaction-data","generation":"1","allocation":limits,
        });
        let proof = serde_json::json!({"schema":PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION,"algorithm":PACKET_COMPLETE_RESTORE_ALGORITHM,"context_digest":&digest,"mac":&digest});
        let binding = serde_json::json!({"schema":PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING,"assigned_query":&digest,"completed_query_response":&digest,"allocation":&allocation});
        let mut envelope = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(Id::new("session-data")?)),
            incarnation_id: Nullable(Some(Id::new("incarnation-data")?)),
            node_id: Nullable(Some(Id::new("node-data")?)),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(Id::new("request-data")?)),
            operation_id: Nullable(None),
            sequence: U64::new(1),
            method: Method::Begin,
            body: serde_json::json!({"kind":"prepare_restore","extensions":{}})
                .as_object()
                .ok_or("body object")?
                .clone(),
            extensions: [
                (PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION.into(), request),
                (
                    PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION.into(),
                    proof,
                ),
            ]
            .into_iter()
            .collect(),
        };
        CompleteRestoreTransferProjection::from_envelope(&envelope)?;
        assert!(
            CompleteRestoreTransferProjection::from_envelope_with_fresh_binding_data(&envelope)
                .is_err()
        );
        envelope.extensions.insert(
            PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.into(),
            binding,
        );
        assert!(CompleteRestoreTransferProjection::from_envelope(&envelope).is_err());
        assert_eq!(
            CompleteRestoreTransferProjection::from_envelope_with_fresh_binding_data(&envelope)?
                .phase(),
            PacketCompleteRestoreTransferPhase::Prepare
        );
        let mut changed = envelope.clone();
        changed
            .extensions
            .get_mut(PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION)
            .and_then(Value::as_object_mut)
            .ok_or("proof object")?
            .insert("mac".into(), "changed".into());
        assert!(
            CompleteRestoreTransferProjection::from_envelope_with_fresh_binding_data(&changed)
                .is_err()
        );
        envelope
            .extensions
            .insert("foreign-extra".into(), Value::Null);
        assert!(
            CompleteRestoreTransferProjection::from_envelope_with_fresh_binding_data(&envelope)
                .is_err()
        );
        Ok(())
    }
}
