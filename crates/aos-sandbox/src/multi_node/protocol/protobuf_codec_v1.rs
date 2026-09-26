//! Versioned protobuf ownership of coordinator/node method payloads.
//!
//! Current sessions use these generated oneofs as the authoritative semantic
//! contract. The retired `AOSNODE1` plus JSON representation is implemented by
//! a separate, explicitly negotiated legacy codec branch.

use aos_proto::aos::sandbox::coordinator::v1 as wire;
use aos_sandbox_core::{ProtocolId, ProtocolVersion, supported_protocol_version};
use buffa::Message as _;

use super::{
    AuthenticatedEvidenceContextV1, AuthenticatedNodeSessionV1, CanonicalNodeFrameKindV1,
    CanonicalNodeSemanticCodecV1, InvalidMultiNodeProtocol, NodeRequestBodyV1, NodeResponseBodyV1,
    NodeWatchEventBodyV1, ResyncInventoryV1, semantic_codec_v1,
};

const SCHEMA_MAJOR: u16 = 1;
const SCHEMA_MINOR: u16 = 0;

const KIND_GET_CAPABILITIES_REQUEST: i32 = 1;
const KIND_GET_CAPABILITIES_RESPONSE: i32 = 2;
const KIND_RECONCILE_ASSIGNMENT_REQUEST: i32 = 3;
const KIND_RECONCILE_ASSIGNMENT_RESPONSE: i32 = 4;
const KIND_RELIST_ASSIGNMENTS_REQUEST: i32 = 5;
const KIND_RELIST_ASSIGNMENTS_RESPONSE: i32 = 6;
const KIND_RECONCILE_DRAIN_REQUEST: i32 = 7;
const KIND_RECONCILE_DRAIN_RESPONSE: i32 = 8;
const KIND_BEGIN_SNAPSHOT_TRANSFER_REQUEST: i32 = 9;
const KIND_BEGIN_SNAPSHOT_TRANSFER_RESPONSE: i32 = 10;
const KIND_SNAPSHOT_CHUNK_REQUEST: i32 = 11;
const KIND_SNAPSHOT_CHUNK_RESPONSE: i32 = 12;
const KIND_SNAPSHOT_DEPENDENCY_REQUEST: i32 = 13;
const KIND_SNAPSHOT_DEPENDENCY_RESPONSE: i32 = 14;
const KIND_WATCH_REQUEST: i32 = 15;
const KIND_WATCH_RESPONSE: i32 = 16;
const KIND_WATCH_CAPABILITY_EVENT: i32 = 17;
const KIND_WATCH_ASSIGNMENT_EVENT: i32 = 18;
const KIND_WATCH_DRAIN_EVENT: i32 = 19;

fn version(value: ProtocolVersion) -> wire::ProtocolVersion {
    wire::ProtocolVersion {
        major: u32::from(value.major()),
        minor: u32::from(value.minor()),
        ..Default::default()
    }
}

fn encode(kind: i32, body: wire::semantic_envelope::Body) -> Vec<u8> {
    let schema = ProtocolVersion::new(SCHEMA_MAJOR, SCHEMA_MINOR);
    wire::SemanticEnvelope {
        schema: Some(version(schema)).into(),
        compatibility: Some(wire::CompatibilityWindow {
            minimum_reader: Some(version(schema)).into(),
            writer: Some(version(schema)).into(),
            ..Default::default()
        })
        .into(),
        kind: kind.into(),
        body: Some(body),
        ..Default::default()
    }
    .encode_to_vec()
}

fn decode(
    bytes: &[u8],
    expected_kind: i32,
    maximum_bytes: u32,
) -> Result<wire::semantic_envelope::Body, InvalidMultiNodeProtocol> {
    if bytes.is_empty() || bytes.len() > maximum_bytes as usize {
        return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
    }
    let envelope = wire::SemanticEnvelope::decode_from_slice(bytes)
        .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    if envelope.encode_to_vec().as_slice() != bytes {
        return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
    }
    validate_version(&envelope)?;
    if envelope.kind.to_i32() != expected_kind
        || !body_matches_kind(envelope.body.as_ref(), expected_kind)
    {
        return Err(InvalidMultiNodeProtocol::MethodMismatch);
    }
    envelope
        .body
        .ok_or(InvalidMultiNodeProtocol::NonCanonicalFrame)
}

fn validate_version(envelope: &wire::SemanticEnvelope) -> Result<(), InvalidMultiNodeProtocol> {
    let schema = envelope
        .schema
        .as_option()
        .ok_or(InvalidMultiNodeProtocol::IncompatibleVersion)?;
    let compatibility = envelope
        .compatibility
        .as_option()
        .ok_or(InvalidMultiNodeProtocol::IncompatibleVersion)?;
    let minimum = compatibility
        .minimum_reader
        .as_option()
        .ok_or(InvalidMultiNodeProtocol::IncompatibleVersion)?;
    let writer = compatibility
        .writer
        .as_option()
        .ok_or(InvalidMultiNodeProtocol::IncompatibleVersion)?;
    let supported = supported_protocol_version(ProtocolId::CoordinatorNode);
    if schema.major != u32::from(SCHEMA_MAJOR)
        || schema.minor != u32::from(SCHEMA_MINOR)
        || writer != schema
        || minimum.major != schema.major
        || minimum.minor > schema.minor
        || u32::from(supported.major()) != schema.major
        || u32::from(supported.minor()) < minimum.minor
    {
        return Err(InvalidMultiNodeProtocol::IncompatibleVersion);
    }
    Ok(())
}

pub(super) fn encode_request(
    body: &NodeRequestBodyV1,
) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
    let kind = request_kind(body.frame_kind());
    Ok(encode(kind, semantic_codec_v1::protobuf_request(body)?))
}

pub(in crate::multi_node) fn decode_request(
    session: &AuthenticatedNodeSessionV1,
    kind: CanonicalNodeFrameKindV1,
    bytes: &[u8],
    now: u64,
) -> Result<NodeRequestBodyV1, InvalidMultiNodeProtocol> {
    let _ = now;
    let body = decode(bytes, request_kind(kind), session.maximum_request_bytes())?;
    semantic_codec_v1::protobuf_request_model(kind, body)
}

pub(super) fn encode_response(
    body: &NodeResponseBodyV1,
) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
    let kind = response_kind(body.frame_kind());
    Ok(encode(kind, semantic_codec_v1::protobuf_response(body)?))
}

pub(in crate::multi_node) fn decode_response(
    context: AuthenticatedEvidenceContextV1,
    kind: CanonicalNodeFrameKindV1,
    bytes: &[u8],
    now: u64,
    codec: &CanonicalNodeSemanticCodecV1,
) -> Result<NodeResponseBodyV1, InvalidMultiNodeProtocol> {
    let _ = now;
    let body = decode(bytes, response_kind(kind), super::MAX_NODE_RESPONSE_BYTES)?;
    semantic_codec_v1::protobuf_response_model(context, kind, body, codec)
}

pub(super) fn encode_watch_event_body(
    body: &NodeWatchEventBodyV1,
) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
    let kind = match body {
        NodeWatchEventBodyV1::Capability(_) => KIND_WATCH_CAPABILITY_EVENT,
        NodeWatchEventBodyV1::Assignment(_) => KIND_WATCH_ASSIGNMENT_EVENT,
        NodeWatchEventBodyV1::Drain(_) => KIND_WATCH_DRAIN_EVENT,
    };
    Ok(encode(
        kind,
        wire::semantic_envelope::Body::WatchEvent(Box::new(
            semantic_codec_v1::protobuf_watch_event_body(body),
        )),
    ))
}

pub(super) fn decode_watch_event_body(
    bytes: &[u8],
    context: AuthenticatedEvidenceContextV1,
) -> Result<NodeWatchEventBodyV1, InvalidMultiNodeProtocol> {
    let envelope = wire::SemanticEnvelope::decode_from_slice(bytes)
        .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    let expected_kind = match envelope.kind.to_i32() {
        KIND_WATCH_CAPABILITY_EVENT | KIND_WATCH_ASSIGNMENT_EVENT | KIND_WATCH_DRAIN_EVENT => {
            envelope.kind.to_i32()
        }
        _ => return Err(InvalidMultiNodeProtocol::MethodMismatch),
    };
    let body = decode(bytes, expected_kind, super::MAX_NODE_RESPONSE_BYTES)?;
    let wire::semantic_envelope::Body::WatchEvent(body) = body else {
        return Err(InvalidMultiNodeProtocol::MethodMismatch);
    };
    let decoded = semantic_codec_v1::protobuf_watch_event_body_model(*body, context)?;
    let actual_kind = match decoded {
        NodeWatchEventBodyV1::Capability(_) => KIND_WATCH_CAPABILITY_EVENT,
        NodeWatchEventBodyV1::Assignment(_) => KIND_WATCH_ASSIGNMENT_EVENT,
        NodeWatchEventBodyV1::Drain(_) => KIND_WATCH_DRAIN_EVENT,
    };
    if actual_kind != expected_kind {
        return Err(InvalidMultiNodeProtocol::MethodMismatch);
    }
    Ok(decoded)
}

pub(super) fn encode_watch_inventory(
    inventory: &ResyncInventoryV1,
) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
    Ok(encode(
        KIND_RELIST_ASSIGNMENTS_RESPONSE,
        semantic_codec_v1::protobuf_response(&NodeResponseBodyV1::AssignmentInventory(Box::new(
            inventory.clone(),
        )))?,
    ))
}

pub(super) fn decode_watch_inventory(
    bytes: &[u8],
    context: AuthenticatedEvidenceContextV1,
    codec: &CanonicalNodeSemanticCodecV1,
) -> Result<ResyncInventoryV1, InvalidMultiNodeProtocol> {
    let body = decode(
        bytes,
        KIND_RELIST_ASSIGNMENTS_RESPONSE,
        super::MAX_NODE_RESPONSE_BYTES,
    )?;
    let decoded = semantic_codec_v1::protobuf_response_model(
        context,
        CanonicalNodeFrameKindV1::RelistAssignmentsResponse,
        body,
        codec,
    )?;
    let NodeResponseBodyV1::AssignmentInventory(inventory) = decoded else {
        return Err(InvalidMultiNodeProtocol::MethodMismatch);
    };
    Ok(*inventory)
}

fn body_matches_kind(body: Option<&wire::semantic_envelope::Body>, expected_kind: i32) -> bool {
    use wire::semantic_envelope::Body;
    matches!(
        (body, expected_kind),
        (
            Some(Body::GetCapabilitiesRequest(_)),
            KIND_GET_CAPABILITIES_REQUEST
        ) | (
            Some(Body::GetCapabilitiesResponse(_)),
            KIND_GET_CAPABILITIES_RESPONSE
        ) | (
            Some(Body::ReconcileAssignmentRequest(_)),
            KIND_RECONCILE_ASSIGNMENT_REQUEST
        ) | (
            Some(Body::ReconcileAssignmentResponse(_)),
            KIND_RECONCILE_ASSIGNMENT_RESPONSE
        ) | (
            Some(Body::RelistAssignmentsRequest(_)),
            KIND_RELIST_ASSIGNMENTS_REQUEST
        ) | (
            Some(Body::RelistAssignmentsResponse(_)),
            KIND_RELIST_ASSIGNMENTS_RESPONSE
        ) | (
            Some(Body::ReconcileDrainRequest(_)),
            KIND_RECONCILE_DRAIN_REQUEST
        ) | (
            Some(Body::ReconcileDrainResponse(_)),
            KIND_RECONCILE_DRAIN_RESPONSE
        ) | (
            Some(Body::BeginSnapshotTransferRequest(_)),
            KIND_BEGIN_SNAPSHOT_TRANSFER_REQUEST
        ) | (
            Some(Body::BeginSnapshotTransferResponse(_)),
            KIND_BEGIN_SNAPSHOT_TRANSFER_RESPONSE
        ) | (
            Some(Body::SnapshotChunkRequest(_)),
            KIND_SNAPSHOT_CHUNK_REQUEST
        ) | (
            Some(Body::SnapshotChunkResponse(_)),
            KIND_SNAPSHOT_CHUNK_RESPONSE
        ) | (
            Some(Body::SnapshotDependencyRequest(_)),
            KIND_SNAPSHOT_DEPENDENCY_REQUEST
        ) | (
            Some(Body::SnapshotDependencyResponse(_)),
            KIND_SNAPSHOT_DEPENDENCY_RESPONSE
        ) | (Some(Body::WatchRequest(_)), KIND_WATCH_REQUEST)
            | (Some(Body::WatchResponse(_)), KIND_WATCH_RESPONSE)
            | (Some(Body::WatchEvent(_)), KIND_WATCH_CAPABILITY_EVENT)
            | (Some(Body::WatchEvent(_)), KIND_WATCH_ASSIGNMENT_EVENT)
            | (Some(Body::WatchEvent(_)), KIND_WATCH_DRAIN_EVENT)
    )
}

const fn request_kind(kind: CanonicalNodeFrameKindV1) -> i32 {
    match kind {
        CanonicalNodeFrameKindV1::GetCapabilitiesRequest => KIND_GET_CAPABILITIES_REQUEST,
        CanonicalNodeFrameKindV1::ReconcileAssignmentRequest => KIND_RECONCILE_ASSIGNMENT_REQUEST,
        CanonicalNodeFrameKindV1::RelistAssignmentsRequest => KIND_RELIST_ASSIGNMENTS_REQUEST,
        CanonicalNodeFrameKindV1::ReconcileDrainRequest => KIND_RECONCILE_DRAIN_REQUEST,
        CanonicalNodeFrameKindV1::BeginSnapshotTransferRequest => {
            KIND_BEGIN_SNAPSHOT_TRANSFER_REQUEST
        }
        CanonicalNodeFrameKindV1::SnapshotChunkRequest => KIND_SNAPSHOT_CHUNK_REQUEST,
        CanonicalNodeFrameKindV1::SnapshotDependencyRequest => KIND_SNAPSHOT_DEPENDENCY_REQUEST,
        CanonicalNodeFrameKindV1::WatchRequest => KIND_WATCH_REQUEST,
        _ => -1,
    }
}

const fn response_kind(kind: CanonicalNodeFrameKindV1) -> i32 {
    match kind {
        CanonicalNodeFrameKindV1::GetCapabilitiesResponse => KIND_GET_CAPABILITIES_RESPONSE,
        CanonicalNodeFrameKindV1::ReconcileAssignmentResponse => KIND_RECONCILE_ASSIGNMENT_RESPONSE,
        CanonicalNodeFrameKindV1::RelistAssignmentsResponse => KIND_RELIST_ASSIGNMENTS_RESPONSE,
        CanonicalNodeFrameKindV1::ReconcileDrainResponse => KIND_RECONCILE_DRAIN_RESPONSE,
        CanonicalNodeFrameKindV1::BeginSnapshotTransferResponse => {
            KIND_BEGIN_SNAPSHOT_TRANSFER_RESPONSE
        }
        CanonicalNodeFrameKindV1::SnapshotChunkResponse => KIND_SNAPSHOT_CHUNK_RESPONSE,
        CanonicalNodeFrameKindV1::SnapshotDependencyResponse => KIND_SNAPSHOT_DEPENDENCY_RESPONSE,
        CanonicalNodeFrameKindV1::WatchResponse => KIND_WATCH_RESPONSE,
        _ => -1,
    }
}

pub(in crate::multi_node) const fn request_frame_kind(
    kind: i32,
) -> Result<CanonicalNodeFrameKindV1, InvalidMultiNodeProtocol> {
    Ok(match kind {
        KIND_GET_CAPABILITIES_REQUEST => CanonicalNodeFrameKindV1::GetCapabilitiesRequest,
        KIND_RECONCILE_ASSIGNMENT_REQUEST => CanonicalNodeFrameKindV1::ReconcileAssignmentRequest,
        KIND_RELIST_ASSIGNMENTS_REQUEST => CanonicalNodeFrameKindV1::RelistAssignmentsRequest,
        KIND_RECONCILE_DRAIN_REQUEST => CanonicalNodeFrameKindV1::ReconcileDrainRequest,
        KIND_BEGIN_SNAPSHOT_TRANSFER_REQUEST => {
            CanonicalNodeFrameKindV1::BeginSnapshotTransferRequest
        }
        KIND_SNAPSHOT_CHUNK_REQUEST => CanonicalNodeFrameKindV1::SnapshotChunkRequest,
        KIND_SNAPSHOT_DEPENDENCY_REQUEST => CanonicalNodeFrameKindV1::SnapshotDependencyRequest,
        KIND_WATCH_REQUEST => CanonicalNodeFrameKindV1::WatchRequest,
        _ => return Err(InvalidMultiNodeProtocol::MethodMismatch),
    })
}

pub(in crate::multi_node) const fn response_frame_kind(
    kind: i32,
) -> Result<CanonicalNodeFrameKindV1, InvalidMultiNodeProtocol> {
    Ok(match kind {
        KIND_GET_CAPABILITIES_RESPONSE => CanonicalNodeFrameKindV1::GetCapabilitiesResponse,
        KIND_RECONCILE_ASSIGNMENT_RESPONSE => CanonicalNodeFrameKindV1::ReconcileAssignmentResponse,
        KIND_RELIST_ASSIGNMENTS_RESPONSE => CanonicalNodeFrameKindV1::RelistAssignmentsResponse,
        KIND_RECONCILE_DRAIN_RESPONSE => CanonicalNodeFrameKindV1::ReconcileDrainResponse,
        KIND_BEGIN_SNAPSHOT_TRANSFER_RESPONSE => {
            CanonicalNodeFrameKindV1::BeginSnapshotTransferResponse
        }
        KIND_SNAPSHOT_CHUNK_RESPONSE => CanonicalNodeFrameKindV1::SnapshotChunkResponse,
        KIND_SNAPSHOT_DEPENDENCY_RESPONSE => CanonicalNodeFrameKindV1::SnapshotDependencyResponse,
        KIND_WATCH_RESPONSE => CanonicalNodeFrameKindV1::WatchResponse,
        _ => return Err(InvalidMultiNodeProtocol::MethodMismatch),
    })
}
