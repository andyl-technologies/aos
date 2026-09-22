//! Authorized public watch bootstrap and bound continuation handling.

use std::time::{SystemTime, UNIX_EPOCH};

use aos_proto::aos::sandbox::v1::{Event, EventKind, Timestamp, WatchRequest};
use aos_sandbox::cli_model::PublicApiAuditMethodV1;
use aos_sandbox::controller_query::{
    NormalizedQueryDigestV1, QueryBindingV1, QueryFilterDigestV1, QuerySortDigestV1,
    QueryVisibilityDigestV1, checked_watch_request_commitment_v1,
};
use aos_sandbox_core::{Operation, ResourceKind};
use buffa::Message as _;
use connectrpc::{ConnectError, ErrorCode, RequestContext, ServiceRequest, ServiceResult};
use futures::stream;
use sha2::{Digest as _, Sha256};

use super::public_services::{exact_resource_id, resource_selector, response_with_query_binding};
use super::{CapabilityService, ResponseStream};

const WATCH_PATH: &[u8] = b"/aos.sandbox.v1.OperationService/Watch";
const WATCH_CURSOR_MAGIC: &[u8; 8] = b"AOSWCR01";
const WATCH_WATERMARK_MAGIC: &[u8; 8] = b"AOSWWM01";
const WATCH_SEQUENCE: u64 = 1;
const WATCH_TOKEN_BYTES: usize =
    8 + aos_sandbox::controller_query::QUERY_BINDING_TRANSPORT_BYTES + 16 + 8 + 32;

impl CapabilityService {
    pub(super) async fn watch_response(
        &self,
        context: &RequestContext,
        request: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ResponseStream<Event>> {
        let protobuf_body = request.bytes().to_vec();
        let mut wire = request.to_owned_message();
        checked_watch_request_commitment_v1(&wire).map_err(|_| invalid_watch_request())?;
        let project_id = exact_resource_id(&wire.project_id, "project")?;
        let authorization = self
            .authorize_public_read(
                context,
                PublicApiAuditMethodV1::Watch,
                ResourceKind::Sandbox,
                Operation::MetadataRead,
                resource_selector(project_id),
                &protobuf_body,
            )
            .await?;

        let resume_cursor = wire
            .resume_after
            .as_option()
            .map(|cursor| cursor.opaque_cursor.clone());
        wire.resume_after = Default::default();
        let filter_bytes = wire.encode_to_vec();
        let binding =
            watch_query_binding(authorization, project_id, &filter_bytes, wire.audit_only);

        if let Some(cursor) = resume_cursor {
            decode_watch_token(&cursor, WATCH_CURSOR_MAGIC, binding, project_id)?;
            return response_with_query_binding(Box::pin(stream::empty()), binding);
        }

        let cursor = encode_watch_token(WATCH_CURSOR_MAGIC, binding, project_id, WATCH_SEQUENCE);
        let watermark =
            encode_watch_token(WATCH_WATERMARK_MAGIC, binding, project_id, WATCH_SEQUENCE);
        let marker = snapshot_complete_event(cursor, watermark)?;
        response_with_query_binding(Box::pin(stream::iter([Ok(marker)])), binding)
    }
}

fn watch_query_binding(
    authorization: aos_sandbox::cli_model::AuditAuthorizationV1,
    project_id: [u8; 16],
    filter_bytes: &[u8],
    audit_only: bool,
) -> QueryBindingV1 {
    let mut normalized = Vec::with_capacity(WATCH_PATH.len() + 1 + project_id.len());
    normalized.extend_from_slice(WATCH_PATH);
    normalized.push(0);
    normalized.extend_from_slice(&project_id);
    let visibility = if audit_only {
        b"authorized-audit-events-v1".as_slice()
    } else {
        b"authorized-public-events-v1".as_slice()
    };

    authorization.query_binding(
        NormalizedQueryDigestV1::commit(&normalized),
        QueryFilterDigestV1::commit(filter_bytes),
        QuerySortDigestV1::commit(b"event-sequence-ascending-v1"),
        QueryVisibilityDigestV1::commit(visibility),
    )
}

fn encode_watch_token(
    magic: &[u8; 8],
    binding: QueryBindingV1,
    project_id: [u8; 16],
    sequence: u64,
) -> Vec<u8> {
    let mut token = Vec::with_capacity(WATCH_TOKEN_BYTES);
    token.extend_from_slice(magic);
    token.extend_from_slice(&binding.to_transport_bytes());
    token.extend_from_slice(&project_id);
    token.extend_from_slice(&sequence.to_be_bytes());
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.public-watch-token.v1\0")
        .chain_update(&token)
        .finalize()
        .into();
    token.extend_from_slice(&digest);
    token
}

fn decode_watch_token(
    token: &[u8],
    magic: &[u8; 8],
    binding: QueryBindingV1,
    project_id: [u8; 16],
) -> Result<u64, ConnectError> {
    let binding_start = magic.len();
    let project_start =
        binding_start + aos_sandbox::controller_query::QUERY_BINDING_TRANSPORT_BYTES;
    let sequence_start = project_start + project_id.len();
    let digest_start = sequence_start + 8;
    if token.len() != WATCH_TOKEN_BYTES
        || token.get(..binding_start) != Some(magic.as_slice())
        || token.get(binding_start..project_start) != Some(binding.to_transport_bytes().as_slice())
        || token.get(project_start..sequence_start) != Some(project_id.as_slice())
    {
        return Err(invalid_watch_cursor());
    }
    let expected: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.public-watch-token.v1\0")
        .chain_update(&token[..digest_start])
        .finalize()
        .into();
    if token[digest_start..] != expected {
        return Err(invalid_watch_cursor());
    }
    let sequence = token
        .get(sequence_start..digest_start)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or_else(invalid_watch_cursor)?;
    if sequence != WATCH_SEQUENCE {
        return Err(invalid_watch_cursor());
    }

    Ok(sequence)
}

fn snapshot_complete_event(
    resume_cursor: Vec<u8>,
    bootstrap_watermark: Vec<u8>,
) -> Result<Event, ConnectError> {
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "system clock precedes Unix epoch"))?;
    let mut event_id: [u8; 16] = Sha256::new()
        .chain_update(b"aos.sandbox.public-watch-snapshot-complete.v1\0")
        .chain_update(&resume_cursor)
        .finalize()[..16]
        .try_into()
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "watch event identity failed"))?;
    event_id[0] |= 1;

    Ok(Event {
        event_id: event_id.to_vec(),
        sequence: WATCH_SEQUENCE,
        kind: EventKind::EVENT_KIND_SNAPSHOT_COMPLETE.into(),
        observed_at: Some(Timestamp {
            seconds: i64::try_from(observed_at.as_secs()).map_err(|_| {
                ConnectError::new(
                    ErrorCode::Internal,
                    "system clock is outside timestamp range",
                )
            })?,
            nanoseconds: observed_at.subsec_nanos(),
            ..Default::default()
        })
        .into(),
        resume_cursor,
        bootstrap_watermark,
        ..Default::default()
    })
}

fn invalid_watch_request() -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, "watch request is invalid")
}

fn invalid_watch_cursor() -> ConnectError {
    ConnectError::new(
        ErrorCode::InvalidArgument,
        "watch cursor does not match the authorized query",
    )
}
