//! Host-local validation for read-only runtime observation and query requests.
//!
//! Observation protobufs carry a common request header, assignment fence, and
//! opaque runtime handle. The authenticated effect query instead carries the
//! byte-exact original Apply body. Validation accepts no host path, PID, or
//! descriptor and reuses the protocol crate's common peer/session header gate.

use aos_proto::aos::sandbox::local::v1::{
    InventoryRuntimeRequest, ObserveRuntimeRequest, QueryRuntimeEffectRequest,
};
use aos_sandbox_core::ProtocolId;
use aos_sandbox_protocol::session::MAXIMUM_HOST_QUERY_PACKET_BYTES;
use aos_sandbox_protocol::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader,
    validate_request_header,
};
use buffa::Message as _;

use crate::worker::HostRuntimeIdentity;

pub(crate) struct ValidatedObserveRuntimeRequest {
    pub(crate) header: ValidatedHeader,
    pub(crate) identity: HostRuntimeIdentity,
    pub(crate) runtime_handle: [u8; 32],
}

pub(crate) struct ValidatedQueryRuntimeEffectRequest {
    pub(crate) header: ValidatedHeader,
    pub(crate) original_apply_request: Vec<u8>,
}

pub(crate) fn decode_query_runtime_effect_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedQueryRuntimeEffectRequest, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_HOST_QUERY_PACKET_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = QueryRuntimeEffectRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    if request.original_apply_request.is_empty()
        || request.original_apply_request.len() > MAXIMUM_REQUEST_BYTES
    {
        return Err(ProtocolValidationError::InvalidField(
            "original_apply_request",
        ));
    }
    Ok(ValidatedQueryRuntimeEffectRequest {
        header,
        original_apply_request: request.original_apply_request,
    })
}

pub(crate) fn decode_observe_runtime_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedObserveRuntimeRequest, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ObserveRuntimeRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    let fence = request
        .fence
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("fence"))?;
    if !fence.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if fence.assignment_epoch == 0 || fence.desired_generation == 0 {
        return Err(ProtocolValidationError::InvalidField("fence"));
    }
    let identity = HostRuntimeIdentity::new(
        exact_nonzero(&fence.sandbox_id, "fence.sandbox_id")?,
        exact_nonzero(&fence.incarnation_id, "fence.incarnation_id")?,
        fence.assignment_epoch,
        fence.desired_generation,
        exact_nonzero(&fence.assignment_digest, "fence.assignment_digest")?,
    );
    let runtime_handle = exact_nonzero(&request.runtime_handle, "runtime_handle")?;
    Ok(ValidatedObserveRuntimeRequest {
        header,
        identity,
        runtime_handle,
    })
}

pub(crate) fn decode_inventory_runtime_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = InventoryRuntimeRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )
}

fn exact_nonzero<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], ProtocolValidationError> {
    let value: [u8; N] = bytes
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField(field))?;
    if value == [0; N] {
        return Err(ProtocolValidationError::InvalidField(field));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Audience, QueryRuntimeEffectRequest, RequestHeader,
    };

    use super::*;

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn header(minor: u32) -> RequestHeader {
        RequestHeader {
            protocol_major: 1,
            protocol_minor: minor,
            request_id: vec![1; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 1_000,
            maximum_response_bytes: 4_096,
            ..Default::default()
        }
    }

    #[test]
    fn observe_accepts_legacy_and_current_headers_with_exact_opaque_identity() {
        for minor in [0, 1] {
            let request = ObserveRuntimeRequest {
                header: Some(header(minor)).into(),
                fence: Some(AssignmentFence {
                    sandbox_id: vec![2; 16],
                    incarnation_id: vec![3; 16],
                    assignment_epoch: 4,
                    desired_generation: 5,
                    assignment_digest: vec![6; 32],
                    ..Default::default()
                })
                .into(),
                runtime_handle: vec![7; 32],
                ..Default::default()
            };
            let validated =
                decode_observe_runtime_request(&request.encode_to_vec(), peer(), policy(), 100)
                    .unwrap();
            assert_eq!(validated.header.protocol_version().minor(), minor as u16);
            assert_eq!(validated.identity.sandbox_id(), &[2; 16]);
            assert_eq!(validated.runtime_handle, [7; 32]);
        }
    }

    #[test]
    fn inventory_rejects_expired_or_trailing_input() {
        let request = InventoryRuntimeRequest {
            header: Some(header(0)).into(),
            ..Default::default()
        };
        assert!(
            decode_inventory_runtime_request(&request.encode_to_vec(), peer(), policy(), 1_000)
                .is_err()
        );
        let mut trailing = request.encode_to_vec();
        trailing.extend_from_slice(&[0xf8, 0x07, 0x01]);
        assert!(decode_inventory_runtime_request(&trailing, peer(), policy(), 100).is_err());
    }

    #[test]
    fn query_requires_a_bounded_exact_original_apply_body() {
        let request = QueryRuntimeEffectRequest {
            header: Some(header(2)).into(),
            original_apply_request: vec![7; 128],
            ..Default::default()
        };
        let validated =
            decode_query_runtime_effect_request(&request.encode_to_vec(), peer(), policy(), 100)
                .unwrap();
        assert_eq!(validated.original_apply_request, vec![7; 128]);

        let empty = QueryRuntimeEffectRequest {
            header: Some(header(2)).into(),
            ..Default::default()
        };
        assert!(
            decode_query_runtime_effect_request(&empty.encode_to_vec(), peer(), policy(), 100)
                .is_err()
        );
    }
}
