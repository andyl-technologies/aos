//! Durable Mount Release request and teardown-authority validation.
//!
//! The acquisition row retains the exact canonical controller request so
//! recovery can reproduce its operation identity, predecessor CAS, and
//! current-or-dominating assignment fence without trusting scalar projections.

use super::*;

pub(super) fn validate_mount_release_request(row: &SourceAcquisitionRowV1) -> Result<()> {
    let (Some(operation), Some(bytes), Some(authority)) = (
        row.release,
        row.mount_release_request.as_deref(),
        row.release_authority,
    ) else {
        if row.release.is_none()
            && row.mount_release_request.is_none()
            && row.release_authority.is_none()
        {
            return Ok(());
        }
        return Err(state_error("Mount Release request presence is partial"));
    };
    let request = ReleaseMountSourceAcquisitionRequest::decode_from_slice(bytes)
        .map_err(|error| state_error(error.to_string()))?;
    let header = request
        .header
        .as_option()
        .ok_or_else(|| state_error("Mount Release header is absent"))?;
    let fence = request
        .fence
        .as_option()
        .ok_or_else(|| state_error("Mount Release fence is absent"))?;
    if !request.__buffa_unknown_fields.is_empty()
        || !header.__buffa_unknown_fields.is_empty()
        || !fence.__buffa_unknown_fields.is_empty()
        || request.encode_to_vec() != bytes
        || header.protocol_major != 2
        || header.protocol_minor != 0
        || header.deadline_boottime_nanoseconds == 0
        || !(aos_sandbox_protocol::MINIMUM_RESPONSE_BYTES
            ..=aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES)
            .contains(&header.maximum_response_bytes)
        || header.audience.as_known()
            != Some(aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER)
        || header.request_id.as_slice() != operation.operation_id
        || mount_source_acquisition_request_digest_v1(bytes).as_bytes() != &operation.request_digest
        || request.acquisition_id.as_slice() != row.acquisition_id
        || request.expected_revision != authority.expected_revision
        || authority.expected_revision == 0
        || request.expected_record_digest.as_slice() != authority.expected_record_digest
        || !nonzero_digest(authority.expected_record_digest)
        || fence.sandbox_id.as_slice() != authority.sandbox_id
        || fence.incarnation_id.as_slice() != authority.incarnation_id
        || fence.assignment_epoch != authority.assignment_epoch
        || fence.desired_generation != authority.desired_generation
        || authority.desired_generation == 0
        || fence.assignment_digest.as_slice() != authority.assignment_digest
        || !release_authority_dominates(row.assignment, authority)
    {
        return Err(state_error(
            "Mount Release request differs from durable teardown authority",
        ));
    }
    Ok(())
}
