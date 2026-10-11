//! Canonical private logical envelopes and their immutable public correlation.

use super::Capture;
use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{
    decode_direct_control, encode_direct_control, DirectLogicalReplyEnvelope,
    DirectLogicalRequestEnvelope, MAX_DIRECT_CONTROL_BYTES,
};

pub(super) fn classify(capture: &Capture, request: &[u8], response: &[u8]) -> Result<String> {
    ensure!(
        capture.method == "POST"
            && capture.status == 200
            && capture.response_content_type.as_deref() == Some("application/json")
            && request.len() <= MAX_DIRECT_CONTROL_BYTES
            && response.len() <= MAX_DIRECT_CONTROL_BYTES,
        "logical transport differs"
    );
    let original: DirectLogicalRequestEnvelope = decode_direct_control(request)?;
    let reply: DirectLogicalReplyEnvelope = decode_direct_control(response)?;
    ensure!(
        encode_direct_control(&original)? == request && encode_direct_control(&reply)? == response,
        "noncanonical logical envelope"
    );

    let phase = capture
        .phase
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing phase"))?;
    original.validate_transport(
        &capture.method,
        &capture.procedure,
        &original.context.public_authority,
        phase,
    )?;
    original.context.validate(
        &original.context.deployment_id,
        &original.context.executor_public_origin,
        original.context.issued_at.get(),
    )?;
    ensure!(
        reply.context == original.context,
        "logical original context changed"
    );
    reply.reply.validate(&original.context.deployment_id)?;
    // No MAC or current-time result is invented here. The actual independently
    // retained successful Worker verification supplies those stronger checks.
    Ok(original.context.request_body_sha256)
}
