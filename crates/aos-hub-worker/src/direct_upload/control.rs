//! Authenticated metadata exchange shared by Worker transport and batch tests.
//!
//! The transport receives the exact signed logical envelope. Returned bytes
//! remain available for physical guards to verify Native's permission and
//! committed acknowledgement independently against the same request context.

use anyhow::Result;
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use async_trait::async_trait;

pub(super) struct LogicalReply {
    pub(super) reply: DirectUploadLogicalReply,
    pub(super) signed: SignedDirectControl,
    pub(super) context: DirectRequestContext,
}

#[async_trait(?Send)]
pub(super) trait Transport {
    async fn post(&self, phase: &str, signed: SignedDirectControl) -> Result<SignedDirectControl>;
}

pub(super) async fn exchange<T: Transport>(
    transport: &T,
    key: &StorageWorkKey,
    context: &DirectRequestContext,
    value: DirectUploadLogicalRequest,
    latest_now: impl Fn() -> Result<u64>,
) -> Result<LogicalReply> {
    context.validate(
        &context.deployment_id,
        &context.executor_public_origin,
        latest_now()?,
    )?;
    let phase = value.phase();
    let envelope = DirectLogicalRequestEnvelope {
        context: context.clone(),
        request: value,
    };
    let request = sign_direct_logical_request(key, &envelope)?;
    let signed = transport.post(phase, request).await?;
    let mut reply =
        verify_direct_logical_reply(key, &signed.signature, &signed.body, context, latest_now()?)?;

    // Only verified Native originals supply the duplicated public intent and
    // placement fields. Mutable versions and lifecycle come from the summary.
    for summary in std::mem::take(&mut reply.reply.session_summaries) {
        let admission = reply
            .reply
            .admissions
            .iter()
            .find(|admission| {
                admission.session_id == summary.session.session_id
                    && admission.logical_fingerprint == summary.session.logical_fingerprint
            })
            .ok_or_else(|| anyhow::anyhow!("direct Native summary original admission absent"))?;
        reply
            .reply
            .sessions
            .push(summary.status(admission, &context.deployment_id)?);
    }

    Ok(LogicalReply {
        reply: reply.reply,
        signed,
        context: context.clone(),
    })
}
