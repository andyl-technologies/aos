//! Authenticated metadata exchange shared by Worker transport and batch tests.
//!
//! The transport receives the exact signed logical envelope. Returned bytes
//! remain available for physical guards to verify Native's permission and
//! committed acknowledgement independently against the same request context.

use anyhow::Result;
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use async_trait::async_trait;
use sha2::Digest as _;

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
    let mut observed = super::observation::Event::new(
        super::observation::Kind::ControlRequest,
        None,
        &context.request_nonce,
    );
    observed.control = Some(super::observation::Control::new(
        context,
        &envelope.request,
        &request.body,
    ));
    observed.direction = Some(super::observation::Direction::WorkerToNative);
    observed.bytes = Some(WireInteger::new(request.body.len() as u64));
    super::observation::emit(&observed);
    let result = transport.post(phase, request).await;
    observed.kind = super::observation::Kind::ControlReply;
    observed.direction = Some(super::observation::Direction::NativeToWorker);
    observed.bytes = result
        .as_ref()
        .ok()
        .map(|signed| WireInteger::new(signed.body.len() as u64));
    observed.outcome = super::observation::Outcome::Unknown;
    if result.is_err() {
        super::observation::emit(&observed);
    }
    let signed = result?;
    if let Some(control) = &mut observed.control {
        control.reply_body_digest = Some(hex::encode(sha2::Sha256::digest(&signed.body)));
    }
    let reply = latest_now().and_then(|now| {
        verify_direct_logical_reply(key, &signed.signature, &signed.body, context, now)
    });
    observed.outcome = if reply.is_ok() {
        super::observation::Outcome::Positive
    } else {
        super::observation::Outcome::Refused
    };
    if let (Some(control), Ok(reply)) = (&mut observed.control, &reply) {
        if control.sessions.is_empty() {
            control.sessions = reply
                .reply
                .admissions
                .iter()
                .map(|admission| {
                    super::observation::Session::new(
                        &admission.session_id,
                        &admission.logical_fingerprint,
                    )
                })
                .collect();
        }
    }
    super::observation::emit(&observed);
    let mut reply = reply?;

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
