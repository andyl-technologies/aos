//! Verifies exact retained Clock MACs without granting any provider permission.

use std::{collections::BTreeSet, path::Path};

use anyhow::{Result, ensure};
use aos_hub_core::{direct_upload::valid_direct_digest, storage_work::StorageWorkKey};

use super::{
    assembly,
    clock_records::{ClockAction, ClockAuthentication, ClockReply, ClockRequest, ClockResult},
    files,
    selection::ExternalMirrorReviewSelection,
};

pub(super) fn validate(
    base: &Path,
    selected: &ExternalMirrorReviewSelection,
    uncertainty: u64,
) -> Result<String> {
    ensure!(
        (2..=32).contains(&selected.clocks.len()) && (1..30).contains(&uncertainty),
        "Mirror actual Clock sample bound differs"
    );
    let secret = assembly::read(base, &selected.inputs.conformance_key, 4096)?;
    let key = StorageWorkKey::new(std::str::from_utf8(&secret)?.trim())?;
    let mut nonces = BTreeSet::new();
    let mut commitments = Vec::new();
    for capture in &selected.clocks {
        let request_bytes = assembly::read(base, &capture.request, files::DOCUMENT_LIMIT)?;
        let reply_bytes = assembly::read(base, &capture.reply, files::DOCUMENT_LIMIT)?;
        let request: ClockRequest = serde_json::from_slice(&request_bytes)?;
        let reply: ClockReply = serde_json::from_slice(&reply_bytes)?;
        let authentication: ClockAuthentication =
            assembly::document(base, &capture.authentication)?;
        let ClockResult::Clock {
            nonce,
            observed_at_millis,
            uncertainty_seconds,
        } = &reply.result;
        let sent = authentication.sent_at_millis.get();
        let received = authentication.received_at_millis.get();
        let expiry = request
            .expires_at
            .get()
            .checked_mul(1000)
            .ok_or_else(|| anyhow::anyhow!("Mirror Clock expiry overflows"))?;
        let issue = selected
            .issued_at
            .checked_mul(1000)
            .ok_or_else(|| anyhow::anyhow!("Mirror issue overflows"))?;
        ensure!(
            request.version == 1
                && reply.version == 1
                && matches!(request.action, ClockAction::Clock)
                && authentication.status == 200
                && valid_direct_digest(&request.run_id)
                && valid_direct_digest(&request.nonce)
                && nonces.insert(request.nonce.clone())
                && request.source_digest == selected.source_digest
                && request.script_version == selected.script_version
                && reply.source_digest == request.source_digest
                && reply.script_version == request.script_version
                && reply.nonce == request.nonce
                && nonce == &request.nonce
                && reply.request_sha256 == capture.request.sha256
                && authentication.request_sha256 == capture.request.sha256
                && authentication.response_sha256 == capture.reply.sha256
                && sent > 0
                && sent <= received
                && received < expiry
                && expiry - sent <= 30_000
                && received <= issue
                && issue - sent <= 3_600_000
                && reply.observed_at_millis == *observed_at_millis
                && uncertainty_seconds.get() <= uncertainty
                && uncertainty_seconds.get() > 0
                && observed_at_millis
                    .get()
                    .abs_diff(sent)
                    .max(observed_at_millis.get().abs_diff(received))
                    < uncertainty * 1000,
            "Mirror Clock source, original or reference bracket differs"
        );
        key.verify_body(
            &authentication.reply_signature,
            &[
                b"aos.direct-upload.qualification-reply.v1\0".as_slice(),
                reply_bytes.as_slice(),
            ]
            .concat(),
        )?;
        commitments.push((
            &capture.request.sha256,
            &capture.reply.sha256,
            &capture.authentication.sha256,
        ));
    }
    aos_hub_core::mirror_work::digest(&(
        "aos.external-mirror.actual-clock-captures.v1",
        commitments,
    ))
}
