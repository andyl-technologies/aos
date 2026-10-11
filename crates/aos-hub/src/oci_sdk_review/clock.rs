//! Independent exact Clock reply authentication and reference bracket joins.

use std::{collections::BTreeSet, path::Path};

use anyhow::{ensure, Result};
use aos_hub_core::{
    direct_upload::{
        direct_qualification_digest, valid_direct_digest, DirectClockMeasurement, WireInteger,
    },
    storage_work::StorageWorkKey,
};

use super::{
    files,
    observations::{ClockAction, ClockAuthentication, ClockReply, ClockRequest, ClockResult},
    selection::OciSdkReviewSelection,
};

pub(super) fn assemble(
    base: &Path,
    selected: &OciSdkReviewSelection,
) -> Result<DirectClockMeasurement> {
    ensure!(
        (2..=32).contains(&selected.clocks.len()),
        "OCI actual Clock sample count differs"
    );
    let secret = files::private_bytes(&base.join(&selected.conformance_key_file), 4096)?;
    let secret = std::str::from_utf8(&secret)
        .map_err(|_| anyhow::anyhow!("OCI Clock verifier malformed"))?
        .trim();
    ensure!(secret.len() >= 32, "OCI Clock verifier size differs");
    let key = StorageWorkKey::new(secret)?;
    let mut nonces = BTreeSet::new();
    let mut commitments = Vec::with_capacity(selected.clocks.len());
    let mut maximum_skew = 0_u64;
    let uncertainty = selected.clock_policy.uncertainty_seconds.get();

    for capture in &selected.clocks {
        let request_bytes = files::selected_bytes(base, &capture.request)?;
        let reply_bytes = files::selected_bytes(base, &capture.reply)?;
        let request: ClockRequest = serde_json::from_slice(&request_bytes)?;
        let reply: ClockReply = serde_json::from_slice(&reply_bytes)?;
        let authentication: ClockAuthentication = files::document(base, &capture.authentication)?;
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
            .ok_or_else(|| anyhow::anyhow!("OCI Clock original cutoff overflows"))?;

        ensure!(
            matches!(request.action, ClockAction::Clock)
                && request.version == 1
                && reply.version == 1
                && authentication.status == 200
                && valid_direct_digest(&request.run_id)
                && valid_direct_digest(&request.nonce)
                && nonces.insert(request.nonce.clone())
                && request.source_digest == selected.expected_source_digest
                && request.script_version == selected.expected_script_version
                && reply.source_digest == request.source_digest
                && reply.script_version == request.script_version
                && reply.nonce == request.nonce
                && *nonce == request.nonce
                && reply.request_sha256 == capture.request.sha256
                && authentication.request_sha256 == capture.request.sha256
                && authentication.response_sha256 == capture.reply.sha256
                && sent > 0
                && sent <= received
                && received < expiry
                && expiry - sent <= 30_000
                && received
                    <= selected
                        .issued_at
                        .checked_mul(1000)
                        .ok_or_else(|| anyhow::anyhow!("OCI Clock issue overflows"))?
                && selected.issued_at * 1000 - sent <= 3_600_000
                && reply.observed_at_millis == *observed_at_millis
                && uncertainty_seconds.get() == uncertainty,
            "OCI actual Clock original, source or reference bracket differs"
        );
        let signed = [
            b"aos.direct-upload.qualification-reply.v1\0".as_slice(),
            reply_bytes.as_slice(),
        ]
        .concat();
        ensure!(
            valid_direct_digest(&authentication.reply_signature),
            "OCI Clock reply signature malformed"
        );
        key.verify_body(&authentication.reply_signature, &signed)
            .map_err(|_| anyhow::anyhow!("OCI Clock reply authentication differs"))?;

        // Use the more conservative endpoint, retaining network latency rather
        // than silently treating a midpoint estimate as actual UTC precision.
        let observed = observed_at_millis.get();
        let skew = observed.abs_diff(sent).max(observed.abs_diff(received));
        ensure!(
            skew < uncertainty * 1000,
            "OCI measured Clock exceeds installed uncertainty"
        );
        maximum_skew = maximum_skew.max(skew);
        commitments.push((
            &capture.request.sha256,
            &capture.reply.sha256,
            &capture.authentication.sha256,
        ));
    }
    Ok(DirectClockMeasurement {
        observation_sha256: direct_qualification_digest(&(
            "aos.oci-documents.actual-clock-captures.v1",
            commitments,
        ))?,
        samples: WireInteger::new(u64::try_from(selected.clocks.len())?),
        maximum_observed_skew_millis: WireInteger::new(maximum_skew),
        uncertainty_seconds: selected.clock_policy.uncertainty_seconds,
        // This measures only the one-shot anchor original joined separately;
        // it is not evidence of business dispatch refusal after expiry.
        expired_mutation_dispatches: WireInteger::new(0),
    })
}
