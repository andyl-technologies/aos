//! Read-only authentication of one retained positive Copy envelope.
//!
//! The production request and reply authenticators check their separate MAC
//! domains, canonical bytes, correlation, positive geometry and deadlines. UTC
//! is sampled here, never supplied by the caller. A successful observation says
//! nothing about installed key identity, current SQL ownership, independently
//! qualified Clock, physical provider settlement or permission to dispatch.
//!
//! ```text
//! storage-body-codec copy-closed-reply <private-selection.json>
//! selection = {version, sourceDigest, deploymentId, expectedOriginalSha256,
//!              key, request, reply, requestSignature, replySignature}
//! body reference = {file, sha256, byteSize}
//! result = {version, scope, sourceDigest, codecSourceSha256, originalSha256,
//!           requestSha256, requestBytes, replySha256, replyBytes, observedAt,
//!           phase}
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Result};
use aos_hub_core::{
    storage_authority::external_object::copy::{
        control::{ExternalCopyReply, ExternalCopyRequest, MAX_EXTERNAL_COPY_CONTROL_BYTES},
        session::CopyPhase,
    },
    storage_work::StorageWorkKey,
};
use serde::{Deserialize, Serialize};

use super::files::{self, BodyFile};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Selection {
    version: u32,
    source_digest: String,
    deployment_id: String,
    expected_original_sha256: String,
    key: BodyFile,
    request: BodyFile,
    reply: BodyFile,
    request_signature: String,
    reply_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Observation {
    version: u32,
    scope: &'static str,
    source_digest: String,
    codec_source_sha256: String,
    original_sha256: String,
    request_sha256: String,
    request_bytes: String,
    reply_sha256: String,
    reply_bytes: String,
    observed_at: i64,
    phase: &'static str,
}

fn authenticate(
    key: &StorageWorkKey,
    request_signature: &str,
    request: &[u8],
    reply_signature: &str,
    reply: &[u8],
    deployment: &str,
    original: &str,
    now: i64,
) -> Result<()> {
    let request =
        ExternalCopyRequest::authenticate(key, request_signature, request, deployment, now)?;
    ensure!(
        request.original.fingerprint()? == original,
        "selected Copy original differs"
    );
    let reply = ExternalCopyReply::authenticate(key, reply_signature, reply, &request, now)?;
    ensure!(
        reply.progress.phase == CopyPhase::Closed,
        "Copy is not closed"
    );
    Ok(())
}

/// Checks the selected actual envelopes without signing or executing work.
///
/// # Errors
/// Refuses changed or insecure private files, invalid selection, nonliteral key,
/// excessive bodies, invalid MAC/canonical shape/correlation, expired permission,
/// an unexpected original or nonpositive progress. The error output hides values.
pub(super) fn inspect(selection: Selection) -> Result<Observation> {
    ensure!(
        selection.version == 1
            && files::valid_digest(&selection.source_digest)
            && files::valid_digest(&selection.expected_original_sha256),
        "invalid Closed envelope selection"
    );
    ensure!(
        selection.key.byte_size == "64",
        "unexpected installed key size"
    );
    for body in [&selection.request, &selection.reply] {
        ensure!(
            body.byte_size.parse::<usize>()? <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "Copy envelope exceeds bound"
        );
    }
    for signature in [&selection.request_signature, &selection.reply_signature] {
        ensure!(
            !signature.is_empty() && signature.len() <= 256,
            "invalid selected signature size"
        );
    }

    let mut consumed = 0;
    let literal_key = files::read(&selection.key, &mut consumed)?;
    ensure!(
        literal_key.len() == 64
            && literal_key
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "installed key must remain literal lowercase hex bytes"
    );
    let key = StorageWorkKey::new(&literal_key)?;
    let request = files::read(&selection.request, &mut consumed)?;
    let reply = files::read(&selection.reply, &mut consumed)?;
    let observed_at = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    authenticate(
        &key,
        &selection.request_signature,
        &request,
        &selection.reply_signature,
        &reply,
        &selection.deployment_id,
        &selection.expected_original_sha256,
        observed_at,
    )?;

    let mut source = Vec::new();
    for file in [
        include_bytes!("main.rs").as_slice(),
        include_bytes!("files.rs").as_slice(),
        include_bytes!("classify.rs").as_slice(),
        include_bytes!("storage_work.rs").as_slice(),
        include_bytes!("ingress.rs").as_slice(),
        include_bytes!("controls.rs").as_slice(),
        include_bytes!("copy_request.rs").as_slice(),
        include_bytes!("copy_closed.rs").as_slice(),
    ] {
        source.extend_from_slice(file);
    }
    Ok(Observation {
        version: 1,
        scope: "authenticated_copy_closed_envelope_only",
        source_digest: selection.source_digest,
        codec_source_sha256: files::digest(&source),
        original_sha256: selection.expected_original_sha256,
        request_sha256: files::digest(&request),
        request_bytes: request.len().to_string(),
        reply_sha256: files::digest(&reply),
        reply_bytes: reply.len().to_string(),
        observed_at,
        phase: "closed",
    })
}

#[cfg(test)]
mod tests;
