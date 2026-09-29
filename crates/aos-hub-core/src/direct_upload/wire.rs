//! Exact bounded signed Native/broker logical requests and result envelopes.
//!
//! Fresh envelopes do not replace the original retained admission. Each domain
//! binds the original public request's bytes, method, path, nonce and audience.
//!
//! ```json
//! {"context":{"deploymentId":"deployment","publicMethod":"POST","publicPath":"/aos.hub.v1.DirectUploadService/CompleteBatch"},"request":{"kind":"authorize","action":"complete","completeStep":"promote"}}
//! ```
//!
//! This abbreviated illustration omits mandatory nonce, deadlines, body digest,
//! exact session intents and independently verified private-stage evidence.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::storage_work::StorageWorkKey;

use super::*;

const REQUEST_DOMAIN: &[u8] = b"aos.direct-upload.logical-request.v1\0";
const REPLY_DOMAIN: &[u8] = b"aos.direct-upload.logical-reply.v1\0";

/// Dedicated exact-body signature header for the private logical request/reply.
pub const DIRECT_LOGICAL_SIGNATURE_HEADER: &str = "x-aos-direct-upload-logical-signature";

/// Exact original public request and deployment/executor audience commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectRequestContext {
    /// Immutable deployment audience.
    pub deployment_id: String,
    /// Protected executor HTTPS public origin, without path or credentials.
    pub executor_public_origin: String,
    /// Fresh transport correlation identity, separate from stable operation IDs.
    pub request_nonce: String,
    /// SHA-256 of the exact original public request body.
    pub request_body_sha256: String,
    /// Exact public method, currently POST.
    pub public_method: String,
    /// Exact package-qualified DirectUploadService request path.
    pub public_path: String,
    /// Inclusive envelope issue time in Unix seconds.
    pub issued_at: WireInteger,
    /// Exclusive short authenticated envelope deadline, at most 30 seconds.
    pub expires_at: WireInteger,
}

impl DirectRequestContext {
    /// Checks exact configured audience and conservative fresh request time.
    ///
    /// `latest_now` must include the caller's qualified clock uncertainty.
    /// Expiry grants no provider settlement or capability-retirement assertion.
    ///
    /// # Errors
    /// Returns a value-free error for audience, method, hash, path or time mismatch.
    pub fn validate(&self, deployment: &str, executor_origin: &str, latest_now: u64) -> Result<()> {
        ensure!(
            valid_direct_identity(deployment)
                && self.deployment_id == deployment
                && self.executor_public_origin == executor_origin
                && valid_origin(executor_origin),
            "direct logical audience mismatch"
        );
        ensure!(
            valid_direct_digest(&self.request_nonce)
                && valid_direct_digest(&self.request_body_sha256)
                && self.public_method == "POST"
                && direct_method(&self.public_path).is_some(),
            "invalid direct logical request context"
        );
        ensure!(
            self.issued_at.get() <= latest_now
                && latest_now < self.expires_at.get()
                && self
                    .expires_at
                    .get()
                    .checked_sub(self.issued_at.get())
                    .is_some_and(|ttl| ttl > 0 && ttl <= 30),
            "direct logical request expired or invalid"
        );
        Ok(())
    }
}

/// Closed signed logical request whose public phase is independently MAC-bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectLogicalRequestEnvelope {
    /// Original public request correlation and protected audience.
    pub context: DirectRequestContext,
    /// Exact typed private phase.
    pub request: DirectUploadLogicalRequest,
}

impl DirectLogicalRequestEnvelope {
    /// Checks the authenticated private phase against the actual HTTP transport.
    ///
    /// The caller must independently MAC-bind the single phase header before
    /// reading the request body; this check correlates that header with the arm.
    ///
    /// # Errors
    /// Returns an error for a changed actual method, public path or private phase.
    pub fn validate_transport(&self, method: &str, path: &str, phase: &str) -> Result<()> {
        ensure!(
            self.context.public_method == method
                && self.context.public_path == path
                && self.request.phase() == phase,
            "direct logical transport phase mismatch"
        );
        validate_phase(self)
    }
}

/// Closed signed logical reply correlated to one exact original request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectLogicalReplyEnvelope {
    /// Exact unchanged context from the authenticated request.
    pub context: DirectRequestContext,
    /// Exact metadata-only logical response.
    pub reply: DirectUploadLogicalReply,
}

/// Transport-ready authenticated bytes with no Debug-visible signature or body.
#[derive(Clone)]
pub struct SignedDirectControl {
    /// Exact canonical typed JSON body, bounded to 256 KiB.
    pub body: Vec<u8>,
    /// Domain-separated protected application HMAC header value.
    pub signature: String,
}

impl std::fmt::Debug for SignedDirectControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedDirectControl")
            .field("body_bytes", &self.body.len())
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// Signs an exact typed request under its distinct protected application domain.
///
/// # Errors
/// Returns an error for invalid phase/correlation, encoded size or signature.
pub fn sign_direct_logical_request(
    key: &StorageWorkKey,
    envelope: &DirectLogicalRequestEnvelope,
) -> Result<SignedDirectControl> {
    validate_phase(envelope)?;
    sign_control(key, REQUEST_DOMAIN, envelope)
}

/// Authenticates bounded raw bytes before parsing and validates audience/time.
///
/// # Errors
/// Returns a value-free error for bad signature, excessive/unknown/duplicate
/// fields, noncanonical encoding, wrong phase, audience or expired context.
pub fn verify_direct_logical_request(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    deployment: &str,
    executor_origin: &str,
    latest_now: u64,
) -> Result<DirectLogicalRequestEnvelope> {
    let envelope: DirectLogicalRequestEnvelope =
        verify_control(key, REQUEST_DOMAIN, signature, body)?;
    envelope
        .context
        .validate(deployment, executor_origin, latest_now)?;
    validate_phase(&envelope)?;
    Ok(envelope)
}

/// Signs a metadata-only logical reply under a separate response domain.
///
/// # Errors
/// Returns an error for malformed/oversized reply or signature construction.
pub fn sign_direct_logical_reply(
    key: &StorageWorkKey,
    envelope: &DirectLogicalReplyEnvelope,
) -> Result<SignedDirectControl> {
    envelope.reply.validate(&envelope.context.deployment_id)?;
    sign_control(key, REPLY_DOMAIN, envelope)
}

/// Verifies a reply against the exact request context and current expiry bound.
///
/// # Errors
/// Returns an error for signature, encoding, changed context, stale time or
/// malformed bounded reply. Business/provider evidence remains independently checked.
pub fn verify_direct_logical_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    expected: &DirectRequestContext,
    latest_now: u64,
) -> Result<DirectLogicalReplyEnvelope> {
    let envelope: DirectLogicalReplyEnvelope = verify_control(key, REPLY_DOMAIN, signature, body)?;
    ensure!(
        &envelope.context == expected,
        "direct logical reply correlation mismatch"
    );
    envelope.context.validate(
        &expected.deployment_id,
        &expected.executor_public_origin,
        latest_now,
    )?;
    envelope.reply.validate(&expected.deployment_id)?;
    Ok(envelope)
}

fn sign_control<T: Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    value: &T,
) -> Result<SignedDirectControl> {
    let body = encode_direct_control(value)?;
    let signature = key
        .sign_body(&domain_body(domain, &body))
        .map_err(|_| anyhow::anyhow!("direct logical signing failed"))?;
    Ok(SignedDirectControl { body, signature })
}

fn verify_control<T: serde::de::DeserializeOwned + Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    signature: &str,
    body: &[u8],
) -> Result<T> {
    ensure!(
        body.len() <= MAX_DIRECT_CONTROL_BYTES,
        "direct logical control exceeds limit"
    );
    key.verify_body(signature, &domain_body(domain, body))
        .map_err(|_| anyhow::anyhow!("direct logical authentication failed"))?;
    let value: T = decode_direct_control(body)?;
    ensure!(
        encode_direct_control(&value)? == body,
        "noncanonical direct logical control"
    );
    Ok(value)
}

fn domain_body(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(domain.len() + body.len());
    value.extend_from_slice(domain);
    value.extend_from_slice(body);
    value
}

fn validate_phase(envelope: &DirectLogicalRequestEnvelope) -> Result<()> {
    let method = direct_method(&envelope.context.public_path);
    match &envelope.request {
        DirectUploadLogicalRequest::Admission { intents } => {
            ensure!(
                method == Some("BeginBatch")
                    && !intents.is_empty()
                    && intents.len() <= MAX_DIRECT_BATCH_ITEMS,
                "direct logical admission phase mismatch"
            );
            for intent in intents {
                intent.validate()?;
            }
        }
        DirectUploadLogicalRequest::Authorize {
            action,
            complete_step,
            stage_evidence,
            sessions,
        } => {
            let expected = match action {
                DirectLogicalAction::Status => "StatusBatch",
                DirectLogicalAction::GrantParts => "GrantPartsBatch",
                DirectLogicalAction::ReportParts => "ReportPartsBatch",
                DirectLogicalAction::Complete => "CompleteBatch",
                DirectLogicalAction::Abort => "Abort",
            };
            ensure!(
                method == Some(expected)
                    && (*action == DirectLogicalAction::Complete) == complete_step.is_some()
                    && !sessions.is_empty()
                    && sessions.len() <= MAX_DIRECT_BATCH_ITEMS,
                "direct logical authorization phase mismatch"
            );
            for session in sessions {
                session.session.validate()?;
                ensure!(
                    valid_direct_digest(&session.operation_id),
                    "invalid direct logical operation"
                );
                let mutating = matches!(
                    action,
                    DirectLogicalAction::Complete | DirectLogicalAction::Abort
                );
                ensure!(
                    mutating == session.expected_resource_version.is_some()
                        && session
                            .expected_resource_version
                            .is_none_or(|v| (1..=i64::MAX as u64).contains(&v.get())),
                    "direct logical mutation version mismatch"
                );
                ensure!(
                    (*action == DirectLogicalAction::Complete) == session.complete_intent.is_some(),
                    "direct logical complete intent presence mismatch"
                );
                if let Some(intent) = &session.complete_intent {
                    intent.fingerprint()?;
                    ensure!(
                        intent.session == session.session
                            && intent.operation_id == session.operation_id
                            && Some(intent.expected_resource_version)
                                == session.expected_resource_version,
                        "direct logical original complete intent mismatch"
                    );
                }
            }
            let promote = *complete_step == Some(DirectCompleteStep::Promote);
            ensure!(
                (!promote && stage_evidence.is_empty())
                    || (promote && stage_evidence.len() == sessions.len()),
                "direct promotion stage evidence count mismatch"
            );
            for (evidence, session) in stage_evidence.iter().zip(sessions) {
                evidence.validate()?;
                ensure!(
                    evidence.session_id == session.session.session_id
                        && evidence.logical_fingerprint == session.session.logical_fingerprint
                        && evidence.operation_id == session.operation_id,
                    "direct promotion stage correlation mismatch"
                );
                let intent = session.complete_intent.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("direct promotion lacks original complete intent")
                })?;
                ensure!(
                    evidence
                        .placements
                        .iter()
                        .map(|placement| &placement.manifest)
                        .eq(intent.manifests.iter()),
                    "direct promotion original manifest mismatch"
                );
            }
        }
        DirectUploadLogicalRequest::Commit { evidence } => {
            ensure!(
                method == Some("CompleteBatch")
                    && !evidence.is_empty()
                    && evidence.len() <= MAX_DIRECT_BATCH_ITEMS,
                "direct logical commit phase mismatch"
            );
            for item in evidence {
                item.validate()?;
            }
        }
        DirectUploadLogicalRequest::AbortReport { outcomes } => {
            ensure!(
                method == Some("Abort")
                    && !outcomes.is_empty()
                    && outcomes.len() <= MAX_DIRECT_BATCH_ITEMS,
                "direct logical abort phase mismatch"
            );
            for item in outcomes {
                item.session.validate()?;
                ensure!(
                    valid_direct_digest(&item.operation_id)
                        && (item.outcome == DirectAbortOutcome::Aborted)
                            == item.receipt_digest.is_some()
                        && item
                            .receipt_digest
                            .as_ref()
                            .is_none_or(|digest| valid_direct_digest(digest)),
                    "invalid direct abort evidence"
                );
            }
        }
    }
    encode_direct_control(envelope)?;
    Ok(())
}

fn direct_method(path: &str) -> Option<&str> {
    let method = path.strip_prefix("/aos.hub.v1.DirectUploadService/")?;
    [
        "GetCapabilities",
        "BeginBatch",
        "StatusBatch",
        "GrantPartsBatch",
        "ReportPartsBatch",
        "CompleteBatch",
        "Abort",
    ]
    .contains(&method)
    .then_some(method)
}

fn valid_origin(origin: &str) -> bool {
    url::Url::parse(origin).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.origin().ascii_serialization() == origin
    })
}
