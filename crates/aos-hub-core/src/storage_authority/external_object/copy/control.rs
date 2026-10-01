//! Fresh metadata-only permissions for retained placement-copy controls.
//!
//! Public control messages carry no source continuation, multipart receipt or
//! provider bytes. The byte executor obtains those only from the separately
//! authenticated physical guard and its own conditional source reads. Renewing
//! an envelope cannot change the immutable copy owner or clear an unknown turn.
//!
//! ```text
//! request = {version, domain, original, claim, plan, control}
//! control = advance | abort | status
//! reply = {version, request_digest, original_digest, progress}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::storage_authority::{canonical_digest, lease::LeaseInteger};
use crate::storage_work::{StorageWorkKey, StorageWorkOperation, StorageWorkPlan};

use super::{digest_string, session::CopyPhase, CopySourceObject, ExternalCopyOriginal};

/// Internal metadata-only control endpoint, rejected by older executors.
pub const EXTERNAL_COPY_PATH: &str = "/_internal/storage/external-copy/v1";
/// Bounds complete control messages before authentication or decoding.
pub const MAX_EXTERNAL_COPY_CONTROL_BYTES: usize = 64 * 1024;

const DOMAIN: &str = "aos.external-placement-copy-control.v1";
const REPLY_DOMAIN: &[u8] = b"aos.external-placement-copy-control-reply.v1\0";

/// Selects one bounded control without selecting arbitrary provider actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyControl {
    /// Advances the guard-selected next provider action once.
    Advance,
    /// Aborts the original positively known incomplete upload when no effect is unknown.
    Abort,
    /// Reads retained progress without issuing any provider effect or lease.
    Status,
}

/// Binds fresh application permission to one actual live SQL controller claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyClaim {
    /// Exact running operation resource version from the successful claim CAS.
    pub operation_resource_version: LeaseInteger,
    /// Actual retained claim token, never a provider effect or retry identity.
    pub claim_token: String,
    /// Actual SQL claim deadline observed before issuing this permission.
    pub expires_at: LeaseInteger,
}

/// Pairs a full immutable original with fresh current SQL permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCopyRequest {
    /// Closed control version, currently one.
    pub version: u8,
    /// Exact signed application domain.
    pub domain: String,
    /// Full retained operation/source/destination original.
    pub original: ExternalCopyOriginal,
    /// Current SQL claim; never part of the stable original fingerprint.
    pub claim: CopyClaim,
    /// Exact freshly authorized same-binding CopyObject plan.
    pub plan: StorageWorkPlan,
    /// Bounded control; physical action selection belongs to the guard.
    pub control: CopyControl,
}

impl ExternalCopyRequest {
    /// Constructs a closed control from actual original, claim and plan projections.
    ///
    /// # Errors
    /// Returns an error for changed pins, claim deadline or plan eligibility.
    pub fn new(
        original: ExternalCopyOriginal,
        claim: CopyClaim,
        plan: StorageWorkPlan,
        control: CopyControl,
        now: i64,
    ) -> Result<Self> {
        let value = Self {
            version: 1,
            domain: DOMAIN.into(),
            original,
            claim,
            plan,
            control,
        };
        value.validate(&value.original.deployment_id, now)?;
        Ok(value)
    }

    /// Checks exact immutable selectors and fresh metadata permission.
    ///
    /// The caller still checks the live SQL claim and current topology before
    /// signing. The Worker independently checks configured profile/cohorts,
    /// current protected binding and the permanent object floor at dispatch.
    ///
    /// # Errors
    /// Returns an error for a foreign deployment, changed original/plan pins,
    /// unknown fields, missing credential selectors or expired claim permission.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<()> {
        self.original.validate()?;
        self.plan.validate(deployment, now)?;
        let original = &self.original;
        let claim = &self.claim;
        ensure!(
            self.version == 1
                && self.domain == DOMAIN
                && original.deployment_id == deployment
                && self.plan.placement_id == original.destination.placement_id.get()
                && self.plan.placement_resource_version
                    == original.destination.resource_version.get()
                && self.plan.placement_prefix == original.destination.prefix
                && self.plan.binding_id == original.binding_id.get()
                && self.plan.binding_resource_version == original.binding_resource_version.get()
                && matches!(self.plan.binding_kind.as_str(), "s3" | "r2")
                && self.plan.binding_snapshot_revision.as_deref()
                    == Some(&original.snapshot_revision)
                && claim.operation_resource_version.get() > 0
                && claim.claim_token.len() == 32
                && claim
                    .claim_token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && claim.expires_at.get() > now
                && self.plan.expires_at > now
                && self.plan.expires_at < claim.expires_at.get(),
            "external copy permission differs from original or live claim"
        );
        let selectors = &self.plan.credential_references;
        ensure!(
            selectors.len() == 2
                && selectors[0].purpose == "read"
                && selectors[0].generation == original.read_generation.get()
                && selectors[1].purpose == "write"
                && selectors[1].generation == original.write_generation.get(),
            "external copy purpose generations differ"
        );
        let StorageWorkOperation::CopyObject {
            source_placement_id,
            source_placement_resource_version,
            source_prefix,
            path,
            expected_size,
            expected_etag,
        } = &self.plan.operation
        else {
            anyhow::bail!("external copy requires a closed CopyObject plan");
        };
        ensure!(
            *source_placement_id == original.source.placement_id.get()
                && *source_placement_resource_version == original.source.resource_version.get()
                && *source_prefix == original.source.prefix
                && *path == original.path
                && *expected_size == original.source_object.bytes.get() as u64
                && *expected_etag == original.source_object.etag
                && serde_json::to_vec(self)?.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "external copy source selector differs"
        );
        Ok(())
    }

    /// Signs the exact bounded canonical metadata permission.
    ///
    /// # Errors
    /// Returns an error for invalid current permission, encoding or signing.
    pub fn sign(
        &self,
        key: &StorageWorkKey,
        deployment: &str,
        now: i64,
    ) -> Result<(Vec<u8>, String)> {
        self.validate(deployment, now)?;
        let body = serde_json::to_vec(self)?;
        Ok((body.clone(), key.sign_body(&body)?))
    }

    /// Authenticates bytes before decoding the closed metadata control.
    ///
    /// # Errors
    /// Returns an error for oversize, invalid MAC, noncanonical JSON or stale pins.
    pub fn authenticate(
        key: &StorageWorkKey,
        signature: &str,
        body: &[u8],
        deployment: &str,
        now: i64,
    ) -> Result<Self> {
        ensure!(
            body.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "oversized external copy control"
        );
        key.verify_body(signature, body)?;
        let value: Self = serde_json::from_slice(body)?;
        ensure!(
            serde_json::to_vec(&value)? == body,
            "noncanonical external copy control"
        );
        value.validate(deployment, now)?;
        Ok(value)
    }
}

/// Reports compact retained progress without exposing private source continuation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyProgress {
    /// Actual durable copy phase.
    pub phase: CopyPhase,
    /// Exact positively acknowledged ordered part count.
    pub completed_parts: u32,
    /// Exact source bytes covered by those positive parts.
    pub copied_bytes: LeaseInteger,
    /// Indicates a permanent unresolved turn; grants no permission to retry it.
    pub pending: bool,
    /// Actual positive destination incarnation, present only after closure.
    pub destination: Option<CopySourceObject>,
    /// Actual full source SHA-256, present only after exact positive closure.
    pub sha256: Option<String>,
}

impl CopyProgress {
    /// Checks exact progress geometry and positive terminal evidence.
    ///
    /// # Errors
    /// Returns an error for impossible progress, unknown terminal state, missing
    /// physical incarnation or a hash inconsistent with the original declaration.
    pub fn validate(&self, original: &ExternalCopyOriginal) -> Result<()> {
        original.validate()?;
        ensure!(
            self.completed_parts <= original.part_count()?
                && self.copied_bytes.get() as u64
                    == (u64::from(self.completed_parts) * original.part_bytes.get() as u64)
                        .min(original.source_object.bytes.get() as u64),
            "copy progress differs from ordered range geometry"
        );
        if self.phase == CopyPhase::Closed {
            let destination = self
                .destination
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("closed copy lacks positive destination"))?;
            let hash = self
                .sha256
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("closed copy lacks source SHA-256"))?;
            destination.validate()?;
            ensure!(
                !self.pending
                    && self.completed_parts == original.part_count()?
                    && destination.bytes == original.source_object.bytes
                    && digest_string(hash)
                    && original
                        .expected_sha256
                        .as_ref()
                        .is_none_or(|expected| expected == hash),
                "closed copy evidence differs from source original"
            );
        } else {
            ensure!(
                self.destination.is_none() && self.sha256.is_none(),
                "nonterminal copy claims closure"
            );
            ensure!(
                (self.phase != CopyPhase::Creating || self.completed_parts == 0)
                    && (self.phase != CopyPhase::Active
                        || original.source_object.bytes.get() > 0)
                    && (self.phase != CopyPhase::Aborted || !self.pending),
                "copy phase conflicts with progress"
            );
        }
        Ok(())
    }
}

/// Correlates a compact producer reply with the exact current signed request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCopyReply {
    /// Closed reply version, currently one.
    pub version: u8,
    /// Full canonical current request commitment, including claim and deadline.
    pub request_digest: String,
    /// Full immutable original commitment from the retained guard.
    pub original_digest: String,
    /// Compact positive or unresolved durable progress.
    pub progress: CopyProgress,
}

impl ExternalCopyReply {
    /// Constructs an exactly request-correlated bounded reply.
    ///
    /// # Errors
    /// Returns an error for invalid progress or encoding.
    pub fn new(request: &ExternalCopyRequest, progress: CopyProgress) -> Result<Self> {
        progress.validate(&request.original)?;
        Ok(Self {
            version: 1,
            request_digest: canonical_digest(request)?,
            original_digest: request.original.fingerprint()?,
            progress,
        })
    }

    /// Signs a reply under a separate MAC domain, without granting dispatch.
    ///
    /// # Errors
    /// Returns an error for changed request/progress or reply bounds.
    pub fn sign(
        &self,
        key: &StorageWorkKey,
        request: &ExternalCopyRequest,
    ) -> Result<(Vec<u8>, String)> {
        self.validate(request)?;
        let body = serde_json::to_vec(self)?;
        ensure!(
            body.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "oversized copy reply"
        );
        let signature = key.sign_body(&[REPLY_DOMAIN, &body].concat())?;
        Ok((body, signature))
    }

    /// Authenticates a bounded exact reply and rechecks current permission time.
    ///
    /// # Errors
    /// Returns an error for oversize, MAC, canonical closure, changed request,
    /// stale application/claim time or impossible positive evidence.
    pub fn authenticate(
        key: &StorageWorkKey,
        signature: &str,
        body: &[u8],
        request: &ExternalCopyRequest,
        now: i64,
    ) -> Result<Self> {
        ensure!(
            body.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "oversized copy reply"
        );
        key.verify_body(signature, &[REPLY_DOMAIN, body].concat())?;
        let value: Self = serde_json::from_slice(body)?;
        ensure!(
            serde_json::to_vec(&value)? == body,
            "noncanonical copy reply"
        );
        request.validate(&request.original.deployment_id, now)?;
        value.validate(request)?;
        Ok(value)
    }

    fn validate(&self, request: &ExternalCopyRequest) -> Result<()> {
        ensure!(
            self.version == 1
                && self.request_digest == canonical_digest(request)?
                && self.original_digest == request.original.fingerprint()?,
            "copy reply differs from original request"
        );
        self.progress.validate(&request.original)
    }
}

#[cfg(test)]
mod tests;
