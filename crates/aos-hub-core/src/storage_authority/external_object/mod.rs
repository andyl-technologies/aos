//! Closed application envelopes for the first external object consumer.
//!
//! A short-lived application plan authorizes a request; a separately signed
//! epoch lease admits new dispatch. A caller-retained operation ID identifies
//! the provider effect across fresh grants. Historical HEAD replay is explicitly
//! historical and establishes neither current readiness nor unknown settlement.
//! This wire does not enable physical domains or migrate business workflows.
//!
//! ```text
//! POST /_internal/storage/external-object/v1
//! x-aos-storage-work-signature: <application HMAC>
//! {version,domain,operation_id,binding_write_revision,plan,lease}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::storage_work::{StorageWorkKey, StorageWorkOperation, StorageWorkPlan};

/// Exact delegated-stage and server-owned external multipart controls.
pub mod stage;

/// Exact provider-incarnation commitments for conditional deletion.
pub mod deletion;

/// Immutable same-binding topology-copy originals and physical ownership.
pub mod copy;

/// Metadata-only guarded HEAD intervals and explicitly historical replay.
pub mod observation;

/// First bounded consumer endpoint; older Workers reject the unknown route.
pub const EXTERNAL_OBJECT_PATH: &str = "/_internal/storage/external-object/v1";
/// Bounds the full application envelope before parsing or body decoding.
pub const MAX_EXTERNAL_OBJECT_REQUEST_BYTES: usize = 256 * 1024;
/// Distinguishes this closed application envelope from ordinary storage plans.
pub const EXTERNAL_OBJECT_APPLICATION_DOMAIN: &str = "aos.external-object-application.v1";

/// Fresh application authorization paired with caller-retained effect identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObjectRequest {
    /// Closed wire version, currently one.
    pub version: u8,
    /// Exact domain marker; signed along with every request field.
    pub domain: String,
    /// Stable operation identity retained before a first provider attempt.
    pub operation_id: String,
    /// Exact writer revision asserted by the independent application authority.
    pub binding_write_revision: super::lease::LeaseInteger,
    /// Independent short-lived application permission and body commitment.
    pub plan: StorageWorkPlan,
    /// Exact canonical signed epoch lease, never used as the trust source.
    pub lease: String,
}

impl ExternalObjectRequest {
    /// Signs one bounded closed application envelope under the plan key.
    ///
    /// The signed domain marker and closed decoder distinguish this message;
    /// the existing plan-key HMAC primitive is reused without key duplication.
    ///
    /// # Errors
    /// Returns an error for invalid identity, grant, lease size or wire bounds.
    pub fn sign(
        &self,
        key: &StorageWorkKey,
        deployment_id: &str,
        now: i64,
    ) -> Result<(Vec<u8>, String)> {
        self.validate(deployment_id, now)?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_EXTERNAL_OBJECT_REQUEST_BYTES,
            "external application envelope too large"
        );
        let signature = key.sign_body(&bytes)?;
        Ok((bytes, signature))
    }

    /// Authenticates exact bytes before decoding a bounded application grant.
    ///
    /// # Errors
    /// Returns an error for signature, closure, encoding, time or plan mismatch.
    pub fn authenticate(
        key: &StorageWorkKey,
        signature: &str,
        bytes: &[u8],
        deployment_id: &str,
        now: i64,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_EXTERNAL_OBJECT_REQUEST_BYTES,
            "external application envelope too large"
        );
        key.verify_body(signature, bytes)?;
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&value)? == bytes,
            "noncanonical external application envelope"
        );
        value.validate(deployment_id, now)?;
        Ok(value)
    }

    /// Rechecks only time immediately after prior cryptographic validation.
    ///
    /// The caller supplies the exact validated payload, acknowledged object
    /// floor and binding snapshot from this request. This inexpensive check
    /// observes time after signature/hash work; it authenticates no input and
    /// permits no await between successful return and provider invocation.
    /// Existing application/snapshot expiry is inclusive; lease expiry is not.
    ///
    /// # Errors
    /// Returns an error for rollback, uncertainty, expired or future permission.
    pub fn check_dispatch_time(
        &self,
        snapshot: &crate::storage_work::StorageBindingSnapshot,
        validated: &super::lease::ValidatedEpochLease,
        floor: &super::lease::EpochLeaseFloor,
        clock: super::lease::LeaseClock,
    ) -> Result<()> {
        let payload = &validated.payload;
        ensure!(
            clock.observed_at >= floor.clock_floor.get()
                && clock.uncertainty >= 0
                && clock.uncertainty <= payload.timing_profile.maximum_clock_uncertainty.get(),
            "unqualified final dispatch clock"
        );
        let earliest = clock
            .observed_at
            .checked_sub(clock.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("final clock underflow"))?;
        let latest = clock
            .observed_at
            .checked_add(clock.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("final clock overflow"))?;
        ensure!(
            earliest >= 0 && payload.issued_at.get() <= latest && latest < payload.not_after.get(),
            "lease expired at actual dispatch observation"
        );
        for (issued, expires) in [
            (self.plan.issued_at, self.plan.expires_at),
            (snapshot.issued_at, snapshot.expires_at),
        ] {
            ensure!(
                issued <= clock.observed_at.saturating_add(5) && expires >= clock.observed_at,
                "application permission expired at actual dispatch observation"
            );
        }
        Ok(())
    }

    /// Checks closed metadata-only scope without granting provider admission.
    ///
    /// # Errors
    /// Returns an error for invalid identity, operation or short-lived plan.
    pub fn validate(&self, deployment_id: &str, now: i64) -> Result<()> {
        ensure!(
            self.version == 1 && self.domain == EXTERNAL_OBJECT_APPLICATION_DOMAIN,
            "invalid external application domain"
        );
        ensure!(
            !self.operation_id.is_empty()
                && self.operation_id.len() <= 128
                && self
                    .operation_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')),
            "invalid retained operation identity"
        );
        ensure!(
            self.lease.len() <= super::lease::MAX_EPOCH_LEASE_BYTES,
            "oversized epoch lease"
        );
        ensure!(
            self.binding_write_revision.get() > 0,
            "missing application writer revision"
        );
        self.plan.validate(deployment_id, now)?;
        ensure!(
            matches!(
                self.plan.operation,
                StorageWorkOperation::PutMetadata { .. }
                    | StorageWorkOperation::PutProbe { .. }
                    | StorageWorkOperation::Head { .. }
                    | StorageWorkOperation::DeleteIfMatches { .. }
                    | StorageWorkOperation::InspectSha256 { .. }
            ) && self.plan.binding_kind != "deployment_r2",
            "unsupported external object operation"
        );
        if let StorageWorkOperation::InspectSha256 {
            path,
            max_source_bytes,
            ..
        } = &self.plan.operation
        {
            ensure!(
                crate::storage_work::admitted_probe_path(path) && *max_source_bytes <= 4096,
                "compact external inspection is restricted to bounded reserved probes"
            );
        }
        Ok(())
    }
}

/// A receipt for one retained turn; this result never permits another dispatch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObjectResult {
    /// Closed receipt version, currently one.
    pub version: u8,
    /// Retained caller effect identity, independent of fresh plan UUIDs.
    pub operation_id: String,
    /// Exact nonsecret semantic intent commitment retained by the object guard.
    pub intent_digest: String,
    /// Provider acknowledgement or explicitly historical observation.
    pub outcome: ExternalObjectOutcome,
}

/// Terminal values of the bounded external object slice.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalObjectOutcome {
    /// A positive provider acknowledgement of this exact metadata PUT.
    PutAcknowledged,
    /// Historical exact-key HEAD from this retained turn; replay is not current.
    HistoricalHead {
        /// None denotes this turn's exact provider HEAD 404, not write settlement.
        object: Option<ExternalObjectHead>,
    },
    /// Positive conditional DELETE acknowledgement for the retained version.
    DeleteAcknowledged {
        /// Exact actual provider version acknowledged by the provider.
        provider_version: String,
        /// Exact entity tag signed into the conditional request.
        etag: String,
    },
    /// Positive absence observation for the exact retained deletion turn.
    DeleteAbsent,
    /// The provider refused the exact version/entity-tag precondition.
    DeletePreconditionFailed,
    /// Exact bounded reserved-probe bytes hashed beside storage.
    ProbeEvidence {
        /// Actual provider metadata for the returned body snapshot.
        object: ExternalObjectHead,
        /// SHA-256 of the complete bounded body, without returning those bytes.
        sha256: String,
    },
}

/// Bounded provider metadata from one historical HEAD turn.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObjectHead {
    /// Canonical decimal byte length; JSON numbers never round this field.
    pub bytes: String,
    /// Exact strong ETag returned by that HEAD; it is not an incarnation stamp.
    pub etag: String,
    /// Actual immutable provider version, absent on historical nonversioned heads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_version: Option<String>,
}
