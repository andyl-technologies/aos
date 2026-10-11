//! Scope-bound receipts for deterministic bundle reproduction.
//!
//! A receipt records semantic agreement with supplied inputs. It establishes no
//! provider, publication, disposition, source or release authority. Hosts retain
//! and authorize receipts separately from authoritative assessment heads.
//!
//! ```json
//! {"schema":"aos.assessment-bundle-reproduction/v1",
//!  "classification":"reproduced","authority":"not-established",
//!  "resourceScope":"local-example","bundleManifestDigest":"sha256:...",
//!  "inventoryDigest":"sha256:...","scanInputDigest":"sha256:...",
//!  "assessmentDigest":"sha256:...","engineDigest":"sha256:...",
//!  "profile":"reference","externalRawMembers":1,
//!  "validatedAt":"2026-10-10T12:00:00Z"}
//! ```

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};

use crate::bundle::{AssessmentBundleV1, BundleProfile};
use crate::time::Timestamp;
use crate::validation::{decode_with_limits, digest, text};

/// Identifies a semantic reproduction proof without an authority admission.
pub const BUNDLE_REPRODUCTION_V1: &str = "aos.assessment-bundle-reproduction/v1";

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 64 * 1024,
    max_depth: 8,
    max_items: 128,
    max_string_bytes: 128,
};

/// Names the verified property of this specific receipt contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReproductionClassification {
    /// The supplied normalized inputs reproduce the claimed canonical assessment.
    Reproduced,
}

/// Separates reproduction from independently established evidence authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReproductionAuthority {
    /// No provider, publisher or release authorization was established by replay.
    NotEstablished,
}

/// Records exact bundle agreement in one independently authorized host namespace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BundleReproductionV1 {
    /// Exact specialized reproduction receipt schema.
    pub schema: String,
    /// Semantic classification, independent of evidence authenticity.
    pub classification: ReproductionClassification,
    /// Explicit absence of an authority admission in this receipt.
    pub authority: ReproductionAuthority,
    /// Intended non-reusable namespace, supplied by the host rather than the bundle.
    pub resource_scope: String,
    /// Exact verified member manifest; transport encoding is not its identity.
    pub bundle_manifest_digest: Sha256Digest,
    /// Exact reproduced normalized subject/component graph.
    pub inventory_digest: Sha256Digest,
    /// Exact reproduced frozen evaluation input.
    pub scan_input_digest: Sha256Digest,
    /// Exact reproduced canonical assessment.
    pub assessment_digest: Sha256Digest,
    /// Exact supported semantic engine profile.
    pub engine_digest: Sha256Digest,
    /// Verified raw-custody profile of the supplied export.
    pub profile: BundleProfile,
    /// Number of explicitly omitted raw members; no references are fetched.
    pub external_raw_members: u32,
    /// Host-provided verification time, independent of frozen evaluation time.
    pub validated_at: Timestamp,
}

impl BundleReproductionV1 {
    /// Reproduces a bundle and binds its result to an explicit host scope and time.
    ///
    /// # Errors
    /// Returns an error for invalid scope, unsupported or inconsistent evidence,
    /// an incomplete closure, or verification before the frozen evaluation time.
    pub fn reproduce(bundle: &AssessmentBundleV1, scope: &str, now: Timestamp) -> Result<Self> {
        text(scope, 128, "bundle reproduction scope")?;
        let manifest = bundle.verify()?;
        if now < bundle.input.evaluated_at {
            bail!("bundle reproduction precedes its frozen evaluation time");
        }
        let receipt = Self {
            schema: BUNDLE_REPRODUCTION_V1.into(),
            classification: ReproductionClassification::Reproduced,
            authority: ReproductionAuthority::NotEstablished,
            resource_scope: scope.into(),
            bundle_manifest_digest: manifest,
            inventory_digest: bundle.manifest.inventory_digest,
            scan_input_digest: bundle.manifest.scan_input_digest,
            assessment_digest: bundle.manifest.assessment_digest,
            engine_digest: bundle.manifest.engine_digest,
            profile: bundle.manifest.profile,
            external_raw_members: u32::try_from(bundle.manifest.external_references.len())?,
            validated_at: now,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Checks an existing receipt against the exact bundle and current host scope.
    ///
    /// # Errors
    /// Returns an error for changed receipt content, a different intended scope,
    /// future verification time or a bundle that no longer reproduces.
    pub fn verify_for(
        &self,
        bundle: &AssessmentBundleV1,
        scope: &str,
        now: &Timestamp,
    ) -> Result<()> {
        self.validate()?;
        if &self.validated_at > now
            || *self != Self::reproduce(bundle, scope, self.validated_at.clone())?
        {
            bail!("bundle reproduction receipt differs from its exact scope, evidence or clock");
        }
        Ok(())
    }

    /// Decodes a bounded closed receipt without treating it as authority evidence.
    ///
    /// # Errors
    /// Returns an error for ambiguous, incompatible, excessive or malformed content.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let receipt: Self = decode_with_limits(bytes, "bundle reproduction receipt", LIMITS)?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Encodes a validated canonical receipt.
    ///
    /// # Errors
    /// Returns an error for invalid content or canonical encoding bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = aos_contract::canonical::to_vec(self)?;
        LIMITS.decode::<serde_json::Value>(&bytes, "bundle reproduction receipt")?;
        Ok(bytes)
    }

    /// Computes the immutable identity retained by a host's import journal.
    ///
    /// # Errors
    /// Returns an error for malformed content or canonical encoding bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        digest(BUNDLE_REPRODUCTION_V1, self)
    }

    fn validate(&self) -> Result<()> {
        text(&self.resource_scope, 128, "bundle reproduction scope")?;
        if self.schema != BUNDLE_REPRODUCTION_V1
            || self.external_raw_members > 4096
            || (self.profile == BundleProfile::SelfContained && self.external_raw_members != 0)
        {
            bail!("invalid bundle reproduction schema or raw-custody profile");
        }
        Ok(())
    }
}
