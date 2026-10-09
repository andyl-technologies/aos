//! Immutable bounded provider observations and explicit completeness evidence.
//!
//! `aos.provider-observation/v1` separates exact response bytes, normalized
//! payload identity, retrieval/revalidation/expiry times, and source coverage.
//! Revalidating unchanged bytes creates a new observation, not a mutable date.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::time::Timestamp;
use crate::validation::{decode, digest, sorted, text};

/// Identifies one immutable provider observation.
pub const PROVIDER_OBSERVATION_V1: &str = "aos.provider-observation/v1";

/// States the exact completeness conclusion established by an adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProviderCoverage {
    /// Establishes all records required by the configured question.
    Complete {
        /// Installed adapter proof class, such as exhausted provider pagination.
        proof: String,
    },
    /// Establishes a profile-specific complete boundary for a bounded question.
    ThroughBoundary {
        /// Exact version/record boundary reached by enumeration.
        identity: String,
        /// Installed profile's justification that the boundary is sufficient.
        proof: String,
    },
    /// Retains useful evidence while making incomplete acquisition visible.
    Partial {
        /// Stable source/limit failure reason.
        reason: String,
        /// Optional digest-bound continuation, not authority to issue new work.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        continuation: Option<Sha256Digest>,
    },
    /// Cannot establish the configured source question.
    Unknown {
        /// Stable unsupported/missing/unavailable reason.
        reason: String,
    },
}

impl ProviderCoverage {
    /// Validates bounded proof and diagnostic identities.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized or control-bearing proof text.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Complete { proof } => text(proof, 128, "coverage proof"),
            Self::ThroughBoundary { identity, proof } => {
                text(identity, 512, "coverage boundary")?;
                text(proof, 128, "coverage proof")
            }
            Self::Partial { reason, .. } | Self::Unknown { reason } => {
                text(reason, 128, "coverage reason")
            }
        }
    }

    /// Reports complete coverage without interpreting an unverified boundary.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }
}

/// Preserves safe conditional-request validators without credential headers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HttpValidators {
    /// Source-supplied ETag of the exact cached bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Source-supplied Last-Modified header of the exact cached bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

/// Binds retained evidence bytes to an admitted source identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceEvidenceRef {
    /// Exact raw or normalized evidence object identity.
    pub digest: Sha256Digest,
    /// Exact encoded byte length used for bounded retrieval.
    pub byte_length: u64,
    /// Installed origin/profile identity; never a credential-bearing URL.
    pub origin: String,
}

/// Records one immutable provider answer with retained uncertainty and timing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderObservationV1 {
    /// Exact closed schema identity.
    pub schema: String,
    /// Installed provider profile.
    pub provider: String,
    /// Exact provider-native project/query identity.
    pub project: String,
    /// Decision-relevant request/parser profile revision.
    pub adapter_version: String,
    /// Sanitized typed request identity; credentials remain in scoped custody.
    pub request_identity_digest: Sha256Digest,
    /// Time at which the retained response bytes were originally acquired.
    pub retrieved_at: Timestamp,
    /// Time at which those exact bytes were last validated against the source.
    pub validated_at: Timestamp,
    /// Explicit expiry selected under the pinned source policy.
    pub expires_at: Timestamp,
    /// Exact response bytes, separate from normalized semantic projection.
    pub response_digest: Sha256Digest,
    /// Exact normalized candidates/advisories/object projection.
    pub payload_digest: Sha256Digest,
    /// Optional validators bound to the retained response bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validators: Option<HttpValidators>,
    /// Adapter-produced completion evidence; HTTP success alone is insufficient.
    pub coverage: ProviderCoverage,
    /// Retained immutable evidence, sorted by digest/size/origin.
    pub source_refs: Vec<SourceEvidenceRef>,
}

impl ProviderObservationV1 {
    /// Decodes a bounded immutable observation with its exact wire semantics.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible/ambiguous/oversized data, null optional
    /// fields, invalid time ordering, duplicate references or unsafe text.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let observation: Self = decode(bytes, "provider observation")?;
        observation.validate()?;
        Ok(observation)
    }

    /// Validates structural provenance and coverage without granting source trust.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schemas, excessive scope, invalid times,
    /// unsafe validator/origin fields, or missing exact-response evidence.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PROVIDER_OBSERVATION_V1 {
            bail!("unsupported provider observation schema");
        }
        for (field, value, maximum) in [
            ("provider", self.provider.as_str(), 128),
            ("project", self.project.as_str(), 1024),
            ("adapter version", self.adapter_version.as_str(), 128),
        ] {
            text(value, maximum, field)?;
        }
        if self.retrieved_at > self.validated_at || self.validated_at > self.expires_at {
            bail!("provider observation has inconsistent timestamp ordering");
        }
        self.coverage.validate()?;
        if self.source_refs.is_empty() || self.source_refs.len() > 128 {
            bail!("provider observation lacks bounded retained source evidence");
        }
        sorted(&self.source_refs, "source evidence references")?;
        if self
            .source_refs
            .windows(2)
            .any(|pair| pair[0].digest == pair[1].digest)
        {
            bail!("provider observation repeats a source evidence identity");
        }
        for source in &self.source_refs {
            text(&source.origin, 128, "source origin profile")?;
            if source.origin.contains(['/', '?', '@']) || source.byte_length > 64 * 1024 * 1024 {
                bail!("source evidence reference exceeds admitted origin/size scope");
            }
        }
        if !self
            .source_refs
            .iter()
            .any(|source| source.digest == self.response_digest)
        {
            bail!("provider observation does not retain its exact response reference");
        }
        if let Some(validators) = &self.validators {
            for value in [validators.etag.as_ref(), validators.last_modified.as_ref()]
                .into_iter()
                .flatten()
            {
                text(value, 2048, "conditional request validator")?;
            }
        }
        Ok(())
    }

    /// Computes the immutable validated observation identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid observation structure or canonical bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        digest(PROVIDER_OBSERVATION_V1, self)
    }

    /// Checks effective freshness at an explicit evaluation time.
    ///
    /// # Errors
    ///
    /// Returns an error when evaluation precedes the claimed validation time.
    pub fn is_fresh_at(&self, evaluated_at: &Timestamp) -> Result<bool> {
        evaluated_at.elapsed_since(&self.validated_at)?;
        Ok(evaluated_at < &self.expires_at)
    }
}
