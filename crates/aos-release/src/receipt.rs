//! Exact staging, qualification, production, and channel receipts.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::evidence::GateResult;

/// Isolated Hub environment named by a publication receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HubEnvironment {
    /// Qualification deployment.
    Staging,
    /// Consumer-facing deployment.
    Production,
}

/// Immutable receipt for committing a closed bundle to one Hub environment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceiptV1 {
    /// Exact receipt schema identifier.
    pub schema_version: String,
    /// Isolated environment that admitted the bundle.
    pub environment: HubEnvironment,
    /// Exact deployment identity verified by the client and Hub.
    pub deployment_id: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Immutable release identity.
    pub release_id: String,
    /// Final manifest identity.
    pub manifest_digest: Sha256Digest,
    /// Closed bundle identity.
    pub bundle_digest: Sha256Digest,
    /// Hub-side publication operation id.
    pub operation_id: String,
    /// Prior production receipt required for promoted imports.
    pub staging_receipt_digest: Option<Sha256Digest>,
    /// RFC 3339 UTC commit time supplied by the Hub.
    pub committed_at: String,
}

impl PublicationReceiptV1 {
    /// Validates environment-specific receipt shape.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers, an empty timestamp, a
    /// staging receipt that claims promotion, or a production receipt without
    /// staging continuity.
    pub fn validate(&self) -> Result<()> {
        require_identifier(&self.deployment_id, "Hub deployment id")?;
        require_identifier(&self.release_id, "release id")?;
        require_identifier(&self.operation_id, "Hub operation id")?;
        if self.committed_at.trim().is_empty() {
            bail!("publication receipt timestamp cannot be empty");
        }
        match (self.environment, self.staging_receipt_digest) {
            (HubEnvironment::Staging, None) | (HubEnvironment::Production, Some(_)) => Ok(()),
            (HubEnvironment::Staging, Some(_)) => {
                bail!("staging receipt cannot claim production promotion")
            }
            (HubEnvironment::Production, None) => {
                bail!("production receipt requires exact staging continuity")
            }
        }
    }
}

/// Signed qualification over exact staged public bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReceiptV1 {
    /// Exact receipt schema identifier.
    pub schema_version: String,
    /// Digest of the staging publication receipt.
    pub staging_receipt_digest: Sha256Digest,
    /// Final release-manifest identity.
    pub manifest_digest: Sha256Digest,
    /// Versioned qualification policy identity.
    pub policy_id: String,
    /// Digest of exact qualification policy bytes.
    pub policy_digest: Sha256Digest,
    /// Public qualification result.
    pub result: GateResult,
    /// Digest of the complete public qualification report.
    pub report_digest: Sha256Digest,
    /// Public qualification authority identity.
    pub authority_id: String,
    /// Nonce supplied by the release coordinator.
    pub nonce: String,
    /// RFC 3339 UTC completion time.
    pub qualified_at: String,
}

/// Compare-and-swap receipt for one signed channel partition operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelReceiptV1 {
    /// Exact receipt schema identifier.
    pub schema_version: String,
    /// Channel name: `edge`, `candidate`, or `stable`.
    pub channel: String,
    /// Inclusive first partition changed.
    pub first_partition: u16,
    /// Inclusive final partition changed.
    pub last_partition: u16,
    /// Expected prior channel generation.
    pub prior_generation: u64,
    /// New channel generation.
    pub new_generation: u64,
    /// Release manifest now named by the changed partitions.
    pub manifest_digest: Sha256Digest,
    /// Exact production receipt authorizing discovery.
    pub production_receipt_digest: Sha256Digest,
    /// RFC 3339 UTC operation time.
    pub committed_at: String,
}

impl ChannelReceiptV1 {
    /// Validates channel, partition, and generation monotonicity.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown channel, a partition outside `0..=255`,
    /// a reversed range, a non-incrementing generation, or an empty timestamp.
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.channel.as_str(), "edge" | "candidate" | "stable") {
            bail!("unknown release channel: {}", self.channel);
        }
        if self.first_partition > self.last_partition || self.last_partition > 255 {
            bail!("channel partition range must be within 0..=255");
        }
        if self.new_generation != self.prior_generation.saturating_add(1) {
            bail!("channel generation must increase by exactly one");
        }
        if self.committed_at.trim().is_empty() {
            bail!("channel receipt timestamp cannot be empty");
        }
        Ok(())
    }
}
