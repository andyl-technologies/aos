//! Surface-neutral publication and channel receipts.
//!
//! Hub deployments sign these receipts with their deployment receipt key;
//! static surfaces sign them with the plan's `surface-receipt` role. Journals
//! treat both surface kinds alike.
//!
//! ```json
//! {"schema_version":"aos.release.publication-receipt/v1",
//!  "destination":"production/stable","surface_role":"production",
//!  "surface_kind":"static","surface_identity":"cdn-2026-09",
//!  "registry":"andyl/main","release_id":"release-2026.9.0",
//!  "manifest_digest":"sha256:...","bundle_digest":"sha256:...",
//!  "operation_id":"publish-1","predecessor_receipt_digest":"sha256:...",
//!  "committed_at":"2026-09-03T00:00:00Z"}
//! ```

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::plan::{
    PlannedDestination, ReleasePlan, SurfaceKind, SurfaceRole, parse_destination_name,
};
use crate::registry::{channel_kind, registry_policy};

/// Schema for a surface-neutral publication receipt.
pub const PUBLICATION_RECEIPT: &str = "aos.release.publication-receipt/v1";

/// Schema for a surface-neutral channel partition receipt.
pub const CHANNEL_RECEIPT: &str = "aos.release.channel-receipt/v1";

/// Immutable receipt for publishing a closed bundle to one destination's surface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    /// Exact receipt schema identifier.
    pub schema_version: String,
    /// Planned destination name, `<role>/<channel>`.
    pub destination: String,
    /// Role of the surface that admitted the bundle.
    pub surface_role: SurfaceRole,
    /// Hub deployment or static origin.
    pub surface_kind: SurfaceKind,
    /// Hub deployment id or static surface identity.
    pub surface_identity: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Immutable release identity.
    pub release_id: String,
    /// Final manifest identity.
    pub manifest_digest: Sha256Digest,
    /// Closed bundle identity.
    pub bundle_digest: Sha256Digest,
    /// Surface-side publication operation id.
    pub operation_id: String,
    /// Staging publication receipt this production publication follows;
    /// absent for staging publications.
    pub predecessor_receipt_digest: Option<Sha256Digest>,
    /// RFC 3339 UTC commit time.
    pub committed_at: String,
}

impl PublicationReceipt {
    /// Validates the receipt shape independently of a plan.
    ///
    /// # Errors
    /// Returns an error for an unsupported schema, malformed identities, a
    /// destination whose role differs from the surface role, a non-UTC
    /// timestamp, a staging receipt with a predecessor, or a production
    /// receipt without one.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != PUBLICATION_RECEIPT {
            bail!("unsupported publication receipt schema");
        }
        let (role, _) = parse_destination_name(&self.destination)?;
        if role != self.surface_role {
            bail!("publication receipt destination differs from its surface role");
        }
        require_identifier(&self.surface_identity, "surface identity")?;
        require_identifier(&self.release_id, "release id")?;
        require_identifier(&self.operation_id, "publication operation id")?;
        registry_policy(&self.registry)?;
        require_utc(&self.committed_at, "publication receipt")?;
        match (self.surface_role, self.predecessor_receipt_digest) {
            (SurfaceRole::Staging, None) | (SurfaceRole::Production, Some(_)) => Ok(()),
            (SurfaceRole::Staging, Some(_)) => {
                bail!("staging publication cannot claim a predecessor publication")
            }
            (SurfaceRole::Production, None) => {
                bail!("production publication requires exact staging continuity")
            }
        }
    }

    /// Requires the receipt to match the plan's destination and frozen surface.
    ///
    /// # Errors
    /// Returns an error for any [`PublicationReceipt::validate`] failure, a
    /// registry or release identity drift, an unplanned destination, or a
    /// surface kind or identity other than the plan's surface for the role.
    pub fn validate_for(&self, plan: &ReleasePlan) -> Result<()> {
        self.validate()?;
        if self.registry != plan.registry || self.release_id != plan.release_id {
            bail!("publication receipt names a different release");
        }
        plan.destination(&self.destination)?;
        let surface = plan.surface(self.surface_role)?;
        if surface.kind != self.surface_kind || surface.identity != self.surface_identity {
            bail!("publication receipt surface differs from the frozen plan");
        }
        Ok(())
    }
}

/// Compare-and-swap receipt for one ring of a destination's channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelReceipt {
    /// Exact receipt schema identifier.
    pub schema_version: String,
    /// Planned destination name, `<role>/<channel>`.
    pub destination: String,
    /// Full channel name, such as `stable` or `stable-2026.3`.
    pub channel: String,
    /// One-based rollout ring advanced by this operation.
    pub ring: u16,
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
    /// Publication receipt of the same surface authorizing discovery.
    pub publication_receipt_digest: Sha256Digest,
    /// Hub deployment or static origin.
    pub surface_kind: SurfaceKind,
    /// Hub deployment id or static surface identity.
    pub surface_identity: String,
    /// RFC 3339 UTC operation time.
    pub committed_at: String,
}

impl ChannelReceipt {
    /// Validates channel, partition, generation, and identity shape.
    ///
    /// # Errors
    /// Returns an error for an unsupported schema, a destination whose
    /// channel differs from `channel`, an unsupported channel kind, a zero
    /// ring, a partition outside `0..=255` or reversed, a non-incrementing
    /// generation, a malformed surface identity, or a non-UTC timestamp.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CHANNEL_RECEIPT {
            bail!("unsupported channel receipt schema");
        }
        let (_, channel) = parse_destination_name(&self.destination)?;
        if channel != self.channel {
            bail!("channel receipt destination differs from its channel");
        }
        channel_kind(&self.channel)?;
        if self.ring == 0 {
            bail!("channel receipt rings are numbered from 1");
        }
        if self.first_partition > self.last_partition || self.last_partition > 255 {
            bail!("channel partition range must be within 0..=255");
        }
        if self.new_generation != self.prior_generation.saturating_add(1) {
            bail!("channel generation must increase by exactly one");
        }
        require_identifier(&self.surface_identity, "surface identity")?;
        require_utc(&self.committed_at, "channel receipt")
    }

    /// Requires the receipt's partition range to be its ring's planned range.
    ///
    /// # Errors
    /// Returns an error for any [`ChannelReceipt::validate`] failure, a
    /// different destination, or a range that differs from the ring's.
    pub fn validate_for(&self, destination: &PlannedDestination) -> Result<()> {
        self.validate()?;
        if self.destination != destination.name {
            bail!("channel receipt names a different destination");
        }
        if destination.ring_range(self.ring)? != (self.first_partition, self.last_partition) {
            bail!(
                "channel receipt range differs from ring {} of {}",
                self.ring,
                destination.name
            );
        }
        Ok(())
    }
}

fn require_utc(value: &str, label: &str) -> Result<()> {
    if !value.ends_with('Z') || humantime::parse_rfc3339(value).is_err() {
        bail!("{label} timestamp must be RFC 3339 UTC");
    }
    Ok(())
}
