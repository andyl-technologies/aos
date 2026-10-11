//! Read-only discovery of a physical guard's genuine retained copy original.
//!
//! The selector contains independently resolved current SQL placement pins,
//! never a newly observed provider incarnation. A result grants no dispatch,
//! continuation, receipt or lease authority. Native rechecks the actual SQL
//! operation, claim and current authorization before reusing the returned owner.
//!
//! ```text
//! selector = {deployment_id, topology, source, destination, path,
//!             binding_stable_id, binding_resource_version,
//!             snapshot_revision, profile_digest}
//! result = unseen | {original, progress}
//! ```

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::storage_authority::{canonical_digest, lease::LeaseInteger};

use super::{
    CopyPlacementPin, CopyTopologyOriginal, ExternalCopyOriginal, MAX_EXTERNAL_COPY_ORIGINAL_BYTES,
    control::CopyProgress, digest_string, identifier,
};

/// Selects an existing original by the exact scheduled owner and physical destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyOriginalSelector {
    /// Exact issuer application deployment.
    pub deployment_id: String,
    /// Genuine retained topology operation and both sealed target selectors.
    pub topology: CopyTopologyOriginal,
    /// Current source SQL row independently resolved from the sealed stable selector.
    pub source: CopyPlacementPin,
    /// Current destination SQL row independently resolved from the sealed selector.
    pub destination: CopyPlacementPin,
    /// Unmodified relative path from the bounded source inventory.
    pub path: String,
    /// Exact current binding stable identity.
    pub binding_stable_id: String,
    /// Exact current binding resource version.
    pub binding_resource_version: LeaseInteger,
    /// Exact nonsecret protected provider snapshot revision.
    pub snapshot_revision: String,
    /// Independently installed copy profile commitment.
    pub profile_digest: String,
    /// Independently installed cross-binding pins; old selectors omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer: Option<super::transfer::CopyTransferPins>,
}

impl CopyOriginalSelector {
    /// Projects read-only identity without exposing or choosing source bytes.
    ///
    /// # Errors
    /// Refuses an invalid original or selector geometry.
    pub fn from_original(original: &ExternalCopyOriginal) -> Result<Self> {
        original.validate()?;
        let value = Self {
            deployment_id: original.deployment_id.clone(),
            topology: original.topology.clone(),
            source: original.source.clone(),
            destination: original.destination.clone(),
            path: original.path.clone(),
            binding_stable_id: original.binding_stable_id.clone(),
            binding_resource_version: original.binding_resource_version,
            snapshot_revision: original.snapshot_revision.clone(),
            profile_digest: original.profile_digest.clone(),
            transfer: original.transfer.clone(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks closed SQL identity and bounded same-binding geometry.
    ///
    /// # Errors
    /// Refuses malformed, cross-binding or changed sealed placement pins.
    pub fn validate(&self) -> Result<()> {
        self.topology.validate()?;
        self.source.validate(&self.topology.source)?;
        self.destination.validate(&self.topology.destination)?;
        identifier(&self.deployment_id)?;
        identifier(&self.binding_stable_id)?;
        let binding_geometry = match &self.transfer {
            Some(transfer) => {
                transfer.validate(&self.source, &self.destination)?;
                transfer.source_binding.binding_stable_id != self.binding_stable_id
            }
            None => {
                self.source.binding_id == self.destination.binding_id
                    && self.source.prefix != self.destination.prefix
            }
        };
        ensure!(
            self.binding_resource_version.get() > 0
                && binding_geometry
                && self.source.placement_id != self.destination.placement_id
                && self.source.registry_id == self.destination.registry_id
                && self.source.cache_id == self.destination.cache_id
                && digest_string(&self.snapshot_revision)
                && digest_string(&self.profile_digest)
                && crate::storage_work::valid_relative_path(&self.path, false)
                && serde_json::to_vec(self)?.len() <= MAX_EXTERNAL_COPY_ORIGINAL_BYTES,
            "invalid retained-copy selector"
        );
        Ok(())
    }

    /// Derives the existing permanent retry identity without a fresh provider HEAD.
    ///
    /// # Errors
    /// Refuses invalid selectors or a failed canonical encoding.
    pub fn copy_id(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(&(
            "aos.external-placement-copy-owner.v1",
            &self.topology.operation_id,
            &self.topology.destination.stable_id,
            &self.path,
        ))
    }

    /// Requires the genuine returned original to preserve every requested SQL pin.
    ///
    /// # Errors
    /// Refuses a foreign original, current pin change or invalid compact progress.
    pub fn validate_retained(
        &self,
        original: &ExternalCopyOriginal,
        progress: &CopyProgress,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            Self::from_original(original)? == *self,
            "retained copy selector changed"
        );
        progress.validate(original)
    }
}
