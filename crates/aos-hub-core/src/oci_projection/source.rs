//! Closed provider-source identity for independent OCI semantic readback.
//!
//! Managed is the historical omitted default. External proves a genuine OCI
//! original and positive incarnation separately from a provider version.

use anyhow::{ensure, Result};
use aos_oci_types::Descriptor;
use serde::{Deserialize, Serialize};
use crate::{storage_work::StorageObjectIdentity, storage_authority::external_object::oci::{
    ExternalOciOriginal, OciProviderIncarnation, reply::OciClosedObject,
}};

/// Identifies the separately authorized producer whose exact object is inspected.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OciProjectionSource {
    /// Historical managed-R2 path requiring an actual provider version.
    #[default]
    Managed,
    /// OCI-owned external object with real positive closure and guard incarnation.
    External {
        /// Exact real upload, actor, writer and purpose-qualified original.
        original: ExternalOciOriginal,
        /// Exact positive provider receipt, not a HEAD-inferred completion.
        closed: OciClosedObject,
    },
}

impl OciProjectionSource {
    /// Tests whether historical Managed wire omission applies.
    #[must_use]
    pub fn is_managed(&self) -> bool { matches!(self, Self::Managed) }

    /// Checks the selected original against this exact document challenge.
    ///
    /// # Errors
    /// Refuses a different key, descriptor, positive receipt or purpose profile.
    pub fn validate(&self, key: &str, descriptor: &Descriptor, profile: &str) -> Result<()> {
        if let Self::External { original, closed } = self {
            original.validate()?;
            closed.bytes.validate()?;
            closed.incarnation.validate(original.scope.physical_authority_id.as_str())?;
            ensure!(original.scope.full_key == key && original.profile_digest == profile
                && closed.bytes.size == descriptor.size && closed.bytes.sha256 == descriptor.digest.encoded()
                && crate::direct_upload::valid_direct_digest(&closed.receipt_digest)
                && crate::surface_write::strong_if_match_etag(&closed.etag)? == closed.etag,
                "external OCI projection source differs from retained positive original");
        }
        Ok(())
    }

    /// Checks actual conditional read identity without substituting guard stamps.
    ///
    /// # Errors
    /// Refuses a false/missing managed version or a substituted external selector.
    pub fn validate_object(&self, object: &StorageObjectIdentity) -> Result<()> {
        match self {
            Self::Managed => ensure!(object.provider_version.as_deref()
                .is_some_and(crate::storage_work::valid_provider_version),
                "managed OCI projection requires actual provider version"),
            Self::External { original, closed } => {
                let version = match &closed.incarnation {
                    OciProviderIncarnation::Versioned { provider_version, .. } => Some(provider_version.as_str()),
                    OciProviderIncarnation::Guarded { .. } => None,
                };
                ensure!(object.key == original.scope.full_key && object.size == closed.bytes.size
                    && object.etag == closed.etag && object.provider_version.as_deref() == version,
                    "external OCI conditional read incarnation changed");
            }
        }
        Ok(())
    }
}
