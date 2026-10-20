//! Typed whole-profile commitments independent of public credential fingerprints.
//!
//! Managed and external variants commit their complete protected public facts and
//! mandatory runtime reference. Callers construct these from actual protected
//! resolution, then compare independent original pins before any provider effect.
//!
//! ```text
//! Managed { profile, privateStagePolicy, runtimeQualification }
//! External { profile, runtimeQualification }
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::storage_authority::lease::LeaseEffect;

use super::*;

/// Exact closed external profile and mandatory configured runtime reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectProtectedExternalProfile {
    /// Actual complete public projection of the protected external publication.
    pub profile: DirectExternalStorageCapabilities,
    /// Independently reviewed runtime reference, never an implicit capacity default.
    pub runtime_qualification: DirectRuntimeQualification,
}

impl DirectProtectedExternalProfile {
    /// Constructs an exact wrapper from independently resolved protected inputs.
    ///
    /// # Errors
    /// Returns a value-free error for malformed profile or runtime facts.
    pub fn new(
        profile: DirectExternalStorageCapabilities,
        runtime_qualification: DirectRuntimeQualification,
    ) -> Result<Self> {
        let result = Self {
            profile,
            runtime_qualification,
        };
        result.validate()?;
        Ok(result)
    }

    /// Checks the complete external profile and configured reference structure.
    ///
    /// # Errors
    /// Returns a value-free error for malformed publication or runtime bounds.
    pub fn validate(&self) -> Result<()> {
        validate_external(&self.profile, &self.runtime_qualification)
    }

    /// Computes the shared complete protected pin without changing the legacy fingerprint.
    ///
    /// # Errors
    /// Returns an error for invalid fields or excessive canonical encoding.
    pub fn digest(&self) -> Result<String> {
        DirectProtectedProfile::External {
            profile: self.profile.clone(),
            runtime_qualification: self.runtime_qualification.clone(),
        }
        .digest()
    }
}

/// Exact typed whole-profile pin captured before the original stage creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DirectProtectedProfile {
    /// Actual managed material publication, private policy and runtime reference.
    Managed {
        /// Actual secret-free material-derived managed credential publication.
        profile: DirectManagedR2Profile,
        /// Independently qualified provider and Worker namespace policy.
        private_stage_policy: DirectPrivateStagePolicyRef,
        /// Mandatory reviewed runtime reference with no readiness implication.
        runtime_qualification: DirectRuntimeQualification,
    },
    /// Actual complete external publication and runtime reference.
    External {
        /// Exact independently resolved issuer, cohorts, credentials and provider policy.
        profile: DirectExternalStorageCapabilities,
        /// Mandatory reviewed runtime reference with no readiness implication.
        runtime_qualification: DirectRuntimeQualification,
    },
}

impl DirectProtectedProfile {
    /// Constructs a whole managed pin from independently resolved protected facts.
    ///
    /// # Errors
    /// Returns a value-free error for malformed profile, private policy or runtime.
    pub fn managed(
        profile: DirectManagedR2Profile,
        private_stage_policy: DirectPrivateStagePolicyRef,
        runtime_qualification: DirectRuntimeQualification,
    ) -> Result<Self> {
        let result = Self::Managed {
            profile,
            private_stage_policy,
            runtime_qualification,
        };
        result.validate()?;
        Ok(result)
    }

    /// Constructs a whole external pin from independently resolved protected facts.
    ///
    /// # Errors
    /// Returns a value-free error for malformed external profile or runtime.
    pub fn external(
        profile: DirectExternalStorageCapabilities,
        runtime_qualification: DirectRuntimeQualification,
    ) -> Result<Self> {
        let result = Self::External {
            profile,
            runtime_qualification,
        };
        result.validate()?;
        Ok(result)
    }

    /// Checks actual typed structural facts before computing a protected pin.
    ///
    /// This does not verify the provenance of a caller-supplied projection.
    ///
    /// # Errors
    /// Returns a value-free error for malformed profile, policy or runtime facts.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Managed {
                profile,
                private_stage_policy,
                runtime_qualification,
            } => {
                profile.validate()?;
                ensure!(
                    valid_direct_identity(&private_stage_policy.policy_id)
                        && valid_direct_digest(&private_stage_policy.policy_digest)
                        && private_stage_policy.namespace == profile.bucket_namespace,
                    "invalid protected managed private policy"
                );
                runtime_qualification.validate()?;
            }
            Self::External {
                profile,
                runtime_qualification,
            } => {
                validate_external(profile, runtime_qualification)?;
            }
        }
        Ok(())
    }

    /// Computes the exact versioned whole-profile commitment from bounded typed bytes.
    ///
    /// Public material fingerprints and external semantic fingerprints keep
    /// their existing distinct domains. Setup pins require explicit republication;
    /// an old admission cannot adopt a new profile on replay.
    ///
    /// # Errors
    /// Returns a value-free error for invalid facts or excessive encoding.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(b"aos.hub.direct.protected-profile.v1\0");
        digest.update(encode_direct_control(self)?);
        Ok(hex::encode(digest.finalize()))
    }
}

// Mandatory cache baseline observation needs both factual HEAD and full GET.
// The raw profile's historical semantic fingerprint retains its own contract.
fn validate_external(
    profile: &DirectExternalStorageCapabilities,
    runtime: &DirectRuntimeQualification,
) -> Result<()> {
    profile.validate()?;
    runtime.validate()?;
    ensure!(
        profile
            .read_cohort
            .allowed_effects
            .contains(&LeaseEffect::Head),
        "protected direct profile lacks baseline read capability"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
