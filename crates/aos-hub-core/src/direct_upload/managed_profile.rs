//! Protected managed-R2 credential publication with a secret-free descriptor.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::*;

/// Optional protected extension of the existing signed storage capabilities.
///
/// Absence means direct-required is unavailable. Native compares this actual
/// protected projection to an independently reviewed setup pin; a signature
/// alone does not establish private bucket/provider or Worker namespace policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectStorageCapabilities {
    /// Closed protected profile-set version, currently two.
    pub version: u32,
    /// Exact public protocol capability identifier.
    pub capability: String,
    /// Actual material-derived secret-free managed bucket/profile publication.
    pub profile: Option<DirectManagedR2Profile>,
    /// Exact independently qualified provider plus Worker private namespace policy.
    pub private_stage_policy: Option<DirectPrivateStagePolicyRef>,
    /// Managed runtime reference; all three managed fields must be present together.
    pub runtime_qualification: Option<DirectRuntimeQualification>,
    /// Only exact requested qualified external wrappers, never a global inventory.
    pub external_profiles: Vec<DirectProtectedExternalProfile>,
}

impl DirectStorageCapabilities {
    /// Checks this protected descriptor against deployment and structural bounds.
    ///
    /// Caller must additionally require exact independently reviewed pin equality.
    ///
    /// # Errors
    /// Returns an error for malformed version, profile, policy or oversized reply.
    pub fn validate(&self, deployment: &str) -> Result<()> {
        ensure!(
            self.version == 2 && self.capability == DIRECT_UPLOAD_CAPABILITY,
            "invalid protected direct capability projection"
        );
        ensure!(
            self.profile.is_some() == self.private_stage_policy.is_some()
                && self.profile.is_some() == self.runtime_qualification.is_some()
                && (self.profile.is_some() || !self.external_profiles.is_empty())
                && self.external_profiles.len() <= MAX_DIRECT_PLACEMENTS,
            "invalid protected direct capability profile set"
        );
        if let (Some(profile), Some(policy), Some(runtime)) = (
            &self.profile,
            &self.private_stage_policy,
            &self.runtime_qualification,
        ) {
            DirectProtectedProfile::Managed {
                profile: profile.clone(),
                private_stage_policy: policy.clone(),
                runtime_qualification: runtime.clone(),
            }
            .validate()?;
            ensure!(
                profile.deployment_id == deployment
                    && valid_direct_identity(&policy.policy_id)
                    && valid_direct_digest(&policy.policy_digest)
                    && policy.namespace == profile.bucket_namespace,
                "invalid protected managed capability projection"
            );
        }
        let mut identities = std::collections::BTreeSet::new();
        for profile in &self.external_profiles {
            profile.validate()?;
            ensure!(
                identities.insert((
                    profile.profile.selector.physical_authority_id.clone(),
                    profile.profile.selector.association.association_id.clone()
                )),
                "duplicate protected external capability profile"
            );
        }
        ensure!(
            encode_direct_control(self)?.len() <= MAX_DIRECT_CAPABILITY_BYTES,
            "protected direct capability projection exceeds limit"
        );
        Ok(())
    }
}

/// Public managed credential/coordinate publication independently pinned by Native.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectManagedR2Profile {
    /// Immutable protected deployment identity.
    pub deployment_id: String,
    /// Permanent independently configured bucket/guard namespace.
    pub bucket_namespace: String,
    /// Exact provider account identity, containing no key material.
    pub account_id: String,
    /// Exact private bucket name, not selected by the caller.
    pub bucket_name: String,
    /// Stable protected credential publication identity.
    pub credential_id: String,
    /// Exact protected credential generation.
    pub credential_generation: WireInteger,
    /// Immutable public secret-version locator resolved only inside the Worker.
    pub secret_version_ref: String,
    /// Commitment derived from actual protected credentials and all coordinates.
    pub credential_fingerprint: String,
    /// Independently qualified exact provider UploadPart checksum algorithm.
    pub checksum_algorithm: DirectChecksumAlgorithm,
    /// Independently accepted mutation clock/continuation qualification digest.
    pub clock_qualification: String,
    /// Conservative qualified clock uncertainty, canonical seconds in 1..29.
    pub clock_uncertainty_seconds: WireInteger,
}

impl DirectManagedR2Profile {
    /// Validates the public descriptor without asserting provider qualification.
    ///
    /// # Errors
    /// Returns a value-free error for malformed identities, generation or digest.
    pub fn validate(&self) -> Result<()> {
        self.validate_coordinates()?;
        ensure!(
            valid_direct_digest(&self.credential_fingerprint),
            "invalid managed direct credential commitment"
        );
        Ok(())
    }

    /// Computes the v2 protected credential, coordinate and clock commitment.
    ///
    /// Secret material is neither serialized nor retained in this model. Caller
    /// configuration must derive this value from the actual selected protected
    /// publication, not accept a manually configured fingerprint as proof.
    ///
    /// # Errors
    /// Returns a value-free error for malformed coordinates or credential inputs.
    pub fn fingerprint_with_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Result<String> {
        self.validate_coordinates()?;
        ensure!(
            !access_key.is_empty()
                && access_key.len() <= 255
                && !access_key.chars().any(char::is_control)
                && !secret_key.is_empty()
                && secret_key.len() <= 4096
                && !secret_key.chars().any(char::is_control),
            "invalid managed direct protected credentials"
        );
        let mut digest = Sha256::new();
        digest.update(b"aos.direct-upload.managed-r2-profile.v2\0");
        for text in [
            &self.deployment_id,
            &self.bucket_namespace,
            &self.account_id,
            &self.bucket_name,
            &self.credential_id,
            &self.secret_version_ref,
            &self.clock_qualification,
            access_key,
            secret_key,
        ] {
            let length = u32::try_from(text.len())
                .map_err(|_| anyhow::anyhow!("managed direct field exceeds limit"))?;
            digest.update(length.to_be_bytes());
            digest.update(text.as_bytes());
        }
        digest.update(self.credential_generation.get().to_be_bytes());
        digest.update(self.clock_uncertainty_seconds.get().to_be_bytes());
        digest.update([match self.checksum_algorithm {
            DirectChecksumAlgorithm::Md5 => 1,
            DirectChecksumAlgorithm::Sha256 => 2,
        }]);
        Ok(hex::encode(digest.finalize()))
    }

    fn validate_coordinates(&self) -> Result<()> {
        ensure!(
            valid_direct_digest(&self.clock_qualification)
                && (1..30).contains(&self.clock_uncertainty_seconds.get()),
            "invalid managed direct clock qualification"
        );
        for value in [
            &self.deployment_id,
            &self.bucket_namespace,
            &self.account_id,
            &self.bucket_name,
            &self.credential_id,
            &self.secret_version_ref,
        ] {
            ensure!(
                valid_direct_identity(value),
                "invalid managed direct profile coordinate"
            );
        }
        ensure!(
            (1..=i64::MAX as u64).contains(&self.credential_generation.get()),
            "invalid managed direct credential generation"
        );
        Ok(())
    }
}
