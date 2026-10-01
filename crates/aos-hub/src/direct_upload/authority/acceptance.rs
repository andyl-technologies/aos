//! Independently reviewed deployment acceptance shared with the Worker runtime.
//!
//! The bounded closed `DirectWorkerQualificationArtifact` contains measured
//! runtime/provider evidence and an Ed25519 signature. Native selects verification
//! keys from a separate operator trust file and projects only its exact profiles.
//!
//! ```json
//! {"reviewer-one":"<hexadecimal Ed25519 public key>"}
//! ```

use std::{collections::BTreeMap, path::Path};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::direct_upload::*;
use ed25519_dalek::VerifyingKey;

const MAX_ACCEPTANCE_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy)]
enum AcceptanceLoad {
    CurrentProducer,
    PositiveMetadataRecovery,
}

#[derive(Clone)]
struct AcceptedProfile {
    deployment: String,
    origin: String,
    profile: DirectProtectedProfile,
    issued_at: u64,
    expires_at: u64,
}

/// Verified runtime acceptance bound to separately configured reviewer keys.
#[derive(Clone)]
pub struct NativeDirectUploadAcceptances {
    accepted: Vec<AcceptedProfile>,
    source_digest: String,
    script_version: String,
}

impl NativeDirectUploadAcceptances {
    /// Loads the shared measured artifact and verifies an independently trusted reviewer.
    ///
    /// The separate key file maps reviewer identities to hexadecimal Ed25519
    /// public keys. Neither the artifact nor discovery can introduce a key.
    /// Emulated evidence is confined to explicit external test provider profiles.
    ///
    /// # Errors
    /// Returns an error for oversized or unknown schemas, bad signatures,
    /// insufficient measurement, invalid audience/profile or expired acceptance.
    pub fn from_files(acceptance_path: &Path, review_keys_path: &Path) -> Result<Self> {
        Self::from_bytes(
            &bounded_file(acceptance_path)?,
            &bounded_file(review_keys_path)?,
            super::current_time()?,
        )
    }

    fn from_bytes(bytes: &[u8], keys: &[u8], now: u64) -> Result<Self> {
        Self::load_bytes(bytes, keys, now, AcceptanceLoad::CurrentProducer)
    }

    /// Loads current producer facts or genuinely expired, signed guard history.
    ///
    /// Historical loading grants no producer qualification. `profiles` continues
    /// to reject expiry, and only fresh exact held-positive metadata recovery may
    /// use the retained issuer and clock-policy facts.
    ///
    /// # Errors
    /// Rejects missing files, invalid signatures, future/invalid validity windows,
    /// untrusted reviewers, malformed facts or unsupported clock/provider policy.
    pub fn from_files_for_positive_recovery(
        acceptance_path: &Path,
        review_keys_path: &Path,
    ) -> Result<Self> {
        Self::load_bytes(
            &bounded_file(acceptance_path)?,
            &bounded_file(review_keys_path)?,
            super::current_time()?,
            AcceptanceLoad::PositiveMetadataRecovery,
        )
    }

    fn load_bytes(bytes: &[u8], keys: &[u8], now: u64, mode: AcceptanceLoad) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_ACCEPTANCE_BYTES && keys.len() <= MAX_ACCEPTANCE_BYTES,
            "direct acceptance exceeds configured bound"
        );
        let artifact: DirectWorkerQualificationArtifact = serde_json::from_slice(bytes)?;
        let review_keys: BTreeMap<String, String> = serde_json::from_slice(keys)?;
        ensure!(
            !review_keys.is_empty() && review_keys.len() <= 32,
            "invalid direct review key set"
        );
        for (identity, key_hex) in &review_keys {
            ensure!(
                valid_direct_identity(identity),
                "invalid direct reviewer identity"
            );
            let bytes: [u8; 32] = hex::decode(key_hex)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid direct reviewer key"))?;
            VerifyingKey::from_bytes(&bytes)?;
        }
        let reviewer = review_keys
            .get(&artifact.reviewer_key_id)
            .context("direct reviewer is not trusted")?;
        if matches!(mode, AcceptanceLoad::PositiveMetadataRecovery)
            && now >= artifact.evidence.valid_until.get()
        {
            artifact.verify_expired_guard_history(
                &artifact.deployment_id,
                &artifact.public_origin,
                reviewer,
                now,
            )?;
        } else {
            artifact.verify(
                &artifact.deployment_id,
                &artifact.public_origin,
                reviewer,
                now,
            )?;
        }
        let origin = url::Url::parse(&artifact.public_origin)?;
        ensure!(
            origin.origin().ascii_serialization() == artifact.public_origin,
            "direct accepted executor origin is not canonical"
        );
        let mut profiles = artifact
            .evidence
            .external_profiles
            .iter()
            .map(|item| DirectProtectedProfile::External {
                profile: item.profile.clone(),
                runtime_qualification: item.runtime_qualification.clone(),
            })
            .collect::<Vec<_>>();
        if let (Some(profile), Some(policy)) = (
            &artifact.evidence.managed_profile,
            &artifact.evidence.private_stage_policy,
        ) {
            profiles.push(DirectProtectedProfile::managed(
                profile.clone(),
                policy.clone(),
                artifact.evidence.runtime.clone(),
            )?);
        }
        for profile in &profiles {
            validate_provider_runtime(artifact.execution_kind, profile)?;
        }
        let accepted = profiles
            .into_iter()
            .map(|profile| AcceptedProfile {
                deployment: artifact.deployment_id.clone(),
                origin: artifact.public_origin.clone(),
                profile,
                issued_at: artifact.evidence.issued_at.get(),
                expires_at: artifact.evidence.valid_until.get(),
            })
            .collect();
        Ok(Self {
            accepted,
            source_digest: artifact.source_digest,
            script_version: artifact.script_version,
        })
    }

    pub(super) fn valid_until(&self, deployment: &str, origin: &str, now: u64) -> Result<u64> {
        self.accepted
            .iter()
            .filter(|item| {
                item.deployment == deployment
                    && item.origin == origin
                    && item.issued_at <= now
                    && now < item.expires_at
            })
            .map(|item| item.expires_at)
            .min()
            .context("direct acceptance missing or expired")
    }

    pub(crate) fn profiles(
        &self,
        deployment: &str,
        origin: &str,
        now: u64,
    ) -> Result<Vec<DirectProtectedProfile>> {
        let profiles = self
            .accepted
            .iter()
            .filter(|item| {
                item.deployment == deployment
                    && item.origin == origin
                    && item.issued_at <= now
                    && now < item.expires_at
            })
            .map(|item| item.profile.clone())
            .collect::<Vec<_>>();
        ensure!(!profiles.is_empty(), "direct acceptance missing or expired");
        Ok(profiles)
    }

    pub(super) fn retained_clock_policy(&self, deployment: &str, origin: &str) -> Result<u64> {
        let mut clocks = self
            .accepted
            .iter()
            .filter(|item| item.deployment == deployment && item.origin == origin)
            .map(|item| match &item.profile {
                DirectProtectedProfile::Managed { profile, .. } => {
                    profile.clock_uncertainty_seconds.get()
                }
                DirectProtectedProfile::External { profile, .. } => {
                    profile.clock_uncertainty.get() as u64
                }
            });
        let clock = clocks
            .next()
            .context("direct reviewed clock policy absent")?;
        ensure!(
            (1..30).contains(&clock) && clocks.all(|item| item == clock),
            "direct reviewed clock policies differ"
        );
        Ok(clock)
    }

    pub(super) fn retained_profiles(
        &self,
        deployment: &str,
        origin: &str,
    ) -> Result<Vec<DirectProtectedProfile>> {
        let profiles = self
            .accepted
            .iter()
            .filter(|item| item.deployment == deployment && item.origin == origin)
            .map(|item| item.profile.clone())
            .collect::<Vec<_>>();
        ensure!(!profiles.is_empty(), "direct reviewed guard history absent");
        Ok(profiles)
    }

    /// Returns previously reviewed guard issuer pins without granting dispatch.
    ///
    /// Terminal metadata evidence remains readable after a producer acceptance
    /// expires. Exact profile selection is still required; this method cannot
    /// authorize a new provider operation or renew that acceptance.
    pub(crate) fn retained_guard_issuer(
        &self,
        deployment: &str,
        origin: &str,
        profile_digest: &str,
    ) -> Result<(String, String, u64)> {
        let uncertainty = self
            .accepted
            .iter()
            .find_map(|accepted| {
                if accepted.deployment != deployment
                    || accepted.origin != origin
                    || !accepted
                        .profile
                        .digest()
                        .is_ok_and(|digest| digest == profile_digest)
                {
                    return None;
                }
                match &accepted.profile {
                    DirectProtectedProfile::Managed { profile, .. } => {
                        Some(profile.clock_uncertainty_seconds.get())
                    }
                    DirectProtectedProfile::External { .. } => None,
                }
            })
            .context("mirror original has no reviewed managed guard issuer")?;
        Ok((
            self.source_digest.clone(),
            self.script_version.clone(),
            uncertainty,
        ))
    }
}

fn validate_provider_runtime(
    runtime: DirectWorkerExecutionKind,
    profile: &DirectProtectedProfile,
) -> Result<()> {
    use aos_hub_core::storage_authority::StorageAuthorityHost;

    let qualified = match (runtime, profile) {
        (DirectWorkerExecutionKind::Hosted, DirectProtectedProfile::Managed { .. }) => true,
        (DirectWorkerExecutionKind::Hosted, DirectProtectedProfile::External { profile, .. }) => {
            !profile.provider_contract_id.starts_with("emulated-")
        }
        (
            DirectWorkerExecutionKind::EmulatedExternal,
            DirectProtectedProfile::External { profile, .. },
        ) => {
            let emulated_host = |host: &StorageAuthorityHost| {
                matches!(host,
                StorageAuthorityHost::Dns(name) if name == "localhost"
                    || name.ends_with(".localhost") || name.ends_with(".test"))
            };
            profile.provider_contract_id.starts_with("emulated-")
                && emulated_host(&profile.write_cohort.alias.spec.host)
                && emulated_host(&profile.read_cohort.alias.spec.host)
        }
        _ => false,
    };
    ensure!(
        qualified,
        "direct accepted runtime does not qualify this provider"
    );
    Ok(())
}

fn bounded_file(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).context("opening direct acceptance configuration")?;
    ensure!(
        file.metadata()?.is_file(),
        "direct acceptance must be an ordinary file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_ACCEPTANCE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_ACCEPTANCE_BYTES,
        "direct acceptance configuration exceeds bound"
    );
    Ok(bytes)
}

#[cfg(test)]
pub(super) mod tests;
