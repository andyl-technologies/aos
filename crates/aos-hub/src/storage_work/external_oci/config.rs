//! Independent public profile/reviewer pins for the External OCI Native adapter.
//!
//! Loading verifies supplied evidence; it never signs a qualification or learns
//! a reviewer key from an artifact. The physical role is installed separately
//! from the logical storage-work role and never contains provider credentials.

use std::{collections::BTreeMap, io::Read as _, path::Path};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_authority::external_object::oci::qualification::{
    ExternalOciAcceptance, ExternalOciProfile,
};
use aos_hub_core::storage_work::{StorageBindingSnapshot, StorageWorkKey};
use serde::Deserialize;

const MAX_PUBLIC_INPUT: usize = 2 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pins {
    version: u8,
    deployment_id: String,
    source_digest: String,
    script_version: String,
    clock_uncertainty_seconds: i64,
    profiles: Vec<ExternalOciProfile>,
}

/// Independently configured exact OCI profiles and verified immutable evidence.
pub struct ExternalOciRuntime {
    pins: Pins,
    accepted: BTreeMap<String, ExternalOciAcceptance>,
    pub(in crate::storage_work) guard: StorageWorkKey,
    #[cfg(all(test, feature = "required-live-dialects"))]
    candidate: Option<aos_hub_core::storage_authority::external_object::oci::candidate::ExternalOciCandidate>,
}

impl ExternalOciRuntime {
    /// Loads separately selected profile pins, measured artifacts and reviewer trust.
    ///
    /// All files are bounded public metadata. `guard_key` is a separately read
    /// private physical-role key, never a provider credential. Controlled-only
    /// evidence cannot activate an ordinary production OCI consumer.
    ///
    /// # Errors
    /// Refuses oversized files, unknown schemas, missing/duplicate profiles,
    /// untrusted signatures, incomplete measurements or stale immutable review.
    pub fn from_files(
        pins: &Path,
        acceptance: &Path,
        reviewers: &Path,
        guard_key: &[u8],
    ) -> Result<Self> {
        Self::from_bytes(&bounded_file(pins)?, &bounded_file(acceptance)?,
            &bounded_file(reviewers)?, guard_key, aos_hub_core::clock::now_unix_secs())
    }

    fn from_bytes(pins: &[u8], accepted: &[u8], reviewers: &[u8], guard: &[u8], now: i64) -> Result<Self> {
        ensure!([pins, accepted, reviewers].iter().all(|bytes| bytes.len() <= MAX_PUBLIC_INPUT),
            "external OCI public configuration exceeds bound");
        let pins: Pins = serde_json::from_slice(pins)?;
        let artifacts: Vec<ExternalOciAcceptance> = serde_json::from_slice(accepted)?;
        let reviewers: BTreeMap<String, String> = serde_json::from_slice(reviewers)?;
        ensure!(pins.version == 1 && (1..30).contains(&pins.clock_uncertainty_seconds)
            && !pins.profiles.is_empty() && pins.profiles.len() <= 16
            && artifacts.len() == pins.profiles.len()
            && !reviewers.is_empty() && reviewers.len() <= 32,
            "external OCI runtime configuration is incomplete");
        let latest = now.checked_add(pins.clock_uncertainty_seconds)
            .context("external OCI configuration clock overflow")?;
        let mut selected = BTreeMap::new();
        for profile in &pins.profiles {
            profile.validate()?;
            let matching: Vec<_> = artifacts.iter().filter(|artifact| &artifact.profile == profile).collect();
            ensure!(matching.len() == 1, "external OCI profile acceptance missing or duplicated");
            let artifact = matching[0];
            let public = reviewers.get(&artifact.reviewer_key_id)
                .context("external OCI reviewer is not independently trusted")?;
            artifact.require_production(public, &artifact.reviewer_key_id, &pins.deployment_id,
                &pins.source_digest, &pins.script_version, profile, latest)?;
            ensure!(selected.insert(profile.digest()?, artifact.clone()).is_none(),
                "external OCI profile duplicated");
        }
        Ok(Self { pins, accepted: selected, guard: StorageWorkKey::new(guard)?,
            #[cfg(all(test, feature = "required-live-dialects"))]
            candidate: None,
        })
    }

    /// Selects one actual reserved test fixture without producing acceptance.
    #[cfg(all(test, feature = "required-live-dialects"))]
    pub(in crate::storage_work) fn controlled(
        candidate: aos_hub_core::storage_authority::external_object::oci::candidate::ExternalOciCandidate,
        profile: ExternalOciProfile,
        uncertainty: i64,
        guard: &[u8],
        now: i64,
    ) -> Result<Self> {
        ensure!((1..30).contains(&uncertainty), "controlled OCI clock unsupported");
        candidate.validate(&candidate.deployment_id, &candidate.source_digest,
            &candidate.script_version, &profile, &candidate.placement_prefix,
            now.checked_add(uncertainty).context("controlled OCI clock overflow")?)?;
        let pins = Pins {
            version: 1, deployment_id: candidate.deployment_id.clone(),
            source_digest: candidate.source_digest.clone(),
            script_version: candidate.script_version.clone(),
            clock_uncertainty_seconds: uncertainty, profiles: vec![profile],
        };
        Ok(Self { pins, accepted: BTreeMap::new(),
            guard: StorageWorkKey::new(guard)?, candidate: Some(candidate) })
    }

    #[cfg(all(test, feature = "required-live-dialects"))]
    pub(in crate::storage_work) fn check_controlled_writer(&self, placement: &str, latest: i64) -> Result<()> {
        if let Some(candidate) = &self.candidate {
            candidate.validate(&self.pins.deployment_id, &self.pins.source_digest,
                &self.pins.script_version, self.pins.profiles.first().context("controlled OCI profile absent")?, placement, latest)?;
        }
        Ok(())
    }

    pub(in crate::storage_work) fn check_original(
        &self, original: &aos_hub_core::storage_authority::external_object::oci::ExternalOciOriginal,
        latest: i64,
    ) -> Result<()> {
        original.validate()?;
        #[cfg(all(test, feature = "required-live-dialects"))]
        if let Some(candidate) = &self.candidate {
            let profile = self.pins.profiles.first().context("controlled OCI profile absent")?;
            ensure!(original.profile_digest == profile.digest()?, "controlled OCI original profile changed");
            return candidate.validate(&self.pins.deployment_id, &self.pins.source_digest,
                &self.pins.script_version, profile, &original.writer.placement_prefix, latest);
        }
        self.accepted.get(&original.profile_digest)
            .context("external OCI independently verified purpose absent")?.check_time(latest)
    }

    pub(in crate::storage_work) fn deployment(&self) -> &str { &self.pins.deployment_id }

    pub(in crate::storage_work) fn uncertainty(&self) -> i64 { self.pins.clock_uncertainty_seconds }

    pub(in crate::storage_work) fn issuer(&self) -> aos_hub_core::mirror_guard::MirrorGuardIssuer {
        aos_hub_core::mirror_guard::MirrorGuardIssuer {
            source_digest: self.pins.source_digest.clone(), script_version: self.pins.script_version.clone(),
        }
    }

    // Metadata cleanup selects retained source coordinates without renewing its
    // expired OCI producer acceptance. Delete permission is checked separately.
    pub(super) fn cleanup_profile(&self, snapshot: &StorageBindingSnapshot, latest: i64)
        -> Result<&ExternalOciProfile> {
        let candidates: Vec<_> = self.pins.profiles.iter().filter(|profile|
            profile.validate_snapshot(snapshot, latest).is_ok()).collect();
        ensure!(candidates.len() == 1, "OCI cleanup physical profile is absent or ambiguous");
        Ok(candidates[0])
    }

    pub(in crate::storage_work) fn profile(&self, snapshot: &StorageBindingSnapshot, now: i64) -> Result<&ExternalOciProfile> {
        let latest = now.checked_add(self.pins.clock_uncertainty_seconds)
            .context("external OCI current clock overflow")?;
        let candidates: Vec<_> = self.pins.profiles.iter().filter(|profile|
            profile.validate_snapshot(snapshot, latest).is_ok()).collect();
        ensure!(candidates.len() == 1, "external OCI actual binding profile is absent or ambiguous");
        let profile = candidates[0];
        #[cfg(all(test, feature = "required-live-dialects"))]
        if let Some(candidate) = &self.candidate {
            candidate.validate(&self.pins.deployment_id, &self.pins.source_digest,
                &self.pins.script_version, profile, &candidate.placement_prefix, latest)?;
            return Ok(profile);
        }
        self.accepted.get(&profile.digest()?).context("external OCI verified profile absent")?
            .check_time(latest)?;
        Ok(profile)
    }
}

fn bounded_file(path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).context("reading external OCI public configuration")?;
    let mut bytes = Vec::new();
    file.take(MAX_PUBLIC_INPUT as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_PUBLIC_INPUT, "external OCI public file exceeds bound");
    Ok(bytes)
}
