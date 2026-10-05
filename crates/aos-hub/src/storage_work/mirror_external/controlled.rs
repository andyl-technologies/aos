//! Explicit test-only External Mirror functional transport selection.
//!
//! The unchanged Direct acceptance loader supplies the prerequisite. An
//! independently verified functional document restricts the upstream and two
//! reserved placements; it supplies no Hosted or production acceptance.

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    direct_upload::DirectProtectedProfile,
    mirror_acceptance::external_controlled::ControlledExternalMirrorArtifact,
    mirror_guard::MirrorGuardIssuer, mirror_work::MirrorOriginal,
};

use crate::storage_work::RemoteStorageWorkClient;

pub(in crate::storage_work) struct FunctionalAuthority {
    pub(in crate::storage_work) artifact: ControlledExternalMirrorArtifact,
    pub(in crate::storage_work) issuer: MirrorGuardIssuer,
    pub(in crate::storage_work) uncertainty: u64,
}

impl FunctionalAuthority {
    // Final metadata readback remains available after producer expiry. It only
    // correlates a held positive original; it cannot create an effect or scope.
    pub(in crate::storage_work) fn require_held(&self, original: &MirrorOriginal) -> Result<()> {
        let selected = original
            .external_destination
            .as_ref()
            .context("functional guard received a Managed original")?;
        ensure!(
            selected.protected_profile == self.artifact.protected_profile
                && selected.acceptance_digest == self.artifact.direct_evidence_sha256
                && original.protected_profile_digest == self.artifact.protected_profile.digest()?
                && original.upstream_base == self.artifact.upstream_base
                && ["full", "pull-through"]
                    .iter()
                    .any(|mode| original.placement_prefix
                        == format!("{}/{mode}", self.artifact.placement_prefix)),
            "functional guard escaped the independently installed probe"
        );
        Ok(())
    }
}

impl RemoteStorageWorkClient {
    /// Installs an independently signed functional document on the real client.
    ///
    /// # Errors
    /// Refuses an absent prerequisite, foreign signature, tuple, scope or cutoff.
    pub(crate) fn with_controlled_external_mirror(
        mut self,
        artifact: ControlledExternalMirrorArtifact,
        reviewer_public: &str,
        guard_key: &[u8],
    ) -> Result<Self> {
        ensure!(
            self.controlled_mirror.is_none(),
            "Managed candidate cannot select External functional purpose"
        );
        let accepted = self
            .mirror_profiles
            .as_ref()
            .context("functional Mirror needs actual Direct acceptance")?;
        let origin = self.executor_origin()?;
        let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        let expected = DirectProtectedProfile::External {
            profile: artifact.protected_profile.profile.clone(),
            runtime_qualification: artifact.protected_profile.runtime_qualification.clone(),
        };
        let current = accepted.profiles(&self.deployment_id, &origin, now)?;
        ensure!(
            current.iter().any(|profile| profile == &expected),
            "functional Mirror prerequisite is not actually accepted"
        );
        let (_, _, evidence) = accepted.external_profile_window(
            &self.deployment_id,
            &origin,
            &expected.digest()?,
            now,
        )?;
        let (source_digest, script_version, uncertainty) =
            accepted.retained_guard_issuer(&self.deployment_id, &origin, &expected.digest()?)?;
        artifact.require_current(
            &self.deployment_id,
            &origin,
            &source_digest,
            &script_version,
            &expected,
            &evidence,
            reviewer_public,
            now,
        )?;
        self = self.with_mirror_guard_key(guard_key)?;
        self.controlled_external_mirror = Some(FunctionalAuthority {
            artifact,
            issuer: MirrorGuardIssuer {
                source_digest,
                script_version,
            },
            uncertainty,
        });
        Ok(self)
    }

    // The only private-address metadata transport is test-only and requires the
    // exact independently signed upstream before using the existing TLS client.
    pub(crate) fn controlled_external_mirror_metadata(
        &self,
        upstream: &str,
    ) -> Result<Option<crate::fetch::HttpFetch>> {
        let Some(selected) = &self.controlled_external_mirror else {
            return Ok(None);
        };
        let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        selected.artifact.validate_unsigned(now)?;
        ensure!(
            upstream == selected.artifact.upstream_base,
            "functional metadata upstream changed"
        );
        Ok(Some(crate::fetch::HttpFetch::controlled_mirror_metadata(
            upstream.trim_end_matches('/').to_owned(),
            self.http.clone(),
        )))
    }
}
