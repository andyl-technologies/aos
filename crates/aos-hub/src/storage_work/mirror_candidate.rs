//! Native test authority for the actual reserved mirror runtime experiment.
//!
//! This module is absent from production builds. It selects the separate
//! candidate endpoint and MAC purpose while retaining the ordinary controller,
//! bounded transport, SQL journal and independent final guard consumer.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{DirectManagedR2Profile, DirectPrivateStagePolicyRef};
use aos_hub_core::mirror_guard::MirrorGuardIssuer;
use aos_hub_core::storage_work::StorageWorkKey;

use super::RemoteStorageWorkClient;

pub(super) struct ControlledMirrorAuthority {
    pub(super) profile_digest: String,
    pub(super) issuer: MirrorGuardIssuer,
    pub(super) uncertainty: u64,
    pub(super) key: StorageWorkKey,
}

impl RemoteStorageWorkClient {
    pub(crate) fn with_controlled_ca(mut self, certificate: &[u8]) -> Result<Self> {
        ensure!(
            self.controlled_mirror.is_some(),
            "controlled TLS requires isolated candidate authority"
        );
        self.http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .add_root_certificate(reqwest::Certificate::from_pem(certificate)?)
            .build()?;
        Ok(self)
    }

    /// Selects actual raw fixture material without creating runtime acceptance.
    ///
    /// # Errors
    /// Returns an error for changed deployment, malformed raw material or issuer,
    /// a reused producer key, or an invalid controlled clock projection.
    pub(crate) fn with_controlled_mirror(
        mut self,
        profile: &DirectManagedR2Profile,
        policy: &DirectPrivateStagePolicyRef,
        issuer: MirrorGuardIssuer,
        candidate_key: &[u8],
    ) -> Result<Self> {
        let key = StorageWorkKey::new(candidate_key)?;
        let separation = b"aos.hub.mirror-candidate-role-separation.v1";
        ensure!(
            self.key
                .verify_body(&key.sign_body(separation)?, separation)
                .is_err(),
            "candidate authority must differ from ordinary storage work"
        );
        ensure!(
            profile.deployment_id == self.deployment_id
                && aos_hub_core::direct_upload::valid_direct_digest(&issuer.source_digest)
                && issuer.script_version == format!("emulated-{}", issuer.source_digest)
                && (1..30).contains(&profile.clock_uncertainty_seconds.get()),
            "candidate raw material differs from the actual controlled issuer"
        );
        let profile_digest =
            aos_hub_core::mirror_acceptance::mirror_candidate_profile_digest(profile, policy)?;
        self.controlled_mirror = Some(ControlledMirrorAuthority {
            profile_digest,
            issuer,
            uncertainty: profile.clock_uncertainty_seconds.get(),
            key,
        });
        Ok(self)
    }
}
