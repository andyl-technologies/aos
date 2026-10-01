//! Independent storage-side OCI document metadata for the Hybrid facade.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    hybrid_ingress::HybridOciManifestAdmission, mirror_guard::MirrorGuardIssuer,
    oci_projection::guard::*,
};
use aos_oci_types::Descriptor;

use super::HybridSurfaceFetch;

mod exchange;

impl HybridSurfaceFetch {
    pub(super) async fn read_oci_projection(
        &self,
        path: &str,
        descriptor: &Descriptor,
        admission: Option<&HybridOciManifestAdmission>,
    ) -> Result<Option<VerifiedOciProjection>> {
        ensure!(
            self.binding.is_instance_default && self.binding.kind == "deployment_r2",
            "OCI document projection requires an admitted managed binding"
        );
        let profile_digest = self.work.mirror_managed_profile_digest()?;
        let origin = self.work.executor_origin()?;
        let profiles = self
            .work
            .mirror_profiles
            .as_ref()
            .context("OCI guard issuer is not independently configured")?;
        let (source_digest, script_version, uncertainty) =
            profiles.retained_guard_issuer(&self.work.deployment_id, &origin, &profile_digest)?;
        let key = self
            .work
            .mirror_guard_key
            .as_ref()
            .context("independent OCI guard role is not configured")?;
        let _capacity = self.work.in_flight.acquire().await?;
        let issued_at = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        let lookup = OciProjectionLookup {
            version: 1,
            protected_profile_digest: profile_digest.clone(),
            deployment_id: self.work.deployment_id.clone(),
            issuer: MirrorGuardIssuer {
                source_digest,
                script_version,
            },
            clock_uncertainty_seconds: uncertainty,
            key: aos_hub_core::keymap::r2_key(&self.placement.prefix, path),
            descriptor: Descriptor {
                media_type: descriptor.media_type,
                digest: descriptor.digest,
                size: descriptor.size,
                urls: Vec::new(),
                annotations: aos_oci_types::Annotations::new(),
                data: None,
                artifact_type: None,
                platform: None,
            },
            admission: admission.cloned(),
            nonce: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            issued_at,
            expires_at: issued_at
                .checked_add(30)
                .context("OCI projection deadline overflow")?,
        };
        let proof = self
            .work
            .exchange_oci_projection(&origin, key, &lookup)
            .await?;

        // The remote proof cannot authorize a changed SQL writer or profile.
        let placement = self
            .db
            .surface_placement(self.placement.id)
            .await?
            .context("OCI placement disappeared during readback")?;
        let binding = self
            .db
            .binding(self.binding.id)
            .await?
            .context("OCI binding disappeared during readback")?;
        ensure!(
            placement.resource_version == self.placement.resource_version
                && placement.binding_id == self.binding.id
                && placement.prefix == self.placement.prefix
                && binding.resource_version == self.binding.resource_version
                && binding.stable_id == self.binding.stable_id
                && binding.kind == self.binding.kind
                && self.work.mirror_managed_profile_digest()? == profile_digest,
            "OCI writer or provider qualification changed during readback"
        );
        Ok(Some(proof))
    }
}
