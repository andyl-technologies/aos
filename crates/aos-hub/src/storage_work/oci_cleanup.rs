//! Actual terminal SQL claims and independent Managed R2 cleanup receipts.

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    db::{BindingRecord, OciTerminalChunkCleanupClaim, SurfacePlacementRecord},
    mirror_guard::MirrorGuardIssuer,
    oci_cleanup::*,
};

use super::HybridSurfaceWrites;

impl HybridSurfaceWrites {
    pub(super) async fn cleanup_managed_oci_chunk(
        &self,
        claim: &OciTerminalChunkCleanupClaim,
    ) -> Result<bool> {
        claim.check_current(&self.db).await?;
        let placement = self
            .db
            .surface_placement(
                claim
                    .upload()
                    .staging_placement_id
                    .context("Managed cleanup staging placement missing")?,
            )
            .await?
            .context("Managed cleanup placement disappeared")?;
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("Managed cleanup binding disappeared")?;
        if binding.kind != "deployment_r2" || !binding.is_instance_default {
            return Ok(false);
        }

        let revision = claim
            .upload()
            .staging_binding_write_revision
            .context("Managed cleanup write revision absent")?;
        let capability = self
            .db
            .oci_conditional_delete_capability(binding.id, revision)
            .await?
            .context("Managed cleanup independently validated Delete capability absent")?;
        ensure!(
            capability.state == "valid"
                && capability.binding_resource_version == binding.resource_version
                && capability.delete_credential_generation.is_none()
                && capability.delete_credential_purpose.is_none(),
            "Managed cleanup Delete capability differs from its actual attached R2 binding"
        );
        let original = ManagedOciCleanupOriginal::from_claim(
            claim,
            placement.prefix.clone(),
            binding.resource_version,
            capability.capability_fingerprint.clone(),
            capability.resource_version,
        )?;
        let origin = self.work.executor_origin()?;
        // An OCI-only anchor artifact is deliberately insufficient for Delete.
        let profile = self
            .work
            .mirror_profiles
            .as_ref()
            .context("Managed cleanup ordinary provider issuer is not installed")?
            .retained_managed_profile_digest(&self.work.deployment_id, &origin)?;
        let (source_digest, script_version, uncertainty) = self
            .work
            .mirror_profiles
            .as_ref()
            .context("Managed cleanup ordinary provider acceptance is not installed")?
            .retained_guard_issuer(&self.work.deployment_id, &origin, &profile)?;
        let guard = self
            .work
            .mirror_guard_key
            .as_ref()
            .context("Managed cleanup independent physical guard role is not installed")?;
        let issued_at = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        let request = ManagedOciCleanupRequest {
            deployment_id: self.work.deployment_id.clone(),
            original,
            protected_profile_digest: profile,
            issuer: MirrorGuardIssuer {
                source_digest,
                script_version,
            },
            clock_uncertainty_seconds: uncertainty,
            nonce: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            issued_at,
            expires_at: issued_at
                .checked_add(30)
                .context("Managed cleanup deadline overflow")?,
        };
        let check = || async {
            claim.check_current(&self.db).await?;
            recheck(self, &placement, &binding, &request.original).await?;
            let latest = u64::try_from(aos_hub_core::clock::now_unix_secs())?
                .checked_add(uncertainty)
                .context("Managed cleanup clock overflow")?;
            request.validate(&self.work.deployment_id, latest)
        };
        check().await?;
        let _capacity = self.work.in_flight.acquire().await?;
        check().await?;
        let (body, signature) = request.sign(&self.work.key)?;
        let remaining = request
            .expires_at
            .checked_sub(
                u64::try_from(aos_hub_core::clock::now_unix_secs())?
                    .checked_add(uncertainty)
                    .context("Managed cleanup clock overflow")?,
            )
            .filter(|seconds| *seconds > 0)
            .context("Managed cleanup deadline expired")?;
        let exchange = async {
            let response = self
                .work
                .http
                .post(format!("{origin}{MANAGED_OCI_CLEANUP_PATH}"))
                .header(MANAGED_OCI_CLEANUP_HEADER, signature)
                .header("content-type", "application/json")
                .body(body)
                .timeout(std::time::Duration::from_secs(remaining))
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("Managed terminal cleanup exchange unknown"))?;
            ensure!(
                response.status() == reqwest::StatusCode::OK,
                "Managed terminal cleanup refused or unknown"
            );
            let signature = response
                .headers()
                .get(MANAGED_OCI_CLEANUP_HEADER)
                .context("Managed cleanup positive physical signature absent")?
                .to_str()?
                .to_owned();
            let bytes =
                super::read_bounded_response(response, MAX_MANAGED_OCI_CLEANUP_BYTES).await?;
            ManagedOciCleanupReply::authenticate(&request, guard, &signature, &bytes)
        };
        let _positive = tokio::time::timeout(std::time::Duration::from_secs(remaining), exchange)
            .await
            .context("Managed cleanup reply deadline expired; outcome remains unknown")??;
        check().await?;
        Ok(true)
    }
}

async fn recheck(
    writers: &HybridSurfaceWrites,
    placement: &SurfacePlacementRecord,
    binding: &BindingRecord,
    original: &ManagedOciCleanupOriginal,
) -> Result<()> {
    let current = writers
        .db
        .surface_placement(placement.id)
        .await?
        .context("Managed cleanup placement disappeared")?;
    let current_binding = writers
        .db
        .binding(binding.id)
        .await?
        .context("Managed cleanup binding disappeared")?;
    let state = writers
        .db
        .binding_write_state(binding.id)
        .await?
        .context("Managed cleanup current write state disappeared")?;
    let capability = writers
        .db
        .oci_conditional_delete_capability(binding.id, original.binding_write_revision)
        .await?
        .context("Managed cleanup Delete capability disappeared")?;
    ensure!(
        current.resource_version == original.placement_resource_version
            && current.registry_id == Some(original.registry_id)
            && current.binding_id == binding.id
            && current.prefix == original.placement_prefix
            && current_binding.resource_version == binding.resource_version
            && current_binding.stable_id == binding.stable_id
            && current_binding.kind == "deployment_r2"
            && current_binding.is_instance_default
            && state.current_write_revision == Some(original.binding_write_revision)
            && capability.state == "valid"
            && capability.binding_resource_version == original.binding_resource_version
            && capability.resource_version == original.delete_capability_resource_version
            && capability.capability_fingerprint == original.delete_capability_fingerprint
            && capability.delete_credential_generation.is_none()
            && capability.delete_credential_purpose.is_none(),
        "Managed terminal cleanup current placement, binding or Delete capability changed"
    );
    Ok(())
}
