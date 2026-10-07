//! Exact terminal SQL cleanup with independent current conditional Delete custody.
//!
//! Upload write authority is never reopened. Every chunk receipt is checked
//! before the caller's existing all-upload cleanup CAS; SQL history remains.

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    db::{BindingRecord, OciTerminalChunkCleanupClaim, SurfacePlacementRecord},
    storage_authority::{control::StorageAuthorityObjectScope, external_object::oci::cleanup::*},
};

use super::{HybridSurfaceWrites, latest};

impl HybridSurfaceWrites {
    pub(in crate::storage_work) async fn cleanup_external_oci_chunk(
        &self,
        claim: &OciTerminalChunkCleanupClaim,
    ) -> Result<bool> {
        claim.check_current(&self.db).await?;
        let upload = claim.upload();
        let placement = self
            .db
            .surface_placement(
                upload
                    .staging_placement_id
                    .context("terminal OCI staging placement absent")?,
            )
            .await?
            .context("terminal OCI staging placement disappeared")?;
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("terminal OCI binding disappeared")?;
        if binding.is_instance_default || !matches!(binding.kind.as_str(), "s3" | "r2") {
            return Ok(false);
        }

        // Current-only custody is deliberate: no terminal upload credential
        // hold exists. Rotation or a missing Delete capability must refuse.
        let revision = upload
            .staging_binding_write_revision
            .context("OCI staging revision absent")?;
        let credential = self
            .db
            .current_binding_credential(binding.id, "delete")
            .await?
            .context("terminal OCI cleanup Delete credential absent")?;
        let capability = self
            .db
            .oci_conditional_delete_capability(binding.id, revision)
            .await?
            .context("terminal OCI conditional Delete capability absent")?;
        ensure!(
            capability.state == "valid"
                && capability.binding_resource_version == binding.resource_version
                && capability.delete_credential_purpose.as_deref() == Some("delete")
                && capability.delete_credential_generation == Some(credential.generation)
                && credential.validation_state == "valid",
            "terminal OCI cleanup requires independently validated exact Delete custody"
        );
        self.work
            .ensure_remote_binding_snapshot(&self.db, &binding)
            .await?;
        let snapshot = self.work.acknowledged_binding_snapshot(binding.id)?;
        let runtime = self
            .work
            .external_oci
            .as_ref()
            .context("OCI guard role is not independently installed")?;
        let profile = runtime.cleanup_profile(&snapshot, latest(runtime)?)?;
        ensure!(
            profile
                .write_cohort
                .association
                .binding_write_revision
                .get()
                == revision,
            "terminal OCI cleanup cannot substitute another physical writer revision"
        );
        let original = OciCleanupOriginal::from_claim(
            claim,
            placement.prefix.clone(),
            binding.resource_version,
            snapshot.binding_spec_revision()?,
            credential.generation,
            capability.capability_fingerprint.clone(),
            capability.resource_version,
        )?;
        let issued_at = aos_hub_core::clock::now_unix_secs();
        let request = OciCleanupRequest {
            deployment_id: self.work.deployment_id.clone(),
            original,
            scope: StorageAuthorityObjectScope {
                guard_namespace_id: profile.write_cohort.authority.guard_namespace_id.clone(),
                physical_authority_id: profile.write_cohort.authority.authority_id.clone(),
                full_key: aos_hub_core::keymap::r2_key(
                    &snapshot.object_prefix,
                    &aos_hub_core::keymap::r2_key(
                        &placement.prefix,
                        &claim.chunk().staging_object_key,
                    ),
                ),
            },
            issuer: runtime.issuer(),
            clock_uncertainty_seconds: u64::try_from(runtime.uncertainty())?,
            nonce: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            issued_at,
            expires_at: issued_at
                .checked_add(30)
                .context("OCI cleanup deadline overflow")?,
        };
        let check = || async {
            claim.check_current(&self.db).await?;
            recheck(self, claim, &placement, &binding, &request.original).await?;
            request.validate(&self.work.deployment_id, latest(runtime)?)
        };
        check().await?;
        let _permit = self.work.in_flight.acquire().await?;
        check().await?;
        let (body, signature) = request.sign(&self.work.key)?;
        let remaining = request
            .expires_at
            .checked_sub(latest(runtime)?)
            .filter(|seconds| *seconds > 0)
            .context("OCI cleanup deadline expired")?;
        let mut exchange = crate::storage_work::telemetry::ExchangeTelemetry::control(
            &request.nonce,
            "external_oci_cleanup",
        );
        let operation = async {
            exchange.offer_control(OCI_CLEANUP_PATH, &body);
            let mut outbound = crate::outbound_inventory::Observation::start(
                crate::outbound_inventory::Owner::ExternalCleanup,
                crate::outbound_inventory::Image::Nonsecret(&body),
                Some(exchange.transport_call_id()),
            );
            let response = self
                .work
                .http
                .post(format!(
                    "{}{}",
                    self.work.executor_origin()?,
                    OCI_CLEANUP_PATH
                ))
                .header(OCI_CLEANUP_SIGNATURE_HEADER, signature)
                .header(
                    crate::storage_work::telemetry::STORAGE_CALL_ID_HEADER,
                    exchange.transport_call_id(),
                )
                .header("content-type", "application/json")
                .body(body)
                .timeout(std::time::Duration::from_secs(remaining as u64))
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("terminal OCI delete exchange unknown"))?;
            outbound.response(response.status().as_u16());
            ensure!(
                response.status() == reqwest::StatusCode::OK,
                "terminal OCI cleanup refused or unknown"
            );
            let signature = response
                .headers()
                .get(OCI_CLEANUP_SIGNATURE_HEADER)
                .context("OCI cleanup positive guard signature absent")?
                .to_str()?
                .to_owned();
            let body = crate::storage_work::read_inventory_observed_response(
                response,
                MAX_OCI_CLEANUP_BYTES,
                &mut outbound,
                |length| exchange.observe_body(length),
            )
            .await?;
            let reply = OciCleanupReply::authenticate(&request, &runtime.guard, &signature, &body)
                .inspect_err(|_| exchange.finish("invalid_result"))?;
            exchange.authenticated_control(&body);
            exchange.finish("success");
            Ok::<_, anyhow::Error>(reply)
        };
        let _positive =
            tokio::time::timeout(std::time::Duration::from_secs(remaining as u64), operation)
                .await
                .context(
                    "terminal OCI cleanup reply deadline expired; outcome remains unknown",
                )??;
        check().await?;
        super::observation::checked(
            exchange.control_observation(),
            "external_oci_cleanup_delete_checked",
            &[
                ("requestSha256", super::observation::digest(&request)),
                ("replySha256", super::observation::digest(&_positive)),
                (
                    "uploadStateSha256",
                    super::observation::upload_digest(claim.upload()),
                ),
                (
                    "chunkStateSha256",
                    super::observation::chunk_digest(claim.chunk()),
                ),
                (
                    "placementStateSha256",
                    super::observation::digest(&(
                        placement.id,
                        placement.resource_version,
                        &placement.prefix,
                    )),
                ),
                (
                    "bindingStateSha256",
                    super::observation::digest(&(
                        binding.id,
                        binding.resource_version,
                        &binding.stable_id,
                    )),
                ),
                (
                    "deleteCredentialSha256",
                    super::observation::digest(&(
                        credential.generation,
                        &credential.validation_state,
                    )),
                ),
                (
                    "deleteCapabilitySha256",
                    super::observation::digest(&(
                        &capability.capability_fingerprint,
                        capability.resource_version,
                    )),
                ),
            ],
        );
        Ok(true)
    }
}

async fn recheck(
    writers: &HybridSurfaceWrites,
    claim: &OciTerminalChunkCleanupClaim,
    placement: &SurfacePlacementRecord,
    binding: &BindingRecord,
    original: &OciCleanupOriginal,
) -> Result<()> {
    let current = writers
        .db
        .surface_placement(placement.id)
        .await?
        .context("OCI cleanup placement disappeared")?;
    let current_binding = writers
        .db
        .binding(binding.id)
        .await?
        .context("OCI cleanup binding disappeared")?;
    let state = writers
        .db
        .binding_write_state(binding.id)
        .await?
        .context("OCI cleanup write state disappeared")?;
    let credential = writers
        .db
        .current_binding_credential(binding.id, "delete")
        .await?
        .context("OCI cleanup Delete credential disappeared")?;
    let capability = writers
        .db
        .oci_conditional_delete_capability(binding.id, original.binding_write_revision)
        .await?
        .context("OCI cleanup Delete capability disappeared")?;
    let snapshot = writers.work.acknowledged_binding_snapshot(binding.id)?;
    ensure!(
        current.resource_version == original.placement_resource_version
            && current.registry_id == Some(original.registry_id)
            && current.binding_id == binding.id
            && current.prefix == original.placement_prefix
            && claim.upload().staging_binding_id == Some(binding.id)
            && current_binding.stable_id == binding.stable_id
            && current_binding.resource_version == original.binding_resource_version
            && state.current_write_revision == Some(original.binding_write_revision)
            && credential.validation_state == "valid"
            && credential.generation == original.delete_generation
            && capability.state == "valid"
            && capability.resource_version == original.delete_capability_resource_version
            && capability.capability_fingerprint == original.delete_capability_fingerprint
            && capability.binding_resource_version == original.binding_resource_version
            && capability.delete_credential_generation == Some(original.delete_generation)
            && snapshot.binding_spec_revision()? == original.binding_spec_revision
            && snapshot.binding_resource_version == original.binding_resource_version,
        "terminal OCI cleanup current physical custody changed"
    );
    Ok(())
}
