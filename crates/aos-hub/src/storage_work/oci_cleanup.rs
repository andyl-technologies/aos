//! Actual terminal SQL claims and independent Managed R2 cleanup receipts.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    db::{BindingRecord, OciTerminalChunkCleanupClaim, SurfacePlacementRecord},
    mirror_guard::MirrorGuardIssuer,
    oci_cleanup::*,
};

use super::HybridSurfaceWrites;
use super::telemetry::{ExchangeTelemetry, STORAGE_CALL_ID_HEADER};

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
        let (profile, source_digest, script_version, uncertainty) = self
            .work
            .managed_cleanup_identity(&original.placement_prefix)?;
        let origin = self.work.executor_origin()?;
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
        let mut exchange = ExchangeTelemetry::control(&request.nonce, "managed_oci_cleanup");
        let url = format!("{origin}{MANAGED_OCI_CLEANUP_PATH}");
        let operation = exchange_cleanup(
            &self.work.http,
            &url,
            &request,
            guard,
            body,
            signature,
            remaining,
            &mut exchange,
        );
        let positive = tokio::time::timeout(std::time::Duration::from_secs(remaining), operation)
            .await
            .context("Managed cleanup reply deadline expired; outcome remains unknown")??;
        check().await?;

        // The existing checks above preserve the current terminal claim and
        // credential-free Delete capability. This receipt performs no queries.
        super::external_oci::observation::checked(
            exchange.control_observation(),
            "managed_oci_cleanup_delete_checked",
            &[
                (
                    "requestSha256",
                    super::external_oci::observation::digest(&request),
                ),
                (
                    "replySha256",
                    super::external_oci::observation::digest(&positive),
                ),
                (
                    "uploadStateSha256",
                    super::external_oci::observation::digest(&(
                        &claim.upload().id,
                        claim.upload().resource_version,
                        &claim.upload().state,
                        &claim.upload().cleanup_state,
                        claim.upload().finished_at,
                        claim.upload().staging_placement_id,
                        claim.upload().staging_binding_id,
                        claim.upload().staging_binding_write_revision,
                    )),
                ),
                (
                    "chunkStateSha256",
                    super::external_oci::observation::digest(&(
                        claim.chunk().ordinal,
                        claim.chunk().byte_offset,
                        claim.chunk().byte_size,
                        claim.chunk().digest,
                        &claim.chunk().staging_object_key,
                        claim.chunk().created_at,
                    )),
                ),
                (
                    "placementStateSha256",
                    super::external_oci::observation::digest(&(
                        placement.id,
                        placement.resource_version,
                        placement.binding_id,
                        placement.registry_id,
                        &placement.prefix,
                    )),
                ),
                (
                    "bindingStateSha256",
                    super::external_oci::observation::digest(&(
                        binding.id,
                        binding.resource_version,
                        &binding.stable_id,
                        &binding.kind,
                        binding.is_instance_default,
                        revision,
                    )),
                ),
                (
                    "deleteCapabilitySha256",
                    super::external_oci::observation::digest(&(
                        &capability.capability_fingerprint,
                        capability.resource_version,
                        capability.binding_resource_version,
                        &capability.state,
                        &capability.delete_credential_generation,
                        &capability.delete_credential_purpose,
                    )),
                ),
            ],
        );
        Ok(true)
    }
}

/// Counts Native-exposed metadata bytes without interpreting upstream completion
/// as consumption. Current SQL and the original cutoff remain the caller's checks.
async fn exchange_cleanup(
    http: &reqwest::Client,
    url: &str,
    request: &ManagedOciCleanupRequest,
    guard: &aos_hub_core::storage_work::StorageWorkKey,
    body: Vec<u8>,
    signature: String,
    remaining: u64,
    exchange: &mut ExchangeTelemetry<'_>,
) -> Result<ManagedOciCleanupReply> {
    exchange.offer_control(MANAGED_OCI_CLEANUP_PATH, &body);
    let mut outbound = crate::outbound_inventory::Observation::start(
        crate::outbound_inventory::Owner::ManagedCleanup,
        crate::outbound_inventory::Image::Nonsecret(&body),
        Some(exchange.transport_call_id()),
    );
    let response = http
        .post(url)
        .header(MANAGED_OCI_CLEANUP_HEADER, signature)
        .header(STORAGE_CALL_ID_HEADER, exchange.transport_call_id())
        .header("content-type", "application/json")
        .body(body)
        .timeout(std::time::Duration::from_secs(remaining))
        .send()
        .await
        .map_err(|_| {
            exchange.finish("transport_failed");
            anyhow::anyhow!("Managed terminal cleanup exchange unknown")
        })?;
    outbound.response(response.status().as_u16());
    if response.status() != reqwest::StatusCode::OK {
        exchange.discard_status_response();
        exchange.finish("http_rejected");
        anyhow::bail!("Managed terminal cleanup refused or unknown");
    }
    let signature = response
        .headers()
        .get(MANAGED_OCI_CLEANUP_HEADER)
        .context("Managed cleanup positive physical signature absent")
        .and_then(|signature| {
            signature
                .to_str()
                .context("Managed cleanup signature is not UTF-8")
        })
        .inspect_err(|_| exchange.finish("invalid_result"))?
        .to_owned();
    let bytes = super::read_inventory_observed_response(
        response,
        MAX_MANAGED_OCI_CLEANUP_BYTES,
        &mut outbound,
        |length| exchange.observe_body(length),
    )
    .await
    .inspect_err(|_| exchange.finish("response_read_failed"))?;
    let reply = ManagedOciCleanupReply::authenticate(request, guard, &signature, &bytes)
        .inspect_err(|_| exchange.finish("invalid_result"))?;
    exchange.authenticated_control(&bytes);
    exchange.finish("success");
    Ok(reply)
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

impl super::RemoteStorageWorkClient {
    fn managed_cleanup_identity(&self, prefix: &str) -> Result<(String, String, String, u64)> {
        #[cfg(test)]
        if let Some(selected) = &self.controlled_managed_cleanup {
            anyhow::ensure!(
                selected.prefix == prefix,
                "Managed cleanup fixture prefix changed"
            );
            return Ok((
                selected.profile.clone(),
                selected.source.clone(),
                selected.script.clone(),
                selected.uncertainty,
            ));
        }
        #[cfg(not(test))]
        let _ = prefix;

        // An OCI-only anchor artifact is deliberately insufficient for Delete.
        let origin = self.executor_origin()?;
        let accepted = self
            .mirror_profiles
            .as_ref()
            .context("Managed cleanup ordinary provider issuer is not installed")?;
        let profile = accepted.retained_managed_profile_digest(&self.deployment_id, &origin)?;
        let (source, script, uncertainty) =
            accepted.retained_guard_issuer(&self.deployment_id, &origin, &profile)?;
        Ok((profile, source, script, uncertainty))
    }

    /// Selects a confined actual emulator identity for terminal cleanup tests.
    ///
    /// The physical namespace profile carries no Delete permission. The actual
    /// terminal SQL claim and independent current capability are checked by
    /// `cleanup_managed_oci_chunk` before this selection is consumed.
    ///
    /// # Errors
    /// Rejects changed deployment, executor origin, source, script or an
    /// unconfined cleanup prefix.
    #[cfg(test)]
    pub(crate) fn with_controlled_managed_cleanup(
        mut self,
        profile: aos_hub_core::oci_sdk_emulation::OciSdkEmulationProfile,
        issuer: aos_hub_core::mirror_guard::MirrorGuardIssuer,
        prefix: String,
    ) -> Result<Self> {
        profile.validate()?;
        anyhow::ensure!(
            profile.deployment_id == self.deployment_id
                && profile.public_origin == self.executor_origin()?
                && profile.worker_source_digest == issuer.source_digest
                && profile.worker_script_version == issuer.script_version
                && aos_hub_core::direct_upload::valid_direct_digest(&issuer.source_digest)
                && issuer.script_version
                    == aos_hub_core::direct_upload::direct_worker_emulated_script_id(
                        &issuer.source_digest
                    )?,
            "Managed cleanup fixture deployment or emulated issuer differs"
        );
        let run = prefix.strip_prefix("qualification/oci-terminal-cleanup/");
        anyhow::ensure!(
            run.is_some_and(|run| !run.is_empty()
                && run.len() <= 64
                && run.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'-')),
            "Managed cleanup fixture prefix is not confined"
        );
        self.controlled_managed_cleanup = Some(ControlledCleanup {
            prefix,
            profile: aos_hub_core::oci_cleanup::managed_cleanup_fixture_profile_digest(&profile)?,
            source: issuer.source_digest,
            script: issuer.script_version,
            uncertainty: profile.clock_policy.uncertainty_seconds.get(),
        });
        Ok(self)
    }
}

#[cfg(test)]
pub(super) struct ControlledCleanup {
    prefix: String,
    profile: String,
    source: String,
    script: String,
    uncertainty: u64,
}

#[cfg(all(test, target_os = "linux"))]
mod controlled;

#[cfg(test)]
mod observation_tests;

#[cfg(test)]
mod observations;
