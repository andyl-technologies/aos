//! OCI-specific Native admission and bounded retained external guard controls.
//!
//! Real OCI reservations and current actor/writer pins authorize small controls.
//! Provider bodies remain on Worker. Independent physical-role receipts report
//! exact retained originals and positive closure; unknown effects remain held.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    storage_authority::{control::StorageAuthorityObjectScope, external_object::oci::{
        admission::{ExternalOciStagePermit, ExternalOciStagePreparation},
        control::{ExternalOciRequest, OciControl, EXTERNAL_OCI_PATH, EXTERNAL_OCI_SIGNATURE_HEADER},
        reply::{ExternalOciReply, VerifiedExternalOciReply, EXTERNAL_OCI_RECEIPT_HEADER, MAX_EXTERNAL_OCI_REPLY_BYTES},
        ExternalOciOriginal, OciObjectOriginal, OciUploadOriginal,
    }},
};

use super::{read_bounded_response, HybridSurfaceWrites, RemoteStorageWorkClient, HybridSurfaceFetch};

mod config;
pub use config::ExternalOciRuntime;

impl RemoteStorageWorkClient {
    /// Installs independently verified External OCI workflow evidence and role.
    ///
    /// # Errors
    /// Refuses another deployment or reuse of the logical storage-work key.
    pub fn with_external_oci_runtime(mut self, runtime: ExternalOciRuntime) -> Result<Self> {
        let domain = b"aos.external-oci-role-separation.v1";
        ensure!(runtime.deployment() == self.deployment_id
            && self.key.verify_body(&runtime.guard.sign_body(domain)?, domain).is_err(),
            "external OCI deployment or independent physical role differs");
        self.external_oci = Some(std::sync::Arc::new(runtime));
        Ok(self)
    }

    async fn exchange_external_oci(&self, request: &ExternalOciRequest) -> Result<ExternalOciReply> {
        let (bytes, signature) = self.external_oci_reply_bytes(request).await?;
        let runtime = self.external_oci.as_ref().context("external OCI runtime absent")?;
        ExternalOciReply::authenticate(request, &runtime.guard, &signature, &bytes)
    }

    async fn external_oci_reply_bytes(&self, request: &ExternalOciRequest) -> Result<(Vec<u8>, String)> {
        let runtime = self.external_oci.as_ref().context("external OCI runtime is not independently configured")?;
        let original_deadline = request.expires_at;
        request.validate(&self.deployment_id, latest(runtime)?)?;
        runtime.check_original(&request.original, latest(runtime)?)?;
        let _capacity = self.in_flight.acquire().await?;
        request.validate(&self.deployment_id, latest(runtime)?)?;
        runtime.check_original(&request.original, latest(runtime)?)?;
        let (bytes, signature) = request.sign(&self.key, &self.deployment_id, latest(runtime)?)?;
        let remaining = original_deadline.checked_sub(latest(runtime)?)
            .filter(|seconds| *seconds > 0).context("external OCI control expired before exchange")?;
        let url = format!("{}{}", self.executor_origin()?, EXTERNAL_OCI_PATH);
        let response = self.http.post(url).header(EXTERNAL_OCI_SIGNATURE_HEADER, signature)
            .header("content-type", "application/json").body(bytes)
            .timeout(std::time::Duration::from_secs(remaining as u64)).send().await
            .map_err(|_| anyhow::anyhow!("external OCI control exchange failed; effects remain unknown"))?;
        ensure!(response.status() == reqwest::StatusCode::OK, "external OCI control refused");
        let signature = response.headers().get(EXTERNAL_OCI_RECEIPT_HEADER)
            .context("external OCI physical reply signature absent")?.to_str()?.to_owned();
        let remaining = original_deadline.checked_sub(latest(runtime)?)
            .filter(|seconds| *seconds > 0).context("external OCI reply original deadline expired")?;
        let bytes = tokio::time::timeout(std::time::Duration::from_secs(remaining as u64),
            read_bounded_response(response, MAX_EXTERNAL_OCI_REPLY_BYTES)).await
            .context("external OCI reply deadline expired; effects remain unknown")??;
        request.validate(&self.deployment_id, latest(runtime)?)?;
        runtime.check_original(&request.original, latest(runtime)?)?;
        Ok((bytes, signature))
    }
}

impl HybridSurfaceWrites {
    pub(super) async fn read_external_stage(&self, permit: &ExternalOciStagePermit) -> Result<VerifiedExternalOciReply> {
        permit.validate_shape()?;
        let runtime = self.work.external_oci.as_ref().context("external OCI runtime absent")?;
        let binding_id = permit.request.original.writer.binding_id.get();
        let snapshot = self.work.acknowledged_binding_snapshot(binding_id)?;
        let profile = runtime.profile(&snapshot, aos_hub_core::clock::now_unix_secs())?;
        ensure!(profile.digest()? == permit.request.original.profile_digest,
            "external OCI current readback profile differs");
        let request = phase(runtime, &snapshot.revision()?, permit.request.original.clone(),
            permit.request.actor.clone(), OciControl::Status)?;
        let (bytes, signature) = self.work.external_oci_reply_bytes(&request).await?;
        let current = self.work.acknowledged_binding_snapshot(binding_id)?;
        ensure!(current.revision()? == snapshot.revision()?
            && runtime.profile(&current, aos_hub_core::clock::now_unix_secs())?.digest()?
                == request.original.profile_digest,
            "external OCI readback current authority changed");
        ExternalOciReply::authenticate_verified(&request, &runtime.guard, &signature, &bytes)
    }

    pub(super) async fn prepare_external_stage(&self, selected: &ExternalOciStagePreparation) -> Result<ExternalOciStagePermit> {
        selected.validate()?;
        let runtime = self.work.external_oci.as_ref()
            .context("external OCI workflow acceptance is not independently installed")?;
        let binding = self.db.binding(selected.writer.binding_id.get()).await?
            .context("external OCI binding disappeared")?;
        self.work.ensure_remote_binding_snapshot(&self.db, &binding).await?;
        let snapshot = self.work.acknowledged_binding_snapshot(binding.id)?;
        let profile = runtime.profile(&snapshot, aos_hub_core::clock::now_unix_secs())?;
        let original = ExternalOciOriginal {
            version: 1, deployment_id: self.work.deployment_id.clone(),
            upload: OciUploadOriginal::from_record(&selected.upload)?,
            actor: selected.actor.clone(), writer: selected.writer.clone(),
            binding_spec_revision: snapshot.binding_spec_revision()?, profile_digest: profile.digest()?,
            scope: StorageAuthorityObjectScope {
                guard_namespace_id: profile.write_cohort.authority.guard_namespace_id.clone(),
                physical_authority_id: profile.write_cohort.authority.authority_id.clone(),
                full_key: aos_hub_core::keymap::r2_key(&aos_hub_core::keymap::r2_key(
                    &selected.writer.binding_prefix, &selected.writer.placement_prefix), &selected.staging_key),
            },
            object: OciObjectOriginal::Chunk { ordinal: selected.ordinal, offset: selected.offset,
                maximum_bytes: selected.maximum_bytes, prior_sha256: selected.prior_sha256.clone(),
                expected: selected.expected.clone(),
            },
        };
        original.validate()?;
        let request = phase(runtime, &snapshot.revision()?, original, selected.actor.clone(), OciControl::RecoverOriginal)?;
        let reply = self.work.exchange_external_oci(&request).await?;
        let original = reply.retained_original.unwrap_or(request.original);
        let snapshot = self.work.acknowledged_binding_snapshot(binding.id)?;
        let current_profile = runtime.profile(&snapshot, aos_hub_core::clock::now_unix_secs())?;
        ensure!(current_profile.digest()? == original.profile_digest,
            "external OCI profile changed during original selection");
        let current_binding = self.db.binding(binding.id).await?.context("external OCI binding disappeared")?;
        let current_placement = self.db.surface_placement(selected.writer.placement_id.get()).await?
            .context("external OCI placement disappeared")?;
        let current_upload = self.db.oci_upload(&selected.upload.id, &selected.upload.writer_id,
            &selected.upload.token_id, aos_hub_core::clock::now_unix_secs()).await?
            .context("external OCI upload expired during original selection")?;
        ensure!(current_binding.resource_version == binding.resource_version
            && current_binding.stable_id == binding.stable_id
            && current_binding.kind == binding.kind && current_upload == selected.upload
            && current_placement.resource_version == selected.writer.placement_resource_version.get()
            && current_placement.write_spec_version == selected.writer.write_spec_version.get()
            && current_placement.effective_write_enabled,
            "external OCI SQL reservation changed during original selection");
        selected.check_current_writer(&self.db).await?;
        let request = phase(runtime, &snapshot.revision()?, original, selected.actor.clone(), OciControl::Stage)?;
        let (_, signature) = request.sign(&self.work.key, &self.work.deployment_id, latest(runtime)?)?;
        let permit = ExternalOciStagePermit { request, signature };
        permit.validate_shape()?;
        Ok(permit)
    }
}

fn latest(runtime: &ExternalOciRuntime) -> Result<i64> {
    aos_hub_core::clock::now_unix_secs().checked_add(runtime.uncertainty())
        .context("external OCI conservative clock overflow")
}

fn phase(runtime: &ExternalOciRuntime, snapshot: &str, original: ExternalOciOriginal,
    actor: aos_hub_core::storage_authority::external_object::oci::OciActorOriginal,
    operation: OciControl) -> Result<ExternalOciRequest> {
    let now = aos_hub_core::clock::now_unix_secs();
    let expires = now.checked_add(30).context("external OCI phase deadline overflow")?
        .min(actor.expires_at.get()).min(original.upload.expires_at.get());
    let request = ExternalOciRequest::new(original, snapshot.into(), actor, now, expires,
        format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple()), operation)?;
    request.validate(runtime.deployment(), latest(runtime)?)?;
    Ok(request)
}

impl HybridSurfaceFetch {
    pub(super) async fn read_external_source(&self, path: &str,
        expected: &aos_hub_core::storage_authority::external_object::oci::OciBytes,
        upload_id: Option<&str>,
    ) -> Result<aos_hub_core::storage_authority::external_object::oci::source::OciSourceReply> {
        use aos_hub_core::{db::SurfaceTarget, storage_authority::external_object::oci::{
            OciWriterOriginal, source::*}};
        let runtime = self.work.external_oci.as_ref().context("external OCI runtime absent")?;
        let registry_id = self.placement.registry_id.context("OCI source registry absent")?;
        let revision = self.db.placement_publication_write_revision(self.placement.id).await?
            .context("OCI source write revision absent")?;
        let authority = self.db.surface_write_authority(SurfaceTarget::Registry(registry_id)).await?
            .context("OCI source writer authority absent")?;
        let writer = OciWriterOriginal::from_registry_records(registry_id, &self.placement,
            &self.binding, &revision, &authority)?;
        self.work.ensure_remote_binding_snapshot(&self.db, &self.binding).await?;
        let snapshot = self.work.acknowledged_binding_snapshot(self.binding.id)?;
        let profile = runtime.profile(&snapshot, aos_hub_core::clock::now_unix_secs())?;
        let issued_at = aos_hub_core::clock::now_unix_secs();
        let lookup = OciSourceLookup {
            version: 1, deployment_id: self.work.deployment_id.clone(), issuer: runtime.issuer(),
            clock_uncertainty_seconds: u64::try_from(runtime.uncertainty())?,
            scope: StorageAuthorityObjectScope {
                guard_namespace_id: profile.write_cohort.authority.guard_namespace_id.clone(),
                physical_authority_id: profile.write_cohort.authority.authority_id.clone(),
                full_key: aos_hub_core::keymap::r2_key(&writer.binding_prefix,
                    &aos_hub_core::keymap::r2_key(&writer.placement_prefix, path)),
            },
            writer, binding_spec_revision: snapshot.binding_spec_revision()?,
            profile_digest: profile.digest()?, expected: expected.clone(),
            upload_id: upload_id.map(str::to_owned), range: None, issued_at,
            expires_at: issued_at.checked_add(30).context("OCI source deadline overflow")?,
            nonce: format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple()),
        };
        #[cfg(all(test, feature = "required-live-dialects"))]
        runtime.check_controlled_writer(&lookup.writer.placement_prefix, latest(runtime)?)?;
        let _permit = self.work.in_flight.acquire().await?;
        lookup.validate(&self.work.deployment_id, latest(runtime)?)?;
        let (body, signature) = lookup.sign(&runtime.guard)?;
        let remaining = lookup.expires_at.checked_sub(latest(runtime)?)
            .filter(|seconds| *seconds > 0).context("OCI source lookup expired")?;
        let operation = async {
            let response = self.work.http.post(format!("{}{}", self.work.executor_origin()?, OCI_SOURCE_PATH))
                .header(OCI_SOURCE_SIGNATURE_HEADER, signature).header("content-type", "application/json")
                .body(body).timeout(std::time::Duration::from_secs(remaining as u64)).send().await
                .map_err(|_| anyhow::anyhow!("OCI source lookup transport failed"))?;
            ensure!(response.status() == reqwest::StatusCode::OK, "OCI source is unavailable or unsettled");
            let signature = response.headers().get(OCI_SOURCE_SIGNATURE_HEADER)
                .context("OCI source reply signature absent")?.to_str()?.to_owned();
            let body = read_bounded_response(response, MAX_OCI_SOURCE_BYTES).await?;
            OciSourceReply::authenticate(&lookup, &runtime.guard, &signature, &body, latest(runtime)?)
        };
        let reply = tokio::time::timeout(std::time::Duration::from_secs(remaining as u64), operation)
            .await.context("OCI source original deadline expired")??;
        let current = self.db.surface_placement(self.placement.id).await?.context("OCI source placement lost")?;
        let binding = self.db.binding(self.binding.id).await?.context("OCI source binding lost")?;
        let revision = self.db.placement_publication_write_revision(current.id).await?.context("OCI source revision lost")?;
        let authority = self.db.surface_write_authority(SurfaceTarget::Registry(registry_id)).await?.context("OCI source authority lost")?;
        let current_writer = OciWriterOriginal::from_registry_records(registry_id, &current, &binding, &revision, &authority)?;
        let current_snapshot = self.work.acknowledged_binding_snapshot(binding.id)?;
        ensure!(current_writer == lookup.writer && current_snapshot.binding_spec_revision()? == lookup.binding_spec_revision
            && runtime.profile(&current_snapshot, aos_hub_core::clock::now_unix_secs())?.digest()? == lookup.profile_digest,
            "OCI source current authority changed during lookup");
        lookup.validate(&self.work.deployment_id, latest(runtime)?)?;
        Ok(reply)
    }
}

mod materialization;
mod cleanup;

#[cfg(all(test, feature = "required-live-dialects"))]
mod tests;
