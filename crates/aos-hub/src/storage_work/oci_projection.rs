//! Independent storage-side OCI document metadata for the Hybrid facade.

use anyhow::{Context as _, Result, ensure};
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
        if !self.binding.is_instance_default && matches!(self.binding.kind.as_str(), "s3" | "r2") {
            return self
                .read_external_oci_projection(path, descriptor, admission)
                .await;
        }
        ensure!(
            self.binding.is_instance_default && self.binding.kind == "deployment_r2",
            "OCI document projection requires an admitted managed binding"
        );
        let origin = self.work.executor_origin()?;
        let (profile_digest, issuer, uncertainty) = self.work.oci_projection_identity(&origin)?;
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
            source: aos_hub_core::oci_projection::OciProjectionSource::Managed,
            deployment_id: self.work.deployment_id.clone(),
            issuer,
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
        let (proof, observation) = self
            .work
            .exchange_oci_projection_observed(&origin, key, &lookup)
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
                && self.work.oci_projection_identity(&origin)?.0 == profile_digest,
            "OCI writer or provider qualification changed during readback"
        );
        if let Some(observation) = observation {
            let facts = (|| {
                let mut commitments = std::collections::BTreeMap::from([
                    (
                        "placementStateSha256",
                        super::telemetry::context::fact_digest(&(
                            placement.id,
                            placement.resource_version,
                            placement.binding_id,
                            &placement.prefix,
                        ))?,
                    ),
                    (
                        "bindingStateSha256",
                        super::telemetry::context::fact_digest(&(
                            binding.id,
                            binding.resource_version,
                            &binding.stable_id,
                            &binding.kind,
                        ))?,
                    ),
                    (
                        "lookupSha256",
                        super::telemetry::context::fact_digest(&lookup)?,
                    ),
                    (
                        "storedObjectSha256",
                        super::telemetry::context::fact_digest(proof.object())?,
                    ),
                    (
                        "descriptorSha256",
                        super::telemetry::context::fact_digest(&lookup.descriptor)?,
                    ),
                    ("profileDigest", profile_digest.clone()),
                ]);
                if let Some(accepted) = &self.work.oci_sdk_emulation {
                    let effect = accepted.document_effect().ok()?;
                    commitments.insert("purposeEvidenceSha256", effect.acceptance_digest.clone());
                    commitments.insert(
                        "documentEffectSha256",
                        super::telemetry::context::fact_digest(&effect)?,
                    );
                }
                Some(commitments)
            })();
            if let Some(commitments) = facts {
                observation.after_sql("managed_oci_current_sql", commitments);
            }
        }
        Ok(Some(proof))
    }
}

impl HybridSurfaceFetch {
    async fn read_external_oci_projection(
        &self,
        path: &str,
        descriptor: &Descriptor,
        admission: Option<&HybridOciManifestAdmission>,
    ) -> Result<Option<VerifiedOciProjection>> {
        use aos_hub_core::{
            oci_projection::OciProjectionSource, storage_authority::external_object::oci::OciBytes,
        };
        let private = path.starts_with("oci/uploads/");
        let upload_id = if private {
            Some(
                admission
                    .context("private OCI document lacks real upload admission")?
                    .upload_id
                    .as_str(),
            )
        } else {
            None
        };
        let source = self
            .read_external_source(
                path,
                &OciBytes {
                    sha256: descriptor.digest.encoded(),
                    size: descriptor.size,
                },
                upload_id,
            )
            .await?;
        let runtime = self
            .work
            .external_oci
            .as_ref()
            .context("external OCI runtime absent")?;
        let issued_at = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        let lookup = OciProjectionLookup {
            version: 1,
            deployment_id: self.work.deployment_id.clone(),
            issuer: runtime.issuer(),
            clock_uncertainty_seconds: u64::try_from(runtime.uncertainty())?,
            protected_profile_digest: source.original.profile_digest.clone(),
            key: source.original.scope.full_key.clone(),
            descriptor: descriptor.clone(),
            admission: admission.cloned(),
            source: OciProjectionSource::External {
                original: source.original,
                closed: source.closed,
            },
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
        let _capacity = self.work.in_flight.acquire().await?;
        let origin = self.work.executor_origin()?;
        let (proof, observation) = self
            .work
            .exchange_oci_projection_observed(&origin, &runtime.guard, &lookup)
            .await?;
        let placement = self
            .db
            .surface_placement(self.placement.id)
            .await?
            .context("OCI placement lost")?;
        let binding = self
            .db
            .binding(self.binding.id)
            .await?
            .context("OCI binding lost")?;
        let snapshot = self.work.acknowledged_binding_snapshot(binding.id)?;
        ensure!(
            placement.resource_version == self.placement.resource_version
                && placement.binding_id == binding.id
                && placement.prefix == self.placement.prefix
                && binding.resource_version == self.binding.resource_version
                && binding.stable_id == self.binding.stable_id
                && binding.kind == self.binding.kind
                && runtime
                    .profile(&snapshot, aos_hub_core::clock::now_unix_secs())?
                    .digest()?
                    == lookup.protected_profile_digest,
            "external OCI document current authority changed"
        );
        super::external_oci::observation::checked(
            observation,
            "external_oci_projection_writer_checked",
            &[
                (
                    "placementStateSha256",
                    super::external_oci::observation::digest(&(
                        placement.id,
                        placement.resource_version,
                        placement.binding_id,
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
                    )),
                ),
                (
                    "lookupSha256",
                    super::external_oci::observation::digest(&lookup),
                ),
                (
                    "storedObjectSha256",
                    super::external_oci::observation::digest(proof.object()),
                ),
                (
                    "descriptorSha256",
                    super::external_oci::observation::digest(&lookup.descriptor),
                ),
                (
                    "profileDigest",
                    Some(lookup.protected_profile_digest.clone()),
                ),
            ],
        );
        Ok(Some(proof))
    }
}

impl super::RemoteStorageWorkClient {
    fn oci_projection_identity(&self, origin: &str) -> Result<(String, MirrorGuardIssuer, u64)> {
        if let Some(acceptance) = &self.oci_sdk_emulation {
            return acceptance.projection_identity(&self.deployment_id, origin);
        }
        let digest = self.mirror_managed_profile_digest()?;
        let profiles = self
            .mirror_profiles
            .as_ref()
            .context("OCI guard issuer is not independently configured")?;
        let (source_digest, script_version, uncertainty) =
            profiles.retained_guard_issuer(&self.deployment_id, origin, &digest)?;
        Ok((
            digest,
            MirrorGuardIssuer {
                source_digest,
                script_version,
            },
            uncertainty,
        ))
    }
}
