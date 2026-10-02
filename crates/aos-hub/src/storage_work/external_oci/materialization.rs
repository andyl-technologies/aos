//! Real OCI claim orchestration with bounded source pages and part advances.
//!
//! Only independently authenticated physical receipts report closure. Every
//! await rechecks the original current SQL claim and actor before a new phase;
//! transport ambiguity preserves the first guard original and unknown effect.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    fetch::SurfaceObjectEvidence,
    storage_authority::{
        control::StorageAuthorityObjectScope,
        external_object::oci::{
            control::OciControl, materialization::ExternalOciMaterialization, ExternalOciOriginal,
            OciBytes, OciObjectOriginal, OciProviderIncarnation, OciSourceManifest,
            OciSourceOriginal, OciUploadOriginal,
        },
    },
};
use futures_util::{stream, StreamExt as _, TryStreamExt as _};

use super::{phase, HybridSurfaceFetch, HybridSurfaceWrites};

impl HybridSurfaceWrites {
    pub(in crate::storage_work) async fn compose_external_oci(
        &self,
        selected: &ExternalOciMaterialization,
    ) -> Result<SurfaceObjectEvidence> {
        selected.check_current(&self.db).await?;
        let runtime = self
            .work
            .external_oci
            .as_ref()
            .context("external OCI runtime absent")?;
        let placement = self
            .db
            .surface_placement(selected.writer.placement_id.get())
            .await?
            .context("external OCI target disappeared")?;
        let binding = self
            .db
            .binding(selected.writer.binding_id.get())
            .await?
            .context("external OCI binding disappeared")?;
        ensure!(
            selected.chunks.is_empty()
                || (selected.upload.staging_placement_id == Some(placement.id)
                    && selected.upload.staging_binding_id == Some(binding.id)),
            "external OCI composition crosses its actual frozen private writer"
        );
        let fetch = HybridSurfaceFetch {
            db: self.db.clone(),
            placement,
            binding,
            work: self.work.clone(),
        };
        let sources: Vec<_> = stream::iter(selected.chunks.iter().cloned())
            .map(|chunk| {
                let fetch = &fetch;
                async move {
                    let reply = fetch
                        .read_external_source(
                            &chunk.staging_object_key,
                            &OciBytes {
                                sha256: chunk.digest.encoded(),
                                size: chunk.byte_size,
                            },
                            Some(&selected.upload.id),
                        )
                        .await?;
                    selected.check_current(&self.db).await?;
                    ensure!(
                        reply.original.actor.account == selected.actor.account
                            && reply.original.actor.token_id == selected.actor.token_id,
                        "OCI materialization source belongs to another authenticated actor"
                    );
                    Ok::<_, anyhow::Error>(OciSourceOriginal {
                        key: reply.original.scope.full_key,
                        bytes: reply.closed.bytes,
                        receipt_digest: reply.closed.receipt_digest,
                        etag: reply.closed.etag,
                        incarnation: reply.closed.incarnation,
                    })
                }
            })
            .buffered(4)
            .try_collect()
            .await?;
        let expected = OciBytes {
            sha256: selected.digest.encoded(),
            size: selected.upload.uploaded_size,
        };
        let manifest = OciSourceManifest::from_sources(&sources)?;
        let snapshot = self
            .work
            .acknowledged_binding_snapshot(selected.writer.binding_id.get())?;
        let profile = runtime.profile(&snapshot, aos_hub_core::clock::now_unix_secs())?;
        let original = ExternalOciOriginal {
            version: 1,
            deployment_id: self.work.deployment_id.clone(),
            upload: OciUploadOriginal::from_record(&selected.upload)?,
            actor: selected.actor.clone(),
            writer: selected.writer.clone(),
            binding_spec_revision: snapshot.binding_spec_revision()?,
            profile_digest: profile.digest()?,
            scope: StorageAuthorityObjectScope {
                guard_namespace_id: profile.write_cohort.authority.guard_namespace_id.clone(),
                physical_authority_id: profile.write_cohort.authority.authority_id.clone(),
                full_key: aos_hub_core::keymap::r2_key(
                    &selected.writer.binding_prefix,
                    &aos_hub_core::keymap::r2_key(
                        &selected.writer.placement_prefix,
                        &aos_hub_core::db::oci_blob_object_key(selected.digest),
                    ),
                ),
            },
            object: OciObjectOriginal::Compose {
                expected: expected.clone(),
                sources: manifest,
            },
        };
        selected.check_current(&self.db).await?;
        let request = phase(
            runtime,
            &snapshot.revision()?,
            original,
            selected.actor.clone(),
            OciControl::RecoverOriginal,
        )?;
        let recovered = self.work.exchange_external_oci(&request).await?;
        selected.check_current(&self.db).await?;
        let original = recovered.retained_original.unwrap_or(request.original);
        ensure!(
            recovered.pending_effect_digest.is_none(),
            "OCI materialization original has an unknown effect"
        );
        if let Some(closed) = recovered.closed {
            return evidence(&expected, closed);
        }
        let mut first = 0;
        while first < sources.len() {
            selected.check_current(&self.db).await?;
            let snapshot = self
                .work
                .acknowledged_binding_snapshot(selected.writer.binding_id.get())?;
            ensure!(
                runtime
                    .profile(&snapshot, aos_hub_core::clock::now_unix_secs())?
                    .digest()?
                    == original.profile_digest,
                "OCI materialization profile changed"
            );
            // Source versions and strong ETags have their own bounded lengths.
            // Count alone does not bound a control: fill only while its exact
            // canonical envelope fits the unchanged 64 KiB metadata budget.
            let mut request = phase(
                runtime,
                &snapshot.revision()?,
                original.clone(),
                selected.actor.clone(),
                OciControl::InstallSources {
                    first: u32::try_from(first)?,
                    sources: vec![sources[first].clone()],
                },
            )?;
            let mut end = first + 1;
            while end < sources.len() && end - first < 32 {
                let mut expanded = request.clone();
                expanded.operation = OciControl::InstallSources {
                    first: u32::try_from(first)?,
                    sources: sources[first..=end].to_vec(),
                };
                if serde_json::to_vec(&expanded)?.len()
                    > aos_hub_core::storage_authority::external_object::oci::control::MAX_EXTERNAL_OCI_CONTROL_BYTES {
                    break;
                }
                request = expanded;
                end += 1;
            }
            request.validate(&self.work.deployment_id, super::latest(runtime)?)?;
            let reply = self.work.exchange_external_oci(&request).await?;
            selected.check_current(&self.db).await?;
            ensure!(
                reply.pending_effect_digest.is_none(),
                "OCI source installation is unresolved"
            );
            first = end;
        }
        // Each reply proves positive progress. No timeout, missing reply or HEAD
        // permits replay; the exact same guard original owns subsequent controls.
        let mut prior_parts = 0;
        for _ in 0..257 {
            selected.check_current(&self.db).await?;
            let snapshot = self
                .work
                .acknowledged_binding_snapshot(selected.writer.binding_id.get())?;
            ensure!(
                runtime
                    .profile(&snapshot, aos_hub_core::clock::now_unix_secs())?
                    .digest()?
                    == original.profile_digest,
                "OCI materialization profile changed"
            );
            let request = phase(
                runtime,
                &snapshot.revision()?,
                original.clone(),
                selected.actor.clone(),
                OciControl::Compose { maximum_parts: 8 },
            )?;
            let reply = self.work.exchange_external_oci(&request).await?;
            selected.check_current(&self.db).await?;
            ensure!(
                reply.pending_effect_digest.is_none(),
                "OCI provider effect remains unknown"
            );
            if let Some(closed) = reply.closed {
                return evidence(&expected, closed);
            }
            ensure!(
                reply.next_part > prior_parts,
                "OCI bounded materialization made no positive progress"
            );
            prior_parts = reply.next_part;
        }
        anyhow::bail!("OCI bounded materialization requires exact original recovery")
    }
}

fn evidence(
    expected: &OciBytes,
    closed: aos_hub_core::storage_authority::external_object::oci::reply::OciClosedObject,
) -> Result<SurfaceObjectEvidence> {
    ensure!(
        &closed.bytes == expected,
        "OCI positive destination differs from full claim"
    );
    let provider_version = match closed.incarnation {
        OciProviderIncarnation::Versioned {
            provider_version, ..
        } => Some(provider_version),
        OciProviderIncarnation::Guarded { .. } => None,
    };
    let sha256: [u8; 32] = hex::decode(&closed.bytes.sha256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("OCI physical hash shape differs"))?;
    Ok(SurfaceObjectEvidence {
        sha256,
        size: i64::try_from(closed.bytes.size)?,
        strong_etag: Some(closed.etag),
        provider_version,
    })
}
