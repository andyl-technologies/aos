//! Bounded manifest admission and visibility barriers for managed mirrors.
//!
//! Private verification supplies the actual encoded commitments. The manifest
//! is sealed before any destination promotion, and pointer eligibility remains
//! separate from the immutable publication phase.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::db::{
    Database, NewRegistryPublication, RegistryPublicationManifestObject, RegistryPublicationRecord,
};
use sha2::{Digest as _, Sha256};

use super::PreparedObject;

pub(super) async fn admit(
    db: &Database,
    registry_id: i64,
    commit: &str,
    refs_digest: &str,
    objects: &[PreparedObject],
) -> Result<RegistryPublicationRecord> {
    ensure!(
        !objects.is_empty(),
        "mirror publication has no verified objects"
    );
    let placement_id = objects[0].original.placement_id;
    let manifest = objects
        .iter()
        .map(|object| {
            let verified = &object.verified;
            ensure!(
                object.original.registry_id == registry_id
                    && object.original.placement_id == placement_id,
                "mirror manifest crosses its selected writer"
            );
            ensure!(
                object.original.path.len() <= 512,
                "mirror catalogue paths must fit 512 UTF-8 bytes"
            );
            Ok(RegistryPublicationManifestObject {
                object_key: object.original.path.clone(),
                expected_hash: verified.sha256.clone(),
                expected_size: i64::try_from(verified.object.size)?,
                object_kind: if aos_hub_core::keymap::is_mutable_path(&object.original.path) {
                    "mutable_pointer"
                } else {
                    "immutable"
                }
                .into(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest_digest = digest_objects(&manifest)?;
    let state = db.registry_publication_state(registry_id).await?;
    let parent = state.and_then(|state| state.current_publication_id);
    // The generation commits bytes and the selected writer, while retry leases
    // and per-object scheduler attempts contribute no fresh operation identity.
    let generation = hex::encode(Sha256::digest(serde_json::to_vec(&(
        "aos.hub.mirror-publication.v1",
        registry_id,
        placement_id,
        objects[0].original.write_spec_version,
        objects[0].original.binding_resource_version,
        &objects[0].original.placement_prefix,
        &manifest_digest,
        refs_digest,
        commit,
        &parent,
    ))?));
    let publication = match db
        .registry_publication_by_generation(registry_id, &generation)
        .await?
    {
        Some(publication) if publication.state == "failed" => {
            db.retry_failed_registry_publication(&publication.publication_id, now())
                .await?
        }
        Some(publication) => publication,
        None => {
            db.create_registry_publication(&NewRegistryPublication {
                publication_id: uuid::Uuid::new_v4().simple().to_string(),
                registry_id,
                generation,
                manifest_digest: manifest_digest.clone(),
                refs_digest: refs_digest.into(),
                default_commit: Some(commit.into()),
                parent_publication_id: parent,
            })
            .await?
        }
    };
    ensure!(
        publication.manifest_digest == manifest_digest
            && publication.refs_digest == refs_digest
            && publication.default_commit.as_deref() == Some(commit),
        "mirror publication changed its immutable manifest"
    );
    if publication.state != "preparing" {
        ensure!(
            matches!(publication.state.as_str(), "writing_pointers" | "ready"),
            "mirror publication cannot be resumed in this state"
        );
        return Ok(publication);
    }

    let session = db
        .begin_registry_publication_manifest_session(
            &publication.publication_id,
            registry_id,
            &manifest_digest,
            i64::try_from(manifest.len())?,
            &uuid::Uuid::new_v4().simple().to_string(),
            now(),
        )
        .await?;
    for (index, chunk) in manifest.chunks(256).enumerate() {
        db.append_registry_publication_manifest_chunk(
            &publication.publication_id,
            &session.lease_token,
            i64::try_from(index)?,
            &digest_objects(chunk)?,
            chunk,
            now(),
        )
        .await?;
    }
    db.seal_registry_publication_manifest_session(
        &publication.publication_id,
        &session.lease_token,
        &[placement_id],
        now(),
    )
    .await?;
    Ok(publication)
}

pub(super) async fn begin_pointers(
    db: &Database,
    publication: &RegistryPublicationRecord,
    placement_id: i64,
) -> Result<()> {
    if publication.state == "ready" {
        return Ok(());
    }
    let current = db
        .registry_publication(&publication.publication_id)
        .await?
        .context("mirror publication disappeared")?;
    if current.state == "preparing" {
        ensure!(
            db.registry_publication_class_is_complete(&publication.publication_id, "immutable",)
                .await?,
            "mirror immutable publication barrier is incomplete"
        );
        ensure!(
            db.advance_registry_publication(
                &publication.publication_id,
                "preparing",
                "writing_pointers",
                now(),
            )
            .await?,
            "mirror pointer phase changed concurrently"
        );
    }
    let placement = db
        .surface_placement(placement_id)
        .await?
        .context("mirror writer disappeared")?;
    db.begin_registry_pointer_advance(
        &publication.publication_id,
        placement_id,
        placement.resource_version,
        placement
            .watermark_resource_version
            .context("mirror watermark missing")?,
        now(),
    )
    .await?;
    Ok(())
}

pub(super) async fn finish(
    db: &Database,
    publication: &RegistryPublicationRecord,
    placement_id: i64,
) -> Result<()> {
    let current = db
        .registry_publication(&publication.publication_id)
        .await?
        .context("mirror publication disappeared")?;
    if current.state != "ready" {
        let placement = db
            .surface_placement(placement_id)
            .await?
            .context("mirror writer disappeared")?;
        db.finalize_registry_pointer_advance(
            &publication.publication_id,
            placement_id,
            placement.resource_version,
            placement
                .watermark_resource_version
                .context("mirror watermark missing")?,
            now(),
        )
        .await?;
        ensure!(
            db.advance_registry_publication(
                &publication.publication_id,
                "writing_pointers",
                "ready",
                now(),
            )
            .await?,
            "mirror publication readiness changed concurrently"
        );
    }
    let state = db
        .registry_publication_state(publication.registry_id)
        .await?
        .context("mirror publication state disappeared")?;
    db.set_current_registry_publication(
        publication.registry_id,
        &publication.publication_id,
        Some(state.resource_version),
    )
    .await?;
    Ok(())
}

fn digest_objects(objects: &[RegistryPublicationManifestObject]) -> Result<String> {
    let fields: Vec<_> = objects
        .iter()
        .map(|object| {
            (
                &object.object_key,
                &object.expected_hash,
                object.expected_size,
                &object.object_kind,
            )
        })
        .collect();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&fields)?)))
}

fn now() -> i64 {
    aos_hub_core::clock::now_unix_secs()
}
