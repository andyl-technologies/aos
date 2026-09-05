//! Records measured development-origin bytes through the publication state machine.
//!
//! Indexing verifies signed metadata, but does not establish delivery evidence for
//! every machine object. Seeding must establish both before serving documentation.

use std::io::Read;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};

use crate::db::{
    Database, NewRegistryPublication, SetRegistryPublicationObject,
    SetRegistryPublicationPlacement, SetSurfaceObject, SurfaceTarget,
};
use crate::fetch::{LocalFsFetch, SurfaceFetch};
use aos_registry_surface::keymap;

/// Records a ready publication for an already verified, isolated seed origin.
///
/// # Errors
///
/// Returns an error if file measurement, inventory consistency, or a publication
/// transition fails. The caller must finish seeding before starting background writers.
pub(super) async fn record(
    db: &Database,
    registry_id: i64,
    placement_id: i64,
    root: &Path,
    image_snapshots: &std::sync::Arc<crate::image_snapshot::ImageSnapshotStore>,
) -> Result<()> {
    let mut inventory = Vec::new();
    measure_tree(root, root, &mut inventory)?;
    inventory.sort();
    let manifest_digest = hex::encode(Sha256::digest(serde_json::to_vec(&inventory)?));
    let refs_digest = inventory
        .iter()
        .find(|(key, _, _)| key == "info/refs")
        .map(|(_, hash, _)| hash.clone())
        .context("seed has no refs snapshot")?;
    let index = db
        .index_status(registry_id)
        .await?
        .context("seed index is missing")?;
    ensure!(index.state == "fresh", "seed index is not verified");
    let publication_id = format!("dev-seed-{registry_id}");
    let now = aos_hub_core::clock::now_unix_secs();
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.clone(),
        registry_id,
        generation: format!("dev-seed-{}", index.generation),
        manifest_digest,
        refs_digest,
        default_commit: index.last_indexed_commit,
        parent_publication_id: None,
    })
    .await?;
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: publication_id.clone(),
        placement_id,
        required: true,
        state: "preparing".into(),
        observed_at: now,
    })
    .await?;

    let fetch =
        LocalFsFetch::new(root).with_image_snapshots(std::sync::Arc::clone(image_snapshots));
    for (key, hash, size) in inventory {
        let etag = fetch
            .inventory_strong_etag(&key)
            .await?
            .context("seed object has no strong storage version")?;
        let mutable = keymap::is_mutable_path(&key);
        let kind = if mutable {
            "mutable_pointer"
        } else {
            "immutable"
        };
        let surface = SurfaceTarget::Registry(registry_id);
        let object = match db.surface_object_named(surface, &key).await? {
            Some(object) => {
                ensure!(
                    object.object_kind == kind
                        && object.content_hash.as_deref() == Some(&hash)
                        && object.size == Some(size),
                    "seed object inventory disagrees for {key}"
                );
                object
            }
            None => {
                db.create_surface_object(&SetSurfaceObject {
                    surface,
                    object_key: key,
                    content_hash: Some(hash.clone()),
                    size: Some(size),
                    object_kind: kind.into(),
                    mutable_publication_id: mutable.then(|| publication_id.clone()),
                })
                .await?
            }
        };
        db.set_registry_publication_object(&SetRegistryPublicationObject {
            publication_id: publication_id.clone(),
            surface_object_id: object.id,
            object_kind: kind.into(),
            expected_hash: hash.clone(),
            expected_size: size,
        })
        .await?;
        db.record_registry_publication_object_presence(
            &publication_id,
            object.id,
            placement_id,
            &hash,
            size,
            Some(&etag),
            now,
        )
        .await?;
    }

    ensure!(
        db.advance_registry_publication(&publication_id, "preparing", "writing_pointers", now)
            .await?,
        "seed publication could not enter pointer phase"
    );
    let placement = db
        .surface_placement(placement_id)
        .await?
        .context("seed placement is missing")?;
    let placement = db
        .begin_registry_pointer_advance(
            &publication_id,
            placement_id,
            placement.resource_version,
            placement
                .watermark_resource_version
                .context("seed watermark is missing")?,
            now,
        )
        .await?;
    db.finalize_registry_pointer_advance(
        &publication_id,
        placement_id,
        placement.resource_version,
        placement
            .watermark_resource_version
            .context("seed watermark disappeared")?,
        now,
    )
    .await?;
    db.promote_registry_publication_mutable_objects(&publication_id)
        .await?;
    ensure!(
        db.advance_registry_publication(&publication_id, "writing_pointers", "ready", now)
            .await?,
        "seed publication could not become ready"
    );
    let state = db
        .registry_publication_state(registry_id)
        .await?
        .context("seed publication state is missing")?;
    db.set_current_registry_publication(registry_id, &publication_id, Some(state.resource_version))
        .await?;
    Ok(())
}

/// Hashes file bodies with bounded memory, including large producer image fixtures.
fn measure_tree(
    root: &Path,
    directory: &Path,
    inventory: &mut Vec<(String, String, i64)>,
) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            measure_tree(root, &path, inventory)?;
        } else {
            ensure!(kind.is_file(), "seed surface contains a nonregular file");
            let key = path
                .strip_prefix(root)?
                .to_str()
                .context("seed object key is not UTF-8")?
                .to_owned();
            if !keymap::is_machine_path(&key) {
                continue;
            }
            let mut file = std::fs::File::open(path)?;
            let mut hash = Sha256::new();
            let mut size = 0_i64;
            let mut buffer = [0_u8; 65536];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hash.update(&buffer[..read]);
                size = size
                    .checked_add(i64::try_from(read)?)
                    .context("seed object is too large")?;
            }
            inventory.push((key, hex::encode(hash.finalize()), size));
        }
    }
    Ok(())
}
