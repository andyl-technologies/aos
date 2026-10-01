//! Records measured development-origin bytes through the publication state machine.
//!
//! Indexing verifies signed metadata, but does not establish delivery evidence for
//! every machine object. Invisible admission precedes indexing; exact measured
//! presence and accounting follow successful verification before serving begins.
//! The never-visible bootstrap declaration is failed during normal indexing,
//! then reopened under its retained parent only after verification succeeds.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};

use crate::db::{
    Database, NewRegistryPublication, RegistryPublicationManifestObject,
    SetRegistryPublicationPlacement, SurfaceTarget,
};
use crate::fetch::{LocalFsFetch, SurfaceFetch};
use aos_registry_surface::keymap;

/// Holds the exact invisible manifest admitted before inventory indexing.
pub(super) struct PreparedPublication {
    input: NewRegistryPublication,
    inventory: Vec<(String, String, i64)>,
    etags: BTreeMap<String, String>,
}

/// Admits fresh measured seed objects without publishing or charging them.
///
/// The caller owns an isolated bootstrap: serving and background writers must
/// not start until signature verification and final publication both succeed.
/// Existing objects retain their original accounting eligibility checks.
///
/// # Errors
///
/// Returns an error for invalid measured metadata, unknown existing accounting
/// origins, conflicting admission, or failed storage-version observation.
pub(super) async fn prepare(
    db: &Database,
    registry_id: i64,
    root: &Path,
    image_snapshots: &std::sync::Arc<crate::image_snapshot::ImageSnapshotStore>,
) -> Result<PreparedPublication> {
    let mut inventory = Vec::new();
    measure_tree(root, root, &mut inventory)?;
    inventory.sort();
    let manifest_digest = hex::encode(Sha256::digest(serde_json::to_vec(&inventory)?));
    let refs_digest = inventory
        .iter()
        .find(|(key, _, _)| key == "info/refs")
        .map(|(_, hash, _)| hash.clone())
        .context("seed has no refs snapshot")?;
    let refs = aos_registry_surface::refs::parse_info_refs(&std::fs::read_to_string(
        root.join("info/refs"),
    )?)?;
    let branch =
        aos_registry_surface::refs::parse_head(&std::fs::read_to_string(root.join("HEAD"))?);
    let commit = branch
        .as_ref()
        .and_then(|branch| refs.branches.get(branch))
        .or_else(|| refs.branches.values().next())
        .context("seed surface advertises no branches")?;
    let input = NewRegistryPublication {
        publication_id: format!("dev-seed-{registry_id}"),
        registry_id,
        generation: format!("dev-seed-{manifest_digest}"),
        manifest_digest,
        refs_digest,
        default_commit: Some(commit.to_hex()),
        parent_publication_id: None,
    };
    db.create_registry_publication(&input).await?;

    let fetch =
        LocalFsFetch::new(root).with_image_snapshots(std::sync::Arc::clone(image_snapshots));
    let mut etags = BTreeMap::new();
    for (key, hash, size) in &inventory {
        let kind = if keymap::is_mutable_path(key) {
            "mutable_pointer"
        } else {
            "immutable"
        };
        let surface = SurfaceTarget::Registry(registry_id);
        if let Some(object) = db.surface_object_named(surface, key).await? {
            ensure!(
                object.object_kind == kind
                    && object.content_hash.as_deref() == Some(hash)
                    && object.size == Some(*size),
                "seed object inventory disagrees for {key}"
            );
            db.verified_registry_object_accounting_eligibility(object.id)
                .await?;
        }
        db.admit_registry_publication_manifest_objects(
            registry_id,
            &input.publication_id,
            &[RegistryPublicationManifestObject {
                object_key: key.clone(),
                object_kind: kind.into(),
                expected_hash: hash.clone(),
                expected_size: *size,
            }],
        )
        .await?;
        let etag = fetch
            .inventory_strong_etag(key)
            .await?
            .context("seed object has no strong storage version")?;
        etags.insert(key.clone(), etag);
    }
    Ok(PreparedPublication {
        input,
        inventory,
        etags,
    })
}

/// Verifies the isolated seed while its retained declaration is inactive.
///
/// Normal index transactions reject every active publication. Bootstrap has no
/// serving process or competing writer: failing its never-visible declaration
/// retains fresh placeholders without claiming positive delivery. The normal
/// indexer can then verify the complete surface without bypassing that guard.
///
/// # Errors
///
/// Returns an error if the original cannot become inactive, its registry is
/// absent, or canonical signed indexing fails or defers.
pub(super) async fn verify_index(
    db: &Database,
    placement_id: i64,
    root: &Path,
    image_snapshots: &std::sync::Arc<crate::image_snapshot::ImageSnapshotStore>,
    prepared: &PreparedPublication,
) -> Result<()> {
    db.fail_registry_publication(
        &prepared.input.publication_id,
        aos_hub_core::clock::now_unix_secs(),
    )
    .await?;
    let registry = db
        .registry_by_id(prepared.input.registry_id)
        .await?
        .context("seeded registry disappeared before verification")?;
    let fetch =
        LocalFsFetch::new(root).with_image_snapshots(std::sync::Arc::clone(image_snapshots));
    let outcome =
        crate::indexer::index_and_record_from_placement(db, &fetch, &registry, Some(placement_id))
            .await?;
    ensure!(!outcome.pending, "seed index verification was deferred");
    Ok(())
}

/// Records exact presence and charges only after the signed seed index is fresh.
///
/// # Errors
///
/// Returns an error for an incomplete or different index, changed measured
/// objects, accounting refusal, or a failed publication transition.
pub(super) async fn record(
    db: &Database,
    placement_id: i64,
    root: &Path,
    image_snapshots: &std::sync::Arc<crate::image_snapshot::ImageSnapshotStore>,
    prepared: &PreparedPublication,
) -> Result<()> {
    let registry_id = prepared.input.registry_id;
    let publication_id = &prepared.input.publication_id;
    let index = db
        .index_status(registry_id)
        .await?
        .context("seed index is missing")?;
    ensure!(
        index.state == "fresh"
            && index.last_indexed_commit == prepared.input.default_commit
            && db.refs_digest(registry_id).await?.as_deref()
                == Some(prepared.input.refs_digest.as_str()),
        "seed index is incomplete or differs from the prepared publication"
    );
    let publication = db
        .registry_publication(publication_id)
        .await?
        .context("prepared seed publication disappeared")?;
    ensure!(
        publication.state == "failed"
            && publication.registry_id == registry_id
            && publication.generation == prepared.input.generation
            && publication.manifest_digest == prepared.input.manifest_digest
            && publication.refs_digest == prepared.input.refs_digest
            && publication.default_commit == prepared.input.default_commit,
        "prepared seed publication changed during verification"
    );
    let fetch =
        LocalFsFetch::new(root).with_image_snapshots(std::sync::Arc::clone(image_snapshots));
    // Check every measured version before the first positive presence/charge.
    for (key, expected) in &prepared.etags {
        ensure!(
            fetch.inventory_strong_etag(key).await?.as_ref() == Some(expected),
            "seed object changed during verification"
        );
    }
    let now = aos_hub_core::clock::now_unix_secs();
    // Reopen only the exact, verified, never-visible original. The existing
    // parent CAS preserves normal publication authority during this transition.
    db.retry_failed_registry_publication(publication_id, now)
        .await?;
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: publication_id.clone(),
        placement_id,
        required: true,
        state: "preparing".into(),
        observed_at: now,
    })
    .await?;
    for (key, hash, size) in &prepared.inventory {
        let object = db
            .surface_object_named(SurfaceTarget::Registry(registry_id), key)
            .await?
            .context("seed publication placeholder disappeared")?;
        let etag = prepared.etags.get(key).context("seed version is missing")?;
        db.record_registry_publication_object_presence(
            publication_id,
            object.id,
            placement_id,
            hash,
            *size,
            Some(etag),
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

#[cfg(test)]
mod tests;
