//! Committed image publication receipts and their catalog object identities.
//!
//! The receipt binds the committed registry identity to its image objects:
//!
//! ```text
//! image-publication receipt
//!   registry identity and commit
//!   image objects with their committed byte identities
//! ```

use crate::registry::objectstore;
use crate::types::RegistryRootConfig;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::Path;

/// Persists the deterministic transaction marker uploaded after image/catalog
/// immutables and before any release or channel pointer.
pub(in crate::registry_ops) fn persist_image_publication_receipt(
    registry_dir: &Path,
) -> Result<()> {
    let repository = git2::Repository::open(registry_dir).context("opening image registry")?;
    let commit = repository
        .head()
        .context("reading image publication HEAD")?
        .peel_to_commit()
        .context("resolving image publication commit")?;
    let commit_id = commit.id().to_string();
    let tree = commit.tree().context("reading image publication tree")?;
    let objects = committed_image_receipt_objects(&repository, &tree)?;
    if objects.is_empty() {
        return Ok(());
    }
    let registry = committed_registry_identity(&repository, &tree)?;
    let catalog_digest = aos_registry_surface::manifest::image_catalog_digest(
        &registry,
        objects.values().map(|object| {
            (
                object.key.as_str(),
                object.role,
                object.byte_size,
                object.sha256.as_str(),
            )
        }),
    );
    let bytes = serde_json::to_vec(&ImagePublicationReceipt {
        schema_version: 1,
        commit: &commit_id,
        registry: &registry,
        catalog_digest: &catalog_digest,
        objects: objects.into_values().collect(),
    })?;
    let git_dir = objectstore::repo_git_dir(registry_dir)?;
    let destination = git_dir
        .join("aos-static-origin/publication-receipts")
        .join(format!("{commit_id}.json"));
    if let Some(existing) = fs::read(&destination)
        .ok()
        .filter(|existing| existing == &bytes)
    {
        let _ = existing;
        return Ok(());
    }
    if destination.exists() {
        bail!("image publication receipt for commit {commit_id} has conflicting bytes");
    }
    let parent = destination
        .parent()
        .context("publication receipt has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".aos-image-receipt-")
        .tempfile_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(&destination)
        .map_err(|error| error.error)
        .with_context(|| format!("persisting image publication receipt for {commit_id}"))?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImagePublicationReceipt<'a> {
    schema_version: u32,
    commit: &'a str,
    registry: &'a str,
    catalog_digest: &'a str,
    objects: Vec<ImagePublicationReceiptObject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImagePublicationReceiptObject {
    key: String,
    role: &'static str,
    byte_size: u64,
    sha256: String,
}

fn committed_registry_identity(
    repository: &git2::Repository,
    root: &git2::Tree<'_>,
) -> Result<String> {
    let entry = root
        .get_name("registry.toml")
        .context("image publication commit has no registry.toml")?;
    let blob = entry
        .to_object(repository)
        .context("reading committed registry.toml")?
        .peel_to_blob()
        .context("committed registry.toml is not a file")?;
    let content =
        std::str::from_utf8(blob.content()).context("committed registry.toml is not UTF-8")?;
    let root: RegistryRootConfig =
        toml::from_str(content).context("parsing committed registry.toml")?;
    if root.registry.name.is_empty() {
        bail!("committed registry identity is empty");
    }
    Ok(root.registry.name)
}

/// Collects every image object identity from the exact committed package tree.
///
/// A receipt describes the full signed image catalog at that commit, rather
/// than only the formats added by the latest command. This makes a fresh
/// indexer able to validate the transaction marker without reconstructing
/// publication history.
fn committed_image_receipt_objects(
    repository: &git2::Repository,
    root: &git2::Tree<'_>,
) -> Result<BTreeMap<String, ImagePublicationReceiptObject>> {
    let Some(packages_entry) = root.get_name("packages") else {
        return Ok(BTreeMap::new());
    };
    let packages = packages_entry
        .to_object(repository)
        .context("reading committed packages tree")?
        .peel_to_tree()
        .context("committed packages path is not a tree")?;
    let mut objects = BTreeMap::new();
    for bucket_entry in &packages {
        let bucket = bucket_entry
            .to_object(repository)
            .context("reading committed package bucket")?
            .peel_to_tree()
            .context("committed package bucket is not a tree")?;
        for package_entry in &bucket {
            let name = package_entry
                .name()
                .context("committed package has no name")?;
            if !name.ends_with(".toml") {
                continue;
            }
            let blob = package_entry
                .to_object(repository)
                .with_context(|| format!("reading committed package '{name}'"))?
                .peel_to_blob()
                .with_context(|| format!("committed package '{name}' is not a file"))?;
            let content = std::str::from_utf8(blob.content())
                .with_context(|| format!("committed package '{name}' is not UTF-8"))?;
            let package = crate::registry::parse::parse_package_file(content)
                .with_context(|| format!("parsing committed package '{name}'"))?;
            if !package.package.sysroot {
                continue;
            }
            for version in package.versions {
                for (platform, artifact) in version.platforms {
                    for image in artifact.images {
                        image.validate_delivery(&version.version, &platform)?;
                        if image.delivery.is_store_backed() {
                            continue;
                        }
                        insert_image_receipt_object(
                            &mut objects,
                            ImagePublicationReceiptObject {
                                key: image.delivery.object_key,
                                role: "disk",
                                byte_size: image.delivery.byte_size,
                                sha256: image.delivery.sha256,
                            },
                        )?;
                        insert_image_receipt_object(
                            &mut objects,
                            ImagePublicationReceiptObject {
                                key: image.delivery.image_info.object_key,
                                role: "image-info",
                                byte_size: image.delivery.image_info.byte_size,
                                sha256: image.delivery.image_info.sha256,
                            },
                        )?;
                    }
                }
            }
        }
    }
    Ok(objects)
}

fn insert_image_receipt_object(
    objects: &mut BTreeMap<String, ImagePublicationReceiptObject>,
    object: ImagePublicationReceiptObject,
) -> Result<()> {
    match objects.entry(object.key.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(object);
        }
        std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &object => {}
        std::collections::btree_map::Entry::Occupied(entry) => {
            bail!(
                "committed image object key '{}' has conflicting identities",
                entry.key()
            );
        }
    }
    Ok(())
}
