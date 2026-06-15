//! Loading a registry's committed tree from a verified commit.
//!
//! Given a commit oid, [`load_registry_tree`] walks `commit → tree →
//! entries` through loose objects and materializes the committed files the
//! index needs: `registry.toml`, `keys.toml`, every
//! `packages/<bucket>/<name>.toml`, and the `closures/` adjacency lists.
//! All file formats are parsed with `aos-package`'s own parsers, so the hub
//! cannot drift from what `apm` accepts.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use aos_package::registry::keys::KeysToml;
use aos_package::registry::parse::{parse_package_file, PackageToml};
use aos_package::types::RegistryRootConfig;

use super::object::{self, Commit, ObjectKind, Oid};
use crate::fetch::SurfaceFetch;

/// Maximum package TOMLs loaded from one registry tree before the index aborts.
///
/// The tree is attacker-controlled: a hostile producer can publish a registry
/// of millions of tiny valid package files across nested buckets, and the
/// background re-index runs in the web-server process — so an uncapped walk
/// would let one tenant OOM the hub for all of them. Mirrors the indexer's
/// [`MAX_SEMVER_TAGS`](crate::indexer::MAX_SEMVER_TAGS) /
/// [`MAX_BRANCHES`](crate::indexer::MAX_BRANCHES) caps, but aborts (rather than
/// truncating) so a registry that overflows is marked failed instead of being
/// silently partially indexed. Sized far above any realistic registry.
pub const MAX_PACKAGES: usize = 50_000;

/// Maximum closure adjacency entries loaded from one registry tree.
///
/// Each `closures/` line contributes one map entry (store-path hash → direct
/// references); a hostile tree can pad these without bound. Capped for the same
/// reason as [`MAX_PACKAGES`], and likewise aborts the index when exceeded.
pub const MAX_CLOSURE_ENTRIES: usize = 1_000_000;

/// Reads loose objects through a [`SurfaceFetch`], verifying each object's
/// content hash against the oid it was requested by.
pub struct ObjectReader<'a> {
    fetch: &'a dyn SurfaceFetch,
}

impl<'a> ObjectReader<'a> {
    /// Create a reader over a surface transport.
    pub fn new(fetch: &'a dyn SurfaceFetch) -> Self {
        Self { fetch }
    }

    /// Read and verify one loose object.
    ///
    /// # Errors
    ///
    /// Returns an error when the object is absent (the publishing pipeline
    /// guarantees loose presence, so absence is surface corruption), fails
    /// to inflate, or hashes to a different oid.
    pub async fn read(&self, oid: Oid) -> Result<(ObjectKind, Vec<u8>)> {
        let path = oid.loose_path();
        let bytes = self
            .fetch
            .fetch(&path)
            .await?
            .with_context(|| format!("loose object {path} is missing from the surface"))?;
        object::decode_loose(&bytes, Some(oid))
    }

    /// Read one loose object, requiring a specific kind.
    ///
    /// # Errors
    ///
    /// Returns an error on read failure or kind mismatch.
    pub async fn read_kind(&self, oid: Oid, want: ObjectKind) -> Result<Vec<u8>> {
        let (kind, content) = self.read(oid).await?;
        if kind != want {
            bail!(
                "object {oid} is a {}, expected {}",
                kind.as_str(),
                want.as_str()
            );
        }
        Ok(content)
    }

    /// Read and parse a commit object.
    ///
    /// # Errors
    ///
    /// Returns an error on read failure or malformed commit.
    pub async fn read_commit(&self, oid: Oid) -> Result<Commit> {
        let content = self.read_kind(oid, ObjectKind::Commit).await?;
        object::parse_commit(&content)
    }
}

/// The committed registry files loaded from one verified commit.
#[derive(Debug)]
pub struct LoadedTree {
    /// Parsed `registry.toml`.
    pub root: RegistryRootConfig,
    /// Parsed `keys.toml`, when committed.
    pub keys: Option<KeysToml>,
    /// Every parsed package file, in tree order.
    pub packages: Vec<PackageToml>,
    /// Closure adjacency lists: store-path hash → direct references.
    pub closures: BTreeMap<String, Vec<String>>,
}

/// Load the committed registry files reachable from `commit_oid`.
///
/// # Errors
///
/// Returns an error when any object is missing or malformed, when
/// `registry.toml` is absent (it is mandatory), or when any committed file
/// fails its format parser.
pub async fn load_registry_tree(fetch: &dyn SurfaceFetch, commit_oid: Oid) -> Result<LoadedTree> {
    let reader = ObjectReader::new(fetch);
    let commit = reader.read_commit(commit_oid).await?;
    let root_tree = object::tree_map(&reader.read_kind(commit.tree, ObjectKind::Tree).await?)?;

    let root_toml = match root_tree.get("registry.toml") {
        Some(entry) => read_utf8_blob(&reader, entry.oid, "registry.toml").await?,
        None => bail!("committed tree has no registry.toml"),
    };
    let root: RegistryRootConfig =
        toml::from_str(&root_toml).context("parsing committed registry.toml")?;

    let keys = match root_tree.get("keys.toml") {
        Some(entry) => {
            let content = read_utf8_blob(&reader, entry.oid, "keys.toml").await?;
            Some(toml::from_str::<KeysToml>(&content).context("parsing committed keys.toml")?)
        }
        None => None,
    };

    let mut packages = Vec::new();
    if let Some(packages_entry) = root_tree.get("packages") {
        let buckets = object::tree_map(
            &reader
                .read_kind(packages_entry.oid, ObjectKind::Tree)
                .await?,
        )?;
        for bucket in buckets.values().filter(|e| e.is_tree()) {
            let files = object::tree_map(&reader.read_kind(bucket.oid, ObjectKind::Tree).await?)?;
            for file in files.values().filter(|e| e.name.ends_with(".toml")) {
                if packages.len() >= MAX_PACKAGES {
                    bail!(
                        "registry tree exceeds the {MAX_PACKAGES}-package index cap; \
                         aborting index"
                    );
                }
                let content = read_utf8_blob(&reader, file.oid, &file.name).await?;
                let package = parse_package_file(&content)
                    .with_context(|| format!("parsing committed packages/…/{}", file.name))?;
                packages.push(package);
            }
        }
    }

    let mut closures = BTreeMap::new();
    if let Some(closures_entry) = root_tree.get("closures") {
        let files = object::tree_map(
            &reader
                .read_kind(closures_entry.oid, ObjectKind::Tree)
                .await?,
        )?;
        for file in files.values().filter(|e| !e.is_tree()) {
            let content = read_utf8_blob(&reader, file.oid, &file.name).await?;
            // Adjacency list: every line is "<hash> [<dep-hash>…]"; the file
            // is named after its root hash but carries the whole closure.
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                if closures.len() >= MAX_CLOSURE_ENTRIES {
                    bail!(
                        "registry tree exceeds the {MAX_CLOSURE_ENTRIES}-entry closure \
                         cap; aborting index"
                    );
                }
                let mut parts = line.split_whitespace().map(str::to_string);
                if let Some(head) = parts.next() {
                    closures.entry(head).or_insert_with(|| parts.collect());
                }
            }
        }
    }

    Ok(LoadedTree {
        root,
        keys,
        packages,
        closures,
    })
}

async fn read_utf8_blob(reader: &ObjectReader<'_>, oid: Oid, name: &str) -> Result<String> {
    let content = reader.read_kind(oid, ObjectKind::Blob).await?;
    String::from_utf8(content).with_context(|| format!("committed file {name} is not UTF-8"))
}
