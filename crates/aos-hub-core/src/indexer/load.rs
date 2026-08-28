//! Loading a registry's committed tree from a verified commit.
//!
//! Given a commit oid, [`load_registry_tree`] walks `commit → tree →
//! entries` through loose objects and materializes the committed files the
//! index needs: `registry.toml`, `keys.toml`, every
//! `packages/<bucket>/<name>.toml`, the package-root realization records under
//! `store/`, the `closures/` adjacency lists, and the optional strict
//! `containers/v1/index.json` release sidecar.
//! All file formats are parsed with the wasm-clean
//! [`aos_registry_surface::manifest`] schema/parsers, so the hub, the Worker,
//! and `apm` cannot drift on what they accept.
//!
//! This module is pure logic over the [`SurfaceFetch`](crate::fetch::SurfaceFetch)
//! port and the dependency-light surface reader; it pulls in no async runtime,
//! filesystem, or HTTP client and compiles to `wasm32-unknown-unknown` (RFC-0004
//! Phase 5).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use aos_oci_types::{
    limits::MAX_JSON_BYTES as MAX_OCI_JSON_BYTES, to_canonical_json, ContainerRelease,
    CONTAINER_RELEASE_SIDECAR_PATH,
};
use aos_registry_surface::manifest::{
    parse_package_file, KeysToml, PackageToml, ReferenceField, RegistryRootConfig,
};
use aos_registry_surface::object::{self, Commit, ObjectKind, Oid};
use aos_registry_surface::store::{self, StoreEntry};
use futures_util::future::try_join_all;
use sha2::Digest as _;

use crate::fetch::SurfaceFetch;

/// Maximum package TOMLs loaded from one registry tree before the index aborts.
///
/// The tree is attacker-controlled: a hostile producer can publish a registry
/// of millions of tiny valid package files across nested buckets, and the
/// background re-index runs in the web-server process — so an uncapped walk
/// would let one tenant OOM the hub for all of them. Mirrors the indexer's
/// [`MAX_RELEASE_TAGS`](crate::indexer::MAX_RELEASE_TAGS) /
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

/// Maximum package-root realization records loaded from one registry tree.
pub const MAX_STORE_ENTRIES: usize = 1_000_000;

/// Maximum concurrent loose-object reads while loading package metadata.
///
/// A modern registry spreads package manifests and realization records across
/// most of their shard trees. Reading every tree and blob serially exceeds the
/// Worker execution window even for a few hundred packages, while this bounded
/// fanout keeps both native and Worker transports below their request limits.
const OBJECT_FETCH_CONCURRENCY: usize = 32;

/// Maximum bundle shards hydrated concurrently before an index walk.
const BUNDLE_FETCH_CONCURRENCY: usize = 32;

/// Reads loose objects through a [`SurfaceFetch`], verifying each object's
/// content hash against the oid it was requested by.
pub struct ObjectReader<'a> {
    fetch: &'a dyn SurfaceFetch,
    // Release generations normally share most tree and blob objects. Keep the
    // verified decoded form for this index pass so concurrent retained-release
    // walks do not repeatedly pay object-store and inflate latency.
    cache: Mutex<BTreeMap<Oid, (ObjectKind, Vec<u8>)>>,
    // Parsing large package manifests and store records dominates retained
    // release walks after object I/O is bundled. Their Git OIDs are immutable,
    // and successive release commits normally share nearly every blob, so the
    // verified head parse can safely serve historical walks in this index pass.
    package_cache: Mutex<BTreeMap<Oid, PackageToml>>,
    store_entry_cache: Mutex<BTreeMap<Oid, StoreEntry>>,
    // Bundle framing is cheap to validate, but inflating and hash-checking every
    // entry eagerly makes preload CPU scale with all published objects rather
    // than the objects reached by this generation. Retain canonical loose bytes
    // and verify them only when the dependency walk selects their OID.
    bundled_loose: Mutex<BTreeMap<Oid, Arc<[u8]>>>,
    attempted_bundles: Mutex<BTreeSet<String>>,
    bundle_gates: Mutex<BTreeMap<String, Arc<futures_util::lock::Mutex<()>>>>,
    bundle_fetches: AtomicUsize,
    loose_fetches: AtomicUsize,
}

impl<'a> ObjectReader<'a> {
    /// Create a reader over a surface transport.
    #[must_use]
    pub fn new(fetch: &'a dyn SurfaceFetch) -> Self {
        Self {
            fetch,
            cache: Mutex::new(BTreeMap::new()),
            package_cache: Mutex::new(BTreeMap::new()),
            store_entry_cache: Mutex::new(BTreeMap::new()),
            bundled_loose: Mutex::new(BTreeMap::new()),
            attempted_bundles: Mutex::new(BTreeSet::new()),
            bundle_gates: Mutex::new(BTreeMap::new()),
            bundle_fetches: AtomicUsize::new(0),
            loose_fetches: AtomicUsize::new(0),
        }
    }

    /// Read and verify one loose object.
    ///
    /// # Errors
    ///
    /// Returns an error when the object is absent (the publishing pipeline
    /// guarantees loose presence, so absence is surface corruption), fails
    /// to inflate, or hashes to a different oid.
    pub async fn read(&self, oid: Oid) -> Result<(ObjectKind, Vec<u8>)> {
        if let Some(decoded) = self.cached(oid)? {
            return Ok(decoded);
        }

        self.load_bundle(oid).await?;
        if let Some(decoded) = self.cached(oid)? {
            return Ok(decoded);
        }
        if let Some(loose) = self.bundled(oid)? {
            match object::decode_loose(&loose, Some(oid)) {
                Ok(decoded) => {
                    self.cache
                        .lock()
                        .map_err(|_| anyhow::anyhow!("registry object cache lock is poisoned"))?
                        .insert(oid, decoded.clone());
                    return Ok(decoded);
                }
                Err(error) => {
                    tracing::warn!(%oid, error = %format!("{error:#}"), "ignoring invalid bundled object");
                }
            }
        }

        let path = oid.loose_path();
        self.loose_fetches.fetch_add(1, Ordering::Relaxed);
        let bytes = self
            .fetch
            .fetch(&path)
            .await?
            .with_context(|| format!("loose object {path} is missing from the surface"))?;
        let decoded = object::decode_loose(&bytes, Some(oid))?;
        self.cache
            .lock()
            .map_err(|_| anyhow::anyhow!("registry object cache lock is poisoned"))?
            .insert(oid, decoded.clone());
        Ok(decoded)
    }

    fn cached(&self, oid: Oid) -> Result<Option<(ObjectKind, Vec<u8>)>> {
        Ok(self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("registry object cache lock is poisoned"))?
            .get(&oid)
            .cloned())
    }

    fn bundled(&self, oid: Oid) -> Result<Option<Arc<[u8]>>> {
        Ok(self
            .bundled_loose
            .lock()
            .map_err(|_| anyhow::anyhow!("registry bundled-object lock is poisoned"))?
            .get(&oid)
            .cloned())
    }

    async fn read_package(&self, oid: Oid, name: &str) -> Result<PackageToml> {
        if let Some(package) = self
            .package_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("registry package cache lock is poisoned"))?
            .get(&oid)
            .cloned()
        {
            return Ok(package);
        }

        let content = read_utf8_blob(self, oid, name).await?;
        let package = parse_committed_package(name, &content)?;
        self.package_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("registry package cache lock is poisoned"))?
            .insert(oid, package.clone());
        Ok(package)
    }

    async fn read_store_entry(&self, oid: Oid, name: &str) -> Result<StoreEntry> {
        if let Some(entry) = self
            .store_entry_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("registry store-entry cache lock is poisoned"))?
            .get(&oid)
            .cloned()
        {
            return Ok(entry);
        }

        let content = read_utf8_blob(self, oid, name).await?;
        let entry = store::parse_entry(&content)
            .with_context(|| format!("parsing committed store record '{name}'"))?;
        self.store_entry_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("registry store-entry cache lock is poisoned"))?
            .insert(oid, entry.clone());
        Ok(entry)
    }

    /// Hydrates every bounded bundle shard before dependency-ordered walking.
    ///
    /// Producers publish all 256 fixed shard names, including empty shards.
    /// Fetching them in bounded parallel batches avoids turning tree discovery
    /// into a sequential object-store round trip per newly encountered shard.
    /// A legacy surface without bundles remains valid and falls back to loose
    /// paths when objects are requested.
    ///
    /// # Errors
    ///
    /// Returns an error when a shard transport fails. Missing or invalid
    /// optional bundles retain canonical loose-object fallback.
    pub(crate) async fn preload_bundles(&self) -> Result<()> {
        if self.load_aggregate_bundle().await? {
            return Ok(());
        }

        let shards = (0_u16..=255)
            .map(|value| format!("{value:02x}"))
            .collect::<Vec<_>>();
        for batch in shards.chunks(BUNDLE_FETCH_CONCURRENCY) {
            try_join_all(
                batch
                    .iter()
                    .map(|shard| self.load_bundle_shard(shard.as_str())),
            )
            .await?;
        }
        Ok(())
    }

    async fn load_aggregate_bundle(&self) -> Result<bool> {
        self.bundle_fetches.fetch_add(1, Ordering::Relaxed);
        let Some(bytes) = self
            .fetch
            .fetch_bounded(
                aos_registry_surface::object_bundle::AGGREGATE_PATH,
                aos_registry_surface::object_bundle::MAX_AGGREGATE_BUNDLE_BYTES,
            )
            .await?
        else {
            return Ok(false);
        };
        let entries = match aos_registry_surface::object_bundle::decode_aggregate(&bytes) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "ignoring invalid aggregate object bundle");
                return Ok(false);
            }
        };

        self.bundled_loose
            .lock()
            .map_err(|_| anyhow::anyhow!("registry bundled-object lock is poisoned"))?
            .extend(
                entries
                    .into_iter()
                    .map(|(oid, loose)| (oid, Arc::from(loose))),
            );
        self.attempted_bundles
            .lock()
            .map_err(|_| anyhow::anyhow!("registry bundle-attempt lock is poisoned"))?
            .extend((0_u16..=255).map(|value| format!("{value:02x}")));
        Ok(true)
    }

    async fn load_bundle(&self, oid: Oid) -> Result<()> {
        let oid_hex = oid.to_hex();
        self.load_bundle_shard(&oid_hex[..2]).await
    }

    async fn load_bundle_shard(&self, shard: &str) -> Result<()> {
        let shard = shard.to_string();

        // Retained release trees load concurrently and often reach the same
        // shard together. A per-shard async gate makes that fetch single-flight:
        // unrelated shards remain parallel, while followers wait for the cache
        // population instead of falling through to thousands of loose reads.
        let gate = self
            .bundle_gates
            .lock()
            .map_err(|_| anyhow::anyhow!("registry bundle-gate lock is poisoned"))?
            .entry(shard.clone())
            .or_default()
            .clone();
        let _guard = gate.lock().await;
        let should_fetch = self
            .attempted_bundles
            .lock()
            .map_err(|_| anyhow::anyhow!("registry bundle-attempt lock is poisoned"))?
            .insert(shard.clone());
        if !should_fetch {
            return Ok(());
        }

        let path = aos_registry_surface::object_bundle::shard_path(&shard)?;
        self.bundle_fetches.fetch_add(1, Ordering::Relaxed);
        let Some(bytes) = self
            .fetch
            .fetch_bounded(&path, aos_registry_surface::object_bundle::MAX_BUNDLE_BYTES)
            .await?
        else {
            return Ok(());
        };
        let entries = match aos_registry_surface::object_bundle::decode(&shard, &bytes) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(%path, error = %format!("{error:#}"), "ignoring invalid object bundle");
                return Ok(());
            }
        };

        self.bundled_loose
            .lock()
            .map_err(|_| anyhow::anyhow!("registry bundled-object lock is poisoned"))?
            .extend(
                entries
                    .into_iter()
                    .map(|(oid, loose)| (oid, Arc::from(loose))),
            );
        Ok(())
    }

    /// Returns bundle reads, loose fallbacks, and verified cached objects.
    pub(crate) fn stats(&self) -> Result<(usize, usize, usize)> {
        let cached = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("registry object cache lock is poisoned"))?
            .len();
        Ok((
            self.bundle_fetches.load(Ordering::Relaxed),
            self.loose_fetches.load(Ordering::Relaxed),
            cached,
        ))
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
    /// Strict signed container-release sidecar, when the commit carries one.
    pub container_release: Option<LoadedContainerRelease>,
}

/// One exact `containers/v1/index.json` document loaded from a release tree.
#[derive(Debug)]
pub struct LoadedContainerRelease {
    /// Strict bounded projection used for release admission.
    pub document: ContainerRelease,
    /// Lowercase SHA-256 of the exact committed JSON bytes.
    pub catalog_digest: String,
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
    load_registry_tree_with_reader(&reader, commit_oid).await
}

/// Loads a committed registry tree through a reader shared by one index pass.
///
/// Sharing the reader lets retained release generations reuse verified Git
/// objects while preserving the same hash and kind checks as an isolated load.
///
/// # Errors
///
/// Returns the same validation and transport errors as [`load_registry_tree`].
pub(crate) async fn load_registry_tree_with_reader(
    reader: &ObjectReader<'_>,
    commit_oid: Oid,
) -> Result<LoadedTree> {
    load_registry_tree_inner(reader, commit_oid, true).await
}

/// Loads the package-bearing subset needed for one retained release snapshot.
///
/// Retained release indexing consumes registry identity, packages, and signed
/// store records. It does not consume the historical key roster or closure
/// adjacency map, both of which can be large and otherwise get reparsed once
/// per retained tag.
///
/// # Errors
///
/// Returns the same package, store, and object validation errors as
/// [`load_registry_tree_with_reader`].
pub(crate) async fn load_release_tree_with_reader(
    reader: &ObjectReader<'_>,
    commit_oid: Oid,
) -> Result<LoadedTree> {
    load_registry_tree_inner(reader, commit_oid, false).await
}

async fn load_registry_tree_inner(
    reader: &ObjectReader<'_>,
    commit_oid: Oid,
    include_governance: bool,
) -> Result<LoadedTree> {
    let commit = reader.read_commit(commit_oid).await?;
    let root_tree = object::tree_map(&reader.read_kind(commit.tree, ObjectKind::Tree).await?)?;

    let root_toml = match root_tree.get("registry.toml") {
        Some(entry) => read_utf8_blob(&reader, entry.oid, "registry.toml").await?,
        None => bail!("committed tree has no registry.toml"),
    };
    let root: RegistryRootConfig =
        toml::from_str(&root_toml).context("parsing committed registry.toml")?;

    let keys = match root_tree.get("keys.toml").filter(|_| include_governance) {
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
        let bucket_entries = buckets
            .values()
            .filter(|entry| entry.is_tree())
            .collect::<Vec<_>>();
        let mut bucket_files = Vec::with_capacity(bucket_entries.len());
        for batch in bucket_entries.chunks(OBJECT_FETCH_CONCURRENCY) {
            bucket_files.extend(
                try_join_all(batch.iter().map(|bucket| async {
                    object::tree_map(&reader.read_kind(bucket.oid, ObjectKind::Tree).await?)
                }))
                .await?,
            );
        }
        let files = bucket_files
            .into_iter()
            .flat_map(BTreeMap::into_values)
            .filter(|entry| entry.name.ends_with(".toml"))
            .collect::<Vec<_>>();
        anyhow::ensure!(
            files.len() <= MAX_PACKAGES,
            "registry tree exceeds the {MAX_PACKAGES}-package index cap; aborting index"
        );
        packages.reserve(files.len());
        for batch in files.chunks(OBJECT_FETCH_CONCURRENCY) {
            packages.extend(
                try_join_all(
                    batch
                        .iter()
                        .map(|file| async { reader.read_package(file.oid, &file.name).await }),
                )
                .await?,
            );
        }
    }

    let mut closures = BTreeMap::new();
    if let Some(closures_entry) = root_tree.get("closures").filter(|_| include_governance) {
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

    let store = load_package_store_records(&reader, &root_tree, &packages).await?;
    if let Some(store) = &store {
        enrich_packages_from_store(&mut packages, store)?;
    }

    let container_release = load_container_release(reader, &root_tree).await?;

    Ok(LoadedTree {
        root,
        keys,
        packages,
        closures,
        container_release,
    })
}

async fn load_container_release(
    reader: &ObjectReader<'_>,
    root_tree: &BTreeMap<String, object::TreeEntry>,
) -> Result<Option<LoadedContainerRelease>> {
    let Some(containers_entry) = root_tree.get("containers") else {
        return Ok(None);
    };
    anyhow::ensure!(
        containers_entry.is_tree(),
        "committed containers entry is not a tree"
    );
    let containers = object::tree_map(
        &reader
            .read_kind(containers_entry.oid, ObjectKind::Tree)
            .await?,
    )?;
    let Some(version_entry) = containers.get("v1") else {
        return Ok(None);
    };
    anyhow::ensure!(
        version_entry.is_tree(),
        "committed containers/v1 entry is not a tree"
    );
    let version = object::tree_map(
        &reader
            .read_kind(version_entry.oid, ObjectKind::Tree)
            .await?,
    )?;
    let Some(index_entry) = version.get("index.json") else {
        return Ok(None);
    };
    anyhow::ensure!(
        !index_entry.is_tree(),
        "committed {CONTAINER_RELEASE_SIDECAR_PATH} entry is not a blob"
    );

    let bytes = reader
        .read_kind(index_entry.oid, ObjectKind::Blob)
        .await
        .with_context(|| format!("loading committed {CONTAINER_RELEASE_SIDECAR_PATH}"))?;
    parse_optional_container_release(Some(&bytes))
}

fn parse_optional_container_release(
    bytes: Option<&[u8]>,
) -> Result<Option<LoadedContainerRelease>> {
    bytes.map(parse_container_release).transpose()
}

fn parse_container_release(bytes: &[u8]) -> Result<LoadedContainerRelease> {
    anyhow::ensure!(
        bytes.len() <= MAX_OCI_JSON_BYTES,
        "committed {CONTAINER_RELEASE_SIDECAR_PATH} exceeds the {MAX_OCI_JSON_BYTES}-byte limit"
    );
    let document = ContainerRelease::from_json(bytes)
        .with_context(|| format!("parsing committed {CONTAINER_RELEASE_SIDECAR_PATH}"))?;
    anyhow::ensure!(
        to_canonical_json(&document)? == bytes,
        "committed {CONTAINER_RELEASE_SIDECAR_PATH} must use canonical JSON"
    );
    let catalog_digest = hex::encode(sha2::Sha256::digest(bytes));
    Ok(LoadedContainerRelease {
        document,
        catalog_digest,
    })
}

#[cfg(test)]
mod container_release_tests {
    use super::*;
    use aos_oci_types::{
        Annotations, ContainerEvidenceMappingQualification, ContainerEvidenceQualification,
        ContainerEvidenceQualificationCheck, ContainerNixProvenance, ContainerOciRelease,
        ContainerReleaseEvidence, ContainerReleaseIdentity, Descriptor, MediaType,
        NixDefinitionIdentity, NixOutputIdentity, Platform, Sha256Digest,
        CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA, CONTAINER_RELEASE_SCHEMA_VERSION,
    };

    fn descriptor(media_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            media_type,
            digest: Sha256Digest::digest(label.as_bytes()),
            size: u64::try_from(label.len()).unwrap(),
            urls: Vec::new(),
            annotations: Annotations::new(),
            data: None,
            artifact_type: None,
            platform: None,
        }
    }

    fn evidence_descriptor(artifact_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            artifact_type: Some(artifact_type),
            ..descriptor(MediaType::OciImageManifest, label)
        }
    }

    fn release_fixture() -> ContainerRelease {
        let mut platform_manifest = descriptor(MediaType::OciImageManifest, "amd64-manifest");
        platform_manifest.platform = Some(Platform::linux_amd64());
        ContainerRelease {
            schema_version: CONTAINER_RELEASE_SCHEMA_VERSION,
            media_type: MediaType::AosContainerRelease,
            identity: ContainerReleaseIdentity {
                release: "1.0.0".to_string(),
                package: "aos".to_string(),
                package_version: "0.1.0".to_string(),
                image: "aos".to_string(),
            },
            oci: ContainerOciRelease {
                index: descriptor(MediaType::OciImageIndex, "index"),
                platform_manifests: vec![platform_manifest],
            },
            nix: ContainerNixProvenance {
                definition: NixDefinitionIdentity {
                    attribute: "containerImages.aos".to_string(),
                    derivation_path:
                        "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container.drv".to_string(),
                },
                output: NixOutputIdentity {
                    name: "out".to_string(),
                    store_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container"
                        .to_string(),
                },
                closure: evidence_descriptor(MediaType::AosNixClosure, "closure"),
            },
            qualification: ContainerEvidenceQualification {
                schema: CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA.to_string(),
                mapping: ContainerEvidenceMappingQualification {
                    complete: true,
                    unknown_paths: Vec::new(),
                },
                corresponding_source: ContainerEvidenceQualificationCheck {
                    complete: true,
                    unknown_paths: Vec::new(),
                },
                licensing: ContainerEvidenceQualificationCheck {
                    complete: true,
                    unknown_paths: Vec::new(),
                },
                ready_for_verified_publication: true,
            },
            evidence: ContainerReleaseEvidence {
                sbom: evidence_descriptor(MediaType::SpdxJson, "sbom"),
                source: evidence_descriptor(MediaType::AosSourceClosure, "source"),
                license: evidence_descriptor(MediaType::AosLicenseReport, "license"),
                provenance: evidence_descriptor(MediaType::InTotoJson, "provenance"),
                signature: evidence_descriptor(MediaType::DsseEnvelope, "signature"),
            },
        }
    }

    #[test]
    fn legacy_tree_without_container_sidecar_remains_compatible() {
        assert!(parse_optional_container_release(None).unwrap().is_none());
    }

    #[test]
    fn malformed_container_sidecar_fails_closed() {
        let error = parse_optional_container_release(Some(br#"{"schemaVersion":1}"#)).unwrap_err();
        assert!(format!("{error:#}").contains(CONTAINER_RELEASE_SIDECAR_PATH));
    }

    #[test]
    fn noncanonical_container_sidecar_is_rejected_before_hashing() {
        let release = release_fixture();
        let canonical = to_canonical_json(&release).unwrap();
        let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
        noncanonical.push(b' ');
        noncanonical.extend(canonical);

        let error = parse_container_release(&noncanonical).unwrap_err();
        assert!(format!("{error:#}").contains("must use canonical JSON"));
    }

    #[test]
    fn oversized_container_sidecar_is_rejected_before_parsing() {
        let bytes = vec![b' '; MAX_OCI_JSON_BYTES + 1];
        let error = parse_container_release(&bytes).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds"));
    }
}

async fn load_package_store_records(
    reader: &ObjectReader<'_>,
    root_tree: &BTreeMap<String, object::TreeEntry>,
    packages: &[PackageToml],
) -> Result<Option<BTreeMap<String, StoreEntry>>> {
    let Some(store_entry) = root_tree.get(store::STORE_DIR) else {
        return Ok(None);
    };
    anyhow::ensure!(store_entry.is_tree(), "committed store entry is not a tree");

    let shards = object::tree_map(&reader.read_kind(store_entry.oid, ObjectKind::Tree).await?)?;
    let mut required = BTreeSet::new();
    for package in packages {
        for version in &package.versions {
            for artifact in version.platforms.values() {
                required.insert(store_hash_component(&artifact.store_path).to_string());
            }
        }
    }
    anyhow::ensure!(
        required.len() <= MAX_STORE_ENTRIES,
        "registry packages reference more than the {MAX_STORE_ENTRIES}-record store graph cap"
    );

    let mut required_shards = BTreeSet::new();
    for hash in &required {
        required_shards.insert(
            store::shard(hash)
                .with_context(|| format!("invalid package store-path hash '{hash}'"))?
                .to_string(),
        );
    }

    let required_shards = required_shards.into_iter().collect::<Vec<_>>();
    let mut shard_files = BTreeMap::new();
    for batch in required_shards.chunks(OBJECT_FETCH_CONCURRENCY) {
        let shards = &shards;
        shard_files.extend(
            try_join_all(batch.iter().cloned().map(|shard_name| async move {
                let shard_entry = shards
                    .get(&shard_name)
                    .with_context(|| format!("signed store graph has no shard '{shard_name}'"))?;
                anyhow::ensure!(
                    shard_entry.is_tree(),
                    "committed store shard '{}' is not a tree",
                    shard_entry.name
                );
                let files =
                    object::tree_map(&reader.read_kind(shard_entry.oid, ObjectKind::Tree).await?)?;
                Ok::<_, anyhow::Error>((shard_name.clone(), files))
            }))
            .await?,
        );
    }

    let required = required.into_iter().collect::<Vec<_>>();
    let mut entries = BTreeMap::new();
    for batch in required.chunks(OBJECT_FETCH_CONCURRENCY) {
        let shard_files = &shard_files;
        entries.extend(
            try_join_all(batch.iter().cloned().map(|hash| async move {
                let shard_name = store::shard(&hash)
                    .with_context(|| format!("invalid package store-path hash '{hash}'"))?;
                let files = shard_files
                    .get(shard_name)
                    .context("loaded store shard disappeared")?;
                let file = files
                    .get(&hash)
                    .with_context(|| format!("signed store graph has no record for '{hash}'"))?;
                anyhow::ensure!(
                    !file.is_tree(),
                    "committed store record '{}' is unexpectedly a tree",
                    file.name
                );
                let parsed = reader.read_store_entry(file.oid, &file.name).await?;
                Ok::<_, anyhow::Error>((hash.clone(), parsed))
            }))
            .await?,
        );
    }
    Ok(Some(entries))
}

fn enrich_packages_from_store(
    packages: &mut [PackageToml],
    store: &BTreeMap<String, StoreEntry>,
) -> Result<()> {
    for package in packages {
        for version in &mut package.versions {
            for (platform, artifact) in &mut version.platforms {
                let hash = store_hash_component(&artifact.store_path);
                let record = store.get(hash).with_context(|| {
                    format!(
                        "package {} {} {platform} has no signed store record for {hash}",
                        package.package.name, version.version
                    )
                })?;
                let nar = record.blessed_nars().into_iter().next().with_context(|| {
                    format!(
                        "package {} {} {platform} store record {hash} has no blessed NAR",
                        package.package.name, version.version
                    )
                })?;
                if !artifact.nar_hash.is_empty() {
                    anyhow::ensure!(
                        nar.matches(&artifact.nar_hash, artifact.nar_size),
                        "package {} {} {platform} legacy NAR metadata disagrees with signed store record {hash}",
                        package.package.name,
                        version.version
                    );
                }
                artifact.nar_hash = nar.nar_hash();
                artifact.nar_size = nar.size;

                let dependencies = record.dep_ias();
                match &mut artifact.references {
                    ReferenceField::Hashes(hashes) if hashes.is_empty() => *hashes = dependencies,
                    ReferenceField::Gate(gate) if gate.hashes.is_empty() => {
                        gate.hashes = dependencies;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn store_hash_component(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.split('-').next().unwrap_or(name)
}

fn parse_committed_package(name: &str, content: &str) -> Result<PackageToml> {
    parse_package_file(content).with_context(|| format!("parsing committed packages/…/{name}"))
}

/// Read one loose blob object and decode its bytes as UTF-8.
///
/// # Errors
///
/// Returns an error on read failure, kind mismatch, or non-UTF-8 content.
async fn read_utf8_blob(reader: &ObjectReader<'_>, oid: Oid, name: &str) -> Result<String> {
    let content = reader.read_kind(oid, ObjectKind::Blob).await?;
    String::from_utf8(content).with_context(|| format!("committed file {name} is not UTF-8"))
}

#[cfg(test)]
mod image_catalog_tests {
    use super::*;

    const DUPLICATE_IMAGE_FORMAT: &str = r#"
[package]
name = "server"
description = "test"
license = "MIT"
maintainer = "test"
sysroot = true

[[versions]]
version = "2026.08"

[versions.platforms.x86_64-linux]
store_path = "/aos/store/server"
closure_size = 1
source_drv = ""
source_nar_hash = ""

[[versions.platforms.x86_64-linux.images]]
format = "raw"
store_path = "/aos/store/raw-one"
nar_hash = "sha256:one"
nar_size = 1

[[versions.platforms.x86_64-linux.images]]
format = "raw"
store_path = "/aos/store/raw-two"
nar_hash = "sha256:two"
nar_size = 1
"#;

    #[test]
    fn hub_committed_package_loader_rejects_duplicate_image_encodings() {
        let error = parse_committed_package("server.toml", DUPLICATE_IMAGE_FORMAT).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("packages/…/server.toml"));
        assert!(rendered.contains("duplicate 'raw' image encodings"));
    }
}

#[cfg(test)]
mod store_graph_tests {
    use super::*;

    const NAR: &str = "1b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy";

    fn modern_package() -> PackageToml {
        parse_committed_package(
            "acl.toml",
            r#"
[package]
name = "acl"
description = "Access control lists"
license = "LGPL-2.1-or-later"
maintainer = "team"

[[versions]]
version = "2.3.2"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/9rd6z1174svja44vjm38h6iql4sz4z9k-acl-2.3.2"
closure_size = 14987624
source_drv = "/nix/store/source-acl.drv"
source_nar_hash = "sha256:source"
"#,
        )
        .unwrap()
    }

    #[test]
    fn modern_package_metadata_is_enriched_from_signed_store_record() {
        let mut packages = vec![modern_package()];
        let mut graph = BTreeMap::new();
        graph.insert(
            "9rd6z1174svja44vjm38h6iql4sz4z9k".to_string(),
            store::parse_entry(&format!(
                "nar:sha256:{NAR}:367184\n  ia:sha256:6ypxvvj6cvgba6jfkna2b7vjsywfssaa\n"
            ))
            .unwrap(),
        );

        enrich_packages_from_store(&mut packages, &graph).unwrap();
        let artifact = packages[0].versions[0]
            .platforms
            .get("x86_64-linux")
            .unwrap();
        assert_eq!(artifact.nar_hash, format!("sha256:{NAR}"));
        assert_eq!(artifact.nar_size, 367184);
        assert_eq!(
            artifact.references.hashes(),
            ["6ypxvvj6cvgba6jfkna2b7vjsywfssaa"]
        );
    }

    #[test]
    fn modern_package_missing_its_store_record_fails_closed() {
        let error =
            enrich_packages_from_store(&mut [modern_package()], &BTreeMap::new()).unwrap_err();
        assert!(format!("{error:#}").contains("has no signed store record"));
    }
}

#[cfg(test)]
mod bundle_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct BundleFetch {
        bytes: Vec<u8>,
        reads: AtomicUsize,
    }

    struct MissingBundleFetch {
        reads: AtomicUsize,
    }

    struct InvalidBundleFetch {
        bundle: Vec<u8>,
        loose: Vec<u8>,
        loose_reads: AtomicUsize,
    }

    struct AggregateBundleFetch {
        bytes: Vec<u8>,
        reads: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for MissingBundleFetch {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            panic!("unexpected loose-object fetch for {path}")
        }

        async fn fetch_bounded(&self, _path: &str, _max_bytes: usize) -> Result<Option<Vec<u8>>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn describe(&self) -> String {
            "missing-bundle-preload".into()
        }
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for BundleFetch {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            panic!("unexpected loose-object fallback for {path}")
        }

        async fn fetch_bounded(&self, _path: &str, _max_bytes: usize) -> Result<Option<Vec<u8>>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(Some(self.bytes.clone()))
        }

        fn describe(&self) -> String {
            "bundle-single-flight".into()
        }
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for InvalidBundleFetch {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            self.loose_reads.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.loose.clone()))
        }

        async fn fetch_bounded(&self, _path: &str, _max_bytes: usize) -> Result<Option<Vec<u8>>> {
            Ok(Some(self.bundle.clone()))
        }

        fn describe(&self) -> String {
            "invalid-bundle-fallback".into()
        }
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for AggregateBundleFetch {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            panic!("unexpected loose-object fetch for {path}")
        }

        async fn fetch_bounded(&self, path: &str, _max_bytes: usize) -> Result<Option<Vec<u8>>> {
            assert_eq!(path, aos_registry_surface::object_bundle::AGGREGATE_PATH);
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.bytes.clone()))
        }

        fn describe(&self) -> String {
            "aggregate-bundle".into()
        }
    }

    #[tokio::test]
    async fn concurrent_same_shard_reads_share_one_bundle_fetch() {
        let mut by_shard = BTreeMap::<String, Vec<(Oid, Vec<u8>)>>::new();
        for value in 0..10_000 {
            let content = format!("bundle value {value}").into_bytes();
            let oid = object::hash_object(ObjectKind::Blob, &content);
            let shard = oid.to_hex()[..2].to_string();
            let entries = by_shard.entry(shard.clone()).or_default();
            entries.push((
                oid,
                object::encode_loose(ObjectKind::Blob, &content).unwrap(),
            ));
            if entries.len() == 2 {
                entries.sort_by_key(|(oid, _)| *oid);
                let bytes = aos_registry_surface::object_bundle::encode(&shard, entries).unwrap();
                let fetch = BundleFetch {
                    bytes,
                    reads: AtomicUsize::new(0),
                };
                let reader = ObjectReader::new(&fetch);

                let (first, second) =
                    tokio::join!(reader.read(entries[0].0), reader.read(entries[1].0),);
                assert_eq!(first.unwrap().0, ObjectKind::Blob);
                assert_eq!(second.unwrap().0, ObjectKind::Blob);
                assert_eq!(fetch.reads.load(Ordering::SeqCst), 1);
                assert_eq!(reader.stats().unwrap(), (1, 0, 2));
                return;
            }
        }
        panic!("test could not find two objects in one shard");
    }

    #[tokio::test]
    async fn preload_attempts_every_fixed_shard_once() {
        let fetch = MissingBundleFetch {
            reads: AtomicUsize::new(0),
        };
        let reader = ObjectReader::new(&fetch);

        reader.preload_bundles().await.unwrap();

        assert_eq!(fetch.reads.load(Ordering::SeqCst), 257);
        assert_eq!(reader.stats().unwrap(), (257, 0, 0));
    }

    #[tokio::test]
    async fn aggregate_preload_replaces_all_shard_fetches() {
        let content = b"aggregate selected object";
        let oid = object::hash_object(ObjectKind::Blob, content);
        let loose = object::encode_loose(ObjectKind::Blob, content).unwrap();
        let fetch = AggregateBundleFetch {
            bytes: aos_registry_surface::object_bundle::encode_aggregate(&[(oid, loose)]).unwrap(),
            reads: AtomicUsize::new(0),
        };
        let reader = ObjectReader::new(&fetch);

        reader.preload_bundles().await.unwrap();
        let (kind, decoded) = reader.read(oid).await.unwrap();

        assert_eq!(kind, ObjectKind::Blob);
        assert_eq!(decoded, content);
        assert_eq!(fetch.reads.load(Ordering::SeqCst), 1);
        assert_eq!(reader.stats().unwrap(), (1, 0, 1));
    }

    #[tokio::test]
    async fn invalid_selected_bundle_entry_falls_back_to_loose_object() {
        let content = b"canonical loose fallback";
        let oid = object::hash_object(ObjectKind::Blob, content);
        let shard = &oid.to_hex()[..2];
        let bundle = aos_registry_surface::object_bundle::encode(
            shard,
            &[(oid, b"not a zlib stream".to_vec())],
        )
        .unwrap();
        let fetch = InvalidBundleFetch {
            bundle,
            loose: object::encode_loose(ObjectKind::Blob, content).unwrap(),
            loose_reads: AtomicUsize::new(0),
        };
        let reader = ObjectReader::new(&fetch);

        let (kind, decoded) = reader.read(oid).await.unwrap();

        assert_eq!(kind, ObjectKind::Blob);
        assert_eq!(decoded, content);
        assert_eq!(fetch.loose_reads.load(Ordering::SeqCst), 1);
        assert_eq!(reader.stats().unwrap(), (1, 1, 1));
    }
}
