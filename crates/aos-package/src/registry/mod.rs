//! Package registry loading, resolution, and synchronization.
//!
//! A registry is a git repository of per-package TOML metadata files plus a
//! `store/` realisation graph, mirrored into a local cache directory by
//! `apm update`. This module ties the pieces together:
//!
//! - [`Registry`] loads one registry's cache and answers name, store-path
//!   hash, and realisation-graph lookups for a single platform.
//! - [`RegistrySet`] layers multiple registries by priority so the highest
//!   priority registry that offers a package wins.
//! - Submodules implement the moving parts: [`git`] (git/dumb-HTTP sync with
//!   signature and fast-forward verification), [`parse`] (package TOML
//!   schema), [`store`] (the `store/` realisation graph - dependency shape,
//!   blessed NAR bytes, and content addresses), [`channel`] and
//!   [`verify`] (channel rollout partitions and signed tag chains), [`keys`]
//!   (the committed `keys.toml` trust roster), [`fetch`] and [`pack`]
//!   (delta/full-pack object transfer), [`objectstore`] and [`static_upload`]
//!   (the producer-side static dumb-HTTP origin), [`nixcache`] (static Nix
//!   binary-cache generation), [`webgen`] (the static no-JS web surface),
//!   [`tuf`] (release metadata thresholds and timestamping), and [`state`]
//!   (persisted sync state).

pub mod channel;
pub mod dumb_http;
pub mod fetch;
pub mod git;
pub mod keys;
pub mod membership;
pub mod nixcache;
pub mod objectstore;
pub mod pack;
pub mod parse;
pub(crate) mod porcelain;
pub(crate) mod repo;
pub mod sb_certs;
pub mod state;
pub mod static_upload;
pub mod store;
pub(crate) mod thinpack;
pub mod tuf;
pub mod verify;
pub mod webgen;

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::types::{PackageMeta, RegistryConfig, TrackingMode};
use parse::parse_registry_matching;
use store::StoreMap;

/// Cache-local receipt for the signed release tag that authenticated the
/// extracted registry tree. The receipt is not itself a trust anchor: remote
/// attestation verification revalidates every field against the signed
/// registry catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTrustReceipt {
    /// Literal schema discriminator.
    pub schema: String,
    /// Registry name bound into the verified keys.
    pub registry: String,
    /// Name-bound semver release tag.
    pub release_tag: String,
    /// Release commit selected by that tag.
    pub commit: String,
    /// Fingerprint of the key whose release-tag signature verified.
    pub tag_signer_key: String,
}

/// File placed beside authenticated package/store metadata after sync.
pub const RELEASE_TRUST_RECEIPT: &str = ".release-trust.json";

pub(crate) fn load_release_trust_receipt(
    registry_dir: &Path,
    expected_registry: &str,
) -> Result<Option<ReleaseTrustReceipt>> {
    let path = registry_dir.join(RELEASE_TRUST_RECEIPT);
    if !path.is_file() {
        return Ok(None);
    }
    let receipt: ReleaseTrustReceipt = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))?;
    if receipt.schema != "aos.registry-release-trust/v1"
        || receipt.registry != expected_registry
        || semver::Version::parse(&receipt.release_tag).is_err()
        || !matches!(receipt.commit.len(), 40 | 64)
        || !receipt
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || receipt.tag_signer_key.len() != 8
        || !receipt
            .tag_signer_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("invalid signed-release trust receipt for registry '{expected_registry}'");
    }
    Ok(Some(receipt))
}

/// A loaded registry with all its packages for the current platform.
#[derive(Debug)]
pub struct Registry {
    /// The registry configuration this instance was loaded from.
    pub config: RegistryConfig,
    /// Newest matching version of every package offered for the loaded
    /// platform, keyed by package name.
    pub packages: HashMap<String, PackageMeta>,
    /// Reverse index from store path hash to the exact package version that
    /// produced it (covers all versions, not just the newest).
    hash_index: HashMap<String, PackageMeta>,
    /// Every package-version entry loaded for this platform and tracking
    /// mode, including entries that share a store-path hash.
    versions: Vec<PackageMeta>,
    /// The registry's `store/` realisation graph: dependency shape, blessed
    /// NAR bytes, and content addresses, keyed by IA store-path hash.
    store: StoreMap,
    /// Verified release identity associated with this extracted cache tree.
    release_trust: Option<ReleaseTrustReceipt>,
}

impl Registry {
    /// Load a registry from its local cache directory.
    ///
    /// The cache directory should contain a `packages/` subdirectory with
    /// the registry's TOML package files organized by first letter, and
    /// optionally a `store/` realisation graph. A missing `store/` directory
    /// is tolerated (a legacy registry) and yields an absent graph.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry tracking config is invalid, the
    /// `packages/` directory cannot be read, any package TOML file inside
    /// it fails to parse, or a present `store/` graph is malformed.
    pub fn load(cache_dir: &Path, config: &RegistryConfig, platform: &str) -> Result<Self> {
        let registry_dir = cache_dir.join(&config.name);
        let version_req = match config.tracking_mode()? {
            TrackingMode::Version(req) => Some(req),
            _ => None,
        };
        let (mut packages, mut hash_index, mut versions) =
            parse_registry_matching(&registry_dir, platform, version_req.as_ref()).with_context(
                || {
                    format!(
                        "loading registry '{}' from {}",
                        config.name,
                        registry_dir.display()
                    )
                },
            )?;

        // The realisation graph is signed security data: a malformed or
        // misfiled record fails the registry load rather than degrading
        // silently.
        let store = StoreMap::load(&registry_dir)
            .with_context(|| format!("loading store/ graph for registry '{}'", config.name))?;
        let release_trust = load_release_trust_receipt(&registry_dir, &config.name)?;

        // Package TOMLs no longer carry nar_hash/nar_size/references - the
        // graph is the single authority. Backfill the in-memory metas from a
        // root realisation so display/verify consumers keep working; legacy
        // registries still populate them from the TOML.
        for meta in packages
            .values_mut()
            .chain(hash_index.values_mut())
            .chain(versions.iter_mut())
        {
            enrich_meta_from_store(meta, &store);
        }

        Ok(Self {
            config: config.clone(),
            packages,
            hash_index,
            versions,
            store,
            release_trust,
        })
    }

    /// Returns the registry's `store/` realisation graph.
    pub fn store_map(&self) -> &StoreMap {
        &self.store
    }

    /// Returns the signed-release receipt for this exact extracted cache.
    pub fn release_trust(&self) -> Option<&ReleaseTrustReceipt> {
        self.release_trust.as_ref()
    }

    /// Returns all loaded package-version entries for this registry.
    pub fn package_versions(&self) -> impl Iterator<Item = &PackageMeta> {
        self.versions.iter()
    }

    /// Looks up the newest version of a package by name.
    pub fn get(&self, name: &str) -> Option<&PackageMeta> {
        self.packages.get(name)
    }

    /// Looks up a package version by its store path hash.
    ///
    /// Unlike [`Registry::get`], this resolves any published version whose
    /// output landed at that hash, which is what closure walking and rollback
    /// metadata rebuilds need.
    pub fn get_by_hash(&self, hash: &str) -> Option<&PackageMeta> {
        self.hash_index.get(hash)
    }

    /// Direct dependency IA hashes of a store path, from the `store/` graph.
    pub fn direct_deps(&self, hash: &str) -> Vec<String> {
        self.store.direct_deps(hash)
    }

    /// Lists all package names offered by this registry (unordered).
    pub fn names(&self) -> Vec<&str> {
        self.packages.keys().map(|s| s.as_str()).collect()
    }

    /// Searches packages by a case-insensitive substring pattern.
    ///
    /// Matches against the package name, and also the description unless
    /// `names_only` is set.
    pub fn search(&self, pattern: &str, names_only: bool) -> Vec<&PackageMeta> {
        let pattern_lower = pattern.to_lowercase();
        self.packages
            .values()
            .filter(|meta| {
                let name_match = meta.name.to_lowercase().contains(&pattern_lower);
                if names_only {
                    name_match
                } else {
                    name_match || meta.description.to_lowercase().contains(&pattern_lower)
                }
            })
            .collect()
    }
}

/// Multi-registry resolver that wraps multiple registries sorted by priority.
#[derive(Debug)]
pub struct RegistrySet {
    registries: Vec<Registry>,
}

impl RegistrySet {
    /// Creates a new registry set from pre-loaded registries.
    ///
    /// Registries should already be sorted by priority (highest first);
    /// [`RegistrySet::resolve`] returns the first match in iteration order.
    pub fn new(registries: Vec<Registry>) -> Self {
        Self { registries }
    }

    /// Loads all enabled registries from the cache directory.
    ///
    /// Registries that fail to load (typically because they have not been
    /// synced yet) are skipped with a warning on stderr rather than failing
    /// the whole set.
    ///
    /// # Errors
    ///
    /// Currently never returns an error; the `Result` is kept for forward
    /// compatibility with stricter loading policies.
    pub fn load(cache_dir: &Path, configs: &[&RegistryConfig], platform: &str) -> Result<Self> {
        let mut registries = Vec::new();
        for config in configs {
            match Registry::load(cache_dir, config, platform) {
                Ok(r) => registries.push(r),
                Err(e) => {
                    // Log warning but continue — a missing cache just means
                    // the registry hasn't been synced yet.
                    eprintln!("warning: skipping registry '{}': {}", config.name, e);
                }
            }
        }
        Ok(Self::new(registries))
    }

    /// Resolves a package name to the package offered by the
    /// highest-priority registry, together with that registry.
    pub fn resolve(&self, name: &str) -> Option<(&Registry, &PackageMeta)> {
        for reg in &self.registries {
            if let Some(meta) = reg.get(name) {
                return Some((reg, meta));
            }
        }
        None
    }

    /// Resolves a store path hash within a specific registry.
    ///
    /// Used for registry-scoped closure walking: all dependencies of a
    /// package resolve from the same registry that provided it.
    pub fn resolve_hash_in(&self, registry_name: &str, hash: &str) -> Option<&PackageMeta> {
        self.registries
            .iter()
            .find(|r| r.config.name == registry_name)
            .and_then(|r| r.get_by_hash(hash))
    }

    /// Returns the `store/` realisation graph of a specific registry.
    pub fn store_map_in(&self, registry_name: &str) -> Option<&StoreMap> {
        self.registries
            .iter()
            .find(|r| r.config.name == registry_name)
            .map(Registry::store_map)
    }

    /// Returns all versions of a package across registries (for `apm policy`).
    ///
    /// Returns entries from all registries, ordered by priority (highest first).
    pub fn all_versions(&self, name: &str) -> Vec<(&Registry, &PackageMeta)> {
        self.registries
            .iter()
            .filter_map(|reg| reg.get(name).map(|meta| (reg, meta)))
            .collect()
    }

    /// Returns a reference to a specific registry by name.
    pub fn get_registry(&self, name: &str) -> Option<&Registry> {
        self.registries.iter().find(|r| r.config.name == name)
    }

    /// Returns all registries in priority order (highest first).
    pub fn registries(&self) -> &[Registry] {
        &self.registries
    }

    /// Builds the per-transaction trust context, seeded from the **whole
    /// graph closure** of each root (RFC-0005 §2.6).
    ///
    /// `roots` pairs each closure root's store-path hash with the name of the
    /// registry that resolved it. For a registry that publishes a `store/`
    /// graph, every member reachable from the root by dependency edges —
    /// including anonymous, non-package members — is attributed to that
    /// registry's graph, so totality and download verification cover every
    /// byte that gets imported, not just the published packages. A legacy
    /// registry (no graph) contributes nothing, so its members fall through
    /// to the unauthenticated narinfo path. Each path is judged against
    /// *that* registry's graph (never a cross-registry union).
    pub fn trust_context_for_roots<'a>(
        &'a self,
        roots: &[(&str, &str)],
    ) -> store::TrustContext<'a> {
        let mut ctx = store::TrustContext::new();
        for (registry_name, root_hash) in roots {
            if let Some(registry) = self.get_registry(registry_name) {
                let map = registry.store_map();
                if map.is_present() {
                    for member in map.reachable(root_hash) {
                        ctx.insert(member, map);
                    }
                }
            }
        }
        ctx
    }
}

/// Re-export `store_path_hash` for use by other modules.
pub use parse::store_path_hash;

/// Fill a meta's `nar_hash`/`nar_size`/`references` from the realisation
/// graph when the TOML did not carry them (post-RFC-0005 registries). A
/// blessed NAR supplies the display/verify values and the graph's edges
/// supply `references`; verification proper checks the full blessed set and
/// the whole graph closure, not these single values. RFC-0005 §2.8 step 1
/// requires this backfill so sysroot containment/lock checks and size
/// summaries keep working when the TOML omits the legacy fields.
fn enrich_meta_from_store(meta: &mut PackageMeta, store: &StoreMap) {
    let hash = store_path_hash(&meta.store_path);
    if meta.references.is_empty() {
        let deps = store.direct_deps(hash);
        if !deps.is_empty() {
            meta.references = deps;
        }
    }
    if !meta.nar_hash.is_empty() && meta.nar_size != 0 {
        return;
    }
    let nars = store.blessed_nars(hash);
    let Some(nar) = nars.first() else {
        return;
    };
    if meta.nar_hash.is_empty() {
        meta.nar_hash = nar.nar_hash();
    }
    if meta.nar_size == 0 {
        meta.nar_size = nar.size;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    use super::parse::{CURL_TOML, MULTI_VERSION_TOML, ZLIB_TOML};

    /// A 52-char nixbase32 SHA-256 digest for store-record fixtures.
    pub(crate) const FIX_NAR: &str = "1b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy";

    /// curl's store record: depends on zlib (`r4q1m2kp8v3x`) plus three
    /// store paths not published as packages.
    pub(crate) fn curl_store_record() -> (&'static str, String) {
        (
            "h7j3k8l2m9n4",
            format!(
                "nar:sha256:{FIX_NAR}:3145728\n\
                 \tia:sha256:r4q1m2kp8v3x\n\
                 \tia:sha256:xr5is7by89v3q\n\
                 \tia:sha256:q8mn2pv73w0x\n\
                 \tia:sha256:kl9m3n0p5p6q\n"
            ),
        )
    }

    /// zlib's store record: a leaf.
    pub(crate) fn zlib_store_record() -> (&'static str, String) {
        ("r4q1m2kp8v3x", format!("nar:sha256:{FIX_NAR}:524288\n"))
    }

    #[test]
    fn release_trust_receipt_is_strictly_validated() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(RELEASE_TRUST_RECEIPT);
        let mut receipt = ReleaseTrustReceipt {
            schema: "aos.registry-release-trust/v1".to_string(),
            registry: "aos-core".to_string(),
            release_tag: "1.4.0".to_string(),
            commit: "a".repeat(40),
            tag_signer_key: "deadbeef".to_string(),
        };
        fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert_eq!(
            load_release_trust_receipt(tmp.path(), "aos-core")
                .unwrap()
                .unwrap(),
            receipt
        );

        receipt.tag_signer_key = "DEADBEEF".to_string();
        fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(load_release_trust_receipt(tmp.path(), "aos-core").is_err());

        receipt.tag_signer_key = "deadbeef".to_string();
        receipt.commit = "not-a-commit".to_string();
        fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(load_release_trust_receipt(tmp.path(), "aos-core").is_err());
    }

    /// Helper: create a registry in a temp directory from TOML test fixtures.
    pub(crate) fn make_registry(
        tmp: &TempDir,
        name: &str,
        priority: u32,
        toml_files: &[(&str, &str)],
    ) -> Registry {
        make_registry_with_store(tmp, name, priority, toml_files, &[])
    }

    /// Helper: create a registry with TOML files and `store/` records.
    pub(crate) fn make_registry_with_store(
        tmp: &TempDir,
        name: &str,
        priority: u32,
        toml_files: &[(&str, &str)],
        store_records: &[(&str, String)],
    ) -> Registry {
        let reg_dir = tmp.path().join(name);
        let pkg_dir = reg_dir.join("packages");
        for (pkg_name, content) in toml_files {
            let first_letter = &pkg_name[..1];
            let dir = pkg_dir.join(first_letter);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(format!("{pkg_name}.toml")), content).unwrap();
        }

        for (ia, content) in store_records {
            let dir = reg_dir.join(store::STORE_DIR).join(&ia[..2]);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(ia), content).unwrap();
        }

        let config = RegistryConfig {
            name: name.to_string(),
            url: format!("https://registry.example.com/{name}"),
            priority,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        };

        Registry::load(tmp.path(), &config, "x86_64-linux").unwrap()
    }

    #[test]
    fn registry_get_by_name() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(&tmp, "test", 500, &[("curl", CURL_TOML)]);
        assert!(reg.get("curl").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn registry_get_by_hash() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(&tmp, "test", 500, &[("curl", CURL_TOML)]);
        let meta = reg.get_by_hash("h7j3k8l2m9n4").unwrap();
        assert_eq!(meta.name, "curl");
    }

    #[test]
    fn registry_load_applies_version_tracking_constraint() {
        let tmp = TempDir::new().unwrap();
        let reg_dir = tmp.path().join("test");
        let pkg_dir = reg_dir.join("packages").join("t");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(pkg_dir.join("tool.toml"), MULTI_VERSION_TOML).unwrap();

        let config = RegistryConfig {
            name: "test".to_string(),
            url: "https://registry.example.com/test".to_string(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: Some("^1.0".to_string()),
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        };

        let reg = Registry::load(tmp.path(), &config, "x86_64-linux").unwrap();

        assert_eq!(reg.get("tool").unwrap().version, "1.0.0");
        assert!(reg.get_by_hash("oldhash111111").is_some());
        assert!(reg.get_by_hash("newhash222222").is_none());
    }

    #[test]
    fn registry_search() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "test",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        let results = reg.search("curl", false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "curl");

        // Search in description
        let results = reg.search("compression", false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "zlib");

        // Names only — should not match description
        let results = reg.search("compression", true);
        assert!(results.is_empty());
    }

    #[test]
    fn registry_set_priority_resolution() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let extra = make_registry(&tmp, "aos-extra", 400, &[("curl", CURL_TOML)]);

        let set = RegistrySet::new(vec![core, extra]);

        // Resolve picks highest priority
        let (reg, meta) = set.resolve("curl").unwrap();
        assert_eq!(reg.config.name, "aos-core");
        assert_eq!(meta.name, "curl");
    }

    #[test]
    fn registry_set_scoped_hash_resolution() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        // Scoped resolution within "aos-core"
        let meta = set.resolve_hash_in("aos-core", "r4q1m2kp8v3x").unwrap();
        assert_eq!(meta.name, "zlib");

        // Wrong registry name returns None
        assert!(set.resolve_hash_in("aos-extra", "r4q1m2kp8v3x").is_none());
    }

    #[test]
    fn registry_set_all_versions() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);
        let extra = make_registry(&tmp, "aos-extra", 400, &[("curl", CURL_TOML)]);

        let set = RegistrySet::new(vec![core, extra]);

        let versions = set.all_versions("curl");
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].0.config.name, "aos-core");
        assert_eq!(versions[1].0.config.name, "aos-extra");
    }

    #[test]
    fn registry_package_versions_keeps_same_store_hash_versions() {
        let tmp = TempDir::new().unwrap();
        let content = MULTI_VERSION_TOML.replace(
            "/var/lib/store/newhash222222-tool-2.0.0",
            "/var/lib/store/oldhash111111-tool-1.0.0",
        );
        let reg = make_registry(&tmp, "aos-core", 500, &[("tool", &content)]);
        let mut versions = reg
            .package_versions()
            .map(|meta| meta.version.as_str())
            .collect::<Vec<_>>();
        versions.sort_unstable();

        assert_eq!(versions, vec!["1.0.0", "2.0.0"]);
        assert_eq!(reg.hash_index.len(), 1);
    }

    #[test]
    fn registry_set_resolve_missing() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);
        let set = RegistrySet::new(vec![core]);

        assert!(set.resolve("nonexistent").is_none());
    }

    #[test]
    fn registry_loads_store_graph() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry_with_store(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
            &[curl_store_record(), zlib_store_record()],
        );

        // Graph is present; curl's edges and blessed bytes are available.
        assert!(core.store_map().is_present());
        assert_eq!(core.direct_deps("h7j3k8l2m9n4").len(), 4);
        assert!(
            core.direct_deps("h7j3k8l2m9n4")
                .contains(&"r4q1m2kp8v3x".to_string())
        );
        assert_eq!(core.store_map().blessed_nars("r4q1m2kp8v3x").len(), 1);

        // Unmapped path has no record.
        assert!(core.store_map().get("nonexistent").is_none());
        assert!(core.direct_deps("nonexistent").is_empty());
    }

    #[test]
    fn registry_set_store_map_in() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry_with_store(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML)],
            &[curl_store_record()],
        );
        let set = RegistrySet::new(vec![core]);

        let map = set.store_map_in("aos-core").unwrap();
        assert!(map.get("h7j3k8l2m9n4").is_some());

        // Wrong registry.
        assert!(set.store_map_in("aos-extra").is_none());
    }

    #[test]
    fn registry_without_store_dir_is_legacy() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);

        // No store/ dir - graph reads as not-present (legacy registry).
        assert!(!core.store_map().is_present());
        assert!(core.store_map().get("h7j3k8l2m9n4").is_none());
    }
}
