//! Registry package TOML parsing.
//!
//! A synced registry cache stores one TOML file per package under
//! `packages/{first_letter}/{name}.toml`. Each file declares package-level
//! metadata (`[package]`), one or more `[[versions]]`, and per-platform
//! artifact details (`[versions.platforms.<platform>]`):
//!
//! ```toml
//! [package]
//! name = "curl"
//! description = "Command-line tool and library for URL transfers"
//! license = "MIT"
//! maintainer = "aos-team"
//!
//! [[versions]]
//! version = "8.5.0"
//!
//! [versions.platforms.x86_64-linux]
//! store_path = "/var/lib/store/h7j3k8l2m9n4-curl-8.5.0"
//! nar_hash = "sha256:..."
//! nar_size = 3145728
//! closure_size = 52428800
//! source_drv = "/var/lib/store/...-curl-8.5.0.drv"
//! source_nar_hash = "sha256:..."
//! references = ["r4q1m2kp8v3x"]
//! ```
//!
//! [`parse_registry`] walks the whole cache directory and flattens it into
//! the per-platform [`PackageMeta`] maps used by the registry resolver: a
//! name-to-newest-version map for normal resolution and a store-path-hash
//! index over every version for reverse lookups.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::types::{PackageMeta, SysrootImageEntry, package_name_bucket, validate_package_name};

// ---------------------------------------------------------------------------
// Package TOML schema (registry format)
// ---------------------------------------------------------------------------

/// Top-level package TOML file from a registry.
#[derive(Debug, Deserialize)]
struct PackageToml {
    /// The `[package]` header with name and descriptive metadata.
    package: PackageHeader,
    /// All published `[[versions]]` entries, oldest layout order preserved.
    #[serde(default)]
    versions: Vec<VersionEntry>,
}

/// The `[package]` header section of a package TOML file.
#[derive(Debug, Deserialize)]
struct PackageHeader {
    /// Package name; must match the TOML file's basename.
    name: String,
    /// One-line human-readable description, searched by `apm search`.
    description: String,
    /// Optional upstream homepage URL.
    #[serde(default)]
    homepage: Option<String>,
    /// SPDX-style license identifier.
    license: String,
    /// Maintainer name or team handle.
    maintainer: String,
    /// Whether this package is a system toplevel (sysroot).
    #[serde(default)]
    sysroot: bool,
}

/// One `[[versions]]` entry of a package TOML file.
#[derive(Debug, Deserialize)]
struct VersionEntry {
    /// Version string; semver when possible, calver otherwise.
    version: String,
    /// Previous version in the version chain (for sysroot packages).
    #[serde(default)]
    previous: Option<String>,
    /// Per-platform artifacts, keyed by platform triple
    /// (e.g. `x86_64-linux`).
    #[serde(default)]
    platforms: HashMap<String, PlatformEntry>,
}

/// A `[versions.platforms.<platform>]` artifact entry.
#[derive(Debug, Deserialize)]
struct PlatformEntry {
    /// Absolute store path of the built output.
    store_path: String,
    /// NAR hash of the output (`sha256:...`).
    nar_hash: String,
    /// Uncompressed NAR size in bytes.
    nar_size: u64,
    /// Total uncompressed size of the runtime closure in bytes.
    closure_size: u64,
    /// Store path of the derivation that produced the output.
    source_drv: String,
    /// NAR hash of the source derivation closure.
    source_nar_hash: String,
    /// Store path hashes of direct runtime references.
    #[serde(default)]
    references: Vec<String>,
    /// Pre-compiled images (only for sysroot packages).
    #[serde(default)]
    images: Vec<ImageEntry>,
}

/// A pre-compiled image entry within a platform entry.
#[derive(Debug, Deserialize)]
struct ImageEntry {
    /// Image format identifier (e.g. `qcow2`).
    format: String,
    /// Absolute store path of the image artifact.
    store_path: String,
    /// NAR hash of the image (`sha256:...`).
    nar_hash: String,
    /// Uncompressed NAR size of the image in bytes.
    nar_size: u64,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse all package TOML files in a registry cache directory.
///
/// Registry layout: `{cache_dir}/packages/{first_letter}/{name}.toml`
///
/// Returns `(packages, hash_index)` where `packages` maps package names to
/// the newest version for normal package resolution and `hash_index` maps
/// every version's store path hash to its exact package metadata for reverse
/// lookup during closure resolution and rollback metadata rebuilds.
///
/// A missing `packages/` directory yields empty maps; packages with no entry
/// for `platform` are skipped silently.
///
/// # Errors
///
/// Returns an error if a directory cannot be read or any package TOML file
/// fails to parse.
pub fn parse_registry(
    dir: &Path,
    platform: &str,
) -> Result<(HashMap<String, PackageMeta>, HashMap<String, PackageMeta>)> {
    parse_registry_matching(dir, platform, None)
}

/// Parse a registry directory, retaining only versions matched by `version_req`.
///
/// A missing `packages/` directory yields empty maps; packages with no entry
/// for `platform` or no version matching `version_req` are skipped silently.
///
/// # Errors
///
/// Returns an error if a directory cannot be read or any package TOML file
/// fails to parse.
pub(crate) fn parse_registry_matching(
    dir: &Path,
    platform: &str,
    version_req: Option<&semver::VersionReq>,
) -> Result<(HashMap<String, PackageMeta>, HashMap<String, PackageMeta>)> {
    let packages_dir = dir.join("packages");
    let mut packages = HashMap::new();
    let mut all_versions = Vec::new();

    if !packages_dir.is_dir() {
        return Ok((packages, HashMap::new()));
    }

    // Walk {first_letter}/{name}.toml
    for letter_entry in std::fs::read_dir(&packages_dir)
        .with_context(|| format!("reading {}", packages_dir.display()))?
    {
        let letter_entry = letter_entry?;
        let letter_path = letter_entry.path();
        if !letter_path.is_dir() {
            continue;
        }

        for toml_entry in std::fs::read_dir(&letter_path)? {
            let toml_entry = toml_entry?;
            let toml_path = toml_entry.path();
            if toml_path.extension().map(|e| e == "toml").unwrap_or(false) {
                let content = std::fs::read_to_string(&toml_path)
                    .with_context(|| format!("reading {}", toml_path.display()))?;
                let toml = parse_package_toml_document(&content)
                    .with_context(|| format!("parsing {}", toml_path.display()))?;
                validate_package_layout(&toml_path, &toml.package.name).with_context(|| {
                    format!("validating package layout for {}", toml_path.display())
                })?;
                let mut metas = package_metas_for_platform(&toml, platform);
                if let Some(req) = version_req {
                    metas.retain(|meta| version_matches_req(&meta.version, req));
                }
                if metas.is_empty() {
                    continue;
                }
                if let Some(meta) = newest_version(&metas) {
                    packages.insert(meta.name.clone(), meta);
                }
                all_versions.extend(metas);
            }
        }
    }

    let hash_index = build_hash_index(&all_versions);
    Ok((packages, hash_index))
}

/// Parse a single package TOML file and extract the newest version for the
/// given platform. Returns `None` if the platform is not available.
///
/// # Errors
///
/// Returns an error if `content` is not valid package TOML.
pub fn parse_package_toml(content: &str, platform: &str) -> Result<Option<PackageMeta>> {
    let metas = parse_package_toml_versions(content, platform)?;
    Ok(newest_version(&metas))
}

/// Validate one package TOML file's declared name and shard path.
///
/// Returns the declared package name so callers that already need the name do
/// not have to duplicate the schema lookup.
///
/// # Errors
///
/// Returns an error if the TOML is invalid, the package name is not path-safe,
/// or the file does not live at `packages/<bucket>/<name>.toml`.
pub fn validate_package_file_layout(path: &Path, content: &str) -> Result<String> {
    let toml = parse_package_toml_document(content)?;
    validate_package_layout(path, &toml.package.name)?;
    Ok(toml.package.name)
}

fn parse_package_toml_document(content: &str) -> Result<PackageToml> {
    let toml: PackageToml = toml::from_str(content).context("invalid package TOML")?;
    validate_package_name(&toml.package.name)?;
    Ok(toml)
}

fn validate_package_layout(path: &Path, package_name: &str) -> Result<()> {
    let expected_file = format!("{package_name}.toml");
    let actual_file = path.file_name().and_then(|name| name.to_str());
    if actual_file != Some(expected_file.as_str()) {
        bail!(
            "package file name does not match package name '{package_name}': expected {expected_file}"
        );
    }

    let expected_bucket = package_name_bucket(package_name);
    let actual_bucket = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str());
    if actual_bucket != Some(expected_bucket.as_str()) {
        bail!(
            "package bucket does not match package name '{package_name}': expected {expected_bucket}"
        );
    }

    Ok(())
}

/// Parse a package TOML file into one [`PackageMeta`] per version that has an
/// entry for `platform`.
fn parse_package_toml_versions(content: &str, platform: &str) -> Result<Vec<PackageMeta>> {
    let toml = parse_package_toml_document(content)?;
    Ok(package_metas_for_platform(&toml, platform))
}

fn package_metas_for_platform(toml: &PackageToml, platform: &str) -> Vec<PackageMeta> {
    let mut metas = Vec::new();

    for ver in &toml.versions {
        if let Some(plat) = ver.platforms.get(platform) {
            let images: Vec<SysrootImageEntry> = plat
                .images
                .iter()
                .map(|img| SysrootImageEntry {
                    format: img.format.clone(),
                    store_path: img.store_path.clone(),
                    nar_hash: img.nar_hash.clone(),
                    nar_size: img.nar_size,
                })
                .collect();

            metas.push(PackageMeta {
                name: toml.package.name.clone(),
                version: ver.version.clone(),
                description: toml.package.description.clone(),
                homepage: toml.package.homepage.clone(),
                license: toml.package.license.clone(),
                maintainer: toml.package.maintainer.clone(),
                platform: platform.to_string(),
                store_path: plat.store_path.clone(),
                nar_hash: plat.nar_hash.clone(),
                nar_size: plat.nar_size,
                references: plat.references.clone(),
                source_drv: plat.source_drv.clone(),
                source_nar_hash: plat.source_nar_hash.clone(),
                closure_size: plat.closure_size,
                sysroot: toml.package.sysroot,
                previous: ver.previous.clone(),
                images,
            });
        }
    }

    metas
}

/// Select the newest version among parsed package metas.
fn newest_version(metas: &[PackageMeta]) -> Option<PackageMeta> {
    metas
        .iter()
        .max_by(|left, right| compare_registry_versions(&left.version, &right.version))
        .cloned()
}

fn version_matches_req(version: &str, req: &semver::VersionReq) -> bool {
    match semver::Version::parse(version) {
        Ok(version) => req.matches(&version),
        Err(_) => false,
    }
}

/// Order two version strings: semver pairs compare semantically, a semver
/// version outranks a non-semver one, and two non-semver versions (e.g.
/// calver like `2026.04`) fall back to lexicographic comparison.
fn compare_registry_versions(left: &str, right: &str) -> Ordering {
    match (semver::Version::parse(left), semver::Version::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        (Ok(_), Err(_)) => Ordering::Greater,
        (Err(_), Ok(_)) => Ordering::Less,
        (Err(_), Err(_)) => left.cmp(right),
    }
}

/// Build a hash-to-package-metadata reverse index from all package versions.
///
/// Keys are store path hashes as returned by [`store_path_hash`]; later
/// entries with the same hash overwrite earlier ones.
pub fn build_hash_index(packages: &[PackageMeta]) -> HashMap<String, PackageMeta> {
    let mut index = HashMap::new();
    for meta in packages {
        let hash = store_path_hash(&meta.store_path);
        index.insert(hash.to_string(), meta.clone());
    }
    index
}

/// Extract the hash component from a store path.
///
/// The hash is the basename segment before the first `-`:
/// `"/var/lib/store/abc123def456-curl-8.5.0"` -> `"abc123def456"`.
/// Inputs without a `/` or `-` are returned unchanged rather than failing.
pub fn store_path_hash(store_path: &str) -> &str {
    let basename = store_path.rsplit('/').next().unwrap_or(store_path);
    // Hash is everything before the first '-'
    basename.split('-').next().unwrap_or(basename)
}

// Test fixtures used by both parse.rs and mod.rs tests.
#[cfg(test)]
pub(crate) const CURL_TOML: &str = r#"
[package]
name = "curl"
description = "Command-line tool and library for URL transfers"
homepage = "https://curl.se"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "8.5.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/h7j3k8l2m9n4-curl-8.5.0"
nar_hash = "sha256:aabbcc"
nar_size = 3145728
closure_size = 52428800
source_drv = "/var/lib/store/i8k4l9m3n0o5-curl-8.5.0.drv"
source_nar_hash = "sha256:112233"
references = ["xr5is7by89v3q", "r4q1m2kp8v3x", "q8mn2pv73w0x", "kl9m3n0o5p6q"]

[versions.platforms.aarch64-linux]
store_path = "/var/lib/store/z1y2x3w4v5u6-curl-8.5.0"
nar_hash = "sha256:aabbdd"
nar_size = 3200000
closure_size = 54000000
source_drv = "/var/lib/store/a9b8c7d6e5f4-curl-8.5.0.drv"
source_nar_hash = "sha256:445566"
references = ["u6v3o4mr1x5z", "w8x9y0z1a2b3"]
"#;

#[cfg(test)]
pub(crate) const ZLIB_TOML: &str = r#"
[package]
name = "zlib"
description = "General-purpose lossless data compression library"
homepage = "https://zlib.net"
license = "Zlib"
maintainer = "aos-team"

[[versions]]
version = "1.3.1"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/r4q1m2kp8v3x-zlib-1.3.1"
nar_hash = "sha256:abc123"
nar_size = 524288
closure_size = 524288
source_drv = "/var/lib/store/s5t2n3lq9w4y-zlib-1.3.1.drv"
source_nar_hash = "sha256:789abc"
references = []
"#;

#[cfg(test)]
pub(crate) const MULTI_VERSION_TOML: &str = r#"
[package]
name = "tool"
description = "Multi-version package"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/oldhash111111-tool-1.0.0"
nar_hash = "sha256:abc123"
nar_size = 128
closure_size = 128
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "2.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/newhash222222-tool-2.0.0"
nar_hash = "sha256:def456"
nar_size = 256
closure_size = 256
source_drv = ""
source_nar_hash = ""
references = []
"#;

#[cfg(test)]
const MULTI_VERSION_CALVER_TOML: &str = r#"
[package]
name = "server"
description = "Multi-version system package"
license = "MIT"
maintainer = "aos-team"
sysroot = true

[[versions]]
version = "2026.03"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/calverold111-server-2026.03"
nar_hash = "sha256:abc123"
nar_size = 128
closure_size = 128
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "2026.04"
previous = "2026.03"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/calvernew222-server-2026.04"
nar_hash = "sha256:def456"
nar_size = 256
closure_size = 256
source_drv = ""
source_nar_hash = ""
references = []
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_curl_x86() {
        let meta = parse_package_toml(CURL_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();
        assert_eq!(meta.name, "curl");
        assert_eq!(meta.version, "8.5.0");
        assert_eq!(
            meta.description,
            "Command-line tool and library for URL transfers"
        );
        assert_eq!(meta.homepage.as_deref(), Some("https://curl.se"));
        assert_eq!(meta.license, "MIT");
        assert_eq!(meta.platform, "x86_64-linux");
        assert_eq!(meta.nar_size, 3145728);
        assert_eq!(meta.references.len(), 4);
        assert_eq!(meta.references[0], "xr5is7by89v3q");
    }

    #[test]
    fn parse_curl_aarch64() {
        let meta = parse_package_toml(CURL_TOML, "aarch64-linux")
            .unwrap()
            .unwrap();
        assert_eq!(meta.platform, "aarch64-linux");
        assert_eq!(meta.nar_size, 3200000);
    }

    #[test]
    fn parse_curl_unknown_platform() {
        let meta = parse_package_toml(CURL_TOML, "riscv64-linux").unwrap();
        assert!(meta.is_none());
    }

    #[test]
    fn parse_zlib_leaf() {
        let meta = parse_package_toml(ZLIB_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();
        assert_eq!(meta.name, "zlib");
        assert!(meta.references.is_empty());
    }

    #[test]
    fn parse_package_toml_rejects_path_like_package_name() {
        let content = CURL_TOML.replace("name = \"curl\"", "name = \"../curl\"");
        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(err.to_string().contains("package name"));
    }

    #[test]
    fn parse_package_toml_selects_newest_semver_version() {
        let meta = parse_package_toml(MULTI_VERSION_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();
        assert_eq!(meta.version, "2.0.0");
        assert_eq!(store_path_hash(&meta.store_path), "newhash222222");
    }

    #[test]
    fn parse_package_toml_selects_newest_non_semver_version() {
        let meta = parse_package_toml(MULTI_VERSION_CALVER_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();
        assert_eq!(meta.version, "2026.04");
        assert_eq!(meta.previous.as_deref(), Some("2026.03"));
        assert_eq!(store_path_hash(&meta.store_path), "calvernew222");
    }

    #[test]
    fn store_path_hash_extraction() {
        assert_eq!(
            store_path_hash("/var/lib/store/h7j3k8l2m9n4-curl-8.5.0"),
            "h7j3k8l2m9n4"
        );
        assert_eq!(
            store_path_hash("/var/lib/store/r4q1m2kp8v3x-zlib-1.3.1"),
            "r4q1m2kp8v3x"
        );
    }

    #[test]
    fn hash_index_maps_package_hash_to_exact_metadata() {
        let curl = parse_package_toml(CURL_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();
        let zlib = parse_package_toml(ZLIB_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();

        let index = build_hash_index(&[curl, zlib]);

        assert_eq!(index.get("h7j3k8l2m9n4").unwrap().name, "curl");
        assert_eq!(index.get("r4q1m2kp8v3x").unwrap().name, "zlib");
    }

    #[test]
    fn hash_index_keeps_multiple_versions_distinct() {
        let versions = parse_package_toml_versions(MULTI_VERSION_TOML, "x86_64-linux")
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();

        let index = build_hash_index(&versions);

        assert_eq!(index.get("oldhash111111").unwrap().version, "1.0.0");
        assert_eq!(index.get("newhash222222").unwrap().version, "2.0.0");
    }

    #[test]
    fn parse_registry_filters_versions_by_semver_constraint() {
        let tmp = tempfile::TempDir::new().unwrap();
        let packages_dir = tmp.path().join("packages").join("t");
        std::fs::create_dir_all(&packages_dir).unwrap();
        std::fs::write(packages_dir.join("tool.toml"), MULTI_VERSION_TOML).unwrap();

        let req = semver::VersionReq::parse("^1.0").unwrap();
        let (packages, index) =
            parse_registry_matching(tmp.path(), "x86_64-linux", Some(&req)).unwrap();

        assert_eq!(packages.get("tool").unwrap().version, "1.0.0");
        assert!(index.contains_key("oldhash111111"));
        assert!(!index.contains_key("newhash222222"));
    }

    #[test]
    fn parse_registry_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let packages_dir = tmp.path().join("packages");

        // Create structure: packages/c/curl.toml, packages/z/zlib.toml
        let c_dir = packages_dir.join("c");
        let z_dir = packages_dir.join("z");
        std::fs::create_dir_all(&c_dir).unwrap();
        std::fs::create_dir_all(&z_dir).unwrap();
        std::fs::write(c_dir.join("curl.toml"), CURL_TOML).unwrap();
        std::fs::write(z_dir.join("zlib.toml"), ZLIB_TOML).unwrap();

        let (packages, index) = parse_registry(tmp.path(), "x86_64-linux").unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.contains_key("curl"));
        assert!(packages.contains_key("zlib"));
        assert!(index.contains_key("h7j3k8l2m9n4")); // curl hash
        assert!(index.contains_key("r4q1m2kp8v3x")); // zlib hash
    }

    #[test]
    fn parse_registry_rejects_package_file_name_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let packages_dir = tmp.path().join("packages").join("c");
        std::fs::create_dir_all(&packages_dir).unwrap();
        std::fs::write(packages_dir.join("not-curl.toml"), CURL_TOML).unwrap();

        let err = parse_registry(tmp.path(), "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("package file name"));
    }

    #[test]
    fn parse_registry_rejects_package_bucket_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let packages_dir = tmp.path().join("packages").join("z");
        std::fs::create_dir_all(&packages_dir).unwrap();
        std::fs::write(packages_dir.join("curl.toml"), CURL_TOML).unwrap();

        let err = parse_registry(tmp.path(), "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("package bucket"));
    }

    #[test]
    fn parse_empty_registry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (packages, index) = parse_registry(tmp.path(), "x86_64-linux").unwrap();
        assert!(packages.is_empty());
        assert!(index.is_empty());
    }
}
