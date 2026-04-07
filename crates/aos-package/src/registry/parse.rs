use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::types::{PackageMeta, SysrootImageEntry};

// ---------------------------------------------------------------------------
// Package TOML schema (registry format)
// ---------------------------------------------------------------------------

/// Top-level package TOML file from a registry.
#[derive(Debug, Deserialize)]
struct PackageToml {
    package: PackageHeader,
    #[serde(default)]
    versions: Vec<VersionEntry>,
}

#[derive(Debug, Deserialize)]
struct PackageHeader {
    name: String,
    description: String,
    #[serde(default)]
    homepage: Option<String>,
    license: String,
    maintainer: String,
    /// Whether this package is a system toplevel (sysroot).
    #[serde(default)]
    sysroot: bool,
}

#[derive(Debug, Deserialize)]
struct VersionEntry {
    version: String,
    /// Previous version in the version chain (for sysroot packages).
    #[serde(default)]
    previous: Option<String>,
    #[serde(default)]
    platforms: HashMap<String, PlatformEntry>,
}

#[derive(Debug, Deserialize)]
struct PlatformEntry {
    store_path: String,
    nar_hash: String,
    nar_size: u64,
    download_hash: String,
    download_size: u64,
    closure_size: u64,
    source_drv: String,
    source_nar_hash: String,
    #[serde(default)]
    references: Vec<String>,
    /// Pre-compiled images (only for sysroot packages).
    #[serde(default)]
    images: Vec<ImageEntry>,
}

/// A pre-compiled image entry within a platform entry.
#[derive(Debug, Deserialize)]
struct ImageEntry {
    format: String,
    store_path: String,
    nar_hash: String,
    nar_size: u64,
    download_hash: String,
    download_size: u64,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse all package TOML files in a registry cache directory.
///
/// Registry layout: `{cache_dir}/packages/{first_letter}/{name}.toml`
///
/// Returns `(packages, hash_index)` where `hash_index` maps store path
/// hashes to package names for reverse lookup during closure resolution.
pub fn parse_registry(
    dir: &Path,
    platform: &str,
) -> Result<(HashMap<String, PackageMeta>, HashMap<String, String>)> {
    let packages_dir = dir.join("packages");
    let mut packages = HashMap::new();

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
                match parse_package_toml(&content, platform) {
                    Ok(Some(meta)) => {
                        packages.insert(meta.name.clone(), meta);
                    }
                    Ok(None) => {
                        // No entry for this platform — skip
                    }
                    Err(e) => {
                        return Err(e.context(format!(
                            "parsing {}",
                            toml_path.display()
                        )));
                    }
                }
            }
        }
    }

    let hash_index = build_hash_index(&packages);
    Ok((packages, hash_index))
}

/// Parse a single package TOML file and extract the latest version for the
/// given platform. Returns `None` if the platform is not available.
pub fn parse_package_toml(content: &str, platform: &str) -> Result<Option<PackageMeta>> {
    let toml: PackageToml =
        toml::from_str(content).context("invalid package TOML")?;

    // Take the first (latest) version that has our platform
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
                    download_hash: img.download_hash.clone(),
                    download_size: img.download_size,
                })
                .collect();

            return Ok(Some(PackageMeta {
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
                download_hash: plat.download_hash.clone(),
                download_size: plat.download_size,
                references: plat.references.clone(),
                source_drv: plat.source_drv.clone(),
                source_nar_hash: plat.source_nar_hash.clone(),
                closure_size: plat.closure_size,
                sysroot: toml.package.sysroot,
                previous: ver.previous.clone(),
                images,
            }));
        }
    }

    Ok(None)
}

/// Build a hash-to-package-name reverse index from a set of packages.
///
/// Each package's store path hash AND all its reference hashes are indexed,
/// enabling O(1) lookup during closure resolution.
pub fn build_hash_index(
    packages: &HashMap<String, PackageMeta>,
) -> HashMap<String, String> {
    let mut index = HashMap::new();
    for (name, meta) in packages {
        let hash = store_path_hash(&meta.store_path);
        index.insert(hash.to_string(), name.clone());
        // Also index all references (they should map back to packages in the
        // same registry for registry-scoped resolution)
        for ref_hash in &meta.references {
            // Don't overwrite if already set — the package's own hash takes priority
            index.entry(ref_hash.clone()).or_insert_with(|| name.clone());
        }
    }
    // Fix: re-insert package's own hashes to ensure they win over reference entries
    for (name, meta) in packages {
        let hash = store_path_hash(&meta.store_path);
        index.insert(hash.to_string(), name.clone());
    }
    index
}

/// Extract the hash component from a store path.
///
/// `"/var/lib/store/abc123def456-curl-8.5.0"` -> `"abc123def456"`
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
download_hash = "sha256:ddeeff"
download_size = 1048576
closure_size = 52428800
source_drv = "/var/lib/store/i8k4l9m3n0o5-curl-8.5.0.drv"
source_nar_hash = "sha256:112233"
references = ["xr5is7by89v3q", "r4q1m2kp8v3x", "q8mn2pv73w0x", "kl9m3n0o5p6q"]

[versions.platforms.aarch64-linux]
store_path = "/var/lib/store/z1y2x3w4v5u6-curl-8.5.0"
nar_hash = "sha256:aabbdd"
nar_size = 3200000
download_hash = "sha256:ddeefg"
download_size = 1100000
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
download_hash = "sha256:def456"
download_size = 196608
closure_size = 524288
source_drv = "/var/lib/store/s5t2n3lq9w4y-zlib-1.3.1.drv"
source_nar_hash = "sha256:789abc"
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
        assert_eq!(meta.description, "Command-line tool and library for URL transfers");
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
    fn hash_index_maps_package_hash_to_name() {
        let mut packages = HashMap::new();
        let curl = parse_package_toml(CURL_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();
        let zlib = parse_package_toml(ZLIB_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();
        packages.insert("curl".into(), curl);
        packages.insert("zlib".into(), zlib);

        let index = build_hash_index(&packages);

        // curl's own hash maps to "curl"
        assert_eq!(index.get("h7j3k8l2m9n4"), Some(&"curl".to_string()));
        // zlib's own hash maps to "zlib"
        assert_eq!(index.get("r4q1m2kp8v3x"), Some(&"zlib".to_string()));
        // curl's reference to zlib also resolves to "zlib" (package's own hash wins)
        assert_eq!(index.get("r4q1m2kp8v3x"), Some(&"zlib".to_string()));
    }

    #[test]
    fn hash_index_includes_references() {
        let mut packages = HashMap::new();
        let curl = parse_package_toml(CURL_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();
        packages.insert("curl".into(), curl);

        let index = build_hash_index(&packages);

        // All of curl's references should be in the index
        assert!(index.contains_key("xr5is7by89v3q"));
        assert!(index.contains_key("r4q1m2kp8v3x"));
        assert!(index.contains_key("q8mn2pv73w0x"));
        assert!(index.contains_key("kl9m3n0o5p6q"));
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
    fn parse_empty_registry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (packages, index) = parse_registry(tmp.path(), "x86_64-linux").unwrap();
        assert!(packages.is_empty());
        assert!(index.is_empty());
    }
}
