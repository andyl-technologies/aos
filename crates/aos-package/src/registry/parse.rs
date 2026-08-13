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
//! closure_size = 52428800
//! source_drv = "/var/lib/store/...-curl-8.5.0.drv"
//! source_nar_hash = "sha256:..."
//!
//! [versions.platforms.x86_64-linux.references]
//! hashes = ["r4q1m2kp8v3x"]
//! min-format = 1
//! requires-features = ["expose-v1", "permissions-v1"]
//! # nar_hash/nar_size may appear in pre-RFC-0005 registries; newer ones
//! # publish the output's content binding in the store/ graph instead.
//! ```
//!
//! [`parse_registry`] walks the whole cache directory and flattens it into
//! the per-platform [`PackageMeta`] maps used by the registry resolver: a
//! name-to-newest-version map for normal resolution and a store-path-hash
//! index over every version for reverse lookups.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::types::{
    PackageMeta, SysrootImageEntry, package_name_bucket, validate_supported_package_meta,
};

// ---------------------------------------------------------------------------
// Package TOML schema (registry format)
// ---------------------------------------------------------------------------

// The pure manifest schema structs moved to the wasm-clean `aos-registry-surface`
// crate (RFC-0004 Phase 5) so the registry hub's `Database`/indexer and the
// Cloudflare Worker can share them without pulling `aos-package` (which is
// native-only). Re-exported here so `aos_package::registry::parse::{PackageToml,
// …}` paths are unchanged. The canonical structs carry the RFC-0005 `store/`
// graph fields (`source_drv`/`source_nar_hash`, legacy `nar_hash`/`nar_size`),
// the RFC-0006 Secure Boot image facts (`sb_signer_cert_sha256`/`sbat`/
// `expected_pcr11`), and the RFC-0001 package-sandboxing metadata (the
// structural `references` gate plus the `expose`/`permissions`/`bpf_lsm`/
// attestation fields and their helper impls such as `PlatformEntry::attestation`
// and the `ReferenceField` accessors).
pub use aos_registry_surface::manifest::{
    ImageCompression, ImageDelivery, ImageEntry, ImageInfoReference, ImageTarget, ImageUkiIdentity,
    ImageVerificationState, PackageHeader, PackageToml, PlatformEntry, ReferenceField,
    ReferenceGate, VersionEntry, immutable_image_info_object_key, immutable_image_object_key,
};

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
    let (packages, hash_index, _) = parse_registry_matching(dir, platform, None)?;
    Ok((packages, hash_index))
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
) -> Result<(
    HashMap<String, PackageMeta>,
    HashMap<String, PackageMeta>,
    Vec<PackageMeta>,
)> {
    let packages_dir = dir.join("packages");
    let mut packages = HashMap::new();
    let mut all_versions = Vec::new();

    if !packages_dir.is_dir() {
        return Ok((packages, HashMap::new(), all_versions));
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
                let metas = package_metas_for_platform(&toml, platform, version_req)
                    .with_context(|| format!("validating {}", toml_path.display()))?;
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
    Ok((packages, hash_index, all_versions))
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

/// Parse a single package TOML file into its full multi-platform document.
///
/// Unlike [`parse_package_toml`], which flattens to the newest version for
/// one platform, this returns the complete file: every version and every
/// platform entry, exactly as committed. Consumers that index or display a
/// whole registry (rather than resolve one install) need the unflattened
/// view — the registry hub's indexer is the canonical caller.
///
/// # Errors
///
/// Returns an error if `content` is not valid package TOML or the declared
/// package name is not path-safe.
pub fn parse_package_file(content: &str) -> Result<PackageToml> {
    parse_package_toml_document(content)
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
    aos_registry_surface::manifest::parse_package_file(content)
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
    package_metas_for_platform(&toml, platform, None)
}

fn package_metas_for_platform(
    toml: &PackageToml,
    platform: &str,
    version_req: Option<&semver::VersionReq>,
) -> Result<Vec<PackageMeta>> {
    let mut metas = Vec::new();

    for ver in &toml.versions {
        if version_req.is_some_and(|req| !version_matches_req(&ver.version, req)) {
            continue;
        }
        if let Some(plat) = ver.platforms.get(platform) {
            let images: Vec<SysrootImageEntry> = plat
                .images
                .iter()
                .map(|img| SysrootImageEntry {
                    format: img.format.clone(),
                    store_path: img.store_path.clone(),
                    nar_hash: img.nar_hash.clone(),
                    nar_size: img.nar_size,
                    delivery: img.delivery.clone(),
                    sb_signer_cert_sha256: img.sb_signer_cert_sha256.clone(),
                    sbat: img.sbat.clone(),
                    expected_pcr11: img.expected_pcr11.clone(),
                    ukis: img.ukis.clone(),
                    root_image: img.root_image.clone(),
                    root_verity: img.root_verity.clone(),
                    root_hash: img.root_hash.clone(),
                    root_hash_sig: img.root_hash_sig.clone(),
                })
                .collect();

            let min_format = max_optional_format(plat.min_format, plat.references.min_format());
            let requires_features =
                merge_features(&plat.requires_features, plat.references.requires_features());
            let attestation = plat.attestation();
            let meta = PackageMeta {
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
                references: plat.references.hashes().to_vec(),
                source_drv: plat.source_drv.clone(),
                source_nar_hash: plat.source_nar_hash.clone(),
                closure_size: plat.closure_size,
                sysroot: toml.package.sysroot,
                previous: ver.previous.clone(),
                images,
                min_format,
                requires_features,
                expose: plat.expose.clone(),
                expose_artifact: plat.expose_artifact.clone(),
                config_module: plat.config_module.clone(),
                permissions: plat.permissions.clone(),
                bpf_lsm: plat.bpf_lsm.clone(),
                attestation,
            };
            if (meta.expose.is_some()
                || meta.expose_artifact.is_some()
                || !meta.permissions.is_empty()
                || meta
                    .bpf_lsm
                    .as_ref()
                    .is_some_and(|bpf_lsm| !bpf_lsm.is_empty())
                || !meta.attestation.is_empty())
                && !plat.references.is_gate()
            {
                bail!(
                    "package '{}' uses RFC-0001 metadata without the structural references gate",
                    meta.name
                );
            }
            validate_supported_package_meta(&meta)?;
            metas.push(meta);
        }
    }

    Ok(metas)
}

fn merge_features(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .chain(right)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn max_optional_format(left: Option<u32>, right: Option<u32>) -> Option<u32> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
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
const EXPOSED_TOML: &str = r#"
[package]
name = "webapp"
description = "Exposed web app"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/webapphash11-webapp-1.0.0"
nar_hash = "sha256:abc123"
nar_size = 1024
closure_size = 1024
source_drv = ""
source_nar_hash = ""
root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
provenance = "attestation/webapp.provenance.jsonl"
measurement = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1", "expose-v1", "permissions-v1", "requires-v1", "network-policy-v1"]

[versions.platforms.x86_64-linux.expose]
target = "aos-pkg-webapp.target"
units = ["webapp.service"]
requires = ["zlib"]

[[versions.platforms.x86_64-linux.expose.images]]
format = "dir"
store_path = "/var/lib/store/webapproot-webapp-root"
nar_hash = "sha256:root"
nar_size = 2048

[versions.platforms.x86_64-linux.permissions]
network = "private-outbound"
tcp-bind = [8080]
tcp-connect = [443]
capabilities = ["CAP_NET_BIND_SERVICE"]
host-paths = [{ path = "/srv/webapp", mode = "read-only" }]
syscalls = "system-service"

[versions.platforms.x86_64-linux.permissions.confinement]
class = "sandboxed-with-holes"
label = "sandboxed-with-holes (network:private-outbound, tcp-bind:8080, tcp-connect:443, capability:CAP_NET_BIND_SERVICE, host-path:read-only:/srv/webapp, syscalls:system-service)"
holes = ["network:private-outbound", "tcp-bind:8080", "tcp-connect:443", "capability:CAP_NET_BIND_SERVICE", "host-path:read-only:/srv/webapp", "syscalls:system-service"]
"#;

#[cfg(test)]
const BPF_LSM_TOML: &str = r#"
[package]
name = "aos-ebpf-lsm-policy"
description = "Fleet BPF-LSM policy"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/bpflsmhash12-aos-ebpf-lsm-policy-0"
nar_hash = "sha256:abc123"
nar_size = 1024
closure_size = 1024
source_drv = ""
source_nar_hash = ""
root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
provenance = "attestation/aos-ebpf-lsm-policy.provenance.jsonl"
measurement = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1", "bpf-lsm-policy-v1"]

[versions.platforms.x86_64-linux.bpf_lsm]

[[versions.platforms.x86_64-linux.bpf_lsm.policies]]
name = "aos-lsm-task-audit"
policy = "share/aos/ebpf-lsm/aos-task-audit.json"
object = "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
programs = ["aos_lsm_file_mprotect"]
"#;

#[cfg(test)]
const ATTESTATION_TOML: &str = r#"
[package]
name = "verity-app"
description = "Package root with verity attestation"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/verityhash12-verity-app-1.0.0"
nar_hash = "sha256:abc123"
nar_size = 1024
closure_size = 1024
source_drv = ""
source_nar_hash = ""

root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
root_hash_sig = "attestation/verity-app.roothash.p7s"
provenance = "attestation/verity-app.provenance.jsonl"
measurement = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1"]
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
    use crate::types::{ConfinementClass, HostPathMode, NetworkPermission, SyscallProfile};

    const MISSING_DELIVERY_IMAGE_TOML: &str = r#"
[package]
name = "server"
description = "AOS server"
license = "MIT"
maintainer = "aos-team"
sysroot = true

[[versions]]
version = "2026.08"

[versions.platforms.x86_64-linux]
store_path = "/aos/store/serverhash-server-2026.08"
closure_size = 1
source_drv = ""
source_nar_hash = ""

[[versions.platforms.x86_64-linux.images]]
format = "raw"
store_path = "/aos/store/imagehash-server-raw"
nar_hash = "sha256:missing-delivery"
nar_size = 10
"#;

    fn direct_image_toml(format: &str) -> String {
        let image_sha256 = "a".repeat(64);
        let info_sha256 = "b".repeat(64);
        let (extension, media_type, targets) = match format {
            "raw" => (
                "img.zst",
                "application/vnd.aos.disk-image.raw+zstd",
                "\"bare-metal\"",
            ),
            "qcow2" => (
                "qcow2",
                "application/vnd.aos.disk-image.qcow2",
                "\"qemu-kvm\", \"openstack\"",
            ),
            "vmdk" => ("vmdk", "application/x-vmdk", "\"vmware\""),
            "vhd" => ("vhd", "application/vnd.aos.disk-image.vhd", "\"hyper-v\""),
            other => panic!("unsupported fixture format {other}"),
        };
        let filename = format!("aos-server.{extension}");
        let object_key = immutable_image_object_key(&image_sha256, &filename);
        let info_key = immutable_image_info_object_key(&image_sha256, &info_sha256);
        let compression = if format == "raw" { "zstd" } else { "none" };
        format!(
            r#"
[package]
name = "server"
description = "AOS server"
license = "MIT"
maintainer = "aos-team"
sysroot = true

[[versions]]
version = "2026.08"

[versions.platforms.x86_64-linux]
store_path = "/aos/store/serverhash-server-2026.08"
closure_size = 1
source_drv = ""
source_nar_hash = ""

[[versions.platforms.x86_64-linux.images]]
format = "{format}"
store_path = "/aos/store/imagehash-server-{format}"
nar_hash = "sha256:nar"
nar_size = 10

[versions.platforms.x86_64-linux.images.delivery]
schema_version = 1
release = "2026.08"
platform = "x86_64-linux"
architecture = "x86_64"
logical_image_id = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
logical_disk_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
rootfs_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
filename = "{filename}"
object_key = "{object_key}"
media_type = "{media_type}"
compression = "{compression}"
byte_size = 10
sha256 = "{image_sha256}"
compatible_targets = [{targets}]

[versions.platforms.x86_64-linux.images.delivery.uki]
filename = "aos-server.efi"
esp_path = "EFI/Linux/aos-server.efi"
byte_size = 1024
sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
verification = "unsigned"

[versions.platforms.x86_64-linux.images.delivery.image_info]
filename = "image-info.json"
object_key = "{info_key}"
media_type = "application/vnd.aos.image-info+json"
byte_size = 20
sha256 = "{info_sha256}"
"#
        )
    }

    #[test]
    fn old_signed_image_catalog_remains_store_install_compatible() {
        let meta = parse_package_toml(MISSING_DELIVERY_IMAGE_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();
        assert_eq!(meta.images.len(), 1);
        assert!(meta.images[0].delivery.is_store_only());
        assert_eq!(meta.images[0].store_path, "/aos/store/imagehash-server-raw");
    }

    #[test]
    fn complete_signed_image_entries_parse_for_every_supported_format() {
        for format in ["raw", "qcow2", "vmdk", "vhd"] {
            let meta = parse_package_toml(&direct_image_toml(format), "x86_64-linux")
                .unwrap()
                .unwrap();
            let delivery = &meta.images[0].delivery;
            assert_eq!(delivery.release, "2026.08");
            assert_eq!(delivery.platform, "x86_64-linux");
            assert_eq!(delivery.architecture, "x86_64");
        }
    }

    #[test]
    fn signed_image_entry_rejects_tamper_and_path_traversal() {
        let base = direct_image_toml("raw");
        for tampered in [
            base.replace("release = \"2026.08\"", "release = \"2026.07\""),
            base.replace("sha256 = \"aaaaaaaa", "sha256 = \"Aaaaaaaa"),
            base.replace(
                "filename = \"aos-server.img\"",
                "filename = \"../server.img\"",
            ),
            base.replace(
                "compatible_targets = [\"bare-metal\"]",
                "compatible_targets = [\"vmware\"]",
            ),
        ] {
            assert!(parse_package_file(&tampered).is_err());
        }
    }

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
    fn parse_expose_and_permissions_metadata() {
        let meta = parse_package_toml(EXPOSED_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();

        assert_eq!(meta.min_format, Some(1));
        assert_eq!(
            meta.requires_features,
            vec![
                "attestation-v1",
                "expose-v1",
                "network-policy-v1",
                "permissions-v1",
                "requires-v1",
            ]
        );
        let expose = meta.expose.as_ref().unwrap();
        assert_eq!(expose.target, "aos-pkg-webapp.target");
        assert_eq!(expose.units, vec!["webapp.service"]);
        assert_eq!(expose.requires, vec!["zlib"]);
        assert_eq!(expose.images.len(), 1);
        assert_eq!(expose.images[0].format, "dir");
        assert_eq!(
            meta.permissions.network,
            Some(NetworkPermission::PrivateOutbound)
        );
        assert_eq!(meta.permissions.tcp_bind, vec![8080]);
        assert_eq!(meta.permissions.tcp_connect, vec![443]);
        assert_eq!(meta.permissions.capabilities, vec!["CAP_NET_BIND_SERVICE"]);
        assert_eq!(meta.permissions.host_paths.len(), 1);
        assert_eq!(meta.permissions.host_paths[0].mode, HostPathMode::ReadOnly);
        assert_eq!(
            meta.permissions.syscalls,
            Some(SyscallProfile::SystemService)
        );
        let confinement = meta.permissions.confinement.as_ref().unwrap();
        assert_eq!(confinement.class, ConfinementClass::SandboxedWithHoles);
        assert_eq!(
            confinement.label,
            "sandboxed-with-holes (network:private-outbound, tcp-bind:8080, tcp-connect:443, capability:CAP_NET_BIND_SERVICE, host-path:read-only:/srv/webapp, syscalls:system-service)"
        );
        assert_eq!(
            confinement.holes,
            vec![
                "network:private-outbound".to_string(),
                "tcp-bind:8080".to_string(),
                "tcp-connect:443".to_string(),
                "capability:CAP_NET_BIND_SERVICE".to_string(),
                "host-path:read-only:/srv/webapp".to_string(),
                "syscalls:system-service".to_string(),
            ]
        );
    }

    #[test]
    fn parse_expose_rejects_target_bound_to_other_package() {
        let content = EXPOSED_TOML.replace(
            r#"target = "aos-pkg-webapp.target""#,
            r#"target = "aos-pkg-other.target""#,
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();

        assert!(
            format!("{err:#}").contains("must equal aos-pkg-webapp.target"),
            "{err:#}"
        );
    }

    #[test]
    fn parse_expose_verity_image_metadata() {
        let content = EXPOSED_TOML.replace(
            r#"[[versions.platforms.x86_64-linux.expose.images]]
format = "dir"
store_path = "/var/lib/store/webapproot-webapp-root"
nar_hash = "sha256:root"
nar_size = 2048
"#,
            r#"[[versions.platforms.x86_64-linux.expose.images]]
format = "ext4-verity"
store_path = "/var/lib/store/webapproot-webapp-root"
nar_hash = "sha256:root"
nar_size = 2048
root_image = "root.img"
root_verity = "root.verity"
root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
root_hash_sig = "root.roothash.p7s"
"#,
        );

        let meta = parse_package_toml(&content, "x86_64-linux")
            .unwrap()
            .unwrap();
        let image = &meta.expose.as_ref().unwrap().images[0];

        assert_eq!(image.format, "ext4-verity");
        assert_eq!(image.root_image.as_deref(), Some("root.img"));
        assert_eq!(image.root_verity.as_deref(), Some("root.verity"));
        assert_eq!(
            image.root_hash.as_deref(),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(image.root_hash_sig.as_deref(), Some("root.roothash.p7s"));
    }

    #[test]
    fn parse_bpf_lsm_policy_metadata() {
        let meta = parse_package_toml(BPF_LSM_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();

        assert_eq!(meta.min_format, Some(1));
        assert_eq!(
            meta.requires_features,
            vec!["attestation-v1", "bpf-lsm-policy-v1"]
        );
        let bpf_lsm = meta.bpf_lsm.as_ref().unwrap();
        assert_eq!(bpf_lsm.policies.len(), 1);
        assert_eq!(bpf_lsm.policies[0].name, "aos-lsm-task-audit");
        assert_eq!(
            bpf_lsm.policies[0].object,
            "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
        );
        assert_eq!(bpf_lsm.policies[0].programs, vec!["aos_lsm_file_mprotect"]);
    }

    #[test]
    fn parse_bpf_lsm_metadata_requires_structural_gate() {
        let content = BPF_LSM_TOML.replace(
            r#"[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1", "bpf-lsm-policy-v1"]
"#,
            r#"references = []
min-format = 1
requires-features = ["attestation-v1", "bpf-lsm-policy-v1"]
"#,
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("structural references gate"));
    }

    #[test]
    fn parse_bpf_lsm_metadata_requires_own_feature_gate() {
        let content = BPF_LSM_TOML.replace("bpf-lsm-policy-v1", "ebpf-net-policy-v1");

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("bpf-lsm-policy-v1"));
    }

    #[test]
    fn parse_attestation_metadata() {
        let meta = parse_package_toml(ATTESTATION_TOML, "x86_64-linux")
            .unwrap()
            .unwrap();

        assert_eq!(meta.min_format, Some(1));
        assert_eq!(meta.requires_features, vec!["attestation-v1"]);
        assert_eq!(
            meta.attestation.root_hash.as_deref(),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            meta.attestation.root_hash_sig.as_deref(),
            Some("attestation/verity-app.roothash.p7s")
        );
        assert_eq!(
            meta.attestation.provenance.as_deref(),
            Some("attestation/verity-app.provenance.jsonl")
        );
        assert_eq!(
            meta.attestation.measurement.as_deref(),
            Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }

    #[test]
    fn parse_attestation_metadata_requires_structural_gate() {
        let content = ATTESTATION_TOML.replace(
            r#"[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1"]
"#,
            r#"references = []
min-format = 1
requires-features = ["attestation-v1"]
"#,
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("structural references gate"));
    }

    #[test]
    fn parse_attestation_metadata_requires_own_feature_gate() {
        let content = ATTESTATION_TOML.replace("attestation-v1", "permissions-v1");

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("attestation-v1"));
    }

    #[test]
    fn rfc0001_structural_gate_fails_old_reference_parser() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct LegacyPackageToml {
            versions: Vec<LegacyVersionEntry>,
        }

        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct LegacyVersionEntry {
            platforms: HashMap<String, LegacyPlatformEntry>,
        }

        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct LegacyPlatformEntry {
            references: Vec<String>,
        }

        let err = toml::from_str::<LegacyPackageToml>(EXPOSED_TOML).unwrap_err();
        assert!(err.to_string().contains("references"));
    }

    #[test]
    fn parse_rfc0001_metadata_requires_structural_gate() {
        let content = EXPOSED_TOML.replace(
            r#"[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1", "expose-v1", "permissions-v1", "requires-v1", "network-policy-v1"]
"#,
            r#"references = []
min-format = 1
requires-features = ["attestation-v1", "expose-v1", "permissions-v1", "requires-v1", "network-policy-v1"]
"#,
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("structural references gate"));
    }

    #[test]
    fn parse_permissions_rejects_unknown_fields() {
        let content = EXPOSED_TOML.replace(
            "[versions.platforms.x86_64-linux.permissions]\n",
            "[versions.platforms.x86_64-linux.permissions]\nfilesystem = \"host\"\n",
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn parse_permissions_rejects_invalid_capability() {
        let content = EXPOSED_TOML.replace("CAP_NET_BIND_SERVICE", "NET_BIND_SERVICE");

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("invalid capability"));
    }

    #[test]
    fn parse_expose_requires_feature_gate() {
        let content = EXPOSED_TOML.replace(
            "requires-features = [\"attestation-v1\", \"expose-v1\", \"permissions-v1\", \"requires-v1\", \"network-policy-v1\"]",
            "requires-features = [\"attestation-v1\", \"permissions-v1\", \"requires-v1\", \"network-policy-v1\"]",
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("expose-v1"));
    }

    #[test]
    fn parse_permissions_requires_feature_gate() {
        let content = EXPOSED_TOML.replace(
            "requires-features = [\"attestation-v1\", \"expose-v1\", \"permissions-v1\", \"requires-v1\", \"network-policy-v1\"]",
            "requires-features = [\"attestation-v1\", \"expose-v1\", \"requires-v1\", \"network-policy-v1\"]",
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("permissions-v1"));
    }

    #[test]
    fn parse_requires_rejects_unsupported_min_format() {
        let content = EXPOSED_TOML.replace("min-format = 1", "min-format = 2");

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("metadata format 2"));
    }

    #[test]
    fn parse_rejects_unknown_platform_fields() {
        let content = EXPOSED_TOML.replace(
            "source_nar_hash = \"\"\n",
            "source_nar_hash = \"\"\npermission = \"host\"\n",
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn parse_rejects_misplaced_package_permissions() {
        let content = EXPOSED_TOML.replace(
            "maintainer = \"aos-team\"\n",
            "maintainer = \"aos-team\"\n\n[package.permissions]\nnetwork = \"host\"\n",
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn parse_rejects_misplaced_version_expose() {
        let content = EXPOSED_TOML.replace(
            "version = \"1.0.0\"\n",
            "version = \"1.0.0\"\nexpose = { target = \"aos-pkg-webapp.target\" }\n",
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn parse_rejects_unknown_image_fields() {
        let content = EXPOSED_TOML.replace(
            "nar_size = 2048\n",
            "nar_size = 2048\npermission = \"host\"\n",
        );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn parse_structural_min_format_cannot_be_overridden_downward() {
        let content = EXPOSED_TOML
            .replace(
                "hashes = []\nmin-format = 1",
                "hashes = []\nmin-format = 99",
            )
            .replace(
                "source_nar_hash = \"\"\n",
                "source_nar_hash = \"\"\nmin-format = 1\n",
            );

        let err = parse_package_toml(&content, "x86_64-linux").unwrap_err();
        assert!(format!("{err:#}").contains("metadata format 99"));
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
        let (packages, index, versions) =
            parse_registry_matching(tmp.path(), "x86_64-linux", Some(&req)).unwrap();

        assert_eq!(packages.get("tool").unwrap().version, "1.0.0");
        assert!(index.contains_key("oldhash111111"));
        assert!(!index.contains_key("newhash222222"));
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn parse_registry_skips_future_format_versions_outside_constraint() {
        let tmp = tempfile::TempDir::new().unwrap();
        let packages_dir = tmp.path().join("packages").join("t");
        std::fs::create_dir_all(&packages_dir).unwrap();
        let content = MULTI_VERSION_TOML.replace(
            "store_path = \"/var/lib/store/newhash222222-tool-2.0.0\"",
            "store_path = \"/var/lib/store/newhash222222-tool-2.0.0\"\nmin-format = 99",
        );
        std::fs::write(packages_dir.join("tool.toml"), content).unwrap();

        let req = semver::VersionReq::parse("^1.0").unwrap();
        let (packages, index, versions) =
            parse_registry_matching(tmp.path(), "x86_64-linux", Some(&req)).unwrap();

        assert_eq!(packages.get("tool").unwrap().version, "1.0.0");
        assert!(index.contains_key("oldhash111111"));
        assert!(!index.contains_key("newhash222222"));
        assert_eq!(versions.len(), 1);
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
