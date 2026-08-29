//! `apm verify` and `apm source` commands.
//!
//! - `verify <pkg>`: compare the installed NAR hash against the registry
//!   entry for the *installed* store path (not the latest candidate, which
//!   may differ after a rollback) — detects on-disk tampering.
//! - `source <pkg>`: inspect a package's source provenance. Every registry
//!   package records the derivation it was built from (`source_drv`) and the
//!   hash of that source (`source_nar_hash`). The command can print those
//!   fields, realise the derivation locally (`--fetch`), or rebuild from
//!   source and compare the rebuilt NAR hash against the installed binary
//!   (`--verify`) for reproducibility auditing.
//!
//! Source metadata for installed packages is preferred from the profile's
//! own [`ApmMeta`](crate::types::ApmMeta) record (which survives registry
//! churn), falling back to the registry entry matched by store-path hash.

use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result, bail};

use super::config::ApmConfig;
use super::download::{
    DownloadRequest, default_engine, download_nars, fetch_narinfo_closure, resolve_mirror_chain,
    split_mirror_chain,
};
use super::profile::Profile;
use super::profile::meta;
use super::registry::{RegistrySet, store_path_hash};
use super::store::filter_missing;
use super::types::{InstalledMeta, PackageMeta};
use super::verify as hash_verify;
use aos_core::error::AosError;
use aos_core::nix::aos_nix_env;
use aos_core::output::{OutputMode, Printer};

// ---------------------------------------------------------------------------
// Platform detection (shared helper)
// ---------------------------------------------------------------------------

/// Nix platform string for the running binary, defaulting to x86_64-linux.
fn current_platform() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64-linux"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-linux"
    } else {
        "x86_64-linux"
    }
}

// ---------------------------------------------------------------------------
// apm verify <package>
// ---------------------------------------------------------------------------

/// Verify an installed package's NAR hash against the registry.
///
/// 1. Look up the package in the profile metadata.
/// 2. Look up the package in the registry to get `nar_hash`.
/// 3. Run `nix-store --dump` on the installed store path.
/// 4. Hash the NAR content with SHA-256.
/// 5. Compare against the registry's `nar_hash`.
///
/// # Errors
///
/// Returns [`AosError::PackageNotFound`] if `package` is not installed, an
/// error if the installed store-path hash cannot be matched in its
/// registry, a hash-mismatch error if the on-disk contents have been
/// modified, or any failure from loading registries / running
/// `nix-store --dump`.
pub async fn run_verify(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    printer.header(&format!("Verifying package '{package}'..."));

    // 1. Open profile and find installed metadata.
    let profile = Profile::open_readonly(config.scope);
    let all_meta = meta::list_meta(&profile)?;

    let installed = all_meta
        .iter()
        .find(|m| m.apm.as_ref().map(|a| a.name == package).unwrap_or(false))
        .ok_or_else(|| AosError::PackageNotFound {
            name: package.to_string(),
        })?;

    let store_path = &installed.store_path;
    let installed_apm = installed
        .apm
        .as_ref()
        .ok_or_else(|| AosError::PackageNotFound {
            name: package.to_string(),
        })?;

    // 2. Load registries and resolve the exact installed package entry for
    // its NAR hash. The latest registry candidate may differ after rollback.
    let enabled = config.enabled_registries();
    let reg_set = RegistrySet::load(&config.cache_path(), &enabled, current_platform())?;
    let pkg_meta = resolve_installed_package_meta(&reg_set, package, installed)?;

    // Prefer the signed store/ graph: a path may have multiple blessed NARs,
    // and an honest install matching any of them is intact. Fall back to the
    // (legacy or enriched) single TOML nar_hash only when the registry
    // publishes no graph for this path.
    let installed_hash = store_path_hash(&pkg_meta.store_path);
    let source_graph_present = reg_set
        .get_registry(&installed_apm.registry)
        .map(|reg| reg.store_map().is_present())
        .unwrap_or(false);
    let blessed = reg_set
        .get_registry(&installed_apm.registry)
        .map(|reg| reg.store_map().blessed_nars(installed_hash))
        .unwrap_or_default();

    // The source registry publishes a graph but has no record for this path:
    // same stripped/malformed condition the install path rejects
    // (verify_downloads) - surface it clearly rather than verifying against an
    // empty enriched hash.
    if blessed.is_empty() && source_graph_present {
        bail!(
            "no store/ record for installed '{package}' ({installed_hash}); the registry \
             '{}' may be malformed or its realisation graph stripped",
            installed_apm.registry,
        );
    }

    printer.kv("Store path", store_path);
    let expected_hash = pkg_meta.nar_hash.clone();
    if blessed.is_empty() {
        printer.kv("Expected NAR hash", &expected_hash);
    } else {
        printer.kv(
            "Expected NAR hash",
            &blessed
                .iter()
                .map(|nar| nar.nar_hash())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    // 3-4. Run nix-store --dump and hash the output.
    let verify_result = if blessed.is_empty() {
        hash_verify::verify_installed(store_path, &expected_hash).await
    } else {
        hash_verify::verify_installed_blessed(store_path, &blessed).await
    };
    match verify_result {
        Ok(actual_hash) => {
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "package": package,
                    "registry": &installed_apm.registry,
                    "version": &installed_apm.version,
                    "store_path": store_path,
                    "expected_nar_hash": expected_hash,
                    "actual_nar_hash": &actual_hash,
                    "verified": true,
                }));
            } else {
                printer.success(&format!("OK: '{package}' integrity verified"));
            }
            Ok(())
        }
        Err(e) => {
            if let Some(AosError::HashMismatch { expected, actual }) = e.downcast_ref::<AosError>()
            {
                printer.error(&format!("MISMATCH: '{package}' has been modified on disk"));
                printer.kv("Expected", expected);
                printer.kv("Actual", actual);
                bail!(
                    "package '{package}' failed integrity verification: expected {expected}, got {actual}"
                );
            }
            Err(e)
        }
    }
}

/// Look up the registry entry matching the *installed* store path of a
/// package (by store-path hash, in the registry recorded at install time).
///
/// This deliberately avoids `RegistrySet::resolve`, which returns the
/// latest candidate — after a rollback the installed version may be older
/// than the registry's newest entry.
fn resolve_installed_package_meta<'a>(
    reg_set: &'a RegistrySet,
    package: &str,
    installed: &InstalledMeta,
) -> Result<&'a PackageMeta> {
    let installed_apm = installed
        .apm
        .as_ref()
        .ok_or_else(|| AosError::PackageNotFound {
            name: package.to_string(),
        })?;
    let installed_hash = store_path_hash(&installed.store_path);

    reg_set
        .resolve_hash_in(&installed_apm.registry, installed_hash)
        .filter(|meta| meta.name == package)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "installed package '{package}' ({}) is not present in registry '{}' by store hash {installed_hash}",
                installed_apm.version,
                installed_apm.registry,
            )
        })
}

/// Source provenance for an installed package: where it came from and the
/// derivation that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceMetadata {
    registry_name: String,
    source_drv: String,
    source_nar_hash: String,
}

/// Resolve a package's source metadata, preferring the profile's own
/// `ApmMeta` record (set at install time) and falling back to the registry
/// entry matched by installed store-path hash.
fn resolve_installed_source_metadata(
    reg_set: &RegistrySet,
    package: &str,
    installed: &InstalledMeta,
) -> Result<SourceMetadata> {
    let installed_apm = installed
        .apm
        .as_ref()
        .ok_or_else(|| AosError::PackageNotFound {
            name: package.to_string(),
        })?;

    if !installed_apm.source_drv.is_empty() {
        return Ok(SourceMetadata {
            registry_name: installed_apm.registry.clone(),
            source_drv: installed_apm.source_drv.clone(),
            source_nar_hash: installed_apm.source_nar_hash.clone(),
        });
    }

    let pkg_meta = resolve_installed_package_meta(reg_set, package, installed)?;
    Ok(SourceMetadata {
        registry_name: installed_apm.registry.clone(),
        source_drv: pkg_meta.source_drv.clone(),
        source_nar_hash: pkg_meta.source_nar_hash.clone(),
    })
}

// ---------------------------------------------------------------------------
// apm source <package>
// ---------------------------------------------------------------------------

/// Show or fetch the source derivation for a package.
///
/// Flags:
/// - `--show-drv`: Print the `source_drv` path from the registry.
/// - `--fetch`: Download the source derivation NAR.
/// - `--verify`: Rebuild from source and compare hash.
/// - (default, no flags): Print the `source_drv` field.
///
/// For `--verify` the expected hash is the freshly dumped NAR hash of the
/// *installed* store path, so the comparison is rebuild-vs-installed rather
/// than rebuild-vs-registry.
///
/// # Errors
///
/// Returns [`AosError::PackageNotFound`] if the package is neither
/// installed nor in any enabled registry (or, with `--verify`, not
/// installed), an error if the package records no source derivation, if the
/// source path cannot be realised from the local store or registry cache,
/// if `nix-store --dump` fails, or if the rebuilt hash does not match the
/// installed binary.
pub async fn run_source(
    config: &ApmConfig,
    package: &str,
    show_drv: bool,
    fetch: bool,
    verify_source: bool,
    printer: &Printer,
) -> Result<()> {
    let enabled = config.enabled_registries();
    let reg_set = RegistrySet::load(&config.cache_path(), &enabled, current_platform())?;

    let mut installed_store_path = None;
    let (registry_name, source_drv, source_nar_hash, expected_hash) = if verify_source {
        let profile = Profile::open_readonly(config.scope);
        let all_meta = meta::list_meta(&profile)?;
        let installed = all_meta
            .iter()
            .find(|m| m.apm.as_ref().map(|a| a.name == package).unwrap_or(false))
            .ok_or_else(|| AosError::PackageNotFound {
                name: package.to_string(),
            })?;
        let source_meta = resolve_installed_source_metadata(&reg_set, package, installed)?;
        installed_store_path = Some(installed.store_path.clone());

        (
            source_meta.registry_name,
            source_meta.source_drv,
            source_meta.source_nar_hash,
            String::new(),
        )
    } else {
        let profile = Profile::open_readonly(config.scope);
        let all_meta = meta::list_meta(&profile)?;

        if let Some(installed) = find_installed_package(&all_meta, package) {
            let source_meta = resolve_installed_source_metadata(&reg_set, package, installed)?;
            installed_store_path = Some(installed.store_path.clone());
            (
                source_meta.registry_name,
                source_meta.source_drv,
                source_meta.source_nar_hash,
                String::new(),
            )
        } else {
            let (reg, pkg_meta) =
                reg_set
                    .resolve(package)
                    .ok_or_else(|| AosError::PackageNotFound {
                        name: package.to_string(),
                    })?;

            (
                reg.config.name.clone(),
                pkg_meta.source_drv.clone(),
                pkg_meta.source_nar_hash.clone(),
                pkg_meta.nar_hash.clone(),
            )
        }
    };

    if source_drv.is_empty() {
        bail!(
            "package '{package}' has no source derivation recorded in registry '{}'",
            registry_name
        );
    }
    let expected_hash = if verify_source {
        let store_path = installed_store_path.as_deref().ok_or_else(|| {
            anyhow::anyhow!("missing installed store path for source verification")
        })?;
        hash_verify::store_path_nar_hash(store_path)
            .await
            .with_context(|| format!("hashing installed package {store_path}"))?
    } else {
        expected_hash
    };

    // Default or --show-drv: just print the source derivation path.
    if show_drv || (!fetch && !verify_source) {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "package": package,
                "registry": &registry_name,
                "source_drv": &source_drv,
                "source_nar_hash": &source_nar_hash,
                "installed": installed_store_path.is_some(),
                "installed_store_path": installed_store_path.as_deref(),
            }));
        } else {
            printer.header(&format!("Source derivation for '{package}':"));
            printer.kv("Source drv", &source_drv);
            printer.kv("Source NAR hash", &source_nar_hash);
            printer.kv("Registry", &registry_name);
        }
        return Ok(());
    }

    let mut realised_path = None;

    // --fetch: realise the source derivation, using the registry cache if
    // the source path is not already available locally.
    if fetch {
        printer.header(&format!("Fetching source derivation for '{package}'..."));
        printer.kv("Source drv", &source_drv);

        let path = realise_source_path(config, &registry_name, &source_drv, printer).await?;
        if printer.mode() == OutputMode::Json && !verify_source {
            printer.json(&serde_json::json!({
                "package": package,
                "registry": &registry_name,
                "source_drv": &source_drv,
                "source_nar_hash": &source_nar_hash,
                "installed": installed_store_path.is_some(),
                "installed_store_path": installed_store_path.as_deref(),
                "realised_path": &path,
            }));
        } else {
            printer.success(&format!("Source realised: {path}"));
        }
        realised_path = Some(path);
    }

    // --verify: rebuild from source and compare hash.
    if verify_source {
        printer.header(&format!("Rebuilding '{package}' from source..."));
        printer.kv("Source drv", &source_drv);

        let built_path = if let Some(path) = realised_path {
            path
        } else {
            realise_source_path(config, &registry_name, &source_drv, printer).await?
        };

        // Now dump and hash the built output.
        printer.info("Hashing rebuilt output...");

        let dump_output = tokio::process::Command::new("nix-store")
            .envs(aos_nix_env())
            .args(["--dump", &built_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("running nix-store --dump {built_path}"))?;

        if !dump_output.status.success() {
            let stderr = String::from_utf8_lossy(&dump_output.stderr);
            bail!(
                "nix-store --dump failed for {built_path}: {}",
                stderr.trim()
            );
        }

        let actual_hash = hash_verify::sha256_stream(dump_output.stdout.as_slice())?;

        printer.kv("Expected NAR hash", &expected_hash);
        printer.kv("Rebuilt NAR hash", &actual_hash);

        if hash_verify::sha256_hashes_equal(&actual_hash, &expected_hash)? {
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "package": package,
                    "registry": &registry_name,
                    "source_drv": &source_drv,
                    "source_nar_hash": &source_nar_hash,
                    "installed": installed_store_path.is_some(),
                    "installed_store_path": installed_store_path.as_deref(),
                    "built_path": &built_path,
                    "expected_nar_hash": &expected_hash,
                    "actual_nar_hash": &actual_hash,
                    "verified": true,
                }));
            } else {
                printer.success(&format!(
                    "OK: source rebuild of '{package}' matches installed binary"
                ));
            }
        } else {
            printer.error(&format!(
                "MISMATCH: source rebuild of '{package}' differs from installed binary"
            ));
            bail!("source verification failed: expected {expected_hash}, got {actual_hash}");
        }
    }

    Ok(())
}

/// Realise a source path locally, importing it from the registry cache when
/// the local Nix store does not already have it.
async fn realise_source_path(
    config: &ApmConfig,
    registry_name: &str,
    source_drv: &str,
    printer: &Printer,
) -> Result<String> {
    match realise_with_nix_store(source_drv).await {
        Ok(path) => Ok(path),
        Err(first_error) => {
            fetch_source_from_registry_cache(config, registry_name, source_drv, printer)
                .await
                .with_context(|| {
                    format!(
                        "fetching source path {source_drv} from registry cache after local realisation failed: {first_error}"
                    )
                })?;
            realise_with_nix_store(source_drv)
                .await
                .with_context(|| format!("realising fetched source path {source_drv}"))
        }
    }
}

/// Run `nix-store --realise` and return its realised path.
async fn realise_with_nix_store(source_drv: &str) -> Result<String> {
    let output = tokio::process::Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["--realise", source_drv])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("running nix-store --realise")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "nix-store --realise failed for {source_drv}: {}",
            stderr.trim()
        );
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        Ok(source_drv.to_string())
    } else {
        Ok(path)
    }
}

/// Download and import a recorded source path from the registry's binary cache.
async fn fetch_source_from_registry_cache(
    config: &ApmConfig,
    registry_name: &str,
    source_drv: &str,
    printer: &Printer,
) -> Result<()> {
    let registry = config
        .registries
        .iter()
        .find(|(registry, _)| registry.name == registry_name)
        .map(|(registry, _)| registry)
        .ok_or_else(|| {
            anyhow::anyhow!("registry '{registry_name}' is not configured for source fetch")
        })?;

    let chain = resolve_mirror_chain(&config.scope.registries_path(), registry);
    let (mirror_url, fallback_mirrors) = split_mirror_chain(&chain);
    let request = DownloadRequest {
        store_path: source_drv.to_string(),
        mirror_url,
        fallback_mirrors,
    };

    let engine = Arc::new(default_engine());
    let resolved = fetch_narinfo_closure(
        engine,
        std::slice::from_ref(&request),
        config.settings.parallel_downloads,
        printer,
    )
    .await
    .with_context(|| format!("fetching narinfo closure for source path {source_drv}"))?;

    let missing = filter_missing(
        &resolved
            .iter()
            .map(|item| item.req.store_path.clone())
            .collect::<Vec<_>>(),
    )
    .await?;
    let missing = missing
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    let resolved = resolved
        .into_iter()
        .filter(|item| missing.contains(&item.req.store_path))
        .collect::<Vec<_>>();

    if resolved.is_empty() {
        return Ok(());
    }

    printer.info("Downloading source NAR(s) from registry cache...");
    let results = download_nars(
        &resolved,
        &config.nar_cache_path(),
        config.settings.parallel_downloads,
        printer,
    )
    .await?;

    for result in &results {
        hash_verify::verify_download_hash(&result.local_path, &result.download_hash)
            .with_context(|| format!("verifying download for {}", result.store_path))?;
        hash_verify::verify_nar_hash_with_compression(
            &result.local_path,
            &result.nar_hash,
            &result.compression,
        )
        .with_context(|| format!("verifying NAR hash for {}", result.store_path))?;
    }

    for result in &results {
        crate::store::import_nar_with_compression(
            &result.local_path,
            &result.store_path,
            &result.references,
            result.deriver.as_deref(),
            &result.compression,
        )
        .await
        .with_context(|| format!("importing source path {}", result.store_path))?;
    }

    Ok(())
}

/// Find the profile metadata entry whose APM name matches `package`.
fn find_installed_package<'a>(
    installed: &'a [InstalledMeta],
    package: &str,
) -> Option<&'a InstalledMeta> {
    installed.iter().find(|meta| {
        meta.apm
            .as_ref()
            .map(|apm| apm.name == package)
            .unwrap_or(false)
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApmConfig;
    use crate::registry::parse::CURL_TOML;
    use crate::types::{ApmMeta, ApmSettings, InstalledMeta, ProfileScope, RegistryConfig};
    use tempfile::TempDir;

    /// Helper: build a minimal ApmConfig with a temp cache dir containing
    /// a registry with specified packages.
    fn make_config_with_registry(tmp: &TempDir, packages: &[(&str, &str)]) -> ApmConfig {
        // Set up the registry cache at tmp/remote/test-reg/packages/{letter}/{name}.toml
        let cache_dir = tmp.path().join("remote");
        let reg_dir = cache_dir.join("test-reg").join("packages");
        for (name, content) in packages {
            let first_letter = &name[..1];
            let dir = reg_dir.join(first_letter);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(format!("{name}.toml")), content).unwrap();
        }

        // Set up the config dir with a registry TOML
        let config_dir = tmp.path().join("config");
        let registries_dir = config_dir.join("registries.d");
        std::fs::create_dir_all(&registries_dir).unwrap();
        std::fs::write(
            registries_dir.join("test-reg.toml"),
            r#"[registry]
name = "test-reg"
url = "https://registry.example.com/test"
priority = 500
"#,
        )
        .unwrap();

        ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![(
                RegistryConfig {
                    name: "test-reg".into(),
                    url: "https://registry.example.com/test".into(),
                    priority: 500,
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
                },
                None,
            )],
            scope: ProfileScope::User,
        }
    }

    /// Helper: write installed metadata to a profile.
    fn write_installed_meta(profile_dir: &std::path::Path, hash: &str, name: &str) {
        let meta_dir = profile_dir.join("meta");
        std::fs::create_dir_all(&meta_dir).unwrap();

        let meta = InstalledMeta {
            store_path: format!("/var/lib/store/{hash}-{name}-1.0"),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(ApmMeta {
                name: name.into(),
                version: "1.0".into(),
                explicit: true,
                registry: "test-reg".into(),
                installed_at: "2026-02-16T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                documentation: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        };

        let json = serde_json::to_string_pretty(&meta).unwrap();
        std::fs::write(meta_dir.join(format!("{hash}.json")), &json).unwrap();
    }

    // -- source: show drv path -----------------------------------------------

    #[tokio::test]
    async fn source_shows_drv_path() {
        let tmp = TempDir::new().unwrap();
        let config = make_config_with_registry(&tmp, &[("curl", CURL_TOML)]);

        // Override cache_path by adjusting config.scope — we'll test via
        // RegistrySet::load directly since config.cache_path() is derived from scope.
        // Instead, test the registry resolution part.
        let enabled = config.enabled_registries();
        let cache_dir = tmp.path().join("remote");
        let reg_set = RegistrySet::load(&cache_dir, &enabled, "x86_64-linux").unwrap();

        let (reg, meta) = reg_set.resolve("curl").unwrap();
        assert_eq!(
            meta.source_drv,
            "/var/lib/store/i8k4l9m3n0o5-curl-8.5.0.drv"
        );
        assert_eq!(meta.source_nar_hash, "sha256:112233");
        assert_eq!(reg.config.name, "test-reg");
    }

    // -- source: missing source_drv ------------------------------------------

    #[tokio::test]
    async fn source_no_source_drv_errors() {
        // Create a package TOML where source_drv is empty.
        let toml_with_empty_source = r#"
[package]
name = "nosrc"
description = "A package with no source"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/abc123-nosrc-1.0"
nar_hash = "sha256:aabb"
nar_size = 1024
closure_size = 1024
source_drv = ""
source_nar_hash = ""
references = []
"#;

        let tmp = TempDir::new().unwrap();
        let config = make_config_with_registry(&tmp, &[("nosrc", toml_with_empty_source)]);

        let cache_dir = tmp.path().join("remote");
        let enabled = config.enabled_registries();
        let reg_set = RegistrySet::load(&cache_dir, &enabled, "x86_64-linux").unwrap();

        let (_, meta) = reg_set.resolve("nosrc").unwrap();
        assert!(meta.source_drv.is_empty());
    }

    // -- source: package not found -------------------------------------------

    #[tokio::test]
    async fn source_package_not_found() {
        let tmp = TempDir::new().unwrap();
        let config = make_config_with_registry(&tmp, &[("curl", CURL_TOML)]);

        let enabled = config.enabled_registries();
        let cache_dir = tmp.path().join("remote");
        let reg_set = RegistrySet::load(&cache_dir, &enabled, "x86_64-linux").unwrap();

        assert!(reg_set.resolve("nonexistent").is_none());
    }

    // -- verify: hash comparison logic (unit test) ---------------------------

    #[test]
    fn verify_hash_comparison_match() {
        let data: &[u8] = b"test NAR content";
        let hash = hash_verify::sha256_stream(data).unwrap();
        // Verify the same data produces the same hash.
        let hash2 = hash_verify::sha256_stream(b"test NAR content".as_slice()).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn verify_hash_comparison_mismatch() {
        let hash1 = hash_verify::sha256_stream(b"content A".as_slice()).unwrap();
        let hash2 = hash_verify::sha256_stream(b"content B".as_slice()).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn verify_resolves_installed_store_hash_not_latest_candidate() {
        let tmp = TempDir::new().unwrap();
        let verify_tool_toml = r#"
[package]
name = "verifytool"
description = "verify test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-verifytool-1.0.0"
nar_hash = "sha256:v1"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "2.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-verifytool-2.0.0"
nar_hash = "sha256:v2"
nar_size = 2
closure_size = 2
source_drv = ""
source_nar_hash = ""
references = []
"#;
        let config = make_config_with_registry(&tmp, &[("verifytool", verify_tool_toml)]);
        let enabled = config.enabled_registries();
        let reg_set =
            RegistrySet::load(&tmp.path().join("remote"), &enabled, "x86_64-linux").unwrap();
        let (_, latest) = reg_set.resolve("verifytool").unwrap();
        assert_eq!(latest.version, "2.0.0");

        let installed = InstalledMeta {
            store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-verifytool-1.0.0".into(),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(ApmMeta {
                name: "verifytool".into(),
                version: "1.0.0".into(),
                explicit: true,
                registry: "test-reg".into(),
                installed_at: "2026-02-16T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                documentation: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        };

        let selected = resolve_installed_package_meta(&reg_set, "verifytool", &installed).unwrap();
        assert_eq!(selected.version, "1.0.0");
        assert_eq!(selected.nar_hash, "sha256:v1");
    }

    #[test]
    fn source_verify_uses_installed_source_metadata_without_registry_entry() {
        let reg_set = RegistrySet::new(Vec::new());
        let installed = InstalledMeta {
            store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-verifytool-1.0.0".into(),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(ApmMeta {
                name: "verifytool".into(),
                version: "1.0.0".into(),
                explicit: true,
                registry: "test-reg".into(),
                installed_at: "2026-02-16T00:00:00Z".into(),
                held: false,
                source_drv: "/nix/store/srcsrcsrcsrcsrcsrcsrcsrcsrcsrcsrcsrc-src.drv".into(),
                source_nar_hash: "sha256:source".into(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                documentation: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        };

        let selected =
            resolve_installed_source_metadata(&reg_set, "verifytool", &installed).unwrap();

        assert_eq!(selected.registry_name, "test-reg");
        assert_eq!(
            selected.source_drv,
            "/nix/store/srcsrcsrcsrcsrcsrcsrcsrcsrcsrcsrcsrc-src.drv"
        );
        assert_eq!(selected.source_nar_hash, "sha256:source");
    }

    #[test]
    fn source_lookup_prefers_installed_package_name() {
        let installed = vec![InstalledMeta {
            store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sourceful-1.0.0".into(),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(ApmMeta {
                name: "sourceful".into(),
                version: "1.0.0".into(),
                explicit: true,
                registry: "test-reg".into(),
                installed_at: "2026-02-16T00:00:00Z".into(),
                held: false,
                source_drv: "/nix/store/srcsrcsrcsrcsrcsrcsrcsrcsrcsrcsrcsrc-sourceful-src".into(),
                source_nar_hash: "sha256:source".into(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                documentation: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }];

        let selected = find_installed_package(&installed, "sourceful")
            .and_then(|meta| meta.apm.as_ref())
            .unwrap();
        assert_eq!(selected.registry, "test-reg");
        assert_eq!(selected.version, "1.0.0");
        assert!(find_installed_package(&installed, "other").is_none());
    }

    // -- verify: installed meta lookup (unit test) ---------------------------

    #[test]
    fn verify_finds_installed_package_meta() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile::open_at(tmp.path().to_path_buf(), ProfileScope::User).unwrap();

        write_installed_meta(tmp.path(), "abc123", "curl");

        let all_meta = meta::list_meta(&profile).unwrap();
        let found = all_meta
            .iter()
            .find(|m| m.apm.as_ref().map(|a| a.name == "curl").unwrap_or(false));
        assert!(found.is_some());
        assert!(found.unwrap().store_path.contains("curl"));
    }

    #[test]
    fn verify_missing_package_not_found() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile::open_at(tmp.path().to_path_buf(), ProfileScope::User).unwrap();

        let all_meta = meta::list_meta(&profile).unwrap();
        let found = all_meta.iter().find(|m| {
            m.apm
                .as_ref()
                .map(|a| a.name == "nonexistent")
                .unwrap_or(false)
        });
        assert!(found.is_none());
    }
}
