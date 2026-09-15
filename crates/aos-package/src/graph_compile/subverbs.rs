//! The private package-runtime `fetch` and `render-one` subverbs (build-spec §4).
//!
//! These two thin, per-package, idempotent verbs back the `ExecStart=`s of the
//! `aos-pkg-fetch@.service` / `aos-pkg-install@.service` templates. They are the
//! only new CLI surface the graph compiler adds.
//!
//! - **`fetch <pkg>`** materializes one package's NAR closure (the store
//!   paths the manifest pinned) into the local store via the configured
//!   substituters, then writes the completion marker `/run/aos/fetch/<pkg>.ok`.
//!   It does not switch generations, render config, or activate.
//! - **`render-one <pkg>`** renders that package's config artifact(s) +
//!   credential handles into the staging area against the signed `expose.config`
//!   metadata, then writes `/run/aos/render/<pkg>.ok`. It does not touch live
//!   `/etc` (the atomic commit is `aos-activate`'s job).
//!
//! # Markers
//!
//! ```text
//! /run/aos/fetch/<pkg>.ok    manifest hash + package pin after verified import
//! /run/aos/render/<pkg>.ok   same identities after validated scoped staging
//! ```
//!
//! The markers are the authoritative "this package is fully present + rendered"
//! signal the degraded re-projection ([`super::reproject`]) reads — they survive
//! a unit going inactive, unlike systemd unit state.
//!
//! # Exit codes
//!
//! `fetch`: `0` fully present/verified (including the already-present no-op);
//! non-zero on any narinfo/download/verify/import failure (so the template's
//! `Restart=on-failure` engages). `render-one`: `0` validated + staged; `2` on a
//! config-validation error (a *permanent* error — the install template has no
//! `Restart=`, so the package drops); other non-zero on a missing fetch marker
//! or staging I/O error.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use aos_core::nar::cache::normalize_sha256_nix32;
use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::config_eval::materialize::ConfigManifest;
use crate::config_eval::runtime::{RuntimePackageOrigin, RuntimePackagePin};
use crate::download::{
    DownloadRequest, ResolvedDownload, default_engine, download_nars, fetch_narinfo_closure,
    resolve_mirror_chain, split_mirror_chain,
};
use crate::registry::store::NarBytes;
use crate::registry::store_path_hash;
use crate::store::filter_missing;
use crate::types::validate_package_name;
use crate::verify::verify_download_hash;

/// Default root under which the per-package completion markers live.
pub const MARKER_ROOT: &str = "/run/aos";

/// Default staging root `render-one` writes artifacts into, consumed later by
/// `aos-activate`.
pub const STAGING_ROOT: &str = "/run/aos/staging";

// ---------------------------------------------------------------------------
// Marker paths (pure)
// ---------------------------------------------------------------------------

/// Path of the fetch completion marker for `pkg` under `marker_root`.
pub fn fetch_marker(marker_root: &Path, pkg: &str) -> PathBuf {
    marker_root.join("fetch").join(format!("{pkg}.ok"))
}

/// Path of the render completion marker for `pkg` under `marker_root`.
pub fn render_marker(marker_root: &Path, pkg: &str) -> PathBuf {
    marker_root.join("render").join(format!("{pkg}.ok"))
}

/// Atomically write a `.ok` marker (truncating any prior content), creating its
/// parent directory.
fn write_marker(path: &Path, manifest: &ConfigManifest, pkg: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let identity = marker_identity(manifest, pkg)?;
    let temporary = path.with_extension("ok.tmp");
    std::fs::write(&temporary, format!("{identity}\n"))
        .with_context(|| format!("writing marker {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("renaming marker {}", path.display()))
}

/// Remove a marker if present, treating absence as success. A failed verb MUST
/// NOT leave a stale `.ok` (build-spec §4.1).
fn clear_marker(path: &Path) {
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Manifest helpers (pure)
// ---------------------------------------------------------------------------

/// Whether `pkg` appears in the manifest's package set.
fn manifest_has_package(manifest: &ConfigManifest, pkg: &str) -> bool {
    manifest
        .packages
        .binary_search_by(|name| name.as_str().cmp(pkg))
        .is_ok()
}

fn marker_identity(manifest: &ConfigManifest, pkg: &str) -> Result<String> {
    let state = super::graph_transaction(manifest)?;
    let pin = state
        .packages
        .get(pkg)
        .with_context(|| format!("package {pkg:?} is absent from graph transaction"))?;
    Ok(format!("{} {pin}", state.manifest))
}

/// Requires the manifest to be the transaction published by graph compilation.
fn ensure_published_transaction(manifest: &ConfigManifest, marker_root: &Path) -> Result<()> {
    let desired = super::graph_transaction(manifest)?;
    let current = super::read_transaction(marker_root)?
        .context("graph transaction state is absent; run graph compilation first")?;
    if current.manifest != desired.manifest || current.packages != desired.packages {
        bail!("manifest does not match the graph compiler's current transaction");
    }
    Ok(())
}

/// Whether a marker belongs to the currently published transaction and pin.
pub(crate) fn marker_is_current(marker_root: &Path, wing: &str, pkg: &str) -> bool {
    let Ok(Some(state)) = super::read_transaction(marker_root) else {
        return false;
    };
    let Some(pin) = state.packages.get(pkg) else {
        return false;
    };
    let expected = format!("{} {pin}", state.manifest);
    std::fs::read_to_string(marker_root.join(wing).join(format!("{pkg}.ok")))
        .is_ok_and(|actual| actual.trim_end() == expected)
}

/// Transaction- and package-pin-scoped staging directory.
pub(crate) fn staging_package_dir(
    staging_root: &Path,
    manifest: &ConfigManifest,
    pkg: &str,
) -> Result<PathBuf> {
    let transaction = super::graph_transaction(manifest)?;
    let pin = transaction
        .packages
        .get(pkg)
        .with_context(|| format!("package {pkg:?} is absent from graph transaction"))?;
    Ok(staging_root
        .join("transactions")
        .join(transaction.manifest.trim_start_matches("sha256:"))
        .join(pkg)
        .join(pin.trim_start_matches("sha256:")))
}

/// Transaction-scoped render output consumed by activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagedPackage {
    /// Staging schema discriminator.
    pub(crate) schema: String,
    /// Exact source-manifest identity.
    pub(crate) manifest: String,
    /// Exact closure/config/credential package identity.
    pub(crate) package_pin: String,
    /// Owning package.
    pub(crate) package: String,
    /// Rendered non-secret files.
    pub(crate) artifacts: Vec<StagedArtifact>,
    /// Opaque credential handles copied from the manifest.
    pub(crate) credentials: Value,
    /// Signed config-driven unit reconcile actions.
    pub(crate) units: BTreeMap<String, crate::config_eval::materialize::UnitReconcileAction>,
}

/// One rendered file stored under an opaque content-derived payload name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagedArtifact {
    /// Final `/etc`-relative path.
    pub(crate) path: String,
    /// Relative payload path below the package staging directory.
    pub(crate) payload: String,
    /// Octal mode applied by the final materializer.
    pub(crate) mode: String,
    /// SHA-256 of the exact staged bytes.
    pub(crate) sha256: String,
}

pub(crate) fn read_staged_package(directory: &Path) -> Result<StagedPackage> {
    let bytes = crate::config_eval::materialize::read_bytes_beneath(directory, "stage.json")?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parsing staged package index beneath {}",
            directory.display()
        )
    })
}

// ---------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------

/// Runs package-runtime `fetch <pkg>` and writes the completion marker.
///
/// Returns the process exit code (build-spec §4.1).
pub async fn run_fetch(
    config: &ApmConfig,
    package: &str,
    manifest_path: &Path,
    marker_root: &Path,
    json_out: bool,
    printer: &Printer,
) -> i32 {
    match fetch_inner(config, package, manifest_path, marker_root, printer).await {
        Ok(roots) => {
            emit(
                json_out,
                printer,
                json!({"op": "fetch", "package": package, "status": "ok", "roots": roots}),
                &format!("fetched closure for {package} ({} root(s))", roots.len()),
            );
            0
        }
        Err(err) => {
            emit_err(json_out, "fetch", package, &err);
            1
        }
    }
}

/// The fallible body of `fetch`: validate, select the closure roots, realise
/// them through the configured substituters, verify presence, write the marker.
async fn fetch_inner(
    config: &ApmConfig,
    package: &str,
    manifest_path: &Path,
    marker_root: &Path,
    printer: &Printer,
) -> Result<Vec<String>> {
    validate_package_name(package).context("invalid package argument")?;
    let manifest = read_manifest(manifest_path)?;
    if !manifest_has_package(&manifest, package) {
        bail!("package '{package}' is not in {}", manifest_path.display());
    }
    ensure_published_transaction(&manifest, marker_root)?;
    // From this point onward the invocation owns the current transaction's
    // marker. Clear prior success before attempting work that can fail.
    clear_marker(&fetch_marker(marker_root, package));

    let pin = manifest
        .package_outputs
        .get(package)
        .with_context(|| format!("manifest has no runtime output pin for package '{package}'"))?;
    let known_paths = pinned_named_paths(pin);
    if pin.origin == RuntimePackageOrigin::Image {
        verify_image_closure(pin)?;
        write_marker(&fetch_marker(marker_root, package), &manifest, package)?;
        return Ok(known_paths);
    }
    let missing = filter_missing(&known_paths)
        .await
        .context("checking pinned closure validity")?;
    let registry = config
        .find_registry(&pin.registry)
        .map(|(registry, _)| registry)
        .filter(|registry| registry.enabled)
        .with_context(|| {
            format!(
                "manifest pins package '{package}' to unavailable registry '{}'",
                pin.registry
            )
        })?;
    let mirrors = resolve_mirror_chain(&config.scope.registries_path(), registry);
    let (mirror_url, fallback_mirrors) = split_mirror_chain(&mirrors);
    if mirror_url.is_empty() {
        bail!("registry '{}' has no configured binary cache", pin.registry);
    }

    // Only exact paths carried by the authenticated runtime pin are eligible
    // as roots. Anonymous members are discovered from narinfo References and
    // admitted solely when their IA hash appears in the same pin.
    if !missing.is_empty() {
        let requests = missing
            .iter()
            .map(|store_path| DownloadRequest {
                store_path: store_path.clone(),
                mirror_url: mirror_url.clone(),
                fallback_mirrors: fallback_mirrors.clone(),
            })
            .collect::<Vec<_>>();
        let resolved = fetch_narinfo_closure(
            Arc::new(default_engine()),
            &requests,
            config.settings.parallel_downloads,
            printer,
        )
        .await
        .context("fetching pinned closure narinfos")?;
        validate_resolved_closure(pin, &requests, &resolved)?;
        let downloads = download_nars(
            &resolved,
            &config.nar_cache_path(),
            config.settings.parallel_downloads,
            printer,
        )
        .await
        .context("downloading pinned closure NARs")?;
        for download in &downloads {
            verify_download_hash(&download.local_path, &download.download_hash)
                .with_context(|| format!("verifying compressed NAR for {}", download.store_path))?;
            let blessed = blessed_nars(pin, store_path_hash(&download.store_path))?;
            crate::verify::verify_nar_blessed_with_compression(
                &download.local_path,
                &blessed,
                &download.compression,
            )
            .with_context(|| {
                format!(
                    "verifying {} against the manifest's authenticated runtime pin",
                    download.store_path
                )
            })?;
        }
        for download in &downloads {
            crate::store::import_nar_with_compression(
                &download.local_path,
                &download.store_path,
                &download.references,
                download.deriver.as_deref(),
                &download.compression,
            )
            .await
            .with_context(|| format!("importing pinned path {}", download.store_path))?;
        }
    }

    // Every full path the signed manifest carries must now be valid. Anonymous
    // members reached from a missing root were checked before import above;
    // when the root was already valid, Nix's store reference closure is kept
    // alive with it and no cache metadata is consulted.
    let missing = filter_missing(&known_paths)
        .await
        .context("checking imported pinned closure")?;
    if !missing.is_empty() {
        bail!(
            "closure for '{package}' still missing {} path(s) after fetch: {}",
            missing.len(),
            missing.join(", ")
        );
    }

    // Marker written only after every path verifies + imports (build-spec §4.1).
    write_marker(&fetch_marker(marker_root, package), &manifest, package)?;
    Ok(known_paths)
}

fn verify_image_closure(pin: &RuntimePackagePin) -> Result<()> {
    for member in &pin.closure {
        let path = member.store_path.as_deref().with_context(|| {
            format!(
                "image-local closure member '{}' has no exact store path",
                member.store_path_hash
            )
        })?;
        let lower_path = crate::config_eval::runtime::immutable_lower_store_path(path)?;
        if !lower_path.exists() {
            bail!("image-local store path {path} is absent from the immutable image store");
        }
        let (hash, size) = crate::config_eval::runtime::local_store_identity_at(path, &lower_path)?;
        if !blessed_nars(pin, &member.store_path_hash)?
            .iter()
            .any(|expected| expected.matches(&hash, size))
        {
            bail!("image-local store path {path} disagrees with its measured-image pin");
        }
    }
    Ok(())
}

fn pinned_named_paths(pin: &RuntimePackagePin) -> Vec<String> {
    let mut paths = pin
        .closure
        .iter()
        .filter_map(|member| member.store_path.clone())
        .collect::<BTreeSet<_>>();
    paths.insert(pin.store_path.clone());
    paths.into_iter().collect()
}

fn blessed_nars(pin: &RuntimePackagePin, hash: &str) -> Result<Vec<NarBytes>> {
    let member = pin
        .closure
        .iter()
        .find(|member| member.store_path_hash == hash)
        .with_context(|| {
            format!("downloaded closure member '{hash}' is absent from runtime pin")
        })?;
    member
        .realisations
        .iter()
        .map(|realisation| NarBytes::from_hash(&realisation.nar_hash, realisation.nar_size))
        .collect()
}

/// Validates every cache-served narinfo against the immutable runtime pin.
fn validate_resolved_closure(
    pin: &RuntimePackagePin,
    requests: &[DownloadRequest],
    resolved: &[ResolvedDownload],
) -> Result<()> {
    let members = pin
        .closure
        .iter()
        .map(|member| (member.store_path_hash.as_str(), member))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for item in resolved {
        if item.req.store_path != item.narinfo.store_path {
            bail!(
                "cache narinfo StorePath {:?} disagrees with requested pinned path {:?}",
                item.narinfo.store_path,
                item.req.store_path
            );
        }
        let hash = store_path_hash(&item.narinfo.store_path);
        let member = members.get(hash).with_context(|| {
            format!(
                "cache closure introduced unauthenticated store-path hash '{hash}' from {}",
                item.narinfo.store_path
            )
        })?;
        if let Some(expected) = member.store_path.as_deref()
            && expected != item.narinfo.store_path
        {
            bail!(
                "cache path {:?} disagrees with pinned path {:?} for hash '{hash}'",
                item.narinfo.store_path,
                expected
            );
        }
        let blessed = blessed_nars(pin, hash)?;
        if !blessed
            .iter()
            .any(|nar| nar.matches(&item.narinfo.nar_hash, item.narinfo.nar_size))
        {
            bail!(
                "cache narinfo NAR {}:{} is not blessed for pinned closure member '{hash}'",
                normalize_sha256_nix32(&item.narinfo.nar_hash),
                item.narinfo.nar_size
            );
        }
        for reference in &item.narinfo.references {
            let reference_hash = store_path_hash(reference);
            if reference_hash != hash && !members.contains_key(reference_hash) {
                bail!(
                    "cache narinfo for {} references unpinned closure member '{reference_hash}'",
                    item.narinfo.store_path
                );
            }
        }
        seen.insert(hash.to_string());
    }
    for request in requests {
        let hash = store_path_hash(&request.store_path);
        if !seen.contains(hash) {
            bail!(
                "cache closure omitted requested pinned path {}",
                request.store_path
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// render-one
// ---------------------------------------------------------------------------

/// Runs package-runtime `render-one <pkg>` and stages its configuration.
///
/// Writes the render marker and returns the process exit code (build-spec
/// §4.2).
pub async fn run_render_one(
    config: &ApmConfig,
    package: &str,
    manifest_path: &Path,
    marker_root: &Path,
    staging_root: &Path,
    json_out: bool,
    printer: &Printer,
) -> i32 {
    match render_inner(config, package, manifest_path, marker_root, staging_root) {
        Ok(written) => {
            emit(
                json_out,
                printer,
                json!({"op": "render-one", "package": package, "status": "ok", "artifacts": written}),
                &format!("rendered {} artifact(s) for {package}", written.len()),
            );
            0
        }
        Err(err) => {
            emit_err(json_out, "render-one", package, &err);
            1
        }
    }
}

/// The fallible body of `render-one`.
fn render_inner(
    _config: &ApmConfig,
    package: &str,
    manifest_path: &Path,
    marker_root: &Path,
    staging_root: &Path,
) -> Result<Vec<String>> {
    validate_package_name(package).context("invalid package argument")?;

    let manifest = read_manifest(manifest_path)?;
    if !manifest_has_package(&manifest, package) {
        bail!("package '{package}' is not in {}", manifest_path.display());
    }
    ensure_published_transaction(&manifest, marker_root)?;
    clear_marker(&render_marker(marker_root, package));

    // Mere marker existence is insufficient: success from an older manifest
    // or a different package closure pin must never satisfy this transaction.
    let expected_marker = marker_identity(&manifest, package)?;
    let actual_marker = std::fs::read_to_string(fetch_marker(marker_root, package)).ok();
    if actual_marker.as_deref().map(str::trim_end) != Some(expected_marker.as_str()) {
        bail!(
            "current fetch marker for '{package}' is absent; run the package runtime fetch first"
        );
    }

    let credential_handles = manifest
        .credentials
        .get(package)
        .cloned()
        .unwrap_or_else(|| json!({}));
    let units = BTreeMap::new();

    let pkg_dir = staging_package_dir(staging_root, &manifest, package)?;
    let transaction = super::graph_transaction(&manifest)?;
    let package_pin = transaction
        .packages
        .get(package)
        .cloned()
        .with_context(|| format!("graph transaction omitted package {package:?}"))?;
    let index = StagedPackage {
        schema: "aos.render-stage/v1".to_string(),
        manifest: transaction.manifest,
        package_pin,
        package: package.to_string(),
        artifacts: Vec::new(),
        credentials: credential_handles,
        units,
    };
    let index_bytes = serde_json::to_vec(&index).context("serializing staged package index")?;
    crate::config_eval::materialize::write_bytes_beneath(
        &pkg_dir,
        "stage.json",
        &index_bytes,
        "0600",
    )
    .with_context(|| {
        format!(
            "publishing staged package index beneath {}",
            pkg_dir.display()
        )
    })?;

    write_marker(&render_marker(marker_root, package), &manifest, package)?;
    Ok(Vec::new())
}

/// Stages a retained package through the same signed renderer used by the
/// live systemd render wing.
///
/// # Errors
///
/// Returns an error when retained runtime or signed render metadata is
/// unavailable or the package configuration is invalid.
pub(crate) fn stage_retained_package(
    config: &ApmConfig,
    package: &str,
    manifest_path: &Path,
    marker_root: &Path,
    staging_root: &Path,
) -> Result<()> {
    render_inner(config, package, manifest_path, marker_root, staging_root).map(|_| ())
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Read + parse a manifest file.
fn read_manifest(path: &Path) -> Result<ConfigManifest> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading manifest {}", path.display()))?;
    let manifest: ConfigManifest = serde_json::from_str(&text)
        .with_context(|| format!("parsing manifest {}", path.display()))?;
    manifest
        .validate()
        .with_context(|| format!("validating manifest {}", path.display()))?;
    Ok(manifest)
}

/// Emit a success payload: structured JSON on stdout in `--json` mode, otherwise
/// a human line via the printer.
fn emit(json_out: bool, printer: &Printer, payload: Value, human: &str) {
    if json_out {
        println!("{payload}");
    } else {
        printer.info(human);
    }
}

/// Emit an error: a JSON error object on stderr in `--json` mode, otherwise a
/// plain diagnostic. Stdout is reserved for structured output (build-spec §4).
fn emit_err(json_out: bool, op: &str, package: &str, err: &anyhow::Error) {
    if json_out {
        eprintln!(
            "{}",
            json!({"op": op, "package": package, "error": format!("{err:#}")})
        );
    } else {
        eprintln!("{op} {package}: {err:#}");
    }
}

#[cfg(test)]
mod subverb_tests {
    use super::*;
    use crate::config_eval::runtime::{RuntimeClosurePin, RuntimeRealisationPin};
    use aos_core::nar::info::NarInfo;

    fn runtime_pin() -> RuntimePackagePin {
        RuntimePackagePin {
            version: "1".into(),
            platform: "x86_64-linux".into(),
            registry: "test".into(),
            origin: RuntimePackageOrigin::Registry,
            store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example".into(),
            nar_hash: format!("sha256:{}", "0".repeat(52)),
            nar_size: 42,
            contract: None,
            closure: vec![RuntimeClosurePin {
                store_path_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                store_path: Some("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example".into()),
                realisations: vec![RuntimeRealisationPin {
                    nar_hash: format!("sha256:{}", "0".repeat(52)),
                    nar_size: 42,
                }],
            }],
        }
    }

    fn resolved(path: &str, nar_size: u64) -> ResolvedDownload {
        ResolvedDownload {
            req: DownloadRequest {
                store_path: path.into(),
                mirror_url: "file:///cache".into(),
                fallback_mirrors: Vec::new(),
            },
            narinfo: NarInfo {
                store_path: path.into(),
                url: "nar/example.nar.zst".into(),
                compression: "zstd".into(),
                file_hash: Some(format!("sha256:{}", "1".repeat(52))),
                file_size: Some(21),
                nar_hash: format!("sha256:{}", "0".repeat(52)),
                nar_size,
                references: Vec::new(),
                deriver: None,
                signatures: Vec::new(),
            },
        }
    }

    #[test]
    fn resolved_closure_must_match_exact_runtime_pin() {
        let pin = runtime_pin();
        let item = resolved(&pin.store_path, 42);
        validate_resolved_closure(
            &pin,
            std::slice::from_ref(&item.req),
            std::slice::from_ref(&item),
        )
        .unwrap();
    }

    #[test]
    fn resolved_closure_rejects_unblessed_nar_size() {
        let pin = runtime_pin();
        let item = resolved(&pin.store_path, 43);
        let error =
            validate_resolved_closure(&pin, std::slice::from_ref(&item.req), &[item.clone()])
                .unwrap_err();
        assert!(error.to_string().contains("not blessed"), "{error:#}");
    }

    #[test]
    fn resolved_closure_rejects_cache_path_substitution() {
        let pin = runtime_pin();
        let mut item = resolved(&pin.store_path, 42);
        item.narinfo.store_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-attacker".into();
        let error =
            validate_resolved_closure(&pin, std::slice::from_ref(&item.req), &[item.clone()])
                .unwrap_err();
        assert!(error.to_string().contains("disagrees"), "{error:#}");
    }

    #[test]
    fn marker_paths_are_under_root() {
        let root = Path::new("/run/aos");
        assert_eq!(
            fetch_marker(root, "redis"),
            Path::new("/run/aos/fetch/redis.ok")
        );
        assert_eq!(
            render_marker(root, "redis"),
            Path::new("/run/aos/render/redis.ok")
        );
    }

    #[test]
    fn marker_and_staging_identity_changes_with_package_pin() {
        let manifest: ConfigManifest = serde_json::from_str(include_str!(
            "../../tests/fixtures/config_manifest/manifest.json"
        ))
        .unwrap();
        let marker_root = tempfile::tempdir().unwrap();
        let staging_root = tempfile::tempdir().unwrap();
        let state = super::super::graph_transaction(&manifest).unwrap();
        super::super::write_transaction(marker_root.path(), &state).unwrap();
        let marker = fetch_marker(marker_root.path(), "example");
        write_marker(&marker, &manifest, "example").unwrap();
        assert!(marker_is_current(marker_root.path(), "fetch", "example"));
        let first_stage = staging_package_dir(staging_root.path(), &manifest, "example").unwrap();

        let mut changed = manifest.clone();
        changed
            .config
            .insert("example".to_string(), json!({"port": 8080}));
        let changed_state = super::super::graph_transaction(&changed).unwrap();
        super::super::write_transaction(marker_root.path(), &changed_state).unwrap();
        assert!(!marker_is_current(marker_root.path(), "fetch", "example"));
        let second_stage = staging_package_dir(staging_root.path(), &changed, "example").unwrap();
        assert_ne!(first_stage, second_stage);
    }
}
