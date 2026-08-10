//! The `apm fetch <pkg>` / `apm render-one <pkg>` subverbs (build-spec §4).
//!
//! These two thin, per-package, idempotent verbs back the `ExecStart=`s of the
//! `aos-pkg-fetch@.service` / `aos-pkg-install@.service` templates. They are the
//! only new CLI surface the graph compiler adds.
//!
//! - **`apm fetch <pkg>`** materializes one package's NAR closure (the store
//!   paths the manifest pinned) into the local store via the configured
//!   substituters, then writes the completion marker `/run/aos/fetch/<pkg>.ok`.
//!   It does not switch generations, render config, or activate.
//! - **`apm render-one <pkg>`** renders that package's config artifact(s) +
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
use sha2::{Digest, Sha256};

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
use crate::store::{filter_missing, import_nar};
use crate::types::{CredentialMeta, ProfileScope, validate_credential_name, validate_package_name};
use crate::verify::{verify_download_hash, verify_nar_blessed};

/// Default root under which the per-package completion markers live.
pub const MARKER_ROOT: &str = "/run/aos";

/// Default staging root `render-one` writes artifacts into, consumed later by
/// `aos-activate`.
pub const STAGING_ROOT: &str = "/run/aos/staging";

/// Config-validation exit code for `render-one` (build-spec §4.2).
pub const EXIT_CONFIG_ERROR: i32 = 2;

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

/// Extract the per-package desired config block from `manifest.config[pkg]`,
/// converted into the [`render_package_config`](crate::render_package_config)
/// input shape (`artifact → field → value`).
fn desired_config_for(
    manifest: &ConfigManifest,
    pkg: &str,
) -> Result<Option<BTreeMap<String, BTreeMap<String, toml::Value>>>> {
    let Some(value) = manifest.config.get(pkg) else {
        return Ok(None);
    };
    let block = value
        .as_object()
        .with_context(|| format!("desired config for package {pkg:?} must be an object"))?;
    let mut artifacts = BTreeMap::new();
    for (artifact, fields) in block {
        let fields_obj = fields.as_object().with_context(|| {
            format!("desired config artifact {pkg}.{artifact} must be an object")
        })?;
        let mut converted = BTreeMap::new();
        for (field, value) in fields_obj {
            converted.insert(
                field.clone(),
                json_to_toml(value).with_context(|| {
                    format!("converting desired config field {pkg}.{artifact}.{field}")
                })?,
            );
        }
        artifacts.insert(artifact.clone(), converted);
    }
    Ok(Some(artifacts))
}

/// Convert a JSON value into the equivalent `toml::Value`.
///
/// `null` has no TOML representation and is rejected. Integers prefer
/// `toml::Value::Integer`; other numbers become `Float`.
fn json_to_toml(v: &Value) -> Result<toml::Value> {
    Ok(match v {
        Value::Null => bail!("null has no TOML representation"),
        Value::Bool(b) => toml::Value::Boolean(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else {
                toml::Value::Float(
                    n.as_f64()
                        .context("JSON number has no finite TOML float representation")?,
                )
            }
        }
        Value::String(s) => toml::Value::String(s.clone()),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_to_toml(item)?);
            }
            toml::Value::Array(out)
        }
        Value::Object(map) => {
            let mut table = toml::value::Table::new();
            for (key, value) in map {
                table.insert(key.clone(), json_to_toml(value)?);
            }
            toml::Value::Table(table)
        }
    })
}

// ---------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------

/// Run `apm fetch <pkg>`: materialize one package's pinned closure, then write
/// the fetch marker. Returns the process exit code (build-spec §4.1).
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
            verify_nar_blessed(&download.local_path, &blessed).with_context(|| {
                format!(
                    "verifying {} against the manifest's authenticated runtime pin",
                    download.store_path
                )
            })?;
        }
        for download in &downloads {
            import_nar(
                &download.local_path,
                &download.store_path,
                &download.references,
                download.deriver.as_deref(),
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

/// Run `apm render-one <pkg>`: render one package's config artifacts into the
/// staging area, then write the render marker. Returns the process exit code
/// (build-spec §4.2).
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
        Err(RenderError::Config(err)) => {
            emit_err(json_out, "render-one", package, &err);
            EXIT_CONFIG_ERROR
        }
        Err(RenderError::Other(err)) => {
            emit_err(json_out, "render-one", package, &err);
            1
        }
    }
}

/// `render-one`'s two failure classes: a permanent config-validation error
/// (exit `2`) versus any other operational error (exit `1`).
enum RenderError {
    /// Desired config failed validation against the signed schema.
    Config(anyhow::Error),
    /// Missing fetch marker, staging I/O, or profile read failure.
    Other(anyhow::Error),
}

/// The fallible body of `render-one`.
fn render_inner(
    config: &ApmConfig,
    package: &str,
    manifest_path: &Path,
    marker_root: &Path,
    staging_root: &Path,
) -> std::result::Result<Vec<String>, RenderError> {
    validate_package_name(package)
        .context("invalid package argument")
        .map_err(RenderError::Other)?;

    let manifest = read_manifest(manifest_path).map_err(RenderError::Other)?;
    if !manifest_has_package(&manifest, package) {
        return Err(RenderError::Other(anyhow::anyhow!(
            "package '{package}' is not in {}",
            manifest_path.display()
        )));
    }
    ensure_published_transaction(&manifest, marker_root).map_err(RenderError::Other)?;
    clear_marker(&render_marker(marker_root, package));

    // Mere marker existence is insufficient: success from an older manifest
    // or a different package closure pin must never satisfy this transaction.
    let expected_marker = marker_identity(&manifest, package).map_err(RenderError::Other)?;
    let actual_marker = std::fs::read_to_string(fetch_marker(marker_root, package)).ok();
    if actual_marker.as_deref().map(str::trim_end) != Some(expected_marker.as_str()) {
        return Err(RenderError::Other(anyhow::anyhow!(
            "current fetch marker for '{package}' is absent; run `apm fetch {package}` first"
        )));
    }

    // Migrated packages consume exact bytes projected by the authenticated
    // config module. Legacy packages retain the signed flat renderer.
    let migrated = manifest.config_projections.get(package);
    let signed = if migrated.is_none() {
        Some(signed_config(config, &manifest, package).map_err(RenderError::Other)?)
    } else {
        None
    };
    let signed_credentials = migrated
        .and_then(|_| {
            manifest
                .package_outputs
                .get(package)?
                .config_projection
                .as_ref()
                .map(|pin| pin.config.credentials.as_slice())
        })
        .or_else(|| signed.as_ref().map(|signed| signed.credentials.as_slice()))
        .ok_or_else(|| anyhow::anyhow!("missing authenticated config schema for {package:?}"))
        .map_err(RenderError::Other)?;
    let credential_handles = canonicalize_credential_handles(
        package,
        manifest.credentials.get(package),
        signed_credentials,
    )
    .map_err(RenderError::Config)?;
    let (rendered, units) = if let Some(projection) = migrated {
        (
            projection
                .artifacts
                .iter()
                .map(|artifact| (artifact.path.clone(), artifact.text.as_bytes().to_vec()))
                .collect::<Vec<_>>(),
            projection.units.clone(),
        )
    } else {
        let signed = signed.as_ref().ok_or_else(|| {
            RenderError::Other(anyhow::anyhow!("legacy signed config metadata disappeared"))
        })?;
        let desired = desired_config_for(&manifest, package).map_err(RenderError::Config)?;
        let rendered = crate::render_package_config(package, &signed.artifacts, desired.as_ref())
            .map_err(RenderError::Config)?
            .into_iter()
            .map(|(artifact, bytes)| (artifact.path.clone(), bytes))
            .collect::<Vec<_>>();
        (
            rendered,
            crate::config_eval::materialize::projected_unit_actions(&signed.artifacts),
        )
    };

    // Stage rendered bytes under opaque, content-derived payload names. The
    // separately validated index is what binds those bytes to final paths;
    // no package-controlled path is ever joined directly onto the filesystem.
    let pkg_dir =
        staging_package_dir(staging_root, &manifest, package).map_err(RenderError::Other)?;
    let mut written = Vec::new();
    let mut staged = Vec::new();
    for (artifact_path, bytes) in rendered {
        let path = etc_relative_artifact_path(&artifact_path).map_err(RenderError::Other)?;
        let sha256 = format!("sha256:{:x}", Sha256::digest(&bytes));
        let payload = format!("payload/{}", sha256.trim_start_matches("sha256:"));
        crate::config_eval::materialize::write_bytes_beneath(&pkg_dir, &payload, &bytes, "0644")
            .with_context(|| format!("staging {artifact_path}"))
            .map_err(RenderError::Other)?;
        staged.push(StagedArtifact {
            path,
            payload,
            mode: "0644".to_string(),
            sha256,
        });
        written.push(artifact_path);
    }
    staged.sort_by(|left, right| left.path.cmp(&right.path));
    if staged.windows(2).any(|pair| pair[0].path == pair[1].path) {
        return Err(RenderError::Other(anyhow::anyhow!(
            "signed config metadata declares a duplicate target path"
        )));
    }
    let transaction = super::graph_transaction(&manifest).map_err(RenderError::Other)?;
    let package_pin = transaction
        .packages
        .get(package)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("graph transaction omitted package {package:?}"))
        .map_err(RenderError::Other)?;
    let index = StagedPackage {
        schema: "aos.render-stage/v1".to_string(),
        manifest: transaction.manifest,
        package_pin,
        package: package.to_string(),
        artifacts: staged,
        credentials: credential_handles,
        units,
    };
    let index_bytes = serde_json::to_vec(&index)
        .context("serializing staged package index")
        .map_err(RenderError::Other)?;
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
    })
    .map_err(RenderError::Other)?;

    write_marker(&render_marker(marker_root, package), &manifest, package)
        .map_err(RenderError::Other)?;
    Ok(written)
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
    render_inner(config, package, manifest_path, marker_root, staging_root)
        .map(|_| ())
        .map_err(|error| match error {
            RenderError::Config(error) | RenderError::Other(error) => error,
        })
}

/// Read the signed `expose.config` artifacts for `package` from the system
/// eval-pinned manifest, or an empty list when the package exposes no config.
struct SignedConfig {
    artifacts: Vec<crate::types::ConfigArtifactMeta>,
    credentials: Vec<CredentialMeta>,
}

fn signed_config(
    config: &ApmConfig,
    manifest: &ConfigManifest,
    package: &str,
) -> Result<SignedConfig> {
    if config.scope != ProfileScope::System {
        bail!("render-one operates on the system profile (run with --system)");
    }
    let pin = manifest
        .package_outputs
        .get(package)
        .with_context(|| format!("manifest has no runtime output pin for package '{package}'"))?;
    Ok(pin.legacy_config.as_ref().map_or(
        SignedConfig {
            artifacts: Vec::new(),
            credentials: Vec::new(),
        },
        |legacy| SignedConfig {
            artifacts: legacy.artifacts.clone(),
            credentials: legacy.credentials.clone(),
        },
    ))
}

pub(crate) fn canonicalize_credential_handles(
    package: &str,
    handles: Option<&Value>,
    signed: &[CredentialMeta],
) -> Result<Value> {
    let Some(handles) = handles else {
        return Ok(json!({}));
    };
    let handles = handles
        .as_object()
        .with_context(|| format!("credential handles for package '{package}' must be an object"))?;
    let signed = signed
        .iter()
        .map(|credential| (credential.name.as_str(), credential))
        .collect::<BTreeMap<_, _>>();
    let mut normalized = serde_json::Map::new();
    for (name, handle) in handles {
        validate_credential_name(name)
            .with_context(|| format!("invalid credential handle '{package}.{name}'"))?;
        let declaration = signed.get(name.as_str()).with_context(|| {
            format!("credential handle '{package}.{name}' has no signed expose.config declaration")
        })?;
        let fields = handle.as_object().with_context(|| {
            format!("credential handle '{package}.{name}' must contain only references")
        })?;
        if let Some(system_credential) = fields.get("system-credential") {
            if fields.len() != 1 {
                bail!("system credential handle '{package}.{name}' contains unsupported fields");
            }
            let system_credential = system_credential.as_str().with_context(|| {
                format!("system credential handle '{package}.{name}' must name a credential")
            })?;
            validate_credential_name(system_credential).with_context(|| {
                format!("invalid source system credential for '{package}.{name}'")
            })?;
            if declaration.source.is_none() {
                bail!("system credential handle '{package}.{name}' has no signed credstore target");
            }
            let mut reference = serde_json::Map::new();
            reference.insert("name".into(), Value::String(name.clone()));
            if let Some(source) = &declaration.source {
                reference.insert("source".into(), Value::String(source.clone()));
            }
            reference.insert("encrypted".into(), Value::Bool(declaration.encrypted));
            reference.insert("units".into(), json!(declaration.units));
            reference.insert(
                "ref".into(),
                Value::String(format!("system-credential:{system_credential}")),
            );
            normalized.insert(name.clone(), Value::Object(reference));
            continue;
        }

        const ALLOWED: &[&str] = &["name", "source", "encrypted", "units", "ref", "ciphertext"];
        if let Some(field) = fields
            .keys()
            .find(|field| !ALLOWED.contains(&field.as_str()))
        {
            bail!("credential handle '{package}.{name}' contains forbidden field {field:?}");
        }
        if fields.get("name").and_then(Value::as_str).unwrap_or(name) != name {
            bail!("credential handle '{package}.{name}' changes its signed name");
        }
        if fields.get("source").is_some()
            && fields.get("source").and_then(Value::as_str) != declaration.source.as_deref()
        {
            bail!("credential handle '{package}.{name}' changes its signed source");
        }
        if fields.get("encrypted").is_some()
            && fields.get("encrypted").and_then(Value::as_bool) != Some(declaration.encrypted)
        {
            bail!("credential handle '{package}.{name}' changes its signed encryption policy");
        }
        if let Some(ciphertext) = fields.get("ciphertext").and_then(Value::as_str)
            && declaration.ciphertext.as_deref() != Some(ciphertext)
        {
            bail!("credential handle '{package}.{name}' changes signed ciphertext");
        }
        if let Some(units) = fields.get("units") {
            let units: Vec<&str> = units
                .as_array()
                .with_context(|| {
                    format!("credential handle '{package}.{name}' units must be an array")
                })?
                .iter()
                .map(|unit| {
                    unit.as_str().with_context(|| {
                        format!("credential handle '{package}.{name}' has a non-string unit")
                    })
                })
                .collect::<Result<_>>()?;
            if units
                != declaration
                    .units
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            {
                bail!("credential handle '{package}.{name}' changes its signed unit set");
            }
        }
        let reference = fields
            .get("ref")
            .and_then(Value::as_str)
            .with_context(|| format!("credential handle '{package}.{name}' must declare ref"))?;
        let mut canonical = serde_json::Map::new();
        canonical.insert("name".into(), Value::String(name.clone()));
        if let Some(source) = &declaration.source {
            canonical.insert("source".into(), Value::String(source.clone()));
        }
        canonical.insert("encrypted".into(), Value::Bool(declaration.encrypted));
        canonical.insert("units".into(), json!(declaration.units));
        canonical.insert("ref".into(), Value::String(reference.to_string()));
        if let Some(ciphertext) = &declaration.ciphertext {
            canonical.insert("ciphertext".into(), Value::String(ciphertext.clone()));
        }
        let secret_ref: crate::secret_ref::SecretRef =
            serde_json::from_value(Value::Object(canonical.clone())).with_context(|| {
                format!("credential handle '{package}.{name}' is not an opaque secretRef")
            })?;
        secret_ref.validate_reference()?;
        normalized.insert(name.clone(), Value::Object(canonical));
    }
    Ok(Value::Object(normalized))
}

fn etc_relative_artifact_path(path: &str) -> Result<String> {
    let relative = path
        .strip_prefix("/etc/")
        .filter(|relative| !relative.is_empty())
        .with_context(|| format!("config artifact path must be strictly beneath /etc: {path}"))?;
    if relative
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        bail!("config artifact path has an unsafe component: {path}");
    }
    Ok(relative.to_string())
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
            config_dependency_outputs: BTreeMap::new(),
            closure: vec![RuntimeClosurePin {
                store_path_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                store_path: Some("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example".into()),
                realisations: vec![RuntimeRealisationPin {
                    nar_hash: format!("sha256:{}", "0".repeat(52)),
                    nar_size: 42,
                }],
            }],
            expose: None,
            expose_artifact: None,
            config_projection: None,
            legacy_config: None,
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
    fn json_to_toml_converts_scalars_and_nesting() {
        let v = json!({"a": 1, "b": "x", "c": [true, 2.5], "d": {"e": 3}});
        let t = json_to_toml(&v).unwrap();
        let table = t.as_table().unwrap();
        assert_eq!(table["a"].as_integer(), Some(1));
        assert_eq!(table["b"].as_str(), Some("x"));
        assert_eq!(table["c"].as_array().unwrap().len(), 2);
        assert_eq!(table["d"].as_table().unwrap()["e"].as_integer(), Some(3));
    }

    #[test]
    fn json_to_toml_rejects_null() {
        assert!(json_to_toml(&Value::Null).is_err());
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
    fn desired_config_extracted_from_manifest() {
        let mut value: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/config_manifest/manifest.json"
        ))
        .unwrap();
        value["config"] = json!({
            "example": { "redis.conf": { "port": 6380, "bind": "127.0.0.1" } }
        });
        let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
        let desired = desired_config_for(&manifest, "example").unwrap().unwrap();
        let artifact = &desired["redis.conf"];
        assert_eq!(artifact["port"].as_integer(), Some(6380));
        assert_eq!(artifact["bind"].as_str(), Some("127.0.0.1"));
        assert!(desired_config_for(&manifest, "absent").unwrap().is_none());
    }

    #[test]
    fn system_credential_shorthand_canonicalizes_to_stable_secret_ref() {
        let signed = [CredentialMeta {
            name: "join-token".into(),
            source: Some("/etc/credstore.encrypted/web/join-token".into()),
            ciphertext: None,
            units: vec!["web.service".into()],
            encrypted: true,
        }];
        let handles = json!({
            "join-token": {"system-credential": "bootstrap-token"}
        });
        let canonical = canonicalize_credential_handles("web", Some(&handles), &signed).unwrap();
        assert_eq!(
            canonical,
            json!({
                "join-token": {
                    "name": "join-token",
                    "source": "/etc/credstore.encrypted/web/join-token",
                    "encrypted": true,
                    "units": ["web.service"],
                    "ref": "system-credential:bootstrap-token"
                }
            })
        );
    }

    #[test]
    fn desired_config_rejects_bad_shapes_instead_of_rendering_defaults() {
        for bad in [
            json!("ignored"),
            json!({"env": "ignored"}),
            json!({
                "env": {"TOKEN": null}
            }),
        ] {
            let mut value: Value = serde_json::from_str(include_str!(
                "../../tests/fixtures/config_manifest/manifest.json"
            ))
            .unwrap();
            value["config"] = json!({"example": bad});
            let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
            assert!(desired_config_for(&manifest, "example").is_err());
        }
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
