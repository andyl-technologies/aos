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
//! /run/aos/fetch/<pkg>.ok    written iff every closure path verified + imported
//! /run/aos/render/<pkg>.ok   written iff the artifact(s) validated + staged
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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::profile::Profile;
use crate::profile::meta::list_meta;
use crate::types::{ProfileScope, validate_package_name};

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
fn write_marker(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, b"ok\n").with_context(|| format!("writing marker {}", path.display()))
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
fn manifest_has_package(manifest: &Value, pkg: &str) -> bool {
    super::reproject::manifest_packages(manifest).contains(pkg)
}

/// The closure roots the manifest pinned for `pkg`: every `storePaths` entry
/// whose store-path *name* component is `pkg` or `pkg-<version>`.
///
/// The manifest's `storePaths` carry the GC-root closure roots with the package
/// name embedded (`/nix/store/<hash>-redis-8.2`). Matching by name selects the
/// roots that belong to `pkg` without a separate per-package closure map.
fn select_closure_roots(store_paths: &[String], pkg: &str) -> Vec<String> {
    store_paths
        .iter()
        .filter(|p| store_path_name(p).map(|name| name_matches(name, pkg)).unwrap_or(false))
        .cloned()
        .collect()
}

/// Whether a store-path name component belongs to `pkg`: an exact match, or
/// `<pkg>-<version>` where the version begins with a digit. The digit boundary
/// keeps `redis` from spuriously selecting a sibling package like `redis-tools`
/// (whose name continues with a letter, not a version).
fn name_matches(name: &str, pkg: &str) -> bool {
    if name == pkg {
        return true;
    }
    name.strip_prefix(pkg)
        .and_then(|rest| rest.strip_prefix('-'))
        .and_then(|version| version.chars().next())
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
}

/// The name component of a `/nix/store/<hash>-<name>` path (everything after the
/// 32-character hash and its `-` separator).
fn store_path_name(path: &str) -> Option<&str> {
    let base = path.rsplit('/').next()?;
    // <hash>-<name>: the hash is the nixbase32 component before the first '-'.
    let dash = base.find('-')?;
    Some(&base[dash + 1..])
}

/// Read `storePaths` from a manifest as a `Vec<String>`.
fn manifest_store_paths(manifest: &Value) -> Vec<String> {
    manifest
        .get("storePaths")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Extract the per-package desired config block from `manifest.config[pkg]`,
/// converted into the [`render_package_config`](crate::render_package_config)
/// input shape (`artifact → field → value`).
fn desired_config_for(
    manifest: &Value,
    pkg: &str,
) -> Option<BTreeMap<String, BTreeMap<String, toml::Value>>> {
    let block = manifest.get("config")?.get(pkg)?.as_object()?;
    let mut artifacts = BTreeMap::new();
    for (artifact, fields) in block {
        let fields_obj = fields.as_object()?;
        let mut converted = BTreeMap::new();
        for (field, value) in fields_obj {
            converted.insert(field.clone(), json_to_toml(value)?);
        }
        artifacts.insert(artifact.clone(), converted);
    }
    Some(artifacts)
}

/// Convert a JSON value into the equivalent `toml::Value`.
///
/// `null` has no TOML representation and yields `None` (the caller treats it as
/// an unconvertible field). Integers prefer `toml::Value::Integer`, other
/// numbers become `Float`.
fn json_to_toml(v: &Value) -> Option<toml::Value> {
    Some(match v {
        Value::Null => return None,
        Value::Bool(b) => toml::Value::Boolean(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else {
                toml::Value::Float(n.as_f64()?)
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
    _config: &ApmConfig,
    package: &str,
    manifest_path: &Path,
    marker_root: &Path,
    json_out: bool,
    printer: &Printer,
) -> i32 {
    match fetch_inner(package, manifest_path, marker_root).await {
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
            // A failed fetch MUST NOT leave a marker (build-spec §4.1).
            clear_marker(&fetch_marker(marker_root, package));
            emit_err(json_out, "fetch", package, &err);
            1
        }
    }
}

/// The fallible body of `fetch`: validate, select the closure roots, realise
/// them through the configured substituters, verify presence, write the marker.
async fn fetch_inner(
    package: &str,
    manifest_path: &Path,
    marker_root: &Path,
) -> Result<Vec<String>> {
    validate_package_name(package).context("invalid package argument")?;
    let manifest = read_manifest(manifest_path)?;
    if !manifest_has_package(&manifest, package) {
        bail!("package '{package}' is not in {}", manifest_path.display());
    }

    let store_paths = manifest_store_paths(&manifest);
    let roots = select_closure_roots(&store_paths, package);
    if roots.is_empty() {
        bail!("manifest pins no store paths for package '{package}'");
    }

    // Materialize each closure root via the configured substituters. `nix-store
    // --realise` is idempotent: an already-present closure is a fast no-op
    // (the idempotent already-present case of build-spec §4.1).
    for root in &roots {
        realise(root)
            .await
            .with_context(|| format!("realising closure root {root}"))?;
    }

    // Verify every root is now valid in the store before claiming success.
    let missing = crate::store::filter_missing(&roots)
        .await
        .context("checking closure validity")?;
    if !missing.is_empty() {
        bail!(
            "closure for '{package}' still missing {} path(s) after fetch: {}",
            missing.len(),
            missing.join(", ")
        );
    }

    // Marker written only after every path verifies + imports (build-spec §4.1).
    write_marker(&fetch_marker(marker_root, package))?;
    Ok(roots)
}

/// `nix-store --realise <root>` — substitute a closure from configured caches.
async fn realise(root: &str) -> Result<()> {
    let status = tokio::process::Command::new("nix-store")
        .args(["--realise", root])
        .status()
        .await
        .with_context(|| format!("spawning nix-store --realise {root}"))?;
    if !status.success() {
        bail!("nix-store --realise {root} exited with {status}");
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
            clear_marker(&render_marker(marker_root, package));
            emit_err(json_out, "render-one", package, &err);
            EXIT_CONFIG_ERROR
        }
        Err(RenderError::Other(err)) => {
            clear_marker(&render_marker(marker_root, package));
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

    // Precondition: the package's closure is local (build-spec §4.2). Fail fast
    // rather than render against an absent store path.
    if !fetch_marker(marker_root, package).exists() {
        return Err(RenderError::Other(anyhow::anyhow!(
            "fetch marker for '{package}' is absent; run `apm fetch {package}` first"
        )));
    }

    let manifest = read_manifest(manifest_path).map_err(RenderError::Other)?;
    if !manifest_has_package(&manifest, package) {
        return Err(RenderError::Other(anyhow::anyhow!(
            "package '{package}' is not in {}",
            manifest_path.display()
        )));
    }

    // Look up the package's signed expose.config artifacts from the profile.
    let artifacts = signed_artifacts(config, package).map_err(RenderError::Other)?;
    let desired = desired_config_for(&manifest, package);

    // Render against the signed schema. A validation failure here is the
    // permanent config-error (exit 2); everything else is operational.
    let rendered = crate::render_package_config(package, &artifacts, desired.as_ref())
        .map_err(RenderError::Config)?;

    // Stage the rendered bytes under <staging>/<pkg>/<artifact-path>; never
    // touch live /etc.
    let pkg_dir = staging_root.join(package);
    let mut written = Vec::new();
    for (artifact, bytes) in rendered {
        // Defense in depth for the never-touch-/etc invariant: a `..` component
        // would escape the staging root. trim_start_matches('/') neutralizes an
        // absolute path but not traversal, so reject `..` outright.
        if artifact
            .path
            .split('/')
            .any(|seg| seg == ".." || seg == ".")
        {
            return Err(RenderError::Other(anyhow::anyhow!(
                "artifact path must not contain '.'/'..' components: {}",
                artifact.path
            )));
        }
        let dest = pkg_dir.join(artifact.path.trim_start_matches('/'));
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))
                .map_err(RenderError::Other)?;
        }
        std::fs::write(&dest, &bytes)
            .with_context(|| format!("staging {}", dest.display()))
            .map_err(RenderError::Other)?;
        written.push(artifact.path.clone());
    }

    write_marker(&render_marker(marker_root, package)).map_err(RenderError::Other)?;
    Ok(written)
}

/// Read the signed `expose.config` artifacts for `package` from the system
/// package profile, or an empty list when the package exposes no config.
fn signed_artifacts(
    config: &ApmConfig,
    package: &str,
) -> Result<Vec<crate::types::ConfigArtifactMeta>> {
    if config.scope != ProfileScope::System {
        bail!("render-one operates on the system profile (run with --system)");
    }
    let profile = Profile::open_readonly(ProfileScope::System);
    let installed = list_meta(&profile)?;
    for entry in &installed {
        let Some(apm) = entry.apm.as_ref() else {
            continue;
        };
        if apm.name != package {
            continue;
        }
        if let Some(expose) = apm.expose.as_ref() {
            return Ok(expose.config.artifacts.clone());
        }
    }
    // No signed expose config: render-one is a clean no-op (marker still set).
    Ok(Vec::new())
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Read + parse a manifest file.
fn read_manifest(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading manifest {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing manifest {}", path.display()))
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

    #[test]
    fn store_path_name_strips_hash() {
        assert_eq!(
            store_path_name("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-redis-8.2"),
            Some("redis-8.2")
        );
        assert_eq!(store_path_name("not-a-store-path"), Some("a-store-path"));
        assert_eq!(store_path_name("/nix/store/nodash"), None);
    }

    #[test]
    fn select_closure_roots_matches_name_and_versioned_name() {
        let paths = vec![
            "/nix/store/h1-redis-8.2".to_string(),
            "/nix/store/h2-redis".to_string(),
            "/nix/store/h3-redis-tools-1.0".to_string(),
            "/nix/store/h4-nginx-1.27".to_string(),
        ];
        let roots = select_closure_roots(&paths, "redis");
        // The digit-boundary heuristic selects `redis` and `redis-8.2` but NOT
        // the sibling package `redis-tools-1.0` (continues with a letter).
        assert_eq!(
            roots,
            vec![
                "/nix/store/h1-redis-8.2".to_string(),
                "/nix/store/h2-redis".to_string(),
            ]
        );
        assert!(select_closure_roots(&paths, "nginx").contains(&"/nix/store/h4-nginx-1.27".to_string()));
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
        assert!(json_to_toml(&Value::Null).is_none());
    }

    #[test]
    fn marker_paths_are_under_root() {
        let root = Path::new("/run/aos");
        assert_eq!(fetch_marker(root, "redis"), Path::new("/run/aos/fetch/redis.ok"));
        assert_eq!(render_marker(root, "redis"), Path::new("/run/aos/render/redis.ok"));
    }

    #[test]
    fn desired_config_extracted_from_manifest() {
        let manifest = json!({
            "packages": ["redis"],
            "config": { "redis": { "redis.conf": { "port": 6380, "bind": "127.0.0.1" } } }
        });
        let desired = desired_config_for(&manifest, "redis").unwrap();
        let artifact = &desired["redis.conf"];
        assert_eq!(artifact["port"].as_integer(), Some(6380));
        assert_eq!(artifact["bind"].as_str(), Some("127.0.0.1"));
        assert!(desired_config_for(&manifest, "absent").is_none());
    }
}
