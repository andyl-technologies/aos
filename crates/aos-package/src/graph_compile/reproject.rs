//! The degraded re-projected-manifest commit (build-spec §5).
//!
//! When the pre-commit wing finishes with some packages dropped (a fetch
//! exhausted its retry budget, or a render hit a config error), `aos-config.target`
//! still reaches `active` and `aos-activate` runs. It MUST NOT commit `/etc` from
//! "whatever happened to materialize" under the full manifest's identity — that
//! would be a generation whose content depends on transient fetch outcomes,
//! breaking content-addressing. Instead it commits a **re-projected manifest**:
//! the full manifest restricted to the packages that materialized, re-hashed
//! into a content-addressed generation id, with the dropped set recorded.
//!
//! # Algorithm
//!
//! 1. `M = { p : fetch(p).ok ∧ render(p).ok }`, `D = packages \ M` (§5.1).
//! 2. Close `M` under the config graph: drop any `p ∈ M` whose dependency is in
//!    `D`, to a fixpoint (§5.2). Cascade drops record `dependency_dropped:<dep>`.
//! 3. `manifest' = manifest` with `packages`/`config`/`credentials`/`graph`
//!    restricted to the final `M`; `generation_id = hash(manifest')` (§5.3).
//! 4. Record the final `D` (with reasons) and `source_manifest_hash =
//!    hash(full-manifest)` (§5.4).
//!
//! A full boot (`D = ∅`) re-hashes to exactly `hash(full-manifest)`: the
//! re-projection is the identity, so the happy path is indistinguishable from a
//! non-degraded eval (§5.3).
//!
//! # Recorded drop-set
//!
//! ```json
//! {
//!   "projected": true,
//!   "source_manifest_hash": "sha256:…",
//!   "dropped": [
//!     { "package": "nginx",    "reason": "fetch_failed" },
//!     { "package": "frontend", "reason": "dependency_dropped:nginx" }
//!   ]
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::ConfigGraph;
use crate::config_eval::materialize::ConfigManifest;

/// Why a package was dropped from the committed subset (build-spec §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// The package's own fetch marker was absent (download budget exhausted).
    FetchFailed,
    /// The package's own render marker was absent (config error).
    RenderFailed,
    /// A config-graph dependency was dropped, so this package cascaded out.
    DependencyDropped(String),
}

impl DropReason {
    /// The wire string recorded in the generation (`fetch_failed`,
    /// `render_failed`, or `dependency_dropped:<dep>`).
    pub fn label(&self) -> String {
        match self {
            DropReason::FetchFailed => "fetch_failed".to_string(),
            DropReason::RenderFailed => "render_failed".to_string(),
            DropReason::DependencyDropped(dep) => format!("dependency_dropped:{dep}"),
        }
    }
}

impl Serialize for DropReason {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.label())
    }
}

/// One recorded drop: the package and why it left the committed subset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DropRecord {
    /// The dropped package name.
    pub package: String,
    /// The drop reason (direct or cascade).
    pub reason: DropReason,
}

/// The outcome of re-projecting a full manifest onto the materialized subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reprojection {
    /// The re-projected manifest (`manifest'`), restricted to the kept set.
    pub manifest: Value,
    /// `hash(manifest')` — the content-addressed id of the committed generation.
    pub generation_id: String,
    /// `hash(full-manifest)` — the un-projected eval output (§5.4 auditability).
    pub source_manifest_hash: String,
    /// The packages that survived (the committed subset `M`), sorted.
    pub kept: BTreeSet<String>,
    /// The final drop-set `D` with reasons, sorted by package.
    pub dropped: Vec<DropRecord>,
    /// `D ≠ ∅` — whether this generation is a re-projection (degraded).
    pub projected: bool,
}

impl Reprojection {
    /// The recorded drop-set metadata, ready to serialize alongside the
    /// generation (build-spec §5.4).
    pub fn drop_record(&self) -> Value {
        serde_json::json!({
            "projected": self.projected,
            "source_manifest_hash": self.source_manifest_hash,
            "dropped": self.dropped,
        })
    }
}

/// Merges transaction-scoped rendered bytes and credential handles into a
/// projection, then recomputes its generation identity.
///
/// # Errors
///
/// Returns an error if a kept package's stage is absent, mismatched, unsafe,
/// tampered, conflicts with another owner, or makes the manifest invalid.
pub fn merge_staged_projection(
    source: &ConfigManifest,
    staging_root: &Path,
    projection: &mut Reprojection,
) -> Result<()> {
    let transaction = super::graph_transaction(source)?;
    let object = projection
        .manifest
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("re-projected manifest is not an object"))?;

    for package in &projection.kept {
        let expected_pin = transaction
            .packages
            .get(package)
            .with_context(|| format!("graph transaction omitted kept package {package:?}"))?;
        let directory = super::subverbs::staging_package_dir(staging_root, source, package)?;
        let stage = super::subverbs::read_staged_package(&directory)
            .with_context(|| format!("loading render stage for package {package:?}"))?;
        if stage.schema != "aos.render-stage/v1"
            || stage.manifest != transaction.manifest
            || &stage.package_pin != expected_pin
            || stage.package != *package
        {
            bail!("render stage identity disagrees for package {package:?}");
        }

        let raw_credentials = source
            .credentials
            .get(package)
            .cloned()
            .unwrap_or(Value::Null);
        let expected_credentials = source
            .package_outputs
            .get(package)
            .and_then(|pin| pin.config_projection.as_ref())
            .map(|pin| {
                super::subverbs::canonicalize_credential_handles(
                    package,
                    source.credentials.get(package),
                    &pin.config.credentials,
                )
            })
            .transpose()?
            .unwrap_or(raw_credentials);
        if stage.credentials != expected_credentials {
            bail!("render stage credential handles disagree for package {package:?}");
        }
        if let Some(expected) = source.config_projections.get(package) {
            let expected_artifacts = expected
                .artifacts
                .iter()
                .map(|artifact| {
                    let path = artifact
                        .path
                        .strip_prefix("/etc/")
                        .with_context(|| {
                            format!(
                                "migrated projection for package {package:?} has path outside /etc"
                            )
                        })?
                        .to_string();
                    Ok((path, (&artifact.sha256, artifact.mode.as_str())))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let staged_artifacts = stage
                .artifacts
                .iter()
                .map(|artifact| {
                    (
                        artifact.path.clone(),
                        (&artifact.sha256, artifact.mode.as_str()),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            if staged_artifacts != expected_artifacts || stage.units != expected.units {
                bail!(
                    "render stage bytes/actions disagree with authenticated migrated projection for package {package:?}"
                );
            }
        }

        let mut seen_paths = BTreeSet::new();
        for artifact in stage.artifacts {
            if !seen_paths.insert(artifact.path.clone()) {
                bail!(
                    "render stage for package {package:?} repeats /etc path {:?}",
                    artifact.path
                );
            }
            validate_staged_artifact(&artifact, package)?;
            let bytes =
                crate::config_eval::materialize::read_bytes_beneath(&directory, &artifact.payload)
                    .with_context(|| {
                        format!(
                            "reading staged payload for package {package:?} path {:?}",
                            artifact.path
                        )
                    })?;
            let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            if actual != artifact.sha256 {
                bail!(
                    "staged payload hash mismatch for package {package:?} path {:?}",
                    artifact.path
                );
            }
            let text = String::from_utf8(bytes).with_context(|| {
                format!(
                    "rendered config for package {package:?} path {:?} is not UTF-8",
                    artifact.path
                )
            })?;
            let entry = serde_json::json!({
                "kind": "text",
                "text": text,
                "mode": artifact.mode,
            });
            let etc = object
                .get_mut("etc")
                .and_then(Value::as_object_mut)
                .context("re-projected manifest has no etc object")?;
            if let Some(existing) = etc.get(&artifact.path)
                && existing != &entry
            {
                bail!(
                    "rendered /etc path {:?} for package {package:?} conflicts with evaluated content",
                    artifact.path
                );
            }
            etc.insert(artifact.path.clone(), entry);

            let owners = object
                .get_mut("ownership")
                .and_then(Value::as_object_mut)
                .and_then(|ownership| ownership.get_mut("etc"))
                .and_then(Value::as_object_mut)
                .context("re-projected manifest has no ownership.etc object")?;
            if let Some(owner) = owners.get(&artifact.path).and_then(Value::as_str)
                && owner != package
            {
                bail!(
                    "rendered /etc path {:?} is owned by {owner:?}, not {package:?}",
                    artifact.path
                );
            }
            owners.insert(artifact.path, Value::String(package.clone()));
        }

        for (unit, action) in stage.units {
            let entry = serde_json::json!({
                "action": action,
                "credentials": [],
                "enable": false,
            });
            {
                let units = object
                    .get_mut("units")
                    .and_then(Value::as_object_mut)
                    .context("re-projected manifest has no units object")?;
                if let Some(existing) = units.get(&unit)
                    && existing != &entry
                {
                    bail!(
                        "config reconcile action for unit {unit:?} conflicts with evaluated content"
                    );
                }
                units.insert(unit.clone(), entry);
            }
            {
                let unit_owners = object
                    .get_mut("ownership")
                    .and_then(Value::as_object_mut)
                    .and_then(|ownership| ownership.get_mut("units"))
                    .and_then(Value::as_object_mut)
                    .context("re-projected manifest has no ownership.units object")?;
                if let Some(owner) = unit_owners.get(&unit).and_then(Value::as_str)
                    && owner != package
                {
                    bail!("config reconcile unit {unit:?} is owned by {owner:?}, not {package:?}");
                }
                unit_owners.insert(unit, Value::String(package.clone()));
            }
        }

        let credentials = object
            .get_mut("credentials")
            .and_then(Value::as_object_mut)
            .context("re-projected manifest has no credentials object")?;
        if stage.credentials.is_null() {
            credentials.remove(package);
        } else {
            credentials.insert(package.clone(), stage.credentials);
        }
    }

    let merged: ConfigManifest = serde_json::from_value(projection.manifest.clone())
        .context("parsing staged re-projected manifest")?;
    merged
        .validate()
        .context("validating staged re-projected manifest")?;
    projection.generation_id = hash_cjson(&projection.manifest);
    Ok(())
}

fn validate_staged_artifact(
    artifact: &super::subverbs::StagedArtifact,
    package: &str,
) -> Result<()> {
    if artifact.path.is_empty()
        || artifact.path.starts_with('/')
        || artifact.path == "aos-job-scripts"
        || artifact.path.starts_with("aos-job-scripts/")
        || artifact
            .path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        bail!(
            "render stage for package {package:?} has unsafe /etc path {:?}",
            artifact.path
        );
    }
    let digest = artifact
        .sha256
        .strip_prefix("sha256:")
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .with_context(|| {
            format!(
                "render stage for package {package:?} has invalid hash {:?}",
                artifact.sha256
            )
        })?;
    if artifact.payload != format!("payload/{digest}") {
        bail!(
            "render stage for package {package:?} has unbound payload path {:?}",
            artifact.payload
        );
    }
    if artifact.mode != "0644" {
        bail!(
            "render stage for package {package:?} has unsupported mode {:?}",
            artifact.mode
        );
    }
    Ok(())
}

/// Re-project `full` onto the packages that materialized, given the on-disk
/// marker sets (build-spec §5).
///
/// `fetched` / `rendered` are the package sets whose `/run/aos/{fetch,render}/<p>.ok`
/// markers exist; [`materialized_subset`] derives them from a marker root.
///
/// # Errors
///
/// Returns an error only if the manifest cannot be canonicalized/hashed
/// (effectively infallible for valid JSON).
pub fn reproject_manifest(
    full: &Value,
    graph: &ConfigGraph,
    fetched: &BTreeSet<String>,
    rendered: &BTreeSet<String>,
) -> Result<Reprojection> {
    let packages = manifest_packages(full);

    // §5.1 — a package is kept iff BOTH its markers exist.
    let mut kept: BTreeSet<String> = packages
        .iter()
        .filter(|p| fetched.contains(*p) && rendered.contains(*p))
        .cloned()
        .collect();

    // Record the *direct* drop reason for every initially-dropped package.
    let mut reasons: BTreeMap<String, DropReason> = BTreeMap::new();
    for p in &packages {
        if kept.contains(p) {
            continue;
        }
        // A package that fetched but failed render is render_failed; otherwise
        // fetch_failed (covers "never fetched" and "fetched-but-not-rendered"
        // where fetch is the missing prerequisite).
        let reason = if fetched.contains(p) && !rendered.contains(p) {
            DropReason::RenderFailed
        } else {
            DropReason::FetchFailed
        };
        reasons.insert(p.clone(), reason);
    }

    // §5.2 — close under the config graph: iterate to a fixpoint, dropping any
    // kept package that depends on a dropped one (cascade).
    loop {
        let mut newly_dropped: Vec<(String, String)> = Vec::new();
        for p in &kept {
            for dep in graph.edges.get(p).map(Vec::as_slice).unwrap_or(&[]) {
                if !kept.contains(dep) {
                    newly_dropped.push((p.clone(), dep.clone()));
                    break;
                }
            }
        }
        if newly_dropped.is_empty() {
            break;
        }
        for (p, dep) in newly_dropped {
            kept.remove(&p);
            reasons
                .entry(p)
                .or_insert(DropReason::DependencyDropped(dep));
        }
    }

    let mut dropped: Vec<DropRecord> = reasons
        .into_iter()
        .filter(|(p, _)| !kept.contains(p))
        .map(|(package, reason)| DropRecord { package, reason })
        .collect();
    dropped.sort_by(|a, b| a.package.cmp(&b.package));

    // §5.3 — restrict the manifest (and the graph projection) to `kept`.
    let manifest = project_manifest(full, &kept)?;

    let generation_id = hash_cjson(&manifest);
    let source_manifest_hash = hash_cjson(full);

    Ok(Reprojection {
        projected: !dropped.is_empty(),
        manifest,
        generation_id,
        source_manifest_hash,
        kept,
        dropped,
    })
}

/// Compute the materialized subsets `(fetched, rendered)` from the marker root
/// (build-spec §5.1): a package is included only when its marker payload
/// matches the graph compiler's current manifest and package pin identity.
///
/// Markers are the authoritative "fully present + rendered" signal (they survive
/// a unit going inactive), so the subset is read from disk, not from systemd
/// unit states.
pub fn materialized_subset(
    packages: &BTreeSet<String>,
    marker_root: &Path,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let fetched = packages
        .iter()
        .filter(|p| super::subverbs::marker_is_current(marker_root, "fetch", p))
        .cloned()
        .collect();
    let rendered = packages
        .iter()
        .filter(|p| super::subverbs::marker_is_current(marker_root, "render", p))
        .cloned()
        .collect();
    (fetched, rendered)
}

/// The package names declared by a manifest (`manifest.packages`), as a sorted
/// set. Accepts a string array or an object array with `name`/`package` keys.
pub fn manifest_packages(manifest: &Value) -> BTreeSet<String> {
    let Some(arr) = manifest.get("packages").and_then(Value::as_array) else {
        return BTreeSet::new();
    };
    arr.iter()
        .filter_map(|item| {
            item.as_str().map(str::to_string).or_else(|| {
                item.as_object()
                    .and_then(|o| o.get("name").or_else(|| o.get("package")))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
        })
        .collect()
}

/// Restrict the package-keyed fields of a manifest to `kept`.
///
/// Filters `packages` (array), the package-keyed `config` and `credentials`
/// maps, and a `graph.edges` projection (both endpoints must be kept). Every
/// other field is passed through verbatim, since fields like `etc`/`units`/
/// `storePaths` are not package-keyed and cannot be projected by package alone
/// (build-spec §5.3).
fn project_manifest(full: &Value, kept: &BTreeSet<String>) -> Result<Value> {
    if kept == &manifest_packages(full) {
        return Ok(full.clone());
    }
    let mut out = full.clone();
    let Some(obj) = out.as_object_mut() else {
        return Ok(out);
    };

    let ownership = obj
        .get("ownership")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let retained = |field: &str, keys: Vec<String>| -> Result<BTreeSet<String>> {
        let owners = ownership
            .get(field)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut result = BTreeSet::new();
        for key in keys {
            let owner = owners
                .get(&key)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "cannot degraded-project manifest: ownership.{field} does not name artifact {key:?}"
                    )
                })?;
            if owner == "@base" || owner == "@host" || kept.contains(owner) {
                result.insert(key);
            }
        }
        Ok(result)
    };

    let map_keys = |field: &str| -> Vec<String> {
        obj.get(field)
            .and_then(Value::as_object)
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default()
    };
    let etc = retained("etc", map_keys("etc"))?;
    let units = retained("units", map_keys("units"))?;
    let job_scripts = retained("jobScripts", map_keys("jobScripts"))?;
    let users = retained(
        "users",
        obj.get("users")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|user| user.get("name").and_then(Value::as_str))
            .map(str::to_string)
            .collect(),
    )?;
    let presets = retained(
        "presets",
        obj.get("presets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|preset| {
                Some(format!(
                    "{}:{}",
                    preset.get("unit")?.as_str()?,
                    preset.get("source")?.as_str()?
                ))
            })
            .collect(),
    )?;
    let store_paths = retained(
        "storePaths",
        obj.get("storePaths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
    )?;

    if let Some(packages) = obj.get_mut("packages").and_then(Value::as_array_mut) {
        packages.retain(|item| {
            let name = item.as_str().map(str::to_string).or_else(|| {
                item.as_object()
                    .and_then(|o| o.get("name").or_else(|| o.get("package")))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
            name.map(|n| kept.contains(&n)).unwrap_or(false)
        });
    }

    for field in [
        "packageOutputs",
        "config",
        "credentials",
        "configProjections",
    ] {
        if let Some(map) = obj.get_mut(field).and_then(Value::as_object_mut) {
            map.retain(|key, _| kept.contains(key));
        }
    }

    for (field, keys) in [
        ("etc", &etc),
        ("units", &units),
        ("jobScripts", &job_scripts),
    ] {
        if let Some(map) = obj.get_mut(field).and_then(Value::as_object_mut) {
            map.retain(|key, _| keys.contains(key));
        }
    }
    if let Some(records) = obj.get_mut("users").and_then(Value::as_array_mut) {
        records.retain(|record| {
            record
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| users.contains(name))
        });
    }
    if let Some(records) = obj.get_mut("presets").and_then(Value::as_array_mut) {
        records.retain(|record| {
            let Some(unit) = record.get("unit").and_then(Value::as_str) else {
                return false;
            };
            let Some(source) = record.get("source").and_then(Value::as_str) else {
                return false;
            };
            presets.contains(&format!("{unit}:{source}"))
        });
    }
    if let Some(paths) = obj.get_mut("storePaths").and_then(Value::as_array_mut) {
        paths.retain(|path| path.as_str().is_some_and(|path| store_paths.contains(path)));
    }

    if let Some(index) = obj.get_mut("ownership").and_then(Value::as_object_mut) {
        for (field, keys) in [
            ("etc", &etc),
            ("units", &units),
            ("jobScripts", &job_scripts),
            ("users", &users),
            ("presets", &presets),
            ("storePaths", &store_paths),
        ] {
            let Some(map) = index.get_mut(field).and_then(Value::as_object_mut) else {
                if !keys.is_empty() {
                    bail!("cannot degraded-project manifest: ownership.{field} is absent");
                }
                continue;
            };
            map.retain(|key, _| keys.contains(key));
        }
    }

    // graph.edges projection: keep an edge only when both endpoints survive.
    if let Some(graph) = obj.get_mut("graph").and_then(Value::as_object_mut)
        && let Some(edges) = graph.get_mut("edges").and_then(Value::as_object_mut)
    {
        edges.retain(|key, _| kept.contains(key));
        for deps in edges.values_mut() {
            if let Some(list) = deps.as_array_mut() {
                list.retain(|d| d.as_str().map(|s| kept.contains(s)).unwrap_or(false));
            }
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Canonical JSON hashing (build-spec §0)
// ---------------------------------------------------------------------------

/// `"sha256:" + hex(sha256(canonical_json(v)))` (build-spec §0).
pub fn hash_cjson(v: &Value) -> String {
    let buf = canonical_json(v);
    let digest = Sha256::digest(buf.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

/// Serializes a JSON value using the manifest's canonical byte encoding.
///
/// Object members are sorted recursively and no insignificant whitespace is
/// emitted. Attestation uses these exact bytes so PCR 15 identifies the same
/// value as [`hash_cjson`].
pub(crate) fn canonical_json(v: &Value) -> String {
    let mut buf = String::new();
    write_canonical(v, &mut buf);
    buf
}

/// Serialize `v` to canonical JSON: object members sorted by key, arrays in
/// declared order, no insignificant whitespace.
fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // serde_json::Map iterates in sorted key order by default (BTreeMap)
            // but may preserve insertion order under the `preserve_order`
            // feature; sort explicitly so canonicalization is feature-independent.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_canonical(value, out);
            }
            out.push('}');
        }
    }
}

/// Write a JSON string with minimal RFC 8259 escaping (build-spec §0).
fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
