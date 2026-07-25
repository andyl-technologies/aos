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

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::ConfigGraph;

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
    let manifest = project_manifest(full, &kept);

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
/// (build-spec §5.1): a package is in `fetched` iff `<root>/fetch/<p>.ok` exists,
/// and in `rendered` iff `<root>/render/<p>.ok` exists.
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
        .filter(|p| marker_root.join("fetch").join(format!("{p}.ok")).exists())
        .cloned()
        .collect();
    let rendered = packages
        .iter()
        .filter(|p| marker_root.join("render").join(format!("{p}.ok")).exists())
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
fn project_manifest(full: &Value, kept: &BTreeSet<String>) -> Value {
    let mut out = full.clone();
    let Some(obj) = out.as_object_mut() else {
        return out;
    };

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

    for field in ["config", "credentials"] {
        if let Some(map) = obj.get_mut(field).and_then(Value::as_object_mut) {
            map.retain(|key, _| kept.contains(key));
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

    out
}

// ---------------------------------------------------------------------------
// Canonical JSON hashing (build-spec §0)
// ---------------------------------------------------------------------------

/// `"sha256:" + hex(sha256(canonical_json(v)))` (build-spec §0).
pub fn hash_cjson(v: &Value) -> String {
    let mut buf = String::new();
    write_canonical(v, &mut buf);
    let digest = Sha256::digest(buf.as_bytes());
    format!("sha256:{}", hex::encode(digest))
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
