//! `apm switch --dry-run` — the off-host/on-host config preflight
//! used by dry-run and preflight operations.
//!
//! Because the eval is a pure function of its inputs, it runs identically
//! off-host (CI `checks.config-eval`) and on-host. `--dry-run` runs the
//! evaluator, loads the current generation's stored `gen-N/manifest.json`,
//! prints a **structural diff**, and stops before
//! `Profile::new_generation()`/`switch_to()`/`activate` — no generation, no
//! `/etc` swap. The same Rust codepath backs the CI gate, so green CI is a real
//! prediction of on-box behavior.
//!
//! ```text
//! manifest diff (gen-7 -> candidate)
//!   /etc entries
//!     ~ aos/packages/web/config.env   (changed)
//!     + nftables/forward.conf         (new; provider: firewall)
//!     - aos/packages/legacy/config.toml (package 'legacy' removed)
//!   systemd units
//!     ~ web.service        reload
//!     + tracing.service    start
//!   packages to fetch (closure delta)
//!     + /nix/store/...-otel-collector-0.9
//! ```
//!
//! The diff is computed over the canonical manifest `Value`s; [`diff_manifests`]
//! is pure and unit-tested over fixtures. The orchestration
//! ([`run_switch_dry_run`]) drives the (builder-gated) evaluator to produce the
//! candidate, then diffs against the loaded base.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Value, json};

/// A single `/etc` entry change in the diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtcChange {
    /// The `/etc`-relative key.
    pub path: String,
    /// What happened to it.
    pub kind: ChangeKind,
}

/// A single unit action in the diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitChange {
    /// The unit name.
    pub unit: String,
    /// The reconcile action (`restart`, `reload`, `none`, `start`, or `stop`).
    pub action: String,
    /// Whether the unit was added, removed, or changed.
    pub kind: ChangeKind,
}

/// The kind of a structural change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// Present in the candidate, absent in the base.
    Added,
    /// Present in the base, absent in the candidate.
    Removed,
    /// Present in both, but the value differs.
    Changed,
}

impl ChangeKind {
    /// The diff sigil (`+`/`-`/`~`).
    pub fn sigil(self) -> char {
        match self {
            ChangeKind::Added => '+',
            ChangeKind::Removed => '-',
            ChangeKind::Changed => '~',
        }
    }
}

/// The structural difference between a base manifest and a candidate manifest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManifestDiff {
    /// `/etc` entry changes, sorted by path.
    pub etc: Vec<EtcChange>,
    /// Per-unit reconcile actions, sorted by unit.
    pub units: Vec<UnitChange>,
    /// Store paths the candidate pins that the base did not (closure delta).
    pub fetch_plan: Vec<String>,
}

impl ManifestDiff {
    /// Whether the diff is empty (the candidate is structurally identical).
    pub fn is_empty(&self) -> bool {
        self.etc.is_empty() && self.units.is_empty() && self.fetch_plan.is_empty()
    }

    /// Render the human-readable diff (operability.md format).
    pub fn render_human(&self, base_label: &str) -> String {
        let mut out = format!("manifest diff ({base_label} -> candidate)\n");
        out.push_str("\n  /etc entries\n");
        if self.etc.is_empty() {
            out.push_str("    (no changes)\n");
        } else {
            for change in &self.etc {
                out.push_str(&format!("    {} {}\n", change.kind.sigil(), change.path));
            }
        }
        out.push_str("\n  systemd units\n");
        if self.units.is_empty() {
            out.push_str("    (no changes)\n");
        } else {
            for change in &self.units {
                out.push_str(&format!(
                    "    {} {:<24} {}\n",
                    change.kind.sigil(),
                    change.unit,
                    change.action
                ));
            }
        }
        out.push_str("\n  packages to fetch (closure delta)\n");
        if self.fetch_plan.is_empty() {
            out.push_str("    (none)\n");
        } else {
            for path in &self.fetch_plan {
                out.push_str(&format!("    + {path}\n"));
            }
        }
        out.push_str(&format!(
            "\n{} etc change(s), {} unit action(s), {} path(s) to fetch.\n",
            self.etc.len(),
            self.units.len(),
            self.fetch_plan.len()
        ));
        out
    }

    /// Render the `--json` envelope (operability.md `etc_diff`, `unit_actions`,
    /// `fetch_plan`, `resolution_trace`). `resolution_trace` is supplied by the
    /// caller (it comes from the fixpoint outcome, not the diff).
    pub fn to_json(&self, resolution_trace: &[String]) -> Value {
        json!({
            "etc_diff": self.etc.iter().map(|c| json!({
                "path": c.path,
                "kind": match c.kind {
                    ChangeKind::Added => "added",
                    ChangeKind::Removed => "removed",
                    ChangeKind::Changed => "changed",
                },
            })).collect::<Vec<_>>(),
            "unit_actions": self.units.iter().map(|u| json!({
                "unit": u.unit,
                "action": u.action,
                "kind": match u.kind {
                    ChangeKind::Added => "added",
                    ChangeKind::Removed => "removed",
                    ChangeKind::Changed => "changed",
                },
            })).collect::<Vec<_>>(),
            "fetch_plan": self.fetch_plan,
            "resolution_trace": resolution_trace,
        })
    }
}

/// Compute the structural diff between a base and a candidate manifest
/// (operability.md §Dry-run). Pure over the two `Value`s.
///
/// `etc` is keyed by `/etc`-relative path; a value difference (including a
/// `kind`/`text`/`target`/`mode` change) is [`ChangeKind::Changed`]. `units`
/// reports each candidate unit's reconcile action, marking units absent from the
/// base as new (`start`). `fetch_plan` is the candidate `storePaths` set minus
/// the base's — the closure delta the switch would have to materialize.
pub fn diff_manifests(base: &Value, candidate: &Value) -> ManifestDiff {
    ManifestDiff {
        etc: diff_etc(base, candidate),
        units: diff_units(base, candidate),
        fetch_plan: fetch_delta(base, candidate),
    }
}

/// Diff the `etc` maps of two manifests.
fn diff_etc(base: &Value, candidate: &Value) -> Vec<EtcChange> {
    let base_etc = object_or_empty(base.get("etc"));
    let cand_etc = object_or_empty(candidate.get("etc"));
    let mut changes = Vec::new();
    for (key, cand_val) in &cand_etc {
        match base_etc.get(key) {
            None => changes.push(EtcChange {
                path: key.clone(),
                kind: ChangeKind::Added,
            }),
            Some(base_val) if *base_val != *cand_val => changes.push(EtcChange {
                path: key.clone(),
                kind: ChangeKind::Changed,
            }),
            Some(_) => {}
        }
    }
    for key in base_etc.keys() {
        if !cand_etc.contains_key(key) {
            changes.push(EtcChange {
                path: key.clone(),
                kind: ChangeKind::Removed,
            });
        }
    }
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    changes
}

/// Diff the `units` maps of two manifests, including removed units that the
/// pre-swap reconciler stops while their old definitions are still loaded.
fn diff_units(base: &Value, candidate: &Value) -> Vec<UnitChange> {
    let base_units = object_or_empty(base.get("units"));
    let cand_units = object_or_empty(candidate.get("units"));
    let mut changes = Vec::new();
    for (unit, cand_val) in &cand_units {
        let base_val = base_units.get(unit);
        // A unit appears in the diff when it is new OR its definition changed.
        let added = base_val.is_none();
        let changed = base_val.map(|b| *b != *cand_val).unwrap_or(true);
        if !changed {
            continue;
        }
        let action = if added {
            "start".to_string()
        } else {
            cand_val
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("restart")
                .to_string()
        };
        changes.push(UnitChange {
            unit: unit.clone(),
            action,
            kind: if added {
                ChangeKind::Added
            } else {
                ChangeKind::Changed
            },
        });
    }
    for unit in base_units.keys() {
        if !cand_units.contains_key(unit) {
            changes.push(UnitChange {
                unit: unit.clone(),
                action: "stop".to_string(),
                kind: ChangeKind::Removed,
            });
        }
    }
    changes.sort_by(|a, b| a.unit.cmp(&b.unit));
    changes
}

/// The candidate `storePaths` set minus the base's (the closure delta).
fn fetch_delta(base: &Value, candidate: &Value) -> Vec<String> {
    let base_paths: std::collections::BTreeSet<String> = store_paths(base);
    let mut delta: Vec<String> = store_paths(candidate)
        .into_iter()
        .filter(|p| !base_paths.contains(p))
        .collect();
    delta.sort();
    delta
}

/// Extract `storePaths` from a manifest as a set.
fn store_paths(manifest: &Value) -> std::collections::BTreeSet<String> {
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

/// A manifest sub-object as a `BTreeMap`, or empty when absent/not an object.
fn object_or_empty(value: Option<&Value>) -> BTreeMap<String, &Value> {
    value
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v)).collect())
        .unwrap_or_default()
}

/// Load and parse a manifest JSON file.
///
/// # Errors
///
/// Returns an error when the file cannot be read or is not valid JSON.
pub fn load_manifest(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading manifest {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing manifest {}", path.display()))
}

/// Run `apm switch --dry-run`: diff a pre-evaluated `candidate` manifest against
/// a `base` manifest and print the result, never touching the live system.
///
/// This is the pure, testable orchestration core: the (builder-gated) evaluator
/// produces `candidate_path` first (via [`super::run_eval_command`]); this
/// function loads both manifests, computes [`diff_manifests`], and renders the
/// human or `--json` form. It returns the diff so the caller (and the fleet test
/// oracle) can assert on it.
///
/// # Errors
///
/// Returns an error when either manifest cannot be read or parsed.
pub fn run_switch_dry_run(
    base_path: &Path,
    base_label: &str,
    candidate_path: &Path,
    resolution_trace: &[String],
    json_out: bool,
) -> Result<ManifestDiff> {
    let base = load_manifest(base_path)?;
    let candidate = load_manifest(candidate_path)?;
    let diff = diff_manifests(&base, &candidate);
    if json_out {
        println!("{}", diff.to_json(resolution_trace));
    } else {
        print!("{}", diff.render_human(base_label));
    }
    Ok(diff)
}

/// Parameters for `apm switch` (`--dry-run` and the real switch share this).
#[derive(Debug, Clone)]
pub struct SwitchParams {
    /// The eval command producing the candidate manifest (`out` is the
    /// candidate path the diff reads). For `--dry-run` this is a temp file.
    pub eval: super::EvalCommand,
    /// The base manifest to diff against (the live generation's
    /// `gen-N/manifest.json`, or any retained generation per `--diff-against`).
    pub base_manifest: std::path::PathBuf,
    /// Human label for the base side of the diff (e.g. `current`, `gen-7`).
    pub base_label: String,
    /// When `true`, stop after the diff (no manifest is committed live).
    pub dry_run: bool,
    /// Where a **real** switch publishes the committed manifest for the
    /// downstream fetch/render/activate pipeline to consume.
    pub live_manifest: std::path::PathBuf,
    /// Render the `--json` diff envelope instead of the human form.
    pub json_out: bool,
}

/// Run `apm switch` (operability.md §Dry-run).
///
/// Drives the (builder-gated) evaluator to a candidate manifest via
/// [`super::run_eval_command`], diffs it against the loaded base, and prints the
/// result. For `--dry-run` it stops there — a clean no-op on the live system.
/// For a real switch it atomically publishes the candidate and its exact graph,
/// compiles the transaction, and waits for the fetch/render/activate target.
/// The active generation's retained source manifest is never overwritten.
///
/// Returns the computed [`ManifestDiff`] so a fleet test can assert the realized
/// `/etc` equals the predicted manifest (the dry-run-as-oracle property).
///
/// # Errors
///
/// Returns an error when the evaluator fails to produce a manifest (a clean
/// no-op), when a manifest cannot be read, or when a real switch cannot publish
/// the committed manifest.
pub async fn run_switch(params: &SwitchParams) -> Result<ManifestDiff> {
    // 1. Evaluate to the candidate manifest (no activation — eval-only).
    let eval_report = super::run_eval_command_with_report(&params.eval)?;

    // 2. Diff the candidate against the base and print.
    let diff = run_switch_dry_run(
        &params.base_manifest,
        &params.base_label,
        &params.eval.out,
        &eval_report.resolution_trace,
        params.json_out,
    )?;

    if params.dry_run {
        return Ok(diff);
    }

    // 3. Publish graph first and manifest second. A crash between the two is
    // fail-closed: strict graph compilation rejects the mismatched pair. The
    // next switch replaces both before starting any transaction.
    let candidate_graph = params.eval.out.with_file_name("graph.json");
    let live_graph = params.live_manifest.with_file_name("graph.json");
    publish_file_atomic(&candidate_graph, &live_graph)?;
    publish_file_atomic(&params.eval.out, &params.live_manifest)?;

    // 4. Compile and synchronously await the systemd transaction. The compiler
    // resets stale RemainAfterExit state, starts the package wings, and waits
    // for aos-activate.service, so success here means activation committed.
    crate::graph_compile::run_graph_compile_command(&params.live_manifest, &live_graph, None)
        .await?;
    Ok(diff)
}

fn publish_file_atomic(source: &Path, destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .with_context(|| format!("{} has no parent directory", destination.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} has no UTF-8 file name", destination.display()))?;
    let temporary = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    std::fs::copy(source, &temporary).with_context(|| {
        format!(
            "copying transaction input {} to {}",
            source.display(),
            temporary.display()
        )
    })?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(&temporary)
        .with_context(|| format!("opening {} for sync", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", temporary.display()))?;
    std::fs::rename(&temporary, destination)
        .with_context(|| format!("publishing {}", destination.display()))?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .open(parent)
        .with_context(|| format!("opening {} for sync", parent.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("syncing {}", parent.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base() -> Value {
        json!({
            "schema": "aos.config-manifest/v1",
            "etc": {
                "aos/packages/web/config.env": {"kind": "text", "text": "PORT=8080\n", "mode": "0644"},
                "aos/packages/legacy/config.toml": {"kind": "text", "text": "x=1\n", "mode": "0644"},
            },
            "units": {
                "web.service": {"action": "reload"},
            },
            "storePaths": [
                "/nix/store/aaa-web-1.0",
                "/nix/store/bbb-curl-8.12",
            ],
        })
    }

    fn candidate() -> Value {
        json!({
            "schema": "aos.config-manifest/v1",
            "etc": {
                "aos/packages/web/config.env": {"kind": "text", "text": "PORT=9090\n", "mode": "0644"},
                "nftables/forward.conf": {"kind": "text", "text": "policy accept\n", "mode": "0644"},
            },
            "units": {
                "web.service": {"action": "reload"},
                "firewall.service": {"action": "restart"},
                "tracing.service": {"action": "restart"},
            },
            "storePaths": [
                "/nix/store/aaa-web-1.0",
                "/nix/store/bbb-curl-8.12",
                "/nix/store/ccc-otel-collector-0.9",
            ],
        })
    }

    #[test]
    fn etc_diff_classifies_add_remove_change() {
        let diff = diff_manifests(&base(), &candidate());
        let by_path: BTreeMap<&str, ChangeKind> =
            diff.etc.iter().map(|c| (c.path.as_str(), c.kind)).collect();
        assert_eq!(by_path["aos/packages/web/config.env"], ChangeKind::Changed);
        assert_eq!(by_path["nftables/forward.conf"], ChangeKind::Added);
        assert_eq!(
            by_path["aos/packages/legacy/config.toml"],
            ChangeKind::Removed
        );
    }

    #[test]
    fn unit_actions_mark_new_and_changed() {
        let diff = diff_manifests(&base(), &candidate());
        let by_unit: BTreeMap<&str, &UnitChange> =
            diff.units.iter().map(|u| (u.unit.as_str(), u)).collect();
        // web.service is unchanged (same action+def) -> not in the diff.
        assert!(!by_unit.contains_key("web.service"));
        // firewall and tracing are new -> "start".
        assert_eq!(by_unit["firewall.service"].kind, ChangeKind::Added);
        assert_eq!(by_unit["firewall.service"].action, "start");
        assert_eq!(by_unit["tracing.service"].kind, ChangeKind::Added);
        // A base-only unit is an observable pre-swap stop action.
        let mut without_web = candidate();
        without_web["units"]
            .as_object_mut()
            .unwrap()
            .remove("web.service");
        let removed = diff_manifests(&base(), &without_web);
        let web = removed
            .units
            .iter()
            .find(|change| change.unit == "web.service")
            .unwrap();
        assert_eq!(web.kind, ChangeKind::Removed);
        assert_eq!(web.action, "stop");
    }

    #[test]
    fn fetch_plan_is_the_closure_delta() {
        let diff = diff_manifests(&base(), &candidate());
        assert_eq!(
            diff.fetch_plan,
            vec!["/nix/store/ccc-otel-collector-0.9".to_string()]
        );
    }

    #[test]
    fn empty_diff_when_identical() {
        let m = base();
        let diff = diff_manifests(&m, &m);
        assert!(diff.is_empty());
    }

    #[test]
    fn json_envelope_has_operability_fields() {
        let diff = diff_manifests(&base(), &candidate());
        let trace = vec!["firewall.forwardPolicy = accept (web -> firewall)".to_string()];
        let v = diff.to_json(&trace);
        assert!(v.get("etc_diff").is_some());
        assert!(v.get("unit_actions").is_some());
        assert!(v.get("fetch_plan").is_some());
        assert_eq!(v["resolution_trace"][0], trace[0]);
    }

    #[test]
    fn human_render_lists_sections() {
        let diff = diff_manifests(&base(), &candidate());
        let text = diff.render_human("gen-7");
        assert!(text.contains("manifest diff (gen-7 -> candidate)"));
        assert!(text.contains("+ nftables/forward.conf"));
        assert!(text.contains("- aos/packages/legacy/config.toml"));
        assert!(text.contains("~ aos/packages/web/config.env"));
        assert!(text.contains("+ /nix/store/ccc-otel-collector-0.9"));
    }

    #[test]
    fn load_and_run_dry_run_over_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base_path = tmp.path().join("gen-7.json");
        let cand_path = tmp.path().join("candidate.json");
        std::fs::write(&base_path, serde_json::to_vec(&base()).unwrap()).unwrap();
        std::fs::write(&cand_path, serde_json::to_vec(&candidate()).unwrap()).unwrap();
        let diff = run_switch_dry_run(&base_path, "gen-7", &cand_path, &[], true).unwrap();
        assert_eq!(diff.etc.len(), 3);
        assert_eq!(diff.fetch_plan.len(), 1);
    }
}
