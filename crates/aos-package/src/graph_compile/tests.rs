//! Unit tests for the graph compiler: dropin/`.wants` generation, the
//! `Wants=`-not-`Requires=` edge rules, cycle detection, idempotency + the
//! reconfiguration delta (driven against a tempdir + a mock systemd client), and
//! the degraded re-projection.

use std::collections::BTreeSet;
use std::sync::Mutex;

use serde_json::json;

use super::reproject::{DropReason, reproject_manifest};
use super::*;

// ---------------------------------------------------------------------------
// A mock SystemdControl that records calls, with optional error injection.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeSystemd {
    calls: Mutex<Vec<String>>,
    fail_reload: bool,
}

#[async_trait::async_trait]
impl SystemdControl for FakeSystemd {
    async fn daemon_reload(&self) -> Result<()> {
        self.calls.lock().unwrap().push("daemon-reload".to_string());
        if self.fail_reload {
            anyhow::bail!("injected reload failure");
        }
        Ok(())
    }

    async fn start_unit_no_wait(&self, name: &str) -> Result<()> {
        self.calls.lock().unwrap().push(format!("start:{name}"));
        Ok(())
    }

    async fn reset_failed_unit(&self, name: &str) -> Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("reset-failed:{name}"));
        Ok(())
    }
}

impl FakeSystemd {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

fn pkgset(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Planning + dropin format
// ---------------------------------------------------------------------------

#[test]
fn plan_reads_packages_and_edges() {
    let manifest = json!({"packages": ["nginx", "firewall"]});
    let graph = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let plan = plan(&manifest, &graph).unwrap();
    assert_eq!(plan.packages(), &pkgset(&["firewall", "nginx"]));
    assert_eq!(plan.dependencies("nginx"), pkgset(&["firewall"]));
    assert!(plan.dependencies("firewall").is_empty());
}

#[test]
fn plan_falls_back_to_graph_nodes_when_no_packages_field() {
    let manifest = json!({});
    let graph = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let plan = plan(&manifest, &graph).unwrap();
    assert_eq!(plan.packages(), &pkgset(&["firewall", "nginx"]));
}

#[test]
fn plan_rejects_edge_to_unknown_package() {
    let manifest = json!({"packages": ["nginx"]});
    let graph = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let err = plan(&manifest, &graph).unwrap_err().to_string();
    assert!(err.contains("not in the manifest set"), "{err}");
}

#[test]
fn plan_rejects_invalid_package_name() {
    let manifest = json!({"packages": ["bad/name"]});
    let graph = ConfigGraph::default();
    assert!(plan(&manifest, &graph).is_err());
}

#[test]
fn plan_detects_cycle() {
    let manifest = json!({"packages": ["a", "b"]});
    let graph = ConfigGraph::from_json(r#"{"edges":{"a":["b"],"b":["a"]}}"#).unwrap();
    let err = plan(&manifest, &graph).unwrap_err().to_string();
    assert!(err.contains("ordering cycle"), "{err}");
}

#[test]
fn dropin_with_deps_emits_after_and_wants_no_requires() {
    let body = dropin_contents("nginx", &pkgset(&["firewall"]));
    assert!(body.contains("[Unit]\n"));
    assert!(body.contains("After=aos-pkg-fetch@nginx.service\n"));
    assert!(body.contains("After=aos-pkg-install@firewall.service\n"));
    assert!(body.contains("Wants=aos-pkg-install@firewall.service\n"));
    // The lever: never a hard dependency edge.
    assert!(!body.contains("Requires="));
    assert!(!body.contains("BindsTo="));
    assert!(!body.contains("Requisite="));
}

#[test]
fn dropin_without_deps_has_only_self_edge() {
    let body = dropin_contents("firewall", &BTreeSet::new());
    assert!(body.contains("After=aos-pkg-fetch@firewall.service\n"));
    assert_eq!(body.matches("After=").count(), 1);
    assert!(!body.contains("Wants="));
}

#[test]
fn dropin_deps_are_lexicographic() {
    let body = dropin_contents("web", &pkgset(&["zlib", "acl", "firewall"]));
    let line = body
        .lines()
        .find(|l| l.starts_with("After=aos-pkg-install@"))
        .unwrap();
    assert_eq!(
        line,
        "After=aos-pkg-install@acl.service aos-pkg-install@firewall.service aos-pkg-install@zlib.service"
    );
}

// ---------------------------------------------------------------------------
// Filesystem reconcile + idempotency + delta
// ---------------------------------------------------------------------------

#[test]
fn reconcile_writes_dropins_and_wants_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());
    let manifest = json!({"packages": ["nginx", "firewall"]});
    let graph = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let plan = plan(&manifest, &graph).unwrap();

    let report = compiler.reconcile_filesystem(&plan).unwrap();
    assert_eq!(report.written, pkgset(&["firewall", "nginx"]));
    assert!(report.removed.is_empty());

    let dropin = dir
        .path()
        .join("aos-pkg-install@nginx.service.d/10-edges.conf");
    let body = std::fs::read_to_string(&dropin).unwrap();
    assert!(body.contains("After=aos-pkg-install@firewall.service"));

    // .wants symlinks point at the templates (relative).
    let fetch_link = dir
        .path()
        .join("aos-fetch.target.wants/aos-pkg-fetch@nginx.service");
    assert_eq!(
        std::fs::read_link(&fetch_link).unwrap(),
        std::path::PathBuf::from("../aos-pkg-fetch@.service")
    );
    let install_link = dir
        .path()
        .join("aos-config-render.target.wants/aos-pkg-install@firewall.service");
    assert_eq!(
        std::fs::read_link(&install_link).unwrap(),
        std::path::PathBuf::from("../aos-pkg-install@.service")
    );
    // No .requires directory anywhere.
    assert!(!dir.path().join("aos-config.target.requires").exists());
}

#[test]
fn reconcile_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());
    let manifest = json!({"packages": ["nginx", "firewall"]});
    let graph = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let plan = plan(&manifest, &graph).unwrap();

    compiler.reconcile_filesystem(&plan).unwrap();
    let snapshot = read_tree(dir.path());
    compiler.reconcile_filesystem(&plan).unwrap();
    assert_eq!(snapshot, read_tree(dir.path()), "second compile diverged");
}

#[test]
fn reconcile_delta_removes_dropped_package() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());

    let g1 = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let p1 = plan(&json!({"packages": ["nginx", "firewall"]}), &g1).unwrap();
    compiler.reconcile_filesystem(&p1).unwrap();

    // New manifest drops nginx.
    let g2 = ConfigGraph::default();
    let p2 = plan(&json!({"packages": ["firewall"]}), &g2).unwrap();
    let report = compiler.reconcile_filesystem(&p2).unwrap();
    assert_eq!(report.removed, pkgset(&["nginx"]));

    assert!(
        !dir.path()
            .join("aos-pkg-install@nginx.service.d")
            .exists()
    );
    assert!(
        !dir.path()
            .join("aos-fetch.target.wants/aos-pkg-fetch@nginx.service")
            .exists()
    );
    // firewall survives.
    assert!(
        dir.path()
            .join("aos-pkg-install@firewall.service.d/10-edges.conf")
            .exists()
    );
}

#[tokio::test]
async fn compile_drives_reset_reload_start_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());

    // First compile with nginx + firewall.
    let g1 = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let m1 = json!({"packages": ["nginx", "firewall"]});
    let fake = FakeSystemd::default();
    compiler.compile(&m1, &g1, &fake).await.unwrap();
    let calls = fake.calls();
    // No removals on first compile: just one reload then the target start.
    assert_eq!(calls, vec!["daemon-reload", "start:aos-config.target"]);

    // Second compile drops nginx -> reset-failed both planes, then reload, start.
    let g2 = ConfigGraph::default();
    let m2 = json!({"packages": ["firewall"]});
    let fake2 = FakeSystemd::default();
    compiler.compile(&m2, &g2, &fake2).await.unwrap();
    let calls = fake2.calls();
    assert_eq!(
        calls,
        vec![
            "reset-failed:aos-pkg-fetch@nginx.service",
            "reset-failed:aos-pkg-install@nginx.service",
            "daemon-reload",
            "start:aos-config.target",
        ]
    );
}

#[tokio::test]
async fn compile_propagates_reload_failure() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());
    let g = ConfigGraph::default();
    let m = json!({"packages": ["firewall"]});
    let fake = FakeSystemd {
        fail_reload: true,
        ..Default::default()
    };
    let err = compiler.compile(&m, &g, &fake).await.unwrap_err();
    assert!(err.to_string().contains("injected reload failure"));
    // Files are still on disk; the start was never issued.
    assert!(!fake.calls().iter().any(|c| c.starts_with("start:")));
}

/// Snapshot a directory tree as a sorted list of `(relpath, kind, content)` for
/// idempotency comparison.
fn read_tree(root: &std::path::Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().to_string();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                out.push((rel, format!("symlink:{}", target.display())));
            } else if meta.is_dir() {
                stack.push(path);
            } else {
                out.push((rel, format!("file:{}", std::fs::read_to_string(&path).unwrap())));
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Degraded re-projection (build-spec §5)
// ---------------------------------------------------------------------------

#[test]
fn reproject_identity_when_nothing_drops() {
    let full = json!({
        "packages": ["nginx", "firewall"],
        "config": {"nginx": {"a": 1}, "firewall": {"b": 2}},
    });
    let graph = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let all = pkgset(&["nginx", "firewall"]);
    let r = reproject_manifest(&full, &graph, &all, &all).unwrap();
    assert!(!r.projected);
    assert!(r.dropped.is_empty());
    // The identity property: gen id == hash of the full manifest.
    assert_eq!(r.generation_id, r.source_manifest_hash);
}

#[test]
fn reproject_drops_failed_fetch_and_cascades_dependents() {
    let full = json!({
        "packages": ["nginx", "firewall", "frontend"],
        "config": {"nginx": {}, "firewall": {}, "frontend": {}},
    });
    // frontend -> nginx -> firewall.
    let graph =
        ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"],"frontend":["nginx"]}}"#).unwrap();
    // firewall fetched+rendered; nginx fetch failed; frontend fetched+rendered.
    let fetched = pkgset(&["firewall", "frontend"]);
    let rendered = pkgset(&["firewall", "frontend"]);
    let r = reproject_manifest(&full, &graph, &fetched, &rendered).unwrap();

    assert!(r.projected);
    assert_eq!(r.kept, pkgset(&["firewall"]));

    // nginx dropped fetch_failed; frontend cascade-dropped (depends on nginx).
    let by_pkg: std::collections::BTreeMap<_, _> = r
        .dropped
        .iter()
        .map(|d| (d.package.clone(), d.reason.clone()))
        .collect();
    assert_eq!(by_pkg["nginx"], DropReason::FetchFailed);
    assert_eq!(
        by_pkg["frontend"],
        DropReason::DependencyDropped("nginx".to_string())
    );

    // The committed manifest keeps only firewall + a new, distinct gen id.
    assert_ne!(r.generation_id, r.source_manifest_hash);
    let kept_pkgs = super::reproject::manifest_packages(&r.manifest);
    assert_eq!(kept_pkgs, pkgset(&["firewall"]));

    // Drop record shape. `dropped` is sorted by package: frontend (cascade)
    // then nginx (direct fetch failure).
    let record = r.drop_record();
    assert_eq!(record["projected"], json!(true));
    assert_eq!(record["source_manifest_hash"], json!(r.source_manifest_hash));
    assert_eq!(record["dropped"][0]["package"], json!("frontend"));
    assert_eq!(record["dropped"][0]["reason"], json!("dependency_dropped:nginx"));
    assert_eq!(record["dropped"][1]["package"], json!("nginx"));
    assert_eq!(record["dropped"][1]["reason"], json!("fetch_failed"));
}

#[test]
fn reproject_render_failed_is_distinct_from_fetch_failed() {
    let full = json!({"packages": ["redis"], "config": {"redis": {}}});
    let graph = ConfigGraph::default();
    // fetched but render failed.
    let r = reproject_manifest(&full, &graph, &pkgset(&["redis"]), &BTreeSet::new()).unwrap();
    assert_eq!(r.dropped.len(), 1);
    assert_eq!(r.dropped[0].reason, DropReason::RenderFailed);
}

#[test]
fn canonical_hash_is_key_order_independent() {
    use super::reproject::hash_cjson;
    let a = json!({"b": 1, "a": 2});
    let b = json!({"a": 2, "b": 1});
    assert_eq!(hash_cjson(&a), hash_cjson(&b));
}
