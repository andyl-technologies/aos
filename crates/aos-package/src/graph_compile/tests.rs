//! Unit tests for the graph compiler: dropin/`.wants` generation, the
//! `Wants=`-not-`Requires=` edge rules, cycle detection, idempotency + the
//! reconfiguration delta (driven against a tempdir + a mock systemd client), and
//! the degraded re-projection.

use std::collections::BTreeSet;
use std::sync::Mutex;

use serde_json::json;
use sha2::Digest;

use super::reproject::{DropReason, reproject_manifest};
use super::*;

// ---------------------------------------------------------------------------
// A mock SystemdControl that records calls, with optional error injection.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeSystemd {
    calls: Mutex<Vec<String>>,
    fail_reload: bool,
    activation: Option<(std::path::PathBuf, FakeActivation)>,
}

#[derive(Clone, Copy)]
enum FakeActivation {
    Complete,
    Degraded,
    Mismatched,
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

    async fn start_unit(&self, name: &str) -> Result<()> {
        self.calls.lock().unwrap().push(format!("start:{name}"));
        if name == ACTIVATE_SERVICE {
            if let Some((root, activation)) = &self.activation {
                let transaction = read_transaction(root)?.context("test graph transaction")?;
                let (transaction_manifest, dropped_packages, status, activation_exit) =
                    match activation {
                        FakeActivation::Complete => {
                            (transaction.manifest, json!([]), "complete", 0)
                        }
                        FakeActivation::Degraded => {
                            (transaction.manifest, json!(["firewall"]), "degraded", 6)
                        }
                        FakeActivation::Mismatched => (
                            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                                .to_string(),
                            json!([]),
                            "complete",
                            0,
                        ),
                    };
                let proof = json!({
                    "schema": "aos.config-activation/v1",
                    "generation": 1,
                    "generation_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "transaction_manifest": transaction_manifest,
                    "dropped_packages": dropped_packages,
                    "status": status,
                    "activation_exit": activation_exit,
                });
                std::fs::write(root.join(ACTIVATION_RECORD), serde_json::to_vec(&proof)?)?;
            }
        }
        Ok(())
    }

    async fn stop_unit(&self, name: &str) -> Result<()> {
        self.calls.lock().unwrap().push(format!("stop:{name}"));
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
    fn activating(root: &std::path::Path, activation: FakeActivation) -> Self {
        Self {
            activation: Some((root.to_path_buf(), activation)),
            ..Self::default()
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

fn pkgset(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn strict_manifest(names: &[&str], graph: &ConfigGraph) -> ConfigManifest {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/config_manifest/manifest.json"
    ))
    .unwrap();
    for field in ["etc", "units", "jobScripts", "config", "credentials"] {
        value[field] = json!({});
    }
    for field in ["users", "presets", "storePaths"] {
        value[field] = json!([]);
    }
    let mut packages = names.to_vec();
    packages.sort_unstable();
    let mut outputs = serde_json::Map::new();
    let mut store_paths = Vec::new();
    let mut store_owners = serde_json::Map::new();
    for (index, package) in packages.iter().enumerate() {
        let digit = char::from_digit((index as u32 % 10) + 1, 10).unwrap();
        let hash: String = std::iter::repeat_n(digit, 32).collect();
        let store_path = format!("/nix/store/{hash}-{package}");
        outputs.insert(
            (*package).to_string(),
            json!({
                "version": "1",
                "platform": "test",
                "registry": "test",
                "store_path": store_path,
                "closure": [{
                    "store_path_hash": hash,
                    "store_path": store_path,
                    "realisations": [{"nar_hash": "sha256:test", "nar_size": 1}]
                }]
            }),
        );
        store_paths.push(store_path.clone());
        store_owners.insert(store_path, json!(package));
    }
    store_paths.sort();
    value["storePaths"] = json!(store_paths);
    value["packages"] = json!(packages);
    value["packageOutputs"] = serde_json::Value::Object(outputs);
    value["graph"] = serde_json::to_value(graph).unwrap();
    value["ownership"] = json!({
        "etc": {}, "units": {}, "jobScripts": {}, "users": {},
        "presets": {}, "storePaths": store_owners
    });
    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    manifest.validate().unwrap();
    manifest
}

// ---------------------------------------------------------------------------
// Planning + dropin format
// ---------------------------------------------------------------------------

#[test]
fn plan_reads_packages_and_edges() {
    let graph = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let manifest = strict_manifest(&["firewall", "nginx"], &graph);
    let plan = plan(&manifest, &graph).unwrap();
    assert_eq!(plan.packages(), &pkgset(&["firewall", "nginx"]));
    assert_eq!(plan.dependencies("nginx"), pkgset(&["firewall"]));
    assert!(plan.dependencies("firewall").is_empty());
}

#[test]
fn plan_accepts_an_empty_strict_manifest() {
    let graph = ConfigGraph::default();
    let manifest = strict_manifest(&[], &graph);
    let plan = plan(&manifest, &graph).unwrap();
    assert!(plan.packages().is_empty());
}

#[test]
fn plan_rejects_edge_to_unknown_package() {
    let graph = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let manifest = strict_manifest(&["nginx"], &ConfigGraph::default());
    let err = plan(&manifest, &graph).unwrap_err().to_string();
    assert!(err.contains("disagrees"), "{err}");
}

#[test]
fn plan_rejects_invalid_package_name() {
    let graph = ConfigGraph::default();
    let mut manifest = strict_manifest(&[], &graph);
    manifest.packages = vec!["bad/name".to_string()];
    assert!(plan(&manifest, &graph).is_err());
}

#[test]
fn plan_detects_cycle() {
    let graph = ConfigGraph::from_json(r#"{"edges":{"a":["b"],"b":["a"]}}"#).unwrap();
    let manifest = strict_manifest(&["a", "b"], &graph);
    let err = plan(&manifest, &graph).unwrap_err().to_string();
    assert!(err.contains("ordering cycle"), "{err}");
}

#[tokio::test]
async fn command_rejects_unknown_manifest_fields_before_systemd() {
    let dir = tempfile::tempdir().unwrap();
    let graph = ConfigGraph::default();
    let manifest = strict_manifest(&[], &graph);
    let mut value = serde_json::to_value(manifest).unwrap();
    value["unexpected"] = json!(true);
    let manifest_path = dir.path().join("manifest.json");
    let graph_path = dir.path().join("graph.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&value).unwrap()).unwrap();
    std::fs::write(&graph_path, br#"{"edges":{}}"#).unwrap();
    let error = run_graph_compile_command(&manifest_path, &graph_path, Some(dir.path()))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("parsing manifest"), "{error:#}");
}

#[tokio::test]
async fn command_requires_the_companion_graph_before_systemd() {
    let dir = tempfile::tempdir().unwrap();
    let graph = ConfigGraph::default();
    let manifest = strict_manifest(&[], &graph);
    let manifest_path = dir.path().join("manifest.json");
    let graph_path = dir.path().join("missing-graph.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let error = run_graph_compile_command(&manifest_path, &graph_path, Some(dir.path()))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("reading graph"), "{error:#}");
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
    let graph = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let manifest = strict_manifest(&["firewall", "nginx"], &graph);
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
    let fetch_barrier =
        std::fs::read_to_string(dir.path().join("aos-fetch.target.d/10-instances.conf")).unwrap();
    assert!(
        fetch_barrier.contains("After=aos-pkg-fetch@firewall.service aos-pkg-fetch@nginx.service")
    );
    let render_barrier = std::fs::read_to_string(
        dir.path()
            .join("aos-config-render.target.d/10-instances.conf"),
    )
    .unwrap();
    assert!(
        render_barrier
            .contains("After=aos-pkg-install@firewall.service aos-pkg-install@nginx.service")
    );
    // No .requires directory anywhere.
    assert!(!dir.path().join("aos-config.target.requires").exists());
}

#[test]
fn reconcile_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());
    let graph = ConfigGraph::from_json(r#"{"edges":{"nginx":["firewall"]}}"#).unwrap();
    let manifest = strict_manifest(&["firewall", "nginx"], &graph);
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
    let m1 = strict_manifest(&["firewall", "nginx"], &g1);
    let p1 = plan(&m1, &g1).unwrap();
    compiler.reconcile_filesystem(&p1).unwrap();

    // New manifest drops nginx.
    let g2 = ConfigGraph::default();
    let m2 = strict_manifest(&["firewall"], &g2);
    let p2 = plan(&m2, &g2).unwrap();
    let report = compiler.reconcile_filesystem(&p2).unwrap();
    assert_eq!(report.removed, pkgset(&["nginx"]));

    assert!(!dir.path().join("aos-pkg-install@nginx.service.d").exists());
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
    let m1 = strict_manifest(&["firewall", "nginx"], &g1);
    let fake = FakeSystemd::activating(dir.path(), FakeActivation::Complete);
    compiler.compile(&m1, &g1, &fake).await.unwrap();
    let calls = fake.calls();
    assert_eq!(
        calls.first().map(String::as_str),
        Some("stop:aos-config.target")
    );
    assert!(calls.contains(&"stop:aos-activate.service".to_string()));
    assert!(calls.contains(&"reset-failed:aos-pkg-fetch@nginx.service".to_string()));
    assert_eq!(calls[calls.len() - 3], "daemon-reload");
    assert_eq!(calls[calls.len() - 2], "start:aos-activate.service");
    assert_eq!(
        calls.last().map(String::as_str),
        Some("start:aos-config.target")
    );

    // Second compile drops nginx -> reset-failed both planes, then reload, start.
    let g2 = ConfigGraph::default();
    let m2 = strict_manifest(&["firewall"], &g2);
    let fake2 = FakeSystemd::activating(dir.path(), FakeActivation::Complete);
    compiler.compile(&m2, &g2, &fake2).await.unwrap();
    let calls = fake2.calls();
    assert!(calls.contains(&"stop:aos-pkg-fetch@nginx.service".to_string()));
    assert!(calls.contains(&"reset-failed:aos-pkg-install@nginx.service".to_string()));
    assert_eq!(
        calls.last().map(String::as_str),
        Some("start:aos-config.target")
    );
}

#[tokio::test]
async fn compile_does_not_restart_a_completed_identical_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());
    let graph = ConfigGraph::default();
    let manifest = strict_manifest(&["firewall"], &graph);
    let first = FakeSystemd::activating(dir.path(), FakeActivation::Complete);
    compiler.compile(&manifest, &graph, &first).await.unwrap();

    let second = FakeSystemd::default();
    compiler.compile(&manifest, &graph, &second).await.unwrap();
    assert!(second.calls().is_empty());
}

#[tokio::test]
async fn completed_proof_does_not_skip_reload_for_tampered_runtime_graph() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());
    let graph = ConfigGraph::default();
    let manifest = strict_manifest(&["firewall"], &graph);
    let first = FakeSystemd::activating(dir.path(), FakeActivation::Complete);
    compiler.compile(&manifest, &graph, &first).await.unwrap();

    let stale = dir
        .path()
        .join("aos-pkg-install@firewall.service.d/99-stale.conf");
    std::fs::write(&stale, b"[Unit]\nRequires=untrusted.service\n").unwrap();

    let retry = FakeSystemd::activating(dir.path(), FakeActivation::Complete);
    compiler.compile(&manifest, &graph, &retry).await.unwrap();
    assert!(retry.calls().contains(&"daemon-reload".to_string()));
    assert!(
        retry
            .calls()
            .contains(&"start:aos-config.target".to_string())
    );
    assert!(!stale.exists());
}

#[tokio::test]
async fn compile_retries_an_identical_degraded_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());
    let graph = ConfigGraph::default();
    let manifest = strict_manifest(&["firewall"], &graph);

    let degraded = FakeSystemd::activating(dir.path(), FakeActivation::Degraded);
    compiler
        .compile(&manifest, &graph, &degraded)
        .await
        .unwrap();
    assert!(!read_transaction(dir.path()).unwrap().unwrap().completed);

    let recovered = FakeSystemd::activating(dir.path(), FakeActivation::Complete);
    compiler
        .compile(&manifest, &graph, &recovered)
        .await
        .unwrap();
    assert!(
        recovered
            .calls()
            .contains(&"start:aos-config.target".to_string())
    );
    assert!(read_transaction(dir.path()).unwrap().unwrap().completed);
}

#[tokio::test]
async fn compile_rejects_a_mismatched_activation_proof() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());
    let graph = ConfigGraph::default();
    let manifest = strict_manifest(&["firewall"], &graph);
    let fake = FakeSystemd::activating(dir.path(), FakeActivation::Mismatched);

    let error = compiler
        .compile(&manifest, &graph, &fake)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not match requested"));
    assert!(!read_transaction(dir.path()).unwrap().unwrap().completed);
}

#[tokio::test]
async fn compile_retries_when_a_completed_state_lacks_matching_proof() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());
    let graph = ConfigGraph::default();
    let manifest = strict_manifest(&["firewall"], &graph);
    let first = FakeSystemd::activating(dir.path(), FakeActivation::Complete);
    compiler.compile(&manifest, &graph, &first).await.unwrap();
    std::fs::write(dir.path().join(ACTIVATION_RECORD), b"{not-json").unwrap();

    let retry = FakeSystemd::activating(dir.path(), FakeActivation::Complete);
    compiler.compile(&manifest, &graph, &retry).await.unwrap();
    assert!(
        retry
            .calls()
            .contains(&"start:aos-config.target".to_string())
    );
}

#[tokio::test]
async fn compile_propagates_reload_failure() {
    let dir = tempfile::tempdir().unwrap();
    let compiler = GraphCompiler::with_run_root(dir.path());
    let g = ConfigGraph::default();
    let m = strict_manifest(&["firewall"], &g);
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
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .to_string();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                out.push((rel, format!("symlink:{}", target.display())));
            } else if meta.is_dir() {
                stack.push(path);
            } else {
                out.push((
                    rel,
                    format!("file:{}", std::fs::read_to_string(&path).unwrap()),
                ));
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
    assert_eq!(
        record["source_manifest_hash"],
        json!(r.source_manifest_hash)
    );
    assert_eq!(record["dropped"][0]["package"], json!("frontend"));
    assert_eq!(
        record["dropped"][0]["reason"],
        json!("dependency_dropped:nginx")
    );
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
fn reproject_filters_every_package_owned_aggregate() {
    let base_store = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base";
    let web_store = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-web";
    let full = json!({
        "packages": ["firewall", "web"],
        "config": {"firewall": {}, "web": {}},
        "credentials": {"firewall": {}, "web": {}},
        "etc": {
            "base.conf": {"kind": "text", "text": "base", "mode": "0644"},
            "web.conf": {"kind": "text", "text": "web", "mode": "0644"}
        },
        "units": {
            "base.service": {"action": "restart"},
            "web.service": {"action": "restart"}
        },
        "jobScripts": {
            "base": {"text": "base", "mode": "0755"},
            "web": {"text": "web", "mode": "0755"}
        },
        "users": [
            {"name": "root"},
            {"name": "web"}
        ],
        "presets": [
            {"unit": "base.service", "source": "image"},
            {"unit": "web.service", "source": "package"}
        ],
        "storePaths": [base_store, web_store],
        "ownership": {
            "etc": {"base.conf": "@base", "web.conf": "web"},
            "units": {"base.service": "@base", "web.service": "web"},
            "jobScripts": {"base": "@base", "web": "web"},
            "users": {"root": "@base", "web": "web"},
            "presets": {"base.service:image": "@base", "web.service:package": "web"},
            "storePaths": {(base_store): "@base", (web_store): "web"}
        }
    });
    let graph = ConfigGraph::default();
    let r = reproject_manifest(
        &full,
        &graph,
        &pkgset(&["firewall"]),
        &pkgset(&["firewall"]),
    )
    .unwrap();

    assert_eq!(r.manifest["packages"], json!(["firewall"]));
    assert!(r.manifest["etc"].get("base.conf").is_some());
    assert!(r.manifest["etc"].get("web.conf").is_none());
    assert!(r.manifest["units"].get("web.service").is_none());
    assert!(r.manifest["jobScripts"].get("web").is_none());
    assert_eq!(r.manifest["users"], json!([{"name": "root"}]));
    assert_eq!(
        r.manifest["presets"],
        json!([{"unit": "base.service", "source": "image"}])
    );
    assert_eq!(r.manifest["storePaths"], json!([base_store]));
    assert!(r.manifest["ownership"]["etc"].get("web.conf").is_none());
}

#[test]
fn degraded_projection_rejects_unowned_aggregate_artifacts() {
    let full = json!({
        "packages": ["firewall", "web"],
        "etc": {"web.conf": {"kind": "text", "text": "web", "mode": "0644"}},
        "ownership": {
            "etc": {}, "units": {}, "jobScripts": {}, "users": {},
            "presets": {}, "storePaths": {}
        }
    });
    let error = reproject_manifest(
        &full,
        &ConfigGraph::default(),
        &pkgset(&["firewall"]),
        &pkgset(&["firewall"]),
    )
    .unwrap_err();
    assert!(error.to_string().contains("ownership.etc"));
}

#[test]
fn degraded_projection_rejects_unowned_etc_removals() {
    let full = json!({
        "packages": ["firewall", "web"],
        "removedEtc": ["systemd/system/nftables.service"],
    });
    let error = reproject_manifest(
        &full,
        &ConfigGraph::default(),
        &pkgset(&["web"]),
        &pkgset(&["web"]),
    )
    .unwrap_err();

    assert!(error.to_string().contains("removedEtc"));
}

#[test]
fn staged_render_bytes_and_credential_handles_enter_generation_manifest() {
    let graph = ConfigGraph::default();
    let mut manifest = strict_manifest(&["web"], &graph);
    manifest
        .package_outputs
        .get_mut("web")
        .unwrap()
        .legacy_config = Some(crate::types::ExposeConfigMeta {
        artifacts: Vec::new(),
        credentials: vec![crate::types::CredentialMeta {
            name: "join-token".into(),
            source: Some("/etc/credstore.encrypted/web/join-token".into()),
            ciphertext: None,
            units: vec!["web.service".into()],
            encrypted: true,
        }],
    });
    manifest.credentials.insert(
        "web".into(),
        json!({
            "join-token": {
                "name": "join-token",
                "source": "/etc/credstore.encrypted/web/join-token",
                "encrypted": true,
                "units": ["web.service"],
                "ref": "tpm2-credstore"
            }
        }),
    );
    let source = serde_json::to_value(&manifest).unwrap();
    let all = pkgset(&["web"]);
    let mut projection = reproject_manifest(&source, &graph, &all, &all).unwrap();
    let staging = tempfile::tempdir().unwrap();
    let directory = super::subverbs::staging_package_dir(staging.path(), &manifest, "web").unwrap();
    let bytes = b"PORT=8080\n";
    let sha256 = format!("sha256:{:x}", sha2::Sha256::digest(bytes));
    let payload = format!("payload/{}", sha256.trim_start_matches("sha256:"));
    crate::config_eval::materialize::write_bytes_beneath(&directory, &payload, bytes, "0644")
        .unwrap();
    let transaction = graph_transaction(&manifest).unwrap();
    let index = json!({
        "schema": "aos.render-stage/v1",
        "manifest": transaction.manifest,
        "package_pin": transaction.packages["web"],
        "package": "web",
        "artifacts": [{
            "path": "aos/packages/web/config.env",
            "payload": payload,
            "mode": "0644",
            "sha256": sha256
        }],
        "credentials": manifest.credentials["web"],
        "units": {}
    });
    crate::config_eval::materialize::write_bytes_beneath(
        &directory,
        "stage.json",
        &serde_json::to_vec(&index).unwrap(),
        "0600",
    )
    .unwrap();

    let before = projection.generation_id.clone();
    super::reproject::merge_staged_projection(&manifest, staging.path(), &mut projection).unwrap();

    assert_eq!(
        projection.manifest["etc"]["aos/packages/web/config.env"]["text"],
        json!("PORT=8080\n")
    );
    assert_eq!(
        projection.manifest["ownership"]["etc"]["aos/packages/web/config.env"],
        json!("web")
    );
    assert_eq!(
        projection.manifest["credentials"]["web"],
        manifest.credentials["web"]
    );
    assert_ne!(projection.generation_id, before);

    let parsed: ConfigManifest = serde_json::from_value(projection.manifest.clone()).unwrap();
    let etc = tempfile::tempdir().unwrap();
    crate::config_eval::materialize::apply(
        &parsed,
        etc.path(),
        crate::config_eval::materialize::DEFAULT_JOB_SCRIPTS_RUNTIME_DIR,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(etc.path().join("aos/packages/web/config.env")).unwrap(),
        bytes
    );
}

#[test]
fn package_without_config_accepts_canonical_empty_credential_stage() {
    let graph = ConfigGraph::default();
    let manifest = strict_manifest(&["acl"], &graph);
    let source = serde_json::to_value(&manifest).unwrap();
    let all = pkgset(&["acl"]);
    let mut projection = reproject_manifest(&source, &graph, &all, &all).unwrap();
    let staging = tempfile::tempdir().unwrap();
    let directory = super::subverbs::staging_package_dir(staging.path(), &manifest, "acl").unwrap();
    let transaction = graph_transaction(&manifest).unwrap();
    let index = json!({
        "schema": "aos.render-stage/v1",
        "manifest": transaction.manifest,
        "package_pin": transaction.packages["acl"],
        "package": "acl",
        "artifacts": [],
        "credentials": {},
        "units": {}
    });
    crate::config_eval::materialize::write_bytes_beneath(
        &directory,
        "stage.json",
        &serde_json::to_vec(&index).unwrap(),
        "0600",
    )
    .unwrap();

    super::reproject::merge_staged_projection(&manifest, staging.path(), &mut projection).unwrap();

    assert_eq!(projection.manifest["credentials"], json!({"acl": {}}));
}

#[test]
fn canonical_hash_is_key_order_independent() {
    use super::reproject::hash_cjson;
    let a = json!({"b": 1, "a": 2});
    let b = json!({"a": 2, "b": 1});
    assert_eq!(hash_cjson(&a), hash_cjson(&b));
}
