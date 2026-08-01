//! Table-driven tests for the resolve↔eval fixpoint driver.
//!
//! The stock-Nix subprocess is replaced by a scripted [`ScriptedEvaluator`]
//! that returns a pre-canned sequence of [`EvalClass`] values, the registry by
//! a [`MockResolver`] mapping package names to config modules, and the fetch by
//! a [`RecordingFetcher`]. This exercises the orchestration — the locally-derived
//! [`SystemRoots`] shared-root map, the by-name structural fallback for private
//! roots, the ABI gate, the config-output-first fetch order, the cycle/cap
//! guard, and the per-system integrity checks — without a real evaluator.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;

use anyhow::{Result, bail};

use super::*;
use crate::types::{
    ConfigModuleMeta, ConfigOutputMeta, ModuleAbiCompat, OwnedRoot, RootContribution,
};

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

/// A [`NixEvaluator`] that replays a fixed sequence of outcomes.
struct ScriptedEvaluator {
    script: RefCell<VecDeque<EvalClass>>,
    /// Working-set size observed on each call, for growth assertions.
    seen_sizes: RefCell<Vec<usize>>,
}

impl ScriptedEvaluator {
    fn new(script: Vec<EvalClass>) -> Self {
        Self {
            script: RefCell::new(script.into()),
            seen_sizes: RefCell::new(Vec::new()),
        }
    }
}

impl NixEvaluator for ScriptedEvaluator {
    fn evaluate(&self, attempt: &EvalAttempt<'_>) -> Result<EvalClass> {
        self.seen_sizes.borrow_mut().push(attempt.working_set.len());
        match self.script.borrow_mut().pop_front() {
            Some(class) => Ok(class),
            None => bail!("scripted evaluator exhausted"),
        }
    }
}

/// A [`ConfigOutputFetcher`] that records fetches and can be set to fail.
struct RecordingFetcher {
    fetched: RefCell<Vec<String>>,
    fail: bool,
}

impl RecordingFetcher {
    fn new() -> Self {
        Self {
            fetched: RefCell::new(Vec::new()),
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            fetched: RefCell::new(Vec::new()),
            fail: true,
        }
    }
}

impl ConfigOutputFetcher for RecordingFetcher {
    fn fetch_config_output(&self, provider: &SelectedProvider<'_>) -> Result<()> {
        if self.fail {
            bail!("registry unreachable");
        }
        self.fetched.borrow_mut().push(provider.package.to_string());
        Ok(())
    }
}

/// A [`ConfigModuleResolver`] over an in-memory `name -> config module` map,
/// standing in for the on-host registry by-name lookup.
struct MockResolver {
    modules: BTreeMap<String, (String, String, ConfigModuleMeta)>,
}

impl MockResolver {
    fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }

    /// Registers `name`'s config module at version `1.0.0`, platform
    /// `x86_64-linux`.
    fn with(mut self, name: &str, module: ConfigModuleMeta) -> Self {
        self.modules.insert(
            name.to_string(),
            ("1.0.0".to_string(), "x86_64-linux".to_string(), module),
        );
        self
    }
}

impl ConfigModuleResolver for MockResolver {
    fn config_module(&self, package: &str) -> Option<ResolvedConfigModule<'_>> {
        let (key, (version, platform, module)) = self.modules.get_key_value(package)?;
        Some(ResolvedConfigModule {
            package: key.as_str(),
            version,
            platform,
            module,
        })
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn compat(min: u32, max: u32) -> ModuleAbiCompat {
    ModuleAbiCompat { min, max }
}

/// A config module owning `root` (with the given contributable sub-paths) — the
/// shared-root owner shape. Pass an empty `root` for a private-root module (a
/// package whose config module owns no shared root; its root is its own name).
fn owner_module(root: &str, contributable: &[&str], abi: ModuleAbiCompat) -> ConfigModuleMeta {
    let owns_roots = if root.is_empty() {
        vec![]
    } else {
        vec![OwnedRoot {
            root: root.to_string(),
            interface_abi: 1,
            contributable: contributable.iter().map(|s| s.to_string()).collect(),
        }]
    };
    ConfigModuleMeta {
        config_output: ConfigOutputMeta {
            store_path: "/nix/store/hash-config".to_string(),
            nar_hash: "sha256:x".to_string(),
            nar_size: 1,
            references: vec![],
        },
        module_abi_compat: abi,
        declares: vec![],
        owns_roots,
        contributes: vec![],
        provides_capabilities: vec![],
    }
}

/// A private-root config module (owns no shared root, ABI band `[min,max]`).
fn private_module(abi: ModuleAbiCompat) -> ConfigModuleMeta {
    owner_module("", &[], abi)
}

fn write_miss(path: &str) -> MissingOption {
    MissingOption {
        path: path.to_string(),
        kind: MissingOptionKind::UndeclaredWrite,
        read_by: Some("/nix/store/h-web/config.nix".to_string()),
    }
}

fn read_miss(root: &str) -> MissingOption {
    MissingOption {
        path: root.to_string(),
        kind: MissingOptionKind::AbsentRootRead,
        read_by: Some("/nix/store/h-web/config.nix:42".to_string()),
    }
}

/// A seed member whose config module is already loaded (`config_output`
/// present) — i.e. it counts toward the no-progress guard.
fn loaded(package: &str) -> WorkingSetMember {
    WorkingSetMember {
        package: package.to_string(),
        version: Some("1".to_string()),
        config_output: Some(format!("/nix/store/h-{package}-config")),
        module_abi_compat: Some(compat(1, 2)),
    }
}

fn inputs(seed: Vec<WorkingSetMember>, abi: u32, cap: Option<u32>) -> FixpointInputs {
    FixpointInputs {
        host_nix: PathBuf::from("/run/aos-eval/host.nix"),
        base_lib: PathBuf::from("/nix/store/hash-aos-base-lib"),
        seed_set: seed,
        module_abi: abi,
        iter_cap: cap,
    }
}

// ---------------------------------------------------------------------------
// Convergence: 0 / 1 / N rounds
// ---------------------------------------------------------------------------

#[test]
fn converges_with_zero_missing_rounds() {
    let resolver = MockResolver::new();
    let eval = ScriptedEvaluator::new(vec![EvalClass::Manifest("{\"m\":1}".into())]);
    let fetcher = RecordingFetcher::new();

    let outcome = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &resolver,
        &eval,
        &fetcher,
    )
    .expect("converges");

    assert_eq!(outcome.manifest, "{\"m\":1}");
    assert_eq!(outcome.iterations, 0);
    assert_eq!(outcome.working_set.len(), 1);
    assert!(outcome.trace.is_empty());
    assert!(fetcher.fetched.borrow().is_empty());
}

#[test]
fn converges_after_one_undeclared_write_round() {
    // Case A resolution via the by-name structural fallback: `firewall.zone`'s
    // root `firewall` is not owned by any seeded package, so it resolves to the
    // package literally named `firewall`.
    let resolver = MockResolver::new().with("firewall", private_module(compat(1, 2)));
    let eval = ScriptedEvaluator::new(vec![
        EvalClass::Missing(vec![write_miss("firewall.zone")]),
        EvalClass::Manifest("{\"m\":1}".into()),
    ]);
    let fetcher = RecordingFetcher::new();

    let outcome = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &resolver,
        &eval,
        &fetcher,
    )
    .expect("converges");

    assert_eq!(outcome.iterations, 1);
    let names: Vec<&str> = outcome
        .working_set
        .iter()
        .map(|m| m.package.as_str())
        .collect();
    assert_eq!(names, vec!["web", "firewall"]);
    assert_eq!(*fetcher.fetched.borrow(), vec!["firewall".to_string()]);
    assert_eq!(outcome.trace.len(), 1);
    assert_eq!(outcome.trace[0].provider_added, "firewall");
    assert_eq!(outcome.trace[0].kind, MissingOptionKind::UndeclaredWrite);
    // Working set grew between the two evals.
    assert_eq!(*eval.seen_sizes.borrow(), vec![1, 2]);
}

#[test]
fn converges_after_n_rounds_mixing_write_and_root_read() {
    let resolver = MockResolver::new()
        .with("firewall", private_module(compat(1, 2)))
        // tls resolves via a Case-B absent-root read.
        .with("tls", private_module(compat(1, 2)));
    let eval = ScriptedEvaluator::new(vec![
        EvalClass::Missing(vec![write_miss("firewall.zone")]),
        EvalClass::Missing(vec![read_miss("tls")]),
        EvalClass::Manifest("{\"m\":1}".into()),
    ]);
    let fetcher = RecordingFetcher::new();

    let outcome = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &resolver,
        &eval,
        &fetcher,
    )
    .expect("converges");

    assert_eq!(outcome.iterations, 2);
    let names: Vec<&str> = outcome
        .working_set
        .iter()
        .map(|m| m.package.as_str())
        .collect();
    assert_eq!(names, vec!["web", "firewall", "tls"]);
    assert_eq!(outcome.trace.len(), 2);
    assert_eq!(outcome.trace[1].kind, MissingOptionKind::AbsentRootRead);
    assert_eq!(outcome.trace[1].provider_added, "tls");
}

#[test]
fn shared_root_owner_resolves_via_system_roots() {
    // A seeded package `fw-pkg` owns the shared root `firewall`; a Case-B read of
    // that root resolves to it through SystemRoots (not the structural
    // fallback), and its bare seed's config output is fetched.
    let resolver = MockResolver::new().with(
        "fw-pkg",
        owner_module("firewall", &["allowedTCPPorts"], compat(1, 2)),
    );
    let eval = ScriptedEvaluator::new(vec![
        EvalClass::Missing(vec![read_miss("firewall")]),
        EvalClass::Manifest("{\"m\":1}".into()),
    ]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![
        WorkingSetMember::seed("web"),
        WorkingSetMember::seed("fw-pkg"),
    ];

    let outcome = run_fixpoint(&inputs(seed, 1, None), &resolver, &eval, &fetcher)
        .expect("converges via SystemRoots owner");
    assert_eq!(outcome.iterations, 1);
    assert_eq!(outcome.trace[0].provider_added, "fw-pkg");
    assert_eq!(*fetcher.fetched.borrow(), vec!["fw-pkg".to_string()]);
}

// ---------------------------------------------------------------------------
// Terminal: provider resolution
// ---------------------------------------------------------------------------

#[test]
fn no_provider_for_unknown_path() {
    let resolver = MockResolver::new();
    let eval = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![write_miss("unknown.opt")])]);
    let fetcher = RecordingFetcher::new();

    let err = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &resolver,
        &eval,
        &fetcher,
    )
    .expect_err("no provider");
    assert!(matches!(err, FixpointError::NoProvider { .. }), "{err:?}");
    // The exact message names the root twice (owner + registry lookup).
    let msg = err.to_string();
    assert!(
        msg.contains("no installed package owns root 'unknown' and no package named 'unknown' exists in the registry"),
        "{msg}"
    );
}

#[test]
fn abi_mismatch_when_named_package_excludes_image_abi() {
    // The package named `firewall` exists but only admits abi 2..4; running
    // image is abi 1 ⇒ AbiMismatch, distinct from NoProvider.
    let resolver = MockResolver::new().with("firewall", private_module(compat(2, 4)));
    let eval = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![write_miss("firewall.zone")])]);
    let fetcher = RecordingFetcher::new();

    let err = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &resolver,
        &eval,
        &fetcher,
    )
    .expect_err("abi mismatch");
    assert!(
        matches!(err, FixpointError::AbiMismatch { want: 1, .. }),
        "{err:?}"
    );
    // The fetch must never run for an ABI-incompatible provider.
    assert!(fetcher.fetched.borrow().is_empty());
}

#[test]
fn abi_mismatch_when_owned_root_excludes_image_abi() {
    // The SystemRoots owner path also distinguishes AbiMismatch from NoProvider.
    let resolver = MockResolver::new().with("fw-pkg", owner_module("firewall", &[], compat(2, 4)));
    let eval = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![read_miss("firewall")])]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![
        WorkingSetMember::seed("web"),
        WorkingSetMember::seed("fw-pkg"),
    ];

    let err = run_fixpoint(&inputs(seed, 1, None), &resolver, &eval, &fetcher)
        .expect_err("owned-root abi mismatch");
    assert!(
        matches!(err, FixpointError::AbiMismatch { want: 1, .. }),
        "{err:?}"
    );
}

#[test]
fn seed_abi_gate_rejects_before_any_eval() {
    let resolver = MockResolver::new();
    // An empty script: if the gate did not fire first, evaluate() would be
    // called and bail "exhausted", a different error.
    let eval = ScriptedEvaluator::new(vec![]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![WorkingSetMember {
        package: "firewall".into(),
        version: Some("9.9.9".into()),
        config_output: Some("/nix/store/h-firewall-config".into()),
        module_abi_compat: Some(compat(2, 4)),
    }];

    let err = run_fixpoint(&inputs(seed, 1, None), &resolver, &eval, &fetcher)
        .expect_err("seed gate rejects");
    assert!(matches!(err, FixpointError::SeedAbiMismatch(_)), "{err:?}");
    // The evaluator was never driven.
    assert!(eval.seen_sizes.borrow().is_empty());
}

#[test]
fn unsatisfiable_when_loaded_provider_still_missing() {
    // firewall's config module is ALREADY loaded (config_output present), yet a
    // read of the firewall root is still missing ⇒ fetching cannot help. This is
    // the real no-progress condition (build-spec §5 read cycle / bad module).
    let resolver =
        MockResolver::new().with("firewall", owner_module("firewall", &[], compat(1, 2)));
    let eval = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![read_miss("firewall")])]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![WorkingSetMember::seed("web"), loaded("firewall")];

    let err = run_fixpoint(&inputs(seed, 1, None), &resolver, &eval, &fetcher)
        .expect_err("unsatisfiable");
    assert!(
        matches!(err, FixpointError::Unsatisfiable { ref provider, .. } if provider == "firewall"),
        "{err:?}"
    );
    // The loaded provider was never re-fetched.
    assert!(fetcher.fetched.borrow().is_empty(), "must not re-fetch");
}

#[test]
fn bare_seed_provider_is_fetched() {
    // A desired package that is ALSO a config provider but seeded BARE (no config
    // module loaded yet) must be fetchable: a read of its root drives the loop to
    // fetch its config output, then converge. (Regression for the prior bug where
    // bare seed names pre-populated the no-progress guard and wedged such a
    // package to Unsatisfiable.)
    let resolver =
        MockResolver::new().with("firewall", owner_module("firewall", &[], compat(1, 2)));
    let eval = ScriptedEvaluator::new(vec![
        EvalClass::Missing(vec![read_miss("firewall")]),
        EvalClass::Manifest("{\"schema\":\"aos.config-manifest/v1\"}".to_string()),
    ]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![
        WorkingSetMember::seed("web"),
        WorkingSetMember::seed("firewall"),
    ];

    let out = run_fixpoint(&inputs(seed, 1, None), &resolver, &eval, &fetcher)
        .expect("converges after fetching the bare provider's config module");
    assert_eq!(out.iterations, 1);
    assert_eq!(
        fetcher.fetched.borrow().as_slice(),
        &["firewall".to_string()]
    );
}

#[test]
fn two_owners_of_one_root_is_exclusivity_violation() {
    // Two seeded packages own the `firewall` root: a per-system owned-root
    // exclusivity violation caught while BUILDING SystemRoots, before any eval.
    let resolver = MockResolver::new()
        .with("firewall-a", owner_module("firewall", &[], compat(1, 2)))
        .with("firewall-b", owner_module("firewall", &[], compat(1, 2)));
    let eval = ScriptedEvaluator::new(vec![]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![
        WorkingSetMember::seed("firewall-a"),
        WorkingSetMember::seed("firewall-b"),
    ];

    let err =
        run_fixpoint(&inputs(seed, 1, None), &resolver, &eval, &fetcher).expect_err("exclusivity");
    assert!(
        matches!(err, FixpointError::AmbiguousProvider { ref root, .. } if root == "firewall"),
        "{err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains("firewall-a@1.0.0"), "{msg}");
    assert!(msg.contains("firewall-b@1.0.0"), "{msg}");
    assert!(
        msg.contains("owned roots are exclusive per system"),
        "{msg}"
    );
    // The evaluator was never driven.
    assert!(eval.seen_sizes.borrow().is_empty());
}

#[test]
fn owned_root_shadowing_a_package_name_is_terminal() {
    // `web-extras` owns root `nginx`, but a package literally named `nginx` is
    // also seeded: its private root would be silently shadowed ⇒ hard error.
    let resolver = MockResolver::new()
        .with("web-extras", owner_module("nginx", &[], compat(1, 2)))
        .with("nginx", private_module(compat(1, 2)));
    let eval = ScriptedEvaluator::new(vec![]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![
        WorkingSetMember::seed("web-extras"),
        WorkingSetMember::seed("nginx"),
    ];

    let err =
        run_fixpoint(&inputs(seed, 1, None), &resolver, &eval, &fetcher).expect_err("shadowing");
    assert!(
        matches!(err, FixpointError::ShadowedRoot { ref root, .. } if root == "nginx"),
        "{err:?}"
    );
    assert!(eval.seen_sizes.borrow().is_empty());
}

#[test]
fn out_of_scope_contribution_is_terminal_at_resolve_time() {
    // `nginx` owns root `nginx` allowing only `virtualHosts`; `web` contributes
    // `nginx.upstreams`, outside the contributable set ⇒ F3-B resolve-time error.
    let mut contributor = private_module(compat(1, 2));
    contributor.contributes = vec![RootContribution {
        root: "nginx".to_string(),
        paths: vec!["upstreams".to_string()],
    }];
    let resolver = MockResolver::new()
        .with(
            "nginx",
            owner_module("nginx", &["virtualHosts"], compat(1, 2)),
        )
        .with("web", contributor);
    let eval = ScriptedEvaluator::new(vec![]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![
        WorkingSetMember::seed("nginx"),
        WorkingSetMember::seed("web"),
    ];

    let err = run_fixpoint(&inputs(seed, 1, None), &resolver, &eval, &fetcher)
        .expect_err("out-of-scope contribution");
    assert!(
        matches!(
            err,
            FixpointError::Contributable { ref path, .. } if path == "upstreams"
        ),
        "{err:?}"
    );
    assert!(eval.seen_sizes.borrow().is_empty());
}

// ---------------------------------------------------------------------------
// Terminal: fetch + eval classes
// ---------------------------------------------------------------------------

#[test]
fn fetch_failure_is_terminal() {
    let resolver = MockResolver::new().with("firewall", private_module(compat(1, 2)));
    let eval = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![write_miss("firewall.zone")])]);
    let fetcher = RecordingFetcher::failing();

    let err = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &resolver,
        &eval,
        &fetcher,
    )
    .expect_err("fetch fails");
    assert!(
        matches!(err, FixpointError::Fetch { ref provider, .. } if provider == "firewall"),
        "{err:?}"
    );
}

#[test]
fn eval_classes_map_to_terminal_errors() {
    let resolver = MockResolver::new();
    let fetcher = RecordingFetcher::new();
    let seed = || vec![WorkingSetMember::seed("web")];

    let cases: Vec<(EvalClass, fn(&FixpointError) -> bool)> = vec![
        (
            EvalClass::UndefinedOption {
                path: "firewall.zone".into(),
                file: None,
            },
            |e| matches!(e, FixpointError::UndefinedOption { .. }),
        ),
        (EvalClass::Conflict { defs: vec![] }, |e| {
            matches!(e, FixpointError::Conflict { .. })
        }),
        (
            EvalClass::Assertion {
                msg: "boom".into(),
                file: None,
            },
            |e| matches!(e, FixpointError::AssertionFailed { .. }),
        ),
        (EvalClass::Killed(KillReason::Oom), |e| {
            matches!(e, FixpointError::EvalKilled { .. })
        }),
        (
            EvalClass::Other {
                stderr: "syntax error".into(),
            },
            |e| matches!(e, FixpointError::EvalError { .. }),
        ),
    ];

    for (class, want) in cases {
        let eval = ScriptedEvaluator::new(vec![class.clone()]);
        let err = run_fixpoint(&inputs(seed(), 1, None), &resolver, &eval, &fetcher)
            .expect_err("terminal");
        assert!(want(&err), "class {class:?} -> {err:?}");
    }
}

// ---------------------------------------------------------------------------
// Non-convergence
// ---------------------------------------------------------------------------

#[test]
fn non_convergence_hits_cap_and_dumps_trace() {
    // Two seeded owners (`prov-a` owns `a`, `prov-b` owns `b`); each gets fetched
    // once (iter 0, 1); at iter == cap (2) the loop bails before a third eval.
    let resolver = MockResolver::new()
        .with("prov-a", owner_module("a", &[], compat(1, 2)))
        .with("prov-b", owner_module("b", &[], compat(1, 2)));
    let eval = ScriptedEvaluator::new(vec![
        EvalClass::Missing(vec![write_miss("a.x")]),
        EvalClass::Missing(vec![write_miss("b.x")]),
    ]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![
        WorkingSetMember::seed("prov-a"),
        WorkingSetMember::seed("prov-b"),
    ];

    let err = run_fixpoint(&inputs(seed, 1, Some(2)), &resolver, &eval, &fetcher)
        .expect_err("non-convergence");

    match err {
        FixpointError::NonConvergence {
            ref trace,
            iterations,
        } => {
            assert_eq!(iterations, 2);
            assert_eq!(trace.len(), 2);
        }
        other => panic!("expected NonConvergence, got {other:?}"),
    }
    let rendered = format!("{err}");
    assert!(rendered.contains("did not converge"), "{rendered}");
    assert!(rendered.contains("prov-a"), "{rendered}");
    assert!(rendered.contains("prov-b"), "{rendered}");
}

#[test]
fn derive_iter_cap_is_bounded_by_ceiling() {
    let empty = SystemRoots::default();
    assert_eq!(derive_iter_cap(0, &empty), ITER_CAP_SLACK);
}

#[test]
fn signed_host_nix_policy_fails_closed_with_no_anchors() {
    // Signed policy must bail before evaluation when the image has no trust
    // anchors, leaving no manifest behind.
    let tmp = tempfile::tempdir().unwrap();
    let host_nix = tmp.path().join("host.nix");
    std::fs::write(&host_nix, b"{ }").unwrap();
    let out = tmp.path().join("manifest.json");
    let cmd = EvalCommand {
        host_nix,
        base_lib: tmp.path().join("base-lib"),
        desired: None,
        module_abi: 1,
        out: out.clone(),
        eval_root: tmp.path().to_path_buf(),
        verbose: 0,
        trusted_config_keys_dirs: Vec::new(),
        require_signed_host_nix: true,
    };
    let err = run_eval_command(&cmd).expect_err("gate must fail closed with no anchors");
    let msg = format!("{err:#}");
    assert!(msg.contains("signature verification"), "wrong error: {msg}");
    assert!(
        !out.exists(),
        "no manifest may be written on a gate failure"
    );
}

#[test]
fn platform_host_nix_policy_needs_no_image_baked_key() {
    let tmp = tempfile::tempdir().unwrap();
    let host_nix = tmp.path().join("host.nix");
    std::fs::write(&host_nix, b"{ }").unwrap();
    let cmd = EvalCommand {
        host_nix,
        base_lib: tmp.path().join("base-lib"),
        desired: None,
        module_abi: 1,
        out: tmp.path().join("manifest.json"),
        eval_root: tmp.path().to_path_buf(),
        verbose: 0,
        trusted_config_keys_dirs: Vec::new(),
        require_signed_host_nix: false,
    };

    super::enforce_host_nix_trust_policy(&cmd)
        .expect("platform metadata is trusted without an image-specific key");
}
