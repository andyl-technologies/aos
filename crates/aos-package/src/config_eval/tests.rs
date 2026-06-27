//! Table-driven tests for the resolve↔eval fixpoint driver.
//!
//! The stock-Nix subprocess is replaced by a scripted [`ScriptedEvaluator`]
//! that returns a pre-canned sequence of [`EvalClass`] values, and the registry
//! fetch by a [`RecordingFetcher`]. This exercises the orchestration — the
//! provider selection, the ABI gate, the config-output-first fetch order, the
//! cycle/cap guard, and the A-vs-B lookup split — without a real evaluator.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;

use anyhow::{Result, bail};

use super::*;
use crate::types::{IndexEntry, ModuleAbiCompat, ProvidesIndex};

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
        self.seen_sizes
            .borrow_mut()
            .push(attempt.working_set.len());
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn compat(min: u32, max: u32) -> ModuleAbiCompat {
    ModuleAbiCompat { min, max }
}

fn entry(pkg: &str, root: &str, owner: bool, abi: ModuleAbiCompat) -> IndexEntry {
    IndexEntry {
        package: pkg.to_string(),
        version: "1.0.0".to_string(),
        platform: "x86_64-linux".to_string(),
        root: root.to_string(),
        owner,
        module_abi_compat: abi,
        config_output: format!("/nix/store/hash-{pkg}-config"),
    }
}

fn put(index: &mut ProvidesIndex, path: &str, entry: IndexEntry) {
    index.options.entry(path.to_string()).or_default().push(entry);
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
    let index = ProvidesIndex::empty();
    let eval = ScriptedEvaluator::new(vec![EvalClass::Manifest("{\"m\":1}".into())]);
    let fetcher = RecordingFetcher::new();

    let outcome = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &index,
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
    let mut index = ProvidesIndex::empty();
    put(
        &mut index,
        "firewall.zone",
        entry("firewall", "firewall", true, compat(1, 2)),
    );
    let eval = ScriptedEvaluator::new(vec![
        EvalClass::Missing(vec![write_miss("firewall.zone")]),
        EvalClass::Manifest("{\"m\":1}".into()),
    ]);
    let fetcher = RecordingFetcher::new();

    let outcome = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &index,
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
    let mut index = ProvidesIndex::empty();
    put(
        &mut index,
        "firewall.zone",
        entry("firewall", "firewall", true, compat(1, 2)),
    );
    // tls declares a `tls.*` root; reached via a Case-B absent-root read.
    put(
        &mut index,
        "tls.mode",
        entry("tls", "tls", true, compat(1, 2)),
    );
    let eval = ScriptedEvaluator::new(vec![
        EvalClass::Missing(vec![write_miss("firewall.zone")]),
        EvalClass::Missing(vec![read_miss("tls")]),
        EvalClass::Manifest("{\"m\":1}".into()),
    ]);
    let fetcher = RecordingFetcher::new();

    let outcome = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &index,
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

// ---------------------------------------------------------------------------
// Terminal: provider resolution
// ---------------------------------------------------------------------------

#[test]
fn no_provider_for_unknown_path() {
    let index = ProvidesIndex::empty();
    let eval = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![write_miss("unknown.opt")])]);
    let fetcher = RecordingFetcher::new();

    let err = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &index,
        &eval,
        &fetcher,
    )
    .expect_err("no provider");
    assert!(matches!(err, FixpointError::NoProvider { .. }), "{err:?}");
}

#[test]
fn abi_mismatch_when_provider_excludes_image_abi() {
    let mut index = ProvidesIndex::empty();
    // Provider exists but only admits abi 2..4; running image is abi 1.
    put(
        &mut index,
        "firewall.zone",
        entry("firewall", "firewall", true, compat(2, 4)),
    );
    let eval = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![write_miss("firewall.zone")])]);
    let fetcher = RecordingFetcher::new();

    let err = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &index,
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
fn seed_abi_gate_rejects_before_any_eval() {
    let index = ProvidesIndex::empty();
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

    let err = run_fixpoint(&inputs(seed, 1, None), &index, &eval, &fetcher)
        .expect_err("seed gate rejects");
    assert!(
        matches!(err, FixpointError::SeedAbiMismatch(_)),
        "{err:?}"
    );
    // The evaluator was never driven.
    assert!(eval.seen_sizes.borrow().is_empty());
}

#[test]
fn unsatisfiable_when_loaded_provider_still_missing() {
    let mut index = ProvidesIndex::empty();
    put(
        &mut index,
        "firewall.zone",
        entry("firewall", "firewall", true, compat(1, 2)),
    );
    // firewall's config module is ALREADY loaded (config_output present), yet a
    // read of the firewall root is still missing ⇒ fetching cannot help. This
    // is the real no-progress condition (build-spec §5 read cycle / bad module).
    let eval = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![read_miss("firewall")])]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![WorkingSetMember::seed("web"), loaded("firewall")];

    let err = run_fixpoint(&inputs(seed, 1, None), &index, &eval, &fetcher)
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
    // A desired package that is ALSO a config provider but seeded BARE (no
    // config module yet) must be fetchable: a read of its root drives the loop
    // to fetch its config output, then converge. (Regression for the prior
    // bug where bare seed names pre-populated the no-progress guard and wedged
    // such a package to Unsatisfiable.)
    let mut index = ProvidesIndex::empty();
    put(
        &mut index,
        "firewall.zone",
        entry("firewall", "firewall", true, compat(1, 2)),
    );
    let eval = ScriptedEvaluator::new(vec![
        EvalClass::Missing(vec![read_miss("firewall")]),
        EvalClass::Manifest("{\"schema\":\"aos.config-manifest/v1\"}".to_string()),
    ]);
    let fetcher = RecordingFetcher::new();
    let seed = vec![
        WorkingSetMember::seed("web"),
        WorkingSetMember::seed("firewall"),
    ];

    let out = run_fixpoint(&inputs(seed, 1, None), &index, &eval, &fetcher)
        .expect("converges after fetching the bare provider's config module");
    assert_eq!(out.iterations, 1);
    assert_eq!(fetcher.fetched.borrow().as_slice(), &["firewall".to_string()]);
}

#[test]
fn ambiguous_when_two_owners_of_one_root() {
    let mut index = ProvidesIndex::empty();
    // Two owners of the `firewall` root surviving the ABI filter: a
    // registry-integrity violation surfaced as AmbiguousProvider, never a
    // silent pick.
    put(
        &mut index,
        "firewall.zone",
        entry("firewall-a", "firewall", true, compat(1, 2)),
    );
    put(
        &mut index,
        "firewall.policy",
        entry("firewall-b", "firewall", true, compat(1, 2)),
    );
    let eval = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![read_miss("firewall")])]);
    let fetcher = RecordingFetcher::new();

    let err = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &index,
        &eval,
        &fetcher,
    )
    .expect_err("ambiguous");
    assert!(
        matches!(err, FixpointError::AmbiguousProvider { .. }),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Terminal: fetch + eval classes
// ---------------------------------------------------------------------------

#[test]
fn fetch_failure_is_terminal() {
    let mut index = ProvidesIndex::empty();
    put(
        &mut index,
        "firewall.zone",
        entry("firewall", "firewall", true, compat(1, 2)),
    );
    let eval = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![write_miss("firewall.zone")])]);
    let fetcher = RecordingFetcher::failing();

    let err = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("web")], 1, None),
        &index,
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
    let index = ProvidesIndex::empty();
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
        (
            EvalClass::Conflict { defs: vec![] },
            |e| matches!(e, FixpointError::Conflict { .. }),
        ),
        (
            EvalClass::Assertion {
                msg: "boom".into(),
                file: None,
            },
            |e| matches!(e, FixpointError::AssertionFailed { .. }),
        ),
        (
            EvalClass::Killed(KillReason::Oom),
            |e| matches!(e, FixpointError::EvalKilled { .. }),
        ),
        (
            EvalClass::Other {
                stderr: "syntax error".into(),
            },
            |e| matches!(e, FixpointError::EvalError { .. }),
        ),
    ];

    for (class, want) in cases {
        let eval = ScriptedEvaluator::new(vec![class.clone()]);
        let err = run_fixpoint(&inputs(seed(), 1, None), &index, &eval, &fetcher)
            .expect_err("terminal");
        assert!(want(&err), "class {class:?} -> {err:?}");
    }
}

// ---------------------------------------------------------------------------
// Non-convergence
// ---------------------------------------------------------------------------

#[test]
fn non_convergence_hits_cap_and_dumps_trace() {
    let mut index = ProvidesIndex::empty();
    put(&mut index, "a.x", entry("prov-a", "a", true, compat(1, 2)));
    put(&mut index, "b.x", entry("prov-b", "b", true, compat(1, 2)));
    // Two distinct providers get added (iter 0, 1); at iter == cap (2) the loop
    // bails before a third eval.
    let eval = ScriptedEvaluator::new(vec![
        EvalClass::Missing(vec![write_miss("a.x")]),
        EvalClass::Missing(vec![write_miss("b.x")]),
    ]);
    let fetcher = RecordingFetcher::new();

    let err = run_fixpoint(
        &inputs(vec![WorkingSetMember::seed("seed")], 1, Some(2)),
        &index,
        &eval,
        &fetcher,
    )
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
    let index = ProvidesIndex::empty();
    assert_eq!(derive_iter_cap(&index), ITER_CAP_SLACK);
}

#[test]
fn host_nix_gate_enforced_by_default_fails_closed_with_no_anchors() {
    // The stage-2 trust gate is ON by default. With no anchor dir and the
    // off-host flag unset, run_eval_command must bail BEFORE the evaluator runs
    // (a clean no-op), never silently fail open — the regression that the CS10
    // review caught in the on-host service wiring.
    let tmp = tempfile::tempdir().unwrap();
    let host_nix = tmp.path().join("host.nix");
    std::fs::write(&host_nix, b"{ }").unwrap();
    let out = tmp.path().join("manifest.json");
    let cmd = EvalCommand {
        host_nix,
        base_lib: tmp.path().join("base-lib"),
        index: None,
        desired: None,
        module_abi: 1,
        out: out.clone(),
        eval_root: tmp.path().to_path_buf(),
        verbose: 0,
        trusted_config_keys_dirs: Vec::new(),
        allow_unsigned_host_nix: false,
    };
    let err = run_eval_command(&cmd).expect_err("gate must fail closed with no anchors");
    let msg = format!("{err:#}");
    assert!(msg.contains("authenticity gate"), "wrong error: {msg}");
    assert!(!out.exists(), "no manifest may be written on a gate failure");
}
