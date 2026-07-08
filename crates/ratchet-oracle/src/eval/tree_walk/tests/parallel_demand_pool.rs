//! Production-wiring tests for the demand fan-out scheduler (L2-P3b).
//!
//! These evaluate real derivation graphs through the public owned-eval entry
//! points with `parallel_workers = Some(K >= 2)`, which spawns the helper
//! worker pool: the main worker publishes derivation attribute and dependency
//! fan-out to the shared demand queue, helpers force shared thunks through
//! the claim/park protocol, and the merged result must be byte-identical to
//! the serial evaluation - including the recorded `.drv` ATerm surfaces and
//! published error replays.

use std::num::NonZeroUsize;

use super::support::lower;
use super::*;

/// A derivation graph wide enough to trigger both fan-out sites: the root's
/// attribute batch and its dependency-list coercion.
const WIDE_DERIVATION_GRAPH: &str = r#"
    let
      mk = name: deps:
        builtins.derivation {
          inherit name deps;
          system = "x86_64-linux";
          builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          args = [ "-c" ":" ];
        };
      leafNames = [ "alpha" "beta" "gamma" "delta" "epsilon" "zeta" ];
      leaves = map (name: mk "leaf-${name}" []) leafNames;
      mids = map (leaf: mk "mid-${leaf.name}" [ leaf ]) leaves;
    in (mk "root" mids).drvPath
"#;

/// Evaluates `source` to its owned outcome with `workers` parallel workers
/// (`None` = serial), returning the root value rendering and the recorded
/// derivation surfaces.
fn eval_derivation_surfaces(source: &str, workers: Option<usize>) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let ir = lower(source);
    let options = match workers {
        Some(workers) => TreeWalkOptions::with_parallel_workers(NonZeroUsize::new(workers)),
        None => TreeWalkOptions::default(),
    };
    let outcome = eval_whnf_owned_with_options(&ir, options).expect("evaluation succeeds");
    let root = outcome
        .heap
        .get_string(outcome.value)
        .expect("root drvPath renders as a string")
        .bytes()
        .to_vec();
    let mut surfaces: Vec<(String, Vec<u8>)> = outcome
        .derivations
        .iter()
        .map(|derivation| {
            (
                derivation.absolute_path().to_owned(),
                derivation.aterm_bytes().unwrap_or_default().to_vec(),
            )
        })
        .collect();
    surfaces.sort();
    (root, surfaces)
}

/// K production workers instantiate a fan-out-heavy derivation graph with
/// byte-identical root path and `.drv` surfaces to the serial evaluator.
#[test]
fn parallel_pool_matches_serial_derivation_surfaces() {
    let (serial_root, serial_surfaces) = eval_derivation_surfaces(WIDE_DERIVATION_GRAPH, None);
    assert!(
        !serial_surfaces.is_empty(),
        "the graph records derivation surfaces"
    );
    for workers in [2, 4] {
        let (parallel_root, parallel_surfaces) =
            eval_derivation_surfaces(WIDE_DERIVATION_GRAPH, Some(workers));
        assert_eq!(
            serial_root, parallel_root,
            "root drvPath diverged with {workers} workers"
        );
        assert_eq!(
            serial_surfaces, parallel_surfaces,
            ".drv surfaces diverged with {workers} workers"
        );
    }
}

/// Repeated parallel runs stay deterministic under schedule nondeterminism.
#[test]
fn parallel_pool_is_schedule_deterministic() {
    let (serial_root, serial_surfaces) = eval_derivation_surfaces(WIDE_DERIVATION_GRAPH, None);
    for _ in 0..5 {
        let (parallel_root, parallel_surfaces) =
            eval_derivation_surfaces(WIDE_DERIVATION_GRAPH, Some(4));
        assert_eq!(serial_root, parallel_root);
        assert_eq!(serial_surfaces, parallel_surfaces);
    }
}

/// A dependency whose instantiation throws surfaces the identical error
/// under the parallel pool: a helper that claims the failing thunk publishes
/// the error and the main worker replays it verbatim.
#[test]
fn parallel_pool_replays_dependency_errors_identically() {
    const FAILING_GRAPH: &str = r#"
        let
          mk = name: deps:
            builtins.derivation {
              inherit name deps;
              system = "x86_64-linux";
              builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              args = [ "-c" ":" ];
            };
          good = map (name: mk "leaf-${name}" []) [ "one" "two" "three" ];
          bad = mk "boom" [ (throw "leaf exploded") ];
        in (mk "root" (good ++ [ bad ])).drvPath
    "#;
    let ir = lower(FAILING_GRAPH);
    let serial_error = eval_whnf_owned_with_options(&ir, TreeWalkOptions::default())
        .expect_err("serial evaluation fails");
    for _ in 0..3 {
        let parallel_error = eval_whnf_owned_with_options(
            &ir,
            TreeWalkOptions::with_parallel_workers(NonZeroUsize::new(4)),
        )
        .expect_err("parallel evaluation fails");
        assert_eq!(
            serial_error.to_string(),
            parallel_error.to_string(),
            "parallel error replay diverged from the serial error"
        );
    }
}

/// Dynamic attribute names interned during parallel evaluation resolve
/// consistently across workers through the shared symbol log.
#[test]
fn parallel_pool_handles_dynamic_symbols_in_derivation_env() {
    const DYNAMIC_GRAPH: &str = r#"
        let
          mk = name: extra:
            builtins.derivation ({
              inherit name;
              system = "x86_64-linux";
              builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              args = [ "-c" ":" ];
            } // extra);
          names = [ "one" "two" "three" "four" "five" ];
          leaves = map (
            name:
              mk "leaf-${name}" (builtins.listToAttrs [
                { name = "dynamic${name}"; value = "payload-${name}"; }
              ])
          ) names;
        in (mk "root" { deps = leaves; }).drvPath
    "#;
    let (serial_root, serial_surfaces) = eval_derivation_surfaces(DYNAMIC_GRAPH, None);
    for _ in 0..3 {
        let (parallel_root, parallel_surfaces) = eval_derivation_surfaces(DYNAMIC_GRAPH, Some(3));
        assert_eq!(serial_root, parallel_root);
        assert_eq!(serial_surfaces, parallel_surfaces);
    }
}

/// Evaluates `source` under `options`, returning the rendered root string,
/// sorted derivation surfaces, and merged evaluator stats.
fn eval_derivation_surfaces_with_options(
    source: &str,
    options: TreeWalkOptions,
) -> (Vec<u8>, Vec<(String, Vec<u8>)>, EvalStats) {
    let ir = lower(source);
    let outcome = eval_whnf_owned_with_options(&ir, options).expect("evaluation succeeds");
    let root = outcome
        .heap
        .get_string(outcome.value)
        .expect("root drvPath renders as a string")
        .bytes()
        .to_vec();
    let mut surfaces: Vec<(String, Vec<u8>)> = outcome
        .derivations
        .iter()
        .map(|derivation| {
            (
                derivation.absolute_path().to_owned(),
                derivation.aterm_bytes().unwrap_or_default().to_vec(),
            )
        })
        .collect();
    surfaces.sort();
    (root, surfaces, outcome.stats)
}

/// A derivation graph whose leaves live in imported files, so helper workers
/// demand imports the main worker may or may not have finished.
fn write_import_fanout_fixture(root: &std::path::Path) -> String {
    let names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"];
    for name in &names {
        fs::write(
            root.join(format!("leaf-{name}.nix")),
            format!(
                r#"builtins.derivation {{
                     name = "leaf-{name}";
                     system = "x86_64-linux";
                     builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                     args = [ "-c" ":" ];
                     payload = import ./payload-{name}.nix;
                   }}"#
            ),
        )
        .expect("leaf writes");
        fs::write(
            root.join(format!("payload-{name}.nix")),
            format!("\"payload-{name}\""),
        )
        .expect("payload writes");
    }
    let imports = names
        .iter()
        .map(|name| format!("(import ./leaf-{name}.nix)"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"(builtins.derivation {{
             name = "root";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             args = [ "-c" ":" ];
             deps = [ {imports} ];
           }}).drvPath"#
    )
}

/// Imported files demanded by helper workers evaluate once through the shared
/// import log and produce byte-identical surfaces to the serial evaluation.
#[test]
fn parallel_pool_shares_import_results_across_workers() {
    let root = fs::canonicalize(unique_temp_dir("parallel-import-fanout"))
        .expect("temp dir canonicalizes");
    let source = write_import_fanout_fixture(&root);
    let mut base_options = TreeWalkOptions::new();
    base_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");

    let (serial_root, serial_surfaces, serial_stats) =
        eval_derivation_surfaces_with_options(&source, base_options.clone());
    assert!(!serial_surfaces.is_empty());

    for _ in 0..3 {
        let workers = 4usize;
        let mut options = base_options.clone();
        options.set_parallel_workers(NonZeroUsize::new(workers));
        let (parallel_root, parallel_surfaces, parallel_stats) =
            eval_derivation_surfaces_with_options(&source, options);
        assert_eq!(serial_root, parallel_root);
        assert_eq!(serial_surfaces, parallel_surfaces);
        // The shared import log bounds cross-worker duplication to genuinely
        // concurrent first imports; without it every helper re-imported every
        // file it demanded. Allow the racy overlap but reject wholesale
        // duplication.
        assert!(
            parallel_stats.imports_evaluated()
                <= serial_stats.imports_evaluated() + workers as u64,
            "parallel workers re-evaluated imports wholesale: {} vs serial {}",
            parallel_stats.imports_evaluated(),
            serial_stats.imports_evaluated(),
        );
    }
}

/// Multi-worker evaluation with shared shape projection enabled stays
/// byte-identical to serial: projected shape ids are dense in one shared log
/// and every worker resolves foreign ids through its prefix replica.
#[test]
fn parallel_pool_shape_projection_matches_serial() {
    let (serial_root, serial_surfaces) = eval_derivation_surfaces(WIDE_DERIVATION_GRAPH, None);
    for workers in [2, 4] {
        let mut options = TreeWalkOptions::with_parallel_workers(NonZeroUsize::new(workers));
        options.set_parallel_shape_projection(true);
        let ir = lower(WIDE_DERIVATION_GRAPH);
        let outcome = eval_whnf_owned_with_options(&ir, options).expect("evaluation succeeds");
        let root = outcome
            .heap
            .get_string(outcome.value)
            .expect("root drvPath renders as a string")
            .bytes()
            .to_vec();
        let mut surfaces: Vec<(String, Vec<u8>)> = outcome
            .derivations
            .iter()
            .map(|derivation| {
                (
                    derivation.absolute_path().to_owned(),
                    derivation.aterm_bytes().unwrap_or_default().to_vec(),
                )
            })
            .collect();
        surfaces.sort();
        assert_eq!(serial_root, root, "shape projection diverged at K={workers}");
        assert_eq!(serial_surfaces, surfaces);
    }
}

/// Shared shape projection with imported modules: foreign projected ids reach
/// workers through replay and demand receipt, and the shaped-select fallback
/// never fails the evaluation.
#[test]
fn parallel_pool_shape_projection_matches_serial_with_imports() {
    let root = fs::canonicalize(unique_temp_dir("parallel-shape-imports"))
        .expect("temp dir canonicalizes");
    let source = write_import_fanout_fixture(&root);
    let mut base_options = TreeWalkOptions::new();
    base_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (serial_root, serial_surfaces, _) =
        eval_derivation_surfaces_with_options(&source, base_options.clone());
    for _ in 0..3 {
        let mut options = base_options.clone();
        options.set_parallel_workers(NonZeroUsize::new(3));
        options.set_parallel_shape_projection(true);
        let (parallel_root, parallel_surfaces, _) =
            eval_derivation_surfaces_with_options(&source, options);
        assert_eq!(serial_root, parallel_root);
        assert_eq!(serial_surfaces, parallel_surfaces);
    }
}
