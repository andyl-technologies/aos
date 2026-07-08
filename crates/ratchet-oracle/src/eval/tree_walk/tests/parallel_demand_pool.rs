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
