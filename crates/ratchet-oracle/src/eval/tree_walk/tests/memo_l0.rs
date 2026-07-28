//! Content-memo (MEMO-1 L0/L1) probe, admission, decline, and CHECK tests.

use std::num::NonZeroUsize;

use super::support::lower;
use super::*;

/// Options with the content memo enabled at a low admission floor.
fn memo_options(min_cost: u32) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::default();
    options.set_memo_options(MemoOptions {
        enabled: true,
        min_cost,
        ..MemoOptions::default()
    });
    options
}

/// A lambda whose body re-allocates one content-identical closed subtree per
/// call: every call after the first should replay from the memo.
const DUPLICATED_SUBTREE: &str = r#"
    let
      f = n:
        let big = { a = "x" + "y"; b = [ 1 2 3 ]; c = 10 + 20; d = "p${"q"}"; };
        in if n > 0 then big.c else big.c + 1;
    in (f 1) + (f 2) + (f 3)
"#;

#[test]
fn duplicated_subtrees_hit_the_l0_memo_with_identical_output() {
    let ir = lower(DUPLICATED_SUBTREE);
    let baseline =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::default()).expect("baseline evaluates");
    let memo = eval_whnf_owned_with_options(&ir, memo_options(1)).expect("memo run evaluates");

    assert_eq!(baseline.value.as_int(), Ok(90));
    assert_eq!(memo.value.as_int(), Ok(90));
    assert!(
        memo.stats.memo_l0_admissions() >= 1,
        "the first force admits an entry: {:?}",
        memo.stats
    );
    assert!(
        memo.stats.memo_l0_hits() >= 1,
        "later instances of the def-site replay from the memo: {:?}",
        memo.stats
    );
    assert_eq!(baseline.stats.memo_l0_hits(), 0, "memo off records nothing");
    assert_eq!(baseline.stats.memo_l0_admissions(), 0);
}

#[test]
fn local_ready_directory_serves_a_completed_exact_recipe() {
    let ir = lower(DUPLICATED_SUBTREE);
    let mut options = TreeWalkOptions::default();
    options.set_memo_options(MemoOptions {
        enabled: false,
        min_cost: 1,
        local_ready_enabled: true,
        local_ready_min_cost: 1,
        ..MemoOptions::default()
    });
    let mut evaluator = TreeWalk::with_options(&ir, options);

    let value = evaluator.eval_root().expect("expression evaluates");
    let (entries, served_hits) = evaluator.test_ready_cell_directory_counts();

    assert_eq!(value.as_int(), Ok(90));
    assert!(entries >= 1, "successful normal forces publish Ready cells");
    assert!(
        served_hits >= 1,
        "a later exact recipe should reuse a still-Ready source cell"
    );
    assert!(
        evaluator.test_ready_cell_plan_count() >= entries,
        "each resident directory def-site should reuse one cached slot plan"
    );
}

#[test]
fn local_ready_census_declines_trace_revalidated_impure_nodes() {
    const READS_ENV: &str = r#"
        let f = n:
          let big = builtins.getEnv "LOCAL_READY_TEST_VAR";
          in big + (if n > 0 then "" else "!");
        in (f 1) + (f 2)
    "#;
    let ir = lower(READS_ENV);
    let mut options = TreeWalkOptions::default();
    options.set_env_var(b"LOCAL_READY_TEST_VAR".to_vec(), b"ready-value".to_vec());
    options.set_memo_options(MemoOptions {
        enabled: false,
        min_cost: 1,
        stats_enabled: true,
        local_ready_enabled: true,
        local_ready_min_cost: 1,
        ..MemoOptions::default()
    });

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("expression evaluates");

    assert!(
        outcome
            .stats
            .memo_economics()
            .ready_cell_effect_or_unsafe_declines()
            >= 1,
        "getEnv must not enter a directory without observation revalidation"
    );
}

#[test]
fn local_ready_directory_fails_closed_when_gc_is_enabled() {
    let ir = lower(DUPLICATED_SUBTREE);
    let mut options = TreeWalkOptions::default();
    options.set_gc_mode(EvalGcMode::Sweep);
    options.set_memo_options(MemoOptions {
        enabled: false,
        min_cost: 1,
        local_ready_enabled: true,
        local_ready_min_cost: 1,
        ..MemoOptions::default()
    });
    let evaluator = TreeWalk::with_options(&ir, options);

    assert_eq!(
        evaluator.test_ready_cell_directory_counts(),
        (0, 0),
        "weak thunk identities must not survive in a reclaiming heap"
    );
}

#[test]
fn local_ready_uses_independent_floor_and_leaves_impure_memo_enabled() {
    assert_eq!(MemoOptions::default().local_ready_min_cost, 64);
    let ir = lower(DUPLICATED_SUBTREE);
    let mut options = memo_options(1);
    let mut memo = *options.memo_options();
    memo.local_ready_enabled = true;
    memo.min_cost = u32::MAX;
    memo.local_ready_min_cost = 1;
    options.set_memo_options(memo);
    let mut evaluator = TreeWalk::with_options(&ir, options);

    let value = evaluator.eval_root().expect("raw expression evaluates");
    let (_, served_hits) = evaluator.test_ready_cell_directory_counts();
    assert_eq!(value.as_int(), Ok(90));
    assert!(served_hits >= 1, "the Ready directory serves the repeat");
    assert_eq!(
        evaluator.stats.memo_l0_misses(),
        0,
        "eligible Ready misses must bypass durable L0 probes"
    );
    assert_eq!(
        evaluator.stats.memo_l0_admissions(),
        0,
        "eligible Ready misses must bypass durable L0 admission"
    );

    const READS_ENV: &str = r#"
        let f = n:
          let big = builtins.getEnv "LOCAL_READY_EXCLUSIVE_TEST_VAR";
          in big + (if n > 0 then "" else "!");
        in (f 1) + (f 2)
    "#;
    let ir = lower(READS_ENV);
    let mut options = memo_options(1);
    options.set_env_var(
        b"LOCAL_READY_EXCLUSIVE_TEST_VAR".to_vec(),
        b"memo-value".to_vec(),
    );
    let mut memo = *options.memo_options();
    memo.local_ready_enabled = true;
    options.set_memo_options(memo);
    let outcome = eval_whnf_owned_with_options(&ir, options).expect("impure expression evaluates");

    assert!(
        outcome.stats.memo_l0_hits() >= 1,
        "a raw-ineligible impure site must retain durable memo behavior: {:?}",
        outcome.stats
    );
}

#[test]
fn l0_stores_immediate_results_as_direct_values() {
    let ir = lower(DUPLICATED_SUBTREE);
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        memo_options(1),
        "expr.nix",
        DUPLICATED_SUBTREE.as_bytes().to_vec(),
    );
    let value = evaluator.eval_root().expect("expression evaluates");
    assert_eq!(value.as_int(), Ok(90));
    let (direct, _) = evaluator.test_memo_l0_representation_counts();
    assert!(
        direct >= 1,
        "the immediate result should avoid a closed payload"
    );
    assert!(evaluator.stats.memo_l0_hits >= 1);
}

#[test]
fn l0_keeps_position_bearing_attrsets_payload_backed() {
    const SOURCE: &str = r#"
        let
          f = n:
            let result = { value = 42; };
            in if n > 0 then result else result;
        in { first = f 1; second = f 2; }
    "#;
    let ir = lower(SOURCE);
    let mut evaluator = TreeWalk::with_options_and_source(
        &ir,
        memo_options(1),
        "expr.nix",
        SOURCE.as_bytes().to_vec(),
    );
    let root = evaluator.eval_root().expect("root evaluates");
    let first = evaluator
        .heap()
        .get_attrs(root)
        .expect("root is attrs")
        .get(symbol_for(&ir, b"first"))
        .expect("first exists");
    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), first)
        .expect("first forces");
    assert!(evaluator.heap().get_attrs(forced).is_ok());
    let second = evaluator
        .heap()
        .get_attrs(root)
        .expect("root is attrs")
        .get(symbol_for(&ir, b"second"))
        .expect("second exists");
    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), second)
        .expect("second forces");
    assert!(evaluator.heap().get_attrs(forced).is_ok());
    let (_, payloads) = evaluator.test_memo_l0_representation_counts();
    assert!(
        payloads >= 1,
        "attrsets retain the position-remapping payload path"
    );
}

#[test]
fn stats_only_run_counts_potential_hits_without_building_memo_tables() {
    let ir = lower(DUPLICATED_SUBTREE);
    let mut options = TreeWalkOptions::default();
    options.set_memo_options(MemoOptions {
        enabled: false,
        min_cost: 1,
        local_ready_min_cost: 1,
        stats_enabled: true,
        ..MemoOptions::default()
    });

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("census run evaluates");
    let economics = outcome.stats.memo_economics();
    assert_eq!(outcome.value.as_int(), Ok(90));
    assert!(economics.potential_candidates() >= 2, "{economics:?}");
    assert!(economics.potential_hit_keys() >= 1, "{economics:?}");
    assert!(economics.potential_hits() >= 1, "{economics:?}");
    assert!(economics.potential_hit_static_cost_units() >= 1);
    assert!(economics.ready_structural_hits() >= 1, "{economics:?}");
    assert_eq!(economics.recursive_structural_repeats(), 0);
    assert!(economics.ready_cell_candidates() >= 2, "{economics:?}");
    assert!(economics.ready_cell_unique_recipes() >= 1, "{economics:?}");
    assert!(economics.ready_cell_ready_hits() >= 1, "{economics:?}");
    assert_eq!(economics.ready_cell_pending_overlaps(), 0);
    assert!(
        economics.ready_cell_two_way_hits() >= economics.ready_cell_one_way_hits(),
        "{economics:?}"
    );
    assert!(
        economics.ready_cell_ready_static_cost_units() >= 1,
        "{economics:?}"
    );
    assert!(
        economics.ready_structural_work_bytes()
            >= u64::try_from(std::mem::size_of::<crate::eval::EvalThunk>())
                .expect("EvalThunk size fits u64")
    );
    assert!(economics.key_samples() >= economics.potential_candidates());
    assert_eq!(economics.probe_samples(), 0, "L0/L1 stayed absent");
    assert_eq!(economics.hit_samples(), 0);
    assert_eq!(economics.record_samples(), 0);
    assert_eq!(outcome.stats.memo_l0_hits(), 0);
    assert_eq!(outcome.stats.memo_l0_declines(), 0);
    assert_eq!(outcome.stats.memo_l1_declines(), 0);
}

#[test]
fn memo_stats_decompose_key_probe_hit_and_record_stages() {
    let ir = lower(DUPLICATED_SUBTREE);
    let mut options = memo_options(1);
    let mut memo = *options.memo_options();
    memo.stats_enabled = true;
    options.set_memo_options(memo);

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("timed memo run evaluates");
    let economics = outcome.stats.memo_economics();
    assert_eq!(outcome.value.as_int(), Ok(90));
    assert!(outcome.stats.memo_l0_hits() >= 1, "{:?}", outcome.stats);
    assert!(economics.key_samples() >= 1, "{economics:?}");
    assert!(economics.probe_samples() >= 1, "{economics:?}");
    assert!(economics.hit_samples() >= 1, "{economics:?}");
    assert!(economics.record_samples() >= 1, "{economics:?}");
}

#[test]
fn admission_floor_gates_probes_entirely() {
    let ir = lower(DUPLICATED_SUBTREE);
    // The duplicated subtree is far below this floor, so no def-site is
    // admitted and the memo performs zero probes.
    let outcome = eval_whnf_owned_with_options(&ir, memo_options(1_000_000)).expect("evaluates");
    assert_eq!(outcome.value.as_int(), Ok(90));
    assert_eq!(outcome.stats.memo_l0_hits(), 0);
    assert_eq!(outcome.stats.memo_l0_misses(), 0);
    assert_eq!(outcome.stats.memo_l0_admissions(), 0);
}

#[test]
fn lambda_capturing_environments_decline_admission() {
    // `big` captures `fn`, a closure with no durable value hash: MEMO-1
    // declines admission for the def-site's every force.
    const CAPTURES_CLOSURE: &str = r#"
        let
          h = n:
            let fn = x: x + n;
                big = [ fn 1 2 3 ];
            in builtins.length big;
        in (h 1) + (h 2)
    "#;
    let ir = lower(CAPTURES_CLOSURE);
    let mut options = memo_options(1);
    let mut memo = *options.memo_options();
    memo.stats_enabled = true;
    options.set_memo_options(memo);
    let outcome = eval_whnf_owned_with_options(&ir, options).expect("evaluates");
    assert_eq!(outcome.value.as_int(), Ok(8));
    assert_eq!(
        outcome.stats.memo_l0_hits(),
        0,
        "closure-capturing subtrees never hit: {:?}",
        outcome.stats
    );
    assert!(
        outcome.stats.memo_economics().unknown_capture_declines() >= 1,
        "the stats-only census classifies the captured closure: {:?}",
        outcome.stats
    );
}

#[test]
fn memo_keys_are_stable_across_evaluator_instances_and_env_sensitive() {
    const SOURCE: &str = r#"let mk = v: { big = [ v 7 8 9 ]; }; in { one = mk 1; two = mk 2; }"#;
    let ir = lower(SOURCE);

    let keys = |ir: &Ir| {
        let mut evaluator = TreeWalk::with_options_and_source(
            ir,
            memo_options(1),
            "expr.nix",
            SOURCE.as_bytes().to_vec(),
        );
        let root = evaluator.eval_root().expect("root evaluates");
        let big = symbol_for(ir, b"big");
        let mut keys = Vec::new();
        for name in [b"one".as_slice(), b"two".as_slice()] {
            let member = {
                let attrs = evaluator.heap().get_attrs(root).expect("root is attrs");
                attrs.get(symbol_for(ir, name)).expect("member exists")
            };
            let forced = evaluator
                .force_value(ir.root, Span::new(0, 0), member)
                .expect("member forces");
            let big_thunk = {
                let attrs = evaluator.heap().get_attrs(forced).expect("member is attrs");
                attrs.get(big).expect("big exists")
            };
            keys.push(
                evaluator
                    .test_memo_candidate_key(big_thunk)
                    .expect("big thunk derives a memo key"),
            );
        }
        keys
    };

    let first = keys(&ir);
    let second = keys(&ir);
    assert_eq!(
        first[0], second[0],
        "the same def-site and captured values key identically across instances"
    );
    assert_eq!(first[1], second[1]);
    assert_ne!(
        first[0], first[1],
        "different captured values produce different keys for one def-site"
    );

    // Different source content changes the code component of every key.
    const OTHER: &str = r#"let mk = v: { big = [ v 7 8 10 ]; }; in { one = mk 1; two = mk 2; }"#;
    let other_ir = lower(OTHER);
    let mut evaluator = TreeWalk::with_options_and_source(
        &other_ir,
        memo_options(1),
        "expr.nix",
        OTHER.as_bytes().to_vec(),
    );
    let root = evaluator.eval_root().expect("root evaluates");
    let one = {
        let attrs = evaluator.heap().get_attrs(root).expect("root is attrs");
        attrs
            .get(symbol_for(&other_ir, b"one"))
            .expect("one exists")
    };
    let forced = evaluator
        .force_value(other_ir.root, Span::new(0, 0), one)
        .expect("one forces");
    let big_thunk = {
        let attrs = evaluator.heap().get_attrs(forced).expect("one is attrs");
        attrs
            .get(symbol_for(&other_ir, b"big"))
            .expect("big exists")
    };
    let other_key = evaluator
        .test_memo_candidate_key(big_thunk)
        .expect("big thunk derives a memo key");
    assert_ne!(
        first[0], other_key,
        "changed source content changes the key"
    );
}

#[test]
fn check_mode_is_clean_on_legitimate_hits() {
    let ir = lower(DUPLICATED_SUBTREE);
    let mut options = TreeWalkOptions::default();
    options.set_memo_options(MemoOptions {
        enabled: true,
        min_cost: 1,
        check_l0: true,
        ..MemoOptions::default()
    });
    let outcome = eval_whnf_owned_with_options(&ir, options).expect("CHECK run evaluates");
    assert_eq!(outcome.value.as_int(), Ok(90));
    assert!(outcome.stats.memo_l0_hits() >= 1, "{:?}", outcome.stats);
}

#[test]
fn check_mode_reports_poisoned_hits_as_divergence() {
    const SOURCE: &str = r#"
        let f = n:
          let big = { a = "x" + "y"; b = [ 1 2 3 ]; c = 10 + 20; };
          in if n > 0 then big.c else big.c + 1;
        in { first = f 1; second = f 2; }
    "#;
    let ir = lower(SOURCE);
    let mut options = TreeWalkOptions::default();
    options.set_memo_options(MemoOptions {
        enabled: true,
        min_cost: 1,
        check_l0: true,
        ..MemoOptions::default()
    });
    let mut evaluator =
        TreeWalk::with_options_and_source(&ir, options, "expr.nix", SOURCE.as_bytes().to_vec());
    let root = evaluator.eval_root().expect("root evaluates");
    let member = |evaluator: &TreeWalk, name: &[u8]| {
        let attrs = evaluator.heap().get_attrs(root).expect("root is attrs");
        attrs.get(symbol_for(&ir, name)).expect("member exists")
    };

    // Forcing `first` admits the big-subtree entry.
    let first = member(&evaluator, b"first");
    let first = evaluator
        .force_value(ir.root, Span::new(0, 0), first)
        .expect("first forces");
    assert_eq!(first.as_int(), Ok(30));

    // Poison every resident entry's payload; the second instance of the
    // def-site keys onto one of them.
    let keys = evaluator.test_memo_l0_keys();
    assert!(!keys.is_empty(), "the first force admitted an entry");
    for key in keys {
        assert!(evaluator.test_memo_poison_l0_payload(
            key,
            crate::cache::CachedExpressionValue::context_free_string(b"poisoned".to_vec()),
        ));
    }

    let second = member(&evaluator, b"second");
    let error = evaluator
        .force_value(ir.root, Span::new(0, 0), second)
        .expect_err("poisoned hit fails CHECK");
    assert!(
        matches!(error.kind(), TreeWalkErrorKind::MemoCheckDivergence { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn impure_slices_revalidate_on_hits() {
    // `big` observes `getEnv`: the entry's slice must revalidate on the hit
    // and the replay must re-record the observation into the trace.
    const READS_ENV: &str = r#"
        let f = n:
          let big = builtins.getEnv "MEMO_TEST_VAR";
          in big + (if n > 0 then "" else "!");
        in (f 1) + (f 2)
    "#;
    let ir = lower(READS_ENV);
    let mut options = memo_options(1);
    options.set_env_var(b"MEMO_TEST_VAR".to_vec(), b"memo-value".to_vec());
    let outcome = eval_whnf_owned_with_options(&ir, options).expect("evaluates");
    let rendered = outcome
        .heap
        .get_string(outcome.value)
        .expect("result is a string")
        .bytes()
        .to_vec();
    assert_eq!(rendered, b"memo-valuememo-value".to_vec());
    assert!(
        outcome.stats.memo_l0_hits() >= 1,
        "the second getEnv subtree replays from the memo: {:?}",
        outcome.stats
    );
    assert!(
        outcome
            .impure_input_trace
            .iter()
            .filter(|fingerprint| fingerprint
                .as_cacheable()
                .is_some_and(|recorded| recorded.identity().subject() == b"MEMO_TEST_VAR"))
            .count()
            >= 2,
        "the hit replays the recorded observation into the trace"
    );
}

/// A derivation graph whose every node computes one content-identical
/// configuration subtree: the parallel L1 tier should dedup them.
const PARALLEL_DUP_GRAPH: &str = r#"
    let
      cfgOf = name:
        let big = { a = "aa"; b = "bb"; c = "cc"; d = 40 + 2; };
        in big.a + big.b + big.c;
      mk = name: deps:
        builtins.derivation {
          inherit name deps;
          system = "x86_64-linux";
          builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          args = [ "-c" ":" ];
          cfg = cfgOf name;
        };
      leaves = map (name: mk "leaf-${name}" []) [ "alpha" "beta" "gamma" "delta" "epsilon" "zeta" ];
      mids = map (leaf: mk "mid-${leaf.name}" [ leaf ]) leaves;
    in (mk "root" mids).drvPath
"#;

fn derivation_surfaces(outcome: &EvalOutcome) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
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

#[test]
fn parallel_workers_share_l1_entries_with_byte_identical_output() {
    let ir = lower(PARALLEL_DUP_GRAPH);
    let baseline = eval_whnf_owned_with_options(&ir, TreeWalkOptions::default())
        .expect("serial baseline evaluates");
    let (baseline_root, baseline_surfaces) = derivation_surfaces(&baseline);
    assert!(!baseline_surfaces.is_empty());

    let mut census_options = TreeWalkOptions::with_parallel_workers(NonZeroUsize::new(4));
    census_options.set_memo_options(MemoOptions {
        enabled: false,
        min_cost: 1,
        stats_enabled: true,
        ..MemoOptions::default()
    });
    let census =
        eval_whnf_owned_with_options(&ir, census_options).expect("parallel census evaluates");
    let (census_root, census_surfaces) = derivation_surfaces(&census);
    assert_eq!(baseline_root, census_root);
    assert_eq!(baseline_surfaces, census_surfaces);
    assert!(census.stats.memo_economics().potential_hits() >= 1);

    // L0 off + L1 auto-on under parallel mode: every probe goes through the
    // shared table, so hits demonstrably cross the worker boundary protocol.
    let mut options = TreeWalkOptions::with_parallel_workers(NonZeroUsize::new(4));
    options.set_memo_options(MemoOptions {
        enabled: true,
        l0_enabled: false,
        min_cost: 1,
        ..MemoOptions::default()
    });
    let outcome = eval_whnf_owned_with_options(&ir, options).expect("parallel memo evaluates");
    let (root, surfaces) = derivation_surfaces(&outcome);
    assert_eq!(baseline_root, root, "root drvPath diverged under L1 memo");
    assert_eq!(baseline_surfaces, surfaces, ".drv surfaces diverged");
    assert!(
        outcome.stats.memo_l1_admissions() >= 1,
        "at least one worker published: {:?}",
        outcome.stats
    );
    assert!(
        outcome.stats.memo_l1_hits() >= 1,
        "duplicated subtrees replay from the shared tier: {:?}",
        outcome.stats
    );

    // CHECK-mode parallel run stays clean and byte-identical.
    let mut check_options = TreeWalkOptions::with_parallel_workers(NonZeroUsize::new(4));
    check_options.set_memo_options(MemoOptions {
        enabled: true,
        l0_enabled: false,
        min_cost: 1,
        check_l1: true,
        ..MemoOptions::default()
    });
    let checked =
        eval_whnf_owned_with_options(&ir, check_options).expect("parallel CHECK run evaluates");
    let (check_root, check_surfaces) = derivation_surfaces(&checked);
    assert_eq!(baseline_root, check_root);
    assert_eq!(baseline_surfaces, check_surfaces);
}
