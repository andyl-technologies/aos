//! Brutal correctness tests for shared-graph parallel forcing.
//!
//! These tests hammer the claim/park/replay/cycle protocol from real OS
//! threads: exactly-once body execution on contended chains and diamonds,
//! identical error replay, same-worker re-entry parity, cross-worker deadlock
//! cycles that must error rather than hang, seeded schedule fuzzing, and a
//! serial-versus-parallel-mode evaluator differential.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

use super::*;
use crate::compile::{Ir, resolve as resolve_ast};
use crate::eval::tree_walk::{TreeWalk, TreeWalkOptions, eval_raw_bytes_with_options};
use crate::syntax::parse_str;

fn workers(count: usize) -> NonZeroUsize {
    NonZeroUsize::new(count).expect("test worker count is nonzero")
}

fn test_cells(count: usize) -> (Arc<ParallelForceCycleRegistry>, Vec<TreeWalkParallelThunkCell>) {
    let registry = Arc::new(ParallelForceCycleRegistry::new());
    let cells = shared_parallel_thunk_cells(count, &registry, |index| {
        TreeWalkError::new(
            TreeWalkErrorKind::ParallelThunkClaimDropped {
                id: crate::compile::IrId::new(index as u32),
            },
            Span::new(0, 1),
        )
    });
    (registry, cells)
}

fn int_of(result: &Result<Value, TreeWalkError>) -> i64 {
    result
        .as_ref()
        .expect("forced value")
        .as_int()
        .expect("int value")
}

/// Runs `test` on its own thread and fails if it does not finish in time.
///
/// Deadlock-sensitive tests must never hang the suite: a lost wakeup or a
/// missed cycle detection would otherwise park worker threads forever.
fn with_deadline(label: &str, test: impl FnOnce() + Send + 'static) {
    let (done, wait) = mpsc::channel();
    std::thread::spawn(move || {
        test();
        let _ = done.send(());
    });
    wait.recv_timeout(Duration::from_secs(60))
        .unwrap_or_else(|_| panic!("{label} deadlocked (60s deadline exceeded)"));
}

#[test]
fn k_workers_force_same_deep_chain_exactly_once() {
    const CHAIN: usize = 200;
    let (_registry, cells) = test_cells(CHAIN);
    let body_runs: Vec<AtomicUsize> = (0..CHAIN).map(|_| AtomicUsize::new(0)).collect();

    let body = |forcer: &ParallelSharedGraphForcer<'_>, index: usize| {
        body_runs[index].fetch_add(1, Ordering::SeqCst);
        if index + 1 < CHAIN {
            let tail = forcer.force(index + 1)?;
            Ok(Value::int(
                tail.as_int().map_err(|_| infinite_recursion_error(index))? + 1,
            ))
        } else {
            Ok(Value::int(1))
        }
    };

    // Roots enter the chain at staggered depths so workers race for claims at
    // different positions, not just the head.
    let reports = force_shared_parallel_roots(
        &cells,
        &[0, CHAIN / 2, CHAIN / 4, CHAIN - 1],
        workers(8),
        &body,
    )
    .expect("harness runs");

    for report in &reports {
        assert_eq!(int_of(&report.root_results[0]), CHAIN as i64);
        assert_eq!(int_of(&report.root_results[1]), (CHAIN - CHAIN / 2) as i64);
        assert_eq!(int_of(&report.root_results[2]), (CHAIN - CHAIN / 4) as i64);
        assert_eq!(int_of(&report.root_results[3]), 1);
    }
    for (index, runs) in body_runs.iter().enumerate() {
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "cell {index} body must run exactly once"
        );
    }
}

#[test]
fn overlapping_diamond_dependencies_across_workers() {
    // 0 = top, depends on 1 (left) and 2 (right); both depend on 3 (base).
    let (_registry, cells) = test_cells(4);
    let body_runs: Vec<AtomicUsize> = (0..4).map(|_| AtomicUsize::new(0)).collect();

    let body = |forcer: &ParallelSharedGraphForcer<'_>, index: usize| {
        body_runs[index].fetch_add(1, Ordering::SeqCst);
        let err = || infinite_recursion_error(index);
        match index {
            0 => {
                let left = forcer.force(1)?.as_int().map_err(|_| err())?;
                let right = forcer.force(2)?.as_int().map_err(|_| err())?;
                Ok(Value::int(left + right))
            }
            1 | 2 => {
                let base = forcer.force(3)?.as_int().map_err(|_| err())?;
                Ok(Value::int(base + index as i64))
            }
            _ => Ok(Value::int(10)),
        }
    };

    // Every worker forces every diamond node, so the base and both arms are
    // contended from multiple directions at once.
    let reports = force_shared_parallel_roots(&cells, &[0, 1, 2, 3], workers(8), &body)
        .expect("harness runs");

    for report in &reports {
        assert_eq!(int_of(&report.root_results[0]), 23);
        assert_eq!(int_of(&report.root_results[1]), 11);
        assert_eq!(int_of(&report.root_results[2]), 12);
        assert_eq!(int_of(&report.root_results[3]), 10);
    }
    for (index, runs) in body_runs.iter().enumerate() {
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "diamond cell {index} body must run exactly once"
        );
    }
}

#[test]
fn error_thunk_replays_identically_and_body_runs_once() {
    let (_registry, cells) = test_cells(1);
    let body_runs = AtomicUsize::new(0);
    let expected = TreeWalkError::new(
        TreeWalkErrorKind::Thrown {
            id: crate::compile::IrId::new(0),
            message: b"parallel error replay".to_vec(),
        },
        Span::new(0, 1),
    );

    let body_runs_reference = &body_runs;
    let error = expected.clone();
    let body = move |_forcer: &ParallelSharedGraphForcer<'_>, _index: usize| {
        body_runs_reference.fetch_add(1, Ordering::SeqCst);
        Err(error.clone())
    };

    let reports =
        force_shared_parallel_roots(&cells, &[0], workers(8), &body).expect("harness runs");

    for report in &reports {
        let observed = report.root_results[0]
            .as_ref()
            .expect_err("error thunk replays as an error");
        assert_eq!(*observed, expected, "every worker replays the same error");
    }
    assert_eq!(
        body_runs.load(Ordering::SeqCst),
        1,
        "failing body must run exactly once across all workers"
    );

    // Later forces replay the published failure without re-running the body.
    let replay = force_shared_parallel_roots(&cells, &[0], workers(1), &body)
        .expect("replay harness runs");
    assert_eq!(
        replay[0].root_results[0]
            .as_ref()
            .expect_err("replay stays an error"),
        &expected
    );
    assert_eq!(body_runs.load(Ordering::SeqCst), 1);
}

#[test]
fn same_worker_reentrant_force_is_infinite_recursion() {
    let (_registry, cells) = test_cells(1);

    // The body of cell 0 forces cell 0 again on the same worker: serial
    // blackhole re-entry, which must surface the serial infinite-recursion
    // error, published for every other observer.
    let body =
        |forcer: &ParallelSharedGraphForcer<'_>, _index: usize| forcer.force(0);

    let reports =
        force_shared_parallel_roots(&cells, &[0], workers(1), &body).expect("harness runs");

    let observed = reports[0].root_results[0]
        .as_ref()
        .expect_err("re-entrant force errors");
    assert_eq!(*observed, infinite_recursion_error(0));
}

#[test]
fn two_worker_cycle_errors_instead_of_deadlocking() {
    with_deadline("two-worker cycle", || {
        // Worker 1 forces cell 0 (whose body needs cell 1); worker 2 forces
        // cell 1 (whose body needs cell 0). The barrier guarantees both bodies
        // are claimed before either forces the other, so the run always forms
        // the cross-worker cycle.
        let (_registry, cells) = test_cells(2);
        let barrier = Barrier::new(2);
        let body = move |forcer: &ParallelSharedGraphForcer<'_>, index: usize| {
            barrier.wait();
            forcer.force(1 - index)
        };

        let reports = std::thread::scope(|scope| {
            let cells = &cells;
            let body = &body;
            let first = scope.spawn(move || {
                let forcer = ParallelSharedGraphForcer {
                    cells,
                    body,
                    worker: ParallelThunkWorkerId::new(1).expect("worker id"),
                };
                forcer.force(0)
            });
            let second = scope.spawn(move || {
                let forcer = ParallelSharedGraphForcer {
                    cells,
                    body,
                    worker: ParallelThunkWorkerId::new(2).expect("worker id"),
                };
                forcer.force(1)
            });
            [
                first.join().expect("worker 1 completes"),
                second.join().expect("worker 2 completes"),
            ]
        });

        // Both forces complete (no deadlock) and both report the serial
        // infinite-recursion error. Which cell index carries the error depends
        // on which worker's pre-park walk detected the cycle, but the error
        // class is always infinite recursion and both workers observe the
        // same propagated error.
        let first_error = reports[0].as_ref().expect_err("worker 1 cycle must error");
        let second_error = reports[1].as_ref().expect_err("worker 2 cycle must error");
        assert!(
            (0..2).any(|cell| *first_error == infinite_recursion_error(cell)),
            "worker 1 must report infinite recursion, got {first_error:?}"
        );
        assert_eq!(
            first_error, second_error,
            "both workers observe the same propagated cycle error"
        );
    });
}

#[test]
fn three_worker_ring_cycle_errors_instead_of_deadlocking() {
    with_deadline("three-worker ring cycle", || {
        let (_registry, cells) = test_cells(3);
        let barrier = Barrier::new(3);
        let body = move |forcer: &ParallelSharedGraphForcer<'_>, index: usize| {
            barrier.wait();
            forcer.force((index + 1) % 3)
        };

        let results = std::thread::scope(|scope| {
            let cells = &cells;
            let body = &body;
            let handles: Vec<_> = (0..3)
                .map(|index| {
                    scope.spawn(move || {
                        let forcer = ParallelSharedGraphForcer {
                            cells,
                            body,
                            worker: ParallelThunkWorkerId::new(index as u64 + 1)
                                .expect("worker id"),
                        };
                        forcer.force(index)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("worker completes"))
                .collect::<Vec<_>>()
        });

        let errors: Vec<&TreeWalkError> = results
            .iter()
            .map(|result| result.as_ref().expect_err("ring cycle must error"))
            .collect();
        assert!(
            (0..3).any(|cell| *errors[0] == infinite_recursion_error(cell)),
            "ring must report infinite recursion, got {:?}",
            errors[0]
        );
        assert!(
            errors.iter().all(|error| *error == errors[0]),
            "every ring worker observes the same propagated cycle error"
        );
    });
}

/// A tiny deterministic LCG for seeded schedule fuzzing.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

#[test]
fn stress_random_dags_with_yield_injection() {
    with_deadline("random DAG stress", || {
        const NODES: usize = 24;
        const ITERATIONS: usize = 60;
        let mut lcg = Lcg(0x5eed_cafe);

        for iteration in 0..ITERATIONS {
            // Random DAG: each node depends on up to two strictly-later nodes,
            // so the graph is acyclic while still deeply contended.
            let dependencies: Vec<Vec<usize>> = (0..NODES)
                .map(|index| {
                    let mut deps = Vec::new();
                    for _ in 0..(lcg.next() % 3) {
                        if index + 1 < NODES {
                            let dep =
                                index + 1 + (lcg.next() as usize % (NODES - index - 1).max(1));
                            deps.push(dep.min(NODES - 1));
                        }
                    }
                    deps
                })
                .collect();
            let yield_mask = lcg.next();

            let (_registry, cells) = test_cells(NODES);
            let body_runs: Vec<AtomicUsize> = (0..NODES).map(|_| AtomicUsize::new(0)).collect();
            let dependencies_reference = &dependencies;
            let body_runs_reference = &body_runs;
            let body = move |forcer: &ParallelSharedGraphForcer<'_>, index: usize| {
                body_runs_reference[index].fetch_add(1, Ordering::SeqCst);
                if yield_mask & (1 << (index % 64)) != 0 {
                    std::thread::yield_now();
                }
                let mut total = index as i64;
                for &dep in &dependencies_reference[index] {
                    total += forcer.force(dep)?.as_int().map_err(|_| {
                        infinite_recursion_error(index)
                    })?;
                }
                Ok(Value::int(total))
            };

            let roots: Vec<usize> = (0..NODES).collect();
            let reports = force_shared_parallel_roots(&cells, &roots, workers(4), &body)
                .expect("stress harness runs");

            // Deterministic oracle: fold the same DAG serially.
            let mut expected = vec![0i64; NODES];
            for index in (0..NODES).rev() {
                expected[index] = index as i64
                    + dependencies[index]
                        .iter()
                        .map(|&dep| expected[dep])
                        .sum::<i64>();
            }
            for report in &reports {
                for (index, result) in report.root_results.iter().enumerate() {
                    assert_eq!(
                        int_of(result),
                        expected[index],
                        "iteration {iteration}: node {index} value diverged"
                    );
                }
            }
            for (index, runs) in body_runs.iter().enumerate() {
                assert_eq!(
                    runs.load(Ordering::SeqCst),
                    1,
                    "iteration {iteration}: node {index} body must run exactly once"
                );
            }
        }
    });
}

fn lower(source: &str) -> Ir {
    aos_nix_dialect::nix_lower(
        resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers")
}

fn parallel_options(worker_count: usize) -> TreeWalkOptions {
    TreeWalkOptions::with_parallel_workers(Some(workers(worker_count)))
}

#[test]
fn differential_serial_vs_parallel_mode_expressions() {
    // Evaluator-level differential: parallel mode (parallel cells attached,
    // registry live, forcing routed through the claim protocol) must produce
    // byte-identical raw renderings to the serial evaluator.
    let corpus = [
        "1 + 2 * 3",
        r#"let f = n: if n < 2 then n else f (n - 1) + f (n - 2); in f 12"#,
        r#"let xs = builtins.genList (i: i * i) 32; in builtins.foldl' (a: b: a + b) 0 xs"#,
        r#"let a = { x = 1; y = a.x + 1; z = a.y + a.x; }; in a.z"#,
        r#"builtins.concatStringsSep "-" (map builtins.toString (builtins.genList (i: i) 12))"#,
        r#"let d = derivation { name = "diff"; system = ":"; builder = ":"; }; in d.drvPath"#,
        r#"with { a = 1; b = 2; }; a + b"#,
        r#"builtins.attrNames { inherit (builtins) map filter; extra = 1; }"#,
    ];

    for source in corpus {
        let ir = lower(source);
        let serial =
            eval_raw_bytes_with_options(&ir, TreeWalkOptions::default()).expect("serial evals");
        for worker_count in [1usize, 4] {
            let parallel = eval_raw_bytes_with_options(&ir, parallel_options(worker_count))
                .expect("parallel-mode evals");
            assert_eq!(
                serial, parallel,
                "parallel_workers={worker_count} diverged on {source:?}"
            );
        }
    }
}

#[test]
fn differential_infinite_recursion_error_parity() {
    // A genuinely cyclic binding must raise the same error class in serial
    // and parallel modes (parallel-cell same-worker re-entry parity).
    let ir = lower("let x = x + 1; in x");
    let serial = eval_raw_bytes_with_options(&ir, TreeWalkOptions::default())
        .expect_err("cyclic binding errors serially");
    let parallel = eval_raw_bytes_with_options(&ir, parallel_options(4))
        .expect_err("cyclic binding errors in parallel mode");
    assert_eq!(
        serial, parallel,
        "parallel mode must replay the serial infinite-recursion error"
    );
}

#[test]
fn parallel_mode_attaches_registry_serial_mode_does_not() {
    let ir = lower("1");
    let serial = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    assert!(serial.parallel_force_registry().is_none());

    let parallel = TreeWalk::with_options(&ir, parallel_options(2));
    assert!(parallel.parallel_force_registry().is_some());

    // Workers of one shared graph install a single shared registry.
    let shared = Arc::new(ParallelForceCycleRegistry::new());
    let mut worker = TreeWalk::with_options(&ir, parallel_options(2));
    worker.set_parallel_force_registry(Arc::clone(&shared));
    assert!(
        worker
            .parallel_force_registry()
            .is_some_and(|registry| Arc::ptr_eq(registry, &shared))
    );
}

#[test]
fn eval_stats_merge_accumulates_per_worker_counters() {
    use crate::eval::tree_walk::EvalStats;

    let ir = lower("let xs = builtins.genList (i: i + 1) 8; in builtins.foldl' (a: b: a + b) 0 xs");
    let mut first = TreeWalk::with_options(&ir, parallel_options(1));
    first.eval_root().expect("first worker evals");
    let mut second = TreeWalk::with_options(&ir, parallel_options(1));
    second.eval_root().expect("second worker evals");

    let first_stats = first.stats();
    let second_stats = second.stats();
    let mut merged = EvalStats::default();
    merged.merge_from(&first_stats);
    merged.merge_from(&second_stats);

    assert!(first_stats.thunks_forced() > 0);
    assert_eq!(
        merged.thunks_forced(),
        first_stats.thunks_forced() + second_stats.thunks_forced()
    );
    assert_eq!(
        merged.thunks_allocated(),
        first_stats.thunks_allocated() + second_stats.thunks_allocated()
    );
    assert_eq!(
        merged.function_calls(),
        first_stats.function_calls() + second_stats.function_calls()
    );
    assert_eq!(
        merged.heap_used_bytes(),
        first_stats.heap_used_bytes() + second_stats.heap_used_bytes()
    );
}

#[test]
fn harness_rejects_out_of_range_roots_and_worker_counts() {
    let (_registry, cells) = test_cells(1);
    let body =
        |_forcer: &ParallelSharedGraphForcer<'_>, _index: usize| Ok(Value::int(1));

    let result = force_shared_parallel_roots(&cells, &[3], workers(1), &body);
    assert!(matches!(
        result,
        Err(ParallelSharedForceError::RootIndexOutOfRange { index: 3, cells: 1 })
    ));
}
