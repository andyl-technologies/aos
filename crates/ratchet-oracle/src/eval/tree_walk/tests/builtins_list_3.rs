//! Tree-walk evaluator tests: builtins list 3.

use super::*;

#[test]
fn all_and_any_primops_check_predicate_then_list_then_result() {
    let ir = lower("builtins.all (1 / 0) []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let predicate = args[0];
    let predicate_span = ir
        .arena
        .node(predicate)
        .expect("predicate argument exists")
        .span;

    let error = eval_whnf(&ir).expect_err("all forces predicate before empty list result");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: predicate }
    );
    assert_eq!(error.span(), predicate_span);

    let ir = lower("builtins.any 1 []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let predicate = args[0];
    let predicate_span = ir
        .arena
        .node(predicate)
        .expect("predicate argument exists")
        .span;

    let error = eval_whnf(&ir).expect_err("any requires a predicate function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: predicate,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), predicate_span);

    let error = eval_whnf_owned(&lower(
        "let a = builtins.all; in a (builtins.throw \"predicate\") (builtins.throw \"list\")",
    ))
    .expect_err("first-class all forces predicate before list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"predicate");

    let error = eval_whnf_owned(&lower(
        "let a = builtins.any; in a (builtins.throw \"predicate\") (builtins.throw \"list\")",
    ))
    .expect_err("first-class any forces predicate before list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"predicate");

    let error = eval_whnf_owned(&lower("let a = builtins.any; in a (x: false) 1"))
        .expect_err("first-class any requires a list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.all (x: true) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf(&ir).expect_err("all requires a list after checking predicate");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    for source in [
        "builtins.all (x: 1) [ \"a\" ]",
        "builtins.any (x: 1) [ \"a\" ]",
    ] {
        let ir = lower(source);
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let predicate = args[0];
        let predicate_span = ir
            .arena
            .node(predicate)
            .expect("predicate argument exists")
            .span;

        let error = eval_whnf(&ir).expect_err("predicate result must be bool");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: predicate,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), predicate_span);
    }
}

#[test]
fn repeated_list_lambda_reuse_counts_every_application_once() {
    for (source, expected_calls) in [
        ("builtins.all (x: true) []", 0),
        ("builtins.all (x: x < 2) [ 0 1 2 3 ]", 3),
        ("builtins.any (x: x == 1) [ 0 1 2 3 ]", 2),
        ("builtins.filter (x: true) [ 0 1 2 ]", 3),
        ("builtins.concatMap (x: [ x ]) [ 0 1 2 ]", 3),
        ("builtins.groupBy (x: \"k\") [ 0 1 2 ]", 3),
    ] {
        let ir = lower(source);
        let mut evaluator = TreeWalk::new(&ir);

        evaluator.eval_root().expect("list builtin evaluates");

        assert_eq!(
            evaluator.stats_snapshot().function_calls(),
            expected_calls,
            "{source}"
        );
    }
}

#[test]
fn any_equality_island_preserves_semantics_order_and_stats() {
    let ((value, calls), admissions) = all_any_eq_island::with_test_enabled(|| {
        let ir = lower("let x = 2; in builtins.any (e: e == x) [ 1 2 (builtins.throw \"late\") ]");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator.eval_root().expect("fused any evaluates");
        (value, evaluator.stats_snapshot().function_calls())
    });
    assert_eq!(value.as_bool(), Ok(true));
    assert_eq!(calls, 2);
    assert_eq!(admissions, 1);

    let (value, admissions) = all_any_eq_island::with_test_enabled(|| {
        eval_whnf(&lower(
            "let elem = x: list: builtins.any (e: e == x) list; \
             in elem 2 [ 1 2 3 ]",
        ))
        .expect("curried lib/lists elem shape evaluates")
    });
    assert_eq!(value.as_bool(), Ok(true));
    assert_eq!(admissions, 1);

    let (error, admissions) = all_any_eq_island::with_test_enabled(|| {
        eval_whnf_owned(&lower(
            "let x = builtins.throw \"candidate\"; \
             in builtins.any (e: e == x) [ (builtins.throw \"element\") ]",
        ))
        .expect_err("left element forces before captured candidate")
    });
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown element error");
    };
    assert_eq!(message, b"element");
    assert_eq!(admissions, 1);

    let (value, admissions) = all_any_eq_island::with_test_enabled(|| {
        eval_whnf(&lower(
            "let x = builtins.throw \"unused\"; in builtins.any (e: e == x) []",
        ))
        .expect("empty any does not force its capture")
    });
    assert_eq!(value.as_bool(), Ok(false));
    assert_eq!(admissions, 0);

    let (value, admissions) = all_any_eq_island::with_test_enabled(|| {
        eval_whnf(&lower(
            "let x = { self = x; }; in builtins.any (e: e == x) [ x ]",
        ))
        .expect("shared cyclic identity compares equal")
    });
    assert_eq!(value.as_bool(), Ok(true));
    assert_eq!(admissions, 1);
}

fn imported_any_equality_error(fused: bool) -> (TreeWalkError, u64) {
    let root_ir = lower("null");
    let id = root_ir.root;
    let span = root_ir.arena.node(id).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&root_ir);
    let source_name = b"/any-equality-island-imported.nix";
    let source = b"x: e: e == x";
    let outer = evaluator
        .load_and_eval_import_ir(
            id,
            span,
            source_name,
            b"/",
            source,
            lower("x: e: e == x"),
            ImportGlobalScope::Fresh,
        )
        .expect("imported outer lambda evaluates");
    let backing = evaluator
        .heap
        .alloc_list(NixList::new(Vec::new()))
        .expect("external pointer backing allocates");
    let external = Value::external(backing.as_heap_ptr().expect("backing has a heap pointer"))
        .expect("external value builds");
    let predicate = evaluator
        .apply_lambda_value(id, span, id, outer, span, id, external)
        .expect("outer lambda returns exact equality predicate");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![external]))
        .expect("input list allocates");
    let mut run = || {
        evaluator.eval_all_any_primop_value(
            id,
            span,
            AllAnyOp::Any,
            EvalPrimOpArg::new(id, span, predicate),
            EvalPrimOpArg::new(id, span, input),
        )
    };
    let (result, admissions) = if fused {
        all_any_eq_island::with_test_enabled(run)
    } else {
        (run(), 0)
    };
    (
        result.expect_err("external equality is unsupported"),
        admissions,
    )
}

fn direct_captured_equality_predicate(
    evaluator: &mut TreeWalk,
    id: IrId,
    span: Span,
    captured: Value,
) -> Value {
    let outer = evaluator
        .eval_root()
        .expect("outer equality lambda evaluates");
    evaluator
        .apply_lambda_value(id, span, id, outer, span, id, captured)
        .expect("captured equality predicate evaluates")
}

#[test]
fn any_equality_island_preserves_imported_body_error_source() {
    let (generic, generic_admissions) = imported_any_equality_error(false);
    let (fused, fused_admissions) = imported_any_equality_error(true);

    assert_eq!(generic.kind(), fused.kind());
    assert_eq!(generic.span(), fused.span());
    assert_eq!(generic_admissions, 0);
    assert_eq!(fused_admissions, 1);
    for error in [&generic, &fused] {
        let source = error.source().expect("imported source is attached");
        assert_eq!(source.name(), b"/any-equality-island-imported.nix");
        assert_eq!(source.bytes(), b"x: e: e == x");
    }
}

fn forwarding_any_equality_result(fused: bool) -> (Result<Value, TreeWalkError>, u64) {
    let ir = lower("let x = 2; in e: e == x");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let predicate = evaluator.eval_root().expect("predicate evaluates");
    let inner = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(id))
        .expect("inner forwarding thunk allocates");
    let inner_cell = evaluator
        .heap
        .test_share_thunk_cell(inner)
        .expect("inner cell resolves");
    let ForceClaim::Claimed(inner_guard) = inner_cell.begin_force().expect("inner claim begins")
    else {
        panic!("inner thunk should be claimable");
    };
    inner_guard
        .finish(Value::int(2))
        .expect("inner result publishes");
    let outer = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(id))
        .expect("outer forwarding thunk allocates");
    let outer_cell = evaluator
        .heap
        .test_share_thunk_cell(outer)
        .expect("outer cell resolves");
    let ForceClaim::Claimed(outer_guard) = outer_cell.begin_force().expect("outer claim begins")
    else {
        panic!("outer thunk should be claimable");
    };
    outer_guard.finish(inner).expect("outer result publishes");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![outer]))
        .expect("input list allocates");
    let mut run = || {
        evaluator.eval_all_any_primop_value(
            id,
            span,
            AllAnyOp::Any,
            EvalPrimOpArg::new(id, span, predicate),
            EvalPrimOpArg::new(id, span, input),
        )
    };
    if fused {
        all_any_eq_island::with_test_enabled(run)
    } else {
        (run(), 0)
    }
}

#[test]
fn any_equality_island_follows_cached_thunk_forwarding_chains() {
    let (generic, generic_admissions) = forwarding_any_equality_result(false);
    let (fused, fused_admissions) = forwarding_any_equality_result(true);

    assert_eq!(
        generic.expect("generic equality evaluates").as_bool(),
        Ok(true)
    );
    assert_eq!(fused.expect("fused equality evaluates").as_bool(), Ok(true));
    assert_eq!(generic_admissions, 0);
    assert_eq!(fused_admissions, 1);
}

// Historical tests for the rejected callback-free replay experiment remain
// excluded while its measured failure is documented in the RFC design notes.
#[cfg(any())]
mod rejected_force_update_machine_tests {
    use super::*;

    #[test]
    fn force_update_machine_replays_cached_forwarding_without_generic_force() {
        let ((result, admissions), coverage) =
            force_update_machine::with_test_enabled(|| forwarding_any_equality_result(true));

        assert_eq!(
            result.expect("machine equality evaluates").as_bool(),
            Ok(true)
        );
        assert_eq!(admissions, 1);
        assert_eq!(coverage.cached_replay, 1);
        assert_eq!(coverage.owned_node_update, 0);
        assert_eq!(coverage.immediate, 0);
        assert_eq!(coverage.fallback, 0);
    }

    #[test]
    fn force_update_machine_owns_supported_node_updates() {
        let ir = lower("let marker = true; in x: e: e == x");
        let id = ir.root;
        let span = ir.arena.node(id).expect("root exists").span;
        let bool_id = ir
            .arena
            .nodes()
            .iter()
            .position(|node| node.kind == IrKind::Bool)
            .and_then(|index| u32::try_from(index).ok())
            .map(IrId::new)
            .expect("marker boolean remains in the arena");
        let mut evaluator = TreeWalk::new(&ir);
        let predicate =
            direct_captured_equality_predicate(&mut evaluator, id, span, Value::bool(true));
        let element = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(bool_id))
            .expect("suspended boolean Node thunk allocates");
        let input = evaluator
            .heap
            .alloc_list(NixList::new(vec![element]))
            .expect("input list allocates");
        let ((machine, admissions), coverage) = force_update_machine::with_test_enabled(|| {
            all_any_eq_island::with_test_enabled(|| {
                evaluator.eval_all_any_primop_value(
                    id,
                    span,
                    AllAnyOp::Any,
                    EvalPrimOpArg::new(id, span, predicate),
                    EvalPrimOpArg::new(id, span, input),
                )
            })
        });

        assert_eq!(
            machine.expect("machine equality evaluates").as_bool(),
            Ok(true)
        );
        assert_eq!(admissions, 1);
        assert!(coverage.owned_node_update >= 1);
        assert_eq!(coverage.fallback, 0);
    }

    #[test]
    fn force_update_machine_declines_unsupported_node_before_mutation() {
        let source = "let x = 2; in builtins.any (e: e == x) [ (1 + 1) ]";
        let ((result, admissions), coverage) = force_update_machine::with_test_enabled(|| {
            all_any_eq_island::with_test_enabled(|| eval_whnf(&lower(source)))
        });

        assert_eq!(
            result.expect("fallback equality evaluates").as_bool(),
            Ok(true)
        );
        assert_eq!(admissions, 1);
        assert_eq!(coverage.owned_node_update, 0);
        assert_eq!(coverage.fallback, 1);

        let ir = lower("(1 + 1) == 2");
        let equality_id = ir.root;
        let equality_node = *ir.arena.node(equality_id).expect("equality node exists");
        let IrData::Binary {
            op: BinOpKind::Eq,
            lhs,
            rhs,
        } = equality_node.data
        else {
            panic!("root is equality");
        };
        let lhs_node = *ir.arena.node(lhs).expect("left operand exists");
        let add_body = ir
            .arena
            .nodes()
            .iter()
            .position(|node| {
                matches!(
                    node.data,
                    IrData::Binary {
                        op: BinOpKind::Add,
                        ..
                    }
                )
            })
            .and_then(|index| u32::try_from(index).ok())
            .map(IrId::new)
            .expect("arithmetic body remains in the arena");
        let rhs_span = ir.arena.node(rhs).expect("right operand exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let unsupported = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(add_body))
            .expect("unsupported arithmetic Node thunk allocates");
        let state_before = evaluator
            .heap
            .get_thunk(unsupported)
            .expect("unsupported thunk resolves")
            .cell()
            .state();
        let declined = evaluator.try_force_update_any_equality_element(
            equality_id,
            &equality_node,
            lhs,
            lhs_node.span,
            unsupported,
            rhs,
            rhs_span,
            Value::int(2),
        );
        let state_after = evaluator
            .heap
            .get_thunk(unsupported)
            .expect("unsupported thunk still resolves")
            .cell()
            .state();
        assert!(declined.is_none());
        assert_eq!(state_before, Ok(ThunkState::Suspended));
        assert_eq!(state_after, state_before);
    }

    #[test]
    fn force_update_machine_preserves_exact_island_stats() {
        fn run(machine: bool) -> (Value, EvalStats) {
            let mut evaluate = || {
                let ir = lower("let x = 2; in builtins.any (e: e == x) [ 1 2 3 ]");
                let mut evaluator = TreeWalk::new(&ir);
                let value = evaluator.eval_root().expect("exact island evaluates");
                (value, evaluator.stats_snapshot())
            };
            if machine {
                force_update_machine::with_test_enabled(|| {
                    all_any_eq_island::with_test_enabled(evaluate).0
                })
                .0
            } else {
                all_any_eq_island::with_test_enabled(evaluate).0
            }
        }

        let generic_island = run(false);
        let machine = run(true);
        assert_eq!(generic_island.0.as_bool(), Ok(true));
        assert_eq!(machine.0.as_bool(), Ok(true));
        assert_eq!(
            machine.1.function_calls(),
            generic_island.1.function_calls()
        );
        assert_eq!(machine.1.thunks_forced(), generic_island.1.thunks_forced());
        assert_eq!(
            machine.1.thunk_cache_hits(),
            generic_island.1.thunk_cache_hits()
        );
        assert_eq!(
            machine.1.reforce_fast_path_hits(),
            generic_island.1.reforce_fast_path_hits()
        );
    }

    #[cfg(feature = "candidate_c_value")]
    #[test]
    fn force_update_machine_declines_typed_heads_before_work_mutation() {
        let ir = lower("let x = 2; in e: e == x");
        let id = ir.root;
        let node = *ir.arena.node(id).expect("predicate root exists");
        let mut options = TreeWalkOptions::new();
        options.set_typed_apply_thunk_heads_enabled(true);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let typed = evaluator
            .alloc_apply_thunk(
                id,
                node.span,
                id,
                node.span,
                Value::int(1),
                id,
                Value::int(2),
            )
            .expect("typed Apply head allocates");
        let counts_before = evaluator.heap.typed_thunk_head_counts();

        let declined = evaluator.try_force_update_any_equality_element(
            id,
            &node,
            id,
            node.span,
            typed,
            id,
            node.span,
            Value::int(2),
        );

        assert!(declined.is_none());
        assert_eq!(
            evaluator.heap.typed_thunk_state_if_any(typed),
            Some(ThunkState::Suspended)
        );
        assert_eq!(evaluator.heap.typed_thunk_head_counts(), counts_before);
        assert!(evaluator.active_force_leases.is_empty());
        assert!(evaluator.active_force_roots.is_empty());
    }

    #[test]
    fn force_update_machine_declines_marked_forwarding_chain() {
        fn run(machine: bool) -> (Value, force_update_machine::ForceUpdateCoverage) {
            let ir = lower("let marker = true; in x: e: e == x");
            let id = ir.root;
            let span = ir.arena.node(id).expect("root exists").span;
            let bool_id = ir
                .arena
                .nodes()
                .iter()
                .position(|node| node.kind == IrKind::Bool)
                .and_then(|index| u32::try_from(index).ok())
                .map(IrId::new)
                .expect("marker boolean remains in the arena");
            let mut evaluator = TreeWalk::new(&ir);
            let predicate =
                direct_captured_equality_predicate(&mut evaluator, id, span, Value::bool(true));
            let inner = evaluator
                .heap
                .alloc_thunk(EvalThunk::new(bool_id))
                .expect("inner Node thunk allocates");
            evaluator.mark_lazy_identity_thunk(inner);
            let outer = evaluator
                .heap
                .alloc_thunk(EvalThunk::new(bool_id))
                .expect("outer forwarding thunk allocates");
            let outer_cell = evaluator
                .heap
                .test_share_thunk_cell(outer)
                .expect("outer cell resolves");
            let ForceClaim::Claimed(outer_guard) =
                outer_cell.begin_force().expect("outer claim begins")
            else {
                panic!("outer thunk should be claimable");
            };
            outer_guard.finish(inner).expect("outer publishes inner");
            let input = evaluator
                .heap
                .alloc_list(NixList::new(vec![outer]))
                .expect("input list allocates");
            let mut evaluate = || {
                all_any_eq_island::with_test_enabled(|| {
                    evaluator.eval_all_any_primop_value(
                        id,
                        span,
                        AllAnyOp::Any,
                        EvalPrimOpArg::new(id, span, predicate),
                        EvalPrimOpArg::new(id, span, input),
                    )
                })
                .0
                .expect("marked forwarding equality evaluates")
            };
            if machine {
                force_update_machine::with_test_enabled(evaluate)
            } else {
                (
                    evaluate(),
                    force_update_machine::ForceUpdateCoverage::zero(),
                )
            }
        }

        let generic = run(false);
        let machine = run(true);
        assert_eq!(generic.0.as_bool(), Ok(true));
        assert_eq!(machine.0.as_bool(), Ok(true));
        assert_eq!(machine.1.cached_replay, 0);
        assert_eq!(machine.1.owned_node_update, 0);
        assert_eq!(machine.1.fallback, 1);
    }

    #[test]
    fn force_update_machine_declines_imported_node_body() {
        fn run(machine: bool) -> (Value, force_update_machine::ForceUpdateCoverage) {
            let root_ir = lower("x: e: e == x");
            let id = root_ir.root;
            let span = root_ir.arena.node(id).expect("root exists").span;
            let imported_ir = lower("true");
            let imported_body = imported_ir.root;
            let mut evaluator = TreeWalk::new(&root_ir);
            evaluator
                .load_and_eval_import_ir(
                    id,
                    span,
                    b"/force-update-imported-node.nix",
                    b"/",
                    b"true",
                    imported_ir,
                    ImportGlobalScope::Fresh,
                )
                .expect("imported boolean evaluates");
            let predicate =
                direct_captured_equality_predicate(&mut evaluator, id, span, Value::bool(true));
            let imported = evaluator
                .heap
                .alloc_thunk(EvalThunk::with_env(
                    EvalModuleId::new(1),
                    imported_body,
                    EvalEnv::default(),
                ))
                .expect("imported Node thunk allocates");
            let input = evaluator
                .heap
                .alloc_list(NixList::new(vec![imported]))
                .expect("input list allocates");
            let mut evaluate = || {
                all_any_eq_island::with_test_enabled(|| {
                    evaluator.eval_all_any_primop_value(
                        id,
                        span,
                        AllAnyOp::Any,
                        EvalPrimOpArg::new(id, span, predicate),
                        EvalPrimOpArg::new(id, span, input),
                    )
                })
                .0
                .expect("imported Node equality evaluates")
            };
            if machine {
                force_update_machine::with_test_enabled(evaluate)
            } else {
                (
                    evaluate(),
                    force_update_machine::ForceUpdateCoverage::zero(),
                )
            }
        }

        let generic = run(false);
        let machine = run(true);
        assert_eq!(generic.0.as_bool(), Ok(true));
        assert_eq!(machine.0.as_bool(), Ok(true));
        assert_eq!(machine.1.owned_node_update, 0);
        assert_eq!(machine.1.fallback, 1);
    }

    #[test]
    fn force_update_machine_declines_when_eval_stats_are_enabled() {
        fn run(machine: bool) -> (Value, EvalStats, force_update_machine::ForceUpdateCoverage) {
            let ir = lower("let x = 2; in builtins.any (e: e == x) [ 1 2 3 ]");
            let mut options = TreeWalkOptions::new();
            options.set_eval_stats_dump(true);
            let mut evaluator = TreeWalk::with_options(&ir, options);
            let mut evaluate = || {
                let value = all_any_eq_island::with_test_enabled(|| evaluator.eval_root())
                    .0
                    .expect("stats-mode exact island evaluates");
                (value, evaluator.stats_snapshot())
            };
            if machine {
                let ((value, stats), coverage) = force_update_machine::with_test_enabled(evaluate);
                (value, stats, coverage)
            } else {
                let (value, stats) = evaluate();
                (
                    value,
                    stats,
                    force_update_machine::ForceUpdateCoverage::zero(),
                )
            }
        }

        let generic = run(false);
        let machine = run(true);
        assert_eq!(generic.0.as_bool(), Ok(true));
        assert_eq!(machine.0.as_bool(), Ok(true));
        assert_eq!(machine.2.fallback, 2);
        assert_eq!(machine.1.function_calls(), generic.1.function_calls());
        assert_eq!(machine.1.thunks_forced(), generic.1.thunks_forced());
        assert_eq!(machine.1.thunk_cache_hits(), generic.1.thunk_cache_hits());
        assert_eq!(
            machine.1.reforce_fast_path_hits(),
            generic.1.reforce_fast_path_hits()
        );
    }
}

#[test]
fn any_equality_island_refuses_nonexact_predicates() {
    for (source, expected) in [
        ("let x = 2; in builtins.any (e: x == e) [ 2 ]", true),
        ("let x = 2; in builtins.any (e: e != x) [ 2 ]", false),
        ("builtins.any (e: e == 2) [ 2 ]", true),
        ("let x = 2; in builtins.all (e: e == x) [ 2 ]", true),
    ] {
        let (value, admissions) =
            all_any_eq_island::with_test_enabled(|| eval_whnf(&lower(source)));
        assert_eq!(
            value
                .expect("declined generic predicate evaluates")
                .as_bool(),
            Ok(expected),
            "{source}"
        );
        assert_eq!(admissions, 0, "{source}");
    }

    let (_result, admissions) = all_any_eq_island::with_test_enabled(|| {
        let ir = lower("let x = 2; in builtins.any (e: e == x) [ 2 ]");
        let mut options = TreeWalkOptions::default();
        options.set_gc_stress_policy(GcStressPolicy::every_safepoint());
        eval_whnf_with_options(&ir, options)
    });
    assert_eq!(admissions, 0);
}

#[test]
fn concat_map_primop_concatenates_mapped_lists_without_forcing_elements() {
    assert_eq!(
        eval("builtins.length (builtins.concatMap (x: [ x x ]) [ 1 2 ])").as_int(),
        Ok(4)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.concatMap (x: [ x x ]) [ 1 2 ]) 0").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.concatMap (x: [ x x ]) [ 1 2 ]) 3").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.length (builtins.concatMap (x: []) [ (1 / 0) ])").as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("builtins.length (builtins.concatMap (x: [ (1 / 0) ]) [ 1 ])").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval(
            "builtins.elemAt (builtins.concatMap builtins.attrValues [ { a = 1; } { b = 2; } ]) 1"
        )
        .as_int(),
        Ok(2)
    );
    assert_eq!(
            eval("builtins.length (let f = builtins.concatMap; in f builtins.attrValues [ { a = 1; } { b = 2; } ])")
                .as_int(),
            Ok(2)
        );
    assert_eq!(
        eval("let f = x: []; xs = [ (1 / 0) ]; in builtins.length (builtins.concatMap f xs)")
            .as_int(),
        Ok(0)
    );
    assert_eq!(
            eval("let builtins = { concatMap = f: list: [ 42 ]; }; in builtins.concatMap (x: []) [] == [ 42 ]")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn concat_map_primop_checks_function_then_list_then_results() {
    let ir = lower("builtins.concatMap (1 / 0) []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let function = args[0];
    let function_span = ir
        .arena
        .node(function)
        .expect("function argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("concatMap forces function before list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: function }
    );
    assert_eq!(error.span(), function_span);

    let ir = lower("builtins.concatMap 1 []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let function = args[0];
    let function_span = ir
        .arena
        .node(function)
        .expect("function argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("concatMap requires a function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), function_span);

    let error = eval_whnf_owned(&lower(
        "let f = builtins.concatMap; in f (builtins.throw \"function\") (builtins.throw \"list\")",
    ))
    .expect_err("first-class concatMap forces function before list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"function");

    let error = eval_whnf_owned(&lower("let f = builtins.concatMap; in f (x: [ x ]) 1"))
        .expect_err("first-class concatMap requires a list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower("let f = builtins.concatMap; in f (x: 1) [ \"a\" ]"))
        .expect_err("first-class concatMap requires list results");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.concatMap (x: [ x ]) 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("concatMap checks list after function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.concatMap (x: 1) [ \"a\" ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let function = args[0];
    let function_span = ir
        .arena
        .node(function)
        .expect("function argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("concatMap requires list results");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), function_span);
}

#[test]
fn group_by_primop_groups_by_string_key_without_forcing_elements() {
    assert_eq!(
        eval_list_string_bytes(
            "builtins.attrNames (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ])"
        ),
        vec![b"big".to_vec(), b"small".to_vec()]
    );
    assert_eq!(
            eval("builtins.length (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ]).small")
                .as_int(),
            Ok(2)
        );
    assert_eq!(
            eval("builtins.elemAt (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ]).small 0")
                .as_int(),
            Ok(1)
        );
    assert_eq!(
            eval("builtins.elemAt (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ]).big 0")
                .as_int(),
            Ok(3)
        );
    assert_eq!(
        eval("builtins.length (builtins.groupBy builtins.typeOf [ 1 \"x\" 2 ]).int").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval(
            "builtins.length (let f = builtins.groupBy; in f builtins.typeOf [ 1 \"x\" 2 ]).string"
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.length (builtins.groupBy (x: \"k\") [ (1 / 0) ]).k").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let f = x: \"k\"; xs = [ (1 / 0) ]; in builtins.length (builtins.groupBy f xs).k")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("let g = builtins.groupBy; in builtins.length (g (x: \"k\") [ (1 / 0) ]).k").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.groupBy (x: x) [ \"b\" \"a\" \"b\" ]).b 1 == \"b\"")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
            eval("let builtins = { groupBy = f: list: { local = [ 42 ]; }; }; in builtins.groupBy (x: \"k\") [] == { local = [ 42 ]; }")
                .as_bool(),
            Ok(true)
        );
}

#[test]
fn group_by_primop_checks_function_then_list_then_key_results() {
    let ir = lower("builtins.groupBy (1 / 0) []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let function = args[0];
    let function_span = ir
        .arena
        .node(function)
        .expect("function argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("groupBy forces function before list");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { id: function }
    );
    assert_eq!(error.span(), function_span);

    let ir = lower("builtins.groupBy 1 []");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let function = args[0];
    let function_span = ir
        .arena
        .node(function)
        .expect("function argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("groupBy requires a function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), function_span);

    let error = eval_whnf_owned(&lower(
        "let f = builtins.groupBy; in f (builtins.throw \"function\") (builtins.throw \"list\")",
    ))
    .expect_err("first-class groupBy forces function before list");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"function");

    let error = eval_whnf_owned(&lower("let f = builtins.groupBy; in f (x: \"k\") 1"))
        .expect_err("first-class groupBy requires a list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower("let f = builtins.groupBy; in f (x: 1) [ \"a\" ]"))
        .expect_err("first-class groupBy requires string keys");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let ir = lower("builtins.groupBy (x: \"k\") 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let list = args[1];
    let list_span = ir.arena.node(list).expect("list argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("groupBy checks list after function");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: list,
            expected: "list",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), list_span);

    let ir = lower("builtins.groupBy (x: 1) [ \"a\" ]");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let function = args[0];
    let function_span = ir
        .arena
        .node(function)
        .expect("function argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("groupBy requires string keys");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: function,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), function_span);
}

#[test]
fn generic_closure_primop_computes_discovery_order_closure() {
    let source = r#"builtins.genericClosure {
            startSet = [
              { key = 1; value = "one"; }
              { key = 2; value = "two"; }
            ];
            operator = item:
              if item.key == 1 then [ { key = 3; value = "three"; } ]
              else if item.key == 2 then [ { key = 4; value = "four"; } ]
              else [];
        }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"[{"key":1,"value":"one"},{"key":2,"value":"two"},{"key":3,"value":"three"},{"key":4,"value":"four"}]"#.to_vec()
        );
    assert_eq!(
        eval(
            r#"builtins.length (builtins.genericClosure {
                 startSet = [
                   (builtins.foldl' (acc: _x: acc) { key = "root"; } [])
                 ];
                 operator = item: [];
               })"#
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
        eval(
            r#"builtins.length (builtins.genericClosure (
                 builtins.foldl' (acc: _x: acc) {
                   startSet = [ { key = "root"; } ];
                   operator = item: [];
                 } []
               ))"#
        )
        .as_int(),
        Ok(1)
    );
    assert_eq!(
            eval_json_bytes(
                r#"let f = builtins.genericClosure; in f {
                    startSet = [ { key = 1; value = "start"; } ];
                    operator = item:
                      if item.key == 1 then [
                        { key = 2; value = "two"; }
                        { key = 3; value = "three"; }
                      ]
                      else if item.key == 2 then [ { key = 4; value = "four"; } ]
                      else if item.key == 3 then [ { key = 5; value = "five"; } ]
                      else [];
                }"#
            ),
            br#"[{"key":1,"value":"start"},{"key":2,"value":"two"},{"key":3,"value":"three"},{"key":4,"value":"four"},{"key":5,"value":"five"}]"#.to_vec()
        );
}

#[test]
fn generic_closure_primop_keeps_first_item_for_duplicate_keys() {
    assert_eq!(
        eval_json_bytes(
            r#"builtins.genericClosure {
                    startSet = [
                      { key = 1; value = "first"; }
                      { key = 1; value = "second"; }
                      { key = 2; value = "third"; }
                    ];
                    operator = item: [];
                }"#
        ),
        br#"[{"key":1,"value":"first"},{"key":2,"value":"third"}]"#.to_vec()
    );
    assert_eq!(
        eval_json_bytes(
            r#"builtins.genericClosure {
                    startSet = [ { key = [ 1 2 ]; value = "start"; } ];
                    operator = item: [
                      { key = [ 1 2 ]; value = "duplicate"; }
                      { key = [ 1 3 ]; value = "next"; }
                    ];
                }"#
        ),
        br#"[{"key":[1,2],"value":"start"},{"key":[1,3],"value":"next"}]"#.to_vec()
    );

    let dir = unique_temp_dir("generic-closure-path-keys");
    let first_path = dir.join("first.txt");
    let second_path = dir.join("second.txt");
    fs::write(&first_path, b"first").expect("first temp file writes");
    fs::write(&second_path, b"second").expect("second temp file writes");
    let first_path = path_source(&first_path);
    let second_path = path_source(&second_path);
    let source = format!(
        r#"builtins.map (item: item.value) (builtins.genericClosure {{
                startSet = [
                  {{ key = {first_path}; value = "first"; }}
                  {{ key = {first_path}; value = "duplicate"; }}
                  {{ key = {second_path}; value = "second"; }}
                ];
                operator = item: [];
            }})"#
    );
    assert_eq!(eval_json_bytes(&source), br#"["first","second"]"#.to_vec());
}

#[test]
fn generic_closure_primop_does_not_force_operator_for_empty_start_set() {
    assert_eq!(
        eval("builtins.length (builtins.genericClosure { startSet = []; })").as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("builtins.length (builtins.genericClosure { startSet = []; operator = 1; })").as_int(),
        Ok(0)
    );
}

#[test]
fn generic_closure_primop_checks_start_items_operator_and_results() {
    let error = eval_whnf_owned(&lower("builtins.genericClosure 1"))
        .expect_err("genericClosure requires an attrset");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower("builtins.genericClosure { operator = item: []; }"))
        .expect_err("genericClosure requires startSet");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = 1; operator = item: []; }",
    ))
    .expect_err("genericClosure startSet must be a list");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ 1 ]; operator = 1; }",
    ))
    .expect_err("genericClosure checks nonempty operator before start items");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ 1 ]; operator = item: []; }",
    ))
    .expect_err("genericClosure start items must be attrsets");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.genericClosure {
                startSet = [ { value = "missing"; } ];
                operator = item: [];
            }"#,
    ))
    .expect_err("genericClosure items require key attributes");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ { key = 1; } ]; }",
    ))
    .expect_err("genericClosure requires operator after nonempty startSet");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ { key = 1; } ]; operator = 1; }",
    ))
    .expect_err("genericClosure operator must be a function");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "function",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ { key = 1; } ]; operator = item: 1; }",
    ))
    .expect_err("genericClosure operator must return lists");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "list",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.genericClosure { startSet = [ { key = 1; } ]; operator = item: [ 2 ]; }",
    ))
    .expect_err("genericClosure generated items must be attrsets");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.genericClosure {
                startSet = [
                  { key = { a = 1; }; value = "first"; }
                  { key = { a = 1; }; value = "second"; }
                ];
                operator = item: [];
            }"#,
    ))
    .expect_err("genericClosure rejects incomparable duplicate keys");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "number, string, path, or list",
            actual: ValueTag::Attrs,
            ..
        }
    ));
}

#[test]
fn generic_closure_primop_checks_generated_keys_when_popped() {
    let error = eval_whnf_owned(&lower(
        r#"builtins.genericClosure {
                startSet = [ { key = 1; } ];
                operator = item:
                  if item.key == 1 then [
                    { key = 2; }
                    { value = "missing"; }
                  ]
                  else if item.key == 2 then builtins.throw "visited two"
                  else [];
            }"#,
    ))
    .expect_err("generated key validation waits until work item is popped");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected generated work item to run before later missing key");
    };
    assert_eq!(message, b"visited two");
}

#[test]
fn gen_list_primop_builds_lazy_indexed_elements() {
    assert_eq!(
        eval("builtins.length (builtins.genList (x: builtins.throw \"generated\") 2)").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.genList (x: x * x) 5) 4").as_int(),
        Ok(16)
    );
    assert_eq!(
        eval_string_bytes("builtins.concatStringsSep \",\" (builtins.genList builtins.toString 3)"),
        b"0,1,2"
    );
    assert_eq!(
        eval("let g = builtins.genList; in builtins.elemAt (g (x: x + 1) 2) 1").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let n = 2; f = x: x + 1; in builtins.elemAt (builtins.genList f n) 1").as_int(),
        Ok(2)
    );

    let error = eval_whnf_owned(&lower(
        "builtins.elemAt (builtins.genList (x: builtins.throw \"generated\") 2) 0",
    ))
    .expect_err("generated element is forced only when selected");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"generated");
}

#[test]
fn gen_list_marks_only_exact_elem_at_add_one_generators() {
    let exact =
        lower("let xs = [ 10 20 30 ]; in builtins.genList (i: builtins.elemAt xs (i + 1)) 2");
    let mut evaluator = TreeWalk::new(&exact);
    let value = evaluator
        .eval_node(exact.root)
        .expect("exact elemAt generator allocates");
    let element = evaluator
        .heap()
        .get_list(value)
        .expect("genList returns a list")
        .get(0)
        .expect("first generated element exists");
    assert!(matches!(
        evaluator
            .heap()
            .get_thunk(element)
            .expect("generated element is a thunk")
            .kind(),
        EvalThunkKind::GenListElemAtAddOne { .. }
    ));

    for source in [
        "let xs = [ 10 20 30 ]; in builtins.genList (i: builtins.elemAt xs (1 + i)) 2",
        "let xs = [ 10 20 30 ]; in builtins.genList (i: builtins.elemAt xs (i + 2)) 2",
        "let xs = [ 10 20 30 ]; in builtins.genList (i: builtins.elemAt xs i) 2",
    ] {
        let ir = lower(source);
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_node(ir.root)
            .expect("unsupported generator still allocates");
        let element = evaluator
            .heap()
            .get_list(value)
            .expect("genList returns a list")
            .get(0)
            .expect("first generated element exists");
        assert!(matches!(
            evaluator
                .heap()
                .get_thunk(element)
                .expect("generated element is a thunk")
                .kind(),
            EvalThunkKind::Apply { .. }
        ));
    }
}

#[test]
fn gen_list_elem_at_add_one_fast_path_preserves_laziness_and_selection() {
    assert_eq!(
        eval(
            "let xs = [ 10 20 30 ]; generated = builtins.genList \
             (i: builtins.elemAt xs (i + 1)) 2; \
             in builtins.elemAt generated 1",
        )
        .as_int(),
        Ok(30)
    );
    assert_eq!(
        eval(
            "let xs = builtins.throw \"receiver\"; \
             in builtins.length (builtins.genList \
                 (i: builtins.elemAt xs (i + 1)) 0)",
        )
        .as_int(),
        Ok(0)
    );
    let error = eval_whnf_owned(&lower(
        "let xs = builtins.throw \"receiver\"; \
         generated = builtins.genList (i: builtins.elemAt xs (i + 1)) 1; \
         in builtins.elemAt generated 0",
    ))
    .expect_err("forcing an element forces its captured receiver");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected the receiver's thrown error");
    };
    assert_eq!(message, b"receiver");
}

#[test]
fn stg_session_tail_enters_nested_genlist_markers_and_balances_updates() {
    let ir = lower(
        "let \
         base = [ \"a\" \"b\" \"c\" \"terminal\" ]; \
         layer1 = builtins.genList (i: builtins.elemAt base (i + 1)) 3; \
         layer2 = builtins.genList (i: builtins.elemAt layer1 (i + 1)) 2; \
         layer3 = builtins.genList (i: builtins.elemAt layer2 (i + 1)) 1; \
         in builtins.elemAt layer3 0",
    );
    let mut options = TreeWalkOptions::new();
    options.set_stg_session_enabled(true);
    let mut evaluator = TreeWalk::with_options(&ir, options);

    let value = evaluator
        .eval_root()
        .expect("nested marker chain evaluates");
    let bytes = evaluator
        .heap()
        .get_string(value)
        .expect("the terminal value is a string")
        .bytes();

    assert_eq!(bytes, b"terminal");
    assert!(
        evaluator.stg_session_marker_claims >= 2,
        "nested markers must use compact explicit update frames"
    );
    assert!(evaluator.active_force_leases.is_empty());
    assert!(evaluator.active_force_roots.is_empty());
    assert!(!evaluator.stg_session_active);
}

#[test]
fn gen_list_primop_checks_length_before_generator() {
    let ir = lower("builtins.genList (builtins.throw \"function\") (builtins.throw \"length\")");

    let error = eval_whnf_owned(&ir).expect_err("genList forces length before generator");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"length");

    let error = eval_whnf_owned(&lower(
        "let g = builtins.genList; in g (builtins.throw \"function\") (builtins.throw \"length\")",
    ))
    .expect_err("first-class genList forces length before generator");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"length");

    let ir = lower("builtins.genList 1 0");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let generator = args[0];
    let generator_span = ir
        .arena
        .node(generator)
        .expect("generator argument exists")
        .span;

    let error = eval_whnf_owned(&ir).expect_err("genList checks generator after length");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: generator,
            expected: "function",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), generator_span);

    let error = eval_whnf_owned(&lower(
        "builtins.length (builtins.genList (builtins.throw \"function\") 0)",
    ))
    .expect_err("genList checks generator even for empty results");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"function");

    let ir = lower("builtins.genList (x: x) 1.2");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let length = args[1];
    let length_span = ir.arena.node(length).expect("length argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("genList length must be an integer");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: length,
            expected: "int",
            actual: ValueTag::Float,
        }
    );
    assert_eq!(error.span(), length_span);

    let ir = lower("builtins.genList (x: x) (-1)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let length = args[1];
    let length_span = ir.arena.node(length).expect("length argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("genList rejects negative lengths");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::NegativeListLength {
            id: length,
            length: -1
        }
    );
    assert_eq!(error.span(), length_span);
}

#[test]
fn map_primop_builds_lazy_mapped_elements() {
    assert_eq!(
        eval("builtins.length (builtins.map (x: x + 1) [ 1 2 ])").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.map (x: x + 1) [ 1 2 ]) 0").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.elemAt (builtins.map (x: x + 1) [ 1 2 ]) 1").as_int(),
        Ok(3)
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.concatStringsSep \",\" (builtins.map builtins.toString [ 1 true null ])"
        ),
        b"1,1,"
    );
    assert_eq!(
        eval("let m = builtins.map; in builtins.elemAt (m (x: x + 1) [ 1 ]) 0").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("let xs = []; in builtins.length (builtins.map (builtins.throw \"function\") xs)")
            .as_int(),
        Ok(0)
    );
    assert_eq!(
        eval("let f = x: x + 1; xs = [ 1 ]; in builtins.elemAt (builtins.map f xs) 0").as_int(),
        Ok(2)
    );
    assert_eq!(
        eval("builtins.length (builtins.map (x: builtins.throw \"mapped\") [ 1 ])").as_int(),
        Ok(1)
    );
    assert_eq!(
        eval("builtins.length (builtins.map (x: x) [ (builtins.throw \"element\") ])").as_int(),
        Ok(1)
    );

    let error = eval_whnf_owned(&lower(
        "builtins.elemAt (builtins.map (x: builtins.throw \"mapped\") [ 1 ]) 0",
    ))
    .expect_err("mapped element is forced only when selected");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"mapped");

    let error = eval_whnf_owned(&lower(
        "builtins.elemAt (builtins.map (x: x) [ (builtins.throw \"element\") ]) 0",
    ))
    .expect_err("source element thunk is still lazy until selected");
    let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
        panic!("expected thrown error");
    };
    assert_eq!(message, b"element");
}
