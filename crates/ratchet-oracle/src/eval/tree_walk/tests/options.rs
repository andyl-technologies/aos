//! Tree-walk evaluator tests: options.

use super::*;
use crate::eval::heap::{EvalHeapResidentMemoryMode, EvalHeapResidentMemorySource};
use crate::heap::MemoryAdviceKind;
use crate::runtime::alloc::{AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint};

#[test]
fn evaluates_inline_scalar_literals() {
    assert_eq!(eval("42").as_int(), Ok(42));
    assert_eq!(eval("true").as_bool(), Ok(true));
    assert_eq!(eval("false").as_bool(), Ok(false));
    assert_eq!(eval("null").as_null(), Ok(()));

    let float = eval("1.25").as_float().expect("float value");
    assert_eq!(float.to_bits(), 1.25f64.to_bits());
}

#[test]
fn evaluates_string_literals_with_owned_heap() {
    let ir = lower("\"hello\"");
    let outcome = eval_whnf_owned(&ir).expect("string evaluates");
    let value = outcome.value();

    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        outcome
            .heap()
            .get_string(value)
            .expect("string is heap-owned")
            .bytes(),
        b"hello"
    );

    let empty = eval_whnf_owned(&lower("\"\"")).expect("empty string evaluates");
    assert_eq!(
        empty
            .heap()
            .get_string(empty.value())
            .expect("empty string is heap-owned")
            .bytes(),
        b""
    );

    let escaped =
        eval_whnf_owned(&lower("\"line\\n\\\"quoted\\\"\"")).expect("escaped string evaluates");
    assert_eq!(
        escaped
            .heap()
            .get_string(escaped.value())
            .expect("escaped string is heap-owned")
            .bytes(),
        b"line\n\"quoted\""
    );
}

#[test]
fn evaluates_uri_literals_as_strings() {
    assert_eq!(
        eval_string_bytes("https://example.test/path?x=1"),
        b"https://example.test/path?x=1"
    );
    assert_eq!(
        eval_string_bytes("https://example.test/path#fragment"),
        b"https://example.test/path"
    );
    assert_eq!(
        eval_string_bytes("https://example.test + \"/more\""),
        b"https://example.test/more"
    );
    assert_eq!(
        eval("https://example.test == \"https://example.test\"").as_bool(),
        Ok(true)
    );
}

#[test]
fn eval_cache_option_defaults_off_and_can_be_enabled() {
    let mut options = TreeWalkOptions::new();

    assert!(!options.eval_cache_enabled());
    options.set_eval_cache_enabled(true);
    assert!(options.eval_cache_enabled());

    let options = TreeWalkOptions::with_eval_cache_enabled(true);
    assert!(options.eval_cache_enabled());
}

#[test]
fn heap_memory_budget_option_can_be_configured() {
    let budget = HeapMemoryBudget::new(4096).expect("budget is non-zero");
    let mut options = TreeWalkOptions::new();

    assert_eq!(options.heap_memory_budget(), None);
    options.set_heap_memory_budget(budget);
    assert_eq!(options.heap_memory_budget(), Some(budget));
    options.clear_heap_memory_budget();
    assert_eq!(options.heap_memory_budget(), None);

    let options = TreeWalkOptions::with_heap_memory_budget(budget);
    assert_eq!(options.heap_memory_budget(), Some(budget));
}

#[test]
fn heap_memory_budget_option_polls_tree_walk_heap_allocations() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("\"budgeted\"");
    let outcome =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_heap_memory_budget(budget))
            .expect("string evaluates");

    assert_eq!(outcome.heap().memory_budget(), Some(budget));
    assert_eq!(
        outcome.heap().resident_memory_mode(),
        EvalHeapResidentMemoryMode::ProcessResidentSetWithArenaFallback
    );
    assert_eq!(outcome.heap().memory_budget_poll_count(), 1);
    let action = outcome
        .memory_budget_action()
        .expect("tree-walk outcome records configured budget action");
    assert_eq!(outcome.heap().last_memory_budget_action(), Some(action));
    assert_eq!(action.decision().budget(), budget);
    assert_eq!(
        action.decision().worker_stats(),
        outcome.heap().arena_stats()
    );
    assert_eq!(
        action.decision().permanent_stats(),
        outcome.heap().permanent_arena_stats()
    );
    match action.decision().resident_source() {
        EvalHeapResidentMemorySource::ArenaMappedBytes => {}
        EvalHeapResidentMemorySource::ProcessResidentSet(_) => {}
    }
    assert!(action.requests_tier_b());
    assert_eq!(outcome.cheap_memory_budget_plan(), None);
}

#[test]
fn attr_path_eval_reports_final_heap_memory_budget_action() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("{ value = \"budgeted\"; }");
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &[b"value".to_vec()],
        TreeWalkOptions::with_heap_memory_budget(budget),
        None,
    )
    .expect("attr-path selection evaluates");

    let action = outcome
        .memory_budget_action()
        .expect("attr-path outcome records configured budget action");
    assert_eq!(outcome.heap().last_memory_budget_action(), Some(action));
    assert_eq!(action.decision().budget(), budget);
    assert_eq!(
        action.decision().permanent_stats(),
        outcome.heap().permanent_arena_stats()
    );
    assert!(action.decision().requires_runtime_action());
    assert_eq!(outcome.cheap_memory_budget_plan(), None);
}

#[test]
fn gc_stress_policy_option_can_be_configured() {
    let policy = GcStressPolicy::every_n_safepoints(2).expect("period is non-zero");
    let mut options = TreeWalkOptions::new();

    assert!(options.gc_stress_policy().is_disabled());
    options.set_gc_stress_policy(policy);
    assert_eq!(options.gc_stress_policy(), policy);
    options.clear_gc_stress_policy();
    assert!(options.gc_stress_policy().is_disabled());

    let options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    assert_eq!(
        options.gc_stress_policy(),
        GcStressPolicy::every_safepoint()
    );
}

#[test]
fn gc_stress_policy_option_marks_tree_walk_heap_allocation_safepoints() {
    let policy = GcStressPolicy::every_safepoint();
    let default_worker =
        eval_whnf_owned(&lower("x: x")).expect("lambda expression evaluates without stress");
    let worker_outcome = eval_whnf_owned_with_options(
        &lower("x: x"),
        TreeWalkOptions::with_gc_stress_policy(policy),
    )
    .expect("lambda expression evaluates");

    assert_eq!(worker_outcome.value().tag(), default_worker.value().tag());
    assert_eq!(worker_outcome.heap().allocator_gc_stress_policy(), policy);
    assert_eq!(
        worker_outcome.heap().permanent_allocator_gc_stress_policy(),
        policy
    );
    let worker_safepoint = worker_outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("worker allocation safepoint records");
    assert_eq!(
        worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert_eq!(
        worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );

    let default_permanent =
        eval_whnf_owned(&lower("\"stress\"")).expect("string expression evaluates without stress");
    let permanent_outcome = eval_whnf_owned_with_options(
        &lower("\"stress\""),
        TreeWalkOptions::with_gc_stress_policy(policy),
    )
    .expect("string expression evaluates");
    assert_eq!(
        permanent_outcome
            .heap()
            .get_string(permanent_outcome.value())
            .expect("stress result is heap-owned string")
            .bytes(),
        default_permanent
            .heap()
            .get_string(default_permanent.value())
            .expect("default result is heap-owned string")
            .bytes()
    );
    let permanent_safepoint = permanent_outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("permanent allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

#[test]
fn heap_cheap_memory_advice_option_can_be_configured() {
    let mut options = TreeWalkOptions::new();

    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), None);
    options.set_heap_cheap_memory_advice_min_idle_epochs(7);
    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), Some(7));
    options.clear_heap_cheap_memory_advice();
    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), None);

    let options = TreeWalkOptions::with_heap_cheap_memory_advice_min_idle_epochs(3);
    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), Some(3));
}

#[test]
fn heap_cheap_memory_advice_option_reports_after_tree_walk_eval() {
    let ir = lower("\"advised\"");
    let default_outcome = eval_whnf_owned(&ir).expect("string evaluates without advice");
    assert_eq!(default_outcome.cheap_memory_advice_report(), None);
    assert_eq!(default_outcome.cheap_memory_budget_plan(), None);

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_heap_cheap_memory_advice_min_idle_epochs(0),
    )
    .expect("string evaluates");

    assert_eq!(outcome.stats(), default_outcome.stats());
    assert_eq!(
        outcome
            .heap()
            .get_string(outcome.value())
            .expect("advised result is a heap-owned string")
            .bytes(),
        default_outcome
            .heap()
            .get_string(default_outcome.value())
            .expect("default result is a heap-owned string")
            .bytes()
    );
    let report = outcome
        .cheap_memory_advice_report()
        .expect("cheap heap advice report is recorded");
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Cold);
    assert_eq!(report.cold_hash_consed().min_idle_epochs(), 0);
    assert!(report.cold_hash_consed().records() >= 1);
    assert!(report.cold_hash_consed().requested_bytes() > 0);
    assert_eq!(outcome.heap().memory_budget_poll_count(), 0);
    assert_eq!(outcome.heap().last_memory_budget_action(), None);
    assert_eq!(outcome.cheap_memory_budget_plan(), None);
}

#[test]
fn heap_cheap_memory_advice_option_reports_after_attr_path_eval() {
    let ir = lower("{ selected = \"advised\"; }");
    let attr_path = vec![b"selected".to_vec()];
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &attr_path,
        TreeWalkOptions::with_heap_cheap_memory_advice_min_idle_epochs(0),
        None,
    )
    .expect("attr-path evaluation succeeds");

    let report = outcome
        .cheap_memory_advice_report()
        .expect("attr-path outcomes also carry the post-evaluation advice report");
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Cold);
    assert_eq!(report.cold_hash_consed().min_idle_epochs(), 0);
    assert_eq!(outcome.heap().memory_budget_poll_count(), 0);
    assert_eq!(outcome.heap().last_memory_budget_action(), None);
    assert_eq!(outcome.cheap_memory_budget_plan(), None);
}

#[test]
fn heap_budget_and_cheap_advice_options_report_cold_aware_plan() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("\"planned\"");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_cheap_memory_advice_min_idle_epochs(0);

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("string evaluates");

    let action = outcome
        .memory_budget_action()
        .expect("heap budget still records the automatic action");
    assert_eq!(action.decision().budget(), budget);
    assert_eq!(
        action.decision().sample().cold_hash_consed_bytes(),
        0,
        "automatic allocation polling stays on unused-tail action telemetry"
    );
    let plan = outcome
        .cheap_memory_budget_plan()
        .expect("combined options record a cold-aware budget plan");
    assert_eq!(plan.decision().budget(), budget);
    assert!(
        plan.decision().sample().cold_hash_consed_bytes() > 0,
        "the opt-in plan carries cold hash-consed spill capacity"
    );
    let plan_report = plan
        .cheap_advice_report()
        .expect("over-budget cold-aware planning records advice telemetry");
    assert_eq!(outcome.cheap_memory_advice_report(), Some(plan_report));
    assert_eq!(plan_report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(
        plan_report.cold_hash_consed().kind(),
        MemoryAdviceKind::Cold
    );
    assert_eq!(plan_report.cold_hash_consed().min_idle_epochs(), 0);
}

#[test]
fn force_cache_materialization_costs_can_be_configured() {
    let costs = MaterializationCosts::new(20, 3, 4, 5);
    let mut options = TreeWalkOptions::new();

    assert_eq!(
        options.force_cache_materialization_costs(),
        MaterializationCosts::new(4, 1, 1, 1)
    );
    options.set_force_cache_materialization_costs(costs);
    assert_eq!(options.force_cache_materialization_costs(), costs);

    let options = TreeWalkOptions::with_force_cache_materialization_costs(costs);
    assert_eq!(options.force_cache_materialization_costs(), costs);
}

#[test]
fn unary_type_predicate_primops_classify_whnf_values() {
    assert_eq!(eval("builtins.isAttrs { a = 1; }").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isAttrs [ 1 ]").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isList [ 1 ]").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isFunction (x: x)").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.isFunction builtins.length").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction (builtins.map (x: x))").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isString \"x\"").as_bool(), Ok(true));
    let ir = lower("builtins.isString \"x\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("isString argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"x".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");
    assert_eq!(
        evaluator
            .eval_strict_unary_primop_value(
                ir.root,
                root.span,
                StrictUnaryPrimOp::IsString,
                argument,
                argument_span,
                value,
            )
            .expect("isString evaluates context-bearing strings")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isInt 1").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isInt 1.0").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isFloat 1.0").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isFloat 1").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isBool false").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isNull null").as_bool(), Ok(true));
    assert_eq!(eval("isNull null").as_bool(), Ok(true));
    assert_eq!(
        eval("let isNull = x: false; in isNull null").as_bool(),
        Ok(false)
    );
    assert_eq!(eval("builtins.isPath /tmp").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isPath \"not-path\"").as_bool(), Ok(false));
}

#[test]
fn type_of_primop_returns_nix_type_names() {
    assert_eq!(eval_string_bytes("builtins.typeOf 1"), b"int");
    assert_eq!(eval_string_bytes("builtins.typeOf 1.0"), b"float");
    assert_eq!(eval_string_bytes("builtins.typeOf false"), b"bool");
    assert_eq!(eval_string_bytes("builtins.typeOf null"), b"null");
    assert_eq!(eval_string_bytes("builtins.typeOf \"x\""), b"string");
    assert_eq!(eval_string_bytes("builtins.typeOf /tmp"), b"path");
    assert_eq!(eval_string_bytes("builtins.typeOf [ 1 ]"), b"list");
    assert_eq!(eval_string_bytes("builtins.typeOf { a = 1; }"), b"set");
    assert_eq!(eval_string_bytes("builtins.typeOf (x: x)"), b"lambda");
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.length"),
        b"lambda"
    );
    assert_eq!(
        eval_string_bytes("builtins.typeOf (builtins.map (x: x))"),
        b"lambda"
    );
}

#[test]
fn builtin_lookup_uses_shared_declaration_registry() {
    let builtin_names = BUILTINS.iter().map(Builtin::name).collect::<BTreeSet<_>>();

    assert_eq!(builtin_names.len(), BUILTINS.len());
    for builtin in BUILTINS.iter().copied() {
        assert_eq!(lookup_builtin(builtin.name()), Some(builtin));
    }
}

#[test]
fn direct_builtin_arity_uses_direct_metadata_not_first_class_metadata() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"__testBuiltin").expect("symbol interns");
    let call = BuiltinCall::new(IrId::new(0), Span::new(0, 13), symbol);
    let builtin = Builtin::test_with_call_arities(
        Some(BuiltinDirect::LazyUnary {
            effect: BuiltinEffect::Pure,
        }),
        Some(3),
    );

    check_builtin_direct_arity(call, builtin, 1).expect("direct arity uses direct metadata");

    let error = check_builtin_direct_arity(call, builtin, 3)
        .expect_err("direct arity ignores first-class arity");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidPrimOpArity {
            id: call.id,
            symbol: call.symbol,
            expected: 1,
            actual: 3,
        }
    );
}

#[test]
fn builtin_surface_matches_pinned_flakes_golden_fixture() {
    let fixture = pinned_builtin_name_bytes();
    assert_eq!(fixture.len(), BUILTINS.len());
    assert!(fixture.windows(2).all(|pair| pair[0] < pair[1]));

    let registry_names = BUILTINS
        .iter()
        .map(|builtin| builtin.name().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(registry_names, fixture);

    let mut options =
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec()).expect("system valid");
    options.set_current_time(1_700_000_000).expect("time valid");

    assert_eq!(
        eval_list_string_bytes_with_options("builtins.attrNames builtins", options.clone()),
        fixture,
    );
    assert_eq!(
        eval_list_string_bytes_with_options("builtins.attrNames builtins.builtins", options),
        fixture,
    );
}

#[test]
fn version_gated_builtin_names_match_pinned_flakes_surface() {
    for name in VERSION_GATED_BUILTIN_NAMES {
        let fixture_contains = PINNED_NIX_2_24_12_FLAKES_BUILTIN_NAMES.contains(name);
        let registry_contains = BUILTINS.lookup(name.as_bytes()).is_some();
        assert_eq!(
            registry_contains, fixture_contains,
            "{name} local registration should match the pinned flake-enabled fixture",
        );

        let source = format!("builtins.hasAttr {} builtins", nix_string_literal(name));
        assert_eq!(
            eval(&source).as_bool(),
            Ok(fixture_contains),
            "{name} runtime presence should match the pinned flake-enabled fixture",
        );
    }
}

#[test]
fn custom_effectful_unary_builtin_declarations_match_runtime_impls() {
    for name in [
        b"pathExists".as_slice(),
        b"readDir".as_slice(),
        b"readFile".as_slice(),
        b"readFileType".as_slice(),
        b"storePath".as_slice(),
    ] {
        assert_eq!(
            direct_builtin(name),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        let builtin = lookup_builtin(name).expect("builtin is registered");

        assert_eq!(builtin.first_class_arity(), Some(1));
        assert!(!builtin.docs().summary().is_empty());
    }
}

#[test]
fn tree_walk_options_normalize_store_dir() {
    let defaulted = TreeWalkOptions::with_store_dir(Vec::new()).expect("empty store dir defaults");
    assert_eq!(defaulted.store_dir(), b"/nix/store");

    let normalized = TreeWalkOptions::with_store_dir(b"//tmp//aos-store/./".to_vec())
        .expect("absolute store dir normalizes");
    assert_eq!(normalized.store_dir(), b"/tmp/aos-store");

    let parent_normalized = TreeWalkOptions::with_store_dir(b"/tmp/../aos-store".to_vec())
        .expect("parent components reduce");
    assert_eq!(parent_normalized.store_dir(), b"/aos-store");

    let nested_parent_normalized =
        TreeWalkOptions::with_store_dir(b"/tmp/aos-store/../other".to_vec())
            .expect("nested parent components reduce");
    assert_eq!(nested_parent_normalized.store_dir(), b"/tmp/other");

    let mut options = TreeWalkOptions::new();
    options
        .set_store_dir(b"/var//aos/store//".to_vec())
        .expect("absolute store dir sets");
    assert_eq!(options.store_dir(), b"/var/aos/store");

    assert_eq!(
        TreeWalkOptions::with_store_dir(b"relative/store".to_vec())
            .expect_err("relative store dir is rejected"),
        TreeWalkOptionsError::RelativeStoreDir
    );

    let base = TreeWalkOptions::with_search_path_base(b"//tmp//aos-search/./".to_vec())
        .expect("absolute search-path base normalizes");
    assert_eq!(base.search_path_base(), b"/tmp/aos-search");

    let mut options = TreeWalkOptions::new();
    options
        .set_search_path_base(b"/var//aos/search//".to_vec())
        .expect("absolute search-path base sets");
    assert_eq!(options.search_path_base(), b"/var/aos/search");

    assert_eq!(
        TreeWalkOptions::with_search_path_base(b"relative/search".to_vec())
            .expect_err("relative search-path base is rejected"),
        TreeWalkOptionsError::RelativeSearchPathBase
    );

    let path_base = TreeWalkOptions::with_path_literal_base(b"//tmp//aos-source/./".to_vec())
        .expect("absolute path-literal base normalizes");
    assert_eq!(
        path_base.path_literal_base(),
        Some(b"/tmp/aos-source".as_slice())
    );

    let mut options = TreeWalkOptions::new();
    assert_eq!(options.path_literal_base(), None);
    options
        .set_path_literal_base(b"/var//aos/source//".to_vec())
        .expect("absolute path-literal base sets");
    assert_eq!(
        options.path_literal_base(),
        Some(b"/var/aos/source".as_slice())
    );
    options.clear_path_literal_base();
    assert_eq!(options.path_literal_base(), None);

    assert_eq!(
        TreeWalkOptions::with_path_literal_base(b"relative/source".to_vec())
            .expect_err("relative path-literal base is rejected"),
        TreeWalkOptionsError::RelativePathLiteralBase
    );

    let home_dir = TreeWalkOptions::with_home_dir(b"//tmp//aos-home/./".to_vec())
        .expect("absolute home directory normalizes");
    assert_eq!(home_dir.home_dir(), Some(b"/tmp/aos-home".as_slice()));

    let mut options = TreeWalkOptions::new();
    assert_eq!(options.home_dir(), None);
    options
        .set_home_dir(b"/var//aos/home//".to_vec())
        .expect("absolute home directory sets");
    assert_eq!(options.home_dir(), Some(b"/var/aos/home".as_slice()));
    options.clear_home_dir();
    assert_eq!(options.home_dir(), None);

    assert_eq!(
        TreeWalkOptions::with_home_dir(b"relative/home".to_vec())
            .expect_err("relative home directory is rejected"),
        TreeWalkOptionsError::RelativeHomeDir
    );
    assert_eq!(
        TreeWalkOptions::with_home_dir(Vec::new()).expect_err("empty home directory is rejected"),
        TreeWalkOptionsError::RelativeHomeDir
    );
}

#[test]
fn to_file_uses_configured_store_dir() {
    let options = TreeWalkOptions::with_store_dir(b"/custom/store".to_vec())
        .expect("custom store dir configures");
    let path = eval_string_bytes_with_options(r#"builtins.toFile "x" "abc""#, options);

    assert!(path.starts_with(b"/custom/store/"), "{path:?}");
    assert!(path.ends_with(b"-x"), "{path:?}");
}

#[test]
fn tree_walk_options_configure_current_system() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.current_system(), None);

    let configured = TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
        .expect("currentSystem configures");
    assert_eq!(
        configured.current_system(),
        Some(b"aarch64-linux".as_slice())
    );

    let mut options = TreeWalkOptions::new();
    options
        .set_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem sets");
    assert_eq!(options.current_system(), Some(b"x86_64-linux".as_slice()));
    options.clear_current_system();
    assert_eq!(options.current_system(), None);

    assert_eq!(
        TreeWalkOptions::with_current_system(Vec::new())
            .expect_err("empty currentSystem is rejected"),
        TreeWalkOptionsError::EmptyCurrentSystem
    );
}

#[test]
fn tree_walk_options_configure_current_time() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.current_time(), None);

    let configured =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime configures");
    assert_eq!(configured.current_time(), Some(1_700_000_000));

    let mut options = TreeWalkOptions::new();
    options
        .set_current_time(1_700_000_001)
        .expect("currentTime sets");
    assert_eq!(options.current_time(), Some(1_700_000_001));
    options.clear_current_time();
    assert_eq!(options.current_time(), None);

    assert_eq!(
        TreeWalkOptions::with_current_time(-1).expect_err("negative currentTime is rejected"),
        TreeWalkOptionsError::NegativeCurrentTime
    );
}

#[test]
fn tree_walk_options_configure_trace_verbose() {
    let defaulted = TreeWalkOptions::new();
    assert!(!defaulted.trace_verbose());

    let configured = TreeWalkOptions::with_trace_verbose(true);
    assert!(configured.trace_verbose());

    let mut options = TreeWalkOptions::new();
    options.set_trace_verbose(true);
    assert!(options.trace_verbose());
    options.set_trace_verbose(false);
    assert!(!options.trace_verbose());
}

#[test]
fn tree_walk_options_configure_abort_on_warn() {
    let defaulted = TreeWalkOptions::new();
    assert!(!defaulted.abort_on_warn());

    let configured = TreeWalkOptions::with_abort_on_warn(true);
    assert!(configured.abort_on_warn());

    let mut options = TreeWalkOptions::new();
    options.set_abort_on_warn(true);
    assert!(options.abort_on_warn());
    options.set_abort_on_warn(false);
    assert!(!options.abort_on_warn());
}

#[test]
fn tree_walk_options_configure_max_call_depth() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.max_call_depth(), DEFAULT_MAX_CALL_DEPTH);

    let configured = TreeWalkOptions::with_max_call_depth(10);
    assert_eq!(configured.max_call_depth(), 10);

    let mut options = TreeWalkOptions::new();
    options.set_max_call_depth(0);
    assert_eq!(options.max_call_depth(), 0);
}

#[test]
fn tree_walk_options_configure_filesystem_access_policy() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.eval_mode(), EvalMode::Impure);
    assert!(defaulted.allowed_paths().is_empty());
    assert!(defaulted.allowed_uris().is_empty());

    let restricted = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    assert_eq!(restricted.eval_mode(), EvalMode::Restricted);

    let mut options = TreeWalkOptions::new();
    options.set_eval_mode(EvalMode::Pure);
    assert_eq!(options.eval_mode(), EvalMode::Pure);
    options
        .add_allowed_path(b"/tmp//allowed/./".to_vec())
        .expect("absolute allowed path configures");
    assert_eq!(options.allowed_paths(), &[b"/tmp/allowed".to_vec()]);
    options
        .set_allowed_paths(vec![b"/var/../tmp/other".to_vec()])
        .expect("allowed paths replace");
    assert_eq!(options.allowed_paths(), &[b"/tmp/other".to_vec()]);
    options.clear_allowed_paths();
    assert!(options.allowed_paths().is_empty());

    options
        .add_allowed_uri(b"https://cache.example/".to_vec())
        .expect("allowed URI prefix configures");
    assert_eq!(
        options.allowed_uris(),
        &[b"https://cache.example/".to_vec()]
    );
    assert!(options.uri_is_allowed(b"https://cache.example/source.tar.gz"));
    assert!(!options.uri_is_allowed(b"https://other.example/source.tar.gz"));
    options
        .set_allowed_uris(vec![b"github:".to_vec()])
        .expect("allowed URI prefixes replace");
    assert_eq!(options.allowed_uris(), &[b"github:".to_vec()]);
    options.clear_allowed_uris();
    assert!(options.allowed_uris().is_empty());

    assert_eq!(
        options
            .add_allowed_path(b"relative/path".to_vec())
            .expect_err("relative allowed paths are rejected"),
        TreeWalkOptionsError::RelativeAllowedPath
    );
    assert_eq!(
        options
            .add_allowed_path(Vec::new())
            .expect_err("empty allowed paths are rejected"),
        TreeWalkOptionsError::RelativeAllowedPath
    );
    assert_eq!(
        options
            .add_allowed_uri(Vec::new())
            .expect_err("empty allowed URI prefixes are rejected"),
        TreeWalkOptionsError::EmptyAllowedUri
    );
}

#[test]
fn tree_walk_options_configure_environment_variables() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.env_var(b"HOME"), None);

    let configured = TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/homeless".to_vec());
    assert_eq!(configured.env_var(b"HOME"), Some(b"/homeless".as_slice()));
    assert_eq!(configured.env_var(b"USER"), None);

    let mut options = TreeWalkOptions::new();
    options.set_env_var(b"USER".to_vec(), b"builder".to_vec());
    assert_eq!(options.env_var(b"USER"), Some(b"builder".as_slice()));
    options.set_env_var(b"USER".to_vec(), b"overridden".to_vec());
    assert_eq!(options.env_var(b"USER"), Some(b"overridden".as_slice()));
    options.clear_env_var(b"USER");
    assert_eq!(options.env_var(b"USER"), None);
}

#[test]
fn tree_walk_options_configure_ambient_search_path_rejection() {
    let mut options = TreeWalkOptions::new();
    assert!(!options.reject_ambient_search_path());

    options.set_reject_ambient_search_path(true);
    assert!(options.reject_ambient_search_path());

    options.set_reject_ambient_search_path(false);
    assert!(!options.reject_ambient_search_path());
}
