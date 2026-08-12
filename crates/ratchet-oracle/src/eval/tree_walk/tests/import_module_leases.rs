//! Imported-module context lease lifecycle and unwind tests.

use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn begin_module(
    evaluator: &mut TreeWalk,
    source_name: &[u8],
    source: &[u8],
    ir: Ir,
) -> ImportModuleWork {
    let id = evaluator.current_ir().root;
    let span = evaluator
        .current_ir()
        .arena
        .node(id)
        .expect("current root exists")
        .span;
    evaluator
        .begin_import_module(
            id,
            span,
            source_name,
            b"/",
            source,
            ir,
            ImportGlobalScope::Fresh,
        )
        .expect("module context begins")
}

#[test]
fn import_module_oracle_wrapper_restores_context_after_success() {
    let root_ir = lower("null");
    let imported_ir = lower("42");
    let id = root_ir.root;
    let span = root_ir.arena.node(id).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&root_ir);
    evaluator
        .with_scopes
        .push(EvalWithScope::new(EvalModuleId::ROOT, id, Value::int(7)));
    evaluator.scoped_globals.push(Value::int(8));

    let value = evaluator
        .load_and_eval_import_ir(
            id,
            span,
            b"/lease-module-success.nix",
            b"/",
            b"42",
            imported_ir,
            ImportGlobalScope::Fresh,
        )
        .expect("imported module evaluates");
    assert!(value.raw_eq(Value::int(42)));
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_import_module_leases.is_empty());
    assert_eq!(evaluator.with_scopes.len(), 1);
    assert!(evaluator.with_scopes[0].value().raw_eq(Value::int(7)));
    assert_eq!(evaluator.scoped_globals.len(), 1);
    assert!(evaluator.scoped_globals[0].raw_eq(Value::int(8)));
}

#[test]
fn import_module_error_uses_imported_source_before_restore() {
    let root_ir = lower("null");
    let mut evaluator = TreeWalk::new(&root_ir);
    let source_name = b"/lease-module-error.nix";
    let source = b"1";
    let work = begin_module(&mut evaluator, source_name, source, lower("1"));
    let error = TreeWalkError::new(
        TreeWalkErrorKind::InvalidNodeId { id: work.root },
        Span::default(),
    );

    let error = evaluator
        .run_import_module_with(work, |_, _| Err(error))
        .expect_err("injected module error propagates");
    let diagnostic_source = error.source().expect("imported source is attached");
    assert_eq!(diagnostic_source.name(), source_name);
    assert_eq!(diagnostic_source.bytes(), source);
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_import_module_leases.is_empty());
}

#[test]
fn nested_import_module_leases_restore_each_caller_context() {
    let root_ir = lower("null");
    let mut evaluator = TreeWalk::new(&root_ir);
    let outer = begin_module(&mut evaluator, b"/outer.nix", b"1", lower("1"));
    assert_eq!(evaluator.current_module, outer.module);
    assert_eq!(evaluator.suspended_env_roots.len(), 1);

    let inner = begin_module(&mut evaluator, b"/inner.nix", b"2", lower("2"));
    assert_eq!(evaluator.current_module, inner.module);
    assert_eq!(evaluator.suspended_env_roots.len(), 2);

    evaluator
        .finish_import_module(inner.token, Ok(Value::int(2)))
        .expect("inner context finishes");
    assert_eq!(evaluator.current_module, outer.module);
    assert_eq!(evaluator.suspended_env_roots.len(), 1);

    evaluator
        .finish_import_module(outer.token, Ok(Value::int(1)))
        .expect("outer context finishes");
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_import_module_leases.is_empty());
}

#[test]
fn import_module_lease_rejects_stale_same_depth_token_before_restore() {
    let root_ir = lower("null");
    let mut evaluator = TreeWalk::new(&root_ir);
    let stale = begin_module(&mut evaluator, b"/stale-first.nix", b"1", lower("1"));
    evaluator
        .finish_import_module(stale.token, Ok(Value::int(1)))
        .expect("first context finishes");
    let active = begin_module(&mut evaluator, b"/stale-second.nix", b"2", lower("2"));
    assert_eq!(stale.token.depth(), active.token.depth());
    assert_ne!(stale.token.generation(), active.token.generation());

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = evaluator.finish_import_module(stale.token, Ok(Value::int(1)));
    }));
    assert!(panic.is_err());
    assert_eq!(evaluator.current_module, active.module);
    assert_eq!(evaluator.suspended_env_roots.len(), 1);
    assert_eq!(evaluator.active_import_module_leases.len(), 1);

    evaluator
        .finish_import_module(active.token, Ok(Value::int(2)))
        .expect("active context still finishes");
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
}

#[test]
fn import_module_generation_exhaustion_precedes_publication_and_context_swap() {
    let root_ir = lower("null");
    let imported_ir = lower("1");
    let id = root_ir.root;
    let span = root_ir.arena.node(id).expect("root exists").span;
    let mut evaluator = TreeWalk::new(&root_ir);
    evaluator.next_import_module_lease_generation = u64::MAX;
    let modules_before = evaluator.modules.len();

    let error = evaluator
        .begin_import_module(
            id,
            span,
            b"/generation-exhausted.nix",
            b"/",
            b"1",
            imported_ir,
            ImportGlobalScope::Fresh,
        )
        .expect_err("generation exhaustion rejects module context");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::ImportModuleLeaseGenerationExhausted { .. }
    ));
    assert_eq!(evaluator.modules.len(), modules_before);
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_import_module_leases.is_empty());
}

#[test]
fn module_panic_restores_context_before_outer_cache_lease_aborts() {
    let root_ir = lower("null");
    let id = root_ir.root;
    let span = root_ir.arena.node(id).expect("root exists").span;
    let cache_path = PathBuf::from("/module-panic-cache.nix");
    let mut evaluator = TreeWalk::new(&root_ir);

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _: Result<Value, TreeWalkError> = evaluator.load_cached_import(
            id,
            span,
            cache_path.clone(),
            cache_path.as_os_str().as_bytes().to_vec(),
            true,
            true,
            |eval| {
                let work = begin_module(eval, b"/module-panic.nix", b"1", lower("1"));
                eval.run_import_module_with(work, |_, _| panic!("injected imported-module panic"))
            },
        );
    }));
    assert!(panic.is_err());
    assert_eq!(evaluator.current_module, EvalModuleId::ROOT);
    assert!(evaluator.suspended_env_roots.is_empty());
    assert!(evaluator.active_import_module_leases.is_empty());
    assert!(evaluator.active_import_cache_leases.is_empty());
    assert!(!evaluator.import_cache.contains_key(&cache_path));
}

#[test]
fn supported_import_module_runs_one_machine_body_without_oracle() {
    let root_ir = lower("null");
    let mut evaluator = TreeWalk::new(&root_ir);
    evaluator.active_root_eval_node = Some(root_ir.root);
    let path = b"/machine-import.nix";
    let work = begin_module(&mut evaluator, path, b"40 + 2", lower("40 + 2"));

    let value = evaluator
        .run_import_module_with(work, |eval, work| {
            eval.eval_import_module_root_with_demand_machine_or_oracle_if_enabled(
                work.root, path, true,
            )
        })
        .expect("supported imported scalar evaluates");
    assert!(value.raw_eq(Value::int(42)));
    assert_eq!(evaluator.demand_machine_import_counters.machine_bodies, 1);
    assert_eq!(evaluator.demand_machine_import_counters.module_declines, 0);
    assert_eq!(
        evaluator.demand_machine_import_counters.oracle_module_calls,
        0
    );
    assert_eq!(evaluator.active_root_eval_node, Some(root_ir.root));
}

#[test]
fn unsupported_import_module_declines_to_exactly_one_oracle_call() {
    let root_ir = lower("null");
    let mut evaluator = TreeWalk::new(&root_ir);
    let path = b"/oracle-import.nix";
    let work = begin_module(&mut evaluator, path, b"[1]", lower("[1]"));

    let value = evaluator
        .run_import_module_with(work, |eval, work| {
            eval.eval_import_module_root_with_demand_machine_or_oracle_if_enabled(
                work.root, path, true,
            )
        })
        .expect("declined imported list evaluates once in the oracle");
    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(evaluator.demand_machine_import_counters.machine_bodies, 0);
    assert_eq!(evaluator.demand_machine_import_counters.module_declines, 1);
    assert_eq!(
        evaluator.demand_machine_import_counters.oracle_module_calls,
        1
    );
}

#[test]
fn active_import_root_force_cache_semantics_force_one_oracle_call() {
    let root_ir = lower("null");
    let mut evaluator = TreeWalk::new(&root_ir);
    evaluator.force_cache_active = true;
    let path = b"/force-cache-import.nix";
    let work = begin_module(&mut evaluator, path, b"42", lower("42"));

    let value = evaluator
        .run_import_module_with(work, |eval, work| {
            eval.eval_import_module_root_with_demand_machine_or_oracle_if_enabled(
                work.root, path, true,
            )
        })
        .expect("force-cache-gated scalar evaluates in the oracle");
    assert!(value.raw_eq(Value::int(42)));
    assert_eq!(evaluator.demand_machine_import_counters.machine_bodies, 0);
    assert_eq!(evaluator.demand_machine_import_counters.module_declines, 1);
    assert_eq!(
        evaluator.demand_machine_import_counters.oracle_module_calls,
        1
    );
}

#[test]
fn text_store_import_keeps_the_existing_force_cache_bypass() {
    let root_ir = lower("null");
    let mut evaluator = TreeWalk::new(&root_ir);
    evaluator.force_cache_active = true;
    let path = b"/text-store-machine-import.nix";
    evaluator.text_store.insert(
        path.to_vec(),
        TextStoreEntry {
            contents: b"42".to_vec(),
            references: StringContext::empty(),
        },
    );
    let work = begin_module(&mut evaluator, path, b"42", lower("42"));

    let value = evaluator
        .run_import_module_with(work, |eval, work| {
            eval.eval_import_module_root_with_demand_machine_or_oracle_if_enabled(
                work.root, path, true,
            )
        })
        .expect("text-store scalar retains the force-cache bypass");
    assert!(value.raw_eq(Value::int(42)));
    assert_eq!(evaluator.demand_machine_import_counters.machine_bodies, 1);
    assert_eq!(evaluator.demand_machine_import_counters.module_declines, 0);
    assert_eq!(
        evaluator.demand_machine_import_counters.oracle_module_calls,
        0
    );
}
