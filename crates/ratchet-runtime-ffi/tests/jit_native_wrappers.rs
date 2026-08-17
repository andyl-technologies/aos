// JIT is off by construction under the Candidate-C variant; re-enabled at S4b (cutover plan section 6.1).
#![cfg(not(feature = "candidate_c_value"))]

use std::{collections::BTreeSet, num::NonZeroUsize};

use ratchet_jit::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate,
    JitTier, JitTieredCodeSlot, TierUpCounter, TierUpDemandHint, TierUpPolicy,
    jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates,
};
use ratchet_oracle::{
    compile::{
        EffectClass, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData, IrFacts, IrId,
        IrInlineCacheSiteId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind, resolve,
    },
    eval::{EvalEnv, EvalFrame, tree_walk::TreeWalk},
    runtime::forcing::rust_callable_aos_force,
    syntax::{BinOpKind, Span, Symbol, SymbolTable, parse_str},
    value::Value,
};
use ratchet_runtime_ffi::{
    aos_jit_stack_map_enter_native_wrapper_address, aos_jit_stack_map_exit_native_wrapper_address,
    context::RuntimeJitContext, wrappers::runtime_native_wrapper_bindings,
};

#[test]
fn jit_native_call_executes_mixed_runtime_ffi_wrappers_with_one_context() {
    let source = "{ target = 42; }";
    let source_span = Span::new(0, source.len() as u32);
    let source_ir = lower_source(source);
    let target_symbol = symbol_for(&source_ir, b"target");
    let lowered_ir = static_has_attr_ir(0, source_ir.symbols.clone(), target_symbol);
    let mut eval = TreeWalk::new(&source_ir);
    let attrs = eval.eval_root().expect("attrset evaluates");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, attrs).expect("attrs capture stores");
    let candidates = runtime_wrapper_candidates(&["aos_env_get", "aos_force", "aos_has_attr"]);
    let env_owned = EvalEnv::capture(&[frame]).expect("env captures");
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env(
        &mut eval,
        source_ir.root,
        source_span,
        &env_owned,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    // SAFETY: The runtime pointer comes from one pinned RuntimeJitContext shared
    // by the force and attr wrappers, the environment pointer comes from a live
    // EvalFrame, all registered candidates are process-local runtime-FFI
    // wrappers with the frozen host ABI, and the attrset value in the frame
    // belongs to the live evaluator.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &lowered_ir,
            lowered_ir.root,
            &candidates,
            rt,
            env,
        )
    }
    .expect("mixed runtime-FFI wrappers execute through JIT");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(preflight.slot().tier1_code_ptr().is_some());
    assert!(preflight.owns_encapsulated_module());
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    assert_eq!(
        invocation
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>(),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_has_attr",
        ]
    );
    assert_imports_registered(
        invocation.finalization(),
        &[
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_has_attr",
        ],
    );
    let value = preflight
        .native_value()
        .expect("promotion path returns native value");
    assert_eq!(value.as_bool(), Ok(true));
}

#[test]
fn jit_native_call_executes_select_runtime_ffi_wrapper_with_one_context() {
    let source = "{ target = 42; other = 7; }";
    let source_span = Span::new(0, source.len() as u32);
    let source_ir = lower_source(source);
    let target_symbol = symbol_for(&source_ir, b"target");
    let lowered_ir = static_select_ir(0, source_ir.symbols.clone(), target_symbol);
    let mut eval = TreeWalk::new(&source_ir);
    let attrs = eval.eval_root().expect("attrset evaluates");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, attrs).expect("attrs capture stores");
    let candidates = runtime_wrapper_candidates(&["aos_env_get", "aos_force", "aos_select_ic"]);
    let env_owned = EvalEnv::capture(&[frame]).expect("env captures");
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env(
        &mut eval,
        source_ir.root,
        source_span,
        &env_owned,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    // SAFETY: The runtime pointer comes from one pinned RuntimeJitContext shared
    // by the force and select wrappers, the environment pointer comes from a
    // live EvalFrame, all registered candidates are process-local runtime-FFI
    // wrappers with the frozen host ABI, and the attrset value in the frame
    // belongs to the live evaluator.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &lowered_ir,
            lowered_ir.root,
            &candidates,
            rt,
            env,
        )
    }
    .expect("select runtime-FFI wrapper executes through JIT");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(preflight.slot().tier1_code_ptr().is_some());
    assert!(preflight.owns_encapsulated_module());
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    assert_eq!(
        invocation
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>(),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_select_ic",
        ]
    );
    assert_imports_registered(
        invocation.finalization(),
        &[
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_select_ic",
        ],
    );
    let value = preflight
        .native_value()
        .expect("promotion path returns native value");
    assert_eq!(value.as_int(), Ok(42));
}

#[test]
fn jit_native_call_executes_select_literal_default_branch_with_one_context() {
    assert_select_literal_default_from_nested_attrset(
        "{ target = null; nested = { other = 7; }; }",
        99,
    );
}

#[test]
fn jit_native_call_executes_select_literal_default_present_branch_with_one_context() {
    assert_select_literal_default_from_nested_attrset(
        "{ target = null; nested = { target = 42; }; }",
        42,
    );
}

fn assert_select_literal_default_from_nested_attrset(source: &str, expected: i64) {
    let source_span = Span::new(0, source.len() as u32);
    let source_ir = lower_source(source);
    let target_symbol = symbol_for(&source_ir, b"target");
    let nested_symbol = symbol_for(&source_ir, b"nested");
    let lowered_ir = static_select_default_ir(0, source_ir.symbols.clone(), target_symbol, 99);
    let mut eval = TreeWalk::new(&source_ir);
    let root = eval.eval_root().expect("attrset evaluates");
    let root_attrs = eval
        .heap()
        .get_attrs(root)
        .expect("root attrset is heap-owned");
    let nested = root_attrs
        .get(nested_symbol)
        .expect("nested attrset exists");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, nested).expect("nested attrset capture stores");
    let candidates =
        runtime_wrapper_candidates(&["aos_env_get", "aos_force", "aos_has_attr", "aos_select_ic"]);
    let env_owned = EvalEnv::capture(&[frame]).expect("env captures");
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env(
        &mut eval,
        source_ir.root,
        source_span,
        &env_owned,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    // SAFETY: The runtime pointer comes from one pinned RuntimeJitContext shared
    // by the force and attr wrappers, the environment pointer comes from a live
    // EvalFrame, all registered candidates are process-local runtime-FFI
    // wrappers with the frozen host ABI, and the nested attrset value in the
    // frame belongs to the live evaluator.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &lowered_ir,
            lowered_ir.root,
            &candidates,
            rt,
            env,
        )
    }
    .expect("select literal default executes through JIT");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(preflight.slot().tier1_code_ptr().is_some());
    assert!(preflight.owns_encapsulated_module());
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    assert_eq!(
        invocation
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>(),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_has_attr",
            "aos_select_ic",
        ]
    );
    assert_imports_registered(
        invocation.finalization(),
        &[
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_has_attr",
            "aos_select_ic",
        ],
    );
    let value = preflight
        .native_value()
        .expect("promotion path returns native value");
    assert_eq!(value.as_int(), Ok(expected));
}

#[test]
fn jit_native_call_executes_update_runtime_ffi_wrapper_with_one_context() {
    let source = "{ left = { keep = 1; replace = 2; }; right = { replace = 42; add = 7; }; }";
    let source_span = Span::new(0, source.len() as u32);
    let source_ir = lower_source(source);
    let keep_symbol = symbol_for(&source_ir, b"keep");
    let replace_symbol = symbol_for(&source_ir, b"replace");
    let add_symbol = symbol_for(&source_ir, b"add");
    let lowered_ir = update_ir(0, 1);
    let mut eval = TreeWalk::new(&source_ir);
    let root = eval.eval_root().expect("attrset evaluates");
    let root_attrs = eval
        .heap()
        .get_attrs(root)
        .expect("root attrset is heap-owned");
    let left = root_attrs
        .get(symbol_for(&source_ir, b"left"))
        .expect("left exists");
    let right = root_attrs
        .get(symbol_for(&source_ir, b"right"))
        .expect("right exists");
    let frame = EvalFrame::new(2).expect("frame allocates");
    frame.set(0, left).expect("left attrset capture stores");
    frame.set(1, right).expect("right attrset capture stores");
    let candidates = runtime_wrapper_candidates(&["aos_env_get", "aos_force", "aos_update"]);
    let env_owned = EvalEnv::capture(&[frame]).expect("env captures");
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env(
        &mut eval,
        source_ir.root,
        source_span,
        &env_owned,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    // SAFETY: The runtime pointer comes from one pinned RuntimeJitContext shared
    // by the force and update wrappers, the environment pointer comes from a live
    // EvalFrame, all registered candidates are process-local runtime-FFI
    // wrappers with the frozen host ABI, and both attrset values in the frame
    // belong to the live evaluator.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &lowered_ir,
            lowered_ir.root,
            &candidates,
            rt,
            env,
        )
    }
    .expect("update runtime-FFI wrapper executes through JIT");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(preflight.slot().tier1_code_ptr().is_some());
    assert!(preflight.owns_encapsulated_module());
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    assert_eq!(
        invocation
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>(),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_update",
        ]
    );
    assert_imports_registered(
        invocation.finalization(),
        &[
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_update",
        ],
    );
    let value = preflight
        .native_value()
        .expect("promotion path returns native value");
    drop(context);
    let attrs = eval
        .heap()
        .get_attrs(value)
        .expect("update result is an attrset");
    assert_eq!(
        attrs.get(keep_symbol).expect("keep persists").as_int(),
        Ok(1)
    );
    assert_eq!(
        attrs
            .get(replace_symbol)
            .expect("replace is right-biased")
            .as_int(),
        Ok(42)
    );
    assert_eq!(
        attrs.get(add_symbol).expect("add is merged").as_int(),
        Ok(7)
    );
}

#[test]
fn jit_native_call_executes_apply_runtime_ffi_wrapper_with_one_context() {
    let source = "x: x + 1";
    let source_span = Span::new(0, source.len() as u32);
    let source_ir = lower_source(source);
    let lowered_ir = apply_ir(0, 1);
    let mut eval = TreeWalk::new(&source_ir);
    let function = eval.eval_root().expect("lambda evaluates");
    let frame = EvalFrame::new(2).expect("frame allocates");
    frame.set(0, function).expect("function capture stores");
    frame
        .set(1, Value::int(41))
        .expect("argument capture stores");
    let candidates = runtime_wrapper_candidates(&["aos_env_get", "aos_apply"]);
    let env_owned = EvalEnv::capture(&[frame]).expect("env captures");
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env(
        &mut eval,
        source_ir.root,
        source_span,
        &env_owned,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    // SAFETY: The runtime pointer comes from one pinned RuntimeJitContext used
    // by the apply wrapper, the environment pointer comes from a live EvalFrame,
    // both registered candidates are process-local runtime-FFI wrappers with the
    // frozen host ABI, and the lambda value in the frame belongs to the live
    // evaluator.
    let preflight = unsafe {
        jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &lowered_ir,
            lowered_ir.root,
            &candidates,
            rt,
            env,
        )
    }
    .expect("apply runtime-FFI wrapper executes through JIT");

    assert!(preflight.did_call_native_code());
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(preflight.slot().tier1_code_ptr().is_some());
    assert!(preflight.owns_encapsulated_module());
    let invocation = preflight
        .native_invocation()
        .expect("promoted preflight owns native invocation");
    assert_eq!(
        invocation
            .finalization()
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| artifact_import.symbol_name())
            .collect::<Vec<_>>(),
        ["aos_env_get", "aos_apply"]
    );
    assert_imports_registered(invocation.finalization(), &["aos_env_get", "aos_apply"]);
    assert!(
        invocation
            .finalization()
            .registered_symbol_for("aos_force")
            .is_none()
    );
    let value = preflight
        .native_value()
        .expect("promotion path returns native value");
    drop(context);
    let forced = rust_callable_aos_force(&mut eval, source_ir.root, source_span, value)
        .expect("JIT apply result forces");
    assert_eq!(forced.as_int(), Ok(42));
}

fn assert_imports_registered(
    finalization: &ratchet_jit::JitCraneliftRegisteredArtifactFinalizationPreflight,
    symbols: &[&str],
) {
    for symbol in symbols {
        assert!(
            finalization.imported_symbol_for(symbol).is_some(),
            "{symbol} must be imported by the finalized artifact"
        );
        assert!(
            finalization.registered_symbol_for(symbol).is_some(),
            "{symbol} must be registered from the runtime-FFI wrapper manifest"
        );
    }
}

fn apply_ir(function_slot: u32, argument_slot: u32) -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local {
                    slot: function_slot,
                },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local {
                    slot: argument_slot,
                },
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(2),
        arena,
        facts,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

fn static_select_ir(slot: u32, symbols: SymbolTable, symbol: Symbol) -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot },
            ),
            IrNode::new(
                IrKind::Select,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Select {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    default: None,
                    site: IrInlineCacheSiteId::new(13),
                },
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(1),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
            .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

fn static_select_default_ir(
    slot: u32,
    symbols: SymbolTable,
    symbol: Symbol,
    default_value: i64,
) -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot },
            ),
            IrNode::new(
                IrKind::Select,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Select {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    default: Some(IrId::new(2)),
                    site: IrInlineCacheSiteId::new(13),
                },
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(9, 11),
                EffectClass::pure(),
                IrData::Int(default_value),
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(1),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
            .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

fn update_ir(left_slot: u32, right_slot: u32) -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: left_slot },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local { slot: right_slot },
            ),
            IrNode::new(
                IrKind::BinOp,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Binary {
                    op: BinOpKind::Update,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(2),
        arena,
        facts,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

fn static_has_attr_ir(slot: u32, symbols: SymbolTable, symbol: Symbol) -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot },
            ),
            IrNode::new(
                IrKind::HasAttr,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::HasAttr {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    site: IrInlineCacheSiteId::new(11),
                },
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(1),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
            .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

fn symbol_for(ir: &Ir, name: &[u8]) -> Symbol {
    let index = ir
        .symbols
        .symbols()
        .iter()
        .position(|symbol| symbol.as_slice() == name)
        .expect("symbol exists in lowered source");
    Symbol::new(index as u32)
}

fn runtime_wrapper_candidates(symbols: &[&str]) -> Vec<JitRuntimeSymbolAddressCandidate> {
    let mut requested = symbols.iter().copied().collect::<BTreeSet<_>>();
    if requested.contains("aos_force") {
        requested.insert("aos_jit_stack_map_enter");
        requested.insert("aos_jit_stack_map_exit");
    }
    let mut candidates = runtime_native_wrapper_bindings()
        .expect("runtime wrapper manifest builds")
        .into_iter()
        .filter(|binding| requested.contains(binding.symbol_name()))
        .map(|binding| {
            let raw = NonZeroUsize::new(binding.address().as_ptr() as usize)
                .expect("runtime wrapper address is non-null");
            JitRuntimeSymbolAddressCandidate::new(
                binding.symbol_name().to_owned(),
                RuntimeSymbolKind::Helper(binding.role()),
                JitRuntimeSymbolAddress::new(raw),
            )
        })
        .collect::<Vec<_>>();
    for (symbol_name, address) in [
        (
            "aos_jit_stack_map_enter",
            aos_jit_stack_map_enter_native_wrapper_address(),
        ),
        (
            "aos_jit_stack_map_exit",
            aos_jit_stack_map_exit_native_wrapper_address(),
        ),
    ] {
        if requested.contains(symbol_name) {
            let raw =
                NonZeroUsize::new(address as usize).expect("stack-map wrapper address is non-null");
            candidates.push(JitRuntimeSymbolAddressCandidate::new(
                symbol_name.to_owned(),
                RuntimeSymbolKind::Helper(RuntimeHelperRole::SafepointControl),
                JitRuntimeSymbolAddress::new(raw),
            ));
        }
    }
    candidates.sort_by(|left, right| left.symbol_name().cmp(right.symbol_name()));
    assert_eq!(
        candidates.len(),
        requested.len(),
        "all requested runtime wrapper symbols must be present"
    );
    candidates
}

fn lower_source(source: &str) -> Ir {
    aos_nix_dialect::nix_lower(
        resolve(parse_str(source).expect("source parses")).expect("source resolves"),
    )
    .expect("source lowers")
}
