//! Unit tests for the tier-1 CLIF lowerer (moved from `lower.rs` verbatim).

use cranelift_codegen::ir::{
    ExtFuncData, ExternalName, FuncRef, InstructionData, Opcode, Type, types,
};
use ratchet_core::{
    BindingLowering, Cardinality, EffectClass, Escape, Ir, IrFacts, IrNode, Strictness,
    ThunkSharing, lower, resolve,
    syntax::{Span, SymbolTable, parse_str},
};
use ratchet_value::value::ValueTag;

use super::*;
use crate::abi::clif_signature_for_runtime_call;

mod stack_map_binding;

#[test]
fn constant_thunk_body_uses_frozen_thunk_signature() {
    let function =
        lower_constant_thunk_body(Value::null()).expect("constant null thunk body lowers");
    let expected_signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())
        .expect("thunk signature lowers");

    assert_eq!(function.name, UserFuncName::default());
    assert_eq!(function.signature, expected_signature);
    assert_eq!(
        entry_block_param_types(&function),
        param_types(&expected_signature)
    );
}

#[test]
fn ir_root_function_name_uses_reserved_namespace_and_root_index() {
    let name = clif_name_for_ir_root(IrId::new(42));
    let user_name = name
        .get_user()
        .expect("IR root CLIF names use user-function metadata");

    assert_eq!(user_name.namespace, AOS_IR_ROOT_FUNCTION_NAMESPACE);
    assert_eq!(user_name.index, 42);
}

#[test]
fn env_get_external_name_uses_reserved_namespace_and_index() {
    let name = clif_external_name_for_aos_env_get();

    assert_eq!(name.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
    assert_eq!(name.index, AOS_ENV_GET_FUNCTION_INDEX);
}

#[test]
fn force_external_name_uses_reserved_namespace_and_index() {
    let name = clif_external_name_for_aos_force();

    assert_eq!(name.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
    assert_eq!(name.index, AOS_FORCE_FUNCTION_INDEX);
}

#[test]
fn apply_external_name_uses_reserved_namespace_and_index() {
    let name = clif_external_name_for_aos_apply();

    assert_eq!(name.namespace, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE);
    assert_eq!(name.index, AOS_APPLY_FUNCTION_INDEX);
}

#[test]
fn tier1_thunk_fact_decision_maps_core_fact_lattice() {
    let cases = [
        (
            ExprFacts::conservative(),
            BindingLowering::Thunk,
            ThunkSharing::Update,
            JitTier1ThunkFactDecision::AllocateUpdatingThunk,
        ),
        (
            ExprFacts {
                strictness: Strictness::DemandedBeforeEffect,
                cardinality: Cardinality::Many,
                escape: Escape::Escapes,
            },
            BindingLowering::Eager,
            ThunkSharing::Update,
            JitTier1ThunkFactDecision::EvaluateEagerWhnf,
        ),
        // Demanded-but-not-before-effect fails closed: S1 alone never
        // licenses eager evaluation (S2 requires DemandedBeforeEffect).
        (
            ExprFacts {
                strictness: Strictness::Demanded,
                cardinality: Cardinality::Many,
                escape: Escape::Escapes,
            },
            BindingLowering::Thunk,
            ThunkSharing::Update,
            JitTier1ThunkFactDecision::AllocateUpdatingThunk,
        ),
        (
            ExprFacts {
                strictness: Strictness::Demanded,
                cardinality: Cardinality::Once,
                escape: Escape::NoEscape,
            },
            BindingLowering::Thunk,
            ThunkSharing::SingleEntry,
            JitTier1ThunkFactDecision::AllocateSingleEntryThunk,
        ),
        (
            ExprFacts {
                strictness: Strictness::Demanded,
                cardinality: Cardinality::Absent,
                escape: Escape::NoEscape,
            },
            BindingLowering::Thunk,
            ThunkSharing::Update,
            JitTier1ThunkFactDecision::AllocateUpdatingThunk,
        ),
        (
            ExprFacts {
                strictness: Strictness::DemandedBeforeEffect,
                cardinality: Cardinality::Many,
                escape: Escape::NoEscape,
            },
            BindingLowering::Scalar,
            ThunkSharing::Update,
            JitTier1ThunkFactDecision::EvaluateScalarValue,
        ),
        (
            ExprFacts {
                strictness: Strictness::DemandedBeforeEffect,
                cardinality: Cardinality::Absent,
                escape: Escape::NoEscape,
            },
            BindingLowering::Scalar,
            ThunkSharing::Update,
            JitTier1ThunkFactDecision::AllocateUpdatingThunk,
        ),
        (
            ExprFacts {
                strictness: Strictness::Unknown,
                cardinality: Cardinality::Once,
                escape: Escape::NoEscape,
            },
            BindingLowering::Thunk,
            ThunkSharing::SingleEntry,
            JitTier1ThunkFactDecision::AllocateSingleEntryThunk,
        ),
        (
            ExprFacts {
                strictness: Strictness::Unknown,
                cardinality: Cardinality::Absent,
                escape: Escape::Escapes,
            },
            BindingLowering::Thunk,
            ThunkSharing::Omit,
            JitTier1ThunkFactDecision::OmitLazyBinding,
        ),
    ];

    for (facts, expected_lowering, expected_sharing, expected_decision) in cases {
        assert_eq!(facts.binding_lowering(), expected_lowering);
        assert_eq!(facts.thunk_sharing(), expected_sharing);
        assert_eq!(
            jit_tier1_thunk_fact_decision_for_facts(facts),
            expected_decision
        );
    }
}

#[test]
fn tier1_thunk_fact_plan_reads_thunk_alloc_facts_without_lowering_clif() {
    let facts = ExprFacts {
        strictness: Strictness::Unknown,
        cardinality: Cardinality::Once,
        escape: Escape::NoEscape,
    };
    let ir = direct_thunk_ir_with_facts(facts);

    let plan = jit_tier1_thunk_fact_plan(&ir, IrId::new(1)).expect("thunk fact plan is built");

    assert_eq!(plan.thunk(), IrId::new(1));
    assert_eq!(plan.body(), IrId::new(0));
    assert_eq!(plan.facts(), facts);
    assert_eq!(plan.binding_lowering(), BindingLowering::Thunk);
    assert_eq!(plan.thunk_sharing(), ThunkSharing::SingleEntry);
    assert_eq!(
        plan.decision(),
        JitTier1ThunkFactDecision::AllocateSingleEntryThunk
    );
}

#[test]
fn tier1_thunk_fact_plan_preserves_absent_strict_contradiction_guard() {
    let facts = ExprFacts {
        strictness: Strictness::DemandedBeforeEffect,
        cardinality: Cardinality::Absent,
        escape: Escape::NoEscape,
    };
    let ir = direct_thunk_ir_with_facts(facts);

    let plan = jit_tier1_thunk_fact_plan(&ir, IrId::new(1)).expect("thunk fact plan is built");

    assert_eq!(plan.binding_lowering(), BindingLowering::Scalar);
    assert_eq!(plan.thunk_sharing(), ThunkSharing::Update);
    assert_eq!(
        plan.decision(),
        JitTier1ThunkFactDecision::AllocateUpdatingThunk
    );
}

#[test]
fn tier1_thunk_fact_plan_rejects_malformed_thunk_nodes() {
    let missing_root_ir = minimal_ir(IrId::new(0), IrArena::new());
    let non_thunk_ir = minimal_ir(
        IrId::new(0),
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            )],
            Vec::new(),
        ),
    );
    let missing_body_ir = minimal_ir(
        IrId::new(0),
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(9)),
            )],
            Vec::new(),
        ),
    );
    let malformed_payload_ir = minimal_ir(
        IrId::new(0),
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        ),
    );
    let self_referential_ir = minimal_ir(
        IrId::new(0),
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            )],
            Vec::new(),
        ),
    );

    let missing_root_error = jit_tier1_thunk_fact_plan(&missing_root_ir, IrId::new(7))
        .expect_err("missing thunk node is rejected");
    let non_thunk_error = jit_tier1_thunk_fact_plan(&non_thunk_ir, IrId::new(0))
        .expect_err("non-thunk root is rejected");
    let missing_body_error = jit_tier1_thunk_fact_plan(&missing_body_ir, IrId::new(0))
        .expect_err("missing thunk body is rejected");
    let malformed_payload_error = jit_tier1_thunk_fact_plan(&malformed_payload_ir, IrId::new(0))
        .expect_err("malformed thunk payload is rejected");
    let self_referential_error = jit_tier1_thunk_fact_plan(&self_referential_ir, IrId::new(0))
        .expect_err("self-referential thunk body is rejected");

    assert!(
        matches!(missing_root_error, JitLowerError::MissingIrNode { root } if root == IrId::new(7))
    );
    assert!(matches!(
        non_thunk_error,
        JitLowerError::UnsupportedThunkFactNode {
            id,
            kind: IrKind::Int,
        } if id == IrId::new(0)
    ));
    assert!(
        matches!(missing_body_error, JitLowerError::MissingIrBody { body } if body == IrId::new(9))
    );
    assert!(matches!(
        malformed_payload_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data: IrData::None,
            expected: "body node",
        }
    ));
    assert!(matches!(
        self_referential_error,
        JitLowerError::SelfReferentialThunkBody { thunk } if thunk == IrId::new(0)
    ));
}

#[test]
fn tier1_thunk_fact_plan_rejects_fact_table_node_count_mismatch() {
    let arena = direct_thunk_arena();
    let mut facts = IrFacts::conservative(3);
    *facts
        .get_mut(IrId::new(1))
        .expect("overlong fixture still has a thunk fact slot") = ExprFacts {
        strictness: Strictness::DemandedBeforeEffect,
        cardinality: Cardinality::Many,
        escape: Escape::NoEscape,
    };
    let ir = Ir {
        root: IrId::new(1),
        arena,
        facts,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    };

    let error = jit_tier1_thunk_fact_plan(&ir, IrId::new(1))
        .expect_err("fact table length mismatch is rejected");

    assert!(matches!(
        error,
        JitLowerError::MismatchedIrFactTable {
            node_count: 2,
            fact_count: 3,
        }
    ));
}

#[test]
fn constant_thunk_body_artifact_records_smoke_metadata() {
    let artifact = lower_constant_thunk_body_artifact(Value::bool(false))
        .expect("constant bool thunk artifact lowers");

    assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
    assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
    assert_eq!(artifact.source(), JitClifArtifactSource::ConstantSmoke);
    assert_eq!(artifact.function_name(), &UserFuncName::default());
    assert_eq!(
        iconst_words(artifact.function()),
        vec![ValueTag::Bool as u64, Value::bool(false).payload_bits()]
    );

    let function = artifact.into_function();
    assert_eq!(function.name, UserFuncName::default());
}

#[test]
fn constant_thunk_body_returns_int_value_words() {
    let function =
        lower_constant_thunk_body(Value::int(-7)).expect("constant int thunk body lowers");

    assert_eq!(
        iconst_words(&function),
        vec![ValueTag::Int as u64, Value::int(-7).payload_bits()]
    );
}

#[test]
fn constant_thunk_body_returns_bool_and_null_value_words() {
    let bool_function =
        lower_constant_thunk_body(Value::bool(true)).expect("constant bool thunk body lowers");
    let null_function =
        lower_constant_thunk_body(Value::null()).expect("constant null thunk body lowers");

    assert_eq!(
        iconst_words(&bool_function),
        vec![ValueTag::Bool as u64, Value::bool(true).payload_bits()]
    );
    assert_eq!(
        iconst_words(&null_function),
        vec![ValueTag::Null as u64, Value::null().payload_bits()]
    );
}

#[test]
fn constant_thunk_body_is_verified_clif_without_jit_module() {
    let function =
        lower_constant_thunk_body(Value::float(-13.25)).expect("constant float thunk body lowers");

    let emitted_constants = iconst_values(&function)
        .into_iter()
        .map(|(value, _word)| value)
        .collect::<Vec<_>>();
    assert_eq!(return_operands(&function), emitted_constants);
    assert_eq!(opcodes(&function).last(), Some(&Opcode::Return));
    verify_clif_function(&function).expect("lowered function verifies independently");
}

#[test]
fn constant_ir_thunk_body_lowers_supported_literal_roots() {
    let cases = [
        (
            IrNode::new(
                IrKind::Int,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Int(-9),
            ),
            Value::int(-9),
        ),
        (
            IrNode::new(
                IrKind::Float,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Float(2.5),
            ),
            Value::float(2.5),
        ),
        (
            IrNode::new(
                IrKind::Bool,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Bool(false),
            ),
            Value::bool(false),
        ),
        (
            IrNode::new(
                IrKind::Null,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::None,
            ),
            Value::null(),
        ),
    ];

    for (node, expected_value) in cases {
        let arena = IrArena::from_raw_parts(vec![node], Vec::new());
        let function =
            lower_constant_ir_thunk_body(&arena, IrId::new(0)).expect("literal IR root lowers");

        assert_eq!(
            iconst_words(&function),
            vec![expected_value.tag() as u64, expected_value.payload_bits()]
        );
    }
}

#[test]
fn constant_ir_thunk_body_lowers_direct_literal_thunk_alloc_root() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(4, 6),
                EffectClass::pure(),
                IrData::Int(17),
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let function = lower_constant_ir_thunk_body(&arena, IrId::new(1))
        .expect("direct literal thunk allocation lowers");

    assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
    assert_eq!(
        iconst_words(&function),
        vec![ValueTag::Int as u64, Value::int(17).payload_bits()]
    );
}

#[test]
fn constant_ir_thunk_body_artifact_records_root_source() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(4, 6),
                EffectClass::pure(),
                IrData::Int(23),
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(1))
        .expect("direct literal thunk allocation artifact lowers");

    assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
    assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
    assert_eq!(
        artifact.source(),
        JitClifArtifactSource::IrRoot(IrId::new(1))
    );
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(1))
    );
    assert_eq!(
        iconst_words(artifact.function()),
        vec![ValueTag::Int as u64, Value::int(23).payload_bits()]
    );
}

#[test]
fn constant_ir_thunk_body_rejects_missing_root() {
    let arena = IrArena::new();

    let error =
        lower_constant_ir_thunk_body(&arena, IrId::new(7)).expect_err("missing root is rejected");

    assert!(matches!(error, JitLowerError::MissingIrNode { root } if root == IrId::new(7)));
}

#[test]
fn constant_ir_thunk_body_rejects_unsupported_root_kind() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("string root is not covered by the constant lowerer");

    assert!(matches!(error, JitLowerError::UnsupportedIrRoot { kind } if kind == IrKind::Str));
}

#[test]
fn constant_ir_thunk_body_rejects_mismatched_literal_payload() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("int root without int payload is malformed");

    assert!(matches!(
        error,
        JitLowerError::MismatchedConstantData {
            kind: IrKind::Int,
            data: IrData::None,
        }
    ));
}

#[test]
fn constant_ir_thunk_body_rejects_missing_thunk_body() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 6),
            EffectClass::pure(),
            IrData::Node(IrId::new(9)),
        )],
        Vec::new(),
    );

    let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("missing thunk body is rejected");

    assert!(matches!(error, JitLowerError::MissingIrBody { body } if body == IrId::new(9)));
}

#[test]
fn constant_ir_thunk_body_rejects_unsupported_thunk_body_kind() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Str,
                Span::new(4, 9),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 9),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let error = lower_constant_ir_thunk_body(&arena, IrId::new(1))
        .expect_err("unsupported thunk body kind is rejected");

    assert!(matches!(error, JitLowerError::UnsupportedIrBody { kind } if kind == IrKind::Str));
}

#[test]
fn constant_ir_thunk_body_rejects_mismatched_thunk_body_payload() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(4, 9),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 9),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let error = lower_constant_ir_thunk_body(&arena, IrId::new(1))
        .expect_err("mismatched thunk body payload is rejected");

    assert!(matches!(
        error,
        JitLowerError::MismatchedBodyConstantData {
            kind: IrKind::Int,
            data: IrData::None,
        }
    ));
}

#[test]
fn constant_ir_thunk_body_rejects_malformed_thunk_alloc_payload() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 6),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("thunk allocation without body node is malformed");

    assert!(matches!(
        error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data: IrData::None,
            expected: "body node",
        }
    ));
}

#[test]
fn constant_ir_root_thunk_body_lowers_real_literal_ir_artifacts() {
    let cases = [
        ("42", Value::int(42)),
        ("2.5", Value::float(2.5)),
        ("false", Value::bool(false)),
        ("null", Value::null()),
    ];

    for (source, expected_value) in cases {
        let ir = lowered_ir(source);
        let function = lower_constant_ir_root_thunk_body(&ir).expect("literal IR artifact lowers");

        assert_eq!(
            iconst_words(&function),
            vec![expected_value.tag() as u64, expected_value.payload_bits()]
        );
    }
}

#[test]
fn constant_ir_root_thunk_body_uses_nonzero_artifact_root() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Str,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(7, 9),
                EffectClass::pure(),
                IrData::Int(11),
            ),
        ],
        Vec::new(),
    );
    let ir = minimal_ir(IrId::new(1), arena);

    let function = lower_constant_ir_root_thunk_body(&ir).expect("nonzero literal root lowers");

    assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
    assert_eq!(
        iconst_words(&function),
        vec![ValueTag::Int as u64, Value::int(11).payload_bits()]
    );
}

#[test]
fn constant_ir_root_thunk_body_artifact_records_nonzero_artifact_root() {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Str,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(7, 9),
                EffectClass::pure(),
                IrData::Int(13),
            ),
        ],
        Vec::new(),
    );
    let ir = minimal_ir(IrId::new(1), arena);

    let artifact =
        lower_constant_ir_root_thunk_body_artifact(&ir).expect("IR root artifact lowers");

    assert_eq!(
        artifact.source(),
        JitClifArtifactSource::IrRoot(IrId::new(1))
    );
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(1))
    );
    assert_eq!(
        iconst_words(artifact.function()),
        vec![ValueTag::Int as u64, Value::int(13).payload_bits()]
    );
}

#[test]
fn constant_ir_root_thunk_body_rejects_missing_artifact_root() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )],
        Vec::new(),
    );
    let ir = minimal_ir(IrId::new(5), arena);

    let error =
        lower_constant_ir_root_thunk_body(&ir).expect_err("missing artifact root is rejected");

    assert!(matches!(error, JitLowerError::MissingIrNode { root } if root == IrId::new(5)));
}

#[test]
fn env_get_ir_thunk_body_imports_env_helper_signature() {
    let arena = IrArena::from_raw_parts(vec![local_var_node(3)], Vec::new());

    let function =
        lower_env_get_ir_thunk_body(&arena, IrId::new(0)).expect("local var root lowers");
    let (_func_ref, import) = single_imported_function(&function);
    let expected_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature(AOS_ENV_GET_SYMBOL)
            .expect("env-get helper signature is core-owned"),
    )
    .expect("env-get signature lowers to CLIF");

    assert_eq!(function.name, clif_name_for_ir_root(IrId::new(0)));
    assert_eq!(
        imported_user_external_name(&function, import),
        clif_external_name_for_aos_env_get()
    );
    assert_eq!(
        function.dfg.signatures[import.signature],
        expected_signature
    );
    assert!(!import.colocated);
}

#[test]
fn env_get_ir_thunk_body_calls_env_helper_with_entry_env_and_slot() {
    let arena = IrArena::from_raw_parts(vec![local_var_node(5)], Vec::new());

    let function =
        lower_env_get_ir_thunk_body(&arena, IrId::new(0)).expect("local var root lowers");
    let (env_get, _import) = single_imported_function(&function);
    let call = single_call_inst(&function);
    let InstructionData::Call { func_ref, .. } = function.dfg.insts[call] else {
        panic!("lowered env-get function emits a direct call");
    };

    assert_eq!(func_ref, env_get);
    assert_eq!(
        opcodes(&function),
        vec![Opcode::Iconst, Opcode::Call, Opcode::Return]
    );
    assert_eq!(
        function.dfg.inst_args(call)[0],
        entry_block_values(&function)[1]
    );
    assert_eq!(
        function.dfg.value_type(function.dfg.inst_args(call)[1]),
        types::I32
    );
    assert_eq!(iconst_words(&function), vec![5]);
    assert_eq!(return_operands(&function), function.dfg.inst_results(call));
    verify_clif_function(&function).expect("env-get function verifies independently");
}

#[test]
fn env_get_ir_thunk_body_lowers_direct_local_thunk_alloc_root() {
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(7),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let artifact = lower_env_get_ir_thunk_body_artifact(&arena, IrId::new(1))
        .expect("direct local thunk allocation lowers");

    assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
    assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
    assert_eq!(
        artifact.source(),
        JitClifArtifactSource::IrRoot(IrId::new(1))
    );
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(1))
    );
    assert_eq!(iconst_words(artifact.function()), vec![7]);
}

#[test]
fn env_get_ir_thunk_body_rejects_mismatched_local_payload() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let error = lower_env_get_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("local var without local payload is malformed");

    assert!(matches!(
        error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data: IrData::None,
            expected: "local slot payload",
        }
    ));
}

#[test]
fn env_get_ir_thunk_body_rejects_unsupported_roots_and_bodies() {
    let root_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )],
        Vec::new(),
    );
    let body_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(1, 2),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let root_error = lower_env_get_ir_thunk_body(&root_arena, IrId::new(0))
        .expect_err("non-local root is not covered by env-get lowering");
    let body_error = lower_env_get_ir_thunk_body(&body_arena, IrId::new(1))
        .expect_err("non-local thunk body is not covered by env-get lowering");

    assert!(
        matches!(root_error, JitLowerError::UnsupportedEnvRoot { kind } if kind == IrKind::Int)
    );
    assert!(
        matches!(body_error, JitLowerError::UnsupportedEnvBody { kind } if kind == IrKind::Int)
    );
}

#[test]
fn env_get_ir_thunk_body_rejects_missing_thunk_body() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Node(IrId::new(9)),
        )],
        Vec::new(),
    );

    let error = lower_env_get_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("missing local thunk body is rejected");

    assert!(matches!(error, JitLowerError::MissingIrBody { body } if body == IrId::new(9)));
}

#[test]
fn env_get_ir_thunk_body_rejects_malformed_thunk_alloc_payload() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let error = lower_env_get_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("local thunk allocation without body node is malformed");

    assert!(matches!(
        error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data: IrData::None,
            expected: "body node",
        }
    ));
}

#[test]
fn forced_env_get_ir_thunk_body_imports_env_get_and_force_signatures() {
    let arena = IrArena::from_raw_parts(vec![local_var_node(11)], Vec::new());

    let function = lower_forced_env_get_ir_thunk_body(&arena, IrId::new(0))
        .expect("forced local var root lowers");
    let env_get_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let force_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    let expected_env_get_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature(AOS_ENV_GET_SYMBOL)
            .expect("env-get helper signature is core-owned"),
    )
    .expect("env-get signature lowers to CLIF");
    let expected_force_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature(AOS_FORCE_SYMBOL)
            .expect("force helper signature is core-owned"),
    )
    .expect("force signature lowers to CLIF");

    assert_eq!(
        function.dfg.signatures[env_get_import.1.signature],
        expected_env_get_signature
    );
    assert_eq!(
        function.dfg.signatures[force_import.1.signature],
        expected_force_signature
    );
}

#[test]
fn forced_env_get_ir_thunk_body_lowers_direct_local_thunk_alloc_root() {
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(17),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let artifact = lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(1))
        .expect("direct forced local thunk allocation lowers");

    assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
    assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
    assert_eq!(
        artifact.source(),
        JitClifArtifactSource::IrRoot(IrId::new(1))
    );
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(1))
    );
    assert_eq!(
        artifact.function().dfg.ext_funcs.len(),
        4,
        "forced env-get artifacts import env-get, force, and stack-map brackets"
    );
}

#[test]
fn apply_local_slots_ir_thunk_body_imports_env_get_and_apply_signatures() {
    let arena = apply_local_slots_arena(2, 5);

    let function = lower_apply_local_slots_ir_thunk_body(&arena, IrId::new(2))
        .expect("direct local-slot apply lowers");
    let env_get_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let apply_import =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_apply());
    let expected_env_get_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature(AOS_ENV_GET_SYMBOL)
            .expect("env-get helper signature is core-owned"),
    )
    .expect("env-get signature lowers to CLIF");
    let expected_apply_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature(AOS_APPLY_SYMBOL)
            .expect("apply helper signature is core-owned"),
    )
    .expect("apply signature lowers to CLIF");

    assert_eq!(
        function.dfg.signatures[env_get_import.1.signature],
        expected_env_get_signature
    );
    assert_eq!(
        function.dfg.signatures[apply_import.1.signature],
        expected_apply_signature
    );
}

#[test]
fn apply_local_slots_ir_thunk_body_reads_function_and_argument_then_calls_apply() {
    let arena = apply_local_slots_arena(3, 8);

    let function = lower_apply_local_slots_ir_thunk_body(&arena, IrId::new(2))
        .expect("direct local-slot apply lowers");
    let (env_get, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    let (apply, _) =
        imported_function_by_user_external_name(&function, clif_external_name_for_aos_apply());
    let calls = call_insts(&function);
    assert_eq!(calls.len(), 3);
    let function_env_get_call = calls[0];
    let argument_env_get_call = calls[1];
    let apply_call = calls[2];
    let InstructionData::Call { func_ref, .. } = function.dfg.insts[function_env_get_call] else {
        panic!("apply lowerer emits function env-get call first");
    };
    assert_eq!(func_ref, env_get);
    let InstructionData::Call { func_ref, .. } = function.dfg.insts[argument_env_get_call] else {
        panic!("apply lowerer emits argument env-get call second");
    };
    assert_eq!(func_ref, env_get);
    let InstructionData::Call { func_ref, .. } = function.dfg.insts[apply_call] else {
        panic!("apply lowerer emits apply call third");
    };
    assert_eq!(func_ref, apply);

    assert_eq!(
        opcodes(&function),
        vec![
            Opcode::Iconst,
            Opcode::Call,
            Opcode::Iconst,
            Opcode::Call,
            Opcode::Call,
            Opcode::Return,
        ]
    );
    assert_eq!(iconst_words(&function), vec![3, 8]);
    assert_eq!(
        function.dfg.inst_args(function_env_get_call)[0],
        entry_block_values(&function)[1]
    );
    assert_eq!(
        function.dfg.inst_args(argument_env_get_call)[0],
        entry_block_values(&function)[1]
    );
    assert_eq!(
        function
            .dfg
            .value_type(function.dfg.inst_args(function_env_get_call)[1]),
        types::I32
    );
    assert_eq!(
        function
            .dfg
            .value_type(function.dfg.inst_args(argument_env_get_call)[1]),
        types::I32
    );
    assert_eq!(
        function.dfg.inst_args(apply_call),
        &[
            entry_block_values(&function)[0],
            function.dfg.inst_results(function_env_get_call)[0],
            function.dfg.inst_results(function_env_get_call)[1],
            function.dfg.inst_results(argument_env_get_call)[0],
            function.dfg.inst_results(argument_env_get_call)[1],
        ]
    );
    assert_eq!(
        return_operands(&function),
        function.dfg.inst_results(apply_call)
    );
    verify_clif_function(&function).expect("apply function verifies independently");
}

#[test]
fn apply_local_slots_ir_thunk_body_lowers_direct_apply_thunk_alloc_root() {
    let arena = apply_local_slots_thunk_arena(13, 21);

    let artifact = lower_apply_local_slots_ir_thunk_body_artifact(&arena, IrId::new(3))
        .expect("direct apply thunk allocation lowers");

    assert_eq!(artifact.tier(), JitTier::Tier1Baseline);
    assert_eq!(artifact.kind(), JitClifArtifactKind::ThunkBody);
    assert_eq!(
        artifact.source(),
        JitClifArtifactSource::IrRoot(IrId::new(3))
    );
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(3))
    );
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_apply(),
    );
    assert_eq!(iconst_words(artifact.function()), vec![13, 21]);
}

#[test]
fn apply_local_slots_ir_thunk_body_rejects_unsupported_roots_and_bodies() {
    let root_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )],
        Vec::new(),
    );
    let body_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(1, 2),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let root_error = lower_apply_local_slots_ir_thunk_body(&root_arena, IrId::new(0))
        .expect_err("non-apply root is not covered by apply lowering");
    let body_error = lower_apply_local_slots_ir_thunk_body(&body_arena, IrId::new(1))
        .expect_err("non-apply thunk body is not covered by apply lowering");

    assert!(
        matches!(root_error, JitLowerError::UnsupportedApplyRoot { kind } if kind == IrKind::Int)
    );
    assert!(
        matches!(body_error, JitLowerError::UnsupportedApplyBody { kind } if kind == IrKind::Int)
    );
}

#[test]
fn apply_local_slots_ir_thunk_body_rejects_malformed_wrappers() {
    let missing_body_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Node(IrId::new(9)),
        )],
        Vec::new(),
    );
    let malformed_wrapper_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let missing_body_error =
        lower_apply_local_slots_ir_thunk_body(&missing_body_arena, IrId::new(0))
            .expect_err("missing apply thunk body is rejected");
    let malformed_wrapper_error =
        lower_apply_local_slots_ir_thunk_body(&malformed_wrapper_arena, IrId::new(0))
            .expect_err("apply thunk allocation without body node is malformed");

    assert!(
        matches!(missing_body_error, JitLowerError::MissingIrBody { body } if body == IrId::new(9))
    );
    assert!(matches!(
        malformed_wrapper_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data: IrData::None,
            expected: "body node",
        }
    ));
}

#[test]
fn apply_local_slots_ir_thunk_body_rejects_malformed_apply_payloads_and_children() {
    let malformed_payload_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Apply,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let missing_child_arena = IrArena::from_raw_parts(
        vec![
            local_var_node(1),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(9),
                },
            ),
        ],
        Vec::new(),
    );
    let unsupported_child_arena = IrArena::from_raw_parts(
        vec![
            local_var_node(1),
            IrNode::new(
                IrKind::Int,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Int(2),
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
    let malformed_child_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::None,
            ),
            local_var_node(2),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );

    let malformed_payload_error =
        lower_apply_local_slots_ir_thunk_body(&malformed_payload_arena, IrId::new(0))
            .expect_err("apply without pair payload is rejected");
    let missing_child_error =
        lower_apply_local_slots_ir_thunk_body(&missing_child_arena, IrId::new(1))
            .expect_err("apply with missing child is rejected");
    let unsupported_child_error =
        lower_apply_local_slots_ir_thunk_body(&unsupported_child_arena, IrId::new(2))
            .expect_err("apply with non-local child is rejected");
    let malformed_child_error =
        lower_apply_local_slots_ir_thunk_body(&malformed_child_arena, IrId::new(2))
            .expect_err("apply with malformed local child is rejected");

    assert!(matches!(
        malformed_payload_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::Apply,
            data: IrData::None,
            expected: "application pair payload",
        }
    ));
    assert!(
        matches!(missing_child_error, JitLowerError::MissingApplyChild { child } if child == IrId::new(9))
    );
    assert!(matches!(
        unsupported_child_error,
        JitLowerError::UnsupportedApplyChild {
            child,
            kind: IrKind::Int,
        } if child == IrId::new(1)
    ));
    assert!(matches!(
        malformed_child_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data: IrData::None,
            expected: "local slot payload",
        }
    ));
}

#[test]
fn tier1_ir_thunk_body_artifact_selects_literal_and_env_get_paths() {
    let literal_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(true),
        )],
        Vec::new(),
    );
    let literal_artifact = lower_tier1_ir_thunk_body_artifact(&literal_arena, IrId::new(0))
        .expect("tier-1 selector lowers literal root");

    assert_eq!(
        iconst_words(literal_artifact.function()),
        vec![ValueTag::Bool as u64, Value::bool(true).payload_bits()]
    );
    assert!(literal_artifact.function().dfg.ext_funcs.is_empty());

    let local_arena = IrArena::from_raw_parts(vec![local_var_node(19)], Vec::new());
    let local_artifact = lower_tier1_ir_thunk_body_artifact(&local_arena, IrId::new(0))
        .expect("tier-1 selector lowers local root through env-get");

    assert_eq!(local_artifact.function().dfg.ext_funcs.len(), 1);
    imported_function_by_user_external_name(
        local_artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    assert_eq!(iconst_words(local_artifact.function()), vec![19]);
}

#[test]
fn tier1_ir_thunk_body_lowers_wrapped_local_body() {
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(23),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let function = lower_tier1_ir_thunk_body(&arena, IrId::new(1))
        .expect("tier-1 selector lowers wrapped local root");

    assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
    assert_eq!(function.dfg.ext_funcs.len(), 1);
    imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    assert_eq!(iconst_words(&function), vec![23]);
}

#[test]
fn tier1_ir_thunk_body_artifact_selects_apply_path() {
    let arena = apply_local_slots_arena(41, 43);

    let artifact = lower_tier1_ir_thunk_body_artifact(&arena, IrId::new(2))
        .expect("tier-1 selector lowers local-slot apply");

    assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_apply(),
    );
    assert_eq!(iconst_words(artifact.function()), vec![41, 43]);
}

#[test]
fn tier1_ir_thunk_body_artifact_selects_wrapped_apply_path() {
    let arena = apply_local_slots_thunk_arena(44, 45);

    let artifact = lower_tier1_ir_thunk_body_artifact(&arena, IrId::new(3))
        .expect("tier-1 selector lowers wrapped local-slot apply");

    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(3))
    );
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_apply(),
    );
    assert_eq!(iconst_words(artifact.function()), vec![44, 45]);
}

#[test]
fn force_aware_tier1_ir_thunk_body_artifact_preserves_literals_and_forces_local_slots() {
    let literal_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 2),
            EffectClass::pure(),
            IrData::Int(29),
        )],
        Vec::new(),
    );
    let literal_artifact =
        lower_force_aware_tier1_ir_thunk_body_artifact(&literal_arena, IrId::new(0))
            .expect("force-aware selector preserves literal lowering");

    assert_eq!(
        iconst_words(literal_artifact.function()),
        vec![ValueTag::Int as u64, Value::int(29).payload_bits()]
    );
    assert!(literal_artifact.function().dfg.ext_funcs.is_empty());

    let local_arena = IrArena::from_raw_parts(vec![local_var_node(31)], Vec::new());
    let local_artifact = lower_force_aware_tier1_ir_thunk_body_artifact(&local_arena, IrId::new(0))
        .expect("force-aware selector lowers local root through env-get and force");

    assert_eq!(local_artifact.function().dfg.ext_funcs.len(), 4);
    imported_function_by_user_external_name(
        local_artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        local_artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        local_artifact.function(),
        clif_external_name_for_aos_jit_stack_map_enter(),
    );
    imported_function_by_user_external_name(
        local_artifact.function(),
        clif_external_name_for_aos_jit_stack_map_exit(),
    );
    assert_eq!(iconst_words(local_artifact.function()), vec![31, 0, 1]);
}

#[test]
fn force_aware_tier1_ir_thunk_body_artifact_selects_apply_without_extra_force() {
    let arena = apply_local_slots_arena(47, 53);

    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact(&arena, IrId::new(2))
        .expect("force-aware selector lowers local-slot apply through apply helper");

    assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_apply(),
    );
    assert_eq!(iconst_words(artifact.function()), vec![47, 53]);
}

#[test]
fn force_aware_tier1_ir_thunk_body_artifact_selects_wrapped_apply_without_extra_force() {
    let arena = apply_local_slots_thunk_arena(54, 55);

    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact(&arena, IrId::new(3))
        .expect("force-aware selector lowers wrapped local-slot apply through apply helper");

    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(3))
    );
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 2);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_apply(),
    );
    assert_eq!(iconst_words(artifact.function()), vec![54, 55]);
}

#[test]
fn full_ir_tier1_selectors_accept_static_select_roots() {
    let ir = static_select_ir(61);

    let Err(arena_only_error) = lower_force_aware_tier1_ir_thunk_body_artifact(&ir.arena, ir.root)
    else {
        panic!("arena-only force-aware selector should reject select roots");
    };
    assert!(matches!(
        arena_only_error,
        JitLowerError::UnsupportedIrRoot {
            kind: IrKind::Select
        } | JitLowerError::UnsupportedIrBody {
            kind: IrKind::Select
        }
    ));

    let artifact = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR selector lowers static select root");
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 5);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_select_ic(),
    );

    let force_aware_artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR force-aware selector lowers static select root");
    assert_eq!(
        force_aware_artifact.function().dfg.ext_funcs.len(),
        artifact.function().dfg.ext_funcs.len()
    );
    imported_function_by_user_external_name(
        force_aware_artifact.function(),
        clif_external_name_for_aos_select_ic(),
    );
}

#[test]
fn full_ir_tier1_selectors_accept_static_select_literal_defaults() {
    let ir = static_select_default_ir(66, IrId::new(2), vec![literal_int_node(99)]);

    let artifact = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR selector lowers static select root with literal default");
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 6);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_has_attr(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_select_ic(),
    );
    assert!(all_iconst_words(artifact.function()).contains(&(ValueTag::Int as u64)));
    assert!(all_iconst_words(artifact.function()).contains(&Value::int(99).payload_bits()));

    let wrapped_default_ir = static_select_default_ir(
        67,
        IrId::new(3),
        vec![
            literal_int_node(99),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(12, 14),
                EffectClass::pure(),
                IrData::Node(IrId::new(2)),
            ),
        ],
    );
    let force_aware_artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(
        &wrapped_default_ir,
        wrapped_default_ir.root,
    )
    .expect("force-aware full-IR selector lowers select with wrapped literal default");
    assert_eq!(force_aware_artifact.function().dfg.ext_funcs.len(), 6);
    imported_function_by_user_external_name(
        force_aware_artifact.function(),
        clif_external_name_for_aos_has_attr(),
    );
    imported_function_by_user_external_name(
        force_aware_artifact.function(),
        clif_external_name_for_aos_select_ic(),
    );
    assert!(
        all_iconst_words(force_aware_artifact.function()).contains(&Value::int(99).payload_bits())
    );
}

#[test]
fn full_ir_tier1_selectors_reject_non_literal_select_defaults() {
    let ir = static_select_default_ir(68, IrId::new(2), vec![local_var_node(69)]);

    let Err(error) = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root) else {
        panic!("non-literal select default is outside the bounded lowerer");
    };

    assert!(matches!(
        error,
        JitLowerError::UnsupportedSelectDefault { default } if default == IrId::new(2)
    ));
}

#[test]
fn full_ir_tier1_selectors_accept_static_has_attr_roots() {
    let ir = static_has_attr_ir(63);

    let Err(arena_only_error) = lower_force_aware_tier1_ir_thunk_body_artifact(&ir.arena, ir.root)
    else {
        panic!("arena-only force-aware selector should reject hasAttr roots");
    };
    assert!(matches!(
        arena_only_error,
        JitLowerError::UnsupportedIrRoot {
            kind: IrKind::HasAttr
        } | JitLowerError::UnsupportedIrBody {
            kind: IrKind::HasAttr
        }
    ));

    let artifact = lower_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR selector lowers static hasAttr root");
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 5);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_has_attr(),
    );

    let force_aware_artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR force-aware selector lowers static hasAttr root");
    assert_eq!(
        force_aware_artifact.function().dfg.ext_funcs.len(),
        artifact.function().dfg.ext_funcs.len()
    );
    imported_function_by_user_external_name(
        force_aware_artifact.function(),
        clif_external_name_for_aos_has_attr(),
    );
}

#[test]
fn full_ir_tier1_selectors_accept_wrapped_static_select_roots() {
    let ir = wrapped_static_select_ir(62);

    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR force-aware selector lowers wrapped static select root");
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(2))
    );
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 5);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_select_ic(),
    );
}

#[test]
fn full_ir_tier1_selectors_accept_wrapped_static_has_attr_roots() {
    let ir = wrapped_static_has_attr_ir(64);

    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(&ir, ir.root)
        .expect("full-IR force-aware selector lowers wrapped static hasAttr root");
    assert_eq!(
        artifact.function_name(),
        &clif_name_for_ir_root(IrId::new(2))
    );
    assert_eq!(artifact.function().dfg.ext_funcs.len(), 5);
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_env_get(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_force(),
    );
    imported_function_by_user_external_name(
        artifact.function(),
        clif_external_name_for_aos_has_attr(),
    );
}

#[test]
fn force_aware_tier1_ir_thunk_body_lowers_wrapped_local_body() {
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(37),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let function = lower_force_aware_tier1_ir_thunk_body(&arena, IrId::new(1))
        .expect("force-aware selector lowers wrapped local root");

    assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
    assert_eq!(function.dfg.ext_funcs.len(), 4);
    imported_function_by_user_external_name(&function, clif_external_name_for_aos_env_get());
    imported_function_by_user_external_name(&function, clif_external_name_for_aos_force());
    imported_function_by_user_external_name(
        &function,
        clif_external_name_for_aos_jit_stack_map_enter(),
    );
    imported_function_by_user_external_name(
        &function,
        clif_external_name_for_aos_jit_stack_map_exit(),
    );
    assert_eq!(iconst_words(&function), vec![37, 0, 1]);
}

#[test]
fn tier1_ir_thunk_body_artifact_reports_unsupported_selector_shapes() {
    let root_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let body_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Str,
                Span::new(1, 6),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let Err(root_error) = lower_tier1_ir_thunk_body_artifact(&root_arena, IrId::new(0)) else {
        panic!("unsupported direct root is rejected");
    };
    let Err(body_error) = lower_force_aware_tier1_ir_thunk_body_artifact(&body_arena, IrId::new(1))
    else {
        panic!("unsupported wrapped body is rejected");
    };

    assert!(matches!(root_error, JitLowerError::UnsupportedIrRoot { kind } if kind == IrKind::Str));
    assert!(matches!(body_error, JitLowerError::UnsupportedIrBody { kind } if kind == IrKind::Str));
}

#[test]
fn tier1_ir_thunk_body_artifact_reports_selector_shape_malformed_roots() {
    let missing_root_arena = IrArena::new();
    let missing_body_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Node(IrId::new(9)),
        )],
        Vec::new(),
    );
    let malformed_wrapper_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::ThunkAlloc,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let Err(missing_root_error) =
        lower_tier1_ir_thunk_body_artifact(&missing_root_arena, IrId::new(7))
    else {
        panic!("missing selector root is rejected");
    };
    let Err(missing_body_error) =
        lower_force_aware_tier1_ir_thunk_body_artifact(&missing_body_arena, IrId::new(0))
    else {
        panic!("missing selector body is rejected");
    };
    let Err(malformed_wrapper_error) =
        lower_tier1_ir_thunk_body_artifact(&malformed_wrapper_arena, IrId::new(0))
    else {
        panic!("malformed selector wrapper is rejected");
    };

    assert!(
        matches!(missing_root_error, JitLowerError::MissingIrNode { root } if root == IrId::new(7))
    );
    assert!(
        matches!(missing_body_error, JitLowerError::MissingIrBody { body } if body == IrId::new(9))
    );
    assert!(matches!(
        malformed_wrapper_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data: IrData::None,
            expected: "body node",
        }
    ));
}

#[test]
fn tier1_ir_thunk_body_artifact_reports_selector_payload_mismatches() {
    let mismatched_literal_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let mismatched_local_arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );
    let mismatched_body_arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Bool,
                Span::new(1, 5),
                EffectClass::pure(),
                IrData::None,
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    );

    let Err(literal_error) =
        lower_tier1_ir_thunk_body_artifact(&mismatched_literal_arena, IrId::new(0))
    else {
        panic!("mismatched selector literal is rejected");
    };
    let Err(local_error) =
        lower_force_aware_tier1_ir_thunk_body_artifact(&mismatched_local_arena, IrId::new(0))
    else {
        panic!("mismatched selector local slot is rejected");
    };
    let Err(body_error) = lower_tier1_ir_thunk_body_artifact(&mismatched_body_arena, IrId::new(1))
    else {
        panic!("mismatched selector thunk body is rejected");
    };

    assert!(matches!(
        literal_error,
        JitLowerError::MismatchedConstantData {
            kind: IrKind::Int,
            data: IrData::None,
        }
    ));
    assert!(matches!(
        local_error,
        JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data: IrData::None,
            expected: "local slot payload",
        }
    ));
    assert!(matches!(
        body_error,
        JitLowerError::MismatchedBodyConstantData {
            kind: IrKind::Bool,
            data: IrData::None,
        }
    ));
}

fn lowered_ir(source: &str) -> Ir {
    lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
        .expect("IR lowers")
}

fn local_var_node(slot: u32) -> IrNode {
    IrNode::new(
        IrKind::LocalVar,
        Span::new(0, 1),
        EffectClass::pure(),
        IrData::Local { slot },
    )
}

fn literal_int_node(value: i64) -> IrNode {
    IrNode::new(
        IrKind::Int,
        Span::new(10, 12),
        EffectClass::pure(),
        IrData::Int(value),
    )
}

fn apply_local_slots_arena(function_slot: u32, argument_slot: u32) -> IrArena {
    IrArena::from_raw_parts(
        vec![
            local_var_node(function_slot),
            local_var_node(argument_slot),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    )
}

fn apply_local_slots_thunk_arena(function_slot: u32, argument_slot: u32) -> IrArena {
    IrArena::from_raw_parts(
        vec![
            local_var_node(function_slot),
            local_var_node(argument_slot),
            IrNode::new(
                IrKind::Apply,
                Span::new(1, 3),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Node(IrId::new(2)),
            ),
        ],
        Vec::new(),
    )
}

fn direct_thunk_ir_with_facts(facts: ExprFacts) -> Ir {
    let mut ir = minimal_ir(IrId::new(1), direct_thunk_arena());
    *ir.facts
        .get_mut(IrId::new(1))
        .expect("direct thunk fixture has a fact record") = facts;
    ir
}

fn static_select_ir(slot: u32) -> Ir {
    let mut symbols = SymbolTable::new();
    let symbol = symbols
        .intern(b"target")
        .expect("fixture symbol table accepts target");
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(slot),
            IrNode::new(
                IrKind::Select,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Select {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    site: IrInlineCacheSiteId::new(11),
                    default: None,
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

fn static_select_default_ir(slot: u32, default: IrId, mut default_nodes: Vec<IrNode>) -> Ir {
    let mut symbols = SymbolTable::new();
    let symbol = symbols
        .intern(b"target")
        .expect("fixture symbol table accepts target");
    let mut nodes = vec![
        local_var_node(slot),
        IrNode::new(
            IrKind::Select,
            Span::new(0, 8),
            EffectClass::pure(),
            IrData::Select {
                receiver: IrId::new(0),
                path: IrAttrPathId::new(0),
                site: IrInlineCacheSiteId::new(11),
                default: Some(default),
            },
        ),
    ];
    nodes.append(&mut default_nodes);
    let arena = IrArena::from_raw_parts(nodes, Vec::new());
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

fn static_has_attr_ir(slot: u32) -> Ir {
    let mut symbols = SymbolTable::new();
    let symbol = symbols
        .intern(b"target")
        .expect("fixture symbol table accepts target");
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(slot),
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

fn wrapped_static_select_ir(slot: u32) -> Ir {
    let mut symbols = SymbolTable::new();
    let symbol = symbols
        .intern(b"target")
        .expect("fixture symbol table accepts target");
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(slot),
            IrNode::new(
                IrKind::Select,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Select {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    site: IrInlineCacheSiteId::new(11),
                    default: None,
                },
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Node(IrId::new(1)),
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(2),
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

fn wrapped_static_has_attr_ir(slot: u32) -> Ir {
    let mut symbols = SymbolTable::new();
    let symbol = symbols
        .intern(b"target")
        .expect("fixture symbol table accepts target");
    let arena = IrArena::from_raw_parts(
        vec![
            local_var_node(slot),
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
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Node(IrId::new(1)),
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(2),
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

fn direct_thunk_arena() -> IrArena {
    IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::Int,
                Span::new(1, 2),
                EffectClass::pure(),
                IrData::Int(1),
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Node(IrId::new(0)),
            ),
        ],
        Vec::new(),
    )
}

fn minimal_ir(root: IrId, arena: IrArena) -> Ir {
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root,
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

fn single_imported_function(function: &Function) -> (FuncRef, &ExtFuncData) {
    let imports = function.dfg.ext_funcs.iter().collect::<Vec<_>>();

    assert_eq!(imports.len(), 1);
    imports[0]
}

fn imported_function_by_user_external_name(
    function: &Function,
    expected: UserExternalName,
) -> (FuncRef, &ExtFuncData) {
    function
        .dfg
        .ext_funcs
        .iter()
        .find(|(_func_ref, import)| imported_user_external_name(function, import) == expected)
        .expect("imported function with expected user external name exists")
}

fn imported_user_external_name(function: &Function, import: &ExtFuncData) -> UserExternalName {
    let ExternalName::User(user_name_ref) = import.name else {
        panic!("imported env-get helper uses a user external name");
    };

    function.params.user_named_funcs()[user_name_ref].clone()
}

fn entry_block_values(function: &Function) -> Vec<cranelift_codegen::ir::Value> {
    let entry_block = function
        .layout
        .entry_block()
        .expect("lowered function has an entry block");
    function.dfg.block_params(entry_block).to_vec()
}

fn entry_block_param_types(function: &Function) -> Vec<Type> {
    entry_block_values(function)
        .iter()
        .map(|value| function.dfg.value_type(*value))
        .collect()
}

fn param_types(signature: &cranelift_codegen::ir::Signature) -> Vec<Type> {
    signature
        .params
        .iter()
        .map(|parameter| parameter.value_type)
        .collect()
}

fn iconst_words(function: &Function) -> Vec<u64> {
    iconst_values(function)
        .into_iter()
        .map(|(_value, word)| word)
        .collect()
}

fn all_iconst_words(function: &Function) -> Vec<u64> {
    function
        .layout
        .blocks()
        .flat_map(|block| function.layout.block_insts(block))
        .filter_map(|inst| match function.dfg.insts[inst] {
            InstructionData::UnaryImm {
                opcode: Opcode::Iconst,
                imm,
            } => Some(imm.bits() as u64),
            _ => None,
        })
        .collect()
}

fn iconst_values(function: &Function) -> Vec<(cranelift_codegen::ir::Value, u64)> {
    let entry_block = function
        .layout
        .entry_block()
        .expect("lowered function has an entry block");
    function
        .layout
        .block_insts(entry_block)
        .filter_map(|inst| match function.dfg.insts[inst] {
            InstructionData::UnaryImm {
                opcode: Opcode::Iconst,
                imm,
            } => Some((function.dfg.inst_results(inst)[0], imm.bits() as u64)),
            _ => None,
        })
        .collect()
}

fn return_operands(function: &Function) -> Vec<cranelift_codegen::ir::Value> {
    let entry_block = function
        .layout
        .entry_block()
        .expect("lowered function has an entry block");
    let return_inst = function
        .layout
        .block_insts(entry_block)
        .find(|inst| function.dfg.insts[*inst].opcode() == Opcode::Return)
        .expect("lowered function has a return instruction");
    function.dfg.inst_args(return_inst).to_vec()
}

fn single_call_inst(function: &Function) -> cranelift_codegen::ir::Inst {
    let calls = call_insts(function);

    assert_eq!(calls.len(), 1);
    calls[0]
}

fn call_insts(function: &Function) -> Vec<cranelift_codegen::ir::Inst> {
    let entry_block = function
        .layout
        .entry_block()
        .expect("lowered function has an entry block");
    function
        .layout
        .block_insts(entry_block)
        .filter(|inst| function.dfg.insts[*inst].opcode() == Opcode::Call)
        .collect()
}

fn opcodes(function: &Function) -> Vec<Opcode> {
    let entry_block = function
        .layout
        .entry_block()
        .expect("lowered function has an entry block");
    function
        .layout
        .block_insts(entry_block)
        .map(|inst| function.dfg.insts[inst].opcode())
        .collect()
}
