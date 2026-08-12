//! Unit tests for the tier-1 CLIF lowerer (moved from `lower.rs` verbatim).

use super::*;

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

// Builds `Value::float`, which the Candidate-C carrier boxes (no inline
// constructor), so this float-literal lowering test is baseline-only.
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

// A literal-root case is `Value::float`, which the Candidate-C carrier boxes
// (no inline constructor), so this float-literal lowering test is baseline-only.
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
