//! One-word (Candidate-C) lowering tests for the delegating tier-1 shapes.
//!
//! The two-word lowering tests in `lower/tests.rs` assert baseline-carrier
//! CLIF shapes (paired iconsts, two-word returns, 16-byte spill strides), so
//! they stay gated off under `candidate_c_value`. This module is the variant
//! counterpart: it asserts that the width-generic emitters produce one-word
//! CLIF against the one-word frozen signatures, and that carrier-semantic
//! shapes (wide-int constants, arithmetic trees) decline instead of emitting
//! two-word code.

use cranelift_codegen::ir::{InstructionData, Opcode, types};
use ratchet_core::{
    EffectClass, IrArena, IrData, IrId, IrKind, IrNode, runtime_thunk_call_signature,
    syntax::{BinOpKind, Span},
};
use ratchet_value::value::{Value, ValueTag, compressed::CompressedValueWord};

use super::*;
use crate::abi::clif_signature_for_runtime_call;

fn node(kind: IrKind, data: IrData) -> IrNode {
    IrNode::new(kind, Span::new(0, 1), EffectClass::pure(), data)
}

fn iconst_words(function: &Function) -> Vec<u64> {
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

fn return_arity(function: &Function) -> usize {
    function.signature.returns.len()
}

#[test]
fn constant_thunk_body_returns_one_compressed_word() {
    let function =
        lower_constant_thunk_body(Value::int(42)).expect("inline-int constant lowers");
    let expected = clif_signature_for_runtime_call(runtime_thunk_call_signature())
        .expect("thunk signature lowers");

    assert_eq!(function.signature, expected);
    assert_eq!(return_arity(&function), 1);
    assert_eq!(function.signature.returns[0].value_type, types::I64);
    assert_eq!(
        iconst_words(&function),
        vec![CompressedValueWord::inline_int(42).expect("inline").raw()]
    );
}

/// Pins the sign-extension decode: a negative inline int's payload bits are
/// the whole compressed word on this carrier, so a `payload_bits`-based
/// embed would mis-reject (or mis-encode) every negative constant.
#[test]
fn negative_int_constant_embeds_its_sign_extended_word() {
    let function =
        lower_constant_thunk_body(Value::int(-17)).expect("negative inline int lowers");
    assert_eq!(
        iconst_words(&function),
        vec![CompressedValueWord::inline_int(-17).expect("inline").raw()]
    );
}

#[test]
fn constant_bool_and_null_embed_their_singleton_words() {
    let cases = [
        (Value::bool(true), CompressedValueWord::boolean(true)),
        (Value::null(), CompressedValueWord::null()),
    ];
    for (value, expected) in cases {
        let function = lower_constant_thunk_body(value).expect("inline scalar lowers");
        assert_eq!(iconst_words(&function), vec![expected.raw()]);
    }
}

#[test]
fn wide_int_constant_ir_declines_as_arena_backed() {
    let arena = IrArena::from_raw_parts(
        vec![node(IrKind::Int, IrData::Int(i64::from(i32::MAX) + 1))],
        Vec::new(),
    );

    let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
        .expect_err("wide integers box through the evaluator heap");
    assert!(matches!(
        error,
        JitLowerError::ArenaBackedConstant { tag: ValueTag::Int }
    ));
}

#[test]
fn env_get_body_returns_one_word_from_the_one_word_helper() {
    let arena = IrArena::from_raw_parts(
        vec![node(IrKind::LocalVar, IrData::Local { slot: 3 })],
        Vec::new(),
    );

    let function = lower_env_get_ir_thunk_body(&arena, IrId::new(0)).expect("env get lowers");
    assert_eq!(return_arity(&function), 1);
    let env_get_signature = function
        .dfg
        .ext_funcs
        .values()
        .next()
        .map(|ext| &function.dfg.signatures[ext.signature])
        .expect("env-get helper is imported");
    assert_eq!(env_get_signature.returns.len(), 1);
}

#[test]
fn forced_env_get_spills_one_word_at_eight_byte_stride() {
    let arena = IrArena::from_raw_parts(
        vec![node(IrKind::LocalVar, IrData::Local { slot: 0 })],
        Vec::new(),
    );

    let function =
        lower_forced_env_get_ir_thunk_body(&arena, IrId::new(0)).expect("forced env get lowers");
    assert_eq!(return_arity(&function), 1);

    let mapped_calls = function
        .layout
        .blocks()
        .flat_map(|block| function.layout.block_insts(block))
        .filter_map(|inst| function.dfg.user_stack_map_entries(inst))
        .collect::<Vec<_>>();
    assert_eq!(mapped_calls.len(), 1, "exactly the force call is mapped");
    let entries = mapped_calls[0];
    // Identity anchor + one compressed word.
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].ty, types::I64);
    // One value spilled after the 32-byte header at an 8-byte stride.
    let slot = entries[1].slot;
    assert_eq!(entries[1].offset, 32);
    assert_eq!(function.sized_stack_slots[slot].size, 40);
}

#[test]
fn apply_local_slots_passes_one_word_per_operand() {
    let arena = IrArena::from_raw_parts(
        vec![
            node(IrKind::LocalVar, IrData::Local { slot: 0 }),
            node(IrKind::LocalVar, IrData::Local { slot: 1 }),
            node(
                IrKind::Apply,
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );

    let function =
        lower_apply_local_slots_ir_thunk_body(&arena, IrId::new(2)).expect("apply lowers");
    // The aos_apply call takes rt + one word per operand = 3 arguments.
    let apply_arg_count = function
        .layout
        .blocks()
        .flat_map(|block| function.layout.block_insts(block))
        .filter_map(|inst| match &function.dfg.insts[inst] {
            InstructionData::Call { args, .. } => {
                Some(args.len(&function.dfg.value_lists))
            }
            _ => None,
        })
        .max()
        .expect("apply body emits calls");
    assert_eq!(apply_arg_count, 3);
    assert_eq!(return_arity(&function), 1);
}

#[test]
fn arith_tree_lowers_to_one_word_compressed_codegen() {
    let arena = IrArena::from_raw_parts(
        vec![
            node(IrKind::LocalVar, IrData::Local { slot: 0 }),
            node(IrKind::LocalVar, IrData::Local { slot: 1 }),
            node(
                IrKind::BinOp,
                IrData::Binary {
                    op: BinOpKind::Add,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );

    let function =
        lower_tier1_ir_thunk_body(&arena, IrId::new(2)).expect("arith tree lowers one-word");
    assert_eq!(return_arity(&function), 1);
}

/// A comparison root selects between the two canonical boolean words.
#[test]
fn arith_comparison_embeds_both_boolean_words() {
    let arena = IrArena::from_raw_parts(
        vec![
            node(IrKind::Int, IrData::Int(1)),
            node(IrKind::Int, IrData::Int(2)),
            node(
                IrKind::BinOp,
                IrData::Binary {
                    op: BinOpKind::Lt,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );

    let function =
        lower_tier1_ir_thunk_body(&arena, IrId::new(2)).expect("comparison lowers one-word");
    let words = iconst_words(&function);
    assert!(words.contains(&CompressedValueWord::boolean(true).raw()));
    assert!(words.contains(&CompressedValueWord::boolean(false).raw()));
}

/// A wide integer literal operand can never pass the inline guard, so the
/// lowering declines up front and the def-site stays on the tree walk.
#[test]
fn arith_tree_declines_wide_literal_operands() {
    let arena = IrArena::from_raw_parts(
        vec![
            node(IrKind::Int, IrData::Int(i64::from(i32::MAX) + 1)),
            node(IrKind::LocalVar, IrData::Local { slot: 0 }),
            node(
                IrKind::BinOp,
                IrData::Binary {
                    op: BinOpKind::Add,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );

    let error = lower_tier1_ir_thunk_body(&arena, IrId::new(2))
        .expect_err("wide literal has no inline word");
    assert!(matches!(
        error,
        JitLowerError::UnsupportedArithOperand {
            kind: IrKind::Int,
            ..
        }
    ));
}

#[test]
fn singleton_list_declines_on_the_one_word_carrier() {
    let arena = IrArena::from_raw_parts(
        vec![
            node(IrKind::Int, IrData::Int(41)),
            node(
                IrKind::List,
                IrData::Children(ratchet_core::IrChildSlice::new(0, 1)),
            ),
        ],
        vec![IrId::new(0)],
    );

    let error = lower_tier1_ir_thunk_body(&arena, IrId::new(1))
        .expect_err("alloc-cons is two-word codegen");
    assert!(matches!(
        error,
        JitLowerError::CarrierUnsupportedShape {
            shape: "alloc-cons"
        }
    ));
}
