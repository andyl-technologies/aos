//! One-word (Candidate-C) lowering of the fused curried-chain tiers.
//!
//! The compressed-word sibling of [`super`]: it owns the one-word lowering
//! entry points ([`lower_tier2_curried_chain_compressed`],
//! [`lower_tier2_fold_genlist_compressed`]), the one-word boundary entry
//! adapter, and the internal recursive signature builder; the recursive
//! expression emitter lives in [`emit`]. Same grammar, same compiled shape
//! (`inner` + boundary `entry`), same deoptimization and budget discipline as
//! the two-word tiers, but every runtime value is one compressed word instead
//! of a `(tag, payload)` pair.
//!
//! # ABI deltas from the two-word carrier
//!
//! - `inner` keeps the entry's `(rt, env)` prefix, replaces the `argv` pointer
//!   with `K` unboxed one-word parameters, and appends one trailing `i64`
//!   budget parameter, returning one word.
//! - The boundary `entry` loads `K` argument words from the caller-owned
//!   `argv` run at the carrier's `size_of::<Value>()` stride (8 bytes, one
//!   load per value — no tag/payload pair), and translates the internal deopt
//!   sentinel word into the canonical null word before returning.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{AbiParam, Function, InstBuilder, MemFlags, Signature, condcodes::IntCC, types},
};
use ratchet_core::{IrArena, IrBinding, IrId, runtime_lambda_argv_call_signature};
use ratchet_value::value::compressed::CompressedValueWord;

use super::super::lambda_rec::import_tier2_local_function;
use super::super::{JitLowerError, append_entry_block_params, clif_name_for_ir_root, verify_clif_function};
use super::{
    JitTier2ChainLowering, JitTier2ChainScan, JitTier2EnvBoundary, JitTier2PinnedCallee,
};
use crate::abi::clif_signature_for_runtime_call;

mod emit;

/// The internal deopt-unwind sentinel word (invalid kind byte `0xFF`).
///
/// Returned by a deopting `inner` frame and propagated by every self-call
/// site; the boundary `entry` translates it to the canonical null word before
/// the word crosses back into Rust, because materializing an invalid
/// compressed kind on the Rust side would be undefined behavior.
const TIER2_DEOPT_SENTINEL_WORD: i64 = 0xFF << 32;

/// The byte stride of one by-value runtime value in the entry's `argv` run.
///
/// Under the Candidate-C carrier a runtime `Value` is a single 8-byte
/// compressed word, so the entry indexes the `argv` run at this stride with one
/// load per value.
const VALUE_STRIDE_BYTES: i32 = 8;

/// Lowers a scanned curried chain into verified fused one-word tier-2 CLIF.
///
/// The one-word counterpart of
/// [`lower_tier2_curried_chain`](super::lower_tier2_curried_chain), with the
/// same arguments, grammar, budget, and deoptimization contract.
///
/// # Errors
///
/// Returns the same scan, ABI, and verifier errors as the two-word lowerer;
/// additionally, an out-of-inline-range integer literal declines as
/// [`JitLowerError::UnsupportedArithOperand`] (the tree walk boxes it).
pub(super) fn lower_tier2_curried_chain_compressed(
    arena: &IrArena,
    bindings: &[IrBinding],
    scan: &JitTier2ChainScan,
    self_upval: Option<(u32, u32)>,
    pinned: &[JitTier2PinnedCallee],
    env_boundary: JitTier2EnvBoundary,
    depth_budget: i64,
) -> Result<JitTier2ChainLowering, JitLowerError> {
    let entry_signature = clif_signature_for_runtime_call(runtime_lambda_argv_call_signature())?;
    let inner_signature = inner_signature_for_arity(&entry_signature, scan.arity());

    let (inner, self_call_count) = emit::build_inner_function(
        arena,
        bindings,
        scan,
        inner_signature.clone(),
        self_upval,
        pinned,
        env_boundary,
        emit::ChainInnerBody::Plain,
    )?;
    let entry = build_entry_function(
        scan.inner_body(),
        entry_signature,
        &inner_signature,
        scan.arity(),
        depth_budget,
    )?;

    verify_clif_function(&inner)?;
    verify_clif_function(&entry)?;

    Ok(JitTier2ChainLowering::from_cached_parts(
        entry,
        inner,
        scan.inner_body(),
        scan.arity(),
        self_upval,
        self_call_count,
    ))
}

/// Lowers a fold operator fused with a `builtins.genList` generator body on the
/// one-word carrier.
///
/// The one-word counterpart of
/// [`lower_tier2_fold_genlist`](super::lower_tier2_fold_genlist), with the same
/// arity-2 requirement and fused-generator seeding.
///
/// # Errors
///
/// Returns [`JitLowerError::UnsupportedArithOperand`] when `scan` is not arity
/// 2 (or a body shape drifts from the scans), plus the ABI and verifier errors
/// of [`lower_tier2_curried_chain_compressed`].
pub(super) fn lower_tier2_fold_genlist_compressed(
    arena: &IrArena,
    bindings: &[IrBinding],
    scan: &JitTier2ChainScan,
    pinned: &[JitTier2PinnedCallee],
    generator_body: IrId,
    depth_budget: i64,
) -> Result<JitTier2ChainLowering, JitLowerError> {
    if scan.arity() != 2 {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: scan.inner_body(),
            kind: ratchet_core::IrKind::Lambda,
        });
    }
    let entry_signature = clif_signature_for_runtime_call(runtime_lambda_argv_call_signature())?;
    let inner_signature = inner_signature_for_arity(&entry_signature, scan.arity());

    let (inner, self_call_count) = emit::build_inner_function(
        arena,
        bindings,
        scan,
        inner_signature.clone(),
        None,
        pinned,
        JitTier2EnvBoundary::OperatorEnv,
        emit::ChainInnerBody::FusedGenerator(generator_body),
    )?;
    let entry = build_entry_function(
        scan.inner_body(),
        entry_signature,
        &inner_signature,
        scan.arity(),
        depth_budget,
    )?;

    verify_clif_function(&inner)?;
    verify_clif_function(&entry)?;

    Ok(JitTier2ChainLowering::from_cached_parts(
        entry,
        inner,
        scan.inner_body(),
        scan.arity(),
        None,
        self_call_count,
    ))
}

/// Builds the internal recursive signature for a K-parameter one-word body.
///
/// `inner` keeps the entry's `(rt, env)` prefix, replaces the `argv` pointer
/// with `K` unboxed one-word `i64` parameters, and appends one trailing `i64`
/// budget parameter; the return matches the frozen entry's one-word `Value`.
fn inner_signature_for_arity(entry: &Signature, arity: u32) -> Signature {
    let mut signature = entry.clone();
    signature.params.truncate(2);
    for _ in 0..arity {
        signature.params.push(AbiParam::new(types::I64));
    }
    signature.params.push(AbiParam::new(types::I64));
    signature
}

/// Builds the boundary entry adapter with the frozen argv lambda-entry ABI.
///
/// The entry loads `arity` by-value runtime words from the caller-owned `argv`
/// run (8-byte stride, one load per value), calls `inner` with the seeded depth
/// budget, and translates the internal deopt sentinel word into the canonical
/// null word (the recorded trap, not the value, signals the deopt).
fn build_entry_function(
    body: IrId,
    entry_signature: Signature,
    inner_signature: &Signature,
    arity: u32,
    depth_budget: i64,
) -> Result<Function, JitLowerError> {
    let mut function = Function::with_name_signature(clif_name_for_ir_root(body), entry_signature);
    let inner_ref = import_tier2_local_function(&mut function, inner_signature);

    let entry_block = append_entry_block_params(&mut function);
    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let params = cursor.func.dfg.block_params(entry_block).to_vec();
    let [rt, env, argv] = params[..] else {
        return Err(JitLowerError::MissingEntryBlockParameter {
            index: params.len(),
        });
    };
    let mut call_arguments = vec![rt, env];
    for j in 0..arity as i32 {
        let word = cursor
            .ins()
            .load(types::I64, MemFlags::trusted(), argv, j * VALUE_STRIDE_BYTES);
        call_arguments.push(word);
    }
    let budget = cursor.ins().iconst(types::I64, depth_budget);
    call_arguments.push(budget);
    let call = cursor.ins().call(inner_ref, &call_arguments);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let [word] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: "tier2_chain_inner",
            expected: 1,
            actual: results.len(),
        });
    };
    let is_sentinel = cursor
        .ins()
        .icmp_imm(IntCC::Equal, word, TIER2_DEOPT_SENTINEL_WORD);
    let clean = cursor.func.dfg.make_block();
    let deopted = cursor.func.dfg.make_block();
    cursor.ins().brif(is_sentinel, deopted, &[], clean, &[]);
    cursor.insert_block(clean);
    cursor.ins().return_(&[word]);
    cursor.insert_block(deopted);
    let null_word = cursor
        .ins()
        .iconst(types::I64, CompressedValueWord::null().raw() as i64);
    cursor.ins().return_(&[null_word]);
    drop(cursor);
    Ok(function)
}
