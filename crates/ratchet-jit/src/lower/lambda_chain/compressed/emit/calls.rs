//! Application-chain emitters (self-call and pinned-inline), split from
//! the compressed tier-2 body emitter (§2 cap).

use super::*;

/// Emits one full application chain: a direct self-call or a pinned inline.
pub(super) fn emit_call_chain(
    cursor: &mut FuncCursor,
    arena: &IrArena,
    ctx: &mut ChainCtx<'_>,
    id: IrId,
    state: &mut EmitState,
) -> Result<TypedVal, JitLowerError> {
    if state.inline_params.is_some() {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: id,
            kind: IrKind::Apply,
        });
    }
    let let_depth = state.let_scopes.len() as u32;
    let (raw_upval, arguments) = flatten_apply_chain(arena, id, ctx.arity + let_depth)?;
    let upval = (raw_upval.0 - let_depth, raw_upval.1);

    if ctx.self_upval == Some(upval) {
        if arguments.len() as u32 != ctx.arity {
            return Err(JitLowerError::UnsupportedArithOperand {
                operand: id,
                kind: IrKind::Apply,
            });
        }
        let mut argument_words = Vec::with_capacity(arguments.len());
        for argument in &arguments {
            let value = emit_expr(cursor, arena, ctx, *argument, state)?;
            // Materialization point: the inner ABI takes encoded words, so a
            // wide decoded argument deopts here.
            argument_words.push(to_word(cursor, ctx, value));
        }
        return emit_self_call(cursor, ctx, &argument_words);
    }

    let Some(pinned) = ctx
        .pinned
        .iter()
        .find(|callee| callee.upval == upval)
        .copied()
    else {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: id,
            kind: IrKind::Apply,
        });
    };
    if arguments.len() as u32 != pinned.arity {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: id,
            kind: IrKind::Apply,
        });
    }
    let mut argument_values = Vec::with_capacity(arguments.len());
    for argument in &arguments {
        argument_values.push(emit_expr(cursor, arena, ctx, *argument, state)?);
    }
    // Inline the pinned callee body over the evaluated arguments (kept typed,
    // so a decoded argument stays decoded through the inlined arithmetic).
    let mut inline_state = EmitState {
        forced_params: state.forced_params.clone(),
        forced_upvals: state.forced_upvals.clone(),
        inline_params: Some(argument_values),
        let_scopes: Vec::new(),
    };
    let result = emit_expr(cursor, arena, ctx, pinned.body, &mut inline_state)?;
    state.forced_params = inline_state.forced_params;
    state.forced_upvals = inline_state.forced_upvals;
    Ok(result)
}

/// Emits one direct self-call with its depth guard and sentinel propagation.
fn emit_self_call(
    cursor: &mut FuncCursor,
    ctx: &mut ChainCtx<'_>,
    argument_words: &[ClifValue],
) -> Result<TypedVal, JitLowerError> {
    let has_budget = cursor
        .ins()
        .icmp_imm(IntCC::SignedGreaterThan, ctx.budget, 1);
    let call_block = cursor.func.dfg.make_block();
    cursor
        .ins()
        .brif(has_budget, call_block, &[], ctx.deopt, &[]);
    cursor.insert_block(call_block);
    let next_budget = cursor.ins().iadd_imm(ctx.budget, -1);
    let mut call_arguments = vec![ctx.rt, ctx.env];
    call_arguments.extend_from_slice(argument_words);
    call_arguments.push(next_budget);
    let call = cursor.ins().call(ctx.self_ref, &call_arguments);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    let [word] = results[..] else {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: "tier2_chain_self",
            expected: 1,
            actual: results.len(),
        });
    };
    let is_sentinel = cursor
        .ins()
        .icmp_imm(IntCC::Equal, word, TIER2_DEOPT_SENTINEL_WORD);
    let continue_block = cursor.func.dfg.make_block();
    cursor
        .ins()
        .brif(is_sentinel, ctx.sentinel, &[], continue_block, &[]);
    cursor.insert_block(continue_block);
    ctx.self_call_count = ctx.self_call_count.saturating_add(1);
    Ok(TypedVal::Word(word))
}
