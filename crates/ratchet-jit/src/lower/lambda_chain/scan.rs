//! Structural scans for the fused curried-chain lowering.
//!
//! This module owns the pre-lowering validation passes of
//! [`lambda_chain`](super): walking a chain of bare-formal lambdas down to
//! its innermost body, checking that body against the fused grammar while
//! collecting the callee upvalue sites the engine must classify, and
//! validating a resolved pinned callee's own chain as call-free arithmetic.
//! The emitters in the parent module re-use the small shape helpers
//! ([`flatten_apply_chain`], [`require_static_bool_condition`]) so scan and
//! emission agree on the grammar by construction.

use ratchet_core::{IrArena, IrData, IrId, IrKind, syntax::BinOpKind, syntax::UnaryOpKind};

use super::{JitTier2ChainCalleeSite, JitTier2ChainScan, TIER2_MAX_CHAIN_ARITY};
use crate::lower::JitLowerError;

/// Mutable scan output threaded through the chain-body walk.
struct ChainBodyScan {
    /// The distinct callee upvalue sites found so far.
    callee_sites: Vec<JitTier2ChainCalleeSite>,
    /// Whether any value operand read the environment beyond the parameters.
    reads_env: bool,
}

/// Scans a curried lambda chain rooted at `(root_pattern, root_body)`.
///
/// Requires the root pattern to be a bare formal whose body is a directly
/// nested lambda (arity at least 2), descends through at most
/// [`TIER2_MAX_CHAIN_ARITY`] bare-formal lambdas, and walks the innermost body
/// under the fused grammar, collecting the callee upvalue sites.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrBody`] when a chain node is absent and
/// [`JitLowerError::UnsupportedArithOperand`] / [`JitLowerError::UnsupportedArithOp`]
/// for any shape outside the fused grammar (a formal-set or defaulted pattern,
/// a chain deeper than the supported arity, a stray upvalue read, an
/// inconsistent callee chain length, or a non-arithmetic body node).
pub fn scan_tier2_curried_chain(
    arena: &IrArena,
    root_pattern: IrId,
    root_body: IrId,
) -> Result<JitTier2ChainScan, JitLowerError> {
    require_bare_formal(arena, root_pattern)?;
    let mut pattern = root_pattern;
    let mut body = root_body;
    let mut arity: u32 = 1;
    loop {
        let node = arena
            .node(body)
            .copied()
            .ok_or(JitLowerError::MissingIrBody { body })?;
        match (node.kind, node.data) {
            (
                IrKind::Lambda,
                IrData::Lambda {
                    pattern: next_pattern,
                    body: next_body,
                    ..
                },
            ) => {
                if arity == TIER2_MAX_CHAIN_ARITY {
                    return Err(JitLowerError::UnsupportedArithOperand {
                        operand: body,
                        kind: IrKind::Lambda,
                    });
                }
                require_bare_formal(arena, next_pattern)?;
                pattern = next_pattern;
                body = next_body;
                arity += 1;
            }
            _ => break,
        }
    }
    if arity < 2 {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: root_body,
            kind: IrKind::Lambda,
        });
    }

    let mut body_scan = ChainBodyScan {
        callee_sites: Vec::new(),
        reads_env: false,
    };
    scan_chain_expr(arena, body, arity, &mut body_scan)?;
    Ok(JitTier2ChainScan {
        arity,
        inner_pattern: pattern,
        inner_body: body,
        callee_sites: body_scan.callee_sites,
        reads_env: body_scan.reads_env,
    })
}

/// Validates a pinned callee's chain: bare formals and a call-free body.
///
/// `expected_arity` is the application-chain length observed at the pinned
/// call sites; the callee's own curried chain must have exactly that arity,
/// and its innermost body must be arithmetic over its own parameters and
/// literals only — no applications and no upvalue reads beyond the chain
/// parameters — so inlining it requires neither environment access nor a
/// recursive lowering. Returns the callee's innermost body node.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrBody`] when a chain node is absent and
/// [`JitLowerError::UnsupportedArithOperand`] / [`JitLowerError::UnsupportedArithOp`]
/// when the callee chain or its body fall outside the call-free grammar.
pub fn scan_tier2_pinned_callee(
    arena: &IrArena,
    root_pattern: IrId,
    root_body: IrId,
    expected_arity: u32,
) -> Result<IrId, JitLowerError> {
    if expected_arity == 0 || expected_arity > TIER2_MAX_CHAIN_ARITY {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: root_body,
            kind: IrKind::Apply,
        });
    }
    require_bare_formal(arena, root_pattern)?;
    let mut body = root_body;
    let mut arity: u32 = 1;
    while arity < expected_arity {
        let node = arena
            .node(body)
            .copied()
            .ok_or(JitLowerError::MissingIrBody { body })?;
        match (node.kind, node.data) {
            (
                IrKind::Lambda,
                IrData::Lambda {
                    pattern: next_pattern,
                    body: next_body,
                    ..
                },
            ) => {
                require_bare_formal(arena, next_pattern)?;
                body = next_body;
                arity += 1;
            }
            (kind, _) => {
                return Err(JitLowerError::UnsupportedArithOperand { operand: body, kind });
            }
        }
    }
    scan_call_free_expr(arena, body, expected_arity)?;
    Ok(body)
}

/// Requires `pattern` to be a bare formal without a default.
fn require_bare_formal(arena: &IrArena, pattern: IrId) -> Result<(), JitLowerError> {
    let node = arena
        .node(pattern)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: pattern })?;
    match (node.kind, node.data) {
        (IrKind::Formal, IrData::Formal { default: None, .. }) => Ok(()),
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand {
            operand: pattern,
            kind,
        }),
    }
}

/// Walks one grammar expression of the chain body, collecting callee sites
/// and environment-read facts.
fn scan_chain_expr(
    arena: &IrArena,
    id: IrId,
    arity: u32,
    body_scan: &mut ChainBodyScan,
) -> Result<(), JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        (IrKind::Int | IrKind::Bool, _) => Ok(()),
        (IrKind::LocalVar, IrData::Local { slot: 0 }) => Ok(()),
        (IrKind::UpvalVar, IrData::Upval { depth, slot: 0 }) if depth < arity => Ok(()),
        // A value read of an upvalue beyond the chain parameters is an
        // environment read against the boundary env pointer; the emitter
        // forces it at first strict use and guards it as an integer.
        (IrKind::UpvalVar, IrData::Upval { depth, .. }) if depth >= arity => {
            body_scan.reads_env = true;
            Ok(())
        }
        (IrKind::BinOp, IrData::Binary { lhs, rhs, .. }) => {
            scan_chain_expr(arena, lhs, arity, body_scan)?;
            scan_chain_expr(arena, rhs, arity, body_scan)
        }
        (
            IrKind::UnaryOp,
            IrData::Unary {
                op: UnaryOpKind::Neg,
                operand,
            },
        ) => scan_chain_expr(arena, operand, arity, body_scan),
        (
            IrKind::If,
            IrData::Triple {
                first,
                second,
                third,
            },
        ) => {
            require_static_bool_condition(arena, first)?;
            scan_chain_expr(arena, first, arity, body_scan)?;
            scan_chain_expr(arena, second, arity, body_scan)?;
            scan_chain_expr(arena, third, arity, body_scan)
        }
        (IrKind::Apply, _) => {
            let (upval, arguments) = flatten_apply_chain(arena, id, arity)?;
            record_callee_site(&mut body_scan.callee_sites, upval, arguments.len() as u32, id)?;
            for argument in arguments {
                scan_chain_expr(arena, argument, arity, body_scan)?;
            }
            Ok(())
        }
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand { operand: id, kind }),
    }
}

/// Walks one call-free grammar expression of a pinned callee body.
fn scan_call_free_expr(arena: &IrArena, id: IrId, arity: u32) -> Result<(), JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        (IrKind::Int | IrKind::Bool, _) => Ok(()),
        (IrKind::LocalVar, IrData::Local { slot: 0 }) => Ok(()),
        (IrKind::UpvalVar, IrData::Upval { depth, slot: 0 }) if depth < arity => Ok(()),
        (IrKind::BinOp, IrData::Binary { lhs, rhs, .. }) => {
            scan_call_free_expr(arena, lhs, arity)?;
            scan_call_free_expr(arena, rhs, arity)
        }
        (
            IrKind::UnaryOp,
            IrData::Unary {
                op: UnaryOpKind::Neg,
                operand,
            },
        ) => scan_call_free_expr(arena, operand, arity),
        (
            IrKind::If,
            IrData::Triple {
                first,
                second,
                third,
            },
        ) => {
            require_static_bool_condition(arena, first)?;
            scan_call_free_expr(arena, first, arity)?;
            scan_call_free_expr(arena, second, arity)?;
            scan_call_free_expr(arena, third, arity)
        }
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand { operand: id, kind }),
    }
}

/// Flattens a nested `Apply` chain into its upvalue head and argument run.
///
/// The head must be an upvalue read beyond the chain's parameter frames
/// (`depth >= arity`); lazy `ThunkAlloc` wrappers around arguments are
/// unwrapped (the fused body evaluates argument expressions eagerly, which is
/// sound inside the pure grammar — see the module docs).
pub(super) fn flatten_apply_chain(
    arena: &IrArena,
    id: IrId,
    arity: u32,
) -> Result<((u32, u32), Vec<IrId>), JitLowerError> {
    let mut arguments = Vec::new();
    let mut cursor = id;
    loop {
        let node = arena
            .node(cursor)
            .copied()
            .ok_or(JitLowerError::MissingIrBody { body: cursor })?;
        match (node.kind, node.data) {
            (IrKind::Apply, IrData::Pair { first, second }) => {
                arguments.push(unwrap_thunk_alloc(arena, second)?);
                cursor = first;
            }
            (IrKind::UpvalVar, IrData::Upval { depth, slot }) if depth >= arity => {
                arguments.reverse();
                return Ok(((depth, slot), arguments));
            }
            (kind, _) => {
                return Err(JitLowerError::UnsupportedArithOperand {
                    operand: cursor,
                    kind,
                });
            }
        }
    }
}

/// Records one callee site, requiring a consistent arity per upvalue.
fn record_callee_site(
    callee_sites: &mut Vec<JitTier2ChainCalleeSite>,
    upval: (u32, u32),
    arity: u32,
    at: IrId,
) -> Result<(), JitLowerError> {
    if let Some(site) = callee_sites.iter_mut().find(|site| site.upval == upval) {
        if site.arity != arity {
            return Err(JitLowerError::UnsupportedArithOperand {
                operand: at,
                kind: IrKind::Apply,
            });
        }
        site.chain_count = site.chain_count.saturating_add(1);
        return Ok(());
    }
    callee_sites.push(JitTier2ChainCalleeSite {
        upval,
        arity,
        chain_count: 1,
    });
    Ok(())
}

/// Requires an `if` condition to be a statically boolean grammar shape.
pub(super) fn require_static_bool_condition(arena: &IrArena, cond: IrId) -> Result<(), JitLowerError> {
    let node = arena
        .node(cond)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: cond })?;
    let statically_boolean = match (node.kind, node.data) {
        (IrKind::Bool, _) => true,
        (IrKind::BinOp, IrData::Binary { op, .. }) => matches!(
            op,
            BinOpKind::Lt
                | BinOpKind::Gt
                | BinOpKind::Le
                | BinOpKind::Ge
                | BinOpKind::Eq
                | BinOpKind::Ne
        ),
        _ => false,
    };
    if statically_boolean {
        Ok(())
    } else {
        Err(JitLowerError::UnsupportedArithOperand {
            operand: cond,
            kind: node.kind,
        })
    }
}

/// Unwraps a lazy `ThunkAlloc` wrapper around an argument expression.
fn unwrap_thunk_alloc(arena: &IrArena, id: IrId) -> Result<IrId, JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => Ok(body),
        _ => Ok(id),
    }
}
