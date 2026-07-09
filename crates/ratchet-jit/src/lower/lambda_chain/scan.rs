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
//!
//! # `let` frames and coordinate normalization
//!
//! Chain bodies may contain `let` expressions (`acc: i: let m = ...; in m`).
//! At run time a `let` pushes one environment frame, so **every** coordinate
//! inside its body — parameter reads, environment reads, and callee-site
//! heads alike — shifts deeper by the enclosing let depth `L`. The scan
//! interprets a read at frame distance `f` under let depth `L` as:
//!
//! - `f < L`: a `let`-binding read (compiled as a virtual register — see the
//!   [`emit`](super::emit) module),
//! - `L <= f < L + K`: a chain-parameter read (must be slot 0),
//! - `f >= L + K`: an environment read.
//!
//! Callee sites are recorded with **normalized** coordinates (`depth - L`),
//! so the engine's pin resolution and the emitter's classification are
//! independent of where inside the let nest a call appears. Binding *values*
//! are scanned in the context of their own frame with the own frame — and
//! the own frames of all enclosing binding values — forbidden: the compiled
//! body computes a binding at its first read, which is only sound when no
//! binding can (transitively) read itself or a same-frame sibling.

use ratchet_core::{
    IrArena, IrAttrPathSegment, IrBinding, IrData, IrId, IrKind, syntax::BinOpKind,
    syntax::UnaryOpKind,
};

use super::{JitTier2ChainCalleeSite, JitTier2ChainScan, TIER2_MAX_CHAIN_ARITY};
use crate::lower::JitLowerError;

/// Mutable scan output threaded through the chain-body walk.
struct ChainBodyScan {
    /// The distinct callee upvalue sites found so far (normalized coords).
    callee_sites: Vec<JitTier2ChainCalleeSite>,
    /// Whether any value operand read the environment beyond the parameters.
    reads_env: bool,
}

/// The `let` context of one scanned chain-body expression.
#[derive(Default)]
struct LetContext {
    /// Binding counts of the let frames between the expression and the chain
    /// call frame, outermost first (`scopes.len()` is the let depth `L`).
    scopes: Vec<u32>,
    /// Absolute let levels whose slots may not be read: the own frames of
    /// every enclosing binding value (the letrec restriction).
    forbidden: Vec<u32>,
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
    bindings: &[IrBinding],
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
    let mut context = LetContext::default();
    scan_chain_expr(arena, bindings, body, arity, &mut context, &mut body_scan)?;
    Ok(JitTier2ChainScan {
        arity,
        inner_pattern: pattern,
        inner_body: body,
        callee_sites: body_scan.callee_sites,
        reads_env: body_scan.reads_env,
    })
}

/// Scans a unary predicate lambda (`x: body`) for the filter seam.
///
/// [`scan_tier2_curried_chain`] requires a chain of at least two bare
/// formals, because the apply and fold seams only pay off when a fused entry
/// replaces several interpreted applies. The strict-filter seam dispatches a
/// **single-parameter** predicate once per element, so this scan admits the
/// arity-1 shape: one bare formal whose body is *not* itself a lambda
/// (`builtins.filter` applies exactly one argument, so a curried body could
/// never produce the boolean the compiled loop checks) and otherwise walks
/// the same fused grammar. `LocalVar` slot 0 is the element parameter, every
/// upvalue read is an environment read against the predicate closure's own
/// captured environment (the `OperatorEnv` boundary at skew 1), and `Apply`
/// chains must be headed by such environment reads (pinned callees).
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrBody`] when a scanned node is absent and
/// [`JitLowerError::UnsupportedArithOperand`] /
/// [`JitLowerError::UnsupportedArithOp`] for any shape outside the fused
/// grammar (a formal-set or defaulted pattern, a lambda body, a stray local
/// read, an inconsistent callee chain length, or a non-arithmetic body node).
pub fn scan_tier2_unary_predicate(
    arena: &IrArena,
    bindings: &[IrBinding],
    root_pattern: IrId,
    root_body: IrId,
) -> Result<JitTier2ChainScan, JitLowerError> {
    require_bare_formal(arena, root_pattern)?;
    let node = arena
        .node(root_body)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: root_body })?;
    if node.kind == IrKind::Lambda {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: root_body,
            kind: IrKind::Lambda,
        });
    }

    let mut body_scan = ChainBodyScan {
        callee_sites: Vec::new(),
        reads_env: false,
    };
    let mut context = LetContext::default();
    scan_chain_expr(arena, bindings, root_body, 1, &mut context, &mut body_scan)?;
    Ok(JitTier2ChainScan {
        arity: 1,
        inner_pattern: root_pattern,
        inner_body: root_body,
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
///
/// `context` carries the enclosing `let` frames; see the [module docs](self)
/// for the coordinate interpretation and normalization rules.
fn scan_chain_expr(
    arena: &IrArena,
    bindings: &[IrBinding],
    id: IrId,
    arity: u32,
    context: &mut LetContext,
    body_scan: &mut ChainBodyScan,
) -> Result<(), JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        (IrKind::Int | IrKind::Bool, _) => Ok(()),
        (IrKind::LocalVar, IrData::Local { slot }) => {
            scan_frame_read(id, IrKind::LocalVar, 0, slot, arity, context, body_scan)
        }
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            scan_frame_read(id, IrKind::UpvalVar, depth, slot, arity, context, body_scan)
        }
        (IrKind::BinOp, IrData::Binary { op, lhs, rhs }) => {
            require_arith_binop(op)?;
            scan_chain_expr(arena, bindings, lhs, arity, context, body_scan)?;
            scan_chain_expr(arena, bindings, rhs, arity, context, body_scan)
        }
        (
            IrKind::UnaryOp,
            IrData::Unary {
                op: UnaryOpKind::Neg,
                operand,
            },
        ) => scan_chain_expr(arena, bindings, operand, arity, context, body_scan),
        (
            IrKind::If,
            IrData::Triple {
                first,
                second,
                third,
            },
        ) => {
            require_static_bool_condition(arena, first)?;
            scan_chain_expr(arena, bindings, first, arity, context, body_scan)?;
            scan_chain_expr(arena, bindings, second, arity, context, body_scan)?;
            scan_chain_expr(arena, bindings, third, arity, context, body_scan)
        }
        (
            IrKind::Let,
            IrData::Let {
                bindings: run,
                body,
                ..
            },
        ) => {
            let start = run.start as usize;
            let Some(run_bindings) = start
                .checked_add(run.len as usize)
                .and_then(|end| bindings.get(start..end))
            else {
                return Err(JitLowerError::UnsupportedArithOperand {
                    operand: id,
                    kind: IrKind::Let,
                });
            };
            // The absolute level of this let frame, and the restore point
            // for early exits.
            let level = context.scopes.len() as u32;
            context.scopes.push(run.len);
            let result = scan_let_frame(arena, bindings, run_bindings, body, arity, level, context, body_scan);
            context.scopes.truncate(level as usize);
            result
        }
        (IrKind::Apply, _) => {
            let let_depth = context.scopes.len() as u32;
            let ((depth, slot), arguments) = flatten_apply_chain(arena, id, arity + let_depth)?;
            // Callee sites are recorded with normalized (let-free) coords so
            // the engine's pin resolution and the emitter's classification
            // are independent of the enclosing let depth.
            record_callee_site(
                &mut body_scan.callee_sites,
                (depth - let_depth, slot),
                arguments.len() as u32,
                id,
            )?;
            for argument in arguments {
                scan_chain_expr(arena, bindings, argument, arity, context, body_scan)?;
            }
            Ok(())
        }
        (kind, _) => Err(JitLowerError::UnsupportedArithOperand { operand: id, kind }),
    }
}

/// Scans one `let` frame: every binding value, then the body.
///
/// Binding values are scanned in the context of their own frame (`let` is
/// recursive in source, so a value's coordinates count its own frame) with
/// that frame's level forbidden — the compiled body computes a binding at
/// its first read, which is only sound when no binding can reach itself or
/// a same-frame sibling. Non-static binding keys reject the shape (the
/// interpreter treats them as an evaluation error this grammar must never
/// bypass).
#[allow(clippy::too_many_arguments)]
fn scan_let_frame(
    arena: &IrArena,
    bindings: &[IrBinding],
    run_bindings: &[IrBinding],
    body: IrId,
    arity: u32,
    level: u32,
    context: &mut LetContext,
    body_scan: &mut ChainBodyScan,
) -> Result<(), JitLowerError> {
    for binding in run_bindings {
        if !matches!(binding.key, IrAttrPathSegment::Static(_)) {
            return Err(JitLowerError::UnsupportedArithOperand {
                operand: binding.value,
                kind: IrKind::Let,
            });
        }
        let value = unwrap_thunk_alloc(arena, binding.value)?;
        context.forbidden.push(level);
        let scanned = scan_chain_expr(arena, bindings, value, arity, context, body_scan);
        context.forbidden.pop();
        scanned?;
    }
    scan_chain_expr(arena, bindings, body, arity, context, body_scan)
}

/// Interprets one frame read (`LocalVar` is distance 0, `UpvalVar { depth }`
/// distance `depth`) under the current let context.
fn scan_frame_read(
    at: IrId,
    kind: IrKind,
    distance: u32,
    slot: u32,
    arity: u32,
    context: &LetContext,
    body_scan: &mut ChainBodyScan,
) -> Result<(), JitLowerError> {
    let reject = Err(JitLowerError::UnsupportedArithOperand { operand: at, kind });
    let let_depth = context.scopes.len() as u32;
    if distance < let_depth {
        // A let-binding read: reject forbidden levels (the letrec
        // restriction) and out-of-range slots.
        let level = let_depth - 1 - distance;
        if context.forbidden.contains(&level) {
            return reject;
        }
        let Some(size) = context.scopes.get(level as usize) else {
            return reject;
        };
        if slot >= *size {
            return reject;
        }
        return Ok(());
    }
    let normalized = distance - let_depth;
    if normalized < arity {
        // A chain-parameter read: parameter frames are single-slot.
        if slot != 0 {
            return reject;
        }
        return Ok(());
    }
    // A value read of an upvalue beyond the chain parameters is an
    // environment read against the boundary env pointer; the emitter forces
    // it at first strict use and guards it as an integer.
    body_scan.reads_env = true;
    Ok(())
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
        (IrKind::BinOp, IrData::Binary { op, lhs, rhs }) => {
            require_arith_binop(op)?;
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

/// Requires a binary operator the chain emitter compiles.
///
/// The emitter supports exactly integer arithmetic and comparisons; any other
/// operator (`//`, `++`, string concatenation, logic) fails the scan here so
/// an out-of-grammar body is a **structural** decision at scan time rather
/// than an emit-time surprise — a def-site whose body could never lower must
/// not linger in transient promotion retries just because its callee
/// bindings are unforced.
fn require_arith_binop(op: BinOpKind) -> Result<(), JitLowerError> {
    match op {
        BinOpKind::Add
        | BinOpKind::Sub
        | BinOpKind::Mul
        | BinOpKind::Div
        | BinOpKind::Lt
        | BinOpKind::Gt
        | BinOpKind::Le
        | BinOpKind::Ge
        | BinOpKind::Eq
        | BinOpKind::Ne => Ok(()),
        op => Err(JitLowerError::UnsupportedArithOp { op }),
    }
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

/// Unwraps a lazy `ThunkAlloc` wrapper around an argument or binding value.
pub(super) fn unwrap_thunk_alloc(arena: &IrArena, id: IrId) -> Result<IrId, JitLowerError> {
    let node = arena
        .node(id)
        .copied()
        .ok_or(JitLowerError::MissingIrBody { body: id })?;
    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => Ok(body),
        _ => Ok(id),
    }
}
