//! Beta-reduction of literal lambda applications (doc 26 §2.1, full cut).
//!
//! `Apply(Lambda(param, body), arg)` — a lambda literal applied in place — is
//! rewritten to `Let { param = arg; in body }` **reusing the lambda's own
//! resolver frame**. The observation making this arena-stable rather than a
//! compacting rebuild: a simple-param lambda frame and a one-binding `let`
//! frame have the *same* layout (one slot, slot `0`), and for a *literal*
//! lambda the lexical environment at the apply site is the lambda's own
//! definition environment. The body therefore keeps every de-Bruijn reference
//! unchanged — `Local { 0 }` reads the binding where it read the parameter,
//! and every `Upval` crosses exactly the frames it crossed before.
//!
//! The one adjustment is on the **argument** subtree: as an apply argument it
//! evaluated in the caller's frame, but as a `let` binding value it evaluates
//! inside the new `let` frame, one binder deeper. Every reference in the
//! argument that crosses the argument's own nested binders is therefore
//! shifted by one (`Local { s }` → `Upval { 1, s }`, `Upval { d, s }` →
//! `Upval { d + 1, s }`), in place, with the classic shift cutoff through
//! nested `Lambda`/`Let`/recursive-`AttrSet` frames. The argument subtree is
//! uniquely owned by its apply node (the lowered IR is a tree), so in-place
//! rewriting is sound and preserves every `IrId` and span.
//!
//! # What the rewrite buys
//!
//! The evaluator's apply path allocates a closure (environment, `with`, and
//! scoped-global captures), dispatches the application, and binds the argument
//! into a fresh frame. The `let` path allocates one linked frame and fills one
//! slot. On workloads dominated by immediate lambda application the rewrite
//! removes the closure allocation and the apply dispatch entirely, and it
//! exposes the body to the other passes (a `Once` binding then inlines, a dead
//! one elides, literals fold).
//!
//! # Soundness
//!
//! * **Laziness** is preserved: the lowered apply argument is already lazy
//!   (`ThunkAlloc` or a trivial literal) and becomes the binding value
//!   verbatim, which the `let` evaluator thunks with the same semantics.
//! * **Dynamic scope** is preserved: a `with` in scope at the apply site is
//!   captured by a lambda closure and is equally in scope for the `let` body
//!   evaluated at the same position; `with` adds no environment frame, so the
//!   shift cutoff ignores it.
//! * **Effects** are preserved conservatively: the rewritten node keeps the
//!   apply node's own effect stamp, and the transform changes no evaluation
//!   order (the body was evaluated immediately by the apply; the `let` body
//!   evaluates immediately too).
//! * Formal-set patterns (`{ a, b, ... }@args: …`) are declined: destructuring
//!   introduces per-formal defaults and partial strictness on the argument
//!   that a one-binding `let` does not replicate.

use crate::syntax::Span;

use super::{
    Ir, IrAttrPathSegment, IrBinding, IrBindingSlice, IrData, IrId, IrKind, IrNode, PassOutcome,
    SimplifyError, SimplifyPass, SimplifyPhase,
};

/// The literal-lambda beta-reduction pass.
///
/// See the [module documentation](self) for the transform and its soundness
/// argument. This is a zero-sized pass with no configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BetaReduceApply;

impl SimplifyPass for BetaReduceApply {
    fn name(&self) -> &'static str {
        "beta-reduce-apply"
    }

    fn runs_in(&self, phase: SimplifyPhase) -> bool {
        matches!(phase, SimplifyPhase::Main)
    }

    fn run(&self, ir: &mut Ir) -> Result<PassOutcome, SimplifyError> {
        let mut changed = false;
        let node_count = ir.arena.nodes().len();
        for index in 0..node_count {
            let Ok(raw) = u32::try_from(index) else {
                break;
            };
            let apply_id = IrId::new(raw);
            if reduce_apply_site(ir, apply_id) {
                changed = true;
            }
        }
        Ok(if changed {
            PassOutcome::Rewritten
        } else {
            PassOutcome::Unchanged
        })
    }
}

/// A validated `Apply(Lambda-literal, arg)` site eligible for reduction.
struct BetaSite {
    /// The lazy argument subtree root (the future binding value).
    argument: IrId,
    /// The lambda body (the future `let` body).
    body: IrId,
    /// The lambda's resolver frame, reused as the `let` frame.
    frame: crate::scope::FrameId,
    /// The parameter symbol (the future binding key).
    param: crate::syntax::Symbol,
    /// The parameter node span, recorded as the binding position.
    param_span: Span,
    /// The apply node's effect stamp, retained on the rewritten `let`.
    /// (`set_node` preserves the node's span, so no span is carried here.)
    effect: super::EffectClass,
}

/// Rewrites one eligible apply site in place. Returns whether the IR changed.
fn reduce_apply_site(ir: &mut Ir, apply_id: IrId) -> bool {
    let Some(site) = eligible_site(ir, apply_id) else {
        return false;
    };
    // The binding table must stay `u32`-addressable; decline instead of erroring
    // (the apply form remains valid IR).
    let Ok(binding_start) = u32::try_from(ir.bindings.len()) else {
        return false;
    };
    // Shift the argument's free references one binder deeper. This mutates the
    // argument subtree, so it must be the last fallible step before committing;
    // `shift_free_refs` only declines (without mutating) on depth overflow.
    if !shift_free_refs(ir, site.argument, 0) {
        return false;
    }
    let mut bindings = std::mem::take(&mut ir.bindings).into_vec();
    bindings.push(IrBinding {
        key: IrAttrPathSegment::Static(site.param),
        position: Some(site.param_span),
        value: site.argument,
    });
    ir.bindings = bindings.into_boxed_slice();
    let _ = ir.arena.set_node(
        apply_id,
        IrKind::Let,
        site.effect,
        IrData::Let {
            bindings: IrBindingSlice::new(binding_start, 1),
            body: site.body,
            frame: Some(site.frame),
        },
    );
    true
}

/// Validates that `apply_id` is an `Apply` of a literal simple-param lambda and
/// returns the site facts needed for the rewrite.
///
/// Declines formal-set patterns, missing frames, frames whose slot layout is
/// not exactly the single parameter slot, and anything that is not a direct
/// `Apply(Lambda, arg)` pair.
fn eligible_site(ir: &Ir, apply_id: IrId) -> Option<BetaSite> {
    let apply = ir.arena.node(apply_id)?;
    if apply.kind != IrKind::Apply {
        return None;
    }
    let IrData::Pair {
        first: function,
        second: argument,
    } = apply.data
    else {
        return None;
    };
    let lambda = ir.arena.node(function)?;
    if lambda.kind != IrKind::Lambda {
        return None;
    }
    let IrData::Lambda {
        pattern,
        body,
        frame,
    } = lambda.data
    else {
        return None;
    };
    let frame = frame?;
    // A one-binding `let` requires a one-slot frame (`eval_let` checks the
    // binding count against the frame's slot count).
    if ir.frames.get(frame.index())?.slot_count != 1 {
        return None;
    }
    let pattern_node = ir.arena.node(pattern)?;
    let IrData::Formal {
        name,
        default: None,
    } = pattern_node.data
    else {
        // Formal sets (and defaulted formals, which cannot occur on a simple
        // parameter) are declined; see the module docs.
        return None;
    };
    if pattern_node.kind != IrKind::Formal {
        return None;
    }
    Some(BetaSite {
        argument,
        body,
        frame,
        param: name,
        param_span: pattern_node.span,
        effect: apply.effect,
    })
}

/// Shifts every reference in the subtree at `id` that crosses `cutoff` nested
/// binders one frame deeper, in place.
///
/// `cutoff` counts the frame binders entered *within* the subtree; a
/// `Local` at cutoff `0` and any `Upval { depth >= cutoff }` reference the
/// world outside the subtree and gain one frame of depth. References resolved
/// entirely inside the subtree are untouched.
///
/// Returns `false` (without mutating the crossing reference) when a shifted
/// depth would overflow; callers decline the whole rewrite in that case.
/// Earlier siblings may already have been shifted when a later one overflows —
/// that cannot happen in practice (`u32::MAX` frame depth is unconstructable
/// by the resolver), and the bail-out exists to keep the arithmetic total.
fn shift_free_refs(ir: &mut Ir, id: IrId, cutoff: u32) -> bool {
    let Some(node) = ir.arena.node(id).copied() else {
        return true;
    };
    match node.data {
        IrData::Local { slot } => {
            if cutoff == 0 {
                let _ = ir.arena.set_node(
                    id,
                    IrKind::UpvalVar,
                    node.effect,
                    IrData::Upval { depth: 1, slot },
                );
            }
            true
        }
        IrData::Upval { depth, slot } => {
            if depth >= cutoff {
                let Some(depth) = depth.checked_add(1) else {
                    return false;
                };
                let _ =
                    ir.arena
                        .set_node(id, node.kind, node.effect, IrData::Upval { depth, slot });
            }
            true
        }
        _ => {
            let (same_depth, deeper) = shift_children(ir, &node);
            for child in same_depth {
                if !shift_free_refs(ir, child, cutoff) {
                    return false;
                }
            }
            for child in deeper {
                let Some(next) = cutoff.checked_add(1) else {
                    return false;
                };
                if !shift_free_refs(ir, child, next) {
                    return false;
                }
            }
            true
        }
    }
}

/// Splits a node's children into those evaluated at the current binder depth
/// and those evaluated one frame deeper.
///
/// Frame binders are `Lambda` (formal defaults and the body evaluate in the
/// lambda frame), `Let` (recursive: binding values and the body evaluate in
/// the let frame), and recursive `AttrSet` construction (binding values
/// evaluate in the set's frame; dynamic keys evaluate outside it). `with`
/// introduces no environment frame, so both its scrutinee and body stay at the
/// current depth.
fn shift_children(ir: &Ir, node: &IrNode) -> (Vec<IrId>, Vec<IrId>) {
    let mut same = Vec::new();
    let mut deeper = Vec::new();
    match node.data {
        IrData::None
        | IrData::Int(_)
        | IrData::Float(_)
        | IrData::Bool(_)
        | IrData::Symbol(_)
        | IrData::GlobalVar { .. }
        | IrData::Local { .. }
        | IrData::Upval { .. }
        | IrData::DialectScopeVar { .. } => {}
        IrData::SearchPath { search_path, .. } => same.extend(search_path),
        IrData::Node(child) => same.push(child),
        IrData::Pair { first, second } => same.extend([first, second]),
        IrData::Triple {
            first,
            second,
            third,
        } => same.extend([first, second, third]),
        IrData::Binary { lhs, rhs, .. } => same.extend([lhs, rhs]),
        IrData::Unary { operand, .. } => same.push(operand),
        IrData::DialectNode { argument, .. } => same.push(argument),
        IrData::Children(slice) | IrData::PrimOp { args: slice, .. } => {
            if let Some(ids) = ir.arena.child_slice(slice) {
                same.extend_from_slice(ids);
            }
        }
        IrData::Select {
            receiver,
            path,
            default,
            ..
        } => {
            same.push(receiver);
            same.extend(dynamic_path_segments(ir, path));
            same.extend(default);
        }
        IrData::HasAttr { receiver, path, .. } => {
            same.push(receiver);
            same.extend(dynamic_path_segments(ir, path));
        }
        IrData::Bindings(slice) => {
            let (keys, values) = binding_keys_and_values(ir, slice);
            same.extend(keys);
            same.extend(values);
        }
        IrData::AttrSet {
            bindings,
            recursive,
            ..
        } => {
            let (keys, values) = binding_keys_and_values(ir, bindings);
            // Dynamic keys evaluate outside a recursive set's frame; values
            // evaluate inside it.
            same.extend(keys);
            if recursive {
                deeper.extend(values);
            } else {
                same.extend(values);
            }
        }
        IrData::Lambda { pattern, body, .. } => {
            // Formal defaults evaluate inside the lambda frame, as does the
            // body; the pattern skeleton itself carries no references.
            deeper.push(pattern);
            deeper.push(body);
        }
        IrData::Let { bindings, body, .. } => {
            let (keys, values) = binding_keys_and_values(ir, bindings);
            // `let` binding keys are static; dynamic keys cannot occur, but
            // route any through the outer depth for shape-totality.
            same.extend(keys);
            deeper.extend(values);
            deeper.push(body);
        }
        IrData::FormalSet { formals, .. } => {
            if let Some(ids) = ir.arena.child_slice(formals) {
                same.extend_from_slice(ids);
            }
        }
        IrData::Formal { default, .. } => same.extend(default),
    }
    (same, deeper)
}

/// The dynamic (`${...}`) segment nodes of an attribute path.
fn dynamic_path_segments(ir: &Ir, path: super::IrAttrPathId) -> Vec<IrId> {
    match ir.attr_paths.get(path.index()) {
        Some(segments) => segments
            .iter()
            .filter_map(|segment| match segment {
                IrAttrPathSegment::Static(_) => None,
                IrAttrPathSegment::Dynamic(node) => Some(*node),
            })
            .collect(),
        None => Vec::new(),
    }
}

/// The dynamic key nodes and value nodes of a binding run, separately.
fn binding_keys_and_values(ir: &Ir, slice: IrBindingSlice) -> (Vec<IrId>, Vec<IrId>) {
    let start = slice.start as usize;
    let Some(end) = start.checked_add(slice.len()) else {
        return (Vec::new(), Vec::new());
    };
    let mut keys = Vec::new();
    let mut values = Vec::new();
    if let Some(bindings) = ir.bindings.get(start..end) {
        for binding in bindings {
            if let IrAttrPathSegment::Dynamic(key) = binding.key {
                keys.push(key);
            }
            values.push(binding.value);
        }
    }
    (keys, values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ConstFold, InlineSingleUse, lower, simplify_with_passes};
    use crate::scope::resolve;
    use crate::syntax::parse_str;

    fn lower_source(source: &str) -> Ir {
        let parsed = parse_str(source).expect("source parses");
        let resolved = resolve(parsed).expect("source resolves");
        lower(resolved).expect("source lowers")
    }

    /// Finds the first node of `kind`, if any.
    fn find_kind(ir: &Ir, kind: IrKind) -> Option<IrId> {
        (0..ir.arena.nodes().len()).map(|i| IrId::new(i as u32)).find(|id| {
            ir.arena
                .node(*id)
                .is_some_and(|node| node.kind == kind)
        })
    }

    fn frame_slot_counts(ir: &Ir) -> Vec<u32> {
        ir.frames.iter().map(|frame| frame.slot_count).collect()
    }

    #[test]
    fn reduces_literal_apply_to_let_preserving_frames() {
        let mut ir = lower_source("(x: x) 2");
        let slots_before = frame_slot_counts(&ir);
        assert!(find_kind(&ir, IrKind::Apply).is_some(), "starts as an apply");
        simplify_with_passes(&mut ir, &[&BetaReduceApply]).expect("beta succeeds");
        assert!(find_kind(&ir, IrKind::Apply).is_none(), "the apply is gone");
        let root = ir.arena.node(ir.root).expect("root");
        let IrData::Let {
            bindings, frame, ..
        } = root.data
        else {
            panic!("root rewrote to a let, got {root:?}");
        };
        assert_eq!(bindings.len(), 1, "one binding for the one parameter");
        assert!(frame.is_some(), "the lambda frame is reused");
        assert_eq!(
            slots_before,
            frame_slot_counts(&ir),
            "frame layouts are untouched"
        );
    }

    #[test]
    fn composes_with_inline_and_fold() {
        // Beta exposes `let x = 2; in x + 1`; inline + fold reduce it to 3.
        let mut ir = lower_source("(x: x + 1) 2");
        simplify_with_passes(&mut ir, &[&BetaReduceApply, &InlineSingleUse, &ConstFold])
            .expect("simplify succeeds");
        let IrData::Let { body, .. } = ir.arena.node(ir.root).expect("root").data else {
            panic!("root is the beta-produced let");
        };
        assert_eq!(
            ir.arena.node(body).expect("body").data,
            IrData::Int(3),
            "beta + inline + fold reduce the application to a literal"
        );
    }

    #[test]
    fn shifts_free_argument_references_one_binder_deeper() {
        // The argument `a` references the outer let frame. As a binding value
        // one frame deeper it must become `Upval { 1, slot_a }`.
        let mut ir = lower_source("let a = 5; in (x: x) a");
        simplify_with_passes(&mut ir, &[&BetaReduceApply]).expect("beta succeeds");
        let IrData::Let { body, .. } = ir.arena.node(ir.root).expect("root").data else {
            panic!("root is the outer let");
        };
        let IrData::Let { bindings, .. } = ir.arena.node(body).expect("inner").data else {
            panic!("body is the beta-produced let");
        };
        let binding = ir.bindings[bindings.start as usize];
        // The binding value may be the reference itself or a thunk around it;
        // find the reference beneath it.
        let mut value = binding.value;
        loop {
            let node = ir.arena.node(value).expect("value node");
            match node.data {
                IrData::Node(inner) => value = inner,
                IrData::Upval { depth, .. } => {
                    assert_eq!(depth, 1, "the free reference gained one frame");
                    assert_eq!(node.kind, IrKind::UpvalVar);
                    break;
                }
                other => panic!("expected a shifted upvalue, found {other:?}"),
            }
        }
    }

    #[test]
    fn shift_cutoff_skips_argument_internal_frames() {
        // The argument is itself a lambda whose body references `a` across its
        // own frame (`Upval { 1 }` before the rewrite). After the rewrite the
        // reference crosses the new let frame too: `Upval { 2 }`.
        let mut ir = lower_source("let a = 1; in (x: x) (y: a)");
        simplify_with_passes(&mut ir, &[&BetaReduceApply]).expect("beta succeeds");
        let upval = find_kind(&ir, IrKind::UpvalVar).expect("an upval survives");
        let IrData::Upval { depth, .. } = ir.arena.node(upval).expect("upval").data else {
            panic!("upval payload");
        };
        assert_eq!(
            depth, 2,
            "a reference crossing the argument's own lambda and the new let"
        );
        // The argument lambda's own parameter reference, if any, is untouched —
        // `y` is unused here, so just assert the internal lambda survived.
        assert!(find_kind(&ir, IrKind::Lambda).is_some());
    }

    #[test]
    fn declines_formal_set_lambda() {
        let mut ir = lower_source("({ a }: a) { a = 1; }");
        let before = ir.arena.nodes().to_vec();
        simplify_with_passes(&mut ir, &[&BetaReduceApply]).expect("beta succeeds");
        assert_eq!(
            before,
            ir.arena.nodes(),
            "formal-set patterns are declined unchanged"
        );
    }

    #[test]
    fn declines_non_literal_function() {
        let mut ir = lower_source("let f = x: x; in f 2");
        let before = ir.arena.nodes().to_vec();
        simplify_with_passes(&mut ir, &[&BetaReduceApply]).expect("beta succeeds");
        assert_eq!(
            before,
            ir.arena.nodes(),
            "only literal lambda applications are reduced"
        );
    }

    #[test]
    fn reduces_curried_literal_chain_outer_stage() {
        // `(x: y: x) 1 2` — the inner apply's function is a lambda literal
        // after the outer reduction exposes it across sweeps.
        let mut ir = lower_source("(x: y: x) 1 2");
        simplify_with_passes(&mut ir, &[&BetaReduceApply]).expect("beta succeeds");
        // At least the inner application (of the two-level chain) reduces on
        // the first sweep; the fixpoint driver reduces the rest across sweeps.
        assert!(
            find_kind(&ir, IrKind::Let).is_some(),
            "at least one stage of the curried chain reduced to a let"
        );
    }
}
