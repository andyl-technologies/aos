//! Static frame-stack tracking and slot/callee resolution ("the chase").
//!
//! The scope-resolved IR references bindings through `(depth, slot)`
//! coordinates. During the analysis walks we maintain a stack of the
//! frame-introducing nodes on the current path (`let`, `rec { }`, lambda), so
//! a variable reference can be statically resolved back to the binding value
//! it names. The chase follows alias chains through `let`-bound values and
//! static attribute selection to find literal lambdas and literal attribute
//! sets entirely within the current module.

use crate::ir::{IrAttrPathSegment, IrBindingSlice, IrData, IrId, IrKind};
use crate::syntax::Symbol;

use super::{Analysis, StrictnessAnalysisError};

/// Maximum alias hops followed by one chase.
pub(super) const CHASE_BUDGET: usize = 32;

/// The `rec { }` override attribute that makes slot values non-static.
const OVERRIDES_ATTR: &[u8] = b"__overrides";

/// One frame-introducing node on the current walk path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FrameScope {
    /// The node that owns the frame.
    pub node: IrId,
    /// How slots map back to source bindings.
    pub kind: FrameKind,
}

/// How one frame's slots map back to binding values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FrameKind {
    /// A `let` frame: slot `i` is the `i`-th binding's value.
    Let {
        /// The let's binding run.
        bindings: IrBindingSlice,
    },
    /// A `rec { }` frame: slot `i` is the `i`-th *static* binding's value.
    ///
    /// Opaque frames (a `__overrides` binding is present, so slot values can
    /// be replaced at runtime) never resolve.
    RecAttrs {
        /// The attrset's binding run.
        bindings: IrBindingSlice,
        /// Whether runtime overrides make slot resolution unsound.
        opaque: bool,
    },
    /// A lambda frame: slots hold call arguments, unresolvable statically.
    Lambda,
}

impl FrameScope {
    /// Builds the frame scope for a frame-introducing node.
    pub(super) fn for_let(node: IrId, bindings: IrBindingSlice) -> Self {
        Self {
            node,
            kind: FrameKind::Let { bindings },
        }
    }

    /// Builds the frame scope for a recursive attrset literal.
    pub(super) fn for_rec_attrs(analysis: &Analysis<'_>, node: IrId, bindings: IrBindingSlice) -> Self {
        let opaque = analysis
            .bindings(node, bindings)
            .ok()
            .is_none_or(|bindings| {
                bindings.iter().any(|binding| match binding.key {
                    IrAttrPathSegment::Static(symbol) => {
                        analysis.ir.symbols.resolve(symbol) == Some(OVERRIDES_ATTR)
                    }
                    IrAttrPathSegment::Dynamic(_) => false,
                })
            });
        Self {
            node,
            kind: FrameKind::RecAttrs { bindings, opaque },
        }
    }

    /// Builds the frame scope for a lambda body.
    pub(super) const fn for_lambda(node: IrId) -> Self {
        Self {
            node,
            kind: FrameKind::Lambda,
        }
    }
}

/// Resolves one `(frame, slot)` coordinate to the binding value node.
///
/// Returns `Ok(None)` when the frame cannot be statically resolved (lambda
/// arguments, override-carrying recursive sets, out-of-range slots).
pub(super) fn resolve_slot(
    analysis: &Analysis<'_>,
    scope: FrameScope,
    slot: u32,
) -> Result<Option<IrId>, StrictnessAnalysisError> {
    match scope.kind {
        FrameKind::Let { bindings } => {
            let bindings = analysis.bindings(scope.node, bindings)?;
            Ok(bindings.get(slot as usize).map(|binding| binding.value))
        }
        FrameKind::RecAttrs { bindings, opaque } => {
            if opaque {
                return Ok(None);
            }
            let bindings = analysis.bindings(scope.node, bindings)?;
            Ok(bindings
                .iter()
                .filter(|binding| matches!(binding.key, IrAttrPathSegment::Static(_)))
                .nth(slot as usize)
                .map(|binding| binding.value))
        }
        FrameKind::Lambda => Ok(None),
    }
}

/// The outcome of chasing an expression to a statically-known callee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChasedCallee {
    /// A literal lambda node.
    Lambda(IrId),
    /// No statically-known callee.
    Unknown,
}

/// Chases an expression to a literal lambda through the current frame stack.
///
/// Follows variable references to `let` / non-opaque `rec` binding values,
/// unwraps `ThunkAlloc` wrappers, and resolves fully-static attribute
/// selection on chased attrset literals. Every hop stays within the current
/// module; `import` boundaries, lambda parameters, `with` scopes, and dynamic
/// keys end the chase conservatively.
pub(super) fn chase_callee(
    analysis: &Analysis<'_>,
    stack: &[FrameScope],
    node: IrId,
) -> Result<ChasedCallee, StrictnessAnalysisError> {
    let mut stack: Vec<FrameScope> = stack.to_vec();
    let mut node = node;
    for _ in 0..CHASE_BUDGET {
        let current = analysis.node(node)?;
        match current.data {
            IrData::Lambda { .. } => return Ok(ChasedCallee::Lambda(node)),
            IrData::Node(body) if current.kind == IrKind::ThunkAlloc => {
                node = body;
            }
            IrData::Local { slot } => {
                let Some(scope) = stack.last().copied() else {
                    return Ok(ChasedCallee::Unknown);
                };
                let Some(value) = resolve_slot(analysis, scope, slot)? else {
                    return Ok(ChasedCallee::Unknown);
                };
                node = value;
            }
            IrData::Upval { depth, slot } => {
                let index = stack.len().checked_sub(1 + depth as usize);
                let Some(index) = index else {
                    return Ok(ChasedCallee::Unknown);
                };
                let scope = stack[index];
                let Some(value) = resolve_slot(analysis, scope, slot)? else {
                    return Ok(ChasedCallee::Unknown);
                };
                // The binding value is evaluated inside its owning frame.
                stack.truncate(index + 1);
                node = value;
            }
            IrData::Select { receiver, path, .. } => {
                let segments = analysis.attr_path(node, path)?;
                let mut receiver = receiver;
                let mut resolved = None;
                // Only fully-static single-step selection is chased; deeper
                // static paths are followed one literal at a time.
                for segment in segments {
                    let IrAttrPathSegment::Static(symbol) = segment else {
                        return Ok(ChasedCallee::Unknown);
                    };
                    let Some((value, frame)) =
                        chase_static_attr(analysis, &mut stack, receiver, *symbol)?
                    else {
                        return Ok(ChasedCallee::Unknown);
                    };
                    if let Some(frame) = frame {
                        stack.push(frame);
                    }
                    receiver = value;
                    resolved = Some(value);
                }
                let Some(value) = resolved else {
                    return Ok(ChasedCallee::Unknown);
                };
                node = value;
            }
            _ => return Ok(ChasedCallee::Unknown),
        }
    }
    Ok(ChasedCallee::Unknown)
}

/// Resolves `receiver.symbol` when the receiver chases to an attrset literal.
///
/// Returns the selected binding value and, for recursive literals, the frame
/// scope its value nodes are evaluated in.
fn chase_static_attr(
    analysis: &Analysis<'_>,
    stack: &mut Vec<FrameScope>,
    receiver: IrId,
    symbol: Symbol,
) -> Result<Option<(IrId, Option<FrameScope>)>, StrictnessAnalysisError> {
    let Some(attrset) = chase_attrset_literal(analysis, stack, receiver)? else {
        return Ok(None);
    };
    let node = analysis.node(attrset)?;
    let IrData::AttrSet {
        bindings,
        recursive,
        has_dynamic,
        ..
    } = node.data
    else {
        return Ok(None);
    };
    if has_dynamic {
        // A dynamic key may shadow or collide with the static lookup.
        return Ok(None);
    }
    let entries = analysis.bindings(attrset, bindings)?;
    let selected = entries.iter().find(|binding| {
        matches!(binding.key, IrAttrPathSegment::Static(key) if key == symbol)
    });
    let Some(selected) = selected else {
        return Ok(None);
    };
    let frame = if recursive {
        let scope = FrameScope::for_rec_attrs(analysis, attrset, bindings);
        if matches!(scope.kind, FrameKind::RecAttrs { opaque: true, .. }) {
            return Ok(None);
        }
        Some(scope)
    } else {
        None
    };
    Ok(Some((selected.value, frame)))
}

/// Chases an expression to an attrset literal node, mutating `stack` to the
/// literal's own frame context.
pub(super) fn chase_attrset_literal(
    analysis: &Analysis<'_>,
    stack: &mut Vec<FrameScope>,
    node: IrId,
) -> Result<Option<IrId>, StrictnessAnalysisError> {
    let mut node = node;
    for _ in 0..CHASE_BUDGET {
        let current = analysis.node(node)?;
        match current.data {
            IrData::AttrSet { .. } => return Ok(Some(node)),
            IrData::Node(body) if current.kind == IrKind::ThunkAlloc => node = body,
            IrData::Local { slot } => {
                let Some(scope) = stack.last().copied() else {
                    return Ok(None);
                };
                let Some(value) = resolve_slot(analysis, scope, slot)? else {
                    return Ok(None);
                };
                node = value;
            }
            IrData::Upval { depth, slot } => {
                let Some(index) = stack.len().checked_sub(1 + depth as usize) else {
                    return Ok(None);
                };
                let scope = stack[index];
                let Some(value) = resolve_slot(analysis, scope, slot)? else {
                    return Ok(None);
                };
                stack.truncate(index + 1);
                node = value;
            }
            _ => return Ok(None),
        }
    }
    Ok(None)
}
