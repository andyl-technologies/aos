//! Fusability analysis for string-interpolation (`IrKind::Interp`) thunk bodies.
//!
//! A tier-1 *fused* interpolation body evaluates a whole `"${a}/${b}"` in one
//! native call: it forces each dynamic part inline (no per-part `eval_node`
//! dispatch, no per-literal-chunk heap allocation) and delegates only the
//! irreducible coerce-and-concatenate to a single runtime helper. That fusion is
//! only sound for a restricted child grammar, so this module classifies an
//! interpolation body before the lowerer commits to it.
//!
//! # Supported (fusable) grammar
//!
//! An interpolation body is [`InterpFusibility::Fusable`] when it is an
//! `IrData::Children` run in which every child is one of:
//!
//! - a literal string chunk ([`IrKind::Str`]) — the helper resolves its bytes
//!   directly from the symbol table, so the tree walk's per-chunk heap string is
//!   never allocated; or
//! - a `${expr}` fragment, which lowers to a single-child `Interp(Node=inner)`
//!   coercion wrapper, whose `inner` is an inline-forceable slot read
//!   ([`IrKind::LocalVar`] or [`IrKind::UpvalVar`]) — the native body loads and
//!   forces it, exactly as the tree walk's `eval_node` would, and hands the
//!   forced value to the helper. A bare slot read (an unwrapped fragment) is
//!   accepted the same way.
//!
//! Any other child shape — including a fragment wrapping a select, application,
//! or other non-slot expression — is not inline-forceable and yields
//! [`InterpFusibility::ComplexChild`]. A [`IrKind::Path`] fragment routes the
//! whole interpolation to the path-building path (a different result type) and
//! yields [`InterpFusibility::PathFragment`]. The degenerate single-child and
//! empty forms are reported distinctly so the caller can handle them without a
//! fused loop.
//!
//! This module is analysis only: it inspects the arena and returns a
//! classification. It does not emit CLIF.

use ratchet_core::{IrArena, IrData, IrId, IrKind};

/// The tier-1 fusability classification of an interpolation thunk body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterpFusibility {
    /// The body is not an interpolation node (after unwrapping one `ThunkAlloc`).
    NotInterp,
    /// An empty interpolation (`IrData::None`); it yields the empty string.
    Empty,
    /// A single-child interpolation (`"${expr}"` with no surrounding chunks); it
    /// coerces one value and needs no fused accumulation loop.
    SingleChild,
    /// A multi-part interpolation whose every child is a literal chunk or an
    /// inline-forceable slot read, with no path fragment.
    ///
    /// `dynamic_parts` counts the `LocalVar`/`UpvalVar` children the native body
    /// forces inline; `literal_parts` counts the `Str` chunks the helper resolves
    /// directly. Their sum is the number of IR child nodes the fused body
    /// collapses into one dispatch.
    Fusable {
        /// Inline-forceable slot-read children.
        dynamic_parts: u32,
        /// Literal string-chunk children.
        literal_parts: u32,
    },
    /// A multi-part interpolation containing a child that cannot be forced inline
    /// (a nested expression, application, select, and so on).
    ComplexChild,
    /// A multi-part interpolation containing a [`IrKind::Path`] fragment, which
    /// builds a path rather than a plain string.
    PathFragment,
}

impl InterpFusibility {
    /// Returns the number of IR child nodes a fused body would collapse into one
    /// native dispatch, or `0` for a non-fusable classification.
    ///
    /// This is the "fused node count" profit proxy: unlike the raw native
    /// instruction census it is not inflated by the per-part helper-call
    /// scaffolding, so it measures how much interpreter dispatch the fusion
    /// actually removes.
    #[must_use]
    pub const fn fused_node_count(&self) -> u32 {
        match self {
            Self::Fusable {
                dynamic_parts,
                literal_parts,
            } => dynamic_parts.saturating_add(*literal_parts),
            _ => 0,
        }
    }

    /// Returns a compact diagnostic key naming this classification.
    ///
    /// Fusable bodies are bucketed by their fused node count (e.g.
    /// `"fusable:n4"`) so a shape histogram shows the part-count distribution
    /// that drives fusion profit; every other classification maps to a fixed
    /// label. Intended for the `AOS_NIX_EVAL_STATS` interpolation-shape report.
    #[must_use]
    pub fn histogram_key(&self) -> String {
        match self {
            Self::NotInterp => "not-interp".to_owned(),
            Self::Empty => "empty".to_owned(),
            Self::SingleChild => "single".to_owned(),
            Self::Fusable { .. } => format!("fusable:n{}", self.fused_node_count()),
            Self::ComplexChild => "complex-child".to_owned(),
            Self::PathFragment => "path-fragment".to_owned(),
        }
    }
}

/// Classifies the tier-1 fusability of an interpolation thunk body at `root`.
///
/// Unwraps at most one [`IrKind::ThunkAlloc`] wrapper, then inspects the
/// interpolation payload and its children. See the [module docs](self) for the
/// grammar behind each [`InterpFusibility`].
#[must_use]
pub fn classify_interp_thunk_body(arena: &IrArena, root: IrId) -> InterpFusibility {
    let Some(node) = arena.node(root).copied() else {
        return InterpFusibility::NotInterp;
    };
    let interp = match (node.kind, node.data) {
        (IrKind::Interp, _) => node,
        (IrKind::ThunkAlloc, IrData::Node(body)) => match arena.node(body).copied() {
            Some(inner) => inner,
            None => return InterpFusibility::NotInterp,
        },
        _ => return InterpFusibility::NotInterp,
    };
    if interp.kind != IrKind::Interp {
        return InterpFusibility::NotInterp;
    }
    match interp.data {
        IrData::None => InterpFusibility::Empty,
        IrData::Node(_) => InterpFusibility::SingleChild,
        IrData::Children(children) => {
            let Some(ids) = arena.child_slice(children) else {
                return InterpFusibility::NotInterp;
            };
            classify_children(arena, ids)
        }
        _ => InterpFusibility::NotInterp,
    }
}

/// Returns the IR node kinds of a multi-part interpolation body's children.
///
/// Unwraps at most one [`IrKind::ThunkAlloc`] wrapper around the interpolation,
/// then returns each `IrData::Children` child's kind in order. Returns an empty
/// vector for a non-`Children` interpolation or a non-interpolation body. This is
/// a diagnostic used to break down why interpolation bodies are (or are not)
/// fusable — i.e. what the non-slot, non-literal children actually are.
#[must_use]
pub fn interp_child_kinds(arena: &IrArena, root: IrId) -> Vec<IrKind> {
    let Some(node) = arena.node(root).copied() else {
        return Vec::new();
    };
    let interp = match (node.kind, node.data) {
        (IrKind::Interp, _) => node,
        (IrKind::ThunkAlloc, IrData::Node(body)) => match arena.node(body).copied() {
            Some(inner) => inner,
            None => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    let IrData::Children(children) = interp.data else {
        return Vec::new();
    };
    let Some(ids) = arena.child_slice(children) else {
        return Vec::new();
    };
    ids.iter()
        .filter_map(|id| arena.node(*id).map(|node| node.kind))
        .collect()
}

/// Returns the inner kinds of a body's `${expr}` fragment children.
///
/// For each child that is a `${expr}` coercion wrapper (`Interp(Node=inner)`),
/// returns `inner`'s IR kind; other children are skipped. This is the census
/// that reveals whether interpolation fragments wrap simple slot reads (fusable)
/// or complex expressions (selects, applications).
#[must_use]
pub fn interp_child_inner_kinds(arena: &IrArena, root: IrId) -> Vec<IrKind> {
    let Some(node) = arena.node(root).copied() else {
        return Vec::new();
    };
    let interp = match (node.kind, node.data) {
        (IrKind::Interp, _) => node,
        (IrKind::ThunkAlloc, IrData::Node(body)) => match arena.node(body).copied() {
            Some(inner) => inner,
            None => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    let IrData::Children(children) = interp.data else {
        return Vec::new();
    };
    let Some(ids) = arena.child_slice(children) else {
        return Vec::new();
    };
    ids.iter()
        .filter_map(|id| arena.node(*id).copied())
        .filter_map(|child| match (child.kind, child.data) {
            (IrKind::Interp, IrData::Node(inner)) => arena.node(inner).map(|node| node.kind),
            _ => None,
        })
        .collect()
}

/// Classifies the children of a multi-part interpolation.
///
/// Returns [`InterpFusibility::PathFragment`] as soon as any child is a path
/// (it dominates the result type), [`InterpFusibility::ComplexChild`] for any
/// non-slot non-literal child, and otherwise [`InterpFusibility::Fusable`] with
/// the dynamic and literal part counts.
fn classify_children(arena: &IrArena, ids: &[IrId]) -> InterpFusibility {
    let mut dynamic_parts: u32 = 0;
    let mut literal_parts: u32 = 0;
    for id in ids {
        let Some(child) = arena.node(*id).copied() else {
            return InterpFusibility::NotInterp;
        };
        match child.kind {
            IrKind::Path => return InterpFusibility::PathFragment,
            IrKind::Str => literal_parts = literal_parts.saturating_add(1),
            IrKind::LocalVar | IrKind::UpvalVar => {
                dynamic_parts = dynamic_parts.saturating_add(1);
            }
            // A `${expr}` fragment lowers to a single-child `Interp(Node=inner)`
            // coercion wrapper; it is fusable only when `inner` is an
            // inline-forceable slot read. A path inner routes to the path builder.
            IrKind::Interp => match interp_fragment_inner(arena, child) {
                Some(inner) => match inner {
                    IrKind::LocalVar | IrKind::UpvalVar => {
                        dynamic_parts = dynamic_parts.saturating_add(1);
                    }
                    IrKind::Path => return InterpFusibility::PathFragment,
                    _ => return InterpFusibility::ComplexChild,
                },
                None => return InterpFusibility::ComplexChild,
            },
            _ => return InterpFusibility::ComplexChild,
        }
    }
    InterpFusibility::Fusable {
        dynamic_parts,
        literal_parts,
    }
}

/// Returns the inner expression kind of a `${expr}` coercion-wrapper fragment.
///
/// A fragment is a single-child `Interp(Node=inner)`; returns `inner`'s kind, or
/// `None` for any other interpolation payload (a nested multi-part or empty
/// fragment), which is not inline-forceable.
fn interp_fragment_inner(arena: &IrArena, fragment: ratchet_core::IrNode) -> Option<IrKind> {
    match fragment.data {
        IrData::Node(inner) => arena.node(inner).map(|node| node.kind),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ratchet_core::{
        EffectClass, IrNode,
        syntax::{Span, Symbol},
    };

    fn node(kind: IrKind, data: IrData) -> IrNode {
        IrNode::new(kind, Span::new(0, 1), EffectClass::pure(), data)
    }

    fn arena(nodes: Vec<IrNode>) -> IrArena {
        IrArena::from_raw_parts(nodes, Vec::new())
    }

    /// An interpolation of literal chunks and slot reads is fusable, and its part
    /// counts and fused-node count reflect the children.
    #[test]
    fn literal_and_slot_children_are_fusable() {
        // 0:Str  1:LocalVar  2:Str  3:UpvalVar  4:Interp[0,1,2,3]
        let nodes = vec![
            node(IrKind::Str, IrData::Symbol(Symbol::new(0))),
            node(IrKind::LocalVar, IrData::Local { slot: 0 }),
            node(IrKind::Str, IrData::Symbol(Symbol::new(1))),
            node(IrKind::UpvalVar, IrData::Upval { depth: 1, slot: 0 }),
        ];
        let mut nodes = nodes;
        let children = IrChildSliceBuilder::of(&[0, 1, 2, 3]);
        nodes.push(node(IrKind::Interp, IrData::Children(children.slice)));
        let arena = IrArena::from_raw_parts(nodes, children.pool);
        let fusibility = classify_interp_thunk_body(&arena, IrId::new(4));
        assert_eq!(
            fusibility,
            InterpFusibility::Fusable {
                dynamic_parts: 2,
                literal_parts: 2,
            }
        );
        assert_eq!(fusibility.fused_node_count(), 4);
    }

    /// A child that is neither a literal nor a slot read is a complex child.
    #[test]
    fn complex_child_is_not_fusable() {
        // 0:Apply  1:Interp[0]
        let mut nodes = vec![node(IrKind::Apply, IrData::None)];
        let children = IrChildSliceBuilder::of(&[0]);
        nodes.push(node(IrKind::Interp, IrData::Children(children.slice)));
        let arena = IrArena::from_raw_parts(nodes, children.pool);
        assert_eq!(
            classify_interp_thunk_body(&arena, IrId::new(1)),
            InterpFusibility::ComplexChild
        );
    }

    /// A `${slot}` fragment (a single-child `Interp(Node=slot)` wrapper) is a
    /// fusable dynamic part, mirroring how real interpolations lower.
    #[test]
    fn wrapped_slot_fragment_is_fusable() {
        // 0:Str  1:LocalVar  2:Interp(Node=1)  3:Interp[0,2]
        let mut nodes = vec![
            node(IrKind::Str, IrData::Symbol(Symbol::new(0))),
            node(IrKind::LocalVar, IrData::Local { slot: 0 }),
            node(IrKind::Interp, IrData::Node(IrId::new(1))),
        ];
        let children = IrChildSliceBuilder::of(&[0, 2]);
        nodes.push(node(IrKind::Interp, IrData::Children(children.slice)));
        let arena = IrArena::from_raw_parts(nodes, children.pool);
        assert_eq!(
            classify_interp_thunk_body(&arena, IrId::new(3)),
            InterpFusibility::Fusable {
                dynamic_parts: 1,
                literal_parts: 1,
            }
        );
    }

    /// A `${a.b}` fragment (a select inside the coercion wrapper) is not fusable.
    #[test]
    fn wrapped_select_fragment_is_complex() {
        // 0:Select  1:Interp(Node=0)  2:Interp[1]
        let mut nodes = vec![
            node(IrKind::Select, IrData::None),
            node(IrKind::Interp, IrData::Node(IrId::new(0))),
        ];
        let children = IrChildSliceBuilder::of(&[1]);
        nodes.push(node(IrKind::Interp, IrData::Children(children.slice)));
        let arena = IrArena::from_raw_parts(nodes, children.pool);
        assert_eq!(
            classify_interp_thunk_body(&arena, IrId::new(2)),
            InterpFusibility::ComplexChild
        );
    }

    /// A path fragment routes the whole interpolation to the path builder.
    #[test]
    fn path_fragment_is_reported() {
        // 0:Str  1:Path  2:Interp[0,1]
        let mut nodes = vec![
            node(IrKind::Str, IrData::Symbol(Symbol::new(0))),
            node(IrKind::Path, IrData::Symbol(Symbol::new(1))),
        ];
        let children = IrChildSliceBuilder::of(&[0, 1]);
        nodes.push(node(IrKind::Interp, IrData::Children(children.slice)));
        let arena = IrArena::from_raw_parts(nodes, children.pool);
        assert_eq!(
            classify_interp_thunk_body(&arena, IrId::new(2)),
            InterpFusibility::PathFragment
        );
    }

    /// The empty and single-child degenerate forms report distinctly, and a
    /// non-interpolation body is `NotInterp`.
    #[test]
    fn degenerate_and_non_interp_forms() {
        let empty = arena(vec![node(IrKind::Interp, IrData::None)]);
        assert_eq!(
            classify_interp_thunk_body(&empty, IrId::new(0)),
            InterpFusibility::Empty
        );
        let single = arena(vec![
            node(IrKind::LocalVar, IrData::Local { slot: 0 }),
            node(IrKind::Interp, IrData::Node(IrId::new(0))),
        ]);
        assert_eq!(
            classify_interp_thunk_body(&single, IrId::new(1)),
            InterpFusibility::SingleChild
        );
        let not_interp = arena(vec![node(IrKind::LocalVar, IrData::Local { slot: 0 })]);
        assert_eq!(
            classify_interp_thunk_body(&not_interp, IrId::new(0)),
            InterpFusibility::NotInterp
        );
    }

    /// A `ThunkAlloc` wrapper around an interpolation is unwrapped once.
    #[test]
    fn thunk_alloc_wrapper_is_unwrapped() {
        // 0:LocalVar 1:Interp[node 0] 2:ThunkAlloc(1)
        let single = arena(vec![
            node(IrKind::LocalVar, IrData::Local { slot: 0 }),
            node(IrKind::Interp, IrData::Node(IrId::new(0))),
            node(IrKind::ThunkAlloc, IrData::Node(IrId::new(1))),
        ]);
        assert_eq!(
            classify_interp_thunk_body(&single, IrId::new(2)),
            InterpFusibility::SingleChild
        );
    }

    /// A small helper building an `IrChildSlice` plus its backing child pool.
    struct IrChildSliceBuilder {
        slice: ratchet_core::IrChildSlice,
        pool: Vec<IrId>,
    }

    impl IrChildSliceBuilder {
        fn of(ids: &[u32]) -> Self {
            let pool: Vec<IrId> = ids.iter().map(|id| IrId::new(*id)).collect();
            let slice = ratchet_core::IrChildSlice::new(0, pool.len() as u32);
            Self { slice, pool }
        }
    }
}
