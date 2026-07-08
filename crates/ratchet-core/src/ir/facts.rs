//! Per-expression analysis facts attached to lowered IR.
//!
//! Whole-program optimization passes refine these facts over time. Until a
//! proof exists, every node carries conservative facts: unknown strictness,
//! many-use cardinality, and escaping allocation behavior.
//!
//! # Demand fact semantics
//!
//! Strictness facts are *relative to the node's nearest enclosing execution
//! unit*: the module root, the body of a `ThunkAlloc`, or the body of a
//! lambda. A demand proof on a node says "whenever that unit executes, this
//! node is evaluated", not "this node is evaluated whenever the module root
//! is". Consumers that act on a node's facts do so at the moment the node is
//! itself evaluated, so the relative reading is the one they need.
//!
//! The demand lattice is ordered `Unknown < Demanded < DemandedBeforeEffect`.
//! Only [`Strictness::DemandedBeforeEffect`] licenses eager lowering
//! ([`BindingLowering::Eager`] / [`BindingLowering::Scalar`]): evaluating a
//! binding at its allocation site is observationally invisible only when the
//! lazy program would have forced it before any observable event —
//! `throw`, `abort`, a failed `assert`, `trace` output, or divergence — could
//! occur (soundness rule S2). [`Strictness::Demanded`] proves S1 only
//! ("forced on every normally-completing path") and is consumed as a fan-out
//! hint and by passes that need existence-of-demand, never as an eager
//! license.

use super::IrId;

/// Whether evaluating an enclosing expression is known to demand this node.
///
/// Levels are relative to the node's nearest enclosing execution unit (module
/// root, thunk body, or lambda body); see the module documentation for the
/// exact reading and the soundness rules each level carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Strictness {
    /// The node is not proven to be demanded, so lazy lowering must be kept.
    #[default]
    Unknown,
    /// The node is proven to be evaluated on every normally-completing path
    /// of its enclosing execution unit (S1), but possibly only after another
    /// observable event may occur. Licenses fan-out hints, never eagerness.
    Demanded,
    /// The node is proven to be evaluated before any observable event of its
    /// enclosing execution unit can occur (S1 + S2). This is the only level
    /// that licenses eager lowering.
    DemandedBeforeEffect,
}

impl Strictness {
    /// Returns whether any positive demand proof exists (S1).
    pub const fn is_demanded(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// Returns whether the proof licenses eager evaluation (S1 + S2).
    pub const fn is_demanded_before_effect(self) -> bool {
        matches!(self, Self::DemandedBeforeEffect)
    }
}

/// How often a lowered binding or expression is known to be entered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Cardinality {
    /// The node is proven unused.
    Absent,
    /// The node is proven to be entered at most once.
    Once,
    /// The node may be entered more than once.
    #[default]
    Many,
}

/// Whether a value allocated by this node is known to stay frame-local.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Escape {
    /// The value is proven not to escape its allocating frame.
    NoEscape,
    /// The value may escape its allocating frame.
    #[default]
    Escapes,
}

/// Per-expression optimization facts attached to one IR node.
///
/// The default is intentionally conservative: unproven strictness keeps lazy
/// thunks, unproven cardinality keeps full update/blackhole machinery, and
/// unproven escape behavior keeps heap allocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExprFacts {
    /// Whether this node is proven demanded, and at which effect rank.
    pub strictness: Strictness,
    /// Whether this node is absent, single-entry, or many-entry.
    pub cardinality: Cardinality,
    /// Whether this node's allocation is proven frame-local.
    pub escape: Escape,
}

impl ExprFacts {
    /// Returns the conservative fact record used before analysis has proven more.
    pub const fn conservative() -> Self {
        Self {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        }
    }

    /// Returns the binding-lowering strategy licensed by these facts.
    ///
    /// Eager execution is licensed only by [`Strictness::DemandedBeforeEffect`]
    /// (S2: no observable event can be reordered by evaluating at the
    /// allocation site). Scalar replacement additionally requires a no-escape
    /// proof. [`Strictness::Demanded`] fails closed to a lazy thunk: it proves
    /// the binding is forced, not that forcing it early is invisible.
    pub const fn binding_lowering(self) -> BindingLowering {
        match (self.strictness, self.escape) {
            (Strictness::DemandedBeforeEffect, Escape::NoEscape) => BindingLowering::Scalar,
            (Strictness::DemandedBeforeEffect, Escape::Escapes) => BindingLowering::Eager,
            (Strictness::Unknown | Strictness::Demanded, _) => BindingLowering::Thunk,
        }
    }

    /// Returns the thunk-sharing mode licensed by these facts.
    ///
    /// Single-entry thunks are only safe when the cardinality proof says the
    /// thunk is entered at most once and the escape proof keeps it frame-local.
    /// A proof of absence licenses omitting the thunk entirely unless another
    /// fact contradicts it by proving the binding demanded at any level.
    pub const fn thunk_sharing(self) -> ThunkSharing {
        match (self.cardinality, self.strictness, self.escape) {
            (Cardinality::Absent, Strictness::Unknown, _) => ThunkSharing::Omit,
            (
                Cardinality::Absent,
                Strictness::Demanded | Strictness::DemandedBeforeEffect,
                _,
            )
            | (Cardinality::Once | Cardinality::Many, _, Escape::Escapes)
            | (Cardinality::Many, _, Escape::NoEscape) => ThunkSharing::Update,
            (Cardinality::Once, _, Escape::NoEscape) => ThunkSharing::SingleEntry,
        }
    }
}

/// Strategy for lowering one binding-position expression.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum BindingLowering {
    /// Allocate a lazy thunk and force it on demand.
    #[default]
    Thunk,
    /// Evaluate eagerly and pass the WHNF value directly.
    Eager,
    /// Evaluate eagerly and keep a non-escaping result out of the heap.
    Scalar,
}

/// Sharing/update machinery required for a thunk-like binding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ThunkSharing {
    /// Keep normal update and blackhole state for sharing and cycle detection.
    #[default]
    Update,
    /// Use a single-entry representation for a frame-local used-once thunk.
    SingleEntry,
    /// Omit code and storage for a proven-absent binding.
    Omit,
}

/// Per-node analysis facts for one lowered IR artifact.
///
/// Entries are indexed by [`IrId`] and are expected to stay in one-to-one order
/// with the node arena. Alongside the per-node [`ExprFacts`] records the table
/// carries a per-node `tryEval` barrier bit: nodes that root the argument
/// subtree of a `builtins.tryEval` application. No transform in the current
/// pipeline consumes the bit; it is persisted for future relocation passes
/// (S4: computations must not be moved across a `tryEval` catch boundary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrFacts {
    nodes: Box<[ExprFacts]>,
    try_eval_barriers: Box<[bool]>,
}

impl IrFacts {
    /// Creates a conservative fact table with one entry per IR node.
    pub fn conservative(node_count: usize) -> Self {
        Self {
            nodes: vec![ExprFacts::conservative(); node_count].into_boxed_slice(),
            try_eval_barriers: vec![false; node_count].into_boxed_slice(),
        }
    }

    /// Returns the number of per-node fact records.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns whether the fact table is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns all fact records in IR node order.
    pub fn as_slice(&self) -> &[ExprFacts] {
        &self.nodes
    }

    /// Returns one fact record by node id.
    pub fn get(&self, id: IrId) -> Option<ExprFacts> {
        self.nodes.get(id.index()).copied()
    }

    /// Returns mutable access to one fact record by node id.
    pub fn get_mut(&mut self, id: IrId) -> Option<&mut ExprFacts> {
        self.nodes.get_mut(id.index())
    }

    /// Returns whether `id` roots the argument subtree of a `tryEval` call.
    pub fn try_eval_barrier(&self, id: IrId) -> bool {
        self.try_eval_barriers
            .get(id.index())
            .copied()
            .unwrap_or(false)
    }

    /// Marks `id` as rooting the argument subtree of a `tryEval` call.
    ///
    /// Out-of-range ids are ignored; the barrier table always mirrors the
    /// node-fact table length.
    pub fn set_try_eval_barrier(&mut self, id: IrId, barrier: bool) {
        if let Some(slot) = self.try_eval_barriers.get_mut(id.index()) {
            *slot = barrier;
        }
    }

    /// Returns all `tryEval` barrier bits in IR node order.
    pub fn try_eval_barriers(&self) -> &[bool] {
        &self.try_eval_barriers
    }
}
