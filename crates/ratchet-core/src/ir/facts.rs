//! Per-expression analysis facts attached to lowered IR.
//!
//! Whole-program optimization passes refine these facts over time. Until a
//! proof exists, every node carries conservative facts: unknown strictness,
//! many-use cardinality, and escaping allocation behavior.

use super::IrId;

/// Whether evaluating an enclosing expression is known to demand this node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Strictness {
    /// The node is not proven to be demanded, so lazy lowering must be kept.
    #[default]
    Unknown,
    /// The node is proven to be evaluated at least once.
    Strict,
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
    /// Whether this node is proven strict.
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
    /// Eager execution is only selected when strictness is positively proven.
    /// Scalar replacement additionally requires a no-escape proof. Any missing
    /// proof falls back to lazy thunk allocation.
    pub const fn binding_lowering(self) -> BindingLowering {
        match (self.strictness, self.escape) {
            (Strictness::Strict, Escape::NoEscape) => BindingLowering::Scalar,
            (Strictness::Strict, Escape::Escapes) => BindingLowering::Eager,
            (Strictness::Unknown, _) => BindingLowering::Thunk,
        }
    }

    /// Returns the thunk-sharing mode licensed by these facts.
    ///
    /// Single-entry thunks are only safe when the cardinality proof says the
    /// thunk is entered at most once and the escape proof keeps it frame-local.
    /// A proof of absence licenses omitting the thunk entirely unless another
    /// fact contradicts it by proving the binding strict.
    pub const fn thunk_sharing(self) -> ThunkSharing {
        match (self.cardinality, self.strictness, self.escape) {
            (Cardinality::Absent, Strictness::Unknown, _) => ThunkSharing::Omit,
            (Cardinality::Absent, Strictness::Strict, _)
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
/// with the node arena.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrFacts {
    nodes: Box<[ExprFacts]>,
}

impl IrFacts {
    /// Creates a conservative fact table with one entry per IR node.
    pub fn conservative(node_count: usize) -> Self {
        Self {
            nodes: vec![ExprFacts::conservative(); node_count].into_boxed_slice(),
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
}
