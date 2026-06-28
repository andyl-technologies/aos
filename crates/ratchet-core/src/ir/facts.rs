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
