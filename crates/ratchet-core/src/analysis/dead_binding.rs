//! Dead-binding elimination planning over usage facts.
//!
//! Cardinality analysis proves when a binding is absent. This module is the
//! conservative consumer boundary for that proof: it identifies `let` bindings
//! whose value code can be omitted while the frame slot is retained as a dummy.
//! It does not rewrite IR or compact frame layouts.

use thiserror::Error;

use crate::ir::{
    Cardinality, Ir, IrAttrPathSegment, IrBinding, IrBindingSlice, IrData, IrId, IrKind,
};
use crate::syntax::Symbol;

/// Builds the dead-binding elimination plan for every `let` binding in `ir`.
///
/// A binding is admitted only when its value facts prove
/// [`Cardinality::Absent`], its strictness remains [`Strictness::Unknown`], and
/// its key is static. The plan keeps a dummy frame slot for each admitted binding
/// so slot indexes remain stable until a later frame-layout transform exists.
///
/// # Errors
///
/// Returns [`DeadBindingEliminationError`] if the fact table length, a `let`
/// payload, binding slice, binding key, value node, or value fact record is
/// internally inconsistent.
pub fn dead_binding_elimination_plan(
    ir: &Ir,
) -> Result<DeadBindingEliminationPlan, DeadBindingEliminationError> {
    let node_count = ir.arena.nodes().len();
    if ir.facts.len() != node_count {
        return Err(DeadBindingEliminationError::InvalidFactTableLength {
            expected: node_count,
            actual: ir.facts.len(),
        });
    }

    let mut eliminations = Vec::new();
    let mut retained = Vec::new();
    let mut let_count = 0;
    let mut binding_count = 0;

    for (index, node) in ir.arena.nodes().iter().enumerate() {
        if node.kind != IrKind::Let {
            continue;
        }
        let let_node = IrId::new(index as u32);
        let IrData::Let { bindings, body, .. } = node.data else {
            return Err(DeadBindingEliminationError::InvalidPayload {
                id: let_node,
                kind: node.kind,
                expected: "let payload",
            });
        };
        ir.arena
            .node(body)
            .ok_or(DeadBindingEliminationError::InvalidNode { id: body })?;
        let_count += 1;
        for (binding_index, binding) in binding_values(ir, let_node, bindings)?
            .into_iter()
            .enumerate()
        {
            binding_count += 1;
            if let Some(reason) = retention_reason(ir, binding)? {
                retained.push(DeadBindingRetention {
                    let_node,
                    binding_index,
                    value: binding.value,
                    reason,
                });
                continue;
            }
            eliminations.push(DeadBindingElimination {
                let_node,
                binding_index,
                value: binding.value,
                replacement: DeadBindingReplacement::DummyFrameSlot,
            });
        }
    }

    Ok(DeadBindingEliminationPlan {
        let_count,
        binding_count,
        eliminations,
        retained,
    })
}

fn retention_reason(
    ir: &Ir,
    binding: IrBinding,
) -> Result<Option<DeadBindingRetentionReason>, DeadBindingEliminationError> {
    let value_node = ir
        .arena
        .node(binding.value)
        .ok_or(DeadBindingEliminationError::InvalidNode { id: binding.value })?;
    validate_payload(binding.value, *value_node)?;
    let facts = ir
        .facts
        .get(binding.value)
        .ok_or(DeadBindingEliminationError::MissingFact { id: binding.value })?;

    match binding.key {
        IrAttrPathSegment::Static(symbol) => {
            if ir.symbols.resolve(symbol).is_none() {
                return Err(DeadBindingEliminationError::InvalidSymbol { symbol });
            }
        }
        IrAttrPathSegment::Dynamic(key) => {
            ir.arena
                .node(key)
                .ok_or(DeadBindingEliminationError::InvalidNode { id: key })?;
            return Ok(Some(DeadBindingRetentionReason::DynamicBindingKey { key }));
        }
    }

    if facts.cardinality != Cardinality::Absent {
        return Ok(Some(DeadBindingRetentionReason::RequiredByCardinality {
            cardinality: facts.cardinality,
        }));
    }
    if facts.strictness.is_demanded() {
        return Ok(Some(DeadBindingRetentionReason::AbsentButStrict));
    }
    validate_omittable_value_edges(ir, binding.value, *value_node)?;
    Ok(None)
}

fn binding_values(
    ir: &Ir,
    id: IrId,
    slice: IrBindingSlice,
) -> Result<Vec<IrBinding>, DeadBindingEliminationError> {
    let start = slice.start as usize;
    let end = start
        .checked_add(slice.len())
        .ok_or(DeadBindingEliminationError::InvalidBindingSlice { id, slice })?;
    ir.bindings
        .get(start..end)
        .map(<[IrBinding]>::to_vec)
        .ok_or(DeadBindingEliminationError::InvalidBindingSlice { id, slice })
}

fn validate_payload(id: IrId, node: crate::ir::IrNode) -> Result<(), DeadBindingEliminationError> {
    let valid = match node.kind {
        IrKind::Int => matches!(node.data, IrData::Int(_)),
        IrKind::Float => matches!(node.data, IrData::Float(_)),
        IrKind::Bool => matches!(node.data, IrData::Bool(_)),
        IrKind::Null => matches!(node.data, IrData::None),
        IrKind::Str | IrKind::Path | IrKind::Uri | IrKind::BuiltinAttr => {
            matches!(node.data, IrData::Symbol(_))
        }
        IrKind::GlobalVar => matches!(node.data, IrData::GlobalVar { .. }),
        IrKind::LocalVar => matches!(node.data, IrData::Local { .. }),
        IrKind::UpvalVar => matches!(node.data, IrData::Upval { .. }),
        IrKind::SearchPath => matches!(node.data, IrData::SearchPath { .. }),
        IrKind::List => matches!(node.data, IrData::Children(_)),
        IrKind::AttrSet => matches!(node.data, IrData::AttrSet { .. }),
        IrKind::Lambda => matches!(node.data, IrData::Lambda { .. }),
        IrKind::FormalSet => matches!(node.data, IrData::FormalSet { .. }),
        IrKind::Formal => matches!(node.data, IrData::Formal { .. }),
        IrKind::Apply | IrKind::With | IrKind::Assert => matches!(node.data, IrData::Pair { .. }),
        IrKind::Select => matches!(node.data, IrData::Select { .. }),
        IrKind::HasAttr => matches!(node.data, IrData::HasAttr { .. }),
        IrKind::Let => matches!(node.data, IrData::Let { .. }),
        IrKind::If => matches!(node.data, IrData::Triple { .. }),
        IrKind::BinOp => matches!(node.data, IrData::Binary { .. }),
        IrKind::UnaryOp => matches!(node.data, IrData::Unary { .. }),
        IrKind::Interp => matches!(
            node.data,
            IrData::Node(_) | IrData::Children(_) | IrData::None
        ),
        IrKind::ThunkAlloc => matches!(node.data, IrData::Node(_)),
        IrKind::PrimOp => matches!(
            node.data,
            IrData::PrimOp { .. } | IrData::DialectNode { .. } | IrData::DialectScopeVar { .. }
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(DeadBindingEliminationError::InvalidPayload {
            id,
            kind: node.kind,
            expected: expected_payload(node.kind),
        })
    }
}

fn validate_omittable_value_edges(
    ir: &Ir,
    id: IrId,
    node: crate::ir::IrNode,
) -> Result<(), DeadBindingEliminationError> {
    if node.kind != IrKind::ThunkAlloc {
        return Ok(());
    }
    let IrData::Node(body) = node.data else {
        return Err(DeadBindingEliminationError::InvalidPayload {
            id,
            kind: node.kind,
            expected: expected_payload(node.kind),
        });
    };
    ir.arena
        .node(body)
        .ok_or(DeadBindingEliminationError::InvalidNode { id: body })?;
    Ok(())
}

fn expected_payload(kind: IrKind) -> &'static str {
    match kind {
        IrKind::Int => "integer payload",
        IrKind::Float => "float payload",
        IrKind::Bool => "boolean payload",
        IrKind::Null => "empty payload",
        IrKind::Str | IrKind::Path | IrKind::Uri => "symbol payload",
        IrKind::LocalVar => "local slot payload",
        IrKind::UpvalVar => "upvalue slot payload",
        IrKind::GlobalVar => "global-var payload",
        IrKind::BuiltinAttr => "symbol payload",
        IrKind::SearchPath => "search-path payload",
        IrKind::List => "children payload",
        IrKind::AttrSet => "attrset payload",
        IrKind::Lambda => "lambda payload",
        IrKind::FormalSet => "formal-set payload",
        IrKind::Formal => "formal payload",
        IrKind::Apply | IrKind::With | IrKind::Assert => "pair payload",
        IrKind::Select => "select payload",
        IrKind::HasAttr => "hasAttr payload",
        IrKind::Let => "let payload",
        IrKind::If => "triple payload",
        IrKind::BinOp => "binary payload",
        IrKind::UnaryOp => "unary payload",
        IrKind::Interp => "interpolation payload",
        IrKind::ThunkAlloc => "thunk body",
        IrKind::PrimOp => "primop payload",
    }
}

/// A conservative dead-binding elimination plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeadBindingEliminationPlan {
    let_count: usize,
    binding_count: usize,
    eliminations: Vec<DeadBindingElimination>,
    retained: Vec<DeadBindingRetention>,
}

impl DeadBindingEliminationPlan {
    /// Returns the number of `let` nodes scanned.
    pub const fn let_count(&self) -> usize {
        self.let_count
    }

    /// Returns the number of `let` bindings scanned.
    pub const fn binding_count(&self) -> usize {
        self.binding_count
    }

    /// Returns bindings whose value code can be omitted.
    pub fn eliminations(&self) -> &[DeadBindingElimination] {
        &self.eliminations
    }

    /// Returns bindings retained with the reason they could not be omitted.
    pub fn retained(&self) -> &[DeadBindingRetention] {
        &self.retained
    }

    /// Returns whether the plan has no eliminated bindings.
    pub fn is_empty(&self) -> bool {
        self.eliminations.is_empty()
    }
}

/// One binding whose value code can be omitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadBindingElimination {
    let_node: IrId,
    binding_index: usize,
    value: IrId,
    replacement: DeadBindingReplacement,
}

impl DeadBindingElimination {
    /// Returns the `let` node that owns the binding.
    pub const fn let_node(self) -> IrId {
        self.let_node
    }

    /// Returns the binding's index within the `let` binding slice.
    pub const fn binding_index(self) -> usize {
        self.binding_index
    }

    /// Returns the omitted binding value node.
    pub const fn value(self) -> IrId {
        self.value
    }

    /// Returns how the eliminated binding is represented in frame layout.
    pub const fn replacement(self) -> DeadBindingReplacement {
        self.replacement
    }
}

/// How a removed binding is represented until frame layout is rewritten.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadBindingReplacement {
    /// Keep a dummy value in the original frame slot.
    DummyFrameSlot,
}

/// One binding retained by the elimination planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadBindingRetention {
    let_node: IrId,
    binding_index: usize,
    value: IrId,
    reason: DeadBindingRetentionReason,
}

impl DeadBindingRetention {
    /// Returns the `let` node that owns the binding.
    pub const fn let_node(self) -> IrId {
        self.let_node
    }

    /// Returns the binding's index within the `let` binding slice.
    pub const fn binding_index(self) -> usize {
        self.binding_index
    }

    /// Returns the retained binding value node.
    pub const fn value(self) -> IrId {
        self.value
    }

    /// Returns why the binding cannot be eliminated.
    pub const fn reason(self) -> DeadBindingRetentionReason {
        self.reason
    }
}

/// Why a binding cannot be omitted by the current planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadBindingRetentionReason {
    /// The binding is demanded according to its current cardinality fact.
    RequiredByCardinality {
        /// The cardinality fact that kept the binding.
        cardinality: Cardinality,
    },
    /// The binding is marked absent and strict, so the facts are contradictory.
    AbsentButStrict,
    /// The binding key is dynamic and must be evaluated before elimination.
    DynamicBindingKey {
        /// The dynamic key node.
        key: IrId,
    },
}

/// A failure while building a dead-binding elimination plan.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DeadBindingEliminationError {
    /// A node id did not exist in the arena.
    #[error("invalid IR node id {id:?}")]
    InvalidNode {
        /// The invalid node id.
        id: IrId,
    },
    /// The fact table did not contain exactly one record per arena node.
    #[error("invalid fact table length: expected {expected}, got {actual}")]
    InvalidFactTableLength {
        /// The number of nodes in the IR arena.
        expected: usize,
        /// The number of records in the fact table.
        actual: usize,
    },
    /// The fact table did not contain a binding value entry.
    #[error("missing fact record for IR node {id:?}")]
    MissingFact {
        /// The node whose fact record was missing.
        id: IrId,
    },
    /// A binding slice did not resolve through the binding table.
    #[error("invalid binding slice {slice:?} at IR node {id:?}")]
    InvalidBindingSlice {
        /// The node that referenced the invalid binding slice.
        id: IrId,
        /// The invalid binding slice.
        slice: IrBindingSlice,
    },
    /// A static binding-key symbol did not resolve through the symbol table.
    #[error("invalid static binding-key symbol {symbol:?}")]
    InvalidSymbol {
        /// The unresolved static binding-key symbol.
        symbol: Symbol,
    },
    /// A node's payload did not match its node kind.
    #[error("invalid payload for {kind:?} node {id:?}: expected {expected}")]
    InvalidPayload {
        /// The node with the invalid payload.
        id: IrId,
        /// The node kind whose payload was invalid.
        kind: IrKind,
        /// The expected payload shape.
        expected: &'static str,
    },
}
