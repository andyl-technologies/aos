//! Worker-wrapper planning over strict direct lambda calls.
//!
//! The full worker-wrapper transform will split a function into an always-inline
//! wrapper and a worker with a stricter calling convention. This precursor does
//! not rewrite IR. It names only the current safe boundary: direct literal
//! lambda applications whose argument is proven demanded before any observable
//! effect (the wrapper *reorders* the force ahead of the body, so only the
//! S1+S2 [`Strictness::DemandedBeforeEffect`] proof licenses it), and whose
//! simple formal parameter or formal-set pattern replays as demanded.

use thiserror::Error;

use crate::analysis::{StrictnessAnalysisError, annotate_strictness};
use crate::ir::{Ir, IrData, IrFacts, IrId, IrKind, Strictness};

/// Builds a worker-wrapper split plan for direct literal lambda calls.
///
/// A call is admitted only when the callee is a literal [`IrKind::Lambda`], the
/// lambda pattern is split-eligible, and the current fact table proves the lazy
/// argument is [`Strictness::DemandedBeforeEffect`] (a merely
/// [`Strictness::Demanded`] argument fails closed: wrapper forcing reorders
/// the force ahead of the body). Split-eligible patterns are simple
/// [`IrKind::Formal`] parameters and validated [`IrKind::FormalSet`] patterns
/// whose strictness replay proves that binding forces the argument. Non-literal
/// callees, unsupported patterns, and unproven arguments are retained so later
/// passes can report why no worker can be introduced yet.
///
/// # Errors
///
/// Returns [`WorkerWrapperPlanError`] if the fact table length, an apply node,
/// lambda payload, pattern payload, lambda body root, argument node, argument
/// fact record, or cloned strictness proof is malformed.
pub fn worker_wrapper_plan(ir: &Ir) -> Result<WorkerWrapperPlan, WorkerWrapperPlanError> {
    let node_count = ir.arena.nodes().len();
    if ir.facts.len() != node_count {
        return Err(WorkerWrapperPlanError::InvalidFactTableLength {
            expected: node_count,
            actual: ir.facts.len(),
        });
    }

    let mut plan = WorkerWrapperPlan::default();

    for (index, node) in ir.arena.nodes().iter().copied().enumerate() {
        if node.kind != IrKind::Apply {
            continue;
        }
        let apply = IrId::new(index as u32);
        plan.apply_count += 1;
        let IrData::Pair {
            first: callee,
            second: argument,
        } = node.data
        else {
            return Err(WorkerWrapperPlanError::InvalidPayload {
                id: apply,
                kind: node.kind,
                expected: "apply payload",
            });
        };
        validate_apply_payload_ids(apply, callee, argument)?;

        if let Some(reason) = retention_reason(ir, apply, callee, argument)? {
            plan.retained.push(WorkerWrapperRetention {
                apply,
                callee,
                argument,
                reason,
            });
            continue;
        }

        plan.splits.push(WorkerWrapperSplit {
            apply,
            lambda: callee,
            argument,
            mode: WorkerWrapperArgumentMode::StrictValue,
        });
    }

    Ok(plan)
}

fn validate_apply_payload_ids(
    apply: IrId,
    callee: IrId,
    argument: IrId,
) -> Result<(), WorkerWrapperPlanError> {
    if apply == callee || apply == argument || callee == argument {
        return Err(WorkerWrapperPlanError::InvalidPayload {
            id: apply,
            kind: IrKind::Apply,
            expected: "non-aliased apply payload",
        });
    }

    Ok(())
}

fn retention_reason(
    ir: &Ir,
    apply: IrId,
    callee: IrId,
    argument: IrId,
) -> Result<Option<WorkerWrapperRetentionReason>, WorkerWrapperPlanError> {
    let lambda_node = *ir
        .arena
        .node(callee)
        .ok_or(WorkerWrapperPlanError::InvalidNode { id: callee })?;
    ir.arena
        .node(argument)
        .ok_or(WorkerWrapperPlanError::InvalidNode { id: argument })?;

    if lambda_node.kind != IrKind::Lambda {
        return Ok(Some(WorkerWrapperRetentionReason::NonLiteralCallee {
            kind: lambda_node.kind,
        }));
    }

    let IrData::Lambda { pattern, body, .. } = lambda_node.data else {
        return Err(WorkerWrapperPlanError::InvalidPayload {
            id: callee,
            kind: lambda_node.kind,
            expected: "lambda payload",
        });
    };
    let pattern_node = *ir
        .arena
        .node(pattern)
        .ok_or(WorkerWrapperPlanError::InvalidNode { id: pattern })?;
    ir.arena
        .node(body)
        .ok_or(WorkerWrapperPlanError::InvalidNode { id: body })?;
    let pattern_is_split_eligible = split_eligible_pattern(pattern, pattern_node)?;
    if !pattern_is_split_eligible {
        return Ok(Some(WorkerWrapperRetentionReason::NonSimplePattern {
            pattern,
            kind: pattern_node.kind,
        }));
    }
    validate_body_root(ir, body)?;

    let facts = ir
        .facts
        .get(argument)
        .ok_or(WorkerWrapperPlanError::MissingFact { id: argument })?;
    if facts.strictness != Strictness::DemandedBeforeEffect {
        return Ok(Some(WorkerWrapperRetentionReason::ArgumentNotStrict {
            strictness: facts.strictness,
        }));
    }
    if !strictness_proves_argument_demand(ir, apply, argument)? {
        return Ok(Some(WorkerWrapperRetentionReason::FormalNotDemanded));
    }

    Ok(None)
}

fn split_eligible_pattern(
    id: IrId,
    node: crate::ir::IrNode,
) -> Result<bool, WorkerWrapperPlanError> {
    match (node.kind, node.data) {
        (IrKind::Formal, IrData::Formal { default: None, .. }) => Ok(true),
        (
            IrKind::Formal,
            IrData::Formal {
                default: Some(_), ..
            },
        ) => Ok(false),
        (IrKind::Formal, _) => Err(WorkerWrapperPlanError::InvalidPayload {
            id,
            kind: node.kind,
            expected: "formal payload",
        }),
        (IrKind::FormalSet, IrData::FormalSet { .. }) => Ok(true),
        (IrKind::FormalSet, _) => Err(WorkerWrapperPlanError::InvalidPayload {
            id,
            kind: node.kind,
            expected: "formal-set payload",
        }),
        _ => Ok(false),
    }
}

fn validate_body_root(ir: &Ir, id: IrId) -> Result<(), WorkerWrapperPlanError> {
    let node = *ir
        .arena
        .node(id)
        .ok_or(WorkerWrapperPlanError::InvalidNode { id })?;
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
        Err(WorkerWrapperPlanError::InvalidPayload {
            id,
            kind: node.kind,
            expected: expected_payload(node.kind),
        })
    }
}

fn strictness_proves_argument_demand(
    ir: &Ir,
    apply: IrId,
    argument: IrId,
) -> Result<bool, WorkerWrapperPlanError> {
    let mut proof_ir = ir.clone();
    proof_ir.root = apply;
    proof_ir.facts = IrFacts::conservative(proof_ir.arena.nodes().len());
    annotate_strictness(&mut proof_ir)?;
    let facts = proof_ir
        .facts
        .get(argument)
        .ok_or(WorkerWrapperPlanError::MissingFact { id: argument })?;
    Ok(facts.strictness == Strictness::DemandedBeforeEffect)
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

/// A conservative worker-wrapper split plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkerWrapperPlan {
    apply_count: usize,
    splits: Vec<WorkerWrapperSplit>,
    retained: Vec<WorkerWrapperRetention>,
}

impl WorkerWrapperPlan {
    /// Returns the number of `apply` nodes scanned.
    pub const fn apply_count(&self) -> usize {
        self.apply_count
    }

    /// Returns calls where a worker with a strict argument can be introduced.
    pub fn splits(&self) -> &[WorkerWrapperSplit] {
        &self.splits
    }

    /// Returns direct calls retained with the reason no split was licensed.
    pub fn retained(&self) -> &[WorkerWrapperRetention] {
        &self.retained
    }

    /// Returns whether the plan introduces no worker-wrapper splits.
    pub fn is_empty(&self) -> bool {
        self.splits.is_empty()
    }
}

/// One direct lambda call licensed for a worker-wrapper split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerWrapperSplit {
    apply: IrId,
    lambda: IrId,
    argument: IrId,
    mode: WorkerWrapperArgumentMode,
}

impl WorkerWrapperSplit {
    /// Returns the `apply` node being split.
    pub const fn apply(self) -> IrId {
        self.apply
    }

    /// Returns the literal lambda callee.
    pub const fn lambda(self) -> IrId {
        self.lambda
    }

    /// Returns the lazy argument that the wrapper should force.
    pub const fn argument(self) -> IrId {
        self.argument
    }

    /// Returns the planned worker argument mode.
    pub const fn mode(self) -> WorkerWrapperArgumentMode {
        self.mode
    }
}

/// Argument-passing mode introduced by the worker-wrapper split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerWrapperArgumentMode {
    /// The wrapper forces the original lazy argument and the worker receives WHNF.
    StrictValue,
}

/// One direct call retained by the worker-wrapper planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerWrapperRetention {
    apply: IrId,
    callee: IrId,
    argument: IrId,
    reason: WorkerWrapperRetentionReason,
}

impl WorkerWrapperRetention {
    /// Returns the `apply` node retained by the planner.
    pub const fn apply(self) -> IrId {
        self.apply
    }

    /// Returns the callee node from the apply payload.
    pub const fn callee(self) -> IrId {
        self.callee
    }

    /// Returns the lazy argument node.
    pub const fn argument(self) -> IrId {
        self.argument
    }

    /// Returns why the call cannot be split by this precursor.
    pub const fn reason(self) -> WorkerWrapperRetentionReason {
        self.reason
    }
}

/// Why a direct call cannot be split by the current worker-wrapper precursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerWrapperRetentionReason {
    /// The callee is not a literal lambda.
    NonLiteralCallee {
        /// The callee node kind.
        kind: IrKind,
    },
    /// The literal lambda pattern is not eligible for this precursor's split.
    NonSimplePattern {
        /// The pattern node.
        pattern: IrId,
        /// The pattern node kind.
        kind: IrKind,
    },
    /// The argument is not proven strict.
    ArgumentNotStrict {
        /// The strictness fact that prevented the split.
        strictness: Strictness,
    },
    /// Strictness replay does not prove the argument is demanded.
    FormalNotDemanded,
}

/// A failure while building a worker-wrapper plan.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WorkerWrapperPlanError {
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
    /// The fact table did not contain an entry for an argument node.
    #[error("missing fact record for IR node {id:?}")]
    MissingFact {
        /// The argument node whose fact record was missing.
        id: IrId,
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
    /// The strictness proof rejected malformed IR.
    #[error(transparent)]
    Strictness(#[from] StrictnessAnalysisError),
}
