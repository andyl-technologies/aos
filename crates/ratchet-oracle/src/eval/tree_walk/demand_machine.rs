//! Default-off explicit-stack execution for closed pure scalar roots.
//!
//! This is the first whole-demand executor foundation. Admission walks the
//! complete reachable root before evaluation and rejects unsupported or
//! effectful nodes. An admitted root then runs without recursive Rust calls:
//! pending IR work lives in `control`, and every intermediate runtime value
//! lives in the evaluator-owned `transient_value_stack_roots`, where allocation
//! safepoints can scan and rewrite it.

use super::*;
use std::{
    ffi::OsStr,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

/// A root admitted and decoded by the closed scalar-machine preflight.
#[derive(Debug)]
struct DemandProgram {
    root: usize,
    root_id: IrId,
    root_node: IrNode,
    ops: Box<[DemandOp]>,
    node_count: usize,
}

/// One predecoded operation in an admitted program.
#[derive(Clone, Copy, Debug)]
enum DemandOp {
    Pending {
        id: IrId,
    },
    Int {
        id: IrId,
        span: Span,
        value: i64,
    },
    Bool {
        id: IrId,
        span: Span,
        value: bool,
    },
    Null {
        id: IrId,
        span: Span,
    },
    If {
        id: IrId,
        node: IrNode,
        condition: DemandOperand,
        then_branch: usize,
        else_branch: usize,
    },
    Arithmetic {
        id: IrId,
        node: IrNode,
        lhs: DemandOperand,
        rhs: DemandOperand,
        op: BinaryArithmeticOp,
    },
}

/// One child operation together with its source identity.
#[derive(Clone, Copy, Debug)]
struct DemandOperand {
    pc: usize,
    id: IrId,
    span: Span,
}

/// One pending operation in the explicit control stack.
#[derive(Clone, Copy, Debug)]
enum DemandControl {
    Eval(usize),
    SelectIf(usize),
    FinishAddLeft(usize),
    FinishBinary(usize),
}

/// Import-module coverage counters for the default-off demand machine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DemandMachineImportCounters {
    /// Imported roots whose bodies ran in the demand machine.
    pub(crate) machine_bodies: u64,
    /// Imported roots declined after the feature was enabled.
    pub(crate) module_declines: u64,
    /// One-shot imported-root oracle continuations entered after a decline.
    pub(crate) oracle_module_calls: u64,
}

impl TreeWalk {
    /// Tries the default-off whole-instantiation scalar executor.
    ///
    /// `None` means that the feature is disabled or preflight declined the
    /// entire root and attribute path without evaluating either.
    pub(super) fn try_eval_demand_machine_instantiation(
        &mut self,
        root: IrId,
        attr_path: &[Vec<u8>],
    ) -> Option<Result<Value, TreeWalkError>> {
        let enabled =
            demand_machine_env_enabled(std::env::var_os("AOS_NIX_DEMAND_MACHINE").as_deref());
        self.try_eval_demand_machine_instantiation_if_enabled(root, attr_path, enabled)
    }

    /// Tries one whole instantiation without consulting process-global state.
    ///
    /// The initial scalar grammar owns only sessions with no attribute
    /// selection. A nonempty path declines before root preflight or execution,
    /// leaving the caller to run the established root-plus-path oracle once.
    fn try_eval_demand_machine_instantiation_if_enabled(
        &mut self,
        root: IrId,
        attr_path: &[Vec<u8>],
        enabled: bool,
    ) -> Option<Result<Value, TreeWalkError>> {
        if !enabled || !attr_path.is_empty() {
            return None;
        }
        let program = self.compile_demand_program(root)?;
        Some(self.execute_demand_program(program))
    }

    /// Evaluates an installed imported-module root through the default-off
    /// machine, falling through to one oracle continuation after a decline.
    pub(super) fn eval_import_module_root_with_demand_machine_or_oracle(
        &mut self,
        root: IrId,
        path: &[u8],
    ) -> Result<Value, TreeWalkError> {
        let enabled =
            demand_machine_env_enabled(std::env::var_os("AOS_NIX_DEMAND_MACHINE").as_deref());
        self.eval_import_module_root_with_demand_machine_or_oracle_if_enabled(root, path, enabled)
    }

    /// Evaluates an imported root without consulting process-global state.
    ///
    /// When disabled this is exactly the established oracle call and does not
    /// affect the experiment counters. When enabled, active force-cache root
    /// semantics force a decline unless the path is an existing text-store
    /// entry, matching [`Self::eval_import_root_with_cache`]'s bypass.
    ///
    /// # Errors
    ///
    /// Returns the admitted machine error or the one-shot oracle error.
    pub(super) fn eval_import_module_root_with_demand_machine_or_oracle_if_enabled(
        &mut self,
        root: IrId,
        path: &[u8],
        enabled: bool,
    ) -> Result<Value, TreeWalkError> {
        if !enabled {
            return self.eval_import_root_with_cache(root, path);
        }
        let force_cache_requires_oracle =
            self.force_cache_active && !self.text_store.contains_key(path);
        let program = (!force_cache_requires_oracle)
            .then(|| self.compile_demand_program(root))
            .flatten();
        if let Some(program) = program {
            self.demand_machine_import_counters.machine_bodies = self
                .demand_machine_import_counters
                .machine_bodies
                .saturating_add(1);
            return self.execute_demand_program(program);
        }

        self.demand_machine_import_counters.module_declines = self
            .demand_machine_import_counters
            .module_declines
            .saturating_add(1);
        self.demand_machine_import_counters.oracle_module_calls = self
            .demand_machine_import_counters
            .oracle_module_calls
            .saturating_add(1);
        self.eval_import_root_with_cache(root, path)
    }

    /// Executes a fully admitted program with panic-safe root-marker cleanup.
    fn execute_demand_program(&mut self, program: DemandProgram) -> Result<Value, TreeWalkError> {
        let root = program.root_id;
        self.with_active_demand_root(root, |eval| {
            eval.run_demand_program(program)
                .map_err(|error| eval.error_with_current_source(error))
        })
    }

    /// Installs and restores the allocation root marker around `run`.
    ///
    /// # Panics
    ///
    /// Resumes a panic from `run` after restoring the displaced marker.
    fn with_active_demand_root<T>(&mut self, root: IrId, run: impl FnOnce(&mut Self) -> T) -> T {
        let previous_root_eval_node = self.active_root_eval_node.replace(root);
        let result = catch_unwind(AssertUnwindSafe(|| run(self)));
        self.active_root_eval_node = previous_root_eval_node;
        match result {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        }
    }

    /// Admits a closed pure expression composed only of supported scalar nodes.
    ///
    /// Both conditional branches are checked even though only one will run.
    /// Consequently a decline always happens before scalar allocation, error
    /// production, or any other evaluator work.
    fn compile_demand_program(&self, root: IrId) -> Option<DemandProgram> {
        let node_count = self.current_ir().arena.nodes().len();
        let root_node = *self.node(root).ok()?;
        if !root_node.effect.is_speculable() || !demand_node_shape_supported(root_node) {
            return None;
        }
        let mut slots = Vec::new();
        slots.try_reserve_exact(node_count).ok()?;
        slots.resize(node_count, None);
        let mut pending = Vec::new();
        pending.try_reserve_exact(node_count).ok()?;
        let mut ops = Vec::new();
        ops.try_reserve_exact(node_count).ok()?;
        let root_pc = enqueue_demand_node(&mut pending, &mut slots, &mut ops, root)?;
        while let Some((pc, id)) = pending.pop() {
            let node = *self.node(id).ok()?;
            if !node.effect.is_speculable() {
                return None;
            }
            let op = match (node.kind, node.data) {
                (IrKind::Int, IrData::Int(value)) => DemandOp::Int {
                    id,
                    span: node.span,
                    value,
                },
                (IrKind::Bool, IrData::Bool(value)) => DemandOp::Bool {
                    id,
                    span: node.span,
                    value,
                },
                (IrKind::Null, IrData::None) => DemandOp::Null {
                    id,
                    span: node.span,
                },
                (
                    IrKind::If,
                    IrData::Triple {
                        first,
                        second,
                        third,
                    },
                ) => {
                    let condition =
                        enqueue_demand_operand(self, &mut pending, &mut slots, &mut ops, first)?;
                    let then_branch =
                        enqueue_demand_node(&mut pending, &mut slots, &mut ops, second)?;
                    let else_branch =
                        enqueue_demand_node(&mut pending, &mut slots, &mut ops, third)?;
                    DemandOp::If {
                        id,
                        node,
                        condition,
                        then_branch,
                        else_branch,
                    }
                }
                (
                    IrKind::BinOp,
                    IrData::Binary {
                        op: op @ (BinOpKind::Add | BinOpKind::Sub | BinOpKind::Mul | BinOpKind::Div),
                        lhs,
                        rhs,
                    },
                ) => {
                    let lhs =
                        enqueue_demand_operand(self, &mut pending, &mut slots, &mut ops, lhs)?;
                    let rhs =
                        enqueue_demand_operand(self, &mut pending, &mut slots, &mut ops, rhs)?;
                    let op = match op {
                        BinOpKind::Add => BinaryArithmeticOp::Add,
                        BinOpKind::Sub => BinaryArithmeticOp::Sub,
                        BinOpKind::Mul => BinaryArithmeticOp::Mul,
                        BinOpKind::Div => BinaryArithmeticOp::Div,
                        _ => return None,
                    };
                    DemandOp::Arithmetic {
                        id,
                        node,
                        lhs,
                        rhs,
                        op,
                    }
                }
                _ => return None,
            };
            *ops.get_mut(pc)? = op;
        }
        if ops
            .iter()
            .any(|operation| matches!(operation, DemandOp::Pending { .. }))
        {
            return None;
        }
        let reachable_node_count = ops.len();
        Some(DemandProgram {
            root: root_pc,
            root_id: root,
            root_node,
            ops: ops.into_boxed_slice(),
            node_count: reachable_node_count,
        })
    }

    /// Executes one admitted program with explicit control and value stacks.
    fn run_demand_program(&mut self, program: DemandProgram) -> Result<Value, TreeWalkError> {
        let (root_id, root_node) = program.root_diagnostic()?;
        let root_span = root_node.span;
        let control_capacity = program
            .node_count
            .checked_mul(2)
            .and_then(|capacity| capacity.checked_add(1))
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: root_id,
                        len: usize::MAX,
                    },
                    root_span,
                )
            })?;
        self.transient_value_stack_roots
            .try_reserve(program.node_count)
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: root_id,
                        len: program.node_count,
                    },
                    root_span,
                )
            })?;
        let mut control = Vec::new();
        control.try_reserve_exact(control_capacity).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: root_id,
                    len: control_capacity,
                },
                root_span,
            )
        })?;
        control.push(DemandControl::Eval(program.root));
        let value_base = self.transient_value_stack_roots.len();
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.run_demand_program_inner(program, value_base, control)
        }));
        self.transient_value_stack_roots.truncate(value_base);
        match result {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        }
    }

    /// Runs an admitted program above the caller's transient-root prefix.
    fn run_demand_program_inner(
        &mut self,
        program: DemandProgram,
        value_base: usize,
        mut control: Vec<DemandControl>,
    ) -> Result<Value, TreeWalkError> {
        while let Some(operation) = control.pop() {
            match operation {
                DemandControl::Eval(id) => match program.op(id)? {
                    DemandOp::Int { id, span, value } => {
                        let value = self.runtime_int_value(id, span, value)?;
                        self.transient_value_stack_roots.push(value);
                    }
                    DemandOp::Bool { value, .. } => {
                        self.transient_value_stack_roots.push(Value::bool(value));
                    }
                    DemandOp::Null { .. } => {
                        self.transient_value_stack_roots.push(Value::null());
                    }
                    DemandOp::If { condition, .. } => {
                        control.push(DemandControl::SelectIf(id));
                        control.push(DemandControl::Eval(condition.pc));
                    }
                    DemandOp::Arithmetic { lhs, rhs, op, .. } => {
                        if op == BinaryArithmeticOp::Add {
                            control.push(DemandControl::FinishAddLeft(id));
                            control.push(DemandControl::Eval(lhs.pc));
                            continue;
                        }
                        control.push(DemandControl::FinishBinary(id));
                        control.push(DemandControl::Eval(rhs.pc));
                        control.push(DemandControl::Eval(lhs.pc));
                    }
                    DemandOp::Pending { id } => {
                        return Err(demand_machine_pending(id, program.root_node.span));
                    }
                },
                DemandControl::SelectIf(pc) => {
                    let DemandOp::If {
                        condition,
                        then_branch,
                        else_branch,
                        ..
                    } = program.op(pc)?
                    else {
                        return Err(program.invalid_op(pc)?);
                    };
                    let value = pop_demand_value(
                        &mut self.transient_value_stack_roots,
                        value_base,
                        condition.id,
                        condition.span,
                    )?;
                    let selected = if self.expect_bool(condition.id, value, condition.span)? {
                        then_branch
                    } else {
                        else_branch
                    };
                    control.push(DemandControl::Eval(selected));
                }
                DemandControl::FinishAddLeft(pc) => {
                    let DemandOp::Arithmetic { lhs, rhs, op, .. } = program.op(pc)? else {
                        return Err(program.invalid_op(pc)?);
                    };
                    if op != BinaryArithmeticOp::Add {
                        return Err(program.invalid_op(pc)?);
                    }
                    let left = pop_demand_value(
                        &mut self.transient_value_stack_roots,
                        value_base,
                        lhs.id,
                        lhs.span,
                    )?;
                    if left.tag() != ValueTag::Int {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::Type {
                                id: lhs.id,
                                expected: "number, string, or path",
                                actual: left.tag(),
                            },
                            lhs.span,
                        )
                        .with_label(lhs.span, "left operand")
                        .with_label(rhs.span, "right operand"));
                    }
                    self.transient_value_stack_roots.push(left);
                    control.push(DemandControl::FinishBinary(pc));
                    control.push(DemandControl::Eval(rhs.pc));
                }
                DemandControl::FinishBinary(pc) => {
                    let DemandOp::Arithmetic {
                        id,
                        node,
                        lhs,
                        rhs,
                        op,
                    } = program.op(pc)?
                    else {
                        return Err(program.invalid_op(pc)?);
                    };
                    let right = pop_demand_value(
                        &mut self.transient_value_stack_roots,
                        value_base,
                        rhs.id,
                        rhs.span,
                    )?;
                    let left = pop_demand_value(
                        &mut self.transient_value_stack_roots,
                        value_base,
                        lhs.id,
                        lhs.span,
                    )?;
                    let left = self
                        .expect_number(lhs.id, left, lhs.span)
                        .map_err(|error| {
                            self.label_binary_operand_error(error, lhs.span, rhs.span)
                        })?;
                    let right = self
                        .expect_number(rhs.id, right, rhs.span)
                        .map_err(|error| {
                            self.label_binary_operand_error(error, lhs.span, rhs.span)
                        })?;
                    let result = self.eval_numeric_values(id, &node, op, left, right)?;
                    self.transient_value_stack_roots.push(result);
                }
            }
        }

        let (root_id, root_node) = program.root_diagnostic()?;
        let value = pop_demand_value(
            &mut self.transient_value_stack_roots,
            value_base,
            root_id,
            root_node.span,
        )?;
        if self.transient_value_stack_roots.len() != value_base {
            return Err(demand_machine_invalid(root_id, root_node));
        }
        Ok(value)
    }
}

impl DemandProgram {
    /// Returns one already-decoded operation by tape index.
    fn op(&self, pc: usize) -> Result<DemandOp, TreeWalkError> {
        self.ops
            .get(pc)
            .copied()
            .ok_or_else(|| demand_machine_invalid(self.root_id, self.root_node))
    }

    /// Returns the root source identity used for machine-internal diagnostics.
    fn root_diagnostic(&self) -> Result<(IrId, IrNode), TreeWalkError> {
        if self.ops.get(self.root).is_none() {
            return Err(demand_machine_invalid(self.root_id, self.root_node));
        }
        Ok((self.root_id, self.root_node))
    }

    /// Reports a tape/control mismatch against the operation's source node.
    fn invalid_op(&self, pc: usize) -> Result<TreeWalkError, TreeWalkError> {
        let (id, node) = self.op(pc)?.diagnostic(self.root_node.span)?;
        Ok(demand_machine_invalid(id, node))
    }
}

impl DemandOp {
    /// Returns the original IR identity retained for diagnostics.
    fn diagnostic(self, fallback_span: Span) -> Result<(IrId, IrNode), TreeWalkError> {
        match self {
            Self::Pending { id } => Err(demand_machine_pending(id, fallback_span)),
            Self::Int { id, span, value } => Ok((
                id,
                IrNode::new(
                    IrKind::Int,
                    span,
                    crate::compile::EffectClass::pure(),
                    IrData::Int(value),
                ),
            )),
            Self::Bool { id, span, value } => Ok((
                id,
                IrNode::new(
                    IrKind::Bool,
                    span,
                    crate::compile::EffectClass::pure(),
                    IrData::Bool(value),
                ),
            )),
            Self::Null { id, span } => Ok((
                id,
                IrNode::new(
                    IrKind::Null,
                    span,
                    crate::compile::EffectClass::pure(),
                    IrData::None,
                ),
            )),
            Self::If { id, node, .. } => Ok((id, node)),
            Self::Arithmetic { id, node, .. } => Ok((id, node)),
        }
    }
}

/// Returns whether one node has a shape the scalar tape can decode.
fn demand_node_shape_supported(node: IrNode) -> bool {
    matches!(
        (node.kind, node.data),
        (IrKind::Int, IrData::Int(_))
            | (IrKind::Bool, IrData::Bool(_))
            | (IrKind::Null, IrData::None)
            | (IrKind::If, IrData::Triple { .. })
            | (
                IrKind::BinOp,
                IrData::Binary {
                    op: BinOpKind::Add | BinOpKind::Sub | BinOpKind::Mul | BinOpKind::Div,
                    ..
                }
            )
    )
}

/// Enqueues one not-yet-seen IR node and returns its compact tape index.
fn enqueue_demand_node(
    pending: &mut Vec<(usize, IrId)>,
    slots: &mut [Option<usize>],
    ops: &mut Vec<DemandOp>,
    id: IrId,
) -> Option<usize> {
    let slot = slots.get_mut(id.index())?;
    if let Some(pc) = *slot {
        return Some(pc);
    }
    let pc = ops.len();
    *slot = Some(pc);
    ops.push(DemandOp::Pending { id });
    pending.push((pc, id));
    Some(pc)
}

/// Enqueues a child and retains its source location for runtime diagnostics.
fn enqueue_demand_operand(
    evaluator: &TreeWalk,
    pending: &mut Vec<(usize, IrId)>,
    slots: &mut [Option<usize>],
    ops: &mut Vec<DemandOp>,
    id: IrId,
) -> Option<DemandOperand> {
    let span = evaluator.node(id).ok()?.span;
    let pc = enqueue_demand_node(pending, slots, ops, id)?;
    Some(DemandOperand { pc, id, span })
}

/// Interprets the repository's conventional default-off boolean environment flag.
fn demand_machine_env_enabled(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| value != "0")
}

/// Reports a post-admission structural mismatch without falling back mid-run.
fn demand_machine_invalid(id: IrId, node: IrNode) -> TreeWalkError {
    TreeWalkError::new(
        TreeWalkErrorKind::InvalidNodeKind {
            id,
            kind: node.kind,
        },
        node.span,
    )
}

/// Reports an impossible unfilled tape slot.
fn demand_machine_pending(id: IrId, span: Span) -> TreeWalkError {
    TreeWalkError::new(
        TreeWalkErrorKind::InvalidNodeKind {
            id,
            kind: IrKind::Int,
        },
        span,
    )
}

/// Pops one machine value or reports an internal stack-contract failure.
fn pop_demand_value(
    values: &mut Vec<Value>,
    base: usize,
    id: IrId,
    span: Span,
) -> Result<Value, TreeWalkError> {
    if values.len() <= base {
        return Err(demand_machine_pending(id, span));
    }
    values.pop().ok_or_else(|| {
        TreeWalkError::new(
            TreeWalkErrorKind::InvalidNodeKind {
                id,
                kind: IrKind::Int,
            },
            span,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{EffectClass, IrFacts, IrWithChain};

    fn pure(kind: IrKind, data: IrData) -> IrNode {
        IrNode::new(kind, Span::default(), EffectClass::pure(), data)
    }

    fn ir(root: IrId, nodes: Vec<IrNode>) -> Ir {
        let arena = IrArena::from_raw_parts(nodes, Vec::new());
        Ir {
            root,
            facts: IrFacts::conservative(arena.nodes().len()),
            arena,
            symbols: SymbolTable::new(),
            frames: Box::new([]),
            with_chains: Box::<[IrWithChain]>::default(),
            attr_paths: Box::new([]),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    #[test]
    fn scalar_machine_matches_tree_walk_for_lazy_branch_and_arithmetic() {
        let expression = ir(
            IrId::new(7),
            vec![
                pure(IrKind::Bool, IrData::Bool(false)),
                pure(IrKind::Int, IrData::Int(1)),
                pure(IrKind::Int, IrData::Int(0)),
                pure(
                    IrKind::BinOp,
                    IrData::Binary {
                        op: BinOpKind::Div,
                        lhs: IrId::new(1),
                        rhs: IrId::new(2),
                    },
                ),
                pure(IrKind::Int, IrData::Int(40)),
                pure(IrKind::Int, IrData::Int(2)),
                pure(
                    IrKind::BinOp,
                    IrData::Binary {
                        op: BinOpKind::Add,
                        lhs: IrId::new(4),
                        rhs: IrId::new(5),
                    },
                ),
                pure(
                    IrKind::If,
                    IrData::Triple {
                        first: IrId::new(0),
                        second: IrId::new(3),
                        third: IrId::new(6),
                    },
                ),
            ],
        );
        let mut oracle = TreeWalk::new(&expression);
        let oracle_value = oracle.eval_node(expression.root).expect("oracle evaluates");
        let mut machine = TreeWalk::new(&expression);
        let program = machine
            .compile_demand_program(expression.root)
            .expect("closed scalar root is admitted");
        let machine_value = machine
            .run_demand_program(program)
            .expect("machine evaluates");
        assert_eq!(
            oracle.runtime_int_payload(expression.root, Span::default(), oracle_value),
            machine.runtime_int_payload(expression.root, Span::default(), machine_value)
        );
        assert_eq!(
            machine.runtime_int_payload(expression.root, Span::default(), machine_value),
            Ok(42)
        );
    }

    #[test]
    fn preflight_declines_effect_in_untaken_branch() {
        let effect = EffectClass::new(1, false);
        let expression = ir(
            IrId::new(3),
            vec![
                pure(IrKind::Bool, IrData::Bool(false)),
                IrNode::new(IrKind::Int, Span::default(), effect, IrData::Int(1)),
                pure(IrKind::Int, IrData::Int(2)),
                pure(
                    IrKind::If,
                    IrData::Triple {
                        first: IrId::new(0),
                        second: IrId::new(1),
                        third: IrId::new(2),
                    },
                ),
            ],
        );
        let machine = TreeWalk::new(&expression);
        assert!(machine.compile_demand_program(expression.root).is_none());
    }

    #[test]
    fn compact_tape_ignores_malformed_unreachable_slots() {
        let expression = ir(
            IrId::new(0),
            vec![
                pure(IrKind::Int, IrData::Int(7)),
                pure(IrKind::Int, IrData::None),
            ],
        );
        let machine = TreeWalk::new(&expression);
        let program = machine
            .compile_demand_program(expression.root)
            .expect("unreachable malformed slots do not affect admission");
        assert_eq!(program.ops.len(), 1);
        assert!(matches!(
            program.ops.first(),
            Some(DemandOp::Int { value: 7, .. })
        ));
    }

    #[test]
    fn preflight_declines_malformed_reachable_slots() {
        let expression = ir(
            IrId::new(1),
            vec![
                pure(IrKind::Int, IrData::None),
                pure(
                    IrKind::BinOp,
                    IrData::Binary {
                        op: BinOpKind::Add,
                        lhs: IrId::new(0),
                        rhs: IrId::new(0),
                    },
                ),
            ],
        );
        let machine = TreeWalk::new(&expression);
        assert!(machine.compile_demand_program(expression.root).is_none());
    }

    #[test]
    fn preflight_declines_out_of_bounds_reachable_slots() {
        let expression = ir(
            IrId::new(0),
            vec![pure(
                IrKind::If,
                IrData::Triple {
                    first: IrId::new(1),
                    second: IrId::new(1),
                    third: IrId::new(1),
                },
            )],
        );
        let machine = TreeWalk::new(&expression);
        assert!(machine.compile_demand_program(expression.root).is_none());
    }

    #[test]
    fn machine_error_restores_the_transient_root_stack() {
        let expression = ir(
            IrId::new(2),
            vec![
                pure(IrKind::Int, IrData::Int(1)),
                pure(IrKind::Int, IrData::Int(0)),
                pure(
                    IrKind::BinOp,
                    IrData::Binary {
                        op: BinOpKind::Div,
                        lhs: IrId::new(0),
                        rhs: IrId::new(1),
                    },
                ),
            ],
        );
        let mut machine = TreeWalk::new(&expression);
        let program = machine
            .compile_demand_program(expression.root)
            .expect("closed scalar root is admitted");
        let error = machine
            .run_demand_program(program)
            .expect_err("division by zero is preserved");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id } if id == expression.root
        ));
        assert!(machine.transient_value_stack_roots.is_empty());
    }

    #[test]
    fn add_type_error_does_not_evaluate_the_right_operand() {
        let expression = ir(
            IrId::new(4),
            vec![
                pure(IrKind::Bool, IrData::Bool(true)),
                pure(IrKind::Int, IrData::Int(1)),
                pure(IrKind::Int, IrData::Int(0)),
                pure(
                    IrKind::BinOp,
                    IrData::Binary {
                        op: BinOpKind::Div,
                        lhs: IrId::new(1),
                        rhs: IrId::new(2),
                    },
                ),
                pure(
                    IrKind::BinOp,
                    IrData::Binary {
                        op: BinOpKind::Add,
                        lhs: IrId::new(0),
                        rhs: IrId::new(3),
                    },
                ),
            ],
        );
        let mut oracle = TreeWalk::new(&expression);
        let oracle_error = oracle
            .eval_node(expression.root)
            .expect_err("oracle rejects the left operand first");
        let mut machine = TreeWalk::new(&expression);
        let program = machine
            .compile_demand_program(expression.root)
            .expect("closed scalar root is admitted");
        let machine_error = machine
            .run_demand_program(program)
            .expect_err("machine rejects the left operand first");
        assert_eq!(machine_error.kind(), oracle_error.kind());
        assert_eq!(machine_error.span(), oracle_error.span());
    }

    #[test]
    fn zero_disables_the_default_off_environment_flag() {
        assert!(!demand_machine_env_enabled(None));
        assert!(!demand_machine_env_enabled(Some(OsStr::new("0"))));
        assert!(demand_machine_env_enabled(Some(OsStr::new("1"))));
    }

    #[test]
    fn empty_attr_path_admits_the_whole_scalar_session() {
        let expression = ir(
            IrId::new(2),
            vec![
                pure(IrKind::Int, IrData::Int(40)),
                pure(IrKind::Int, IrData::Int(2)),
                pure(
                    IrKind::BinOp,
                    IrData::Binary {
                        op: BinOpKind::Add,
                        lhs: IrId::new(0),
                        rhs: IrId::new(1),
                    },
                ),
            ],
        );
        let mut machine = TreeWalk::new(&expression);
        let value = machine
            .try_eval_demand_machine_instantiation_if_enabled(expression.root, &[], true)
            .expect("the empty-path scalar session is admitted")
            .expect("the admitted scalar session evaluates");
        assert_eq!(
            machine.runtime_int_payload(expression.root, Span::default(), value),
            Ok(42)
        );
        assert_eq!(machine.active_root_eval_node, None);
    }

    #[test]
    fn nonempty_attr_path_declines_before_root_execution() {
        let expression = ir(
            IrId::new(2),
            vec![
                pure(IrKind::Int, IrData::Int(1)),
                pure(IrKind::Int, IrData::Int(0)),
                pure(
                    IrKind::BinOp,
                    IrData::Binary {
                        op: BinOpKind::Div,
                        lhs: IrId::new(0),
                        rhs: IrId::new(1),
                    },
                ),
            ],
        );
        let attr_path = vec![b"value".to_vec()];
        let mut evaluator = TreeWalk::new(&expression);
        assert!(
            evaluator
                .try_eval_demand_machine_instantiation_if_enabled(
                    expression.root,
                    &attr_path,
                    true,
                )
                .is_none()
        );
        assert!(evaluator.transient_value_stack_roots.is_empty());
        assert_eq!(evaluator.active_root_eval_node, None);

        let error = evaluator
            .eval_root()
            .expect_err("the unchanged oracle session evaluates the root once");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id } if id == expression.root
        ));
    }

    #[test]
    fn active_root_marker_is_restored_before_machine_panic_resumes() {
        let expression = ir(IrId::new(0), vec![pure(IrKind::Int, IrData::Int(1))]);
        let displaced = IrId::new(17);
        let mut evaluator = TreeWalk::new(&expression);
        evaluator.active_root_eval_node = Some(displaced);

        let panic = catch_unwind(AssertUnwindSafe(|| {
            evaluator
                .with_active_demand_root(expression.root, |_| panic!("injected demand-root panic"));
        }));
        assert!(panic.is_err());
        assert_eq!(evaluator.active_root_eval_node, Some(displaced));
    }

    #[test]
    fn preflight_visits_a_shared_dag_once() {
        const DEPTH: u32 = 64;
        let mut nodes = vec![
            pure(IrKind::Bool, IrData::Bool(true)),
            pure(IrKind::Int, IrData::Int(9)),
        ];
        let mut shared = IrId::new(1);
        for _ in 0..DEPTH {
            let next = IrId::new(nodes.len() as u32);
            nodes.push(pure(
                IrKind::If,
                IrData::Triple {
                    first: IrId::new(0),
                    second: shared,
                    third: shared,
                },
            ));
            shared = next;
        }
        let expression = ir(shared, nodes);
        let machine = TreeWalk::new(&expression);
        assert!(machine.compile_demand_program(shared).is_some());
    }

    #[test]
    fn deeply_nested_conditionals_use_the_explicit_control_stack() {
        const DEPTH: u32 = 20_000;
        let mut nodes = vec![
            pure(IrKind::Bool, IrData::Bool(true)),
            pure(IrKind::Int, IrData::Int(7)),
        ];
        let mut root = IrId::new(1);
        for _ in 0..DEPTH {
            let next = IrId::new(nodes.len() as u32);
            nodes.push(pure(
                IrKind::If,
                IrData::Triple {
                    first: IrId::new(0),
                    second: root,
                    third: IrId::new(1),
                },
            ));
            root = next;
        }
        let expression = ir(root, nodes);
        let mut machine = TreeWalk::new(&expression);
        let program = machine
            .compile_demand_program(root)
            .expect("deep scalar root is admitted");
        let value = machine
            .run_demand_program(program)
            .expect("machine evaluates");
        assert_eq!(
            machine.runtime_int_payload(root, Span::default(), value),
            Ok(7)
        );
        assert!(machine.transient_value_stack_roots.is_empty());
    }
}
