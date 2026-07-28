//! Default-off generic packed-STG application execution.
//!
//! The executor owns explicit value, lazy-argument, update, call, and control
//! stacks. A complete lambda body is lowered, runtime-checked, cached, and all
//! stack storage is reserved before the ordinary Apply thunk is claimed.
//! Unsupported bodies therefore return to the tree-walk oracle without an
//! observable force-state transition.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use crate::compile::stg::{
    StgCodeBlock, StgCodeKey, StgDeclineReason, StgLiteral, StgLowerOutcome, StgModuleId,
    StgNumericBinOp, StgOpcode, lower_stg_code_block,
};

use super::*;

const IR_KIND_COUNT: usize = IrKind::PrimOp as usize + 1;
const STG_DISQUALIFIER_HISTOGRAM_LEN: usize = 32;
const STG_DISQUALIFIER_LAMBDA: u8 = 1 << 0;
const STG_DISQUALIFIER_PRIMOP: u8 = 1 << 3;
const STG_DISQUALIFIER_INVALID_SITE: u8 = 1 << 4;

/// Dynamic counters for the default-off generic executor.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct StgApplyCounters {
    pub(super) attempts: u64,
    pub(super) declines: u64,
    pub(super) cache_hits: u64,
    pub(super) blocks_lowered: u64,
    pub(super) claims: u64,
    pub(super) completions: u64,
    pub(super) force_continuations: u64,
    pub(super) oracle_leaves: u64,
    pub(super) errors: u64,
    pub(super) panics: u64,
    pub(super) lower_declines: [u64; 11],
    pub(super) lower_decline_kinds: [u64; IR_KIND_COUNT],
    pub(super) blocks_with_lambda: u64,
    pub(super) blocks_with_thunk: u64,
    pub(super) blocks_with_apply: u64,
    pub(super) blocks_with_select: u64,
    pub(super) blocks_with_other_primop: u64,
    /// Newly lowered blocks grouped by their complete executor-disqualifier bitmap.
    pub(super) disqualifier_bitmap_histogram: [u64; STG_DISQUALIFIER_HISTOGRAM_LEN],
    /// Cache hits for blocks whose capability preflight cached a negative result.
    pub(super) negative_cache_hits: u64,
    /// Lazy thunk nodes entered by the explicit machine.
    pub(super) thunk_continuations: u64,
    /// Unary application continuations completed by the explicit machine.
    pub(super) apply_continuations: u64,
}

#[derive(Clone, Copy, Debug)]
enum StgControl {
    Eval(u32),
    ForceTop(u32),
    FinishAddLeft {
        pc: u32,
        site: u32,
    },
    FinishBinary {
        pc: u32,
        site: u32,
    },
    CaptureArgument(u32),
    FinishElemAt {
        pc: u32,
        base: usize,
    },
    FinishSelect {
        pc: u32,
        site: u32,
    },
    FinishApply {
        pc: u32,
        function_pc: u32,
        argument_pc: u32,
    },
}

/// Mutable state owned by the generic packed-STG executor.
#[derive(Debug, Default)]
pub(super) struct StgApplyRuntime {
    cache: HashMap<StgCodeKey, Option<Rc<StgCodeBlock>>>,
    /// Values retained across explicit machine continuations.
    pub(super) value_stack: Vec<Value>,
    /// Lazy builtin arguments retained across explicit machine continuations.
    pub(super) argument_stack: Vec<EvalPrimOpArg>,
    /// Detached ordinary thunk claims awaiting publication.
    pub(super) update_stack: Vec<ForceLeaseToken>,
    /// Lambda contexts awaiting restoration.
    pub(super) call_stack: Vec<LambdaCallLeaseToken>,
    /// Packed-node continuations awaiting execution.
    control_stack: Vec<StgControl>,
    /// Whether this executor currently owns control.
    pub(super) active: bool,
    pub(super) counters: StgApplyCounters,
    #[cfg(test)]
    pub(super) panic_after_claim: bool,
    #[cfg(test)]
    pub(super) panic_before_nested_apply: bool,
}

impl StgApplyRuntime {
    /// Returns whether no callback or retained continuation state is live.
    pub(super) fn is_idle(&self) -> bool {
        !self.active
            && self.value_stack.is_empty()
            && self.argument_stack.is_empty()
            && self.update_stack.is_empty()
            && self.call_stack.is_empty()
            && self.control_stack.is_empty()
    }

    fn clear_execution(&mut self) {
        self.value_stack.clear();
        self.argument_stack.clear();
        self.update_stack.clear();
        self.call_stack.clear();
        self.control_stack.clear();
        self.active = false;
    }
}

impl TreeWalk {
    /// Tries to force one ordinary Apply thunk through packed STG.
    ///
    /// Returns `None` only before claiming the thunk. Once a detached force
    /// lease is owned, every success, error, and panic is completed or unwound
    /// through the evaluator-owned update and lambda-call stacks.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_force_stg_apply(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        function: EvalNodeRef,
        function_span: Span,
        function_value: Value,
        argument: EvalNodeRef,
        argument_value: Value,
    ) -> Option<Result<Value, TreeWalkError>> {
        let interpreted_admitted = self.stg_apply_admitted();
        let mixed_admitted = self.options.mixed_ready_call_enabled();
        if (!interpreted_admitted && !mixed_admitted) || function_value.tag() != ValueTag::Lambda {
            return None;
        }
        self.stg_apply_runtime.counters.attempts =
            self.stg_apply_runtime.counters.attempts.saturating_add(1);

        let lambda = match self.heap.clone_lambda(function_value) {
            Ok(lambda) => lambda,
            Err(error) => {
                return Some(Err(TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: function.id(),
                        source: error,
                    },
                    function_span,
                )));
            }
        };
        if function.module() != lambda.module() || argument.module() != lambda.module() {
            self.stg_apply_decline();
            return None;
        }
        let pattern = match self.node_in_module(lambda.module(), lambda.pattern()) {
            Ok(pattern) => *pattern,
            Err(error) => return Some(Err(error)),
        };
        if pattern.kind != IrKind::Formal
            || !matches!(pattern.data, IrData::Formal { default: None, .. })
        {
            self.stg_apply_decline();
            return None;
        }
        let argument_span = match self.node_in_module(argument.module(), argument.id()) {
            Ok(node) => node.span,
            Err(error) => return Some(Err(error)),
        };
        let key = StgCodeKey::new(
            StgModuleId::new(u64::from(lambda.module().as_u32())),
            lambda.body(),
            Some(lambda.frame()),
        );
        let block = match self.stg_apply_cached_block(lambda.module(), key) {
            Ok(Some(block)) => block,
            Ok(None) => {
                self.stg_apply_decline();
                return None;
            }
            Err(error) => return Some(Err(error)),
        };
        let prepared_mixed = self.prepare_mixed_ready_call(
            EvalNodeRef::new(self.current_module, id),
            function,
            function_value,
            argument,
            argument_value,
            &lambda,
            &block,
        );
        if !interpreted_admitted && prepared_mixed.is_none() {
            self.stg_apply_decline();
            return None;
        }
        if !self.stg_apply_reserve(block.words().len()) {
            self.stg_apply_decline();
            return None;
        }

        let force_token = match self.begin_force_lease(id, span, source_thunk) {
            Ok(BeginForceLease::AlreadyForced(value)) => return Some(Ok(value)),
            Ok(BeginForceLease::Claimed(token)) => token,
            Ok(BeginForceLease::Declined) => {
                self.stg_apply_decline();
                return None;
            }
            Err(error) => return Some(Err(error)),
        };

        self.note_direct_island_force();
        self.increment_thunks_forced();
        self.stg_apply_runtime.counters.claims =
            self.stg_apply_runtime.counters.claims.saturating_add(1);
        self.stg_apply_runtime.update_stack.push(force_token);
        self.stg_apply_runtime.active = true;
        let saved_module = self.current_module;
        self.current_module = function.module();

        let outcome = catch_unwind(AssertUnwindSafe(|| {
            #[cfg(test)]
            if self.stg_apply_runtime.panic_after_claim {
                panic!("injected packed-STG panic after Apply claim");
            }
            let work = match self.begin_lambda_call_lease(
                id,
                span,
                function.id(),
                function_value,
                function_span,
                argument.id(),
                argument_span,
                argument_value,
            )? {
                BeginLambdaCallLease::Ready(work) => work,
                BeginLambdaCallLease::Declined => {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::InvalidNodeKind {
                            id: lambda.body(),
                            kind: IrKind::Lambda,
                        },
                        span,
                    ));
                }
            };
            debug_assert_eq!(work.module, lambda.module());
            debug_assert_eq!(work.body, lambda.body());
            self.stg_apply_runtime.call_stack.push(work.token);
            if let Some(prepared) = prepared_mixed.as_ref()
                && let MixedReadyCallHook::Completed(value) = prepared.run()
            {
                let Some(call_token) = self.stg_apply_runtime.call_stack.pop() else {
                    unreachable!("mixed ready-call stack is unbalanced");
                };
                return self.finish_lambda_call_lease(call_token, Ok(value));
            }
            self.stg_apply_runtime
                .control_stack
                .push(StgControl::Eval(block.root_pc()));
            let value = self.run_stg_block(&block)?;
            let Some(call_token) = self.stg_apply_runtime.call_stack.pop() else {
                unreachable!("packed-STG lambda call stack is unbalanced");
            };
            self.finish_lambda_call_lease(call_token, Ok(value))
        }));

        match outcome {
            Ok(Ok(value)) => {
                let Some(token) = self.stg_apply_runtime.update_stack.pop() else {
                    unreachable!("packed-STG update stack is unbalanced");
                };
                let result = self.finish_force_lease(id, span, token, value);
                self.current_module = saved_module;
                self.stg_apply_runtime.clear_execution();
                match result {
                    Ok(value) => {
                        self.stg_apply_runtime.counters.completions = self
                            .stg_apply_runtime
                            .counters
                            .completions
                            .saturating_add(1);
                        Some(Ok(value))
                    }
                    Err(error) => {
                        self.stg_apply_runtime.counters.errors =
                            self.stg_apply_runtime.counters.errors.saturating_add(1);
                        Some(Err(error))
                    }
                }
            }
            Ok(Err(error)) => {
                let error = self.error_with_current_source(error);
                self.abort_stg_apply(id, span);
                self.current_module = saved_module;
                self.stg_apply_runtime.clear_execution();
                self.stg_apply_runtime.counters.errors =
                    self.stg_apply_runtime.counters.errors.saturating_add(1);
                Some(Err(error))
            }
            Err(payload) => {
                self.abort_stg_apply(id, span);
                self.current_module = saved_module;
                self.stg_apply_runtime.clear_execution();
                self.stg_apply_runtime.counters.panics =
                    self.stg_apply_runtime.counters.panics.saturating_add(1);
                resume_unwind(payload)
            }
        }
    }

    fn stg_apply_admitted(&self) -> bool {
        self.options.stg_session_enabled()
            && !self.stg_apply_runtime.active
            && !self.stg_session_active
            && self.gc_mode == EvalGcMode::Off
            && self.options.gc_stress_policy() == GcStressPolicy::disabled()
            && self.options.parallel_workers().is_none()
            && !self.options.parallel_thunk_payloads_enabled()
            && self.shared.is_none()
            && self.tier1_engine.is_none()
            && !self.options.jit_tier1_publish_enabled()
            && !self.force_cache_active
            && !self.options.memo_active()
            && !self.options.boundary_memo_active()
            && !self.options.eval_stats_dump()
    }

    fn stg_apply_decline(&mut self) {
        self.stg_apply_runtime.counters.declines =
            self.stg_apply_runtime.counters.declines.saturating_add(1);
    }

    pub(super) fn stg_apply_cached_block(
        &mut self,
        module: EvalModuleId,
        key: StgCodeKey,
    ) -> Result<Option<Rc<StgCodeBlock>>, TreeWalkError> {
        if let Some(cached) = self.stg_apply_runtime.cache.get(&key) {
            self.stg_apply_runtime.counters.cache_hits =
                self.stg_apply_runtime.counters.cache_hits.saturating_add(1);
            if cached.is_none() {
                self.stg_apply_runtime.counters.negative_cache_hits = self
                    .stg_apply_runtime
                    .counters
                    .negative_cache_hits
                    .saturating_add(1);
            }
            return Ok(cached.clone());
        }
        let outcome = lower_stg_code_block(self.module_ir(module)?, key).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidNodeId { id: key.body() },
                Span::default(),
            )
        })?;
        let block = match outcome {
            StgLowerOutcome::Lowered(block) => {
                self.stg_apply_runtime.counters.blocks_lowered = self
                    .stg_apply_runtime
                    .counters
                    .blocks_lowered
                    .saturating_add(1);
                self.record_stg_block_shapes(&block);
                let disqualifiers = self.stg_block_disqualifiers(&block);
                let histogram = &mut self
                    .stg_apply_runtime
                    .counters
                    .disqualifier_bitmap_histogram[usize::from(disqualifiers)];
                *histogram = histogram.saturating_add(1);
                (disqualifiers == 0).then(|| Rc::new(block))
            }
            StgLowerOutcome::Declined(decline) => {
                let kind = decline.kind() as usize;
                self.stg_apply_runtime.counters.lower_decline_kinds[kind] =
                    self.stg_apply_runtime.counters.lower_decline_kinds[kind].saturating_add(1);
                let index = match decline.reason() {
                    StgDeclineReason::UnsupportedKind => 0,
                    StgDeclineReason::UnsupportedShape => 1,
                    StgDeclineReason::SelectDefault => 2,
                    StgDeclineReason::DynamicSelectPath => 3,
                    StgDeclineReason::NonUnaryLambda => 4,
                    StgDeclineReason::MissingFrameContext => 5,
                    StgDeclineReason::InvalidFrameSlot => 6,
                    StgDeclineReason::InvalidFrameCapture => 7,
                    StgDeclineReason::AmbiguousFrameContext => 8,
                    StgDeclineReason::NonNumericBinaryOperator => 9,
                    StgDeclineReason::OperandTooWide => 10,
                };
                self.stg_apply_runtime.counters.lower_declines[index] =
                    self.stg_apply_runtime.counters.lower_declines[index].saturating_add(1);
                None
            }
        };
        self.stg_apply_runtime.cache.insert(key, block.clone());
        Ok(block)
    }

    /// Records opcode families once per newly lowered complete block.
    fn record_stg_block_shapes(&mut self, block: &StgCodeBlock) {
        let mut lambda = false;
        let mut thunk = false;
        let mut apply = false;
        let mut select = false;
        let mut other_primop = false;
        for word in block.words() {
            match word.opcode() {
                StgOpcode::Lambda1 => lambda = true,
                StgOpcode::Thunk => thunk = true,
                StgOpcode::Apply1 => apply = true,
                StgOpcode::Select => select = true,
                StgOpcode::PrimOp => {
                    let exact_elem_at = block
                        .primop_sites()
                        .get(word.operand_a() as usize)
                        .is_some_and(|site| {
                            site.argument_pcs().len() == 2
                                && self.symbols.resolve(site.symbol()) == Some(b"elemAt")
                        });
                    other_primop |= !exact_elem_at;
                }
                StgOpcode::LiteralInt
                | StgOpcode::LiteralBool
                | StgOpcode::LiteralNull
                | StgOpcode::Local
                | StgOpcode::Upval
                | StgOpcode::BinaryNumeric
                | StgOpcode::OracleLeaf => {}
            }
        }
        let counters = &mut self.stg_apply_runtime.counters;
        counters.blocks_with_lambda = counters
            .blocks_with_lambda
            .saturating_add(u64::from(lambda));
        counters.blocks_with_thunk = counters.blocks_with_thunk.saturating_add(u64::from(thunk));
        counters.blocks_with_apply = counters.blocks_with_apply.saturating_add(u64::from(apply));
        counters.blocks_with_select = counters
            .blocks_with_select
            .saturating_add(u64::from(select));
        counters.blocks_with_other_primop = counters
            .blocks_with_other_primop
            .saturating_add(u64::from(other_primop));
    }

    /// Computes the complete executor-capability bitmap for a lowered block.
    ///
    /// This preflight runs once, immediately after lowering. A nonzero bitmap
    /// is cached as a negative result so later forces neither retain the block
    /// nor rescan its hot words. Multiple bits deliberately remain set when a
    /// block contains overlapping unsupported opcode families.
    fn stg_block_disqualifiers(&self, block: &StgCodeBlock) -> u8 {
        let mut bits = 0_u8;
        for word in block.words() {
            match word.opcode() {
                StgOpcode::LiteralInt
                | StgOpcode::LiteralBool
                | StgOpcode::LiteralNull
                | StgOpcode::Local
                | StgOpcode::Upval
                | StgOpcode::OracleLeaf => {}
                StgOpcode::BinaryNumeric => {
                    if block
                        .binary_sites()
                        .get(word.operand_a() as usize)
                        .is_none()
                    {
                        bits |= STG_DISQUALIFIER_INVALID_SITE;
                    }
                }
                StgOpcode::Select => {
                    let valid = block
                        .select_sites()
                        .get(word.operand_a() as usize)
                        .is_some_and(|site| site.default_pc().is_none());
                    if !valid {
                        bits |= STG_DISQUALIFIER_INVALID_SITE;
                    }
                }
                StgOpcode::PrimOp => {
                    let executable = block
                        .primop_sites()
                        .get(word.operand_a() as usize)
                        .is_some_and(|site| {
                            site.argument_pcs().len() == 2
                                && self.symbols.resolve(site.symbol()) == Some(b"elemAt")
                        });
                    if !executable {
                        bits |= STG_DISQUALIFIER_PRIMOP;
                    }
                }
                StgOpcode::Lambda1 => bits |= STG_DISQUALIFIER_LAMBDA,
                StgOpcode::Thunk | StgOpcode::Apply1 => {}
            }
        }
        bits
    }

    fn stg_apply_reserve(&mut self, nodes: usize) -> bool {
        let controls = nodes.saturating_mul(4).saturating_add(4);
        self.stg_apply_runtime
            .value_stack
            .try_reserve(nodes)
            .is_ok()
            && self
                .stg_apply_runtime
                .argument_stack
                .try_reserve(nodes)
                .is_ok()
            && self.stg_apply_runtime.update_stack.try_reserve(1).is_ok()
            && self.stg_apply_runtime.call_stack.try_reserve(1).is_ok()
            && self
                .stg_apply_runtime
                .control_stack
                .try_reserve(controls)
                .is_ok()
    }

    fn run_stg_block(&mut self, block: &StgCodeBlock) -> Result<Value, TreeWalkError> {
        while let Some(control) = self.stg_apply_runtime.control_stack.pop() {
            match control {
                StgControl::Eval(pc) => self.eval_stg_pc(block, pc)?,
                StgControl::ForceTop(pc) => {
                    let value = self.pop_stg_value(pc)?;
                    if value.is_thunk() {
                        self.stg_apply_runtime.counters.force_continuations = self
                            .stg_apply_runtime
                            .counters
                            .force_continuations
                            .saturating_add(1);
                    }
                    let source = self.stg_source(block, pc)?;
                    let value = self.force_node_result(source.ir(), source.span(), value)?;
                    self.stg_apply_runtime.value_stack.push(value);
                }
                StgControl::FinishAddLeft { pc, site } => {
                    self.finish_stg_add_left(block, pc, site)?;
                }
                StgControl::FinishBinary { pc, site } => {
                    self.finish_stg_binary(block, pc, site)?;
                }
                StgControl::CaptureArgument(pc) => {
                    let value = self.pop_stg_value(pc)?;
                    let source = self.stg_source(block, pc)?;
                    self.stg_apply_runtime
                        .argument_stack
                        .push(EvalPrimOpArg::new_in_module(
                            self.current_module,
                            source.ir(),
                            source.span(),
                            value,
                        ));
                }
                StgControl::FinishElemAt { pc, base } => {
                    let (index, list) = match self.stg_apply_runtime.argument_stack.get(base..) {
                        Some([index, list]) => (*index, *list),
                        _ => return Err(self.stg_invariant_error(pc)),
                    };
                    let result = self.eval_elem_at_primop_value(list, index)?;
                    self.stg_apply_runtime.argument_stack.truncate(base);
                    self.stg_apply_runtime.value_stack.push(result);
                    self.stg_apply_runtime
                        .control_stack
                        .push(StgControl::ForceTop(pc));
                }
                StgControl::FinishSelect { pc, site } => {
                    self.finish_stg_select(block, pc, site)?;
                }
                StgControl::FinishApply {
                    pc,
                    function_pc,
                    argument_pc,
                } => {
                    self.finish_stg_apply(block, pc, function_pc, argument_pc)?;
                }
            }
        }
        if self.stg_apply_runtime.value_stack.len() != 1 {
            return Err(self.stg_invariant_error(block.root_pc()));
        }
        self.pop_stg_value(block.root_pc())
    }

    fn eval_stg_pc(&mut self, block: &StgCodeBlock, pc: u32) -> Result<(), TreeWalkError> {
        let word = block
            .words()
            .get(pc as usize)
            .copied()
            .ok_or_else(|| self.stg_invariant_error(pc))?;
        let source = self.stg_source(block, pc)?;
        match word.opcode() {
            StgOpcode::LiteralInt => {
                let StgLiteral::Int(value) = block
                    .literals()
                    .get(word.operand_a() as usize)
                    .copied()
                    .ok_or_else(|| self.stg_invariant_error(pc))?;
                let value = self.runtime_int_value(source.ir(), source.span(), value)?;
                self.stg_apply_runtime.value_stack.push(value);
            }
            StgOpcode::LiteralBool => self
                .stg_apply_runtime
                .value_stack
                .push(Value::bool(word.operand_a() != 0)),
            StgOpcode::LiteralNull => self.stg_apply_runtime.value_stack.push(Value::null()),
            StgOpcode::Local | StgOpcode::Upval => {
                let node = *self.node(source.ir())?;
                let value = if word.opcode() == StgOpcode::Local {
                    self.eval_local_var(source.ir(), &node)?
                } else {
                    self.eval_upval_var(source.ir(), &node)?
                };
                self.stg_apply_runtime.value_stack.push(value);
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::ForceTop(pc));
            }
            StgOpcode::BinaryNumeric => {
                let site = block
                    .binary_sites()
                    .get(word.operand_a() as usize)
                    .copied()
                    .ok_or_else(|| self.stg_invariant_error(pc))?;
                if site.op() == StgNumericBinOp::Add {
                    self.stg_apply_runtime
                        .control_stack
                        .push(StgControl::FinishAddLeft {
                            pc,
                            site: word.operand_a(),
                        });
                    self.stg_apply_runtime
                        .control_stack
                        .push(StgControl::Eval(site.lhs_pc()));
                } else {
                    self.stg_apply_runtime
                        .control_stack
                        .push(StgControl::FinishBinary {
                            pc,
                            site: word.operand_a(),
                        });
                    self.stg_apply_runtime
                        .control_stack
                        .push(StgControl::Eval(site.rhs_pc()));
                    self.stg_apply_runtime
                        .control_stack
                        .push(StgControl::Eval(site.lhs_pc()));
                }
            }
            StgOpcode::PrimOp => {
                let site = block
                    .primop_sites()
                    .get(word.operand_a() as usize)
                    .ok_or_else(|| self.stg_invariant_error(pc))?;
                let [list_pc, index_pc] = site.argument_pcs() else {
                    return Err(self.stg_invariant_error(pc));
                };
                let base = self.stg_apply_runtime.argument_stack.len();
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::FinishElemAt { pc, base });
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::CaptureArgument(*list_pc));
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::Eval(*list_pc));
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::CaptureArgument(*index_pc));
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::Eval(*index_pc));
            }
            StgOpcode::OracleLeaf => {
                self.stg_apply_runtime.counters.oracle_leaves = self
                    .stg_apply_runtime
                    .counters
                    .oracle_leaves
                    .saturating_add(1);
                let value = self.eval_node(source.ir())?;
                self.stg_apply_runtime.value_stack.push(value);
            }
            StgOpcode::Select => {
                let site = block
                    .select_sites()
                    .get(word.operand_a() as usize)
                    .copied()
                    .ok_or_else(|| self.stg_invariant_error(pc))?;
                if site.default_pc().is_some() {
                    return Err(self.stg_invariant_error(pc));
                }
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::FinishSelect {
                        pc,
                        site: word.operand_a(),
                    });
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::Eval(site.receiver_pc()));
            }
            StgOpcode::Thunk => {
                self.stg_apply_runtime.counters.thunk_continuations = self
                    .stg_apply_runtime
                    .counters
                    .thunk_continuations
                    .saturating_add(1);
                let value = self.eval_lazy_node(source.ir())?;
                self.stg_apply_runtime.value_stack.push(value);
                // Apply arguments use `eval_call_argument` and therefore do
                // not enter their packed child. Every reached Thunk node is in
                // a demanded position and must resume at WHNF.
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::ForceTop(pc));
            }
            StgOpcode::Apply1 => {
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::FinishApply {
                        pc,
                        function_pc: word.operand_a(),
                        argument_pc: word.operand_b(),
                    });
                self.stg_apply_runtime
                    .control_stack
                    .push(StgControl::Eval(word.operand_a()));
            }
            StgOpcode::Lambda1 => {
                return Err(self.stg_invariant_error(pc));
            }
        }
        Ok(())
    }

    /// Completes one unary application through the evaluator's exact argument and call helpers.
    ///
    /// The function stays on `value_stack` while call-summary planning and lazy
    /// argument allocation run. The resulting argument is then retained beside
    /// it while [`TreeWalk::apply_lambda_value`] owns the ordinary lambda,
    /// primop, or functor call protocol. As with the rest of this executor, the
    /// copied Rust locals are sound only under the hard `GcMode::Off` admission
    /// rule; moving collection would require transient roots and post-safepoint
    /// reloads.
    fn finish_stg_apply(
        &mut self,
        block: &StgCodeBlock,
        pc: u32,
        function_pc: u32,
        argument_pc: u32,
    ) -> Result<(), TreeWalkError> {
        let function_source = self.stg_source(block, function_pc)?;
        let argument_source = self.stg_source(block, argument_pc)?;
        let apply_source = self.stg_source(block, pc)?;
        let function = self
            .stg_apply_runtime
            .value_stack
            .last()
            .copied()
            .ok_or_else(|| self.stg_invariant_error(function_pc))?;
        let function =
            self.ensure_applicable_value(function_source.ir(), function_source.span(), function)?;
        if block
            .words()
            .get(argument_pc as usize)
            .is_some_and(|word| word.opcode() == StgOpcode::Thunk)
        {
            self.stg_apply_runtime.counters.thunk_continuations = self
                .stg_apply_runtime
                .counters
                .thunk_continuations
                .saturating_add(1);
        }
        let argument = self.eval_call_argument(
            apply_source.ir(),
            function_source.ir(),
            function_source.span(),
            function,
            argument_source.ir(),
        )?;
        self.stg_apply_runtime.value_stack.push(argument);
        #[cfg(test)]
        if self.stg_apply_runtime.panic_before_nested_apply {
            panic!("injected packed-STG panic before nested Apply");
        }
        let value = self.apply_lambda_value(
            apply_source.ir(),
            apply_source.span(),
            function_source.ir(),
            function,
            function_source.span(),
            argument_source.ir(),
            argument,
        )?;
        let _ = self.pop_stg_value(argument_pc)?;
        let _ = self.pop_stg_value(function_pc)?;
        self.stg_apply_runtime.value_stack.push(value);
        self.stg_apply_runtime.counters.apply_continuations = self
            .stg_apply_runtime
            .counters
            .apply_continuations
            .saturating_add(1);
        self.stg_apply_runtime
            .control_stack
            .push(StgControl::ForceTop(pc));
        Ok(())
    }

    /// Completes a static, no-default selection through the oracle's exact helper.
    ///
    /// The receiver remains on `value_stack` throughout the helper call so the
    /// evaluator owns its retained continuation value. A copied Rust local is
    /// still passed to the helper; this is sound under the executor's hard
    /// `GcMode::Off` admission rule. Enabling moving collection here would also
    /// require a transient root plus reload after every possible safepoint.
    fn finish_stg_select(
        &mut self,
        block: &StgCodeBlock,
        pc: u32,
        site_index: u32,
    ) -> Result<(), TreeWalkError> {
        let site = block
            .select_sites()
            .get(site_index as usize)
            .copied()
            .ok_or_else(|| self.stg_invariant_error(pc))?;
        if site.default_pc().is_some() {
            return Err(self.stg_invariant_error(pc));
        }
        let receiver = self
            .stg_apply_runtime
            .value_stack
            .last()
            .copied()
            .ok_or_else(|| self.stg_invariant_error(site.receiver_pc()))?;
        let source = self.stg_source(block, pc)?;
        let value = self.eval_select_from_value(
            source.ir(),
            source.span(),
            receiver,
            site.path(),
            Some(site.site()),
            None,
            false,
        )?;
        let _ = self.pop_stg_value(site.receiver_pc())?;
        self.stg_apply_runtime.value_stack.push(value);
        self.stg_apply_runtime
            .control_stack
            .push(StgControl::ForceTop(pc));
        Ok(())
    }

    /// Continues numeric addition or exits to the exact overloaded oracle.
    ///
    /// Nix `+` dispatches on the forced left operand and must not evaluate the
    /// right operand when that dispatch fails. The packed machine therefore
    /// stages addition separately. Numeric left operands remain in the
    /// machine; strings, paths, attrsets, lazy-identity thunks, and invalid
    /// operands re-enter the original binary node before the right side has
    /// been touched.
    fn finish_stg_add_left(
        &mut self,
        block: &StgCodeBlock,
        pc: u32,
        site_index: u32,
    ) -> Result<(), TreeWalkError> {
        let site = block
            .binary_sites()
            .get(site_index as usize)
            .copied()
            .ok_or_else(|| self.stg_invariant_error(pc))?;
        let left = self.pop_stg_value(site.lhs_pc())?;
        if matches!(left.tag(), ValueTag::Int | ValueTag::Float) {
            self.stg_apply_runtime.value_stack.push(left);
            self.stg_apply_runtime
                .control_stack
                .push(StgControl::FinishBinary {
                    pc,
                    site: site_index,
                });
            self.stg_apply_runtime
                .control_stack
                .push(StgControl::Eval(site.rhs_pc()));
            return Ok(());
        }

        self.stg_apply_runtime.counters.oracle_leaves = self
            .stg_apply_runtime
            .counters
            .oracle_leaves
            .saturating_add(1);
        let source = self.stg_source(block, pc)?;
        let value = self.eval_node(source.ir())?;
        self.stg_apply_runtime.value_stack.push(value);
        Ok(())
    }

    fn finish_stg_binary(
        &mut self,
        block: &StgCodeBlock,
        pc: u32,
        site_index: u32,
    ) -> Result<(), TreeWalkError> {
        let site = block
            .binary_sites()
            .get(site_index as usize)
            .copied()
            .ok_or_else(|| self.stg_invariant_error(pc))?;
        let right = self.pop_stg_value(site.rhs_pc())?;
        let left = self.pop_stg_value(site.lhs_pc())?;
        let lhs = self.stg_source(block, site.lhs_pc())?;
        let rhs = self.stg_source(block, site.rhs_pc())?;
        let left = self
            .expect_number(lhs.ir(), left, lhs.span())
            .map_err(|error| self.label_binary_operand_error(error, lhs.span(), rhs.span()))?;
        let right = self
            .expect_number(rhs.ir(), right, rhs.span())
            .map_err(|error| self.label_binary_operand_error(error, lhs.span(), rhs.span()))?;
        let source = self.stg_source(block, pc)?;
        let node = *self.node(source.ir())?;
        let op = match site.op() {
            StgNumericBinOp::Add => BinaryArithmeticOp::Add,
            StgNumericBinOp::Sub => BinaryArithmeticOp::Sub,
            StgNumericBinOp::Mul => BinaryArithmeticOp::Mul,
            StgNumericBinOp::Div => BinaryArithmeticOp::Div,
        };
        let value = self.eval_numeric_values(source.ir(), &node, op, left, right)?;
        self.stg_apply_runtime.value_stack.push(value);
        Ok(())
    }

    fn pop_stg_value(&mut self, pc: u32) -> Result<Value, TreeWalkError> {
        self.stg_apply_runtime
            .value_stack
            .pop()
            .ok_or_else(|| self.stg_invariant_error(pc))
    }

    fn stg_source(
        &self,
        block: &StgCodeBlock,
        pc: u32,
    ) -> Result<crate::compile::stg::StgSourceMapEntry, TreeWalkError> {
        block
            .source_at(pc)
            .ok_or_else(|| self.stg_invariant_error(pc))
    }

    fn stg_invariant_error(&self, pc: u32) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::InvalidNodeId { id: IrId::new(pc) },
            Span::default(),
        )
    }

    fn abort_stg_apply(&mut self, id: IrId, span: Span) {
        while let Some(token) = self.stg_apply_runtime.call_stack.pop() {
            self.abort_lambda_call_lease(token);
        }
        while let Some(token) = self.stg_apply_runtime.update_stack.pop() {
            let _ = self.abort_force_lease(id, span, token);
        }
    }
}
