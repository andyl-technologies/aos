//! Default-off source-backed mixed execution for statically ready calls.
//!
//! The first admitted corridor is deliberately narrow: one ordinary Apply
//! thunk whose callable is a capture-free simple lambda, whose argument is an
//! inline `i32`, and whose target returns that parameter or an inline `i32`.
//! Plan lowering and native preparation finish before the outer thunk is
//! claimed. Native completion is accepted only through the backend-neutral
//! [`MixedReadyCallHook`] contract.

use std::rc::Rc;

use crate::compile::{
    IrData, IrId, IrKind,
    analysis::analyze_semantic_subslice,
    mixed_machine::{
        MixedCodeIdentity, MixedModuleKey, MixedOp, MixedOracleCallTargetBlock,
        MixedOracleNodeLowerOutcome, MixedOraclePlanLowerOutcome, MixedPlanBounds,
        lower_mixed_oracle_node, lower_mixed_oracle_ready_call_plan,
    },
    stg::{StgCodeBlock, StgLiteral, StgModuleId, StgOpcode},
};
use crate::eval::heap::EvalLambda;
use crate::eval::module::EvalNodeRef;
use crate::value::Value;

use super::{
    MixedReadyCallActivation, MixedReadyCallDecision, MixedReadyCallHook, MixedReadyCallToken,
    Tier1Engine, TreeWalk, lowered_ir_fingerprint,
};

const EMPTY_CAPTURE_LAYOUT_VERSION: u32 = 1;
const EMPTY_CAPTURE_LAYOUT_DOMAIN: &[u8] = b"aos-nix:mixed-ready-call:empty-capture:v1\0";
const SEMANTIC_PLAN_DOMAIN: &[u8] = b"aos-nix:mixed-ready-call:semantic-plan:v1\0";

/// One fully prepared activation retained across the outer force claim.
pub(super) struct PreparedMixedReadyCall {
    engine: Rc<dyn Tier1Engine>,
    token: MixedReadyCallToken,
    callable: Value,
    argument: Value,
    expected_result: Value,
}

impl PreparedMixedReadyCall {
    /// Runs the prepared activation after ordinary force/call leases are owned.
    pub(super) fn run(&self) -> MixedReadyCallHook {
        let frames = [self.callable];
        let calls = [MixedReadyCallDecision {
            callable: self.callable,
            target_ordinal: 0,
            frame: 0,
        }];
        self.engine.run_mixed_ready_call(
            self.token,
            MixedReadyCallActivation {
                argument: self.argument,
                entry_frame: 0,
                frames: &frames,
                frame_stride: 1,
                calls: &calls,
                expected_result: self.expected_result,
            },
        )
    }
}

impl TreeWalk {
    /// Prepares the narrow ready-call corridor without claiming evaluator work.
    pub(super) fn prepare_mixed_ready_call(
        &mut self,
        apply: EvalNodeRef,
        function: EvalNodeRef,
        function_value: Value,
        argument: EvalNodeRef,
        argument_value: Value,
        lambda: &EvalLambda,
        target_code: &StgCodeBlock,
    ) -> Option<PreparedMixedReadyCall> {
        if !self.mixed_ready_call_admitted()
            || !lambda.env().is_empty()
            || !lambda.with_scope_env().is_empty()
            || !lambda.scoped_global_env().is_empty()
        {
            return None;
        }
        let argument_integer = i32::try_from(argument_value.as_int().ok()?).ok()?;
        let module = lambda.module();
        let ir = self.tier1_module_ir(module)?;
        if apply.module() != module
            || function.module() != module
            || argument.module() != module
            || !matches!(
                ir.arena.node(apply.id()),
                Some(node)
                    if node.kind == IrKind::Apply
                        && matches!(
                            node.data,
                            IrData::Pair { first, second }
                                if first == function.id() && second == argument.id()
                        )
            )
        {
            return None;
        }
        let definition = unique_lambda_definition(ir, lambda)?;
        let module_digest = lowered_ir_fingerprint(ir).ok()?.as_bytes();
        let capture_layout_digest = *blake3::hash(EMPTY_CAPTURE_LAYOUT_DOMAIN).as_bytes();
        let MixedOracleNodeLowerOutcome::Lowered(entry) = lower_mixed_oracle_node(
            ir,
            StgModuleId::new(u64::from(module.as_u32())),
            module_digest,
            apply.id(),
            apply.id(),
            capture_layout_digest,
        )
        .ok()?
        else {
            return None;
        };
        let target = MixedOracleCallTargetBlock::new(
            MixedCodeIdentity::new(
                module_digest,
                definition,
                lambda.body(),
                Some(lambda.frame()),
                capture_layout_digest,
            ),
            target_code.clone(),
        );
        let semantic_digest = semantic_plan_digest(ir, apply.id(), lambda.body())?;
        let MixedOraclePlanLowerOutcome::Lowered(plan) = lower_mixed_oracle_ready_call_plan(
            MixedModuleKey::new(module_digest, semantic_digest, EMPTY_CAPTURE_LAYOUT_VERSION),
            MixedPlanBounds::new(16, 1, 1),
            &entry,
            &[target],
        )
        .ok()?
        else {
            return None;
        };
        let [
            MixedOp::LoadLocal { slot: 0, .. },
            MixedOp::ConstInt { value, .. },
            ..,
        ] = plan.operations()
        else {
            return None;
        };
        if i32::try_from(*value).ok()? != argument_integer {
            return None;
        }
        let expected_result = ready_target_result(target_code, argument_value)?;
        let engine = self.tier1_engine.clone()?;
        let token = engine.prepare_mixed_ready_call(&plan)?;
        Some(PreparedMixedReadyCall {
            engine,
            token,
            callable: function_value,
            argument: argument_value,
            expected_result,
        })
    }

    /// Prepares a direct source application through the same packed target seam.
    pub(super) fn prepare_direct_mixed_ready_call(
        &mut self,
        apply: EvalNodeRef,
        function: EvalNodeRef,
        function_value: Value,
        argument: EvalNodeRef,
        argument_value: Value,
        lambda: &EvalLambda,
    ) -> Option<PreparedMixedReadyCall> {
        let key = crate::compile::stg::StgCodeKey::new(
            StgModuleId::new(u64::from(lambda.module().as_u32())),
            lambda.body(),
            Some(lambda.frame()),
        );
        let target_code = self.stg_apply_cached_block(lambda.module(), key).ok()??;
        self.prepare_mixed_ready_call(
            apply,
            function,
            function_value,
            argument,
            argument_value,
            lambda,
            &target_code,
        )
    }

    /// Returns whether mixed preparation is safe in the current evaluator mode.
    fn mixed_ready_call_admitted(&self) -> bool {
        self.options.mixed_ready_call_enabled()
            && self.tier1_engine.is_some()
            && !self.stg_apply_runtime.active
            && !self.stg_session_active
            && self.gc_mode == crate::eval::heap::EvalGcMode::Off
            && self.options.parallel_workers().is_none()
            && !self.options.parallel_thunk_payloads_enabled()
            && self.shared.is_none()
            && !self.force_cache_active
            && !self.options.memo_active()
            && !self.options.boundary_memo_active()
    }
}

fn unique_lambda_definition(ir: &crate::compile::Ir, lambda: &EvalLambda) -> Option<IrId> {
    let mut matches = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            matches!(
                (node.kind, node.data),
                (
                    IrKind::Lambda,
                    IrData::Lambda {
                        pattern,
                        body,
                        frame: Some(frame),
                    }
                ) if pattern == lambda.pattern()
                    && body == lambda.body()
                    && frame == lambda.frame()
            )
            .then(|| u32::try_from(index).ok())
            .flatten()
            .map(IrId::new)
        });
    let found = matches.next()?;
    matches.next().is_none().then_some(found)
}

fn semantic_plan_digest(ir: &crate::compile::Ir, apply: IrId, target: IrId) -> Option<[u8; 32]> {
    let entry = analyze_semantic_subslice(ir, apply).ok()?;
    let target = analyze_semantic_subslice(ir, target).ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEMANTIC_PLAN_DOMAIN);
    hasher.update(&(entry.canonical_bytes().len() as u64).to_le_bytes());
    hasher.update(entry.canonical_bytes());
    hasher.update(&(target.canonical_bytes().len() as u64).to_le_bytes());
    hasher.update(target.canonical_bytes());
    Some(*hasher.finalize().as_bytes())
}

fn ready_target_result(code: &StgCodeBlock, argument: Value) -> Option<Value> {
    let word = *code.words().get(code.root_pc() as usize)?;
    match word.opcode() {
        StgOpcode::Local if word.operand_a() == 0 => Some(argument),
        StgOpcode::LiteralInt => match code.literals().get(word.operand_a() as usize)? {
            StgLiteral::Int(value) => {
                i32::try_from(*value).ok()?;
                Some(Value::int(*value))
            }
        },
        _ => None,
    }
}
