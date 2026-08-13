//! Direct mixed ready-call executable preparation and activation.
//!
//! The tree-walk oracle owns only backend-neutral rooted [`Value`] inputs.
//! This module privately translates those values into the one-word
//! mixed-superblock ABI and accepts a native completion only when its word
//! exactly matches the evaluator's already-known safe result.

use std::rc::Rc;

use ratchet_core::mixed_machine::MixedModulePlan;
use ratchet_jit::cranelift::{
    JitMixedSuperblockActivation, JitMixedSuperblockCallDecision, JitMixedSuperblockOutcome,
    compile_mixed_superblock,
};
use ratchet_oracle::eval::tree_walk::{
    MixedReadyCallActivation, MixedReadyCallHook, MixedReadyCallToken,
};

use super::NixJitTier1Engine;

impl NixJitTier1Engine {
    /// Prepares or reuses entry zero of one validated ready-call plan.
    pub(super) fn prepare_mixed_ready_call_impl(
        &self,
        plan: &MixedModulePlan,
    ) -> Option<MixedReadyCallToken> {
        {
            let executables = self.mixed_ready.borrow();
            if let Some((index, _)) = executables.iter().enumerate().find(|(_, executable)| {
                executable.cache_key().plan() == plan.key()
                    && executable.cache_key().canonical_plan() == plan.canonical_bytes()
            }) {
                return u64::try_from(index).ok().map(MixedReadyCallToken::new);
            }
        }

        let executable = Rc::new(compile_mixed_superblock(plan, 0).ok()?);
        let mut executables = self.mixed_ready.borrow_mut();
        let index = u64::try_from(executables.len()).ok()?;
        executables.push(executable);
        Some(MixedReadyCallToken::new(index))
    }

    /// Runs one prepared executable without decoding an arbitrary native word.
    pub(super) fn run_mixed_ready_call_impl(
        &self,
        token: MixedReadyCallToken,
        activation: MixedReadyCallActivation<'_>,
    ) -> MixedReadyCallHook {
        let Ok(index) = usize::try_from(token.engine_id()) else {
            return MixedReadyCallHook::Invalid;
        };
        let executable = {
            let executables = self.mixed_ready.borrow();
            let Some(executable) = executables.get(index) else {
                return MixedReadyCallHook::Invalid;
            };
            Rc::clone(executable)
        };

        let frames: Vec<u64> = activation
            .frames
            .iter()
            .map(|value| value.transient_identity_bits())
            .collect();
        let calls: Vec<JitMixedSuperblockCallDecision> = activation
            .calls
            .iter()
            .map(|decision| {
                JitMixedSuperblockCallDecision::target(
                    decision.callable.transient_identity_bits(),
                    decision.target_ordinal,
                    decision.frame,
                )
            })
            .collect();
        let mut updates = [];
        let Ok(mut native) = JitMixedSuperblockActivation::new(
            activation.argument.transient_identity_bits(),
            activation.entry_frame,
            &frames,
            activation.frame_stride,
            &calls,
            &[],
            &mut updates,
        ) else {
            return MixedReadyCallHook::Invalid;
        };
        match executable.run(&mut native) {
            JitMixedSuperblockOutcome::Complete(raw)
                if raw == activation.expected_result.transient_identity_bits() =>
            {
                MixedReadyCallHook::Completed(activation.expected_result)
            }
            JitMixedSuperblockOutcome::Complete(_) => MixedReadyCallHook::Invalid,
            JitMixedSuperblockOutcome::SideExit(statepoint) => {
                MixedReadyCallHook::SideExit(statepoint)
            }
            JitMixedSuperblockOutcome::InvalidActivation => MixedReadyCallHook::Invalid,
        }
    }
}

#[cfg(all(test, feature = "candidate_c_value"))]
mod tests {
    use ratchet_core::{
        Ir, IrData, lower,
        mixed_machine::{
            MixedCodeIdentity, MixedModuleKey, MixedOracleCallTargetBlock,
            MixedOracleNodeLowerOutcome, MixedOraclePlanLowerOutcome, MixedPlanBounds,
            lower_mixed_oracle_node, lower_mixed_oracle_ready_call_plan,
        },
        resolve,
        stg::{StgCodeKey, StgLowerOutcome, StgModuleId, lower_stg_code_block},
        syntax::parse_str,
    };
    use ratchet_oracle::eval::tree_walk::{MixedReadyCallDecision, Tier1Engine};
    use ratchet_value::value::Value;

    use super::*;

    fn lowered(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("IR lowers")
    }

    fn literal_ready_plan() -> MixedModulePlan {
        let entry_ir = lowered("f: f 1");
        let entry_lambda = *entry_ir.arena.node(entry_ir.root).expect("lambda exists");
        let IrData::Lambda {
            body: entry_body, ..
        } = entry_lambda.data
        else {
            panic!("lambda payload expected");
        };
        let MixedOracleNodeLowerOutcome::Lowered(entry) = lower_mixed_oracle_node(
            &entry_ir,
            StgModuleId::new(7),
            [7; 32],
            entry_ir.root,
            entry_body,
            [9; 32],
        )
        .expect("entry lowering succeeds") else {
            panic!("application entry must lower");
        };

        let target_ir = lowered("x: 42");
        let target_lambda = *target_ir.arena.node(target_ir.root).expect("lambda exists");
        let IrData::Lambda {
            body: target_body,
            frame: target_frame,
            ..
        } = target_lambda.data
        else {
            panic!("lambda payload expected");
        };
        let StgLowerOutcome::Lowered(target_code) = lower_stg_code_block(
            &target_ir,
            StgCodeKey::new(StgModuleId::new(8), target_body, target_frame),
        )
        .expect("target lowering succeeds") else {
            panic!("literal target must lower");
        };
        let target = MixedOracleCallTargetBlock::new(
            MixedCodeIdentity::new([8; 32], target_ir.root, target_body, target_frame, [5; 32]),
            target_code,
        );
        let MixedOraclePlanLowerOutcome::Lowered(plan) = lower_mixed_oracle_ready_call_plan(
            MixedModuleKey::new([7; 32], [6; 32], 1),
            MixedPlanBounds::new(16, 1, 1),
            &entry,
            &[target],
        )
        .expect("ready-call translation succeeds") else {
            panic!("ready-call plan must lower");
        };
        plan
    }

    #[test]
    fn prepared_literal_ready_call_returns_only_the_known_value() {
        let engine = NixJitTier1Engine::new().expect("engine initializes");
        let token = engine
            .prepare_mixed_ready_call(&literal_ready_plan())
            .expect("plan compiles");
        let callable = Value::int(7);
        let expected = Value::int(42);
        let frames = [callable];
        let calls = [MixedReadyCallDecision {
            callable,
            target_ordinal: 0,
            frame: 0,
        }];

        let outcome = engine.run_mixed_ready_call(
            token,
            MixedReadyCallActivation {
                argument: Value::null(),
                entry_frame: 0,
                frames: &frames,
                frame_stride: 1,
                calls: &calls,
                expected_result: expected,
            },
        );

        let MixedReadyCallHook::Completed(actual) = outcome else {
            panic!("native ready-call must complete");
        };
        assert_eq!(
            actual.transient_identity_bits(),
            expected.transient_identity_bits()
        );
    }

    #[test]
    fn prepared_literal_ready_call_rejects_wrong_expected_value() {
        let engine = NixJitTier1Engine::new().expect("engine initializes");
        let token = engine
            .prepare_mixed_ready_call(&literal_ready_plan())
            .expect("plan compiles");
        let callable = Value::int(7);
        let frames = [callable];
        let calls = [MixedReadyCallDecision {
            callable,
            target_ordinal: 0,
            frame: 0,
        }];

        let outcome = engine.run_mixed_ready_call(
            token,
            MixedReadyCallActivation {
                argument: Value::null(),
                entry_frame: 0,
                frames: &frames,
                frame_stride: 1,
                calls: &calls,
                expected_result: Value::int(41),
            },
        );

        assert!(matches!(outcome, MixedReadyCallHook::Invalid));
    }
}
