//! Exact-identity lowering of real oracle Node bodies into packed superblocks.
//!
//! This is the front end of the mixed runner adapter. It recovers the Node
//! body's resolver frame from immutable IR, lowers the real body through the
//! packed STG table, and retains an exact work identity suitable for
//! [`MixedForceGuards`]. Its deliberately narrow second stage translates one
//! unary application with explicit exact targets into a completely validated
//! guarded-call/force/update CFG.

use thiserror::Error;

use super::{
    MIXED_CALL_TARGET_CAP, MixedBlock, MixedBlockId, MixedCallTarget, MixedCodeIdentity,
    MixedEntry, MixedEntryKind, MixedForceGuards, MixedFunction, MixedFunctionId, MixedModuleKey,
    MixedModulePlan, MixedOp, MixedPlanBounds, MixedPlanError, MixedSource, MixedStatepoint,
    MixedStatepointId, MixedStatepointMode, MixedStatepointReason, MixedTableRange,
    MixedTerminator, MixedValueId, MixedValueType,
};
use crate::analysis::{IrFrameIdentity, IrFrameIdentityError, resolve_unique_ir_frame};
use crate::stg::{
    StgCodeBlock, StgCodeKey, StgDecline, StgLowerError, StgLowerOutcome, StgModuleId, StgOpcode,
    lower_stg_code_block,
};
use crate::{Ir, IrId};

/// A real frame-specialized Node body ready for mixed-CFG translation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixedOracleNodeBlock {
    work: MixedCodeIdentity,
    code: StgCodeBlock,
    apply_sites: u32,
}

impl MixedOracleNodeBlock {
    /// Returns the exact identity a runtime must match before claiming work.
    pub const fn work(&self) -> MixedCodeIdentity {
        self.work
    }

    /// Returns the packed real-IR expression table.
    pub const fn code(&self) -> &StgCodeBlock {
        &self.code
    }

    /// Returns the number of unary application nodes in the lowered block.
    pub const fn apply_sites(&self) -> u32 {
        self.apply_sites
    }
}

/// Conservative reason a real Node body did not enter the target grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MixedOracleNodeDecline {
    /// The body is not reachable from the immutable module root.
    UnreachableFrame,
    /// The shared body occurs under more than one resolver frame.
    AmbiguousFrame,
    /// Packed STG lowering conservatively rejected part of the body.
    Stg(StgDecline),
    /// The body contains no unary application and cannot cover Node/Apply work.
    NoApply,
}

/// Result of attempting the first real Node/Apply superblock lowering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MixedOracleNodeLowerOutcome {
    /// The complete body and at least one unary application were lowered.
    Lowered(MixedOracleNodeBlock),
    /// The body was conservatively declined without an executable fragment.
    Declined(MixedOracleNodeDecline),
}

/// Reports malformed immutable IR encountered before atomic lowering.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MixedOracleNodeLowerError {
    /// Resolver-frame recovery encountered malformed IR side tables.
    #[error("mixed oracle frame recovery failed")]
    Frame(#[from] IrFrameIdentityError),
    /// Packed STG lowering encountered malformed IR.
    #[error("mixed oracle packed lowering failed")]
    Stg(#[from] StgLowerError),
}

/// One caller-supplied exact guarded-call target and its real packed body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixedOracleCallTargetBlock {
    identity: MixedCodeIdentity,
    code: StgCodeBlock,
}

impl MixedOracleCallTargetBlock {
    /// Creates an explicit target without deriving or weakening its identity.
    pub const fn new(identity: MixedCodeIdentity, code: StgCodeBlock) -> Self {
        Self { identity, code }
    }

    /// Returns the exact identity checked by the guarded call.
    pub const fn identity(&self) -> MixedCodeIdentity {
        self.identity
    }

    /// Returns the real packed target body.
    pub const fn code(&self) -> &StgCodeBlock {
        &self.code
    }
}

/// Conservative reason an STG block did not enter the executable corridor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MixedOraclePlanDecline {
    /// At least one exact call target is required.
    NoCallTargets,
    /// The supplied exact target population exceeds the mixed-plan guard cap.
    TooManyCallTargets {
        /// Supplied target population.
        actual: usize,
        /// Maximum population accepted by one guarded application.
        cap: u32,
    },
    /// The entry root is not one unary application with two distinct leaves.
    UnsupportedEntryShape,
    /// One application operand is shared or occurs more than once.
    MultiUseApplyOperand,
    /// The callable leaf is not a direct lexical value.
    UnsupportedCallable,
    /// The argument leaf is not a supported literal or lexical load.
    UnsupportedArgument,
    /// A target is not a direct lexical-parameter return.
    UnsupportedCallTarget {
        /// Zero-based target index.
        target: usize,
    },
}

/// Result of atomically translating a real STG corridor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MixedOraclePlanLowerOutcome {
    /// The complete plan passed all mixed-machine validation.
    Lowered(MixedModulePlan),
    /// No partial plan was emitted.
    Declined(MixedOraclePlanDecline),
}

/// Malformed explicit input or an internally invalid translated plan.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MixedOraclePlanLowerError {
    /// An exact identity disagrees with the packed block it accompanies.
    #[error("mixed oracle {role} identity does not match its packed STG block")]
    IdentityMismatch {
        /// Whether the mismatch belongs to the entry or a target.
        role: &'static str,
    },
    /// A packed node lacks its mandatory original source coordinate.
    #[error("mixed oracle packed block is missing source coordinate for pc {pc}")]
    MissingSource {
        /// Packed program counter without a source-map entry.
        pc: u32,
    },
    /// The assembled corridor failed the complete mixed-plan validator.
    #[error("mixed oracle corridor failed mixed-plan validation")]
    Plan(#[from] MixedPlanError),
}

/// Atomically translates the smallest real STG application/force corridor.
///
/// The admitted entry is exactly one `Apply1` whose callable is a lexical
/// value and whose argument is a distinct lexical load or integer literal.
/// Every caller-supplied target must be a one-word lexical-parameter return.
/// The translator then installs complete guarded-call and force fallback
/// statepoints and three exact force/update arms. `claimed_result_slot` is the
/// runtime frame slot promised by each successfully claimed force family.
///
/// No code identity is synthesized: `targets` and `force_guards` are copied
/// exactly from the caller. Source coordinates are copied from each packed
/// block's source map. Unsupported or shared shapes decline before any plan is
/// returned.
///
/// # Errors
///
/// Returns [`MixedOraclePlanLowerError`] when an explicit identity disagrees
/// with its block, mandatory source information is absent, or the fully
/// assembled plan fails validation.
pub fn lower_mixed_oracle_apply_force_plan(
    key: MixedModuleKey,
    bounds: MixedPlanBounds,
    entry: &MixedOracleNodeBlock,
    targets: &[MixedOracleCallTargetBlock],
    force_guards: MixedForceGuards,
    claimed_result_slot: u32,
) -> Result<MixedOraclePlanLowerOutcome, MixedOraclePlanLowerError> {
    validate_block_identity("entry", entry.work, &entry.code)?;
    if targets.is_empty() {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::NoCallTargets,
        ));
    }
    if targets.len() > MIXED_CALL_TARGET_CAP as usize {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::TooManyCallTargets {
                actual: targets.len(),
                cap: MIXED_CALL_TARGET_CAP,
            },
        ));
    }

    let root_pc = entry.code.root_pc();
    let Some(root) = entry.code.words().get(root_pc as usize).copied() else {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::UnsupportedEntryShape,
        ));
    };
    if root.opcode() != StgOpcode::Apply1 || entry.apply_sites != 1 {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::UnsupportedEntryShape,
        ));
    }
    let callable_pc = root.operand_a();
    let argument_pc = root.operand_b();
    let operands_share_source = entry
        .code
        .source_at(callable_pc)
        .zip(entry.code.source_at(argument_pc))
        .is_some_and(|(callable, argument)| callable.ir() == argument.ir());
    if callable_pc == argument_pc || operands_share_source {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::MultiUseApplyOperand,
        ));
    }
    if entry.code.words().len() != 3 {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::UnsupportedEntryShape,
        ));
    }
    let Some(callable) = entry.code.words().get(callable_pc as usize).copied() else {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::UnsupportedCallable,
        ));
    };
    if !matches!(callable.opcode(), StgOpcode::Local | StgOpcode::Upval) {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::UnsupportedCallable,
        ));
    }
    let Some(callable_op) = lower_lexical(callable, MixedValueId::new(1)) else {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::UnsupportedCallable,
        ));
    };
    let Some(argument) = entry.code.words().get(argument_pc as usize).copied() else {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::UnsupportedArgument,
        ));
    };
    let Some(argument_op) = lower_argument(&entry.code, argument, MixedValueId::new(2)) else {
        return Ok(MixedOraclePlanLowerOutcome::Declined(
            MixedOraclePlanDecline::UnsupportedArgument,
        ));
    };

    let apply_source = packed_source(&entry.code, entry.work.module_digest, root_pc)?;
    let mut functions = Vec::with_capacity(1 + targets.len());
    let mut blocks = Vec::with_capacity(6 + targets.len());
    let mut call_targets = Vec::with_capacity(targets.len());
    functions.push(MixedFunction {
        source: apply_source,
        parameter: MixedValueId::new(0),
        parameter_type: MixedValueType::Value,
        return_type: MixedValueType::Value,
        entry: MixedBlockId::new(0),
        blocks: MixedTableRange::new(0, 6),
    });
    blocks.push(MixedBlock {
        source: apply_source,
        operations: MixedTableRange::new(0, 2),
        terminator: MixedTerminator::ApplyGuarded {
            function: MixedValueId::new(1),
            argument: MixedValueId::new(2),
            result: MixedValueId::new(3),
            targets: MixedTableRange::new(0, targets.len() as u32),
            continuation: MixedBlockId::new(1),
            fallback: MixedStatepointId::new(0),
        },
    });
    blocks.push(MixedBlock {
        source: apply_source,
        operations: MixedTableRange::new(2, 0),
        terminator: MixedTerminator::Force {
            subject: MixedValueId::new(3),
            result: MixedValueId::new(4),
            result_type: MixedValueType::Value,
            guards: force_guards,
            ready: MixedBlockId::new(2),
            node: MixedBlockId::new(3),
            apply: MixedBlockId::new(4),
            gen_list: MixedBlockId::new(5),
            fallback: MixedStatepointId::new(1),
        },
    });
    blocks.push(MixedBlock {
        source: apply_source,
        operations: MixedTableRange::new(2, 0),
        terminator: MixedTerminator::Return {
            value: MixedValueId::new(4),
        },
    });
    let mut operations = vec![callable_op, argument_op];
    for branch in 0..3_u32 {
        let value = MixedValueId::new(5 + branch);
        let operation_start = operations.len() as u32;
        operations.push(MixedOp::LoadLocal {
            destination: value,
            slot: claimed_result_slot,
        });
        blocks.push(MixedBlock {
            source: apply_source,
            operations: MixedTableRange::new(operation_start, 1),
            terminator: MixedTerminator::Update {
                value,
                result: MixedValueId::new(4),
                next: MixedBlockId::new(2),
            },
        });
    }

    for (target_index, target) in targets.iter().enumerate() {
        validate_block_identity("call target", target.identity, &target.code)?;
        let target_root = target.code.root_pc();
        let direct_return = target
            .code
            .words()
            .get(target_root as usize)
            .copied()
            .filter(|word| word.opcode() == StgOpcode::Local);
        if target.code.words().len() != 1
            || !direct_return.is_some_and(|word| word.operand_a() == 0)
        {
            return Ok(MixedOraclePlanLowerOutcome::Declined(
                MixedOraclePlanDecline::UnsupportedCallTarget {
                    target: target_index,
                },
            ));
        }
        let source = packed_source(&target.code, target.identity.module_digest, target_root)?;
        let function_id = MixedFunctionId::new((target_index + 1) as u32);
        let block_id = MixedBlockId::new((target_index + 6) as u32);
        let parameter = MixedValueId::new((target_index + 8) as u32);
        functions.push(MixedFunction {
            source,
            parameter,
            parameter_type: MixedValueType::Value,
            return_type: MixedValueType::Value,
            entry: block_id,
            blocks: MixedTableRange::new(block_id.as_u32(), 1),
        });
        blocks.push(MixedBlock {
            source,
            operations: MixedTableRange::new(operations.len() as u32, 0),
            terminator: MixedTerminator::Return { value: parameter },
        });
        call_targets.push(MixedCallTarget {
            code: target.identity,
            function: function_id,
            argument_destination: parameter,
        });
    }

    let plan = MixedModulePlan::new(
        key,
        bounds,
        vec![MixedEntry {
            kind: MixedEntryKind::ForceWhnf,
            source: apply_source,
            function: MixedFunctionId::new(0),
            frame: entry.work.frame,
            capture_layout_digest: entry.work.capture_layout_digest,
        }],
        functions,
        blocks,
        operations,
        call_targets,
        vec![
            MixedStatepoint {
                source: apply_source,
                resume: MixedBlockId::new(1),
                live_values: Box::new([MixedValueId::new(1), MixedValueId::new(2)]),
                live_virtuals: Box::new([]),
                result: Some(MixedValueId::new(3)),
                result_type: Some(MixedValueType::Value),
                mode: MixedStatepointMode::Resume,
                reason: MixedStatepointReason::UnknownCall,
            },
            MixedStatepoint {
                source: apply_source,
                resume: MixedBlockId::new(2),
                live_values: Box::new([MixedValueId::new(3)]),
                live_virtuals: Box::new([]),
                result: Some(MixedValueId::new(4)),
                result_type: Some(MixedValueType::Value),
                mode: MixedStatepointMode::Resume,
                reason: MixedStatepointReason::UnsupportedForce,
            },
        ],
    )?;
    Ok(MixedOraclePlanLowerOutcome::Lowered(plan))
}

fn validate_block_identity(
    role: &'static str,
    identity: MixedCodeIdentity,
    code: &StgCodeBlock,
) -> Result<(), MixedOraclePlanLowerError> {
    let key = code.key();
    if identity.body != key.body() || identity.frame != key.frame() {
        return Err(MixedOraclePlanLowerError::IdentityMismatch { role });
    }
    Ok(())
}

fn packed_source(
    code: &StgCodeBlock,
    module_digest: [u8; 32],
    pc: u32,
) -> Result<MixedSource, MixedOraclePlanLowerError> {
    code.source_at(pc)
        .map(|source| MixedSource::new(module_digest, source.ir(), source.span()))
        .ok_or(MixedOraclePlanLowerError::MissingSource { pc })
}

fn lower_argument(
    code: &StgCodeBlock,
    argument: crate::stg::StgOpWord,
    destination: MixedValueId,
) -> Option<MixedOp> {
    match argument.opcode() {
        StgOpcode::LiteralInt => {
            let crate::stg::StgLiteral::Int(value) =
                *code.literals().get(argument.operand_a() as usize)?;
            Some(MixedOp::ConstInt { destination, value })
        }
        StgOpcode::Local => Some(MixedOp::LoadLocal {
            destination,
            slot: argument.operand_a(),
        }),
        StgOpcode::Upval => Some(MixedOp::LoadUpvalue {
            destination,
            depth: argument.operand_a(),
            slot: argument.operand_b(),
        }),
        _ => None,
    }
}

fn lower_lexical(word: crate::stg::StgOpWord, destination: MixedValueId) -> Option<MixedOp> {
    match word.opcode() {
        StgOpcode::Local => Some(MixedOp::LoadLocal {
            destination,
            slot: word.operand_a(),
        }),
        StgOpcode::Upval => Some(MixedOp::LoadUpvalue {
            destination,
            depth: word.operand_a(),
            slot: word.operand_b(),
        }),
        _ => None,
    }
}

/// Lowers one real source-backed Node body into the Node/Apply front-end grammar.
///
/// `module_id` is the evaluator-assigned collision-free identity used by the
/// packed-code cache, while `module_digest` remains the full identity checked
/// by the force guard. `definition` names the thunk-allocation or other stable
/// definition site. `capture_layout_digest` is supplied by the evaluator's
/// versioned capture layout analysis and participates in the pre-claim work
/// identity.
///
/// # Errors
///
/// Returns [`MixedOracleNodeLowerError`] when the immutable IR is malformed.
/// Unsupported but well-formed bodies return
/// [`MixedOracleNodeLowerOutcome::Declined`].
pub fn lower_mixed_oracle_node(
    ir: &Ir,
    module_id: StgModuleId,
    module_digest: [u8; 32],
    definition: IrId,
    body: IrId,
    capture_layout_digest: [u8; 32],
) -> Result<MixedOracleNodeLowerOutcome, MixedOracleNodeLowerError> {
    let frame = match resolve_unique_ir_frame(ir, body)? {
        IrFrameIdentity::Unique(frame) => frame,
        IrFrameIdentity::Ambiguous => {
            return Ok(MixedOracleNodeLowerOutcome::Declined(
                MixedOracleNodeDecline::AmbiguousFrame,
            ));
        }
        IrFrameIdentity::Unreachable => {
            return Ok(MixedOracleNodeLowerOutcome::Declined(
                MixedOracleNodeDecline::UnreachableFrame,
            ));
        }
    };
    let key = StgCodeKey::new(module_id, body, frame);
    let code = match lower_stg_code_block(ir, key)? {
        StgLowerOutcome::Lowered(code) => code,
        StgLowerOutcome::Declined(decline) => {
            return Ok(MixedOracleNodeLowerOutcome::Declined(
                MixedOracleNodeDecline::Stg(decline),
            ));
        }
    };
    let apply_sites = code
        .words()
        .iter()
        .filter(|word| word.opcode() == StgOpcode::Apply1)
        .count() as u32;
    if apply_sites == 0 {
        return Ok(MixedOracleNodeLowerOutcome::Declined(
            MixedOracleNodeDecline::NoApply,
        ));
    }
    Ok(MixedOracleNodeLowerOutcome::Lowered(MixedOracleNodeBlock {
        work: MixedCodeIdentity::new(
            module_digest,
            definition,
            body,
            frame,
            capture_layout_digest,
        ),
        code,
        apply_sites,
    }))
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::super::{
        MixedCallable, MixedExecutablePlan, MixedExecutionOutcome, MixedExecutionRunner,
        MixedForceAction, MixedMachineRuntime,
    };
    use super::*;
    use crate::syntax::parse_str;
    use crate::{IrData, lower, resolve};

    fn lowered(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("IR lowers")
    }

    #[test]
    fn lowers_a_real_frame_specialized_node_apply_body() {
        let ir = lowered("f: f 1");
        let lambda = *ir.arena.node(ir.root).expect("lambda exists");
        let IrData::Lambda { body, frame, .. } = lambda.data else {
            panic!("lambda payload expected");
        };
        let outcome =
            lower_mixed_oracle_node(&ir, StgModuleId::new(7), [7; 32], ir.root, body, [9; 32])
                .expect("lowering succeeds");
        let MixedOracleNodeLowerOutcome::Lowered(block) = outcome else {
            panic!("real unary apply body must lower");
        };
        assert_eq!(block.work().body, body);
        assert_eq!(block.work().frame, frame);
        assert_eq!(block.apply_sites(), 1);
    }

    #[test]
    fn declines_a_real_body_that_cannot_cover_apply_work() {
        let ir = lowered("x: x");
        let lambda = *ir.arena.node(ir.root).expect("lambda exists");
        let IrData::Lambda { body, .. } = lambda.data else {
            panic!("lambda payload expected");
        };
        assert_eq!(
            lower_mixed_oracle_node(&ir, StgModuleId::new(7), [7; 32], ir.root, body, [9; 32],)
                .expect("lowering succeeds"),
            MixedOracleNodeLowerOutcome::Declined(MixedOracleNodeDecline::NoApply)
        );
    }

    #[test]
    fn translates_real_apply_and_target_bodies_with_exact_sources() {
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
            panic!("real application entry must lower");
        };
        let target = direct_target("x: x", StgModuleId::new(8), [8; 32]);
        let force_guards = exact_force_guards();

        let MixedOraclePlanLowerOutcome::Lowered(plan) = lower_mixed_oracle_apply_force_plan(
            MixedModuleKey::new([7; 32], [6; 32], 1),
            MixedPlanBounds::new(16, 2, 2),
            &entry,
            &[target.clone()],
            force_guards,
            0,
        )
        .expect("corridor translation succeeds") else {
            panic!("real corridor must lower");
        };

        assert_eq!(plan.call_targets()[0].code, target.identity());
        assert_eq!(plan.statepoints().len(), 2);
        assert_eq!(
            plan.statepoints()[0].reason,
            MixedStatepointReason::UnknownCall
        );
        assert_eq!(
            plan.statepoints()[1].reason,
            MixedStatepointReason::UnsupportedForce
        );
        let root_source = entry
            .code()
            .source_at(entry.code().root_pc())
            .expect("root source exists");
        assert_eq!(plan.entries()[0].source.ir, root_source.ir());
        assert_eq!(plan.entries()[0].source.span, root_source.span());
        assert_eq!(plan.entries()[0].source.module_digest, [7; 32]);
        assert!(matches!(
            plan.blocks()[0].terminator,
            MixedTerminator::ApplyGuarded { .. }
        ));
        assert!(matches!(
            plan.blocks()[1].terminator,
            MixedTerminator::Force { guards, .. } if guards == force_guards
        ));
        assert!(
            plan.blocks()[3..6]
                .iter()
                .all(|block| matches!(block.terminator, MixedTerminator::Update { .. }))
        );
        assert_eq!(
            plan.operations(),
            &[
                MixedOp::LoadLocal {
                    destination: MixedValueId::new(1),
                    slot: 0,
                },
                MixedOp::ConstInt {
                    destination: MixedValueId::new(2),
                    value: 1,
                },
                MixedOp::LoadLocal {
                    destination: MixedValueId::new(5),
                    slot: 0,
                },
                MixedOp::LoadLocal {
                    destination: MixedValueId::new(6),
                    slot: 0,
                },
                MixedOp::LoadLocal {
                    destination: MixedValueId::new(7),
                    slot: 0,
                },
            ]
        );
        assert!(matches!(
            plan.blocks()[0].terminator,
            MixedTerminator::ApplyGuarded {
                function,
                argument,
                result,
                ..
            } if function == MixedValueId::new(1)
                && argument == MixedValueId::new(2)
                && result == MixedValueId::new(3)
        ));

        let executable = MixedExecutablePlan::new(&plan).expect("translated plan is executable");
        let mut runner = MixedExecutionRunner::<CorridorRuntime>::new(executable, 0, 777, 0, 2)
            .expect("runner allocates");
        let mut runtime = CorridorRuntime {
            target: target.identity(),
            frames: vec![vec![8]],
        };
        assert_eq!(
            runner
                .run(&mut runtime)
                .expect("translated corridor executes"),
            MixedExecutionOutcome::Complete(1)
        );
    }

    #[test]
    fn declines_shared_apply_operands_atomically() {
        let mut ir = lowered("f: f 1");
        let lambda = *ir.arena.node(ir.root).expect("lambda exists");
        let IrData::Lambda { body, .. } = lambda.data else {
            panic!("lambda payload expected");
        };
        let apply = *ir.arena.node(body).expect("application exists");
        let IrData::Pair { first: shared, .. } = apply.data else {
            panic!("application payload expected");
        };
        let mut nodes = ir.arena.nodes().to_vec();
        nodes[body.as_u32() as usize].data = IrData::Pair {
            first: shared,
            second: shared,
        };
        ir.arena = crate::IrArena::from_raw_parts(nodes, ir.arena.child_pool().to_vec());
        let MixedOracleNodeLowerOutcome::Lowered(entry) =
            lower_mixed_oracle_node(&ir, StgModuleId::new(7), [7; 32], ir.root, body, [9; 32])
                .expect("entry lowering succeeds")
        else {
            panic!("real application entry must lower");
        };
        let target = direct_target("x: x", StgModuleId::new(8), [8; 32]);

        assert_eq!(
            lower_mixed_oracle_apply_force_plan(
                MixedModuleKey::new([7; 32], [6; 32], 1),
                MixedPlanBounds::new(16, 2, 2),
                &entry,
                &[target],
                exact_force_guards(),
                0,
            )
            .expect("well-formed shared shape declines"),
            MixedOraclePlanLowerOutcome::Declined(MixedOraclePlanDecline::MultiUseApplyOperand)
        );
    }

    #[test]
    fn rejects_malformed_explicit_target_identity() {
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
            panic!("real application entry must lower");
        };
        let target = direct_target("x: x", StgModuleId::new(8), [8; 32]);
        let malformed = MixedOracleCallTargetBlock::new(
            MixedCodeIdentity::new(
                target.identity().module_digest,
                target.identity().definition,
                IrId::new(target.identity().body.as_u32() + 1),
                target.identity().frame,
                target.identity().capture_layout_digest,
            ),
            target.code().clone(),
        );

        assert_eq!(
            lower_mixed_oracle_apply_force_plan(
                MixedModuleKey::new([7; 32], [6; 32], 1),
                MixedPlanBounds::new(16, 2, 2),
                &entry,
                &[malformed],
                exact_force_guards(),
                0,
            ),
            Err(MixedOraclePlanLowerError::IdentityMismatch {
                role: "call target"
            })
        );
    }

    fn direct_target(
        source: &str,
        module_id: StgModuleId,
        module_digest: [u8; 32],
    ) -> MixedOracleCallTargetBlock {
        let ir = lowered(source);
        let lambda = *ir.arena.node(ir.root).expect("lambda exists");
        let IrData::Lambda { body, frame, .. } = lambda.data else {
            panic!("lambda payload expected");
        };
        let key = StgCodeKey::new(module_id, body, frame);
        let StgLowerOutcome::Lowered(code) =
            lower_stg_code_block(&ir, key).expect("packed target lowering succeeds")
        else {
            panic!("direct target must lower");
        };
        MixedOracleCallTargetBlock::new(
            MixedCodeIdentity::new(module_digest, ir.root, body, frame, [5; 32]),
            code,
        )
    }

    fn exact_force_guards() -> MixedForceGuards {
        MixedForceGuards::new(exact_identity(20), exact_identity(30), exact_identity(40))
    }

    fn exact_identity(seed: u32) -> MixedCodeIdentity {
        MixedCodeIdentity::new(
            [seed as u8; 32],
            IrId::new(seed),
            IrId::new(seed + 1),
            None,
            [seed.wrapping_add(1) as u8; 32],
        )
    }

    struct CorridorRuntime {
        target: MixedCodeIdentity,
        frames: Vec<Vec<u64>>,
    }

    impl MixedMachineRuntime for CorridorRuntime {
        type Value = u64;
        type Frame = usize;
        type ForceTarget = ();
        type UpdateToken = ();
        type Error = Infallible;

        fn integer(&mut self, value: i64) -> Result<Self::Value, Self::Error> {
            Ok(value as u64)
        }

        fn boolean(&mut self, value: bool) -> Self::Value {
            u64::from(value)
        }

        fn null(&mut self) -> Self::Value {
            0
        }

        fn load_local(
            &mut self,
            frame: Self::Frame,
            slot: u32,
        ) -> Result<Self::Value, Self::Error> {
            Ok(self.frames[frame][slot as usize])
        }

        fn load_upvalue(
            &mut self,
            frame: Self::Frame,
            depth: u32,
            slot: u32,
        ) -> Result<Self::Value, Self::Error> {
            Ok(self.frames[frame - depth as usize][slot as usize])
        }

        fn add_integer(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<Self::Value, Self::Error> {
            Ok(left.wrapping_add(right))
        }

        fn integer_less_than(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<Self::Value, Self::Error> {
            Ok(u64::from(left < right))
        }

        fn decode_boolean(&mut self, value: Self::Value) -> Result<bool, Self::Error> {
            Ok(value != 0)
        }

        fn begin_force(
            &mut self,
            subject: Self::Value,
            _guards: MixedForceGuards,
        ) -> Result<
            MixedForceAction<Self::Value, Self::Frame, Self::ForceTarget, Self::UpdateToken>,
            Self::Error,
        > {
            Ok(MixedForceAction::Ready(subject))
        }

        fn inspect_callable(
            &mut self,
            callable: Self::Value,
        ) -> Result<MixedCallable<Self::Frame>, Self::Error> {
            Ok(if callable == 8 {
                MixedCallable::Materialized {
                    code: self.target,
                    frame: 0,
                }
            } else {
                MixedCallable::Declined
            })
        }

        fn publish_update(
            &mut self,
            _target: &Self::ForceTarget,
            _token: &Self::UpdateToken,
            _value: Self::Value,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn abort_update(&mut self, _target: Self::ForceTarget, _token: Self::UpdateToken) {}
    }
}
