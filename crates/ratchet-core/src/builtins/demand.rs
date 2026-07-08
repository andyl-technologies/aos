//! Declarative per-builtin argument demand signatures.
//!
//! [`demand_signature`] is the single source of truth for how a direct
//! builtin call site treats each argument position. It is derived from
//! [`BuiltinExecution`] — the same record that drives evaluator dispatch — so
//! the demand analysis and the tree-walk evaluator cannot drift apart: any
//! builtin whose runtime forcing behavior changes must change its execution
//! strategy, and the signature (plus the validation tests in this module)
//! changes with it.
//!
//! A signature classifies each argument of the *direct-lowered* call shape:
//!
//! - [`ArgDemand::Lazy`] — the builtin does not (provably) force the argument
//!   on every call: higher-order callbacks skipped by empty inputs, verbose
//!   trace messages, `or`-style conditional operands.
//! - [`ArgDemand::Forced`] — the builtin forces the argument to WHNF the
//!   moment it evaluates that position, on every call.
//! - [`ArgDemand::ForcedUnderCatch`] — the builtin forces the argument inside
//!   an error-catching scope (`tryEval`). The direct call site still forces
//!   immediately, but demand must never be propagated *through* the builtin
//!   into an enclosing lambda's parameter summary (soundness rule S4): a
//!   hoisted force would escape the catch.
//! - [`ArgDemand::Result`] — the builtin returns the argument's value as its
//!   own result without forcing it (`seq e1 e2` returns `e2` lazily). The
//!   argument node is evaluated, so analysis may descend into it, but no
//!   forcing claim exists at this position. `after_effect` records that the
//!   builtin performs an observable effect (trace/warn output, a deep force)
//!   before evaluating the position, capping any demand propagated through
//!   it to [`crate::ir::Strictness::Demanded`].
//! - [`ArgDemand::Barred`] — the argument is evaluated by the builtin, but
//!   demand propagation through the position is barred entirely because
//!   forcing it earlier would change observable error attribution
//!   (`addErrorContext`).

use super::types::{
    BuiltinExecution, DirectBinaryPrimOp, StrictBinaryPrimOp, StrictTernaryPrimOp, TraceMode,
};

/// How a direct builtin call site treats one argument position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgDemand {
    /// The argument is not proven to be forced on every call.
    Lazy,
    /// The argument is forced to WHNF when the builtin evaluates the position.
    Forced,
    /// The argument is forced inside an error-catching scope (`tryEval`).
    ///
    /// Demand must not propagate through this position into enclosing lambda
    /// parameter summaries (S4).
    ForcedUnderCatch,
    /// The argument's value is returned as the builtin's own result without
    /// being forced by the builtin.
    Result {
        /// Whether an observable builtin effect precedes this position.
        after_effect: bool,
    },
    /// The argument is evaluated but demand propagation through the position
    /// is barred (error-attribution boundaries such as `addErrorContext`).
    Barred,
}

impl ArgDemand {
    /// Returns whether the builtin forces this position on every call.
    pub const fn is_forced(self) -> bool {
        matches!(self, Self::Forced | Self::ForcedUnderCatch)
    }

    /// Returns whether demand may propagate through this position into an
    /// enclosing lambda's parameter summary (S4 and error-attribution bars).
    pub const fn propagates_summary_demand(self) -> bool {
        matches!(self, Self::Forced | Self::Result { .. })
    }
}

/// The per-argument demand signature for one builtin's direct call shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DemandSignature {
    args: &'static [ArgDemand],
}

impl DemandSignature {
    const fn new(args: &'static [ArgDemand]) -> Self {
        Self { args }
    }

    /// Returns the demand classes in argument-position order.
    pub const fn args(&self) -> &'static [ArgDemand] {
        self.args
    }

    /// Returns the demand class for one argument position.
    ///
    /// Positions beyond the signature fall back to [`ArgDemand::Lazy`], so a
    /// malformed call site can never claim more demand than the declaration.
    pub fn arg(&self, index: usize) -> ArgDemand {
        self.args.get(index).copied().unwrap_or(ArgDemand::Lazy)
    }
}

const NO_ARGS: DemandSignature = DemandSignature::new(&[]);
const FORCED_1: DemandSignature = DemandSignature::new(&[ArgDemand::Forced]);
const FORCED_2: DemandSignature = DemandSignature::new(&[ArgDemand::Forced, ArgDemand::Forced]);
const FORCED_3: DemandSignature = DemandSignature::new(&[
    ArgDemand::Forced,
    ArgDemand::Forced,
    ArgDemand::Forced,
]);
const CALLBACK_THEN_FORCED: DemandSignature =
    DemandSignature::new(&[ArgDemand::Lazy, ArgDemand::Forced]);
const FOLDL_STRICT: DemandSignature = DemandSignature::new(&[
    ArgDemand::Forced,
    ArgDemand::Lazy,
    ArgDemand::Forced,
]);
const TRY_EVAL: DemandSignature = DemandSignature::new(&[ArgDemand::ForcedUnderCatch]);
const SEQ: DemandSignature = DemandSignature::new(&[
    ArgDemand::Forced,
    ArgDemand::Result {
        after_effect: false,
    },
]);
const DEEP_SEQ: DemandSignature = DemandSignature::new(&[
    ArgDemand::Forced,
    ArgDemand::Result { after_effect: true },
]);
const TRACE_ALWAYS: DemandSignature = DemandSignature::new(&[
    ArgDemand::Forced,
    ArgDemand::Result { after_effect: true },
]);
const TRACE_VERBOSE: DemandSignature = DemandSignature::new(&[
    ArgDemand::Lazy,
    ArgDemand::Result { after_effect: true },
]);
const ADD_ERROR_CONTEXT: DemandSignature =
    DemandSignature::new(&[ArgDemand::Lazy, ArgDemand::Barred]);
const LAZY_RESULT: DemandSignature = DemandSignature::new(&[ArgDemand::Result {
    after_effect: false,
}]);

/// Returns the argument demand signature for one builtin execution strategy.
///
/// The classification mirrors the tree-walk evaluator's forcing behavior for
/// each strategy. In particular, higher-order callback arguments that an empty
/// input can skip stay [`ArgDemand::Lazy`], `tryEval` is
/// [`ArgDemand::ForcedUnderCatch`], and trace-like builtins mark their value
/// position as a post-effect result so demand propagated through it can never
/// reach [`crate::ir::Strictness::DemandedBeforeEffect`].
pub const fn demand_signature(execution: BuiltinExecution) -> DemandSignature {
    match execution {
        BuiltinExecution::Import
        | BuiltinExecution::Derivation
        | BuiltinExecution::GenericClosure
        | BuiltinExecution::Path
        | BuiltinExecution::PathExists
        | BuiltinExecution::ReadDir
        | BuiltinExecution::ReadFile
        | BuiltinExecution::ReadFileType
        | BuiltinExecution::FetchGit
        | BuiltinExecution::FetchMercurial
        | BuiltinExecution::FetchTarball
        | BuiltinExecution::FetchTree
        | BuiltinExecution::GetFlake
        | BuiltinExecution::Fetchurl
        | BuiltinExecution::FlakeRefToString
        | BuiltinExecution::ParseFlakeRef
        | BuiltinExecution::StrictUnary { .. } => FORCED_1,
        BuiltinExecution::TryEval => TRY_EVAL,
        BuiltinExecution::ScopedImport
        | BuiltinExecution::FindFile
        | BuiltinExecution::FilterSource
        | BuiltinExecution::ToFile => FORCED_2,
        BuiltinExecution::StrictBinary { primop, .. } => match primop {
            StrictBinaryPrimOp::All
            | StrictBinaryPrimOp::Any
            | StrictBinaryPrimOp::ConcatMap
            | StrictBinaryPrimOp::Filter
            | StrictBinaryPrimOp::GenList
            | StrictBinaryPrimOp::GroupBy
            | StrictBinaryPrimOp::Map
            | StrictBinaryPrimOp::Partition => CALLBACK_THEN_FORCED,
            StrictBinaryPrimOp::AppendContext
            | StrictBinaryPrimOp::Add
            | StrictBinaryPrimOp::Sub
            | StrictBinaryPrimOp::Mul
            | StrictBinaryPrimOp::Div
            | StrictBinaryPrimOp::BitAnd
            | StrictBinaryPrimOp::BitOr
            | StrictBinaryPrimOp::BitXor
            | StrictBinaryPrimOp::CompareVersions
            | StrictBinaryPrimOp::ElemAt
            | StrictBinaryPrimOp::LessThan
            | StrictBinaryPrimOp::HashString
            | StrictBinaryPrimOp::HashFile
            | StrictBinaryPrimOp::Match
            | StrictBinaryPrimOp::Split => FORCED_2,
        },
        BuiltinExecution::DirectBinary(primop) => match primop {
            DirectBinaryPrimOp::Elem
            | DirectBinaryPrimOp::MapAttrs
            | DirectBinaryPrimOp::ZipAttrsWith => CALLBACK_THEN_FORCED,
            DirectBinaryPrimOp::GetAttr
            | DirectBinaryPrimOp::HasAttr
            | DirectBinaryPrimOp::UnsafeGetAttrPos
            | DirectBinaryPrimOp::RemoveAttrs
            | DirectBinaryPrimOp::IntersectAttrs
            | DirectBinaryPrimOp::CatAttrs
            | DirectBinaryPrimOp::ConcatStringsSep => FORCED_2,
        },
        BuiltinExecution::DirectTernary(primop) => match primop {
            StrictTernaryPrimOp::FoldlStrict => FOLDL_STRICT,
            StrictTernaryPrimOp::ReplaceStrings | StrictTernaryPrimOp::Substring => FORCED_3,
        },
        BuiltinExecution::Sort => CALLBACK_THEN_FORCED,
        BuiltinExecution::Seq => SEQ,
        BuiltinExecution::DeepSeq => DEEP_SEQ,
        BuiltinExecution::AddErrorContext => ADD_ERROR_CONTEXT,
        BuiltinExecution::Trace {
            mode: TraceMode::Always,
        } => TRACE_ALWAYS,
        BuiltinExecution::Trace {
            mode: TraceMode::Verbose,
        } => TRACE_VERBOSE,
        BuiltinExecution::Warn => TRACE_ALWAYS,
        BuiltinExecution::DerivationStrict => FORCED_1,
        BuiltinExecution::LazyUnary => LAZY_RESULT,
        BuiltinExecution::BuiltinsValue
        | BuiltinExecution::TrueValue
        | BuiltinExecution::FalseValue
        | BuiltinExecution::NullValue
        | BuiltinExecution::CurrentSystemValue
        | BuiltinExecution::CurrentTimeValue
        | BuiltinExecution::StoreDirValue
        | BuiltinExecution::NixVersionValue
        | BuiltinExecution::LangVersionValue
        | BuiltinExecution::NixPathValue => NO_ARGS,
    }
}

#[cfg(test)]
mod tests {
    use super::super::BUILTINS;
    use super::*;

    /// Every builtin's demand signature covers exactly its direct arity, so a
    /// signature can never claim demand for an argument the evaluator does not
    /// receive at a direct call site.
    #[test]
    fn demand_signature_arity_matches_direct_lowering() {
        for builtin in BUILTINS.iter() {
            let signature = demand_signature(builtin.execution());
            if let Some(direct) = builtin.direct() {
                assert_eq!(
                    signature.args().len(),
                    direct.arity(),
                    "signature arity mismatch for {:?}",
                    String::from_utf8_lossy(builtin.name()),
                );
            } else {
                assert!(
                    signature.args().is_empty(),
                    "value builtin {:?} must not declare argument demand",
                    String::from_utf8_lossy(builtin.name()),
                );
            }
        }
    }

    /// The forced-argument sets agree with the evaluator's execution
    /// strategies: no lazily-dispatched position is declared forced.
    #[test]
    fn demand_signature_agrees_with_execution_strategy() {
        for builtin in BUILTINS.iter() {
            let execution = builtin.execution();
            let signature = demand_signature(execution);
            match execution {
                BuiltinExecution::TryEval => {
                    assert_eq!(signature.arg(0), ArgDemand::ForcedUnderCatch);
                }
                BuiltinExecution::AddErrorContext => {
                    assert_eq!(signature.arg(0), ArgDemand::Lazy);
                    assert_eq!(signature.arg(1), ArgDemand::Barred);
                }
                BuiltinExecution::Seq | BuiltinExecution::DeepSeq => {
                    assert_eq!(signature.arg(0), ArgDemand::Forced);
                    assert!(matches!(signature.arg(1), ArgDemand::Result { .. }));
                }
                BuiltinExecution::Trace {
                    mode: TraceMode::Verbose,
                } => {
                    // The message is only forced when verbose tracing is on.
                    assert_eq!(signature.arg(0), ArgDemand::Lazy);
                    assert_eq!(
                        signature.arg(1),
                        ArgDemand::Result { after_effect: true }
                    );
                }
                BuiltinExecution::Trace { .. } | BuiltinExecution::Warn => {
                    assert_eq!(signature.arg(0), ArgDemand::Forced);
                    assert_eq!(
                        signature.arg(1),
                        ArgDemand::Result { after_effect: true }
                    );
                }
                BuiltinExecution::Sort => {
                    // The comparator can be skipped by empty inputs.
                    assert_eq!(signature.arg(0), ArgDemand::Lazy);
                    assert_eq!(signature.arg(1), ArgDemand::Forced);
                }
                BuiltinExecution::DerivationStrict => {
                    // The serializer forces the argument attrset to WHNF
                    // before any other work; the per-attribute S3 seeding
                    // lives in the strictness analysis, not this table.
                    assert_eq!(signature.arg(0), ArgDemand::Forced);
                }
                _ => {}
            }
        }
    }

    /// Higher-order callback arguments that empty inputs can skip stay lazy.
    #[test]
    fn demand_signature_keeps_skippable_callbacks_lazy() {
        for name in [
            "map", "filter", "all", "any", "concatMap", "genList", "groupBy", "partition",
            "mapAttrs", "zipAttrsWith", "elem", "sort",
        ] {
            let builtin = BUILTINS
                .lookup(name.as_bytes())
                .unwrap_or_else(|| panic!("builtin {name} exists"));
            let signature = demand_signature(builtin.execution());
            assert_eq!(signature.arg(0), ArgDemand::Lazy, "{name} callback");
            assert_eq!(signature.arg(1), ArgDemand::Forced, "{name} input");
        }
        let foldl = BUILTINS.lookup(b"foldl'").expect("foldl' exists");
        let signature = demand_signature(foldl.execution());
        assert_eq!(signature.arg(0), ArgDemand::Forced);
        assert_eq!(signature.arg(1), ArgDemand::Lazy, "foldl' initial value");
        assert_eq!(signature.arg(2), ArgDemand::Forced);
    }

    /// Out-of-range positions fail closed to lazy.
    #[test]
    fn demand_signature_out_of_range_positions_are_lazy() {
        let length = BUILTINS.lookup(b"length").expect("length exists");
        let signature = demand_signature(length.execution());
        assert_eq!(signature.arg(7), ArgDemand::Lazy);
    }
}
