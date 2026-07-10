//! `ratchet-core` — the core IR, scope resolver, and builtin metadata for the
//! AOS Nix evaluator (RFC-0007 §1.1 Phase 1b).
//!
//! Compilation passes from parsed AST to evaluator IR.
//!
//! The compile layer starts with scope resolution: it rewrites expression
//! identifiers into de Bruijn-style variable accesses and records the frame side
//! tables that later lowering, interpretation, and serialization consume.
//!
//! The `builtins` submodule owns the builtin *metadata* layer — the declaration
//! inventory, name lookup, direct-lowering classification, and the abstract
//! [`builtins::BuiltinExecutor`] adapter trait. Lowering and scope resolution
//! consume this metadata without depending on any concrete evaluator. Runtime
//! tiers (the tree-walk oracle) implement the executor trait and supply the
//! builtin *execution* behavior, so the dependency runs runtime -> compile.

#![forbid(unsafe_code)]

/// Re-export of the parser/AST crate so the moved compile sources can keep
/// resolving their `crate::syntax::…` paths after the crate split.
pub use aos_nix_syntax as syntax;

pub mod analysis;
pub mod builtins;
pub mod ir;
pub mod runtime_abi;
pub mod scope;

#[cfg(test)]
mod workspace_safety;

pub use analysis::{
    CaptureAnalysisError, CaptureAnalysisReport, CardinalityAnalysisError,
    CardinalityAnalysisReport, DeadBindingElimination,
    DeadBindingEliminationError, DeadBindingEliminationPlan, DeadBindingReplacement,
    DeadBindingRetention, DeadBindingRetentionReason, EscapeAnalysisError, EscapeAnalysisReport,
    FLAT_CAPTURE_MAX_SLOTS, FrameLocalSingleEntryThunk, FrameLocalThunkDowngrade,
    FrameLocalThunkDowngradeError,
    FrameLocalThunkUpdateReason, FullLazinessAnalysisError, FullLazinessAnalysisReport,
    FullLazinessCandidate, PrimOpArgumentEscape, PrimOpEscapeSignature, ScalarReplacement,
    ScalarReplacementError,
    ScalarReplacementKind, ScalarReplacementPlan, ScalarReplacementRetention,
    ScalarReplacementRetentionReason, StrictnessAnalysisError, StrictnessAnalysisReport,
    WorkerWrapperArgumentMode, WorkerWrapperPlan, WorkerWrapperPlanError, WorkerWrapperRetention,
    WorkerWrapperRetentionReason, WorkerWrapperSplit, analyze_full_laziness,
    annotate_capture_plans, annotate_cardinality,
    annotate_escape, annotate_strictness, dead_binding_elimination_plan,
    frame_local_single_entry_thunk_downgrade, primop_argument_escape_signature,
    primop_escape_signature, scalar_replacement_plan,
    worker_wrapper_plan,
};
pub use ir::{
    BindingLowering, CapturePlan, Cardinality, Effect, EffectClass, Escape, ExprFacts,
    FlatCaptureAccess, IR_ANALYSIS_VERSION, Ir,
    IrAnalysisError, SharedChainReason,
    IrAnalysisReport, IrArena, IrAttrPathId, IrAttrPathSegment, IrBinding, IrBindingSlice,
    IrChildSlice, IrData, IrDependencyFootprint, IrDialectOp, IrError, IrErrorKind, IrFacts,
    IrFrameCaptureFootprint, IrId, IrInlineCacheSiteId, IrKind, IrLowerOptions, IrNode, IrShape,
    IrShapeId, IrWithChain, LambdaAttrKeys, LambdaAttrValueSummary, LambdaCallSummary, LambdaDemand,
    LambdaFormalSummary, Strictness, ThunkSharing, all_pure, all_pure_builtin, annotate_import_ir,
    annotate_ir, lower, lower_with_options,
};
pub use runtime_abi::{
    BUILTIN_SYMBOL_PREFIX, BuiltinRuntimeSymbol, MAX_RUNTIME_PRIMOP_ABI_ARITY,
    RUNTIME_HELPER_CALL_SIGNATURES, RUNTIME_HELPER_SYMBOL_PREFIX, RUNTIME_HELPER_SYMBOLS,
    RUNTIME_LAMBDA_ARGV_CALL_SIGNATURE, RUNTIME_LAMBDA_CALL_SIGNATURE,
    RUNTIME_PRIMOP_CALL_SIGNATURES, RUNTIME_THUNK_CALL_SIGNATURE,
    RuntimeAbiCallingConvention, RuntimeAbiParameter, RuntimeAbiParameterKind,
    RuntimeAbiReturnKind, RuntimeAbiValueLayout, RuntimeBuiltinCallBinding,
    RuntimeBuiltinCallManifestEntry, RuntimeBuiltinCallManifestResult,
    RuntimeBuiltinCallMissingBinding, RuntimeBuiltinCallPreflight,
    RuntimeBuiltinCallPreflightResult, RuntimeBuiltinCallStatus, RuntimeCallAbiError,
    RuntimeCallSignature, RuntimeCallableKind, RuntimeHelperRole, RuntimeHelperSymbol,
    RuntimeSymbolKind, RuntimeSymbolManifestEntry, RuntimeSymbolNameError,
    runtime_abi_value_layout, runtime_builtin_call_manifest, runtime_builtin_call_preflight,
    runtime_helper_call_signature, runtime_helper_call_signatures, runtime_helper_symbols,
    runtime_lambda_argv_call_signature, runtime_lambda_call_signature,
    runtime_primop_call_signature, runtime_primop_call_signatures, runtime_symbol_manifest,
    runtime_thunk_call_signature,
};
pub use scope::{
    FrameId, FrameInfo, InheritGroupId, InheritResolution, InheritSource, ResolvedAst,
    ResolverOptions, ScopeError, ScopeErrorKind, ScopeResolver, ScopeTables, Upvalue, WithChain,
    WithChainId, resolve,
};
