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
pub mod grin_region;
pub mod ir;
pub mod mixed_machine;
pub mod runtime_abi;
pub mod scope;
pub mod stg;

#[cfg(test)]
mod workspace_safety;

pub use analysis::{
    CallTargetCandidates, CaptureAnalysisError, CaptureAnalysisReport, CardinalityAnalysisError,
    CardinalityAnalysisReport, ClosureFlowReport, DEFAULT_PROMISE_REGION_SPECIALIZATION_CAP,
    DeadBindingElimination, DeadBindingEliminationError, DeadBindingEliminationPlan,
    DeadBindingReplacement, DeadBindingRetention, DeadBindingRetentionReason, EscapeAnalysisError,
    EscapeAnalysisReport, FLAT_CAPTURE_MAX_SLOTS, FrameLocalSingleEntryThunk,
    FrameLocalThunkDowngrade, FrameLocalThunkDowngradeError, FrameLocalThunkUpdateReason,
    FullLazinessAnalysisError, FullLazinessAnalysisReport, FullLazinessCandidate, IrFrameIdentity,
    IrFrameIdentityError, KnownCallTarget, PrimOpArgumentEscape, PrimOpEscapeSignature,
    PromiseNodeSpecializationCount, PromiseRegionDisposition, PromiseRegionError, PromiseRegionKey,
    PromiseRegionNode, PromiseRegionOptions, PromiseRegionPlan, PromiseRegionSymbolValidation,
    PromiseStatepoint, PromiseStatepointKind, PromiseVirtualAllocationSite, ScalarReplacement,
    ScalarReplacementError, ScalarReplacementKind, ScalarReplacementPlan,
    ScalarReplacementRetention, ScalarReplacementRetentionReason, SemanticBinderId,
    SemanticBindingComponent, SemanticSlice, SemanticSliceError, StrictnessAnalysisError,
    StrictnessAnalysisReport, VirtualAllocationCounts, VirtualAllocationKind,
    WorkerWrapperArgumentMode, WorkerWrapperPlan, WorkerWrapperPlanError, WorkerWrapperRetention,
    WorkerWrapperRetentionReason, WorkerWrapperSplit, analyze_call_target_candidates,
    analyze_full_laziness, analyze_known_call_targets, analyze_semantic_slice,
    analyze_semantic_subslice, analyze_semantic_subslice_with_symbols, annotate_capture_plans,
    annotate_cardinality, annotate_escape, annotate_strictness, dead_binding_elimination_plan,
    frame_local_single_entry_thunk_downgrade, plan_promise_region,
    primop_argument_escape_signature, primop_escape_signature, resolve_unique_ir_frame,
    scalar_replacement_plan, semantic_subslice_retains_all,
    semantic_subslice_retains_all_with_symbols, worker_wrapper_plan,
};
pub use ir::{
    BindingLowering, CapturePlan, Cardinality, Effect, EffectClass, Escape, ExprFacts,
    FlatCaptureAccess, IR_ANALYSIS_VERSION, Ir, IrAnalysisError, IrAnalysisReport, IrArena,
    IrAttrPathId, IrAttrPathSegment, IrBinding, IrBindingSlice, IrChildSlice, IrData,
    IrDependencyFootprint, IrDialectOp, IrError, IrErrorKind, IrFacts, IrFactsStorage,
    IrFrameCaptureFootprint, IrId, IrInlineCacheSiteId, IrKind, IrLowerOptions, IrNode, IrShape,
    IrShapeId, IrWithChain, LambdaAttrKeys, LambdaAttrValueSummary, LambdaCallSummary,
    LambdaDemand, LambdaFormalSummary, PASS_SET_VERSION, PassOutcome, SIMPLIFY_MAX_ITERS,
    SharedChainReason, SimplifyError, SimplifyPass, SimplifyPhase, Strictness, ThunkSharing,
    all_pure, all_pure_builtin, annotate_import_ir, annotate_ir, lower, lower_with_options,
    render_ir, simplify_ir, simplify_with_passes,
};
pub use runtime_abi::{
    BUILTIN_SYMBOL_PREFIX, BuiltinRuntimeSymbol, MAX_RUNTIME_PRIMOP_ABI_ARITY,
    RUNTIME_FOLD_STEP_I64ACC_CALL_SIGNATURE, RUNTIME_HELPER_CALL_SIGNATURES,
    RUNTIME_HELPER_SYMBOL_PREFIX, RUNTIME_HELPER_SYMBOLS, RUNTIME_LAMBDA_ARGV_CALL_SIGNATURE,
    RUNTIME_LAMBDA_CALL_SIGNATURE, RUNTIME_PRIMOP_CALL_SIGNATURES, RUNTIME_THUNK_CALL_SIGNATURE,
    RuntimeAbiCallingConvention, RuntimeAbiParameter, RuntimeAbiParameterKind,
    RuntimeAbiReturnKind, RuntimeAbiValueLayout, RuntimeBuiltinCallBinding,
    RuntimeBuiltinCallManifestEntry, RuntimeBuiltinCallManifestResult,
    RuntimeBuiltinCallMissingBinding, RuntimeBuiltinCallPreflight,
    RuntimeBuiltinCallPreflightResult, RuntimeBuiltinCallStatus, RuntimeCallAbiError,
    RuntimeCallSignature, RuntimeCallableKind, RuntimeHelperRole, RuntimeHelperSymbol,
    RuntimeSymbolKind, RuntimeSymbolManifestEntry, RuntimeSymbolNameError,
    candidate_b_runtime_abi_value_layout, candidate_c_runtime_abi_value_layout,
    runtime_abi_value_layout, runtime_builtin_call_manifest, runtime_builtin_call_preflight,
    runtime_fold_step_i64acc_call_signature, runtime_helper_call_signature,
    runtime_helper_call_signatures, runtime_helper_symbols, runtime_lambda_argv_call_signature,
    runtime_lambda_call_signature, runtime_primop_call_signature, runtime_primop_call_signatures,
    runtime_symbol_manifest, runtime_thunk_call_signature,
};
pub use scope::{
    FrameId, FrameInfo, InheritGroupId, InheritResolution, InheritSource, ResolvedAst,
    ResolverOptions, ScopeError, ScopeErrorKind, ScopeResolver, ScopeTables, Upvalue, WithChain,
    WithChainId, resolve,
};
