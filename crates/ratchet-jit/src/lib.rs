//! `ratchet-jit` -- the future unsafe execution-tier boundary for RFC-0007.
//!
//! This crate is the landing zone for the Cranelift baseline JIT and later
//! optimized native tiers. It intentionally starts with safe, non-callable
//! scaffolding: [`abi`] mirrors the frozen runtime-call signatures from
//! `ratchet-core` and names inert thunk/lambda native-entry aliases,
//! [`artifact`] records address-free CLIF artifact metadata,
//! [`cranelift`] records exact Cranelift crate pins and constructs encapsulated
//! `JITModule` declaration, artifact-definition/finalization,
//! registered-symbol artifact-definition/finalization, unregistered/registered
//! tier-slot, promotion-gated preflights, a bounded native thunk-call path
//! for no-import artifacts, an explicit unsafe registered native-call path
//! for caller-supplied host-ABI-matched runtime candidates, and a
//! promotion-gated registered native-call composition precursor,
//! [`lower`] builds verified CLIF bodies for the first literal Core-IR, local
//! environment-slot, direct local-slot application, static attr selection,
//! constant-thunk smoke tests, bounded shape-directed tier-1 lowerer selectors,
//! and address-free tier-1 fact plans,
//! [`module`] composes artifacts with runtime-symbol declaration
//! readiness, [`safepoints`] records the compiled-tier stack-map obligation,
//! [`symbols`] mirrors the stable runtime symbol manifest from `ratchet-core`
//! and preflights future native-address registration metadata, [`tier`] names
//! the first safe tier-up policy and slot metadata, [`warmup`] keeps the
//! copy-and-patch hedge measurable, and [`safety`] records the unsafe-boundary
//! discipline.
//! Runtime-symbol semantic candidate reports currently remain in
//! `ratchet-oracle`; [`symbols`] owns only JIT-local declaration and opaque
//! native-address registration readiness. A later shared metadata layer can move
//! semantic candidate classification below both crates without making the JIT
//! crate depend on the safe oracle stack.
//!
//! Actual exported `unsafe extern "C"` wrappers, full runtime symbol tables, and
//! evaluator thunk-state dispatch remain future work inside this crate. The
//! current `JITBuilder::symbol` precursor registers only explicit opaque address
//! metadata with an encapsulated builder. Native-call paths keep code-pointer
//! casts/calls behind local `// SAFETY:` invariants, and the registered
//! runtime-importing path is an `unsafe fn` because callers must prove supplied
//! native-address candidates, runtime pointers, valid `Value` tags, and the
//! supported host `Value` calling convention satisfy the frozen ABI.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod abi;
pub mod artifact;
pub mod cranelift;
pub mod lower;
pub mod module;
pub mod safepoints;
pub mod safety;
pub mod symbols;
pub mod tier;
pub mod warmup;

pub use abi::{
    JitClifSignatureError, JitEnvFramePtr, JitLambdaFn, JitRuntimeAbiInventory,
    JitRuntimeContextPtr, JitThunkFn, clif_signature_for_runtime_call, jit_runtime_abi_inventory,
};
pub use artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource};
pub use cranelift::{
    ACTIVE_CRANELIFT_CODEGEN_VERSION, ACTIVE_CRANELIFT_JIT_VERSION,
    ACTIVE_CRANELIFT_MODULE_VERSION, ACTIVE_CRANELIFT_NATIVE_VERSION,
    JitCraneliftArtifactDefinitionPreflight, JitCraneliftArtifactFinalizationPreflight,
    JitCraneliftDefinedFunction, JitCraneliftDependencyPin, JitCraneliftFinalizedFunction,
    JitCraneliftImportedSymbol, JitCraneliftModuleDeclarationPreflight, JitCraneliftModuleSetup,
    JitCraneliftModuleSetupError, JitCraneliftNativeCallError, JitCraneliftNativeThunkInvocation,
    JitCraneliftRegisteredArtifactDefinitionPreflight,
    JitCraneliftRegisteredArtifactFinalizationPreflight,
    JitCraneliftRegisteredNativeThunkInvocation, JitCraneliftRegisteredSymbol,
    JitCraneliftRegisteredTier1NativeCallError, JitCraneliftRegisteredTier1NativeCallPreflight,
    JitCraneliftRegisteredTier1PromotionPreflight, JitCraneliftRegisteredTier1SlotPreflight,
    JitCraneliftSymbolRegistrationPreflight, JitCraneliftTier1PromotionError,
    JitCraneliftTier1PromotionPreflight, JitCraneliftTier1SlotPreflight,
    PINNED_CRANELIFT_CODEGEN_VERSION, PINNED_CRANELIFT_JIT_VERSION,
    PINNED_CRANELIFT_MODULE_VERSION, PINNED_CRANELIFT_NATIVE_VERSION,
    jit_cranelift_artifact_definition_preflight_for_artifact,
    jit_cranelift_artifact_finalization_preflight_for_artifact, jit_cranelift_dependency_pin,
    jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates,
    jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates,
    jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates,
    jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates,
    jit_cranelift_module_declaration_preflight_for_artifact,
    jit_cranelift_module_setup_for_artifact, jit_cranelift_module_setup_for_plan,
    jit_cranelift_native_thunk_call_for_artifact,
    jit_cranelift_registered_artifact_definition_preflight_with_candidates,
    jit_cranelift_registered_artifact_finalization_preflight_with_candidates,
    jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates,
    jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates,
    jit_cranelift_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates,
    jit_cranelift_registered_tier1_slot_preflight_with_candidates,
    jit_cranelift_symbol_registration_preflight_with_candidates,
    jit_cranelift_tier1_promotion_preflight_for_ir_root,
    jit_cranelift_tier1_slot_preflight_for_artifact,
};
pub use lower::{
    AOS_APPLY_FUNCTION_INDEX, AOS_ENV_GET_FUNCTION_INDEX, AOS_FORCE_FUNCTION_INDEX,
    AOS_HAS_ATTR_FUNCTION_INDEX, AOS_IR_ROOT_FUNCTION_NAMESPACE,
    AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_SELECT_IC_FUNCTION_INDEX, JitLowerError,
    JitTier1ThunkFactDecision, JitTier1ThunkFactPlan, clif_external_name_for_aos_apply,
    clif_external_name_for_aos_env_get, clif_external_name_for_aos_force,
    clif_external_name_for_aos_has_attr, clif_external_name_for_aos_select_ic,
    clif_name_for_ir_root, jit_tier1_thunk_fact_decision_for_facts, jit_tier1_thunk_fact_plan,
    lower_apply_local_slots_ir_root_thunk_body,
    lower_apply_local_slots_ir_root_thunk_body_artifact, lower_apply_local_slots_ir_thunk_body,
    lower_apply_local_slots_ir_thunk_body_artifact, lower_constant_ir_root_thunk_body,
    lower_constant_ir_root_thunk_body_artifact, lower_constant_ir_thunk_body,
    lower_constant_ir_thunk_body_artifact, lower_constant_thunk_body,
    lower_constant_thunk_body_artifact, lower_env_get_ir_root_thunk_body,
    lower_env_get_ir_root_thunk_body_artifact, lower_env_get_ir_thunk_body,
    lower_env_get_ir_thunk_body_artifact, lower_force_aware_tier1_ir_thunk_body,
    lower_force_aware_tier1_ir_thunk_body_artifact,
    lower_force_aware_tier1_ir_thunk_body_artifact_for_ir,
    lower_force_aware_tier1_ir_thunk_body_for_ir, lower_forced_env_get_ir_root_thunk_body,
    lower_forced_env_get_ir_root_thunk_body_artifact, lower_forced_env_get_ir_thunk_body,
    lower_forced_env_get_ir_thunk_body_artifact, lower_has_attr_local_slot_ir_root_thunk_body,
    lower_has_attr_local_slot_ir_root_thunk_body_artifact, lower_has_attr_local_slot_ir_thunk_body,
    lower_has_attr_local_slot_ir_thunk_body_artifact, lower_select_local_slot_ir_root_thunk_body,
    lower_select_local_slot_ir_root_thunk_body_artifact, lower_select_local_slot_ir_thunk_body,
    lower_select_local_slot_ir_thunk_body_artifact, lower_tier1_ir_thunk_body,
    lower_tier1_ir_thunk_body_artifact, lower_tier1_ir_thunk_body_artifact_for_ir,
    lower_tier1_ir_thunk_body_for_ir,
};
pub use module::{
    JitModuleArtifactMetadata, JitModuleArtifactRuntimeImport, JitModuleArtifactRuntimeImportGap,
    JitModuleReadinessError, JitModuleReadinessPlan, JitModuleReadinessPreflight,
    jit_module_readiness_plan_for_artifact, jit_module_readiness_preflight_for_artifact,
};
pub use safepoints::{
    JitSafepointPlacement, JitSafepointPolicy, JitSafepointTier, REQUIRED_JIT_SAFEPOINT_PLACEMENTS,
    jit_safepoint_policy,
};
pub use safety::{
    JIT_SAFETY_COMMENT_PREFIX, JIT_UNSAFE_CRATE_LINT, JitInnateUnsafeOperation,
    JitUnsafeDiscipline, jit_unsafe_discipline,
};
pub use symbols::{
    JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate, JitRuntimeSymbolDeclaration,
    JitRuntimeSymbolDeclarationError, JitRuntimeSymbolDeclarationGap,
    JitRuntimeSymbolDeclarationPreflight, JitRuntimeSymbolInventory,
    JitRuntimeSymbolRegistrationBinding, JitRuntimeSymbolRegistrationError,
    JitRuntimeSymbolRegistrationGap, JitRuntimeSymbolRegistrationPlan,
    JitRuntimeSymbolRegistrationPlanError, JitRuntimeSymbolRegistrationPreflight,
    jit_runtime_symbol_declaration_preflight, jit_runtime_symbol_inventory,
    jit_runtime_symbol_registration_plan, jit_runtime_symbol_registration_plan_with_candidates,
    jit_runtime_symbol_registration_preflight,
    jit_runtime_symbol_registration_preflight_with_candidates,
};
pub use tier::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitCompiledCodePointer, JitTier, JitTieredCodeSlot,
    JitTieredCodeSlotError, TierUpCounter, TierUpDecision, TierUpDemandHint, TierUpObservation,
    TierUpPolicy, TierUpReasons,
};
pub use warmup::{
    CopyAndPatchComparison, CopyAndPatchHedgeDecision, CopyAndPatchHedgeGate,
    DEFAULT_COPY_AND_PATCH_COMPILE_SHARE_THRESHOLD_PERCENT,
    DEFAULT_COPY_AND_PATCH_SPEEDUP_THRESHOLD, Tier1WarmupBackend, Tier1WarmupObservation,
};
