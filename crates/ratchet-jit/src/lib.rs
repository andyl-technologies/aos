//! `ratchet-jit` -- the future unsafe execution-tier boundary for RFC-0007.
//!
//! This crate is the landing zone for the Cranelift baseline JIT and later
//! optimized native tiers. It intentionally starts with safe, non-executable
//! scaffolding: [`abi`] mirrors the frozen runtime-call signatures from
//! `ratchet-core`, [`artifact`] records address-free CLIF artifact metadata,
//! [`cranelift`] records the exact Cranelift codegen crate pin for the current
//! CLIF slices, [`lower`] builds verified CLIF bodies for the first literal
//! Core-IR and constant-thunk smoke tests, [`safepoints`] records the
//! compiled-tier stack-map obligation, [`symbols`] mirrors the stable runtime
//! symbol manifest from `ratchet-core`, [`tier`] names the first safe tier-up
//! policy, [`warmup`] keeps the copy-and-patch hedge measurable, and [`safety`]
//! records the unsafe-boundary discipline. Runtime-symbol candidate reports
//! currently remain in `ratchet-oracle`; a later shared metadata layer can move
//! them below both crates without making the JIT crate depend on the safe oracle
//! stack.
//!
//! Actual `unsafe extern "C"` wrappers, raw function-pointer calls, Cranelift
//! module construction, and `JITBuilder::symbol` registration are future work
//! inside this crate. Unsafe blocks are allowed only behind the crate-level
//! `unsafe_op_in_unsafe_fn` discipline and must carry local `// SAFETY:`
//! invariants when those later slices land.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod abi;
pub mod artifact;
pub mod cranelift;
pub mod lower;
pub mod safepoints;
pub mod safety;
pub mod symbols;
pub mod tier;
pub mod warmup;

pub use abi::{
    JitClifSignatureError, JitRuntimeAbiInventory, clif_signature_for_runtime_call,
    jit_runtime_abi_inventory,
};
pub use artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource};
pub use cranelift::{
    ACTIVE_CRANELIFT_CODEGEN_VERSION, JitCraneliftDependencyPin, PINNED_CRANELIFT_CODEGEN_VERSION,
    jit_cranelift_dependency_pin,
};
pub use lower::{
    AOS_IR_ROOT_FUNCTION_NAMESPACE, JitLowerError, clif_name_for_ir_root,
    lower_constant_ir_root_thunk_body, lower_constant_ir_root_thunk_body_artifact,
    lower_constant_ir_thunk_body, lower_constant_ir_thunk_body_artifact, lower_constant_thunk_body,
    lower_constant_thunk_body_artifact,
};
pub use safepoints::{
    JitSafepointPlacement, JitSafepointPolicy, JitSafepointTier, REQUIRED_JIT_SAFEPOINT_PLACEMENTS,
    jit_safepoint_policy,
};
pub use safety::{
    JIT_SAFETY_COMMENT_PREFIX, JIT_UNSAFE_CRATE_LINT, JitInnateUnsafeOperation,
    JitUnsafeDiscipline, jit_unsafe_discipline,
};
pub use symbols::{JitRuntimeSymbolInventory, jit_runtime_symbol_inventory};
pub use tier::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitTier, TierUpCounter, TierUpDecision, TierUpDemandHint,
    TierUpObservation, TierUpPolicy, TierUpReasons,
};
pub use warmup::{
    CopyAndPatchComparison, CopyAndPatchHedgeDecision, CopyAndPatchHedgeGate,
    DEFAULT_COPY_AND_PATCH_COMPILE_SHARE_THRESHOLD_PERCENT,
    DEFAULT_COPY_AND_PATCH_SPEEDUP_THRESHOLD, Tier1WarmupBackend, Tier1WarmupObservation,
};
