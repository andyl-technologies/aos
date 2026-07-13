//! Cranelift dependency pin and safe JIT-module setup.
//!
//! This module records the Cranelift crate versions that the current CLIF
//! slices are validated against and constructs the first real `JITModule`
//! scaffolds. The symbol-registration scaffold installs explicitly supplied
//! native-address candidates into a `JITBuilder` symbol table. The declaration
//! scaffold declares shape-known runtime symbols as imported functions. The
//! artifact-definition scaffold additionally compiles one verified CLIF artifact
//! into an encapsulated module. The artifact-finalization scaffold finalizes one
//! defined artifact and returns opaque code-pointer metadata. The promotion
//! scaffold records safe slot hotness and compiles currently-supported literal
//! and registered env-slot roots when policy requests tier 1. The native
//! thunk-call scaffold casts and calls finalized no-import thunk artifacts, and
//! can also call registered runtime-importing artifacts behind an explicit
//! unsafe boundary when the caller supplies host-ABI-matched native candidates.
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, mem,
    ptr::{self, NonNull},
    rc::Rc,
};
use cranelift_codegen::{
    CodegenError, Context,
    ir::{ExternalName, Function, UserExternalName},
    isa::OwnedTargetIsa,
    settings::{self, Configurable, SetError},
};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, ModuleError};
use ratchet_core::{Ir, IrArena, IrId};
use ratchet_value::value::Value;
use crate::{
    abi::{JitEnvFramePtr, JitRuntimeContextPtr, JitThunkFn},
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource, JitValueAbi},
    lower::{
        JitLowerError, lower_constant_ir_thunk_body_artifact,
        lower_force_aware_tier1_ir_thunk_body_artifact,
        lower_force_aware_tier1_ir_thunk_body_artifact_for_ir, lower_tier1_ir_thunk_body_artifact,
        lower_tier1_ir_thunk_body_artifact_for_ir,
    },
    module::{
        JitModuleArtifactMetadata, JitModuleArtifactRuntimeImport, JitModuleReadinessError,
        JitModuleReadinessPlan, JitModuleReadinessPreflight,
        jit_module_readiness_preflight_for_artifact,
    },
    symbols::{
        JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate, JitRuntimeSymbolDeclaration,
        JitRuntimeSymbolDeclarationGap, JitRuntimeSymbolRegistrationBinding,
        JitRuntimeSymbolRegistrationError, JitRuntimeSymbolRegistrationGap,
        jit_runtime_symbol_registration_preflight_with_candidates,
    },
    tier::{
        JitTieredCodeSlot, JitTieredCodeSlotError, TierUpDecision, TierUpDemandHint, TierUpPolicy,
    },
};
mod candidate_b;
mod candidate_c;
mod finalized;
mod native_error;
mod tier2;
pub use candidate_b::jit_cranelift_call_context_finalized_candidate_b_thunk_entry;
pub use candidate_c::jit_cranelift_call_context_finalized_candidate_c_thunk_entry;
pub use finalized::JitCraneliftFinalizedFunction;
pub use native_error::JitCraneliftNativeCallError;
use native_error::require_artifact_value_abi;
pub use tier2::jit_cranelift_call_context_finalized_fold_step_i64acc_entry;
pub use tier2::jit_cranelift_call_context_finalized_lambda_argv_entry;
pub use tier2::jit_cranelift_call_context_finalized_lambda_entry;
/// The exact `cranelift-codegen` crate version required by this JIT slice.
pub const PINNED_CRANELIFT_CODEGEN_VERSION: &str = "0.127.4";

/// The exact `cranelift-jit` crate version required by this JIT slice.
pub const PINNED_CRANELIFT_JIT_VERSION: &str = "0.127.4";

/// The exact `cranelift-module` crate version required by this JIT slice.
pub const PINNED_CRANELIFT_MODULE_VERSION: &str = "0.127.4";

/// The exact `cranelift-native` crate version required by this JIT slice.
pub const PINNED_CRANELIFT_NATIVE_VERSION: &str = "0.127.4";
/// The `cranelift-codegen` crate version linked into this build.
pub const ACTIVE_CRANELIFT_CODEGEN_VERSION: &str = cranelift_codegen::VERSION;

/// The `cranelift-jit` crate version linked into this build.
pub const ACTIVE_CRANELIFT_JIT_VERSION: &str = cranelift_jit::VERSION;

/// The `cranelift-module` crate version linked into this build.
pub const ACTIVE_CRANELIFT_MODULE_VERSION: &str = cranelift_module::VERSION;

/// The `cranelift-native` crate version linked into this build.
pub const ACTIVE_CRANELIFT_NATIVE_VERSION: &str = cranelift_native::VERSION;

/// The Cranelift dependency pin visible to JIT setup code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitCraneliftDependencyPin {
    codegen_version: &'static str,
    jit_version: &'static str,
    module_version: &'static str,
    native_version: &'static str,
}

impl JitCraneliftDependencyPin {
    /// Creates dependency-pin metadata from an exact Cranelift codegen version.
    pub const fn new(codegen_version: &'static str) -> Self {
        Self::with_versions(
            codegen_version,
            PINNED_CRANELIFT_JIT_VERSION,
            PINNED_CRANELIFT_MODULE_VERSION,
            PINNED_CRANELIFT_NATIVE_VERSION,
        )
    }

    /// Creates dependency-pin metadata from exact Cranelift crate versions.
    pub const fn with_versions(
        codegen_version: &'static str,
        jit_version: &'static str,
        module_version: &'static str,
        native_version: &'static str,
    ) -> Self {
        Self {
            codegen_version,
            jit_version,
            module_version,
            native_version,
        }
    }

    /// Returns the pinned `cranelift-codegen` crate version.
    pub const fn codegen_version(self) -> &'static str {
        self.codegen_version
    }

    /// Returns the pinned `cranelift-jit` crate version.
    pub const fn jit_version(self) -> &'static str {
        self.jit_version
    }

    /// Returns the pinned `cranelift-module` crate version.
    pub const fn module_version(self) -> &'static str {
        self.module_version
    }

    /// Returns the pinned `cranelift-native` crate version.
    pub const fn native_version(self) -> &'static str {
        self.native_version
    }
}

/// Returns the Cranelift dependency pin for this build.
pub const fn jit_cranelift_dependency_pin() -> JitCraneliftDependencyPin {
    JitCraneliftDependencyPin::with_versions(
        PINNED_CRANELIFT_CODEGEN_VERSION,
        PINNED_CRANELIFT_JIT_VERSION,
        PINNED_CRANELIFT_MODULE_VERSION,
        PINNED_CRANELIFT_NATIVE_VERSION,
    )
}


mod preflight_a;
mod preflight_b;
mod preflight_fns;
mod context;
mod tier1;
mod module_setup;

pub use preflight_a::*;
pub use preflight_b::*;
pub use preflight_fns::*;
pub use context::*;
pub use tier1::*;
pub use module_setup::*;

#[cfg(test)]
mod tests;
