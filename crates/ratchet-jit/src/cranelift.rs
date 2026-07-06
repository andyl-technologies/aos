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
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, mem,
    ptr::{self, NonNull},
};

use cranelift_codegen::{
    CodegenError, Context,
    ir::{ExternalName, Function, UserExternalName},
    settings::{self, Configurable, SetError},
};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, ModuleError};
use ratchet_core::{IrArena, IrId};
use ratchet_value::value::{Value, ValueError};

use crate::{
    abi::{JitEnvFramePtr, JitRuntimeContextPtr, JitThunkFn},
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource},
    lower::{
        JitLowerError, lower_constant_ir_thunk_body_artifact,
        lower_force_aware_tier1_ir_thunk_body_artifact, lower_tier1_ir_thunk_body_artifact,
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
        JitCompiledCodePointer, JitTieredCodeSlot, JitTieredCodeSlotError, TierUpDecision,
        TierUpDemandHint, TierUpPolicy,
    },
};

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

/// A runtime symbol declared as an imported function in a JIT module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitCraneliftImportedSymbol {
    symbol_name: String,
    linkage: Linkage,
    func_id: FuncId,
}

impl JitCraneliftImportedSymbol {
    fn new(symbol_name: String, linkage: Linkage, func_id: FuncId) -> Self {
        Self {
            symbol_name,
            linkage,
            func_id,
        }
    }

    /// Returns the stable runtime symbol name declared in the module.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the Cranelift module linkage for the imported symbol.
    pub const fn linkage(&self) -> Linkage {
        self.linkage
    }

    /// Returns the Cranelift function identifier assigned to the import.
    pub const fn func_id(&self) -> FuncId {
        self.func_id
    }
}

/// A verified CLIF artifact defined inside an encapsulated JIT module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitCraneliftDefinedFunction {
    symbol_name: String,
    linkage: Linkage,
    func_id: FuncId,
}

impl JitCraneliftDefinedFunction {
    fn new(symbol_name: String, linkage: Linkage, func_id: FuncId) -> Self {
        Self {
            symbol_name,
            linkage,
            func_id,
        }
    }

    /// Returns the stable module symbol name declared for the artifact body.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the Cranelift module linkage for the defined artifact body.
    pub const fn linkage(&self) -> Linkage {
        self.linkage
    }

    /// Returns the Cranelift function identifier assigned to the artifact body.
    pub const fn func_id(&self) -> FuncId {
        self.func_id
    }
}

/// A runtime symbol registered with a Cranelift JIT builder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitCraneliftRegisteredSymbol {
    symbol_name: String,
    address: JitRuntimeSymbolAddress,
}

impl JitCraneliftRegisteredSymbol {
    fn new(symbol_name: String, address: JitRuntimeSymbolAddress) -> Self {
        Self {
            symbol_name,
            address,
        }
    }

    /// Returns the stable runtime symbol name registered with the builder.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the opaque native address metadata passed to the builder.
    pub const fn address(&self) -> JitRuntimeSymbolAddress {
        self.address
    }
}

/// A verified CLIF artifact finalized into executable memory.
///
/// The code pointer stored here is metadata tied to the lifetime of the
/// [`JITModule`] owned by the finalization preflight that returned it. It is not
/// a standalone ownership handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitCraneliftFinalizedFunction {
    defined_function: JitCraneliftDefinedFunction,
    code_ptr: NonNull<u8>,
}

impl JitCraneliftFinalizedFunction {
    fn new(defined_function: JitCraneliftDefinedFunction, code_ptr: NonNull<u8>) -> Self {
        Self {
            defined_function,
            code_ptr,
        }
    }

    /// Returns the artifact body that was finalized.
    pub const fn defined_function(&self) -> &JitCraneliftDefinedFunction {
        &self.defined_function
    }

    /// Returns the stable module symbol name for the finalized artifact body.
    pub fn symbol_name(&self) -> &str {
        self.defined_function.symbol_name()
    }

    /// Returns the opaque finalized code pointer.
    ///
    /// This is code-pointer metadata only. Callers must not cast or call this
    /// pointer outside reviewed native-call paths such as
    /// [`jit_cranelift_native_thunk_call_for_artifact`]. The pointer's validity
    /// is tied to the owning
    /// [`JitCraneliftArtifactFinalizationPreflight`] and its encapsulated
    /// [`JITModule`]; retaining it after that owner is dropped can leave stale
    /// metadata.
    pub const fn code_ptr(&self) -> NonNull<u8> {
        self.code_ptr
    }

    /// Returns the finalized code pointer as tier-slot metadata.
    ///
    /// This preserves the same non-callable, non-owning lifetime contract as
    /// [`Self::code_ptr`]. It only adapts the pointer into the safe metadata type
    /// accepted by [`crate::tier::JitTieredCodeSlot`].
    pub const fn compiled_code_ptr(&self) -> JitCompiledCodePointer {
        JitCompiledCodePointer::from_non_null(self.code_ptr)
    }
}

/// A real `JITModule` created from a builder with runtime symbols registered.
pub struct JitCraneliftSymbolRegistrationPreflight {
    registered_symbols: Vec<JitCraneliftRegisteredSymbol>,
    symbol_gaps: Vec<JitRuntimeSymbolRegistrationGap>,
    module: JITModule,
}

impl JitCraneliftSymbolRegistrationPreflight {
    fn new(
        registered_symbols: Vec<JitCraneliftRegisteredSymbol>,
        symbol_gaps: Vec<JitRuntimeSymbolRegistrationGap>,
        module: JITModule,
    ) -> Self {
        Self {
            registered_symbols,
            symbol_gaps,
            module,
        }
    }

    /// Returns runtime symbols registered in the JIT builder's symbol table.
    pub fn registered_symbols(&self) -> &[JitCraneliftRegisteredSymbol] {
        &self.registered_symbols
    }

    /// Returns runtime symbols that still block complete symbol registration.
    pub fn symbol_gaps(&self) -> &[JitRuntimeSymbolRegistrationGap] {
        &self.symbol_gaps
    }

    /// Returns true when every stable runtime symbol has been registered.
    pub fn is_complete(&self) -> bool {
        self.symbol_gaps.is_empty()
    }

    /// Returns the registered symbol for `symbol_name`, when present.
    pub fn registered_symbol_for(
        &self,
        symbol_name: &str,
    ) -> Option<&JitCraneliftRegisteredSymbol> {
        self.registered_symbols
            .iter()
            .find(|symbol| symbol.symbol_name() == symbol_name)
    }

    /// Returns the registration gap for `symbol_name`, when present.
    pub fn gap_for_symbol(&self, symbol_name: &str) -> Option<&JitRuntimeSymbolRegistrationGap> {
        self.symbol_gaps
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }

    /// Returns true because this preflight owns an encapsulated `JITModule`.
    pub fn owns_encapsulated_module(&self) -> bool {
        let _module = &self.module;
        true
    }
}

/// A real `JITModule` with runtime symbols registered and one artifact defined.
pub struct JitCraneliftRegisteredArtifactDefinitionPreflight {
    artifact: JitModuleArtifactMetadata,
    defined_function: JitCraneliftDefinedFunction,
    imported_symbols: Vec<JitCraneliftImportedSymbol>,
    registered_symbols: Vec<JitCraneliftRegisteredSymbol>,
    artifact_runtime_imports: Vec<JitModuleArtifactRuntimeImport>,
    registration_gaps: Vec<JitRuntimeSymbolRegistrationGap>,
    module: JITModule,
}

impl JitCraneliftRegisteredArtifactDefinitionPreflight {
    fn new(
        artifact: JitModuleArtifactMetadata,
        defined_function: JitCraneliftDefinedFunction,
        imported_symbols: Vec<JitCraneliftImportedSymbol>,
        registered_symbols: Vec<JitCraneliftRegisteredSymbol>,
        artifact_runtime_imports: Vec<JitModuleArtifactRuntimeImport>,
        registration_gaps: Vec<JitRuntimeSymbolRegistrationGap>,
        module: JITModule,
    ) -> Self {
        Self {
            artifact,
            defined_function,
            imported_symbols,
            registered_symbols,
            artifact_runtime_imports,
            registration_gaps,
            module,
        }
    }

    /// Returns the CLIF artifact metadata that seeded module setup.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns the artifact body defined inside the registered-symbol module.
    pub const fn defined_function(&self) -> &JitCraneliftDefinedFunction {
        &self.defined_function
    }

    /// Returns runtime symbols declared as imported functions in the module.
    pub fn imported_symbols(&self) -> &[JitCraneliftImportedSymbol] {
        &self.imported_symbols
    }

    /// Returns runtime symbols registered in the JIT builder's symbol table.
    pub fn registered_symbols(&self) -> &[JitCraneliftRegisteredSymbol] {
        &self.registered_symbols
    }

    /// Returns runtime imports required by this artifact body.
    pub fn artifact_runtime_imports(&self) -> &[JitModuleArtifactRuntimeImport] {
        &self.artifact_runtime_imports
    }

    /// Returns stable runtime symbols still missing complete registration metadata.
    pub fn registration_gaps(&self) -> &[JitRuntimeSymbolRegistrationGap] {
        &self.registration_gaps
    }

    /// Returns true when every stable runtime symbol has registration metadata.
    pub fn is_complete(&self) -> bool {
        self.registration_gaps.is_empty()
    }

    /// Returns the imported-symbol declaration for `symbol_name`, when present.
    pub fn imported_symbol_for(&self, symbol_name: &str) -> Option<&JitCraneliftImportedSymbol> {
        self.imported_symbols
            .iter()
            .find(|symbol| symbol.symbol_name() == symbol_name)
    }

    /// Returns the registered symbol for `symbol_name`, when present.
    pub fn registered_symbol_for(
        &self,
        symbol_name: &str,
    ) -> Option<&JitCraneliftRegisteredSymbol> {
        self.registered_symbols
            .iter()
            .find(|symbol| symbol.symbol_name() == symbol_name)
    }

    /// Returns the registration gap for `symbol_name`, when present.
    pub fn registration_gap_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&JitRuntimeSymbolRegistrationGap> {
        self.registration_gaps
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }

    /// Returns true because this preflight owns an encapsulated `JITModule`.
    pub fn owns_encapsulated_module(&self) -> bool {
        let _module = &self.module;
        true
    }
}

/// A real `JITModule` with runtime symbols registered and one artifact finalized.
pub struct JitCraneliftRegisteredArtifactFinalizationPreflight {
    artifact: JitModuleArtifactMetadata,
    finalized_function: JitCraneliftFinalizedFunction,
    imported_symbols: Vec<JitCraneliftImportedSymbol>,
    registered_symbols: Vec<JitCraneliftRegisteredSymbol>,
    artifact_runtime_imports: Vec<JitModuleArtifactRuntimeImport>,
    registration_gaps: Vec<JitRuntimeSymbolRegistrationGap>,
    module: JITModule,
}

impl JitCraneliftRegisteredArtifactFinalizationPreflight {
    fn new(
        artifact: JitModuleArtifactMetadata,
        finalized_function: JitCraneliftFinalizedFunction,
        imported_symbols: Vec<JitCraneliftImportedSymbol>,
        registered_symbols: Vec<JitCraneliftRegisteredSymbol>,
        artifact_runtime_imports: Vec<JitModuleArtifactRuntimeImport>,
        registration_gaps: Vec<JitRuntimeSymbolRegistrationGap>,
        module: JITModule,
    ) -> Self {
        Self {
            artifact,
            finalized_function,
            imported_symbols,
            registered_symbols,
            artifact_runtime_imports,
            registration_gaps,
            module,
        }
    }

    /// Returns the CLIF artifact metadata that seeded module setup.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns the finalized artifact body metadata.
    pub const fn finalized_function(&self) -> &JitCraneliftFinalizedFunction {
        &self.finalized_function
    }

    /// Returns runtime symbols declared as imported functions in the module.
    pub fn imported_symbols(&self) -> &[JitCraneliftImportedSymbol] {
        &self.imported_symbols
    }

    /// Returns runtime symbols registered in the JIT builder's symbol table.
    pub fn registered_symbols(&self) -> &[JitCraneliftRegisteredSymbol] {
        &self.registered_symbols
    }

    /// Returns runtime imports required by this artifact body.
    pub fn artifact_runtime_imports(&self) -> &[JitModuleArtifactRuntimeImport] {
        &self.artifact_runtime_imports
    }

    /// Returns stable runtime symbols still missing complete registration metadata.
    pub fn registration_gaps(&self) -> &[JitRuntimeSymbolRegistrationGap] {
        &self.registration_gaps
    }

    /// Returns true when every stable runtime symbol has registration metadata.
    pub fn is_complete(&self) -> bool {
        self.registration_gaps.is_empty()
    }

    /// Returns the imported-symbol declaration for `symbol_name`, when present.
    pub fn imported_symbol_for(&self, symbol_name: &str) -> Option<&JitCraneliftImportedSymbol> {
        self.imported_symbols
            .iter()
            .find(|symbol| symbol.symbol_name() == symbol_name)
    }

    /// Returns the registered symbol for `symbol_name`, when present.
    pub fn registered_symbol_for(
        &self,
        symbol_name: &str,
    ) -> Option<&JitCraneliftRegisteredSymbol> {
        self.registered_symbols
            .iter()
            .find(|symbol| symbol.symbol_name() == symbol_name)
    }

    /// Returns the registration gap for `symbol_name`, when present.
    pub fn registration_gap_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&JitRuntimeSymbolRegistrationGap> {
        self.registration_gaps
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }

    /// Returns true because this preflight owns an encapsulated `JITModule`.
    pub fn owns_encapsulated_module(&self) -> bool {
        let _module = &self.module;
        true
    }
}

/// A real `JITModule` with one artifact body finalized into executable memory.
pub struct JitCraneliftArtifactFinalizationPreflight {
    artifact: JitModuleArtifactMetadata,
    finalized_function: JitCraneliftFinalizedFunction,
    imported_symbols: Vec<JitCraneliftImportedSymbol>,
    symbol_gaps: Vec<JitRuntimeSymbolDeclarationGap>,
    module: JITModule,
}

impl JitCraneliftArtifactFinalizationPreflight {
    fn new(
        artifact: JitModuleArtifactMetadata,
        finalized_function: JitCraneliftFinalizedFunction,
        imported_symbols: Vec<JitCraneliftImportedSymbol>,
        symbol_gaps: Vec<JitRuntimeSymbolDeclarationGap>,
        module: JITModule,
    ) -> Self {
        Self {
            artifact,
            finalized_function,
            imported_symbols,
            symbol_gaps,
            module,
        }
    }

    /// Returns the CLIF artifact metadata that seeded module setup.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns the finalized artifact body metadata.
    pub const fn finalized_function(&self) -> &JitCraneliftFinalizedFunction {
        &self.finalized_function
    }

    /// Returns runtime symbols declared as imported functions in the module.
    pub fn imported_symbols(&self) -> &[JitCraneliftImportedSymbol] {
        &self.imported_symbols
    }

    /// Returns runtime symbols that still block complete module setup.
    pub fn symbol_gaps(&self) -> &[JitRuntimeSymbolDeclarationGap] {
        &self.symbol_gaps
    }

    /// Returns true when every stable runtime symbol has been declared.
    pub fn is_complete(&self) -> bool {
        self.symbol_gaps.is_empty()
    }

    /// Returns the imported-symbol declaration for `symbol_name`, when present.
    pub fn imported_symbol_for(&self, symbol_name: &str) -> Option<&JitCraneliftImportedSymbol> {
        self.imported_symbols
            .iter()
            .find(|symbol| symbol.symbol_name() == symbol_name)
    }

    /// Returns the declaration gap for `symbol_name`, when present.
    pub fn gap_for_symbol(&self, symbol_name: &str) -> Option<&JitRuntimeSymbolDeclarationGap> {
        self.symbol_gaps
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }

    /// Returns true because this preflight owns an encapsulated `JITModule`.
    pub fn owns_encapsulated_module(&self) -> bool {
        let _module = &self.module;
        true
    }
}

/// Result of calling one finalized thunk body through the native ABI.
///
/// The invocation owns the finalization preflight that keeps the backing
/// [`JITModule`] alive while exposing the already-returned value for tests and
/// future differential harness integration.
pub struct JitCraneliftNativeThunkInvocation {
    finalization: JitCraneliftArtifactFinalizationPreflight,
    value: Value,
}

impl JitCraneliftNativeThunkInvocation {
    fn new(finalization: JitCraneliftArtifactFinalizationPreflight, value: Value) -> Self {
        Self {
            finalization,
            value,
        }
    }

    /// Returns the finalization preflight that owns the backing JIT module.
    pub const fn finalization(&self) -> &JitCraneliftArtifactFinalizationPreflight {
        &self.finalization
    }

    /// Returns the finalized artifact body metadata.
    pub const fn finalized_function(&self) -> &JitCraneliftFinalizedFunction {
        self.finalization.finalized_function()
    }

    /// Returns the value produced by the native thunk call.
    pub const fn value(&self) -> Value {
        self.value
    }

    /// Returns true because this invocation owns the module backing the call target.
    pub fn owns_encapsulated_module(&self) -> bool {
        self.finalization.owns_encapsulated_module()
    }
}

/// Result of calling one finalized registered thunk body through the native ABI.
///
/// The invocation owns the registered finalization preflight that keeps the
/// backing [`JITModule`] alive. Unlike [`JitCraneliftNativeThunkInvocation`],
/// this value can represent artifacts that call registered runtime imports, so
/// constructing it requires the caller to uphold the unsafe native-address and
/// runtime-pointer invariants of
/// [`jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`].
pub struct JitCraneliftRegisteredNativeThunkInvocation {
    finalization: JitCraneliftRegisteredArtifactFinalizationPreflight,
    value: Value,
}

impl JitCraneliftRegisteredNativeThunkInvocation {
    fn new(
        finalization: JitCraneliftRegisteredArtifactFinalizationPreflight,
        value: Value,
    ) -> Self {
        Self {
            finalization,
            value,
        }
    }

    /// Returns the registered finalization preflight that owns the backing JIT module.
    pub const fn finalization(&self) -> &JitCraneliftRegisteredArtifactFinalizationPreflight {
        &self.finalization
    }

    /// Returns the finalized artifact body metadata.
    pub const fn finalized_function(&self) -> &JitCraneliftFinalizedFunction {
        self.finalization.finalized_function()
    }

    /// Returns the value produced by the native thunk call.
    pub const fn value(&self) -> Value {
        self.value
    }

    /// Returns true because this invocation owns the module backing the call target.
    pub fn owns_encapsulated_module(&self) -> bool {
        self.finalization.owns_encapsulated_module()
    }
}

/// A finalized artifact kept alive beside safe tier-1 slot metadata.
pub struct JitCraneliftTier1SlotPreflight {
    finalization: JitCraneliftArtifactFinalizationPreflight,
    slot: JitTieredCodeSlot,
}

impl JitCraneliftTier1SlotPreflight {
    fn new(
        finalization: JitCraneliftArtifactFinalizationPreflight,
        slot: JitTieredCodeSlot,
    ) -> Self {
        Self { finalization, slot }
    }

    /// Returns the finalization preflight that owns the encapsulated `JITModule`.
    pub const fn finalization(&self) -> &JitCraneliftArtifactFinalizationPreflight {
        &self.finalization
    }

    /// Returns the safe tiered-code slot with tier-1 metadata installed.
    ///
    /// The slot's opaque pointer remains non-callable metadata. Its backend
    /// lifetime is kept alive by [`Self::finalization`].
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        &self.slot
    }

    /// Returns the finalized artifact body metadata.
    pub const fn finalized_function(&self) -> &JitCraneliftFinalizedFunction {
        self.finalization.finalized_function()
    }

    /// Returns the CLIF artifact metadata that seeded the owned module setup.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        self.finalization.artifact()
    }

    /// Returns true because this preflight owns the module backing the slot pointer.
    pub fn owns_encapsulated_module(&self) -> bool {
        self.finalization.owns_encapsulated_module()
    }
}

/// A registered-symbol finalized artifact kept alive beside tier-1 slot metadata.
pub struct JitCraneliftRegisteredTier1SlotPreflight {
    finalization: JitCraneliftRegisteredArtifactFinalizationPreflight,
    slot: JitTieredCodeSlot,
}

impl JitCraneliftRegisteredTier1SlotPreflight {
    fn new(
        finalization: JitCraneliftRegisteredArtifactFinalizationPreflight,
        slot: JitTieredCodeSlot,
    ) -> Self {
        Self { finalization, slot }
    }

    /// Returns the finalization preflight that owns the encapsulated `JITModule`.
    pub const fn finalization(&self) -> &JitCraneliftRegisteredArtifactFinalizationPreflight {
        &self.finalization
    }

    /// Returns the safe tiered-code slot with tier-1 metadata installed.
    ///
    /// The slot's opaque pointer remains non-callable metadata. Its backend
    /// lifetime is kept alive by [`Self::finalization`].
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        &self.slot
    }

    /// Returns the finalized artifact body metadata.
    pub const fn finalized_function(&self) -> &JitCraneliftFinalizedFunction {
        self.finalization.finalized_function()
    }

    /// Returns the CLIF artifact metadata that seeded the owned module setup.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        self.finalization.artifact()
    }

    /// Returns true because this preflight owns the module backing the slot pointer.
    pub fn owns_encapsulated_module(&self) -> bool {
        self.finalization.owns_encapsulated_module()
    }
}

/// Result of one promotion-gated tier-1 compile attempt.
pub enum JitCraneliftTier1PromotionPreflight {
    /// The invocation was recorded, but policy did not request compilation.
    StayedInTier {
        /// The updated safe tiered-code slot.
        slot: JitTieredCodeSlot,
        /// The policy decision made after recording the invocation.
        decision: TierUpDecision,
    },
    /// Policy requested promotion and a tier-1 artifact was finalized into a slot.
    Promoted {
        /// The owned finalization plus tier-slot metadata.
        preflight: JitCraneliftTier1SlotPreflight,
        /// The policy decision that requested promotion.
        decision: TierUpDecision,
    },
}

impl JitCraneliftTier1PromotionPreflight {
    /// Returns the policy decision made for this promotion attempt.
    pub const fn decision(&self) -> TierUpDecision {
        match self {
            Self::StayedInTier { decision, .. } | Self::Promoted { decision, .. } => *decision,
        }
    }

    /// Returns true when this attempt compiled and installed tier-1 metadata.
    pub const fn did_compile(&self) -> bool {
        matches!(self, Self::Promoted { .. })
    }

    /// Returns the updated tiered-code slot.
    ///
    /// For promoted results, the returned slot is backed by the finalization
    /// preflight held in the same enum value.
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        match self {
            Self::StayedInTier { slot, .. } => slot,
            Self::Promoted { preflight, .. } => preflight.slot(),
        }
    }

    /// Returns the owned tier-1 preflight when compilation occurred.
    pub const fn promoted_preflight(&self) -> Option<&JitCraneliftTier1SlotPreflight> {
        match self {
            Self::StayedInTier { .. } => None,
            Self::Promoted { preflight, .. } => Some(preflight),
        }
    }

    /// Returns true when this value owns a `JITModule` backing the slot pointer.
    pub fn owns_encapsulated_module(&self) -> bool {
        match self {
            Self::StayedInTier { .. } => false,
            Self::Promoted { preflight, .. } => preflight.owns_encapsulated_module(),
        }
    }
}

/// Result of one registered-symbol promotion-gated tier-1 compile attempt.
pub enum JitCraneliftRegisteredTier1PromotionPreflight {
    /// The invocation was recorded, but policy did not request compilation.
    StayedInTier {
        /// The updated safe tiered-code slot.
        slot: JitTieredCodeSlot,
        /// The policy decision made after recording the invocation.
        decision: TierUpDecision,
    },
    /// Policy requested promotion and a registered tier-1 artifact was installed.
    Promoted {
        /// The owned registered finalization plus tier-slot metadata.
        preflight: JitCraneliftRegisteredTier1SlotPreflight,
        /// The policy decision that requested promotion.
        decision: TierUpDecision,
    },
}

impl JitCraneliftRegisteredTier1PromotionPreflight {
    /// Returns the policy decision made for this promotion attempt.
    pub const fn decision(&self) -> TierUpDecision {
        match self {
            Self::StayedInTier { decision, .. } | Self::Promoted { decision, .. } => *decision,
        }
    }

    /// Returns true when this attempt compiled and installed tier-1 metadata.
    pub const fn did_compile(&self) -> bool {
        matches!(self, Self::Promoted { .. })
    }

    /// Returns the updated tiered-code slot.
    ///
    /// For promoted results, the returned slot is backed by the registered
    /// finalization preflight held in the same enum value.
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        match self {
            Self::StayedInTier { slot, .. } => slot,
            Self::Promoted { preflight, .. } => preflight.slot(),
        }
    }

    /// Returns the owned registered tier-1 preflight when compilation occurred.
    pub const fn promoted_preflight(&self) -> Option<&JitCraneliftRegisteredTier1SlotPreflight> {
        match self {
            Self::StayedInTier { .. } => None,
            Self::Promoted { preflight, .. } => Some(preflight),
        }
    }

    /// Returns true when this value owns a `JITModule` backing the slot pointer.
    pub fn owns_encapsulated_module(&self) -> bool {
        match self {
            Self::StayedInTier { .. } => false,
            Self::Promoted { preflight, .. } => preflight.owns_encapsulated_module(),
        }
    }
}

/// Result of one registered-symbol promotion-gated tier-1 native call attempt.
pub enum JitCraneliftRegisteredTier1NativeCallPreflight {
    /// The invocation was recorded, but policy did not request compilation or a native call.
    StayedInTier {
        /// The updated safe tiered-code slot.
        slot: JitTieredCodeSlot,
        /// The policy decision made after recording the invocation.
        decision: TierUpDecision,
    },
    /// Policy requested promotion, tier-1 metadata was installed, and native code was called.
    PromotedAndCalled {
        /// The updated safe tiered-code slot with tier-1 pointer metadata.
        slot: JitTieredCodeSlot,
        /// The owned registered native invocation that keeps the module alive.
        invocation: JitCraneliftRegisteredNativeThunkInvocation,
        /// The policy decision that requested promotion.
        decision: TierUpDecision,
    },
}

impl JitCraneliftRegisteredTier1NativeCallPreflight {
    /// Returns the policy decision made for this native-call attempt.
    pub const fn decision(&self) -> TierUpDecision {
        match self {
            Self::StayedInTier { decision, .. } | Self::PromotedAndCalled { decision, .. } => {
                *decision
            }
        }
    }

    /// Returns true when this attempt compiled and called tier-1 code.
    pub const fn did_call_native_code(&self) -> bool {
        matches!(self, Self::PromotedAndCalled { .. })
    }

    /// Returns the updated tiered-code slot.
    ///
    /// For promoted results, the returned slot is backed by the native
    /// invocation held in the same enum value.
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        match self {
            Self::StayedInTier { slot, .. } | Self::PromotedAndCalled { slot, .. } => slot,
        }
    }

    /// Returns the owned registered native invocation when native code was called.
    pub const fn native_invocation(&self) -> Option<&JitCraneliftRegisteredNativeThunkInvocation> {
        match self {
            Self::StayedInTier { .. } => None,
            Self::PromotedAndCalled { invocation, .. } => Some(invocation),
        }
    }

    /// Returns the native value when native code was called.
    pub const fn native_value(&self) -> Option<Value> {
        match self {
            Self::StayedInTier { .. } => None,
            Self::PromotedAndCalled { invocation, .. } => Some(invocation.value()),
        }
    }

    /// Returns true when this value owns a `JITModule` backing the slot pointer.
    pub fn owns_encapsulated_module(&self) -> bool {
        match self {
            Self::StayedInTier { .. } => false,
            Self::PromotedAndCalled { invocation, .. } => invocation.owns_encapsulated_module(),
        }
    }
}

/// A failure from a promotion-gated tier-1 compile attempt.
#[derive(Debug)]
pub struct JitCraneliftTier1PromotionError {
    slot: JitTieredCodeSlot,
    decision: TierUpDecision,
    source: JitCraneliftModuleSetupError,
}

impl JitCraneliftTier1PromotionError {
    fn new(
        slot: JitTieredCodeSlot,
        decision: TierUpDecision,
        source: JitCraneliftModuleSetupError,
    ) -> Self {
        Self {
            slot,
            decision,
            source,
        }
    }

    /// Returns the invocation-updated slot from the failed promotion attempt.
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        &self.slot
    }

    /// Returns the policy decision that requested compilation.
    pub const fn decision(&self) -> TierUpDecision {
        self.decision
    }

    /// Returns the underlying lowering, finalization, or slot-install error.
    pub const fn setup_error(&self) -> &JitCraneliftModuleSetupError {
        &self.source
    }

    /// Consumes the error and returns the invocation-updated slot.
    pub fn into_slot(self) -> JitTieredCodeSlot {
        self.slot
    }
}

impl fmt::Display for JitCraneliftTier1PromotionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "tier-1 promotion failed after decision {:?}: {}",
            self.decision, self.source
        )
    }
}

impl Error for JitCraneliftTier1PromotionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// A real `JITModule` containing imported runtime-symbol declarations plus gaps.
pub struct JitCraneliftModuleDeclarationPreflight {
    artifact: JitModuleArtifactMetadata,
    imported_symbols: Vec<JitCraneliftImportedSymbol>,
    symbol_gaps: Vec<JitRuntimeSymbolDeclarationGap>,
    module: JITModule,
}

impl JitCraneliftModuleDeclarationPreflight {
    fn new(
        artifact: JitModuleArtifactMetadata,
        imported_symbols: Vec<JitCraneliftImportedSymbol>,
        symbol_gaps: Vec<JitRuntimeSymbolDeclarationGap>,
        module: JITModule,
    ) -> Self {
        Self {
            artifact,
            imported_symbols,
            symbol_gaps,
            module,
        }
    }

    /// Returns the CLIF artifact metadata that seeded module setup.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns runtime symbols declared as imported functions in the module.
    pub fn imported_symbols(&self) -> &[JitCraneliftImportedSymbol] {
        &self.imported_symbols
    }

    /// Returns runtime symbols that still block complete module setup.
    pub fn symbol_gaps(&self) -> &[JitRuntimeSymbolDeclarationGap] {
        &self.symbol_gaps
    }

    /// Returns true when every stable runtime symbol has been declared.
    pub fn is_complete(&self) -> bool {
        self.symbol_gaps.is_empty()
    }

    /// Returns the imported-symbol declaration for `symbol_name`, when present.
    pub fn imported_symbol_for(&self, symbol_name: &str) -> Option<&JitCraneliftImportedSymbol> {
        self.imported_symbols
            .iter()
            .find(|symbol| symbol.symbol_name() == symbol_name)
    }

    /// Returns the declaration gap for `symbol_name`, when present.
    pub fn gap_for_symbol(&self, symbol_name: &str) -> Option<&JitRuntimeSymbolDeclarationGap> {
        self.symbol_gaps
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }

    /// Returns true because this preflight owns an encapsulated `JITModule`.
    pub fn owns_encapsulated_module(&self) -> bool {
        let _module = &self.module;
        true
    }
}

/// A real `JITModule` with one verified CLIF artifact body defined inside it.
pub struct JitCraneliftArtifactDefinitionPreflight {
    artifact: JitModuleArtifactMetadata,
    defined_function: JitCraneliftDefinedFunction,
    imported_symbols: Vec<JitCraneliftImportedSymbol>,
    symbol_gaps: Vec<JitRuntimeSymbolDeclarationGap>,
    module: JITModule,
}

impl JitCraneliftArtifactDefinitionPreflight {
    fn new(
        artifact: JitModuleArtifactMetadata,
        defined_function: JitCraneliftDefinedFunction,
        imported_symbols: Vec<JitCraneliftImportedSymbol>,
        symbol_gaps: Vec<JitRuntimeSymbolDeclarationGap>,
        module: JITModule,
    ) -> Self {
        Self {
            artifact,
            defined_function,
            imported_symbols,
            symbol_gaps,
            module,
        }
    }

    /// Returns the CLIF artifact metadata that seeded module setup.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns the artifact body defined inside the module.
    pub const fn defined_function(&self) -> &JitCraneliftDefinedFunction {
        &self.defined_function
    }

    /// Returns runtime symbols declared as imported functions in the module.
    pub fn imported_symbols(&self) -> &[JitCraneliftImportedSymbol] {
        &self.imported_symbols
    }

    /// Returns runtime symbols that still block complete module setup.
    pub fn symbol_gaps(&self) -> &[JitRuntimeSymbolDeclarationGap] {
        &self.symbol_gaps
    }

    /// Returns true when every stable runtime symbol has been declared.
    pub fn is_complete(&self) -> bool {
        self.symbol_gaps.is_empty()
    }

    /// Returns the imported-symbol declaration for `symbol_name`, when present.
    pub fn imported_symbol_for(&self, symbol_name: &str) -> Option<&JitCraneliftImportedSymbol> {
        self.imported_symbols
            .iter()
            .find(|symbol| symbol.symbol_name() == symbol_name)
    }

    /// Returns the declaration gap for `symbol_name`, when present.
    pub fn gap_for_symbol(&self, symbol_name: &str) -> Option<&JitRuntimeSymbolDeclarationGap> {
        self.symbol_gaps
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }

    /// Returns true because this preflight owns an encapsulated `JITModule`.
    pub fn owns_encapsulated_module(&self) -> bool {
        let _module = &self.module;
        true
    }
}

/// A real `JITModule` whose stable runtime symbols are fully declared.
pub struct JitCraneliftModuleSetup {
    artifact: JitModuleArtifactMetadata,
    imported_symbols: Vec<JitCraneliftImportedSymbol>,
    module: JITModule,
}

impl JitCraneliftModuleSetup {
    fn new(
        artifact: JitModuleArtifactMetadata,
        imported_symbols: Vec<JitCraneliftImportedSymbol>,
        module: JITModule,
    ) -> Self {
        Self {
            artifact,
            imported_symbols,
            module,
        }
    }

    /// Returns the CLIF artifact metadata that seeded module setup.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns every runtime symbol declared as an imported function.
    pub fn imported_symbols(&self) -> &[JitCraneliftImportedSymbol] {
        &self.imported_symbols
    }

    /// Returns the imported-symbol declaration for `symbol_name`, when present.
    pub fn imported_symbol_for(&self, symbol_name: &str) -> Option<&JitCraneliftImportedSymbol> {
        self.imported_symbols
            .iter()
            .find(|symbol| symbol.symbol_name() == symbol_name)
    }

    /// Returns true because this setup owns an encapsulated `JITModule`.
    pub fn owns_encapsulated_module(&self) -> bool {
        let _module = &self.module;
        true
    }
}

/// A failure from a promotion-gated registered tier-1 native call attempt.
#[derive(Debug)]
pub struct JitCraneliftRegisteredTier1NativeCallError {
    slot: JitTieredCodeSlot,
    decision: TierUpDecision,
    source: JitCraneliftNativeCallError,
}

impl JitCraneliftRegisteredTier1NativeCallError {
    fn new(
        slot: JitTieredCodeSlot,
        decision: TierUpDecision,
        source: JitCraneliftNativeCallError,
    ) -> Self {
        Self {
            slot,
            decision,
            source,
        }
    }

    /// Returns the invocation-updated slot from the failed native-call attempt.
    pub const fn slot(&self) -> &JitTieredCodeSlot {
        &self.slot
    }

    /// Returns the policy decision that requested native execution.
    pub const fn decision(&self) -> TierUpDecision {
        self.decision
    }

    /// Returns the underlying native-call, lowering, finalization, or install error.
    pub const fn native_call_error(&self) -> &JitCraneliftNativeCallError {
        &self.source
    }

    /// Consumes the error and returns the invocation-updated slot.
    pub fn into_slot(self) -> JitTieredCodeSlot {
        self.slot
    }
}

impl fmt::Display for JitCraneliftRegisteredTier1NativeCallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "registered tier-1 native thunk call failed after decision {:?}: {}",
            self.decision, self.source
        )
    }
}

impl Error for JitCraneliftRegisteredTier1NativeCallError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// A failure while constructing a safe Cranelift JIT-module scaffold.
#[derive(Debug)]
pub enum JitCraneliftModuleSetupError {
    /// Cranelift could not build an ISA for this host.
    UnsupportedHost {
        /// The Cranelift-native host-detection failure.
        message: &'static str,
    },
    /// A Cranelift setting required by the JIT scaffold was rejected.
    Settings(SetError),
    /// Cranelift rejected the native ISA configuration.
    TargetIsa(CodegenError),
    /// Runtime-symbol readiness metadata could not be completed.
    Readiness(JitModuleReadinessError),
    /// Native runtime-symbol registration metadata could not be built.
    RuntimeSymbolRegistration(JitRuntimeSymbolRegistrationError),
    /// A call-bearing artifact requires runtime symbols that are not registered.
    ArtifactRuntimeImportsRequireRegistration {
        /// Stable runtime symbols imported by the artifact body.
        symbol_names: Vec<String>,
    },
    /// A tier-1 artifact could not be lowered from Core IR.
    LowerTier1Artifact {
        /// The Core IR root requested for tier-1 compilation.
        root: IrId,
        /// The underlying CLIF lowering error.
        source: JitLowerError,
    },
    /// A runtime-symbol import could not be declared in the module.
    DeclareRuntimeSymbol {
        /// The stable runtime symbol being declared.
        symbol_name: String,
        /// The underlying Cranelift module error.
        source: ModuleError,
    },
    /// The verified CLIF artifact body could not be declared in the module.
    DeclareArtifactFunction {
        /// The stable module symbol assigned to the artifact body.
        symbol_name: String,
        /// The underlying Cranelift module error.
        source: ModuleError,
    },
    /// The verified CLIF artifact body could not be defined in the module.
    DefineArtifactFunction {
        /// The stable module symbol assigned to the artifact body.
        symbol_name: String,
        /// The underlying Cranelift module error.
        source: ModuleError,
    },
    /// The JIT module could not finalize defined functions.
    FinalizeDefinitions {
        /// The stable module symbol that was being finalized.
        symbol_name: String,
        /// The underlying Cranelift module error.
        source: ModuleError,
    },
    /// Cranelift returned a null finalized function pointer.
    FinalizedFunctionPointerNull {
        /// The stable module symbol assigned to the artifact body.
        symbol_name: String,
    },
    /// Finalized code metadata could not be installed into the tier-1 slot.
    InstallTier1Code {
        /// The stable module symbol assigned to the artifact body.
        symbol_name: String,
        /// The underlying slot update error.
        source: JitTieredCodeSlotError,
    },
}

/// A failure while calling finalized native thunk code.
#[derive(Debug)]
pub enum JitCraneliftNativeCallError {
    /// The current host does not have a reviewed native `Value` calling convention.
    UnsupportedNativeValueAbi {
        /// Human-readable reason this host is not enabled for native thunk calls.
        message: &'static str,
    },
    /// The artifact could not be lowered, finalized, or installed into callable code metadata.
    FinalizeArtifact {
        /// The underlying Cranelift setup error.
        source: JitCraneliftModuleSetupError,
    },
    /// The finalized artifact is not a compiled thunk body.
    UnsupportedArtifactKind {
        /// The lowered artifact kind carried by finalization metadata.
        kind: JitClifArtifactKind,
    },
    /// The native call returned valid-tag bits that violate the runtime value payload layout.
    InvalidReturnValue {
        /// The stable module symbol that was called.
        symbol_name: String,
        /// The valid-tag value whose payload failed validation.
        value: Value,
        /// The underlying value-layout error.
        source: ValueError,
    },
}

impl fmt::Display for JitCraneliftNativeCallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedNativeValueAbi { message } => write!(formatter, "{message}"),
            Self::FinalizeArtifact { source } => write!(formatter, "{source}"),
            Self::UnsupportedArtifactKind { kind } => {
                write!(
                    formatter,
                    "artifact kind {kind:?} is not callable as a thunk body"
                )
            }
            Self::InvalidReturnValue {
                symbol_name,
                source,
                ..
            } => write!(
                formatter,
                "native thunk {symbol_name:?} returned an invalid runtime value: {source}"
            ),
        }
    }
}

impl Error for JitCraneliftNativeCallError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UnsupportedNativeValueAbi { .. } => None,
            Self::FinalizeArtifact { source } => Some(source),
            Self::UnsupportedArtifactKind { .. } => None,
            Self::InvalidReturnValue { source, .. } => Some(source),
        }
    }
}

impl fmt::Display for JitCraneliftModuleSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost { message } => {
                write!(formatter, "Cranelift does not support this host: {message}")
            }
            Self::Settings(error) => write!(formatter, "{error}"),
            Self::TargetIsa(error) => write!(formatter, "{error}"),
            Self::Readiness(error) => write!(formatter, "{error}"),
            Self::RuntimeSymbolRegistration(error) => write!(formatter, "{error}"),
            Self::ArtifactRuntimeImportsRequireRegistration { symbol_names } => write!(
                formatter,
                "artifact runtime imports require registered native symbols before Cranelift definition: {}",
                symbol_names.join(", ")
            ),
            Self::LowerTier1Artifact { root, source } => write!(
                formatter,
                "IR root {root:?} could not be lowered for tier-1 compilation: {source}"
            ),
            Self::DeclareRuntimeSymbol {
                symbol_name,
                source,
            } => write!(
                formatter,
                "runtime symbol {symbol_name:?} could not be declared in the JIT module: {source}"
            ),
            Self::DeclareArtifactFunction {
                symbol_name,
                source,
            } => write!(
                formatter,
                "artifact function {symbol_name:?} could not be declared in the JIT module: {source}"
            ),
            Self::DefineArtifactFunction {
                symbol_name,
                source,
            } => write!(
                formatter,
                "artifact function {symbol_name:?} could not be defined in the JIT module: {source}"
            ),
            Self::FinalizeDefinitions {
                symbol_name,
                source,
            } => write!(
                formatter,
                "artifact function {symbol_name:?} could not be finalized in the JIT module: {source}"
            ),
            Self::FinalizedFunctionPointerNull { symbol_name } => write!(
                formatter,
                "artifact function {symbol_name:?} finalized to a null code pointer"
            ),
            Self::InstallTier1Code {
                symbol_name,
                source,
            } => write!(
                formatter,
                "artifact function {symbol_name:?} could not be installed into a tier-1 slot: {source}"
            ),
        }
    }
}

impl Error for JitCraneliftModuleSetupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UnsupportedHost { .. } => None,
            Self::Settings(error) => Some(error),
            Self::TargetIsa(error) => Some(error),
            Self::Readiness(error) => Some(error),
            Self::RuntimeSymbolRegistration(error) => Some(error),
            Self::ArtifactRuntimeImportsRequireRegistration { .. } => None,
            Self::LowerTier1Artifact { source, .. } => Some(source),
            Self::DeclareRuntimeSymbol { source, .. } => Some(source),
            Self::DeclareArtifactFunction { source, .. } => Some(source),
            Self::DefineArtifactFunction { source, .. } => Some(source),
            Self::FinalizeDefinitions { source, .. } => Some(source),
            Self::FinalizedFunctionPointerNull { .. } => None,
            Self::InstallTier1Code { source, .. } => Some(source),
        }
    }
}

impl From<SetError> for JitCraneliftModuleSetupError {
    fn from(error: SetError) -> Self {
        Self::Settings(error)
    }
}

impl From<CodegenError> for JitCraneliftModuleSetupError {
    fn from(error: CodegenError) -> Self {
        Self::TargetIsa(error)
    }
}

impl From<JitModuleReadinessError> for JitCraneliftModuleSetupError {
    fn from(error: JitModuleReadinessError) -> Self {
        Self::Readiness(error)
    }
}

impl From<JitRuntimeSymbolRegistrationError> for JitCraneliftModuleSetupError {
    fn from(error: JitRuntimeSymbolRegistrationError) -> Self {
        Self::RuntimeSymbolRegistration(error)
    }
}

/// Builds a real JIT module and declares shape-known runtime symbol imports.
///
/// The returned preflight owns a [`JITModule`] with callable builtin and
/// core-owned allocation, call-control apply, environment-access,
/// write-barrier, and force/deep-force helper imports declared using
/// `Linkage::Import`. Unshaped helpers and value-only builtins remain explicit
/// gaps. No runtime symbol addresses are registered and no CLIF functions are
/// defined, finalized, or called.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] if runtime-symbol
/// readiness metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration.
pub fn jit_cranelift_module_declaration_preflight_for_artifact(
    artifact: &JitClifArtifact,
) -> Result<JitCraneliftModuleDeclarationPreflight, JitCraneliftModuleSetupError> {
    let readiness = jit_module_readiness_preflight_for_artifact(artifact)?;
    let (module, imported_symbols) = module_with_imported_symbols(readiness.symbol_declarations())?;

    Ok(JitCraneliftModuleDeclarationPreflight::new(
        readiness.artifact().clone(),
        imported_symbols,
        readiness.symbol_gaps().to_vec(),
        module,
    ))
}

/// Builds a JIT module from a builder with explicit runtime symbols registered.
///
/// The returned preflight calls [`JITBuilder::symbol`] for every runtime symbol
/// that has both CLIF declaration metadata and explicit native-address candidate
/// metadata. Missing declarations, missing addresses, kind mismatches, duplicate
/// candidates, and unknown candidates remain explicit gaps or errors from the
/// registration metadata layer. The resulting module is not given imported
/// declarations, no CLIF body is defined or finalized, and no registered address
/// is dereferenced or called.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::RuntimeSymbolRegistration`] if
/// runtime-symbol registration metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration.
pub fn jit_cranelift_symbol_registration_preflight_with_candidates(
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftSymbolRegistrationPreflight, JitCraneliftModuleSetupError> {
    let registration = jit_runtime_symbol_registration_preflight_with_candidates(candidates)?;
    let (module, registered_symbols) = module_with_registered_symbols(registration.bindings())?;

    Ok(JitCraneliftSymbolRegistrationPreflight::new(
        registered_symbols,
        registration.gaps().to_vec(),
        module,
    ))
}

/// Registers explicit runtime symbols and defines one verified CLIF artifact body.
///
/// The returned preflight calls [`JITBuilder::symbol`] for every supplied
/// native-address candidate that matches CLIF declaration metadata, declares
/// shape-known runtime imports in the same module, rewrites artifact runtime
/// imports to Cranelift module-local function references, and passes the artifact
/// body to Cranelift's definition API. It does not finalize definitions,
/// dereference registered addresses, expose a code pointer, or call native code.
/// Stable runtime symbols outside the artifact's import set may remain
/// registration gaps.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] if artifact readiness
/// metadata cannot be built or has unresolved runtime imports. Returns
/// [`JitCraneliftModuleSetupError::RuntimeSymbolRegistration`] if
/// runtime-symbol registration metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration`]
/// when the artifact imports a runtime symbol without matching native-address
/// registration metadata. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration. Returns
/// [`JitCraneliftModuleSetupError::DeclareArtifactFunction`] if Cranelift
/// rejects the artifact function declaration. Returns
/// [`JitCraneliftModuleSetupError::DefineArtifactFunction`] if Cranelift rejects
/// the artifact function definition.
pub fn jit_cranelift_registered_artifact_definition_preflight_with_candidates(
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredArtifactDefinitionPreflight, JitCraneliftModuleSetupError> {
    let readiness =
        require_resolved_artifact_imports(jit_module_readiness_preflight_for_artifact(&artifact)?)?;
    let registration = jit_runtime_symbol_registration_preflight_with_candidates(candidates)?;
    require_registered_artifact_imports(&readiness, &registration)?;

    let symbol_name = module_symbol_name_for_artifact(readiness.artifact());
    let artifact_metadata = readiness.artifact().clone();
    let artifact_runtime_imports = readiness.artifact_runtime_imports().to_vec();
    let registration_gaps = registration.gaps().to_vec();
    let (mut module, registered_symbols, imported_symbols) =
        module_with_registered_and_imported_symbols(
            registration.bindings(),
            readiness.symbol_declarations(),
        )?;
    let defined_function =
        define_registered_artifact_function(&mut module, artifact, &imported_symbols, symbol_name)?;

    Ok(JitCraneliftRegisteredArtifactDefinitionPreflight::new(
        artifact_metadata,
        defined_function,
        imported_symbols,
        registered_symbols,
        artifact_runtime_imports,
        registration_gaps,
        module,
    ))
}

/// Registers explicit runtime symbols, defines one artifact body, and finalizes it.
///
/// The returned preflight composes the registered-symbol artifact-definition path
/// with [`JITModule::finalize_definitions`], returning a non-null opaque code
/// pointer for the finalized artifact body. Registered addresses may be used by
/// Cranelift relocation during finalization, but this path does not dereference
/// those addresses directly, cast the finalized code pointer, install tier
/// metadata, or call native code. Stable runtime symbols outside the artifact's
/// import set may remain registration gaps.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] if artifact readiness
/// metadata cannot be built or has unresolved runtime imports. Returns
/// [`JitCraneliftModuleSetupError::RuntimeSymbolRegistration`] if
/// runtime-symbol registration metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration`]
/// when the artifact imports a runtime symbol without matching native-address
/// registration metadata. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration. Returns
/// [`JitCraneliftModuleSetupError::DeclareArtifactFunction`] if Cranelift
/// rejects the artifact function declaration. Returns
/// [`JitCraneliftModuleSetupError::DefineArtifactFunction`] if Cranelift rejects
/// the artifact function definition. Returns
/// [`JitCraneliftModuleSetupError::FinalizeDefinitions`] if Cranelift cannot
/// finalize the module definitions. Returns
/// [`JitCraneliftModuleSetupError::FinalizedFunctionPointerNull`] if Cranelift
/// reports a null code pointer after successful finalization.
///
/// # Panics
///
/// Panics if Cranelift reports successful artifact definition and module
/// finalization but then fails its own invariant for looking up the finalized
/// function by [`FuncId`].
pub fn jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredArtifactFinalizationPreflight, JitCraneliftModuleSetupError> {
    let readiness =
        require_resolved_artifact_imports(jit_module_readiness_preflight_for_artifact(&artifact)?)?;
    let registration = jit_runtime_symbol_registration_preflight_with_candidates(candidates)?;
    require_registered_artifact_imports(&readiness, &registration)?;

    let symbol_name = module_symbol_name_for_artifact(readiness.artifact());
    let artifact_metadata = readiness.artifact().clone();
    let artifact_runtime_imports = readiness.artifact_runtime_imports().to_vec();
    let registration_gaps = registration.gaps().to_vec();
    let (mut module, registered_symbols, imported_symbols) =
        module_with_registered_and_imported_symbols(
            registration.bindings(),
            readiness.symbol_declarations(),
        )?;
    let defined_function =
        define_registered_artifact_function(&mut module, artifact, &imported_symbols, symbol_name)?;

    module.finalize_definitions().map_err(|source| {
        JitCraneliftModuleSetupError::FinalizeDefinitions {
            symbol_name: defined_function.symbol_name().to_owned(),
            source,
        }
    })?;
    let code_ptr = finalized_function_pointer(&module, &defined_function)?;
    let finalized_function = JitCraneliftFinalizedFunction::new(defined_function, code_ptr);

    Ok(JitCraneliftRegisteredArtifactFinalizationPreflight::new(
        artifact_metadata,
        finalized_function,
        imported_symbols,
        registered_symbols,
        artifact_runtime_imports,
        registration_gaps,
        module,
    ))
}

/// Builds a real JIT module and defines one verified CLIF artifact body.
///
/// The returned preflight owns a [`JITModule`] with callable builtin imports
/// declared, plus one artifact body declared as an exported function and passed
/// to Cranelift's definition API. Unshaped helper and value-only builtin gaps
/// are preserved. Artifacts with runtime imports are rejected by this
/// unregistered path and must use the registered-symbol definition path. A
/// successful definition lets Cranelift compile the body and allocate JIT code
/// memory inside the private module. The module is not finalized, no code
/// pointer is returned, and no native code is called.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] if runtime-symbol
/// readiness metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration. Returns
/// [`JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration`]
/// when the artifact body imports runtime helpers that the current path cannot
/// register. Returns
/// [`JitCraneliftModuleSetupError::DeclareArtifactFunction`] if Cranelift
/// rejects the artifact function declaration. Returns
/// [`JitCraneliftModuleSetupError::DefineArtifactFunction`] if Cranelift rejects
/// the artifact function definition.
pub fn jit_cranelift_artifact_definition_preflight_for_artifact(
    artifact: JitClifArtifact,
) -> Result<JitCraneliftArtifactDefinitionPreflight, JitCraneliftModuleSetupError> {
    let readiness = require_definition_ready_artifact_imports(
        jit_module_readiness_preflight_for_artifact(&artifact)?,
    )?;
    let symbol_name = module_symbol_name_for_artifact(readiness.artifact());
    let artifact_metadata = readiness.artifact().clone();
    let symbol_gaps = readiness.symbol_gaps().to_vec();
    let (mut module, imported_symbols) =
        module_with_imported_symbols(readiness.symbol_declarations())?;
    let defined_function = define_artifact_function(&mut module, artifact, symbol_name)?;

    Ok(JitCraneliftArtifactDefinitionPreflight::new(
        artifact_metadata,
        defined_function,
        imported_symbols,
        symbol_gaps,
        module,
    ))
}

/// Builds a real JIT module, defines one verified CLIF artifact, and finalizes it.
///
/// The returned preflight owns a [`JITModule`] with callable builtin imports,
/// one artifact body declared as an exported function, and finalized executable
/// memory for that body. The finalized code pointer is exposed only as opaque
/// metadata for later unsafe call-boundary work. This does not cast the code
/// pointer to a function pointer, call native code, or lower generic IR.
/// This unregistered API rejects call-bearing artifacts; those artifacts must
/// use the registered-symbol finalization path. Full native-call integration
/// still requires real exported wrappers and matching address registration for
/// every emitted runtime call.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] if runtime-symbol
/// readiness metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration. Returns
/// [`JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration`]
/// when the artifact body imports runtime helpers that the current path cannot
/// register. Returns
/// [`JitCraneliftModuleSetupError::DeclareArtifactFunction`] if Cranelift
/// rejects the artifact function declaration. Returns
/// [`JitCraneliftModuleSetupError::DefineArtifactFunction`] if Cranelift rejects
/// the artifact function definition. Returns
/// [`JitCraneliftModuleSetupError::FinalizeDefinitions`] if Cranelift cannot
/// finalize the module definitions. Returns
/// [`JitCraneliftModuleSetupError::FinalizedFunctionPointerNull`] if Cranelift
/// reports a null code pointer after successful finalization.
///
/// # Panics
///
/// Panics if Cranelift reports successful artifact definition and module
/// finalization but then fails its own invariant for looking up the finalized
/// function by [`FuncId`].
pub fn jit_cranelift_artifact_finalization_preflight_for_artifact(
    artifact: JitClifArtifact,
) -> Result<JitCraneliftArtifactFinalizationPreflight, JitCraneliftModuleSetupError> {
    let readiness = require_definition_ready_artifact_imports(
        jit_module_readiness_preflight_for_artifact(&artifact)?,
    )?;
    let symbol_name = module_symbol_name_for_artifact(readiness.artifact());
    let artifact_metadata = readiness.artifact().clone();
    let symbol_gaps = readiness.symbol_gaps().to_vec();
    let (mut module, imported_symbols) =
        module_with_imported_symbols(readiness.symbol_declarations())?;
    let defined_function = define_artifact_function(&mut module, artifact, symbol_name)?;

    module.finalize_definitions().map_err(|source| {
        JitCraneliftModuleSetupError::FinalizeDefinitions {
            symbol_name: defined_function.symbol_name().to_owned(),
            source,
        }
    })?;
    let code_ptr = finalized_function_pointer(&module, &defined_function)?;
    let finalized_function = JitCraneliftFinalizedFunction::new(defined_function, code_ptr);

    Ok(JitCraneliftArtifactFinalizationPreflight::new(
        artifact_metadata,
        finalized_function,
        imported_symbols,
        symbol_gaps,
        module,
    ))
}

/// Finalizes one thunk artifact and calls it through the native thunk ABI.
///
/// This is the first bounded native-call path for the Cranelift tier. It is
/// intended for currently supported no-import thunk artifacts, such as constant
/// smoke bodies and literal Core-IR roots. The call uses null runtime-context
/// and environment-frame pointers because those lowerers ignore both entry
/// parameters. The returned invocation owns the finalization preflight so the
/// backing [`JITModule`] remains alive for inspection after the call.
///
/// This function does not publish the code pointer into evaluator thunk state,
/// perform an atomic thunk-state transition, call registered runtime helpers, or
/// support artifacts that import runtime symbols.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError::FinalizeArtifact`] when the artifact
/// cannot be finalized, including the current registered-symbol requirement for
/// runtime-importing artifacts. Returns
/// [`JitCraneliftNativeCallError::UnsupportedNativeValueAbi`] when the current
/// host has no reviewed by-value [`Value`] ABI parity with the two-word CLIF
/// lowering. Returns
/// [`JitCraneliftNativeCallError::UnsupportedArtifactKind`] when the finalized
/// artifact metadata is not a thunk body. Returns
/// [`JitCraneliftNativeCallError::InvalidReturnValue`] when the native thunk
/// returns a valid-tag [`Value`] whose payload bits violate the runtime layout.
///
/// # Panics
///
/// Panics under the same Cranelift unresolved-import and finalized-function
/// lookup conditions as [`jit_cranelift_artifact_finalization_preflight_for_artifact`].
pub fn jit_cranelift_native_thunk_call_for_artifact(
    artifact: JitClifArtifact,
) -> Result<JitCraneliftNativeThunkInvocation, JitCraneliftNativeCallError> {
    require_supported_native_value_abi()?;

    let finalization = jit_cranelift_artifact_finalization_preflight_for_artifact(artifact)
        .map_err(|source| JitCraneliftNativeCallError::FinalizeArtifact { source })?;

    if finalization.artifact().kind() != JitClifArtifactKind::ThunkBody {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactKind {
            kind: finalization.artifact().kind(),
        });
    }

    let thunk_entry = thunk_entry_from_finalized_code(finalization.finalized_function().code_ptr());
    // SAFETY: The artifact was produced by this crate's thunk-body lowerers,
    // verified with the frozen thunk CLIF signature, finalized by Cranelift,
    // and kept alive by `finalization`. The current no-import lowerers used by
    // this path do not dereference the runtime or environment pointers.
    let value = unsafe { thunk_entry(ptr::null_mut(), ptr::null_mut()) };
    value
        .validate_payload()
        .map_err(|source| JitCraneliftNativeCallError::InvalidReturnValue {
            symbol_name: finalization.finalized_function().symbol_name().to_owned(),
            value,
            source,
        })?;

    Ok(JitCraneliftNativeThunkInvocation::new(finalization, value))
}

/// Finalizes one registered thunk artifact and calls it through the native thunk ABI.
///
/// This is the bounded native-call path for artifacts that import runtime
/// helpers, such as the current local environment-slot and forced environment
/// precursors. It composes explicit native-address candidates with the
/// registered finalization path, then calls the finalized thunk entry while
/// keeping the backing [`JITModule`] alive in the returned invocation.
///
/// This function does not publish the code pointer into evaluator thunk state,
/// perform an atomic thunk-state transition, or validate that supplied helper
/// addresses came from exported AOS runtime wrappers. It only checks that
/// candidate symbol names and kinds match JIT declaration metadata before those
/// addresses are registered with Cranelift.
///
/// # Safety
///
/// Every native-address candidate that can be called by `artifact` must point to
/// a live function with the exact frozen `extern "C"` ABI for its runtime
/// symbol, and it must remain valid until the returned invocation is dropped.
/// `rt` and `env` must be valid for the compiled thunk body and for every helper
/// candidate the body can call. Candidate functions must not unwind across the C
/// ABI boundary. Every compiled body and candidate return path must produce a
/// valid [`Value`] tag; payload-layout violations can be reported as
/// [`JitCraneliftNativeCallError::InvalidReturnValue`], but invalid enum
/// discriminants cannot be materialized safely after crossing back into Rust.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError::FinalizeArtifact`] when the artifact
/// cannot be finalized through the registered-symbol path, including missing or
/// wrong-kind candidates for artifact imports. Returns
/// [`JitCraneliftNativeCallError::UnsupportedNativeValueAbi`] when the current
/// host has no reviewed by-value [`Value`] ABI parity with the two-word CLIF
/// lowering. Returns
/// [`JitCraneliftNativeCallError::UnsupportedArtifactKind`] when the finalized
/// artifact metadata is not a thunk body. Returns
/// [`JitCraneliftNativeCallError::InvalidReturnValue`] when the native thunk
/// returns a valid-tag [`Value`] whose payload bits violate the runtime layout.
///
/// # Panics
///
/// Panics under the same Cranelift unresolved-import and finalized-function
/// lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`].
pub unsafe fn jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
) -> Result<JitCraneliftRegisteredNativeThunkInvocation, JitCraneliftNativeCallError> {
    require_supported_native_value_abi()?;

    let finalization = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        artifact, candidates,
    )
    .map_err(|source| JitCraneliftNativeCallError::FinalizeArtifact { source })?;

    if finalization.artifact().kind() != JitClifArtifactKind::ThunkBody {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactKind {
            kind: finalization.artifact().kind(),
        });
    }

    let thunk_entry = thunk_entry_from_finalized_code(finalization.finalized_function().code_ptr());
    // SAFETY: The caller guarantees that registered helper candidates and the
    // runtime/environment pointers satisfy the frozen native ABI for this
    // artifact. The artifact body was produced by this crate's thunk lowerers,
    // verified with the frozen thunk CLIF signature, finalized by Cranelift, and
    // kept alive by `finalization`.
    let value = unsafe { thunk_entry(rt, env) };
    value
        .validate_payload()
        .map_err(|source| JitCraneliftNativeCallError::InvalidReturnValue {
            symbol_name: finalization.finalized_function().symbol_name().to_owned(),
            value,
            source,
        })?;

    Ok(JitCraneliftRegisteredNativeThunkInvocation::new(
        finalization,
        value,
    ))
}

/// Finalizes one artifact and installs its pointer into owned tier-1 slot metadata.
///
/// The returned preflight keeps the `JITModule` owner and the safe
/// [`JitTieredCodeSlot`] in the same value. The slot's code pointer is still
/// metadata only: this does not publish into an evaluator heap thunk, cast the
/// pointer to a function type, call native code, or lower generic IR.
///
/// # Errors
///
/// Returns any error from
/// [`jit_cranelift_artifact_finalization_preflight_for_artifact`]. Returns
/// [`JitCraneliftModuleSetupError::InstallTier1Code`] if the finalized pointer
/// metadata cannot be installed into the fresh slot.
///
/// # Panics
///
/// Panics under the same Cranelift unresolved-import and finalized-function
/// lookup conditions as [`jit_cranelift_artifact_finalization_preflight_for_artifact`].
pub fn jit_cranelift_tier1_slot_preflight_for_artifact(
    artifact: JitClifArtifact,
) -> Result<JitCraneliftTier1SlotPreflight, JitCraneliftModuleSetupError> {
    let finalization = jit_cranelift_artifact_finalization_preflight_for_artifact(artifact)?;
    tier1_slot_preflight_from_finalization(finalization, JitTieredCodeSlot::new())
}

fn thunk_entry_from_finalized_code(code_ptr: NonNull<u8>) -> JitThunkFn {
    // SAFETY: Cranelift returned this pointer for a function defined with the
    // frozen thunk signature lowered from `ratchet-core` metadata. The caller
    // validates the artifact kind and keeps the owning `JITModule` alive while
    // the returned entry is called.
    let entry = unsafe { mem::transmute::<*mut u8, JitThunkFn>(code_ptr.as_ptr()) };
    entry
}

/// Finalizes one registered artifact and installs it into owned tier-1 metadata.
///
/// The returned preflight composes
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`]
/// with safe [`JitTieredCodeSlot`] installation. Registered addresses may be used
/// by Cranelift relocation during finalization, but this path does not
/// dereference or call those addresses, publish into evaluator heap thunk state,
/// cast the finalized code pointer, or call native code. Stable runtime symbols
/// outside the artifact's import set may remain registration gaps.
///
/// # Errors
///
/// Returns any error from
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`].
/// Returns [`JitCraneliftModuleSetupError::InstallTier1Code`] if the finalized
/// pointer metadata cannot be installed into the fresh slot.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`].
pub fn jit_cranelift_registered_tier1_slot_preflight_with_candidates(
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredTier1SlotPreflight, JitCraneliftModuleSetupError> {
    let finalization = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        artifact, candidates,
    )?;
    registered_tier1_slot_preflight_from_finalization(finalization, JitTieredCodeSlot::new())
}

/// Records one invocation and compiles a supported IR root only when policy promotes.
///
/// This is the first safe compile-on-hotness composition point. It records one
/// invocation in `slot`, asks `policy` whether tier 1 should be selected, and
/// lowers/finalizes `root` only when the resulting [`TierUpDecision`] requests
/// promotion. Promoted results keep the finalized `JITModule` owner beside the
/// installed slot metadata. Non-promoted results return the updated slot without
/// lowering, module construction, finalization, or pointer installation.
///
/// # Errors
///
/// Returns [`JitCraneliftTier1PromotionError`] if policy requests promotion but
/// the current literal-only lowerer cannot lower `root`, or if artifact
/// finalization or tier-slot installation fails. The error preserves the
/// invocation-updated slot and the policy decision alongside the underlying
/// setup error.
///
/// # Panics
///
/// Panics under the same Cranelift unresolved-import and finalized-function
/// lookup conditions as [`jit_cranelift_artifact_finalization_preflight_for_artifact`]
/// when policy requests promotion.
pub fn jit_cranelift_tier1_promotion_preflight_for_ir_root(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
) -> Result<JitCraneliftTier1PromotionPreflight, JitCraneliftTier1PromotionError> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftTier1PromotionPreflight::StayedInTier { slot, decision });
    }

    let artifact = match lower_constant_ir_thunk_body_artifact(arena, root) {
        Ok(artifact) => artifact,
        Err(source) => {
            return Err(JitCraneliftTier1PromotionError::new(
                slot,
                decision,
                JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
            ));
        }
    };
    let finalization = match jit_cranelift_artifact_finalization_preflight_for_artifact(artifact) {
        Ok(finalization) => finalization,
        Err(source) => return Err(JitCraneliftTier1PromotionError::new(slot, decision, source)),
    };
    let preflight = tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
        .map_err(|(slot, source)| JitCraneliftTier1PromotionError::new(slot, decision, source))?;

    Ok(JitCraneliftTier1PromotionPreflight::Promoted {
        preflight,
        decision,
    })
}

/// Records one invocation and compiles a supported registered IR root on promotion.
///
/// This composes tier-up policy with the registered-symbol tier-1 slot path. It
/// supports the current literal roots, local environment-slot roots that lower
/// to `aos_env_get` runtime calls, and direct local-slot application roots that
/// lower to `aos_env_get` plus `aos_apply` runtime calls. Non-promoted results
/// return the updated slot without lowering, module construction, finalization,
/// or pointer installation.
///
/// # Errors
///
/// Returns [`JitCraneliftTier1PromotionError`] if policy requests promotion but
/// the current registered lowerer cannot lower `root`, if required artifact
/// runtime imports lack matching candidates, or if finalization or tier-slot
/// installation fails. The error preserves the invocation-updated slot and the
/// policy decision alongside the underlying setup error.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`]
/// when policy requests promotion.
pub fn jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredTier1PromotionPreflight, JitCraneliftTier1PromotionError> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftRegisteredTier1PromotionPreflight::StayedInTier { slot, decision });
    }

    let artifact = match lower_tier1_ir_thunk_body_artifact(arena, root) {
        Ok(artifact) => artifact,
        Err(source) => {
            return Err(JitCraneliftTier1PromotionError::new(
                slot,
                decision,
                JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
            ));
        }
    };
    let finalization =
        match jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            artifact, candidates,
        ) {
            Ok(finalization) => finalization,
            Err(source) => {
                return Err(JitCraneliftTier1PromotionError::new(slot, decision, source));
            }
        };
    let preflight =
        registered_tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
            .map_err(|(slot, source)| {
                JitCraneliftTier1PromotionError::new(slot, decision, source)
            })?;

    Ok(JitCraneliftRegisteredTier1PromotionPreflight::Promoted {
        preflight,
        decision,
    })
}

/// Records one invocation and compiles a force-aware registered IR root on promotion.
///
/// This composes tier-up policy with the registered-symbol tier-1 slot path, but
/// uses the force-call lowerer for local environment-slot roots. Literal roots
/// still lower through the constant path, and direct local-slot application
/// roots still lower through the `aos_apply` helper because apply owns the
/// function-call forcing boundary. Local-slot roots can finalize when the
/// candidate set contains both `aos_env_get` and `aos_force`; direct local-slot
/// application roots can finalize when the candidate set contains both
/// `aos_env_get` and `aos_apply`. Successful promotions install the resulting
/// opaque code pointer into owned tier-1 slot metadata.
///
/// Non-promoted results return the updated slot without lowering, module
/// construction, finalization, or pointer installation.
///
/// # Errors
///
/// Returns [`JitCraneliftTier1PromotionError`] if policy requests promotion but
/// the current force-aware lowerer cannot lower `root`, if required artifact
/// runtime imports lack matching candidates, or if finalization or tier-slot
/// installation fails. The error preserves the invocation-updated slot and the
/// policy decision alongside the underlying setup error.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`]
/// when policy requests promotion and Cranelift finalizes an artifact.
pub fn jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredTier1PromotionPreflight, JitCraneliftTier1PromotionError> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftRegisteredTier1PromotionPreflight::StayedInTier { slot, decision });
    }

    let artifact = match lower_force_aware_tier1_ir_thunk_body_artifact(arena, root) {
        Ok(artifact) => artifact,
        Err(source) => {
            return Err(JitCraneliftTier1PromotionError::new(
                slot,
                decision,
                JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
            ));
        }
    };
    let finalization =
        match jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            artifact, candidates,
        ) {
            Ok(finalization) => finalization,
            Err(source) => {
                return Err(JitCraneliftTier1PromotionError::new(slot, decision, source));
            }
        };
    let preflight =
        registered_tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
            .map_err(|(slot, source)| {
                JitCraneliftTier1PromotionError::new(slot, decision, source)
            })?;

    Ok(JitCraneliftRegisteredTier1PromotionPreflight::Promoted {
        preflight,
        decision,
    })
}

/// Records one invocation, compiles a force-aware registered IR root, and calls it on promotion.
///
/// This is the first promotion-gated native execution composition point. It
/// records one invocation in `slot`, asks `policy` whether tier 1 should be
/// selected, and only when promotion is requested lowers a currently supported
/// force-aware registered IR root, finalizes it with explicit native-address
/// candidates, calls the resulting thunk entry, and installs the finalized code
/// pointer into the updated slot metadata.
///
/// Non-promoted results return the updated slot without lowering, requiring
/// candidates, constructing a module, finalizing code, or crossing the native
/// call boundary. This function does not publish into evaluator thunk state or
/// perform atomic thunk-state transitions.
///
/// # Safety
///
/// The caller must either prove this attempt cannot promote, or uphold the same
/// candidate, runtime/environment pointer, host ABI, non-unwinding, and valid
/// returned-tag requirements as
/// [`jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`]
/// for any path that may promote and enter native code.
///
/// # Errors
///
/// Returns [`JitCraneliftRegisteredTier1NativeCallError`] if policy requests
/// promotion but the current force-aware lowerer cannot lower `root`, required
/// artifact runtime imports lack matching candidates, the host native `Value`
/// ABI is not supported, finalization or native invocation fails, the returned
/// valid-tag value has an invalid payload, or tier-slot metadata installation
/// fails. The error preserves the invocation-updated slot and the policy
/// decision alongside the underlying native-call error.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`]
/// when policy requests promotion and Cranelift finalizes an artifact.
pub unsafe fn jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    candidates: &[JitRuntimeSymbolAddressCandidate],
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
) -> Result<
    JitCraneliftRegisteredTier1NativeCallPreflight,
    JitCraneliftRegisteredTier1NativeCallError,
> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftRegisteredTier1NativeCallPreflight::StayedInTier { slot, decision });
    }

    let artifact =
        lower_force_aware_tier1_ir_thunk_body_artifact(arena, root).map_err(|source| {
            JitCraneliftRegisteredTier1NativeCallError::new(
                slot.clone(),
                decision,
                JitCraneliftNativeCallError::FinalizeArtifact {
                    source: JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
                },
            )
        })?;
    // SAFETY: This function forwards its caller's native-address, runtime,
    // environment, host-ABI, non-unwinding, and valid returned-tag obligations
    // to the registered native thunk-call boundary.
    let promotion_gated_registered_native_thunk_invocation = unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact, candidates, rt, env,
        )
    }
    .map_err(|source| {
        JitCraneliftRegisteredTier1NativeCallError::new(slot.clone(), decision, source)
    })?;

    let code_ptr = promotion_gated_registered_native_thunk_invocation
        .finalized_function()
        .compiled_code_ptr();
    if let Err(source) = slot.install_tier1_code(code_ptr) {
        return Err(JitCraneliftRegisteredTier1NativeCallError::new(
            slot,
            decision,
            JitCraneliftNativeCallError::FinalizeArtifact {
                source: JitCraneliftModuleSetupError::InstallTier1Code {
                    symbol_name: promotion_gated_registered_native_thunk_invocation
                        .finalized_function()
                        .symbol_name()
                        .to_owned(),
                    source,
                },
            },
        ));
    }

    Ok(
        JitCraneliftRegisteredTier1NativeCallPreflight::PromotedAndCalled {
            slot,
            invocation: promotion_gated_registered_native_thunk_invocation,
            decision,
        },
    )
}

/// Builds a complete JIT module setup for `artifact`.
///
/// This strict gate only succeeds once runtime-symbol readiness is complete.
/// In the current implementation it returns a readiness error because unshaped
/// helper symbols and value-only builtins still have declaration gaps.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] while runtime-symbol
/// declaration gaps remain or if readiness metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration.
pub fn jit_cranelift_module_setup_for_artifact(
    artifact: &JitClifArtifact,
) -> Result<JitCraneliftModuleSetup, JitCraneliftModuleSetupError> {
    let readiness = jit_module_readiness_preflight_for_artifact(artifact)?;
    let plan = JitModuleReadinessPlan::from_preflight(readiness)?;
    jit_cranelift_module_setup_for_plan(&plan)
}

/// Builds a complete JIT module setup from a checked readiness plan.
///
/// The returned setup owns a [`JITModule`] whose runtime-symbol imports have
/// been declared but not bound to executable addresses.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift
/// cannot build an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration.
pub fn jit_cranelift_module_setup_for_plan(
    plan: &JitModuleReadinessPlan,
) -> Result<JitCraneliftModuleSetup, JitCraneliftModuleSetupError> {
    let (module, imported_symbols) = module_with_imported_symbols(plan.symbol_declarations())?;

    Ok(JitCraneliftModuleSetup::new(
        plan.artifact().clone(),
        imported_symbols,
        module,
    ))
}

fn require_definition_ready_artifact_imports(
    readiness: JitModuleReadinessPreflight,
) -> Result<JitModuleReadinessPreflight, JitCraneliftModuleSetupError> {
    let readiness = require_resolved_artifact_imports(readiness)?;

    let symbol_names = readiness
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name().to_owned())
        .collect::<Vec<_>>();

    if symbol_names.is_empty() {
        Ok(readiness)
    } else {
        Err(
            JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
                symbol_names,
            },
        )
    }
}

fn require_resolved_artifact_imports(
    readiness: JitModuleReadinessPreflight,
) -> Result<JitModuleReadinessPreflight, JitCraneliftModuleSetupError> {
    if !readiness.artifact_runtime_import_gaps().is_empty() {
        return Err(JitCraneliftModuleSetupError::Readiness(
            JitModuleReadinessError::UnresolvedArtifactRuntimeImports {
                preflight: readiness,
            },
        ));
    }

    Ok(readiness)
}

fn require_registered_artifact_imports(
    readiness: &JitModuleReadinessPreflight,
    registration: &crate::symbols::JitRuntimeSymbolRegistrationPreflight,
) -> Result<(), JitCraneliftModuleSetupError> {
    let missing_symbol_names = readiness
        .artifact_runtime_imports()
        .iter()
        .filter(|artifact_import| {
            registration
                .binding_for_symbol(artifact_import.symbol_name())
                .is_none()
        })
        .map(|artifact_import| artifact_import.symbol_name().to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if missing_symbol_names.is_empty() {
        Ok(())
    } else {
        Err(
            JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
                symbol_names: missing_symbol_names,
            },
        )
    }
}

fn module_with_imported_symbols(
    declarations: &[JitRuntimeSymbolDeclaration],
) -> Result<(JITModule, Vec<JitCraneliftImportedSymbol>), JitCraneliftModuleSetupError> {
    let builder = native_jit_builder()?;
    let mut module = JITModule::new(builder);
    let imported_symbols = declare_imported_symbols(&mut module, declarations)?;

    Ok((module, imported_symbols))
}

fn module_with_registered_symbols(
    bindings: &[JitRuntimeSymbolRegistrationBinding],
) -> Result<(JITModule, Vec<JitCraneliftRegisteredSymbol>), JitCraneliftModuleSetupError> {
    let mut builder = native_jit_builder()?;
    let mut registered_symbols = Vec::with_capacity(bindings.len());

    for binding in bindings {
        builder.symbol(
            binding.symbol_name(),
            ptr::with_exposed_provenance::<u8>(binding.address().as_nonzero_usize().get()),
        );
        registered_symbols.push(JitCraneliftRegisteredSymbol::new(
            binding.symbol_name().to_owned(),
            binding.address(),
        ));
    }

    Ok((JITModule::new(builder), registered_symbols))
}

fn module_with_registered_and_imported_symbols(
    bindings: &[JitRuntimeSymbolRegistrationBinding],
    declarations: &[JitRuntimeSymbolDeclaration],
) -> Result<
    (
        JITModule,
        Vec<JitCraneliftRegisteredSymbol>,
        Vec<JitCraneliftImportedSymbol>,
    ),
    JitCraneliftModuleSetupError,
> {
    let mut builder = native_jit_builder()?;
    let mut registered_symbols = Vec::with_capacity(bindings.len());

    for binding in bindings {
        builder.symbol(
            binding.symbol_name(),
            ptr::with_exposed_provenance::<u8>(binding.address().as_nonzero_usize().get()),
        );
        registered_symbols.push(JitCraneliftRegisteredSymbol::new(
            binding.symbol_name().to_owned(),
            binding.address(),
        ));
    }

    let mut module = JITModule::new(builder);
    let imported_symbols = declare_imported_symbols(&mut module, declarations)?;

    Ok((module, registered_symbols, imported_symbols))
}

fn declare_imported_symbols(
    module: &mut JITModule,
    declarations: &[JitRuntimeSymbolDeclaration],
) -> Result<Vec<JitCraneliftImportedSymbol>, JitCraneliftModuleSetupError> {
    let mut imported_symbols = Vec::with_capacity(declarations.len());

    for declaration in declarations {
        let func_id = module
            .declare_function(
                declaration.symbol_name(),
                Linkage::Import,
                declaration.signature(),
            )
            .map_err(
                |source| JitCraneliftModuleSetupError::DeclareRuntimeSymbol {
                    symbol_name: declaration.symbol_name().to_owned(),
                    source,
                },
            )?;
        imported_symbols.push(JitCraneliftImportedSymbol::new(
            declaration.symbol_name().to_owned(),
            Linkage::Import,
            func_id,
        ));
    }

    Ok(imported_symbols)
}

fn define_artifact_function(
    module: &mut JITModule,
    artifact: JitClifArtifact,
    symbol_name: String,
) -> Result<JitCraneliftDefinedFunction, JitCraneliftModuleSetupError> {
    let function = artifact.into_function();
    define_artifact_function_body(module, function, symbol_name)
}

fn define_registered_artifact_function(
    module: &mut JITModule,
    artifact: JitClifArtifact,
    imported_symbols: &[JitCraneliftImportedSymbol],
    symbol_name: String,
) -> Result<JitCraneliftDefinedFunction, JitCraneliftModuleSetupError> {
    let mut function = artifact.into_function();
    rewrite_artifact_runtime_imports_for_module(&mut function, imported_symbols);
    define_artifact_function_body(module, function, symbol_name)
}

fn define_artifact_function_body(
    module: &mut JITModule,
    function: Function,
    symbol_name: String,
) -> Result<JitCraneliftDefinedFunction, JitCraneliftModuleSetupError> {
    let func_id = module
        .declare_function(&symbol_name, Linkage::Export, &function.signature)
        .map_err(
            |source| JitCraneliftModuleSetupError::DeclareArtifactFunction {
                symbol_name: symbol_name.clone(),
                source,
            },
        )?;
    let mut context = Context::for_function(function);
    module
        .define_function(func_id, &mut context)
        .map_err(
            |source| JitCraneliftModuleSetupError::DefineArtifactFunction {
                symbol_name: symbol_name.clone(),
                source,
            },
        )?;

    Ok(JitCraneliftDefinedFunction::new(
        symbol_name,
        Linkage::Export,
        func_id,
    ))
}

fn rewrite_artifact_runtime_imports_for_module(
    function: &mut Function,
    imported_symbols: &[JitCraneliftImportedSymbol],
) {
    let module_func_ids = imported_symbols
        .iter()
        .map(|symbol| (symbol.symbol_name(), symbol.func_id()))
        .collect::<BTreeMap<_, _>>();
    let runtime_import_func_ids = function
        .dfg
        .ext_funcs
        .iter()
        .filter_map(|(func_ref, import)| {
            let ExternalName::User(user_name_ref) = import.name else {
                return None;
            };
            let user_external_name = function.params.user_named_funcs().get(user_name_ref)?;
            let symbol_name = runtime_symbol_name_for_user_external_name(user_external_name)?;
            let func_id = module_func_ids.get(symbol_name)?;
            Some((func_ref, *func_id))
        })
        .collect::<Vec<_>>();

    for (func_ref, func_id) in runtime_import_func_ids {
        let user_name_ref =
            function.declare_imported_user_function(UserExternalName::new(0, func_id.as_u32()));
        if let Some(import) = function.dfg.ext_funcs.get_mut(func_ref) {
            import.name = ExternalName::user(user_name_ref);
        }
    }
}

fn runtime_symbol_name_for_user_external_name(
    user_external_name: &UserExternalName,
) -> Option<&'static str> {
    match (user_external_name.namespace, user_external_name.index) {
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_ENV_GET_FUNCTION_INDEX,
        ) => Some("aos_env_get"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_FORCE_FUNCTION_INDEX,
        ) => Some("aos_force"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_APPLY_FUNCTION_INDEX,
        ) => Some("aos_apply"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_HAS_ATTR_FUNCTION_INDEX,
        ) => Some("aos_has_attr"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_SELECT_IC_FUNCTION_INDEX,
        ) => Some("aos_select_ic"),
        _ => None,
    }
}

fn finalized_function_pointer(
    module: &JITModule,
    function: &JitCraneliftDefinedFunction,
) -> Result<NonNull<u8>, JitCraneliftModuleSetupError> {
    NonNull::new(module.get_finalized_function(function.func_id()) as *mut u8).ok_or_else(|| {
        JitCraneliftModuleSetupError::FinalizedFunctionPointerNull {
            symbol_name: function.symbol_name().to_owned(),
        }
    })
}

fn tier1_slot_preflight_from_finalization(
    finalization: JitCraneliftArtifactFinalizationPreflight,
    slot: JitTieredCodeSlot,
) -> Result<JitCraneliftTier1SlotPreflight, JitCraneliftModuleSetupError> {
    tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
        .map_err(|(_slot, error)| error)
}

fn tier1_slot_preflight_from_finalization_preserving_slot(
    finalization: JitCraneliftArtifactFinalizationPreflight,
    mut slot: JitTieredCodeSlot,
) -> Result<JitCraneliftTier1SlotPreflight, (JitTieredCodeSlot, JitCraneliftModuleSetupError)> {
    let symbol_name = finalization.finalized_function().symbol_name().to_owned();
    let code_ptr = finalization.finalized_function().compiled_code_ptr();

    if let Err(source) = slot.install_tier1_code(code_ptr) {
        return Err((
            slot,
            JitCraneliftModuleSetupError::InstallTier1Code {
                symbol_name,
                source,
            },
        ));
    }

    Ok(JitCraneliftTier1SlotPreflight::new(finalization, slot))
}

fn registered_tier1_slot_preflight_from_finalization(
    finalization: JitCraneliftRegisteredArtifactFinalizationPreflight,
    slot: JitTieredCodeSlot,
) -> Result<JitCraneliftRegisteredTier1SlotPreflight, JitCraneliftModuleSetupError> {
    registered_tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
        .map_err(|(_slot, error)| error)
}

fn registered_tier1_slot_preflight_from_finalization_preserving_slot(
    finalization: JitCraneliftRegisteredArtifactFinalizationPreflight,
    mut slot: JitTieredCodeSlot,
) -> Result<
    JitCraneliftRegisteredTier1SlotPreflight,
    (JitTieredCodeSlot, JitCraneliftModuleSetupError),
> {
    let symbol_name = finalization.finalized_function().symbol_name().to_owned();
    let code_ptr = finalization.finalized_function().compiled_code_ptr();

    if let Err(source) = slot.install_tier1_code(code_ptr) {
        return Err((
            slot,
            JitCraneliftModuleSetupError::InstallTier1Code {
                symbol_name,
                source,
            },
        ));
    }

    Ok(JitCraneliftRegisteredTier1SlotPreflight::new(
        finalization,
        slot,
    ))
}

fn module_symbol_name_for_artifact(artifact: &JitModuleArtifactMetadata) -> String {
    let kind = match artifact.kind() {
        JitClifArtifactKind::ThunkBody => "thunk_body",
    };
    match artifact.source() {
        JitClifArtifactSource::ConstantSmoke => format!("aos.jit.constant_smoke.{kind}"),
        JitClifArtifactSource::IrRoot(root) => {
            format!("aos.jit.ir_root.{}.{kind}", root.as_u32())
        }
    }
}

fn require_supported_native_value_abi() -> Result<(), JitCraneliftNativeCallError> {
    if cfg!(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    )) {
        Ok(())
    } else {
        Err(JitCraneliftNativeCallError::UnsupportedNativeValueAbi {
            message: "native thunk calls require a reviewed by-value Value ABI on this host",
        })
    }
}

fn native_jit_builder() -> Result<JITBuilder, JitCraneliftModuleSetupError> {
    let mut flag_builder = settings::builder();
    flag_builder.set("use_colocated_libcalls", "false")?;
    flag_builder.set("is_pic", "false")?;
    let isa_builder = cranelift_native::builder()
        .map_err(|message| JitCraneliftModuleSetupError::UnsupportedHost { message })?;
    let isa = isa_builder.finish(settings::Flags::new(flag_builder))?;
    Ok(JITBuilder::with_isa(
        isa,
        cranelift_module::default_libcall_names(),
    ))
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, ptr::NonNull};

    use cranelift_codegen::ir::{
        ExtFuncData, ExternalName, Function, UserExternalName, UserFuncName,
    };
    use ratchet_core::syntax::Span;
    use ratchet_core::{
        EffectClass, IrArena, IrData, IrId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
        runtime_helper_call_signature, runtime_thunk_call_signature,
    };
    use ratchet_value::value::Value;

    use super::*;
    use crate::{
        abi::clif_signature_for_runtime_call,
        lower::{
            AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, clif_name_for_ir_root,
            lower_apply_local_slots_ir_thunk_body_artifact, lower_constant_ir_thunk_body_artifact,
            lower_constant_thunk_body_artifact, lower_env_get_ir_thunk_body_artifact,
            lower_forced_env_get_ir_thunk_body_artifact,
        },
        module::{JitModuleReadinessError, jit_module_readiness_preflight_for_artifact},
        tier::{DEFAULT_TIER1_INVOCATION_THRESHOLD, JitTier, TierUpCounter, TierUpReasons},
    };

    fn synthetic_address(raw: usize) -> JitRuntimeSymbolAddress {
        JitRuntimeSymbolAddress::new(NonZeroUsize::new(raw).expect("test address is non-zero"))
    }

    fn synthetic_address_candidate(
        symbol_name: &str,
        kind: RuntimeSymbolKind,
        raw: usize,
    ) -> JitRuntimeSymbolAddressCandidate {
        JitRuntimeSymbolAddressCandidate::new(symbol_name.to_owned(), kind, synthetic_address(raw))
    }

    fn synthetic_runtime_import_target() {}

    fn synthetic_runtime_import_address() -> usize {
        synthetic_runtime_import_target as *const () as usize
    }

    fn env_get_artifact(slot: u32) -> JitClifArtifact {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot },
            )],
            Vec::new(),
        );

        lower_env_get_ir_thunk_body_artifact(&arena, IrId::new(0)).expect("env-get artifact lowers")
    }

    fn forced_env_get_artifact(slot: u32) -> JitClifArtifact {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot },
            )],
            Vec::new(),
        );

        lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
            .expect("forced env-get artifact lowers")
    }

    fn apply_artifact(function_slot: u32, argument_slot: u32) -> JitClifArtifact {
        let arena = apply_arena(function_slot, argument_slot);

        lower_apply_local_slots_ir_thunk_body_artifact(&arena, IrId::new(2))
            .expect("apply artifact lowers")
    }

    fn apply_arena(function_slot: u32, argument_slot: u32) -> IrArena {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Local {
                        slot: function_slot,
                    },
                ),
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(2, 3),
                    EffectClass::pure(),
                    IrData::Local {
                        slot: argument_slot,
                    },
                ),
                IrNode::new(
                    IrKind::Apply,
                    Span::new(0, 3),
                    EffectClass::pure(),
                    IrData::Pair {
                        first: IrId::new(0),
                        second: IrId::new(1),
                    },
                ),
            ],
            Vec::new(),
        );

        arena
    }

    fn wrapped_apply_arena(function_slot: u32, argument_slot: u32) -> IrArena {
        IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Local {
                        slot: function_slot,
                    },
                ),
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(2, 3),
                    EffectClass::pure(),
                    IrData::Local {
                        slot: argument_slot,
                    },
                ),
                IrNode::new(
                    IrKind::Apply,
                    Span::new(0, 3),
                    EffectClass::pure(),
                    IrData::Pair {
                        first: IrId::new(0),
                        second: IrId::new(1),
                    },
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 3),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(2)),
                ),
            ],
            Vec::new(),
        )
    }

    fn artifact_with_unknown_runtime_helper_import() -> JitClifArtifact {
        let mut function = Function::with_name_signature(
            UserFuncName::default(),
            clif_signature_for_runtime_call(runtime_thunk_call_signature())
                .expect("thunk signature lowers"),
        );
        let env_get_signature = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_env_get")
                .expect("env-get helper signature is core-owned"),
        )
        .expect("env-get signature lowers");
        let signature_ref = function.import_signature(env_get_signature);
        let user_name = function.declare_imported_user_function(UserExternalName::new(
            AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            99,
        ));
        function.import_function(ExtFuncData {
            name: ExternalName::user(user_name),
            signature: signature_ref,
            colocated: false,
        });

        JitClifArtifact::new(
            JitTier::Tier1Baseline,
            JitClifArtifactKind::ThunkBody,
            JitClifArtifactSource::ConstantSmoke,
            function,
        )
    }

    #[test]
    fn active_cranelift_versions_match_pin() {
        assert_eq!(
            ACTIVE_CRANELIFT_CODEGEN_VERSION,
            PINNED_CRANELIFT_CODEGEN_VERSION
        );
        assert_eq!(ACTIVE_CRANELIFT_JIT_VERSION, PINNED_CRANELIFT_JIT_VERSION);
        assert_eq!(
            ACTIVE_CRANELIFT_MODULE_VERSION,
            PINNED_CRANELIFT_MODULE_VERSION
        );
        assert_eq!(
            ACTIVE_CRANELIFT_NATIVE_VERSION,
            PINNED_CRANELIFT_NATIVE_VERSION
        );
    }

    #[test]
    fn dependency_pin_exposes_exact_cranelift_versions() {
        let pin = jit_cranelift_dependency_pin();

        assert_eq!(pin.codegen_version(), PINNED_CRANELIFT_CODEGEN_VERSION);
        assert_eq!(pin.jit_version(), PINNED_CRANELIFT_JIT_VERSION);
        assert_eq!(pin.module_version(), PINNED_CRANELIFT_MODULE_VERSION);
        assert_eq!(pin.native_version(), PINNED_CRANELIFT_NATIVE_VERSION);
    }

    #[test]
    fn symbol_registration_preflight_builds_module_without_default_registrations() {
        let preflight = jit_cranelift_symbol_registration_preflight_with_candidates(&[])
            .expect("JIT symbol registration preflight builds");

        assert!(preflight.registered_symbols().is_empty());
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
        assert!(matches!(
            preflight.gap_for_symbol("aos_alloc_attrs"),
            Some(
                crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                    kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
                    ..
                }
            )
        ));
        assert!(matches!(
            preflight.gap_for_symbol("aos_force"),
            Some(
                crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                    kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                    ..
                }
            )
        ));
    }

    #[test]
    fn symbol_registration_preflight_registers_explicit_candidates_in_manifest_order() {
        let candidates = [
            synthetic_address_candidate(
                "nix.builtin.derivationStrict",
                RuntimeSymbolKind::Builtin,
                2,
            ),
            synthetic_address_candidate(
                "aos_alloc_attrs",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
                1,
            ),
            synthetic_address_candidate(
                "aos_env_get",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                3,
            ),
        ];
        let preflight = jit_cranelift_symbol_registration_preflight_with_candidates(&candidates)
            .expect("JIT symbol registration preflight builds");
        let registered_symbols = preflight
            .registered_symbols()
            .iter()
            .map(JitCraneliftRegisteredSymbol::symbol_name)
            .collect::<Vec<_>>();

        assert_eq!(
            registered_symbols,
            vec![
                "aos_alloc_attrs",
                "aos_env_get",
                "nix.builtin.derivationStrict"
            ]
        );
        assert_eq!(
            preflight
                .registered_symbol_for("aos_alloc_attrs")
                .expect("allocation helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            1
        );
        assert!(preflight.gap_for_symbol("aos_alloc_attrs").is_none());
        assert_eq!(
            preflight
                .registered_symbol_for("aos_env_get")
                .expect("environment helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            3
        );
        assert!(preflight.gap_for_symbol("aos_env_get").is_none());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn symbol_registration_preflight_propagates_registration_metadata_errors() {
        let candidates = [synthetic_address_candidate(
            "aos_not_a_runtime_symbol",
            RuntimeSymbolKind::Builtin,
            1,
        )];
        let Err(error) = jit_cranelift_symbol_registration_preflight_with_candidates(&candidates)
        else {
            panic!("unknown address candidates must be rejected before builder setup");
        };

        assert!(matches!(
            error,
            JitCraneliftModuleSetupError::RuntimeSymbolRegistration(
                crate::symbols::JitRuntimeSymbolRegistrationError::UnknownAddressCandidate {
                    symbol_name,
                }
            ) if symbol_name == "aos_not_a_runtime_symbol"
        ));
    }

    #[test]
    fn symbol_registration_preflight_propagates_duplicate_candidate_errors() {
        let candidates = [
            synthetic_address_candidate("aos_alloc_attrs", RuntimeSymbolKind::Builtin, 1),
            synthetic_address_candidate("aos_alloc_attrs", RuntimeSymbolKind::Builtin, 2),
        ];
        let Err(error) = jit_cranelift_symbol_registration_preflight_with_candidates(&candidates)
        else {
            panic!("duplicate address candidates must be rejected before builder setup");
        };

        assert!(matches!(
            error,
            JitCraneliftModuleSetupError::RuntimeSymbolRegistration(
                crate::symbols::JitRuntimeSymbolRegistrationError::DuplicateAddressCandidate {
                    symbol_name,
                }
            ) if symbol_name == "aos_alloc_attrs"
        ));
    }

    #[test]
    fn symbol_registration_preflight_preserves_kind_mismatch_gaps() {
        let candidates = [synthetic_address_candidate(
            "aos_alloc_attrs",
            RuntimeSymbolKind::Builtin,
            1,
        )];
        let preflight = jit_cranelift_symbol_registration_preflight_with_candidates(&candidates)
            .expect("JIT symbol registration preflight builds");

        assert!(preflight.registered_symbol_for("aos_alloc_attrs").is_none());
        assert!(matches!(
            preflight.gap_for_symbol("aos_alloc_attrs"),
            Some(
                crate::symbols::JitRuntimeSymbolRegistrationGap::NativeAddressKindMismatch {
                    declaration_kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
                    candidate_kind: RuntimeSymbolKind::Builtin,
                    ..
                }
            )
        ));
    }

    #[test]
    fn registered_artifact_definition_defines_env_get_artifact_with_candidate() {
        let candidates = [synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        )];

        let preflight = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
            env_get_artifact(4),
            &candidates,
        )
        .expect("registered env-get artifact definition preflight builds");

        assert_eq!(
            preflight.defined_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
        assert_eq!(preflight.artifact_runtime_imports().len(), 1);
        assert_eq!(
            preflight.artifact_runtime_imports()[0].symbol_name(),
            "aos_env_get"
        );
        assert!(preflight.imported_symbol_for("aos_env_get").is_some());
        assert_eq!(
            preflight
                .registered_symbol_for("aos_env_get")
                .expect("env helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            3
        );
        assert!(
            preflight
                .registration_gap_for_symbol("aos_env_get")
                .is_none()
        );
        assert!(matches!(
            preflight.registration_gap_for_symbol("aos_force"),
            Some(
                crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                    kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                    ..
                }
            )
        ));
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_artifact_definition_defines_forced_env_get_artifact_with_candidates() {
        let candidates = [
            synthetic_address_candidate(
                "aos_env_get",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                3,
            ),
            synthetic_address_candidate(
                "aos_force",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                5,
            ),
        ];

        let preflight = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
            forced_env_get_artifact(4),
            &candidates,
        )
        .expect("registered forced env-get artifact definition preflight builds");

        assert_eq!(
            preflight.defined_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
        assert_eq!(
            preflight
                .artifact_runtime_imports()
                .iter()
                .map(|runtime_import| runtime_import.symbol_name())
                .collect::<Vec<_>>(),
            ["aos_env_get", "aos_force"]
        );
        assert!(preflight.imported_symbol_for("aos_env_get").is_some());
        assert!(preflight.imported_symbol_for("aos_force").is_some());
        assert_eq!(
            preflight
                .registered_symbol_for("aos_env_get")
                .expect("env helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            3
        );
        assert_eq!(
            preflight
                .registered_symbol_for("aos_force")
                .expect("force helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            5
        );
        assert!(
            preflight
                .registration_gap_for_symbol("aos_env_get")
                .is_none()
        );
        assert!(preflight.registration_gap_for_symbol("aos_force").is_none());
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_artifact_definition_defines_apply_artifact_with_candidates() {
        let candidates = [
            synthetic_address_candidate(
                "aos_env_get",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                3,
            ),
            synthetic_address_candidate(
                "aos_apply",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl),
                7,
            ),
        ];

        let preflight = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
            apply_artifact(4, 6),
            &candidates,
        )
        .expect("registered apply artifact definition preflight builds");

        assert_eq!(
            preflight.defined_function().symbol_name(),
            "aos.jit.ir_root.2.thunk_body"
        );
        assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
        assert_eq!(
            preflight
                .artifact_runtime_imports()
                .iter()
                .map(|runtime_import| runtime_import.symbol_name())
                .collect::<Vec<_>>(),
            ["aos_env_get", "aos_apply"]
        );
        assert!(preflight.imported_symbol_for("aos_env_get").is_some());
        assert!(preflight.imported_symbol_for("aos_apply").is_some());
        assert_eq!(
            preflight
                .registered_symbol_for("aos_env_get")
                .expect("env helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            3
        );
        assert_eq!(
            preflight
                .registered_symbol_for("aos_apply")
                .expect("apply helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            7
        );
        assert!(
            preflight
                .registration_gap_for_symbol("aos_env_get")
                .is_none()
        );
        assert!(preflight.registration_gap_for_symbol("aos_apply").is_none());
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_artifact_definition_requires_candidates_for_artifact_imports() {
        let Err(error) = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
            env_get_artifact(4),
            &[],
        ) else {
            panic!("env-get artifact definition requires registered env helper candidate");
        };

        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error
        else {
            panic!("expected artifact runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
    }

    #[test]
    fn registered_artifact_definition_requires_force_candidate_for_forced_artifacts() {
        let candidates = [synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        )];

        let Err(error) = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
            forced_env_get_artifact(4),
            &candidates,
        ) else {
            panic!("forced env-get artifact definition requires registered force helper candidate");
        };

        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error
        else {
            panic!("expected artifact runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_force".to_owned()]);
    }

    #[test]
    fn registered_artifact_definition_preserves_unresolved_artifact_import_readiness() {
        let Err(error) = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
            artifact_with_unknown_runtime_helper_import(),
            &[],
        ) else {
            panic!("unresolved artifact import must stay a readiness error");
        };

        let JitCraneliftModuleSetupError::Readiness(
            JitModuleReadinessError::UnresolvedArtifactRuntimeImports { preflight },
        ) = error
        else {
            panic!("expected unresolved artifact-import readiness error");
        };

        assert!(preflight.artifact_runtime_imports().is_empty());
        assert_eq!(preflight.artifact_runtime_import_gaps().len(), 1);
        assert!(!preflight.is_complete());
    }

    #[test]
    fn registered_artifact_definition_rejects_wrong_kind_candidates_for_artifact_imports() {
        let candidates = [synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Builtin,
            3,
        )];

        let Err(error) = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
            env_get_artifact(4),
            &candidates,
        ) else {
            panic!("wrong-kind env helper candidate must not satisfy artifact imports");
        };

        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error
        else {
            panic!("expected artifact runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
    }

    #[test]
    fn registered_artifact_definition_allows_constant_artifacts_with_registration_gaps() {
        let artifact =
            lower_constant_thunk_body_artifact(Value::int(5)).expect("constant artifact lowers");

        let preflight =
            jit_cranelift_registered_artifact_definition_preflight_with_candidates(artifact, &[])
                .expect("constant artifact does not need runtime imports");

        assert_eq!(
            preflight.defined_function().symbol_name(),
            "aos.jit.constant_smoke.thunk_body"
        );
        assert!(preflight.artifact_runtime_imports().is_empty());
        assert!(preflight.registered_symbols().is_empty());
        assert!(preflight.imported_symbol_for("aos_env_get").is_some());
        assert!(matches!(
            preflight.registration_gap_for_symbol("aos_env_get"),
            Some(
                crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                    kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                    ..
                }
            )
        ));
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_artifact_finalization_finalizes_env_get_artifact_with_candidate() {
        let env_get_address = synthetic_runtime_import_address();
        let candidates = [synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            env_get_address,
        )];

        let preflight = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            env_get_artifact(4),
            &candidates,
        )
        .expect("registered env-get artifact finalization preflight builds");

        assert_eq!(
            preflight.finalized_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert_eq!(
            preflight.finalized_function().defined_function().linkage(),
            Linkage::Export
        );
        assert_ne!(
            preflight.finalized_function().code_ptr().as_ptr() as usize,
            0
        );
        assert_eq!(
            preflight
                .finalized_function()
                .compiled_code_ptr()
                .as_non_null(),
            preflight.finalized_function().code_ptr()
        );
        assert_eq!(preflight.artifact_runtime_imports().len(), 1);
        assert!(preflight.imported_symbol_for("aos_env_get").is_some());
        assert_eq!(
            preflight
                .registered_symbol_for("aos_env_get")
                .expect("env helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            env_get_address
        );
        assert!(
            preflight
                .registration_gap_for_symbol("aos_env_get")
                .is_none()
        );
        assert!(matches!(
            preflight.registration_gap_for_symbol("aos_force"),
            Some(
                crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                    kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                    ..
                }
            )
        ));
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_artifact_finalization_allows_constant_artifacts_with_registration_gaps() {
        let artifact =
            lower_constant_thunk_body_artifact(Value::int(8)).expect("constant artifact lowers");

        let preflight =
            jit_cranelift_registered_artifact_finalization_preflight_with_candidates(artifact, &[])
                .expect("constant artifact does not need runtime imports");

        assert_eq!(
            preflight.finalized_function().symbol_name(),
            "aos.jit.constant_smoke.thunk_body"
        );
        assert_ne!(
            preflight.finalized_function().code_ptr().as_ptr() as usize,
            0
        );
        assert!(preflight.artifact_runtime_imports().is_empty());
        assert!(preflight.registered_symbols().is_empty());
        assert!(preflight.imported_symbol_for("aos_env_get").is_some());
        assert!(matches!(
            preflight.registration_gap_for_symbol("aos_env_get"),
            Some(
                crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                    kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                    ..
                }
            )
        ));
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_artifact_finalization_requires_candidates_for_artifact_imports() {
        let Err(error) = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            env_get_artifact(4),
            &[],
        ) else {
            panic!("env-get artifact finalization requires registered env helper candidate");
        };

        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error
        else {
            panic!("expected artifact runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
    }

    #[test]
    fn registered_artifact_finalization_finalizes_forced_env_get_artifact_with_candidates() {
        let candidates = [
            synthetic_address_candidate(
                "aos_env_get",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                3,
            ),
            synthetic_address_candidate(
                "aos_force",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                5,
            ),
        ];

        let preflight = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            forced_env_get_artifact(4),
            &candidates,
        )
        .expect("forced env-get artifact finalization accepts registered helpers");

        assert_eq!(
            preflight.finalized_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert_ne!(
            preflight.finalized_function().code_ptr().as_ptr() as usize,
            0
        );
        assert_eq!(
            preflight
                .finalized_function()
                .compiled_code_ptr()
                .as_non_null(),
            preflight.finalized_function().code_ptr()
        );
        let artifact_import_names = preflight
            .artifact_runtime_imports()
            .iter()
            .map(JitModuleArtifactRuntimeImport::symbol_name)
            .collect::<Vec<_>>();
        assert_eq!(artifact_import_names, ["aos_env_get", "aos_force"]);
        assert!(preflight.imported_symbol_for("aos_env_get").is_some());
        assert!(preflight.imported_symbol_for("aos_force").is_some());
        assert_eq!(
            preflight
                .registered_symbol_for("aos_env_get")
                .expect("env helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            3
        );
        assert_eq!(
            preflight
                .registered_symbol_for("aos_force")
                .expect("force helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            5
        );
        assert!(
            preflight
                .registration_gap_for_symbol("aos_env_get")
                .is_none()
        );
        assert!(preflight.registration_gap_for_symbol("aos_force").is_none());
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_artifact_finalization_preserves_unresolved_artifact_import_readiness() {
        let Err(error) = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            artifact_with_unknown_runtime_helper_import(),
            &[],
        ) else {
            panic!("unresolved artifact import must stay a readiness error");
        };

        let JitCraneliftModuleSetupError::Readiness(
            JitModuleReadinessError::UnresolvedArtifactRuntimeImports { preflight },
        ) = error
        else {
            panic!("expected unresolved artifact-import readiness error");
        };

        assert!(preflight.artifact_runtime_imports().is_empty());
        assert_eq!(preflight.artifact_runtime_import_gaps().len(), 1);
        assert!(!preflight.is_complete());
    }

    #[test]
    fn registered_artifact_finalization_rejects_wrong_kind_candidates_for_artifact_imports() {
        let candidates = [synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Builtin,
            3,
        )];

        let Err(error) = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            env_get_artifact(4),
            &candidates,
        ) else {
            panic!("wrong-kind env helper candidate must not satisfy artifact imports");
        };

        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error
        else {
            panic!("expected artifact runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
    }

    #[test]
    fn module_declaration_preflight_builds_jit_module_imports() {
        let artifact =
            lower_constant_thunk_body_artifact(Value::int(99)).expect("constant artifact lowers");
        let readiness = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module readiness preflight builds");
        let preflight = jit_cranelift_module_declaration_preflight_for_artifact(&artifact)
            .expect("JIT module declaration preflight builds");

        assert_eq!(
            preflight.artifact().function_name(),
            &UserFuncName::default()
        );
        assert_eq!(
            preflight.imported_symbols().len(),
            readiness.symbol_declarations().len()
        );
        for declaration in readiness.symbol_declarations() {
            assert!(
                preflight
                    .imported_symbol_for(declaration.symbol_name())
                    .is_some(),
                "{} is declared as a JIT module import",
                declaration.symbol_name()
            );
        }
        assert!(
            preflight
                .imported_symbols()
                .iter()
                .all(|symbol| symbol.linkage() == Linkage::Import)
        );
        assert!(
            preflight
                .imported_symbol_for("nix.builtin.derivationStrict")
                .is_some()
        );
        assert!(preflight.imported_symbol_for("aos_apply").is_some());
        assert!(preflight.imported_symbol_for("aos_deopt").is_some());
        assert!(preflight.imported_symbol_for("aos_env_get").is_some());
        assert!(
            preflight
                .imported_symbol_for("aos_blackhole_check")
                .is_some()
        );
        assert!(preflight.imported_symbol_for("aos_force").is_some());
        assert!(preflight.imported_symbol_for("aos_has_attr").is_some());
        assert!(preflight.imported_symbol_for("aos_select_ic").is_some());
        assert!(preflight.imported_symbol_for("aos_update").is_some());
        assert!(preflight.imported_symbol_for("aos_throw").is_some());
        assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn artifact_definition_preflight_defines_constant_artifact_in_encapsulated_module() {
        let artifact =
            lower_constant_thunk_body_artifact(Value::int(7)).expect("constant artifact lowers");
        let preflight = jit_cranelift_artifact_definition_preflight_for_artifact(artifact)
            .expect("artifact definition preflight builds");

        assert_eq!(
            preflight.defined_function().symbol_name(),
            "aos.jit.constant_smoke.thunk_body"
        );
        assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
        assert!(
            preflight
                .imported_symbol_for("nix.builtin.derivationStrict")
                .is_some()
        );
        assert!(preflight.imported_symbol_for("aos_apply").is_some());
        assert!(preflight.imported_symbol_for("aos_deopt").is_some());
        assert!(
            preflight
                .imported_symbol_for("aos_blackhole_check")
                .is_some()
        );
        assert!(preflight.imported_symbol_for("aos_force").is_some());
        assert!(preflight.imported_symbol_for("aos_has_attr").is_some());
        assert!(preflight.imported_symbol_for("aos_select_ic").is_some());
        assert!(preflight.imported_symbol_for("aos_update").is_some());
        assert!(preflight.imported_symbol_for("aos_throw").is_some());
        assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn artifact_definition_preflight_uses_deterministic_ir_root_symbol() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Bool,
                    Span::new(0, 4),
                    EffectClass::pure(),
                    IrData::Bool(false),
                ),
                IrNode::new(
                    IrKind::Int,
                    Span::new(5, 6),
                    EffectClass::pure(),
                    IrData::Int(5),
                ),
            ],
            Vec::new(),
        );
        let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(1))
            .expect("IR root artifact lowers");
        let preflight = jit_cranelift_artifact_definition_preflight_for_artifact(artifact)
            .expect("artifact definition preflight builds");

        assert_eq!(
            preflight.artifact().function_name(),
            &clif_name_for_ir_root(IrId::new(1))
        );
        assert_eq!(
            preflight.defined_function().symbol_name(),
            "aos.jit.ir_root.1.thunk_body"
        );
        assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn artifact_definition_preflight_refuses_artifact_runtime_imports() {
        let Err(error) =
            jit_cranelift_artifact_definition_preflight_for_artifact(env_get_artifact(4))
        else {
            panic!("call-bearing artifact must wait for registered runtime symbols");
        };

        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error
        else {
            panic!("expected artifact runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
    }

    #[test]
    fn artifact_definition_preflight_preserves_unresolved_artifact_import_readiness() {
        let Err(error) = jit_cranelift_artifact_definition_preflight_for_artifact(
            artifact_with_unknown_runtime_helper_import(),
        ) else {
            panic!("unresolved artifact import must stay a readiness error");
        };

        let JitCraneliftModuleSetupError::Readiness(
            JitModuleReadinessError::UnresolvedArtifactRuntimeImports { preflight },
        ) = error
        else {
            panic!("expected unresolved artifact-import readiness error");
        };

        assert!(preflight.artifact_runtime_imports().is_empty());
        assert_eq!(preflight.artifact_runtime_import_gaps().len(), 1);
        assert!(!preflight.is_complete());
    }

    #[test]
    fn artifact_finalization_preflight_finalizes_constant_artifact_code_pointer() {
        let artifact =
            lower_constant_thunk_body_artifact(Value::int(11)).expect("constant artifact lowers");
        let preflight = jit_cranelift_artifact_finalization_preflight_for_artifact(artifact)
            .expect("artifact finalization preflight builds");

        assert_eq!(
            preflight.finalized_function().symbol_name(),
            "aos.jit.constant_smoke.thunk_body"
        );
        assert_eq!(
            preflight.finalized_function().defined_function().linkage(),
            Linkage::Export
        );
        assert_ne!(
            preflight.finalized_function().code_ptr().as_ptr() as usize,
            0
        );
        assert_eq!(
            preflight
                .finalized_function()
                .compiled_code_ptr()
                .as_non_null(),
            preflight.finalized_function().code_ptr()
        );
        assert!(
            preflight
                .imported_symbol_for("nix.builtin.derivationStrict")
                .is_some()
        );
        assert!(preflight.imported_symbol_for("aos_apply").is_some());
        assert!(preflight.imported_symbol_for("aos_deopt").is_some());
        assert!(
            preflight
                .imported_symbol_for("aos_blackhole_check")
                .is_some()
        );
        assert!(preflight.imported_symbol_for("aos_force").is_some());
        assert!(preflight.imported_symbol_for("aos_has_attr").is_some());
        assert!(preflight.imported_symbol_for("aos_select_ic").is_some());
        assert!(preflight.imported_symbol_for("aos_update").is_some());
        assert!(preflight.imported_symbol_for("aos_throw").is_some());
        assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
        assert!(!preflight.is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn artifact_finalization_preflight_uses_deterministic_ir_root_symbol() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Null,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );
        let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(0))
            .expect("IR root artifact lowers");
        let preflight = jit_cranelift_artifact_finalization_preflight_for_artifact(artifact)
            .expect("artifact finalization preflight builds");

        assert_eq!(
            preflight.artifact().function_name(),
            &clif_name_for_ir_root(IrId::new(0))
        );
        assert_eq!(
            preflight.finalized_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert_ne!(
            preflight.finalized_function().code_ptr().as_ptr() as usize,
            0
        );
        assert_eq!(
            preflight
                .finalized_function()
                .compiled_code_ptr()
                .as_non_null(),
            preflight.finalized_function().code_ptr()
        );
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn artifact_finalization_preflight_refuses_artifact_runtime_imports() {
        let Err(error) =
            jit_cranelift_artifact_finalization_preflight_for_artifact(env_get_artifact(8))
        else {
            panic!("call-bearing artifact must wait for registered runtime symbols");
        };

        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error
        else {
            panic!("expected artifact runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
    }

    #[test]
    fn native_thunk_call_executes_constant_smoke_artifact() {
        let expected = Value::int(23);
        let artifact =
            lower_constant_thunk_body_artifact(expected).expect("constant artifact lowers");
        let invocation = jit_cranelift_native_thunk_call_for_artifact(artifact)
            .expect("constant artifact can be called through native thunk ABI");

        assert!(invocation.value().raw_eq(expected));
        assert_eq!(
            invocation.finalized_function().symbol_name(),
            "aos.jit.constant_smoke.thunk_body"
        );
        assert_eq!(
            invocation
                .finalized_function()
                .compiled_code_ptr()
                .as_non_null(),
            invocation.finalized_function().code_ptr()
        );
        assert!(invocation.owns_encapsulated_module());
        assert!(!invocation.finalization().is_complete());
    }

    #[test]
    fn native_thunk_call_executes_literal_ir_artifact() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Bool,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Bool(true),
            )],
            Vec::new(),
        );
        let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(0))
            .expect("literal IR artifact lowers");
        let invocation = jit_cranelift_native_thunk_call_for_artifact(artifact)
            .expect("literal IR artifact can be called through native thunk ABI");

        assert!(invocation.value().raw_eq(Value::bool(true)));
        assert_eq!(
            invocation.finalized_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert!(invocation.owns_encapsulated_module());
    }

    #[test]
    fn native_thunk_call_rejects_artifact_runtime_imports() {
        let Err(error) = jit_cranelift_native_thunk_call_for_artifact(env_get_artifact(8)) else {
            panic!("call-bearing artifact must wait for registered runtime symbols");
        };

        let JitCraneliftNativeCallError::FinalizeArtifact {
            source:
                JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names },
        } = error
        else {
            panic!("expected native call to preserve runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
    }

    #[test]
    fn tier1_slot_preflight_refuses_artifact_runtime_imports() {
        let Err(error) = jit_cranelift_tier1_slot_preflight_for_artifact(env_get_artifact(12))
        else {
            panic!("call-bearing artifact must wait for registered runtime symbols");
        };

        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error
        else {
            panic!("expected artifact runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
    }

    #[test]
    fn tier1_slot_preflight_installs_constant_artifact_metadata() {
        let artifact =
            lower_constant_thunk_body_artifact(Value::int(17)).expect("constant artifact lowers");
        let preflight = jit_cranelift_tier1_slot_preflight_for_artifact(artifact)
            .expect("tier-1 slot preflight builds");

        assert_eq!(
            preflight.finalized_function().symbol_name(),
            "aos.jit.constant_smoke.thunk_body"
        );
        assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
        assert!(preflight.slot().is_tier1_installed());
        assert_eq!(
            preflight.slot().tier1_code_ptr(),
            Some(preflight.finalized_function().compiled_code_ptr())
        );
        assert_eq!(
            preflight
                .slot()
                .tier1_code_ptr()
                .map(JitCompiledCodePointer::as_non_null),
            Some(preflight.finalized_function().code_ptr())
        );
        assert!(!preflight.finalization().is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn tier1_slot_preflight_keeps_ir_root_module_owner_with_slot() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Bool,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Bool(true),
            )],
            Vec::new(),
        );
        let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(0))
            .expect("IR root artifact lowers");
        let preflight = jit_cranelift_tier1_slot_preflight_for_artifact(artifact)
            .expect("tier-1 slot preflight builds");

        assert_eq!(
            preflight.artifact().function_name(),
            &clif_name_for_ir_root(IrId::new(0))
        );
        assert_eq!(
            preflight.finalized_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
        assert_eq!(
            preflight.slot().tier1_code_ptr(),
            Some(preflight.finalized_function().compiled_code_ptr())
        );
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_tier1_slot_preflight_installs_env_get_artifact_with_candidate() {
        let env_get_address = synthetic_runtime_import_address();
        let candidates = [synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            env_get_address,
        )];

        let preflight = jit_cranelift_registered_tier1_slot_preflight_with_candidates(
            env_get_artifact(7),
            &candidates,
        )
        .expect("registered tier-1 env-get slot preflight builds");

        assert_eq!(
            preflight.finalized_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
        assert!(preflight.slot().is_tier1_installed());
        assert_eq!(
            preflight.slot().tier1_code_ptr(),
            Some(preflight.finalized_function().compiled_code_ptr())
        );
        assert_eq!(
            preflight
                .slot()
                .tier1_code_ptr()
                .map(JitCompiledCodePointer::as_non_null),
            Some(preflight.finalized_function().code_ptr())
        );
        assert_eq!(preflight.finalization().artifact_runtime_imports().len(), 1);
        assert!(
            preflight
                .finalization()
                .imported_symbol_for("aos_env_get")
                .is_some()
        );
        assert_eq!(
            preflight
                .finalization()
                .registered_symbol_for("aos_env_get")
                .expect("env helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            env_get_address
        );
        assert!(
            preflight
                .finalization()
                .registration_gap_for_symbol("aos_env_get")
                .is_none()
        );
        assert!(!preflight.finalization().is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_tier1_slot_preflight_installs_forced_env_get_artifact_with_candidates() {
        let candidates = [
            synthetic_address_candidate(
                "aos_env_get",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                3,
            ),
            synthetic_address_candidate(
                "aos_force",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                5,
            ),
        ];

        let preflight = jit_cranelift_registered_tier1_slot_preflight_with_candidates(
            forced_env_get_artifact(7),
            &candidates,
        )
        .expect("registered tier-1 forced env-get slot preflight builds");

        assert_eq!(
            preflight.finalized_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
        assert!(preflight.slot().is_tier1_installed());
        assert_eq!(
            preflight.slot().tier1_code_ptr(),
            Some(preflight.finalized_function().compiled_code_ptr())
        );
        assert_eq!(preflight.finalization().artifact_runtime_imports().len(), 2);
        assert!(
            preflight
                .finalization()
                .imported_symbol_for("aos_env_get")
                .is_some()
        );
        assert!(
            preflight
                .finalization()
                .imported_symbol_for("aos_force")
                .is_some()
        );
        assert!(
            preflight
                .finalization()
                .registration_gap_for_symbol("aos_env_get")
                .is_none()
        );
        assert!(
            preflight
                .finalization()
                .registration_gap_for_symbol("aos_force")
                .is_none()
        );
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_tier1_slot_preflight_installs_constant_artifact_with_registration_gaps() {
        let artifact =
            lower_constant_thunk_body_artifact(Value::int(21)).expect("constant artifact lowers");

        let preflight =
            jit_cranelift_registered_tier1_slot_preflight_with_candidates(artifact, &[])
                .expect("registered constant tier-1 slot preflight builds");

        assert_eq!(
            preflight.finalized_function().symbol_name(),
            "aos.jit.constant_smoke.thunk_body"
        );
        assert_eq!(preflight.slot().current_tier(), JitTier::Tier1Baseline);
        assert_eq!(
            preflight.slot().tier1_code_ptr(),
            Some(preflight.finalized_function().compiled_code_ptr())
        );
        assert!(
            preflight
                .finalization()
                .artifact_runtime_imports()
                .is_empty()
        );
        assert!(preflight.finalization().registered_symbols().is_empty());
        assert!(matches!(
            preflight
                .finalization()
                .registration_gap_for_symbol("aos_env_get"),
            Some(
                crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                    kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                    ..
                }
            )
        ));
        assert!(!preflight.finalization().is_complete());
        assert!(preflight.owns_encapsulated_module());
    }

    #[test]
    fn registered_tier1_slot_preflight_requires_candidates_for_artifact_imports() {
        let Err(error) =
            jit_cranelift_registered_tier1_slot_preflight_with_candidates(env_get_artifact(7), &[])
        else {
            panic!("registered tier-1 env-get slot requires env helper candidate");
        };

        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error
        else {
            panic!("expected artifact runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
    }

    #[test]
    fn registered_tier1_slot_preflight_preserves_unresolved_artifact_import_readiness() {
        let Err(error) = jit_cranelift_registered_tier1_slot_preflight_with_candidates(
            artifact_with_unknown_runtime_helper_import(),
            &[],
        ) else {
            panic!("unresolved artifact import must stay a readiness error");
        };

        let JitCraneliftModuleSetupError::Readiness(
            JitModuleReadinessError::UnresolvedArtifactRuntimeImports { preflight },
        ) = error
        else {
            panic!("expected unresolved artifact-import readiness error");
        };

        assert!(preflight.artifact_runtime_imports().is_empty());
        assert_eq!(preflight.artifact_runtime_import_gaps().len(), 1);
        assert!(!preflight.is_complete());
    }

    #[test]
    fn registered_tier1_slot_preflight_rejects_wrong_kind_candidates_for_artifact_imports() {
        let candidates = [synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Builtin,
            3,
        )];

        let Err(error) = jit_cranelift_registered_tier1_slot_preflight_with_candidates(
            env_get_artifact(7),
            &candidates,
        ) else {
            panic!("wrong-kind env helper candidate must not satisfy artifact imports");
        };

        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error
        else {
            panic!("expected artifact runtime-import registration guard");
        };

        assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
    }

    #[test]
    fn promotion_preflight_records_cold_invocation_without_lowering_unsupported_root() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );
        let result = jit_cranelift_tier1_promotion_preflight_for_ir_root(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
        )
        .expect("cold unsupported root does not lower");

        assert!(!result.did_compile());
        assert_eq!(
            result.decision(),
            TierUpDecision::StayInTier(JitTier::Tier0Oracle)
        );
        assert_eq!(result.slot().invocation_counter().invocations(), 1);
        assert_eq!(result.slot().current_tier(), JitTier::Tier0Oracle);
        assert!(result.promoted_preflight().is_none());
        assert!(!result.owns_encapsulated_module());
    }

    #[test]
    fn promotion_preflight_compiles_literal_root_at_threshold() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Int(99),
            )],
            Vec::new(),
        );
        let result = jit_cranelift_tier1_promotion_preflight_for_ir_root(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
        )
        .expect("threshold literal root compiles");

        assert!(result.did_compile());
        assert_eq!(
            result.decision().reasons(),
            Some(TierUpReasons::new(true, false))
        );
        assert_eq!(
            result.slot().invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
        let promoted = result
            .promoted_preflight()
            .expect("promotion result owns compiled preflight");
        assert_eq!(
            promoted.finalized_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert_eq!(
            result.slot().tier1_code_ptr(),
            Some(promoted.finalized_function().compiled_code_ptr())
        );
        assert!(result.owns_encapsulated_module());
    }

    #[test]
    fn promotion_preflight_compiles_multi_use_before_threshold() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Bool,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Bool(false),
            )],
            Vec::new(),
        );
        let result = jit_cranelift_tier1_promotion_preflight_for_ir_root(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &arena,
            IrId::new(0),
        )
        .expect("multi-use literal root compiles");

        assert!(result.did_compile());
        assert_eq!(
            result.decision().reasons(),
            Some(TierUpReasons::new(false, true))
        );
        assert_eq!(result.slot().invocation_counter().invocations(), 1);
        assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
        assert!(result.promoted_preflight().is_some());
    }

    #[test]
    fn promotion_preflight_installed_slot_skips_repeat_compilation() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            )],
            Vec::new(),
        );
        let mut slot = JitTieredCodeSlot::with_counter(TierUpCounter::new(u64::MAX));
        let code_ptr = JitCompiledCodePointer::from_non_null(NonNull::dangling());
        slot.install_tier1_code(code_ptr)
            .expect("test tier-1 metadata installs");

        let result = jit_cranelift_tier1_promotion_preflight_for_ir_root(
            slot,
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
            &arena,
            IrId::new(0),
        )
        .expect("installed slot does not recompile");

        assert!(!result.did_compile());
        assert_eq!(
            result.decision(),
            TierUpDecision::StayInTier(JitTier::Tier1Baseline)
        );
        assert_eq!(result.slot().invocation_counter().invocations(), u64::MAX);
        assert_eq!(result.slot().tier1_code_ptr(), Some(code_ptr));
        assert!(result.promoted_preflight().is_none());
    }

    #[test]
    fn promotion_preflight_reports_lowering_error_only_after_promotion() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );
        let result = jit_cranelift_tier1_promotion_preflight_for_ir_root(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
        );
        let Err(error) = result else {
            panic!("promoted unsupported root reports lowering error");
        };

        assert_eq!(
            error.slot().invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert_eq!(
            error.decision().reasons(),
            Some(TierUpReasons::new(true, false))
        );
        let JitCraneliftModuleSetupError::LowerTier1Artifact { root, source } = error.setup_error()
        else {
            panic!("expected tier-1 lowering error");
        };
        assert_eq!(*root, IrId::new(0));
        assert!(matches!(
            source,
            JitLowerError::UnsupportedIrRoot { kind: IrKind::Str }
        ));
    }

    #[test]
    fn registered_promotion_preflight_records_cold_invocation_without_lowering_unsupported_root() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );
        let result =
            jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::new(),
                TierUpPolicy::default(),
                TierUpDemandHint::NoMultiUseEvidence,
                &arena,
                IrId::new(0),
                &[],
            )
            .expect("cold unsupported root does not lower");

        assert!(!result.did_compile());
        assert_eq!(
            result.decision(),
            TierUpDecision::StayInTier(JitTier::Tier0Oracle)
        );
        assert_eq!(result.slot().invocation_counter().invocations(), 1);
        assert_eq!(result.slot().current_tier(), JitTier::Tier0Oracle);
        assert!(result.promoted_preflight().is_none());
        assert!(!result.owns_encapsulated_module());
    }

    #[test]
    fn registered_promotion_preflight_compiles_env_get_root_at_threshold_with_candidate() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Local { slot: 9 },
            )],
            Vec::new(),
        );
        let env_get_address = synthetic_runtime_import_address();
        let candidates = [synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            env_get_address,
        )];

        let result =
            jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::with_counter(TierUpCounter::new(
                    DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
                )),
                TierUpPolicy::default(),
                TierUpDemandHint::NoMultiUseEvidence,
                &arena,
                IrId::new(0),
                &candidates,
            )
            .expect("threshold env-get root compiles with registered helper");

        assert!(result.did_compile());
        assert_eq!(
            result.decision().reasons(),
            Some(TierUpReasons::new(true, false))
        );
        assert_eq!(
            result.slot().invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
        let promoted = result
            .promoted_preflight()
            .expect("promotion result owns registered compiled preflight");
        assert_eq!(
            promoted.finalized_function().symbol_name(),
            "aos.jit.ir_root.0.thunk_body"
        );
        assert_eq!(
            result.slot().tier1_code_ptr(),
            Some(promoted.finalized_function().compiled_code_ptr())
        );
        assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 1);
        assert_eq!(
            promoted
                .finalization()
                .registered_symbol_for("aos_env_get")
                .expect("env helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            env_get_address
        );
        assert!(
            promoted
                .finalization()
                .imported_symbol_for("aos_env_get")
                .is_some()
        );
        assert!(result.owns_encapsulated_module());
    }

    #[test]
    fn registered_promotion_preflight_compiles_apply_root_with_candidates() {
        let arena = apply_arena(4, 6);
        let candidates = [
            synthetic_address_candidate(
                "aos_env_get",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                3,
            ),
            synthetic_address_candidate(
                "aos_apply",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl),
                7,
            ),
        ];

        let result =
            jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::with_counter(TierUpCounter::new(
                    DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
                )),
                TierUpPolicy::default(),
                TierUpDemandHint::NoMultiUseEvidence,
                &arena,
                IrId::new(2),
                &candidates,
            )
            .expect("threshold apply root compiles with registered helpers");

        assert!(result.did_compile());
        assert_eq!(
            result.decision().reasons(),
            Some(TierUpReasons::new(true, false))
        );
        assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
        let promoted = result
            .promoted_preflight()
            .expect("promotion result owns registered compiled preflight");
        assert_eq!(
            promoted.artifact().function_name(),
            &clif_name_for_ir_root(IrId::new(2))
        );
        assert_eq!(
            result.slot().tier1_code_ptr(),
            Some(promoted.finalized_function().compiled_code_ptr())
        );
        assert_eq!(
            promoted
                .finalization()
                .artifact_runtime_imports()
                .iter()
                .map(JitModuleArtifactRuntimeImport::symbol_name)
                .collect::<Vec<_>>(),
            ["aos_env_get", "aos_apply"]
        );
        assert!(
            promoted
                .finalization()
                .imported_symbol_for("aos_env_get")
                .is_some()
        );
        assert!(
            promoted
                .finalization()
                .imported_symbol_for("aos_apply")
                .is_some()
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_env_get")
                .is_some()
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_apply")
                .is_some()
        );
        assert!(result.owns_encapsulated_module());
    }

    #[test]
    fn registered_promotion_preflight_compiles_wrapped_env_get_root_with_candidate() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 6),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(1)),
                ),
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(1, 5),
                    EffectClass::pure(),
                    IrData::Local { slot: 11 },
                ),
            ],
            Vec::new(),
        );
        let candidates = [synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            synthetic_runtime_import_address(),
        )];

        let result =
            jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::new(),
                TierUpPolicy::default(),
                TierUpDemandHint::MultiUse,
                &arena,
                IrId::new(0),
                &candidates,
            )
            .expect("wrapped env-get root compiles with registered helper");

        assert!(result.did_compile());
        let promoted = result
            .promoted_preflight()
            .expect("promotion result owns registered compiled preflight");
        assert_eq!(
            promoted.artifact().function_name(),
            &clif_name_for_ir_root(IrId::new(0))
        );
        assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 1);
        assert!(
            promoted
                .finalization()
                .imported_symbol_for("aos_env_get")
                .is_some()
        );
        assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
        assert!(result.owns_encapsulated_module());
    }

    #[test]
    fn registered_promotion_preflight_compiles_literal_root_without_candidates() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Bool,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Bool(true),
            )],
            Vec::new(),
        );
        let result =
            jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::new(),
                TierUpPolicy::default(),
                TierUpDemandHint::MultiUse,
                &arena,
                IrId::new(0),
                &[],
            )
            .expect("multi-use literal root compiles without runtime candidates");

        assert!(result.did_compile());
        assert_eq!(
            result.decision().reasons(),
            Some(TierUpReasons::new(false, true))
        );
        let promoted = result
            .promoted_preflight()
            .expect("promotion result owns registered compiled preflight");
        assert!(
            promoted
                .finalization()
                .artifact_runtime_imports()
                .is_empty()
        );
        assert!(promoted.finalization().registered_symbols().is_empty());
        assert_eq!(
            result.slot().tier1_code_ptr(),
            Some(promoted.finalized_function().compiled_code_ptr())
        );
        assert!(result.owns_encapsulated_module());
    }

    #[test]
    fn registered_promotion_preflight_compiles_wrapped_literal_root_without_candidates() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 6),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(1)),
                ),
                IrNode::new(
                    IrKind::Int,
                    Span::new(1, 5),
                    EffectClass::pure(),
                    IrData::Int(123),
                ),
            ],
            Vec::new(),
        );

        let result =
            jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::new(),
                TierUpPolicy::default(),
                TierUpDemandHint::MultiUse,
                &arena,
                IrId::new(0),
                &[],
            )
            .expect("wrapped literal root compiles without runtime candidates");

        assert!(result.did_compile());
        let promoted = result
            .promoted_preflight()
            .expect("promotion result owns registered compiled preflight");
        assert_eq!(
            promoted.artifact().function_name(),
            &clif_name_for_ir_root(IrId::new(0))
        );
        assert!(
            promoted
                .finalization()
                .artifact_runtime_imports()
                .is_empty()
        );
        assert!(promoted.finalization().registered_symbols().is_empty());
        assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
        assert!(result.owns_encapsulated_module());
    }

    #[test]
    fn registered_promotion_preflight_reports_missing_candidate_after_promotion() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Local { slot: 9 },
            )],
            Vec::new(),
        );
        let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &[],
        );
        let Err(error) = result else {
            panic!("promoted env-get root requires registered env helper");
        };

        assert_eq!(
            error.slot().invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert_eq!(
            error.decision().reasons(),
            Some(TierUpReasons::new(true, false))
        );
        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error.setup_error()
        else {
            panic!("expected artifact runtime-import registration guard");
        };
        assert_eq!(symbol_names, &["aos_env_get".to_owned()]);
    }

    #[test]
    fn force_aware_registered_promotion_preflight_records_cold_invocation_without_lowering() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );
        let result =
            jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::new(),
                TierUpPolicy::default(),
                TierUpDemandHint::NoMultiUseEvidence,
                &arena,
                IrId::new(0),
                &[],
            )
            .expect("cold unsupported root does not lower");

        assert!(!result.did_compile());
        assert_eq!(
            result.decision(),
            TierUpDecision::StayInTier(JitTier::Tier0Oracle)
        );
        assert_eq!(result.slot().invocation_counter().invocations(), 1);
        assert_eq!(result.slot().current_tier(), JitTier::Tier0Oracle);
        assert!(result.promoted_preflight().is_none());
        assert!(!result.owns_encapsulated_module());
    }

    #[test]
    fn force_aware_registered_promotion_preflight_compiles_literal_root_without_candidates() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Bool,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Bool(true),
            )],
            Vec::new(),
        );
        let result =
            jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::new(),
                TierUpPolicy::default(),
                TierUpDemandHint::MultiUse,
                &arena,
                IrId::new(0),
                &[],
            )
            .expect("force-aware literal root compiles without runtime candidates");

        assert!(result.did_compile());
        assert_eq!(
            result.decision().reasons(),
            Some(TierUpReasons::new(false, true))
        );
        let promoted = result
            .promoted_preflight()
            .expect("promotion result owns registered compiled preflight");
        assert!(
            promoted
                .finalization()
                .artifact_runtime_imports()
                .is_empty()
        );
        assert!(promoted.finalization().registered_symbols().is_empty());
        assert_eq!(
            result.slot().tier1_code_ptr(),
            Some(promoted.finalized_function().compiled_code_ptr())
        );
        assert!(result.owns_encapsulated_module());
    }

    #[test]
    fn force_aware_registered_promotion_preflight_installs_forced_env_slot() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Local { slot: 9 },
            )],
            Vec::new(),
        );
        let candidates = [
            synthetic_address_candidate(
                "aos_env_get",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                3,
            ),
            synthetic_address_candidate(
                "aos_force",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                5,
            ),
        ];

        let result =
            jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::with_counter(TierUpCounter::new(
                    DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
                )),
                TierUpPolicy::default(),
                TierUpDemandHint::NoMultiUseEvidence,
                &arena,
                IrId::new(0),
                &candidates,
            )
            .expect("force-aware env-slot promotion finalizes with registered helpers");

        assert_eq!(
            result.slot().invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
        assert_eq!(
            result.decision().reasons(),
            Some(TierUpReasons::new(true, false))
        );
        assert!(result.did_compile());
        let promoted = result
            .promoted_preflight()
            .expect("promotion owns registered tier-1 preflight");
        assert_eq!(
            result.slot().tier1_code_ptr(),
            Some(promoted.finalized_function().compiled_code_ptr())
        );
        assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 2);
        assert!(
            promoted
                .finalization()
                .imported_symbol_for("aos_env_get")
                .is_some()
        );
        assert!(
            promoted
                .finalization()
                .imported_symbol_for("aos_force")
                .is_some()
        );
        assert_eq!(
            promoted
                .finalization()
                .registered_symbol_for("aos_env_get")
                .expect("env helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            3
        );
        assert_eq!(
            promoted
                .finalization()
                .registered_symbol_for("aos_force")
                .expect("force helper is registered")
                .address()
                .as_nonzero_usize()
                .get(),
            5
        );
        assert!(
            promoted
                .finalization()
                .registration_gap_for_symbol("aos_env_get")
                .is_none()
        );
        assert!(
            promoted
                .finalization()
                .registration_gap_for_symbol("aos_force")
                .is_none()
        );
        assert!(!promoted.finalization().is_complete());
        assert!(result.owns_encapsulated_module());
    }

    #[test]
    fn force_aware_registered_promotion_preflight_preserves_wrapped_apply_helper_boundary() {
        let arena = wrapped_apply_arena(10, 12);
        let candidates = [
            synthetic_address_candidate(
                "aos_env_get",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                3,
            ),
            synthetic_address_candidate(
                "aos_apply",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl),
                7,
            ),
        ];

        let result =
            jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::new(),
                TierUpPolicy::default(),
                TierUpDemandHint::MultiUse,
                &arena,
                IrId::new(3),
                &candidates,
            )
            .expect("force-aware wrapped apply promotion finalizes with apply helper");

        assert_eq!(
            result.decision().reasons(),
            Some(TierUpReasons::new(false, true))
        );
        assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
        assert!(result.did_compile());
        let promoted = result
            .promoted_preflight()
            .expect("promotion owns registered tier-1 preflight");
        assert_eq!(
            promoted.artifact().function_name(),
            &clif_name_for_ir_root(IrId::new(3))
        );
        assert_eq!(
            result.slot().tier1_code_ptr(),
            Some(promoted.finalized_function().compiled_code_ptr())
        );
        assert_eq!(
            promoted
                .finalization()
                .artifact_runtime_imports()
                .iter()
                .map(JitModuleArtifactRuntimeImport::symbol_name)
                .collect::<Vec<_>>(),
            ["aos_env_get", "aos_apply"]
        );
        assert!(
            promoted
                .finalization()
                .imported_symbol_for("aos_env_get")
                .is_some()
        );
        assert!(
            promoted
                .finalization()
                .imported_symbol_for("aos_apply")
                .is_some()
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_env_get")
                .is_some()
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_apply")
                .is_some()
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_force")
                .is_none()
        );
        assert!(result.owns_encapsulated_module());
    }

    #[test]
    fn force_aware_registered_promotion_preflight_requires_force_candidate() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Local { slot: 9 },
            )],
            Vec::new(),
        );
        let candidates = [synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        )];

        let result =
            jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::with_counter(TierUpCounter::new(
                    DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
                )),
                TierUpPolicy::default(),
                TierUpDemandHint::NoMultiUseEvidence,
                &arena,
                IrId::new(0),
                &candidates,
            );
        let Err(error) = result else {
            panic!("force-aware env-slot promotion requires a force helper candidate");
        };

        assert_eq!(
            error.slot().invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
        assert!(error.slot().tier1_code_ptr().is_none());
        assert_eq!(
            error.decision().reasons(),
            Some(TierUpReasons::new(true, false))
        );
        let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
            symbol_names,
        } = error.setup_error()
        else {
            panic!("expected force helper registration guard");
        };
        assert_eq!(symbol_names, &["aos_force".to_owned()]);
    }

    #[test]
    fn force_aware_registered_promotion_preflight_forces_wrapped_env_slot() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 6),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(1)),
                ),
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(1, 5),
                    EffectClass::pure(),
                    IrData::Local { slot: 11 },
                ),
            ],
            Vec::new(),
        );
        let candidates = [
            synthetic_address_candidate(
                "aos_env_get",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                3,
            ),
            synthetic_address_candidate(
                "aos_force",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                5,
            ),
        ];

        let result =
            jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::new(),
                TierUpPolicy::default(),
                TierUpDemandHint::MultiUse,
                &arena,
                IrId::new(0),
                &candidates,
            )
            .expect("wrapped force-aware env-slot promotion finalizes with registered helpers");

        assert_eq!(
            result.decision().reasons(),
            Some(TierUpReasons::new(false, true))
        );
        assert_eq!(result.slot().current_tier(), JitTier::Tier1Baseline);
        assert!(result.did_compile());
        let promoted = result
            .promoted_preflight()
            .expect("promotion owns registered tier-1 preflight");
        assert_eq!(
            result.slot().tier1_code_ptr(),
            Some(promoted.finalized_function().compiled_code_ptr())
        );
        assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 2);
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_env_get")
                .is_some()
        );
        assert!(
            promoted
                .finalization()
                .registered_symbol_for("aos_force")
                .is_some()
        );
        assert!(result.owns_encapsulated_module());
    }

    #[test]
    fn force_aware_registered_promotion_preflight_reports_malformed_local_payload_after_promotion()
    {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let result =
            jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                JitTieredCodeSlot::with_counter(TierUpCounter::new(
                    DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
                )),
                TierUpPolicy::default(),
                TierUpDemandHint::NoMultiUseEvidence,
                &arena,
                IrId::new(0),
                &[],
            );
        let Err(error) = result else {
            panic!("hot malformed local root reports a lowering error");
        };

        assert_eq!(
            error.slot().invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert_eq!(
            error.decision().reasons(),
            Some(TierUpReasons::new(true, false))
        );
        let JitCraneliftModuleSetupError::LowerTier1Artifact { root, source } = error.setup_error()
        else {
            panic!("expected force-aware lowering error");
        };
        assert_eq!(*root, IrId::new(0));
        assert!(matches!(
            source,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::LocalVar,
                data: IrData::None,
                expected: "local slot payload",
            }
        ));
    }

    #[test]
    fn registered_promotion_preflight_installed_slot_skips_repeat_compilation() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::Local { slot: 9 },
            )],
            Vec::new(),
        );
        let mut slot = JitTieredCodeSlot::with_counter(TierUpCounter::new(u64::MAX));
        let code_ptr = JitCompiledCodePointer::from_non_null(NonNull::dangling());
        slot.install_tier1_code(code_ptr)
            .expect("test tier-1 metadata installs");

        let result =
            jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
                slot,
                TierUpPolicy::default(),
                TierUpDemandHint::MultiUse,
                &arena,
                IrId::new(0),
                &[],
            )
            .expect("installed registered slot does not recompile");

        assert!(!result.did_compile());
        assert_eq!(
            result.decision(),
            TierUpDecision::StayInTier(JitTier::Tier1Baseline)
        );
        assert_eq!(result.slot().invocation_counter().invocations(), u64::MAX);
        assert_eq!(result.slot().tier1_code_ptr(), Some(code_ptr));
        assert!(result.promoted_preflight().is_none());
        assert!(!result.owns_encapsulated_module());
    }

    #[test]
    fn registered_promotion_preflight_reports_lowering_error_only_after_promotion() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );
        let result = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            &[],
        );
        let Err(error) = result else {
            panic!("promoted unsupported root reports lowering error");
        };

        assert_eq!(
            error.slot().invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert_eq!(
            error.decision().reasons(),
            Some(TierUpReasons::new(true, false))
        );
        let JitCraneliftModuleSetupError::LowerTier1Artifact { root, source } = error.setup_error()
        else {
            panic!("expected tier-1 lowering error");
        };
        assert_eq!(*root, IrId::new(0));
        assert!(matches!(
            source,
            JitLowerError::UnsupportedIrRoot { kind: IrKind::Str }
        ));
    }

    #[test]
    fn complete_module_setup_refuses_current_runtime_symbol_gaps() {
        let artifact =
            lower_constant_thunk_body_artifact(Value::null()).expect("constant artifact lowers");
        let Err(error) = jit_cranelift_module_setup_for_artifact(&artifact) else {
            panic!("runtime-symbol gaps must block complete JIT module setup");
        };

        let JitCraneliftModuleSetupError::Readiness(
            JitModuleReadinessError::IncompleteRuntimeSymbols { preflight },
        ) = error
        else {
            panic!("expected incomplete readiness error");
        };

        assert!(
            preflight
                .declaration_for_symbol("nix.builtin.derivationStrict")
                .is_some()
        );
        assert!(preflight.declaration_for_symbol("aos_force").is_some());
        assert!(
            preflight
                .declaration_for_symbol("aos_blackhole_check")
                .is_some()
        );
        assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
    }
}
