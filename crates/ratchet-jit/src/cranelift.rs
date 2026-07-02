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
//! scaffold records safe slot hotness and compiles only currently-supported
//! literal roots when policy requests tier 1. None of these paths transmutes code
//! pointers or calls native code.

use std::{
    error::Error,
    fmt,
    ptr::{self, NonNull},
};

use cranelift_codegen::{
    CodegenError, Context,
    settings::{self, Configurable, SetError},
};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, ModuleError};
use ratchet_core::{IrArena, IrId};

use crate::{
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource},
    lower::{JitLowerError, lower_constant_ir_thunk_body_artifact},
    module::{
        JitModuleArtifactMetadata, JitModuleReadinessError, JitModuleReadinessPlan,
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
/// The code pointer stored here is metadata tied to the lifetime of the owning
/// [`JITModule`] inside [`JitCraneliftArtifactFinalizationPreflight`]. It is
/// not a standalone ownership handle.
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
    /// pointer until the unsafe native-call boundary lands. The pointer's
    /// validity is tied to the owning
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
/// core-owned allocation/write-barrier helper imports declared using
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

/// Builds a real JIT module and defines one verified CLIF artifact body.
///
/// The returned preflight owns a [`JITModule`] with callable builtin imports
/// declared, plus one artifact body declared as an exported function and passed
/// to Cranelift's definition API. Unshaped helper and value-only builtin gaps
/// are preserved. A successful definition lets Cranelift compile the body and
/// allocate JIT code memory inside the private module. The module is not
/// finalized, no code pointer is returned, and no native code is called.
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
/// [`JitCraneliftModuleSetupError::DeclareArtifactFunction`] if Cranelift
/// rejects the artifact function declaration. Returns
/// [`JitCraneliftModuleSetupError::DefineArtifactFunction`] if Cranelift rejects
/// the artifact function definition.
pub fn jit_cranelift_artifact_definition_preflight_for_artifact(
    artifact: JitClifArtifact,
) -> Result<JitCraneliftArtifactDefinitionPreflight, JitCraneliftModuleSetupError> {
    let readiness = jit_module_readiness_preflight_for_artifact(&artifact)?;
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
/// Current crate-built artifacts are constant/literal bodies with no runtime
/// call relocations; call-bearing artifacts require the later path that composes
/// artifact finalization with complete runtime-symbol address registration.
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
/// Panics if an artifact references imported runtime symbols whose addresses
/// have not been registered before Cranelift relocation. Panics if Cranelift
/// reports successful artifact definition and module finalization but then
/// fails its own invariant for looking up the finalized function by [`FuncId`].
pub fn jit_cranelift_artifact_finalization_preflight_for_artifact(
    artifact: JitClifArtifact,
) -> Result<JitCraneliftArtifactFinalizationPreflight, JitCraneliftModuleSetupError> {
    let readiness = jit_module_readiness_preflight_for_artifact(&artifact)?;
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

fn module_with_imported_symbols(
    declarations: &[JitRuntimeSymbolDeclaration],
) -> Result<(JITModule, Vec<JitCraneliftImportedSymbol>), JitCraneliftModuleSetupError> {
    let builder = native_jit_builder()?;
    let mut module = JITModule::new(builder);
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

fn define_artifact_function(
    module: &mut JITModule,
    artifact: JitClifArtifact,
    symbol_name: String,
) -> Result<JitCraneliftDefinedFunction, JitCraneliftModuleSetupError> {
    let function = artifact.into_function();
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

    use cranelift_codegen::ir::UserFuncName;
    use ratchet_core::syntax::Span;
    use ratchet_core::{
        EffectClass, IrArena, IrData, IrId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
    };
    use ratchet_value::value::Value;

    use super::*;
    use crate::{
        lower::{
            clif_name_for_ir_root, lower_constant_ir_thunk_body_artifact,
            lower_constant_thunk_body_artifact,
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
            Some(crate::symbols::JitRuntimeSymbolRegistrationGap::Declaration(
                crate::symbols::JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                    role: RuntimeHelperRole::ForcingControl,
                    ..
                }
            ))
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
            vec!["aos_alloc_attrs", "nix.builtin.derivationStrict"]
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
        assert!(matches!(
            preflight.gap_for_symbol("aos_force"),
            Some(
                JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                    role: RuntimeHelperRole::ForcingControl,
                    ..
                }
            )
        ));
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
        assert!(matches!(
            preflight.gap_for_symbol("aos_force"),
            Some(
                JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                    role: RuntimeHelperRole::ForcingControl,
                    ..
                }
            )
        ));
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
        assert!(matches!(
            preflight.gap_for_symbol("aos_force"),
            Some(
                JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                    role: RuntimeHelperRole::ForcingControl,
                    ..
                }
            )
        ));
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
        assert!(preflight.gap_for_symbol("aos_force").is_some());
    }
}
