//! Preflight metadata types: imported/defined symbols, stack maps, registered
//! symbols, and the artifact definition/finalization/native-thunk/tier-1
//! slot/promotion preflight records.

use super::*;

/// A runtime symbol declared as an imported function in a JIT module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitCraneliftImportedSymbol {
    symbol_name: String,
    linkage: Linkage,
    func_id: FuncId,
}

impl JitCraneliftImportedSymbol {
    pub(crate) fn new(symbol_name: String, linkage: Linkage, func_id: FuncId) -> Self {
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
    user_stack_maps: Vec<JitCraneliftUserStackMap>,
}

impl JitCraneliftDefinedFunction {
    pub(crate) fn new(
        symbol_name: String,
        linkage: Linkage,
        func_id: FuncId,
        user_stack_maps: Vec<JitCraneliftUserStackMap>,
    ) -> Self {
        Self {
            symbol_name,
            linkage,
            func_id,
            user_stack_maps,
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

    /// Returns finalized user stack maps keyed by call return-address offset.
    pub fn user_stack_maps(&self) -> &[JitCraneliftUserStackMap] {
        &self.user_stack_maps
    }
}

/// One finalized live-value entry in a Cranelift user stack map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JitCraneliftUserStackMapEntry {
    pub(crate) value_type: cranelift_codegen::ir::Type,
    pub(crate) sp_offset: u32,
}

impl JitCraneliftUserStackMapEntry {
    /// Returns the CLIF word type recorded for the live value anchor.
    pub const fn value_type(self) -> cranelift_codegen::ir::Type {
        self.value_type
    }

    /// Returns the byte offset from the compiled frame's stack pointer.
    pub const fn sp_offset(self) -> u32 {
        self.sp_offset
    }
}

/// A finalized user stack map for one compiled call safepoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitCraneliftUserStackMap {
    pub(crate) return_address_offset: u32,
    pub(crate) call_span: u32,
    pub(crate) identity_sp_offset: Option<u32>,
    pub(crate) entries: Vec<JitCraneliftUserStackMapEntry>,
}

impl JitCraneliftUserStackMap {
    /// Returns the call return-address offset from the function entrypoint.
    pub const fn return_address_offset(&self) -> u32 {
        self.return_address_offset
    }

    /// Returns the machine-code byte span covered by the call instruction.
    pub const fn call_span(&self) -> u32 {
        self.call_span
    }

    /// Returns the SP-relative address-identity anchor for this safepoint.
    pub const fn identity_sp_offset(&self) -> Option<u32> {
        self.identity_sp_offset
    }

    /// Returns stack-pointer-relative live runtime-value anchors.
    pub fn entries(&self) -> &[JitCraneliftUserStackMapEntry] {
        &self.entries
    }
}

/// A runtime symbol registered with a Cranelift JIT builder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitCraneliftRegisteredSymbol {
    symbol_name: String,
    address: JitRuntimeSymbolAddress,
}

impl JitCraneliftRegisteredSymbol {
    pub(crate) fn new(symbol_name: String, address: JitRuntimeSymbolAddress) -> Self {
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

/// A real `JITModule` created from a builder with runtime symbols registered.
pub struct JitCraneliftSymbolRegistrationPreflight {
    registered_symbols: Vec<JitCraneliftRegisteredSymbol>,
    symbol_gaps: Vec<JitRuntimeSymbolRegistrationGap>,
    module: JITModule,
}

impl JitCraneliftSymbolRegistrationPreflight {
    pub(crate) fn new(
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
    pub(crate) fn new(
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
    pub(crate) fn new(
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
    pub(crate) fn new(
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
    pub(crate) fn new(
        finalization: JitCraneliftArtifactFinalizationPreflight,
        value: Value,
    ) -> Self {
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
    pub(crate) fn new(
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
    pub(crate) fn new(
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
    pub(crate) fn new(
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
