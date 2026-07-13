//! Promotion error, module-declaration and artifact-definition preflights,
//! module setup + native-call error records, and their `Display`/`Error`/`From`
//! implementations.

use super::*;

/// A failure from a promotion-gated tier-1 compile attempt.
#[derive(Debug)]
pub struct JitCraneliftTier1PromotionError {
    slot: JitTieredCodeSlot,
    decision: TierUpDecision,
    source: JitCraneliftModuleSetupError,
}

impl JitCraneliftTier1PromotionError {
    pub(crate) fn new(
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
    pub(crate) fn new(
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
    pub(crate) fn new(
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
    pub(crate) fn new(
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
    pub(crate) fn new(
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

