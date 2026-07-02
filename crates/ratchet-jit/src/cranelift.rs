//! Cranelift dependency pin and safe JIT-module setup.
//!
//! This module records the Cranelift crate versions that the current CLIF
//! slices are validated against and constructs the first real `JITModule`
//! scaffolds. The symbol-registration scaffold installs explicitly supplied
//! native-address candidates into a `JITBuilder` symbol table. The declaration
//! scaffold declares shape-known runtime symbols as imported functions. The
//! artifact-definition scaffold additionally compiles one verified CLIF artifact
//! into an encapsulated module. None of these paths finalize memory, return code
//! pointers, or call native code.

use std::{error::Error, fmt, ptr};

use cranelift_codegen::{
    CodegenError, Context,
    settings::{self, Configurable, SetError},
};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, ModuleError};

use crate::{
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource},
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
            Self::DeclareRuntimeSymbol { source, .. } => Some(source),
            Self::DeclareArtifactFunction { source, .. } => Some(source),
            Self::DefineArtifactFunction { source, .. } => Some(source),
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
    use std::num::NonZeroUsize;

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
