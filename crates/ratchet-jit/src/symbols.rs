//! Runtime-symbol inventory and registration-readiness metadata.
//!
//! The inventory in this module mirrors the stable runtime symbol manifest owned
//! by `ratchet-core`. It gives future Cranelift setup code a local, documented
//! entry point for the symbol names and roles it may declare, without attaching
//! executable addresses or consulting the safe oracle's candidate-readiness
//! reports. It also preflights which stable symbols can currently be declared
//! with CLIF signatures, and which declarations have explicit opaque
//! native-address candidate metadata, without dereferencing those addresses,
//! exposing function pointers, calling `JITBuilder::symbol`, or creating a
//! `JITModule`.

use std::{collections::BTreeMap, error::Error, fmt, num::NonZeroUsize};

use cranelift_codegen::ir::Signature;

use ratchet_core::{
    RuntimeBuiltinCallBinding, RuntimeBuiltinCallMissingBinding, RuntimeCallSignature,
    RuntimeHelperRole, RuntimeSymbolKind, RuntimeSymbolManifestEntry, RuntimeSymbolNameError,
    runtime_builtin_call_preflight, runtime_helper_call_signature, runtime_symbol_manifest,
};

use crate::abi::{JitClifSignatureError, clif_signature_for_runtime_call};

/// Address-free runtime symbols visible to future JIT modules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JitRuntimeSymbolInventory {
    symbols: Vec<RuntimeSymbolManifestEntry>,
}

impl JitRuntimeSymbolInventory {
    /// Builds the JIT-side runtime-symbol inventory from core metadata.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest
    /// cannot be built.
    pub fn from_core_metadata() -> Result<Self, RuntimeSymbolNameError> {
        Ok(Self {
            symbols: runtime_symbol_manifest()?,
        })
    }

    /// Returns runtime symbols in stable core manifest order.
    pub fn symbols(&self) -> &[RuntimeSymbolManifestEntry] {
        &self.symbols
    }

    /// Returns true when the inventory contains `symbol_name`.
    pub fn contains_symbol(&self, symbol_name: &str) -> bool {
        self.symbols
            .iter()
            .any(|symbol| symbol.name() == symbol_name)
    }

    /// Returns the symbol kind for `symbol_name` when it is present.
    pub fn symbol_kind(&self, symbol_name: &str) -> Option<RuntimeSymbolKind> {
        self.symbols
            .iter()
            .find(|symbol| symbol.name() == symbol_name)
            .map(RuntimeSymbolManifestEntry::kind)
    }
}

/// Returns the JIT-side view of the stable runtime-symbol inventory.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest cannot
/// be built.
pub fn jit_runtime_symbol_inventory() -> Result<JitRuntimeSymbolInventory, RuntimeSymbolNameError> {
    JitRuntimeSymbolInventory::from_core_metadata()
}

/// A CLIF declaration for a stable runtime symbol before address binding.
#[derive(Clone, Debug, PartialEq)]
pub struct JitRuntimeSymbolDeclaration {
    symbol_name: String,
    kind: RuntimeSymbolKind,
    signature: Signature,
}

impl JitRuntimeSymbolDeclaration {
    fn new(symbol_name: String, kind: RuntimeSymbolKind, signature: Signature) -> Self {
        Self {
            symbol_name,
            kind,
            signature,
        }
    }

    /// Returns the stable symbol name to declare in a future Cranelift module.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the runtime symbol family served by this declaration.
    pub const fn kind(&self) -> RuntimeSymbolKind {
        self.kind
    }

    /// Returns the CLIF signature attached to this address-free declaration.
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// A stable runtime symbol that cannot yet be declared with a CLIF signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JitRuntimeSymbolDeclarationGap {
    /// Runtime helper ABI metadata is not core-owned yet.
    HelperWithoutCoreCallSignature {
        /// The stable `aos_*` helper symbol name.
        symbol_name: String,
        /// The runtime subsystem served by the helper.
        role: RuntimeHelperRole,
    },
    /// The builtin is a value symbol rather than a callable primop wrapper.
    BuiltinValueOnly {
        /// The stable `nix.builtin.*` runtime symbol name.
        symbol_name: String,
        /// The byte-oriented builtin declaration name.
        builtin_name: &'static [u8],
    },
    /// The builtin declares an arity without frozen CLIF ABI metadata.
    BuiltinUnsupportedArity {
        /// The stable `nix.builtin.*` runtime symbol name.
        symbol_name: String,
        /// The byte-oriented builtin declaration name.
        builtin_name: &'static [u8],
        /// The declared first-class builtin arity.
        arity: usize,
        /// The largest primop arity described by current metadata.
        max: usize,
    },
    /// The builtin manifest and builtin call preflight were out of sync.
    BuiltinWithoutCallMetadata {
        /// The stable `nix.builtin.*` runtime symbol name.
        symbol_name: String,
    },
}

impl JitRuntimeSymbolDeclarationGap {
    fn helper(symbol_name: String, role: RuntimeHelperRole) -> Self {
        Self::HelperWithoutCoreCallSignature { symbol_name, role }
    }

    fn from_builtin_missing(missing: &RuntimeBuiltinCallMissingBinding) -> Self {
        match missing {
            RuntimeBuiltinCallMissingBinding::ValueOnly {
                symbol_name,
                builtin_name,
            } => Self::BuiltinValueOnly {
                symbol_name: symbol_name.to_owned(),
                builtin_name,
            },
            RuntimeBuiltinCallMissingBinding::UnsupportedArity {
                symbol_name,
                builtin_name,
                arity,
                max,
            } => Self::BuiltinUnsupportedArity {
                symbol_name: symbol_name.to_owned(),
                builtin_name,
                arity: *arity,
                max: *max,
            },
        }
    }

    fn builtin_without_call_metadata(symbol_name: String) -> Self {
        Self::BuiltinWithoutCallMetadata { symbol_name }
    }

    /// Returns the stable runtime symbol name for this gap.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::HelperWithoutCoreCallSignature { symbol_name, .. }
            | Self::BuiltinValueOnly { symbol_name, .. }
            | Self::BuiltinUnsupportedArity { symbol_name, .. }
            | Self::BuiltinWithoutCallMetadata { symbol_name } => symbol_name,
        }
    }

    /// Returns the runtime symbol family served by this gap.
    pub const fn kind(&self) -> RuntimeSymbolKind {
        match self {
            Self::HelperWithoutCoreCallSignature { role, .. } => RuntimeSymbolKind::Helper(*role),
            Self::BuiltinValueOnly { .. }
            | Self::BuiltinUnsupportedArity { .. }
            | Self::BuiltinWithoutCallMetadata { .. } => RuntimeSymbolKind::Builtin,
        }
    }
}

/// Address-free CLIF declaration readiness for stable runtime symbols.
#[derive(Clone, Debug, PartialEq)]
pub struct JitRuntimeSymbolDeclarationPreflight {
    declarations: Vec<JitRuntimeSymbolDeclaration>,
    gaps: Vec<JitRuntimeSymbolDeclarationGap>,
}

impl JitRuntimeSymbolDeclarationPreflight {
    fn new(
        declarations: Vec<JitRuntimeSymbolDeclaration>,
        gaps: Vec<JitRuntimeSymbolDeclarationGap>,
    ) -> Self {
        Self { declarations, gaps }
    }

    /// Returns symbols that can currently be declared with CLIF signatures.
    pub fn declarations(&self) -> &[JitRuntimeSymbolDeclaration] {
        &self.declarations
    }

    /// Returns stable symbols that do not yet have CLIF declaration metadata.
    pub fn gaps(&self) -> &[JitRuntimeSymbolDeclarationGap] {
        &self.gaps
    }

    /// Returns true when every stable runtime symbol has declaration metadata.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Returns the declaration for `symbol_name`, when present.
    pub fn declaration_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&JitRuntimeSymbolDeclaration> {
        self.declarations
            .iter()
            .find(|declaration| declaration.symbol_name() == symbol_name)
    }

    /// Returns the declaration gap for `symbol_name`, when present.
    pub fn gap_for_symbol(&self, symbol_name: &str) -> Option<&JitRuntimeSymbolDeclarationGap> {
        self.gaps
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }
}

/// A failure while building JIT-side CLIF declaration metadata.
#[derive(Debug)]
pub enum JitRuntimeSymbolDeclarationError {
    /// Core runtime symbol metadata could not be built.
    SymbolName(RuntimeSymbolNameError),
    /// A frozen runtime-call signature could not be lowered to CLIF.
    ClifSignature {
        /// The stable runtime symbol being declared.
        symbol_name: String,
        /// The underlying CLIF signature conversion failure.
        source: JitClifSignatureError,
    },
}

impl fmt::Display for JitRuntimeSymbolDeclarationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SymbolName(error) => write!(formatter, "{error}"),
            Self::ClifSignature {
                symbol_name,
                source,
            } => write!(
                formatter,
                "runtime symbol {symbol_name:?} could not be declared with a CLIF signature: {source}"
            ),
        }
    }
}

impl Error for JitRuntimeSymbolDeclarationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SymbolName(error) => Some(error),
            Self::ClifSignature { source, .. } => Some(source),
        }
    }
}

impl From<RuntimeSymbolNameError> for JitRuntimeSymbolDeclarationError {
    fn from(error: RuntimeSymbolNameError) -> Self {
        Self::SymbolName(error)
    }
}

/// An opaque native address prepared for future runtime-symbol registration.
///
/// This is address metadata only. The JIT crate stores the non-zero word so
/// registration preflights can prove symbol/name/kind alignment without
/// dereferencing it or converting it to a function pointer. Cranelift setup may
/// pass accepted candidates to `JITBuilder::symbol`, but the metadata layer
/// never calls, validates, or persists the address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitRuntimeSymbolAddress {
    raw: NonZeroUsize,
}

impl JitRuntimeSymbolAddress {
    /// Wraps a non-zero native address word.
    pub const fn new(raw: NonZeroUsize) -> Self {
        Self { raw }
    }

    /// Returns the underlying non-zero native address word.
    pub const fn as_nonzero_usize(self) -> NonZeroUsize {
        self.raw
    }
}

/// Native-address metadata supplied for one stable runtime symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JitRuntimeSymbolAddressCandidate {
    symbol_name: String,
    kind: RuntimeSymbolKind,
    address: JitRuntimeSymbolAddress,
}

impl JitRuntimeSymbolAddressCandidate {
    /// Creates address metadata for a stable runtime symbol.
    pub fn new(
        symbol_name: String,
        kind: RuntimeSymbolKind,
        address: JitRuntimeSymbolAddress,
    ) -> Self {
        Self {
            symbol_name,
            kind,
            address,
        }
    }

    /// Returns the stable runtime symbol name served by the address.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the runtime symbol family served by the address.
    pub const fn kind(&self) -> RuntimeSymbolKind {
        self.kind
    }

    /// Returns the opaque native address metadata.
    pub const fn address(&self) -> JitRuntimeSymbolAddress {
        self.address
    }
}

/// A runtime symbol with both a CLIF declaration and native address metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct JitRuntimeSymbolRegistrationBinding {
    declaration: JitRuntimeSymbolDeclaration,
    address: JitRuntimeSymbolAddress,
}

impl JitRuntimeSymbolRegistrationBinding {
    fn new(declaration: JitRuntimeSymbolDeclaration, address: JitRuntimeSymbolAddress) -> Self {
        Self {
            declaration,
            address,
        }
    }

    /// Returns the stable runtime symbol name ready for future registration.
    pub fn symbol_name(&self) -> &str {
        self.declaration.symbol_name()
    }

    /// Returns the runtime symbol family served by this binding.
    pub const fn kind(&self) -> RuntimeSymbolKind {
        self.declaration.kind()
    }

    /// Returns the CLIF signature that future module imports use.
    pub const fn signature(&self) -> &Signature {
        self.declaration.signature()
    }

    /// Returns the address-free declaration metadata paired with the address.
    pub const fn declaration(&self) -> &JitRuntimeSymbolDeclaration {
        &self.declaration
    }

    /// Returns the opaque native address metadata.
    pub const fn address(&self) -> JitRuntimeSymbolAddress {
        self.address
    }
}

/// One stable runtime symbol that is not ready for native registration.
#[derive(Clone, Debug, PartialEq)]
pub enum JitRuntimeSymbolRegistrationGap {
    /// The symbol still lacks CLIF declaration metadata.
    Declaration(JitRuntimeSymbolDeclarationGap),
    /// The symbol has a CLIF declaration but no native address metadata.
    MissingNativeAddress {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The runtime symbol family that needs an address.
        kind: RuntimeSymbolKind,
    },
    /// Native address metadata was supplied for the wrong symbol family.
    NativeAddressKindMismatch {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The symbol family declared by the CLIF metadata.
        declaration_kind: RuntimeSymbolKind,
        /// The symbol family claimed by the address candidate.
        candidate_kind: RuntimeSymbolKind,
    },
}

impl JitRuntimeSymbolRegistrationGap {
    fn declaration(gap: JitRuntimeSymbolDeclarationGap) -> Self {
        Self::Declaration(gap)
    }

    fn missing_native_address(declaration: &JitRuntimeSymbolDeclaration) -> Self {
        Self::MissingNativeAddress {
            symbol_name: declaration.symbol_name().to_owned(),
            kind: declaration.kind(),
        }
    }

    fn native_address_kind_mismatch(
        declaration: &JitRuntimeSymbolDeclaration,
        candidate: &JitRuntimeSymbolAddressCandidate,
    ) -> Self {
        Self::NativeAddressKindMismatch {
            symbol_name: declaration.symbol_name().to_owned(),
            declaration_kind: declaration.kind(),
            candidate_kind: candidate.kind(),
        }
    }

    /// Returns the stable runtime symbol name for this gap.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::Declaration(gap) => gap.symbol_name(),
            Self::MissingNativeAddress { symbol_name, .. }
            | Self::NativeAddressKindMismatch { symbol_name, .. } => symbol_name,
        }
    }

    /// Returns the runtime symbol family that still blocks registration.
    pub const fn kind(&self) -> RuntimeSymbolKind {
        match self {
            Self::Declaration(gap) => gap.kind(),
            Self::MissingNativeAddress { kind, .. } => *kind,
            Self::NativeAddressKindMismatch {
                declaration_kind, ..
            } => *declaration_kind,
        }
    }

    /// Returns the declaration gap when registration is blocked earlier.
    pub const fn declaration_gap(&self) -> Option<&JitRuntimeSymbolDeclarationGap> {
        match self {
            Self::Declaration(gap) => Some(gap),
            Self::MissingNativeAddress { .. } | Self::NativeAddressKindMismatch { .. } => None,
        }
    }

    /// Returns the missing-address symbol family, when this gap has a declaration.
    pub const fn missing_native_address_kind(&self) -> Option<RuntimeSymbolKind> {
        match self {
            Self::MissingNativeAddress { kind, .. } => Some(*kind),
            Self::Declaration(_) | Self::NativeAddressKindMismatch { .. } => None,
        }
    }
}

/// Runtime-symbol readiness for future `JITBuilder::symbol` registration.
#[derive(Clone, Debug, PartialEq)]
pub struct JitRuntimeSymbolRegistrationPreflight {
    bindings: Vec<JitRuntimeSymbolRegistrationBinding>,
    gaps: Vec<JitRuntimeSymbolRegistrationGap>,
}

impl JitRuntimeSymbolRegistrationPreflight {
    fn new(
        bindings: Vec<JitRuntimeSymbolRegistrationBinding>,
        gaps: Vec<JitRuntimeSymbolRegistrationGap>,
    ) -> Self {
        Self { bindings, gaps }
    }

    /// Returns runtime symbols with declaration and address metadata.
    pub fn bindings(&self) -> &[JitRuntimeSymbolRegistrationBinding] {
        &self.bindings
    }

    /// Returns stable runtime symbols not ready for native registration.
    pub fn gaps(&self) -> &[JitRuntimeSymbolRegistrationGap] {
        &self.gaps
    }

    /// Returns true when every stable runtime symbol has registration metadata.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Returns the registration binding for `symbol_name`, when present.
    pub fn binding_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&JitRuntimeSymbolRegistrationBinding> {
        self.bindings
            .iter()
            .find(|binding| binding.symbol_name() == symbol_name)
    }

    /// Returns the registration gap for `symbol_name`, when present.
    pub fn gap_for_symbol(&self, symbol_name: &str) -> Option<&JitRuntimeSymbolRegistrationGap> {
        self.gaps
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }

    /// Converts a complete preflight into registration metadata.
    ///
    /// # Errors
    ///
    /// Returns [`JitRuntimeSymbolRegistrationPlanError::Incomplete`] when any
    /// runtime symbol still lacks registration metadata.
    pub fn into_registration_plan(
        self,
    ) -> Result<JitRuntimeSymbolRegistrationPlan, JitRuntimeSymbolRegistrationPlanError> {
        let missing_count = self.gaps.len();
        if missing_count == 0 {
            Ok(JitRuntimeSymbolRegistrationPlan::new(self.bindings))
        } else {
            Err(JitRuntimeSymbolRegistrationPlanError::Incomplete {
                missing_count,
                preflight: self,
            })
        }
    }
}

/// Complete runtime-symbol metadata for a future `JITBuilder::symbol` pass.
#[derive(Clone, Debug, PartialEq)]
pub struct JitRuntimeSymbolRegistrationPlan {
    bindings: Vec<JitRuntimeSymbolRegistrationBinding>,
}

impl JitRuntimeSymbolRegistrationPlan {
    fn new(bindings: Vec<JitRuntimeSymbolRegistrationBinding>) -> Self {
        Self { bindings }
    }

    /// Returns runtime-symbol bindings in stable manifest order.
    pub fn bindings(&self) -> &[JitRuntimeSymbolRegistrationBinding] {
        &self.bindings
    }

    /// Returns the registration binding for `symbol_name`, when present.
    pub fn binding_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&JitRuntimeSymbolRegistrationBinding> {
        self.bindings
            .iter()
            .find(|binding| binding.symbol_name() == symbol_name)
    }
}

/// A failure while building native runtime-symbol registration metadata.
#[derive(Debug)]
pub enum JitRuntimeSymbolRegistrationError {
    /// CLIF declaration metadata could not be built.
    Declaration(JitRuntimeSymbolDeclarationError),
    /// More than one native address candidate was supplied for one symbol.
    DuplicateAddressCandidate {
        /// The duplicated stable runtime symbol name.
        symbol_name: String,
    },
    /// A native address candidate named a symbol outside the runtime manifest.
    UnknownAddressCandidate {
        /// The unknown runtime symbol name.
        symbol_name: String,
    },
}

impl fmt::Display for JitRuntimeSymbolRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declaration(error) => write!(formatter, "{error}"),
            Self::DuplicateAddressCandidate { symbol_name } => write!(
                formatter,
                "runtime symbol {symbol_name:?} has duplicate native address candidates"
            ),
            Self::UnknownAddressCandidate { symbol_name } => write!(
                formatter,
                "native address candidate {symbol_name:?} is not a stable runtime symbol"
            ),
        }
    }
}

impl Error for JitRuntimeSymbolRegistrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Declaration(error) => Some(error),
            Self::DuplicateAddressCandidate { .. } | Self::UnknownAddressCandidate { .. } => None,
        }
    }
}

impl From<JitRuntimeSymbolDeclarationError> for JitRuntimeSymbolRegistrationError {
    fn from(error: JitRuntimeSymbolDeclarationError) -> Self {
        Self::Declaration(error)
    }
}

/// A failure while building complete native runtime-symbol registration metadata.
#[derive(Debug)]
pub enum JitRuntimeSymbolRegistrationPlanError {
    /// Registration preflight metadata could not be built.
    Registration(JitRuntimeSymbolRegistrationError),
    /// Some runtime symbols cannot yet be registered with native addresses.
    Incomplete {
        /// The number of runtime symbols still missing registration metadata.
        missing_count: usize,
        /// The preserved preflight report, including ready bindings and gaps.
        preflight: JitRuntimeSymbolRegistrationPreflight,
    },
}

impl fmt::Display for JitRuntimeSymbolRegistrationPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registration(error) => write!(formatter, "{error}"),
            Self::Incomplete { missing_count, .. } => write!(
                formatter,
                "runtime symbol native registration metadata is incomplete: {missing_count} symbol(s) missing"
            ),
        }
    }
}

impl Error for JitRuntimeSymbolRegistrationPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Registration(error) => Some(error),
            Self::Incomplete { .. } => None,
        }
    }
}

impl From<JitRuntimeSymbolRegistrationError> for JitRuntimeSymbolRegistrationPlanError {
    fn from(error: JitRuntimeSymbolRegistrationError) -> Self {
        Self::Registration(error)
    }
}

/// Builds address-free CLIF declaration readiness for stable runtime symbols.
///
/// Callable builtin symbols receive CLIF signatures from the frozen core primop
/// ABI. Runtime helpers whose ABI shapes are core-owned receive helper CLIF
/// signatures. Helpers without core-owned shapes and value-only builtin symbols
/// remain explicit gaps, because this crate still has no executable addresses to
/// register.
///
/// # Errors
///
/// Returns [`JitRuntimeSymbolDeclarationError::SymbolName`] if core symbol
/// metadata cannot be built. Returns
/// [`JitRuntimeSymbolDeclarationError::ClifSignature`] if a callable builtin or
/// core-owned helper signature cannot be lowered to CLIF on this host.
pub fn jit_runtime_symbol_declaration_preflight()
-> Result<JitRuntimeSymbolDeclarationPreflight, JitRuntimeSymbolDeclarationError> {
    let manifest = runtime_symbol_manifest()?;
    let builtin_call_preflight = runtime_builtin_call_preflight()?;
    let builtin_bindings = builtin_bindings_by_symbol(builtin_call_preflight.call_bindings());
    let builtin_gaps = builtin_gaps_by_symbol(builtin_call_preflight.missing_bindings());

    let mut declarations = Vec::new();
    let mut gaps = Vec::new();

    for symbol in manifest {
        match symbol.kind() {
            RuntimeSymbolKind::Helper(role) => {
                if let Some(signature) = runtime_helper_call_signature(symbol.name()) {
                    declarations.push(declaration_for_helper_signature(
                        symbol.name(),
                        role,
                        signature,
                    )?);
                } else {
                    gaps.push(JitRuntimeSymbolDeclarationGap::helper(
                        symbol.name().to_owned(),
                        role,
                    ));
                }
            }
            RuntimeSymbolKind::Builtin => {
                if let Some(binding) = builtin_bindings.get(symbol.name()) {
                    declarations.push(declaration_for_builtin_binding(binding)?);
                } else if let Some(gap) = builtin_gaps.get(symbol.name()) {
                    gaps.push(JitRuntimeSymbolDeclarationGap::from_builtin_missing(gap));
                } else {
                    gaps.push(
                        JitRuntimeSymbolDeclarationGap::builtin_without_call_metadata(
                            symbol.name().to_owned(),
                        ),
                    );
                }
            }
        }
    }

    Ok(JitRuntimeSymbolDeclarationPreflight::new(
        declarations,
        gaps,
    ))
}

/// Builds native registration readiness with no installed address candidates.
///
/// The report consumes the CLIF declaration preflight and preserves stable
/// runtime-symbol order. In the current safe scaffold no native address table is
/// installed, so every declaration becomes a missing-address gap while
/// declaration gaps are preserved. This does not call `JITBuilder::symbol`,
/// expose raw function pointers, or dereference address metadata.
///
/// # Errors
///
/// Returns [`JitRuntimeSymbolRegistrationError::Declaration`] if runtime-symbol
/// declaration metadata cannot be built.
pub fn jit_runtime_symbol_registration_preflight()
-> Result<JitRuntimeSymbolRegistrationPreflight, JitRuntimeSymbolRegistrationError> {
    jit_runtime_symbol_registration_preflight_with_candidates(&[])
}

/// Builds native registration readiness from explicit address candidates.
///
/// The report joins stable CLIF declarations with supplied native address
/// metadata and preserves runtime-symbol manifest order. Declaration gaps,
/// missing address candidates, and symbol-kind mismatches remain explicit gaps.
/// This does not call `JITBuilder::symbol`, expose raw function pointers, or
/// dereference address metadata.
///
/// # Errors
///
/// Returns [`JitRuntimeSymbolRegistrationError::Declaration`] if runtime-symbol
/// declaration metadata cannot be built. Returns
/// [`JitRuntimeSymbolRegistrationError::DuplicateAddressCandidate`] when two
/// address candidates name the same runtime symbol. Returns
/// [`JitRuntimeSymbolRegistrationError::UnknownAddressCandidate`] when an
/// address candidate names a symbol outside the stable runtime manifest.
pub fn jit_runtime_symbol_registration_preflight_with_candidates(
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitRuntimeSymbolRegistrationPreflight, JitRuntimeSymbolRegistrationError> {
    let declaration_preflight = jit_runtime_symbol_declaration_preflight()?;
    Ok(project_runtime_symbol_registration_preflight(
        &declaration_preflight,
        candidates,
    )?)
}

/// Builds complete native registration metadata with no installed address table.
///
/// This strict gate currently returns an incomplete error because no safe
/// native address candidates are installed and declaration gaps remain.
///
/// # Errors
///
/// Returns [`JitRuntimeSymbolRegistrationPlanError::Registration`] if the
/// registration preflight cannot be built. Returns
/// [`JitRuntimeSymbolRegistrationPlanError::Incomplete`] while any runtime
/// symbol lacks declaration or address metadata.
pub fn jit_runtime_symbol_registration_plan()
-> Result<JitRuntimeSymbolRegistrationPlan, JitRuntimeSymbolRegistrationPlanError> {
    jit_runtime_symbol_registration_plan_with_candidates(&[])
}

/// Builds complete native registration metadata from explicit address candidates.
///
/// # Errors
///
/// Returns [`JitRuntimeSymbolRegistrationPlanError::Registration`] if the
/// registration preflight cannot be built. Returns
/// [`JitRuntimeSymbolRegistrationPlanError::Incomplete`] while any runtime
/// symbol lacks declaration or address metadata.
pub fn jit_runtime_symbol_registration_plan_with_candidates(
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitRuntimeSymbolRegistrationPlan, JitRuntimeSymbolRegistrationPlanError> {
    let preflight = jit_runtime_symbol_registration_preflight_with_candidates(candidates)?;
    Ok(preflight.into_registration_plan()?)
}

fn project_runtime_symbol_registration_preflight(
    declaration_preflight: &JitRuntimeSymbolDeclarationPreflight,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitRuntimeSymbolRegistrationPreflight, JitRuntimeSymbolRegistrationError> {
    let declarations = declarations_by_symbol(declaration_preflight.declarations());
    let declaration_gaps = declaration_gaps_by_symbol(declaration_preflight.gaps());
    let address_candidates = address_candidates_by_symbol(candidates)?;
    let manifest = runtime_symbol_manifest().map_err(JitRuntimeSymbolDeclarationError::from)?;
    let manifest_symbols = manifest
        .iter()
        .map(|symbol| (symbol.name(), ()))
        .collect::<BTreeMap<_, _>>();
    let mut bindings = Vec::new();
    let mut gaps = Vec::new();

    for candidate in candidates {
        if !manifest_symbols.contains_key(candidate.symbol_name()) {
            return Err(JitRuntimeSymbolRegistrationError::UnknownAddressCandidate {
                symbol_name: candidate.symbol_name().to_owned(),
            });
        }
    }

    for symbol in manifest {
        if let Some(declaration) = declarations.get(symbol.name()) {
            if let Some(candidate) = address_candidates.get(symbol.name()) {
                if candidate.kind() == declaration.kind() {
                    bindings.push(JitRuntimeSymbolRegistrationBinding::new(
                        (*declaration).clone(),
                        candidate.address(),
                    ));
                } else {
                    gaps.push(
                        JitRuntimeSymbolRegistrationGap::native_address_kind_mismatch(
                            declaration,
                            candidate,
                        ),
                    );
                }
            } else {
                gaps.push(JitRuntimeSymbolRegistrationGap::missing_native_address(
                    declaration,
                ));
            }
        } else if let Some(gap) = declaration_gaps.get(symbol.name()) {
            gaps.push(JitRuntimeSymbolRegistrationGap::declaration((*gap).clone()));
        }
    }

    Ok(JitRuntimeSymbolRegistrationPreflight::new(bindings, gaps))
}

fn builtin_bindings_by_symbol(
    bindings: &[RuntimeBuiltinCallBinding],
) -> BTreeMap<&str, &RuntimeBuiltinCallBinding> {
    bindings
        .iter()
        .map(|binding| (binding.symbol_name(), binding))
        .collect()
}

fn builtin_gaps_by_symbol(
    gaps: &[RuntimeBuiltinCallMissingBinding],
) -> BTreeMap<&str, &RuntimeBuiltinCallMissingBinding> {
    gaps.iter().map(|gap| (gap.symbol_name(), gap)).collect()
}

fn declarations_by_symbol(
    declarations: &[JitRuntimeSymbolDeclaration],
) -> BTreeMap<&str, &JitRuntimeSymbolDeclaration> {
    declarations
        .iter()
        .map(|declaration| (declaration.symbol_name(), declaration))
        .collect()
}

fn declaration_gaps_by_symbol(
    gaps: &[JitRuntimeSymbolDeclarationGap],
) -> BTreeMap<&str, &JitRuntimeSymbolDeclarationGap> {
    gaps.iter().map(|gap| (gap.symbol_name(), gap)).collect()
}

fn address_candidates_by_symbol(
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<BTreeMap<&str, &JitRuntimeSymbolAddressCandidate>, JitRuntimeSymbolRegistrationError> {
    let mut candidates_by_symbol = BTreeMap::new();

    for candidate in candidates {
        if candidates_by_symbol
            .insert(candidate.symbol_name(), candidate)
            .is_some()
        {
            return Err(
                JitRuntimeSymbolRegistrationError::DuplicateAddressCandidate {
                    symbol_name: candidate.symbol_name().to_owned(),
                },
            );
        }
    }

    Ok(candidates_by_symbol)
}

fn declaration_for_builtin_binding(
    binding: &RuntimeBuiltinCallBinding,
) -> Result<JitRuntimeSymbolDeclaration, JitRuntimeSymbolDeclarationError> {
    declaration_for_runtime_signature(
        binding.symbol_name(),
        RuntimeSymbolKind::Builtin,
        binding.signature(),
    )
}

fn declaration_for_helper_signature(
    symbol_name: &str,
    role: RuntimeHelperRole,
    signature: RuntimeCallSignature,
) -> Result<JitRuntimeSymbolDeclaration, JitRuntimeSymbolDeclarationError> {
    declaration_for_runtime_signature(symbol_name, RuntimeSymbolKind::Helper(role), signature)
}

fn declaration_for_runtime_signature(
    symbol_name: &str,
    kind: RuntimeSymbolKind,
    runtime_signature: RuntimeCallSignature,
) -> Result<JitRuntimeSymbolDeclaration, JitRuntimeSymbolDeclarationError> {
    let signature = clif_signature_for_runtime_call(runtime_signature).map_err(|source| {
        JitRuntimeSymbolDeclarationError::ClifSignature {
            symbol_name: symbol_name.to_owned(),
            source,
        }
    })?;

    Ok(JitRuntimeSymbolDeclaration::new(
        symbol_name.to_owned(),
        kind,
        signature,
    ))
}

#[cfg(test)]
mod tests;
