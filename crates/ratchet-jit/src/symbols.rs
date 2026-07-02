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
mod tests {
    use std::num::NonZeroUsize;

    use ratchet_core::{
        RuntimeCallableKind, RuntimeHelperRole, RuntimeSymbolKind, runtime_builtin_call_preflight,
        runtime_helper_call_signature, runtime_helper_call_signatures,
        runtime_primop_call_signature, runtime_symbol_manifest,
    };

    use super::*;
    use crate::abi::clif_signature_for_runtime_call;

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
    fn jit_runtime_symbol_inventory_mirrors_core_manifest() {
        let inventory =
            jit_runtime_symbol_inventory().expect("JIT runtime symbol inventory builds");
        let core_manifest = runtime_symbol_manifest().expect("core runtime symbol manifest builds");

        assert_eq!(inventory.symbols(), core_manifest.as_slice());
    }

    #[test]
    fn jit_runtime_symbol_inventory_preserves_representative_kinds() {
        let inventory =
            jit_runtime_symbol_inventory().expect("JIT runtime symbol inventory builds");

        assert!(inventory.contains_symbol("aos_alloc_attrs"));
        assert_eq!(
            inventory.symbol_kind("aos_alloc_attrs"),
            Some(RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation))
        );
        assert!(inventory.contains_symbol("nix.builtin.derivationStrict"));
        assert_eq!(
            inventory.symbol_kind("nix.builtin.derivationStrict"),
            Some(RuntimeSymbolKind::Builtin)
        );
        assert_eq!(inventory.symbol_kind("missing.runtime.symbol"), None);
    }

    #[test]
    fn jit_runtime_symbol_inventory_keeps_core_ordering() {
        let inventory =
            jit_runtime_symbol_inventory().expect("JIT runtime symbol inventory builds");

        assert!(
            inventory
                .symbols()
                .windows(2)
                .all(|window| window[0].name() < window[1].name())
        );
        assert!(
            inventory
                .symbols()
                .iter()
                .any(|symbol| matches!(symbol.kind(), RuntimeSymbolKind::Builtin))
        );
        assert!(
            inventory
                .symbols()
                .iter()
                .any(|symbol| matches!(symbol.kind(), RuntimeSymbolKind::Helper(_)))
        );
    }

    #[test]
    fn jit_runtime_symbol_declaration_preflight_declares_callable_builtins() {
        let preflight = jit_runtime_symbol_declaration_preflight()
            .expect("JIT symbol declaration preflight builds");
        let declaration = preflight
            .declaration_for_symbol("nix.builtin.derivationStrict")
            .expect("callable builtin has a CLIF declaration");
        let expected_signature = clif_signature_for_runtime_call(
            runtime_primop_call_signature(1).expect("arity lowers"),
        )
        .expect("arity 1 CLIF signature lowers");

        assert_eq!(declaration.symbol_name(), "nix.builtin.derivationStrict");
        assert_eq!(declaration.kind(), RuntimeSymbolKind::Builtin);
        assert_eq!(declaration.signature(), &expected_signature);
    }

    #[test]
    fn jit_runtime_symbol_declaration_preflight_declares_core_owned_helpers() {
        let preflight = jit_runtime_symbol_declaration_preflight()
            .expect("JIT symbol declaration preflight builds");
        let allocation_declaration = preflight
            .declaration_for_symbol("aos_alloc_attrs")
            .expect("core-owned allocation helper has a CLIF declaration");
        let apply_declaration = preflight
            .declaration_for_symbol("aos_apply")
            .expect("core-owned apply helper has a CLIF declaration");
        let deopt_declaration = preflight
            .declaration_for_symbol("aos_deopt")
            .expect("core-owned deopt helper has a CLIF declaration");
        let env_get_declaration = preflight
            .declaration_for_symbol("aos_env_get")
            .expect("core-owned environment helper has a CLIF declaration");
        let write_barrier_declaration = preflight
            .declaration_for_symbol("aos_gc_write_barrier")
            .expect("core-owned write-barrier helper has a CLIF declaration");
        let force_declaration = preflight
            .declaration_for_symbol("aos_force")
            .expect("core-owned force helper has a CLIF declaration");
        let force_deep_declaration = preflight
            .declaration_for_symbol("aos_force_deep")
            .expect("core-owned deep-force helper has a CLIF declaration");
        let blackhole_check_declaration = preflight
            .declaration_for_symbol("aos_blackhole_check")
            .expect("core-owned blackhole-check helper has a CLIF declaration");
        let has_attr_declaration = preflight
            .declaration_for_symbol("aos_has_attr")
            .expect("core-owned has-attr helper has a CLIF declaration");
        let select_ic_declaration = preflight
            .declaration_for_symbol("aos_select_ic")
            .expect("core-owned select-IC helper has a CLIF declaration");
        let update_declaration = preflight
            .declaration_for_symbol("aos_update")
            .expect("core-owned update helper has a CLIF declaration");
        let throw_declaration = preflight
            .declaration_for_symbol("aos_throw")
            .expect("core-owned throw helper has a CLIF declaration");
        let expected_allocation = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_alloc_attrs")
                .expect("allocation helper signature is core-owned"),
        )
        .expect("allocation helper signature lowers");
        let expected_apply = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_apply")
                .expect("apply helper signature is core-owned"),
        )
        .expect("apply helper signature lowers");
        let expected_deopt = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_deopt")
                .expect("deopt helper signature is core-owned"),
        )
        .expect("deopt helper signature lowers");
        let expected_env_get = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_env_get")
                .expect("environment helper signature is core-owned"),
        )
        .expect("environment helper signature lowers");
        let expected_write_barrier = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_gc_write_barrier")
                .expect("write-barrier helper signature is core-owned"),
        )
        .expect("write-barrier helper signature lowers");
        let expected_force = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_force")
                .expect("force helper signature is core-owned"),
        )
        .expect("force helper signature lowers");
        let expected_force_deep = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_force_deep")
                .expect("deep-force helper signature is core-owned"),
        )
        .expect("deep-force helper signature lowers");
        let expected_blackhole_check = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_blackhole_check")
                .expect("blackhole-check helper signature is core-owned"),
        )
        .expect("blackhole-check helper signature lowers");
        let expected_has_attr = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_has_attr")
                .expect("has-attr helper signature is core-owned"),
        )
        .expect("has-attr helper signature lowers");
        let expected_select_ic = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_select_ic")
                .expect("select-IC helper signature is core-owned"),
        )
        .expect("select-IC helper signature lowers");
        let expected_update = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_update")
                .expect("update helper signature is core-owned"),
        )
        .expect("update helper signature lowers");
        let expected_throw = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_throw")
                .expect("throw helper signature is core-owned"),
        )
        .expect("throw helper signature lowers");

        assert_eq!(
            allocation_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation)
        );
        assert_eq!(allocation_declaration.signature(), &expected_allocation);
        assert_eq!(
            apply_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl)
        );
        assert_eq!(apply_declaration.signature(), &expected_apply);
        assert_eq!(
            deopt_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::Deoptimization)
        );
        assert_eq!(deopt_declaration.signature(), &expected_deopt);
        assert_eq!(
            env_get_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess)
        );
        assert_eq!(env_get_declaration.signature(), &expected_env_get);
        assert_eq!(
            write_barrier_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::WriteBarrier)
        );
        assert_eq!(
            write_barrier_declaration.signature(),
            &expected_write_barrier
        );
        assert_eq!(
            force_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
        );
        assert_eq!(force_declaration.signature(), &expected_force);
        assert_eq!(
            force_deep_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
        );
        assert_eq!(force_deep_declaration.signature(), &expected_force_deep);
        assert_eq!(
            blackhole_check_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl)
        );
        assert_eq!(
            blackhole_check_declaration.signature(),
            &expected_blackhole_check
        );
        assert_eq!(
            has_attr_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
        );
        assert_eq!(has_attr_declaration.signature(), &expected_has_attr);
        assert_eq!(
            select_ic_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
        );
        assert_eq!(select_ic_declaration.signature(), &expected_select_ic);
        assert_eq!(
            update_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess)
        );
        assert_eq!(update_declaration.signature(), &expected_update);
        assert_eq!(
            throw_declaration.kind(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ErrorControl)
        );
        assert_eq!(throw_declaration.signature(), &expected_throw);
        assert!(preflight.gap_for_symbol("aos_alloc_attrs").is_none());
        assert!(preflight.gap_for_symbol("aos_apply").is_none());
        assert!(preflight.gap_for_symbol("aos_deopt").is_none());
        assert!(preflight.gap_for_symbol("aos_env_get").is_none());
        assert!(preflight.gap_for_symbol("aos_gc_write_barrier").is_none());
        assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
        assert!(preflight.gap_for_symbol("aos_force").is_none());
        assert!(preflight.gap_for_symbol("aos_force_deep").is_none());
        assert!(preflight.gap_for_symbol("aos_has_attr").is_none());
        assert!(preflight.gap_for_symbol("aos_select_ic").is_none());
        assert!(preflight.gap_for_symbol("aos_update").is_none());
        assert!(preflight.gap_for_symbol("aos_throw").is_none());
    }

    #[test]
    fn jit_runtime_symbol_declaration_preflight_reports_unshaped_helper_gaps() {
        let preflight = jit_runtime_symbol_declaration_preflight()
            .expect("JIT symbol declaration preflight builds");

        for (symbol_name, role) in [
            ("aos_try_begin", RuntimeHelperRole::ErrorControl),
            ("aos_try_end", RuntimeHelperRole::ErrorControl),
        ] {
            assert!(matches!(
                preflight.gap_for_symbol(symbol_name),
                Some(
                    JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                        role: gap_role,
                        ..
                    }
                ) if *gap_role == role
            ));
            assert!(preflight.declaration_for_symbol(symbol_name).is_none());
        }
    }

    #[test]
    fn jit_runtime_symbol_declaration_preflight_reports_value_only_builtin_gaps() {
        let preflight = jit_runtime_symbol_declaration_preflight()
            .expect("JIT symbol declaration preflight builds");

        assert!(matches!(
            preflight.gap_for_symbol("nix.builtin.true"),
            Some(JitRuntimeSymbolDeclarationGap::BuiltinValueOnly {
                builtin_name: b"true",
                ..
            })
        ));
        assert!(
            preflight
                .declaration_for_symbol("nix.builtin.true")
                .is_none()
        );
    }

    #[test]
    fn jit_runtime_symbol_declaration_preflight_matches_core_builtin_call_counts() {
        let preflight = jit_runtime_symbol_declaration_preflight()
            .expect("JIT symbol declaration preflight builds");
        let builtin_preflight =
            runtime_builtin_call_preflight().expect("core builtin call preflight builds");

        assert!(!preflight.is_complete());
        assert_eq!(
            preflight.declarations().len(),
            builtin_preflight.call_bindings().len() + runtime_helper_call_signatures().len()
        );
        for binding in builtin_preflight.call_bindings() {
            assert!(
                preflight
                    .declaration_for_symbol(binding.symbol_name())
                    .is_some(),
                "{} has a JIT CLIF declaration",
                binding.symbol_name()
            );
        }
        for signature in runtime_helper_call_signatures() {
            let RuntimeCallableKind::Helper { symbol } = signature.callable() else {
                panic!("helper signature uses helper callable kind");
            };
            assert!(
                preflight.declaration_for_symbol(symbol.name()).is_some(),
                "{} has a JIT CLIF declaration",
                symbol.name()
            );
        }
    }

    #[test]
    fn jit_runtime_symbol_registration_preflight_reports_missing_native_addresses() {
        let declaration_preflight = jit_runtime_symbol_declaration_preflight()
            .expect("JIT symbol declaration preflight builds");
        let preflight = jit_runtime_symbol_registration_preflight()
            .expect("JIT symbol registration preflight builds");

        assert!(preflight.bindings().is_empty());
        assert!(!preflight.is_complete());
        assert_eq!(
            preflight.gaps().len(),
            declaration_preflight.declarations().len() + declaration_preflight.gaps().len()
        );
        assert!(matches!(
            preflight.gap_for_symbol("aos_alloc_attrs"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
                ..
            })
        ));
        assert!(matches!(
            preflight.gap_for_symbol("aos_apply"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl),
                ..
            })
        ));
        assert!(matches!(
            preflight.gap_for_symbol("aos_deopt"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Deoptimization),
                ..
            })
        ));
        assert!(matches!(
            preflight.gap_for_symbol("aos_env_get"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                ..
            })
        ));
        assert!(matches!(
            preflight.gap_for_symbol("nix.builtin.derivationStrict"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Builtin,
                ..
            })
        ));
        assert!(matches!(
            preflight.gap_for_symbol("aos_force"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                ..
            })
        ));
        assert!(matches!(
            preflight.gap_for_symbol("aos_has_attr"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
                ..
            })
        ));
        assert!(matches!(
            preflight.gap_for_symbol("aos_select_ic"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
                ..
            })
        ));
        assert!(matches!(
            preflight.gap_for_symbol("aos_update"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
                ..
            })
        ));
        assert!(matches!(
            preflight.gap_for_symbol("aos_throw"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ErrorControl),
                ..
            })
        ));
    }

    #[test]
    fn jit_runtime_symbol_registration_preflight_binds_synthetic_candidates_in_manifest_order() {
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
        let preflight = jit_runtime_symbol_registration_preflight_with_candidates(&candidates)
            .expect("JIT symbol registration preflight builds");
        let binding_symbols = preflight
            .bindings()
            .iter()
            .map(JitRuntimeSymbolRegistrationBinding::symbol_name)
            .collect::<Vec<_>>();

        assert_eq!(
            binding_symbols,
            vec![
                "aos_alloc_attrs",
                "aos_env_get",
                "nix.builtin.derivationStrict"
            ]
        );
        assert_eq!(
            preflight
                .binding_for_symbol("aos_alloc_attrs")
                .expect("allocation helper candidate binds")
                .address()
                .as_nonzero_usize()
                .get(),
            1
        );
        assert!(preflight.gap_for_symbol("aos_alloc_attrs").is_none());
        assert_eq!(
            preflight
                .binding_for_symbol("aos_env_get")
                .expect("environment helper candidate binds")
                .address()
                .as_nonzero_usize()
                .get(),
            3
        );
        assert!(preflight.gap_for_symbol("aos_env_get").is_none());
        assert!(matches!(
            preflight.gap_for_symbol("aos_force"),
            Some(JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                ..
            })
        ));
    }

    #[test]
    fn jit_runtime_symbol_registration_preflight_reports_kind_mismatches() {
        let candidates = [synthetic_address_candidate(
            "aos_alloc_attrs",
            RuntimeSymbolKind::Builtin,
            1,
        )];
        let preflight = jit_runtime_symbol_registration_preflight_with_candidates(&candidates)
            .expect("JIT symbol registration preflight builds");

        assert!(preflight.binding_for_symbol("aos_alloc_attrs").is_none());
        assert!(matches!(
            preflight.gap_for_symbol("aos_alloc_attrs"),
            Some(JitRuntimeSymbolRegistrationGap::NativeAddressKindMismatch {
                declaration_kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
                candidate_kind: RuntimeSymbolKind::Builtin,
                ..
            })
        ));
    }

    #[test]
    fn jit_runtime_symbol_registration_preflight_keeps_declaration_gaps_before_addresses() {
        let candidates = [
            synthetic_address_candidate(
                "aos_blackhole_check",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                1,
            ),
            synthetic_address_candidate(
                "aos_has_attr",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
                2,
            ),
            synthetic_address_candidate(
                "aos_try_begin",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::ErrorControl),
                3,
            ),
            synthetic_address_candidate(
                "aos_try_end",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::ErrorControl),
                4,
            ),
            synthetic_address_candidate(
                "aos_update",
                RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
                5,
            ),
        ];
        let preflight = jit_runtime_symbol_registration_preflight_with_candidates(&candidates)
            .expect("JIT symbol registration preflight builds");

        for (symbol_name, role) in [
            ("aos_try_begin", RuntimeHelperRole::ErrorControl),
            ("aos_try_end", RuntimeHelperRole::ErrorControl),
        ] {
            assert!(preflight.binding_for_symbol(symbol_name).is_none());
            assert!(matches!(
                preflight.gap_for_symbol(symbol_name),
                Some(JitRuntimeSymbolRegistrationGap::Declaration(
                    JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                        role: gap_role,
                        ..
                    }
                )) if *gap_role == role
            ));
        }
        assert!(
            preflight
                .binding_for_symbol("aos_blackhole_check")
                .is_some()
        );
        assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
        assert!(preflight.binding_for_symbol("aos_has_attr").is_some());
        assert!(preflight.gap_for_symbol("aos_has_attr").is_none());
        assert!(preflight.binding_for_symbol("aos_update").is_some());
        assert!(preflight.gap_for_symbol("aos_update").is_none());
    }

    #[test]
    fn jit_runtime_symbol_registration_preflight_rejects_duplicate_candidates() {
        let candidates = [
            synthetic_address_candidate("aos_alloc_attrs", RuntimeSymbolKind::Builtin, 1),
            synthetic_address_candidate("aos_alloc_attrs", RuntimeSymbolKind::Builtin, 2),
        ];
        let Err(error) = jit_runtime_symbol_registration_preflight_with_candidates(&candidates)
        else {
            panic!("duplicate address candidates must be rejected");
        };

        assert!(matches!(
            error,
            JitRuntimeSymbolRegistrationError::DuplicateAddressCandidate { symbol_name }
                if symbol_name == "aos_alloc_attrs"
        ));
    }

    #[test]
    fn jit_runtime_symbol_registration_preflight_rejects_unknown_candidates() {
        let candidates = [synthetic_address_candidate(
            "aos_not_a_runtime_symbol",
            RuntimeSymbolKind::Builtin,
            1,
        )];
        let Err(error) = jit_runtime_symbol_registration_preflight_with_candidates(&candidates)
        else {
            panic!("unknown address candidates must be rejected");
        };

        assert!(matches!(
            error,
            JitRuntimeSymbolRegistrationError::UnknownAddressCandidate { symbol_name }
                if symbol_name == "aos_not_a_runtime_symbol"
        ));
    }

    #[test]
    fn jit_runtime_symbol_registration_plan_refuses_current_address_gaps() {
        let Err(error) = jit_runtime_symbol_registration_plan() else {
            panic!("missing native addresses must block complete registration plans");
        };

        let JitRuntimeSymbolRegistrationPlanError::Incomplete {
            missing_count,
            preflight,
        } = error
        else {
            panic!("expected incomplete registration plan");
        };

        assert_eq!(missing_count, preflight.gaps().len());
        assert!(preflight.gap_for_symbol("aos_alloc_attrs").is_some());
        assert!(
            preflight
                .gap_for_symbol("nix.builtin.derivationStrict")
                .is_some()
        );
    }

    #[test]
    fn jit_runtime_symbol_registration_preflight_converts_synthetic_complete_report_to_plan() {
        let declaration_preflight = jit_runtime_symbol_declaration_preflight()
            .expect("JIT symbol declaration preflight builds");
        let declaration = declaration_preflight
            .declaration_for_symbol("aos_alloc_attrs")
            .expect("allocation helper declaration exists")
            .clone();
        let binding = JitRuntimeSymbolRegistrationBinding::new(declaration, synthetic_address(1));
        let preflight = JitRuntimeSymbolRegistrationPreflight::new(vec![binding.clone()], vec![]);
        let plan = preflight
            .into_registration_plan()
            .expect("synthetic complete registration preflight converts");

        assert_eq!(plan.bindings(), &[binding]);
        assert!(plan.binding_for_symbol("aos_alloc_attrs").is_some());
    }
}
