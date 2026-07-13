//! Stable runtime ABI metadata for future native tiers.
//!
//! The safe tree-walk evaluator does not register Cranelift symbols, but the
//! compile metadata already owns the frozen names and call shapes that persisted
//! compiled-IR artifacts will reference. Builtins use `nix.builtin.<name>` and
//! runtime helpers use `aos_<verb>[_<qualifier>]`, matching RFC-0007 §10. The
//! call-signature descriptors in this module are contract metadata only; they do
//! not export wrappers, create raw-pointer call boundaries, or register a JIT
//! symbol table.

use std::{collections::BTreeSet, str};

use thiserror::Error;

use crate::builtins::BUILTINS;

mod stack_map;
mod value_layout;
mod signature_tables;
pub use value_layout::{
    RuntimeAbiValueLayout, candidate_b_runtime_abi_value_layout,
    candidate_c_runtime_abi_value_layout, runtime_abi_value_layout,
};
pub use signature_tables::{
    MAX_RUNTIME_PRIMOP_ABI_ARITY, RUNTIME_HELPER_CALL_SIGNATURES, RUNTIME_LAMBDA_ARGV_CALL_SIGNATURE, RUNTIME_LAMBDA_CALL_SIGNATURE,
    RUNTIME_PRIMOP_CALL_SIGNATURES, RUNTIME_THUNK_CALL_SIGNATURE, runtime_helper_call_signature,
    runtime_helper_call_signatures, runtime_lambda_argv_call_signature,
    runtime_lambda_call_signature, runtime_primop_call_signature, runtime_primop_call_signatures,
    runtime_thunk_call_signature,
};

/// The stable prefix for builtin runtime symbol names.
pub const BUILTIN_SYMBOL_PREFIX: &str = "nix.builtin.";

/// The stable prefix for non-builtin runtime helper symbols.
pub const RUNTIME_HELPER_SYMBOL_PREFIX: &str = "aos_";

/// A stable builtin runtime symbol name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltinRuntimeSymbol {
    name: &'static [u8],
}

impl BuiltinRuntimeSymbol {
    /// Creates a stable runtime symbol view for a builtin declaration name.
    pub(crate) const fn new(name: &'static [u8]) -> Self {
        Self { name }
    }

    /// Returns the common `nix.builtin.` prefix.
    pub const fn prefix(self) -> &'static str {
        BUILTIN_SYMBOL_PREFIX
    }

    /// Returns the Nix-visible builtin name suffix.
    pub const fn builtin_name(self) -> &'static [u8] {
        self.name
    }

    /// Returns the stable symbol as owned text.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSymbolNameError::NonUtf8BuiltinName`] if the builtin
    /// name suffix cannot be represented as UTF-8 for a future string-keyed JIT
    /// symbol table.
    pub fn to_symbol_string(self) -> Result<String, RuntimeSymbolNameError> {
        let name = str::from_utf8(self.name).map_err(|source| {
            RuntimeSymbolNameError::NonUtf8BuiltinName {
                name: self.name.into(),
                source,
            }
        })?;
        let mut symbol = String::with_capacity(BUILTIN_SYMBOL_PREFIX.len() + name.len());
        symbol.push_str(BUILTIN_SYMBOL_PREFIX);
        symbol.push_str(name);
        Ok(symbol)
    }
}

/// A stable non-builtin runtime helper symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeHelperSymbol {
    name: &'static str,
    role: RuntimeHelperRole,
}

impl RuntimeHelperSymbol {
    /// Creates a stable runtime helper symbol declaration.
    const fn new(name: &'static str, role: RuntimeHelperRole) -> Self {
        Self { name, role }
    }

    /// Returns the symbol name that future native tiers register.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the runtime area served by this helper.
    pub const fn role(self) -> RuntimeHelperRole {
        self.role
    }
}

/// The runtime subsystem served by a stable helper symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeHelperRole {
    /// Allocation helpers route heap object creation through the active GC.
    Allocation,
    /// Call helpers own generic apply/call entrypoints.
    CallControl,
    /// Deoptimization helpers return native execution to the interpreter.
    Deoptimization,
    /// Environment helpers load values from compiled closure environments.
    EnvironmentAccess,
    /// Forcing helpers own thunk forcing, deep forcing, and blackhole checks.
    ForcingControl,
    /// Write-barrier helpers own GC-visible heap mutation boundaries.
    WriteBarrier,
    /// Attribute helpers own select, presence, and update slow paths.
    AttrsetAccess,
    /// Error helpers own catch-frame and diagnostic control transfer.
    ErrorControl,
    /// Primop-dispatch helpers delegate a lowered builtin-call body back to the
    /// interpreter's builtin executor.
    PrimopDispatch,
    /// Safepoint helpers bind compiled-frame stack-map storage to the collector.
    SafepointControl,
}

/// Stable runtime helper symbols that compiled tiers may reference.
pub const RUNTIME_HELPER_SYMBOLS: &[RuntimeHelperSymbol] = &[
    RuntimeHelperSymbol::new("aos_alloc_attrs", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_cons", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_lambda", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_list", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_raw", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_string", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_thunk", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_apply", RuntimeHelperRole::CallControl),
    RuntimeHelperSymbol::new("aos_blackhole_check", RuntimeHelperRole::ForcingControl),
    RuntimeHelperSymbol::new("aos_deopt", RuntimeHelperRole::Deoptimization),
    RuntimeHelperSymbol::new("aos_env_get", RuntimeHelperRole::EnvironmentAccess),
    RuntimeHelperSymbol::new("aos_force", RuntimeHelperRole::ForcingControl),
    RuntimeHelperSymbol::new("aos_force_deep", RuntimeHelperRole::ForcingControl),
    RuntimeHelperSymbol::new("aos_gc_write_barrier", RuntimeHelperRole::WriteBarrier),
    RuntimeHelperSymbol::new("aos_has_attr", RuntimeHelperRole::AttrsetAccess),
    RuntimeHelperSymbol::new("aos_jit_stack_map_enter", RuntimeHelperRole::SafepointControl),
    RuntimeHelperSymbol::new("aos_jit_stack_map_exit", RuntimeHelperRole::SafepointControl),
    RuntimeHelperSymbol::new("aos_primop_call", RuntimeHelperRole::PrimopDispatch),
    RuntimeHelperSymbol::new("aos_select_ic", RuntimeHelperRole::AttrsetAccess),
    RuntimeHelperSymbol::new("aos_string_length", RuntimeHelperRole::PrimopDispatch),
    RuntimeHelperSymbol::new("aos_throw", RuntimeHelperRole::ErrorControl),
    RuntimeHelperSymbol::new("aos_try_begin", RuntimeHelperRole::ErrorControl),
    RuntimeHelperSymbol::new("aos_try_end", RuntimeHelperRole::ErrorControl),
    RuntimeHelperSymbol::new("aos_update", RuntimeHelperRole::AttrsetAccess),
    RuntimeHelperSymbol::new("aos_upval_get", RuntimeHelperRole::EnvironmentAccess),
];

/// Returns the frozen runtime helper symbol declarations.
pub const fn runtime_helper_symbols() -> &'static [RuntimeHelperSymbol] {
    RUNTIME_HELPER_SYMBOLS
}

/// The runtime callable family served by one native-call signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeCallableKind {
    /// A compiled thunk body taking only runtime context and environment.
    ThunkBody,
    /// A compiled lambda body taking one already-applied Nix argument.
    LambdaBody,
    /// A builtin primop wrapper taking `arity` positional Nix arguments.
    Primop {
        /// The number of positional [`RuntimeAbiParameterKind::Value`] arguments.
        arity: usize,
    },
    /// A runtime helper registered under a stable `aos_*` symbol.
    Helper {
        /// The stable helper symbol served by this signature.
        symbol: RuntimeHelperSymbol,
    },
}

/// The machine calling convention promised by a runtime-call signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAbiCallingConvention {
    /// The platform C ABI reserved for future Cranelift and exported wrappers.
    ExternC,
}

/// One parameter in a frozen runtime-call signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAbiParameter {
    name: &'static str,
    kind: RuntimeAbiParameterKind,
}

impl RuntimeAbiParameter {
    const fn new(name: &'static str, kind: RuntimeAbiParameterKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable parameter name used in ABI metadata.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level parameter kind.
    pub const fn kind(self) -> RuntimeAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by runtime-call signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAbiParameterKind {
    /// The mutable evaluator runtime context pointer.
    RuntimeContext,
    /// The captured environment frame pointer.
    EnvPointer,
    /// A pointer to tier deoptimization state reconstruction metadata.
    DeoptRecordPointer,
    /// A pointer to runtime-owned error payload metadata.
    ErrorPointer,
    /// A pointer to native code for a thunk or lambda body.
    CodePointer,
    /// A pointer to a runtime thunk object.
    ThunkPointer,
    /// A pointer to a runtime lambda closure object.
    LambdaPointer,
    /// A pointer to a runtime attrset object.
    AttrsPointer,
    /// A pointer to a runtime list object.
    ListPointer,
    /// A pointer to a runtime string header object.
    StringHeaderPointer,
    /// A pointer to raw heap storage.
    RawPointer,
    /// A by-value runtime `Value` using [`runtime_abi_value_layout`].
    Value,
    /// A hidden-class shape identifier.
    ShapeId,
    /// A target-pointer-sized unsigned integer.
    Usize,
    /// A runtime-specific raw allocation type tag.
    TypeTag,
    /// A dense interned-symbol table index.
    SymbolId,
    /// A stable per-lookup inline-cache site identifier.
    InlineCacheSiteId,
    /// A 32-bit unsigned integer.
    U32,
}

/// The machine-level result kind returned by runtime-call signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAbiReturnKind {
    /// A by-value runtime `Value` using [`runtime_abi_value_layout`].
    Value,
    /// No machine-level result.
    Unit,
    /// Control does not return to the native caller.
    Diverges,
    /// A pointer to a runtime thunk object.
    ThunkPointer,
    /// A pointer to a runtime lambda closure object.
    LambdaPointer,
    /// A pointer to a runtime attrset object.
    AttrsPointer,
    /// A pointer to a runtime list object.
    ListPointer,
    /// A pointer to a runtime string header object.
    StringHeaderPointer,
    /// A pointer to raw heap storage.
    RawPointer,
}

/// A frozen native-call signature for a runtime callable family.
///
/// This is safe metadata only. It describes the eventual `extern "C"` ABI that
/// Cranelift lowering and exported wrappers must agree on, but does not create
/// function pointers, exported symbols, or unsafe call boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeCallSignature {
    callable: RuntimeCallableKind,
    convention: RuntimeAbiCallingConvention,
    parameters: &'static [RuntimeAbiParameter],
    return_kind: RuntimeAbiReturnKind,
}

impl RuntimeCallSignature {
    const fn new(
        callable: RuntimeCallableKind,
        convention: RuntimeAbiCallingConvention,
        parameters: &'static [RuntimeAbiParameter],
        return_kind: RuntimeAbiReturnKind,
    ) -> Self {
        Self {
            callable,
            convention,
            parameters,
            return_kind,
        }
    }

    /// Returns the runtime callable family served by this signature.
    pub const fn callable(self) -> RuntimeCallableKind {
        self.callable
    }

    /// Returns the machine calling convention used by this signature.
    pub const fn convention(self) -> RuntimeAbiCallingConvention {
        self.convention
    }

    /// Returns the ordered ABI parameters.
    pub const fn parameters(self) -> &'static [RuntimeAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind.
    pub const fn return_kind(self) -> RuntimeAbiReturnKind {
        self.return_kind
    }
}

/// A failure while selecting runtime-call ABI metadata.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RuntimeCallAbiError {
    /// The requested primop arity has no frozen native-call signature today.
    #[error("primop arity {arity} exceeds the frozen runtime ABI maximum {max}")]
    UnsupportedPrimopArity {
        /// The requested primop arity.
        arity: usize,
        /// The largest primop arity described by the current ABI metadata.
        max: usize,
    },
}

/// Result returned when building builtin runtime-call manifest metadata.
pub type RuntimeBuiltinCallManifestResult =
    Result<Vec<RuntimeBuiltinCallManifestEntry>, RuntimeSymbolNameError>;

/// Builds the stable builtin runtime-call manifest.
///
/// The manifest preserves sorted `nix.builtin.*` symbol order and classifies
/// each builtin as a callable primop wrapper, a value-only builtin, or a builtin
/// whose declared arity has no frozen native-call signature yet. This is safe
/// ABI-contract metadata only; it does not export builtin wrappers or install
/// JIT symbols.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError::NonUtf8BuiltinName`] if a builtin suffix is
/// not valid UTF-8.
pub fn runtime_builtin_call_manifest() -> RuntimeBuiltinCallManifestResult {
    let mut entries = Vec::with_capacity(BUILTINS.len());

    for builtin in BUILTINS.iter().copied() {
        entries.push(RuntimeBuiltinCallManifestEntry::new(
            builtin.runtime_symbol().to_symbol_string()?,
            builtin.name(),
            RuntimeBuiltinCallStatus::from_first_class_arity(builtin.first_class_arity()),
        ));
    }

    entries.sort_by(|left, right| left.symbol_name.cmp(&right.symbol_name));
    Ok(entries)
}

/// Result returned when building builtin runtime-call preflight metadata.
pub type RuntimeBuiltinCallPreflightResult =
    Result<RuntimeBuiltinCallPreflight, RuntimeSymbolNameError>;

/// Builds callable builtin runtime-call readiness metadata.
///
/// Callable builtin symbols receive their frozen primop call signature. Builtin
/// value symbols and unsupported arities are reported as gaps so later native
/// registration cannot silently treat them as executable wrappers.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError::NonUtf8BuiltinName`] if the builtin call
/// manifest cannot be built.
pub fn runtime_builtin_call_preflight() -> RuntimeBuiltinCallPreflightResult {
    let mut call_bindings = Vec::new();
    let mut missing_bindings = Vec::new();

    for entry in runtime_builtin_call_manifest()? {
        match entry.status() {
            RuntimeBuiltinCallStatus::Callable { arity, signature } => {
                call_bindings.push(RuntimeBuiltinCallBinding::new(
                    entry.symbol_name().to_owned(),
                    entry.builtin_name(),
                    arity,
                    signature,
                ));
            }
            RuntimeBuiltinCallStatus::ValueOnly => {
                missing_bindings.push(RuntimeBuiltinCallMissingBinding::value_only(
                    entry.symbol_name().to_owned(),
                    entry.builtin_name(),
                ));
            }
            RuntimeBuiltinCallStatus::UnsupportedArity { arity, max } => {
                missing_bindings.push(RuntimeBuiltinCallMissingBinding::unsupported_arity_gap(
                    entry.symbol_name().to_owned(),
                    entry.builtin_name(),
                    arity,
                    max,
                ));
            }
        }
    }

    Ok(RuntimeBuiltinCallPreflight::new(
        call_bindings,
        missing_bindings,
    ))
}

/// The current runtime-call status for one builtin symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeBuiltinCallStatus {
    /// A callable builtin wrapper with a frozen primop call signature.
    Callable {
        /// The first-class builtin arity served by the wrapper.
        arity: usize,
        /// The native-call signature reserved for this arity.
        signature: RuntimeCallSignature,
    },
    /// A builtin value symbol such as `true`, `false`, `null`, or `builtins`.
    ValueOnly,
    /// A callable builtin whose arity exceeds the frozen metadata inventory.
    UnsupportedArity {
        /// The declared first-class builtin arity.
        arity: usize,
        /// The largest primop arity described by current metadata.
        max: usize,
    },
}

impl RuntimeBuiltinCallStatus {
    fn from_first_class_arity(first_class_arity: Option<usize>) -> Self {
        match first_class_arity {
            Some(arity) => match runtime_primop_call_signature(arity) {
                Ok(signature) => Self::Callable { arity, signature },
                Err(RuntimeCallAbiError::UnsupportedPrimopArity { max, .. }) => {
                    Self::UnsupportedArity { arity, max }
                }
            },
            None => Self::ValueOnly,
        }
    }
}

/// One builtin symbol and its current runtime-call status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBuiltinCallManifestEntry {
    symbol_name: String,
    builtin_name: &'static [u8],
    status: RuntimeBuiltinCallStatus,
}

impl RuntimeBuiltinCallManifestEntry {
    fn new(
        symbol_name: String,
        builtin_name: &'static [u8],
        status: RuntimeBuiltinCallStatus,
    ) -> Self {
        Self {
            symbol_name,
            builtin_name,
            status,
        }
    }

    /// Returns the stable `nix.builtin.*` runtime symbol name.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the byte-oriented builtin declaration name.
    pub const fn builtin_name(&self) -> &'static [u8] {
        self.builtin_name
    }

    /// Returns the current runtime-call status for this builtin symbol.
    pub const fn status(&self) -> RuntimeBuiltinCallStatus {
        self.status
    }
}

/// A callable builtin runtime-call binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBuiltinCallBinding {
    symbol_name: String,
    builtin_name: &'static [u8],
    arity: usize,
    signature: RuntimeCallSignature,
}

impl RuntimeBuiltinCallBinding {
    fn new(
        symbol_name: String,
        builtin_name: &'static [u8],
        arity: usize,
        signature: RuntimeCallSignature,
    ) -> Self {
        Self {
            symbol_name,
            builtin_name,
            arity,
            signature,
        }
    }

    /// Returns the stable `nix.builtin.*` runtime symbol name.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the byte-oriented builtin declaration name.
    pub const fn builtin_name(&self) -> &'static [u8] {
        self.builtin_name
    }

    /// Returns the first-class builtin arity served by this binding.
    pub const fn arity(&self) -> usize {
        self.arity
    }

    /// Returns the native-call signature reserved for this builtin binding.
    pub const fn signature(&self) -> RuntimeCallSignature {
        self.signature
    }
}

/// One builtin symbol that does not yet have a callable runtime binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeBuiltinCallMissingBinding {
    /// The builtin is a value symbol rather than a callable primop wrapper.
    ValueOnly {
        /// The stable `nix.builtin.*` runtime symbol name.
        symbol_name: String,
        /// The byte-oriented builtin declaration name.
        builtin_name: &'static [u8],
    },
    /// The builtin declares an arity without a frozen call signature.
    UnsupportedArity {
        /// The stable `nix.builtin.*` runtime symbol name.
        symbol_name: String,
        /// The byte-oriented builtin declaration name.
        builtin_name: &'static [u8],
        /// The declared first-class builtin arity.
        arity: usize,
        /// The largest primop arity described by current metadata.
        max: usize,
    },
}

impl RuntimeBuiltinCallMissingBinding {
    fn value_only(symbol_name: String, builtin_name: &'static [u8]) -> Self {
        Self::ValueOnly {
            symbol_name,
            builtin_name,
        }
    }

    fn unsupported_arity_gap(
        symbol_name: String,
        builtin_name: &'static [u8],
        arity: usize,
        max: usize,
    ) -> Self {
        Self::UnsupportedArity {
            symbol_name,
            builtin_name,
            arity,
            max,
        }
    }

    /// Returns the stable `nix.builtin.*` runtime symbol name.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::ValueOnly { symbol_name, .. } | Self::UnsupportedArity { symbol_name, .. } => {
                symbol_name
            }
        }
    }

    /// Returns the byte-oriented builtin declaration name.
    pub const fn builtin_name(&self) -> &'static [u8] {
        match self {
            Self::ValueOnly { builtin_name, .. } | Self::UnsupportedArity { builtin_name, .. } => {
                builtin_name
            }
        }
    }

    /// Returns the unsupported arity when this gap is arity-related.
    pub const fn unsupported_arity(&self) -> Option<usize> {
        match self {
            Self::UnsupportedArity { arity, .. } => Some(*arity),
            Self::ValueOnly { .. } => None,
        }
    }
}

/// A deterministic readiness report for callable builtin runtime symbols.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBuiltinCallPreflight {
    call_bindings: Vec<RuntimeBuiltinCallBinding>,
    missing_bindings: Vec<RuntimeBuiltinCallMissingBinding>,
}

impl RuntimeBuiltinCallPreflight {
    fn new(
        call_bindings: Vec<RuntimeBuiltinCallBinding>,
        missing_bindings: Vec<RuntimeBuiltinCallMissingBinding>,
    ) -> Self {
        Self {
            call_bindings,
            missing_bindings,
        }
    }

    /// Returns callable builtin bindings in stable symbol order.
    pub fn call_bindings(&self) -> &[RuntimeBuiltinCallBinding] {
        &self.call_bindings
    }

    /// Returns builtin symbols that do not yet have callable bindings.
    pub fn missing_bindings(&self) -> &[RuntimeBuiltinCallMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every builtin symbol has a callable runtime binding.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }
}

/// The runtime symbol family served by a manifest entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolKind {
    /// A non-builtin helper registered under an `aos_*` symbol.
    Helper(RuntimeHelperRole),
    /// A Nix builtin registered under a `nix.builtin.*` symbol.
    Builtin,
}

/// One stable runtime symbol that future native tiers register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolManifestEntry {
    name: String,
    kind: RuntimeSymbolKind,
}

impl RuntimeSymbolManifestEntry {
    fn new(name: String, kind: RuntimeSymbolKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable symbol name registered with a native symbol table.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the runtime symbol family served by this entry.
    pub const fn kind(&self) -> RuntimeSymbolKind {
        self.kind
    }
}

/// Builds the stable runtime symbol manifest for future native tiers.
///
/// The manifest combines all `aos_*` helper symbols and all declared
/// `nix.builtin.*` builtin symbols into one deterministic, lexicographically
/// sorted table. Future `JITBuilder::symbol` registration can consume this
/// manifest before attaching executable addresses from the active runtime.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError::NonUtf8BuiltinName`] if a builtin suffix is
/// not valid UTF-8. Returns [`RuntimeSymbolNameError::DuplicateRuntimeSymbol`]
/// if the combined helper and builtin inventories contain the same final symbol
/// name more than once.
pub fn runtime_symbol_manifest() -> Result<Vec<RuntimeSymbolManifestEntry>, RuntimeSymbolNameError>
{
    let mut entries = Vec::with_capacity(runtime_helper_symbols().len() + BUILTINS.len());
    let mut seen = BTreeSet::new();

    for helper in runtime_helper_symbols().iter().copied() {
        push_manifest_entry(
            &mut entries,
            &mut seen,
            RuntimeSymbolManifestEntry::new(
                helper.name().to_owned(),
                RuntimeSymbolKind::Helper(helper.role()),
            ),
        )?;
    }

    for builtin in BUILTINS.iter().copied() {
        push_manifest_entry(
            &mut entries,
            &mut seen,
            RuntimeSymbolManifestEntry::new(
                builtin.runtime_symbol().to_symbol_string()?,
                RuntimeSymbolKind::Builtin,
            ),
        )?;
    }

    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn push_manifest_entry(
    entries: &mut Vec<RuntimeSymbolManifestEntry>,
    seen: &mut BTreeSet<String>,
    entry: RuntimeSymbolManifestEntry,
) -> Result<(), RuntimeSymbolNameError> {
    if !seen.insert(entry.name.clone()) {
        return Err(RuntimeSymbolNameError::DuplicateRuntimeSymbol { symbol: entry.name });
    }
    entries.push(entry);
    Ok(())
}

/// An invalid stable runtime symbol name.
#[derive(Clone, Debug, Error)]
pub enum RuntimeSymbolNameError {
    /// A builtin declaration name was not valid UTF-8.
    #[error("builtin runtime symbol suffix {name:?} is not valid UTF-8")]
    NonUtf8BuiltinName {
        /// The invalid builtin name bytes.
        name: Box<[u8]>,
        /// The UTF-8 validation failure.
        #[source]
        source: str::Utf8Error,
    },
    /// A final runtime symbol name appeared more than once.
    #[error("runtime symbol {symbol:?} appears more than once")]
    DuplicateRuntimeSymbol {
        /// The duplicated final symbol name.
        symbol: String,
    },
}

#[cfg(test)]
mod tests;
