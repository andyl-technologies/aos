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
    RuntimeHelperSymbol::new("aos_select_ic", RuntimeHelperRole::AttrsetAccess),
    RuntimeHelperSymbol::new("aos_throw", RuntimeHelperRole::ErrorControl),
    RuntimeHelperSymbol::new("aos_try_begin", RuntimeHelperRole::ErrorControl),
    RuntimeHelperSymbol::new("aos_try_end", RuntimeHelperRole::ErrorControl),
    RuntimeHelperSymbol::new("aos_update", RuntimeHelperRole::AttrsetAccess),
];

/// Returns the frozen runtime helper symbol declarations.
pub const fn runtime_helper_symbols() -> &'static [RuntimeHelperSymbol] {
    RUNTIME_HELPER_SYMBOLS
}

/// The maximum builtin arity covered by the frozen primop ABI metadata today.
pub const MAX_RUNTIME_PRIMOP_ABI_ARITY: usize = 3;

const RUNTIME_ABI_VALUE_LAYOUT: RuntimeAbiValueLayout = RuntimeAbiValueLayout::new(16, 2, 8);

const THUNK_CALL_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
];
const LAMBDA_CALL_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("arg", RuntimeAbiParameterKind::Value),
];
const PRIMOP_0_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
];
const PRIMOP_1_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("a0", RuntimeAbiParameterKind::Value),
];
const PRIMOP_2_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("a0", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("a1", RuntimeAbiParameterKind::Value),
];
const PRIMOP_3_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("a0", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("a1", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("a2", RuntimeAbiParameterKind::Value),
];

/// The frozen runtime-call signature for compiled thunk bodies.
pub const RUNTIME_THUNK_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::ThunkBody,
    RuntimeAbiCallingConvention::ExternC,
    THUNK_CALL_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);

/// The frozen runtime-call signature for compiled lambda bodies.
pub const RUNTIME_LAMBDA_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::LambdaBody,
    RuntimeAbiCallingConvention::ExternC,
    LAMBDA_CALL_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);

const RUNTIME_PRIMOP_0_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Primop { arity: 0 },
    RuntimeAbiCallingConvention::ExternC,
    PRIMOP_0_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_PRIMOP_1_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Primop { arity: 1 },
    RuntimeAbiCallingConvention::ExternC,
    PRIMOP_1_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_PRIMOP_2_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Primop { arity: 2 },
    RuntimeAbiCallingConvention::ExternC,
    PRIMOP_2_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_PRIMOP_3_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Primop { arity: 3 },
    RuntimeAbiCallingConvention::ExternC,
    PRIMOP_3_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);

/// Frozen runtime-call signatures for builtin primop arities covered today.
pub const RUNTIME_PRIMOP_CALL_SIGNATURES: &[RuntimeCallSignature] = &[
    RUNTIME_PRIMOP_0_CALL_SIGNATURE,
    RUNTIME_PRIMOP_1_CALL_SIGNATURE,
    RUNTIME_PRIMOP_2_CALL_SIGNATURE,
    RUNTIME_PRIMOP_3_CALL_SIGNATURE,
];

/// Returns the by-value runtime value layout assumed by native call metadata.
pub const fn runtime_abi_value_layout() -> RuntimeAbiValueLayout {
    RUNTIME_ABI_VALUE_LAYOUT
}

/// Returns the frozen runtime-call signature for compiled thunk bodies.
pub const fn runtime_thunk_call_signature() -> RuntimeCallSignature {
    RUNTIME_THUNK_CALL_SIGNATURE
}

/// Returns the frozen runtime-call signature for compiled lambda bodies.
pub const fn runtime_lambda_call_signature() -> RuntimeCallSignature {
    RUNTIME_LAMBDA_CALL_SIGNATURE
}

/// Returns the frozen primop call-signature inventory.
pub const fn runtime_primop_call_signatures() -> &'static [RuntimeCallSignature] {
    RUNTIME_PRIMOP_CALL_SIGNATURES
}

/// Returns the frozen primop call signature for `arity`.
///
/// # Errors
///
/// Returns [`RuntimeCallAbiError::UnsupportedPrimopArity`] when `arity` exceeds
/// [`MAX_RUNTIME_PRIMOP_ABI_ARITY`].
pub fn runtime_primop_call_signature(
    arity: usize,
) -> Result<RuntimeCallSignature, RuntimeCallAbiError> {
    match arity {
        0 => Ok(RUNTIME_PRIMOP_0_CALL_SIGNATURE),
        1 => Ok(RUNTIME_PRIMOP_1_CALL_SIGNATURE),
        2 => Ok(RUNTIME_PRIMOP_2_CALL_SIGNATURE),
        3 => Ok(RUNTIME_PRIMOP_3_CALL_SIGNATURE),
        _ => Err(RuntimeCallAbiError::UnsupportedPrimopArity {
            arity,
            max: MAX_RUNTIME_PRIMOP_ABI_ARITY,
        }),
    }
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
}

/// The machine calling convention promised by a runtime-call signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAbiCallingConvention {
    /// The platform C ABI reserved for future Cranelift and exported wrappers.
    ExternC,
}

/// The by-value layout assumed for the runtime `Value` ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAbiValueLayout {
    size_bytes: usize,
    register_words: usize,
    register_word_bytes: usize,
}

impl RuntimeAbiValueLayout {
    const fn new(size_bytes: usize, register_words: usize, register_word_bytes: usize) -> Self {
        Self {
            size_bytes,
            register_words,
            register_word_bytes,
        }
    }

    /// Returns the by-value `Value` size expected at native call boundaries.
    pub const fn size_bytes(self) -> usize {
        self.size_bytes
    }

    /// Returns the number of machine words used to pass a `Value` in registers.
    pub const fn register_words(self) -> usize {
        self.register_words
    }

    /// Returns the byte width of each register-passed `Value` word.
    pub const fn register_word_bytes(self) -> usize {
        self.register_word_bytes
    }
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
    /// A by-value runtime `Value` using [`runtime_abi_value_layout`].
    Value,
}

/// The machine-level result kind returned by runtime-call signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAbiReturnKind {
    /// A by-value runtime `Value` using [`runtime_abi_value_layout`].
    Value,
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
mod tests {
    use std::collections::BTreeSet;

    use crate::builtins::BUILTINS;

    use super::*;

    #[test]
    fn builtin_runtime_symbols_use_frozen_prefix_and_visible_names() {
        assert_eq!(
            BUILTINS
                .lookup(b"derivationStrict")
                .expect("derivationStrict is registered")
                .runtime_symbol()
                .to_symbol_string()
                .expect("builtin name is UTF-8"),
            "nix.builtin.derivationStrict"
        );
        assert_eq!(
            BUILTINS
                .lookup(b"foldl'")
                .expect("foldl' is registered")
                .runtime_symbol()
                .to_symbol_string()
                .expect("builtin name is UTF-8"),
            "nix.builtin.foldl'"
        );

        for builtin in BUILTINS.iter().copied() {
            let symbol = builtin
                .runtime_symbol()
                .to_symbol_string()
                .expect("declared builtin names are UTF-8");
            assert!(symbol.starts_with(BUILTIN_SYMBOL_PREFIX), "{symbol}");
            assert_eq!(
                &symbol.as_bytes()[BUILTIN_SYMBOL_PREFIX.len()..],
                builtin.name()
            );
        }
    }

    #[test]
    fn builtin_runtime_symbol_rejects_non_utf8_suffixes() {
        let error = BuiltinRuntimeSymbol::new(b"\xff")
            .to_symbol_string()
            .expect_err("invalid UTF-8 is rejected");

        assert!(matches!(
            error,
            RuntimeSymbolNameError::NonUtf8BuiltinName { .. }
        ));
    }

    #[test]
    fn runtime_helper_symbols_are_unique_sorted_and_prefixed() {
        let mut previous = None;
        let mut seen = BTreeSet::new();

        for symbol in runtime_helper_symbols() {
            assert!(symbol.name().starts_with(RUNTIME_HELPER_SYMBOL_PREFIX));
            assert!(
                seen.insert(symbol.name()),
                "{} appears twice",
                symbol.name()
            );
            if let Some(previous) = previous {
                assert!(
                    previous < symbol.name(),
                    "{previous} before {}",
                    symbol.name()
                );
            }
            previous = Some(symbol.name());
        }
    }

    #[test]
    fn runtime_helper_symbols_include_single_write_barrier_wall() {
        let write_barriers = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() == RuntimeHelperRole::WriteBarrier)
            .map(RuntimeHelperSymbol::name)
            .collect::<BTreeSet<_>>();

        assert_eq!(write_barriers, BTreeSet::from(["aos_gc_write_barrier"]));
    }

    #[test]
    fn runtime_call_metadata_pins_value_layout_and_convention() {
        let value_layout = runtime_abi_value_layout();

        assert_eq!(value_layout.size_bytes(), 16);
        assert_eq!(value_layout.register_words(), 2);
        assert_eq!(value_layout.register_word_bytes(), 8);

        let mut signatures = vec![
            runtime_thunk_call_signature(),
            runtime_lambda_call_signature(),
        ];
        signatures.extend(runtime_primop_call_signatures().iter().copied());

        for signature in signatures {
            assert_eq!(signature.convention(), RuntimeAbiCallingConvention::ExternC);
            assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
            assert_eq!(
                signature.parameters()[0],
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext)
            );
            assert_eq!(
                signature.parameters()[1],
                RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer)
            );
        }
    }

    #[test]
    fn thunk_and_lambda_call_signatures_share_runtime_prefix() {
        let thunk = runtime_thunk_call_signature();
        let lambda = runtime_lambda_call_signature();

        assert_eq!(thunk.callable(), RuntimeCallableKind::ThunkBody);
        assert_eq!(thunk.parameters(), THUNK_CALL_PARAMETERS);
        assert_eq!(thunk.parameters().len(), 2);

        assert_eq!(lambda.callable(), RuntimeCallableKind::LambdaBody);
        assert_eq!(lambda.parameters(), LAMBDA_CALL_PARAMETERS);
        assert_eq!(lambda.parameters().len(), 3);
        assert_eq!(
            lambda.parameters()[2],
            RuntimeAbiParameter::new("arg", RuntimeAbiParameterKind::Value)
        );
    }

    #[test]
    fn primop_call_signatures_cover_declared_builtin_arities() {
        let max_declared_arity = BUILTINS
            .iter()
            .filter_map(|builtin| builtin.first_class_arity())
            .max()
            .expect("first-class builtins exist");

        assert_eq!(MAX_RUNTIME_PRIMOP_ABI_ARITY, 3);
        assert!(max_declared_arity <= MAX_RUNTIME_PRIMOP_ABI_ARITY);
        assert_eq!(
            runtime_primop_call_signatures().len(),
            MAX_RUNTIME_PRIMOP_ABI_ARITY + 1
        );

        for arity in 0..=MAX_RUNTIME_PRIMOP_ABI_ARITY {
            let signature = runtime_primop_call_signature(arity).expect("arity is covered");
            assert_eq!(signature.callable(), RuntimeCallableKind::Primop { arity });
            assert_eq!(signature.parameters().len(), arity + 2);
            for (index, parameter) in signature.parameters().iter().copied().enumerate() {
                match index {
                    0 => assert_eq!(
                        parameter,
                        RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext)
                    ),
                    1 => assert_eq!(
                        parameter,
                        RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer)
                    ),
                    argument_index => {
                        let expected_name = format!("a{}", argument_index - 2);
                        assert_eq!(
                            parameter.name(),
                            expected_name.as_str(),
                            "primop argument names stay positional"
                        );
                        assert_eq!(parameter.kind(), RuntimeAbiParameterKind::Value);
                    }
                }
            }
        }
    }

    #[test]
    fn primop_call_signature_rejects_unfrozen_arities() {
        let error = runtime_primop_call_signature(MAX_RUNTIME_PRIMOP_ABI_ARITY + 1)
            .expect_err("unsupported arity rejects");

        assert_eq!(
            error,
            RuntimeCallAbiError::UnsupportedPrimopArity {
                arity: MAX_RUNTIME_PRIMOP_ABI_ARITY + 1,
                max: MAX_RUNTIME_PRIMOP_ABI_ARITY,
            }
        );
    }

    #[test]
    fn runtime_symbol_manifest_combines_helpers_and_builtins() {
        let manifest = runtime_symbol_manifest().expect("manifest builds");

        assert_eq!(
            manifest.len(),
            runtime_helper_symbols().len() + BUILTINS.len()
        );
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.name() == "aos_gc_write_barrier")
                .map(RuntimeSymbolManifestEntry::kind),
            Some(RuntimeSymbolKind::Helper(RuntimeHelperRole::WriteBarrier))
        );
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.name() == "nix.builtin.derivationStrict")
                .map(RuntimeSymbolManifestEntry::kind),
            Some(RuntimeSymbolKind::Builtin)
        );
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.name() == "nix.builtin.foldl'")
                .map(RuntimeSymbolManifestEntry::kind),
            Some(RuntimeSymbolKind::Builtin)
        );

        for helper in runtime_helper_symbols().iter().copied() {
            assert_eq!(
                manifest
                    .iter()
                    .find(|entry| entry.name() == helper.name())
                    .map(RuntimeSymbolManifestEntry::kind),
                Some(RuntimeSymbolKind::Helper(helper.role())),
                "{} helper appears in the manifest",
                helper.name()
            );
        }

        for builtin in BUILTINS.iter().copied() {
            let symbol = builtin
                .runtime_symbol()
                .to_symbol_string()
                .expect("builtin symbol is UTF-8");
            assert_eq!(
                manifest
                    .iter()
                    .find(|entry| entry.name() == symbol)
                    .map(RuntimeSymbolManifestEntry::kind),
                Some(RuntimeSymbolKind::Builtin),
                "{symbol} builtin appears in the manifest"
            );
        }
    }

    #[test]
    fn runtime_symbol_manifest_is_sorted_and_unique() {
        let manifest = runtime_symbol_manifest().expect("manifest builds");
        let mut previous = None;
        let mut seen = BTreeSet::new();

        for entry in &manifest {
            assert!(
                seen.insert(entry.name().to_owned()),
                "{} appears twice",
                entry.name()
            );
            if let Some(previous) = previous {
                assert!(
                    previous < entry.name(),
                    "{previous} before {}",
                    entry.name()
                );
            }
            previous = Some(entry.name());
        }
    }

    #[test]
    fn runtime_symbol_manifest_rejects_duplicates_before_registration() {
        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        let duplicate = RuntimeSymbolManifestEntry::new(
            "aos_duplicate".to_owned(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
        );

        push_manifest_entry(&mut entries, &mut seen, duplicate.clone())
            .expect("first symbol records");
        let error = push_manifest_entry(&mut entries, &mut seen, duplicate)
            .expect_err("duplicate symbol rejects");

        assert!(matches!(
            error,
            RuntimeSymbolNameError::DuplicateRuntimeSymbol { .. }
        ));
        assert_eq!(entries.len(), 1);
    }
}
