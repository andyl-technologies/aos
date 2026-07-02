//! Address-free runtime-symbol inventory consumed by future JIT registration.
//!
//! The inventory in this module mirrors the stable runtime symbol manifest owned
//! by `ratchet-core`. It gives future Cranelift setup code a local, documented
//! entry point for the symbol names and roles it may declare, without attaching
//! executable addresses or consulting the safe oracle's candidate-readiness
//! reports. It also preflights which stable symbols can currently be declared
//! with CLIF signatures without attaching addresses or creating a `JITModule`.

use std::{collections::BTreeMap, error::Error, fmt};

use cranelift_codegen::ir::Signature;

use ratchet_core::{
    RuntimeBuiltinCallBinding, RuntimeBuiltinCallMissingBinding, RuntimeHelperRole,
    RuntimeSymbolKind, RuntimeSymbolManifestEntry, RuntimeSymbolNameError,
    runtime_builtin_call_preflight, runtime_symbol_manifest,
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
    /// Runtime helper ABI metadata is not owned by `ratchet-jit` yet.
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

/// Builds address-free CLIF declaration readiness for stable runtime symbols.
///
/// Callable builtin symbols receive CLIF signatures from the frozen core
/// primop ABI. Helper symbols and value-only builtin symbols remain explicit
/// gaps, because this crate still has no helper wrapper ABI or executable
/// addresses to register.
///
/// # Errors
///
/// Returns [`JitRuntimeSymbolDeclarationError::SymbolName`] if core symbol
/// metadata cannot be built. Returns
/// [`JitRuntimeSymbolDeclarationError::ClifSignature`] if a callable builtin
/// signature cannot be lowered to CLIF on this host.
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
                gaps.push(JitRuntimeSymbolDeclarationGap::helper(
                    symbol.name().to_owned(),
                    role,
                ));
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

fn declaration_for_builtin_binding(
    binding: &RuntimeBuiltinCallBinding,
) -> Result<JitRuntimeSymbolDeclaration, JitRuntimeSymbolDeclarationError> {
    let signature = clif_signature_for_runtime_call(binding.signature()).map_err(|source| {
        JitRuntimeSymbolDeclarationError::ClifSignature {
            symbol_name: binding.symbol_name().to_owned(),
            source,
        }
    })?;

    Ok(JitRuntimeSymbolDeclaration::new(
        binding.symbol_name().to_owned(),
        RuntimeSymbolKind::Builtin,
        signature,
    ))
}

#[cfg(test)]
mod tests {
    use ratchet_core::{
        RuntimeHelperRole, RuntimeSymbolKind, runtime_builtin_call_preflight,
        runtime_primop_call_signature, runtime_symbol_manifest,
    };

    use super::*;
    use crate::abi::clif_signature_for_runtime_call;

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
    fn jit_runtime_symbol_declaration_preflight_reports_helper_gaps() {
        let preflight = jit_runtime_symbol_declaration_preflight()
            .expect("JIT symbol declaration preflight builds");

        assert!(matches!(
            preflight.gap_for_symbol("aos_force"),
            Some(
                JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                    role: RuntimeHelperRole::ForcingControl,
                    ..
                }
            )
        ));
        assert!(matches!(
            preflight.gap_for_symbol("aos_alloc_attrs"),
            Some(
                JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                    role: RuntimeHelperRole::Allocation,
                    ..
                }
            )
        ));
        assert!(preflight.declaration_for_symbol("aos_force").is_none());
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
            builtin_preflight.call_bindings().len()
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
    }
}
