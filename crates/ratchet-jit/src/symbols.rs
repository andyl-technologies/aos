//! Address-free runtime-symbol inventory consumed by future JIT registration.
//!
//! The inventory in this module mirrors the stable runtime symbol manifest owned
//! by `ratchet-core`. It gives future Cranelift setup code a local, documented
//! entry point for the symbol names and roles it may declare, without attaching
//! executable addresses or consulting the safe oracle's candidate-readiness
//! reports.

use ratchet_core::{
    RuntimeSymbolKind, RuntimeSymbolManifestEntry, RuntimeSymbolNameError, runtime_symbol_manifest,
};

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

#[cfg(test)]
mod tests {
    use ratchet_core::{RuntimeHelperRole, RuntimeSymbolKind, runtime_symbol_manifest};

    use super::*;

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
}
