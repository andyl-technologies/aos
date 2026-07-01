//! Stable runtime ABI symbol names for future native tiers.
//!
//! The safe tree-walk evaluator does not register Cranelift symbols, but the
//! compile metadata already owns the frozen names that persisted compiled-IR
//! artifacts will reference. Builtins use `nix.builtin.<name>` and runtime
//! helpers use `aos_<verb>[_<qualifier>]`, matching RFC-0007 §10.

use std::str;

use thiserror::Error;

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
}
