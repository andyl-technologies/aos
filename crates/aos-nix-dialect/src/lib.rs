//! The Nix language dialect for the ratchet engine.
//!
//! This crate teaches the language-agnostic engine ([`ratchet_core`]) the Nix
//! language's semantics by implementing the [`ratchet_dialect::Dialect`]
//! registration interface. Today that is the effect classification: Nix's
//! `derivationStrict` boundary is the one core IR node kind that performs
//! externally observable work, so it lowers to [`EffectClass::Effectful`] while
//! every other kind is [`EffectClass::Pure`].
//!
//! Callers that want Nix semantics lower through [`nix_lower`] (or
//! [`nix_lower_with_options`]) rather than [`ratchet_core::lower`], which would
//! otherwise apply the engine's all-pure default and miss the effect boundary.

#![forbid(unsafe_code)]

use ratchet_core::{EffectClass, Ir, IrError, IrKind, IrLowerOptions, ResolvedAst};
use ratchet_dialect::Dialect;

/// The Nix language dialect.
///
/// Implements [`Dialect`] for the Nix language. The dialect is zero-sized; it
/// carries no state and exists to plug Nix's semantics into the engine at
/// lowering time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NixDialect;

impl Dialect for NixDialect {
    fn effect_of(&self, kind: IrKind) -> EffectClass {
        nix_effect_of(kind)
    }
}

/// Returns the Nix effect classification for a core IR node kind.
///
/// This is the free-function form of [`NixDialect::effect_of`], suitable for
/// installation into [`IrLowerOptions::with_effect_of`] as a `fn` pointer.
/// Nix's `derivationStrict` boundary is effectful; every other node is pure.
pub fn nix_effect_of(kind: IrKind) -> EffectClass {
    match kind {
        IrKind::DerivationStrict => EffectClass::Effectful,
        _ => EffectClass::Pure,
    }
}

/// Returns default lowering options carrying the Nix effect classifier.
///
/// Equivalent to [`IrLowerOptions::new`] with [`nix_effect_of`] installed.
pub fn nix_lower_options() -> IrLowerOptions {
    IrLowerOptions::new().with_effect_of(nix_effect_of)
}

/// Lowers a scope-resolved Nix AST into evaluator IR with Nix semantics.
///
/// This is the Nix-aware counterpart to [`ratchet_core::lower`]: it installs the
/// [`nix_effect_of`] classifier so that `derivationStrict` nodes lower to
/// [`EffectClass::Effectful`].
///
/// # Errors
///
/// Returns [`IrError`] under the same conditions as
/// [`ratchet_core::lower_with_options`]: when the resolved AST has an invalid
/// shape for the lowering contract or an IR side table exceeds `u32`
/// addressability.
pub fn nix_lower(resolved: ResolvedAst) -> Result<Ir, IrError> {
    nix_lower_with_options(resolved, IrLowerOptions::new())
}

/// Lowers a scope-resolved Nix AST into evaluator IR with explicit options and
/// Nix semantics.
///
/// The Nix effect classifier ([`nix_effect_of`]) is always installed onto
/// `options` before lowering, overriding any effect classifier the caller may
/// have set, so other option fields (e.g. the dynamic builtin scope) are
/// preserved.
///
/// # Errors
///
/// Returns [`IrError`] under the same conditions as
/// [`ratchet_core::lower_with_options`].
pub fn nix_lower_with_options(
    resolved: ResolvedAst,
    options: IrLowerOptions,
) -> Result<Ir, IrError> {
    ratchet_core::lower_with_options(resolved, options.with_effect_of(nix_effect_of))
}
