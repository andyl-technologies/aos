//! The dialect registration interface for the ratchet engine.
//!
//! The ratchet engine ([`ratchet_core`]) is language-agnostic: it lowers a
//! resolved AST into IR and evaluates it without any built-in knowledge of a
//! particular source language's semantics. A *dialect* is the seam through
//! which a language teaches the engine those semantics.
//!
//! Today a [`Dialect`] supplies effect classification for core IR node kinds and
//! direct builtins, but it is the registration-time interface a
//! language plugs into, and the intended growth surface for everything a
//! language must contribute at lowering time:
//!
//! - effect classification (present),
//! - extra node operations and the primop table,
//! - rewrite rules and lowering hooks.
//!
//! A dialect is always consumed monomorphically: the engine resolves the
//! concrete classifier (a `fn` pointer) before lowering and never dispatches
//! through `dyn Dialect` on the force path.

#![forbid(unsafe_code)]

use ratchet_core::{
    EffectClass, IrDialectOp, IrKind,
    builtins::{BuiltinDirect, BuiltinEffect},
};

/// A language dialect that supplies the engine with language-specific semantics.
///
/// Implementors describe how a source language maps onto the engine's core IR.
/// The trait is the registration-time interface: a language constructs a
/// dialect value once and the engine reads the contributions it needs (effect
/// members now; extra operations, the primop table, rewrite rules, and lowering
/// hooks are the growth surface). It is consumed monomorphically and never
/// invoked via `dyn` on the force path.
pub trait Dialect {
    /// Returns the dialect's effect classification for a core IR node kind.
    ///
    /// The engine calls this while lowering to stamp each [`ratchet_core::IrNode`]
    /// with its [`EffectClass`], which downstream speculation and caching passes
    /// use to decide what may be reordered or memoized.
    fn effect_of(&self, kind: IrKind) -> EffectClass;

    /// Returns the dialect's effect classification for a direct-lowered builtin.
    ///
    /// The `name` argument is the source-language builtin name when the lowering
    /// context can resolve it. The `effect` argument carries coarse metadata from
    /// the builtin declaration table; dialects may refine that into distinct
    /// members such as import, file IO, environment access, and derivation
    /// construction.
    fn builtin_effect_of(&self, name: Option<&[u8]>, effect: BuiltinEffect) -> EffectClass;

    /// Returns the dialect operation key for a direct-lowered builtin.
    ///
    /// Dialect operations are distinct from ordinary primitive operations even
    /// though they use the same compact escape-hatch storage in the engine.
    fn builtin_dialect_op(&self, name: Option<&[u8]>, direct: BuiltinDirect)
    -> Option<IrDialectOp>;

    /// Returns the dialect operation key for unresolved dynamic-scope variables.
    ///
    /// Dialects without dynamic scope return `None`, causing lowering to reject
    /// source forms that require a dynamic lookup operation.
    fn dynamic_scope_var_op(&self) -> Option<IrDialectOp>;

    /// Returns the dialect's effect classification for a dialect operation key.
    fn dialect_op_effect_of(&self, op: IrDialectOp) -> EffectClass;
}
