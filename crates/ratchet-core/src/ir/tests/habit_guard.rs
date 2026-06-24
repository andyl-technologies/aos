//! RFC-0007 Phase 1b deliverable #6 — the "habit guard".
//!
//! The Core IR `IrKind` taxonomy is language-AGNOSTIC. New dialect features —
//! especially new builtins — must NOT add `IrKind` variants: they route through
//! the generic `IrKind::PrimOp` escape hatch, and dialect state such as
//! string-context lives in `aos-nix-dialect`, never in the engine. (The
//! string-context half of the habit is already enforced structurally —
//! ratchet-core has no dependency on any dialect crate, so it *cannot* name the
//! context types.)
//!
//! This guard is an exhaustive match over every `IrKind` variant with no `_`
//! arm: adding a variant fails to compile here until it is added below, forcing
//! a conscious decision (and code review) about whether the new variant is truly
//! language-agnostic. Most new dialect concepts are not — they belong behind
//! `PrimOp` or in `aos-nix-dialect`.

use crate::ir::IrKind;

/// Exhaustively names every `IrKind`, so the taxonomy cannot grow a
/// dialect-specific variant without a maintainer tripping this guard.
#[test]
fn ir_kind_taxonomy_is_language_agnostic() {
    fn assert_known(kind: IrKind) {
        // No wildcard arm: this match must remain exhaustive by enumeration.
        // Dialect-shaped operations, including Nix dynamic `with` probes and
        // `derivationStrict`, must route through the generic `IrKind::PrimOp`
        // escape hatch. Do NOT add language-specific variants here.
        match kind {
            IrKind::Int
            | IrKind::Float
            | IrKind::Bool
            | IrKind::Null
            | IrKind::Str
            | IrKind::Path
            | IrKind::SearchPath
            | IrKind::Uri
            | IrKind::LocalVar
            | IrKind::UpvalVar
            | IrKind::GlobalVar
            | IrKind::BuiltinAttr
            | IrKind::List
            | IrKind::AttrSet
            | IrKind::Lambda
            | IrKind::FormalSet
            | IrKind::Formal
            | IrKind::Apply
            | IrKind::Select
            | IrKind::HasAttr
            | IrKind::Let
            | IrKind::With
            | IrKind::Assert
            | IrKind::If
            | IrKind::BinOp
            | IrKind::UnaryOp
            | IrKind::Interp
            | IrKind::ThunkAlloc
            | IrKind::PrimOp => {}
        }
    }

    // Touch the generic builtin escape hatch the habit steers new builtins toward.
    assert_known(IrKind::PrimOp);
}
