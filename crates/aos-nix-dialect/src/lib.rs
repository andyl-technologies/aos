//! The Nix language dialect for the ratchet engine.
//!
//! This crate teaches the language-agnostic engine ([`ratchet_core`]) the Nix
//! language's semantics by implementing the [`ratchet_dialect::Dialect`]
//! registration interface. Today that is the effect classification for core IR
//! node kinds and direct builtins. Nix supplies distinct effect members for
//! `import`, import-from-derivation, `readFile`, `derivationStrict`, and related
//! IO boundaries; the engine stores only their compact effect stamps.
//!
//! Callers that want Nix semantics lower through [`nix_lower`] (or
//! [`nix_lower_with_options`]) rather than [`ratchet_core::lower`], which would
//! otherwise apply the engine's all-pure default and miss the effect boundary.
//!
//! The dialect also owns the Nix string *context* ([`string_context`]): the set
//! of store-path dependencies a string carries and unions on concatenation. The
//! context is Nix-language-specific and feeds `.drv` input edges, so it belongs
//! to the dialect; the engine layers the generic string value on top of it.

#![forbid(unsafe_code)]

pub mod string_context;

use ratchet_core::{
    EffectClass, Ir, IrDialectOp, IrError, IrKind, IrLowerOptions, ResolvedAst,
    builtins::{BuiltinDirect, BuiltinEffect},
};
use ratchet_dialect::Dialect;

/// Pure, speculable Nix evaluation.
pub const NIX_EFFECT_PURE: EffectClass = EffectClass::pure();

/// The `derivationStrict` boundary that materializes `.drv` metadata.
pub const NIX_EFFECT_DERIVATION_STRICT: EffectClass = EffectClass::new(1, false);

/// Nix file import, including `scopedImport`.
pub const NIX_EFFECT_IMPORT: EffectClass = EffectClass::new(2, false);

/// Import-from-derivation realization before an eval-time read.
pub const NIX_EFFECT_IFD: EffectClass = EffectClass::new(3, false);

/// Eval-time file reads through `readFile`.
pub const NIX_EFFECT_READ_FILE: EffectClass = EffectClass::new(4, false);

/// Eval-time filesystem metadata and path-copying operations.
pub const NIX_EFFECT_FILE_IO: EffectClass = EffectClass::new(5, false);

/// Environment-variable observation through `getEnv`.
pub const NIX_EFFECT_ENV: EffectClass = EffectClass::new(6, false);

/// Source-fetching builtins that observe configured fetch inputs.
pub const NIX_EFFECT_FETCH: EffectClass = EffectClass::new(7, false);

/// User-visible trace and warning emission.
pub const NIX_EFFECT_TRACE: EffectClass = EffectClass::new(8, false);

/// A conservative fallback for effectful Nix builtins without a refined member.
pub const NIX_EFFECT_GENERIC: EffectClass = EffectClass::new(9, false);

/// Builtins whose value depends on eval-time CLI/system/impure state.
///
/// This is the non-speculable member for the "CLI/system-sensitive" builtins —
/// `currentSystem`, `currentTime`, `nixVersion`, `langVersion`, `nixPath`, and
/// `storeDir` (see [`nix_builtin_is_cli_sensitive`]). Their result is
/// deterministic *within* a single evaluation but varies across runs with the
/// `--eval-system` flag, the wall clock, or the store/path configuration, so a
/// simplifier pass must never fold or propagate their value into the cached IR
/// (RFC-0007 doc 25 §5; doc 30 §8 decision D5). Marking them non-speculable keeps
/// `is_speculable()`-gated rewrites from baking a `--eval-system`-dependent value
/// into a `.drv`.
pub const NIX_EFFECT_CLI_SENSITIVE: EffectClass = EffectClass::new(10, false);

/// Nix dialect operation for the `derivationStrict` `.drv` boundary.
pub const NIX_OP_DERIVATION_STRICT: IrDialectOp = IrDialectOp::new(1);

/// Nix dialect operation for dynamic lookup through active `with` scopes.
pub const NIX_OP_WITH_VAR: IrDialectOp = IrDialectOp::new(2);

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

    fn builtin_effect_of(&self, name: Option<&[u8]>, effect: BuiltinEffect) -> EffectClass {
        nix_builtin_effect_of(name, effect)
    }

    fn builtin_dialect_op(
        &self,
        name: Option<&[u8]>,
        direct: BuiltinDirect,
    ) -> Option<IrDialectOp> {
        nix_builtin_dialect_op(name, direct)
    }

    fn dynamic_scope_var_op(&self) -> Option<IrDialectOp> {
        nix_dynamic_scope_var_op()
    }

    fn dialect_op_effect_of(&self, op: IrDialectOp) -> EffectClass {
        nix_dialect_op_effect_of(op)
    }
}

/// Returns the Nix effect classification for a core IR node kind.
///
/// This is the free-function form of [`NixDialect::effect_of`], suitable for
/// installation into [`IrLowerOptions::with_effect_of`] as a `fn` pointer.
/// Every core node is pure by default. Nix-only operations such as
/// `derivationStrict` are classified through [`nix_dialect_op_effect_of`].
pub fn nix_effect_of(kind: IrKind) -> EffectClass {
    let _ = kind;
    NIX_EFFECT_PURE
}

/// Returns the Nix effect classification for a direct-lowered builtin.
///
/// Pure builtin metadata maps to [`NIX_EFFECT_PURE`]. Effectful metadata is
/// refined by builtin name so later cache and scheduling layers can distinguish
/// import, file-read, IFD, and derivation boundaries without the engine owning a
/// closed Nix effect enum.
pub fn nix_builtin_effect_of(name: Option<&[u8]>, effect: BuiltinEffect) -> EffectClass {
    if effect == BuiltinEffect::Pure {
        return NIX_EFFECT_PURE;
    }

    match name {
        Some(b"derivation" | b"derivationStrict") => NIX_EFFECT_DERIVATION_STRICT,
        Some(b"import" | b"scopedImport") => NIX_EFFECT_IMPORT,
        Some(b"readFile") => NIX_EFFECT_READ_FILE,
        Some(b"toFile") => NIX_EFFECT_FILE_IO,
        Some(b"getEnv") => NIX_EFFECT_ENV,
        Some(b"fetchGit" | b"fetchMercurial" | b"fetchTarball" | b"fetchTree" | b"fetchurl") => {
            NIX_EFFECT_FETCH
        }
        Some(b"trace" | b"traceVerbose" | b"warn") => NIX_EFFECT_TRACE,
        Some(
            b"filterSource" | b"findFile" | b"hashFile" | b"path" | b"pathExists" | b"readDir"
            | b"readFileType" | b"storePath",
        ) => NIX_EFFECT_FILE_IO,
        _ => NIX_EFFECT_GENERIC,
    }
}

/// Returns whether `name` is a CLI/system/impure-sensitive Nix builtin.
///
/// These builtins — `currentSystem`, `currentTime`, `nixVersion`, `langVersion`,
/// `nixPath`, and `storeDir` — read eval-time CLI, system, clock, or store
/// configuration. They are ordinarily reached as *values*
/// (`builtins.currentSystem`), which lower to a pure `BuiltinAttr` node, so the
/// effect-class stamp alone does not flag them. The simplifier consults this
/// predicate to refuse folding or propagating their value into the cached IR,
/// which would bake a `--eval-system`-dependent (or otherwise per-run) result
/// into a `.drv` (RFC-0007 doc 25 §5; doc 30 §8 decision D5). Their non-speculable
/// effect member, for the paths that carry one, is [`NIX_EFFECT_CLI_SENSITIVE`].
#[must_use]
pub fn nix_builtin_is_cli_sensitive(name: &[u8]) -> bool {
    matches!(
        name,
        b"currentSystem"
            | b"currentTime"
            | b"nixVersion"
            | b"langVersion"
            | b"nixPath"
            | b"storeDir"
    )
}

/// Returns the Nix dialect operation for a direct-lowered builtin, when the
/// builtin is a Nix dialect operation instead of an ordinary primop.
pub fn nix_builtin_dialect_op(_name: Option<&[u8]>, direct: BuiltinDirect) -> Option<IrDialectOp> {
    match direct {
        BuiltinDirect::DerivationStrict => Some(NIX_OP_DERIVATION_STRICT),
        _ => None,
    }
}

/// Returns the Nix dialect operation for dynamic `with` variable probes.
pub fn nix_dynamic_scope_var_op() -> Option<IrDialectOp> {
    Some(NIX_OP_WITH_VAR)
}

/// Returns the Nix effect classification for a dialect operation key.
pub fn nix_dialect_op_effect_of(op: IrDialectOp) -> EffectClass {
    match op {
        NIX_OP_DERIVATION_STRICT => NIX_EFFECT_DERIVATION_STRICT,
        NIX_OP_WITH_VAR => NIX_EFFECT_PURE,
        _ => NIX_EFFECT_GENERIC,
    }
}

/// Returns default lowering options carrying the Nix effect classifier.
///
/// Equivalent to [`IrLowerOptions::new`] with [`nix_effect_of`] and
/// [`nix_builtin_effect_of`] installed.
pub fn nix_lower_options() -> IrLowerOptions {
    IrLowerOptions::new()
        .with_effect_of(nix_effect_of)
        .with_builtin_effect_of(nix_builtin_effect_of)
        .with_builtin_dialect_op(nix_builtin_dialect_op)
        .with_dynamic_scope_var_op(nix_dynamic_scope_var_op)
        .with_dialect_op_effect_of(nix_dialect_op_effect_of)
}

/// Lowers a scope-resolved Nix AST into evaluator IR with Nix semantics.
///
/// This is the Nix-aware counterpart to [`ratchet_core::lower`]: it installs the
/// [`nix_effect_of`] classifier so that `derivationStrict` nodes lower to
/// [`NIX_EFFECT_DERIVATION_STRICT`].
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
    ratchet_core::lower_with_options(
        resolved,
        options
            .with_effect_of(nix_effect_of)
            .with_builtin_effect_of(nix_builtin_effect_of)
            .with_builtin_dialect_op(nix_builtin_dialect_op)
            .with_dynamic_scope_var_op(nix_dynamic_scope_var_op)
            .with_dialect_op_effect_of(nix_dialect_op_effect_of),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratchet_core::{IrData, IrKind, resolve, syntax::parse_str};

    #[test]
    fn nix_effect_members_are_dialect_owned() {
        assert_eq!(
            nix_dialect_op_effect_of(NIX_OP_DERIVATION_STRICT),
            NIX_EFFECT_DERIVATION_STRICT
        );
        assert_eq!(nix_dialect_op_effect_of(NIX_OP_WITH_VAR), NIX_EFFECT_PURE);
        assert_eq!(
            nix_builtin_dialect_op(Some(b"derivationStrict"), BuiltinDirect::DerivationStrict),
            Some(NIX_OP_DERIVATION_STRICT)
        );
        assert_eq!(
            nix_builtin_effect_of(Some(b"import"), BuiltinEffect::Effectful),
            NIX_EFFECT_IMPORT
        );
        assert_eq!(
            nix_builtin_effect_of(Some(b"readFile"), BuiltinEffect::Effectful),
            NIX_EFFECT_READ_FILE
        );
        assert_eq!(
            nix_builtin_effect_of(Some(b"toFile"), BuiltinEffect::Effectful),
            NIX_EFFECT_FILE_IO
        );
        assert_ne!(
            nix_builtin_effect_of(Some(b"toFile"), BuiltinEffect::Effectful),
            NIX_EFFECT_IFD
        );
        assert_eq!(
            nix_builtin_effect_of(Some(b"typeOf"), BuiltinEffect::Pure),
            NIX_EFFECT_PURE
        );
        assert!(NIX_EFFECT_PURE.is_speculable());
        assert!(!NIX_EFFECT_IMPORT.is_speculable());
        assert_ne!(
            NIX_EFFECT_IMPORT.effect_key(),
            NIX_EFFECT_READ_FILE.effect_key()
        );
    }

    #[test]
    fn cli_sensitive_builtins_are_non_speculable_and_classified() {
        assert!(
            !NIX_EFFECT_CLI_SENSITIVE.is_speculable(),
            "CLI/system-sensitive builtins must never be speculated"
        );
        assert_ne!(
            NIX_EFFECT_CLI_SENSITIVE.effect_key(),
            NIX_EFFECT_PURE.effect_key()
        );
        for name in [
            b"currentSystem".as_slice(),
            b"currentTime",
            b"nixVersion",
            b"langVersion",
            b"nixPath",
            b"storeDir",
        ] {
            assert!(
                nix_builtin_is_cli_sensitive(name),
                "{} must be classified CLI/system-sensitive",
                String::from_utf8_lossy(name)
            );
        }
        // Genuinely pure/total builtins stay foldable.
        for name in [
            b"add".as_slice(),
            b"sub",
            b"length",
            b"stringLength",
            b"typeOf",
            b"toString",
        ] {
            assert!(
                !nix_builtin_is_cli_sensitive(name),
                "{} is pure and must remain speculable",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn nix_lower_stamps_direct_builtin_effect_members() {
        for (source, expected) in [
            ("import ./foo.nix", NIX_EFFECT_IMPORT),
            ("builtins.readFile ./foo.txt", NIX_EFFECT_READ_FILE),
            (
                "builtins.toFile \"generated.nix\" \"3\"",
                NIX_EFFECT_FILE_IO,
            ),
        ] {
            let resolved =
                resolve(parse_str(source).expect("source parses")).expect("source resolves");
            let ir = nix_lower(resolved).expect("source lowers");
            let root = ir.arena.node(ir.root).expect("root node exists");
            assert_eq!(root.kind, IrKind::PrimOp);
            assert_eq!(root.effect, expected);
            assert!(matches!(root.data, IrData::PrimOp { .. }));
        }
    }

    #[test]
    fn nix_lower_stamps_derivation_strict_effect_member() {
        let resolved = resolve(
            parse_str("builtins.derivationStrict { name = \"x\"; }").expect("source parses"),
        )
        .expect("source resolves");
        let ir = nix_lower(resolved).expect("source lowers");
        let root = ir.arena.node(ir.root).expect("root node exists");
        assert_eq!(root.kind, IrKind::PrimOp);
        assert_eq!(root.effect, NIX_EFFECT_DERIVATION_STRICT);
        assert!(matches!(
            root.data,
            IrData::DialectNode {
                op: NIX_OP_DERIVATION_STRICT,
                ..
            }
        ));
    }

    #[test]
    fn nix_lower_stamps_with_vars_as_dialect_ops() {
        let resolved = resolve(parse_str("with { a = 1; }; a").expect("source parses"))
            .expect("source resolves");
        let ir = nix_lower(resolved).expect("source lowers");
        let IrData::Pair { second, .. } = ir.arena.node(ir.root).expect("root node exists").data
        else {
            panic!("with payload expected");
        };
        let body = ir.arena.node(second).expect("body node exists");
        assert_eq!(body.kind, IrKind::PrimOp);
        assert_eq!(body.effect, NIX_EFFECT_PURE);
        assert!(matches!(
            body.data,
            IrData::DialectScopeVar {
                op: NIX_OP_WITH_VAR,
                ..
            }
        ));
    }
}
