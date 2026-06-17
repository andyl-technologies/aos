//! `aos-core` facing native evaluator shim.
//!
//! [`NixNative`] is the stable integration handle that will own the parser
//! cache, symbol interner, hash-consing tables, and evaluator arena as Phase 1
//! fills in. The current implementation is deliberately conservative: it never
//! fabricates a derivation, while expression JSON evaluation is enabled only for
//! the tree-walk subset that can be evaluated without derivation materialization.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::compile::{EffectClass, Ir, IrData, IrKind, lower, resolve};
use crate::error::NativeEvalError;
use crate::eval::{TreeWalkError, TreeWalkErrorKind, eval_whnf_owned};
use crate::runtime::builtins::{BUILTINS, BuiltinEffect, BuiltinExecution};
use crate::syntax::{Span, parse_str};
use crate::value::ValueTag;

/// In-process RFC-0007 evaluator handle.
#[derive(Debug, Clone)]
pub struct NixNative {
    verbose: u8,
}

impl NixNative {
    /// Creates a native evaluator handle.
    ///
    /// # Errors
    ///
    /// The Phase-1 shim has no fallible initialization. Future implementations
    /// may return errors when opening the persistent cache or validating store
    /// paths.
    pub fn new(verbose: u8) -> Result<Self> {
        Ok(Self { verbose })
    }

    /// Returns the configured verbosity level.
    pub fn verbose(&self) -> u8 {
        self.verbose
    }

    /// Evaluates `attr` from `file` to a derivation path.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] until the Phase-1 parser,
    /// oracle, and derivation serializer are implemented.
    pub fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
        Err(NativeEvalError::unsupported("native instantiation").into())
    }

    /// Evaluates a raw expression to a derivation path.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] until expression
    /// instantiation is implemented.
    pub fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
        Err(NativeEvalError::unsupported("native expression instantiation").into())
    }

    /// Evaluates a raw expression and renders it as strict JSON text.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] when the expression reaches an
    /// evaluator feature that is still outside the native tree-walk subset.
    /// Returns [`NativeEvalError::EvalError`] when the expression fails with
    /// normal Nix evaluation semantics or cannot be represented as JSON.
    pub fn eval_expr(&self, expr: &str) -> Result<String> {
        let source = json_wrapper_source(expr);
        let parsed = parse_str(&source).map_err(|source| {
            unsupported_frontend_error("parse", source.to_string(), source.span(), expr.len())
        })?;
        let resolved = resolve(parsed).map_err(|source| {
            unsupported_frontend_error("resolve", source.to_string(), source.span(), expr.len())
        })?;
        let ir = lower(resolved).map_err(|source| {
            unsupported_frontend_error("lower", source.to_string(), source.span(), expr.len())
        })?;
        ensure_native_json_subset(&ir, expr.len())?;
        let outcome = eval_whnf_owned(&ir).map_err(|error| native_eval_error(error, expr.len()))?;
        let string = outcome
            .heap()
            .get_string(outcome.value())
            .map_err(|source| NativeEvalError::Internal {
                message: format!("JSON renderer returned a non-string value: {source}"),
            })?;
        String::from_utf8(string.bytes().to_vec()).map_err(|source| {
            NativeEvalError::Internal {
                message: format!("JSON renderer returned non-UTF-8 bytes: {source}"),
            }
            .into()
        })
    }

    /// Returns a stable implementation name for diagnostics.
    pub fn name(&self) -> &'static str {
        "aos-nix"
    }
}

const JSON_WRAPPER_PREFIX: &str = "builtins.toJSON (\n";
const JSON_WRAPPER_SUFFIX: &str = "\n)";

fn json_wrapper_source(expr: &str) -> String {
    format!("{JSON_WRAPPER_PREFIX}{expr}{JSON_WRAPPER_SUFFIX}")
}

fn unsupported_frontend_error(
    stage: &'static str,
    message: String,
    span: Span,
    expr_len: usize,
) -> NativeEvalError {
    NativeEvalError::Unsupported {
        feature: format!("native expression {stage} failure: {message}"),
        span: source_span_from_wrapped(span, expr_len),
    }
}

fn native_eval_error(error: TreeWalkError, expr_len: usize) -> NativeEvalError {
    let kind = error.kind();
    if tree_walk_error_is_unsupported(&kind) {
        return NativeEvalError::Unsupported {
            feature: kind.to_string(),
            span: source_span_from_wrapped(error.span(), expr_len),
        };
    }

    NativeEvalError::EvalError {
        message: error.to_string(),
    }
}

fn tree_walk_error_is_unsupported(kind: &TreeWalkErrorKind) -> bool {
    match kind {
        TreeWalkErrorKind::UnsupportedLambdaPattern { .. }
        | TreeWalkErrorKind::UnsupportedLetBindingKey { .. }
        | TreeWalkErrorKind::UnsupportedSourcePathType { .. }
        | TreeWalkErrorKind::UnsupportedBinaryOp { .. }
        | TreeWalkErrorKind::UnsupportedPrimOp { .. }
        | TreeWalkErrorKind::UnsupportedBuiltinAttr { .. }
        | TreeWalkErrorKind::UnsupportedEqualityType { .. }
        | TreeWalkErrorKind::UnsupportedAttrPath { .. }
        | TreeWalkErrorKind::UnsupportedNode { .. } => true,
        TreeWalkErrorKind::Type {
            expected,
            actual: ValueTag::Attrs,
            ..
        } => matches!(*expected, "lambda" | "function"),
        _ => false,
    }
}

fn ensure_native_json_subset(ir: &Ir, expr_len: usize) -> Result<(), NativeEvalError> {
    for node in ir.arena.nodes() {
        if node.effect == EffectClass::Effectful {
            return Err(unsupported_native_node(
                "effectful expression evaluation",
                node.span,
                expr_len,
            ));
        }

        if node.kind == IrKind::GlobalVar
            && let IrData::Symbol(symbol) = node.data
        {
            let Some(name) = ir.symbols.resolve(symbol) else {
                continue;
            };
            if builtin_requires_cli_fallback(name) {
                return Err(unsupported_native_node(
                    "CLI-sensitive builtin evaluation",
                    node.span,
                    expr_len,
                ));
            }
        }

        if node.kind == IrKind::SearchPath {
            return Err(unsupported_native_node(
                "configured Nix search path lookup",
                node.span,
                expr_len,
            ));
        }
    }

    Ok(())
}

fn builtin_requires_cli_fallback(name: &[u8]) -> bool {
    if name == b"builtins" {
        return true;
    }

    let Some(metadata) = BUILTINS.lookup(name) else {
        return false;
    };

    match metadata.execution() {
        BuiltinExecution::Unsupported
        | BuiltinExecution::EffectfulUnaryUnsupported
        | BuiltinExecution::DerivationStrict
        | BuiltinExecution::CurrentSystemValue
        | BuiltinExecution::CurrentTimeValue
        | BuiltinExecution::StoreDirValue
        | BuiltinExecution::NixPathValue
        | BuiltinExecution::PathExists
        | BuiltinExecution::ReadDir
        | BuiltinExecution::ReadFile
        | BuiltinExecution::ReadFileType
        | BuiltinExecution::FindFile
        | BuiltinExecution::Trace { .. }
        | BuiltinExecution::Warn => true,
        BuiltinExecution::StrictUnary { effect, .. }
        | BuiltinExecution::StrictBinary { effect, .. } => effect == BuiltinEffect::Effectful,
        _ => false,
    }
}

fn unsupported_native_node(feature: &'static str, span: Span, expr_len: usize) -> NativeEvalError {
    NativeEvalError::Unsupported {
        feature: feature.to_string(),
        span: source_span_from_wrapped(span, expr_len),
    }
}

fn source_span_from_wrapped(span: Span, expr_len: usize) -> Option<crate::error::SrcSpan> {
    let prefix_len = u32::try_from(JSON_WRAPPER_PREFIX.len()).ok()?;
    let expr_len = u32::try_from(expr_len).ok()?;
    let expr_end = prefix_len.checked_add(expr_len)?;
    if span.start < prefix_len || span.end > expr_end {
        return None;
    }
    Some(src_span(Span::new(
        span.start - prefix_len,
        span.end - prefix_len,
    )))
}

const fn src_span(span: Span) -> crate::error::SrcSpan {
    crate::error::SrcSpan {
        start: span.start,
        end: span.end,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn native_expression_eval_renders_strict_json() -> Result<()> {
        let native = NixNative::new(0)?;

        assert_eq!(native.eval_expr("1 + 1")?, "2");
        assert_eq!(native.eval_expr("1 # trailing comment")?, "1");
        assert_eq!(native.eval_expr(r#""x""#)?, r#""x""#);
        assert_eq!(
            native.eval_expr(r#"{ b = 1; a = [ true null "x" ]; }"#)?,
            r#"{"a":[true,null,"x"],"b":1}"#
        );

        Ok(())
    }

    #[test]
    fn configured_cpp_nix_native_expression_eval_matches_cli_json() -> Result<()> {
        let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
            eprintln!("AOS_NIX_ORACLE not set; skipping configured native eval_expr check");
            return Ok(());
        };
        let native = NixNative::new(0)?;

        for source in [
            "1 + 1",
            "1 # trailing comment",
            r#""x""#,
            r#"{ b = 1; a = [ true null "x" ]; }"#,
            r#"builtins.toJSON { a = "x"; }"#,
        ] {
            let output = Command::new(&oracle)
                .args(["--eval", "--strict", "--json", "--expr", source])
                .output()?;
            assert!(
                output.status.success(),
                "C++ Nix oracle unexpectedly rejected {source:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let expected = String::from_utf8(output.stdout)?.trim().to_string();
            assert_eq!(native.eval_expr(source)?, expected, "{source}");
        }

        Ok(())
    }

    #[test]
    fn native_expression_eval_reports_semantic_errors() -> Result<()> {
        let native = NixNative::new(0)?;
        let err = native
            .eval_expr("1 + true")
            .expect_err("type errors are native evaluation errors");

        assert!(matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message }) if message.contains("type error")
        ));
        Ok(())
    }

    #[test]
    fn native_expression_eval_rejects_cli_sensitive_builtins() -> Result<()> {
        let native = NixNative::new(0)?;

        for source in [
            r#"builtins.getEnv "HOME""#,
            "builtins.nixPath",
            "builtins ? currentSystem",
            "builtins.attrNames builtins",
            "<nixpkgs>",
        ] {
            let err = native
                .eval_expr(source)
                .expect_err("CLI-sensitive expressions must fall back");
            assert!(
                matches!(
                    err.downcast_ref::<NativeEvalError>(),
                    Some(NativeEvalError::Unsupported { span: Some(_), .. })
                ),
                "{source}"
            );
        }

        Ok(())
    }

    #[test]
    fn native_expression_eval_keeps_frontend_gaps_fallback_eligible() -> Result<()> {
        let native = NixNative::new(0)?;
        let err = native
            .eval_expr("let { body = 1; }")
            .expect_err("frontend gaps should fall back to the CLI");

        assert!(matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, .. })
                if feature.contains("native expression parse failure")
        ));
        Ok(())
    }

    #[test]
    fn native_expression_eval_handles_functor_application() -> Result<()> {
        let native = NixNative::new(0)?;
        let json = native.eval_expr("({ __functor = self: x: x + 1; } 1)")?;

        assert_eq!(json, "2");
        Ok(())
    }

    #[test]
    fn native_expression_eval_keeps_non_functor_attrset_application_fallback_eligible() -> Result<()>
    {
        let native = NixNative::new(0)?;
        let err = native
            .eval_expr("({} 1)")
            .expect_err("non-functor attrset application should fall back to the CLI");

        assert!(matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                if feature.contains("type error")
        ));
        Ok(())
    }

    #[test]
    fn native_expression_eval_keeps_missing_features_fallback_eligible() -> Result<()> {
        let native = NixNative::new(0)?;
        let err = native
            .eval_expr(r#"builtins.import "/tmp/aos-nix-native-missing-import.nix""#)
            .expect_err("unsupported features are still reported as unsupported");

        assert!(matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                if feature.contains("effectful expression evaluation")
                    || feature.contains("CLI-sensitive builtin evaluation")
                    || feature.contains("unsupported tree-walk primop")
        ));
        assert_eq!(native.name(), "aos-nix");
        Ok(())
    }
}
