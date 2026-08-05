//! First-class option-graph capture for native module evaluation.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use anyhow::Result;
use serde::Deserialize;

use super::NixNative;
use crate::error::NativeEvalError;
use crate::eval::{EvalStats, OptionReadObserver};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvaluatedOutput {
    manifest: serde_json::Value,
    option_writes: Vec<EvaluatedWrite>,
}

#[derive(Deserialize)]
struct EvaluatedWrite {
    package: String,
    option: String,
}

impl NixNative {
    /// Evaluates strict JSON and returns a canonical first-class option graph.
    ///
    /// Reads are captured at executed `config.<path>` select nodes. Writes are
    /// emitted by the evaluated module system after conditional definitions
    /// have been resolved. Resolver inputs only authenticate source and root
    /// ownership; they do not claim that an access occurred.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::eval_expr`].
    pub fn eval_expr_with_option_graph(
        &self,
        expr: &str,
        module_owners: impl IntoIterator<Item = (PathBuf, String)>,
        root_owners: impl IntoIterator<Item = (String, String)>,
    ) -> Result<crate::NativeEvalOutput> {
        Ok(self
            .eval_expr_with_option_graph_and_stats(expr, module_owners, root_owners)?
            .0)
    }

    /// Evaluates strict JSON and returns its option graph and work counters.
    ///
    /// This is the telemetry-bearing form used by the P2 parity and incremental
    /// cache gates. It has identical evaluation semantics to
    /// [`Self::eval_expr_with_option_graph`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::eval_expr_with_option_graph`].
    pub fn eval_expr_with_option_graph_and_stats(
        &self,
        expr: &str,
        module_owners: impl IntoIterator<Item = (PathBuf, String)>,
        root_owners: impl IntoIterator<Item = (String, String)>,
    ) -> Result<(crate::NativeEvalOutput, EvalStats)> {
        let mut module_owners = module_owners
            .into_iter()
            .map(|(path, package)| {
                let path = fs::canonicalize(&path).unwrap_or(path);
                (path, package)
            })
            .collect::<Vec<_>>();
        // A package owns every imported helper beneath its authenticated
        // config-output root. Prefer the narrowest matching root so callers
        // may still provide an exact file owner alongside a containing root.
        module_owners.sort_by(|(left, _), (right, _)| {
            right
                .components()
                .count()
                .cmp(&left.components().count())
                .then_with(|| left.cmp(right))
        });
        let root_owners = root_owners.into_iter().collect::<BTreeMap<_, _>>();
        let observer = OptionReadObserver::default();
        let mut evaluator = self.clone();
        if !module_owners.is_empty() {
            evaluator.options.set_option_read_observer(observer.clone());
        }
        let (json, stats) = evaluator.eval_expr_with_stats(expr)?;
        let evaluated: EvaluatedOutput =
            serde_json::from_str(&json).map_err(|source| NativeEvalError::Internal {
                message: format!("decoding native option-graph output: {source}"),
            })?;

        let mut accesses = evaluated
            .option_writes
            .into_iter()
            .map(|write| crate::OptionAccess {
                package: write.package,
                option: write.option,
                kind: crate::OptionAccessKind::Write,
                provider: None,
            })
            .collect::<Vec<_>>();
        for read in observer.snapshot() {
            let source = PathBuf::from(std::ffi::OsString::from_vec(read.source));
            let source = fs::canonicalize(&source).unwrap_or(source);
            let Some((_, package)) = module_owners
                .iter()
                .find(|(owned, _)| source == *owned || source.starts_with(owned))
            else {
                continue;
            };
            let option = read
                .path
                .iter()
                .map(|segment| String::from_utf8_lossy(segment))
                .collect::<Vec<_>>()
                .join(".");
            let provider = read
                .path
                .first()
                .and_then(|root| std::str::from_utf8(root).ok())
                .and_then(|root| root_owners.get(root))
                .filter(|provider| *provider != package)
                .cloned();
            accesses.push(crate::OptionAccess {
                package: package.clone(),
                option,
                kind: crate::OptionAccessKind::Read,
                provider,
            });
        }

        Ok((
            crate::NativeEvalOutput {
                json: serde_json::to_string(&evaluated.manifest).map_err(|source| {
                    NativeEvalError::Internal {
                        message: format!("encoding native manifest output: {source}"),
                    }
                })?,
                option_graph: crate::OptionGraph::from_accesses(accesses),
            },
            stats,
        ))
    }
}
