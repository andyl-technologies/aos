//! Hermetic command-line driver for native-evaluator parity checks.
//!
//! This intentionally small binary evaluates one checked-in expression and
//! emits its manifest plus the evaluator-observed option graph as JSON. It is
//! packaged for CI differential checks; production configuration activation
//! continues to use the `apm` evaluator seam.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use aos_nix::eval::{EvalMode, TreeWalkOptions};
use aos_nix::{NativeEvalOutput, NixNative};
use serde::Serialize;

#[derive(Debug)]
struct Arguments {
    expression: PathBuf,
    allowed_paths: Vec<PathBuf>,
    module_owners: Vec<(PathBuf, String)>,
    root_owners: Vec<(String, String)>,
    cache_root: Option<PathBuf>,
    max_eval_steps: Option<u64>,
    reject_obvious_divergence: bool,
}

#[derive(Serialize)]
struct Output {
    graph: aos_nix::OptionGraph,
    manifest: serde_json::Value,
    stats: Stats,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Stats {
    /// Number of native evaluator invocations made by this command.
    evaluation_iterations: u64,
    /// Number of error-driven provider fixpoint rounds made by this command.
    provider_fixpoint_iterations: u64,
    cache_hits: u64,
    cache_misses: u64,
    early_cutoffs: u64,
    root_cutoffs: u64,
    force_cache_hits: u64,
    imports_evaluated: u64,
    thunks_forced: u64,
}

fn main() -> Result<()> {
    let arguments = parse_arguments(std::env::args_os().skip(1))?;
    let expression = std::fs::read_to_string(&arguments.expression).with_context(|| {
        format!(
            "reading parity expression {}",
            arguments.expression.display()
        )
    })?;
    if arguments.reject_obvious_divergence {
        aos_nix::totality::reject_obvious_divergence(&expression)
            .context("running native pre-evaluation totality analysis")?;
    }

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Pure);
    options.set_reject_ambient_search_path(true);
    if let Some(base) = arguments.expression.parent() {
        options
            .set_path_literal_base(base.as_os_str().as_encoded_bytes().to_vec())
            .context("setting parity expression base")?;
    }
    if let Some(cache_root) = &arguments.cache_root {
        options.set_parse_cache_root(cache_root.join("parse"));
        options.set_persist_cache_root(cache_root.join("persist"));
        options.set_eval_cache_enabled(true);
    }
    options.set_max_eval_steps(arguments.max_eval_steps);
    for path in std::iter::once(&arguments.expression).chain(&arguments.allowed_paths) {
        options
            .add_allowed_path(path.as_os_str().as_encoded_bytes().to_vec())
            .with_context(|| format!("allowing parity input {}", path.display()))?;
    }
    let evaluator = NixNative::with_options(0, options).context("initializing native evaluator")?;
    let (NativeEvalOutput { json, option_graph }, stats) = evaluator
        .eval_expr_with_option_graph_and_stats(
            &expression,
            arguments.module_owners,
            arguments.root_owners,
        )
        .context("evaluating parity expression")?;
    let manifest = serde_json::from_str(&json).context("decoding native manifest")?;
    let output = Output {
        graph: option_graph,
        manifest,
        stats: Stats {
            // This binary is the native one-shot resolver intrinsic. It loads
            // the authenticated provider set once and never runs the legacy
            // error-parse/fetch/re-evaluate loop.
            evaluation_iterations: 1,
            provider_fixpoint_iterations: 0,
            cache_hits: stats.cache_hits(),
            cache_misses: stats.cache_misses(),
            early_cutoffs: stats.early_cutoffs(),
            root_cutoffs: stats.root_cutoffs(),
            force_cache_hits: stats.force_cache_hits(),
            imports_evaluated: stats.imports_evaluated(),
            thunks_forced: stats.thunks_forced(),
        },
    };
    serde_json::to_writer(std::io::stdout().lock(), &output)
        .context("writing native parity output")?;
    std::io::stdout()
        .lock()
        .write_all(b"\n")
        .context("terminating native parity output")?;
    Ok(())
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> Result<Arguments> {
    let mut arguments = arguments.into_iter();
    let expression = arguments
        .next()
        .map(PathBuf::from)
        .context("usage: aos-nix-eval EXPRESSION [--allow PATH] [--module-owner PATH=PACKAGE] [--root-owner ROOT=PACKAGE]")?;
    let mut parsed = Arguments {
        expression,
        allowed_paths: Vec::new(),
        module_owners: Vec::new(),
        root_owners: Vec::new(),
        cache_root: None,
        max_eval_steps: None,
        reject_obvious_divergence: false,
    };

    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .with_context(|| format!("missing value for {}", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--allow") => parsed.allowed_paths.push(PathBuf::from(value)),
            Some("--module-owner") => {
                let (path, package) = split_owner(value, "module owner")?;
                parsed.module_owners.push((PathBuf::from(path), package));
            }
            Some("--root-owner") => {
                let (root, package) = split_owner(value, "root owner")?;
                let root = root
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("root owner is not UTF-8"))?;
                parsed.root_owners.push((root, package));
            }
            Some("--cache-root") => parsed.cache_root = Some(PathBuf::from(value)),
            Some("--max-eval-steps") => {
                parsed.max_eval_steps = Some(
                    value
                        .to_str()
                        .context("max eval steps is not UTF-8")?
                        .parse()
                        .context("max eval steps is not an unsigned integer")?,
                );
            }
            Some("--reject-obvious-divergence") => {
                parsed.reject_obvious_divergence = match value.to_str() {
                    Some("yes" | "true" | "1") => true,
                    Some("no" | "false" | "0") => false,
                    _ => bail!("--reject-obvious-divergence expects yes or no"),
                };
            }
            _ => bail!("unknown aos-nix-eval argument: {}", flag.to_string_lossy()),
        }
    }
    Ok(parsed)
}

fn split_owner(value: OsString, description: &str) -> Result<(OsString, String)> {
    let bytes = value.as_encoded_bytes();
    let separator = bytes
        .iter()
        .rposition(|byte| *byte == b'=')
        .with_context(|| format!("{description} must use VALUE=PACKAGE"))?;
    let left = OsString::from_vec(bytes[..separator].to_vec());
    let package = std::str::from_utf8(&bytes[separator + 1..])
        .with_context(|| format!("{description} package is not UTF-8"))?
        .to_string();
    if left.is_empty() || package.is_empty() {
        bail!("{description} must use non-empty VALUE=PACKAGE");
    }
    Ok((left, package))
}
