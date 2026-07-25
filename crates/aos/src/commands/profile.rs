//! `aos profile` — find build/dev artifacts that leaked into a runtime
//! closure.
//!
//! Two subcommands, both backed by the `aos-profile` crate:
//!
//! - `closure` — enumerate a target's runtime closure, rank paths by
//!   exclusive (dominator-subtree) size, and rule on every suspect build
//!   tool or dev output with the evidence that holds it in.
//! - `refs` — explain why one package references another, classifying
//!   each occurrence of the dependency's hash (ELF `.interp`, RPATH,
//!   `.comment`, shebang, `pkg-config`, …) so a leak can be fixed at the
//!   source.

use std::collections::HashMap;

use anyhow::{Context, Result};

use aos_core::nix::NixRunner;
use aos_core::output::{Printer, create_spinner};
use aos_profile::target::{Target, resolve};
use aos_profile::{ClosureGraph, report, scan};

use crate::cli::ProfileCmd;

/// `aos profile <closure|refs>` — dispatch to the profiling operation.
///
/// # Errors
///
/// Returns an error if a target fails to build, a store query fails, or
/// a referrer cannot be scanned.
pub fn run(nix: &NixRunner, printer: &Printer, cmd: &ProfileCmd) -> Result<()> {
    match cmd {
        ProfileCmd::Closure {
            target,
            top,
            suspects_only,
            deep,
        } => closure(nix, printer, target, *top, *suspects_only, *deep),
        ProfileCmd::Refs {
            package,
            dependency,
        } => refs(nix, printer, package, dependency),
    }
}

/// Resolves a target spec to a realised store path, building the
/// attribute first when necessary.
fn resolve_target(nix: &NixRunner, printer: &Printer, spec: &str) -> Result<String> {
    match resolve(spec) {
        Target::StorePath(p) => Ok(p),
        Target::Attr(attr) => {
            printer.info(&format!("Building '{attr}' to realise the closure..."));
            let spinner = create_spinner(&format!("building {attr}"));
            let path = nix
                .build(&attr, None)
                .with_context(|| format!("building '{attr}'"));
            spinner.finish_and_clear();
            Ok(path?.to_string_lossy().into_owned())
        }
    }
}

/// Profiles a target's runtime closure.
fn closure(
    nix: &NixRunner,
    printer: &Printer,
    target: &str,
    top: usize,
    suspects_only: bool,
    deep: bool,
) -> Result<()> {
    let path = resolve_target(nix, printer, target)?;

    let cli = aos_core::nix::NixCli::new(0);
    let spinner = create_spinner("enumerating closure");
    let graph = ClosureGraph::build(&cli, &path)?;
    spinner.finish_and_clear();

    printer.info(&format!(
        "Scanning {} paths for leaked references{}...",
        graph.paths.len(),
        if deep { " (deep)" } else { "" }
    ));
    let spinner = create_spinner("classifying references");
    let mut analysis = report::analyze(&graph, top, deep)?;
    spinner.finish_and_clear();

    if suspects_only {
        analysis.largest.clear();
        analysis.suspects.retain(|s| s.verdict.is_leak());
    }

    let value = serde_json::to_value(&analysis).context("serialising analysis")?;
    if printer.json_if_active(&value) {
        return Ok(());
    }

    report::render(printer, &analysis);
    Ok(())
}

/// Explains why `package` references `dependency`.
fn refs(nix: &NixRunner, printer: &Printer, package: &str, dependency: &str) -> Result<()> {
    let pkg_path = resolve_target(nix, printer, package)?;
    let dep_path = resolve_target(nix, printer, dependency)?;

    let dep_hash =
        scan::store_hash(&dep_path).with_context(|| format!("'{dep_path}' is not a store path"))?;
    let mut targets = HashMap::new();
    targets.insert(dep_hash.to_string(), dep_path.clone());

    let spinner = create_spinner("scanning referrer content");
    let found = scan::scan_path(&pkg_path, &targets)?;
    spinner.finish_and_clear();

    let sites = found.get(&dep_path).cloned().unwrap_or_default();
    let (v, note) = report::refine_verdict(&dep_path, &sites);

    if printer.mode() == aos_core::output::OutputMode::Json {
        let value = serde_json::json!({
            "package": pkg_path,
            "dependency": dep_path,
            "verdict": v,
            "note": note,
            "sites": sites,
        });
        printer.json(&value);
        return Ok(());
    }

    report::render_refs(printer, &pkg_path, &dep_path, &sites, v, note.as_deref());
    Ok(())
}
