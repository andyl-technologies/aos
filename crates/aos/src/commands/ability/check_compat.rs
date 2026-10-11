//! Checks one release owner's structural interface compatibility.
//!
//! Inputs are bounded native documentation and an optional JSON array of exact
//! exceptions. The shared comparator owns compatibility policy; this command
//! renders its checked report before failing an incompatible release check.

use anyhow::{Context as _, Result};
use aos_core::output::{OutputMode, Printer};
use aos_doc_model::runtime::compatibility::{
    CompatibilityException, CompatibilityReport, ReleaseOwner, check_compatibility,
};

use crate::cli::AbilityCheckCompatArgs;
use crate::commands::input::read_bounded_file;

const MAX_EXCEPTION_BYTES: u64 = 64 * 1024;

/// Signals an incompatible decision whose diagnostic report was already emitted.
#[derive(Debug)]
pub(crate) struct CompatibilityFailure;

impl std::fmt::Display for CompatibilityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("release interface compatibility check failed")
    }
}

impl std::error::Error for CompatibilityFailure {}

/// Reads the comparison inputs and renders the shared compatibility decision.
///
/// # Errors
/// Returns an error for invalid or oversized inputs, invalid exceptions or
/// release identities, an incompatible result, or failed report serialization.
pub(super) fn run(args: &AbilityCheckCompatArgs, printer: &Printer) -> Result<()> {
    let before = super::read_document(&args.before, None)?;
    let after = super::read_document(&args.after, None)?;
    let owner = match (&args.owner, args.os) {
        (Some(package), false) => ReleaseOwner::Package(package.clone()),
        (None, true) => ReleaseOwner::Os,
        _ => anyhow::bail!("select exactly one release owner with --owner or --os"),
    };
    let exceptions: Vec<CompatibilityException> = match &args.exceptions {
        Some(path) => {
            let bytes = read_bounded_file(path, MAX_EXCEPTION_BYTES, "compatibility exceptions")?;
            serde_json::from_slice(&bytes).context("decoding compatibility exceptions")?
        }
        None => Vec::new(),
    };

    let report = check_compatibility(&before, &after, &owner, &exceptions)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::to_value(&report)?);
    } else {
        printer.raw(&render_report(&report)?);
    }
    if !report.compatible {
        return Err(CompatibilityFailure.into());
    }
    Ok(())
}

fn render_report(report: &CompatibilityReport) -> Result<String> {
    let status = if report.compatible {
        "Compatible"
    } else {
        "Incompatible"
    };
    let mut rendered = format!("{status} release interface\n");
    if report.compatibility_boundary {
        rendered.push_str("The release version leaves the previous compatibility requirement.\n");
    }
    for change in &report.changes {
        let status = if change.waived { "waived" } else { "unwaived" };
        let path = change
            .path
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join(".");
        rendered.push_str(&format!(
            "\n{} ({status}): {}\n  {path}\n",
            change.id, change.reason
        ));
    }
    Ok(rendered)
}
