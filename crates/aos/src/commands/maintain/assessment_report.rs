//! Exact retained local assessment reports and independent automation exit policy.
//!
//! Reads reproduce protected historical evidence without advancing scan heads,
//! evaluating current package metadata or acquiring provider observations.

use anyhow::{Context as _, Result};
use aos_contract::Sha256Digest;
use aos_core::{
    nix::NixRunner,
    output::{OutputMode, Printer},
};

use super::{inventory, state::StateStore};
use crate::cli::{Cli, MaintainArgs, MaintainReportArgs};

/// Reads one exact retained assessment in the current local journal namespace.
///
/// # Errors
/// Returns an error for absent/invalid identity, unavailable tools or state,
/// corrupt custody, conflicting policy scope or a selected report-policy failure.
pub fn run_assessment_report(
    cli: &Cli,
    args: &MaintainArgs,
    command: &MaintainReportArgs,
    printer: &Printer,
) -> Result<()> {
    let digest = command
        .assessment_digest
        .as_deref()
        .context("exact assessment digest required")?;
    let digest = Sha256Digest::parse(digest)?;
    let nix = NixRunner::new(cli.verbose, cli.quiet)?;
    let coordinates = inventory::repository_coordinates(nix.root())?;
    let store = StateStore::open(args.state_dir.as_deref(), &coordinates)?;
    let bundle = store.export_local_assessment_evidence(digest)?;
    let outcome = crate::commands::assessment_policy::policy(&command.fail_on)?
        .map(|policy| policy.evaluate(&bundle.assessment))
        .transpose()?;
    if args.jsonl || printer.mode() == OutputMode::Json {
        let mut envelope = serde_json::json!({
            "schema_version":"aos.assessment-cli/v1", "kind":"package-assessment",
            "execution":{"mode":"local", "scan_input_digest":bundle.input.digest()?,
                "evaluated_at":bundle.input.evaluated_at},
            "data":bundle.assessment,
        });
        if let Some(outcome) = &outcome {
            outcome.to_bytes(&bundle.assessment)?;
            envelope["reportPolicy"] = serde_json::to_value(outcome)?;
        }
        printer.json(&envelope);
    } else {
        printer.info(&format!(
            "Retained assessment {digest}; evaluated at {}",
            bundle.input.evaluated_at
        ));
        for subject in &bundle.assessment.subject_results {
            for line in
                aos_maintain::presentation::assessment_subject_lines(subject, &subject.subject_ref)
            {
                printer.info(&line);
            }
        }
    }
    crate::commands::assessment_policy::finish(printer, args.jsonl, outcome.as_ref())
}
