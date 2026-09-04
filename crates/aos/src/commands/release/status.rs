//! Read-only reconciliation of a captured release journal.

use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_release::state::parse_journal;

use crate::cli::ReleaseStatusArgs;

use super::capture;

/// Validates and displays the latest durable release state.
pub(super) fn run(args: &ReleaseStatusArgs, printer: &Printer) -> Result<()> {
    let bytes = capture::control_file(&args.journal, "release journal")?;
    let entries = parse_journal(&bytes)?;
    let state = aos_release::verify::verify_journal(&entries)?;
    let latest = entries.last().context("release journal is empty")?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.status/v1",
        "state": state,
        "sequence": latest.sequence,
        "plan_digest": latest.plan_digest,
        "manifest_digest": latest.manifest_digest,
        "operation_ids": latest.operation_ids,
        "evidence": latest.evidence,
        "recorded_at": latest.recorded_at,
    })) {
        return Ok(());
    }
    printer.info(&format!("State: {state:?}"));
    printer.kv("Sequence", &latest.sequence.to_string());
    printer.kv("Plan", &latest.plan_digest.to_string());
    if let Some(manifest) = latest.manifest_digest {
        printer.kv("Manifest", &manifest.to_string());
    }
    printer.kv("Recorded", &latest.recorded_at);
    Ok(())
}
