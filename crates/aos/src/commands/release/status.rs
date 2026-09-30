//! Read-only reconciliation of a captured release journal.
//!
//! Prints the global lifecycle state, then one `<destination>: <state>` line
//! per destination: every published destination, plus the plan's
//! unpublished destinations as `pending` when `--plan` is given.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::plan::ReleasePlan;

use crate::cli::ReleaseStatusArgs;

use super::capture;
use super::journal::Journal;

/// Validates and displays the latest durable release state.
pub(super) fn run(args: &ReleaseStatusArgs, printer: &Printer) -> Result<()> {
    let journal = Journal::read(&args.journal, "release journal")?;
    let latest = journal.entries.last().context("release journal is empty")?;

    let mut destinations: BTreeMap<String, String> = journal
        .summary
        .destinations
        .iter()
        .map(|(name, state)| (name.clone(), state.to_string()))
        .collect();
    if let Some(path) = &args.plan {
        let bytes = capture::control_file(path, "release plan")?;
        canonical::require_canonical(&bytes, "release plan")?;
        let plan: ReleasePlan = canonical::from_slice(&bytes, "release plan")?;
        aos_release::verify::verify_journal_for_plan(&plan, &journal.entries)?;
        for destination in &plan.destinations {
            destinations
                .entry(destination.name.clone())
                .or_insert_with(|| "pending".to_owned());
        }
        if destinations.len() != plan.destinations.len() {
            bail!("journal records a destination outside the plan");
        }
    }

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.status/v1",
        "state": journal.summary.global,
        "destinations": destinations,
        "sequence": latest.sequence,
        "plan_digest": latest.plan_digest,
        "manifest_digest": latest.manifest_digest,
        "operation_ids": latest.operation_ids,
        "evidence": latest.evidence,
        "recorded_at": latest.recorded_at,
    })) {
        return Ok(());
    }
    println!("State: {}", journal.summary.global);
    for (destination, state) in &destinations {
        println!("{destination}: {state}");
    }
    printer.kv("Sequence", &latest.sequence.to_string());
    printer.kv("Plan", &latest.plan_digest.to_string());
    if let Some(manifest) = latest.manifest_digest {
        printer.kv("Manifest", &manifest.to_string());
    }
    printer.kv("Recorded", &latest.recorded_at);
    Ok(())
}
