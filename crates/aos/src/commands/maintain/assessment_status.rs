//! Local read adapter for the shared, inventory-complete profile status contract.

use anyhow::Result;
use aos_assessment_http::PhysicalClock;
use aos_assessment_runtime::application::StatusQueryV1;
use aos_assessment_runtime::ports::Clock as _;
use aos_contract::Sha256Digest;
use aos_core::nix::NixRunner;
use aos_core::output::{OutputMode, Printer};

use super::{inventory, state::StateStore};
use crate::cli::{Cli, MaintainArgs, MaintainStatusArgs};

/// Renders independent local profile heads without provider or recovery effects.
///
/// # Errors
/// Returns an error for invalid selectors, missing/corrupt custody, legacy
/// inventory without a current admission, or an invalidated continuation.
pub fn run_local_status(
    cli: &Cli,
    args: &MaintainArgs,
    command: &MaintainStatusArgs,
    printer: &Printer,
) -> Result<()> {
    let nix = NixRunner::new(cli.verbose, cli.quiet)?;
    let coordinates = inventory::repository_coordinates(nix.root())?;
    let store = StateStore::open(args.state_dir.as_deref(), &coordinates)?;
    let query = StatusQueryV1 {
        schema: "aos.assessment-status-query/v1".into(),
        profiles: crate::cli::assessment_profiles(&command.profiles),
        limit: command.limit.unwrap_or(100),
        after_subject: command.after_subject.clone(),
        inventory_digest: command
            .inventory_digest
            .as_deref()
            .map(Sha256Digest::parse)
            .transpose()?,
        policy_digest: command
            .policy_digest
            .as_deref()
            .map(Sha256Digest::parse)
            .transpose()?,
    };
    let status = store.local_assessment_status(&query, PhysicalClock.now()?)?;
    if printer.mode() == OutputMode::Json || args.jsonl {
        printer.json(&serde_json::json!({
            "schema_version": "aos.assessment-cli/v1", "kind": "assessment-status",
            "execution": {"mode": "local"}, "data": status,
        }));
    } else {
        crate::commands::assessment_presentation::render_status(printer, &status);
    }
    Ok(())
}
