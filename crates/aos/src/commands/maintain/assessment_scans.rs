//! Local adapters for the shared bounded scan lookup and cancellation contracts.
//!
//! Reads do not recover, restart or contact providers. Explicit recovery uses
//! released process leases; waiting never silently starts another operation.

use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use aos_assessment_http::PhysicalClock;
use aos_assessment_runtime::application::ScanReceiptV1;
use aos_assessment_runtime::control::{ScanCancellationV1, ScanListQueryV1};
use aos_assessment_runtime::ports::Clock as _;
use aos_assessment_runtime::scan::ScanState;
use aos_core::nix::NixRunner;
use aos_core::output::{OutputMode, Printer};
use aos_maintain::presentation::escape_terminal;

use crate::cli::{Cli, MaintainArgs, MaintainScansCommand};

use super::{inventory, state::StateStore};

/// Runs an exact local journal operation using the same Hub-facing contracts.
///
/// # Errors
/// Returns an error for missing/corrupt state, invalid selections, revision
/// conflicts, unavailable process custody or unsuccessful/exhausted waits.
pub async fn run_local_scans(
    cli: &Cli,
    args: &MaintainArgs,
    command: &MaintainScansCommand,
    printer: &Printer,
) -> Result<()> {
    let nix = NixRunner::new(cli.verbose, cli.quiet)?;
    let coordinates = inventory::repository_coordinates(nix.root())?;
    let store = StateStore::open(args.state_dir.as_deref(), &coordinates)?;
    match command {
        MaintainScansCommand::List { limit, after_scan } => {
            let page = store.list_local_assessment_scans(
                &ScanListQueryV1 {
                    schema: "aos.assessment-scan-list-query/v1".into(),
                    limit: *limit,
                    after_scan: after_scan.clone(),
                },
                PhysicalClock.now()?,
            )?;
            if printer.mode() == OutputMode::Json || args.jsonl {
                printer.json(
                    &serde_json::json!({"schema_version":"aos.assessment-cli/v1",
                    "kind":"assessment-scans", "execution":{"mode":"local"}, "data":page}),
                );
            } else {
                for scan in &page.scans {
                    printer.info(&format!(
                        "{}: {}; generation {}; revision {}",
                        escape_terminal(&scan.scan_id, 128),
                        scan.state.as_str(),
                        scan.generation,
                        scan.resource_version
                    ));
                }
            }
        }
        MaintainScansCommand::Inspect { scan_id } => {
            print_local_receipt(
                args,
                printer,
                &store.inspect_local_assessment_scan(scan_id)?,
            );
        }
        MaintainScansCommand::Cancel {
            scan_id,
            expected_revision,
        } => {
            let receipt = store.cancel_local_assessment_scan(&ScanCancellationV1 {
                schema: "aos.assessment-scan-cancellation/v1".into(),
                scan_id: scan_id.clone(),
                expected_revision: *expected_revision,
            })?;
            print_local_receipt(args, printer, &receipt);
        }
        MaintainScansCommand::Wait { scan_id, timeout } => {
            let started = Instant::now();
            loop {
                let receipt = store.inspect_local_assessment_scan(scan_id)?;
                if receipt.state.is_terminal() {
                    print_local_receipt(args, printer, &receipt);
                    if !matches!(receipt.state, ScanState::Succeeded | ScanState::Partial) {
                        bail!("local assessment scan ended in {}", receipt.state.as_str());
                    }
                    break;
                }
                if started.elapsed() >= Duration::from_secs(u64::from(*timeout)) {
                    bail!(
                        "local assessment wait expired; the operation remains {}",
                        receipt.state.as_str()
                    );
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                    signal = tokio::signal::ctrl_c() => {
                        signal?;
                        bail!("local assessment wait interrupted; the operation is unchanged");
                    }
                }
            }
        }
        MaintainScansCommand::Recover { limit } => {
            let receipts = store.recover_local_assessment_scans(*limit as usize)?;
            if printer.mode() == OutputMode::Json || args.jsonl {
                printer.json(&serde_json::json!({"schema_version":"aos.assessment-cli/v1",
                    "kind":"assessment-scan-recovery", "execution":{"mode":"local"}, "data":receipts}));
            } else {
                for receipt in &receipts {
                    print_local_receipt(args, printer, receipt);
                }
            }
        }
    }
    Ok(())
}

pub(super) fn print_local_receipt(args: &MaintainArgs, printer: &Printer, receipt: &ScanReceiptV1) {
    if printer.mode() == OutputMode::Json || args.jsonl {
        printer.json(
            &serde_json::json!({"schema_version":"aos.assessment-cli/v1",
            "kind":"assessment-scan", "execution":{"mode":"local"}, "data":receipt}),
        );
    } else {
        printer.info(&format!(
            "Scan {}: {}; generation {}; revision {}",
            escape_terminal(&receipt.scan_id, 128),
            receipt.state.as_str(),
            receipt.generation,
            receipt.resource_version
        ));
        if let Some(digest) = receipt.assessment_digest {
            printer.info(&format!("Assessment {digest}"));
        }
        if let Some(code) = &receipt.failure_code {
            printer.info(&format!("Reason: {}", escape_terminal(code, 128)));
        }
    }
}
