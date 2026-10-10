//! Canonical package assessment reads through the public Hub API.
//!
//! Domain payloads retain their original field names inside the Hub CLI
//! envelope so local tooling can consume the exact same inner document.

use anyhow::Result;
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment_runtime::application::ScanReceiptV1;
use aos_assessment_runtime::application::{AssessmentStatusV1, StatusQueryV1};
use aos_assessment_runtime::control::{
    ScanCancellationV1, ScanListQueryV1, ScanListV1, ScanLookupV1, ScanRetryV1, ScanSubmissionV1,
};
use aos_contract::Sha256Digest;
use aos_core::output::{OutputMode, Printer};
use aos_maintain::presentation::escape_terminal as escape_bounded_terminal;
use aos_remote::{hub_rpc, hub_types};

use super::client::hub_client;
use crate::cli::{HubAssessmentCmd, HubAssessmentScansCmd};
use crate::commands::input::read_bounded_file;

fn escape_terminal(text: &str) -> String {
    escape_bounded_terminal(text, 4096)
}

/// Executes assessment reads with the normal explicit Hub credential selection.
///
/// # Errors
/// Returns an error for invalid selectors, unavailable credentials, failed API
/// calls or incompatible canonical inner documents.
pub(super) async fn run(printer: &Printer, command: &HubAssessmentCmd) -> Result<()> {
    match command {
        HubAssessmentCmd::Scan {
            access,
            registry,
            request,
            wait,
            wait_seconds,
        } => {
            let bytes = read_bounded_file(request, 262_144, "assessment scan submission")?;
            let submission = ScanSubmissionV1::from_slice(&bytes)?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response = client
                .call_topology(
                    hub_rpc::RequestPackageScan,
                    &hub_types::AssessmentControlRequest {
                        registry_slug: registry.clone(),
                        document_json: serde_json::to_vec(&submission)?,
                    },
                )
                .await?;
            let receipt = ScanReceiptV1::from_slice(&response.document_json)?;
            let receipt = if *wait {
                wait_for_scan(&client, registry, receipt, *wait_seconds).await?
            } else {
                receipt
            };
            print_receipt(printer, receipt)
        }
        HubAssessmentCmd::Scans { command } => run_scans(printer, command).await,
        HubAssessmentCmd::Status {
            access,
            registry,
            profiles,
            limit,
            after_subject,
            inventory_digest,
            policy_digest,
        } => {
            let mut profiles = profiles.iter().copied().map(Into::into).collect::<Vec<_>>();
            profiles.sort();
            profiles.dedup();
            let query = StatusQueryV1 {
                schema: "aos.assessment-status-query/v1".into(),
                profiles,
                limit: *limit,
                after_subject: after_subject.clone(),
                inventory_digest: inventory_digest
                    .as_deref()
                    .map(Sha256Digest::parse)
                    .transpose()?,
                policy_digest: policy_digest
                    .as_deref()
                    .map(Sha256Digest::parse)
                    .transpose()?,
            };
            query.validate()?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response = client
                .call_topology(
                    hub_rpc::GetAssessmentStatus,
                    &hub_types::AssessmentStatusRequest {
                        registry_slug: registry.clone(),
                        query_json: serde_json::to_vec(&query)?,
                    },
                )
                .await?;
            let status = AssessmentStatusV1::from_slice(&response.document_json)?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({"schema_version":"aos.hub.cli/v1", "kind":"assessment-status", "data":status}));
            } else {
                for subject in &status.subjects {
                    printer.info(&format!(
                        "{} {} ({})",
                        escape_terminal(&subject.package_coordinate),
                        escape_terminal(&subject.version),
                        escape_terminal(&subject.platform)
                    ));
                    for profile in &subject.profiles {
                        let evidence = if profile.committed_generation == 0 {
                            "unassessed"
                        } else if profile.fresh {
                            "complete and fresh"
                        } else {
                            "incomplete or expired"
                        };
                        printer.info(&format!(
                            "  {:?}: {evidence}{}",
                            profile.profile,
                            if profile.pending {
                                "; scan pending"
                            } else {
                                ""
                            }
                        ));
                    }
                }
                printer.info(&format!("Observed at {}", status.as_of));
                if let Some(next) = status.next_subject {
                    printer.info(&format!(
                        "Next page: --after-subject {} --inventory-digest {} --policy-digest {}",
                        escape_terminal(&next),
                        status.inventory_digest,
                        status.policy_digest
                    ));
                }
            }
            Ok(())
        }
        HubAssessmentCmd::Get {
            access,
            registry,
            digest,
        } => {
            let digest = Sha256Digest::parse(digest)?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response = client
                .call_topology(
                    hub_rpc::GetPackageAssessment,
                    &hub_types::AssessmentObjectRequest {
                        registry_slug: registry.clone(),
                        assessment_digest: digest.to_string(),
                    },
                )
                .await?;
            let assessment = PackageAssessmentV1::from_slice(&response.document_json)?;
            anyhow::ensure!(
                assessment.digest()? == digest,
                "Hub returned a different assessment identity"
            );
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({"schema_version":"aos.hub.cli/v1", "kind":"package-assessment", "data":assessment}));
            } else {
                for subject in &assessment.subject_results {
                    for line in aos_maintain::presentation::assessment_subject_lines(
                        subject,
                        &subject.subject_ref,
                    ) {
                        printer.info(&line);
                    }
                }
            }
            Ok(())
        }
    }
}

async fn wait_for_scan(
    client: &aos_remote::HubClient,
    registry: &str,
    mut receipt: ScanReceiptV1,
    seconds: u32,
) -> Result<ScanReceiptV1> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(u64::from(seconds));
    let scan_id = receipt.scan_id.clone();
    let mut delay = 1;
    while !receipt.state.is_terminal() {
        let next = tokio::time::timeout_at(deadline, async {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            let response = client
                .call_topology(
                    hub_rpc::GetPackageScan,
                    &hub_types::AssessmentControlRequest {
                        registry_slug: registry.into(),
                        document_json: serde_json::to_vec(&ScanLookupV1 {
                            schema: "aos.assessment-scan-lookup/v1".into(),
                            scan_id: scan_id.clone(),
                        })?,
                    },
                )
                .await?;
            ScanReceiptV1::from_slice(&response.document_json)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "waiting for scan {} timed out; the durable Hub operation continues",
                escape_terminal(&scan_id)
            )
        })??;
        anyhow::ensure!(
            next.scan_id == receipt.scan_id
                && next.request_digest == receipt.request_digest
                && next.generation == receipt.generation
                && next.request.resource_scope == receipt.request.resource_scope
                && next.resource_version >= receipt.resource_version,
            "Hub scan polling returned a conflicting identity or older revision"
        );
        receipt = next;
        delay = (delay * 2).min(5);
    }
    Ok(receipt)
}

async fn run_scans(printer: &Printer, command: &HubAssessmentScansCmd) -> Result<()> {
    let (access, registry, document_json) = match command {
        HubAssessmentScansCmd::List {
            access,
            registry,
            limit,
            after_scan,
        } => (
            access,
            registry,
            serde_json::to_vec(&ScanListQueryV1 {
                schema: "aos.assessment-scan-list-query/v1".into(),
                limit: *limit,
                after_scan: after_scan.clone(),
            })?,
        ),
        HubAssessmentScansCmd::Inspect {
            access,
            registry,
            scan_id,
        } => (
            access,
            registry,
            serde_json::to_vec(&ScanLookupV1 {
                schema: "aos.assessment-scan-lookup/v1".into(),
                scan_id: scan_id.clone(),
            })?,
        ),
        HubAssessmentScansCmd::Cancel {
            access,
            registry,
            scan_id,
            expected_revision,
        } => (
            access,
            registry,
            serde_json::to_vec(&ScanCancellationV1 {
                schema: "aos.assessment-scan-cancellation/v1".into(),
                scan_id: scan_id.clone(),
                expected_revision: *expected_revision,
            })?,
        ),
        HubAssessmentScansCmd::Retry {
            access,
            registry,
            scan_id,
            idempotency_key,
        } => (
            access,
            registry,
            serde_json::to_vec(&ScanRetryV1 {
                schema: "aos.assessment-scan-retry/v1".into(),
                scan_id: scan_id.clone(),
                idempotency_key: idempotency_key.clone(),
            })?,
        ),
    };
    let request = hub_types::AssessmentControlRequest {
        registry_slug: registry.clone(),
        document_json,
    };
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    let response = match command {
        HubAssessmentScansCmd::List { .. } => {
            client
                .call_topology(hub_rpc::ListPackageScans, &request)
                .await?
        }
        HubAssessmentScansCmd::Inspect { .. } => {
            client
                .call_topology(hub_rpc::GetPackageScan, &request)
                .await?
        }
        HubAssessmentScansCmd::Cancel { .. } => {
            client
                .call_topology(hub_rpc::CancelPackageScan, &request)
                .await?
        }
        HubAssessmentScansCmd::Retry { .. } => {
            client
                .call_topology(hub_rpc::RetryPackageScan, &request)
                .await?
        }
    };
    if matches!(command, HubAssessmentScansCmd::List { .. }) {
        let page = ScanListV1::from_slice(&response.document_json)?;
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({"schema_version":"aos.hub.cli/v1", "kind":"assessment-scans", "data":page}));
        } else {
            for scan in &page.scans {
                printer.info(&format!(
                    "{}: {:?}; generation {}; revision {}",
                    escape_terminal(&scan.scan_id),
                    scan.state,
                    scan.generation,
                    scan.resource_version
                ));
            }
            if let Some(next) = &page.next_scan {
                printer.info(&format!(
                    "Next page: --after-scan {}",
                    escape_terminal(next)
                ));
            }
        }
        Ok(())
    } else {
        print_receipt(printer, ScanReceiptV1::from_slice(&response.document_json)?)
    }
}

fn print_receipt(printer: &Printer, receipt: ScanReceiptV1) -> Result<()> {
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({"schema_version":"aos.hub.cli/v1", "kind":"assessment-scan", "data":receipt}));
    } else {
        printer.info(&format!(
            "Scan {}: {:?}; generation {}; revision {}",
            escape_terminal(&receipt.scan_id),
            receipt.state,
            receipt.generation,
            receipt.resource_version
        ));
        if let Some(digest) = receipt.assessment_digest {
            printer.info(&format!("Assessment {digest}"));
        }
    }
    Ok(())
}
