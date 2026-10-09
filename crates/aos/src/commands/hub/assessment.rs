//! Canonical package assessment reads through the public Hub API.
//!
//! Domain payloads retain their original field names inside the Hub CLI
//! envelope so local tooling can consume the exact same inner document.

use anyhow::Result;
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment_runtime::application::{AssessmentStatusV1, StatusQueryV1};
use aos_contract::Sha256Digest;
use aos_core::output::{OutputMode, Printer};
use aos_maintain::presentation::escape_terminal as escape_bounded_terminal;
use aos_remote::{hub_rpc, hub_types};

use super::client::hub_client;
use crate::cli::HubAssessmentCmd;

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
                    printer.info(&escape_terminal(&subject.subject_ref));
                    for coverage in &subject.coverage {
                        printer.info(&format!(
                            "  {:?}: {:?}; {} of {} components evaluated",
                            coverage.profile,
                            coverage.state,
                            coverage.counts.evaluated,
                            coverage.counts.declared
                        ));
                    }
                    for finding in &subject.findings {
                        printer.info(&format!(
                            "  {}: {:?}",
                            escape_terminal(&finding.advisory_ids.join(", ")),
                            finding.applicability
                        ));
                    }
                    for version in &subject.versions {
                        printer.info(&format!(
                            "  {}: {:?}",
                            escape_terminal(&version.current.comparison_version),
                            version.decision
                        ));
                    }
                }
            }
            Ok(())
        }
    }
}
