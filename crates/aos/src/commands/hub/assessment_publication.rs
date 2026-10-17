//! Exact publication availability over the normal scoped Hub transport.

use anyhow::{Result, bail};
use aos_assessment_runtime::publication::{
    PublicationAvailability, PublicationQueryV1, PublicationStatusV1,
};
use aos_contract::Sha256Digest;
use aos_core::output::{OutputMode, Printer};
use aos_maintain::presentation::escape_terminal;
use aos_remote::{hub_rpc, hub_types};

use super::client::hub_client;
use crate::cli::HubAssessmentCmd;

/// Inspects publication coordinates without acquiring evidence or enabling scans.
///
/// # Errors
/// Returns an error for invalid selection, unavailable credentials, failed RPCs
/// or an incompatible response that changes the selected publication or page.
pub(super) async fn run(printer: &Printer, command: &HubAssessmentCmd) -> Result<()> {
    let HubAssessmentCmd::Publication {
        access,
        registry,
        limit,
        after_output,
        publication_digest,
        resource_scope,
    } = command
    else {
        bail!("unsupported publication inspection command");
    };
    let query = PublicationQueryV1 {
        schema: "aos.assessment-publication-query/v1".into(),
        limit: *limit,
        after_output: after_output
            .as_deref()
            .map(Sha256Digest::parse)
            .transpose()?,
        publication_digest: publication_digest
            .as_deref()
            .map(Sha256Digest::parse)
            .transpose()?,
        resource_scope: resource_scope.clone(),
    };
    let document_json = serde_json::to_vec(&query)?;
    PublicationQueryV1::from_slice(&document_json)?;
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    let response = client
        .call_topology(
            hub_rpc::GetAssessmentPublicationStatus,
            &hub_types::AssessmentControlRequest {
                registry_slug: registry.clone(),
                document_json,
            },
        )
        .await?;
    let status = PublicationStatusV1::from_slice(&response.document_json)?;
    status.validate_for(&query)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "schema_version": "aos.hub.cli/v1", "kind": "assessment-publication", "data": status,
        }));
        return Ok(());
    }
    let description = match &status.availability {
        PublicationAvailability::NoPublication => {
            "No authenticated publication is available.".into()
        }
        PublicationAvailability::AwaitingProjection { release } => format!(
            "Publication {} awaits a bounded complete catalog and artifact snapshot.",
            escape_terminal(&release.release, 255)
        ),
        PublicationAvailability::InvalidProjection { release } => format!(
            "Publication {} has an invalid projection; its package assessment status is unknown.",
            escape_terminal(&release.release, 255)
        ),
        PublicationAvailability::Unassessable {
            unsupported_count, ..
        } => format!(
            "No scan declarations are available; {unsupported_count} published primary outputs remain unassessed."
        ),
        PublicationAvailability::Ready {
            declared_outputs,
            unsupported_count,
            active_inventory_revision,
            ..
        } => format!(
            "Scan declarations cover {declared_outputs} published primary outputs; {unsupported_count} lack declarations. Inventory {}.",
            if active_inventory_revision.is_some() {
                "is active"
            } else {
                "awaits activation"
            }
        ),
    };
    printer.info(&description);
    for output in &status.unsupported_outputs {
        printer.info(&format!(
            "  {} {} ({}): no scan declaration [{}]",
            escape_terminal(&output.package_name, 255),
            escape_terminal(&output.version, 256),
            escape_terminal(&output.platform, 128),
            output.output_ref
        ));
    }
    printer.info(&format!("Observed at {}", status.as_of));
    if let Some(next) = status.next_output {
        let digest = status
            .publication_digest
            .ok_or_else(|| anyhow::anyhow!("publication continuation lacks custody"))?;
        printer.info(&format!(
            "Continue with --after-output {next} --publication-digest {digest} --resource-scope {}",
            escape_terminal(&status.resource_scope, 128)
        ));
    }
    Ok(())
}
