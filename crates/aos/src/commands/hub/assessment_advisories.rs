//! Exact advisory/CVE inspection over the ordinary scoped Hub transport.

use anyhow::{Result, bail};
use aos_assessment_runtime::advisories::retained::{AdvisoryPageV2, AdvisoryQueryV2};
use aos_assessment_runtime::advisories::{AdvisoryPageV1, AdvisoryQueryV1};
use aos_contract::Sha256Digest;
use aos_core::output::{OutputMode, Printer};
use aos_remote::{hub_rpc, hub_types};

use super::client::hub_client;
use crate::cli::HubAssessmentCmd;

/// Reads retained advisory revisions without requesting provider refresh.
///
/// # Errors
/// Returns an error for invalid selection, unavailable authority, failed RPCs
/// or a response that changes the exact selected advisory or snapshot.
pub(super) async fn run(printer: &Printer, command: &HubAssessmentCmd) -> Result<()> {
    let HubAssessmentCmd::Advisory {
        access,
        registry,
        advisory_id,
        assessment_digest,
        subject_ref,
        after_record,
        retained,
        cursor,
        resource_scope,
        limit,
    } = command
    else {
        bail!("unsupported advisory command");
    };
    let query = AdvisoryQueryV1 {
        schema: "aos.assessment-advisory-query/v1".into(),
        advisory_id: advisory_id.clone(),
        resource_scope: resource_scope.clone(),
        assessment_digest: assessment_digest
            .as_deref()
            .map(Sha256Digest::parse)
            .transpose()?,
        subject_ref: subject_ref.clone(),
        after_record: after_record
            .as_deref()
            .map(Sha256Digest::parse)
            .transpose()?,
        limit: *limit,
    };
    query.validate()?;
    if (*retained || cursor.is_some()) && after_record.is_some() {
        bail!("legacy record positions cannot be combined with retained advisory cursors");
    }
    let retained_query = if *retained || cursor.is_some() {
        let selection = AdvisoryQueryV2 {
            schema: "aos.assessment-advisory-query/v2".into(),
            advisory_id: query.advisory_id.clone(),
            resource_scope: query.resource_scope.clone(),
            assessment_digest: query.assessment_digest,
            subject_ref: query.subject_ref.clone(),
            cursor: cursor.clone(),
            limit: query.limit,
        };
        selection.validate()?;
        Some(selection)
    } else {
        None
    };
    let document_json = if let Some(query) = &retained_query {
        serde_json::to_vec(query)?
    } else {
        serde_json::to_vec(&query)?
    };
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    let response = client
        .call_topology(
            hub_rpc::GetAssessmentAdvisory,
            &hub_types::AssessmentControlRequest {
                registry_slug: registry.clone(),
                document_json,
            },
        )
        .await?;
    if let Some(query) = &retained_query {
        let retained = AdvisoryPageV2::from_slice(&response.document_json)?;
        retained.validate_for(query)?;
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "schema_version":"aos.hub.cli/v1", "kind":"assessment-advisory", "data":retained,
            }));
        } else {
            crate::commands::assessment_presentation::render_advisory(printer, &retained.page);
            printer.info(&format!("Capture expires {}", retained.expires_at));
            if let Some(cursor) = &retained.next_cursor {
                printer.info(&format!("Next cursor {cursor}"));
            }
        }
        return Ok(());
    }
    let page = AdvisoryPageV1::from_slice(&response.document_json)?;
    page.validate_for(&query)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "schema_version":"aos.hub.cli/v1", "kind":"assessment-advisory", "data":page,
        }));
        return Ok(());
    }
    crate::commands::assessment_presentation::render_advisory(printer, &page);
    Ok(())
}
