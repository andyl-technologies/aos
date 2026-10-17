//! Canonical dynamic originals and independent reader-time images.
//!
//! Reader values can bind an immutable original. They cannot recreate a prior
//! authorization, CAS transaction, compact omitted reply, or provider outcome.
//!
//! Independent reader input families use these closed shapes. The admission
//! and optional intent/receipt fields contain the actual typed SQL documents.
//!
//! ```text
//! publication: {"publicationId":"...","registryId":"1","registrySlug":"...",
//!   "ordinal":"1","state":"preparing","manifestDigest":"...",
//!   "refsDigest":"...","registryScopeKey":"..."}
//! session: {"original":{"sessionId":"...","publicationId":"...",
//!   "state":"admitted","admission":{...},"resourceVersion":"1",
//!   "ownerScopeKey":"...","cacheId":null,"cacheTicketId":null},
//!   "completeIntent":null,"completionReceipt":null}
//! ```

use super::{positive_reader_version, AdmissionRow, Capture, ReaderOriginal};
use crate::files;
use anyhow::{ensure, Result};
use aos_hub_core::application_body_observation::{image, EncodedImage};
use aos_hub_core::direct_upload::*;
use aos_proto_types::{GetRegistryPublicationRequest, RegistryPublication};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationRow {
    publication_id: String,
    registry_id: String,
    registry_slug: String,
    ordinal: String,
    state: String,
    manifest_digest: String,
    refs_digest: String,
    registry_scope_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionRow {
    original: AdmissionRow,
    complete_intent: Option<CompleteRow>,
    completion_receipt: Option<CompletionRow>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompleteRow {
    operation_id: String,
    expected_resource_version: String,
    intent_digest: String,
    intent: DirectCompleteRequest,
    admitted_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletionRow {
    operation_id: String,
    logical_fingerprint: String,
    evidence_digest: String,
    evidence: DirectCompletionEvidence,
    final_guards: Vec<DirectFinalGuardRecord>,
    committed_at: String,
    resulting_resource_version: String,
}

fn encoded<T: Serialize>(value: &T) -> Result<EncodedImage> {
    Ok(image(&encode_direct_control(value)?))
}

fn reader_row(row: &SessionRow, deployment: &str) -> Result<()> {
    let original = &row.original;
    original.admission.validate(deployment)?;
    ensure!(
        original.session_id == original.admission.session_id
            && original.resource_version.is_some()
            && original
                .owner_scope_key
                .as_ref()
                .is_some_and(|scope| !scope.is_empty())
            && original.cache_id.is_none()
            && original.cache_ticket_id.is_none(),
        "dynamic reader owner or session differs"
    );
    let DirectUploadTarget::PublicationObject { publication_id, .. } =
        &original.admission.intent.target
    else {
        anyhow::bail!("dynamic reader original is not a publication target");
    };
    ensure!(
        original.publication_id == *publication_id,
        "dynamic reader owner differs"
    );
    positive_reader_version(original.resource_version.as_deref().unwrap_or_default())?;
    ensure!(
        matches!(
            original.state.as_str(),
            "admitted"
                | "staged_verified"
                | "committed"
                | "abort_pending"
                | "abort_unknown"
                | "aborted"
        ),
        "dynamic reader lifecycle differs"
    );
    if let Some(complete) = &row.complete_intent {
        complete.intent.fingerprint()?;
        ensure!(
            complete.intent.session.session_id == original.session_id
                && complete.intent.session.logical_fingerprint
                    == original.admission.logical_fingerprint
                && complete.intent.operation_id == complete.operation_id
                && complete.intent.expected_resource_version.get().to_string()
                    == complete.expected_resource_version
                && complete.intent.fingerprint()? == complete.intent_digest,
            "dynamic reader Complete original differs"
        );
        positive_reader_version(&complete.admitted_at)?;
    }
    if let Some(receipt) = &row.completion_receipt {
        let complete = row
            .complete_intent
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("completion lacks retained Complete"))?;
        receipt
            .evidence
            .validate_against(&original.admission, deployment)?;
        ensure!(
            receipt.evidence.operation_id == receipt.operation_id
                && receipt.operation_id == complete.operation_id
                && receipt.evidence.logical_fingerprint == receipt.logical_fingerprint
                && files::digest(&encode_direct_control(&receipt.evidence)?)
                    == receipt.evidence_digest
                && receipt.final_guards.len() == original.admission.placements.len(),
            "dynamic reader completion receipt differs"
        );
        positive_reader_version(&receipt.committed_at)?;
        positive_reader_version(&receipt.resulting_resource_version)?;
        ensure!(
            receipt.resulting_resource_version.parse::<u64>()? > 1,
            "completion result version differs"
        );
        ensure!(
            original.state == "committed"
                && original.resource_version.as_deref()
                    == Some(receipt.resulting_resource_version.as_str()),
            "reader committed state/version differs from its receipt"
        );
        let mut guarded_placements = BTreeSet::new();
        for guard in &receipt.final_guards {
            ensure!(
                guarded_placements.insert(guard.reservation.placement.placement_id),
                "duplicated dynamic reader final guard"
            );
            guard.validate_for(
                &original.admission,
                &complete.intent,
                &receipt.evidence,
                deployment,
            )?;
        }
    }
    ensure!(
        (original.state == "committed") == row.completion_receipt.is_some(),
        "reader committed state lacks its retained receipt"
    );
    Ok(())
}

fn sessions(sql: &[u8], deployment: &str) -> Result<BTreeMap<String, SessionRow>> {
    let mut rows = BTreeMap::new();
    for line in std::str::from_utf8(sql)?.lines() {
        ensure!(
            rows.len() < MAX_DIRECT_BATCH_ITEMS,
            "dynamic reader exceeds batch bound"
        );
        let row: SessionRow = serde_json::from_str(line)?;
        // SQL formatting is not canonical, but nested typed documents must not
        // silently drop fields through a DTO decoder.
        let value: Value = serde_json::from_str(line)?;
        ensure!(
            value["original"]["admission"] == serde_json::to_value(&row.original.admission)?,
            "dynamic reader admission has unclassified fields"
        );
        if let Some(complete) = &row.complete_intent {
            ensure!(
                value["completeIntent"]["intent"] == serde_json::to_value(&complete.intent)?,
                "dynamic reader Complete has unclassified fields"
            );
        }
        if let Some(receipt) = &row.completion_receipt {
            ensure!(
                value["completionReceipt"]["evidence"] == serde_json::to_value(&receipt.evidence)?
                    && value["completionReceipt"]["finalGuards"]
                        == serde_json::to_value(&receipt.final_guards)?,
                "dynamic reader receipt has unclassified fields"
            );
        }
        reader_row(&row, deployment)?;
        ensure!(
            rows.insert(row.original.session_id.clone(), row).is_none(),
            "duplicated dynamic reader original"
        );
    }
    Ok(rows)
}

/// Joins a canonical Get reply to one bounded independent publication row.
///
/// # Errors
/// Refuses foreign publication identity, mutable reader-time substitutions,
/// noncanonical public bytes, or malformed SQL values.
pub(super) fn publication_get(
    capture: &Capture,
    request: &[u8],
    reply: &[u8],
    sql: &[u8],
) -> Result<Vec<ReaderOriginal>> {
    ensure!(
        capture.procedure == "/aos.hub.v1.PublishService/GetRegistryPublication",
        "dynamic Get route differs"
    );
    super::super::public_rpc::classify(capture, request, reply)?;
    let selected: GetRegistryPublicationRequest = super::exact(request)?;
    let response: RegistryPublication = super::exact(reply)?;
    let row: PublicationRow = serde_json::from_slice(sql)?;
    positive_reader_version(&row.registry_id)?;
    positive_reader_version(&row.ordinal)?;
    ensure!(
        matches!(
            row.state.as_str(),
            "preparing" | "writing_pointers" | "ready" | "failed" | "retired"
        ),
        "dynamic publication reader state differs"
    );
    ensure!(
        row.publication_id == selected.publication_id
            && response.publication_id == row.publication_id
            && response.registry == row.registry_slug
            && response.ordinal.to_string() == row.ordinal
            && response.manifest_digest == row.manifest_digest
            && response.refs_digest == row.refs_digest
            && !row.registry_scope_key.is_empty(),
        "dynamic Get immutable reader original differs"
    );
    Ok(vec![ReaderOriginal::Dynamic {
        values: json!({
            "operation":"publication_get", "publicationId":row.publication_id,
            "registryId":row.registry_id, "ordinal":row.ordinal,
            "manifestDigest":row.manifest_digest, "refsDigest":row.refs_digest,
            "registryScopeSha256":files::digest(row.registry_scope_key.as_bytes()),
            "reply":image(reply), "readerState":row.state,
        }),
    }])
}

/// Joins actual protected Authorize/Commit envelopes to retained originals.
///
/// # Errors
/// Refuses missing, duplicated, foreign, noncanonical or unsupported originals,
/// changed completion receipts, or a reply that omitted a selected success.
pub(super) fn logical(
    kind: &str,
    capture: &Capture,
    request: &[u8],
    reply: &[u8],
    sql: &[u8],
) -> Result<Vec<ReaderOriginal>> {
    super::super::logical::classify(capture, request, reply)?;
    let original: DirectLogicalRequestEnvelope = decode_direct_control(request)?;
    let response: DirectLogicalReplyEnvelope = decode_direct_control(reply)?;
    let deployment = &original.context.deployment_id;
    let mut rows = sessions(sql, deployment)?;
    ensure!(
        response.reply.errors.is_empty(),
        "dynamic reply has per-original refusal"
    );
    let mut output = Vec::new();
    match (&original.request, kind) {
        (
            DirectUploadLogicalRequest::Authorize {
                action,
                complete_step,
                sessions,
                ..
            },
            "direct_authorize",
        ) => {
            ensure!(
                !sessions.is_empty()
                    && sessions.len() <= MAX_DIRECT_BATCH_ITEMS
                    && response.reply.authorizations == *sessions,
                "dynamic Authorize reply original coverage differs"
            );
            let compact = matches!(
                complete_step,
                Some(DirectCompleteStep::Baseline | DirectCompleteStep::Promote)
            );
            ensure!(
                if compact {
                    response.reply.admissions.is_empty()
                        && response.reply.sessions.is_empty()
                        && response.reply.session_summaries.is_empty()
                } else {
                    response.reply.admissions.len() == sessions.len()
                        && response.reply.sessions.len() + response.reply.session_summaries.len()
                            == sessions.len()
                },
                "dynamic Authorize reply coverage differs"
            );
            let mut selected_permissions = 0;
            for selected in sessions {
                let row = rows
                    .remove(&selected.session.session_id)
                    .ok_or_else(|| anyhow::anyhow!("missing dynamic Authorize reader original"))?;
                ensure!(
                    selected.session.logical_fingerprint
                        == row.original.admission.logical_fingerprint,
                    "dynamic Authorize fingerprint differs"
                );
                if !compact {
                    let actual: Vec<_> = response
                        .reply
                        .admissions
                        .iter()
                        .filter(|admission| admission.session_id == selected.session.session_id)
                        .collect();
                    ensure!(
                        actual.len() == 1 && actual[0] == &row.original.admission,
                        "dynamic Authorize returned admission differs"
                    );
                }
                let permissions: Vec<_> = response
                    .reply
                    .baseline_permissions
                    .iter()
                    .filter(|permission| permission.binding.session == selected.session)
                    .collect();
                selected_permissions += permissions.len();
                let mut values = json!({
                    "operation":"direct_authorize", "sessionId":selected.session.session_id,
                    "requestContext":encoded(&original.context)?, "selectedOriginal":encoded(selected)?,
                    "action":action, "completeStep":complete_step,
                    "admission":encoded(&row.original.admission)?,
                    "baselinePermissions":encoded(&permissions)?,
                    "readerState":row.original.state,
                    "readerResourceVersion":row.original.resource_version,
                });
                // Freeze carries an actual compact state/RV plus an admission.
                // Baseline/Promote carry neither: later SQL cannot fill that gap.
                let statuses: Vec<_> = response
                    .reply
                    .sessions
                    .iter()
                    .filter(|status| status.session == selected.session)
                    .cloned()
                    .chain(
                        response
                            .reply
                            .session_summaries
                            .iter()
                            .filter(|summary| summary.session == selected.session)
                            .map(|summary| summary.status(&row.original.admission, deployment))
                            .collect::<Result<Vec<_>>>()?,
                    )
                    .collect();
                if !matches!(
                    complete_step,
                    Some(DirectCompleteStep::Baseline | DirectCompleteStep::Promote)
                ) {
                    ensure!(
                        statuses.len() == 1,
                        "dynamic Authorize actual status is missing"
                    );
                    let status = &statuses[0];
                    let placements = row
                        .original
                        .admission
                        .placements
                        .iter()
                        .map(|placement| placement.public_ref(deployment))
                        .collect::<Result<Vec<_>>>()?;
                    status.validate_for(
                        &selected.session,
                        &row.original.admission.intent,
                        &placements,
                    )?;
                    ensure!(
                        status.parts.is_empty()
                            && status.next_cursor.is_none()
                            && status.outstanding_grants,
                        "dynamic logical status contains provider progress"
                    );
                    values["returnedStatus"] = serde_json::to_value(encoded(status)?)?;
                    values["observedState"] = serde_json::to_value(status.state)?;
                    values["observedResourceVersion"] =
                        serde_json::to_value(status.resource_version)?;
                } else {
                    ensure!(
                        statuses.is_empty(),
                        "compact dynamic reply contains unexpected status"
                    );
                }
                output.push(ReaderOriginal::Dynamic { values });
            }
            ensure!(
                selected_permissions == response.reply.baseline_permissions.len(),
                "unselected dynamic baseline permission"
            );
        }
        (
            DirectUploadLogicalRequest::Commit {
                evidence,
                final_guards,
                final_guard_refs,
            },
            "direct_commit",
        ) => {
            ensure!(
                !evidence.is_empty() && evidence.len() <= MAX_DIRECT_BATCH_ITEMS,
                "dynamic Commit originals exceed batch bound"
            );
            ensure!(
                response.reply.admissions.len() == evidence.len()
                    && response.reply.sessions.len() == evidence.len()
                    && response.reply.session_summaries.is_empty()
                    && response.reply.authorizations.is_empty()
                    && response.reply.baseline_permissions.is_empty(),
                "dynamic Commit reply coverage differs"
            );
            let mut selected_ids = BTreeSet::new();
            let mut selected_guard_count = 0;
            for selected in evidence {
                ensure!(
                    selected_ids.insert(&selected.session_id),
                    "duplicate dynamic Commit original"
                );
                let row = rows
                    .remove(&selected.session_id)
                    .ok_or_else(|| anyhow::anyhow!("missing dynamic Commit reader original"))?;
                let complete = row
                    .complete_intent
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("dynamic Commit lacks Complete original"))?;
                let receipt = row
                    .completion_receipt
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("dynamic Commit lacks completion receipt"))?;
                ensure!(
                    selected == &receipt.evidence,
                    "dynamic Commit evidence differs from retained receipt"
                );
                let guards = &receipt.final_guards;
                selected_guard_count += guards.len();
                let references = guards
                    .iter()
                    .map(DirectFinalGuardRef::from_record)
                    .collect::<Result<Vec<_>>>()?;
                let actual_refs: Vec<_> = final_guard_refs
                    .iter()
                    .filter(|reference| reference.session.session_id == selected.session_id)
                    .cloned()
                    .collect();
                ensure!(
                    references == actual_refs && final_guards.is_empty(),
                    "dynamic Commit guard originals differ"
                );
                let statuses: Vec<_> = response
                    .reply
                    .sessions
                    .iter()
                    .filter(|status| status.session.session_id == selected.session_id)
                    .collect();
                ensure!(
                    statuses.len() == 1 && statuses[0].state == DirectSessionState::Committed,
                    "dynamic Commit reply has no retained committed original"
                );
                let admissions: Vec<_> = response
                    .reply
                    .admissions
                    .iter()
                    .filter(|admission| admission.session_id == selected.session_id)
                    .collect();
                ensure!(
                    admissions.len() == 1 && admissions[0] == &row.original.admission,
                    "dynamic Commit actual admission differs"
                );
                let placements = row
                    .original
                    .admission
                    .placements
                    .iter()
                    .map(|placement| placement.public_ref(deployment))
                    .collect::<Result<Vec<_>>>()?;
                statuses[0].validate_for(
                    &complete.intent.session,
                    &row.original.admission.intent,
                    &placements,
                )?;
                ensure!(
                    statuses[0].resource_version.get().to_string()
                        == receipt.resulting_resource_version
                        && statuses[0].parts.is_empty()
                        && statuses[0].next_cursor.is_none()
                        && statuses[0].outstanding_grants,
                    "dynamic Commit returned status differs"
                );
                output.push(ReaderOriginal::Dynamic {
                    values: json!({
                        "operation":"direct_commit", "sessionId":selected.session_id,
                        "deploymentSha256":files::digest(deployment.as_bytes()),
                        "admission":encoded(&row.original.admission)?,
                        "completeOriginal":encoded(&complete.intent)?,
                        "completionEvidence":encoded(selected)?, "finalGuards":encoded(guards)?,
                        "readerState":row.original.state,
                        "readerResourceVersion":row.original.resource_version,
                        "receiptResultingResourceVersion":receipt.resulting_resource_version,
                        "replyResourceVersion":statuses[0].resource_version,
                    }),
                });
            }
            ensure!(
                selected_guard_count == final_guard_refs.len(),
                "unselected dynamic guard reference"
            );
        }
        _ => anyhow::bail!("dynamic logical operation differs"),
    }
    ensure!(rows.is_empty(), "unselected dynamic reader originals");
    Ok(output)
}
