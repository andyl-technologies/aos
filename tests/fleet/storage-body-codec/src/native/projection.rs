//! Immutable source and retained SQL value joins for two bounded Native phases.
//!
//! These comparisons do not authenticate a SQL reader, a transport, or a current
//! actor. Their unresolved dimensions are explicit; no object-payload zero is
//! emitted merely because the selected values match.

use super::{public_rpc::exact, Capture};
use crate::files::{self, BodyFile};
use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use aos_proto_types::{
    AppendRegistryPublicationManifestRequest, RegistryPublicationManifestSession,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum Selection {
    PublicationAppend {
        original_request: BodyFile,
        immutable_chunk_receipt: BodyFile,
    },
    DirectAdmission {
        original_request: BodyFile,
        original_public_request: BodyFile,
        sql_admissions: BodyFile,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Observation {
    version: u8,
    kind: &'static str,
    original_request_sha256: String,
    sql_evidence_sha256: String,
    matched_original_count: String,
    request_control_bytes: String,
    reply_control_bytes: String,
    object_payload_bytes: Option<String>,
    sql_reader_authority: &'static str,
    missing: [&'static str; 1],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChunkReceipt {
    publication_id: String,
    chunk_index: u32,
    chunk_digest: String,
    object_count: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionRow {
    session_id: String,
    publication_id: String,
    state: String,
    admission: DirectUploadAdmission,
}

/// Compares selected immutable originals without granting reader authority.
///
/// # Errors
/// Refuses changed bytes, malformed references, unsupported phases, unmatched
/// canonical originals or retained SQL values, and excessive body/corpus sizes.
pub(super) fn inspect(
    selection: &Selection,
    capture: &Capture,
    request: &[u8],
    reply: &[u8],
    consumed: &mut usize,
) -> Result<Observation> {
    let (kind, original_sha, sql_sha, count) = match selection {
        Selection::PublicationAppend {
            original_request,
            immutable_chunk_receipt,
        } => {
            let original = files::read(original_request, consumed)?;
            let sql = files::read(immutable_chunk_receipt, consumed)?;
            ensure!(
                original == request,
                "publication source page differs from received bytes"
            );
            let count = append(capture, request, reply, &sql)?;
            (
                "publication_manifest_append",
                files::digest(&original),
                files::digest(&sql),
                count,
            )
        }
        Selection::DirectAdmission {
            original_request,
            original_public_request,
            sql_admissions,
        } => {
            let original = files::read(original_request, consumed)?;
            let sql = files::read(sql_admissions, consumed)?;
            ensure!(
                original == request,
                "Direct logical original differs from received bytes"
            );
            let public = files::read(original_public_request, consumed)?;
            let count = admission(capture, request, reply, &public, &sql)?;
            (
                "direct_logical_admission",
                files::digest(&original),
                files::digest(&sql),
                count,
            )
        }
    };
    Ok(Observation {
        version: 1,
        kind,
        original_request_sha256: original_sha,
        sql_evidence_sha256: sql_sha,
        matched_original_count: count.to_string(),
        request_control_bytes: request.len().to_string(),
        reply_control_bytes: reply.len().to_string(),
        object_payload_bytes: None,
        sql_reader_authority: "not_checked_join_measured_read_only_source_process_and_window",
        missing: ["independent_sql_reader_custody_and_temporal_current_fences"],
    })
}

fn append(capture: &Capture, request: &[u8], reply: &[u8], sql: &[u8]) -> Result<usize> {
    ensure!(
        capture.procedure == "/aos.hub.v1.PublishService/AppendRegistryPublicationManifest",
        "immutable page route differs"
    );
    super::public_rpc::classify(capture, request, reply)?;
    let original: AppendRegistryPublicationManifestRequest = exact(request)?;
    let response: RegistryPublicationManifestSession = exact(reply)?;
    // SQL JSON formatting is not Rust canonical encoding. Decode its closed row
    // and compare actual fields; the page digest uses the production serializer.
    let retained: ChunkReceipt = serde_json::from_slice(sql)?;
    ensure!(
        retained.publication_id == original.publication_id
            && retained.chunk_index == original.chunk_index
            && retained.chunk_digest == super::manifest_digest::digest(&original.objects)?
            && retained.object_count as usize == original.objects.len()
            && response.publication_id == retained.publication_id,
        "immutable admitted publication page differs"
    );
    Ok(original.objects.len())
}

fn admission(
    capture: &Capture,
    request: &[u8],
    reply: &[u8],
    public: &[u8],
    sql: &[u8],
) -> Result<usize> {
    super::logical::classify(capture, request, reply)?;
    let original: DirectLogicalRequestEnvelope = decode_direct_control(request)?;
    let response: DirectLogicalReplyEnvelope = decode_direct_control(reply)?;
    let DirectUploadLogicalRequest::Admission { intents } = &original.request else {
        anyhow::bail!("changing Direct phase has no immutable admission projection");
    };
    let DirectUploadRequest::BeginBatch(batch) =
        decode_direct_public_request("BeginBatch", public)?
    else {
        anyhow::bail!("Direct original is not BeginBatch");
    };
    ensure!(
        encode_direct_control(&batch)? == public
            && original.context.public_path == "/aos.hub.v1.DirectUploadService/BeginBatch"
            && original.context.request_body_sha256 == files::digest(public)
            && batch.items == *intents,
        "public BeginBatch original differs from Native intents"
    );
    ensure!(
        !intents.is_empty()
            && intents.len() <= MAX_DIRECT_BATCH_ITEMS
            && response.reply.errors.is_empty()
            && response.reply.sessions.is_empty()
            && response.reply.session_summaries.is_empty()
            && response.reply.authorizations.is_empty()
            && response.reply.baseline_permissions.is_empty()
            && response.reply.admissions.len() == intents.len(),
        "Direct admission reply contains changing or incomplete projections"
    );
    let mut retained = BTreeMap::new();
    for line in std::str::from_utf8(sql)?.lines() {
        ensure!(
            retained.len() < MAX_DIRECT_BATCH_ITEMS,
            "excessive retained admissions"
        );
        let row: AdmissionRow = serde_json::from_str(line)?;
        let DirectUploadTarget::PublicationObject { publication_id, .. } =
            &row.admission.intent.target
        else {
            anyhow::bail!("retained admission is not a publication original");
        };
        row.admission.validate(&original.context.deployment_id)?;
        ensure!(
            row.session_id == row.admission.session_id
                && row.publication_id == *publication_id
                && matches!(
                    row.state.as_str(),
                    "admitted"
                        | "staged_verified"
                        | "committed"
                        | "abort_pending"
                        | "abort_unknown"
                        | "aborted"
                ),
            "SQL admission scalar differs"
        );
        ensure!(
            retained.insert(row.session_id, row.admission).is_none(),
            "duplicate retained admission"
        );
    }
    ensure!(
        retained.len() == intents.len(),
        "immutable admission coverage differs"
    );
    let mut expected = BTreeMap::new();
    for intent in intents {
        ensure!(
            expected
                .insert(intent.client_operation_id.as_str(), intent)
                .is_none(),
            "duplicate original intent"
        );
    }
    for admission in &response.reply.admissions {
        admission.validate(&original.context.deployment_id)?;
        ensure!(
            expected.remove(admission.intent.client_operation_id.as_str())
                == Some(&admission.intent)
                && retained.remove(&admission.session_id).as_ref() == Some(admission),
            "logical admission actor, source or placements differ from immutable SQL original"
        );
    }
    ensure!(
        expected.is_empty() && retained.is_empty(),
        "unmatched immutable admission"
    );
    Ok(intents.len())
}

#[cfg(test)]
mod tests;
