//! Immutable source and retained SQL value joins for two bounded Native phases.
//!
//! These comparisons do not authenticate a SQL reader, a transport, or a current
//! actor. Their unresolved dimensions are explicit; no object-payload zero is
//! emitted merely because the selected values match.

//! A selected immutable page uses the closed body-reference format below. The
//! references identify privately retained files; matching them does not prove
//! the SQL reader's custody or the request's authentication.
//!
//! ```json
//! {
//!   "kind": "publication_append",
//!   "originalRequest": {
//!     "file": "original.json",
//!     "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
//!     "byteSize": "256"
//!   },
//!   "immutableChunkReceipt": {
//!     "file": "chunk.json",
//!     "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
//!     "byteSize": "128"
//!   }
//! }
//! ```

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
    #[serde(skip_serializing_if = "Option::is_none")]
    sql_originals: Option<Vec<ReaderOriginal>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChunkReceipt {
    publication_id: String,
    chunk_index: u32,
    chunk_digest: String,
    object_count: u32,
    #[serde(default)]
    accepted_at: Option<String>,
    #[serde(default)]
    registry_id: Option<String>,
    #[serde(default)]
    resource_version: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    manifest_digest: Option<String>,
    #[serde(default)]
    lease_expires_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionRow {
    session_id: String,
    publication_id: String,
    state: String,
    admission: DirectUploadAdmission,
    #[serde(default)]
    resource_version: Option<String>,
    #[serde(default)]
    owner_scope_key: Option<String>,
    #[serde(default)]
    cache_id: Option<String>,
    #[serde(default)]
    cache_ticket_id: Option<String>,
}

#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum ReaderOriginal {
    Admission {
        session_id: String,
        admission: aos_hub_core::application_body_observation::EncodedImage,
        owner: aos_hub_core::application_body_observation::EncodedImage,
        owner_scope_sha256: String,
        reader_status_resource_version: String,
        reader_state: String,
    },
    ManifestChunk {
        publication_id: String,
        chunk_index: u32,
        chunk_digest: String,
        object_count: u32,
        accepted_at: String,
        registry_id: String,
        reader_session_resource_version: String,
        reader_state: String,
        manifest_digest: String,
        reader_lease_expires_at: Option<String>,
    },
}

fn positive_reader_version(value: &str) -> Result<()> {
    let parsed: i64 = value.parse()?;
    ensure!(
        parsed > 0 && parsed.to_string() == value,
        "noncanonical reader-time version"
    );
    Ok(())
}

fn reader_originals(kind: &str, sql: &[u8]) -> Result<Option<Vec<ReaderOriginal>>> {
    if kind == "publication_manifest_append" {
        let row: ChunkReceipt = serde_json::from_slice(sql)?;
        let Some(version) = row.resource_version else {
            ensure!(
                row.accepted_at.is_none()
                    && row.registry_id.is_none()
                    && row.state.is_none()
                    && row.manifest_digest.is_none()
                    && row.lease_expires_at.is_none(),
                "partial SQL chunk reader projection"
            );
            return Ok(None);
        };
        positive_reader_version(&version)?;
        ensure!(
            matches!(row.state.as_deref(), Some("accepting" | "sealed")),
            "SQL reader session state differs"
        );
        let registry = row
            .registry_id
            .ok_or_else(|| anyhow::anyhow!("missing SQL registry"))?;
        positive_reader_version(&registry)?;
        return Ok(Some(vec![ReaderOriginal::ManifestChunk {
            publication_id: row.publication_id,
            chunk_index: row.chunk_index,
            chunk_digest: row.chunk_digest,
            object_count: row.object_count,
            accepted_at: row
                .accepted_at
                .ok_or_else(|| anyhow::anyhow!("missing SQL accepted time"))?,
            registry_id: registry,
            reader_session_resource_version: version,
            reader_state: row
                .state
                .ok_or_else(|| anyhow::anyhow!("missing SQL session state"))?,
            manifest_digest: row
                .manifest_digest
                .ok_or_else(|| anyhow::anyhow!("missing SQL manifest digest"))?,
            reader_lease_expires_at: row.lease_expires_at,
        }]));
    }
    let mut rows = Vec::new();
    let mut enriched = None;
    for line in std::str::from_utf8(sql)?.lines() {
        let row: AdmissionRow = serde_json::from_str(line)?;
        let raw_row: serde_json::Value = serde_json::from_str(line)?;
        let canonical_original: serde_json::Value =
            serde_json::from_slice(&encode_direct_control(&row.admission)?)?;
        ensure!(
            raw_row.get("admission") == Some(&canonical_original),
            "SQL nested admission has unknown or noncanonical typed values"
        );
        let present = row.resource_version.is_some();
        ensure!(
            enriched.is_none_or(|first| first == present),
            "mixed SQL admission reader images"
        );
        enriched = Some(present);
        let Some(version) = row.resource_version else {
            ensure!(
                row.owner_scope_key.is_none()
                    && row.cache_id.is_none()
                    && row.cache_ticket_id.is_none(),
                "partial SQL owner projection"
            );
            continue;
        };
        positive_reader_version(&version)?;
        ensure!(
            row.cache_id.is_none()
                && row.cache_ticket_id.is_none()
                && matches!(
                    &row.admission.intent.target,
                    DirectUploadTarget::PublicationObject { .. }
                ),
            "SQL owner is not the actual publication original"
        );
        ensure!(
            rows.len() < 32,
            "SQL admission reader exceeds source checkpoint bound"
        );
        let scope = row
            .owner_scope_key
            .ok_or_else(|| anyhow::anyhow!("missing SQL owner scope"))?;
        ensure!(
            !scope.is_empty() && scope.len() <= 64,
            "SQL owner scope exceeds bound"
        );
        let admission = encode_direct_control(&row.admission)?;
        let owner = serde_json::to_vec(&("publication", None::<i64>, None::<&str>))?;
        rows.push(ReaderOriginal::Admission {
            session_id: row.session_id,
            admission: aos_hub_core::application_body_observation::image(&admission),
            owner: aos_hub_core::application_body_observation::image(&owner),
            owner_scope_sha256: files::digest(scope.as_bytes()),
            reader_status_resource_version: version,
            reader_state: row.state,
        });
    }
    Ok(enriched.filter(|value| *value).map(|_| rows))
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
    let (kind, original_sha, sql_sha, count, sql_originals) = match selection {
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
                reader_originals("publication_manifest_append", &sql)?,
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
                reader_originals("direct_logical_admission", &sql)?,
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
        sql_originals,
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
            && response.reply.sessions.len() == intents.len()
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
    for (admission, status) in response
        .reply
        .admissions
        .iter()
        .zip(&response.reply.sessions)
    {
        admission.validate(&original.context.deployment_id)?;
        let placements = admission
            .placements
            .iter()
            .map(|placement| placement.public_ref(&original.context.deployment_id))
            .collect::<Result<Vec<_>>>()?;
        status.validate_for(
            &DirectSessionRef {
                session_id: admission.session_id.clone(),
                logical_fingerprint: admission.logical_fingerprint.clone(),
            },
            &admission.intent,
            &placements,
        )?;
        // The Native constructor echoes logical status without provider parts.
        // Its RV and lifecycle state remain observations, not current SQL proof.
        ensure!(
            status.parts.is_empty() && status.next_cursor.is_none() && status.outstanding_grants,
            "logical admission status contains provider progress or changed accounting"
        );
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
