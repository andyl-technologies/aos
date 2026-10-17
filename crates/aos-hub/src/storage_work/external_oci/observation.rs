//! Value-free projections after the existing purpose-specific current checks.
//!
//! Writer/snapshot, materialization IAM+claim and terminal Delete observations
//! are distinct. These records correlate consumed authenticated bytes; no
//! record authenticates traffic, grants permission or replaces a current check.

use std::collections::BTreeMap;

use serde::Serialize;

use super::ControlObservation;
use crate::storage_work::telemetry::context::fact_digest;

pub(in crate::storage_work) fn digest(value: &impl Serialize) -> Option<String> {
    fact_digest(value)
}

/// Commits every observed upload column without making the DB record a wire type.
pub(super) fn upload_digest(upload: &aos_hub_core::db::OciUploadRecord) -> Option<String> {
    digest(&serde_json::json!({
        "id": upload.id, "registry_id": upload.registry_id,
        "repository_id": upload.repository_id, "publication_id": upload.publication_id,
        "quota_reservation_id": upload.quota_reservation_id,
        "writer_id": upload.writer_id, "token_id": upload.token_id,
        "expected_digest": upload.expected_digest, "expected_size": upload.expected_size,
        "maximum_size": upload.maximum_size, "uploaded_size": upload.uploaded_size,
        "authenticated_source_sha256": upload.authenticated_source_sha256,
        "authenticated_source_bytes": upload.authenticated_source_bytes,
        "staging_placement_id": upload.staging_placement_id,
        "staging_placement_resource_version": upload.staging_placement_resource_version,
        "staging_binding_id": upload.staging_binding_id,
        "staging_binding_write_revision": upload.staging_binding_write_revision,
        "final_digest": upload.final_digest,
        "materialization_placement_id": upload.materialization_placement_id,
        "materialization_placement_resource_version": upload.materialization_placement_resource_version,
        "materialization_binding_id": upload.materialization_binding_id,
        "materialization_binding_write_revision": upload.materialization_binding_write_revision,
        "sha256": upload.sha256, "state": upload.state, "expires_at": upload.expires_at,
        "created_at": upload.created_at, "finished_at": upload.finished_at,
        "cleanup_state": upload.cleanup_state, "cleanup_finished_at": upload.cleanup_finished_at,
        "resource_version": upload.resource_version,
    }))
}

pub(super) fn chunk_digest(chunk: &aos_hub_core::db::OciUploadChunkRecord) -> Option<String> {
    digest(&(
        chunk.ordinal,
        chunk.byte_offset,
        chunk.byte_size,
        chunk.digest,
        &chunk.staging_object_key,
        chunk.created_at,
    ))
}

pub(in crate::storage_work) fn checked(
    observation: Option<ControlObservation>,
    kind: &'static str,
    facts: &[(&'static str, Option<String>)],
) {
    let Some(observation) = observation else {
        return;
    };
    let commitments: Option<BTreeMap<_, _>> = facts
        .iter()
        .map(|(name, digest)| Some((*name, digest.clone()?)))
        .collect();
    if let Some(commitments) = commitments {
        observation.after_sql(kind, commitments);
    }
}

pub(super) fn materialization(
    observation: Option<ControlObservation>,
    selected: &aos_hub_core::storage_authority::external_object::oci::materialization::ExternalOciMaterialization,
    kind: &'static str,
    request: &impl Serialize,
    reply: &impl Serialize,
    outcome: &'static str,
) {
    // The caller has just completed check_current: atomic current IAM and the
    // exact completing SQL claim. This helper performs no additional checks.
    checked(
        observation,
        kind,
        &[
            ("requestSemanticSha256", digest(request)),
            ("replySemanticSha256", digest(reply)),
            ("actorOriginalSha256", digest(&selected.actor)),
            ("writerSha256", digest(&selected.writer)),
            ("uploadStateSha256", upload_digest(&selected.upload)),
            ("expectedDigestSha256", digest(&selected.digest.encoded())),
            ("outcomeSha256", digest(&outcome)),
        ],
    );
}
