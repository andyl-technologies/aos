//! Closed direct-session and OCI-summary row consistency for supported snapshots.
//!
//! These checks retain exact original cells. They verify local document shape
//! and duplicated scalar commitments, never provider settlement, signature
//! authority, current ACLs, or eligibility to resume effects after restoration.

use anyhow::{ensure, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::direct_upload::{
    encode_direct_control, DirectAbortRequest, DirectCompleteRequest, DirectCompletionEvidence,
    DirectDependencyPhase, DirectDestinationBaselineEvidence, DirectPlacement,
    DirectUploadAdmission, DirectUploadIntent, DirectUploadTarget, DirectVerifiedStageEvidence,
};
use crate::value::{FromValue, Row, Value};

use super::{json, TableContract};

pub(super) fn validate_row(name: &str, table: &TableContract, row: &Row) -> Result<()> {
    let cells = Cells { table, row };
    // New nullable UUID fields are structural provenance, never a license to
    // repair an archived token pin. Historical catalogues have no such column.
    let identity_column = match name {
        "users" | "service_accounts" => Some("principal_incarnation"),
        "tokens" => Some("owner_incarnation"),
        "topology_plans" => Some("actor_incarnation"),
        _ => None,
    };
    if let Some(column) =
        identity_column.filter(|name| table.columns.iter().any(|column| column.name == *name))
    {
        if let Some(value) = cells.get::<Option<String>>(column)? {
            let parsed = uuid::Uuid::parse_str(&value)
                .map_err(|_| anyhow::anyhow!("snapshot principal incarnation is invalid"))?;
            ensure!(
                parsed.get_version_num() == 4
                    && parsed.get_variant() == uuid::Variant::RFC4122
                    && parsed.to_string() == value,
                "snapshot principal incarnation is invalid"
            );
        }
    }
    if name.starts_with("direct_upload_") || name == "direct_oci_allocations" {
        ensure!(
            crate::direct_upload::valid_direct_identity(&cells.get::<String>("deployment_id")?),
            "snapshot direct deployment identity is invalid"
        );
    }
    match name {
        "direct_oci_allocations" => direct_oci_allocation(&cells)?,
        "direct_upload_sessions" => session(&cells)?,
        "direct_upload_session_placements" => placement(&cells)?,
        "direct_upload_completion_intents" => complete(&cells)?,
        "direct_upload_abort_intents" => abort(&cells)?,
        "direct_upload_baselines" => {
            let evidence: DirectDestinationBaselineEvidence = cells.document("evidence_json")?;
            evidence.validate()?;
            ensure!(
                evidence.binding.deployment_id == cells.get::<String>("deployment_id")?
                    && evidence.binding.session.session_id == cells.get::<String>("session_id")?
                    && evidence.binding.placement.placement_id.get()
                        == cells.counter("placement_id")?
                    && evidence.binding.complete_operation_id
                        == cells.get::<String>("complete_operation_id")?
                    && evidence.fingerprint()? == cells.get::<String>("baseline_digest")?
                    && cells.counter("activated_at")? > 0,
                "snapshot direct baseline scalar mismatch"
            );
        }
        "direct_upload_stage_receipts" => {
            let proof: DirectVerifiedStageEvidence = cells.document("evidence_json")?;
            proof.validate()?;
            evidence_identity(
                &cells,
                &proof.session_id,
                &proof.operation_id,
                &proof.logical_fingerprint,
            )?;
        }
        "direct_upload_completion_receipts" => {
            let proof: DirectCompletionEvidence = cells.document("evidence_json")?;
            proof.validate()?;
            let guards: Vec<crate::direct_upload::DirectFinalGuardRecord> =
                cells.document("final_guards_json")?;
            ensure!(
                guards.len() == proof.placements.len()
                    && cells.counter("committed_at")? > 0
                    && cells.counter("resulting_resource_version")? > 1,
                "snapshot direct final required set or lifecycle mismatch"
            );
            for (guard, placement) in guards.iter().zip(&proof.placements) {
                guard.validate()?;
                ensure!(
                    guard.reservation.deployment_id == cells.get::<String>("deployment_id")?
                        && guard.reservation.reservation_operation_id
                            == placement.promotion_operation_id
                        && guard.selected.session.session_id == proof.session_id
                        && guard.selected.session.logical_fingerprint == proof.logical_fingerprint
                        && guard.selected.operation_id == proof.operation_id
                        && guard.selected.manifest == placement.manifest
                        && guard.sha256 == proof.sha256
                        && guard.byte_size == proof.byte_size
                        && guard.source_incarnation == placement.staging_incarnation
                        && guard.final_incarnation == placement.final_incarnation
                        && guard.final_etag == placement.final_etag,
                    "snapshot direct final receipt original mismatch"
                );
            }
            evidence_identity(
                &cells,
                &proof.session_id,
                &proof.operation_id,
                &proof.logical_fingerprint,
            )?;
        }
        "oci_image_config_projections" => config_summary(&cells)?,
        "oci_upload_sessions" => oci_authenticated_source(&cells)?,
        _ => {}
    }
    Ok(())
}

fn oci_authenticated_source(cells: &Cells<'_>) -> Result<()> {
    if !cells.has("authenticated_source_sha256") {
        return Ok(());
    }
    let sha: Option<String> = cells.get("authenticated_source_sha256")?;
    let size: Option<i64> = cells.get("authenticated_source_bytes")?;
    ensure!(
        sha.is_some() == size.is_some(),
        "snapshot OCI source identity is incomplete"
    );
    if let (Some(sha), Some(size)) = (sha, size) {
        ensure!(
            crate::direct_upload::valid_direct_digest(&sha)
                && (0..=16 * 1024 * 1024 * 1024).contains(&size)
                && cells.get::<String>("state")? == "complete"
                && cells.counter("uploaded_size")? == 0
                && cells.counter("sha256_total_bytes")? == 0
                && cells.get::<String>("final_digest")? == format!("sha256:{sha}")
                && cells.get::<Option<i64>>("expected_size")? == Some(size)
                && cells.get::<Option<String>>("expected_digest")? == Some(format!("sha256:{sha}")),
            "snapshot OCI authenticated source scalar mismatch"
        );
    }
    Ok(())
}

fn direct_oci_allocation(cells: &Cells<'_>) -> Result<()> {
    use crate::direct_upload::{DirectActorKind, DirectActorSlot, WireInteger};

    let kind: String = cells.get("actor_kind")?;
    let actor = DirectActorSlot {
        kind: match kind.as_str() {
            "user" => DirectActorKind::User,
            "service_account" => DirectActorKind::ServiceAccount,
            _ => anyhow::bail!("snapshot direct OCI actor kind is invalid"),
        },
        numeric_id: WireInteger::new(cells.counter("actor_id")?),
        incarnation: cells.get("actor_incarnation")?,
    };
    actor.validate()?;
    let deployment: String = cells.get("deployment_id")?;
    let principal = actor.principal_id(&deployment)?;
    let operation: String = cells.get("client_operation_id")?;
    ensure!(
        principal == cells.get::<String>("principal_id")?
            && crate::direct_upload::deterministic_business_operation_id(
                &deployment,
                &principal,
                &operation,
            )? == cells.get::<String>("business_id")?
            && cells.counter("registry_id")? > 0
            && cells.counter("repository_id")? > 0
            && cells.counter("declared_size")? <= 16 * 1024 * 1024 * 1024
            && cells.counter("created_at")? > 0
            && crate::direct_upload::valid_direct_identity(
                &cells.get::<String>("registry_stable_id")?,
            )
            && crate::direct_upload::valid_direct_identity(&cells.get::<String>("upload_id")?,)
            && crate::direct_upload::valid_direct_digest(&cells.get::<String>("source_sha256")?,),
        "snapshot direct OCI allocation scalar mismatch"
    );
    aos_oci_types::RepositoryName::parse(&cells.get::<String>("repository_name")?)?;

    // This checks audit-ID syntax only. An archived token ID never establishes
    // live credentials or permission to restart an external provider effect.
    let token: String = cells.get("original_token_id")?;
    let token_id = uuid::Uuid::parse_str(&token)?;
    ensure!(
        token_id.get_version_num() == 4
            && token_id.get_variant() == uuid::Variant::RFC4122
            && token_id.to_string() == token,
        "snapshot direct OCI token audit ID is invalid"
    );
    Ok(())
}

fn session(cells: &Cells<'_>) -> Result<()> {
    let deployment: String = cells.get("deployment_id")?;
    let intent: DirectUploadIntent = cells.document("intent_json")?;
    let admission: DirectUploadAdmission = cells.document("admission_json")?;
    admission.validate(&deployment)?;
    ensure!(
        admission.intent == intent
            && admission.session_id == cells.get::<String>("session_id")?
            && admission.principal_id == cells.get::<String>("principal_id")?
            && admission.logical_fingerprint == cells.get::<String>("logical_fingerprint")?
            && intent.client_operation_id == cells.get::<String>("client_operation_id")?
            && intent.expected_sha256 == cells.get::<String>("source_sha256")?
            && intent.byte_size.get() == cells.counter("declared_size")?
            && intent.part_size.get() == cells.counter("part_size")?
            && admission.expires_at.get() == cells.counter("expires_at")?
            && phase(intent.dependency_phase)
                == cells.get::<String>("declared_dependency_phase")?,
        "snapshot direct admission scalar mismatch"
    );
    let owner_matches = match &intent.target {
        DirectUploadTarget::CacheObject { cache_id, path } => {
            cells.get::<String>("target_kind")? == "cache_object"
                && cache_id == &cells.get::<String>("cache_identifier")?
                && cells.counter("cache_id")? > 0
                && path == &cells.get::<String>("object_path")?
                && cells.null("publication_id")?
                && cells.null("surface_object_id")?
                && cells.null("oci_upload_id")?
                && !cells.null("cache_ticket_id")?
        }
        DirectUploadTarget::PublicationObject {
            publication_id,
            surface_object_id,
            path,
        } => {
            cells.get::<String>("target_kind")? == "publication_object"
                && publication_id == &cells.get::<String>("publication_id")?
                && surface_object_id.get() == cells.counter("surface_object_id")?
                && path == &cells.get::<String>("object_path")?
                && cells.null("cache_id")?
                && cells.null("cache_identifier")?
                && cells.null("oci_upload_id")?
                && cells.null("cache_ticket_id")?
        }
        DirectUploadTarget::OciBlob { upload_id } => {
            cells.get::<String>("target_kind")? == "oci_blob"
                && upload_id == &cells.get::<String>("oci_upload_id")?
                && cells.null("cache_id")?
                && cells.null("cache_identifier")?
                && cells.null("publication_id")?
                && cells.null("surface_object_id")?
                && cells.null("object_path")?
                && cells.null("cache_ticket_id")?
        }
    };
    ensure!(owner_matches, "snapshot direct admission owner mismatch");
    let state: String = cells.get("state")?;
    ensure!(
        matches!(
            state.as_str(),
            "admitted"
                | "staged_verified"
                | "committed"
                | "abort_pending"
                | "abort_unknown"
                | "aborted"
        ),
        "snapshot direct session state is unknown"
    );
    let final_phase: Option<String> = cells.get("final_dependency_phase")?;
    ensure!(
        final_phase
            .as_deref()
            .is_none_or(|value| matches!(value, "content" | "leaf_metadata" | "visibility")),
        "snapshot direct dependency phase is unknown"
    );
    let created = cells.counter("created_at")?;
    ensure!(
        cells.counter("expires_at")? > created
            && cells.counter("updated_at")? >= created
            && cells.counter("resource_version")? > 0
            && (state == "committed") != cells.null("completed_at")?,
        "snapshot direct session lifecycle mismatch"
    );
    Ok(())
}

fn placement(cells: &Cells<'_>) -> Result<()> {
    let deployment: String = cells.get("deployment_id")?;
    let placement: DirectPlacement = cells.document("placement_json")?;
    placement.validate(&deployment)?;
    ensure!(
        placement.placement_id.get() == cells.counter("placement_id")?
            && placement.placement_resource_version.get()
                == cells.counter("placement_resource_version")?
            && placement.write_spec_version.get() == cells.counter("write_spec_version")?
            && placement.binding_id.get() == cells.counter("binding_id")?
            && placement.binding_resource_version.get()
                == cells.counter("binding_resource_version")?
            && placement.binding_write_revision.get() == cells.counter("binding_write_revision")?
            && placement.fingerprint(&deployment)?
                == cells.get::<String>("placement_fingerprint")?,
        "snapshot direct placement scalar mismatch"
    );
    Ok(())
}

fn abort(cells: &Cells<'_>) -> Result<()> {
    let intent: DirectAbortRequest = cells.document("intent_json")?;
    intent.session.validate()?;
    ensure!(
        crate::direct_upload::valid_direct_digest(&intent.operation_id)
            && intent.expected_resource_version.get() > 0
            && intent.session.session_id == cells.get::<String>("session_id")?
            && intent.operation_id == cells.get::<String>("operation_id")?
            && intent.expected_resource_version.get()
                == cells.counter("expected_resource_version")?
            && cells.get::<String>("intent_digest")?
                == hex::encode(Sha256::digest(encode_direct_control(&intent)?))
            && cells.counter("admitted_at")? > 0,
        "snapshot direct abort scalar mismatch"
    );
    let terminal: Option<String> = cells.get("terminal_receipt_digest")?;
    let settled: Option<i64> = cells.get("settled_at")?;
    let admitted: i64 = cells.get("admitted_at")?;
    ensure!(
        terminal.is_some() == settled.is_some()
            && terminal
                .as_ref()
                .is_none_or(|digest| crate::direct_upload::valid_direct_digest(digest))
            && settled.is_none_or(|time| time >= admitted),
        "snapshot direct abort terminal receipt mismatch"
    );
    Ok(())
}

fn complete(cells: &Cells<'_>) -> Result<()> {
    let complete: DirectCompleteRequest = cells.document("intent_json")?;
    ensure!(
        complete.session.session_id == cells.get::<String>("session_id")?
            && complete.operation_id == cells.get::<String>("operation_id")?
            && complete.expected_resource_version.get()
                == cells.counter("expected_resource_version")?
            && complete.fingerprint()? == cells.get::<String>("intent_digest")?
            && cells.counter("admitted_at")? > 0,
        "snapshot direct completion intent mismatch"
    );
    Ok(())
}

fn evidence_identity(
    cells: &Cells<'_>,
    session: &str,
    operation: &str,
    fingerprint: &str,
) -> Result<()> {
    let bytes: String = cells.get("evidence_json")?;
    ensure!(
        session == cells.get::<String>("session_id")?
            && operation == cells.get::<String>("operation_id")?
            && fingerprint == cells.get::<String>("logical_fingerprint")?
            && hex::encode(Sha256::digest(bytes.as_bytes()))
                == cells.get::<String>("evidence_digest")?,
        "snapshot direct evidence scalar mismatch"
    );
    Ok(())
}

fn config_summary(cells: &Cells<'_>) -> Result<()> {
    // Generation 3 has neither field and retains its original exact-raw rules.
    if !cells.has("config_representation") {
        return Ok(());
    }
    let representation: String = cells.get("config_representation")?;
    let size: Option<i64> = cells.get("config_source_size")?;
    ensure!(
        size.is_none_or(|value| (1..=4_194_304).contains(&value)),
        "snapshot OCI config source size is invalid"
    );
    match representation.as_str() {
        "exact_raw" => ensure!(
            cells.null("config_summary_json")?,
            "snapshot exact OCI config carries a summary"
        ),
        "storage_summary_v1" => {
            let summary: crate::hybrid_ingress::projection::OciImageConfigSemanticsV1 =
                cells.document("config_summary_json")?;
            summary.validate()?;
            ensure!(
                cells.get::<String>("config_json")?.is_empty()
                    && size == Some(i64::from(summary.source_size))
                    && cells.get::<String>("config_digest")?
                        == format!("sha256:{}", summary.source_sha256),
                "snapshot OCI summary representation mismatch"
            );
        }
        _ => anyhow::bail!("snapshot OCI config representation is unknown"),
    }
    Ok(())
}

fn phase(value: DirectDependencyPhase) -> &'static str {
    match value {
        DirectDependencyPhase::Content => "content",
        DirectDependencyPhase::LeafMetadata => "leaf_metadata",
        DirectDependencyPhase::Visibility => "visibility",
    }
}

struct Cells<'a> {
    table: &'a TableContract,
    row: &'a Row,
}

impl Cells<'_> {
    fn has(&self, name: &str) -> bool {
        self.table.columns.iter().any(|column| column.name == name)
    }

    fn index(&self, name: &str) -> Result<usize> {
        self.table
            .columns
            .iter()
            .position(|column| column.name == name)
            .ok_or_else(|| anyhow::anyhow!("snapshot closed row column is absent"))
    }

    fn get<T: FromValue>(&self, name: &str) -> Result<T> {
        self.row
            .get(self.index(name)?)
            .map_err(|_| anyhow::anyhow!("snapshot closed row scalar differs"))
    }

    fn counter(&self, name: &str) -> Result<u64> {
        u64::try_from(self.get::<i64>(name)?)
            .map_err(|_| anyhow::anyhow!("snapshot closed row counter is invalid"))
    }

    fn null(&self, name: &str) -> Result<bool> {
        Ok(matches!(
            super::value_at(self.row, self.index(name)?)?,
            Value::Null
        ))
    }

    fn document<T: DeserializeOwned + Serialize>(&self, name: &str) -> Result<T> {
        let text: String = self.get(name)?;
        let document: T = json::closed(json::parse(&text)?)?;
        ensure!(
            encode_direct_control(&document)? == text.as_bytes(),
            "snapshot closed business document is not canonical"
        );
        Ok(document)
    }
}
