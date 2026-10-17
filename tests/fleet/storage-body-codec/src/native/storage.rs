//! Adapter around the unchanged shared storage-body codec and result validator.

use super::{Capture, Observation};
use crate::{files, Case};
use anyhow::{ensure, Result};
use aos_hub_core::storage_work::{StorageWorkPlan, StorageWorkResult};

pub(super) fn classify(
    capture: &Capture,
    request: &[u8],
    response: &[u8],
    source: &str,
    observation: &mut Observation,
) -> Result<()> {
    ensure!(
        capture.control_selection.is_some() != capture.storage_work_selection.is_some(),
        "ambiguous storage selection"
    );
    let (deployment, original) = if let Some(selected) = &capture.control_selection {
        ensure!(selected.source_digest == source, "control source changed");
        (selected.deployment_id.clone(), &selected.original_request)
    } else {
        let selected = capture
            .storage_work_selection
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing storage selection"))?;
        ensure!(selected.source_digest == source, "storage source changed");
        let completed = selected.completion_observed_at_unix_millis.parse::<u64>()?;
        ensure!(
            completed > 0 && completed.to_string() == selected.completion_observed_at_unix_millis,
            "noncanonical completion observation"
        );
        let plan: StorageWorkPlan = super::public_rpc::exact(request)?;
        (plan.deployment_id, &selected.original_plan)
    };
    let mut original_bytes = 0;
    ensure!(
        files::read(original, &mut original_bytes)? == request,
        "storage original changed"
    );
    if capture.control_selection.is_some() {
        canonical_control(&capture.procedure, request, response, capture.status)?;
    }
    let case = Case {
        request_id: capture.request_id.clone(),
        method: capture.method.clone(),
        path_and_query: capture.procedure.clone(),
        phase: capture.phase.clone(),
        status: capture.status,
        response_content_type: capture.response_content_type.clone(),
        response_content_encoding: capture.response_content_encoding.clone(),
        original_request: clone_file(original),
        received_request: clone_file(&capture.bodies.request),
        received_reply: clone_file(&capture.bodies.response),
        original_ingress: None,
        received_ingress: None,
    };
    let mut extra_bytes = 0;
    let decoded = crate::classify::classify(
        &case,
        request,
        response,
        source,
        &deployment,
        &mut extra_bytes,
    )?;
    ensure!(
        extra_bytes == 0
            && decoded.payload.request_raw_object_bytes == "0"
            && decoded.payload.reply_raw_object_bytes == "0",
        "raw object payload remains unsupported"
    );
    if capture.control_selection.is_some() {
        ensure!(
            decoded.class == "storage_control_metadata",
            "unsupported control class"
        );
        observation.class = "storage_control_metadata";
        observation.control = Some(serde_json::json!({
            "operation": decoded.operation, "selectedSourceDigest": source,
            "originalRequestSha256": original.sha256,
            "originalRequestSemanticSha256": observation.request.typed_semantic_sha256,
            "deploymentIdSha256": files::digest(deployment.as_bytes()),
            "challengeNonceSha256": decoded.exchange_id_sha256,
            "originalContextSha256": decoded.original_context_sha256,
            "returnedProtectedMaterialBytes": "0",
            "correlationValidatorSourceSha256": decoded.codec_source_sha256,
        }));
    } else {
        ensure!(
            capture.procedure == aos_hub_core::storage_work::STORAGE_WORK_PATH
                && capture.status == 200,
            "unsupported ordinary storage reply"
        );
        let plan: StorageWorkPlan = super::public_rpc::exact(request)?;
        let result: StorageWorkResult = super::public_rpc::exact(response)?;
        observation.class = match plan.operation.kind() {
            "inspect_git_object" | "inspect_git_objects" | "inspect_stored_git_pack_v1" => {
                "storage_selected_git_content"
            }
            "filter_git_tree_entries_v1" | "filter_stored_git_pack_tree_v1" => {
                "storage_selected_git_tree_rows"
            }
            "inspect_metadata" => "storage_exact_metadata_document",
            "inspect_metadata_objects" => "storage_exact_metadata_document_page",
            "inspect_documentation" => "storage_documentation_index_projection",
            "inspect_documentation_content" => "storage_documentation_canonical_model",
            _ => "storage_control_metadata",
        };
        observation.storage_work = Some(serde_json::json!({
            "originalPlanSha256": original.sha256, "selectedSourceDigest": source,
            "planIdSha256": decoded.exchange_id_sha256, "operation": decoded.operation,
            "executorSourceBytes": result.source_bytes.to_string(),
            "placementPrefixSha256": files::digest(plan.placement_prefix.as_bytes()),
            "payload": {"returnedWholeOciObjectBytes":"0", "returnedOciRangeBytes":"0",
                "selectedDataBytes": decoded.payload.selected_data_bytes,
                "semanticOciProjectionBytes": decoded.payload.semantic_oci_projection_bytes},
        }));
    }
    Ok(())
}

fn clone_file(reference: &files::BodyFile) -> files::BodyFile {
    files::BodyFile {
        file: reference.file.clone(),
        sha256: reference.sha256.clone(),
        byte_size: reference.byte_size.clone(),
    }
}

fn canonical_control(path: &str, request: &[u8], response: &[u8], status: u16) -> Result<()> {
    use super::public_rpc::exact;
    use aos_hub_core::{
        direct_upload::{
            DirectAuthorityLookup, DirectAuthorityLookupReply, DirectFinalGuardLookup,
            DirectFinalGuardReply, DirectStorageCapabilitiesReply,
            DirectStorageCapabilitiesRequest, DIRECT_AUTHORITY_LOOKUP_PATH,
            DIRECT_FINAL_GUARD_PATH,
        },
        storage_work::{
            binding_custody::{
                StorageBindingAdoptionReply, StorageBindingAdoptionRequest,
                STORAGE_BINDING_ADOPTION_PATH,
            },
            StorageCapabilities, STORAGE_CAPABILITIES_CHALLENGE, STORAGE_CAPABILITIES_PATH,
        },
    };

    match path {
        DIRECT_AUTHORITY_LOOKUP_PATH => {
            let _: DirectAuthorityLookup = exact(request)?;
            if status == 200 {
                let _: DirectAuthorityLookupReply = exact(response)?;
            }
        }
        DIRECT_FINAL_GUARD_PATH => {
            let _: DirectFinalGuardLookup = exact(request)?;
            if status == 200 {
                let _: DirectFinalGuardReply = exact(response)?;
            }
        }
        STORAGE_BINDING_ADOPTION_PATH => {
            let _: StorageBindingAdoptionRequest = exact(request)?;
            if status == 200 {
                let _: StorageBindingAdoptionReply = exact(response)?;
            }
        }
        STORAGE_CAPABILITIES_PATH if request == STORAGE_CAPABILITIES_CHALLENGE => {
            if status == 200 {
                let _: StorageCapabilities = exact(response)?;
            }
        }
        STORAGE_CAPABILITIES_PATH => {
            let _: DirectStorageCapabilitiesRequest = exact(request)?;
            if status == 200 {
                let _: DirectStorageCapabilitiesReply = exact(response)?;
            }
        }
        _ => anyhow::bail!("unsupported control selection"),
    }
    Ok(())
}
