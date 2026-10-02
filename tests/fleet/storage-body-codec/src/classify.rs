//! Shared closed codecs and exact Distribution phase body observations.
//!
//! The classification describes encoded application bodies. It does not verify
//! a compact MAC, authorize a current actor or infer where provider work ran.

use anyhow::{ensure, Result};
use aos_hub_core::{
    hybrid_ingress::{
        decode_hybrid_ingress_observation, HybridOciChunkAdmission,
        HybridOciChunkCompletionRequest, HybridOciManifestAdmission, HybridOciManifestPreflight,
        HYBRID_OCI_FINAL_AUTHORIZATION_PHASE,
    },
    oci::{
        decode_hybrid_oci_upload_control_observation, parse_oci_path,
        HybridOciUploadControlObservation, OciRequest,
    },
    oci_projection::{guard::decode_oci_projection_observation, OciDocumentProjection},
    storage_authority::external_object::copy::{
        control::EXTERNAL_COPY_PATH,
        metadata::EXTERNAL_COPY_METADATA_PATH,
        observation::{decode_copy_control_observation, decode_copy_metadata_observation},
    },
};
use aos_oci_types::{Annotations, Descriptor, MediaType, Sha256Digest};
use serde::de::DeserializeOwned;

use crate::{files, Case, Observation, Payload};

pub(super) fn classify(
    case: &Case,
    request: &[u8],
    reply: &[u8],
    source_digest: &str,
    deployment: &str,
    consumed: &mut usize,
) -> Result<Observation> {
    let mut payload = Payload::metadata();
    let (operation, class, exchange_id) = match case.path_and_query.as_str() {
        EXTERNAL_COPY_PATH => {
            control_case(case)?;
            let (request, _) = decode_copy_control_observation(request, reply, deployment)?;
            (
                "external_copy_control",
                "external_copy_control_metadata",
                request.plan.plan_id,
            )
        }
        EXTERNAL_COPY_METADATA_PATH => {
            control_case(case)?;
            let (request, _) = decode_copy_metadata_observation(request, reply, deployment)?;
            (
                "external_copy_metadata",
                "external_copy_profile_metadata",
                request.plan.plan_id,
            )
        }
        aos_hub_core::storage_work::STORAGE_WORK_PATH => {
            ensure!(
                case.method == "POST"
                    && case.phase.is_none()
                    && case.original_ingress.is_none()
                    && case.received_ingress.is_none(),
                "storage work transport differs"
            );
            let expected_type = if case.status == 200 {
                "application/json"
            } else {
                "text/plain; charset=utf-8"
            };
            ensure!(
                case.response_content_type.as_deref() == Some(expected_type),
                "storage work response type differs"
            );
            let (request, class, observed) =
                crate::storage_work::decode_transport(request, reply, deployment, case.status)?;
            payload = observed;
            (request.operation.kind(), class, request.plan_id)
        }
        aos_hub_core::storage_authority::external_object::oci::control::EXTERNAL_OCI_PATH => {
            control_case(case)?;
            let (request, _) = aos_hub_core::storage_authority::external_object::oci::observation::decode_external_oci_control_observation(request, reply, deployment)?;
            (
                "external_oci_control",
                "external_oci_control_metadata",
                request.nonce,
            )
        }
        aos_hub_core::storage_authority::external_object::oci::source::OCI_SOURCE_PATH => {
            control_case(case)?;
            let (request, _) = aos_hub_core::storage_authority::external_object::oci::observation::decode_external_oci_source_observation(request, reply, deployment)?;
            ensure!(
                request.issuer.source_digest == source_digest,
                "source implementation differs"
            );
            (
                "external_oci_source",
                "external_oci_source_metadata",
                request.nonce,
            )
        }
        aos_hub_core::storage_authority::external_object::oci::cleanup::OCI_CLEANUP_PATH => {
            control_case(case)?;
            let (request, _) = aos_hub_core::storage_authority::external_object::oci::observation::decode_external_oci_cleanup_observation(request, reply, deployment)?;
            ensure!(
                request.issuer.source_digest == source_digest,
                "cleanup implementation differs"
            );
            (
                "external_oci_cleanup",
                "external_oci_cleanup_metadata",
                request.nonce,
            )
        }
        aos_hub_core::oci_cleanup::MANAGED_OCI_CLEANUP_PATH => {
            control_case(case)?;
            let (request, _) =
                aos_hub_core::oci_cleanup::observation::decode_managed_oci_cleanup_observation(
                    request, reply, deployment,
                )?;
            ensure!(
                request.issuer.source_digest == source_digest,
                "Managed cleanup implementation differs"
            );
            (
                "managed_oci_cleanup",
                "managed_oci_terminal_cleanup_metadata",
                request.nonce,
            )
        }
        aos_hub_core::oci_projection::guard::OCI_PROJECTION_PATH => {
            control_case(case)?;
            let (request, reply) = decode_oci_projection_observation(request, reply, deployment)?;
            ensure!(
                request.issuer.source_digest == source_digest,
                "projection source differs"
            );
            ensure!(
                request.descriptor.data.is_none() && !has_inline_data(&reply.projection),
                "inline object bodies remain unsupported"
            );
            payload.semantic_oci_projection_bytes =
                serde_json::to_vec(&reply.projection)?.len().to_string();
            (
                "OciDocumentProjection",
                "oci_stored_document_projection",
                request.nonce,
            )
        }
        path if crate::controls::supports(path) => {
            crate::controls::decode(case, request, reply, deployment)?
        }
        _ if case.status >= 400
            || !case.path_and_query.starts_with("/v2/")
            || case.method == "HEAD" =>
        {
            let (operation, class, exchange_id, observed) =
                crate::ingress::decode(case, request, reply, deployment, consumed)?;
            payload = observed;
            (operation, class, exchange_id)
        }
        _ => {
            let (operation, class, exchange_id, observed) =
                distribution(case, request, reply, deployment, consumed)?;
            payload = observed;
            (operation, class, exchange_id)
        }
    };
    let mut source = Vec::new();
    for file in [
        include_bytes!("main.rs").as_slice(),
        include_bytes!("files.rs").as_slice(),
        include_bytes!("classify.rs").as_slice(),
        include_bytes!("storage_work.rs").as_slice(),
        include_bytes!("ingress.rs").as_slice(),
        include_bytes!("controls.rs").as_slice(),
        include_bytes!("copy_request.rs").as_slice(),
    ] {
        source.extend_from_slice(file);
    }
    Ok(Observation {
        request_id: case.request_id.clone(),
        source_digest: source_digest.into(),
        request_sha256: files::digest(request),
        reply_sha256: files::digest(reply),
        codec_source_sha256: files::digest(&source),
        exchange_id_sha256: files::digest(exchange_id.as_bytes()),
        original_context_sha256: files::digest(request),
        operation,
        class,
        payload,
    })
}

fn control_case(case: &Case) -> Result<()> {
    ensure!(
        case.method == "POST"
            && case.phase.is_none()
            && case.status == 200
            && case.original_ingress.is_none()
            && case.received_ingress.is_none()
            && case.response_content_type.as_deref() == Some("application/json"),
        "control transport differs"
    );
    Ok(())
}

fn distribution(
    case: &Case,
    request: &[u8],
    reply: &[u8],
    deployment: &str,
    consumed: &mut usize,
) -> Result<(&'static str, &'static str, String, Payload)> {
    let original = files::read(
        case.original_ingress
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing original ingress"))?,
        consumed,
    )?;
    let received = files::read(
        case.received_ingress
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing received ingress"))?,
        consumed,
    )?;
    ensure!(original == received, "ingress compact substituted");
    let ingress = decode_hybrid_ingress_observation(std::str::from_utf8(&received)?)?;
    ensure!(
        ingress.deployment_id == deployment
            && ingress.method == case.method
            && ingress.path_and_query == case.path_and_query
            && ingress.upload_phase == case.phase
            && ingress.body_sha256 == files::digest(request),
        "ingress and original bodies differ"
    );
    let (path, query) = case
        .path_and_query
        .split_once('?')
        .map_or((case.path_and_query.as_str(), None), |(path, query)| {
            (path, Some(query))
        });
    let oci =
        parse_oci_path(path).map_err(|_| anyhow::anyhow!("unsupported Distribution route"))?;
    let mut payload = Payload::metadata();
    let metadata = "oci_distribution_control_metadata";
    let (operation, class) = match (&oci, case.method.as_str(), case.phase.as_deref()) {
        (OciRequest::BlobUploadCollection { .. }, "POST", None)
        | (OciRequest::BlobUpload { .. }, "GET" | "HEAD" | "DELETE" | "PUT", None)
        | (OciRequest::BlobUpload { .. }, "PATCH", Some(HYBRID_OCI_FINAL_AUTHORIZATION_PHASE)) => {
            let observed = decode_hybrid_oci_upload_control_observation(
                &oci,
                &case.method,
                case.phase.as_deref(),
                query,
                request,
                reply,
                case.status,
            )?;
            let operation = match observed {
                HybridOciUploadControlObservation::Start => "oci_upload_start",
                HybridOciUploadControlObservation::Status => "oci_upload_status",
                HybridOciUploadControlObservation::Cancel => "oci_upload_cancel",
                HybridOciUploadControlObservation::Finalize { .. } => "oci_upload_finalize",
                HybridOciUploadControlObservation::FinalAuthorization { .. } => {
                    "oci_upload_final_authorize"
                }
            };
            (operation, metadata)
        }
        (OciRequest::Manifest { .. }, "PUT", Some("authorize")) => {
            ensure!(
                query.is_none() && request.is_empty() && reply.is_empty() && case.status == 204,
                "manifest authorization body differs"
            );
            ("oci_manifest_authorize", metadata)
        }
        (OciRequest::Manifest { .. }, "PUT", Some("preflight")) => {
            ensure!(
                query.is_none()
                    && request.len() <= 2048
                    && reply.len() <= 4096
                    && case.status == 200,
                "manifest preflight transport differs"
            );
            let preflight: HybridOciManifestPreflight = closed(request)?;
            let _: HybridOciManifestAdmission = closed(reply)?;
            preflight.sha256_state.validate()?;
            ("oci_manifest_preflight", metadata)
        }
        (OciRequest::Manifest { .. }, "PUT", Some("complete")) => {
            let upload_id = query
                .and_then(|query| query.strip_prefix("aos_hybrid_manifest_upload="))
                .ok_or_else(|| anyhow::anyhow!("missing completion original"))?;
            ensure!(
                upload_id.len() == 32
                    && upload_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "invalid completion original"
            );
            ensure!(
                request == b"{}" && reply.is_empty() && case.status == 201,
                "manifest completion body differs"
            );
            ("oci_manifest_complete", metadata)
        }
        (OciRequest::BlobUpload { .. }, "PATCH", Some("preflight")) => {
            ensure!(
                query.is_none() && request.is_empty() && reply.len() <= 4096 && case.status == 200,
                "chunk preflight transport differs"
            );
            let admission: HybridOciChunkAdmission = closed(reply)?;
            admission.sha256_state.validate()?;
            ("oci_chunk_preflight", metadata)
        }
        (OciRequest::BlobUpload { .. }, "PATCH", Some("complete")) => {
            ensure!(
                query.is_none()
                    && request.len() <= 16 * 1024
                    && reply.is_empty()
                    && case.status == 202,
                "chunk completion body differs"
            );
            let completion: HybridOciChunkCompletionRequest = closed(request)?;
            completion.admission.sha256_state.validate()?;
            completion.next_sha256_state.validate()?;
            ("oci_chunk_complete", metadata)
        }
        (OciRequest::Blob { digest, .. }, "GET", None) => {
            ensure!(
                query.is_none() && request.is_empty() && case.status == 200,
                "blob read transport differs"
            );
            if !reply.is_empty() {
                ensure!(
                    Sha256Digest::digest(reply) == *digest,
                    "raw blob digest differs"
                );
            }
            payload.reply_raw_object_bytes = reply.len().to_string();
            ("oci_blob_download", "oci_distribution_blob_body")
        }
        (OciRequest::Manifest { .. }, "GET", None) => {
            ensure!(
                query.is_none() && request.is_empty() && case.status == 200,
                "document read transport differs"
            );
            if !reply.is_empty() {
                let media_type = MediaType::parse(
                    case.response_content_type
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("document media type missing"))?,
                )?;
                let descriptor = Descriptor {
                    media_type,
                    digest: Sha256Digest::digest(reply),
                    size: reply.len() as u64,
                    urls: Vec::new(),
                    annotations: Annotations::new(),
                    data: None,
                    artifact_type: None,
                    platform: None,
                };
                let _ = OciDocumentProjection::from_stored_bytes(&descriptor, reply)?;
            }
            payload.reply_raw_object_bytes = reply.len().to_string();
            ("oci_document_download", "oci_distribution_document_body")
        }
        _ => anyhow::bail!("unsupported Distribution body path"),
    };
    Ok((operation, class, ingress.request_id, payload))
}

fn closed<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    Ok(serde_json::from_slice(body)?)
}

fn has_inline_data(projection: &OciDocumentProjection) -> bool {
    match projection {
        OciDocumentProjection::Manifest(manifest) => {
            manifest.config.data.is_some()
                || manifest
                    .layers
                    .iter()
                    .any(|descriptor| descriptor.data.is_some())
                || manifest
                    .subject
                    .as_ref()
                    .is_some_and(|descriptor| descriptor.data.is_some())
        }
        OciDocumentProjection::Index(index) => {
            index
                .manifests
                .iter()
                .any(|descriptor| descriptor.data.is_some())
                || index
                    .subject
                    .as_ref()
                    .is_some_and(|descriptor| descriptor.data.is_some())
        }
        OciDocumentProjection::Config(_) => false,
    }
}
