//! Shared read and refused-control body observations for the actual ingress corpus.
//!
//! Canonical body types and exact historical ingress correlation classify bytes
//! only. No signature, current permission, provider or placement is accepted.

use crate::{files, Case, Payload};
use anyhow::{ensure, Result};
use aos_hub_core::{
    delivery::{
        classify_capability, DeliveryCapability, DeliverySurfaceKind, RouteAdvertisementPath,
    },
    hybrid_ingress::{
        decode_hybrid_ingress_observation, HybridOciChunkCompletionRequest,
        HybridOciManifestPreflight,
    },
    oci::{parse_oci_path, OciRequest},
};
use aos_oci_types::DistributionErrorEnvelope;

pub(super) fn decode(
    case: &Case,
    request: &[u8],
    reply: &[u8],
    deployment: &str,
    consumed: &mut usize,
) -> Result<(&'static str, &'static str, String, Payload)> {
    let original = files::read(
        case.original_ingress
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("original ingress missing"))?,
        consumed,
    )?;
    let received = files::read(
        case.received_ingress
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("received ingress missing"))?,
        consumed,
    )?;
    ensure!(original == received, "ingress compact substituted");
    let assertion = decode_hybrid_ingress_observation(std::str::from_utf8(&received)?)?;
    ensure!(
        assertion.deployment_id == deployment
            && assertion.method == case.method
            && assertion.path_and_query == case.path_and_query
            && assertion.upload_phase == case.phase
            && assertion.body_sha256 == files::digest(request),
        "ingress transport differs"
    );
    let mut payload = Payload::metadata();
    if case.status >= 400 {
        refused_request(case, request)?;
        ensure!(
            reply.is_empty() || reply.len() <= 16 * 1024,
            "refused control reply exceeds observation bound"
        );
        if !reply.is_empty() {
            ensure!(
                case.response_content_type.as_deref() == Some("application/json"),
                "refused control content type differs"
            );
            let envelope = DistributionErrorEnvelope::from_json(reply)?;
            ensure!(
                serde_json::to_value(&envelope)?
                    == serde_json::from_slice::<serde_json::Value>(reply)?,
                "refusal contains unclassified fields"
            );
            ensure!(
                envelope.errors.iter().all(|entry| entry.detail.is_none()),
                "unclassified structured refusal detail"
            );
        }
        return Ok((
            "ingress_refused_control",
            "ingress_refused_metadata",
            assertion.request_id,
            payload,
        ));
    }
    ensure!(
        matches!(case.method.as_str(), "GET" | "HEAD")
            && case.phase.is_none()
            && request.is_empty()
            && case.status == 200
            && !case.path_and_query.contains('?'),
        "read control transport differs"
    );
    let path = RouteAdvertisementPath::parse_raw_target(&case.path_and_query)?;
    if let Ok(oci) = parse_oci_path(path.as_str()) {
        ensure!(
            matches!(oci, OciRequest::Blob { .. } | OciRequest::Manifest { .. })
                && reply.is_empty(),
            "nonempty or unsupported OCI authorization reply"
        );
        return Ok((
            "ingress_storage_read",
            "ingress_empty_read_authorization",
            assertion.request_id,
            payload,
        ));
    }
    let (_, after_org) = path
        .as_str()
        .trim_start_matches('/')
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("surface organization missing"))?;
    let (_, relative) = after_org
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("surface read path missing"))?;
    if classify_capability(DeliverySurfaceKind::Registry, relative) != DeliveryCapability::Web {
        ensure!(
            reply.is_empty(),
            "storage read authorization body is not empty"
        );
        return Ok((
            "ingress_storage_read",
            "ingress_empty_read_authorization",
            assertion.request_id,
            payload,
        ));
    }
    ensure!(
        case.method == "GET"
            && case.response_content_type.as_deref().is_some_and(
                |kind| kind == "application/json" || kind.starts_with("application/json;")
            ),
        "browse content type differs"
    );
    ensure!(
        reply.len() <= 4 * 1024 * 1024,
        "browse body exceeds existing document bound"
    );
    match relative {
        "-/api/packages" => {
            closed_serialized::<Vec<aos_proto_types::PackageSummary>>(reply)?;
        }
        "-/api/channels" => {
            closed_serialized::<Vec<aos_proto_types::Channel>>(reply)?;
        }
        "-/api/releases" => {
            closed_serialized::<Vec<aos_proto_types::Release>>(reply)?;
        }
        selected if selected.starts_with("-/api/packages/") => {
            closed_serialized::<aos_proto_types::Package>(reply)?;
        }
        selected if selected.starts_with("-/api/v1/documentation/") => {
            let digest = selected.trim_start_matches("-/api/v1/documentation/");
            aos_doc_model::runtime::RuntimeDocument::from_json(reply)?;
            ensure!(
                format!("sha256:{}", files::digest(reply)) == digest,
                "canonical document identity differs"
            );
            payload.reply_raw_object_bytes = reply.len().to_string();
            return Ok((
                "ingress_document_read",
                "ingress_canonical_document_body",
                assertion.request_id,
                payload,
            ));
        }
        _ => anyhow::bail!("unsupported browse read"),
    }
    payload.selected_data_bytes = reply.len().to_string();
    Ok((
        "ingress_browse_query",
        "ingress_browse_selected_data",
        assertion.request_id,
        payload,
    ))
}

fn refused_request(case: &Case, request: &[u8]) -> Result<()> {
    let (path, query) = case
        .path_and_query
        .split_once('?')
        .map_or((case.path_and_query.as_str(), None), |(path, query)| {
            (path, Some(query))
        });
    match (
        parse_oci_path(path),
        case.method.as_str(),
        case.phase.as_deref(),
    ) {
        (Ok(OciRequest::Manifest { .. }), "PUT", Some("complete")) => {
            ensure!(
                request == b"{}"
                    && query.is_some_and(|query| query
                        .strip_prefix("aos_hybrid_manifest_upload=")
                        .is_some_and(|value| value.len() == 32
                            && value.bytes().all(
                                |byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                            ))),
                "refused completion original differs"
            );
        }
        (Ok(OciRequest::Manifest { .. }), "PUT", Some("preflight")) => {
            ensure!(
                query.is_none() && request.len() <= 2048,
                "refused preflight bound differs"
            );
            let value: HybridOciManifestPreflight = serde_json::from_slice(request)?;
            value.sha256_state.validate()?;
        }
        (Ok(OciRequest::BlobUpload { .. }), "PATCH", Some("complete")) => {
            ensure!(
                query.is_none() && request.len() <= 16 * 1024,
                "refused chunk bound differs"
            );
            let value: HybridOciChunkCompletionRequest = serde_json::from_slice(request)?;
            value.admission.sha256_state.validate()?;
            value.next_sha256_state.validate()?;
        }
        (_, "GET" | "HEAD", None) if request.is_empty() => {
            RouteAdvertisementPath::parse_raw_target(path)?;
        }
        (Ok(_), "POST" | "PUT" | "PATCH" | "DELETE", _) if request.is_empty() => {}
        _ => anyhow::bail!("unsupported refused request body"),
    }
    Ok(())
}

// These bodies are emitted by the existing shared message serializers. A
// round-trip check rejects extra fields without a second hand-written schema.
fn closed_serialized<T: serde::de::DeserializeOwned + serde::Serialize>(body: &[u8]) -> Result<()> {
    let value: T = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_value(value)? == serde_json::from_slice::<serde_json::Value>(body)?,
        "browse reply contains unclassified or noncanonical fields"
    );
    Ok(())
}
