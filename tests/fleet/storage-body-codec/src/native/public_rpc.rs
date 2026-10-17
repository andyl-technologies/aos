//! Exact production ProtoJSON and portable Direct public control bodies.

use super::Capture;
use anyhow::{ensure, Result};
use aos_proto_types::direct_upload::*;
use aos_proto_types::*;
use serde::{de::DeserializeOwned, Serialize};

/// Requires every retained byte to be emitted by the selected production DTO.
pub(super) fn exact<T: DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    let decoded: T = serde_json::from_slice(raw)?;
    ensure!(
        serde_json::to_vec(&decoded)? == raw,
        "noncanonical or unclassified DTO bytes"
    );
    Ok(decoded)
}

fn same_publication(original: &str, reply: &RegistryPublication) -> Result<()> {
    ensure!(
        !original.is_empty() && reply.publication_id == original,
        "publication changed"
    );
    publication(reply)
}

fn publication(reply: &RegistryPublication) -> Result<()> {
    ensure!(
        !reply.publication_id.is_empty()
            && !reply.registry.is_empty()
            && valid_direct_digest(&reply.manifest_digest)
            && valid_direct_digest(&reply.default_commit),
        "invalid publication identity"
    );
    let mut paths = std::collections::BTreeSet::new();
    for object in &reply.objects {
        ensure!(
            paths.insert(&object.path)
                && !object.path.is_empty()
                && valid_direct_digest(&object.sha256)
                && object.byte_size >= 0,
            "invalid publication object identity"
        );
        object_path(&object.path)?;
    }
    Ok(())
}

fn object_path(path: &str) -> Result<()> {
    use aos_hub_core::service::{
        MAX_REGISTRY_PUBLICATION_PATH_BYTES, MAX_REGISTRY_PUBLICATION_PATH_COMPONENTS,
    };
    ensure!(
        aos_hub_core::keymap::is_machine_path(path)
            && path.len() <= MAX_REGISTRY_PUBLICATION_PATH_BYTES
            && path.split('/').count() <= MAX_REGISTRY_PUBLICATION_PATH_COMPONENTS,
        "publication path is not bounded machine metadata"
    );
    aos_hub_core::url_guard::validate_http_surface_path(path)?;
    Ok(())
}

pub(super) fn classify(capture: &Capture, request: &[u8], response: &[u8]) -> Result<&'static str> {
    ensure!(
        capture.method == "POST"
            && capture.phase.is_none()
            && capture.status == 200
            && capture.response_content_type.as_deref() == Some("application/json"),
        "public RPC transport differs"
    );
    if capture.procedure == "/-/auth/session-token" {
        ensure!(request.is_empty(), "session token request has a body");
        let reply: BrowserSessionTokenResponse = exact(response)?;
        ensure!(
            reply.token_type == "Bearer"
                && reply.expires_in == 300
                && !reply.access_token.is_empty()
                && reply.access_token.len() <= 16384
                && reply
                    .principal
                    .as_ref()
                    .is_some_and(|principal| principal.kind == "user" && principal.id > 0),
            "session token shape differs"
        );
        return Ok("browser_session_token_metadata");
    }
    if let Some(method) = capture
        .procedure
        .strip_prefix("/aos.hub.v1.DirectUploadService/")
    {
        if method == "GetCapabilities" {
            let original: direct_upload::DirectGetCapabilities = exact(request)?;
            let reply: direct_upload::DirectUploadCapabilities = exact(response)?;
            reply.validate_for(&original.target)?;
        } else {
            let original = decode_direct_public_request(method, request)?;
            let canonical = match &original {
                DirectUploadRequest::BeginBatch(value) => encode_direct_control(value)?,
                DirectUploadRequest::StatusBatch(value) => encode_direct_control(value)?,
                DirectUploadRequest::GrantPartsBatch(value) => encode_direct_control(value)?,
                DirectUploadRequest::ReportPartsBatch(value) => encode_direct_control(value)?,
                DirectUploadRequest::CompleteBatch(value) => encode_direct_control(value)?,
                DirectUploadRequest::Abort(value) => encode_direct_control(value)?,
            };
            ensure!(canonical == request, "noncanonical Direct request");
            let operation = match original {
                DirectUploadRequest::BeginBatch(value) => value.operation_id,
                DirectUploadRequest::StatusBatch(value) => value.operation_id,
                DirectUploadRequest::GrantPartsBatch(value) => value.operation_id,
                DirectUploadRequest::ReportPartsBatch(value) => value.operation_id,
                DirectUploadRequest::CompleteBatch(value) => value.operation_id,
                DirectUploadRequest::Abort(value) => value.operation_id,
            };
            let reply: direct_upload::DirectUploadResponse = exact(response)?;
            reply.validate()?;
            ensure!(reply.operation_id == operation, "Direct operation changed");
        }
        return Ok("public_protojson_control_metadata");
    }
    match capture.procedure.as_str() {
        "/aos.hub.v1.PublishService/BeginRegistryPublicationManifest" => {
            let original: BeginRegistryPublicationManifestRequest = exact(request)?;
            let reply: RegistryPublicationManifestSession = exact(response)?;
            ensure!(
                !original.registry.is_empty()
                    && original.registry.len() <= 512
                    && original.object_count > 0
                    && original.object_count as usize
                        <= aos_hub_core::service::MAX_REGISTRY_PUBLICATION_OBJECTS
                    && valid_direct_digest(&original.manifest_digest)
                    && reply.manifest_digest == original.manifest_digest
                    && reply.object_count == original.object_count
                    && !reply.publication_id.is_empty()
                    && !reply.lease_token.is_empty(),
                "manifest original changed"
            );
        }
        "/aos.hub.v1.PublishService/AppendRegistryPublicationManifest" => {
            let original: AppendRegistryPublicationManifestRequest = exact(request)?;
            let reply: RegistryPublicationManifestSession = exact(response)?;
            ensure!(
                !original.objects.is_empty()
                    && original.objects.len() <= 256
                    && valid_direct_digest(&original.chunk_digest)
                    && reply.publication_id == original.publication_id
                    && reply.lease_token == original.lease_token
                    && reply.next_chunk_index
                        == original
                            .chunk_index
                            .checked_add(1)
                            .ok_or_else(|| anyhow::anyhow!("chunk overflow"))?,
                "manifest append changed"
            );
            ensure!(
                super::manifest_digest::digest(&original.objects)? == original.chunk_digest,
                "manifest chunk commitment changed"
            );
            let mut paths = std::collections::BTreeSet::new();
            for object in &original.objects {
                object_path(&object.path)?;
                ensure!(
                    paths.insert(&object.path)
                        && object.byte_size >= 0
                        && valid_direct_digest(&object.sha256)
                        && matches!(object.kind.as_str(), "immutable" | "mutable_pointer")
                        && object.media_type.len() <= 256,
                    "invalid manifest object metadata"
                );
            }
        }
        "/aos.hub.v1.PublishService/SealRegistryPublicationManifest" => {
            let original: SealRegistryPublicationManifestRequest = exact(request)?;
            same_publication(&original.publication_id, &exact(response)?)?;
        }
        "/aos.hub.v1.PublishService/GetRegistryPublication" => {
            let original: GetRegistryPublicationRequest = exact(request)?;
            same_publication(&original.publication_id, &exact(response)?)?;
        }
        "/aos.hub.v1.PublishService/CommitRegistryPublication" => {
            let original: CommitRegistryPublicationRequest = exact(request)?;
            same_publication(&original.publication_id, &exact(response)?)?;
        }
        "/aos.hub.v1.PublishService/ListRegistryPublications" => {
            let original: ListRegistryPublicationsRequest = exact(request)?;
            let reply: ListRegistryPublicationsResponse = exact(response)?;
            for value in reply.publications {
                publication(&value)?;
                ensure!(
                    value.registry == original.registry,
                    "listed registry changed"
                );
            }
        }
        "/aos.hub.v1.RegistryService/GetRegistry" => {
            let _: GetRegistryRequest = exact(request)?;
            let _: GetRegistryResponse = exact(response)?;
        }
        "/aos.hub.v1.IdentityService/WhoAmI" => {
            let _: WhoAmIRequest = exact(request)?;
            let _: WhoAmIResponse = exact(response)?;
        }
        _ => anyhow::bail!("unsupported public RPC"),
    }
    Ok("public_protojson_control_metadata")
}
