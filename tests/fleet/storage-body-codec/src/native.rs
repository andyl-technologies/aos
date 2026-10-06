//! Confined observations of private Native application bodies.
//!
//! Authentication, current SQL and complete membership remain independent joins.

mod browser;
mod logical;
mod manifest_digest;
mod projection;
mod public_rpc;
mod storage;

use crate::files::{self, BodyFile};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    version: u32,
    codec_revision: String,
    source_digest: String,
    issuer_verifier: Option<IssuerVerifier>,
    captures: Vec<Capture>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssuerVerifier {
    key_id: String,
    public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Capture {
    request_id: String,
    procedure: String,
    method: String,
    phase: Option<String>,
    status: u16,
    response_content_type: Option<String>,
    response_content_encoding: Option<String>,
    bodies: Bodies,
    control_selection: Option<ControlSelection>,
    storage_work_selection: Option<StorageSelection>,
    empty_response_observation: Option<EmptyResponse>,
    immutable_projection: Option<projection::Selection>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bodies {
    request: BodyFile,
    response: BodyFile,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlSelection {
    source_digest: String,
    deployment_id: String,
    original_request: BodyFile,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StorageSelection {
    source_digest: String,
    completion_observed_at_unix_millis: String,
    original_plan: BodyFile,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmptyResponse {
    kind: String,
    request_id: String,
    status: u16,
    upstream_status: u16,
    response_body_bytes: u64,
    request_completion: String,
    upstream_response_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BodyObservation {
    sha256: String,
    byte_size: String,
    typed_semantic_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Observation {
    request_id_sha256: String,
    procedure: String,
    method: String,
    phase: Option<String>,
    class: &'static str,
    request: BodyObservation,
    response: BodyObservation,
    original_public_request_sha256: Option<String>,
    browser_source: Option<Value>,
    authentication: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    control: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_work: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    immutable_projection: Option<projection::Observation>,
}

fn body(bytes: &[u8]) -> BodyObservation {
    BodyObservation {
        sha256: files::digest(bytes),
        byte_size: bytes.len().to_string(),
        typed_semantic_sha256: files::digest(bytes),
    }
}

/// Emits the existing eight-field observational report.
///
/// # Errors
/// Refuses changed provenance, custody, bounds or unsupported body classes.
pub(super) fn run_manifest(path: &Path) -> Result<()> {
    let raw = files::read_manifest(path)?;
    let (observations, bytes) = inspect(serde_json::from_slice(&raw)?)?;
    serde_json::to_writer(
        std::io::stdout().lock(),
        &serde_json::json!({
            "version": 1, "codecRevision": env!("NATIVE_CODEC_REVISION"),
            "selectedSourceDigest": env!("NATIVE_WORKER_SOURCE_DIGEST"),
            "manifestSha256": files::digest(&raw), "selectedBodyBytes": bytes,
            "maximumSelectedBodyBytes": crate::MAX_CORPUS_BYTES,
            "maximumBodyBytes": 8 * 1024 * 1024, "captures": observations,
        }),
    )?;
    Ok(())
}

fn inspect(selection: Selection) -> Result<(Vec<Observation>, usize)> {
    ensure!(
        selection.version == 1
            && selection.codec_revision == env!("NATIVE_CODEC_REVISION")
            && selection.source_digest == env!("NATIVE_WORKER_SOURCE_DIGEST"),
        "selected runtime differs"
    );
    ensure!(
        !selection.captures.is_empty() && selection.captures.len() <= crate::MAX_CASES,
        "empty or excessive captures"
    );
    let mut identifiers = BTreeSet::new();
    let mut selected_bytes = 0;
    let mut observations = Vec::with_capacity(selection.captures.len());
    for capture in selection.captures {
        ensure!(
            !capture.request_id.is_empty()
                && capture.request_id.len() <= 128
                && !capture.request_id.chars().any(char::is_control)
                && identifiers.insert(capture.request_id.clone()),
            "invalid or duplicate capture"
        );
        ensure!(
            capture
                .response_content_encoding
                .as_deref()
                .is_none_or(|value| value.is_empty() || value == "identity"),
            "encoded capture unsupported"
        );
        let request = files::read(&capture.bodies.request, &mut selected_bytes)?;
        let response = files::read(&capture.bodies.response, &mut selected_bytes)?;
        if let Some(empty) = &capture.empty_response_observation {
            ensure!(
                empty.kind == "measured_completed_empty_transport"
                    && empty.request_id == capture.request_id
                    && empty.status == capture.status
                    && empty.upstream_status == capture.status
                    && empty.response_body_bytes == 0
                    && empty.upstream_response_bytes == 0
                    && empty.request_completion == "OK"
                    && response.is_empty(),
                "empty transport observation differs"
            );
        }
        let mut observation = Observation {
            request_id_sha256: files::digest(capture.request_id.as_bytes()),
            procedure: capture.procedure.clone(),
            method: capture.method.clone(),
            phase: capture.phase.clone(),
            class: "",
            request: body(&request),
            response: body(&response),
            original_public_request_sha256: None,
            browser_source: None,
            authentication: "not_checked_join_independent_authenticated_worker_receipt",
            control: None,
            storage_work: None,
            immutable_projection: None,
        };
        if capture.control_selection.is_some() || capture.storage_work_selection.is_some() {
            storage::classify(
                &capture,
                &request,
                &response,
                &selection.source_digest,
                &mut observation,
            )?;
        } else if capture.procedure
            == aos_hub_core::storage_authority::lease::control::ISSUER_CONTROL_PATH
        {
            issuer(
                &capture,
                &request,
                &response,
                selection.issuer_verifier.as_ref(),
            )?;
            observation.class = "issuer_control_metadata";
        } else if capture.phase.is_some() {
            observation.original_public_request_sha256 =
                Some(logical::classify(&capture, &request, &response)?);
            observation.class =
                "logical_control_with_optional_normalized_narinfo_or_oci_projection";
        } else if capture.procedure == "/-/instance" {
            browser::classify(&capture, &request, &response)?;
            observation.class = "authenticated_instance_app_shell_html";
            observation.browser_source = Some(browser::source());
        } else {
            observation.class = public_rpc::classify(&capture, &request, &response)?;
        }
        if let Some(selected) = &capture.immutable_projection {
            observation.immutable_projection = Some(projection::inspect(
                selected,
                &capture,
                &request,
                &response,
                &mut selected_bytes,
            )?);
        }
        observations.push(observation);
    }
    Ok((observations, selected_bytes))
}

fn issuer(
    capture: &Capture,
    request: &[u8],
    response: &[u8],
    verifier: Option<&IssuerVerifier>,
) -> Result<()> {
    use aos_hub_core::storage_authority::lease::{control, EpochLeaseVerifier};
    ensure!(
        capture.method == "POST"
            && capture.phase.is_none()
            && capture.status == 200
            && capture.response_content_type.as_deref() == Some("application/json"),
        "issuer transport differs"
    );
    let verifier = verifier.ok_or_else(|| anyhow::anyhow!("missing issuer trust anchor"))?;
    let bytes: [u8; 32] = hex::decode(&verifier.public_key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("issuer public key length differs"))?;
    let verifier = EpochLeaseVerifier::from_bytes(verifier.key_id.clone(), &bytes)?;
    let original = control::IssuerRequest::decode(request)?;
    original.validate(&original.installation, original.issued_at.get())?;
    control::verify_issuer_reply(&verifier, &original, response)?;
    Ok(())
}

#[cfg(test)]
mod tests;
