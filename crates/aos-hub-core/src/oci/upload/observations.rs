//! Bounded admission observations after the existing fresh actor recheck.
//!
//! The exact permit commitment joins the Native transport's earlier writer
//! check to this later actor check without changing any wire or permission.
//! Independent current SQL, installed purpose and provider evidence is still
//! required. No raw account, token, key or request body is logged.

use anyhow::{Result, ensure};
use aos_oci_types::Sha256Digest;
use serde::Serialize;

use crate::hybrid_ingress::{HYBRID_OCI_FINAL_AUTHORIZATION_PHASE, HybridOciFinalAdmission};
use crate::oci::OciRequest;

#[cfg(test)]
mod tests;

/// Describes one retained bounded upload control without authenticating it.
///
/// The request/reply shape is correlated with the actual production query
/// parsers. No variant establishes current IAM, writer choice, provider effect,
/// upload state, successful settlement or fresh execution permission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HybridOciUploadControlObservation {
    /// Describes an empty upload creation exchange.
    Start,
    /// Describes an empty upload status response.
    Status,
    /// Describes an empty cancellation response.
    Cancel,
    /// Describes an empty final completion for the selected digest.
    Finalize {
        /// Exact sole digest selected by the original query.
        digest: Sha256Digest,
    },
    /// Describes the closed routing hint after bodyless final authorization.
    FinalAuthorization {
        /// Exact sole digest shared with the later final completion query.
        digest: Sha256Digest,
        /// Observed routing/replay hint; it grants no effect or permission.
        admission: HybridOciFinalAdmission,
    },
}

/// Decodes one retained exact upload control using the production query parsers.
///
/// The caller independently correlates the original signed ingress and consumed
/// bytes. Empty application bodies are distinguished from raw blob transfer;
/// this decoder never checks a MAC, changes upload state or accepts live IAM.
///
/// # Errors
/// Returns an error for unsupported operations/phases/statuses, nonempty raw
/// request/reply bodies, oversized authorization metadata, unknown reply fields,
/// malformed or duplicated query selectors, or invalid direct allocation input.
pub fn decode_hybrid_oci_upload_control_observation(
    request: &OciRequest,
    method: &str,
    phase: Option<&str>,
    query: Option<&str>,
    request_body: &[u8],
    reply_body: &[u8],
    status: u16,
) -> Result<HybridOciUploadControlObservation> {
    ensure!(
        query.is_none_or(|value| value.len() <= 4096),
        "upload query exceeds observation bound"
    );
    ensure!(
        request_body.is_empty(),
        "upload control contains raw request bytes"
    );
    match (request, method, phase) {
        (OciRequest::BlobUploadCollection { .. }, "POST", None) => {
            ensure!(
                status == 202 && reply_body.is_empty(),
                "upload creation reply differs"
            );
            let parsed =
                super::parse_start_query(query.unwrap_or_default()).map_err(anyhow::Error::msg)?;
            if parsed.operation_id.is_some() {
                parsed
                    .validate_direct_allocation()
                    .map_err(anyhow::Error::msg)?;
            }
            Ok(HybridOciUploadControlObservation::Start)
        }
        (OciRequest::BlobUpload { .. }, "GET" | "HEAD", None) => {
            ensure!(
                query.is_none() && status == 204 && reply_body.is_empty(),
                "upload status differs"
            );
            Ok(HybridOciUploadControlObservation::Status)
        }
        (OciRequest::BlobUpload { .. }, "DELETE", None) => {
            ensure!(
                query.is_none() && status == 204 && reply_body.is_empty(),
                "upload cancellation differs"
            );
            Ok(HybridOciUploadControlObservation::Cancel)
        }
        (OciRequest::BlobUpload { .. }, "PUT", None) => {
            ensure!(
                status == 201 && reply_body.is_empty(),
                "upload final reply differs"
            );
            let digest =
                super::parse_final_digest(query.unwrap_or_default()).map_err(anyhow::Error::msg)?;
            Ok(HybridOciUploadControlObservation::Finalize { digest })
        }
        (OciRequest::BlobUpload { .. }, "PATCH", Some(HYBRID_OCI_FINAL_AUTHORIZATION_PHASE)) => {
            ensure!(
                status == 200 && reply_body.len() <= 1024,
                "final authorization reply exceeds its control bound"
            );
            let digest =
                super::parse_final_digest(query.unwrap_or_default()).map_err(anyhow::Error::msg)?;
            let admission = serde_json::from_slice::<HybridOciFinalAdmission>(reply_body)?;
            Ok(HybridOciUploadControlObservation::FinalAuthorization { digest, admission })
        }
        _ => anyhow::bail!("upload control operation is unsupported"),
    }
}

use crate::storage_authority::{
    canonical_digest,
    external_object::oci::{OciActorOriginal, admission::ExternalOciStagePermit},
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionObservation {
    version: u8,
    phase: &'static str,
    stage_permit_sha256: String,
    actor_original_sha256: String,
    writer_sha256: String,
    upload_original_sha256: String,
    profile_digest: String,
    completed_at_unix_micros: String,
}

pub(super) fn external_admission(
    phase: &'static str,
    permit: &ExternalOciStagePermit,
    actor: &OciActorOriginal,
) {
    if !matches!(phase, "chunk" | "manifest")
        || actor != &permit.request.actor
        || permit.validate_shape().is_err()
    {
        return;
    }
    let encoded = (|| -> anyhow::Result<String> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        let observation = AdmissionObservation {
            version: 1,
            phase,
            stage_permit_sha256: canonical_digest(permit)?,
            actor_original_sha256: canonical_digest(actor)?,
            writer_sha256: canonical_digest(&permit.request.original.writer)?,
            upload_original_sha256: canonical_digest(&permit.request.original.upload)?,
            profile_digest: permit.request.original.profile_digest.clone(),
            completed_at_unix_micros: now.as_micros().to_string(),
        };
        Ok(serde_json::to_string(&observation)?)
    })();
    if let Ok(encoded) = encoded {
        if encoded.len() <= 4096 {
            tracing::info!("external_oci_admission_actor_checked {encoded}");
        }
    }
}
