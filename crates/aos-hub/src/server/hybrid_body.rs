//! Pre-body admission for the hybrid Native origin.
//!
//! An authenticated private phase chooses a bounded metadata format. The
//! classifier never authorizes an upload, substitutes for the body MAC, or
//! treats an OCI route suffix as proof of an enabled delivery route.

use aos_hub_core::hybrid_ingress::{HybridIngressAssertion, HYBRID_UPLOAD_PHASE_HEADER};
use aos_hub_core::oci::OciRequest;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};

use crate::db::Database;

const CACHE_OBJECT_CONTROL_BYTES: usize = 64 * 1024;
const MANIFEST_CONTROL_BYTES: usize = 2;
const DIRECT_CONTROL_BYTES: usize = 256 * 1024;

pub(super) async fn body_limit(
    db: Option<&Database>,
    control_url: &str,
    assertion: &HybridIngressAssertion,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<usize, StatusCode> {
    let phases = headers.get_all(HYBRID_UPLOAD_PHASE_HEADER);
    let mut phases = phases.iter();
    let phase = phases
        .next()
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if phases.next().is_some() || phase != assertion.upload_phase.as_deref() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let path = uri.path();
    let mut fixed_manifest_completion = false;
    let limit = if path.starts_with("/aos.hub.v1.") {
        if !aos_hub_core::connect::hybrid_control_authority_matches(
            control_url,
            &assertion.authority,
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?
        {
            return Err(StatusCode::MISDIRECTED_REQUEST);
        }
        control_limit(method, path, uri.query(), phase)?
    } else {
        let oci = if matches!(
            *method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            match db {
                Some(db) => {
                    aos_hub_core::connect::resolve_hybrid_oci_path(db, &assertion.authority, path)
                        .await
                        .map_err(|_| StatusCode::BAD_REQUEST)?
                }
                None => None,
            }
        } else {
            None
        };
        match oci {
            Some(oci) => {
                fixed_manifest_completion = matches!(oci, OciRequest::Manifest { .. })
                    && *method == Method::PUT
                    && phase == Some("complete");
                oci_limit(method, &oci, uri.query(), phase)?
            }
            None if phase.is_some() || matches!(*method, Method::PUT | Method::PATCH) => {
                return Err(StatusCode::BAD_REQUEST);
            }
            None if matches!(*method, Method::GET | Method::HEAD | Method::DELETE) => 0,
            None => super::RPC_MAX_BODY_BYTES,
        }
    };

    // Completion contains one canonical empty control. Authenticate its
    // exact commitment before polling; even a valid actor cannot send raw
    // manifest bytes through this private metadata route.
    if fixed_manifest_completion
        && assertion.body_sha256 != aos_hub_core::hybrid_ingress::body_sha256(b"{}")
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    // A declared oversized body can be rejected without touching the stream.
    // Undeclared/chunked bodies are bounded by the same selected cap afterward.
    let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
    if let Some(value) = lengths.next() {
        let length = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(StatusCode::BAD_REQUEST)?;
        if lengths.next().is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if fixed_manifest_completion && length != MANIFEST_CONTROL_BYTES as u64 {
            return Err(StatusCode::BAD_REQUEST);
        }
        if length > limit as u64 {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
    if limit == 0 && assertion.body_sha256 != aos_hub_core::hybrid_ingress::body_sha256(&[]) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(limit)
}

fn control_limit(
    method: &Method,
    path: &str,
    query: Option<&str>,
    phase: Option<&str>,
) -> Result<usize, StatusCode> {
    let segments: Vec<_> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    // These legacy JSON methods contain original narinfo text. Hybrid clients
    // must use verified direct staging; a private phase cannot make raw text a
    // semantic projection. Standalone routing does not use this classifier.
    if segments.first() == Some(&"aos.hub.v1.BinaryCacheService")
        && segments.get(1).is_some_and(|method| {
            matches!(*method, "RegisterCacheNarinfos" | "ReportCacheNarinfos")
        })
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    let upload = segments
        .get(1)
        .is_some_and(|operation| matches!(*operation, "UploadObject" | "UploadPart"));
    if upload {
        if *method != Method::PUT || query.is_some() || path.contains('%') || path.contains("//") {
            return Err(StatusCode::BAD_REQUEST);
        }
        let phase = phase.ok_or(StatusCode::BAD_REQUEST)?;
        let expected_segments = match (segments[0], segments[1]) {
            ("aos.hub.v1.BinaryCacheService", "UploadObject") => 5,
            ("aos.hub.v1.PublishService", "UploadObject") => 4,
            ("aos.hub.v1.BinaryCacheService" | "aos.hub.v1.PublishService", "UploadPart") => 4,
            _ => return Err(StatusCode::BAD_REQUEST),
        };
        if segments.len() != expected_segments {
            return Err(StatusCode::BAD_REQUEST);
        }
        return match (segments[0], segments[1], phase) {
            ("aos.hub.v1.BinaryCacheService", "UploadObject" | "UploadPart", "preflight")
            | ("aos.hub.v1.PublishService", "UploadPart", "preflight")
            | ("aos.hub.v1.PublishService", "UploadObject", "admit") => Ok(0),
            ("aos.hub.v1.BinaryCacheService", "UploadObject", "admit" | "complete") => {
                Ok(CACHE_OBJECT_CONTROL_BYTES)
            }
            ("aos.hub.v1.BinaryCacheService", "UploadPart", "admit" | "complete") => Ok(4096),
            ("aos.hub.v1.PublishService", "UploadObject", "complete") => Ok(64 * 1024),
            ("aos.hub.v1.PublishService", "UploadPart", "admit" | "complete") => Ok(256 * 1024),
            _ => Err(StatusCode::BAD_REQUEST),
        };
    }
    if segments.first() == Some(&"aos.hub.v1.DirectUploadService") {
        if *method != Method::POST || segments.len() != 2 || query.is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
        return match (segments[1], phase) {
            ("GetCapabilities", None) => Ok(4096),
            ("BeginBatch", Some("admission"))
            | (
                "StatusBatch" | "GrantPartsBatch" | "ReportPartsBatch" | "CompleteBatch" | "Abort",
                Some("authorize"),
            )
            | ("CompleteBatch", Some("commit"))
            | ("Abort", Some("abort-report")) => Ok(DIRECT_CONTROL_BYTES),
            _ => Err(StatusCode::BAD_REQUEST),
        };
    }
    if phase.is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    match *method {
        Method::POST => Ok(super::RPC_MAX_BODY_BYTES),
        Method::GET | Method::HEAD => Ok(0),
        _ => Err(StatusCode::METHOD_NOT_ALLOWED),
    }
}

fn oci_limit(
    method: &Method,
    oci: &OciRequest,
    query: Option<&str>,
    phase: Option<&str>,
) -> Result<usize, StatusCode> {
    match (oci, method, phase) {
        (OciRequest::BlobUpload { .. }, &Method::PATCH, Some("preflight")) if query.is_none() => {
            Ok(0)
        }
        (OciRequest::BlobUpload { .. }, &Method::PATCH, Some("complete")) if query.is_none() => {
            Ok(16 * 1024)
        }
        (OciRequest::Manifest { .. }, &Method::PUT, Some("authorize")) if query.is_none() => Ok(0),
        (OciRequest::Manifest { .. }, &Method::PUT, Some("preflight")) if query.is_none() => {
            Ok(2048)
        }
        (OciRequest::Manifest { .. }, &Method::PUT, Some("complete")) => {
            if !valid_manifest_query(query) {
                return Err(StatusCode::BAD_REQUEST);
            }
            Ok(MANIFEST_CONTROL_BYTES)
        }
        (OciRequest::BlobUploadCollection { .. }, &Method::POST, None)
        | (OciRequest::BlobUpload { .. }, &Method::PUT | &Method::DELETE, None) => Ok(0),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

fn valid_manifest_query(query: Option<&str>) -> bool {
    let Some(query) = query else { return false };
    let Some(id) = query.strip_prefix("aos_hybrid_manifest_upload=") else {
        return false;
    };
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests;
