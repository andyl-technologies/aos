//! Signed request context for the hybrid Worker's Native origin.
//!
//! The public Worker is the only caller allowed onto the hybrid origin. Its
//! assertion binds the public authority and transport facts to the exact
//! method, path, and body forwarded to Native. The origin verifies it before
//! any route, authentication, or rate-limit middleware can use those facts.

use std::collections::BTreeMap;
use std::net::IpAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Header carrying the compact signed Worker ingress assertion.
pub const HYBRID_INGRESS_HEADER: &str = "x-aos-hybrid-ingress";
/// Internal response header carrying an exact Worker-side R2 delivery grant.
pub const HYBRID_DELIVERY_HEADER: &str = "x-aos-hybrid-delivery";
/// Private request header selecting one Worker-owned upload phase.
pub const HYBRID_UPLOAD_PHASE_HEADER: &str = "x-aos-hybrid-upload-phase";
/// Maximum required R2 placements in one bounded publication admission.
pub const MAX_HYBRID_PUBLICATION_PLACEMENTS: usize = 32;

/// Marks a verified Worker-to-Native request for data-plane route fencing.
#[derive(Clone, Copy, Debug)]
pub struct HybridOriginRequest;

const MAX_LIFETIME_SECONDS: i64 = 30;
const FUTURE_SKEW_SECONDS: i64 = 5;

type HmacSha256 = Hmac<Sha256>;

/// The public request facts attested by the Worker ingress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridIngressAssertion {
    /// The wire format version. Only version 1 is accepted.
    pub version: u8,
    /// Deployment identity shared by the Worker and Native Hub.
    pub deployment_id: String,
    /// Unix time when the Worker signed the request.
    pub issued_at: i64,
    /// Unix time after which the origin rejects the request.
    pub expires_at: i64,
    /// Unique request identifier for tracing and replay investigation.
    pub request_id: String,
    /// Public client-facing scheme, always HTTPS in hybrid mode.
    pub scheme: String,
    /// Public authority, including a non-default port.
    pub authority: String,
    /// Uppercase HTTP method.
    pub method: String,
    /// Exact path and query supplied by the public client.
    pub path_and_query: String,
    /// SHA-256 of the request body sent to the origin.
    pub body_sha256: String,
    /// Client IP verified by the Cloudflare ingress.
    pub client_ip: String,
}

/// Exact object snapshot that Native authorizes the Worker to deliver.
///
/// Native emits this only after the shared delivery route and surface read
/// authorization succeed. The origin middleware binds it to the signed
/// request before the Worker reads from R2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridDeliveryTarget {
    /// Full key in the deployment R2 bucket.
    pub object_key: String,
    /// Size observed from the selected placement.
    pub object_size: u64,
    /// Strong provider version observed with the size.
    pub object_etag: String,
    /// Shared surface MIME classification.
    pub content_type: String,
    /// Shared surface cache policy.
    pub cache_control: String,
    /// Whether delivery must sandbox and download the producer document.
    pub producer_document: bool,
    /// Exact HTTP plan for an immutable object, including its selected range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planned_response: Option<HybridPlannedDelivery>,
}

/// Immutable object response that the Worker serves from a verified R2 snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridPlannedDelivery {
    /// Planned HTTP status, either 200 or 206 for a response with a body.
    pub status: u16,
    /// Inclusive first body byte selected by Native's conditional request plan.
    pub start: u64,
    /// Inclusive final body byte selected by Native's conditional request plan.
    pub end: u64,
    /// Exact allowlisted response headers from a shared object HTTP planner.
    pub headers: BTreeMap<String, String>,
}

/// Short-lived delivery authority signed by the Native origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridDeliveryGrant {
    /// Grant wire version.
    pub version: u8,
    /// Deployment shared by the Worker and Native origin.
    pub deployment_id: String,
    /// The exact Worker-signed ingress request that caused authorization.
    pub request_id: String,
    /// Expiry inherited from the ingress request.
    pub expires_at: i64,
    /// Exact physical object and response classification.
    pub target: HybridDeliveryTarget,
}

/// Native's size bound for an authorized cache ticket before reading client bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridCacheUploadPreflight {
    /// Exact size reserved by the authorized cache upload ticket.
    pub expected_size: u64,
}

/// Metadata sent to Native before the Worker writes an admitted cache object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridCacheUploadAdmissionRequest {
    /// Exact number of client body bytes retained at the Worker.
    pub size: u64,
    /// Lowercase SHA-256 of those bytes, computed beside R2.
    pub sha256: String,
    /// Exact narinfo body, when the object is a small signed narinfo.
    pub narinfo: Option<String>,
}

/// Native's decision for one exact Worker-side cache PUT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridCacheUploadAdmission {
    /// Full deployment R2 key from the selected SQL placement when writable.
    pub object_key: Option<String>,
    /// Whether an identical ticket already completed and needs no new PUT.
    pub completed: bool,
}

/// Evidence echoed after the Worker has attempted its R2 PUT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridCacheUploadCompletionRequest {
    /// Declared object size retained by the Worker.
    pub size: u64,
    /// Lowercase SHA-256 computed over the client body.
    pub sha256: String,
}

/// Native's frozen admission for one OCI chunk written beside deployment R2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridOciChunkAdmission {
    /// Upload row version that the chunk completion must compare and advance.
    pub upload_resource_version: i64,
    /// Current contiguous byte count before this chunk.
    pub offset: u64,
    /// Zero-based ordinal assigned to this attempt.
    pub ordinal: u32,
    /// Largest body the Worker may accept for this attempt.
    pub maximum_chunk_bytes: u64,
    /// Exact staging placement selected by Native.
    pub placement_id: i64,
    /// Frozen staging placement revision.
    pub placement_resource_version: i64,
    /// Storage binding used by the selected placement.
    pub binding_id: i64,
    /// Immutable binding write revision for this chunk.
    pub binding_write_revision: i64,
    /// Placement prefix in the deployment R2 bucket.
    pub placement_prefix: String,
    /// Attempt-unique path relative to the staging placement.
    pub staging_object_key: String,
    /// Portable SHA-256 state before the Worker reads the chunk.
    pub sha256_state: crate::db::OciSha256State,
}

/// Worker evidence for completing one admitted OCI chunk in Native SQL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridOciChunkCompletionRequest {
    /// Admission returned for this exact upload attempt.
    pub admission: HybridOciChunkAdmission,
    /// Number of client bytes written to the staging object.
    pub byte_size: u64,
    /// Lowercase SHA-256 of this chunk's bytes.
    pub chunk_sha256: String,
    /// Resumable SHA-256 state after these bytes.
    pub next_sha256_state: crate::db::OciSha256State,
}

/// One SQL-fenced R2 destination for a declared publication object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridPublicationUploadPlacement {
    /// Required placement identity.
    pub placement_id: i64,
    /// Frozen placement resource version.
    pub placement_resource_version: i64,
    /// Selected deployment R2 binding identity.
    pub binding_id: i64,
    /// Frozen binding resource version.
    pub binding_resource_version: i64,
    /// Full object key in the deployment R2 bucket.
    pub object_key: String,
    /// Companion pack key for a Git pack index, when required.
    pub companion_pack_key: Option<String>,
}

/// Native's authorized destinations and expected identity for one Worker PUT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridPublicationUploadAdmission {
    /// Surface-relative path from the frozen publication manifest.
    pub path: String,
    /// Exact expected byte size from the frozen manifest.
    pub size: i64,
    /// Exact expected lowercase SHA-256 from the frozen manifest.
    pub sha256: String,
    /// Every required R2 placement to write and verify.
    pub placements: Vec<HybridPublicationUploadPlacement>,
}

/// Evidence returned after the Worker has attempted every admitted R2 PUT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridPublicationUploadCompletionRequest {
    /// Exact number of bytes retained by the Worker.
    pub size: u64,
    /// SHA-256 computed over the client body.
    pub sha256: String,
    /// Complete admitted placement identities, echoed for Native revalidation.
    pub placements: Vec<HybridPublicationUploadPlacement>,
}

/// Verification failures for a hybrid ingress assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HybridIngressError {
    /// The service credential is too short for a production HMAC key.
    #[error("hybrid ingress key must contain at least 32 bytes")]
    WeakKey,
    /// The compact assertion or its fields are malformed.
    #[error("hybrid ingress assertion is malformed")]
    Malformed,
    /// The signature does not authenticate the payload.
    #[error("hybrid ingress signature is invalid")]
    InvalidSignature,
    /// The assertion is expired, premature, or excessively long-lived.
    #[error("hybrid ingress assertion is outside its validity window")]
    InvalidTime,
    /// The assertion names a different deployment or HTTP request.
    #[error("hybrid ingress assertion does not match the request")]
    RequestMismatch,
}

/// Signs and verifies requests from one configured hybrid ingress trust domain.
#[derive(Clone)]
pub struct HybridIngressKey {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for HybridIngressKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HybridIngressKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl HybridIngressKey {
    /// Creates a signer and verifier from one deployment secret.
    ///
    /// # Errors
    ///
    /// Returns an error when the secret contains fewer than 32 bytes.
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, HybridIngressError> {
        let bytes = bytes.as_ref();
        if bytes.len() < 32 {
            return Err(HybridIngressError::WeakKey);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Signs one fully populated request assertion.
    ///
    /// # Errors
    ///
    /// Returns an error if the assertion is malformed or cannot be encoded.
    pub fn sign(&self, assertion: &HybridIngressAssertion) -> Result<String, HybridIngressError> {
        validate_assertion(assertion)?;
        let payload = serde_json::to_vec(assertion).map_err(|_| HybridIngressError::Malformed)?;
        let payload_text = URL_SAFE_NO_PAD.encode(payload);
        let mut mac =
            HmacSha256::new_from_slice(&self.bytes).map_err(|_| HybridIngressError::WeakKey)?;
        mac.update(payload_text.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{payload_text}.{signature}"))
    }

    /// Verifies a signed assertion against the received origin request.
    ///
    /// `path_and_query` is the raw URI component received by Native, and
    /// `body` is the exact bounded body that will enter its router.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, unauthenticated, stale, or mismatched
    /// assertions.
    pub fn verify(
        &self,
        compact: &str,
        deployment_id: &str,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        now: i64,
    ) -> Result<HybridIngressAssertion, HybridIngressError> {
        let (payload_text, signature_text) = compact
            .split_once('.')
            .filter(|(_, signature)| !signature.contains('.'))
            .ok_or(HybridIngressError::Malformed)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_text)
            .map_err(|_| HybridIngressError::Malformed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_text)
            .map_err(|_| HybridIngressError::Malformed)?;
        if URL_SAFE_NO_PAD.encode(&payload) != payload_text
            || URL_SAFE_NO_PAD.encode(&signature) != signature_text
            || signature.len() != 32
        {
            return Err(HybridIngressError::Malformed);
        }

        let mut mac =
            HmacSha256::new_from_slice(&self.bytes).map_err(|_| HybridIngressError::WeakKey)?;
        mac.update(payload_text.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| HybridIngressError::InvalidSignature)?;

        let assertion: HybridIngressAssertion =
            serde_json::from_slice(&payload).map_err(|_| HybridIngressError::Malformed)?;
        validate_assertion(&assertion)?;
        if assertion.issued_at > now.saturating_add(FUTURE_SKEW_SECONDS)
            || assertion.expires_at < now
            || assertion.expires_at < assertion.issued_at
            || assertion.expires_at.saturating_sub(assertion.issued_at) > MAX_LIFETIME_SECONDS
        {
            return Err(HybridIngressError::InvalidTime);
        }
        if assertion.deployment_id != deployment_id
            || assertion.method != method
            || assertion.path_and_query != path_and_query
            || assertion.body_sha256 != hex::encode(Sha256::digest(body))
        {
            return Err(HybridIngressError::RequestMismatch);
        }
        Ok(assertion)
    }

    /// Signs one Native-authorized R2 delivery for the verified ingress request.
    ///
    /// # Errors
    ///
    /// Returns an error if the target is malformed or cannot be encoded.
    pub fn sign_delivery(
        &self,
        assertion: &HybridIngressAssertion,
        target: HybridDeliveryTarget,
    ) -> Result<String, HybridIngressError> {
        validate_assertion(assertion)?;
        if !matches!(assertion.method.as_str(), "GET" | "HEAD") {
            return Err(HybridIngressError::RequestMismatch);
        }
        validate_delivery_target(&target)?;
        let grant = HybridDeliveryGrant {
            version: 1,
            deployment_id: assertion.deployment_id.clone(),
            request_id: assertion.request_id.clone(),
            expires_at: assertion.expires_at,
            target,
        };
        let payload = serde_json::to_vec(&grant).map_err(|_| HybridIngressError::Malformed)?;
        let payload_text = URL_SAFE_NO_PAD.encode(payload);
        let mut mac =
            HmacSha256::new_from_slice(&self.bytes).map_err(|_| HybridIngressError::WeakKey)?;
        mac.update(b"aos-hybrid-delivery-v1\0");
        mac.update(payload_text.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{payload_text}.{signature}"))
    }

    /// Verifies a Native delivery grant against this exact Worker request.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, forged, expired, or mismatched grants.
    pub fn verify_delivery(
        &self,
        compact: &str,
        assertion: &HybridIngressAssertion,
        now: i64,
    ) -> Result<HybridDeliveryTarget, HybridIngressError> {
        if !matches!(assertion.method.as_str(), "GET" | "HEAD") {
            return Err(HybridIngressError::RequestMismatch);
        }
        let (payload_text, signature_text) = compact
            .split_once('.')
            .filter(|(_, signature)| !signature.contains('.'))
            .ok_or(HybridIngressError::Malformed)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_text)
            .map_err(|_| HybridIngressError::Malformed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_text)
            .map_err(|_| HybridIngressError::Malformed)?;
        if URL_SAFE_NO_PAD.encode(&payload) != payload_text
            || URL_SAFE_NO_PAD.encode(&signature) != signature_text
            || signature.len() != 32
            || payload.len() > 4096
        {
            return Err(HybridIngressError::Malformed);
        }
        let mut mac =
            HmacSha256::new_from_slice(&self.bytes).map_err(|_| HybridIngressError::WeakKey)?;
        mac.update(b"aos-hybrid-delivery-v1\0");
        mac.update(payload_text.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| HybridIngressError::InvalidSignature)?;

        let grant: HybridDeliveryGrant =
            serde_json::from_slice(&payload).map_err(|_| HybridIngressError::Malformed)?;
        validate_delivery_target(&grant.target)?;
        if grant.version != 1
            || grant.deployment_id != assertion.deployment_id
            || grant.request_id != assertion.request_id
        {
            return Err(HybridIngressError::RequestMismatch);
        }
        if grant.expires_at != assertion.expires_at || grant.expires_at < now {
            return Err(HybridIngressError::InvalidTime);
        }
        Ok(grant.target)
    }
}

fn validate_delivery_target(target: &HybridDeliveryTarget) -> Result<(), HybridIngressError> {
    if target.object_key.is_empty()
        || target.object_key.len() > 2048
        || target.object_key.starts_with('/')
        || target
            .object_key
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || target
            .object_key
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || crate::surface_write::strong_if_match_etag(&target.object_etag).is_err()
        || target.content_type.is_empty()
        || target.content_type.len() > 256
        || target.cache_control.is_empty()
        || target.cache_control.len() > 256
        || target
            .content_type
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || target
            .cache_control
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(HybridIngressError::Malformed);
    }
    if let Some(planned) = &target.planned_response {
        let length = planned
            .end
            .checked_sub(planned.start)
            .and_then(|n| n.checked_add(1));
        let valid_range = planned.start <= planned.end
            && planned.end < target.object_size
            && length.is_some_and(|length| {
                planned.headers.get("content-length") == Some(&length.to_string())
            });
        let valid_status = match planned.status {
            200 => {
                planned.start == 0
                    && planned.end.checked_add(1) == Some(target.object_size)
                    && !planned.headers.contains_key("content-range")
            }
            206 => {
                planned.headers.get("content-range")
                    == Some(&format!(
                        "bytes {}-{}/{}",
                        planned.start, planned.end, target.object_size
                    ))
            }
            _ => false,
        };
        let valid_headers = planned.headers.len() <= 12
            && planned.headers.get("content-type") == Some(&target.content_type)
            && planned.headers.get("cache-control") == Some(&target.cache_control)
            && planned
                .headers
                .get("accept-ranges")
                .is_some_and(|value| value == "bytes")
            && planned.headers.iter().all(|(name, value)| {
                matches!(
                    name.as_str(),
                    "accept-ranges"
                        | "cache-control"
                        | "content-type"
                        | "content-disposition"
                        | "content-length"
                        | "content-range"
                        | "docker-content-digest"
                        | "docker-distribution-api-version"
                        | "etag"
                        | "repr-digest"
                        | "vary"
                        | "x-aos-sha256"
                        | "x-content-type-options"
                ) && value.len() <= 512
                    && !value.bytes().any(|byte| byte.is_ascii_control())
            });
        if target.producer_document || !valid_range || !valid_status || !valid_headers {
            return Err(HybridIngressError::Malformed);
        }
    }
    Ok(())
}

fn validate_assertion(assertion: &HybridIngressAssertion) -> Result<(), HybridIngressError> {
    if assertion.version != 1
        || assertion.deployment_id.is_empty()
        || assertion.deployment_id.len() > 128
        || assertion.request_id.is_empty()
        || assertion.request_id.len() > 128
        || assertion.scheme != "https"
        || assertion.method.is_empty()
        || assertion.method.len() > 16
        || !assertion
            .method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
        || !assertion.path_and_query.starts_with('/')
        || assertion.path_and_query.len() > 8192
        || assertion.body_sha256.len() != 64
        || !assertion
            .body_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || assertion.client_ip.parse::<IpAddr>().is_err()
        || assertion.authority.contains('@')
        || assertion
            .authority
            .parse::<axum::http::uri::Authority>()
            .is_err()
    {
        return Err(HybridIngressError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assertion() -> HybridIngressAssertion {
        HybridIngressAssertion {
            version: 1,
            deployment_id: "deployment-1".into(),
            issued_at: 100,
            expires_at: 130,
            request_id: "request-1".into(),
            scheme: "https".into(),
            authority: "hub.example.test".into(),
            method: "POST".into(),
            path_and_query: "/aos.hub.v1.RegistryService/List?view=all".into(),
            body_sha256: hex::encode(Sha256::digest(b"body")),
            client_ip: "192.0.2.4".into(),
        }
    }

    #[test]
    fn request_context_is_bound_to_method_path_body_and_deployment() {
        let key = HybridIngressKey::new([7; 32]).unwrap();
        let signed = key.sign(&assertion()).unwrap();
        assert_eq!(
            key.verify(
                &signed,
                "deployment-1",
                "POST",
                "/aos.hub.v1.RegistryService/List?view=all",
                b"body",
                110,
            )
            .unwrap(),
            assertion()
        );
        assert_eq!(
            key.verify(&signed, "deployment-1", "GET", "/", b"body", 110),
            Err(HybridIngressError::RequestMismatch)
        );
        assert_eq!(
            key.verify(
                &signed,
                "deployment-1",
                "POST",
                "/aos.hub.v1.RegistryService/List?view=all",
                b"other",
                110,
            ),
            Err(HybridIngressError::RequestMismatch)
        );
        assert_eq!(
            key.verify(
                &signed,
                "deployment-2",
                "POST",
                "/aos.hub.v1.RegistryService/List?view=all",
                b"body",
                110,
            ),
            Err(HybridIngressError::RequestMismatch)
        );
        assert_eq!(
            key.verify(
                &signed,
                "deployment-1",
                "POST",
                "/aos.hub.v1.RegistryService/List?view=all",
                b"body",
                131,
            ),
            Err(HybridIngressError::InvalidTime)
        );
    }

    #[test]
    fn delivery_grant_is_bound_to_request_and_exact_object_version() {
        let key = HybridIngressKey::new([7; 32]).unwrap();
        let mut request = assertion();
        request.method = "GET".into();
        let target = HybridDeliveryTarget {
            object_key: "tenant/cache/nar/abc.nar.zst".into(),
            object_size: 42,
            object_etag: "\"r2-version\"".into(),
            content_type: "application/octet-stream".into(),
            cache_control: "public, max-age=31536000, immutable".into(),
            producer_document: false,
            planned_response: None,
        };

        let signed = key.sign_delivery(&request, target.clone()).unwrap();
        assert_eq!(key.verify_delivery(&signed, &request, 110), Ok(target));

        let mut other_request = request.clone();
        other_request.request_id = "request-2".into();
        assert_eq!(
            key.verify_delivery(&signed, &other_request, 110),
            Err(HybridIngressError::RequestMismatch)
        );
        assert_eq!(
            key.verify_delivery(&signed, &request, 131),
            Err(HybridIngressError::InvalidTime)
        );

        let mut forged = signed.into_bytes();
        forged[0] = if forged[0] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            key.verify_delivery(&String::from_utf8(forged).unwrap(), &request, 110),
            Err(HybridIngressError::InvalidSignature)
        );
    }

    #[test]
    fn delivery_grants_reject_escaped_keys_and_weak_versions() {
        let key = HybridIngressKey::new([7; 32]).unwrap();
        let mut request = assertion();
        request.method = "GET".into();
        let mut target = HybridDeliveryTarget {
            object_key: "tenant/cache/nar/abc.nar.zst".into(),
            object_size: 42,
            object_etag: "\"r2-version\"".into(),
            content_type: "application/octet-stream".into(),
            cache_control: "private, no-store".into(),
            producer_document: false,
            planned_response: None,
        };

        target.object_key = "tenant/../other/secret".into();
        assert_eq!(
            key.sign_delivery(&request, target.clone()),
            Err(HybridIngressError::Malformed)
        );
        target.object_key = "tenant/cache/nar/abc.nar.zst".into();
        target.object_etag = "W/\"weak\"".into();
        assert_eq!(
            key.sign_delivery(&request, target),
            Err(HybridIngressError::Malformed)
        );
    }

    #[test]
    fn signed_image_grant_binds_exact_range_and_safe_headers() {
        let key = HybridIngressKey::new([7; 32]).unwrap();
        let mut request = assertion();
        request.method = "GET".into();
        let headers = BTreeMap::from([
            ("accept-ranges".into(), "bytes".into()),
            ("cache-control".into(), "private, no-store".into()),
            ("content-length".into(), "4".into()),
            ("content-range".into(), "bytes 4-7/42".into()),
            ("content-type".into(), "application/octet-stream".into()),
        ]);
        let mut target = HybridDeliveryTarget {
            object_key: "tenant/images/sha256/a/object.img".into(),
            object_size: 42,
            object_etag: "\"r2-version\"".into(),
            content_type: "application/octet-stream".into(),
            cache_control: "private, no-store".into(),
            producer_document: false,
            planned_response: Some(HybridPlannedDelivery {
                status: 206,
                start: 4,
                end: 7,
                headers,
            }),
        };

        let signed = key.sign_delivery(&request, target.clone()).unwrap();
        assert_eq!(
            key.verify_delivery(&signed, &request, 110),
            Ok(target.clone())
        );

        let planned = target.planned_response.as_mut().unwrap();
        planned
            .headers
            .insert("set-cookie".into(), "session=forged".into());
        assert_eq!(
            key.sign_delivery(&request, target.clone()),
            Err(HybridIngressError::Malformed)
        );

        let planned = target.planned_response.as_mut().unwrap();
        planned.headers.remove("set-cookie");
        planned.status = 200;
        assert_eq!(
            key.sign_delivery(&request, target),
            Err(HybridIngressError::Malformed)
        );
    }

    #[test]
    fn oci_grant_preserves_distribution_headers_and_private_policy() {
        let key = HybridIngressKey::new([7; 32]).unwrap();
        let mut request = assertion();
        request.method = "GET".into();
        let digest = format!("sha256:{}", "a".repeat(64));
        let media_type = "application/vnd.oci.image.layer.v1.tar+gzip";
        let headers = BTreeMap::from([
            ("accept-ranges".into(), "bytes".into()),
            ("cache-control".into(), "private, no-store".into()),
            ("content-length".into(), "4".into()),
            ("content-range".into(), "bytes 4-7/42".into()),
            ("content-type".into(), media_type.into()),
            ("docker-content-digest".into(), digest.clone()),
            (
                "docker-distribution-api-version".into(),
                "registry/2.0".into(),
            ),
            ("etag".into(), format!("\"{digest}\"")),
            ("vary".into(), "Authorization".into()),
            ("x-content-type-options".into(), "nosniff".into()),
        ]);
        let target = HybridDeliveryTarget {
            object_key: "tenant/oci/blobs/sha256/a".into(),
            object_size: 42,
            object_etag: "\"r2-version\"".into(),
            content_type: media_type.into(),
            cache_control: "private, no-store".into(),
            producer_document: false,
            planned_response: Some(HybridPlannedDelivery {
                status: 206,
                start: 4,
                end: 7,
                headers,
            }),
        };

        let signed = key.sign_delivery(&request, target.clone()).unwrap();
        assert_eq!(key.verify_delivery(&signed, &request, 110), Ok(target));
    }
}
