//! Authenticated ingress assertions for delivery-route requests.
//!
//! A TLS terminator, VPN gateway, or external access provider can forward a
//! request to Hub while preserving the verified transport and access facts in
//! a short-lived HMAC assertion. Hub never trusts forwarding headers directly:
//! the assertion is bound to the exact method, authority, and path-and-query,
//! and its verification key is explicit deployment configuration.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::connect::{DeliveryAccessEvidence, DeliveryTransportEvidence};

/// HTTP header carrying the compact signed ingress assertion.
pub const DELIVERY_ATTESTATION_HEADER: &str = "x-aos-delivery-attestation";

/// Maximum accepted assertion lifetime.
const MAX_LIFETIME_SECONDS: i64 = 30;
/// Small allowance for clocks that are not perfectly synchronized.
const FUTURE_SKEW_SECONDS: i64 = 5;

type HmacSha256 = Hmac<Sha256>;

/// Returns the current Unix timestamp in the active runtime.
#[must_use]
pub fn delivery_attestation_now() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or_default()
    }
}

/// A verified transport assertion supplied by an upstream ingress adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryTransportAssertion {
    /// Actual client-facing scheme (`http` or `https`).
    pub scheme: String,
    /// Immutable endpoint ingress kind (`hub` or `layer7`).
    pub ingress_kind: String,
}

/// A verified access assertion supplied by an upstream ingress adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeliveryAccessAssertion {
    /// No private/external access assertion accompanies the request.
    None,
    /// The request arrived through one exact network-boundary revision.
    PrivateNetwork {
        /// Stable boundary identifier.
        boundary_id: String,
        /// Exact active boundary revision.
        boundary_revision: i64,
    },
    /// An external access provider authenticated the request.
    ExternalProvider {
        /// Closed provider implementation kind.
        provider_kind: String,
        /// Stable provider resource identifier.
        resource_id: String,
        /// Exact provider policy/configuration revision.
        revision: String,
    },
}

/// Versioned payload authenticated by an ingress adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryAttestation {
    /// Wire-format version. Version 1 is the only accepted version.
    pub version: u8,
    /// Unix timestamp at which the adapter issued the assertion.
    pub issued_at: i64,
    /// Unix timestamp after which Hub must reject the assertion.
    pub expires_at: i64,
    /// One-use unpredictable identifier, unique within the validity window.
    pub nonce: String,
    /// Exact delivery-route identity for which the adapter issued the assertion.
    pub route_id: String,
    /// Exact immutable route configuration digest.
    pub route_configuration_digest: String,
    /// Exact uppercase HTTP method.
    pub method: String,
    /// Exact request authority, including a non-default port.
    pub authority: String,
    /// Exact raw path and query string.
    pub path_and_query: String,
    /// Transport facts verified by the adapter.
    pub transport: DeliveryTransportAssertion,
    /// Optional private-network or external-provider fact.
    pub access: DeliveryAccessAssertion,
}

/// Verification failures for an ingress assertion.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeliveryAttestationError {
    /// The configured verifier key is too short for a production HMAC key.
    #[error("delivery attestation key must contain at least 32 bytes")]
    WeakKey,
    /// The compact assertion or its JSON payload is malformed.
    #[error("delivery attestation is malformed")]
    Malformed,
    /// The HMAC does not authenticate the payload.
    #[error("delivery attestation signature is invalid")]
    InvalidSignature,
    /// The assertion is expired, premature, or has an excessive lifetime.
    #[error("delivery attestation is outside its validity window")]
    InvalidTime,
    /// The assertion is not bound to this exact HTTP request.
    #[error("delivery attestation does not match the request")]
    RequestMismatch,
    /// The assertion contains an unsupported transport or access shape.
    #[error("delivery attestation contains unsupported evidence")]
    InvalidEvidence,
}

/// Verifies short-lived HMAC assertions from one configured ingress trust domain.
#[derive(Clone)]
pub struct DeliveryAttestationVerifier {
    key: Vec<u8>,
}

/// Cryptographically verified assertion awaiting durable replay admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeliveryAttestation {
    /// Transport facts authenticated by the ingress adapter.
    pub transport: DeliveryTransportEvidence,
    /// Access facts authenticated by the ingress adapter.
    pub access: DeliveryAccessEvidence,
    /// Exact route identity sealed into the assertion.
    pub route_id: String,
    /// Exact immutable route configuration digest sealed into the assertion.
    pub route_configuration_digest: String,
    /// SHA-256 digest of the one-use nonce; the nonce itself is never persisted.
    pub nonce_digest: String,
    /// Assertion expiry used to bound durable replay state.
    pub expires_at: i64,
}

impl std::fmt::Debug for DeliveryAttestationVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeliveryAttestationVerifier")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl DeliveryAttestationVerifier {
    /// Creates a verifier from an explicit deployment secret.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryAttestationError::WeakKey`] when `key` contains fewer
    /// than 32 bytes.
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, DeliveryAttestationError> {
        let key = key.as_ref();
        if key.len() < 32 {
            return Err(DeliveryAttestationError::WeakKey);
        }
        Ok(Self { key: key.to_vec() })
    }

    /// Verifies and decodes one compact `base64url(payload).base64url(mac)` value.
    ///
    /// The signature is checked before JSON decoding. The payload must match
    /// the exact request method, authority, and path-and-query.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed input, an invalid signature or time
    /// window, a request mismatch, or unsupported evidence.
    pub fn verify(
        &self,
        compact: &str,
        method: &str,
        authority: &str,
        path_and_query: &str,
        now: i64,
    ) -> Result<VerifiedDeliveryAttestation, DeliveryAttestationError> {
        let (payload_text, signature_text) = compact
            .split_once('.')
            .filter(|(_, signature)| !signature.contains('.'))
            .ok_or(DeliveryAttestationError::Malformed)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_text)
            .map_err(|_| DeliveryAttestationError::Malformed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_text)
            .map_err(|_| DeliveryAttestationError::Malformed)?;
        if URL_SAFE_NO_PAD.encode(&payload) != payload_text
            || URL_SAFE_NO_PAD.encode(&signature) != signature_text
            || signature.len() != 32
        {
            return Err(DeliveryAttestationError::Malformed);
        }
        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|_| DeliveryAttestationError::WeakKey)?;
        mac.update(payload_text.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| DeliveryAttestationError::InvalidSignature)?;
        let assertion: DeliveryAttestation =
            serde_json::from_slice(&payload).map_err(|_| DeliveryAttestationError::Malformed)?;
        if assertion.version != 1
            || assertion.issued_at > now + FUTURE_SKEW_SECONDS
            || assertion.expires_at < now
            || assertion.expires_at < assertion.issued_at
            || assertion.expires_at - assertion.issued_at > MAX_LIFETIME_SECONDS
        {
            return Err(DeliveryAttestationError::InvalidTime);
        }
        if assertion.method != method
            || assertion.authority != authority
            || assertion.path_and_query != path_and_query
        {
            return Err(DeliveryAttestationError::RequestMismatch);
        }
        if !matches!(assertion.transport.scheme.as_str(), "http" | "https")
            || !matches!(assertion.transport.ingress_kind.as_str(), "hub" | "layer7")
            || assertion.nonce.len() < 16
            || assertion.nonce.len() > 128
            || !assertion
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || assertion.route_id.is_empty()
            || assertion.route_configuration_digest.len() != 64
            || !assertion
                .route_configuration_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(DeliveryAttestationError::InvalidEvidence);
        }
        let tls_identity = if assertion.transport.scheme == "https" {
            Some(super::connect::attested_authority_host(authority)?)
        } else {
            None
        };
        let transport = DeliveryTransportEvidence {
            scheme: assertion.transport.scheme,
            ingress_kind: assertion.transport.ingress_kind,
            tls_identity,
        };
        let access = match assertion.access {
            DeliveryAccessAssertion::None => DeliveryAccessEvidence {
                boundary: None,
                external_provider: None,
            },
            DeliveryAccessAssertion::PrivateNetwork {
                boundary_id,
                boundary_revision,
            } if !boundary_id.is_empty() && boundary_revision > 0 => DeliveryAccessEvidence {
                boundary: Some((boundary_id, boundary_revision)),
                external_provider: None,
            },
            DeliveryAccessAssertion::ExternalProvider {
                provider_kind,
                resource_id,
                revision,
            } if !provider_kind.is_empty() && !resource_id.is_empty() && !revision.is_empty() => {
                DeliveryAccessEvidence {
                    boundary: None,
                    external_provider: Some((provider_kind, resource_id, revision)),
                }
            }
            _ => return Err(DeliveryAttestationError::InvalidEvidence),
        };
        Ok(VerifiedDeliveryAttestation {
            transport,
            access,
            route_id: assertion.route_id,
            route_configuration_digest: assertion.route_configuration_digest,
            nonce_digest: hex::encode(Sha256::digest(assertion.nonce.as_bytes())),
            expires_at: assertion.expires_at,
        })
    }

    #[cfg(test)]
    fn sign(&self, assertion: &DeliveryAttestation) -> String {
        let payload = serde_json::to_vec(assertion).unwrap();
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let mut mac = HmacSha256::new_from_slice(&self.key).unwrap();
        mac.update(payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{payload}.{signature}")
    }
}

impl From<()> for DeliveryAttestationError {
    fn from((): ()) -> Self {
        Self::InvalidEvidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assertion() -> DeliveryAttestation {
        DeliveryAttestation {
            version: 1,
            issued_at: 100,
            expires_at: 130,
            nonce: "0123456789abcdef".into(),
            route_id: "route-1".into(),
            route_configuration_digest:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            method: "GET".into(),
            authority: "cache.example:8443".into(),
            path_and_query: "/nar/abc?download=1".into(),
            transport: DeliveryTransportAssertion {
                scheme: "https".into(),
                ingress_kind: "layer7".into(),
            },
            access: DeliveryAccessAssertion::PrivateNetwork {
                boundary_id: "boundary-1".into(),
                boundary_revision: 7,
            },
        }
    }

    #[test]
    fn verifies_exact_request_and_typed_evidence() {
        let verifier = DeliveryAttestationVerifier::new([7_u8; 32]).unwrap();
        let compact = verifier.sign(&assertion());
        let verified = verifier
            .verify(
                &compact,
                "GET",
                "cache.example:8443",
                "/nar/abc?download=1",
                115,
            )
            .unwrap();
        assert_eq!(verified.transport.scheme, "https");
        assert_eq!(verified.transport.ingress_kind, "layer7");
        assert_eq!(verified.access.boundary, Some(("boundary-1".into(), 7)));
    }

    #[test]
    fn rejects_spoofed_unsigned_and_rebound_assertions() {
        let verifier = DeliveryAttestationVerifier::new([7_u8; 32]).unwrap();
        let compact = verifier.sign(&assertion());
        for (method, authority, path_and_query) in [
            ("POST", "cache.example:8443", "/nar/abc?download=1"),
            ("GET", "evil.example:8443", "/nar/abc?download=1"),
            ("GET", "cache.example:8443", "/nar/other?download=1"),
            ("GET", "cache.example:8443", "/nar/abc?download=0"),
        ] {
            assert_eq!(
                verifier.verify(&compact, method, authority, path_and_query, 115),
                Err(DeliveryAttestationError::RequestMismatch)
            );
        }
        let mut bytes = compact.clone().into_bytes();
        if let Some(last) = bytes.last_mut() {
            *last = if *last == b'A' { b'B' } else { b'A' };
        }
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(matches!(
            verifier.verify(
                &tampered,
                "GET",
                "cache.example:8443",
                "/nar/abc?download=1",
                115,
            ),
            Err(DeliveryAttestationError::InvalidSignature)
                | Err(DeliveryAttestationError::Malformed)
        ));
        assert_eq!(
            verifier.verify(
                &format!("{compact}="),
                "GET",
                "cache.example:8443",
                "/nar/abc?download=1",
                115,
            ),
            Err(DeliveryAttestationError::Malformed)
        );
    }

    #[test]
    fn rejects_stale_and_overlong_assertions() {
        let verifier = DeliveryAttestationVerifier::new([7_u8; 32]).unwrap();
        let compact = verifier.sign(&assertion());
        assert_eq!(
            verifier.verify(
                &compact,
                "GET",
                "cache.example:8443",
                "/nar/abc?download=1",
                131,
            ),
            Err(DeliveryAttestationError::InvalidTime)
        );
    }

    #[test]
    fn seals_the_exact_route_configuration_revision() {
        let verifier = DeliveryAttestationVerifier::new([7_u8; 32]).unwrap();
        let compact = verifier.sign(&assertion());
        let verified = verifier
            .verify(
                &compact,
                "GET",
                "cache.example:8443",
                "/nar/abc?download=1",
                115,
            )
            .unwrap();
        assert_eq!(verified.route_id, "route-1");
        assert_eq!(
            verified.route_configuration_digest,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_ne!(
            verified.route_configuration_digest,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }
}
