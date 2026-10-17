//! Purpose-separated callback headers and authority deadlines for hardened Worker egress.
//!
//! Legacy v3 requests retain their original encoding. This independent profile
//! authenticates every additional callback header, the full physical deadline and
//! compact response facts; a v3 signature cannot authorize these effects.

use anyhow::{ensure, Result};
use aos_assessment::time::Timestamp;

use super::{RequestEvidence, ResponseEvidence};

/// Names the independent notification-only gateway request and response profile.
pub const CONTRACT: &str = "aos-hardened-egress-assessment-notification-v1";

/// Signs an installer challenge proving support for the callback-only gateway contract.
///
/// # Errors
/// Returns an error for malformed challenges or weak gateway keys.
pub fn sign_challenge(key: &[u8], evidence: &super::ChallengeEvidence<'_>) -> Result<String> {
    sign_capability(key, evidence, b"aos-notification-egress-challenge-v1\0")
}

/// Verifies a callback readiness challenge independently of legacy gateway authority.
///
/// # Errors
/// Returns an error for malformed challenges, wrong MAC or another purpose domain.
pub fn verify_challenge(
    key: &[u8],
    evidence: &super::ChallengeEvidence<'_>,
    signature: &str,
) -> Result<()> {
    super::verify_encoded(&sign_challenge(key, evidence)?, signature)
}

/// Signs the callback gateway's authenticated readiness response.
///
/// # Errors
/// Returns an error for malformed challenges or weak gateway keys.
pub fn sign_challenge_response(
    key: &[u8],
    evidence: &super::ChallengeEvidence<'_>,
) -> Result<String> {
    sign_capability(
        key,
        evidence,
        b"aos-notification-egress-challenge-response-v1\0",
    )
}

/// Verifies that a paired gateway implements the callback-only contract.
///
/// # Errors
/// Returns an error for altered challenges, wrong MAC or legacy capability substitution.
pub fn verify_challenge_response(
    key: &[u8],
    evidence: &super::ChallengeEvidence<'_>,
    signature: &str,
) -> Result<()> {
    super::verify_encoded(&sign_challenge_response(key, evidence)?, signature)
}

fn sign_capability(
    key: &[u8],
    evidence: &super::ChallengeEvidence<'_>,
    domain: &[u8],
) -> Result<String> {
    super::validate_key(key)?;
    super::validate_challenge(evidence)?;
    super::sign(key, domain, |message| {
        super::push_i64(message, evidence.timestamp);
        super::push_field(message, evidence.nonce);
    })
}

/// Authenticates exactly one timestamp-bound callback POST and its full authority window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationRequestEvidence<'a> {
    /// Original URL, body digest, closed callback headers and gateway replay identity.
    pub request: RequestEvidence<'a>,
    /// Exact shared callback signing profile.
    pub signature_version: &'a str,
    /// Immutable key version selected by independently installed callback custody.
    pub key_version: &'a str,
    /// Original signed physical-attempt timestamp in the shared UTC timestamp format.
    pub callback_timestamp: &'a str,
    /// Exclusive physical authority deadline, never more than 60 seconds after admission.
    pub deadline: u64,
    /// Fresh coordinator time from the exact verified current-effect grant.
    pub effect_checked_at: u64,
    /// Exclusive latest dispatch time from that grant, at most five seconds later.
    pub effect_dispatch_by: u64,
}

/// Authenticates accepted response headers without retaining any callback response body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationResponseEvidence<'a> {
    /// Exact request nonce, connected public peer, unchanged target URL and actual status.
    pub response: ResponseEvidence<'a>,
    /// Numeric upstream retry minimum, bounded to at most 3,600 seconds.
    pub retry_after_seconds: Option<u32>,
}

impl NotificationRequestEvidence<'_> {
    /// Checks closed callback metadata and authority through the complete 15-second timeout.
    ///
    /// # Errors
    /// Returns an error for unrelated methods/headers, malformed timestamps or expired deadlines.
    pub fn validate_at(&self, now: u64) -> Result<()> {
        super::validate_request(&self.request)?;
        let timestamp = Timestamp::parse(self.callback_timestamp)?.unix_seconds();
        let gateway_time = u64::try_from(self.request.timestamp)?;
        ensure!(
            self.request.method == "POST"
                && self.request.content_type == Some("application/json")
                && self.request.range.is_none()
                && self.request.if_match.is_none()
                && self.request.authorization.is_none()
                && self.request.webhook_event == Some("assessment.notification")
                && self.signature_version == "aos.notification-signature/hmac-sha256-v1",
            "notification egress requires its exact closed callback profile"
        );
        ensure!(
            !self.key_version.is_empty()
                && self.key_version.len() <= 128
                && !self.key_version.chars().any(char::is_control),
            "notification egress key version is invalid"
        );
        ensure!(
            timestamp <= gateway_time
                && self.effect_checked_at <= gateway_time
                && gateway_time <= now
                && now < self.effect_dispatch_by
                && self.effect_dispatch_by <= self.effect_checked_at.saturating_add(5)
                && now.saturating_add(15) <= self.deadline
                && self.deadline <= timestamp.saturating_add(60),
            "notification egress authority does not cover its full timeout"
        );
        crate::secret_version::validate_secret_version_ref(self.key_version)?;
        crate::url_guard::is_safe_remote_url(self.request.target_url)?;
        ensure!(
            self.request.target_url.len() <= 2048,
            "notification egress destination exceeds its registered URL bound"
        );
        let url = url::Url::parse(self.request.target_url)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "notification egress requires registered HTTPS without userinfo or fragments"
        );
        Ok(())
    }
}

/// Signs an exact callback envelope in its independent gateway purpose domain.
///
/// # Errors
/// Returns an error for a weak gateway key or malformed/expired callback authority.
pub fn sign_request(key: &[u8], evidence: &NotificationRequestEvidence<'_>) -> Result<String> {
    super::validate_key(key)?;
    evidence.validate_at(u64::try_from(evidence.request.timestamp)?)?;
    super::sign_encoded(key, &encode_request(evidence))
}

/// Returns the exact commitment held by durable gateway replay admission.
///
/// # Errors
/// Returns an error for invalid callback metadata or authority deadlines.
pub fn request_digest(evidence: &NotificationRequestEvidence<'_>) -> Result<String> {
    evidence.validate_at(u64::try_from(evidence.request.timestamp)?)?;
    Ok(super::body_sha256(&encode_request(evidence)))
}

/// Verifies callback metadata before resolving DNS or admitting a gateway nonce.
///
/// # Errors
/// Returns an error for the wrong purpose/MAC, invalid metadata or malformed signatures.
pub fn verify_request(
    key: &[u8],
    evidence: &NotificationRequestEvidence<'_>,
    signature: &str,
) -> Result<()> {
    let expected = sign_request(key, evidence)?;
    super::verify_encoded(&expected, signature)
}

/// Signs compact callback transport facts in the independent response purpose domain.
///
/// # Errors
/// Returns an error for a weak key, invalid peer facts or an unbounded retry minimum.
pub fn sign_response(key: &[u8], evidence: &NotificationResponseEvidence<'_>) -> Result<String> {
    super::validate_key(key)?;
    super::validate_response(&evidence.response)?;
    ensure!(
        evidence
            .retry_after_seconds
            .is_none_or(|seconds| seconds <= 3600),
        "notification response retry minimum exceeds its bound"
    );
    super::sign(
        key,
        b"aos-hardened-egress-notification-response-v1\0",
        |message| {
            super::push_i64(message, evidence.response.timestamp);
            super::push_field(message, evidence.response.nonce);
            super::push_field(message, evidence.response.final_url);
            super::push_field(message, evidence.response.peer_ip);
            message.extend_from_slice(&evidence.response.status.to_be_bytes());
            match evidence.retry_after_seconds {
                Some(seconds) => {
                    message.push(1);
                    message.extend_from_slice(&seconds.to_be_bytes());
                }
                None => message.push(0),
            }
        },
    )
}

/// Verifies compact callback facts before classifying an upstream HTTP outcome.
///
/// # Errors
/// Returns an error for invalid facts, altered retry minimum or an unrelated signature.
pub fn verify_response(
    key: &[u8],
    evidence: &NotificationResponseEvidence<'_>,
    signature: &str,
) -> Result<()> {
    let expected = sign_response(key, evidence)?;
    super::verify_encoded(&expected, signature)
}

fn encode_request(evidence: &NotificationRequestEvidence<'_>) -> Vec<u8> {
    let mut message = b"aos-hardened-egress-notification-request-v1\0".to_vec();
    let original = super::encode_request(&evidence.request);
    message.extend_from_slice(&(original.len() as u64).to_be_bytes());
    message.extend_from_slice(&original);
    super::push_field(&mut message, evidence.signature_version);
    super::push_field(&mut message, evidence.key_version);
    super::push_field(&mut message, evidence.callback_timestamp);
    message.extend_from_slice(&evidence.deadline.to_be_bytes());
    message.extend_from_slice(&evidence.effect_checked_at.to_be_bytes());
    message.extend_from_slice(&evidence.effect_dispatch_by.to_be_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> NotificationRequestEvidence<'static> {
        NotificationRequestEvidence {
            request: RequestEvidence {
                timestamp: 1000,
                nonce: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
                target_url: "https://receiver.example/callback",
                method: "POST",
                body_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                content_type: Some("application/json"),
                range: None,
                if_match: None,
                authorization: None,
                webhook_event: Some("assessment.notification"),
                webhook_signature: Some(
                    "sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
                webhook_delivery_id: Some("delivery_1"),
            },
            signature_version: "aos.notification-signature/hmac-sha256-v1",
            key_version: "worker://assessment/notification/v1",
            callback_timestamp: "1970-01-01T00:16:40Z",
            deadline: 1060,
            effect_checked_at: 1000,
            effect_dispatch_by: 1005,
        }
    }

    #[test]
    fn callback_headers_deadlines_and_legacy_domains_cannot_substitute() {
        let key = [7; 32];
        let evidence = fixture();
        let signature = sign_request(&key, &evidence).unwrap();
        verify_request(&key, &evidence, &signature).unwrap();
        let legacy = super::super::sign_request(&key, &evidence.request).unwrap();
        assert!(verify_request(&key, &evidence, &legacy).is_err());
        assert!(super::super::verify_request(&key, &evidence.request, &signature).is_err());
        let mut changed = evidence.clone();
        changed.key_version = "worker://assessment/notification/v2";
        assert!(verify_request(&key, &changed, &signature).is_err());
        changed = evidence.clone();
        changed.callback_timestamp = "1970-01-01T00:16:39Z";
        changed.deadline = 1059;
        assert!(verify_request(&key, &changed, &signature).is_err());
        changed = evidence.clone();
        changed.effect_checked_at = 999;
        assert!(verify_request(&key, &changed, &signature).is_err());
        changed = evidence.clone();
        changed.effect_dispatch_by = 1004;
        assert!(verify_request(&key, &changed, &signature).is_err());
        changed = evidence.clone();
        changed.deadline = 1059;
        assert!(verify_request(&key, &changed, &signature).is_err());
        changed = evidence;
        changed.request.target_url = "https://other.example/callback";
        assert!(verify_request(&key, &changed, &signature).is_err());
    }

    #[test]
    fn late_admission_and_unrelated_headers_cannot_authorize_a_callback() {
        let evidence = fixture();
        evidence.validate_at(1004).unwrap();
        assert!(evidence.validate_at(1005).is_err());
        let mut short = evidence.clone();
        short.request.timestamp = 1046;
        short.effect_checked_at = 1046;
        short.effect_dispatch_by = 1051;
        assert!(short.validate_at(1046).is_err());
        assert!(evidence.validate_at(999).is_err());
        let mut changed = evidence.clone();
        changed.request.authorization = Some("Bearer unrelated");
        assert!(sign_request(&[7; 32], &changed).is_err());
        changed = evidence;
        changed.request.webhook_event = Some("release.published");
        assert!(sign_request(&[7; 32], &changed).is_err());
    }

    #[test]
    fn retry_status_and_connected_peer_facts_are_authenticated_together() {
        let key = [7; 32];
        let evidence = NotificationResponseEvidence {
            response: ResponseEvidence {
                timestamp: 1010,
                nonce: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
                final_url: "https://receiver.example/callback",
                peer_ip: "8.8.8.8",
                status: 429,
            },
            retry_after_seconds: Some(30),
        };
        let signature = sign_response(&key, &evidence).unwrap();
        verify_response(&key, &evidence, &signature).unwrap();
        let mut changed = evidence.clone();
        changed.retry_after_seconds = Some(31);
        assert!(verify_response(&key, &changed, &signature).is_err());
        changed = evidence.clone();
        changed.response.status = 204;
        assert!(verify_response(&key, &changed, &signature).is_err());
        let legacy = super::super::sign_response(&key, &evidence.response).unwrap();
        assert!(verify_response(&key, &evidence, &legacy).is_err());
        changed = evidence;
        changed.retry_after_seconds = Some(3601);
        assert!(sign_response(&key, &changed).is_err());
    }

    #[test]
    fn callback_readiness_cannot_use_legacy_or_request_signatures() {
        let key = [7; 32];
        let evidence = super::super::ChallengeEvidence {
            timestamp: 1000,
            nonce: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
        };
        let request = sign_challenge(&key, &evidence).unwrap();
        verify_challenge(&key, &evidence, &request).unwrap();
        assert!(verify_challenge_response(&key, &evidence, &request).is_err());
        let legacy = super::super::sign_challenge_response(&key, &evidence).unwrap();
        assert!(verify_challenge_response(&key, &evidence, &legacy).is_err());
        let response = sign_challenge_response(&key, &evidence).unwrap();
        verify_challenge_response(&key, &evidence, &response).unwrap();
        assert!(super::super::verify_challenge_response(&key, &evidence, &response).is_err());
    }
}
