//! Closed controls for a separately compiled live-stream experiment.
//!
//! This purpose cannot authenticate production ingress or permit storage writes.
//! The controlled runner checks actual installed source, script and raw profile.
//!
//! ```text
//! control = {run_id, source, script, original ingress, fixture-only live target}
//! ```

pub mod query;

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{HybridIngressAssertion, HybridLiveDeliveryTarget};
use crate::storage_work::StorageWorkKey;

/// Reserved control endpoint compiled only into the controlled Worker runner.
pub const LIVE_CANDIDATE_PATH: &str = "/__hub/mirror-live-candidate";
/// Fixed controlled response ceiling; this is not hosted qualification.
pub const LIVE_CANDIDATE_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum metadata-only controlled request.
pub const LIVE_CANDIDATE_CONTROL_BYTES: usize = 16 * 1024;
const DOMAIN: &[u8] = b"aos.hub.mirror-live-controlled-candidate.v1\0";

/// Binds one fresh fixture-only stream to actual installed runtime pins.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorLiveCandidateRequest {
    /// Closed experiment control version.
    pub version: u8,
    /// Lowercase 32-hex experiment identity, also selecting the source namespace.
    pub run_id: String,
    /// Actual compiled source commitment selected by the controlled runner.
    pub compiled_source_sha256: String,
    /// Actual installed script identity, not a production acceptance artifact.
    pub script_version: String,
    /// Exact original request facts; no Native IAM proof is fabricated.
    pub request: HybridIngressAssertion,
    /// Reserved source and destination metadata for the same stream code.
    pub target: HybridLiveDeliveryTarget,
}

impl MirrorLiveCandidateRequest {
    /// Checks freshness, original context and closed fixture namespace geometry.
    ///
    /// # Errors
    /// Refuses stale controls, public namespaces, unsupported methods or excessive bounds.
    pub fn validate(&self, deployment: &str, latest_now: i64) -> Result<()> {
        super::validate_assertion(&self.request)?;
        super::validate_intrinsic_lifetime(&self.request)?;
        self.target.validate()?;
        let namespace = format!(".aos-mirror-qualification/{}", self.run_id);
        let upstream = url::Url::parse(&self.target.upstream_base)?;
        ensure!(
            self.version == 1
                && self.run_id.len() == 32
                && self
                    .run_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && crate::direct_upload::valid_direct_digest(&self.compiled_source_sha256)
                && !self.script_version.is_empty()
                && self.script_version.len() <= 128
                && self.request.deployment_id == deployment
                && self.request.issued_at <= latest_now
                && latest_now < self.request.expires_at
                && matches!(self.request.method.as_str(), "GET" | "HEAD")
                && self.request.body_sha256 == crate::hybrid_ingress::body_sha256(&[])
                && self.request.upload_phase.is_none()
                && self.target.maximum_bytes <= LIVE_CANDIDATE_MAX_BYTES
                && self.target.placement_prefix == format!("{namespace}/final")
                && upstream.path().trim_end_matches('/') == format!("/{namespace}")
                && self.request.path_and_query == format!("/{namespace}/{}", self.target.path),
            "live candidate context or fixture namespace differs"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= LIVE_CANDIDATE_CONTROL_BYTES,
            "live candidate exceeds control bound"
        );
        Ok(())
    }
}

/// Signs one exact fixture request under the independent candidate key role.
///
/// # Errors
/// Returns an error for malformed controls or signing failure.
pub fn sign_mirror_live_candidate(
    key: &StorageWorkKey,
    request: &MirrorLiveCandidateRequest,
) -> Result<String> {
    request.validate(&request.request.deployment_id, request.request.issued_at)?;
    Ok(key.sign_body(&signed_body(&serde_json::to_vec(request)?))?)
}

/// Authenticates bounded original control bytes before any source admission.
///
/// # Errors
/// Refuses foreign signatures, stale requests or destinations outside the fixture.
pub fn verify_mirror_live_candidate(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    deployment: &str,
    latest_now: i64,
) -> Result<MirrorLiveCandidateRequest> {
    ensure!(
        body.len() <= LIVE_CANDIDATE_CONTROL_BYTES,
        "live candidate exceeds control bound"
    );
    key.verify_body(signature, &signed_body(body))?;
    let request: MirrorLiveCandidateRequest = serde_json::from_slice(body)?;
    request.validate(deployment, latest_now)?;
    Ok(request)
}

fn signed_body(body: &[u8]) -> Vec<u8> {
    [DOMAIN, body].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> MirrorLiveCandidateRequest {
        let mut target = super::super::tests::target();
        let run_id = "ab".repeat(16);
        target.upstream_base =
            format!("https://upstream.example.com/.aos-mirror-qualification/{run_id}");
        target.placement_prefix = format!(".aos-mirror-qualification/{run_id}/final");
        MirrorLiveCandidateRequest {
            version: 1,
            run_id: run_id.clone(),
            compiled_source_sha256: "cd".repeat(32),
            script_version: "controlled-script-1".into(),
            request: HybridIngressAssertion {
                version: 1,
                deployment_id: "deployment-1".into(),
                issued_at: 100,
                expires_at: 130,
                request_id: "candidate-live-1".into(),
                scheme: "https".into(),
                authority: "hub.example.com".into(),
                method: "GET".into(),
                path_and_query: format!("/.aos-mirror-qualification/{run_id}/HEAD"),
                body_sha256: crate::hybrid_ingress::body_sha256(&[]),
                upload_phase: None,
                client_ip: "192.0.2.1".into(),
            },
            target,
        }
    }

    #[test]
    fn controlled_live_signature_is_separate_fresh_and_exact() {
        let key = StorageWorkKey::new([17; 32]).unwrap();
        let request = request();
        let bytes = serde_json::to_vec(&request).unwrap();
        let signature = sign_mirror_live_candidate(&key, &request).unwrap();
        assert!(
            verify_mirror_live_candidate(&key, &signature, &bytes, "deployment-1", 101).is_ok()
        );
        assert!(key.verify_body(&signature, &bytes).is_err());
        assert!(verify_mirror_live_candidate(&key, &signature, &bytes, "foreign", 101).is_err());
        assert!(
            verify_mirror_live_candidate(&key, &signature, &bytes, "deployment-1", 130).is_err()
        );
        let mut changed = request.clone();
        changed.request.request_id.push('x');
        assert!(verify_mirror_live_candidate(
            &key,
            &signature,
            &serde_json::to_vec(&changed).unwrap(),
            "deployment-1",
            101
        )
        .is_err());
    }

    #[test]
    fn controlled_live_refuses_public_namespaces_and_unbounded_source() {
        let mut request = request();
        request.target.placement_prefix = "public/registry".into();
        assert!(request.validate("deployment-1", 101).is_err());
        let mut request = self::request();
        request.target.upstream_base = "https://upstream.example.com/public".into();
        assert!(request.validate("deployment-1", 101).is_err());
        let mut request = self::request();
        request.target.path = "objects/pack/pack-fixture.pack".into();
        request.target.class = super::super::HybridLiveDeliveryClass::Pack;
        request.request.path_and_query = format!(
            "/.aos-mirror-qualification/{}/{}",
            request.run_id, request.target.path
        );
        request.target.maximum_bytes = LIVE_CANDIDATE_MAX_BYTES;
        assert!(request.validate("deployment-1", 101).is_ok());
        request.target.maximum_bytes += 1;
        assert!(request.validate("deployment-1", 101).is_err());
    }
}
