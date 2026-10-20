//! Fresh protected discovery of the unchanged Worker's actual public bindings.
//!
//! Discovery publishes no credentials and grants no runtime acceptance. The
//! installer compares this actual projection with independently signed evidence
//! before writing the version-specific acceptance registry entry.
//!
//! ```text
//! challenge = {version, nonce, expiresAt, externalSelectors}
//! reply = {request: challenge, identity: actual protected public projection}
//! request and reply use separate domain-separated guard-key signatures
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::storage_work::StorageWorkKey;

use super::*;

/// Exact protected discovery route, available before production qualification.
pub const DIRECT_WORKER_DEPLOYMENT_PATH: &str = "/_internal/storage/direct-upload-deployment";
/// Guard-key signature header for discovery requests and responses.
pub const DIRECT_WORKER_DEPLOYMENT_SIGNATURE_HEADER: &str = "x-aos-direct-deployment-signature";

const REQUEST_DOMAIN: &[u8] = b"aos.direct-upload.deployment-identity-request.v1\0";
const RESPONSE_DOMAIN: &[u8] = b"aos.direct-upload.deployment-identity-response.v1\0";

/// Independently selected queue delivery bounds, separate from isolate pools.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectQueueDeliveryPolicy {
    /// Maximum jobs delivered in one queue invocation.
    pub maximum_batch_size: WireInteger,
    /// Maximum concurrent global invocations; absent only for unsupported emulator delivery.
    pub maximum_concurrent_invocations: Option<WireInteger>,
}

impl DirectQueueDeliveryPolicy {
    /// Checks delivery bounds against the participating isolate's class ceiling.
    ///
    /// # Errors
    /// Returns an error for unsupported invocation bounds or excessive batch sizes.
    pub fn validate(&self, class_ceiling: u64) -> Result<()> {
        ensure!(
            (1..=class_ceiling).contains(&self.maximum_batch_size.get())
                && self
                    .maximum_concurrent_invocations
                    .as_ref()
                    .is_none_or(|bound| (1..=32).contains(&bound.get())),
            "direct queue delivery policy invalid"
        );
        Ok(())
    }

    /// Checks delivery bounds for the actual execution environment.
    ///
    /// A missing invocation bound records unsupported emulator configuration,
    /// without making a global concurrency claim. Hosted policies require a cap.
    ///
    /// # Errors
    /// Returns an error for invalid bounds or a missing hosted invocation cap.
    pub fn validate_for_execution(
        &self,
        class_ceiling: u64,
        kind: DirectWorkerExecutionKind,
    ) -> Result<()> {
        self.validate(class_ceiling)?;
        ensure!(
            kind == DirectWorkerExecutionKind::EmulatedExternal
                || self.maximum_concurrent_invocations.is_some(),
            "hosted queue invocation bound absent"
        );
        Ok(())
    }
}

/// Candidate bounds installed for explicitly isolated qualification fixtures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectWorkerQualificationLimits {
    /// Maximum provider requests used by protected fixture execution.
    pub maximum_provider_requests: WireInteger,
    /// Maximum source size used by protected fixture execution.
    pub maximum_object_bytes: WireInteger,
}

impl DirectWorkerQualificationLimits {
    /// Checks the fixed candidate bounds before fixture dispatch.
    ///
    /// # Errors
    /// Returns an error for zero/excessive source sizes or request capacity.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (2..=32).contains(&self.maximum_provider_requests.get())
                && (1..=MAX_DIRECT_OBJECT_BYTES).contains(&self.maximum_object_bytes.get()),
            "direct qualification candidate bounds invalid"
        );
        Ok(())
    }
}

/// Fresh bounded discovery challenge naming only independently selected providers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectWorkerDeploymentChallenge {
    /// Closed discovery format, currently one.
    pub version: u32,
    /// Fresh random challenge commitment preventing reply replay.
    pub nonce: String,
    /// Original challenge cutoff, no more than thirty seconds after creation.
    pub expires_at: WireInteger,
    /// Exact independently accepted external selectors to resolve, if any.
    pub external_selectors: Vec<DirectExternalProfileSelector>,
}

impl DirectWorkerDeploymentChallenge {
    fn validate(&self, now: u64) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            now < self.expires_at.get() && self.expires_at.get() <= now.saturating_add(30),
            "direct Worker discovery challenge invalid or expired"
        );
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && valid_direct_digest(&self.nonce)
                && self.external_selectors.len() <= MAX_DIRECT_PLACEMENTS,
            "direct Worker discovery challenge invalid"
        );
        let mut selectors = std::collections::BTreeSet::new();
        for selector in &self.external_selectors {
            ensure!(
                selectors.insert(selector.fingerprint()?),
                "direct Worker discovery selector repeated"
            );
        }
        Ok(())
    }
}

/// Actual protected public projection of the current unchanged Worker deployment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectWorkerDeploymentIdentity {
    /// Closed deployment projection format, currently one.
    pub version: u32,
    /// Actual paired deployment audience.
    pub deployment_id: String,
    /// Actual configured public executor origin.
    pub public_origin: String,
    /// Actual compiled hermetic Worker source identity.
    pub source_digest: String,
    /// Actual current hosted version metadata identifier.
    pub script_version: String,
    /// Actual independently installed reviewer verifier, never learned from KV.
    pub qualification_public_key: String,
    /// Actual configured immutable clock comparison mode.
    pub clock_mode: DirectClockPolicyMode,
    /// Actual configured clock policy commitment, independent of observed reports.
    pub clock_qualification: String,
    /// Actual configured conservative clock uncertainty, in seconds.
    pub clock_uncertainty_seconds: WireInteger,
    /// Actual material-derived managed profile, if selected.
    pub managed_profile: Option<DirectManagedR2Profile>,
    /// Actual configured managed private namespace policy, if selected.
    pub private_stage_policy: Option<DirectPrivateStagePolicyRef>,
    /// Actual resolved protected external profiles for the exact challenged selectors.
    pub external_profiles: Vec<DirectExternalStorageCapabilities>,
    /// Actual bulk queue binding's name.
    pub bulk_queue: String,
    /// Actual metadata queue binding's distinct name.
    pub metadata_queue: String,
    /// Actual configured bulk queue delivery bounds.
    pub bulk_queue_policy: DirectQueueDeliveryPolicy,
    /// Actual configured metadata queue delivery bounds.
    pub metadata_queue_policy: DirectQueueDeliveryPolicy,
    /// Actual configured consumer parallelism ceiling.
    pub maximum_parallel_objects: WireInteger,
    /// Explicit isolated fixture bounds, absent unless separately enabled.
    pub qualification_limits: Option<DirectWorkerQualificationLimits>,
}

/// Signed protected discovery result echoing its exact original challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectWorkerDeploymentReply {
    /// Original exact challenge, including selectors and cutoff.
    pub request: DirectWorkerDeploymentChallenge,
    /// Actual unchanged deployment projection, with no provider secret values.
    pub identity: DirectWorkerDeploymentIdentity,
}

impl DirectWorkerQualificationArtifact {
    /// Matches accepted evidence against a freshly authenticated actual deployment.
    ///
    /// Caller first verifies this artifact with independent reviewer trust and
    /// verifies the deployment reply using the separate protected guard key.
    ///
    /// # Errors
    /// Returns a value-free error for changed code, version, profile, clock,
    /// verifier, queue names or consumer capacity.
    pub fn verify_deployment_identity(
        &self,
        actual: &DirectWorkerDeploymentIdentity,
        trusted_public: &str,
    ) -> Result<()> {
        self.verify_runtime_identity(&actual.source_digest, &actual.script_version)?;
        let evidence = &self.evidence;
        let external: Vec<_> = evidence
            .external_profiles
            .iter()
            .map(|item| item.profile.clone())
            .collect();
        ensure!(
            actual.version == 1
                && actual.deployment_id == self.deployment_id
                && actual.public_origin == self.public_origin
                && actual.qualification_public_key == trusted_public
                && actual.clock_mode == evidence.clock_policy.mode
                && actual.clock_qualification == evidence.clock_policy.commitment()?
                && actual.clock_uncertainty_seconds == evidence.clock_policy.uncertainty_seconds
                && actual.managed_profile == evidence.managed_profile
                && actual.private_stage_policy == evidence.private_stage_policy
                && actual.external_profiles == external
                && actual.bulk_queue == evidence.bulk_queue.queue_name
                && actual.metadata_queue == evidence.metadata_queue.queue_name
                && actual.bulk_queue_policy == evidence.bulk_queue.delivery_policy
                && actual.metadata_queue_policy == evidence.metadata_queue.delivery_policy
                && actual.maximum_parallel_objects == evidence.runtime.maximum_parallel_objects,
            "direct accepted bindings differ from actual unchanged deployment"
        );
        ensure!(
            actual.qualification_limits == evidence.qualification_limits,
            "direct accepted qualification controls differ from installed bindings"
        );
        Ok(())
    }
}

/// Signs one protected deployment discovery challenge.
///
/// # Errors
/// Returns an error for malformed selectors or excessive canonical encoding.
pub fn sign_direct_worker_deployment_request(
    key: &StorageWorkKey,
    challenge: &DirectWorkerDeploymentChallenge,
) -> Result<SignedDirectControl> {
    challenge.validate_shape()?;
    sign(key, REQUEST_DOMAIN, challenge)
}

/// Authenticates a fresh bounded protected deployment discovery challenge.
///
/// # Errors
/// Returns an error for expired, forged, oversized or noncanonical requests.
pub fn verify_direct_worker_deployment_request(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    now: u64,
) -> Result<DirectWorkerDeploymentChallenge> {
    let challenge: DirectWorkerDeploymentChallenge = verify(key, REQUEST_DOMAIN, signature, body)?;
    challenge.validate(now)?;
    Ok(challenge)
}

/// Signs a public deployment projection and its exact original challenge.
///
/// # Errors
/// Returns an error if the canonical reply exceeds protocol bounds.
pub fn sign_direct_worker_deployment_reply(
    key: &StorageWorkKey,
    reply: &DirectWorkerDeploymentReply,
) -> Result<SignedDirectControl> {
    sign(key, RESPONSE_DOMAIN, reply)
}

/// Authenticates an actual deployment reply for the exact fresh challenge.
///
/// # Errors
/// Returns an error for expired, forged, oversized, reordered or replayed replies.
pub fn verify_direct_worker_deployment_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    expected: &DirectWorkerDeploymentChallenge,
    now: u64,
) -> Result<DirectWorkerDeploymentReply> {
    let reply: DirectWorkerDeploymentReply = verify(key, RESPONSE_DOMAIN, signature, body)?;
    expected.validate(now)?;
    ensure!(
        &reply.request == expected,
        "direct Worker discovery original challenge differs"
    );
    Ok(reply)
}

fn sign(
    key: &StorageWorkKey,
    domain: &[u8],
    value: &impl Serialize,
) -> Result<SignedDirectControl> {
    let body = encode_direct_control(value)?;
    let signature = key.sign_body(&[domain, body.as_slice()].concat())?;
    Ok(SignedDirectControl { body, signature })
}

fn verify<T: serde::de::DeserializeOwned + Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    signature: &str,
    body: &[u8],
) -> Result<T> {
    ensure!(
        body.len() <= MAX_DIRECT_CAPABILITY_BYTES,
        "direct Worker discovery exceeds limit"
    );
    key.verify_body(signature, &[domain, body].concat())?;
    let value: T = decode_direct_control(body)?;
    ensure!(
        encode_direct_control(&value)? == body,
        "direct Worker discovery encoding noncanonical"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    #[test]
    fn unsupported_emulator_invocation_bound_cannot_qualify_hosted_delivery() {
        let mut policy = DirectQueueDeliveryPolicy {
            maximum_batch_size: WireInteger::new(4),
            maximum_concurrent_invocations: None,
        };
        policy
            .validate_for_execution(4, DirectWorkerExecutionKind::EmulatedExternal)
            .unwrap();
        assert!(policy
            .validate_for_execution(4, DirectWorkerExecutionKind::Hosted)
            .is_err());
        policy.maximum_concurrent_invocations = Some(WireInteger::new(2));
        policy
            .validate_for_execution(4, DirectWorkerExecutionKind::Hosted)
            .unwrap();
        policy.maximum_concurrent_invocations = Some(WireInteger::new(33));
        assert!(policy
            .validate_for_execution(4, DirectWorkerExecutionKind::EmulatedExternal)
            .is_err());
    }

    fn identity(
        artifact: &DirectWorkerQualificationArtifact,
        reviewer: &str,
    ) -> DirectWorkerDeploymentIdentity {
        let evidence = &artifact.evidence;
        DirectWorkerDeploymentIdentity {
            version: 1,
            deployment_id: artifact.deployment_id.clone(),
            public_origin: artifact.public_origin.clone(),
            source_digest: artifact.source_digest.clone(),
            script_version: artifact.script_version.clone(),
            qualification_public_key: reviewer.into(),
            clock_mode: evidence.clock_policy.mode,
            clock_qualification: evidence.clock_policy.commitment().unwrap(),
            clock_uncertainty_seconds: evidence.clock.uncertainty_seconds,
            managed_profile: evidence.managed_profile.clone(),
            private_stage_policy: evidence.private_stage_policy.clone(),
            external_profiles: Vec::new(),
            bulk_queue: evidence.bulk_queue.queue_name.clone(),
            metadata_queue: evidence.metadata_queue.queue_name.clone(),
            bulk_queue_policy: evidence.bulk_queue.delivery_policy.clone(),
            metadata_queue_policy: evidence.metadata_queue.delivery_policy.clone(),
            maximum_parallel_objects: evidence.runtime.maximum_parallel_objects,
            qualification_limits: evidence.qualification_limits.clone(),
        }
    }

    #[test]
    fn accepted_fixture_bounds_match_the_installed_opt_in_and_actual_runtime() {
        let (mut artifact, reviewer) =
            super::super::worker_qualification::fixtures::direct_worker_qualification_fixture();
        artifact.evidence.qualification_limits = Some(DirectWorkerQualificationLimits {
            maximum_provider_requests: artifact.evidence.runtime.maximum_parallel_provider_requests,
            maximum_object_bytes: artifact.evidence.runtime.maximum_object_bytes,
        });
        artifact.evidence_sha256 = direct_qualification_digest(&artifact.evidence).unwrap();
        let key = SigningKey::from_bytes(&[0x19; 32]);
        artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
        let mut actual = identity(&artifact, &reviewer);
        artifact
            .verify("deployment-1", "https://hub.example.test", &reviewer, 100)
            .unwrap();
        artifact
            .verify_deployment_identity(&actual, &reviewer)
            .unwrap();

        actual
            .qualification_limits
            .as_mut()
            .unwrap()
            .maximum_provider_requests = WireInteger::new(4);
        assert!(artifact
            .verify_deployment_identity(&actual, &reviewer)
            .is_err());
        actual.qualification_limits = None;
        assert!(artifact
            .verify_deployment_identity(&actual, &reviewer)
            .is_err());
        artifact
            .evidence
            .qualification_limits
            .as_mut()
            .unwrap()
            .maximum_object_bytes = WireInteger::new(1024);
        artifact.evidence_sha256 = direct_qualification_digest(&artifact.evidence).unwrap();
        artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
        assert!(artifact
            .verify("deployment-1", "https://hub.example.test", &reviewer, 100)
            .is_err());
    }

    #[test]
    fn new_observations_activate_the_unchanged_installed_policy_only_when_independently_signed() {
        let (mut artifact, reviewer) =
            super::super::worker_qualification::fixtures::direct_worker_qualification_fixture();
        let actual = identity(&artifact, &reviewer);
        let installed_profile = artifact.evidence.managed_profile.clone();
        let installed_policy = artifact.evidence.private_stage_policy.clone();

        artifact.evidence.clock.observation_sha256 = "91".repeat(32);
        artifact.evidence.clock.samples = WireInteger::new(32);
        artifact
            .evidence
            .privacy
            .as_mut()
            .unwrap()
            .observation_sha256 = "92".repeat(32);
        artifact.evidence_sha256 = direct_qualification_digest(&artifact.evidence).unwrap();
        assert!(artifact
            .verify("deployment-1", "https://hub.example.test", &reviewer, 100)
            .is_err());

        let key = SigningKey::from_bytes(&[0x19; 32]);
        artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
        artifact
            .verify("deployment-1", "https://hub.example.test", &reviewer, 100)
            .unwrap();
        artifact
            .verify_deployment_identity(&actual, &reviewer)
            .unwrap();
        assert_eq!(artifact.evidence.managed_profile, installed_profile);
        assert_eq!(artifact.evidence.private_stage_policy, installed_policy);

        let mut changed = actual.clone();
        changed.clock_uncertainty_seconds = WireInteger::new(2);
        assert!(artifact
            .verify_deployment_identity(&changed, &reviewer)
            .is_err());
        changed = actual.clone();
        changed.script_version = "different-script".into();
        assert!(artifact
            .verify_deployment_identity(&changed, &reviewer)
            .is_err());

        let mut value = serde_json::to_value(&actual).unwrap();
        value["clockMode"] = "unbounded_utc".into();
        assert!(serde_json::from_value::<DirectWorkerDeploymentIdentity>(value).is_err());
        artifact.evidence.clock_policy.uncertainty_seconds = WireInteger::new(2);
        artifact.evidence_sha256 = direct_qualification_digest(&artifact.evidence).unwrap();
        artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
        assert!(artifact
            .verify("deployment-1", "https://hub.example.test", &reviewer, 100)
            .is_err());
    }

    #[test]
    fn independent_acceptance_matches_actual_credential_clock_and_current_version() {
        let (artifact, reviewer) =
            super::super::worker_qualification::fixtures::direct_worker_qualification_fixture();
        let actual = identity(&artifact, &reviewer);
        artifact
            .verify_deployment_identity(&actual, &reviewer)
            .unwrap();

        for mutation in 0..8 {
            let mut changed = actual.clone();
            match mutation {
                0 => changed.script_version = "new-version".into(),
                1 => changed.source_digest = "ab".repeat(32),
                2 => {
                    changed
                        .managed_profile
                        .as_mut()
                        .unwrap()
                        .credential_fingerprint = "ab".repeat(32)
                }
                3 => changed.clock_uncertainty_seconds = WireInteger::new(2),
                4 => changed.qualification_public_key = "ab".repeat(32),
                5 => changed.metadata_queue = changed.bulk_queue.clone(),
                6 => changed.maximum_parallel_objects = WireInteger::new(8),
                7 => {
                    changed.metadata_queue_policy.maximum_concurrent_invocations =
                        Some(WireInteger::new(3))
                }
                _ => unreachable!(),
            }
            assert!(
                artifact
                    .verify_deployment_identity(&changed, &reviewer)
                    .is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn protected_discovery_is_fresh_original_bound_and_separate_from_reviewer_acceptance() {
        let (artifact, reviewer) =
            super::super::worker_qualification::fixtures::direct_worker_qualification_fixture();
        let guard = StorageWorkKey::new([0x51; 32]).unwrap();
        let other = StorageWorkKey::new([0x52; 32]).unwrap();
        let challenge = DirectWorkerDeploymentChallenge {
            version: 1,
            nonce: "ab".repeat(32),
            expires_at: WireInteger::new(130),
            external_selectors: Vec::new(),
        };
        let request = sign_direct_worker_deployment_request(&guard, &challenge).unwrap();

        assert_eq!(
            verify_direct_worker_deployment_request(&guard, &request.signature, &request.body, 100)
                .unwrap(),
            challenge
        );
        assert!(verify_direct_worker_deployment_request(
            &other,
            &request.signature,
            &request.body,
            100
        )
        .is_err());
        assert!(verify_direct_worker_deployment_request(
            &guard,
            &request.signature,
            &request.body,
            130
        )
        .is_err());
        let reply = DirectWorkerDeploymentReply {
            request: challenge.clone(),
            identity: identity(&artifact, &reviewer),
        };
        let signed = sign_direct_worker_deployment_reply(&guard, &reply).unwrap();
        verify_direct_worker_deployment_reply(
            &guard,
            &signed.signature,
            &signed.body,
            &challenge,
            100,
        )
        .unwrap();

        let mut replay = challenge;
        replay.nonce = "cd".repeat(32);
        assert!(verify_direct_worker_deployment_reply(
            &guard,
            &signed.signature,
            &signed.body,
            &replay,
            100
        )
        .is_err());
        assert!(verify_direct_worker_deployment_request(
            &guard,
            &signed.signature,
            &signed.body,
            100
        )
        .is_err());
        assert!(artifact
            .verify(
                "deployment-1",
                "https://hub.example.test",
                &hex::encode([0x51; 32]),
                100
            )
            .is_err());
    }
}
