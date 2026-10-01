//! Closed independently signed acceptance of measured hosted Worker behavior.
//!
//! Public measurements and full protected profile projections are accepted
//! together by a separately trusted reviewer. Neither configuration digests nor
//! a successful probe alone authorize production dispatch.
//!
//! ```text
//! artifact = {version, deploymentId, publicOrigin, workersRsVersion,
//! sourceDigest, scriptVersion, evidenceSha256, evidence, signature}
//! signature = Ed25519(domain || canonical artifact identity tuple)
//! evidenceSha256 = SHA256(canonical evidence)
//! ```

use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::*;

const DOMAIN: &[u8] = b"aos.direct-upload.accepted-worker-qualification.v1\0";

#[derive(Clone, Copy)]
enum QualificationValidity {
    Producer,
    ExpiredGuardHistory,
}

/// Closed execution environment independently covered by the acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectWorkerExecutionKind {
    /// Actual Cloudflare Workers execution with hosted version metadata.
    Hosted,
    /// Explicitly enabled local qualification for external test providers only.
    EmulatedExternal,
}

/// Independently accepted hosted Worker deployment and measurement bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectWorkerQualificationArtifact {
    /// Closed acceptance format, currently one.
    pub version: u32,
    /// Exact hosted or explicitly emulated external execution environment.
    pub execution_kind: DirectWorkerExecutionKind,
    /// Stable identity of the independently trusted reviewer publication.
    pub reviewer_key_id: String,
    /// Exact paired deployment audience.
    pub deployment_id: String,
    /// Exact public HTTPS origin of the qualified executor.
    pub public_origin: String,
    /// Exact source-built Worker SDK version.
    pub workers_rs_version: String,
    /// Digest of the source used to build the qualified Worker artifact.
    pub source_digest: String,
    /// Actual hosted Cloudflare script version measured by the probe.
    pub script_version: String,
    /// Commitment to all canonical measurement and profile evidence.
    pub evidence_sha256: String,
    /// Accepted bounded observations and full protected public projections.
    pub evidence: DirectWorkerQualificationEvidence,
    /// Lowercase hexadecimal independent reviewer Ed25519 signature.
    pub signature: String,
}

impl DirectWorkerQualificationArtifact {
    /// Checks an unsigned review candidate without granting runtime acceptance.
    ///
    /// # Errors
    /// Returns a value-free error for changed bindings,
    /// malformed or insufficient measurements, expired evidence or unknown fields.
    pub fn validate_unsigned(&self, deployment: &str, public_origin: &str, now: u64) -> Result<()> {
        self.validate_unsigned_for(
            deployment,
            public_origin,
            now,
            QualificationValidity::Producer,
        )
    }

    fn validate_unsigned_for(
        &self,
        deployment: &str,
        public_origin: &str,
        now: u64,
        validity: QualificationValidity,
    ) -> Result<()> {
        ensure!(
            self.version == 1
                && self.deployment_id == deployment
                && valid_registry_identity(deployment)
                && valid_registry_identity(&self.reviewer_key_id)
                && self.public_origin == public_origin
                && self.workers_rs_version == "0.8.5"
                && valid_direct_digest(&self.source_digest)
                && valid_registry_identity(&self.script_version)
                && valid_direct_digest(&self.evidence_sha256),
            "direct accepted Worker identity differs"
        );
        let origin = url::Url::parse(public_origin)
            .map_err(|_| anyhow::anyhow!("direct accepted Worker origin invalid"))?;
        ensure!(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none(),
            "direct accepted Worker origin invalid"
        );
        ensure!(
            direct_qualification_digest(&self.evidence)? == self.evidence_sha256,
            "direct accepted measurement commitment differs"
        );
        match self.execution_kind {
            DirectWorkerExecutionKind::Hosted => ensure!(
                !self.script_version.starts_with("emulated-"),
                "hosted Worker cannot accept emulated identity"
            ),
            DirectWorkerExecutionKind::EmulatedExternal => ensure!(
                self.script_version == direct_worker_emulated_script_id(&self.source_digest)?
                    && origin.host_str().is_some_and(emulated_dns_host),
                "emulated Worker source identity or reserved origin differs"
            ),
        }
        self.evidence.validate(self, now, validity)
    }

    /// Verifies independent reviewer trust, exact audience and measured evidence.
    ///
    /// The trusted public key is independently installed and never learned from
    /// the operator artifact. Unsigned candidate validation grants no authority.
    ///
    /// # Errors
    /// Returns a value-free error for changed bindings, invalid signatures,
    /// unsupported execution identities or expired/insufficient measurements.
    pub fn verify(
        &self,
        deployment: &str,
        public_origin: &str,
        trusted_public_hex: &str,
        now: u64,
    ) -> Result<()> {
        self.validate_unsigned(deployment, public_origin, now)?;
        self.verify_signature(trusted_public_hex)
    }

    /// Verifies genuinely expired, previously issued guard facts without qualifying dispatch.
    ///
    /// This distinct historical check preserves all signed profile, installation,
    /// source, runtime and clock-policy facts. It rejects future or invalid windows
    /// and never projects a fresh qualification deadline or provider permission.
    /// Callers may use it only for independently authenticated held-positive metadata.
    ///
    /// # Errors
    /// Rejects a current or future artifact, malformed facts, changed audience,
    /// unknown reviewer, insufficient original validity or invalid signature.
    pub fn verify_expired_guard_history(
        &self,
        deployment: &str,
        public_origin: &str,
        trusted_public_hex: &str,
        now: u64,
    ) -> Result<()> {
        self.validate_unsigned_for(
            deployment,
            public_origin,
            now,
            QualificationValidity::ExpiredGuardHistory,
        )?;
        self.verify_signature(trusted_public_hex)
    }

    fn verify_signature(&self, trusted_public_hex: &str) -> Result<()> {
        ensure!(
            valid_direct_digest(trusted_public_hex)
                && self.signature.len() == 128
                && self
                    .signature
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "direct acceptance verifier or signature malformed"
        );
        let public: [u8; 32] = hex::decode(trusted_public_hex)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("direct acceptance verifier malformed"))?;
        let signature = hex::decode(&self.signature)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
            .ok_or_else(|| anyhow::anyhow!("direct acceptance signature malformed"))?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| anyhow::anyhow!("direct acceptance verifier malformed"))?
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("direct acceptance signature invalid"))?;

        Ok(())
    }

    /// Encodes the domain-separated identity accepted by an independent reviewer.
    ///
    /// This method exposes no private signing key and grants no acceptance.
    ///
    /// # Errors
    /// Returns an error if the canonical public identity exceeds protocol bounds.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let identity = encode_direct_control(&(
            self.version,
            self.execution_kind,
            &self.reviewer_key_id,
            &self.deployment_id,
            &self.public_origin,
            &self.workers_rs_version,
            &self.source_digest,
            &self.script_version,
            &self.evidence_sha256,
        ))?;
        Ok([DOMAIN, identity.as_slice()].concat())
    }

    /// Matches the acceptance to the actual compiled source and hosted version.
    ///
    /// # Errors
    /// Returns an error when an update, local emulator or different build no
    /// longer has the identity independently measured and accepted.
    pub fn verify_runtime_identity(&self, source_digest: &str, script_version: &str) -> Result<()> {
        ensure!(
            self.source_digest == source_digest && self.script_version == script_version,
            "direct accepted Worker build or hosted version differs"
        );
        Ok(())
    }
}

/// Closed measurement bundle accepted for one Worker deployment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectWorkerQualificationEvidence {
    /// Independently observed installed bytes, mandatory for emulator acceptance.
    pub installation: Option<DirectWorkerInstallationMeasurement>,
    /// Immutable conservative clock policy installed before measurements.
    pub clock_policy: DirectClockPolicy,
    /// Exact separately opted-in isolated fixture bounds installed before measurement.
    pub qualification_limits: Option<DirectWorkerQualificationLimits>,
    /// Original mutation-clock observations and their bounded uncertainty.
    pub clock: DirectClockMeasurement,
    /// Exact measured runtime ceilings exposed in every protected profile.
    pub runtime: DirectRuntimeQualification,
    /// Actual capacity observations backing the accepted runtime reference.
    pub runtime_measurement: DirectRuntimeMeasurement,
    /// Actual protected-material-derived managed descriptor, when selected.
    pub managed_profile: Option<DirectManagedR2Profile>,
    /// Independently measured provider and Worker namespace privacy policy.
    pub private_stage_policy: Option<DirectPrivateStagePolicyRef>,
    /// Exact qualified external wrappers selected by this deployment.
    pub external_profiles: Vec<DirectProtectedExternalProfile>,
    /// Hosted ordinary R2 binding and direct S3 observations for managed use.
    pub sdk_probe: Option<DirectHostedSdkProbeDocument>,
    /// Independently retained namespace privacy observations for managed use.
    pub privacy: Option<DirectPrivacyMeasurement>,
    /// Actual separately provisioned bulk verification queue measurement.
    pub bulk_queue: DirectQueueMeasurement,
    /// Actual separately provisioned metadata verification queue measurement.
    pub metadata_queue: DirectQueueMeasurement,
    /// Earliest accepted UTC timestamp, in seconds.
    pub issued_at: WireInteger,
    /// Immutable acceptance cutoff; operator configuration cannot renew it.
    pub valid_until: WireInteger,
}

impl DirectWorkerQualificationEvidence {
    fn validate(
        &self,
        artifact: &DirectWorkerQualificationArtifact,
        now: u64,
        validity: QualificationValidity,
    ) -> Result<()> {
        if let Some(installation) = &self.installation {
            installation.validate(artifact)?;
        }
        ensure!(
            artifact.execution_kind != DirectWorkerExecutionKind::EmulatedExternal
                || self.installation.is_some(),
            "direct emulator installation observations absent"
        );
        let clock_policy_commitment = self.clock_policy.commitment()?;
        self.runtime.validate()?;
        if let Some(limits) = &self.qualification_limits {
            limits.validate()?;
            ensure!(
                limits.maximum_provider_requests == self.runtime.maximum_parallel_provider_requests
                    && limits.maximum_object_bytes == self.runtime.maximum_object_bytes,
                "direct accepted runtime differs from installed qualification bounds"
            );
        }
        ensure!(
            self.runtime.maximum_parallel_objects.get() >= 2
                && self.runtime.maximum_parallel_provider_requests.get() >= 2,
            "direct runtime requires a reserved metadata verification slot"
        );
        let valid_time = match validity {
            QualificationValidity::Producer => {
                self.issued_at.get() <= now
                    && now
                        .checked_add(self.clock.uncertainty_seconds.get())
                        .is_some_and(|latest| latest < self.valid_until.get())
            }
            QualificationValidity::ExpiredGuardHistory => {
                self.issued_at.get() <= now
                    && self
                        .issued_at
                        .get()
                        .checked_add(self.clock.uncertainty_seconds.get())
                        .is_some_and(|latest| latest < self.valid_until.get())
                    && now >= self.valid_until.get()
            }
        };
        ensure!(
            self.clock.uncertainty_seconds == self.clock_policy.uncertainty_seconds
                && valid_time
                && self.clock.samples.get() > 0
                && valid_direct_digest(&self.clock.observation_sha256)
                && (1..30).contains(&self.clock.uncertainty_seconds.get())
                && self.clock.maximum_observed_skew_millis.get()
                    <= self.clock.uncertainty_seconds.get() * 1000
                && self.clock.expired_mutation_dispatches.get() == 0,
            "direct accepted mutation clock or validity insufficient"
        );
        self.runtime
            .validate_foreground_window(30, self.clock.uncertainty_seconds.get())?;
        let capacity = &self.runtime_measurement;
        ensure!(
            self.runtime.qualification_digest == direct_qualification_digest(capacity)?
                && capacity.samples.get() > 0
                && valid_direct_digest(&capacity.observation_sha256)
                && capacity.maximum_verified_object_bytes.get()
                    >= self.runtime.maximum_object_bytes.get()
                && capacity.peak_parallel_objects.get()
                    >= self.runtime.maximum_parallel_objects.get()
                && capacity.peak_parallel_provider_requests.get()
                    >= self.runtime.maximum_parallel_provider_requests.get()
                && capacity.maximum_verification_millis.get() > 0
                && capacity.maximum_verification_millis.get()
                    <= self
                        .runtime
                        .maximum_verification_seconds
                        .get()
                        .saturating_mul(1000)
                && capacity.maximum_settlement_millis.get() > 0
                && capacity.maximum_settlement_millis.get()
                    <= self
                        .runtime
                        .settlement_reserve_seconds
                        .get()
                        .saturating_mul(1000),
            "direct accepted runtime capacity insufficient"
        );
        self.bulk_queue
            .validate(artifact, "content", &self.runtime)?;
        self.metadata_queue
            .validate(artifact, "metadata", &self.runtime)?;
        ensure!(
            self.bulk_queue.queue_name != self.metadata_queue.queue_name,
            "direct verification queues must be independent"
        );

        let managed = self.managed_profile.is_some();
        ensure!(
            artifact.execution_kind != DirectWorkerExecutionKind::EmulatedExternal || !managed,
            "emulated Worker qualification cannot accept managed storage"
        );
        ensure!(
            managed == self.private_stage_policy.is_some()
                && managed == self.sdk_probe.is_some()
                && managed == self.privacy.is_some()
                && (managed || !self.external_profiles.is_empty())
                && self.external_profiles.len() <= MAX_DIRECT_PLACEMENTS,
            "direct accepted protected profile set incomplete"
        );
        if let (Some(profile), Some(policy), Some(sdk), Some(privacy)) = (
            &self.managed_profile,
            &self.private_stage_policy,
            &self.sdk_probe,
            &self.privacy,
        ) {
            DirectProtectedProfile::managed(profile.clone(), policy.clone(), self.runtime.clone())?;
            ensure!(
                profile.deployment_id == artifact.deployment_id
                    && profile.clock_qualification == clock_policy_commitment
                    && profile.clock_uncertainty_seconds == self.clock.uncertainty_seconds
                    && privacy.namespace == profile.bucket_namespace
                    && privacy.provider_account_id == profile.account_id
                    && privacy.provider_bucket_name == profile.bucket_name
                    && privacy.policy_id == policy.policy_id
                    && policy.policy_digest
                        == direct_private_stage_policy_commitment(
                            &policy.policy_id,
                            &policy.namespace
                        )?
                    && privacy.independent_writer_count.get() == 0
                    && matches!(privacy.public_read_rejection_status, 401 | 403 | 404)
                    && matches!(privacy.worker_namespace_rejection_status, 403 | 404)
                    && valid_direct_digest(&privacy.observation_sha256)
                    && valid_direct_digest(&privacy.provider_policy_readback_sha256),
                "direct accepted managed privacy or clock differs"
            );
            let public_endpoint = url::Url::parse(&privacy.public_endpoint)
                .map_err(|_| anyhow::anyhow!("direct privacy public endpoint invalid"))?;
            ensure!(
                public_endpoint.scheme() == "https"
                    && public_endpoint.host_str().is_some()
                    && public_endpoint.username().is_empty()
                    && public_endpoint.password().is_none()
                    && public_endpoint.path() == "/"
                    && public_endpoint.query().is_none()
                    && public_endpoint.fragment().is_none(),
                "direct privacy public endpoint invalid"
            );
            sdk.validate(artifact, profile)?;
        }
        let mut selectors = std::collections::BTreeSet::new();
        for external in &self.external_profiles {
            external.validate()?;
            validate_direct_worker_external_execution(artifact.execution_kind, &external.profile)?;
            ensure!(
                external.runtime_qualification == self.runtime
                    && u64::try_from(external.profile.clock_uncertainty.get()).ok()
                        == Some(self.clock_policy.uncertainty_seconds.get())
                    && selectors.insert((
                        external.profile.selector.physical_authority_id.clone(),
                        external.profile.selector.association.association_id.clone(),
                    )),
                "direct accepted external runtime or selector differs"
            );
        }
        Ok(())
    }
}

/// Derives the explicit emulator identity from the actual compiled source digest.
///
/// # Errors
/// Returns an error for malformed or noncanonical source identities.
pub fn direct_worker_emulated_script_id(source: &str) -> Result<String> {
    ensure!(
        valid_direct_digest(source),
        "emulated Worker source identity invalid"
    );
    Ok(format!("emulated-{source}"))
}

/// Checks a full external profile against the independently accepted execution mode.
///
/// Actual service routing and installed executable hashes remain independently
/// measured report inputs. Issuer identity strings are not inferred hostnames.
///
/// # Errors
/// Returns an error for emulator contracts in hosted use or nonreserved storage
/// aliases in explicit emulator qualification.
pub fn validate_direct_worker_external_execution(
    kind: DirectWorkerExecutionKind,
    profile: &DirectExternalStorageCapabilities,
) -> Result<()> {
    use crate::storage_authority::StorageAuthorityHost;

    let emulated_contract = profile.provider_contract_id.starts_with("emulated-");
    let reserved_alias = |host: &StorageAuthorityHost| matches!(host, StorageAuthorityHost::Dns(name) if emulated_dns_host(name));
    ensure!(
        match kind {
            DirectWorkerExecutionKind::Hosted => !emulated_contract,
            DirectWorkerExecutionKind::EmulatedExternal =>
                emulated_contract
                    && reserved_alias(&profile.write_cohort.alias.spec.host)
                    && reserved_alias(&profile.read_cohort.alias.spec.host),
        },
        "direct external execution mode or actual storage aliases differ"
    );
    Ok(())
}

fn emulated_dns_host(name: &str) -> bool {
    name.ends_with(".test") || name == "localhost" || name.ends_with(".localhost")
}

/// Installed mutation-clock policy whose commitment excludes observed reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectClockPolicy {
    /// Closed policy format, currently one.
    pub version: u32,
    /// Conservative absolute UTC comparison mode.
    pub mode: DirectClockPolicyMode,
    /// Fixed positive uncertainty below the thirty-second foreground window.
    pub uncertainty_seconds: WireInteger,
}

/// Closed clock comparison modes supported by the direct executor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectClockPolicyMode {
    /// Compares fresh UTC against the immutable cutoff with conservative uncertainty.
    BoundedUtc,
}

impl DirectClockPolicy {
    /// Returns the stable commitment installed before source/version measurement.
    ///
    /// # Errors
    /// Returns an error for unsupported versions or invalid uncertainty bounds.
    pub fn commitment(&self) -> Result<String> {
        ensure!(
            self.version == 1 && (1..30).contains(&self.uncertainty_seconds.get()),
            "direct installed clock policy invalid"
        );
        direct_qualification_digest(&("aos.direct-upload.clock-policy.v1", self))
    }
}

/// Commits to the installed private namespace and exclusive physical writer policy.
///
/// Actual provider privacy observations remain separate signed evidence. This
/// commitment can be installed before measuring the unchanged Worker version.
///
/// # Errors
/// Returns an error for invalid policy or namespace coordinates.
pub fn direct_private_stage_policy_commitment(policy_id: &str, namespace: &str) -> Result<String> {
    ensure!(
        valid_direct_identity(policy_id) && valid_direct_identity(namespace),
        "direct installed private namespace policy invalid"
    );
    direct_qualification_digest(&(
        "aos.direct-upload.private-stage-policy.v1",
        policy_id,
        namespace,
        "deny-public-and-unauthorized-reads",
        "exclusive-guarded-physical-writer",
    ))
}

/// Measured mutation-clock behavior with no renewal or configured proof shortcut.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectClockMeasurement {
    /// Commitment to the independently retained raw clock observation report.
    pub observation_sha256: String,
    /// Number of observed mutation/expiry samples.
    pub samples: WireInteger,
    /// Largest absolute skew measured against the reference clock.
    pub maximum_observed_skew_millis: WireInteger,
    /// Conservative accepted uncertainty, in seconds.
    pub uncertainty_seconds: WireInteger,
    /// Number of observed new mutations after the original cutoff; must be zero.
    pub expired_mutation_dispatches: WireInteger,
}

/// Measured source size, parallel capacity and foreground verification duration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectRuntimeMeasurement {
    /// Commitment to the independently retained capacity observation report.
    pub observation_sha256: String,
    /// Number of positive immutable object verification samples.
    pub samples: WireInteger,
    /// Largest positively verified source size in bytes.
    pub maximum_verified_object_bytes: WireInteger,
    /// Peak simultaneous object verification operations actually observed.
    pub peak_parallel_objects: WireInteger,
    /// Peak simultaneous provider requests actually observed.
    pub peak_parallel_provider_requests: WireInteger,
    /// Largest observed end-to-end bounded verification duration.
    pub maximum_verification_millis: WireInteger,
    /// Largest observed control/settlement duration.
    pub maximum_settlement_millis: WireInteger,
}

/// Accepted observations of provider privacy and exclusive namespace writers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPrivacyMeasurement {
    /// Commitment to the independently retained provider and namespace report.
    pub observation_sha256: String,
    /// Exact accepted private namespace.
    pub namespace: String,
    /// Exact operator-selected privacy policy identity.
    pub policy_id: String,
    /// Actual provider account correlated with the policy API readback.
    pub provider_account_id: String,
    /// Actual provider bucket correlated with the policy API readback.
    pub provider_bucket_name: String,
    /// Actual managed public endpoint reported by the provider policy API.
    pub public_endpoint: String,
    /// Commitment to actual public-domain/custom-domain policy API readback.
    pub provider_policy_readback_sha256: String,
    /// Actual anonymous provider read refusal status.
    pub public_read_rejection_status: u16,
    /// Actual unauthorized Worker staging namespace read refusal status.
    pub worker_namespace_rejection_status: u16,
    /// Independently observed writers bypassing the physical guard; must be zero.
    pub independent_writer_count: WireInteger,
}

/// Actual hosted queue observations bound to one deployment and script version.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectQueueMeasurement {
    /// Exact installed per-queue global invocation and batch delivery policy.
    pub delivery_policy: DirectQueueDeliveryPolicy,
    /// Commitment to retained actual provider/emulator consumer configuration readback.
    pub configuration_readback_sha256: String,
    /// Commitment to the independently retained queue observation report.
    pub observation_sha256: String,
    /// Actual hosted queue name, also used by the producer and consumer bindings.
    pub queue_name: String,
    /// Closed queue class: `content` or `metadata`.
    pub dependency_phase: String,
    /// Number of positively retained verification jobs.
    pub completed_jobs: WireInteger,
    /// Peak simultaneous jobs actually observed in this queue.
    pub peak_parallel_objects: WireInteger,
    /// Largest positively verified queue source size.
    pub maximum_verified_object_bytes: WireInteger,
    /// Source identity under which the queue measurements were collected.
    pub source_digest: String,
    /// Actual hosted script version under which jobs ran.
    pub script_version: String,
    /// Positive same-isolate metadata progress samples overlapping active bulk work.
    pub metadata_progress_during_bulk: WireInteger,
    /// Retained same-isolate overlap report commitment, required for metadata.
    pub mixed_load_observation_sha256: Option<String>,
}

impl DirectQueueMeasurement {
    fn validate(
        &self,
        artifact: &DirectWorkerQualificationArtifact,
        phase: &str,
        runtime: &DirectRuntimeQualification,
    ) -> Result<()> {
        let minimum_size = if phase == "content" {
            runtime.maximum_object_bytes.get()
        } else {
            // Qualification exercises the production narinfo semantic parser.
            runtime
                .maximum_object_bytes
                .get()
                .min(crate::fetch::MAX_CACHE_NARINFO_BYTES as u64)
        };
        let class_limit = if phase == "content" {
            runtime.maximum_parallel_objects.get().saturating_sub(1)
        } else {
            runtime.maximum_parallel_objects.get()
        };
        self.delivery_policy
            .validate_for_execution(class_limit, artifact.execution_kind)?;
        ensure!(
            valid_direct_queue_name(&self.queue_name)
                && self.dependency_phase == phase
                && valid_direct_digest(&self.observation_sha256)
                && valid_direct_digest(&self.configuration_readback_sha256)
                && self.completed_jobs.get() >= class_limit
                && self.peak_parallel_objects.get() == class_limit
                && self.maximum_verified_object_bytes.get() >= minimum_size
                && self.source_digest == artifact.source_digest
                && self.script_version == artifact.script_version,
            "direct accepted queue observations insufficient or changed"
        );
        ensure!(
            if phase == "metadata" {
                self.metadata_progress_during_bulk.get() > 0
                    && self
                        .mixed_load_observation_sha256
                        .as_deref()
                        .is_some_and(valid_direct_digest)
            } else {
                self.metadata_progress_during_bulk.get() == 0
                    && self.mixed_load_observation_sha256.is_none()
            },
            "direct metadata progress under bulk load unmeasured"
        );
        Ok(())
    }
}

/// Closed positive identity of an ordinary R2 acknowledged object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectHostedSdkObjectReceipt {
    /// Exact provider object version retained after positive Complete.
    pub version: String,
    /// Exact opaque provider ETag of the acknowledged object.
    pub etag: String,
    /// Acknowledged object size; retained wire spelling matches the SDK journal.
    pub byte_size: WireInteger,
}

/// Original actual hosted identity captured before the SDK probe's first effect.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectHostedSdkProbeOriginal {
    /// Exact fresh probe run identity.
    pub run_id: String,
    /// Actual R2 account hosting the protected selected bucket.
    pub account_id: String,
    /// Actual protected bucket name.
    pub bucket_name: String,
    /// Actual Cloudflare script version from the version metadata binding.
    pub script_version: String,
    /// Actual hosted Cloudflare edge location, never an emulator placeholder.
    pub colo: String,
}

/// Actual ordinary R2 SDK and direct S3 observations retained by a hosted probe.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectHostedSdkProbeDocument {
    /// Closed hosted probe format, currently one.
    pub version: u32,
    /// Exact hosted observation source, `hosted_ordinary_r2_binding`.
    pub source_kind: String,
    /// Exact source-built workers-rs version.
    pub workers_rs_version: String,
    /// Exact source digest of the hosted probe implementation.
    pub source_digest: String,
    /// Immutable original hosted probe identity.
    pub original: DirectHostedSdkProbeOriginal,
    /// SHA-256 of the fixed probe bytes positively read back after Complete.
    pub expected_sha256: String,
    /// Size of the fixed probe bytes.
    pub expected_byte_size: WireInteger,
    /// Exact checksum contract actually exercised by the direct S3 probe.
    pub upload_part_checksum_algorithm: DirectChecksumAlgorithm,
    /// Positive immutable source Complete receipt.
    pub source: DirectHostedSdkObjectReceipt,
    /// Positive separate streamed-copy Complete receipt.
    pub destination: DirectHostedSdkObjectReceipt,
    /// Observed ordinary Create outcome, required `positive`.
    pub ordinary_create: String,
    /// Observed ordinary Complete outcome, required `positive`.
    pub ordinary_complete: String,
    /// Observed ordinary Head outcome, required `positive`.
    pub ordinary_head: String,
    /// Observed streamed whole-object hash and size outcome, required `positive`.
    pub ordinary_get_streamed_sha_size: String,
    /// Observed streamed range hash and size outcome, required `positive`.
    pub ordinary_range_streamed_sha_size: String,
    /// Observed streamed range UploadPart copy outcome, required `positive`.
    pub ordinary_upload_part_streamed_copy: String,
    /// Observed ordinary Abort outcome, required `positive`.
    pub ordinary_abort: String,
    /// Positively identified late UploadPart refusal after Complete, `negative`.
    pub late_part_after_complete: String,
    /// Positively identified late UploadPart refusal after Abort, `negative`.
    pub late_part_after_abort: String,
    /// Commitment to the independently retained direct S3 checksum refusal response.
    pub direct_s3_checksum_rejection_sha256: String,
    /// Actual retained probe cleanup state; unknown effects cannot be erased.
    pub cleanup_state: String,
}

impl DirectHostedSdkProbeDocument {
    fn validate(
        &self,
        artifact: &DirectWorkerQualificationArtifact,
        profile: &DirectManagedR2Profile,
    ) -> Result<()> {
        let positive = [
            &self.ordinary_create,
            &self.ordinary_complete,
            &self.ordinary_head,
            &self.ordinary_get_streamed_sha_size,
            &self.ordinary_range_streamed_sha_size,
            &self.ordinary_upload_part_streamed_copy,
            &self.ordinary_abort,
        ];
        ensure!(
            self.version == 1
                && self.source_kind == "hosted_ordinary_r2_binding"
                && self.workers_rs_version == artifact.workers_rs_version
                && self.source_digest == artifact.source_digest
                && self.original.script_version == artifact.script_version
                && self.original.account_id == profile.account_id
                && self.original.bucket_name == profile.bucket_name
                && valid_direct_digest(&self.original.run_id)
                && self.original.colo.len() == 3
                && self
                    .original
                    .colo
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase())
                && valid_direct_digest(&self.expected_sha256)
                && self.upload_part_checksum_algorithm == profile.checksum_algorithm
                && self.expected_byte_size.get() > 0
                && self.source.byte_size == self.expected_byte_size
                && self.destination.byte_size == self.expected_byte_size
                && valid_direct_identity(&self.source.version)
                && valid_direct_identity(&self.destination.version)
                && self.source.version != self.destination.version
                && valid_receipt_text(&self.source.etag)
                && valid_receipt_text(&self.destination.etag)
                && positive
                    .iter()
                    .all(|outcome| outcome.as_str() == "positive")
                && self.late_part_after_complete == "negative"
                && self.late_part_after_abort == "negative"
                && valid_direct_digest(&self.direct_s3_checksum_rejection_sha256)
                && matches!(
                    self.cleanup_state.as_str(),
                    "retained_known_objects" | "removed_known_objects"
                ),
            "direct accepted hosted SDK observations incomplete or changed"
        );
        Ok(())
    }
}

/// Computes a canonical public measurement commitment without granting acceptance.
///
/// # Errors
/// Returns an error if the closed encoding exceeds protocol bounds.
pub fn direct_qualification_digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(encode_direct_control(value)?)))
}

/// Selects one signed acceptance for the exact unchanged deployed Worker version.
///
/// # Errors
/// Returns an error for invalid original deployment, source or script identity.
pub fn direct_worker_acceptance_key(
    deployment: &str,
    source: &str,
    script: &str,
) -> Result<String> {
    ensure!(
        valid_registry_identity(deployment)
            && valid_direct_digest(source)
            && valid_registry_identity(script),
        "direct acceptance registry identity invalid"
    );
    Ok(format!(
        "aos.direct-upload.acceptance.v1/{deployment}/{source}/{script}"
    ))
}

/// Checks an operator-supplied Cloudflare queue identifier.
#[must_use]
pub fn valid_direct_queue_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_receipt_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn valid_registry_identity(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(any(test, feature = "test-fixtures"))]
pub(crate) mod fixtures;

#[cfg(test)]
mod tests;
