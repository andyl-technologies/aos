//! Public release evidence and target qualification results.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::manifest::ReleaseManifestV1;
use crate::plan::ReleasePlan;
use crate::platform::Platform;

/// Schema for a destination-scoped qualification report at one hold point.
pub const QUALIFICATION_REPORT: &str = "aos.release.qualification-report/v1";
/// Schema for one execution case over public staging objects.
pub const QUALIFICATION_EXECUTOR_REQUEST: &str = "aos.release.qualification-executor-request/v1";
/// Schema for one platform executor's canonical response.
pub const QUALIFICATION_EXECUTOR_RESPONSE: &str = "aos.release.qualification-executor-response/v1";

/// One immutable public staging object supplied to a qualification executor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationObject {
    /// Manifest artifact identity.
    pub artifact_id: String,
    /// Anonymous HTTPS URL from which the exact staged bytes must be read.
    pub url: String,
    /// Exact expected byte length.
    pub size_bytes: u64,
    /// Exact expected SHA-256 digest.
    pub sha256: Sha256Digest,
}

/// One verified object from a retained, non-public predecessor bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRetainedObject {
    /// Manifest artifact identity in the predecessor release.
    pub artifact_id: String,
    /// Absolute local path from which the executor must recapture the bytes.
    pub source_path: String,
    /// Exact expected byte length.
    pub size_bytes: u64,
    /// Exact expected SHA-256 digest.
    pub sha256: Sha256Digest,
}

/// One public verification key supplied with a retained predecessor bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTrustedKey {
    /// Stable manifest signer key identity.
    pub key_id: String,
    /// Exact Ed25519 public key as 64 lowercase hexadecimal digits.
    pub public_key_hex: String,
}

/// Closed local input needed to reverify and exercise a prior release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRetainedBundle {
    /// Absolute root of the complete retained predecessor bundle.
    pub bundle_path: String,
    /// Exact predecessor subject graph recaptured before scenario execution.
    pub objects: Vec<QualificationRetainedObject>,
    /// Ordered public keys with which the executor reverifies the bundle.
    pub trusted_keys: Vec<QualificationTrustedKey>,
}

/// Closed request for one planned gate on one artifact-bearing platform.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationExecutorRequest {
    /// Exact request schema identifier.
    pub schema_version: String,
    /// Applicable shared-contract execution case.
    pub qualification_case: crate::qualification_evidence::QualificationCase,
    /// Canonical registry identity.
    pub registry: String,
    /// Immutable release identity.
    pub release_id: String,
    /// Digest of the signed staging publication receipt.
    pub staging_receipt_digest: Sha256Digest,
    /// Final release-manifest payload digest.
    pub manifest_digest: Sha256Digest,
    /// Planned gate identifier.
    pub policy_id: String,
    /// Digest of the exact planned gate policy.
    pub policy_digest: Sha256Digest,
    /// Native platform on which the executor must run.
    pub platform: Platform,
    /// Artifact identities the gate result must cover.
    pub subjects: Vec<String>,
    /// Complete immutable public staging object inventory.
    pub objects: Vec<QualificationObject>,
    /// Verified local predecessor input required by an update case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_predecessor: Option<QualificationRetainedBundle>,
    /// Coordinator-chosen replay-resistant request nonce.
    pub nonce: String,
}

impl QualificationExecutorRequest {
    /// Validates the closed executor request and public object inventory.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, ordering, subject, URL, or
    /// nonce fields.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != QUALIFICATION_EXECUTOR_REQUEST {
            bail!("unsupported qualification executor request schema");
        }
        let case = &self.qualification_case;
        if case.requirement_id != self.policy_id
            || case.policy_digest != self.policy_digest
            || case.subjects != self.subjects
            || case
                .platform
                .is_some_and(|platform| platform != self.platform)
        {
            bail!("qualification request differs from its exact execution case");
        }
        require_identifier(&self.registry, "qualification registry")?;
        require_identifier(&self.release_id, "qualification release id")?;
        require_identifier(&self.policy_id, "qualification policy id")?;
        if self.nonce.len() < 32 || !self.nonce.is_ascii() {
            bail!("qualification request nonce must contain at least 32 ASCII bytes");
        }
        if self.subjects.is_empty()
            || self.subjects.windows(2).any(|pair| pair[0] >= pair[1])
            || self.objects.is_empty()
            || self
                .objects
                .windows(2)
                .any(|pair| pair[0].artifact_id >= pair[1].artifact_id)
        {
            bail!("qualification subjects and objects must be nonempty, unique, and sorted");
        }
        let object_ids = self
            .objects
            .iter()
            .map(|object| object.artifact_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for object in &self.objects {
            require_identifier(&object.artifact_id, "qualification object id")?;
            if !object.url.starts_with("https://")
                || object.url.contains('@')
                || object.url.contains('#')
                || object.url.contains('?')
            {
                bail!("qualification object URL must be anonymous immutable HTTPS");
            }
        }
        if self
            .subjects
            .iter()
            .any(|subject| !object_ids.contains(subject.as_str()))
        {
            bail!("qualification request subject is absent from its public object inventory");
        }
        match (&case.predecessor, &self.retained_predecessor) {
            (Some(_), Some(retained)) => retained.validate(&self.subjects)?,
            (Some(_), None) => {
                bail!("qualification update request lacks its exact predecessor bundle")
            }
            (None, Some(_)) => {
                bail!("qualification request has a predecessor bundle without an update case")
            }
            (None, None) => {}
        }
        Ok(())
    }

    /// Computes the domain-separated canonical request digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be canonically encoded.
    pub fn digest(&self) -> Result<Sha256Digest> {
        Sha256Digest::of_canonical(QUALIFICATION_EXECUTOR_REQUEST, self)
    }
}

impl QualificationRetainedBundle {
    fn validate(&self, subjects: &[String]) -> Result<()> {
        let bundle = std::path::Path::new(&self.bundle_path);
        if !normalized_absolute_path(bundle) {
            bail!("qualification predecessor bundle path must be absolute and normalized");
        }
        if self.objects.is_empty()
            || self
                .objects
                .windows(2)
                .any(|pair| pair[0].artifact_id >= pair[1].artifact_id)
        {
            bail!("qualification predecessor objects must be nonempty, unique, and sorted");
        }
        for object in &self.objects {
            require_identifier(&object.artifact_id, "qualification predecessor object id")?;
            let path = std::path::Path::new(&object.source_path);
            if !normalized_absolute_path(path) || !path.starts_with(bundle) {
                bail!("qualification predecessor object path escapes its retained bundle");
            }
        }
        let object_ids = self
            .objects
            .iter()
            .map(|object| object.artifact_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if !object_ids.contains("control/release-manifest-envelope")
            || subjects
                .iter()
                .any(|subject| !object_ids.contains(subject.as_str()))
        {
            bail!("qualification update request lacks its exact predecessor object graph");
        }
        if self.trusted_keys.is_empty()
            || self
                .trusted_keys
                .windows(2)
                .any(|pair| pair[0].key_id >= pair[1].key_id)
        {
            bail!("qualification predecessor keys must be nonempty, unique, and sorted");
        }
        for key in &self.trusted_keys {
            require_identifier(&key.key_id, "qualification predecessor key id")?;
            if key.public_key_hex.len() != 64
                || !key
                    .public_key_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("qualification predecessor key must be lowercase hexadecimal Ed25519 bytes");
            }
        }
        Ok(())
    }
}

fn normalized_absolute_path(path: &std::path::Path) -> bool {
    path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

/// Canonical response emitted by a bounded native qualification executor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationExecutorResponse {
    /// Exact response schema identifier.
    pub schema_version: String,
    /// Digest of the exact canonical request read by the executor.
    pub request_digest: Sha256Digest,
    /// Closed public evidence record derived by the executor.
    pub evidence: EvidenceRecord,
    /// Public machine-readable gate report retained by the coordinator.
    pub report: serde_json::Value,
}

/// Closed result of a release gate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateResult {
    /// The selected policy passed.
    Passed,
    /// The selected policy failed and blocks the relevant transition.
    Failed,
}

/// Public, non-sensitive result of one versioned release gate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    /// Structured observations for shared-contract evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification: Option<crate::qualification_evidence::QualificationObservation>,
    /// Stable evidence identity unique within the release.
    pub id: String,
    /// Versioned gate or qualification policy identifier.
    pub policy_id: String,
    /// Digest of the exact policy bytes.
    pub policy_digest: Sha256Digest,
    /// Platform qualified by this evidence, when target-specific.
    pub platform: Option<Platform>,
    /// Artifact identities covered by the result.
    pub subjects: Vec<String>,
    /// Closed gate result.
    pub result: GateResult,
    /// Digest of the public report file in the release bundle.
    pub report_digest: Sha256Digest,
    /// Public executor or authority identity.
    pub authority_id: String,
    /// Nonce binding remote qualification to the release request.
    pub nonce: Option<String>,
    /// RFC 3339 UTC start time supplied by the executor.
    pub started_at: String,
    /// RFC 3339 UTC finish time supplied by the executor.
    pub finished_at: String,
}

impl EvidenceRecord {
    /// Validates stable identifiers and nonempty subject/time fields.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers, an empty or duplicate
    /// subject set, an empty time, or an empty nonce when present.
    pub fn validate(&self) -> Result<()> {
        require_identifier(&self.id, "evidence id")?;
        require_identifier(&self.policy_id, "evidence policy id")?;
        require_identifier(&self.authority_id, "evidence authority id")?;
        if self.subjects.is_empty() {
            bail!("evidence {} must cover at least one subject", self.id);
        }
        for subject in &self.subjects {
            require_identifier(subject, "evidence subject")?;
        }
        let mut subjects = self.subjects.clone();
        subjects.sort();
        if subjects.windows(2).any(|pair| pair[0] == pair[1]) {
            bail!("evidence {} contains a duplicate subject", self.id);
        }
        if self.started_at.trim().is_empty() || self.finished_at.trim().is_empty() {
            bail!("evidence {} has an empty time", self.id);
        }
        if self.nonce.as_ref().is_some_and(|nonce| nonce.is_empty()) {
            bail!("evidence {} has an empty nonce", self.id);
        }
        Ok(())
    }
}

/// Destination-scoped evidence over exact published release bytes at one hold point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReport {
    /// Coordinator-derived claim outcomes at admission.
    pub claims: Vec<crate::qualification::claims::ClaimOutcome>,
    /// Planned destination whose profile selected the evidence.
    pub destination: String,
    /// Hold point the evidence authorizes.
    pub phase: crate::qualification::QualificationPhase,
    /// Admission time bound by the qualification authority's signature.
    pub admitted_at: String,
    /// Exact report schema identifier.
    pub schema_version: String,
    /// Digest of the signed staging publication receipt.
    pub staging_receipt_digest: Sha256Digest,
    /// Final release-manifest payload digest.
    pub manifest_digest: Sha256Digest,
    /// Public executor records in stable evidence-id order.
    pub evidence: Vec<EvidenceRecord>,
}

impl QualificationReport {
    /// Recomputes stored assurance results and checks freshness at a hold point.
    ///
    /// Results describe the report's signed admission time. A later consumer
    /// also checks evidence at its own trusted time before authorizing effects.
    /// `destination` names the planned destination whose profile selects the
    /// evidence; it must equal the signed field so a report cannot be replayed
    /// for another destination.
    ///
    /// # Errors
    /// Returns an error for an unsupported schema, a wrong phase or
    /// destination, fabricated assurance, future admission time or unmet
    /// release-blocking obligations.
    pub fn validate_phase(
        &self,
        plan: &ReleasePlan,
        manifest: &ReleaseManifestV1,
        destination: &str,
        phase: crate::qualification::QualificationPhase,
        now: &str,
    ) -> Result<()> {
        if self.phase != phase || self.schema_version != QUALIFICATION_REPORT {
            bail!("qualification report schema or phase differs from its contract");
        }
        if self.destination != destination {
            bail!("qualification report destination differs from the requested destination");
        }
        if humantime::parse_rfc3339(&self.admitted_at)? > humantime::parse_rfc3339(now)? {
            bail!("report admission time is in the future");
        }

        let derived = crate::qualification_evidence::assess_observations(
            plan,
            manifest,
            Some(destination),
            phase,
            &self.evidence,
            &self.admitted_at,
            None,
        )?;
        if self.claims != derived {
            bail!("reported assurance differs from independently validated evidence");
        }
        crate::qualification_evidence::validate_observations(
            plan,
            manifest,
            Some(destination),
            phase,
            &self.evidence,
            now,
            None,
        )
    }

    /// Validates a staging report against exact staged release bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for identity drift or any
    /// [`QualificationReport::validate_phase`] failure at the staging hold
    /// point, evaluated at the report's own admission time.
    pub fn validate(
        &self,
        plan: &ReleasePlan,
        manifest: &ReleaseManifestV1,
        staging_receipt_digest: Sha256Digest,
        manifest_digest: Sha256Digest,
    ) -> Result<()> {
        if self.staging_receipt_digest != staging_receipt_digest
            || self.manifest_digest != manifest_digest
        {
            bail!("qualification report identity differs from staged release bytes");
        }
        self.validate_phase(
            plan,
            manifest,
            &self.destination,
            crate::qualification::QualificationPhase::Staging,
            &self.admitted_at,
        )
    }
}

/// Frozen requirement for one versioned gate.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateRequirement {
    /// Stable gate identifier.
    pub policy_id: String,
    /// Digest of exact gate policy bytes.
    pub policy_digest: Sha256Digest,
    /// Whether a failed or missing result blocks the destination: always true
    /// for requirements, and the claim's `blocks_release` for claims.
    pub blocking: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qualification::{QualificationMethod, QualificationPhase};
    use crate::qualification_evidence::QualificationCase;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::of_bytes(label.as_bytes())
    }

    #[test]
    fn executor_request_closes_public_objects_and_subjects() {
        let subjects = vec!["package/example/aarch64-darwin".to_owned()];
        let request = QualificationExecutorRequest {
            qualification_case: QualificationCase {
                schema_version: crate::qualification_evidence::QUALIFICATION_CASE.to_owned(),
                claim: None,
                measurements: std::collections::BTreeMap::new(),
                minimum_observed_seconds: None,
                id: "package-function-example".to_owned(),
                requirement_id: "package-function".to_owned(),
                native_operation_spec: None,
                policy_digest: digest("policy"),
                plan_digest: digest("plan"),
                subjects_digest: digest("subjects"),
                phase: QualificationPhase::Staging,
                platform: Some(Platform::Aarch64Darwin),
                package_role: None,
                target: None,
                subjects: subjects.clone(),
                checks: vec!["installs".to_owned()],
                method: QualificationMethod::Automated,
                predecessor: None,
            },
            schema_version: QUALIFICATION_EXECUTOR_REQUEST.to_owned(),
            registry: crate::registry::MAIN_REGISTRY.to_owned(),
            release_id: "release-2026.9.0".to_owned(),
            staging_receipt_digest: digest("staging"),
            manifest_digest: digest("manifest"),
            policy_id: "package-function".to_owned(),
            policy_digest: digest("policy"),
            platform: Platform::Aarch64Darwin,
            subjects,
            objects: vec![QualificationObject {
                artifact_id: "package/example/aarch64-darwin".to_owned(),
                url: "https://aos.staging.andyl.org/andyl/main/packages/example.nar".to_owned(),
                size_bytes: 42,
                sha256: digest("package"),
            }],
            retained_predecessor: None,
            nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        };
        assert!(request.validate().is_ok());

        let mut missing = request.clone();
        missing.subjects = vec!["package/not-present".to_owned()];
        assert!(missing.validate().is_err());

        let mut other_case = request.clone();
        other_case.qualification_case.requirement_id = "image-lifecycle".to_owned();
        assert!(other_case.validate().is_err());

        let mut mutable_url = request;
        mutable_url.objects[0].url.push_str("?token=secret");
        assert!(mutable_url.validate().is_err());
    }
}
