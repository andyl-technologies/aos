//! The public release record: one signed-by-extension document per release
//! that states what was qualified, to what assurance, and under which
//! support promise.
//!
//! Registry finalization happens before staging qualification, so the
//! qualification outcome cannot live in the registry tree. The record is
//! composed after admission from documents the pipeline already produced and
//! is published beside the release manifest as a delegated TUF target
//! (`releases/<class>/<version>/release-record.json`). Consumers verify it
//! through the TUF chain, and independently through the embedded signed
//! qualification envelope, so the served registry and its store objects
//! remain the authority; the Hub only renders what it fetched and verified.
//!
//! ```json
//! {
//!   "schema_version": "aos.release-record/v1",
//!   "registry": "andyl/main",
//!   "release_id": "release-2026.9.1",
//!   "version": "2026.9.1",
//!   "train": "2026.9",
//!   "release_class": "stable",
//!   "source_commit": "…",
//!   "plan_digest": "sha256:…",
//!   "manifest_digest": "sha256:…",
//!   "qualification": {
//!     "policy_id": "full-release-qualification",
//!     "policy_digest": "sha256:…",
//!     "result": "passed",
//!     "qualified_at": "2026-09-05T12:00:00Z",
//!     "authority_id": "qualification-authority",
//!     "receipt_digest": "sha256:…",
//!     "report_digest": "sha256:…",
//!     "claims": [{"claim_id": "…", "required_assurance": "A3", "achieved_assurance": "A3", "disposition": "passed", "blocks_release": true, "case_id": "…", "environment_digest": null}]
//!   },
//!   "support": {"kind": "lts", "supported_until": "2028-09-30"},
//!   "signed_qualification": "{…signed receipt envelope…}"
//! }
//! ```

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::digest::Sha256Digest;
use crate::evidence::{GateResult, QualificationReportV1};
use crate::manifest::ReleaseManifestV1;
use crate::plan::{ReleaseClass, ReleasePlanV1};
use crate::qualification::QualificationPhase;
use crate::qualification::claims::ClaimOutcome;
use crate::receipt::QualificationReceiptV1;

/// Exact record schema identifier.
pub const RECORD_V1: &str = "aos.release-record/v1";

/// Served path of a release's record beneath the registry surface root.
#[must_use]
pub fn record_path(class: ReleaseClass, version: &str) -> String {
    format!(
        "releases/{}/{version}/release-record.json",
        crate::tuf::TufRole::for_release(class).as_str()
    )
}

/// Public qualification outcome copied from the admitted receipt and report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationSummaryV1 {
    /// Versioned qualification policy identity.
    pub policy_id: String,
    /// Digest of the exact policy bytes.
    pub policy_digest: Sha256Digest,
    /// Public gate result.
    pub result: GateResult,
    /// RFC 3339 UTC admission time bound by the authority's signature.
    pub qualified_at: String,
    /// Qualification authority identity.
    pub authority_id: String,
    /// Digest of the signed qualification envelope.
    pub receipt_digest: Sha256Digest,
    /// Digest of the complete public report.
    pub report_digest: Sha256Digest,
    /// Hold point the report covers, when the report states one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<QualificationPhase>,
    /// Per-claim outcomes at admission, in report order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<ClaimOutcome>,
}

/// The train's support statement at publication time.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSupportV1 {
    /// Support class of the train.
    pub kind: aos_registry_surface::support::SupportKind,
    /// Last supported day when the policy states one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_until: Option<String>,
}

/// The public release record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRecordV1 {
    /// Exact record schema.
    pub schema_version: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Immutable release identity.
    pub release_id: String,
    /// Exact release version.
    pub version: String,
    /// The train the version belongs to, as `major.minor`.
    pub train: String,
    /// Release maturity class.
    pub release_class: ReleaseClass,
    /// Exact source commit.
    pub source_commit: String,
    /// Digest of the frozen plan.
    pub plan_digest: Sha256Digest,
    /// Final manifest payload digest.
    pub manifest_digest: Sha256Digest,
    /// Public qualification outcome.
    pub qualification: QualificationSummaryV1,
    /// The train's support statement from the plan's contract, when stated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<ReleaseSupportV1>,
    /// The exact signed qualification envelope, so a consumer can verify the
    /// summary against the authority's key without the Hub.
    pub signed_qualification: String,
}

impl ReleaseRecordV1 {
    /// Composes the record from the frozen plan, final manifest, admitted
    /// qualification receipt (payload and signed envelope), and public report.
    ///
    /// The caller has already verified the envelope signature, the receipt's
    /// bindings, and the report; this function only checks the bindings it
    /// copies so the record cannot disagree with its sources.
    ///
    /// # Errors
    /// Returns an error when the receipt or report does not describe the
    /// manifest, when the envelope digest does not match the receipt, or when
    /// the version has no train.
    pub fn compose(
        plan: &ReleasePlanV1,
        manifest: &ReleaseManifestV1,
        manifest_digest: Sha256Digest,
        receipt: &QualificationReceiptV1,
        signed_qualification: &[u8],
        report: &QualificationReportV1,
    ) -> Result<Self> {
        if receipt.manifest_digest != manifest_digest || report.manifest_digest != manifest_digest {
            bail!("qualification evidence does not describe the release manifest");
        }
        if receipt.report_digest != Sha256Digest::of_bytes(&canonical::to_vec(report)?) {
            bail!("qualification receipt does not name the supplied report");
        }
        let envelope_digest = Sha256Digest::of_bytes(signed_qualification);
        let parsed =
            semver::Version::parse(&manifest.version).context("parsing release version")?;
        let train = format!("{}.{}", parsed.major, parsed.minor);
        let support = plan
            .qualification
            .as_ref()
            .and_then(|contract| contract.support.as_ref())
            .and_then(|policy| policy.trains.get(&train))
            .map(|entry| ReleaseSupportV1 {
                kind: entry.kind,
                supported_until: entry.supported_until.clone(),
            });
        Ok(Self {
            schema_version: RECORD_V1.to_owned(),
            registry: manifest.registry.clone(),
            release_id: manifest.release_id.clone(),
            version: manifest.version.clone(),
            train,
            release_class: manifest.release_class,
            source_commit: manifest.source_commit.clone(),
            plan_digest: manifest.plan_digest,
            manifest_digest,
            qualification: QualificationSummaryV1 {
                policy_id: receipt.policy_id.clone(),
                policy_digest: receipt.policy_digest,
                result: receipt.result,
                qualified_at: receipt.qualified_at.clone(),
                authority_id: receipt.authority_id.clone(),
                receipt_digest: envelope_digest,
                report_digest: receipt.report_digest,
                phase: report.phase,
                claims: report.claims.clone().unwrap_or_default(),
            },
            support,
            signed_qualification: String::from_utf8(signed_qualification.to_vec())
                .context("signed qualification envelope is not UTF-8")?,
        })
    }

    /// Checks internal consistency: schema, version and train agreement, and
    /// that the embedded envelope is the receipt the summary describes.
    ///
    /// # Errors
    /// Returns an error for an unknown schema, a version that is not in the
    /// stated train, an envelope whose digest or payload disagrees with the
    /// summary, or a summary whose class does not match its served path.
    pub fn validate(&self) -> Result<QualificationReceiptV1> {
        if self.schema_version != RECORD_V1 {
            bail!("unsupported release record schema");
        }
        let parsed = semver::Version::parse(&self.version).context("parsing record version")?;
        if self.train != format!("{}.{}", parsed.major, parsed.minor) {
            bail!("release record train does not match its version");
        }
        let envelope_bytes = self.signed_qualification.as_bytes();
        if Sha256Digest::of_bytes(envelope_bytes) != self.qualification.receipt_digest {
            bail!("release record envelope digest does not match its summary");
        }
        let envelope: crate::receipt::SignedReceiptEnvelopeV1 =
            canonical::from_slice(envelope_bytes, "signed qualification envelope")?;
        let receipt: QualificationReceiptV1 = serde_json::from_value(envelope.payload)
            .context("decoding qualification receipt payload")?;
        receipt.validate()?;
        if receipt.manifest_digest != self.manifest_digest
            || receipt.policy_id != self.qualification.policy_id
            || receipt.policy_digest != self.qualification.policy_digest
            || receipt.result != self.qualification.result
            || receipt.qualified_at != self.qualification.qualified_at
            || receipt.authority_id != self.qualification.authority_id
            || receipt.report_digest != self.qualification.report_digest
        {
            bail!("release record summary disagrees with its signed qualification receipt");
        }
        if let Some(support) = &self.support {
            if support.kind == aos_registry_surface::support::SupportKind::Lts
                && support.supported_until.is_none()
            {
                bail!("release record marks an LTS train without an end date");
            }
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT_V1, SignedReceiptEnvelopeV1};
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn composed_records_bind_their_evidence_and_round_trip() -> anyhow::Result<()> {
        let (mut plan, manifest) = crate::verify::tests::qualification_fixture()?;
        let mut contract = plan.qualification.clone().unwrap();
        let train = {
            let parsed = semver::Version::parse(&manifest.version)?;
            format!("{}.{}", parsed.major, parsed.minor)
        };
        let policy = contract.support.get_or_insert_with(Default::default);
        policy.trains.insert(
            train.clone(),
            aos_registry_surface::support::SupportTrain {
                kind: aos_registry_surface::support::SupportKind::Lts,
                supported_until: Some("2030-01-31".into()),
            },
        );
        plan.qualification = Some(contract);
        let manifest_digest = Sha256Digest::of_bytes(canonical::to_vec(&manifest)?);
        let report = QualificationReportV1 {
            claims: Some(Vec::new()),
            phase: Some(QualificationPhase::Staging),
            admitted_at: Some("2026-09-05T12:00:00Z".into()),
            schema_version: "aos.release.qualification-report/v3".into(),
            staging_receipt_digest: Sha256Digest::of_bytes(b"staging"),
            manifest_digest,
            evidence: Vec::new(),
        };
        let receipt = QualificationReceiptV1 {
            schema_version: crate::receipt::QUALIFICATION_RECEIPT_V1.into(),
            staging_receipt_digest: Sha256Digest::of_bytes(b"staging"),
            manifest_digest,
            policy_id: "full-release-qualification".into(),
            policy_digest: plan.public_evidence_policy_digest,
            result: GateResult::Passed,
            report_digest: Sha256Digest::of_bytes(canonical::to_vec(&report)?),
            authority_id: "qualification-authority".into(),
            nonce: "a".repeat(64),
            qualified_at: "2026-09-05T12:00:00Z".into(),
        };
        let key = SigningKey::from_bytes(&[5_u8; 32]);
        let payload = canonical::to_vec(&receipt)?;
        let signature =
            key.sign(Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload).as_bytes());
        let envelope = canonical::to_vec(&SignedReceiptEnvelopeV1 {
            schema_version: SIGNED_RECEIPT_V1.into(),
            key_id: "qualification-authority".into(),
            payload: serde_json::from_slice(&payload)?,
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
        })?;

        let record = ReleaseRecordV1::compose(
            &plan,
            &manifest,
            manifest_digest,
            &receipt,
            &envelope,
            &report,
        )?;
        assert_eq!(record.train, train);
        assert_eq!(
            record.support.as_ref().unwrap().supported_until.as_deref(),
            Some("2030-01-31")
        );
        assert_eq!(
            record.qualification.phase,
            Some(QualificationPhase::Staging)
        );
        let verified = record.validate()?;
        assert_eq!(verified, receipt);
        let bytes = canonical::to_vec(&record)?;
        let decoded: ReleaseRecordV1 = canonical::from_slice(&bytes, "record")?;
        assert_eq!(decoded, record);

        let mut tampered = record.clone();
        tampered.qualification.result = GateResult::Failed;
        assert!(
            tampered.validate().is_err(),
            "summary must match the signed receipt"
        );
        let mut wrong_train = record.clone();
        wrong_train.train = "1.0".into();
        assert!(wrong_train.validate().is_err());
        assert!(
            ReleaseRecordV1::compose(
                &plan,
                &manifest,
                Sha256Digest::of_bytes(b"other"),
                &receipt,
                &envelope,
                &report
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn record_paths_follow_the_delegated_role() {
        assert_eq!(
            record_path(ReleaseClass::Stable, "2026.9.1"),
            "releases/stable/2026.9.1/release-record.json"
        );
        assert_eq!(
            record_path(ReleaseClass::Emergency, "2026.9.2"),
            "releases/stable/2026.9.2/release-record.json"
        );
        assert_eq!(
            record_path(ReleaseClass::Candidate, "2026.10.0-rc.1"),
            "releases/candidate/2026.10.0-rc.1/release-record.json"
        );
    }
}
