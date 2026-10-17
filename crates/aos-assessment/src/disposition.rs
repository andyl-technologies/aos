//! Exact reviewed applicability statements, separate from raw advisory matches.
//!
//! Structural validation and deterministic replay do not grant review authority.
//! Hosts verify detached signatures, issuer scope and revocation before admitting
//! a statement. Reproduced imports never become authorized release exceptions.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::time::Timestamp;
use crate::validation::{digest, sorted, text};

/// Identifies an exact immutable reviewed applicability statement.
pub const SECURITY_DISPOSITION_V1: &str = "aos.security-disposition/v1";

/// Preserves interoperable applicability independently from risk acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DispositionStatus {
    /// Confirms the raw affected claim.
    Affected,
    /// Records specifically justified inapplicability to this component.
    NotAffected,
    /// Records a verified fix in this exact component/artifact.
    Fixed,
    /// Preserves an unresolved applicability review.
    UnderInvestigation,
}

/// Binds a reviewed claim to exact component and advisory revision evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecurityDispositionV1 {
    /// Exact schema discriminator.
    pub schema: String,
    /// Exact component instance including patches/configuration/containing bytes.
    pub component_instance_digest: Sha256Digest,
    /// Exact sorted advisory revisions reviewed by the statement.
    pub advisory_record_digests: Vec<Sha256Digest>,
    /// Explicit applicability status; never an alert acknowledgement.
    pub status: DispositionStatus,
    /// Stable OpenVEX-compatible justification or fix proof class.
    pub justification: String,
    /// Bounded technical explanation, separate from provider error text.
    pub explanation: String,
    /// Sorted exact patch/build/runtime evidence supporting the claim.
    pub evidence_digests: Vec<Sha256Digest>,
    /// Stable issuer identity whose signature is verified by the admitting host.
    pub issuer: String,
    /// Stable reviewer identity authorized for the exact publication/scope.
    pub reviewer: String,
    /// Exact authority-policy admission evidence, not a self-issued trusted flag.
    pub authorization_digest: Sha256Digest,
    /// Inclusive statement validity start.
    pub valid_from: Timestamp,
    /// Exclusive statement validity end; statements cannot last indefinitely.
    pub expires_at: Timestamp,
}

impl SecurityDispositionV1 {
    /// Validates bounded statement structure without granting issuer authority.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible schemas, invalid time bounds, missing
    /// exact scopes/proofs, oversized text or unordered evidence identities.
    pub fn validate(&self) -> Result<()> {
        if self.schema != SECURITY_DISPOSITION_V1 || self.valid_from >= self.expires_at {
            bail!("invalid security disposition schema or validity interval");
        }
        if self.advisory_record_digests.is_empty()
            || self.advisory_record_digests.len() > 128
            || self.evidence_digests.len() > 128
        {
            bail!("security disposition requires bounded exact advisory scope");
        }
        sorted(
            &self.advisory_record_digests,
            "disposition advisory revisions",
        )?;
        sorted(&self.evidence_digests, "disposition supporting evidence")?;
        for (field, value, maximum) in [
            (
                "disposition justification",
                self.justification.as_str(),
                128,
            ),
            ("disposition explanation", self.explanation.as_str(), 4096),
            ("disposition issuer", self.issuer.as_str(), 128),
            ("disposition reviewer", self.reviewer.as_str(), 128),
        ] {
            text(value, maximum, field)?;
        }
        if matches!(
            self.status,
            DispositionStatus::NotAffected | DispositionStatus::Fixed
        ) && self.evidence_digests.is_empty()
        {
            bail!("a resolving disposition requires exact supporting evidence");
        }
        Ok(())
    }

    /// Computes the immutable statement identity after structural validation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid structure or canonical resource bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        digest(SECURITY_DISPOSITION_V1, self)
    }

    /// Tests exact component/revision scope and explicit validity time.
    #[must_use]
    pub fn applies_at(
        &self,
        component: Sha256Digest,
        advisory: Sha256Digest,
        evaluated_at: &Timestamp,
    ) -> bool {
        self.component_instance_digest == component
            && self
                .advisory_record_digests
                .binary_search(&advisory)
                .is_ok()
            && evaluated_at >= &self.valid_from
            && evaluated_at < &self.expires_at
    }
}
