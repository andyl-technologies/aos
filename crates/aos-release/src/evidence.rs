//! Public release evidence and target qualification results.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::platform::Platform;

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

/// Frozen requirement for one versioned gate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateRequirement {
    /// Stable gate identifier.
    pub policy_id: String,
    /// Digest of exact gate policy bytes.
    pub policy_digest: Sha256Digest,
    /// Whether this gate is required before stable authorization.
    pub required_for_stable: bool,
}
