//! Failure kinds and canonical signature-key policies.

use super::*;

/// Closed failure discriminant carried by a triage signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailureKind {
    /// The recorded run contains a failed assertion or property violation.
    PropertyViolation,
    /// The recorded run diverged from deterministic replay and was localized by bisection.
    Divergence,
    /// The recorded run exhausted a deterministic execution budget.
    Timeout,
}

/// Closed execution-budget domains that can produce a timeout finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailureTimeoutBudgetKind {
    /// The run exhausted its scheduler quantum allowance.
    ExecutionQuanta,
    /// The run reached its configured virtual-time boundary.
    VirtualTime,
}

/// Stable property identity carried by a property-violation signature.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailurePropertyKey {
    /// Stable assertion or property identifier read from the violation record.
    pub id: AssertionId,
    /// Quantifier or guest marker flavor read from the violation record.
    pub quantifier: AssertionQuantifierKind,
}

/// First attributable point for one recorded failure.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureFirstFailingPoint {
    /// Open-set event kind attached to the violation site or bisection point.
    pub event_kind: String,
    /// Scenario node that owns the failure site, when the record is node-local.
    pub faulting_node: Option<NodeId>,
}

/// Bucketed coverage class used by the first failure-signature model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureCoverageClass {
    /// Versioned bucketing algorithm used for this class.
    pub algorithm: &'static str,
    /// Coarse deterministic bucket derived from the coverage fingerprint.
    pub bucket: u16,
}

impl FailureCoverageClass {
    /// Builds a bucketed class from a deterministic coverage fingerprint.
    #[must_use]
    pub fn from_coverage_fingerprint(coverage_fingerprint: ContentHash) -> Self {
        Self {
            algorithm: FAILURE_COVERAGE_CLASS_ALGORITHM,
            bucket: u16::from_be_bytes([
                coverage_fingerprint.bytes[0],
                coverage_fingerprint.bytes[1],
            ]),
        }
    }
}

/// Closed failure-signature policy levels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignaturePolicyLevel {
    /// Clusters by failure kind and stable property id.
    Coarse,
    /// Clusters by the everyday failure key used by default triage.
    #[default]
    Default,
    /// Adds the cone-scoped causal slice hash to separate code paths.
    Fine,
    /// Adds absolute icount and full causal-cone material for forensic runs.
    Exact,
}

/// Versioned selector for failure-signature key fields.
///
/// The policy is closed over the four RFC0010 levels and records the schema
/// version plus coverage-class bucketing algorithm in every key projection and
/// triage result identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignaturePolicy {
    pub(in crate::model) level: SignaturePolicyLevel,
}

impl SignaturePolicy {
    /// Returns the coarse clustering policy.
    #[must_use]
    pub fn coarse() -> Self {
        Self {
            level: SignaturePolicyLevel::Coarse,
        }
    }

    /// Returns the default clustering policy.
    #[must_use]
    pub fn default_policy() -> Self {
        Self {
            level: SignaturePolicyLevel::Default,
        }
    }

    /// Returns the fine-grained clustering policy.
    #[must_use]
    pub fn fine() -> Self {
        Self {
            level: SignaturePolicyLevel::Fine,
        }
    }

    /// Returns the exact forensic clustering policy.
    #[must_use]
    pub fn exact() -> Self {
        Self {
            level: SignaturePolicyLevel::Exact,
        }
    }

    /// Returns the closed policy level.
    #[must_use]
    pub fn level(&self) -> SignaturePolicyLevel {
        self.level
    }

    /// Returns the versioned policy schema identifier.
    #[must_use]
    pub fn schema_version(&self) -> u16 {
        SIGNATURE_POLICY_SCHEMA_VERSION
    }

    /// Returns the fixed coverage-class bucketing algorithm selected by policy.
    #[must_use]
    pub fn coverage_class_algorithm(&self) -> &'static str {
        FAILURE_COVERAGE_CLASS_ALGORITHM
    }

    /// Returns whether this policy allows minimization merges.
    ///
    /// `exact` is forensic and must not minimize-merge.
    #[must_use]
    pub fn allows_minimize_merge(&self) -> bool {
        !matches!(self.level, SignaturePolicyLevel::Exact)
    }

    /// Returns whether the causal slice hash is a key field.
    #[must_use]
    pub fn keys_causal_slice_hash(&self) -> bool {
        matches!(
            self.level,
            SignaturePolicyLevel::Fine | SignaturePolicyLevel::Exact
        )
    }

    /// Returns whether absolute icount is a key field.
    #[must_use]
    pub fn keys_absolute_icount(&self) -> bool {
        matches!(self.level, SignaturePolicyLevel::Exact)
    }

    /// Projects `signature` into this policy's deterministic key.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] if the
    /// signature's coverage bucket was built by a different algorithm, or if the
    /// exact policy is requested for a signature that does not retain full
    /// causal-cone material.
    pub fn signature_key(
        &self,
        signature: &FailureSignature,
    ) -> Result<FailureSignatureKey, EngineError> {
        if signature.coverage_class.algorithm != self.coverage_class_algorithm() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-signature.policy",
                reason: "signature coverage class algorithm does not match policy",
            });
        }
        if self.level == SignaturePolicyLevel::Exact && signature.causal_cone.is_none() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-signature.policy",
                reason: "exact policy requires full causal cone material",
            });
        }
        Ok(FailureSignatureKey {
            policy: *self,
            canonical_material: failure_signature_key_material(signature, *self),
        })
    }

    /// Returns the canonical policy material included in result identities.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_signature_policy_material(*self)
    }

    /// Returns the content address of this policy selector.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            FAILURE_SIGNATURE_KEY_DOMAIN,
            &self.canonical_material(),
        )
    }
}

/// Deterministic projection of a signature under a [`SignaturePolicy`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureSignatureKey {
    pub(in crate::model) policy: SignaturePolicy,
    pub(in crate::model) canonical_material: String,
}

impl FailureSignatureKey {
    /// Returns the policy that selected this key's fields.
    #[must_use]
    pub fn policy(&self) -> SignaturePolicy {
        self.policy
    }

    /// Returns the canonical material hashed into the cluster id.
    #[must_use]
    pub fn canonical_material(&self) -> &str {
        &self.canonical_material
    }

    /// Returns the content-addressed cluster id for this key.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(FAILURE_SIGNATURE_KEY_DOMAIN, &self.canonical_material)
    }
}

/// Content-addressed identity of one triage result.
///
/// The findings ledger content address and active signature policy are both
/// included, so re-clustering the same ledger under the same policy resolves to
/// the same result identity while a policy change is a distinct artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureTriageResultIdentity {
    /// Content hash of the findings ledger being clustered.
    pub findings_ledger: ContentHash,
    /// Active policy used to project failure-signature keys.
    pub policy: SignaturePolicy,
}

impl FailureTriageResultIdentity {
    /// Builds a triage result identity from a findings ledger and policy.
    #[must_use]
    pub fn new(findings_ledger: ContentHash, policy: SignaturePolicy) -> Self {
        Self {
            findings_ledger,
            policy,
        }
    }

    /// Returns the canonical identity material.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_triage_result_identity_material(*self)
    }

    /// Returns the content-addressed triage result id.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            FAILURE_TRIAGE_RESULT_IDENTITY_DOMAIN,
            &self.canonical_material(),
        )
    }
}
