//! Portable explanations for authenticated provider-selection decisions.
//!
//! Explanations are derived only from a [`VerifiedPlanningSnapshot`]. They
//! therefore report the exact decision and bounded rejection history retained
//! by the planner instead of reconstructing possible candidates after the fact.
//! The `redacted` audience removes deployment topology, authority grants, and
//! free-form rejection details while preserving the selected public interface,
//! decision source, guarantees, and an explicit account of omitted fields.
//! Callers choose the audience and must enforce access before requesting
//! deployment disclosure; verified provenance does not authenticate a reader.
//! Redacted output retains the snapshot and binding commitments plus a request
//! ordinal, so export policy must also consider that residual correlation.
//!
//! ```json
//! {
//!   "schema": "aos.ability.binding-explanation/v1",
//!   "required_features": [],
//!   "planning_snapshot": "sha256:<planning-snapshot-digest>",
//!   "binding_plan": "sha256:<binding-plan-digest>",
//!   "request_ordinal": 0,
//!   "audience": "redacted",
//!   "request": { "disclosure": "redacted" },
//!   "outcome": {
//!     "status": "unresolved",
//!     "obligations": [{
//!       "kind": "authorization",
//!       "obligation": { "disclosure": "redacted" }
//!     }]
//!   },
//!   "rejected_candidates": {
//!     "disclosure": "redacted",
//!     "retained_count": 2
//!   },
//!   "limitations": [
//!     "commitment-correlation-retained",
//!     "request-details-redacted",
//!     "obligation-details-redacted",
//!     "candidate-history-redacted"
//!   ]
//! }
//! ```

use std::io::{self, Write};

use aos_ability_model::{
    ABILITY_LIMITS_V1, AuthorityGrant, BindingId, BindingRequest, BindingSource,
    DeploymentObligation, GuaranteeKey, InstanceId, InterfaceKey, LocalKey, PlanId,
    ProviderImplementationReference, RequestId, RequiredFeature, ResourceLifetime, RevisionId,
};
use aos_ability_plan::{CandidateRejection, VerifiedPlanningSnapshot};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact schema discriminator for one provider-selection explanation.
pub const BINDING_EXPLANATION_SCHEMA: &str = "aos.ability.binding-explanation/v1";

/// Maximum canonical byte length emitted for one provider-selection explanation.
pub const BINDING_EXPLANATION_MAX_BYTES: usize = ABILITY_LIMITS_V1.max_document_bytes as usize;

/// Selects which retained planning details the caller chooses to disclose.
///
/// This selection does not authenticate or authorize a reader. A frontend must
/// enforce deployment access before selecting [`Self::Deployment`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingExplanationAudience {
    /// Retains exact deployment identities, grants, and rejection constraints.
    Deployment,
    /// Removes private deployment topology and free-form diagnostic details.
    Redacted,
}

/// Carries either an exact deployment value or an explicit redaction marker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "disclosure", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProtectedValue<T> {
    /// Retains the exact value after the caller permits deployment disclosure.
    Disclosed {
        /// Carries the retained planning value.
        value: T,
    },
    /// States that the value was intentionally withheld.
    Redacted,
}

/// Explains whether the request selected a provider or remains an obligation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BindingExplanationOutcome {
    /// A checked binding satisfied the request.
    Selected {
        /// Records which deterministic precedence rule selected the provider.
        source: BindingSource,
        /// Identifies the selected public interface contract.
        interface: InterfaceKey,
        /// Lists guarantees supplied by the selected provider.
        guarantees: Vec<GuaranteeKey>,
        /// Bounds the lifetime of retained resources.
        lifetime: ResourceLifetime,
        /// Reports whether separate implementation authority was admitted.
        mediation_allowed: bool,
        /// Names the policy candidate when deployment disclosure is allowed.
        candidate: ProtectedValue<LocalKey>,
        /// Names the plan-local binding when deployment disclosure is allowed.
        binding: ProtectedValue<BindingId>,
        /// Names the selected provider when deployment disclosure is allowed.
        provider: ProtectedValue<InstanceId>,
        /// Pins the implementation and executable artifact when disclosure is allowed.
        implementation: ProtectedValue<ProviderImplementationReference>,
        /// Identifies the authorizing policy revision when disclosure is allowed.
        policy_revision: ProtectedValue<RevisionId>,
        /// Retains caller authority when deployment disclosure is allowed.
        caller_grant: ProtectedValue<AuthorityGrant>,
        /// Retains provider authority when deployment disclosure is allowed.
        provider_grant: ProtectedValue<AuthorityGrant>,
    },
    /// The checked plan retained an explicit deployment obligation.
    Unresolved {
        /// Lists every retained missing input in canonical plan order.
        obligations: Vec<ExplainedObligation>,
    },
}

/// Carries one classified obligation with audience-controlled private detail.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplainedObligation {
    /// Classifies the missing input without exposing its private detail.
    pub kind: aos_ability_model::ObligationKind,
    /// Retains the exact obligation only when deployment disclosure is selected.
    pub obligation: ProtectedValue<DeploymentObligation>,
}

/// Retains exact bounded rejection history or a count with an explicit redaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "disclosure", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RejectedCandidateHistory {
    /// Retains the planner's exact request-specific rejection records.
    Disclosed {
        /// Carries records in their retained deterministic encounter order.
        entries: Vec<CandidateRejection>,
    },
    /// Withholds candidate identities and free-form constraint messages.
    Redacted {
        /// Reports how many retained records were withheld.
        retained_count: usize,
    },
}

/// Names information that a redacted explanation deliberately cannot establish.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExplanationLimitation {
    /// Exact commitments and request order may correlate this export with a deployment.
    CommitmentCorrelationRetained,
    /// The consuming deployment identity and request constraints were withheld.
    RequestDetailsRedacted,
    /// The provider, implementation, and policy identities were withheld.
    ProviderDetailsRedacted,
    /// Caller and provider authority grants were withheld.
    AuthorityGrantsRedacted,
    /// Candidate identities and rejection constraints were withheld.
    CandidateHistoryRedacted,
    /// The obligation description and related resource identity were withheld.
    ObligationDetailsRedacted,
}

/// Owns one deterministic explanation derived from verified planning provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingExplanation {
    schema: String,
    required_features: Vec<RequiredFeature>,
    planning_snapshot: Sha256Digest,
    binding_plan: PlanId,
    request_ordinal: usize,
    audience: BindingExplanationAudience,
    request: ProtectedValue<BindingRequest>,
    outcome: BindingExplanationOutcome,
    rejected_candidates: RejectedCandidateHistory,
    limitations: Vec<ExplanationLimitation>,
}

/// Reports why a provider-selection explanation could not be constructed.
#[derive(Debug, Error)]
pub enum BindingExplanationError {
    /// The requested identity is absent from the verified final plan.
    #[error("verified planning snapshot has no request with the supplied identity")]
    UnknownRequest,
    /// Verified planning records disagree about the request outcome.
    #[error("verified planning snapshot has inconsistent provider-selection records")]
    InconsistentPlanningRecords,
    /// Canonical JSON encoding failed.
    #[error("binding explanation encoding failed: {0}")]
    Encoding(#[source] anyhow::Error),
    /// The encoded explanation exceeds the version-1 byte bound.
    #[error("binding explanation exceeds its encoded byte limit")]
    EncodedSizeLimit,
}

impl BindingExplanation {
    /// Explains one request from externally committed, structurally replayed planning data.
    ///
    /// Rejected candidates are limited to records actually retained by the
    /// bounded planner. This method never reruns discovery or invents reasons
    /// for candidates absent from the snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is absent, retained decisions disagree
    /// with the checked binding plan, or the explanation cannot be encoded
    /// within the version-1 bound.
    pub fn from_planning(
        planning: &VerifiedPlanningSnapshot,
        request: &RequestId,
        audience: BindingExplanationAudience,
    ) -> Result<Self, BindingExplanationError> {
        let checked = planning.checked_binding();
        let (request_ordinal, request_document) = checked
            .document()
            .requests
            .iter()
            .enumerate()
            .find(|(_, candidate)| candidate.id == *request)
            .ok_or(BindingExplanationError::UnknownRequest)?;
        let decisions = planning
            .outcome()
            .resolution
            .decisions
            .iter()
            .filter(|decision| decision.request == *request)
            .collect::<Vec<_>>();
        let bindings = checked
            .bindings()
            .iter()
            .filter(|binding| binding.request == *request)
            .collect::<Vec<_>>();
        let obligations = checked
            .document()
            .obligations
            .iter()
            .filter(|obligation| obligation.request == *request)
            .collect::<Vec<_>>();

        let outcome = match (
            decisions.as_slice(),
            bindings.as_slice(),
            obligations.as_slice(),
        ) {
            ([decision], [binding], [])
                if decision.source == binding.source && decision.candidate == binding.id.0 =>
            {
                selected_outcome(decision.candidate.clone(), binding, audience)
            }
            ([], [], [_, ..]) => unresolved_outcome(&obligations, audience),
            _ => return Err(BindingExplanationError::InconsistentPlanningRecords),
        };
        let rejected_candidates =
            rejection_history(&planning.outcome().resolution.rejections, request, audience);
        let limitations = limitations(&outcome, &rejected_candidates, audience);
        let explanation = Self {
            schema: BINDING_EXPLANATION_SCHEMA.to_string(),
            required_features: Vec::new(),
            planning_snapshot: planning.snapshot_digest(),
            binding_plan: checked.id(),
            request_ordinal,
            audience,
            request: protect(request_document.clone(), audience),
            outcome,
            rejected_candidates,
            limitations,
        };
        explanation.canonical_bytes()?;
        Ok(explanation)
    }

    /// Returns the independently checked planning-snapshot commitment.
    #[must_use]
    pub const fn planning_snapshot(&self) -> Sha256Digest {
        self.planning_snapshot
    }

    /// Returns the checked final binding-plan identity.
    #[must_use]
    pub const fn binding_plan(&self) -> PlanId {
        self.binding_plan
    }

    /// Returns the request's zero-based position in canonical plan order.
    #[must_use]
    pub const fn request_ordinal(&self) -> usize {
        self.request_ordinal
    }

    /// Returns the disclosure audience encoded into this explanation.
    #[must_use]
    pub const fn audience(&self) -> BindingExplanationAudience {
        self.audience
    }

    /// Returns the request or its explicit redaction marker.
    #[must_use]
    pub const fn request(&self) -> &ProtectedValue<BindingRequest> {
        &self.request
    }

    /// Returns the selected binding or unresolved obligation explanation.
    #[must_use]
    pub const fn outcome(&self) -> &BindingExplanationOutcome {
        &self.outcome
    }

    /// Returns retained candidate rejections or their explicit redacted count.
    #[must_use]
    pub const fn rejected_candidates(&self) -> &RejectedCandidateHistory {
        &self.rejected_candidates
    }

    /// Returns all explicit limitations introduced by redaction.
    #[must_use]
    pub fn limitations(&self) -> &[ExplanationLimitation] {
        &self.limitations
    }

    /// Encodes this explanation as bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical serialization fails or the explanation
    /// exceeds its version-1 byte bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BindingExplanationError> {
        let mut writer = ExplanationBoundedWriter::new(BINDING_EXPLANATION_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                BindingExplanationError::EncodedSizeLimit
            } else {
                BindingExplanationError::Encoding(error.into())
            }
        })?;
        aos_contract::canonical::to_vec(self).map_err(BindingExplanationError::Encoding)
    }
}

fn selected_outcome(
    candidate: LocalKey,
    binding: &aos_ability_model::Binding,
    audience: BindingExplanationAudience,
) -> BindingExplanationOutcome {
    BindingExplanationOutcome::Selected {
        source: binding.source,
        interface: binding.interface.clone(),
        guarantees: binding.guarantees.clone(),
        lifetime: binding.lifetime,
        mediation_allowed: binding.mediation_allowed,
        candidate: protect(candidate, audience),
        binding: protect(binding.id.clone(), audience),
        provider: protect(binding.provider.clone(), audience),
        implementation: protect(binding.implementation.clone(), audience),
        policy_revision: protect(binding.policy_revision, audience),
        caller_grant: protect(binding.caller_grant.clone(), audience),
        provider_grant: protect(binding.provider_grant.clone(), audience),
    }
}

fn unresolved_outcome(
    obligations: &[&DeploymentObligation],
    audience: BindingExplanationAudience,
) -> BindingExplanationOutcome {
    BindingExplanationOutcome::Unresolved {
        obligations: obligations
            .iter()
            .map(|obligation| ExplainedObligation {
                kind: obligation.kind,
                obligation: protect((*obligation).clone(), audience),
            })
            .collect(),
    }
}

fn protect<T>(value: T, audience: BindingExplanationAudience) -> ProtectedValue<T> {
    match audience {
        BindingExplanationAudience::Deployment => ProtectedValue::Disclosed { value },
        BindingExplanationAudience::Redacted => ProtectedValue::Redacted,
    }
}

fn rejection_history(
    retained: &[CandidateRejection],
    request: &RequestId,
    audience: BindingExplanationAudience,
) -> RejectedCandidateHistory {
    let entries = retained
        .iter()
        .filter(|rejection| rejection.request == *request)
        .cloned()
        .collect::<Vec<_>>();
    match audience {
        BindingExplanationAudience::Deployment => RejectedCandidateHistory::Disclosed { entries },
        BindingExplanationAudience::Redacted => RejectedCandidateHistory::Redacted {
            retained_count: entries.len(),
        },
    }
}

fn limitations(
    outcome: &BindingExplanationOutcome,
    history: &RejectedCandidateHistory,
    audience: BindingExplanationAudience,
) -> Vec<ExplanationLimitation> {
    if audience == BindingExplanationAudience::Deployment {
        return Vec::new();
    }

    let mut limitations = vec![
        ExplanationLimitation::CommitmentCorrelationRetained,
        ExplanationLimitation::RequestDetailsRedacted,
    ];
    match outcome {
        BindingExplanationOutcome::Selected { .. } => limitations.extend([
            ExplanationLimitation::ProviderDetailsRedacted,
            ExplanationLimitation::AuthorityGrantsRedacted,
        ]),
        BindingExplanationOutcome::Unresolved { .. } => {
            limitations.push(ExplanationLimitation::ObligationDetailsRedacted);
        }
    }
    if matches!(
        history,
        RejectedCandidateHistory::Redacted {
            retained_count: 1..
        }
    ) {
        limitations.push(ExplanationLimitation::CandidateHistoryRedacted);
    }
    limitations
}

struct ExplanationBoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl ExplanationBoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for ExplanationBoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized binding explanation exceeds its byte limit",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use aos_ability_model::ObligationKind;
    use aos_ability_plan::test_support::{
        verified_planning_multiple_obligations, verified_planning_with_rejection,
    };

    use super::*;

    #[test]
    fn deployment_explanation_reports_only_retained_selection_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let planning = verified_planning_with_rejection();
        let request = planning.checked_binding().document().requests[0].id.clone();

        let explanation = BindingExplanation::from_planning(
            &planning,
            &request,
            BindingExplanationAudience::Deployment,
        )?;

        assert_eq!(explanation.planning_snapshot(), planning.snapshot_digest());
        assert!(matches!(
            explanation.outcome(),
            BindingExplanationOutcome::Selected {
                candidate: ProtectedValue::Disclosed { .. },
                provider: ProtectedValue::Disclosed { .. },
                caller_grant: ProtectedValue::Disclosed { .. },
                provider_grant: ProtectedValue::Disclosed { .. },
                ..
            }
        ));
        assert_eq!(
            explanation.rejected_candidates(),
            &RejectedCandidateHistory::Disclosed {
                entries: planning.outcome().resolution.rejections.clone()
            }
        );
        assert!(explanation.limitations().is_empty());
        let bytes = explanation.canonical_bytes()?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes)?["schema"],
            BINDING_EXPLANATION_SCHEMA
        );
        Ok(())
    }

    #[test]
    fn redacted_explanation_withholds_topology_grants_and_constraint_text()
    -> Result<(), Box<dyn std::error::Error>> {
        let planning = verified_planning_with_rejection();
        let request = planning.checked_binding().document().requests[0].id.clone();
        let explanation = BindingExplanation::from_planning(
            &planning,
            &request,
            BindingExplanationAudience::Redacted,
        )?;

        assert!(matches!(explanation.request(), ProtectedValue::Redacted));
        assert!(matches!(
            explanation.outcome(),
            BindingExplanationOutcome::Selected {
                candidate: ProtectedValue::Redacted,
                binding: ProtectedValue::Redacted,
                provider: ProtectedValue::Redacted,
                implementation: ProtectedValue::Redacted,
                policy_revision: ProtectedValue::Redacted,
                caller_grant: ProtectedValue::Redacted,
                provider_grant: ProtectedValue::Redacted,
                ..
            }
        ));
        assert_eq!(
            explanation.limitations(),
            &[
                ExplanationLimitation::CommitmentCorrelationRetained,
                ExplanationLimitation::RequestDetailsRedacted,
                ExplanationLimitation::ProviderDetailsRedacted,
                ExplanationLimitation::AuthorityGrantsRedacted,
                ExplanationLimitation::CandidateHistoryRedacted,
            ]
        );

        let bytes = explanation.canonical_bytes()?;
        assert_eq!(
            explanation.rejected_candidates(),
            &RejectedCandidateHistory::Redacted { retained_count: 1 }
        );
        for private_value in [
            "consumer",
            "planning-provider",
            "a-rejected-short-lifetime",
            "binding lifetime is shorter than the requested lifetime",
        ] {
            assert!(
                !bytes
                    .windows(private_value.len())
                    .any(|window| window == private_value.as_bytes())
            );
        }
        Ok(())
    }

    #[test]
    fn unresolved_explanation_preserves_every_verified_obligation_with_per_record_redaction()
    -> Result<(), Box<dyn std::error::Error>> {
        let planning = verified_planning_multiple_obligations();
        let request = planning.checked_binding().document().requests[0].id.clone();

        let deployment = BindingExplanation::from_planning(
            &planning,
            &request,
            BindingExplanationAudience::Deployment,
        )?;
        let redacted = BindingExplanation::from_planning(
            &planning,
            &request,
            BindingExplanationAudience::Redacted,
        )?;

        let BindingExplanationOutcome::Unresolved { obligations } = deployment.outcome() else {
            return Err("expected unresolved deployment explanation".into());
        };
        assert_eq!(obligations.len(), 2);
        assert!(
            obligations.iter().all(|obligation| matches!(
                obligation.obligation,
                ProtectedValue::Disclosed { .. }
            ))
        );

        let BindingExplanationOutcome::Unresolved { obligations } = redacted.outcome() else {
            return Err("expected unresolved redacted explanation".into());
        };
        assert_eq!(
            obligations
                .iter()
                .map(|obligation| obligation.kind)
                .collect::<Vec<_>>(),
            vec![
                ObligationKind::Authorization,
                ObligationKind::ExternalProvider
            ]
        );
        assert!(
            obligations
                .iter()
                .all(|obligation| obligation.obligation == ProtectedValue::Redacted)
        );
        assert!(
            redacted
                .limitations()
                .contains(&ExplanationLimitation::ObligationDetailsRedacted)
        );
        let bytes = redacted.canonical_bytes()?;
        for private_value in [
            "operator authorization is unavailable",
            "external provider is unavailable",
        ] {
            assert!(
                !bytes
                    .windows(private_value.len())
                    .any(|window| window == private_value.as_bytes())
            );
        }
        Ok(())
    }

    #[test]
    fn rejection_history_filters_the_bounded_planner_records_without_inference() {
        let planning = verified_planning_with_rejection();
        let request = planning.checked_binding().document().requests[0].id.clone();
        let other_request = RequestId {
            consumer: request.consumer.clone(),
            scope: request.scope.clone(),
            key: LocalKey::new("other").expect("static key"),
        };
        let records = vec![
            CandidateRejection {
                request: request.clone(),
                candidate: LocalKey::new("first").expect("static key"),
                constraint: "first retained reason".to_string(),
            },
            CandidateRejection {
                request: other_request,
                candidate: LocalKey::new("other-candidate").expect("static key"),
                constraint: "unrelated reason".to_string(),
            },
        ];

        assert_eq!(
            rejection_history(&records, &request, BindingExplanationAudience::Deployment),
            RejectedCandidateHistory::Disclosed {
                entries: vec![records[0].clone()]
            }
        );
        assert_eq!(
            rejection_history(&records, &request, BindingExplanationAudience::Redacted),
            RejectedCandidateHistory::Redacted { retained_count: 1 }
        );
    }
}
