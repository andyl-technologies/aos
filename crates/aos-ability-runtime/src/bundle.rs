//! Reloadable planning and transition provenance for durable recovery.
//!
//! The canonical on-disk bundle has this abbreviated layout:
//!
//! ```text
//! {
//!   "schema": "aos.ability.plan-bundle/v1",
//!   "plan": "<effect-plan-id>",
//!   "desired": { "snapshot_digest": "<digest>", "snapshot": { ... }, ... },
//!   "current": { "snapshot_digest": "<digest>", "snapshot": { ... }, ... } | null,
//!   "transition_authority_digest": "<digest>" | null,
//!   "transition_authority": { ... } | null,
//!   "transition_digest": "<digest>",
//!   "transition": { ... }
//! }
//! ```
//!
//! The execution journal independently anchors the canonical bundle digest.
//! Retained snapshot and policy digests inside the bundle are replay inputs;
//! they do not authenticate a bundle whose external journal commitment did not
//! originate from trusted initial planning and transition evaluation.

use std::collections::BTreeSet;

use aos_ability_model::{
    ABILITY_LIMITS_V1, EnvironmentDocument, InterfaceDocument, PackageDocument, PlanId,
    RequiredFeature, TransitionAuthorizationDocument, VersionedDocument,
};
use aos_ability_plan::{
    PLANNING_SNAPSHOT_MAX_BYTES, PlanningReplayInputs, PlanningSnapshot, PlanningSnapshotError,
    RecursiveComposer, ResolutionPolicyDocument, TRANSITION_SNAPSHOT_MAX_BYTES, TransitionPlanner,
    TransitionReplayInputs, TransitionSnapshot, TransitionSnapshotError, VerifiedPlanningSnapshot,
    VerifiedTransitionPlan,
};
use aos_ability_validate::{
    CheckedEffectPlan, CheckedTransitionAuthority, TransitionAuthorityError,
    TransitionAuthorityInputs, ValidationContext, ValidationErrors,
};
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact schema discriminator for retained planning and transition provenance.
pub const PLAN_BUNDLE_SCHEMA: &str = "aos.ability.plan-bundle/v1";

const AUTHENTICATED_POLICY_SET_SCHEMA: &str = "aos.ability.authenticated-policy-set/v1";
const PLAN_BUNDLE_COMPONENT_LIMIT: usize = 24;

/// Maximum encoded byte length accepted for one retained plan bundle.
pub const PLAN_BUNDLE_MAX_BYTES: usize = PLANNING_SNAPSHOT_MAX_BYTES
    .saturating_mul(2)
    .saturating_add(TRANSITION_SNAPSHOT_MAX_BYTES)
    .saturating_add(
        (ABILITY_LIMITS_V1.max_document_bytes as usize).saturating_mul(PLAN_BUNDLE_COMPONENT_LIMIT),
    );

/// Reports why retained planning provenance could not be encoded or replayed.
#[derive(Debug, Error)]
pub enum PlanBundleError {
    /// Canonical bundle encoding failed.
    #[error("plan-provenance bundle encoding failed: {0}")]
    Encode(#[source] anyhow::Error),
    /// Bounded strict bundle decoding failed.
    #[error("plan-provenance bundle decoding failed: {0}")]
    Decode(#[source] anyhow::Error),
    /// The bundle carries an unsupported schema discriminator.
    #[error("plan-provenance bundle has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// The encoded bytes are valid JSON but not their canonical representation.
    #[error("plan-provenance bundle is not canonically encoded")]
    NoncanonicalEncoding,
    /// The retained authenticated policy copy does not match its bundle commitment.
    #[error("plan-provenance bundle authenticated policy commitment does not match")]
    PolicyCommitmentMismatch,
    /// Retained planning provenance failed structural replay.
    #[error("planning snapshot replay failed: {0}")]
    Planning(#[from] PlanningSnapshotError),
    /// Retained transition provenance failed structural replay.
    #[error("transition snapshot replay failed: {0}")]
    Transition(#[from] TransitionSnapshotError),
    /// Retained current-policy teardown authority failed semantic replay.
    #[error("transition authority replay failed: {0}")]
    Authority(#[from] TransitionAuthorityError),
    /// Exact retained interface inputs no longer pass semantic validation.
    #[error("plan-provenance interface validation failed: {0}")]
    Validation(#[from] ValidationErrors),
    /// The sealed plans and retained commitments do not identify one transition.
    #[error("plan-provenance bundle contains inconsistent planning or transition linkage")]
    LinkageMismatch,
    /// Replay changed the canonical normalized bundle.
    #[error("plan-provenance bundle inputs are not in validated canonical order")]
    NoncanonicalInputs,
}

/// Owns independently committed inputs for one planning-snapshot replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedPlanningProvenance {
    snapshot_digest: Sha256Digest,
    snapshot: PlanningSnapshot,
    authenticated_policy_digest: Sha256Digest,
    authenticated_policies: Vec<ResolutionPolicyDocument>,
    interfaces: Vec<InterfaceDocument>,
    environment: EnvironmentDocument,
    packages: Vec<PackageDocument>,
}

/// Owns all portable provenance required to reconstruct one checked effect plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReloadablePlanBundle {
    schema: String,
    plan: PlanId,
    desired: RetainedPlanningProvenance,
    current: Option<RetainedPlanningProvenance>,
    transition_authority_digest: Option<Sha256Digest>,
    transition_authority: Option<TransitionAuthorizationDocument>,
    transition_digest: Sha256Digest,
    transition: TransitionSnapshot,
}

impl ReloadablePlanBundle {
    /// Captures sealed desired, prior, and transition provenance.
    ///
    /// # Errors
    ///
    /// Returns an error when a sealed planning result cannot be snapshotted or
    /// the supplied seals do not identify the same desired and prior plans.
    pub fn from_verified(
        desired: &VerifiedPlanningSnapshot,
        current: Option<&VerifiedPlanningSnapshot>,
        authority: Option<&CheckedTransitionAuthority>,
        transition: &VerifiedTransitionPlan,
    ) -> Result<Self, PlanBundleError> {
        if transition.desired_planning_digest() != desired.snapshot_digest()
            || transition.current_planning_digest()
                != current.map(VerifiedPlanningSnapshot::snapshot_digest)
            || transition.transition_authority_digest()
                != authority.map(CheckedTransitionAuthority::digest)
            || transition.effect_plan() != transition.checked_effect().id()
        {
            return Err(PlanBundleError::LinkageMismatch);
        }

        let interfaces = transition
            .checked_effect()
            .interfaces()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let desired = RetainedPlanningProvenance::from_verified(desired, interfaces.clone())?;
        let current = current
            .map(|planning| RetainedPlanningProvenance::from_verified(planning, interfaces.clone()))
            .transpose()?;
        let bundle = Self {
            schema: PLAN_BUNDLE_SCHEMA.to_string(),
            plan: transition.effect_plan(),
            desired,
            current,
            transition_authority_digest: authority.map(CheckedTransitionAuthority::digest),
            transition_authority: authority.map(|authority| authority.document().clone()),
            transition_digest: transition.snapshot_digest(),
            transition: transition.snapshot().clone(),
        };
        bundle.validate_linkage()?;
        Ok(bundle)
    }

    /// Returns the checked effect-plan identity committed by this bundle.
    #[must_use]
    pub const fn plan(&self) -> PlanId {
        self.plan
    }

    /// Returns the independently retained desired planning commitment.
    #[must_use]
    pub const fn desired_planning_digest(&self) -> Sha256Digest {
        self.desired.snapshot_digest
    }

    /// Returns the independently retained prior planning commitment, when present.
    #[must_use]
    pub fn current_planning_digest(&self) -> Option<Sha256Digest> {
        self.current.as_ref().map(|current| current.snapshot_digest)
    }

    /// Returns the independently retained transition commitment.
    #[must_use]
    pub const fn transition_digest(&self) -> Sha256Digest {
        self.transition_digest
    }

    /// Returns the independently retained current-policy teardown commitment.
    #[must_use]
    pub const fn transition_authority_digest(&self) -> Option<Sha256Digest> {
        self.transition_authority_digest
    }

    /// Encodes the bundle in the canonical AOS JSON dialect.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or canonical JSON serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PlanBundleError> {
        self.validate_linkage()?;
        let bytes = aos_contract::canonical::to_vec(self).map_err(PlanBundleError::Encode)?;
        plan_bundle_limits()
            .decode::<serde_json::Value>(&bytes, PLAN_BUNDLE_SCHEMA)
            .map_err(PlanBundleError::Encode)?;
        Ok(bytes)
    }

    /// Computes the domain-separated identity of the canonical bundle.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical JSON serialization fails.
    pub fn digest(&self) -> Result<Sha256Digest, PlanBundleError> {
        Ok(Sha256Digest::separated(
            PLAN_BUNDLE_SCHEMA,
            self.canonical_bytes()?,
        ))
    }

    /// Decodes one strictly bounded canonical bundle.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, structurally invalid, unknown,
    /// noncanonical, or internally inconsistent input.
    pub fn decode(bytes: &[u8]) -> Result<Self, PlanBundleError> {
        let bundle = plan_bundle_limits()
            .decode::<Self>(bytes, PLAN_BUNDLE_SCHEMA)
            .map_err(PlanBundleError::Decode)?;
        if bundle.schema != PLAN_BUNDLE_SCHEMA {
            return Err(PlanBundleError::UnsupportedSchema);
        }
        if bundle.canonical_bytes()? != bytes {
            return Err(PlanBundleError::NoncanonicalEncoding);
        }
        bundle.validate_linkage()?;
        Ok(bundle)
    }

    /// Structurally replays planning and transition construction.
    ///
    /// This proves that retained transcripts reconstruct the committed graph.
    /// It proves provider execution only when the bundle's digest was anchored
    /// by a trusted initial evaluation and supplied independently on recovery.
    ///
    /// # Errors
    ///
    /// Returns an error when any independent commitment differs, any retained
    /// input fails current validation, replay derives a different graph, or
    /// the retained inputs are not in canonical validated order.
    pub fn revalidate(
        self,
        supported_features: BTreeSet<RequiredFeature>,
    ) -> Result<CheckedEffectPlan, PlanBundleError> {
        let retained = self.clone();
        let (desired, desired_context) = self.desired.verify(&supported_features)?;
        let current = self
            .current
            .as_ref()
            .map(|planning| {
                planning
                    .verify(&supported_features)
                    .map(|(verified, _)| verified)
            })
            .transpose()?;
        let authority = match (
            self.transition_authority,
            self.transition_authority_digest,
            current.as_ref(),
        ) {
            (Some(document), Some(expected_digest), Some(current)) => {
                Some(desired_context.validate_transition_authority(
                    document.clone(),
                    TransitionAuthorityInputs {
                        expected_digest,
                        desired_planning: desired.snapshot_digest(),
                        current_planning: current.snapshot_digest(),
                        authorization_policy_revision: document.authorization_policy_revision,
                        desired: desired.checked_binding(),
                        current: current.checked_binding(),
                    },
                )?)
            }
            (None, None, _) => None,
            _ => return Err(PlanBundleError::LinkageMismatch),
        };
        let transition = self.transition.verify_structure(
            &TransitionPlanner::new(&desired_context),
            TransitionReplayInputs {
                expected_digest: self.transition_digest,
                desired: &desired,
                current: current.as_ref(),
                authority: authority.as_ref(),
            },
        )?;
        if transition.effect_plan() != self.plan {
            return Err(PlanBundleError::LinkageMismatch);
        }

        let reconstructed =
            Self::from_verified(&desired, current.as_ref(), authority.as_ref(), &transition)?;
        if reconstructed != retained {
            return Err(PlanBundleError::NoncanonicalInputs);
        }
        Ok(transition.into_checked_effect())
    }

    fn validate_linkage(&self) -> Result<(), PlanBundleError> {
        if self.schema != PLAN_BUNDLE_SCHEMA {
            return Err(PlanBundleError::UnsupportedSchema);
        }
        if self.desired.snapshot.digest()? != self.desired.snapshot_digest
            || self
                .current
                .as_ref()
                .is_some_and(|current| {
                    !matches!(current.snapshot.digest(), Ok(digest) if digest == current.snapshot_digest)
                })
            || self.transition.digest()? != self.transition_digest
            || self.transition.desired_planning_digest() != self.desired.snapshot_digest
            || self.transition.current_planning_digest() != self.current_planning_digest()
            || self.transition.transition_authority_digest()
                != self.transition_authority_digest
            || self.transition.effect_plan() != self.plan
        {
            return Err(PlanBundleError::LinkageMismatch);
        }
        self.desired.validate_policy_commitment()?;
        if let Some(current) = &self.current {
            current.validate_policy_commitment()?;
        }
        match (
            &self.transition_authority,
            self.transition_authority_digest,
            &self.current,
        ) {
            (Some(authority), Some(expected), Some(_))
                if authority
                    .content_digest()
                    .map_err(|source| PlanBundleError::Encode(anyhow::Error::new(source)))?
                    == expected => {}
            (None, None, _) => {}
            _ => return Err(PlanBundleError::LinkageMismatch),
        }
        Ok(())
    }
}

impl RetainedPlanningProvenance {
    fn from_verified(
        verified: &VerifiedPlanningSnapshot,
        interfaces: Vec<InterfaceDocument>,
    ) -> Result<Self, PlanBundleError> {
        let checked = verified.checked_binding();
        let authenticated_policies = verified.outcome().policies.clone();
        Ok(Self {
            snapshot_digest: verified.snapshot_digest(),
            snapshot: PlanningSnapshot::from_outcome(verified.outcome())?,
            authenticated_policy_digest: policy_set_digest(&authenticated_policies)?,
            authenticated_policies,
            interfaces,
            environment: checked.environment().clone(),
            packages: checked.packages().to_vec(),
        })
    }

    fn verify(
        &self,
        supported_features: &BTreeSet<RequiredFeature>,
    ) -> Result<(VerifiedPlanningSnapshot, ValidationContext), PlanBundleError> {
        self.validate_policy_commitment()?;
        let context = ValidationContext::new(supported_features.clone(), self.interfaces.clone())?;
        let verified = self.snapshot.verify_structure(
            &RecursiveComposer::new(&context),
            PlanningReplayInputs {
                expected_digest: self.snapshot_digest,
                authenticated_policies: &self.authenticated_policies,
                seed: self.snapshot.seed().clone(),
                environment: self.environment.clone(),
                packages: self.packages.clone(),
            },
        )?;
        Ok((verified, context))
    }

    fn validate_policy_commitment(&self) -> Result<(), PlanBundleError> {
        if policy_set_digest(&self.authenticated_policies)? != self.authenticated_policy_digest {
            return Err(PlanBundleError::PolicyCommitmentMismatch);
        }
        Ok(())
    }
}

fn policy_set_digest(
    policies: &[ResolutionPolicyDocument],
) -> Result<Sha256Digest, PlanBundleError> {
    let bytes =
        aos_contract::canonical::to_vec(&policies.to_vec()).map_err(PlanBundleError::Encode)?;
    Ok(Sha256Digest::separated(
        AUTHENTICATED_POLICY_SET_SCHEMA,
        bytes,
    ))
}

fn plan_bundle_limits() -> JsonLimits {
    JsonLimits {
        max_bytes: PLAN_BUNDLE_MAX_BYTES,
        max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize + 2,
        max_items: scaled_limit(ABILITY_LIMITS_V1.max_collection_items),
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    }
}

fn scaled_limit(limit: u64) -> usize {
    usize::try_from(limit)
        .unwrap_or(usize::MAX)
        .saturating_mul(PLAN_BUNDLE_COMPONENT_LIMIT)
}

#[cfg(test)]
mod tests {
    use aos_ability_plan::test_support::{
        verified_planning_authorized_removal_fixture, verified_planning_transition_plan,
        verified_planning_transition_with_current,
        verified_planning_transition_with_distinct_current,
    };

    use super::*;

    #[test]
    fn exact_bundle_round_trips_and_structurally_replays() -> Result<(), Box<dyn std::error::Error>>
    {
        let (planning, transition) = verified_planning_transition_plan();
        let bundle = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)?;
        let expected_digest = bundle.digest()?;
        let expected_plan = transition.effect_plan();
        let bytes = bundle.canonical_bytes()?;

        let decoded = ReloadablePlanBundle::decode(&bytes)?;
        assert_eq!(decoded.digest()?, expected_digest);
        assert_eq!(decoded.revalidate(BTreeSet::new())?.id(), expected_plan);
        Ok(())
    }

    #[test]
    fn equivalent_noncanonical_json_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let (planning, transition) = verified_planning_transition_plan();
        let bytes = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)?
            .canonical_bytes()?;
        let mut padded = Vec::with_capacity(bytes.len() + 1);
        padded.push(b' ');
        padded.extend(bytes);

        assert!(matches!(
            ReloadablePlanBundle::decode(&padded),
            Err(PlanBundleError::NoncanonicalEncoding)
        ));
        Ok(())
    }

    #[test]
    fn prior_planning_snapshot_round_trips_and_replays() -> Result<(), Box<dyn std::error::Error>> {
        let (desired, current, transition) = verified_planning_transition_with_distinct_current();
        let bundle =
            ReloadablePlanBundle::from_verified(&desired, Some(&current), None, &transition)?;
        let expected_current = Some(current.snapshot_digest());
        let bytes = bundle.canonical_bytes()?;

        let decoded = ReloadablePlanBundle::decode(&bytes)?;
        assert_eq!(decoded.current_planning_digest(), expected_current);
        assert_ne!(decoded.desired_planning_digest(), current.snapshot_digest());
        assert_eq!(
            decoded.revalidate(BTreeSet::new())?.id(),
            transition.effect_plan()
        );
        Ok(())
    }

    #[test]
    fn transition_authority_round_trips_and_replays() -> Result<(), Box<dyn std::error::Error>> {
        let (desired, current, authority, transition) =
            verified_planning_authorized_removal_fixture();
        let bundle = ReloadablePlanBundle::from_verified(
            &desired,
            Some(&current),
            Some(&authority),
            &transition,
        )?;
        let bytes = bundle.canonical_bytes()?;

        let decoded = ReloadablePlanBundle::decode(&bytes)?;
        assert_eq!(
            decoded.transition_authority_digest(),
            Some(authority.digest())
        );
        assert_eq!(
            decoded.revalidate(BTreeSet::new())?.id(),
            transition.effect_plan()
        );
        Ok(())
    }

    #[test]
    fn transition_authority_tampering_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let (desired, current, authority, transition) =
            verified_planning_authorized_removal_fixture();
        let bundle = ReloadablePlanBundle::from_verified(
            &desired,
            Some(&current),
            Some(&authority),
            &transition,
        )?;
        let mut value: serde_json::Value = serde_json::from_slice(&bundle.canonical_bytes()?)?;
        value["transition_authority"]["authorization_policy_revision"] =
            serde_json::to_value(Sha256Digest::of_bytes("forged teardown policy"))?;

        assert!(matches!(
            ReloadablePlanBundle::decode(&aos_contract::canonical::to_vec(&value)?),
            Err(PlanBundleError::LinkageMismatch)
        ));
        Ok(())
    }

    #[test]
    fn transition_output_tampering_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let (planning, transition) = verified_planning_transition_plan();
        let bundle = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)?;
        let mut value: serde_json::Value = serde_json::from_slice(&bundle.canonical_bytes()?)?;
        value["transition"]["effect_document"]["limits"]["max_graph_edges"] = serde_json::json!(1);

        assert!(ReloadablePlanBundle::decode(&aos_contract::canonical::to_vec(&value)?).is_err());
        Ok(())
    }

    #[test]
    fn transition_commitment_tampering_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let (planning, transition) = verified_planning_transition_plan();
        let bundle = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)?;
        let mut value: serde_json::Value = serde_json::from_slice(&bundle.canonical_bytes()?)?;
        value["transition_digest"] =
            serde_json::to_value(Sha256Digest::of_bytes("forged transition"))?;

        assert!(matches!(
            ReloadablePlanBundle::decode(&aos_contract::canonical::to_vec(&value)?),
            Err(PlanBundleError::LinkageMismatch)
        ));
        Ok(())
    }

    #[test]
    fn planning_linkage_tampering_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let (planning, transition) = verified_planning_transition_with_current();
        let bundle =
            ReloadablePlanBundle::from_verified(&planning, Some(&planning), None, &transition)?;
        let mut value: serde_json::Value = serde_json::from_slice(&bundle.canonical_bytes()?)?;
        value["current"]["snapshot_digest"] =
            serde_json::to_value(Sha256Digest::of_bytes("forged prior planning"))?;

        assert!(matches!(
            ReloadablePlanBundle::decode(&aos_contract::canonical::to_vec(&value)?),
            Err(PlanBundleError::LinkageMismatch)
        ));
        Ok(())
    }

    #[test]
    fn authenticated_policy_copy_tampering_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let (planning, transition) = verified_planning_transition_plan();
        let bundle = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)?;
        let mut value: serde_json::Value = serde_json::from_slice(&bundle.canonical_bytes()?)?;
        value["desired"]["authenticated_policies"][0]["policy_revision"] =
            serde_json::to_value(Sha256Digest::of_bytes("forged policy"))?;

        assert!(matches!(
            ReloadablePlanBundle::decode(&aos_contract::canonical::to_vec(&value)?),
            Err(PlanBundleError::PolicyCommitmentMismatch)
        ));
        Ok(())
    }
}
