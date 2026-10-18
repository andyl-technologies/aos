//! Reviewed plan seals and idempotency decisions.

use serde::{Deserialize, Serialize};

use super::primitives::{
    Actor, ContentDigest, ControlError, Generation, MutationCommit, MutationResourceIdentity,
    ResourceVersion, RevisionHead, StableId,
};

/// Maximum lifetime of a retained-control mutation plan.
pub const MAX_PLAN_LIFETIME_SECS: i64 = 24 * 60 * 60;

/// A bounded caller-generated key for exactly-once request handling.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Validates an idempotency key.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] unless the key contains 1-128 visible
    /// ASCII bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, ControlError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ControlError::Invalid {
                field: "idempotency_key",
                reason: "must contain 1-128 visible ASCII bytes".into(),
            });
        }
        Ok(Self(value))
    }

    /// Returns the exact idempotency key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for IdempotencyKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// The exact current head sealed by a mutation plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HeadSeal {
    /// Expected stable identity.
    pub stable_id: StableId,
    /// Expected immutable generation.
    pub generation: Generation,
    /// Expected content digest.
    pub content_digest: ContentDigest,
    /// Expected compare-and-swap version.
    pub resource_version: ResourceVersion,
}

impl From<&RevisionHead> for HeadSeal {
    fn from(head: &RevisionHead) -> Self {
        Self {
            stable_id: head.stable_id.clone(),
            generation: head.generation,
            content_digest: head.content_digest.clone(),
            resource_version: head.resource_version,
        }
    }
}

/// One concrete effect displayed during plan review.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanEffect {
    /// Canonical effect kind.
    pub kind: String,
    /// Exact affected stable identity.
    pub target: StableId,
    /// Digest of the complete effect inputs.
    pub input_digest: ContentDigest,
    /// Whether apply must schedule durable external work.
    pub requires_operation: bool,
}

impl PlanEffect {
    fn sort_key(&self) -> (&str, &str, &str) {
        (
            self.kind.as_str(),
            self.target.as_str(),
            self.input_digest.as_str(),
        )
    }
}

/// Whether apply requires a destructive-action confirmation hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ConfirmationRequirement {
    /// No destructive confirmation is required.
    None,
    /// Apply must present this exact server-derived hash.
    Required {
        /// SHA-256 hash bound to the destructive review copy.
        confirmation_hash: ContentDigest,
    },
}

/// Complete inputs used to create an immutable reviewed plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanSealRequest {
    /// Stable server-issued plan identity.
    pub plan_id: StableId,
    /// Canonical mutation kind.
    pub mutation_kind: String,
    /// Primary target stable identity.
    pub target: StableId,
    /// Actor that created the plan.
    pub planned_by: Actor,
    /// Digest of the actor's exact authorization scope and grants.
    pub actor_scope_digest: ContentDigest,
    /// Current target head, absent only for creation.
    pub expected_head: Option<HeadSeal>,
    /// Digest of the normalized semantic request.
    pub request_digest: ContentDigest,
    /// Ordered, concrete effects displayed for review.
    pub effects: Vec<PlanEffect>,
    /// Destructive confirmation policy.
    pub confirmation: ConfirmationRequirement,
    /// Unix timestamp at which the plan was created.
    pub created_at: i64,
    /// Unix timestamp after which apply must fail closed.
    pub expires_at: i64,
}

/// An immutable plan whose seal covers every apply-relevant field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SealedPlan {
    request: PlanSealRequest,
    effects_digest: ContentDigest,
    seal_digest: ContentDigest,
}

impl<'de> Deserialize<'de> for SealedPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SealedPlanWire {
            request: PlanSealRequestWire,
            effects_digest: ContentDigest,
            seal_digest: ContentDigest,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PlanEffectWire {
            kind: String,
            target: StableId,
            input_digest: ContentDigest,
            requires_operation: bool,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct HeadSealWire {
            stable_id: StableId,
            generation: Generation,
            content_digest: ContentDigest,
            resource_version: ResourceVersion,
        }

        #[derive(Deserialize)]
        #[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
        enum ConfirmationRequirementWire {
            None,
            Required { confirmation_hash: ContentDigest },
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PlanSealRequestWire {
            plan_id: StableId,
            mutation_kind: String,
            target: StableId,
            planned_by: Actor,
            actor_scope_digest: ContentDigest,
            expected_head: Option<HeadSealWire>,
            request_digest: ContentDigest,
            effects: Vec<PlanEffectWire>,
            confirmation: ConfirmationRequirementWire,
            created_at: i64,
            expires_at: i64,
        }

        let wire = SealedPlanWire::deserialize(deserializer)?;
        let request = PlanSealRequest {
            plan_id: wire.request.plan_id,
            mutation_kind: wire.request.mutation_kind,
            target: wire.request.target,
            planned_by: wire.request.planned_by,
            actor_scope_digest: wire.request.actor_scope_digest,
            expected_head: wire.request.expected_head.map(|head| HeadSeal {
                stable_id: head.stable_id,
                generation: head.generation,
                content_digest: head.content_digest,
                resource_version: head.resource_version,
            }),
            request_digest: wire.request.request_digest,
            effects: wire
                .request
                .effects
                .into_iter()
                .map(|effect| PlanEffect {
                    kind: effect.kind,
                    target: effect.target,
                    input_digest: effect.input_digest,
                    requires_operation: effect.requires_operation,
                })
                .collect(),
            confirmation: match wire.request.confirmation {
                ConfirmationRequirementWire::None => ConfirmationRequirement::None,
                ConfirmationRequirementWire::Required { confirmation_hash } => {
                    ConfirmationRequirement::Required { confirmation_hash }
                }
            },
            created_at: wire.request.created_at,
            expires_at: wire.request.expires_at,
        };
        let sealed = Self::seal(request).map_err(serde::de::Error::custom)?;
        if sealed.effects_digest != wire.effects_digest || sealed.seal_digest != wire.seal_digest {
            return Err(serde::de::Error::custom(ControlError::DigestMismatch));
        }
        Ok(sealed)
    }
}

impl SealedPlan {
    /// Validates and seals a reviewed plan.
    ///
    /// Effects must already be in canonical order. Requiring the planner to
    /// present canonical order prevents a retry from producing another seal for
    /// semantically identical work.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for invalid timestamps, names, missing
    /// effects, duplicate/non-canonical effects, or a creation plan that seals
    /// an existing head with another identity. Returns a serialization error if
    /// a digest cannot be derived.
    pub fn seal(request: PlanSealRequest) -> Result<Self, ControlError> {
        if request.plan_id.kind() != "plan" {
            return Err(ControlError::Invalid {
                field: "plan_id",
                reason: "must use a plan stable identity".into(),
            });
        }
        if !is_canonical_semantic_name(&request.mutation_kind) {
            return Err(ControlError::Invalid {
                field: "mutation_kind",
                reason: "must be 1-64 bytes of canonical lowercase snake_case".into(),
            });
        }
        let lifetime = request.expires_at.checked_sub(request.created_at);
        if !matches!(
            lifetime,
            Some(seconds) if seconds > 0 && seconds <= MAX_PLAN_LIFETIME_SECS
        ) {
            return Err(ControlError::Invalid {
                field: "expires_at",
                reason: "must be after creation and no more than 24 hours later".into(),
            });
        }
        if request.effects.is_empty() {
            return Err(ControlError::Invalid {
                field: "effects",
                reason: "a reviewed mutation must expose at least one concrete effect".into(),
            });
        }
        if request.effects.len() > 1_024 {
            return Err(ControlError::Invalid {
                field: "effects",
                reason: "must not contain more than 1024 effects".into(),
            });
        }
        for effect in &request.effects {
            if !is_canonical_semantic_name(&effect.kind) {
                return Err(ControlError::Invalid {
                    field: "effect_kind",
                    reason: "must be 1-64 bytes of canonical lowercase snake_case".into(),
                });
            }
        }
        if request
            .effects
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
        {
            return Err(ControlError::Invalid {
                field: "effects",
                reason: "must be strictly ordered and duplicate-free".into(),
            });
        }
        if let Some(head) = &request.expected_head {
            if head.stable_id != request.target {
                return Err(ControlError::IdentityMismatch {
                    expected: request.target.to_string(),
                    received: head.stable_id.to_string(),
                });
            }
        }
        let effects_digest = ContentDigest::of_value(&request.effects)?;
        let seal_digest = ContentDigest::of_value(&(&request, &effects_digest))?;
        Ok(Self {
            request,
            effects_digest,
            seal_digest,
        })
    }

    /// Returns the server-issued plan identity.
    #[must_use]
    pub fn plan_id(&self) -> &StableId {
        &self.request.plan_id
    }

    /// Returns the canonical mutation kind.
    #[must_use]
    pub fn mutation_kind(&self) -> &str {
        &self.request.mutation_kind
    }

    /// Returns the sealed effect list.
    #[must_use]
    pub fn effects(&self) -> &[PlanEffect] {
        &self.request.effects
    }

    /// Returns the digest covering the complete immutable plan.
    #[must_use]
    pub fn seal_digest(&self) -> &ContentDigest {
        &self.seal_digest
    }

    /// Validates an apply request against time, actor, current grants, head, and confirmation.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] if the plan is expired, the applying
    /// actor differs from the planning actor, authorization scope/grants have
    /// changed, confirmation is absent/incorrect, the persisted seal was
    /// altered, or current state no longer matches the sealed head. Returns a
    /// digest error if actor fingerprinting fails.
    pub fn validate_apply(
        &self,
        now: i64,
        applying_actor: &Actor,
        current_actor_scope_digest: &ContentDigest,
        current_head: Option<&RevisionHead>,
        confirmation_hash: Option<&ContentDigest>,
    ) -> Result<ValidatedApply, ControlError> {
        self.verify_seal()?;
        if now < self.request.created_at || now >= self.request.expires_at {
            return Err(ControlError::Invalid {
                field: "plan_id",
                reason: "plan is not within its validity window".into(),
            });
        }
        if applying_actor.fingerprint()? != self.request.planned_by.fingerprint()? {
            return Err(ControlError::Invalid {
                field: "actor",
                reason: "apply actor differs from the actor sealed by the plan".into(),
            });
        }
        if current_actor_scope_digest != &self.request.actor_scope_digest {
            return Err(ControlError::Invalid {
                field: "actor_scope_digest",
                reason: "authorization scope or grants changed after planning".into(),
            });
        }
        match (&self.request.expected_head, current_head) {
            (None, None) => {}
            (Some(expected), Some(current)) if *expected == HeadSeal::from(current) => {}
            (Some(expected), Some(current)) if expected.stable_id != current.stable_id => {
                return Err(ControlError::IdentityMismatch {
                    expected: expected.stable_id.to_string(),
                    received: current.stable_id.to_string(),
                });
            }
            _ => {
                return Err(ControlError::Invalid {
                    field: "expected_head",
                    reason: "current state differs from the reviewed plan".into(),
                });
            }
        }
        match &self.request.confirmation {
            ConfirmationRequirement::None if confirmation_hash.is_none() => {}
            ConfirmationRequirement::Required {
                confirmation_hash: expected,
            } if confirmation_hash == Some(expected) => {}
            _ => {
                return Err(ControlError::Invalid {
                    field: "confirmation_hash",
                    reason: "does not match the reviewed destructive action".into(),
                });
            }
        }
        Ok(ValidatedApply {
            plan_id: self.request.plan_id.clone(),
            target: self.request.target.clone(),
            expected_head: self.request.expected_head.clone(),
            plan_seal_digest: self.seal_digest.clone(),
            request_digest: self.request.request_digest.clone(),
            effects_digest: self.effects_digest.clone(),
            requires_operation: self
                .request
                .effects
                .iter()
                .any(|effect| effect.requires_operation),
        })
    }

    fn verify_seal(&self) -> Result<(), ControlError> {
        let effects_digest = ContentDigest::of_value(&self.request.effects)?;
        let seal_digest = ContentDigest::of_value(&(&self.request, &effects_digest))?;
        if effects_digest != self.effects_digest || seal_digest != self.seal_digest {
            return Err(ControlError::DigestMismatch);
        }
        Ok(())
    }
}

/// Evidence produced after a plan passes all apply-time gates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedApply {
    /// Applied plan identity.
    plan_id: StableId,
    /// Exact resource identity reviewed by the plan.
    target: StableId,
    /// Exact pre-mutation head, absent only for creation.
    expected_head: Option<HeadSeal>,
    /// Digest of the complete sealed plan.
    plan_seal_digest: ContentDigest,
    /// Digest of the normalized semantic mutation request.
    request_digest: ContentDigest,
    /// Digest of its concrete effects.
    effects_digest: ContentDigest,
    /// Whether apply must return and schedule a durable operation.
    requires_operation: bool,
}

impl ValidatedApply {
    /// Returns the immutable plan identity.
    #[must_use]
    pub fn plan_id(&self) -> &StableId {
        &self.plan_id
    }

    /// Returns the exact resource identity reviewed by the plan.
    #[must_use]
    pub fn target(&self) -> &StableId {
        &self.target
    }

    /// Returns the exact pre-mutation head, absent only for creation.
    #[must_use]
    pub fn expected_head(&self) -> Option<&HeadSeal> {
        self.expected_head.as_ref()
    }

    /// Returns the normalized semantic request digest.
    #[must_use]
    pub fn request_digest(&self) -> &ContentDigest {
        &self.request_digest
    }

    /// Returns the digest of the complete validated plan seal.
    #[must_use]
    pub fn plan_seal_digest(&self) -> &ContentDigest {
        &self.plan_seal_digest
    }

    /// Returns the digest of the exact reviewed effects.
    #[must_use]
    pub fn effects_digest(&self) -> &ContentDigest {
        &self.effects_digest
    }

    /// Reports whether apply must schedule a durable operation.
    #[must_use]
    pub fn requires_operation(&self) -> bool {
        self.requires_operation
    }
}

/// One persisted exactly-once outcome keyed by semantic request digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdempotencyRecord {
    /// Caller-generated idempotency key.
    pub key: IdempotencyKey,
    /// Digest of the normalized semantic request, excluding the key.
    pub request_digest: ContentDigest,
    /// Digest of the complete response or operation reference.
    pub outcome_digest: ContentDigest,
}

/// Persisted exactly-once outcome for immutable plan creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanCreationRecord {
    /// Caller-generated plan-creation idempotency key.
    pub key: IdempotencyKey,
    /// Digest of the normalized semantic planning request.
    pub request_digest: ContentDigest,
    /// Server-issued immutable plan identity.
    pub plan_id: StableId,
    /// Digest of the complete sealed plan returned previously.
    pub plan_seal_digest: ContentDigest,
}

/// Required behavior for an idempotent plan-creation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanCreationDecision {
    /// No record exists and no replay was requested; create one plan.
    Admit,
    /// Return the exact previously sealed plan without creating another.
    Replay,
    /// The key, semantic request, or explicit retry target was substituted.
    Conflict,
}

/// Classifies plan creation against an optional persisted creation record.
///
/// An explicit retry identity is never advisory: it must name the exact plan
/// retained under the same idempotency key and semantic request digest.
#[must_use]
pub fn decide_plan_creation(
    existing: Option<&PlanCreationRecord>,
    key: &IdempotencyKey,
    request_digest: &ContentDigest,
    retry_plan_id: Option<&StableId>,
) -> PlanCreationDecision {
    if retry_plan_id.is_some_and(|plan_id| plan_id.kind() != "plan") {
        return PlanCreationDecision::Conflict;
    }
    match existing {
        None if retry_plan_id.is_none() => PlanCreationDecision::Admit,
        Some(record)
            if record.plan_id.kind() == "plan"
                && record.key == *key
                && record.request_digest == *request_digest
                && retry_plan_id.map_or(true, |plan_id| plan_id == &record.plan_id) =>
        {
            PlanCreationDecision::Replay
        }
        _ => PlanCreationDecision::Conflict,
    }
}

/// Complete atomic persistence intent for one exactly-once reviewed apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactlyOnceApplyCommit<T> {
    /// Resource, audit, and event-outbox records committed together.
    mutation: MutationCommit<T>,
    /// Validated immutable plan evidence.
    apply: ValidatedApply,
    /// Exactly-once request/outcome record committed in the same transaction.
    idempotency: IdempotencyRecord,
}

impl<T: MutationResourceIdentity> ExactlyOnceApplyCommit<T> {
    /// Joins mutation, plan, and idempotency intents into one transaction unit.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::DigestMismatch`] when the idempotency record does
    /// not describe the same normalized semantic request as the applied plan.
    pub fn new(
        mutation: MutationCommit<T>,
        apply: ValidatedApply,
        idempotency: IdempotencyRecord,
    ) -> Result<Self, ControlError> {
        if apply.request_digest != idempotency.request_digest {
            return Err(ControlError::DigestMismatch);
        }
        if apply.target != *mutation.resource().mutation_stable_id() {
            return Err(ControlError::IdentityMismatch {
                expected: apply.target.to_string(),
                received: mutation.resource().mutation_stable_id().to_string(),
            });
        }
        if apply.target != mutation.audit().resource_stable_id
            || apply.target != mutation.outbox().resource_stable_id
            || apply
                .expected_head
                .as_ref()
                .is_some_and(|head| head.stable_id != apply.target)
        {
            return Err(ControlError::Invalid {
                field: "apply_target",
                reason: "plan target, expected head, audit, and outbox must be identical".into(),
            });
        }
        let required_generation = match &apply.expected_head {
            Some(head) => head.generation.next()?,
            None => Generation::new(1)?,
        };
        if mutation.resource().mutation_generation() != required_generation {
            return Err(ControlError::NonContiguousGeneration {
                expected: required_generation.get(),
                received: mutation.resource().mutation_generation().get(),
            });
        }
        Ok(Self {
            mutation,
            apply,
            idempotency,
        })
    }

    /// Consumes the checked apply unit into atomic persistence records.
    #[must_use]
    pub fn into_parts(self) -> (MutationCommit<T>, ValidatedApply, IdempotencyRecord) {
        (self.mutation, self.apply, self.idempotency)
    }
}

/// Required behavior for an incoming idempotent request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdempotencyDecision {
    /// No record exists; the request may be admitted.
    Admit,
    /// The exact semantic request completed previously; replay its stored result.
    Replay,
    /// The key was reused for a different semantic request; fail closed.
    Conflict,
}

/// Classifies a request against an optional persisted idempotency record.
#[must_use]
pub fn decide_idempotency(
    existing: Option<&IdempotencyRecord>,
    key: &IdempotencyKey,
    request_digest: &ContentDigest,
) -> IdempotencyDecision {
    match existing {
        None => IdempotencyDecision::Admit,
        Some(record) if record.key == *key && record.request_digest == *request_digest => {
            IdempotencyDecision::Replay
        }
        Some(_) => IdempotencyDecision::Conflict,
    }
}

fn is_canonical_semantic_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.split('_').all(|word| {
            let mut bytes = word.bytes();
            bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
                && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_control::primitives::{ActorKind, AuditIntent, OutboxIntent, Revision};

    fn actor(id: u64) -> Actor {
        Actor::new(ActorKind::User, Some(id), format!("user-{id}")).unwrap()
    }

    fn digest(value: &str) -> ContentDigest {
        ContentDigest::of_bytes(value)
    }

    fn plan() -> SealedPlan {
        SealedPlan::seal(PlanSealRequest {
            plan_id: StableId::new("plan:one").unwrap(),
            mutation_kind: "update_branding".into(),
            target: StableId::new("instance-settings:branding").unwrap(),
            planned_by: actor(1),
            actor_scope_digest: digest("scope"),
            expected_head: None,
            request_digest: digest("request"),
            effects: vec![PlanEffect {
                kind: "advance_head".into(),
                target: StableId::new("instance-settings:branding").unwrap(),
                input_digest: digest("effect"),
                requires_operation: false,
            }],
            confirmation: ConfirmationRequirement::None,
            created_at: 10,
            expires_at: 20,
        })
        .unwrap()
    }

    #[test]
    fn apply_is_bound_to_actor_time_and_current_head() {
        let plan = plan();
        assert!(plan
            .validate_apply(19, &actor(1), &digest("scope"), None, None)
            .is_ok());
        assert!(plan
            .validate_apply(20, &actor(1), &digest("scope"), None, None)
            .is_err());
        assert!(plan
            .validate_apply(19, &actor(2), &digest("scope"), None, None)
            .is_err());
        assert!(plan
            .validate_apply(19, &actor(1), &digest("changed-scope"), None, None)
            .is_err());
    }

    #[test]
    fn idempotency_replays_only_the_same_semantic_request() {
        let key = IdempotencyKey::new("request-1").unwrap();
        let record = IdempotencyRecord {
            key: key.clone(),
            request_digest: digest("a"),
            outcome_digest: digest("result"),
        };
        assert_eq!(
            decide_idempotency(Some(&record), &key, &digest("a")),
            IdempotencyDecision::Replay
        );
        assert_eq!(
            decide_idempotency(Some(&record), &key, &digest("b")),
            IdempotencyDecision::Conflict
        );
    }

    #[test]
    fn plan_creation_retry_replays_only_the_exact_prior_plan() {
        let key = IdempotencyKey::new("plan-request-1").unwrap();
        let plan_id = StableId::new("plan:one").unwrap();
        let record = PlanCreationRecord {
            key: key.clone(),
            request_digest: digest("plan-request"),
            plan_id: plan_id.clone(),
            plan_seal_digest: digest("plan-seal"),
        };
        assert_eq!(
            decide_plan_creation(Some(&record), &key, &digest("plan-request"), Some(&plan_id),),
            PlanCreationDecision::Replay
        );
        assert_eq!(
            decide_plan_creation(
                Some(&record),
                &key,
                &digest("plan-request"),
                Some(&StableId::new("plan:other").unwrap()),
            ),
            PlanCreationDecision::Conflict
        );
        assert_eq!(
            decide_plan_creation(None, &key, &digest("plan-request"), Some(&plan_id)),
            PlanCreationDecision::Conflict
        );
    }

    #[test]
    fn idempotency_keys_revalidate_during_deserialization() {
        assert!(serde_json::from_str::<IdempotencyKey>(r#""contains space""#).is_err());
    }

    #[test]
    fn effects_must_be_strictly_canonical() {
        let mut request = plan().request;
        request.effects.push(request.effects[0].clone());
        assert!(SealedPlan::seal(request).is_err());
    }

    #[test]
    fn semantic_names_reject_case_and_ambiguous_separators() {
        let mut request = plan().request;
        request.plan_id = StableId::new("user:not-a-plan").unwrap();
        assert!(SealedPlan::seal(request).is_err());

        let mut request = plan().request;
        request.mutation_kind = "UpdateBranding".into();
        assert!(SealedPlan::seal(request).is_err());

        let mut request = plan().request;
        request.effects[0].kind = "advance__head".into();
        assert!(SealedPlan::seal(request).is_err());
    }

    #[test]
    fn apply_recomputes_the_persisted_seal() {
        let mut plan = plan();
        plan.seal_digest = digest("tampered");
        assert!(matches!(
            plan.validate_apply(19, &actor(1), &digest("scope"), None, None),
            Err(ControlError::DigestMismatch)
        ));
    }

    #[test]
    fn sealed_plan_deserialization_revalidates_structure_and_digests() {
        let plan = plan();
        let mut encoded = serde_json::to_value(&plan).unwrap();
        encoded["seal_digest"] = serde_json::Value::String(digest("tampered").as_str().to_owned());
        assert!(serde_json::from_value::<SealedPlan>(encoded).is_err());

        let mut encoded = serde_json::to_value(plan()).unwrap();
        encoded["request"]["mutation_kind"] = serde_json::Value::String("Not_Canonical".into());
        assert!(serde_json::from_value::<SealedPlan>(encoded).is_err());

        let mut encoded = serde_json::to_value(plan()).unwrap();
        encoded["unknown_signed_field"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<SealedPlan>(encoded).is_err());
    }

    #[test]
    fn atomic_apply_rejects_resource_or_generation_substitution() {
        let plan = plan();
        let apply = plan
            .validate_apply(19, &actor(1), &digest("scope"), None, None)
            .unwrap();
        let resource = Revision::new(
            apply.target.clone(),
            Generation::new(1).unwrap(),
            "new branding".to_owned(),
            actor(1),
            19,
        )
        .unwrap();
        let audit = AuditIntent {
            action: "update_branding".into(),
            owner_scope: StableId::new("org:acme").unwrap(),
            resource_stable_id: apply.target.clone(),
            actor: actor(1),
            detail_digest: digest("audit"),
        };
        let outbox = OutboxIntent {
            event_id: StableId::new("event:branding-one").unwrap(),
            event_name: "branding_updated".into(),
            owner_scope: audit.owner_scope.clone(),
            resource_kind: apply.target.kind().into(),
            resource_stable_id: apply.target.clone(),
            resource_generation: Generation::new(1).unwrap(),
            actor: actor(1),
            payload_digest: digest("event"),
            occurred_at: 19,
        };
        let mut forged_resource = resource.clone();
        forged_resource.content_digest = digest("forged-contents");
        assert!(MutationCommit::new(forged_resource, audit.clone(), outbox.clone()).is_err());
        let mutation = MutationCommit::new(resource, audit, outbox).unwrap();
        let idempotency = IdempotencyRecord {
            key: IdempotencyKey::new("apply-one").unwrap(),
            request_digest: apply.request_digest.clone(),
            outcome_digest: digest("outcome"),
        };
        ExactlyOnceApplyCommit::new(mutation, apply.clone(), idempotency.clone()).unwrap();

        let other_id = StableId::new("instance-settings:other").unwrap();
        let other_resource = Revision::new(
            other_id.clone(),
            Generation::new(1).unwrap(),
            "other".to_owned(),
            actor(1),
            19,
        )
        .unwrap();
        let other_audit = AuditIntent {
            action: "update_branding".into(),
            owner_scope: StableId::new("org:acme").unwrap(),
            resource_stable_id: other_id.clone(),
            actor: actor(1),
            detail_digest: digest("audit-other"),
        };
        let other_outbox = OutboxIntent {
            event_id: StableId::new("event:branding-other").unwrap(),
            event_name: "branding_updated".into(),
            owner_scope: other_audit.owner_scope.clone(),
            resource_kind: other_id.kind().into(),
            resource_stable_id: other_id,
            resource_generation: Generation::new(1).unwrap(),
            actor: actor(1),
            payload_digest: digest("event-other"),
            occurred_at: 19,
        };
        let other_mutation =
            MutationCommit::new(other_resource, other_audit, other_outbox).unwrap();
        assert!(
            ExactlyOnceApplyCommit::new(other_mutation, apply.clone(), idempotency.clone(),)
                .is_err()
        );

        let wrong_generation = Revision::new(
            apply.target.clone(),
            Generation::new(2).unwrap(),
            "skipped generation".to_owned(),
            actor(1),
            19,
        )
        .unwrap();
        let wrong_audit = AuditIntent {
            action: "update_branding".into(),
            owner_scope: StableId::new("org:acme").unwrap(),
            resource_stable_id: apply.target.clone(),
            actor: actor(1),
            detail_digest: digest("audit-wrong-generation"),
        };
        let wrong_outbox = OutboxIntent {
            event_id: StableId::new("event:branding-wrong-generation").unwrap(),
            event_name: "branding_updated".into(),
            owner_scope: wrong_audit.owner_scope.clone(),
            resource_kind: apply.target.kind().into(),
            resource_stable_id: apply.target.clone(),
            resource_generation: Generation::new(2).unwrap(),
            actor: actor(1),
            payload_digest: digest("event-wrong-generation"),
            occurred_at: 19,
        };
        let wrong_mutation =
            MutationCommit::new(wrong_generation, wrong_audit, wrong_outbox).unwrap();
        assert!(ExactlyOnceApplyCommit::new(wrong_mutation, apply, idempotency).is_err());
    }
}
