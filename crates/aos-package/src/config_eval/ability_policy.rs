//! Publication and fresh admission of current ability authority.
//!
//! Each root-owned current-authority scope is a mutable native trust input. It
//! is deliberately separate from retained plan bundles: the plan proves what
//! was checked, while this scope states whether the exact effect is still
//! admitted by current operator policy and live provider/resource observations.
//! A successful protected read is the authorization linearization point. This
//! policy rereads the scope for every authorization call. An installed
//! orchestrator must pass it through admission and immediate dispatch so a
//! replacement affects later decisions without granting from retained history.
//!
//! ```text
//! {"authority_epoch":7,"bindings":[...],"max_age_millis":30000,"observed_at_restart_millis":...,
//!  "plan":"sha256:...","policy_fence":"sha256:...",
//!  "platform_policy":"sha256:...","policy_revision":"sha256:...",
//!  "provider_assignments":[...],
//!  "required_features":[...],"resolution_policy":"sha256:...",
//!  "resource_observations":[...],"schema":"aos.ability.current-authority/v1",
//!  "sequence":42,"transition_authority":null}
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use aos_ability_model::{
    ABILITY_LIMITS_V1, Binding, MethodReference, Operation, PlanId, ProviderAssignment,
    RequiredFeature, ResourceAccess, RevisionId, TransactionId, TransitionAuthorizationDocument,
    VersionedDocument,
};
use aos_ability_plan::ResolutionPolicyDocument;
use aos_ability_runtime::adapter::{
    InvocationPurpose, MonotonicClock, ResourceAdmissionEvidence, ResourceRevisionObservation,
    SystemMonotonicClock,
};
use aos_ability_runtime::execution::{
    AuthorityRejection, RuntimeAuthorityRole, TrustedAdmissionPolicy, TrustedAuthoritySnapshot,
};
use aos_ability_validate::CheckedEffectPlan;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

/// Root-owned directory containing independently revocable activation scopes.
pub const CURRENT_ABILITY_AUTHORITY_ROOT: &str = "/run/apm/ability-authority";

const CURRENT_ABILITY_AUTHORITY_SCHEMA: &str = "aos.ability.current-authority/v1";
const CURRENT_ABILITY_AUTHORITY_SCHEMA_V2: &str = "aos.ability.current-authority/v2";
const CURRENT_ABILITY_AUTHORITY_MAX_BYTES: usize = 8 * 1024 * 1024;
const CURRENT_ABILITY_AUTHORITY_MAX_ENTRIES: usize = 65_536;

/// Identifies one independently refreshed native activation authority scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentAuthorityScope {
    /// Identifies the retained checked plan admitted in this scope.
    pub plan: PlanId,
    /// Separates concurrent or successive executions of the same plan.
    pub transaction: TransactionId,
}

impl CurrentAuthorityScope {
    /// Resolves this scope beneath the protected system authority root.
    #[must_use]
    pub fn system_path(&self) -> PathBuf {
        Path::new(CURRENT_ABILITY_AUTHORITY_ROOT)
            .join(self.plan.0.hex())
            .join(format!("{}.json", self.transaction.0.as_str()))
    }
}

mod storage;

pub use storage::{
    CurrentAbilityAuthorityPublisher, CurrentAbilityAuthoritySource,
    RootOwnedCurrentAuthorityFence, RootOwnedCurrentAuthoritySource,
};

/// Carries independently published current policy and live assignment evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentAbilityAuthorityDocument {
    /// Carries current-authority v1 or transaction-linked health v2.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Changes whenever current operator authority is revoked or republished.
    pub policy_fence: RevisionId,
    /// Identifies the transaction that owns a version-2 health publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionId>,
    /// Binds this publication to the protected monotonic authority epoch.
    pub authority_epoch: u64,
    /// Identifies the current grants represented by this publication.
    pub policy_revision: RevisionId,
    /// Commits to the authenticated resolution policy used to issue bindings.
    pub resolution_policy: Sha256Digest,
    /// Commits to exact native-platform policy authority when one is used.
    pub platform_policy: Option<Sha256Digest>,
    /// Commits to fresh teardown authority when the plan retires prior state.
    pub transition_authority: Option<Sha256Digest>,
    /// Increases for every changed publication under this native path.
    pub sequence: u64,
    /// Records the trusted restart-stable time of the live observations.
    pub observed_at_restart_millis: u64,
    /// Bounds how long assignment and resource observations remain admissible.
    pub max_age_millis: u64,
    /// Identifies the exact checked effect plan admitted by this publication.
    pub plan: PlanId,
    /// Lists independently policy-issued bindings in canonical binding order.
    pub bindings: Vec<Binding>,
    /// Lists current provider assignments in canonical provider order.
    pub provider_assignments: Vec<ProviderAssignment>,
    /// Lists authoritative present or absent resource observations in canonical order.
    pub resource_observations: Vec<CurrentResourceObservation>,
}

/// Carries independently authenticated native-platform binding authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentPlatformPolicyDocument {
    /// Carries `aos.ability.platform-policy/v1`.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Identifies the current operator policy revision.
    pub policy_revision: RevisionId,
    /// Lists exact platform-issued bindings in canonical binding order.
    pub bindings: Vec<Binding>,
}

impl VersionedDocument for CurrentPlatformPolicyDocument {
    const SCHEMA: &'static str = "aos.ability.platform-policy/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }
}

/// Records one authoritative current resource observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentResourceObservation {
    /// Identifies the exact logical resource that was probed.
    pub resource: aos_ability_model::ResourceId,
    /// Distinguishes proven absence from an exact present revision.
    pub state: CurrentResourceState,
}

/// Distinguishes an absent resource from one with known semantic content.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CurrentResourceState {
    /// An authoritative probe established that the resource does not exist.
    Absent,
    /// An authoritative probe established the exact current revision.
    Present {
        /// Identifies the observed semantic content.
        revision: RevisionId,
    },
    /// The exact loaded revision exists but is not running.
    Stopped {
        /// Identifies the loaded semantic revision.
        revision: RevisionId,
    },
    /// The resource exists, but direct behavior evidence contradicts its revision.
    Divergent {
        /// Identifies the loaded semantic revision.
        revision: RevisionId,
    },
}

impl CurrentAbilityAuthorityDocument {
    /// Checks the closed schema, bounds, canonical ordering, and policy coherence.
    ///
    /// # Errors
    ///
    /// Returns an error when the publication is malformed, unsupported, empty,
    /// oversized, noncanonical, or internally inconsistent.
    pub fn validate(
        &self,
        supported_features: &BTreeSet<RequiredFeature>,
    ) -> Result<(), CurrentAuthorityError> {
        let carries_runtime_health = self.resource_observations.iter().any(|observation| {
            matches!(
                observation.state,
                CurrentResourceState::Stopped { .. } | CurrentResourceState::Divergent { .. }
            )
        });
        if !matches!(
            (
                self.schema.as_str(),
                carries_runtime_health,
                self.transaction.is_some()
            ),
            (CURRENT_ABILITY_AUTHORITY_SCHEMA, false, false)
                | (CURRENT_ABILITY_AUTHORITY_SCHEMA_V2, _, true)
        ) {
            return Err(invalid("current authority uses an unsupported schema"));
        }
        if self
            .required_features
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "current authority required features are not strictly canonical",
            ));
        }
        if self
            .required_features
            .iter()
            .any(|feature| !supported_features.contains(feature))
        {
            return Err(invalid(
                "current authority requires an unsupported semantic feature",
            ));
        }
        if self.authority_epoch == 0 || self.sequence == 0 || self.max_age_millis == 0 {
            return Err(invalid(
                "current authority epoch, sequence, and maximum age must be positive",
            ));
        }
        if self.bindings.len() > CURRENT_ABILITY_AUTHORITY_MAX_ENTRIES
            || self.provider_assignments.len() > CURRENT_ABILITY_AUTHORITY_MAX_ENTRIES
            || self.resource_observations.len() > CURRENT_ABILITY_AUTHORITY_MAX_ENTRIES
        {
            return Err(invalid("current authority exceeds its entry limit"));
        }
        if self
            .bindings
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(invalid(
                "current authority bindings are not strictly canonical",
            ));
        }
        if self
            .bindings
            .iter()
            .any(|binding| binding.policy_revision != self.policy_revision)
        {
            return Err(invalid(
                "current authority binding uses another policy revision",
            ));
        }
        if self.provider_assignments.windows(2).any(|pair| {
            pair[0]
                .provider
                .cmp(&pair[1].provider)
                .then_with(|| pair[0].interface.cmp(&pair[1].interface))
                .is_ge()
        }) {
            return Err(invalid(
                "current authority provider assignments are not strictly canonical",
            ));
        }
        if self
            .resource_observations
            .windows(2)
            .any(|pair| pair[0].resource >= pair[1].resource)
        {
            return Err(invalid(
                "current authority resource observations are not strictly canonical",
            ));
        }

        let bytes = aos_contract::canonical::to_vec(self)
            .map_err(|error| invalid(format!("encoding current authority: {error}")))?;
        if bytes.len() > CURRENT_ABILITY_AUTHORITY_MAX_BYTES
            || bytes.len() > ABILITY_LIMITS_V1.max_document_bytes as usize
        {
            return Err(invalid("current authority exceeds its encoded byte limit"));
        }
        Ok(())
    }

    /// Computes the schema-separated digest of this current-authority document.
    ///
    /// # Errors
    ///
    /// Returns an error when the document cannot be encoded canonically.
    pub(crate) fn content_digest(&self) -> Result<Sha256Digest, CurrentAuthorityError> {
        let bytes = aos_contract::canonical::to_vec(self)
            .map_err(|error| invalid(format!("encoding current authority: {error}")))?;
        Ok(Sha256Digest::separated(&self.schema, bytes))
    }
}

/// Supplies live observations that a trusted publisher sampled independently.
#[derive(Clone, Debug)]
pub struct CurrentAuthorityObservations {
    /// Increases for every changed publication.
    pub sequence: u64,
    /// Records when these observations were sampled.
    pub observed_at_restart_millis: u64,
    /// Bounds observation freshness.
    pub max_age_millis: u64,
    /// Lists exact live provider assignments.
    pub provider_assignments: Vec<ProviderAssignment>,
    /// Lists resource presence or absence established by authoritative probes.
    pub resource_observations: Vec<CurrentResourceObservation>,
}

/// Supplies independently authenticated policy inputs for one publication.
pub struct CurrentAuthorityPublication<'a> {
    /// Identifies the revocation-sensitive current policy generation.
    pub policy_fence: RevisionId,
    /// Identifies the transaction for a version-2 health publication.
    pub transaction: Option<&'a TransactionId>,
    /// Supplies the authenticated desired-state resolution policy.
    pub resolution_policy: &'a ResolutionPolicyDocument,
    /// Supplies independently authenticated native-platform bindings, when used.
    pub platform_policy: Option<&'a CurrentPlatformPolicyDocument>,
    /// Supplies fresh policy authority for exact teardown bindings, when used.
    pub transition_authority: Option<&'a TransitionAuthorizationDocument>,
    /// Supplies the checked graph whose bindings must be rederived from policy.
    pub plan: &'a CheckedEffectPlan,
    /// Supplies current assignment and resource observations.
    pub observations: CurrentAuthorityObservations,
}

/// Pins immutable plan-policy commitments used for every fresh admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentAuthorityCommitment {
    /// Identifies the exact retained effect plan.
    pub plan: PlanId,
    /// Pins the transaction carried by version-2 health authority.
    pub transaction: Option<TransactionId>,
    /// Pins the protected authority epoch observed during plan admission.
    pub authority_epoch: u64,
    /// Identifies the revocation-sensitive policy publication.
    pub policy_fence: RevisionId,
    /// Identifies grants authorized for the plan.
    pub policy_revision: RevisionId,
    /// Pins the authenticated desired-state policy input.
    pub resolution_policy: Sha256Digest,
    /// Pins native-platform authority when the plan uses it.
    pub platform_policy: Option<Sha256Digest>,
    /// Pins fresh teardown authority when the plan retires prior state.
    pub transition_authority: Option<Sha256Digest>,
    /// Rejects authority publications predating candidate construction.
    pub minimum_sequence: u64,
}

/// Reopens and revalidates native current policy before every effect decision.
#[derive(Debug)]
pub struct NativeCurrentAdmissionPolicy<Source, Clock> {
    source: Source,
    clock: Clock,
    commitment: CurrentAuthorityCommitment,
    supported_features: BTreeSet<RequiredFeature>,
    last_publication: Option<ObservedPublication>,
}

/// Publishes fresh native observations and immediately consumes that authority.
///
/// One instance owns a transaction-scoped protected publication. Its first
/// refresh fixes the policy commitment and authority epoch; later refreshes
/// may advance observations while every admission remains pinned to those
/// immutable commitments.
pub(crate) struct PublishingNativeAdmissionPolicy {
    publisher: CurrentAbilityAuthorityPublisher,
    source: RootOwnedCurrentAuthoritySource,
    clock: SystemMonotonicClock,
    transaction: TransactionId,
    policy_fence: RevisionId,
    resolution_policy: ResolutionPolicyDocument,
    platform_policy: Option<CurrentPlatformPolicyDocument>,
    transition_authority: Option<TransitionAuthorizationDocument>,
    supported_features: BTreeSet<RequiredFeature>,
    transaction_linked: bool,
    sequence: u64,
    max_age_millis: u64,
    admission:
        Option<NativeCurrentAdmissionPolicy<RootOwnedCurrentAuthoritySource, SystemMonotonicClock>>,
}

impl PublishingNativeAdmissionPolicy {
    /// Constructs a transaction-scoped publisher and admission policy.
    #[must_use]
    pub(crate) fn new(
        scope: &CurrentAuthorityScope,
        policy_fence: RevisionId,
        resolution_policy: ResolutionPolicyDocument,
        platform_policy: Option<CurrentPlatformPolicyDocument>,
        transition_authority: Option<TransitionAuthorizationDocument>,
        supported_features: BTreeSet<RequiredFeature>,
        max_age_millis: u64,
        transaction_linked: bool,
    ) -> Self {
        Self {
            publisher: CurrentAbilityAuthorityPublisher::system(scope),
            source: RootOwnedCurrentAuthoritySource::system(scope),
            clock: SystemMonotonicClock::new(),
            transaction: scope.transaction.clone(),
            policy_fence,
            resolution_policy,
            platform_policy,
            transition_authority,
            supported_features,
            transaction_linked,
            sequence: 0,
            max_age_millis,
            admission: None,
        }
    }

    /// Publishes one protected observation set and returns its exact authority document.
    ///
    /// # Errors
    ///
    /// Returns an error when policy reissuance, durable publication, or the
    /// transaction's immutable current-authority commitment fails.
    pub(crate) fn publish_authority(
        &mut self,
        plan: &CheckedEffectPlan,
        assignments: &[ProviderAssignment],
        resources: Vec<CurrentResourceObservation>,
    ) -> Result<CurrentAbilityAuthorityDocument, CurrentAuthorityError> {
        if self.max_age_millis == 0 {
            return Err(invalid(
                "native current-authority maximum age must be positive",
            ));
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("native current-authority sequence overflowed"))?;
        let carries_runtime_health = resources.iter().any(|observation| {
            matches!(
                observation.state,
                CurrentResourceState::Stopped { .. } | CurrentResourceState::Divergent { .. }
            )
        });
        let retains_transaction = self.transaction_linked
            || !plan.operations().is_empty()
            || carries_runtime_health
            || self
                .admission
                .as_ref()
                .is_some_and(|admission| admission.commitment.transaction.is_some());
        let document = self
            .publisher
            .publish_resuming(CurrentAuthorityPublication {
                policy_fence: self.policy_fence,
                transaction: retains_transaction.then_some(&self.transaction),
                resolution_policy: &self.resolution_policy,
                platform_policy: self.platform_policy.as_ref(),
                transition_authority: self.transition_authority.as_ref(),
                plan,
                observations: CurrentAuthorityObservations {
                    sequence: self.sequence,
                    observed_at_restart_millis: self.clock.restart_stable_millis(),
                    max_age_millis: self.max_age_millis,
                    provider_assignments: assignments.to_vec(),
                    resource_observations: resources,
                },
            })?;
        if let Some(admission) = &self.admission {
            if admission.commitment.plan != document.plan
                || admission.commitment.transaction != document.transaction
                || admission.commitment.authority_epoch != document.authority_epoch
                || admission.commitment.policy_fence != document.policy_fence
                || admission.commitment.policy_revision != document.policy_revision
                || admission.commitment.resolution_policy != document.resolution_policy
                || admission.commitment.platform_policy != document.platform_policy
                || admission.commitment.transition_authority != document.transition_authority
            {
                return Err(invalid(
                    "native current-authority commitment changed during execution",
                ));
            }
            return Ok(document);
        }

        let commitment = CurrentAuthorityCommitment {
            plan: document.plan,
            transaction: document.transaction.clone(),
            authority_epoch: document.authority_epoch,
            policy_fence: document.policy_fence,
            policy_revision: document.policy_revision,
            resolution_policy: document.resolution_policy,
            platform_policy: document.platform_policy,
            transition_authority: document.transition_authority,
            minimum_sequence: document.sequence,
        };
        self.admission = Some(NativeCurrentAdmissionPolicy::new(
            self.source.clone(),
            self.clock.clone(),
            commitment,
            self.supported_features.clone(),
        ));
        Ok(document)
    }

    fn admission_mut(
        &mut self,
    ) -> Result<
        &mut NativeCurrentAdmissionPolicy<RootOwnedCurrentAuthoritySource, SystemMonotonicClock>,
        CurrentAuthorityError,
    > {
        self.admission
            .as_mut()
            .ok_or_else(|| invalid("native current authority was not published before admission"))
    }
}

#[derive(Clone, Copy, Debug)]
struct ObservedPublication {
    sequence: u64,
    observed_at_restart_millis: u64,
    digest: Sha256Digest,
}

impl<Source, Clock> NativeCurrentAdmissionPolicy<Source, Clock> {
    /// Constructs an admission policy around an independently protected source.
    #[must_use]
    pub fn new(
        source: Source,
        clock: Clock,
        commitment: CurrentAuthorityCommitment,
        supported_features: BTreeSet<RequiredFeature>,
    ) -> Self {
        Self {
            source,
            clock,
            commitment,
            supported_features,
            last_publication: None,
        }
    }
}

impl<Source, Clock> NativeCurrentAdmissionPolicy<Source, Clock>
where
    Source: CurrentAbilityAuthoritySource,
    Clock: MonotonicClock,
{
    fn refresh(&mut self) -> Result<CurrentAbilityAuthorityDocument, CurrentAuthorityError> {
        let document = self
            .source
            .load_current()
            .map_err(|error| source_error(error.to_string()))?;
        self.accept_publication(&document)?;
        Ok(document)
    }

    fn accept_publication(
        &mut self,
        document: &CurrentAbilityAuthorityDocument,
    ) -> Result<(), CurrentAuthorityError> {
        document.validate(&self.supported_features)?;
        if document.plan != self.commitment.plan
            || document.transaction != self.commitment.transaction
            || document.authority_epoch != self.commitment.authority_epoch
            || document.policy_fence != self.commitment.policy_fence
            || document.policy_revision != self.commitment.policy_revision
            || document.resolution_policy != self.commitment.resolution_policy
            || document.platform_policy != self.commitment.platform_policy
            || document.transition_authority != self.commitment.transition_authority
        {
            return Err(invalid(
                "current authority differs from the retained plan-policy commitment",
            ));
        }
        if document.sequence < self.commitment.minimum_sequence {
            return Err(invalid(
                "current authority predates the retained minimum sequence",
            ));
        }

        let now = self.clock.restart_stable_millis();
        let age = now
            .checked_sub(document.observed_at_restart_millis)
            .ok_or_else(|| invalid("current authority observation is in the future"))?;
        if age > document.max_age_millis {
            return Err(invalid("current authority observations have expired"));
        }

        let digest = document.content_digest()?;
        if let Some(previous) = self.last_publication {
            if document.sequence < previous.sequence
                || document.observed_at_restart_millis < previous.observed_at_restart_millis
            {
                return Err(invalid("current authority publication moved backward"));
            }
            if document.sequence == previous.sequence && digest != previous.digest {
                return Err(invalid(
                    "current authority changed without advancing its sequence",
                ));
            }
        }
        self.last_publication = Some(ObservedPublication {
            sequence: document.sequence,
            observed_at_restart_millis: document.observed_at_restart_millis,
            digest,
        });
        Ok(())
    }

    /// Revalidates all authority needed to retain an unchanged native mapping.
    ///
    /// # Errors
    ///
    /// Returns an error when the publication is stale or revoked, its checked
    /// bindings or live assignments changed, or any mapped resource is absent
    /// or has a different observed revision.
    pub(crate) fn authorize_native_no_op(
        &mut self,
        plan: &CheckedEffectPlan,
        assignments: &[ProviderAssignment],
        resources: &super::native_resource_map::NativeResourceMap,
    ) -> Result<(), CurrentAuthorityError> {
        let current = self.refresh()?;
        if plan.id() != self.commitment.plan {
            return Err(invalid("native no-op uses another checked plan"));
        }
        if current.bindings != plan.binding_plan().bindings() {
            return Err(invalid(
                "current policy bindings differ from the checked no-op plan",
            ));
        }
        if current.provider_assignments != assignments {
            return Err(invalid(
                "current provider assignments differ from the no-op observations",
            ));
        }
        if current.resource_observations.len() != resources.entries.len() {
            return Err(invalid(
                "current resource observations differ from the retained native map",
            ));
        }
        for mapping in &resources.entries {
            let observation = current
                .resource_observations
                .binary_search_by(|observation| observation.resource.cmp(&mapping.resource))
                .ok()
                .map(|index| &current.resource_observations[index])
                .ok_or_else(|| invalid("current authority lacks a retained native resource"))?;
            if observation.state
                != (CurrentResourceState::Present {
                    revision: mapping.revision,
                })
            {
                return Err(invalid(
                    "current resource revision differs from the retained native map",
                ));
            }
        }
        Ok(())
    }

    /// Revalidates one exact freshly observed union for linked recovery.
    ///
    /// # Errors
    ///
    /// Returns an error when the publication is stale or revoked, its checked
    /// bindings or assignments changed, or its complete resource states differ.
    pub(crate) fn authorize_native_observed_no_op(
        &mut self,
        plan: &CheckedEffectPlan,
        assignments: &[ProviderAssignment],
        resources: &[CurrentResourceObservation],
    ) -> Result<(), CurrentAuthorityError> {
        let current = self.refresh()?;
        if plan.id() != self.commitment.plan {
            return Err(invalid("native no-op uses another checked plan"));
        }
        if current.bindings != plan.binding_plan().bindings() {
            return Err(invalid(
                "current policy bindings differ from the checked no-op plan",
            ));
        }
        if current.provider_assignments != assignments {
            return Err(invalid(
                "current provider assignments differ from the no-op observations",
            ));
        }
        if current.resource_observations != resources {
            return Err(invalid(
                "current resource observations differ from the linked recovery union",
            ));
        }
        Ok(())
    }
}

/// Holds one protected native authority publication through adapter dispatch.
pub struct NativeDispatchAuthority<Fence> {
    fence: Fence,
    expected_plan: PlanId,
}

impl<Fence> TrustedAuthoritySnapshot for NativeDispatchAuthority<Fence>
where
    Fence: AsRef<CurrentAbilityAuthorityDocument>,
{
    type Error = CurrentAuthorityError;

    fn authorize_role(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        authorize_current_role(
            self.fence.as_ref(),
            plan,
            binding,
            operation,
            method,
            purpose,
            role,
            self.expected_plan,
        )
    }

    fn authorize_resources(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        expected_provider: Option<&ProviderAssignment>,
        resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        authorize_current_resources(
            self.fence.as_ref(),
            plan,
            binding,
            operation,
            expected_provider,
            resources,
            self.expected_plan,
        )
    }
}

impl<Source, Clock> TrustedAuthoritySnapshot for NativeCurrentAdmissionPolicy<Source, Clock>
where
    Source: CurrentAbilityAuthoritySource,
    Clock: MonotonicClock,
{
    type Error = CurrentAuthorityError;

    fn authorize_role(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        let current = self.refresh()?;
        authorize_current_role(
            &current,
            plan,
            binding,
            operation,
            method,
            purpose,
            role,
            self.commitment.plan,
        )
    }

    fn authorize_resources(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        expected_provider: Option<&ProviderAssignment>,
        resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        let current = self.refresh()?;
        authorize_current_resources(
            &current,
            plan,
            binding,
            operation,
            expected_provider,
            resources,
            self.commitment.plan,
        )
    }
}

impl<Source, Clock> TrustedAdmissionPolicy for NativeCurrentAdmissionPolicy<Source, Clock>
where
    Source: CurrentAbilityAuthoritySource,
    Clock: MonotonicClock,
{
    type DispatchFence = NativeDispatchAuthority<Source::Fence>;

    fn acquire_dispatch_fence(
        &mut self,
        _plan: &CheckedEffectPlan,
        _binding: &Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
    ) -> Result<Self::DispatchFence, AuthorityRejection<Self::Error>> {
        let fence = self.source.acquire_current_fence().map_err(|error| {
            AuthorityRejection::new(
                RuntimeAuthorityRole::CurrentAuthorityPublication,
                source_error(error.to_string()),
            )
        })?;
        self.accept_publication(fence.as_ref()).map_err(|error| {
            AuthorityRejection::new(RuntimeAuthorityRole::CurrentAuthorityPublication, error)
        })?;
        Ok(NativeDispatchAuthority {
            fence,
            expected_plan: self.commitment.plan,
        })
    }
}

impl super::native_dispatch::NativeAuthorityRefresh for PublishingNativeAdmissionPolicy {
    fn refresh_authority(
        &mut self,
        plan: &CheckedEffectPlan,
        assignments: &[ProviderAssignment],
        resources: Vec<CurrentResourceObservation>,
    ) -> Result<(), Self::Error> {
        self.publish_authority(plan, assignments, resources)
            .map(|_| ())
    }
}

impl super::native_dispatch::NativeNoOpAdmissionPolicy for PublishingNativeAdmissionPolicy {
    fn authorize_no_op(
        &mut self,
        plan: &CheckedEffectPlan,
        assignments: &[ProviderAssignment],
        resources: &super::native_resource_map::NativeResourceMap,
    ) -> Result<(), Self::Error> {
        self.admission_mut()?
            .authorize_native_no_op(plan, assignments, resources)
    }

    fn authorize_observed_no_op(
        &mut self,
        plan: &CheckedEffectPlan,
        assignments: &[ProviderAssignment],
        resources: &[CurrentResourceObservation],
    ) -> Result<(), Self::Error> {
        self.admission_mut()?
            .authorize_native_observed_no_op(plan, assignments, resources)
    }
}

impl TrustedAuthoritySnapshot for PublishingNativeAdmissionPolicy {
    type Error = CurrentAuthorityError;

    fn authorize_role(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        self.admission_mut()?
            .authorize_role(plan, binding, operation, method, purpose, role)
    }

    fn authorize_resources(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        expected_provider: Option<&ProviderAssignment>,
        resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        self.admission_mut()?.authorize_resources(
            plan,
            binding,
            operation,
            expected_provider,
            resources,
        )
    }
}

impl TrustedAdmissionPolicy for PublishingNativeAdmissionPolicy {
    type DispatchFence = NativeDispatchAuthority<RootOwnedCurrentAuthorityFence>;

    fn acquire_dispatch_fence(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> Result<Self::DispatchFence, AuthorityRejection<Self::Error>> {
        self.admission_mut()
            .map_err(|error| {
                AuthorityRejection::new(RuntimeAuthorityRole::CurrentAuthorityPublication, error)
            })?
            .acquire_dispatch_fence(plan, binding, operation, method, purpose)
    }
}

fn authorize_current_role(
    current: &CurrentAbilityAuthorityDocument,
    plan: &CheckedEffectPlan,
    binding: &Binding,
    operation: &Operation,
    method: &MethodReference,
    purpose: InvocationPurpose,
    role: RuntimeAuthorityRole,
    expected_plan: PlanId,
) -> Result<(), CurrentAuthorityError> {
    require_checked_membership(plan, binding, operation, expected_plan)?;
    let authorized = find_binding(current, binding)?;

    match role {
        RuntimeAuthorityRole::CallerBindingGrant => {
            if authorized.id != binding.id
                || authorized.request != binding.request
                || authorized.source != binding.source
                || authorized.caller_grant != binding.caller_grant
                || authorized.policy_revision != binding.policy_revision
                || authorized.lifetime != binding.lifetime
                || authorized.mediation_allowed != binding.mediation_allowed
            {
                return Err(invalid(
                    "current caller binding or grant differs from the checked operation",
                ));
            }
        }
        RuntimeAuthorityRole::ProviderMethodImplementation => {
            if authorized.interface != binding.interface
                || authorized.provider != binding.provider
                || authorized.provider_package != binding.provider_package
                || authorized.implementation != binding.implementation
                || authorized.provider_grant != binding.provider_grant
            {
                return Err(invalid(
                    "current provider method or implementation differs from the checked binding",
                ));
            }
            require_purpose_method(operation, method, purpose)?;
            plan.authorize_invocation(operation, method)
                .map_err(|error| invalid(format!("checked invocation is unauthorized: {error}")))?;
        }
        RuntimeAuthorityRole::EnforcementPlatformGuarantee => {
            if authorized.guarantees != binding.guarantees {
                return Err(invalid(
                    "current enforcement or platform guarantees differ from the checked binding",
                ));
            }
        }
        RuntimeAuthorityRole::AssignmentIncarnation => {
            require_live_assignment(current, binding)?;
        }
        RuntimeAuthorityRole::CurrentAuthorityPublication => {}
    }
    Ok(())
}

fn authorize_current_resources(
    current: &CurrentAbilityAuthorityDocument,
    plan: &CheckedEffectPlan,
    binding: &Binding,
    operation: &Operation,
    expected_provider: Option<&ProviderAssignment>,
    resources: &[ResourceAdmissionEvidence],
    expected_plan: PlanId,
) -> Result<(), CurrentAuthorityError> {
    require_checked_membership(plan, binding, operation, expected_plan)?;
    let assignment = require_live_assignment(current, binding)?;
    if expected_provider.is_some_and(|expected| expected != assignment) {
        return Err(invalid(
            "durable provider assignment differs from current policy assignment",
        ));
    }
    if operation.accesses.len() != resources.len() {
        return Err(invalid(
            "resource evidence count differs from the checked operation",
        ));
    }

    for (access, evidence) in operation.accesses.iter().zip(resources) {
        require_current_resource_evidence(current, assignment, access, evidence)?;
    }
    Ok(())
}

fn require_current_resource_evidence(
    current: &CurrentAbilityAuthorityDocument,
    assignment: &ProviderAssignment,
    access: &ResourceAccess,
    evidence: &ResourceAdmissionEvidence,
) -> Result<(), CurrentAuthorityError> {
    if evidence.resource() != &access.resource {
        return Err(invalid("resource evidence names another checked resource"));
    }
    if evidence.provider_incarnation() != Some(&assignment.incarnation) {
        return Err(invalid(
            "resource evidence differs from the checked handler assignment",
        ));
    }
    let observed = current
        .resource_observations
        .binary_search_by(|observation| observation.resource.cmp(&access.resource))
        .ok()
        .map(|index| current.resource_observations[index].state)
        .ok_or_else(|| invalid("current authority lacks an authoritative resource observation"))?;
    let evidence_matches = match (evidence.revision_observation(), observed) {
        (ResourceRevisionObservation::Absent, CurrentResourceState::Absent) => true,
        (
            ResourceRevisionObservation::Present(evidence_revision),
            CurrentResourceState::Present { revision }
            | CurrentResourceState::Stopped { revision }
            | CurrentResourceState::Divergent { revision },
        ) => evidence_revision == revision,
        (ResourceRevisionObservation::Unknown, CurrentResourceState::Divergent { .. }) => true,
        _ => false,
    };
    if !evidence_matches {
        return Err(invalid(
            "resource evidence differs from authoritative current state",
        ));
    }
    Ok(())
}

/// Reports protected current-authority publication or admission failures.
#[derive(Debug)]
pub enum CurrentAuthorityError {
    /// A filesystem operation on the protected authority path failed.
    Io {
        /// Names the failed operation.
        operation: &'static str,
        /// Names the protected path.
        path: PathBuf,
        /// Retains the operating-system failure.
        source: io::Error,
    },
    /// A source implementation could not supply current authority.
    Source(String),
    /// Current authority failed closed validation or exact admission checks.
    Invalid(String),
}

impl fmt::Display for CurrentAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
            Self::Source(reason) => write!(formatter, "loading current authority: {reason}"),
            Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl std::error::Error for CurrentAuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Source(_) | Self::Invalid(_) => None,
        }
    }
}

fn build_publication(
    publication: CurrentAuthorityPublication<'_>,
) -> Result<CurrentAbilityAuthorityDocument, CurrentAuthorityError> {
    let policy = publication.resolution_policy;
    let policy_digest = policy
        .content_digest()
        .map_err(|error| invalid(format!("validating resolution policy: {error}")))?;
    let policy_revision = publication.plan.binding_plan().document().policy_revision;
    if policy.policy_revision != policy_revision {
        return Err(invalid(
            "resolution policy revision differs from the checked plan",
        ));
    }
    let transition_digest = publication
        .transition_authority
        .map(VersionedDocument::content_digest)
        .transpose()
        .map_err(|error| invalid(format!("validating transition authority: {error}")))?;
    if publication
        .transition_authority
        .is_some_and(|authority| authority.authorization_policy_revision != policy_revision)
    {
        return Err(invalid(
            "transition authority revision differs from the checked plan",
        ));
    }
    if publication.transition_authority.is_some_and(|authority| {
        let mut identities = BTreeSet::new();
        authority
            .teardown_bindings
            .iter()
            .any(|entry| !identities.insert(entry.binding.id.clone()))
    }) {
        return Err(invalid(
            "transition authority contains duplicate binding identities",
        ));
    }
    let platform_policy_digest = publication
        .platform_policy
        .map(VersionedDocument::content_digest)
        .transpose()
        .map_err(|error| invalid(format!("validating platform policy: {error}")))?;
    if publication.platform_policy.is_some_and(|platform| {
        platform.policy_revision != policy_revision
            || platform
                .bindings
                .iter()
                .any(|binding| binding.policy_revision != policy_revision)
            || platform
                .bindings
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
    }) {
        return Err(invalid(
            "platform policy bindings differ from the checked policy revision or order",
        ));
    }

    let mut required_features = policy.required_features.clone();
    if let Some(authority) = publication.transition_authority {
        required_features.extend(authority.required_features.iter().cloned());
    }
    if let Some(platform) = publication.platform_policy {
        required_features.extend(platform.required_features.iter().cloned());
    }
    required_features.sort();
    required_features.dedup();

    let mut bindings = Vec::with_capacity(publication.plan.binding_plan().bindings().len());
    for checked in publication.plan.binding_plan().bindings() {
        let policy_binding = independently_issued_binding(
            checked,
            policy,
            publication.platform_policy,
            publication.transition_authority,
        )?;
        if &policy_binding != checked {
            return Err(invalid(format!(
                "checked binding {:?} differs from independently issued policy authority",
                checked.id
            )));
        }
        bindings.push(policy_binding);
    }
    bindings.sort_by(|left, right| left.id.cmp(&right.id));
    if bindings.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(invalid("policy issued duplicate binding identities"));
    }

    let mut provider_assignments = publication.observations.provider_assignments;
    provider_assignments.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then_with(|| left.interface.cmp(&right.interface))
    });
    if provider_assignments
        .windows(2)
        .any(|pair| pair[0].provider == pair[1].provider && pair[0].interface == pair[1].interface)
    {
        return Err(invalid(
            "observations contain duplicate provider assignments",
        ));
    }
    let mut resource_observations = publication.observations.resource_observations;
    resource_observations.sort_by(|left, right| left.resource.cmp(&right.resource));
    if resource_observations
        .windows(2)
        .any(|pair| pair[0].resource == pair[1].resource)
    {
        return Err(invalid("observations contain duplicate resource revisions"));
    }

    let carries_runtime_health = resource_observations.iter().any(|observation| {
        matches!(
            observation.state,
            CurrentResourceState::Stopped { .. } | CurrentResourceState::Divergent { .. }
        )
    });
    let schema = if publication.transaction.is_some() || carries_runtime_health {
        CURRENT_ABILITY_AUTHORITY_SCHEMA_V2
    } else {
        CURRENT_ABILITY_AUTHORITY_SCHEMA
    };
    Ok(CurrentAbilityAuthorityDocument {
        schema: schema.to_string(),
        required_features,
        policy_fence: publication.policy_fence,
        transaction: if schema == CURRENT_ABILITY_AUTHORITY_SCHEMA_V2 {
            Some(
                publication
                    .transaction
                    .cloned()
                    .ok_or_else(|| invalid("version-2 current authority lacks a transaction"))?,
            )
        } else {
            None
        },
        authority_epoch: 0,
        policy_revision,
        resolution_policy: policy_digest,
        platform_policy: platform_policy_digest,
        transition_authority: transition_digest,
        sequence: publication.observations.sequence,
        observed_at_restart_millis: publication.observations.observed_at_restart_millis,
        max_age_millis: publication.observations.max_age_millis,
        plan: publication.plan.id(),
        bindings,
        provider_assignments,
        resource_observations,
    })
}

fn independently_issued_binding(
    checked: &Binding,
    policy: &ResolutionPolicyDocument,
    platform: Option<&CurrentPlatformPolicyDocument>,
    transition: Option<&TransitionAuthorizationDocument>,
) -> Result<Binding, CurrentAuthorityError> {
    let transition_binding = transition
        .into_iter()
        .flat_map(|authority| &authority.teardown_bindings)
        .map(|authority| &authority.binding)
        .find(|binding| binding.id == checked.id);
    let platform_binding = platform
        .into_iter()
        .flat_map(|policy| &policy.bindings)
        .find(|binding| binding.id == checked.id);

    let candidates = policy
        .candidates
        .iter()
        .filter(|candidate| candidate_matches_binding(candidate, checked))
        .collect::<Vec<_>>();
    let direct = match (transition_binding, platform_binding) {
        (Some(_), Some(_)) => {
            return Err(invalid(format!(
                "binding {:?} is ambiguously issued by transition and platform policy",
                checked.id
            )));
        }
        (Some(binding), None) | (None, Some(binding)) => Some(binding),
        (None, None) => None,
    };
    if let Some(binding) = direct {
        if !candidates.is_empty() {
            return Err(invalid(format!(
                "binding {:?} is ambiguously issued by native and resolution policy",
                checked.id
            )));
        }
        return Ok(binding.clone());
    }
    let [candidate] = candidates.as_slice() else {
        return Err(invalid(format!(
            "checked binding {:?} lacks one exact independently issued candidate",
            checked.id
        )));
    };
    Ok(Binding {
        id: checked.id.clone(),
        request: candidate.request.clone(),
        interface: candidate.interface.clone(),
        provider: candidate.provider.clone(),
        provider_package: Some(candidate.provider_package),
        implementation: candidate.implementation.clone(),
        source: checked.source,
        caller_grant: candidate.caller_grant.clone(),
        provider_grant: candidate.provider_grant.clone(),
        guarantees: candidate.guarantees.clone(),
        policy_revision: candidate.policy_revision,
        lifetime: candidate.lifetime,
        mediation_allowed: candidate.mediation_allowed,
    })
}

/// Verifies that each checked binding has one exact independent policy issuer.
///
/// # Errors
///
/// Returns an error when a binding is absent, ambiguous, or differs from the
/// exact resolution, transition, or native-platform policy grant.
pub(crate) fn validate_independent_binding_authority(
    plan: &CheckedEffectPlan,
    resolution: &ResolutionPolicyDocument,
    platform: Option<&CurrentPlatformPolicyDocument>,
    transition: Option<&TransitionAuthorizationDocument>,
) -> Result<(), CurrentAuthorityError> {
    for checked in plan.binding_plan().bindings() {
        let issued = independently_issued_binding(checked, resolution, platform, transition)?;
        if &issued != checked {
            return Err(invalid(format!(
                "checked binding {:?} differs from independently issued policy authority",
                checked.id
            )));
        }
    }
    Ok(())
}

fn candidate_matches_binding(
    candidate: &aos_ability_plan::BindingCandidate,
    binding: &Binding,
) -> bool {
    candidate.request == binding.request
        && candidate.interface == binding.interface
        && candidate.provider == binding.provider
        && Some(candidate.provider_package) == binding.provider_package
        && candidate.implementation == binding.implementation
        && candidate.policy_revision == binding.policy_revision
}

fn require_checked_membership(
    plan: &CheckedEffectPlan,
    binding: &Binding,
    operation: &Operation,
    expected_plan: PlanId,
) -> Result<(), CurrentAuthorityError> {
    if plan.id() != expected_plan
        || plan.operation(&operation.key) != Some(operation)
        || plan.binding_plan().binding(&binding.id) != Some(binding)
        || operation.binding != binding.id
    {
        return Err(invalid(
            "operation and binding do not belong to the retained checked plan",
        ));
    }
    Ok(())
}

fn find_binding<'a>(
    current: &'a CurrentAbilityAuthorityDocument,
    binding: &Binding,
) -> Result<&'a Binding, CurrentAuthorityError> {
    current
        .bindings
        .binary_search_by(|candidate| candidate.id.cmp(&binding.id))
        .ok()
        .map(|index| &current.bindings[index])
        .ok_or_else(|| invalid("current policy revoked the checked binding"))
}

fn require_live_assignment<'a>(
    current: &'a CurrentAbilityAuthorityDocument,
    binding: &Binding,
) -> Result<&'a ProviderAssignment, CurrentAuthorityError> {
    let assignment = current
        .provider_assignments
        .binary_search_by(|assignment| {
            assignment
                .provider
                .cmp(&binding.provider)
                .then_with(|| assignment.interface.cmp(&binding.interface))
        })
        .ok()
        .map(|index| &current.provider_assignments[index])
        .ok_or_else(|| invalid("current authority lacks the provider assignment"))?;
    if assignment.implementation != binding.implementation {
        return Err(invalid(
            "current provider assignment differs from the checked binding",
        ));
    }
    Ok(assignment)
}

fn require_purpose_method(
    operation: &Operation,
    method: &MethodReference,
    purpose: InvocationPurpose,
) -> Result<(), CurrentAuthorityError> {
    let expected = match purpose {
        InvocationPurpose::Effect => {
            return if method.interface == operation.interface && method.method == operation.method {
                Ok(())
            } else {
                Err(invalid("effect purpose names another operation method"))
            };
        }
        InvocationPurpose::Reconcile | InvocationPurpose::ReconcileCompensation => {
            operation.recovery.reconcile.as_ref()
        }
        InvocationPurpose::Cancel => operation.recovery.cancel.as_ref(),
        InvocationPurpose::Compensate => operation.recovery.compensate.as_ref(),
    };
    if expected != Some(method) {
        return Err(invalid(
            "invocation purpose does not match the checked recovery method",
        ));
    }
    Ok(())
}

fn invalid(reason: impl Into<String>) -> CurrentAuthorityError {
    CurrentAuthorityError::Invalid(reason.into())
}

fn source_error(reason: impl Into<String>) -> CurrentAuthorityError {
    CurrentAuthorityError::Source(reason.into())
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> CurrentAuthorityError {
    CurrentAuthorityError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests;
