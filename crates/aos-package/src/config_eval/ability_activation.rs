//! Immutable inputs for native structured ability activation.
//!
//! A version-3 configuration manifest pins two canonical JSON sidecars. The
//! desired sidecar carries the original composition seed and its target
//! environment; the policy sidecar carries the independently authenticated
//! resolution-policy sequence. This module verifies each complete Nix store
//! object before reading its document through a descriptor-relative,
//! no-symlink path and checking the exact document commitment.
//!
//! The two sidecar document shapes are:
//!
//! ```json
//! {"environment":{"schema":"aos.ability.environment/v1","...":"..."},"schema":"aos.ability.activation-desired/v1","seed":{"schema":"aos.ability.desired-state/v1","...":"..."}}
//! {"native_resource_map":{"desired_state":"sha256:...","entries":[...],"schema":"aos.ability.native-resource-map/v3"},"platform_policy":{"bindings":[...],"policy_revision":"sha256:...","required_features":[],"schema":"aos.ability.platform-policy/v1"},"policies":[{"schema":"aos.ability.resolution-policy/v1","...":"..."}],"schema":"aos.ability.authenticated-policy-set/v3","transition_authority":null}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read as _;
use std::path::{Component, Path};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AggregateOutput, DesiredStateDocument, EnvironmentDocument,
    ImplementationKind, RequiredFeature, ResourceReference, TransitionAuthorizationDocument,
    ValueExpression, VersionedDocument,
};
use aos_ability_plan::{
    PlanningReplayInputs, PlanningSnapshot, ResolutionPolicyDocument, TransitionInputs,
    TransitionPlanner, TransitionReconciliation, VerifiedPlanningSnapshot,
};
use aos_ability_runtime::bundle::ReloadablePlanBundle;
use aos_ability_validate::{
    BindingAuthorityKind, CheckedBindingPlan, CheckedEffectPlan, CheckedTransitionAuthority,
    TransitionAuthorityInputs,
};
use aos_contract::Sha256Digest;
use rustix::fs::{self, FileType, Mode, OFlags};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::ability::RestrictedAbilityEvaluator;
use super::ability_policy::{CurrentAbilityAuthorityDocument, CurrentPlatformPolicyDocument};
use super::ability_policy_authority::OperatorPolicyAuthorityStore;
use super::materialize::{
    AbilityActivationInput, AbilityPackageCoordinate as PinnedAbilityPackageCoordinate,
    ConfigManifest, PinnedAbilitySidecar,
};
use super::native_resource_map::{
    NativeOutputLocator, NativeResourceMap, NativeResourceMapping, NativeResourceQualification,
    kubernetes_resource_owner,
};
use super::runtime::{RuntimePackageOrigin, RuntimeResolution};
use crate::ability_package::{
    AbilityPackageCoordinate, NativeAbilityRetentionVerifier, VerifiedAbilityPackageSet,
};
use crate::config::ApmConfig;

/// Canonical desired-state input supplied to native composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationDesiredInputDocument {
    /// Carries `aos.ability.activation-desired/v1`.
    pub schema: String,
    /// Supplies the original normalized desired-state composition seed.
    pub seed: DesiredStateDocument,
    /// Supplies the authenticated target environment and current inventory.
    pub environment: EnvironmentDocument,
}

impl ActivationDesiredInputDocument {
    /// Current activation desired-input schema.
    pub const SCHEMA: &'static str = "aos.ability.activation-desired/v1";

    /// Validates the desired seed and its exact environment commitment.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema or an embedded document is invalid, or
    /// when the seed names a different target environment.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == Self::SCHEMA,
            "unsupported ability activation desired-input schema {:?}",
            self.schema
        );
        validate_embedded_document(&self.seed, "activation desired seed")?;
        validate_embedded_document(&self.environment, "activation target environment")?;
        let environment = self
            .environment
            .content_digest()
            .context("identifying activation target environment")?;
        ensure!(
            self.seed.environment == environment,
            "activation desired seed names a different target environment"
        );
        Ok(())
    }
}

/// Canonical independently authenticated policy sequence for composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPolicySetDocument {
    /// Carries a supported authenticated policy-set schema.
    pub schema: String,
    /// Lists exact policy snapshots in canonical desired-state order.
    pub policies: Vec<ResolutionPolicyDocument>,
    /// Supplies fresh authority for exact teardown bindings, when needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_authority: Option<TransitionAuthorizationDocument>,
    /// Supplies independently authorized logical-to-physical execution mappings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_resource_map: Option<NativeResourceMap>,
    /// Supplies operator-authorized bindings issued by the native platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_policy: Option<CurrentPlatformPolicyDocument>,
}

impl AuthenticatedPolicySetDocument {
    /// Planning-only policy-set schema without native execution authority.
    pub const SCHEMA_V1: &'static str = "aos.ability.authenticated-policy-set/v1";
    /// Current policy-set schema carrying native execution authority.
    pub const SCHEMA_V2: &'static str = "aos.ability.authenticated-policy-set/v2";
    /// Native execution policy set with explicit platform binding authority.
    pub const SCHEMA_V3: &'static str = "aos.ability.authenticated-policy-set/v3";
    /// Current authenticated policy-set schema.
    pub const SCHEMA: &'static str = Self::SCHEMA_V3;

    /// Constructs a canonical execution-eligible policy-set document.
    ///
    /// # Errors
    ///
    /// Returns an error when policies are duplicated or inconsistent with the
    /// desired input, or when the native resource map is intrinsically invalid.
    pub fn new(
        desired: &ActivationDesiredInputDocument,
        mut policies: Vec<ResolutionPolicyDocument>,
        transition_authority: Option<TransitionAuthorizationDocument>,
        native_resource_map: NativeResourceMap,
    ) -> Result<Self> {
        policies.sort_by_key(|policy| policy.desired_state);
        let document = Self {
            schema: Self::SCHEMA_V2.to_string(),
            policies,
            transition_authority,
            native_resource_map: Some(native_resource_map),
            platform_policy: None,
        };
        document.validate(desired)?;
        Ok(document)
    }

    /// Validates policy sequencing and its relationship to a desired input.
    ///
    /// Version 1 remains valid for pure planning replay but carries no native
    /// execution authority. Version 2 requires an intrinsic resource map.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema, ordering, environment commitments,
    /// embedded documents, or native map are invalid.
    pub fn validate(&self, desired: &ActivationDesiredInputDocument) -> Result<()> {
        ensure!(
            matches!(
                self.schema.as_str(),
                Self::SCHEMA_V1 | Self::SCHEMA_V2 | Self::SCHEMA_V3
            ),
            "unsupported authenticated ability policy-set schema {:?}",
            self.schema
        );
        ensure!(
            (self.schema == Self::SCHEMA_V1
                && self.native_resource_map.is_none()
                && self.platform_policy.is_none())
                || (self.schema == Self::SCHEMA_V2
                    && self.native_resource_map.is_some()
                    && self.platform_policy.is_none())
                || (self.schema == Self::SCHEMA_V3 && self.native_resource_map.is_some()),
            "authenticated policy-set schema does not match native authority fields"
        );
        ensure!(
            self.policies
                .windows(2)
                .all(|pair| pair[0].desired_state < pair[1].desired_state),
            "authenticated ability policies are not in strict desired-state order"
        );

        let environment = desired
            .environment
            .content_digest()
            .context("identifying activation target environment")?;
        for policy in &self.policies {
            validate_embedded_document(policy, "authenticated resolution policy")?;
            ensure!(
                policy.environment == environment,
                "authenticated resolution policy names a different target environment"
            );
        }
        if let Some(authority) = &self.transition_authority {
            validate_embedded_document(authority, "authenticated transition authority")?;
        }
        if let Some(resource_map) = &self.native_resource_map {
            resource_map.validate()?;
            validate_postgresql_credential_maps(resource_map)?;
        }
        if let Some(platform_policy) = &self.platform_policy {
            validate_embedded_document(platform_policy, "authenticated platform policy")?;
            ensure!(
                platform_policy
                    .bindings
                    .windows(2)
                    .all(|pair| pair[0].id < pair[1].id),
                "authenticated platform-policy bindings are not in strict identity order"
            );
            ensure!(
                platform_policy.bindings.iter().all(|binding| {
                    binding.policy_revision == platform_policy.policy_revision
                        && binding.provider.environment == desired.environment.environment
                        && binding.request.consumer.environment == desired.environment.environment
                }),
                "authenticated platform-policy binding differs from its policy revision or target environment"
            );
        }
        Ok(())
    }
}

fn validate_postgresql_credential_maps(resource_map: &NativeResourceMap) -> Result<()> {
    for mapping in resource_map.entries.iter().filter(|mapping| {
        matches!(
            mapping.qualification,
            NativeResourceQualification::Postgresql { .. }
        )
    }) {
        ensure!(
            resource_map.entries.iter().any(|candidate| {
                candidate.resource.provider == mapping.resource.provider
                    && matches!(
                        candidate.qualification,
                        NativeResourceQualification::CredentialDelivery { .. }
                    )
            }),
            "PostgreSQL native execution requires authenticated credential delivery; trust authentication is unsupported"
        );
    }
    Ok(())
}

/// Holds live-verified immutable inputs ready for native specialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAbilityActivationInputs {
    desired: ActivationDesiredInputDocument,
    policy_set: AuthenticatedPolicySetDocument,
    policy_sidecar: PinnedAbilitySidecar,
    packages: Vec<PinnedAbilityPackageCoordinate>,
}

/// Owns one checked native effect graph and its reloadable provenance.
#[derive(Clone, Debug)]
pub struct SpecializedAbilityActivation {
    plan: CheckedEffectPlan,
    bundle: ReloadablePlanBundle,
    current_binding_plan: Option<CheckedBindingPlan>,
    desired_state: DesiredStateDocument,
    current_desired_state: Option<DesiredStateDocument>,
    desired_native_resources: NativeResourceMap,
    current_native_resources: Option<NativeResourceMap>,
    policy_authority: Vec<PinnedAbilitySidecar>,
}

impl SpecializedAbilityActivation {
    /// Returns the checked effect graph selected for execution.
    #[must_use]
    pub const fn plan(&self) -> &CheckedEffectPlan {
        &self.plan
    }

    /// Returns the reloadable planning and transition provenance.
    #[must_use]
    pub const fn bundle(&self) -> &ReloadablePlanBundle {
        &self.bundle
    }

    /// Returns the independently checked retained binding plan, when present.
    #[must_use]
    pub const fn current_binding_plan(&self) -> Option<&CheckedBindingPlan> {
        self.current_binding_plan.as_ref()
    }

    /// Returns the freshly specialized fixed-point desired state.
    #[must_use]
    pub const fn desired_state(&self) -> &DesiredStateDocument {
        &self.desired_state
    }

    /// Returns the retained generation's fixed-point desired state, when present.
    #[must_use]
    pub const fn current_desired_state(&self) -> Option<&DesiredStateDocument> {
        self.current_desired_state.as_ref()
    }

    /// Returns the independently authorized desired native-resource mapping.
    #[must_use]
    pub const fn desired_native_resources(&self) -> &NativeResourceMap {
        &self.desired_native_resources
    }

    /// Returns the retained generation's native-resource mapping, when present.
    #[must_use]
    pub const fn current_native_resources(&self) -> Option<&NativeResourceMap> {
        self.current_native_resources.as_ref()
    }

    /// Rechecks every policy grant needed by a dependent native dispatch.
    ///
    /// Dispatchers call this immediately before each operation admission, so
    /// removing or replacing an operator record fences further effects while
    /// leaving an already admitted in-flight operation to journal recovery.
    ///
    /// # Errors
    ///
    /// Returns an error when the desired policy authorization is absent,
    /// replaced, unsafe, or no longer matches its exact sidecar.
    pub fn reauthorize(&self, operator_authority: &OperatorPolicyAuthorityStore) -> Result<()> {
        self.acquire_authority_fence(operator_authority).map(|_| ())
    }

    /// Captures exact operator grants for one monotonic dispatch decision.
    ///
    /// Each protected record read is the authorization linearization point.
    /// Removing a record afterward fences the next invocation; it does not
    /// retroactively revoke the dispatch whose exact records are returned.
    ///
    /// # Errors
    ///
    /// Returns an error when any desired policy authorization is absent,
    /// replaced, unsafe, or no longer matches its exact sidecar.
    pub fn acquire_authority_fence(
        &self,
        operator_authority: &OperatorPolicyAuthorityStore,
    ) -> Result<Vec<super::ability_policy_authority::OperatorPolicyAuthorityRecord>> {
        let mut records = Vec::with_capacity(self.policy_authority.len());
        for policy in &self.policy_authority {
            records.push(operator_authority.authorize(policy)?);
        }
        Ok(records)
    }

    /// Separates the owned checked graph from its reloadable provenance.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CheckedEffectPlan,
        ReloadablePlanBundle,
        DesiredStateDocument,
        Option<DesiredStateDocument>,
        NativeResourceMap,
        Option<NativeResourceMap>,
        Vec<PinnedAbilitySidecar>,
    ) {
        (
            self.plan,
            self.bundle,
            self.desired_state,
            self.current_desired_state,
            self.desired_native_resources,
            self.current_native_resources,
            self.policy_authority,
        )
    }
}

impl VerifiedAbilityActivationInputs {
    /// Loads and authenticates the structured activation inputs from a manifest.
    ///
    /// The manifest must carry the version-3 activation descriptor. Both
    /// complete sidecar store objects are checked against their pinned NAR and
    /// reference identities before either document is accepted.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest lacks activation inputs, a store
    /// object differs from its commitment, a document path traverses a link or
    /// special object, or a document is noncanonical, malformed, or
    /// inconsistent with the other input.
    pub fn load(
        manifest: &ConfigManifest,
        operator_authority: &OperatorPolicyAuthorityStore,
    ) -> Result<Self> {
        manifest.validate()?;
        let activation = manifest
            .inputs
            .ability_activation
            .as_ref()
            .context("config manifest does not carry native ability activation inputs")?;
        operator_authority
            .authorize(&activation.authenticated_policy_set)
            .context("authenticating native policy set through operator authority")?;
        Self::load_activation(activation)
    }

    /// Returns the original desired-state seed and target environment.
    #[must_use]
    pub const fn desired(&self) -> &ActivationDesiredInputDocument {
        &self.desired
    }

    /// Returns the independently authenticated resolution-policy sequence.
    #[must_use]
    pub const fn policy_set(&self) -> &AuthenticatedPolicySetDocument {
        &self.policy_set
    }

    /// Returns the exact sidecar descriptor protected by operator authority.
    #[must_use]
    pub const fn policy_sidecar(&self) -> &PinnedAbilitySidecar {
        &self.policy_sidecar
    }

    fn load_activation(activation: &AbilityActivationInput) -> Result<Self> {
        let desired_bytes = load_sidecar(&activation.desired_state, "desired state")?;
        let desired: ActivationDesiredInputDocument =
            decode_canonical_sidecar(&desired_bytes, ActivationDesiredInputDocument::SCHEMA)?;
        desired.validate()?;

        let policy_bytes = load_sidecar(
            &activation.authenticated_policy_set,
            "authenticated policy set",
        )?;
        let policy_set: AuthenticatedPolicySetDocument =
            decode_canonical_sidecar(&policy_bytes, AuthenticatedPolicySetDocument::SCHEMA)?;
        policy_set.validate(&desired)?;
        validate_policy_feature_binding(&activation.required_features, &policy_set)?;

        Ok(Self {
            desired,
            policy_set,
            policy_sidecar: activation.authenticated_policy_set.clone(),
            packages: activation.packages.clone(),
        })
    }
}

fn validate_policy_feature_binding(
    required_features: &[String],
    policy_set: &AuthenticatedPolicySetDocument,
) -> Result<()> {
    let native_execution = required_features
        .iter()
        .any(|feature| feature == "native-resource-map-v2");
    let native_platform_policy = required_features
        .iter()
        .any(|feature| feature == "native-platform-policy-v1");
    ensure!(
        (policy_set.schema == AuthenticatedPolicySetDocument::SCHEMA_V1
            && !native_execution
            && !native_platform_policy)
            || (policy_set.schema == AuthenticatedPolicySetDocument::SCHEMA_V2
                && native_execution
                && !native_platform_policy)
            || (policy_set.schema == AuthenticatedPolicySetDocument::SCHEMA_V3
                && native_execution
                && native_platform_policy),
        "authenticated policy-set schema does not match its manifest feature gates"
    );
    Ok(())
}

/// Specializes authenticated package modules into one checked native graph.
///
/// Desired and prior planning each use the exact sealed package catalog pinned
/// by their own generation. Their union is used only to validate a transition
/// that can retain artifacts from both generations. Prior state is planning
/// provenance only. Any removal must also carry the freshly authenticated
/// transition authority from the desired policy set.
///
/// # Errors
///
/// Returns an error when composition, snapshot reconstruction, teardown
/// authorization, transition evaluation, or reload-bundle construction fails.
pub fn specialize_activation(
    desired: &VerifiedAbilityActivationInputs,
    current: Option<&VerifiedAbilityActivationInputs>,
    packages: &VerifiedAbilityPackageSet,
    evaluator: &mut RestrictedAbilityEvaluator,
) -> Result<SpecializedAbilityActivation> {
    specialize_activation_with_reconciliation(desired, current, packages, evaluator, None)
}

/// Constructs a fresh linked repair graph from protected live observations.
///
/// The source activation must be effect-free and use the same desired and
/// retained planning inputs. The resulting transition snapshot retains the
/// source-plan link and the exact current-authority observation publication.
///
/// # Errors
///
/// Returns an error when the source plan can perform effects, a planning or
/// policy commitment differs, observations do not cover the native map, or
/// provider construction does not produce a distinct repair graph.
pub fn specialize_reconciliation(
    desired: &VerifiedAbilityActivationInputs,
    current: &VerifiedAbilityActivationInputs,
    packages: &VerifiedAbilityPackageSet,
    evaluator: &mut RestrictedAbilityEvaluator,
    source: &SpecializedAbilityActivation,
    reconciliation: TransitionReconciliation,
    supported_features: &BTreeSet<RequiredFeature>,
) -> Result<SpecializedAbilityActivation> {
    specialize_reconciliation_inner(
        desired,
        current,
        packages,
        evaluator,
        source,
        reconciliation,
        supported_features,
        None,
    )
}

/// Constructs a linked repair graph for resources retained by failed adoption receipts.
///
/// Unlike ordinary drift repair, the initially checked graph may contain the
/// exact adoption effects. A freshly authenticated classification still links
/// the replacement graph, and every named receipt resource must be covered by
/// that classification.
///
/// # Errors
///
/// Returns an error under the same conditions as [`specialize_reconciliation`],
/// or when the failed receipt set is empty, unobserved, or lacks exact adoption
/// authority for an effectful source graph.
pub(crate) fn specialize_adoption_reconciliation(
    desired: &VerifiedAbilityActivationInputs,
    current: &VerifiedAbilityActivationInputs,
    packages: &VerifiedAbilityPackageSet,
    evaluator: &mut RestrictedAbilityEvaluator,
    source: &SpecializedAbilityActivation,
    reconciliation: TransitionReconciliation,
    supported_features: &BTreeSet<RequiredFeature>,
    receipt_resources: &BTreeSet<aos_ability_model::ResourceId>,
) -> Result<SpecializedAbilityActivation> {
    ensure!(
        !receipt_resources.is_empty()
            && reconciliation.unsettled_provider_adoptions
                == receipt_resources.iter().cloned().collect::<Vec<_>>()
            && receipt_resources.iter().all(|resource| {
                reconciliation
                    .observations
                    .iter()
                    .any(|observation| &observation.resource == resource)
            }),
        "settled provider-adoption recovery does not classify every receipt resource"
    );
    if !source.plan().operations().is_empty() {
        ensure!(
            receipt_resources.iter().all(|resource| {
                source
                    .bundle()
                    .provider_adoptions()
                    .iter()
                    .any(|adoption| &adoption.resource == resource)
            }),
            "effectful provider-adoption recovery lacks exact transition authority"
        );
    }

    specialize_reconciliation_inner(
        desired,
        current,
        packages,
        evaluator,
        source,
        reconciliation,
        supported_features,
        Some(receipt_resources),
    )
}

#[allow(clippy::too_many_arguments)]
fn specialize_reconciliation_inner(
    desired: &VerifiedAbilityActivationInputs,
    current: &VerifiedAbilityActivationInputs,
    packages: &VerifiedAbilityPackageSet,
    evaluator: &mut RestrictedAbilityEvaluator,
    source: &SpecializedAbilityActivation,
    reconciliation: TransitionReconciliation,
    supported_features: &BTreeSet<RequiredFeature>,
    settled_adoption_resources: Option<&BTreeSet<aos_ability_model::ResourceId>>,
) -> Result<SpecializedAbilityActivation> {
    ensure!(
        source.plan().operations().is_empty() || settled_adoption_resources.is_some(),
        "runtime reconciliation source plan is not effect-free or adoption-linked"
    );
    ensure!(
        reconciliation.source_plan == source.plan().id(),
        "runtime reconciliation names another source plan"
    );
    validate_reconciliation_authority_source(desired, source, &reconciliation, supported_features)?;

    let repaired = specialize_activation_with_reconciliation(
        desired,
        Some(current),
        packages,
        evaluator,
        Some(&reconciliation),
    )?;
    ensure!(
        repaired.bundle().desired_planning_digest() == source.bundle().desired_planning_digest()
            && repaired.bundle().current_planning_digest()
                == source.bundle().current_planning_digest(),
        "runtime reconciliation changed its authenticated planning inputs"
    );
    ensure!(
        repaired.plan().id() != source.plan().id(),
        "runtime reconciliation did not produce a distinct repair graph"
    );
    if repaired.plan().operations().is_empty() {
        let Some(settled_adoption_resources) = settled_adoption_resources else {
            bail!("runtime reconciliation did not produce a repair operation");
        };
        ensure!(
            settled_adoption_resources.iter().all(|resource| {
                let desired_revision = repaired
                    .desired_native_resources()
                    .entries
                    .iter()
                    .find(|mapping| &mapping.resource == resource)
                    .map(|mapping| mapping.revision);
                reconciliation.observations.iter().any(|observation| {
                    &observation.resource == resource
                        && matches!(
                            observation.state,
                            aos_ability_plan::RuntimeResourceState::Present {
                                revision,
                                health: aos_ability_plan::RuntimeResourceHealth::Healthy,
                            } if Some(revision) == desired_revision
                        )
                })
            }),
            "empty provider-adoption recovery lacks exact healthy observations"
        );
    }
    Ok(repaired)
}

fn validate_reconciliation_authority_source(
    desired: &VerifiedAbilityActivationInputs,
    source: &SpecializedAbilityActivation,
    reconciliation: &TransitionReconciliation,
    supported_features: &BTreeSet<RequiredFeature>,
) -> Result<()> {
    let authority: CurrentAbilityAuthorityDocument =
        serde_json::from_value(reconciliation.authority_document.as_json().clone())
            .context("decoding retained runtime reconciliation authority")?;
    authority
        .validate(supported_features)
        .context("validating retained runtime reconciliation authority")?;
    let binding_plan = source.plan().binding_plan().document();
    let matching_policies = desired
        .policy_set()
        .policies
        .iter()
        .filter(|policy| {
            policy.desired_state == binding_plan.desired_state
                && policy.environment == binding_plan.environment
                && policy.policy_revision == binding_plan.policy_revision
        })
        .collect::<Vec<_>>();
    let [resolution_policy] = matching_policies.as_slice() else {
        bail!("repair source does not select one authenticated resolution policy");
    };
    let expected_policy_fence = Sha256Digest::parse(&desired.policy_sidecar().document_sha256)
        .context("decoding retained runtime reconciliation policy fence")?;
    let expected_platform_policy = desired
        .policy_set()
        .platform_policy
        .as_ref()
        .map(VersionedDocument::content_digest)
        .transpose()
        .context("identifying retained runtime platform policy")?;
    let expected_transition_authority = desired
        .policy_set()
        .transition_authority
        .as_ref()
        .map(VersionedDocument::content_digest)
        .transpose()
        .context("identifying retained runtime transition authority")?;
    ensure!(
        authority.content_digest()? == reconciliation.authority_publication,
        "runtime reconciliation authority digest differs from its canonical document"
    );
    ensure!(
        authority.plan == source.plan().id()
            && authority.transaction.as_ref() == Some(&reconciliation.transaction)
            && authority.policy_fence == aos_ability_model::RevisionId(expected_policy_fence)
            && authority.policy_revision == binding_plan.policy_revision
            && authority.resolution_policy == resolution_policy.content_digest()?
            && authority.platform_policy == expected_platform_policy
            && authority.transition_authority == expected_transition_authority
            && authority.bindings == source.plan().binding_plan().bindings(),
        "runtime reconciliation authority differs from its authenticated source inputs"
    );
    Ok(())
}

fn specialize_activation_with_reconciliation(
    desired: &VerifiedAbilityActivationInputs,
    current: Option<&VerifiedAbilityActivationInputs>,
    packages: &VerifiedAbilityPackageSet,
    evaluator: &mut RestrictedAbilityEvaluator,
    reconciliation: Option<&TransitionReconciliation>,
) -> Result<SpecializedAbilityActivation> {
    let desired_packages = packages_for_inputs(desired, packages)?;
    let desired_catalog = desired_packages.planning_catalog()?;
    let desired_planning = specialize_planning(desired, &desired_catalog, evaluator)
        .context("specializing desired ability planning state")?;
    let current_planning = current
        .map(|current| {
            let current_packages = packages_for_inputs(current, packages)?;
            let current_catalog = current_packages.planning_catalog()?;
            specialize_planning(current, &current_catalog, evaluator)
                .context("specializing retained current ability planning state")
        })
        .transpose()?;
    let desired_native_resources =
        validate_execution_resource_map(desired, &desired_planning, &desired_packages, "desired")?
            .clone();
    let current_native_resources = current
        .zip(current_planning.as_ref())
        .map(|(current, planning)| {
            let current_packages = packages_for_inputs(current, packages)?;
            validate_execution_resource_map(current, planning, &current_packages, "current")
                .cloned()
        })
        .transpose()?;
    if let Some(reconciliation) = reconciliation {
        validate_runtime_reconciliation(
            desired,
            &desired_native_resources,
            current_native_resources.as_ref(),
            reconciliation,
        )?;
    }
    validate_cross_generation_physical_claims(
        &desired_native_resources,
        &desired_planning.outcome().desired_state,
        current_native_resources.as_ref().zip(
            current_planning
                .as_ref()
                .map(|planning| &planning.outcome().desired_state),
        ),
    )?;
    let transition_catalog = packages.planning_catalog()?;
    let authority = authenticate_transition_authority(
        desired,
        &transition_catalog,
        &desired_planning,
        current_planning.as_ref(),
    )?;
    let transition = TransitionPlanner::new(transition_catalog.validation_context())
        .plan(
            &desired_planning,
            TransitionInputs {
                current: current_planning.as_ref(),
                authority: authority.as_ref(),
                reconciliation,
            },
            evaluator,
        )
        .context("specializing native ability transition")?;
    validate_native_operation_coverage(
        transition.checked_effect(),
        &desired_native_resources,
        current_native_resources.as_ref(),
        (
            desired_planning.checked_binding(),
            &desired_planning.outcome().desired_state,
        ),
        current_planning.as_ref().map(|planning| {
            (
                planning.checked_binding(),
                &planning.outcome().desired_state,
            )
        }),
    )?;
    let bundle = ReloadablePlanBundle::from_verified(
        &desired_planning,
        current_planning.as_ref(),
        authority.as_ref(),
        &transition,
    )
    .context("constructing reloadable native ability plan")?;
    let desired_state = desired_planning.outcome().desired_state.clone();
    let current_desired_state = current_planning
        .as_ref()
        .map(|planning| planning.outcome().desired_state.clone());
    let current_binding_plan = current_planning
        .as_ref()
        .map(|planning| planning.checked_binding().clone());
    let plan = transition.into_checked_effect();
    // Only desired policy remains a live execution grant. Retained current
    // mappings are historical facts authenticated by generation evidence;
    // fresh desired transition authority governs every teardown operation.
    let policy_authority = vec![desired.policy_sidecar.clone()];
    Ok(SpecializedAbilityActivation {
        plan,
        bundle,
        current_binding_plan,
        desired_state,
        current_desired_state,
        desired_native_resources,
        current_native_resources,
        policy_authority,
    })
}

fn validate_runtime_reconciliation(
    desired: &VerifiedAbilityActivationInputs,
    desired_resources: &NativeResourceMap,
    current_resources: Option<&NativeResourceMap>,
    reconciliation: &TransitionReconciliation,
) -> Result<()> {
    let expected_policy_fence = aos_ability_model::RevisionId(
        Sha256Digest::parse(&desired.policy_sidecar().document_sha256)
            .context("decoding runtime reconciliation policy fence")?,
    );
    ensure!(
        reconciliation.policy_fence == expected_policy_fence,
        "runtime reconciliation uses another operator policy fence"
    );
    let mut resources = current_resources
        .into_iter()
        .flat_map(|resources| &resources.entries)
        .map(|mapping| (&mapping.resource, mapping))
        .collect::<BTreeMap<_, _>>();
    for mapping in &desired_resources.entries {
        resources.insert(&mapping.resource, mapping);
    }
    ensure!(
        reconciliation.observations.len() == resources.len(),
        "runtime reconciliation does not classify the complete desired/current native resource map"
    );
    for (observation, resource) in reconciliation.observations.iter().zip(resources.keys()) {
        ensure!(
            &observation.resource == *resource,
            "runtime reconciliation observation names a foreign native resource"
        );
    }
    Ok(())
}

fn packages_for_inputs(
    inputs: &VerifiedAbilityActivationInputs,
    packages: &VerifiedAbilityPackageSet,
) -> Result<VerifiedAbilityPackageSet> {
    let mut selected = Vec::with_capacity(inputs.packages.len());
    for coordinate in &inputs.packages {
        let package = packages
            .get(&coordinate.name, &coordinate.version, &coordinate.platform)
            .with_context(|| {
                format!(
                    "ability package {}@{} ({}) is absent from the verified generation union",
                    coordinate.name, coordinate.version, coordinate.platform
                )
            })?;
        ensure!(
            package.manifest_sha256().to_string() == coordinate.manifest_sha256
                && package.package_digest().to_string() == coordinate.package_digest,
            "ability package {}@{} ({}) seal differs from its generation coordinate",
            coordinate.name,
            coordinate.version,
            coordinate.platform
        );
        selected.push(package.clone());
    }
    VerifiedAbilityPackageSet::from_verified(selected)
}

fn validate_execution_resource_map<'a>(
    inputs: &'a VerifiedAbilityActivationInputs,
    planning: &VerifiedPlanningSnapshot,
    packages: &VerifiedAbilityPackageSet,
    generation: &str,
) -> Result<&'a NativeResourceMap> {
    let resource_map = inputs.policy_set.native_resource_map.as_ref().with_context(|| {
        format!(
            "{generation} authenticated policy-set/v1 is planning-readable but ineligible for native execution"
        )
    })?;
    resource_map.validate()?;

    validate_resource_map_against_planning(
        resource_map,
        &planning.outcome().desired_state,
        planning.checked_binding(),
        packages,
        generation,
    )?;
    Ok(resource_map)
}

fn validate_resource_map_against_planning(
    resource_map: &NativeResourceMap,
    desired_state: &DesiredStateDocument,
    checked_binding: &CheckedBindingPlan,
    packages: &VerifiedAbilityPackageSet,
    generation: &str,
) -> Result<()> {
    let desired_state_digest = desired_state
        .content_digest()
        .with_context(|| format!("identifying {generation} fixed-point desired state"))?;
    ensure!(
        resource_map.desired_state == desired_state_digest,
        "{generation} native resource map names a different fixed-point desired state"
    );

    for mapping in &resource_map.entries {
        ensure!(
            desired_state.resources.iter().any(|resource| {
                resource.resource == mapping.resource && resource.revision == mapping.revision
            }),
            "{generation} native mapping names a resource revision outside the fixed-point desired state"
        );
        let binding = checked_binding
            .binding(&mapping.binding)
            .with_context(|| format!("{generation} native mapping names an unknown binding"))?;
        ensure!(
            binding.provider_package == Some(mapping.owner_package)
                && binding.implementation == mapping.implementation,
            "{generation} native mapping disagrees with its checked provider binding"
        );
        ensure!(
            binding.provider == mapping.resource.provider
                || mapping_has_checked_owner_route(mapping, binding, checked_binding, packages)?,
            "{generation} native mapping has no checked logical-owner to terminal-handler route"
        );
        if let NativeResourceQualification::SystemdService {
            consumer_observation: Some(consumer_observation),
            ..
        } = &mapping.qualification
        {
            ensure!(
                consumer_observation.expected_instance == binding.request.consumer,
                "{generation} native consumer observation names another checked instance"
            );
            ensure!(
                desired_state.resources.iter().any(|resource| {
                    resource.resource == consumer_observation.content_resource
                        && resource.revision == consumer_observation.expected_content_revision
                }),
                "{generation} native consumer observation names unauthenticated content"
            );
        }
        let owner = packages
            .iter()
            .find(|package| package.package_digest() == mapping.owner_package)
            .with_context(|| {
                format!("{generation} native mapping owner package is not authenticated")
            })?;
        ensure!(
            owner.artifacts().contains(&mapping.implementation.artifact),
            "{generation} native mapping implementation artifact is outside its owner package"
        );

        validate_mapping_outputs(mapping, desired_state, owner, generation)?;
    }
    Ok(())
}

fn mapping_has_checked_owner_route(
    mapping: &NativeResourceMapping,
    handler_binding: &aos_ability_model::Binding,
    checked_binding: &CheckedBindingPlan,
    packages: &VerifiedAbilityPackageSet,
) -> Result<bool> {
    let Some(handler_request) = checked_binding
        .document()
        .requests
        .iter()
        .find(|request| request.id == handler_binding.request)
    else {
        return Ok(false);
    };
    if handler_request.id.consumer != mapping.resource.provider
        || handler_request.lifetime != handler_binding.lifetime
    {
        return Ok(false);
    }
    let Some(package) = handler_binding.provider_package.and_then(|digest| {
        packages
            .iter()
            .find(|package| package.package_digest() == digest)
    }) else {
        return Ok(false);
    };
    let exact_terminal = package
        .package()
        .implementation
        .providers
        .iter()
        .filter(|implementation| {
            implementation.descriptor_digest().ok()
                == Some(handler_binding.implementation.descriptor)
                && implementation.interface == handler_binding.interface
                && implementation.artifact == handler_binding.implementation.artifact
                && matches!(
                    implementation.implementation,
                    ImplementationKind::TerminalHandler { .. }
                )
        })
        .count()
        == 1;
    let exact_caller_grant = handler_binding
        .caller_grant
        .resources
        .iter()
        .any(|permission| {
            permission.resource == mapping.resource
                && permission.access.is_write()
                && !permission.operations.is_empty()
                && permission
                    .operations
                    .iter()
                    .all(|method| handler_binding.caller_grant.methods.contains(method))
        });

    Ok(exact_terminal && exact_caller_grant)
}

fn validate_mapping_outputs(
    mapping: &NativeResourceMapping,
    desired_state: &DesiredStateDocument,
    owner: &crate::ability_package::VerifiedAbilityPackage,
    generation: &str,
) -> Result<()> {
    match &mapping.qualification {
        NativeResourceQualification::ManagedConfiguration {
            candidate,
            resource_reference,
            ..
        } => {
            ensure_candidate_string(candidate, desired_state, generation)?;
            ensure_resource_reference(
                resource_reference,
                desired_state,
                &mapping.resource,
                generation,
            )?;
        }
        NativeResourceQualification::SystemdService {
            resource_reference, ..
        } => ensure_resource_reference(
            resource_reference,
            desired_state,
            &mapping.resource,
            generation,
        )?,
        NativeResourceQualification::NginxValidation {
            executable,
            candidate,
            ..
        } => {
            ensure!(
                owner.artifacts().contains(executable),
                "{generation} nginx executable is outside the mapped owner package"
            );
            ensure_candidate_string(candidate, desired_state, generation)?;
        }
        NativeResourceQualification::KubernetesObject {
            kubectl,
            api_version,
            object_kind,
            namespace,
            name,
            object_json,
            resource_reference,
            ..
        } => {
            ensure!(
                owner.artifacts().contains(kubectl),
                "{generation} kubectl executable is outside the mapped owner package"
            );
            ensure_kubernetes_object(
                object_json,
                desired_state,
                &mapping.resource,
                mapping.revision,
                api_version,
                object_kind,
                namespace.as_deref(),
                name,
                generation,
            )?;
            ensure_resource_reference(
                resource_reference,
                desired_state,
                &mapping.resource,
                generation,
            )?;
        }
        NativeResourceQualification::Postgresql {
            control,
            postgresql,
            ..
        } => {
            ensure!(
                owner.artifacts().contains(control),
                "{generation} PostgreSQL control artifact is outside the mapped owner package"
            );
            ensure!(
                owner.artifacts().contains(postgresql),
                "{generation} PostgreSQL distribution artifact is outside the mapped owner package"
            );
        }
        NativeResourceQualification::AbImageRollout { .. }
        | NativeResourceQualification::CredentialDelivery { .. }
        | NativeResourceQualification::NetworkEndpoint { .. }
        | NativeResourceQualification::HostStorage { .. }
        | NativeResourceQualification::HostNetworkPolicy { .. } => {}
    }
    Ok(())
}

fn ensure_candidate_string(
    locator: &NativeOutputLocator,
    desired_state: &DesiredStateDocument,
    generation: &str,
) -> Result<()> {
    let output = locate_aggregate_output(locator, desired_state, generation)?;
    let value = locate_literal_json(&output.value, &locator.field_path).with_context(|| {
        format!("{generation} native candidate locator does not select a literal value")
    })?;
    ensure!(
        value.as_str().is_some(),
        "{generation} native candidate locator does not select a string"
    );
    Ok(())
}

fn ensure_kubernetes_object(
    locator: &NativeOutputLocator,
    desired_state: &DesiredStateDocument,
    resource: &aos_ability_model::ResourceId,
    revision: aos_ability_model::RevisionId,
    api_version: &str,
    kind: &str,
    namespace: Option<&str>,
    name: &str,
    generation: &str,
) -> Result<()> {
    let output = locate_aggregate_output(locator, desired_state, generation)?;
    let candidate = locate_literal_json(&output.value, &locator.field_path)
        .and_then(serde_json::Value::as_str)
        .with_context(|| {
            format!("{generation} Kubernetes object locator does not select a string")
        })?;
    let object =
        aos_contract::canonical::require_canonical(candidate.as_bytes(), "Kubernetes object")?;
    ensure!(
        object.get("apiVersion").and_then(serde_json::Value::as_str) == Some(api_version)
            && object.get("kind").and_then(serde_json::Value::as_str) == Some(kind),
        "{generation} Kubernetes object type differs from its native qualification"
    );
    let metadata = object
        .get("metadata")
        .and_then(serde_json::Value::as_object)
        .with_context(|| format!("{generation} Kubernetes object has no metadata object"))?;
    ensure!(
        metadata.get("name").and_then(serde_json::Value::as_str) == Some(name)
            && metadata
                .get("namespace")
                .and_then(serde_json::Value::as_str)
                == namespace,
        "{generation} Kubernetes object identity differs from its native qualification"
    );
    ensure!(
        metadata.get("generateName").is_none(),
        "{generation} Kubernetes object may not use generated identity"
    );
    let annotations = metadata
        .get("annotations")
        .and_then(serde_json::Value::as_object)
        .with_context(|| format!("{generation} Kubernetes object has no metadata annotations"))?;
    let expected_owner = kubernetes_resource_owner(resource)?.to_string();
    let expected_revision = revision.0.to_string();
    ensure!(
        annotations
            .get("aos.andyl.com/object-revision")
            .and_then(serde_json::Value::as_str)
            == Some(expected_revision.as_str())
            && annotations
                .get("aos.andyl.com/resource-owner")
                .and_then(serde_json::Value::as_str)
                == Some(expected_owner.as_str()),
        "{generation} Kubernetes object annotations differ from its resource revision or owner"
    );
    ensure!(
        object.get("status").is_none(),
        "{generation} Kubernetes desired object contains the server-managed status field"
    );
    const SERVER_METADATA_FIELDS: [&str; 8] = [
        "creationTimestamp",
        "deletionGracePeriodSeconds",
        "deletionTimestamp",
        "generation",
        "managedFields",
        "resourceVersion",
        "selfLink",
        "uid",
    ];
    ensure!(
        SERVER_METADATA_FIELDS
            .iter()
            .all(|field| !metadata.contains_key(*field)),
        "{generation} Kubernetes desired object contains server-managed metadata"
    );
    Ok(())
}

fn ensure_resource_reference(
    locator: &NativeOutputLocator,
    desired_state: &DesiredStateDocument,
    resource: &aos_ability_model::ResourceId,
    generation: &str,
) -> Result<()> {
    let output = locate_aggregate_output(locator, desired_state, generation)?;
    let reference =
        locate_resource_reference(&output.value, &locator.field_path).with_context(|| {
            format!("{generation} native resource locator does not select a resource reference")
        })?;
    ensure!(
        reference.resource == *resource,
        "{generation} native resource locator names a different logical resource"
    );
    Ok(())
}

fn locate_aggregate_output<'a>(
    locator: &NativeOutputLocator,
    desired_state: &'a DesiredStateDocument,
    generation: &str,
) -> Result<&'a AggregateOutput> {
    desired_state
        .outputs
        .iter()
        .find(|output| {
            output.aggregate == locator.aggregate
                && output.interface == locator.interface
                && output.port == locator.port
        })
        .with_context(|| format!("{generation} native locator names an absent aggregate output"))
}

fn locate_literal_json<'a>(
    expression: &'a ValueExpression,
    field_path: &[aos_ability_model::LocalKey],
) -> Option<&'a serde_json::Value> {
    match expression {
        ValueExpression::Literal { value } => {
            field_path.iter().try_fold(value.as_json(), |value, field| {
                value.as_object()?.get(field.as_str())
            })
        }
        ValueExpression::Object { fields } if !field_path.is_empty() => {
            let (field, remaining) = field_path.split_first()?;
            locate_literal_json(fields.get(field.as_str())?, remaining)
        }
        _ => None,
    }
}

fn locate_resource_reference<'a>(
    expression: &'a ValueExpression,
    field_path: &[aos_ability_model::LocalKey],
) -> Option<&'a ResourceReference> {
    match expression {
        ValueExpression::ResourceReference { reference } if field_path.is_empty() => {
            Some(reference)
        }
        ValueExpression::Object { fields } if !field_path.is_empty() => {
            let (field, remaining) = field_path.split_first()?;
            locate_resource_reference(fields.get(field.as_str())?, remaining)
        }
        _ => None,
    }
}

fn validate_cross_generation_physical_claims(
    desired: &NativeResourceMap,
    desired_state: &DesiredStateDocument,
    current: Option<(&NativeResourceMap, &DesiredStateDocument)>,
) -> Result<()> {
    let Some((current, current_state)) = current else {
        return Ok(());
    };

    let current_by_resource = current
        .entries
        .iter()
        .map(|entry| (&entry.resource, entry))
        .collect::<std::collections::BTreeMap<_, _>>();
    for desired_entry in &desired.entries {
        let Some(current_entry) = current_by_resource.get(&desired_entry.resource) else {
            continue;
        };
        ensure!(
            physical_claim(&desired_entry.qualification)
                == physical_claim(&current_entry.qualification),
            "retained logical native resource changes its physical class or object without a relocation transition"
        );
        if let (
            NativeResourceQualification::Postgresql {
                cluster: desired_cluster,
                database: desired_database,
                postgresql_major: desired_major,
                role: desired_role,
                ..
            },
            NativeResourceQualification::Postgresql {
                cluster: current_cluster,
                database: current_database,
                postgresql_major: current_major,
                role: current_role,
                ..
            },
        ) = (&desired_entry.qualification, &current_entry.qualification)
        {
            ensure!(
                desired_cluster == current_cluster
                    && desired_database == current_database
                    && desired_role == current_role,
                "retained PostgreSQL resource changes its stable identity"
            );
            ensure!(
                desired_major == current_major,
                "retained PostgreSQL resource changes its compatible major version"
            );
        }
        if desired_entry.revision == current_entry.revision {
            ensure!(
                desired_entry.implementation == current_entry.implementation
                    && desired_entry.qualification == current_entry.qualification,
                "unchanged native resource revision changes selected execution semantics"
            );
            ensure!(
                resolved_native_execution_inputs(desired_entry, desired_state)?
                    == resolved_native_execution_inputs(current_entry, current_state)?,
                "unchanged native resource revision changes selected execution values"
            );
        }
    }

    let mut unique_claims = BTreeSet::new();
    let mut units = BTreeMap::new();
    let mut consumer_endpoints = BTreeMap::new();
    let mut paths = Vec::new();
    for entry in desired.entries.iter().chain(&current.entries) {
        let (class, object, is_path) = physical_claim(&entry.qualification);
        if !unique_claims.insert((entry.resource.clone(), class, object.clone())) {
            continue;
        }
        if is_path {
            paths.push((object, class, &entry.resource));
        } else if let Some(owner) = units.insert(object, &entry.resource)
            && owner != &entry.resource
        {
            bail!("desired and current native mappings alias one physical unit");
        }
        if let NativeResourceQualification::SystemdService {
            consumer_observation: Some(consumer_observation),
            ..
        } = &entry.qualification
        {
            let endpoint: std::net::SocketAddr = consumer_observation
                .endpoint
                .parse()
                .context("parsing validated native consumer observation endpoint")?;
            if let Some(owner) = consumer_endpoints.insert(endpoint, &entry.resource)
                && owner != &entry.resource
            {
                bail!(
                    "desired and current native mappings alias one consumer observation endpoint"
                );
            }
        }
    }
    paths.sort_by(|left, right| {
        left.0
            .split('/')
            .cmp(right.0.split('/'))
            .then_with(|| left.1.cmp(right.1))
            .then_with(|| left.2.cmp(right.2))
    });
    for pair in paths.windows(2) {
        let [
            (left_path, left_class, left_resource),
            (right_path, right_class, right_resource),
        ] = pair
        else {
            continue;
        };
        if path_claims_overlap(left_path, right_path)
            && (left_class != right_class || left_resource != right_resource)
        {
            bail!(
                "desired and current native mappings overlap physical paths across incompatible claims"
            );
        }
    }
    Ok(())
}

fn resolved_native_execution_inputs<'a>(
    mapping: &'a NativeResourceMapping,
    desired_state: &'a DesiredStateDocument,
) -> Result<(Option<&'a str>, Option<&'a ResourceReference>)> {
    match &mapping.qualification {
        NativeResourceQualification::ManagedConfiguration {
            candidate,
            resource_reference,
            ..
        } => Ok((
            Some(mapped_candidate(candidate, desired_state)?),
            Some(mapped_reference(resource_reference, desired_state)?),
        )),
        NativeResourceQualification::SystemdService {
            resource_reference, ..
        } => Ok((
            None,
            Some(mapped_reference(resource_reference, desired_state)?),
        )),
        NativeResourceQualification::NginxValidation { candidate, .. } => {
            Ok((Some(mapped_candidate(candidate, desired_state)?), None))
        }
        NativeResourceQualification::KubernetesObject {
            object_json,
            resource_reference,
            ..
        } => Ok((
            Some(mapped_candidate(object_json, desired_state)?),
            Some(mapped_reference(resource_reference, desired_state)?),
        )),
        NativeResourceQualification::AbImageRollout { .. }
        | NativeResourceQualification::CredentialDelivery { .. }
        | NativeResourceQualification::NetworkEndpoint { .. }
        | NativeResourceQualification::HostStorage { .. }
        | NativeResourceQualification::HostNetworkPolicy { .. }
        | NativeResourceQualification::Postgresql { .. } => Ok((None, None)),
    }
}

fn mapped_candidate<'a>(
    locator: &NativeOutputLocator,
    desired_state: &'a DesiredStateDocument,
) -> Result<&'a str> {
    let output = locate_aggregate_output(locator, desired_state, "cross-generation")?;
    locate_literal_json(&output.value, &locator.field_path)
        .and_then(serde_json::Value::as_str)
        .context("mapped native candidate disappeared after validation")
}

fn mapped_reference<'a>(
    locator: &NativeOutputLocator,
    desired_state: &'a DesiredStateDocument,
) -> Result<&'a ResourceReference> {
    let output = locate_aggregate_output(locator, desired_state, "cross-generation")?;
    locate_resource_reference(&output.value, &locator.field_path)
        .context("mapped native resource reference disappeared after validation")
}

fn path_claims_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn physical_claim(qualification: &NativeResourceQualification) -> (&'static str, String, bool) {
    match qualification {
        NativeResourceQualification::AbImageRollout { .. } => {
            ("ab-image-rollout", "machine".to_string(), false)
        }
        NativeResourceQualification::ManagedConfiguration { destination, .. } => {
            ("managed-configuration", destination.clone(), true)
        }
        NativeResourceQualification::SystemdService { unit, .. } => {
            ("systemd-service", unit.clone(), false)
        }
        NativeResourceQualification::NginxValidation {
            validation_prefix, ..
        } => ("nginx-validation", validation_prefix.clone(), true),
        NativeResourceQualification::KubernetesObject {
            api_version,
            object_kind,
            namespace,
            name,
            ..
        } => (
            "kubernetes-object",
            format!(
                "{api_version}/{object_kind}/{}/{name}",
                namespace.as_deref().unwrap_or("")
            ),
            false,
        ),
        NativeResourceQualification::CredentialDelivery { view } => (
            "credential-view",
            format!("/var/lib/aos/ability-runtime/credentials/{view}"),
            true,
        ),
        NativeResourceQualification::NetworkEndpoint {
            address,
            port,
            transport,
        } => (
            "network-endpoint",
            format!("{transport}:{address}:{port}"),
            false,
        ),
        NativeResourceQualification::HostStorage {
            cluster, purpose, ..
        } => (
            "host-storage",
            format!("/var/lib/aos/ability-runtime/storage/{cluster}-{purpose}"),
            true,
        ),
        NativeResourceQualification::HostNetworkPolicy { policy } => {
            ("host-network-policy", policy.clone(), false)
        }
        NativeResourceQualification::Postgresql { cluster, .. } => (
            "postgresql-cluster",
            format!("/var/lib/aos/ability-runtime/postgresql/{cluster}"),
            true,
        ),
    }
}

fn validate_native_operation_coverage(
    plan: &CheckedEffectPlan,
    desired_map: &NativeResourceMap,
    current_map: Option<&NativeResourceMap>,
    desired_planning: (&CheckedBindingPlan, &DesiredStateDocument),
    current_planning: Option<(&CheckedBindingPlan, &DesiredStateDocument)>,
) -> Result<()> {
    for operation in plan.operations() {
        let interface = operation.interface.name.as_str();
        if !is_native_interface(interface) {
            continue;
        }

        let authority = plan
            .binding_plan()
            .binding_authority(&operation.binding)
            .context("native operation has no checked binding authority")?;
        let (resource_map, source_binding, source_plan, source_desired_state) = match authority {
            BindingAuthorityKind::Desired => (
                desired_map,
                &operation.binding,
                desired_planning.0,
                desired_planning.1,
            ),
            BindingAuthorityKind::Teardown { source_binding, .. } => (
                current_map
                    .context("native teardown operation has no retained current resource map")?,
                source_binding,
                current_planning
                    .context("native teardown operation has no retained current planning")?
                    .0,
                current_planning
                    .context("native teardown operation has no retained current planning")?
                    .1,
            ),
        };
        let mapping = resource_map
            .entries
            .iter()
            .find(|mapping| mapping.resource == operation.target.resource)
            .context("native operation target is absent from its authenticated resource map")?;
        ensure!(
            mapping.binding == *source_binding,
            "native operation resource map names a different authoritative binding"
        );
        let source = source_plan
            .binding(source_binding)
            .context("native operation source binding is absent from checked planning")?;
        let dispatched = plan
            .binding_plan()
            .binding(&operation.binding)
            .context("native operation dispatch binding is absent")?;
        ensure!(
            mapping.implementation == source.implementation
                && mapping.implementation == dispatched.implementation,
            "native operation would dispatch through a different provider artifact"
        );
        ensure!(
            qualification_supports_interface(&mapping.qualification, interface),
            "native operation interface is incompatible with its physical qualification"
        );
        if let Some(reference) = mapped_resource_reference(mapping, source_desired_state)? {
            ensure!(
                reference.operations.contains(&operation.method),
                "native operation method is absent from the mapped resource-reference grant"
            );
        }
    }
    Ok(())
}

fn is_native_interface(interface: &str) -> bool {
    matches!(
        interface,
        "aos.managed-configuration-effects"
            | "aos.systemd-service-effects"
            | aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME
            | aos_ability_model::builtin::KUBERNETES_OBJECT_INTERFACE_NAME
            | aos_ability_model::builtin::CREDENTIAL_DELIVERY_EFFECTS_INTERFACE_NAME
            | aos_ability_model::builtin::NETWORK_ENDPOINT_INTERFACE_NAME
            | aos_ability_model::builtin::HOST_STORAGE_INTERFACE_NAME
            | aos_ability_model::builtin::HOST_NETWORK_POLICY_INTERFACE_NAME
            | aos_ability_model::builtin::POSTGRESQL_EFFECTS_INTERFACE_NAME
            | aos_ability_model::builtin::AB_IMAGE_ROLLOUT_INTERFACE_NAME
            | "aos.nginx-validation"
    )
}

fn qualification_supports_interface(
    qualification: &NativeResourceQualification,
    interface: &str,
) -> bool {
    matches!(
        (qualification, interface),
        (
            NativeResourceQualification::AbImageRollout { .. },
            aos_ability_model::builtin::AB_IMAGE_ROLLOUT_INTERFACE_NAME
        ) | (
            NativeResourceQualification::ManagedConfiguration { .. },
            "aos.managed-configuration-effects"
        ) | (
            NativeResourceQualification::SystemdService { .. },
            "aos.systemd-service-effects"
                | aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME
        ) | (
            NativeResourceQualification::NginxValidation { .. },
            "aos.nginx-validation"
        ) | (
            NativeResourceQualification::KubernetesObject { .. },
            aos_ability_model::builtin::KUBERNETES_OBJECT_INTERFACE_NAME
        ) | (
            NativeResourceQualification::CredentialDelivery { .. },
            aos_ability_model::builtin::CREDENTIAL_DELIVERY_EFFECTS_INTERFACE_NAME
        ) | (
            NativeResourceQualification::NetworkEndpoint { .. },
            aos_ability_model::builtin::NETWORK_ENDPOINT_INTERFACE_NAME
        ) | (
            NativeResourceQualification::HostStorage { .. },
            aos_ability_model::builtin::HOST_STORAGE_INTERFACE_NAME
        ) | (
            NativeResourceQualification::HostNetworkPolicy { .. },
            aos_ability_model::builtin::HOST_NETWORK_POLICY_INTERFACE_NAME
        ) | (
            NativeResourceQualification::Postgresql { .. },
            aos_ability_model::builtin::POSTGRESQL_EFFECTS_INTERFACE_NAME
        )
    )
}

fn mapped_resource_reference<'a>(
    mapping: &'a NativeResourceMapping,
    desired_state: &'a DesiredStateDocument,
) -> Result<Option<&'a ResourceReference>> {
    let locator = match &mapping.qualification {
        NativeResourceQualification::ManagedConfiguration {
            resource_reference, ..
        }
        | NativeResourceQualification::SystemdService {
            resource_reference, ..
        }
        | NativeResourceQualification::KubernetesObject {
            resource_reference, ..
        } => resource_reference,
        NativeResourceQualification::AbImageRollout { .. }
        | NativeResourceQualification::NginxValidation { .. }
        | NativeResourceQualification::CredentialDelivery { .. }
        | NativeResourceQualification::NetworkEndpoint { .. }
        | NativeResourceQualification::HostStorage { .. }
        | NativeResourceQualification::HostNetworkPolicy { .. }
        | NativeResourceQualification::Postgresql { .. } => return Ok(None),
    };
    let output = locate_aggregate_output(locator, desired_state, "operation")?;
    locate_resource_reference(&output.value, &locator.field_path)
        .map(Some)
        .context("mapped native resource reference disappeared after validation")
}

fn specialize_planning(
    inputs: &VerifiedAbilityActivationInputs,
    catalog: &crate::ability_package::VerifiedAbilityPlanningCatalog,
    evaluator: &mut RestrictedAbilityEvaluator,
) -> Result<VerifiedPlanningSnapshot> {
    let outcome = catalog.composer().compose(
        &inputs.policy_set.policies,
        inputs.desired.seed.clone(),
        inputs.desired.environment.clone(),
        catalog.packages().to_vec(),
        evaluator,
    )?;
    let snapshot = PlanningSnapshot::from_outcome(&outcome)?;
    let expected_digest = snapshot.digest()?;
    snapshot
        .verify_structure(
            &catalog.composer(),
            PlanningReplayInputs {
                expected_digest,
                authenticated_policies: &inputs.policy_set.policies,
                seed: inputs.desired.seed.clone(),
                environment: inputs.desired.environment.clone(),
                packages: catalog.packages().to_vec(),
            },
        )
        .map_err(anyhow::Error::new)
}

fn authenticate_transition_authority(
    desired: &VerifiedAbilityActivationInputs,
    catalog: &crate::ability_package::VerifiedAbilityPlanningCatalog,
    desired_planning: &VerifiedPlanningSnapshot,
    current_planning: Option<&VerifiedPlanningSnapshot>,
) -> Result<Option<CheckedTransitionAuthority>> {
    let Some(document) = desired.policy_set.transition_authority.clone() else {
        return Ok(None);
    };
    let current = current_planning
        .context("transition authority is present without retained current planning state")?;
    let expected_digest = document
        .content_digest()
        .context("identifying authenticated transition authority")?;
    let authority = catalog.validation_context().validate_transition_authority(
        document.clone(),
        TransitionAuthorityInputs {
            expected_digest,
            desired_planning: desired_planning.snapshot_digest(),
            current_planning: current.snapshot_digest(),
            authorization_policy_revision: document.authorization_policy_revision,
            desired: desired_planning.checked_binding(),
            current: current.checked_binding(),
        },
    )?;
    Ok(Some(authority))
}

/// Reconstructs fresh sealed packages for desired and retained generations.
///
/// Every registry package is reverified against the currently trusted key
/// roster, its dedicated provenance statement, its exact companion manifest,
/// and the live retention catalog. Callers should pass both the candidate and
/// current generation manifests when transition planning may tear down prior
/// owners.
///
/// # Errors
///
/// Returns an error when a manifest is invalid, a coordinate is missing or
/// inconsistent, an image-local package lacks replayable registry trust, or
/// current provenance, package bytes, and live store objects do not reproduce
/// an exact verified package seal.
pub fn verify_generation_packages(
    config: &ApmConfig,
    manifests: &[&ConfigManifest],
) -> Result<VerifiedAbilityPackageSet> {
    let mut packages = Vec::new();
    for manifest in manifests {
        manifest.validate()?;
        let Some(activation) = &manifest.inputs.ability_activation else {
            continue;
        };
        for pinned in &activation.packages {
            let package = manifest
                .package_outputs
                .get(&pinned.name)
                .with_context(|| {
                    format!(
                        "generation packageOutputs omits ability package {:?}",
                        pinned.name
                    )
                })?;
            ensure!(
                package.origin == RuntimePackageOrigin::Registry,
                "image-local structured ability package {:?} has no replayable registry trust receipt",
                pinned.name
            );
            let ability = package
                .ability
                .as_ref()
                .context("ability coordinate has no authenticated package metadata")?;
            let (_, provenance) = crate::install::read_provenance_artifact(
                &config.cache_path(),
                &pinned.registry,
                &ability.provenance,
            )?;
            let trusted_keys = crate::install::read_registry_provenance_trusted_keys(
                &config.cache_path(),
                &pinned.registry,
            )?;
            let manifest_bytes =
                crate::ability_package::read_package_manifest(&pinned.ability_store_path)?;
            let coordinate = AbilityPackageCoordinate {
                name: &pinned.name,
                version: &pinned.version,
                platform: &pinned.platform,
                store_path: &pinned.runtime_store_path,
                nar_hash: &pinned.runtime_nar_hash,
            };
            let verified = crate::ability_package::verify_pinned_ability_package(
                coordinate,
                ability,
                &manifest_bytes,
                &provenance,
                &pinned.registry,
                &trusted_keys,
                &NativeAbilityRetentionVerifier::new(),
            )
            .with_context(|| {
                format!(
                    "reverifying generation ability package {}@{}",
                    pinned.name, pinned.version
                )
            })?;
            packages.push(verified);
        }
    }
    VerifiedAbilityPackageSet::from_verified(packages)
}

/// Verifies structured ability companions directly from registry resolution.
///
/// This bootstrap path is used before a version-3 manifest exists. It applies
/// the same provenance, trusted-key, package-manifest, artifact, and live
/// retention checks as generation replay and does not treat evaluated manifest
/// data as package authority.
///
/// # Errors
///
/// Returns an error when a structured package is image-local, provenance or
/// trusted registry keys are unavailable, or package bytes and live retained
/// objects do not reproduce the authenticated seal.
pub fn verify_runtime_packages(
    config: &ApmConfig,
    runtime: &RuntimeResolution,
) -> Result<VerifiedAbilityPackageSet> {
    let mut packages = Vec::new();
    for (name, package) in &runtime.packages {
        let Some(ability) = &package.ability else {
            continue;
        };
        ensure!(
            package.origin == RuntimePackageOrigin::Registry,
            "image-local structured ability package {name:?} has no replayable registry trust receipt"
        );
        let (_, provenance) = crate::install::read_provenance_artifact(
            &config.cache_path(),
            &package.registry,
            &ability.provenance,
        )?;
        let trusted_keys = crate::install::read_registry_provenance_trusted_keys(
            &config.cache_path(),
            &package.registry,
        )?;
        let manifest_bytes = crate::ability_package::read_package_manifest(&ability.store_path)?;
        let coordinate = AbilityPackageCoordinate {
            name,
            version: &package.version,
            platform: &package.platform,
            store_path: &package.store_path,
            nar_hash: &package.nar_hash,
        };
        let verified = crate::ability_package::verify_pinned_ability_package(
            coordinate,
            ability,
            &manifest_bytes,
            &provenance,
            &package.registry,
            &trusted_keys,
            &NativeAbilityRetentionVerifier::new(),
        )
        .with_context(|| {
            format!(
                "verifying resolved ability package {}@{}",
                name, package.version
            )
        })?;
        packages.push(verified);
    }
    VerifiedAbilityPackageSet::from_verified(packages)
}

fn load_sidecar(sidecar: &PinnedAbilitySidecar, label: &str) -> Result<Vec<u8>> {
    let nar_hex = aos_registry_surface::store::canonical_digest_hex(&sidecar.nar_hash)
        .with_context(|| format!("decoding ability {label} NAR identity"))?;
    let nar_hash = Sha256Digest::parse(&format!("sha256:{nar_hex}"))
        .with_context(|| format!("decoding ability {label} NAR identity"))?;
    crate::ability_package::retention::verify_store_object(
        &sidecar.store_path,
        nar_hash,
        sidecar.nar_size,
        &sidecar.references,
    )
    .with_context(|| format!("verifying ability {label} store object"))?;

    let bytes = read_regular_file_beneath(
        Path::new(&sidecar.store_path),
        Path::new(&sidecar.document),
        sidecar.document_size,
    )
    .with_context(|| format!("reading pinned ability {label} document"))?;
    let expected = Sha256Digest::parse(&sidecar.document_sha256)
        .with_context(|| format!("decoding ability {label} document identity"))?;
    ensure!(
        Sha256Digest::of_bytes(&bytes) == expected,
        "ability {label} document differs from its exact byte commitment"
    );
    Ok(bytes)
}

fn read_regular_file_beneath(root: &Path, relative: &Path, expected_size: u64) -> Result<Vec<u8>> {
    ensure!(
        !relative.as_os_str().is_empty()
            && !relative.is_absolute()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "ability document path is not a safe relative path"
    );

    let mut directory = fs::openat(
        fs::CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening sidecar root {}", root.display()))?;
    let components = relative.components().collect::<Vec<_>>();
    for component in &components[..components.len().saturating_sub(1)] {
        let Component::Normal(name) = component else {
            bail!("ability document path changed during validated traversal");
        };
        directory = fs::openat(
            &directory,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening ability document directory {name:?}"))?;
    }

    let Some(Component::Normal(file_name)) = components.last() else {
        bail!("ability document path has no final file name");
    };
    let descriptor = fs::openat(
        &directory,
        *file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .with_context(|| format!("opening ability document {file_name:?}"))?;
    let metadata = fs::fstat(&descriptor).context("statting ability document descriptor")?;
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile,
        "ability document is not a regular file"
    );
    ensure!(
        u64::try_from(metadata.st_size).ok() == Some(expected_size),
        "ability document size differs from its commitment"
    );

    let limit = expected_size
        .checked_add(1)
        .context("ability document byte limit overflowed")?;
    let mut bytes = Vec::with_capacity(usize::try_from(expected_size).unwrap_or(0));
    File::from(descriptor)
        .take(limit)
        .read_to_end(&mut bytes)
        .context("reading ability document bytes")?;
    ensure!(
        u64::try_from(bytes.len()).ok() == Some(expected_size),
        "ability document bytes differ from its committed size"
    );
    Ok(bytes)
}

fn decode_canonical_sidecar<T>(bytes: &[u8], schema: &str) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let limits = aos_contract::limits::JsonLimits {
        max_bytes: ABILITY_LIMITS_V1.max_document_bytes as usize,
        max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize + 2,
        max_items: ABILITY_LIMITS_V1.max_collection_items as usize,
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    };
    let document = limits
        .decode::<T>(bytes, schema)
        .with_context(|| format!("decoding {schema}"))?;
    let canonical = aos_contract::canonical::to_vec(&document)
        .with_context(|| format!("encoding canonical {schema}"))?;
    ensure!(
        canonical == bytes,
        "{schema} is not encoded as exact canonical JSON"
    );
    Ok(document)
}

fn validate_embedded_document<T>(document: &T, label: &str) -> Result<()>
where
    T: VersionedDocument,
{
    aos_ability_model::document::encode_canonical(document)
        .with_context(|| format!("validating {label}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::num::NonZeroU32;
    use std::os::unix::fs::symlink;

    use aos_ability_model::{
        AbilityActivationMode, AbilityValue, AccessMode, AggregateId, AggregateOutput,
        ArtifactReference, BindingId, EnvironmentId, ExecutionStage, ExportDeclaration,
        HandlerDescriptor, ImplementationKind, InstanceId, InterfaceKey, InterfaceName, LocalKey,
        OperationFamily, OperationPhase, OutputDescriptor, PackageDocument, PackageImplementation,
        PlanId, ProviderImplementation, ProviderImplementationReference, ResourceId,
        ResourceLifetime, ResourceReference, RevisionId, ScopePath, TransactionId, ValueExpression,
        ValuePhase, ValueSchema, ValueVisibility,
    };

    use super::*;

    #[test]
    fn postgresql_native_map_rejects_trust_without_credential_delivery() {
        let mut mapping = test_native_mapping("/etc/unused.conf");
        let artifact = mapping.implementation.artifact.clone();
        mapping.qualification = NativeResourceQualification::Postgresql {
            cluster: "application".to_string(),
            database: "application".to_string(),
            role: "application".to_string(),
            control: artifact.clone(),
            postgresql: artifact,
            postgresql_major: 18,
        };
        let resource_map = NativeResourceMap::new(digest("desired"), vec![mapping])
            .expect("PostgreSQL native map has intrinsic shape");

        let error = validate_postgresql_credential_maps(&resource_map)
            .expect_err("credential-free PostgreSQL must reject trust mode");
        assert!(
            error
                .to_string()
                .contains("trust authentication is unsupported")
        );
    }

    #[test]
    fn descriptor_relative_reader_rejects_symlink_escape() {
        let root = tempfile::tempdir().expect("temporary sidecar root");
        let outside = tempfile::tempdir().expect("temporary outside directory");
        fs::write(outside.path().join("desired.json"), b"{}").expect("write outside document");
        symlink(outside.path(), root.path().join("mutable")).expect("create intermediate symlink");

        let error = read_regular_file_beneath(root.path(), Path::new("mutable/desired.json"), 2)
            .expect_err("sidecar reader must reject an intermediate symlink");
        assert!(error.to_string().contains("document directory"));

        symlink(
            outside.path().join("desired.json"),
            root.path().join("desired.json"),
        )
        .expect("create final symlink");
        let error = read_regular_file_beneath(root.path(), Path::new("desired.json"), 2)
            .expect_err("sidecar reader must reject a final symlink");
        assert!(error.to_string().contains("opening ability document"));
    }

    #[test]
    fn descriptor_relative_reader_checks_exact_regular_file_size() {
        let root = tempfile::tempdir().expect("temporary sidecar root");
        fs::create_dir(root.path().join("inputs")).expect("create input directory");
        fs::write(root.path().join("inputs/desired.json"), b"{}").expect("write desired document");

        let bytes = read_regular_file_beneath(root.path(), Path::new("inputs/desired.json"), 2)
            .expect("read exact regular document");
        assert_eq!(bytes, b"{}");
        let error = read_regular_file_beneath(root.path(), Path::new("inputs/desired.json"), 3)
            .expect_err("sidecar reader must check exact size");
        assert!(error.to_string().contains("size differs"));
    }

    #[test]
    fn canonical_sidecar_decoder_rejects_equivalent_noncanonical_json() {
        #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(deny_unknown_fields)]
        struct Example {
            schema: String,
            value: u32,
        }

        let canonical = br#"{"schema":"example/v1","value":1}"#;
        let decoded: Example =
            decode_canonical_sidecar(canonical, "example/v1").expect("canonical sidecar");
        assert_eq!(decoded.value, 1);

        let error = decode_canonical_sidecar::<Example>(
            br#"{ "schema": "example/v1", "value": 1 }"#,
            "example/v1",
        )
        .expect_err("noncanonical bytes must fail");
        assert!(error.to_string().contains("exact canonical JSON"));
    }

    #[test]
    fn specialization_keeps_upgrade_generations_on_their_exact_package_universes() {
        let (fixture, _) = aos_ability_plan::test_support::verified_planning_transition_plan();
        let mut environment = fixture.checked_binding().environment().clone();
        environment.providers.clear();
        environment.resources.clear();
        environment.controllers.clear();
        environment.guarantees.clear();
        let environment_digest = environment.content_digest().unwrap();
        let mut seed = fixture.outcome().seed.clone();
        seed.environment = environment_digest;
        seed.instances.clear();
        seed.contributions.clear();
        seed.child_requests.clear();
        seed.resources.clear();
        seed.outputs.clear();
        seed.controllers.clear();
        let mut policy = fixture.outcome().policies[0].clone();
        policy.desired_state = seed.content_digest().unwrap();
        policy.environment = environment_digest;
        policy.policy_revision = environment.policy_revision;
        policy.candidates.clear();
        policy.explicit_bindings.clear();
        policy.existing_pins.clear();
        policy.operator_orders.clear();
        policy.enabled_providers.clear();
        policy.obligations.clear();

        let sealed_v1 = crate::ability_package::seal_test_package(test_package("1.0.0")).unwrap();
        let sealed_v2 = crate::ability_package::seal_test_package(test_package("2.0.0")).unwrap();
        let current = test_inputs(&seed, &environment, &policy, &sealed_v1);
        let desired = test_inputs(&seed, &environment, &policy, &sealed_v2);
        let packages =
            VerifiedAbilityPackageSet::from_verified(vec![sealed_v1, sealed_v2]).unwrap();
        let mut evaluator = RestrictedAbilityEvaluator::new(
            "/unreachable/nix-instantiate",
            "/unreachable/prlimit",
            "/unreachable/cache",
            super::super::ability::AbilityEvaluationLimits::default(),
        )
        .unwrap();

        let specialized =
            specialize_activation(&desired, Some(&current), &packages, &mut evaluator)
                .unwrap_or_else(|error| panic!("specialization failed: {error:#?}"));

        let bundle: serde_json::Value = serde_json::from_slice(
            &specialized
                .bundle()
                .canonical_bytes()
                .expect("upgrade bundle must encode"),
        )
        .expect("upgrade bundle must be JSON");
        assert_eq!(
            bundle["desired"]["packages"][0]["package"]["version"],
            "2.0.0"
        );
        assert_eq!(
            bundle["current"]["packages"][0]["package"]["version"],
            "1.0.0"
        );
        assert!(specialized.plan().operations().is_empty());

        let mut planning_only = desired.clone();
        planning_only.policy_set.schema = AuthenticatedPolicySetDocument::SCHEMA_V1.to_string();
        planning_only.policy_set.native_resource_map = None;
        let error =
            specialize_activation(&planning_only, Some(&current), &packages, &mut evaluator)
                .expect_err("policy-set/v1 must remain execution-ineligible");
        assert!(error.to_string().contains("planning-readable"));

        let planning_features = vec!["abilities-v1".to_string(), "ability-effects-v1".to_string()];
        let execution_features = vec![
            "abilities-v1".to_string(),
            "ability-effects-v1".to_string(),
            "native-resource-map-v2".to_string(),
        ];
        let platform_execution_features = vec![
            "abilities-v1".to_string(),
            "ability-effects-v1".to_string(),
            "native-platform-policy-v1".to_string(),
            "native-resource-map-v2".to_string(),
        ];
        validate_policy_feature_binding(&planning_features, &planning_only.policy_set)
            .expect("planning-only v1 remains readable with the historical feature set");
        assert!(
            validate_policy_feature_binding(&planning_features, &desired.policy_set).is_err(),
            "v3 execution policy must require the platform-policy feature gate"
        );
        assert!(
            validate_policy_feature_binding(&execution_features, &planning_only.policy_set)
                .is_err(),
            "planning-only policy must not advertise execution compatibility"
        );
        validate_policy_feature_binding(&platform_execution_features, &desired.policy_set)
            .expect("v3 execution policy matches the explicit platform feature gate");

        let mut v2_with_platform = desired.clone();
        v2_with_platform.policy_set.schema = AuthenticatedPolicySetDocument::SCHEMA_V2.to_string();
        v2_with_platform.policy_set.platform_policy = Some(CurrentPlatformPolicyDocument {
            schema: CurrentPlatformPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            policy_revision: policy.policy_revision,
            bindings: Vec::new(),
        });
        assert!(
            v2_with_platform
                .policy_set
                .validate(&v2_with_platform.desired)
                .is_err(),
            "policy-set/v2 must reject v3 platform authority fields"
        );

        let mut mismatched = desired.clone();
        mismatched
            .policy_set
            .native_resource_map
            .as_mut()
            .expect("v2 map is present")
            .desired_state = Sha256Digest::of_bytes(b"different desired state");
        let error = specialize_activation(&mismatched, Some(&current), &packages, &mut evaluator)
            .expect_err("map must bind the fixed-point desired state");
        assert!(error.to_string().contains("different fixed-point"));
    }

    #[test]
    fn runtime_reconciliation_requires_the_exact_policy_fence_and_complete_map() {
        let (inputs, resources) = test_reconciliation_inputs();
        let mapping = &resources.entries[0];
        let expected_policy_fence = RevisionId(
            Sha256Digest::parse(&inputs.policy_sidecar.document_sha256)
                .expect("test policy fence must parse"),
        );
        let mut reconciliation = TransitionReconciliation {
            schema: aos_ability_plan::RUNTIME_OBSERVATIONS_SCHEMA.to_string(),
            source_plan: PlanId(digest("source plan")),
            transaction: TransactionId(local("repair-attempt")),
            policy_fence: expected_policy_fence,
            authority_epoch: 2,
            sequence: 3,
            observed_at_restart_millis: 5,
            max_age_millis: 1_000,
            authority_publication: digest("current authority"),
            authority_document: AbilityValue::new(serde_json::json!({})).unwrap(),
            unsettled_provider_adoptions: Vec::new(),
            observations: vec![aos_ability_plan::RuntimeResourceObservation {
                resource: mapping.resource.clone(),
                state: aos_ability_plan::RuntimeResourceState::Present {
                    revision: mapping.revision,
                    health: aos_ability_plan::RuntimeResourceHealth::Stopped,
                },
            }],
        };

        validate_runtime_reconciliation(&inputs, &resources, None, &reconciliation)
            .expect("exact complete classification must be accepted");

        reconciliation.observations.clear();
        let error = validate_runtime_reconciliation(&inputs, &resources, None, &reconciliation)
            .expect_err("an incomplete resource classification must fail closed");
        assert!(
            error
                .to_string()
                .contains("complete desired/current native resource map"),
            "unexpected reconciliation error: {error}"
        );

        reconciliation.observations = vec![aos_ability_plan::RuntimeResourceObservation {
            resource: ResourceId {
                provider: instance("foreign"),
                key: local("configuration"),
            },
            state: aos_ability_plan::RuntimeResourceState::Absent,
        }];
        let error = validate_runtime_reconciliation(&inputs, &resources, None, &reconciliation)
            .expect_err("a foreign resource classification must fail closed");
        assert!(error.to_string().contains("foreign native resource"));

        reconciliation.observations[0].resource = mapping.resource.clone();
        reconciliation.policy_fence = RevisionId(digest("revoked policy"));
        let error = validate_runtime_reconciliation(&inputs, &resources, None, &reconciliation)
            .expect_err("another operator policy fence must fail closed");
        assert!(error.to_string().contains("another operator policy fence"));
    }

    #[test]
    fn cross_generation_map_cannot_move_an_unchanged_logical_resource() {
        let current_entry = test_native_mapping("/etc/example.conf");
        let mut desired_entry = current_entry.clone();
        let NativeResourceQualification::ManagedConfiguration { destination, .. } =
            &mut desired_entry.qualification
        else {
            panic!("test mapping is managed configuration");
        };
        *destination = "/etc/moved-example.conf".to_string();
        let current = NativeResourceMap::new(digest("current"), vec![current_entry])
            .expect("current map is valid");
        let desired = NativeResourceMap::new(digest("desired"), vec![desired_entry])
            .expect("desired map is independently valid");
        let current_state = test_native_desired_state(&current.entries[0], "candidate bytes");
        let desired_state = test_native_desired_state(&desired.entries[0], "candidate bytes");

        let error = validate_cross_generation_physical_claims(
            &desired,
            &desired_state,
            Some((&current, &current_state)),
        )
        .expect_err("map-only physical relocation must fail before transition execution");
        assert!(error.to_string().contains("relocation transition"));
    }

    #[test]
    fn unchanged_revision_cannot_change_native_execution_semantics() {
        let current_entry = test_native_mapping("/etc/example.conf");
        let mut desired_entry = current_entry.clone();
        let NativeResourceQualification::ManagedConfiguration { candidate, .. } =
            &mut desired_entry.qualification
        else {
            panic!("test mapping is managed configuration");
        };
        candidate.field_path.push(local("different"));
        let current = NativeResourceMap::new(digest("current"), vec![current_entry])
            .expect("current map is valid");
        let desired = NativeResourceMap::new(digest("desired"), vec![desired_entry])
            .expect("desired map is independently valid");
        let current_state = test_native_desired_state(&current.entries[0], "candidate bytes");
        let desired_state = test_native_desired_state(&desired.entries[0], "candidate bytes");

        let error = validate_cross_generation_physical_claims(
            &desired,
            &desired_state,
            Some((&current, &current_state)),
        )
        .expect_err("unchanged revision must retain exact execution semantics");
        assert!(error.to_string().contains("execution semantics"));
    }

    #[test]
    fn unchanged_execution_can_move_to_new_authenticated_provenance() {
        let current_entry = test_native_mapping("/etc/example.conf");
        let mut desired_entry = current_entry.clone();
        desired_entry.owner_package = digest("replacement package");
        desired_entry.binding = BindingId(local("replacement-binding"));
        let current = NativeResourceMap::new(digest("current"), vec![current_entry])
            .expect("current map is valid");
        let desired = NativeResourceMap::new(digest("desired"), vec![desired_entry])
            .expect("desired map is independently valid");
        let current_state = test_native_desired_state(&current.entries[0], "candidate bytes");
        let desired_state = test_native_desired_state(&desired.entries[0], "candidate bytes");

        validate_cross_generation_physical_claims(
            &desired,
            &desired_state,
            Some((&current, &current_state)),
        )
        .expect("fresh provenance retains the same logical provider and execution semantics");
        assert_ne!(desired, current);
        assert!(
            crate::config_eval::native_dispatch::retained_maps_match_execution(&desired, &current)
        );
    }

    #[test]
    fn provider_replacement_cannot_adopt_a_retained_physical_path() {
        let current_entry = test_native_mapping("/etc/example.conf");
        let mut desired_entry = current_entry.clone();
        desired_entry.resource.provider.key = local("replacement-provider");
        desired_entry.owner_package = digest("replacement package");
        desired_entry.binding = BindingId(local("replacement-binding"));
        let current = NativeResourceMap::new(digest("current"), vec![current_entry])
            .expect("current map is valid");
        let desired = NativeResourceMap::new(digest("desired"), vec![desired_entry])
            .expect("desired map is independently valid");
        let current_state = test_native_desired_state(&current.entries[0], "candidate bytes");
        let desired_state = test_native_desired_state(&desired.entries[0], "candidate bytes");

        let error = validate_cross_generation_physical_claims(
            &desired,
            &desired_state,
            Some((&current, &current_state)),
        )
        .expect_err("a different logical provider cannot adopt the retained physical path");
        assert!(error.to_string().contains("overlap physical paths"));
    }

    #[test]
    fn provider_replacement_can_use_a_distinct_physical_resource() {
        let current_entry = test_native_mapping("/etc/example.conf");
        let mut desired_entry = current_entry.clone();
        desired_entry.resource.provider.key = local("replacement-provider");
        desired_entry.owner_package = digest("replacement package");
        desired_entry.binding = BindingId(local("replacement-binding"));
        let NativeResourceQualification::ManagedConfiguration { destination, .. } =
            &mut desired_entry.qualification
        else {
            panic!("test mapping is managed configuration");
        };
        *destination = "/etc/replacement-example.conf".to_string();
        let current = NativeResourceMap::new(digest("current"), vec![current_entry])
            .expect("current map is valid");
        let desired = NativeResourceMap::new(digest("desired"), vec![desired_entry])
            .expect("desired map is independently valid");
        let current_state = test_native_desired_state(&current.entries[0], "candidate bytes");
        let desired_state = test_native_desired_state(&desired.entries[0], "candidate bytes");

        validate_cross_generation_physical_claims(
            &desired,
            &desired_state,
            Some((&current, &current_state)),
        )
        .expect("a different logical provider can use a distinct physical resource");
    }

    #[test]
    fn unchanged_revision_cannot_select_different_candidate_bytes() {
        let current_entry = test_native_mapping("/etc/example.conf");
        let desired_entry = current_entry.clone();
        let current = NativeResourceMap::new(digest("current"), vec![current_entry])
            .expect("current map is valid");
        let desired = NativeResourceMap::new(digest("desired"), vec![desired_entry])
            .expect("desired map is independently valid");
        let current_state = test_native_desired_state(&current.entries[0], "old candidate bytes");
        let desired_state = test_native_desired_state(&desired.entries[0], "new candidate bytes");

        let error = validate_cross_generation_physical_claims(
            &desired,
            &desired_state,
            Some((&current, &current_state)),
        )
        .expect_err("an unchanged revision must retain the selected candidate value");
        assert!(error.to_string().contains("execution values"));
    }

    #[test]
    fn checked_native_plan_requires_its_exact_populated_resource_map() {
        let mut fixture = aos_ability_validate::test_support::plan_fixture();
        let interface = &mut fixture.interfaces[0].interface;
        interface.name = InterfaceName::new("aos.managed-configuration-effects")
            .expect("native interface name is valid");
        interface.outputs.insert(
            local("configuration"),
            OutputDescriptor {
                schema: ValueSchema::Record {
                    fields: BTreeMap::from([
                        (
                            local("candidate"),
                            ValueSchema::String {
                                max_length: 4_096,
                                syntax: None,
                            },
                        ),
                        (local("resource"), ValueSchema::ResourceReference),
                    ]),
                    optional_fields: Vec::new(),
                },
                phase: ValuePhase::Planning,
                visibility: ValueVisibility::Protected,
                lifetime: ResourceLifetime::Instance,
            },
        );
        let method = interface
            .methods
            .remove(&local("observe"))
            .expect("fixture has its observe method");
        interface.methods.insert(
            local("prepare"),
            aos_ability_model::MethodDescriptor {
                operation_family: OperationFamily::PrepareManagedConfiguration,
                parameters: method.parameters,
                target_resource: interface.name.clone(),
                outputs: method.outputs,
                permitted_operations: vec![local("prepare")],
                guarantees: method.guarantees,
                outcome: method.outcome,
            },
        );
        fixture.refresh_interface();

        let binding = &mut fixture.binding_plan.bindings[0];
        let interface_key = binding.interface.clone();
        let artifact = binding.implementation.artifact.clone();
        let handler_key = local("prepare-handler");
        let provider = ProviderImplementation {
            interface: interface_key.clone(),
            artifact: artifact.clone(),
            requirements: Vec::new(),
            implementation: ImplementationKind::TerminalHandler {
                handler: handler_key.clone(),
            },
            owns_resource_kinds: vec![interface_key.name.clone()],
            state_format: None,
        };
        let provider_descriptor = provider
            .descriptor_digest()
            .expect("test provider descriptor must encode");
        binding.implementation = ProviderImplementationReference {
            descriptor: provider_descriptor,
            artifact: artifact.clone(),
            handler: Some(handler_key.clone()),
        };
        fixture.binding_inputs.environment.providers[0].implementation =
            binding.implementation.clone();

        let package = PackageDocument {
            schema: PackageDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            activation_mode: AbilityActivationMode::StructuredEffects,
            package: aos_ability_model::document::PackageSubject {
                name: local("native-managed-configuration"),
                version: "1.0.0".to_string(),
                payload: artifact.clone(),
                source: artifact.clone(),
            },
            artifacts: vec![artifact.clone()],
            exports: vec![ExportDeclaration {
                name: local("managed-configuration"),
                interface: interface_key.clone(),
                aggregation: None,
                implementation: provider_descriptor,
            }],
            requirements: Vec::new(),
            module_entry_points: BTreeMap::new(),
            implementation: PackageImplementation {
                providers: vec![provider],
                handlers: BTreeMap::from([(
                    handler_key,
                    HandlerDescriptor {
                        artifact: artifact.clone(),
                        entry_point: "libexec/managed-configuration".to_string(),
                        arguments: ValueSchema::Boolean,
                        result: ValueSchema::Boolean,
                    },
                )]),
            },
            ownership: vec![ScopePath::root()],
        };
        let owner_package = package
            .content_digest()
            .expect("test package must have a content digest");
        binding.provider_package = Some(owner_package);
        fixture.binding_inputs.packages = vec![package.clone()];

        fixture.binding_inputs.desired_state.child_requests[0].methods = vec![local("prepare")];
        fixture.binding_plan.requests[0].methods = vec![local("prepare")];
        binding.caller_grant.methods = vec![local("prepare")];
        binding.caller_grant.resources[0].access = AccessMode::ExclusiveWrite;
        binding.caller_grant.resources[0].operations = vec![local("prepare")];
        let operation = &mut fixture.effect_plan.operations[0];
        operation.key.key = local("prepare");
        operation.method = local("prepare");
        operation.family = OperationFamily::PrepareManagedConfiguration;
        operation.phase = OperationPhase::Preparing;
        operation.input_phase = ValuePhase::Planning;
        operation.target.operations = vec![local("prepare")];
        operation.accesses[0].mode = AccessMode::ExclusiveWrite;

        let resource = operation.target.resource.clone();
        let aggregate = AggregateId {
            provider: resource.provider.clone(),
            group: local("configuration"),
        };
        let controller_assignment = aos_ability_model::ControllerAssignment {
            resource: resource.clone(),
            controller: aggregate.clone(),
        };
        operation.controller = Some(aggregate.clone());
        fixture.binding_inputs.environment.controllers = vec![controller_assignment.clone()];
        fixture.binding_inputs.desired_state.controllers = vec![controller_assignment.clone()];
        fixture.effect_plan.controllers = vec![controller_assignment];
        fixture.binding_inputs.desired_state.outputs = vec![AggregateOutput {
            aggregate: aggregate.clone(),
            interface: interface_key.clone(),
            port: local("configuration"),
            value: ValueExpression::Object {
                fields: BTreeMap::from([
                    (
                        "candidate".to_string(),
                        ValueExpression::Literal {
                            value: AbilityValue::new(serde_json::json!("candidate bytes"))
                                .expect("candidate is bounded"),
                        },
                    ),
                    (
                        "resource".to_string(),
                        ValueExpression::ResourceReference {
                            reference: ResourceReference {
                                interface: interface_key.clone(),
                                resource: resource.clone(),
                                operations: vec![local("prepare")],
                                lifetime: ResourceLifetime::Instance,
                            },
                        },
                    ),
                ]),
            },
        }];
        fixture.refresh_commitments();

        let verified_package =
            crate::ability_package::seal_test_package(package).expect("test package must seal");
        let packages = VerifiedAbilityPackageSet::from_verified(vec![verified_package])
            .expect("test package set must construct");
        let checked = fixture
            .validate()
            .unwrap_or_else(|error| panic!("native test fixture must validate: {error:#?}"));
        let desired_state = checked.binding_plan().desired_state();
        let locator = NativeOutputLocator {
            aggregate,
            interface: interface_key,
            port: local("configuration"),
            field_path: vec![local("candidate")],
        };
        let mut reference_locator = locator.clone();
        reference_locator.field_path = vec![local("resource")];
        let mapping = NativeResourceMapping {
            resource: resource.clone(),
            revision: desired_state
                .resources
                .iter()
                .find(|revision| revision.resource == resource)
                .map(|revision| revision.revision)
                .expect("checked desired state keeps the fixture resource"),
            owner_package,
            binding: checked.operations()[0].binding.clone(),
            implementation: checked.binding_plan().bindings()[0].implementation.clone(),
            qualification: NativeResourceQualification::ManagedConfiguration {
                destination: "/etc/example.conf".to_string(),
                candidate: locator,
                resource_reference: reference_locator,
            },
        };
        let resource_map = NativeResourceMap::new(
            desired_state
                .content_digest()
                .expect("checked desired state must identify"),
            vec![mapping.clone()],
        )
        .expect("populated native map must be intrinsically valid");

        validate_resource_map_against_planning(
            &resource_map,
            desired_state,
            checked.binding_plan(),
            &packages,
            "test",
        )
        .expect("the exact populated map must match checked planning");
        validate_native_operation_coverage(
            &checked,
            &resource_map,
            None,
            (checked.binding_plan(), desired_state),
            None,
        )
        .expect("the exact populated map must cover its checked native operation");

        let mut wrong_binding = mapping.clone();
        wrong_binding.binding = BindingId(local("wrong-binding"));
        let wrong_binding_map =
            NativeResourceMap::new(resource_map.desired_state, vec![wrong_binding])
                .expect("wrong binding does not violate intrinsic map structure");
        assert!(
            validate_resource_map_against_planning(
                &wrong_binding_map,
                desired_state,
                checked.binding_plan(),
                &packages,
                "test",
            )
            .is_err(),
            "an unknown mapped binding must fail planning validation"
        );

        let mut wrong_locator = mapping.clone();
        let NativeResourceQualification::ManagedConfiguration {
            resource_reference, ..
        } = &mut wrong_locator.qualification
        else {
            panic!("test mapping is managed configuration");
        };
        resource_reference.field_path = vec![local("missing-resource")];
        let wrong_locator_map =
            NativeResourceMap::new(resource_map.desired_state, vec![wrong_locator])
                .expect("wrong locator does not violate intrinsic map structure");
        assert!(
            validate_resource_map_against_planning(
                &wrong_locator_map,
                desired_state,
                checked.binding_plan(),
                &packages,
                "test",
            )
            .is_err(),
            "a locator outside the checked output must fail planning validation"
        );

        let empty_map = NativeResourceMap::new(resource_map.desired_state, Vec::new())
            .expect("an empty map is intrinsically valid");
        assert!(
            validate_native_operation_coverage(
                &checked,
                &empty_map,
                None,
                (checked.binding_plan(), desired_state),
                None,
            )
            .is_err(),
            "a checked native operation must have an authenticated mapped target"
        );
    }

    fn test_package(version: &str) -> PackageDocument {
        let (_, effect) = aos_ability_plan::test_support::verified_planning_effect_plan();
        let mut package = effect.binding_plan().packages()[0].clone();
        package.package.version = version.to_string();
        package.activation_mode = AbilityActivationMode::StructuredEffects;
        package.exports.clear();
        package.requirements.clear();
        package.module_entry_points.clear();
        package.implementation = PackageImplementation {
            providers: Vec::new(),
            handlers: BTreeMap::new(),
        };
        package.ownership.clear();
        package
    }

    fn test_native_mapping(destination: &str) -> NativeResourceMapping {
        NativeResourceMapping {
            resource: ResourceId {
                provider: instance("provider"),
                key: local("configuration"),
            },
            revision: RevisionId(digest("revision")),
            owner_package: digest("owner package"),
            binding: BindingId(local("binding")),
            implementation: ProviderImplementationReference {
                descriptor: digest("implementation"),
                artifact: ArtifactReference {
                    content: digest("runtime content"),
                    store_path: "/nix/store/00000000000000000000000000000000-runtime".to_string(),
                    nar_hash: digest("runtime nar"),
                    closure: digest("runtime closure"),
                },
                handler: Some(local("handler")),
            },
            qualification: NativeResourceQualification::ManagedConfiguration {
                destination: destination.to_string(),
                candidate: test_locator("candidate"),
                resource_reference: test_locator("resource"),
            },
        }
    }

    fn test_reconciliation_inputs() -> (VerifiedAbilityActivationInputs, NativeResourceMap) {
        let (fixture, _) = aos_ability_plan::test_support::verified_planning_transition_plan();
        let mut environment = fixture.checked_binding().environment().clone();
        environment.providers.clear();
        environment.resources.clear();
        environment.controllers.clear();
        environment.guarantees.clear();
        let environment_digest = environment.content_digest().unwrap();

        let mut seed = fixture.outcome().seed.clone();
        seed.environment = environment_digest;
        seed.instances.clear();
        seed.contributions.clear();
        seed.child_requests.clear();
        seed.resources.clear();
        seed.outputs.clear();
        seed.controllers.clear();

        let mut policy = fixture.outcome().policies[0].clone();
        policy.desired_state = seed.content_digest().unwrap();
        policy.environment = environment_digest;
        policy.policy_revision = environment.policy_revision;
        policy.candidates.clear();
        policy.explicit_bindings.clear();
        policy.existing_pins.clear();
        policy.operator_orders.clear();
        policy.enabled_providers.clear();
        policy.obligations.clear();

        let package = crate::ability_package::seal_test_package(test_package("1.0.0")).unwrap();
        let inputs = test_inputs(&seed, &environment, &policy, &package);
        let mapping = test_native_mapping("/etc/example.conf");
        let resources = NativeResourceMap::new(seed.content_digest().unwrap(), vec![mapping])
            .expect("test native resource map must be valid");

        (inputs, resources)
    }

    fn test_locator(field: &str) -> NativeOutputLocator {
        NativeOutputLocator {
            aggregate: AggregateId {
                provider: instance("provider"),
                group: local("aggregate"),
            },
            interface: InterfaceKey {
                name: InterfaceName::new("aos.test").expect("interface name is valid"),
                abi: NonZeroU32::new(1).expect("interface ABI is nonzero"),
                descriptor: digest("interface"),
            },
            port: local("output"),
            field_path: vec![local(field)],
        }
    }

    fn test_native_desired_state(
        mapping: &NativeResourceMapping,
        candidate: &str,
    ) -> DesiredStateDocument {
        let (candidate_locator, resource_locator) = match &mapping.qualification {
            NativeResourceQualification::ManagedConfiguration {
                candidate,
                resource_reference,
                ..
            } => (candidate, resource_reference),
            _ => panic!("test mapping is managed configuration"),
        };
        assert_eq!(candidate_locator.aggregate, resource_locator.aggregate);
        assert_eq!(candidate_locator.interface, resource_locator.interface);
        assert_eq!(candidate_locator.port, resource_locator.port);

        DesiredStateDocument {
            schema: DesiredStateDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            environment: digest("environment"),
            instances: Vec::new(),
            contributions: Vec::new(),
            child_requests: Vec::new(),
            resources: vec![aos_ability_model::ResourceRevision {
                resource: mapping.resource.clone(),
                revision: mapping.revision,
            }],
            outputs: vec![AggregateOutput {
                aggregate: candidate_locator.aggregate.clone(),
                interface: candidate_locator.interface.clone(),
                port: candidate_locator.port.clone(),
                value: ValueExpression::Object {
                    fields: BTreeMap::from([
                        (
                            candidate_locator.field_path[0].as_str().to_string(),
                            ValueExpression::Literal {
                                value: AbilityValue::new(serde_json::json!(candidate))
                                    .expect("candidate is bounded"),
                            },
                        ),
                        (
                            resource_locator.field_path[0].as_str().to_string(),
                            ValueExpression::ResourceReference {
                                reference: ResourceReference {
                                    interface: candidate_locator.interface.clone(),
                                    resource: mapping.resource.clone(),
                                    operations: vec![local("prepare")],
                                    lifetime: ResourceLifetime::Instance,
                                },
                            },
                        ),
                    ]),
                },
            }],
            controllers: Vec::new(),
        }
    }

    fn instance(key: &str) -> InstanceId {
        InstanceId {
            environment: EnvironmentId {
                authority: local("test"),
                key: local("host"),
                stage: ExecutionStage::Host,
            },
            key: local(key),
        }
    }

    fn local(value: &str) -> LocalKey {
        LocalKey::new(value).expect("local key is valid")
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::of_bytes(value.as_bytes())
    }

    fn test_inputs(
        seed: &DesiredStateDocument,
        environment: &EnvironmentDocument,
        policy: &ResolutionPolicyDocument,
        package: &crate::ability_package::VerifiedAbilityPackage,
    ) -> VerifiedAbilityActivationInputs {
        VerifiedAbilityActivationInputs {
            desired: ActivationDesiredInputDocument {
                schema: ActivationDesiredInputDocument::SCHEMA.to_string(),
                seed: seed.clone(),
                environment: environment.clone(),
            },
            policy_set: AuthenticatedPolicySetDocument {
                schema: AuthenticatedPolicySetDocument::SCHEMA.to_string(),
                policies: vec![policy.clone()],
                transition_authority: None,
                native_resource_map: Some(
                    NativeResourceMap::new(seed.content_digest().unwrap(), Vec::new()).unwrap(),
                ),
                platform_policy: None,
            },
            policy_sidecar: PinnedAbilitySidecar {
                store_path: "/nix/store/00000000000000000000000000000000-policy".to_string(),
                nar_hash: format!("sha256:{}", "0".repeat(52)),
                nar_size: 1,
                references: Vec::new(),
                document: "policy.json".to_string(),
                document_sha256: format!("sha256:{}", "a".repeat(64)),
                document_size: 1,
            },
            packages: vec![PinnedAbilityPackageCoordinate {
                name: package.package_name().to_string(),
                version: package.package_version().to_string(),
                platform: package.platform().to_string(),
                registry: "test".to_string(),
                runtime_store_path: package.package().package.payload.store_path.clone(),
                runtime_nar_hash: package.package().package.payload.nar_hash.to_string(),
                runtime_nar_size: 1,
                ability_store_path: package
                    .retention_manifest()
                    .companion_store_path()
                    .to_string(),
                ability_nar_hash: package
                    .retention_manifest()
                    .companion_nar_hash()
                    .to_string(),
                manifest_sha256: package.manifest_sha256().to_string(),
                package_digest: package.package_digest().to_string(),
            }],
        }
    }
}
