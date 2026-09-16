//! Immutable inputs for structured ability activation.
//!
//! A configuration manifest pins two canonical JSON sidecars. The
//! desired sidecar carries the original composition seed and its target
//! environment; the policy sidecar carries the independently authenticated
//! resolution-policy sequence. This module verifies each complete Nix store
//! object before reading its document through a descriptor-relative,
//! no-symlink path and checking the exact document commitment.
//!
//! The two sidecar document shapes are:
//!
//! ```json
//! {"environment":{"schema":"aos.contract.environment/v1","...":"..."},"schema":"aos.contract.activation-desired/v1","seed":{"schema":"aos.contract.desired-state/v1","...":"..."}}
//! {"platform_policy":{"bindings":[...],"policy_revision":"sha256:...","required_features":[],"schema":"aos.contract.platform-policy/v1"},"policies":[{"schema":"aos.contract.resolution-policy/v1","...":"..."}],"schema":"aos.contract.authenticated-policy-set/v1","transition_authority":null}
//! ```

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read as _;
use std::path::{Component, Path};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, DesiredStateDocument, EnvironmentDocument, RequiredFeature,
    TransitionAuthorizationDocument, VersionedDocument,
};
use aos_ability_plan::{
    PlanningReplayInputs, PlanningSnapshot, ResolutionPolicyDocument, TransitionInputs,
    TransitionPlanner, TransitionReconciliation, VerifiedPlanningSnapshot,
};
use aos_ability_runtime::bundle::ReloadablePlanBundle;
use aos_ability_validate::{
    CheckedBindingPlan, CheckedEffectPlan, CheckedTransitionAuthority, TransitionAuthorityInputs,
};
use aos_contract::Sha256Digest;
use rustix::fs::{self, FileType, Mode, OFlags};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::ability::RestrictedAbilityEvaluator;
use super::ability_policy::{CurrentAbilityAuthorityDocument, CurrentPlatformPolicyDocument};
use super::ability_policy_authority::OperatorPolicyAuthorityStore;
use super::materialize::{AbilityActivationInput, ConfigManifest, PinnedAbilitySidecar};
use super::runtime::{ContractOrigin, RuntimePackagePin, RuntimeResolution};
use crate::config::ApmConfig;
use crate::package_contract::{
    NativePackageContractRetentionVerifier, PackageContractCoordinate, VerifiedPackageContractSet,
};

/// Canonical desired-state input supplied to native composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationDesiredInputDocument {
    /// Carries `aos.contract.activation-desired/v1`.
    pub schema: String,
    /// Supplies the original normalized desired-state composition seed.
    pub seed: DesiredStateDocument,
    /// Supplies the authenticated target environment and current inventory.
    pub environment: EnvironmentDocument,
}

impl ActivationDesiredInputDocument {
    /// Current activation desired-input schema.
    pub const SCHEMA: &'static str = "aos.contract.activation-desired/v1";

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
    /// Supplies operator-authorized bindings issued by the native platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_policy: Option<CurrentPlatformPolicyDocument>,
}

impl AuthenticatedPolicySetDocument {
    /// Current authenticated policy-set schema.
    pub const SCHEMA: &'static str = "aos.contract.authenticated-policy-set/v1";

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
    ) -> Result<Self> {
        policies.sort_by_key(|policy| policy.desired_state);
        let document = Self {
            schema: Self::SCHEMA.to_string(),
            policies,
            transition_authority,
            platform_policy: None,
        };
        document.validate(desired)?;
        Ok(document)
    }

    /// Validates policy sequencing and its relationship to a desired input.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema, ordering, environment commitments,
    /// embedded documents, or native map are invalid.
    pub fn validate(&self, desired: &ActivationDesiredInputDocument) -> Result<()> {
        ensure!(
            self.schema == Self::SCHEMA,
            "unsupported authenticated ability policy-set schema {:?}",
            self.schema
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

/// Holds live-verified immutable inputs ready for native specialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAbilityActivationInputs {
    desired: ActivationDesiredInputDocument,
    policy_set: AuthenticatedPolicySetDocument,
    policy_sidecar: PinnedAbilitySidecar,
    packages: Vec<VerifiedPackageIdentity>,
    execution_observer: Option<aos_ability_plan::SourceStageExecutionObserver>,
}

/// Identifies one package from its already verified manifest contract.
#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedPackageIdentity {
    name: String,
    version: String,
    platform: String,
    manifest_sha256: String,
    package_digest: String,
}

/// Owns one checked native effect graph and its reloadable provenance.
#[derive(Clone, Debug)]
pub struct SpecializedAbilityActivation {
    plan: CheckedEffectPlan,
    bundle: ReloadablePlanBundle,
    current_binding_plan: Option<CheckedBindingPlan>,
    desired_state: DesiredStateDocument,
    current_desired_state: Option<DesiredStateDocument>,
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
        Vec<PinnedAbilitySidecar>,
    ) {
        (
            self.plan,
            self.bundle,
            self.desired_state,
            self.current_desired_state,
            self.policy_authority,
        )
    }
}

impl VerifiedAbilityActivationInputs {
    /// Loads and authenticates the structured activation inputs from a manifest.
    ///
    /// The manifest must carry the current activation descriptor. Both
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
        let packages = verified_package_identities(manifest)?;
        Self::load_activation(activation, packages)
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

    /// Returns the execution observer selected by the final module fixed point.
    #[must_use]
    pub const fn execution_observer(
        &self,
    ) -> Option<&aos_ability_plan::SourceStageExecutionObserver> {
        self.execution_observer.as_ref()
    }

    fn load_activation(
        activation: &AbilityActivationInput,
        packages: Vec<VerifiedPackageIdentity>,
    ) -> Result<Self> {
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
            packages,
            execution_observer: activation.execution_observer.clone(),
        })
    }
}

fn verified_package_identities(manifest: &ConfigManifest) -> Result<Vec<VerifiedPackageIdentity>> {
    manifest
        .package_outputs
        .iter()
        .filter_map(|(name, package)| {
            package.contract.as_ref().map(|contract| -> Result<_> {
                let resolved = super::static_packages::resolve(
                    name,
                    &package.version,
                    &package.platform,
                    &package.store_path,
                    &package.nar_hash,
                    contract,
                    &manifest.inputs.store_view,
                )?;

                Ok(VerifiedPackageIdentity {
                    name: name.clone(),
                    version: package.version.clone(),
                    platform: package.platform.clone(),
                    manifest_sha256: resolved.manifest_digest.to_string(),
                    package_digest: resolved.document.content_digest()?.to_string(),
                })
            })
        })
        .collect()
}

fn validate_policy_feature_binding(
    required_features: &[String],
    policy_set: &AuthenticatedPolicySetDocument,
) -> Result<()> {
    let native_platform_policy = required_features
        .iter()
        .any(|feature| feature == "native-platform-policy-v1");
    ensure!(
        native_platform_policy == policy_set.platform_policy.is_some(),
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
    packages: &VerifiedPackageContractSet,
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
    packages: &VerifiedPackageContractSet,
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
#[allow(clippy::too_many_arguments)]
fn specialize_reconciliation_inner(
    desired: &VerifiedAbilityActivationInputs,
    current: &VerifiedAbilityActivationInputs,
    packages: &VerifiedPackageContractSet,
    evaluator: &mut RestrictedAbilityEvaluator,
    source: &SpecializedAbilityActivation,
    reconciliation: TransitionReconciliation,
    supported_features: &BTreeSet<RequiredFeature>,
    _settled_adoption_resources: Option<&BTreeSet<aos_ability_model::ResourceId>>,
) -> Result<SpecializedAbilityActivation> {
    ensure!(
        source.plan().operations().is_empty(),
        "runtime reconciliation source plan is not effect-free"
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
    ensure!(
        !repaired.plan().operations().is_empty(),
        "runtime reconciliation did not produce a repair operation"
    );
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
    packages: &VerifiedPackageContractSet,
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
    if let Some(reconciliation) = reconciliation {
        validate_runtime_reconciliation(
            desired,
            &desired_planning.outcome().desired_state,
            current_planning
                .as_ref()
                .map(|planning| &planning.outcome().desired_state),
            reconciliation,
        )?;
    }
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
        policy_authority,
    })
}

fn validate_runtime_reconciliation(
    desired: &VerifiedAbilityActivationInputs,
    desired_state: &DesiredStateDocument,
    current_state: Option<&DesiredStateDocument>,
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
    let mut resources = current_state
        .into_iter()
        .flat_map(|state| &state.resources)
        .map(|resource| resource.resource.clone())
        .collect::<BTreeSet<_>>();
    for resource in &desired_state.resources {
        resources.insert(resource.resource.clone());
    }
    ensure!(
        reconciliation.observations.len() == resources.len(),
        "runtime reconciliation does not classify the complete desired/current native resource map"
    );
    for (observation, resource) in reconciliation.observations.iter().zip(resources.iter()) {
        ensure!(
            &observation.resource == resource,
            "runtime reconciliation observation names a foreign resource"
        );
    }
    Ok(())
}

fn packages_for_inputs(
    inputs: &VerifiedAbilityActivationInputs,
    packages: &VerifiedPackageContractSet,
) -> Result<VerifiedPackageContractSet> {
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
    VerifiedPackageContractSet::from_verified(selected)
}

pub(crate) fn specialize_planning(
    inputs: &VerifiedAbilityActivationInputs,
    catalog: &crate::package_contract::VerifiedPackagePlanningCatalog,
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
    let verified = snapshot
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
        .map_err(anyhow::Error::new)?;
    Ok(verified)
}

fn authenticate_transition_authority(
    desired: &VerifiedAbilityActivationInputs,
    catalog: &crate::package_contract::VerifiedPackagePlanningCatalog,
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
) -> Result<VerifiedPackageContractSet> {
    let mut packages = Vec::new();
    for manifest in manifests {
        manifest.validate()?;
        for (name, package) in &manifest.package_outputs {
            let Some(contract) = package.contract.as_ref() else {
                continue;
            };
            let verified = verify_runtime_package_contract(
                config,
                name,
                package,
                contract,
                &manifest.inputs.store_view,
            )
            .with_context(|| {
                format!(
                    "reverifying generation ability package {}@{}",
                    name, package.version
                )
            })?;
            packages.push(verified);
        }
    }
    VerifiedPackageContractSet::from_verified(packages)
}

/// Verifies structured ability companions directly from registry resolution.
///
/// This bootstrap path verifies registry resolution before a generation
/// manifest is materialized. It applies the same provenance, trusted-key,
/// package-manifest, artifact, and live retention checks as generation replay
/// and does not treat evaluated manifest data as package authority.
///
/// # Errors
///
/// Returns an error when a structured package is image-local, provenance or
/// trusted registry keys are unavailable, or package bytes and live retained
/// objects do not reproduce the authenticated seal.
pub fn verify_runtime_packages(
    config: &ApmConfig,
    runtime: &RuntimeResolution,
    store_view: &super::store_view::StoreViewLocator,
) -> Result<VerifiedPackageContractSet> {
    let mut packages = Vec::new();
    for (name, package) in &runtime.packages {
        let Some(ability) = &package.contract else {
            continue;
        };
        let verified = verify_runtime_package_contract(config, name, package, ability, store_view)
            .with_context(|| {
                format!(
                    "verifying resolved ability package {}@{}",
                    name, package.version
                )
            })?;
        packages.push(verified);
    }
    VerifiedPackageContractSet::from_verified(packages)
}

fn verify_runtime_package_contract(
    config: &ApmConfig,
    name: &str,
    package: &RuntimePackagePin,
    origin: &ContractOrigin,
    store_view: &super::store_view::StoreViewLocator,
) -> Result<crate::package_contract::VerifiedPackageContract> {
    let coordinate = PackageContractCoordinate {
        name,
        version: &package.version,
        platform: &package.platform,
        store_path: &package.store_path,
        nar_hash: &package.nar_hash,
    };
    match origin {
        ContractOrigin::Registry { metadata } => {
            let (_, provenance) = crate::install::read_provenance_artifact(
                &config.cache_path(),
                &package.registry,
                &metadata.provenance,
            )?;
            let trusted_keys = crate::install::read_registry_provenance_trusted_keys(
                &config.cache_path(),
                &package.registry,
            )?;
            let manifest_bytes =
                crate::package_contract::read_package_manifest(&metadata.document.store_path)?;
            crate::package_contract::verify_pinned_package_contract(
                coordinate,
                metadata,
                &manifest_bytes,
                &provenance,
                &package.registry,
                &trusted_keys,
                &NativePackageContractRetentionVerifier::new(),
            )
        }
        ContractOrigin::EmbeddedStatic { .. } => {
            let resolved = super::static_packages::resolve(
                name,
                &package.version,
                &package.platform,
                &package.store_path,
                &package.nar_hash,
                origin,
                store_view,
            )?;
            crate::package_contract::verify_embedded_static_package(coordinate, resolved)
        }
    }
}

fn load_sidecar(sidecar: &PinnedAbilitySidecar, label: &str) -> Result<Vec<u8>> {
    let nar_hex = aos_registry_surface::store::canonical_digest_hex(&sidecar.nar_hash)
        .with_context(|| format!("decoding ability {label} NAR identity"))?;
    let nar_hash = Sha256Digest::parse(&format!("sha256:{nar_hex}"))
        .with_context(|| format!("decoding ability {label} NAR identity"))?;
    crate::package_contract::retention::verify_store_object(
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
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;

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
    fn policy_feature_binding_requires_exact_platform_policy_presence() {
        let plan = aos_ability_validate::test_support::checked_effect_plan();
        let desired = ActivationDesiredInputDocument {
            schema: ActivationDesiredInputDocument::SCHEMA.to_string(),
            seed: plan.binding_plan().desired_state().clone(),
            environment: plan.binding_plan().environment().clone(),
        };
        let policy = AuthenticatedPolicySetDocument {
            schema: AuthenticatedPolicySetDocument::SCHEMA.to_string(),
            policies: Vec::new(),
            transition_authority: None,
            platform_policy: None,
        };

        policy.validate(&desired).expect("policy shape is valid");
        validate_policy_feature_binding(&[], &policy).expect("absent feature matches policy");
        assert!(
            validate_policy_feature_binding(&["native-platform-policy-v1".to_string()], &policy)
                .is_err()
        );
    }
}
