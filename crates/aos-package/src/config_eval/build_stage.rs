//! Hermetic build-stage resolution of an authenticated ability fixed point.
//!
//! The adapter accepts only existing canonical planning documents, resolved
//! package companions, and a data-only Nix intent module. It replays the
//! approved planning snapshot, resolves selected provider modules through
//! those exact package documents, and runs the same bounded stock-Nix rounds
//! as the live evaluator. Its output contains no pending requests and can be
//! consumed by package-owned static materializers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::document::{
    DesiredInstance, FreshnessCondition, PlatformIdentity, ProviderInventory, ProviderState,
};
use aos_ability_model::{
    AuthorityGrant, DesiredStateDocument, EnvironmentDocument, EnvironmentId, ExecutionStage,
    InstanceId, InterfaceDocument, LocalKey, PackageDocument, ProviderImplementationReference,
    RevisionId, VersionedDocument,
};
use aos_ability_plan::{
    BindingCandidate, CandidateSelection, CompositionError, PlanningReplayInputs, PlanningSnapshot,
    ResolutionPolicyDocument,
};
use aos_ability_validate::PackageOutputSelector;
use aos_ability_validate::build_frontend::ResolvedPackageOutput;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::ability_activation::{ActivationDesiredInputDocument, AuthenticatedPolicySetDocument};
use super::ability_rounds::resolve_ability_rounds;
use super::stock::{StockAbilityRoundEvaluator, StockAbilityRoundResolver, StockNixEvaluator};
use super::{EvalAttempt, PackageOutputs, WorkingSetMember};
use crate::package_contract::VerifiedPackagePlanningCatalog;

const BUILD_STAGE_SPEC_SCHEMA: &str = "aos.ability.build-stage-resolution/v1";
const BUILD_STAGE_AUTHORITY_SPEC_SCHEMA: &str = "aos.ability.build-stage-authority/v1";
const STATIC_SELECTION_INTENT_SCHEMA: &str = "aos.ability.static-selection-intent/v1";
const BUILD_STAGE_PLAN_SCHEMA: &str = "aos.ability.build-stage-plan/v1";
const BUILD_STAGE_OUTPUT_SCHEMA: &str = "aos.ability.resolved-stage/v1";
const MAXIMUM_SPEC_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildStagePlanningSpec {
    schema: String,
    stage: ExecutionStage,
    authority: LocalKey,
    key: LocalKey,
    desired_input: PathBuf,
    authenticated_policy_set: PathBuf,
    packages: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildStageAuthoritySpec {
    schema: String,
    stage: ExecutionStage,
    authority: LocalKey,
    key: LocalKey,
    platform: PlatformIdentity,
    selection_intent: PathBuf,
    packages: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticSelectionIntent {
    schema: String,
    instances: Vec<StaticInstanceIntent>,
    requests: Vec<StaticRequestIntent>,
    selections: Vec<StaticSelection>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticInstanceIntent {
    name: String,
    identity: InstanceId,
    package: LocalKey,
    configuration: Option<aos_ability_model::AbilityValue>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticRequestIntent {
    name: String,
    root: bool,
    request: aos_ability_model::BindingRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticSelection {
    request_name: String,
    request: aos_ability_model::RequestId,
    package: LocalKey,
    implementation: LocalKey,
    provider_instance_name: String,
    provider: InstanceId,
    slot: LocalKey,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildStageResolutionSpec {
    schema: String,
    stage: ExecutionStage,
    authority: LocalKey,
    key: LocalKey,
    base_lib: PathBuf,
    intent_module: PathBuf,
    desired_input: PathBuf,
    authenticated_policy_set: PathBuf,
    planning_artifact: PathBuf,
    packages: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildStagePlanManifest {
    schema: String,
    environment: aos_ability_model::EnvironmentId,
    planning_snapshot: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResolvedBuildStage<'a> {
    schema: &'static str,
    environment: &'a aos_ability_model::EnvironmentId,
    planning_snapshot: Sha256Digest,
    fixed_point: &'a super::ability_rounds::AbilityFixedPointProjection,
}

/// Authors canonical static planning inputs from one explicit source selection.
///
/// The source projection names package-local implementations and logical
/// instances. Exact package, interface, implementation, and artifact identities
/// come only from the resolved package companions supplied beside it.
///
/// # Errors
///
/// Returns an error when the intent is noncanonical, differs from the target
/// stage, names an absent package implementation, omits an explicit request
/// selection, or fails common recursive composition and binding validation.
pub fn author_build_stage(spec_path: &Path, output_path: &Path) -> Result<()> {
    let spec: BuildStageAuthoritySpec =
        read_canonical(spec_path, "build-stage authority specification")?;
    validate_authority_spec(&spec)?;
    let intent: StaticSelectionIntent =
        read_canonical(&spec.selection_intent, "static ability selection intent")?;
    validate_static_intent_order(&intent)?;

    let LoadedPackages { documents, .. } = load_packages(&spec.packages)?;
    let catalog = VerifiedPackagePlanningCatalog::from_resolved_contracts(documents.clone())?;
    let packages = catalog.packages().to_vec();
    let environment_id = EnvironmentId {
        authority: spec.authority,
        key: spec.key,
        stage: spec.stage,
    };
    validate_intent_environment(&intent, &environment_id)?;

    let revision = static_policy_revision(&intent, &spec.platform, &packages)?;
    let candidates = binding_candidates(&intent, &documents, revision)?;
    let environment = EnvironmentDocument {
        schema: EnvironmentDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        environment: environment_id,
        platform: spec.platform,
        policy_revision: revision,
        providers: planned_provider_inventory(&candidates)?,
        resources: Vec::new(),
        controllers: Vec::new(),
        guarantees: Vec::new(),
        freshness: FreshnessCondition {
            generation: revision,
            max_age_millis: aos_ability_model::MAX_SAFE_INTEGER,
        },
    };
    let environment_digest = environment.content_digest()?;
    let seed = desired_seed(&intent, &packages, environment_digest)?;
    let policies = compose_static_policies(&catalog, &environment, &seed, candidates)?;

    let desired = ActivationDesiredInputDocument {
        schema: ActivationDesiredInputDocument::SCHEMA.to_string(),
        seed,
        environment,
    };
    desired.validate()?;
    let policy_set = AuthenticatedPolicySetDocument::new(&desired, policies, None)?;

    fs::create_dir_all(output_path).with_context(|| {
        format!(
            "creating build-stage authority output {}",
            output_path.display()
        )
    })?;
    fs::write(
        output_path.join("desired.json"),
        aos_contract::canonical::to_vec(&desired)?,
    )
    .context("writing canonical build-stage desired input")?;
    fs::write(
        output_path.join("policy.json"),
        aos_contract::canonical::to_vec(&policy_set)?,
    )
    .context("writing canonical build-stage authenticated policy set")
}

/// Plans one build-stage graph from authenticated package and policy inputs.
///
/// # Errors
///
/// Returns an error when the adapter input is noncanonical, a package source or
/// policy is invalid, the target environment differs, or bounded composition
/// cannot produce one checked planning snapshot.
pub fn plan_build_stage(spec_path: &Path, output_path: &Path) -> Result<()> {
    let spec: BuildStagePlanningSpec =
        read_canonical(spec_path, "build-stage planning specification")?;
    validate_planning_spec(&spec)?;

    let desired: ActivationDesiredInputDocument =
        read_canonical(&spec.desired_input, "build-stage desired input")?;
    desired.validate()?;
    let policies: AuthenticatedPolicySetDocument = read_canonical(
        &spec.authenticated_policy_set,
        "build-stage authenticated policy set",
    )?;
    policies.validate(&desired)?;
    validate_environment(&desired, spec.stage, &spec.authority, &spec.key)?;

    let LoadedPackages { documents, .. } = load_packages(&spec.packages)?;
    let catalog = VerifiedPackagePlanningCatalog::from_resolved_contracts(documents)?;
    let mut composition_evaluator = super::native_activation::production_evaluator()?;
    let outcome = catalog.composer().compose(
        &policies.policies,
        desired.seed.clone(),
        desired.environment.clone(),
        catalog.packages().to_vec(),
        &mut composition_evaluator,
    )?;
    let snapshot = PlanningSnapshot::from_outcome(&outcome)?;
    let expected_digest = snapshot.digest()?;
    snapshot.verify_structure(
        &catalog.composer(),
        PlanningReplayInputs {
            expected_digest,
            authenticated_policies: &policies.policies,
            seed: desired.seed.clone(),
            environment: desired.environment.clone(),
            packages: catalog.packages().to_vec(),
        },
    )?;

    let snapshot_bytes = snapshot.canonical_bytes()?;
    let manifest = BuildStagePlanManifest {
        schema: BUILD_STAGE_PLAN_SCHEMA.to_string(),
        environment: desired.environment.environment.clone(),
        planning_snapshot: expected_digest,
    };
    let manifest_bytes =
        aos_contract::canonical::to_vec(&manifest).context("encoding build-stage plan manifest")?;
    fs::create_dir_all(output_path)
        .with_context(|| format!("creating build-stage plan output {}", output_path.display()))?;
    fs::write(output_path.join("snapshot.json"), snapshot_bytes)
        .context("writing retained build-stage planning snapshot")?;
    fs::write(output_path.join("manifest.json"), manifest_bytes)
        .context("writing retained build-stage plan manifest")
}

/// Resolves one checked stage graph and writes its canonical build projection.
///
/// # Errors
///
/// Returns an error when the adapter specification or any existing planning
/// document is noncanonical, a package companion is malformed, planning replay
/// differs, provider selection is inexact, Nix evaluation fails, or the final
/// fixed point differs from the checked binding plan.
pub fn resolve_build_stage(spec_path: &Path, output_path: &Path, eval_root: &Path) -> Result<()> {
    let spec: BuildStageResolutionSpec = read_canonical(spec_path, "build-stage specification")?;
    validate_spec(&spec)?;

    let desired: ActivationDesiredInputDocument =
        read_canonical(&spec.desired_input, "build-stage desired input")?;
    desired.validate()?;
    let policies: AuthenticatedPolicySetDocument = read_canonical(
        &spec.authenticated_policy_set,
        "build-stage authenticated policy set",
    )?;
    policies.validate(&desired)?;
    let plan_manifest: BuildStagePlanManifest = read_canonical(
        &spec.planning_artifact.join("manifest.json"),
        "build-stage plan manifest",
    )?;
    ensure!(
        plan_manifest.schema == BUILD_STAGE_PLAN_SCHEMA,
        "unsupported build-stage plan manifest schema"
    );
    let planning_bytes = read_bounded(
        &spec.planning_artifact.join("snapshot.json"),
        "build-stage planning snapshot",
    )?;
    let planning = PlanningSnapshot::decode(&planning_bytes)
        .context("decoding build-stage planning snapshot")?;
    let planning_snapshot_digest = plan_manifest.planning_snapshot;
    ensure!(
        planning.digest()? == planning_snapshot_digest,
        "build-stage planning snapshot differs from its retained commitment"
    );

    let LoadedPackages {
        working_set,
        documents,
        artifact_locators,
    } = load_packages(&spec.packages)?;
    let catalog = VerifiedPackagePlanningCatalog::from_resolved_contracts(documents)?;
    let mut composition_evaluator = super::native_activation::production_evaluator()?;
    let verified = planning.replay_with(
        &catalog.composer(),
        PlanningReplayInputs {
            expected_digest: planning_snapshot_digest,
            authenticated_policies: &policies.policies,
            seed: desired.seed.clone(),
            environment: desired.environment.clone(),
            packages: catalog.packages().to_vec(),
        },
        &mut composition_evaluator,
    )?;

    validate_environment(&desired, spec.stage, &spec.authority, &spec.key)?;
    ensure!(
        plan_manifest.environment == desired.environment.environment,
        "build-stage plan manifest names a different environment"
    );

    let evaluator = StockNixEvaluator::new(eval_root, 0);
    let attempt = EvalAttempt {
        host_nix: &spec.intent_module,
        runtime_modules: &[],
        base_lib: &spec.base_lib,
        facts_json: None,
        working_set: &working_set,
        iteration: 0,
    };
    let round_evaluator = StockAbilityRoundEvaluator::for_build_stage(
        &evaluator,
        attempt,
        stage_name(spec.stage),
        spec.authority.as_str(),
        spec.key.as_str(),
    );
    let round_resolver =
        StockAbilityRoundResolver::for_build_stage(&working_set, &verified, &artifact_locators);
    let mut outcome = resolve_ability_rounds(
        &round_evaluator,
        &round_resolver,
        aos_ability_model::ABILITY_LIMITS_V1.max_resolver_rounds,
    )?;
    outcome
        .fixed_point
        .bind_checked_planning(&verified, &outcome.selections)?;

    let output = ResolvedBuildStage {
        schema: BUILD_STAGE_OUTPUT_SCHEMA,
        environment: &desired.environment.environment,
        planning_snapshot: verified.snapshot_digest(),
        fixed_point: &outcome.fixed_point,
    };
    let bytes = aos_contract::canonical::to_vec(&output)
        .context("encoding resolved build-stage projection")?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating build-stage output {}", parent.display()))?;
    }
    fs::write(output_path, bytes)
        .with_context(|| format!("writing resolved build stage {}", output_path.display()))
}

fn validate_authority_spec(spec: &BuildStageAuthoritySpec) -> Result<()> {
    ensure!(
        spec.schema == BUILD_STAGE_AUTHORITY_SPEC_SCHEMA,
        "unsupported build-stage authority schema"
    );
    validate_stage_inputs(
        spec.stage,
        std::iter::once(&spec.selection_intent),
        &spec.packages,
    )
}

fn validate_static_intent_order(intent: &StaticSelectionIntent) -> Result<()> {
    ensure!(
        intent.schema == STATIC_SELECTION_INTENT_SCHEMA,
        "unsupported static ability selection intent schema"
    );
    ensure!(
        intent
            .instances
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name),
        "static ability instances are not in unique canonical name order"
    );
    ensure!(
        intent
            .requests
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name),
        "static ability requests are not in unique canonical name order"
    );
    ensure!(
        intent.selections.windows(2).all(|pair| {
            (&pair[0].request, &pair[0].request_name) < (&pair[1].request, &pair[1].request_name)
        }),
        "static ability selections are not in unique canonical request order"
    );
    ensure!(
        intent.instances.len() as u64
            <= u64::from(aos_ability_model::ABILITY_LIMITS_V1.max_collection_items)
            && intent.requests.len() as u64
                <= u64::from(aos_ability_model::ABILITY_LIMITS_V1.max_collection_items)
            && intent.selections.len() as u64
                <= u64::from(aos_ability_model::ABILITY_LIMITS_V1.max_collection_items),
        "static ability selection intent exceeds the item bound"
    );
    Ok(())
}

fn validate_intent_environment(
    intent: &StaticSelectionIntent,
    environment: &EnvironmentId,
) -> Result<()> {
    ensure!(
        intent
            .instances
            .iter()
            .all(|instance| instance.identity.environment == *environment),
        "static ability instance names another target environment"
    );
    ensure!(
        intent
            .requests
            .iter()
            .all(|request| request.request.id.consumer.environment == *environment),
        "static ability request names another target environment"
    );
    ensure!(
        intent.selections.iter().all(|selection| {
            selection.request.consumer.environment == *environment
                && selection.provider.environment == *environment
        }),
        "static ability selection names another target environment"
    );
    Ok(())
}

fn static_policy_revision(
    intent: &StaticSelectionIntent,
    platform: &PlatformIdentity,
    packages: &[PackageDocument],
) -> Result<RevisionId> {
    #[derive(Serialize)]
    struct PolicyIdentity<'a> {
        schema: &'static str,
        intent: &'a StaticSelectionIntent,
        platform: &'a PlatformIdentity,
        packages: Vec<Sha256Digest>,
    }

    let packages = packages
        .iter()
        .map(VersionedDocument::content_digest)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let material = PolicyIdentity {
        schema: "aos.ability.static-selection-policy-identity/v1",
        intent,
        platform,
        packages,
    };
    let bytes = aos_contract::canonical::to_vec(&material)
        .context("encoding static ability policy identity")?;
    Ok(RevisionId(Sha256Digest::separated(
        "aos.ability.static-selection-policy/v1",
        bytes,
    )))
}

fn desired_seed(
    intent: &StaticSelectionIntent,
    packages: &[PackageDocument],
    environment: Sha256Digest,
) -> Result<DesiredStateDocument> {
    let packages_by_name = packages
        .iter()
        .map(|package| (package.package.name.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let mut instances = Vec::with_capacity(intent.instances.len());
    for instance in &intent.instances {
        let package = packages_by_name.get(&instance.package).with_context(|| {
            format!(
                "static instance {:?} names absent package {:?}",
                instance.name, instance.package
            )
        })?;
        instances.push(DesiredInstance {
            instance: instance.identity.clone(),
            package: package.content_digest()?,
            // Presence in the final source composition is the image's explicit
            // desired-instance enablement. Provider selection remains binding-owned.
            enabled: true,
            configuration: instance.configuration.clone(),
        });
    }
    instances.sort_by(|left, right| left.instance.cmp(&right.instance));
    ensure!(
        instances
            .windows(2)
            .all(|pair| pair[0].instance < pair[1].instance),
        "static ability instances repeat a deployment identity"
    );

    let mut requests = intent
        .requests
        .iter()
        .filter(|request| request.root)
        .map(|request| request.request.clone())
        .collect::<Vec<_>>();
    requests.sort_by(|left, right| left.id.cmp(&right.id));
    ensure!(
        requests.windows(2).all(|pair| pair[0].id < pair[1].id),
        "static root requests repeat a request identity"
    );

    Ok(DesiredStateDocument {
        schema: DesiredStateDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        environment,
        instances,
        contributions: Vec::new(),
        child_requests: requests,
        resources: Vec::new(),
        outputs: Vec::new(),
        controllers: Vec::new(),
    })
}

fn binding_candidates(
    intent: &StaticSelectionIntent,
    package_contracts: &[(PackageDocument, Vec<InterfaceDocument>)],
    policy_revision: RevisionId,
) -> Result<Vec<(aos_ability_model::BindingRequest, BindingCandidate)>> {
    let packages_by_name = package_contracts
        .iter()
        .map(|(package, interfaces)| (package.package.name.clone(), (package, interfaces)))
        .collect::<BTreeMap<_, _>>();
    let instances_by_name = intent
        .instances
        .iter()
        .map(|instance| (instance.name.as_str(), instance))
        .collect::<BTreeMap<_, _>>();
    let requests_by_name = intent
        .requests
        .iter()
        .map(|request| (request.name.as_str(), request))
        .collect::<BTreeMap<_, _>>();
    let mut candidates = Vec::with_capacity(intent.selections.len());

    for selection in &intent.selections {
        let request = requests_by_name
            .get(selection.request_name.as_str())
            .with_context(|| {
                format!(
                    "static selection names absent request {:?}",
                    selection.request_name
                )
            })?;
        ensure!(
            request.request.id == selection.request,
            "static selection request name and identity disagree"
        );
        let provider_instance = instances_by_name
            .get(selection.provider_instance_name.as_str())
            .with_context(|| {
                format!(
                    "static selection names absent provider instance {:?}",
                    selection.provider_instance_name
                )
            })?;
        ensure!(
            provider_instance.identity == selection.provider
                && provider_instance.package == selection.package,
            "static provider instance differs from its selected identity or package"
        );

        let (package, interfaces) =
            packages_by_name.get(&selection.package).with_context(|| {
                format!(
                    "static selection names absent package {:?}",
                    selection.package
                )
            })?;
        let implementation = package
            .implementation
            .providers
            .iter()
            .find(|provider| provider.name == selection.implementation)
            .with_context(|| {
                format!(
                    "static selection names absent implementation {:?}:{:?}",
                    selection.package, selection.implementation
                )
            })?;
        let descriptor = implementation.descriptor_digest()?;
        ensure!(
            package.exports.iter().any(|export| {
                export.implementation_name == implementation.name
                    && export.implementation == descriptor
                    && export.interface == implementation.interface
            }),
            "static selection implementation is not an exported package ability"
        );
        let interface = interfaces
            .iter()
            .find(|interface| {
                interface
                    .interface_key()
                    .is_ok_and(|key| key == implementation.interface)
            })
            .context("static selection implementation interface is absent")?;
        ensure!(
            request
                .request
                .accepted_interfaces
                .contains(&implementation.interface),
            "static selection implementation does not satisfy the request interface"
        );
        ensure!(
            request
                .request
                .methods
                .iter()
                .all(|method| { interface.interface.methods.contains_key(method) }),
            "static selection implementation does not supply every requested method"
        );

        let caller_grant = AuthorityGrant {
            principal: request.request.id.consumer.clone(),
            methods: request.request.methods.clone(),
            contributions: vec![aos_ability_model::ContributionPermission {
                aggregate: aos_ability_model::AggregateId {
                    provider: selection.provider.clone(),
                    group: interface.interface.aggregation.controller_group.clone(),
                },
                slot: selection.slot.clone(),
            }],
            resources: Vec::new(),
        };
        let provider_grant = AuthorityGrant {
            principal: selection.provider.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
        };

        let candidate_key = static_candidate_key(selection)?;
        candidates.push((
            request.request.clone(),
            BindingCandidate {
                key: candidate_key,
                request: selection.request.clone(),
                interface: implementation.interface.clone(),
                provider: selection.provider.clone(),
                provider_package: package.content_digest()?,
                implementation: ProviderImplementationReference {
                    descriptor,
                    artifact: implementation.artifact.clone(),
                    handler: implementation.handler.clone(),
                },
                caller_grant,
                provider_grant,
                guarantees: implementation.guarantees.clone(),
                policy_revision,
                lifetime: request.request.lifetime,
                mediation_allowed: false,
                exclusive_resources: Vec::new(),
            },
        ));
    }
    candidates.sort_by(|left, right| left.1.key.cmp(&right.1.key));
    ensure!(
        candidates
            .windows(2)
            .all(|pair| pair[0].1.key < pair[1].1.key),
        "static selection candidate identities are not unique"
    );
    Ok(candidates)
}

fn static_candidate_key(selection: &StaticSelection) -> Result<LocalKey> {
    let bytes = aos_contract::canonical::to_vec(selection)
        .context("encoding static ability candidate identity")?;
    let digest = Sha256Digest::separated("aos.ability.static-candidate/v1", bytes);
    LocalKey::new(format!("candidate-{}", digest.hex())).map_err(Into::into)
}

fn planned_provider_inventory(
    candidates: &[(aos_ability_model::BindingRequest, BindingCandidate)],
) -> Result<Vec<ProviderInventory>> {
    let mut providers = BTreeMap::new();
    for (_, candidate) in candidates {
        let inventory = ProviderInventory {
            provider: candidate.provider.clone(),
            interface: candidate.interface.clone(),
            implementation: candidate.implementation.clone(),
            state: ProviderState::Planned,
            incarnation: None,
            guarantees: candidate.guarantees.clone(),
        };
        let key = (inventory.provider.clone(), inventory.interface.clone());
        if let Some(existing) = providers.insert(key, inventory.clone()) {
            ensure!(
                existing == inventory,
                "static selections disagree about one planned provider inventory entry"
            );
        }
    }
    Ok(providers.into_values().collect())
}

fn compose_static_policies(
    catalog: &VerifiedPackagePlanningCatalog,
    environment: &EnvironmentDocument,
    seed: &DesiredStateDocument,
    candidates: Vec<(aos_ability_model::BindingRequest, BindingCandidate)>,
) -> Result<Vec<ResolutionPolicyDocument>> {
    let mut evaluator = super::native_activation::production_evaluator()?;
    compose_static_policies_with(catalog, environment, seed, candidates, &mut evaluator)
}

fn compose_static_policies_with(
    catalog: &VerifiedPackagePlanningCatalog,
    environment: &EnvironmentDocument,
    seed: &DesiredStateDocument,
    candidates: Vec<(aos_ability_model::BindingRequest, BindingCandidate)>,
    evaluator: &mut impl aos_ability_plan::CompositionEvaluator,
) -> Result<Vec<ResolutionPolicyDocument>> {
    let candidate_requests = candidates
        .iter()
        .map(|(_, candidate)| candidate.request.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        candidate_requests.len() == candidates.len(),
        "static selection contains several candidates for one request"
    );

    let mut policies = Vec::new();
    let outcome = loop {
        match catalog.composer().compose(
            &policies,
            seed.clone(),
            environment.clone(),
            catalog.packages().to_vec(),
            &mut *evaluator,
        ) {
            Ok(outcome) => break outcome,
            Err(CompositionError::PolicyRequired {
                desired_state,
                desired_state_digest,
                environment: required_environment,
            }) => {
                ensure!(
                    required_environment == environment.content_digest()?,
                    "static composition requested policy for another environment"
                );
                ensure!(
                    !policies.iter().any(|policy: &ResolutionPolicyDocument| {
                        policy.desired_state == desired_state_digest
                    }),
                    "static composition repeated a policy request"
                );
                policies.push(policy_for_desired(
                    &desired_state,
                    desired_state_digest,
                    required_environment,
                    environment.policy_revision,
                    &candidates,
                )?);
                policies.sort_by_key(|policy| policy.desired_state);
            }
            Err(error) => bail!("validating static ability composition: {error:?}"),
        }
    };

    let mut expected_requests = candidates
        .iter()
        .map(|(request, _)| request.clone())
        .collect::<Vec<_>>();
    expected_requests.sort_by(|left, right| left.id.cmp(&right.id));
    ensure!(
        outcome.desired_state.child_requests == expected_requests,
        "static selection does not exactly cover the composed request graph"
    );
    Ok(outcome.policies)
}

fn policy_for_desired(
    desired: &DesiredStateDocument,
    desired_state: Sha256Digest,
    environment: Sha256Digest,
    policy_revision: RevisionId,
    selections: &[(aos_ability_model::BindingRequest, BindingCandidate)],
) -> Result<ResolutionPolicyDocument> {
    let requests = desired
        .child_requests
        .iter()
        .map(|request| request.id.clone())
        .collect::<BTreeSet<_>>();
    let mut candidates = selections
        .iter()
        .filter(|(_, candidate)| requests.contains(&candidate.request))
        .map(|(_, candidate)| candidate.clone())
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.key.cmp(&right.key));
    ensure!(
        candidates.len() == requests.len(),
        "static composition pass lacks one explicit candidate per request"
    );
    let mut explicit_bindings = candidates
        .iter()
        .map(|candidate| CandidateSelection {
            request: candidate.request.clone(),
            candidate: candidate.key.clone(),
        })
        .collect::<Vec<_>>();
    explicit_bindings.sort_by(|left, right| left.request.cmp(&right.request));

    Ok(ResolutionPolicyDocument {
        schema: ResolutionPolicyDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_state,
        environment,
        policy_revision,
        candidates,
        explicit_bindings,
        existing_pins: Vec::new(),
        operator_orders: Vec::new(),
        enabled_providers: Vec::new(),
        obligations: Vec::new(),
    })
}

fn validate_planning_spec(spec: &BuildStagePlanningSpec) -> Result<()> {
    ensure!(
        spec.schema == BUILD_STAGE_SPEC_SCHEMA,
        "unsupported build-stage planning schema"
    );
    validate_stage_inputs(
        spec.stage,
        [&spec.desired_input, &spec.authenticated_policy_set],
        &spec.packages,
    )
}

fn validate_environment(
    desired: &ActivationDesiredInputDocument,
    stage: ExecutionStage,
    authority: &LocalKey,
    key: &LocalKey,
) -> Result<()> {
    ensure!(
        desired.environment.environment.stage == stage
            && desired.environment.environment.authority == *authority
            && desired.environment.environment.key == *key,
        "build-stage identity differs from the authenticated planning environment"
    );
    Ok(())
}

fn validate_spec(spec: &BuildStageResolutionSpec) -> Result<()> {
    ensure!(
        spec.schema == BUILD_STAGE_SPEC_SCHEMA,
        "unsupported build-stage resolution schema"
    );
    validate_stage_inputs(
        spec.stage,
        [
            &spec.base_lib,
            &spec.intent_module,
            &spec.desired_input,
            &spec.authenticated_policy_set,
            &spec.planning_artifact,
        ],
        &spec.packages,
    )
}

fn validate_stage_inputs<'a>(
    stage: ExecutionStage,
    fixed_inputs: impl IntoIterator<Item = &'a PathBuf>,
    packages: &'a [PathBuf],
) -> Result<()> {
    ensure!(
        stage != ExecutionStage::Build,
        "build-stage resolver cannot target the artifact-construction stage"
    );
    ensure!(
        !packages.is_empty()
            && packages.len() as u64
                <= u64::from(aos_ability_model::ABILITY_LIMITS_V1.max_collection_items),
        "build-stage package companion count is outside the supported bound"
    );
    ensure!(
        packages.windows(2).all(|pair| pair[0] < pair[1]),
        "build-stage package companions are not unique canonical order"
    );
    for path in fixed_inputs.into_iter().chain(packages.iter()) {
        super::stock::store_root_and_suffix(path)?;
    }
    Ok(())
}

struct LoadedPackages {
    working_set: Vec<WorkingSetMember>,
    documents: Vec<(PackageDocument, Vec<InterfaceDocument>)>,
    artifact_locators:
        BTreeMap<String, BTreeMap<PackageOutputSelector, aos_ability_model::ArtifactReference>>,
}

fn load_packages(companions: &[PathBuf]) -> Result<LoadedPackages> {
    let mut working_set = Vec::with_capacity(companions.len());
    let mut documents = Vec::with_capacity(companions.len());
    let mut artifact_locators = BTreeMap::new();

    for companion in companions {
        let package_path = companion.join("package.json");
        let interface_path = companion.join("interfaces");
        aos_ability_validate::build_frontend::validate_package_source(
            &package_path,
            &interface_path,
        )?;
        let package: PackageDocument = read_canonical(&package_path, "resolved package document")?;
        let interfaces = load_package_interfaces(&package, &interface_path)?;
        let resolved: Vec<ResolvedPackageOutput> = read_canonical(
            &companion.join("selectors.json"),
            "resolved selector manifest",
        )?;
        let (outputs, locators) = package_outputs(&package, resolved)?;
        let name = package.package.name.as_str().to_string();
        ensure!(
            artifact_locators.insert(name.clone(), locators).is_none(),
            "build-stage package catalog repeats {name:?}"
        );
        working_set.push(WorkingSetMember {
            registry: None,
            release_trust: None,
            config_realization: None,
            package: name,
            version: Some(package.package.version.clone()),
            contract: Some(super::ResolvedPackageContract {
                document: package.clone(),
                interfaces: interfaces.clone(),
            }),
            outputs,
        });
        documents.push((package, interfaces));
    }
    working_set.sort_by(|left, right| left.package.cmp(&right.package));
    ensure!(
        working_set
            .windows(2)
            .all(|pair| pair[0].package < pair[1].package),
        "build-stage package documents do not have unique names"
    );

    Ok(LoadedPackages {
        working_set,
        documents,
        artifact_locators,
    })
}

fn load_package_interfaces(
    package: &PackageDocument,
    directory: &Path,
) -> Result<Vec<InterfaceDocument>> {
    package
        .interfaces
        .values()
        .map(|expected| {
            let path = directory.join(format!("{}.json", expected.descriptor.hex()));
            let document: InterfaceDocument =
                read_canonical(&path, "resolved package interface document")?;
            ensure!(
                document.interface_key()? == *expected,
                "resolved package interface {} disagrees with its package contract",
                path.display()
            );
            Ok(document)
        })
        .collect()
}

fn package_outputs(
    package: &PackageDocument,
    resolved: Vec<ResolvedPackageOutput>,
) -> Result<(
    PackageOutputs,
    BTreeMap<PackageOutputSelector, aos_ability_model::ArtifactReference>,
)> {
    let mut outputs = PackageOutputs {
        self_output: Some(package.package.payload.store_path.clone()),
        dependencies: BTreeMap::new(),
    };
    let mut locators = BTreeMap::new();
    let mut previous = None;
    for selected in resolved {
        let key = (selected.package.clone(), selected.output.clone());
        ensure!(
            previous.as_ref().is_none_or(|prior| prior < &key),
            "resolved selector manifest is not unique canonical order"
        );
        previous = Some(key);
        let selector = PackageOutputSelector {
            package: LocalKey::new(selected.package.clone())?,
            output: LocalKey::new(selected.output.clone())?,
        };
        if selected.package == "self" && selected.output == "out" {
            ensure!(
                selected.artifact == package.package.payload,
                "resolved self output differs from package payload"
            );
            outputs.self_output = Some(selected.artifact.store_path.clone());
        } else if selected.package != "self" && selected.output == "out" {
            outputs.dependencies.insert(
                selected.package.clone(),
                selected.artifact.store_path.clone(),
            );
        }
        ensure!(
            locators.insert(selector, selected.artifact).is_none(),
            "resolved selector manifest contains a duplicate selector"
        );
    }
    Ok((outputs, locators))
}

fn read_canonical<T>(path: &Path, owner: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let bytes = read_bounded(path, owner)?;
    let value: T = serde_json::from_slice(&bytes).with_context(|| format!("decoding {owner}"))?;
    ensure!(
        aos_contract::canonical::to_vec(&value)? == bytes,
        "{owner} is not canonical JSON"
    );
    Ok(value)
}

fn read_bounded(path: &Path, owner: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading {owner} metadata {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{owner} is not a regular file: {}", path.display());
    }
    ensure!(
        metadata.len() > 0 && metadata.len() <= MAXIMUM_SPEC_BYTES,
        "{owner} size is outside the supported bound"
    );
    fs::read(path).with_context(|| format!("reading {owner} {}", path.display()))
}

const fn stage_name(stage: ExecutionStage) -> &'static str {
    match stage {
        ExecutionStage::Build => "build",
        ExecutionStage::Initrd => "initrd",
        ExecutionStage::Host => "host",
        ExecutionStage::SystemContainer => "system-container",
        ExecutionStage::User => "user",
        ExecutionStage::ApplicationContainer => "application-container",
    }
}

#[cfg(test)]
mod tests {
    use aos_ability_model::document::{FreshnessCondition, PlatformIdentity};
    use aos_ability_model::{
        AbilityValue, EnvironmentDocument, ExecutionStage, LocalKey, ModuleLocator,
        ProviderImplementationReference, VersionedDocument,
    };
    use aos_ability_plan::{CompositionEvaluator, EvaluationError};
    use aos_ability_validate::build_frontend::ResolvedPackageOutput;

    use super::{
        ActivationDesiredInputDocument, AuthenticatedPolicySetDocument,
        STATIC_SELECTION_INTENT_SCHEMA, StaticInstanceIntent, StaticRequestIntent, StaticSelection,
        StaticSelectionIntent, binding_candidates, compose_static_policies_with, desired_seed,
        package_outputs, planned_provider_inventory, static_policy_revision,
    };
    use crate::package_contract::VerifiedPackagePlanningCatalog;

    #[test]
    fn resolved_output_manifest_must_use_package_then_output_order() {
        let fixture = aos_ability_validate::test_support::stateful_owner_plan_fixture();
        let package = &fixture.binding_inputs.packages[0];
        let artifact = package.package.payload.clone();
        let unordered = vec![
            ResolvedPackageOutput {
                package: "z-provider".to_string(),
                output: "out".to_string(),
                artifact: artifact.clone(),
            },
            ResolvedPackageOutput {
                package: "a-provider".to_string(),
                output: "out".to_string(),
                artifact,
            },
        ];

        let error = package_outputs(package, unordered)
            .expect_err("an output-before-package manifest must fail closed");

        assert!(error.to_string().contains("canonical order"));
    }

    #[test]
    fn static_selection_is_enriched_from_exact_package_documents() {
        let fixture = aos_ability_validate::test_support::stateful_owner_plan_fixture();
        let package = fixture.binding_inputs.packages[0].clone();
        let implementation = package
            .implementation
            .providers
            .iter()
            .find(|provider| provider.name.as_str() == "terminal")
            .expect("fixture package must expose its terminal implementation");
        let request = fixture
            .binding_inputs
            .desired_state
            .child_requests
            .iter()
            .find(|request| {
                request
                    .accepted_interfaces
                    .contains(&implementation.interface)
            })
            .expect("fixture must request the terminal interface")
            .clone();
        let provider = fixture.binding_plan.bindings[0].provider.clone();
        let slot = LocalKey::new("root").expect("test slot");
        let intent = StaticSelectionIntent {
            schema: STATIC_SELECTION_INTENT_SCHEMA.to_string(),
            instances: vec![StaticInstanceIntent {
                name: "provider".to_string(),
                identity: provider.clone(),
                package: package.package.name.clone(),
                configuration: None,
            }],
            requests: vec![StaticRequestIntent {
                name: "root".to_string(),
                root: true,
                request: request.clone(),
            }],
            selections: vec![StaticSelection {
                request_name: "root".to_string(),
                request: request.id.clone(),
                package: package.package.name.clone(),
                implementation: implementation.name.clone(),
                provider_instance_name: "provider".to_string(),
                provider: provider.clone(),
                slot,
            }],
        };
        let platform = PlatformIdentity {
            system: LocalKey::new("linux").expect("test system"),
            architecture: LocalKey::new("x86_64").expect("test architecture"),
        };
        let packages = vec![package.clone()];
        let revision =
            static_policy_revision(&intent, &platform, &packages).expect("static policy revision");
        let contracts = vec![(package.clone(), fixture.interfaces.clone())];
        let candidates =
            binding_candidates(&intent, &contracts, revision).expect("exact binding candidate");
        let environment = EnvironmentDocument {
            schema: EnvironmentDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            environment: request.id.consumer.environment.clone(),
            platform,
            policy_revision: revision,
            providers: planned_provider_inventory(&candidates).expect("planned provider inventory"),
            resources: Vec::new(),
            controllers: Vec::new(),
            guarantees: Vec::new(),
            freshness: FreshnessCondition {
                generation: revision,
                max_age_millis: aos_ability_model::MAX_SAFE_INTEGER,
            },
        };
        assert_eq!(environment.environment.stage, ExecutionStage::Host);
        let environment_digest = environment.content_digest().expect("environment digest");
        let seed = desired_seed(&intent, &packages, environment_digest).expect("desired seed");
        let candidate = &candidates[0].1;

        assert_eq!(
            candidate.provider_package,
            package.content_digest().unwrap()
        );
        assert_eq!(candidate.interface, implementation.interface);
        assert_eq!(candidate.implementation.artifact, implementation.artifact);
        assert_eq!(candidate.lifetime, request.lifetime);
        assert!(candidate.exclusive_resources.is_empty());

        let catalog = VerifiedPackagePlanningCatalog::from_resolved_contracts(vec![(
            package,
            fixture.interfaces,
        )])
        .expect("verified package catalog");
        let policies = compose_static_policies_with(
            &catalog,
            &environment,
            &seed,
            candidates,
            &mut UnexpectedEvaluation,
        )
        .expect("complete static composition");
        let desired = ActivationDesiredInputDocument {
            schema: ActivationDesiredInputDocument::SCHEMA.to_string(),
            seed,
            environment,
        };
        desired.validate().expect("canonical desired input");
        let policy_set = AuthenticatedPolicySetDocument::new(&desired, policies, None)
            .expect("canonical authenticated policy set");

        assert_eq!(policy_set.policies.len(), 1);
        assert_eq!(policy_set.policies[0].explicit_bindings.len(), 1);
    }

    struct UnexpectedEvaluation;

    impl CompositionEvaluator for UnexpectedEvaluation {
        fn evaluate(
            &mut self,
            _implementation: &ProviderImplementationReference,
            _module: &ModuleLocator,
            _entry: &LocalKey,
            _input: &AbilityValue,
        ) -> Result<AbilityValue, EvaluationError> {
            Err(EvaluationError::new(
                "terminal fixture unexpectedly requested provider evaluation",
            ))
        }
    }
}
