//! Authenticated activation inputs for the production A/B rollout fixture.
//!
//! The generator authenticates the reference package from the configured
//! registry, runs the ordinary recursive composer, and binds the resulting
//! logical machine resource to the native A/B image adapter. It emits the same
//! retained sidecars consumed by production structured activation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::builtin::{
    AB_IMAGE_ROLLOUT_FEATURE, ab_image_rollout_interface, ab_image_rollout_request_schema,
};
use aos_ability_model::document::{
    DesiredInstance, FreshnessCondition, PlatformIdentity, ProviderInventory, ProviderState,
};
use aos_ability_model::{
    AbilityValue, AccessMode, AuthorityGrant, BindingId, DesiredStateDocument, EnvironmentDocument,
    EnvironmentId, ExecutionStage, ImplementationKind, InstanceId, InterfaceDescriptor,
    InterfaceDocument, InterfaceKey, InterfaceName, LifecycleSemantics, LocalKey, OutputDescriptor,
    PackageDocument, ProviderAdoptionAuthorization, ProviderAdoptionEndpoint,
    ProviderImplementation, ProviderImplementationReference, RequiredFeature, ResourceId,
    ResourceLifetime, ResourcePermission, RevisionId, TeardownBindingAuthorization,
    TeardownProviderAuthorization, TransitionAuthorizationDocument, ValuePhase, ValueSchema,
    ValueVisibility, VersionedDocument,
};
use aos_ability_plan::{
    AbRolloutRequest, BindingCandidate, CandidateSelection, CompositionError,
    EnabledProviderSelection, PlanningReplayInputs, PlanningSnapshot, RecursiveComposer,
    ResolutionPolicyDocument, VerifiedPlanningSnapshot,
};
use aos_ability_validate::ValidationContext;
use aos_contract::Sha256Digest;
use aos_package::ability_package::VerifiedAbilityPackageSet;
use aos_package::config::ApmConfig;
use aos_package::config_eval::ability::{AbilityEvaluationLimits, RestrictedAbilityEvaluator};
use aos_package::config_eval::ability_activation::{
    ActivationDesiredInputDocument, AuthenticatedPolicySetDocument,
};
use aos_package::config_eval::ability_policy::CurrentPlatformPolicyDocument;
use aos_package::config_eval::native_resource_map::{
    NativeResourceMap, NativeResourceMapping, NativeResourceQualification,
};
use aos_package::config_eval::runtime::resolve_runtime;
use aos_package::platform::native_platform;
use aos_package::registry::RegistrySet;
use aos_package::types::ProfileScope;

use super::ability_activation_fixture::{retain_sidecar, write_operator_authority};

const COMPATIBLE_PACKAGE: &str = "ability-reference-image-rollout";
const INCOMPATIBLE_PACKAGE: &str = "ability-reference-image-rollout-incompatible";
const HIGH_LEVEL_INTERFACE: &str = "aos.ab-image-rollout";
const FOREIGN_MAP_AUDIT_SCHEMA: &str = "aos.qualification.rollout-foreign-map-audit/v1";

struct RolloutFixture {
    context: ValidationContext,
    environment: EnvironmentDocument,
    package: PackageDocument,
    package_digest: Sha256Digest,
    provider: InstanceId,
    terminal_provider: InstanceId,
    high_interface: InterfaceKey,
    high_implementation: ProviderImplementationReference,
    effects_interface: InterfaceKey,
    effects_implementation: ProviderImplementationReference,
    policy_revision: RevisionId,
    evaluator: RestrictedAbilityEvaluator,
}

struct ComposedRollout {
    seed: DesiredStateDocument,
    environment: EnvironmentDocument,
    desired_state: DesiredStateDocument,
    policies: Vec<ResolutionPolicyDocument>,
    bindings: Vec<aos_ability_model::Binding>,
    package: PackageDocument,
    provider: InstanceId,
    planning: VerifiedPlanningSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ActivationMode {
    Rollout,
    Retire,
    Qualification(String),
}

impl ActivationMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "rollout" => Ok(Self::Rollout),
            "retire" => Ok(Self::Retire),
            value if value.starts_with("qualification-") => {
                let method = value.trim_start_matches("qualification-");
                ensure!(
                    matches!(
                        method,
                        "drain"
                            | "hold"
                            | "observe-boot"
                            | "observe-health"
                            | "prepare"
                            | "retain"
                            | "retire"
                            | "rollout"
                            | "select"
                            | "withdraw"
                    ),
                    "unknown rollout qualification method {method:?}"
                );
                Ok(Self::Qualification(method.to_string()))
            }
            _ => bail!("unknown rollout activation mode {value:?}"),
        }
    }
}

/// Generates retained structured-activation inputs for a rollout, retirement,
/// or exact-method qualification cell.
///
/// Arguments are `OUTPUT REQUEST_JSON --operator-authority-output AUTHORITY_DIR
/// --mode MODE [--provider-incarnation-revision REVISION]
/// [--alternate-provider-incarnation-revision REVISION]
/// [--provider-package compatible|incompatible]` with an optional paired
/// `--provider-adoption-source-package compatible|incompatible
/// --provider-adoption-from REVISION
/// --provider-adoption-current-planning DIGEST`. `MODE` is
/// `rollout`, `retire`, or `qualification-{method}`. The optional revision
/// gives state-transition fixtures a fresh authenticated terminal identity.
/// The request JSON carries one exact
/// [`AbRolloutRequest`]; qualification changes only graph selection and keeps
/// the production terminal handler and native resource mapping.
///
/// # Errors
///
/// Returns an error when the request, authenticated package, recursive plan,
/// native resource mapping, or retained sidecar is invalid.
pub(super) fn generate(arguments: &[String]) -> Result<()> {
    if arguments.len() < 6
        || !arguments.len().is_multiple_of(2)
        || arguments[2] != "--operator-authority-output"
        || arguments[4] != "--mode"
    {
        bail!(
            "usage: aos-release-fleet-fixture rollout-activation OUTPUT REQUEST_JSON --operator-authority-output AUTHORITY_DIR --mode rollout|retire|qualification-METHOD [--provider-incarnation-revision REVISION] [--alternate-provider-incarnation-revision REVISION] [--provider-package compatible|incompatible] [--provider-adoption-source-package compatible|incompatible --provider-adoption-from REVISION --provider-adoption-current-planning DIGEST]"
        );
    }

    let output = Path::new(&arguments[0]);
    let request_path = Path::new(&arguments[1]);
    let authority_output = Path::new(&arguments[3]);
    let mode = ActivationMode::parse(&arguments[5])?;
    let mut provider_incarnation_revision = None;
    let mut alternate_provider_incarnation_revision = None;
    let mut provider_package = None;
    let mut adoption_source_package = None;
    let mut adoption_source_revision = None;
    let mut adoption_current_planning = None;
    let mut option_index = 6;
    while option_index < arguments.len() {
        let value = arguments
            .get(option_index + 1)
            .context("rollout fixture option has no value")?;
        match arguments[option_index].as_str() {
            "--provider-incarnation-revision" => {
                ensure!(
                    provider_incarnation_revision
                        .replace(value.as_str())
                        .is_none(),
                    "provider incarnation revision is repeated"
                );
            }
            "--alternate-provider-incarnation-revision" => {
                ensure!(
                    alternate_provider_incarnation_revision
                        .replace(value.as_str())
                        .is_none(),
                    "alternate provider incarnation revision is repeated"
                );
            }
            "--provider-package" => {
                ensure!(
                    provider_package.replace(value.as_str()).is_none(),
                    "provider package is repeated"
                );
            }
            "--provider-adoption-source-package" => {
                ensure!(
                    adoption_source_package.replace(value.as_str()).is_none(),
                    "provider adoption source package is repeated"
                );
            }
            "--provider-adoption-from" => {
                ensure!(
                    adoption_source_revision.replace(value.as_str()).is_none(),
                    "provider adoption source revision is repeated"
                );
            }
            "--provider-adoption-current-planning" => {
                ensure!(
                    adoption_current_planning
                        .replace(
                            Sha256Digest::parse(value)
                                .context("parsing retained rollout planning digest")?,
                        )
                        .is_none(),
                    "provider adoption current planning is repeated"
                );
            }
            option => bail!("unknown rollout fixture option {option:?}"),
        }
        option_index += 2;
    }
    for revision in [
        provider_incarnation_revision,
        alternate_provider_incarnation_revision,
        adoption_source_revision,
    ]
    .into_iter()
    .flatten()
    {
        validate_provider_revision(revision)?;
    }
    ensure!(
        adoption_source_revision.is_some() == adoption_current_planning.is_some(),
        "rollout provider adoption source and current planning must appear together"
    );
    ensure!(
        adoption_source_package.is_none() || adoption_source_revision.is_some(),
        "rollout provider adoption source package requires an adoption source"
    );
    let selected_package = rollout_package_name(provider_package.unwrap_or("compatible"))?;
    let source_package = adoption_source_package
        .map(rollout_package_name)
        .transpose()?
        .unwrap_or(COMPATIBLE_PACKAGE);
    ensure!(
        alternate_provider_incarnation_revision.is_none() || adoption_source_revision.is_none(),
        "rollout fixture cannot combine an alternate provider and an adoption source"
    );
    ensure!(
        output != authority_output,
        "operator authority output must be separate from the activation descriptor output"
    );

    let request_bytes = fs::read(request_path)
        .with_context(|| format!("reading rollout request {}", request_path.display()))?;
    let request: AbRolloutRequest = serde_json::from_slice(&request_bytes)
        .with_context(|| format!("decoding rollout request {}", request_path.display()))?;
    let canonical_request = aos_contract::canonical::to_vec(&request)?;
    ensure!(
        request_bytes == canonical_request,
        "rollout request is not exact canonical JSON"
    );

    fs::create_dir_all(output)
        .with_context(|| format!("creating rollout fixture output {}", output.display()))?;
    let packages = load_verified_packages(selected_package, Some(source_package))?;
    let fixture = RolloutFixture::new(
        &packages,
        selected_package,
        &mode,
        provider_incarnation_revision,
        alternate_provider_incarnation_revision.or(adoption_source_revision),
    )?;
    let composed = fixture.compose(&request, &mode)?;
    let transition_authority = if let Some(source_revision) = adoption_source_revision {
        let current_mode = ActivationMode::Rollout;
        let current = RolloutFixture::new(
            &packages,
            source_package,
            &current_mode,
            Some(source_revision),
            provider_incarnation_revision,
        )?
        .compose(&request, &current_mode)?;
        Some(provider_adoption_authority(
            &composed,
            &current,
            adoption_current_planning
                .context("rollout provider adoption lacks current planning")?,
            &mode,
        )?)
    } else {
        None
    };
    let native_resource_map = rollout_resource_map(&composed, &request, &mode)?;
    let platform_policy = platform_policy(&composed)?;
    let desired_document = ActivationDesiredInputDocument {
        schema: ActivationDesiredInputDocument::SCHEMA.to_string(),
        seed: composed.seed,
        environment: composed.environment,
    };
    let mut policy_document = AuthenticatedPolicySetDocument::new(
        &desired_document,
        composed.policies,
        transition_authority,
        native_resource_map,
    )?;
    policy_document.schema = AuthenticatedPolicySetDocument::SCHEMA.to_string();
    policy_document.platform_policy = Some(platform_policy);
    policy_document.validate(&desired_document)?;

    let desired_sidecar = retain_sidecar(output, "desired", "desired.json", &desired_document)?;
    let policy_sidecar = retain_sidecar(output, "policy", "policy.json", &policy_document)?;
    write_operator_authority(authority_output, &policy_sidecar)?;
    let activation = serde_json::json!({
        "schema": "aos.ability.activation-input/v1",
        "required_features": [
            "ab-image-rollout-v1",
            "abilities-v1",
            "ability-effects-v1",
            "native-platform-policy-v1",
            "native-resource-map-v1"
        ],
        "desired_state": desired_sidecar,
        "authenticated_policy_set": policy_sidecar,
        "packages": [],
    });
    let bytes = aos_contract::canonical::to_vec(&activation)
        .context("encoding canonical rollout activation input")?;
    fs::write(output.join("activation.json"), bytes)
        .with_context(|| format!("writing {}/activation.json", output.display()))?;
    Ok(())
}

/// Audits a forged logical rollout against the production one-machine map invariant.
///
/// Arguments are `OUTPUT REQUEST_JSON METHOD`. The command authenticates the
/// production package, composes the real request, then submits a second logical
/// resource with the same physical A/B qualification to [`NativeResourceMap`].
///
/// # Errors
///
/// Returns an error when the request, method, package, composition, or expected
/// physical-collision rejection is absent or malformed.
pub(super) fn audit_foreign_map(arguments: &[String]) -> Result<()> {
    let [output, request_path, method] = arguments else {
        bail!(
            "usage: aos-release-fleet-fixture rollout-foreign-map-audit OUTPUT REQUEST_JSON METHOD"
        );
    };
    let interface = ab_image_rollout_interface()?;
    ensure!(
        interface.interface.methods.contains_key(&key(method)?),
        "rollout foreign-map audit names an unsupported method {method:?}"
    );

    let request_bytes = fs::read(request_path)
        .with_context(|| format!("reading rollout request {request_path}"))?;
    let request: AbRolloutRequest = serde_json::from_slice(&request_bytes)
        .with_context(|| format!("decoding rollout request {request_path}"))?;
    ensure!(
        request_bytes == aos_contract::canonical::to_vec(&request)?,
        "rollout request is not exact canonical JSON"
    );

    let packages = load_verified_packages(COMPATIBLE_PACKAGE, None)?;
    let mode = ActivationMode::Rollout;
    let fixture = RolloutFixture::new(&packages, COMPATIBLE_PACKAGE, &mode, None, None)?;
    let composed = fixture.compose(&request, &mode)?;
    let valid = rollout_resource_map(&composed, &request, &mode)?;
    let [real] = valid.entries.as_slice() else {
        bail!("rollout foreign-map audit requires one real mapping");
    };
    let mut forged = real.clone();
    forged.resource.key = key("foreign-machine")?;
    let attempted_entries = vec![real.clone(), forged.clone()];
    let error = NativeResourceMap::new(valid.desired_state, attempted_entries.clone())
        .expect_err("distinct logical rollouts must reject the one-machine collision");
    ensure!(
        error.to_string().contains("A/B image rollout host"),
        "rollout map rejected for another reason: {error:#}"
    );

    let interface_key = interface.interface_key()?;
    let operation = |resource: &ResourceId, operation_method: &str, suffix: &str| {
        serde_json::json!({
            "key": {"scope": ["provider-negative", method], "key": suffix},
            "interface": interface_key.clone(),
            "method": operation_method,
            "resource": resource,
        })
    };
    let behavioral_witness = matches!(method.as_str(), "observe-boot" | "observe-health")
        .then(|| operation(&real.resource, "hold", "blocked-mutation-witness"));
    let audit = serde_json::json!({
        "schema": FOREIGN_MAP_AUDIT_SCHEMA,
        "method": method,
        "desired-state": valid.desired_state,
        "real-mapping": real,
        "forged-mapping": forged,
        "attempted-map-digest": Sha256Digest::of_bytes(
            &aos_contract::canonical::to_vec(&attempted_entries)?
        ),
        "rejection": {
            "class": "physical-resource-collision",
            "resource": "A/B image rollout host",
            "message-digest": Sha256Digest::of_bytes(error.to_string().as_bytes()),
        },
        "foreign-operation": operation(&forged.resource, method, "foreign-attempt"),
        "dependent-operation": operation(&real.resource, method, "blocked-real-machine"),
        "behavioral-witness": behavioral_witness,
    });
    let bytes = aos_contract::canonical::to_vec(&audit)?;
    fs::write(output, bytes)
        .with_context(|| format!("writing rollout foreign-map audit {output}"))?;
    Ok(())
}

fn rollout_package_name(selection: &str) -> Result<&'static str> {
    match selection {
        "compatible" => Ok(COMPATIBLE_PACKAGE),
        "incompatible" => Ok(INCOMPATIBLE_PACKAGE),
        value => bail!("unknown rollout provider package {value:?}"),
    }
}

fn load_verified_packages(
    selected_package: &str,
    source_package: Option<&str>,
) -> Result<VerifiedAbilityPackageSet> {
    let config = ApmConfig::load(ProfileScope::System)?;
    let enabled = config.enabled_registries();
    let registries = RegistrySet::load_for_config_evaluation(
        &config.cache_path(),
        &enabled,
        &native_platform(),
    )?;
    let mut names = vec![selected_package.to_string()];
    if let Some(source_package) = source_package {
        names.push(source_package.to_string());
    }
    names.sort();
    names.dedup();
    let runtime = resolve_runtime(&registries, &names)?;
    aos_package::config_eval::ability_activation::verify_runtime_packages(&config, &runtime)
}

fn provider_adoption_authority(
    desired: &ComposedRollout,
    current: &ComposedRollout,
    expected_current_planning: Sha256Digest,
    mode: &ActivationMode,
) -> Result<TransitionAuthorizationDocument> {
    let ActivationMode::Qualification(method) = mode else {
        bail!("rollout provider adoption requires an exact qualification method");
    };
    let method = key(method)?;
    ensure!(
        current.planning.snapshot_digest() == expected_current_planning,
        "synthesized rollout source planning {} differs from retained planning {}",
        current.planning.snapshot_digest(),
        expected_current_planning,
    );
    let resources = desired
        .desired_state
        .resources
        .iter()
        .filter(|revision| revision.resource.key.as_str() == "machine")
        .map(|revision| revision.resource.clone())
        .collect::<Vec<_>>();
    let [resource] = resources.as_slice() else {
        bail!("rollout provider adoption requires one retained machine resource");
    };
    ensure!(
        current
            .desired_state
            .resources
            .iter()
            .any(|revision| revision.resource == *resource),
        "rollout provider adoption source lacks the retained machine resource"
    );

    let candidate = adoption_endpoint(desired, resource, &method)?;
    let source = adoption_endpoint(current, resource, &method)?;
    ensure!(
        source.handler_provider != candidate.handler_provider,
        "rollout provider adoption must change the terminal provider instance"
    );

    let source_plan = current.planning.checked_binding();
    let source_binding = source_plan
        .binding(&source.handler_binding)
        .context("rollout adoption source binding disappeared")?;
    let source_request = source_plan
        .document()
        .requests
        .iter()
        .find(|request| request.id == source_binding.request)
        .context("rollout adoption source request disappeared")?;
    let mut request = source_request.clone();
    request.id.key = key(&format!("adopt-request-{}", source_binding.id.0.as_str()))?;
    request.methods = vec![method.clone()];
    let mut binding = source_binding.clone();
    binding.id = BindingId(key(&format!(
        "adopt-binding-{}",
        source_binding.id.0.as_str()
    ))?);
    binding.request = request.id.clone();
    binding.policy_revision = desired
        .planning
        .checked_binding()
        .document()
        .policy_revision;
    binding.caller_grant.methods = vec![method.clone()];
    binding.caller_grant.contributions.clear();
    binding.caller_grant.resources.retain(|permission| {
        permission.resource == *resource && permission.operations.contains(&method)
    });
    ensure!(
        binding.caller_grant.resources.len() == 1,
        "rollout adoption source lacks one exact machine grant"
    );
    binding.caller_grant.resources[0].operations = vec![method];
    binding.provider_grant.methods.clear();
    binding.provider_grant.contributions.clear();
    binding.provider_grant.resources.clear();

    let desired_policy_revision = desired
        .planning
        .checked_binding()
        .document()
        .policy_revision;
    Ok(TransitionAuthorizationDocument {
        schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: vec![RequiredFeature::new(
            aos_ability_model::PROVIDER_STATE_ADOPTION_V1,
        )?],
        desired_planning: desired.planning.snapshot_digest(),
        current_planning: current.planning.snapshot_digest(),
        desired_policy_revision,
        prior_policy_revision: current
            .planning
            .checked_binding()
            .document()
            .policy_revision,
        authorization_policy_revision: desired_policy_revision,
        teardown_bindings: vec![TeardownBindingAuthorization {
            source_binding: source_binding.id.clone(),
            request,
            binding,
        }],
        teardown_providers: Vec::<TeardownProviderAuthorization>::new(),
        provider_adoptions: vec![ProviderAdoptionAuthorization {
            resource: resource.clone(),
            resource_interface: candidate.handler_interface.clone(),
            source,
            candidate,
        }],
    })
}

fn adoption_endpoint(
    composed: &ComposedRollout,
    resource: &ResourceId,
    method: &LocalKey,
) -> Result<ProviderAdoptionEndpoint> {
    let plan = composed.planning.checked_binding();
    let owner = composed
        .package
        .implementation
        .providers
        .iter()
        .find(|implementation| {
            implementation.interface.name.as_str() == HIGH_LEVEL_INTERFACE
                && matches!(
                    implementation.implementation,
                    ImplementationKind::PureComposition { .. }
                )
                && implementation.state_format.is_some()
                && implementation
                    .owns_resource_kinds
                    .iter()
                    .any(|kind| kind.as_str() == "aos.ab-image-rollout-effects")
        })
        .context("rollout package lacks its stateful machine owner")?;
    let bindings = plan
        .bindings()
        .iter()
        .filter(|binding| {
            binding.request.consumer == composed.provider
                && binding.interface.name.as_str() == "aos.ab-image-rollout-effects"
                && binding.caller_grant.methods.contains(method)
                && binding.caller_grant.resources.iter().any(|permission| {
                    permission.resource == *resource && permission.operations.contains(method)
                })
        })
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        bail!(
            "rollout provider adoption lacks one exact {:?} binding",
            method.as_str()
        );
    };
    let handler_package = binding
        .provider_package
        .context("rollout adoption handler lacks its package")?;
    let assignments = plan
        .environment()
        .providers
        .iter()
        .filter(|provider| {
            provider.provider == binding.provider
                && provider.interface == binding.interface
                && provider.implementation == binding.implementation
                && provider.state == ProviderState::Available
        })
        .collect::<Vec<_>>();
    let [assignment] = assignments.as_slice() else {
        bail!("rollout adoption handler lacks one live assignment");
    };

    Ok(ProviderAdoptionEndpoint {
        provider: composed.provider.clone(),
        package: composed.package.content_digest()?,
        interface: owner.interface.clone(),
        implementation: provider_reference(owner)?,
        state_format: owner
            .state_format
            .clone()
            .context("rollout adoption owner lost its state format")?,
        handler_binding: binding.id.clone(),
        handler_method: method.clone(),
        handler_provider: binding.provider.clone(),
        handler_incarnation: assignment
            .incarnation
            .clone()
            .context("rollout adoption assignment has no incarnation")?,
        handler_interface: binding.interface.clone(),
        handler_implementation: binding.implementation.clone(),
        handler_package,
    })
}

impl RolloutFixture {
    fn new(
        verified: &VerifiedAbilityPackageSet,
        selected_package: &str,
        mode: &ActivationMode,
        provider_incarnation_revision: Option<&str>,
        alternate_incarnation_revision: Option<&str>,
    ) -> Result<Self> {
        let verified_package = verified
            .iter()
            .find(|package| package.package().package.name.as_str() == selected_package)
            .with_context(|| {
                format!("authenticated rollout package {selected_package:?} is absent")
            })?;
        ensure!(
            verified_package.package().package.name.as_str() == selected_package,
            "rollout fixture authenticated an unexpected package"
        );
        let package = verified_package.package().clone();
        let package_digest = package.content_digest()?;

        let high_document = high_level_interface(matches!(mode, ActivationMode::Qualification(_)))?;
        let effects_document = ab_image_rollout_interface()?;
        let high_interface = high_document.interface_key()?;
        let effects_interface = effects_document.interface_key()?;
        let supported_features = BTreeSet::from([
            RequiredFeature::new("abilities-v1")?,
            RequiredFeature::new(AB_IMAGE_ROLLOUT_FEATURE)?,
            RequiredFeature::new(aos_ability_model::PROVIDER_STATE_FORMAT_V1)?,
            RequiredFeature::new(aos_ability_model::PROVIDER_STATE_ADOPTION_V1)?,
        ]);
        let context = ValidationContext::new(supported_features, [high_document, effects_document])
            .context("validating rollout fixture interface catalog")?;

        let mut high_implementation = None;
        let mut effects_implementation = None;
        for implementation in &package.implementation.providers {
            let reference = provider_reference(implementation)?;
            if implementation.interface == high_interface {
                ensure!(
                    matches!(
                        implementation.implementation,
                        ImplementationKind::PureComposition { .. }
                    ),
                    "rollout strategy provider is not pure composition"
                );
                high_implementation = Some(reference);
            } else if implementation.interface == effects_interface {
                ensure!(
                    matches!(
                        implementation.implementation,
                        ImplementationKind::TerminalHandler { .. }
                    ),
                    "rollout effects provider is not terminal"
                );
                effects_implementation = Some(reference);
            } else {
                bail!(
                    "rollout fixture package exports unexpected interface {}",
                    implementation.interface.name
                );
            }
        }
        let high_implementation =
            high_implementation.context("rollout strategy provider is absent")?;
        let effects_implementation =
            effects_implementation.context("rollout effects provider is absent")?;

        let environment_id = EnvironmentId {
            authority: key("reference")?,
            key: key("rollout-host")?,
            stage: ExecutionStage::Host,
        };
        let provider = instance(&environment_id, "image-rollout")?;
        let selected_terminal_provider =
            terminal_provider(&environment_id, provider_incarnation_revision)?;
        let policy_revision = RevisionId(digest(40));
        let mut providers = vec![ProviderInventory {
            provider: provider.clone(),
            interface: high_interface.clone(),
            implementation: high_implementation.clone(),
            state: ProviderState::Declared,
            incarnation: None,
            guarantees: Vec::new(),
        }];
        for revision in [
            provider_incarnation_revision,
            alternate_incarnation_revision,
        ] {
            let assignment_provider = terminal_provider(&environment_id, revision)?;
            if providers
                .iter()
                .any(|assignment| assignment.provider == assignment_provider)
            {
                continue;
            }
            providers.push(ProviderInventory {
                provider: assignment_provider,
                interface: effects_interface.clone(),
                implementation: effects_implementation.clone(),
                state: ProviderState::Available,
                incarnation: Some(provider_incarnation("rollout-terminal-v1", revision)?),
                guarantees: Vec::new(),
            });
        }
        providers.sort_by(|left, right| {
            left.interface
                .cmp(&right.interface)
                .then_with(|| left.provider.cmp(&right.provider))
        });
        let environment = EnvironmentDocument {
            schema: EnvironmentDocument::SCHEMA.to_string(),
            required_features: vec![RequiredFeature::new(AB_IMAGE_ROLLOUT_FEATURE)?],
            environment: environment_id,
            platform: PlatformIdentity {
                system: key("linux")?,
                architecture: key("x86_64")?,
            },
            policy_revision,
            providers,
            resources: Vec::new(),
            controllers: Vec::new(),
            guarantees: Vec::new(),
            freshness: FreshnessCondition {
                generation: RevisionId(digest(41)),
                max_age_millis: 60_000,
            },
        };
        let evaluator = RestrictedAbilityEvaluator::new(
            required_environment("AOS_NIX_INSTANTIATE")?,
            required_environment("AOS_PRLIMIT")?,
            required_environment("AOS_TEST_ABILITY_CACHE")?,
            AbilityEvaluationLimits::default(),
        )?;

        Ok(Self {
            context,
            environment,
            package,
            package_digest,
            provider,
            terminal_provider: selected_terminal_provider,
            high_interface,
            high_implementation,
            effects_interface,
            effects_implementation,
            policy_revision,
            evaluator,
        })
    }

    fn compose(
        mut self,
        request: &AbRolloutRequest,
        mode: &ActivationMode,
    ) -> Result<ComposedRollout> {
        let seed = self.seed(request, mode)?;
        let mut policies = Vec::new();
        loop {
            match RecursiveComposer::new(&self.context).compose(
                &policies,
                seed.clone(),
                self.environment.clone(),
                vec![self.package.clone()],
                &mut self.evaluator,
            ) {
                Ok(outcome) => {
                    let snapshot = PlanningSnapshot::from_outcome(&outcome)
                        .context("constructing rollout planning snapshot")?;
                    let mut authenticated_policies = policies.clone();
                    authenticated_policies.sort_by_key(|policy| policy.desired_state);
                    let planning = snapshot
                        .verify_structure(
                            &RecursiveComposer::new(&self.context),
                            PlanningReplayInputs {
                                expected_digest: snapshot.digest()?,
                                authenticated_policies: &authenticated_policies,
                                seed: seed.clone(),
                                environment: self.environment.clone(),
                                packages: vec![self.package.clone()],
                            },
                        )
                        .context("verifying rollout planning snapshot")?;
                    return Ok(ComposedRollout {
                        seed,
                        environment: self.environment,
                        desired_state: outcome.desired_state,
                        policies,
                        bindings: outcome.resolution.checked.bindings().to_vec(),
                        package: self.package,
                        provider: self.provider,
                        planning,
                    });
                }
                Err(CompositionError::PolicyRequired { desired_state, .. }) => {
                    policies.push(self.policy_for(&desired_state)?);
                }
                Err(error) => bail!("composing reference image rollout: {error:#?}"),
            }
        }
    }

    fn seed(
        &self,
        request: &AbRolloutRequest,
        mode: &ActivationMode,
    ) -> Result<DesiredStateDocument> {
        let instances = if !matches!(mode, ActivationMode::Retire) {
            let configuration = match mode {
                ActivationMode::Qualification(method) => serde_json::json!({
                    "method": method,
                    "request": request,
                }),
                ActivationMode::Rollout => serde_json::to_value(request)?,
                ActivationMode::Retire => unreachable!("retirement has no desired instance"),
            };
            vec![DesiredInstance {
                instance: self.provider.clone(),
                package: self.package_digest,
                enabled: true,
                configuration: Some(AbilityValue::new(configuration)?),
            }]
        } else {
            Vec::new()
        };
        Ok(DesiredStateDocument {
            schema: DesiredStateDocument::SCHEMA.to_string(),
            required_features: vec![RequiredFeature::new(AB_IMAGE_ROLLOUT_FEATURE)?],
            environment: self.environment.content_digest()?,
            instances,
            contributions: Vec::new(),
            child_requests: Vec::new(),
            resources: Vec::new(),
            outputs: Vec::new(),
            controllers: Vec::new(),
        })
    }

    fn policy_for(&self, desired: &DesiredStateDocument) -> Result<ResolutionPolicyDocument> {
        let machine = ResourceId {
            provider: self.provider.clone(),
            key: key("machine")?,
        };
        let resource_grant = ResourcePermission {
            resource: machine,
            access: AccessMode::ExclusiveWrite,
            operations: Vec::new(),
        };
        let enabled_providers = desired
            .instances
            .iter()
            .filter(|instance| instance.enabled && instance.instance == self.provider)
            .map(|_| EnabledProviderSelection {
                instance: self.provider.clone(),
                interface: self.high_interface.clone(),
                implementation: self.high_implementation.clone(),
                provider_grant: AuthorityGrant {
                    principal: self.provider.clone(),
                    methods: Vec::new(),
                    contributions: Vec::new(),
                    resources: vec![resource_grant.clone()],
                },
                policy_revision: self.policy_revision,
                lifetime: ResourceLifetime::Persistent,
            })
            .collect::<Vec<_>>();
        let mut candidates = desired
            .child_requests
            .iter()
            .map(|request| {
                ensure!(
                    request.accepted_interfaces == [self.effects_interface.clone()],
                    "rollout strategy requested an unexpected effects interface"
                );
                let resources = vec![ResourcePermission {
                    resource: ResourceId {
                        provider: self.provider.clone(),
                        key: key("machine")?,
                    },
                    access: AccessMode::ExclusiveWrite,
                    operations: request.methods.clone(),
                }];
                Ok(BindingCandidate {
                    key: binding_key(&request.id)?,
                    request: request.id.clone(),
                    interface: self.effects_interface.clone(),
                    provider: self.terminal_provider.clone(),
                    provider_package: self.package_digest,
                    implementation: self.effects_implementation.clone(),
                    caller_grant: AuthorityGrant {
                        principal: request.id.consumer.clone(),
                        methods: request.methods.clone(),
                        contributions: Vec::new(),
                        resources: resources.clone(),
                    },
                    provider_grant: AuthorityGrant {
                        principal: self.terminal_provider.clone(),
                        methods: Vec::new(),
                        contributions: Vec::new(),
                        resources,
                    },
                    guarantees: Vec::new(),
                    policy_revision: self.policy_revision,
                    lifetime: ResourceLifetime::Persistent,
                    mediation_allowed: true,
                    exclusive_resources: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        candidates.sort_by(|left, right| left.key.cmp(&right.key));
        let explicit_bindings = candidates
            .iter()
            .map(|candidate| CandidateSelection {
                request: candidate.request.clone(),
                candidate: candidate.key.clone(),
            })
            .collect();
        Ok(ResolutionPolicyDocument {
            schema: ResolutionPolicyDocument::SCHEMA.to_string(),
            required_features: vec![RequiredFeature::new(AB_IMAGE_ROLLOUT_FEATURE)?],
            desired_state: desired.content_digest()?,
            environment: self.environment.content_digest()?,
            policy_revision: self.policy_revision,
            candidates,
            explicit_bindings,
            existing_pins: Vec::new(),
            operator_orders: Vec::new(),
            enabled_providers,
            obligations: Vec::new(),
        })
    }
}

fn rollout_resource_map(
    composed: &ComposedRollout,
    request: &AbRolloutRequest,
    mode: &ActivationMode,
) -> Result<NativeResourceMap> {
    let mappings = if !matches!(mode, ActivationMode::Retire) {
        let resource = composed
            .desired_state
            .resources
            .iter()
            .find(|revision| revision.resource.key.as_str() == "machine")
            .context("composed rollout has no machine resource")?;
        let binding = composed
            .bindings
            .iter()
            .find(|binding| binding.request.key.as_str() == "effects")
            .context("composed rollout has no effects binding")?;
        vec![NativeResourceMapping {
            resource: resource.resource.clone(),
            revision: resource.revision,
            owner_package: binding
                .provider_package
                .context("rollout effects binding is not package-backed")?,
            binding: binding.id.clone(),
            implementation: binding.implementation.clone(),
            qualification: NativeResourceQualification::AbImageRollout {
                request: request.clone(),
            },
        }]
    } else {
        Vec::new()
    };
    NativeResourceMap::new(composed.desired_state.content_digest()?, mappings)
}

fn platform_policy(composed: &ComposedRollout) -> Result<CurrentPlatformPolicyDocument> {
    let mut bindings = composed
        .bindings
        .iter()
        .filter(|binding| {
            !composed.policies.iter().any(|policy| {
                policy.candidates.iter().any(|candidate| {
                    candidate.request == binding.request
                        && candidate.interface == binding.interface
                        && candidate.provider == binding.provider
                        && Some(candidate.provider_package) == binding.provider_package
                        && candidate.implementation == binding.implementation
                        && candidate.policy_revision == binding.policy_revision
                })
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    bindings.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(CurrentPlatformPolicyDocument {
        schema: CurrentPlatformPolicyDocument::SCHEMA.to_string(),
        required_features: vec![RequiredFeature::new(AB_IMAGE_ROLLOUT_FEATURE)?],
        policy_revision: composed.environment.policy_revision,
        bindings,
    })
}

fn high_level_interface(qualification: bool) -> Result<InterfaceDocument> {
    let configuration = if qualification {
        ValueSchema::Record {
            fields: BTreeMap::from([
                (
                    key("method")?,
                    ValueSchema::StringEnum {
                        values: [
                            "drain",
                            "hold",
                            "observe-boot",
                            "observe-health",
                            "prepare",
                            "retain",
                            "retire",
                            "rollout",
                            "select",
                            "withdraw",
                        ]
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                    },
                ),
                (key("request")?, ab_image_rollout_request_schema()?),
            ]),
            optional_fields: Vec::new(),
        }
    } else {
        ab_image_rollout_request_schema()?
    };
    Ok(InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: InterfaceName::new(HIGH_LEVEL_INTERFACE)?,
            abi: NonZeroU32::new(1).context("rollout interface ABI must be nonzero")?,
            request: ValueSchema::Boolean,
            configuration: Some(configuration),
            outputs: BTreeMap::from([(
                key("machine")?,
                OutputDescriptor {
                    schema: ValueSchema::ResourceReference,
                    phase: ValuePhase::Planning,
                    visibility: ValueVisibility::Protected,
                    lifetime: ResourceLifetime::Persistent,
                },
            )]),
            methods: BTreeMap::new(),
            lifecycle: LifecycleSemantics {
                stable_resource_identity: true,
                releases_ephemeral_on_disable: false,
                retains_persistent_by_default: true,
                persistent_delete_method: None,
            },
            guarantees: Vec::new(),
        },
    })
}

fn provider_reference(
    implementation: &ProviderImplementation,
) -> Result<ProviderImplementationReference> {
    let handler = match &implementation.implementation {
        ImplementationKind::PureComposition { .. } => None,
        ImplementationKind::TerminalHandler { handler } => Some(handler.clone()),
    };
    Ok(ProviderImplementationReference {
        descriptor: implementation.descriptor_digest()?,
        artifact: implementation.artifact.clone(),
        handler,
    })
}

fn instance(environment: &EnvironmentId, name: &str) -> Result<InstanceId> {
    Ok(InstanceId {
        environment: environment.clone(),
        key: key(name)?,
    })
}

fn terminal_provider(environment: &EnvironmentId, revision: Option<&str>) -> Result<InstanceId> {
    let name = revision
        .map(|revision| format!("image-rollout-terminal-{revision}"))
        .unwrap_or_else(|| "image-rollout-terminal".to_string());
    instance(environment, &name)
}

fn validate_provider_revision(revision: &str) -> Result<()> {
    ensure!(
        !revision.is_empty()
            && revision.len() <= 96
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)),
        "provider incarnation revision is outside the safe fixture subset"
    );
    Ok(())
}

fn provider_incarnation(
    identity: &str,
    revision: Option<&str>,
) -> Result<aos_ability_model::IncarnationId> {
    let identity = revision
        .map(|revision| format!("{identity}-{revision}"))
        .unwrap_or_else(|| identity.to_string());
    aos_ability_model::IncarnationId::new(&identity).map_err(anyhow::Error::from)
}

fn binding_key(request: &aos_ability_model::RequestId) -> Result<LocalKey> {
    key(&format!("bind-{}-{}", request.consumer.key, request.key))
}

fn key(value: &str) -> Result<LocalKey> {
    LocalKey::new(value).map_err(anyhow::Error::from)
}

fn required_environment(name: &str) -> Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .with_context(|| format!("reading required environment variable {name}"))
}

fn digest(tag: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([tag; 32])
}
