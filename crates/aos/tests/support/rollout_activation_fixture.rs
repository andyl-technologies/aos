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
    AbilityValue, AccessMode, AuthorityGrant, DesiredStateDocument, EnvironmentDocument,
    EnvironmentId, ExecutionStage, ImplementationKind, InstanceId, InterfaceDescriptor,
    InterfaceDocument, InterfaceKey, InterfaceName, LifecycleSemantics, LocalKey, OutputDescriptor,
    PackageDocument, ProviderImplementation, ProviderImplementationReference, RequiredFeature,
    ResourceId, ResourceLifetime, ResourcePermission, RevisionId, ValuePhase, ValueSchema,
    ValueVisibility, VersionedDocument,
};
use aos_ability_plan::{
    AbRolloutRequest, BindingCandidate, CandidateSelection, CompositionError,
    EnabledProviderSelection, RecursiveComposer, ResolutionPolicyDocument,
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

const PACKAGE_NAME: &str = "ability-reference-image-rollout";
const HIGH_LEVEL_INTERFACE: &str = "aos.ab-image-rollout";

struct RolloutFixture {
    context: ValidationContext,
    environment: EnvironmentDocument,
    package: PackageDocument,
    package_digest: Sha256Digest,
    provider: InstanceId,
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
/// --mode MODE`. `MODE` is `rollout`, `retire`, or
/// `qualification-{method}`. The request JSON carries one exact
/// [`AbRolloutRequest`]; qualification changes only graph selection and keeps
/// the production terminal handler and native resource mapping.
///
/// # Errors
///
/// Returns an error when the request, authenticated package, recursive plan,
/// native resource mapping, or retained sidecar is invalid.
pub(super) fn generate(arguments: &[String]) -> Result<()> {
    if arguments.len() != 6
        || arguments[2] != "--operator-authority-output"
        || arguments[4] != "--mode"
    {
        bail!(
            "usage: aos-release-fleet-fixture rollout-activation OUTPUT REQUEST_JSON --operator-authority-output AUTHORITY_DIR --mode rollout|retire|qualification-METHOD"
        );
    }

    let output = Path::new(&arguments[0]);
    let request_path = Path::new(&arguments[1]);
    let authority_output = Path::new(&arguments[3]);
    let mode = ActivationMode::parse(&arguments[5])?;
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
    let packages = load_verified_package()?;
    let fixture = RolloutFixture::new(&packages, &mode)?;
    let composed = fixture.compose(&request, &mode)?;
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
        None,
        native_resource_map,
    )?;
    policy_document.schema = AuthenticatedPolicySetDocument::SCHEMA_V3.to_string();
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
            "native-resource-map-v2"
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

fn load_verified_package() -> Result<VerifiedAbilityPackageSet> {
    let config = ApmConfig::load(ProfileScope::System)?;
    let enabled = config.enabled_registries();
    let registries = RegistrySet::load_for_config_evaluation(
        &config.cache_path(),
        &enabled,
        &native_platform(),
    )?;
    let runtime = resolve_runtime(&registries, &[PACKAGE_NAME.to_string()])?;
    aos_package::config_eval::ability_activation::verify_runtime_packages(&config, &runtime)
}

impl RolloutFixture {
    fn new(verified: &VerifiedAbilityPackageSet, mode: &ActivationMode) -> Result<Self> {
        let packages = verified.iter().collect::<Vec<_>>();
        let [verified_package] = packages.as_slice() else {
            bail!(
                "rollout fixture requires exactly one authenticated package, found {}",
                packages.len()
            );
        };
        ensure!(
            verified_package.package().package.name.as_str() == PACKAGE_NAME,
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
        let policy_revision = RevisionId(digest(40));
        let mut providers = vec![
            ProviderInventory {
                provider: provider.clone(),
                interface: high_interface.clone(),
                implementation: high_implementation.clone(),
                state: ProviderState::Declared,
                incarnation: None,
                guarantees: Vec::new(),
            },
            ProviderInventory {
                provider: provider.clone(),
                interface: effects_interface.clone(),
                implementation: effects_implementation.clone(),
                state: ProviderState::Available,
                incarnation: Some(aos_ability_model::IncarnationId::new(
                    "rollout-terminal-v1",
                )?),
                guarantees: Vec::new(),
            },
        ];
        providers.sort_by(|left, right| left.interface.cmp(&right.interface));
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
                    return Ok(ComposedRollout {
                        seed,
                        environment: self.environment,
                        desired_state: outcome.desired_state,
                        policies,
                        bindings: outcome.resolution.checked.bindings().to_vec(),
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
                    provider: self.provider.clone(),
                    provider_package: self.package_digest,
                    implementation: self.effects_implementation.clone(),
                    caller_grant: AuthorityGrant {
                        principal: request.id.consumer.clone(),
                        methods: request.methods.clone(),
                        contributions: Vec::new(),
                        resources: resources.clone(),
                    },
                    provider_grant: AuthorityGrant {
                        principal: self.provider.clone(),
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
