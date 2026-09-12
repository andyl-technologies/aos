//! Authenticated native PostgreSQL activation and fixture-only authority staging.
//!
//! Generation replays the signed production provider through the recursive
//! composer, qualifies each terminal host resource, and stages policy and
//! credential authorities outside the Nix store. The deterministic credentials
//! and provisioning command exist only in `pkgs.aos.testSupport`; production
//! code never synthesizes credential authority or test secrets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::num::NonZeroU32;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::builtin::{
    credential_delivery_effects_interface, host_network_policy_interface,
    host_network_policy_loopback_tcp_ingress_guarantee, host_storage_interface,
    network_endpoint_interface, postgresql_effects_interface,
};
use aos_ability_model::document::{
    Contribution, DesiredInstance, FreshnessCondition, PlatformIdentity, ProviderInventory,
    ProviderState,
};
use aos_ability_model::{
    AbilityValue, AccessMode, AggregateId, ArtifactReference, AuthorityGrant, Binding, BindingId,
    BindingRequest, BindingSource, ContributionPermission, DesiredStateDocument,
    EnvironmentDocument, EnvironmentId, ExecutionStage, ImplementationKind, InstanceId,
    InterfaceDescriptor, InterfaceDocument, InterfaceKey, InterfaceName, LifecycleSemantics,
    LocalKey, OutputDescriptor, PackageDocument, ProviderAdoptionAuthorization,
    ProviderAdoptionEndpoint, ProviderImplementation, ProviderImplementationReference,
    RequiredFeature, ResourceId, ResourceLifetime, ResourcePermission, ResourceRevision,
    RevisionId, ScopePath, StringConstraint, StringSyntax, TeardownBindingAuthorization,
    TeardownProviderAuthorization, TransitionAuthorizationDocument, ValuePhase, ValueSchema,
    ValueVisibility, VersionedDocument,
};
use aos_ability_plan::{
    BindingCandidate, CandidateSelection, CompositionError, EnabledProviderSelection,
    PlanningReplayInputs, PlanningSnapshot, RecursiveComposer, ResolutionPolicyDocument,
    VerifiedPlanningSnapshot,
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
use serde::{Deserialize, Serialize};

use super::ability_activation_fixture::{retain_sidecar, write_operator_authority};

const PUBLIC_INTERFACE: &str = "aos.postgresql";
const PUBLIC_DESCRIPTOR: &str =
    "sha256:0c2cfe5a8480b0dd1113e56414241cb81c54c080a5e0bc63be60b6d033464898";
const PROVIDER_INSTANCE: &str = "postgresql";
const TERMINAL_PROVIDER_INSTANCE: &str = "postgresql-terminal";
const CREDENTIAL_SOURCE_ROOT: &str = "/var/lib/aos/ability-runtime/credential-sources";
const MAX_CLUSTERS: usize = 64;
const MAX_CREDENTIAL_RECORD_BYTES: u64 = 64 * 1024;
const MAX_CREDENTIAL_SECRET_BYTES: u64 = 64 * 1024;

const CONTROL_FAULTS: &[&str] = &[
    "hold-quarantine-after-start",
    "crash-initdb-before-pg-version",
    "crash-initdb-after-pg-version",
    "crash-quarantine-config",
    "crash-quarantine-hba",
    "crash-quarantine-ident",
    "crash-publish-final-config",
    "crash-publish-final-hba",
    "crash-publish-final-ident",
];

const AUTHORITY_FAULTS: &[&str] = &[
    "credential-authority",
    "endpoint-authority",
    "storage-authority",
    "network-policy-authority",
    "postgresql-authority",
    "forged-guarantee",
    "forged-retained-adoption",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    Full,
    Remove,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Authentication {
    Scram,
    Trust,
}

#[derive(Clone, Debug)]
struct Cluster {
    database: String,
    role: String,
    credential_version: Option<String>,
    configuration: String,
}

#[derive(Clone, Debug)]
struct GenerateOptions {
    output: PathBuf,
    authority_output: PathBuf,
    clusters: Vec<Cluster>,
    lifecycle: Lifecycle,
    authentication: Authentication,
    fault: Option<String>,
    artifact: String,
    adoption_from: Option<String>,
    adoption_current_planning: Option<Sha256Digest>,
}

struct PostgresqlFixture {
    context: ValidationContext,
    environment: EnvironmentDocument,
    packages: Vec<PackageDocument>,
    selected_package: Sha256Digest,
    selected_document: PackageDocument,
    consumer_package: Option<Sha256Digest>,
    provider: InstanceId,
    terminal_provider: InstanceId,
    interfaces: BTreeMap<String, InterfaceKey>,
    implementations: BTreeMap<String, ProviderImplementationReference>,
    policy_revision: RevisionId,
    evaluator: RestrictedAbilityEvaluator,
}

struct ComposedPostgresql {
    seed: DesiredStateDocument,
    environment: EnvironmentDocument,
    desired_state: DesiredStateDocument,
    policies: Vec<ResolutionPolicyDocument>,
    bindings: Vec<Binding>,
    selected_document: PackageDocument,
    provider: InstanceId,
    planning: Option<VerifiedPlanningSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialSourceRecord {
    schema: String,
    resource: ResourceId,
    version: String,
    source_path: String,
    content_digest: Sha256Digest,
}

#[derive(Serialize)]
struct CredentialSourceKey<'a> {
    resource: &'a ResourceId,
    version: &'a str,
}

/// Generates a credentialed PostgreSQL activation fixture.
///
/// # Errors
///
/// Returns an error when arguments are invalid, signed packages cannot be
/// replayed, composition fails, or authority staging cannot be written.
pub(super) fn generate(arguments: &[String]) -> Result<()> {
    let options = parse_credentialed(arguments)?;
    generate_with_options(options)
}

/// Generates a direct trust-authentication PostgreSQL activation fixture.
///
/// # Errors
///
/// Returns an error when arguments are invalid, signed packages cannot be
/// replayed, composition fails, or authority staging cannot be written.
pub(super) fn generate_terminal(arguments: &[String]) -> Result<()> {
    let options = parse_terminal(arguments)?;
    generate_with_options(options)
}

fn generate_with_options(options: GenerateOptions) -> Result<()> {
    validate_options(&options)?;
    fs::create_dir_all(&options.output)
        .with_context(|| format!("creating PostgreSQL fixture {}", options.output.display()))?;
    fs::create_dir_all(&options.authority_output).with_context(|| {
        format!(
            "creating PostgreSQL authority staging {}",
            options.authority_output.display()
        )
    })?;

    let selected_name = selected_package_name(&options)?;
    let adoption_source = options
        .adoption_from
        .as_deref()
        .map(adoption_package_name)
        .transpose()?;
    let verified = load_verified_packages(&selected_name, adoption_source, options.authentication)?;
    let fixture = PostgresqlFixture::new(&verified, &selected_name, options.authentication)?;
    let mut composed = fixture.compose(&options.clusters, options.lifecycle)?;
    let transition_authority = if let Some(source_name) = adoption_source {
        let current = PostgresqlFixture::new(&verified, source_name, options.authentication)?
            .compose(&options.clusters, Lifecycle::Full)?;
        Some(provider_adoption_authority(
            &composed,
            &current,
            options
                .adoption_current_planning
                .context("provider adoption lacks the retained current planning digest")?,
        )?)
    } else {
        None
    };
    let mut native_resources = postgresql_native_resource_map(&composed, &options.clusters)?;
    apply_negative_fault(
        options.fault.as_deref(),
        &mut native_resources,
        &mut composed.policies,
    )?;
    let platform_policy = platform_policy(&composed);
    if options.authentication == Authentication::Scram && options.lifecycle == Lifecycle::Full {
        stage_credentials(&options, &composed.provider)?;
    }
    write_provider_description(&options, &composed, &selected_name)?;

    let desired_document = ActivationDesiredInputDocument {
        schema: ActivationDesiredInputDocument::SCHEMA.to_string(),
        seed: composed.seed,
        environment: composed.environment,
    };
    let policy_document = if options.authentication == Authentication::Trust {
        AuthenticatedPolicySetDocument {
            schema: AuthenticatedPolicySetDocument::SCHEMA_V3.to_string(),
            policies: composed.policies,
            transition_authority,
            native_resource_map: Some(native_resources),
            platform_policy: Some(platform_policy),
        }
    } else {
        let mut document = AuthenticatedPolicySetDocument::new(
            &desired_document,
            composed.policies,
            transition_authority,
            native_resources,
        )?;
        document.schema = AuthenticatedPolicySetDocument::SCHEMA_V3.to_string();
        document.platform_policy = Some(platform_policy);
        document
    };
    if options.authentication == Authentication::Scram
        && !is_negative_fault(options.fault.as_deref())
        && options.artifact != "adoption-incompatible"
    {
        policy_document.validate(&desired_document)?;
    }

    let desired_sidecar = retain_sidecar(
        &options.output,
        "desired",
        "desired.json",
        &desired_document,
    )?;
    let policy_sidecar =
        retain_sidecar(&options.output, "policy", "policy.json", &policy_document)?;
    let policy_staging = options.authority_output.join("policy");
    write_operator_authority(&policy_staging, &policy_sidecar)?;

    write_activation(&options.output, desired_sidecar, policy_sidecar)?;
    Ok(())
}

fn provider_adoption_authority(
    desired: &ComposedPostgresql,
    current: &ComposedPostgresql,
    expected_current_planning: Sha256Digest,
) -> Result<TransitionAuthorizationDocument> {
    let desired_planning = desired
        .planning
        .as_ref()
        .context("provider adoption candidate lacks a verified planning snapshot")?;
    let current_planning = current
        .planning
        .as_ref()
        .context("provider adoption source lacks a verified planning snapshot")?;
    ensure!(
        current_planning.snapshot_digest() == expected_current_planning,
        "synthesized adoption source planning {} differs from the retained prior generation {}",
        current_planning.snapshot_digest(),
        expected_current_planning,
    );
    ensure!(
        desired.environment == current.environment,
        "provider adoption plans must share one authenticated environment"
    );
    let resource = desired
        .desired_state
        .resources
        .iter()
        .filter(|revision| revision.resource.key.as_str().ends_with("-postgresql"))
        .map(|revision| revision.resource.clone())
        .collect::<Vec<_>>();
    let [resource] = resource.as_slice() else {
        bail!("provider adoption requires exactly one retained PostgreSQL resource");
    };
    ensure!(
        current
            .desired_state
            .resources
            .iter()
            .any(|revision| revision.resource == *resource),
        "provider adoption source lacks the retained PostgreSQL resource"
    );

    let method = key("materialize")?;
    let candidate = adoption_endpoint(desired, resource, &method)?;
    let source = adoption_endpoint(current, resource, &method)?;
    ensure!(
        source.handler_interface == candidate.handler_interface,
        "provider adoption changes the PostgreSQL resource kind"
    );
    ensure!(
        source.handler_provider != candidate.handler_provider,
        "provider adoption source and candidate must use distinct terminal handler instances"
    );

    let source_binding = current_planning
        .checked_binding()
        .binding(&source.handler_binding)
        .context("provider adoption source handler binding disappeared")?;
    let source_request = current_planning
        .checked_binding()
        .document()
        .requests
        .iter()
        .find(|request| request.id == source_binding.request)
        .context("provider adoption source binding lost its checked request")?;
    let stop = key("stop")?;
    let mut request = source_request.clone();
    request.id.key = key(&format!("adopt-request-{}", source_binding.id.0.as_str()))?;
    let mut binding = source_binding.clone();
    binding.id = BindingId(key(&format!(
        "adopt-binding-{}",
        source_binding.id.0.as_str()
    ))?);
    binding.request = request.id.clone();
    binding.policy_revision = desired_planning
        .checked_binding()
        .document()
        .policy_revision;
    binding.caller_grant.contributions.clear();
    binding.caller_grant.methods = vec![stop.clone()];
    binding.caller_grant.resources.retain(|permission| {
        permission.resource == *resource && permission.operations.contains(&stop)
    });
    ensure!(
        binding.caller_grant.resources.len() == 1,
        "provider adoption source lacks one exact PostgreSQL Stop grant"
    );
    binding.caller_grant.resources[0].operations = vec![stop];
    binding.provider_grant.methods.clear();
    binding.provider_grant.contributions.clear();
    binding.provider_grant.resources.clear();
    let teardown_bindings = vec![TeardownBindingAuthorization {
        source_binding: source_binding.id.clone(),
        request,
        binding,
    }];

    let desired_policy_revision = desired_planning
        .checked_binding()
        .document()
        .policy_revision;
    Ok(TransitionAuthorizationDocument {
        schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: vec![RequiredFeature::new(
            aos_ability_model::PROVIDER_STATE_ADOPTION_V1,
        )?],
        desired_planning: desired_planning.snapshot_digest(),
        current_planning: current_planning.snapshot_digest(),
        desired_policy_revision,
        prior_policy_revision: current_planning
            .checked_binding()
            .document()
            .policy_revision,
        authorization_policy_revision: desired_policy_revision,
        teardown_bindings,
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
    composed: &ComposedPostgresql,
    resource: &ResourceId,
    method: &LocalKey,
) -> Result<ProviderAdoptionEndpoint> {
    let planning = composed
        .planning
        .as_ref()
        .context("provider adoption endpoint lacks verified planning")?;
    let binding_plan = planning.checked_binding();
    let owner_package = composed.selected_document.content_digest()?;
    let owner = composed
        .selected_document
        .implementation
        .providers
        .iter()
        .find(|implementation| {
            implementation.interface.name.as_str() == PUBLIC_INTERFACE
                && matches!(
                    implementation.implementation,
                    ImplementationKind::PureComposition { .. }
                )
                && implementation.state_format.is_some()
                && implementation
                    .owns_resource_kinds
                    .iter()
                    .any(|kind| kind.as_str() == "aos.postgresql-effects")
        })
        .context("provider adoption package lacks its stateful PostgreSQL owner")?;
    let binding = binding_plan
        .bindings()
        .iter()
        .filter(|binding| {
            binding.request.consumer == composed.provider
                && binding.interface.name.as_str() == "aos.postgresql-effects"
                && binding.caller_grant.methods.contains(method)
                && binding.caller_grant.resources.iter().any(|permission| {
                    permission.resource == *resource
                        && permission.access.is_write()
                        && permission.operations.contains(method)
                })
        })
        .collect::<Vec<_>>();
    let [binding] = binding.as_slice() else {
        bail!("provider adoption lacks one exact PostgreSQL materialization binding");
    };
    let handler_package = binding
        .provider_package
        .context("provider adoption handler lacks its exact package")?;
    let assignments = binding_plan
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
        bail!("provider adoption handler lacks one exact live assignment");
    };

    Ok(ProviderAdoptionEndpoint {
        provider: composed.provider.clone(),
        package: owner_package,
        interface: owner.interface.clone(),
        implementation: provider_reference(owner)?,
        state_format: owner
            .state_format
            .clone()
            .context("provider adoption owner lost its state format")?,
        handler_binding: binding.id.clone(),
        handler_method: method.clone(),
        handler_provider: binding.provider.clone(),
        handler_incarnation: assignment
            .incarnation
            .clone()
            .context("available PostgreSQL assignment has no incarnation")?,
        handler_interface: binding.interface.clone(),
        handler_implementation: binding.implementation.clone(),
        handler_package,
    })
}

fn selected_package_name(options: &GenerateOptions) -> Result<String> {
    if let Some(fault) = options.fault.as_deref().and_then(control_fault_name) {
        return Ok(format!("ability-reference-postgresql-fault-{fault}"));
    }
    match options.artifact.as_str() {
        "baseline" => Ok("ability-reference-postgresql".to_string()),
        "upgrade" => Ok("ability-reference-postgresql-upgrade".to_string()),
        "adoption-v1" => Ok("ability-reference-postgresql-adoption-v1".to_string()),
        "adoption-v2" => Ok("ability-reference-postgresql-adoption-v2".to_string()),
        "adoption-incompatible" => {
            Ok("ability-reference-postgresql-adoption-incompatible".to_string())
        }
        "adoption-v2-interrupted" => {
            Ok("ability-reference-postgresql-adoption-v2-interrupted".to_string())
        }
        value => bail!("unknown PostgreSQL artifact selection {value:?}"),
    }
}

fn adoption_package_name(artifact: &str) -> Result<&'static str> {
    match artifact {
        "adoption-v1" => Ok("ability-reference-postgresql-adoption-v1"),
        "adoption-v2" => Ok("ability-reference-postgresql-adoption-v2"),
        "adoption-v2-interrupted" => Ok("ability-reference-postgresql-adoption-v2-interrupted"),
        value => bail!("unknown PostgreSQL adoption source {value:?}"),
    }
}

fn load_verified_packages(
    selected_name: &str,
    adoption_source: Option<&str>,
    authentication: Authentication,
) -> Result<VerifiedAbilityPackageSet> {
    let config = ApmConfig::load(ProfileScope::System)?;
    let enabled = config.enabled_registries();
    let registries = RegistrySet::load_for_config_evaluation(
        &config.cache_path(),
        &enabled,
        &native_platform(),
    )?;
    let mut names = if selected_name.starts_with("ability-reference-postgresql-adoption-")
        || adoption_source.is_some()
    {
        [
            "ability-reference-postgresql-adoption-incompatible",
            "ability-reference-postgresql-adoption-v1",
            "ability-reference-postgresql-adoption-v2",
            "ability-reference-postgresql-adoption-v2-interrupted",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    } else {
        vec![selected_name.to_string()]
    };
    if let Some(source) = adoption_source
        && !names.iter().any(|name| name == source)
    {
        names.push(source.to_string());
    }
    if authentication == Authentication::Scram {
        names.push("ability-reference-postgresql-consumer".to_string());
    }
    names.sort();
    names.dedup();
    let runtime = resolve_runtime(&registries, &names)?;
    aos_package::config_eval::ability_activation::verify_runtime_packages(&config, &runtime)
}

fn parse_credentialed(arguments: &[String]) -> Result<GenerateOptions> {
    if arguments.len() < 7 {
        bail!(
            "usage: aos-release-fleet-fixture postgresql-activation OUTPUT DATABASE ROLE CREDENTIAL_VERSION --configuration LABEL [--lifecycle full|remove] [--fault NAME] [--additional-postgresql DATABASE ROLE VERSION CONFIGURATION]... [--postgresql-artifact baseline|upgrade|adoption-v1|adoption-v2|adoption-v2-interrupted|adoption-incompatible] [--provider-adoption-from adoption-v1|adoption-v2|adoption-v2-interrupted --provider-adoption-current-planning DIGEST] --operator-authority-output DIR"
        );
    }
    let mut options = GenerateOptions {
        output: PathBuf::from(&arguments[0]),
        authority_output: PathBuf::new(),
        clusters: vec![Cluster {
            database: arguments[1].clone(),
            role: arguments[2].clone(),
            credential_version: Some(arguments[3].clone()),
            configuration: String::new(),
        }],
        lifecycle: Lifecycle::Full,
        authentication: Authentication::Scram,
        fault: None,
        artifact: "baseline".to_string(),
        adoption_from: None,
        adoption_current_planning: None,
    };
    let mut index = 4;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--configuration" => {
                let value = required_option(arguments, index, 1, "--configuration")?;
                ensure!(
                    options.clusters[0].configuration.is_empty(),
                    "--configuration is repeated"
                );
                options.clusters[0].configuration = value[0].clone();
                index += 2;
            }
            "--lifecycle" => {
                let value = required_option(arguments, index, 1, "--lifecycle")?;
                options.lifecycle = match value[0].as_str() {
                    "full" => Lifecycle::Full,
                    "remove" => Lifecycle::Remove,
                    other => bail!("unknown PostgreSQL lifecycle {other:?}"),
                };
                index += 2;
            }
            "--fault" => {
                let value = required_option(arguments, index, 1, "--fault")?;
                ensure!(options.fault.is_none(), "--fault is repeated");
                options.fault = Some(value[0].clone());
                index += 2;
            }
            "--additional-postgresql" => {
                let value = required_option(arguments, index, 4, "--additional-postgresql")?;
                options.clusters.push(Cluster {
                    database: value[0].clone(),
                    role: value[1].clone(),
                    credential_version: Some(value[2].clone()),
                    configuration: value[3].clone(),
                });
                index += 5;
            }
            "--postgresql-artifact" => {
                let value = required_option(arguments, index, 1, "--postgresql-artifact")?;
                options.artifact = value[0].clone();
                index += 2;
            }
            "--provider-adoption-from" => {
                let value = required_option(arguments, index, 1, "--provider-adoption-from")?;
                ensure!(
                    options.adoption_from.is_none(),
                    "--provider-adoption-from is repeated"
                );
                options.adoption_from = Some(value[0].clone());
                index += 2;
            }
            "--provider-adoption-current-planning" => {
                let value =
                    required_option(arguments, index, 1, "--provider-adoption-current-planning")?;
                ensure!(
                    options.adoption_current_planning.is_none(),
                    "--provider-adoption-current-planning is repeated"
                );
                options.adoption_current_planning = Some(
                    Sha256Digest::parse(&value[0])
                        .context("parsing retained provider-adoption planning digest")?,
                );
                index += 2;
            }
            "--operator-authority-output" => {
                let value = required_option(arguments, index, 1, "--operator-authority-output")?;
                ensure!(
                    options.authority_output.as_os_str().is_empty(),
                    "--operator-authority-output is repeated"
                );
                options.authority_output = PathBuf::from(&value[0]);
                index += 2;
            }
            option => bail!("unknown PostgreSQL fixture option {option:?}"),
        }
    }
    ensure!(
        !options.clusters[0].configuration.is_empty(),
        "--configuration is required"
    );
    ensure!(
        !options.authority_output.as_os_str().is_empty(),
        "--operator-authority-output is required"
    );
    Ok(options)
}

fn parse_terminal(arguments: &[String]) -> Result<GenerateOptions> {
    if arguments.len() != 9
        || arguments[3] != "--auth"
        || arguments[4] != "trust"
        || arguments[5] != "--configuration"
        || arguments[7] != "--operator-authority-output"
    {
        bail!(
            "usage: aos-release-fleet-fixture postgresql-terminal-activation OUTPUT DATABASE ROLE --auth trust --configuration LABEL --operator-authority-output DIR"
        );
    }
    Ok(GenerateOptions {
        output: PathBuf::from(&arguments[0]),
        authority_output: PathBuf::from(&arguments[8]),
        clusters: vec![Cluster {
            database: arguments[1].clone(),
            role: arguments[2].clone(),
            credential_version: None,
            configuration: arguments[6].clone(),
        }],
        lifecycle: Lifecycle::Full,
        authentication: Authentication::Trust,
        fault: None,
        artifact: "baseline".to_string(),
        adoption_from: None,
        adoption_current_planning: None,
    })
}

fn required_option<'a>(
    arguments: &'a [String],
    index: usize,
    count: usize,
    name: &str,
) -> Result<&'a [String]> {
    arguments
        .get(index + 1..index + 1 + count)
        .with_context(|| format!("{name} requires {count} value(s)"))
}

fn validate_options(options: &GenerateOptions) -> Result<()> {
    ensure!(
        options.output != options.authority_output,
        "authority staging must differ from activation output"
    );
    ensure!(
        !options.clusters.is_empty() && options.clusters.len() <= MAX_CLUSTERS,
        "PostgreSQL fixture requires between 1 and {MAX_CLUSTERS} clusters"
    );
    let mut databases = BTreeSet::new();
    let mut roles = BTreeSet::new();
    for cluster in &options.clusters {
        validate_postgresql_identifier(&cluster.database, "database")?;
        validate_postgresql_identifier(&cluster.role, "role")?;
        ensure!(
            databases.insert(cluster.database.clone()),
            "duplicate PostgreSQL database {:?}",
            cluster.database
        );
        ensure!(
            roles.insert(cluster.role.clone()),
            "duplicate PostgreSQL role {:?}",
            cluster.role
        );
        ensure!(
            !cluster.configuration.is_empty() && cluster.configuration.len() <= 128,
            "PostgreSQL configuration label is outside 1..=128 bytes"
        );
        if let Some(version) = &cluster.credential_version {
            ensure!(
                !version.is_empty() && version.len() <= 71,
                "credential version is outside 1..=71 bytes"
            );
        }
    }
    if let Some(fault) = options.fault.as_deref() {
        ensure!(
            control_fault_name(fault).is_some() || AUTHORITY_FAULTS.contains(&fault),
            "unknown PostgreSQL fixture fault {fault:?}"
        );
    }
    if let Some(source) = options.adoption_from.as_deref() {
        adoption_package_name(source)?;
        ensure!(
            matches!(
                options.artifact.as_str(),
                "adoption-v1" | "adoption-v2" | "adoption-incompatible" | "adoption-v2-interrupted"
            ),
            "provider adoption requires a stateful PostgreSQL candidate"
        );
        ensure!(
            source != options.artifact,
            "provider adoption must replace the selected package"
        );
        ensure!(
            options.lifecycle == Lifecycle::Full && options.clusters.len() == 1,
            "provider adoption fixture requires one retained full-lifecycle cluster"
        );
        ensure!(
            options.fault.is_none(),
            "provider adoption cannot be combined with another fixture fault"
        );
        ensure!(
            options.adoption_current_planning.is_some(),
            "provider adoption requires the retained current planning digest"
        );
    } else {
        ensure!(
            options.adoption_current_planning.is_none(),
            "a retained current planning digest requires provider adoption"
        );
    }
    Ok(())
}

fn validate_postgresql_identifier(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && LocalKey::new(value).is_ok()
            && !matches!(
                value,
                "postgres" | "template0" | "template1" | "aos-ability-postgresql"
            ),
        "PostgreSQL {label} is not an admitted identifier"
    );
    Ok(())
}

fn control_fault_name(fault: &str) -> Option<&str> {
    let fault = fault.strip_prefix("postgresql-").unwrap_or(fault);
    CONTROL_FAULTS.contains(&fault).then_some(fault)
}

fn is_negative_fault(fault: Option<&str>) -> bool {
    fault.is_some_and(|fault| AUTHORITY_FAULTS.contains(&fault))
}

impl PostgresqlFixture {
    fn new(
        verified: &VerifiedAbilityPackageSet,
        selected_name: &str,
        authentication: Authentication,
    ) -> Result<Self> {
        let mut identified = verified
            .iter()
            .map(|package| {
                let document = package.package().clone();
                Ok((document.content_digest()?, document))
            })
            .collect::<Result<Vec<_>>>()?;
        identified.sort_by_key(|(digest, _)| *digest);
        let packages = identified
            .iter()
            .map(|(_, package)| package.clone())
            .collect::<Vec<_>>();
        let (selected_package, selected_document) = identified
            .iter()
            .find(|(_, package)| package.package.name.as_str() == selected_name)
            .cloned()
            .with_context(|| format!("signed PostgreSQL package {selected_name:?} is absent"))?;
        let consumer_package = identified
            .iter()
            .find(|(_, package)| {
                package.package.name.as_str() == "ability-reference-postgresql-consumer"
            })
            .map(|(digest, _)| *digest);
        if authentication == Authentication::Scram {
            ensure!(
                consumer_package.is_some(),
                "signed PostgreSQL consumer package is absent"
            );
        }

        let interface_documents = postgresql_interfaces()?;
        let interfaces = interface_documents
            .iter()
            .map(|document| {
                Ok((
                    document.interface.name.as_str().to_string(),
                    document.interface_key()?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let context = ValidationContext::new(
            BTreeSet::from([
                RequiredFeature::new("abilities-v1")?,
                RequiredFeature::new(aos_ability_model::PROVIDER_STATE_FORMAT_V1)?,
                RequiredFeature::new(aos_ability_model::PROVIDER_STATE_ADOPTION_V1)?,
            ]),
            interface_documents,
        )?;

        let mut implementations = BTreeMap::new();
        for implementation in &selected_document.implementation.providers {
            let expected = interfaces
                .get(implementation.interface.name.as_str())
                .with_context(|| {
                    format!(
                        "PostgreSQL package exports unknown interface {}",
                        implementation.interface.name
                    )
                })?;
            ensure!(
                expected == &implementation.interface,
                "PostgreSQL package interface {} differs from the fixture contract",
                implementation.interface.name
            );
            implementations.insert(
                implementation.interface.name.as_str().to_string(),
                provider_reference(implementation)?,
            );
        }
        for interface in [
            PUBLIC_INTERFACE,
            "aos.credential-delivery-effects",
            "aos.network-endpoint-effects",
            "aos.host-storage-effects",
            "aos.host-network-policy-effects",
            "aos.postgresql-effects",
        ] {
            ensure!(
                implementations.contains_key(interface),
                "PostgreSQL package omits {interface} implementation"
            );
        }

        let environment_id = EnvironmentId {
            authority: key("reference")?,
            key: key("postgresql-host")?,
            stage: ExecutionStage::Host,
        };
        let provider = instance(
            &environment_id,
            if authentication == Authentication::Trust {
                TERMINAL_PROVIDER_INSTANCE
            } else {
                PROVIDER_INSTANCE
            },
        )?;
        let terminal_provider = terminal_provider_for_package(&environment_id, selected_package)?;
        let guarantee = host_network_policy_loopback_tcp_ingress_guarantee()?;
        let mut providers = Vec::new();
        let mut terminal_implementations = BTreeMap::<String, Vec<_>>::new();
        for (package_digest, package) in &identified {
            for implementation in &package.implementation.providers {
                if matches!(
                    implementation.implementation,
                    ImplementationKind::TerminalHandler { .. }
                ) {
                    let reference = provider_reference(implementation)?;
                    let implementations = terminal_implementations
                        .entry(implementation.interface.name.as_str().to_string())
                        .or_default();
                    if !implementations.contains(&(*package_digest, reference.clone())) {
                        implementations.push((*package_digest, reference));
                    }
                }
            }
        }
        for interface in [
            "aos.credential-delivery-effects",
            "aos.network-endpoint-effects",
            "aos.host-storage-effects",
            "aos.host-network-policy-effects",
            "aos.postgresql-effects",
        ] {
            if authentication == Authentication::Trust
                && interface == "aos.credential-delivery-effects"
            {
                continue;
            }
            for (package_digest, implementation) in terminal_implementations
                .get(interface)
                .context("PostgreSQL terminal implementation inventory is incomplete")?
            {
                providers.push(ProviderInventory {
                    provider: terminal_provider_for_package(&environment_id, *package_digest)?,
                    interface: interfaces[interface].clone(),
                    implementation: implementation.clone(),
                    state: ProviderState::Available,
                    incarnation: Some(aos_ability_model::IncarnationId::new(&format!(
                        "postgresql-{}-{}",
                        interface.replace('.', "-"),
                        digest_label(*package_digest)
                    ))?),
                    guarantees: if interface == "aos.host-network-policy-effects" {
                        vec![guarantee.clone()]
                    } else {
                        Vec::new()
                    },
                });
            }
        }
        providers.sort_by(|left, right| {
            left.provider
                .cmp(&right.provider)
                .then_with(|| left.interface.cmp(&right.interface))
                .then_with(|| {
                    left.implementation
                        .descriptor
                        .cmp(&right.implementation.descriptor)
                })
        });
        let policy_revision = RevisionId(digest(40));
        let evaluator = RestrictedAbilityEvaluator::new(
            required_environment("AOS_NIX_INSTANTIATE")?,
            required_environment("AOS_PRLIMIT")?,
            required_environment("AOS_TEST_ABILITY_CACHE")?,
            AbilityEvaluationLimits::default(),
        )?;
        Ok(Self {
            context,
            environment: EnvironmentDocument {
                schema: EnvironmentDocument::SCHEMA.to_string(),
                required_features: Vec::new(),
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
            },
            packages,
            selected_package,
            selected_document,
            consumer_package,
            provider,
            terminal_provider,
            interfaces,
            implementations,
            policy_revision,
            evaluator,
        })
    }

    fn compose(mut self, clusters: &[Cluster], lifecycle: Lifecycle) -> Result<ComposedPostgresql> {
        if self.consumer_package.is_none() {
            return self.compose_terminal(clusters);
        }
        let seed = self.seed(clusters, lifecycle)?;
        let mut policies = Vec::new();
        loop {
            match RecursiveComposer::new(&self.context).compose(
                &policies,
                seed.clone(),
                self.environment.clone(),
                self.packages.clone(),
                &mut self.evaluator,
            ) {
                Ok(outcome) => {
                    let snapshot = PlanningSnapshot::from_outcome(&outcome)
                        .context("constructing PostgreSQL planning snapshot")?;
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
                                packages: self.packages.clone(),
                            },
                        )
                        .context("verifying PostgreSQL planning snapshot")?;
                    return Ok(ComposedPostgresql {
                        seed,
                        environment: self.environment,
                        desired_state: outcome.desired_state,
                        policies,
                        bindings: outcome.resolution.checked.bindings().to_vec(),
                        selected_document: self.selected_document,
                        provider: self.provider,
                        planning: Some(planning),
                    });
                }
                Err(CompositionError::PolicyRequired { desired_state, .. }) => {
                    policies.push(self.policy_for(&desired_state)?);
                }
                Err(error) => bail!("composing PostgreSQL deployment: {error:#?}"),
            }
        }
    }

    fn seed(&self, clusters: &[Cluster], lifecycle: Lifecycle) -> Result<DesiredStateDocument> {
        let environment = self.environment.content_digest()?;
        let mut instances = vec![DesiredInstance {
            instance: self.provider.clone(),
            package: self.selected_package,
            enabled: true,
            configuration: None,
        }];
        let mut child_requests = Vec::new();
        let mut contributions = Vec::new();
        if lifecycle == Lifecycle::Full {
            let consumer_package = self
                .consumer_package
                .context("credentialed fixture has no consumer package")?;
            for (index, cluster) in clusters.iter().enumerate() {
                let consumer = instance(
                    &self.environment.environment,
                    &format!("postgresql-consumer-{index:02}"),
                )?;
                let request = aos_ability_model::RequestId {
                    consumer: consumer.clone(),
                    scope: ScopePath::root(),
                    key: key("postgresql")?,
                };
                instances.push(DesiredInstance {
                    instance: consumer,
                    package: consumer_package,
                    enabled: true,
                    configuration: None,
                });
                child_requests.push(BindingRequest {
                    id: request.clone(),
                    accepted_interfaces: vec![self.interfaces[PUBLIC_INTERFACE].clone()],
                    methods: Vec::new(),
                    guarantees: Vec::new(),
                    lifetime: ResourceLifetime::Persistent,
                });
                contributions.push(Contribution {
                    request: request.clone(),
                    aggregate: AggregateId {
                        provider: self.provider.clone(),
                        group: key("postgresql")?,
                    },
                    slot: key(&cluster.database)?,
                    grant: BindingId(binding_key(&request)?),
                    value: AbilityValue::new(serde_json::json!({
                        "cluster": cluster.database,
                        "database": cluster.database,
                        "role": cluster.role,
                        "credential_version": cluster.credential_version.as_deref().context("credentialed cluster has no version")?,
                    }))?,
                });
            }
        }
        instances.sort_by(|left, right| left.instance.cmp(&right.instance));
        child_requests.sort_by(|left, right| left.id.cmp(&right.id));
        contributions.sort_by(|left, right| left.slot.cmp(&right.slot));
        Ok(DesiredStateDocument {
            schema: DesiredStateDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            environment,
            instances,
            contributions,
            child_requests,
            resources: Vec::new(),
            outputs: Vec::new(),
            controllers: Vec::new(),
        })
    }

    fn policy_for(&self, desired: &DesiredStateDocument) -> Result<ResolutionPolicyDocument> {
        let mut candidates = desired
            .child_requests
            .iter()
            .map(|request| self.candidate_for(request, desired))
            .collect::<Result<Vec<_>>>()?;
        candidates.sort_by(|left, right| left.key.cmp(&right.key));
        let mut explicit_bindings = candidates
            .iter()
            .map(|candidate| CandidateSelection {
                request: candidate.request.clone(),
                candidate: candidate.key.clone(),
            })
            .collect::<Vec<_>>();
        explicit_bindings.sort_by(|left, right| left.request.cmp(&right.request));

        let mut enabled_providers = desired
            .instances
            .iter()
            .filter(|desired| desired.enabled && desired.instance == self.provider)
            .map(|_| EnabledProviderSelection {
                instance: self.provider.clone(),
                interface: self.interfaces[PUBLIC_INTERFACE].clone(),
                implementation: self.implementations[PUBLIC_INTERFACE].clone(),
                provider_grant: AuthorityGrant {
                    principal: self.provider.clone(),
                    methods: Vec::new(),
                    contributions: Vec::new(),
                    resources: provider_resource_permissions(desired, &self.provider),
                },
                policy_revision: self.policy_revision,
                lifetime: ResourceLifetime::Persistent,
            })
            .collect::<Vec<_>>();
        enabled_providers.sort_by(|left, right| left.instance.cmp(&right.instance));
        Ok(ResolutionPolicyDocument {
            schema: ResolutionPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
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

    fn candidate_for(
        &self,
        request: &BindingRequest,
        desired: &DesiredStateDocument,
    ) -> Result<BindingCandidate> {
        let interface = request
            .accepted_interfaces
            .first()
            .context("PostgreSQL request has no accepted interface")?
            .clone();
        let terminal = interface.name.as_str() != PUBLIC_INTERFACE;
        let candidate_provider = if terminal {
            self.terminal_provider.clone()
        } else {
            self.provider.clone()
        };
        let resources = if terminal {
            terminal_resource_permissions(
                desired,
                &self.provider,
                interface.name.as_str(),
                request,
            )?
        } else {
            Vec::new()
        };
        let contributions = if terminal {
            Vec::new()
        } else {
            let matches = desired
                .contributions
                .iter()
                .filter(|contribution| contribution.request == request.id)
                .collect::<Vec<_>>();
            let [contribution] = matches.as_slice() else {
                bail!("PostgreSQL request has {} contributions", matches.len());
            };
            vec![ContributionPermission {
                aggregate: contribution.aggregate.clone(),
                slot: contribution.slot.clone(),
            }]
        };
        let implementation = self
            .implementations
            .get(interface.name.as_str())
            .cloned()
            .with_context(|| {
                format!("PostgreSQL package omits {} implementation", interface.name)
            })?;
        Ok(BindingCandidate {
            key: binding_key(&request.id)?,
            request: request.id.clone(),
            interface,
            provider: candidate_provider.clone(),
            provider_package: self.selected_package,
            implementation,
            caller_grant: AuthorityGrant {
                principal: request.id.consumer.clone(),
                methods: request.methods.clone(),
                contributions,
                resources: resources.clone(),
            },
            provider_grant: AuthorityGrant {
                principal: candidate_provider,
                methods: Vec::new(),
                contributions: Vec::new(),
                resources: Vec::new(),
            },
            guarantees: request.guarantees.clone(),
            policy_revision: self.policy_revision,
            lifetime: request.lifetime,
            mediation_allowed: true,
            exclusive_resources: Vec::new(),
        })
    }

    fn compose_terminal(self, clusters: &[Cluster]) -> Result<ComposedPostgresql> {
        let [cluster] = clusters else {
            bail!("direct trust PostgreSQL fixture requires exactly one cluster");
        };
        let resource = ResourceId {
            provider: self.provider.clone(),
            key: key(&format!("{}-postgresql", cluster.database))?,
        };
        let request = BindingRequest {
            id: aos_ability_model::RequestId {
                consumer: self.provider.clone(),
                scope: ScopePath::root(),
                key: key("postgresql-terminal")?,
            },
            accepted_interfaces: vec![self.interfaces["aos.postgresql-effects"].clone()],
            methods: ["materialize", "observe", "restart", "start", "stop"]
                .into_iter()
                .map(key)
                .collect::<Result<Vec<_>>>()?,
            guarantees: Vec::new(),
            lifetime: ResourceLifetime::Persistent,
        };
        let revision = RevisionId(Sha256Digest::of_canonical(
            "aos.ability.postgresql-terminal-trust-fixture/v1",
            &serde_json::json!({
                "cluster": cluster.database,
                "configuration": cluster.configuration,
                "database": cluster.database,
                "role": cluster.role,
            }),
        )?);
        let environment_digest = self.environment.content_digest()?;
        let seed = DesiredStateDocument {
            schema: DesiredStateDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            environment: environment_digest,
            instances: vec![DesiredInstance {
                instance: self.provider.clone(),
                package: self.selected_package,
                enabled: true,
                configuration: None,
            }],
            contributions: Vec::new(),
            child_requests: vec![request.clone()],
            resources: vec![ResourceRevision {
                resource: resource.clone(),
                revision,
            }],
            outputs: Vec::new(),
            controllers: Vec::new(),
        };
        let candidate = self.candidate_for(&request, &seed)?;
        let binding = Binding {
            id: BindingId(candidate.key),
            request: request.id,
            interface: candidate.interface,
            provider: candidate.provider,
            provider_package: Some(candidate.provider_package),
            implementation: candidate.implementation,
            source: BindingSource::SoleEligible,
            caller_grant: candidate.caller_grant,
            provider_grant: candidate.provider_grant,
            guarantees: candidate.guarantees,
            policy_revision: candidate.policy_revision,
            lifetime: candidate.lifetime,
            mediation_allowed: candidate.mediation_allowed,
        };
        Ok(ComposedPostgresql {
            seed: seed.clone(),
            environment: self.environment,
            desired_state: seed,
            policies: Vec::new(),
            bindings: vec![binding],
            selected_document: self.selected_document,
            provider: self.provider,
            planning: None,
        })
    }
}

fn provider_resource_permissions(
    desired: &DesiredStateDocument,
    provider: &InstanceId,
) -> Vec<ResourcePermission> {
    desired
        .resources
        .iter()
        .filter(|resource| resource.resource.provider == *provider)
        .map(|resource| ResourcePermission {
            resource: resource.resource.clone(),
            access: AccessMode::ExclusiveWrite,
            operations: Vec::new(),
        })
        .collect()
}

fn terminal_resource_permissions(
    desired: &DesiredStateDocument,
    provider: &InstanceId,
    interface: &str,
    request: &BindingRequest,
) -> Result<Vec<ResourcePermission>> {
    let suffix = match interface {
        "aos.credential-delivery-effects" => "credential",
        "aos.network-endpoint-effects" => "endpoint",
        "aos.host-storage-effects" => "storage",
        "aos.host-network-policy-effects" => "network-policy",
        "aos.postgresql-effects" => "postgresql",
        _ => bail!("unsupported PostgreSQL terminal interface {interface:?}"),
    };
    Ok(desired
        .resources
        .iter()
        .filter(|resource| {
            resource.resource.provider == *provider
                && resource
                    .resource
                    .key
                    .as_str()
                    .ends_with(&format!("-{suffix}"))
        })
        .map(|resource| ResourcePermission {
            resource: resource.resource.clone(),
            access: AccessMode::ExclusiveWrite,
            operations: request.methods.clone(),
        })
        .collect())
}

fn postgresql_interfaces() -> Result<Vec<InterfaceDocument>> {
    let mut interfaces = vec![
        postgresql_public_interface()?,
        credential_delivery_effects_interface()?,
        network_endpoint_interface()?,
        host_storage_interface()?,
        host_network_policy_interface()?,
        postgresql_effects_interface()?,
    ];
    interfaces.sort_by(|left, right| left.interface.name.cmp(&right.interface.name));
    Ok(interfaces)
}

fn postgresql_public_interface() -> Result<InterfaceDocument> {
    let cluster = ValueSchema::String {
        max_length: 128,
        syntax: Some(StringSyntax::LocalKeyV1),
    };
    let identifier = ValueSchema::String {
        max_length: 63,
        syntax: Some(StringSyntax::LocalKeyV1),
    };
    let revision = ValueSchema::String {
        max_length: 71,
        syntax: None,
    };
    let document = InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: InterfaceName::new(PUBLIC_INTERFACE)?,
            abi: NonZeroU32::new(1).context("PostgreSQL interface ABI is zero")?,
            request: ValueSchema::Record {
                fields: BTreeMap::from([
                    (key("cluster")?, cluster),
                    (key("credential_version")?, revision),
                    (key("database")?, identifier.clone()),
                    (key("role")?, identifier),
                ]),
                optional_fields: Vec::new(),
            },
            configuration: None,
            outputs: BTreeMap::from([(
                key("clusters")?,
                OutputDescriptor {
                    schema: ValueSchema::Map {
                        key: StringConstraint {
                            max_length: 128,
                            syntax: Some(StringSyntax::LocalKeyV1),
                        },
                        value: Box::new(ValueSchema::ResourceReference),
                        max_entries: 64,
                    },
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
    };
    ensure!(
        document.interface_key()?.descriptor == Sha256Digest::parse(PUBLIC_DESCRIPTOR)?,
        "PostgreSQL public fixture descriptor differs from signed package contract"
    );
    Ok(document)
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

fn platform_policy(composed: &ComposedPostgresql) -> CurrentPlatformPolicyDocument {
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
    CurrentPlatformPolicyDocument {
        schema: CurrentPlatformPolicyDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        policy_revision: composed.environment.policy_revision,
        bindings,
    }
}

fn required_environment(name: &str) -> Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .with_context(|| format!("reading required environment variable {name}"))
}

fn instance(environment: &EnvironmentId, name: &str) -> Result<InstanceId> {
    Ok(InstanceId {
        environment: environment.clone(),
        key: key(name)?,
    })
}

fn terminal_provider_for_package(
    environment: &EnvironmentId,
    package: Sha256Digest,
) -> Result<InstanceId> {
    instance(
        environment,
        &format!("postgresql-handler-{}", package.hex()),
    )
}

fn digest_label(digest: Sha256Digest) -> String {
    digest.hex()[..12].to_string()
}

fn binding_key(request: &aos_ability_model::RequestId) -> Result<LocalKey> {
    key(&format!("bind-{}-{}", request.consumer.key, request.key))
}

fn key(value: &str) -> Result<LocalKey> {
    LocalKey::new(value).map_err(anyhow::Error::from)
}

fn digest(tag: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([tag; 32])
}

fn postgresql_native_resource_map(
    composed: &ComposedPostgresql,
    clusters: &[Cluster],
) -> Result<NativeResourceMap> {
    let control =
        package_artifact_with_entry(&composed.selected_document, "bin/postgresql-control")?;
    let postgresql = package_artifact_with_entry(&composed.selected_document, "bin/postgres")?;
    let mut entries = Vec::new();
    for revision in &composed.desired_state.resources {
        let resource_key = revision.resource.key.as_str();
        let (cluster_name, request_key, qualification) =
            if let Some(cluster) = resource_key.strip_suffix("-credential") {
                (
                    cluster,
                    "credential",
                    NativeResourceQualification::CredentialDelivery {
                        view: resource_key.to_string(),
                    },
                )
            } else if let Some(cluster) = resource_key.strip_suffix("-endpoint") {
                (
                    cluster,
                    "endpoint",
                    NativeResourceQualification::NetworkEndpoint {
                        address: "127.0.0.1".to_string(),
                        port: 0,
                        transport: "tcp".to_string(),
                    },
                )
            } else if let Some(cluster) = resource_key.strip_suffix("-network-policy") {
                (
                    cluster,
                    "network-policy",
                    NativeResourceQualification::HostNetworkPolicy {
                        policy: resource_key.to_string(),
                    },
                )
            } else if let Some(cluster) = resource_key.strip_suffix("-storage") {
                (
                    cluster,
                    "storage",
                    NativeResourceQualification::HostStorage {
                        cluster: cluster.to_string(),
                        purpose: "database".to_string(),
                    },
                )
            } else if let Some(cluster_name) = resource_key.strip_suffix("-postgresql") {
                let cluster = clusters
                    .iter()
                    .find(|candidate| candidate.database == cluster_name)
                    .with_context(|| {
                        format!("PostgreSQL resource names unknown cluster {cluster_name:?}")
                    })?;
                (
                    cluster_name,
                    "postgresql-terminal",
                    NativeResourceQualification::Postgresql {
                        cluster: cluster_name.to_string(),
                        database: cluster.database.clone(),
                        role: cluster.role.clone(),
                        control: control.clone(),
                        postgresql: postgresql.clone(),
                        postgresql_major: 18,
                    },
                )
            } else {
                bail!("unexpected PostgreSQL resource key {resource_key:?}");
            };
        ensure!(
            clusters
                .iter()
                .any(|cluster| cluster.database == cluster_name),
            "resource names unknown PostgreSQL cluster {cluster_name:?}"
        );
        let binding = find_binding(composed, request_key)?;
        entries.push(NativeResourceMapping {
            resource: revision.resource.clone(),
            revision: revision.revision,
            owner_package: binding
                .provider_package
                .context("PostgreSQL terminal binding is not package-backed")?,
            binding: binding.id.clone(),
            implementation: binding.implementation.clone(),
            qualification,
        });
    }
    NativeResourceMap::new(composed.desired_state.content_digest()?, entries)
}

fn find_binding<'a>(composed: &'a ComposedPostgresql, request_key: &str) -> Result<&'a Binding> {
    let matches = composed
        .bindings
        .iter()
        .filter(|binding| {
            binding.request.consumer == composed.provider
                && binding.request.key.as_str() == request_key
        })
        .collect::<Vec<_>>();
    let [binding] = matches.as_slice() else {
        bail!(
            "PostgreSQL plan has {} bindings for request {request_key:?}",
            matches.len()
        );
    };
    Ok(binding)
}

fn package_artifact_with_entry(
    package: &PackageDocument,
    entry: &str,
) -> Result<ArtifactReference> {
    let mut artifacts = package.artifacts.clone();
    artifacts.push(package.package.payload.clone());
    artifacts.extend(
        package
            .implementation
            .providers
            .iter()
            .map(|provider| provider.artifact.clone()),
    );
    artifacts.sort_by_key(|artifact| artifact.content);
    artifacts.dedup_by(|left, right| left == right);
    let matches = artifacts
        .into_iter()
        .filter(|artifact| {
            let root = Path::new(&artifact.store_path);
            let path = root.join(entry);
            fs::canonicalize(path)
                .ok()
                .is_some_and(|canonical| canonical.starts_with(root))
        })
        .collect::<Vec<_>>();
    let [artifact] = matches.as_slice() else {
        bail!(
            "signed PostgreSQL package has {} direct artifacts containing {entry:?}",
            matches.len()
        );
    };
    Ok(artifact.clone())
}

fn apply_negative_fault(
    fault: Option<&str>,
    native_resources: &mut NativeResourceMap,
    policies: &mut [ResolutionPolicyDocument],
) -> Result<()> {
    let Some(fault) = fault.filter(|fault| AUTHORITY_FAULTS.contains(fault)) else {
        return Ok(());
    };
    match fault {
        "credential-authority"
        | "endpoint-authority"
        | "storage-authority"
        | "network-policy-authority"
        | "postgresql-authority" => {
            let expected_kind = match fault {
                "credential-authority" => "credential-delivery",
                "endpoint-authority" => "network-endpoint",
                "storage-authority" => "host-storage",
                "network-policy-authority" => "host-network-policy",
                "postgresql-authority" => "postgresql",
                _ => return Err(anyhow::anyhow!("unknown authority fault {fault:?}")),
            };
            let mapping = native_resources
                .entries
                .iter_mut()
                .find(|mapping| qualification_kind(&mapping.qualification) == expected_kind)
                .with_context(|| format!("negative fixture has no {expected_kind} mapping"))?;
            mapping.owner_package = digest(250);
        }
        "forged-guarantee" => {
            let candidate = policies
                .iter_mut()
                .flat_map(|policy| &mut policy.candidates)
                .find(|candidate| {
                    candidate.interface.name.as_str() == "aos.host-network-policy-effects"
                })
                .context("negative fixture has no network-policy candidate")?;
            let guarantee = candidate
                .guarantees
                .first_mut()
                .context("negative network-policy candidate has no guarantee")?;
            guarantee.descriptor = digest(251);
        }
        "forged-retained-adoption" => {
            let mapping = native_resources
                .entries
                .iter_mut()
                .find(|mapping| {
                    matches!(
                        mapping.qualification,
                        NativeResourceQualification::Postgresql { .. }
                    )
                })
                .context("negative fixture has no PostgreSQL mapping")?;
            mapping.revision = RevisionId(digest(252));
        }
        _ => bail!("unknown PostgreSQL negative fault {fault:?}"),
    }
    Ok(())
}

fn qualification_kind(qualification: &NativeResourceQualification) -> &'static str {
    match qualification {
        NativeResourceQualification::AbImageRollout { .. } => "ab-image-rollout",
        NativeResourceQualification::ManagedConfiguration { .. } => "managed-configuration",
        NativeResourceQualification::SystemdService { .. } => "systemd-service",
        NativeResourceQualification::NginxValidation { .. } => "nginx-validation",
        NativeResourceQualification::KubernetesObject { .. } => "kubernetes-object",
        NativeResourceQualification::CredentialDelivery { .. } => "credential-delivery",
        NativeResourceQualification::NetworkEndpoint { .. } => "network-endpoint",
        NativeResourceQualification::HostStorage { .. } => "host-storage",
        NativeResourceQualification::HostNetworkPolicy { .. } => "host-network-policy",
        NativeResourceQualification::Postgresql { .. } => "postgresql",
    }
}

fn stage_credentials(options: &GenerateOptions, provider: &InstanceId) -> Result<()> {
    let staging_root = options.authority_output.join("credential-sources");
    fs::create_dir_all(&staging_root)?;
    let test_only = options.output.join("test-only");
    fs::create_dir_all(&test_only)?;
    for (index, cluster) in options.clusters.iter().enumerate() {
        let version = cluster
            .credential_version
            .as_deref()
            .context("credentialed cluster has no credential version")?;
        let resource = ResourceId {
            provider: provider.clone(),
            key: key(&format!("{}-credential", cluster.database))?,
        };
        let resource_digest =
            Sha256Digest::of_canonical("aos.ability.native-host-resource/v1", &resource)?.hex();
        let source_digest = Sha256Digest::of_canonical(
            "aos.ability.credential-source-key/v1",
            &CredentialSourceKey {
                resource: &resource,
                version,
            },
        )?
        .hex();
        let secret = deterministic_secret(cluster)?;
        let production_secret =
            format!("{CREDENTIAL_SOURCE_ROOT}/{resource_digest}/{source_digest}.secret");
        let record = CredentialSourceRecord {
            schema: "aos.ability.credential-source/v1".to_string(),
            resource,
            version: version.to_string(),
            source_path: production_secret,
            content_digest: Sha256Digest::of_bytes(secret.as_bytes()),
        };
        let cluster_staging = staging_root.join(&resource_digest);
        fs::create_dir_all(&cluster_staging)?;
        write_private_file(
            &cluster_staging.join(format!("{source_digest}.json")),
            &aos_contract::canonical::to_vec(&record)?,
        )?;
        write_private_file(
            &cluster_staging.join(format!("{source_digest}.secret")),
            secret.as_bytes(),
        )?;
        let test_name = if index == 0 {
            "credential.secret".to_string()
        } else {
            format!("credential-{resource_digest}.secret")
        };
        write_private_file(&test_only.join(test_name), secret.as_bytes())?;
    }
    Ok(())
}

fn deterministic_secret(cluster: &Cluster) -> Result<String> {
    let seed = serde_json::json!({
        "configuration": cluster.configuration,
        "database": cluster.database,
        "role": cluster.role,
        "version": cluster.credential_version,
    });
    let digest = Sha256Digest::of_canonical("aos.ability.postgresql-fixture-secret/v1", &seed)?;
    Ok(format!("aos-pg-fixture-{}\n", &digest.hex()[..32]))
}

fn write_activation(
    output: &Path,
    desired: aos_package::config_eval::materialize::PinnedAbilitySidecar,
    policy: aos_package::config_eval::materialize::PinnedAbilitySidecar,
) -> Result<()> {
    let activation = serde_json::json!({
        "schema": "aos.ability.activation-input/v1",
        "required_features": [
            "abilities-v1",
            "ability-effects-v1",
            "native-platform-policy-v1",
            "native-resource-map-v2"
        ],
        "desired_state": desired,
        "authenticated_policy_set": policy,
        "packages": [],
    });
    fs::write(
        output.join("activation.json"),
        aos_contract::canonical::to_vec(&activation)?,
    )?;
    Ok(())
}

fn write_provider_description(
    options: &GenerateOptions,
    composed: &ComposedPostgresql,
    selected_name: &str,
) -> Result<()> {
    let resources = composed
        .desired_state
        .resources
        .iter()
        .map(|revision| (revision.resource.key.as_str(), &revision.resource))
        .collect::<BTreeMap<_, _>>();
    let document = serde_json::json!({
        "schema": "aos.ability.postgresql-fixture/v1",
        "authentication": match options.authentication {
            Authentication::Scram => "scram",
            Authentication::Trust => "trust",
        },
        "clusters": options.clusters.iter().map(|cluster| serde_json::json!({
            "cluster": cluster.database,
            "database": cluster.database,
            "role": cluster.role,
            "credential_version": cluster.credential_version,
        })).collect::<Vec<_>>(),
        "lifecycle": match options.lifecycle {
            Lifecycle::Full => "full",
            Lifecycle::Remove => "remove",
        },
        "provider": composed.provider,
        "resources": resources,
        "selected_package": selected_name,
    });
    fs::write(
        options.output.join("provider.json"),
        aos_contract::canonical::to_vec(&document)?,
    )?;
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("creating protected fixture file {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Provisions staged PostgreSQL policy and credential authority.
///
/// # Errors
///
/// Returns an error when staged records are noncanonical, their protected
/// secret digests or final paths differ, or immutable authority already exists
/// with different bytes or metadata.
pub(super) fn provision_authority(arguments: &[String]) -> Result<()> {
    if arguments.len() != 1 {
        bail!("usage: aos-release-fleet-fixture postgresql-authority-provision AUTHORITY_STAGING");
    }
    let staging = Path::new(&arguments[0]);
    let policy = staging.join("policy");
    let policy_records = regular_files(&policy)?;
    let [policy_record] = policy_records.as_slice() else {
        bail!(
            "PostgreSQL authority staging has {} policy records",
            policy_records.len()
        );
    };
    super::ability_activation_fixture::provision_authority(&[policy_record
        .to_string_lossy()
        .into_owned()])?;

    provision_credential_authority(staging)
}

/// Provisions credential source records staged by a native fixture.
///
/// # Errors
///
/// Returns an error when a staged source is unsafe, noncanonical, or differs
/// from an immutable source already installed under the protected runtime root.
pub(super) fn provision_credential_authority(staging: &Path) -> Result<()> {
    let credential_staging = staging.join("credential-sources");
    if !credential_staging.try_exists()? {
        return Ok(());
    }
    ensure_protected_directory(Path::new(CREDENTIAL_SOURCE_ROOT), false)?;
    for resource_directory in strict_directories(&credential_staging)? {
        let resource_digest = canonical_hex_name(&resource_directory, "credential resource")?;
        let destination = Path::new(CREDENTIAL_SOURCE_ROOT).join(&resource_digest);
        ensure_protected_directory(&destination, true)?;
        let files = regular_files(&resource_directory)?;
        let records = files
            .iter()
            .filter(|path| {
                path.extension().and_then(|extension| extension.to_str()) == Some("json")
            })
            .collect::<Vec<_>>();
        for record_path in records {
            provision_credential_source(record_path, &resource_digest, &destination)?;
        }
    }
    Ok(())
}

fn provision_credential_source(
    record_path: &Path,
    resource_digest: &str,
    destination: &Path,
) -> Result<()> {
    let stem = record_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context("credential source record has no UTF-8 stem")?;
    ensure!(
        canonical_hex(stem),
        "credential source key is not canonical"
    );
    let bytes = read_protected_staging_file(record_path, MAX_CREDENTIAL_RECORD_BYTES)?;
    let record: CredentialSourceRecord =
        aos_contract::canonical::from_slice(&bytes, "credential source record")?;
    ensure!(
        aos_contract::canonical::to_vec(&record)? == bytes,
        "credential source record is not exact canonical JSON"
    );
    let expected_resource =
        Sha256Digest::of_canonical("aos.ability.native-host-resource/v1", &record.resource)?.hex();
    ensure!(
        expected_resource == resource_digest,
        "credential source resource directory differs from its record"
    );
    let expected_source = Sha256Digest::of_canonical(
        "aos.ability.credential-source-key/v1",
        &CredentialSourceKey {
            resource: &record.resource,
            version: &record.version,
        },
    )?
    .hex();
    ensure!(
        expected_source == stem,
        "credential source key differs from its record"
    );
    let secret_path = record_path.with_extension("secret");
    let secret = read_protected_staging_file(&secret_path, MAX_CREDENTIAL_SECRET_BYTES)?;
    ensure!(
        !secret.is_empty()
            && secret.len() <= MAX_CREDENTIAL_SECRET_BYTES as usize
            && Sha256Digest::of_bytes(&secret) == record.content_digest,
        "credential source secret differs from its record"
    );
    let final_secret = destination.join(format!("{stem}.secret"));
    ensure!(
        record.source_path == final_secret.to_string_lossy(),
        "credential source record names another final secret path"
    );
    install_immutable(&final_secret, &secret)?;
    install_immutable(&destination.join(format!("{stem}.json")), &bytes)?;
    Ok(())
}

fn regular_files(directory: &Path) -> Result<Vec<PathBuf>> {
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("reading fixture directory {}", directory.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "fixture path {} is not a direct directory",
        directory.display()
    );

    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "fixture directory {} contains a non-file entry",
            directory.display()
        );
        paths.push(path);
    }
    paths.sort();
    Ok(paths)
}

fn strict_directories(directory: &Path) -> Result<Vec<PathBuf>> {
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("reading fixture directory {}", directory.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "fixture path {} is not a direct directory",
        directory.display()
    );

    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
            "fixture directory {} contains a non-directory entry",
            directory.display()
        );
        paths.push(path);
    }
    paths.sort();
    Ok(paths)
}

fn canonical_hex_name(path: &Path, label: &str) -> Result<String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{label} has no UTF-8 name"))?;
    ensure!(canonical_hex(name), "{label} is not canonical");
    Ok(name.to_string())
}

fn canonical_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn ensure_protected_directory(path: &Path, leaf: bool) -> Result<()> {
    let parent = path
        .parent()
        .context("protected authority directory has no parent")?;
    ensure_trusted_directory_chain(parent)?;
    if !path.try_exists()? {
        if leaf {
            fs::create_dir(path)?;
        } else {
            fs::create_dir_all(path)?;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o777 == 0o700,
        "protected authority directory {} has invalid metadata",
        path.display()
    );
    Ok(())
}

fn ensure_trusted_directory_chain(path: &Path) -> Result<()> {
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        if !current.try_exists()? {
            fs::create_dir(&current)?;
            fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
        }
        let metadata = fs::symlink_metadata(&current)?;
        ensure!(
            metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o022 == 0,
            "authority parent {} is not a trusted root directory",
            current.display()
        );
    }
    Ok(())
}

fn read_protected_staging_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.len() <= max_bytes,
        "credential staging file {} has invalid metadata or size",
        path.display()
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= max_bytes,
        "credential staging file {} exceeds its size bound",
        path.display()
    );
    Ok(bytes)
}

fn install_immutable(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 <= MAX_CREDENTIAL_RECORD_BYTES,
        "authority file exceeds its installation bound"
    );
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let installed = read_protected_staging_file(path, MAX_CREDENTIAL_RECORD_BYTES)?;
            ensure!(
                installed == bytes,
                "existing authority file {} differs from staged authority",
                path.display()
            );
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.len() == bytes.len() as u64,
        "new authority file {} has invalid metadata",
        path.display()
    );
    File::open(
        path.parent()
            .context("authority destination has no parent directory")?,
    )?
    .sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_interface_matches_signed_identifier_bounds_and_descriptor() {
        let document = postgresql_public_interface().expect("public interface constructs");
        assert_eq!(
            document
                .interface_key()
                .expect("public interface identifies")
                .descriptor,
            Sha256Digest::parse(PUBLIC_DESCRIPTOR).expect("descriptor parses")
        );
        let ValueSchema::Record {
            fields,
            optional_fields,
        } = document.interface.request
        else {
            panic!("public PostgreSQL request must be a record");
        };
        assert!(optional_fields.is_empty());
        assert!(matches!(
            fields.get(&key("cluster").expect("cluster key")),
            Some(ValueSchema::String {
                max_length: 128,
                ..
            })
        ));
        for field in ["database", "role"] {
            assert!(matches!(
                fields.get(&key(field).expect("identifier key")),
                Some(ValueSchema::String { max_length: 63, .. })
            ));
        }
    }

    #[test]
    fn terminal_interface_keeps_closed_optional_credential_encoding() {
        let document = postgresql_effects_interface().expect("terminal interface constructs");
        let ValueSchema::Record {
            fields,
            optional_fields,
        } = document.interface.request
        else {
            panic!("terminal PostgreSQL request must be a record");
        };
        assert!(optional_fields.is_empty());
        assert!(matches!(
            fields.get(&key("credential_view").expect("credential key")),
            Some(ValueSchema::Optional { .. })
        ));
    }
}
