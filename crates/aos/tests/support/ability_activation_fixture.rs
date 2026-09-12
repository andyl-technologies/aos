//! Authenticated sidecar generation for the reference ability VM.
//!
//! This fixture starts from the signed registry selected by the system APM
//! configuration. It verifies the exact ability companions and their retained
//! artifacts, runs the production recursive planner, and only then writes the
//! desired and policy documents used by the VM activation path.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::num::NonZeroU32;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::builtin::{
    credential_delivery_effects_interface, host_network_policy_interface,
    host_network_policy_loopback_tcp_egress_guarantee,
    host_network_policy_loopback_tcp_ingress_guarantee, host_storage_interface,
    network_endpoint_interface,
};
use aos_ability_model::document::{
    Contribution, DesiredInstance, FreshnessCondition, PlatformIdentity, ProviderInventory,
    ProviderState,
};
use aos_ability_model::{
    AbilityValue, AccessMode, AggregateId, Binding, BindingId, BindingRequest,
    ContributionPermission, CredentialAction, DesiredStateDocument, EnvironmentDocument,
    EnvironmentId, ExecutionStage, ImplementationKind, InstanceId, InterfaceDescriptor,
    InterfaceDocument, InterfaceKey, InterfaceName, LifecycleSemantics, LocalKey, MethodDescriptor,
    OperationFamily, OutcomeSemantics, OutputDescriptor, PackageDocument, ProviderImplementation,
    ProviderImplementationReference, RequiredFeature, ResourceId, ResourceLifetime,
    ResourcePermission, RevisionId, ScopePath, ServiceAction, StringConstraint, StringSyntax,
    ValuePhase, ValueSchema, ValueVisibility, VersionedDocument,
};
use aos_ability_plan::{
    BindingCandidate, CandidateSelection, CompositionError, EnabledProviderSelection,
    RecursiveComposer, ResolutionPolicyDocument,
};
use aos_ability_validate::ValidationContext;
use aos_contract::Sha256Digest;
use aos_core::nix::store::NixCli;
use aos_package::ability_package::VerifiedAbilityPackageSet;
use aos_package::config::ApmConfig;
use aos_package::config_eval::ability::{AbilityEvaluationLimits, RestrictedAbilityEvaluator};
use aos_package::config_eval::ability_activation::{
    ActivationDesiredInputDocument, AuthenticatedPolicySetDocument,
};
use aos_package::config_eval::ability_policy::CurrentPlatformPolicyDocument;
use aos_package::config_eval::ability_policy_authority::{
    OperatorPolicyAuthorityRecord, OperatorPolicyAuthorityStore,
};
use aos_package::config_eval::materialize::PinnedAbilitySidecar;
use aos_package::config_eval::native_resource_map::{
    HostStorageLifetime, HostStorageOwner, NativeHttpConsumerObservation, NativeOutputLocator,
    NativeResourceMap, NativeResourceMapping, NativeResourceQualification,
};
use aos_package::config_eval::runtime::{RuntimeResolution, resolve_runtime};
use aos_package::platform::native_platform;
use aos_package::registry::RegistrySet;
use aos_package::types::ProfileScope;
use serde::{Deserialize, Serialize};

const CREDENTIAL_SOURCE_ROOT: &str = "/var/lib/aos/ability-runtime/credential-sources";
const MAX_TLS_BUNDLE_BYTES: u64 = 64 * 1024;

const PACKAGE_NAMES: [&str; 5] = [
    "ability-reference-nginx-consumer",
    "ability-reference-nginx",
    "ability-reference-managed-configuration",
    "ability-reference-credential",
    "ability-reference-systemd",
];

struct ReferenceFixture {
    context: ValidationContext,
    environment: EnvironmentDocument,
    packages: Vec<PackageDocument>,
    consumer_package: Sha256Digest,
    nginx_package: Sha256Digest,
    lower_packages: BTreeMap<String, Sha256Digest>,
    terminal_packages: BTreeMap<String, Sha256Digest>,
    implementations: BTreeMap<String, ProviderImplementationReference>,
    terminal_implementations: BTreeMap<String, ProviderImplementationReference>,
    interfaces: BTreeMap<String, InterfaceKey>,
    policy_revision: RevisionId,
    evaluator: RestrictedAbilityEvaluator,
}

struct ComposedReference {
    seed: DesiredStateDocument,
    environment: EnvironmentDocument,
    desired_state: DesiredStateDocument,
    policies: Vec<ResolutionPolicyDocument>,
    bindings: Vec<aos_ability_model::Binding>,
}

#[derive(Clone, Debug)]
struct ReferenceTls {
    version: String,
    bundle: PathBuf,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReferenceLifecycle {
    Full,
    RemovePrimaryContributor,
    RemoveMainContributors,
    DisableMain,
}

impl ReferenceLifecycle {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "full" => Ok(Self::Full),
            "remove-primary-contributor" => Ok(Self::RemovePrimaryContributor),
            "remove-main-contributors" => Ok(Self::RemoveMainContributors),
            "disable-main" => Ok(Self::DisableMain),
            _ => bail!("unknown reference lifecycle scenario {value:?}"),
        }
    }

    const fn includes_primary(self) -> bool {
        matches!(self, Self::Full)
    }

    const fn includes_main_contributors(self) -> bool {
        matches!(self, Self::Full | Self::RemovePrimaryContributor)
    }

    const fn enables_main(self) -> bool {
        !matches!(self, Self::DisableMain)
    }
}

/// Generates one immutable activation-input descriptor for the reference VM.
///
/// Arguments are `OUTPUT PRIMARY_RESPONSE SECONDARY_RESPONSE
/// --operator-authority-output AUTHORITY_DIR [--lifecycle SCENARIO]`, where the
/// responses become the bodies for `alpha.example` and `gamma.example`.
/// `SCENARIO` selects a bounded removal or disable transition for lifecycle
/// qualification. The generated descriptor is written to
/// `OUTPUT/activation.json` and names two fixed-output sidecars added to the
/// local Nix store. The separate authority directory receives the explicit
/// operator anchor that the VM provisions.
///
/// # Errors
///
/// Returns an error when registry package authentication, restricted Nix
/// evaluation, planning, native qualification, or sidecar retention fails.
pub(super) fn generate(arguments: &[String]) -> Result<()> {
    if arguments.len() < 5
        || arguments[3] != "--operator-authority-output"
        || (arguments.len() - 5) % 2 != 0
    {
        bail!(
            "usage: aos-release-fleet-fixture ability-activation OUTPUT PRIMARY_RESPONSE SECONDARY_RESPONSE --operator-authority-output AUTHORITY_DIR [--lifecycle SCENARIO] [--tls-version VERSION --tls-bundle PATH]"
        );
    }
    let output = Path::new(&arguments[0]);
    let primary_response = &arguments[1];
    let secondary_response = &arguments[2];
    let authority_output = Path::new(&arguments[4]);
    let mut lifecycle = ReferenceLifecycle::Full;
    let mut tls_version = None;
    let mut tls_bundle = None;
    for option in arguments[5..].chunks_exact(2) {
        match option[0].as_str() {
            "--lifecycle" => lifecycle = ReferenceLifecycle::parse(&option[1])?,
            "--tls-version" => tls_version = Some(option[1].clone()),
            "--tls-bundle" => tls_bundle = Some(PathBuf::from(&option[1])),
            unknown => bail!("unknown reference activation option {unknown:?}"),
        }
    }
    let tls = match (tls_version, tls_bundle) {
        (Some(version), Some(bundle)) => {
            let parsed_version =
                Sha256Digest::parse(&version).context("parsing TLS credential version")?;
            ensure!(
                parsed_version.to_string() == version,
                "TLS credential version must be a canonical SHA-256 digest"
            );
            let metadata = fs::symlink_metadata(&bundle)
                .with_context(|| format!("reading TLS bundle metadata {}", bundle.display()))?;
            ensure!(
                metadata.is_file() && metadata.len() > 0 && metadata.len() <= MAX_TLS_BUNDLE_BYTES,
                "TLS bundle must be a nonempty regular file no larger than {MAX_TLS_BUNDLE_BYTES} bytes"
            );
            Some(ReferenceTls { version, bundle })
        }
        (None, None) => None,
        _ => bail!("TLS credential version and bundle must be provided together"),
    };
    ensure!(
        authority_output != output,
        "operator authority output must be separate from the activation descriptor output"
    );
    ensure!(
        [primary_response, secondary_response]
            .into_iter()
            .all(|response| {
                !response.is_empty()
                    && response.len() <= 256
                    && response
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._:/ ".contains(&byte))
            }),
        "a reference response is outside the fixture's safe value subset"
    );

    fs::create_dir_all(output)
        .with_context(|| format!("creating ability fixture output {}", output.display()))?;
    let (_runtime, packages) = load_verified_packages()?;
    let fixture = ReferenceFixture::new(&packages)?;
    let composed = fixture.compose(
        primary_response,
        secondary_response,
        lifecycle,
        tls.as_ref(),
    )?;

    if let Some(tls) = &tls {
        stage_tls_credentials(authority_output, &composed, tls)?;
    }

    let native_resource_map = reference_native_resource_map(&composed)?;
    let platform_policy = reference_platform_policy(&composed);
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
        .context("encoding canonical reference activation input")?;
    fs::write(output.join("activation.json"), bytes)
        .with_context(|| format!("writing {}/activation.json", output.display()))?;
    Ok(())
}

/// Provisions one generated record through the production authority store.
///
/// # Errors
///
/// Returns an error when the argument is missing, the record is not exact
/// canonical JSON, or the protected authority store rejects publication.
pub(super) fn provision_authority(arguments: &[String]) -> Result<()> {
    if arguments.len() != 1 {
        bail!("usage: aos-release-fleet-fixture ability-authority-provision RECORD");
    }

    let path = Path::new(&arguments[0]);
    let bytes = fs::read(path)
        .with_context(|| format!("reading operator policy authority {}", path.display()))?;
    let record: OperatorPolicyAuthorityRecord = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding operator policy authority {}", path.display()))?;
    ensure!(
        record.canonical_bytes()? == bytes,
        "operator policy authority input is not exact canonical JSON"
    );

    OperatorPolicyAuthorityStore::open()
        .context("opening protected operator policy authority store")?
        .provision(&record)
        .context("provisioning protected operator policy authority")?;

    let staging = path
        .parent()
        .context("operator policy authority record has no staging directory")?;
    super::postgresql_activation_fixture::provision_credential_authority(staging)
}

pub(super) fn write_operator_authority(
    output: &Path,
    policy_set: &PinnedAbilitySidecar,
) -> Result<()> {
    let document_digest = Sha256Digest::parse(&policy_set.document_sha256)
        .context("decoding operator-authorized policy-set document digest")?;
    let digest_hex = document_digest.hex();

    fs::create_dir_all(output)
        .with_context(|| format!("creating operator authority output {}", output.display()))?;
    let record = OperatorPolicyAuthorityRecord::new(policy_set.clone())?;
    let bytes = record.canonical_bytes()?;
    let path = output.join(format!("{digest_hex}.json"));
    fs::write(&path, bytes)
        .with_context(|| format!("writing operator policy authority {}", path.display()))?;
    Ok(())
}

fn stage_tls_credentials(
    authority_output: &Path,
    composed: &ComposedReference,
    tls: &ReferenceTls,
) -> Result<()> {
    let secret = fs::read(&tls.bundle)
        .with_context(|| format!("reading TLS credential bundle {}", tls.bundle.display()))?;
    ensure!(
        !secret.is_empty() && secret.len() as u64 <= MAX_TLS_BUNDLE_BYTES,
        "TLS credential bundle is outside the supported size range"
    );

    let provider = lower_provider(&composed.environment.environment, "credential")?;
    let resources = composed
        .desired_state
        .resources
        .iter()
        .filter(|revision| revision.resource.provider == provider)
        .collect::<Vec<_>>();
    ensure!(
        !resources.is_empty(),
        "TLS deployment produced no credential resources"
    );

    let staging_root = authority_output.join("credential-sources");
    fs::create_dir_all(&staging_root)?;
    for revision in resources {
        ensure!(
            revision.revision.0.to_string() == tls.version,
            "credential resource revision differs from its declared TLS version"
        );
        let resource = &revision.resource;
        let resource_digest =
            Sha256Digest::of_canonical("aos.ability.native-host-resource/v1", resource)?.hex();
        let source_digest = Sha256Digest::of_canonical(
            "aos.ability.credential-source-key/v1",
            &CredentialSourceKey {
                resource,
                version: &tls.version,
            },
        )?
        .hex();
        let source_path =
            format!("{CREDENTIAL_SOURCE_ROOT}/{resource_digest}/{source_digest}.secret");
        let record = CredentialSourceRecord {
            schema: "aos.ability.credential-source/v1".to_string(),
            resource: resource.clone(),
            version: tls.version.clone(),
            source_path,
            content_digest: Sha256Digest::of_bytes(&secret),
        };
        let resource_root = staging_root.join(resource_digest);
        fs::create_dir_all(&resource_root)?;
        write_private_file(
            &resource_root.join(format!("{source_digest}.json")),
            &aos_contract::canonical::to_vec(&record)?,
        )?;
        write_private_file(
            &resource_root.join(format!("{source_digest}.secret")),
            &secret,
        )?;
    }

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

fn load_verified_packages() -> Result<(RuntimeResolution, VerifiedAbilityPackageSet)> {
    let config = ApmConfig::load(ProfileScope::System)?;
    let enabled = config.enabled_registries();
    let registries = RegistrySet::load_for_config_evaluation(
        &config.cache_path(),
        &enabled,
        &native_platform(),
    )?;
    let names = PACKAGE_NAMES
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let runtime = resolve_runtime(&registries, &names)?;
    let packages =
        aos_package::config_eval::ability_activation::verify_runtime_packages(&config, &runtime)?;
    Ok((runtime, packages))
}

impl ReferenceFixture {
    fn new(verified: &VerifiedAbilityPackageSet) -> Result<Self> {
        let mut identified_packages = verified
            .iter()
            .map(|package| {
                let document = package.package().clone();
                Ok((document.content_digest()?, document))
            })
            .collect::<Result<Vec<_>>>()?;
        identified_packages.sort_by_key(|(digest, _)| *digest);
        let packages = identified_packages
            .into_iter()
            .map(|(_, package)| package)
            .collect::<Vec<_>>();
        let interface_documents = interface_documents()?;
        let interface_guarantees = interface_documents
            .iter()
            .map(|document| {
                (
                    document.interface.name.as_str().to_string(),
                    document.interface.guarantees.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let interfaces = interface_documents
            .iter()
            .map(|document| {
                Ok((
                    document.interface.name.as_str().to_string(),
                    document.interface_key()?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let supported_features = BTreeSet::from([RequiredFeature::new("abilities-v1")?]);
        let context = ValidationContext::new(supported_features, interface_documents)
            .context("validating reference interface catalog")?;

        let mut consumer_package = None;
        let mut nginx_package = None;
        let mut lower_packages = BTreeMap::new();
        let mut terminal_packages = BTreeMap::new();
        let mut implementations = BTreeMap::new();
        let mut terminal_implementations = BTreeMap::new();
        for package in &packages {
            let package_digest = package.content_digest()?;
            if package.package.name.as_str() == "ability-reference-nginx-consumer" {
                consumer_package = Some(package_digest);
            }
            for provider in &package.implementation.providers {
                let name = provider.interface.name.as_str();
                ensure_interface_matches(&interfaces, &provider.interface)?;
                let reference = provider_reference(provider)?;
                match provider.implementation {
                    ImplementationKind::PureComposition { .. } => {
                        implementations.insert(name.to_string(), reference);
                        if name == "aos.nginx" {
                            nginx_package = Some(package_digest);
                        } else {
                            lower_packages.insert(name.to_string(), package_digest);
                        }
                    }
                    ImplementationKind::TerminalHandler { .. } => {
                        terminal_packages.insert(name.to_string(), package_digest);
                        terminal_implementations.insert(name.to_string(), reference);
                    }
                }
            }
        }

        let environment_id = EnvironmentId {
            authority: key("reference")?,
            key: key("host")?,
            stage: ExecutionStage::Host,
        };
        let policy_revision = RevisionId(digest(20));
        let mut providers = Vec::new();
        for suffix in ["configuration", "credential", "service"] {
            let name = lower_interface_name(suffix)?;
            let provider = lower_provider(&environment_id, suffix)?;
            providers.push(ProviderInventory {
                provider: provider.clone(),
                interface: interfaces
                    .get(name)
                    .with_context(|| format!("missing interface {name}"))?
                    .clone(),
                implementation: implementations
                    .get(name)
                    .with_context(|| format!("missing implementation {name}"))?
                    .clone(),
                state: ProviderState::Declared,
                incarnation: None,
                guarantees: Vec::new(),
            });
            let terminal_name = terminal_interface_name(name);
            if let Some(implementation) = terminal_implementations.get(terminal_name) {
                providers.push(ProviderInventory {
                    provider,
                    interface: interfaces
                        .get(terminal_name)
                        .with_context(|| format!("missing interface {terminal_name}"))?
                        .clone(),
                    implementation: implementation.clone(),
                    state: ProviderState::Available,
                    incarnation: Some(aos_ability_model::IncarnationId::new("reference-terminal")?),
                    guarantees: interface_guarantees
                        .get(terminal_name)
                        .with_context(|| format!("missing guarantees for {terminal_name}"))?
                        .clone(),
                });
            }
        }
        let policy_guarantees = vec![
            host_network_policy_loopback_tcp_egress_guarantee()?,
            host_network_policy_loopback_tcp_ingress_guarantee()?,
        ];
        for name in ["nginx-main", "nginx-secondary"] {
            let provider = instance(&environment_id, name)?;
            for interface_name in [
                "aos.nginx-validation",
                "aos.network-endpoint-effects",
                "aos.host-network-policy-effects",
                "aos.host-storage-effects",
            ] {
                providers.push(ProviderInventory {
                    provider: provider.clone(),
                    interface: interfaces
                        .get(interface_name)
                        .with_context(|| format!("missing {interface_name} interface"))?
                        .clone(),
                    implementation: terminal_implementations
                        .get(interface_name)
                        .with_context(|| format!("missing {interface_name} implementation"))?
                        .clone(),
                    state: ProviderState::Available,
                    incarnation: Some(aos_ability_model::IncarnationId::new(&format!(
                        "reference-{name}-{}-terminal",
                        interface_name.replace('.', "-")
                    ))?),
                    guarantees: if interface_name == "aos.host-network-policy-effects" {
                        policy_guarantees.clone()
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
                    generation: RevisionId(digest(21)),
                    max_age_millis: 60_000,
                },
            },
            packages,
            consumer_package: consumer_package.context("reference consumer package is absent")?,
            nginx_package: nginx_package.context("reference nginx package is absent")?,
            lower_packages,
            terminal_packages,
            implementations,
            terminal_implementations,
            interfaces,
            policy_revision,
            evaluator,
        })
    }

    fn compose(
        mut self,
        primary_response: &str,
        secondary_response: &str,
        lifecycle: ReferenceLifecycle,
        tls: Option<&ReferenceTls>,
    ) -> Result<ComposedReference> {
        let seed = self.seed(primary_response, secondary_response, lifecycle, tls)?;
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
                    return Ok(ComposedReference {
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
                Err(error) => bail!("composing reference ability deployment: {error:#?}"),
            }
        }
    }

    fn seed(
        &self,
        primary_response: &str,
        secondary_response: &str,
        lifecycle: ReferenceLifecycle,
        tls: Option<&ReferenceTls>,
    ) -> Result<DesiredStateDocument> {
        let environment = self.environment.content_digest()?;
        let nginx_main = instance(&self.environment.environment, "nginx-main")?;
        let nginx_secondary = instance(&self.environment.environment, "nginx-secondary")?;
        let configuration = |instance: &str, port: u16, tls_port: u16| -> Result<AbilityValue> {
            let mut configuration = serde_json::json!({
                "address": "127.0.0.1",
                "execution_strategy": "systemd-manager",
                "port": port,
            });
            if let Some(tls) = tls {
                let resource = ResourceId {
                    provider: lower_provider(&self.environment.environment, "credential")?,
                    key: key(&format!("{instance}-credential-view"))?,
                };
                let resource_digest =
                    Sha256Digest::of_canonical("aos.ability.native-host-resource/v1", &resource)?
                        .hex();
                let version_digest = Sha256Digest::of_canonical(
                    "aos.ability.credential-view-key/v1",
                    &CredentialSourceKey {
                        resource: &resource,
                        version: &tls.version,
                    },
                )?
                .hex();
                configuration["tls_port"] = serde_json::json!(tls_port);
                configuration["tls_credential_path"] = serde_json::json!(format!(
                    "/var/lib/aos/ability-runtime/credentials/{resource_digest}-{version_digest}.view"
                ));
            }
            AbilityValue::new(configuration).map_err(Into::into)
        };
        let mut instances = vec![
            DesiredInstance {
                instance: nginx_main.clone(),
                package: self.nginx_package,
                enabled: lifecycle.enables_main(),
                configuration: Some(configuration("nginx-main", 18081, 18443)?),
            },
            DesiredInstance {
                instance: nginx_secondary.clone(),
                package: self.nginx_package,
                enabled: true,
                configuration: Some(configuration("nginx-secondary", 18082, 18444)?),
            },
        ];
        let mut child_requests = Vec::new();
        let mut contributions = Vec::new();
        let mut applications = vec![(
            "app-c",
            &nginx_secondary,
            "gamma.example",
            secondary_response,
        )];
        if lifecycle.includes_main_contributors() {
            applications.push(("app-b", &nginx_main, "beta.example", "beta-v1"));
        }
        if lifecycle.includes_primary() {
            applications.push(("app-a", &nginx_main, "alpha.example", primary_response));
        }
        for (application, provider, host, content) in applications {
            let application = instance(&self.environment.environment, application)?;
            let request = aos_ability_model::RequestId {
                consumer: application.clone(),
                scope: ScopePath::root(),
                key: key("nginx")?,
            };
            instances.push(DesiredInstance {
                instance: application.clone(),
                package: self.consumer_package,
                enabled: true,
                configuration: Some(AbilityValue::new(serde_json::json!({
                    "address": "127.0.0.1",
                    "port": backend_port(application.key.as_str())?,
                    "transport": "tcp",
                }))?),
            });
            child_requests.push(BindingRequest {
                id: request.clone(),
                accepted_interfaces: vec![self.interface("aos.nginx")?],
                methods: Vec::new(),
                guarantees: Vec::new(),
                lifetime: ResourceLifetime::Instance,
            });
            let mut value = serde_json::json!({
                "host": host,
                "response_content": content,
                "response_identity": application.key.as_str(),
                "proxy_backend": true,
                "tls": tls.is_some(),
            });
            if let Some(tls) = tls {
                value["credential_version"] = serde_json::json!(tls.version);
            }
            contributions.push(Contribution {
                request: request.clone(),
                aggregate: AggregateId {
                    provider: provider.clone(),
                    group: key("nginx")?,
                },
                slot: application.key.clone(),
                grant: BindingId(binding_key(&request)?),
                value: AbilityValue::new(value)?,
            });
        }
        instances.sort_by(|left, right| left.instance.cmp(&right.instance));
        child_requests.sort_by(|left, right| left.id.cmp(&right.id));
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
            .filter(|desired| desired.enabled && desired.package == self.nginx_package)
            .map(|desired| {
                let nginx = desired.instance.clone();
                Ok(EnabledProviderSelection {
                    instance: nginx.clone(),
                    interface: self.interface("aos.nginx")?,
                    implementation: self.implementation("aos.nginx")?,
                    provider_grant: aos_ability_model::AuthorityGrant {
                        principal: nginx.clone(),
                        methods: Vec::new(),
                        contributions: Vec::new(),
                        resources: vec![ResourcePermission {
                            resource: ResourceId {
                                provider: nginx,
                                key: key("virtual-hosts")?,
                            },
                            access: AccessMode::ExclusiveWrite,
                            operations: Vec::new(),
                        }],
                    },
                    policy_revision: self.policy_revision,
                    lifetime: ResourceLifetime::Instance,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        enabled_providers.extend(
            desired
                .instances
                .iter()
                .filter(|instance| instance.enabled && instance.package == self.consumer_package)
                .map(|instance| {
                    Ok(EnabledProviderSelection {
                        instance: instance.instance.clone(),
                        interface: self.interface("aos.http-backend")?,
                        implementation: self.implementation("aos.http-backend")?,
                        provider_grant: aos_ability_model::AuthorityGrant {
                            principal: instance.instance.clone(),
                            methods: Vec::new(),
                            contributions: Vec::new(),
                            resources: Vec::new(),
                        },
                        policy_revision: self.policy_revision,
                        lifetime: ResourceLifetime::Instance,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        );
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
            .context("reference request has no accepted interface")?
            .clone();
        let terminal = matches!(
            request.id.key.as_str(),
            "effects"
                | "validation-terminal"
                | "service-terminal"
                | "endpoint"
                | "network-policy"
                | "storage"
        );
        let (provider, provider_package, implementation, resources, contributions) = if terminal {
            let provider = if request.id.key.as_str() == "service-terminal" {
                lower_provider(&self.environment.environment, "service")?
            } else {
                request.id.consumer.clone()
            };
            let exact_service_key = (request.id.key.as_str() == "service-terminal")
                .then(|| format!("{}-service", request.id.consumer.key));
            let resources = desired
                .resources
                .iter()
                .filter(|revision| {
                    revision.resource.provider == provider
                        && exact_service_key
                            .as_ref()
                            .is_none_or(|expected| revision.resource.key.as_str() == expected)
                })
                .map(|revision| ResourcePermission {
                    resource: revision.resource.clone(),
                    access: AccessMode::ExclusiveWrite,
                    operations: request.methods.clone(),
                })
                .collect();
            (
                provider,
                *self
                    .terminal_packages
                    .get(interface.name.as_str())
                    .with_context(|| format!("missing terminal package for {}", interface.name))?,
                self.terminal_implementation(interface.name.as_str())?,
                resources,
                Vec::new(),
            )
        } else if interface == self.interface("aos.nginx")? {
            let matching_contributions = desired
                .contributions
                .iter()
                .filter(|contribution| contribution.request == request.id)
                .collect::<Vec<_>>();
            let [contribution] = matching_contributions.as_slice() else {
                bail!(
                    "reference nginx request has {} matching contributions",
                    matching_contributions.len()
                );
            };
            let provider = contribution.aggregate.provider.clone();
            let contributions = vec![ContributionPermission {
                aggregate: AggregateId {
                    provider: provider.clone(),
                    group: key("nginx")?,
                },
                slot: request.id.consumer.key.clone(),
            }];
            (
                provider,
                self.nginx_package,
                self.implementation("aos.nginx")?,
                Vec::new(),
                contributions,
            )
        } else if interface == self.interface("aos.http-backend")? {
            let application = request
                .id
                .scope
                .as_slice()
                .last()
                .context("reference backend request has no application scope")?;
            let provider = instance(&self.environment.environment, application.as_str())?;

            (
                provider,
                self.consumer_package,
                self.implementation("aos.http-backend")?,
                Vec::new(),
                Vec::new(),
            )
        } else {
            let suffix = request.id.key.as_str();
            let name = lower_interface_name(suffix)?;
            let (group, operations, resource_key) = lower_authority(suffix)?;
            let provider = lower_provider(&self.environment.environment, suffix)?;
            let resource = ResourceId {
                provider: provider.clone(),
                key: key(&format!("{}-{resource_key}", request.id.consumer.key))?,
            };
            let resources = desired
                .resources
                .iter()
                .any(|revision| revision.resource == resource)
                .then(|| {
                    operations
                        .iter()
                        .map(|operation| key(operation))
                        .collect::<Result<Vec<_>>>()
                        .map(|operations| {
                            vec![ResourcePermission {
                                resource,
                                access: AccessMode::Read,
                                operations,
                            }]
                        })
                })
                .transpose()?
                .unwrap_or_default();
            let contributions = vec![ContributionPermission {
                aggregate: AggregateId {
                    provider: provider.clone(),
                    group: key(group)?,
                },
                slot: request.id.consumer.key.clone(),
            }];
            (
                provider,
                *self
                    .lower_packages
                    .get(name)
                    .with_context(|| format!("missing lower package for {name}"))?,
                self.implementation(name)?,
                resources,
                contributions,
            )
        };
        let caller = request.id.consumer.clone();
        let caller_grant = aos_ability_model::AuthorityGrant {
            principal: caller,
            methods: request.methods.clone(),
            contributions,
            resources: resources.clone(),
        };
        let provider_grant = aos_ability_model::AuthorityGrant {
            principal: provider.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: resources
                .iter()
                .cloned()
                .map(|mut permission| {
                    if permission.resource.provider == provider {
                        permission.access = AccessMode::ExclusiveWrite;
                    }
                    permission
                })
                .collect(),
        };
        let guarantees = if interface.name.as_str() == "aos.host-network-policy-effects" {
            vec![
                host_network_policy_loopback_tcp_egress_guarantee()?,
                host_network_policy_loopback_tcp_ingress_guarantee()?,
            ]
        } else {
            Vec::new()
        };
        Ok(BindingCandidate {
            key: binding_key(&request.id)?,
            request: request.id.clone(),
            interface,
            provider,
            provider_package,
            implementation,
            caller_grant,
            provider_grant,
            guarantees,
            policy_revision: self.policy_revision,
            lifetime: ResourceLifetime::Instance,
            mediation_allowed: true,
            exclusive_resources: Vec::new(),
        })
    }

    fn interface(&self, name: &str) -> Result<InterfaceKey> {
        self.interfaces
            .get(name)
            .cloned()
            .with_context(|| format!("reference interface {name} is absent"))
    }

    fn implementation(&self, name: &str) -> Result<ProviderImplementationReference> {
        self.implementations
            .get(name)
            .cloned()
            .with_context(|| format!("reference implementation {name} is absent"))
    }

    fn terminal_implementation(&self, name: &str) -> Result<ProviderImplementationReference> {
        self.terminal_implementations
            .get(name)
            .cloned()
            .with_context(|| format!("reference terminal implementation {name} is absent"))
    }
}

fn reference_native_resource_map(composed: &ComposedReference) -> Result<NativeResourceMap> {
    let environment = &composed.environment.environment;
    let configuration_provider = lower_provider(environment, "configuration")?;
    let credential_provider = lower_provider(environment, "credential")?;
    let service_provider = lower_provider(environment, "service")?;
    let mut mappings = Vec::new();

    for (name, endpoint) in [
        ("nginx-main", "127.0.0.1:18081"),
        ("nginx-secondary", "127.0.0.1:18082"),
    ]
    .into_iter()
    .filter(|(name, _)| {
        composed.desired_state.instances.iter().any(|desired| {
            desired.enabled
                && desired.instance.environment == *environment
                && desired.instance.key.as_str() == *name
        })
    }) {
        let nginx = instance(environment, name)?;
        let storage_scope = Sha256Digest::of_bytes(serde_json::to_vec(&nginx)?)
            .hex()
            .chars()
            .take(32)
            .collect::<String>();
        let nginx_resource = resource_revision(composed, &nginx, "virtual-hosts")?;

        let configuration = native_mapping(
            composed,
            &configuration_provider,
            &format!("{name}-configuration"),
            &configuration_provider,
            "effects",
            NativeResourceQualification::ManagedConfiguration {
                destination: format!("/var/lib/aos/ability-reference/{name}.conf"),
                candidate: output_locator(
                    &configuration_provider,
                    "configuration",
                    fixture_interface(composed, "aos.managed-configuration")?,
                    "rendered-configurations",
                    &[name],
                )?,
                resource_reference: output_locator(
                    &configuration_provider,
                    "configuration",
                    fixture_interface(composed, "aos.managed-configuration")?,
                    "published-configurations",
                    &[name],
                )?,
            },
        )?;
        ensure_reference_managed_configuration_grant(composed, &configuration)?;

        let service_resource =
            resource_revision(composed, &service_provider, &format!("{name}-service"))?;
        let service = native_mapping(
            composed,
            &service_provider,
            &format!("{name}-service"),
            &nginx,
            "service-terminal",
            NativeResourceQualification::SystemdService {
                unit: format!("nginx-{name}.service"),
                resource_reference: output_locator(
                    &service_provider,
                    "services",
                    fixture_interface(composed, "aos.systemd-service")?,
                    "managers",
                    &[name],
                )?,
                consumer_observation: Some(NativeHttpConsumerObservation {
                    schema: NativeHttpConsumerObservation::SCHEMA.to_string(),
                    endpoint: endpoint.to_string(),
                    authority: "aos-consumer.invalid".to_string(),
                    path: "/__aos/consumer".to_string(),
                    expected_instance: nginx.clone(),
                    expected_controller_revision: service_resource.revision,
                    content_resource: nginx_resource.resource.clone(),
                    expected_content_revision: nginx_resource.revision,
                }),
            },
        )?;

        let validation_binding = find_binding(composed, &nginx, "validation-terminal")?;
        let validation = NativeResourceMapping {
            resource: nginx_resource.resource.clone(),
            revision: nginx_resource.revision,
            owner_package: binding_package(validation_binding)?,
            binding: validation_binding.id.clone(),
            implementation: validation_binding.implementation.clone(),
            qualification: NativeResourceQualification::NginxValidation {
                executable: validation_binding.implementation.artifact.clone(),
                validation_prefix: format!("/var/lib/aos/ability-reference/{name}"),
                candidate: output_locator(
                    &nginx,
                    "nginx",
                    fixture_interface(composed, "aos.nginx")?,
                    "rendered-configuration",
                    &[],
                )?,
            },
        };

        mappings.extend([configuration, service, validation]);

        let credential_key = format!("{name}-credential-view");
        if composed.desired_state.resources.iter().any(|revision| {
            revision.resource.provider == credential_provider
                && revision.resource.key.as_str() == credential_key
        }) {
            let credential = native_mapping(
                composed,
                &credential_provider,
                &credential_key,
                &credential_provider,
                "effects",
                NativeResourceQualification::CredentialDelivery {
                    view: credential_key.clone(),
                },
            )?;
            mappings.push(credential);
        }

        for revision in composed
            .desired_state
            .resources
            .iter()
            .filter(|revision| revision.resource.provider == nginx)
        {
            let resource_key = revision.resource.key.as_str();
            if resource_key.contains("-endpoint-") {
                let port = resource_key
                    .rsplit_once('-')
                    .context("nginx endpoint resource has no port")?
                    .1
                    .parse::<u16>()
                    .context("nginx endpoint resource has an invalid port")?;
                mappings.push(native_mapping(
                    composed,
                    &nginx,
                    resource_key,
                    &nginx,
                    "endpoint",
                    NativeResourceQualification::NetworkEndpoint {
                        address: "127.0.0.1".to_string(),
                        port,
                        transport: "tcp".to_string(),
                    },
                )?);
            } else if resource_key.contains("-network-policy-") {
                mappings.push(native_mapping(
                    composed,
                    &nginx,
                    resource_key,
                    &nginx,
                    "network-policy",
                    NativeResourceQualification::HostNetworkPolicy {
                        policy: resource_key.to_string(),
                    },
                )?);
            } else if let Some(purpose) = resource_key.strip_suffix("-storage") {
                ensure!(
                    matches!(purpose, "logs" | "runtime" | "state"),
                    "nginx storage resource has an unsupported purpose"
                );
                let lifetime = if purpose == "runtime" {
                    HostStorageLifetime::Instance
                } else {
                    HostStorageLifetime::Persistent
                };
                mappings.push(native_mapping(
                    composed,
                    &nginx,
                    resource_key,
                    &nginx,
                    "storage",
                    NativeResourceQualification::HostStorage {
                        cluster: storage_scope.clone(),
                        lifetime,
                        owner: HostStorageOwner::Root,
                        purpose: purpose.to_string(),
                    },
                )?);
            }
        }
    }

    NativeResourceMap::new(composed.desired_state.content_digest()?, mappings)
}

fn reference_platform_policy(composed: &ComposedReference) -> CurrentPlatformPolicyDocument {
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

fn ensure_reference_managed_configuration_grant(
    composed: &ComposedReference,
    mapping: &NativeResourceMapping,
) -> Result<()> {
    let NativeResourceQualification::ManagedConfiguration {
        resource_reference, ..
    } = &mapping.qualification
    else {
        bail!("reference managed-configuration mapping has the wrong qualification");
    };
    let output = composed
        .desired_state
        .outputs
        .iter()
        .find(|output| {
            output.aggregate == resource_reference.aggregate
                && output.interface == resource_reference.interface
                && output.port == resource_reference.port
        })
        .context("reference managed-configuration resource output is absent")?;
    let reference = locate_resource_reference(&output.value, &resource_reference.field_path)
        .context("reference managed-configuration locator does not select a resource reference")?;
    let expected = ["prepare", "publish", "read", "release"];
    let actual = reference
        .operations
        .iter()
        .map(LocalKey::as_str)
        .collect::<Vec<_>>();
    ensure!(
        actual == expected,
        "reference managed-configuration resource grant must contain exactly {expected:?}, found {actual:?}"
    );
    Ok(())
}

fn locate_resource_reference<'a>(
    expression: &'a aos_ability_model::ValueExpression,
    field_path: &[LocalKey],
) -> Option<&'a aos_ability_model::ResourceReference> {
    match expression {
        aos_ability_model::ValueExpression::ResourceReference { reference }
            if field_path.is_empty() =>
        {
            Some(reference)
        }
        aos_ability_model::ValueExpression::Object { fields } if !field_path.is_empty() => {
            let (field, remaining) = field_path.split_first()?;
            locate_resource_reference(fields.get(field.as_str())?, remaining)
        }
        _ => None,
    }
}

fn native_mapping(
    composed: &ComposedReference,
    resource_provider: &InstanceId,
    resource_key: &str,
    binding_consumer: &InstanceId,
    request_key: &str,
    qualification: NativeResourceQualification,
) -> Result<NativeResourceMapping> {
    let resource = resource_revision(composed, resource_provider, resource_key)?;
    let binding = find_binding(composed, binding_consumer, request_key)?;
    Ok(NativeResourceMapping {
        resource: resource.resource.clone(),
        revision: resource.revision,
        owner_package: binding_package(binding)?,
        binding: binding.id.clone(),
        implementation: binding.implementation.clone(),
        qualification,
    })
}

fn resource_revision<'a>(
    composed: &'a ComposedReference,
    provider: &InstanceId,
    resource_key: &str,
) -> Result<&'a aos_ability_model::ResourceRevision> {
    let matches = composed
        .desired_state
        .resources
        .iter()
        .filter(|revision| {
            revision.resource.provider == *provider
                && revision.resource.key.as_str() == resource_key
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "reference desired state has {} matches for resource {resource_key:?}",
        matches.len()
    );
    Ok(matches[0])
}

fn find_binding<'a>(
    composed: &'a ComposedReference,
    consumer: &InstanceId,
    request_key: &str,
) -> Result<&'a Binding> {
    let matches = composed
        .bindings
        .iter()
        .filter(|binding| {
            binding.request.consumer == *consumer && binding.request.key.as_str() == request_key
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "reference binding plan has {} matches for request {request_key:?}",
        matches.len()
    );
    Ok(matches[0])
}

fn binding_package(binding: &Binding) -> Result<Sha256Digest> {
    binding
        .provider_package
        .context("native terminal binding is not package-backed")
}

fn fixture_interface(composed: &ComposedReference, name: &str) -> Result<InterfaceKey> {
    composed
        .bindings
        .iter()
        .map(|binding| &binding.interface)
        .find(|interface| interface.name.as_str() == name)
        .cloned()
        .with_context(|| format!("reference binding plan omits interface {name}"))
}

fn output_locator(
    provider: &InstanceId,
    group: &str,
    interface: InterfaceKey,
    port: &str,
    field_path: &[&str],
) -> Result<NativeOutputLocator> {
    Ok(NativeOutputLocator {
        aggregate: AggregateId {
            provider: provider.clone(),
            group: key(group)?,
        },
        interface,
        port: key(port)?,
        field_path: field_path
            .iter()
            .map(|component| key(component))
            .collect::<Result<Vec<_>>>()?,
    })
}

pub(super) fn retain_sidecar(
    output: &Path,
    name: &str,
    document_name: &str,
    document: &impl Serialize,
) -> Result<PinnedAbilitySidecar> {
    let source = output.join(format!("{name}-source"));
    match fs::remove_dir_all(&source) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("removing stale sidecar source"),
    }
    fs::create_dir(&source)
        .with_context(|| format!("creating sidecar source {}", source.display()))?;
    let bytes = aos_contract::canonical::to_vec(document)
        .with_context(|| format!("encoding canonical {name} sidecar"))?;
    fs::write(source.join(document_name), &bytes)
        .with_context(|| format!("writing {name} sidecar document"))?;

    let output = Command::new("nix-store")
        .args(["--add-fixed", "--recursive", "sha256"])
        .arg(&source)
        .output()
        .with_context(|| format!("adding {name} sidecar to the Nix store"))?;
    ensure!(
        output.status.success(),
        "adding {name} sidecar to the Nix store failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let store_path = String::from_utf8(output.stdout)
        .context("nix-store returned a non-UTF-8 sidecar path")?
        .trim()
        .to_string();
    ensure!(
        store_path.starts_with("/nix/store/"),
        "nix-store returned an invalid sidecar path"
    );
    let info = NixCli::new(0).path_info(&store_path)?;
    let mut references = info
        .references
        .iter()
        .filter(|reference| *reference != &store_path)
        .map(|reference| store_hash(reference))
        .collect::<Result<Vec<_>>>()?;
    references.sort();
    references.dedup();
    Ok(PinnedAbilitySidecar {
        store_path,
        nar_hash: info.nar_hash,
        nar_size: info.nar_size,
        references,
        document: document_name.to_string(),
        document_sha256: Sha256Digest::of_bytes(&bytes).to_string(),
        document_size: bytes.len() as u64,
    })
}

fn store_hash(path: &str) -> Result<String> {
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .context("Nix reference has no UTF-8 basename")?;
    let (hash, _) = name
        .split_once('-')
        .context("Nix reference has no store hash separator")?;
    ensure!(hash.len() == 32, "Nix reference has an invalid store hash");
    Ok(hash.to_string())
}

fn interface_documents() -> Result<Vec<InterfaceDocument>> {
    let endpoint = ValueSchema::Record {
        fields: BTreeMap::from([
            (
                key("address")?,
                ValueSchema::String {
                    max_length: 15,
                    syntax: None,
                },
            ),
            (
                key("port")?,
                ValueSchema::Integer {
                    minimum: 1024,
                    maximum: 65535,
                },
            ),
            (
                key("transport")?,
                ValueSchema::StringEnum {
                    values: vec!["tcp".to_string()],
                },
            ),
        ]),
        optional_fields: Vec::new(),
    };
    let consumer_probe = ValueSchema::Record {
        fields: BTreeMap::from([
            (
                key("address")?,
                ValueSchema::String {
                    max_length: 15,
                    syntax: None,
                },
            ),
            (
                key("execution_strategy")?,
                ValueSchema::StringEnum {
                    values: vec![
                        "foreground-process".to_string(),
                        "systemd-manager".to_string(),
                    ],
                },
            ),
            (
                key("port")?,
                ValueSchema::Integer {
                    minimum: 1024,
                    maximum: 65535,
                },
            ),
            (
                key("tls_credential_path")?,
                ValueSchema::String {
                    max_length: 4096,
                    syntax: None,
                },
            ),
            (
                key("tls_port")?,
                ValueSchema::Integer {
                    minimum: 1024,
                    maximum: 65535,
                },
            ),
        ]),
        optional_fields: vec![key("tls_credential_path")?, key("tls_port")?],
    };
    let nginx_request = ValueSchema::Record {
        fields: BTreeMap::from([
            (key("host")?, string_schema()),
            (
                key("response_content")?,
                ValueSchema::String {
                    max_length: 256,
                    syntax: None,
                },
            ),
            (
                key("response_identity")?,
                ValueSchema::String {
                    max_length: 128,
                    syntax: Some(StringSyntax::LocalKeyV1),
                },
            ),
            (key("proxy_backend")?, ValueSchema::Boolean),
            (key("tls")?, ValueSchema::Boolean),
            (
                key("credential_version")?,
                ValueSchema::String {
                    max_length: 71,
                    syntax: None,
                },
            ),
        ]),
        optional_fields: vec![key("credential_version")?, key("proxy_backend")?],
    };
    let managed_nginx_request = match &nginx_request {
        ValueSchema::Record {
            fields,
            optional_fields,
        } => {
            let mut fields = fields.clone();
            fields.insert(key("backend_endpoint")?, endpoint.clone());
            let mut optional_fields = optional_fields.clone();
            optional_fields.push(key("backend_endpoint")?);
            optional_fields.sort();
            ValueSchema::Record {
                fields,
                optional_fields,
            }
        }
        _ => unreachable!("nginx request is a record"),
    };
    let mut documents = vec![
        network_endpoint_interface()?,
        host_network_policy_interface()?,
        host_storage_interface()?,
        interface_document(
            "aos.http-backend",
            ValueSchema::Boolean,
            Some(endpoint.clone()),
            vec![(
                "endpoint",
                ValueSchema::Optional {
                    value: Box::new(endpoint),
                },
            )],
        )?,
        interface_document(
            "aos.nginx",
            nginx_request.clone(),
            Some(consumer_probe.clone()),
            vec![
                ("configuration", ValueSchema::ResourceReference),
                (
                    "credential-view",
                    ValueSchema::Optional {
                        value: Box::new(ValueSchema::ResourceReference),
                    },
                ),
                ("manager", ValueSchema::ResourceReference),
                ("rendered-configuration", string_schema()),
                (
                    "virtual-host-count",
                    ValueSchema::Integer {
                        minimum: 0,
                        maximum: 1024,
                    },
                ),
            ],
        )?,
        interface_document(
            "aos.managed-configuration",
            ValueSchema::Record {
                fields: BTreeMap::from([
                    (
                        key("virtualHosts")?,
                        ValueSchema::List {
                            element: Box::new(managed_nginx_request),
                            max_items: 1024,
                        },
                    ),
                    (key("consumer_content_revision")?, string_schema()),
                    (key("consumer_controller_revision")?, string_schema()),
                    (key("consumer_instance")?, string_schema()),
                    (key("consumer_probe")?, consumer_probe),
                ]),
                optional_fields: Vec::new(),
            },
            None,
            vec![
                ("published-configurations", resource_map_schema()),
                (
                    "rendered-configurations",
                    ValueSchema::Map {
                        key: map_key_constraint(),
                        value: Box::new(string_schema()),
                        max_entries: 1024,
                    },
                ),
            ],
        )?,
        interface_document(
            "aos.credential-delivery",
            ValueSchema::Record {
                fields: BTreeMap::from([
                    (
                        key("hosts")?,
                        ValueSchema::List {
                            element: Box::new(string_schema()),
                            max_items: 1024,
                        },
                    ),
                    (
                        key("version")?,
                        ValueSchema::String {
                            max_length: 71,
                            syntax: None,
                        },
                    ),
                ]),
                optional_fields: Vec::new(),
            },
            None,
            vec![("credential-views", resource_map_schema())],
        )?,
        credential_delivery_effects_interface()?,
        interface_document(
            "aos.systemd-service",
            ValueSchema::Record {
                fields: BTreeMap::from([
                    (key("configuration_revision")?, string_schema()),
                    (key("consumer_endpoint")?, string_schema()),
                    (key("unit")?, string_schema()),
                    (
                        key("virtual_host_count")?,
                        ValueSchema::Integer {
                            minimum: 0,
                            maximum: 1024,
                        },
                    ),
                ]),
                optional_fields: Vec::new(),
            },
            None,
            vec![("managers", resource_map_schema())],
        )?,
        interface_document(
            "aos.nginx-validation",
            ValueSchema::Boolean,
            None,
            Vec::new(),
        )?,
        interface_document(
            "aos.managed-configuration-effects",
            ValueSchema::Boolean,
            None,
            Vec::new(),
        )?,
        interface_document(
            "aos.systemd-service-effects",
            ValueSchema::Boolean,
            None,
            Vec::new(),
        )?,
        aos_ability_model::builtin::foreground_process_interface()?,
    ];
    documents
        .iter_mut()
        .find(|document| document.interface.name.as_str() == "aos.systemd-service-effects")
        .context("missing systemd effects interface")?
        .interface
        .guarantees = vec![
        aos_ability_model::builtin::local_systemd_manager_guarantee()?,
        aos_ability_model::builtin::system_container_manager_delegation_guarantee()?,
    ];
    documents.sort_by(|left, right| left.interface.name.cmp(&right.interface.name));
    Ok(documents)
}

fn interface_document(
    name: &str,
    request: ValueSchema,
    configuration: Option<ValueSchema>,
    outputs: Vec<(&str, ValueSchema)>,
) -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(name)?;
    let validation_parameters = nginx_validation_request_schema()?;
    let methods = reference_method_families(name)
        .into_iter()
        .map(|(method, operation_family)| {
            Ok((
                key(method)?,
                MethodDescriptor {
                    operation_family,
                    parameters: if name == "aos.nginx-validation" {
                        validation_parameters.clone()
                    } else {
                        ValueSchema::Boolean
                    },
                    target_resource: interface_name.clone(),
                    outputs: BTreeMap::new(),
                    permitted_operations: vec![key(method)?],
                    guarantees: Vec::new(),
                    outcome: OutcomeSemantics {
                        completion_evidence: ValueSchema::Boolean,
                        observation_evidence: ValueSchema::Boolean,
                        supports_rejected_before_effect: true,
                        indeterminate: if matches!(
                            method,
                            "deliver"
                                | "observe"
                                | "prepare"
                                | "publish"
                                | "record"
                                | "release"
                                | "stop"
                                | "validate"
                        ) {
                            aos_ability_model::IndeterminateSemantics::Reconcile
                        } else {
                            aos_ability_model::IndeterminateSemantics::InterventionRequired
                        },
                    },
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: interface_name,
            abi: NonZeroU32::new(1).context("interface ABI must be nonzero")?,
            request,
            configuration,
            outputs: outputs
                .into_iter()
                .map(|(name, schema)| {
                    Ok((
                        key(name)?,
                        OutputDescriptor {
                            schema,
                            phase: ValuePhase::Planning,
                            visibility: ValueVisibility::Protected,
                            lifetime: ResourceLifetime::Instance,
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?,
            methods,
            lifecycle: LifecycleSemantics {
                stable_resource_identity: true,
                releases_ephemeral_on_disable: true,
                retains_persistent_by_default: true,
                persistent_delete_method: None,
            },
            guarantees: Vec::new(),
        },
    })
}

fn nginx_validation_request_schema() -> Result<ValueSchema> {
    let credential_view = ValueSchema::Record {
        fields: BTreeMap::from([
            (
                key("path")?,
                ValueSchema::String {
                    max_length: 4096,
                    syntax: None,
                },
            ),
            (
                key("version")?,
                ValueSchema::String {
                    max_length: 71,
                    syntax: None,
                },
            ),
        ]),
        optional_fields: Vec::new(),
    };
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (key("candidate")?, ValueSchema::Boolean),
            (
                key("credential_views")?,
                ValueSchema::List {
                    element: Box::new(credential_view),
                    max_items: 1024,
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

fn reference_method_families(name: &str) -> Vec<(&'static str, OperationFamily)> {
    match name {
        "aos.credential-delivery-effects" => vec![
            (
                "acquire",
                OperationFamily::Credential {
                    action: CredentialAction::Acquire,
                },
            ),
            (
                "deliver",
                OperationFamily::Credential {
                    action: CredentialAction::Deliver,
                },
            ),
            ("release", OperationFamily::ReleaseResource),
        ],
        "aos.nginx-validation" => vec![
            ("record", OperationFamily::RecordGenerationAssociation),
            ("release", OperationFamily::ReleaseResource),
            ("validate", OperationFamily::ValidateCandidate),
        ],
        "aos.managed-configuration-effects" => vec![
            ("prepare", OperationFamily::PrepareManagedConfiguration),
            ("publish", OperationFamily::PublishConfiguration),
            ("release", OperationFamily::ReleaseResource),
        ],
        "aos.systemd-service-effects" => vec![
            ("observe", OperationFamily::ObserveReadiness),
            (
                "reload",
                OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Reload,
                },
            ),
            (
                "start",
                OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Start,
                },
            ),
            (
                "stop",
                OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Stop,
                },
            ),
        ],
        _ => Vec::new(),
    }
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

fn ensure_interface_matches(
    expected: &BTreeMap<String, InterfaceKey>,
    actual: &InterfaceKey,
) -> Result<()> {
    let expected = expected.get(actual.name.as_str()).with_context(|| {
        format!(
            "production companion exports unknown interface {}",
            actual.name
        )
    })?;
    ensure!(
        actual == expected,
        "production companion interface {} differs from the fixture contract",
        actual.name
    );
    Ok(())
}

fn backend_port(application: &str) -> Result<u16> {
    match application {
        "app-a" => Ok(19001),
        "app-b" => Ok(19002),
        "app-c" => Ok(19003),
        _ => bail!("unknown reference backend application {application}"),
    }
}

fn lower_interface_name(suffix: &str) -> Result<&'static str> {
    match suffix {
        "configuration" => Ok("aos.managed-configuration"),
        "credential" => Ok("aos.credential-delivery"),
        "service" => Ok("aos.systemd-service"),
        _ => bail!("unknown lower-interface suffix {suffix:?}"),
    }
}

fn terminal_interface_name(interface: &str) -> &'static str {
    match interface {
        "aos.credential-delivery" => "aos.credential-delivery-effects",
        "aos.managed-configuration" => "aos.managed-configuration-effects",
        "aos.systemd-service" => "aos.systemd-service-effects",
        _ => "",
    }
}

fn lower_authority(suffix: &str) -> Result<(&'static str, Vec<&'static str>, &'static str)> {
    match suffix {
        "configuration" => Ok((
            "configuration",
            vec!["prepare", "publish", "read", "release"],
            "configuration",
        )),
        "credential" => Ok(("credentials", vec!["deliver"], "credential-view")),
        "service" => Ok(("services", vec!["observe", "reload", "start"], "service")),
        _ => bail!("unknown lower authority {suffix:?}"),
    }
}

fn lower_provider(environment: &EnvironmentId, suffix: &str) -> Result<InstanceId> {
    instance(environment, &format!("shared-{suffix}"))
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

fn string_schema() -> ValueSchema {
    ValueSchema::String {
        max_length: 64 * 1024,
        syntax: None,
    }
}

fn resource_map_schema() -> ValueSchema {
    ValueSchema::Map {
        key: map_key_constraint(),
        value: Box::new(ValueSchema::ResourceReference),
        max_entries: 1024,
    }
}

fn map_key_constraint() -> StringConstraint {
    StringConstraint {
        max_length: 128,
        syntax: Some(StringSyntax::LocalKeyV1),
    }
}
