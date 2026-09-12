//! Signed-package planning fixture for real K3s native activation.
//!
//! The fixture loads only packages authenticated through the configured system
//! registry, evaluates the pure K3s provider, resolves its terminal bindings,
//! and emits pinned native activation sidecars.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};
use aos_ability_model::document::{
    Contribution, DesiredInstance, FreshnessCondition, PlatformIdentity, ProviderInventory,
    ProviderState,
};
use aos_ability_model::identity::compare_instance_ids;
use aos_ability_model::{
    AbilityValue, AccessMode, AggregateId, Binding, BindingId, BindingRequest,
    ContributionPermission, DesiredStateDocument, EnvironmentDocument, EnvironmentId,
    ExecutionStage, ImplementationKind, InstanceId, InterfaceDocument, InterfaceKey, LocalKey,
    PackageDocument, ProviderImplementation, ProviderImplementationReference, RequestId,
    RequiredFeature, ResourceId, ResourceLifetime, ResourcePermission, RevisionId, ScopePath,
    VersionedDocument, ABILITY_LIMITS_V1,
};
use aos_ability_plan::{
    BindingCandidate, CandidateSelection, CompositionError, EnabledProviderSelection,
    RecursiveComposer, ResolutionDecision, ResolutionPolicyDocument, Resolver,
};
use aos_ability_validate::ValidationContext;
use aos_contract::Sha256Digest;
use aos_core::nix::store::NixCli;
use aos_package::ability_package::{VerifiedAbilityPackage, VerifiedAbilityPackageSet};
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
    NativeOutputLocator, NativeResourceMap, NativeResourceMapping, NativeResourceQualification,
};
use aos_package::config_eval::runtime::{resolve_runtime, RuntimeResolution};
use aos_package::platform::native_platform;
use aos_package::registry::RegistrySet;
use aos_package::types::ProfileScope;
use serde::Serialize;

const PACKAGE_NAMES: [&str; 5] = [
    "ability-reference-cilium",
    "ability-reference-k3s",
    "ability-reference-kubernetes-terminal",
    "ability-reference-longhorn",
    "ability-reference-systemd-bootstrap",
];
const K3S_INTERFACE: &str = "aos.k3s-cluster";
const KUBERNETES_INTERFACE: &str = "aos.kubernetes-object-effects";
const SYSTEMD_BOOTSTRAP_INTERFACE: &str = "aos.systemd-provider-bootstrap";
const PLANNING_REJECTION_SCHEMA: &str = "aos.test.kubernetes-planning-rejection/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlanningFault {
    MissingSystemdBootstrap,
    CyclicK3sBootstrap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureLifecycle {
    Full,
    Remove,
}

impl PlanningFault {
    fn parse(value: Option<&str>) -> Option<Self> {
        match value {
            Some("missing-systemd-bootstrap") => Some(Self::MissingSystemdBootstrap),
            Some("cyclic-k3s-bootstrap") => Some(Self::CyclicK3sBootstrap),
            _ => None,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::MissingSystemdBootstrap => "missing-available-systemd-bootstrap-root",
            Self::CyclicK3sBootstrap => "cyclic-k3s-bootstrap-lineage",
        }
    }

    const fn expected_diagnostic(self) -> &'static str {
        match self {
            Self::MissingSystemdBootstrap => {
                "binding has no exact usable environment inventory or desired-package provider evidence"
            }
            Self::CyclicK3sBootstrap => "provider dependency lineage contains a cycle",
        }
    }
}

#[derive(Clone)]
struct PlanningTraceInput {
    desired_state: DesiredStateDocument,
    policy: ResolutionPolicyDocument,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct KubernetesPlanningRejection {
    schema: &'static str,
    fault: &'static str,
    disposition: &'static str,
    diagnostic: String,
    environment: EnvironmentDocument,
    environment_digest: Sha256Digest,
    seed: DesiredStateDocument,
    seed_digest: Sha256Digest,
    bounds: PlanningTraceBounds,
    cycle: Option<PlanningCycleEvidence>,
    trace: Vec<PlanningTraceEntry>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PlanningTraceBounds {
    maximum_rounds: u32,
    maximum_entries: u32,
    maximum_bytes: u64,
    retained_rounds: u32,
    retained_entries: u32,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PlanningCycleEvidence {
    nodes: Vec<InstanceId>,
    edges: Vec<ProviderLineageEdge>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PlanningTraceEntry {
    round: u32,
    desired_state: DesiredStateDocument,
    desired_state_digest: Sha256Digest,
    policy: ResolutionPolicyDocument,
    policy_digest: Sha256Digest,
    attempted_selections: Vec<CandidateSelection>,
    result: PlanningResolutionResult,
}

#[derive(Clone, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum PlanningResolutionResult {
    Resolved {
        decisions: Vec<ResolutionDecision>,
        bindings: Vec<Binding>,
        recursive_lineage: Vec<ProviderLineageEdge>,
    },
    Rejected {
        diagnostic: String,
    },
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderLineageEdge {
    request: RequestId,
    interface: InterfaceKey,
    consumer: InstanceId,
    provider: InstanceId,
}

struct KubernetesFixture {
    context: ValidationContext,
    environment: EnvironmentDocument,
    packages: Vec<PackageDocument>,
    package_digests: BTreeMap<String, Sha256Digest>,
    implementations: BTreeMap<String, ProviderImplementationReference>,
    interfaces: BTreeMap<String, InterfaceKey>,
    policy_revision: RevisionId,
    evaluator: RestrictedAbilityEvaluator,
}

struct ComposedKubernetes {
    seed: DesiredStateDocument,
    environment: EnvironmentDocument,
    desired_state: DesiredStateDocument,
    policies: Vec<ResolutionPolicyDocument>,
    bindings: Vec<Binding>,
}

/// Generates a pinned native activation descriptor for a real K3s fixture.
///
/// Arguments are `OUTPUT CILIUM_REPLICAS INCLUDE_LONGHORN
/// --operator-authority-output AUTHORITY_DIR`.
///
/// # Errors
///
/// Returns an error when package authentication, interface loading, recursive
/// composition, native qualification, or sidecar retention fails.
pub(super) fn generate(arguments: &[String]) -> Result<()> {
    let Some(authority_flag_index) = arguments
        .iter()
        .position(|argument| argument == "--operator-authority-output")
    else {
        bail!(
            "usage: aos-release-fleet-fixture kubernetes-activation OUTPUT CILIUM_REPLICAS INCLUDE_LONGHORN [FAULT] --operator-authority-output AUTHORITY_DIR [--lifecycle full|remove]"
        );
    };
    ensure!(
        matches!(authority_flag_index, 3 | 4)
            && arguments.len() >= authority_flag_index + 2
            && (arguments.len() - authority_flag_index - 2) % 2 == 0,
        "Kubernetes activation arguments are malformed"
    );
    let fault = (authority_flag_index == 4).then(|| arguments[3].as_str());
    let authority_index = authority_flag_index + 1;
    let mut lifecycle = FixtureLifecycle::Full;
    for option in arguments[authority_index + 1..].chunks_exact(2) {
        match option[0].as_str() {
            "--lifecycle" => {
                lifecycle = match option[1].as_str() {
                    "full" => FixtureLifecycle::Full,
                    "remove" => FixtureLifecycle::Remove,
                    value => bail!("unknown Kubernetes lifecycle {value:?}"),
                };
            }
            value => bail!("unknown Kubernetes activation option {value:?}"),
        }
    }
    let output = Path::new(&arguments[0]);
    let cilium_replicas = arguments[1]
        .parse::<u16>()
        .context("parsing Cilium operator replica count")?;
    ensure!(
        (1..=16).contains(&cilium_replicas),
        "Cilium operator replica count is outside 1..=16"
    );
    let include_longhorn = match arguments[2].as_str() {
        "true" => true,
        "false" => false,
        _ => bail!("INCLUDE_LONGHORN must be true or false"),
    };
    let authority_output = Path::new(&arguments[authority_index]);
    ensure!(
        authority_output != output,
        "operator authority output must differ from activation output"
    );

    fs::create_dir_all(output)
        .with_context(|| format!("creating Kubernetes fixture output {}", output.display()))?;
    let (_runtime, verified) = load_verified_packages()?;
    let mut fixture = KubernetesFixture::new(&verified)?;
    let planning_fault = PlanningFault::parse(fault);
    ensure!(
        planning_fault.is_none() || lifecycle == FixtureLifecycle::Full,
        "negative Kubernetes planning fixtures require the full lifecycle"
    );
    if let Some(planning_fault) = planning_fault {
        fixture.apply_planning_fault(planning_fault)?;
    }
    let mut planning_trace = Vec::new();
    let composition = fixture.compose(
        cilium_replicas,
        include_longhorn,
        fault,
        lifecycle,
        &mut planning_trace,
    );
    if let Some(planning_fault) = planning_fault {
        let diagnostic = composition
            .err()
            .context("negative Kubernetes planning fixture unexpectedly composed")?;
        ensure!(
            diagnostic.contains(planning_fault.expected_diagnostic()),
            "negative Kubernetes planning fixture rejected for an unexpected reason: {diagnostic}"
        );
        write_planning_rejection(
            output,
            planning_fault,
            &diagnostic,
            &fixture,
            &planning_trace,
        )?;
        bail!(
            "Kubernetes planning rejected before effect plan ({}): {diagnostic}",
            planning_fault.code()
        );
    }
    let mut composed = composition.map_err(anyhow::Error::msg)?;

    let mut native_resource_map = kubernetes_native_resource_map(&composed)?;
    apply_negative_fault(fault, &mut native_resource_map, &mut composed.policies)?;
    let platform_policy = platform_policy(&composed);
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
    fs::write(
        output.join("activation.json"),
        aos_contract::canonical::to_vec(&activation)?,
    )
    .with_context(|| format!("writing {}/activation.json", output.display()))?;
    Ok(())
}

fn write_planning_rejection(
    output: &Path,
    fault: PlanningFault,
    diagnostic: &str,
    fixture: &KubernetesFixture,
    inputs: &[PlanningTraceInput],
) -> Result<()> {
    ensure!(
        inputs.len() <= ABILITY_LIMITS_V1.max_resolver_rounds as usize,
        "Kubernetes planning rejection trace exceeds the node bound"
    );

    // Replay the public resolver over the exact authenticated pass inputs. This
    // retains real binding decisions even though the composer returns no pass on error.
    let resolver = Resolver::new(&fixture.context);
    let mut trace_entries = 0_u32;
    let trace = inputs
        .iter()
        .enumerate()
        .map(|(round, input)| {
            let result = match resolver.resolve(
                &input.policy,
                input.desired_state.clone(),
                fixture.environment.clone(),
                fixture.packages.clone(),
            ) {
                Ok(outcome) => {
                    let recursive_lineage = outcome
                        .checked
                        .bindings()
                        .iter()
                        .filter(|binding| binding.implementation.handler.is_none())
                        .map(|binding| ProviderLineageEdge {
                            request: binding.request.clone(),
                            interface: binding.interface.clone(),
                            consumer: binding.request.consumer.clone(),
                            provider: binding.provider.clone(),
                        })
                        .collect::<Vec<_>>();
                    trace_entries = trace_entries
                        .saturating_add(input.policy.explicit_bindings.len() as u32)
                        .saturating_add(outcome.decisions.len() as u32)
                        .saturating_add(outcome.checked.bindings().len() as u32)
                        .saturating_add(recursive_lineage.len() as u32);
                    PlanningResolutionResult::Resolved {
                        decisions: outcome.decisions,
                        bindings: outcome.checked.bindings().to_vec(),
                        recursive_lineage,
                    }
                }
                Err(error) => {
                    trace_entries =
                        trace_entries.saturating_add(input.policy.explicit_bindings.len() as u32);
                    PlanningResolutionResult::Rejected {
                        diagnostic: error.to_string(),
                    }
                }
            };
            Ok(PlanningTraceEntry {
                round: u32::try_from(round).context("Kubernetes planning trace round overflow")?,
                desired_state: input.desired_state.clone(),
                desired_state_digest: input.desired_state.content_digest()?,
                policy: input.policy.clone(),
                policy_digest: input.policy.content_digest()?,
                attempted_selections: input.policy.explicit_bindings.clone(),
                result,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        trace_entries <= ABILITY_LIMITS_V1.max_graph_edges,
        "Kubernetes planning rejection trace exceeds the edge bound"
    );

    let cycle = planning_cycle_evidence(&trace);
    ensure!(
        (fault == PlanningFault::CyclicK3sBootstrap) == cycle.is_some(),
        "Kubernetes planning rejection cycle evidence does not match the injected fault"
    );
    let seed = inputs
        .first()
        .context("Kubernetes planning rejection has no traced seed")?
        .desired_state
        .clone();
    let evidence = KubernetesPlanningRejection {
        schema: PLANNING_REJECTION_SCHEMA,
        fault: fault.code(),
        disposition: "rejected-before-effect-plan",
        diagnostic: diagnostic.to_string(),
        environment: fixture.environment.clone(),
        environment_digest: fixture.environment.content_digest()?,
        seed_digest: seed.content_digest()?,
        seed,
        bounds: PlanningTraceBounds {
            maximum_rounds: ABILITY_LIMITS_V1.max_resolver_rounds,
            maximum_entries: ABILITY_LIMITS_V1.max_graph_edges,
            maximum_bytes: ABILITY_LIMITS_V1.max_document_bytes,
            retained_rounds: u32::try_from(trace.len())
                .context("Kubernetes planning trace round count overflow")?,
            retained_entries: trace_entries,
        },
        cycle,
        trace,
    };
    let bytes = aos_contract::canonical::to_vec(&evidence)?;
    ensure!(
        bytes.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "Kubernetes planning rejection trace exceeds the byte bound"
    );
    fs::write(output.join("planning-rejection.json"), bytes).with_context(|| {
        format!(
            "writing Kubernetes planning rejection evidence under {}",
            output.display()
        )
    })?;
    Ok(())
}

fn planning_cycle_evidence(trace: &[PlanningTraceEntry]) -> Option<PlanningCycleEvidence> {
    let edges = trace
        .iter()
        .flat_map(|entry| match &entry.result {
            PlanningResolutionResult::Resolved {
                recursive_lineage, ..
            } => recursive_lineage.as_slice(),
            PlanningResolutionResult::Rejected { .. } => &[],
        })
        .filter(|edge| edge.consumer == edge.provider)
        .cloned()
        .collect::<Vec<_>>();
    if edges.is_empty() {
        return None;
    }

    let nodes = edges
        .iter()
        .flat_map(|edge| [edge.consumer.clone(), edge.provider.clone()])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Some(PlanningCycleEvidence { nodes, edges })
}

fn apply_negative_fault(
    fault: Option<&str>,
    native_resource_map: &mut NativeResourceMap,
    policies: &mut [ResolutionPolicyDocument],
) -> Result<()> {
    let Some(fault) = fault else {
        return Ok(());
    };
    match fault {
        "mapping-namespace" | "mapping-kind" => {
            let qualification = native_resource_map
                .entries
                .iter_mut()
                .find_map(|mapping| match &mut mapping.qualification {
                    NativeResourceQualification::KubernetesObject {
                        object_kind,
                        namespace,
                        ..
                    } => Some((object_kind, namespace)),
                    _ => None,
                })
                .context("negative Kubernetes fixture has no object mapping")?;
            if fault == "mapping-namespace" {
                *qualification.1 = Some("default".to_string());
            } else {
                *qualification.0 = "ConfigMap".to_string();
            }
        }
        "resource-grant" => {
            let candidate = policies
                .iter_mut()
                .flat_map(|policy| &mut policy.candidates)
                .find(|candidate| candidate.interface.name.as_str() == KUBERNETES_INTERFACE)
                .context("negative Kubernetes fixture has no terminal policy candidate")?;
            candidate.caller_grant.resources.clear();
            candidate.provider_grant.resources.clear();
        }
        "cluster-rbac" => {
            let qualification = native_resource_map
                .entries
                .iter_mut()
                .find_map(|mapping| match &mut mapping.qualification {
                    NativeResourceQualification::KubernetesObject {
                        api_version,
                        object_kind,
                        namespace,
                        name,
                        ..
                    } if mapping.resource.key.as_str() == "cilium-helmchart" => {
                        Some((api_version, object_kind, namespace, name))
                    }
                    _ => None,
                })
                .context("negative Kubernetes fixture has no Cilium object mapping")?;
            *qualification.0 = "rbac.authorization.k8s.io/v1".to_string();
            *qualification.1 = "ClusterRole".to_string();
            *qualification.2 = None;
            *qualification.3 = "aos-forbidden-cluster-role".to_string();
        }
        _ => bail!("unknown Kubernetes negative fixture fault {fault}"),
    }
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

impl KubernetesFixture {
    fn new(verified: &VerifiedAbilityPackageSet) -> Result<Self> {
        let mut verified_packages = verified.iter().collect::<Vec<_>>();
        verified_packages.sort_by_key(|package| package.package_digest());
        let packages = verified_packages
            .iter()
            .map(|package| package.package().clone())
            .collect::<Vec<_>>();
        let interface_documents = load_interface_documents(&verified_packages)?;
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
        let context = ValidationContext::new(supported_features, interface_documents)?;

        let mut package_digests = BTreeMap::new();
        let mut implementations = BTreeMap::new();
        for package in &packages {
            package_digests.insert(
                package.package.name.as_str().to_string(),
                package.content_digest()?,
            );
            for provider in &package.implementation.providers {
                let expected = interfaces
                    .get(provider.interface.name.as_str())
                    .context("verified package exports an unknown interface")?;
                ensure!(
                    expected == &provider.interface,
                    "provider interface differs from its authenticated document"
                );
                implementations.insert(
                    provider.interface.name.as_str().to_string(),
                    provider_reference(provider)?,
                );
            }
        }

        let environment_id = EnvironmentId {
            authority: key("reference")?,
            key: key("host")?,
            stage: ExecutionStage::Host,
        };
        let k3s = instance(&environment_id, "k3s")?;
        let policy_revision = RevisionId(digest(40));
        let mut providers = vec![
            ProviderInventory {
                provider: k3s.clone(),
                interface: required_interface(&interfaces, K3S_INTERFACE)?,
                implementation: required_implementation(&implementations, K3S_INTERFACE)?,
                state: ProviderState::Declared,
                incarnation: None,
                guarantees: Vec::new(),
            },
            ProviderInventory {
                provider: k3s.clone(),
                interface: required_interface(&interfaces, SYSTEMD_BOOTSTRAP_INTERFACE)?,
                implementation: required_implementation(
                    &implementations,
                    SYSTEMD_BOOTSTRAP_INTERFACE,
                )?,
                state: ProviderState::Available,
                incarnation: Some(aos_ability_model::IncarnationId::new(
                    "reference-systemd-bootstrap",
                )?),
                guarantees: Vec::new(),
            },
            ProviderInventory {
                provider: k3s,
                interface: required_interface(&interfaces, KUBERNETES_INTERFACE)?,
                implementation: required_implementation(&implementations, KUBERNETES_INTERFACE)?,
                state: ProviderState::Planned,
                incarnation: None,
                guarantees: Vec::new(),
            },
        ];
        providers.sort_by(|left, right| {
            compare_instance_ids(&left.provider, &right.provider)
                .then_with(|| left.interface.cmp(&right.interface))
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
                    generation: RevisionId(digest(41)),
                    max_age_millis: 60_000,
                },
            },
            packages,
            package_digests,
            implementations,
            interfaces,
            policy_revision,
            evaluator,
        })
    }

    fn apply_planning_fault(&mut self, fault: PlanningFault) -> Result<()> {
        if fault != PlanningFault::MissingSystemdBootstrap {
            return Ok(());
        }

        let before = self.environment.providers.len();
        self.environment
            .providers
            .retain(|provider| provider.interface.name.as_str() != SYSTEMD_BOOTSTRAP_INTERFACE);
        ensure!(
            before == self.environment.providers.len().saturating_add(1),
            "Kubernetes fixture did not remove exactly one systemd bootstrap root"
        );
        ensure!(
            !self
                .environment
                .providers
                .iter()
                .any(|provider| { provider.state == ProviderState::Available }),
            "Kubernetes missing-bootstrap fixture retained an Available provider root"
        );
        Ok(())
    }

    fn compose(
        &mut self,
        cilium_replicas: u16,
        include_longhorn: bool,
        fault: Option<&str>,
        lifecycle: FixtureLifecycle,
        planning_trace: &mut Vec<PlanningTraceInput>,
    ) -> std::result::Result<ComposedKubernetes, String> {
        let seed = self
            .seed(cilium_replicas, include_longhorn, fault, lifecycle)
            .map_err(|error| error.to_string())?;
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
                    return Ok(ComposedKubernetes {
                        seed,
                        environment: self.environment.clone(),
                        desired_state: outcome.desired_state,
                        policies,
                        bindings: outcome.resolution.checked.bindings().to_vec(),
                    });
                }
                Err(CompositionError::PolicyRequired { desired_state, .. }) => {
                    let policy = self
                        .policy_for(&desired_state)
                        .map_err(|error| error.to_string())?;
                    planning_trace.push(PlanningTraceInput {
                        desired_state: (*desired_state).clone(),
                        policy: policy.clone(),
                    });
                    policies.push(policy);
                }
                Err(error) => {
                    return Err(format!("composing Kubernetes ability deployment: {error}"));
                }
            }
        }
    }

    fn seed(
        &self,
        cilium_replicas: u16,
        include_longhorn: bool,
        fault: Option<&str>,
        lifecycle: FixtureLifecycle,
    ) -> Result<DesiredStateDocument> {
        let environment = self.environment.content_digest()?;
        let k3s = instance(&self.environment.environment, "k3s")?;
        if lifecycle == FixtureLifecycle::Remove {
            return Ok(DesiredStateDocument {
                schema: DesiredStateDocument::SCHEMA.to_string(),
                required_features: Vec::new(),
                environment,
                instances: Vec::new(),
                contributions: Vec::new(),
                child_requests: Vec::new(),
                resources: Vec::new(),
                outputs: Vec::new(),
                controllers: Vec::new(),
            });
        }
        let mut instances = vec![DesiredInstance {
            instance: k3s.clone(),
            package: self.package("ability-reference-k3s")?,
            enabled: true,
            configuration: None,
        }];
        let mut child_requests = Vec::new();
        let mut contributions = Vec::new();
        let cilium_chart = if fault == Some("cluster-rbac") {
            "__aos_forbidden_cluster_role__"
        } else {
            "cilium"
        };
        let mut addons = vec![(
            "cilium",
            "ability-reference-cilium",
            serde_json::json!({
                "chart": cilium_chart,
                "repo": "https://helm.cilium.io/",
                "target_namespace": "kube-system",
                "values_content": format!(
                    "kubeProxyReplacement: true\noperator:\n  replicas: {cilium_replicas}\n"
                ),
                "version": "1.17.6"
            }),
        )];
        if include_longhorn {
            addons.push((
                "longhorn",
                "ability-reference-longhorn",
                serde_json::json!({
                    "chart": "longhorn",
                    "repo": "https://charts.longhorn.io",
                    "target_namespace": "longhorn-system",
                    "values_content": "defaultSettings:\n  defaultReplicaCount: '1'\npersistence:\n  defaultClassReplicaCount: 1\n",
                    "version": "1.8.1"
                }),
            ));
        }
        if fault == Some("cyclic-k3s-bootstrap") {
            child_requests.push(BindingRequest {
                id: RequestId {
                    consumer: k3s.clone(),
                    scope: ScopePath::root(),
                    key: key("bootstrap-lineage-cycle")?,
                },
                accepted_interfaces: vec![self.interface(K3S_INTERFACE)?],
                methods: Vec::new(),
                guarantees: Vec::new(),
                lifetime: ResourceLifetime::Instance,
            });
        }
        for (name, package_name, value) in addons {
            let consumer = instance(&self.environment.environment, name)?;
            let request = aos_ability_model::RequestId {
                consumer: consumer.clone(),
                scope: ScopePath::root(),
                key: key("k3s")?,
            };
            instances.push(DesiredInstance {
                instance: consumer.clone(),
                package: self.package(package_name)?,
                enabled: true,
                configuration: None,
            });
            child_requests.push(BindingRequest {
                id: request.clone(),
                accepted_interfaces: vec![self.interface(K3S_INTERFACE)?],
                methods: Vec::new(),
                guarantees: Vec::new(),
                lifetime: ResourceLifetime::Instance,
            });
            contributions.push(Contribution {
                request: request.clone(),
                aggregate: AggregateId {
                    provider: k3s.clone(),
                    group: key("k3s")?,
                },
                slot: key(name)?,
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
        let k3s = instance(&self.environment.environment, "k3s")?;
        let mut root_resource_keys = BTreeSet::from([key("server-service")?]);
        for contribution in &desired.contributions {
            if contribution.aggregate.provider == k3s
                && contribution.aggregate.group.as_str() == "k3s"
            {
                root_resource_keys
                    .insert(key(&format!("{}-helmchart", contribution.slot.as_str()))?);
            }
        }
        let root_resources = root_resource_keys
            .into_iter()
            .map(|resource_key| {
                let operations = if resource_key.as_str() == "server-service" {
                    ["observe-manager", "start", "stop"]
                } else {
                    ["apply", "delete", "observe"]
                }
                .into_iter()
                .map(key)
                .collect::<Result<Vec<_>>>()?;

                Ok(ResourcePermission {
                    resource: ResourceId {
                        provider: k3s.clone(),
                        key: resource_key,
                    },
                    access: AccessMode::ExclusiveWrite,
                    operations,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let enabled_providers = vec![EnabledProviderSelection {
            instance: k3s.clone(),
            interface: self.interface(K3S_INTERFACE)?,
            implementation: self.implementation(K3S_INTERFACE)?,
            provider_grant: aos_ability_model::AuthorityGrant {
                principal: k3s.clone(),
                methods: Vec::new(),
                contributions: Vec::new(),
                resources: root_resources,
            },
            policy_revision: self.policy_revision,
            lifetime: ResourceLifetime::Instance,
        }];
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
            .context("Kubernetes fixture request has no interface")?
            .clone();
        let k3s = instance(&self.environment.environment, "k3s")?;
        let terminal = interface.name.as_str() != K3S_INTERFACE;
        let resources = if terminal {
            desired
                .resources
                .iter()
                .filter(|revision| {
                    revision.resource.provider == k3s
                        && match interface.name.as_str() {
                            SYSTEMD_BOOTSTRAP_INTERFACE => {
                                revision.resource.key.as_str() == "server-service"
                            }
                            KUBERNETES_INTERFACE => {
                                revision.resource.key.as_str().ends_with("-helmchart")
                            }
                            _ => false,
                        }
                })
                .map(|revision| ResourcePermission {
                    resource: revision.resource.clone(),
                    access: AccessMode::ExclusiveWrite,
                    operations: request.methods.clone(),
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let contributions = if terminal {
            Vec::new()
        } else {
            vec![ContributionPermission {
                aggregate: AggregateId {
                    provider: k3s.clone(),
                    group: key("k3s")?,
                },
                slot: request.id.consumer.key.clone(),
            }]
        };
        let provider_package = if terminal {
            match interface.name.as_str() {
                SYSTEMD_BOOTSTRAP_INTERFACE => {
                    self.package("ability-reference-systemd-bootstrap")?
                }
                KUBERNETES_INTERFACE => self.package("ability-reference-kubernetes-terminal")?,
                other => bail!("unsupported Kubernetes terminal interface {other}"),
            }
        } else {
            self.package("ability-reference-k3s")?
        };
        let caller_grant = aos_ability_model::AuthorityGrant {
            principal: request.id.consumer.clone(),
            methods: request.methods.clone(),
            contributions,
            resources: resources.clone(),
        };
        let provider_grant = aos_ability_model::AuthorityGrant {
            principal: k3s.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources,
        };
        Ok(BindingCandidate {
            key: binding_key(&request.id)?,
            request: request.id.clone(),
            interface: interface.clone(),
            provider: k3s,
            provider_package,
            implementation: self.implementation(interface.name.as_str())?,
            caller_grant,
            provider_grant,
            guarantees: Vec::new(),
            policy_revision: self.policy_revision,
            lifetime: ResourceLifetime::Instance,
            mediation_allowed: true,
            exclusive_resources: Vec::new(),
        })
    }

    fn package(&self, name: &str) -> Result<Sha256Digest> {
        self.package_digests
            .get(name)
            .copied()
            .with_context(|| format!("missing Kubernetes fixture package {name}"))
    }

    fn interface(&self, name: &str) -> Result<InterfaceKey> {
        required_interface(&self.interfaces, name)
    }

    fn implementation(&self, name: &str) -> Result<ProviderImplementationReference> {
        required_implementation(&self.implementations, name)
    }
}

fn load_interface_documents(
    packages: &[&VerifiedAbilityPackage],
) -> Result<Vec<InterfaceDocument>> {
    let mut documents = BTreeMap::new();
    for package in packages {
        let root = Path::new(package.retention_manifest().companion_store_path());
        for export in &package.package().exports {
            let path = root
                .join("interfaces")
                .join(format!("{}.json", export.interface.descriptor.hex()));
            let bytes = fs::read(&path)
                .with_context(|| format!("reading authenticated interface {}", path.display()))?;
            let document: InterfaceDocument = serde_json::from_slice(&bytes)
                .with_context(|| format!("decoding authenticated interface {}", path.display()))?;
            ensure!(
                aos_contract::canonical::to_vec(&document)? == bytes,
                "authenticated interface {} is not canonical JSON",
                path.display()
            );
            ensure!(
                document.interface_key()? == export.interface,
                "authenticated interface {} has another identity",
                path.display()
            );
            documents.insert(export.interface.clone(), document);
        }
    }
    Ok(documents.into_values().collect())
}

fn kubernetes_native_resource_map(composed: &ComposedKubernetes) -> Result<NativeResourceMap> {
    let k3s = instance(&composed.environment.environment, "k3s")?;
    if !composed
        .desired_state
        .instances
        .iter()
        .any(|desired| desired.enabled && desired.instance == k3s)
    {
        return NativeResourceMap::new(composed.desired_state.content_digest()?, Vec::new());
    }
    let k3s_interface = fixture_interface(composed, K3S_INTERFACE)?;
    let service_binding = find_binding(composed, &k3s, "systemd-bootstrap")?;
    let service_revision = resource_revision(composed, &k3s, "server-service")?;
    let mut mappings = vec![NativeResourceMapping {
        resource: service_revision.resource.clone(),
        revision: service_revision.revision,
        owner_package: binding_package(service_binding)?,
        binding: service_binding.id.clone(),
        implementation: service_binding.implementation.clone(),
        qualification: NativeResourceQualification::SystemdService {
            unit: "k3s.service".to_string(),
            resource_reference: output_locator(&k3s, "k3s", k3s_interface.clone(), "service", &[])?,
            consumer_observation: None,
        },
    }];
    let kubernetes_binding = find_binding(composed, &k3s, "kubernetes-terminal")?;
    for addon in ["cilium", "longhorn"] {
        let resource_key = format!("{addon}-helmchart");
        let Some(revision) = composed.desired_state.resources.iter().find(|revision| {
            revision.resource.provider == k3s && revision.resource.key.as_str() == resource_key
        }) else {
            continue;
        };
        mappings.push(NativeResourceMapping {
            resource: revision.resource.clone(),
            revision: revision.revision,
            owner_package: binding_package(kubernetes_binding)?,
            binding: kubernetes_binding.id.clone(),
            implementation: kubernetes_binding.implementation.clone(),
            qualification: NativeResourceQualification::KubernetesObject {
                kubectl: kubernetes_binding.implementation.artifact.clone(),
                kubeconfig: "/etc/rancher/k3s/k3s.yaml".to_string(),
                api_version: "helm.cattle.io/v1".to_string(),
                object_kind: "HelmChart".to_string(),
                namespace: Some("kube-system".to_string()),
                name: addon.to_string(),
                object_json: output_locator(
                    &k3s,
                    "k3s",
                    k3s_interface.clone(),
                    "object-json",
                    &[addon],
                )?,
                resource_reference: output_locator(
                    &k3s,
                    "k3s",
                    k3s_interface.clone(),
                    "objects",
                    &[addon],
                )?,
            },
        });
    }
    NativeResourceMap::new(composed.desired_state.content_digest()?, mappings)
}

fn platform_policy(composed: &ComposedKubernetes) -> CurrentPlatformPolicyDocument {
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

fn write_operator_authority(output: &Path, policy_set: &PinnedAbilitySidecar) -> Result<()> {
    fs::create_dir_all(output)
        .with_context(|| format!("creating operator authority output {}", output.display()))?;
    let digest = Sha256Digest::parse(&policy_set.document_sha256)?;
    let record = OperatorPolicyAuthorityRecord::new(policy_set.clone())?;
    fs::write(
        output.join(format!("{}.json", digest.hex())),
        record.canonical_bytes()?,
    )?;
    Ok(())
}

pub(super) fn provision_authority(arguments: &[String]) -> Result<()> {
    if arguments.len() != 1 {
        bail!("usage: aos-release-fleet-fixture kubernetes-authority-provision RECORD");
    }
    let bytes = fs::read(&arguments[0])?;
    let record: OperatorPolicyAuthorityRecord = serde_json::from_slice(&bytes)?;
    ensure!(
        record.canonical_bytes()? == bytes,
        "authority record is not canonical JSON"
    );
    OperatorPolicyAuthorityStore::open()?.provision(&record)
}

fn resource_revision<'a>(
    composed: &'a ComposedKubernetes,
    provider: &InstanceId,
    resource_key: &str,
) -> Result<&'a aos_ability_model::ResourceRevision> {
    composed
        .desired_state
        .resources
        .iter()
        .find(|revision| {
            revision.resource.provider == *provider
                && revision.resource.key.as_str() == resource_key
        })
        .with_context(|| format!("missing Kubernetes resource {resource_key}"))
}

fn find_binding<'a>(
    composed: &'a ComposedKubernetes,
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
    ensure!(matches.len() == 1, "expected one binding for {request_key}");
    Ok(matches[0])
}

fn fixture_interface(composed: &ComposedKubernetes, name: &str) -> Result<InterfaceKey> {
    composed
        .bindings
        .iter()
        .map(|binding| &binding.interface)
        .find(|interface| interface.name.as_str() == name)
        .cloned()
        .with_context(|| format!("binding plan omits interface {name}"))
}

fn binding_package(binding: &Binding) -> Result<Sha256Digest> {
    binding
        .provider_package
        .context("terminal binding has no package")
}

fn output_locator(
    provider: &InstanceId,
    group: &str,
    interface: InterfaceKey,
    port: &str,
    fields: &[&str],
) -> Result<NativeOutputLocator> {
    Ok(NativeOutputLocator {
        aggregate: AggregateId {
            provider: provider.clone(),
            group: key(group)?,
        },
        interface,
        port: key(port)?,
        field_path: fields
            .iter()
            .map(|field| key(field))
            .collect::<Result<Vec<_>>>()?,
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

fn required_interface(
    interfaces: &BTreeMap<String, InterfaceKey>,
    name: &str,
) -> Result<InterfaceKey> {
    interfaces
        .get(name)
        .cloned()
        .with_context(|| format!("missing interface {name}"))
}

fn required_implementation(
    implementations: &BTreeMap<String, ProviderImplementationReference>,
    name: &str,
) -> Result<ProviderImplementationReference> {
    implementations
        .get(name)
        .cloned()
        .with_context(|| format!("missing implementation {name}"))
}

fn retain_sidecar(
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
    fs::create_dir(&source)?;
    let bytes = aos_contract::canonical::to_vec(document)?;
    fs::write(source.join(document_name), &bytes)?;
    let output = Command::new("nix-store")
        .args(["--add-fixed", "--recursive", "sha256"])
        .arg(&source)
        .output()?;
    ensure!(
        output.status.success(),
        "adding sidecar failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let store_path = String::from_utf8(output.stdout)?.trim().to_string();
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
        .context("Nix reference has no store hash")?;
    ensure!(hash.len() == 32, "Nix reference has invalid store hash");
    Ok(hash.to_string())
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
