//! Static routing and live policy composition for native ability dispatch.
//!
//! The registry closes the gap between a checked effect graph and the small
//! built-in adapter set. Every mapped resource must resolve through its exact
//! authenticated terminal package before a transaction is opened. The policy
//! wrapper then combines revocable operator authorization with the existing
//! current-assignment policy at every admission and immediate dispatch check.

use std::fmt;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, ensure};
use aos_ability_model::{
    AggregateOutput, Binding, DependencyKind, DesiredStateDocument, IncarnationId, MethodReference,
    Operation, PlanNodeKey, ProviderAssignment, ResourceId, ResultProducerKey, ScopedOperationKey,
    TransactionId, ValueExpression,
};
use aos_ability_plan::{
    RuntimeResourceHealth, RuntimeResourceObservation, RuntimeResourceState,
    TransitionReconciliation,
};
use aos_ability_runtime::adapter::{
    CancellationToken, InvocationPurpose, MonotonicClock, ResourceAdmissionEvidence,
    ResourceRevisionObservation, SystemMonotonicClock, TrustedAdapter, TrustedResourceCatalog,
};
use aos_ability_runtime::execution::{
    AdmittedOperation, CheckedExecutionJournalSnapshot, ExecutionBoundaryObserver, ExecutionError,
    ExecutionStep, RecoveryAction, TerminalResult, TrustedAdmissionPolicy,
};
use aos_ability_runtime::journal::JournalLimits;
use aos_ability_validate::{BindingAuthorityKind, CheckedEffectPlan};
use aos_contract::Sha256Digest;

use super::ability_activation::SpecializedAbilityActivation;
use super::ability_policy::{
    CurrentAbilityAuthoritySource, CurrentResourceObservation, CurrentResourceState,
    NativeCurrentAdmissionPolicy,
};
use super::ability_policy_authority::OperatorPolicyAuthorityStore;
use super::ability_store::inventory::{
    NativeNoOpResourceObservation, verify_retained_native_consumers,
};
use super::ability_store::{
    NativeAbilitySession, NativeObservationSession, RetainedAbilityDiagnosticSource,
};
use super::kubernetes_ability::{
    DeferredKubernetesApiCapability, KubernetesApiCapability, KubernetesObjectResourceCatalog,
    KubernetesObjectResourceSpec, NativeKubernetesObjectAdapter, preflight_native_kubernetes,
};
use super::managed_configuration_ability::{
    ManagedConfigurationResourceCatalog, ManagedConfigurationResourceSpec,
    NativeManagedConfigurationAdapter, preflight_native_managed_configuration,
};
use super::native_adapter_surface::{adapter_id, supports_exact_route};
use super::native_consumer_observation::{
    classify_native_http_consumer, observe_native_http_consumer,
};
use super::native_host_resources::{
    HostResourceAllocations, NativeDependencyBinding, NativeHostResourceAdapter,
    NativeHostResourceCatalog, NativeHostResourceKind, NativeHostResourceSpec,
    StorageAllocationRequest, preflight_native_host_resource,
};
use super::native_provider_capability::{
    KubernetesClusterReadinessOutput, NativeProviderReadinessOutput, SystemdManagerCapabilities,
    reacquire_kubernetes_assignment,
};
use super::native_resource_map::{
    NativeResourceMap, NativeResourceMapping, NativeResourceQualification,
};
use super::nginx_ability::{
    NativeNginxAdapter, NginxResourceCatalog, NginxResourceSpec, preflight_native_nginx,
};
use super::systemd_ability::{
    NativeSystemdAdapter, NativeSystemdServiceAdapter, SystemdResourceCatalog,
    SystemdResourceRuntimeState, SystemdResourceSpec, preflight_native_systemd,
};
use crate::ability_package::{VerifiedAbilityPackage, VerifiedAbilityPackageSet};

const MANAGED_CONFIGURATION_STATE_ROOT: &str = "/var/lib/aos/ability-runtime/managed-configuration";
const NGINX_STATE_ROOT: &str = "/var/lib/aos/ability-runtime/nginx";
const RETRY_CANCELLATION_POLL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeCancellationAction {
    Continue,
    Dispatch,
    Unsupported,
}

/// Selects the built-in adapter family authenticated for one native mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeAdapterKind {
    /// Uses the exact kubectl and protected cluster capability.
    KubernetesObject,
    /// Uses the root-owned managed-configuration adapter.
    ManagedConfiguration,
    /// Uses the exact nginx validation adapter.
    NginxValidation,
    /// Uses either supported exact systemd terminal contract.
    Systemd,
    /// Uses one exact production host-resource contract.
    HostResource(NativeHostResourceKind),
}

/// Borrows the exact package and mapping selected for one checked operation.
pub(crate) struct NativeAdapterRoute<'a> {
    pub(crate) package: &'a VerifiedAbilityPackage,
    pub(crate) mapping: &'a NativeResourceMapping,
    desired_state: &'a DesiredStateDocument,
    generation: NativeResourceGeneration,
    pub(crate) assignment_interface: aos_ability_model::InterfaceKey,
    pub(crate) kind: NativeAdapterKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeResourceGeneration {
    Desired,
    Current,
}

/// Holds a closed, preflighted routing table for the built-in native adapters.
pub(crate) struct NativeAdapterRegistry<'a> {
    plan: &'a CheckedEffectPlan,
    desired: &'a NativeResourceMap,
    current: Option<&'a NativeResourceMap>,
    desired_state: &'a DesiredStateDocument,
    current_desired_state: Option<&'a DesiredStateDocument>,
    current_planning: Option<aos_contract::Sha256Digest>,
    reconciliation: Option<&'a TransitionReconciliation>,
    packages: &'a VerifiedAbilityPackageSet,
    host_allocations: HostResourceAllocations,
}

/// Supplies independently authenticated evidence for an effect-free transition.
///
/// An empty effect graph is not itself evidence that the retained generation
/// is healthy. Implementations must authenticate a successful prior
/// transaction and freshly observe the actual native consumers represented by
/// `current_resources`. They must also revalidate the supplied live provider
/// assignments and current resource state before returning success.
pub(crate) trait TrustedNativeNoOpVerifier {
    /// Verifies that an empty native transition can safely retain current state.
    ///
    /// # Errors
    ///
    /// Returns an error unless prior success, current policy and assignments,
    /// resource revisions, and actual consumer ownership are all freshly proven.
    fn verify_no_op(&mut self, evidence: NativeNoOpEvidence<'_>) -> Result<()>;
}

/// Borrows every expected value needed to authenticate a native no-op.
#[derive(Clone, Copy)]
pub(crate) struct NativeNoOpEvidence<'a> {
    /// Identifies the newly opened empty transaction.
    pub(crate) transaction: &'a TransactionId,
    /// Supplies the checked empty graph whose retained state is being accepted.
    pub(crate) plan: &'a CheckedEffectPlan,
    /// Supplies the freshly specialized desired state.
    pub(crate) desired_state: &'a DesiredStateDocument,
    /// Supplies the retained generation state that prior success established.
    pub(crate) current_desired_state: &'a DesiredStateDocument,
    /// Supplies the retained native mapping with identical execution semantics.
    pub(crate) current_resources: &'a NativeResourceMap,
    /// Commits to the retained planning state the prior transaction installed.
    pub(crate) current_planning: aos_contract::Sha256Digest,
    /// Supplies independently observed live provider assignments.
    pub(crate) assignments: &'a [ProviderAssignment],
    /// Supplies direct adapter observations of every retained native resource.
    pub(crate) resources: &'a [NativeNoOpResourceObservation],
}

/// Replays one protected retained transaction as native no-op evidence.
pub(crate) struct RetainedNativeNoOpVerifier {
    source: Option<RetainedAbilityDiagnosticSource>,
    journal_limits: JournalLimits,
}

impl RetainedNativeNoOpVerifier {
    /// Constructs a one-shot verifier around a descriptor-anchored retained source.
    #[must_use]
    pub(crate) const fn new(
        source: RetainedAbilityDiagnosticSource,
        journal_limits: JournalLimits,
    ) -> Self {
        Self {
            source: Some(source),
            journal_limits,
        }
    }
}

impl TrustedNativeNoOpVerifier for RetainedNativeNoOpVerifier {
    fn verify_no_op(&mut self, evidence: NativeNoOpEvidence<'_>) -> Result<()> {
        let source = self
            .source
            .take()
            .context("retained native no-op evidence was already consumed")?;
        let retained_generation = source.generation().to_path_buf();
        ensure!(
            source.desired_planning() == evidence.current_planning,
            "successful retained transaction installed another planning state"
        );
        let retained_plan_is_empty = source.plan().operations().is_empty();
        let native_no_op_verified = source.native_no_op_verified();
        let expected_transaction = source.transaction().clone();
        let expected_plan = source.plan().id();
        let expected_bundle = source.plan_bundle();
        let (plan, _, journal, journal_path) = source.into_parts();
        let snapshot = CheckedExecutionJournalSnapshot::read_file(
            &plan,
            journal,
            journal_path,
            self.journal_limits,
        )
        .context("replaying retained native transaction for no-op verification")?;
        ensure!(
            snapshot.transaction() == &expected_transaction
                && snapshot.plan_bundle() == expected_bundle,
            "retained native transaction differs from its protected selection"
        );
        require_successful_retained_transaction(
            snapshot.terminal(),
            snapshot.incomplete_tail_bytes(),
            retained_plan_is_empty,
            native_no_op_verified,
        )?;
        verify_retained_native_consumers(
            &retained_generation,
            &expected_transaction,
            expected_plan,
            evidence.resources,
        )
        .context("verifying retained native consumer ownership")?;
        Ok(())
    }
}

fn require_successful_retained_transaction(
    terminal: Option<TerminalResult>,
    incomplete_tail_bytes: u64,
    plan_is_empty: bool,
    native_no_op_verified: bool,
) -> Result<()> {
    ensure!(
        incomplete_tail_bytes == 0,
        "retained native transaction has an incomplete journal tail"
    );
    ensure!(
        terminal == Some(TerminalResult::Succeeded),
        "retained native transaction did not settle successfully"
    );
    ensure!(
        !plan_is_empty || native_no_op_verified,
        "retained empty native transaction lacks protected no-op verification evidence"
    );
    Ok(())
}

pub(crate) trait NativeNoOpAdmissionPolicy: TrustedAdmissionPolicy {
    fn authorize_no_op(
        &mut self,
        plan: &CheckedEffectPlan,
        assignments: &[ProviderAssignment],
        resources: &NativeResourceMap,
    ) -> std::result::Result<(), Self::Error>;
}

/// Refreshes independently observed assignment and resource authority.
pub(crate) trait NativeAuthorityRefresh: NativeNoOpAdmissionPolicy {
    /// Publishes a fresh authority view before another native effect decision.
    ///
    /// # Errors
    ///
    /// Returns an error when observations cannot be authenticated or the
    /// protected current-authority scope cannot be advanced.
    fn refresh_authority(
        &mut self,
        plan: &CheckedEffectPlan,
        assignments: &[ProviderAssignment],
        resources: Vec<CurrentResourceObservation>,
    ) -> std::result::Result<(), Self::Error>;
}

impl<Source, Clock> NativeNoOpAdmissionPolicy for NativeCurrentAdmissionPolicy<Source, Clock>
where
    Source: CurrentAbilityAuthoritySource,
    Clock: MonotonicClock,
{
    fn authorize_no_op(
        &mut self,
        plan: &CheckedEffectPlan,
        assignments: &[ProviderAssignment],
        resources: &NativeResourceMap,
    ) -> std::result::Result<(), Self::Error> {
        self.authorize_native_no_op(plan, assignments, resources)
    }
}

impl<'a> NativeAdapterRegistry<'a> {
    /// Preflights every desired/current mapping and every checked native route.
    ///
    /// # Errors
    ///
    /// Returns an error when an owner package, terminal handler, exact adapter
    /// contract, executable selection, teardown map, or operation route differs
    /// from the authenticated resource map.
    pub(crate) fn new(
        activation: &'a SpecializedAbilityActivation,
        packages: &'a VerifiedAbilityPackageSet,
    ) -> Result<Self> {
        let mut registry = Self {
            plan: activation.plan(),
            desired: activation.desired_native_resources(),
            current: activation.current_native_resources(),
            desired_state: activation.desired_state(),
            current_desired_state: activation.current_desired_state(),
            current_planning: activation.bundle().current_planning_digest(),
            reconciliation: activation.bundle().reconciliation(),
            packages,
            host_allocations: HostResourceAllocations::default(),
        };

        for mapping in registry
            .desired
            .entries
            .iter()
            .chain(registry.current.into_iter().flat_map(|map| &map.entries))
        {
            registry.preflight_mapping(mapping)?;
        }
        registry.host_allocations = registry.build_host_allocations()?;
        // Preflight the complete graph before any operation can be admitted.
        // A later branch selection must never expose an unsupported route.
        for operation in registry.plan.operations() {
            registry.route(operation)?;
        }
        registry.validate_manager_readiness_contracts()?;

        Ok(registry)
    }

    /// Resolves one checked operation to its exact authenticated adapter route.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation is not a checked graph member or its
    /// authoritative generation lacks the exact mapped resource and interface.
    pub(crate) fn route(&self, operation: &Operation) -> Result<NativeAdapterRoute<'a>> {
        ensure!(
            self.plan.operation(&operation.key) == Some(operation),
            "native dispatcher operation is outside the checked plan"
        );
        let authority = self
            .plan
            .binding_plan()
            .binding_authority(&operation.binding)
            .context("native dispatcher operation has no checked binding authority")?;
        let (resource_map, desired_state, source_binding, generation) = match authority {
            BindingAuthorityKind::Desired => (
                self.desired,
                self.activation_desired_state(),
                &operation.binding,
                NativeResourceGeneration::Desired,
            ),
            BindingAuthorityKind::Teardown { source_binding, .. } => (
                self.current
                    .context("native teardown dispatch has no retained current resource map")?,
                self.activation_current_desired_state()?,
                source_binding,
                NativeResourceGeneration::Current,
            ),
        };
        let mapping = resource_map
            .entries
            .iter()
            .find(|mapping| mapping.resource == operation.target.resource)
            .context("native dispatcher target is absent from its authoritative resource map")?;
        ensure!(
            &mapping.binding == source_binding,
            "native dispatcher mapping names a different authoritative binding"
        );
        let mut route = self.preflight_mapping(mapping)?;
        ensure!(
            route.assignment_interface == operation.interface,
            "native dispatcher mapping resolves to a different terminal interface"
        );
        preflight_operation_contract(route.kind, operation)?;
        route.desired_state = desired_state;
        route.generation = generation;
        Ok(route)
    }

    /// Selects the exact live assignment that a route's catalog must require.
    ///
    /// # Errors
    ///
    /// Returns an error unless exactly one current assignment matches the
    /// mapped provider, terminal interface, and implementation.
    pub(crate) fn assignment(
        &self,
        route: &NativeAdapterRoute<'_>,
        assignments: &[ProviderAssignment],
    ) -> Result<ProviderAssignment> {
        let mut matching = assignments.iter().filter(|assignment| {
            assignment.provider == route.mapping.resource.provider
                && assignment.interface == route.assignment_interface
                && assignment.implementation == route.mapping.implementation
        });
        let assignment = matching
            .next()
            .context("native dispatcher has no exact live provider assignment")?;
        ensure!(
            matching.next().is_none(),
            "native dispatcher found duplicate live provider assignments"
        );
        Ok(assignment.clone())
    }

    /// Verifies that a durable readiness output belongs to the selected route.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider, interface, or implementation differs
    /// from the authenticated mapping and terminal package.
    fn require_route_assignment(
        &self,
        route: &NativeAdapterRoute<'_>,
        assignment: &ProviderAssignment,
    ) -> Result<()> {
        ensure!(
            assignment.provider == route.mapping.resource.provider
                && assignment.interface == route.assignment_interface
                && assignment.implementation == route.mapping.implementation,
            "planned provider assignment differs from the authenticated native route"
        );
        Ok(())
    }

    /// Builds the trusted managed-configuration catalog input for one route.
    ///
    /// # Errors
    ///
    /// Returns an error when the route has another qualification or a mapped
    /// candidate disappeared after specialization.
    pub(crate) fn managed_configuration_spec(
        &self,
        route: &NativeAdapterRoute<'_>,
    ) -> Result<ManagedConfigurationResourceSpec> {
        let NativeResourceQualification::ManagedConfiguration {
            destination,
            candidate,
            ..
        } = &route.mapping.qualification
        else {
            return Err(anyhow!(
                "native dispatcher route is not managed configuration"
            ));
        };
        let current_revision = self
            .current_mapping(&route.mapping.resource)
            .map(|mapping| mapping.revision);
        let desired_revision = (route.generation == NativeResourceGeneration::Desired)
            .then_some(route.mapping.revision);

        Ok(ManagedConfigurationResourceSpec {
            resource: route.mapping.resource.clone(),
            destination: destination
                .strip_prefix('/')
                .context("managed-configuration destination is not absolute")?
                .into(),
            candidate: mapped_candidate(candidate, route.desired_state)?
                .as_bytes()
                .to_vec(),
            current_revision,
            desired_revision,
        })
    }

    /// Builds the trusted nginx catalog input for one route.
    ///
    /// # Errors
    ///
    /// Returns an error when the route has another qualification or a mapped
    /// current/desired candidate disappeared after specialization.
    pub(crate) fn nginx_spec(&self, route: &NativeAdapterRoute<'_>) -> Result<NginxResourceSpec> {
        let NativeResourceQualification::NginxValidation {
            validation_prefix,
            candidate,
            ..
        } = &route.mapping.qualification
        else {
            return Err(anyhow!("native dispatcher route is not nginx validation"));
        };
        let current = self.current_mapping(&route.mapping.resource);
        let current_candidate_digest = current
            .map(|mapping| {
                let NativeResourceQualification::NginxValidation { candidate, .. } =
                    &mapping.qualification
                else {
                    return Err(anyhow!(
                        "retained nginx resource changed qualification class"
                    ));
                };
                let state = self.activation_current_desired_state()?;
                Ok(aos_contract::Sha256Digest::of_bytes(
                    mapped_candidate(candidate, state)?.as_bytes(),
                ))
            })
            .transpose()?;

        Ok(NginxResourceSpec {
            resource: route.mapping.resource.clone(),
            validation_prefix: validation_prefix.into(),
            candidate: mapped_candidate(candidate, route.desired_state)?
                .as_bytes()
                .to_vec(),
            current_generation: current.map(|mapping| mapping.revision),
            current_candidate_digest,
            desired_generation: (route.generation == NativeResourceGeneration::Desired)
                .then_some(route.mapping.revision),
        })
    }

    /// Builds the trusted systemd catalog input for one route.
    ///
    /// # Errors
    ///
    /// Returns an error when the route has another qualification.
    pub(crate) fn systemd_spec(
        &self,
        route: &NativeAdapterRoute<'_>,
    ) -> Result<SystemdResourceSpec> {
        let NativeResourceQualification::SystemdService {
            unit,
            consumer_observation,
            ..
        } = &route.mapping.qualification
        else {
            return Err(anyhow!("native dispatcher route is not a systemd service"));
        };
        let generation = match route.generation {
            NativeResourceGeneration::Desired => self.desired.desired_state,
            NativeResourceGeneration::Current => {
                self.current
                    .context("native systemd teardown has no current resource map")?
                    .desired_state
            }
        };

        Ok(SystemdResourceSpec {
            resource: route.mapping.resource.clone(),
            unit: unit.clone(),
            revision: route.mapping.revision,
            generation,
            owner_package: route.mapping.owner_package,
            consumer_observation: consumer_observation.clone(),
        })
    }

    /// Builds the trusted Kubernetes catalog input for one route.
    ///
    /// # Errors
    ///
    /// Returns an error when the route has another qualification or its
    /// canonical object output disappeared after specialization.
    pub(crate) fn kubernetes_spec(
        &self,
        route: &NativeAdapterRoute<'_>,
    ) -> Result<KubernetesObjectResourceSpec> {
        let NativeResourceQualification::KubernetesObject {
            kubectl,
            kubeconfig,
            api_version,
            object_kind,
            namespace,
            name,
            object_json,
            ..
        } = &route.mapping.qualification
        else {
            return Err(anyhow!(
                "native dispatcher route is not a Kubernetes object"
            ));
        };
        let current_revision = self
            .current_mapping(&route.mapping.resource)
            .map(|mapping| mapping.revision);
        let current_object_json = self
            .current_mapping(&route.mapping.resource)
            .map(|mapping| {
                let NativeResourceQualification::KubernetesObject { object_json, .. } =
                    &mapping.qualification
                else {
                    return Err(anyhow!(
                        "retained Kubernetes resource changed qualification class"
                    ));
                };
                Ok(
                    mapped_candidate(object_json, self.activation_current_desired_state()?)?
                        .as_bytes()
                        .to_vec(),
                )
            })
            .transpose()?;

        Ok(KubernetesObjectResourceSpec {
            resource: route.mapping.resource.clone(),
            kubectl: kubectl.clone(),
            kubeconfig: kubeconfig.into(),
            api_version: api_version.clone(),
            kind: object_kind.clone(),
            namespace: namespace.clone(),
            name: name.clone(),
            object_json: mapped_candidate(object_json, route.desired_state)?
                .as_bytes()
                .to_vec(),
            current_revision,
            current_object_json,
            desired_revision: (route.generation == NativeResourceGeneration::Desired)
                .then_some(route.mapping.revision),
        })
    }

    /// Builds the exact static host-resource catalog input for one route.
    fn host_resource_spec(&self, route: &NativeAdapterRoute<'_>) -> Result<NativeHostResourceSpec> {
        ensure!(
            NativeHostResourceKind::from_qualification(&route.mapping.qualification).is_some(),
            "native dispatcher route is not a production host resource"
        );
        Ok(NativeHostResourceSpec {
            resource: route.mapping.resource.clone(),
            revision: route.mapping.revision,
            qualification: route.mapping.qualification.clone(),
            retained_qualification: self
                .current_mapping(&route.mapping.resource)
                .map(|mapping| mapping.qualification.clone()),
            dependencies: self.host_resource_dependencies(route.mapping)?,
            storage_binding: match NativeHostResourceKind::from_qualification(
                &route.mapping.qualification,
            ) {
                Some(NativeHostResourceKind::Storage) => {
                    self.host_allocations.storage(&route.mapping.resource)
                }
                Some(NativeHostResourceKind::Endpoint) => {
                    self.host_allocations.endpoint(&route.mapping.resource)
                }
                Some(NativeHostResourceKind::Postgresql) => {
                    self.host_allocations.postgresql(&route.mapping.resource)
                }
                _ => None,
            },
        })
    }

    fn build_host_allocations(&self) -> Result<HostResourceAllocations> {
        let mut storage = std::collections::BTreeMap::new();
        for mapping in self
            .desired
            .entries
            .iter()
            .chain(self.current.into_iter().flat_map(|map| &map.entries))
        {
            let NativeResourceQualification::HostStorage { cluster, purpose } =
                &mapping.qualification
            else {
                continue;
            };
            let request = StorageAllocationRequest {
                resource: mapping.resource.clone(),
                cluster: cluster.clone(),
                purpose: purpose.clone(),
            };
            if let Some(previous) = storage.insert(mapping.resource.clone(), request) {
                ensure!(
                    previous.cluster == *cluster && previous.purpose == *purpose,
                    "retained storage resource changed its stable identity"
                );
            }
        }

        let mut postgresql_storage = std::collections::BTreeMap::new();
        let mut postgresql_endpoint = std::collections::BTreeMap::new();
        for mapping in &self.desired.entries {
            if !matches!(
                mapping.qualification,
                NativeResourceQualification::Postgresql { .. }
            ) {
                continue;
            }
            let dependencies = self.host_resource_dependencies(mapping)?;
            let storage_bindings = dependencies
                .values()
                .flatten()
                .filter(|binding| binding.input == "storage_path")
                .collect::<Vec<_>>();
            let Some(binding) = storage_bindings.first() else {
                continue;
            };
            ensure!(
                storage_bindings.iter().all(|candidate| {
                    candidate.resource == binding.resource
                        && candidate.revision == binding.revision
                        && candidate.qualification == binding.qualification
                        && candidate.interface == binding.interface
                        && candidate.output == binding.output
                }),
                "PostgreSQL consumers disagree about their storage producer"
            );
            ensure!(
                postgresql_storage
                    .insert(mapping.resource.clone(), binding.resource.clone())
                    .is_none(),
                "PostgreSQL resource has duplicate storage bindings"
            );
            let endpoint_bindings = dependencies
                .values()
                .flatten()
                .filter(|binding| binding.input == "endpoint")
                .collect::<Vec<_>>();
            if let Some(endpoint) = endpoint_bindings.first() {
                ensure!(
                    endpoint_bindings.iter().all(|candidate| {
                        candidate.resource == endpoint.resource
                            && candidate.revision == endpoint.revision
                            && candidate.qualification == endpoint.qualification
                            && candidate.interface == endpoint.interface
                            && candidate.output == endpoint.output
                    }),
                    "PostgreSQL consumers disagree about their endpoint producer"
                );
                ensure!(
                    postgresql_endpoint
                        .insert(mapping.resource.clone(), endpoint.resource.clone())
                        .is_none(),
                    "PostgreSQL resource has duplicate endpoint bindings"
                );
            }
        }
        HostResourceAllocations::build(
            storage.into_values().collect(),
            postgresql_storage,
            postgresql_endpoint,
        )
        .context("allocating persistent host-resource slots")
    }

    fn host_resource_dependencies(
        &self,
        mapping: &NativeResourceMapping,
    ) -> Result<std::collections::BTreeMap<ScopedOperationKey, Vec<NativeDependencyBinding>>> {
        let kind = NativeHostResourceKind::from_qualification(&mapping.qualification)
            .context("native mapping is not a host resource")?;
        let expected_inputs: &[(&str, &[&str], &str)] = match kind {
            NativeHostResourceKind::Postgresql => &[
                (
                    "credential_view",
                    &["deliver", "acquire"],
                    aos_ability_model::builtin::CREDENTIAL_VIEW_OUTPUT,
                ),
                (
                    "endpoint",
                    &["materialize", "observe"],
                    aos_ability_model::builtin::NETWORK_ENDPOINT_OUTPUT,
                ),
                (
                    "storage_path",
                    &["ensure", "observe"],
                    aos_ability_model::builtin::HOST_STORAGE_PATH_OUTPUT,
                ),
            ],
            NativeHostResourceKind::NetworkPolicy => &[(
                "endpoint",
                &["materialize", "observe"],
                aos_ability_model::builtin::NETWORK_ENDPOINT_OUTPUT,
            )],
            _ => return Ok(std::collections::BTreeMap::new()),
        };
        let target_methods: &[&str] = match kind {
            NativeHostResourceKind::Postgresql => &["materialize", "observe"],
            NativeHostResourceKind::NetworkPolicy => &["apply", "observe"],
            _ => unreachable!(),
        };
        let operations = self.plan.operations().iter().filter(|operation| {
            operation.target.resource == mapping.resource
                && target_methods.contains(&operation.method.as_str())
        });
        let mut by_consumer = std::collections::BTreeMap::new();
        for operation in operations {
            let ValueExpression::Object { fields } = &operation.inputs else {
                return Err(anyhow!("host-resource inputs are not a closed object"));
            };
            let mut dependencies = Vec::new();
            for (input, expected_methods, expected_output) in expected_inputs {
                let expression = fields
                    .get(*input)
                    .context("host-resource input is absent from its checked request")?;
                if matches!(kind, NativeHostResourceKind::Postgresql)
                    && matches!(expression, ValueExpression::Literal { value } if value.as_json().is_null())
                {
                    continue;
                }
                let ValueExpression::OperationResult { reference } = expression else {
                    return Err(anyhow!(
                        "host-resource dependency is not a direct operation result"
                    ));
                };
                let ResultProducerKey::Operation { key } = &reference.producer else {
                    return Err(anyhow!(
                        "host-resource dependency does not have unambiguous operation lineage"
                    ));
                };
                let producer = self
                    .plan
                    .operation(key)
                    .context("host-resource dependency producer is absent")?;
                ensure!(
                    expected_methods.contains(&producer.method.as_str())
                        && reference.output.as_str() == *expected_output,
                    "host-resource dependency uses the wrong producer method or output"
                );
                let from = PlanNodeKey::Operation { key: key.clone() };
                let to = PlanNodeKey::Operation {
                    key: operation.key.clone(),
                };
                ensure!(
                    self.plan.edges().iter().any(|edge| {
                        edge.from == from && edge.to == to && edge.kind == DependencyKind::Data
                    }),
                    "host-resource dependency has no exact checked data edge"
                );
                let producer_mapping = self
                    .desired
                    .entries
                    .iter()
                    .find(|candidate| candidate.resource == producer.target.resource)
                    .context("host-resource dependency has no native producer mapping")?;
                let producer_route = self.preflight_mapping(producer_mapping)?;
                let expected_kind = match *input {
                    "credential_view" => NativeHostResourceKind::Credential,
                    "endpoint" => NativeHostResourceKind::Endpoint,
                    "storage_path" => NativeHostResourceKind::Storage,
                    _ => return Err(anyhow!("unknown host-resource dependency input")),
                };
                ensure!(
                    producer_route.kind == NativeAdapterKind::HostResource(expected_kind)
                        && producer_route.assignment_interface == producer.interface,
                    "host-resource dependency selects another provider contract"
                );
                dependencies.push(NativeDependencyBinding {
                    input: (*input).to_string(),
                    producer: key.clone(),
                    resource: producer.target.resource.clone(),
                    revision: producer_mapping.revision,
                    qualification: producer_mapping.qualification.clone(),
                    interface: producer.interface.clone(),
                    method: producer.method.clone(),
                    output: reference.output.clone(),
                });
            }
            dependencies.sort_by(|left, right| left.input.cmp(&right.input));
            ensure!(
                by_consumer
                    .insert(operation.key.clone(), dependencies)
                    .is_none(),
                "host-resource dependency map contains a duplicate consumer"
            );
        }
        Ok(by_consumer)
    }

    fn current_mapping(&self, resource: &ResourceId) -> Option<&'a NativeResourceMapping> {
        self.current?
            .entries
            .iter()
            .find(|mapping| &mapping.resource == resource)
    }

    fn retained_resources_match_execution(&self) -> bool {
        let Some(current) = self.current else {
            return false;
        };
        retained_maps_match_execution(self.desired, current)
    }

    fn activation_desired_state(&self) -> &'a DesiredStateDocument {
        self.desired_state
    }

    fn activation_current_desired_state(&self) -> Result<&'a DesiredStateDocument> {
        self.current_desired_state
            .context("native teardown dispatch has no retained current desired state")
    }

    fn validate_manager_readiness_contracts(&self) -> Result<()> {
        for operation in self.plan.operations() {
            if operation.method.as_str() == "observe-manager" {
                ensure!(
                    self.plan
                        .document()
                        .provider_readiness
                        .iter()
                        .any(|readiness| readiness.producer == operation.key),
                    "native observe-manager operation has no planned manager output"
                );
            }
        }

        let mut producer_outputs = std::collections::BTreeSet::new();
        for readiness in &self.plan.document().provider_readiness {
            let producer = self
                .plan
                .operation(&readiness.producer)
                .context("native manager readiness producer is absent")?;
            let route = self.route(producer)?;
            let binding = self
                .plan
                .binding_plan()
                .binding(&readiness.binding)
                .context("native manager readiness binding is absent")?;
            ensure!(
                route.kind == NativeAdapterKind::Systemd
                    && route.assignment_interface
                        == aos_ability_model::builtin::systemd_provider_bootstrap_interface_key()?
                    && producer.method.as_str() == "observe-manager"
                    && matches!(
                        binding.interface.name.as_str(),
                        aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME
                            | aos_ability_model::builtin::KUBERNETES_OBJECT_INTERFACE_NAME
                    ),
                "native planned-provider readiness is not an exact supported provider bootstrap"
            );
            if binding.interface.name.as_str()
                == aos_ability_model::builtin::KUBERNETES_OBJECT_INTERFACE_NAME
            {
                self.kubernetes_capability_spec(&binding.provider)?;
            }
            ensure!(
                producer_outputs.insert((readiness.producer.clone(), readiness.output.clone())),
                "native planned manager readiness reuses one output for multiple bindings"
            );
        }
        Ok(())
    }

    fn planned_manager_bootstrap_resource(
        &self,
        operation: &aos_ability_model::ScopedOperationKey,
    ) -> Result<ResourceId> {
        let consumer = self
            .plan
            .operation(operation)
            .context("planned manager consumer operation is absent")?;
        let readiness = self
            .plan
            .provider_readiness(&consumer.binding)
            .context("planned manager consumer has no readiness declaration")?;
        let producer = self
            .plan
            .operation(&readiness.producer)
            .context("planned manager readiness producer is absent")?;
        Ok(self.route(producer)?.mapping.resource.clone())
    }

    fn kubernetes_capability(
        &self,
        provider: &aos_ability_model::InstanceId,
    ) -> Result<KubernetesApiCapability> {
        let (package, kubectl, kubeconfig) = self.kubernetes_capability_spec(provider)?;
        KubernetesApiCapability::new(package, kubectl, Path::new(kubeconfig))
            .context("authenticating Kubernetes API capability")
    }

    fn kubernetes_capability_spec(
        &self,
        provider: &aos_ability_model::InstanceId,
    ) -> Result<(
        &VerifiedAbilityPackage,
        &aos_ability_model::ArtifactReference,
        &str,
    )> {
        let mut selected: Option<(
            &aos_ability_model::ArtifactReference,
            &str,
            &NativeResourceMapping,
        )> = None;
        for mapping in self
            .desired
            .entries
            .iter()
            .chain(self.current.into_iter().flat_map(|map| &map.entries))
            .filter(|mapping| &mapping.resource.provider == provider)
        {
            let NativeResourceQualification::KubernetesObject {
                kubectl,
                kubeconfig,
                ..
            } = &mapping.qualification
            else {
                continue;
            };
            if let Some((selected_kubectl, selected_kubeconfig, _)) = selected {
                ensure!(
                    selected_kubectl == kubectl && selected_kubeconfig == kubeconfig,
                    "one Kubernetes provider maps to multiple cluster capabilities"
                );
            } else {
                selected = Some((kubectl, kubeconfig, mapping));
            }
        }
        let (kubectl, kubeconfig, mapping) =
            selected.context("planned Kubernetes provider has no qualified cluster capability")?;
        let package = self
            .packages
            .iter()
            .find(|package| package.package_digest() == mapping.owner_package)
            .context("Kubernetes capability owner package is not authenticated")?;
        ensure!(
            package.artifacts().contains(kubectl),
            "Kubernetes capability artifact is outside its owner package"
        );
        Ok((package, kubectl, kubeconfig))
    }

    fn preflight_readiness_output(
        &self,
        systemd: &SystemdManagerCapabilities,
        output: aos_ability_model::LocalKey,
        binding: &Binding,
        bootstrap_resource: &ResourceId,
    ) -> Result<()> {
        match binding.interface.name.as_str() {
            aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME => systemd
                .readiness_output(output, binding, bootstrap_resource)
                .map(|_| ()),
            aos_ability_model::builtin::KUBERNETES_OBJECT_INTERFACE_NAME => self
                .kubernetes_capability_spec(&binding.provider)
                .map(|_| ()),
            _ => Err(anyhow!(
                "planned provider readiness targets an unsupported native interface"
            )),
        }
    }

    fn readiness_output(
        &self,
        systemd: &SystemdManagerCapabilities,
        output: aos_ability_model::LocalKey,
        binding: &Binding,
        bootstrap_resource: &ResourceId,
    ) -> Result<NativeProviderReadinessOutput> {
        match binding.interface.name.as_str() {
            aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME => systemd
                .readiness_output(output, binding, bootstrap_resource)
                .map(NativeProviderReadinessOutput::Systemd),
            aos_ability_model::builtin::KUBERNETES_OBJECT_INTERFACE_NAME => {
                let (package, kubectl, kubeconfig) =
                    self.kubernetes_capability_spec(&binding.provider)?;
                let capability =
                    DeferredKubernetesApiCapability::new(package, kubectl, Path::new(kubeconfig))?;
                KubernetesClusterReadinessOutput::new(output, binding, capability)
                    .map(NativeProviderReadinessOutput::Kubernetes)
            }
            _ => Err(anyhow!(
                "planned provider readiness targets an unsupported native interface"
            )),
        }
    }

    fn preflight_mapping(
        &self,
        mapping: &'a NativeResourceMapping,
    ) -> Result<NativeAdapterRoute<'a>> {
        let package = self
            .packages
            .iter()
            .find(|package| package.package_digest() == mapping.owner_package)
            .context("native dispatcher mapping owner package is not authenticated")?;
        let handler = mapping
            .implementation
            .handler
            .as_ref()
            .context("native dispatcher mapping does not select a terminal handler")?;
        let terminal = package
            .resolve_terminal_handler(mapping.implementation.descriptor, handler)
            .context("native dispatcher package does not resolve the mapped terminal handler")?;
        ensure!(
            terminal.provider().artifact == mapping.implementation.artifact
                && terminal.handler().artifact == mapping.implementation.artifact,
            "native dispatcher terminal artifact differs from the mapped implementation"
        );
        let assignment_interface = terminal.provider().interface.clone();
        let assignment = ProviderAssignment {
            provider: mapping.resource.provider.clone(),
            interface: assignment_interface.clone(),
            implementation: mapping.implementation.clone(),
            incarnation: IncarnationId::new("native-static-preflight")
                .context("constructing native adapter preflight assignment")?,
        };
        let kind = match &mapping.qualification {
            NativeResourceQualification::ManagedConfiguration { .. } => {
                preflight_native_managed_configuration(package, &assignment)
                    .context("preflighting managed-configuration adapter")?;
                NativeAdapterKind::ManagedConfiguration
            }
            NativeResourceQualification::NginxValidation { executable, .. } => {
                preflight_native_nginx(package, &assignment, executable)
                    .context("preflighting nginx adapter")?;
                NativeAdapterKind::NginxValidation
            }
            NativeResourceQualification::SystemdService { .. } => {
                preflight_native_systemd(package, &assignment)
                    .context("preflighting systemd adapter")?;
                NativeAdapterKind::Systemd
            }
            NativeResourceQualification::KubernetesObject { .. } => {
                preflight_native_kubernetes(package, &assignment)
                    .context("preflighting Kubernetes object adapter")?;
                NativeAdapterKind::KubernetesObject
            }
            qualification => {
                let kind = NativeHostResourceKind::from_qualification(qualification)
                    .context("native mapping has no built-in adapter qualification")?;
                preflight_native_host_resource(package, &assignment, qualification, kind)
                    .context("preflighting native host-resource adapter")?;
                NativeAdapterKind::HostResource(kind)
            }
        };

        Ok(NativeAdapterRoute {
            package,
            mapping,
            desired_state: self.desired_state,
            generation: NativeResourceGeneration::Desired,
            assignment_interface,
            kind,
        })
    }
}

pub(crate) fn retained_maps_match_execution(
    desired: &NativeResourceMap,
    current: &NativeResourceMap,
) -> bool {
    desired.entries.len() == current.entries.len()
        && desired
            .entries
            .iter()
            .zip(&current.entries)
            .all(|(desired, current)| {
                desired.resource == current.resource
                    && desired.revision == current.revision
                    && desired.implementation == current.implementation
                    && desired.qualification == current.qualification
            })
}

/// Executes a preflighted native graph through the closed built-in adapter set.
pub(crate) struct NativeDispatcher<'a> {
    registry: NativeAdapterRegistry<'a>,
    assignments: Vec<ProviderAssignment>,
    systemd: SystemdManagerCapabilities,
}

/// Carries one complete, read-only classification of the retained native map.
pub(crate) struct NativeDriftClassification {
    runtime: Vec<RuntimeResourceObservation>,
    authority: Vec<CurrentResourceObservation>,
    assignments: Vec<ProviderAssignment>,
    requires_reconciliation: bool,
}

impl NativeDriftClassification {
    /// Reports whether any classified resource needs a repair graph.
    #[must_use]
    pub(crate) fn requires_reconciliation(&self) -> bool {
        self.requires_reconciliation
    }

    /// Returns exact observations retained by linked transition provenance.
    #[must_use]
    pub(crate) fn runtime_observations(&self) -> &[RuntimeResourceObservation] {
        &self.runtime
    }

    /// Returns resource states published through protected current authority.
    #[must_use]
    pub(crate) fn authority_observations(&self) -> &[CurrentResourceObservation] {
        &self.authority
    }

    /// Returns provider assignments established during the same classification.
    #[must_use]
    pub(crate) fn assignments(&self) -> &[ProviderAssignment] {
        &self.assignments
    }
}

impl<'a> NativeDispatcher<'a> {
    /// Validates the complete native route set without opening live handles.
    ///
    /// # Errors
    ///
    /// Returns an error when any possible operation lacks an authenticated,
    /// supported built-in route.
    pub(crate) fn preflight(
        activation: &'a SpecializedAbilityActivation,
        packages: &'a VerifiedAbilityPackageSet,
    ) -> Result<()> {
        NativeAdapterRegistry::new(activation, packages).map(|_| ())
    }

    /// Constructs a dispatcher only after the complete graph and package union pass preflight.
    ///
    /// `packages` must be the independently verified union of desired and
    /// retained package generations. Exact owner digests select old artifacts
    /// for teardown after a provider upgrade.
    ///
    /// # Errors
    ///
    /// Returns an error when any operation, including an inactive branch,
    /// lacks an exact built-in route or supported effect and recovery methods.
    pub(crate) fn new(
        activation: &'a SpecializedAbilityActivation,
        packages: &'a VerifiedAbilityPackageSet,
        systemd: Arc<aos_systemd::SystemdManagerConnection>,
    ) -> Result<Self> {
        let environment = activation
            .plan()
            .binding_plan()
            .environment()
            .environment
            .clone();
        let systemd = SystemdManagerCapabilities::single_host(environment, systemd)
            .context("registering host systemd capability")?;
        Self::new_with_systemd_capabilities(activation, packages, systemd)
    }

    /// Constructs a dispatcher from caller-authenticated scoped manager transports.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::new`]. Planned
    /// manager bindings additionally require an exact scoped capability.
    pub(crate) fn new_with_systemd_capabilities(
        activation: &'a SpecializedAbilityActivation,
        packages: &'a VerifiedAbilityPackageSet,
        systemd: SystemdManagerCapabilities,
    ) -> Result<Self> {
        let registry = NativeAdapterRegistry::new(activation, packages)?;
        for readiness in &registry.plan.document().provider_readiness {
            let producer = registry
                .plan
                .operation(&readiness.producer)
                .context("planned manager readiness producer disappeared after preflight")?;
            let route = registry.route(producer)?;
            let binding = registry
                .plan
                .binding_plan()
                .binding(&readiness.binding)
                .context("planned manager readiness binding disappeared after preflight")?;
            registry
                .preflight_readiness_output(
                    &systemd,
                    readiness.output.clone(),
                    binding,
                    &route.mapping.resource,
                )
                .context("preflighting planned native provider capability")?;
        }
        Ok(Self {
            registry,
            assignments: Vec::new(),
            systemd,
        })
    }

    /// Classifies every desired native resource without issuing an effect.
    ///
    /// The caller must retain the machine-global switch lock through
    /// classification, current-authority publication, and repair planning.
    /// Every resource is requalified through its trusted catalog. Transient or
    /// unavailable states fail closed instead of selecting a repair action.
    ///
    /// # Errors
    ///
    /// Returns an error when the source plan is not effect-free, a provider or
    /// resource cannot be requalified, consumer evidence is foreign or
    /// unavailable, or the complete desired map is not classified exactly once.
    pub(crate) fn classify_retained_resources(
        &mut self,
        session: &NativeObservationSession,
    ) -> Result<NativeDriftClassification> {
        ensure!(
            self.registry.plan.operations().is_empty(),
            "native drift classification requires an effect-free source plan"
        );
        ensure!(
            self.registry.retained_resources_match_execution(),
            "native drift classification requires identical retained execution semantics"
        );

        for mapping in &self.registry.desired.entries {
            let route = self.registry.preflight_mapping(mapping)?;
            if self.registry.assignment(&route, &self.assignments).is_err() {
                let assignment = self.native_observation_assignment(session, &route)?;
                Self::retain_assignment(&mut self.assignments, assignment)?;
            }
        }

        let mut runtime = Vec::with_capacity(self.registry.desired.entries.len());
        let mut authority = Vec::with_capacity(self.registry.desired.entries.len());
        let mut requires_reconciliation = false;
        for mapping in &self.registry.desired.entries {
            let route = self.registry.preflight_mapping(mapping)?;
            let assignment = self.registry.assignment(&route, &self.assignments)?;
            let inventory = session.resource_inventory();
            let state = match route.kind {
                NativeAdapterKind::KubernetesObject => {
                    let spec = self.registry.kubernetes_spec(&route)?;
                    let catalog = KubernetesObjectResourceCatalog::new(
                        route.package,
                        assignment,
                        inventory,
                        0,
                        [spec],
                    )
                    .context("constructing Kubernetes drift catalog")?;
                    catalog
                        .classify_runtime_revision(&mapping.resource)
                        .context("classifying current Kubernetes object")?
                        .1
                }
                NativeAdapterKind::ManagedConfiguration => {
                    let spec = self.registry.managed_configuration_spec(&route)?;
                    let catalog = ManagedConfigurationResourceCatalog::new(
                        Path::new("/"),
                        Path::new(MANAGED_CONFIGURATION_STATE_ROOT),
                        assignment,
                        inventory,
                        0,
                        [spec],
                    )
                    .context("constructing managed-configuration drift catalog")?;
                    catalog
                        .classify_runtime_revision(&mapping.resource)
                        .context("classifying current managed configuration")?
                        .1
                }
                NativeAdapterKind::NginxValidation => {
                    let spec = self.registry.nginx_spec(&route)?;
                    let catalog = NginxResourceCatalog::new(
                        Path::new(NGINX_STATE_ROOT),
                        assignment,
                        inventory,
                        0,
                        [spec],
                    )
                    .context("constructing nginx drift catalog")?;
                    catalog
                        .classify_runtime_revision(&mapping.resource)
                        .context("classifying current nginx association")?
                        .1
                }
                NativeAdapterKind::Systemd => {
                    let spec = self.registry.systemd_spec(&route)?;
                    let connection = self
                        .systemd
                        .reacquire_assignment(&assignment)
                        .context("reacquiring systemd capability for drift classification")?;
                    let catalog =
                        SystemdResourceCatalog::new(connection, assignment, inventory, [spec])
                            .context("constructing systemd drift catalog")?;
                    let (_, active_state) = catalog
                        .classify_runtime_state(&mapping.resource)
                        .context("classifying current systemd resource")?;
                    match active_state {
                        SystemdResourceRuntimeState::Stopped => RuntimeResourceState::Present {
                            revision: mapping.revision,
                            health: RuntimeResourceHealth::Stopped,
                        },
                        SystemdResourceRuntimeState::Active => {
                            let NativeResourceQualification::SystemdService {
                                consumer_observation,
                                ..
                            } = &mapping.qualification
                            else {
                                return Err(anyhow!(
                                    "systemd drift route changed resource qualification"
                                ));
                            };
                            if let Some(expected_consumer) = consumer_observation {
                                let observed_consumer =
                                    classify_native_http_consumer(expected_consumer)
                                        .context("classifying actual systemd service consumer")?;
                                let health = if observed_consumer.controller_revision
                                    == expected_consumer.expected_controller_revision
                                    && observed_consumer.content_revision
                                        == expected_consumer.expected_content_revision
                                {
                                    RuntimeResourceHealth::Healthy
                                } else {
                                    RuntimeResourceHealth::Divergent
                                };
                                RuntimeResourceState::Present {
                                    // The checked systemd receipt established the
                                    // resource revision; consumer headers only
                                    // classify behavior at that revision.
                                    revision: mapping.revision,
                                    health,
                                }
                            } else {
                                RuntimeResourceState::Present {
                                    revision: mapping.revision,
                                    health: RuntimeResourceHealth::Healthy,
                                }
                            }
                        }
                    }
                }
                NativeAdapterKind::HostResource(kind) => {
                    let spec = self.registry.host_resource_spec(&route)?;
                    let catalog =
                        NativeHostResourceCatalog::new(assignment, inventory, kind, [spec])
                            .context("constructing host-resource drift catalog")?;
                    catalog
                        .classify_runtime_state(&mapping.resource)
                        .context("classifying current host resource")?
                        .1
                }
            };
            let authority_state = current_authority_state(state);
            requires_reconciliation |= !matches!(
                state,
                RuntimeResourceState::Present {
                    revision,
                    health: RuntimeResourceHealth::Healthy,
                } if revision == mapping.revision
            );
            runtime.push(RuntimeResourceObservation {
                resource: mapping.resource.clone(),
                state,
            });
            authority.push(CurrentResourceObservation {
                resource: mapping.resource.clone(),
                state: authority_state,
            });
        }
        Ok(NativeDriftClassification {
            runtime,
            authority,
            assignments: self.assignments.clone(),
            requires_reconciliation,
        })
    }

    fn native_observation_assignment(
        &self,
        session: &NativeObservationSession,
        route: &NativeAdapterRoute<'_>,
    ) -> Result<ProviderAssignment> {
        if route.kind == NativeAdapterKind::Systemd {
            return self
                .systemd
                .observe_assignment(
                    &route.mapping.resource.provider,
                    &route.assignment_interface,
                    &route.mapping.implementation,
                )
                .context("observing the current systemd manager assignment");
        }
        if route.kind == NativeAdapterKind::KubernetesObject {
            let NativeResourceQualification::KubernetesObject {
                kubectl,
                kubeconfig,
                ..
            } = &route.mapping.qualification
            else {
                return Err(anyhow!(
                    "Kubernetes drift route changed resource qualification"
                ));
            };
            let capability =
                KubernetesApiCapability::new(route.package, kubectl, Path::new(kubeconfig))?;
            let incarnation = capability
                .observe_incarnation_bounded(30_000)
                .context("observing the current Kubernetes provider assignment")?;
            return Ok(ProviderAssignment {
                provider: route.mapping.resource.provider.clone(),
                interface: route.assignment_interface.clone(),
                implementation: route.mapping.implementation.clone(),
                incarnation,
            });
        }
        let incarnation = IncarnationId::new(format!(
            "native/{}/{}",
            session.transaction().0.as_str(),
            route.mapping.implementation.descriptor.hex()
        ))
        .context("constructing native observation assignment")?;
        Ok(ProviderAssignment {
            provider: route.mapping.resource.provider.clone(),
            interface: route.assignment_interface.clone(),
            implementation: route.mapping.implementation.clone(),
            incarnation,
        })
    }

    /// Runs stable single-operation batches while reporting exact boundaries.
    ///
    /// Keeping each admitted token through dispatch, reconciliation, and
    /// release prevents process-scoped resource ownership from being dropped
    /// between runtime state-machine steps.
    ///
    /// # Errors
    ///
    /// Returns an error for admission, adapter, persistence, cleanup,
    /// intervention, nonterminal scheduling failure, or when the explicitly
    /// configured observer fails closed. The caller must drop the session and
    /// recover the same transaction after such a failure.
    pub(crate) fn run_to_terminal_with_observer<Policy, NoOpVerifier, Observer>(
        &mut self,
        session: &mut NativeAbilitySession<'a>,
        policy: &mut OperatorAuthorizedPolicy<'_, Policy>,
        no_op_verifier: &mut NoOpVerifier,
        cancellation: &CancellationToken,
        observer: &mut Observer,
    ) -> Result<TerminalResult>
    where
        Policy: NativeAuthorityRefresh,
        NoOpVerifier: TrustedNativeNoOpVerifier,
        Observer: ExecutionBoundaryObserver,
    {
        let clock = SystemMonotonicClock::new();
        loop {
            if let Some(terminal) = session.transaction().summary().terminal() {
                if self.registry.plan.operations().is_empty() {
                    self.ensure_no_op_assignments(session)?;
                    return self.verify_no_op(session, policy, no_op_verifier, terminal);
                }
                return Ok(terminal);
            }
            ensure!(
                !cancellation.is_cancelled(),
                "native activation was cancelled before another operation could be admitted"
            );
            let ready = session
                .schedule_ready(NonZeroUsize::MIN)
                .map_err(anyhow::Error::new)?;
            let item = ready
                .first()
                .context("native transaction is nonterminal but has no schedulable operation")?;
            let operation = session
                .transaction()
                .plan()
                .operation(item.operation())
                .context("native scheduler returned an operation outside its plan")?;

            match item.action() {
                RecoveryAction::SettleFailureBeforeEffect => {
                    let evidence =
                        aos_ability_model::AbilityValue::new(serde_json::Value::Bool(false))
                            .context("constructing native failure evidence")?;
                    session
                        .settle_failure_before_effect(item.operation(), evidence)
                        .map_err(anyhow::Error::new)?;
                    continue;
                }
                RecoveryAction::AwaitRetryBackoff {
                    eligible_at_millis, ..
                } => {
                    wait_for_retry_eligibility(&clock, cancellation, *eligible_at_millis)?;
                }
                RecoveryAction::InterventionRequired
                | RecoveryAction::CompensationInterventionRequired => {
                    return Err(anyhow!(
                        "native operation {:?} requires operator intervention",
                        item.operation()
                    ));
                }
                _ => {}
            }

            let route = self.registry.route(operation)?;
            let (assignment, planned_bootstrap) = Self::assignment_for_operation(
                &self.registry,
                &mut self.assignments,
                &self.systemd,
                session,
                item.operation(),
                &route,
            )?;
            let recovering_resource = matches!(
                item.action(),
                RecoveryAction::ReconcileBeforeRetry { .. } | RecoveryAction::ReconcileCompensation
            )
            .then_some(&operation.target.resource);
            let resources = self.observe_current_resources(session, recovering_resource)?;
            policy.refresh_authority(&self.assignments, resources)?;
            self.dispatch_route(
                session,
                item.operation(),
                route,
                assignment,
                planned_bootstrap.as_ref(),
                policy,
                &clock,
                cancellation,
                observer,
            )?;
        }
    }

    fn assignment_for_operation(
        registry: &NativeAdapterRegistry<'_>,
        assignments: &mut Vec<ProviderAssignment>,
        systemd: &SystemdManagerCapabilities,
        session: &NativeAbilitySession<'a>,
        operation: &aos_ability_model::ScopedOperationKey,
        route: &NativeAdapterRoute<'_>,
    ) -> Result<(ProviderAssignment, Option<ResourceId>)> {
        if let Some(assignment) = session
            .transaction()
            .provider_assignment_for(operation)
            .map_err(anyhow::Error::new)?
        {
            registry.require_route_assignment(route, &assignment)?;
            let bootstrap_resource = registry.planned_manager_bootstrap_resource(operation)?;
            match assignment.interface.name.as_str() {
                aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME => systemd
                    .reacquire_planned_assignment(&assignment, &bootstrap_resource)
                    .context("reacquiring planned systemd provider capability")
                    .map(|_| ())?,
                aos_ability_model::builtin::KUBERNETES_OBJECT_INTERFACE_NAME => {
                    let capability = registry.kubernetes_capability(&assignment.provider)?;
                    reacquire_kubernetes_assignment(&capability, &assignment)
                        .context("reacquiring planned Kubernetes provider capability")?;
                }
                _ => {
                    return Err(anyhow!(
                        "planned native assignment uses an unsupported provider interface"
                    ));
                }
            }
            Self::retain_assignment(assignments, assignment.clone())?;
            return Ok((assignment, Some(bootstrap_resource)));
        }
        if let Ok(assignment) = registry.assignment(route, assignments) {
            return Ok((assignment, None));
        }

        let assignment = Self::native_assignment(systemd, session, route)?;
        Self::retain_assignment(assignments, assignment.clone())?;
        Ok((assignment, None))
    }

    fn ensure_no_op_assignments(&mut self, session: &NativeAbilitySession<'a>) -> Result<()> {
        for mapping in &self.registry.desired.entries {
            let route = self.registry.preflight_mapping(mapping)?;
            if self.registry.assignment(&route, &self.assignments).is_ok() {
                continue;
            }
            let assignment = Self::native_assignment(&self.systemd, session, &route)?;
            Self::retain_assignment(&mut self.assignments, assignment)?;
        }
        Ok(())
    }

    fn native_assignment(
        systemd: &SystemdManagerCapabilities,
        session: &NativeAbilitySession<'a>,
        route: &NativeAdapterRoute<'_>,
    ) -> Result<ProviderAssignment> {
        if route.kind == NativeAdapterKind::Systemd {
            return systemd
                .observe_assignment(
                    &route.mapping.resource.provider,
                    &route.assignment_interface,
                    &route.mapping.implementation,
                )
                .context("observing the current systemd manager assignment");
        }

        if route.kind == NativeAdapterKind::KubernetesObject {
            let NativeResourceQualification::KubernetesObject {
                kubectl,
                kubeconfig,
                ..
            } = &route.mapping.qualification
            else {
                return Err(anyhow!(
                    "Kubernetes adapter route changed qualification class"
                ));
            };
            let capability =
                KubernetesApiCapability::new(route.package, kubectl, Path::new(kubeconfig))?;
            let incarnation = capability
                .observe_incarnation_bounded(30_000)
                .context("observing the current Kubernetes provider assignment")?;
            return Ok(ProviderAssignment {
                provider: route.mapping.resource.provider.clone(),
                interface: route.assignment_interface.clone(),
                implementation: route.mapping.implementation.clone(),
                incarnation,
            });
        }

        let incarnation = IncarnationId::new(format!(
            "native/{}/{}",
            session.transaction().transaction().0.as_str(),
            route.mapping.implementation.descriptor.hex()
        ))
        .context("constructing native executor assignment")?;
        Ok(ProviderAssignment {
            provider: route.mapping.resource.provider.clone(),
            interface: route.assignment_interface.clone(),
            implementation: route.mapping.implementation.clone(),
            incarnation,
        })
    }

    fn retain_assignment(
        assignments: &mut Vec<ProviderAssignment>,
        assignment: ProviderAssignment,
    ) -> Result<()> {
        match assignments.binary_search_by(|candidate| candidate.provider.cmp(&assignment.provider))
        {
            Ok(index) if assignments[index] == assignment => Ok(()),
            Ok(_) => Err(anyhow!(
                "native provider assignment changed within one authority refresh interval"
            )),
            Err(index) => {
                assignments.insert(index, assignment);
                Ok(())
            }
        }
    }

    fn verify_no_op<Policy, NoOpVerifier>(
        &self,
        session: &mut NativeAbilitySession<'a>,
        policy: &mut OperatorAuthorizedPolicy<'_, Policy>,
        verifier: &mut NoOpVerifier,
        terminal: TerminalResult,
    ) -> Result<TerminalResult>
    where
        Policy: NativeAuthorityRefresh,
        NoOpVerifier: TrustedNativeNoOpVerifier,
    {
        ensure!(
            terminal == TerminalResult::Succeeded,
            "empty native transaction reached a non-success terminal state"
        );
        let current_resources = self
            .registry
            .current
            .context("empty native transition has no authenticated retained resource map")?;
        let current_desired_state = self.registry.activation_current_desired_state()?;
        ensure!(
            self.registry.retained_resources_match_execution(),
            "empty native transition changed retained execution semantics"
        );

        let resource_observations = self.observe_no_op_resources(session)?;
        let current_observations = resource_observations
            .iter()
            .map(|observation| CurrentResourceObservation {
                resource: observation.qualified.logical().clone(),
                state: CurrentResourceState::Present {
                    revision: observation.revision,
                },
            })
            .collect();
        policy.refresh_authority(&self.assignments, current_observations)?;
        policy.authorize_no_op(&self.assignments, current_resources)?;
        verifier.verify_no_op(NativeNoOpEvidence {
            transaction: session.transaction().transaction(),
            plan: self.registry.plan,
            desired_state: self.registry.desired_state,
            current_desired_state,
            current_resources,
            current_planning: self
                .registry
                .current_planning
                .context("empty native transition lacks a retained planning commitment")?,
            assignments: &self.assignments,
            resources: &resource_observations,
        })?;
        session
            .persist_native_no_op_verification()
            .context("publishing native no-op verification evidence")?;
        Ok(terminal)
    }

    fn observe_no_op_resources(
        &self,
        session: &NativeAbilitySession<'a>,
    ) -> Result<Vec<NativeNoOpResourceObservation>> {
        let mut observations = Vec::with_capacity(self.registry.desired.entries.len());
        for mapping in &self.registry.desired.entries {
            let route = self.registry.preflight_mapping(mapping)?;
            let assignment = self.registry.assignment(&route, &self.assignments)?;
            let inventory = session.resource_inventory();
            let (qualified, revision, requires_consumer) = match route.kind {
                NativeAdapterKind::KubernetesObject => {
                    let spec = self.registry.kubernetes_spec(&route)?;
                    let catalog = KubernetesObjectResourceCatalog::new(
                        route.package,
                        assignment,
                        inventory,
                        0,
                        [spec],
                    )
                    .context("constructing Kubernetes no-op catalog")?;
                    let (qualified, observed) = catalog
                        .observe_no_op(&mapping.resource)
                        .context("observing Kubernetes no-op resource")?;
                    ensure!(
                        observed == ResourceRevisionObservation::Present(mapping.revision),
                        "Kubernetes resource drifted during no-op verification"
                    );
                    (qualified, mapping.revision, false)
                }
                NativeAdapterKind::ManagedConfiguration => {
                    let spec = self.registry.managed_configuration_spec(&route)?;
                    let catalog = ManagedConfigurationResourceCatalog::new(
                        Path::new("/"),
                        Path::new(MANAGED_CONFIGURATION_STATE_ROOT),
                        assignment,
                        inventory,
                        0,
                        [spec],
                    )
                    .context("constructing managed-configuration no-op catalog")?;
                    let (qualified, observed) = catalog
                        .observe_no_op(&mapping.resource)
                        .context("observing managed-configuration no-op resource")?;
                    let expected = ResourceRevisionObservation::Present(mapping.revision);
                    ensure!(
                        observed == expected,
                        "managed-configuration resource drifted during no-op verification"
                    );
                    (qualified, mapping.revision, false)
                }
                NativeAdapterKind::NginxValidation => {
                    let spec = self.registry.nginx_spec(&route)?;
                    let catalog = NginxResourceCatalog::new(
                        Path::new(NGINX_STATE_ROOT),
                        assignment,
                        inventory,
                        0,
                        [spec],
                    )
                    .context("constructing nginx no-op catalog")?;
                    let (qualified, observed) = catalog
                        .observe_no_op(&mapping.resource)
                        .context("observing nginx no-op resource")?;
                    let expected = ResourceRevisionObservation::Present(mapping.revision);
                    ensure!(
                        observed == expected,
                        "nginx resource drifted during no-op verification"
                    );
                    (qualified, mapping.revision, false)
                }
                NativeAdapterKind::Systemd => {
                    let spec = self.registry.systemd_spec(&route)?;
                    let connection = self
                        .systemd
                        .reacquire_assignment(&assignment)
                        .context("reacquiring systemd capability for no-op observation")?;
                    let catalog =
                        SystemdResourceCatalog::new(connection, assignment, inventory, [spec])
                            .context("constructing systemd no-op catalog")?;
                    let qualified = catalog
                        .observe_no_op(&mapping.resource)
                        .context("observing systemd no-op resource")?;
                    let NativeResourceQualification::SystemdService {
                        consumer_observation,
                        ..
                    } = &mapping.qualification
                    else {
                        return Err(anyhow!(
                            "systemd no-op route changed resource qualification"
                        ));
                    };
                    let requires_consumer = consumer_observation.is_some();
                    if let Some(consumer_observation) = consumer_observation {
                        observe_native_http_consumer(consumer_observation)
                            .context("observing actual systemd service consumer")?;
                    }
                    (qualified, mapping.revision, requires_consumer)
                }
                NativeAdapterKind::HostResource(kind) => {
                    let spec = self.registry.host_resource_spec(&route)?;
                    let catalog =
                        NativeHostResourceCatalog::new(assignment, inventory, kind, [spec])
                            .context("constructing host-resource no-op catalog")?;
                    let (qualified, observed) = catalog
                        .observe_no_op(&mapping.resource)
                        .context("observing host-resource no-op state")?;
                    ensure!(
                        observed == ResourceRevisionObservation::Present(mapping.revision),
                        "host resource drifted during no-op verification"
                    );
                    (qualified, mapping.revision, false)
                }
            };
            observations.push(NativeNoOpResourceObservation {
                qualified,
                revision,
                requires_consumer,
            });
        }
        Ok(observations)
    }

    fn observe_current_resources(
        &self,
        session: &NativeAbilitySession<'a>,
        recovering_resource: Option<&ResourceId>,
    ) -> Result<Vec<CurrentResourceObservation>> {
        let mut observations = std::collections::BTreeMap::new();
        for operation in self.registry.plan.operations() {
            let route = self.registry.route(operation)?;
            let Ok(assignment) = self.registry.assignment(&route, &self.assignments) else {
                continue;
            };
            let planned_bootstrap = session
                .transaction()
                .provider_assignment_for(&operation.key)
                .map_err(anyhow::Error::new)?
                .map(|_| {
                    self.registry
                        .planned_manager_bootstrap_resource(&operation.key)
                })
                .transpose()?;
            let state = self.observe_current_resource(
                session,
                &route,
                assignment,
                planned_bootstrap.as_ref(),
                recovering_resource,
            )?;
            if let Some(previous) = observations.insert(route.mapping.resource.clone(), state)
                && previous != state
            {
                return Err(anyhow!(
                    "native resource produced inconsistent current observations"
                ));
            }
        }
        Ok(observations
            .into_iter()
            .map(|(resource, state)| CurrentResourceObservation { resource, state })
            .collect())
    }

    fn observe_current_resource(
        &self,
        session: &NativeAbilitySession<'a>,
        route: &NativeAdapterRoute<'_>,
        assignment: ProviderAssignment,
        planned_bootstrap: Option<&ResourceId>,
        recovering_resource: Option<&ResourceId>,
    ) -> Result<CurrentResourceState> {
        let inventory = session.resource_inventory();
        let state = match route.kind {
            NativeAdapterKind::KubernetesObject => {
                let spec = self.registry.kubernetes_spec(route)?;
                let catalog = KubernetesObjectResourceCatalog::new(
                    route.package,
                    assignment,
                    inventory,
                    0,
                    [spec],
                )
                .context("constructing Kubernetes observation catalog")?;
                catalog
                    .classify_runtime_revision(&route.mapping.resource)
                    .context("observing current Kubernetes object revision")?
                    .1
            }
            NativeAdapterKind::ManagedConfiguration => {
                let spec = self.registry.managed_configuration_spec(route)?;
                let catalog = ManagedConfigurationResourceCatalog::new(
                    Path::new("/"),
                    Path::new(MANAGED_CONFIGURATION_STATE_ROOT),
                    assignment,
                    inventory,
                    0,
                    [spec],
                )
                .context("constructing managed-configuration observation catalog")?;
                catalog
                    .classify_runtime_revision(&route.mapping.resource)
                    .context("observing current managed-configuration revision")?
                    .1
            }
            NativeAdapterKind::NginxValidation => {
                let spec = self.registry.nginx_spec(route)?;
                let catalog = NginxResourceCatalog::new(
                    Path::new(NGINX_STATE_ROOT),
                    assignment,
                    inventory,
                    0,
                    [spec],
                )
                .context("constructing nginx observation catalog")?;
                catalog
                    .classify_runtime_revision(&route.mapping.resource)
                    .context("observing current nginx association")?
                    .1
            }
            NativeAdapterKind::Systemd => {
                let spec = self.registry.systemd_spec(route)?;
                let connection = if let Some(bootstrap_resource) = planned_bootstrap {
                    self.systemd
                        .reacquire_planned_assignment(&assignment, bootstrap_resource)
                        .context("reacquiring planned systemd capability for current observation")?
                } else {
                    self.systemd
                        .reacquire_assignment(&assignment)
                        .context("reacquiring systemd control capability for current observation")?
                };
                let catalog =
                    SystemdResourceCatalog::new(connection, assignment, inventory, [spec])
                        .context("observing current systemd unit revision")?;
                let (_, state) = catalog
                    .classify_runtime_state(&route.mapping.resource)
                    .context("classifying current systemd unit state")?;
                if state == SystemdResourceRuntimeState::Stopped {
                    RuntimeResourceState::Present {
                        revision: route.mapping.revision,
                        health: RuntimeResourceHealth::Stopped,
                    }
                } else {
                    let NativeResourceQualification::SystemdService {
                        consumer_observation,
                        ..
                    } = &route.mapping.qualification
                    else {
                        return Err(anyhow!(
                            "systemd current-observation route changed resource qualification"
                        ));
                    };
                    if let Some(expected_consumer) = consumer_observation {
                        let observed = classify_native_http_consumer(expected_consumer)
                            .context("classifying current systemd service consumer")?;
                        let health = if observed.controller_revision
                            == expected_consumer.expected_controller_revision
                            && observed.content_revision
                                == expected_consumer.expected_content_revision
                        {
                            RuntimeResourceHealth::Healthy
                        } else {
                            RuntimeResourceHealth::Divergent
                        };
                        RuntimeResourceState::Present {
                            // The checked systemd receipt established the
                            // resource revision; consumer headers only
                            // classify behavior at that revision.
                            revision: route.mapping.revision,
                            health,
                        }
                    } else {
                        RuntimeResourceState::Present {
                            revision: route.mapping.revision,
                            health: RuntimeResourceHealth::Healthy,
                        }
                    }
                }
            }
            NativeAdapterKind::HostResource(kind) => {
                let spec = self.registry.host_resource_spec(route)?;
                let catalog = NativeHostResourceCatalog::new(assignment, inventory, kind, [spec])
                    .context("constructing host-resource observation catalog")?;
                catalog
                    .classify_runtime_state(&route.mapping.resource)
                    .context("observing current host-resource state")?
                    .1
            }
        };
        self.current_state_for_execution(
            &route.mapping.resource,
            state,
            recovering_resource == Some(&route.mapping.resource),
        )
    }

    fn current_state_for_execution(
        &self,
        resource: &ResourceId,
        state: RuntimeResourceState,
        recovering_resource: bool,
    ) -> Result<CurrentResourceState> {
        let retained = self.registry.reconciliation.and_then(|reconciliation| {
            reconciliation
                .observations
                .binary_search_by(|observation| observation.resource.cmp(resource))
                .ok()
                .map(|index| reconciliation.observations[index].state)
        });
        validate_runtime_health_authority(state, retained, recovering_resource)?;
        Ok(current_authority_state(state))
    }

    fn dispatch_route<Policy, Observer>(
        &self,
        session: &mut NativeAbilitySession<'a>,
        operation: &aos_ability_model::ScopedOperationKey,
        route: NativeAdapterRoute<'a>,
        assignment: ProviderAssignment,
        planned_bootstrap: Option<&ResourceId>,
        policy: &mut OperatorAuthorizedPolicy<'_, Policy>,
        clock: &SystemMonotonicClock,
        cancellation: &CancellationToken,
        observer: &mut Observer,
    ) -> Result<()>
    where
        Policy: TrustedAdmissionPolicy,
        Observer: ExecutionBoundaryObserver,
    {
        match route.kind {
            NativeAdapterKind::KubernetesObject => {
                let spec = self.registry.kubernetes_spec(&route)?;
                let inventory = session.resource_inventory();
                let mut catalog = KubernetesObjectResourceCatalog::new(
                    route.package,
                    assignment.clone(),
                    inventory,
                    0,
                    [spec],
                )
                .context("constructing Kubernetes object resource catalog")?;
                let mut adapter = NativeKubernetesObjectAdapter::new(route.package, assignment)
                    .context("constructing Kubernetes object adapter")?;
                drive_with_adapter(
                    session,
                    operation,
                    &mut adapter,
                    &mut catalog,
                    policy,
                    clock,
                    cancellation,
                    observer,
                )
            }
            NativeAdapterKind::ManagedConfiguration => {
                let spec = self.registry.managed_configuration_spec(&route)?;
                let inventory = session.resource_inventory();
                let mut catalog = ManagedConfigurationResourceCatalog::new(
                    Path::new("/"),
                    Path::new(MANAGED_CONFIGURATION_STATE_ROOT),
                    assignment.clone(),
                    inventory,
                    0,
                    [spec],
                )
                .context("constructing managed-configuration resource catalog")?;
                let mut adapter = NativeManagedConfigurationAdapter::new(route.package, assignment)
                    .context("constructing managed-configuration adapter")?;
                drive_with_adapter(
                    session,
                    operation,
                    &mut adapter,
                    &mut catalog,
                    policy,
                    clock,
                    cancellation,
                    observer,
                )
            }
            NativeAdapterKind::NginxValidation => {
                let spec = self.registry.nginx_spec(&route)?;
                let inventory = session.resource_inventory();
                let mut catalog = NginxResourceCatalog::new(
                    Path::new(NGINX_STATE_ROOT),
                    assignment.clone(),
                    inventory,
                    0,
                    [spec],
                )
                .context("constructing nginx resource catalog")?;
                let mut adapter = NativeNginxAdapter::new(route.package, assignment)
                    .context("constructing nginx adapter")?;
                drive_with_adapter(
                    session,
                    operation,
                    &mut adapter,
                    &mut catalog,
                    policy,
                    clock,
                    cancellation,
                    observer,
                )
            }
            NativeAdapterKind::Systemd => {
                let spec = self.registry.systemd_spec(&route)?;
                let inventory = session.resource_inventory();
                let connection = if let Some(bootstrap_resource) = planned_bootstrap {
                    self.systemd
                        .reacquire_planned_assignment(&assignment, bootstrap_resource)
                        .context("reacquiring planned systemd capability for immediate dispatch")?
                } else {
                    self.systemd
                        .reacquire_assignment(&assignment)
                        .context("reacquiring systemd control capability for immediate dispatch")?
                };
                let mut catalog =
                    SystemdResourceCatalog::new(connection, assignment.clone(), inventory, [spec])
                        .context("constructing systemd resource catalog")?;
                if route.assignment_interface.name.as_str()
                    == aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME
                {
                    let mut adapter = NativeSystemdAdapter::new(route.package, assignment)
                        .context("constructing built-in systemd adapter")?;
                    drive_with_adapter(
                        session,
                        operation,
                        &mut adapter,
                        &mut catalog,
                        policy,
                        clock,
                        cancellation,
                        observer,
                    )
                } else if route.assignment_interface.name.as_str()
                    == aos_ability_model::builtin::SYSTEMD_PROVIDER_BOOTSTRAP_INTERFACE_NAME
                {
                    let readiness =
                        self.provider_readiness_outputs(operation, &route.mapping.resource)?;
                    let mut adapter = NativeSystemdServiceAdapter::new_with_manager_readiness(
                        route.package,
                        assignment,
                        readiness,
                    )
                    .context("constructing reference systemd adapter")?;
                    drive_with_adapter(
                        session,
                        operation,
                        &mut adapter,
                        &mut catalog,
                        policy,
                        clock,
                        cancellation,
                        observer,
                    )
                } else {
                    let mut adapter = NativeSystemdServiceAdapter::new(route.package, assignment)
                        .context("constructing reference systemd adapter")?;
                    drive_with_adapter(
                        session,
                        operation,
                        &mut adapter,
                        &mut catalog,
                        policy,
                        clock,
                        cancellation,
                        observer,
                    )
                }
            }
            NativeAdapterKind::HostResource(kind) => {
                let spec = self.registry.host_resource_spec(&route)?;
                let inventory = session.resource_inventory();
                let mut catalog =
                    NativeHostResourceCatalog::new(assignment.clone(), inventory, kind, [spec])
                        .context("constructing host-resource catalog")?;
                let mut adapter = NativeHostResourceAdapter::new(
                    route.package,
                    assignment,
                    &route.mapping.qualification,
                    kind,
                )
                .context("constructing host-resource adapter")?;
                drive_with_adapter(
                    session,
                    operation,
                    &mut adapter,
                    &mut catalog,
                    policy,
                    clock,
                    cancellation,
                    observer,
                )
            }
        }
    }

    fn provider_readiness_outputs(
        &self,
        operation: &aos_ability_model::ScopedOperationKey,
        bootstrap_resource: &ResourceId,
    ) -> Result<Vec<NativeProviderReadinessOutput>> {
        let mut outputs = Vec::new();
        for readiness in self
            .registry
            .plan
            .document()
            .provider_readiness
            .iter()
            .filter(|readiness| &readiness.producer == operation)
        {
            let binding = self
                .registry
                .plan
                .binding_plan()
                .binding(&readiness.binding)
                .context("planned manager readiness binding disappeared")?;
            outputs.push(
                self.registry
                    .readiness_output(
                        &self.systemd,
                        readiness.output.clone(),
                        binding,
                        bootstrap_resource,
                    )
                    .context("selecting planned native provider capability")?,
            );
        }
        Ok(outputs)
    }
}

/// Waits for persisted retry eligibility while keeping cancellation bounded.
fn wait_for_retry_eligibility(
    clock: &impl MonotonicClock,
    cancellation: &CancellationToken,
    eligible_at_millis: u64,
) -> Result<()> {
    loop {
        ensure!(
            !cancellation.is_cancelled(),
            "native activation was cancelled while awaiting retry eligibility"
        );
        let remaining = eligible_at_millis.saturating_sub(clock.restart_stable_millis());
        if remaining == 0 {
            return Ok(());
        }
        thread::sleep(RETRY_CANCELLATION_POLL.min(Duration::from_millis(remaining)));
    }
}

fn validate_runtime_health_authority(
    state: RuntimeResourceState,
    retained: Option<RuntimeResourceState>,
    recovering_resource: bool,
) -> Result<()> {
    let carries_health = matches!(
        state,
        RuntimeResourceState::Present {
            health: RuntimeResourceHealth::Stopped | RuntimeResourceHealth::Divergent,
            ..
        }
    );
    if !carries_health {
        return Ok(());
    }

    // A retained intent may have stopped or partially changed its own
    // resource. Admit only its reconciliation observation here; a later
    // retry must still carry checked repair authority before another effect.
    if recovering_resource {
        return Ok(());
    }
    let retained =
        retained.context("runtime health evidence is outside checked repair authority")?;
    ensure!(
        retained == state,
        "runtime health evidence differs from checked repair authority"
    );
    Ok(())
}

const fn current_authority_state(state: RuntimeResourceState) -> CurrentResourceState {
    match state {
        RuntimeResourceState::Absent => CurrentResourceState::Absent,
        RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Healthy,
        } => CurrentResourceState::Present { revision },
        RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Stopped,
        } => CurrentResourceState::Stopped { revision },
        RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Divergent,
        } => CurrentResourceState::Divergent { revision },
    }
}

fn drive_with_adapter<'plan, Adapter, Catalog, Policy, Observer>(
    session: &mut NativeAbilitySession<'plan>,
    operation: &aos_ability_model::ScopedOperationKey,
    adapter: &mut Adapter,
    catalog: &mut Catalog,
    policy: &mut OperatorAuthorizedPolicy<'_, Policy>,
    clock: &SystemMonotonicClock,
    cancellation: &CancellationToken,
    observer: &mut Observer,
) -> Result<()>
where
    Adapter: TrustedAdapter,
    Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
    Policy: TrustedAdmissionPolicy,
    Observer: ExecutionBoundaryObserver,
{
    let admission = session
        .admit(operation, adapter, catalog, policy, clock)
        .map_err(|failure| failure.into_parts().1)?;
    let admitted = match admission {
        Ok(admitted) => admitted,
        Err(failure) => {
            let reason = failure.error().to_string();
            let cleanup_failed = session.retry_admission_cleanup(failure, catalog).is_err();
            return Err(anyhow!(
                "native admission failed: {reason}; cleanup_failed={cleanup_failed}"
            ));
        }
    };

    drive_admitted_to_release(
        session,
        admitted,
        adapter,
        catalog,
        policy,
        clock,
        cancellation,
        observer,
    )
}

fn drive_admitted_to_release<'plan, Adapter, Catalog, Policy, Observer>(
    session: &mut NativeAbilitySession<'plan>,
    admitted: AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
    adapter: &mut Adapter,
    catalog: &mut Catalog,
    policy: &mut OperatorAuthorizedPolicy<'_, Policy>,
    clock: &SystemMonotonicClock,
    cancellation: &CancellationToken,
    observer: &mut Observer,
) -> Result<()>
where
    Adapter: TrustedAdapter,
    Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
    Policy: TrustedAdmissionPolicy,
    Observer: ExecutionBoundaryObserver,
{
    loop {
        let action = session
            .transaction()
            .next_action(&admitted.operation().key)
            .map_err(anyhow::Error::new)?;
        let cancellation_action = if cancellation.is_cancelled() {
            native_cancellation_action(&action, admitted.operation().recovery.cancel.is_some())
        } else {
            NativeCancellationAction::Continue
        };
        match cancellation_action {
            NativeCancellationAction::Dispatch => {
                let step = session
                    .cancel_admitted_with_observer(
                        &admitted,
                        adapter,
                        policy,
                        clock,
                        cancellation,
                        observer,
                    )
                    .map_err(anyhow::Error::new)?
                    .map_err(anyhow::Error::new)?;
                match step {
                    ExecutionStep::Completed | ExecutionStep::RejectedBeforeEffect => continue,
                    ExecutionStep::Indeterminate => {
                        return Err(anyhow!(
                            "native cancellation of operation {:?} remained indeterminate",
                            admitted.operation().key
                        ));
                    }
                    ExecutionStep::SafeToRetry | ExecutionStep::InterventionRequired => {
                        return Err(anyhow!(
                            "native cancellation of operation {:?} returned an invalid step {step:?}",
                            admitted.operation().key
                        ));
                    }
                }
            }
            NativeCancellationAction::Unsupported => {
                return Err(anyhow!(
                    "native operation {:?} was cancelled but its checked contract has no cancellation method",
                    admitted.operation().key
                ));
            }
            NativeCancellationAction::Continue => {}
        }
        match action {
            RecoveryAction::Execute { .. }
            | RecoveryAction::ReconcileBeforeRetry { .. }
            | RecoveryAction::ExecuteCompensation
            | RecoveryAction::ReconcileCompensation => {
                let result = session
                    .drive_admitted_with_observer(
                        &admitted,
                        adapter,
                        policy,
                        clock,
                        cancellation,
                        observer,
                    )
                    .map_err(anyhow::Error::new)?;
                match result {
                    Ok(_) => {}
                    Err(ExecutionError::CancelledBeforeIntent)
                        if cancellation.is_cancelled()
                            && admitted.operation().recovery.cancel.is_some() =>
                    {
                        continue;
                    }
                    Err(ExecutionError::CancelledBeforeIntent) if cancellation.is_cancelled() => {
                        return Err(anyhow!(
                            "native operation {:?} was cancelled but its checked contract has no cancellation method",
                            admitted.operation().key
                        ));
                    }
                    Err(error) => return Err(anyhow::Error::new(error)),
                }
            }
            RecoveryAction::ReleaseResources | RecoveryAction::ReleaseCompensationResources => {
                let release = session
                    .release_admitted::<Adapter, _, _>(admitted, catalog, clock)
                    .map_err(|failure| failure.into_parts().1)?;
                return match release {
                    Ok(()) => Ok(()),
                    Err(failure) => {
                        let reason = failure.error().to_string();
                        match session.retry_release(failure, catalog, clock) {
                            Ok(Ok(())) => Ok(()),
                            Ok(Err(_)) => Err(anyhow!(
                                "native resource release remained incomplete after retry: {reason}"
                            )),
                            Err(marker) => Err(anyhow::Error::new(marker.into_parts().1)),
                        }
                    }
                };
            }
            RecoveryAction::InterventionRequired
            | RecoveryAction::CompensationInterventionRequired => {
                return Err(anyhow!(
                    "native operation {:?} requires operator intervention",
                    admitted.operation().key
                ));
            }
            other => {
                return Err(anyhow!(
                    "admitted native operation selected incompatible action {other:?}"
                ));
            }
        }
    }
}

const fn native_cancellation_action(
    action: &RecoveryAction,
    cancellation_supported: bool,
) -> NativeCancellationAction {
    if !matches!(
        action,
        RecoveryAction::Execute { .. } | RecoveryAction::ReconcileBeforeRetry { .. }
    ) {
        return NativeCancellationAction::Continue;
    }
    if cancellation_supported {
        NativeCancellationAction::Dispatch
    } else {
        NativeCancellationAction::Unsupported
    }
}

fn mapped_candidate<'a>(
    locator: &super::native_resource_map::NativeOutputLocator,
    desired_state: &'a DesiredStateDocument,
) -> Result<&'a str> {
    let output = locate_aggregate_output(locator, desired_state)?;
    locate_literal_json(&output.value, &locator.field_path)
        .and_then(serde_json::Value::as_str)
        .context("mapped native candidate disappeared after specialization")
}

fn locate_aggregate_output<'a>(
    locator: &super::native_resource_map::NativeOutputLocator,
    desired_state: &'a DesiredStateDocument,
) -> Result<&'a AggregateOutput> {
    desired_state
        .outputs
        .iter()
        .find(|output| {
            output.aggregate == locator.aggregate
                && output.interface == locator.interface
                && output.port == locator.port
        })
        .context("mapped native locator disappeared after specialization")
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

fn preflight_operation_contract(kind: NativeAdapterKind, operation: &Operation) -> Result<()> {
    ensure!(
        native_method_is_supported(
            kind,
            operation.interface.name.as_str(),
            operation.interface.abi.get(),
            operation.interface.descriptor,
            operation.method.as_str(),
            operation.method.as_str(),
            InvocationPurpose::Effect,
        ),
        "native dispatcher has no adapter for the checked effect method"
    );
    for (method, purpose) in [
        (
            operation.recovery.reconcile.as_ref(),
            InvocationPurpose::Reconcile,
        ),
        (
            operation.recovery.cancel.as_ref(),
            InvocationPurpose::Cancel,
        ),
        (
            operation.recovery.compensate.as_ref(),
            InvocationPurpose::Compensate,
        ),
    ] {
        let Some(method) = method else {
            continue;
        };
        ensure!(
            method.interface == operation.interface
                && native_method_is_supported(
                    kind,
                    method.interface.name.as_str(),
                    method.interface.abi.get(),
                    operation.interface.descriptor,
                    operation.method.as_str(),
                    method.method.as_str(),
                    purpose,
                ),
            "native dispatcher has no adapter for a checked recovery method"
        );
    }
    Ok(())
}

fn native_method_is_supported(
    kind: NativeAdapterKind,
    interface: &str,
    interface_abi: u32,
    interface_descriptor: Sha256Digest,
    effect_method: &str,
    invoked_method: &str,
    purpose: InvocationPurpose,
) -> bool {
    adapter_id(kind, interface).is_some_and(|adapter| {
        supports_exact_route(
            adapter,
            interface,
            interface_abi,
            interface_descriptor,
            effect_method,
            invoked_method,
            purpose,
        )
    })
}

/// Combines desired-policy authority with fresh current-assignment policy.
pub(crate) struct OperatorAuthorizedPolicy<'a, Policy> {
    activation: &'a SpecializedAbilityActivation,
    operator_authority: &'a OperatorPolicyAuthorityStore,
    current: Policy,
}

impl<'a, Policy> OperatorAuthorizedPolicy<'a, Policy> {
    /// Constructs a policy that reopens operator authority before each check.
    pub(crate) const fn new(
        activation: &'a SpecializedAbilityActivation,
        operator_authority: &'a OperatorPolicyAuthorityStore,
        current: Policy,
    ) -> Self {
        Self {
            activation,
            operator_authority,
            current,
        }
    }

    fn authorize_no_op(
        &mut self,
        assignments: &[ProviderAssignment],
        resources: &NativeResourceMap,
    ) -> std::result::Result<(), OperatorAuthorizedPolicyError>
    where
        Policy: NativeNoOpAdmissionPolicy,
    {
        self.activation
            .reauthorize(self.operator_authority)
            .map_err(OperatorAuthorizedPolicyError::Operator)?;
        self.current
            .authorize_no_op(self.activation.plan(), assignments, resources)
            .map_err(|error| OperatorAuthorizedPolicyError::Current(anyhow!(error)))
    }

    fn refresh_authority(
        &mut self,
        assignments: &[ProviderAssignment],
        resources: Vec<CurrentResourceObservation>,
    ) -> std::result::Result<(), OperatorAuthorizedPolicyError>
    where
        Policy: NativeAuthorityRefresh,
    {
        self.activation
            .reauthorize(self.operator_authority)
            .map_err(OperatorAuthorizedPolicyError::Operator)?;
        self.current
            .refresh_authority(self.activation.plan(), assignments, resources)
            .map_err(|error| OperatorAuthorizedPolicyError::Current(anyhow!(error)))
    }
}

/// Reports which independently refreshed policy layer rejected dispatch.
#[derive(Debug)]
pub(crate) enum OperatorAuthorizedPolicyError {
    /// The desired policy sidecar lost its exact operator grant.
    Operator(anyhow::Error),
    /// The current binding, assignment, or resource observation changed.
    Current(anyhow::Error),
}

impl fmt::Display for OperatorAuthorizedPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operator(source) => {
                write!(
                    formatter,
                    "operator policy authority rejected native dispatch: {source}"
                )
            }
            Self::Current(source) => {
                write!(
                    formatter,
                    "current native admission policy rejected dispatch: {source}"
                )
            }
        }
    }
}

impl std::error::Error for OperatorAuthorizedPolicyError {}

impl<Policy> TrustedAdmissionPolicy for OperatorAuthorizedPolicy<'_, Policy>
where
    Policy: TrustedAdmissionPolicy,
{
    type Error = OperatorAuthorizedPolicyError;

    fn authorize(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> Result<(), Self::Error> {
        self.activation
            .reauthorize(self.operator_authority)
            .map_err(OperatorAuthorizedPolicyError::Operator)?;
        self.current
            .authorize(plan, binding, operation, method, purpose)
            .map_err(|error| OperatorAuthorizedPolicyError::Current(anyhow!(error)))
    }

    fn authorize_resources(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        expected_provider: Option<&ProviderAssignment>,
        resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        self.activation
            .reauthorize(self.operator_authority)
            .map_err(OperatorAuthorizedPolicyError::Operator)?;
        self.current
            .authorize_resources(plan, binding, operation, expected_provider, resources)
            .map_err(|error| OperatorAuthorizedPolicyError::Current(anyhow!(error)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_eval::native_adapter_surface::{NATIVE_METHODS, NativeAdapterId};

    struct FixedClock;

    impl MonotonicClock for FixedClock {
        fn now_millis(&self) -> u64 {
            0
        }

        fn restart_stable_millis(&self) -> u64 {
            0
        }
    }

    #[test]
    fn retry_wait_observes_cancellation_within_the_poll_bound() {
        let cancellation = CancellationToken::default();
        let signal = cancellation.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            signal.cancel();
        });
        let started = std::time::Instant::now();

        let error = wait_for_retry_eligibility(&FixedClock, &cancellation, u64::MAX)
            .expect_err("a cancelled retry wait must stop");

        canceller.join().expect("cancellation thread");
        assert!(error.to_string().contains("cancelled"));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "retry wait exceeded its bounded cancellation poll"
        );
    }

    #[test]
    fn native_cancellation_routes_only_unsettled_effect_attempts() {
        let attempt = std::num::NonZeroU32::MIN;
        for action in [
            RecoveryAction::Execute { attempt },
            RecoveryAction::ReconcileBeforeRetry { attempt },
        ] {
            assert_eq!(
                native_cancellation_action(&action, true),
                NativeCancellationAction::Dispatch
            );
            assert_eq!(
                native_cancellation_action(&action, false),
                NativeCancellationAction::Unsupported
            );
        }

        for action in [
            RecoveryAction::ReleaseResources,
            RecoveryAction::ExecuteCompensation,
            RecoveryAction::ReconcileCompensation,
            RecoveryAction::ReleaseCompensationResources,
            RecoveryAction::InterventionRequired,
            RecoveryAction::CompensationInterventionRequired,
            RecoveryAction::None,
        ] {
            assert_eq!(
                native_cancellation_action(&action, true),
                NativeCancellationAction::Continue
            );
            assert_eq!(
                native_cancellation_action(&action, false),
                NativeCancellationAction::Continue
            );
        }
    }

    #[test]
    fn partial_effect_health_is_scoped_to_retained_reconciliation() {
        let state = RuntimeResourceState::Present {
            revision: aos_ability_model::RevisionId(aos_contract::Sha256Digest::of_bytes(
                b"current revision",
            )),
            health: RuntimeResourceHealth::Divergent,
        };

        validate_runtime_health_authority(state, None, true)
            .expect("the retained reconciliation may inspect its partial effect");
        assert!(
            validate_runtime_health_authority(state, None, false).is_err(),
            "the same evidence must not authorize a new effect or retry"
        );
        validate_runtime_health_authority(state, Some(state), false)
            .expect("an independently checked repair plan retains exact health evidence");

        let different = RuntimeResourceState::Present {
            revision: aos_ability_model::RevisionId(aos_contract::Sha256Digest::of_bytes(
                b"different revision",
            )),
            health: RuntimeResourceHealth::Divergent,
        };
        assert!(
            validate_runtime_health_authority(state, Some(different), false).is_err(),
            "checked repair authority must match the exact runtime state"
        );
    }

    #[test]
    fn native_method_matrix_is_closed_to_exact_adapter_contracts() {
        assert!(native_method_is_supported(
            NativeAdapterKind::ManagedConfiguration,
            "aos.managed-configuration-effects",
            1,
            advertised_descriptor(NativeAdapterId::ManagedConfiguration),
            "publish",
            "publish",
            InvocationPurpose::Effect,
        ));
        assert!(native_method_is_supported(
            NativeAdapterKind::Systemd,
            aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME,
            1,
            advertised_descriptor(NativeAdapterId::SystemdManager),
            "stop",
            "observe",
            InvocationPurpose::Reconcile,
        ));
        assert!(native_method_is_supported(
            NativeAdapterKind::HostResource(NativeHostResourceKind::Postgresql),
            "aos.postgresql-effects",
            1,
            advertised_descriptor(NativeAdapterId::Postgresql),
            "restart",
            "restart",
            InvocationPurpose::Reconcile,
        ));

        assert!(!native_method_is_supported(
            NativeAdapterKind::ManagedConfiguration,
            "aos.managed-configuration-effects",
            2,
            advertised_descriptor(NativeAdapterId::ManagedConfiguration),
            "publish",
            "publish",
            InvocationPurpose::Effect,
        ));
        assert!(!native_method_is_supported(
            NativeAdapterKind::Systemd,
            aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME,
            1,
            advertised_descriptor(NativeAdapterId::SystemdManager),
            "start",
            "observe",
            InvocationPurpose::Cancel,
        ));
        assert!(!native_method_is_supported(
            NativeAdapterKind::Systemd,
            "aos.systemd-service-effects",
            1,
            advertised_descriptor(NativeAdapterId::SystemdServiceLegacy),
            "reload",
            "observe",
            InvocationPurpose::Reconcile,
        ));
        assert!(native_method_is_supported(
            NativeAdapterKind::HostResource(NativeHostResourceKind::Credential),
            "aos.credential-delivery-effects",
            1,
            advertised_descriptor(NativeAdapterId::CredentialDelivery),
            "deliver",
            "deliver",
            InvocationPurpose::Cancel,
        ));
        assert!(!native_method_is_supported(
            NativeAdapterKind::KubernetesObject,
            aos_ability_model::builtin::KUBERNETES_OBJECT_INTERFACE_NAME,
            1,
            advertised_descriptor(NativeAdapterId::KubernetesObject),
            "apply",
            "apply",
            InvocationPurpose::Compensate,
        ));

        assert!(!native_method_is_supported(
            NativeAdapterKind::ManagedConfiguration,
            "aos.managed-configuration-effects",
            1,
            Sha256Digest::of_bytes(b"foreign interface descriptor"),
            "publish",
            "publish",
            InvocationPurpose::Effect,
        ));
    }

    #[test]
    fn every_advertised_method_preflights_its_exact_production_plan_routes() {
        for contract in NATIVE_METHODS {
            let kind = runtime_kind(contract.adapter);
            let mut operation = aos_ability_validate::test_support::plan_fixture()
                .effect_plan
                .operations
                .remove(0);
            operation.interface.name =
                aos_ability_model::InterfaceName::new(contract.interface_name)
                    .expect("generated interface name");
            operation.interface.abi =
                std::num::NonZeroU32::new(contract.interface_abi).expect("generated ABI");
            operation.interface.descriptor = contract.interface_descriptor;
            operation.method =
                aos_ability_model::LocalKey::new(contract.method).expect("generated method");
            operation.target.interface = operation.interface.clone();
            operation.target.operations = vec![operation.method.clone()];
            operation.recovery.reconcile = contract.reconcile.map(|method| MethodReference {
                interface: operation.interface.clone(),
                method: aos_ability_model::LocalKey::new(method).expect("generated reconcile"),
            });
            operation.recovery.cancel = contract.cancel.map(|method| MethodReference {
                interface: operation.interface.clone(),
                method: aos_ability_model::LocalKey::new(method).expect("generated cancel"),
            });
            operation.recovery.compensate = None;

            preflight_operation_contract(kind, &operation)
                .expect("the generated production route must preflight");

            operation.interface.descriptor =
                Sha256Digest::of_bytes(b"foreign interface descriptor");
            assert!(
                preflight_operation_contract(kind, &operation).is_err(),
                "{}:{} admitted a foreign interface descriptor",
                contract.interface_name,
                contract.method,
            );
            operation.interface.descriptor = contract.interface_descriptor;

            operation.recovery.reconcile = Some(MethodReference {
                interface: operation.interface.clone(),
                method: aos_ability_model::LocalKey::new("foreign-recovery").expect("test method"),
            });
            assert!(
                preflight_operation_contract(kind, &operation).is_err(),
                "{}:{} admitted a foreign recovery route",
                contract.interface_name,
                contract.method,
            );
        }
    }

    fn runtime_kind(adapter: NativeAdapterId) -> NativeAdapterKind {
        match adapter {
            NativeAdapterId::CredentialDelivery => {
                NativeAdapterKind::HostResource(NativeHostResourceKind::Credential)
            }
            NativeAdapterId::HostNetworkPolicy => {
                NativeAdapterKind::HostResource(NativeHostResourceKind::NetworkPolicy)
            }
            NativeAdapterId::HostStorage => {
                NativeAdapterKind::HostResource(NativeHostResourceKind::Storage)
            }
            NativeAdapterId::KubernetesObject => NativeAdapterKind::KubernetesObject,
            NativeAdapterId::ManagedConfiguration => NativeAdapterKind::ManagedConfiguration,
            NativeAdapterId::NetworkEndpoint => {
                NativeAdapterKind::HostResource(NativeHostResourceKind::Endpoint)
            }
            NativeAdapterId::NginxValidation => NativeAdapterKind::NginxValidation,
            NativeAdapterId::Postgresql => {
                NativeAdapterKind::HostResource(NativeHostResourceKind::Postgresql)
            }
            NativeAdapterId::SystemdBootstrap
            | NativeAdapterId::SystemdManager
            | NativeAdapterId::SystemdServiceLegacy => NativeAdapterKind::Systemd,
        }
    }

    fn advertised_descriptor(adapter: NativeAdapterId) -> Sha256Digest {
        NATIVE_METHODS
            .iter()
            .find(|contract| contract.adapter == adapter)
            .expect("generated adapter must advertise a method")
            .interface_descriptor
    }

    #[test]
    fn native_no_op_rejects_failed_indeterminate_and_torn_prior_transactions() {
        for terminal in [None, Some(TerminalResult::SettledFailure)] {
            assert!(require_successful_retained_transaction(terminal, 0, false, false).is_err());
        }
        assert!(
            require_successful_retained_transaction(
                Some(TerminalResult::Succeeded),
                1,
                false,
                false,
            )
            .is_err()
        );
        require_successful_retained_transaction(Some(TerminalResult::Succeeded), 0, false, false)
            .expect("settled exact prior success");
    }

    #[test]
    fn zero_operation_plan_root_is_not_prior_native_success_without_verification() {
        let error = require_successful_retained_transaction(
            Some(TerminalResult::Succeeded),
            0,
            true,
            false,
        )
        .expect_err("vacuous journal success cannot replace native verification");
        assert!(error.to_string().contains("protected no-op verification"));

        require_successful_retained_transaction(Some(TerminalResult::Succeeded), 0, true, true)
            .expect("protected no-op verification authenticates empty-plan success");
    }
}
