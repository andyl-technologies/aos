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
    AggregateOutput, Binding, DesiredStateDocument, IncarnationId, MethodReference, Operation,
    ProviderAssignment, ResourceId, TransactionId, ValueExpression,
};
use aos_ability_runtime::adapter::{
    CancellationToken, InvocationPurpose, MonotonicClock, ResourceAdmissionEvidence,
    ResourceRevisionObservation, SystemMonotonicClock, TrustedAdapter, TrustedResourceCatalog,
};
use aos_ability_runtime::execution::{
    AdmittedOperation, CheckedExecutionJournalSnapshot, RecoveryAction, TerminalResult,
    TrustedAdmissionPolicy,
};
use aos_ability_runtime::journal::JournalLimits;
use aos_ability_validate::{BindingAuthorityKind, CheckedEffectPlan};

use super::ability_activation::SpecializedAbilityActivation;
use super::ability_policy::{CurrentAbilityAuthoritySource, NativeCurrentAdmissionPolicy};
use super::ability_policy_authority::OperatorPolicyAuthorityStore;
use super::ability_store::inventory::{
    NativeNoOpResourceObservation, verify_retained_native_consumers,
};
use super::ability_store::{NativeAbilitySession, RetainedAbilityDiagnosticSource};
use super::managed_configuration_ability::{
    ManagedConfigurationResourceCatalog, ManagedConfigurationResourceSpec,
    NativeManagedConfigurationAdapter, preflight_native_managed_configuration,
};
use super::native_resource_map::{
    NativeResourceMap, NativeResourceMapping, NativeResourceQualification,
};
use super::nginx_ability::{
    NativeNginxAdapter, NginxResourceCatalog, NginxResourceSpec, preflight_native_nginx,
};
use super::systemd_ability::{
    NativeSystemdAdapter, NativeSystemdServiceAdapter, SystemdResourceCatalog, SystemdResourceSpec,
    preflight_native_systemd,
};
use crate::ability_package::{VerifiedAbilityPackage, VerifiedAbilityPackageSet};

const MANAGED_CONFIGURATION_STATE_ROOT: &str = "/var/lib/aos/ability-runtime/managed-configuration";
const NGINX_STATE_ROOT: &str = "/var/lib/aos/ability-runtime/nginx";

/// Selects the built-in adapter family authenticated for one native mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeAdapterKind {
    /// Uses the root-owned managed-configuration adapter.
    ManagedConfiguration,
    /// Uses the exact nginx validation adapter.
    NginxValidation,
    /// Uses either supported exact systemd terminal contract.
    Systemd,
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
    packages: &'a VerifiedAbilityPackageSet,
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
    /// Supplies the identical desired/current native mapping being retained.
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
) -> Result<()> {
    ensure!(
        incomplete_tail_bytes == 0,
        "retained native transaction has an incomplete journal tail"
    );
    ensure!(
        terminal == Some(TerminalResult::Succeeded),
        "retained native transaction did not settle successfully"
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
        let registry = Self {
            plan: activation.plan(),
            desired: activation.desired_native_resources(),
            current: activation.current_native_resources(),
            desired_state: activation.desired_state(),
            current_desired_state: activation.current_desired_state(),
            current_planning: activation.bundle().current_planning_digest(),
            packages,
        };

        for mapping in registry
            .desired
            .entries
            .iter()
            .chain(registry.current.into_iter().flat_map(|map| &map.entries))
        {
            registry.preflight_mapping(mapping)?;
        }
        // Preflight the complete graph before any operation can be admitted.
        // A later branch selection must never expose an unsupported route.
        for operation in registry.plan.operations() {
            registry.route(operation)?;
        }

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
        let NativeResourceQualification::SystemdService { unit, .. } = &route.mapping.qualification
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
        })
    }

    fn current_mapping(&self, resource: &ResourceId) -> Option<&'a NativeResourceMapping> {
        self.current?
            .entries
            .iter()
            .find(|mapping| &mapping.resource == resource)
    }

    fn activation_desired_state(&self) -> &'a DesiredStateDocument {
        self.desired_state
    }

    fn activation_current_desired_state(&self) -> Result<&'a DesiredStateDocument> {
        self.current_desired_state
            .context("native teardown dispatch has no retained current desired state")
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

/// Executes a preflighted native graph through the closed built-in adapter set.
pub(crate) struct NativeDispatcher<'a> {
    registry: NativeAdapterRegistry<'a>,
    assignments: &'a [ProviderAssignment],
    systemd: Arc<aos_systemd::SystemdManagerConnection>,
}

impl<'a> NativeDispatcher<'a> {
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
        assignments: &'a [ProviderAssignment],
        systemd: Arc<aos_systemd::SystemdManagerConnection>,
    ) -> Result<Self> {
        let registry = NativeAdapterRegistry::new(activation, packages)?;
        for mapping in registry.desired.entries.iter().chain(
            registry
                .current
                .into_iter()
                .flat_map(|current| &current.entries),
        ) {
            let route = registry.preflight_mapping(mapping)?;
            registry.assignment(&route, assignments)?;
        }

        Ok(Self {
            registry,
            assignments,
            systemd,
        })
    }

    /// Runs stable single-operation batches until the transaction is terminal.
    ///
    /// Keeping each admitted token through dispatch, reconciliation, and
    /// release prevents process-scoped resource ownership from being dropped
    /// between runtime state-machine steps.
    ///
    /// # Errors
    ///
    /// Returns an error for admission, adapter, persistence, cleanup,
    /// intervention, or nonterminal scheduling failure. The caller must drop
    /// the session and recover the same transaction after such a failure.
    pub(crate) fn run_to_terminal<Policy, NoOpVerifier>(
        &self,
        session: &mut NativeAbilitySession<'a>,
        policy: &mut OperatorAuthorizedPolicy<'_, Policy>,
        no_op_verifier: &mut NoOpVerifier,
        cancellation: &CancellationToken,
    ) -> Result<TerminalResult>
    where
        Policy: NativeNoOpAdmissionPolicy,
        NoOpVerifier: TrustedNativeNoOpVerifier,
    {
        let clock = SystemMonotonicClock::new();
        loop {
            if let Some(terminal) = session.transaction().summary().terminal() {
                if self.registry.plan.operations().is_empty() {
                    return self.verify_no_op(session, policy, no_op_verifier, terminal);
                }
                return Ok(terminal);
            }
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
                    let remaining =
                        eligible_at_millis.saturating_sub(clock.restart_stable_millis());
                    if remaining > 0 {
                        thread::sleep(Duration::from_millis(remaining));
                    }
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
            let assignment = self.registry.assignment(&route, self.assignments)?;
            self.dispatch_route(
                session,
                item.operation(),
                route,
                assignment,
                policy,
                &clock,
                cancellation,
            )?;
        }
    }

    fn verify_no_op<Policy, NoOpVerifier>(
        &self,
        session: &NativeAbilitySession<'a>,
        policy: &mut OperatorAuthorizedPolicy<'_, Policy>,
        verifier: &mut NoOpVerifier,
        terminal: TerminalResult,
    ) -> Result<TerminalResult>
    where
        Policy: NativeNoOpAdmissionPolicy,
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
            self.registry.desired == current_resources,
            "empty native transition changed its authenticated resource map"
        );

        policy.authorize_no_op(self.assignments, current_resources)?;
        let resource_observations = self.observe_no_op_resources(session)?;
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
            assignments: self.assignments,
            resources: &resource_observations,
        })?;
        Ok(terminal)
    }

    fn observe_no_op_resources(
        &self,
        session: &NativeAbilitySession<'a>,
    ) -> Result<Vec<NativeNoOpResourceObservation>> {
        let mut observations = Vec::with_capacity(self.registry.desired.entries.len());
        for mapping in &self.registry.desired.entries {
            let route = self.registry.preflight_mapping(mapping)?;
            let assignment = self.registry.assignment(&route, self.assignments)?;
            let inventory = session.resource_inventory();
            let (qualified, revision, requires_consumer) = match route.kind {
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
                    let catalog = SystemdResourceCatalog::new(
                        Arc::clone(&self.systemd),
                        assignment,
                        inventory,
                        [spec],
                    )
                    .context("constructing systemd no-op catalog")?;
                    let _qualified = catalog
                        .observe_no_op(&mapping.resource)
                        .context("observing systemd no-op resource")?;
                    require_authenticated_systemd_consumer_revision()?
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

    fn dispatch_route<Policy>(
        &self,
        session: &mut NativeAbilitySession<'a>,
        operation: &aos_ability_model::ScopedOperationKey,
        route: NativeAdapterRoute<'a>,
        assignment: ProviderAssignment,
        policy: &mut OperatorAuthorizedPolicy<'_, Policy>,
        clock: &SystemMonotonicClock,
        cancellation: &CancellationToken,
    ) -> Result<()>
    where
        Policy: TrustedAdmissionPolicy,
    {
        match route.kind {
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
                )
            }
            NativeAdapterKind::Systemd => {
                let spec = self.registry.systemd_spec(&route)?;
                let inventory = session.resource_inventory();
                let mut catalog = SystemdResourceCatalog::new(
                    Arc::clone(&self.systemd),
                    assignment.clone(),
                    inventory,
                    [spec],
                )
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
                    )
                }
            }
        }
    }
}

fn require_authenticated_systemd_consumer_revision<T>() -> Result<T> {
    Err(anyhow!(
        "systemd active state and loaded revision do not authenticate the actual consumer revision"
    ))
}

fn drive_with_adapter<'plan, Adapter, Catalog, Policy>(
    session: &mut NativeAbilitySession<'plan>,
    operation: &aos_ability_model::ScopedOperationKey,
    adapter: &mut Adapter,
    catalog: &mut Catalog,
    policy: &mut OperatorAuthorizedPolicy<'_, Policy>,
    clock: &SystemMonotonicClock,
    cancellation: &CancellationToken,
) -> Result<()>
where
    Adapter: TrustedAdapter,
    Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
    Policy: TrustedAdmissionPolicy,
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
    )
}

fn drive_admitted_to_release<'plan, Adapter, Catalog, Policy>(
    session: &mut NativeAbilitySession<'plan>,
    admitted: AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
    adapter: &mut Adapter,
    catalog: &mut Catalog,
    policy: &mut OperatorAuthorizedPolicy<'_, Policy>,
    clock: &SystemMonotonicClock,
    cancellation: &CancellationToken,
) -> Result<()>
where
    Adapter: TrustedAdapter,
    Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
    Policy: TrustedAdmissionPolicy,
{
    loop {
        let action = session
            .transaction()
            .next_action(&admitted.operation().key)
            .map_err(anyhow::Error::new)?;
        match action {
            RecoveryAction::Execute { .. }
            | RecoveryAction::ReconcileBeforeRetry { .. }
            | RecoveryAction::ExecuteCompensation
            | RecoveryAction::ReconcileCompensation => {
                session
                    .drive_admitted(&admitted, adapter, policy, clock, cancellation)
                    .map_err(anyhow::Error::new)?
                    .map_err(anyhow::Error::new)?;
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
    method: &str,
    purpose: InvocationPurpose,
) -> bool {
    match (kind, interface, purpose) {
        (
            NativeAdapterKind::ManagedConfiguration,
            "aos.managed-configuration-effects",
            InvocationPurpose::Effect | InvocationPurpose::Reconcile | InvocationPurpose::Cancel,
        ) => matches!(method, "prepare" | "publish" | "release"),
        (
            NativeAdapterKind::NginxValidation,
            "aos.nginx-validation",
            InvocationPurpose::Effect | InvocationPurpose::Reconcile | InvocationPurpose::Cancel,
        ) => matches!(method, "validate" | "record" | "release"),
        (
            NativeAdapterKind::Systemd,
            aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME,
            InvocationPurpose::Effect,
        ) => matches!(method, "start" | "reload" | "restart" | "stop" | "observe"),
        (
            NativeAdapterKind::Systemd,
            aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME,
            InvocationPurpose::Reconcile | InvocationPurpose::Cancel,
        ) => method == "observe",
        (NativeAdapterKind::Systemd, "aos.systemd-service-effects", InvocationPurpose::Effect) => {
            matches!(method, "observe" | "reload" | "start" | "stop")
        }
        (
            NativeAdapterKind::Systemd,
            "aos.systemd-service-effects",
            InvocationPurpose::Reconcile | InvocationPurpose::Cancel,
        ) => method == "observe",
        _ => false,
    }
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

    #[test]
    fn native_method_matrix_is_closed_to_exact_adapter_contracts() {
        let supported = [
            (
                NativeAdapterKind::ManagedConfiguration,
                "aos.managed-configuration-effects",
                "publish",
                InvocationPurpose::Effect,
            ),
            (
                NativeAdapterKind::ManagedConfiguration,
                "aos.managed-configuration-effects",
                "publish",
                InvocationPurpose::Reconcile,
            ),
            (
                NativeAdapterKind::ManagedConfiguration,
                "aos.managed-configuration-effects",
                "release",
                InvocationPurpose::Cancel,
            ),
            (
                NativeAdapterKind::NginxValidation,
                "aos.nginx-validation",
                "validate",
                InvocationPurpose::Effect,
            ),
            (
                NativeAdapterKind::NginxValidation,
                "aos.nginx-validation",
                "record",
                InvocationPurpose::Reconcile,
            ),
            (
                NativeAdapterKind::NginxValidation,
                "aos.nginx-validation",
                "release",
                InvocationPurpose::Cancel,
            ),
            (
                NativeAdapterKind::Systemd,
                aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME,
                "restart",
                InvocationPurpose::Effect,
            ),
            (
                NativeAdapterKind::Systemd,
                aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME,
                "observe",
                InvocationPurpose::Reconcile,
            ),
            (
                NativeAdapterKind::Systemd,
                "aos.systemd-service-effects",
                "start",
                InvocationPurpose::Effect,
            ),
            (
                NativeAdapterKind::Systemd,
                "aos.systemd-service-effects",
                "observe",
                InvocationPurpose::Cancel,
            ),
        ];
        for (kind, interface, method, purpose) in supported {
            assert!(native_method_is_supported(kind, interface, method, purpose));
        }

        let rejected = [
            (
                NativeAdapterKind::ManagedConfiguration,
                "aos.nginx-validation",
                "publish",
                InvocationPurpose::Effect,
            ),
            (
                NativeAdapterKind::NginxValidation,
                "aos.nginx-validation",
                "publish",
                InvocationPurpose::Effect,
            ),
            (
                NativeAdapterKind::Systemd,
                aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME,
                "restart",
                InvocationPurpose::Reconcile,
            ),
            (
                NativeAdapterKind::Systemd,
                "aos.systemd-service-effects",
                "restart",
                InvocationPurpose::Effect,
            ),
            (
                NativeAdapterKind::Systemd,
                "aos.systemd-service-effects",
                "observe",
                InvocationPurpose::Compensate,
            ),
        ];
        for (kind, interface, method, purpose) in rejected {
            assert!(!native_method_is_supported(
                kind, interface, method, purpose
            ));
        }
    }

    #[test]
    fn native_no_op_rejects_failed_indeterminate_and_torn_prior_transactions() {
        for terminal in [None, Some(TerminalResult::SettledFailure)] {
            assert!(require_successful_retained_transaction(terminal, 0).is_err());
        }
        assert!(
            require_successful_retained_transaction(Some(TerminalResult::Succeeded), 1).is_err()
        );
        require_successful_retained_transaction(Some(TerminalResult::Succeeded), 0)
            .expect("settled exact prior success");
    }

    #[test]
    fn systemd_no_op_rejects_indeterminate_actual_consumer_revision() {
        let error = require_authenticated_systemd_consumer_revision::<()>()
            .expect_err("unit metadata alone must not authorize a native no-op");
        assert!(error.to_string().contains("actual consumer revision"));
    }
}
