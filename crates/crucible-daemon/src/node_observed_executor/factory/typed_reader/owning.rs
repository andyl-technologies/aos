//! Conjoins current behavioral authority with original typed source custody.
//!
//! A host installs this policy independently of package files. Its accepted
//! report authority, exact package identity and extension registry are separate
//! premises. Every original process and window is checked again under custody.

use std::{cell::RefCell, rc::Rc};

use crucible::node_adapters::cnp::{LineageReferenceQualification, OriginalRuntimeLineage};
use crucible::node_admission::{
    AdmittedGraph, InstalledExtensionPeerPolicy, InstalledExtensionRegistry,
};
use crucible::node_contract::{InputProvenanceClosure, OriginalInputLineage};
use crucible::node_scheduling::RuntimeInputBatch;
use crucible_node_contract::{
    ContentRef, ExtensionSelection, HashRef, Id, ResourceLimits, Validate,
};
use crucible_node_provider::{
    ProviderError, bodies::RealizeResult, client::OriginalLineageRealization,
    reference_lineage::LineageSourceGuard, reference_service::ReferenceProfile,
};

use super::{
    super::{NodeObservedError, refused},
    InstalledTypedReaderCatalogPolicy, InstalledTypedReaderPackage,
};
use super::{fixture_authority::InstalledTypedReaderFixtureAuthority, kernel};
use crate::node_qualification::{
    AcceptanceLimits, CnpBehavioralAcceptance, InstalledAcceptancePolicy,
};

#[path = "owning_windows.rs"]
mod windows;
use windows::WindowSeal;

struct Enrollment {
    provider: u32,
    native: u32,
    kernel: kernel::Enrollment,
    realization: RealizeResult,
}

struct OriginalSource {
    package: Rc<InstalledTypedReaderPackage>,
    profile: ReferenceProfile,
    resources: ResourceLimits,
    enrollment: RefCell<Option<Enrollment>>,
    graph: RefCell<Option<HashRef>>,
    windows: RefCell<Vec<WindowSeal>>,
    maximum_windows: usize,
}

/// Retains independent host trust and finite original-source policy capacity.
///
/// Construction does not install a namespace, certify a class or create Child.
/// The registry must already authenticate the exact source interpretation, and
/// the acceptance authority must already own the complete current certificate.
/// An absent certificate cannot be substituted with a successful package load.
pub struct InstalledTypedReaderOwningPolicy {
    pub(super) expected_package: ContentRef,
    pub(super) registry: Rc<InstalledExtensionRegistry>,
    authority: Rc<HostAuthority>,
    resources: ResourceLimits,
    sources: Rc<RefCell<Vec<Rc<OriginalSource>>>>,
}

impl InstalledTypedReaderOwningPolicy {
    /// Reserves three original policy holders before either native group exists.
    ///
    /// The fixed cohort contains two producers and one consumer. The separate
    /// complete custody reservation supplies their six slots plus whole runtime.
    /// This API does not select an ordinary provider or launch a process.
    ///
    /// # Errors
    /// Refuses absent independent behavioral authority, invalid package/resource
    /// scope or unavailable policy capacity. No package files are read here.
    pub fn new(
        expected_package: ContentRef,
        registry: Rc<InstalledExtensionRegistry>,
        acceptance: Option<Rc<dyn InstalledAcceptancePolicy>>,
        acceptance_limits: AcceptanceLimits,
        resources: ResourceLimits,
    ) -> Result<Self, NodeObservedError> {
        let acceptance = acceptance
            .ok_or_else(|| refused("complete typed reader behavioral authority unavailable"))?;
        expected_package.validate()?;
        resources.validate()?;
        if resources.processes.get() != 2
            || resources.maximum_operations.get() > 64
            || acceptance_limits.maximum_record_bytes == 0
        {
            return Err(refused("typed source original resource geometry differs"));
        }
        let mut sources = Vec::new();
        sources
            .try_reserve_exact(3)
            .map_err(|_| refused("typed original source policy credit"))?;
        Ok(Self {
            expected_package,
            registry,
            authority: Rc::new(HostAuthority::Accepted {
                policy: acceptance,
                limits: acceptance_limits,
            }),
            resources,
            sources: Rc::new(RefCell::new(sources)),
        })
    }
    pub(super) fn authenticate_launch(
        &self,
        parts: &super::InstalledTypedReaderPreparedParts,
        launch: &crucible_node_provider::reference_service::ReferenceNegotiatedLineageReaderLaunchBootstrap,
    ) -> Result<(), NodeObservedError> {
        self.authority
            .source(&parts.package, &parts.profile, &self.resources)
            .map_err(native_error)?;
        let expected = parts.package.profile(
            parts.profile.descriptor.id.clone(),
            parts.profile.owner.id.clone(),
            launch.bootstrap.quantum_ps,
            launch.bootstrap.host_budget_ns,
            launch.closed_ingress,
        )?;
        if expected.configuration_ref != parts.profile.configuration_ref
            || expected.descriptor != parts.profile.descriptor
            || expected.operating_contract != parts.profile.operating_contract
            || expected.guarantees != parts.profile.guarantees
            || expected.node_manifest != parts.profile.node_manifest
        {
            return Err(refused("typed private launch source configuration differs"));
        }
        if launch.bootstrap.resource_limits != self.resources {
            return Err(refused("typed private launch resources differ"));
        }
        match self.authority.as_ref() {
            HostAuthority::Fixture { policy, plan } => policy
                .authenticate_launch(plan, &parts.package, &parts.profile, launch)
                .map_err(native_error),
            // Class acceptance does not manufacture private host admission authority.
            HostAuthority::Accepted { .. } => {
                Err(refused("installed typed private launch issuer unavailable"))
            }
        }
    }

    /// Installs an independently configured finite onboarding fixture authority.
    ///
    /// This explicit route collects evidence without assuming a not-yet-produced
    /// acceptance certificate. It cannot convert fixture results into accepted
    /// ordinary classes. All original native/source checks remain identical.
    ///
    /// # Errors
    /// Refuses absent fixture authority or an unauthenticated/changed frozen plan
    /// before package reads, retention or Child allocation.
    pub fn for_conformance(
        expected_package: ContentRef,
        registry: Rc<InstalledExtensionRegistry>,
        fixture: Option<Rc<dyn InstalledTypedReaderFixtureAuthority>>,
        resources: ResourceLimits,
    ) -> Result<Self, NodeObservedError> {
        let fixture =
            fixture.ok_or_else(|| refused("independent typed fixture authority unavailable"))?;
        expected_package.validate()?;
        resources.validate()?;
        if resources.processes.get() != 2 || !(1..=64).contains(&resources.maximum_operations.get())
        {
            return Err(refused("typed fixture original resource geometry differs"));
        }
        let plan = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fixture.authenticate_fixture_plan(&expected_package, &resources)
        }))
        .map_err(|_| refused("installed typed fixture plan callback unwound"))?
        .map_err(native_error)?;
        plan.validate()?;
        let mut sources = Vec::new();
        sources
            .try_reserve_exact(3)
            .map_err(|_| refused("typed fixture source credit"))?;
        Ok(Self {
            expected_package,
            registry,
            resources,
            authority: Rc::new(HostAuthority::Fixture {
                policy: fixture,
                plan,
            }),
            sources: Rc::new(RefCell::new(sources)),
        })
    }
}

impl InstalledTypedReaderCatalogPolicy for InstalledTypedReaderOwningPolicy {
    fn prepare_original_policy(
        &self,
        package: &Rc<InstalledTypedReaderPackage>,
        profile: &ReferenceProfile,
        peer: &InstalledExtensionPeerPolicy,
        admitted: Option<(&AdmittedGraph, &Id)>,
        maximum_operations: usize,
    ) -> Result<Box<dyn LineageReferenceQualification>, NodeObservedError> {
        if package.identity() != &self.expected_package
            || !(1..=64).contains(&maximum_operations)
            || maximum_operations as u64 > self.resources.maximum_operations.get()
        {
            return Err(refused("typed source package or operation credit differs"));
        }
        // Fresh complete acceptance precedes policy retention and all Child work.
        self.authority
            .source(package, profile, &self.resources)
            .map_err(native_error)?;
        let installed = package.peer_policy(Rc::clone(&self.registry))?;
        let selected = package.definition().selection();
        if installed.contract(selected).map_err(native_error)?
            != peer.contract(selected).map_err(native_error)?
        {
            return Err(refused("typed source installed interpretation differs"));
        }
        check_profile(package, profile).map_err(native_error)?;
        if let Some((graph, node)) = admitted {
            check_graph(package, profile, &installed, graph, node).map_err(native_error)?;
        }
        let mut sources = self
            .sources
            .try_borrow_mut()
            .map_err(|_| refused("typed policy original borrow"))?;
        if sources.len() >= 3
            || sources
                .iter()
                .any(|source| source.profile.descriptor.id == profile.descriptor.id)
        {
            return Err(refused("typed original source holder already reserved"));
        }
        profile
            .preflight_retention(1024 * 1024)
            .map_err(native_error)?;
        let mut seals = Vec::new();
        seals
            .try_reserve_exact(maximum_operations)
            .map_err(|_| refused("typed original window credit"))?;
        let source = Rc::new(OriginalSource {
            package: Rc::clone(package),
            profile: profile.clone(),
            resources: self.resources.clone(),
            enrollment: RefCell::new(None),
            graph: RefCell::new(None),
            windows: RefCell::new(seals),
            maximum_windows: maximum_operations,
        });
        sources.push(Rc::clone(&source));
        Ok(Box::new(OriginalTypedPolicy {
            source,
            sources: Rc::clone(&self.sources),
            registry: Rc::clone(&self.registry),
            authority: Rc::clone(&self.authority),
        }))
    }
}

struct OriginalTypedPolicy {
    source: Rc<OriginalSource>,
    sources: Rc<RefCell<Vec<Rc<OriginalSource>>>>,
    registry: Rc<InstalledExtensionRegistry>,
    authority: Rc<HostAuthority>,
}

impl OriginalTypedPolicy {
    fn current(&self) -> Result<(), ProviderError> {
        let enrolled = self.source.enrollment.try_borrow().map_err(|_| invalid())?;
        let enrolled = enrolled.as_ref().ok_or_else(invalid)?;
        authenticate_acceptance(self.authority.as_ref(), &self.source, &enrolled.realization)?;
        if kernel::current(
            &self.source.package,
            enrolled.provider,
            enrolled.native,
            &self.source.resources,
            &enrolled.kernel.ready,
        )? != enrolled.kernel
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl LineageReferenceQualification for OriginalTypedPolicy {
    fn collection_plan(&self) -> Option<&ContentRef> {
        match self.authority.as_ref() {
            HostAuthority::Fixture { plan, .. } => Some(plan),
            HostAuthority::Accepted { .. } => None,
        }
    }

    fn authenticate_collection_dispatch(
        &self,
        plan: &crucible::node_admission::InstalledConformancePlan,
    ) -> Result<(), ProviderError> {
        let HostAuthority::Fixture {
            policy,
            plan: expected,
        } = self.authority.as_ref()
        else {
            return Err(invalid());
        };
        if plan.evidence().plan_ref != expected {
            return Err(invalid());
        }
        plan.reauthenticate().map_err(|_| invalid())?;
        self.current()?;
        // This configured callback ends with direct source owner reads. No
        // installed callback follows before the guarded transport operation.
        policy.authenticate_terminal_native(expected)
    }

    fn authenticate_collection_scope(
        &self,
        guard: &LineageSourceGuard,
        original: &OriginalLineageRealization<'_>,
        plan: &crucible::node_admission::InstalledConformancePlan,
    ) -> Result<(), ProviderError> {
        let HostAuthority::Fixture {
            policy,
            plan: expected,
        } = self.authority.as_ref()
        else {
            return Err(invalid());
        };
        if plan.evidence().plan_ref != expected {
            return Err(invalid());
        }
        plan.reauthenticate().map_err(|_| invalid())?;
        self.current()?;
        guard.verify_extension_registrar()?;
        check_profile(&self.source.package, original.profile())?;
        if original.profile().descriptor != self.source.profile.descriptor
            || original.profile().configuration_ref != self.source.profile.configuration_ref
            || original.profile().owner != self.source.profile.owner
        {
            return Err(invalid());
        }
        policy.authenticate_realization(
            expected,
            &self.source.package,
            &self.source.profile,
            guard,
            original,
            &self.source.resources,
        )?;
        guard.verify_extension_registrar()
    }

    fn authenticate_realization(
        &self,
        guard: &LineageSourceGuard,
        original: &OriginalLineageRealization<'_>,
    ) -> Result<(), ProviderError> {
        check_profile(&self.source.package, original.profile())?;
        if original.profile().descriptor != self.source.profile.descriptor
            || original.bootstrap().resource_limits != self.source.resources
        {
            return Err(invalid());
        }
        guard.verify_extension_registrar()?;
        authenticate_acceptance(
            self.authority.as_ref(),
            &self.source,
            original.realization(),
        )?;
        if let HostAuthority::Fixture { policy, plan } = self.authority.as_ref() {
            policy.authenticate_realization(
                plan,
                &self.source.package,
                &self.source.profile,
                guard,
                original,
                &self.source.resources,
            )?;
        }
        let provider = guard.provider_pid().ok_or_else(invalid)?;
        let native = u32::try_from(original.native_pid().get()).map_err(|_| invalid())?;
        let measured = kernel::enroll(
            &self.source.package,
            provider,
            original,
            &self.source.resources,
        )?;
        let mut retained = self
            .source
            .enrollment
            .try_borrow_mut()
            .map_err(|_| invalid())?;
        match retained.as_ref() {
            Some(old)
                if old.provider == provider
                    && old.native == native
                    && old.kernel == measured
                    && old.realization == *original.realization() =>
            {
                Ok(())
            }
            Some(_) => Err(invalid()),
            None => {
                windows::count(original.realization(), 1024 * 1024)?;
                *retained = Some(Enrollment {
                    provider,
                    native,
                    kernel: measured,
                    realization: original.realization().clone(),
                });
                Ok(())
            }
        }
    }

    fn authenticate_peer_extensions(
        &self,
        guard: &LineageSourceGuard,
        original: &OriginalLineageRealization<'_>,
        selected: &[ExtensionSelection],
        admitted: Option<(&AdmittedGraph, &Id)>,
    ) -> Result<(), ProviderError> {
        self.current()?;
        guard.verify_extension_registrar()?;
        if selected != std::slice::from_ref(self.source.package.definition().selection())
            || guard.selected_extensions() != Some(selected)
            || original.profile().descriptor != self.source.profile.descriptor
        {
            return Err(invalid());
        }
        let peer = self
            .source
            .package
            .peer_policy(Rc::clone(&self.registry))
            .map_err(|_| invalid())?;
        if let Some((graph, node)) = admitted {
            check_graph(
                &self.source.package,
                &self.source.profile,
                &peer,
                graph,
                node,
            )?;
            let mut retained = self.source.graph.try_borrow_mut().map_err(|_| invalid())?;
            match retained.as_ref() {
                Some(old) if old != graph.world_binding_hash() => return Err(invalid()),
                Some(_) => {}
                None => *retained = Some(graph.world_binding_hash().clone()),
            }
        }
        guard.verify_extension_registrar()
    }

    fn authenticate_original_inputs(
        &self,
        guard: &LineageSourceGuard,
        original: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<(), ProviderError> {
        self.current()?;
        guard.verify_extension_registrar()?;
        windows::authenticate_inputs(self, original, provenance, lineage)?;
        if let HostAuthority::Fixture { policy, plan } = self.authority.as_ref() {
            policy.authenticate_inputs(
                plan,
                &self.source.package,
                &self.source.profile,
                original,
                provenance,
                lineage,
            )?;
        }
        guard.verify_extension_registrar()
    }

    fn authenticate_window(
        &self,
        original: &OriginalRuntimeLineage<'_>,
    ) -> Result<(), ProviderError> {
        self.current()?;
        windows::authenticate_window(self, original)
    }
}

enum HostAuthority {
    Accepted {
        policy: Rc<dyn InstalledAcceptancePolicy>,
        limits: AcceptanceLimits,
    },
    Fixture {
        policy: Rc<dyn InstalledTypedReaderFixtureAuthority>,
        plan: ContentRef,
    },
}

impl HostAuthority {
    fn source(
        &self,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        resources: &ResourceLimits,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Accepted { policy, limits } => {
                CnpBehavioralAcceptance::new(policy.as_ref(), *limits)
                    .authenticate_prelaunch(profile, resources)
                    .map_err(|_| invalid())
            }
            Self::Fixture { policy, plan } => {
                if policy.authenticate_fixture_plan(package.identity(), resources)? != *plan {
                    return Err(invalid());
                }
                policy.authenticate_source(plan, package, profile, resources)
            }
        }
    }

    fn realization(
        &self,
        source: &OriginalSource,
        original: &RealizeResult,
    ) -> Result<(), ProviderError> {
        self.source(&source.package, &source.profile, &source.resources)?;
        match self {
            Self::Accepted { policy, limits } => {
                CnpBehavioralAcceptance::new(policy.as_ref(), *limits)
                    .authenticate_original_realization(&source.profile, original, &source.resources)
                    .map_err(|_| invalid())
            }
            Self::Fixture { .. } => Ok(()),
        }
    }
}

fn authenticate_acceptance(
    authority: &HostAuthority,
    source: &OriginalSource,
    realization: &RealizeResult,
) -> Result<(), ProviderError> {
    authority.realization(source, realization)
}

fn check_profile(
    package: &InstalledTypedReaderPackage,
    profile: &ReferenceProfile,
) -> Result<(), ProviderError> {
    let Some(definition) = profile.input_lineage_definition() else {
        return Err(invalid());
    };
    if definition.selection() != package.definition().selection()
        || definition.declaration() != package.definition().declaration()
        || definition.handler() != package.definition().handler()
    {
        return Err(invalid());
    }
    // Regenerate the complete profile from this installation, not supplied labels.
    let (reference, bytes) = profile
        .contents
        .get(&profile.configuration_ref.hash.digest)
        .ok_or_else(invalid)?;
    if reference != &profile.configuration_ref {
        return Err(invalid());
    }
    reference.verify(bytes)?;
    let value = crucible_node_contract::canonical::parse_json(bytes, 65536)?;
    let quantum = serde_json::from_value(value.get("quantum_ps").cloned().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let budget = serde_json::from_value(value.get("host_budget_ns").cloned().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let closed = match value
        .get("input_policy")
        .and_then(serde_json::Value::as_str)
    {
        Some("closed-no-ingress") => true,
        Some("admitted-causal-source") => false,
        _ => return Err(invalid()),
    };
    let expected = package
        .profile(
            profile.descriptor.id.clone(),
            profile.owner.id.clone(),
            quantum,
            budget,
            closed,
        )
        .map_err(|_| invalid())?;
    if profile.descriptor != expected.descriptor
        || profile.implementation != expected.implementation
        || profile.operating_contract != expected.operating_contract
        || profile.capabilities != expected.capabilities
        || profile.guarantees != expected.guarantees
        || profile.owner != expected.owner
        || profile.node_manifest != expected.node_manifest
        || profile.provider_manifest != expected.provider_manifest
        || profile.configuration_ref != expected.configuration_ref
        || profile.content_possession_schema != expected.content_possession_schema
        || profile.contents != expected.contents
    {
        return Err(invalid());
    }
    Ok(())
}

fn check_graph(
    package: &InstalledTypedReaderPackage,
    profile: &ReferenceProfile,
    peer: &InstalledExtensionPeerPolicy,
    graph: &AdmittedGraph,
    node: &Id,
) -> Result<(), ProviderError> {
    let selection = package.definition().selection();
    let (_, handler, semantics) = peer.contract(selection)?;
    let selected = graph
        .selected_extensions()
        .definitions()
        .find(|entry| entry.selection() == selection)
        .ok_or_else(invalid)?;
    if node != &profile.descriptor.id
        || graph.descriptor(node) != Some(&profile.descriptor)
        || selected.handler_identity() != handler
        || selected.semantic_contract() != semantics
    {
        return Err(invalid());
    }
    let binding = graph.binding(node).ok_or_else(invalid)?;
    let selected_use = package.definition().durable_extensions()?;
    if binding.compatibility.extensions != selected_use
        || binding.compatibility.operating_contract != profile.operating_contract
    {
        return Err(invalid());
    }
    Ok(())
}

fn native_error(error: ProviderError) -> NodeObservedError {
    NodeObservedError::Native(error.to_string())
}
fn invalid() -> ProviderError {
    ProviderError::Correlation("installed typed original source policy differs")
}

pub(super) fn count_launch(
    value: &impl serde::Serialize,
    maximum: usize,
) -> Result<(), ProviderError> {
    windows::count(value, maximum)
}
