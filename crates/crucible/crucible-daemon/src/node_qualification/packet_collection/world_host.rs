//! Retains three original packet peers through one whole-world collection actor.
//!
//! All peer mailboxes, 54 attempted-case tickets, the one runtime slot and both
//! publishers exist before Child. One public registry realizes the three peers;
//! one complete graph and one provider capsule establish the all-owner barrier.
//! No singleton activation, guard reconstruction or ordinary graph escapes.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    task::{Context, Poll},
};

use crucible_engine::{
    node_adapters::cnp::{
        CnpSemanticAdmissionFailure, CnpSemanticConformanceNode,
        CnpSemanticConformanceWorldProvider, CnpSemanticLaunchGuard, CnpSemanticPreparation,
        CnpSemanticPreparationFailure, CnpSemanticRegistry, CnpSemanticSource,
        CnpSemanticWorldPreparationFailure, CnpSemanticWorldReservationFailure,
        InstalledCnpConformanceRole,
    },
    node_admission::{
        AdmissionError, AdmissionLimits, AdmissionRequest, ConformanceGraph,
        InstalledConformancePlan, ScenarioRequirements, admit_conformance_graph,
    },
    node_contract::{
        ActivationPublisher, ActivationRecord, ConformanceResultPublisher, ConformanceRuntime,
        RuntimeCustodySlot, RuntimeLimits,
    },
};
use crucible_node_transport::handshake::TrustedHandshakeVerifier;

use super::{
    InstalledPacketWorldCollectionAuthority, PacketCollectionFailure, PacketHostPhase,
    PacketPeerLaunchFailure, PacketWorldActor, PacketWorldActorFailure, PacketWorldActorPhase,
    PacketWorldCaseReservations, PreparedPacketCollectionPeer, QualificationError,
};
use crate::node_qualification::CollectedConformance;

/// Supplies the complete original pre-Child whole-world invocation.
pub struct PacketWorldHostRequest<'a, V, A, R> {
    /// Owns all three peer capsules prepared by the SAME installed authority.
    pub peers: [Box<PreparedPacketCollectionPeer<'a, V>>; 3],
    /// Owns all 54 original attempted-case tickets reserved before any Child.
    pub cases: PacketWorldCaseReservations<'a, InstalledPacketWorldCollectionAuthority>,
    /// Retains the identical opaque plan Rc used by the case reservations.
    pub plan: Rc<InstalledConformancePlan>,
    /// Owns the complete source-authored requirements with no omitted participants.
    pub requirements: ScenarioRequirements,
    /// Owns the complete original activation proposal without predicted Ready.
    pub activation: ActivationRecord,
    /// Owns the single original full-world reservation made before Child.
    pub runtime_custody: Box<dyn RuntimeCustodySlot>,
    /// Bounds complete original structural admission without weakened defaults.
    pub admission_limits: AdmissionLimits,
    /// Bounds all participants' operation, output and cleanup ledgers.
    pub runtime_limits: RuntimeLimits,
    /// Owns the authentic same-world durable initial coordinator publisher.
    pub activation_publisher: A,
    /// Owns the actual durable publisher for all 27 original result placements.
    pub result_publisher: R,
    /// Bounds actual post-Arm initial coordinator construction before any copies.
    pub maximum_coordinator_bytes: usize,
}

/// Describes a held original whole-world failure without claiming reclamation.
pub enum PacketWorldHostFailure {
    /// Refuses a repeated launch or unavailable original preparation phase.
    Phase,
    /// Retains the original launch, realization, admission or transfer refusal.
    Preparation,
    /// Retains the original actor's native, report or durable-publication failure.
    Lifecycle(PacketCollectionFailure),
    /// Keeps the same upper capsule outside a callback unwind boundary.
    Unwind,
}

/// Retains the complete native-free host on preparation refusal.
pub struct PacketWorldHostPreparationFailure<'a, V, A, R> {
    /// Reports the actual current-scope, credit or original-roster refusal.
    pub error: QualificationError,
    /// Keeps all original peer reservations, publishers and attempted cases.
    pub original: Box<PacketWorldHost<'a, V, A, R>>,
}

/// Owns one actual full-world realization and its nine-window actor.
///
/// Every participant enters this holder before any launch or metadata callback.
/// Refusal seals Held; it never starts a replacement Child. Native lower owners
/// retain their original supervisor transfer contracts across consuming SDK
/// operations; this holder retains the full upper proposal, plan and failures.
/// Trusted mailbox lifetime, allocator failure and consuming runner finalization
/// retain their separate limits. Portable reports grant no accepted class.
#[must_use = "keep the whole original host until authenticated supervised retirement"]
pub struct PacketWorldHost<'a, V, A, R> {
    authority: &'a Rc<InstalledPacketWorldCollectionAuthority>,
    peers: [Option<Box<PreparedPacketCollectionPeer<'a, V>>>; 3],
    launch_failures: [Option<PacketPeerLaunchFailure<'a, V>>; 3],
    guards: [Option<CnpSemanticLaunchGuard>; 3],
    roles: [Option<InstalledCnpConformanceRole>; 3],
    preparations: [Option<CnpSemanticPreparation>; 3],
    realization_failures: [Option<CnpSemanticPreparationFailure>; 3],
    admission_failures: [Option<CnpSemanticAdmissionFailure>; 3],
    nodes: Vec<CnpSemanticConformanceNode>,
    native: Vec<Box<dyn crucible_engine::node_contract::SimulationNode>>,
    graph: Option<ConformanceGraph>,
    graph_failure: Option<AdmissionError>,
    descriptors: Vec<crucible_node_format::NodeDescriptor>,
    bindings: Vec<crucible_node_format::NodeBinding>,
    owners: Vec<crucible_node_format::OwnerBinding>,
    provider: Option<CnpSemanticConformanceWorldProvider>,
    reservation_failure: Option<CnpSemanticWorldReservationFailure>,
    transfer_failure: Option<CnpSemanticWorldPreparationFailure>,
    runtime: Option<ConformanceRuntime>,
    cases: Option<PacketWorldCaseReservations<'a, InstalledPacketWorldCollectionAuthority>>,
    actor: Option<PacketWorldActor<'a, InstalledPacketWorldCollectionAuthority, A, R>>,
    actor_failure:
        Option<Box<PacketWorldActorFailure<'a, InstalledPacketWorldCollectionAuthority, A, R>>>,
    activation_publisher: Option<A>,
    result_publisher: Option<R>,
    plan: Rc<InstalledConformancePlan>,
    requirements: ScenarioRequirements,
    activation: Option<ActivationRecord>,
    runtime_custody: Option<Box<dyn RuntimeCustodySlot>>,
    registry: Option<CnpSemanticRegistry>,
    admission_limits: AdmissionLimits,
    runtime_limits: RuntimeLimits,
    maximum_coordinator_bytes: usize,
    phase: PacketHostPhase,
}

impl InstalledPacketWorldCollectionAuthority {
    /// Prepares one owning caller for all three peers without native effects.
    ///
    /// # Errors
    /// Returns the same complete holder on wrong authority/plan/owner roster,
    /// altered requirements, exhausted whole-world credit or source registration
    /// refusal. Every original attempted ticket and publisher remains retained.
    // Success and failure retain the same generic native/publisher ownership;
    // the complete returned capsule must stay explicit in this public contract.
    #[allow(clippy::type_complexity)]
    pub fn prepare_world_host<'a, V, A, R>(
        self: &'a Rc<Self>,
        request: PacketWorldHostRequest<'a, V, A, R>,
    ) -> Result<Box<PacketWorldHost<'a, V, A, R>>, PacketWorldHostPreparationFailure<'a, V, A, R>>
    where
        V: TrustedHandshakeVerifier,
        A: ActivationPublisher,
        R: ConformanceResultPublisher,
    {
        let [peer0, peer1, peer2] = request.peers;
        let mut original = Box::new(PacketWorldHost {
            authority: self,
            peers: [Some(peer0), Some(peer1), Some(peer2)],
            launch_failures: [None, None, None],
            guards: [None, None, None],
            roles: [None, None, None],
            preparations: [None, None, None],
            realization_failures: [None, None, None],
            admission_failures: [None, None, None],
            nodes: Vec::new(),
            native: Vec::new(),
            graph: None,
            graph_failure: None,
            descriptors: Vec::new(),
            bindings: Vec::new(),
            owners: Vec::new(),
            provider: None,
            reservation_failure: None,
            transfer_failure: None,
            runtime: None,
            cases: Some(request.cases),
            actor: None,
            actor_failure: None,
            activation_publisher: Some(request.activation_publisher),
            result_publisher: Some(request.result_publisher),
            plan: request.plan,
            requirements: request.requirements,
            activation: Some(request.activation),
            runtime_custody: Some(request.runtime_custody),
            registry: None,
            admission_limits: request.admission_limits,
            runtime_limits: request.runtime_limits,
            maximum_coordinator_bytes: request.maximum_coordinator_bytes,
            phase: PacketHostPhase::Prepared,
        });
        let checked = catch_unwind(AssertUnwindSafe(|| {
            if original.maximum_coordinator_bytes == 0
                || original.maximum_coordinator_bytes > 65_536
                || original.runtime_limits.maximum_nodes < 3
                || original.runtime_limits.maximum_owners < 3
                || !original.cases.as_ref().is_some_and(|cases| {
                    cases.has_original_authority(self.as_ref(), &original.plan)
                })
            {
                return Err(refused());
            }
            self.validate_world_proposal(
                &original.requirements,
                original.activation.as_ref().ok_or_else(refused)?,
            )?;
            for member in 0..3 {
                if !original.peers[member]
                    .as_ref()
                    .is_some_and(|peer| peer.has_world_authority(self.as_ref(), member))
                {
                    return Err(refused());
                }
            }
            // Reserve complete participants before Child. Each actual node is
            // moved into this same Vec before the next source callback.
            super::scope::encoded_size(
                &(
                    (
                        &self.source(0)?.installation().descriptor,
                        &self.source(0)?.installation().binding,
                        &self.source(0)?.installation().owner,
                    ),
                    (
                        &self.source(1)?.installation().descriptor,
                        &self.source(1)?.installation().binding,
                        &self.source(1)?.installation().owner,
                    ),
                    (
                        &self.source(2)?.installation().descriptor,
                        &self.source(2)?.installation().binding,
                        &self.source(2)?.installation().owner,
                    ),
                ),
                8 * 1024 * 1024,
            )?;
            original.nodes.try_reserve_exact(3).map_err(|_| refused())?;
            original
                .native
                .try_reserve_exact(3)
                .map_err(|_| refused())?;
            original
                .descriptors
                .try_reserve_exact(3)
                .map_err(|_| refused())?;
            original
                .bindings
                .try_reserve_exact(3)
                .map_err(|_| refused())?;
            original
                .owners
                .try_reserve_exact(3)
                .map_err(|_| refused())?;
            for member in 0..3 {
                let selected = self.source(member)?.installation();
                original.descriptors.push(selected.descriptor.clone());
                original.bindings.push(selected.binding.clone());
                original.owners.push(selected.owner.clone());
            }
            original.registry = Some(
                CnpSemanticRegistry::new(self.clone(), 3)
                    .map_err(|error| QualificationError::Evidence(error.reason))?,
            );
            for member in 0..3 {
                original.roles[member] = Some(
                    original
                        .registry
                        .as_mut()
                        .ok_or_else(refused)?
                        .install_for_conformance(
                            self.source(member)?.clone(),
                            self.clone(),
                            &original.plan,
                        )
                        .map_err(|error| QualificationError::Evidence(error.reason))?,
                );
            }
            original
                .plan
                .reauthenticate()
                .map_err(|error| QualificationError::Evidence(error.to_string()))?;
            self.current()
        }));
        let error = match checked {
            Ok(Ok(())) => return Ok(original),
            Ok(Err(error)) => error,
            Err(_) => QualificationError::Refused("packet full-world preparation callback unwound"),
        };
        original.phase = PacketHostPhase::Held;
        Err(PacketWorldHostPreparationFailure { error, original })
    }
}

impl<'a, V: TrustedHandshakeVerifier, A: ActivationPublisher, R: ConformanceResultPublisher>
    PacketWorldHost<'a, V, A, R>
{
    /// Transfers original native custody without consuming upper source or publication data.
    ///
    /// # Errors
    /// Keeps the complete host on unresolved or unsupported borrowed cleanup.
    /// Ok records transfer only; the supervisor independently proves actual
    /// kernel and whole-world reclamation.
    ///
    /// # Panics
    /// Installed cleanup callbacks may unwind. Keep this host outside the
    /// boundary. Trusted native slots retain without unwinding, as on Drop.
    pub fn retire_original(&mut self) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.phase = PacketHostPhase::Held;
        if let Some(actor) = self.actor.as_mut() {
            actor.retire_original()?;
        }
        if let Some(failure) = self.actor_failure.as_mut() {
            failure.original.retire_original()?;
        }
        if let Some(runtime) = self.runtime.as_mut() {
            runtime.retire_original()?;
        }
        if let Some(CnpSemanticWorldPreparationFailure::Runtime(failure)) =
            self.transfer_failure.as_mut()
        {
            failure.retire_original()?;
        }
        if let Some(provider) = self.provider.as_mut() {
            provider.retire_original(self.runtime_limits)?;
        }
        if let Some(failure) = self.reservation_failure.as_mut() {
            failure.original.retire_original(self.runtime_limits)?;
        }
        for node in &mut self.nodes {
            node.retire_original();
        }
        for member in 0..3 {
            if let Some(peer) = self.peers[member].as_mut() {
                peer.retire_original();
            }
            if let Some(failure) = self.launch_failures[member].as_mut() {
                failure.original.retire_original();
            }
            if let Some(guard) = self.guards[member].as_mut() {
                guard.retire_original();
            }
            if let Some(preparation) = self.preparations[member].as_mut() {
                preparation.retire_original();
            }
            if let Some(failure) = self.realization_failures[member].as_mut() {
                failure.retire_original();
            }
            if let Some(failure) = self.admission_failures[member].as_mut() {
                failure.retire_original();
            }
        }
        // This slot exists here only before provider/runtime adoption. Its
        // original unused reservation is released; transferred slots stay in
        // their retained provider/runtime shells and the same queue.
        drop(self.runtime_custody.take());
        Ok(())
    }

    /// Launches and realizes the original full world once, retaining all failures.
    ///
    /// # Errors
    /// Retains original guards, realizations, nodes, proposal and publishers on
    /// any peer, source, graph, remote Admit or runtime construction refusal.
    pub fn start(&mut self) -> Result<(), PacketWorldHostFailure> {
        if self.phase != PacketHostPhase::Prepared {
            return Err(PacketWorldHostFailure::Phase);
        }
        self.phase = PacketHostPhase::Held;
        match catch_unwind(AssertUnwindSafe(|| self.start_original())) {
            Ok(result) => result,
            Err(_) => Err(PacketWorldHostFailure::Unwind),
        }
    }

    /// Borrows the concrete retained start refusal without extracting native custody.
    ///
    /// The view covers original launch, realization, admission and runtime transfer
    /// failures. It runs no callback and allocates no diagnostic copy.
    pub fn start_error(&self) -> Option<&dyn std::fmt::Debug> {
        if let Some(failure) = self.launch_failures.iter().flatten().next() {
            return Some(&failure.error);
        }
        if let Some(failure) = self.realization_failures.iter().flatten().next() {
            return Some(&failure.error);
        }
        if let Some(failure) = &self.graph_failure {
            return Some(failure);
        }
        if let Some(failure) = self.admission_failures.iter().flatten().next() {
            return Some(&failure.error);
        }
        if let Some(failure) = &self.reservation_failure {
            return Some(&failure.error);
        }
        if let Some(failure) = &self.transfer_failure {
            return match failure {
                CnpSemanticWorldPreparationFailure::Held(error) => Some(error),
                CnpSemanticWorldPreparationFailure::Runtime(failure) => Some(&failure.reason),
            };
        }
        if let Some(failure) = &self.actor_failure {
            return Some(&failure.error);
        }

        None
    }

    fn start_original(&mut self) -> Result<(), PacketWorldHostFailure> {
        for member in 0..3 {
            let peer = self.peers[member]
                .take()
                .ok_or(PacketWorldHostFailure::Phase)?;
            match peer.start() {
                Ok(guard) => self.guards[member] = Some(guard),
                Err(failure) => {
                    self.launch_failures[member] = Some(failure);
                    return Err(PacketWorldHostFailure::Preparation);
                }
            }
        }
        for member in 0..3 {
            let guard = self.guards[member]
                .take()
                .ok_or(PacketWorldHostFailure::Phase)?;
            let role = self.roles[member]
                .take()
                .ok_or(PacketWorldHostFailure::Phase)?;
            match CnpSemanticPreparation::prepare_for_conformance(guard, role) {
                Ok(preparation) => self.preparations[member] = Some(preparation),
                Err(failure) => {
                    self.realization_failures[member] = Some(failure);
                    return Err(PacketWorldHostFailure::Preparation);
                }
            }
        }
        let admission = admit_conformance_graph(
            AdmissionRequest {
                world: self.authority.world(),
                descriptors: &self.descriptors,
                bindings: &self.bindings,
                owners: &self.owners,
                requirements: &self.requirements,
            },
            &self.plan,
            self.admission_limits,
        );
        match admission {
            Ok(graph) => self.graph = Some(graph),
            Err(error) => {
                self.graph_failure = Some(error);
                return Err(PacketWorldHostFailure::Preparation);
            }
        }
        for member in 0..3 {
            let preparation = self.preparations[member]
                .take()
                .ok_or(PacketWorldHostFailure::Phase)?;
            match preparation
                .into_conformance_node(self.graph.as_ref().ok_or(PacketWorldHostFailure::Phase)?)
            {
                Ok(node) => self.nodes.push(node),
                Err(failure) => {
                    self.admission_failures[member] = Some(failure);
                    return Err(PacketWorldHostFailure::Preparation);
                }
            }
        }
        let graph = self.graph.take().ok_or(PacketWorldHostFailure::Phase)?;
        let activation = self
            .activation
            .take()
            .ok_or(PacketWorldHostFailure::Phase)?;
        let slot = self
            .runtime_custody
            .take()
            .ok_or(PacketWorldHostFailure::Phase)?;
        match CnpSemanticConformanceWorldProvider::reserve(
            std::mem::take(&mut self.nodes),
            std::mem::take(&mut self.native),
            activation,
            graph,
            slot,
        ) {
            Ok(provider) => self.provider = Some(provider),
            Err(failure) => {
                self.reservation_failure = Some(failure);
                return Err(PacketWorldHostFailure::Preparation);
            }
        }
        match self
            .provider
            .as_mut()
            .ok_or(PacketWorldHostFailure::Phase)?
            .prepare_conformance(self.runtime_limits)
        {
            Ok(runtime) => self.runtime = Some(runtime),
            Err(failure) => {
                self.transfer_failure = Some(failure);
                return Err(PacketWorldHostFailure::Preparation);
            }
        }
        let cases = self.cases.take().ok_or(PacketWorldHostFailure::Phase)?;
        let runtime = self.runtime.take().ok_or(PacketWorldHostFailure::Phase)?;
        let activation = self
            .activation_publisher
            .take()
            .ok_or(PacketWorldHostFailure::Phase)?;
        let result = self
            .result_publisher
            .take()
            .ok_or(PacketWorldHostFailure::Phase)?;
        match cases.attach(runtime, activation, result, self.maximum_coordinator_bytes) {
            Ok(actor) => self.actor = Some(actor),
            Err(failure) => {
                self.actor_failure = Some(failure);
                return Err(PacketWorldHostFailure::Preparation);
            }
        }
        self.phase = PacketHostPhase::Running;
        Ok(())
    }

    /// Polls the one original nine-window actor without another peer or Begin.
    ///
    /// # Errors
    /// Keeps original runtime, report bodies, tokens and publishers on refusal or
    /// unwind. Only same-body publication reconciliation can be polled again.
    pub fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), PacketWorldHostFailure>> {
        if self.phase == PacketHostPhase::Complete {
            return Poll::Ready(Ok(()));
        }
        if self.phase != PacketHostPhase::Running {
            return Poll::Ready(Err(PacketWorldHostFailure::Phase));
        }
        let Some(actor) = self.actor.as_mut() else {
            self.phase = PacketHostPhase::Held;
            return Poll::Ready(Err(PacketWorldHostFailure::Phase));
        };
        match catch_unwind(AssertUnwindSafe(|| actor.poll(context))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(Ok(()))) => {
                self.phase = PacketHostPhase::Complete;
                Poll::Ready(Ok(()))
            }
            Ok(Poll::Ready(Err(error))) => {
                if actor.phase() == PacketWorldActorPhase::Held {
                    self.phase = PacketHostPhase::Held;
                }
                Poll::Ready(Err(PacketWorldHostFailure::Lifecycle(error)))
            }
            Err(_) => {
                self.phase = PacketHostPhase::Held;
                Poll::Ready(Err(PacketWorldHostFailure::Unwind))
            }
        }
    }

    /// Reports data-only progress without granting an ordinary graph or runtime.
    pub fn phase(&self) -> PacketHostPhase {
        self.phase
    }

    /// Borrows data-only actor progress while preserving all native and runtime custody.
    pub fn progress(&self) -> Option<(super::PacketWorldActorPhase, usize, usize)> {
        self.actor.as_ref().map(PacketWorldActor::progress)
    }

    /// Borrows original observations while all unknown normative rows stay explicit.
    pub fn collected(&self) -> Option<&[Option<CollectedConformance>; 3]> {
        self.actor.as_ref().map(PacketWorldActor::collected)
    }
}

fn refused() -> QualificationError {
    QualificationError::Refused("original packet whole-world host scope unavailable")
}
