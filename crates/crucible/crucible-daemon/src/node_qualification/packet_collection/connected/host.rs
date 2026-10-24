//! Retains three original native peers and the genuine shared scheduler owner.
//!
//! The complete holder exists before Child and survives callback failure or
//! unwind. One graph, original runtime slot and opaque plan cover native three
//! plus the host scheduler. The legacy disconnected whole-world holder is separate.

use super::super::peer::connected::{
    PacketConnectedPeerLaunchFailure, PreparedPacketConnectedPeer,
};
use super::{InstalledPacketConnectedCollectionAuthority, QualificationError, refused};
use crucible_engine::{
    node_adapters::cnp::{
        CnpSemanticAdmissionFailure, CnpSemanticConformanceNode,
        CnpSemanticConformanceWorldProvider, CnpSemanticExactConformanceWorldProvider,
        CnpSemanticExactWorldReservation, CnpSemanticExactWorldReservationFailure,
        CnpSemanticLaunchGuard, CnpSemanticPreparation, CnpSemanticPreparationFailure,
        CnpSemanticRegistry, CnpSemanticWorldPreparationFailure, InstalledCnpConformanceRole,
    },
    node_admission::{
        AdmissionError, AdmissionLimits, AdmissionRequest, ConformanceAdmissionAuthority,
        ConformanceGraph, InstalledConformancePlan, ScenarioRequirements, admit_conformance_graph,
    },
    node_contract::{
        ActivationRecord, ConformanceRuntime, HostSchedulingSource, PreparedHostSchedulingNode,
        RuntimeCustodySlot, RuntimeError, RuntimeLimits, SimulationNode,
    },
};
use crucible_node_format::{NodeBinding, NodeDescriptor, OwnerBinding};
use crucible_node_transport::handshake::TrustedHandshakeVerifier;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
};

/// Transfers one complete pre-Child connected invocation into its original holder.
pub struct PacketConnectedHostRequest<'a, V> {
    /// Owns three previously prepared actual private peer capsules.
    pub peers: [Box<PreparedPacketConnectedPeer<'a, V>>; 3],
    /// Retains the same installed plan used by every actual native source.
    pub plan: Rc<InstalledConformancePlan>,
    /// Owns the complete four-node scenario requirements.
    pub requirements: ScenarioRequirements,
    /// Owns the original complete activation proposal without predicted Ready.
    pub activation: ActivationRecord,
    /// Owns the single original runtime reservation made before Child.
    pub runtime_custody: Box<dyn RuntimeCustodySlot>,
    /// Bounds complete graph admission without an ordinary-class exemption.
    pub admission_limits: AdmissionLimits,
    /// Bounds all original operation, input, output and cleanup ledgers.
    pub runtime_limits: RuntimeLimits,
}

/// Keeps the complete original invocation when connected preparation refuses.
pub struct PacketConnectedHostPreparationFailure<'a, V> {
    /// Reports the concrete original static preparation refusal.
    pub error: QualificationError,
    /// Retains all native-free reservations and original source metadata.
    pub original: Box<PacketConnectedHost<'a, V>>,
}

/// Distinguishes original preparation refusal from a held callback unwind.
#[derive(Debug)]
pub enum PacketConnectedHostFailure {
    /// Refuses a repeated or incomplete original transition.
    Phase,
    /// Retains the original concrete preparation refusal in the owning holder.
    Preparation,
    /// Retains the complete same holder after an installed callback unwinds.
    Unwind,
}

/// Owns one native-three/host-one exact collecting runtime and its failed custody.
///
/// The runtime getter exposes only the collecting facade. It cannot extract an
/// ordinary graph, native node, activation permission or accepted class. Keep
/// this holder and its original supervisor outside any callback unwind boundary.
#[must_use = "retain all original connected custody through authenticated reclamation"]
pub struct PacketConnectedHost<'a, V> {
    authority: &'a Rc<InstalledPacketConnectedCollectionAuthority>,
    peers: [Option<Box<PreparedPacketConnectedPeer<'a, V>>>; 3],
    launch_failures: [Option<PacketConnectedPeerLaunchFailure<'a, V>>; 3],
    guards: [Option<CnpSemanticLaunchGuard>; 3],
    roles: [Option<InstalledCnpConformanceRole>; 3],
    preparations: [Option<CnpSemanticPreparation>; 3],
    realization_failures: [Option<CnpSemanticPreparationFailure>; 3],
    admission_failures: [Option<CnpSemanticAdmissionFailure>; 3],
    nodes: Vec<CnpSemanticConformanceNode>,
    native: Vec<Box<dyn SimulationNode>>,
    host_node: Option<PreparedHostSchedulingNode>,
    host_error: Option<crucible_engine::node_contract::OperationFailure>,
    host: Rc<HostSchedulingSource>,
    graph: Option<ConformanceGraph>,
    graph_failure: Option<AdmissionError>,
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerBinding>,
    provider: Option<CnpSemanticExactConformanceWorldProvider>,
    reservation_failure: Option<CnpSemanticExactWorldReservationFailure>,
    transfer_failure: Option<CnpSemanticWorldPreparationFailure>,
    runtime: Option<ConformanceRuntime>,
    plan: Rc<InstalledConformancePlan>,
    requirements: ScenarioRequirements,
    activation: Option<ActivationRecord>,
    runtime_custody: Option<Box<dyn RuntimeCustodySlot>>,
    registry: Option<CnpSemanticRegistry>,
    admission_limits: AdmissionLimits,
    runtime_limits: RuntimeLimits,
    attempted: bool,
}

impl InstalledPacketConnectedCollectionAuthority {
    /// Reserves the complete same-authority connected host before any native birth.
    ///
    /// # Errors
    /// Returns the original complete holder on a changed plan/peer roster, wrong
    /// host selection, altered full activation or unavailable finite pointer credit.
    #[allow(clippy::type_complexity)]
    pub fn prepare_connected_host<'a, V: TrustedHandshakeVerifier>(
        self: &'a Rc<Self>,
        request: PacketConnectedHostRequest<'a, V>,
    ) -> Result<Box<PacketConnectedHost<'a, V>>, PacketConnectedHostPreparationFailure<'a, V>> {
        let [peer0, peer1, peer2] = request.peers;
        let mut original = Box::new(PacketConnectedHost {
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
            host_node: None,
            host_error: None,
            host: Rc::clone(self.host_source()),
            graph: None,
            graph_failure: None,
            descriptors: Vec::new(),
            bindings: Vec::new(),
            owners: Vec::new(),
            provider: None,
            reservation_failure: None,
            transfer_failure: None,
            runtime: None,
            plan: request.plan,
            requirements: request.requirements,
            activation: Some(request.activation),
            runtime_custody: Some(request.runtime_custody),
            registry: None,
            admission_limits: request.admission_limits,
            runtime_limits: request.runtime_limits,
            attempted: false,
        });
        let checked = catch_unwind(AssertUnwindSafe(|| {
            self.current()?;
            original
                .plan
                .authenticate_authority(self.as_ref())
                .map_err(|error| QualificationError::Evidence(error.to_string()))?;
            let world = self.world().identity()?;
            if original.runtime_limits.maximum_nodes < 4
                || original.runtime_limits.maximum_owners < 4
                || original.activation.as_ref().is_none_or(|activation| {
                    activation.world_binding_hash != world || activation.owners.len() != 4
                })
            {
                return Err(refused());
            }
            for member in 0..3 {
                if !original.peers[member]
                    .as_ref()
                    .is_some_and(|peer| peer.has_authority(self, member))
                {
                    return Err(refused());
                }
            }
            original
                .descriptors
                .try_reserve_exact(4)
                .map_err(|_| refused())?;
            original
                .bindings
                .try_reserve_exact(4)
                .map_err(|_| refused())?;
            original
                .owners
                .try_reserve_exact(4)
                .map_err(|_| refused())?;
            original.nodes.try_reserve_exact(3).map_err(|_| refused())?;
            original
                .native
                .try_reserve_exact(4)
                .map_err(|_| refused())?;
            let selected = [
                self.participant(0)?.installation(),
                self.participant(1)?.installation(),
                self.participant(2)?.installation(),
            ];
            super::super::scope::encoded_size(
                &(
                    selected
                        .iter()
                        .map(|selected| (&selected.descriptor, &selected.binding, &selected.owner))
                        .collect::<Vec<_>>(),
                    original.host.selection(),
                    original
                        .activation
                        .as_ref()
                        .map(super::super::scope::activation_view),
                    &original.requirements,
                ),
                8 * 1024 * 1024,
            )?;
            for member in 0..3 {
                let selected = self.participant(member)?.installation();
                original.descriptors.push(selected.descriptor.clone());
                original.bindings.push(selected.binding.clone());
                original.owners.push(selected.owner.clone());
            }
            let host = original.host.selection();
            original.descriptors.push(host.descriptor.clone());
            original.bindings.push(host.binding.clone());
            original.owners.push(host.owner.clone());
            self.authenticate_collection_world(
                original.plan.evidence(),
                AdmissionRequest {
                    world: self.world(),
                    descriptors: &original.descriptors,
                    bindings: &original.bindings,
                    owners: &original.owners,
                    requirements: &original.requirements,
                },
            )
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
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
                            self.semantic_source(member)?,
                            self.clone(),
                            &original.plan,
                        )
                        .map_err(|error| QualificationError::Evidence(error.reason))?,
                );
            }
            self.current()
        }));
        match checked {
            Ok(Ok(())) => Ok(original),
            Ok(Err(error)) => Err(PacketConnectedHostPreparationFailure { error, original }),
            Err(_) => Err(PacketConnectedHostPreparationFailure {
                error: QualificationError::Refused(
                    "connected original preparation callback unwound",
                ),
                original,
            }),
        }
    }
}

impl<V: TrustedHandshakeVerifier> PacketConnectedHost<'_, V> {
    /// Launches and realizes the three original peers once beneath the complete graph.
    ///
    /// # Errors
    /// Retains original peers, failed transfers, host node and source metadata on
    /// any socket, native realization, graph admission or runtime refusal.
    pub fn start(&mut self) -> Result<(), PacketConnectedHostFailure> {
        if self.attempted {
            return Err(PacketConnectedHostFailure::Phase);
        }
        self.attempted = true;
        match catch_unwind(AssertUnwindSafe(|| self.start_original())) {
            Ok(result) => result,
            Err(_) => Err(PacketConnectedHostFailure::Unwind),
        }
    }

    fn start_original(&mut self) -> Result<(), PacketConnectedHostFailure> {
        for member in 0..3 {
            let peer = self.peers[member]
                .take()
                .ok_or(PacketConnectedHostFailure::Phase)?;
            match peer.start() {
                Ok(guard) => self.guards[member] = Some(guard),
                Err(failure) => {
                    self.launch_failures[member] = Some(failure);
                    return Err(PacketConnectedHostFailure::Preparation);
                }
            }
        }
        for member in 0..3 {
            let guard = self.guards[member]
                .take()
                .ok_or(PacketConnectedHostFailure::Phase)?;
            let role = self.roles[member]
                .take()
                .ok_or(PacketConnectedHostFailure::Phase)?;
            match CnpSemanticPreparation::prepare_for_conformance(guard, role) {
                Ok(preparation) => self.preparations[member] = Some(preparation),
                Err(failure) => {
                    self.realization_failures[member] = Some(failure);
                    return Err(PacketConnectedHostFailure::Preparation);
                }
            }
        }
        match admit_conformance_graph(
            AdmissionRequest {
                world: self.authority.world(),
                descriptors: &self.descriptors,
                bindings: &self.bindings,
                owners: &self.owners,
                requirements: &self.requirements,
            },
            &self.plan,
            self.admission_limits,
        ) {
            Ok(graph) => self.graph = Some(graph),
            Err(error) => {
                self.graph_failure = Some(error);
                return Err(PacketConnectedHostFailure::Preparation);
            }
        }
        for member in 0..3 {
            let preparation = self.preparations[member]
                .take()
                .ok_or(PacketConnectedHostFailure::Phase)?;
            match preparation.into_conformance_node(
                self.graph
                    .as_ref()
                    .ok_or(PacketConnectedHostFailure::Phase)?,
            ) {
                Ok(node) => self.nodes.push(node),
                Err(failure) => {
                    self.admission_failures[member] = Some(failure);
                    return Err(PacketConnectedHostFailure::Preparation);
                }
            }
        }
        match self.host.prepare_collection_node(
            self.graph
                .as_ref()
                .ok_or(PacketConnectedHostFailure::Phase)?,
            self.activation
                .as_ref()
                .ok_or(PacketConnectedHostFailure::Phase)?,
        ) {
            Ok(host) => self.host_node = Some(host),
            Err(error) => {
                self.host_error = Some(error);
                return Err(PacketConnectedHostFailure::Preparation);
            }
        }
        let graph = self.graph.take().ok_or(PacketConnectedHostFailure::Phase)?;
        let activation = self
            .activation
            .take()
            .ok_or(PacketConnectedHostFailure::Phase)?;
        let slot = self
            .runtime_custody
            .take()
            .ok_or(PacketConnectedHostFailure::Phase)?;
        let host = self
            .host_node
            .take()
            .ok_or(PacketConnectedHostFailure::Phase)?;
        match CnpSemanticConformanceWorldProvider::reserve_exact_inputs(
            CnpSemanticExactWorldReservation {
                nodes: std::mem::take(&mut self.nodes),
                native: std::mem::take(&mut self.native),
                host,
                activation,
                graph,
                runtime_custody: slot,
                source: Rc::clone(&self.host),
            },
        ) {
            Ok(provider) => self.provider = Some(provider),
            Err(failure) => {
                self.reservation_failure = Some(failure);
                return Err(PacketConnectedHostFailure::Preparation);
            }
        }
        match self
            .provider
            .as_mut()
            .ok_or(PacketConnectedHostFailure::Phase)?
            .prepare_conformance_exact_inputs(self.runtime_limits, Rc::clone(&self.host))
        {
            Ok(runtime) => self.runtime = Some(runtime),
            Err(failure) => {
                self.transfer_failure = Some(failure);
                return Err(PacketConnectedHostFailure::Preparation);
            }
        }
        Ok(())
    }

    /// Borrows the same opaque collecting runtime, without extracting ordinary authority.
    ///
    /// # Errors
    /// Refuses an incomplete original start or changed installed source scene.
    pub fn runtime(&mut self) -> Result<&mut ConformanceRuntime, QualificationError> {
        self.authority.current()?;
        self.runtime.as_mut().ok_or_else(refused)
    }

    /// Borrows the concrete original startup refusal without moving native custody.
    pub fn start_error(&self) -> Option<&dyn std::fmt::Debug> {
        if let Some(failure) = self.launch_failures.iter().flatten().next() {
            return Some(&failure.error);
        }
        if let Some(failure) = self.realization_failures.iter().flatten().next() {
            return Some(&failure.error);
        }
        if let Some(error) = &self.graph_failure {
            return Some(error);
        }
        if let Some(failure) = self.admission_failures.iter().flatten().next() {
            return Some(&failure.error);
        }
        if let Some(error) = &self.host_error {
            return Some(error);
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
        None
    }

    /// Transfers the same original custody for independent authenticated reclamation.
    ///
    /// # Errors
    /// Retains unresolved or unsupported cleanup obligations in their original holder.
    ///
    /// # Panics
    /// Installed cleanup callbacks may unwind; keep this holder outside that boundary.
    pub fn retire_original(&mut self) -> Result<(), RuntimeError> {
        if let Some(runtime) = self.runtime.as_mut() {
            runtime.retire_original()?;
        }
        if let Some(provider) = self.provider.as_mut() {
            provider.retire_original(self.runtime_limits)?;
        }
        if let Some(failure) = self.reservation_failure.as_mut() {
            failure.original.retire_original(self.runtime_limits)?;
        }
        if let Some(CnpSemanticWorldPreparationFailure::Runtime(failure)) =
            self.transfer_failure.as_mut()
        {
            failure.retire_original()?;
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
        drop(self.runtime_custody.take());
        Ok(())
    }
}
