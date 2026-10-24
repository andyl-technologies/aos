//! Wires the measured three-peer world to one actor and actual durable publishers.
//!
//! Preparation reserves all54 source-fixed observations, three native/journal
//! mailboxes and one complete runtime slot before Child. The actual issuer,
//! supervisor, same opaque plan and stores remain retained through nine windows,
//! original consumed ACKs, borrowed retirement and independent kernel cleanup.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use crucible_engine::{
    node_admission::{AdmissionLimits, InstalledConformancePlan, ScenarioRequirements},
    node_contract::{ActivationRecord, RuntimeCustodySlot, RuntimeLimits},
};
use crucible_node_format::Id;
use crucible_node_transport::{
    client::ClientCustody,
    connection::{BodySchemaVerifier, ConnectionSupervisor},
    envelope::Envelope,
    handshake::{Handshake, TrustedHandshakeVerifier},
    reference_packet::service::PacketSourceLaunch,
};
use crucible_store::content_store::{ImmutableBlobBackend, MutableRefBackend, RefName};

use super::{
    InstalledPacketWorldCollectionAuthority, PacketHostPhase, PacketPeerLaunchRequest,
    PacketWorldCaseReservations, PacketWorldHost, PacketWorldHostFailure,
    PacketWorldHostPreparationFailure, PacketWorldHostRequest, PacketWorldHostSupervisor,
    PacketWorldIndependentGraphOwner, PacketWorldPublicationRequest, PacketWorldReservationFailure,
    PacketWorldSupervisionObservation, PreparedPacketCollectionPeer, QualificationError,
    StoredPacketWorldResultPublisher, supervision::PacketSupervisionFailure,
};
use crate::{
    node_observed_executor::StoredWorldActivationPublisher,
    node_qualification::CollectedConformance,
};

type Host<'a, V> =
    PacketWorldHost<'a, V, StoredWorldActivationPublisher, StoredPacketWorldResultPublisher>;
type HostFailure<'a, V> = PacketWorldHostPreparationFailure<
    'a,
    V,
    StoredWorldActivationPublisher,
    StoredPacketWorldResultPublisher,
>;

/// Supplies one independently configured original transport before peer creation.
pub struct PacketWorldPeerTransport<V> {
    /// Names this member's measured original peer executable.
    pub executable: PathBuf,
    /// Names this member's exact original fresh private directory.
    pub directory: PathBuf,
    /// Owns the source-authenticated edition3 complete private launch.
    pub launch: PacketSourceLaunch,
    /// Owns the actual independently installed host registrar.
    pub handshake: Handshake,
    /// Owns the actual selected source/kernel Hello verifier.
    pub verifier: V,
    /// Retains the actual incident and stream-quarantine supervisor.
    pub supervisor: Rc<dyn ConnectionSupervisor>,
    /// Retains only the initial source-installed Hello schema verifier.
    pub hello_schema: Rc<dyn BodySchemaVerifier>,
    /// Owns the complete original Hello with its private credentials.
    pub hello: Envelope,
    /// Names this actual original host connection registration.
    pub connection: Id,
    /// Owns complete original predeclared controller/native response custody.
    pub content: ClientCustody,
    /// Bounds one original private bootstrap and Hello deadline.
    pub budget: Duration,
}

/// Supplies actual storage and transport configuration for one whole-world fixture.
pub struct PacketWorldStoredFixtureRequest<'a, V> {
    /// Borrows the original independently installed full-world policy owner.
    pub graph_owner: &'a PacketWorldIndependentGraphOwner,
    /// Borrows the one complete-world original supervision inventory.
    pub supervisor: &'a PacketWorldHostSupervisor,
    /// Owns all three original transports in the authenticated participant order.
    pub transports: [PacketWorldPeerTransport<V>; 3],
    /// Owns the complete exact original world requirements.
    pub requirements: ScenarioRequirements,
    /// Owns the complete original activation proposal without predicted Ready.
    pub activation: ActivationRecord,
    /// Bounds unchanged full-world structural admission.
    pub admission_limits: AdmissionLimits,
    /// Bounds complete original participant/operation/input/output ledgers.
    pub runtime_limits: RuntimeLimits,
    /// Retains actual durable immutable bytes through publication and cleanup.
    pub blobs: Arc<dyn ImmutableBlobBackend>,
    /// Retains actual durable write-once references under the same store lifetime.
    pub refs: Arc<dyn MutableRefBackend>,
    /// Names the actual complete-world initial activation placement.
    pub activation_reference: RefName,
    /// Names27 distinct original result roots in window/member order.
    pub result_references: [RefName; 27],
    /// Bounds the complete authentic post-Arm coordinator before serialization.
    pub maximum_coordinator_bytes: usize,
    /// Bounds each original visible result placement construction peak.
    pub maximum_each_result_bytes: usize,
    /// Bounds all27 original result placement ceilings together.
    pub maximum_total_result_bytes: usize,
}

struct Original<'a, V> {
    authority: &'a Rc<InstalledPacketWorldCollectionAuthority>,
    graph_owner: &'a PacketWorldIndependentGraphOwner,
    supervisor: &'a PacketWorldHostSupervisor,
    transports: [Option<PacketWorldPeerTransport<V>>; 3],
    peers: [Option<Box<PreparedPacketCollectionPeer<'a, V>>>; 3],
    native: [Option<Box<dyn crucible_engine::node_adapters::cnp::CnpSemanticProcessSlot>>; 3],
    journal: [Option<Box<dyn super::PacketPeerJournalSlot>>; 3],
    runtime: Option<Box<dyn RuntimeCustodySlot>>,
    plan: Option<Rc<InstalledConformancePlan>>,
    cases: Option<PacketWorldCaseReservations<'a, InstalledPacketWorldCollectionAuthority>>,
    case_failure:
        Option<Box<PacketWorldReservationFailure<'a, InstalledPacketWorldCollectionAuthority>>>,
    activation_publisher: Option<StoredWorldActivationPublisher>,
    result_publisher: Option<StoredPacketWorldResultPublisher>,
    host: Option<Box<Host<'a, V>>>,
    host_failure: Option<HostFailure<'a, V>>,
    requirements: ScenarioRequirements,
    activation: Option<ActivationRecord>,
    admission_limits: AdmissionLimits,
    runtime_limits: RuntimeLimits,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    activation_reference: RefName,
    result_references: Option<[RefName; 27]>,
    maximum_coordinator_bytes: usize,
    maximum_each_result_bytes: usize,
    maximum_total_result_bytes: usize,
    preparation_error: Option<QualificationError>,
    started: bool,
    retired: bool,
}

/// Retains a refused native-free preparation and every original attempted case.
pub struct PacketWorldStoredFixtureFailure<'a, V: TrustedHandshakeVerifier> {
    /// Retains the complete original preparation for observation or cleanup.
    pub original: PacketWorldStoredFixture<'a, V>,
}

/// Owns one concrete stored three-peer lifecycle without an ordinary runtime escape.
///
/// The original owner and supervisor outlive this borrowed fixture. All source,
/// report and publisher metadata stay in a preowned Box outside callback guards.
/// Once started, Drop attempts borrowed native transfer and deliberately retains
/// that same finite upper capsule, including uncertain publication bodies. This
/// fixture audit retention has no automatic GC/recycle contract. Explicit native
/// cleanup is proved by the original supervisor, independently of reports.
#[must_use = "retain the original full-world fixture through supervised cleanup and audit"]
pub struct PacketWorldStoredFixture<'a, V: TrustedHandshakeVerifier> {
    original: Option<Box<Original<'a, V>>>,
}

impl InstalledPacketWorldCollectionAuthority {
    /// Prepares the actual one-world storage, supervision and nine-window caller.
    ///
    /// No peer is spawned. All54 tickets precede Child and Arm, and one runtime
    /// reservation covers all three participants beneath their original activation.
    ///
    /// # Errors
    /// Returns the same complete original holder on changed owner/plan/world,
    /// inadequate body credit, unsupported durable storage or transport refusal.
    /// No current class qualification or Ready authority follows from preparation.
    pub fn prepare_stored_world_fixture<'a, V: TrustedHandshakeVerifier>(
        self: &'a Rc<Self>,
        request: PacketWorldStoredFixtureRequest<'a, V>,
    ) -> Result<PacketWorldStoredFixture<'a, V>, Box<PacketWorldStoredFixtureFailure<'a, V>>> {
        let [transport0, transport1, transport2] = request.transports;
        let mut original = Box::new(Original {
            authority: self,
            graph_owner: request.graph_owner,
            supervisor: request.supervisor,
            transports: [Some(transport0), Some(transport1), Some(transport2)],
            peers: [None, None, None],
            native: [None, None, None],
            journal: [None, None, None],
            runtime: None,
            plan: None,
            cases: None,
            case_failure: None,
            activation_publisher: None,
            result_publisher: None,
            host: None,
            host_failure: None,
            requirements: request.requirements,
            activation: Some(request.activation),
            admission_limits: request.admission_limits,
            runtime_limits: request.runtime_limits,
            blobs: request.blobs,
            refs: request.refs,
            activation_reference: request.activation_reference,
            result_references: Some(request.result_references),
            maximum_coordinator_bytes: request.maximum_coordinator_bytes,
            maximum_each_result_bytes: request.maximum_each_result_bytes,
            maximum_total_result_bytes: request.maximum_total_result_bytes,
            preparation_error: None,
            started: false,
            retired: false,
        });
        // The complete original is outside the callback unwind boundary. No
        // effectful lifecycle can start before all preparation has succeeded.
        let result = catch_unwind(AssertUnwindSafe(|| original.prepare()));
        let error = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(_) => Some(refused("packet whole-world preparation callback unwind")),
        };
        if let Some(error) = error {
            original.preparation_error = Some(error);
            return Err(Box::new(PacketWorldStoredFixtureFailure {
                original: PacketWorldStoredFixture {
                    original: Some(original),
                },
            }));
        }
        Ok(PacketWorldStoredFixture {
            original: Some(original),
        })
    }
}

impl<'a, V: TrustedHandshakeVerifier> Original<'a, V> {
    fn prepare(&mut self) -> Result<(), QualificationError> {
        // Prospective requirements associations and the complete activation
        // extent precede every clone in publisher/host preparation. This view
        // is non-authorizing borrowed data, never serialization of live authority.
        super::scope::encoded_size(
            &(
                &self.requirements,
                &self.requirements,
                &self.requirements,
                super::scope::activation_view(self.activation.as_ref().ok_or_else(phase)?),
            ),
            8 * 1024 * 1024,
        )?;
        if self.runtime_limits.maximum_nodes < 3
            || self.runtime_limits.maximum_owners < 3
            || self.runtime_limits.maximum_operations < 27
            || self.runtime_limits.maximum_retained_outputs < 3
        {
            return Err(phase());
        }
        for transport in self.transports.iter().flatten() {
            // Each source has nine original windows, plus bounded bootstrap and
            // blob transfer RPCs. World/3 binds a separate finite wire tuple;
            // singleton requests64/journal256 remains unchanged.
            if transport.launch.schema_version != 3
                || transport.launch.limits.requests.get() != 256
                || transport.launch.limits.journal_entries.get() != 1024
                || transport.content.maximum_requests() != 256
            {
                return Err(phase());
            }
        }
        self.authority
            .authenticate_original_graph_owner(self.graph_owner)?;
        self.authority.validate_world_proposal(
            &self.requirements,
            self.activation.as_ref().ok_or_else(phase)?,
        )?;
        if self.maximum_coordinator_bytes == 0 || self.maximum_coordinator_bytes > 65_536 {
            return Err(phase());
        }
        let plan = Rc::new(
            self.authority
                .collection_plan()
                .map_err(|error| QualificationError::Evidence(error.message))?,
        );
        self.plan = Some(plan.clone());
        match PacketWorldCaseReservations::reserve(
            self.authority.reservation_request(plan.clone())?,
        ) {
            Ok(cases) => self.cases = Some(cases),
            Err(failure) => {
                self.case_failure = Some(failure);
                return Err(phase());
            }
        }
        self.result_publisher = Some(
            StoredPacketWorldResultPublisher::new(PacketWorldPublicationRequest {
                authority: self.authority.clone(),
                plan,
                requirements: self.requirements.clone(),
                blobs: self.blobs.clone(),
                refs: self.refs.clone(),
                references: self.result_references.take().ok_or_else(phase)?,
                maximum_each_bytes: self.maximum_each_result_bytes,
                maximum_total_bytes: self.maximum_total_result_bytes,
            })
            .map_err(|error| QualificationError::Evidence(error.to_string()))?,
        );
        self.activation_publisher = Some(
            StoredWorldActivationPublisher::new(
                self.blobs.clone(),
                self.refs.clone(),
                self.activation_reference.clone(),
            )
            .map_err(|error| QualificationError::Evidence(error.to_string()))?,
        );
        let reservations = self.supervisor.reserve_original(
            self.activation.as_ref().ok_or_else(phase)?,
            self.runtime_limits,
        )?;
        let [native0, native1, native2] = reservations.native;
        let [journal0, journal1, journal2] = reservations.journal;
        self.native = [Some(native0), Some(native1), Some(native2)];
        self.journal = [Some(journal0), Some(journal1), Some(journal2)];
        self.runtime = Some(reservations.runtime);
        for member in 0..3 {
            let transport = self.transports[member].take().ok_or_else(phase)?;
            let peer = self.authority.prepare_packet_peer(
                member,
                PacketPeerLaunchRequest {
                    executable: transport.executable,
                    directory: transport.directory,
                    launch: transport.launch,
                    handshake: transport.handshake,
                    verifier: transport.verifier,
                    supervisor: transport.supervisor,
                    hello_schema: transport.hello_schema,
                    hello: transport.hello,
                    connection: transport.connection,
                    content: transport.content,
                    native_custody: self.native[member].take().ok_or_else(phase)?,
                    journal_custody: self.journal[member].take().ok_or_else(phase)?,
                    budget: transport.budget,
                },
            )?;
            self.peers[member] = Some(peer);
        }
        self.authority
            .authenticate_original_graph_owner(self.graph_owner)?;
        let peers = [
            self.peers[0].take().ok_or_else(phase)?,
            self.peers[1].take().ok_or_else(phase)?,
            self.peers[2].take().ok_or_else(phase)?,
        ];
        let request = PacketWorldHostRequest {
            peers,
            cases: self.cases.take().ok_or_else(phase)?,
            plan: self.plan.as_ref().ok_or_else(phase)?.clone(),
            requirements: self.requirements.clone(),
            activation: self.activation.take().ok_or_else(phase)?,
            runtime_custody: self.runtime.take().ok_or_else(phase)?,
            admission_limits: self.admission_limits,
            runtime_limits: self.runtime_limits,
            activation_publisher: self.activation_publisher.take().ok_or_else(phase)?,
            result_publisher: self.result_publisher.take().ok_or_else(phase)?,
            maximum_coordinator_bytes: self.maximum_coordinator_bytes,
        };
        match self.authority.prepare_world_host(request) {
            Ok(host) => self.host = Some(host),
            Err(failure) => {
                self.host_failure = Some(failure);
                return Err(phase());
            }
        }
        Ok(())
    }
}

impl<V> Original<'_, V> {
    fn retire_original(&mut self) -> Result<(), crucible_engine::node_contract::RuntimeError>
    where
        V: TrustedHandshakeVerifier,
    {
        if let Some(host) = self.host.as_mut() {
            host.retire_original()?;
        }
        if let Some(failure) = self.host_failure.as_mut() {
            failure.original.retire_original()?;
        }
        for peer in self.peers.iter_mut().flatten() {
            peer.retire_original();
        }
        for member in 0..3 {
            drop(self.native[member].take());
            drop(self.journal[member].take());
        }
        drop(self.runtime.take());
        self.retired = true;
        Ok(())
    }
}

impl<V: TrustedHandshakeVerifier> PacketWorldStoredFixture<'_, V> {
    /// Starts the one original three-peer caller exactly once.
    ///
    /// # Errors
    /// Retains the complete original on stale issuer, phase, native or admission
    /// refusal. This never launches a replacement for any failed original peer.
    pub fn start(&mut self) -> Result<(), PacketWorldHostFailure> {
        let original = self
            .original
            .as_mut()
            .ok_or(PacketWorldHostFailure::Phase)?;
        if original.started || original.retired {
            return Err(PacketWorldHostFailure::Phase);
        }
        original
            .authority
            .authenticate_original_graph_owner(original.graph_owner)
            .map_err(|_| PacketWorldHostFailure::Preparation)?;
        original.started = true;
        original
            .host
            .as_mut()
            .ok_or(PacketWorldHostFailure::Phase)?
            .start()
    }

    /// Polls the same one-world actor through27 original grants and54 observations.
    ///
    /// # Errors
    /// Retains the same runtime, tokens, publishers and failed originals. Source
    /// uncertainty cannot become a new grant, accepted report or second Child.
    pub fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), PacketWorldHostFailure>> {
        let Some(original) = self.original.as_mut() else {
            return Poll::Ready(Err(PacketWorldHostFailure::Phase));
        };
        if !original.started || original.retired {
            return Poll::Ready(Err(PacketWorldHostFailure::Phase));
        }
        match original.host.as_mut() {
            Some(host) => host.poll(context),
            None => Poll::Ready(Err(PacketWorldHostFailure::Phase)),
        }
    }

    /// Transfers actual native custody while keeping all original upper audit data.
    ///
    /// # Errors
    /// Retains the same original capsule on borrowed cleanup refusal or callback
    /// unwind. Ok means transfer, never proof of kernel or world reclamation.
    pub fn retire_original(&mut self) -> Result<(), PacketWorldHostFailure> {
        let original = self
            .original
            .as_mut()
            .ok_or(PacketWorldHostFailure::Phase)?;
        match catch_unwind(AssertUnwindSafe(|| original.retire_original())) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(PacketWorldHostFailure::Preparation),
            Err(_) => Err(PacketWorldHostFailure::Unwind),
        }
    }

    /// Polls original supervised reclamation without discarding private journals.
    ///
    /// # Errors
    /// Preserves authentic runtime/native cleanup errors or callback unwind.
    /// Pending keeps the original owner and finite obligations retained.
    pub fn poll_reclamation(
        &self,
        context: &mut Context<'_>,
    ) -> Poll<Result<PacketWorldSupervisionObservation, PacketSupervisionFailure>> {
        match self.original.as_ref() {
            Some(original) => original.supervisor.poll_reclamation(context),
            None => Poll::Pending,
        }
    }

    /// Borrows actual collected bodies while unavailable normative cases stay explicit.
    pub fn collected(&self) -> Option<&[Option<CollectedConformance>; 3]> {
        self.original
            .as_ref()?
            .host
            .as_ref()
            .and_then(|host| host.collected())
    }

    /// Reports data-only original host progress without graph or runtime access.
    pub fn phase(&self) -> PacketHostPhase {
        self.original
            .as_ref()
            .and_then(|original| original.host.as_ref())
            .map_or(PacketHostPhase::Held, |host| host.phase())
    }

    /// Borrows data-only actor progress without extracting the retained original holder.
    pub fn progress(&self) -> Option<(super::PacketWorldActorPhase, usize, usize)> {
        self.original.as_ref()?.host.as_ref()?.progress()
    }

    /// Borrows the concrete start refusal while retaining every original holder.
    pub fn start_error(&self) -> Option<&dyn std::fmt::Debug> {
        self.original.as_ref()?.host.as_ref()?.start_error()
    }

    /// Borrows the most specific retained native-free preparation refusal.
    ///
    /// Lower reservation and host errors stay in their original holders. This
    /// observation lends their error without consuming custody or running callbacks.
    pub fn preparation_error(&self) -> Option<&QualificationError> {
        let original = self.original.as_ref()?;
        if let Some(failure) = &original.case_failure {
            return Some(&failure.error);
        }
        if let Some(failure) = &original.host_failure {
            return Some(&failure.error);
        }

        original.preparation_error.as_ref()
    }
}

impl<V: TrustedHandshakeVerifier> Drop for PacketWorldStoredFixture<'_, V> {
    fn drop(&mut self) {
        if let Some(mut original) = self.original.take()
            && original.started
        {
            let _ = catch_unwind(AssertUnwindSafe(|| original.retire_original()));
            // A started upper capsule may contain uncertain durable bodies.
            // Keep it whole after attempted borrowed transfer, even on
            // refusal or unwind. The independent supervisor proves cleanup.
            // No implicit successful cleanup
            // or audit GC is claimed by dropping this public handle.
            std::mem::forget(original);
        }
    }
}

fn refused(message: &'static str) -> QualificationError {
    QualificationError::Refused(message)
}

fn phase() -> QualificationError {
    refused("packet stored whole-world preparation refused")
}
