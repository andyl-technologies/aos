//! Joins measured fixture policy to the actual singleton caller and durable stores.

use std::{path::PathBuf, rc::Rc, sync::Arc, time::Duration};

use crucible::{
    node_adapters::cnp::{CnpSemanticRegistry, CnpSemanticSource},
    node_admission::AdmissionLimits,
    node_contract::{ActivationRecord, RuntimeLimits},
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend, RefName};
use crucible_node_contract::Id;
use crucible_node_provider::{
    client::ClientCustody,
    connection::{BodySchemaVerifier, ConnectionSupervisor},
    envelope::Envelope,
    handshake::{Handshake, TrustedHandshakeVerifier},
    reference_packet::service::PacketSourceLaunch,
};

use super::super::{
    PacketHostCollection, PacketHostCollectionRequest, PacketHostPreparationFailure,
    PacketPeerLaunchRequest,
};
use super::{InstalledPacketMeasuredFixture, QualificationError, population};

/// Supplies independently installed transport, original private launch and storage.
///
/// The constructor is only a pre-Child composition. The actual Hello verifier,
/// incident supervisor, connection registration and complete body custody are
/// independent mandatory boundaries. This request grants neither Ready nor an
/// accepted class and cannot construct a native owner from portable metadata.
pub struct PacketFixturePrepareRequest<V> {
    /// Moves the same complete original private launch measured at installation.
    pub launch: PacketSourceLaunch,
    /// Retains the actual original host Hello registrar.
    pub handshake: Handshake,
    /// Retains the actual source/kernel handshake verifier.
    pub verifier: V,
    /// Retains the independently installed incident and quarantine supervisor.
    pub supervisor: Rc<dyn ConnectionSupervisor>,
    /// Retains the source-owned initial Hello validator; later codec is fixed.
    pub hello_schema: Rc<dyn BodySchemaVerifier>,
    /// Retains the exact original outgoing Hello.
    pub hello: Envelope,
    /// Names its original connection registration.
    pub connection: Id,
    /// Retains all actual request and incoming-body journal reservations.
    pub content: ClientCustody,
    /// Supplies the full source-authenticated activation proposal, with no Ready.
    pub activation: ActivationRecord,
    /// Selects unchanged complete ordinary structural admission ceilings.
    pub admission_limits: AdmissionLimits,
    /// Selects unchanged original runtime ledger and cleanup ceilings.
    pub runtime_limits: RuntimeLimits,
    /// Names the independently retained public fixture evidence directory.
    pub public_storage: PathBuf,
    /// Names this original's unique write-once initial activation placement.
    pub activation_reference: RefName,
    /// Names this original's unique write-once result placement.
    pub result_reference: RefName,
    /// Bounds the original Hello/bootstrap deadline, at most sixty seconds.
    pub budget: Duration,
    /// Bounds complete result construction and all four visible placement bodies.
    pub maximum_result_bytes: usize,
}

/// Keeps effect-free setup refusal separate from the retained owning caller.
pub enum PacketFixturePrepareFailure<'a, V> {
    /// Refuses before Child; original measured source/private bytes stay installed.
    Setup(QualificationError),
    /// Retains the exact complete caller and all original reservations on refusal.
    Original(PacketHostPreparationFailure<'a, V>),
}

impl InstalledPacketMeasuredFixture {
    /// Prepares the actual source peer, supervisor and CAS-backed caller once.
    ///
    /// No Child is launched by this method. The returned caller's `start` uses
    /// real public Discover/Realize/Admit/Arm and authenticated initial publication.
    /// Both runner case tickets are reserved before Begin. Later failures retain
    /// the same runtime, source/token/oracle and publication roots. The caller
    /// keeps this installation alive through the returned lifetime.
    ///
    /// # Errors
    /// Refuses repeat preparation, changed current measurements or original
    /// launch/plan, unavailable supervisor capacity, storage or credit, returning
    /// the complete owning caller when that caller has already been assembled.
    pub fn prepare<V: TrustedHandshakeVerifier>(
        &self,
        request: PacketFixturePrepareRequest<V>,
    ) -> Result<Box<PacketHostCollection<'_, V>>, PacketFixturePrepareFailure<'_, V>> {
        if self.prepared.replace(true) {
            return Err(PacketFixturePrepareFailure::Setup(super::refused()));
        }
        let setup = |error| PacketFixturePrepareFailure::Setup(error);
        self.policy.current().map_err(setup)?;
        let plan = self
            .authority
            .collection_plan()
            .map_err(|error| setup(QualificationError::Evidence(error.to_string())))?;
        let reservations = self
            .supervisor
            .reserve_original(&request.activation, request.runtime_limits)
            .map_err(setup)?;
        let peer = self
            .authority
            .prepare_packet_peer(PacketPeerLaunchRequest {
                executable: self.policy.measurements.peer.path.clone(),
                directory: self.policy.private_directory.clone(),
                launch: request.launch,
                handshake: request.handshake,
                verifier: request.verifier,
                supervisor: request.supervisor,
                hello_schema: request.hello_schema,
                hello: request.hello,
                connection: request.connection,
                content: request.content,
                native_custody: reservations.native,
                journal_custody: reservations.journal,
                budget: request.budget,
            })
            .map_err(setup)?;
        let registry = CnpSemanticRegistry::new(self.policy.clone(), 1)
            .map_err(|error| setup(QualificationError::Evidence(error.reason)))?;
        let blobs = Arc::new(DirectoryBlobBackend::new(
            "packet-conformance-originals",
            request.public_storage.join("blobs"),
        ));
        let refs = Arc::new(DirectoryRefBackend::new(
            request.public_storage.join("refs"),
        ));
        self.authority
            .prepare_host_collection(PacketHostCollectionRequest {
                peer,
                plan,
                requirements: self.policy.requirements.clone(),
                activation: request.activation,
                registry,
                runtime_custody: reservations.runtime,
                admission_limits: request.admission_limits,
                runtime_limits: request.runtime_limits,
                qualification_limits: self.limits,
                node: self.policy.source.installation().descriptor.id.clone(),
                operation: self.policy.operation.clone(),
                horizon: self.policy.horizon,
                before_case: population::BEFORE.into(),
                after_case: population::AFTER.into(),
                blobs,
                refs,
                activation_reference: request.activation_reference,
                result_reference: request.result_reference,
                maximum_coordinator_bytes: 65_536,
                maximum_result_bytes: request.maximum_result_bytes,
            })
            .map_err(PacketFixturePrepareFailure::Original)
    }
}
