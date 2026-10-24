//! Transfers real baseline transport owners into the registered preparation holder.
//!
//! Native birth and initial transport allocations retain their independent
//! admission contract. This path accepts their actual owners, installs the same
//! pre-reserved supervisor in the SDK session, and retains every surviving
//! partial before proceeding to the separate Core HOST-window issuer.

use super::*;
use crucible_engine::node_adapters::cnp::{CnpSemanticLaunchGuard, InstalledCnpConformanceRole};
use crucible_node_transport::{
    ProviderError,
    client::{
        CanonicalAckCodecMetadataExtent, ClientCustody, ClientPeer, ClientSession, CnpController,
        ControllerRoute, ExchangeDeadline, OriginalHelloJournal,
    },
    connection::BodySchemaVerifier,
    envelope::Envelope,
    handshake::{ExtensionHandshake, TrustedHandshakeVerifier},
    reference_packet::{control::PacketControlSelection, service::PacketNative5CaptureProfile},
    reference_service::InstalledContent,
    transport::original_frames::OriginalFrameReservation,
};
use std::{os::unix::net::UnixStream, time::Duration};

/// Contains actual previously admitted native and transport inputs for one peer.
///
/// These owners are not permission to construct or launch a native process. The
/// installed authority, original guarded Child, actual peer credentials and
/// typed Source registration remain independently checked by the existing SDK
/// and adapter. The registered holder takes the whole value before invoking any
/// verifier or transport callback. A partial value is retained but deliberately
/// has no complete HOST storage row.
#[must_use = "retain actual baseline owners until transferred or supervised"]
pub struct PacketCompletePreparationConnection {
    /// Retains the actual original guarded process, not a PID or receipt claim.
    pub guard: Option<CnpSemanticLaunchGuard>,
    /// Retains the independently registered conformance role for that Source.
    pub role: Option<InstalledCnpConformanceRole>,
    /// Retains the already connected original socket until SDK negotiation.
    pub stream: Option<UnixStream>,
    /// Binds negotiation to actual independently measured peer facts.
    pub peer: ClientPeer,
    /// Contains the exact original outgoing Hello used by the recorded journal.
    pub hello: Envelope,
    /// Names the original connection; negotiation consumes this value once.
    pub connection_id: Option<Id>,
    /// Retains the same installed typed handshake through attachment or refusal.
    pub handshake: Option<ExtensionHandshake>,
    /// Retains actual verified content and finite original journal capacities.
    pub content: Option<ClientCustody>,
    /// Retains preconstructed actual node/owner route storage.
    pub route: Option<ControllerRoute>,
    /// Retains the preallocated original protocol frame bank until installation.
    pub frames: Option<OriginalFrameReservation>,
    /// Retains the exact selected codec input, consumed without a fresh clone.
    pub selection: Option<PacketControlSelection>,
    /// Retains the exact installed coordinator bytes for codec installation.
    pub coordinator: Option<InstalledContent>,
    /// Retains the exact preselected capture profile, not a late format upgrade.
    pub profile: Option<PacketNative5CaptureProfile>,
    /// Retains installed body validation until it moves into the actual session.
    pub schemas: Option<Rc<dyn BodySchemaVerifier>>,
    /// Retains the original whole physical exchange deadline.
    pub deadline: ExchangeDeadline,
    /// Limits the already admitted baseline transport frame bytes.
    pub maximum_bytes: usize,
    /// Limits the already admitted baseline transport JSON nesting.
    pub maximum_nesting: usize,
    /// Limits existing controller operations independently of the HOST window.
    pub controller_budget: Duration,
    /// Retains the original recorded Hello until the Source callback takes it.
    pub hello_journal: Option<OriginalHelloJournal>,
    /// Retains the genuine planned query ID before the HOST issuer is invoked.
    pub planned_id: Option<Id>,
    /// Retains the original keyed Admit ID until its single actual dispatch.
    pub admit_id: Option<Id>,
    /// Retains a successful original session before controller validation.
    pub pending_session: Option<ClientSession>,
    /// Retains a successful original controller before guarded attachment.
    pub controller: Option<CnpController>,
    /// Retains actual SDK diagnostics on a terminal baseline refusal.
    pub provider_failure: Option<ProviderError>,
    /// Retains actual adapter diagnostics on a terminal baseline refusal.
    pub preparation_failure: Option<crucible_engine::node_contract::OperationFailure>,
}

impl PacketCompleteReportStartupHolder {
    /// Negotiates and prepares one actual peer using its reserved known supervisor.
    ///
    /// The holder keeps the incoming native/transport owners before the first
    /// callback. The SDK consumes the original socket in its ordinary negotiation
    /// transaction; failed negotiation does not invent a returned session. A
    /// successful controller and handshake move through the real guarded
    /// attachment. The actual preparation and independent Admit response occupy
    /// their holder slots before later validation can refuse or unwind.
    ///
    /// This is a baseline owner transfer, not admission of native birth or initial
    /// protocol buffers. It never issues a HOST ticket from constructor inputs.
    ///
    /// # Errors
    /// Refuses a foreign or unfinished holder, repeated member, absent actual
    /// baseline owner, changed source selection, SDK/native failure or an invalid
    /// completed once-Admit. All surviving original owners remain in the holder.
    pub fn prepare_original_connection_into(
        original: &Rc<RefCell<Self>>,
        member: usize,
        incoming: &mut Option<PacketCompletePreparationConnection>,
        verifier: &mut impl TrustedHandshakeVerifier,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !held.completed.get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        held.graph_owner
            .authenticate_original_report_policy_data(&held.authority.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let source = held
            .authority
            .roster
            .sources
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let launch = held
            .authority
            .original_launches
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if incoming.is_none() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let mut owners = held
            .preparations
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let peer = owners
            .peers
            .get_mut(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if peer.connection_attempted
            || peer.preparation.is_some()
            || peer.connection.is_some()
            || peer.registry.is_some()
            || peer.planned_id.is_some()
            || peer.admit_response.is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let supervisor = Rc::clone(
            peer.operational
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        );
        let hello_slot = Rc::clone(
            peer.hello_slot
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        );
        peer.connection_attempted = true;
        peer.connection = incoming.take();
        let connection = peer
            .connection
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if connection.pending_session.is_some()
            || connection.controller.is_some()
            || connection.provider_failure.is_some()
            || connection.preparation_failure.is_some()
            || connection.selection.as_ref() != Some(&launch.selection)
            || connection.coordinator.as_ref().is_none_or(|coordinator| {
                coordinator.reference != launch.initial_coordinator.reference
                    || coordinator.bytes != launch.initial_coordinator.bytes
            })
            || connection.profile.as_ref() != Some(&launch.capture_profile)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let guard = connection
            .guard
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let custody = retain_provider_failure(guard.custody(), &mut connection.provider_failure)?;
        if custody.provider_pid() != connection.peer.pid {
            return Err(RuntimeError::ForeignAuthority);
        }
        peer.registry = Some(retain_provider_failure(
            connection
                .handshake
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .retain_original_registry_metadata_owner(),
            &mut connection.provider_failure,
        )?);
        connection.pending_session = Some(retain_provider_failure(
            ClientSession::negotiate_extensions_recorded_before(
                connection
                    .stream
                    .take()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                &connection.peer,
                &connection.hello,
                connection
                    .connection_id
                    .take()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                connection
                    .handshake
                    .as_mut()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                verifier,
                supervisor,
                connection
                    .schemas
                    .take()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                connection.deadline.clone(),
                connection.maximum_bytes,
                connection.maximum_nesting,
                connection
                    .hello_journal
                    .as_mut()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            ),
            &mut connection.provider_failure,
        )?);
        connection.controller = Some(retain_provider_failure(
            CnpController::new_retained(
                &mut connection.pending_session,
                &mut connection.content,
                &mut connection.route,
                connection.controller_budget,
            ),
            &mut connection.provider_failure,
        )?);
        retain_provider_failure(
            connection
                .controller
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .install_native5_source_ack_emitter_codec_with_metadata_extent(
                    &mut connection.frames,
                    connection
                        .selection
                        .take()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    connection
                        .coordinator
                        .take()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    connection
                        .profile
                        .take()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
                ),
            &mut connection.provider_failure,
        )?;
        {
            let mut original_hello = hello_slot
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if original_hello.is_some() {
                return Err(RuntimeError::OutstandingObligations);
            }
            *original_hello = connection.hello_journal.take();
        }
        retain_provider_failure(
            connection
                .guard
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .attach_extensions_owned(&mut connection.controller, &mut connection.handshake),
            &mut connection.provider_failure,
        )?;
        let guard = connection
            .guard
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let role = connection
            .role
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        match CnpSemanticPreparation::prepare_for_conformance(guard, role) {
            Ok(preparation) => peer.preparation = Some(preparation),
            Err(failure) => {
                connection.guard = Some(failure.guard);
                connection.preparation_failure = Some(failure.error);
                return Err(RuntimeError::UnsupportedFacet);
            }
        }
        if hello_slot
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let preparation = peer
            .preparation
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let admit_id = connection
            .admit_id
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let admitted = preparation.call_original_canonical_ack_admit_into(
            source,
            admit_id,
            &mut peer.admit_response,
        );
        if let Err(error) = admitted {
            connection.preparation_failure = Some(error);
            return Err(RuntimeError::UnsupportedFacet);
        }
        if let Err(error) = preparation.retain_original_canonical_ack_world_admission(source) {
            connection.preparation_failure = Some(error);
            return Err(RuntimeError::UnsupportedFacet);
        }
        peer.planned_id = connection.planned_id.take();
        preparation.authenticate_original_fresh_query_preparation_data(source)?;
        if peer.planned_id.is_none()
            || peer.admit_response.is_none()
            || connection.guard.is_some()
            || connection.role.is_some()
            || connection.pending_session.is_some()
            || connection.controller.is_some()
            || connection.handshake.is_some()
            || connection.frames.is_some()
            || connection.hello_journal.is_some()
            || connection.content.is_some()
            || connection.route.is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Only redundant baseline inputs (Hello/peer facts/deadline) remain.
        // Original protocol journals, registrar, frame banks and process custody
        // are already inside the preparation; its independent Admit DTO remains
        // in the counted holder slot. Refusal above never drops a partial input.
        peer.connection = None;
        held.authenticate_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }
}

fn retain_provider_failure<T>(
    result: Result<T, ProviderError>,
    original: &mut Option<ProviderError>,
) -> Result<T, RuntimeError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            *original = Some(error);
            Err(RuntimeError::UnsupportedFacet)
        }
    }
}
