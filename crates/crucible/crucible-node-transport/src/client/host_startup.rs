//! Retains one closed original packet host SDK construction attempt.
//!
//! The installed Source admits this construction before calling the SDK. The
//! prospective storage row is data; it cannot authenticate a Source, start a
//! process, register a graph, or admit a subsequent control request. Every
//! independently created SDK owner stays in this same partial holder.

use std::{collections::BTreeMap, os::unix::net::UnixStream, rc::Rc, time::Duration};

use crucible_node_format::{ContentRef, Id};

use crate::{
    ProviderError,
    connection::{ConnectionSupervisor, OriginalRetainedSupervisor},
    envelope::Envelope,
    handshake::{ExtensionHandshake, Handshake},
    reference_packet::{
        control::PacketControlSelection,
        service::{PacketNative5CaptureProfile, PacketNative5SourceLaunch},
    },
    reference_service::InstalledContent,
    transport::original_frames::OriginalFrameReservation,
};

use super::{
    ClientContent, ClientCustody, ClientPeer, ClientSession, CnpController, ControllerRoute,
    ExchangeDeadline, OriginalHelloJournal,
};

mod descriptors;
pub(crate) mod hello;
mod initial_lifecycle;
mod initial_socket;
pub use descriptors::original_packet_host_descriptor_counter_scratch_data;
mod storage;

pub use initial_lifecycle::{
    OriginalPacketHostInitialAttachmentScope, OriginalPacketHostInitialAttachmentSink,
    PacketNativeHostInitialLifecycleStorageData,
    original_packet_host_initial_lifecycle_counter_scratch_data,
};
pub use initial_socket::original_packet_host_initial_socket_counter_scratch_data;

pub use storage::{
    PacketNativeHostStartupStorageData, original_packet_host_startup_counter_scratch_data,
    original_packet_host_startup_storage_data,
};

/// Borrows original installation data for the closed host constructor.
///
/// The caller authenticates these loans against its actual installed authority
/// and private birth. Equal data supplied by another caller grants no rights.
pub struct PacketNativeHostStartupInputs<'a> {
    /// Borrows the same source-selected typed native launch.
    pub launch: &'a PacketNative5SourceLaunch,
    /// Borrows its canonical expected host registration, retained before birth.
    pub registration: &'a [u8],
    /// Borrows the already installed promised content bodies without copying them.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
    /// Borrows the source-installed executable used by the same launch guard.
    pub executable: &'a ContentRef,
}

/// Owns the partial host constructor without native or semantic permissions.
///
/// There is no extractor for the controller. A separate Source action must
/// admit initial control methods before the same controller can be attached
/// to a preparation. Refusal never manufactures a completed native baseline.
#[must_use = "retain partial SDK owners beside their original guarded process"]
pub struct OriginalPacketHostStartup {
    creator: crate::protocol_snapshot::ProtocolCaptureOwner,
    quote: PacketNativeHostStartupStorageData,
    registration: Option<hello::Registration>,
    selection: Option<PacketControlSelection>,
    coordinator: Option<InstalledContent>,
    profile: Option<PacketNative5CaptureProfile>,
    executable: Option<ContentRef>,
    schemas: Option<Rc<hello::InitialHelloSchema>>,
    deadline: Option<ExchangeDeadline>,
    plain_handshake: Option<Handshake>,
    handshake: Option<ExtensionHandshake>,
    hello: Option<Envelope>,
    hello_journal: Option<OriginalHelloJournal>,
    pending_content: Option<(ContentRef, Vec<u8>)>,
    content: Option<ClientContent>,
    custody: Option<ClientCustody>,
    frames: Option<OriginalFrameReservation>,
    route: Option<ControllerRoute>,
    stream: Option<UnixStream>,
    hello_attempt: Option<super::session::OriginalHostHelloAttempt>,
    session: Option<ClientSession>,
    controller: Option<CnpController>,
    failure: Option<ProviderError>,
    preparing: bool,
    prepared: bool,
    connecting: bool,
    connected: bool,
    initial_attachment_attempted: bool,
}

impl OriginalPacketHostStartup {
    /// Constructs the SDK owners after the Source's independent action passes.
    ///
    /// `maximum_requested_bytes` reconciles the data quote; it is not an SDK
    /// authority constructor. The actual Source consumer authenticates and
    /// consumes its opaque original action before entering this method.
    ///
    /// # Errors
    /// Refuses an occupied slot, incomplete selected input, insufficient storage,
    /// invalid original content or any partial/repeated construction. Once the
    /// attempt is installed, every surviving owner remains in `completed`.
    pub fn prepare_into(
        inputs: &PacketNativeHostStartupInputs<'_>,
        nonce: &[u8; 32],
        hello_id: &Id,
        maximum_requested_bytes: usize,
        completed: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() {
            return Err(refused());
        }
        let quote = original_packet_host_startup_storage_data(inputs, hello_id)?;
        if quote.requested_peak_data()? > maximum_requested_bytes {
            return Err(refused());
        }
        *completed = Some(Self {
            creator: crate::protocol_snapshot::ProtocolCaptureOwner::new(),
            quote,
            registration: None,
            selection: None,
            coordinator: None,
            profile: None,
            executable: None,
            schemas: None,
            deadline: None,
            plain_handshake: None,
            handshake: None,
            hello: None,
            hello_journal: None,
            pending_content: None,
            content: None,
            custody: None,
            frames: None,
            route: None,
            stream: None,
            hello_attempt: None,
            session: None,
            controller: None,
            failure: None,
            preparing: true,
            prepared: false,
            connecting: false,
            connected: false,
            initial_attachment_attempted: false,
        });
        let original = completed.as_mut().ok_or_else(refused)?;
        match original.prepare(inputs, nonce, hello_id) {
            Ok(()) => {
                original.preparing = false;
                original.prepared = true;
                Ok(())
            }
            Err(error) => {
                original.failure = Some(error);
                Err(refused())
            }
        }
    }

    fn prepare(
        &mut self,
        inputs: &PacketNativeHostStartupInputs<'_>,
        nonce: &[u8; 32],
        hello_id: &Id,
    ) -> Result<(), ProviderError> {
        self.creator.ensure_current()?;
        self.registration = Some(hello::Registration::decode(inputs.registration)?);
        let registration = self.registration.as_ref().ok_or_else(refused)?;
        registration.authenticate_launch(inputs.launch)?;

        self.selection = Some(inputs.launch.selection.clone());
        self.coordinator = Some(inputs.launch.initial_coordinator.clone());
        self.profile = Some(inputs.launch.capture_profile.clone());
        self.executable = Some(inputs.executable.clone());
        self.schemas = Some(Rc::new(hello::InitialHelloSchema));
        let selection = self.selection.as_ref().ok_or_else(refused)?;
        self.plain_handshake = Some(hello::handshake(inputs.launch, registration)?);
        self.handshake = Some(ExtensionHandshake::from_original_empty_registry_retained(
            &mut self.plain_handshake,
        )?);
        self.hello = Some(hello::request(
            inputs.launch,
            registration,
            nonce,
            hello_id,
        )?);
        self.hello_journal = Some(OriginalHelloJournal::reserve_native5(
            self.hello.as_ref().ok_or_else(refused)?,
            hello::MAXIMUM_HELLO_BYTES,
            64,
        )?);
        self.frames = Some(OriginalFrameReservation::reserve(
            usize::try_from(inputs.launch.storage.frame_bank_bytes.get()).map_err(|_| refused())?,
            usize::try_from(inputs.launch.storage.frames_per_direction.get())
                .map_err(|_| refused())?,
        )?);
        self.route = Some(ControllerRoute {
            node: selection.realization.descriptors[0].id.clone(),
            execution_owner: selection.realization.owner_bindings[0].owner.id.clone(),
        });

        self.content = Some(ClientContent::new(
            self.quote.content_bytes,
            self.quote.content_objects,
            self.quote.maximum_chunk,
        )?);
        for (reference, bytes) in inputs.content {
            // Keep the owned body before validation, installation or a later
            // allocation can refuse. The immutable input remains independently
            // held by the installed caller through this whole construction.
            self.pending_content = Some((reference.clone(), Vec::new()));
            let pending = self.pending_content.as_mut().ok_or_else(refused)?;
            pending
                .1
                .try_reserve_exact(bytes.len())
                .map_err(|_| refused())?;
            if pending.1.capacity() > bytes.len() {
                return Err(refused());
            }
            pending.1.extend_from_slice(bytes);
            pending.0.verify(&pending.1)?;
            self.content
                .as_mut()
                .ok_or_else(refused)?
                .install_original_host_startup_from_slot(&mut self.pending_content)?;
        }
        self.custody = Some(ClientCustody::new(
            self.quote.maximum_requests,
            self.content.take().ok_or_else(refused)?,
        )?);
        self.reconcile_prepared_data()?;
        self.creator.ensure_current()
    }

    /// Performs the one recorded Hello and constructs its original controller.
    ///
    /// The caller checks the Source's same launch/Child/plan before and after
    /// this call. The known supervisor must be the previously admitted concrete
    /// SDK owner. No caller-defined verifier or schema callback enters this
    /// constructor. The session checks actual peer credentials and streams the
    /// complete measured executable under its fixed original deadline.
    ///
    /// # Errors
    /// Refuses an incomplete/repeated attempt, foreign supervisor, changed peer,
    /// malformed Hello, revoked registrar, unavailable capacity or transport
    /// failure. Partial journals, errors and successful owners remain retained.
    pub fn connect_into(
        &mut self,
        stream: &mut Option<UnixStream>,
        peer: &ClientPeer,
        operational: &Rc<dyn ConnectionSupervisor>,
        supervisor: &OriginalRetainedSupervisor,
        controller_budget: Duration,
    ) -> Result<(), ProviderError> {
        self.creator.ensure_current()?;
        if !self.prepared
            || self.preparing
            || self.connecting
            || self.connected
            || self.failure.is_some()
            || self.stream.is_some()
            || stream.is_none()
        {
            return Err(refused());
        }
        supervisor.authenticate_original_handle_data(operational)?;
        if self.executable.as_ref() != Some(&peer.executable) {
            return Err(refused());
        }
        self.reconcile_prepared_data()?;
        self.connecting = true;
        self.stream = stream.take();
        let result = self.connect(peer, operational, controller_budget);
        match result {
            Ok(()) => {
                if let Err(error) = self.reconcile_connected_data(supervisor) {
                    self.failure = Some(error);
                    return Err(refused());
                }
                self.connecting = false;
                self.connected = true;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(error);
                Err(refused())
            }
        }
    }

    fn connect(
        &mut self,
        peer: &ClientPeer,
        supervisor: &Rc<dyn ConnectionSupervisor>,
        controller_budget: Duration,
    ) -> Result<(), ProviderError> {
        self.start_initial_deadline()?;
        let registration = self.registration.as_ref().ok_or_else(refused)?;
        let selection = self.selection.as_ref().ok_or_else(refused)?;
        let hello = self.hello.as_ref().ok_or_else(refused)?;
        let mut verifier = hello::Verifier {
            selection,
            registration,
        };
        let guard = hello::ResponseGuard {
            selection,
            registration,
            request: hello,
            executable: self.executable.as_ref().ok_or_else(refused)?,
        };
        self.hello_attempt = Some(super::session::OriginalHostHelloAttempt::new(
            self.stream.take().ok_or_else(refused)?,
        ));
        self.hello_attempt
            .as_mut()
            .ok_or_else(refused)?
            .negotiate_into(
                peer,
                hello,
                registration.connection_id.clone(),
                self.handshake.as_mut().ok_or_else(refused)?,
                &mut verifier,
                &guard,
                self.schemas.as_ref().ok_or_else(refused)?,
                supervisor,
                self.deadline.as_ref().ok_or_else(refused)?,
                self.hello_journal.as_mut().ok_or_else(refused)?,
                &mut self.session,
            )?;
        self.controller = Some(CnpController::new_retained(
            &mut self.session,
            &mut self.custody,
            &mut self.route,
            controller_budget,
        )?);
        self.creator.ensure_current()
    }
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original packet host SDK construction")
}

#[cfg(test)]
mod tests;

mod source_json;
pub use source_json::{
    original_host_source_json_counter_scratch_data, original_host_source_json_extent_storage_data,
    original_host_source_json_occurrence_storage_data,
};
