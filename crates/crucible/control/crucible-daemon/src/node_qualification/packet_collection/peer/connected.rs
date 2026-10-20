//! Launches one original edition-four peer under bounded private bootstrap custody.
//!
//! The prepared capsule and native supervisor reservation exist before Child.
//! The private launch and Hello share one pre-launch deadline; neither a failed
//! exchange nor a dropped capsule replaces the original peer or its journals.

use std::{
    fs::File,
    os::{fd::OwnedFd, unix::process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
    time::Duration,
};

use crucible_engine::node_adapters::cnp::{
    CnpSemanticLaunchGuard, CnpSemanticLaunchReservation, CnpSemanticProcessSlot,
};
use crucible_node_format::{ContentRef, Id};
use crucible_node_transport::{
    ProviderError,
    client::{
        ClientCustody, ClientPeer, ClientSession, CnpController, ControllerRoute, DeadlineStream,
        ExchangeDeadline, OriginalHelloJournal,
    },
    connection::{BodySchemaVerifier, ConnectionSupervisor},
    envelope::Envelope,
    handshake::{Handshake, TrustedHandshakeVerifier},
    reference_packet::service::PacketConnectedSourceLaunch,
    transport::write_frame,
};

use super::super::{InstalledPacketConnectedCollectionAuthority, QualificationError};
use super::{
    DirectoryIdentity, PacketPeerJournalCustody, PacketPeerJournalSlot, connect, native,
    private_directory,
};

/// Retains independently configured private launch and actual handshake custody.
pub struct PacketConnectedPeerLaunchRequest<V> {
    /// Names the independently selected, measured peer executable.
    pub executable: PathBuf,
    /// Names the fresh private session directory chosen by the host.
    pub directory: PathBuf,
    /// Retains the complete private source launch, including secret token custody.
    pub launch: PacketConnectedSourceLaunch,
    /// Retains the original host handshake registrar across every failure.
    pub handshake: Handshake,
    /// Retains the installed actual source/kernel Hello verifier.
    pub verifier: V,
    /// Retains the actual incident and stream-quarantine supervisor.
    pub supervisor: Rc<dyn ConnectionSupervisor>,
    /// Supplies only initial Hello verification; the packet codec replaces it.
    pub hello_schema: Rc<dyn BodySchemaVerifier>,
    /// Contains the complete original Hello rather than regenerated retry bytes.
    pub hello: Envelope,
    /// Names the one original host connection registration.
    pub connection: Id,
    /// Retains the predeclared complete controller request and incoming bodies.
    pub content: ClientCustody,
    /// Retains the native process supervisor reservation made before Child.
    pub native_custody: Box<dyn CnpSemanticProcessSlot>,
    /// Retains the independently pre-reserved returned-journal mailbox.
    pub journal_custody: Box<dyn PacketPeerJournalSlot>,
    /// Bounds complete bootstrap/socket/Hello physical preparation once.
    pub budget: Duration,
}

/// Retains the preallocated private capsule when the original launch fails.
pub struct PacketConnectedPeerLaunchFailure<'a, V> {
    /// Describes the original failure without claiming native containment.
    pub error: ProviderError,
    /// Owns original secret, registrar, guard and unused reservations.
    pub original: Box<PreparedPacketConnectedPeer<'a, V>>,
}

/// Prepares one private source peer without ordinary accepted-class authority.
///
/// This capsule has no retry or resource extraction after failure. Drop hands
/// any actual native guard to its pre-reserved original supervisor. The returned
/// successful guard still requires source realization and opaque graph admission.
#[must_use = "retain original launch custody until actual native reclamation"]
pub struct PreparedPacketConnectedPeer<'a, V> {
    authority: PeerAuthority<'a>,
    request: PeerSettings<V>,
    executable: ContentRef,
    directory_identity: DirectoryIdentity,
    launch_body: serde_json::Value,
    original_hello: Option<OriginalHelloJournal>,
    journal_custody: Option<Box<dyn PacketPeerJournalSlot>>,
    controller: Option<CnpController>,
    pending_session: Option<ClientSession>,
    controller_error: Option<ProviderError>,
    controller_route: Option<ControllerRoute>,
    bootstrap: Option<(
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    )>,
    native_reservation: Option<CnpSemanticLaunchReservation>,
    content: Option<ClientCustody>,
    handshake: Option<Handshake>,
    guard: Option<CnpSemanticLaunchGuard>,
    failed_attachment: Option<crucible_engine::node_adapters::cnp::CnpSemanticAttachmentFailure>,
    attempted: bool,
}

struct PeerSettings<V> {
    executable: PathBuf,
    directory: PathBuf,
    launch: PacketConnectedSourceLaunch,
    verifier: V,
    supervisor: Rc<dyn ConnectionSupervisor>,
    hello_schema: Rc<dyn BodySchemaVerifier>,
    hello: Envelope,
    connection: Id,
    budget: Duration,
}

#[derive(Clone, Copy)]
struct PeerAuthority<'a> {
    original: &'a Rc<InstalledPacketConnectedCollectionAuthority>,
    member: usize,
}

impl PeerAuthority<'_> {
    fn source(
        &self,
    ) -> Result<&crucible_engine::node_adapters::cnp::CnpSemanticInstallation, QualificationError>
    {
        Ok(self.original.participant(self.member)?.installation())
    }

    fn current(&self) -> Result<(), QualificationError> {
        self.original.current()
    }

    fn private_launch(
        &self,
        launch: &PacketConnectedSourceLaunch,
        executable: &std::path::Path,
        directory: &std::path::Path,
        terminal: bool,
    ) -> Result<(), QualificationError> {
        self.original
            .authenticate_private_peer(launch, executable, directory, terminal)
    }
}

impl InstalledPacketConnectedCollectionAuthority {
    /// Prepares one original closed-input peer under the complete world authority.
    ///
    /// All three owning capsules and the full host runtime reservation must exist
    /// before starting a child. Preparation issues no Arm, Ready or activation.
    ///
    /// # Errors
    /// Refuses changed original member/source/current scope, invalid private
    /// launch, insufficient credit or unavailable owning bootstrap endpoints.
    pub fn prepare_connected_peer<V: TrustedHandshakeVerifier>(
        self: &Rc<Self>,
        member: usize,
        request: PacketConnectedPeerLaunchRequest<V>,
    ) -> Result<Box<PreparedPacketConnectedPeer<'_, V>>, QualificationError> {
        prepare_peer(
            PeerAuthority {
                original: self,
                member,
            },
            request,
        )
    }
}

fn prepare_peer<'a, V: TrustedHandshakeVerifier>(
    authority: PeerAuthority<'a>,
    request: PacketConnectedPeerLaunchRequest<V>,
) -> Result<Box<PreparedPacketConnectedPeer<'a, V>>, QualificationError> {
    if request.budget.is_zero() || request.budget > Duration::from_secs(60) {
        return Err(QualificationError::Refused(
            "packet original launch deadline",
        ));
    }
    request.launch.validate().map_err(native)?;
    let directory_identity =
        private_directory(&request.directory, request.launch.controller_uid.get())
            .map_err(native)?;
    let selected = authority.source()?;
    if request.launch.schema_version != 4
        || request.launch.selection.provider != selected.provider
        || request.launch.selection.realization.descriptors
            != std::slice::from_ref(&selected.descriptor)
        || request.launch.selection.realization.bindings != std::slice::from_ref(&selected.binding)
        || request.launch.selection.realization.owner_bindings
            != std::slice::from_ref(&selected.owner)
    {
        return Err(QualificationError::Refused(
            "packet original private source differs",
        ));
    }
    super::super::scope::encoded_size(
        &(
            &request.launch,
            &request.launch,
            &request.hello,
            &request.hello,
            &request.hello,
        ),
        8 * 1024 * 1024,
    )?;
    let frame_bytes = usize::try_from(request.launch.limits.frame_bytes.get())
        .map_err(|_| QualificationError::Refused("packet original frame credit"))?;
    let nesting = usize::try_from(request.launch.limits.nesting.get())
        .map_err(|_| QualificationError::Refused("packet original nesting credit"))?;
    let original_hello =
        OriginalHelloJournal::reserve(&request.hello, frame_bytes, nesting).map_err(native)?;
    authority.current()?;
    authority.private_launch(
        &request.launch,
        &request.executable,
        &request.directory,
        false,
    )?;
    let actual = crucible_node_transport::conformance::measure_executable(&request.executable)
        .map_err(native)?;
    if !selected
        .provider
        .implementation
        .artifacts
        .iter()
        .any(|artifact| artifact.role.as_str() == "executable" && artifact.content == actual)
    {
        return Err(QualificationError::Refused(
            "packet actual selected peer bytes differ",
        ));
    }
    let bootstrap = std::os::unix::net::UnixStream::pair().map_err(|error| native(error.into()))?;
    let launch_body =
        serde_json::to_value(&request.launch).map_err(crucible_node_format::ContractError::from)?;
    let controller_route = ControllerRoute {
        node: selected.descriptor.id.clone(),
        execution_owner: selected.owner.owner.id.clone(),
    };
    let PacketConnectedPeerLaunchRequest {
        executable,
        directory,
        launch,
        handshake,
        verifier,
        supervisor,
        hello_schema,
        hello,
        connection,
        content,
        native_custody,
        journal_custody,
        budget,
    } = request;
    let native_reservation =
        CnpSemanticLaunchReservation::reserve(directory.clone(), actual.clone(), native_custody);
    // The owning failure capsule and complete private frame are allocated
    // before the peer can exist. The secret stays in this private owner.
    Ok(Box::new(PreparedPacketConnectedPeer {
        authority,
        request: PeerSettings {
            executable,
            directory,
            launch,
            verifier,
            supervisor,
            hello_schema,
            hello,
            connection,
            budget,
        },
        executable: actual,
        directory_identity,
        launch_body,
        original_hello: Some(original_hello),
        journal_custody: Some(journal_custody),
        controller: None,
        pending_session: None,
        controller_error: None,
        controller_route: Some(controller_route),
        bootstrap: Some(bootstrap),
        native_reservation: Some(native_reservation),
        content: Some(content),
        handshake: Some(handshake),
        guard: None,
        failed_attachment: None,
        attempted: false,
    }))
}

impl<'a, V: TrustedHandshakeVerifier> PreparedPacketConnectedPeer<'a, V> {
    pub(in super::super) fn has_authority(
        &self,
        original: &Rc<InstalledPacketConnectedCollectionAuthority>,
        member: usize,
    ) -> bool {
        Rc::ptr_eq(self.authority.original, original) && self.authority.member == member
    }

    /// Launches, authenticates and attaches the same original peer exactly once.
    ///
    /// # Errors
    /// Returns this preallocated owner on changed scope, spawn/bootstrap failure,
    /// expiration, foreign peer, failed original Hello or attachment. No failed
    /// Hello or Child is retried. The actual guard stays outside unwind handling.
    pub fn start(
        mut self: Box<Self>,
    ) -> Result<CnpSemanticLaunchGuard, PacketConnectedPeerLaunchFailure<'a, V>> {
        if self.attempted {
            return Err(PacketConnectedPeerLaunchFailure {
                error: ProviderError::Correlation("packet original launch already attempted"),
                original: self,
            });
        }
        self.attempted = true;
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.start_original()));
        match result {
            Ok(Ok(())) => match self.guard.take() {
                Some(guard) => Ok(guard),
                None => Err(PacketConnectedPeerLaunchFailure {
                    error: ProviderError::Correlation("packet original attached guard absent"),
                    original: self,
                }),
            },
            Ok(Err(error)) => Err(PacketConnectedPeerLaunchFailure {
                error,
                original: self,
            }),
            Err(_) => Err(PacketConnectedPeerLaunchFailure {
                error: ProviderError::Correlation("packet original launch authority unwound"),
                original: self,
            }),
        }
    }

    fn start_original(&mut self) -> Result<(), ProviderError> {
        self.authority
            .current()
            .map_err(|_| ProviderError::Correlation("packet current launch revoked"))?;
        self.authority
            .private_launch(
                &self.request.launch,
                &self.request.executable,
                &self.request.directory,
                false,
            )
            .map_err(|_| ProviderError::Correlation("packet original private launch revoked"))?;
        let deadline = ExchangeDeadline::start(self.request.budget)?;
        let (reader, writer) = self.bootstrap.take().ok_or(ProviderError::Correlation(
            "packet bootstrap endpoints absent",
        ))?;
        let input = Stdio::from(File::from(OwnedFd::from(reader)));
        let socket = self.request.directory.join("control.sock");
        let directory = self.request.directory.clone();
        if private_directory(&directory, self.request.launch.controller_uid.get())?
            != self.directory_identity
        {
            return Err(ProviderError::Correlation(
                "original packet private directory changed",
            ));
        }
        // Every fallible preparation and arbitrary installed validator precedes
        // this source-owned terminal read. Only local ownership moves and spawn
        // follow it; the actual Child is separately authenticated before Hello.
        self.authority
            .private_launch(
                &self.request.launch,
                &self.request.executable,
                &directory,
                true,
            )
            .map_err(|_| {
                ProviderError::Correlation("packet final original launch scope revoked")
            })?;
        let reservation = self
            .native_reservation
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "packet original native reservation absent",
            ))?;
        // The complete holder, cached slot identity and ReadOwner already exist.
        // launch installs Child into this same field before kernel authentication;
        // an unwind leaves it in the capsule retained outside catch_unwind.
        reservation.launch(
            Command::new(&self.request.executable)
                .arg(&socket)
                .stdin(input)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .process_group(0),
        )?;
        let reservation = self
            .native_reservation
            .take()
            .ok_or(ProviderError::Correlation(
                "packet original native reservation transferred",
            ))?;
        match reservation.into_guard() {
            Ok(guard) => self.guard = Some(guard),
            Err(failure) => {
                self.native_reservation = Some(failure.original);
                return Err(failure.error);
            }
        }
        let mut bootstrap = DeadlineStream::with_deadline(writer, deadline.clone())?;
        write_frame(&mut bootstrap, &self.launch_body, 1024 * 1024)?;
        drop(bootstrap);
        let stream = connect(&socket, &deadline)?;
        let guard = self.guard.as_ref().ok_or(ProviderError::Correlation(
            "packet actual launch guard absent",
        ))?;
        let peer = ClientPeer {
            pid: guard.custody()?.provider_pid(),
            uid: u32::try_from(self.request.launch.controller_uid.get())
                .map_err(|_| ProviderError::Correlation("packet actual peer UID bound"))?,
            executable: self.executable.clone(),
        };
        let handshake = self.handshake.as_mut().ok_or(ProviderError::Correlation(
            "packet original handshake absent",
        ))?;
        let original_hello = self
            .original_hello
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "packet original Hello journal absent",
            ))?;
        let session = ClientSession::negotiate_recorded_before(
            stream,
            &peer,
            &self.request.hello,
            self.request.connection.clone(),
            handshake,
            &mut self.request.verifier,
            self.request.supervisor.clone(),
            self.request.hello_schema.clone(),
            deadline,
            usize::try_from(self.request.launch.limits.frame_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("packet frame bound"))?,
            usize::try_from(self.request.launch.limits.nesting.get())
                .map_err(|_| ProviderError::ResourceExhausted("packet nesting bound"))?,
            original_hello,
        );
        // Install the actual Hello session before any later validation. The
        // pre-Child capsule remains the owner if construction refuses or unwinds.
        self.pending_session = Some(session?);
        match CnpController::new_retained(
            &mut self.pending_session,
            &mut self.content,
            &mut self.controller_route,
            self.request.budget,
        ) {
            Ok(controller) => self.controller = Some(controller),
            Err(error) => {
                self.controller_error = Some(error);
                return Err(ProviderError::Correlation(
                    "packet original controller construction refused",
                ));
            }
        }
        let selected = self
            .authority
            .source()
            .map_err(|_| ProviderError::Correlation("packet connected original source absent"))?;
        self.controller
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "packet original controller absent",
            ))?
            .install_connected_packet_transport_schema(&selected.binding, &selected.owner)?;
        let controller = self.controller.take().ok_or(ProviderError::Correlation(
            "packet original controller transferred",
        ))?;
        let guard = self.guard.take().ok_or(ProviderError::Correlation(
            "packet original guard transferred",
        ))?;
        let handshake = self.handshake.take().ok_or(ProviderError::Correlation(
            "packet original handshake transferred",
        ))?;
        match guard.attach(controller, handshake) {
            Ok(guard) => self.guard = Some(guard),
            Err(failure) => {
                // Attachment offers no recovery constructor. Keep the complete
                // original rejected guard/journals and diagnostic in this same
                // capsule; Drop uses its already reserved native supervisor.
                self.failed_attachment = Some(failure);
                return Err(ProviderError::Correlation(
                    "packet original attachment refused",
                ));
            }
        }
        Ok(())
    }
}

impl<V> PreparedPacketConnectedPeer<'_, V> {
    pub(in super::super) fn retire_original(&mut self) {
        if let Some(guard) = self.guard.as_mut() {
            guard.retire_original();
        }
        if let Some(failure) = self.failed_attachment.as_mut() {
            failure.retire_original();
        }
        drop(self.native_reservation.take());
        self.return_original_journal();
    }

    fn return_original_journal(&mut self) {
        // Move every surviving original without allocation or public encoding.
        // The independently reserved mailbox outlives this launch capsule and
        // remains distinct from the native guard's actual cleanup proof.
        let original = PacketPeerJournalCustody {
            _handshake: self.handshake.take(),
            _controller: self.controller.take(),
            _pending_session: self.pending_session.take(),
            _controller_error: self.controller_error.take(),
            _controller_route: self.controller_route.take(),
            _controller_budget: self.request.budget,
            _content: self.content.take(),
            _hello: self.original_hello.take(),
            _private_launch: std::mem::take(&mut self.launch_body),
        };
        if let Some(mut slot) = self.journal_custody.take() {
            slot.retain(original);
        }
    }
}

impl<V> Drop for PreparedPacketConnectedPeer<'_, V> {
    fn drop(&mut self) {
        self.return_original_journal();
    }
}
