//! Launches one original packet peer under bounded private bootstrap custody.
//!
//! The prepared capsule and native supervisor reservation exist before Child.
//! The private launch and Hello share one pre-launch deadline; neither a failed
//! exchange nor a dropped capsule replaces the original peer or its journals.

use std::{
    fs::File,
    os::{
        fd::OwnedFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
    time::Duration,
};

use crucible::node_adapters::cnp::{
    CnpSemanticLaunchGuard, CnpSemanticLaunchReservation, CnpSemanticProcessSlot, CnpSemanticSource,
};
use crucible_node_contract::{ContentRef, Id};
use crucible_node_provider::{
    ProviderError,
    client::{
        ClientCustody, ClientPeer, ClientSession, CnpController, ControllerRoute, DeadlineStream,
        ExchangeDeadline, OriginalHelloJournal,
    },
    connection::{BodySchemaVerifier, ConnectionSupervisor},
    envelope::Envelope,
    handshake::{Handshake, TrustedHandshakeVerifier},
    reference_packet::service::PacketSourceLaunch,
    transport::write_frame,
};

use super::{InstalledPacketCollectionAuthority, QualificationError};

/// Retains independently configured private launch and actual handshake custody.
pub struct PacketPeerLaunchRequest<V> {
    /// Names the independently selected, measured peer executable.
    pub executable: PathBuf,
    /// Names the fresh private session directory chosen by the host.
    pub directory: PathBuf,
    /// Retains the complete private source launch, including secret token custody.
    pub launch: PacketSourceLaunch,
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

/// Retains full original transport and private launch data without permission.
///
/// This opaque sidecar has no command, registration replacement, token getter,
/// Clone or Deserialize. The native supervisor retains it until authentic
/// original process reclamation and deliberate immutable evidence retention.
pub struct PacketPeerJournalCustody {
    _handshake: Option<Handshake>,
    _controller: Option<CnpController>,
    _pending_session: Option<ClientSession>,
    _controller_error: Option<ProviderError>,
    _controller_route: Option<ControllerRoute>,
    _controller_budget: Duration,
    _content: Option<ClientCustody>,
    _hello: Option<OriginalHelloJournal>,
    _private_launch: serde_json::Value,
}

/// Owns a finite returned-journal slot reserved alongside native custody.
///
/// The installed host implementation preallocates its one original mailbox
/// before Child. Retention must neither unwind nor drop incoming original data;
/// native cleanup does not authorize discarding unresolved transport evidence.
pub trait PacketPeerJournalSlot {
    /// Retains complete original data in the same pre-reserved supervision scope.
    fn retain(&mut self, original: PacketPeerJournalCustody);
}

/// Retains the preallocated private capsule when the original launch fails.
pub struct PacketPeerLaunchFailure<'a, V> {
    /// Describes the original failure without claiming native containment.
    pub error: ProviderError,
    /// Owns original secret, registrar, guard and unused reservations.
    pub original: Box<PreparedPacketCollectionPeer<'a, V>>,
}

/// Prepares one private source peer without ordinary accepted-class authority.
///
/// This capsule has no retry or resource extraction after failure. Drop hands
/// any actual native guard to its pre-reserved original supervisor. The returned
/// successful guard still requires source realization and opaque graph admission.
#[must_use = "retain original launch custody until actual native reclamation"]
pub struct PreparedPacketCollectionPeer<'a, V> {
    authority: &'a InstalledPacketCollectionAuthority,
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
    failed_attachment: Option<crucible::node_adapters::cnp::CnpSemanticAttachmentFailure>,
    attempted: bool,
}

struct PeerSettings<V> {
    executable: PathBuf,
    directory: PathBuf,
    launch: PacketSourceLaunch,
    verifier: V,
    supervisor: Rc<dyn ConnectionSupervisor>,
    hello_schema: Rc<dyn BodySchemaVerifier>,
    hello: Envelope,
    connection: Id,
    budget: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

impl InstalledPacketCollectionAuthority {
    /// Authenticates the exact private source and prepares transports before Child.
    ///
    /// # Errors
    /// Refuses changed current scope, launch edition/source/program/host/peer,
    /// exhausted complete private-body credit or unavailable socket endpoints.
    /// No native peer is launched by this preparation method.
    pub fn prepare_packet_peer<V: TrustedHandshakeVerifier>(
        &self,
        request: PacketPeerLaunchRequest<V>,
    ) -> Result<Box<PreparedPacketCollectionPeer<'_, V>>, QualificationError> {
        if request.budget.is_zero() || request.budget > Duration::from_secs(60) {
            return Err(QualificationError::Refused(
                "packet original launch deadline",
            ));
        }
        request.launch.validate().map_err(native)?;
        let directory_identity =
            private_directory(&request.directory, request.launch.controller_uid.get())
                .map_err(native)?;
        let selected = self.source.installation();
        if request.launch.schema_version != 2
            || request.launch.selection.provider != selected.provider
            || request.launch.selection.realization.descriptors
                != std::slice::from_ref(&selected.descriptor)
            || request.launch.selection.realization.bindings
                != std::slice::from_ref(&selected.binding)
            || request.launch.selection.realization.owner_bindings
                != std::slice::from_ref(&selected.owner)
        {
            return Err(QualificationError::Refused(
                "packet original private source differs",
            ));
        }
        super::scope::encoded_size(
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
        self.current()?;
        self.installed.authenticate_packet_private_launch(
            &self.plan,
            &request.launch,
            &request.executable,
        )?;
        let actual = crucible_node_provider::conformance::measure_executable(&request.executable)
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
        let bootstrap =
            std::os::unix::net::UnixStream::pair().map_err(|error| native(error.into()))?;
        let launch_body = serde_json::to_value(&request.launch)
            .map_err(crucible_node_contract::ContractError::from)?;
        let controller_route = ControllerRoute {
            node: selected.descriptor.id.clone(),
            execution_owner: selected.owner.owner.id.clone(),
        };
        let PacketPeerLaunchRequest {
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
        let native_reservation = CnpSemanticLaunchReservation::reserve(
            directory.clone(),
            actual.clone(),
            native_custody,
        );
        // The owning failure capsule and complete private frame are allocated
        // before the peer can exist. The secret stays in this private owner.
        Ok(Box::new(PreparedPacketCollectionPeer {
            authority: self,
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
}

impl<'a, V: TrustedHandshakeVerifier> PreparedPacketCollectionPeer<'a, V> {
    pub(super) fn has_authority(&self, authority: &InstalledPacketCollectionAuthority) -> bool {
        std::ptr::eq(self.authority, authority)
    }

    /// Launches, authenticates and attaches the same original peer exactly once.
    ///
    /// # Errors
    /// Returns this preallocated owner on changed scope, spawn/bootstrap failure,
    /// expiration, foreign peer, failed original Hello or attachment. No failed
    /// Hello or Child is retried. The actual guard stays outside unwind handling.
    pub fn start(
        mut self: Box<Self>,
    ) -> Result<CnpSemanticLaunchGuard, PacketPeerLaunchFailure<'a, V>> {
        if self.attempted {
            return Err(PacketPeerLaunchFailure {
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
                None => Err(PacketPeerLaunchFailure {
                    error: ProviderError::Correlation("packet original attached guard absent"),
                    original: self,
                }),
            },
            Ok(Err(error)) => Err(PacketPeerLaunchFailure {
                error,
                original: self,
            }),
            Err(_) => Err(PacketPeerLaunchFailure {
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
            .installed
            .authenticate_packet_private_launch(
                &self.authority.plan,
                &self.request.launch,
                &self.request.executable,
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
            .installed
            .authenticate_packet_launch_current_scope(
                &self.authority.plan,
                &self.request.launch,
                &self.request.executable,
                &directory,
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
                .stderr(Stdio::null())
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
        self.controller
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "packet original controller absent",
            ))?
            .install_packet_transport_schema()?;
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

impl<V> Drop for PreparedPacketCollectionPeer<'_, V> {
    fn drop(&mut self) {
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

fn private_directory(path: &std::path::Path, uid: u64) -> Result<DirectoryIdentity, ProviderError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || u64::from(metadata.uid()) != uid
        || std::fs::read_dir(path)?.next().transpose()?.is_some()
    {
        return Err(ProviderError::Correlation(
            "packet private original directory scope",
        ));
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
    })
}

fn connect(
    path: &std::path::Path,
    deadline: &ExchangeDeadline,
) -> Result<std::os::unix::net::UnixStream, ProviderError> {
    loop {
        let remaining = deadline.remaining()?;
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                // Socket readiness alone is polled under the unchanged cut.
                std::thread::park_timeout(remaining.min(Duration::from_millis(5)));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn native(error: ProviderError) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}
