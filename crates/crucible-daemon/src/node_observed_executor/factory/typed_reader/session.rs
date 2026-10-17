//! Prepares private typed Hello custody before Child and drives its original stream.
//!
//! Secret launch and Hello bodies stay in this owning capsule. Host-supplied
//! authentication, schema and incident supervisors remain mandatory; measured
//! package metadata cannot instantiate them or grant native/class authority.

use std::{
    collections::BTreeMap, io::Read, os::unix::net::UnixStream, path::PathBuf, rc::Rc,
    time::Duration,
};

use crucible::node_adapters::cnp::LineageControlledReference;
use crucible_node_contract::{Bytes, ContentRef, Extensions, Id, U64, Validate};
use crucible_node_provider::{
    ProviderError,
    client::{
        ClientContent, ClientCustody, ClientPeer, ClientSession, ExchangeDeadline,
        ReferenceController, ReferenceControllerPreparationFailure,
    },
    connection::{BodySchemaVerifier, ConnectionSupervisor},
    envelope::{Envelope, MessageKind, Method, Nullable},
    handshake::{
        EXTENSION_NEGOTIATION_V1, ExtensionHandshake, ExtensionOfferV1, Handshake, HelloRequest,
        NegotiationPolicy, TrustedHandshakeVerifier, TrustedInstallation,
    },
    reference_lineage::INPUT_LINEAGE_FEATURE,
    reference_service::{ReferenceNegotiatedLineageReaderLaunchBootstrap, ReferenceProfile},
};

use super::{
    super::{NodeObservedError, refused},
    LaunchedTypedReaderProvider, PreparedTypedReaderCohort, TypedReaderAdoptionFailure,
    TypedReaderLaunchError,
};

/// Supplies independent host services and all original IDs before native launch.
///
/// The private launch object must never be persisted in a conformance report.
/// This object supplies no default trusted verifier or accepted class policy.
pub struct TypedReaderSessionRequest<V: TrustedHandshakeVerifier> {
    /// Retains the exact private source/target launch scope without public hashing.
    pub launch: ReferenceNegotiatedLineageReaderLaunchBootstrap,
    /// Names a fresh private socket directory prepared by the owning launcher.
    pub directory: PathBuf,
    /// Names the sole original Hello request.
    pub hello: Id,
    /// Names the sole original connection registration.
    pub connection: Id,
    /// Names the original complete discovery request.
    pub discovery: Id,
    /// Names the original native realization request.
    pub realization: Id,
    /// Supplies independent installed peer/launch/contract authentication.
    pub verifier: Box<V>,
    /// Retains original connection incidents, including uncertain Hello outcomes.
    pub supervisor: Rc<dyn ConnectionSupervisor>,
    /// Supplies independent complete received-body schema authentication.
    pub schemas: Rc<dyn BodySchemaVerifier>,
    /// Bounds launch delivery, socket availability and the initial Hello together.
    pub budget: Duration,
}

/// Returns the same host/private request when preparation refuses before Child.
pub struct TypedReaderSessionPreparationFailure<V: TrustedHandshakeVerifier> {
    /// Reports refusal without claiming a native launch or control effect.
    pub error: NodeObservedError,
    /// Retains the original private source request and independent host services.
    pub request: TypedReaderSessionRequest<V>,
}

/// Retains the complete prelaunch Hello, typed registrar and content custody.
pub struct PreparedTypedReaderSession<V: TrustedHandshakeVerifier> {
    request: TypedReaderSessionRequest<V>,
    package: ContentRef,
    profile: ReferenceProfile,
    peer_executable: ContentRef,
    hello: Envelope,
    registrar: Box<ExtensionHandshake>,
    custody: ClientCustody,
    bootstrap_transport: Option<(UnixStream, UnixStream)>,
    deadline: Option<ExchangeDeadline>,
}

/// Keeps the prepared session beside the same actual spawned source capsule.
pub struct LaunchedTypedReaderSession<V: TrustedHandshakeVerifier> {
    provider: LaunchedTypedReaderProvider,
    prepared: PreparedTypedReaderSession<V>,
    attempted: bool,
}

/// Returns both the original launch result and preallocated private session.
pub struct TypedReaderSessionLaunchFailure<V: TrustedHandshakeVerifier> {
    /// Retains the actual launch failure and its original seven-slot obligations.
    pub launch: TypedReaderLaunchError,
    /// Retains the original Hello, registrar, host services and byte journals.
    pub prepared: PreparedTypedReaderSession<V>,
}

/// Preserves original stream and process custody at each authenticated boundary.
pub enum TypedReaderSessionFailure<V: TrustedHandshakeVerifier> {
    /// Retains the same Child, registrar and uncertain original Hello on refusal.
    Hello {
        /// Reports the original connection/authentication refusal.
        error: ProviderError,
        /// Retains actual source-group custody and all prepared host state.
        original: Box<LaunchedTypedReaderSession<V>>,
    },
    /// Retains the actual authenticated session and byte journals on validation failure.
    Controller {
        /// Retains the same original source and reader reservation.
        provider: Box<LaunchedTypedReaderProvider>,
        /// Retains the exact registrar used by the original Hello.
        registrar: Box<ExtensionHandshake>,
        /// Retains the authenticated stream and complete controller preparation.
        original: Box<ReferenceControllerPreparationFailure>,
        /// Retains independent host authentication custody.
        verifier: Box<V>,
    },
    /// Retains original attached controller/registrar and native realization journals.
    Adoption(Box<TypedReaderAdoptionFailure>),
}

impl PreparedTypedReaderCohort {
    /// Prepares one declared source's entire private session before Child.
    ///
    /// Counts full profile/private launch retention before clones, authenticates
    /// the installed fixture/source scope, preinstalls every bounded original
    /// content body, and freezes the nonce, typed offer and original request IDs.
    /// The cohort's seven reservations remain unconsumed on this path.
    ///
    /// # Errors
    /// Returns the same request on missing slots, foreign target/source, absent
    /// host authority, invalid IDs, exhausted whole-record/content credit or panic.
    pub fn prepare_session<V: TrustedHandshakeVerifier>(
        &self,
        request: TypedReaderSessionRequest<V>,
    ) -> Result<PreparedTypedReaderSession<V>, Box<TypedReaderSessionPreparationFailure<V>>> {
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let parts = &self
                .pending
                .iter()
                .find(|pending| {
                    pending.parts.profile.descriptor.id == request.launch.bootstrap.node_id
                        && pending.parts.profile.owner.id == request.launch.bootstrap.owner_id
                })
                .ok_or_else(|| refused("typed session has no remaining original reservation"))?
                .parts;
            validate_request(&request)?;
            let bootstrap = &request.launch.bootstrap;
            if bootstrap.node_id != parts.profile.descriptor.id
                || bootstrap.owner_id != parts.profile.owner.id
                || bootstrap.world_binding_hash != self.target.world_binding_hash
                || bootstrap.activation_id != self.target.activation_id
                || bootstrap.world_generation != self.target.generation
                || !self.target.owners.iter().any(|owner| {
                    owner.owner == bootstrap.owner_id
                        && owner.incarnation == bootstrap.authority.incarnation_id
                        && owner.generation == bootstrap.authority.owner_generation
                })
            {
                return Err(refused("typed session original source/target differs"));
            }
            super::owning::count_launch(&request.launch, 16 * 1024 * 1024).map_err(native)?;
            parts
                .profile
                .preflight_retention(1024 * 1024)
                .map_err(native)?;
            self.policy.authenticate_launch(parts, &request.launch)?;

            // This constructor precedes Child. Complete body credit and immutable
            // installation occur here, so Hello cannot trigger their allocation.
            let mut content =
                ClientContent::new(64 * 1024 * 1024, 4096, 1024 * 1024).map_err(native)?;
            content
                .install_borrowed(
                    parts
                        .profile
                        .content_objects()
                        .iter()
                        .map(|body| (&body.reference, body.bytes.as_slice()))
                        .chain(
                            bootstrap
                                .installed_content
                                .iter()
                                .map(|body| (&body.reference, body.bytes.as_slice())),
                        ),
                )
                .map_err(native)?;
            let custody = ClientCustody::new(4096, content).map_err(native)?;
            let peer = parts
                .package
                .peer_policy(Rc::clone(&self.policy.registry))?;
            let (registrar, hello) = prepare_hello(
                &request,
                &parts.profile,
                parts.package.definition().selection(),
                Rc::new(peer),
            )
            .map_err(native)?;

            Ok((
                parts.package.identity().clone(),
                parts.profile.clone(),
                parts.package.artifact_content("provider")?.clone(),
                custody,
                registrar,
                hello,
                UnixStream::pair().map_err(|error| native(error.into()))?,
            ))
        }))
        .unwrap_or_else(|_| Err(refused("typed session preparation authority unwound")));
        match checked {
            Ok((
                package,
                profile,
                peer_executable,
                custody,
                registrar,
                hello,
                bootstrap_transport,
            )) => Ok(PreparedTypedReaderSession {
                request,
                package,
                profile,
                peer_executable,
                custody,
                registrar,
                hello,
                bootstrap_transport: Some(bootstrap_transport),
                deadline: None,
            }),
            Err(error) => Err(Box::new(TypedReaderSessionPreparationFailure {
                error,
                request,
            })),
        }
    }

    /// Launches only the source whose original session was prepared beforehand.
    ///
    /// # Errors
    /// Returns both the complete original launch outcome and prepared session
    /// on changed queue/source scope or launch refusal. No replacement is tried.
    pub fn launch_session<V: TrustedHandshakeVerifier>(
        &mut self,
        mut prepared: PreparedTypedReaderSession<V>,
    ) -> Result<LaunchedTypedReaderSession<V>, Box<TypedReaderSessionLaunchFailure<V>>> {
        let matches = self.pending.front().is_some_and(|pending| {
            pending.parts.package.identity() == &prepared.package
                && pending.parts.profile.descriptor == prepared.profile.descriptor
                && pending.parts.profile.owner == prepared.profile.owner
                && pending.parts.profile.configuration_ref == prepared.profile.configuration_ref
        });
        if !matches {
            return Err(Box::new(TypedReaderSessionLaunchFailure {
                launch: TypedReaderLaunchError::NoRemainingReservation(refused(
                    "typed prepared session source queue changed",
                )),
                prepared,
            }));
        }
        if prepared.deadline.is_some() || prepared.bootstrap_transport.is_none() {
            return Err(Box::new(TypedReaderSessionLaunchFailure {
                launch: TypedReaderLaunchError::NoRemainingReservation(refused(
                    "typed original launch transport already attempted",
                )),
                prepared,
            }));
        }
        let deadline = match ExchangeDeadline::start(prepared.request.budget) {
            Ok(deadline) => deadline,
            Err(error) => {
                return Err(Box::new(TypedReaderSessionLaunchFailure {
                    launch: TypedReaderLaunchError::NoRemainingReservation(native(error.into())),
                    prepared,
                }));
            }
        };
        prepared.deadline = Some(deadline.clone());
        let Some((reader, writer)) = prepared.bootstrap_transport.take() else {
            return Err(Box::new(TypedReaderSessionLaunchFailure {
                launch: TypedReaderLaunchError::NoRemainingReservation(refused(
                    "typed original bootstrap endpoints unavailable",
                )),
                prepared,
            }));
        };
        match self.launch_next_transport(
            prepared.request.directory.clone(),
            &prepared.request.launch,
            Some((reader, writer, deadline)),
        ) {
            Ok(provider) => Ok(LaunchedTypedReaderSession {
                provider,
                prepared,
                attempted: false,
            }),
            Err(launch) => Err(Box::new(TypedReaderSessionLaunchFailure {
                launch,
                prepared,
            })),
        }
    }
}

impl<V: TrustedHandshakeVerifier> LaunchedTypedReaderSession<V> {
    /// Authenticates one original Hello and consumes its actual native realization.
    ///
    /// Kernel peer PID/UID/executable checks precede Hello. Socket availability
    /// polling consumes the same pre-launch deadline as bootstrap delivery;
    /// once a Hello starts it is never retried.
    /// The actual surviving typed registrar then enters the same source guard
    /// before Discover/Realize and the consuming negotiated source constructor.
    /// This admits no common runtime activation, class certificate or Ready.
    ///
    /// # Errors
    /// Preserves original process/registration/journal owners on peer mismatch,
    /// timeout, transport uncertainty, verifier panic or source adoption refusal.
    pub fn realize_original(
        mut self,
    ) -> Result<LineageControlledReference, Box<TypedReaderSessionFailure<V>>> {
        if self.attempted {
            return Err(Box::new(TypedReaderSessionFailure::Hello {
                error: ProviderError::Correlation("original typed Hello already attempted"),
                original: Box::new(self),
            }));
        }
        // Sticky before any connection work. Even a refused attempt remains
        // original evidence; extracting its capsule cannot reset or retry it.
        self.attempted = true;
        let connected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let deadline = self
                .prepared
                .deadline
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "original launch deadline unavailable",
                ))?
                .clone();
            let socket = self.prepared.request.directory.join("control.sock");
            let stream = connect_original(&socket, &deadline)?;
            let peer = ClientPeer {
                pid: self
                    .provider
                    .guard
                    .provider_pid()
                    .ok_or(ProviderError::Correlation(
                        "original provider custody missing",
                    ))?,
                uid: u32::try_from(self.prepared.request.launch.bootstrap.controller_uid.get())
                    .map_err(|_| ProviderError::Correlation("original peer UID overflow"))?,
                executable: self.prepared.peer_executable.clone(),
            };
            ClientSession::negotiate_extensions_before(
                stream,
                &peer,
                &self.prepared.hello,
                self.prepared.request.connection.clone(),
                &mut self.prepared.registrar,
                &mut *self.prepared.request.verifier,
                Rc::clone(&self.prepared.request.supervisor),
                Rc::clone(&self.prepared.request.schemas),
                deadline,
                usize::try_from(
                    self.prepared
                        .request
                        .launch
                        .bootstrap
                        .limits
                        .frame_bytes
                        .get(),
                )
                .map_err(|_| ProviderError::ResourceExhausted("typed Hello frame ceiling"))?,
                usize::try_from(self.prepared.request.launch.bootstrap.limits.nesting.get())
                    .map_err(|_| ProviderError::ResourceExhausted("typed Hello nesting ceiling"))?,
            )
        }))
        .unwrap_or_else(|_| {
            Err(ProviderError::Correlation(
                "typed original Hello verifier unwound",
            ))
        });
        let session = match connected {
            Ok(session) => session,
            Err(error) => {
                return Err(Box::new(TypedReaderSessionFailure::Hello {
                    error,
                    original: Box::new(self),
                }));
            }
        };
        let PreparedTypedReaderSession {
            request,
            profile,
            registrar,
            custody,
            ..
        } = self.prepared;
        let TypedReaderSessionRequest {
            launch,
            discovery,
            realization,
            verifier,
            budget,
            ..
        } = request;
        let controller = match ReferenceController::new_qualified_owned(
            profile,
            launch.bootstrap,
            session,
            custody,
            budget,
            launch.qualification_refs,
        ) {
            Ok(controller) => Box::new(controller),
            Err(original) => {
                return Err(Box::new(TypedReaderSessionFailure::Controller {
                    provider: Box::new(self.provider),
                    registrar,
                    original,
                    verifier,
                }));
            }
        };
        self.provider
            .realize_original(controller, registrar, discovery, realization)
            .map_err(|original| Box::new(TypedReaderSessionFailure::Adoption(original)))
    }
}

impl<V: TrustedHandshakeVerifier> TypedReaderSessionFailure<V> {
    pub(super) fn retire_original(&mut self) -> Result<(), ProviderError> {
        match self {
            Self::Hello { original, .. } => {
                original.provider.guard.retire_original()?;
                original.provider.runtime.release_unused()
            }
            Self::Controller { provider, .. } => {
                provider.guard.retire_original()?;
                provider.runtime.release_unused()
            }
            Self::Adoption(original) => match original.as_mut() {
                TypedReaderAdoptionFailure::Original { provider, .. } => {
                    provider.guard.retire_original()?;
                    provider.runtime.release_unused()
                }
                TypedReaderAdoptionFailure::Preparation(original) => {
                    original.guard.retire_original()?;
                    original.slot.release_unused()
                }
                TypedReaderAdoptionFailure::Attachment { .. } => {
                    // Consuming rejected controller/registrar containment is
                    // not a borrowed proof. Preserve this entire attachment
                    // and remain Unknown until an authentic handoff exists.
                    Err(ProviderError::Correlation(
                        "borrowed rejected attachment retirement unavailable",
                    ))
                }
            },
        }
    }

    /// Services original pre-realization cleanup while retaining all failed state.
    ///
    /// Hello/controller failures retain the same private request, registrar and
    /// journals throughout actual group reclamation. No missing PID, timeout or
    /// contained lease constitutes proof of termination. Adoption failures use
    /// the attached native reader's existing owning retirement path instead.
    ///
    /// # Errors
    /// Retains the complete failure on unresolved source custody or operational
    /// reclamation error, and refuses to substitute this path for live adoption.
    pub fn poll_preparation_reclamation(&mut self) -> Result<bool, ProviderError> {
        match self {
            Self::Hello { original, .. } => {
                let complete = original.provider.guard.poll_reclamation()?;
                if complete {
                    original.prepared.registrar.contain();
                }
                Ok(complete)
            }
            Self::Controller {
                provider,
                registrar,
                ..
            } => {
                let complete = provider.guard.poll_reclamation()?;
                if complete {
                    registrar.contain();
                }
                Ok(complete)
            }
            Self::Adoption(_) => Err(ProviderError::Correlation(
                "actual typed adoption requires its owning native retirement",
            )),
        }
    }
}

fn validate_request<V: TrustedHandshakeVerifier>(
    request: &TypedReaderSessionRequest<V>,
) -> Result<(), NodeObservedError> {
    request.launch.validate()?;
    request
        .launch
        .bootstrap
        .installed_content
        .iter()
        .try_fold(0usize, |total, body| {
            total
                .checked_add(body.bytes.as_slice().len())
                .filter(|total| *total <= 16 * 1024 * 1024)
                .ok_or_else(|| refused("typed session original private body credit"))
        })?;
    let ids = [
        &request.hello,
        &request.connection,
        &request.discovery,
        &request.realization,
    ];
    for (index, id) in ids.iter().enumerate() {
        id.validate()?;
        if ids[..index].contains(id) {
            return Err(refused("typed original session request identities overlap"));
        }
    }
    if request.budget.is_zero()
        || request.budget > Duration::from_secs(60)
        || !request.directory.is_absolute()
        || request.directory.join("control.sock").as_os_str().len() >= 108
    {
        return Err(refused("typed original session deadline/directory credit"));
    }
    Ok(())
}

fn prepare_hello<V: TrustedHandshakeVerifier>(
    request: &TypedReaderSessionRequest<V>,
    profile: &ReferenceProfile,
    selected: &crucible_node_contract::ExtensionSelection,
    installed: Rc<dyn crucible_node_provider::handshake::InstalledExtensionNegotiationVerifier>,
) -> Result<(Box<ExtensionHandshake>, Envelope), ProviderError> {
    let bootstrap = &request.launch.bootstrap;
    let features = [
        "cnp.control-evidence/1",
        "cnp.core/1",
        EXTENSION_NEGOTIATION_V1,
        INPUT_LINEAGE_FEATURE,
    ]
    .into_iter()
    .map(Id::new)
    .collect::<Result<Vec<_>, _>>()?;
    let (binding, _) = profile.bind_qualified(
        bootstrap.authority.clone(),
        &request.launch.qualification_refs,
    )?;
    let mut token = [0; 32];
    token.copy_from_slice(bootstrap.admission_token.as_slice());
    let handshake = Handshake::new(
        TrustedInstallation {
            session_id: bootstrap.authority.session_id.clone(),
            incarnation_id: bootstrap.authority.incarnation_id.clone(),
            measured_implementation: profile.implementation.clone(),
            launch_receipt: bootstrap.admission_receipt.clone(),
            admission_token: token,
        },
        NegotiationPolicy {
            supported_features: features.clone(),
            required_features: features.clone(),
            provider_limits: bootstrap.limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref,
            envelope_extension_features: BTreeMap::from([(
                EXTENSION_NEGOTIATION_V1.to_owned(),
                Id::new(EXTENSION_NEGOTIATION_V1)?,
            )]),
        },
    )?;
    let registrar = Box::new(ExtensionHandshake::new(handshake, installed)?);
    let mut nonce = [0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let request_body = HelloRequest {
        versions: vec!["CNP/1".to_owned()],
        session_id: bootstrap.authority.session_id.clone(),
        controller_nonce: Bytes::new(nonce.to_vec()),
        required_features: features,
        optional_features: Vec::new(),
        limits: bootstrap.limits,
        admission_token: bootstrap.admission_token.clone(),
        resume_session: None,
        extensions: Extensions::new(),
    };
    let serde_json::Value::Object(body) =
        serde_json::to_value(&request_body).map_err(crucible_node_contract::ContractError::from)?
    else {
        return Err(ProviderError::Correlation(
            "typed Hello body is not an object",
        ));
    };
    let offer = ExtensionOfferV1 {
        format: U64::new(1),
        required: vec![selected.clone()],
        optional: Vec::new(),
    };
    offer.validate()?;
    let hello = Envelope {
        protocol: "CNP/1".to_owned(),
        message: MessageKind::Request,
        session_id: Nullable(None),
        incarnation_id: Nullable(None),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(request.hello.clone())),
        sequence: U64::new(1),
        method: Method::Hello,
        body,
        extensions: BTreeMap::from([(
            EXTENSION_NEGOTIATION_V1.to_owned(),
            serde_json::to_value(offer).map_err(crucible_node_contract::ContractError::from)?,
        )]),
    };
    hello.validate()?;
    super::owning::count_launch(
        &hello,
        usize::try_from(bootstrap.limits.frame_bytes.get().min(1024 * 1024))
            .map_err(|_| ProviderError::ResourceExhausted("typed Hello envelope credit"))?,
    )?;
    Ok((registrar, hello))
}

fn connect_original(
    socket: &std::path::Path,
    deadline: &ExchangeDeadline,
) -> Result<UnixStream, ProviderError> {
    loop {
        let remaining = deadline.remaining()?;
        match UnixStream::connect(socket) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                // Only socket availability is polled. An attempted Hello is
                // never resent and a new process/session is never substituted.
                // This source publishes its socket after spawn and exposes no
                // readiness descriptor. Parking avoids a connect busy loop;
                // early/spurious wakes only recheck readiness and the same cut.
                std::thread::park_timeout(remaining.min(Duration::from_millis(5)));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn native(error: ProviderError) -> NodeObservedError {
    NodeObservedError::Native(error.to_string())
}
