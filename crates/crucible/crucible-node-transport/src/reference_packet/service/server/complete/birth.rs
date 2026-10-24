//! Retains the original native service across each borrowed birth phase.
//!
//! The immutable original cut is checked before listener effects, Hello, native
//! construction and endpoint publication. All refused phase owners and unwind
//! payloads stay in this capsule until the host reaps the same original Child.

use super::super::super::super::connected::PacketConnectedProgram;
use super::super::super::super::control::PacketCompleteControlBirthFailure;
use super::super::super::super::coordinator::PacketNative5CoordinatorInstallation;
use super::super::super::super::{PacketEvent, PacketModelBirthFailure};
use super::*;
use crate::client::{ExchangeDeadline, OriginalNative5BirthCut, OriginalNative5BirthStream};
use crate::connection::Native5ConnectionBirthRefusal;
use crate::native_hello::{OriginalNativeHelloExchange, OriginalNativeHelloJournal};
use std::any::Any;
use std::os::unix::net::UnixStream;

pub(super) struct CompleteBirth {
    launch: PacketNative5SourceLaunch,
    cut: OriginalNative5BirthCut,
    hello: Option<OriginalNativeHelloJournal>,
    boot: Option<Rc<std::cell::RefCell<super::super::super::ack_emitter::NativeAckBoot>>>,
    bootstrap_literals: Option<Rc<std::cell::RefCell<OriginalFrameReservation>>>,
    selected_handshake: Option<ExtensionHandshake>,
    selected_registry: Option<Rc<EmptyBootExtensions>>,
    exchange: Option<OriginalNativeHelloExchange<OriginalNative5BirthStream>>,
    raw: Option<UnixStream>,
    bounded_failure: Option<Box<crate::client::OriginalNative5BirthStreamRefusal>>,
    hello_bind_failure: Option<
        Box<crate::native_hello::OriginalNativeHelloBindRefusal<OriginalNative5BirthStream>>,
    >,
    bounded: Option<OriginalNative5BirthStream>,
    control_stream: Option<DeadlineStream>,
    listener: Option<UnixListener>,
    bank: Option<OriginalFrameReservation>,
    handshake: Option<Handshake>,
    authority: Option<ConnectionAuthority>,
    policy: Option<Rc<Native5Policy>>,
    supervisor: Option<Rc<Supervisor>>,
    connection: Option<Connection<DeadlineStream>>,
    connection_failure: Option<Box<Native5ConnectionBirthRefusal<DeadlineStream>>>,
    effect_socket: Option<UnixDatagram>,
    producer: Option<PacketProgram>,
    reactive: Option<PacketConnectedProgram>,
    producer_model_failure: Option<PacketModelBirthFailure<Vec<PacketEvent>>>,
    reactive_model_failure: Option<
        PacketModelBirthFailure<super::super::super::super::connected::PacketConnectedDefinition>,
    >,
    producer_failure: Option<PacketCompleteControlBirthFailure<PacketProgram>>,
    reactive_failure: Option<PacketCompleteControlBirthFailure<PacketConnectedProgram>>,
    native: Option<PacketControl>,
    endpoint_failure: Option<
        Box<super::super::super::super::endpoint::PacketCompleteEndpointRefusal<DeadlineStream>>,
    >,
    deadline: Option<ExchangeDeadline>,
    endpoint: Option<super::super::super::super::endpoint::PacketEndpoint<DeadlineStream>>,
    pub(super) error: Option<ProviderError>,
    pub(super) unwind: Option<Box<dyn Any + Send>>,
}

impl CompleteBirth {
    pub(super) fn new(launch: PacketNative5SourceLaunch) -> Result<Self, ProviderError> {
        let cut = OriginalNative5BirthCut::start(Duration::from_secs(5))?;
        Ok(Self::from_original_cut(launch, cut))
    }

    fn from_original_cut(launch: PacketNative5SourceLaunch, cut: OriginalNative5BirthCut) -> Self {
        Self {
            launch,
            cut,
            hello: None,
            boot: None,
            bootstrap_literals: None,
            selected_handshake: None,
            selected_registry: None,
            exchange: None,
            raw: None,
            bounded_failure: None,
            hello_bind_failure: None,
            bounded: None,
            control_stream: None,
            listener: None,
            bank: None,
            handshake: None,
            authority: None,
            policy: None,
            supervisor: None,
            connection: None,
            connection_failure: None,
            effect_socket: None,
            producer: None,
            reactive: None,
            producer_model_failure: None,
            reactive_model_failure: None,
            producer_failure: None,
            reactive_failure: None,
            native: None,
            endpoint_failure: None,
            deadline: None,
            endpoint: None,
            error: None,
            unwind: None,
        }
    }

    pub(super) fn from_original_boot(
        launch: PacketNative5SourceLaunch,
        cut: OriginalNative5BirthCut,
        boot: Rc<std::cell::RefCell<super::super::super::ack_emitter::NativeAckBoot>>,
        literals: Rc<std::cell::RefCell<OriginalFrameReservation>>,
    ) -> Self {
        let mut original = Self::from_original_cut(launch, cut);
        original.boot = Some(boot);
        original.bootstrap_literals = Some(literals);
        original
    }

    pub(super) fn hold(self) -> ! {
        loop {
            std::hint::black_box(&self);
            std::thread::park();
        }
    }

    pub(super) fn prepare(&mut self, socket: &Path) -> Result<PacketSourceService, ProviderError> {
        self.cut.ensure_current()?;
        self.launch.validate()?;
        // Owned11 preparation requires the actual private boot and independent
        // born metadata selection. Other compact preparation stays closed.
        let selected_owned11 = matches!(
            self.launch.capture_profile,
            super::super::super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) && self.launch.protocol_metadata_limits.is_some()
            && self.launch.native_codec_metadata_extent.is_some()
            && self.launch.ack_emitter_selection.is_some()
            && self.boot.is_some();
        if !self.launch.capture_profile.is_original_arrays() && !selected_owned11 {
            return Err(ProviderError::Conflict(
                "native5 compact service mechanism not installed",
            ));
        }
        if self.launch.ack_emitter_selection.is_some() && self.boot.is_none() {
            return Err(ProviderError::Correlation(
                "canonical ACK source association is not installed",
            ));
        }
        if self.launch.confirmation_selection.is_some() && self.boot.is_none() {
            return Err(ProviderError::Conflict(
                "native5 confirmation service mechanism not installed",
            ));
        }
        self.hello = Some(OriginalNativeHelloJournal::reserve(65_536, 64)?);
        if self.hello.as_ref().ok_or_else(absent)?.allocated_bytes()
            > usize::try_from(self.launch.storage.hello_bytes.get()).map_err(|_| absent())?
        {
            return Err(ProviderError::ResourceExhausted(
                "native5 actual Hello allocation",
            ));
        }
        self.bank = Some(OriginalFrameReservation::reserve(
            usize::try_from(self.launch.storage.frame_bank_bytes.get()).map_err(|_| absent())?,
            usize::try_from(self.launch.storage.frames_per_direction.get())
                .map_err(|_| absent())?,
        )?);
        private_parent(socket)?;
        private_parent(&self.launch.effects)?;
        let effects = fs::symlink_metadata(&self.launch.effects)?;
        if !effects.file_type().is_socket() || effects.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(ProviderError::Correlation(
                "native5 effect receiver ownership",
            ));
        }
        let executable = crate::conformance::measure_executable(&std::env::current_exe()?)?;
        if !self
            .launch
            .selection
            .provider
            .implementation
            .artifacts
            .iter()
            .any(|artifact| {
                artifact.role.as_str() == "executable" && artifact.content == executable
            })
        {
            return Err(ProviderError::Correlation(
                "native5 provider executable differs",
            ));
        }
        self.supervisor = Some(Rc::new(Supervisor::new()?));
        self.cut.ensure_current()?;
        self.listener = Some(UnixListener::bind(socket)?);
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        self.listener
            .as_ref()
            .ok_or_else(absent)?
            .set_nonblocking(true)?;
        loop {
            self.cut.ensure_current()?;
            match self.listener.as_ref().ok_or_else(absent)?.accept() {
                Ok((stream, _)) => {
                    self.raw = Some(stream);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::yield_now()
                }
                Err(error) => return Err(error.into()),
            }
        }
        let stream = self.raw.as_ref().ok_or_else(absent)?;
        let credentials =
            rustix::net::sockopt::socket_peercred(stream).map_err(std::io::Error::from)?;
        if u64::from(credentials.uid.as_raw()) != self.launch.controller_uid.get()
            || credentials.pid.as_raw_nonzero().get() as u64 != self.launch.controller_pid.get()
        {
            return Err(ProviderError::Correlation(
                "native5 original controller kernel identity",
            ));
        }
        let peer = Path::new("/proc")
            .join(self.launch.controller_pid.get().to_string())
            .join("exe");
        if crate::conformance::measure_executable(&peer)? != self.launch.controller_executable {
            return Err(ProviderError::Correlation(
                "native5 original controller executable",
            ));
        }
        let stream = self.raw.take().ok_or_else(absent)?;
        self.bounded = Some(match self.cut.bind_owned(stream) {
            Ok(stream) => stream,
            Err(failure) => {
                self.bounded_failure = Some(failure);
                return Err(absent());
            }
        });
        let journal = self.hello.take().ok_or_else(absent)?;
        let stream = self.bounded.take().ok_or_else(absent)?;
        self.exchange = Some(match journal.bind_owned(stream) {
            Ok(exchange) => exchange,
            Err(failure) => {
                self.hello_bind_failure = Some(failure);
                return Err(absent());
            }
        });
        self.cut.ensure_current()?;
        // Hello local DOMs and typed claims end before policy/coordinator
        // construction. All original journals/authority/handshake fields stay
        // on self, including every failed-partial owner.
        {
            let value = {
                let boot = self
                    .boot
                    .as_ref()
                    .map(|boot| {
                        boot.try_borrow().map_err(|_| {
                            ProviderError::Conflict("native original Hello boot borrowed")
                        })
                    })
                    .transpose()?;
                let preflight = boot
                    .as_ref()
                    .map(|boot| boot.original_native_hello_preflight(&self.launch))
                    .transpose()?
                    .flatten();
                let exchange = self.exchange.as_mut().ok_or_else(absent)?;
                match preflight.as_ref() {
                    Some(preflight) => exchange.receive_original_preflight(preflight)?,
                    None => exchange.receive()?,
                }
            }
            .ok_or(ProviderError::Frame("native5 original Hello missing"))?;
            // The immutable boot loan ends before later handshake callbacks.
            let request = Envelope::decode(&canonical::canonical_json(&value)?, 65_536)?;
            let RequestBody::Hello(hello_request) = decode_request(request.method, &request.body)?
            else {
                return Err(ProviderError::Frame(
                    "native5 original initial frame is not Hello",
                ));
            };
            let invocation = self
                .boot
                .as_ref()
                .map(|boot| {
                    let boot = boot
                        .try_borrow()
                        .map_err(|_| ProviderError::Conflict("native Hello boot borrowed"))?;
                    boot.original_invocation_hello_registration_data()?
                        .map(|registration| {
                            super::hello_selection::invocation_selection(
                                &self.launch.selection.provider,
                                registration,
                            )
                        })
                        .transpose()
                })
                .transpose()?
                .flatten();
            let (mut selected, envelope_extensions) = if let Some(selection) = invocation {
                selection
            } else {
                let mut selected = vec![
                    Id::new("cnp.control-evidence/1")?,
                    Id::new("cnp.core/1")?,
                    Id::new(
                        super::super::super::super::continuation_contracts::PACKET_COMPLETE_LINEAGE_FEATURE,
                    )?,
                    Id::new(super::super::super::super::input::PACKET_INPUT_FEATURE)?,
                ];
                let mut envelope_extensions = std::collections::BTreeMap::from([(
                    super::super::super::super::input::PACKET_INPUT_FEATURE.into(),
                    Id::new(super::super::super::super::input::PACKET_INPUT_FEATURE)?,
                )]);
                if self.launch.confirmation_selection.is_some() {
                    selected.push(Id::new(
                        super::super::super::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE,
                    )?);
                    envelope_extensions.insert(
                        super::super::super::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION
                        .into(),
                        Id::new(
                            super::super::super::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE,
                        )?,
                    );
                }
                if self.launch.ack_emitter_selection.is_some() {
                    selected.push(Id::new(
                        super::super::super::ack_emitter::PACKET_NATIVE_CANONICAL_ACK_FEATURE,
                    )?);
                    selected.push(Id::new(
                        super::super::super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
                    )?);
                    envelope_extensions.insert(
                        super::super::super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE.into(),
                        Id::new(
                            super::super::super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
                        )?,
                    );
                }
                if self.launch.complete_restore_selection.is_some() {
                    for key in [
                        super::super::super::complete_restore::PACKET_COMPLETE_RESTORE_FEATURE,
                        super::super::super::complete_restore::PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
                        super::super::super::complete_restore::PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
                    ] {
                        selected.push(Id::new(key)?);
                        envelope_extensions.insert(key.into(), Id::new(key)?);
                    }
                }
                if self.launch.complete_restore_selection == Some(
                    super::super::super::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                {
                    use super::super::super::complete_restore::{*, transfer::*};
                    selected.push(Id::new(PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE)?);
                    selected.push(Id::new(PACKET_NATIVE_RESTORED_RECORD_FEATURE)?);
                    for phase in [PacketCompleteRestoreTransferPhase::Prepare, PacketCompleteRestoreTransferPhase::Commit] {
                        for key in [phase.request_extension(), phase.proof_extension(), phase.receipt_extension()] {
                            selected.push(Id::new(key)?);
                            envelope_extensions.insert(key.into(), Id::new(key)?);
                        }
                    }
                }
                if self.boot.is_some() {
                    selected.push(Id::new(EXTENSION_NEGOTIATION_V1)?);
                    envelope_extensions.insert(
                        EXTENSION_NEGOTIATION_V1.into(),
                        Id::new(EXTENSION_NEGOTIATION_V1)?,
                    );
                }
                (selected, envelope_extensions)
            };
            selected.sort();
            let binding = &self.launch.selection.realization.bindings[0];
            let mut token = [0; 32];
            token.copy_from_slice(self.launch.admission_token.as_slice());
            self.handshake = Some(Handshake::new(
                TrustedInstallation {
                    session_id: binding.authority.session_id.clone(),
                    incarnation_id: binding.authority.incarnation_id.clone(),
                    measured_implementation: self.launch.selection.provider.implementation.clone(),
                    launch_receipt: self.launch.selection.admission_receipt.clone(),
                    admission_token: token,
                },
                NegotiationPolicy {
                    supported_features: selected.clone(),
                    required_features: selected.clone(),
                    provider_limits: self.launch.limits,
                    required_schemas: Vec::new(),
                    required_guarantees: binding.compatibility.guarantees_ref.clone(),
                    envelope_extension_features: envelope_extensions,
                },
            )?);
            let mut nonce = vec![0; 32];
            std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut nonce)?;
            let result = HelloResult {
                version: "CNP/1".into(),
                session_id: binding.authority.session_id.clone(),
                incarnation_id: binding.authority.incarnation_id.clone(),
                controller_nonce: hello_request.controller_nonce.clone(),
                provider_nonce: Bytes::new(nonce),
                selected_features: selected.clone(),
                limits: self.launch.limits.intersection(hello_request.limits)?,
                resume_token: Nullable(None),
                provider_identity: self.launch.selection.provider.clone(),
                resumed_operations: Vec::new(),
            };
            let mut response = request.clone();
            response.message = MessageKind::Response;
            response.incarnation_id = Nullable(Some(binding.authority.incarnation_id.clone()));
            response.body = body(ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: body(&result)?,
                extensions: Extensions::new(),
            })?;
            self.cut.ensure_current()?;
            if self.boot.is_some() {
                response.extensions.insert(
                    EXTENSION_NEGOTIATION_V1.into(),
                    serde_json::to_value(ExtensionSelectionV1 {
                        format: U64::new(1),
                        selected: Vec::new(),
                    })
                    .map_err(ContractError::from)?,
                );
                self.selected_registry = Some(Rc::new(EmptyBootExtensions));
                self.selected_handshake = Some(ExtensionHandshake::from_original_empty_retained(
                    &mut self.handshake,
                    self.selected_registry.as_ref().ok_or_else(absent)?,
                )?);
            }
            self.authority = Some(if let Some(handshake) = self.selected_handshake.as_mut() {
                handshake.admit_original_envelopes(
                    &request,
                    &response,
                    &hello_request,
                    &result,
                    Id::new("packet-native5-original-connection")?,
                    &mut CompleteVerifier {
                        launch: &self.launch,
                        selected: &selected,
                    },
                )?
            } else {
                self.handshake
                    .as_mut()
                    .ok_or_else(absent)?
                    .admit_original_envelopes(
                        &request,
                        &response,
                        &hello_request,
                        &result,
                        Id::new("packet-native5-original-connection")?,
                        &mut CompleteVerifier {
                            launch: &self.launch,
                            selected: &selected,
                        },
                    )?
            });
            // Their complete body/identity/feature/registry guards have finished;
            // publication needs the encoded response, not independent typed claims.
            drop(hello_request);
            drop(result);
            self.cut.ensure_current()?;
            self.exchange
                .as_mut()
                .ok_or_else(absent)?
                .publish(&serde_json::to_value(&response).map_err(ContractError::from)?)?;
        }
        let policy = if let Some(restoration) = self.launch.complete_restore_selection {
            Native5Policy::from_original_launch_with_complete_restore(
                self.launch.selection.clone(),
                self.launch.initial_coordinator.clone(),
                self.launch.capture_profile.clone(),
                self.launch.confirmation_selection.ok_or_else(absent)?,
                self.launch.ack_emitter_selection.ok_or_else(absent)?,
                self.launch
                    .native_codec_metadata_extent
                    .ok_or_else(absent)?,
                self.launch.protocol_metadata_limits.ok_or_else(absent)?,
                restoration,
            )?
            .with_restore_input_emitter_selection(self.launch.restore_input_emitter_selection)?
        } else if let Some(metadata) = self.launch.protocol_metadata_limits {
            Native5Policy::from_original_launch_with_protocol_metadata(
                self.launch.selection.clone(),
                self.launch.initial_coordinator.clone(),
                self.launch.capture_profile.clone(),
                self.launch
                    .confirmation_selection
                    .ok_or(ProviderError::Correlation(
                        "owned native confirmation absent",
                    ))?,
                self.launch
                    .ack_emitter_selection
                    .ok_or(ProviderError::Correlation("owned native ACK absent"))?,
                self.launch
                    .native_codec_metadata_extent
                    .ok_or(ProviderError::Correlation(
                        "owned native codec extent absent",
                    ))?,
                metadata,
            )?
        } else if let Some(emitter) = self.launch.ack_emitter_selection {
            let confirmation =
                self.launch
                    .confirmation_selection
                    .ok_or(ProviderError::Correlation(
                        "native5 ACK confirmation absent",
                    ))?;
            if let Some(extent) = self.launch.native_codec_metadata_extent {
                Native5Policy::from_original_launch_with_ack_emitter_metadata_extent(
                    self.launch.selection.clone(),
                    self.launch.initial_coordinator.clone(),
                    self.launch.capture_profile.clone(),
                    confirmation,
                    emitter,
                    extent,
                )?
            } else {
                Native5Policy::from_original_launch_with_ack_emitter(
                    self.launch.selection.clone(),
                    self.launch.initial_coordinator.clone(),
                    self.launch.capture_profile.clone(),
                    confirmation,
                    emitter,
                )?
            }
        } else if let Some(confirmation) = self.launch.confirmation_selection {
            Native5Policy::from_original_launch_with_confirmation(
                self.launch.selection.clone(),
                self.launch.initial_coordinator.clone(),
                self.launch.capture_profile.clone(),
                confirmation,
            )?
        } else if self.launch.capture_profile.is_original_arrays() {
            Native5Policy::from_original_launch(
                self.launch.selection.clone(),
                self.launch.initial_coordinator.clone(),
            )?
        } else {
            Native5Policy::from_original_launch_with_profile(
                self.launch.selection.clone(),
                self.launch.initial_coordinator.clone(),
                self.launch.capture_profile.clone(),
            )?
        };
        let policy = policy
            .with_capture_allocation_selection(self.launch.capture_allocation_selection)?
            .with_fresh_restore_allocation_selection(
                self.launch.fresh_restore_allocation_selection,
            )?;
        self.policy = Some(Rc::new(policy));
        if self
            .policy
            .as_ref()
            .ok_or_else(absent)?
            .confirmation_selection()
            != self.launch.confirmation_selection
        {
            return Err(ProviderError::Correlation(
                "native5 original confirmation selection changed",
            ));
        }
        let expected_ack_definition = self
            .launch
            .ack_emitter_selection
            .map(|_| super::super::super::ack_emitter::native_canonical_blob_ack_schema())
            .transpose()?
            .map(|schema| schema.definition);
        let policy = self.policy.as_ref().ok_or_else(absent)?;
        if policy.ack_emitter_selection() != self.launch.ack_emitter_selection
            || policy.ack_emitter_definition() != expected_ack_definition.as_ref()
        {
            return Err(ProviderError::Correlation(
                "native5 original ACK selection changed",
            ));
        }
        let expected_confirmation_definition = self
            .launch
            .confirmation_selection
            .map(|_| super::super::super::confirmation::native_after_confirmation_schema())
            .transpose()?
            .map(|schema| schema.definition);
        if self
            .policy
            .as_ref()
            .ok_or_else(absent)?
            .confirmation_definition()
            != expected_confirmation_definition.as_ref()
        {
            return Err(ProviderError::Correlation(
                "native5 original confirmation definition changed",
            ));
        }
        if self.policy.as_ref().ok_or_else(absent)?.capture_profile()
            != &self.launch.capture_profile
        {
            return Err(ProviderError::Correlation(
                "native5 original capture profile changed",
            ));
        }
        let coordinator = PacketNative5CoordinatorInstallation::decode(
            self.launch.initial_coordinator.bytes.as_slice(),
            &self.launch.selection,
        )?;
        self.cut.ensure_current()?;
        let (stream, journal) = self.exchange.take().ok_or_else(absent)?.into_parts();
        self.hello = Some(journal);
        let (stream, deadline) = match stream.into_control_stream_owned() {
            Ok(pair) => pair,
            Err(failure) => {
                self.bounded_failure = Some(failure);
                return Err(absent());
            }
        };
        self.control_stream = Some(stream);
        self.deadline = Some(deadline);
        let authority = self.authority.take().ok_or_else(absent)?;
        let negotiated = authority.limits();
        self.connection = Some(
            match Connection::new_native5_owned(
                self.control_stream.take().ok_or_else(absent)?,
                authority,
                self.supervisor.as_ref().ok_or_else(absent)?.clone(),
                self.policy.as_ref().ok_or_else(absent)?.clone(),
            ) {
                Ok(connection) => connection,
                Err(failure) => {
                    self.connection_failure = Some(failure);
                    return Err(absent());
                }
            },
        );
        self.cut.ensure_current()?;
        self.connection
            .as_mut()
            .ok_or_else(absent)?
            .install_native5_native_codec(
                &mut self.bank,
                self.policy.as_ref().ok_or_else(absent)?.clone(),
            )?;
        self.effect_socket = Some(UnixDatagram::unbound()?);
        self.effect_socket
            .as_ref()
            .ok_or_else(absent)?
            .connect(&self.launch.effects)?;
        self.cut.ensure_current()?;
        self.native = Some(match &self.launch.program {
            PacketConnectedSourceProgram::Producer { program } => {
                self.producer = Some(
                    match PacketProgram::new_retained(
                        program.events.clone(),
                        self.effect_socket.take().ok_or_else(absent)?,
                    ) {
                        Ok(original) => original,
                        Err(failure) => {
                            self.producer_model_failure = Some(failure);
                            return Err(absent());
                        }
                    },
                );
                match PacketControl::new_complete_producer_retained(
                    self.launch.selection.clone(),
                    self.producer.take().ok_or_else(absent)?,
                    coordinator,
                ) {
                    Ok(native) => native,
                    Err(failure) => {
                        self.producer_failure = Some(failure);
                        return Err(absent());
                    }
                }
            }
            PacketConnectedSourceProgram::Reactive { program } => {
                self.reactive = Some(
                    match PacketConnectedProgram::new_retained(
                        program.clone(),
                        self.effect_socket.take().ok_or_else(absent)?,
                    ) {
                        Ok(original) => original,
                        Err(failure) => {
                            self.reactive_model_failure = Some(failure);
                            return Err(absent());
                        }
                    },
                );
                match PacketControl::new_complete_reactive_retained(
                    self.launch.selection.clone(),
                    self.reactive.take().ok_or_else(absent)?,
                    coordinator,
                ) {
                    Ok(native) => native,
                    Err(failure) => {
                        self.reactive_failure = Some(failure);
                        return Err(absent());
                    }
                }
            }
        });
        self.native
            .as_mut()
            .ok_or_else(absent)?
            .bind_complete_original_storage(self.launch.storage.clone(), negotiated)?;
        self.native
            .as_mut()
            .ok_or_else(absent)?
            .bind_complete_original_capture_profile(self.launch.capture_profile.clone())?;
        if let Some(confirmation) = self.launch.confirmation_selection {
            self.native
                .as_mut()
                .ok_or_else(absent)?
                .bind_complete_original_confirmation_selection(confirmation)?;
        }
        if let Some(emitter) = self.launch.ack_emitter_selection {
            self.native
                .as_mut()
                .ok_or_else(absent)?
                .bind_complete_original_ack_emitter_selection(emitter)?;
        }
        if let Some(metadata) = self.launch.protocol_metadata_limits {
            self.native
                .as_mut()
                .ok_or_else(absent)?
                .bind_complete_original_protocol_metadata_limits(metadata)?;
        }
        if let Some(restoration) = self.launch.complete_restore_selection {
            self.native
                .as_mut()
                .ok_or_else(absent)?
                .bind_complete_original_restore_selection(restoration)?;
        }
        if let Some(emitter) = self.launch.restore_input_emitter_selection {
            self.native
                .as_mut()
                .ok_or_else(absent)?
                .bind_complete_original_restore_input_emitter_selection(emitter)?;
        }
        if let Some(selection) = self.launch.capture_allocation_selection {
            self.native
                .as_mut()
                .ok_or_else(absent)?
                .bind_complete_original_capture_allocation_selection(selection)?;
        }
        self.native
            .as_ref()
            .ok_or_else(absent)?
            .authenticate_complete_capture_allocation_selection(
                self.launch.capture_allocation_selection,
            )?;
        self.cut.ensure_current()?;
        self.endpoint = Some(
            match super::super::super::super::endpoint::PacketEndpoint::new_complete(
                self.connection.take().ok_or_else(absent)?,
                self.native.take().ok_or_else(absent)?,
                self.policy.as_ref().ok_or_else(absent)?.clone(),
                self.supervisor.as_ref().ok_or_else(absent)?.clone(),
                self.launch.storage.clone(),
                self.hello.take().ok_or_else(absent)?,
            ) {
                Ok(endpoint) => endpoint,
                Err(failure) => {
                    self.endpoint_failure = Some(failure);
                    return Err(absent());
                }
            },
        );
        if let Some(boot) = self.boot.as_ref() {
            self.endpoint
                .as_mut()
                .ok_or_else(absent)?
                .bind_original_canonical_ack_boot(
                    Rc::clone(boot),
                    Rc::clone(self.policy.as_ref().ok_or_else(absent)?),
                )?;
        }
        // The successful endpoint remains owned if the constructor consumed the
        // original birth period or any required phase owner is unavailable.
        self.cut.ensure_current()?;
        let supervisor = self.supervisor.as_ref().ok_or_else(absent)?.clone();
        let handshake = match (
            self.handshake.take(),
            self.selected_handshake.take(),
            self.selected_registry.take(),
        ) {
            (Some(handshake), None, None) => Some(
                super::super::super::OriginalServiceHandshake::Legacy(handshake),
            ),
            (None, Some(handshake), Some(registry)) => {
                Some(super::super::super::OriginalServiceHandshake::Selected {
                    handshake,
                    registry,
                })
            }
            (legacy, selected, registry) => {
                self.handshake = legacy;
                self.selected_handshake = selected;
                self.selected_registry = registry;
                None
            }
        };
        match (self.endpoint.take(), handshake, self.deadline.take()) {
            (Some(endpoint), Some(handshake), Some(deadline)) => Ok(PacketSourceService {
                endpoint,
                _handshake: handshake,
                _private_bootstrap: None,
                _supervisor: supervisor,
                deadline,
            }),
            (endpoint, handshake, deadline) => {
                self.endpoint = endpoint;
                match handshake {
                    Some(super::super::super::OriginalServiceHandshake::Legacy(h)) => {
                        self.handshake = Some(h)
                    }
                    Some(super::super::super::OriginalServiceHandshake::Selected {
                        handshake,
                        registry,
                    }) => {
                        self.selected_handshake = Some(handshake);
                        self.selected_registry = Some(registry);
                    }
                    None => {}
                }
                self.deadline = deadline;
                Err(absent())
            }
        }
    }
}

fn absent() -> ProviderError {
    ProviderError::Correlation("native5 retained original birth phase refused")
}

// This protocol milestone installs no unregistered extension declaration.
// A nonempty peer roster refuses rather than becoming trusted planning data.
pub(in crate::reference_packet::service) struct EmptyBootExtensions;

impl crate::handshake::OriginalEmptyExtensionRegistry for EmptyBootExtensions {}

impl InstalledExtensionNegotiationVerifier for EmptyBootExtensions {
    fn supported(&self) -> &[ExtensionSelection] {
        &[]
    }
    fn required(&self) -> &[ExtensionSelection] {
        &[]
    }
    fn verify_selection(
        &self,
        selected: &[ExtensionSelection],
        _: &IdSet,
    ) -> Result<(), ProviderError> {
        if selected.is_empty() {
            Ok(())
        } else {
            Err(ProviderError::Correlation(
                "native boot typed declaration not installed",
            ))
        }
    }
}

// Each payload is an actual original failure/custody owner above. They are
// conservatively summed even though successful transfer makes phases exclusive.
pub(in crate::reference_packet::service) fn original_native_birth_phase_layout_bytes()
-> Result<usize, ProviderError> {
    [
        std::mem::size_of::<CompleteBirth>(),
        std::mem::size_of::<PacketSourceService>(),
        std::mem::size_of::<crate::client::OriginalNative5BirthStreamRefusal>(),
        std::mem::size_of::<
            crate::native_hello::OriginalNativeHelloBindRefusal<OriginalNative5BirthStream>,
        >(),
        std::mem::size_of::<Native5ConnectionBirthRefusal<DeadlineStream>>(),
        std::mem::size_of::<
            super::super::super::super::endpoint::PacketCompleteEndpointRefusal<DeadlineStream>,
        >(),
        std::mem::size_of::<crate::client::ExchangeDeadline>(),
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| {
        total
            .checked_add(bytes)
            .ok_or(ProviderError::ResourceExhausted(
                "native birth phase headers",
            ))
    })
}

// This roster is specific to the actual original CompleteBirth constructors:
// two independent frame-bank Rcs (control and Hello), native policy and sealed
// codec, connection actor, Control identity, shared deadline and empty registry.
// The existing private-bootstrap bank is charged by its separate phase.
pub(in crate::reference_packet::service) fn original_native_birth_shared_layout_bytes()
-> Result<usize, ProviderError> {
    fn shared<T>() -> Result<usize, ProviderError> {
        std::mem::size_of::<T>()
            .checked_add(
                crate::retained_metadata::requested_storage::shared_header_storage_data(
                    1,
                    std::mem::align_of::<T>(),
                )?,
            )
            .ok_or(ProviderError::ResourceExhausted(
                "native shared birth header",
            ))
    }
    let terms = [
        shared::<std::cell::RefCell<OriginalFrameReservation>>()?,
        shared::<std::cell::RefCell<OriginalFrameReservation>>()?,
        shared::<std::cell::RefCell<super::super::super::ack_emitter::NativeAckBoot>>()?,
        shared::<Native5Policy>()?,
        shared::<crate::connection::Native5CodecOwner>()?,
        shared::<crate::protocol_snapshot::ProtocolCaptureOwner>()?,
        shared::<()>()?,
        shared::<std::cell::Cell<crate::operational_time::OperationalDeadline>>()?,
        crate::client::OriginalNative5BirthCut::original_requested_layout_data()?,
        shared::<EmptyBootExtensions>()?,
        shared::<std::sync::atomic::AtomicU64>()?,
        shared::<std::sync::Mutex<()>>()?,
        // The selected empty extension roster retains its real Arc allocation.
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            std::mem::align_of::<crucible_node_format::ExtensionSelection>(),
        )?,
        shared::<Supervisor>()?,
        // Supervisor::new reserves one incident and one blob quarantine slot.
        // The selected original driver stops/holds on the first failure. These
        // are actual inline Vec payload slots, not claims that failures are empty.
        std::mem::size_of::<crate::connection::ConnectionIncident>(),
        std::mem::size_of::<crate::blob::BlobQuarantine>(),
        crate::blob::BlobReceiver::original_empty_shared_requested_storage_data()?,
    ];
    terms.into_iter().try_fold(0usize, |sum, term| {
        sum.checked_add(term)
            .ok_or(ProviderError::ResourceExhausted(
                "native shared birth roster",
            ))
    })
}
