//! Authenticates a genuine native-five birth before installing its immutable codec.

use super::super::{Native5Policy, PacketNative5SourceLaunch};
use super::*;
use crate::{
    native_hello::OriginalNativeHelloJournal, transport::original_frames::OriginalFrameReservation,
};

pub(in super::super) fn accept_complete(
    socket: &Path,
    launch: PacketNative5SourceLaunch,
) -> Result<PacketSourceService, ProviderError> {
    launch.validate()?;
    let hello = OriginalNativeHelloJournal::reserve(65_536, 64)?;
    if hello.allocated_bytes()
        > usize::try_from(launch.storage.hello_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("native5 Hello storage"))?
    {
        return Err(ProviderError::ResourceExhausted(
            "native5 actual Hello allocation",
        ));
    }
    let mut bank = Some(OriginalFrameReservation::reserve(
        usize::try_from(launch.storage.frame_bank_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("native5 bank bytes"))?,
        usize::try_from(launch.storage.frames_per_direction.get())
            .map_err(|_| ProviderError::ResourceExhausted("native5 frame descriptors"))?,
    )?);
    private_parent(socket)?;
    private_parent(&launch.effects)?;
    let effects = fs::symlink_metadata(&launch.effects)?;
    if !effects.file_type().is_socket() || effects.uid() != rustix::process::geteuid().as_raw() {
        return Err(ProviderError::Correlation(
            "native5 effect receiver ownership",
        ));
    }
    let executable = crate::conformance::measure_executable(&std::env::current_exe()?)?;
    if !launch
        .selection
        .provider
        .implementation
        .artifacts
        .iter()
        .any(|artifact| artifact.role.as_str() == "executable" && artifact.content == executable)
    {
        return Err(ProviderError::Correlation(
            "native5 provider executable differs",
        ));
    }
    let supervisor = Rc::new(Supervisor::new()?);
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let (stream, _) = listener.accept()?;
    let credentials =
        rustix::net::sockopt::socket_peercred(&stream).map_err(std::io::Error::from)?;
    if u64::from(credentials.uid.as_raw()) != launch.controller_uid.get()
        || credentials.pid.as_raw_nonzero().get() as u64 != launch.controller_pid.get()
    {
        return Err(ProviderError::Correlation(
            "native5 original controller kernel identity",
        ));
    }
    let peer = Path::new("/proc")
        .join(launch.controller_pid.get().to_string())
        .join("exe");
    if crate::conformance::measure_executable(&peer)? != launch.controller_executable {
        return Err(ProviderError::Correlation(
            "native5 original controller executable",
        ));
    }
    let (stream, deadline) = DeadlineStream::new(stream, Duration::from_secs(5))?;
    let mut exchange = hello.bind(stream)?;
    let value = exchange
        .receive()?
        .ok_or(ProviderError::Frame("native5 original Hello missing"))?;
    let request = Envelope::decode(&canonical::canonical_json(&value)?, 65_536)?;
    let RequestBody::Hello(hello_request) = decode_request(request.method, &request.body)? else {
        return Err(ProviderError::Frame(
            "native5 original initial frame is not Hello",
        ));
    };
    let selected = vec![
        Id::new("cnp.control-evidence/1")?,
        Id::new("cnp.core/1")?,
        Id::new(super::super::super::continuation_contracts::PACKET_COMPLETE_LINEAGE_FEATURE)?,
        Id::new(super::super::super::input::PACKET_INPUT_FEATURE)?,
    ];
    let binding = &launch.selection.realization.bindings[0];
    let mut token = [0; 32];
    token.copy_from_slice(launch.admission_token.as_slice());
    let mut handshake = Handshake::new(
        TrustedInstallation {
            session_id: binding.authority.session_id.clone(),
            incarnation_id: binding.authority.incarnation_id.clone(),
            measured_implementation: launch.selection.provider.implementation.clone(),
            launch_receipt: launch.selection.admission_receipt.clone(),
            admission_token: token,
        },
        NegotiationPolicy {
            supported_features: selected.clone(),
            required_features: selected.clone(),
            provider_limits: launch.limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref.clone(),
            envelope_extension_features: std::collections::BTreeMap::from([(
                super::super::super::input::PACKET_INPUT_FEATURE.into(),
                Id::new(super::super::super::input::PACKET_INPUT_FEATURE)?,
            )]),
        },
    )?;
    let mut nonce = vec![0; 32];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut nonce)?;
    let result = HelloResult {
        version: "CNP/1".into(),
        session_id: binding.authority.session_id.clone(),
        incarnation_id: binding.authority.incarnation_id.clone(),
        controller_nonce: hello_request.controller_nonce,
        provider_nonce: Bytes::new(nonce),
        selected_features: selected.clone(),
        limits: launch.limits.intersection(hello_request.limits)?,
        resume_token: Nullable(None),
        provider_identity: launch.selection.provider.clone(),
        resumed_operations: Vec::new(),
    };
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.incarnation_id = Nullable(Some(binding.authority.incarnation_id.clone()));
    response.body = body(ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: body(result)?,
        extensions: Extensions::new(),
    })?;
    let authority = handshake.admit_envelopes(
        &request,
        &response,
        Id::new("packet-native5-original-connection")?,
        &mut CompleteVerifier {
            launch: &launch,
            selected: &selected,
        },
    )?;
    exchange.publish(&serde_json::to_value(&response).map_err(ContractError::from)?)?;
    let (stream, hello) = exchange.into_parts();
    let policy = Rc::new(Native5Policy::from_original_launch(
        launch.selection.clone(),
        launch.initial_coordinator.clone(),
    )?);
    let coordinator =
        super::super::super::coordinator::PacketNative5CoordinatorInstallation::decode(
            launch.initial_coordinator.bytes.as_slice(),
            &launch.selection,
        )?;
    let negotiated_limits = authority.limits();
    let mut connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        policy.clone(),
        EndpointRole::Provider,
    )?;
    connection.install_native5_native_codec(&mut bank, policy.clone())?;
    let effect_socket = UnixDatagram::unbound()?;
    effect_socket.connect(&launch.effects)?;
    let mut native = match launch.program {
        PacketConnectedSourceProgram::Producer { program } => PacketControl::new_complete_producer(
            launch.selection,
            PacketProgram::new(program.events, effect_socket)?,
            coordinator,
        )?,
        PacketConnectedSourceProgram::Reactive { program } => PacketControl::new_complete_reactive(
            launch.selection,
            super::super::super::connected::PacketConnectedProgram::new(program, effect_socket)?,
            coordinator,
        )?,
    };
    native.bind_complete_original_storage(launch.storage.clone(), negotiated_limits)?;
    let endpoint = match super::super::super::endpoint::PacketEndpoint::new_complete(
        connection,
        native,
        policy,
        supervisor.clone(),
        launch.storage,
        hello,
    ) {
        Ok(endpoint) => endpoint,
        Err(mut failure) => {
            // Hello has already completed. Retain the SAME failed native,
            // connection, literal Hello and every prepared bank until its
            // original host supervisor performs actual kernel reclamation.
            let containment = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                failure.contain_original()
            }));
            let original = (failure, handshake, deadline, supervisor, containment);
            loop {
                std::hint::black_box(&original);
                std::thread::park();
            }
        }
    };
    Ok(PacketSourceService {
        endpoint,
        _handshake: handshake,
        _supervisor: supervisor,
        deadline,
    })
}

struct CompleteVerifier<'a> {
    launch: &'a PacketNative5SourceLaunch,
    selected: &'a IdSet,
}

impl TrustedHandshakeVerifier for CompleteVerifier<'_> {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installation: &TrustedInstallation,
        _: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if installation.measured_implementation != self.launch.selection.provider.implementation
            || result.provider_identity != self.launch.selection.provider
        {
            return Err(ProviderError::Correlation(
                "native5 actual handshake implementation",
            ));
        }
        Ok(())
    }
    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        features: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        if manifest != &self.launch.selection.provider
            || features != self.selected
            || !schemas.is_empty()
            || guarantees
                != &self.launch.selection.realization.bindings[0]
                    .compatibility
                    .guarantees_ref
        {
            return Err(ProviderError::Correlation(
                "native5 actual handshake contract",
            ));
        }
        Ok(())
    }
    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        _: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        Err(ProviderError::Correlation(
            "native5 resume requires distinct original restoration",
        ))
    }
    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "native5 original connection cannot be substituted",
        ))
    }
}
