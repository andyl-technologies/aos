//! Native private socket installation and real original packet construction.

use crucible_node_format::*;
use std::{
    fs,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixDatagram, UnixListener},
    },
    path::Path,
    rc::Rc,
    time::Duration,
};

use super::super::{PacketProgram, control::PacketControl};
use super::{
    PacketConnectedSourceLaunch, PacketConnectedSourceProgram, PacketSourceLaunch,
    PacketSourceService, security::*,
};
use crate::{
    ProviderError,
    bodies::*,
    client::DeadlineStream,
    connection::*,
    envelope::*,
    handshake::*,
    transport::{FrameReader, write_frame},
};

pub(in crate::reference_packet::service) mod complete;
pub(super) use complete::{accept_complete, accept_complete_with_boot};

pub(super) fn accept(
    socket: &Path,
    launch: PacketSourceLaunch,
) -> Result<PacketSourceService, ProviderError> {
    launch.validate()?;
    accept_native(
        socket,
        ServerLaunch {
            schema_version: launch.schema_version,
            selection: launch.selection,
            program: PacketConnectedSourceProgram::Producer {
                program: launch.program,
            },
            controller_pid: launch.controller_pid,
            controller_uid: launch.controller_uid,
            controller_executable: launch.controller_executable,
            admission_token: launch.admission_token,
            initial_coordinator: launch.initial_coordinator,
            limits: launch.limits,
            effects: launch.effects,
        },
    )
}

pub(super) fn accept_connected(
    socket: &Path,
    launch: PacketConnectedSourceLaunch,
) -> Result<PacketSourceService, ProviderError> {
    launch.validate()?;
    accept_native(
        socket,
        ServerLaunch {
            schema_version: launch.schema_version,
            selection: launch.selection,
            program: launch.program,
            controller_pid: launch.controller_pid,
            controller_uid: launch.controller_uid,
            controller_executable: launch.controller_executable,
            admission_token: launch.admission_token,
            initial_coordinator: launch.initial_coordinator,
            limits: launch.limits,
            effects: launch.effects,
        },
    )
}

// Only fully validated private launches reach this internal common lifecycle.
// The selected native interpreter and ingress edition remain independent.
pub(super) struct ServerLaunch {
    pub(super) schema_version: u16,
    pub(super) selection: super::super::control::PacketControlSelection,
    pub(super) program: PacketConnectedSourceProgram,
    pub(super) controller_pid: U64,
    pub(super) controller_uid: U64,
    pub(super) controller_executable: ContentRef,
    pub(super) admission_token: Bytes,
    pub(super) initial_coordinator: crate::reference_service::InstalledContent,
    pub(super) limits: Limits,
    pub(super) effects: std::path::PathBuf,
}

fn accept_native(
    socket: &Path,
    launch: ServerLaunch,
) -> Result<PacketSourceService, ProviderError> {
    private_parent(socket)?;
    private_parent(&launch.effects)?;
    let effects = fs::symlink_metadata(&launch.effects)?;
    if !effects.file_type().is_socket() || effects.uid() != rustix::process::geteuid().as_raw() {
        return Err(ProviderError::Correlation(
            "packet original effect receiver is not privately owned",
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
            "packet actual provider executable differs",
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
            "packet original controller kernel identity differs",
        ));
    }
    let peer = Path::new("/proc")
        .join(launch.controller_pid.get().to_string())
        .join("exe");
    if crate::conformance::measure_executable(&peer)? != launch.controller_executable {
        return Err(ProviderError::Correlation(
            "packet original controller executable differs",
        ));
    }
    let (mut stream, deadline) = DeadlineStream::new(stream, Duration::from_secs(5))?;
    let value = FrameReader::with_limits(&mut stream, 65_536, 64)?
        .read()?
        .ok_or(ProviderError::Frame("packet original Hello missing"))?;
    let request = Envelope::decode(&canonical::canonical_json(&value)?, 65_536)?;
    let RequestBody::Hello(hello) = decode_request(request.method, &request.body)? else {
        return Err(ProviderError::Frame(
            "packet original initial frame is not Hello",
        ));
    };
    let selected = features(launch.schema_version)?;
    let binding =
        launch
            .selection
            .realization
            .bindings
            .first()
            .ok_or(ProviderError::Correlation(
                "packet original owner binding absent",
            ))?;
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
            envelope_extension_features: extensions(launch.schema_version)?,
        },
    )?;
    let mut nonce = vec![0; 32];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut nonce)?;
    let result = HelloResult {
        version: "CNP/1".into(),
        session_id: binding.authority.session_id.clone(),
        incarnation_id: binding.authority.incarnation_id.clone(),
        controller_nonce: hello.controller_nonce,
        provider_nonce: Bytes::new(nonce),
        selected_features: selected,
        limits: launch.limits.intersection(hello.limits)?,
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
        Id::new("packet-original-connection")?,
        &mut Verifier(&launch),
    )?;
    write_frame(
        &mut stream,
        &serde_json::to_value(response).map_err(ContractError::from)?,
        65_536,
    )?;
    let common = if launch.schema_version == 2 {
        Some(
            super::super::coordinator::PacketCoordinatorInstallation::decode(
                launch.initial_coordinator.bytes.as_slice(),
                &launch.selection,
            )?,
        )
    } else {
        None
    };
    let world = if launch.schema_version == 3 {
        Some(
            super::super::coordinator::PacketWorldCoordinatorInstallation::decode(
                launch.initial_coordinator.bytes.as_slice(),
                &launch.selection,
            )?,
        )
    } else {
        None
    };
    let connected = if launch.schema_version == 4 {
        Some(
            super::super::coordinator::PacketConnectedCoordinatorInstallation::decode(
                launch.initial_coordinator.bytes.as_slice(),
                &launch.selection,
            )?,
        )
    } else {
        None
    };
    let ingress = if connected.is_some() {
        super::super::contracts::connected_ingress_contract()?
    } else if world.is_some() {
        super::super::contracts::world_ingress_contract()?
    } else if common.is_some() {
        super::super::contracts::common_ingress_contract()?
    } else {
        super::super::contracts::installed_ingress_contract()?
    };
    let policy = Rc::new(Policy {
        selection: launch.selection.clone(),
        coordinator: launch.initial_coordinator,
        definition: canonical::content_ref(&ingress, "application/json")?,
        common: common.clone(),
        world: world.clone(),
        connected: connected.clone(),
    });
    let mut connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        policy.clone(),
        EndpointRole::Provider,
    )?;
    if launch.schema_version == 4 {
        let owner = launch.selection.realization.owner_bindings.first().ok_or(
            ProviderError::Correlation("packet connected original owner binding absent"),
        )?;
        connection.install_connected_packet_schema(binding, owner)?;
    }
    let effect_socket = UnixDatagram::unbound()?;
    effect_socket.connect(&launch.effects)?;
    let native = match launch.program {
        PacketConnectedSourceProgram::Producer { program } => {
            let program = PacketProgram::new(program.events, effect_socket)?;
            if let Some(connected) = connected {
                PacketControl::new_producer_in_connected_world(
                    launch.selection,
                    program,
                    connected,
                )?
            } else if let Some(world) = world {
                PacketControl::new_world_immediate(launch.selection, program, world)?
            } else {
                let mut native = PacketControl::new_immediate(launch.selection, program)?;
                if let Some(common) = common {
                    native.install_common_coordinator(common)?;
                }
                native
            }
        }
        PacketConnectedSourceProgram::Reactive { program } => {
            let coordinator = connected.ok_or(ProviderError::Correlation(
                "packet reactive source requires original connected coordinator",
            ))?;
            let program =
                super::super::connected::PacketConnectedProgram::new(program, effect_socket)?;
            PacketControl::new_connected_world(launch.selection, program, coordinator)?
        }
    };
    let endpoint = match super::super::endpoint::PacketEndpoint::new(
        connection,
        native,
        policy,
        supervisor.clone(),
    ) {
        Ok(endpoint) => endpoint,
        Err(failure) => {
            // No native callback has run: constructor requires the unopened
            // gate. The caller still owns this original native process itself.
            let (_, _, error) = failure.into_parts();
            return Err(error);
        }
    };
    Ok(PacketSourceService {
        endpoint,
        _handshake: super::OriginalServiceHandshake::Legacy(handshake),
        _private_bootstrap: None,
        _supervisor: supervisor,
        deadline,
    })
}

fn private_parent(path: &Path) -> Result<(), ProviderError> {
    let parent = path
        .parent()
        .ok_or(ProviderError::Frame("packet private parent missing"))?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(ProviderError::Correlation(
            "packet private directory ownership differs",
        ));
    }
    Ok(())
}

fn body(
    value: impl serde::Serialize,
) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
    match serde_json::to_value(value).map_err(ContractError::from)? {
        serde_json::Value::Object(value) => Ok(value),
        _ => Err(ProviderError::Frame("packet source body must be an object")),
    }
}
