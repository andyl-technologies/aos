//! Launches the measured public provider under original pre-reserved custody.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    os::unix::{fs::DirBuilderExt, net::UnixStream, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
    time::Duration,
};

use crucible::{
    node_adapters::cnp::{CnpLaunchGuard, CnpReferencePreparation},
    node_contract::{ActivationRecord, OwnerIdentity},
};
use crucible_node_contract::{Bytes, ContentRef, Extensions, Id, U64, canonical};
use crucible_node_provider::{
    ProviderError,
    client::{
        ClientContent, ClientCustody, ClientPeer, ClientSession, ObservationHandle,
        ObservationLimits, ReferenceController,
    },
    connection::{BodySchemaVerifier, ConnectionIncident, ConnectionSupervisor, ReceivedBody},
    envelope::{Envelope, MessageKind, Method, Nullable},
    handshake::{
        ConnectionAuthority, Handshake, HelloRequest, NegotiationPolicy, TrustedInstallation,
    },
    reference_service::{PublicReferenceProfile, ReferenceServiceInstalledLaunchBootstrap},
    transport::write_frame,
};

use crate::supervision::ProcessDeadline;

use super::{
    custody::{PublicPeerScope, PublicReferenceCustodyQueue},
    installation::SourcePublicReferenceInstallation,
};

pub(super) struct PublicLaunchRequest {
    pub(super) directory: PathBuf,
    pub(super) activation: ActivationRecord,
    pub(super) owner: OwnerIdentity,
    pub(super) source_roots: Vec<ContentRef>,
    pub(super) closed_ingress: bool,
    pub(super) hello_id: Id,
    pub(super) connection_id: Id,
    pub(super) controller_nonce: Bytes,
    pub(super) observation_limits: ObservationLimits,
    pub(super) observation_sink: Rc<RefCell<Option<ObservationHandle>>>,
}

pub(super) struct ObservedPublicPreparation {
    pub(super) prepared: CnpReferencePreparation,
    pub(super) observations: ObservationHandle,
    pub(super) probe: serde_json::Value,
}

/// Keeps the one original connection's uncertainty in its native reservation.
struct IncidentCustody(Rc<RefCell<Option<ConnectionIncident>>>);

impl ConnectionSupervisor for IncidentCustody {
    fn quarantine(&self, incident: ConnectionIncident) {
        // A private instance is supplied to exactly one Connection. Its source
        // implementation fences before calling this hook, including Drop; the
        // constructor's refusal cannot coexist with a constructed connection.
        *self.0.borrow_mut() = Some(incident);
    }
}

struct InstalledSchemas;

impl BodySchemaVerifier for InstalledSchemas {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        envelope: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if !envelope.extensions.is_empty()
            || envelope
                .body
                .get("extensions")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|extensions| !extensions.is_empty())
        {
            return Err(ProviderError::Frame(
                "public reference selected an unsupported extension",
            ));
        }
        Ok(())
    }
}

/// Performs native preparation, leaving every failure in the original queue.
///
/// This does not arm, publish a world or discharge the qualification ledger.
pub(super) fn launch(
    installed: &mut SourcePublicReferenceInstallation,
    queue: &PublicReferenceCustodyQueue,
    request: PublicLaunchRequest,
) -> Result<ObservedPublicPreparation, ProviderError> {
    if request.observation_sink.borrow().is_some() {
        return Err(ProviderError::Correlation(
            "original observation slot already occupied",
        ));
    }
    let probe_plan = super::source_probe::SourceProbePlan::build(installed)?;
    let provider = installed
        .package
        .executable("provider")
        .map_err(package_error)?
        .to_path_buf();
    let device = installed
        .package
        .executable("device")
        .map_err(package_error)?
        .to_path_buf();
    let bootstrap = installed.bootstrap.clone();
    if request.owner.owner != bootstrap.owner_id
        || request.owner.incarnation != bootstrap.authority.incarnation_id
        || request.owner.generation != bootstrap.authority.owner_generation
        || request.activation.generation != bootstrap.world_generation
        || request.activation.activation_id != bootstrap.activation_id
        || request.activation.world_binding_hash != bootstrap.world_binding_hash
        || request.controller_nonce.as_slice().len() != 32
        || bootstrap.controller_uid.get() != u64::from(rustix::process::geteuid().as_raw())
    {
        return Err(ProviderError::Correlation(
            "public launch differs from original host reservation",
        ));
    }
    let launch = ReferenceServiceInstalledLaunchBootstrap {
        schema_version: 3,
        profile: PublicReferenceProfile::ByteLinkedV1 {
            closed_ingress: request.closed_ingress,
        },
        bootstrap: bootstrap.clone(),
        qualification_refs: installed.qualifications.clone(),
    };
    let private_launch = canonical::canonical_json(
        &serde_json::to_value(launch).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let features = super::unit::required_features()?;
    let hello_body = HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: bootstrap.authority.session_id.clone(),
        controller_nonce: request.controller_nonce,
        required_features: features.clone(),
        optional_features: Vec::new(),
        limits: bootstrap.limits,
        admission_token: bootstrap.admission_token.clone(),
        resume_session: None,
        extensions: Extensions::new(),
    };
    let hello = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(None),
        incarnation_id: Nullable(None),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(request.hello_id)),
        sequence: U64::new(1),
        method: Method::Hello,
        body: serde_json::to_value(hello_body)
            .map_err(crucible_node_contract::ContractError::from)?
            .as_object()
            .cloned()
            .ok_or(ProviderError::Frame("public hello body is not an object"))?,
        extensions: Extensions::new(),
    };
    let original_hello = canonical::canonical_json(
        &serde_json::to_value(&hello).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let socket = request.directory.join("control.sock");
    if socket.as_os_str().len() > 100 || !request.directory.is_absolute() {
        return Err(ProviderError::ResourceExhausted(
            "private public socket path geometry",
        ));
    }
    let incidents = Rc::new(RefCell::new(None));
    let slot = queue.reserve(PublicPeerScope {
        activation: request.activation,
        owner: request.owner,
        implementation: installed.package.identity().clone(),
        source_roots: request.source_roots,
        publication: None,
        connection_incident: incidents.clone(),
        private_launch,
        original_hello,
    })?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&request.directory)?;

    let mut child = Command::new(provider)
        .arg(&socket)
        .arg(device)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let stdin = child.stdin.take();
    // From this point every return and unwind transfers the same Child and
    // native group to the pre-reserved owning actor slot.
    let mut guard =
        CnpLaunchGuard::new(child, request.directory, slot).map_err(|failure| failure.error)?;
    let mut stdin = stdin.ok_or(ProviderError::Correlation(
        "original private launch pipe absent",
    ))?;
    write_frame(
        &mut stdin,
        &serde_json::to_value(ReferenceServiceInstalledLaunchBootstrap {
            schema_version: 3,
            profile: PublicReferenceProfile::ByteLinkedV1 {
                closed_ingress: request.closed_ingress,
            },
            bootstrap: bootstrap.clone(),
            qualification_refs: installed.qualifications.clone(),
        })
        .map_err(crucible_node_contract::ContractError::from)?,
        16 * 1024 * 1024,
    )?;
    drop(stdin);
    let deadline = ProcessDeadline::after(Duration::from_secs(3)).ok_or(
        ProviderError::ResourceExhausted("private public connection deadline"),
    )?;
    let stream = loop {
        match UnixStream::connect(&socket) {
            Ok(stream) => break stream,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) && !deadline.expired() =>
            {
                deadline.pause(Duration::from_millis(1))
            }
            Err(error) => return Err(error.into()),
        }
    };
    let (binding, _) = installed
        .profile
        .bind_qualified(bootstrap.authority.clone(), &installed.qualifications)?;
    let mut token = [0; 32];
    token.copy_from_slice(bootstrap.admission_token.as_slice());
    let mut handshake = Handshake::new(
        TrustedInstallation {
            session_id: bootstrap.authority.session_id.clone(),
            incarnation_id: bootstrap.authority.incarnation_id.clone(),
            measured_implementation: installed.profile.implementation.clone(),
            launch_receipt: bootstrap.admission_receipt.clone(),
            admission_token: token,
        },
        NegotiationPolicy {
            supported_features: features.clone(),
            required_features: features,
            provider_limits: bootstrap.limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref,
            envelope_extension_features: BTreeMap::new(),
        },
    )?;
    let peer = ClientPeer {
        pid: guard
            .provider_pid()
            .ok_or(ProviderError::Correlation("actual public provider absent"))?,
        uid: rustix::process::geteuid().as_raw(),
        executable: installed
            .package
            .artifact_content("provider")
            .map_err(package_error)?
            .clone(),
    };
    let session = ClientSession::negotiate(
        stream,
        &peer,
        &hello,
        request.connection_id,
        &mut handshake,
        installed,
        Rc::new(IncidentCustody(incidents)),
        Rc::new(InstalledSchemas),
        Duration::from_secs(3),
        1_048_576,
        64,
    )?;
    let mut controller = ReferenceController::new_qualified(
        installed.profile.clone(),
        bootstrap,
        session,
        ClientCustody::new(256, ClientContent::new(16 * 1024 * 1024, 256, 16_384)?)?,
        Duration::from_secs(3),
        installed.qualifications.clone(),
    )?;
    let observations = controller.observe(request.observation_limits)?;
    *request.observation_sink.borrow_mut() = Some(observations.clone());
    guard.attach(controller, handshake)?;
    let (probe, original_snapshot) =
        super::source_probe_execution::collect(installed, &mut guard, &probe_plan, &observations)?;
    let probe = serde_json::json!({"premises":probe,"original_snapshot_bytes":original_snapshot});
    let prepared = CnpReferencePreparation::prepare(guard, installed)
        .map_err(|failure| ProviderError::Io(std::io::Error::other(failure.error.reason)))?;
    Ok(ObservedPublicPreparation {
        prepared,
        observations,
        probe,
    })
}

fn package_error(error: super::super::NodeObservedError) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}
