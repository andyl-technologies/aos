//! Prepares one ordinary closed reference peer under its original custody.
//!
//! Normal behavioral acceptance precedes Child and wire Admit. Source/native
//! enrollment is separate. This module performs no qualification probes, Arm,
//! world publication, execution, preservation or replacement connection.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    os::unix::{fs::DirBuilderExt, net::UnixStream, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
    time::Duration,
};

use serde::Serialize;

use crucible::{
    node_adapters::cnp::{CnpAcceptedPreparation, CnpLaunchGuard},
    node_contract::{ActivationRecord, OwnerIdentity},
};
use crucible_node_contract::{
    Bytes, ContentRef, Extensions, Id, Phase, Position, U64, Validate, canonical,
};
use crucible_node_provider::{
    ProviderError,
    client::{
        ClientContent, ClientCustody, ClientPeer, ClientSession, ExchangeDeadline,
        OriginalHelloJournal,
    },
    connection::{BodySchemaVerifier, ConnectionIncident, ConnectionSupervisor, ReceivedBody},
    envelope::{Envelope, MessageKind, Method, Nullable},
    handshake::{
        ConnectionAuthority, Handshake, HelloRequest, NegotiationPolicy, TrustedInstallation,
    },
    reference_service::{PublicReferenceProfile, ReferenceServiceInstalledLaunchBootstrap},
};

use crate::node_qualification::{
    AcceptanceLimits, CnpBehavioralAcceptance, InstalledAcceptancePolicy,
};

use super::{
    super::{
        custody::{PublicPeerScope, PublicReferenceCustodyQueue},
        installation::SourcePublicReferenceInstallation,
    },
    negotiation::OriginalReferenceNegotiation,
};

const EXCHANGE_BUDGET: Duration = Duration::from_secs(3);
const FRAME_BYTES: usize = 1024 * 1024;
const CONTENT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Serialize)]
struct PrivateLaunchView<'a> {
    schema_version: u16,
    profile: PublicReferenceProfile,
    bootstrap: &'a crucible_node_provider::reference_service::ReferenceServiceBootstrap,
    qualification_refs: &'a [ContentRef],
}

/// Contains host-private source selection; portable configuration cannot construct it.
pub(super) struct OrdinaryReferenceLaunch {
    pub(super) directory: PathBuf,
    pub(super) birth_currency: Option<super::currency::OriginalBirthCurrency>,
    pub(super) activation: ActivationRecord,
    pub(super) owner: OwnerIdentity,
    pub(super) source_roots: Vec<ContentRef>,
    pub(super) hello_id: Id,
    pub(super) connection_id: Id,
    pub(super) controller_nonce: Bytes,
}

struct OriginalIncident(Rc<RefCell<Option<ConnectionIncident>>>);

impl ConnectionSupervisor for OriginalIncident {
    fn quarantine(&self, incident: ConnectionIncident) {
        *self.0.borrow_mut() = Some(incident);
    }
}

struct ClosedSchemas;

impl BodySchemaVerifier for ClosedSchemas {
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
                "ordinary reference extension unsupported",
            ));
        }
        Ok(())
    }
}

/// Prepares the original peer after exact source and normal class preflight.
///
/// The caller reserves its complete world builder before invoking this function.
/// This additional native slot owns only this original Child and its complete
/// private transport data. It is not another complete-world slot or activation.
///
/// # Errors
/// Refuses foreign singleton scope, missing normal Accepted qualification,
/// exhausted source/transport credit or uncertain original native preparation.
/// Every effectful return retains the original peer in the same native queue.
pub(super) fn prepare(
    installed: &mut SourcePublicReferenceInstallation,
    queue: &PublicReferenceCustodyQueue,
    mut request: OrdinaryReferenceLaunch,
    policy: &dyn InstalledAcceptancePolicy,
    acceptance_limits: AcceptanceLimits,
) -> Result<CnpAcceptedPreparation, ProviderError> {
    preflight(installed, &request, policy, acceptance_limits)?;
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
    let launch = ReferenceServiceInstalledLaunchBootstrap {
        schema_version: 3,
        profile: PublicReferenceProfile::ByteLinkedV1 {
            closed_ingress: true,
        },
        bootstrap: bootstrap.clone(),
        qualification_refs: installed.qualifications.clone(),
    };
    super::geometry::bounded(&launch, CONTENT_BYTES)?;
    let launch_value =
        serde_json::to_value(launch).map_err(crucible_node_contract::ContractError::from)?;
    let private_launch = canonical::canonical_json(&launch_value)?;
    canonical::parse_json_with_depth(&private_launch, CONTENT_BYTES, 64)?;
    let upload =
        super::launch_upload::OriginalLaunchUpload::reserve(&private_launch, CONTENT_BYTES)?;
    let features = super::super::unit::required_features()?;
    let (binding, _) = installed
        .profile
        .bind_qualified(bootstrap.authority.clone(), &installed.qualifications)?;
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
        body: serde_json::to_value(HelloRequest {
            versions: vec!["CNP/1".into()],
            session_id: bootstrap.authority.session_id.clone(),
            controller_nonce: request.controller_nonce,
            required_features: features.clone(),
            optional_features: Vec::new(),
            limits: bootstrap.limits,
            admission_token: bootstrap.admission_token.clone(),
            resume_session: None,
            extensions: Extensions::new(),
        })
        .map_err(crucible_node_contract::ContractError::from)?
        .as_object()
        .cloned()
        .ok_or(ProviderError::Frame("ordinary Hello body is not an object"))?,
        extensions: Extensions::new(),
    };
    let hello_journal = OriginalHelloJournal::reserve(&hello, FRAME_BYTES, 64)?;
    let original_hello = canonical::canonical_json(
        &serde_json::to_value(&hello).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let mut token = [0; 32];
    token.copy_from_slice(bootstrap.admission_token.as_slice());
    let handshake = Handshake::new(
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
    let journal = ClientCustody::new(4096, ClientContent::new(CONTENT_BYTES, 4096, 16_384)?)?;
    let originals = Rc::new(RefCell::new(OriginalReferenceNegotiation::new(
        hello_journal,
        handshake,
        journal,
        upload,
        request
            .birth_currency
            .take()
            .ok_or(ProviderError::Correlation(
                "ordinary original birth currency absent",
            ))?,
    )));
    let incidents = Rc::new(RefCell::new(None));
    let socket = request.directory.join("control.sock");
    let slot = queue.reserve(PublicPeerScope {
        activation: request.activation,
        owner: request.owner,
        implementation: installed.package.identity().clone(),
        source_roots: request.source_roots,
        source_custody: Some(Rc::new(installed.package.retain_original_sources()?)),
        publication: None,
        connection_incident: incidents.clone(),
        private_launch,
        original_hello,
        ordinary_negotiation: Some(originals.clone()),
    })?;
    // The same terminal originals fence the FIRST resource effect, including
    // directory creation. No installed callback lies between this read and birth.
    let mut child = originals.borrow().birth_currency.before_birth(|| {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&request.directory)?;
        Command::new(provider)
            .arg(&socket)
            .arg(device)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(ProviderError::from)
    })?;
    // The already-reserved queue holder owns the original pipe before any
    // fallible guard construction, fcntl, write or Hello callback.
    originals.borrow_mut().upload.stdin = child.stdin.take();
    let mut guard =
        CnpLaunchGuard::new(child, request.directory, slot).map_err(|failure| failure.error)?;
    let deadline = originals.borrow_mut().upload.upload(EXCHANGE_BUDGET)?;
    let stream = connect_original(&socket, &deadline)?;
    let peer = ClientPeer {
        pid: guard
            .provider_pid()
            .ok_or(ProviderError::Correlation("ordinary original Child absent"))?,
        uid: rustix::process::geteuid().as_raw(),
        executable: installed
            .package
            .artifact_content("provider")
            .map_err(package_error)?
            .clone(),
    };
    {
        let mut owned = originals.borrow_mut();
        let OriginalReferenceNegotiation {
            hello: hello_journal,
            handshake,
            session,
            ..
        } = &mut *owned;
        let registrar = handshake.as_mut().ok_or(ProviderError::Correlation(
            "ordinary original registrar absent",
        ))?;
        *session = Some(ClientSession::negotiate_recorded_before(
            stream,
            &peer,
            &hello,
            request.connection_id,
            registrar,
            installed,
            Rc::new(OriginalIncident(incidents)),
            Rc::new(ClosedSchemas),
            deadline,
            FRAME_BYTES,
            64,
            hello_journal,
        )?);
        owned.prepare_controller(
            installed.profile.clone(),
            bootstrap,
            installed.qualifications.clone(),
            EXCHANGE_BUDGET,
        )?;
        owned.attach_original(&mut guard)?;
    }
    let acceptance = CnpBehavioralAcceptance::new(policy, acceptance_limits);
    CnpAcceptedPreparation::prepare(guard, installed, &acceptance)
        .map_err(|failure| ProviderError::Io(std::io::Error::other(failure.error.reason)))
}

fn preflight(
    installed: &SourcePublicReferenceInstallation,
    request: &OrdinaryReferenceLaunch,
    policy: &dyn InstalledAcceptancePolicy,
    limits: AcceptanceLimits,
) -> Result<(), ProviderError> {
    // Bound complete source-owned inputs before constructing launch Values or
    // cloning private credentials. Bytes' own temporary encoding remains bounded
    // by the separately checked installed body inventory below.
    let source_bytes = installed
        .profile
        .content_objects()
        .iter()
        .map(|object| object.bytes.len())
        .chain(
            installed
                .bootstrap
                .installed_content
                .iter()
                .map(|object| object.bytes.as_slice().len()),
        )
        .try_fold(0usize, |total, bytes| total.checked_add(bytes))
        .ok_or(ProviderError::ResourceExhausted(
            "ordinary source body total overflow",
        ))?;
    if source_bytes > CONTENT_BYTES || installed.bootstrap.installed_content.len() > 4096 {
        return Err(ProviderError::ResourceExhausted(
            "ordinary source body inventory credit",
        ));
    }
    super::geometry::bounded(
        &PrivateLaunchView {
            schema_version: 3,
            profile: PublicReferenceProfile::ByteLinkedV1 {
                closed_ingress: true,
            },
            bootstrap: &installed.bootstrap,
            qualification_refs: &installed.qualifications,
        },
        CONTENT_BYTES,
    )?;
    installed
        .bootstrap
        .validate()
        .map_err(ProviderError::from)?;
    request.hello_id.validate()?;
    request.connection_id.validate()?;
    super::geometry::bounded(
        &(
            &request.activation.activation_id,
            &request.activation.world_binding_hash,
            request.activation.generation,
            request.activation.boundary,
            &request.activation.owners,
            &request.owner.owner,
            &request.owner.incarnation,
            request.owner.generation,
            &request.source_roots,
            &request.hello_id,
            &request.connection_id,
        ),
        FRAME_BYTES,
    )?;
    let bootstrap = &installed.bootstrap;
    if request.activation.owners.as_slice() != std::slice::from_ref(&request.owner)
        || request.activation.boundary
            != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
        || request.owner.owner != bootstrap.owner_id
        || request.owner.incarnation != bootstrap.authority.incarnation_id
        || request.owner.generation != bootstrap.authority.owner_generation
        || request.activation.activation_id != bootstrap.activation_id
        || request.activation.generation != bootstrap.world_generation
        || request.activation.world_binding_hash != bootstrap.world_binding_hash
        || request.controller_nonce.as_slice().len() != 32
        || bootstrap.controller_uid.get() != u64::from(rustix::process::geteuid().as_raw())
        || request.source_roots.len() > 64
        || !request.directory.is_absolute()
        || request.directory.join("control.sock").as_os_str().len() > 100
    {
        return Err(ProviderError::Correlation(
            "ordinary closed peer differs from original host scope",
        ));
    }
    let regenerated = installed
        .package
        .profile(
            installed.profile.descriptor.id.clone(),
            installed.profile.owner.id.clone(),
            bootstrap.quantum_ps,
            bootstrap.host_budget_ns,
            true,
        )
        .map_err(package_error)?;
    let (binding, _) =
        regenerated.bind_qualified(bootstrap.authority.clone(), &installed.qualifications)?;
    let (actual, _) = installed
        .profile
        .bind_qualified(bootstrap.authority.clone(), &installed.qualifications)?;
    if actual != binding
        || policy
            .scope_for_node(&binding.compatibility.node_id)
            .map_err(|error| ProviderError::Io(std::io::Error::other(error.to_string())))?
            .binding
            != &binding.compatibility
    {
        return Err(ProviderError::Correlation(
            "ordinary complete source binding changed",
        ));
    }
    CnpBehavioralAcceptance::new(policy, limits)
        .authenticate_prelaunch(&regenerated, &bootstrap.resource_limits)
        .map_err(|error| ProviderError::Io(std::io::Error::other(error.to_string())))
}

fn package_error(error: crate::node_observed_executor::NodeObservedError) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}

// NONBLOCK covers a full listen backlog too; no blocking connect can spend a
// second unbounded period after the original bootstrap upload. Only an absent
// listener is polled, under that same physical cut and without another Child.
fn connect_original(
    path: &std::path::Path,
    deadline: &ExchangeDeadline,
) -> Result<UnixStream, ProviderError> {
    loop {
        deadline.remaining()?;
        let socket = rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(std::io::Error::from)?;
        let address = rustix::net::SocketAddrUnix::new(path).map_err(std::io::Error::from)?;
        match rustix::net::connect(&socket, &address) {
            Ok(()) => {
                let stream = UnixStream::from(socket);
                stream.set_nonblocking(false)?;
                deadline.remaining()?;
                return Ok(stream);
            }
            Err(error)
                if matches!(
                    error,
                    rustix::io::Errno::NOENT | rustix::io::Errno::CONNREFUSED
                ) =>
            {
                std::thread::park_timeout(deadline.remaining()?.min(Duration::from_millis(1)));
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
    }
}
