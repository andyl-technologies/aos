//! Native Unix endpoint, authenticated negotiation, and original-request dispatch.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use crucible_node_contract::*;
use serde_json::{Map, Value};

use crate::ProviderError;
use crate::blob::BlobReceiver;
use crate::bodies::*;
use crate::connection::{Connection, EndpointRole, ReceivedBody};
use crate::envelope::{Envelope, MessageKind, Nullable, RequestOrigin};
use crate::handshake::*;
use crate::journal::JournalLimits;
use crate::native_journal::*;
use crate::transport::{FrameReader, write_frame};

use super::bootstrap::{PublicReferenceProfile, ReferenceServiceBootstrap};
use super::profile::ReferenceProfile;
use super::resources::{Resources, Supervisor};
use super::security::{NativeVerifier, SchemaVerifier};
use super::{completed, object, refusal, unknown};

/// Serves one privately installed native incarnation on a private Unix socket.
///
/// The caller supplies bootstrap facts through an authenticated host channel.
/// Connections may resume the retained incarnation, but cannot replace original
/// requests or run unsupported exact, capture, or physical-pause operations.
///
/// # Errors
/// Rejects malformed bootstrap, nonprivate socket directories, unavailable
/// supervision, executable measurements, or native socket installation failure.
pub fn serve(
    socket: &Path,
    child: &Path,
    bootstrap: ReferenceServiceBootstrap,
) -> Result<(), ProviderError> {
    serve_selected(
        socket,
        child,
        bootstrap,
        PublicReferenceProfile::ChecksumJsonV1,
    )
}

/// Serves an explicitly selected public profile under original private authority.
///
/// The selected profile is regenerated from the actual measured executables.
/// Its binding must match the privately installed admission before any native
/// companion is realized. Actor-native profiles cannot be selected here.
///
/// # Errors
/// Refuses invalid bootstrap, mismatched profile/admission, unavailable native
/// resource enforcement, nonprivate endpoints or transport installation failure.
pub fn serve_selected(
    socket: &Path,
    child: &Path,
    bootstrap: ReferenceServiceBootstrap,
    selection: PublicReferenceProfile,
) -> Result<(), ProviderError> {
    serve_bound(socket, child, bootstrap, selection, &[])
}

/// Serves a privately installed qualified binding without minting provider proof.
///
/// The private edition-three record supplies exact host-selected evidence. Its
/// immutable bindings and host admission must agree before opening the socket;
/// genuine evidence acceptance remains exclusively in the host registry.
///
/// # Errors
/// Refuses malformed installed launch, absent evidence bytes, changed binding
/// identity or unavailable native custody and resource enforcement.
pub fn serve_installed(
    socket: &Path,
    child: &Path,
    launch: super::ReferenceServiceInstalledLaunchBootstrap,
) -> Result<(), ProviderError> {
    launch.validate()?;
    serve_bound(
        socket,
        child,
        launch.bootstrap,
        launch.profile,
        &launch.qualification_refs,
    )
}

fn serve_bound(
    socket: &Path,
    child: &Path,
    bootstrap: ReferenceServiceBootstrap,
    selection: PublicReferenceProfile,
    qualifications: &[ContentRef],
) -> Result<(), ProviderError> {
    bootstrap.validate()?;
    super::limits::enforce(&bootstrap)?;
    let parent = socket
        .parent()
        .ok_or(ProviderError::Frame("socket has no private parent"))?;
    let metadata = fs::metadata(parent)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(ProviderError::Correlation(
            "socket directory is not privately owned",
        ));
    }
    let provider_executable = crate::conformance::measure_executable(&std::env::current_exe()?)?;
    let device_executable = crate::conformance::measure_executable(child)?;
    let profile = match selection {
        PublicReferenceProfile::ChecksumJsonV1 => ReferenceProfile::build(
            bootstrap.node_id.clone(),
            bootstrap.owner_id.clone(),
            provider_executable,
            device_executable,
            bootstrap.quantum_ps,
            bootstrap.host_budget_ns,
        ),
        PublicReferenceProfile::ByteLinkedV1 { closed_ingress } => {
            ReferenceProfile::build_public_linked(
                bootstrap.node_id.clone(),
                bootstrap.owner_id.clone(),
                provider_executable,
                device_executable,
                bootstrap.quantum_ps,
                bootstrap.host_budget_ns,
                closed_ingress,
            )
        }
    }?;
    let (binding, owner_binding) =
        profile.bind_qualified(bootstrap.authority.clone(), qualifications)?;
    let supervisor = Supervisor::new();
    let blobs = BlobReceiver::new(
        bootstrap.authority.session_id.clone(),
        bootstrap.authority.incarnation_id.clone(),
        Supervisor::blob_limits(&bootstrap)?,
        Rc::new(supervisor.clone()),
    )?;
    let mut resources = Resources {
        bootstrap: bootstrap.clone(),
        profile: profile.clone(),
        child_path: child.to_owned(),
        socket_parent: parent.to_owned(),
        child: None,
        binding: binding.clone(),
        owner_binding,
        realized: false,
        admitted: false,
        staged: false,
        active: false,
        gate_receipt: None,
        ready_receipt: None,
        contents: BTreeMap::new(),
        content_bytes: 0,
        blobs,
        verified: BTreeMap::new(),
        pins: Vec::new(),
        input: None,
        input_bytes: Vec::new(),
        input_custody: None,
        next_quantum: U64::new(0),
        next_observation: U64::new(1),
        window: None,
        transferred: std::cell::RefCell::new(BTreeSet::new()),
        consumed: BTreeSet::new(),
    };
    for content in profile.content_objects() {
        resources.store(content.bytes.clone(), &content.reference.media_type)?;
    }
    for content in &bootstrap.installed_content {
        resources.store(
            content.bytes.as_slice().to_vec(),
            &content.reference.media_type,
        )?;
    }
    let admission: ControlReceipt = resources.resolve(&bootstrap.admission_receipt)?;
    let admitted: AdmissionRecord = resources.resolve(&admission.record_ref)?;
    if admission.kind != ControlReceiptKind::Admission
        || admission.issuer != ReceiptIssuer::Host
        || admitted.binding_hashes != [binding.identity()?]
        || admitted.world_binding_hash != bootstrap.world_binding_hash
        || admitted.measured_artifacts != profile.implementation.artifacts
        || admitted.resource_limits != bootstrap.resource_limits
        || admitted.qualification_refs != qualifications
    {
        return Err(ProviderError::Correlation(
            "private bootstrap admission differs from measured installation",
        ));
    }

    let entries = bounded(bootstrap.limits.journal_entries)?;
    let operations = bounded(bootstrap.resource_limits.maximum_operations)?.min(entries);
    let events = bounded(bootstrap.resource_limits.pending_events)?.min(entries);
    let bytes = bounded(bootstrap.resource_limits.content_bytes)?;
    let mut journal = NativeJournal::new(
        bootstrap.authority.session_id.clone(),
        bootstrap.authority.incarnation_id.clone(),
        JournalLimits {
            entries_per_origin: entries,
            outcome_bytes: bytes,
            tombstones_per_origin: entries,
        },
        NativeJournalLimits {
            operations,
            operation_tombstones: entries,
            input_batches: events,
            observation_batches: events,
            retained_bytes: bytes,
        },
        resources,
        &supervisor,
    )?;
    let core = Id::new("cnp.core/1")?;
    let mut supported_features = vec![core.clone()];
    supported_features.extend(profile.provider_manifest.extensions_supported.clone());
    supported_features.sort();
    supported_features.dedup();
    let mut token = [0; 32];
    token.copy_from_slice(bootstrap.admission_token.as_slice());
    let guarantees = binding.compatibility.guarantees_ref.clone();
    let mut handshake = Handshake::new(
        TrustedInstallation {
            session_id: bootstrap.authority.session_id.clone(),
            incarnation_id: bootstrap.authority.incarnation_id.clone(),
            measured_implementation: profile.implementation.clone(),
            launch_receipt: bootstrap.admission_receipt.clone(),
            admission_token: token,
        },
        NegotiationPolicy {
            supported_features,
            required_features: vec![core],
            provider_limits: bootstrap.limits,
            required_schemas: Vec::new(),
            required_guarantees: guarantees,
            envelope_extension_features: BTreeMap::new(),
        },
    )?;
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let mut old_stream = None;
    let mut connection_number = 0u64;
    loop {
        let (stream, _) = listener.accept()?;
        connection_number =
            connection_number
                .checked_add(1)
                .ok_or(ProviderError::ResourceExhausted(
                    "native connection identities",
                ))?;
        if connection_number > 4096 {
            return Err(ProviderError::ResourceExhausted(
                "native connection custody",
            ));
        }
        let connection_id = Id::new(format!("reference-connection-{connection_number}"))?;
        let admitted = negotiate(
            stream,
            connection_id,
            &bootstrap,
            &mut handshake,
            &journal,
            &mut old_stream,
        );
        let Ok((stream, authority)) = admitted else {
            continue;
        };
        let Ok(mut connection) = Connection::new(
            stream,
            authority.clone(),
            Rc::new(supervisor.clone()),
            Rc::new(SchemaVerifier),
            EndpointRole::Provider,
        ) else {
            continue;
        };
        let mut sequence = U64::new(2);
        while let Ok(Some(frame)) = connection.receive() {
            let ReceivedBody::Request(body) = frame.body else {
                break;
            };
            let result = dispatch(&mut journal, &authority, &frame.envelope, &body);
            let response = match result {
                Ok(body) => body,
                Err(error) => refusal(&error)?,
            };
            let completed_response = response
                .get("status")
                .is_some_and(|value| value == "completed");
            let has_observations = response
                .get("result")
                .and_then(|result| result.get("observations"))
                .and_then(Value::as_array)
                .is_some_and(|observations| !observations.is_empty());
            let pending_committed = journal
                .resources()
                .window
                .as_ref()
                .and_then(|window| window.committed_ref.as_ref())
                .is_some_and(|reference| {
                    !journal
                        .resources()
                        .transferred
                        .borrow()
                        .contains(&reference.hash.digest)
                });
            let selected_control_evidence = authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == "cnp.control-evidence/1");
            let control_evidence = completed_response
                && selected_control_evidence
                && matches!(
                    body.as_ref(),
                    RequestBody::Realize(_)
                        | RequestBody::Activate(_)
                        | RequestBody::Input(_)
                        | RequestBody::WorldActivate(_)
                        | RequestBody::Begin(_)
                        | RequestBody::Poll(_)
                        | RequestBody::Observe(_)
                        | RequestBody::QuantumClose(_)
                        | RequestBody::Abort(_)
                        | RequestBody::Release(_)
                );
            // Keep the original terminal response immutable while its referenced
            // receipt closure is transferred on the opposite request lane.
            let retained_response = control_evidence.then(|| response.clone());
            let mut envelope = frame.envelope.clone();
            envelope.message = MessageKind::Response;
            envelope.sequence = sequence;
            envelope.body = response;
            sequence = sequence.checked_add(U64::new(1))?;
            if connection.send(envelope).is_err() {
                break;
            }
            if let Some(response) = retained_response
                && super::transfer::publish_control(
                    &mut connection,
                    &authority,
                    &mut journal,
                    &mut sequence,
                    &response,
                )
                .is_err()
            {
                break;
            }
            if completed_response
                && !selected_control_evidence
                && (has_observations || pending_committed)
                && matches!(
                    body.as_ref(),
                    RequestBody::Observe(_) | RequestBody::Poll(_)
                )
                && super::transfer::publish(
                    &mut connection,
                    &authority,
                    &mut journal,
                    &mut sequence,
                )
                .is_err()
            {
                break;
            }
        }
    }
}

fn bounded(value: U64) -> Result<usize, ProviderError> {
    usize::try_from(value.get())
        .map_err(|_| ProviderError::ResourceExhausted("native allowance exceeds platform"))
}

fn random() -> Result<Bytes, ProviderError> {
    let mut bytes = vec![0; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(Bytes::new(bytes))
}

fn negotiate(
    stream: UnixStream,
    connection: Id,
    bootstrap: &ReferenceServiceBootstrap,
    handshake: &mut Handshake,
    journal: &NativeJournal<Resources>,
    old: &mut Option<UnixStream>,
) -> Result<(UnixStream, ConnectionAuthority), ProviderError> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let credentials =
        rustix::net::sockopt::socket_peercred(&stream).map_err(std::io::Error::from)?;
    if u64::from(credentials.uid.as_raw()) != bootstrap.controller_uid.get() {
        return Err(ProviderError::Correlation("controller native UID differs"));
    }
    let mut reader = FrameReader::new(stream.try_clone()?, bounded(bootstrap.limits.frame_bytes)?)?;
    let value = reader
        .read()?
        .ok_or(ProviderError::Frame("hello missing"))?;
    let request = Envelope::decode(
        &canonical::canonical_json(&value)?,
        bounded(bootstrap.limits.frame_bytes)?,
    )?;
    let RequestBody::Hello(hello) = decode_request(request.method, &request.body)? else {
        return Err(ProviderError::Frame("initial frame is not hello"));
    };
    let mut supported_features = vec![Id::new("cnp.core/1")?];
    supported_features.extend(
        journal
            .resources()
            .profile
            .provider_manifest
            .extensions_supported
            .clone(),
    );
    supported_features.sort();
    supported_features.dedup();
    let selected_features: Vec<Id> = supported_features
        .iter()
        .filter(|name| {
            hello
                .required_features
                .iter()
                .chain(&hello.optional_features)
                .any(|id| id == *name)
        })
        .cloned()
        .collect();
    let result = HelloResult {
        version: "CNP/1".to_owned(),
        session_id: bootstrap.authority.session_id.clone(),
        incarnation_id: bootstrap.authority.incarnation_id.clone(),
        controller_nonce: hello.controller_nonce.clone(),
        provider_nonce: random()?,
        selected_features: selected_features.clone(),
        limits: hello.limits.intersection(bootstrap.limits)?,
        resume_token: Nullable(
            if selected_features
                .iter()
                .any(|id| id.as_str() == "cnp.resume/1")
            {
                Some(random()?)
            } else {
                None
            },
        ),
        provider_identity: journal.resources().profile.provider_manifest.clone(),
        resumed_operations: match &hello.resume_session {
            Some(resume) => journal.resumed_operations(&resume.unresolved_operation_ids)?,
            None => Vec::new(),
        },
    };
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.incarnation_id = Nullable(Some(bootstrap.authority.incarnation_id.clone()));
    response.body = completed(result)?;
    let mut verifier = ExchangeVerifier {
        journal,
        old,
        peer_uid: credentials.uid.as_raw(),
        expected_uid: bootstrap.controller_uid,
    };
    let authority = match handshake.admit_envelopes(&request, &response, connection, &mut verifier)
    {
        Ok(authority) => authority,
        Err(error) => {
            let mut refused = response;
            refused.body = refusal(&error)?;
            if hello
                .required_features
                .iter()
                .any(|id| !supported_features.contains(id))
            {
                refused.body = super::rejected("UNSUPPORTED_FEATURE")?;
            }
            write_frame(
                &mut stream.try_clone()?,
                &serde_json::to_value(refused).map_err(ContractError::from)?,
                bounded(bootstrap.limits.frame_bytes)?,
            )?;
            return Err(error);
        }
    };
    let mut writer = stream.try_clone()?;
    write_frame(
        &mut writer,
        &serde_json::to_value(response).map_err(ContractError::from)?,
        bounded(bootstrap.limits.frame_bytes)?,
    )?;
    *old = Some(stream.try_clone()?);
    Ok((stream, authority))
}

struct ExchangeVerifier<'a> {
    journal: &'a NativeJournal<Resources>,
    old: &'a mut Option<UnixStream>,
    peer_uid: u32,
    expected_uid: U64,
}

impl TrustedHandshakeVerifier for ExchangeVerifier<'_> {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installation: &TrustedInstallation,
        _: &HelloRequest,
        _: &HelloResult,
    ) -> Result<(), ProviderError> {
        if u64::from(self.peer_uid) != self.expected_uid.get()
            || installation.measured_implementation
                != self.journal.resources().profile.implementation
        {
            return Err(ProviderError::Correlation("native launch identity differs"));
        }
        self.journal
            .resources()
            .content(&installation.launch_receipt)?;
        Ok(())
    }

    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        _: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        if manifest != &self.journal.resources().profile.provider_manifest
            || guarantees
                != &self
                    .journal
                    .resources()
                    .binding
                    .compatibility
                    .guarantees_ref
        {
            return Err(ProviderError::Correlation(
                "selected installed contract differs",
            ));
        }
        self.journal.resources().content(guarantees)?;
        for schema in schemas {
            self.journal.resources().content(&schema.definition)?;
        }
        Ok(())
    }

    fn resume_custody(
        &mut self,
        session: &Id,
        incarnation: &Id,
        operations: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        if session != &self.journal.snapshot().session_id
            || incarnation != &self.journal.snapshot().incarnation_id
        {
            return Err(ProviderError::Correlation(
                "native incarnation custody differs",
            ));
        }
        self.journal.resumed_operations(operations)
    }

    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        self.old
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "old native stream custody missing",
            ))?
            .shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
}

fn dispatch(
    journal: &mut NativeJournal<Resources>,
    authority: &ConnectionAuthority,
    envelope: &Envelope,
    body: &RequestBody,
) -> Result<Map<String, Value>, ProviderError> {
    let request_id = envelope
        .request_id
        .0
        .clone()
        .ok_or(ProviderError::Correlation("request identity missing"))?;
    let verifier = NativeVerifier { request_id };
    if let RequestBody::Begin(request) = body {
        let refused_code = if !matches!(request.kind, BeginKind::QuantumBegin | BeginKind::Shutdown)
        {
            Some("UNSUPPORTED_FEATURE")
        } else if !journal.resources().active {
            Some("INVALID_STATE")
        } else {
            None
        };
        if let Some(code) = refused_code {
            return match journal.register_request(authority, envelope, RequestOrigin::Controller)? {
                NativeRequestRegistration::New(permit) => {
                    let refusal = super::rejected(code)?;
                    journal.record_request_refusal(&permit, &refusal)?;
                    Ok(refusal)
                }
                NativeRequestRegistration::Original(original) => match original.outcome {
                    Some(bytes) => object(canonical::parse_json(&bytes, 16 * 1024 * 1024)?),
                    None => unknown(),
                },
            };
        }
        let registered = match journal.register_begin(authority, envelope, request, &verifier) {
            Ok(registered) => registered,
            Err(error) => {
                let response = refusal(&error)?;
                match journal.register_request(authority, envelope, RequestOrigin::Controller)? {
                    NativeRequestRegistration::New(permit) => {
                        journal.record_request_refusal(&permit, &response)?;
                    }
                    NativeRequestRegistration::Original(original) => {
                        return match original.outcome {
                            Some(bytes) => object(canonical::parse_json(&bytes, 16 * 1024 * 1024)?),
                            None => unknown(),
                        };
                    }
                }
                return Ok(response);
            }
        };
        return match registered {
            BeginRegistration::Original(original) => original.outcome.map_or_else(unknown, Ok),
            BeginRegistration::New(permit) => {
                let arguments = request.decoded_arguments()?;
                let outcome =
                    journal.with_operation_resources(&permit, |resources| match &arguments {
                        BeginArguments::QuantumBegin(arguments) => {
                            completed(resources.run_quantum(envelope, arguments)?)
                        }
                        BeginArguments::Shutdown(_) => completed(resources.shutdown(envelope)?),
                        _ => Err(ProviderError::Frame("unsupported reference operation")),
                    });
                let outcome = match outcome {
                    Ok(outcome) => outcome,
                    Err(_) => unknown()?,
                };
                if let Some(batch) = journal
                    .resources()
                    .window
                    .as_ref()
                    .filter(|window| &window.operation == permit.operation_id())
                    .map(|window| window.observation.clone())
                    && journal
                        .append_observation(&permit, &batch, &verifier)
                        .is_err()
                {
                    journal.mark_operation_uncertain(permit.operation_id())?;
                    return unknown();
                }
                if journal
                    .record_terminal(&permit, &outcome, &verifier)
                    .is_err()
                {
                    journal.mark_operation_uncertain(permit.operation_id())?;
                    return unknown();
                }
                Ok(outcome)
            }
        };
    }
    if let RequestBody::Input(request) = body {
        return match journal.accept_input(authority, envelope, request, &verifier) {
            Ok(InputAcceptance::Accepted(result)) => completed(result),
            Ok(InputAcceptance::Original(original)) => {
                original.result.map_or_else(unknown, completed)
            }
            Err(error) => {
                let hash = envelope.request_hash(RequestOrigin::Controller)?;
                if journal.snapshot().inputs.values().any(|original| {
                    original.request_hash == hash && original.state == OperationState::Unknown
                }) {
                    unknown()
                } else {
                    Err(error)
                }
            }
        };
    }
    let registration = journal.register_request(authority, envelope, RequestOrigin::Controller)?;
    let NativeRequestRegistration::New(permit) = registration else {
        let NativeRequestRegistration::Original(original) = registration else {
            return Err(ProviderError::Conflict("request registration unavailable"));
        };
        return match original.outcome {
            Some(bytes) => object(canonical::parse_json(&bytes, 16 * 1024 * 1024)?),
            None => unknown(),
        };
    };
    if let Err(error) = journal.resources().preflight(body) {
        let response = refusal(&error)?;
        journal.record_request_refusal(&permit, &response)?;
        return Ok(response);
    }
    let response = (|| -> Result<Map<String, Value>, ProviderError> {
        match body {
            RequestBody::Discover(request) => {
                if request.cursor.is_some() {
                    return Err(ProviderError::Frame(
                        "reference discovery cursor unsupported",
                    ));
                }
                let profile = &journal.resources().profile;
                let profiles = if request.profile_ids.is_empty()
                    || request
                        .profile_ids
                        .contains(&profile.node_manifest.profile_id)
                {
                    vec![profile.node_manifest.clone()]
                } else {
                    Vec::new()
                };
                completed(DiscoverResult {
                    provider_manifest: profile.provider_manifest.clone(),
                    profiles,
                    facet_schemas: profile.implementation.formats.clone(),
                    complete: true,
                    next_cursor: Nullable(None),
                })
            }
            RequestBody::Observe(request) => {
                journal.resources().check_observation_scope(
                    envelope,
                    request.owner_generation,
                    &request.binding_hash,
                )?;
                let page = journal.observe(
                    &OwnerStream {
                        owner: journal.resources().bootstrap.owner_id.clone(),
                        generation: request.owner_generation,
                    },
                    request.after_observation_sequence,
                    bounded(request.maximum_items)?,
                )?;
                let inventory =
                    journal.with_request_resources(&permit, |resources| resources.pending())?;
                completed(ObserveResult {
                    observations: page.observations,
                    next_sequence: page.next_sequence,
                    complete: page.complete,
                    inventory_hash: inventory.hash,
                })
            }
            RequestBody::Poll(request) => {
                let operation = envelope
                    .operation_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation("poll operation missing"))?;
                if let Some(refused) = journal.snapshot().refused_operations.get(operation) {
                    if envelope.node_id.0 != refused.node_id
                        || envelope.execution_owner_id.0 != refused.execution_owner_id
                        || envelope.capture_owner_id.0 != refused.capture_owner_id
                    {
                        return Err(ProviderError::Correlation(
                            "poll changed original refused scope",
                        ));
                    }
                    return completed(journal.poll(
                        operation,
                        request.after_observation_sequence,
                        64,
                    )?);
                }
                let original = journal.snapshot().operations.get(operation).ok_or(
                    ProviderError::Correlation("poll original operation missing"),
                )?;
                journal.resources().check_owner(
                    envelope,
                    original.scope.owner_generation,
                    &original.scope.binding_hash,
                )?;
                completed(journal.poll(operation, request.after_observation_sequence, 64)?)
            }
            RequestBody::Cancel(_) => {
                let operation = envelope
                    .operation_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation("cancel operation missing"))?;
                let original = journal.snapshot().operations.get(operation).ok_or(
                    ProviderError::Correlation("cancel original operation missing"),
                )?;
                journal.resources().check_owner(
                    envelope,
                    original.scope.owner_generation,
                    &original.scope.binding_hash,
                )?;
                completed(journal.request_cancel(operation)?)
            }
            RequestBody::Retire(request) => {
                super::retirement::retire(journal, &permit, request, &verifier)
            }
            RequestBody::Hello(_) | RequestBody::Begin(_) | RequestBody::Input(_) => Err(
                ProviderError::Frame("method unavailable in registered dispatch"),
            ),
            _ => journal
                .with_request_resources(&permit, |resources| resources.control(envelope, body)),
        }
    })();
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            let refusal = refusal(&error)?;
            if journal.record_request_refusal(&permit, &refusal).is_ok() {
                return Ok(refusal);
            }
            unknown()?
        }
    };
    if journal.record_request_terminal(&permit, &response).is_err() {
        return unknown();
    }
    Ok(response)
}
