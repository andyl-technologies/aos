//! Actual installed two-provider preparation retained beneath complete runtime custody.

#[path = "native/graph.rs"]
mod graph;

use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::Read,
    os::unix::{fs::DirBuilderExt, net::UnixStream, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    rc::Rc,
    time::Duration,
};

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError, bodies::*, client::*, connection::*, envelope::*, handshake::*,
    reference_service::*,
};

use crucible::node_adapters::cnp::*;
use crucible::node_contract::{
    ActivationRecord, EffectKnowledge, NodeRuntime, OperationFailure, OwnerIdentity,
    RuntimeCustodyQueue, RuntimeCustodySupervisor, RuntimeLimits, SimulationNode,
};
use crucible::node_scheduling::InputPayload;

struct Slot {
    identity: U64,
    retained: Rc<RefCell<Vec<CnpPeerCustody>>>,
}

impl CnpProcessCustodySlot for Slot {
    fn identity(&self) -> U64 {
        self.identity
    }

    fn retain(&mut self, custody: CnpPeerCustody) {
        let mut retained = self.retained.borrow_mut();
        assert!(
            retained.is_empty(),
            "the native slot was reserved before launch"
        );
        retained.push(custody);
    }
}

struct Installed {
    profile: ReferenceProfile,
    bootstrap: ReferenceServiceBootstrap,
    qualifications: Vec<ContentRef>,
    enrolled: RefCell<Option<NativeIdentity>>,
}

impl CnpReferenceQualification for Installed {
    fn authenticate_provider(
        &self,
        guard: &CnpLaunchGuard,
        profile: &ReferenceProfile,
    ) -> Result<(), OperationFailure> {
        if guard.provider_pid().is_none()
            || profile.descriptor != self.profile.descriptor
            || profile.implementation != self.profile.implementation
        {
            return Err(refused("actual installed fixture changed"));
        }
        Ok(())
    }

    fn authenticate_realization(
        &self,
        guard: &CnpLaunchGuard,
        realization: &RealizeResult,
        gate: &ClosedGateRecord,
        companion_pid: u32,
    ) -> Result<(), OperationFailure> {
        if realization.prepared_token != self.bootstrap.prepared_token
            || !gate.gate_closed
            || companion_pid == 0
        {
            return Err(refused("actual realized fixture changed"));
        }
        let provider = guard
            .provider_pid()
            .ok_or_else(|| refused("actual provider absent"))?;
        let identity = NativeIdentity::enroll(provider, companion_pid, &self.profile)?;
        if self
            .enrolled
            .borrow()
            .as_ref()
            .is_some_and(|original| original != &identity)
        {
            return Err(refused("original native enrollment changed"));
        }
        *self.enrolled.borrow_mut() = Some(identity);
        Ok(())
    }
}

impl TrustedHandshakeVerifier for Installed {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installation: &TrustedInstallation,
        _: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if installation.measured_implementation != self.profile.implementation
            || installation.launch_receipt != self.bootstrap.admission_receipt
            || result.provider_identity != self.profile.provider_manifest
        {
            return Err(ProviderError::Correlation("foreign installed fixture"));
        }
        Ok(())
    }

    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        _: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        if manifest != &self.profile.provider_manifest
            || guarantees
                != &self
                    .profile
                    .bind(self.bootstrap.authority.clone())?
                    .0
                    .compatibility
                    .guarantees_ref
        {
            return Err(ProviderError::Correlation("foreign installed contract"));
        }
        self.profile.content(guarantees)?;
        for schema in schemas {
            self.profile.content(&schema.definition)?;
        }
        Ok(())
    }

    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        operations: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        if !operations.is_empty() {
            return Err(ProviderError::Correlation(
                "initial fixture has no operation",
            ));
        }
        Ok(Vec::new())
    }

    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation("initial fixture has no stream"))
    }
}

#[derive(Default)]
struct Supervisor(RefCell<Vec<ConnectionIncident>>);
impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        self.0.borrow_mut().push(incident);
    }
}

struct Schemas;
impl BodySchemaVerifier for Schemas {
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
            return Err(ProviderError::Frame("uninstalled fixture extension"));
        }
        Ok(())
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn entropy() -> Bytes {
    let mut token = vec![0; 32];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut token)
        .unwrap();
    Bytes::new(token)
}

fn installation(provider: &std::path::Path, device: &std::path::Path) -> Installed {
    let profile = ReferenceProfile::build_public_linked(
        id("checksum"),
        id("checksum-owner"),
        crucible_node_provider::conformance::measure_executable(provider).unwrap(),
        crucible_node_provider::conformance::measure_executable(device).unwrap(),
        U64::new(1000),
        U64::new(1_000_000_000),
        true,
    )
    .unwrap();
    let authority = LiveAuthority {
        schema_version: 1,
        session_id: id("actual-core-session"),
        incarnation_id: id("actual-core-incarnation"),
        realization_id: id("actual-core-realization"),
        activation_id: None,
        world_generation: U64::new(0),
        owner_generation: U64::new(1),
        input_epoch: id("actual-core-input-epoch"),
        host_receipt: canonical::content_ref(
            b"private fixture admission constructed below",
            "text/plain",
        )
        .unwrap(),
        extensions: Extensions::new(),
    };
    let bootstrap = ReferenceServiceBootstrap::fixture(
        &profile,
        authority,
        entropy(),
        U64::new(u64::from(rustix::process::geteuid().as_raw())),
        Limits {
            frame_bytes: U64::new(1_048_576),
            nesting: U64::new(64),
            requests: U64::new(16),
            journal_entries: U64::new(256),
            blob_chunk_bytes: U64::new(16_384),
        },
        ResourceLimits {
            cpu_budget_ns: U64::new(4_000_000_000),
            memory_bytes: U64::new(512 * 1024 * 1024),
            writable_bytes: U64::new(0),
            processes: U64::new(2),
            descriptors: U64::new(32),
            pending_events: U64::new(16),
            content_bytes: U64::new(16 * 1024 * 1024),
            maximum_operations: U64::new(8),
            extensions: Extensions::new(),
        },
        canonical::hash(
            "cnp.world-binding.v1",
            b"actual core preparation fixture without fidelity qualification",
        )
        .unwrap(),
    )
    .unwrap();
    let evidence =
        b"source-installed actual process fixture; no fidelity qualification claim".to_vec();
    let launch = bootstrap
        .install_qualifications(
            &profile,
            vec![InstalledContent {
                reference: canonical::content_ref(&evidence, "text/plain").unwrap(),
                bytes: Bytes::new(evidence),
            }],
        )
        .unwrap();
    Installed {
        profile,
        bootstrap: launch.bootstrap,
        qualifications: launch.qualification_refs,
        enrolled: RefCell::new(None),
    }
}

fn connect(guard: &mut CnpLaunchGuard, socket: &std::path::Path, installed: &mut Installed) {
    let bootstrap = installed.bootstrap.clone();
    let features = vec![id("cnp.control-evidence/1"), id("cnp.core/1")];
    let (binding, _) = installed
        .profile
        .bind_qualified(bootstrap.authority.clone(), &installed.qualifications)
        .unwrap();
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
            required_features: features.clone(),
            provider_limits: bootstrap.limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref,
            envelope_extension_features: BTreeMap::new(),
        },
    )
    .unwrap();
    let hello = HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: bootstrap.authority.session_id.clone(),
        controller_nonce: entropy(),
        required_features: features,
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
        request_id: Nullable(Some(id("actual-core-hello"))),
        sequence: U64::new(1),
        method: Method::Hello,
        body: serde_json::to_value(hello)
            .unwrap()
            .as_object()
            .unwrap()
            .clone(),
        extensions: Extensions::new(),
    };
    let peer = ClientPeer {
        pid: guard.provider_pid().unwrap(),
        uid: rustix::process::geteuid().as_raw(),
        executable: installed
            .profile
            .implementation
            .artifacts
            .iter()
            .find(|artifact| artifact.id.as_str() == "provider")
            .unwrap()
            .content
            .clone(),
    };
    let session = ClientSession::negotiate(
        UnixStream::connect(socket).unwrap(),
        &peer,
        &hello,
        id("actual-core-connection"),
        &mut handshake,
        installed,
        Rc::new(Supervisor::default()),
        Rc::new(Schemas),
        Duration::from_secs(3),
        1_048_576,
        64,
    )
    .unwrap();
    let controller = ReferenceController::new_qualified(
        installed.profile.clone(),
        bootstrap,
        session,
        ClientCustody::new(
            256,
            ClientContent::new(16 * 1024 * 1024, 256, 16_384).unwrap(),
        )
        .unwrap(),
        Duration::from_secs(3),
        installed.qualifications.clone(),
    )
    .unwrap();
    guard.attach(controller, handshake).unwrap();
}

fn profile(provider: &Path, device: &Path, node: &str, closed_ingress: bool) -> ReferenceProfile {
    ReferenceProfile::build_public_linked(
        id(node),
        id(&format!("{node}-owner")),
        crucible_node_provider::conformance::measure_executable(provider).unwrap(),
        crucible_node_provider::conformance::measure_executable(device).unwrap(),
        U64::new(1000),
        U64::new(1_000_000_000),
        closed_ingress,
    )
    .unwrap()
}

fn installed(
    profile: ReferenceProfile,
    definition: &graph::Definition,
    provider: &Path,
    device: &Path,
) -> Installed {
    let standard = installation(provider, device);
    let bootstrap = ReferenceServiceBootstrap::fixture(
        &profile,
        graph::initial_authority(&profile.descriptor.id, definition.qualification()),
        entropy(),
        U64::new(u64::from(rustix::process::geteuid().as_raw())),
        standard.bootstrap.limits,
        standard.bootstrap.resource_limits,
        definition.world.identity().unwrap(),
    )
    .unwrap();
    let launch = bootstrap
        .install_qualifications(
            &profile,
            vec![InstalledContent {
                reference: definition.qualification().clone(),
                bytes: Bytes::new(definition.content[definition.qualification()].clone()),
            }],
        )
        .unwrap();
    Installed {
        profile,
        bootstrap: launch.bootstrap,
        qualifications: launch.qualification_refs,
        enrolled: RefCell::new(None),
    }
}

fn launch(
    provider: &Path,
    device: &Path,
    installed: &mut Installed,
    directory: PathBuf,
    retained: Rc<RefCell<Vec<CnpPeerCustody>>>,
) -> CnpReferencePreparation {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = directory.join("control.sock");
    let slot = Box::new(Slot {
        identity: U64::new(if installed.profile.descriptor.id == id("consumer") {
            1
        } else {
            2
        }),
        retained,
    });
    let mut child = Command::new(provider)
        .arg(&socket)
        .arg(device)
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let mut guard = CnpLaunchGuard::new(child, directory, slot).ok().unwrap();
    let mut stdin = stdin;
    crucible_node_provider::transport::write_frame(
        &mut stdin,
        &serde_json::to_value(ReferenceServiceInstalledLaunchBootstrap {
            schema_version: 3,
            profile: PublicReferenceProfile::ByteLinkedV1 {
                closed_ingress: installed.profile.descriptor.id == id("producer"),
            },
            bootstrap: installed.bootstrap.clone(),
            qualification_refs: installed.qualifications.clone(),
        })
        .unwrap(),
        16 * 1024 * 1024,
    )
    .unwrap();
    drop(stdin);
    for _ in 0..300 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        socket.exists(),
        "actual public endpoint did not become available"
    );
    connect(&mut guard, &socket, installed);
    match CnpReferencePreparation::prepare(guard, installed) {
        Ok(prepared) => prepared,
        Err(failure) => panic!(
            "actual public world preparation failed: {:?}",
            failure.error
        ),
    }
}

fn refused(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

#[derive(Clone, PartialEq, Eq)]
struct NativeIdentity {
    provider: u32,
    companion: u32,
    provider_start: String,
    companion_start: String,
}

impl NativeIdentity {
    fn enroll(
        provider: u32,
        companion: u32,
        profile: &ReferenceProfile,
    ) -> Result<Self, OperationFailure> {
        let identity = Self {
            provider,
            companion,
            provider_start: start_ticks(provider)?,
            companion_start: start_ticks(companion)?,
        };
        identity.authenticate(profile)?;
        Ok(identity)
    }

    fn authenticate(&self, profile: &ReferenceProfile) -> Result<(), OperationFailure> {
        if start_ticks(self.provider)? != self.provider_start
            || start_ticks(self.companion)? != self.companion_start
        {
            return Err(refused("original process lifetime changed"));
        }
        for (pid, role) in [(self.provider, "provider"), (self.companion, "device")] {
            let expected = profile
                .implementation
                .artifacts
                .iter()
                .find(|artifact| artifact.id.as_str() == role)
                .ok_or_else(|| refused("installed native artifact absent"))?;
            let actual = crucible_node_provider::conformance::measure_executable(&PathBuf::from(
                format!("/proc/{pid}/exe"),
            ))
            .map_err(|_| refused("actual native executable unavailable"))?;
            if actual != expected.content {
                return Err(refused("actual native source bytes changed"));
            }
        }
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.companion))
            .map_err(|_| refused("original native ancestry unavailable"))?;
        let pid = i32::try_from(self.companion)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| refused("original native PID invalid"))?;
        let group = rustix::process::getpgid(Some(pid))
            .map_err(|_| refused("original private process group unavailable"))?;
        if !status
            .lines()
            .any(|line| line == format!("PPid:\t{}", self.provider))
            || u32::try_from(group.as_raw_nonzero().get()).ok() != Some(self.provider)
        {
            return Err(refused("actual native companion escaped original custody"));
        }
        Ok(())
    }
}

fn start_ticks(pid: u32) -> Result<String, OperationFailure> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| refused("original process lifetime unavailable"))?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| refused("invalid native process record"))?;
    fields
        .split_whitespace()
        .nth(19)
        .map(str::to_owned)
        .ok_or_else(|| refused("native process start time absent"))
}

impl Installed {
    fn authenticate_enrolled(&self) -> Result<(), OperationFailure> {
        self.enrolled
            .borrow()
            .as_ref()
            .ok_or_else(|| refused("native node was not independently enrolled"))?
            .authenticate(&self.profile)
    }
}

pub(super) struct NativeWorld {
    pub(super) runtime: Option<NodeRuntime>,
    pub(super) record: ActivationRecord,
    pub(super) coordinator: InputPayload,
    retained: Vec<Rc<RefCell<Vec<CnpPeerCustody>>>>,
    queue: RuntimeCustodyQueue,
    processes: Vec<u32>,
    _directory: tempfile::TempDir,
}

impl NativeWorld {
    pub(super) fn prepare() -> Self {
        let provider = PathBuf::from(
            std::env::var_os("CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE")
                .expect("set source-built public provider"),
        );
        let device = PathBuf::from(
            std::env::var_os("CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE")
                .expect("set source-built companion"),
        );
        let profiles = vec![
            profile(&provider, &device, "consumer", false),
            profile(&provider, &device, "producer", true),
        ];
        let qualification = b"Installed native public checksum pair: actual independently enrolled private process groups, byte-preserving direct boundary-sampled connection, nondeterministic quantized limited-state profiles, bounded coordinator custody in consumer/state. No snapshot, fork, exact CPU or physical pause qualification.".to_vec();
        let artifacts = BTreeMap::from([
            (
                crucible_node_provider::conformance::measure_executable(&provider).unwrap(),
                provider.clone(),
            ),
            (
                crucible_node_provider::conformance::measure_executable(&device).unwrap(),
                device.clone(),
            ),
        ]);
        let definition = graph::Definition::build(&profiles, qualification, artifacts);
        let mut installed = profiles
            .into_iter()
            .map(|profile| installed(profile, &definition, &provider, &device))
            .collect::<Vec<_>>();
        let directory = tempfile::tempdir().unwrap();
        let retained = (0..installed.len())
            .map(|_| Rc::new(RefCell::new(Vec::with_capacity(1))))
            .collect::<Vec<_>>();
        // The whole-world reservation precedes every native launch. The
        // binding roster is independently regenerated from installed profiles.
        let record = ActivationRecord {
            generation: installed[0].bootstrap.world_generation,
            activation_id: installed[0].bootstrap.activation_id.clone(),
            world_binding_hash: definition.world.identity().unwrap(),
            owners: installed
                .iter()
                .map(|installation| OwnerIdentity {
                    owner: installation.profile.owner.id.clone(),
                    incarnation: installation.bootstrap.authority.incarnation_id.clone(),
                    generation: installation.bootstrap.authority.owner_generation,
                })
                .collect(),
            boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        };
        let queue = RuntimeCustodyQueue::new(1).unwrap();
        let world_cleanup = QueueCleanup(queue.clone());
        let slot = queue
            .reserve_world(&record, RuntimeLimits::default())
            .unwrap();
        let launch_custody = LaunchCustody {
            retained: retained.clone(),
        };
        let mut prepared = Vec::new();
        for (index, installation) in installed.iter_mut().enumerate() {
            prepared.push(launch(
                &provider,
                &device,
                installation,
                directory
                    .path()
                    .join(installation.profile.descriptor.id.as_str()),
                Rc::clone(&retained[index]),
            ));
        }
        let processes = installed
            .iter()
            .flat_map(|installation| {
                let enrollment = installation.enrolled.borrow();
                let enrollment = enrollment.as_ref().unwrap();
                [enrollment.provider, enrollment.companion]
            })
            .collect();
        let graph = definition.admit(&installed, &prepared);
        assert_eq!(graph.world_binding_hash(), &record.world_binding_hash);
        assert_eq!(graph.owners().count(), record.owners.len());
        let mut nodes: Vec<Box<dyn SimulationNode>> = Vec::new();
        for (prepared, installation) in prepared.into_iter().zip(&installed) {
            nodes.push(Box::new(
                prepared
                    .into_node(&graph, &installation.profile.descriptor.id, installation, 8)
                    .unwrap(),
            ));
        }
        let mut runtime = NodeRuntime::new(
            &graph,
            nodes,
            record.clone(),
            RuntimeLimits::default(),
            slot,
        )
        .unwrap_or_else(|failure| panic!("actual public runtime refused: {}", failure.error));
        runtime.arm_all().unwrap();
        let coordinator = runtime
            .initial_coordinator_snapshot(&graph, 1024 * 1024)
            .unwrap();
        drop(launch_custody);
        drop(world_cleanup);
        Self {
            runtime: Some(runtime),
            record,
            coordinator,
            retained,
            queue,
            processes,
            _directory: directory,
        }
    }

    pub(super) fn runtime(&mut self) -> &mut NodeRuntime {
        self.runtime.as_mut().unwrap()
    }

    pub(super) fn reclaim(&mut self) -> bool {
        use std::task::{Context, Poll, Waker};
        drop(self.runtime.take());
        let mut context = Context::from_waker(Waker::noop());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while self.queue.reserved_worlds() != 0 {
            match self.queue.poll_reclamation(&mut context) {
                Poll::Ready(Err(_)) => return false,
                _ if std::time::Instant::now() >= deadline => return false,
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        for slot in &self.retained {
            let mut slot = slot.borrow_mut();
            if slot.len() != 1 || !slot[0].poll_reclamation().unwrap_or(false) {
                return false;
            }
        }
        while self
            .processes
            .iter()
            .any(|pid| PathBuf::from(format!("/proc/{pid}")).exists())
        {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }
}

impl Drop for NativeWorld {
    fn drop(&mut self) {
        if !self.reclaim() {
            eprintln!("actual public activation fixture retained unresolved cleanup custody");
            for slot in &self.retained {
                std::mem::forget(Rc::clone(slot));
            }
        }
    }
}

/// Contains original children if native preparation panics before runtime formation.
struct LaunchCustody {
    retained: Vec<Rc<RefCell<Vec<CnpPeerCustody>>>>,
}

impl Drop for LaunchCustody {
    fn drop(&mut self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        for slot in &self.retained {
            while let Some(custody) = slot.borrow_mut().first_mut() {
                if custody.poll_reclamation().unwrap_or(false) {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    eprintln!("actual public preparation fixture cleanup remains unresolved");
                    // Preserve the original owning slot on a failed test rather
                    // than destroying unresolved Child/connection custody.
                    std::mem::forget(Rc::clone(slot));
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// Polls complete runtime custody after preparation unwinds before returning its world.
struct QueueCleanup(RuntimeCustodyQueue);

impl Drop for QueueCleanup {
    fn drop(&mut self) {
        use std::task::{Context, Waker};
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut context = Context::from_waker(Waker::noop());
        // A successful constructor still has a live reserved world; its owning
        // NativeWorld handles retirement. Unwound worlds are already retained.
        while self.0.retained_worlds() != 0 {
            let _ = self.0.poll_reclamation(&mut context);
            if std::time::Instant::now() >= deadline {
                eprintln!("actual complete public fixture cleanup remains supervised");
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
