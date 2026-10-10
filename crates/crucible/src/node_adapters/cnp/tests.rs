//! Actual public preparation and original process custody, without fidelity qualification.

// crucible-lint: allow rust-allow -- native fixture assertions deliberately panic on lost original resources.
// crucible-lint: allow panic-shortcut -- These cnp tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "world_tests.rs"]
mod world;

#[path = "lifecycle_resend_tests.rs"]
mod lifecycle_resend;

use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::Read,
    os::unix::{fs::DirBuilderExt, net::UnixStream, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
    time::Duration,
};

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError, bodies::*, client::*, connection::*, envelope::*, handshake::*,
    reference_service::*,
};

use super::*;
use crate::node_contract::{ActivationRecord, OperationFailure};

struct Slot(Rc<RefCell<Vec<CnpPeerCustody>>>);

impl CnpProcessCustodySlot for Slot {
    fn identity(&self) -> U64 {
        U64::new(1)
    }
    fn retain(&mut self, custody: CnpPeerCustody) {
        let mut retained = self.0.borrow_mut();
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
            return Err(super::readiness::refused(
                "actual installed fixture changed",
            ));
        }
        Ok(())
    }
    fn authenticate_realization(
        &self,
        _: &CnpLaunchGuard,
        realization: &RealizeResult,
        gate: &ClosedGateRecord,
        companion_pid: u32,
    ) -> Result<(), OperationFailure> {
        if realization.prepared_token != self.bootstrap.prepared_token
            || !gate.gate_closed
            || companion_pid == 0
        {
            return Err(super::readiness::refused("actual realized fixture changed"));
        }
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
    }
}

fn connect(guard: &mut CnpLaunchGuard, socket: &std::path::Path, installed: &mut Installed) {
    connect_with_schema(guard, socket, installed, Rc::new(Schemas));
}

fn connect_with_schema(
    guard: &mut CnpLaunchGuard,
    socket: &std::path::Path,
    installed: &mut Installed,
    schemas: Rc<dyn BodySchemaVerifier>,
) {
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
        schemas,
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

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE and CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn actual_public_preparation_retains_original_ready_and_reclaims_both_native_processes() {
    let provider = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE")
            .expect("set source-built public provider"),
    );
    let device = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE")
            .expect("set source-built companion"),
    );
    let mut installed = installation(&provider, &device);
    let directory = std::env::temp_dir().join(format!(
        "cnp-core-preparation-{}-{}",
        std::process::id(),
        installed.bootstrap.admission_token.as_slice()[0]
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = directory.join("control.sock");
    let retained = Rc::new(RefCell::new(Vec::new()));
    // Reserve the finite slot before creating an actual process.
    let slot = Box::new(Slot(Rc::clone(&retained)));
    let mut child = Command::new(&provider)
        .arg(&socket)
        .arg(&device)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .unwrap();
    let stdin = child.stdin.take();
    let mut guard = CnpLaunchGuard::new(child, directory.clone(), slot)
        .ok()
        .unwrap();
    let mut stdin = stdin.unwrap();
    crucible_node_provider::transport::write_frame(
        &mut stdin,
        &serde_json::to_value(ReferenceServiceInstalledLaunchBootstrap {
            schema_version: 3,
            profile: PublicReferenceProfile::ByteLinkedV1 {
                closed_ingress: true,
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
        "actual private provider did not become available"
    );
    connect(&mut guard, &socket, &mut installed);
    let prepared = match CnpReferencePreparation::prepare(guard, &installed) {
        Ok(prepared) => prepared,
        Err(failure) => panic!("actual public preparation failed: {:?}", failure.error),
    };
    let companion = prepared.companion_pid;
    let mut controlled = super::control::CnpControlledReference::new(prepared, 8);
    let record = ActivationRecord {
        generation: installed.bootstrap.world_generation,
        activation_id: installed.bootstrap.activation_id.clone(),
        world_binding_hash: installed.bootstrap.world_binding_hash.clone(),
        owners: vec![crate::node_contract::OwnerIdentity {
            owner: installed.bootstrap.owner_id.clone(),
            incarnation: installed.bootstrap.authority.incarnation_id.clone(),
            generation: installed.bootstrap.authority.owner_generation,
        }],
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
    };
    let first = controlled.prepare_activation(&record).unwrap();
    assert_eq!(controlled.prepare_activation(&record).unwrap(), first);
    let mut changed = record.clone();
    changed.generation = U64::new(2);
    assert!(controlled.prepare_activation(&changed).is_err());
    assert_eq!(
        controlled.prepared.as_ref().unwrap().owner.ready_receipt,
        first.ready_receipt
    );
    assert!(
        controlled.active.is_none(),
        "readiness did not open a world gate"
    );
    for _ in 0..300 {
        if controlled.quarantine_public().unwrap() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        controlled.status,
        crucible_node_provider::reference_device::DeviceStatus::Reaped
    );
    assert!(!std::path::Path::new(&format!("/proc/{companion}")).exists());
    drop(controlled);
    assert_eq!(
        retained.borrow().len(),
        1,
        "drop retained actual original journal custody"
    );
    assert!(retained.borrow_mut()[0].poll_reclamation().unwrap());
    std::fs::remove_dir_all(directory).unwrap();
}

#[path = "original_conflict_tests.rs"]
mod original_conflict;

#[path = "acceptance_tests.rs"]
mod acceptance;
