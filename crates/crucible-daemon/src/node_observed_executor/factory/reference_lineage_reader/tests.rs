//! Exercises the measured candidate reader under actual common runtime custody.
//!
//! Originals are persisted separately from inert counterfactual data. This
//! fixture issues no accepted class, capture capability or ordinary selector.

// crucible-lint: allow panic-shortcut -- This cfg(test)-only installed native fixture and its graph/namespace children panic on invalid setup or failed assertions; guarded world custody retains original peers during unwind.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crucible::node_adapters::cnp::*;
use crucible::node_admission::*;
use crucible::node_contract::*;
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend, RefName};
use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError, bodies::*, client::*, connection::*, envelope::*, handshake::*,
    reference_lineage::*, reference_service::*,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    io::Read,
    os::unix::{fs::DirBuilderExt, net::UnixStream, process::CommandExt},
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use super::{
    extension::ReaderExtensionPolicy, package::InstalledReaderPackage,
    policy::InstalledReaderPolicy,
};
use crate::node_observed_executor::StoredWorldActivationPublisher;

#[path = "graph.rs"]
mod graph;

#[path = "namespace_tests.rs"]
mod namespace_tests;

struct Installed {
    profile: ReferenceProfile,
    bootstrap: ReferenceServiceBootstrap,
    qualifications: Vec<ContentRef>,
    binding: NodeBinding,
    owner: OwnerBinding,
    policy: Rc<InstalledReaderPolicy>,
}

impl Installed {
    fn authenticate_enrolled(&self) -> Result<(), ProviderError> {
        self.policy.authenticate_enrolled()
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
        features: &IdSet,
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
        self.policy.record_negotiation(features)?;
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

struct Schemas {
    definition: InputLineageDefinition,
}

impl BodySchemaVerifier for Schemas {
    fn verify(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        body: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if !envelope.extensions.is_empty() {
            return Err(ProviderError::Frame(
                "uninstalled fixture envelope extension",
            ));
        }
        if let ReceivedBody::Request(request) = body
            && let RequestBody::Input(input) = request.as_ref()
        {
            if !authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == INPUT_LINEAGE_FEATURE)
            {
                return Err(ProviderError::Frame("reader feature not negotiated"));
            }
            // This authenticates only the selected containing application.
            // Owning source/native input validation remains a separate gate.
            self.definition
                .input_inventory_reference(&input.extensions)?;
            return Ok(());
        }
        if envelope
            .body
            .get("extensions")
            .and_then(serde_json::Value::as_object)
            .is_none_or(|extensions| !extensions.is_empty())
        {
            return Err(ProviderError::Frame("uninstalled fixture body extension"));
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

fn controller(
    guard: &LineageSourceGuard,
    socket: &std::path::Path,
    installed: &mut Installed,
) -> (ReferenceController, Handshake) {
    let bootstrap = installed.bootstrap.clone();
    let features = vec![
        id("cnp.control-evidence/1"),
        id("cnp.core/1"),
        id("org.andyl.reference.original-input-lineage/1"),
    ];
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
        Rc::new(Schemas {
            definition: installed
                .profile
                .input_lineage_definition()
                .unwrap()
                .clone(),
        }),
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
            4096,
            ClientContent::new(16 * 1024 * 1024, 4096, 16_384).unwrap(),
        )
        .unwrap(),
        Duration::from_secs(3),
        installed.qualifications.clone(),
    )
    .unwrap();
    (controller, handshake)
}

struct SourceSlot {
    identity: U64,
    retained: Rc<RefCell<Option<LineageSourceCustody>>>,
    retention_failed: Rc<Cell<bool>>,
}

impl LineageSourceCustodySlot for SourceSlot {
    fn identity(&self) -> U64 {
        self.identity
    }

    fn retain(self: Box<Self>, custody: LineageSourceCustody) {
        let Ok(mut retained) = self.retained.try_borrow_mut() else {
            self.retention_failed.set(true);
            std::mem::forget(custody);
            return;
        };
        if retained.is_some() {
            self.retention_failed.set(true);
            std::mem::forget(custody);
            return;
        }
        *retained = Some(custody);
    }
}

struct RuntimeSlot {
    identity: U64,
    retained: Rc<RefCell<Option<LineageRuntimeCustody>>>,
    retention_failed: Rc<Cell<bool>>,
}

impl LineageRuntimeCustodySlot for RuntimeSlot {
    fn identity(&self) -> U64 {
        self.identity
    }

    fn retain(self: Box<Self>, custody: LineageRuntimeCustody) {
        let Ok(mut retained) = self.retained.try_borrow_mut() else {
            self.retention_failed.set(true);
            std::mem::forget(custody);
            return;
        };
        if retained.is_some() {
            self.retention_failed.set(true);
            std::mem::forget(custody);
            return;
        }
        *retained = Some(custody);
    }
}

struct PolicyHandle(Rc<InstalledReaderPolicy>);

impl LineageReferenceQualification for PolicyHandle {
    fn authenticate_realization(
        &self,
        guard: &LineageSourceGuard,
        original: &OriginalLineageRealization<'_>,
    ) -> Result<(), ProviderError> {
        self.0.authenticate_realization(guard, original)
    }

    fn authenticate_window(
        &self,
        original: &OriginalRuntimeLineage<'_>,
    ) -> Result<(), ProviderError> {
        self.0.authenticate_window(original)
    }
}

fn installed(
    package: Rc<InstalledReaderPackage>,
    profile: ReferenceProfile,
    definition: &graph::Definition,
) -> Installed {
    let mut bootstrap = ReferenceServiceBootstrap::fixture(
        &profile,
        graph::initial_authority(&profile.descriptor.id, definition.qualification()),
        entropy(),
        U64::new(u64::from(rustix::process::geteuid().as_raw())),
        Limits {
            frame_bytes: U64::new(1_048_576),
            nesting: U64::new(64),
            requests: U64::new(32),
            journal_entries: U64::new(4096),
            blob_chunk_bytes: U64::new(16_384),
        },
        ResourceLimits {
            cpu_budget_ns: U64::new(8_000_000_000),
            memory_bytes: U64::new(512 * 1024 * 1024),
            writable_bytes: U64::new(0),
            processes: U64::new(2),
            descriptors: U64::new(32),
            pending_events: U64::new(16),
            content_bytes: U64::new(32 * 1024 * 1024),
            maximum_operations: U64::new(16),
            extensions: Extensions::new(),
        },
        definition.world.identity().unwrap(),
    )
    .unwrap();
    let qualifications = vec![definition.qualification().clone()];
    let (initial_binding, _) = profile
        .bind_qualified(bootstrap.authority.clone(), &qualifications)
        .unwrap();
    let admission = AdmissionRecord {
        schema_version: 1,
        realization_id: bootstrap.authority.realization_id.clone(),
        binding_hashes: vec![initial_binding.identity().unwrap()],
        world_binding_hash: bootstrap.world_binding_hash.clone(),
        measured_artifacts: profile.implementation.artifacts.clone(),
        qualification_refs: qualifications.clone(),
        resource_limits: bootstrap.resource_limits.clone(),
        evidence_refs: Vec::new(),
        extensions: Extensions::new(),
    };
    admission.validate().unwrap();
    let record_ref = install_original(&mut bootstrap.installed_content, &admission);
    let receipt = ControlReceipt {
        schema_version: 1,
        kind: ControlReceiptKind::Admission,
        session_id: bootstrap.authority.session_id.clone(),
        incarnation_id: bootstrap.authority.incarnation_id.clone(),
        request_id: id("private-admission"),
        operation_id: None,
        owner_ids: vec![bootstrap.owner_id.clone()],
        world_generation: U64::new(0),
        record_ref,
        issuer: ReceiptIssuer::Host,
        extensions: Extensions::new(),
    };
    receipt.validate().unwrap();
    let receipt_ref = install_original(&mut bootstrap.installed_content, &receipt);
    bootstrap.authority.host_receipt = receipt_ref.clone();
    bootstrap.admission_receipt = receipt_ref;
    bootstrap.installed_content.push(InstalledContent {
        reference: definition.qualification().clone(),
        bytes: Bytes::new(definition.content[definition.qualification()].clone()),
    });
    for (reference, bytes) in package.definition().objects() {
        if !bootstrap
            .installed_content
            .iter()
            .any(|body| &body.reference == reference)
        {
            bootstrap.installed_content.push(InstalledContent {
                reference: reference.clone(),
                bytes: Bytes::new(bytes.clone()),
            });
        }
    }
    let (binding, owner) = profile
        .bind_qualified(bootstrap.authority.clone(), &qualifications)
        .unwrap();
    let policy = Rc::new(InstalledReaderPolicy::new(package, profile.clone(), 8).unwrap());
    Installed {
        profile,
        bootstrap,
        qualifications,
        binding,
        owner,
        policy,
    }
}

fn install_original(
    contents: &mut Vec<InstalledContent>,
    value: &impl serde::Serialize,
) -> ContentRef {
    let bytes = canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    if let Some(original) = contents.iter().find(|object| object.reference == reference) {
        assert_eq!(original.bytes.as_slice(), bytes);
    } else {
        contents.push(InstalledContent {
            reference: reference.clone(),
            bytes: Bytes::new(bytes),
        });
    }
    reference
}

fn launch(
    package: &InstalledReaderPackage,
    installed: &mut Installed,
    directory: PathBuf,
    source_slot: Box<dyn LineageSourceCustodySlot>,
    runtime_slot: Box<dyn LineageRuntimeCustodySlot>,
    observation: &Rc<RefCell<Option<ObservationHandle>>>,
) -> LineageControlledReference {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = directory.join("control.sock");
    let child = Command::new(package.executable("provider").unwrap())
        .arg(&socket)
        .arg(package.executable("device").unwrap())
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .unwrap();
    let mut guard = LineageSourceGuard::new(
        child,
        directory,
        package.artifact_content("provider").unwrap().clone(),
        package.artifact_content("device").unwrap().clone(),
        source_slot,
    )
    .ok()
    .unwrap();
    let declaration = package.definition().regenerated().declaration();
    let core = |name: &str| {
        declaration
            .dependencies
            .iter()
            .find_map(|dependency| match dependency {
                ExtensionDependency::Core {
                    identifier,
                    definition,
                    ..
                } if identifier.as_str() == name => Some(definition.clone()),
                _ => None,
            })
            .unwrap()
    };
    let launch = ReferenceLineageReaderLaunchBootstrap {
        schema_version: 6,
        closed_ingress: installed.profile.descriptor.id == id("source"),
        bootstrap: installed.bootstrap.clone(),
        qualification_refs: installed.qualifications.clone(),
        definition_sources: LineageReaderDefinitionSources {
            namespace_publication: declaration.owner.publication_origin.clone(),
            handler: package.definition().regenerated().handler().clone(),
            event: core("cnp.event"),
            input: core("cnp.input-batch"),
            stop: core("cnp.stop-receipt"),
        },
    };
    launch.validate().unwrap();
    guard
        .write_private_bootstrap(
            canonical::canonical_json(&serde_json::to_value(launch).unwrap()).unwrap(),
        )
        .unwrap();
    for _ in 0..300 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists());
    let (mut controller, handshake) = controller(&guard, &socket, installed);
    let handle = controller.observe(observation_limits()).unwrap();
    *observation.borrow_mut() = Some(handle);
    let mut guard = guard.attach(controller, handshake).ok().unwrap();
    let discovered = guard
        .call(
            id(&format!("discover/{}", installed.profile.descriptor.id)),
            None,
            Method::Discover,
            false,
            DiscoverRequest {
                profile_ids: vec![installed.profile.node_manifest.profile_id.clone()],
                cursor: None,
                extensions: Extensions::new(),
            },
        )
        .unwrap();
    let Some(MethodResult::Discover(result)) = discovered.result else {
        panic!("original selected discovery failed")
    };
    assert_eq!(
        result.provider_manifest,
        installed.profile.provider_manifest
    );
    assert_eq!(
        result.profiles,
        vec![installed.profile.node_manifest.clone()]
    );
    assert!(result.complete);
    assert!(result.next_cursor.0.is_none());
    let realization = id(&format!("realize/{}", installed.profile.descriptor.id));
    guard
        .call(
            realization.clone(),
            None,
            Method::Realize,
            false,
            RealizeRequest {
                realization_id: installed.bootstrap.authority.realization_id.clone(),
                configuration: installed.profile.configuration_ref.clone(),
                requested_node_ids: vec![installed.profile.descriptor.id.clone()],
                resource_limits: installed.bootstrap.resource_limits.clone(),
                extensions: Extensions::new(),
            },
        )
        .unwrap();
    guard
        .with_original_realization(&realization, |view| {
            installed.policy.authenticate_realization(&guard, &view)
        })
        .unwrap();
    let admitted = guard
        .call(
            id(&format!("admit/{}", installed.profile.descriptor.id)),
            None,
            Method::Admit,
            false,
            AdmitRequest {
                bindings: vec![installed.binding.clone()],
                world_binding_hash: installed.bootstrap.world_binding_hash.clone(),
                admission_receipt: installed.bootstrap.admission_receipt.clone(),
                extensions: Extensions::new(),
            },
        )
        .unwrap();
    let Some(MethodResult::Admit(admitted)) = admitted.result else {
        panic!("original selected admission failed")
    };
    assert_eq!(
        admitted.accepted_binding_hashes,
        vec![installed.binding.identity().unwrap()]
    );
    LineageControlledReference::from_original(
        guard,
        realization,
        Box::new(PolicyHandle(installed.policy.clone())),
        runtime_slot,
        16,
    )
    .unwrap_or_else(|failure| panic!("selected control refused: {}", failure.error))
}

struct World {
    graph: Option<AdmittedGraph>,
    activation: Option<WorldActivation>,
    runtime: Option<NodeRuntime>,
    pending_slot: Option<Box<dyn RuntimeCustodySlot>>,
    queue: RuntimeCustodyQueue,
    retention_failed: Rc<Cell<bool>>,
    source: Vec<Rc<RefCell<Option<LineageSourceCustody>>>>,
    host: Vec<Rc<RefCell<Option<LineageRuntimeCustody>>>>,
    directory: Option<tempfile::TempDir>,
    policies: Vec<Rc<InstalledReaderPolicy>>,
    observations: Vec<Rc<RefCell<Option<ObservationHandle>>>>,
}

impl World {
    fn persist_observations(&self, root: &std::path::Path, suffix: &str) -> bool {
        let mut persisted = true;
        for (index, observation) in self.observations.iter().enumerate() {
            let result = (|| -> Result<(), ProviderError> {
                let slot = observation.try_borrow().map_err(|_| {
                    ProviderError::Correlation("original observer remains borrowed")
                })?;
                let document = match slot.as_ref() {
                    Some(handle) => {
                        let requests = handle.request_keys()?;
                        let contents = handle.content_references()?;
                        let original =
                            handle.snapshot(&requests, &contents, observation_limits())?;
                        serde_json::to_value(original).map_err(ContractError::from)?
                    }
                    None => serde_json::json!({"not_created": true}),
                };
                let bytes = canonical::canonical_json(&document)?;
                std::fs::write(
                    root.join(format!("original-peer-{index}{suffix}.json")),
                    bytes,
                )?;
                Ok(())
            })();
            if let Err(error) = result {
                persisted = false;
                eprintln!("original journal persistence unavailable: {error}");
            }
        }
        persisted
    }
}

impl Drop for World {
    fn drop(&mut self) {
        // Teardown may cross source callbacks and persistence code. An unwind
        // cannot bypass the owning actor's final custody fence.
        if catch_unwind(AssertUnwindSafe(|| self.retire_original())).is_err() {
            loop {
                std::thread::park_timeout(Duration::from_secs(1));
            }
        }
    }
}

impl World {
    fn retire_original(&mut self) {
        let root = self.directory.take().map(tempfile::TempDir::keep);
        let mut originals_persisted = false;
        if let Some(root) = &root {
            eprintln!("original reader evidence retained: {}", root.display());
            originals_persisted = self.persist_observations(root, "");
        }
        drop(self.runtime.take());
        drop(self.pending_slot.take());
        let mut context = Context::from_waker(Waker::noop());
        let mut reclaimed = false;
        for _ in 0..10_000 {
            let _ = self.queue.poll_reclamation(&mut context);
            let host_done = self.host.iter().all(|slot| {
                slot.try_borrow_mut().is_ok_and(|mut retained| {
                    retained
                        .as_mut()
                        .is_none_or(|capsule| capsule.poll_reclamation().unwrap_or(false))
                })
            });
            let source_done = self.source.iter().all(|slot| {
                slot.try_borrow_mut().is_ok_and(|mut retained| {
                    retained
                        .as_mut()
                        .is_none_or(|capsule| capsule.poll_reclamation().unwrap_or(false))
                })
            });
            if self.queue.reserved_worlds() == 0
                && host_done
                && source_done
                && !self.retention_failed.get()
            {
                reclaimed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Some(root) = &root {
            // Reclamation can append authentic Abort/Shutdown/Release originals.
            // Keep the earlier cutoff and this terminal cutoff as distinct archives.
            originals_persisted &= self.persist_observations(root, "-retired");
            let document = serde_json::json!({
                "schema":"crucible.reference.reader-three-peer.retirement.v1",
                "original_world_reserved":self.queue.reserved_worlds(),
                "all_original_capsules_reclaimed":reclaimed,
                "all_original_journals_persisted":originals_persisted,
                "slot_retention_failed":self.retention_failed.get(),
                "class_accepted":false,
            });
            match canonical::canonical_json(&document) {
                Ok(bytes) => {
                    if let Err(error) = std::fs::write(root.join("original-retirement.json"), bytes)
                    {
                        originals_persisted = false;
                        eprintln!("retirement persistence unavailable: {error}");
                    }
                }
                Err(error) => {
                    originals_persisted = false;
                    eprintln!("retirement encoding unavailable: {error}");
                }
            }
        }
        if !reclaimed || !originals_persisted {
            eprintln!("original reader world remains under retained UNKNOWN custody");
            // The owning actor remains alive on unresolved native custody.
            // A leaked Rc followed by process exit would not supervise either group.
            eprintln!("reader actor parked with its original complete capsule population");
            loop {
                std::thread::park_timeout(Duration::from_secs(1));
            }
        }
    }
}

impl World {
    fn prepare(package: Rc<InstalledReaderPackage>) -> Self {
        let profiles = ["disk", "link", "source"]
            .into_iter()
            .map(|node| {
                package
                    .profile(
                        id(node),
                        id(&format!("{node}-owner")),
                        U64::new(1000),
                        U64::new(1_000_000_000),
                        node == "source",
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let caller = crucible_node_provider::conformance::measure_executable(std::path::Path::new(
            "/proc/self/exe",
        ))
        .unwrap();
        let fixture = canonical::canonical_json(&serde_json::json!({
            "schema": "crucible.reference.reader-three-peer.candidate.v1",
            "installed_package": package.identity(),
            "actual_host_executable": caller,
            "namespace_policy": "exact predeclared installed package and regenerated durable facet/compat only",
            "dynamic_input": "owning selected source reader under sealed runtime original input capability",
            "cohort": {
                "quanta_per_peer": 3,
                "initial_quantum_order": ["source", "link", "disk"],
                "subsequent_quantum_order": ["disk", "link", "source"],
                "route_latency_ps": 0,
                "maximum_pending_events_per_route": 1,
                "maximum_pending_bytes_per_route": 4096
            },
            "transport_limits": {
                "journal_entries": 4096,
                "maximum_outstanding_requests": 32,
                "frame_bytes": 1048576,
                "host_original_request_entries_per_lane": 4096,
                "host_content_objects": 4096,
                "host_content_bytes": 16777216
            },
            "class_accepted": false,
            "adverse_source_inspection": include_str!("namespace_tests.rs"),
            "observation_limits": {
                "maximum_requests": 4096,
                "maximum_objects": 4096,
                "maximum_bytes": 33554432
            },
            "sources": {
                "fixture": include_str!("tests.rs"),
                "policy": include_str!("policy.rs"),
                "package": include_str!("package.rs"),
                "definition": include_str!("definition.rs"),
                "namespace": include_str!("extension.rs"),
                "native": include_str!("native.rs"),
                "graph": include_str!("graph.rs"),
                "owning_cleanup": include_str!("../../../../../crucible/src/node_adapters/cnp/lineage_reader/lifecycle.rs"),
                "selected_input": include_str!("../../../../../crucible/src/node_adapters/cnp/lineage_reader/input.rs"),
                "selected_boundary": include_str!("../../../../../crucible/src/node_adapters/cnp/lineage_reader/boundary.rs"),
                "selected_publication": include_str!("../../../../../crucible/src/node_adapters/cnp/lineage_reader/publication.rs"),
                "selected_native_rows": include_str!("../../../../../crucible/src/node_adapters/cnp/lineage_reader/window_evidence.rs"),
                "runtime_original_lineage": include_str!("../../../../../crucible/src/node_contract/runtime_original_input_lineage.rs"),
                "runtime_original_geometry": include_str!("../../../../../crucible/src/node_contract/runtime_original_input_lineage/geometry.rs"),
                "runtime_original_assembly": include_str!("../../../../../crucible/src/node_contract/runtime_original_input_lineage/assembly.rs")
            }
        }))
        .unwrap();
        let artifacts = BTreeMap::from([
            (
                package.provider().content.clone(),
                package.provider().path.clone(),
            ),
            (
                package.device().content.clone(),
                package.device().path.clone(),
            ),
        ]);
        let definition = graph::Definition::build(&profiles, fixture, artifacts);
        let mut installations = profiles
            .into_iter()
            .map(|profile| installed(package.clone(), profile, &definition))
            .collect::<Vec<_>>();
        let extension = ReaderExtensionPolicy::new(
            package.clone(),
            definition.world.clone(),
            installations
                .iter()
                .map(|node| {
                    (
                        node.profile.descriptor.id.clone(),
                        (node.binding.clone(), node.policy.clone()),
                    )
                })
                .collect(),
        )
        .unwrap();
        let registry = extension.install().unwrap();
        let record = ActivationRecord {
            generation: installations[0].bootstrap.world_generation,
            activation_id: installations[0].bootstrap.activation_id.clone(),
            world_binding_hash: definition.world.identity().unwrap(),
            owners: installations
                .iter()
                .map(|node| OwnerIdentity {
                    owner: node.profile.owner.id.clone(),
                    incarnation: node.bootstrap.authority.incarnation_id.clone(),
                    generation: node.bootstrap.authority.owner_generation,
                })
                .collect(),
            boundary: position(0, Phase::BoundaryControl),
        };
        let queue = RuntimeCustodyQueue::new(1).unwrap();
        let slot = queue
            .reserve_world(&record, RuntimeLimits::default())
            .unwrap();
        let directory = tempfile::Builder::new()
            .prefix("lr-")
            .tempdir_in("/tmp")
            .unwrap();
        let source = (0..3)
            .map(|_| Rc::new(RefCell::new(None)))
            .collect::<Vec<_>>();
        let host = (0..3)
            .map(|_| Rc::new(RefCell::new(None)))
            .collect::<Vec<_>>();
        // The World owner exists before every Child and retains both consuming
        // slot populations if any preparation or graph admission unwinds.
        let mut world = Self {
            graph: None,
            activation: None,
            runtime: None,
            pending_slot: Some(slot),
            queue,
            retention_failed: Rc::new(Cell::new(false)),
            source,
            host,
            directory: Some(directory),
            observations: (0..3).map(|_| Rc::new(RefCell::new(None))).collect(),
            policies: installations
                .iter()
                .map(|node| node.policy.clone())
                .collect(),
        };
        let mut controls = Vec::with_capacity(3);
        for (index, installation) in installations.iter_mut().enumerate() {
            let source_slot = Box::new(SourceSlot {
                identity: U64::new(index as u64 + 1),
                retained: world.source[index].clone(),
                retention_failed: world.retention_failed.clone(),
            });
            let runtime_slot = Box::new(RuntimeSlot {
                identity: U64::new(index as u64 + 4),
                retained: world.host[index].clone(),
                retention_failed: world.retention_failed.clone(),
            });
            controls.push(launch(
                &package,
                installation,
                world
                    .directory
                    .as_ref()
                    .unwrap()
                    .path()
                    .join(installation.profile.descriptor.id.as_str()),
                source_slot,
                runtime_slot,
                &world.observations[index],
            ));
        }
        let graph = definition.admit(&installations, &registry);
        let nodes: Vec<Box<dyn SimulationNode>> = controls
            .into_iter()
            .zip(&installations)
            .map(|(control, installed)| {
                Box::new(
                    control
                        .into_node(&graph, &installed.profile.descriptor.id, 16)
                        .unwrap(),
                ) as Box<dyn SimulationNode>
            })
            .collect();
        let runtime = NodeRuntime::new(
            &graph,
            nodes,
            record.clone(),
            RuntimeLimits::default(),
            world.pending_slot.take().unwrap(),
        )
        .unwrap_or_else(|failure| {
            panic!("original complete reader world failed: {}", failure.error)
        });
        world.graph = Some(graph);
        world.runtime = Some(runtime);
        let runtime = world.runtime.as_mut().unwrap();
        runtime.arm_all().unwrap();
        let coordinator = runtime
            .initial_coordinator_snapshot(world.graph.as_ref().unwrap(), 1024 * 1024)
            .unwrap();
        let prepared = runtime.prepared_node_records().unwrap().to_vec();
        let store = world.directory.as_ref().unwrap().path().join("store");
        let mut publisher = StoredWorldActivationPublisher::new(
            Arc::new(DirectoryBlobBackend::new(
                "reader-original",
                store.join("blobs"),
            )),
            Arc::new(DirectoryRefBackend::new(store.join("refs"))),
            RefName::new("node-world-activations/reader-original").unwrap(),
        )
        .unwrap()
        .with_prepared_coordinator(record, prepared, coordinator)
        .unwrap();
        let activation = runtime.activate(&mut publisher).unwrap();
        assert_eq!(activation.prepared_owners().unwrap().len(), 3);
        world.activation = Some(activation);
        world
    }
}

fn observation_limits() -> ObservationLimits {
    ObservationLimits {
        maximum_requests: 4096,
        maximum_objects: 4096,
        maximum_bytes: 32 * 1024 * 1024,
    }
}

fn position(tick: u64, phase: Phase) -> Position {
    Position::new(U64::new(tick), U64::new(0), phase)
}

fn quantum(world: &mut World, node: &Id, index: u64) -> serde_json::Value {
    let runtime = world.runtime.as_mut().unwrap();
    let activation = world.activation.as_ref().unwrap().clone();
    let graph = world.graph.as_ref().unwrap();
    let stage = id(&format!("stage/{node}/{index}"));
    let batch = id(&format!("batch/{node}/{index}"));
    let input = runtime
        .scheduler(graph, &activation)
        .unwrap()
        .prepare_input_batch(
            node,
            stage.clone(),
            batch.clone(),
            position(index * 1000 + 1, Phase::BoundaryControl),
        )
        .unwrap();
    let deliveries = input.deliveries().to_vec();
    runtime.stage_inputs(input).unwrap();
    let acknowledgement = runtime.recover_input_staging(&activation, &stage).unwrap();
    let accepted = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();
    runtime.commit_input_staging(&accepted).unwrap();
    let grant = runtime
        .scheduler(graph, &activation)
        .unwrap()
        .admit_quantum(
            node,
            id(&format!("run/{node}/{index}")),
            id(&format!("window/{node}/{index}")),
            batch,
        )
        .unwrap();
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
        panic!("original selected quantum did not begin")
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(runtime.poll(&token, &mut context), Poll::Pending));
    assert_eq!(runtime.close_quantum(&token).unwrap(), Submission::Accepted);
    let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut context) else {
        panic!("original selected window did not close")
    };
    let scheduling = outcome.scheduling.as_ref().unwrap();
    assert_eq!(scheduling.publications.len(), 1);
    assert!(scheduling.publications[0].causal_parents.is_empty());
    let publication = scheduling.publications[0].clone();
    assert_eq!(
        publication.publication_id,
        id(&format!("checksum-{}", index + 1))
    );
    assert_eq!(publication.native_sequence, U64::new(index + 1));
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    serde_json::json!({
        "node": node,
        "quantum": index,
        "deliveries": deliveries,
        "publication": publication,
        "acknowledged": true
    })
}

#[test]
#[ignore = "requires the exact predeclared source-built reader implementation manifest"]
fn actual_installed_reader_source_link_disk_preserves_original_input_and_native_checksum() {
    let manifest = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_LINEAGE_READER_IMPLEMENTATION_MANIFEST")
            .expect("reader implementation must be bound"),
    );
    let original =
        canonical::content_ref(include_bytes!("installed-fixture.json"), "application/json")
            .unwrap();
    let package = InstalledReaderPackage::load(&manifest, &original).unwrap();
    assert_eq!(package.document(), include_bytes!("installed-fixture.json"));
    let mut world = World::prepare(package);
    let mut windows = Vec::new();
    for index in 0..3 {
        // The first source-first pass establishes authentic production bounds.
        // Later sink-first passes drain each one-entry route before publication.
        let ordered_nodes = if index == 0 {
            ["source", "link", "disk"]
        } else {
            ["disk", "link", "source"]
        };
        for node in ordered_nodes {
            let original = quantum(&mut world, &id(node), index);
            let bytes = canonical::canonical_json(&original).unwrap();
            std::fs::write(
                world
                    .directory
                    .as_ref()
                    .unwrap()
                    .path()
                    .join(format!("original-window-{}.json", windows.len())),
                bytes,
            )
            .unwrap();
            windows.push(original);
        }
    }
    let source_witnesses = world
        .policies
        .iter()
        .map(|policy| policy.witnesses().unwrap())
        .collect::<Vec<_>>();
    verify_original_three_peer_chain(&windows, &source_witnesses);
    let original = serde_json::json!({
        "schema": "crucible.reference.reader-three-peer.original.v1",
        "class_accepted": false,
        "windows": windows,
        "source_witnesses": source_witnesses
    });
    let bytes = canonical::canonical_json(&original).unwrap();
    std::fs::write(
        world
            .directory
            .as_ref()
            .unwrap()
            .path()
            .join("original-windows.json"),
        bytes,
    )
    .unwrap();
    eprintln!(
        "original reader evidence: {}",
        world.directory.as_ref().unwrap().path().display()
    );
}

// This checks actual retained publications and deliveries, not a reconstructed
// parent-ID graph. Earlier input ancestry remains distinct from same-time causes.
fn verify_original_three_peer_chain(
    windows: &[serde_json::Value],
    witnesses: &[Vec<serde_json::Value>],
) {
    let window = |node: &str, quantum: u64| {
        windows
            .iter()
            .find(|row| row["node"] == node && row["quantum"] == quantum)
            .unwrap()
    };
    let witness = |node: &str, quantum: u64| {
        witnesses
            .iter()
            .flatten()
            .find(|row| {
                row["node"] == node
                    && row["stage"]["grant"]["quantum"]
                        .as_str()
                        .and_then(|value| value.parse::<u64>().ok())
                        == Some(quantum)
            })
            .unwrap()
    };

    assert_eq!(windows.len(), 9);
    for originals in witnesses {
        assert_eq!(originals.len(), 3);
    }
    for (producer, producer_quantum, consumer, consumer_quantum) in
        [("source", 0, "link", 1), ("link", 1, "disk", 2)]
    {
        let original = window(producer, producer_quantum);
        let accepted = window(consumer, consumer_quantum);
        let publication = &original["publication"];
        let deliveries = accepted["deliveries"].as_array().unwrap();
        assert_eq!(deliveries.len(), 1);
        let delivery = &deliveries[0];

        assert_eq!(delivery["producer_endpoint"], publication["endpoint"]);
        assert_eq!(delivery["publication_id"], publication["publication_id"]);
        assert_eq!(delivery["native_sequence"], publication["native_sequence"]);
        assert_eq!(delivery["publication"], publication["publication"]);
        assert_eq!(delivery["payload"], publication["payload"]);
        assert_eq!(delivery["consumer"], consumer);
        assert_eq!(delivery["producer"], producer);
        assert_eq!(delivery["causal_parents"], serde_json::json!([]));
        assert_eq!(publication["causal_parents"], serde_json::json!([]));
        assert_eq!(original["acknowledged"], true);
        assert_eq!(accepted["acknowledged"], true);
        assert_eq!(
            delivery["provenance_ref"],
            witness(producer, producer_quantum)["measurement"]
        );

        let consumed = witness(consumer, consumer_quantum);
        assert_eq!(consumed["stage"]["entries"].as_array().unwrap().len(), 1);
        assert_eq!(
            consumed["stage"]["entries"][0]["payload"],
            publication["payload"]
        );
        let previous: NativeLineageReceipt =
            serde_json::from_value(witness(consumer, consumer_quantum - 1)["receipt"].clone())
                .unwrap();
        assert_eq!(
            consumed["receipt"]["previous_closed"],
            serde_json::to_value(previous.identity().unwrap()).unwrap()
        );
    }
}
