//! Runs the private installed candidate through actual common-runtime windows.
//!
//! The owning thread keeps both custody queues outside callback unwind scopes.
//! A run result is observational evidence; it does not accept the full normative
//! population or supply an ordinary factory qualification token.

use crucible::{
    node_contract::{
        ActivationPublisher, ActivationRecord, NodeRuntime, PreparedWorldPublication,
        PublicationStatus, RuntimeCustodyQueue, RuntimeCustodySupervisor, RuntimeError,
        RuntimeLimits, SimulationNode, ValidatedNodePreparation,
    },
    node_scheduling::InputPayload,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
    MutableRefBackend, ObjectKind, RefName,
};
use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    client::{ObservationHandle, ObservationLimits},
    reference_device::DeviceGrant,
};
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, mpsc},
    task::{Context, Poll, Waker},
    time::Duration,
};

static QUALIFICATION_ACTOR_RESERVED: AtomicBool = AtomicBool::new(false);

struct QualificationActorLease;

impl Drop for QualificationActorLease {
    fn drop(&mut self) {
        QUALIFICATION_ACTOR_RESERVED.store(false, Ordering::Release);
    }
}

use super::{
    candidate::{PrivateCandidate, entropy},
    criteria::ReferenceQualificationCriteria,
    custody::PublicReferenceCustodyQueue,
    launch::{ObservedPublicPreparation, PublicLaunchRequest, launch},
    package::InstalledPublicReferencePackage,
    unit::SemanticQualificationUnit,
    witness::{OriginalPublicWindowWitness, collect_original_windows},
};
use crate::node_observed_executor::activation::StoredWorldActivationPublisher;
use crate::node_qualification::{
    ReferenceExpectedWindow, ReferenceOracleContract, ReferenceWindowObservation,
};
use crate::node_qualification::{ReferenceWindowCase, collect_reference_window};

/// Retains the durable original result after authentic native reclamation.
pub(super) struct CandidateHarnessResult {
    original_result: ContentId,
    retirement_result: ContentId,
    succeeded: bool,
    original_bytes: Vec<u8>,
    retirement_bytes: Vec<u8>,
    unit: Option<SemanticQualificationUnit>,
    criteria: Option<ReferenceQualificationCriteria>,
    population_result: Option<ContentId>,
}

impl CandidateHarnessResult {
    pub(super) fn original_result(&self) -> ContentId {
        self.original_result
    }

    pub(super) fn retirement_result(&self) -> ContentId {
        self.retirement_result
    }

    pub(super) fn population_result(&self) -> Option<ContentId> {
        self.population_result
    }

    pub(super) fn succeeded(&self) -> bool {
        self.succeeded
    }

    pub(super) fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }

    pub(super) fn retirement_bytes(&self) -> &[u8] {
        &self.retirement_bytes
    }

    /// Borrows the source-measured plan installed before the first native child.
    pub(super) fn qualification_context(
        &self,
    ) -> Option<(&SemanticQualificationUnit, &ReferenceQualificationCriteria)> {
        Some((self.unit.as_ref()?, self.criteria.as_ref()?))
    }
}

/// Starts a source-owned actor; dropping the receiver cannot drop native custody.
pub(super) fn start(
    directory: PathBuf,
) -> Result<
    mpsc::Receiver<Result<CandidateHarnessResult, super::run_error::QualificationRunError>>,
    std::io::Error,
> {
    QUALIFICATION_ACTOR_RESERVED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "installed qualification actor already reserved",
            )
        })?;
    let lease = QualificationActorLease;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("reference-qualification".into())
        .spawn(move || {
            let _lease = lease;
            let result =
                run_actor(directory).map_err(super::run_error::QualificationRunError::from);
            let _ = sender.send(result);
        })?;
    Ok(receiver)
}

struct Actor {
    private: PathBuf,
    blobs: Arc<DirectoryBlobBackend>,
    refs: Arc<DirectoryRefBackend>,
    peers: PublicReferenceCustodyQueue,
    worlds: RuntimeCustodyQueue,
    runtime: Option<NodeRuntime>,
    candidate: Option<PrivateCandidate>,
    observers: Vec<Rc<RefCell<Option<ObservationHandle>>>>,
    windows: Vec<Vec<ReferenceWindowObservation>>,
    runtime_retries: Vec<Vec<super::runtime_retries::RuntimeCachedRecovery>>,
    probes: Vec<serde_json::Value>,
    prepared_probes: Vec<serde_json::Value>,
    phase: &'static str,
    planned: Vec<Vec<ReferenceWindowCase>>,
    oracles: Vec<ReferenceOracleContract>,
    unit: Option<SemanticQualificationUnit>,
    criteria: Option<ReferenceQualificationCriteria>,
}

fn run_actor(directory: PathBuf) -> Result<CandidateHarnessResult, ProviderError> {
    use std::os::unix::fs::DirBuilderExt;
    if !directory.is_absolute() {
        return Err(ProviderError::Frame(
            "qualification directory must be absolute",
        ));
    }
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let mut actor = Actor {
        blobs: Arc::new(DirectoryBlobBackend::new(
            "installed-reference-qualification",
            directory.join("blobs"),
        )),
        refs: Arc::new(DirectoryRefBackend::new(directory.join("refs"))),
        private: directory.join("native"),
        peers: PublicReferenceCustodyQueue::new(2)?,
        worlds: RuntimeCustodyQueue::new(1).map_err(failure)?,
        runtime: None,
        candidate: None,
        observers: (0..2).map(|_| Rc::new(RefCell::new(None))).collect(),
        windows: (0..2).map(|_| Vec::with_capacity(3)).collect(),
        runtime_retries: (0..2).map(|_| Vec::with_capacity(3)).collect(),
        probes: Vec::with_capacity(2),
        prepared_probes: Vec::with_capacity(2),
        phase: "source-enrollment",
        planned: Vec::with_capacity(2),
        oracles: Vec::with_capacity(2),
        unit: None,
        criteria: None,
    };
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&actor.private)?;
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| actor.execute()));
    let result = match attempt {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("original native callback unwound".into()),
    };
    let succeeded = result.is_ok();
    let source_roots = actor.peers.source_roots();
    // Encoding and storage do not discharge native custody. Reclaim originals
    // first, retaining the result value even if its encoding has not succeeded.
    drop(actor.runtime.take());
    let mut context = Context::from_waker(Waker::noop());
    let mut original_peers = Vec::with_capacity(2);
    loop {
        let world = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            actor.worlds.poll_reclamation(&mut context)
        }));
        let native = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            actor.peers.poll_reclamation()
        }));
        if matches!(world, Ok(Poll::Ready(Ok(())))) || actor.worlds.reserved_worlds() == 0 {
            while let Some(peer) = actor.peers.take_reclaimed() {
                original_peers.push(peer);
            }
        }
        if actor.worlds.reserved_worlds() == 0 && actor.peers.outstanding() == 0 {
            break;
        }
        // Disconnected receivers and repeated native callback errors cannot turn
        // owning supervision into a busy loop or destroy the original objects.
        let _ = native;
        std::thread::sleep(Duration::from_millis(10));
    }
    // A permanent storage failure leaves this same owning actor alive with the
    // original journals. A lost storage acknowledgement retries the identical
    // write-once identities; it cannot replace failed evidence with a new run.
    let (original_result, original_bytes, retirement_result, retirement_bytes) = loop {
        let retained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let failed_original;
            let original = match &result {
                Ok(original) => original,
                Err(error) => {
                    failed_original = actor.failed_original(error);
                    &failed_original
                }
            };
            let original_bytes = canonical::canonical_json(original)?;
            let original_result = actor.persist(&original_bytes, "qualification/original")?;
            let retirement_bytes = canonical::canonical_json(&serde_json::json!({
                "schema":"crucible.reference.candidate-retirement.v1", "original_result":original_result.encode(),
                "reclaimed_original_peers": original_peers.len(), "world_reservations":actor.worlds.reserved_worlds(),
                "original_source_roots":source_roots,
                "original_scopes":original_peers.iter().map(|peer| serde_json::json!({
                    "activation":crucible::node_contract::SavedRuntimeActivation::from(&peer.scope.activation),
                    "owner":peer.scope.owner,"implementation":peer.scope.implementation,
                    "original_provider_pid":peer.custody.provider_pid(),
                    "publication":publication_name(peer.scope.publication),
                    "original_private_launch_bytes":peer.scope.private_launch.len(),
                    "original_private_hello_bytes":peer.scope.original_hello.len(),
                })).collect::<Vec<_>>()
            }))?;
            let retirement_result = actor.persist(&retirement_bytes, "qualification/retirement")?;
            Ok::<_, ProviderError>((
                original_result,
                original_bytes,
                retirement_result,
                retirement_bytes,
            ))
        }));
        if let Ok(Ok(retained)) = retained {
            break retained;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut original = CandidateHarnessResult {
        original_result,
        retirement_result,
        succeeded,
        original_bytes,
        retirement_bytes,
        unit: actor.unit.take(),
        criteria: actor.criteria.take(),
        population_result: None,
    };
    if original.qualification_context().is_some() {
        // The plan was retained before first Child. Keep original native
        // journals alive until the full population, including missing cases,
        // is durable; dropping a caller cannot discard failed original rows.
        loop {
            let issued = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let issued = super::issuer::issue_report(&original).map_err(failure)?;
                actor.persist_population(&original, &issued)
            }));
            if let Ok(Ok(reference)) = issued {
                original.population_result = Some(reference);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    // Complete private native journals remain owned until every original root
    // and the full declared population are durable. Secrets are never emitted.
    drop(original_peers);
    Ok(original)
}

fn publication_name(status: Option<PublicationStatus>) -> &'static str {
    match status {
        None => "not_attempted",
        Some(PublicationStatus::NotCommitted) => "not_committed",
        Some(PublicationStatus::Committed) => "committed",
        Some(PublicationStatus::Unknown) => "unknown",
    }
}

impl Actor {
    fn persist_population(
        &self,
        original: &CandidateHarnessResult,
        issued: &crate::node_qualification::IssuedQualification,
    ) -> Result<ContentId, ProviderError> {
        let (unit, criteria) = original
            .qualification_context()
            .ok_or(ProviderError::Frame(
                "original predeclared source context absent",
            ))?;
        let mut objects = std::collections::BTreeMap::new();
        for (reference, bytes) in unit.objects.iter().chain(criteria.objects.iter()) {
            reference.verify(bytes)?;
            if objects
                .insert(reference.clone(), bytes.as_slice())
                .is_some_and(|first| first != bytes)
            {
                return Err(ProviderError::Correlation("source evidence object changed"));
            }
        }
        for (reference, bytes) in issued.objects() {
            reference.verify(bytes.as_slice())?;
            if objects
                .insert(reference.clone(), bytes.as_slice())
                .is_some_and(|first| first != bytes.as_slice())
            {
                return Err(ProviderError::Correlation(
                    "issued original evidence object changed",
                ));
            }
        }
        let mut roots = Vec::with_capacity(objects.len());
        for (index, (reference, bytes)) in objects.into_iter().enumerate() {
            let object =
                self.persist(bytes, &format!("qualification/population/object/{index}"))?;
            roots.push(serde_json::json!({"reference":reference,"object":object.encode()}));
        }
        let report = self.persist(issued.bytes(), "qualification/population/report")?;
        let inspection = super::metadata_inspection::inspect(original, issued).map_err(failure)?;
        let inspection_bytes = canonical::canonical_json(
            &serde_json::to_value(inspection)
                .map_err(crucible_node_contract::ContractError::from)?,
        )?;
        let inspection_root =
            self.persist(&inspection_bytes, "qualification/metadata-inspection")?;
        let package = self
            .candidate
            .as_ref()
            .ok_or(ProviderError::Frame("original package absent"))?
            .installations[0]
            .package
            .clone();
        let artifact_plan = package.artifact_measurement_plan().map_err(failure)?;
        let source_fixtures = unit
            .objects
            .get(&unit.identity.fixtures)
            .ok_or(ProviderError::Frame("original fixture absent"))?;
        let source_fixtures = canonical::parse_json(source_fixtures, 16 * 1024 * 1024)?;
        if source_fixtures["artifact_integrity_plan"] != artifact_plan.fixture() {
            return Err(ProviderError::Frame(
                "original artifact measurement plan changed",
            ));
        }
        let artifact_controls = artifact_plan.inspect(&package).map_err(failure)?;
        let artifact_bytes = canonical::canonical_json(
            &serde_json::to_value(artifact_controls)
                .map_err(crucible_node_contract::ContractError::from)?,
        )?;
        let artifact_root = self.persist(&artifact_bytes, "qualification/artifact-integrity")?;
        let envelope = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.reference.original-population-roots.v1",
            "report":issued.reference(),"report_object":report.encode(),
            "metadata_inspection":inspection_root.encode(),
            "artifact_integrity":artifact_root.encode(),
            "original_result":original.original_result().encode(),
            "retirement_result":original.retirement_result().encode(),
            "objects":roots,"qualification_accepted":false
        }))?;
        // The manifest is a sibling of the object/report directory. Directory
        // references cannot simultaneously use one name as a file and parent.
        self.persist(&envelope, "qualification/population-manifest")
    }

    /// Retains the original failed or incomplete population without retry labels.
    fn failed_original(&self, error: &str) -> serde_json::Value {
        let observations=self.observers.iter().map(|slot| {
            let slot=slot.borrow();
            let Some(observer)=slot.as_ref() else {
                return serde_json::json!({"recording_complete":false,"reason":"native observer not reached"});
            };
            let snapshot=(|| {
                let keys=observer.request_keys()?;
                let refs=observer.content_references()?;
                observer.snapshot(&keys,&refs,ObservationLimits {
                    maximum_requests:1024,maximum_objects:1024,maximum_bytes:8*1024*1024,
                })
            })();
            match snapshot {
                Ok(snapshot)=>serde_json::to_value(snapshot).unwrap_or_else(|_|serde_json::json!({"recording_complete":false,"reason":"original observation encoding refused"})),
                Err(_)=>serde_json::json!({"recording_complete":false,"reason":"original observation unavailable"}),
            }
        }).collect::<Vec<_>>();
        let candidate=self.candidate.as_ref().map(|candidate| serde_json::json!({
            "world":candidate.definition.world,
            "activation":crucible::node_contract::SavedRuntimeActivation::from(&candidate.activation),
            "predeclared_cases":self.planned.iter().map(|cases|cases.iter().map(|case|
                serde_json::json!({"stage":case.stage,"batch":case.batch,"operation":case.operation,"grant":case.grant,"input_cut":case.input_cut})
            ).collect::<Vec<_>>()).collect::<Vec<_>>(),
        }));
        serde_json::json!({"schema":"crucible.reference.candidate-failure.v1","phase":self.phase,
            "error":error,"candidate":candidate,"original_observations":observations,
            "original_completed_windows":self.windows,"original_runtime_retries":self.runtime_retries,"source_probes":self.probes,"prepared_probes":self.prepared_probes,"qualification_accepted":false})
    }

    fn persist(&self, bytes: &[u8], name: &str) -> Result<ContentId, ProviderError> {
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        let _guard = self.refs.acquire_publication_guard().map_err(failure)?;
        let receipt = self
            .blobs
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .map_err(failure)?;
        if !receipt.is_durable() {
            return Err(ProviderError::Frame("candidate evidence not durable"));
        }
        let reference = RefName::new(name).map_err(failure)?;
        match self
            .refs
            .compare_exchange(&reference, None, id)
            .map_err(failure)?
        {
            crucible_cas::content_store::RefCasOutcome::Advanced { next } if next == id => Ok(id),
            crucible_cas::content_store::RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == id => Ok(id),
            _ => Err(ProviderError::Correlation(
                "original candidate result slot differs",
            )),
        }
    }

    fn execute(&mut self) -> Result<serde_json::Value, ProviderError> {
        let package = InstalledPublicReferencePackage::built_in().map_err(failure)?;
        self.candidate = Some(PrivateCandidate::new(
            Rc::clone(&package),
            U64::new(1000),
            U64::new(1_000_000_000),
        )?);
        let candidate = self
            .candidate
            .as_mut()
            .ok_or(ProviderError::Frame("original candidate metadata absent"))?;
        self.phase = "predeclared-fixture";
        for installed in &candidate.installations {
            let cases = (0..3)
                .map(|quantum| window_case(installed, quantum))
                .collect::<Result<Vec<_>, _>>()?;
            self.oracles.push(oracle_contract(installed, &cases)?);
            self.planned.push(cases);
        }
        self.phase = "predeclared-qualification-unit";
        let unit = super::context::measure(candidate, &self.oracles)?;
        let criteria =
            ReferenceQualificationCriteria::build(unit.identity.clone()).map_err(failure)?;
        self.unit = Some(unit);
        self.criteria = Some(criteria);
        self.phase = "native-preparation";
        let slot = self
            .worlds
            .reserve_world(&candidate.activation, RuntimeLimits::default())
            .map_err(failure)?;
        let mut prepared = Vec::with_capacity(2);
        for (index, installed) in candidate.installations.iter_mut().enumerate() {
            prepared.push(launch(
                installed,
                &self.peers,
                PublicLaunchRequest {
                    directory: self.private.join(installed.profile.descriptor.id.as_str()),
                    activation: candidate.activation.clone(),
                    owner: candidate.activation.owners[index].clone(),
                    source_roots: vec![
                        package.identity().clone(),
                        candidate.definition.qualification().clone(),
                    ],
                    closed_ingress: index == 1,
                    hello_id: Id::new(format!("hello/{index}"))?,
                    connection_id: Id::new(format!("connection/{index}"))?,
                    controller_nonce: entropy()?,
                    observation_sink: Rc::clone(&self.observers[index]),
                    observation_limits: ObservationLimits {
                        maximum_requests: 1024,
                        maximum_objects: 1024,
                        maximum_bytes: 8 * 1024 * 1024,
                    },
                },
            )?);
        }
        self.phase = "complete-graph-admission";
        let graph = candidate.definition.admit_candidate(
            &candidate.installations,
            &prepared
                .iter()
                .map(|node| &node.prepared)
                .collect::<Vec<_>>(),
        )?;
        let mut observations = Vec::with_capacity(2);
        let mut nodes: Vec<Box<dyn SimulationNode>> = Vec::with_capacity(2);
        for (original, installed) in prepared.into_iter().zip(&candidate.installations) {
            let ObservedPublicPreparation {
                prepared,
                observations: observer,
                probe,
                prepared_probe,
            } = original;
            self.probes.push(probe);
            self.prepared_probes.push(prepared_probe);
            observations.push(observer);
            nodes.push(Box::new(
                prepared
                    .into_node(&graph, &installed.profile.descriptor.id, installed, 8)
                    .map_err(|error| failure(error.reason))?,
            ));
        }
        self.runtime = Some(
            NodeRuntime::new(
                &graph,
                nodes,
                candidate.activation.clone(),
                RuntimeLimits::default(),
                slot,
            )
            .map_err(|error| failure(&error.error))?,
        );
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(ProviderError::Frame("original candidate runtime absent"))?;
        self.phase = "actual-readiness";
        runtime.arm_all().map_err(failure)?;
        let coordinator = runtime
            .initial_coordinator_snapshot(&graph, 1024 * 1024)
            .map_err(failure)?;
        let stored = StoredWorldActivationPublisher::new(
            self.blobs.clone(),
            self.refs.clone(),
            RefName::new("node-world-activations/candidate").map_err(failure)?,
        )
        .map_err(failure)?
        .with_prepared_coordinator(
            candidate.activation.clone(),
            runtime.prepared_node_records().map_err(failure)?.to_vec(),
            coordinator.clone(),
        )
        .map_err(failure)?;
        let mut publisher = Publisher {
            stored,
            peers: self.peers.clone(),
            original: None,
        };
        self.phase = "complete-world-publication";
        let activation = runtime.activate(&mut publisher).map_err(failure)?;
        runtime.scheduler(&graph, &activation).map_err(failure)?;
        for node in graph.node_ids() {
            let observation = runtime
                .observe_scheduling(&activation, node)
                .map_err(failure)?;
            runtime
                .scheduler(&graph, &activation)
                .map_err(failure)?
                .accept_boundary_observation(observation)
                .map_err(failure)?;
        }
        self.phase = "original-native-windows";
        let mut context = Context::from_waker(Waker::noop());
        for (index, quantum) in [(1usize, 0usize), (0, 0), (0, 1), (1, 1), (0, 2), (1, 2)] {
            // The single connection credit remains in original custody until
            // consumer input ACK. Consume the pending prefix before granting
            // another producer window; no horizon or capacity is widened.
            let case = &self.planned[index][quantum];
            self.windows[index].push(
                collect_reference_window(runtime, &graph, &activation, case, &mut context)
                    .map_err(failure)?,
            );
            self.phase = "original-runtime-cached-recovery";
            let window = self.windows[index].last().ok_or(ProviderError::Frame(
                "original window unavailable for recovery",
            ))?;
            self.runtime_retries[index].push(super::runtime_retries::collect(
                runtime,
                &graph,
                &activation,
                case,
                window,
                &mut context,
            )?);
            self.phase = "original-native-windows";
        }
        self.phase = "independent-window-oracle";
        let mut witnesses = Vec::<OriginalPublicWindowWitness>::with_capacity(2);
        for (index, installed) in candidate.installations.iter().enumerate() {
            let contract = &self.oracles[index];
            witnesses.push(collect_original_windows(
                installed,
                &observations[index],
                contract,
                &activation,
                &self.windows[index],
            )?);
        }
        let original = publisher
            .original
            .ok_or(ProviderError::Frame("actual complete publication absent"))?;
        Ok(
            serde_json::json!({"schema":"crucible.reference.candidate-original.v1","implementation":package.identity(),
                "activation":crucible::node_contract::SavedRuntimeActivation::from(activation.record()),
                "source_probes":self.probes,"prepared_probes":self.prepared_probes,"runtime_cached_recovery":self.runtime_retries,"prepared_nodes":original.nodes(),"prepared_owners":original.prepared_owners(),"coordinator":coordinator,"windows":witnesses.iter().map(|witness|serde_json::json!({
                    "reference":witness.reference,"bytes":witness.bytes})).collect::<Vec<_>>()
            }),
        )
    }
}

struct Publisher {
    stored: StoredWorldActivationPublisher,
    peers: PublicReferenceCustodyQueue,
    original: Option<PreparedWorldPublication>,
}
impl ActivationPublisher for Publisher {
    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        self.stored.prepare_coordinator(record, nodes)
    }
    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.original = Some(prepared.clone());
        if self
            .peers
            .record_publication(record, prepared, PublicationStatus::Unknown)
            .is_err()
        {
            return PublicationStatus::Unknown;
        }
        let status = self.stored.publish_complete(record, prepared);
        if self
            .peers
            .record_publication(record, prepared, status)
            .is_err()
        {
            return PublicationStatus::Unknown;
        }
        status
    }
    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        if self.original.as_ref() != Some(prepared)
            || self
                .peers
                .record_publication(record, prepared, PublicationStatus::Unknown)
                .is_err()
        {
            return PublicationStatus::Unknown;
        }
        let status = self.stored.reconcile_complete(record, prepared);
        if self
            .peers
            .record_publication(record, prepared, status)
            .is_err()
        {
            return PublicationStatus::Unknown;
        }
        status
    }
    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::NotCommitted
    }
    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Unknown
    }
}

pub(super) fn window_case(
    installed: &super::installation::SourcePublicReferenceInstallation,
    quantum: u64,
) -> Result<ReferenceWindowCase, ProviderError> {
    let name = installed.profile.descriptor.id.as_str();
    let time = quantum
        .checked_mul(installed.bootstrap.quantum_ps.get())
        .ok_or(ProviderError::Frame("candidate window overflow"))?;
    let end = time
        .checked_add(installed.bootstrap.quantum_ps.get())
        .ok_or(ProviderError::Frame("candidate window overflow"))?;
    let batch = Id::new(format!("candidate/{name}/batch/{quantum}"))?;
    Ok(ReferenceWindowCase {
        node: installed.profile.descriptor.id.clone(),
        stage: Id::new(format!("candidate/{name}/stage/{quantum}"))?,
        batch: batch.clone(),
        operation: Id::new(format!("candidate/{name}/operation/{quantum}"))?,
        input_cut: Position::new(
            U64::new(
                time.checked_add(1)
                    .ok_or(ProviderError::Frame("candidate sampling overflow"))?,
            ),
            U64::new(0),
            Phase::BoundaryControl,
        ),
        grant: DeviceGrant {
            owner_id: installed.profile.owner.id.clone(),
            incarnation_id: installed.bootstrap.authority.incarnation_id.clone(),
            generation: installed.bootstrap.authority.owner_generation,
            window_id: Id::new(format!("candidate/{name}/window/{quantum}"))?,
            input_batch_id: batch,
            quantum: U64::new(quantum),
            start: Position::new(U64::new(time), U64::new(0), Phase::BoundaryControl),
            publication: Position::new(U64::new(end), U64::new(0), Phase::Publication),
            host_budget_ns: installed.bootstrap.host_budget_ns,
        },
    })
}

pub(super) fn oracle_contract(
    installed: &super::installation::SourcePublicReferenceInstallation,
    cases: &[ReferenceWindowCase],
) -> Result<ReferenceOracleContract, ProviderError> {
    let expected_payload = br#"{"bytes_processed":"0","checksum":"0"}"#;
    let input = canonical::content_ref(expected_payload, "application/octet-stream")?;
    let empty = canonical::content_ref(b"", "application/octet-stream")?;
    let expected = cases
        .iter()
        .enumerate()
        .map(|(index, case)| {
            Ok(ReferenceExpectedWindow {
                window: case.grant.window_id.clone(),
                batch: case.batch.clone(),
                input: if installed.profile.descriptor.id.as_str() == "consumer" && index >= 1 {
                    input.clone()
                } else {
                    empty.clone()
                },
            })
        })
        .collect::<Result<Vec<_>, ProviderError>>()?;
    Ok(ReferenceOracleContract {
        owner: installed.profile.owner.id.clone(),
        incarnation: installed.bootstrap.authority.incarnation_id.clone(),
        generation: installed.bootstrap.authority.owner_generation,
        quantum_ps: installed.bootstrap.quantum_ps,
        host_budget_ns: installed.bootstrap.host_budget_ns,
        first_quantum: U64::new(0),
        first_time_ps: U64::new(0),
        initial_checksum: U64::new(0),
        maximum_windows: 3,
        maximum_input_bytes: 4096,
        expected_windows: expected,
    })
}
fn failure(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Actual native fixture failure must fail the test
// crucible-lint: allow rust-allow -- Actual native fixture failure must fail the test
#[allow(
    clippy::unwrap_used,
    reason = "Actual native fixture failure must fail the test"
)]
mod source_probe_native_test {
    use super::*;
    #[test]
    #[ignore = "requires compiled installed source-built reference implementation package"]
    fn actual_guarded_pre_realization_refusals_preserve_original_native_world() {
        let nonce = super::super::candidate::entropy().unwrap();
        let short = nonce
            .as_slice()
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = PathBuf::from(format!("/tmp/p-probes-{short}"));
        let receiver = super::start(path.clone()).unwrap();
        let original = receiver.recv().unwrap().unwrap();
        assert!(
            original.succeeded(),
            "failed original retained at {}",
            path.display()
        );
        let value = canonical::parse_json(original.original_bytes(), 16 * 1024 * 1024).unwrap();
        let probes = value["source_probes"].as_array().unwrap();
        assert_eq!(probes.len(), 2);
        for probe in probes {
            assert_eq!(
                probe["premises"]["provider_before"],
                probe["premises"]["provider_after"]
            );
            assert_eq!(
                probe["premises"]["controls"]["cases"]
                    .as_array()
                    .unwrap()
                    .len(),
                3
            );
            let bytes: Vec<u8> =
                serde_json::from_value(probe["original_snapshot_bytes"].clone()).unwrap();
            let snapshot = canonical::parse_json(&bytes, 1024 * 1024).unwrap();
            assert_eq!(snapshot["recording_complete"], true);
            assert_eq!(snapshot["observed_unknown"], false);
            assert_eq!(
                snapshot["evidence"]["requests"].as_array().unwrap().len(),
                3
            );
        }
        eprintln!(
            "source-built provider-only cohort: six original rejected controls, two unchanged native premises, full common world/windows/oracle/reap; original {}",
            original.original_result().encode()
        );
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Actual native fixture failure must fail the test
// crucible-lint: allow rust-allow -- Actual native fixture failure must fail the test
#[allow(
    clippy::unwrap_used,
    reason = "Actual native fixture failure must fail the test"
)]
mod prepared_adverse_native_test {
    use super::*;

    #[test]
    #[ignore = "requires compiled installed source-built reference implementation package"]
    fn actual_prepared_adverse_controls_preserve_original_first_native_quantum() {
        let nonce = super::super::candidate::entropy().unwrap();
        let short = nonce
            .as_slice()
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = PathBuf::from(format!("/tmp/pp-probes-{short}"));
        let original = super::start(path.clone()).unwrap().recv().unwrap().unwrap();
        assert!(
            original.succeeded(),
            "failed original retained at {}",
            path.display()
        );
        let value = canonical::parse_json(original.original_bytes(), 16 * 1024 * 1024).unwrap();
        let probes = value["prepared_probes"].as_array().unwrap();
        assert_eq!(probes.len(), 2);
        for probe in probes {
            let premises = &probe["premises"];
            assert_eq!(premises["provider_before"], premises["provider_after"]);
            assert_eq!(premises["controls"]["cases"].as_array().unwrap().len(), 6);
            assert_eq!(premises["controls"]["unchanged_pending_page"], true);
            assert_eq!(
                premises["initial_gate"]["schema"],
                "crucible.reference.original-prepared-gate.v1"
            );
            let bytes: Vec<u8> =
                serde_json::from_value(probe["original_snapshot_bytes"].clone()).unwrap();
            let snapshot = canonical::parse_json(&bytes, 1024 * 1024).unwrap();
            assert_eq!(snapshot["recording_complete"], true);
            assert_eq!(snapshot["observed_unknown"], false);
            assert_eq!(
                snapshot["evidence"]["requests"].as_array().unwrap().len(),
                6
            );
        }
        let owners = value["windows"].as_array().unwrap();
        let recoveries = value["runtime_cached_recovery"].as_array().unwrap();
        assert_eq!(recoveries.len(), 2);
        for owner in recoveries {
            let windows = owner.as_array().unwrap();
            assert_eq!(windows.len(), 3);
            for recovery in windows {
                for (reference_field, bytes_field) in [
                    ("outcome", "outcome_bytes"),
                    ("visible_coordinator", "visible_coordinator_bytes"),
                ] {
                    let reference: ContentRef =
                        serde_json::from_value(recovery[reference_field].clone()).unwrap();
                    let bytes: Bytes =
                        serde_json::from_value(recovery[bytes_field].clone()).unwrap();
                    reference.verify(bytes.as_slice()).unwrap();
                }
            }
        }
        assert_eq!(owners.len(), 2);
        for owner in owners {
            let bytes: Bytes = serde_json::from_value(owner["bytes"].clone()).unwrap();
            let reference: ContentRef = serde_json::from_value(owner["reference"].clone()).unwrap();
            reference.verify(bytes.as_slice()).unwrap();
            let witness = canonical::parse_json(bytes.as_slice(), 8 * 1024 * 1024).unwrap();
            assert_eq!(witness["windows"].as_array().unwrap().len(), 3);
            assert_eq!(witness["windows"][0]["original_grant"]["quantum"], "0");
            assert_eq!(witness["independent_oracle"]["windows"], "3");
            let cycles = &witness["supported_cycles"]["cycles"];
            assert_eq!(cycles.as_array().unwrap().len(), 3);
            for cycle in cycles.as_array().unwrap() {
                let sequences = ["input", "begin", "close", "consumption"].map(|kind| {
                    serde_json::from_value::<U64>(cycle[kind]["wire_sequence"].clone()).unwrap()
                });
                assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
            }
            let supported = &witness["supported_preparation"];
            assert_eq!(
                supported["schema"],
                "crucible.reference.original-supported-preparation.v1"
            );
            let mut previous = 0;
            for control in [
                "discovery",
                "realization",
                "admission",
                "readiness",
                "global_activation",
            ] {
                let sequence: U64 =
                    serde_json::from_value(supported[control]["wire_sequence"].clone()).unwrap();
                assert!(sequence.get() > previous);
                previous = sequence.get();
                let request: ContentRef =
                    serde_json::from_value(supported[control]["request"].clone()).unwrap();
                let response: ContentRef =
                    serde_json::from_value(supported[control]["response"].clone()).unwrap();
                assert!(request.length.get() > 0 && response.length.get() > 0);
            }
        }
        let retired = canonical::parse_json(original.retirement_bytes(), 1024 * 1024).unwrap();
        assert_eq!(retired["reclaimed_original_peers"], 2);
        assert_eq!(retired["world_reservations"], 0);
        eprintln!(
            "source-built original prepared cohort persisted at {}: twelve controls, authentic unsupported and body-scope refusals, original gates and pending revision-zero oracle, six independently checked native windows, original groups reclaimed; partial qualification only",
            path.display()
        );
    }
}
