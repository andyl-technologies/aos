//! Executes and retains one authored native singleton collecting attempt.

use std::{
    cell::RefCell,
    fs::File,
    io::Read,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use crucible_engine::node_contract::{
    ActivationPublisher, ActivationRecord, GracefulRetirementQualification, NodeRuntime,
    PreparedWorldPublication, PublicationStatus, QuarantinedRuntime, RuntimeCustodyQueue,
    RuntimeCustodySupervisor, RuntimeError, RuntimeLimits, RuntimeSnapshot, SimulationNode,
    ValidatedNodePreparation, WorldActivation,
};
use crucible_engine::node_scheduling::InputPayload;
use crucible_node_format::{Id, Phase, Position, U64, canonical};
use crucible_node_transport::ProviderError;
use crucible_store::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
    ObjectKind, RefName,
};

use super::super::{
    candidate::{PrivateCandidate, entropy},
    custody::PublicReferenceCustodyQueue,
    package::InstalledPublicReferencePackage,
    run_error::QualificationRunError,
    singleton_criteria::SingletonQualificationCriteria,
    singleton_unit::SingletonQualificationUnit,
    unit::UnitSourceObjects,
    vendor_bridge::{CollectingReferenceLaunch, prepare_collecting_singleton},
    witness::collect_original_windows,
};
use super::SingletonCollectionObservation;
use crate::node_observed_executor::activation::StoredWorldActivationPublisher;

static RESERVED: AtomicBool = AtomicBool::new(false);

struct ActorLease;

impl Drop for ActorLease {
    fn drop(&mut self) {
        RESERVED.store(false, Ordering::Release);
    }
}

pub(super) fn start(
    directory: PathBuf,
) -> Result<
    mpsc::Receiver<Result<SingletonCollectionObservation, QualificationRunError>>,
    std::io::Error,
> {
    RESERVED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "singleton actor already reserved",
            )
        })?;
    let lease = ActorLease;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("reference-singleton-collection".into())
        .spawn(move || {
            let _lease = lease;
            let mut actor = match Actor::new(directory) {
                Ok(actor) => actor,
                Err(error) => {
                    let _ = sender.send(Err(error.into()));
                    return;
                }
            };
            let original =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| actor.execute()));
            match original {
                Ok(Ok(observation)) => {
                    let _ = sender.send(Ok(observation));
                }
                failure => {
                    let error = match failure {
                        Ok(Err(error)) => QualificationRunError::from(error),
                        Err(_) => QualificationRunError::Refused(
                            "original singleton callback unwound; custody held",
                        ),
                        Ok(Ok(observation)) => {
                            let _ = sender.send(Ok(observation));
                            return;
                        }
                    };
                    let _ = sender.send(Err(error));
                    // The same actor, original data, directory and queues stay held.
                    // Notification grants no release and cannot start a retry.
                    loop {
                        std::thread::park_timeout(Duration::from_secs(1));
                    }
                }
            }
        })?;
    Ok(receiver)
}

struct Actor {
    directory: PathBuf,
    peers: PublicReferenceCustodyQueue,
    worlds: RuntimeCustodyQueue,
    runtime: Option<NodeRuntime>,
    retired: Option<QuarantinedRuntime>,
    candidate: Option<PrivateCandidate>,
    unit: Option<SingletonQualificationUnit>,
    criteria: Option<SingletonQualificationCriteria>,
    adverse: Option<Rc<super::super::singleton_adverse::SingletonAdversePopulation>>,
    clause_verifier: Option<super::super::singleton_clause::SingletonClauseVerifier>,
    history: Option<OriginalHistory>,
    blobs: Arc<DirectoryBlobBackend>,
    refs: Arc<DirectoryRefBackend>,
}

struct OriginalHistory {
    ledger: RuntimeSnapshot,
    bytes: Vec<u8>,
    root: ContentId,
}

impl Actor {
    fn new(directory: PathBuf) -> Result<Self, ProviderError> {
        if !directory.is_absolute()
            || directory.join("singleton/control.sock").as_os_str().len() > 100
        {
            return Err(ProviderError::ResourceExhausted(
                "singleton private directory geometry",
            ));
        }
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        Ok(Self {
            peers: PublicReferenceCustodyQueue::new(1)?,
            worlds: RuntimeCustodyQueue::new(1).map_err(failure)?,
            runtime: None,
            retired: None,
            candidate: None,
            unit: None,
            criteria: None,
            adverse: None,
            clause_verifier: None,
            history: None,
            blobs: Arc::new(DirectoryBlobBackend::new(
                "installed-singleton-collection",
                directory.join("private-blobs"),
            )),
            refs: Arc::new(DirectoryRefBackend::new(directory.join("private-refs"))),
            directory,
        })
    }

    fn persist_exact(&self, bytes: &[u8]) -> Result<ContentId, ProviderError> {
        let root = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        let receipt = self
            .blobs
            .put_if_absent(root, &BlobHandle::from_bytes(bytes.to_vec()))
            .map_err(failure)?;
        if !receipt.is_durable()
            || self
                .blobs
                .read(root, None)
                .and_then(|handle| handle.read_all(bytes.len() as u64))
                .map_err(failure)?
                != bytes
        {
            return Err(ProviderError::Correlation(
                "singleton original history not durable and exact",
            ));
        }
        Ok(root)
    }

    fn execute(&mut self) -> Result<SingletonCollectionObservation, ProviderError> {
        let package = InstalledPublicReferencePackage::built_in().map_err(failure)?;
        self.candidate = Some(PrivateCandidate::new_singleton(
            Rc::clone(&package),
            U64::new(1000),
            U64::new(1_000_000_000),
        )?);
        let candidate = self
            .candidate
            .as_ref()
            .ok_or(ProviderError::Correlation("singleton candidate absent"))?;
        if candidate.definition.topology()
            != super::super::world::CandidateTopology::OrdinarySingleton
        {
            return Err(ProviderError::Correlation(
                "singleton source topology differs",
            ));
        }
        let [installed] = candidate.installations.as_slice() else {
            return Err(ProviderError::Correlation(
                "singleton original installation roster differs",
            ));
        };
        let cases = (0..3)
            .map(|index| super::super::harness::window_case(installed, index))
            .collect::<Result<Vec<_>, _>>()?;
        let oracle = super::super::harness::oracle_contract(installed, &cases)?;
        let unit =
            SingletonQualificationUnit::measure(installed, source_context(&package, &oracle)?)?;
        let criteria = SingletonQualificationCriteria::build(&unit).map_err(failure)?;
        self.clause_verifier = Some(
            super::super::singleton_clause::SingletonClauseVerifier::prepare(&unit, &criteria)
                .map_err(failure)?,
        );
        for (reference, bytes) in unit.objects.iter().chain(criteria.objects.iter()) {
            reference.verify(bytes)?;
            self.persist_exact(bytes)?;
        }
        criteria.reference.verify(&criteria.bytes)?;
        let adverse = Rc::new(
            super::super::singleton_adverse::SingletonAdversePopulation::new(installed, &unit)?,
        );
        adverse.reference.verify(&adverse.bytes)?;
        self.persist_exact(&adverse.bytes)?;
        self.adverse = Some(adverse);
        // Both complete objects precede the first native allocation. A failed
        // run retains this original population without changing its source scope.
        self.unit = Some(unit);
        self.criteria = Some(criteria);
        let slot = self
            .worlds
            .reserve_world(&candidate.activation, RuntimeLimits::default())
            .map_err(failure)?;
        let candidate = self
            .candidate
            .as_mut()
            .ok_or(ProviderError::Correlation("singleton candidate absent"))?;
        let observer = Rc::new(RefCell::new(None));
        let prepared = prepare_collecting_singleton(
            &mut candidate.installations[0],
            &self.peers,
            CollectingReferenceLaunch {
                directory: self.directory.join("singleton"),
                activation: candidate.activation.clone(),
                owner: candidate.activation.owners[0].clone(),
                source_roots: vec![
                    package.identity().clone(),
                    candidate.definition.qualification().clone(),
                ],
                hello_id: Id::new("singleton/hello")?,
                connection_id: Id::new("singleton/connection")?,
                controller_nonce: entropy()?,
                observations: Rc::clone(&observer),
                adverse: self.adverse.clone(),
            },
        )?;
        let graph = candidate
            .definition
            .admit_candidate(&candidate.installations, &[&prepared])?;
        let node = prepared
            .into_node(
                &graph,
                &candidate.installations[0].profile.descriptor.id,
                &candidate.installations[0],
                8,
            )
            .map_err(|error| failure(error.reason))?;
        let nodes: Vec<Box<dyn SimulationNode>> = vec![Box::new(node)];
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
            .ok_or(ProviderError::Correlation("singleton runtime absent"))?;
        runtime.arm_all().map_err(failure)?;
        let coordinator = runtime
            .initial_coordinator_snapshot(&graph, 1024 * 1024)
            .map_err(failure)?;
        let stored = StoredWorldActivationPublisher::new(
            self.blobs.clone(),
            self.refs.clone(),
            RefName::new("node-world-activations/singleton").map_err(failure)?,
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
        let activation = runtime.activate(&mut publisher).map_err(failure)?;
        runtime.scheduler(&graph, &activation).map_err(failure)?;
        let node_id = &candidate.installations[0].profile.descriptor.id;
        let boundary = runtime
            .observe_scheduling(&activation, node_id)
            .map_err(failure)?;
        runtime
            .scheduler(&graph, &activation)
            .map_err(failure)?
            .accept_boundary_observation(boundary)
            .map_err(failure)?;
        let mut context = Context::from_waker(Waker::noop());
        let mut windows = Vec::with_capacity(3);
        for case in &cases {
            windows.push(
                crate::node_qualification::collect_reference_window(
                    runtime,
                    &graph,
                    &activation,
                    case,
                    &mut context,
                )
                .map_err(failure)?,
            );
        }
        let observer = observer.borrow();
        let witness = collect_original_windows(
            &candidate.installations[0],
            observer.as_ref().ok_or(ProviderError::Correlation(
                "original singleton observation absent",
            ))?,
            &oracle,
            &activation,
            &windows,
        )?;
        let cut = Position::new(U64::new(3000), U64::new(0), Phase::BoundaryControl);
        let ledger = runtime
            .runtime_snapshot(cut, U64::new(0), 8 * 1024 * 1024)
            .map_err(failure)?;
        let scheduler = runtime
            .retirement_scheduler_snapshot(&activation, cut, U64::new(0))
            .map_err(failure)?;
        let histories = runtime
            .retirement_histories(&activation, 128 * 1024 * 1024)
            .map_err(failure)?;
        let history_views = histories
            .iter()
            .map(|history| {
                serde_json::json!({
                    "route": {"node": history.route.node, "owners": history.route.owners},
                    "bodies": history.bodies,
                })
            })
            .collect::<Vec<_>>();
        let bytes = canonical::canonical_json(&serde_json::json!({
            "schema": "crucible.reference.singleton-original-history.v1",
            "ledger": ledger,
            "scheduler": scheduler,
            "histories": history_views,
            "windows": windows,
            "initial_coordinator": coordinator,
            "window_witness": {"reference": witness.reference, "bytes": witness.bytes},
        }))?;
        let root = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        self.history = Some(OriginalHistory {
            ledger,
            bytes,
            root,
        });
        let original = self.history.as_ref().ok_or(ProviderError::Correlation(
            "original singleton history absent",
        ))?;
        if self.persist_exact(&original.bytes)? != original.root {
            return Err(ProviderError::Correlation(
                "singleton original history identity changed",
            ));
        }
        self.retired =
            Some(NodeRuntime::take_graceful_retirement(&mut self.runtime).map_err(failure)?);
        let retired = self
            .retired
            .as_mut()
            .ok_or(ProviderError::Correlation("singleton retirement absent"))?;
        loop {
            match retired.poll_reclamation(&mut context) {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(error)) => return Err(failure(error)),
                Poll::Pending => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        retired
            .authenticate_retired_ledger(&original.ledger, 8 * 1024 * 1024)
            .map_err(failure)?;
        retired.transfer_retirement_resources().map_err(failure)?;
        loop {
            self.peers.poll_reclamation()?;
            if self.peers.resolve_original_reclaimed()? {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let release = Release {
            peers: &self.peers,
            history: original,
            blobs: self.blobs.as_ref(),
        };
        QuarantinedRuntime::release_after_authenticated_supervision(
            &mut self.retired,
            &activation,
            &release,
        )
        .map_err(failure)?;
        let unit = self
            .unit
            .as_ref()
            .ok_or(ProviderError::Correlation("singleton unit absent"))?;
        let criteria = self
            .criteria
            .as_ref()
            .ok_or(ProviderError::Correlation("singleton complete plan absent"))?;
        let adverse = self
            .adverse
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "singleton adverse population absent",
            ))?
            .observation()?;
        let reviews = self
            .clause_verifier
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "singleton clause verifier absent",
            ))?
            .population(criteria, &adverse)
            .map_err(failure)?;
        let bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.reference.singleton-original-observation.v1", "implementation":package.identity(),
            "unit":unit.identity, "plan":criteria.plan, "plan_reference":criteria.reference,
            "original_history":original.root.encode(), "activation":crucible_engine::node_contract::SavedRuntimeActivation::from(activation.record()),
            "prepared_world":publisher.original.map(|original|serde_json::json!({"nodes":original.nodes(),"owners":original.prepared_owners()})),
            "positive_semantic_native_archive_resolution":true,
            "remaining_clause_reviews":criteria.clauses.keys().collect::<Vec<_>>(),
            "adverse_native_case":adverse,"complete_clause_reviews":reviews, "qualification_accepted":false
        }))?;
        self.persist_exact(&bytes)?;
        Ok(SingletonCollectionObservation {
            implementation: package.identity().clone(),
            bytes,
        })
    }
}

struct Release<'a> {
    peers: &'a PublicReferenceCustodyQueue,
    history: &'a OriginalHistory,
    blobs: &'a dyn ImmutableBlobBackend,
}

impl GracefulRetirementQualification for Release<'_> {
    fn authenticate_release(
        &self,
        original: &QuarantinedRuntime,
        activation: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        original.authenticate_retired_ledger(&self.history.ledger, 8 * 1024 * 1024)?;
        if self
            .blobs
            .read(self.history.root, None)
            .and_then(|handle| handle.read_all(self.history.bytes.len() as u64))
            .map_err(|_| RuntimeError::InvalidReceipt)?
            != self.history.bytes
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        self.peers
            .authenticate_resolved(activation.record())
            .map_err(|_| RuntimeError::OutstandingObligations)
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
        if self
            .peers
            .record_publication(record, prepared, PublicationStatus::Unknown)
            .is_err()
        {
            return PublicationStatus::Unknown;
        }
        self.original = Some(prepared.clone());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.stored.publish_complete(record, prepared)
        }));
        let status = result.unwrap_or(PublicationStatus::Unknown);
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

fn source_context(
    package: &InstalledPublicReferencePackage,
    oracle: &crate::node_qualification::ReferenceOracleContract,
) -> Result<UnitSourceObjects, ProviderError> {
    let executable = std::env::current_exe()?;
    let mut source = File::open(executable)?;
    let mut bytes = Vec::new();
    source
        .by_ref()
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 512 * 1024 * 1024 {
        return Err(ProviderError::ResourceExhausted(
            "singleton actual harness ELF bound",
        ));
    }
    let harness = canonical::canonical_json(&serde_json::json!({
        "schema":"crucible.reference.singleton-harness-source.v1", "actual_executable":canonical::content_ref(&bytes,"application/vnd.crucible.executable")?,
        "actor":include_str!("singleton_actor.rs"),"interface":include_str!("singleton.rs"),
        "adverse":include_str!("singleton_adverse.rs"),"conflict_collector":include_str!("singleton_conflict.rs"),"conflict_wire":include_str!("source_original_conflict_wire.rs"),"clause_verifier":include_str!("singleton_clause.rs"),
        "launch":include_str!("vendor_bridge/collecting_launch.rs"),"shared_original_transport":include_str!("vendor_bridge/negotiation.rs"),
        "source_package":package.identity()
    }))?;
    let (_, specification) =
        crate::node_qualification::normative_specification().map_err(failure)?;
    Ok(UnitSourceObjects {
        environment: canonical::canonical_json(
            &serde_json::json!({"schema":"crucible.reference.singleton-environment.v1","architecture":std::env::consts::ARCH,"os":std::env::consts::OS,"kernel_release":std::fs::read_to_string("/proc/sys/kernel/osrelease")?,"effective_uid":rustix::process::geteuid().as_raw().to_string(),"locale":"C"}),
        )?,
        harness,
        specification,
        fixtures: canonical::canonical_json(
            &serde_json::json!({"schema":"crucible.reference.singleton-fixture.v1","windows":{"quantum_ps":oracle.quantum_ps,"host_budget_ns":oracle.host_budget_ns,"first_quantum":oracle.first_quantum,"first_time_ps":oracle.first_time_ps,"initial_checksum":oracle.initial_checksum,"maximum_windows":oracle.maximum_windows,"maximum_input_bytes":oracle.maximum_input_bytes,"expected":oracle.expected_windows.iter().map(|window|serde_json::json!({"window":window.window,"batch":window.batch,"input":window.input})).collect::<Vec<_>>()},"node":"singleton","owner":"singleton-owner","connections":[],"retirement":"same original world, complete private histories before first Shutdown; exact semantic and native original capsule archive before release"}),
        )?,
    })
}

fn failure(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}
