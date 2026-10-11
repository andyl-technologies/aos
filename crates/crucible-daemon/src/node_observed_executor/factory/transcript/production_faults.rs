//! Conditional-specific storage failures over original authenticated native recordings.
//!
//! Each fault surrounds a real durable directory put. An acknowledgement lost
//! after placement must preserve original runtime publication custody just like
//! a refusal before placement; neither permits scheduler commitment or retry.

use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use crucible::node_adapters::transcript::AuthenticatedTranscript;
use crucible_cas::content_store::{
    BackendCapabilities, ByteRange, DirectoryBlobBackend, PutReceipt, StoreError,
};

use super::*;

#[derive(Clone, Copy)]
enum Target {
    Source(ContentId),
    ProducerReceipt,
}

#[derive(Clone, Copy)]
enum FailureMode {
    BeforePlacement,
    AfterPlacement,
    Nondurable,
    PanicBeforePlacement,
    PanicAfterPlacement,
}

impl FailureMode {
    fn places_bytes(self) -> bool {
        matches!(
            self,
            Self::AfterPlacement | Self::Nondurable | Self::PanicAfterPlacement
        )
    }

    fn panics(self) -> bool {
        matches!(self, Self::PanicBeforePlacement | Self::PanicAfterPlacement)
    }
}

struct FaultBlobs {
    inner: Arc<dyn ImmutableBlobBackend>,
    target: Target,
    mode: FailureMode,
    armed: AtomicBool,
    failed: Mutex<Option<ContentId>>,
    failed_body: Mutex<Option<Vec<u8>>>,
}

impl ImmutableBlobBackend for FaultBlobs {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let matches = match self.target {
            Target::Source(original) => id == original,
            Target::ProducerReceipt => {
                let bytes = source.read_all(16 * 1024 * 1024)?;
                serde_json::from_slice::<serde_json::Value>(&bytes).is_ok_and(|value| {
                    value.get("objects").is_some()
                        && value
                            .get("operation")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|operation| operation.contains("producer"))
                })
            }
        };
        if !matches || !self.armed.swap(false, Ordering::AcqRel) {
            return self.inner.put_if_absent(id, source);
        }
        *self.failed.lock().map_err(|_| StoreError::Incompatible)? = Some(id);
        *self
            .failed_body
            .lock()
            .map_err(|_| StoreError::Incompatible)? = Some(source.read_all(16 * 1024 * 1024)?);
        let placed = if self.mode.places_bytes() {
            Some(self.inner.put_if_absent(id, source)?)
        } else {
            None
        };
        if self.mode.panics() {
            panic!("injected original conditional store panic");
        }
        if matches!(self.mode, FailureMode::Nondurable) {
            let mut receipt = placed.ok_or(StoreError::Incompatible)?;
            for placement in &mut receipt.placements {
                placement.durable = false;
            }
            return Ok(receipt);
        }
        Err(StoreError::Incompatible)
    }
}

// This wrapper only observes the original backend before the real worker
// contains it. It grants no additional request or native effect permission.
struct CheckedBackend {
    inner: NodeObservedBackend,
    faults: Arc<FaultBlobs>,
    checked: Arc<AtomicBool>,
}

#[cfg(test)]
impl ObservedAttemptBackend for CheckedBackend {
    type Error = NodeObservedError;

    fn retention_roots(&self) -> std::collections::BTreeSet<ContentId> {
        self.inner.retention_roots()
    }

    fn validate_realization(
        &mut self,
        request: &ObservedAttemptRequest,
    ) -> Result<(), Self::Error> {
        self.inner.validate_realization(request)
    }

    fn start(&mut self, request: &ObservedAttemptRequest) -> Result<(), Self::Error> {
        self.inner.start(request)
    }

    fn poll(
        &mut self,
        execution: ExecutionId,
    ) -> Result<Option<crucible_campaign::observed_node_attempt::ObservedAttemptResult>, Self::Error>
    {
        let before = self.inner.test_replay_coordinator_frontier()?;
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.inner.poll(execution)));
        if !matches!(&result, Ok(Ok(_))) {
            assert_eq!(
                self.inner.test_replay_coordinator_frontier()?,
                before,
                "failed proof placement committed scheduling progress"
            );
            let bytes = self.faults.failed_body.lock().unwrap().clone().unwrap();
            let expected_proof = serde_json::from_slice(&bytes).unwrap();
            self.inner
                .test_replay_original_receipt_is_uncommitted(&expected_proof)?;
            self.checked.store(true, Ordering::Release);
        }
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn contain(&mut self, execution: ExecutionId) -> Result<bool, Self::Error> {
        self.inner.contain(execution)
    }
}

/// Exercises original body-copy and post-completion proof faults after source death.
#[cfg(test)]
pub(in super::super) fn drive_store_failures(
    sources: BTreeMap<Id, AuthenticatedTranscript>,
    executable: PathBuf,
    private_root: PathBuf,
    configuration: NodeRunConfiguration,
) {
    let modes = [
        FailureMode::BeforePlacement,
        FailureMode::AfterPlacement,
        FailureMode::Nondurable,
        FailureMode::PanicBeforePlacement,
        FailureMode::PanicAfterPlacement,
    ];
    for (ordinal, (source_copy, mode)) in [true, false]
        .into_iter()
        .flat_map(|source_copy| modes.into_iter().map(move |mode| (source_copy, mode)))
        .enumerate()
    {
        let catalog = InstalledNodeCatalog::new(
            executable.clone(),
            measure_executable(&executable).unwrap(),
            private_root.clone(),
            Duration::from_secs(5),
            1,
        )
        .unwrap();
        let execution =
            ExecutionId::from_bytes([110 + u8::try_from(ordinal).unwrap(); 16]).unwrap();
        let prepared = catalog
            .select_conditional_replay(sources.clone(), &configuration)
            .unwrap()
            .prepare(&catalog, execution)
            .unwrap();
        let first_source = prepared.source_objects.values().next().unwrap();
        let source_id = ContentId::for_bytes(ObjectKind::Trace, 1, &first_source.bytes);
        let target = if source_copy {
            Target::Source(source_id)
        } else {
            Target::ProducerReceipt
        };
        let inner: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "conditional-faults",
            private_root.join(format!("conditional-fault-blobs-{ordinal}")),
        ));
        let faults = Arc::new(FaultBlobs {
            inner: inner.clone(),
            target,
            mode,
            armed: AtomicBool::new(true),
            failed: Mutex::new(None),
            failed_body: Mutex::new(None),
        });
        let refs: Arc<dyn MutableRefBackend> =
            Arc::new(crucible_cas::content_store::DirectoryRefBackend::new(
                private_root.join(format!("conditional-fault-refs-{ordinal}")),
            ));
        let inputs_bytes = super::super::super::super::backend::input_context_bytes(
            &prepared.world.scenario,
            &prepared.configuration,
        )
        .unwrap();
        let inputs = ContentId::for_bytes(ObjectKind::Trace, 1, &inputs_bytes);
        inner
            .put_if_absent(inputs, &BlobHandle::from_bytes(inputs_bytes))
            .unwrap();
        let root = RefName::new(format!(
            "node-world-activations/conditional-fault-{ordinal}"
        ))
        .unwrap();
        let publisher =
            StoredWorldActivationPublisher::new(faults.clone(), refs.clone(), root.clone())
                .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            NodeObservedBackend::from_conditional_replay(
                prepared,
                publisher,
                faults.clone(),
                inputs,
                execution,
            )
        }));
        if source_copy {
            match result {
                Err(_) if mode.panics() => {}
                Ok(Err(_)) if !mode.panics() => {}
                _ => panic!("source copy fault was not contained before activation"),
            }
            assert_eq!(*faults.failed.lock().unwrap(), Some(source_id));
            assert_eq!(inner.contains(source_id).unwrap(), mode.places_bytes());
            assert!(refs.read_ref(&root).unwrap().is_none());
            assert_eq!(catalog.custody().retained_worlds(), 1);
        } else {
            let backend = result.unwrap().unwrap();
            let repository = CampaignRepository::new(faults.clone(), refs.clone());
            let scenario = backend.scenario_artifact();
            repository
                .publish_scenario_artifact(
                    scenario.scenario(),
                    scenario.payload_schema(),
                    scenario.payload().to_vec(),
                )
                .unwrap();
            let config = backend.configuration_artifact();
            repository
                .publish_configuration_artifact(
                    config.scenario(),
                    config.scenario_artifact(),
                    config.configuration(),
                    config.payload_schema(),
                    config.payload().to_vec(),
                )
                .unwrap();
            let request = backend.request(execution).unwrap();
            let admission = backend.admission().clone();
            let checked = Arc::new(AtomicBool::new(false));
            let checked_backend = CheckedBackend {
                inner: backend,
                faults: faults.clone(),
                checked: checked.clone(),
            };
            let repository = Arc::new(repository);
            let mut worker =
                ObservedAttemptWorker::new(repository.clone(), checked_backend, 1).unwrap();
            worker
                .submit("conditional-fault-original", &request, &admission)
                .unwrap();
            let deadline = ProcessDeadline::after(Duration::from_secs(10)).unwrap();
            loop {
                assert!(worker.retention_roots().contains(&source_id));
                match worker.poll(execution) {
                    Ok(ObservedAttemptState::Quarantined {
                        request: original,
                        reason,
                        ..
                    }) => {
                        assert_eq!(original, request);
                        assert_eq!(
                            reason,
                            if mode.panics() {
                                "native-poll-panicked"
                            } else {
                                "native-poll-uncertain"
                            }
                        );
                        break;
                    }
                    Ok(ObservedAttemptState::Reserved(_)) | Err(_) => {}
                    Ok(ObservedAttemptState::Completed(_)) => {
                        panic!("failed proof copy published completion")
                    }
                }
                assert!(
                    !deadline.expired(),
                    "original conditional failure was not quarantined"
                );
            }
            assert!(checked.load(Ordering::Acquire));
            let failed = faults.failed.lock().unwrap().unwrap();
            assert_eq!(inner.contains(failed).unwrap(), mode.places_bytes());
            assert!(!worker.retention_roots().contains(&failed));
            assert!(matches!(
                repository.observed_execution_state(execution).unwrap(),
                Some(ObservedAttemptState::Quarantined { .. })
            ));
            while worker.active_executions() != 0 {
                worker.poll(execution).unwrap();
                assert!(
                    !deadline.expired(),
                    "original failed replay custody was abandoned"
                );
            }
            drop(worker);
        }
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let deadline = ProcessDeadline::after(Duration::from_secs(10)).unwrap();
        while catalog.custody().reserved_worlds() != 0 {
            if let std::task::Poll::Ready(Err(error)) =
                catalog.custody().poll_reclamation(&mut context)
            {
                panic!("failed original replay reclamation: {error:?}");
            }
            assert!(
                !deadline.expired(),
                "complete failed replay world remains held"
            );
        }
    }
}
