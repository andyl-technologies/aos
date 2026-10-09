//! Durable original pending-admission and finite portable codec regressions.
//!
//! These tests authenticate no source provider. Directory CAS proves original
//! request custody; source applicability remains the owning native fixture's job.

// crucible-lint: allow panic-shortcut -- Original-request codec and durable custody regressions fail on their first unmet assertion; no failed test is rerun.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::ledger::ConditionalPreparationLedger;
use super::{
    ConditionalPreparationRecord, ConditionalPreparationRequest, ConditionalPreparationState,
    encode,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
    MutableRefBackend, ObjectKind, RefName,
};
use crucible_node_contract::{Bytes, Id, canonical};
use std::{collections::BTreeMap, sync::Arc};

fn request() -> ConditionalPreparationRequest {
    let reference =
        canonical::content_ref(b"unqualified original source", "application/json").unwrap();
    ConditionalPreparationRequest {
        ledger:"original-replay".into(), execution:"82828282828282828282828282828282".into(),
        sources:BTreeMap::from([(Id::new("producer").unwrap(), reference.clone()),
            (Id::new("consumer").unwrap(), reference)]),
        configuration:Bytes::new(br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"150","maximum_rounds":"32"}"#.to_vec()),
    }
}

#[test]
fn restarted_pending_receipt_cannot_redispatch_or_change_exact_original_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "conditional-preparation-test",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = ConditionalPreparationLedger::new(blobs.clone(), refs.clone()).unwrap();
    let original = request();
    let reserved = ledger.reserve(&original).unwrap();
    assert!(reserved.original_dispatch);
    assert!(matches!(
        reserved.record.outcome,
        ConditionalPreparationState::AwaitingAdmission { .. }
    ));
    let roots = ledger.retention_roots().unwrap();
    assert!(roots.contains(&ContentId::parse(&reserved.record.request).unwrap()));
    let body = blobs
        .read(ContentId::parse(&reserved.record.request).unwrap(), None)
        .unwrap()
        .read_all(65536)
        .unwrap();
    assert_eq!(body, encode(&original).unwrap());

    let restarted = ConditionalPreparationLedger::new(blobs, refs).unwrap();
    let retry = restarted.reserve(&original).unwrap();
    assert!(!retry.original_dispatch);
    assert_eq!(retry.record, reserved.record);
    assert!(
        restarted
            .complete(&retry, ConditionalPreparationState::Unavailable {})
            .is_err()
    );
    let mut altered = original.clone();
    altered.configuration = Bytes::new(
        original
            .configuration
            .as_slice()
            .iter()
            .copied()
            .chain(*b" ")
            .collect(),
    );
    assert!(restarted.reserve(&altered).is_err());
    assert_eq!(
        restarted.state(&original.execution).unwrap(),
        reserved.record
    );

    let unavailable = ledger
        .complete(&reserved, ConditionalPreparationState::Unavailable {})
        .unwrap();
    assert_eq!(unavailable.request, reserved.record.request);
    assert!(!restarted.reserve(&original).unwrap().original_dispatch);
    assert!(matches!(
        restarted.state(&original.execution).unwrap().outcome,
        ConditionalPreparationState::Unavailable { .. }
    ));
}

#[test]
fn exhausted_persistent_credit_refuses_before_new_request_placement() {
    let directory = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "conditional-preparation-credit",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    // Consumed credit can exceed completed records after an interrupted earlier
    // reservation. It must not be refunded merely because no operation ref won.
    let bytes = canonical::canonical_json(&serde_json::json!({"format":"crucible.conditional-preparation-quota","version":1,"consumed":4096})).unwrap();
    let quota = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    assert!(
        blobs
            .put_if_absent(quota, &BlobHandle::from_bytes(bytes))
            .unwrap()
            .is_durable()
    );
    refs.compare_exchange(
        &RefName::new("node-conditional-preparation-quota/records").unwrap(),
        None,
        quota,
    )
    .unwrap();
    let ledger = ConditionalPreparationLedger::new(blobs.clone(), refs).unwrap();
    let original = request();
    let request_id = ContentId::for_bytes(ObjectKind::Trace, 1, &encode(&original).unwrap());
    assert!(ledger.reserve(&original).is_err());
    assert!(!blobs.contains(request_id).unwrap());
    assert!(ledger.state(&original.execution).is_err());
}

#[test]
fn data_only_receipts_refuse_foreign_fields_oversize_and_fresh_mode_claims() {
    let original = request();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &encode(&original).unwrap());
    let receipt = ConditionalPreparationRecord {
        format: "crucible.conditional-preparation".into(),
        version: 1,
        execution: original.execution,
        request: id.encode(),
        outcome: ConditionalPreparationState::AwaitingAdmission {},
    };
    let bytes = receipt.canonical_bytes().unwrap();
    assert_eq!(
        ConditionalPreparationRecord::from_canonical_bytes(&bytes).unwrap(),
        receipt
    );
    let mut value = serde_json::to_value(&receipt).unwrap();
    value["ready"] = serde_json::json!(true);
    assert!(
        ConditionalPreparationRecord::from_canonical_bytes(
            &canonical::canonical_json(&value).unwrap()
        )
        .is_err()
    );
    let mut invalid = request();
    invalid.configuration = Bytes::new(vec![b' '; 4097]);
    assert!(invalid.validate().is_err());
    let mut invalid = receipt;
    invalid.outcome = ConditionalPreparationState::Admitted {
        observed_request: Bytes::new(b"unsupported fresh claim".to_vec()),
    };
    assert!(invalid.validate().is_err());
}

#[test]
fn pending_status_and_exact_retry_do_not_wait_for_the_owning_actor() {
    use super::super::{Command, NodeObservationService, NodeObservationServiceError};
    use std::sync::{Mutex, atomic::AtomicBool, mpsc};

    let directory = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "conditional-preparation-queue",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = ConditionalPreparationLedger::new(blobs.clone(), refs.clone()).unwrap();
    let (commands, receiver) = mpsc::sync_channel(1);
    // The actor deliberately has not consumed its only queue slot. These calls
    // must return durable metadata without source verification or actor replies.
    let service = NodeObservationService {
        commands,
        stopping: Arc::new(AtomicBool::new(false)),
        roots: Arc::new(Mutex::new(Default::default())),
        retired: Arc::new(AtomicBool::new(false)),
        preparations: Some(ledger.clone()),
        capabilities:
            super::super::capability_preparation::ledger::CapabilityPreparationLedger::new(
                blobs.clone(),
                refs.clone(),
            )
            .unwrap(),
    };
    let retention = service.retention_owner();
    let original = request();
    let pending = service
        .submit_conditional_preparation(original.clone())
        .unwrap();
    assert!(matches!(
        pending.outcome,
        ConditionalPreparationState::AwaitingAdmission {}
    ));
    assert_eq!(
        service
            .conditional_preparation_status(&original.execution)
            .unwrap(),
        pending
    );
    assert_eq!(
        service.submit_conditional_preparation(original).unwrap(),
        pending
    );

    let mut excess = request();
    excess.execution = "83838383838383838383838383838383".into();
    let unavailable = service
        .submit_conditional_preparation(excess.clone())
        .unwrap();
    assert!(matches!(
        unavailable.outcome,
        ConditionalPreparationState::Unavailable {}
    ));
    assert_eq!(
        service.submit_conditional_preparation(excess).unwrap(),
        unavailable
    );

    let command = receiver.try_recv().unwrap();
    let Command::ConditionalPreparation {
        request: queued, ..
    } = &command
    else {
        panic!("the original queue slot changed command scope");
    };
    assert_eq!(queued.execution, pending.execution);
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    drop(service);
    super::super::reply_refusal(command, NodeObservationServiceError::Unavailable);
    assert!(matches!(
        ledger.state(&pending.execution).unwrap().outcome,
        ConditionalPreparationState::Unavailable {}
    ));
    assert!(!ledger.reserve(&request()).unwrap().original_dispatch);
    let roots = retention.retention_roots().unwrap();
    assert!(roots.contains(&ContentId::parse(&pending.request).unwrap()));
    assert!(roots.contains(&ContentId::parse(&unavailable.request).unwrap()));
}

#[derive(Clone, Copy)]
enum WriteFailure {
    Before,
    After,
    Nondurable,
    PanicBefore,
    PanicAfter,
}

struct CompletionFault {
    inner: Arc<dyn ImmutableBlobBackend>,
    mode: WriteFailure,
    armed: std::sync::atomic::AtomicBool,
}

impl ImmutableBlobBackend for CompletionFault {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> crucible_cas::content_store::BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, crucible_cas::content_store::StoreError> {
        self.inner.contains(id)
    }

    fn read(
        &self,
        id: ContentId,
        range: Option<crucible_cas::content_store::ByteRange>,
    ) -> Result<BlobHandle, crucible_cas::content_store::StoreError> {
        self.inner.read(id, range)
    }

    fn put_if_absent(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<crucible_cas::content_store::PutReceipt, crucible_cas::content_store::StoreError>
    {
        use crucible_cas::content_store::StoreError;
        use std::sync::atomic::Ordering;

        if !self.armed.swap(false, Ordering::AcqRel) {
            return self.inner.put_if_absent(id, source);
        }
        let placed = if matches!(
            self.mode,
            WriteFailure::After | WriteFailure::Nondurable | WriteFailure::PanicAfter
        ) {
            Some(self.inner.put_if_absent(id, source)?)
        } else {
            None
        };
        if matches!(
            self.mode,
            WriteFailure::PanicBefore | WriteFailure::PanicAfter
        ) {
            panic!("injected original preparation completion panic");
        }
        if matches!(self.mode, WriteFailure::Nondurable) {
            let mut receipt = placed.ok_or(StoreError::Incompatible)?;
            for placement in &mut receipt.placements {
                placement.durable = false;
            }
            return Ok(receipt);
        }
        Err(StoreError::Incompatible)
    }
}

#[test]
fn completion_write_uncertainty_retains_pending_original_and_never_redispatches() {
    use std::sync::atomic::{AtomicBool, Ordering};

    for mode in [
        WriteFailure::Before,
        WriteFailure::After,
        WriteFailure::Nondurable,
        WriteFailure::PanicBefore,
        WriteFailure::PanicAfter,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let durable: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "conditional-preparation-uncertain",
            directory.path().join("blobs"),
        ));
        let refs: Arc<dyn MutableRefBackend> =
            Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
        let fault = Arc::new(CompletionFault {
            inner: durable.clone(),
            mode,
            armed: AtomicBool::new(false),
        });
        let ledger = ConditionalPreparationLedger::new(fault.clone(), refs.clone()).unwrap();
        let original = request();
        let reservation = ledger.reserve(&original).unwrap();
        let roots = ledger.retention_roots().unwrap();
        fault.armed.store(true, Ordering::Release);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.complete(&reservation, ConditionalPreparationState::Unavailable {})
        }));
        assert!(!matches!(result, Ok(Ok(_))));

        // A failed completion can have placed bytes; only the exact original
        // mutable ref establishes its status. Restart never dispatches it again.
        let restarted = ConditionalPreparationLedger::new(durable, refs).unwrap();
        assert_eq!(
            restarted.state(&original.execution).unwrap(),
            reservation.record
        );
        assert_eq!(restarted.retention_roots().unwrap(), roots);
        let retry = restarted.reserve(&original).unwrap();
        assert!(!retry.original_dispatch);
        assert!(
            restarted
                .complete(&retry, ConditionalPreparationState::Unavailable {})
                .is_err()
        );
        assert_eq!(
            restarted.state(&original.execution).unwrap(),
            reservation.record
        );
    }
}

#[test]
fn concurrent_exact_submissions_reserve_only_one_original_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "conditional-preparation-concurrent",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = ConditionalPreparationLedger::new(blobs, refs).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let workers = (0..8)
        .map(|_| {
            let ledger = ledger.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                ledger.reserve(&request())
            })
        })
        .collect::<Vec<_>>();
    let submissions = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    let reservations = submissions
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .collect::<Vec<_>>();
    assert_eq!(
        reservations
            .iter()
            .filter(|reservation| reservation.original_dispatch)
            .count(),
        1
    );
    let original = ledger.state(&request().execution).unwrap();
    assert!(
        reservations
            .iter()
            .all(|reservation| reservation.record == original)
    );
    // Storage contention can refuse a concurrent submission. Reconciliation of
    // every exact original then returns the single durable owner without a new
    // dispatch permission, including callers that saw transport/store failure.
    for _ in submissions {
        let retry = ledger.reserve(&request()).unwrap();
        assert!(!retry.original_dispatch);
        assert_eq!(retry.record, original);
    }
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn queued_shutdown_completion_panic_preserves_original_and_reclaims_native_world() {
    use super::super::{ActorControl, ActorStorage, Command, run_actor};
    use crate::node_observed_executor::{
        InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection,
        factory::measure_executable,
    };
    use crate::node_scenario::NodeRunConfiguration;
    use crucible::node_adapters::transcript::TranscriptLimits;
    use crucible_campaign::{CampaignRepository, ExecutionId};
    use crucible_node_contract::U64;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::Duration;

    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    for mode in [WriteFailure::PanicBefore, WriteFailure::PanicAfter] {
        let directory = tempfile::tempdir().unwrap();
        let durable: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "conditional-shutdown-native",
            directory.path().join("blobs"),
        ));
        let refs: Arc<dyn MutableRefBackend> =
            Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
        let fault = Arc::new(CompletionFault {
            inner: durable.clone(),
            mode,
            armed: AtomicBool::new(false),
        });
        let ledger = ConditionalPreparationLedger::new(fault.clone(), refs.clone()).unwrap();
        let original = request();
        let reservation = ledger.reserve(&original).unwrap();
        let expected = reservation.record.clone();
        let original_roots = ledger.retention_roots().unwrap();

        // Allocate a genuine native world, then leave its complete failed
        // recording preparation in the catalog's reserved reclamation queue.
        // The shutdown callback must not drop that owning catalog on unwind.
        let mut catalog = InstalledNodeCatalog::new(
            executable.clone(),
            measure_executable(&executable).unwrap(),
            directory.path().to_owned(),
            Duration::from_secs(5),
            1,
        )
        .unwrap();
        let selections = vec![
            InstalledNodeSelection {
                node: Id::new("clock").unwrap(),
                owner: Id::new("clock-owner").unwrap(),
                kind: InstalledNodeKind::HostClock,
            },
            InstalledNodeSelection {
                node: Id::new("device").unwrap(),
                owner: Id::new("device-owner").unwrap(),
                kind: InstalledNodeKind::ReferenceDevice {
                    quantum_ps: U64::new(50),
                    host_budget_ns: U64::new(20_000_000),
                },
            },
        ];
        let scenario = catalog.scenario(&selections).unwrap();
        let configuration = NodeRunConfiguration {
            format: "crucible.node-run-configuration".into(),
            version: 1,
            horizon_ps: U64::new(50),
            maximum_rounds: U64::new(8),
        };
        let refused = catalog.prepare_recorded_world(
            &selections,
            scenario,
            &configuration,
            ExecutionId::from_bytes([94; 16]).unwrap(),
            TranscriptLimits {
                maximum_records: U64::new(8),
                maximum_record_bytes: U64::new(32),
                maximum_total_bytes: U64::new(32),
            },
        );
        assert!(refused.is_err());
        let custody = catalog.custody().clone();
        assert_eq!(custody.reserved_worlds(), 1);
        assert_eq!(custody.retained_worlds(), 1);

        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(Command::ConditionalPreparation {
                request: original.clone(),
                reservation,
                ledger: ledger.clone(),
            })
            .unwrap_or_else(|_| panic!("original shutdown request was not queued"));
        let retired = Arc::new(AtomicBool::new(false));
        fault.armed.store(true, Ordering::Release);
        run_actor(
            catalog,
            1,
            ActorStorage {
                capability_archive: directory.path().join("capability-clock-archive"),
                capabilities:
                    super::super::capability_preparation::ledger::CapabilityPreparationLedger::new(
                        durable.clone(),
                        refs.clone(),
                    )
                    .unwrap(),
                preparations: Some(ledger.clone()),
                transcripts: None,
                repository: Arc::new(CampaignRepository::new(durable.clone(), refs.clone())),
                blobs: fault,
                refs: refs.clone(),
            },
            ActorControl {
                receiver,
                stopping: Arc::new(AtomicBool::new(true)),
                roots: Arc::new(Mutex::new(Default::default())),
                retired: retired.clone(),
            },
        );

        assert!(retired.load(Ordering::Acquire));
        assert_eq!(custody.reserved_worlds(), 0);
        assert_eq!(custody.retained_worlds(), 0);
        let restarted = ConditionalPreparationLedger::new(durable, refs).unwrap();
        assert_eq!(restarted.state(&original.execution).unwrap(), expected);
        assert_eq!(restarted.retention_roots().unwrap(), original_roots);
        assert!(!restarted.reserve(&original).unwrap().original_dispatch);
    }
}
