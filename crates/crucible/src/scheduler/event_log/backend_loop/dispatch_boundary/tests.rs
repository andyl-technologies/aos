//! Actual imported queues and publication ledgers with modeled native stops.
//!
//! Real scheduler PICK, late import, cap authorization, ring publication,
//! refresh and checkpoint restore are exercised. The stop and final execution
//! observations are modeled; these tests grant no native Source authority.

use super::*;
use crate::scheduler::io_inventory::tests::{Echo, fixture, observation, ok};
use crate::{
    AdvanceOutcome, BackendError, IoCompletion, QuantumRequest, SingleSchedulerCheckpoint,
    StepObservation,
};
use crucible_device::{IoCore, Request};
use crucible_shmem::{FrameEntry, RingHeader};

struct SelectedQueueBackend {
    model: crate::MockSimulationBackend,
    queue: IoCore,
    ring: RingHeader,
    entries: Vec<FrameEntry>,
    staged: Vec<ScheduledEventKey>,
    refuse_shutdown: bool,
}

impl SimulationBackend for SelectedQueueBackend {
    fn stage_dispatch_boundary_io_completion(
        &mut self,
        boundary: &BackendRunDispatchBoundary,
        key: &ScheduledEventKey,
        completion: &IoCompletion,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        if completion.source_delivery.delivery_icount != boundary.reached.ticks
            || at.ticks != boundary.reached.ticks
        {
            return Err(BackendError::Rejected {
                message: String::from("selected response changed its modeled stopped tick"),
            });
        }
        let result = self
            .queue
            .deliver_selected_to_shmem(
                at.ticks,
                completion.source_delivery,
                &completion.payload,
                &self.ring,
                &mut self.entries,
            )
            .map_err(|error| BackendError::Rejected {
                message: error.source.to_string(),
            })?;
        if !matches!(result, crucible_device::SelectedDeliveryOutcome::Published) {
            return Err(BackendError::Rejected {
                message: String::from("selected fixture publication backpressured"),
            });
        }
        self.staged.push(key.clone());
        Ok(())
    }

    fn step_to(&mut self, at: VirtualTime) -> Result<StepObservation, BackendError> {
        self.model.step_to(at)
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        self.model.apply(effect, at)
    }

    fn snapshot(&mut self) -> Result<crate::BackendSnapshot, BackendError> {
        self.model.snapshot()
    }

    fn restore(&mut self, snapshot: &crate::BackendSnapshot) -> Result<(), BackendError> {
        self.model.restore(snapshot)
    }

    fn now(&self) -> VirtualTime {
        self.model.now()
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        self.model.fingerprint(node)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        if self.refuse_shutdown {
            return Err(BackendError::Rejected {
                message: String::from("modeled shutdown refused without releasing its owner"),
            });
        }
        self.model.shutdown()
    }
}

impl ConcurrentSimulationBackend for SelectedQueueBackend {
    fn execute_concurrent_runs(
        &mut self,
        _: Vec<ConcurrentBackendRun>,
        _: usize,
    ) -> Result<Vec<ConcurrentBackendRunResult>, BackendError> {
        Err(BackendError::Unsupported {
            capability: "fixture initial execution",
        })
    }

    fn resume_dispatch_boundary(
        &mut self,
        run: ConcurrentBackendRun,
        boundary: &BackendRunDispatchBoundary,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        assert_eq!(
            run.admission.control_token(),
            boundary.admission.control_token()
        );
        assert_eq!(run.admission.context(), boundary.admission.context());
        // Only this native observation is modeled. The original semantic owner
        // and refreshed physical window were sealed by the real planner.
        Ok(ConcurrentBackendRunResult::Completed(
            ConcurrentBackendRunOutcome {
                node: run.node().clone(),
                step: StepObservation::from_advance_outcome(
                    run.ceiling(),
                    AdvanceOutcome::ReachedHorizon,
                ),
                rng_evidence: Vec::new(),
                network_outputs: Vec::new(),
                observations: Vec::new(),
            },
        ))
    }
}

fn late_queue_stop(
    second_reply: bool,
) -> (
    SingleScheduler,
    PreparedHostRun,
    SelectedQueueBackend,
    crucible_device::block::BlockFaultState,
    ScheduledEvent,
) {
    let (mut scheduler, initial, pipeline) = fixture();
    let mut queue = ok(IoCore::new(initial.snapshot().src_node, 4, 4));
    ok(scheduler.import_initial_io_inventory(observation(&scheduler, &queue, &pipeline)));
    let mut prepared = ok(scheduler.prepare_host_concurrent_quantum_limited(
        QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        },
        1,
    ));
    let mut run = prepared.runs.remove(0);
    let mut scheduler = prepared.next;
    assert_eq!(run.admission.semantic_horizon().icount.retired, 64);

    ok(queue.enqueue_request(Request::new(30, 9, b"late original response".to_vec())));
    if second_reply {
        ok(queue.enqueue_request(Request::new(30, 10, b"second original response".to_vec())));
    }
    ok(queue.process_inbox(&mut Echo));
    ok(scheduler.import_initial_io_inventory(observation(&scheduler, &queue, &pipeline)));
    let event = scheduler.pending_events[0].clone();
    ok(scheduler.tighten_cap_boundary_admission(&mut run, NodeCounter { ticks: 30 }));
    assert_eq!(run.admission.dispatch_horizon().icount.retired, 30);
    assert_eq!(run.admission.semantic_horizon().icount.retired, 64);
    let backend = SelectedQueueBackend {
        model: crate::MockSimulationBackend::new(),
        queue,
        ring: RingHeader::new(),
        entries: vec![ok(FrameEntry::new(0, 0, 0, &[])); 4],
        staged: Vec::new(),
        refuse_shutdown: false,
    };
    (scheduler, run, backend, pipeline, event)
}

#[test]
fn dispatch_acknowledged_original_queue_survives_refresh_and_checkpoint() {
    let (mut scheduler, mut run, mut backend, pipeline, event) = late_queue_stop(false);
    let boundary = BackendRunDispatchBoundary {
        admission: run.admission.clone(),
        reached: NodeCounter { ticks: 30 },
    };
    let held = HeldDeliveryCeiling::observe(&scheduler, &BTreeMap::new());
    let mut retained = None;
    let result = ok(resolve_dispatch_boundary(
        &mut scheduler,
        &mut backend,
        &mut run,
        boundary,
        &held,
        &mut retained,
    ));
    let ConcurrentBackendRunResult::Completed(completed) = result else {
        panic!("modeled final completion missing");
    };
    assert!(retained.is_none());
    assert_eq!(backend.staged, vec![event.key.clone()]);
    assert_eq!(ok(backend.ring.live_len(&backend.entries)), 1);
    assert!(backend.queue.snapshot().inflight.is_empty());
    assert_eq!(run.staged_input_events, vec![event.clone()]);
    assert_eq!(run.plan.before, NodeCounter { ticks: 0 });

    ok(scheduler.commit_prepared_host_run(
        run,
        completed.step.reached.ticks,
        &[],
        Vec::new(),
        Vec::new(),
    ));
    let bytes = ok(ok(scheduler.checkpoint()).canonical_bytes());
    let (mut restored, _, _) = fixture();
    ok(ok(SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)).restore_into(&mut restored));
    assert_eq!(restored.imported_io, scheduler.imported_io);
    for actor in [&mut scheduler, &mut restored] {
        ok(actor.import_initial_io_inventory(observation(actor, &backend.queue, &pipeline)));
        assert!(actor.pending_events.is_empty());
        let refreshed = ok(ok(actor.checkpoint()).canonical_bytes());
        let (mut replay, _, _) = fixture();
        ok(
            ok(SingleSchedulerCheckpoint::from_canonical_bytes(&refreshed))
                .restore_into(&mut replay),
        );
        assert_eq!(replay.imported_io, actor.imported_io);
    }
}

#[test]
fn dispatch_ledger_refusal_retains_acknowledged_prefix_and_uncertain_original_key() {
    let (mut scheduler, mut run, mut backend, _, first) = late_queue_stop(true);
    let second = scheduler.pending_events[1].clone();
    let original_owner = run.admission.clone();
    let configuration = scheduler.configuration.clone();
    let prefix = scheduler.event_log.offset();
    // Inject a stale duplicate ledger record while the real queue still owns
    // both replies. The post-publication join must refuse this inconsistency;
    // it cannot roll back either actual ring write or erase the attempted key.
    ok(scheduler.record_imported_io_publication(&second));
    let boundary = BackendRunDispatchBoundary {
        admission: run.admission.clone(),
        reached: NodeCounter { ticks: 30 },
    };
    let held = HeldDeliveryCeiling::observe(&scheduler, &BTreeMap::new());
    let mut retained = None;

    assert!(
        resolve_dispatch_boundary(
            &mut scheduler,
            &mut backend,
            &mut run,
            boundary,
            &held,
            &mut retained,
        )
        .is_err()
    );

    assert_eq!(backend.staged, vec![first.key.clone(), second.key.clone()]);
    assert_eq!(ok(backend.ring.live_len(&backend.entries)), 2);
    assert!(backend.queue.snapshot().inflight.is_empty());
    let failed = retained
        .as_ref()
        .unwrap_or_else(|| panic!("owed dispatch owner lost"));
    assert_eq!(failed.applied_keys(), std::slice::from_ref(&first.key));
    assert_eq!(failed.attempted_key(), Some(&second.key));
    assert_eq!(failed.events(), &[first, second]);
    assert_eq!(failed._run.admission, original_owner);
    assert_eq!(run.admission, original_owner);
    assert_eq!(scheduler.nodes[0].counter, NodeCounter { ticks: 0 });
    assert_eq!(scheduler.configuration, configuration);
    assert_eq!(scheduler.event_log.offset(), prefix);
    assert_eq!(scheduler.pending_events.len(), 2);
    assert!(scheduler.last_advance.is_none());
}

#[test]
fn dispatch_shutdown_retains_owed_owner_on_failure_and_releases_it_on_success() {
    let (mut scheduler, mut run, mut backend, _, first) = late_queue_stop(true);
    let second = scheduler.pending_events[1].clone();
    ok(scheduler.record_imported_io_publication(&second));
    let boundary = BackendRunDispatchBoundary {
        admission: run.admission.clone(),
        reached: NodeCounter { ticks: 30 },
    };
    let held = HeldDeliveryCeiling::observe(&scheduler, &BTreeMap::new());
    let mut retained = None;
    assert!(
        resolve_dispatch_boundary(
            &mut scheduler,
            &mut backend,
            &mut run,
            boundary,
            &held,
            &mut retained,
        )
        .is_err()
    );
    backend.refuse_shutdown = true;
    let mut actor = BackendQuantumLoop::new(scheduler, backend);
    actor.failed_dispatch_resolution = retained;
    actor.continuation_poisoned = true;

    assert!(actor.shutdown_backend_owner().is_err());
    let owed = actor
        .failed_dispatch_resolution()
        .unwrap_or_else(|| panic!("failed shutdown lost owner"));
    assert_eq!(owed.applied_keys(), std::slice::from_ref(&first.key));
    assert_eq!(owed.attempted_key(), Some(&second.key));
    assert_eq!(owed.events(), &[first, second]);
    assert_eq!(owed._run.admission, run.admission);
    assert!(!actor.backend().model.state().shutdown);

    actor.backend_mut().refuse_shutdown = false;
    ok(actor.shutdown_backend_owner());
    assert!(actor.failed_dispatch_resolution().is_none());
    assert!(actor.backend().model.state().shutdown);
    assert!(actor.continuation_is_poisoned());
    assert_eq!(actor.loop_impl().nodes[0].counter, NodeCounter { ticks: 0 });
    assert!(actor.loop_impl().last_advance.is_none());
}
