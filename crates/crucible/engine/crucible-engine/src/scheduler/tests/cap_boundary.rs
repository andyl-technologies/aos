//! Scheduler-owned no-motion cap negotiation with explicit model receipts.
//!
//! These fixtures exercise real PICK/publication/arbitration. Their private
//! receipt and timer records model the lower seam and confer no native authority.

use super::*;
use crate::BackendEffect;

struct CapBackend {
    inner: MockSimulationBackend,
    caps: std::collections::VecDeque<u64>,
    retained: BTreeMap<NodeId, BackendRunCapBoundary>,
    dispatch_stops: BTreeMap<NodeId, BackendRunDispatchBoundary>,
    admissions: Vec<PreparedRunAdmission>,
    fail_readmission: bool,
    peer_pause: bool,
    moved_report: bool,
    stale_admission: Option<PreparedRunAdmission>,
}

impl CapBackend {
    fn new(caps: &[u64]) -> Self {
        Self {
            inner: MockSimulationBackend::new(),
            caps: caps.iter().copied().collect(),
            retained: BTreeMap::new(),
            dispatch_stops: BTreeMap::new(),
            admissions: Vec::new(),
            fail_readmission: false,
            peer_pause: false,
            moved_report: false,
            stale_admission: None,
        }
    }

    fn wave(
        &mut self,
        run: ConcurrentBackendRun,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        self.admissions.push(run.admission.clone());
        if run.node().name == "a"
            && let Some(cap) = self.caps.pop_front()
        {
            let before = self.inner.node_now(run.node())?;
            let boundary = BackendRunCapBoundary {
                admission: self.stale_admission.clone().unwrap_or(run.admission),
                stopped: NodeCounter {
                    ticks: before.ticks + u64::from(self.moved_report),
                },
                tighter_cap: NodeCounter { ticks: cap },
            };
            self.retained
                .insert(boundary.admission.node().clone(), boundary.clone());
            return Ok(ConcurrentBackendRunResult::CapBoundary(boundary));
        }
        let step = if self.peer_pause && run.node().name == "b" {
            self.inner
                .step_node_to(run.node(), VirtualTime { ticks: 5 })?;
            let mut step = StepObservation::from_advance_outcome(
                run.ceiling(),
                crate::AdvanceOutcome::Paused {
                    at: Icount { retired: 5 },
                },
            );
            step.physical_stop = crate::BackendPhysicalStop::GuestSelectable;
            step
        } else {
            self.inner.step_node_to(run.node(), run.ceiling())?
        };
        self.retained.remove(run.node());
        if step.physical_stop == crate::BackendPhysicalStop::Horizon
            && step.reached.ticks < run.admission.semantic_horizon().icount.retired
        {
            let boundary = BackendRunDispatchBoundary {
                reached: NodeCounter {
                    ticks: step.reached.ticks,
                },
                admission: run.admission,
            };
            self.dispatch_stops
                .insert(boundary.admission.node().clone(), boundary.clone());
            return Ok(ConcurrentBackendRunResult::DispatchBoundary(boundary));
        }
        Ok(ConcurrentBackendRunResult::Completed(
            ConcurrentBackendRunOutcome {
                node: run.node().clone(),
                step,
                rng_evidence: Vec::new(),
                network_outputs: Vec::new(),
                observations: Vec::new(),
            },
        ))
    }
}

impl SimulationBackend for CapBackend {
    fn io_inventory_authority(&self) -> crate::BackendIoInventoryAuthority {
        crate::BackendIoInventoryAuthority::SchedulerOwnedModel
    }

    fn step_to(&mut self, at: VirtualTime) -> Result<StepObservation, BackendError> {
        self.inner.step_to(at)
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        self.inner.apply(effect, at)
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        self.inner.snapshot()
    }

    fn restore(&mut self, state: &BackendSnapshot) -> Result<(), BackendError> {
        self.inner.restore(state)
    }

    fn now(&self) -> VirtualTime {
        self.inner.now()
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        self.inner.fingerprint(node)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.inner.shutdown()
    }
}

impl ConcurrentSimulationBackend for CapBackend {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        _workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunResult>, BackendError> {
        runs.into_iter().map(|run| self.wave(run)).collect()
    }

    fn resume_cap_boundary(
        &mut self,
        run: ConcurrentBackendRun,
        boundary: &BackendRunCapBoundary,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        if self.retained.get(boundary.admission.node()) != Some(boundary)
            || self.fail_readmission
            || self.inner.node_now(run.node())?.ticks != boundary.stopped.ticks
            || run.admission.context() != boundary.admission.context()
            || run.admission.control_token() != boundary.admission.control_token()
            || run.admission.semantic_horizon() != boundary.admission.semantic_horizon()
            || run.admission.input_inventory().generation()
                <= boundary.admission.input_inventory().generation()
            || run.ceiling().ticks > boundary.tighter_cap.ticks
        {
            return Err(BackendError::Rejected {
                message: String::from("model retained cap source refuses readmission"),
            });
        }
        self.wave(run)
    }

    fn resume_dispatch_boundary(
        &mut self,
        run: ConcurrentBackendRun,
        boundary: &BackendRunDispatchBoundary,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        if self.dispatch_stops.get(run.node()) != Some(boundary)
            || self.inner.node_now(run.node())?.ticks != boundary.reached.ticks
            || run.admission.context() != boundary.admission.context()
            || run.admission.control_token() != boundary.admission.control_token()
            || run.admission.input_inventory().generation()
                <= boundary.admission.input_inventory().generation()
        {
            return Err(BackendError::Rejected {
                message: String::from("model internal cap changed retained owner"),
            });
        }
        self.dispatch_stops.remove(run.node());
        self.wave(run)
    }
}

fn scheduler() -> SingleScheduler {
    test_scheduler(
        vec![test_scenario_node(
            "a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    )
}

fn request(scheduler: &SingleScheduler) -> QuantumRequest {
    QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    }
}

#[test]
fn cap_negotiation_keeps_original_owner_across_each_strictly_tighter_wave() {
    for workers in [1, 2] {
        let scheduler = scheduler();
        let request = request(&scheduler);
        let mut actor = BackendQuantumLoop::new(scheduler, CapBackend::new(&[20, 10]));

        let outcome = actor
            .drive_concurrent_quantum(request, workers)
            .expect("actual scheduler readmits each no-motion wave");

        assert_eq!(outcome.outcomes.len(), 1);
        assert_eq!(outcome.outcomes[0].frontier.ticks, 64);
        let admissions = &actor.backend().admissions;
        assert_eq!(admissions.len(), 4);
        assert_eq!(admissions[1].dispatch_horizon().icount.retired, 20);
        assert_eq!(admissions[2].dispatch_horizon().icount.retired, 10);
        assert_eq!(admissions[3].dispatch_horizon().icount.retired, 64);
        for wave in &admissions[1..] {
            assert_eq!(wave.context(), admissions[0].context());
            assert_eq!(wave.control_token(), admissions[0].control_token());
            assert_eq!(wave.semantic_horizon(), admissions[0].semantic_horizon());
        }
        assert!(
            admissions
                .windows(2)
                .all(|pair| pair[0].input_inventory().generation()
                    < pair[1].input_inventory().generation())
        );
        assert_eq!(actor.backend().inner.state().delivered_inputs.len(), 0);
        assert!(actor.backend().retained.is_empty());
    }
}

#[test]
fn cap_readmission_failure_is_cleanup_only_without_step_floor_or_retry() {
    let scheduler = scheduler();
    let configuration = scheduler.configuration().clone();
    let offset = scheduler.event_log().offset();
    let first_request = request(&scheduler);
    let mut backend = CapBackend::new(&[20]);
    backend.fail_readmission = true;
    let mut actor = BackendQuantumLoop::new(scheduler, backend);

    assert!(actor.drive_concurrent_quantum(first_request, 2).is_err());

    assert_eq!(actor.loop_impl().configuration(), &configuration);
    assert_eq!(actor.loop_impl().event_log().offset(), offset);
    assert_eq!(actor.backend().inner.now().ticks, 0);
    assert_eq!(actor.backend().admissions.len(), 1);
    let retained = actor
        .failed_cap_negotiation()
        .expect("original RUN stays reviewable");
    assert!(
        retained.readmission().input_inventory().generation()
            > retained.boundary().admission.input_inventory().generation()
    );
    assert_eq!(retained.readmission().dispatch_horizon().icount.retired, 20);
    assert_eq!(
        retained.boundary(),
        actor
            .backend()
            .retained
            .values()
            .next()
            .expect("private receipt")
    );
    assert!(
        actor
            .drive_concurrent_quantum(request(actor.loop_impl()), 1)
            .is_err()
    );
    assert_eq!(actor.backend().admissions.len(), 1);
}

#[test]
fn same_looser_or_zero_cap_cannot_republish_scheduler_authority() {
    let scheduler = scheduler();
    let initial = scheduler
        .prepare_host_concurrent_quantum_limited(request(&scheduler), 1)
        .expect("real PICK");
    let target = initial.runs[0].plan.target_counter;
    for cap in [0, target, target + 1] {
        let mut actor = BackendQuantumLoop::new(scheduler.clone(), CapBackend::new(&[cap]));
        assert!(
            actor
                .drive_concurrent_quantum(request(&scheduler), 1)
                .is_err()
        );
        assert_eq!(actor.backend().admissions.len(), 1);
        assert_eq!(actor.backend().inner.now().ticks, 0);
        assert_eq!(
            actor.loop_impl().event_log().offset(),
            scheduler.event_log().offset()
        );
    }
}

#[test]
fn negotiated_motion_rejoins_canonical_peer_stop_before_semantic_publication() {
    for workers in [1, 2] {
        let scheduler = test_scheduler(
            ["a", "b"]
                .into_iter()
                .map(|name| {
                    test_scenario_node(
                        name,
                        0,
                        SchedulerNodeActivity::Runnable,
                        NetworkLookahead::Infinite,
                        ExactLocalEvent::NoArmedTimer,
                    )
                })
                .collect(),
            Vec::new(),
        );
        let first_request = request(&scheduler);
        let mut backend = CapBackend::new(&[20, 10]);
        backend.peer_pause = true;
        let mut actor = BackendQuantumLoop::new(scheduler, backend);

        let outcome = actor
            .drive_concurrent_quantum(first_request, workers)
            .expect("peer selectable remains canonical before paid cap");

        assert_eq!(outcome.outcomes.len(), 1);
        // Uncommitted held a10 keeps the shared frontier at its actual counter0.
        assert_eq!(outcome.outcomes[0].frontier.ticks, 0);
        let witness = actor
            .held_host_stop_witness()
            .expect("peer5 holds later a10");
        assert_eq!(witness.node().name, "b");
        assert_eq!(witness.physical_pause().ticks, 5);
        assert_eq!(actor.loop_impl().nodes[1].counter.ticks, 5);
        assert_eq!(actor.loop_impl().nodes[0].counter.ticks, 0);
        assert_eq!(
            actor
                .backend()
                .inner
                .node_now(&NodeId {
                    name: String::from("a")
                })
                .expect("modeled paid peer remains owned")
                .ticks,
            10
        );
        assert_eq!(
            actor
                .backend()
                .admissions
                .iter()
                .filter(|a| a.node().name == "a")
                .count(),
            3
        );
    }
}

#[test]
fn moved_or_stale_admission_refuses_before_new_motion() {
    for stale in [false, true] {
        let scheduler = scheduler();
        let mut backend = CapBackend::new(&[20]);
        if stale {
            let mut different = scheduler.clone();
            different.topology_epoch += 1;
            let prepared = different
                .prepare_host_concurrent_quantum_limited(request(&different), 1)
                .expect("actual different context PICK");
            backend.stale_admission = Some(prepared.runs[0].admission.clone());
        } else {
            backend.moved_report = true;
        }
        let mut actor = BackendQuantumLoop::new(scheduler.clone(), backend);

        assert!(
            actor
                .drive_concurrent_quantum(request(&scheduler), 2)
                .is_err()
        );

        assert_eq!(actor.backend().admissions.len(), 1);
        assert_eq!(actor.backend().inner.now().ticks, 0);
        assert!(!actor.backend().retained.is_empty());
        assert_eq!(
            actor.loop_impl().event_log().offset(),
            scheduler.event_log().offset()
        );
    }
}
