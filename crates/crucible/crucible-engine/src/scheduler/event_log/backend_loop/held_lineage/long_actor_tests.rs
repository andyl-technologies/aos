//! Modeled console bytes use the real concurrent actor and original stopped peer.

use super::*;
use crate::backend::MockSimulationBackend;
use crate::{
    AdvanceOutcome, BackendPhysicalStop, BackendSnapshot, HeldHostStopWitness,
    NativeConsoleByteOrigin, NativeConsoleMappingLease, StepObservation,
};

struct OriginalRun {
    admission: PreparedRunAdmission,
    map: NativeConsoleMappingLease,
}

struct HeldGrowthBackend {
    inner: MockSimulationBackend,
    current: BTreeMap<NodeId, OriginalRun>,
    first: BTreeMap<NodeId, OriginalRun>,
    held: Option<(NodeId, VirtualTime)>,
    held_admission: Option<PreparedRunAdmission>,
    target: VirtualTime,
    dispatched: u64,
    bytes: u64,
}

impl HeldGrowthBackend {
    fn new() -> Self {
        Self {
            inner: MockSimulationBackend::new(),
            current: BTreeMap::new(),
            first: BTreeMap::new(),
            held: None,
            held_admission: None,
            target: VirtualTime { ticks: 0 },
            dispatched: 0,
            bytes: 0,
        }
    }

    fn release(&mut self, witness: &HeldHostStopWitness) -> Result<(), SchedulerError> {
        if self.held.as_ref() != Some(&(witness.node().clone(), witness.physical_pause())) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("modeled guest release differs from the owned physical stop"),
            });
        }
        let admitted = self
            .held_admission
            .as_ref()
            .unwrap_or_else(|| panic!("original held admission"));
        let original = self
            .current
            .get(witness.node())
            .unwrap_or_else(|| panic!("current held node"));
        assert!(admitted.shares_semantic_owner(&original.admission));
        assert_eq!(admitted.context(), original.admission.context());
        assert_eq!(admitted.control_token(), original.admission.control_token());
        self.held = None;
        self.held_admission = None;
        Ok(())
    }

    fn assert_originals(&self) {
        if let Some((node, _)) = &self.held {
            let admitted = self
                .held_admission
                .as_ref()
                .unwrap_or_else(|| panic!("original held admission"));
            let original = self
                .current
                .get(node)
                .unwrap_or_else(|| panic!("current held node"));
            assert!(admitted.shares_semantic_owner(&original.admission));
            assert_eq!(admitted.context(), original.admission.context());
            assert_eq!(admitted.control_token(), original.admission.control_token());
            assert_eq!(
                admitted
                    .retain_native_console_mapping(0)
                    .unwrap_or_else(|_| panic!("held original map")),
                original.map,
            );
        }
        for original in self.first.values().chain(self.current.values()) {
            assert_eq!(
                original
                    .admission
                    .retain_native_console_mapping(0)
                    .unwrap_or_else(|_| panic!("original mapping")),
                original.map,
            );
        }
    }
}

impl SimulationBackend for HeldGrowthBackend {
    fn io_inventory_authority(&self) -> crate::BackendIoInventoryAuthority {
        crate::BackendIoInventoryAuthority::SchedulerOwnedModel
    }

    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        self.inner.step_to(ceiling)
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        self.inner.apply(effect, at)
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        self.inner.snapshot()
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        self.inner.restore(snapshot)
    }

    fn now(&self) -> VirtualTime {
        self.inner.now()
    }

    fn node_now(&self, node: &NodeId) -> Result<VirtualTime, BackendError> {
        self.inner.node_now(node)
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        self.inner.fingerprint(node)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.inner.shutdown()
    }
}

impl ConcurrentSimulationBackend for HeldGrowthBackend {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        maximum_workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunResult>, BackendError> {
        // The genuine concurrent adapter also dispatches single-node catch-up
        // under the same retained original RUN; it must not become a new epoch.
        assert!((1..=2).contains(&maximum_workers));
        assert!((1..=2).contains(&runs.len()));
        runs.into_iter()
            .map(|run| {
                let node = run.node().clone();
                assert!(self.held.as_ref().is_none_or(|(held, _)| held != &node));
                let map = run
                    .admission
                    .retain_native_console_mapping(0)
                    .unwrap_or_else(|_| panic!("genuine RUN mapping"));
                if let Some(original) = self.current.get(&node) {
                    assert_eq!(map, original.map);
                    if run.admission.shares_semantic_owner(&original.admission) {
                        assert_eq!(run.admission.context(), original.admission.context());
                        assert_eq!(
                            run.admission.control_token(),
                            original.admission.control_token()
                        );
                        assert_eq!(
                            run.admission.semantic_horizon(),
                            original.admission.semantic_horizon()
                        );
                    } else {
                        // A committed byte changes the immutable event-log context.
                        // The ordinary planner therefore admits a fresh A RUN;
                        // B's already stopped original admission is never replaced.
                        assert_eq!(node.name, "a");
                        assert_ne!(run.admission.context(), original.admission.context());
                        assert!(run.admission.control_token() > original.admission.control_token());
                        self.current.insert(
                            node.clone(),
                            OriginalRun {
                                admission: run.admission.clone(),
                                map: map.clone(),
                            },
                        );
                    }
                } else {
                    self.current.insert(
                        node.clone(),
                        OriginalRun {
                            admission: run.admission.clone(),
                            map: map.clone(),
                        },
                    );
                    self.first
                        .entry(node.clone())
                        .or_insert_with(|| OriginalRun {
                            admission: run.admission.clone(),
                            map: map.clone(),
                        });
                }
                let before = self.inner.node_now(&node)?.ticks;
                let reached = if node.name == "a" {
                    VirtualTime { ticks: before + 1 }
                } else {
                    self.target
                };
                assert!(before < reached.ticks && reached <= run.ceiling());
                let mut step = StepObservation::from_advance_outcome(
                    reached,
                    AdvanceOutcome::Paused {
                        at: Icount {
                            retired: reached.ticks,
                        },
                    },
                );
                step.requested_ceiling = run.ceiling();
                self.inner.step_node_to(&node, reached)?;
                let observations = if node.name == "a" {
                    let origin = NativeConsoleByteOrigin {
                        device: ContentHash { bytes: [7; 32] },
                        stream: 1,
                        logical_generation: 0,
                        node_sequence: reached.ticks,
                        stream_sequence: reached.ticks,
                        emitted_ps: reached.ticks,
                        raw_prefix: reached.ticks,
                        vcpu: 0,
                        byte: b'A',
                    };
                    let event = map
                        .project_origin(&node, &origin)
                        .unwrap_or_else(|_| panic!("same original byte map"));
                    let mut foreign = origin.clone();
                    foreign.logical_generation = 1;
                    assert!(map.project_origin(&node, &foreign).is_err());
                    step.physical_stop = BackendPhysicalStop::ConsoleOutput {
                        sequence: origin.node_sequence,
                    };
                    self.bytes += 1;
                    vec![event]
                } else {
                    step.physical_stop = BackendPhysicalStop::CampaignMarker;
                    self.held = Some((node.clone(), reached));
                    self.held_admission = Some(run.admission.clone());
                    Vec::new()
                };
                self.dispatched += 1;
                step.applied_preemptions = run.preemptions;
                Ok(ConcurrentBackendRunResult::Completed(
                    ConcurrentBackendRunOutcome {
                        node,
                        step,
                        rng_evidence: Vec::new(),
                        network_outputs: Vec::new(),
                        observations,
                    },
                ))
            })
            .collect()
    }
}

fn held_growth_scheduler() -> SingleScheduler {
    let nodes = ["a", "b"]
        .into_iter()
        .map(|name| SchedulerScenarioNode {
            id: SchedulerNodeId {
                node: NodeId { name: name.into() },
                kind: SchedulingNodeKind::Vm,
            },
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Runnable,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        })
        .collect();
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "memory-diagnostic-held-console-growth",
        32768,
        SimInstant { ticks: 32768 },
        nodes,
        Vec::new(),
    )
    .with_rendezvous_interval(SimDuration { ticks: 4096 })
    .unwrap_or_else(|_| panic!("retained semantic RUN cap"));
    SingleScheduler::new(scenario).unwrap_or_else(|_| panic!("genuine two-node scheduler"))
}

#[test]
fn original_stopped_peer_survives_more_than_one_full_evidence_segment() {
    const BYTES: u64 = 2048;
    let mut backend = HeldGrowthBackend::new();
    backend.target = VirtualTime { ticks: BYTES };
    let mut actor = BackendQuantumLoop::new(held_growth_scheduler(), backend);
    let result = actor
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: actor.loop_impl().configuration().clone(),
                control: Vec::new(),
            },
            2,
        )
        .unwrap_or_else(|error| panic!("actual long-held actor: {error}"));
    assert_eq!(actor.backend().bytes, BYTES);
    assert_eq!(actor.backend().dispatched, BYTES + 1);
    assert_eq!(result.outcomes.len() as u64, BYTES + 1);
    actor.backend().assert_originals();
    let held = actor
        .held_host_continuation
        .as_ref()
        .unwrap_or_else(|| panic!("original B remains held"));
    assert!(
        held.lineage
            .tip
            .as_ref()
            .is_none_or(|tip| tip.generation <= MAX_CANONICAL_EXTENSIONS)
    );
    assert!(!held.lineage.certified_origins.is_empty());
    assert!(
        held.lineage
            .tip
            .as_ref()
            .is_none_or(|tip| tip.generation <= 6)
    );
    assert!(held.lineage.certified_origins.len() <= actor.loop_impl().nodes.len() * 3);
    assert_eq!(held.original_runs.len(), 2);
    let retained_b = &held.original_runs[&NodeId { name: "b".into() }];
    assert!(
        retained_b.admission.shares_semantic_owner(
            actor
                .backend()
                .held_admission
                .as_ref()
                .unwrap_or_else(|| panic!("actual stopped B owner")),
        )
    );
    let log = actor.loop_impl().event_log().retained_entries();
    let emitted = log
        .iter()
        .filter_map(|entry| match &entry.payload {
            SchedulerEventLogPayload::Observable(
                crate::ObservableEventPayload::NativeConsoleByte { origin, .. },
            ) => Some(origin.node_sequence),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(emitted, (1..=BYTES).collect::<Vec<_>>());
    let checkpoint = actor
        .loop_impl()
        .checkpoint()
        .unwrap_or_else(|error| panic!("exact canonical checkpoint: {error}"));
    let bytes = checkpoint
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("checkpoint encode: {error}"));
    assert_eq!(
        SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("checkpoint decode: {error}"))
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("checkpoint reencode: {error}")),
        bytes
    );
    let witness = actor
        .held_host_stop_witness()
        .unwrap_or_else(|| panic!("actual B marker"));
    actor
        .validate_held_host_stop(&witness)
        .unwrap_or_else(|error| panic!("exact owner after checkpoints: {error}"));
    let before = actor.loop_impl().event_log_offset();
    let dispatched = actor.backend().dispatched;
    assert!(
        actor
            .settle_held_host_stop(&witness, |_, _, _| -> Result<(), SchedulerError> {
                Err(rejected("deliberately refused guest release"))
            })
            .is_err()
    );
    assert_eq!(actor.loop_impl().event_log_offset(), before);
    assert_eq!(actor.backend().dispatched, dispatched);
    actor
        .settle_held_host_stop(&witness, |_, backend, _| backend.release(&witness))
        .unwrap_or_else(|error| panic!("explicit real stopped-peer release: {error}"));
    assert!(!actor.has_unsettled_host_continuation());
    assert_eq!(actor.backend().dispatched, dispatched);
}
