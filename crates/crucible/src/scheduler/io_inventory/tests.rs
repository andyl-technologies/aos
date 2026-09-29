//! Real queue and World import tests with explicitly modeled native observation.
//!
//! These exercise the actual IoCore, scheduler import and continuation codecs.
//! They do not install or authenticate a native Source or physical input owner.

use super::*;
use crate::{
    ContentAddressedBlobRef, NodeTemplate, ReadyPoint, VmArchitecture, WhiteBoxPolicy,
    WorldBlockLatency, WorldIoCoreConfig, WorldIoNode, WorldNode, WorldNodeDef,
};
use crucible_device::{
    AffineLatency, ComputedResponse, DeviceError, IoCore, IoSubNode, Request, Response,
    ResponseStatus,
};

pub(in crate::scheduler) fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("physical inventory fixture: {error:?}"))
}

fn id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

pub(in crate::scheduler) struct Echo;

impl IoSubNode for Echo {
    type Latency = AffineLatency;
    type ComputeCheckpoint = ();

    fn latency_model(&self) -> &AffineLatency {
        &AffineLatency {
            base_ns: 0,
            per_byte_ns: 0,
        }
    }

    fn compute_checkpoint(&self) {}

    fn restore_compute_checkpoint(&mut self, _: ()) {}

    fn compute(&mut self, request: &Request) -> Result<ComputedResponse, DeviceError> {
        Ok(ComputedResponse::primary(Response::new(
            request.request_id,
            ResponseStatus::Ok,
            request.payload.clone(),
        )))
    }
}

pub(in crate::scheduler) fn fixture() -> (
    SingleScheduler,
    IoCore,
    crucible_device::block::BlockFaultState,
) {
    fixture_at(0, 30)
}

fn fixture_at(
    ready: u64,
    reply: u64,
) -> (
    SingleScheduler,
    IoCore,
    crucible_device::block::BlockFaultState,
) {
    let bytes = vec![0; 512];
    let store = MemoryDagStore::new();
    let image = ok(store.put(&bytes));
    let world = ok(World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(WorldNode {
                id: id("a"),
                arch: VmArchitecture::X86_64,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::FixedIcount {
                    icount: Icount { retired: ready },
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: 1,
                kernel: None,
                root_image: None,
                initrd: None,
            }),
            WorldNodeDef::Io(WorldIoNode::block(
                id("disk"),
                id("a"),
                WorldIoCoreConfig::new(),
                ContentAddressedBlobRef::from_hash(image),
                512,
                WorldBlockLatency::new(0, 0, 0, 0, 0),
            )),
        ],
        Vec::new(),
    ));
    let node = SchedulerScenarioNode {
        id: SchedulerNodeId {
            node: id("a"),
            kind: SchedulingNodeKind::Vm,
        },
        counter: NodeCounter { ticks: ready },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead: NetworkLookahead::Infinite,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    };
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "actual-queue-inventory",
        16,
        SimInstant { ticks: 64 },
        vec![node],
        Vec::new(),
    )
    .with_ready_point_counter(
        SchedulerNodeId {
            node: id("a"),
            kind: SchedulingNodeKind::Vm,
        },
        NodeCounter { ticks: ready },
    );
    let scheduler = ok(SingleScheduler::from_world(
        scenario,
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    ));
    let source = ok(crate::WorldIoInstantiationLayout::derive(
        &world,
        WorldIoLayoutPolicy::default(),
    ))
    .get(&id("disk"))
    .unwrap_or_else(|| panic!("declared source is absent"))
    .source_node;
    let mut queue = ok(IoCore::new(source, 4, 4));
    ok(queue.enqueue_request(Request::new(reply, 9, b"actual response".to_vec())));
    ok(queue.process_inbox(&mut Echo));
    (
        scheduler,
        queue,
        crucible_device::block::BlockFaultState::write_through(512),
    )
}

pub(in crate::scheduler) fn observation(
    scheduler: &SingleScheduler,
    queue: &IoCore,
    pipeline: &crucible_device::block::BlockFaultState,
) -> BackendIoInventory {
    let snapshot = queue.snapshot();
    let device = SchedulerNodeId {
        node: id("disk"),
        kind: SchedulingNodeKind::Disk,
    };
    let completions = snapshot
        .inflight
        .iter()
        .map(|pending| crate::BackendIoComputedReply {
            source_delivery: pending.key,
            payload: pending.response.payload.clone(),
        })
        .collect();
    BackendIoInventory {
        node: id("a"),
        observed: scheduler.nodes[0].counter,
        generation: NonZeroU64::MIN,
        native_caps: BackendIoNativeCaps {
            timer: BackendIoNativeCap::ObservedAbsent,
            input: BackendIoNativeCap::ObservedAbsent,
        },
        queues: vec![BackendIoQueueSnapshot {
            world: scheduler
                .inventory_world
                .as_ref()
                .unwrap_or_else(|| panic!("actual World owner missing"))
                .id(),
            device,
            source_node: snapshot.src_node,
            revision: snapshot.queue_revision,
            pipeline_revision: Some(ok(pipeline.observation_revision())),
            next_pipeline_boundary: ok(
                pipeline.execution_service_summary(scheduler.nodes[0].counter.ticks)
            )
            .input_deadline
            .map(|ticks| NodeCounter { ticks }),
            completions,
        }],
    }
}

#[test]
fn repeated_actual_queue_observation_preserves_the_single_canonical_key() {
    let (mut scheduler, queue, pipeline) = fixture();
    let device = SchedulerNodeId {
        node: id("disk"),
        kind: SchedulingNodeKind::Disk,
    };
    let consumer = scheduler.nodes[0].id.clone();
    scheduler
        .event_sequences
        .set_next_sequence(device, consumer, 100);
    let inventory = observation(&scheduler, &queue, &pipeline);

    ok(scheduler.import_initial_io_inventory(inventory.clone()));
    let first = scheduler.pending_events.clone();
    ok(scheduler.import_initial_io_inventory(inventory));

    assert_eq!(scheduler.pending_events, first);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].key.sequence(), 100);
    let ScheduledEventPayload::IoCompletion(completion) = &first[0].payload else {
        panic!("physical completion absent");
    };
    assert_eq!(completion.source_delivery, queue.snapshot().inflight[0].key);
    assert_eq!(completion.source_delivery.seq, 0);
}

#[test]
fn missing_foreign_and_changed_queue_observations_leave_actor_state_unchanged() {
    let (mut scheduler, queue, pipeline) = fixture();
    let inventory = observation(&scheduler, &queue, &pipeline);
    ok(scheduler.import_initial_io_inventory(inventory.clone()));
    let before = ok(ok(scheduler.checkpoint()).canonical_bytes());
    let mut missing = inventory.clone();
    missing.queues.clear();
    let mut foreign = inventory.clone();
    foreign.queues[0].source_node += 1;
    let mut mutated = inventory;
    mutated.queues[0].completions[0].payload.push(1);

    for refused in [missing, foreign, mutated] {
        assert!(scheduler.import_initial_io_inventory(refused).is_err());
        assert_eq!(ok(ok(scheduler.checkpoint()).canonical_bytes()), before);
    }
}

#[test]
fn actual_queue_removal_without_acknowledged_publication_is_refused() {
    let (mut scheduler, mut queue, pipeline) = fixture();
    ok(scheduler.import_initial_io_inventory(observation(&scheduler, &queue, &pipeline)));
    let before = scheduler.pending_events.clone();
    assert_eq!(ok(queue.advance_to(30)), 1);
    assert!(ok(queue.pop_response()).is_some());

    assert!(
        scheduler
            .import_initial_io_inventory(observation(&scheduler, &queue, &pipeline))
            .is_err()
    );
    assert_eq!(scheduler.pending_events, before);
}

#[test]
fn pending_origin_ledger_survives_repeated_restore_and_rejects_prior_schema() {
    let (mut scheduler, queue, pipeline) = fixture();
    ok(scheduler.import_initial_io_inventory(observation(&scheduler, &queue, &pipeline)));
    let bytes = ok(ok(scheduler.checkpoint()).canonical_bytes());
    assert!(bytes.starts_with(b"crucible.single-scheduler-continuation.v6\0"));

    for _ in 0..2 {
        let (mut restored, _, _) = fixture();
        ok(ok(SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)).restore_into(&mut restored));
        assert_eq!(restored.imported_io, scheduler.imported_io);
        ok(restored.import_initial_io_inventory(observation(&restored, &queue, &pipeline)));
        assert_eq!(restored.pending_events, scheduler.pending_events);
    }
    for &version in b"45" {
        let mut retired = bytes.clone();
        retired[b"crucible.single-scheduler-continuation.v".len()] = version;
        assert!(matches!(
            SingleSchedulerCheckpoint::from_canonical_bytes(&retired),
            Err(SingleSchedulerCheckpointError::Version)
        ));
    }
}

#[test]
fn unknown_native_caps_refuse_before_actor_import_or_pick() {
    let (mut scheduler, queue, pipeline) = fixture();
    let before = ok(ok(scheduler.checkpoint()).canonical_bytes());
    let original = observation(&scheduler, &queue, &pipeline);

    for timer_unknown in [false, true] {
        let mut missing = original.clone();
        if timer_unknown {
            missing.native_caps.timer = BackendIoNativeCap::Unknown;
        } else {
            missing.native_caps.input = BackendIoNativeCap::Unknown;
        }
        assert!(scheduler.import_initial_io_inventory(missing).is_err());
        assert_eq!(ok(ok(scheduler.checkpoint()).canonical_bytes()), before);
        assert!(scheduler.pending_events.is_empty());
        assert!(scheduler.ceiling_publications.is_empty());
    }
}

#[test]
fn native_caps_use_actual_ready_mapping_and_bound_semantic_authorization() {
    let (mut scheduler, queue, pipeline) = fixture_at(100, 130);
    let mut facts = observation(&scheduler, &queue, &pipeline);
    facts.native_caps = BackendIoNativeCaps {
        timer: BackendIoNativeCap::Armed(NodeCounter { ticks: 120 }),
        input: BackendIoNativeCap::Armed(NodeCounter { ticks: 115 }),
    };
    ok(scheduler.import_initial_io_inventory(facts));

    let window =
        ok(scheduler.advance_window(&scheduler.nodes[0], SimInstant { ticks: 0 }, None, None));
    assert_eq!(window.target_time, SimInstant { ticks: 15 });
    assert_eq!(window.semantic_target_time, SimInstant { ticks: 15 });
    assert_eq!(
        window.semantic_icount_rounding,
        SchedulerIcountRounding::ConservativeFloor
    );
    assert_eq!(window.quiescent_horizon, None);
    assert_eq!(scheduler.nodes[0].counter, NodeCounter { ticks: 100 });
    assert!(scheduler.ceiling_publications.is_empty());
}

#[test]
fn armed_zero_is_a_real_due_bound_and_past_native_cap_is_stale() {
    let (mut scheduler, queue, pipeline) = fixture();
    let mut facts = observation(&scheduler, &queue, &pipeline);
    facts.native_caps.timer = BackendIoNativeCap::Armed(NodeCounter { ticks: 0 });
    ok(scheduler.import_initial_io_inventory(facts));

    let window =
        ok(scheduler.advance_window(&scheduler.nodes[0], SimInstant { ticks: 0 }, None, None));
    assert_eq!(window.target_time, SimInstant { ticks: 0 });
    assert_eq!(window.semantic_target_time, SimInstant { ticks: 0 });
    assert!(scheduler.ceiling_publications.is_empty());

    let (mut mapped, queue, pipeline) = fixture_at(100, 120);
    let before = ok(ok(mapped.checkpoint()).canonical_bytes());
    let mut stale = observation(&mapped, &queue, &pipeline);
    stale.native_caps.input = BackendIoNativeCap::Armed(NodeCounter { ticks: 99 });
    assert!(mapped.import_initial_io_inventory(stale).is_err());
    assert_eq!(ok(ok(mapped.checkpoint()).canonical_bytes()), before);
}

#[test]
fn native_cap_knowledge_is_mandatory_and_preserved_by_continuation() {
    let (mut scheduler, queue, pipeline) = fixture();
    let mut facts = observation(&scheduler, &queue, &pipeline);
    facts.native_caps.timer = BackendIoNativeCap::Armed(NodeCounter { ticks: 20 });
    ok(scheduler.import_initial_io_inventory(facts));
    let bytes = ok(ok(scheduler.checkpoint()).canonical_bytes());
    let (mut restored, _, _) = fixture();
    ok(ok(SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)).restore_into(&mut restored));
    assert_eq!(
        restored.imported_native_boundary(&id("a")),
        Some(NodeCounter { ticks: 20 })
    );

    let retained = scheduler
        .imported_io
        .get(&id("a"))
        .unwrap_or_else(|| panic!("retained native facts"));
    let mut encoded = Vec::new();
    ok(ciborium::ser::into_writer(retained, &mut encoded));
    let mut value: ciborium::Value = ok(ciborium::de::from_reader(encoded.as_slice()));
    let ciborium::Value::Map(fields) = &mut value else {
        panic!("imported source map")
    };
    fields.retain(|(key, _)| key.as_text() != Some("native_caps"));
    let mut missing = Vec::new();
    ok(ciborium::ser::into_writer(&value, &mut missing));
    assert!(ciborium::de::from_reader::<ImportedIoNode, _>(missing.as_slice()).is_err());
}

#[test]
fn restored_physical_tick_uses_the_retained_ready_mapping_instead_of_shared_time() {
    let (mut scheduler, queue, pipeline) = fixture_at(100, 120);
    ok(scheduler.import_initial_io_inventory(observation(&scheduler, &queue, &pipeline)));
    assert_eq!(scheduler.pending_events[0].key.virtual_time().ticks, 20);
    let ScheduledEventPayload::IoCompletion(completion) = &scheduler.pending_events[0].payload
    else {
        panic!("physical completion absent");
    };
    assert_eq!(completion.source_delivery.delivery_icount, 120);
    assert_eq!(completion.delivery_tick.ticks, 20);

    let bytes = ok(ok(scheduler.checkpoint()).canonical_bytes());
    let (mut restored, _, _) = fixture_at(100, 120);
    ok(ok(SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)).restore_into(&mut restored));
    assert_eq!(restored.pending_events, scheduler.pending_events);
    ok(restored.import_initial_io_inventory(observation(&restored, &queue, &pipeline)));
    assert_eq!(restored.pending_events.len(), 1);
}

/// The native consumer is deliberately modeled; queue, actor and codecs are real.
struct FixedConsumerBackend {
    model: crate::MockSimulationBackend,
    inventory: BackendIoInventory,
    replies: std::collections::VecDeque<(usize, crate::BackendFixedInputState)>,
    owners: Vec<crate::PreparedHostFixedInput>,
    refuse: bool,
}

impl SimulationBackend for FixedConsumerBackend {
    fn observe_node_io_inventory(
        &mut self,
        node: &NodeId,
    ) -> Result<BackendIoInventory, BackendError> {
        if node != &self.inventory.node {
            return Err(BackendError::Rejected {
                message: String::from("foreign fixture node"),
            });
        }
        Ok(self.inventory.clone())
    }

    fn settle_fixed_input(
        &mut self,
        prepared: &crate::PreparedHostFixedInput,
    ) -> Result<crate::BackendFixedInputResult, BackendError> {
        self.owners.push(prepared.clone());
        if self.refuse {
            return Err(BackendError::Rejected {
                message: String::from("modeled consumer refusal"),
            });
        }
        let Some((consumed, state)) = self.replies.pop_front() else {
            return Err(BackendError::Rejected {
                message: String::from("fixture outcome absent"),
            });
        };
        Ok(crate::BackendFixedInputResult {
            prepared: prepared.clone(),
            consumed,
            state,
        })
    }

    fn step_to(&mut self, at: VirtualTime) -> Result<crate::StepObservation, BackendError> {
        self.model.step_to(at)
    }

    fn apply(
        &mut self,
        effect: &crate::BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
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
        self.model.shutdown()
    }
}

fn fixed_actor(
    replies: &[(usize, crate::BackendFixedInputState)],
) -> crate::BackendQuantumLoop<SingleScheduler, FixedConsumerBackend> {
    let (scheduler, mut queue, pipeline) = fixture_at(30, 30);
    ok(queue.enqueue_request(Request::new(30, 10, b"second actual response".to_vec())));
    ok(queue.process_inbox(&mut Echo));
    let inventory = observation(&scheduler, &queue, &pipeline);
    crate::BackendQuantumLoop::new(
        scheduler,
        FixedConsumerBackend {
            model: crate::MockSimulationBackend::new(),
            inventory,
            replies: replies.iter().copied().collect(),
            owners: Vec::new(),
            refuse: false,
        },
    )
}

#[test]
fn fixed_current_input_keeps_the_original_owner_and_batch_through_partial_reseal() {
    use crate::BackendFixedInputState::{Partial, Pending, Published, Resealed};
    let mut actor = fixed_actor(&[(0, Pending), (1, Partial), (2, Resealed), (2, Published)]);
    let configuration = actor.loop_impl().configuration.clone();
    let frontier = actor.loop_impl().frontier;

    for state in [Pending, Partial, Resealed] {
        assert_eq!(
            ok(actor.settle_current_fixed_input()).map(|result| result.state),
            Some(state)
        );
        assert_eq!(actor.loop_impl().pending_events.len(), 2);
        assert!(actor.loop_impl().checkpoint().is_err());
        assert!(actor.loop_impl().settled_fixed_input_events.is_empty());
        assert_eq!(actor.loop_impl().configuration, configuration);
        assert_eq!(actor.loop_impl().frontier, frontier);
        assert!(actor.loop_impl().ceiling_publications.is_empty());
    }
    assert_eq!(
        ok(actor.settle_current_fixed_input()).map(|result| result.state),
        Some(Published)
    );
    assert!(actor.loop_impl().pending_events.is_empty());
    assert_eq!(actor.loop_impl().settled_fixed_input_events.len(), 2);
    assert!(
        actor
            .backend()
            .owners
            .iter()
            .all(|owner| owner == &actor.backend().owners[0])
    );
    assert_eq!(actor.backend().owners[0].at(), NodeCounter { ticks: 30 });
    assert_eq!(
        actor.backend().owners[0].events()[0]
            .key
            .virtual_time()
            .ticks,
        0
    );
    assert_eq!(actor.loop_impl().configuration, configuration);
    assert_eq!(actor.loop_impl().frontier, frontier);
    assert!(actor.loop_impl().ceiling_publications.is_empty());

    let bytes = ok(ok(actor.loop_impl().checkpoint()).canonical_bytes());
    let (mut restored, _, _) = fixture_at(30, 30);
    ok(ok(SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)).restore_into(&mut restored));
    assert_eq!(
        restored.settled_fixed_input_events,
        actor.loop_impl().settled_fixed_input_events
    );
    assert_eq!(restored.fixed_input_generation, 1);
}

#[test]
fn partial_fixed_input_failure_preserves_the_entire_batch_cleanup_only() {
    use crate::BackendFixedInputState::Partial;
    let mut actor = fixed_actor(&[(1, Partial)]);
    assert!(ok(actor.settle_current_fixed_input()).is_some());
    let before = actor.loop_impl().pending_events.clone();
    actor.backend_mut().refuse = true;

    assert!(actor.settle_current_fixed_input().is_err());
    assert_eq!(actor.loop_impl().pending_events, before);
    assert!(actor.loop_impl().settled_fixed_input_events.is_empty());
    let calls = actor.backend().owners.len();
    assert!(actor.settle_current_fixed_input().is_err());
    assert_eq!(actor.backend().owners.len(), calls);
    assert!(actor.loop_impl().ceiling_publications.is_empty());
}

#[test]
fn incomplete_published_and_regressing_fixed_input_results_cannot_retire_events() {
    use crate::BackendFixedInputState::{Partial, Published};
    for outcomes in [vec![(1, Published)], vec![(1, Partial), (0, Partial)]] {
        let mut actor = fixed_actor(&outcomes);
        if outcomes.len() == 2 {
            assert!(ok(actor.settle_current_fixed_input()).is_some());
        }
        assert!(actor.settle_current_fixed_input().is_err());
        assert_eq!(actor.loop_impl().pending_events.len(), 2);
        assert!(actor.loop_impl().settled_fixed_input_events.is_empty());
        assert!(actor.loop_impl().ceiling_publications.is_empty());
    }
}

#[test]
fn fixed_input_generation_exhaustion_refuses_before_backend_effects() {
    use crate::BackendFixedInputState::Published;
    let mut actor = fixed_actor(&[(2, Published)]);
    actor.loop_impl_mut().fixed_input_generation = u64::MAX;

    assert!(actor.settle_current_fixed_input().is_err());
    assert!(actor.backend().owners.is_empty());
    assert_eq!(actor.loop_impl().pending_events.len(), 2);
    assert!(actor.loop_impl().settled_fixed_input_events.is_empty());
}

#[test]
fn changed_actor_source_refuses_before_a_second_fixed_input_backend_call() {
    use crate::BackendFixedInputState::{Partial, Published};
    let mut actor = fixed_actor(&[(1, Partial), (2, Published)]);
    assert!(ok(actor.settle_current_fixed_input()).is_some());
    actor.loop_impl_mut().branch_frontier_cap = Some(SimInstant { ticks: 4 });
    let calls = actor.backend().owners.len();

    assert!(actor.settle_current_fixed_input().is_err());
    assert_eq!(actor.backend().owners.len(), calls);
    assert_eq!(actor.loop_impl().pending_events.len(), 2);
    assert!(actor.loop_impl().settled_fixed_input_events.is_empty());
}

#[test]
fn a_partial_fixed_consumer_cannot_be_overwritten_by_checkpoint_restore() {
    use crate::BackendFixedInputState::Partial;
    let mut actor = fixed_actor(&[(1, Partial)]);
    let initial = ok(actor.loop_impl().checkpoint());
    assert!(ok(actor.settle_current_fixed_input()).is_some());
    let before = actor.loop_impl().pending_events.clone();

    assert!(initial.restore_into(actor.loop_impl_mut()).is_err());
    assert_eq!(actor.loop_impl().pending_events, before);
    assert!(actor.loop_impl().checkpoint().is_err());
}

#[test]
fn repeated_inventory_cannot_recreate_a_missing_original_actor_event() {
    let (mut scheduler, queue, pipeline) = fixture();
    let observed = observation(&scheduler, &queue, &pipeline);
    ok(scheduler.import_initial_io_inventory(observed.clone()));
    scheduler.pending_events.clear();

    assert!(scheduler.import_initial_io_inventory(observed).is_err());
    assert!(scheduler.pending_events.is_empty());
}

#[test]
fn published_fixed_input_history_is_committed_once_by_the_later_semantic_run() {
    use crate::BackendFixedInputState::Published;
    let mut actor = fixed_actor(&[(2, Published)]);
    assert_eq!(
        ok(actor.settle_current_fixed_input()).map(|result| result.state),
        Some(Published)
    );
    let settled = actor.loop_impl().settled_fixed_input_events.clone();
    let scheduler = actor.loop_impl_mut();
    let prepared = ok(scheduler.prepare_host_concurrent_quantum_limited(
        QuantumRequest {
            configuration: scheduler.configuration.clone(),
            control: Vec::new(),
        },
        1,
    ));
    let run = prepared.runs[0].clone();
    let reached = run.plan.target_counter;
    let outcome = ok(scheduler.commit_prepared_host_run(run, reached, &[], Vec::new(), Vec::new()));

    assert_eq!(outcome.resolved_events, settled);
    assert!(scheduler.settled_fixed_input_events.is_empty());
    assert!(scheduler.pending_events.is_empty());
    assert_eq!(scheduler.quanta, 1);
}

#[test]
fn independent_block_pipeline_revision_exposes_deadline_without_queue_mutation() {
    let (mut scheduler, queue, mut pipeline) = fixture();
    let original = observation(&scheduler, &queue, &pipeline);
    ok(scheduler.import_initial_io_inventory(original.clone()));
    let before = ok(ok(scheduler.checkpoint()).canonical_bytes());
    let mut hidden = original.clone();
    hidden.queues[0].next_pipeline_boundary = Some(NodeCounter { ticks: 46 });

    assert!(scheduler.import_initial_io_inventory(hidden).is_err());
    assert_eq!(ok(ok(scheduler.checkpoint()).canonical_bytes()), before);

    let request = crucible_device::BlockRequest::read(11, 0, 4);
    let mut directive =
        crucible_device::block::ResolvedBlockFaultDirective::fault_free(&request, 512);
    directive.execution_ticks = 46;
    ok(pipeline.require_execution_opportunities(true));
    ok(pipeline.install(request.identity(), directive));
    let mut device = crucible_device::BlockDevice::new(
        ok(IoCore::new(queue.snapshot().src_node, 4, 4)),
        crucible_device::BaseImage::new(vec![0; 512]),
        crucible_device::BlockLatency::default(),
    );
    ok(device.restore_storage_fault_state(pipeline));
    ok(device.submit(0, &request));
    pipeline = device.storage_fault_state().clone();
    let current = observation(&scheduler, &queue, &pipeline);
    assert_eq!(current.queues[0].revision, original.queues[0].revision);
    assert!(current.queues[0].pipeline_revision > original.queues[0].pipeline_revision);
    ok(scheduler.import_initial_io_inventory(current));

    assert_eq!(
        scheduler.imported_pipeline_boundary(&id("a")),
        Some(NodeCounter { ticks: 46 })
    );
    assert_eq!(scheduler.pending_events.len(), 1);
}

#[test]
fn block_pipeline_revision_is_mandatory_and_cannot_regress() {
    let (mut scheduler, queue, mut pipeline) = fixture();
    ok(pipeline.require_directives(true));
    let current = observation(&scheduler, &queue, &pipeline);
    ok(scheduler.import_initial_io_inventory(current.clone()));
    let before = ok(ok(scheduler.checkpoint()).canonical_bytes());
    let mut missing = current.clone();
    missing.queues[0].pipeline_revision = None;
    let mut stale = current;
    stale.queues[0].pipeline_revision = Some(NonZeroU64::MIN);

    assert!(scheduler.import_initial_io_inventory(missing).is_err());
    assert!(scheduler.import_initial_io_inventory(stale).is_err());
    assert_eq!(ok(ok(scheduler.checkpoint()).canonical_bytes()), before);
}

#[test]
fn restored_queue_requires_an_explicit_pipeline_revision_field() {
    let (mut scheduler, queue, pipeline) = fixture();
    ok(scheduler.import_initial_io_inventory(observation(&scheduler, &queue, &pipeline)));
    let retained = scheduler
        .imported_io
        .get(&id("a"))
        .unwrap_or_else(|| panic!("actual imported node"));
    let queue = retained
        .queues
        .values()
        .next()
        .unwrap_or_else(|| panic!("actual imported queue"));
    let mut encoded = Vec::new();
    ok(ciborium::ser::into_writer(queue, &mut encoded));
    let mut value: ciborium::Value = ok(ciborium::de::from_reader(encoded.as_slice()));
    let ciborium::Value::Map(fields) = &mut value else {
        panic!("queue checkpoint map");
    };
    let before = fields.len();
    fields.retain(|(key, _)| key != &ciborium::Value::Text("pipeline_revision".into()));
    assert_eq!(fields.len(), before - 1);
    encoded.clear();
    ok(ciborium::ser::into_writer(&value, &mut encoded));

    let restored: Result<ImportedIoQueue, _> = ciborium::de::from_reader(encoded.as_slice());
    assert!(restored.is_err());
}

#[test]
fn restored_current_reply_cannot_replace_its_actor_projected_time() {
    let (mut scheduler, queue, pipeline) = fixture_at(100, 120);
    ok(scheduler.import_initial_io_inventory(observation(&scheduler, &queue, &pipeline)));
    let imported = scheduler
        .imported_io
        .get_mut(&id("a"))
        .unwrap_or_else(|| panic!("actual imported owner"));
    let queue = imported
        .queues
        .values_mut()
        .next()
        .unwrap_or_else(|| panic!("actual imported queue"));
    queue.current[0].delivery_tick = SimInstant { ticks: 120 };

    assert!(scheduler.validate_imported_io_ledger().is_err());
}

#[test]
fn native_caps_bound_idle_wake_without_fabricating_quiescent_completion() {
    let (mut scheduler, queue, pipeline) = fixture_at(100, 130);
    scheduler.nodes[0].activity = SchedulerNodeActivity::Idle;
    for vcpu in &mut scheduler.nodes[0].vcpu_idle_states {
        vcpu.halted = true;
        vcpu.pending_input = false;
    }
    let mut facts = observation(&scheduler, &queue, &pipeline);
    facts.native_caps.timer = BackendIoNativeCap::Armed(NodeCounter { ticks: 110 });
    ok(scheduler.import_initial_io_inventory(facts));

    let candidate = ok(scheduler.idle_advance_candidate(&scheduler.nodes[0], None, None));
    let EffectiveHorizonProjection::Finite {
        target_time,
        quiescent_horizon,
        ..
    } = candidate
    else {
        panic!("actual armed native deadline must bound the idle candidate")
    };
    assert_eq!(target_time, SimInstant { ticks: 10 });
    assert_eq!(quiescent_horizon, None);
    assert_eq!(scheduler.nodes[0].counter, NodeCounter { ticks: 100 });
    assert!(scheduler.ceiling_publications.is_empty());
}

#[path = "fixed_consumers.rs"]
mod fixed_consumers;

#[test]
fn live_world_attachment_retains_the_exact_physical_queue_owner() {
    let (mut scheduler, queue, pipeline) = fixture();
    let world = scheduler
        .inventory_world
        .clone()
        .unwrap_or_else(|| panic!("fixture World"));
    // A live backend owns its queues; construct the equivalent scheduler state
    // before the actual World attachment rather than a modeled device owner.
    scheduler.inventory_world = None;
    scheduler.device_sub_nodes.clear();
    ok(scheduler.attach_world_network_links(&world));

    assert_eq!(
        scheduler
            .inventory_world
            .as_ref()
            .unwrap_or_else(|| panic!("attached World"))
            .id(),
        world.id()
    );
    let inventory = observation(&scheduler, &queue, &pipeline);
    ok(scheduler.import_initial_io_inventory(inventory));
    assert_eq!(scheduler.imported_io.len(), 1);
}

#[test]
fn mismatched_vm_topology_and_rebinding_world_preserve_the_original_owner() {
    let (mut scheduler, _queue, _pipeline) = fixture();
    let world = scheduler
        .inventory_world
        .clone()
        .unwrap_or_else(|| panic!("fixture World"));
    scheduler.inventory_world = None;
    scheduler.device_sub_nodes.clear();
    let mut foreign_vm = world
        .vm_nodes()
        .first()
        .unwrap_or_else(|| panic!("VM"))
        .clone();
    foreign_vm.id = id("foreign");
    let foreign = ok(World::from_node_defs_and_links(
        vec![WorldNodeDef::Vm(foreign_vm)],
        Vec::new(),
    ));
    let before = ok(ok(scheduler.checkpoint()).canonical_bytes());
    assert!(matches!(
        scheduler.attach_world_network_links(&foreign),
        Err(SchedulerWorldInstantiationError::VmTopologyMismatch { .. })
    ));
    assert!(scheduler.inventory_world.is_none());
    assert_eq!(ok(ok(scheduler.checkpoint()).canonical_bytes()), before);

    ok(scheduler.attach_world_network_links(&world));
    let mut changed_vm = world
        .vm_nodes()
        .first()
        .unwrap_or_else(|| panic!("VM"))
        .clone();
    changed_vm.memory_mib += 1;
    let rebound = ok(World::from_node_defs_and_links(
        vec![WorldNodeDef::Vm(changed_vm)],
        Vec::new(),
    ));
    assert!(scheduler.attach_world_network_links(&rebound).is_err());
    assert_eq!(
        scheduler
            .inventory_world
            .as_ref()
            .unwrap_or_else(|| panic!("original owner"))
            .id(),
        world.id()
    );
    assert_eq!(ok(ok(scheduler.checkpoint()).canonical_bytes()), before);
}

#[path = "../device_group_selection/tests.rs"]
mod device_group_selection_tests;
