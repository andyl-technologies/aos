//! Actual concurrent caller and queue publication with modeled native ownership.

use super::*;
use crate::{ConcurrentQuantumLoop, ConcurrentSimulationBackend, QuantumRequest};
use crucible_shmem::{FrameEntry, RingHeader};

struct OwnedQueue {
    owner: NodeId,
    device: SchedulerNodeId,
    core: IoCore,
    pipeline: crucible_device::block::BlockFaultState,
    output: RingHeader,
    entries: Vec<FrameEntry>,
}

struct TwoConsumers {
    world: ContentHash,
    queues: Vec<OwnedQueue>,
    model: crate::MockSimulationBackend,
    owners: Vec<crate::PreparedHostFixedInput>,
    published: Vec<NodeId>,
    dispatches: usize,
    pending_b_once: bool,
    repeat_a: bool,
}

impl SimulationBackend for TwoConsumers {
    fn observe_node_io_inventory(
        &mut self,
        node: &NodeId,
    ) -> Result<BackendIoInventory, BackendError> {
        let queue = self
            .queues
            .iter()
            .find(|queue| &queue.owner == node)
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("foreign observed consumer"),
            })?;
        let current = queue.core.snapshot();
        Ok(BackendIoInventory {
            node: node.clone(),
            observed: NodeCounter { ticks: 0 },
            generation: NonZeroU64::MIN,
            // This backend models complete native facts; operational facts are
            // separately joined by the actual held Node observer.
            native_caps: crate::BackendIoNativeCaps {
                timer: crate::BackendIoNativeCap::ObservedAbsent,
                input: crate::BackendIoNativeCap::ObservedAbsent,
            },
            queues: vec![BackendIoQueueSnapshot {
                world: self.world,
                device: queue.device.clone(),
                source_node: current.src_node,
                revision: current.queue_revision,
                pipeline_revision: Some(queue.pipeline.observation_revision().map_err(
                    |error| BackendError::Rejected {
                        message: error.to_string(),
                    },
                )?),
                next_pipeline_boundary: None,
                completions: current
                    .inflight
                    .iter()
                    .map(|reply| BackendIoComputedReply {
                        source_delivery: reply.key,
                        payload: reply.response.payload.clone(),
                    })
                    .collect(),
            }],
        })
    }

    fn settle_fixed_input(
        &mut self,
        prepared: &crate::PreparedHostFixedInput,
    ) -> Result<crate::BackendFixedInputResult, BackendError> {
        self.owners.push(prepared.clone());
        if prepared.node() == &id("b") && self.pending_b_once {
            self.pending_b_once = false;
            return Ok(crate::BackendFixedInputResult {
                prepared: prepared.clone(),
                consumed: 0,
                state: crate::BackendFixedInputState::Pending,
            });
        }
        let queue = self
            .queues
            .iter_mut()
            .find(|queue| &queue.owner == prepared.node())
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("foreign fixed consumer"),
            })?;
        for event in prepared.events() {
            let ScheduledEventPayload::IoCompletion(completion) = &event.payload else {
                return Err(BackendError::Rejected {
                    message: String::from("fixture supports computed replies only"),
                });
            };
            let published = queue
                .core
                .deliver_selected_to_shmem(
                    prepared.at().ticks,
                    completion.source_delivery,
                    &completion.payload,
                    &queue.output,
                    &mut queue.entries,
                )
                .map_err(|error| BackendError::Rejected {
                    message: error.source.to_string(),
                })?;
            if published != crucible_device::SelectedDeliveryOutcome::Published {
                return Err(BackendError::Rejected {
                    message: String::from("fixture reply ring is full"),
                });
            }
        }
        self.published.push(prepared.node().clone());
        if prepared.node() == &id("a") && self.repeat_a {
            queue
                .core
                .enqueue_request(Request::new(0, 42, b"new actual origin".to_vec()))
                .map_err(|error| BackendError::Rejected {
                    message: error.source.to_string(),
                })?;
            queue
                .core
                .process_inbox(&mut Echo)
                .map_err(|error| BackendError::Rejected {
                    message: error.to_string(),
                })?;
        }
        Ok(crate::BackendFixedInputResult {
            prepared: prepared.clone(),
            consumed: prepared.events().len(),
            state: crate::BackendFixedInputState::Published,
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

impl ConcurrentSimulationBackend for TwoConsumers {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<crate::ConcurrentBackendRun>,
        workers: usize,
    ) -> Result<Vec<crate::ConcurrentBackendRunResult>, BackendError> {
        if self.queues.iter().any(|queue| {
            !self.published.contains(&queue.owner) || !queue.core.snapshot().inflight.is_empty()
        }) {
            return Err(BackendError::Rejected {
                message: String::from("positive dispatch preceded complete current-T publication"),
            });
        }
        self.dispatches += 1;
        self.model.execute_concurrent_runs(runs, workers)
    }
}

fn two_consumers() -> crate::BackendQuantumLoop<SingleScheduler, TwoConsumers> {
    let store = MemoryDagStore::new();
    let image = ok(store.put(&vec![0; 512]));
    let mut definitions = Vec::new();
    let mut nodes = Vec::new();
    for name in ["a", "b"] {
        definitions.push(WorldNodeDef::Vm(WorldNode {
            id: id(name),
            arch: VmArchitecture::X86_64,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            kernel: None,
            root_image: None,
            initrd: None,
        }));
        definitions.push(WorldNodeDef::Io(WorldIoNode::block(
            id(&format!("disk-{name}")),
            id(name),
            WorldIoCoreConfig::new(),
            ContentAddressedBlobRef::from_hash(image),
            512,
            WorldBlockLatency::new(0, 0, 0, 0, 0),
        )));
        nodes.push(SchedulerScenarioNode {
            id: SchedulerNodeId {
                node: id(name),
                kind: SchedulingNodeKind::Vm,
            },
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Runnable,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        });
    }
    let world = ok(World::from_node_defs_and_links(definitions, Vec::new()));
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "two-real-fixed-queues",
        16,
        SimInstant { ticks: 64 },
        nodes,
        Vec::new(),
    );
    let scheduler = ok(SingleScheduler::from_world(
        scenario,
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    ));
    let layout = ok(crate::WorldIoInstantiationLayout::derive(
        &world,
        WorldIoLayoutPolicy::default(),
    ));
    let queues = ["a", "b"]
        .into_iter()
        .map(|name| {
            let device = id(&format!("disk-{name}"));
            let source = layout
                .get(&device)
                .unwrap_or_else(|| panic!("actual configured producer"));
            let mut core = ok(IoCore::new(source.source_node, 4, 4));
            ok(core.enqueue_request(Request::new(
                0,
                9,
                b"same payload distinct real origins".to_vec(),
            )));
            ok(core.process_inbox(&mut Echo));
            OwnedQueue {
                owner: id(name),
                device: SchedulerNodeId {
                    node: device,
                    kind: SchedulingNodeKind::Disk,
                },
                core,
                pipeline: crucible_device::block::BlockFaultState::write_through(512),
                output: RingHeader::new(),
                entries: vec![FrameEntry::default(); 4],
            }
        })
        .collect();
    crate::BackendQuantumLoop::new(
        scheduler,
        TwoConsumers {
            world: world.id(),
            queues,
            model: crate::MockSimulationBackend::new(),
            owners: Vec::new(),
            published: Vec::new(),
            dispatches: 0,
            pending_b_once: false,
            repeat_a: false,
        },
    )
}

fn drive(
    actor: &mut crate::BackendQuantumLoop<SingleScheduler, TwoConsumers>,
    workers: usize,
) -> Result<crate::SchedulerConcurrentQuantumOutcome, SchedulerError> {
    actor.drive_concurrent_quantum(
        QuantumRequest {
            configuration: actor.loop_impl().configuration.clone(),
            control: Vec::new(),
        },
        workers,
    )
}

#[test]
fn both_current_consumers_publish_before_any_positive_concurrent_dispatch() {
    for workers in [1, 2] {
        let mut actor = two_consumers();
        ok(drive(&mut actor, workers));
        assert_eq!(actor.backend().published, [id("a"), id("b")]);
        assert_eq!(actor.backend().dispatches, 1);
        assert_eq!(actor.backend().owners.len(), 2);
        for queue in &actor.backend().queues {
            assert!(queue.core.snapshot().inflight.is_empty());
            let delivered = ok(queue.output.dequeue(&queue.entries))
                .unwrap_or_else(|| panic!("real published response"));
            assert_eq!(delivered.delivery_icount, 0);
            assert_eq!(delivered.src_node, queue.core.snapshot().src_node);
        }
    }
}

#[test]
fn pending_second_consumer_retains_owner_and_retry_does_not_republish_first() {
    let mut actor = two_consumers();
    actor.backend_mut().pending_b_once = true;
    let before = actor.loop_impl().configuration.clone();
    assert!(drive(&mut actor, 2).is_err());
    assert_eq!(actor.backend().published, [id("a")]);
    assert_eq!(actor.backend().dispatches, 0);
    assert_eq!(actor.loop_impl().configuration, before);
    assert!(actor.loop_impl().ceiling_publications.is_empty());
    let retained_b = actor.backend().owners[1].clone();

    ok(drive(&mut actor, 2));
    assert_eq!(actor.backend().published, [id("a"), id("b")]);
    assert_eq!(actor.backend().owners[2], retained_b);
    assert_eq!(actor.backend().dispatches, 1);
}

#[test]
fn repeated_consumer_refuses_before_second_publication_or_positive_dispatch() {
    let mut actor = two_consumers();
    actor.backend_mut().repeat_a = true;
    assert!(drive(&mut actor, 2).is_err());
    assert_eq!(actor.backend().published, [id("a")]);
    assert_eq!(actor.backend().owners.len(), 1);
    assert_eq!(actor.backend().dispatches, 0);
    assert_eq!(actor.backend().queues[0].core.snapshot().inflight.len(), 1);
    assert!(actor.loop_impl().ceiling_publications.is_empty());

    assert!(actor.retained_fixed_input_for_test().is_none());
    assert!(!actor.loop_impl().fixed_input_in_progress);
    assert_eq!(actor.loop_impl().fixed_input_generation, 1);
    assert!(actor.loop_impl().checkpoint().is_ok());
    assert!(!actor.continuation_is_poisoned());

    actor.backend_mut().repeat_a = false;
    ok(drive(&mut actor, 2));
    assert_eq!(actor.backend().published, [id("a"), id("a"), id("b")]);
    assert_eq!(actor.backend().owners.len(), 3);
    assert_ne!(actor.backend().owners[0], actor.backend().owners[1]);
    assert_ne!(
        actor.backend().owners[0].events()[0],
        actor.backend().owners[1].events()[0]
    );
    assert_eq!(actor.backend().dispatches, 1);
}
