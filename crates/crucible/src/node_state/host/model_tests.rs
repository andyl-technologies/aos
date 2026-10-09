//! Real pending storage/link queues, cold archives and independent future progress.
//!
//! Installed qualification is synthetic in these tests. Actual native model
//! state, whole-runtime ledger, archive authentication and restore are executed.

use super::*;
use crate::{DeviceId, NodeId, ScheduledIoNode, SchedulerNodeId, SchedulingNodeKind, Seed};
use crucible_device::netlink::{Frame, FrameDraws, LinkFaults, NetLink, PastDeliveryPolicy};
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, FsTree, IoCore, NinepDevice, NinepLatency,
};

#[derive(Clone, Copy)]
enum QueuedModel {
    Block,
    Ninep,
    Link,
}

impl QueuedModel {
    fn role(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Ninep => "filesystem",
            Self::Link => "network_link",
        }
    }

    fn make(self) -> HostModel {
        let native_node = NodeId { name: "a".into() };
        match self {
            Self::Block => {
                let mut io = ScheduledIoNode::new(
                    SchedulerNodeId {
                        node: native_node,
                        kind: SchedulingNodeKind::Disk,
                    },
                    NodeId { name: "vm".into() },
                    DeviceId {
                        name: "disk".into(),
                    },
                    BlockDevice::new(
                        IoCore::new(7, 16, 16).unwrap(),
                        BaseImage::new(vec![0xab; 4096]),
                        BlockLatency::new(2, 2, 2, 2, 1),
                    ),
                    Seed::from_u64(42),
                );
                io.submit_fifo(0, &BlockRequest::write(1, 0, vec![7, 8, 9]))
                    .unwrap();
                assert_eq!(io.pending_completion_keys().count(), 1);
                HostModel::Io(Box::new(io))
            }
            Self::Ninep => {
                let tree = FsTree::try_new(crucible_device::ninep::tree::Node::Directory {
                    children: BTreeMap::from([(
                        "contents".into(),
                        crucible_device::ninep::tree::Node::File {
                            content: vec![1, 2, 3],
                        },
                    )]),
                })
                .unwrap();
                let mut io = ScheduledIoNode::new_ninep(
                    SchedulerNodeId {
                        node: native_node,
                        kind: SchedulingNodeKind::NineP,
                    },
                    NodeId { name: "vm".into() },
                    DeviceId { name: "fs".into() },
                    NinepDevice::new(
                        IoCore::new(9, 16, 16).unwrap(),
                        tree,
                        NinepLatency::new(5, 5, 0),
                    ),
                    Seed::from_u64(42),
                );
                let mut version = vec![21, 0, 0, 0, 100, 0xff, 0xff];
                version.extend_from_slice(&4608u32.to_le_bytes());
                version.extend_from_slice(&8u16.to_le_bytes());
                version.extend_from_slice(b"9P2000.L");
                io.submit_ninep_frame(0, &version).unwrap();
                let mut attach = vec![23, 0, 0, 0, 104, 1, 0];
                attach.extend_from_slice(&11u32.to_le_bytes());
                attach.extend_from_slice(&u32::MAX.to_le_bytes());
                attach.extend_from_slice(&0u16.to_le_bytes());
                attach.extend_from_slice(&0u16.to_le_bytes());
                attach.extend_from_slice(&0u32.to_le_bytes());
                io.submit_ninep_frame(0, &attach).unwrap();
                assert_eq!(io.pending_completion_keys().count(), 2);
                HostModel::Io(Box::new(io))
            }
            Self::Link => {
                let mut link = NetLink::new(7, 5000, 1, LinkFaults::none()).unwrap();
                link.emit(
                    &Frame::new(0, 1, vec![1, 2, 3, 4]),
                    &FrameDraws::default(),
                    PastDeliveryPolicy::FailLoud,
                )
                .unwrap();
                assert_eq!(link.inflight_len(), 1);
                HostModel::Link(Box::new(link))
            }
        }
    }
}

struct QueuedQualification<'a> {
    selected: QueuedModel,
    source: Option<&'a AuthenticatedHostSource<'a>>,
}

impl HostModelQualification for QueuedQualification<'_> {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        _: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        let expected = if descriptor.id == id("a") {
            self.selected.make()
        } else {
            HostModel::Clock(VirtualClock::new())
        };
        if model.initialization_bytes(16 * 1024 * 1024)?
            == expected.initialization_bytes(16 * 1024 * 1024)?
        {
            Ok(())
        } else {
            Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "actual test native initialization differs".into(),
            })
        }
    }

    fn authenticate_continuation(
        &self,
        _: &HostModel,
        descriptor: &NodeDescriptor,
        _: &NodeBinding,
        native: &[u8],
        source: &RuntimeSnapshot,
        target: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        if self.source.is_some_and(|authenticated| {
            authenticated.node() == &descriptor.id
                && authenticated.native() == native
                && authenticated.runtime() == source
        }) && target.generation > source.source_activation.generation
            && target.boundary == source.capture_cut
        {
            Ok(())
        } else {
            Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "authentic test original source differs".into(),
            })
        }
    }
}

struct QueuedFactory(QueuedModel);

impl HostWorldFactory for QueuedFactory {
    fn authenticate_coordinator(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &crate::node_scheduling::SchedulingSnapshot,
        _: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        assert!(graph.world().connections.is_empty());
        assert!(graph.coordinator_policy().external_inputs.is_empty());
        assert_eq!(runtime.capture_cut, scheduler.capture_cut);
        assert_eq!(runtime.capture_ordinal, scheduler.capture_ordinal);
        crate::node_scheduling::validate_saved_source(graph, scheduler)
            .map_err(super::super::super::schema)
    }

    fn reservation(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        node: &Id,
        native: &[u8],
        limits: HostModelResources,
    ) -> Result<RestoreReservations, StateError> {
        ModelFactory.reservation(graph, node, native, limits)
    }

    fn state_schema(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        node: &Id,
    ) -> Result<crucible_node_contract::SchemaRef, StateError> {
        ModelFactory.state_schema(graph, node)
    }

    fn authenticate_source(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        node: &Id,
        native: &[u8],
        source: &RuntimeSnapshot,
        _: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        let inventory = validate_host_continuation(
            native,
            source,
            graph.descriptor(node).unwrap(),
            graph.binding(node).unwrap(),
            HostModelResources::default(),
        )
        .map_err(super::super::native_failure)?;
        if node == &id("a") {
            match self.0.make() {
                HostModel::Io(mut io) => io.restore_checkpoint(&crate::device_subnode::DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(&inventory.native_model.bytes).map_err(super::super::super::schema)?).map_err(super::super::super::schema)?,
                HostModel::Link(_) => {
                    let snapshot = crucible_device::netlink::LinkSnapshot::from_canonical_bytes(&inventory.native_model.bytes).map_err(super::super::super::schema)?;
                    NetLink::restore(&snapshot).map_err(super::super::super::schema)?;
                }
                HostModel::SeededLink {..} | HostModel::Clock(_) | HostModel::ScriptedSource(_) | HostModel::Semantics(_) => unreachable!(),
            }
        } else if inventory.native_model.bytes
            != host_clock_initial_bytes(source.capture_cut.time_ps.get())
        {
            return Err(super::super::archive::refusal(
                "original test clock codec differs",
            ));
        }
        Ok(())
    }

    fn prepare_node(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        node: &Id,
        source: &AuthenticatedHostSource<'_>,
        target: &ActivationRecord,
        limits: HostModelResources,
    ) -> Result<(HostModelNode, NativeRuntimeContinuationEvidence), StateError> {
        let qualification = QueuedQualification {
            selected: self.0,
            source: Some(source),
        };
        let model = if node == &id("a") {
            self.0.make()
        } else {
            HostModel::Clock(VirtualClock::new())
        };
        let mut actual = HostModelNode::new(graph, node, model, &qualification, limits)
            .map_err(super::super::native_failure)?;
        let proof = actual
            .prepare_continuation(source.native(), source.runtime(), target, &qualification)
            .map_err(super::super::native_failure)?;
        Ok((actual, proof))
    }
}

fn source_with_pending(
    graph: &crate::node_admission::AdmittedGraph,
    selected: QueuedModel,
    queue: &mut RuntimeCustodyQueue,
) -> (NodeRuntime, WorldActivation) {
    let qualification = QueuedQualification {
        selected,
        source: None,
    };
    let nodes = graph
        .node_ids()
        .map(|node| {
            let model = if node == &id("a") {
                selected.make()
            } else {
                HostModel::Clock(VirtualClock::new())
            };
            Box::new(
                HostModelNode::new(
                    graph,
                    node,
                    model,
                    &qualification,
                    HostModelResources::default(),
                )
                .unwrap(),
            ) as Box<dyn SimulationNode>
        })
        .collect();
    let record = activation(graph, 1, cut(0));
    let slot = queue
        .reserve_world(&record, RuntimeLimits::default())
        .unwrap();
    let mut runtime = NodeRuntime::new(graph, nodes, record, RuntimeLimits::default(), slot)
        .ok()
        .unwrap();
    runtime.arm_all().unwrap();
    let world = runtime.activate(&mut Publisher).unwrap();
    (runtime, world)
}

fn queued_archive_branches(selected: QueuedModel) {
    let directory = TestDirectory::new();
    let limits = StateLimits::default();
    let archive = HostArchive::open(directory.path().join("private"), limits).unwrap();
    let initial = selected
        .make()
        .initialization_bytes(16 * 1024 * 1024)
        .unwrap();
    let (graph, blobs) =
        crate::node_admission::test_fixture_host_initial_queue(selected.role(), initial.clone(), 1);
    let mut queue = RuntimeCustodyQueue::new(8).unwrap();
    let (mut runtime, world) = source_with_pending(&graph, selected, &mut queue);
    advance(&mut runtime, &graph, &world, &id("a"), 100, false);
    advance(&mut runtime, &graph, &world, &id("z"), 100, true);
    let signed = archive
        .capture_world(
            &graph,
            &mut runtime,
            &world,
            cut(100),
            7.into(),
            id("capture/native-queue"),
            requirements(),
            &Immutable(blobs),
            &QueuedFactory(selected),
        )
        .unwrap();
    let artifact = signed.artifact().clone();
    drop(runtime);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..8 {
        let _ = queue.poll_reclamation(&mut context);
    }
    assert_eq!(queue.reserved_worlds(), 0);

    let restore = |generation: u64| {
        let signed = archive.load(&artifact).unwrap();
        let (fresh, _) = crate::node_admission::test_fixture_host_initial_queue(
            selected.role(),
            initial.clone(),
            generation,
        );
        let graph = Rc::new(fresh);
        let verified = signed
            .admit(&graph, requirements(), &QueuedFactory(selected), limits)
            .unwrap();
        let target = activation(&graph, generation, cut(100));
        let mut driver = HostWorldRestoreDriver::new(
            graph.clone(),
            signed,
            Rc::new(QueuedFactory(selected)),
            queue.clone(),
        )
        .unwrap();
        let prepared = stage_restore(&graph, verified, target, &mut driver, limits)
            .unwrap_or_else(|error| panic!("{}", error.error));
        let RestorePublication::Committed(mut restored) = prepared.publish(&mut Publisher) else {
            panic!("native branch did not publish")
        };
        let original = restored.runtime_mut().recover(&id("run/a/100")).unwrap();
        let commit = restored
            .runtime_mut()
            .recover_scheduling_commit(&original)
            .unwrap();
        restored
            .runtime_mut()
            .acknowledge_scheduled(&original, &commit)
            .unwrap();
        (graph, restored)
    };
    let (left_graph, mut left) = restore(2);
    let (right_graph, mut right) = restore(3);
    let left_world = left.activation().clone();
    let right_world = right.activation().clone();
    // One sibling drains its real pending responses while the other remains
    // before their exact delivery cut. No initial request is executed again.
    let left_token = advance(
        left.runtime_mut(),
        &left_graph,
        &left_world,
        &id("a"),
        6000,
        false,
    );
    advance(
        left.runtime_mut(),
        &left_graph,
        &left_world,
        &id("z"),
        6000,
        true,
    );
    advance(
        right.runtime_mut(),
        &right_graph,
        &right_world,
        &id("a"),
        1000,
        true,
    );
    advance(
        right.runtime_mut(),
        &right_graph,
        &right_world,
        &id("z"),
        1000,
        true,
    );
    let left_source = left
        .runtime_mut()
        .runtime_snapshot(cut(6000), 8.into(), limits.maximum_record_bytes)
        .unwrap();
    let right_source = right
        .runtime_mut()
        .runtime_snapshot(cut(1000), 8.into(), limits.maximum_record_bytes)
        .unwrap();
    let left_caps = left
        .runtime_mut()
        .capture_host_native(
            &left_world,
            &left_source,
            limits.maximum_record_bytes,
            limits.maximum_content_bytes,
            limits.maximum_total_content_bytes,
            limits.maximum_content_objects,
        )
        .unwrap();
    let right_caps = right
        .runtime_mut()
        .capture_host_native(
            &right_world,
            &right_source,
            limits.maximum_record_bytes,
            limits.maximum_content_bytes,
            limits.maximum_total_content_bytes,
            limits.maximum_content_objects,
        )
        .unwrap();
    let native_bytes = |caps: Vec<HostNativeCapture>,
                        source: &RuntimeSnapshot,
                        graph: &crate::node_admission::AdmittedGraph| {
        let native = caps
            .into_iter()
            .find(|entry| entry.node() == &id("a"))
            .unwrap();
        validate_host_continuation(
            &native.state().bytes,
            source,
            graph.descriptor(&id("a")).unwrap(),
            graph.binding(&id("a")).unwrap(),
            HostModelResources::default(),
        )
        .unwrap()
        .native_model
        .bytes
    };
    assert_ne!(
        native_bytes(left_caps, &left_source, &left_graph),
        native_bytes(right_caps, &right_source, &right_graph)
    );
    let right_token = advance(
        right.runtime_mut(),
        &right_graph,
        &right_world,
        &id("a"),
        6000,
        false,
    );
    let left_result = left.runtime_mut().poll(&left_token, &mut context);
    let right_result = right.runtime_mut().poll(&right_token, &mut context);
    let Poll::Ready(Ok(left_outcome)) = left_result else {
        panic!("left original result missing")
    };
    let Poll::Ready(Ok(right_outcome)) = right_result else {
        panic!("right original result missing")
    };
    let payloads = |outcome: OperationOutcome| {
        outcome
            .scheduling
            .unwrap()
            .publications
            .into_iter()
            .map(|output| (output.native_sequence, output.payload_bytes))
            .collect::<Vec<_>>()
    };
    let left_outputs = payloads(left_outcome);
    assert!(!left_outputs.is_empty());
    assert_eq!(left_outputs, payloads(right_outcome));
}

#[test]
fn block_dirty_overlay_and_pending_reply_restore_into_independent_worlds() {
    queued_archive_branches(QueuedModel::Block);
}

#[test]
fn ninep_fid_session_and_pending_replies_restore_into_independent_worlds() {
    queued_archive_branches(QueuedModel::Ninep);
}

#[test]
fn native_link_pending_frame_restores_into_independent_worlds() {
    queued_archive_branches(QueuedModel::Link);
}
