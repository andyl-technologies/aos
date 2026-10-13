//! Actual host-model role projections, native definition drift and inert reads.

// crucible-lint: allow panic-shortcut -- These controls panic on fixture or native-state invariant failures.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_device::netlink::{Frame, LinkFaults};
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, FsTree, IoCore, NinepDevice, NinepLatency,
};

struct ActualModelQualification;

impl HostModelQualification for ActualModelQualification {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        _: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        // These real-device component controls use the existing synthetic graph;
        // installed artifact/profile qualification remains the production owner's job.
        if descriptor.roles.as_slice() == [Id::new(model.role()).unwrap()] {
            Ok(())
        } else {
            Err(failure("actual source model and fixture roster differ"))
        }
    }
}

fn original_node(model: HostModel) -> HostModelNode {
    let bytes = model.initialization_bytes(1 << 20).unwrap();
    let (graph, _) = if matches!(model, HostModel::Clock(_)) {
        crate::node_admission::test_fixture_host_clocks()
    } else {
        crate::node_admission::test_fixture_host_model(model.role(), bytes)
    };
    HostModelNode::new(
        &graph,
        &Id::new("a").unwrap(),
        model,
        &ActualModelQualification,
        HostModelResources::default(),
    )
    .unwrap()
}

fn io_model(block: BlockDevice) -> HostModel {
    HostModel::Io(Box::new(ScheduledIoNode::new(
        crate::SchedulerNodeId {
            node: crate::NodeId { name: "a".into() },
            kind: crate::SchedulingNodeKind::Disk,
        },
        crate::NodeId { name: "vm".into() },
        crate::DeviceId {
            name: "disk".into(),
        },
        block,
        crate::Seed::from_u64(42),
    )))
}

#[test]
fn actual_clock_role_borrows_original_profile_without_alarms_or_readiness() {
    let mut node = original_node(HostModel::Clock(VirtualClock::new()));
    let Some(HostModel::Clock(clock)) = node.model.as_mut() else {
        panic!("original clock absent")
    };
    clock.advance_to(17).unwrap();
    let before = node.capture().unwrap();
    let route = node.route.clone();
    let facets = node.facets.clone();

    {
        let interface: &dyn ClockNode = &node;
        let view = interface.clock_description().unwrap();
        let description: &dyn RoleDescription = &view;
        assert!(std::ptr::eq(
            description.role_profile(),
            &node.binding.compatibility.profile_ref
        ));
        assert!(std::ptr::eq(view.declaration.descriptor, &node.descriptor));
        assert_eq!(view.declaration.role.as_str(), "clock");
        assert_eq!(view.mapping, ClockMapping::IdentityPicoseconds);
        assert_eq!(view.alarms, ClockAlarms::Unsupported);
        assert!(view.refuses_overflow);
        assert!(node.block_description().is_err());
        assert!(node.filesystem_description().is_err());
        assert!(node.link_description().is_err());
    }

    assert_eq!(node.capture().unwrap(), before);
    assert_eq!(node.route, route);
    assert_eq!(node.facets, facets);
    assert!(node.readiness.is_none());
    assert!(node.completed.is_empty());

    // Native frontier movement does not change the clock's static definition.
    let Some(HostModel::Clock(clock)) = node.model.as_mut() else {
        panic!("original clock absent")
    };
    clock.advance_to(91).unwrap();
    assert_eq!(
        node.clock_description().unwrap().mapping,
        ClockMapping::IdentityPicoseconds
    );
}

#[test]
fn actual_block_role_exposes_volatile_durability_and_keeps_pending_response() {
    use crucible_device::block::{
        BlockCompletionDurability, BlockDiscardSemantics, BlockDurabilityConfig,
    };
    let base = BaseImage::new(vec![0xa7; 8192]);
    let expected_hash = base.hash();
    let mut block = BlockDevice::new(
        IoCore::new(19, 8, 8).unwrap(),
        base,
        BlockLatency::new(3, 5, 7, 11, 2),
    );
    let mut config = BlockDurabilityConfig::write_through(8192);
    config.atomic_write_bytes = 8;
    config.maximum_request_bytes = 64;
    config.discard_granularity_bytes = 8;
    config.discard_semantics = BlockDiscardSemantics::ReadsOldData;
    config.volatile_cache_bytes = 32;
    config.cache_entries = 2;
    config.completion_durability = BlockCompletionDurability::VolatileCacheAccepted;
    block.configure_storage_faults(config, false).unwrap();
    block.submit(0, &BlockRequest::get_length(9)).unwrap();
    let node = original_node(io_model(block));
    let before = node.capture().unwrap();

    let interface: &dyn BlockNode = &node;
    let view = interface.block_description().unwrap();
    assert_eq!(view.length_bytes, 8192);
    assert_eq!(view.base_hash, expected_hash);
    assert_eq!(
        view.storage_ownership,
        BlockStorageOwnership::PinnedBasePrivateCopyOnWrite
    );
    assert_eq!(view.atomic_write_bytes, 8);
    assert_eq!(view.maximum_request_bytes, 64);
    assert_eq!(view.volatile_cache_bytes, 32);
    assert_eq!(
        view.completion_durability,
        CompletionDurability::VolatileCacheAccepted
    );
    assert_eq!(view.discard_readback, DiscardReadback::PreviousBytes);
    assert_eq!(view.latency.read_base_ns, 3);
    assert_eq!(view.latency.per_byte_ns, 2);
    assert!(view.operations.contains(&BlockOperation::Flush));
    assert_eq!(node.capture().unwrap(), before);
    assert!(node.filesystem_description().is_err());
    assert!(node.clock_description().is_err());
    assert!(node.readiness.is_none());
}

#[test]
fn actual_filesystem_role_keeps_negotiated_session_and_pinned_namespace() {
    let tree = FsTree::try_new(crucible_device::ninep::tree::Node::Directory {
        children: BTreeMap::from([(
            "original".into(),
            crucible_device::ninep::tree::Node::File {
                content: b"pinned original bytes".to_vec(),
            },
        )]),
    })
    .unwrap();
    let expected_hash = tree.content_hash();
    let mut filesystem = NinepDevice::new(
        IoCore::new(23, 8, 8).unwrap(),
        tree,
        NinepLatency::new(13, 17, 3),
    );
    let mut version = vec![21, 0, 0, 0, 100, 0xff, 0xff];
    version.extend_from_slice(&1024u32.to_le_bytes());
    version.extend_from_slice(&8u16.to_le_bytes());
    version.extend_from_slice(b"9P2000.L");
    filesystem.submit(0, &version).unwrap();
    let model = HostModel::Io(Box::new(ScheduledIoNode::new_ninep(
        crate::SchedulerNodeId {
            node: crate::NodeId { name: "a".into() },
            kind: crate::SchedulingNodeKind::NineP,
        },
        crate::NodeId { name: "vm".into() },
        crate::DeviceId { name: "fs".into() },
        filesystem,
        crate::Seed::from_u64(42),
    )));
    let node = original_node(model);
    let before = node.capture().unwrap();

    let interface: &dyn FilesystemNode = &node;
    let view = interface.filesystem_description().unwrap();
    assert_eq!(view.namespace_hash, expected_hash);
    assert_eq!(view.dialect, FilesystemDialect::Ninep2000L);
    assert!(view.read_only && view.session_scoped_fids && view.version_negotiated);
    assert_eq!(
        view.permissions,
        FilesystemPermissions::FixedReadOnlyAttributes
    );
    assert_eq!(
        view.visibility,
        FilesystemVisibility::OriginalSessionReplies
    );
    assert_eq!(view.negotiated_message_bytes, 1024);
    assert_eq!(
        view.latency,
        FilesystemLatencyDescription {
            control_ns: 13,
            data_ns: 17,
            per_byte_ns: 3
        }
    );
    assert_eq!(node.capture().unwrap(), before);
    assert!(node.block_description().is_err());
    assert!(node.readiness.is_none());
}

#[test]
fn actual_link_role_keeps_original_inflight_frame_and_refuses_definition_drift() {
    let mut link = NetLink::new(29, 19, 7, LinkFaults::none()).unwrap();
    let mut rng = link.rng(42, "test", "role-view");
    link.emit_with_rng_draws(
        &Frame::new(10, 41, vec![9, 8, 7]),
        &mut rng,
        crucible_device::netlink::PastDeliveryPolicy::FailLoud,
    )
    .unwrap();
    let mut node = original_node(HostModel::Link(Box::new(link)));
    let before = node.capture().unwrap();

    {
        let interface: &dyn NetworkLinkNode = &node;
        let view = interface.link_description().unwrap();
        assert_eq!(view.base_latency_ps, 19);
        assert_eq!(view.latency_floor_ps, 7);
        assert_eq!(view.effective_latency_ps, 19);
        assert_eq!(view.delivery_order, FrameDeliveryOrder::TimeSourceSequence);
        assert_eq!(view.input_endpoint, node.input_endpoint.as_ref());
        assert_eq!(view.output_endpoint, node.output_endpoint.as_ref());
        assert_eq!(node.capture().unwrap(), before);
    }

    let Some(HostModel::Link(link)) = node.model.as_mut() else {
        panic!("original link absent")
    };
    link.set_faults(LinkFaults {
        added_latency_ticks: 5,
        ..LinkFaults::none()
    });
    let changed = node.capture().unwrap();
    assert!(node.link_description().is_err());
    assert_eq!(node.capture().unwrap(), changed);
    assert!(node.readiness.is_none());
}

#[test]
fn role_roster_release_and_unenrolled_alarm_extension_refuse_without_mutation() {
    let mut node = original_node(HostModel::Clock(VirtualClock::new()));
    let original_descriptor = node.descriptor.clone();
    node.descriptor.roles = vec![Id::new("block").unwrap()];
    let before = node.capture().unwrap();
    assert!(node.clock_description().is_err());
    assert!(node.block_description().is_err());
    assert_eq!(node.capture().unwrap(), before);

    node.descriptor = original_descriptor;
    node.model = Some(HostModel::RateAlarmClock(Box::new(
        super::super::super::rate_alarm_clock::RateAlarmClock::new(
            super::super::super::rate_alarm_clock::RateAlarmClockDefinition {
                numerator: 3.into(),
                denominator: 2.into(),
                epoch_ps: 0.into(),
                epoch_counter: 7.into(),
                drift_ppb: -100,
            },
        )
        .unwrap(),
    )));
    let before = node.capture().unwrap();
    assert!(node.clock_description().is_err());
    assert_eq!(node.capture().unwrap(), before);

    node.model = None;
    assert!(node.clock_description().is_err());
    assert!(node.block_description().is_err());
    assert!(node.filesystem_description().is_err());
    assert!(node.link_description().is_err());
    assert!(node.readiness.is_none());
}

#[test]
fn actual_enrolled_role_getter_keeps_original_rational_clock_and_pending_alarm() {
    use crate::node_adapters::{RateAlarmClock, RateAlarmClockDefinition, RateAlarmClockRequest};

    let definition = RateAlarmClockDefinition {
        numerator: 3.into(),
        denominator: 2.into(),
        epoch_ps: 0.into(),
        epoch_counter: 7.into(),
        drift_ppb: -500_000_000,
    };
    let mut clock = RateAlarmClock::new(definition.clone()).unwrap();
    let request = canonical::canonical_json(
        &serde_json::to_value(RateAlarmClockRequest::Arm {
            correlation: Id::new("original-alarm").unwrap(),
            target: 13.into(),
        })
        .unwrap(),
    )
    .unwrap();
    clock
        .consume(Position::new(0.into(), 2.into(), Phase::Reaction), &request)
        .unwrap();
    let model = HostModel::RateAlarmClock(Box::new(clock));
    let initial = model.initialization_bytes(1 << 20).unwrap();
    let (graph, evidence) = crate::node_admission::test_fixture_host_rate_alarm_clock(initial);
    let schema = crate::node_adapters::host_rate_alarm_clock_schema().unwrap();
    assert_eq!(
        evidence[&schema.definition.hash.digest],
        crate::node_adapters::RATE_ALARM_CLOCK_SPECIFICATION.as_bytes()
    );
    let mut node = HostModelNode::new(
        &graph,
        &Id::new("a").unwrap(),
        model,
        &ActualModelQualification,
        HostModelResources::default(),
    )
    .unwrap();
    let before = node.capture().unwrap();
    let Some(HostModel::RateAlarmClock(clock)) = node.model.as_ref() else {
        panic!("original enrolled clock absent")
    };
    let original_native = clock.capture().unwrap();
    let original_alarm = clock.earliest_alarm().unwrap();
    assert_eq!(original_alarm.time_ps.get(), 8);

    let interface: &dyn ClockNode = &node;
    let view = interface.clock_description().unwrap();
    assert_eq!(view.declaration.role.as_str(), "rate_alarm_clock");
    assert!(
        view.declaration
            .binding
            .implementation
            .formats
            .contains(&schema)
    );
    assert!(std::ptr::eq(
        view.role_profile(),
        &node.binding.compatibility.profile_ref
    ));
    assert_eq!(
        view.mapping,
        ClockMapping::RationalCounter {
            numerator: 3,
            denominator: 2,
            epoch_ps: 0,
            epoch_counter: 7,
            drift_ppb: -500_000_000,
        }
    );
    assert_eq!(
        view.alarms,
        ClockAlarms::OriginalRationalRequests {
            maximum_requests: 64
        }
    );
    assert!(view.refuses_overflow);
    assert_eq!(node.capture().unwrap(), before);
    assert_eq!(clock.earliest_alarm(), Some(original_alarm));
    assert_eq!(clock.definition(), &definition);
    assert!(node.readiness.is_none());
    assert!(node.completed.is_empty());

    let Some(HostModel::RateAlarmClock(clock)) = node.model.as_mut() else {
        panic!("original enrolled clock absent")
    };
    assert_eq!(
        clock
            .publish(Position::new(0.into(), 2.into(), Phase::Reaction))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(clock.earliest_alarm(), Some(original_alarm));
    // Native response movement and restoration never replace the retained
    // source-qualified rate definition in the same owning host node.
    assert!(node.clock_description().is_ok());
    let Some(HostModel::RateAlarmClock(clock)) = node.model.as_mut() else {
        panic!("original enrolled clock absent")
    };
    clock.restore(&original_native).unwrap();
    assert!(node.clock_description().is_ok());
    assert_eq!(node.capture().unwrap(), before);
}
