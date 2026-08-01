//! Checks T-GHC-2 OS-agnostic black-box observation.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::collections::BTreeSet;

use crucible::{
    Action, AssertionDef, AssertionId, BLACK_BOX_OBSERVATION_CONTRACTS,
    BLACK_BOX_OBSERVATION_KINDS, BlackBoxObservationKind, BlackBoxObservationSource, CodePoint,
    ContentAddressedBlobRef, ContentHash, Event, EventGraph, EventGraphState, FramePredicate,
    Icount, IoEventKind, NodeId, NodeLifecycle, NodeTemplate, ObservableEvent, Predicate,
    Properties, Property, ReadyPoint, RegexProgram, ResolvedMemPlace, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode,
};

const AARCH64_BARE_METAL_NON_LINUX_IMAGE: &[u8] = &[
    0x00, 0x00, 0x80, 0xd2, // mov x0, #0
    0x20, 0x00, 0x80, 0xd2, // mov x0, #1
    0x40, 0x00, 0x80, 0xd2, // mov x0, #2
    0x00, 0x00, 0x00, 0x14, // b .
];

fn assertion(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn event(name: &str) -> crucible::EventId {
    crucible::EventId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn opaque_non_linux_image_ref() -> ContentAddressedBlobRef {
    ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(AARCH64_BARE_METAL_NON_LINUX_IMAGE))
}

fn opaque_non_linux_world() -> World {
    World::from_nodes(vec![WorldNode {
        id: node("monitor"),
        arch: VmArchitecture::Aarch64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount { icount: icount(1) },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: Some(opaque_non_linux_image_ref()),
        initrd: None,
    }])
    .expect("opaque non-Linux world should validate without a guest software contract")
}

fn black_box_predicate() -> Predicate {
    Predicate::all_of(vec![
        Predicate::console_match(
            node("monitor"),
            RegexProgram::from_pattern("standalone monitor ready"),
        ),
        Predicate::network_match(None, FramePredicate::contains(b"telemetry:ready".to_vec())),
        Predicate::io_pattern(node("monitor"), IoEventKind::Fsync),
        Predicate::node_state(node("monitor"), NodeLifecycle::Started),
        Predicate::coverage_point(node("monitor"), CodePoint::guest_address(0x8000)),
        Predicate::node_state(node("monitor"), NodeLifecycle::Hung),
    ])
}

fn black_box_events() -> Vec<ObservableEvent> {
    vec![
        ObservableEvent::console_output(
            time(30),
            node("monitor"),
            b"standalone monitor ready\n".to_vec(),
        ),
        ObservableEvent::network_delivered(time(30), None, b"telemetry:ready".to_vec()),
        ObservableEvent::io_completion(time(30), node("monitor"), IoEventKind::Fsync, b"ok"),
        ObservableEvent::node_state(time(30), node("monitor"), NodeLifecycle::Started),
        ObservableEvent::coverage_block(icount(30), node("monitor"), 0x8000, 0x20),
        ObservableEvent::node_state(time(30), node("monitor"), NodeLifecycle::Hung),
        ObservableEvent::memory_sample(
            time(30),
            icount(30),
            node("monitor"),
            ResolvedMemPlace::physical_address(0x1000, 8),
            0xfeed,
        ),
    ]
}

struct NoGuestSoftwareLeaves;

impl crucible::ConditionLeafOracle for NoGuestSoftwareLeaves {
    fn leaf_is_true(&mut self, leaf: crucible::ConditionLeaf<'_>) -> bool {
        match leaf {
            crucible::ConditionLeaf::Named { .. } | crucible::ConditionLeaf::GuestMarker { .. } => {
                panic!("OS-agnostic black-box checks must not need guest software leaves")
            }
        }
    }
}

#[test]
fn black_box_contract_catalog_has_no_guest_software_assumptions() {
    let kinds = BLACK_BOX_OBSERVATION_CONTRACTS
        .iter()
        .map(|contract| contract.kind())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        kinds,
        BLACK_BOX_OBSERVATION_KINDS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );

    for contract in BLACK_BOX_OBSERVATION_CONTRACTS {
        assert!(!contract.requires_guest_os_contract());
        assert!(!contract.requires_guest_init_contract());
        assert!(!contract.requires_guest_filesystem_contract());
        assert!(!contract.requires_guest_abi_contract());
        assert!(!contract.carries_host_to_guest_payload());
    }

    assert_eq!(
        BlackBoxObservationKind::ConsoleSerialOutput
            .contract()
            .source(),
        BlackBoxObservationSource::ExternalConsoleSerialSink
    );
}

#[test]
fn non_linux_opaque_image_uses_black_box_observation_without_guest_contract() {
    let world = opaque_non_linux_world();
    let node = &world.vm_nodes()[0];
    assert_eq!(node.arch, VmArchitecture::Aarch64);
    assert_eq!(node.white_box, WhiteBoxPolicy::Disabled);
    assert_eq!(node.root_image, Some(opaque_non_linux_image_ref()));
    assert_eq!(node.kernel, None);
    assert_eq!(node.initrd, None);

    let predicate = black_box_predicate();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: assertion("opaque-image-observable"),
            message: String::from("opaque image remains black-box observable"),
            property: Property::Always {
                predicate: predicate.clone(),
            },
        }],
    )
    .expect("black-box properties should validate for an opaque non-Linux image");
    assert_eq!(properties.assertions().len(), 1);

    for event in black_box_events() {
        let contract = event
            .black_box_observation_contract()
            .expect("test events should be required black-box observations");
        assert!(!contract.requires_guest_os_contract());
        assert!(!contract.requires_guest_init_contract());
        assert!(!contract.requires_guest_filesystem_contract());
        assert!(!contract.requires_guest_abi_contract());
        assert!(!contract.carries_host_to_guest_payload());
    }

    assert!(
        support::evaluation_with_observables(30, black_box_events(), NoGuestSoftwareLeaves,)
            .evaluate_assertion_condition(&predicate)
    );

    let graph = EventGraph::new_for_world(
        vec![Event::once(
            event("pass-on-opaque-image-observation"),
            Some(predicate),
            Action::Pass,
        )],
        &world,
    )
    .expect("black-box event graph should not require a guest OS contract");
    let mut state = EventGraphState::new();
    let firings = support::evaluate_graph(
        &graph,
        &mut state,
        support::evaluation_with_observables(30, black_box_events(), NoGuestSoftwareLeaves),
    );
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "pass-on-opaque-image-observation");
}

#[test]
fn console_serial_observation_is_output_only() {
    let event = ObservableEvent::console_output(
        time(7),
        node("monitor"),
        b"standalone monitor ready\n".to_vec(),
    );
    let contract = event
        .black_box_observation_contract()
        .expect("console output should be a black-box observation");

    assert_eq!(
        contract.kind(),
        BlackBoxObservationKind::ConsoleSerialOutput
    );
    assert_eq!(
        contract.source(),
        BlackBoxObservationSource::ExternalConsoleSerialSink
    );
    assert!(!contract.carries_host_to_guest_payload());
    assert!(!contract.requires_guest_abi_contract());
}
