//! Checks T-GHC-12 channel determinism and marker fingerprint neutrality.

#![cfg(feature = "test-double")]
#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AdvanceOutcome, Backend, BackendInput, ContentHash, ExecutionFingerprint, ExecutionHorizon,
    Icount, NodeId, NodeTemplate, ObservableEvent, ReadyPoint, SchedulerEvaluationBoundaryKind,
    SchedulerEventLogAppend, SchedulerEventLogEntry, SchedulerLivenessScenario, Shift, SimBackend,
    SimInstant, SingleScheduler, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
    compare_event_log_determinism, event_log_causal_projection,
    observable_event_from_whitebox_marker_payload,
};
use crucible_protocol::{
    WhiteboxCoverageMarkerBody, WhiteboxEventMarkerBody, WhiteboxLifecycleMarkerEvent,
    WhiteboxMarkerPayload,
};

#[test]
fn whitebox_channel_fingerprints_are_identical_with_markers_on_vs_off() {
    let markers_off = run_channel_material(
        WhiteBoxPolicy::Disabled,
        MarkerMode::Off,
        b"same-workload",
        20,
    );
    let markers_on = run_channel_material(
        WhiteBoxPolicy::Enabled,
        MarkerMode::On,
        b"same-workload",
        20,
    );

    assert_eq!(
        markers_off.determinism_material(),
        markers_on.determinism_material()
    );
    assert_eq!(
        markers_off.causal_event_log_fingerprint,
        markers_on.causal_event_log_fingerprint
    );
    assert_eq!(
        markers_off.backend_fingerprint,
        markers_on.backend_fingerprint
    );

    let comparison = compare_event_log_determinism(&markers_off.event_log, &markers_on.event_log);
    assert!(comparison.passes());
    assert_eq!(
        comparison.expected().canonical_bytes(),
        comparison.reproduced().canonical_bytes()
    );

    let changed_causal = run_channel_material(
        WhiteBoxPolicy::Disabled,
        MarkerMode::Off,
        b"same-workload",
        21,
    );
    assert_ne!(
        markers_off.causal_event_log_fingerprint,
        changed_causal.causal_event_log_fingerprint
    );

    let changed_workload = run_channel_material(
        WhiteBoxPolicy::Enabled,
        MarkerMode::On,
        b"changed-workload",
        20,
    );
    assert_ne!(
        markers_on.backend_fingerprint,
        changed_workload.backend_fingerprint
    );
}

#[test]
fn app_random_compiled_in_zero_requests_is_fingerprint_identical() {
    let disabled = run_channel_material(
        WhiteBoxPolicy::Disabled,
        MarkerMode::Off,
        b"same-workload",
        20,
    );
    let compiled_in_zero = run_channel_material(
        WhiteBoxPolicy::Enabled,
        MarkerMode::Off,
        b"same-workload",
        20,
    );

    assert_eq!(
        disabled.determinism_material(),
        compiled_in_zero.determinism_material()
    );
    assert_eq!(disabled.event_log, compiled_in_zero.event_log);

    let comparison =
        compare_event_log_determinism(&disabled.event_log, &compiled_in_zero.event_log);
    assert!(comparison.passes());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MarkerMode {
    Off,
    On,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChannelRunMaterial {
    causal_event_log_fingerprint: ContentHash,
    backend_fingerprint: ExecutionFingerprint,
    event_log: Vec<SchedulerEventLogEntry>,
}

impl ChannelRunMaterial {
    fn determinism_material(&self) -> ChannelDeterminismMaterial {
        ChannelDeterminismMaterial {
            causal_event_log_fingerprint: self.causal_event_log_fingerprint,
            backend_fingerprint: self.backend_fingerprint.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChannelDeterminismMaterial {
    causal_event_log_fingerprint: ContentHash,
    backend_fingerprint: ExecutionFingerprint,
}

fn run_channel_material(
    white_box: WhiteBoxPolicy,
    marker_mode: MarkerMode,
    workload: &[u8],
    boundary_ticks: u64,
) -> ChannelRunMaterial {
    let world = channel_world(white_box);
    assert!(world.nodes().iter().all(|node| node.white_box == white_box));
    let mut scheduler = SingleScheduler::new(channel_scenario("channel-determinism", &world))
        .expect("channel determinism scheduler should build");
    let mut event_log = Vec::new();

    record_append(
        scheduler
            .append_observable_events(black_box_events())
            .expect("black-box channel events should append"),
        &mut event_log,
    );
    if marker_mode == MarkerMode::On {
        record_append(
            scheduler
                .append_observable_events(marker_events())
                .expect("white-box marker events should append"),
            &mut event_log,
        );
    }
    record_append(
        scheduler
            .append_evaluation_boundary(
                time(boundary_ticks),
                SchedulerEvaluationBoundaryKind::Quantum,
            )
            .expect("causal boundary should append"),
        &mut event_log,
    );

    let mut backend = SimBackend::new();
    backend
        .deliver_input(BackendInput {
            node: node("db-0"),
            payload: workload.to_vec(),
        })
        .expect("deterministic backend input should deliver");
    assert_eq!(
        backend.advance_to_horizon(ExecutionHorizon {
            icount: icount(4096),
        }),
        Ok(AdvanceOutcome::ReachedHorizon)
    );

    backend
        .fingerprint()
        .map(|backend_fingerprint| ChannelRunMaterial {
            causal_event_log_fingerprint: event_log_causal_projection(&event_log).content_hash(),
            backend_fingerprint,
            event_log,
        })
        .expect("deterministic backend fingerprint should read")
}

fn record_append(append: SchedulerEventLogAppend, event_log: &mut Vec<SchedulerEventLogEntry>) {
    event_log.extend(append.entries);
}

fn channel_world(white_box: WhiteBoxPolicy) -> World {
    World::from_nodes(vec![WorldNode {
        id: node("db-0"),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount { icount: icount(1) },
        white_box,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("channel determinism world should validate")
}

fn channel_scenario(name: &str, world: &World) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        Shift { bits: 0 },
        16,
        SimInstant { nanos: 100 },
        Vec::new(),
        Vec::new(),
    )
    .with_trigger_world(world)
}

fn black_box_events() -> Vec<ObservableEvent> {
    vec![ObservableEvent::console_output(
        time(10),
        node("db-0"),
        b"db-0 ready\n".to_vec(),
    )]
}

fn marker_events() -> Vec<ObservableEvent> {
    [
        (9, lifecycle_payload()),
        (11, event_payload("guest.note")),
        (12, coverage_payload("hot-path")),
    ]
    .into_iter()
    .map(|(retired, payload)| {
        observable_event_from_whitebox_marker_payload(icount(retired), node("db-0"), &payload)
            .expect("observational marker payload should map to an event-log observation")
    })
    .collect()
}

fn lifecycle_payload() -> WhiteboxMarkerPayload {
    WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::SetupComplete)
}

fn event_payload(name: &str) -> WhiteboxMarkerPayload {
    WhiteboxMarkerPayload::Event(WhiteboxEventMarkerBody {
        name: name.to_owned(),
        details: Vec::new(),
    })
}

fn coverage_payload(point: &str) -> WhiteboxMarkerPayload {
    WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
        point: point.to_owned(),
    })
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
