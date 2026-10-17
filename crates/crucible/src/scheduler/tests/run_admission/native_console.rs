//! Original semantic RUN projection, boot visibility and checkpoint controls.

use super::*;

fn scheduler() -> SingleScheduler {
    SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "console-ready-projection",
            16,
            SimInstant { ticks: 64 },
            vec![test_scenario_node(
                "a",
                100,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )],
            Vec::new(),
        )
        .with_ready_point_counter(
            scheduler_node("a", SchedulingNodeKind::Vm),
            NodeCounter { ticks: 100 },
        ),
    )
    .expect("original ready point creates scheduler")
}

fn origin(ps: u64) -> crate::NativeConsoleByteOrigin {
    crate::NativeConsoleByteOrigin {
        device: ContentHash { bytes: [7; 32] },
        stream: 1,
        logical_generation: 0,
        node_sequence: 1,
        stream_sequence: 1,
        emitted_ps: ps,
        raw_prefix: 17,
        vcpu: 0,
        byte: 0xff,
    }
}

#[test]
fn original_console_run_map_and_boot_visibility_survive_later_rebase() {
    let mut scheduler = scheduler();
    let admission = prepare(&scheduler).runs[0].admission.clone();
    let map = admission
        .retain_native_console_mapping(0)
        .expect("genuine original RUN map");
    let node = admission.node();
    let boot = origin(90);
    let event = map
        .project_boot_origin(node, NodeCounter { ticks: 100 }, &boot)
        .expect("boot visibility is original ready point");
    assert_eq!(event.at().ticks, 0);
    assert_eq!(
        event.payload(),
        &crate::ObservableEventPayload::NativeConsoleByte {
            node: node.clone(),
            origin: boot.clone()
        }
    );
    assert_eq!(
        map.project_origin(node, &origin(105))
            .expect("RUN projection")
            .at()
            .ticks,
        5
    );

    scheduler
        .rebase_restarted_backend_counter(node, NodeCounter { ticks: 80 })
        .expect("original restart owner rebases counter");
    let later = prepare(&scheduler).runs[0]
        .admission
        .retain_native_console_mapping(0)
        .expect("later genuine RUN map");
    assert_eq!(
        later
            .project_origin(node, &origin(105))
            .expect("later projection")
            .at()
            .ticks,
        25
    );
    assert_eq!(
        map.project_origin(node, &origin(105))
            .expect("retained original projection")
            .at()
            .ticks,
        5
    );
    assert_eq!(
        later
            .project_boot_origin(node, NodeCounter { ticks: 100 }, &boot)
            .expect("immutable original ready map")
            .at()
            .ticks,
        0
    );
}

#[test]
fn console_projection_refuses_foreign_origin_and_ready_owner_without_restamping() {
    let scheduler = scheduler();
    let admission = prepare(&scheduler).runs[0].admission.clone();
    let map = admission
        .retain_native_console_mapping(0)
        .expect("genuine map");
    let node = admission.node();
    assert!(
        map.project_boot_origin(node, NodeCounter { ticks: 101 }, &origin(90))
            .is_err()
    );
    assert!(
        map.project_boot_origin(node, NodeCounter { ticks: 100 }, &origin(101))
            .is_err()
    );
    let mut changed = origin(105);
    changed.logical_generation = 1;
    assert!(map.project_origin(node, &changed).is_err());
    assert!(
        map.project_origin(
            &NodeId {
                name: String::from("b")
            },
            &origin(105)
        )
        .is_err()
    );
    let encoded = map.to_canonical_bytes().expect("checkpoint map encoding");
    assert_eq!(
        crate::NativeConsoleMappingLease::from_canonical_bytes(&encoded).expect("exact map decode"),
        map
    );
    let mut drifted_boot = encoded.clone();
    let ready_time_offset = drifted_boot.len() - 8;
    drifted_boot[ready_time_offset..].copy_from_slice(&1_u64.to_le_bytes());
    assert!(crate::NativeConsoleMappingLease::from_canonical_bytes(&drifted_boot).is_err());

    let mut trailing = encoded;
    trailing.push(0);
    assert!(crate::NativeConsoleMappingLease::from_canonical_bytes(&trailing).is_err());
}

#[test]
fn scheduler_checkpoint_preserves_original_console_ready_map_after_rebase() {
    let mut scheduler = scheduler();
    scheduler
        .rebase_restarted_backend_counter(
            &NodeId {
                name: String::from("a"),
            },
            NodeCounter { ticks: 80 },
        )
        .expect("original restart owner rebases counter");
    let bytes = scheduler
        .checkpoint()
        .expect("genuine checkpoint")
        .canonical_bytes()
        .expect("canonical checkpoint");
    let checkpoint = SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)
        .expect("current version checkpoint");
    let mut restored = self::scheduler();
    checkpoint
        .restore_into(&mut restored)
        .expect("original ready identity restores");
    let admission = prepare(&restored).runs[0].admission.clone();
    let map = admission
        .retain_native_console_mapping(0)
        .expect("restored original maps");
    assert_eq!(
        map.project_origin(admission.node(), &origin(105))
            .expect("restored RUN")
            .at()
            .ticks,
        25
    );
    assert_eq!(
        map.project_boot_origin(admission.node(), NodeCounter { ticks: 100 }, &origin(90))
            .expect("restored ready visibility")
            .at()
            .ticks,
        0
    );
}
