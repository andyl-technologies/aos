//! Shared content-address gate fixtures.

use super::*;

pub(super) fn unique_temp_dir(label: &str) -> PathBuf {
    let index = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("crucible-{label}-{}-{index}", std::process::id()));
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("temporary DAG store root should be clearable: {error}"),
    }
    root
}

pub(super) fn checkpoint_with_search_frontier_choices(
    mut checkpoint: Checkpoint,
    decisions: Vec<Decision>,
) -> Checkpoint {
    let state = checkpoint
        .state
        .as_ref()
        .expect("test checkpoint must be materialized");
    let mut scheduler = state.scheduler.clone();
    scheduler.search_frontier =
        SearchFrontierChoices::from_decision_sequences(decisions.into_iter().map(std::iter::once));
    checkpoint.state = Some(MaterializedState::from_components_with_event_log_segments(
        state.vm_snapshots.clone(),
        state.device_overlays.clone(),
        scheduler,
        state.decision_rng.clone(),
        state.event_log,
        state.event_log_segments.clone(),
    ));
    checkpoint
}

pub(super) fn scenario(material: &str) -> ScenarioDef {
    ScenarioDef::from_canonical_material("crucible.test.content-address.scenario", material)
}

pub(super) fn event_key(virtual_time: u64, sequence: u64) -> EventKey {
    EventKey::new(
        VirtualTime {
            ticks: virtual_time,
        },
        scheduler_node("consumer"),
        scheduler_node("producer"),
        sequence,
    )
}

pub(super) fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

pub(super) fn fixed_schedule() -> Schedule {
    Schedule::empty()
        .appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: vec![event_key(1, 2), event_key(1, 3)],
        }))
        .appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_link("link-a-b/drop"),
            value: 1,
        }))
        .appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_node("guest/request"),
            value: 0xabcd_1234,
        }))
}

pub(super) fn generated_schedule(seed: u64, decisions: u64) -> Schedule {
    let mut schedule = Schedule::empty();
    for index in 0..decisions {
        schedule = schedule.appended(generated_decision(seed, index));
    }
    schedule
}

pub(super) fn generated_decision(seed: u64, index: u64) -> Decision {
    match (seed + index) % 3 {
        0 => Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime {
                ticks: seed + index,
            },
            order: vec![event_key(seed + index, index)],
        }),
        1 => Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name(format!("stream-{seed}-{index}")),
            value: u64::from(index.is_multiple_of(2)),
        }),
        _ => Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name(format!("stream-{seed}")),
            value: seed ^ index,
        }),
    }
}

pub(super) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

pub(super) fn symmetry_class(name: &str) -> SymmetryClassId {
    SymmetryClassId {
        name: String::from(name),
    }
}

pub(super) fn node_blob(material: &str) -> NodeBlobRef {
    NodeBlobRef::baked(ContentHash::from_canonical_material(
        "crucible.test.content-address.node-blob",
        material,
    ))
}

pub(super) fn preemption_decision(node: &str, retired: u64) -> Decision {
    Decision::Preemption(PreemptionDecision {
        node: node_id(node),
        at: crucible::SimInstant { ticks: retired },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    })
}

pub(super) fn fat_checkpoint_with_coverage(
    configuration: &Configuration,
    parent: &Configuration,
    coverage: ContentHash,
    node_blobs: BTreeMap<NodeId, NodeBlobRef>,
) -> Checkpoint {
    fat_checkpoint_with_coverage_and_event_log(
        configuration,
        parent,
        coverage,
        node_blobs,
        EventLogOffset::default(),
    )
}

pub(super) fn fat_checkpoint_with_coverage_and_event_log(
    configuration: &Configuration,
    parent: &Configuration,
    coverage: ContentHash,
    node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    event_log: EventLogOffset,
) -> Checkpoint {
    let node_icounts = node_blobs
        .keys()
        .cloned()
        .map(|node| (node, Icount { retired: 99 }))
        .collect::<BTreeMap<_, _>>();
    let state = MaterializedState::from_components(
        materialized_snapshots_for_blobs(&node_blobs, &node_icounts),
        BTreeMap::new(),
        SchedulerState::empty(),
        DecisionRngState::empty(),
        event_log,
    );
    Checkpoint::from_recorded_configuration(
        configuration,
        Some(parent),
        VirtualTime::default(),
        node_icounts,
        CheckpointKind::Fat,
        node_blobs,
    )
    .unwrap_or_else(|error| panic!("fat checkpoint should be constructible: {error}"))
    .with_materialized_state(Some(state))
    .with_coverage_fingerprint(coverage)
}

pub(super) fn materialized_snapshots_for_blobs(
    node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
    node_icounts: &BTreeMap<NodeId, Icount>,
) -> BTreeMap<NodeId, VmSnapshotRef> {
    node_blobs
        .iter()
        .map(|(node, blob)| {
            (
                node.clone(),
                VmSnapshotRef::new(
                    blob.clone(),
                    node_icounts.get(node).copied().unwrap_or_default(),
                ),
            )
        })
        .collect()
}

pub(super) fn cow_fork_checkpoint(
    configuration: &Configuration,
    parent: &Configuration,
    vm_delta: ContentHash,
    overlay_delta: ContentHash,
    log_prefix: ContentHash,
    log_segment: ContentHash,
) -> Checkpoint {
    let node = NodeId {
        name: String::from("node-a"),
    };
    let device = DeviceId {
        name: String::from("disk-a"),
    };
    let parent_vm =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.vm", "parent-ready");
    let resolved_vm =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.vm", "resolved-dirty");
    let parent_overlay =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.overlay", "base");
    let resolved_overlay =
        ContentHash::from_canonical_material("crucible.test.cow-sharing.overlay", "resolved");
    let icount = Icount { retired: 33 };
    let node_blobs = BTreeMap::from([(
        node.clone(),
        NodeBlobRef::cow_delta(parent_vm, vm_delta, resolved_vm),
    )]);
    let node_icounts = BTreeMap::from([(node.clone(), icount)]);
    let state = MaterializedState::from_components(
        BTreeMap::from([(
            node,
            VmSnapshotRef::new(
                NodeBlobRef::cow_delta(parent_vm, vm_delta, resolved_vm),
                icount,
            ),
        )]),
        BTreeMap::from([(
            device,
            DeviceOverlayDelta::new(
                parent_overlay,
                overlay_delta,
                resolved_overlay,
                DeviceRngState::empty(),
            ),
        )]),
        SchedulerState::empty(),
        DecisionRngState::empty(),
        EventLogOffset::with_appended_segment(log_prefix, 96, 3, log_segment),
    );

    Checkpoint::from_recorded_configuration(
        configuration,
        Some(parent),
        VirtualTime::default(),
        node_icounts,
        CheckpointKind::Fat,
        node_blobs,
    )
    .unwrap_or_else(|error| panic!("CoW fork checkpoint should be recorded-shaped: {error}"))
    .with_materialized_state(Some(state))
}

pub(super) fn recorded_fat_checkpoint(configuration: &Configuration) -> Checkpoint {
    let parent = if configuration.is_genesis() {
        None
    } else {
        let schedule = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))
            .unwrap_or_else(|error| panic!("test schedule prefix should build: {error}"));
        Some(Configuration {
            def: configuration.def.clone(),
            schedule,
        })
    };
    Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("test checkpoint should be recorded-shaped: {error}"))
}

pub(super) fn append_schedule(prefix: &Schedule, delta: &Schedule) -> Schedule {
    let mut schedule = prefix.clone();
    for decision in delta.decisions() {
        schedule = schedule.appended(decision.clone());
    }
    schedule
}

pub(super) fn fixed_vectors(
    scenario: &ScenarioDef,
    schedule: &Schedule,
    configuration: &Configuration,
    state: &State,
) -> [(&'static str, String); 7] {
    [
        ("scenario", hash_hex(scenario.id())),
        ("schedule", hash_hex(schedule.content_hash())),
        ("configuration", hash_hex(configuration.content_hash())),
        ("state", hash_hex(state.id)),
        (
            "world-component",
            hash_hex(ContentHash::from_canonical_material(
                "crucible.test.content-address.world",
                "nodes=[node-a,node-b]\nlinks=[a-b]\n",
            )),
        ),
        (
            "snapshot-blob",
            hash_hex(ContentHash::from_canonical_material(
                "crucible.test.content-address.snapshot",
                "vm=node-a\npage=0000\nbytes=0011223344556677\n",
            )),
        ),
        (
            "event-log-segment",
            hash_hex(ContentHash::from_canonical_material(
                "crucible.test.content-address.log",
                "0 delivery node-a->node-b icount=5\n1 fault link-drop fired=true\n",
            )),
        ),
    ]
}

pub(super) fn expected_vectors(
    vectors: [(&'static str, &'static str); 7],
) -> [(&'static str, String); 7] {
    vectors.map(|(name, hash)| (name, hash.to_owned()))
}

pub(super) fn hash_hex(hash: ContentHash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(hash.bytes.len() * 2);
    for byte in hash.bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
