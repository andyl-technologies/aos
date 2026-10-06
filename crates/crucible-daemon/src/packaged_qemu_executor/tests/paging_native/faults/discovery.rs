//! Authenticated target discovery retained under the original native Service.
//!
//! The stopped discovery machine and its metadata loan remain live throughout
//! all seeded lanes. Every lane must reproduce the declared register schema in
//! ordinary setup admission; this helper never installs a guessed CPU schema.

use super::*;
use crucible_shmem::*;

pub(super) fn with_discovered_world(run: impl FnOnce(&World)) {
    let source = paging_scenario();
    environment::with_native_repository_environment(
        "fault-discovery",
        34_900,
        |root, storage| {
            super::super::super::hot_fork_native::native_repository(&source, root, storage)
        },
        |mut config| {
            // This original Service spans the six sequential execution/replay
            // lanes; its finite lifetime is admitted before its watchdog starts.
            config.lifecycle = Arc::new(
                crucible_api::vm_lifecycle::ProductionVmLifecycleConfig::new(
                    environment_path("CRUCIBLE_PAGING_QEMU"),
                    environment_path("CRUCIBLE_PAGING_PLUGIN"),
                    environment_path("CRUCIBLE_PAGING_KERNEL"),
                    environment_path("CRUCIBLE_PAGING_ROOT"),
                    config.lifecycle.run_state_root(),
                )
                .with_initrd(environment_path("CRUCIBLE_PAGING_INITRD"))
                .with_root_image_format(crucible_qemu::QemuRootImageFormat::Raw)
                .with_kernel_cmdline_prefix("console=ttyS0 reboot=k panic=1 quiet rdinit=/init")
                .with_run_ceiling_ticks(50_000_000_000)
                .with_rendezvous_interval_ticks(8_000_000)
                .with_quantum_budget(256)
                .with_completion_timeout(Duration::from_secs(10_500)),
            );
            config
        },
        |prepared, config, _repository| {
            run_capture(prepared, config, &source, |context| {
                extend_native_operations(context);
                let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
                    .expect("actual discovery process and ext4 quota");
                let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
                    config.lifecycle.clone(),
                    ComposedQemuAttemptResourceGuardFactory::new(host),
                );
                let mut lifecycle = factory
                    .begin_fresh(&source.scenario_def(), &source, context)
                    .expect("genuinely admitted stopped discovery machine");
                let world_node = source.world().vm_nodes().first().expect("one native node");
                let node = world_node.id.clone();
                let manifest = lifecycle
                    .register_capability_manifest(&node)
                    .expect("actual setup-authenticated register manifest");
                let bytes = retained_metadata_bound(manifest);
                let metadata = lifecycle
                    .reserve_fault_manifest_metadata(&node, bytes)
                    .expect("original discovery node metadata loan before encoding or copying");

                let capabilities = world_capabilities(manifest, world_node);
                let world = source
                    .world()
                    .clone()
                    .with_fault_topology(WorldFaultTopology {
                        node_capabilities: vec![capabilities],
                        ..WorldFaultTopology::default()
                    })
                    .expect("authenticated capability declaration");
                assert_eq!(world.vm_nodes(), source.world().vm_nodes());
                run(&world);

                // World/scenario copies have finished before releasing their
                // loan. Native cleanup still occurs inside the charged Service.
                drop(world);
                drop(metadata);
                lifecycle.shutdown().expect("actual discovery node cleanup");
                Ok(())
            })
            .expect("discovery Service custody survives all authored World uses");
        },
    );
}

pub(in crate::packaged_qemu_executor::tests::paging_native) fn retained_metadata_bound(
    manifest: &FaultRegisterCapabilityManifestV1,
) -> u64 {
    // The fixture uses at most 32 simultaneous canonical/decoded schema copies
    // across one scenario, accepted assignment, capture and two replay owners.
    // Rows account strings, hex expansion, phase/effect vectors and allocator
    // padding; the fixed allowance covers World/plan and codec scratch.
    let one_copy = manifest.rows.iter().fold(4096_usize, |bytes, row| {
        let masks = row.writable_mask.len()
            + row.reserved_mask.len()
            + row.ignored_mask.len()
            + row.read_only_mask.len();
        bytes
            .checked_add(512 + 4 * row.name.len() + 4 * masks)
            .expect("bounded register manifest allocation estimate")
    });
    let bytes = one_copy
        .checked_mul(32)
        .and_then(|bytes| bytes.checked_add(256 * 1024))
        .expect("bounded retained schema peak");
    u64::try_from(bytes).expect("host metadata size fits resource ledger")
}

pub(in crate::packaged_qemu_executor::tests::paging_native) fn world_capabilities(
    manifest: &FaultRegisterCapabilityManifestV1,
    node: &WorldNode,
) -> WorldNodeFaultCapabilities {
    assert_eq!(manifest.architecture, FaultCapabilityScope::X86_64);
    let encoded = manifest
        .encode()
        .expect("authenticated manifest canonical encoding");
    let registers = manifest.rows.iter().map(world_register).collect();
    WorldNodeFaultCapabilities {
        id: SignalId::parse("memory-capabilities").expect("capability ID"),
        node: SignalId::parse(&node.id.name).expect("exact node ID"),
        architecture: WorldNodeArchitecture::X86_64,
        cpu_model: manifest.cpu_model.clone(),
        register_schema: ContentHash {
            bytes: *blake3::hash(&encoded).as_bytes(),
        },
        registers,
        address_spaces: vec![WorldNodeAddressSpace {
            id: SignalId::parse("gpa").expect("native GPA namespace"),
            start_address: 0,
            length_bytes: u64::from(node.memory_mib) * 1024 * 1024,
        }],
        page_bytes: 4096,
        dram_geometry: WorldNodeDramGeometry::emulated_v1(),
        interrupts: Vec::new(),
        hardware_errors: Vec::new(),
        clock_sources: Vec::new(),
        accelerators: Vec::new(),
        ready_markers: Vec::new(),
        semantic_version: 1,
    }
}

fn world_register(row: &FaultRegisterCapabilityRowV1) -> WorldNodeRegister {
    assert_eq!(row.model_phase_mask & !((1 << 10) | (1 << 11)), 0);
    assert_eq!(row.side_effects & !FAULT_REGISTER_SIDE_EFFECTS_V1_MASK, 0);
    assert_eq!(row.capabilities & !FAULT_REGISTER_CAPABILITIES_V1_MASK, 0);
    let group = match row.group {
        FaultRegisterGroupV1::GeneralPurpose => WorldNodeRegisterGroup::GeneralPurpose,
        FaultRegisterGroupV1::ControlFlow => WorldNodeRegisterGroup::ControlFlow,
        FaultRegisterGroupV1::Flags => WorldNodeRegisterGroup::Flags,
        FaultRegisterGroupV1::Segment => WorldNodeRegisterGroup::Segment,
        FaultRegisterGroupV1::Control => WorldNodeRegisterGroup::Control,
        FaultRegisterGroupV1::System => WorldNodeRegisterGroup::System,
        FaultRegisterGroupV1::Debug => WorldNodeRegisterGroup::Debug,
        FaultRegisterGroupV1::FloatingPoint => WorldNodeRegisterGroup::FloatingPoint,
        FaultRegisterGroupV1::Vector => WorldNodeRegisterGroup::Vector,
        FaultRegisterGroupV1::Error => WorldNodeRegisterGroup::Error,
    };
    let model_phases = [FaultPhase::BeforeInstruction, FaultPhase::AfterInstruction]
        .into_iter()
        .enumerate()
        .filter_map(|(index, phase)| {
            (row.model_phase_mask & (1 << (10 + index)) != 0).then_some(phase)
        })
        .collect();
    let side_effects = [
        (
            FAULT_REGISTER_SIDE_EFFECT_TLB_FLUSH,
            WorldNodeRegisterSideEffect::TlbFlush,
        ),
        (
            FAULT_REGISTER_SIDE_EFFECT_TB_FLUSH,
            WorldNodeRegisterSideEffect::TranslationBlockFlush,
        ),
        (
            FAULT_REGISTER_SIDE_EFFECT_CPU_FLAGS,
            WorldNodeRegisterSideEffect::FlagsRecompute,
        ),
        (
            FAULT_REGISTER_SIDE_EFFECT_INTERRUPT,
            WorldNodeRegisterSideEffect::InterruptReevaluate,
        ),
        (
            FAULT_REGISTER_SIDE_EFFECT_TIMER,
            WorldNodeRegisterSideEffect::TimerRearm,
        ),
        (
            FAULT_REGISTER_SIDE_EFFECT_CONTROL_FLOW,
            WorldNodeRegisterSideEffect::ControlFlowSynchronize,
        ),
    ]
    .into_iter()
    .filter_map(|(flag, effect)| (row.side_effects & flag != 0).then_some(effect))
    .collect();
    WorldNodeRegister {
        // Native names can contain underscores; authoring IDs use the same
        // exact numeric identity while retaining the original ABI name below.
        id: SignalId::parse(format!("register-{}", row.numeric_id)).expect("native register ID"),
        name: row.name.clone(),
        numeric_id: row.numeric_id,
        group,
        width_bits: row.width_bits,
        per_vcpu: true,
        model_phases,
        side_effects,
        impulse: row.capabilities & FAULT_REGISTER_CAPABILITY_IMPULSE != 0,
        persistent: row.capabilities & FAULT_REGISTER_CAPABILITY_PERSISTENT != 0,
        vmstate: row.capabilities & FAULT_REGISTER_CAPABILITY_VMSTATE != 0,
        writable_mask_hex: lower_hex(&row.writable_mask),
        reserved_mask_hex: lower_hex(&row.reserved_mask),
        ignored_mask_hex: lower_hex(&row.ignored_mask),
        read_only_mask_hex: lower_hex(&row.read_only_mask),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("infallible String formatter");
    }
    encoded
}

#[test]
fn capability_projection_preserves_exact_manifest_bytes_and_guest_definition() {
    // This codec fixture proves projection only. Native qualification obtains
    // the manifest from an admitted live node and never uses this constructor.
    let manifest = FaultRegisterCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        cpu_model: String::from("max-x86_64-cpu"),
        rows: vec![FaultRegisterCapabilityRowV1 {
            numeric_id: 1,
            name: String::from("rax"),
            width_bits: 64,
            group: FaultRegisterGroupV1::GeneralPurpose,
            model_phase_mask: (1 << 10) | (1 << 11),
            side_effects: FAULT_REGISTER_SIDE_EFFECT_TLB_FLUSH
                | FAULT_REGISTER_SIDE_EFFECT_CONTROL_FLOW,
            capabilities: FAULT_REGISTER_CAPABILITIES_V1_MASK,
            writable_mask: vec![0xff; 8],
            reserved_mask: vec![0; 8],
            ignored_mask: vec![0; 8],
            read_only_mask: vec![0; 8],
        }],
    };
    let base = paging_scenario();
    let node = base.world().vm_nodes().first().expect("one native node");
    let capability = world_capabilities(&manifest, node);
    let requirement =
        crucible_qemu::QemuFaultCapabilityRequirement::current_v1_for_node(&capability)
            .expect("canonical projection must be admitted");
    assert_eq!(
        requirement
            .target_manifest()
            .and_then(|target| target.exact_register_manifest()),
        Some(&manifest)
    );
    assert!(
        retained_metadata_bound(&manifest)
            > 32 * manifest.encode().expect("fixture encoding").len() as u64
    );

    let world = base
        .world()
        .clone()
        .with_fault_topology(WorldFaultTopology {
            node_capabilities: vec![capability],
            ..WorldFaultTopology::default()
        })
        .expect("closed capability projection");
    for seed in SEEDS {
        let scenario = fault_scenario(&world, seed);
        assert_eq!(scenario.world().vm_nodes(), base.world().vm_nodes());
        assert_eq!(scenario.scenario_def().seed(), Seed::from_u64(seed));
    }
}
