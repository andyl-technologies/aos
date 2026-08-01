//! Checks RFC-0010 T-WL-6 workload parameterization invariants.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ContentAddressedBlobRef, ContentHash, EngineError, GuestWorkloadBinary,
    GuestWorkloadConfigTreeDelivery, GuestWorkloadConfigTreeRef, GuestWorkloadParameterKey,
    GuestWorkloadScalarParameter, Icount, NodeId, NodeTemplate, Plan, Properties,
    ReproductionArtifact, ScenarioDefForm, Schedule, Seed, VmArchitecture,
    WORKLOAD_CONFIG_TREE_DETERMINISTIC_QIDS, WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER,
    WORKLOAD_CONFIG_TREE_SORTED_ENUMERATION, WORKLOAD_CONFIG_TREES_ARE_READ_ONLY,
    WORKLOAD_PARAMETER_HOST_RUNTIME_POKES_ALLOWED, WORKLOAD_PARAMETERS_ARE_SCENARIO_CONFIG,
    WhiteBoxPolicy, World, WorldNode, WorldWorkloadConfigTree,
};

#[test]
fn scalar_workload_parameters_are_cmdline_scenario_config() -> Result<(), EngineError> {
    let rate = GuestWorkloadScalarParameter::new(GuestWorkloadParameterKey::Rate, "50")?;
    let count = GuestWorkloadScalarParameter::new(GuestWorkloadParameterKey::Count, "100")?;
    let target =
        GuestWorkloadScalarParameter::new(GuestWorkloadParameterKey::Target, "server:8080")?;
    let payload =
        GuestWorkloadScalarParameter::new(GuestWorkloadParameterKey::PayloadSizeBytes, "4096")?;

    assert_eq!(rate.scenario_parameter(), "rate=50");
    let cmdline = payload.selected_cmdline(&target.selected_cmdline(
        &count.selected_cmdline(&rate.selected_cmdline("console=ttyS0 rate=old")),
    ));
    assert_eq!(
        cmdline,
        "console=ttyS0 rate=50 count=100 target=server:8080 payload_size_bytes=4096"
    );

    let world = World::from_nodes(vec![world_node("client", cmdline, None)])?;
    let node = only_node(world.vm_nodes());
    let scalars = node.guest_workload_scalar_parameters();
    assert_eq!(
        scalars.get(&GuestWorkloadParameterKey::Rate),
        Some(&String::from("50"))
    );
    assert_eq!(
        scalars.get(&GuestWorkloadParameterKey::Count),
        Some(&String::from("100"))
    );
    assert_eq!(
        scalars.get(&GuestWorkloadParameterKey::Target),
        Some(&String::from("server:8080"))
    );
    assert_eq!(
        scalars.get(&GuestWorkloadParameterKey::PayloadSizeBytes),
        Some(&String::from("4096"))
    );
    Ok(())
}

#[test]
fn scalar_parameter_change_changes_scenario_id_and_reproduces() -> Result<(), EngineError> {
    const { assert!(WORKLOAD_PARAMETERS_ARE_SCENARIO_CONFIG) };
    const { assert!(!WORKLOAD_PARAMETER_HOST_RUNTIME_POKES_ALLOWED) };

    let rate_50 = form_with_cmdline("console=ttyS0 crucible.workload=httpget rate=50 count=100")?;
    let rate_100 = form_with_cmdline("console=ttyS0 crucible.workload=httpget rate=100 count=100")?;
    let count_200 = form_with_cmdline("console=ttyS0 crucible.workload=httpget rate=50 count=200")?;

    assert_ne!(rate_50.id(), rate_100.id());
    assert_ne!(rate_50.id(), count_200.id());
    assert_eq!(rate_50.seed(), rate_100.seed());
    assert_eq!(rate_50.seed(), count_200.seed());

    assert_individually_reproducible(&rate_50)?;
    assert_individually_reproducible(&rate_100)?;
    assert_individually_reproducible(&count_200)?;
    Ok(())
}

#[test]
fn structured_config_tree_refs_are_read_only_content_addressed() -> Result<(), EngineError> {
    assert_eq!(WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER, "wcfg");
    const { assert!(WORKLOAD_CONFIG_TREES_ARE_READ_ONLY) };
    const { assert!(WORKLOAD_CONFIG_TREE_DETERMINISTIC_QIDS) };
    const { assert!(WORKLOAD_CONFIG_TREE_SORTED_ENUMERATION) };

    let rootfs = GuestWorkloadConfigTreeRef::read_only_rootfs(
        blob("rootfs-workload-config-v1"),
        "/etc/workload",
    )?;
    let ninep =
        GuestWorkloadConfigTreeRef::read_only_ninep(blob("ninep-workload-config-v1"), "/workload")?;

    assert_eq!(
        rootfs.delivery(),
        GuestWorkloadConfigTreeDelivery::ReadOnlyRootfs
    );
    assert!(rootfs.delivery().is_read_only());
    assert_eq!(rootfs.mount(), "/etc/workload");
    assert!(
        rootfs
            .scenario_parameter()
            .starts_with("wcfg=readonly_rootfs,export=blake3:")
    );

    assert_eq!(
        ninep.delivery(),
        GuestWorkloadConfigTreeDelivery::ReadOnlyNineP
    );
    assert!(ninep.delivery().is_read_only());
    assert_eq!(ninep.mount(), "/workload");
    assert!(
        ninep
            .scenario_parameter()
            .starts_with("wcfg=readonly_9p,export=blake3:")
    );

    let selected = ninep.selected_cmdline("console=ttyS0 wcfg=old");
    assert_eq!(
        GuestWorkloadConfigTreeRef::from_cmdline(&selected),
        Some(ninep)
    );
    Ok(())
}

#[test]
fn config_tree_change_changes_scenario_id_and_reproduces() -> Result<(), EngineError> {
    let rootfs_a = GuestWorkloadConfigTreeRef::read_only_rootfs(
        blob("rootfs-workload-config-v1"),
        "/etc/workload",
    )?;
    let rootfs_b = GuestWorkloadConfigTreeRef::read_only_rootfs(
        blob("rootfs-workload-config-v2"),
        "/etc/workload",
    )?;
    let ninep_a =
        GuestWorkloadConfigTreeRef::read_only_ninep(blob("ninep-workload-config-v1"), "/workload")?;
    let ninep_b =
        GuestWorkloadConfigTreeRef::read_only_ninep(blob("ninep-workload-config-v2"), "/workload")?;

    let rootfs_form_a = form_with_config_tree(&rootfs_a)?;
    let rootfs_form_b = form_with_config_tree(&rootfs_b)?;
    let ninep_form_a = form_with_config_tree(&ninep_a)?;
    let ninep_form_b = form_with_config_tree(&ninep_b)?;
    let template_rootfs = scenario_def_with_template(
        NodeTemplate::fixed_icount(Icount { retired: 1 })
            .cmdline("console=ttyS0")
            .guest_workload(GuestWorkloadBinary::Benchmark)
            .guest_workload_config_tree(&rootfs_a),
    )?;
    let manual_rootfs = world_with_config_tree(&rootfs_a)?
        .scenario_def_with_plan_properties_and_seed(
            &Plan::empty(),
            &Properties::empty(),
            Seed::from_u64(7),
        )?;

    assert_ne!(rootfs_form_a.id(), rootfs_form_b.id());
    assert_ne!(ninep_form_a.id(), ninep_form_b.id());
    assert_ne!(rootfs_form_a.id(), ninep_form_a.id());
    assert_eq!(template_rootfs.id(), manual_rootfs.id());
    assert_eq!(rootfs_form_a.seed(), rootfs_form_b.seed());
    assert_eq!(ninep_form_a.seed(), ninep_form_b.seed());

    let rootfs_node = only_node(rootfs_form_a.world().vm_nodes());
    assert_eq!(rootfs_node.root_image, Some(rootfs_a.export()));
    assert_eq!(
        rootfs_node.guest_workload_config_tree(),
        Some(rootfs_a.clone())
    );
    assert_eq!(
        rootfs_form_a.world().workload_config_trees(),
        vec![WorldWorkloadConfigTree {
            node: NodeId {
                name: String::from("client")
            },
            config: rootfs_a.clone(),
        }]
    );

    let ninep_node = only_node(ninep_form_a.world().vm_nodes());
    assert_eq!(ninep_node.root_image, None);
    assert_eq!(
        ninep_node.guest_workload_config_tree(),
        Some(ninep_a.clone())
    );
    assert_eq!(
        ninep_form_a.world().workload_config_trees(),
        vec![WorldWorkloadConfigTree {
            node: NodeId {
                name: String::from("client")
            },
            config: ninep_a.clone(),
        }]
    );

    assert_individually_reproducible(&rootfs_form_a)?;
    assert_individually_reproducible(&rootfs_form_b)?;
    assert_individually_reproducible(&ninep_form_a)?;
    assert_individually_reproducible(&ninep_form_b)?;
    Ok(())
}

#[test]
fn workload_parameterization_rejects_invalid_or_duplicate_values() {
    assert_invalid_scalar_value(GuestWorkloadScalarParameter::new(
        GuestWorkloadParameterKey::Rate,
        "",
    ));
    assert_invalid_config_mount(GuestWorkloadConfigTreeRef::read_only_ninep(
        blob("ninep-workload-config-v1"),
        "relative/path",
    ));
    assert_invalid_config_mount(GuestWorkloadConfigTreeRef::read_only_ninep(
        blob("ninep-workload-config-v1"),
        "/etc/work,load",
    ));

    assert_duplicate_scalar_parameter(World::from_nodes(vec![world_node(
        "client",
        "console=ttyS0 rate=50 rate=100",
        None,
    )]));
    assert_invalid_world_scalar_value(World::from_nodes(vec![world_node(
        "client",
        "console=ttyS0 count=",
        None,
    )]));
    assert_unsupported_config_tree(
        World::from_nodes(vec![world_node(
            "client",
            "console=ttyS0 wcfg=mutable_9px,export=blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,mount=/workload",
            None,
        )]),
        "mutable_9px",
    );
    assert_unsupported_config_tree(
        World::from_nodes(vec![world_node(
            "client",
            "console=ttyS0 wcfg=readonly_9p,export=/nix/store/workload,mount=/workload",
            None,
        )]),
        "readonly_9p",
    );
    assert_unsupported_config_tree(
        World::from_nodes(vec![world_node(
            "client",
            "console=ttyS0 wcfg=readonly_9p,export=blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,mount=relative/path",
            None,
        )]),
        "relative/path",
    );
    assert_duplicate_config_tree(World::from_nodes(vec![world_node(
        "client",
        "console=ttyS0 wcfg=readonly_9p,export=blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,mount=/workload wcfg=readonly_9p,export=blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,mount=/workload",
        None,
    )]));

    let rootfs = GuestWorkloadConfigTreeRef::read_only_rootfs(
        blob("rootfs-workload-config-v1"),
        "/etc/workload",
    )
    .expect("rootfs fixture should validate");
    assert_rootfs_config_missing_root_image(World::from_nodes(vec![world_node(
        "client",
        rootfs.selected_cmdline("console=ttyS0"),
        None,
    )]));
    assert_rootfs_config_mismatched_root_image(World::from_nodes(vec![world_node(
        "client",
        rootfs.selected_cmdline("console=ttyS0"),
        Some(blob("different-rootfs-image")),
    )]));
}

#[test]
fn workload_parameterization_rejects_malformed_toml_and_binary_forms() -> Result<(), EngineError> {
    let form = form_with_cmdline("console=ttyS0 crucible.workload=httpget rate=50 padxxxxx")?;
    let duplicate_toml = replace_once(form.to_canonical_toml()?, "padxxxxx", "rate=100");
    assert_duplicate_scalar_parameter(ScenarioDefForm::from_canonical_toml(&duplicate_toml));

    let duplicate_bytes = replace_ascii_once(form.to_compact_binary(), "padxxxxx", "rate=100");
    assert_duplicate_scalar_parameter(ScenarioDefForm::from_compact_binary(&duplicate_bytes));

    let config = GuestWorkloadConfigTreeRef::read_only_ninep(
        blob("ninep-workload-config-v1"),
        "/etc/workload",
    )?;
    let config_form = form_with_config_tree(&config)?;
    let invalid_toml = replace_once(
        config_form.to_canonical_toml()?,
        "readonly_9p",
        "mutable_9px",
    );
    assert_unsupported_config_tree(
        ScenarioDefForm::from_canonical_toml(&invalid_toml),
        "mutable_9px",
    );

    let invalid_bytes = replace_ascii_once(
        config_form.to_compact_binary(),
        "readonly_9p",
        "mutable_9px",
    );
    assert_unsupported_config_tree(
        ScenarioDefForm::from_compact_binary(&invalid_bytes),
        "mutable_9px",
    );

    let rootfs_config = GuestWorkloadConfigTreeRef::read_only_rootfs(
        blob("rootfs-workload-config-v1"),
        "/etc/workload",
    )?;
    let rootfs_form = form_with_config_tree(&rootfs_config)?;
    let different_rootfs = blob("different-rootfs-image").to_uri();
    let rootfs_mismatch_toml = replace_once(
        rootfs_form.to_canonical_toml()?,
        &rootfs_config.export().to_uri(),
        &different_rootfs,
    );
    assert_rootfs_config_mismatched_root_image(ScenarioDefForm::from_canonical_toml(
        &rootfs_mismatch_toml,
    ));

    let rootfs_mismatch_bytes = replace_ascii_once(
        rootfs_form.to_compact_binary(),
        &rootfs_config.export().to_uri(),
        &different_rootfs,
    );
    assert_rootfs_config_mismatched_root_image(ScenarioDefForm::from_compact_binary(
        &rootfs_mismatch_bytes,
    ));
    Ok(())
}

fn form_with_cmdline(cmdline: &str) -> Result<ScenarioDefForm, EngineError> {
    form_from_world(World::from_nodes(vec![world_node(
        "client", cmdline, None,
    )])?)
}

fn form_with_config_tree(
    config: &GuestWorkloadConfigTreeRef,
) -> Result<ScenarioDefForm, EngineError> {
    form_from_world(world_with_config_tree(config)?)
}

fn world_with_config_tree(config: &GuestWorkloadConfigTreeRef) -> Result<World, EngineError> {
    let cmdline =
        config.selected_cmdline(&GuestWorkloadBinary::Benchmark.selected_cmdline("console=ttyS0"));
    let root_image = if config.delivery() == GuestWorkloadConfigTreeDelivery::ReadOnlyRootfs {
        Some(config.export())
    } else {
        None
    };
    World::from_nodes(vec![world_node("client", cmdline, root_image)])
}

fn scenario_def_with_template(
    template: NodeTemplate,
) -> Result<crucible::ScenarioDef, EngineError> {
    crucible::ScenarioBuilder::new()
        .node("client", template)
        .seed(Seed::from_u64(7))
        .build()
}

fn form_from_world(world: World) -> Result<ScenarioDefForm, EngineError> {
    ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(7),
        10,
    )
}

fn assert_individually_reproducible(form: &ScenarioDefForm) -> Result<(), EngineError> {
    let toml = ScenarioDefForm::from_canonical_toml(&form.to_canonical_toml()?)?;
    let binary = ScenarioDefForm::from_compact_binary(&form.to_compact_binary())?;
    assert_eq!(form.id(), toml.id());
    assert_eq!(form.id(), binary.id());
    assert_eq!(form.canonical_bytes(), toml.canonical_bytes());
    assert_eq!(form.canonical_bytes(), binary.canonical_bytes());
    assert_eq!(
        form.world().canonical_bytes(),
        toml.world().canonical_bytes()
    );
    assert_eq!(
        form.world().canonical_bytes(),
        binary.world().canonical_bytes()
    );

    let artifact = ReproductionArtifact::capture(form, &Schedule::empty())?;
    let replay = artifact.replay()?;
    assert_eq!(replay.scenario, form.id());
    assert_eq!(artifact.scenario_form().id(), form.id());
    assert_eq!(artifact.seed(), form.seed());
    Ok(())
}

fn world_node(
    name: &str,
    cmdline: impl Into<String>,
    root_image: Option<ContentAddressedBlobRef>,
) -> WorldNode {
    WorldNode {
        id: NodeId {
            name: name.to_owned(),
        },
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: cmdline.into(),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image,
        initrd: None,
    }
}

fn only_node(nodes: &[WorldNode]) -> &WorldNode {
    assert_eq!(nodes.len(), 1);
    &nodes[0]
}

fn blob(material: &str) -> ContentAddressedBlobRef {
    ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
        "crucible.test.workload-config-tree",
        material,
    ))
}

fn replace_once(haystack: String, needle: &str, replacement: &str) -> String {
    let offset = haystack
        .find(needle)
        .unwrap_or_else(|| panic!("test fixture should contain {needle}"));
    let mut replaced = haystack;
    replaced.replace_range(offset..offset + needle.len(), replacement);
    replaced
}

fn replace_ascii_once(mut haystack: Vec<u8>, needle: &str, replacement: &str) -> Vec<u8> {
    assert_eq!(
        needle.len(),
        replacement.len(),
        "binary fixture replacement must preserve string length"
    );
    let offset = haystack
        .windows(needle.len())
        .position(|window| window == needle.as_bytes())
        .unwrap_or_else(|| panic!("binary fixture should contain {needle}"));
    haystack[offset..offset + needle.len()].copy_from_slice(replacement.as_bytes());
    haystack
}

fn assert_invalid_scalar_value<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorkloadParameterInvalidValue { .. }) => {}
        other => panic!("expected invalid scalar parameter value, got {other:?}"),
    }
}

fn assert_invalid_config_mount<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorkloadConfigTreeInvalidMount { .. }) => {}
        other => panic!("expected invalid workload config-tree mount, got {other:?}"),
    }
}

fn assert_duplicate_scalar_parameter<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeDuplicateWorkloadParameter { .. }) => {}
        other => panic!("expected duplicate workload scalar parameter, got {other:?}"),
    }
}

fn assert_invalid_world_scalar_value<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeInvalidWorkloadParameterValue { .. }) => {}
        other => panic!("expected invalid world scalar parameter value, got {other:?}"),
    }
}

fn assert_unsupported_config_tree<T: std::fmt::Debug>(
    result: Result<T, EngineError>,
    expected_value_fragment: &str,
) {
    match result {
        Err(EngineError::WorldNodeUnsupportedWorkloadConfigTree { value, .. }) => {
            assert!(value.contains(expected_value_fragment), "{value}");
        }
        other => panic!("expected unsupported workload config tree, got {other:?}"),
    }
}

fn assert_duplicate_config_tree<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeDuplicateWorkloadConfigTree { .. }) => {}
        other => panic!("expected duplicate workload config tree, got {other:?}"),
    }
}

fn assert_rootfs_config_missing_root_image<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeWorkloadConfigTreeRootfsMissingRootImage { .. }) => {}
        other => panic!("expected rootfs config tree missing root image, got {other:?}"),
    }
}

fn assert_rootfs_config_mismatched_root_image<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeWorkloadConfigTreeRootfsMismatchedRootImage { .. }) => {}
        other => panic!("expected rootfs config tree mismatched root image, got {other:?}"),
    }
}
