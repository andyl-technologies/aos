//! Independent component identities and reuse across scenario definitions.

use super::*;

#[test]
fn spatial_components_have_independent_content_addresses_and_cross_reuse()
-> Result<(), Box<dyn std::error::Error>> {
    let world = world_from_nodes(two_ready_nodes());
    let mut other_nodes = two_ready_nodes();
    other_nodes[0].memory_mib += 128;
    let other_world = world_from_nodes(other_nodes);
    let plan = Plan::from_event_graph_for_world(
        &world,
        EventGraph::new_for_world(
            vec![Event::once(
                EventId::from_name("start-a"),
                None,
                Action::start_node(node_id("a")),
            )],
            &world,
        )?,
    )?;
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("a-started"),
            message: String::from("a remains started"),
            property: Property::Always {
                predicate: Predicate::node_state(node_id("a"), NodeLifecycle::Started),
            },
        }],
    )?;

    assert_eq!(
        world.id(),
        ContentHash::from_canonical_material(
            "crucible.model.world.v6",
            std::str::from_utf8(&world.canonical_bytes())?,
        )
    );
    assert_eq!(
        plan.content_hash(),
        ContentHash::from_canonical_material(
            "crucible.model.plan.v6",
            std::str::from_utf8(&plan.canonical_bytes())?,
        )
    );
    assert_eq!(
        properties.content_hash(),
        ContentHash::from_canonical_material(
            "crucible.model.properties.v2",
            std::str::from_utf8(&properties.canonical_bytes())?,
        )
    );

    let plan_reused = Plan::from_event_graph_for_world(&other_world, plan.event_graph().clone())?;
    let properties_reused =
        Properties::from_assertions_for_world(&other_world, properties.assertions().to_vec())?;
    let reused_world_form = world.scenario_def_with_plan_and_properties(&plan, &properties)?;
    let reused_plan_properties_form =
        other_world.scenario_def_with_plan_and_properties(&plan_reused, &properties_reused)?;

    assert_ne!(world.id(), other_world.id());
    assert_eq!(plan.content_hash(), plan_reused.content_hash());
    assert_eq!(properties.content_hash(), properties_reused.content_hash());
    assert_ne!(reused_world_form.id(), reused_plan_properties_form.id());

    let changed_plan = Plan::empty();
    let changed_plan_form =
        world.scenario_def_with_plan_and_properties(&changed_plan, &properties)?;
    let changed_properties = Properties::empty();
    let changed_properties_form =
        world.scenario_def_with_plan_and_properties(&plan, &changed_properties)?;

    assert_ne!(plan.content_hash(), changed_plan.content_hash());
    assert_ne!(properties.content_hash(), changed_properties.content_hash());
    assert_ne!(reused_world_form.id(), changed_plan_form.id());
    assert_ne!(reused_world_form.id(), changed_properties_form.id());
    assert_eq!(
        world.scenario_def_with_plan_and_properties(&plan, &properties)?,
        reused_world_form,
    );

    Ok(())
}

fn spatial_fixture() -> Result<(World, Plan, Properties), Box<dyn std::error::Error>> {
    let mut nodes = two_ready_nodes();
    nodes[1].ready_point = nodes[0].ready_point.clone();
    for node in &mut nodes {
        node.kernel = Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
            b"kernel",
        )));
        node.root_image = Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
            b"root",
        )));
        node.initrd = Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
            b"initrd",
        )));
    }
    let world = world_from_nodes_and_links(
        nodes,
        vec![transport_link("a", "b", 10, 1, 0, Some(1_000_000))],
    );
    let plan = Plan::from_event_graph_for_world(
        &world,
        EventGraph::new_for_world(
            vec![Event::once(
                EventId::from_name("start-a"),
                None,
                Action::start_node(node_id("a")),
            )],
            &world,
        )?,
    )?;
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("a-started"),
            message: String::from("a remains started"),
            property: Property::Always {
                predicate: Predicate::node_state(node_id("a"), NodeLifecycle::Started),
            },
        }],
    )?;

    Ok((world, plan, properties))
}

#[test]
fn scenario_def_form_is_immutable_pure_four_tuple_value() -> Result<(), Box<dyn std::error::Error>>
{
    let (world, plan, properties) = spatial_fixture()?;
    let seed = Seed::from_u64(41);
    let form = ScenarioDefForm::from_components(&world, &plan, &properties, seed)?;

    assert_eq!(form.world(), &world);
    assert_eq!(form.plan(), &plan);
    assert_eq!(form.properties(), &properties);
    assert_eq!(form.seed(), seed);
    assert_eq!(form.id(), form.scenario_def().id());
    assert_eq!(
        form,
        ScenarioDefForm::from_components(&world, &plan, &properties, seed)?,
    );
    assert_ne!(
        form.id(),
        ScenarioDefForm::from_components(&world, &plan, &properties, Seed::from_u64(42))?.id(),
    );
    assert!(matches!(
        ContentAddressedBlobRef::parse("kernel", "/nix/store/not-a-content-ref"),
        Err(EngineError::ScenarioImageReferenceNotContentAddressed { field, .. })
            if field == "kernel"
    ));

    Ok(())
}

#[test]
fn scenario_layers_stay_structurally_orthogonal() -> Result<(), Box<dyn std::error::Error>> {
    let (world, plan, properties) = spatial_fixture()?;
    let form = ScenarioDefForm::from_components(&world, &plan, &properties, Seed::from_u64(41))?;
    let toml = form.to_canonical_toml()?;
    let value: toml::Value = toml::from_str(&toml)?;

    let world_layer = value["world"]
        .as_table()
        .unwrap_or_else(|| panic!("world layer must be a TOML table"));
    let plan_layer = value["plan"]
        .as_table()
        .unwrap_or_else(|| panic!("plan layer must be a TOML table"));
    let properties_layer = value["properties"]
        .as_table()
        .unwrap_or_else(|| panic!("properties layer must be a TOML table"));
    assert!(world_layer.contains_key("link"));
    assert!(plan_layer.contains_key("event"));
    assert!(properties_layer.contains_key("assertion"));
    assert!(!world_layer.contains_key("event"));
    assert!(!world_layer.contains_key("assertion"));
    assert!(!plan_layer.contains_key("node"));
    assert!(!properties_layer.contains_key("link"));
    assert!(toml.contains("seed = \"0x"));
    assert!(!toml.contains("boot_event"));
    assert!(!toml.contains("entrypoint"));
    assert_eq!(ScenarioDefForm::from_canonical_toml(&toml)?, form);

    Ok(())
}

#[test]
fn scenario_builder_keeps_authoring_layers_structurally_orthogonal()
-> Result<(), Box<dyn std::error::Error>> {
    let (manual_world, plan, properties) = spatial_fixture()?;
    let manual_world = World::from_nodes_and_links(
        manual_world.vm_nodes().to_vec(),
        vec![LinkDef::new(node_id("a"), node_id("b"))?],
    )?;
    let seed = Seed::from_u64(41);
    let authored = ScenarioBuilder::new()
        .node(
            "a",
            NodeTemplate::from_world_node(
                manual_world
                    .vm_nodes()
                    .first()
                    .ok_or("fixture node a missing")?,
            ),
        )
        .node_like("b", "a")
        .link("a", "b")
        .plan(plan.clone())
        .properties(properties.clone())
        .seed(seed)
        .build()?;
    let reused = ScenarioBuilder::new()
        .world(&manual_world)
        .plan(plan.clone())
        .properties(properties.clone())
        .seed(seed)
        .build()?;

    assert_eq!(authored, reused);
    assert_eq!(
        reused,
        ScenarioDefForm::from_components(&manual_world, &plan, &properties, seed)?.scenario_def(),
    );
    let wrong_properties = Properties::from_assertions_for_world(
        &manual_world,
        vec![AssertionDef {
            id: AssertionId::from_name("missing-node"),
            message: String::from("invalid property"),
            property: Property::Always {
                predicate: Predicate::node_state(node_id("undeclared"), NodeLifecycle::Started),
            },
        }],
    );
    assert!(matches!(
        wrong_properties,
        Err(EngineError::PropertyPredicateUnknownNode { .. })
    ));
    let incompatible_world = world_from_nodes(vec![
        manual_world
            .vm_nodes()
            .get(1)
            .ok_or("fixture node b missing")?
            .clone(),
    ]);
    assert!(
        ScenarioBuilder::new()
            .world(&incompatible_world)
            .plan(plan)
            .build()
            .is_err()
    );

    Ok(())
}

#[test]
fn properties_content_address_is_orthogonal_and_validated() -> Result<(), Box<dyn std::error::Error>>
{
    let (world, plan, properties) = spatial_fixture()?;
    let mut authored_order = properties.assertions().to_vec();
    let mut second = authored_order[0].clone();
    second.id = AssertionId::from_name("second");
    authored_order.push(second);
    let properties = Properties::from_assertions_for_world(&world, authored_order.clone())?;
    authored_order.reverse();
    let same_properties = Properties::from_assertions_for_world(&world, authored_order)?;

    assert_eq!(properties.assertions(), same_properties.assertions());
    assert_eq!(properties.content_hash(), same_properties.content_hash());
    let incompatible_world = world_from_nodes(vec![
        world
            .vm_nodes()
            .get(1)
            .ok_or("fixture node b missing")?
            .clone(),
    ]);
    assert!(matches!(
        incompatible_world.scenario_def_with_plan_and_properties(&Plan::empty(), &properties),
        Err(EngineError::PropertyPredicateUnknownNode { .. }),
    ));
    assert!(
        incompatible_world
            .scenario_def_with_plan_and_properties(&plan, &Properties::empty())
            .is_err()
    );

    Ok(())
}

#[test]
fn plan_content_address_preserves_declared_event_order() -> Result<(), Box<dyn std::error::Error>> {
    let (world, plan, _) = spatial_fixture()?;
    let mut authored_order = plan.event_graph().events().to_vec();
    authored_order.push(Event::once(
        EventId::from_name("start-b"),
        None,
        Action::start_node(node_id("b")),
    ));
    let plan = Plan::from_event_graph_for_world(
        &world,
        EventGraph::new_for_world(authored_order.clone(), &world)?,
    )?;
    authored_order.reverse();
    let reordered_plan = Plan::from_event_graph_for_world(
        &world,
        EventGraph::new_for_world(authored_order, &world)?,
    )?;

    assert_ne!(plan.canonical_bytes(), reordered_plan.canonical_bytes());
    assert_ne!(plan.content_hash(), reordered_plan.content_hash());
    assert_eq!(
        Plan::from_compact_binary_for_world(&world, &plan.to_compact_binary())?.content_hash(),
        plan.content_hash(),
    );
    let incompatible_world = world_from_nodes(vec![
        world
            .vm_nodes()
            .get(1)
            .ok_or("fixture node b missing")?
            .clone(),
    ]);
    assert!(
        incompatible_world
            .scenario_def_with_plan_and_properties(&plan, &Properties::empty())
            .is_err()
    );

    Ok(())
}

#[test]
fn serializable_scenario_form_round_trips_and_rejects_host_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let (world, plan, properties) = spatial_fixture()?;
    let form = ScenarioDefForm::from_components(&world, &plan, &properties, Seed::from_u64(41))?;
    let toml = form.to_canonical_toml()?;
    let parsed_toml = ScenarioDefForm::from_canonical_toml(&toml)?;
    let binary = form.to_compact_binary();
    let parsed_binary = ScenarioDefForm::from_compact_binary(&binary)?;

    assert_eq!(parsed_toml, form);
    assert_eq!(parsed_binary, form);
    assert_eq!(parsed_binary.canonical_bytes(), form.canonical_bytes());
    assert_eq!(parsed_binary.to_canonical_toml()?, toml);
    let kernel = world
        .vm_nodes()
        .first()
        .ok_or("fixture node a missing")?
        .kernel
        .unwrap_or_else(|| panic!("fixture has a content-addressed kernel"));
    let invalid_path_toml = toml.replacen(&kernel.to_uri(), "/tmp/host-kernel", 1);
    assert!(matches!(
        ScenarioDefForm::from_canonical_toml(&invalid_path_toml),
        Err(EngineError::ScenarioImageReferenceNotContentAddressed { .. }),
    ));
    for (field, reference) in [
        (
            "kernel",
            world
                .vm_nodes()
                .first()
                .ok_or("fixture node a missing")?
                .kernel,
        ),
        (
            "root_image",
            world
                .vm_nodes()
                .first()
                .ok_or("fixture node a missing")?
                .root_image,
        ),
        (
            "initrd",
            world
                .vm_nodes()
                .first()
                .ok_or("fixture node a missing")?
                .initrd,
        ),
    ] {
        assert!(toml.contains(&format!(
            "{field} = \"{}\"",
            reference
                .unwrap_or_else(|| panic!("fixture image reference"))
                .to_uri()
        )));
    }
    let wrong_hash = ContentHash::from_bytes(b"wrong-serialized-id");
    let wrong_id_toml = toml.replacen(&form.id().to_hex(), &wrong_hash.to_hex(), 1);
    assert!(matches!(
        ScenarioDefForm::from_canonical_toml(&wrong_id_toml),
        Err(EngineError::ScenarioSerializedIdMismatch {
            component: "scenario",
            ..
        }),
    ));
    let empty_world = World::from_nodes_and_links(Vec::new(), Vec::new())?;
    let wrong_empty_world_toml = empty_world.to_canonical_toml()?.replacen(
        &empty_world.id().to_hex(),
        &wrong_hash.to_hex(),
        1,
    );
    assert!(matches!(
        World::from_canonical_toml(&wrong_empty_world_toml),
        Err(EngineError::ScenarioSerializedIdMismatch {
            component: "world",
            ..
        }),
    ));

    let mut truncated = binary;
    truncated.pop();
    assert!(ScenarioDefForm::from_compact_binary(&truncated).is_err());

    Ok(())
}

#[test]
fn scenario_family_pins_concrete_validated_instances() -> Result<(), Box<dyn std::error::Error>> {
    let space = FamilySpace::new(
        SeedSpace::explicit(vec![Seed::from_u64(1), Seed::from_u64(2)])?,
        TopologySizeRange::new(2, 3)?,
        vec![TopologyShape::Ring, TopologyShape::Mesh],
    )?;
    let family = ScenarioFamily::new(space, NodeTemplate::fixed_icount(Icount { retired: 24 }));
    let total = family.space().cardinality()?;
    assert_eq!(total, 8);

    for index in 0..total {
        let pinned = family.instantiate_sample(index)?;
        assert_eq!(pinned, family.instantiate(pinned.params())?);
        assert_eq!(pinned.form().seed(), pinned.params().seed);
        assert_eq!(
            pinned.form().world().vm_nodes().len(),
            pinned.params().topology_size as usize
        );
        assert_eq!(pinned.form().plan(), &Plan::empty());
        assert_eq!(
            ScenarioDefForm::from_compact_binary(&pinned.form().to_compact_binary())?,
            *pinned.form(),
        );
        assert_eq!(
            pinned.genesis_configuration().scenario_form(),
            pinned.form()
        );
    }
    assert!(matches!(
        family.instantiate_sample(total),
        Err(EngineError::ScenarioFamilyParameterOutOfSpace { .. })
    ));

    Ok(())
}

#[test]
fn reproduction_artifact_is_self_contained_and_replay_checked()
-> Result<(), Box<dyn std::error::Error>> {
    let (world, plan, properties) = spatial_fixture()?;
    let form = ScenarioDefForm::from_components(&world, &plan, &properties, Seed::from_u64(41))?;
    let schedule = Schedule::empty().appended(Decision::RngDraw(RngDecision {
        stream: RngStreamId::for_node("a"),
        value: 17,
    }));
    let schedule_binary = schedule.to_compact_binary();
    assert_eq!(Schedule::from_compact_binary(&schedule_binary)?, schedule);
    let artifact = ReproductionArtifact::capture(&form, &schedule)?;
    let artifact_bytes = artifact.to_compact_binary();
    assert_eq!(
        ReproductionArtifact::from_compact_binary(&artifact_bytes)?,
        artifact
    );
    assert_eq!(artifact.seed(), artifact.scenario_def().seed());
    let family = ScenarioFamily::new(
        FamilySpace::new(
            SeedSpace::explicit(vec![Seed::from_u64(41)])?,
            TopologySizeRange::new(2, 2)?,
            vec![TopologyShape::Ring],
        )?,
        NodeTemplate::fixed_icount(Icount { retired: 24 }),
    );
    let pinned = family.instantiate_sample(0)?.genesis_configuration();
    let pinned_genesis_artifact =
        ReproductionArtifact::capture(pinned.scenario_form(), &pinned.configuration().schedule)?;
    assert!(pinned_genesis_artifact.schedule().is_empty());
    assert_eq!(
        pinned_genesis_artifact.replay()?.state,
        reduce(
            &pinned.configuration().def,
            &pinned.configuration().schedule
        )?
        .id
    );

    let expected_state = artifact.replay()?.state;
    assert_eq!(
        artifact.verify_replay(expected_state)?.state,
        expected_state
    );
    let wrong_state = ContentHash::from_bytes(b"wrong-state");
    assert!(matches!(
        artifact.verify_replay(wrong_state),
        Err(EngineError::ReproductionArtifactReplayMismatch { .. })
    ));
    let schedule_drift_artifact =
        ReproductionArtifact::from_recorded_parts(form, Schedule::empty());
    assert!(matches!(
        schedule_drift_artifact.verify_replay(expected_state),
        Err(EngineError::ReproductionArtifactReplayMismatch { .. })
    ));

    Ok(())
}

#[test]
fn canonicalization_hashes_meaning_not_authoring_spelling() -> Result<(), Box<dyn std::error::Error>>
{
    let (world, plan, properties) = spatial_fixture()?;
    let mut nodes = world.vm_nodes().to_vec();
    nodes.reverse();
    let reordered = World::from_nodes_and_links(nodes, world.links().to_vec())?;
    assert_eq!(world, reordered);
    assert_eq!(world.canonical_bytes(), reordered.canonical_bytes());

    let form = ScenarioDefForm::from_components(&world, &plan, &properties, Seed::from_u64(41))?;
    let toml = form.to_canonical_toml()?;
    let annotated = format!("# Author comments do not affect meaning\n{toml}\n");
    let parsed = ScenarioDefForm::from_canonical_toml(&annotated)?;
    assert_eq!(parsed.id(), form.id());
    assert_eq!(parsed.canonical_bytes(), form.canonical_bytes());

    Ok(())
}

#[test]
fn scenario_def_form_rejects_well_formedness_matrix_before_hashing()
-> Result<(), Box<dyn std::error::Error>> {
    let (world, plan, properties) = spatial_fixture()?;
    let a = world
        .vm_nodes()
        .first()
        .ok_or("fixture node a missing")?
        .clone();
    assert!(matches!(
        World::from_nodes_and_links(vec![a.clone(), a.clone()], Vec::new()),
        Err(EngineError::DuplicateWorldNodeId { .. }),
    ));
    for (memory_mib, smp_vcpus) in [(0, 1), (512, 0)] {
        let invalid_node = WorldNode {
            memory_mib,
            smp_vcpus,
            ..a.clone()
        };
        assert!(World::from_nodes_and_links(vec![invalid_node], Vec::new()).is_err());
    }
    let invalid_ready = WorldNode {
        ready_point: ReadyPoint::AgentSignal,
        white_box: WhiteBoxPolicy::Disabled,
        ..a.clone()
    };
    assert!(matches!(
        World::from_nodes_and_links(vec![invalid_ready], Vec::new()),
        Err(EngineError::WhiteBoxReadyPointWithoutOptIn { .. })
    ));
    let undeclared_link = transport_link("a", "undeclared", 10, 0, 0, None);
    assert!(matches!(
        World::from_nodes_and_links(vec![a.clone()], vec![undeclared_link]),
        Err(EngineError::WorldLinkUnknownNode { .. })
    ));
    let subfloor_link = LinkDef::with_transport(
        node_id("a"),
        node_id("b"),
        MIN_LINK_LATENCY,
        SimDuration { ticks: 1 },
        LinkLossProbability::ZERO,
        None,
    );
    assert!(matches!(
        subfloor_link,
        Err(EngineError::WorldLinkJitterBelowLatencyFloor { .. })
    ));
    let incompatible_world = world_from_nodes(vec![
        world
            .vm_nodes()
            .get(1)
            .ok_or("fixture node b missing")?
            .clone(),
    ]);
    assert!(
        ScenarioDefForm::from_components(
            &incompatible_world,
            &plan,
            &Properties::empty(),
            Seed::default()
        )
        .is_err()
    );
    assert!(matches!(
        ScenarioDefForm::from_components(
            &incompatible_world,
            &Plan::empty(),
            &properties,
            Seed::default()
        ),
        Err(EngineError::PropertyPredicateUnknownNode { .. })
    ));
    let form = ScenarioDefForm::from_components(&world, &plan, &properties, Seed::default())?;
    let canonical_toml = form.to_canonical_toml()?;
    let removed_clock_setting =
        canonical_toml.replacen("smp_vcpus = 1", "smp_vcpus = 1\nicount_shift = 64", 1);
    assert!(ScenarioDefForm::from_canonical_toml(&removed_clock_setting).is_err());

    let invalid_toml = canonical_toml.replacen("smp_vcpus = 1", "smp_vcpus = 0", 1);
    assert!(matches!(
        ScenarioDefForm::from_canonical_toml(&invalid_toml),
        Err(EngineError::WorldNodeSmpVcpuCountZero { .. })
    ));

    Ok(())
}
