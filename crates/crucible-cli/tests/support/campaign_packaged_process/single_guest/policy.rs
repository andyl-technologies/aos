//! Actual public policy compilation for the retained single-guest continuation.
//!
//! This host control imports a modeled scenario without starting a QEMU executor.
//! It checks the shared flight helper's compiled policy and active campaign head.

use super::*;

#[test]
fn materialization_policy_declares_the_selected_continuation_stop() -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    let node = WorldNode {
        id: NodeId {
            name: "single".into(),
        },
        arch: VmArchitecture::X86_64,
        memory_mib: 128,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    };
    let world = World::from_nodes_and_links(vec![node], Vec::new())?;
    let graph = EventGraph::builder()
        .event("single.complete")
        .entrypoint()
        .when(Predicate::once(Predicate::guest_marker(
            MarkerId::from_name(COMPLETION_MARKER),
        )))
        .action(Action::Pass)
        .build_for_world(&world)?;
    let plan = Plan::from_event_graph_for_world(&world, graph)?;
    let scenario =
        ScenarioDefForm::from_components(&world, &plan, &Properties::empty(), Seed::from_u64(103))?;
    let input = fixture._temporary.path().join("host-policy.scenario.toml");
    fs::write(&input, scenario.to_canonical_toml()?)?;
    let compiled = run_json(
        command(&["--format", "jsonl", "campaign", "scenario", "compile"])
            .arg(&input)
            .arg("--output")
            .arg(&fixture.fixture),
        "compile host policy scenario",
    )?;

    guest_choice::create_guest_choice_campaign_with_timeout(
        &fixture,
        &compiled,
        "host-policy-control-no-qemu",
        Some(VIRTUAL_BUDGET_PS),
        &MATERIALIZATION_STOP_CONDITIONS,
    )?;
    let input_policy =
        fs::read_to_string(fixture._temporary.path().join("guest-choice-policy.toml"))?;
    let policy = CampaignPolicy::from_canonical_bytes(&fs::read(
        fixture._temporary.path().join("guest-choice-policy.bin"),
    )?)?;
    assert!(
        policy.stop_conditions().contains(COMPLETION_MARKER),
        "actual compiled policy omitted the continuation stop; input={input_policy}"
    );
    assert_eq!(
        policy.stop_conditions(),
        &BTreeSet::from(["scenario-complete".to_owned(), COMPLETION_MARKER.to_owned(),])
    );

    let mut service = fixture.start_service(None)?;
    let head = campaign_status(&fixture)?;
    assert_eq!(json_string(&head, "policy")?, policy.id()?.to_string());
    service.stop()?;
    Ok(())
}
