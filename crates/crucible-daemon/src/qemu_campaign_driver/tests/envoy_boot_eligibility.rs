//! Exact quiet Envoy fixture admission and changed-input refusals.
//!
//! The shared canonical text fixture comes from the CLI author. Its companion
//! CLI contract regenerates the complete eligibility input, avoiding a second
//! topology author in these driver tests.

use super::super::envoy_boot::envoy_choice_free_boot_eligible;
use super::*;
use crucible::{LinkDef, LinkLossProbability, SimDuration, VmArchitecture};

type LaunchInputChange = (&'static str, fn(&mut WorldNode));

fn authored_fixture() -> ScenarioDefForm {
    ScenarioDefForm::from_canonical_toml(include_str!("fixtures/worked-network-quiet.toml"))
        .expect("CLI-authored quiet Envoy fixture")
}

fn replace_world(base: &ScenarioDefForm, world: &World) -> ScenarioDefForm {
    ScenarioDefForm::from_components(world, base.plan(), base.properties(), base.seed())
        .expect("valid replacement world")
        .with_selectables(base.selectables().clone())
        .expect("unchanged selectable catalog")
}

fn replace_nodes(base: &ScenarioDefForm, change: fn(&mut WorldNode)) -> ScenarioDefForm {
    let mut nodes: Vec<_> = base.world().vm_nodes().iter().cloned().collect();
    change(&mut nodes[0]);
    let world = World::from_nodes_and_links(nodes, base.world().links().to_vec())
        .expect("valid changed launch inputs")
        .with_fault_topology(base.world().fault_topology().clone())
        .expect("unchanged fault topology");
    replace_world(base, &world)
}

#[test]
fn generated_quiet_envoy_fixture_is_eligible() {
    let scenario = authored_fixture();
    assert_eq!(scenario.world().vm_nodes().len(), 5);
    assert!(envoy_choice_free_boot_eligible(&input_for_scenario(
        scenario,
        StopCondition::NextChoice,
    )));
}

#[test]
fn generated_quiet_envoy_fixture_refuses_changed_launch_inputs() {
    let scenario = authored_fixture();
    let changes: [LaunchInputChange; 9] = [
        ("obsolete nonquiet command line", |vm| {
            vm.cmdline = vm.cmdline.replace(" quiet loglevel=4", "");
        }),
        ("extra command line argument", |vm| {
            vm.cmdline.push_str(" extra=1")
        }),
        ("different role token", |vm| {
            vm.cmdline = vm
                .cmdline
                .replace("network.role=router-a", "network.role=router-b");
        }),
        ("different architecture", |vm| {
            vm.arch = VmArchitecture::Aarch64
        }),
        ("different memory", |vm| vm.memory_mib = 256),
        ("different ready point", |vm| {
            vm.ready_point = ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            };
        }),
        ("missing kernel", |vm| vm.kernel = None),
        ("missing root image", |vm| vm.root_image = None),
        ("different processor count", |vm| vm.smp_vcpus = 2),
    ];

    for (reason, change) in changes {
        let changed = replace_nodes(&scenario, change);
        assert!(
            !envoy_choice_free_boot_eligible(&input_for_scenario(
                changed,
                StopCondition::NextChoice
            )),
            "accepted {reason}",
        );
    }
}

#[test]
fn generated_quiet_envoy_fixture_requires_choice_seed_catalog_and_transport() {
    let scenario = authored_fixture();
    assert!(!envoy_choice_free_boot_eligible(&input_for_scenario(
        scenario.clone(),
        StopCondition::Terminal,
    )));
    let different_seed = ScenarioDefForm::from_components(
        scenario.world(),
        scenario.plan(),
        scenario.properties(),
        Seed::from_u64(1),
    )
    .expect("valid different seed")
    .with_selectables(scenario.selectables().clone())
    .expect("valid catalog");
    assert!(!envoy_choice_free_boot_eligible(&input_for_scenario(
        different_seed,
        StopCondition::NextChoice,
    )));
    let without_catalog = scenario
        .with_selectables(ScenarioSelectables::empty())
        .expect("empty selectable catalog");
    assert!(!envoy_choice_free_boot_eligible(&input_for_scenario(
        without_catalog,
        StopCondition::NextChoice,
    )));

    let mut links = scenario.world().links().to_vec();
    let (left, right) = links[0].endpoints();
    links[0] = LinkDef::with_transport(
        left.clone(),
        right.clone(),
        SimDuration::from_nanoseconds(1_000_000).expect("different positive latency"),
        SimDuration::from_nanoseconds(100_000).expect("original jitter"),
        LinkLossProbability::ZERO,
        Some(10_000_000_000),
    )
    .expect("valid changed transport");
    let world =
        World::from_nodes_and_links(scenario.world().vm_nodes().iter().cloned().collect(), links)
            .expect("valid world")
            .with_fault_topology(scenario.world().fault_topology().clone())
            .expect("unchanged fault topology");
    assert!(!envoy_choice_free_boot_eligible(&input_for_scenario(
        replace_world(&scenario, &world),
        StopCondition::NextChoice,
    )));
}
