//! Two-VM world whose VMs park together at a network fault phase marker.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use crucible::model::{
    DagStore, FaultDirection, GuestWorkloadBinary, SignalId, WhiteBoxPolicy, WorldFaultDomain,
    WorldFaultTargetRef, WorldFaultTopology, WorldNodeDef,
};
use crucible::{
    AssertionDef, AssertionId, Plan, Properties, ScenarioDefForm, ScenarioSelectableLimits,
    ScenarioSelectables, Seed, World,
};

use super::{guest_quanta_declaration, native_world, signal_id};

/// Builds a two-VM world that parks at a network fault phase marker.
///
/// Both VMs emit the first-phase marker after setup and park there, so the
/// all-VM network fault choice is offered at one joined frontier. After the
/// release, curl requests two guest selections in turn. The VMs keep their
/// interfaces down: with no traffic the parked boundary is quiet, and the
/// selected fault changes only modeled fabric state.
pub(in super::super) fn build_network_fault_anchor(
    fixture: &str,
    artifacts: Arc<dyn DagStore>,
    kernel: &Path,
    root_image: &Path,
) -> Result<(ScenarioDefForm, Arc<dyn DagStore>), Box<dyn Error>> {
    let world = native_world(fixture, kernel, root_image)?;
    let mut nodes = Vec::new();
    for (name, role) in [
        ("curl", "hot-fork-anchor-chooser"),
        ("nginx", "hot-fork-anchor-peer"),
    ] {
        let mut node = world
            .vm_nodes()
            .iter()
            .find(|node| node.id.name == name)
            .cloned()
            .ok_or("representative fixture omits an anchor VM")?;
        node.cmdline =
            GuestWorkloadBinary::Benchmark.selected_cmdline(&format!("console=ttyS0 role={role}"));
        // Phase markers and selections travel through the white-box agent.
        node.white_box = WhiteBoxPolicy::Enabled;
        nodes.push(WorldNodeDef::Vm(node));
    }
    let links = world
        .links()
        .iter()
        .filter(|link| {
            let (a, b) = link.endpoints();
            BTreeSet::from([a.name.as_str(), b.name.as_str()]) == BTreeSet::from(["curl", "nginx"])
        })
        .cloned()
        .collect::<Vec<_>>();
    let world = World::from_node_defs_and_links(nodes, links)?
        .with_fault_topology(anchor_fault_topology(&world)?)?;

    let plan = Plan::empty();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef::guest_sometimes(
            AssertionId::from_name("hot-fork-continuation-complete"),
            "The selected continuation completes",
        )],
    )?;
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::new(4, 8, 16, 32)?,
        vec![
            crucible::NetworkFaultSelectable::declaration()?,
            guest_quanta_declaration()?,
        ],
    )?;
    let source = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(0x000a_7020),
        0,
    )?
    .with_selectables(selectables)?;

    Ok((source, artifacts))
}

/// Keeps the curl-nginx segment, with one fault domain per direction.
fn anchor_fault_topology(world: &World) -> Result<WorldFaultTopology, Box<dyn Error>> {
    let segment = signal_id("curl-nginx-segment")?;
    let primary = signal_id("primary")?;
    let backup = signal_id("backup")?;

    let mut segments = world
        .fault_topology()
        .network_segments
        .iter()
        .filter(|candidate| candidate.id == segment)
        .cloned()
        .collect::<Vec<_>>();
    for kept in &mut segments {
        kept.fault_domains = vec![primary.clone(), backup.clone()];
    }
    let interfaces = world
        .fault_topology()
        .network_interfaces
        .iter()
        .filter(|interface| {
            segments
                .iter()
                .any(|kept| kept.interface_a == interface.id || kept.interface_b == interface.id)
        })
        .cloned()
        .collect();
    let domain = |id: SignalId, direction: FaultDirection| WorldFaultDomain {
        id,
        targets: vec![WorldFaultTargetRef::NetworkSegment {
            segment: segment.clone(),
            direction,
        }],
    };

    Ok(WorldFaultTopology {
        fault_domains: vec![
            domain(primary, FaultDirection::AToB),
            domain(backup, FaultDirection::BToA),
        ],
        network_interfaces: interfaces,
        network_segments: segments,
        ..WorldFaultTopology::default()
    })
}

#[test]
fn network_fault_anchor_world_offers_the_park_choice_and_the_guest_choice() {
    let fixture =
        include_str!("../../../../../../../tests/crucible/fixtures/e2e-determinism.scenario.toml");
    let directory = tempfile::tempdir().expect("create test directory");
    let kernel = directory.path().join("kernel");
    let root_image = directory.path().join("root.ext4");
    std::fs::write(&kernel, b"selected kernel bytes").expect("write selected kernel");
    std::fs::write(&root_image, b"selected root bytes").expect("write selected root image");
    let artifacts: Arc<dyn DagStore> = Arc::new(crucible::model::MemoryDagStore::new());

    let (scenario, _artifacts) =
        build_network_fault_anchor(fixture, artifacts, &kernel, &root_image)
            .expect("build the anchor scenario");

    let world = scenario.world();
    let vms = world
        .vm_nodes()
        .iter()
        .map(|node| (node.id.name.as_str(), node.white_box))
        .collect::<Vec<_>>();
    assert_eq!(
        vms,
        [
            ("curl", WhiteBoxPolicy::Enabled),
            ("nginx", WhiteBoxPolicy::Enabled)
        ]
    );
    assert_eq!(world.io_nodes().count(), 0);
    assert_eq!(world.links().len(), 1);
    assert!(
        scenario
            .selectables()
            .declaration("hot-fork.retry-quanta")
            .is_some()
    );

    // The park offers the network choice, and its selected branch resolves
    // against the kept segment's fault domains.
    let park = crucible::Configuration::genesis(scenario.scenario_def());
    let selectable = crucible::NetworkFaultSelectable::next(
        &scenario,
        &park,
        crucible::NetworkFaultPhase::First,
        crucible::VirtualTime { ticks: 1 },
        &[],
    )
    .expect("network choice resolves")
    .expect("network choice is offered");
    for path in ["primary", "backup", "both"] {
        let value =
            crucible::NetworkFaultSelectable::selected_value("link_down", path, 1_000, 0, 0)
                .expect("network fault value");
        let branch = selectable
            .resolve_branch(
                &selectable
                    .branch_selection(value)
                    .expect("branch selection"),
            )
            .expect("network fault branch");
        crucible::NetworkFaultCampaignReplayPlan::new(branch.selected().clone(), vec![branch])
            .expect("network replay plan")
            .validate_topology(world.fault_topology())
            .expect("the selected path names a kept fault domain");
    }
}
