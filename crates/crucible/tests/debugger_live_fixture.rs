//! Canonical white-box scenarios for live debugger acceptance.

#![forbid(unsafe_code)]

use crucible::{
    ContentAddressedBlobRef, ContentHash, EngineError, Icount, NodeId, Plan, Properties,
    ReadyPoint, ScenarioDefForm, Seed, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn asset(name: &str) -> ContentAddressedBlobRef {
    ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
        "crucible.debugger-live-fixture.asset.v1",
        name,
    ))
}

fn debugger_live_scenario(architecture: VmArchitecture) -> Result<ScenarioDefForm, EngineError> {
    let node = WorldNode {
        id: NodeId {
            name: String::from("debuggee"),
        },
        arch: architecture,
        memory_mib: 256,
        cmdline: String::from("quiet"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        icount_shift: 0,
        kernel: Some(asset("linux-kernel")),
        root_image: Some(asset("debug-agent-root-image")),
        initrd: None,
    };
    let world = World::from_nodes(vec![node])?;

    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(0xd06),
    )
}

#[test]
fn live_debugger_fixtures_are_canonical() -> Result<(), EngineError> {
    let cases = [
        (
            VmArchitecture::X86_64,
            include_str!("../../../tests/crucible/fixtures/debugger-live-x86_64.scenario.toml"),
        ),
        (
            VmArchitecture::Aarch64,
            include_str!("../../../tests/crucible/fixtures/debugger-live-aarch64.scenario.toml"),
        ),
    ];

    for (architecture, expected) in cases {
        let canonical = debugger_live_scenario(architecture)?.to_canonical_toml()?;
        assert_eq!(canonical, expected, "{architecture:?} fixture drifted");
    }
    Ok(())
}
