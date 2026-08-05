//! Canonical scenario fixture for process-level live-QEMU search.

use crucible::{
    ContentAddressedBlobRef, ContentHash, EngineError, LinkDef, LinkLossProbability, NodeId, Plan,
    Properties, ReadyPoint, ScenarioDefForm, Seed, SimDuration, VmArchitecture, WhiteBoxPolicy,
    World, WorldNode,
};

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn asset(name: &str) -> ContentAddressedBlobRef {
    ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
        "crucible.live-qemu-search-fixture.asset.v1",
        name,
    ))
}

fn live_qemu_search_scenario() -> Result<ScenarioDefForm, EngineError> {
    let kernel = asset("stock-linux-kernel");
    let root_image = asset("minimal-root-fixture");
    let initrd = asset("certified-network-initramfs");
    let nodes = ["client", "server"]
        .into_iter()
        .map(|name| WorldNode {
            id: node(name),
            arch: VmArchitecture::X86_64,
            memory_mib: 256,
            cmdline: String::from("console=ttyS0 quiet net.ifnames=0"),
            ready_point: ReadyPoint::FixedIcount {
                icount: crucible::Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            icount_shift: 0,
            kernel: Some(kernel),
            root_image: Some(root_image),
            initrd: Some(initrd),
        })
        .collect();
    let link = LinkDef::with_transport(
        node("client"),
        node("server"),
        SimDuration {
            nanos: 3_999_000_000,
        },
        SimDuration { nanos: 0 },
        LinkLossProbability::from_millionths(250_000)?,
        None,
    )?;
    let world = World::from_nodes_and_links(nodes, vec![link])?;
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(42),
    )
}

#[test]
fn live_qemu_search_fixture_is_canonical() -> Result<(), EngineError> {
    let canonical = live_qemu_search_scenario()?.to_canonical_toml()?;
    assert_eq!(
        canonical,
        include_str!("../../../tests/crucible/fixtures/live-qemu-search.scenario.toml")
    );
    assert!(canonical.contains("initrd = "));
    assert!(canonical.contains("loss_millionths = 250000"));
    Ok(())
}

#[test]
fn nginx_fixture_is_canonical() -> Result<(), EngineError> {
    let text = include_str!("../../../tests/crucible/fixtures/nginx-curl-http-200.scenario.toml");
    let scenario = ScenarioDefForm::from_canonical_toml(text)?;
    assert_eq!(scenario.to_canonical_toml()?, text);
    Ok(())
}
