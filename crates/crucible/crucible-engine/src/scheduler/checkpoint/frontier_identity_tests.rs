//! Preserves recorded scheduler-frontier identities across streaming encoding.

use super::*;

const DOMAIN: &str = "crucible.production-vm-exact-ram-frontier.v1";

const RECORDED: &[(&str, &str)] = &[
    (
        "native-crash-restart",
        "6fad36a20ae2cf07e9289339be884e47cc76ede5d1f2c2b125c53c28dd6def47",
    ),
    (
        "encoding-unicode-node",
        "3b6bc0bb9cc6c5086f3e6b86022a6f4311dbf1abdea5df7e1336ffe082ae7154",
    ),
    (
        "native-happy-path",
        "5af4d87039d323869132c6af9334f563d96b0ceac682238484796d503a1e5562",
    ),
    (
        "native-partition-recovery",
        "9b22f93fb9c0ca07ece43d05c487d9e4e0b0816e03fff6b070072ceafe3dad94",
    ),
    (
        "encoding-frontier-0",
        "6fad36a20ae2cf07e9289339be884e47cc76ede5d1f2c2b125c53c28dd6def47",
    ),
    (
        "encoding-frontier-23",
        "2b1932b8ca7295b042a387815d8f178fc79d8dabe6ce7987908a3d93c29820e5",
    ),
    (
        "encoding-frontier-24",
        "122aabd025822ec1d27d36f30beaa6fb420563d6bc4dd7d085e7f23a925f3d47",
    ),
    (
        "encoding-frontier-255",
        "d4f6ac3807821d830cf3ebf6de35deecb576a5e72bae13248a3fa6daa47a94a3",
    ),
    (
        "encoding-frontier-256",
        "cce007d46b227bb6424f037de76f1a4e0535831f6de0c1f803a65f48efcb8a6e",
    ),
    (
        "encoding-frontier-65535",
        "61db2ebf03593e467d10263135a3998fc9109c05991e7a04146f5f57c25be90a",
    ),
    (
        "encoding-frontier-65536",
        "4513672ca410a372e541d3e98f34cd79b92b83fa8c40f371521a37ce6bb97c9f",
    ),
    (
        "encoding-frontier-4294967295",
        "787685a24796c33b6417adeb8e340ecc78ef7e42ba47a0c1ac2bcd75624b85ba",
    ),
    (
        "encoding-frontier-4294967296",
        "883a4cd0f3b7c907e023897f7b0e387dd2b9ac0cb80caed916519e1fc5d0fd76",
    ),
    (
        "encoding-frontier-18446744073709551615",
        "87158684be3fb716b641f5a2d0dbce71efdc080c742caae246005f3902c2df5b",
    ),
];

fn original_frontier(
    case: &str,
    checkpoint: &SingleSchedulerCheckpoint,
) -> Result<ContentHash, SingleSchedulerCheckpointError> {
    let bytes = checkpoint.canonical_bytes()?;
    let mut material = String::with_capacity(bytes.len() * 2);
    use std::fmt::Write as _;
    for byte in &bytes {
        write!(material, "{byte:02x}").unwrap();
    }
    let identity = ContentHash::from_canonical_material(DOMAIN, &material);
    assert_eq!(
        identity,
        ContentHash::from_canonical_hex_bytes(DOMAIN, &bytes)
    );
    let recorded = RECORDED.iter().find(|(name, _)| *name == case).unwrap().1;
    assert_eq!(identity.to_hex(), recorded);
    assert_eq!(checkpoint.exact_ram_frontier_identity()?, identity);
    Ok(identity)
}

fn native_checkpoint(
    fixture: crate::ExampleScenarioFixture,
) -> Result<SingleSchedulerCheckpoint, Box<dyn std::error::Error>> {
    let source = fixture.scenario;
    let scenario = SchedulerLivenessScenario::from_runnable_world(
        "frontier-streaming-vectors",
        4,
        SimInstant { ticks: 100 },
        37,
        source.world(),
    )
    .with_scenario_def(source.scenario_def());
    Ok(SingleScheduler::new(scenario)?.checkpoint()?)
}

#[test]
fn streaming_frontier_preserves_recorded_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let _scope = crate::test_support::fixture_decode_scope(16 * 1024 * 1024)?;
    let checkpoint = native_checkpoint(crate::crash_restart_scenario()?)?;
    original_frontier("native-crash-restart", &checkpoint)?;

    let mut unicode = checkpoint.clone();
    unicode.wire.nodes[0].id.node.name = String::from("vm-é水🦀");
    original_frontier("encoding-unicode-node", &unicode)?;

    for (name, fixture) in [
        ("native-happy-path", crate::happy_path_scenario()?),
        (
            "native-partition-recovery",
            crate::partition_recovery_scenario()?,
        ),
    ] {
        original_frontier(name, &native_checkpoint(fixture)?)?;
    }

    // These preserve the actual borrowed wire while exercising CBOR integer
    // widths. They test encoding, not execution authentication of changed cuts.
    for frontier in [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u32::MAX as u64,
        u32::MAX as u64 + 1,
        u64::MAX,
    ] {
        let mut scalar = checkpoint.clone();
        scalar.wire.frontier = frontier;
        original_frontier(&format!("encoding-frontier-{frontier}"), &scalar)?;
    }
    Ok(())
}
