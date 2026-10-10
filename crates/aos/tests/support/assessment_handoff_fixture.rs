//! Test-only independent local discovery and exact clean-source update inputs.

#[path = "../../../aos-assessment/tests/common/mod.rs"]
mod common;

use std::io::{Read as _, Write as _};

use anyhow::{Context as _, Result, ensure};
use aos_assessment::input::Profile;
use aos_assessment_http::PhysicalClock;
use aos_assessment_runtime::ports::Clock;
use aos_contract::Sha256Digest;
use aos_maintain::discovery::{DiscoverySnapshotV1, select_unit};
use aos_maintain::envelope::InventoryEnvelopeV1;

pub(super) fn inventory(arguments: &[String]) -> Result<()> {
    ensure!(arguments.is_empty(), "usage: assessment-handoff-inventory");
    std::io::stdout().write_all(&serde_json::to_vec(
        &common::updates::maintenance_inventory()?,
    )?)?;
    Ok(())
}

pub(super) fn input(arguments: &[String]) -> Result<()> {
    let envelope = envelope(arguments)?;
    let now = PhysicalClock.now()?;
    let mut data = common::updates::data(now.clone())?;
    let source = Sha256Digest::of_canonical("aos.source-content/v1", &envelope.content)?;
    data.inventory.subjects[0].source_content_digest = Some(source);
    data.inventory.components[0].source_content_digest = Some(source);
    data.inventory.subjects[0].component_inventory_digest =
        data.inventory.components[0].digest()?;
    let input = data.freeze(vec![Profile::Updates], now)?;
    aos_assessment::evaluator::evaluate(&input, &data)?;
    std::io::stdout().write_all(&serde_json::to_vec(&data)?)?;
    Ok(())
}

pub(super) fn discovery(arguments: &[String]) -> Result<()> {
    let envelope = envelope(arguments)?;
    let now = PhysicalClock.now()?;
    let data = common::updates::data(now.clone())?;
    let mut observation = data.upstream[0].observation.clone();
    let mut newer = observation.candidates[0].clone();
    newer.raw_id = "v1.4.0".into();
    newer.raw_version = "1.4.0".into();
    observation.candidates.push(newer);
    observation.response_digest = Sha256Digest::of_bytes("independent local discovery fixture");
    let unit = envelope
        .inventory
        .units
        .first()
        .context("fixture local unit")?;
    let units = vec![select_unit(
        unit,
        &std::collections::BTreeMap::from([("main".into(), observation.clone())]),
        now.unix_seconds(),
        86400,
    )?];
    let snapshot = DiscoverySnapshotV1 {
        schema: aos_maintain::DISCOVERY_SNAPSHOT_V1.into(),
        inventory_envelope_digest: Sha256Digest::of_canonical(
            aos_maintain::MAINTENANCE_INVENTORY_ENVELOPE_V1,
            &envelope,
        )?,
        observations: std::collections::BTreeMap::from([(
            "fixture-1/main/primary".into(),
            observation,
        )]),
        units,
        evaluated_at_unix: now.unix_seconds(),
    };
    snapshot.validate()?;
    std::io::stdout().write_all(&serde_json::to_vec(&snapshot)?)?;
    Ok(())
}

fn envelope(arguments: &[String]) -> Result<InventoryEnvelopeV1> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let [path] = arguments else {
        anyhow::bail!("fixture requires one local inventory envelope");
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= 16 * 1024 * 1024,
        "fixture envelope must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "fixture envelope exceeded its read limit"
    );
    let envelope: InventoryEnvelopeV1 = serde_json::from_slice(&bytes)?;
    envelope.validate()?;
    Ok(envelope)
}
