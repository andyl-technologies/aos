//! Test-only portable vulnerability inputs and independent evidence verification.

use std::io::{Read as _, Write as _};

use anyhow::{bail, Context as _, Result};
use aos_assessment::bundle::AssessmentBundleV1;
use aos_assessment::time::Timestamp;
use aos_assessment_http::PhysicalClock;
use aos_assessment_runtime::ports::Clock;

#[path = "../../../aos-assessment/tests/common/mod.rs"]
mod common;

pub(super) fn input(arguments: &[String]) -> Result<()> {
    let [version] = arguments else {
        bail!("usage: assessment-input VERSION");
    };
    let mut data = common::fixture(version)?;
    let now = PhysicalClock.now()?;
    let snapshot = data
        .advisory_snapshot
        .as_mut()
        .context("fixture snapshot")?;
    for source in &mut snapshot.sources {
        source.observation.retrieved_at = now.clone();
        source.observation.validated_at = now.clone();
        source.observation.expires_at = Timestamp::from_unix_seconds(now.unix_seconds() + 86400)?;
    }
    let frozen = data.freeze(vec![aos_assessment::input::Profile::Vulnerabilities], now)?;
    aos_assessment::evaluator::evaluate(&frozen, &data)?;
    std::io::stdout().write_all(&serde_json::to_vec(&data)?)?;
    Ok(())
}

pub(super) fn verify(arguments: &[String]) -> Result<()> {
    let [path] = arguments else {
        bail!("usage: assessment-verify BUNDLE");
    };
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    let bundle = AssessmentBundleV1::from_slice(&bytes)?;
    bundle.verify()?;
    std::io::stdout().write_all(&serde_json::to_vec(&bundle.assessment)?)?;
    Ok(())
}
