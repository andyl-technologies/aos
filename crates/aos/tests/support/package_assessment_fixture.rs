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

pub(super) fn hold_lane(arguments: &[String]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::time::{Duration, Instant};

    let [lock_path, ready_path, release_path] = arguments else {
        bail!("usage: assessment-lane-lock LOCK READY RELEASE");
    };
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lock_path)?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
    let mut ready = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ready_path)?;
    ready.write_all(b"locked")?;
    ready.sync_all()?;
    let started = Instant::now();
    while !std::path::Path::new(release_path).try_exists()? {
        if started.elapsed() >= Duration::from_secs(120) {
            bail!("assessment lane fixture release deadline elapsed");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
