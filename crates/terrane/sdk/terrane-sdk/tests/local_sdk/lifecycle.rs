//! Checks monotonic lifecycle for a completed durable directory snapshot.

use super::fixture::{Fixture, MAIN, OLD, TestResult, inventory};
use std::time::Duration;
use terrane_sdk::surface::{ExposureState, ReaderMode, SchemaState, View};

#[tokio::test]
async fn sdk_checkout_public_api_lifecycle_preserves_completed_directory() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let serving = fixture
        .repository
        .realize(View::parse(MAIN)?, fixture.hints("completed"))
        .await?;
    let status = serving.status();
    assert_eq!(status.commit, commit);
    assert_eq!(status.surface, "sdk");
    assert_eq!(status.reader, ReaderMode::Pinned);
    assert_eq!(status.writer, None);
    assert_eq!(status.realizer, None);
    assert_eq!(status.last_commit, None);
    assert!(status.features.is_empty());
    assert_eq!(status.schema, SchemaState::Valid);
    assert_eq!(status.state, ExposureState::Serving);
    let output = fixture.parent.join("completed");
    assert_eq!(std::fs::read(output.join("file"))?, OLD);
    let original = inventory(&output)?;

    serving.drain(Duration::ZERO)?;
    assert_eq!(serving.status().state, ExposureState::Drained);
    assert_eq!(inventory(&output)?, original);
    serving.stop()?;
    assert_eq!(serving.status().state, ExposureState::Stopped);
    serving.drain(Duration::ZERO)?;
    serving.stop()?;
    let mut expected = status;
    expected.state = ExposureState::Stopped;
    assert_eq!(serving.status(), expected);
    assert_eq!(inventory(&output)?, original);
    Ok(())
}
