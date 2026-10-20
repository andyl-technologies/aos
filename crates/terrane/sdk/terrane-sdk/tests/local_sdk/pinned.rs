//! Checks immutable targets and confined supported filesystem entries.

use super::fixture::{Fixture, MAIN, NEW, OLD, TestResult, fixed, metadata};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use terrane_sdk::surface::View;

#[tokio::test]
async fn sdk_checkout_public_api_pins_ref_and_fixed_commit_across_reopen() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let old = fixture.commit_bytes(OLD).await?;
    let pinned = fixture
        .repository
        .realize(View::parse(MAIN)?, fixture.hints("pinned"))
        .await?;
    assert_eq!(pinned.status().commit, old);
    let fork = fixture
        .repository
        .fork(
            MAIN,
            "refs/heads/_/fork",
            fixture
                .repository
                .source_request(&fixture.authority, metadata("Fork historical fixture")),
        )
        .await?;
    let current = fixture.commit_bytes(NEW).await?;
    assert_ne!(old, current);
    fixture = fixture.reopen().await?;

    let historical = fixture
        .repository
        .realize(fixed(old), fixture.hints("historical"))
        .await?;
    let latest = fixture
        .repository
        .realize(View::parse(MAIN)?, fixture.hints("latest"))
        .await?;
    let forked = fixture
        .repository
        .realize(View::parse("refs/heads/_/fork")?, fixture.hints("forked"))
        .await?;
    assert_eq!(historical.status().commit, old);
    assert_eq!(latest.status().commit, current);
    assert_eq!(forked.status().commit, fork.commit);
    for output in ["pinned", "historical", "forked"] {
        assert_eq!(
            std::fs::read(fixture.parent.join(output).join("file"))?,
            OLD
        );
    }
    assert_eq!(std::fs::read(fixture.parent.join("latest/file"))?, NEW);
    assert_eq!(pinned.status().commit, old);
    Ok(())
}

#[tokio::test]
async fn sdk_checkout_public_api_confines_subtree_and_preserves_supported_entries() -> TestResult {
    let fixture = Fixture::new().await?;
    let source = fixture.parent.join("entries");
    std::fs::create_dir(&source)?;
    std::fs::create_dir(source.join("visible"))?;
    std::fs::create_dir(source.join("visible/nested"))?;
    std::fs::set_permissions(
        source.join("visible/nested"),
        std::fs::Permissions::from_mode(0o750),
    )?;
    std::fs::write(source.join("visible/file"), OLD)?;
    std::fs::set_permissions(
        source.join("visible/file"),
        std::fs::Permissions::from_mode(0o640),
    )?;
    std::fs::hard_link(source.join("visible/file"), source.join("visible/hard"))?;
    symlink("file", source.join("visible/link"))?;
    std::fs::write(source.join("sibling"), b"excluded sibling")?;
    let commit = fixture.commit_directory(&source).await?;

    let serving = fixture
        .repository
        .realize(
            View::parse(&format!("{MAIN}:/visible"))?,
            fixture.hints("scoped"),
        )
        .await?;
    assert_eq!(serving.status().commit, commit);
    let output = fixture.parent.join("scoped");
    let mut names = std::fs::read_dir(&output)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    assert_eq!(
        names,
        ["file", "hard", "link", "nested"].map(std::ffi::OsString::from)
    );
    assert_eq!(std::fs::read(output.join("file"))?, OLD);
    assert_eq!(std::fs::read(output.join("hard"))?, OLD);
    assert_eq!(std::fs::read(output.join("link"))?, OLD);
    assert_eq!(
        std::fs::read_link(output.join("link"))?,
        std::path::Path::new("file")
    );
    let file = std::fs::metadata(output.join("file"))?;
    let hard = std::fs::metadata(output.join("hard"))?;
    assert_eq!((file.dev(), file.ino()), (hard.dev(), hard.ino()));
    assert_eq!(file.mode() & 0o7777, 0o640);
    assert_eq!(
        std::fs::metadata(output.join("nested"))?.mode() & 0o7777,
        0o750
    );
    assert_eq!(std::fs::read_dir(output.join("nested"))?.count(), 0);
    Ok(())
}
