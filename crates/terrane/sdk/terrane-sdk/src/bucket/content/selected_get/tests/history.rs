//! Checks ordinary committed-log DATA from genuine native publications.

use super::*;

/// Checks public initial log data and refuses its late physical replacement.
///
/// # Errors
/// Propagates actual publication, read, closing-pause and filesystem failures.
///
/// # Panics
/// Panics if native fixture setup or proposal construction fails, or if log
/// selection, hard links, returned bytes or physical replacement refusal
/// contradict the fixture assertions.
pub(super) async fn check_public_logs() -> TestResult {
    let native = crate::ref_advance::tests::fixture().await;
    let name = "refs/heads/tenant/main";
    let token = crate::ref_advance::tests::token();
    let mut session = native.begin(name, &token, "sdk").await?;
    let plaintext = b"actual ordinary selected history payload";
    let first = native
        .advance(
            &mut session,
            crate::ref_advance::tests::request_file(Vec::new(), plaintext),
        )
        .await?;
    let second = native
        .advance(
            &mut session,
            crate::ref_advance::tests::request_file(vec![first.commit], plaintext),
        )
        .await?;
    assert_eq!(second.seq, first.seq + 1);

    let bucket = native.store();
    let logs = {
        let holder = SingleHeld::acquire_read_only(bucket).await?;
        let held = holder.source();
        let observed = held.observe_for_read().await?;
        observed
            .physical_reads()
            .iter()
            .filter_map(|read| {
                read.path()
                    .strip_prefix(bucket.root())
                    .ok()
                    .filter(|path| path.starts_with("logs"))
                    .map(|_| read.path().to_path_buf())
            })
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert!(
        logs.len() >= 2,
        "genuine head and predecessor log reads missing"
    );
    for path in &logs {
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).await?;
        tokio::fs::hard_link(path, path.with_extension("ordinary-link")).await?;
        assert_eq!(tokio::fs::symlink_metadata(path).await?.nlink(), 2);
    }
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
    let encoded = raw(plaintext);
    assert_eq!(bucket.get(&identity, None).await?, encoded);
    assert_eq!(
        bucket
            .get(
                &identity,
                Some(ByteRange {
                    start: 1,
                    length: 5
                })
            )
            .await?,
        encoded[1..6]
    );

    let paused = PausedGet::start(bucket, &identity).await?;
    let path = logs.iter().next().ok_or("actual predecessor log absent")?;
    replace_equal(path).await?;
    refused(paused.finish().await?);

    let original = native
        .guard()
        .configured_original_authority()?
        .control()
        .to_owned();
    tokio::fs::remove_dir_all(original).await?;
    tokio::fs::remove_dir_all(control_path(bucket.root())).await?;
    tokio::fs::remove_dir_all(bucket.root()).await?;
    Ok(())
}
