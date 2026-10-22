//! Compare-and-swap behavior of static-object conditional writes.
//!
//! The filesystem tests run everywhere. The S3 and SFTP variants run the
//! same scenario against disposable remotes when the backend-matrix
//! environment variables are set (see `backend_matrix.rs`), and are ignored
//! otherwise.

use std::path::{Path, PathBuf};

use aos_nix_cache::backend::{
    ConditionalOutcome, ConditionalWriteUnsupported, Expectation, MUTABLE_CACHE_CONTROL,
    ObjectVersion,
};
use aos_nix_cache::{AuthOptions, CacheBackend, from_url};

const FIRST: &[u8] = b"{\"generation\":1}\n";
const SECOND: &[u8] = b"{\"generation\":2}\n";
const RECORD_LIMIT: usize = 4096;

/// Writes both record versions into a scratch directory.
fn record_sources(scratch: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    let first = scratch.join("first.json");
    let second = scratch.join("second.json");
    std::fs::write(&first, FIRST)?;
    std::fs::write(&second, SECOND)?;
    Ok((first, second))
}

async fn put(
    backend: &dyn CacheBackend,
    path: &str,
    source: &Path,
    expect: Expectation,
) -> anyhow::Result<ConditionalOutcome> {
    backend
        .put_static_file_conditional(
            path,
            source,
            Some("application/json"),
            Some(MUTABLE_CACHE_CONTROL),
            expect,
        )
        .await
}

fn written(outcome: ConditionalOutcome) -> ObjectVersion {
    match outcome {
        ConditionalOutcome::Written(version) => version,
        other => panic!("expected a committed write, got {other:?}"),
    }
}

fn refused(current: &ObjectVersion) -> ConditionalOutcome {
    ConditionalOutcome::PreconditionFailed {
        current: Some(current.clone()),
    }
}

/// Runs the create / refuse / advance / refuse sequence against `url`.
async fn compare_and_swap_round_trip(url: &str, path: &str) -> anyhow::Result<()> {
    let backend = from_url(url, &AuthOptions::default()).await?;
    let backend = backend.as_ref();
    let scratch = tempfile::tempdir()?;
    let (first, second) = record_sources(scratch.path())?;

    assert_eq!(backend.get_static_object(path, RECORD_LIMIT).await?, None);

    let first_version = written(put(backend, path, &first, Expectation::Absent).await?);
    assert_eq!(
        put(backend, path, &second, Expectation::Absent).await?,
        refused(&first_version),
    );
    assert_eq!(
        backend.get_static_object(path, RECORD_LIMIT).await?,
        Some((FIRST.to_vec(), first_version.clone())),
    );

    let stale = Expectation::Version(ObjectVersion("stale".to_string()));
    assert_eq!(
        put(backend, path, &second, stale).await?,
        refused(&first_version),
    );

    let current = Expectation::Version(first_version.clone());
    let second_version = written(put(backend, path, &second, current).await?);
    assert_ne!(second_version, first_version);

    let superseded = Expectation::Version(first_version);
    assert_eq!(
        put(backend, path, &first, superseded).await?,
        refused(&second_version),
    );
    assert_eq!(
        backend.get_static_object(path, RECORD_LIMIT).await?,
        Some((SECOND.to_vec(), second_version)),
    );

    Ok(())
}

/// Returns a path unique to this run, so remote tests never collide with
/// earlier runs' records. A local temporary directory supplies the random
/// component.
fn unique_remote_path() -> anyhow::Result<String> {
    let scratch = tempfile::tempdir()?;
    let unique = scratch
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("temporary directory name is not UTF-8"))?;
    Ok(format!("aos-conditional-test/{unique}/generation"))
}

#[tokio::test]
async fn file_backend_compares_and_swaps_generation_records() -> anyhow::Result<()> {
    let origin = tempfile::tempdir()?;
    let url = format!("file://{}", origin.path().display());

    compare_and_swap_round_trip(&url, "channels/edge/generation").await?;

    // Neither lock files nor temporaries survive the writes.
    let mut names = std::fs::read_dir(origin.path().join("channels/edge"))?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<anyhow::Result<Vec<_>>>()?;
    names.sort();
    assert_eq!(names, ["generation"]);

    Ok(())
}

#[tokio::test]
async fn file_backend_versions_are_content_sha256() -> anyhow::Result<()> {
    let origin = tempfile::tempdir()?;
    let url = format!("file://{}", origin.path().display());
    let backend = from_url(&url, &AuthOptions::default()).await?;
    let scratch = tempfile::tempdir()?;
    let (first, _) = record_sources(scratch.path())?;

    let version = written(put(backend.as_ref(), "generation", &first, Expectation::Absent).await?);

    assert_eq!(
        version.as_str(),
        aos_transfer::protocol::conditional::content_version(FIRST)
    );
    Ok(())
}

#[tokio::test]
async fn file_backend_refuses_oversized_and_unnormalized_reads() -> anyhow::Result<()> {
    let origin = tempfile::tempdir()?;
    std::fs::write(origin.path().join("generation"), FIRST)?;
    let url = format!("file://{}", origin.path().display());
    let backend = from_url(&url, &AuthOptions::default()).await?;

    let oversized = backend
        .get_static_object("generation", FIRST.len() - 1)
        .await;
    let escaping = backend
        .get_static_object("../generation", RECORD_LIMIT)
        .await;
    let absolute = backend.get_static_object("/generation", RECORD_LIMIT).await;

    assert!(oversized.is_err());
    assert!(escaping.is_err());
    assert!(absolute.is_err());
    Ok(())
}

#[tokio::test]
async fn http_backend_reports_conditional_writes_unsupported() -> anyhow::Result<()> {
    let backend = from_url("http://127.0.0.1:9/cache", &AuthOptions::default()).await?;
    let scratch = tempfile::tempdir()?;
    let (first, _) = record_sources(scratch.path())?;

    let read = backend
        .get_static_object("generation", RECORD_LIMIT)
        .await
        .unwrap_err();
    let write = put(backend.as_ref(), "generation", &first, Expectation::Absent)
        .await
        .unwrap_err();

    assert!(read.downcast_ref::<ConditionalWriteUnsupported>().is_some());
    assert!(
        write
            .downcast_ref::<ConditionalWriteUnsupported>()
            .is_some()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires AOS_CACHE_TEST_S3_URL and working S3-compatible credentials"]
async fn s3_backend_compares_and_swaps_against_env_url() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("AOS_CACHE_TEST_S3_URL") else {
        eprintln!("AOS_CACHE_TEST_S3_URL not set; skipping ignored S3 conditional-write test");
        return Ok(());
    };
    compare_and_swap_round_trip(&url, &unique_remote_path()?).await
}

#[tokio::test]
#[ignore = "requires AOS_CACHE_TEST_SFTP_URL and working SFTP credentials"]
async fn sftp_backend_compares_and_swaps_against_env_url() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("AOS_CACHE_TEST_SFTP_URL") else {
        eprintln!("AOS_CACHE_TEST_SFTP_URL not set; skipping ignored SFTP conditional-write test");
        return Ok(());
    };
    compare_and_swap_round_trip(&url, &unique_remote_path()?).await
}
