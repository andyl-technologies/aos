//! Exact, crash-recoverable deletion for native filesystem placements.
//!
//! A conditional delete first moves the named object to a deterministic,
//! same-directory quarantine with `RENAME_NOREPLACE`. It then verifies the
//! quarantined inode's frozen ETag, size, and SHA-256 before unlinking it. A
//! crash after the rename is recoverable because a retry derives the same
//! quarantine name. Identity mismatch restores the object with another
//! no-replace rename, so a concurrent replacement is never overwritten or
//! mistaken for the inventoried object.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use anyhow::{bail, Context as _, Result};
use sha2::{Digest as _, Sha256};

use aos_hub_core::surface_write::{self, SurfaceDeleteOutcome, SurfaceDeletePrecondition};

type ObjectLock = tokio::sync::Mutex<()>;

static OBJECT_LOCKS: OnceLock<Mutex<std::collections::BTreeMap<PathBuf, Weak<ObjectLock>>>> =
    OnceLock::new();

/// Locks one resolved object path against native writes and deletes.
pub(crate) async fn lock_object(path: &Path) -> tokio::sync::OwnedMutexGuard<()> {
    let lock = {
        let locks = OBJECT_LOCKS.get_or_init(|| Mutex::new(std::collections::BTreeMap::new()));
        let mut locks = locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(path).and_then(Weak::upgrade) {
            lock
        } else {
            let lock = Arc::new(ObjectLock::new(()));
            locks.insert(path.to_path_buf(), Arc::downgrade(&lock));
            lock
        }
    };
    lock.lock_owned().await
}

/// Deletes the exact inventoried filesystem object or fails closed.
///
/// The storage root and every traversed directory must be owned by the
/// effective user and not writable by group or other users. This is the trust
/// boundary that makes the quarantine name private from external writers;
/// in-process writers additionally participate in [`lock_object`].
///
/// # Errors
///
/// Returns an error for unsafe paths, insecure storage directories, missing
/// identity inputs, I/O failures, or a retained-quarantine conflict. Identity
/// mismatches are represented by [`SurfaceDeleteOutcome::PreconditionFailed`].
pub(crate) async fn delete_if_matches(
    root: &Path,
    path: &str,
    expected: &SurfaceDeletePrecondition,
) -> Result<SurfaceDeleteOutcome> {
    let expected_etag = expected
        .etag
        .as_deref()
        .context("filesystem identity-checked deletion requires a strong ETag")?;
    let expected_hash = expected
        .content_hash
        .as_deref()
        .context("filesystem identity-checked deletion requires a content hash")?;
    let expected_size = expected
        .size
        .context("filesystem identity-checked deletion requires an exact size")?;
    let target = crate::fetch::safe_join(root, path)
        .with_context(|| format!("resolving surface path {path}"))?;
    let canonical_root = tokio::fs::canonicalize(root)
        .await
        .with_context(|| format!("canonicalizing storage root {}", root.display()))?;
    let parent = target
        .parent()
        .context("filesystem deletion target has no parent")?;
    let canonical_parent = tokio::fs::canonicalize(parent)
        .await
        .with_context(|| format!("canonicalizing storage parent {}", parent.display()))?;
    if !canonical_parent.starts_with(&canonical_root) {
        bail!("surface path '{path}' escapes the storage root via symlink");
    }
    validate_directories(&canonical_root, &canonical_parent).await?;
    let file_name = target
        .file_name()
        .context("filesystem deletion target has no file name")?;
    let canonical = canonical_parent.join(file_name);
    let quarantine = quarantine_path(&canonical, expected);

    let _guard = lock_object(&canonical).await;
    capture_or_resume(&canonical, &quarantine).await?;
    if !tokio::fs::try_exists(&quarantine)
        .await
        .with_context(|| format!("inspecting {}", quarantine.display()))?
    {
        return Ok(SurfaceDeleteOutcome::NotFound);
    }

    let mut file = tokio::fs::File::open(&quarantine)
        .await
        .with_context(|| format!("opening {}", quarantine.display()))?;
    let before = file
        .metadata()
        .await
        .with_context(|| format!("reading identity for {}", quarantine.display()))?;
    if !file_is_service_owned(&before) {
        drop(file);
        restore_quarantine(&quarantine, &canonical).await?;
        return Ok(precondition_failed());
    }
    let actual_etag = delete_etag(path, &before);
    if surface_write::strong_if_match_etag(expected_etag)?
        != surface_write::strong_if_match_etag(&actual_etag)?
        || i64::try_from(before.len()).ok() != Some(expected_size)
    {
        drop(file);
        restore_quarantine(&quarantine, &canonical).await?;
        return Ok(precondition_failed());
    }

    use tokio::io::AsyncReadExt as _;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .with_context(|| format!("hashing {}", quarantine.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let after = file
        .metadata()
        .await
        .with_context(|| format!("rechecking identity for {}", quarantine.display()))?;
    let named = tokio::fs::symlink_metadata(&quarantine)
        .await
        .with_context(|| format!("rechecking {}", quarantine.display()))?;
    if !same_object(&before, &after)
        || !same_object(&after, &named)
        || !sha256_identity_matches(expected_hash, &digest)
    {
        drop(file);
        restore_quarantine(&quarantine, &canonical).await?;
        return Ok(precondition_failed());
    }

    drop(file);
    tokio::fs::remove_file(&quarantine)
        .await
        .with_context(|| format!("deleting {}", quarantine.display()))?;
    sync_parent_directory(&canonical).await?;
    Ok(SurfaceDeleteOutcome::Deleted {
        etag: Some(actual_etag),
        content_hash: Some(format!("sha256:{}", hex::encode(digest))),
        size: i64::try_from(before.len()).ok(),
    })
}

async fn capture_or_resume(target: &Path, quarantine: &Path) -> Result<()> {
    let target_exists = tokio::fs::symlink_metadata(target).await;
    let quarantine_exists = tokio::fs::symlink_metadata(quarantine).await;
    match (target_exists, quarantine_exists) {
        (Ok(_), Ok(_)) => {
            bail!("filesystem identity-checked deletion has a retained quarantine conflict");
        }
        (Err(target_error), Err(quarantine_error))
            if target_error.kind() == std::io::ErrorKind::NotFound
                && quarantine_error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        (Err(target_error), Ok(_)) if target_error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        (Ok(target_metadata), Err(quarantine_error))
            if quarantine_error.kind() == std::io::ErrorKind::NotFound =>
        {
            if target_metadata.file_type().is_symlink() || !target_metadata.is_file() {
                bail!("filesystem deletion target is not a regular file");
            }
            rename_noreplace(target, quarantine).with_context(|| {
                format!(
                    "quarantining filesystem object {} for identity verification",
                    target.display()
                )
            })?;
            sync_parent_directory(target).await
        }
        (Err(error), _) => Err(error).with_context(|| format!("inspecting {}", target.display())),
        (_, Err(error)) => {
            Err(error).with_context(|| format!("inspecting {}", quarantine.display()))
        }
    }
}

fn delete_etag(path: &str, metadata: &std::fs::Metadata) -> String {
    if let Some(digest) = crate::fetch::LocalFsFetch::immutable_digest(path) {
        return format!("\"snapshot-sha256-{digest}\"");
    }
    use std::os::unix::fs::MetadataExt as _;
    format!(
        "\"fs-{}-{}-{}-{}-{}\"",
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec()
    )
}

fn quarantine_path(target: &Path, expected: &SurfaceDeletePrecondition) -> PathBuf {
    use std::os::unix::ffi::OsStrExt as _;

    let mut hasher = Sha256::new();
    hasher.update(target.as_os_str().as_bytes());
    hasher.update([0]);
    hasher.update(expected.etag.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(
        expected
            .content_hash
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(expected.size.unwrap_or_default().to_be_bytes());
    target.with_file_name(format!(
        ".aos-delete-{}.quarantine",
        hex::encode(hasher.finalize())
    ))
}

fn rename_noreplace(source: &Path, target: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        target,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

async fn restore_quarantine(quarantine: &Path, target: &Path) -> Result<()> {
    rename_noreplace(quarantine, target).with_context(|| {
        format!(
            "restoring identity-mismatched filesystem object from {}",
            quarantine.display()
        )
    })?;
    sync_parent_directory(target).await
}

async fn validate_directories(root: &Path, parent: &Path) -> Result<()> {
    let mut directory = root.to_path_buf();
    loop {
        let metadata = tokio::fs::symlink_metadata(&directory)
            .await
            .with_context(|| format!("inspecting filesystem directory {}", directory.display()))?;
        use std::os::unix::fs::MetadataExt as _;
        anyhow::ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o022 == 0,
            "filesystem identity-checked deletion requires service-owned, non-writable storage directories"
        );
        if directory == parent {
            return Ok(());
        }
        let component = parent
            .strip_prefix(&directory)
            .context("filesystem deletion parent escaped storage root")?
            .components()
            .next()
            .context("filesystem deletion parent traversal ended unexpectedly")?;
        directory.push(component);
    }
}

fn file_is_service_owned(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.is_file()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.mode() & 0o022 == 0
}

fn same_object(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

fn sha256_identity_matches(expected: &str, digest: &[u8; 32]) -> bool {
    let encoded = hex::encode(digest);
    if expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return expected.eq_ignore_ascii_case(&encoded);
    }
    expected
        .strip_prefix("sha256:")
        .is_some_and(|expected| expected.eq_ignore_ascii_case(&encoded))
        || expected.strip_prefix("sha256-").is_some_and(|expected| {
            use base64::Engine as _;
            expected == base64::engine::general_purpose::STANDARD.encode(digest)
        })
}

fn precondition_failed() -> SurfaceDeleteOutcome {
    SurfaceDeleteOutcome::PreconditionFailed {
        detail: "filesystem object identity changed after inventory".to_string(),
    }
}

async fn sync_parent_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let directory = tokio::fs::File::open(parent)
            .await
            .with_context(|| format!("opening directory {} for sync", parent.display()))?;
        directory
            .sync_all()
            .await
            .with_context(|| format!("syncing directory {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn precondition(
        path: &str,
        bytes: &[u8],
        metadata: &std::fs::Metadata,
    ) -> SurfaceDeletePrecondition {
        SurfaceDeletePrecondition {
            etag: Some(delete_etag(path, metadata)),
            content_hash: Some(format!("sha256:{}", hex::encode(Sha256::digest(bytes)))),
            size: Some(bytes.len() as i64),
        }
    }

    #[tokio::test]
    async fn stale_identity_is_restored_and_exact_identity_is_deleted() {
        let directory = tempfile::tempdir().unwrap();
        let path = "objects/exact";
        let target = directory.path().join(path);
        tokio::fs::create_dir_all(target.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&target, b"first").await.unwrap();
        let stale = precondition(path, b"first", &tokio::fs::metadata(&target).await.unwrap());

        tokio::fs::write(&target, b"other").await.unwrap();
        assert!(matches!(
            delete_if_matches(directory.path(), path, &stale)
                .await
                .unwrap(),
            SurfaceDeleteOutcome::PreconditionFailed { .. }
        ));
        assert_eq!(tokio::fs::read(&target).await.unwrap(), b"other");

        let current = precondition(path, b"other", &tokio::fs::metadata(&target).await.unwrap());
        assert!(matches!(
            delete_if_matches(directory.path(), path, &current)
                .await
                .unwrap(),
            SurfaceDeleteOutcome::Deleted { .. }
        ));
        assert!(matches!(
            delete_if_matches(directory.path(), path, &current)
                .await
                .unwrap(),
            SurfaceDeleteOutcome::NotFound
        ));
    }

    #[tokio::test]
    async fn retry_resumes_a_durable_quarantine_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = "objects/restart";
        let target = directory.path().join(path);
        tokio::fs::create_dir_all(target.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&target, b"retained").await.unwrap();
        let expected = precondition(
            path,
            b"retained",
            &tokio::fs::metadata(&target).await.unwrap(),
        );
        let quarantine = quarantine_path(&target, &expected);
        rename_noreplace(&target, &quarantine).unwrap();
        sync_parent_directory(&target).await.unwrap();

        assert!(matches!(
            delete_if_matches(directory.path(), path, &expected)
                .await
                .unwrap(),
            SurfaceDeleteOutcome::Deleted { .. }
        ));
        assert!(!tokio::fs::try_exists(&quarantine).await.unwrap());
    }

    #[tokio::test]
    async fn target_and_retained_quarantine_conflict_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = "objects/conflict";
        let target = directory.path().join(path);
        tokio::fs::create_dir_all(target.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&target, b"old").await.unwrap();
        let expected = precondition(path, b"old", &tokio::fs::metadata(&target).await.unwrap());
        let quarantine = quarantine_path(&target, &expected);
        rename_noreplace(&target, &quarantine).unwrap();
        tokio::fs::write(&target, b"replacement").await.unwrap();

        let error = delete_if_matches(directory.path(), path, &expected)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("retained quarantine conflict"));
        assert_eq!(tokio::fs::read(&target).await.unwrap(), b"replacement");
        assert_eq!(tokio::fs::read(&quarantine).await.unwrap(), b"old");
    }

    #[tokio::test]
    async fn concurrent_cooperating_rewrite_is_never_deleted_as_the_old_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = "objects/concurrent";
        let target = directory.path().join(path);
        tokio::fs::create_dir_all(target.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&target, b"old").await.unwrap();
        let expected = precondition(path, b"old", &tokio::fs::metadata(&target).await.unwrap());

        let barrier = lock_object(&target).await;
        let root = directory.path().to_path_buf();
        let deletion = tokio::spawn(async move { delete_if_matches(&root, path, &expected).await });
        let rewrite_target = target.clone();
        let rewrite = tokio::spawn(async move {
            let _guard = lock_object(&rewrite_target).await;
            tokio::fs::write(&rewrite_target, b"replacement").await
        });
        drop(barrier);

        let deletion = deletion.await.unwrap().unwrap();
        rewrite.await.unwrap().unwrap();
        assert!(matches!(
            deletion,
            SurfaceDeleteOutcome::Deleted { .. } | SurfaceDeleteOutcome::PreconditionFailed { .. }
        ));
        assert_eq!(tokio::fs::read(&target).await.unwrap(), b"replacement");
    }

    #[tokio::test]
    async fn immutable_oci_path_uses_the_snapshot_identity() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"oci bytes";
        let digest = hex::encode(Sha256::digest(bytes));
        let path = format!("oci/blobs/sha256/{digest}");
        let target = directory.path().join(&path);
        tokio::fs::create_dir_all(target.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&target, bytes).await.unwrap();
        let expected = SurfaceDeletePrecondition {
            etag: Some(format!("\"snapshot-sha256-{digest}\"")),
            content_hash: Some(format!("sha256:{digest}")),
            size: Some(bytes.len() as i64),
        };

        assert!(matches!(
            delete_if_matches(directory.path(), &path, &expected)
                .await
                .unwrap(),
            SurfaceDeleteOutcome::Deleted { .. }
        ));
    }
}
