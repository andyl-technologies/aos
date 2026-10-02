//! Resumes identity-bound filesystem uploads through private partial objects.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;

use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};

/// Copies a verified source into a durable partial object and atomically exposes it.
pub(super) fn put(root: &Path, relative: &str, source: &Path, expected: &str) -> Result<()> {
    super::conditional::validate_relative_path(relative)?;
    let mut input = std::fs::File::open(source)?;
    let (size, actual) = crate::upload_resume::source_identity(
        &aos_net::MultipartSource::FileHandle(std::sync::Arc::new(input.try_clone()?)),
    )?;
    anyhow::ensure!(
        actual == expected,
        "filesystem upload source changed after inventory"
    );

    let private = root.join(".aos-upload-resume");
    std::fs::create_dir_all(&private)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))?;
    }
    let identity = hex::encode(Sha256::digest(serde_json::to_vec(&(
        relative, size, expected,
    ))?));
    let lock_path = private.join(format!("{identity}.lock"));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)?;
    let transfer_lock = crate::upload_resume::TransferLock::acquire(lock)
        .context("another process is transferring this filesystem object")?;
    let partial_path = private.join(format!("{identity}.part"));
    let mut partial = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&partial_path)?;
    let retained = partial.metadata()?.len();
    anyhow::ensure!(
        retained <= size,
        "filesystem upload checkpoint exceeds admitted size"
    );

    // Compare retained bytes to the exact admitted source before trusting an
    // offset, including after a crash between writing data and syncing it.
    let mut source_buffer = [0_u8; 128 * 1024];
    let mut retained_buffer = [0_u8; 128 * 1024];
    let mut remaining = retained;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(source_buffer.len() as u64))?;
        input.read_exact(&mut source_buffer[..count])?;
        partial.read_exact(&mut retained_buffer[..count])?;
        anyhow::ensure!(
            source_buffer[..count] == retained_buffer[..count],
            "filesystem upload checkpoint does not match admitted bytes"
        );
        remaining -= count as u64;
    }
    input.seek(SeekFrom::Start(retained))?;
    partial.seek(SeekFrom::Start(retained))?;
    while remaining < size - retained {
        let count = usize::try_from((size - retained - remaining).min(source_buffer.len() as u64))?;
        input.read_exact(&mut source_buffer[..count])?;
        partial.write_all(&source_buffer[..count])?;
        remaining += count as u64;
        if remaining % (8 * 1024 * 1024) == 0 {
            partial.sync_data()?;
        }
    }
    partial.sync_all()?;
    let (_, transferred) = crate::upload_resume::source_identity(
        &aos_net::MultipartSource::FileHandle(std::sync::Arc::new(partial.try_clone()?)),
    )?;
    anyhow::ensure!(
        transferred == expected,
        "filesystem upload failed exact SHA-256 verification"
    );
    let destination = root.join(relative);
    let parent = destination
        .parent()
        .context("filesystem upload destination has no parent")?;
    std::fs::create_dir_all(parent)?;
    match std::fs::hard_link(&partial_path, &destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let (_, current) = crate::upload_resume::source_identity(
                &aos_net::MultipartSource::File(destination.clone()),
            )?;
            anyhow::ensure!(
                current == expected,
                "immutable filesystem object already exists with conflicting bytes"
            );
        }
        Err(error) => return Err(error).context("installing immutable filesystem object"),
    }
    std::fs::remove_file(&partial_path)?;

    // The identity lock guards only the in-flight partial object. Remove it
    // while it is still held so a completed upload leaves no private files in
    // the served origin; publication surfaces reject unknown paths.
    std::fs::remove_file(&lock_path)?;
    drop(transfer_lock);
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_path(root: &Path, relative: &str, bytes: &[u8]) -> Result<std::path::PathBuf> {
        let digest = hex::encode(Sha256::digest(bytes));
        let identity = hex::encode(Sha256::digest(serde_json::to_vec(&(
            relative,
            bytes.len() as u64,
            digest,
        ))?));
        Ok(root
            .join(".aos-upload-resume")
            .join(format!("{identity}.part")))
    }

    #[test]
    fn resumes_verified_prefix_and_never_replaces_conflicting_immutable_bytes() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("origin");
        let source = temporary.path().join("source");
        let bytes = b"a verified retained prefix followed by remaining bytes";
        std::fs::write(&source, bytes)?;
        let partial = retained_path(&root, "images/disk", bytes)?;
        std::fs::create_dir_all(partial.parent().unwrap())?;
        std::fs::write(&partial, &bytes[..12])?;
        let digest = hex::encode(Sha256::digest(bytes));

        put(&root, "images/disk", &source, &digest)?;

        assert_eq!(std::fs::read(root.join("images/disk"))?, bytes);
        assert!(!partial.exists());
        assert_eq!(
            std::fs::read_dir(root.join(".aos-upload-resume"))?.count(),
            0,
            "a completed upload must not leave private resume files"
        );
        std::fs::write(root.join("images/disk"), b"other immutable bytes")?;
        assert!(put(&root, "images/disk", &source, &digest).is_err());
        assert_eq!(
            std::fs::read(root.join("images/disk"))?,
            b"other immutable bytes"
        );
        Ok(())
    }

    #[test]
    fn rejects_retained_prefix_from_another_source_without_exposing_it() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("origin");
        let source = temporary.path().join("source");
        let bytes = b"the exact reviewed source";
        std::fs::write(&source, bytes)?;
        let partial = retained_path(&root, "nar/object", bytes)?;
        std::fs::create_dir_all(partial.parent().unwrap())?;
        std::fs::write(&partial, b"wrong")?;

        assert!(
            put(
                &root,
                "nar/object",
                &source,
                &hex::encode(Sha256::digest(bytes))
            )
            .is_err()
        );
        assert!(!root.join("nar/object").exists());
        assert_eq!(std::fs::read(partial)?, b"wrong");
        Ok(())
    }
}
