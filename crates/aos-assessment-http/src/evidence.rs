//! Immutable partitioned source custody on a private Native service filesystem.
//!
//! The deployment supplies a private root whose ancestors remain under trusted
//! administrative control. Only authenticated assessment work receives this
//! port; partition strings cannot grant authorization or select filesystem paths.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, bail};
use aos_assessment_runtime::ports::EvidenceStore;
use aos_contract::Sha256Digest;

const MAX_BYTES: u64 = 8 * 1024 * 1024;
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

/// Retains exact provider bytes under private content-addressed Native custody.
///
/// Each authorization partition has a separate hashed directory. Files are
/// installed atomically without replacement and are rehashed on every read.
/// Blocking filesystem effects run outside the async executor's worker threads.
#[derive(Clone, Debug)]
pub struct NativeEvidenceStore {
    root: PathBuf,
}

impl NativeEvidenceStore {
    /// Opens or creates a private evidence root owned by the service deployment.
    ///
    /// Existing roots must be real directories with no group or other access.
    /// Parent directories must already exist and remain trusted for the lifetime
    /// of this store. This constructor never changes existing permissions.
    ///
    /// # Errors
    /// Returns an error for relative paths, absent parents, unsafe permissions,
    /// symbolic links, non-directory roots, or unavailable filesystem custody.
    pub async fn open(root: PathBuf) -> Result<Self> {
        if !root.is_absolute() {
            bail!("assessment evidence root must be an absolute deployment path");
        }
        tokio::task::spawn_blocking(move || {
            private_directory(&root)?;
            Ok(Self {
                root: fs::canonicalize(root)?,
            })
        })
        .await
        .context("evidence root initialization task failed")?
    }

    fn partition_directory(&self, partition: &str, create: bool) -> Result<PathBuf> {
        if partition.is_empty() || partition.len() > 128 || partition.chars().any(char::is_control)
        {
            bail!("invalid assessment evidence partition");
        }
        require_private_directory(&self.root)?;
        let directory = self.root.join(Sha256Digest::of_bytes(partition).hex());
        if create {
            private_directory(&directory)?;
        } else {
            require_private_directory(&directory)?;
        }
        Ok(directory)
    }

    fn retain_blocking(&self, partition: &str, bytes: &[u8]) -> Result<Sha256Digest> {
        if bytes.len() as u64 > MAX_BYTES {
            bail!("source evidence exceeds the Native custody byte ceiling");
        }
        let directory = self.partition_directory(partition, true)?;
        let digest = Sha256Digest::of_bytes(bytes);
        let target = directory.join(digest.hex());
        let (temporary, mut file) = temporary_file(&directory)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temporary.path, &target) {
            Ok(()) => File::open(&directory)?.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let retained = self.read_blocking(partition, digest, bytes.len() as u64)?;
        if retained != bytes {
            bail!("existing source evidence differs from exact immutable custody");
        }
        Ok(digest)
    }

    fn read_blocking(
        &self,
        partition: &str,
        digest: Sha256Digest,
        max_bytes: u64,
    ) -> Result<Vec<u8>> {
        if max_bytes > MAX_BYTES {
            bail!("source evidence read exceeds the Native custody byte ceiling");
        }
        let directory = self.partition_directory(partition, false)?;
        let path = directory.join(digest.hex());
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > max_bytes
        {
            bail!("source evidence has unsafe custody or exceeds the exact read bound");
        }
        let length = metadata.len();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(usize::try_from(length)?)
            .context("source evidence allocation failed")?;
        // The extra byte detects concurrent growth without admitting an
        // unbounded read, even when the metadata size initially fit the limit.
        std::io::Read::by_ref(&mut file)
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != length || Sha256Digest::of_bytes(&bytes) != digest {
            bail!("source evidence differs from its immutable content identity");
        }
        Ok(bytes)
    }
}

#[async_trait::async_trait]
impl EvidenceStore for NativeEvidenceStore {
    async fn retain(&self, partition: &str, bytes: &[u8]) -> Result<Sha256Digest> {
        if bytes.len() as u64 > MAX_BYTES {
            bail!("source evidence exceeds the Native custody byte ceiling");
        }
        let store = self.clone();
        let partition = partition.to_owned();
        let bytes = bytes.to_vec();
        tokio::task::spawn_blocking(move || store.retain_blocking(&partition, &bytes))
            .await
            .context("source evidence retention task failed")?
    }

    async fn read(&self, partition: &str, digest: Sha256Digest, max_bytes: u64) -> Result<Vec<u8>> {
        let store = self.clone();
        let partition = partition.to_owned();
        tokio::task::spawn_blocking(move || store.read_blocking(&partition, digest, max_bytes))
            .await
            .context("source evidence read task failed")?
    }
}

fn require_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        bail!("assessment evidence requires a private real directory");
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    require_private_directory(path)
}

struct TemporaryFile {
    path: PathBuf,
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn temporary_file(directory: &Path) -> Result<(TemporaryFile, File)> {
    for _ in 0..8 {
        let path = directory.join(format!(
            ".pending-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((TemporaryFile { path }, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    bail!("private source custody temporary names are exhausted")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn immutable_custody_survives_restart_and_is_partitioned_and_bounded() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let root = parent.path().join("evidence");
        let store = NativeEvidenceStore::open(root.clone()).await?;
        let expected = b"exact retained source response";
        let digest = store.retain("registry:first", expected).await?;
        let receipts = tokio::join!(
            store.retain("registry:first", expected),
            store.retain("registry:first", expected)
        );
        assert_eq!(receipts.0?, digest);
        assert_eq!(receipts.1?, digest);

        let reopened = NativeEvidenceStore::open(root).await?;
        assert_eq!(
            reopened
                .read("registry:first", digest, expected.len() as u64)
                .await?,
            expected
        );
        assert!(
            reopened
                .read("registry:second", digest, MAX_BYTES)
                .await
                .is_err()
        );
        assert!(
            reopened
                .read("registry:first", digest, expected.len() as u64 - 1)
                .await
                .is_err()
        );
        assert!(
            reopened
                .read("registry:first", digest, MAX_BYTES + 1)
                .await
                .is_err()
        );
        assert!(
            reopened
                .retain("registry:first", &vec![0; MAX_BYTES as usize + 1])
                .await
                .is_err()
        );
        assert_eq!(reopened.retain("registry:second", expected).await?, digest);
        Ok(())
    }

    #[tokio::test]
    async fn corruption_and_symbolic_link_custody_never_become_valid_evidence() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let store = NativeEvidenceStore::open(parent.path().join("evidence")).await?;
        let digest = store.retain("partition", b"source").await?;
        let path = store
            .partition_directory("partition", false)?
            .join(digest.hex());
        fs::write(&path, b"broken")?;
        assert!(store.read("partition", digest, MAX_BYTES).await.is_err());
        assert!(store.retain("partition", b"source").await.is_err());
        assert_eq!(fs::read(&path)?, b"broken");

        fs::remove_file(&path)?;
        let outside = parent.path().join("outside");
        fs::write(&outside, b"source")?;
        std::os::unix::fs::symlink(&outside, &path)?;
        assert!(store.read("partition", digest, MAX_BYTES).await.is_err());
        assert!(store.retain("partition", b"source").await.is_err());
        assert_eq!(fs::read(&outside)?, b"source");
        Ok(())
    }

    #[tokio::test]
    async fn public_roots_and_linked_partition_directories_are_refused() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let public = parent.path().join("public");
        fs::create_dir(&public)?;
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))?;
        assert!(NativeEvidenceStore::open(public).await.is_err());
        let root = parent.path().join("private");
        let store = NativeEvidenceStore::open(root.clone()).await?;
        let outside = parent.path().join("outside");
        private_directory(&outside)?;
        std::os::unix::fs::symlink(
            &outside,
            root.join(Sha256Digest::of_bytes("partition").hex()),
        )?;
        assert!(store.retain("partition", b"source").await.is_err());
        assert_eq!(fs::read_dir(outside)?.count(), 0);
        Ok(())
    }
}
