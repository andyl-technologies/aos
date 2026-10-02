//! Durable identity-bound checkpoints for cache multipart transfers.
//!
//! Journals retain provider upload ids and accepted part receipts under the
//! user's cache directory. A changed destination, key, size, or SHA-256 creates
//! a different checkpoint; revision changes reuse only identical objects.
//! The format is private client state:
//!
//! ```json
//! {"upload_id":"provider-id","part_size":8388608,"parts":[[1,"etag"]]}
//! ```

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use aos_net::MultipartSource;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub(crate) upload_id: String,
    pub(crate) part_size: u64,
    pub(crate) parts: Vec<(u32, String)>,
}

/// Releases transfer ownership even if a subprocess inherited the descriptor.
pub(crate) struct TransferLock {
    file: std::fs::File,
}

impl TransferLock {
    pub(crate) fn acquire(file: std::fs::File) -> Result<Self> {
        file.try_lock()?;
        Ok(Self { file })
    }
}

impl Drop for TransferLock {
    fn drop(&mut self) {
        // Closing only this descriptor can leave a forked child holding the
        // same open-file description until exec. Ownership ends with the guard.
        let _ = self.file.unlock();
    }
}

/// Holds an OS advisory lock until this transfer finishes or its process exits.
pub(crate) struct ResumeJournal {
    path: PathBuf,
    _lock: TransferLock,
}

impl ResumeJournal {
    pub(crate) fn open(namespace: &str, path: &str, size: u64, sha256: &str) -> Result<Self> {
        let root = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .context("durable uploads require XDG_CACHE_HOME or HOME")?
            .join("aos/uploads");
        Self::open_at(root, namespace, path, size, sha256)
    }

    pub(crate) fn open_at(
        root: PathBuf,
        namespace: &str,
        path: &str,
        size: u64,
        sha256: &str,
    ) -> Result<Self> {
        std::fs::create_dir_all(&root).context("creating durable upload journal directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        }
        let identity = serde_json::to_vec(&(namespace, path, size, sha256))?;
        let key = hex::encode(Sha256::digest(identity));
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join(format!("{key}.lock")))?;
        let lock = TransferLock::acquire(lock)
            .context("another process is transferring this exact object")?;
        Ok(Self {
            path: root.join(format!("{key}.json")),
            _lock: lock,
        })
    }

    pub(crate) fn read(&self) -> Result<Option<Checkpoint>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("decoding durable multipart checkpoint")?,
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("reading durable multipart checkpoint"),
        }
    }

    pub(crate) fn write(&self, checkpoint: &Checkpoint) -> Result<()> {
        let parent = self.path.parent().context("upload journal has no parent")?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&serde_json::to_vec(checkpoint)?)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.path)
            .context("replacing durable multipart checkpoint")?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub(crate) fn clear(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing completed multipart checkpoint"),
        }
    }
}

/// Hashes the exact rewindable source before reusing any provider session.
pub(crate) fn source_identity(source: &MultipartSource) -> Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let file = match source {
        MultipartSource::Bytes(bytes) => {
            return Ok((
                u64::try_from(bytes.len())?,
                hex::encode(Sha256::digest(bytes)),
            ));
        }
        MultipartSource::File(path) => std::fs::File::open(path)?,
        MultipartSource::FileHandle(file) => file.try_clone()?,
    };
    // A cloned descriptor shares its cursor, so read_at leaves the pinned source
    // cursor untouched and makes identity inspection independent of prior reads.
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt as _;
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = file.read_at(&mut buffer, size)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            size = size
                .checked_add(u64::try_from(count)?)
                .context("upload size overflow")?;
        }
    }
    #[cfg(not(unix))]
    {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let mut file = file;
        file.seek(SeekFrom::Start(0))?;
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            size = size
                .checked_add(u64::try_from(count)?)
                .context("upload size overflow")?;
        }
    }
    Ok((size, hex::encode(hasher.finalize())))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn transfer_lock_releases_ownership_despite_a_retained_descriptor() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let open = || {
            std::fs::File::options()
                .read(true)
                .write(true)
                .open(file.path())
                .unwrap()
        };
        let lock = TransferLock::acquire(open()).unwrap();
        let inherited = lock.file.try_clone().unwrap();

        assert!(TransferLock::acquire(open()).is_err());
        drop(lock);

        let next = TransferLock::acquire(open()).unwrap();
        assert!(TransferLock::acquire(open()).is_err());
        drop(next);
        drop(inherited);
    }
}
