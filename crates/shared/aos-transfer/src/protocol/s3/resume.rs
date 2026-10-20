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

use crate::MultipartSource;
use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    pub(super) upload_id: String,
    pub(super) part_size: u64,
    pub(super) parts: Vec<(u32, String)>,
}

/// Holds an OS advisory lock until this transfer finishes or its process exits.
pub(super) struct ResumeJournal {
    path: PathBuf,
    _lock: std::fs::File,
}

impl ResumeJournal {
    pub(super) fn open(namespace: &str, path: &str, size: u64, sha256: &str) -> Result<Self> {
        let root = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .context("durable uploads require XDG_CACHE_HOME or HOME")?
            .join("aos/s3-uploads");
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
        lock.try_lock()
            .context("another process is transferring this exact object")?;
        Ok(Self {
            path: root.join(format!("{key}.json")),
            _lock: lock,
        })
    }

    pub(super) fn read(&self) -> Result<Option<Checkpoint>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("decoding durable multipart checkpoint")?,
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("reading durable multipart checkpoint"),
        }
    }

    pub(super) fn write(&self, checkpoint: &Checkpoint) -> Result<()> {
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

    pub(super) fn clear(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing completed multipart checkpoint"),
        }
    }
}

/// Hashes the exact rewindable source before reusing any provider session.
pub(super) fn source_identity(source: &MultipartSource) -> Result<(u64, String)> {
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
