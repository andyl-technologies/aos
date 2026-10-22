//! Private storage for resumable HTTP uploads.
//!
//! A session belongs to one view, provisioning-token identity, and store hash.
//! Its filename is an opaque digest of those values. The file starts with a
//! fixed header containing the declared payload length, followed by contiguous
//! payload bytes.

use std::collections::HashSet;
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use aos_nix::StoreHash;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

const HEADER_MAGIC: &[u8; 8] = b"AOSUPLD1";
pub(crate) const HEADER_LENGTH: u64 = 16;
static ACTIVE_SESSIONS: LazyLock<Mutex<HashSet<PathBuf>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// A validated inclusive byte range for one upload request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UploadRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) total: u64,
}

impl UploadRange {
    /// Parses `bytes start-end/total` and validates its arithmetic.
    pub(crate) fn parse(value: &str) -> Result<Self, SessionError> {
        let rest = value
            .strip_prefix("bytes ")
            .ok_or(SessionError::MalformedRange)?;
        let (range, total) = rest.split_once('/').ok_or(SessionError::MalformedRange)?;
        let (start, end) = range.split_once('-').ok_or(SessionError::MalformedRange)?;
        let parsed = Self {
            start: start.parse().map_err(|_| SessionError::MalformedRange)?,
            end: end.parse().map_err(|_| SessionError::MalformedRange)?,
            total: total.parse().map_err(|_| SessionError::MalformedRange)?,
        };

        if parsed.total == 0 || parsed.start > parsed.end || parsed.end >= parsed.total {
            return Err(SessionError::MalformedRange);
        }
        Ok(parsed)
    }

    fn length(self) -> Result<u64, SessionError> {
        self.end
            .checked_sub(self.start)
            .and_then(|length| length.checked_add(1))
            .ok_or(SessionError::MalformedRange)
    }
}

/// The result of appending one exact range to a session.
pub(crate) struct UploadProgress {
    /// Payload bytes durably appended so far.
    pub(crate) received: u64,
    /// Declared complete payload length.
    pub(crate) total: u64,
    /// Session file containing the private header and payload.
    pub(crate) path: PathBuf,
}

impl UploadProgress {
    pub(crate) fn is_complete(&self) -> bool {
        self.received == self.total
    }
}

/// Errors produced while opening or extending a resumable session.
#[derive(Debug)]
pub(crate) enum SessionError {
    MalformedRange,
    LengthMismatch { declared: u64, actual: u64 },
    LimitExceeded { maximum: u64 },
    Busy,
    Missing,
    OffsetMismatch { expected: u64, actual: u64 },
    TotalChanged { expected: u64, actual: u64 },
    InvalidState,
    Io(std::io::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedRange => formatter.write_str("malformed Content-Range"),
            Self::LengthMismatch { declared, actual } => {
                write!(
                    formatter,
                    "range declares {declared} bytes but body has {actual}"
                )
            }
            Self::LimitExceeded { maximum } => {
                write!(formatter, "upload exceeds {maximum} byte limit")
            }
            Self::Busy => formatter.write_str("upload session is busy"),
            Self::Missing => formatter.write_str("upload session does not exist"),
            Self::OffsetMismatch { expected, actual } => {
                write!(formatter, "expected offset {expected}, received {actual}")
            }
            Self::TotalChanged { expected, actual } => {
                write!(formatter, "expected total {expected}, received {actual}")
            }
            Self::InvalidState => formatter.write_str("upload session state is invalid"),
            Self::Io(error) => write!(formatter, "upload session I/O: {error}"),
        }
    }
}

impl From<std::io::Error> for SessionError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

struct SessionPaths {
    data: PathBuf,
}

impl SessionPaths {
    fn new(root: &Path, view: &str, principal: &str, hash: &StoreHash) -> Self {
        let mut digest = Sha256::new();
        for component in [
            view.as_bytes(),
            principal.as_bytes(),
            hash.as_str().as_bytes(),
        ] {
            digest.update((component.len() as u64).to_be_bytes());
            digest.update(component);
        }
        let identifier = hex::encode(digest.finalize());
        let directory = root.join("uploads").join("rest");

        Self {
            data: directory.join(format!("{identifier}.partial")),
        }
    }
}

struct SessionLock {
    path: PathBuf,
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE_SESSIONS.lock() {
            active.remove(&self.path);
        }
    }
}

async fn prepare_directory(path: &Path) -> Result<(), SessionError> {
    tokio::fs::create_dir_all(path).await?;
    let metadata = tokio::fs::symlink_metadata(path).await?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SessionError::InvalidState);
    }
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    Ok(())
}

fn acquire_lock(path: &Path) -> Result<SessionLock, SessionError> {
    let mut active = ACTIVE_SESSIONS
        .lock()
        .map_err(|_| SessionError::InvalidState)?;
    if !active.insert(path.to_path_buf()) {
        return Err(SessionError::Busy);
    }

    Ok(SessionLock {
        path: path.to_path_buf(),
    })
}

async fn open_existing(path: &Path) -> Result<tokio::fs::File, SessionError> {
    tokio::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SessionError::Missing
            } else {
                SessionError::Io(error)
            }
        })
}

async fn open_for_read(path: &Path) -> Result<tokio::fs::File, SessionError> {
    tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SessionError::Missing
            } else {
                SessionError::Io(error)
            }
        })
}

async fn create_session(path: &Path, total: u64) -> Result<tokio::fs::File, SessionError> {
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .await
        .map_err(SessionError::Io)?;
    file.write_all(HEADER_MAGIC).await?;
    file.write_all(&total.to_be_bytes()).await?;
    Ok(file)
}

async fn inspect_session(
    file: &mut tokio::fs::File,
    requested_total: u64,
) -> Result<u64, SessionError> {
    let metadata = file.metadata().await?;
    if !metadata.is_file() || metadata.len() < HEADER_LENGTH {
        return Err(SessionError::InvalidState);
    }

    file.seek(std::io::SeekFrom::Start(0)).await?;
    let mut header = [0u8; HEADER_LENGTH as usize];
    file.read_exact(&mut header).await?;
    if &header[..8] != HEADER_MAGIC {
        return Err(SessionError::InvalidState);
    }
    let stored_total = u64::from_be_bytes(
        header[8..]
            .try_into()
            .map_err(|_| SessionError::InvalidState)?,
    );
    if stored_total != requested_total {
        return Err(SessionError::TotalChanged {
            expected: stored_total,
            actual: requested_total,
        });
    }

    metadata
        .len()
        .checked_sub(HEADER_LENGTH)
        .ok_or(SessionError::InvalidState)
}

/// Appends one contiguous range to the session selected by the request identity.
pub(crate) async fn append(
    root: &Path,
    view: &str,
    principal: &str,
    hash: &StoreHash,
    range: UploadRange,
    body: &[u8],
    maximum_bytes: u64,
) -> Result<UploadProgress, SessionError> {
    if range.total > maximum_bytes {
        return Err(SessionError::LimitExceeded {
            maximum: maximum_bytes,
        });
    }
    let declared_length = range.length()?;
    let actual_length = u64::try_from(body.len()).map_err(|_| SessionError::LengthMismatch {
        declared: declared_length,
        actual: u64::MAX,
    })?;
    if declared_length != actual_length {
        return Err(SessionError::LengthMismatch {
            declared: declared_length,
            actual: actual_length,
        });
    }

    let paths = SessionPaths::new(root, view, principal, hash);
    let directory = paths.data.parent().ok_or(SessionError::InvalidState)?;
    prepare_directory(directory).await?;
    let _lock = acquire_lock(&paths.data)?;

    let mut file = if range.start == 0 {
        match create_session(&paths.data, range.total).await {
            Ok(file) => file,
            Err(SessionError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                open_existing(&paths.data).await?
            }
            Err(error) => return Err(error),
        }
    } else {
        open_existing(&paths.data).await?
    };

    let received = inspect_session(&mut file, range.total).await?;
    if received != range.start {
        return Err(SessionError::OffsetMismatch {
            expected: received,
            actual: range.start,
        });
    }

    file.write_all(body).await?;
    file.sync_data().await?;
    let received = received
        .checked_add(actual_length)
        .ok_or(SessionError::InvalidState)?;

    Ok(UploadProgress {
        received,
        total: range.total,
        path: paths.data,
    })
}

/// Returns progress for the session selected by the request identity.
pub(crate) async fn progress(
    root: &Path,
    view: &str,
    principal: &str,
    hash: &StoreHash,
) -> Result<(u64, u64), SessionError> {
    let paths = SessionPaths::new(root, view, principal, hash);
    let mut file = open_for_read(&paths.data).await?;
    let metadata = file.metadata().await?;
    if metadata.len() < HEADER_LENGTH {
        return Err(SessionError::InvalidState);
    }
    file.seek(std::io::SeekFrom::Start(0)).await?;
    let mut header = [0u8; HEADER_LENGTH as usize];
    file.read_exact(&mut header).await?;
    if &header[..8] != HEADER_MAGIC {
        return Err(SessionError::InvalidState);
    }
    let total = u64::from_be_bytes(
        header[8..]
            .try_into()
            .map_err(|_| SessionError::InvalidState)?,
    );
    Ok((metadata.len() - HEADER_LENGTH, total))
}

/// Removes a completed or abandoned session file.
pub(crate) async fn remove(path: &Path) {
    let _ = tokio::fs::remove_file(path).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash() -> StoreHash {
        "0123456789abcdfghijklmnpqrsvwxyz".parse().unwrap()
    }

    #[tokio::test]
    async fn ranges_must_be_contiguous_and_exact() {
        let directory = tempfile::tempdir().unwrap();
        let first = UploadRange::parse("bytes 0-2/6").unwrap();
        append(directory.path(), "view", "one", &hash(), first, b"abc", 8)
            .await
            .unwrap();

        let gap = UploadRange::parse("bytes 4-5/6").unwrap();
        assert!(matches!(
            append(directory.path(), "view", "one", &hash(), gap, b"ef", 8).await,
            Err(SessionError::OffsetMismatch {
                expected: 3,
                actual: 4
            })
        ));
        let overlap = UploadRange::parse("bytes 2-3/6").unwrap();
        assert!(matches!(
            append(directory.path(), "view", "one", &hash(), overlap, b"cd", 8).await,
            Err(SessionError::OffsetMismatch {
                expected: 3,
                actual: 2
            })
        ));

        let final_range = UploadRange::parse("bytes 3-5/6").unwrap();
        let completed = append(
            directory.path(),
            "view",
            "one",
            &hash(),
            final_range,
            b"def",
            8,
        )
        .await
        .unwrap();
        assert!(completed.is_complete());
        let bytes = std::fs::read(completed.path).unwrap();
        assert_eq!(&bytes[HEADER_LENGTH as usize..], b"abcdef");
    }

    #[tokio::test]
    async fn sessions_are_scoped_by_view_and_principal() {
        let directory = tempfile::tempdir().unwrap();
        let first = UploadRange::parse("bytes 0-1/4").unwrap();
        append(directory.path(), "a", "one", &hash(), first, b"ab", 8)
            .await
            .unwrap();

        assert_eq!(
            progress(directory.path(), "a", "one", &hash())
                .await
                .unwrap(),
            (2, 4)
        );
        assert!(matches!(
            progress(directory.path(), "b", "one", &hash()).await,
            Err(SessionError::Missing)
        ));
        assert!(matches!(
            progress(directory.path(), "a", "two", &hash()).await,
            Err(SessionError::Missing)
        ));
    }

    #[tokio::test]
    async fn total_and_body_length_cannot_change() {
        let directory = tempfile::tempdir().unwrap();
        let first = UploadRange::parse("bytes 0-1/4").unwrap();
        append(directory.path(), "view", "one", &hash(), first, b"ab", 8)
            .await
            .unwrap();

        let changed = UploadRange::parse("bytes 2-4/5").unwrap();
        assert!(matches!(
            append(directory.path(), "view", "one", &hash(), changed, b"cde", 8).await,
            Err(SessionError::TotalChanged {
                expected: 4,
                actual: 5
            })
        ));
        let wrong_length = UploadRange::parse("bytes 2-3/4").unwrap();
        assert!(matches!(
            append(
                directory.path(),
                "view",
                "one",
                &hash(),
                wrong_length,
                b"c",
                8
            )
            .await,
            Err(SessionError::LengthMismatch { .. })
        ));

        let oversized = UploadRange::parse("bytes 0-0/9").unwrap();
        assert!(matches!(
            append(directory.path(), "view", "two", &hash(), oversized, b"x", 8,).await,
            Err(SessionError::LimitExceeded { maximum: 8 })
        ));
    }

    #[tokio::test]
    async fn symlink_session_files_are_not_followed() {
        let directory = tempfile::tempdir().unwrap();
        let paths = SessionPaths::new(directory.path(), "view", "one", &hash());
        prepare_directory(paths.data.parent().unwrap())
            .await
            .unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&target, &paths.data).unwrap();

        let range = UploadRange::parse("bytes 0-0/1").unwrap();
        assert!(
            append(directory.path(), "view", "one", &hash(), range, b"x", 8)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
    }

    #[tokio::test]
    async fn concurrent_writers_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let paths = SessionPaths::new(directory.path(), "view", "one", &hash());
        let held = acquire_lock(&paths.data).unwrap();
        let range = UploadRange::parse("bytes 0-0/2").unwrap();

        assert!(matches!(
            append(directory.path(), "view", "one", &hash(), range, b"x", 8).await,
            Err(SessionError::Busy)
        ));

        drop(held);
        append(directory.path(), "view", "one", &hash(), range, b"x", 8)
            .await
            .unwrap();
    }

    #[test]
    fn malformed_and_huge_ranges_are_rejected() {
        for value in [
            "items 0-1/2",
            "bytes 1-0/2",
            "bytes 0-2/2",
            "bytes 0-0/0",
            "bytes 0-18446744073709551615/18446744073709551615",
            "bytes 0-0/*",
        ] {
            assert!(
                UploadRange::parse(value).is_err(),
                "accepted malformed range {value:?}"
            );
        }
    }
}
