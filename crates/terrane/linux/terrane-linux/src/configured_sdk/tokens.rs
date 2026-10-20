//! Loads bounded exposure capabilities from retained ordinary native files.

use std::{
    fmt,
    fs::File,
    io::{self, Read},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

use rustix::fs::{Mode, OFlags, open, openat};
use terrane_sdk::{repository::Error as RepositoryError, surface::TokenResolver};

use crate::quota_confinement::Installed;

use super::preflight::canonical_path;

/// Bounds one native credential input without changing the portable token format.
///
/// This adapter accepts at most one mebibyte per token file. Larger canonical
/// capabilities require a future explicit native budget, not an encoding change.
pub const TOKEN_FILE_BYTE_BUDGET: usize = 1024 * 1024;

pub(super) struct FileTokens<'receipt> {
    pub(super) installed: &'receipt Installed,
}

#[async_trait::async_trait]
impl TokenResolver for FileTokens<'_> {
    async fn resolve(&self, reference: &str) -> Result<Vec<u8>, RepositoryError> {
        self.installed.check_current()?;
        let path = credential_path(reference).map_err(repository_error)?;
        let result = tokio::task::spawn_blocking(move || read_token(&path))
            .await
            .map_err(|_| {
                RepositoryError::Io(io::Error::other("exposure credential task failed"))
            })?;
        self.installed.check_current()?;
        result.map_err(repository_error)
    }
}

pub(super) fn credential_path(reference: &str) -> Result<PathBuf, TokenFileError> {
    let raw = reference.strip_prefix("file:").unwrap_or(reference);
    let path = Path::new(raw);
    if !canonical_path(path) {
        return Err(TokenFileError::InvalidReference);
    }
    Ok(path.to_owned())
}

pub(super) fn read_token(path: &Path) -> Result<Vec<u8>, TokenFileError> {
    if !canonical_path(path) {
        return Err(TokenFileError::InvalidReference);
    }
    let components: Vec<_> = path.components().collect();
    let Some((Component::Normal(name), parents)) = components.split_last() else {
        return Err(TokenFileError::InvalidReference);
    };
    let directory_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open("/", directory_flags, Mode::empty()).map_err(native_error)?;
    for component in parents {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, *name, directory_flags, Mode::empty())
                    .map_err(native_error)?;
            }
            _ => return Err(TokenFileError::InvalidReference),
        }
    }

    // O_PATH never invokes a device's readable open or waits for a FIFO writer.
    // Classify the retained inode before obtaining any descriptor that can read.
    let descriptor = openat(
        &directory,
        *name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(native_error)?;
    let retained = File::from(descriptor);
    let before = retained.metadata().map_err(io_error)?;
    if !before.is_file() {
        return Err(TokenFileError::NotRegular);
    }
    if before.len() > TOKEN_FILE_BYTE_BUDGET as u64 {
        return Err(TokenFileError::TooLarge);
    }

    // Bootstrap authenticates procfs before Tokio exists. The private retained
    // descriptor cannot be recycled while alive. Only this checked regular inode
    // is reopened through procfs; no caller-supplied magic-link path is accepted.
    let descriptor_path = format!("/proc/self/fd/{}", retained.as_raw_fd());
    let readable = open(
        descriptor_path.as_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(native_error)?;
    let file = File::from(readable);
    let opened = file.metadata().map_err(io_error)?;
    if !same_file(&before, &opened) {
        return Err(TokenFileError::Changed);
    }

    let mut bytes = Vec::new();
    file.take(TOKEN_FILE_BYTE_BUDGET as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > TOKEN_FILE_BYTE_BUDGET {
        return Err(TokenFileError::TooLarge);
    }
    let after = retained.metadata().map_err(io_error)?;
    if !same_file(&before, &after) || bytes.len() as u64 != before.len() {
        return Err(TokenFileError::Changed);
    }
    if bytes.is_empty() {
        return Err(TokenFileError::Empty);
    }
    Ok(bytes)
}

fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn native_error(error: rustix::io::Errno) -> TokenFileError {
    io_error(error.into())
}

fn io_error(error: io::Error) -> TokenFileError {
    // Native errors retain only their closed I/O category. In particular no
    // credential reference, file contents or provider-controlled text survives.
    TokenFileError::Io(error.kind())
}

fn repository_error(error: TokenFileError) -> RepositoryError {
    RepositoryError::Io(io::Error::new(error.io_kind(), error))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TokenFileError {
    InvalidReference,
    NotRegular,
    TooLarge,
    Changed,
    Empty,
    Io(io::ErrorKind),
}

impl TokenFileError {
    fn io_kind(self) -> io::ErrorKind {
        match self {
            Self::Io(kind) => kind,
            Self::InvalidReference | Self::NotRegular => io::ErrorKind::InvalidInput,
            Self::TooLarge | Self::Changed | Self::Empty => io::ErrorKind::InvalidData,
        }
    }
}

impl fmt::Display for TokenFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("native exposure credential could not be read safely")
    }
}

impl std::error::Error for TokenFileError {}
