//! Atomic and conditional SFTP writes.
//!
//! Every SFTP `PUT` writes a uniquely named sibling and renames it over the
//! destination, so a reader never observes a partially written object:
//!
//! ```text
//! <dir>/.<name>.aos-transfer-<pid>-<seq>   create exclusively, write, close
//! <dir>/<name>                             rename the sibling over it
//! ```
//!
//! # Replacing existing objects
//!
//! libssh2 asks for an overwriting, atomic rename, but SFTP protocol
//! version 3 (spoken by OpenSSH) has no rename flags, and OpenSSH refuses to
//! rename onto an existing file. The `posix-rename@openssh.com` extension
//! would replace atomically, but `ssh2` 0.9 does not expose it. When the
//! first rename fails and the destination exists, the destination is
//! unlinked and the rename retried. Readers can then briefly observe the
//! object as absent, but never as truncated or mixed.
//!
//! # Conditional writes
//!
//! A conditional write (see [`crate::protocol::conditional`]) creates
//! `<dir>/.<name>.lock` with `CREATE | EXCL`, hashes the current object,
//! writes atomically when the precondition holds, and removes the lock.
//! Conditional writers serialize against each other through that lock, which
//! also covers the unlink-and-rename window above. Unconditional writers do
//! not take it.
//!
//! # Manual testing
//!
//! The workspace has no SFTP server fixture. Ignored `aos-cache` tests
//! exercise both write paths against a disposable remote directory:
//!
//! ```text
//! export AOS_CACHE_TEST_SFTP_URL=sftp://user@host/tmp/aos-sftp-test
//! cargo test -p aos-cache --test backend_matrix -- --ignored sftp
//! cargo test -p aos-cache --test conditional_writes -- --ignored sftp
//! ```
//!
//! Test against both an OpenSSH server (unlink-and-rename fallback) and,
//! where available, a server that honors rename flags. Afterwards the remote
//! directory must contain no `.*.aos-transfer-*` temporaries and no `.*.lock`
//! files. To check lock contention, create `.generation.lock` beside a
//! record by hand and confirm that a conditional write fails naming it.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use ssh2::{ErrorCode, OpenFlags, OpenType, RenameFlags, Session, Sftp};

use super::SFTP_CHUNK_SIZE;
use crate::protocol::conditional::{
    content_version, lock_attempts, lock_file_contents, lock_file_name, lock_timeout_error,
    precondition_failed_result, written_result, WritePrecondition, LOCK_POLL,
};
use crate::types::TransferResult;

/// SFTP status for a missing path (`SSH_FX_NO_SUCH_FILE`,
/// draft-ietf-secsh-filexfer-02 section 7).
const SSH_FX_NO_SUCH_FILE: i32 = 2;

/// Permissions for created files, matching `ssh2::Sftp::create`.
const FILE_MODE: i32 = 0o644;

/// Permissions for a created parent directory.
const DIRECTORY_MODE: i32 = 0o755;

/// Distinguishes temporaries created concurrently by one process.
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Outcome of one attempt to take the lock and perform a conditional write.
enum ConditionalAttempt {
    /// Another writer holds the lock; nothing was read or written.
    Contended,
    /// The precondition was evaluated; the result reports whether the write
    /// happened.
    Completed(TransferResult),
}

/// Writes all of `source` to `destination` through a temporary sibling
/// that is renamed into place, returning the number of bytes written.
///
/// Like the historical in-place writer, this creates only the immediate
/// parent directory, and does so best effort.
pub(super) fn write_atomically(
    sftp: &Sftp,
    destination: &str,
    source: &mut dyn Read,
) -> Result<u64> {
    let destination = Path::new(destination);
    let (parent, filename) = split_destination(destination)?;
    let _ = sftp.mkdir(parent, DIRECTORY_MODE);

    let (temporary, mut file) = create_temporary(sftp, parent, filename)?;
    let written = copy_and_close(&mut file, source, &temporary)
        .and_then(|count| replace(sftp, &temporary, destination).map(|()| count));

    if written.is_err() {
        let _ = sftp.unlink(&temporary);
    }
    written
}

/// Writes `data` to `destination` only if `precondition` holds, waiting up
/// to `lock_wait` for a contended lock.
///
/// Each attempt runs on the blocking pool and holds the session only while
/// it works, so other transfers on the cached session progress between
/// polls.
pub(super) async fn conditional_put(
    session: Arc<Mutex<Session>>,
    destination: String,
    data: Vec<u8>,
    precondition: WritePrecondition,
    lock_wait: Duration,
) -> Result<TransferResult> {
    let lock = lock_path(Path::new(&destination))?;
    let data = Arc::new(data);

    for attempt in 1..=lock_attempts(lock_wait) {
        if attempt > 1 {
            tokio::time::sleep(LOCK_POLL).await;
        }

        let session = Arc::clone(&session);
        let path = destination.clone();
        let bytes = Arc::clone(&data);
        let expected = precondition.clone();

        let attempt = tokio::task::spawn_blocking(move || {
            let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
            let sftp = session.sftp().context("opening SFTP channel")?;
            try_conditional_write(&sftp, &path, &bytes, &expected)
        })
        .await
        .context("SFTP conditional write task panicked")??;

        if let ConditionalAttempt::Completed(result) = attempt {
            return Ok(result);
        }
    }

    Err(lock_timeout_error(&lock.display().to_string(), lock_wait))
}

/// Takes the destination's lock once and, if acquired, evaluates the
/// precondition and writes. The lock is always removed before returning.
fn try_conditional_write(
    sftp: &Sftp,
    destination: &str,
    data: &[u8],
    precondition: &WritePrecondition,
) -> Result<ConditionalAttempt> {
    let destination = Path::new(destination);
    let (parent, _) = split_destination(destination)?;
    let _ = sftp.mkdir(parent, DIRECTORY_MODE);

    let lock = lock_path(destination)?;
    let flags = OpenFlags::WRITE | OpenFlags::EXCLUSIVE;
    match sftp.open_mode(&lock, flags, FILE_MODE, OpenType::File) {
        Ok(mut file) => {
            // The lock's existence is what serializes writers; its contents
            // only help an operator identify a stale lock.
            let _ = file.write_all(lock_file_contents().as_bytes());
        }
        Err(error) => {
            // SFTPv3 reports an existing file as a generic failure, so
            // contention is confirmed by looking for the lock itself.
            return if path_exists(sftp, &lock)? {
                Ok(ConditionalAttempt::Contended)
            } else {
                Err(error).with_context(|| format!("creating lock file {}", lock.display()))
            };
        }
    }

    let outcome = compare_and_write(sftp, destination, data, precondition);

    // A leftover lock blocks later conditional writers with an explicit
    // timeout that names it, so a failed removal must not misreport a write
    // that already committed.
    if let Err(error) = sftp.unlink(&lock) {
        tracing::warn!("removing lock file {}: {error}", lock.display());
    }

    outcome.map(ConditionalAttempt::Completed)
}

/// Compares the current version of `destination` with `precondition` and
/// replaces it with `data` when it matches. Callers hold the lock.
fn compare_and_write(
    sftp: &Sftp,
    destination: &Path,
    data: &[u8],
    precondition: &WritePrecondition,
) -> Result<TransferResult> {
    let current = read_version(sftp, destination)?;
    if !precondition.is_satisfied_by(current.as_deref()) {
        return Ok(precondition_failed_result(current));
    }

    let path = destination
        .to_str()
        .context("SFTP destination path is not UTF-8")?;
    let mut source = data;
    write_atomically(sftp, path, &mut source)?;

    Ok(written_result(content_version(data), data.len() as u64))
}

/// Returns the [`content_version`] of the object at `path`, or `None` when
/// it does not exist. Any other failure is an error, so an unreadable
/// object is never mistaken for an absent one.
fn read_version(sftp: &Sftp, path: &Path) -> Result<Option<String>> {
    let mut file = match sftp.open(path) {
        Ok(file) => file,
        Err(error) if is_no_such_file(&error) => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("opening {}", path.display())),
    };

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(content_version(&bytes)))
}

/// Exclusively creates a fresh temporary sibling of `filename` in `parent`.
fn create_temporary(sftp: &Sftp, parent: &Path, filename: &str) -> Result<(PathBuf, ssh2::File)> {
    let flags = OpenFlags::WRITE | OpenFlags::EXCLUSIVE;

    for _ in 0..16 {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".{filename}.aos-transfer-{}-{sequence}",
            std::process::id()
        ));

        match sftp.open_mode(&temporary, flags, FILE_MODE, OpenType::File) {
            Ok(file) => return Ok((temporary, file)),
            // Another host's process may share our pid; try the next name.
            Err(_) if path_exists(sftp, &temporary)? => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("creating temp file {}", temporary.display()));
            }
        }
    }

    anyhow::bail!(
        "could not reserve a temporary file beside {}/{filename}",
        parent.display()
    )
}

/// Streams `source` into `file` in chunks and closes it, surfacing any
/// error the server reports on close.
fn copy_and_close(file: &mut ssh2::File, source: &mut dyn Read, temporary: &Path) -> Result<u64> {
    let mut buffer = vec![0_u8; SFTP_CHUNK_SIZE];
    let mut written: u64 = 0;

    loop {
        let count = source.read(&mut buffer).context("reading upload source")?;
        if count == 0 {
            break;
        }
        file.write_all(&buffer[..count])
            .with_context(|| format!("writing {}", temporary.display()))?;
        written += count as u64;
    }

    file.close()
        .with_context(|| format!("closing {}", temporary.display()))?;
    Ok(written)
}

/// Renames `temporary` over `destination`, falling back to unlink and
/// rename on servers that cannot overwrite (see the module docs).
fn replace(sftp: &Sftp, temporary: &Path, destination: &Path) -> Result<()> {
    let flags = Some(RenameFlags::OVERWRITE | RenameFlags::ATOMIC | RenameFlags::NATIVE);
    let rename_error = match sftp.rename(temporary, destination, flags) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };

    // Only an existing destination explains the refusal; anything else is a
    // genuine failure and is reported as such.
    if !path_exists(sftp, destination).unwrap_or(false) {
        return Err(rename_error).with_context(|| {
            format!(
                "renaming {} to {}",
                temporary.display(),
                destination.display()
            )
        });
    }

    sftp.unlink(destination)
        .with_context(|| format!("removing {} before replacement", destination.display()))?;
    sftp.rename(temporary, destination, flags).with_context(|| {
        format!(
            "renaming {} to {}",
            temporary.display(),
            destination.display()
        )
    })
}

/// Returns whether `path` exists, treating only `SSH_FX_NO_SUCH_FILE` as
/// absence.
fn path_exists(sftp: &Sftp, path: &Path) -> Result<bool> {
    match sftp.stat(path) {
        Ok(_) => Ok(true),
        Err(error) if is_no_such_file(&error) => Ok(false),
        Err(error) => Err(error).with_context(|| format!("stat {}", path.display())),
    }
}

/// Returns whether an SFTP error reports a missing path.
fn is_no_such_file(error: &ssh2::Error) -> bool {
    error.code() == ErrorCode::SFTP(SSH_FX_NO_SUCH_FILE)
}

/// Returns the path of the lock file guarding conditional writes of
/// `destination`.
fn lock_path(destination: &Path) -> Result<PathBuf> {
    let (parent, filename) = split_destination(destination)?;
    Ok(parent.join(lock_file_name(filename)))
}

/// Splits a remote destination into its parent directory and UTF-8 file
/// name.
fn split_destination(destination: &Path) -> Result<(&Path, &str)> {
    let parent = destination
        .parent()
        .context("SFTP destination has no parent directory")?;
    let filename = destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("SFTP destination filename is not UTF-8")?;
    Ok((parent, filename))
}
