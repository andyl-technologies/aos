//! Fresh per-attempt artifact directories and stable artifact names.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Root under which fingerprint attempts receive exclusive directories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRunnerArtifactRoot {
    path: PathBuf,
}

impl LiveRunnerArtifactRoot {
    /// Validates an absolute artifact root.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerArtifactsError`] when `path` is not absolute.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, LiveRunnerArtifactsError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(LiveRunnerArtifactsError::RootNotAbsolute { path });
        }
        Ok(Self { path })
    }

    /// Returns the artifact root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates a fresh directory for exactly one attempt.
    ///
    /// Existing attempt directories are rejected instead of reused, preventing
    /// stale QMP sockets or traces from satisfying a later run.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerArtifactsError`] when the root cannot be created, the
    /// attempt directory already exists, or the fresh directory cannot be made.
    pub fn create_attempt(
        &self,
        attempt: u32,
    ) -> Result<LiveRunnerArtifacts, LiveRunnerArtifactsError> {
        fs::create_dir_all(&self.path).map_err(|source| LiveRunnerArtifactsError::Io {
            operation: "create artifact root",
            path: self.path.clone(),
            source,
        })?;
        let directory = self.path.join(format!("attempt-{attempt:08}"));
        fs::create_dir(&directory).map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                LiveRunnerArtifactsError::AttemptAlreadyExists {
                    path: directory.clone(),
                }
            } else {
                LiveRunnerArtifactsError::Io {
                    operation: "create fresh attempt directory",
                    path: directory.clone(),
                    source,
                }
            }
        })?;
        LiveRunnerArtifacts::from_fresh_directory(directory)
    }
}

/// Stable paths owned by one fresh fingerprint attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRunnerArtifacts {
    directory: PathBuf,
    qmp_socket: PathBuf,
    trace: PathBuf,
    preflight_trace: PathBuf,
    serial_log: PathBuf,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
}

impl LiveRunnerArtifacts {
    fn from_fresh_directory(directory: PathBuf) -> Result<Self, LiveRunnerArtifactsError> {
        let qmp_socket = directory.join("qmp.sock");
        if qmp_socket.as_os_str().as_encoded_bytes().len() >= 108 {
            return Err(LiveRunnerArtifactsError::QmpSocketPathTooLong { path: qmp_socket });
        }
        Ok(Self {
            qmp_socket,
            trace: directory.join("trace.jsonl"),
            preflight_trace: directory.join("preflight.jsonl"),
            serial_log: directory.join("serial.log"),
            stdout_log: directory.join("qemu.stdout.log"),
            stderr_log: directory.join("qemu.stderr.log"),
            directory,
        })
    }

    /// Returns the exclusive attempt directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns the QMP Unix socket path.
    #[must_use]
    pub fn qmp_socket(&self) -> &Path {
        &self.qmp_socket
    }

    /// Returns the regular observation trace path.
    #[must_use]
    pub fn trace(&self) -> &Path {
        &self.trace
    }

    /// Returns the definition-only preflight trace path.
    #[must_use]
    pub fn preflight_trace(&self) -> &Path {
        &self.preflight_trace
    }

    /// Returns the guest serial log path.
    #[must_use]
    pub fn serial_log(&self) -> &Path {
        &self.serial_log
    }

    /// Returns the QEMU stdout log path.
    #[must_use]
    pub fn stdout_log(&self) -> &Path {
        &self.stdout_log
    }

    /// Returns the QEMU stderr log path.
    #[must_use]
    pub fn stderr_log(&self) -> &Path {
        &self.stderr_log
    }
}

/// Failures while allocating fresh live-run artifacts.
#[derive(Debug, Error)]
pub enum LiveRunnerArtifactsError {
    /// Artifact root must be absolute.
    #[error("live-run artifact root is not absolute: {path}", path = path.display())]
    RootNotAbsolute {
        /// Rejected root.
        path: PathBuf,
    },
    /// An attempt directory would be reused.
    #[error("live-run attempt directory already exists: {path}", path = path.display())]
    AttemptAlreadyExists {
        /// Existing attempt directory.
        path: PathBuf,
    },
    /// Linux Unix-socket path limit would be exceeded.
    #[error("QMP Unix socket path is too long: {path}", path = path.display())]
    QmpSocketPathTooLong {
        /// Rejected socket path.
        path: PathBuf,
    },
    /// Filesystem operation failed.
    #[error("{operation} at {path} failed: {source}", path = path.display())]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Filesystem path involved.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEST_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn fresh_test_root(label: &str) -> Result<PathBuf, Box<dyn Error>> {
        let nonce = TEST_ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(std::env::temp_dir().join(format!("crucible-{label}-{}-{nonce}", std::process::id())))
    }

    #[test]
    fn attempt_paths_are_stable_and_reuse_is_rejected() -> Result<(), Box<dyn Error>> {
        let root_path = fresh_test_root("live-run-artifacts")?;
        let root = LiveRunnerArtifactRoot::new(&root_path)?;
        let attempt = root.create_attempt(7)?;
        assert_eq!(attempt.directory(), root_path.join("attempt-00000007"));
        assert_eq!(attempt.trace(), attempt.directory().join("trace.jsonl"));
        assert_eq!(
            attempt.preflight_trace(),
            attempt.directory().join("preflight.jsonl")
        );
        assert!(matches!(
            root.create_attempt(7),
            Err(LiveRunnerArtifactsError::AttemptAlreadyExists { .. })
        ));
        fs::remove_dir_all(root_path)?;
        Ok(())
    }
}
