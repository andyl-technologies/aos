//! Supplies the current process's genuine memory leaf beneath protected ancestry.
//!
//! A protected Nix harness supplies explicit mount tools. Native runs retain the
//! original numeric proc path. Both paths expose the same physical memory leaf;
//! reading unmapped address zero still fails in the actual native body read.

use std::fs::{File, Metadata};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const MOUNT_TOOL: &str = "TERRANE_TEST_PROC_MOUNT";
const UNMOUNT_TOOL: &str = "TERRANE_TEST_PROC_UMOUNT";

/// Retains a genuine process-memory leaf and its optional private bind mount.
pub(super) struct ActualBodyReadEio {
    path: PathBuf,
    alias: Option<ProcessAlias>,
}

impl ActualBodyReadEio {
    /// Creates a genuine memory leaf under the harness's physical ancestry.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete tool configuration, failed native setup,
    /// or a bind mount that changes the captured process or leaf identity.
    pub(super) fn new() -> io::Result<Self> {
        let process = PathBuf::from(format!("/proc/{}", std::process::id()));
        let tools = match (std::env::var_os(MOUNT_TOOL), std::env::var_os(UNMOUNT_TOOL)) {
            (None, None) => None,
            (Some(mount), Some(unmount)) => {
                let mount = PathBuf::from(mount);
                let unmount = PathBuf::from(unmount);
                if !mount.is_absolute() || !unmount.is_absolute() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "proc fixture tools must be absolute paths",
                    ));
                }
                Some((mount, unmount))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "proc fixture requires both explicit tools",
                ));
            }
        };
        let Some((mount, unmount)) = tools else {
            return Ok(Self {
                path: process.join("mem"),
                alias: None,
            });
        };

        // Open handles retain the source inodes across the second pathname lookup.
        let source_process = File::open(&process)?;
        let source_mem = File::open(process.join("mem"))?;
        let process_identity = physical_identity(&source_process.metadata()?);
        let mem_identity = physical_identity(&source_mem.metadata()?);
        static SERIAL: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "native-body-read-eio-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let mountpoint = root.join("process");
        let mut alias = ProcessAlias {
            root: Some(root),
            mountpoint,
            unmount,
            mounted: false,
            source_process,
            source_mem,
        };
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&alias.mountpoint)?;

        // A tool may establish the bind before reporting failure. Treat every
        // attempt as mounted so cleanup never traverses an uncertain proc tree.
        alias.mounted = true;
        let status = Command::new(mount)
            .args(["--bind", "--"])
            .arg(&process)
            .arg(&alias.mountpoint)
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "proc fixture bind mount failed: {status}",
            )));
        }
        let path = alias.mountpoint.join("mem");
        if physical_identity(&std::fs::symlink_metadata(&alias.mountpoint)?) != process_identity
            || physical_identity(&std::fs::symlink_metadata(&path)?) != mem_identity
            || physical_identity(&alias.source_process.metadata()?) != process_identity
            || physical_identity(&alias.source_mem.metadata()?) != mem_identity
        {
            return Err(io::Error::other(
                "proc fixture bind changed physical identity",
            ));
        }
        Ok(Self {
            path,
            alias: Some(alias),
        })
    }

    /// Returns the actual native memory pathname checked by the witness.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Completes unmounting before any recursive fixture cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error if the private mount cannot be detached or removed.
    pub(super) fn finish(mut self) -> io::Result<()> {
        if let Some(alias) = &mut self.alias {
            alias.cleanup()?;
        }
        Ok(())
    }
}

struct ProcessAlias {
    root: Option<PathBuf>,
    mountpoint: PathBuf,
    unmount: PathBuf,
    mounted: bool,
    source_process: File,
    source_mem: File,
}

impl ProcessAlias {
    fn cleanup(&mut self) -> io::Result<()> {
        if self.mounted {
            let status = Command::new(&self.unmount)
                .arg("--")
                .arg(&self.mountpoint)
                .status()?;
            if !status.success() {
                return Err(io::Error::other(format!(
                    "proc fixture unmount failed: {status}",
                )));
            }
            self.mounted = false;
        }
        if let Some(root) = &self.root {
            std::fs::remove_dir_all(root)?;
            self.root = None;
        }
        Ok(())
    }
}

impl Drop for ProcessAlias {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            // Retain a still-mounted private root. Explicit completion reports
            // failures without masking an existing setup error or panic.
            let _ = writeln!(io::stderr().lock(), "proc fixture cleanup failed: {error}");
        }
    }
}

fn physical_identity(metadata: &Metadata) -> (u64, u64, u32, u32, u32, u64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
    )
}

#[cfg(test)]
mod tests {
    //! Checks completion and panic cleanup against the genuine memory inode.

    #![allow(
        clippy::unwrap_used,
        reason = "Fixture assertions intentionally panic."
    )]

    use super::*;

    #[test]
    fn genuine_memory_fixture_cleans_up_after_completion_and_unwind() {
        let native_path = PathBuf::from(format!("/proc/{}/mem", std::process::id()));
        let native = File::open(&native_path).unwrap();
        let native_identity = physical_identity(&native.metadata().unwrap());

        let completed = ActualBodyReadEio::new().unwrap();
        let configured =
            std::env::var_os(MOUNT_TOOL).is_some() && std::env::var_os(UNMOUNT_TOOL).is_some();
        assert_eq!(completed.alias.is_some(), configured);
        if !configured {
            assert_eq!(completed.path(), native_path);
        }
        let completed_root = completed
            .alias
            .as_ref()
            .and_then(|alias| alias.root.clone());
        assert_eq!(
            physical_identity(&std::fs::symlink_metadata(completed.path()).unwrap()),
            native_identity,
        );
        completed.finish().unwrap();
        if let Some(root) = completed_root {
            assert!(!root.exists());
        }

        let unwinding = ActualBodyReadEio::new().unwrap();
        assert_eq!(unwinding.alias.is_some(), configured);
        let unwinding_root = unwinding
            .alias
            .as_ref()
            .and_then(|alias| alias.root.clone());
        assert_eq!(
            physical_identity(&std::fs::symlink_metadata(unwinding.path()).unwrap()),
            native_identity,
        );
        let result = std::panic::catch_unwind(move || {
            let _fixture = unwinding;
            panic!("exercise memory fixture cleanup during unwinding");
        });
        assert!(result.is_err());
        if let Some(root) = unwinding_root {
            assert!(!root.exists());
        }

        assert_eq!(
            physical_identity(&native.metadata().unwrap()),
            native_identity,
        );
        assert_eq!(
            physical_identity(&std::fs::symlink_metadata(&native_path).unwrap()),
            native_identity,
        );
    }
}
