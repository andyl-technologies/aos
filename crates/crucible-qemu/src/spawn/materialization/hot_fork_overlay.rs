//! Guarded creation of one fresh overlay for a stopped hot-fork source.
//!
//! The original generation directory, helper child, process contract, and file
//! inode remain bound throughout creation and admission into the native graph.

use super::*;
use crate::spawn::invalid_input;
use rustix::fs::open;

impl QemuPreparedRunDirectory {
    /// Authenticates an overlay basename under the original source working directory.
    ///
    /// The native process retains its launch cwd even when its ancestor is
    /// private to the supervisor. This checks that actual cwd against the
    /// retained directory and the named file against the admitted open inode.
    ///
    /// # Errors
    ///
    /// Returns an error on a different cwd, generation path, named inode, or
    /// missing source process. The caller also retains full process identity.
    pub fn authenticate_hot_fork_overlay_name(
        &self,
        source_pid: u32,
        file: &File,
        path: &Path,
    ) -> Result<std::path::PathBuf, QemuSpawnError> {
        self.revalidate_identity()?;
        let name = path
            .file_name()
            .filter(|_| path.parent() == Some(self.path.as_path()))
            .ok_or_else(|| {
                invalid_input(
                    "authenticate original hot-fork overlay",
                    "detached overlay is outside its original directory",
                )
            })?;
        let cwd = open(
            format!("/proc/{source_pid}/cwd").as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "open original hot-fork source cwd",
            source: source.into(),
        })?;
        let cwd_metadata = fstat(&cwd).map_err(|source| QemuSpawnError::Io {
            operation: "inspect original hot-fork source cwd",
            source: source.into(),
        })?;
        let directory_metadata = fstat(&self.directory).map_err(|source| QemuSpawnError::Io {
            operation: "inspect retained hot-fork directory",
            source: source.into(),
        })?;
        if cwd_metadata.st_dev != directory_metadata.st_dev
            || cwd_metadata.st_ino != directory_metadata.st_ino
        {
            return Err(invalid_input(
                "authenticate original hot-fork overlay",
                "hot-fork source cwd differs from its retained generation",
            ));
        }
        let named = openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "reopen admitted detached overlay",
            source: source.into(),
        })?;
        let named_metadata = fstat(&named).map_err(|source| QemuSpawnError::Io {
            operation: "inspect admitted detached overlay name",
            source: source.into(),
        })?;
        let retained = fstat(file).map_err(|source| QemuSpawnError::Io {
            operation: "inspect admitted detached overlay inode",
            source: source.into(),
        })?;
        if rustix::fs::FileType::from_raw_mode(retained.st_mode)
            != rustix::fs::FileType::RegularFile
            || retained.st_nlink != 1
            || retained.st_dev != named_metadata.st_dev
            || retained.st_ino != named_metadata.st_ino
            || retained.st_size != named_metadata.st_size
        {
            return Err(invalid_input(
                "authenticate original hot-fork overlay",
                "detached overlay name no longer binds its admitted regular inode",
            ));
        }
        Ok(std::path::PathBuf::from(name))
    }

    /// Creates one detached empty qcow2 overlay for a stopped hot-fork root.
    ///
    /// The sibling source-built image tool runs under this generation's exact
    /// cgroup, cancellation, credentials, directory, and resource contract.
    /// The new name is exclusive and remains in the source directory until
    /// QEMU either installs it or the owning source is reconciled. A failed
    /// command may leave that named file as explicit cleanup debt.
    ///
    /// # Errors
    ///
    /// Returns a guarded image error, possibly retaining an unreaped helper,
    /// if the directory, contract, helper, or resulting inode fails admission.
    pub fn prepare_hot_fork_detached_root_overlay_guarded(
        &self,
        qemu_executable: &Path,
        process_contract: &QemuChildProcessContract,
        graph_generation: u64,
        virtual_size: u64,
    ) -> Result<(File, std::path::PathBuf), crate::spawn::QemuGuardedImagePreparationError> {
        let fail = |source| crate::spawn::QemuGuardedImagePreparationError {
            source,
            child: None,
        };
        if !self.launch_resources.has_root_overlay() || graph_generation == 0 || virtual_size == 0 {
            return Err(fail(QemuSpawnError::Io {
                operation: "admit detached hot-fork root overlay",
                source: io::Error::new(io::ErrorKind::InvalidInput, "invalid root or size"),
            }));
        }
        self.validate_helper_basis(process_contract).map_err(fail)?;
        let image_tool = qemu_executable.with_file_name("qemu-img");
        if !image_tool.is_absolute() {
            return Err(fail(QemuSpawnError::FreshImageToolPath {
                path: image_tool,
            }));
        }

        let file_name = format!("crucible-hot-fork-overlay-{graph_generation}.qcow2");
        let file = openat(
            &self.directory,
            file_name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|source| {
            fail(QemuSpawnError::Io {
                operation: "reserve detached hot-fork root overlay",
                source: source.into(),
            })
        })?;
        let original = fstat(&file).map_err(|source| {
            fail(QemuSpawnError::Io {
                operation: "inspect detached hot-fork root overlay",
                source: source.into(),
            })
        })?;

        // The helper drops to the generation's admitted credentials before it
        // opens this reserved inode. Keep the file private to that same owner.
        if let Some(credentials) = self.child_credentials {
            fchown(
                &file,
                Some(Uid::from_raw(credentials.user_id)),
                Some(Gid::from_raw(credentials.group_id)),
            )
            .map_err(|source| {
                fail(QemuSpawnError::Io {
                    operation: "assign detached hot-fork root-overlay ownership",
                    source: source.into(),
                })
            })?;
        }

        let args = [
            OsString::from("create"),
            OsString::from("-q"),
            OsString::from("-f"),
            OsString::from("qcow2"),
            OsString::from(&file_name),
            OsString::from(format!("{virtual_size}B")),
        ];
        crate::spawn::run_guarded_image_tool(
            &image_tool,
            &args,
            "create detached hot-fork root overlay",
            self,
            process_contract,
        )?;

        let named = openat(
            &self.directory,
            file_name.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| {
            fail(QemuSpawnError::Io {
                operation: "reopen detached hot-fork root overlay",
                source: source.into(),
            })
        })?;
        let after = fstat(&named).map_err(|source| {
            fail(QemuSpawnError::Io {
                operation: "inspect created hot-fork root overlay",
                source: source.into(),
            })
        })?;
        if original.st_dev != after.st_dev
            || original.st_ino != after.st_ino
            || after.st_size <= 0
            || after.st_size as u64 > self.admitted_ceiling.2
        {
            return Err(fail(QemuSpawnError::Io {
                operation: "authenticate detached hot-fork root overlay",
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "image inode changed or is empty",
                ),
            }));
        }
        fsync(&file).map_err(|source| {
            fail(QemuSpawnError::Io {
                operation: "synchronize detached hot-fork root overlay",
                source: source.into(),
            })
        })?;
        fsync(&self.directory).map_err(|source| {
            fail(QemuSpawnError::Io {
                operation: "synchronize detached hot-fork directory",
                source: source.into(),
            })
        })?;
        Ok((File::from(file), self.path.join(file_name)))
    }
}
