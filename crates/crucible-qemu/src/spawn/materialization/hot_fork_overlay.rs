//! Guarded creation of one fresh overlay for a stopped hot-fork source.
//!
//! The original generation directory, helper child, process contract, and file
//! inode remain bound throughout creation and admission into the native graph.

use super::*;

impl QemuPreparedRunDirectory {
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
