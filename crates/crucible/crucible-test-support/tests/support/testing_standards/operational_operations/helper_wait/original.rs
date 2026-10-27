//! Binds late helper effects to the actual paused node and entered Original.
//!
//! Closed constructors, real installed shares and retained event checks cannot
//! be replaced by same-Main guards or copied generation facts.

use super::Companion;

pub(super) const OWNER: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/node/hot_fork_source_original.rs",
    required: &[
        (
            r#"pub struct QemuHotForkSourceOriginal {
    lender: SourceCleanupLender,
    original: CheckpointOriginalLoan,
}"#,
            1,
        ),
        (
            r#"impl QemuHotForkSourceOriginal {
    pub(crate) fn guard(&self) -> &HostOperationGuard {
        self.original.guard()
    }

    pub(crate) fn check(&self, receiver: &SourceCleanupLender) -> Result<(), HostSupervisionError> {
        if !self.lender.same_identity(receiver) {
            return Err(HostSupervisionError::Unavailable);
        }
        self.lender
            .controller()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        self.original.check()
    }

    pub(crate) fn checked_original(
        &self,
        receiver: &SourceCleanupLender,
    ) -> Result<&HostOperationGuard, crate::QemuSpawnError> {
        self.check(receiver)
            .map_err(|source| crate::QemuSpawnError::SourceAdmission {
                source: source.into(),
            })?;
        Ok(self.guard())
    }
}"#,
            1,
        ),
        (
            r#"impl QemuNode {
    pub(crate) fn hot_fork_source_original(
        &self,
    ) -> Result<QemuHotForkSourceOriginal, QemuNodeError> {
        let lender = self
            .original_native_binding
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)
            .and_then(|binding| binding.source_helper_lender())
            .map_err(|_| QemuNodeError::CheckpointOriginal {
                source: CheckpointOriginalError::before(
                    CheckpointOriginalCause::SourceBindingUnavailable,
                ),
            })?;
        let original = self.checkpoint_original_loan()?;
        Ok(QemuHotForkSourceOriginal { lender, original })
    }
}"#,
            1,
        ),
    ],
};

pub(super) const SOURCE: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster/process_purpose/source_cleanup.rs",
    required: &[(
        r#"impl OriginalNativeNodeBinding {
    /// Borrows the live Source share actually retained by this installed node.
    pub(crate) fn source_helper_lender(
        &self,
    ) -> Result<SourceCleanupLender, OriginalActorAccountError> {
        let installed = self
            .installed_process
            .as_ref()
            .filter(|installed| {
                installed.subdivision_index == 0
                    && installed.index == self.index
                    && installed.generation == self.generation
                    && RosterWeak::ptr_eq(&installed.roster, &self.roster)
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let lender = SourceCleanupLender {
            roster: RosterWeak::clone(&installed.roster),
            index: installed.index,
            generation: installed.generation,
            process_generation: Some(installed.process_generation),
        };
        lender.controller()?;
        Ok(lender)
    }
}"#,
        1,
    )],
};

pub(super) const PAUSE: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/node_set/disk_seal.rs",
    required: &[(
        r#"pub fn begin_hot_fork_disk_seal(
        &mut self,
        node: &NodeId,
    ) -> Result<
        (
            crate::QmpHotForkBlockSealState,
            crate::QemuHotForkSourceOriginal,
        ),
        BackendError,
    > {
        self.node_mut(node)?
            .pause_for_hot_fork_template()
            .map_err(|error| BackendError::Rejected {
                message: format!("pause hot-fork disk source: {error}"),
            })?;
        let original = self
            .node_mut(node)?
            .hot_fork_source_original()
            .map_err(|error| BackendError::Rejected {
                message: format!("retain hot-fork Source original: {error}"),
            })?;
        let state = self
            .node_mut(node)?
            .query_hot_fork_block_seal()
            .map_err(|error| BackendError::Rejected {
                message: format!("query current hot-fork disk roots: {error}"),
            })?;
        Ok((state, original))
    }"#,
        1,
    )],
};

pub(super) const MATERIALIZATION: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/spawn/materialization/hot_fork_overlay.rs",
    required: &[(
        r#"pub fn prepare_hot_fork_detached_root_overlay_guarded(
        &self,
        qemu_executable: &Path,
        process_contract: &QemuChildProcessContract,
        effect_original: &crate::QemuHotForkSourceOriginal,
        graph_generation: u64,
        virtual_size: u64,
    ) -> Result<(File, std::path::PathBuf), crate::spawn::QemuGuardedImagePreparationError> {
        let fail = |source| crate::spawn::QemuGuardedImagePreparationError::local(source);
        if !self.launch_resources.has_root_overlay() || graph_generation == 0 || virtual_size == 0 {
            return Err(fail(QemuSpawnError::Io {
                operation: "admit detached hot-fork root overlay",
                source: io::Error::new(io::ErrorKind::InvalidInput, "invalid root or size"),
            }));
        }
        self.validate_retained_source_helper_basis(process_contract)
            .map_err(fail)?;
        let receiver = process_contract
            .retained_source_helper_lender()
            .map_err(fail)?;
        effect_original.checked_original(&receiver).map_err(fail)?;
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
        crate::spawn::run_guarded_image_tool_with_original(
            &image_tool,
            &args,
            "create detached hot-fork root overlay",
            self,
            process_contract,
            crate::spawn::GuardedImageToolPurpose::RetainedHotForkSource,
            Some(effect_original),
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
    }"#,
        1,
    )],
};
