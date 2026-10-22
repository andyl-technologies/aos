//! Binds retained preparation, borrowed admission and exact target moves.
//!
//! These complete producer clauses grant no Source funding or launched proof.

use super::Companion;

pub(super) const ADMISSION: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/supervision/node_step_gate.rs",
    required: &[
        (
            r##"pub(crate) struct AtomicExactRestoreAdmission<'a> {
    run_directory: &'a QemuPreparedRunDirectory,
    process_contract: &'a QemuChildProcessContract,
    identity: QemuLiveNodeIdentity<'a>,
    snapshot: &'a QemuVmSnapshot,
    ram_inputs: &'a crate::spawn::SealedAtomicExactRestoreInputs,
    device_file: File,
    cancellation_descriptor: BorrowedFd<'a>,
    exact_binding: crate::spawn::QemuExactDeviceStateBinding,
}"##,
            1,
        ),
        (
            r##"impl<'a> AtomicExactRestoreAdmission<'a> {
    /// Validates and binds the prepared storage, process, snapshot, and inputs.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNodeStepGateError`] when the prepared transaction is
    /// incomplete or any sealed input, request identity, or snapshot differs.
    pub(crate) fn admit(
        run_directory: &'a mut QemuPreparedRunDirectory,
        process_contract: &'a QemuChildProcessContract,
        identity: QemuLiveNodeIdentity<'a>,
        snapshot: &'a QemuVmSnapshot,
        snapshot_object: ContentHash,
        ram_inputs: &'a crate::spawn::SealedAtomicExactRestoreInputs,
        cancellation_descriptor: BorrowedFd<'a>,
    ) -> Result<Self, QemuLiveNodeStepGateError> {
        let exact_binding = ram_inputs.binding();
        let target = ram_inputs.target();
        if target.snapshot() != snapshot_object || target.node() != identity.node {
            return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from(
                    "repository-rooted target does not bind the launched node and snapshot",
                ),
            });
        }
        Self::new_with_binding(
            run_directory,
            process_contract,
            identity,
            snapshot,
            ram_inputs,
            cancellation_descriptor,
            exact_binding,
        )
    }

    pub(crate) fn new_with_binding(
        run_directory: &'a mut QemuPreparedRunDirectory,
        process_contract: &'a QemuChildProcessContract,
        identity: QemuLiveNodeIdentity<'a>,
        snapshot: &'a QemuVmSnapshot,
        ram_inputs: &'a crate::spawn::SealedAtomicExactRestoreInputs,
        cancellation_descriptor: BorrowedFd<'a>,
        exact_binding: crate::spawn::QemuExactDeviceStateBinding,
    ) -> Result<Self, QemuLiveNodeStepGateError> {
        let request = ram_inputs.request();
        if exact_binding.snapshot() != Some(ram_inputs.target().snapshot()) {
            return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from(
                    "authenticated exact-checkpoint root does not bind the restored snapshot",
                ),
            });
        }
        run_directory
            .validate_exact_ram_inputs(exact_binding, ram_inputs)
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        run_directory
            .claim_exact_checkpoint_materialization(process_contract, exact_binding)
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        let device_file = run_directory
            .exact_device_state_input(exact_binding)
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        let restore = QemuExactCheckpointRestore::new(
            request,
            ram_inputs.root_descriptor(),
            device_file.as_fd(),
            cancellation_descriptor,
        );
        validate_exact_checkpoint_restore(snapshot, restore)?;

        Ok(Self {
            run_directory,
            process_contract,
            identity,
            snapshot,
            ram_inputs,
            device_file,
            cancellation_descriptor,
            exact_binding,
        })
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn launch_atomic_exact_restore(
    config: &QemuLiveNodeStepGateConfig,
    request: AtomicExactRestoreAdmission<'_>,
    resume_restored: bool,
    original_native_binding: crate::linux_attempt_host::OriginalNativeNodeBinding,
    original_workspace: Option<crate::spawn::OriginalDeviceDigestWorkspace>,
) -> Result<crate::node::IssuedLaunchOwner, QemuLiveNodeStepGateError> {
    let descriptors = QemuExactCheckpointRestoreDescriptors::new(
        request.ram_inputs.root_descriptor(),
        request.device_file.as_fd(),
        request.cancellation_descriptor,
    );
    let restore = QemuNodeRestorePlan::exact_checkpoint(
        request.snapshot,
        request.ram_inputs.request(),
        descriptors,
        request.ram_inputs.topology(),
        request.ram_inputs.source(),
    );
    validate_restore_descriptors(&restore)?;
    let node = prepare_paused_live_node(
        config,
        LiveNodeAssembly {
            run_directory: request.run_directory,
            process_contract: request.process_contract,
            identity: request.identity,
            restore: Some(restore),
            resume_restored,
            exact_binding: Some(request.exact_binding),
            #[cfg(target_os = "linux")]
            original_native_binding: Some(original_native_binding),
            #[cfg(target_os = "linux")]
            original_workspace,
        },
    )?
    .prime_and_build_issued()?;
    Ok(node)
}
"##,
            1,
        ),
    ],
};

pub(super) const MATERIALIZATION: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/spawn/materialization/exact_restore.rs",
    required: &[(
        r##"pub(crate) fn materialize_production_exact_checkpoint(
        &mut self,
        process_contract: &QemuChildProcessContract,
        target: &mut Option<crucible_engine::exact_checkpoint::ExactCheckpointVerifiedNode>,
        source: QemuProductionExactRestoreSource,
        cancellation: BorrowedFd<'_>,
    ) -> Result<SealedAtomicExactRestoreInputs, QemuSpawnError> {
        if self.exact_checkpoint_target.is_some() {
            return Err(invalid_input(
                "retain exact restore target",
                "prepared directory already retains an authenticated target",
            ));
        }
        let target = target.take().ok_or_else(|| {
            invalid_input(
                "retain exact restore target",
                "authenticated target is absent",
            )
        })?;
        // The directory is already in its issued artifact guard. Retain the
        // actual relation there before validation or materialization effects.
        self.exact_checkpoint_target = Some(target);
        let target = self.exact_checkpoint_target.as_ref().ok_or_else(|| {
            invalid_input(
                "retain exact restore target",
                "authenticated target was lost",
            )
        })?;
        let QemuProductionExactRestoreSource {
            mut root_overlay,
            mut device_state,
            ram,
        } = source;
        let paged = target.paged_ram().map_err(|_| {
            invalid_input(
                "authenticate exact RAM source",
                "checkpoint RAM root is malformed",
            )
        })?;
        if paged.root_record() != ram.root_record()
            || paged.object_id().encode() != ram.root_object_id()
        {
            return Err(invalid_input(
                "authenticate exact RAM source",
                "retained backing differs from the checkpoint root",
            ));
        }
        let repository_root = ContentHash {
            bytes: target.repository_root().content_id().digest(),
        };
        process_contract.require_exact_checkpoint_root(repository_root)?;
        self.require_same_attempt(process_contract)?;

        let binding = QemuExactDeviceStateBinding::from_exact_checkpoint_root(
            target.root(),
            target.target_manifest(),
            target.snapshot(),
        );
        let (_, root_overlay_bytes) = target.root_overlay();
        let (_, device_content, device_state_bytes) = target.device_state();
        self.admit_exact_checkpoint_materialization_with_binding(
            binding,
            root_overlay_bytes,
            device_state_bytes,
        )?;
        let mut overlay = self.begin_atomic_exact_root_overlay(root_overlay_bytes)?;
        copy_exact_checkpoint_stream(
            &mut root_overlay,
            &mut overlay,
            cancellation,
            "copy exact root overlay",
        )?;
        overlay.finish()?;

        let mut device = self.begin_atomic_exact_device_state(device_state_bytes)?;
        copy_exact_checkpoint_stream(
            &mut device_state,
            &mut device,
            cancellation,
            "copy exact device state",
        )?;
        device.finish()?;
        require_exact_restore_not_canceled(cancellation)?;

        let metadata = ram.root_record().try_encode().map_err(|_| {
            invalid_input(
                "seal exact RAM metadata",
                "bounded RAM metadata encoding failed",
            )
        })?;
        let metadata_bytes = u64::try_from(metadata.len()).map_err(|_| {
            invalid_input(
                "seal exact RAM metadata",
                "RAM metadata length cannot be represented",
            )
        })?;
        let mut root =
            QemuExactCheckpointInputMaterialization::new(metadata_bytes).map_err(|source| {
                QemuSpawnError::Io {
                    operation: "create sealed RAM root metadata",
                    source,
                }
            })?;
        root.write_all(&metadata)
            .map_err(|source| QemuSpawnError::Io {
                operation: "write sealed RAM root metadata",
                source,
            })?;
        let root = root.finish().map_err(|source| QemuSpawnError::Io {
            operation: "seal RAM root metadata",
            source,
        })?;
        let (checkpoint, target_identity, frontier) = paged.identity();
        let descriptor = |name| {
            crate::QmpDescriptorName::new(name).map_err(|_| {
                invalid_input(
                    "seal exact restore admission",
                    "restore descriptor name is invalid",
                )
            })
        };
        let request = crate::QmpCheckpointRestoreRequest::new_paged(
            ram.root_record(),
            ram.binding(),
            crate::qmp::ram_restore::QmpCheckpointRestoreDescriptorNames {
                root: descriptor("crucible-ram-root")?,
                device: descriptor("crucible-device-state")?,
                cancellation: descriptor("crucible-cancellation")?,
            },
            device_content,
            crate::QmpCheckpointIdentity::new(checkpoint, target_identity, frontier),
            device_state_bytes,
        )
        .map_err(|_| {
            invalid_input(
                "seal exact restore admission",
                "restore metadata cannot form a bounded QMP request",
            )
        })?;
        self.revalidate_identity()?;
        self.revalidate_root_overlay_identity()?;
        fsync(&self.directory).map_err(|source| QemuSpawnError::Io {
            operation: "synchronize exact checkpoint materialization set",
            source: source.into(),
        })?;
        let target = self.exact_checkpoint_target.take().ok_or_else(|| {
            invalid_input(
                "seal exact restore admission",
                "authenticated target was consumed early",
            )
        })?;
        self.exact_checkpoint_materialization =
            PreparedExactCheckpointMaterialization::Complete { binding };
        Ok(SealedAtomicExactRestoreInputs {
            root,
            source: ram,
            binding,
            attempt_binding: Arc::clone(&self.attempt_binding),
            request,
            target,
        })
    }"##,
        1,
    )],
};
