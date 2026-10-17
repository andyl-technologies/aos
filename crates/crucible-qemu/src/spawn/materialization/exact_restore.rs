//! Authenticated overlay, device state, and lazy RAM-root admission.

use super::super::invalid_input;
use super::*;

impl QemuPreparedRunDirectory {
    /// Materializes non-RAM bytes and seals bounded RAM metadata for lazy restore.
    ///
    /// The retained source already owns its immutable storage lease. RAM pages
    /// stay in that source and are authenticated individually when requested.
    /// Any failure leaves the destination unlaunchable.
    ///
    /// # Errors
    ///
    /// Returns an error for a changed attempt, mismatched authenticated source,
    /// excessive non-RAM storage, failed stream authentication, or sealing failure.
    pub(crate) fn materialize_production_exact_checkpoint(
        &mut self,
        process_contract: &QemuChildProcessContract,
        target: crucible::exact_checkpoint::ExactCheckpointVerifiedNode,
        source: QemuProductionExactRestoreSource,
        cancellation: BorrowedFd<'_>,
    ) -> Result<SealedAtomicExactRestoreInputs, QemuSpawnError> {
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
        self.exact_checkpoint_target = Some(target);

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
    }

    fn admit_exact_checkpoint_materialization_with_binding(
        &mut self,
        binding: QemuExactDeviceStateBinding,
        root_overlay_bytes: u64,
        device_state_bytes: u64,
    ) -> Result<(), QemuSpawnError> {
        if self.exact_checkpoint_materialization != PreparedExactCheckpointMaterialization::Absent {
            return Err(invalid_input(
                "admit exact checkpoint materialization",
                "an exact checkpoint was already admitted",
            ));
        }
        if !self.launch_resources.has_root_overlay()
            || root_overlay_bytes == 0
            || device_state_bytes == 0
        {
            return Err(invalid_input(
                "admit exact checkpoint materialization",
                "non-RAM artifact geometry is invalid",
            ));
        }
        let aggregate = device_state_bytes
            .checked_add(root_overlay_bytes)
            .and_then(|bytes| {
                bytes.checked_add(crucible_ram::Limits::default().max_record_bytes as u64)
            });
        if aggregate.is_none_or(|bytes| bytes > self.admitted_ceiling.2) {
            return Err(QemuSpawnError::PreparedExactCheckpointArtifactsTooLarge {
                device_state_bytes,
                root_overlay_bytes,
                ram_bytes: crucible_ram::Limits::default().max_record_bytes as u64,
                maximum: self.admitted_ceiling.2,
            });
        }
        if self.exact_device_state_materialization
            != PreparedDeviceStateMaterialization::Provisioned
            || self.root_overlay_materialization != PreparedRootOverlayMaterialization::Absent
        {
            return Err(invalid_input(
                "admit exact checkpoint materialization",
                "prepared destinations are not empty",
            ));
        }
        self.revalidate_identity()?;
        self.exact_checkpoint_materialization = PreparedExactCheckpointMaterialization::Updating {
            binding,
            device_state_bytes,
            root_overlay_bytes,
        };
        Ok(())
    }
}
