//! Exact-checkpoint materialization for guarded QEMU run directories.

use super::super::invalid_input;
use super::*;

impl QemuPreparedRunDirectory {
    /// Authenticates and seals every artifact for one exact restore.
    ///
    /// The method drains the complete source streams and validates the bound
    /// sparse-overlay identity plus device and RAM SHA-256 identities. It
    /// returns no writable staging handle. Any error leaves the directory
    /// unlaunchable.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the target belongs to another attempt,
    /// the stream count or bytes differ, or a destination cannot be sealed.
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
            ram_layers,
        } = source;
        if ram_layers.len() != target.ram_layer_count() {
            return Err(invalid_input(
                "materialize exact checkpoint",
                "RAM source count differs from the repository-bound target",
            ));
        }

        let (_, root_overlay_bytes) = target.root_overlay();
        let (_, _, device_state_bytes) = target.device_state();
        let ram_layer_bytes = (0..target.ram_layer_count())
            .map(|index| {
                target
                    .ram_layer(index)
                    .map(|layer| layer.artifact().2)
                    .ok_or_else(|| {
                        invalid_input(
                            "materialize exact checkpoint",
                            "authenticated RAM layer disappeared before materialization",
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.admit_atomic_exact_restore_materialization(process_contract, target)?;

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

        for (index, (mut reader, expected_bytes)) in
            ram_layers.into_iter().zip(ram_layer_bytes).enumerate()
        {
            let index = u16::try_from(index).map_err(|_| {
                invalid_input(
                    "materialize exact checkpoint",
                    "RAM layer index cannot be represented by the QMP ABI",
                )
            })?;
            let mut destination = self.begin_atomic_exact_ram_layer(index, expected_bytes)?;
            copy_exact_checkpoint_stream(
                &mut reader,
                &mut destination,
                cancellation,
                "copy exact RAM layer",
            )?;
            destination.finish()?;
        }

        self.seal_atomic_exact_restore_inputs()
    }

    /// Admits a production exact-checkpoint set bound to its authenticated root.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the complete set geometry or prepared
    /// directory state is invalid.
    fn admit_atomic_exact_restore_materialization(
        &mut self,
        process_contract: &QemuChildProcessContract,
        target: crucible::exact_checkpoint::ExactCheckpointVerifiedNode,
    ) -> Result<(), QemuSpawnError> {
        let repository_root = ContentHash {
            bytes: target.repository_root().content_id().digest(),
        };
        process_contract.require_exact_checkpoint_root(repository_root)?;
        if !Arc::ptr_eq(&self.attempt_binding, &process_contract.attempt_binding) {
            return Err(QemuSpawnError::PreparedLaunchAdmissionChanged);
        }
        let binding = QemuExactDeviceStateBinding::from_exact_checkpoint_root(
            target.root(),
            target.target_manifest(),
            target.snapshot(),
        );
        let (_, root_overlay_bytes) = target.root_overlay();
        let (_, _, device_state_bytes) = target.device_state();
        let ram_layer_bytes = (0..target.ram_layer_count())
            .map(|index| {
                target
                    .ram_layer(index)
                    .map(|layer| layer.artifact().2)
                    .ok_or_else(|| {
                        invalid_input(
                            "admit exact checkpoint materialization",
                            "authenticated RAM layer disappeared during admission",
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.admit_exact_checkpoint_materialization_with_binding(
            binding,
            root_overlay_bytes,
            device_state_bytes,
            &ram_layer_bytes,
        )?;
        self.exact_checkpoint_target = Some(target);
        Ok(())
    }

    /// Admits one complete exact-checkpoint artifact set before any write.
    ///
    /// The declared device state, root overlay, and every ordered RAM layer are
    /// charged together against the attempt's aggregate writable ceiling. A
    /// successful admission blocks launch until
    /// [`Self::seal_atomic_exact_restore_inputs`] seals the complete set.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the artifact shape is invalid, another
    /// exact set was already admitted, the aggregate exceeds the writable
    /// ceiling, or the pinned launch artifacts changed before admission.
    fn admit_exact_checkpoint_materialization_with_binding(
        &mut self,
        binding: QemuExactDeviceStateBinding,
        root_overlay_bytes: u64,
        device_state_bytes: u64,
        ram_layer_bytes: &[u64],
    ) -> Result<(), QemuSpawnError> {
        if self.exact_checkpoint_materialization != PreparedExactCheckpointMaterialization::Absent {
            return Err(invalid_input(
                "admit exact checkpoint materialization",
                "an exact checkpoint artifact set was already admitted",
            ));
        }
        if !self.launch_resources.has_root_overlay()
            || root_overlay_bytes == 0
            || device_state_bytes == 0
            || ram_layer_bytes.is_empty()
            || ram_layer_bytes.len() > crucible::exact_checkpoint::MAX_EXACT_CHECKPOINT_RAM_LAYERS
            || ram_layer_bytes.contains(&0)
        {
            return Err(invalid_input(
                "admit exact checkpoint materialization",
                "the exact checkpoint artifact set has invalid geometry",
            ));
        }
        let ram_bytes = ram_layer_bytes
            .iter()
            .try_fold(0_u64, |total, bytes| total.checked_add(*bytes));
        let aggregate = ram_bytes.and_then(|ram_bytes| {
            device_state_bytes
                .checked_add(root_overlay_bytes)
                .and_then(|base| base.checked_add(ram_bytes))
        });
        if aggregate.is_none_or(|bytes| bytes > self.admitted_ceiling.2) {
            return Err(QemuSpawnError::PreparedExactCheckpointArtifactsTooLarge {
                device_state_bytes,
                root_overlay_bytes,
                ram_bytes: ram_bytes.unwrap_or(u64::MAX),
                maximum: self.admitted_ceiling.2,
            });
        }
        if self.exact_device_state_materialization
            != PreparedDeviceStateMaterialization::Provisioned
            || self.root_overlay_materialization != PreparedRootOverlayMaterialization::Absent
        {
            return Err(invalid_input(
                "admit exact checkpoint materialization",
                "the prepared destinations are not empty provisioned artifacts",
            ));
        }
        self.revalidate_identity()?;

        let mut admitted_layers = Vec::new();
        admitted_layers
            .try_reserve_exact(ram_layer_bytes.len())
            .map_err(|_| QemuSpawnError::PreparedExactCheckpointAdmissionAllocation)?;
        admitted_layers.extend_from_slice(ram_layer_bytes);
        self.exact_checkpoint_materialization = PreparedExactCheckpointMaterialization::Updating {
            binding,
            device_state_bytes,
            root_overlay_bytes,
            ram_layer_bytes: admitted_layers,
            next_ram_layer: 0,
        };
        Ok(())
    }

    /// Begins one ordered exact RAM input in an owned sealable memfd.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when no admitted set awaits this exact ordered
    /// layer, its index or length differs from admission, the bound device state
    /// or root overlay is incomplete, the run-directory identity changed, or
    /// sealed input creation fails.
    fn begin_atomic_exact_ram_layer(
        &mut self,
        index: u16,
        expected_bytes: u64,
    ) -> Result<AtomicExactRamLayerWriter<'_>, QemuSpawnError> {
        let (_, expected_sha256, target_bytes) = self
            .exact_checkpoint_target
            .as_ref()
            .and_then(|target| target.ram_layer(usize::from(index)))
            .map(|layer| layer.artifact())
            .ok_or_else(|| {
                invalid_input(
                    "begin exact RAM input materialization",
                    "production RAM materialization has no authenticated target layer",
                )
            })?;
        if target_bytes != expected_bytes {
            return Err(invalid_input(
                "begin exact RAM input materialization",
                "RAM input length differs from the repository target layer",
            ));
        }
        self.begin_ram_input_materialization(
            index,
            expected_bytes,
            StreamSha256Verifier {
                expected: expected_sha256,
                observed: Sha256::new(),
            },
        )
    }

    fn begin_ram_input_materialization(
        &mut self,
        index: u16,
        expected_bytes: u64,
        verifier: StreamSha256Verifier,
    ) -> Result<AtomicExactRamLayerWriter<'_>, QemuSpawnError> {
        let index = usize::from(index);
        let (binding, device_state_bytes, root_overlay_bytes, next_ram_layer, admitted_bytes) =
            match &self.exact_checkpoint_materialization {
                PreparedExactCheckpointMaterialization::Updating {
                    binding,
                    device_state_bytes,
                    root_overlay_bytes,
                    ram_layer_bytes,
                    next_ram_layer,
                } => (
                    *binding,
                    *device_state_bytes,
                    *root_overlay_bytes,
                    *next_ram_layer,
                    ram_layer_bytes.get(index).copied(),
                ),
                PreparedExactCheckpointMaterialization::Absent
                | PreparedExactCheckpointMaterialization::Complete { .. }
                | PreparedExactCheckpointMaterialization::Claimed { .. } => {
                    return Err(invalid_input(
                        "begin exact RAM input materialization",
                        "no exact checkpoint artifact set is awaiting RAM inputs",
                    ));
                }
            };
        if index != next_ram_layer || admitted_bytes != Some(expected_bytes) {
            return Err(invalid_input(
                "begin exact RAM input materialization",
                "RAM input differs from the admitted ordered layer",
            ));
        }
        if self.exact_device_state_materialization
            != (PreparedDeviceStateMaterialization::Exact {
                binding,
                bytes: device_state_bytes,
            })
            || self.root_overlay_materialization
                != (PreparedRootOverlayMaterialization::Exact {
                    binding,
                    bytes: root_overlay_bytes,
                })
        {
            return Err(QemuSpawnError::PreparedExactCheckpointNotReady {
                path: self.path.clone(),
            });
        }
        self.revalidate_identity()?;
        self.revalidate_root_overlay_identity()?;

        let destination =
            QemuExactCheckpointInputMaterialization::new(expected_bytes).map_err(|source| {
                QemuSpawnError::Io {
                    operation: "create sealed exact RAM input",
                    source,
                }
            })?;

        Ok(AtomicExactRamLayerWriter {
            prepared: self,
            destination,
            verifier,
            layer_index: index,
            expected_bytes,
            written_bytes: 0,
        })
    }

    /// Seals an admitted exact-checkpoint artifact set after every RAM layer.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when any admitted layer remains incomplete,
    /// the bound device or overlay differs, or directory synchronization fails.
    /// Failure leaves the prepared directory unlaunchable.
    fn seal_atomic_exact_restore_inputs(
        &mut self,
    ) -> Result<SealedAtomicExactRestoreInputs, QemuSpawnError> {
        let target = self.exact_checkpoint_target.as_ref().ok_or_else(|| {
            invalid_input(
                "finish exact checkpoint materialization",
                "the authenticated exact-checkpoint target is absent",
            )
        })?;
        let layer_count = target.ram_layer_count();
        let layers = (0..layer_count)
            .filter_map(|index| {
                target.ram_layer(index).map(|layer| {
                    let (_, content, bytes) = layer.artifact();
                    (content, layer.topology(), bytes)
                })
            })
            .collect::<Vec<_>>();
        let final_layer = target
            .ram_layer(layer_count.saturating_sub(1))
            .ok_or_else(|| {
                invalid_input(
                    "finish exact checkpoint materialization",
                    "authenticated exact checkpoint has no final RAM layer",
                )
            })?;
        let (checkpoint, target_identity, frontier) = final_layer.identity();
        let identity = crate::QmpCheckpointIdentity::new(checkpoint, target_identity, frontier);
        let device_content = target.device_state().1;

        let inner =
            self.seal_atomic_exact_restore_inputs_with_metadata(identity, device_content, layers)?;
        let target = self.exact_checkpoint_target.take().ok_or_else(|| {
            invalid_input(
                "finish exact checkpoint materialization",
                "authenticated exact-checkpoint target was consumed early",
            )
        })?;

        Ok(SealedAtomicExactRestoreInputs { inner, target })
    }

    fn seal_atomic_exact_restore_inputs_with_metadata(
        &mut self,
        identity: crate::QmpCheckpointIdentity,
        device_content: ContentHash,
        layers: Vec<(ContentHash, ContentHash, u64)>,
    ) -> Result<QemuGuardedRamInputs, QemuSpawnError> {
        let (binding, device_state_bytes, root_overlay_bytes, ram_layer_count, complete) =
            match &self.exact_checkpoint_materialization {
                PreparedExactCheckpointMaterialization::Updating {
                    binding,
                    device_state_bytes,
                    root_overlay_bytes,
                    ram_layer_bytes,
                    next_ram_layer,
                } => (
                    *binding,
                    *device_state_bytes,
                    *root_overlay_bytes,
                    ram_layer_bytes.len(),
                    *next_ram_layer == ram_layer_bytes.len(),
                ),
                PreparedExactCheckpointMaterialization::Absent
                | PreparedExactCheckpointMaterialization::Complete { .. }
                | PreparedExactCheckpointMaterialization::Claimed { .. } => {
                    return Err(invalid_input(
                        "finish exact checkpoint materialization",
                        "no exact checkpoint artifact set is awaiting completion",
                    ));
                }
            };
        if !complete
            || self.exact_device_state_materialization
                != (PreparedDeviceStateMaterialization::Exact {
                    binding,
                    bytes: device_state_bytes,
                })
            || self.root_overlay_materialization
                != (PreparedRootOverlayMaterialization::Exact {
                    binding,
                    bytes: root_overlay_bytes,
                })
        {
            return Err(QemuSpawnError::PreparedExactCheckpointNotReady {
                path: self.path.clone(),
            });
        }
        self.revalidate_identity()?;
        self.revalidate_root_overlay_identity()?;
        fsync(&self.directory).map_err(|source| QemuSpawnError::Io {
            operation: "synchronize exact checkpoint materialization set",
            source: source.into(),
        })?;
        if self.exact_ram_inputs.len() != ram_layer_count {
            return Err(invalid_input(
                "finish exact checkpoint materialization",
                "one or more admitted RAM inputs are no longer retained",
            ));
        }
        if layers.len() != ram_layer_count
            || layers
                .iter()
                .enumerate()
                .any(|(index, (_, _, bytes))| *bytes != self.exact_ram_inputs[index].expected_bytes)
        {
            return Err(invalid_input(
                "finish exact checkpoint materialization",
                "restore metadata differs from the retained ordered RAM inputs",
            ));
        }
        let topology = layers
            .first()
            .map(|(_, topology, _)| *topology)
            .ok_or_else(|| {
                invalid_input(
                    "finish exact checkpoint materialization",
                    "restore metadata has no RAM layers",
                )
            })?;
        if layers
            .iter()
            .any(|(_, layer_topology, _)| *layer_topology != topology)
        {
            return Err(invalid_input(
                "finish exact checkpoint materialization",
                "restore metadata contains different RAM topologies",
            ));
        }
        let restore_layers = layers
            .into_iter()
            .enumerate()
            .map(|(index, (content, _, maximum_bytes))| {
                crate::QmpCheckpointRestoreLayer::new(
                    crate::QmpDescriptorName::new(format!("crucible-ram-{index}"))?,
                    content,
                    maximum_bytes,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                invalid_input(
                    "finish exact checkpoint materialization",
                    "restore layer metadata cannot form a bounded QMP request",
                )
            })?;
        let device_descriptor =
            crate::QmpDescriptorName::new("crucible-device-state").map_err(|_| {
                invalid_input(
                    "finish exact checkpoint materialization",
                    "device descriptor name is invalid",
                )
            })?;
        let cancellation_descriptor = crate::QmpDescriptorName::new("crucible-cancellation")
            .map_err(|_| {
                invalid_input(
                    "finish exact checkpoint materialization",
                    "cancellation descriptor name is invalid",
                )
            })?;
        let request = crate::QmpCheckpointRestoreRequest::new(
            restore_layers,
            device_descriptor,
            device_content,
            cancellation_descriptor,
            identity,
            device_state_bytes,
        )
        .map_err(|_| {
            invalid_input(
                "finish exact checkpoint materialization",
                "restore metadata cannot form a bounded QMP request",
            )
        })?;
        self.exact_checkpoint_materialization =
            PreparedExactCheckpointMaterialization::Complete { binding };
        Ok(QemuGuardedRamInputs {
            inputs: std::mem::take(&mut self.exact_ram_inputs),
            binding,
            attempt_binding: Arc::clone(&self.attempt_binding),
            request,
            topology,
        })
    }
}
