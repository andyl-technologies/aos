//! Immutable QEMU fault-capability manifest decoding and binding.

use super::*;

impl QemuFaultCommandApis {
    pub(in crate::fault_command) fn capability_rows(
        self,
    ) -> Result<Vec<FaultCapabilityRowV1>, FaultCommandBridgeError> {
        let required = (self.capabilities)(std::ptr::null_mut(), 0);
        if required == 0 || required > 4_096 {
            return Err(FaultCommandBridgeError::CapabilityCount { required });
        }
        let empty = QemuFaultCapability {
            command_kind: 0,
            scope: 0,
            semantic_version: 0,
            phase_mask: 0,
            maximum_payload_bytes: 0,
            maximum_pending_commands: 0,
            required_feature_bits: 0,
            name: std::ptr::null(),
            payload_schema: std::ptr::null(),
        };
        let mut raw = vec![empty; required];
        let observed = (self.capabilities)(raw.as_mut_ptr(), raw.len());
        if observed != required {
            return Err(FaultCommandBridgeError::CapabilityRegistryChanged {
                expected: required,
                observed,
            });
        }
        let rows = raw
            .into_iter()
            .map(capability_row)
            .collect::<Result<Vec<_>, _>>()?;
        fault_capability_manifest_digest(&rows).map_err(|source| {
            let keys = rows
                .iter()
                .map(|row| {
                    format!(
                        "{}:{}:{}",
                        row.command_kind as u16, row.semantic_version, row.scope as u16
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            FaultCommandBridgeError::CapabilityRegistryAbi { keys, source }
        })?;
        Ok(rows)
    }

    pub(in crate::fault_command) fn register_manifest(
        self,
    ) -> Result<FaultRegisterCapabilityManifestV1, FaultCommandBridgeError> {
        let mut architecture = 0_u16;
        let mut cpu_model = std::ptr::null();
        let required =
            (self.register_manifest)(std::ptr::null_mut(), 0, &mut architecture, &mut cpu_model);
        if required == 0 || required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultCommandBridgeError::RegisterManifestCount { required });
        }
        let empty = QemuFaultRegisterCapability {
            numeric_id: 0,
            width_bits: 0,
            group: 0,
            reserved: 0,
            model_phase_mask: 0,
            side_effects: 0,
            capabilities: 0,
            name: std::ptr::null(),
            writable_mask: std::ptr::null(),
            reserved_mask: std::ptr::null(),
            ignored_mask: std::ptr::null(),
            read_only_mask: std::ptr::null(),
            mask_bytes: 0,
        };
        let mut raw = vec![empty; required];
        let observed = (self.register_manifest)(
            raw.as_mut_ptr(),
            raw.len(),
            &mut architecture,
            &mut cpu_model,
        );
        if observed != required {
            return Err(FaultCommandBridgeError::RegisterManifestChanged {
                expected: required,
                observed,
            });
        }
        let manifest = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::from_u16(architecture)
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
            cpu_model: capability_text(cpu_model, "cpu_model")?.to_owned(),
            rows: raw
                .into_iter()
                .map(register_capability_row)
                .collect::<Result<Vec<_>, _>>()?,
        };
        let encoded = manifest.encode().map_err(|source| {
            let keys = manifest
                .rows
                .iter()
                .map(|row| format!("{}:{}", row.numeric_id, row.name))
                .collect::<Vec<_>>()
                .join(",");
            FaultCommandBridgeError::RegisterManifestAbi {
                architecture,
                cpu_model: manifest.cpu_model.clone(),
                keys,
                source,
            }
        })?;
        FaultRegisterCapabilityManifestV1::decode(&encoded)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    pub(in crate::fault_command) fn instruction_manifest(
        self,
    ) -> Result<InstructionEvidenceIdentity, FaultCommandBridgeError> {
        let mut sha256 = [0_u8; 32];
        let mut architecture = 0_u16;
        let required = (self.instruction_manifest)(
            std::ptr::null_mut(),
            0,
            sha256.as_mut_ptr(),
            &mut architecture,
        );
        if required == 0 || required > 16_384 || sha256 == [0; 32] {
            return Err(FaultCommandBridgeError::InstructionManifestCount { required });
        }
        let mut manifest = vec![0_u8; required];
        let mut copied_sha256 = [0_u8; 32];
        let mut copied_architecture = 0_u16;
        let observed = (self.instruction_manifest)(
            manifest.as_mut_ptr(),
            manifest.len(),
            copied_sha256.as_mut_ptr(),
            &mut copied_architecture,
        );
        if observed != required
            || copied_sha256 != sha256
            || copied_architecture != architecture
            || sha2::Sha256::digest(&manifest).as_slice() != sha256
        {
            return Err(FaultCommandBridgeError::InstructionManifestChanged);
        }
        Ok(InstructionEvidenceIdentity {
            architecture: FaultCapabilityScope::from_u16(architecture)
                .map_err(|_source| FaultCommandBridgeError::InstructionManifestChanged)?,
            manifest_sha256: sha256,
        })
    }

    pub(in crate::fault_command) fn interrupt_manifest(
        self,
    ) -> Result<FaultInterruptCapabilityManifestV1, FaultCommandBridgeError> {
        let mut architecture = 0_u16;
        let required = (self.interrupt_manifest)(std::ptr::null_mut(), 0, &mut architecture);
        if required == 0 || required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultCommandBridgeError::InterruptManifestCount { required });
        }
        let empty = QemuFaultInterruptCapability {
            family: 0,
            trigger: 0,
            polarity: 0,
            delivery_drop: 0,
            vector_start: 0,
            vector_end: 0,
            replacement_vector_start: 0,
            replacement_vector_end: 0,
            priority: 0,
            vmstate: 0,
            reserved: 0,
            model_phase_mask: 0,
            id: std::ptr::null(),
            controller: std::ptr::null(),
            source: std::ptr::null(),
            controller_version: std::ptr::null(),
            target_vcpus: std::ptr::null(),
            target_vcpu_count: 0,
        };
        let mut raw = vec![empty; required];
        let observed = (self.interrupt_manifest)(raw.as_mut_ptr(), raw.len(), &mut architecture);
        if observed != required {
            return Err(FaultCommandBridgeError::InterruptManifestChanged {
                expected: required,
                observed,
            });
        }
        let manifest = FaultInterruptCapabilityManifestV1 {
            architecture: FaultCapabilityScope::from_u16(architecture)
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
            rows: raw
                .into_iter()
                .map(interrupt_capability_row)
                .collect::<Result<Vec<_>, _>>()?,
        };
        FaultInterruptCapabilityManifestV1::decode(
            &manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        )
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    pub(in crate::fault_command) fn bind_interrupt_manifest(
        self,
        manifest: &FaultInterruptCapabilityManifestV1,
    ) -> Result<(), FaultCommandBridgeError> {
        for (index, row) in manifest.rows.iter().enumerate() {
            let row_index = u32::try_from(index)
                .map_err(|_source| FaultCommandBridgeError::InterruptManifestRow)?;
            let id = crucible_shmem::fault_object_id_hash_v1(&row.id);
            let controller = crucible_shmem::fault_object_id_hash_v1(&row.controller);
            let source = crucible_shmem::fault_object_id_hash_v1(&row.source);
            let status =
                (self.interrupt_bind)(row_index, id.as_ptr(), controller.as_ptr(), source.as_ptr());
            if status != 0 {
                return Err(FaultCommandBridgeError::InterruptManifestBind { row_index, status });
            }
        }
        let status = (self.interrupt_bindings_seal)();
        if status != 0 {
            return Err(FaultCommandBridgeError::InterruptManifestBind {
                row_index: 0,
                status,
            });
        }
        Ok(())
    }

    pub(in crate::fault_command) fn hardware_error_manifest(
        self,
    ) -> Result<FaultHardwareErrorCapabilityManifestV1, FaultCommandBridgeError> {
        let mut architecture = 0_u16;
        let required = (self.hardware_error_manifest)(std::ptr::null_mut(), 0, &mut architecture);
        if required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultCommandBridgeError::HardwareErrorManifestCount { required });
        }
        let empty = QemuFaultHardwareErrorCapability {
            record_kind: 0,
            error_class: 0,
            mechanism: 0,
            visibility_mask: 0,
            bank_number: 0,
            bank_count: 0,
            vector: 0,
            reserved0: 0,
            status_required: 0,
            status_allowed: 0,
            syndrome_required: 0,
            syndrome_allowed: 0,
            model_phase_mask: 0,
            privilege_mask: 0,
            corrected: 0,
            maskable: 0,
            vmstate: 0,
            reserved1: 0,
            id: std::ptr::null(),
            bank: std::ptr::null(),
            channel: std::ptr::null(),
            rank: std::ptr::null(),
            firmware: std::ptr::null(),
            state: std::ptr::null(),
        };
        let mut raw = vec![empty; required];
        let observed =
            (self.hardware_error_manifest)(raw.as_mut_ptr(), raw.len(), &mut architecture);
        if observed != required {
            return Err(FaultCommandBridgeError::HardwareErrorManifestChanged {
                expected: required,
                observed,
            });
        }
        let manifest = FaultHardwareErrorCapabilityManifestV1 {
            architecture: FaultCapabilityScope::from_u16(architecture)
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
            rows: raw
                .into_iter()
                .map(hardware_error_capability_row)
                .collect::<Result<Vec<_>, _>>()?,
        };
        FaultHardwareErrorCapabilityManifestV1::decode(
            &manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        )
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    pub(in crate::fault_command) fn bind_hardware_error_manifest(
        self,
        manifest: &FaultHardwareErrorCapabilityManifestV1,
    ) -> Result<(), FaultCommandBridgeError> {
        let manifest_payload = manifest
            .encode()
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        let manifest_sha256: [u8; 32] = sha2::Sha256::digest(&manifest_payload).into();
        for (index, row) in manifest.rows.iter().enumerate() {
            let row_index = u32::try_from(index)
                .map_err(|_source| FaultCommandBridgeError::HardwareErrorManifestRow)?;
            let id = crucible_shmem::fault_object_id_hash_v1(&row.id);
            let bank = crucible_shmem::fault_object_id_hash_v1(&row.bank);
            let channel = crucible_shmem::fault_object_id_hash_v1(&row.channel);
            let rank = crucible_shmem::fault_object_id_hash_v1(&row.rank);
            let firmware = crucible_shmem::fault_object_id_hash_v1(&row.firmware);
            let state = crucible_shmem::fault_object_id_hash_v1(&row.state);
            let status = (self.hardware_error_bind)(
                row_index,
                id.as_ptr(),
                bank.as_ptr(),
                channel.as_ptr(),
                rank.as_ptr(),
                firmware.as_ptr(),
                state.as_ptr(),
            );
            if status != 0 {
                return Err(FaultCommandBridgeError::HardwareErrorManifestBind {
                    row_index,
                    status,
                });
            }
        }
        let status = (self.hardware_error_bindings_seal)(manifest_sha256.as_ptr());
        if status != 0 {
            return Err(FaultCommandBridgeError::HardwareErrorManifestBind {
                row_index: 0,
                status,
            });
        }
        Ok(())
    }

    pub(in crate::fault_command) fn clock_manifest(
        self,
    ) -> Result<FaultClockCapabilityManifestV1, FaultCommandBridgeError> {
        let mut architecture = 0_u16;
        let required = (self.clock_manifest)(std::ptr::null_mut(), 0, &mut architecture);
        if required == 0 || required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultCommandBridgeError::ClockManifestCount { required });
        }
        let empty = QemuFaultClockCapability {
            source_kind: 0,
            architecture: 0,
            base_domain: 0,
            timer_relationship: 0,
            width_bits: 0,
            flags: 0,
            frequency_numerator: 0,
            frequency_denominator: 0,
            model_phase_mask: 0,
            vmstate: 0,
            monotonicity: 0,
            reserved: [0; 6],
            id: std::ptr::null(),
            implementation: std::ptr::null(),
        };
        let mut raw = vec![empty; required];
        let observed = (self.clock_manifest)(raw.as_mut_ptr(), raw.len(), &mut architecture);
        if observed != required {
            return Err(FaultCommandBridgeError::ClockManifestChanged {
                expected: required,
                observed,
            });
        }
        let architecture = FaultCapabilityScope::from_u16(architecture)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        let manifest = FaultClockCapabilityManifestV1 {
            architecture,
            rows: raw
                .into_iter()
                .map(|row| clock_capability_row(row, architecture))
                .collect::<Result<Vec<_>, _>>()?,
        };
        FaultClockCapabilityManifestV1::decode(
            &manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        )
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    pub(in crate::fault_command) fn accelerator_manifest(
        self,
    ) -> Result<Option<FaultAcceleratorCapabilityManifestV1>, FaultCommandBridgeError> {
        let required = (self.accelerator_manifest)(std::ptr::null_mut(), 0);
        if required == 0 {
            return Ok(None);
        }
        if required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultCommandBridgeError::AcceleratorManifestCount { required });
        }
        let empty = QemuFaultAcceleratorCapability {
            class_mask: 0,
            fault_family_mask: 0,
            queue_start: 0,
            queue_end: 0,
            queue_depth: 0,
            maximum_input_bytes: 0,
            maximum_output_bytes: 0,
            device_memory_bytes: 0,
            ecc_mode_mask: 0,
            job_kind_count: 0,
            vmstate: 0,
            reserved: [0; 7],
            id: std::ptr::null(),
            implementation: std::ptr::null(),
        };
        let mut raw = vec![empty; required];
        let observed = (self.accelerator_manifest)(raw.as_mut_ptr(), raw.len());
        if observed != required {
            return Err(FaultCommandBridgeError::AcceleratorManifestChanged {
                expected: required,
                observed,
            });
        }
        let manifest = FaultAcceleratorCapabilityManifestV1 {
            rows: raw
                .into_iter()
                .map(|row| {
                    if row.reserved != [0; 7] {
                        return Err(FaultCommandBridgeError::AcceleratorManifestRow);
                    }
                    Ok(FaultAcceleratorCapabilityRowV1 {
                        id: capability_text(row.id, "accelerator.id")?.to_owned(),
                        implementation: capability_text(
                            row.implementation,
                            "accelerator.implementation",
                        )?
                        .to_owned(),
                        class_mask: row.class_mask,
                        fault_family_mask: row.fault_family_mask,
                        queue_start: row.queue_start,
                        queue_end: row.queue_end,
                        queue_depth: row.queue_depth,
                        maximum_input_bytes: row.maximum_input_bytes,
                        maximum_output_bytes: row.maximum_output_bytes,
                        device_memory_bytes: row.device_memory_bytes,
                        ecc_mode_mask: row.ecc_mode_mask,
                        job_kind_count: row.job_kind_count,
                        vmstate: row.vmstate == 1,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        let encoded = manifest
            .encode()
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        FaultAcceleratorCapabilityManifestV1::decode(&encoded)
            .map(Some)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    pub(in crate::fault_command) fn system_manifest(
        self,
    ) -> Result<FaultSystemCapabilityManifestV1, FaultCommandBridgeError> {
        let mut raw = QemuFaultSystemManifest {
            semantic_version: 0,
            vmstate_format_version: 0,
            vmstate_section_count: 0,
            reserved: 0,
            vmstate_sections_sha256: [0; 32],
            system_capability: std::ptr::null(),
            vmstate_capability: std::ptr::null(),
            qemu_build_id: std::ptr::null(),
            qemu_atomic_patch_hash: std::ptr::null(),
            shmem_header_hash: std::ptr::null(),
        };
        let status = (self.system_manifest)(&mut raw);
        if status != 0
            || raw.reserved != 0
            || capability_text(raw.system_capability, "system_capability")?
                != "qemu.fault-system.complete.v1"
            || capability_text(raw.vmstate_capability, "vmstate_capability")?
                != "qemu.fault-vmstate.v1"
        {
            return Err(FaultCommandBridgeError::SystemManifest { status });
        }
        let qemu_build_id = capability_text(raw.qemu_build_id, "qemu_build_id")?;
        let qemu_atomic_patch_hash =
            capability_text(raw.qemu_atomic_patch_hash, "qemu_atomic_patch_hash")?;
        let shmem_header_hash = capability_text(raw.shmem_header_hash, "shmem_header_hash")?;
        let identity_matches = match (
            EXPECTED_QEMU_BUILD_ID,
            EXPECTED_QEMU_ATOMIC_PATCH_HASH,
            EXPECTED_SHMEM_HEADER_HASH,
        ) {
            (Some(build), Some(atomic_patch), Some(shmem)) => {
                build == qemu_build_id
                    && atomic_patch == qemu_atomic_patch_hash
                    && shmem == shmem_header_hash
            }
            _ => cfg!(test),
        };
        if !identity_matches {
            return Err(FaultCommandBridgeError::SystemIdentityMismatch);
        }
        let manifest = FaultSystemCapabilityManifestV1 {
            semantic_version: raw.semantic_version,
            vmstate_format_version: raw.vmstate_format_version,
            vmstate_section_count: raw.vmstate_section_count,
            vmstate_sections_sha256: raw.vmstate_sections_sha256,
            emulator_build_id: text_digest(qemu_build_id, "qemu_build_id")?,
            emulator_atomic_patch_hash: text_digest(
                qemu_atomic_patch_hash,
                "qemu_atomic_patch_hash",
            )?,
            shmem_header_hash: text_digest(shmem_header_hash, "shmem_header_hash")?,
        };
        FaultSystemCapabilityManifestV1::decode(
            &manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        )
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    pub(in crate::fault_command) fn bind_clock_manifest(
        self,
        manifest: &FaultClockCapabilityManifestV1,
    ) -> Result<(), FaultCommandBridgeError> {
        let payload = manifest
            .encode()
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        let manifest_sha256: [u8; 32] = sha2::Sha256::digest(&payload).into();

        for (index, row) in manifest.rows.iter().enumerate() {
            let row_index = u32::try_from(index)
                .map_err(|_source| FaultCommandBridgeError::ClockManifestRow)?;
            let id = crucible_shmem::fault_object_id_hash_v1(&row.id);
            let status = (self.clock_bind)(row_index, id.as_ptr());
            if status != 0 {
                return Err(FaultCommandBridgeError::ClockManifestBind { row_index, status });
            }
        }
        let status = (self.clock_bindings_seal)(manifest_sha256.as_ptr());
        if status != 0 {
            return Err(FaultCommandBridgeError::ClockManifestBind {
                row_index: 0,
                status,
            });
        }
        Ok(())
    }

    pub(in crate::fault_command) fn bind_register_manifest(
        self,
        manifest: &FaultRegisterCapabilityManifestV1,
    ) -> Result<(), FaultCommandBridgeError> {
        let architecture_name = match manifest.architecture {
            FaultCapabilityScope::X86_64 => "x86_64",
            FaultCapabilityScope::Aarch64 => "aarch64",
            _ => return Err(FaultCommandBridgeError::RegisterManifestRow),
        };
        let architecture_identity = crucible_shmem::fault_object_id_hash_v1(architecture_name);
        let architecture_status = (self.register_bind_architecture)(architecture_identity.as_ptr());
        if architecture_status != 0 {
            return Err(FaultCommandBridgeError::RegisterManifestBind {
                numeric_id: 0,
                status: architecture_status,
            });
        }
        for row in &manifest.rows {
            let identity = crucible_shmem::fault_object_id_hash_v1(&row.name);
            let status = (self.register_bind)(identity.as_ptr(), row.numeric_id);
            if status != 0 {
                return Err(FaultCommandBridgeError::RegisterManifestBind {
                    numeric_id: row.numeric_id,
                    status,
                });
            }
        }
        let seal_status = (self.register_bindings_seal)();
        if seal_status != 0 {
            return Err(FaultCommandBridgeError::RegisterManifestBind {
                numeric_id: 0,
                status: seal_status,
            });
        }
        Ok(())
    }
}

fn capability_row(
    raw: QemuFaultCapability,
) -> Result<FaultCapabilityRowV1, FaultCommandBridgeError> {
    let name = capability_text(raw.name, "name")?;
    let schema = capability_text(raw.payload_schema, "payload_schema")?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_HASH_DOMAIN);
    hasher.update(name.as_bytes());
    hasher.update(&[0]);
    hasher.update(schema.as_bytes());
    let row = FaultCapabilityRowV1 {
        command_kind: FaultCommandKind::from_u16(raw.command_kind)
            .map_err(|source| invalid_capability_row(raw, name, source))?,
        semantic_version: raw.semantic_version,
        scope: FaultCapabilityScope::from_u16(raw.scope)
            .map_err(|source| invalid_capability_row(raw, name, source))?,
        phase_mask: raw.phase_mask,
        maximum_payload_bytes: raw.maximum_payload_bytes,
        maximum_pending_commands: raw.maximum_pending_commands,
        required_feature_bits: raw.required_feature_bits,
        capability_hash: *hasher.finalize().as_bytes(),
    };
    FaultCapabilityRowV1::decode(&row.encode())
        .map_err(|source| invalid_capability_row(raw, name, source))
}

fn invalid_capability_row(
    raw: QemuFaultCapability,
    name: &str,
    source: FaultAbiError,
) -> FaultCommandBridgeError {
    FaultCommandBridgeError::CapabilityRowAbi {
        name: name.to_owned(),
        command_kind: raw.command_kind,
        scope: raw.scope,
        semantic_version: raw.semantic_version,
        phase_mask: raw.phase_mask,
        maximum_payload_bytes: raw.maximum_payload_bytes,
        maximum_pending_commands: raw.maximum_pending_commands,
        required_feature_bits: raw.required_feature_bits,
        source,
    }
}

fn register_capability_row(
    raw: QemuFaultRegisterCapability,
) -> Result<FaultRegisterCapabilityRowV1, FaultCommandBridgeError> {
    let expected_mask_bytes = usize::try_from(raw.width_bits.div_ceil(8))
        .map_err(|_source| FaultCommandBridgeError::RegisterManifestRow)?;
    if raw.reserved != 0
        || raw.width_bits == 0
        || raw.width_bits > crucible_shmem::HARD_FAULT_REGISTER_WIDTH_BITS
        || raw.mask_bytes != expected_mask_bytes
        || raw.writable_mask.is_null()
        || raw.reserved_mask.is_null()
        || raw.ignored_mask.is_null()
        || raw.read_only_mask.is_null()
    {
        return Err(FaultCommandBridgeError::RegisterManifestRow);
    }
    let copy_mask = |pointer: *const u8| {
        // SAFETY: the QEMU manifest export promises process-lifetime arrays of
        // exactly `ceil(width_bits / 8)` bytes. Width, the redundant length,
        // and null pointers were checked above before this synchronous copy.
        unsafe { std::slice::from_raw_parts(pointer, raw.mask_bytes) }.to_vec()
    };
    let row = FaultRegisterCapabilityRowV1 {
        numeric_id: raw.numeric_id,
        name: capability_text(raw.name, "register_name")?.to_owned(),
        width_bits: raw.width_bits,
        group: FaultRegisterGroupV1::from_u16(raw.group)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        model_phase_mask: raw.model_phase_mask,
        side_effects: raw.side_effects,
        capabilities: raw.capabilities,
        writable_mask: copy_mask(raw.writable_mask),
        reserved_mask: copy_mask(raw.reserved_mask),
        ignored_mask: copy_mask(raw.ignored_mask),
        read_only_mask: copy_mask(raw.read_only_mask),
    };
    row.validate()
        .map_err(|source| FaultCommandBridgeError::RegisterManifestRowAbi {
            numeric_id: raw.numeric_id,
            name: row.name.clone(),
            width_bits: raw.width_bits,
            group: raw.group,
            model_phase_mask: raw.model_phase_mask,
            side_effects: raw.side_effects,
            capabilities: raw.capabilities,
            mask_bytes: raw.mask_bytes,
            source,
        })?;
    Ok(row)
}

fn interrupt_capability_row(
    raw: QemuFaultInterruptCapability,
) -> Result<FaultInterruptCapabilityRowV1, FaultCommandBridgeError> {
    if raw.reserved != 0
        || raw.target_vcpu_count == 0
        || raw.target_vcpu_count > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS
        || raw.target_vcpus.is_null()
    {
        return Err(FaultCommandBridgeError::InterruptManifestRow);
    }
    let target_vcpus =
        // SAFETY: the sealed QEMU manifest owns a process-lifetime target array;
        // its non-null pointer and hard-bounded element count were checked above.
        unsafe { std::slice::from_raw_parts(raw.target_vcpus, raw.target_vcpu_count) }.to_vec();
    Ok(FaultInterruptCapabilityRowV1 {
        id: capability_text(raw.id, "interrupt_id")?.to_owned(),
        controller: capability_text(raw.controller, "interrupt_controller")?.to_owned(),
        source: capability_text(raw.source, "interrupt_source")?.to_owned(),
        controller_version: capability_text(raw.controller_version, "controller_version")?
            .to_owned(),
        family: FaultInterruptFamilyV1::from_u16(raw.family)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        vector_start: raw.vector_start,
        vector_end: raw.vector_end,
        replacement_vector_start: raw.replacement_vector_start,
        replacement_vector_end: raw.replacement_vector_end,
        trigger: FaultInterruptTriggerV1::from_u16(raw.trigger)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        polarity: FaultInterruptPolarityV1::from_u16(raw.polarity)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        target_vcpus,
        model_phase_mask: raw.model_phase_mask,
        priority: raw.priority,
        delivery_drop: FaultInterruptDeliveryDropV1::from_u16(raw.delivery_drop)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        vmstate: raw.vmstate == 1,
    })
}

fn clock_capability_row(
    raw: QemuFaultClockCapability,
    architecture: FaultCapabilityScope,
) -> Result<FaultClockCapabilityRowV1, FaultCommandBridgeError> {
    if raw.architecture != architecture as u16 || raw.reserved != [0; 6] || raw.vmstate > 1 {
        return Err(FaultCommandBridgeError::ClockManifestRow);
    }
    Ok(FaultClockCapabilityRowV1 {
        id: capability_text(raw.id, "clock_id")?.to_owned(),
        implementation: capability_text(raw.implementation, "clock_implementation")?.to_owned(),
        source_kind: raw.source_kind,
        base_domain: raw.base_domain,
        timer_relationship: raw.timer_relationship,
        width_bits: raw.width_bits,
        flags: raw.flags,
        frequency_numerator: raw.frequency_numerator,
        frequency_denominator: raw.frequency_denominator,
        model_phase_mask: raw.model_phase_mask,
        vmstate: raw.vmstate == 1,
        monotonicity: raw.monotonicity,
    })
}

fn hardware_error_capability_row(
    raw: QemuFaultHardwareErrorCapability,
) -> Result<FaultHardwareErrorCapabilityRowV1, FaultCommandBridgeError> {
    if raw.reserved0 != 0
        || raw.reserved1 != 0
        || raw.corrected > 1
        || raw.maskable > 1
        || raw.vmstate > 1
    {
        return Err(FaultCommandBridgeError::HardwareErrorManifestRow);
    }
    Ok(FaultHardwareErrorCapabilityRowV1 {
        id: capability_text(raw.id, "hardware_error_id")?.to_owned(),
        bank: capability_text(raw.bank, "hardware_error_bank")?.to_owned(),
        channel: capability_text(raw.channel, "hardware_error_channel")?.to_owned(),
        rank: capability_text(raw.rank, "hardware_error_rank")?.to_owned(),
        firmware: capability_text(raw.firmware, "hardware_error_firmware")?.to_owned(),
        state: capability_text(raw.state, "hardware_error_state")?.to_owned(),
        record_kind: FaultHardwareErrorRecordKindV1::from_u16(raw.record_kind)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        error_class: FaultHardwareErrorClassV1::from_u16(raw.error_class)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        mechanism: FaultHardwareErrorMechanismV1::from_u16(raw.mechanism)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        visibility_mask: raw.visibility_mask,
        bank_number: raw.bank_number,
        bank_count: raw.bank_count,
        vector: raw.vector,
        status_required: raw.status_required,
        status_allowed: raw.status_allowed,
        syndrome_required: raw.syndrome_required,
        syndrome_allowed: raw.syndrome_allowed,
        model_phase_mask: raw.model_phase_mask,
        privilege_mask: raw.privilege_mask,
        corrected: raw.corrected == 1,
        maskable: raw.maskable == 1,
        vmstate: raw.vmstate == 1,
    })
}

fn capability_text(
    pointer: *const c_char,
    field: &'static str,
) -> Result<&'static str, FaultCommandBridgeError> {
    let pointer = NonNull::new(pointer.cast_mut())
        .ok_or(FaultCommandBridgeError::CapabilityStringNull { field })?;
    // SAFETY: QEMU's capability ABI promises process-lifetime NUL-terminated
    // strings, and the registry is sealed before this synchronous copy.
    unsafe { CStr::from_ptr(pointer.as_ptr()) }
        .to_str()
        .map_err(|_source| FaultCommandBridgeError::CapabilityStringUtf8 { field })
}

fn text_digest(text: &str, field: &'static str) -> Result<[u8; 32], FaultCommandBridgeError> {
    let bytes =
        hex::decode(text).map_err(|_source| FaultCommandBridgeError::CapabilityDigest { field })?;
    bytes
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::CapabilityDigest { field })
}
