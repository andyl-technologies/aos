//! Storage policy references and binding ownership admission.

use super::*;

pub(super) fn validate_storage_effect_policy_references(
    binding: &FaultBinding,
    world: &World,
    programs: &[SignalProgram],
) -> Result<(), FaultSignalAuthoringError> {
    let EffectSpecification::Storage(specification) = binding.effect().specification() else {
        return Ok(());
    };
    let topology = world.fault_topology();
    let require = |reference: &FaultObjectId,
                   accepted: &[StoragePolicyArtifactClass],
                   field: &'static str|
     -> Result<(), FaultSignalAuthoringError> {
        let actual = topology
            .storage_policy_artifact(reference)
            .map(|declaration| declaration.artifact.class());
        if actual.is_some_and(|actual| accepted.contains(&actual)) {
            return Ok(());
        }
        Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
            binding: binding.id().as_str().to_owned(),
            reference: reference.as_str().to_owned(),
            field,
            expected: accepted
                .iter()
                .map(|class| class.as_str())
                .collect::<Vec<_>>()
                .join(" or "),
            actual: actual.map(StoragePolicyArtifactClass::as_str),
        })
    };
    let require_storage_device = |reference: &FaultObjectId,
                                  field: &'static str|
     -> Result<(), FaultSignalAuthoringError> {
        if topology.storage_devices.iter().any(|device| {
            device.device.as_str() == reference.as_str() && device.kind == WorldStorageKind::Block
        }) {
            return Ok(());
        }
        Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
            binding: binding.id().as_str().to_owned(),
            reference: reference.as_str().to_owned(),
            field,
            expected: String::from("world block storage device"),
            actual: None,
        })
    };
    let require_program_node =
        |reference: &FaultObjectId, field: &'static str| -> Result<(), FaultSignalAuthoringError> {
            let exists = programs
                .iter()
                .find(|program| program.id() == binding.program())
                .and_then(|program| {
                    let id = SignalId::parse(reference.as_str()).ok()?;
                    program.exported_shape(&id)
                })
                .is_some_and(|shape| matches!(shape.value_type, SignalValueType::Event(_)));
            if exists {
                return Ok(());
            }
            Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                binding: binding.id().as_str().to_owned(),
                reference: reference.as_str().to_owned(),
                field,
                expected: String::from("exported event signal in the binding program"),
                actual: None,
            })
        };
    let require_block_range = |reference: &FaultObjectId,
                               range: ByteRange,
                               field: &'static str|
     -> Result<(), FaultSignalAuthoringError> {
        require_storage_device(reference, field)?;
        let valid = topology
            .storage_devices
            .iter()
            .find(|device| device.device.as_str() == reference.as_str())
            .is_some_and(|device| {
                let block = u64::from(device.persistence.logical_block_bytes);
                range.end() <= device.persistence.length_bytes
                    && range.start().is_multiple_of(block)
                    && range.length().is_multiple_of(block)
            });
        if valid {
            return Ok(());
        }
        Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
            binding: binding.id().as_str().to_owned(),
            reference: reference.as_str().to_owned(),
            field,
            expected: String::from("in-bounds logical-block-aligned world block range"),
            actual: None,
        })
    };
    let selected_block_contracts = || {
        binding
            .selector()
            .resolved()
            .targets()
            .iter()
            .map(|target| {
                let hash = match target {
                    ResolvedFaultTarget::BlockDevice { device }
                    | ResolvedFaultTarget::BlockRange { device, .. } => device,
                    _ => return None,
                };
                let node = world
                    .io_nodes()
                    .find(|node| node.fault_target_hash() == *hash)?;
                topology.storage_devices.iter().find(|device| {
                    device.device.as_str() == node.id.name.as_str()
                        && device.kind == WorldStorageKind::Block
                })
            })
            .collect::<Option<Vec<_>>>()
            .filter(|contracts| !contracts.is_empty())
    };
    let selected_maximum_request_bytes = || {
        binding
            .selector()
            .resolved()
            .targets()
            .iter()
            .map(|target| {
                let (hash, selected_length) = match target {
                    ResolvedFaultTarget::BlockDevice { device } => (device, None),
                    ResolvedFaultTarget::BlockRange {
                        device,
                        length_bytes,
                        ..
                    } => (device, Some(*length_bytes)),
                    _ => return None,
                };
                let node = world
                    .io_nodes()
                    .find(|node| node.fault_target_hash() == *hash)?;
                let contract = topology.storage_devices.iter().find(|device| {
                    device.device.as_str() == node.id.name.as_str()
                        && device.kind == WorldStorageKind::Block
                })?;
                Some(
                    selected_length
                        .unwrap_or(contract.persistence.maximum_request_bytes)
                        .min(contract.persistence.maximum_request_bytes),
                )
            })
            .collect::<Option<Vec<_>>>()
            .filter(|lengths| !lengths.is_empty())
            .and_then(|lengths| lengths.into_iter().max())
    };
    let typed_result = &[StoragePolicyArtifactClass::TypedResult];
    let require_typed_result = |reference: &FaultObjectId,
                                field: &'static str,
                                success: Option<bool>|
     -> Result<(), FaultSignalAuthoringError> {
        require(reference, typed_result, field)?;
        let declaration = topology.storage_policy_artifact(reference).ok_or_else(|| {
            FaultSignalAuthoringError::InvalidStoragePolicyReference {
                binding: binding.id().as_str().to_owned(),
                reference: reference.as_str().to_owned(),
                field,
                expected: String::from("typed result matching the target protocol"),
                actual: None,
            }
        })?;
        let StoragePolicyArtifactKind::TypedResult(result) = &declaration.artifact else {
            return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                binding: binding.id().as_str().to_owned(),
                reference: reference.as_str().to_owned(),
                field,
                expected: String::from("typed result"),
                actual: Some(declaration.artifact.class().as_str()),
            });
        };
        let ninep = binding
            .selector()
            .resolved()
            .targets()
            .iter()
            .all(|target| target.kind() == FaultTargetKind::NinePDevice);
        let block = binding
            .selector()
            .resolved()
            .targets()
            .iter()
            .all(|target| target.kind() != FaultTargetKind::NinePDevice);
        let protocol_matches = matches!(result, StoragePolicyTypedResult::NineP { .. }) && ninep
            || matches!(result, StoragePolicyTypedResult::Block { .. }) && block;
        let success_matches = match (success, result) {
            (None, _) => true,
            (Some(expected), StoragePolicyTypedResult::Block { result }) => {
                (*result == StoragePolicyResult::Success) == expected
            }
            (Some(false), StoragePolicyTypedResult::NineP { .. }) => true,
            (Some(true), StoragePolicyTypedResult::NineP { .. }) => false,
        };
        if protocol_matches && success_matches {
            return Ok(());
        }
        Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
            binding: binding.id().as_str().to_owned(),
            reference: reference.as_str().to_owned(),
            field,
            expected: String::from("typed result matching target protocol and result context"),
            actual: Some(declaration.artifact.class().as_str()),
        })
    };
    match specification {
        StorageEffectSpecification::Service { service_policy, .. } => {
            require(
                service_policy,
                &[StoragePolicyArtifactClass::Service],
                "service_policy",
            )?;
        }
        StorageEffectSpecification::OperationFailure { status, .. } => {
            require_typed_result(status, "status", Some(false))?;
        }
        StorageEffectSpecification::StallTimeout {
            recovery_event,
            timeout_result,
            ..
        } => {
            require_typed_result(timeout_result, "timeout_result", Some(false))?;
            if let Some(recovery_event) = recovery_event {
                require_program_node(recovery_event, "recovery_event")?;
            }
        }
        StorageEffectSpecification::FlushDisposition {
            kind,
            status,
            recovery_event,
            ..
        } => {
            require_typed_result(
                status,
                "status",
                Some(!matches!(
                    kind,
                    StorageFlushKind::Error | StorageFlushKind::Stall
                )),
            )?;
            if let Some(recovery_event) = recovery_event {
                require_program_node(recovery_event, "recovery_event")?;
            }
        }
        StorageEffectSpecification::DuplicateCompletion {
            copies,
            gap_nanos,
            protocol_policy,
        } => {
            if copies.get() > 256 || gap_nanos.checked_mul(u64::from(copies.get())).is_none() {
                return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: format!("{}x{}", copies.get(), gap_nanos),
                    field: "copies/gap_nanos",
                    expected: String::from(
                        "at most 256 copies with representable cumulative delay",
                    ),
                    actual: None,
                });
            }
            require(
                protocol_policy,
                &[StoragePolicyArtifactClass::DuplicateCompletion],
                "protocol_policy",
            )?;
            if let Some(StoragePolicyArtifactKind::DuplicateCompletion(
                StoragePolicyDuplicateCompletion::ProtocolError { result },
            )) = topology
                .storage_policy_artifact(protocol_policy)
                .map(|artifact| &artifact.artifact)
            {
                require_typed_result(result, "protocol_policy.result", Some(false))?;
            }
        }
        StorageEffectSpecification::ReadTransform { mutation } => match mutation {
            StorageReadMutation::Stale { version } => {
                require(
                    version,
                    &[StoragePolicyArtifactClass::Bytes],
                    "mutation.version",
                )?;
                let bytes = topology
                    .storage_policy_artifact(version)
                    .and_then(|artifact| match &artifact.artifact {
                        StoragePolicyArtifactKind::Bytes { bytes } => Some(bytes.len()),
                        _ => None,
                    });
                if selected_maximum_request_bytes().is_none_or(|maximum| {
                    bytes.is_none_or(|bytes| u64::try_from(bytes).unwrap_or(u64::MAX) < maximum)
                }) {
                    return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: version.as_str().to_owned(),
                        field: "mutation.version",
                        expected: String::from(
                            "byte artifact large enough for every legal selected read",
                        ),
                        actual: Some(StoragePolicyArtifactClass::Bytes.as_str()),
                    });
                }
            }
            StorageReadMutation::Misdirected {
                source_device,
                source_range,
            } => {
                require_block_range(source_device, *source_range, "mutation.source_range")?;
                if selected_maximum_request_bytes()
                    .is_none_or(|maximum| source_range.length() < maximum)
                {
                    return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: source_range.length().to_string(),
                        field: "mutation.source_range.length",
                        expected: String::from(
                            "range large enough for every legal selected request",
                        ),
                        actual: None,
                    });
                }
            }
            StorageReadMutation::BitFlip { range, mask } => {
                let minimum_read = selected_block_contracts().and_then(|contracts| {
                    contracts
                        .iter()
                        .map(|device| u64::from(device.persistence.logical_block_bytes))
                        .min()
                });
                if u64::try_from(mask.decoded_len()).ok() != Some(range.length())
                    || minimum_read.is_none_or(|minimum| range.end() > minimum)
                {
                    return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: format!("{}+{}", range.start(), range.length()),
                        field: "mutation.range/mask",
                        expected: String::from(
                            "equal-length mask fitting every legal selected read",
                        ),
                        actual: None,
                    });
                }
            }
        },
        StorageEffectSpecification::WriteDisposition {
            disposition,
            acknowledged_status,
        } => {
            require_typed_result(acknowledged_status, "acknowledged_status", None)?;
            if let StorageWriteDispositionKind::Misdirected {
                destination_device,
                destination_range,
            } = disposition
            {
                require_block_range(
                    destination_device,
                    *destination_range,
                    "disposition.destination_range",
                )?;
                if selected_maximum_request_bytes()
                    .is_none_or(|maximum| destination_range.length() < maximum)
                {
                    return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: destination_range.length().to_string(),
                        field: "disposition.destination_range.length",
                        expected: String::from(
                            "range large enough for every legal selected request",
                        ),
                        actual: None,
                    });
                }
            }
        }
        StorageEffectSpecification::PersistenceOrder { ordering_rule, .. } => {
            require(
                ordering_rule,
                &[StoragePolicyArtifactClass::Persistence],
                "ordering_rule",
            )?;
        }
        StorageEffectSpecification::VolatileCache {
            capacity_bytes,
            cache_policy,
        } => {
            require(
                cache_policy,
                &[StoragePolicyArtifactClass::Cache],
                "cache_policy",
            )?;
            if let Some(StoragePolicyArtifactKind::Cache(policy)) = topology
                .storage_policy_artifact(cache_policy)
                .map(|artifact| &artifact.artifact)
                && let StoragePolicyDirtyEviction::Fail { result } = &policy.dirty_eviction
            {
                require_typed_result(result, "cache_policy.dirty_eviction.result", Some(false))?;
            }
            if selected_block_contracts().is_none_or(|contracts| {
                contracts
                    .iter()
                    .any(|device| capacity_bytes.get() > device.persistence.volatile_cache_bytes)
            }) {
                return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: capacity_bytes.get().to_string(),
                    field: "capacity_bytes",
                    expected: String::from(
                        "capacity at or below every selected device volatile-cache bound",
                    ),
                    actual: None,
                });
            }
        }
        StorageEffectSpecification::VolatileCacheLoss { selector, .. } => {
            if let StorageVolatileCacheLossSelector::RangeIntersection { range } = selector {
                let valid = binding
                    .selector()
                    .resolved()
                    .targets()
                    .iter()
                    .all(|target| {
                        let hash = match target {
                            ResolvedFaultTarget::BlockDevice { device }
                            | ResolvedFaultTarget::BlockRange { device, .. } => device,
                            _ => return false,
                        };
                        let Some(node) = world
                            .io_nodes()
                            .find(|node| node.fault_target_hash() == *hash)
                        else {
                            return false;
                        };
                        topology.storage_devices.iter().any(|device| {
                            let block = u64::from(device.persistence.logical_block_bytes);
                            device.device.as_str() == node.id.name.as_str()
                                && device.kind == WorldStorageKind::Block
                                && range.end() <= device.persistence.length_bytes
                                && range.start().is_multiple_of(block)
                                && range.length().is_multiple_of(block)
                        })
                    });
                if !valid {
                    return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: format!("{}+{}", range.start(), range.length()),
                        field: "selector.range",
                        expected: String::from(
                            "in-bounds logical-block-aligned range on every selected block device",
                        ),
                        actual: None,
                    });
                }
            }
        }
        StorageEffectSpecification::FlashState {
            erase_block_bytes,
            program_page_bytes,
            endurance_cycles,
            retention_rule,
            read_disturb_rule,
            program_erase_rule,
            ..
        } => {
            require(
                retention_rule,
                &[StoragePolicyArtifactClass::Retention],
                "retention_rule",
            )?;
            require(
                read_disturb_rule,
                &[StoragePolicyArtifactClass::ReadDisturb],
                "read_disturb_rule",
            )?;
            require(
                program_erase_rule,
                &[StoragePolicyArtifactClass::ProgramErase],
                "program_erase_rule",
            )?;
            if selected_block_contracts().is_none_or(|contracts| {
                contracts.iter().any(|device| {
                    device.media.flash_geometry()
                        != Some((
                            erase_block_bytes.get(),
                            u32::try_from(program_page_bytes.get()).unwrap_or(u32::MAX),
                            endurance_cycles.get(),
                        ))
                })
            }) {
                return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: format!(
                        "{}/{}/{}",
                        erase_block_bytes.get(),
                        program_page_bytes.get(),
                        endurance_cycles.get()
                    ),
                    field: "flash geometry",
                    expected: String::from(
                        "exact Flash media geometry on every selected block device",
                    ),
                    actual: None,
                });
            }
        }
        StorageEffectSpecification::ControllerLifecycle {
            transition,
            transition_policy,
            namespaces,
            paths,
        } => {
            require(
                transition_policy,
                &[StoragePolicyArtifactClass::ControllerTransition],
                "transition_policy",
            )?;
            let transition_matches = topology
                .storage_policy_artifact(transition_policy)
                .is_some_and(|artifact| {
                    matches!(
                        &artifact.artifact,
                        StoragePolicyArtifactKind::ControllerTransition(policy)
                            if policy.transition == *transition
                    )
                });
            if !transition_matches {
                return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: transition_policy.as_str().to_owned(),
                    field: "transition_policy.transition",
                    expected: format!("policy for {transition:?}"),
                    actual: Some(StoragePolicyArtifactClass::ControllerTransition.as_str()),
                });
            }
            let targets = binding.selector().resolved().targets();
            let exact_controller_targets = !targets.is_empty() && targets.iter().enumerate().all(|(index, target)| {
                let ResolvedFaultTarget::StorageController { controller, .. } = target else { return false; };
                !targets[..index].iter().any(|prior| matches!(prior, ResolvedFaultTarget::StorageController { controller: candidate, .. } if candidate == controller))
            });
            let owned = exact_controller_targets
                && targets.iter().all(|target| {
                    let ResolvedFaultTarget::StorageController {
                        controller: controller_id,
                        ..
                    } = target
                    else {
                        return false;
                    };
                    topology
                        .storage_controllers
                        .iter()
                        .find(|controller| controller.id.as_str() == controller_id.as_str())
                        .is_some_and(|controller| {
                            namespaces.as_slice().iter().all(|namespace| {
                                controller
                                    .namespaces
                                    .iter()
                                    .any(|declared| declared.id.as_str() == namespace.as_str())
                            }) && paths.as_slice().iter().all(|path| {
                                controller
                                    .paths
                                    .iter()
                                    .any(|declared| declared.id.as_str() == path.as_str())
                            })
                        })
                });
            if !owned {
                return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: String::from("controller lifecycle set"),
                    field: "namespaces/paths",
                    expected: String::from(
                        "namespaces and paths owned by every selected World controller",
                    ),
                    actual: None,
                });
            }
        }
        StorageEffectSpecification::ArrayState {
            layout,
            member_path_state,
            selection_policy,
            rebuild_service,
            consistency_policy,
            failure_result,
        } => {
            let array = topology
                .storage_arrays
                .iter()
                .find(|array| array.id.as_str() == layout.as_str());
            let selected_targets = binding.selector().resolved().targets();
            let exact_array_targets = !selected_targets.is_empty()
                && selected_targets.iter().all(|target| {
                    matches!(
                        target,
                        ResolvedFaultTarget::StorageArray { array, .. }
                            if array.as_str() == layout.as_str()
                    )
                });
            if array.is_none() || !exact_array_targets {
                return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: layout.as_str().to_owned(),
                    field: "layout",
                    expected: String::from("world storage array"),
                    actual: None,
                });
            }
            require(
                member_path_state,
                &[StoragePolicyArtifactClass::ArrayState],
                "member_path_state",
            )?;
            let state_matches = array.is_some_and(|array| {
                let expected_members = array
                    .members
                    .iter()
                    .map(|member| member.id.as_str())
                    .collect::<Vec<_>>();
                let expected_paths = array
                    .paths
                    .iter()
                    .map(|path| path.id.as_str())
                    .collect::<Vec<_>>();
                topology
                    .storage_policy_artifact(member_path_state)
                    .is_some_and(|artifact| match &artifact.artifact {
                        StoragePolicyArtifactKind::ArrayState { members, paths } => {
                            members
                                .iter()
                                .map(|member| member.member.as_str())
                                .eq(expected_members)
                                && paths
                                    .iter()
                                    .map(|path| path.path.as_str())
                                    .eq(expected_paths)
                        }
                        _ => false,
                    })
            });
            if !state_matches {
                return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: member_path_state.as_str().to_owned(),
                    field: "member_path_state",
                    expected: String::from(
                        "array_state containing every and only the selected array's members and paths",
                    ),
                    actual: Some(StoragePolicyArtifactClass::ArrayState.as_str()),
                });
            }
            require(
                selection_policy,
                &[StoragePolicyArtifactClass::ArraySelection],
                "selection_policy",
            )?;
            require(
                rebuild_service,
                &[StoragePolicyArtifactClass::Rebuild],
                "rebuild_service",
            )?;
            require(
                consistency_policy,
                &[StoragePolicyArtifactClass::ArrayConsistency],
                "consistency_policy",
            )?;
            require(
                failure_result,
                &[StoragePolicyArtifactClass::TypedResult],
                "failure_result",
            )?;
            let block_failure = topology
                .storage_policy_artifact(failure_result)
                .is_some_and(|artifact| {
                    matches!(
                        artifact.artifact,
                        StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::Block {
                            result
                        }) if result != StoragePolicyResult::Success
                    )
                });
            if !block_failure {
                return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: failure_result.as_str().to_owned(),
                    field: "failure_result",
                    expected: String::from("non-success block typed_result"),
                    actual: Some(StoragePolicyArtifactClass::TypedResult.as_str()),
                });
            }
        }
        StorageEffectSpecification::NinePResult {
            kind,
            errno,
            version,
            object,
            ..
        } => match kind {
            NinePResultKind::Errno => {
                if errno.is_none_or(|errno| errno <= 0) {
                    return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: errno.unwrap_or_default().to_string(),
                        field: "errno",
                        expected: String::from("positive Linux errno"),
                        actual: None,
                    });
                }
            }
            NinePResultKind::Stale => require(
                version.as_ref().ok_or_else(|| {
                    FaultSignalAuthoringError::InvalidStoragePolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: String::from("absent"),
                        field: "version",
                        expected: String::from("ninep_object"),
                        actual: None,
                    }
                })?,
                &[StoragePolicyArtifactClass::NinePObject],
                "version",
            )?,
            NinePResultKind::Misdirected => require(
                object.as_ref().ok_or_else(|| {
                    FaultSignalAuthoringError::InvalidStoragePolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: String::from("absent"),
                        field: "object",
                        expected: String::from("ninep_object"),
                        actual: None,
                    }
                })?,
                &[StoragePolicyArtifactClass::NinePObject],
                "object",
            )?,
        },
        StorageEffectSpecification::NinePVisibility {
            update,
            visibility_event,
            visibility_policy,
            ..
        } => {
            require(update, &[StoragePolicyArtifactClass::NinePObject], "update")?;
            require(
                visibility_policy,
                &[StoragePolicyArtifactClass::NinePVisibility],
                "visibility_policy",
            )?;
            if let Some(visibility_event) = visibility_event {
                require_program_node(visibility_event, "visibility_event")?;
            }
        }
        StorageEffectSpecification::ReportedCapacity { length_bytes, .. } => {
            if selected_block_contracts().is_none_or(|contracts| {
                contracts.iter().any(|device| {
                    length_bytes.get() > device.persistence.length_bytes
                        || !length_bytes
                            .get()
                            .is_multiple_of(u64::from(device.persistence.logical_block_bytes))
                })
            }) {
                return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: length_bytes.get().to_string(),
                    field: "length_bytes",
                    expected: String::from(
                        "logical-block-aligned capacity at or below every selected block device",
                    ),
                    actual: None,
                });
            }
        }
        StorageEffectSpecification::MediaRange { range, .. } => {
            if selected_block_contracts().is_none_or(|contracts| {
                contracts
                    .iter()
                    .any(|device| range.end() > device.persistence.length_bytes)
            }) {
                return Err(FaultSignalAuthoringError::InvalidStoragePolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: format!("{}+{}", range.start(), range.length()),
                    field: "range",
                    expected: String::from("in-bounds range on every selected block device"),
                    actual: None,
                });
            }
        }
        StorageEffectSpecification::Availability { .. }
        | StorageEffectSpecification::Latency { .. }
        | StorageEffectSpecification::CompletionReorder { .. } => {}
    }
    Ok(())
}
