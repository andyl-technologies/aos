//! Canonical scenario ownership for signal-driven fault programs and bindings.
//!
//! A [`FaultSignalPlan`] is the sole scenario-level container for executable
//! fault causes. It admits already-validated signal programs and bindings,
//! rejects cross-program or duplicate identities, and derives one content
//! address over the complete executable contracts.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;

use crate::model::{
    NetworkPolicyArtifactClass, NetworkPolicyArtifactKind, NetworkPolicyRfCorruption,
    StoragePolicyArtifactClass, StoragePolicyArtifactKind, StoragePolicyDirtyEviction,
    StoragePolicyDuplicateCompletion, StoragePolicyResult, StoragePolicyTypedResult, World,
    WorldStorageKind,
};

use super::*;

/// Exact maximum signal graphs in one scenario plan.
///
/// Public v2 authoring owns one flat `plan.signal` graph. Independent physical
/// causes are disconnected components in that graph rather than separately
/// addressable program containers.
pub const HARD_FAULT_SIGNAL_PROGRAM_LIMIT: usize = 1;
/// Maximum deterministic persistence bytes for one admitted fault layer.
pub const HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES: usize = 256 * 1024 * 1024;

/// Canonical, immutable signal-driven fault layer for one scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultSignalPlan {
    programs: Vec<SignalProgram>,
    bindings: Vec<FaultBinding>,
    resource_limits: FaultResourceLimits,
    id: ContentHash,
    wire_bytes: Vec<u8>,
}

impl Default for FaultSignalPlan {
    fn default() -> Self {
        Self::empty()
    }
}

impl FaultSignalPlan {
    /// Builds the empty fault layer.
    #[must_use]
    pub fn empty() -> Self {
        let resource_limits = FaultResourceLimits::default();
        let material = format!(
            "{}programs=0\nbindings=0",
            resource_limits.canonical_material()
        );
        let wire_bytes = format!(
            "{{\"semantic_version\":2,\"resource_limits\":{},\"signal_program\":[],\"fault_binding\":[]}}",
            resource_limits.canonical_json_object()
        )
        .into_bytes();
        Self {
            programs: Vec::new(),
            bindings: Vec::new(),
            resource_limits,
            id: ContentHash::from_canonical_material("crucible.fault-signal-plan.v2", &material),
            wire_bytes,
        }
    }

    /// Validates, canonicalizes, and addresses complete executable contracts.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalPlanError`] for excessive or duplicate programs or
    /// bindings, a binding admitted against an absent program, or canonical
    /// binding encoding failure.
    pub fn new(
        mut programs: Vec<SignalProgram>,
        mut bindings: Vec<FaultBinding>,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultSignalPlanError> {
        resource_limits
            .validate()
            .map_err(FaultSignalPlanError::ResourceLimit)?;
        let signal_limits = resource_limits
            .signal_limits()
            .map_err(FaultSignalPlanError::ResourceLimit)?;
        programs.sort_by_key(SignalProgram::id);
        if programs.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(FaultSignalPlanError::DuplicateProgram);
        }
        if programs.len() > HARD_FAULT_SIGNAL_PROGRAM_LIMIT {
            return Err(FaultSignalPlanError::TooManyPrograms {
                actual: programs.len(),
                hard: HARD_FAULT_SIGNAL_PROGRAM_LIMIT,
            });
        }
        if bindings.len() > HARD_FAULT_BINDING_LIMIT {
            return Err(FaultSignalPlanError::TooManyBindings {
                actual: bindings.len(),
                hard: HARD_FAULT_BINDING_LIMIT,
            });
        }
        let binding_count = u64::try_from(bindings.len()).map_err(|_| {
            FaultSignalPlanError::ResourceLimit(FaultResourceLimitError::UsageOverflow {
                field: "bindings",
                current: 0,
                requested: u64::MAX,
                configured: resource_limits.bindings,
                hard: u64::try_from(HARD_FAULT_BINDING_LIMIT).unwrap_or(u64::MAX),
            })
        })?;
        resource_limits
            .reserve("bindings", 0, binding_count)
            .map_err(FaultSignalPlanError::ResourceLimit)?;
        if let Some(program) = programs
            .iter()
            .find(|program| program.limits() != signal_limits)
        {
            return Err(FaultSignalPlanError::ProgramLimitsMismatch {
                program: program.id(),
            });
        }
        bindings.sort_by(|left, right| left.id().cmp(right.id()));
        if bindings.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(FaultSignalPlanError::DuplicateBinding);
        }
        let mut active_by_target = BTreeMap::<ResolvedFaultTarget, u64>::new();
        let mut trace_windows = 0_u64;
        let mut mapping_points = 0_u64;
        for binding in &bindings {
            reserve_usize(
                resource_limits,
                "signals_per_binding",
                0,
                binding.signals().len(),
            )?;
            reserve_usize(
                resource_limits,
                "resolved_targets_per_binding",
                0,
                binding.selector().resolved().targets().len(),
            )?;
            reserve_usize(
                resource_limits,
                "search_candidates_per_choice",
                0,
                binding.search().candidate_count(),
            )?;
            resource_limits
                .reserve(
                    "trace_mutation_windows",
                    trace_windows,
                    binding.search().trace_mutation_windows(),
                )
                .map_err(FaultSignalPlanError::ResourceLimit)?;
            trace_windows = trace_windows
                .checked_add(binding.search().trace_mutation_windows())
                .ok_or_else(|| {
                    FaultSignalPlanError::ResourceLimit(FaultResourceLimitError::UsageOverflow {
                        field: "trace_mutation_windows",
                        current: trace_windows,
                        requested: binding.search().trace_mutation_windows(),
                        configured: resource_limits.trace_mutation_windows,
                        hard: 262_144,
                    })
                })?;
            resource_limits
                .reserve(
                    "mapping_mutation_points",
                    mapping_points,
                    binding.search().mapping_mutation_points(),
                )
                .map_err(FaultSignalPlanError::ResourceLimit)?;
            mapping_points = mapping_points
                .checked_add(binding.search().mapping_mutation_points())
                .ok_or_else(|| {
                    FaultSignalPlanError::ResourceLimit(FaultResourceLimitError::UsageOverflow {
                        field: "mapping_mutation_points",
                        current: mapping_points,
                        requested: binding.search().mapping_mutation_points(),
                        configured: resource_limits.mapping_mutation_points,
                        hard: 262_144,
                    })
                })?;
            if matches!(
                binding.effect().lifetime(),
                EffectLifetime::Persistent | EffectLifetime::StateMachine
            ) {
                for target in binding.selector().resolved().targets() {
                    let current = active_by_target.get(target).copied().unwrap_or(0);
                    resource_limits
                        .reserve("active_contributions_per_target", current, 1)
                        .map_err(FaultSignalPlanError::ResourceLimit)?;
                    active_by_target.insert(target.clone(), current + 1);
                }
            }
        }
        let program_ids = programs
            .iter()
            .map(SignalProgram::id)
            .collect::<BTreeSet<_>>();
        if let Some(binding) = bindings
            .iter()
            .find(|binding| !program_ids.contains(&binding.program()))
        {
            return Err(FaultSignalPlanError::MissingProgram {
                binding: binding.id().clone(),
                program: binding.program(),
            });
        }
        let mut material = resource_limits.canonical_material();
        material.push_str(&format!(
            "programs={}\nbindings={}",
            programs.len(),
            bindings.len()
        ));
        for program in &programs {
            material.push_str("\nprogram=");
            material.push_str(&program.id().to_hex());
        }
        for binding in &bindings {
            let digest = binding
                .contract_digest()
                .map_err(FaultSignalPlanError::BindingCodec)?;
            material.push_str("\nbinding=");
            material.push_str(binding.id().as_str());
            material.push(':');
            material.push_str(&digest.to_hex());
        }
        let mut plan = Self {
            programs,
            bindings,
            resource_limits,
            id: ContentHash::from_canonical_material("crucible.fault-signal-plan.v2", &material),
            wire_bytes: Vec::new(),
        };
        plan.wire_bytes = encode_wire_bounded(
            &FaultSignalPlanWire::from_plan(&plan),
            HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES,
        )
        .map_err(FaultSignalPlanError::WireCodec)?;
        Ok(plan)
    }

    /// Returns the fault-layer content identity.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns signal programs in canonical content-identity order.
    #[must_use]
    pub fn programs(&self) -> &[SignalProgram] {
        &self.programs
    }

    /// Returns bindings in canonical authored-identity order.
    #[must_use]
    pub fn bindings(&self) -> &[FaultBinding] {
        &self.bindings
    }

    /// Returns the complete scenario-owned resource contract.
    #[must_use]
    pub const fn resource_limits(&self) -> FaultResourceLimits {
        self.resource_limits
    }

    /// Returns the versioned deterministic persistence bytes.
    #[must_use]
    pub(crate) fn wire_bytes(&self) -> &[u8] {
        &self.wire_bytes
    }

    /// Decodes and re-admits versioned deterministic persistence bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalPlanDecodeError`] for malformed JSON or any wire
    /// contract that fails semantic admission.
    pub(crate) fn from_wire_bytes(bytes: &[u8]) -> Result<Self, FaultSignalPlanDecodeError> {
        if bytes.len() > HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES {
            return Err(FaultSignalPlanDecodeError::WireLimit {
                actual: bytes.len(),
                hard: HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES,
            });
        }
        serde_json::from_slice::<FaultSignalPlanWire>(bytes)
            .map_err(FaultSignalPlanDecodeError::Json)?
            .admit()
            .map_err(FaultSignalPlanDecodeError::Admission)
    }

    /// Re-resolves every persisted selector against the supplied world.
    ///
    /// # Errors
    ///
    /// Returns a strict authoring error when a persisted target, fault domain,
    /// or dynamic path is absent or resolves differently in `world`.
    pub(crate) fn validate_for_world(
        &self,
        world: &World,
    ) -> Result<(), FaultSignalAuthoringError> {
        let icount_shift = world
            .vm_nodes()
            .iter()
            .map(|node| node.icount_shift)
            .max()
            .unwrap_or(0);
        let scale = 1_u64.checked_shl(u32::from(icount_shift)).unwrap_or(0);
        for binding in &self.bindings {
            validate_selector_for_world(binding.selector(), world)?;
            validate_network_effect_policy_references(binding, world)?;
            validate_storage_effect_policy_references(binding, world, &self.programs)?;
            let intervals = [
                match binding.sampling() {
                    BindingSampling::CadenceNanos(cadence) => Some(cadence.get()),
                    _ => None,
                },
                match binding.mapping() {
                    BindingMapping::Threshold {
                        residence_nanos, ..
                    } if *residence_nanos > 0 => Some(*residence_nanos),
                    _ => None,
                },
            ];
            for nanos in intervals.into_iter().flatten() {
                if scale == 0 || nanos % scale != 0 {
                    return Err(FaultSignalAuthoringError::RuntimeWakeupAlignment {
                        binding: binding.id().as_str().to_owned(),
                        nanos,
                        icount_shift,
                    });
                }
            }
        }
        let expected_trajectory_shape = SignalShape {
            value_type: SignalValueType::Vector3(Box::new(SignalValueType::I64)),
            unit: SignalUnit::Millimetres,
            scale_decimal_exponent: 0,
        };
        for endpoint in &world.fault_topology().mobile_endpoints {
            let node = self
                .programs
                .iter()
                .find_map(|program| program.exported_node(&endpoint.truth_trajectory))
                .ok_or_else(|| FaultSignalAuthoringError::MissingTrajectorySignal {
                    endpoint: endpoint.id.as_str().to_owned(),
                    signal: endpoint.truth_trajectory.as_str().to_owned(),
                })?;
            if node.domain != SignalDomain::VirtualTime || node.output != expected_trajectory_shape
            {
                return Err(FaultSignalAuthoringError::InvalidTrajectorySignal {
                    endpoint: endpoint.id.as_str().to_owned(),
                    signal: endpoint.truth_trajectory.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Returns bindings grouped by their exact admitted program identity.
    #[must_use]
    pub fn bindings_by_program(&self) -> BTreeMap<ContentHash, Vec<&FaultBinding>> {
        let mut grouped = BTreeMap::<_, Vec<_>>::new();
        for binding in &self.bindings {
            grouped.entry(binding.program()).or_default().push(binding);
        }
        grouped
    }

    /// Returns every fine-grained production capability required at admission.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalPlanError::Capability`] if a registry capability
    /// constant violates the canonical capability-ID grammar.
    pub fn required_capabilities(
        &self,
    ) -> Result<BTreeSet<FaultCapabilityId>, FaultSignalPlanError> {
        self.bindings
            .iter()
            .map(|binding| {
                FaultCapabilityId::parse(binding.effect().capability())
                    .map_err(FaultSignalPlanError::Capability)
            })
            .collect()
    }
}

fn reserve_usize(
    limits: FaultResourceLimits,
    field: &'static str,
    current: usize,
    requested: usize,
) -> Result<(), FaultSignalPlanError> {
    let current = u64::try_from(current).map_err(|_| {
        FaultSignalPlanError::ResourceLimit(FaultResourceLimitError::Representation {
            field,
            value: u64::MAX,
        })
    })?;
    let requested = u64::try_from(requested).map_err(|_| {
        FaultSignalPlanError::ResourceLimit(FaultResourceLimitError::Representation {
            field,
            value: u64::MAX,
        })
    })?;
    limits
        .reserve(field, current, requested)
        .map_err(FaultSignalPlanError::ResourceLimit)
}

fn validate_storage_effect_policy_references(
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
            let targeted = binding
                .selector()
                .resolved()
                .targets()
                .iter()
                .filter_map(|target| match target {
                    ResolvedFaultTarget::StorageController { controller, .. } => {
                        Some(controller.as_str())
                    }
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            let exact_controller_targets = targeted.len()
                == binding.selector().resolved().targets().len()
                && !targeted.is_empty();
            let owned =
                exact_controller_targets
                    && targeted.iter().all(|controller_id| {
                        topology
                            .storage_controllers
                            .iter()
                            .find(|controller| controller.id.as_str() == *controller_id)
                            .is_some_and(|controller| {
                                let declared_namespaces = controller
                                    .namespaces
                                    .iter()
                                    .map(|namespace| namespace.id.as_str())
                                    .collect::<BTreeSet<_>>();
                                let declared_paths = controller
                                    .paths
                                    .iter()
                                    .map(|path| path.id.as_str())
                                    .collect::<BTreeSet<_>>();
                                namespaces.as_slice().iter().all(|namespace| {
                                    declared_namespaces.contains(namespace.as_str())
                                }) && paths
                                    .as_slice()
                                    .iter()
                                    .all(|path| declared_paths.contains(path.as_str()))
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

fn validate_network_effect_policy_references(
    binding: &FaultBinding,
    world: &World,
) -> Result<(), FaultSignalAuthoringError> {
    let EffectSpecification::Network(specification) = binding.effect().specification() else {
        return Ok(());
    };
    let topology = world.fault_topology();
    let require = |reference: &FaultObjectId,
                   accepted: &[NetworkPolicyArtifactClass],
                   field: &'static str|
     -> Result<(), FaultSignalAuthoringError> {
        let actual = topology
            .network_policy_artifact(reference)
            .map(|declaration| declaration.artifact.class());
        if actual.is_some_and(|actual| accepted.contains(&actual)) {
            return Ok(());
        }
        Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
            binding: binding.id().as_str().to_owned(),
            reference: reference.as_str().to_owned(),
            field,
            expected: accepted
                .iter()
                .map(|class| class.as_str())
                .collect::<Vec<_>>()
                .join(" or "),
            actual: actual.map(NetworkPolicyArtifactClass::as_str),
        })
    };
    let integer = &[NetworkPolicyArtifactClass::IntegerLookup];
    let state_machine = &[NetworkPolicyArtifactClass::StateMachine];
    let require_service_inputs = |effect: &'static str,
                                  expected: Vec<ServiceProfileInput>|
     -> Result<(), FaultSignalAuthoringError> {
        let actual = binding
            .service_declaration()
            .map(|declaration| declaration.inputs.clone());
        if actual.as_ref() == Some(&expected) {
            return Ok(());
        }
        Err(FaultSignalAuthoringError::InvalidNetworkServiceInputs {
            binding: binding.id().as_str().to_owned(),
            effect,
            expected,
            actual,
        })
    };
    let require_path =
        |reference: &FaultObjectId, field: &'static str| -> Result<(), FaultSignalAuthoringError> {
            if topology
                .network_paths
                .iter()
                .any(|path| path.id.as_str() == reference.as_str())
            {
                return Ok(());
            }
            Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                binding: binding.id().as_str().to_owned(),
                reference: reference.as_str().to_owned(),
                field,
                expected: String::from("world network path"),
                actual: None,
            })
        };
    let require_vm =
        |reference: &FaultObjectId, field: &'static str| -> Result<(), FaultSignalAuthoringError> {
            if world
                .vm_nodes()
                .iter()
                .any(|node| node.id.name == reference.as_str())
            {
                return Ok(());
            }
            Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                binding: binding.id().as_str().to_owned(),
                reference: reference.as_str().to_owned(),
                field,
                expected: String::from("world VM node"),
                actual: None,
            })
        };
    let require_exhaustive_event = |machine: &FaultObjectId,
                                    event: &FaultObjectId,
                                    field: &'static str|
     -> Result<(), FaultSignalAuthoringError> {
        require(machine, state_machine, field)?;
        let declaration = topology.network_policy_artifact(machine).ok_or_else(|| {
            FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                binding: binding.id().as_str().to_owned(),
                reference: machine.as_str().to_owned(),
                field,
                expected: String::from("state_machine"),
                actual: None,
            }
        })?;
        let NetworkPolicyArtifactKind::StateMachine {
            states,
            transitions,
            ..
        } = &declaration.artifact
        else {
            return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                binding: binding.id().as_str().to_owned(),
                reference: machine.as_str().to_owned(),
                field,
                expected: String::from("state_machine"),
                actual: Some(declaration.artifact.class().as_str()),
            });
        };
        if states.iter().all(|state| {
            transitions
                .iter()
                .filter(|edge| {
                    &edge.from == state
                        && &edge.event == event
                        && edge.traffic_policy == NetworkInFlightPolicy::Preserve
                })
                .count()
                == 1
        }) {
            return Ok(());
        }
        Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
            binding: binding.id().as_str().to_owned(),
            reference: machine.as_str().to_owned(),
            field,
            expected: format!(
                "one `{event}` transition with preserve traffic policy from every state"
            ),
            actual: Some("non-exhaustive state machine"),
        })
    };
    match specification {
        NetworkEffectSpecification::ProfileDelta {
            loss_hazard,
            corruption_hazard,
            technology_metrics,
            ..
        } => {
            for (reference, field) in [
                (loss_hazard.as_ref(), "loss_hazard"),
                (corruption_hazard.as_ref(), "corruption_hazard"),
                (technology_metrics.as_ref(), "technology_metrics"),
            ] {
                if let Some(reference) = reference {
                    require(reference, integer, field)?;
                }
            }
        }
        NetworkEffectSpecification::PropagationDelay {
            distance_velocity_lookup: Some(reference),
            ..
        } => require(reference, integer, "distance_velocity_lookup")?,
        NetworkEffectSpecification::Jitter {
            distribution_lookup: Some(reference),
            ..
        } => require(reference, integer, "distribution_lookup")?,
        NetworkEffectSpecification::QueuePolicy {
            discipline,
            discipline_parameters,
            typed_error,
            ..
        } => {
            if let Some(reference) = discipline_parameters {
                require(
                    reference,
                    &[NetworkPolicyArtifactClass::QueueDiscipline],
                    "discipline_parameters",
                )?;
                let declaration = topology.network_policy_artifact(reference).ok_or_else(|| {
                    FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: reference.as_str().to_owned(),
                        field: "discipline_parameters",
                        expected: String::from("queue_discipline"),
                        actual: None,
                    }
                })?;
                let NetworkPolicyArtifactKind::QueueDiscipline(parameters) = &declaration.artifact
                else {
                    return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: reference.as_str().to_owned(),
                        field: "discipline_parameters",
                        expected: String::from("queue_discipline"),
                        actual: Some(declaration.artifact.class().as_str()),
                    });
                };
                let class_discipline = matches!(
                    discipline,
                    NetworkQueueDiscipline::StrictPriority
                        | NetworkQueueDiscipline::WeightedRoundRobin
                        | NetworkQueueDiscipline::DeficitRoundRobin
                );
                if class_discipline == parameters.classes.is_empty()
                    || matches!(discipline, NetworkQueueDiscipline::Red)
                        && !parameters.classes.is_empty()
                {
                    return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: reference.as_str().to_owned(),
                        field: "discipline_parameters.classes",
                        expected: if class_discipline {
                            String::from("nonempty queue classes")
                        } else {
                            String::from("no queue classes")
                        },
                        actual: Some(if parameters.classes.is_empty() {
                            "empty"
                        } else {
                            "nonempty"
                        }),
                    });
                }
                for class in &parameters.classes {
                    require(
                        &class.selector,
                        &[NetworkPolicyArtifactClass::PacketSelector],
                        "queue_class.selector",
                    )?;
                }
            }
            if let Some(reference) = typed_error {
                require(
                    reference,
                    &[NetworkPolicyArtifactClass::TypedResponse],
                    "typed_error",
                )?;
            }
        }
        NetworkEffectSpecification::BurstErrorState {
            state_parameters, ..
        } => {
            require(
                state_parameters,
                &[NetworkPolicyArtifactClass::ErrorStateTable],
                "state_parameters",
            )?;
            let declaration = topology
                .network_policy_artifact(state_parameters)
                .ok_or_else(
                    || FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: state_parameters.as_str().to_owned(),
                        field: "state_parameters",
                        expected: String::from("error_state_table"),
                        actual: None,
                    },
                )?;
            if let NetworkPolicyArtifactKind::ErrorStateTable { states, .. } = &declaration.artifact
            {
                if states.len() != 2 {
                    return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: state_parameters.as_str().to_owned(),
                        field: "state_parameters",
                        expected: String::from("two-state error_state_table"),
                        actual: Some("error_state_table"),
                    });
                }
                for state in states {
                    if let Some(transform) = &state.corruption_transform {
                        require(
                            transform,
                            &[NetworkPolicyArtifactClass::ByteTemplate],
                            "error_state.corruption_transform",
                        )?;
                    }
                }
            }
        }
        NetworkEffectSpecification::PayloadTransform { mutation } => match mutation {
            NetworkPayloadMutation::FieldMutation { field, replacement } => {
                require(
                    field,
                    &[NetworkPolicyArtifactClass::PacketSelector],
                    "field",
                )?;
                require(
                    replacement,
                    &[NetworkPolicyArtifactClass::ByteTemplate],
                    "replacement",
                )?;
            }
            NetworkPayloadMutation::UndetectedCorruption { transform } => {
                require(
                    transform,
                    &[NetworkPolicyArtifactClass::ByteTemplate],
                    "transform",
                )?;
                let nonempty = topology.network_policy_artifact(transform).is_some_and(
                    |artifact| {
                        matches!(
                            &artifact.artifact,
                            NetworkPolicyArtifactKind::ByteTemplate { bytes } if !bytes.is_empty()
                        )
                    },
                );
                if !nonempty {
                    return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: transform.as_str().to_owned(),
                        field: "transform",
                        expected: String::from("nonempty byte_template"),
                        actual: Some("empty byte_template"),
                    });
                }
            }
            NetworkPayloadMutation::BitFlip { .. } | NetworkPayloadMutation::Truncate { .. } => {}
        },
        NetworkEffectSpecification::Mtu {
            typed_error: Some(reference),
            ..
        } => require(
            reference,
            &[NetworkPolicyArtifactClass::TypedResponse],
            "typed_error",
        )?,
        NetworkEffectSpecification::ForwardingMutation { selector, mutation } => {
            require(
                selector,
                &[NetworkPolicyArtifactClass::PacketSelector],
                "selector",
            )?;
            use super::NetworkStaleEntryDisposition;
            match mutation {
                NetworkForwardingMutationKind::WrongPort { recipient } => {
                    require_vm(recipient, "recipient")?;
                }
                NetworkForwardingMutationKind::Flood { recipients } => {
                    for recipient in recipients.as_slice() {
                        require_vm(recipient, "recipients")?;
                    }
                }
                NetworkForwardingMutationKind::Loop { next_hop, .. } => {
                    require_vm(next_hop, "next_hop")?;
                }
                NetworkForwardingMutationKind::StaleAge {
                    expired: NetworkStaleEntryDisposition::Flood { recipients },
                    ..
                } => {
                    for recipient in recipients.as_slice() {
                        require_vm(recipient, "expired.recipients")?;
                    }
                }
                NetworkForwardingMutationKind::Blackhole
                | NetworkForwardingMutationKind::StaleAge { .. } => {}
            }
        }
        NetworkEffectSpecification::RouteTransition {
            old_route,
            new_route,
            convergence_events,
            ..
        } => {
            require_path(old_route, "old_route")?;
            require_path(new_route, "new_route")?;
            require(convergence_events, state_machine, "convergence_events")?;
        }
        NetworkEffectSpecification::ControlPlaneService {
            service_curve,
            overflow_policy,
            ..
        } => {
            require(
                service_curve,
                &[NetworkPolicyArtifactClass::ServiceCurve],
                "service_curve",
            )?;
            require(
                overflow_policy,
                &[NetworkPolicyArtifactClass::Overflow],
                "overflow_policy",
            )?;
            require_overflow_typed_error(
                topology,
                binding,
                overflow_policy,
                NetworkPolicyArtifactClass::ControlResult,
                "overflow_policy.typed_error",
            )?;
        }
        NetworkEffectSpecification::FirewallDisposition {
            typed_reject,
            rule,
            state_machine: machine,
            transition_event,
            ..
        } => {
            require(rule, &[NetworkPolicyArtifactClass::PacketSelector], "rule")?;
            require_exhaustive_event(machine, transition_event, "state_machine")?;
            if let Some(reference) = typed_reject {
                require(
                    reference,
                    &[NetworkPolicyArtifactClass::TypedResponse],
                    "typed_reject",
                )?;
            }
        }
        NetworkEffectSpecification::ConnectionState {
            flow_key,
            state_machine: machine,
            transition_event,
            overflow,
            ..
        } => {
            require(
                flow_key,
                &[NetworkPolicyArtifactClass::PacketKey],
                "flow_key",
            )?;
            require_exhaustive_event(machine, transition_event, "state_machine")?;
            if let NetworkConnectionOverflow::TypedError { response } = overflow {
                require(
                    response,
                    &[NetworkPolicyArtifactClass::TypedResponse],
                    "overflow.response",
                )?;
            }
        }
        NetworkEffectSpecification::SharedMedium {
            resources, policy, ..
        } => {
            require(
                policy,
                &[NetworkPolicyArtifactClass::MediumAccess],
                "policy",
            )?;
            let invalid_medium = |field| FaultSignalAuthoringError::InvalidNetworkMediumContract {
                binding: binding.id().as_str().to_owned(),
                field,
            };
            let actual_participants = resources
                .as_slice()
                .iter()
                .map(FaultObjectId::as_str)
                .collect::<BTreeSet<_>>();
            for target in binding.selector().resolved().targets() {
                let ResolvedFaultTarget::NetworkMedium { medium, resource } = target else {
                    return Err(invalid_medium("target"));
                };
                let declaration = topology
                    .network_media
                    .iter()
                    .find(|candidate| candidate.id.as_str() == medium.as_str())
                    .ok_or_else(|| invalid_medium("medium"))?;
                if declaration.access_policy.as_str() != policy.as_str()
                    || !declaration
                        .resources
                        .iter()
                        .any(|candidate| candidate.as_str() == resource.as_str())
                {
                    return Err(invalid_medium("policy_or_channel"));
                }
                let attached_interfaces = topology
                    .network_segments
                    .iter()
                    .filter(|segment| {
                        segment
                            .medium
                            .as_ref()
                            .is_some_and(|candidate| candidate.as_str() == declaration.id.as_str())
                    })
                    .flat_map(|segment| [&segment.interface_a, &segment.interface_b])
                    .collect::<BTreeSet<_>>();
                let expected_participants = topology
                    .network_interfaces
                    .iter()
                    .filter(|interface| attached_interfaces.contains(&interface.id))
                    .map(|interface| interface.endpoint.as_str())
                    .collect::<BTreeSet<_>>();
                if expected_participants.is_empty() || actual_participants != expected_participants
                {
                    return Err(invalid_medium("participants"));
                }
            }
        }
        NetworkEffectSpecification::RfChannel {
            propagation_fields,
            sinr_transfer,
            ..
        } => {
            let inputs = vec![
                ServiceProfileInput {
                    role: FaultObjectId::parse("distance").map_err(|_error| {
                        FaultSignalAuthoringError::InvalidField("service_profile.inputs.role")
                    })?,
                    shape: SignalShape {
                        value_type: SignalValueType::U64,
                        unit: SignalUnit::Millimetres,
                        scale_decimal_exponent: 0,
                    },
                },
                ServiceProfileInput {
                    role: FaultObjectId::parse("orientation").map_err(|_error| {
                        FaultSignalAuthoringError::InvalidField("service_profile.inputs.role")
                    })?,
                    shape: SignalShape {
                        value_type: SignalValueType::I64,
                        unit: SignalUnit::Millidegrees,
                        scale_decimal_exponent: 0,
                    },
                },
                ServiceProfileInput {
                    role: FaultObjectId::parse("interference").map_err(|_error| {
                        FaultSignalAuthoringError::InvalidField("service_profile.inputs.role")
                    })?,
                    shape: SignalShape {
                        value_type: SignalValueType::U64,
                        unit: SignalUnit::Femtowatts,
                        scale_decimal_exponent: 0,
                    },
                },
                ServiceProfileInput {
                    role: FaultObjectId::parse("fading").map_err(|_error| {
                        FaultSignalAuthoringError::InvalidField("service_profile.inputs.role")
                    })?,
                    shape: SignalShape {
                        value_type: SignalValueType::U64,
                        unit: SignalUnit::PartsPerMillion,
                        scale_decimal_exponent: 0,
                    },
                },
            ];
            require_service_inputs("rf_channel", inputs)?;
            require(
                propagation_fields,
                &[NetworkPolicyArtifactClass::RfPropagation],
                "propagation_fields",
            )?;
            require(
                sinr_transfer,
                &[NetworkPolicyArtifactClass::RfTransfer],
                "sinr_transfer",
            )?;
            let declaration = topology
                .network_policy_artifact(sinr_transfer)
                .ok_or_else(
                    || FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: sinr_transfer.as_str().to_owned(),
                        field: "sinr_transfer",
                        expected: String::from("rf_transfer"),
                        actual: None,
                    },
                )?;
            if let NetworkPolicyArtifactKind::RfTransfer(transfer) = &declaration.artifact {
                for profile in &transfer.profiles {
                    if let NetworkPolicyRfCorruption::Undetected { transform } =
                        &profile.corruption_action
                    {
                        require(
                            transform,
                            &[NetworkPolicyArtifactClass::ByteTemplate],
                            "sinr_transfer.corruption_action.transform",
                        )?;
                        let nonempty =
                            topology
                                .network_policy_artifact(transform)
                                .is_some_and(|artifact| {
                                    matches!(
                                        &artifact.artifact,
                                        NetworkPolicyArtifactKind::ByteTemplate { bytes }
                                            if !bytes.is_empty()
                                    )
                                });
                        if !nonempty {
                            return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                                binding: binding.id().as_str().to_owned(),
                                reference: transform.as_str().to_owned(),
                                field: "sinr_transfer.corruption_action.transform",
                                expected: String::from("nonempty byte_template"),
                                actual: Some("empty byte_template"),
                            });
                        }
                    }
                }
            }
        }
        NetworkEffectSpecification::Association { policy } => {
            require(policy, &[NetworkPolicyArtifactClass::Association], "policy")?;
            let declaration = topology.network_policy_artifact(policy).ok_or_else(|| {
                FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: policy.as_str().to_owned(),
                    field: "policy",
                    expected: String::from("association"),
                    actual: None,
                }
            })?;
            if let NetworkPolicyArtifactKind::Association(association_policy) =
                &declaration.artifact
            {
                let mut declared = association_policy
                    .candidates
                    .iter()
                    .map(|candidate| candidate.candidate.clone())
                    .collect::<Vec<_>>();
                declared.sort();
                declared.dedup();
                let mismatched_target =
                    binding
                        .selector()
                        .resolved()
                        .targets()
                        .iter()
                        .any(|target| {
                            let ResolvedFaultTarget::NetworkAttachment { attachment, .. } = target
                            else {
                                return true;
                            };
                            let Some(attachment) = topology
                                .network_attachments
                                .iter()
                                .find(|candidate| candidate.id.as_str() == attachment.as_str())
                            else {
                                return true;
                            };
                            attachment.candidates.len() != declared.len()
                                || attachment
                                    .candidates
                                    .iter()
                                    .map(SignalId::as_str)
                                    .ne(declared.iter().map(FaultObjectId::as_str))
                        });
                if mismatched_target {
                    return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: policy.as_str().to_owned(),
                        field: "policy.candidates",
                        expected: String::from("exact World attachment candidate set"),
                        actual: Some("different candidate set"),
                    });
                }
            }
        }
        NetworkEffectSpecification::ControlResultTransform {
            technology,
            operations,
            kind,
            result,
        } => {
            if binding
                .opportunity_filter()
                .is_none_or(|filter| filter.operations != *operations)
            {
                return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: technology.as_str().to_owned(),
                    field: "opportunity_filter.operations",
                    expected: String::from("exact control-result transform operation set"),
                    actual: Some("different or absent operation set"),
                });
            }
            if let Some(result) = result {
                require(
                    result,
                    &[NetworkPolicyArtifactClass::ControlResult],
                    "result",
                )?;
            }
            let result_schema = result.as_ref().and_then(|result| {
                topology
                    .network_policy_artifact(result)
                    .and_then(|artifact| {
                        let NetworkPolicyArtifactKind::ControlResult { schema, .. } =
                            &artifact.artifact
                        else {
                            return None;
                        };
                        Some(schema.as_str())
                    })
            });
            for target in binding.selector().resolved().targets() {
                let (expected_technology, allowed_operations, replacement_schema) = match target {
                    ResolvedFaultTarget::NetworkPath { .. } => (
                        "network-routing-v1",
                        &[FaultOperation::NetworkRoute][..],
                        "network-route-id-v1",
                    ),
                    ResolvedFaultTarget::NetworkAttachment { attachment, .. } => {
                        let attachment = topology
                            .network_attachments
                            .iter()
                            .find(|candidate| candidate.id.as_str() == attachment.as_str())
                            .ok_or_else(|| {
                                FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                                    binding: binding.id().as_str().to_owned(),
                                    reference: attachment.as_str().to_owned(),
                                    field: "target.attachment",
                                    expected: String::from("declared network attachment"),
                                    actual: None,
                                }
                            })?;
                        (
                            attachment.technology.as_str(),
                            &[
                                FaultOperation::NetworkAssociate,
                                FaultOperation::NetworkHandoff,
                            ][..],
                            "network-association-inputs-i64-v1",
                        )
                    }
                    ResolvedFaultTarget::NetworkForwarder { .. } => (
                        "network-forwarder-v1",
                        &[FaultOperation::NetworkChange][..],
                        "network-forwarder-state-v1",
                    ),
                    ResolvedFaultTarget::NetworkContact { .. } => (
                        "network-contact-v1",
                        &[
                            FaultOperation::NetworkAcquire,
                            FaultOperation::NetworkTeardown,
                        ][..],
                        "network-contact-plan-v1",
                    ),
                    _ => {
                        return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                            binding: binding.id().as_str().to_owned(),
                            reference: technology.as_str().to_owned(),
                            field: "target",
                            expected: String::from("network control target"),
                            actual: Some("different target kind"),
                        });
                    }
                };
                let operations_valid = operations
                    .as_slice()
                    .iter()
                    .all(|operation| allowed_operations.contains(operation));
                let schema_valid = match kind {
                    NetworkControlResultKind::Drop | NetworkControlResultKind::Stale => {
                        result_schema.is_none()
                    }
                    NetworkControlResultKind::Bias => {
                        matches!(target, ResolvedFaultTarget::NetworkAttachment { .. })
                            && result_schema == Some("network-score-bias-i64-v1")
                    }
                    NetworkControlResultKind::Replace => result_schema == Some(replacement_schema),
                    NetworkControlResultKind::Error => {
                        result_schema == Some("network-control-error-v1")
                    }
                };
                if technology.as_str() != expected_technology || !operations_valid || !schema_valid
                {
                    return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: technology.as_str().to_owned(),
                        field: "technology/operations/result",
                        expected: String::from(
                            "target-specific control technology, operations, and result schema",
                        ),
                        actual: Some("incompatible control transform contract"),
                    });
                }
            }
        }
        NetworkEffectSpecification::RecipientSubset {
            membership_version,
            drop_members,
            retain_count,
            ..
        } => {
            require(
                membership_version,
                &[NetworkPolicyArtifactClass::RecipientMembership],
                "membership_version",
            )?;
            let declaration = topology
                .network_policy_artifact(membership_version)
                .ok_or_else(
                    || FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: membership_version.as_str().to_owned(),
                        field: "membership_version",
                        expected: String::from("recipient_membership"),
                        actual: None,
                    },
                )?;
            if let NetworkPolicyArtifactKind::RecipientMembership { members } =
                &declaration.artifact
            {
                let invalid_drop = drop_members.as_ref().is_some_and(|dropped| {
                    dropped.as_slice().iter().any(|member| {
                        members
                            .binary_search_by(|candidate| candidate.member.cmp(member))
                            .is_err()
                    })
                });
                let invalid_retain = retain_count.as_ref().is_some_and(|count| {
                    usize::try_from(count.get())
                        .map_or(true, |count| count > members.as_slice().len())
                });
                if invalid_drop || invalid_retain {
                    return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: declaration.id.as_str().to_owned(),
                        field: "recipient_subset",
                        expected: String::from("drop subset and retain count within membership"),
                        actual: Some("out-of-membership selection"),
                    });
                }
            }
        }
        NetworkEffectSpecification::Contact {
            intervals,
            range_delay_lookup,
            beams,
            gateways,
        } => {
            require_service_inputs(
                "contact",
                vec![ServiceProfileInput {
                    role: FaultObjectId::parse("range").map_err(|_error| {
                        FaultSignalAuthoringError::InvalidField("service_profile.inputs.role")
                    })?,
                    shape: SignalShape {
                        value_type: SignalValueType::U64,
                        unit: SignalUnit::Millimetres,
                        scale_decimal_exponent: 0,
                    },
                }],
            )?;
            require(
                intervals,
                &[NetworkPolicyArtifactClass::ContactPlan],
                "intervals",
            )?;
            require(range_delay_lookup, integer, "range_delay_lookup")?;
            let declaration = topology.network_policy_artifact(intervals).ok_or_else(|| {
                FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: intervals.as_str().to_owned(),
                    field: "intervals",
                    expected: String::from("contact_plan"),
                    actual: None,
                }
            })?;
            if let NetworkPolicyArtifactKind::ContactPlan { intervals } = &declaration.artifact
                && intervals.iter().any(|interval| {
                    beams.as_slice().binary_search(&interval.beam).is_err()
                        || gateways
                            .as_slice()
                            .binary_search(&interval.gateway)
                            .is_err()
                })
            {
                return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                    binding: binding.id().as_str().to_owned(),
                    reference: declaration.id.as_str().to_owned(),
                    field: "intervals.beam/gateway",
                    expected: String::from("members of the effect beam and gateway sets"),
                    actual: Some("undeclared contact member"),
                });
            }
        }
        NetworkEffectSpecification::CustodyQueue {
            custody_policy,
            route_contact_plan,
            ..
        } => {
            require(
                custody_policy,
                &[NetworkPolicyArtifactClass::Overflow],
                "custody_policy",
            )?;
            require(
                route_contact_plan,
                &[NetworkPolicyArtifactClass::ContactPlan],
                "route_contact_plan",
            )?;
            require_overflow_typed_error(
                topology,
                binding,
                custody_policy,
                NetworkPolicyArtifactClass::TypedResponse,
                "custody_policy.typed_error",
            )?;
        }
        NetworkEffectSpecification::Availability { .. }
        | NetworkEffectSpecification::Flap { .. }
        | NetworkEffectSpecification::NegotiatedMode { .. }
        | NetworkEffectSpecification::PropagationDelay { .. }
        | NetworkEffectSpecification::AccessDelay { .. }
        | NetworkEffectSpecification::Jitter { .. }
        | NetworkEffectSpecification::ServiceCurve { .. }
        | NetworkEffectSpecification::TokenBucket { .. }
        | NetworkEffectSpecification::FrameLoss { .. }
        | NetworkEffectSpecification::Duplicate { .. }
        | NetworkEffectSpecification::Reorder { .. }
        | NetworkEffectSpecification::DetectedFrameError { .. }
        | NetworkEffectSpecification::Mtu { .. }
        | NetworkEffectSpecification::PauseBackpressure { .. }
        | NetworkEffectSpecification::ForwarderLifecycle { .. } => {}
    }
    Ok(())
}

fn require_overflow_typed_error(
    topology: &crate::model::WorldFaultTopology,
    binding: &FaultBinding,
    overflow: &FaultObjectId,
    expected: NetworkPolicyArtifactClass,
    field: &'static str,
) -> Result<(), FaultSignalAuthoringError> {
    let declaration = topology.network_policy_artifact(overflow).ok_or_else(|| {
        FaultSignalAuthoringError::InvalidNetworkPolicyReference {
            binding: binding.id().as_str().to_owned(),
            reference: overflow.as_str().to_owned(),
            field,
            expected: String::from("overflow"),
            actual: None,
        }
    })?;
    let NetworkPolicyArtifactKind::Overflow { typed_error, .. } = &declaration.artifact else {
        return Ok(());
    };
    let Some(typed_error) = typed_error else {
        return Ok(());
    };
    let actual = topology
        .network_policy_artifact(typed_error)
        .map(|result| result.artifact.class());
    if actual == Some(expected) {
        return Ok(());
    }
    Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
        binding: binding.id().as_str().to_owned(),
        reference: typed_error.as_str().to_owned(),
        field,
        expected: String::from(expected.as_str()),
        actual: actual.map(NetworkPolicyArtifactClass::as_str),
    })
}

impl Hash for FaultSignalPlan {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Failure to admit a scenario's complete signal-driven fault layer.
#[derive(Debug)]
pub enum FaultSignalPlanError {
    /// The complete plan resource contract is invalid or exceeded.
    ResourceLimit(FaultResourceLimitError),
    /// A signal graph was admitted with limits different from its owning plan.
    ProgramLimitsMismatch {
        /// Mismatched graph identity.
        program: ContentHash,
    },
    /// Program count exceeds the implementation-owned hard ceiling.
    TooManyPrograms {
        /// Submitted count.
        actual: usize,
        /// Compiled ceiling.
        hard: usize,
    },
    /// Binding count exceeds the implementation-owned hard ceiling.
    TooManyBindings {
        /// Submitted count.
        actual: usize,
        /// Compiled ceiling.
        hard: usize,
    },
    /// Two submitted programs have the same content identity.
    DuplicateProgram,
    /// Two submitted bindings reuse one authored binding identity.
    DuplicateBinding,
    /// A binding was admitted against a program absent from this plan.
    MissingProgram {
        /// Authored binding identity.
        binding: FaultObjectId,
        /// Missing content-addressed program identity.
        program: ContentHash,
    },
    /// Canonical binding encoding failed.
    BindingCodec(serde_json::Error),
    /// Complete plan persistence encoding failed.
    WireCodec(serde_json::Error),
    /// A compiled registry capability ID was malformed.
    Capability(FaultContractError),
}

impl fmt::Display for FaultSignalPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fault signal plan admission failed: {self:?}")
    }
}

impl Error for FaultSignalPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ResourceLimit(error) => Some(error),
            Self::BindingCodec(error) => Some(error),
            Self::WireCodec(error) => Some(error),
            Self::Capability(error) => Some(error),
            _ => None,
        }
    }
}

/// Failure to parse or semantically admit persisted fault-signal bytes.
#[derive(Debug)]
pub(crate) enum FaultSignalPlanDecodeError {
    /// The encoded plan exceeds the compiled persistence bound.
    WireLimit {
        /// Submitted byte count.
        actual: usize,
        /// Compiled byte ceiling.
        hard: usize,
    },
    /// JSON syntax or structural decoding failed.
    Json(serde_json::Error),
    /// The decoded contract failed semantic admission.
    Admission(FaultSignalWireError),
}

impl fmt::Display for FaultSignalPlanDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WireLimit { actual, hard } => write!(
                formatter,
                "fault signal plan wire bytes {actual} exceed hard limit {hard}"
            ),
            Self::Json(error) => write!(formatter, "decode fault signal plan JSON: {error}"),
            Self::Admission(error) => error.fmt(formatter),
        }
    }
}

impl Error for FaultSignalPlanDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::WireLimit { .. } => None,
            Self::Json(error) => Some(error),
            Self::Admission(error) => Some(error),
        }
    }
}

struct BoundedWireWriter {
    bytes: Vec<u8>,
    hard: usize,
}

impl io::Write for BoundedWireWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("fault signal wire length overflow"))?;
        if next > self.hard {
            return Err(io::Error::other(
                "fault signal wire exceeds compiled byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_wire_bounded<T: serde::Serialize>(
    value: &T,
    hard: usize,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut writer = BoundedWireWriter {
        bytes: Vec::new(),
        hard,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.bytes)
}

#[cfg(test)]
#[path = "plan_test.rs"]
mod tests;
