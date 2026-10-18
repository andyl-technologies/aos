//! Canonical scenario ownership for signal-driven fault programs and bindings.
//!
//! A [`FaultSignalPlan`] is the sole scenario-level container for executable
//! fault causes. It admits already-validated signal programs and bindings,
//! rejects cross-program or duplicate identities, and derives one content
//! address over the complete executable contracts.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::model::{
    NetworkPolicyArtifactClass, NetworkPolicyArtifactKind, NetworkPolicyRfCorruption,
    StoragePolicyArtifactClass, StoragePolicyArtifactKind, StoragePolicyDirtyEviction,
    StoragePolicyDuplicateCompletion, StoragePolicyResult, StoragePolicyTypedResult, World,
    WorldStorageKind,
};

use super::*;

mod network_policy;
mod storage_policy;
use network_policy::validate_network_effect_policy_references;
use storage_policy::validate_storage_effect_policy_references;

#[path = "plan_world_resource_limits.rs"]
mod world_resource_limits;
use world_resource_limits::{
    reserve_usize, validate_network_effect_resource_limits, validate_world_resource_limits,
};

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
    wire_bytes: Cow<'static, [u8]>,
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
        Self {
            programs: Vec::new(),
            bindings: Vec::new(),
            resource_limits,
            id: ContentHash::from_canonical_material_bytes(
                "crucible.fault-signal-plan.v2",
                resource_limits::EMPTY_PLAN_MATERIAL.bytes(),
            ),
            wire_bytes: Cow::Borrowed(resource_limits::EMPTY_PLAN_WIRE.bytes()),
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
        programs.sort_unstable_by_key(SignalProgram::id);
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
        bindings.sort_unstable_by(|left, right| left.id().cmp(right.id()));
        if bindings.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(FaultSignalPlanError::DuplicateBinding);
        }
        let mut active_by_target = BTreeMap::<&ResolvedFaultTarget, u64>::new();
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
                    if current == 0 {
                        crate::owned_decode::charge_btree_entry::<&ResolvedFaultTarget, u64>()
                            .map_err(FaultSignalPlanError::OriginalAdmission)?;
                    }
                    active_by_target.insert(target, current + 1);
                }
            }
        }
        if let Some(binding) = bindings.iter().find(|binding| {
            !programs
                .iter()
                .any(|program| program.id() == binding.program())
        }) {
            return Err(FaultSignalPlanError::MissingProgram {
                binding: binding.id().clone(),
                program: binding.program(),
            });
        }
        crate::owned_decode::charge_array::<ContentHash>(bindings.len())
            .map_err(FaultSignalPlanError::OriginalAdmission)?;
        let mut binding_digests = Vec::new();
        binding_digests
            .try_reserve_exact(bindings.len())
            .map_err(|source| {
                FaultSignalPlanError::OriginalAdmission(
                    crate::owned_decode::DecodeAdmissionError::new(source),
                )
            })?;
        for binding in &bindings {
            let digest = binding
                .contract_digest()
                .map_err(FaultSignalPlanError::BindingCodec)?;
            binding_digests.push(digest);
        }
        let material = PlanMaterial {
            limits: resource_limits,
            programs: &programs,
            bindings: &bindings,
            binding_digests: &binding_digests,
        };
        let id = crate::model::canonical::hash_material("crucible.fault-signal-plan.v2", &material)
            .map_err(|source| FaultSignalPlanError::Canonical(Box::new(source)))?;
        let mut plan = Self {
            programs,
            bindings,
            resource_limits,
            id,
            wire_bytes: Cow::Borrowed(&[]),
        };
        plan.wire_bytes = crate::owned_decode::to_json_vec_bounded(
            &wire::borrowed::PlanWireRef(&plan),
            HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES,
        )
        .map_err(FaultSignalPlanError::OriginalAdmission)?
        .into();
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
        crate::owned_decode::from_json_slice::<FaultSignalPlanWire>(bytes)
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
        validate_world_resource_limits(self.resource_limits, world)?;
        for binding in &self.bindings {
            validate_selector_for_world(binding.selector(), world)?;
            validate_network_effect_resource_limits(self.resource_limits, binding)?;
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
                if nanos.checked_mul(SIM_TICKS_PER_NS).is_none() {
                    return Err(FaultSignalAuthoringError::RuntimeWakeupOverflow {
                        binding: binding.id().as_str().to_owned(),
                        nanos,
                    });
                }
            }
        }
        let expected_trajectory_shape = SignalShape {
            value_type: SignalValueType::Vector3(SignalVectorElementType::I64),
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
    ///
    /// # Errors
    /// Refuses exhausted original metadata credit or allocation failure before
    /// constructing a group's owned index.
    pub fn bindings_by_program(
        &self,
    ) -> Result<BTreeMap<ContentHash, Vec<&FaultBinding>>, FaultSignalPlanError> {
        let mut grouped = BTreeMap::<_, Vec<_>>::new();
        for program in &self.programs {
            let count = self
                .bindings
                .iter()
                .filter(|binding| binding.program() == program.id())
                .count();
            if count == 0 {
                continue;
            }
            crate::owned_decode::charge_btree_entry::<ContentHash, Vec<&FaultBinding>>()
                .map_err(FaultSignalPlanError::OriginalAdmission)?;
            let mut bindings = Vec::new();
            crate::owned_decode::reserve_vec(&mut bindings, count)
                .map_err(FaultSignalPlanError::OriginalAdmission)?;
            bindings.extend(
                self.bindings
                    .iter()
                    .filter(|binding| binding.program() == program.id()),
            );
            grouped.insert(program.id(), bindings);
        }
        Ok(grouped)
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
        let mut capabilities = BTreeSet::new();
        for binding in &self.bindings {
            let name = binding.effect().capability();
            if capabilities
                .iter()
                .any(|id: &FaultCapabilityId| id.as_str() == name)
            {
                continue;
            }
            crate::owned_decode::charge_btree_set_entry::<FaultCapabilityId>()
                .map_err(FaultSignalPlanError::OriginalAdmission)?;
            crate::owned_decode::charge_array::<u8>(name.len())
                .map_err(FaultSignalPlanError::OriginalAdmission)?;
            capabilities
                .insert(FaultCapabilityId::parse(name).map_err(FaultSignalPlanError::Capability)?);
        }
        Ok(capabilities)
    }
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
    /// Original artifact memory authority refused an allocation.
    OriginalAdmission(crate::owned_decode::DecodeAdmissionError),
    /// Canonical content addressing failed before plan publication.
    Canonical(Box<crate::model::EngineError>),
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
            Self::OriginalAdmission(source) => Some(source),
            Self::Canonical(source) => Some(source.as_ref()),
            Self::ResourceLimit(error) => Some(error),
            Self::BindingCodec(error) => Some(error),
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

struct PlanMaterial<'a> {
    limits: FaultResourceLimits,
    programs: &'a [SignalProgram],
    bindings: &'a [FaultBinding],
    binding_digests: &'a [ContentHash],
}

impl fmt::Display for PlanMaterial<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for descriptor in FAULT_RESOURCE_LIMIT_DESCRIPTORS {
            let value = self.limits.configured(descriptor.field).ok_or(fmt::Error)?;
            writeln!(formatter, "{}={value}", descriptor.field)?;
        }
        write!(
            formatter,
            "programs={}\nbindings={}",
            self.programs.len(),
            self.bindings.len()
        )?;
        for program in self.programs {
            write!(formatter, "\nprogram=")?;
            for byte in program.id().bytes {
                write!(formatter, "{byte:02x}")?;
            }
        }
        for (binding, digest) in self.bindings.iter().zip(self.binding_digests) {
            write!(formatter, "\nbinding={}:", binding.id().as_str())?;
            for byte in digest.bytes {
                write!(formatter, "{byte:02x}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "plan_test.rs"]
mod tests;
