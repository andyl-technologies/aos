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

use crate::model::{NetworkPolicyArtifactClass, NetworkPolicyArtifactKind, World};

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
        Self {
            programs: Vec::new(),
            bindings: Vec::new(),
            id: ContentHash::from_canonical_material(
                "crucible.fault-signal-plan.v1",
                "programs=0\nbindings=0",
            ),
            wire_bytes: b"{\"semantic_version\":1,\"signal_program\":[],\"fault_binding\":[]}"
                .to_vec(),
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
    ) -> Result<Self, FaultSignalPlanError> {
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
        bindings.sort_by(|left, right| left.id().cmp(right.id()));
        if bindings.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(FaultSignalPlanError::DuplicateBinding);
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
        let mut material = format!("programs={}\nbindings={}", programs.len(), bindings.len());
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
            id: ContentHash::from_canonical_material("crucible.fault-signal-plan.v1", &material),
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
            discipline_parameters: Some(reference),
            ..
        } => {
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
            if let NetworkPolicyArtifactKind::QueueDiscipline(parameters) = &declaration.artifact {
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
            NetworkPayloadMutation::UndetectedCorruption { transform } => require(
                transform,
                &[NetworkPolicyArtifactClass::ByteTemplate],
                "transform",
            )?,
            NetworkPayloadMutation::BitFlip { .. } | NetworkPayloadMutation::Truncate { .. } => {}
        },
        NetworkEffectSpecification::PauseBackpressure {
            resume_event: Some(reference),
            ..
        } => require(reference, state_machine, "resume_event")?,
        NetworkEffectSpecification::Mtu {
            typed_error: Some(reference),
            ..
        } => require(
            reference,
            &[NetworkPolicyArtifactClass::ControlResult],
            "typed_error",
        )?,
        NetworkEffectSpecification::ForwardingMutation { selector, .. } => require(
            selector,
            &[NetworkPolicyArtifactClass::PacketSelector],
            "selector",
        )?,
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
        }
        NetworkEffectSpecification::FirewallDisposition {
            typed_reject,
            rule,
            state,
            ..
        } => {
            require(rule, &[NetworkPolicyArtifactClass::PacketSelector], "rule")?;
            require(state, state_machine, "state")?;
            if let Some(reference) = typed_reject {
                require(
                    reference,
                    &[NetworkPolicyArtifactClass::ControlResult],
                    "typed_reject",
                )?;
            }
        }
        NetworkEffectSpecification::ConnectionState { transition, .. } => {
            require(transition, state_machine, "transition")?;
        }
        NetworkEffectSpecification::SharedMedium {
            arbitration,
            collision_capture,
            backoff_duty_cycle,
            ..
        } => {
            for (reference, field) in [
                (arbitration, "arbitration"),
                (collision_capture, "collision_capture"),
                (backoff_duty_cycle, "backoff_duty_cycle"),
            ] {
                require(
                    reference,
                    &[NetworkPolicyArtifactClass::MediumAccess],
                    field,
                )?;
            }
        }
        NetworkEffectSpecification::RfChannel {
            propagation_fields,
            sinr_transfer,
            fading_field,
            ..
        } => {
            require(
                propagation_fields,
                &[NetworkPolicyArtifactClass::RfChannel],
                "propagation_fields",
            )?;
            require(
                sinr_transfer,
                &[NetworkPolicyArtifactClass::RfChannel],
                "sinr_transfer",
            )?;
            if let Some(reference) = fading_field {
                require(reference, integer, "fading_field")?;
            }
        }
        NetworkEffectSpecification::Association {
            candidates,
            selection_policy,
            timer_policy,
            authentication_policy,
            traffic_policy,
            ..
        } => {
            for (reference, field) in [
                (selection_policy, "selection_policy"),
                (timer_policy, "timer_policy"),
                (authentication_policy, "authentication_policy"),
                (traffic_policy, "traffic_policy"),
            ] {
                require(reference, &[NetworkPolicyArtifactClass::Association], field)?;
            }
            let declaration = topology
                .network_policy_artifact(selection_policy)
                .ok_or_else(
                    || FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: selection_policy.as_str().to_owned(),
                        field: "selection_policy",
                        expected: String::from("association"),
                        actual: None,
                    },
                )?;
            if let NetworkPolicyArtifactKind::Association(policy) = &declaration.artifact {
                let mut declared = policy
                    .candidates
                    .iter()
                    .map(|candidate| candidate.candidate.clone())
                    .collect::<Vec<_>>();
                declared.sort();
                declared.dedup();
                if declared.as_slice() != candidates.as_slice() {
                    return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: selection_policy.as_str().to_owned(),
                        field: "selection_policy.candidates",
                        expected: String::from("exact effect candidate set"),
                        actual: Some("different candidate set"),
                    });
                }
            }
        }
        NetworkEffectSpecification::ControlResultTransform { result, .. } => require(
            result,
            &[NetworkPolicyArtifactClass::ControlResult],
            "result",
        )?,
        NetworkEffectSpecification::Contact {
            intervals,
            transition_policy,
            range_delay_lookup,
            ..
        } => {
            require(
                intervals,
                &[NetworkPolicyArtifactClass::ContactPlan],
                "intervals",
            )?;
            require(transition_policy, state_machine, "transition_policy")?;
            require(range_delay_lookup, integer, "range_delay_lookup")?;
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
        }
        NetworkEffectSpecification::Availability { .. }
        | NetworkEffectSpecification::Flap { .. }
        | NetworkEffectSpecification::NegotiatedMode { .. }
        | NetworkEffectSpecification::PropagationDelay { .. }
        | NetworkEffectSpecification::AccessDelay { .. }
        | NetworkEffectSpecification::Jitter { .. }
        | NetworkEffectSpecification::ServiceCurve { .. }
        | NetworkEffectSpecification::TokenBucket { .. }
        | NetworkEffectSpecification::QueuePolicy { .. }
        | NetworkEffectSpecification::FrameLoss { .. }
        | NetworkEffectSpecification::Duplicate { .. }
        | NetworkEffectSpecification::Reorder { .. }
        | NetworkEffectSpecification::DetectedFrameError { .. }
        | NetworkEffectSpecification::Mtu { .. }
        | NetworkEffectSpecification::PauseBackpressure { .. }
        | NetworkEffectSpecification::RecipientSubset { .. }
        | NetworkEffectSpecification::ForwarderLifecycle { .. } => {}
    }
    Ok(())
}

impl Hash for FaultSignalPlan {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Failure to admit a scenario's complete signal-driven fault layer.
#[derive(Debug)]
pub enum FaultSignalPlanError {
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
