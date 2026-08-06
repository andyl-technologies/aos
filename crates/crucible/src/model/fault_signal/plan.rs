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
    NetworkPolicyArtifactClass, NetworkPolicyArtifactKind, NetworkPolicyRfCorruption, World,
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
            if let NetworkPolicyArtifactKind::ContactPlan { intervals } = &declaration.artifact {
                if intervals.iter().any(|interval| {
                    beams.as_slice().binary_search(&interval.beam).is_err()
                        || gateways
                            .as_slice()
                            .binary_search(&interval.gateway)
                            .is_err()
                }) {
                    return Err(FaultSignalAuthoringError::InvalidNetworkPolicyReference {
                        binding: binding.id().as_str().to_owned(),
                        reference: declaration.id.as_str().to_owned(),
                        field: "intervals.beam/gateway",
                        expected: String::from("members of the effect beam and gateway sets"),
                        actual: Some("undeclared contact member"),
                    });
                }
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
