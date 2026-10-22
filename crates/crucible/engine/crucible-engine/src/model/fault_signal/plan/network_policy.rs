//! Network policy references and physical service binding admission.

use super::*;

pub(super) fn validate_network_effect_policy_references(
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
            .map(|declaration| &declaration.inputs);
        if actual == Some(&expected) {
            return Ok(());
        }
        if let Some(inputs) = actual {
            admit_input_copy(inputs)?;
        }
        let actual = actual.cloned();
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
            let actual_participants =
                borrowed_set(resources.as_slice().iter().map(FaultObjectId::as_str))?;
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
                let attached_interfaces = borrowed_set(
                    topology
                        .network_segments
                        .iter()
                        .filter(|segment| {
                            segment.medium.as_ref().is_some_and(|candidate| {
                                candidate.as_str() == declaration.id.as_str()
                            })
                        })
                        .flat_map(|segment| [&segment.interface_a, &segment.interface_b]),
                )?;
                let expected_participants = borrowed_set(
                    topology
                        .network_interfaces
                        .iter()
                        .filter(|interface| attached_interfaces.contains(&interface.id))
                        .map(|interface| interface.endpoint.as_str()),
                )?;
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
            crate::owned_decode::charge_array::<ServiceProfileInput>(4)
                .map_err(FaultSignalAuthoringError::OriginalAdmission)?;
            crate::owned_decode::charge_array::<u8>("distanceorientationinterferencefading".len())
                .map_err(FaultSignalAuthoringError::OriginalAdmission)?;
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
            crate::owned_decode::charge_array::<ServiceProfileInput>(1)
                .map_err(FaultSignalAuthoringError::OriginalAdmission)?;
            crate::owned_decode::charge_array::<u8>("range".len())
                .map_err(FaultSignalAuthoringError::OriginalAdmission)?;
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

fn borrowed_set<T: Ord>(
    items: impl IntoIterator<Item = T>,
) -> Result<BTreeSet<T>, FaultSignalAuthoringError> {
    let mut set = BTreeSet::new();
    for item in items {
        if !set.contains(&item) {
            crate::owned_decode::charge_btree_set_entry::<T>()
                .map_err(FaultSignalAuthoringError::OriginalAdmission)?;
            set.insert(item);
        }
    }
    Ok(set)
}

fn admit_input_copy(inputs: &[ServiceProfileInput]) -> Result<(), FaultSignalAuthoringError> {
    crate::owned_decode::charge_array::<ServiceProfileInput>(inputs.len())
        .map_err(FaultSignalAuthoringError::OriginalAdmission)?;
    for input in inputs {
        crate::owned_decode::charge_array::<u8>(input.role.as_str().len())
            .map_err(FaultSignalAuthoringError::OriginalAdmission)?;
        if let SignalValueType::Enum(schema) | SignalValueType::Event(schema) =
            &input.shape.value_type
        {
            crate::owned_decode::charge_array::<u8>(schema.as_str().len())
                .map_err(FaultSignalAuthoringError::OriginalAdmission)?;
        }
    }
    Ok(())
}
