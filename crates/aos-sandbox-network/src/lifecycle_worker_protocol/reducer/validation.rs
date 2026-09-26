//! Closed transition and kernel-identity validation for the Network reducer.

use crate::namespace_catalog::{
    NetworkNamespaceLifecycleActionV1, NetworkNamespaceObservedStateKindV1,
    NetworkNamespaceObservedStateV1,
};

use super::{
    NetworkLifecycleActionProgressV1, NetworkLifecycleEffectStepV1, NetworkLifecycleFenceV1,
    NetworkLifecycleGateResidualV1, NetworkLifecycleIntentV1, NetworkLifecycleLinkIdentityV1,
    NetworkLifecycleLinkOperationalV1, NetworkLifecycleReducerError,
    NetworkLifecycleResidualPresenceV1, NetworkLifecycleResidualV1, NetworkLifecycleTcIdentityV1,
    NetworkLifecycleTopologyResidualV1, NetworkNamespacePinTeardownPhaseV1, residual_digest,
};

pub(super) fn validate_residual(
    intent: NetworkLifecycleIntentV1,
    residual: NetworkLifecycleResidualV1,
) -> Result<(), NetworkLifecycleReducerError> {
    let nonzero = [
        residual.resource_digest,
        residual.catalog_digest,
        residual.currentness_digest,
        residual.first_snapshot_digest,
        residual.second_snapshot_digest,
        residual.digest,
    ]
    .iter()
    .all(|digest| digest.as_bytes() != &[0; 32]);
    let pin_evidence_valid = match residual.pin_teardown {
        NetworkNamespacePinTeardownPhaseV1::Retained => true,
        NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(digest)
        | NetworkNamespacePinTeardownPhaseV1::EffectUnknown(digest)
        | NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(digest) => {
            digest.as_bytes() != &[0; 32]
        }
    };
    if !nonzero
        || !pin_evidence_valid
        || residual.intent_digest != intent.digest()
        || residual.assignment != intent.fence().assignment()
        || residual.kernel_digest != intent.kernel().digest()
        || residual.observed_boottime_nanoseconds == 0
        || residual.observation_ordinal == 0
        || residual.first_snapshot_digest != residual.second_snapshot_digest
        || residual.digest != residual_digest(residual)
        || residual.namespace == NetworkLifecycleResidualPresenceV1::Absent
            && !matches!(
                residual.pin_teardown,
                NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(_)
            )
        || residual.namespace != NetworkLifecycleResidualPresenceV1::Absent
            && matches!(
                residual.pin_teardown,
                NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(_)
            )
        || residual.links == NetworkLifecycleResidualPresenceV1::Absent
            && residual.tc != NetworkLifecycleResidualPresenceV1::Absent
        || !topology_matches_kernel(
            intent.kernel.links,
            residual.topology,
            residual.namespace,
            residual.links,
        )
        || residual.links == NetworkLifecycleResidualPresenceV1::Absent
            && residual.link_operational != NetworkLifecycleLinkOperationalV1::Absent
        || residual.links == NetworkLifecycleResidualPresenceV1::Present
            && !matches!(
                residual.link_operational,
                NetworkLifecycleLinkOperationalV1::Down | NetworkLifecycleLinkOperationalV1::Up
            )
    {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    if matches!(
        intent.kernel.links,
        NetworkLifecycleLinkIdentityV1::Isolated { .. }
    ) && (residual.links != NetworkLifecycleResidualPresenceV1::Absent
        || residual.link_operational != NetworkLifecycleLinkOperationalV1::Absent
        || residual.bpffs != NetworkLifecycleResidualPresenceV1::Absent
        || residual.tc != NetworkLifecycleResidualPresenceV1::Absent)
    {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }

    if intent.action() != NetworkNamespaceLifecycleActionV1::Destroy {
        let expected_owned_presence = match intent.kernel.links {
            NetworkLifecycleLinkIdentityV1::Isolated { .. } => {
                residual.links == NetworkLifecycleResidualPresenceV1::Absent
                    && residual.bpffs == NetworkLifecycleResidualPresenceV1::Absent
                    && residual.tc == NetworkLifecycleResidualPresenceV1::Absent
            }
            NetworkLifecycleLinkIdentityV1::Veth { .. } => {
                residual.links == NetworkLifecycleResidualPresenceV1::Present
                    && residual.bpffs == NetworkLifecycleResidualPresenceV1::Present
                    && residual.tc == NetworkLifecycleResidualPresenceV1::Present
            }
        };
        if residual.namespace != NetworkLifecycleResidualPresenceV1::Present
            || !expected_owned_presence
            || !matches!(
                residual.pin_teardown,
                NetworkNamespacePinTeardownPhaseV1::Retained
            )
        {
            return Err(NetworkLifecycleReducerError::ObservationMismatch);
        }
    }
    use NetworkLifecycleActionProgressV1 as Progress;
    use NetworkLifecycleResidualPresenceV1 as Presence;
    let progress_objects_valid = match residual.action_progress {
        Progress::TcDetached => residual.tc == Presence::Absent,
        Progress::BpffsRemoved => {
            residual.tc == Presence::Absent && residual.bpffs == Presence::Absent
        }
        Progress::LinksRemoved | Progress::PinAuthorized => {
            residual.tc == Presence::Absent
                && residual.bpffs == Presence::Absent
                && residual.links == Presence::Absent
                && topology_removable_absent(residual.topology)
                && residual.link_operational == NetworkLifecycleLinkOperationalV1::Absent
        }
        Progress::PinRemoved => {
            residual.namespace == Presence::Absent
                && residual.links == Presence::Absent
                && residual.bpffs == Presence::Absent
                && residual.tc == Presence::Absent
                && residual.gate == NetworkLifecycleGateResidualV1::Absent
                && topology_all_absent(residual.topology)
                && residual.link_operational == NetworkLifecycleLinkOperationalV1::Absent
        }
        _ => true,
    };
    if !progress_objects_valid {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    Ok(())
}

fn topology_matches_kernel(
    identity: NetworkLifecycleLinkIdentityV1,
    topology: NetworkLifecycleTopologyResidualV1,
    namespace: NetworkLifecycleResidualPresenceV1,
    aggregate: NetworkLifecycleResidualPresenceV1,
) -> bool {
    use NetworkLifecycleResidualPresenceV1 as Presence;

    match (identity, topology) {
        (
            NetworkLifecycleLinkIdentityV1::Isolated { .. },
            NetworkLifecycleTopologyResidualV1::Isolated { loopback },
        ) => {
            aggregate == Presence::Absent
                && loopback
                    == if namespace == Presence::Absent {
                        Presence::Absent
                    } else {
                        Presence::Present
                    }
        }
        (
            NetworkLifecycleLinkIdentityV1::Veth { .. },
            NetworkLifecycleTopologyResidualV1::Veth {
                loopback,
                host_peer,
                sandbox_peer,
                addresses,
                routes,
                neighbors,
            },
        ) => {
            let expected = if [host_peer, sandbox_peer]
                .iter()
                .all(|value| *value == Presence::Present)
            {
                Presence::Present
            } else if [host_peer, sandbox_peer]
                .iter()
                .all(|value| *value == Presence::Absent)
            {
                Presence::Absent
            } else {
                Presence::Partial
            };
            loopback
                == if namespace == Presence::Absent {
                    Presence::Absent
                } else {
                    Presence::Present
                }
                && aggregate == expected
                && (aggregate != Presence::Present
                    || [addresses, routes, neighbors]
                        .iter()
                        .all(|value| *value == Presence::Present))
                && (aggregate != Presence::Absent
                    || [addresses, routes, neighbors]
                        .iter()
                        .all(|value| *value == Presence::Absent))
        }
        _ => false,
    }
}

pub(super) fn next_effect_step(
    intent: NetworkLifecycleIntentV1,
    residual: NetworkLifecycleResidualV1,
) -> Result<Option<NetworkLifecycleEffectStepV1>, NetworkLifecycleReducerError> {
    validate_residual(intent, residual)?;
    use NetworkLifecycleActionProgressV1 as Progress;
    use NetworkLifecycleEffectStepV1 as Step;
    let step = match intent.action() {
        NetworkNamespaceLifecycleActionV1::Arm => match residual.action_progress {
            Progress::Initial => Some(Step::EnsureLinksDown),
            Progress::LinksDown => Some(Step::ProgramLeaseGate),
            Progress::GateProgrammed if residual.gate == armed_gate(intent) => {
                Some(Step::ConfigureExactAddressPairs)
            }
            Progress::AddressesConfigured => Some(Step::ConfigureExactRoutes),
            Progress::RoutesConfigured => Some(Step::ConfigureExactPermanentNeighbors),
            Progress::NeighborsConfigured => Some(Step::VerifyExactPlanConfiguration),
            Progress::PlanVerified => Some(Step::RaiseLinks),
            Progress::LinksRaised
                if residual.gate == armed_gate(intent)
                    && links_at_target(residual.topology, residual.link_operational, true)
                    && residual.state == intent.desired_state =>
            {
                None
            }
            _ => return Err(NetworkLifecycleReducerError::ObservationMismatch),
        },
        NetworkNamespaceLifecycleActionV1::Renew => match residual.action_progress {
            Progress::Initial => Some(Step::ProgramLeaseGate),
            Progress::GateProgrammed
                if residual.gate == armed_gate(intent)
                    && residual.state == intent.desired_state =>
            {
                None
            }
            _ => return Err(NetworkLifecycleReducerError::ObservationMismatch),
        },
        NetworkNamespaceLifecycleActionV1::Disarm => match residual.action_progress {
            Progress::Initial => Some(Step::LowerLinks),
            Progress::LinksDown => Some(Step::ProgramDefaultDrop),
            Progress::GateProgrammed
                if residual.gate == NetworkLifecycleGateResidualV1::DefaultDrop =>
            {
                Some(Step::ConfigureExactAddressPairs)
            }
            Progress::AddressesConfigured => Some(Step::ConfigureExactRoutes),
            Progress::RoutesConfigured => Some(Step::ConfigureExactPermanentNeighbors),
            Progress::NeighborsConfigured => Some(Step::VerifyExactPlanConfiguration),
            Progress::PlanVerified
                if residual.gate == NetworkLifecycleGateResidualV1::DefaultDrop
                    && links_at_target(residual.topology, residual.link_operational, false)
                    && residual.state == intent.desired_state =>
            {
                None
            }
            _ => return Err(NetworkLifecycleReducerError::ObservationMismatch),
        },
        NetworkNamespaceLifecycleActionV1::Destroy => {
            use NetworkLifecycleResidualPresenceV1 as Presence;

            if residual.action_progress == Progress::Initial {
                Some(Step::LowerLinks)
            } else if residual.action_progress == Progress::LinksDown {
                Some(Step::ProgramDefaultDrop)
            } else if residual.action_progress == Progress::GateProgrammed
                && residual.gate == NetworkLifecycleGateResidualV1::DefaultDrop
            {
                Some(Step::DetachTcGate)
            } else if residual.action_progress == Progress::TcDetached {
                Some(Step::RemoveBpffsPins)
            } else if residual.action_progress == Progress::BpffsRemoved {
                Some(Step::RemoveLinks)
            } else if residual.action_progress == Progress::LinksRemoved
                && residual.namespace != Presence::Absent
            {
                match residual.pin_teardown {
                    NetworkNamespacePinTeardownPhaseV1::Retained => {
                        Some(Step::AuthorizeNamespacePinTeardown)
                    }
                    NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(_) => {
                        return Err(NetworkLifecycleReducerError::ObservationMismatch);
                    }
                    NetworkNamespacePinTeardownPhaseV1::EffectUnknown(_) => {
                        return Err(NetworkLifecycleReducerError::Pending);
                    }
                    NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(_) => {
                        return Err(NetworkLifecycleReducerError::ObservationMismatch);
                    }
                }
            } else if residual.action_progress == Progress::PinAuthorized
                && matches!(
                    residual.pin_teardown,
                    NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(_)
                )
            {
                Some(Step::RemoveNamespacePin)
            } else if residual.action_progress == Progress::PinRemoved
                && residual.gate == NetworkLifecycleGateResidualV1::Absent
                && residual.state == intent.desired_state
            {
                None
            } else {
                return Err(NetworkLifecycleReducerError::ObservationMismatch);
            }
        }
        NetworkNamespaceLifecycleActionV1::Fence => {
            return Err(NetworkLifecycleReducerError::InvalidTransition);
        }
    };
    Ok(step)
}

fn armed_gate(intent: NetworkLifecycleIntentV1) -> NetworkLifecycleGateResidualV1 {
    NetworkLifecycleGateResidualV1::Armed {
        lease_digest: intent.fence().ownership_lease_digest(),
        lease_generation: intent.fence().lease_generation(),
        fail_stop_boottime_nanoseconds: intent.fence().fail_stop_boottime_nanoseconds(),
    }
}

pub(super) fn validate_step_progress(
    step: NetworkLifecycleEffectStepV1,
    prior: NetworkLifecycleResidualV1,
    current: NetworkLifecycleResidualV1,
) -> Result<(), NetworkLifecycleReducerError> {
    let time_advanced = current.observation_ordinal > prior.observation_ordinal
        && current.observed_boottime_nanoseconds >= prior.observed_boottime_nanoseconds;
    let identity_unchanged = current.intent_digest == prior.intent_digest
        && current.assignment == prior.assignment
        && current.kernel_digest == prior.kernel_digest
        && current.catalog_digest == prior.catalog_digest;
    let successor = expected_progress(step);
    let not_applied = current.action_progress == prior.action_progress
        && !residual_effect_changed(prior, current);
    let applied = current.action_progress == successor
        && current.currentness_digest != prior.currentness_digest;
    let valid = match step {
        NetworkLifecycleEffectStepV1::EnsureLinksDown
        | NetworkLifecycleEffectStepV1::LowerLinks => {
            current.namespace == prior.namespace
                && current.links == prior.links
                && current.topology == prior.topology
                && current.bpffs == prior.bpffs
                && current.tc == prior.tc
                && current.gate == prior.gate
                && current.pin_teardown == prior.pin_teardown
                && current.resource_digest == prior.resource_digest
                && links_at_target(current.topology, current.link_operational, false)
        }
        NetworkLifecycleEffectStepV1::ProgramLeaseGate
        | NetworkLifecycleEffectStepV1::ProgramDefaultDrop => {
            current.namespace == prior.namespace
                && current.links == prior.links
                && current.bpffs == prior.bpffs
                && current.tc == prior.tc
                && current.pin_teardown == prior.pin_teardown
                && current.topology == prior.topology
                && current.link_operational == prior.link_operational
                && match step {
                    NetworkLifecycleEffectStepV1::ProgramLeaseGate => {
                        matches!(current.gate, NetworkLifecycleGateResidualV1::Armed { .. })
                    }
                    NetworkLifecycleEffectStepV1::ProgramDefaultDrop => {
                        current.gate == NetworkLifecycleGateResidualV1::DefaultDrop
                    }
                    _ => false,
                }
        }
        NetworkLifecycleEffectStepV1::ConfigureExactAddressPairs
        | NetworkLifecycleEffectStepV1::ConfigureExactRoutes
        | NetworkLifecycleEffectStepV1::ConfigureExactPermanentNeighbors => {
            current.namespace == prior.namespace
                && current.links == prior.links
                && current.bpffs == prior.bpffs
                && current.tc == prior.tc
                && current.gate == prior.gate
                && current.pin_teardown == prior.pin_teardown
                && current.resource_digest == prior.resource_digest
                && current.link_operational == prior.link_operational
                && topology_configuration_progress(step, prior.topology, current.topology)
        }
        NetworkLifecycleEffectStepV1::VerifyExactPlanConfiguration => {
            current.namespace == prior.namespace
                && current.links == prior.links
                && current.topology == prior.topology
                && current.bpffs == prior.bpffs
                && current.tc == prior.tc
                && current.gate == prior.gate
                && current.pin_teardown == prior.pin_teardown
                && current.resource_digest == prior.resource_digest
                && current.link_operational == prior.link_operational
        }
        NetworkLifecycleEffectStepV1::RaiseLinks => {
            current.namespace == prior.namespace
                && current.links == prior.links
                && current.topology == prior.topology
                && current.bpffs == prior.bpffs
                && current.tc == prior.tc
                && current.gate == prior.gate
                && current.pin_teardown == prior.pin_teardown
                && links_at_target(current.topology, current.link_operational, true)
        }
        NetworkLifecycleEffectStepV1::DetachTcGate => {
            current.namespace == prior.namespace
                && current.links == prior.links
                && current.bpffs == prior.bpffs
                && current.pin_teardown == prior.pin_teardown
                && current.gate == prior.gate
                && current.state == prior.state
                && current.topology == prior.topology
                && current.link_operational == prior.link_operational
        }
        NetworkLifecycleEffectStepV1::RemoveBpffsPins => {
            prior.tc == NetworkLifecycleResidualPresenceV1::Absent
                && current.tc == prior.tc
                && current.namespace == prior.namespace
                && current.links == prior.links
                && current.pin_teardown == prior.pin_teardown
                && current.gate == prior.gate
                && current.state == prior.state
                && current.topology == prior.topology
                && current.link_operational == prior.link_operational
        }
        NetworkLifecycleEffectStepV1::RemoveLinks => {
            prior.tc == NetworkLifecycleResidualPresenceV1::Absent
                && prior.bpffs == NetworkLifecycleResidualPresenceV1::Absent
                && current.tc == prior.tc
                && current.bpffs == prior.bpffs
                && current.namespace == prior.namespace
                && current.pin_teardown == prior.pin_teardown
                && current.gate == prior.gate
                && current.state == prior.state
                && current.link_operational == NetworkLifecycleLinkOperationalV1::Absent
                && topology_removable_absent(current.topology)
        }
        NetworkLifecycleEffectStepV1::AuthorizeNamespacePinTeardown => {
            current.namespace == prior.namespace
                && current.links == prior.links
                && current.bpffs == prior.bpffs
                && current.tc == prior.tc
                && current.gate == prior.gate
                && current.state == prior.state
                && current.resource_digest == prior.resource_digest
                && current.catalog_digest == prior.catalog_digest
                && current.topology == prior.topology
                && current.link_operational == prior.link_operational
                && matches!(
                    prior.pin_teardown,
                    NetworkNamespacePinTeardownPhaseV1::Retained
                )
                && matches!(
                    current.pin_teardown,
                    NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(_)
                )
        }
        NetworkLifecycleEffectStepV1::RemoveNamespacePin => {
            prior.links == NetworkLifecycleResidualPresenceV1::Absent
                && prior.bpffs == NetworkLifecycleResidualPresenceV1::Absent
                && prior.tc == NetworkLifecycleResidualPresenceV1::Absent
                && matches!(
                    prior.pin_teardown,
                    NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(_)
                )
                && current.namespace == NetworkLifecycleResidualPresenceV1::Absent
                && current.links == prior.links
                && current.bpffs == prior.bpffs
                && current.tc == prior.tc
                && current.gate == NetworkLifecycleGateResidualV1::Absent
                && matches!(
                    current.pin_teardown,
                    NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(_)
                )
                && match (prior.pin_teardown, current.pin_teardown) {
                    (
                        NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(left),
                        NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(right),
                    ) => left == right,
                    _ => false,
                }
                && topology_namespace_removed(prior.topology, current.topology)
                && current.link_operational == prior.link_operational
        }
    };
    if time_advanced && identity_unchanged && (not_applied || applied && valid) {
        Ok(())
    } else {
        Err(NetworkLifecycleReducerError::ObservationMismatch)
    }
}

pub(super) fn validate_action_step_result(
    intent: NetworkLifecycleIntentV1,
    step: NetworkLifecycleEffectStepV1,
    prior: NetworkLifecycleResidualV1,
    current: NetworkLifecycleResidualV1,
) -> Result<(), NetworkLifecycleReducerError> {
    if current.action_progress == prior.action_progress {
        return Ok(());
    }
    let state_valid = match (intent.action(), step) {
        (
            NetworkNamespaceLifecycleActionV1::Arm
            | NetworkNamespaceLifecycleActionV1::Renew
            | NetworkNamespaceLifecycleActionV1::Disarm,
            NetworkLifecycleEffectStepV1::ProgramLeaseGate
            | NetworkLifecycleEffectStepV1::ProgramDefaultDrop,
        ) => current.state == intent.desired_state,
        (
            NetworkNamespaceLifecycleActionV1::Destroy,
            NetworkLifecycleEffectStepV1::ProgramDefaultDrop,
        ) => current.state.kind() == NetworkNamespaceObservedStateKindV1::DefaultDrop,
        (
            NetworkNamespaceLifecycleActionV1::Destroy,
            NetworkLifecycleEffectStepV1::RemoveNamespacePin,
        ) => current.state == intent.desired_state,
        _ => current.state == prior.state,
    };
    let gate_valid = match step {
        NetworkLifecycleEffectStepV1::ProgramLeaseGate => current.gate == armed_gate(intent),
        NetworkLifecycleEffectStepV1::ProgramDefaultDrop => {
            current.gate == NetworkLifecycleGateResidualV1::DefaultDrop
        }
        NetworkLifecycleEffectStepV1::RemoveNamespacePin => {
            current.gate == NetworkLifecycleGateResidualV1::Absent
        }
        _ => current.gate == prior.gate,
    };
    if state_valid && gate_valid {
        Ok(())
    } else {
        Err(NetworkLifecycleReducerError::ObservationMismatch)
    }
}

pub(super) fn residual_effect_changed(
    prior: NetworkLifecycleResidualV1,
    current: NetworkLifecycleResidualV1,
) -> bool {
    prior.state != current.state
        || prior.resource_digest != current.resource_digest
        || prior.catalog_digest != current.catalog_digest
        || prior.namespace != current.namespace
        || prior.links != current.links
        || prior.bpffs != current.bpffs
        || prior.tc != current.tc
        || prior.gate != current.gate
        || prior.pin_teardown != current.pin_teardown
        || prior.topology != current.topology
        || prior.link_operational != current.link_operational
        || prior.action_progress != current.action_progress
}

fn expected_progress(step: NetworkLifecycleEffectStepV1) -> NetworkLifecycleActionProgressV1 {
    use NetworkLifecycleActionProgressV1 as Progress;
    match step {
        NetworkLifecycleEffectStepV1::EnsureLinksDown
        | NetworkLifecycleEffectStepV1::LowerLinks => Progress::LinksDown,
        NetworkLifecycleEffectStepV1::ProgramLeaseGate
        | NetworkLifecycleEffectStepV1::ProgramDefaultDrop => Progress::GateProgrammed,
        NetworkLifecycleEffectStepV1::ConfigureExactAddressPairs => Progress::AddressesConfigured,
        NetworkLifecycleEffectStepV1::ConfigureExactRoutes => Progress::RoutesConfigured,
        NetworkLifecycleEffectStepV1::ConfigureExactPermanentNeighbors => {
            Progress::NeighborsConfigured
        }
        NetworkLifecycleEffectStepV1::VerifyExactPlanConfiguration => Progress::PlanVerified,
        NetworkLifecycleEffectStepV1::RaiseLinks => Progress::LinksRaised,
        NetworkLifecycleEffectStepV1::DetachTcGate => Progress::TcDetached,
        NetworkLifecycleEffectStepV1::RemoveBpffsPins => Progress::BpffsRemoved,
        NetworkLifecycleEffectStepV1::RemoveLinks => Progress::LinksRemoved,
        NetworkLifecycleEffectStepV1::AuthorizeNamespacePinTeardown => Progress::PinAuthorized,
        NetworkLifecycleEffectStepV1::RemoveNamespacePin => Progress::PinRemoved,
    }
}

fn topology_configuration_progress(
    step: NetworkLifecycleEffectStepV1,
    prior: NetworkLifecycleTopologyResidualV1,
    current: NetworkLifecycleTopologyResidualV1,
) -> bool {
    use NetworkLifecycleResidualPresenceV1 as Presence;
    match (prior, current) {
        (
            NetworkLifecycleTopologyResidualV1::Isolated { loopback: left },
            NetworkLifecycleTopologyResidualV1::Isolated { loopback: right },
        ) => left == right,
        (
            NetworkLifecycleTopologyResidualV1::Veth {
                loopback: left_loopback,
                host_peer: left_host,
                sandbox_peer: left_sandbox,
                addresses: left_addresses,
                routes: left_routes,
                neighbors: left_neighbors,
            },
            NetworkLifecycleTopologyResidualV1::Veth {
                loopback: right_loopback,
                host_peer: right_host,
                sandbox_peer: right_sandbox,
                addresses: right_addresses,
                routes: right_routes,
                neighbors: right_neighbors,
            },
        ) => {
            left_loopback == right_loopback
                && left_host == right_host
                && left_sandbox == right_sandbox
                && match step {
                    NetworkLifecycleEffectStepV1::ConfigureExactAddressPairs => {
                        right_addresses == Presence::Present
                            && left_routes == right_routes
                            && left_neighbors == right_neighbors
                    }
                    NetworkLifecycleEffectStepV1::ConfigureExactRoutes => {
                        left_addresses == right_addresses
                            && right_routes == Presence::Present
                            && left_neighbors == right_neighbors
                    }
                    NetworkLifecycleEffectStepV1::ConfigureExactPermanentNeighbors => {
                        left_addresses == right_addresses
                            && left_routes == right_routes
                            && right_neighbors == Presence::Present
                    }
                    _ => false,
                }
        }
        _ => false,
    }
}

fn links_at_target(
    topology: NetworkLifecycleTopologyResidualV1,
    operational: NetworkLifecycleLinkOperationalV1,
    raised: bool,
) -> bool {
    match topology {
        NetworkLifecycleTopologyResidualV1::Isolated { .. } => {
            operational == NetworkLifecycleLinkOperationalV1::Absent
        }
        NetworkLifecycleTopologyResidualV1::Veth { .. } => {
            operational
                == if raised {
                    NetworkLifecycleLinkOperationalV1::Up
                } else {
                    NetworkLifecycleLinkOperationalV1::Down
                }
        }
    }
}

fn topology_removable_absent(topology: NetworkLifecycleTopologyResidualV1) -> bool {
    use NetworkLifecycleResidualPresenceV1 as Presence;
    match topology {
        NetworkLifecycleTopologyResidualV1::Isolated { .. } => true,
        NetworkLifecycleTopologyResidualV1::Veth {
            loopback: _,
            host_peer,
            sandbox_peer,
            addresses,
            routes,
            neighbors,
        } => [host_peer, sandbox_peer, addresses, routes, neighbors]
            .iter()
            .all(|value| *value == Presence::Absent),
    }
}

fn topology_all_absent(topology: NetworkLifecycleTopologyResidualV1) -> bool {
    use NetworkLifecycleResidualPresenceV1 as Presence;
    match topology {
        NetworkLifecycleTopologyResidualV1::Isolated { loopback } => loopback == Presence::Absent,
        NetworkLifecycleTopologyResidualV1::Veth {
            loopback,
            host_peer,
            sandbox_peer,
            addresses,
            routes,
            neighbors,
        } => [
            loopback,
            host_peer,
            sandbox_peer,
            addresses,
            routes,
            neighbors,
        ]
        .iter()
        .all(|value| *value == Presence::Absent),
    }
}

fn topology_namespace_removed(
    prior: NetworkLifecycleTopologyResidualV1,
    current: NetworkLifecycleTopologyResidualV1,
) -> bool {
    use NetworkLifecycleResidualPresenceV1 as Presence;
    match (prior, current) {
        (
            NetworkLifecycleTopologyResidualV1::Isolated {
                loopback: Presence::Present,
            },
            NetworkLifecycleTopologyResidualV1::Isolated {
                loopback: Presence::Absent,
            },
        ) => true,
        (
            NetworkLifecycleTopologyResidualV1::Veth {
                loopback: Presence::Present,
                host_peer: Presence::Absent,
                sandbox_peer: Presence::Absent,
                addresses: Presence::Absent,
                routes: Presence::Absent,
                neighbors: Presence::Absent,
            },
            NetworkLifecycleTopologyResidualV1::Veth {
                loopback: Presence::Absent,
                host_peer: Presence::Absent,
                sandbox_peer: Presence::Absent,
                addresses: Presence::Absent,
                routes: Presence::Absent,
                neighbors: Presence::Absent,
            },
        ) => true,
        _ => false,
    }
}

pub(super) fn validate_operation(
    action: NetworkNamespaceLifecycleActionV1,
    prior: NetworkNamespaceObservedStateV1,
    desired: NetworkNamespaceObservedStateV1,
    fence: NetworkLifecycleFenceV1,
) -> Result<(), NetworkLifecycleReducerError> {
    let valid = match action {
        NetworkNamespaceLifecycleActionV1::Arm => {
            prior.kind() == NetworkNamespaceObservedStateKindV1::DefaultDrop
                && desired.kind() == NetworkNamespaceObservedStateKindV1::Armed
                && desired.lease()
                    == Some((
                        fence.ownership_lease_digest(),
                        fence.lease_generation(),
                        fence.fail_stop_boottime_nanoseconds(),
                    ))
        }
        NetworkNamespaceLifecycleActionV1::Renew => {
            prior.kind() == NetworkNamespaceObservedStateKindV1::Armed
                && desired.kind() == NetworkNamespaceObservedStateKindV1::Armed
                && prior.lease().is_some_and(|(_, generation, deadline)| {
                    generation < fence.lease_generation()
                        && deadline < fence.fail_stop_boottime_nanoseconds()
                })
                && desired.lease()
                    == Some((
                        fence.ownership_lease_digest(),
                        fence.lease_generation(),
                        fence.fail_stop_boottime_nanoseconds(),
                    ))
        }
        NetworkNamespaceLifecycleActionV1::Disarm => {
            matches!(
                prior.kind(),
                NetworkNamespaceObservedStateKindV1::Armed
                    | NetworkNamespaceObservedStateKindV1::Fenced
            ) && desired.kind() == NetworkNamespaceObservedStateKindV1::DefaultDrop
        }
        NetworkNamespaceLifecycleActionV1::Destroy => {
            matches!(
                prior.kind(),
                NetworkNamespaceObservedStateKindV1::DefaultDrop
                    | NetworkNamespaceObservedStateKindV1::Fenced
            ) && desired.kind() == NetworkNamespaceObservedStateKindV1::Absent
        }
        NetworkNamespaceLifecycleActionV1::Fence => false,
    };
    if valid {
        Ok(())
    } else {
        Err(NetworkLifecycleReducerError::InvalidTransition)
    }
}

pub(super) fn valid_link_identity(identity: NetworkLifecycleLinkIdentityV1) -> bool {
    match identity {
        NetworkLifecycleLinkIdentityV1::Isolated { loopback_ifindex } => loopback_ifindex != 0,
        NetworkLifecycleLinkIdentityV1::Veth {
            loopback_ifindex,
            host_ifindex,
            sandbox_ifindex,
            host_link_digest,
            sandbox_link_digest,
        } => {
            loopback_ifindex != 0
                && host_ifindex != 0
                && sandbox_ifindex != 0
                && loopback_ifindex != sandbox_ifindex
                && host_link_digest.as_bytes() != &[0; 32]
                && sandbox_link_digest.as_bytes() != &[0; 32]
                && host_link_digest != sandbox_link_digest
        }
    }
}

pub(super) fn valid_tc_identity(
    links: NetworkLifecycleLinkIdentityV1,
    identity: NetworkLifecycleTcIdentityV1,
) -> bool {
    match (links, identity) {
        (NetworkLifecycleLinkIdentityV1::Isolated { .. }, NetworkLifecycleTcIdentityV1::Absent) => {
            true
        }
        (
            NetworkLifecycleLinkIdentityV1::Veth { .. },
            NetworkLifecycleTcIdentityV1::LeaseGate {
                bpffs_device,
                bpffs_inode,
                host_ingress_program_id,
                host_egress_program_id,
                lease_map_id,
                artifact_digest,
                loader_binding_digest,
            },
        ) => {
            bpffs_device != 0
                && bpffs_inode != 0
                && host_ingress_program_id != 0
                && host_egress_program_id != 0
                && lease_map_id != 0
                && artifact_digest.as_bytes() != &[0; 32]
                && loader_binding_digest.as_bytes() != &[0; 32]
        }
        _ => false,
    }
}
