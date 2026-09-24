//! Host-verified all-VM boundary for one atomic network fault choice.

use super::*;

fn phase_marker(phase: NetworkFaultPhase) -> &'static str {
    match phase {
        NetworkFaultPhase::First => "fault.transport.ready",
        NetworkFaultPhase::Followup => "fault.followup.ready",
    }
}

fn marker_phase(marker: &str) -> Option<NetworkFaultPhase> {
    match marker {
        "fault.transport.ready" => Some(NetworkFaultPhase::First),
        "fault.followup.ready" => Some(NetworkFaultPhase::Followup),
        _ => None,
    }
}

pub(super) fn next_network_fault_discovery(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    parent: &Configuration,
    retained: &[SchedulerEventLogEntry],
    new_entries: &[SchedulerEventLogEntry],
    frontier: VirtualTime,
    quiescence: Option<&SchedulerQuiescence>,
) -> Result<Option<ChoiceDiscovery>, QemuFreshModeledDriverError> {
    if input
        .scenario()
        .selectables()
        .declaration("fault.network")
        .is_none()
    {
        // The marker name is inert in scenarios that did not opt into this
        // environment adapter. The producer still rejects scalar stand-ins.
        NetworkFaultSelectable::next(
            input.scenario(),
            parent,
            NetworkFaultPhase::First,
            frontier,
            &[],
        )
        .map_err(QemuFreshModeledDriverError::NetworkFault)?;
        return Ok(None);
    }
    let entries = retained.iter().chain(new_entries);
    let Some(phase) = entries
        .clone()
        .filter_map(|entry| {
            let SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
                marker,
                ..
            }) = entry.payload()
            else {
                return None;
            };
            marker_phase(&marker.name).map(|phase| (entry.sequence(), phase))
        })
        .max_by_key(|(sequence, _)| *sequence)
        .map(|(_, phase)| phase)
    else {
        return Ok(None);
    };
    let expected_nodes = input
        .scenario()
        .world()
        .vm_nodes()
        .iter()
        .map(|vm| vm.id.clone())
        .collect::<BTreeSet<_>>();
    let mut markers = BTreeMap::new();
    for entry in entries {
        let SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            marker,
        }) = entry.payload()
        else {
            continue;
        };
        if marker_phase(&marker.name) != Some(phase) {
            continue;
        }
        if !expected_nodes.contains(node) || entry.at() > frontier {
            return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
                reason: "phase marker names an unknown VM or a future frontier",
            });
        }
        if markers
            .insert(
                node.clone(),
                (*retired_icount, entry.at(), entry.sequence()),
            )
            .is_some()
        {
            return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
                reason: "a VM emitted the same phase marker more than once",
            });
        }
    }
    if markers.len() != expected_nodes.len() {
        // Scheduler quiescence can occur between staggered guest markers.
        // A missing event is terminal only when every VM has already parked
        // for this phase and no further marker can arrive.
        let mut every_vm_parked = true;
        for node in &expected_nodes {
            let parked = lifecycle
                .parked_campaign_marker(node)
                .map_err(QemuFreshModeledDriverError::Scheduler)?;
            every_vm_parked &= parked
                .as_ref()
                .is_some_and(|proof| proof.marker == phase_marker(phase));
        }
        if every_vm_parked {
            return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
                reason: "parked network phase omitted one or more authenticated VM markers",
            });
        }
        return Ok(None);
    }

    let branches = input.signal_fault_replay().network_branches();
    let selected_phase = branches.iter().find(|branch| branch.phase() == phase);
    let mut parked_count = 0;
    for node in &expected_nodes {
        let parked = lifecycle
            .parked_campaign_marker(node)
            .map_err(QemuFreshModeledDriverError::Scheduler)?;
        let Some(parked) = parked else {
            continue;
        };
        let (retired, _, _) =
            markers
                .get(node)
                .ok_or(QemuFreshModeledDriverError::NetworkFaultBoundary {
                    reason: "parked VM has no authenticated phase marker",
                })?;
        if parked.marker != phase_marker(phase)
            || parked.marker_icount != *retired
            || retired.retired.checked_add(1) != Some(parked.physical_icount.retired)
        {
            return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
                reason: "physical VMStop differs from the authenticated phase marker",
            });
        }
        parked_count += 1;
    }
    if let Some(selected) = selected_phase.filter(|_| parked_count == 0) {
        // An empty park set is safe only when every exact release was committed
        // into the authenticated network checkpoint for this selected branch.
        for node in &expected_nodes {
            if !lifecycle
                .campaign_marker_release_committed(
                    node,
                    phase_marker(phase),
                    selected.selected().id(),
                )
                .map_err(QemuFreshModeledDriverError::Scheduler)?
            {
                return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
                    reason: "selected network phase lost a marker park without release proof",
                });
            }
        }
        return Ok(None);
    }
    if parked_count != expected_nodes.len() {
        if quiescence.is_some_and(SchedulerQuiescence::is_quiescent) {
            return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
                reason: "quiescent network phase has an unparked VM",
            });
        }
        return Ok(None);
    }

    let marker_sequence = markers
        .values()
        .map(|(_, _, sequence)| *sequence)
        .max()
        .ok_or(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "network phase has no final marker sequence",
        })?;
    let last_marker_at = markers.values().map(|(_, at, _)| *at).max().ok_or(
        QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "network phase has no final marker time",
        },
    )?;
    validate_network_fault_boundary(
        marker_sequence,
        last_marker_at,
        frontier,
        quiescence,
        lifecycle.pending_network_output_count(),
        retained,
        new_entries,
    )?;
    if !lifecycle
        .exact_checkpoint_ready()
        .map_err(QemuFreshModeledDriverError::Scheduler)?
        || !lifecycle
            .campaign_network_queues_empty()
            .map_err(QemuFreshModeledDriverError::Scheduler)?
    {
        return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "device I/O, selectable catalogs, or network queues are not checkpoint ready",
        });
    }

    if let Some(selected) = selected_phase {
        if selected.at() != frontier {
            return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
                reason: "selected network phase differs from the parked frontier",
            });
        }
        for node in &expected_nodes {
            lifecycle
                .release_parked_campaign_marker(node, phase_marker(phase), selected.selected().id())
                .map_err(QemuFreshModeledDriverError::Scheduler)?;
        }
        return Ok(None);
    }

    NetworkFaultSelectable::next(input.scenario(), parent, phase, frontier, branches)
        .map_err(QemuFreshModeledDriverError::NetworkFault)?
        .map(|selectable| {
            selectable
                .discovery()
                .map_err(QemuFreshModeledDriverError::Campaign)
        })
        .transpose()
}

pub(super) fn validate_network_fault_boundary(
    marker_sequence: u64,
    marker_at: VirtualTime,
    frontier: VirtualTime,
    quiescence: Option<&SchedulerQuiescence>,
    pending_network_outputs: usize,
    retained: &[SchedulerEventLogEntry],
    new_entries: &[SchedulerEventLogEntry],
) -> Result<(), QemuFreshModeledDriverError> {
    if marker_at > frontier {
        return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "phase marker lies beyond the scheduler frontier",
        });
    }
    if !quiescence.is_some_and(SchedulerQuiescence::is_quiescent) {
        return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "scheduler-owned world state is not quiescent",
        });
    }
    if pending_network_outputs != 0 {
        return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "the virtual fabric retains pending output",
        });
    }
    if retained.iter().chain(new_entries).any(|entry| {
        entry.sequence() > marker_sequence
            && matches!(
                entry.payload(),
                SchedulerEventLogPayload::Observable(_)
                    | SchedulerEventLogPayload::ResolvedHappening(_)
                    | SchedulerEventLogPayload::FaultObservation(_)
            )
    }) {
        return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "an observable or resolved operation followed the final phase marker",
        });
    }
    Ok(())
}
