//! Host-verified all-VM boundary for one atomic network fault choice.

use super::*;
use crucible::NetworkFaultSelectable;

/// Adds a network choice already proven at the initial scheduler boundary.
///
/// # Errors
///
/// Returns an attempt failure if discovery or bounded retention fails.
pub(super) fn discover_initial_network_fault_choice(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    configuration: &Configuration,
    entries: &[SchedulerEventLogEntry],
    frontier: VirtualTime,
    quiescence: Option<&SchedulerQuiescence>,
    discoveries: &mut RetainedChoiceDiscoveries,
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    if input.attempt().stop().accepts_next_choice()
        && let Some(discovery) = next_network_fault_discovery(
            lifecycle,
            input,
            configuration,
            entries,
            &[],
            frontier,
            quiescence,
        )
        .map_err(AttemptWorkerFailure::Terminal)?
    {
        discoveries
            .insert(discovery)
            .map_err(AttemptWorkerFailure::Terminal)?;
    }
    Ok(())
}

/// Adds a new quantum's network discovery once, preserving retained order.
///
/// # Errors
///
/// Returns an attempt failure if the opportunity identity cannot be addressed.
pub(super) fn append_new_network_fault_discovery(
    discovery: ChoiceDiscovery,
    retained: &RetainedChoiceDiscoveries,
    outcome: &mut QuantumOutcome,
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    let opportunity_id = discovery.opportunity().id().map_err(|error| {
        AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::Campaign(error))
    })?;
    if !retained.discoveries.contains_key(&opportunity_id)
        && !outcome.discovered_choices.iter().any(|existing| {
            existing
                .opportunity()
                .id()
                .is_ok_and(|existing_id| existing_id == opportunity_id)
        })
    {
        outcome.discovered_choices.push(discovery);
    }
    Ok(())
}

/// Admits a post-quantum network choice only after the serial boot boundary.
///
/// # Errors
///
/// Returns an attempt failure if the all-VM proof, boot boundary, or choice
/// identity is invalid.
pub(super) fn discover_quantum_network_fault_choice(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    retained_entries: &[SchedulerEventLogEntry],
    outcome: &mut QuantumOutcome,
    was_parallel_boot: bool,
    discoveries: &RetainedChoiceDiscoveries,
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    if let Some(discovery) = next_network_fault_discovery(
        lifecycle,
        input,
        &outcome.configuration,
        retained_entries,
        &outcome.event_log_entries,
        outcome.frontier,
        outcome.scheduler_quiescence.as_ref(),
    )
    .map_err(AttemptWorkerFailure::Terminal)?
    {
        EnvoyParallelBoot::require_serial_network_boundary(was_parallel_boot)?;
        append_new_network_fault_discovery(discovery, discoveries, outcome)?;
    }
    Ok(())
}

/// Parks staggered network-phase marker holds so later VMs reach theirs.
///
/// Each VM stops at its phase marker at a different time, while the atomic
/// choice needs every VM parked. Without parking, the first held marker would
/// block every RUN the remaining VMs need. Returns whether any VM parked.
///
/// # Errors
///
/// Returns an attempt failure when a held marker cannot park or its peer
/// outcomes cannot be published.
pub(super) fn park_network_fault_markers(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    outcome: &mut QuantumOutcome,
) -> Result<bool, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    if input
        .scenario()
        .selectables()
        .declaration("fault.network")
        .is_none()
    {
        return Ok(false);
    }
    let markers = [
        phase_marker(NetworkFaultPhase::First),
        phase_marker(NetworkFaultPhase::Followup),
    ];
    let parks = lifecycle
        .park_held_campaign_markers(&markers, outcome)
        .map_err(classify_scheduler_error)?;
    Ok(parks != 0)
}

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

pub(super) fn validate_phase_marker_coordinate(
    phase: NetworkFaultPhase,
    entry: &SchedulerEventLogEntry,
    node: &NodeId,
    expected_nodes: &BTreeSet<NodeId>,
    frontier: VirtualTime,
) -> Result<(), QemuFreshModeledDriverError> {
    if !expected_nodes.contains(node) {
        return Err(QemuFreshModeledDriverError::NetworkFaultMarkerUnknownVm {
            phase: phase_marker(phase),
            sequence: entry.sequence(),
            node: node.name.clone(),
        });
    }
    if entry.at() > frontier {
        return Err(QemuFreshModeledDriverError::NetworkFaultMarkerFuture {
            phase: phase_marker(phase),
            sequence: entry.sequence(),
            node: node.name.clone(),
            marker_tick: entry.at().ticks,
            frontier_tick: frontier.ticks,
        });
    }
    Ok(())
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
        .map_err(|error| QemuFreshModeledDriverError::NetworkFault(Box::new(error)))?;
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
        // A VM parked at this marker no longer bounds the frontier, so its
        // committed marker may lie ahead of it until the all-VM park join.
        let parked_here = expected_nodes.contains(node)
            && lifecycle
                .parked_campaign_marker(node)
                .map_err(QemuFreshModeledDriverError::Scheduler)?
                .is_some_and(|proof| proof.marker == phase_marker(phase));
        let coordinate_bound = if parked_here {
            frontier.max(entry.at())
        } else {
            frontier
        };
        validate_phase_marker_coordinate(phase, entry, node, &expected_nodes, coordinate_bound)?;
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
        // The event log carries the marker's logical tick; the park pairs it
        // with the raw count recovered at the physical VMStop.
        if parked.marker != phase_marker(phase)
            || parked.marker_tick != *retired
            || parked.marker_icount.retired.checked_add(1)
                != Some(parked.physical_raw_icount.retired)
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

    // Every VM is physically parked at this phase. Join their scheduler parks
    // to one frontier before validating it and capturing the checkpoint.
    let frontier = lifecycle
        .join_campaign_parks_to_frontier()
        .map_err(QemuFreshModeledDriverError::Scheduler)?
        .map_or(frontier, |joined| joined.max(frontier));

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
        .map_err(|error| QemuFreshModeledDriverError::NetworkFault(Box::new(error)))?
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
    let Some(quiescence) = quiescence else {
        return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "scheduler quiescence evidence is unavailable",
        });
    };
    if !quiescence.is_quiescent() {
        return Err(not_quiescent_boundary(quiescence));
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

/// Names the leading blockers so a failed physical boundary stays diagnosable.
fn not_quiescent_boundary(quiescence: &SchedulerQuiescence) -> QemuFreshModeledDriverError {
    const SUMMARY_BLOCKERS: usize = 8;

    let mut summary = quiescence
        .blockers
        .iter()
        .take(SUMMARY_BLOCKERS)
        .map(|blocker| format!("{blocker:?}"))
        .collect::<Vec<_>>()
        .join("; ");
    if quiescence.blockers.len() > SUMMARY_BLOCKERS {
        summary.push_str("; ...");
    }
    QemuFreshModeledDriverError::NetworkFaultBoundaryNotQuiescent {
        count: quiescence.blockers.len(),
        summary,
    }
}
