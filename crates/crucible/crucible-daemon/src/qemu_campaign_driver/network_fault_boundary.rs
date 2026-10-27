//! Host-verified all-VM boundary for one atomic network fault choice.

use super::*;
use crucible_engine::{NetworkFaultSelectable, SchedulerQuiescenceBlocker};

/// Adds a network choice already proven at the initial scheduler boundary.
///
/// # Errors
///
/// Returns an attempt failure if discovery or bounded retention fails.
pub(super) fn discover_initial_network_fault_choice(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    configuration: &Configuration,
    markers: &NetworkFaultMarkerIndex,
    frontier: VirtualTime,
    quiescence: Option<&SchedulerQuiescence>,
    discoveries: &mut RetainedChoiceDiscoveries,
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    if input.attempt().stop().accepts_next_choice()
        && let Some(discovery) = next_network_fault_discovery(
            lifecycle,
            input,
            configuration,
            markers,
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
    retained: &NetworkFaultMarkerIndex,
    outcome: &mut QuantumOutcome,
    was_parallel_boot: bool,
    discoveries: &RetainedChoiceDiscoveries,
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    // The index is bounded by phases and VMs, so this per-quantum view costs
    // the new entries only, independent of the attempt's length.
    let mut markers = retained.clone();
    markers.observe_all(&outcome.event_log_entries);
    if let Some(discovery) = next_network_fault_discovery(
        lifecycle,
        input,
        &outcome.configuration,
        &markers,
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
    if !declares_network_fault(input) {
        return Ok(false);
    }
    let parks = lifecycle
        .park_held_campaign_markers(&NETWORK_FAULT_PHASE_MARKERS, outcome)
        .map_err(classify_scheduler_error)?;
    Ok(parks != 0)
}

/// Guest markers at which each VM parks before a network fault phase.
pub(crate) const NETWORK_FAULT_PHASE_MARKERS: [&str; 2] = [
    phase_marker(NetworkFaultPhase::First),
    phase_marker(NetworkFaultPhase::Followup),
];

/// Returns whether the attempt's scenario declares the network fault choice.
///
/// Without the declaration, a same-named guest marker is inert.
pub(crate) fn declares_network_fault(input: &CrucibleAttemptExecution) -> bool {
    input
        .scenario()
        .selectables()
        .declaration("fault.network")
        .is_some()
}

/// Returns the guest marker at which every VM parks before `phase`.
pub(crate) const fn phase_marker(phase: NetworkFaultPhase) -> &'static str {
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
    markers: &NetworkFaultMarkerIndex,
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
    let Some(phase) = markers.latest_phase() else {
        return Ok(None);
    };
    let expected_nodes = input
        .scenario()
        .world()
        .vm_nodes()
        .iter()
        .map(|vm| vm.id.clone())
        .collect::<BTreeSet<_>>();
    let phase_markers = markers.phase(phase);
    let mut markers_by_node = BTreeMap::new();
    for entry in phase_markers.entries() {
        let SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            ..
        }) = entry.payload()
        else {
            continue;
        };
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
        markers_by_node.insert(
            node.clone(),
            (*retired_icount, entry.at(), entry.sequence()),
        );
    }
    if phase_markers.repeated() {
        return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "a VM emitted the same phase marker more than once",
        });
    }
    let markers_by_node = markers_by_node;
    if markers_by_node.len() != expected_nodes.len() {
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
            markers_by_node
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

    let marker_sequence = markers_by_node
        .values()
        .map(|(_, _, sequence)| *sequence)
        .max()
        .ok_or(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "network phase has no final marker sequence",
        })?;
    let last_marker_at = markers_by_node.values().map(|(_, at, _)| *at).max().ok_or(
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
        markers.last_activity_sequence(),
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
    last_activity_sequence: Option<u64>,
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
    // Frames already inside World links are checkpointed fabric state: a
    // parked VM consumes none, and the park join retimes any it missed to its
    // resume instant. Every other blocker is unsettled work.
    let unsettled = quiescence
        .blockers
        .iter()
        .filter(|blocker| {
            !matches!(
                blocker,
                SchedulerQuiescenceBlocker::NetworkFrameInFlight { .. }
            )
        })
        .collect::<Vec<_>>();
    if !unsettled.is_empty() {
        return Err(not_quiescent_boundary(&unsettled));
    }
    if pending_network_outputs != 0 {
        return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "the virtual fabric retains pending output",
        });
    }
    if last_activity_sequence.is_some_and(|sequence| sequence > marker_sequence) {
        return Err(QemuFreshModeledDriverError::NetworkFaultBoundary {
            reason: "an observable or resolved operation followed the final phase marker",
        });
    }
    Ok(())
}

/// Names the leading blockers so a failed physical boundary stays diagnosable.
fn not_quiescent_boundary(
    unsettled: &[&SchedulerQuiescenceBlocker],
) -> QemuFreshModeledDriverError {
    const SUMMARY_BLOCKERS: usize = 8;

    let mut summary = unsettled
        .iter()
        .take(SUMMARY_BLOCKERS)
        .map(|blocker| format!("{blocker:?}"))
        .collect::<Vec<_>>()
        .join("; ");
    if unsettled.len() > SUMMARY_BLOCKERS {
        summary.push_str("; ...");
    }
    QemuFreshModeledDriverError::NetworkFaultBoundaryNotQuiescent {
        count: unsettled.len(),
        summary,
    }
}

/// Network-fault phase markers and guest activity folded over an event log.
///
/// Discovery needs the latest phase marker, every VM's marker for that phase,
/// and whether any observable or resolved work followed it. Retaining just
/// those keeps the per-quantum check proportional to the quantum's new
/// entries. The state is bounded by the two phases and the distinct VMs that
/// emitted their markers.
#[derive(Clone, Debug, Default)]
pub(crate) struct NetworkFaultMarkerIndex {
    latest_phase: Option<(u64, NetworkFaultPhase)>,
    first: PhaseMarkers,
    followup: PhaseMarkers,
    last_activity_sequence: Option<u64>,
}

/// Each VM's first marker for one phase, plus whether any VM repeated it.
#[derive(Clone, Debug, Default)]
pub(crate) struct PhaseMarkers {
    by_node: BTreeMap<NodeId, SchedulerEventLogEntry>,
    repeated: bool,
}

impl PhaseMarkers {
    /// Returns the retained markers in log order.
    pub(crate) fn entries(&self) -> Vec<&SchedulerEventLogEntry> {
        let mut entries = self.by_node.values().collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.sequence());
        entries
    }

    /// Returns whether some VM emitted this phase's marker more than once.
    pub(crate) const fn repeated(&self) -> bool {
        self.repeated
    }
}

impl NetworkFaultMarkerIndex {
    /// Folds every entry of `entries`, in order.
    #[cfg(test)]
    pub(crate) fn from_entries<'a>(
        entries: impl IntoIterator<Item = &'a SchedulerEventLogEntry>,
    ) -> Self {
        let mut index = Self::default();
        index.observe_all(entries);
        index
    }

    /// Folds each entry of `entries`, in order.
    pub(crate) fn observe_all<'a>(
        &mut self,
        entries: impl IntoIterator<Item = &'a SchedulerEventLogEntry>,
    ) {
        for entry in entries {
            self.observe(entry);
        }
    }

    /// Folds one appended entry.
    pub(crate) fn observe(&mut self, entry: &SchedulerEventLogEntry) {
        let payload = entry.payload();
        if matches!(
            payload,
            SchedulerEventLogPayload::Observable(_)
                | SchedulerEventLogPayload::ResolvedHappening(_)
                | SchedulerEventLogPayload::FaultObservation(_)
        ) {
            self.last_activity_sequence = self.last_activity_sequence.max(Some(entry.sequence()));
        }

        let SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
            node,
            marker,
            ..
        }) = payload
        else {
            return;
        };
        let Some(phase) = marker_phase(&marker.name) else {
            return;
        };
        if self
            .latest_phase
            .is_none_or(|(sequence, _)| entry.sequence() > sequence)
        {
            self.latest_phase = Some((entry.sequence(), phase));
        }
        let markers = match phase {
            NetworkFaultPhase::First => &mut self.first,
            NetworkFaultPhase::Followup => &mut self.followup,
        };
        if markers.by_node.contains_key(node) {
            markers.repeated = true;
        } else {
            markers.by_node.insert(node.clone(), entry.clone());
        }
    }

    /// Returns the phase of the latest phase marker.
    pub(crate) fn latest_phase(&self) -> Option<NetworkFaultPhase> {
        self.latest_phase.map(|(_, phase)| phase)
    }

    /// Returns the markers retained for `phase`.
    pub(crate) const fn phase(&self, phase: NetworkFaultPhase) -> &PhaseMarkers {
        match phase {
            NetworkFaultPhase::First => &self.first,
            NetworkFaultPhase::Followup => &self.followup,
        }
    }

    /// Returns the latest observable, resolved, or fault entry's sequence.
    pub(crate) const fn last_activity_sequence(&self) -> Option<u64> {
        self.last_activity_sequence
    }
}
