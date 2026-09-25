//! Audited choice-free prefix for the five-node Envoy guest fixture.
//!
//! The authenticated fixture token and topology permit concurrent QEMU RUNs
//! only until west's convergence marker reaches the scheduler event log. Any
//! choice during that prefix aborts the unpublished attempt continuation.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use crucible::{
    Decision, NetworkFaultSelectable, NodeTemplate, ObservableEventPayload, QuantumOutcome,
    ReadyPoint, SchedulerEventLogEntry, SchedulerEventLogPayload, Seed, VmArchitecture,
    WhiteBoxPolicy,
};

use super::{QemuFreshModeledDriverError, QemuModeledAttemptLifecycle};
use crate::{AttemptWorkerFailure, CrucibleAttemptExecution};

const ENVOY_FIXTURE_SEED: u64 = 802_750_664_550_812_378;

/// Reports whether an attempt carries the audited five-node boot capability.
pub(super) fn envoy_choice_free_boot_eligible(input: &CrucibleAttemptExecution) -> bool {
    // The fixture-authored cmdline token opts this exact boot graph into the
    // choice-free prefix proven by west convergence and positive link latency.
    if !input.attempt().stop().accepts_next_choice()
        || !input.signal_fault_replay().network_branches().is_empty()
        || input.scenario().seed() != Seed::from_u64(ENVOY_FIXTURE_SEED)
    {
        return false;
    }

    let world = input.scenario().world();
    let roles = world
        .vm_nodes()
        .iter()
        .filter(|node| {
            node.cmdline
                == format!(
                    "root=/dev/vda rw init=/init console=ttyS0 network.role={} network.fixture=worked-recovery crucible.choice-free-boot=envoy-network-v2",
                    node.id.name
                )
                && node.icount_shift == 0
                && node.arch == VmArchitecture::X86_64
                && node.memory_mib == 512
                && node.ready_point == ReadyPoint::AgentSignal
                && node.white_box == WhiteBoxPolicy::Enabled
                && node.smp_vcpus == NodeTemplate::DEFAULT_SMP_VCPUS
                && node.kernel.is_some()
                && node.root_image.is_some()
                && node.initrd.is_none()
        })
        .map(|node| node.id.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "router-a",
        "router-b",
        "router-c",
        "traffic-east",
        "traffic-west",
    ]);
    let declaration = NetworkFaultSelectable::declaration().ok();
    let expected_links = BTreeSet::from([
        ("router-a", "traffic-west"),
        ("router-a", "router-b"),
        ("router-b", "router-c"),
        ("router-a", "router-c"),
        ("router-c", "traffic-east"),
    ]);
    let actual_links = world
        .links()
        .iter()
        .filter(|link| {
            link.latency().nanos == 10_000_000
                && link.jitter().nanos == 100_000
                && link.loss().millionths() == 0
                && link.bandwidth_bps() == Some(10_000_000_000)
        })
        .map(|link| {
            let (left, right) = link.endpoints();
            (left.name.as_str(), right.name.as_str())
        })
        .collect::<BTreeSet<_>>();
    let topology = world.fault_topology();

    roles == expected
        && world.nodes().len() == expected.len()
        && world.links().len() == expected_links.len()
        && actual_links == expected_links
        && topology.fault_domains.len() == 2
        && topology.network_interfaces.len() == 10
        && topology.network_segments.len() == 5
        && topology.network_paths.len() == 10
        && input.scenario().selectables().declaration("fault.network") == declaration.as_ref()
        && input
            .scenario()
            .selectables()
            .declaration("recovery.response")
            .is_some()
}

/// Finds west's authenticated convergence marker in scheduler-owned evidence.
pub(super) fn west_convergence_marker_seen(entries: &[SchedulerEventLogEntry]) -> bool {
    entries.iter().any(|entry| {
        matches!(
            entry.payload(),
            SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestSemanticMarker {
                node,
                marker,
                instance,
                details,
                ..
            }) if node.name == "traffic-west"
                && marker == "network.converged"
                && instance == "instance-1"
                && details.is_empty()
        )
    })
}

/// Owns the audited concurrent prefix before west reports route convergence.
pub(super) struct EnvoyParallelBoot {
    active: bool,
    next_progress_quanta: u64,
    observable_events: u64,
    nodes: BTreeMap<String, NodeBootProgress>,
}

struct NodeBootProgress {
    stage: &'static str,
    stage_order: u8,
    stage_icount: u64,
    console_bytes: usize,
}

impl NodeBootProgress {
    fn new() -> Self {
        Self {
            stage: "none",
            stage_order: 0,
            stage_icount: 0,
            console_bytes: 0,
        }
    }
}

fn boot_stage(marker: &str) -> Option<(u8, &'static str)> {
    match marker {
        "boot.init-mounted" => Some((1, "init-mounted")),
        "boot.network-configured" => Some((2, "network-configured")),
        "boot.service-starting" => Some((3, "service-starting")),
        "lifecycle.setup_complete" => Some((4, "setup-complete")),
        "boot.route-probing" => Some((5, "route-probing")),
        "boot.local-healthy" => Some((6, "local-healthy")),
        "boot.route-ready" => Some((6, "route-ready")),
        _ => None,
    }
}

impl EnvoyParallelBoot {
    /// Arms parallel RUNs only for a fresh, not-yet-converged Envoy attempt.
    pub(super) fn arm(
        input: &CrucibleAttemptExecution,
        fresh_start: bool,
        entries: &[SchedulerEventLogEntry],
        lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    ) -> Self {
        let eligible = fresh_start && envoy_choice_free_boot_eligible(input);
        let active = eligible && !west_convergence_marker_seen(entries);
        lifecycle.set_choice_free_parallel_boot(active);
        if fresh_start && input.scenario().seed() == Seed::from_u64(ENVOY_FIXTURE_SEED) {
            let _ = writeln!(
                std::io::stderr().lock(),
                "CRUCIBLE-ENVOY-BOOT-PROGRESS-V1 armed={active} eligible={eligible}"
            );
        }
        Self {
            active,
            next_progress_quanta: 1,
            observable_events: 0,
            nodes: [
                "router-a",
                "router-b",
                "router-c",
                "traffic-east",
                "traffic-west",
            ]
            .into_iter()
            .map(|node| (String::from(node), NodeBootProgress::new()))
            .collect(),
        }
    }

    /// Reports bounded scheduler progress while the first Envoy choice is pending.
    pub(super) fn report_progress(&mut self, completed_quanta: u64, outcome: &QuantumOutcome) {
        if !self.active {
            return;
        }

        for entry in &outcome.event_log_entries {
            let SchedulerEventLogPayload::Observable(observable) = entry.payload() else {
                continue;
            };
            self.observable_events = self.observable_events.saturating_add(1);

            match observable {
                // The QEMU observation binds each guest stage to its node and retired icount.
                ObservableEventPayload::GuestMarker {
                    retired_icount,
                    node,
                    marker,
                } => {
                    let Some((stage_order, stage)) = boot_stage(&marker.name) else {
                        continue;
                    };
                    let Some(progress) = self.nodes.get_mut(&node.name) else {
                        continue;
                    };
                    if stage_order > progress.stage_order {
                        progress.stage = stage;
                        progress.stage_order = stage_order;
                        progress.stage_icount = retired_icount.retired;
                    }
                }
                ObservableEventPayload::ConsoleOutput { node, bytes } => {
                    if let Some(progress) = self.nodes.get_mut(&node.name) {
                        progress.console_bytes = progress.console_bytes.saturating_add(bytes.len());
                    }
                }
                _ => {}
            }
        }
        let converged = west_convergence_marker_seen(&outcome.event_log_entries);
        if completed_quanta < self.next_progress_quanta && !converged {
            return;
        }

        let nodes = self
            .nodes
            .iter()
            .map(|(name, progress)| {
                format!(
                    "{name}={stage}@{icount}/console:{console_bytes}",
                    stage = progress.stage,
                    icount = progress.stage_icount,
                    console_bytes = progress.console_bytes,
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(
            std::io::stderr().lock(),
            "CRUCIBLE-ENVOY-BOOT-PROGRESS-V1 quanta={} frontier_ns={} observable_events={} converged={converged} nodes={nodes}",
            completed_quanta,
            outcome.frontier.ticks,
            self.observable_events,
        );
        self.next_progress_quanta = if self.next_progress_quanta == 1 {
            1_024
        } else {
            self.next_progress_quanta.saturating_mul(4)
        };
    }

    /// Stops parallel RUNs after the west marker and refuses an earlier choice.
    ///
    /// # Errors
    ///
    /// Returns a terminal boundary error if a choice appears in the boot prefix.
    pub(super) fn observe(
        &mut self,
        lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
        outcome: &QuantumOutcome,
    ) -> Result<bool, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
        let was_active = self.active;
        if was_active
            && (!outcome.discovered_choices.is_empty()
                || outcome.decisions.iter().any(|decision| {
                    matches!(decision, Decision::Selection(_) | Decision::Override(_))
                }))
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::NetworkFaultBoundary {
                    reason: "choice-free Envoy boot discovered a selection before its readiness marker",
                },
            ));
        }
        if self.active && west_convergence_marker_seen(&outcome.event_log_entries) {
            self.active = false;
            lifecycle.set_choice_free_parallel_boot(false);
        }
        Ok(was_active)
    }

    /// Refuses a synthetic network choice found inside the parallel prefix.
    ///
    /// # Errors
    ///
    /// Returns a terminal boundary error when discovery preceded the marker.
    pub(super) fn require_serial_network_boundary(
        was_active: bool,
    ) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
        if was_active {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::NetworkFaultBoundary {
                    reason: "network fault choice preceded the serial Envoy readiness boundary",
                },
            ));
        }
        Ok(())
    }
}
