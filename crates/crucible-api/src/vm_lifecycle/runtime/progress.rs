//! Opt-in, bounded diagnostics around production scheduler operations.
//!
//! Host time controls only stderr sampling. These notices never select a
//! deadline, mutate a queue, or replace the operation's actual result.

use std::collections::BTreeMap;
use std::io::Write;
// crucible-lint: allow host-nondeterminism-state -- host time limits diagnostic output only; scheduler state and results remain authoritative.
use std::time::{Duration, Instant};

use super::super::ProductionVmLifecycleLoop;
use crucible::{ObservableEventPayload, QuantumOutcome, SchedulerEventLogPayload, WorldVmNodes};

const REPORT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_REPORTS: u16 = 1024;
const MAX_REPORTED_NODES: usize = 32;
const CONSOLE_TAIL_BYTES: usize = 160;

/// Retains observed guest evidence without treating console text as readiness.
#[derive(Debug, Default)]
struct GuestBootProgress {
    stage: Option<&'static str>,
    // Coordinate carried by the decoded event, not an independent raw count.
    stage_icount: u64,
    setup_receipts: u64,
    console_bytes: usize,
    console_tail: Vec<u8>,
}

impl GuestBootProgress {
    fn observe(&mut self, event: &ObservableEventPayload) -> bool {
        match event {
            ObservableEventPayload::GuestMarker {
                retired_icount,
                marker,
                ..
            } => {
                let stage = match marker.name.as_str() {
                    "boot.init-mounted" => "init-mounted",
                    "boot.network-configured" => "network-configured",
                    "boot.service-starting" => "service-starting",
                    "lifecycle.setup_complete" => {
                        self.setup_receipts = self.setup_receipts.saturating_add(1);
                        "setup-complete"
                    }
                    _ => return false,
                };
                self.stage = Some(stage);
                self.stage_icount = retired_icount.retired;
                return true;
            }
            ObservableEventPayload::ConsoleOutput { bytes, .. } => {
                self.console_bytes = self.console_bytes.saturating_add(bytes.len());
                let retained = bytes.len().min(CONSOLE_TAIL_BYTES);
                let keep_prior = CONSOLE_TAIL_BYTES.saturating_sub(retained);
                let remove_prior = self.console_tail.len().saturating_sub(keep_prior);
                self.console_tail.drain(..remove_prior);
                self.console_tail
                    .extend_from_slice(&bytes[bytes.len() - retained..]);
            }
            _ => {}
        }
        false
    }
}

/// Reads host time solely to limit stderr notices, never scheduler decisions.
#[allow(clippy::disallowed_methods)]
fn diagnostic_clock() -> Instant {
    Instant::now()
}

/// Process-local sampling state excluded from every checkpoint and wire format.
#[derive(Debug, Default)]
pub(in crate::vm_lifecycle) struct RuntimeProgress {
    enabled: bool,
    remaining: u16,
    next_report: Option<Instant>,
    guest_boot: BTreeMap<String, GuestBootProgress>,
}

impl RuntimeProgress {
    pub(in crate::vm_lifecycle) fn from_environment() -> Self {
        let maximum = std::env::var("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or_default()
            .min(MAX_REPORTS);
        Self {
            enabled: maximum != 0,
            remaining: maximum,
            ..Self::default()
        }
    }

    pub(in crate::vm_lifecycle) fn observe(
        &mut self,
        outcome: &QuantumOutcome,
        nodes: WorldVmNodes<'_>,
    ) -> bool {
        // The disabled path retains no payload and performs no clock read.
        if !self.enabled {
            return false;
        }
        let mut stage_observed = false;
        for entry in &outcome.event_log_entries {
            let SchedulerEventLogPayload::Observable(event) = entry.payload() else {
                continue;
            };
            let node = match event {
                ObservableEventPayload::ConsoleOutput { node, .. }
                | ObservableEventPayload::GuestMarker { node, .. } => node,
                _ => continue,
            };
            if nodes
                .iter()
                .take(MAX_REPORTED_NODES)
                .any(|known| &known.id == node)
            {
                stage_observed |= self
                    .guest_boot
                    .entry(node.name.clone())
                    .or_default()
                    .observe(event);
            }
        }
        stage_observed
    }

    pub(in crate::vm_lifecycle) fn reserve_evidence_report(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }

    pub(in crate::vm_lifecycle) fn begin(&mut self) -> bool {
        if self.remaining < 2 {
            return false;
        }
        self.begin_at(diagnostic_clock())
    }

    fn begin_at(&mut self, now: Instant) -> bool {
        if self.remaining < 2 || self.next_report.is_some_and(|next| now < next) {
            return false;
        }
        // Reserve both notices before effects. A blocked operation leaves its
        // before notice visible without inventing a completed quantum.
        self.remaining -= 2;
        self.next_report = now.checked_add(REPORT_INTERVAL);
        true
    }
}

impl ProductionVmLifecycleLoop {
    pub(in crate::vm_lifecycle) fn report_runtime_progress(&self, stage: &str) {
        let scheduler = self.inner.loop_impl();
        let nodes = self.source.world().vm_nodes();
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "CRUCIBLE-RUNTIME-PROGRESS-V1 stage={stage} quanta={} frontier_ps={} pending_network_outputs={} node_count={} omitted_nodes={} published_slot_status=unavailable tx_rx_counters=unavailable",
            scheduler.quanta(),
            scheduler.frontier().ticks,
            self.inner.pending_network_output_count(),
            nodes.len(),
            nodes.len().saturating_sub(MAX_REPORTED_NODES),
        );
        for node in nodes.iter().take(MAX_REPORTED_NODES) {
            // These are retained, authenticated boundary coordinates. The
            // backend clock is not a fresh shared-slot sample during a RUN.
            let scheduler_time = scheduler
                .scheduler_time_for_node(&node.id)
                .map(|time| time.ticks);
            let backend_time =
                crucible::SimulationBackend::node_now(self.inner.backend(), &node.id)
                    .map(|time| time.ticks);
            let state = self.production_node_fault_evidence(&node.id);
            let _ = writeln!(
                stderr,
                "CRUCIBLE-RUNTIME-PROGRESS-V1 stage={stage} node={:?} scheduler_time_ps={scheduler_time:?} backend_last_observed_tick_ps={backend_time:?} lifecycle_state={state:?}",
                node.id.name,
            );
            let boot = self.runtime_progress.guest_boot.get(&node.id.name);
            let console_tail = String::from_utf8_lossy(
                boot.map_or(&[][..], |progress| progress.console_tail.as_slice()),
            );
            let _ = writeln!(
                stderr,
                "CRUCIBLE-RUNTIME-BOOT-V1 stage={stage} node={:?} guest_stage={} stage_icount={} setup_receipts={} console_bytes={} console_tail_partial=true console_tail={console_tail:?}",
                node.id.name,
                boot.and_then(|progress| progress.stage)
                    .unwrap_or("not-attested"),
                boot.map_or(0, |progress| progress.stage_icount),
                boot.map_or(0, |progress| progress.setup_receipts),
                boot.map_or(0, |progress| progress.console_bytes),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_reserve_pairs_at_bounded_cadence_without_sleeping() {
        let now = diagnostic_clock();
        let mut progress = RuntimeProgress {
            remaining: 4,
            ..RuntimeProgress::default()
        };

        assert!(progress.begin_at(now));
        assert!(!progress.begin_at(now + Duration::from_secs(4)));
        assert!(progress.begin_at(now + REPORT_INTERVAL));
        assert!(!progress.begin_at(now + REPORT_INTERVAL * 2));
        assert_eq!(progress.remaining, 0);
    }

    #[test]
    fn disabled_and_exhausted_reporters_do_not_sample() {
        let mut disabled = RuntimeProgress::default();
        assert!(!disabled.begin());
        let mut exhausted = RuntimeProgress {
            remaining: 1,
            ..RuntimeProgress::default()
        };
        assert!(!exhausted.begin());
        assert_eq!(exhausted.remaining, 1);
    }

    #[test]
    fn console_tail_is_bounded_and_cannot_attest_guest_setup() {
        let node = crucible::NodeId {
            name: "curl".into(),
        };
        let mut progress = GuestBootProgress::default();
        let first = ObservableEventPayload::ConsoleOutput {
            node: node.clone(),
            bytes: vec![b'a'; CONSOLE_TAIL_BYTES + 20],
        };
        assert!(!progress.observe(&first));
        let forged_setup = ObservableEventPayload::ConsoleOutput {
            node,
            bytes: b"lifecycle.setup_complete\n\xff".to_vec(),
        };
        assert!(!progress.observe(&forged_setup));
        assert_eq!(progress.console_tail.len(), CONSOLE_TAIL_BYTES);
        assert_eq!(progress.console_bytes, CONSOLE_TAIL_BYTES + 20 + 26);
        assert!(
            progress
                .console_tail
                .ends_with(b"lifecycle.setup_complete\n\xff")
        );
        assert_eq!(progress.setup_receipts, 0);
        assert_eq!(progress.stage, None);
    }

    #[test]
    fn only_decoded_guest_marker_records_setup_receipt() {
        let node = crucible::NodeId {
            name: "nginx".into(),
        };
        let mut progress = GuestBootProgress::default();
        let event = ObservableEventPayload::GuestMarker {
            retired_icount: crucible::Icount { retired: 42 },
            node,
            marker: crucible::MarkerId {
                name: "lifecycle.setup_complete".into(),
            },
        };
        assert!(progress.observe(&event));
        assert_eq!(progress.stage, Some("setup-complete"));
        assert_eq!(progress.stage_icount, 42);
        assert_eq!(progress.setup_receipts, 1);

        let mut budget = RuntimeProgress {
            remaining: 1,
            ..RuntimeProgress::default()
        };
        assert!(budget.reserve_evidence_report());
        assert!(!budget.reserve_evidence_report());
    }

    #[test]
    fn outcome_capture_ignores_disabled_and_undeclared_guest_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let scenario = crucible::crash_restart_scenario()?.scenario;
        let node = scenario
            .world()
            .vm_nodes()
            .iter()
            .next()
            .ok_or("missing fixture node")?
            .id
            .clone();
        let marker = crucible::MarkerId {
            name: "lifecycle.setup_complete".into(),
        };
        let entries = vec![
            crucible::SchedulerEventLogEntry::guest_marker_observation(
                0,
                crucible::Icount { retired: 40 },
                crucible::NodeId {
                    name: "unlisted-progress-node".into(),
                },
                marker.clone(),
            ),
            crucible::SchedulerEventLogEntry::guest_marker_observation(
                1,
                crucible::Icount { retired: 42 },
                node.clone(),
                marker,
            ),
        ];
        let outcome = QuantumOutcome {
            configuration: crucible::Configuration::genesis(scenario.scenario_def()),
            frontier: crucible::VirtualTime { ticks: 42 },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, 2),
            scheduler_quiescence: None,
        };

        let mut disabled = RuntimeProgress::default();
        assert!(!disabled.observe(&outcome, scenario.world().vm_nodes()));
        assert!(disabled.guest_boot.is_empty());
        assert!(disabled.next_report.is_none());

        let mut enabled = RuntimeProgress {
            enabled: true,
            remaining: 4,
            ..RuntimeProgress::default()
        };
        assert!(enabled.observe(&outcome, scenario.world().vm_nodes()));
        assert_eq!(enabled.guest_boot.len(), 1);
        assert_eq!(
            enabled
                .guest_boot
                .get(&node.name)
                .ok_or("missing declared node")?
                .setup_receipts,
            1
        );
        assert!(!enabled.guest_boot.contains_key("unlisted-progress-node"));
        Ok(())
    }
}
