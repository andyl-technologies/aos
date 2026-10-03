//! Opt-in, bounded diagnostics around production scheduler operations.
//!
//! Host time controls only stderr sampling. These notices never select a
//! deadline, mutate a queue, or replace the operation's actual result.

use std::collections::BTreeMap;
use std::io::Write;
// crucible-lint: allow host-monotonic-time -- host time limits stderr sampling only, never scheduler state or results.
use std::time::{Duration, Instant};

use super::super::ProductionVmLifecycleLoop;
use crucible::{ObservableEventPayload, QuantumOutcome, SchedulerEventLogPayload, WorldVmNodes};

const REPORT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_REPORTS: u16 = 1024;
// A finite late-evidence allowance, not a guarantee for every node or marker.
const MAX_RESERVED_EVIDENCE_REPORTS: u16 = 16;
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
// crucible-lint: allow clippy-disallowed-method -- this private clock limits opt-in stderr notices; disabled reporting returns before calling it.
#[allow(clippy::disallowed_methods)]
// crucible-lint: allow host-monotonic-time -- the returned host instant belongs only to process-local stderr cadence.
fn diagnostic_clock() -> Instant {
    // crucible-lint: allow host-monotonic-time -- this clock never selects a modeled deadline or affects an operation result.
    Instant::now()
}

/// Process-local sampling state excluded from every checkpoint and wire format.
#[derive(Debug, Default)]
pub(in crate::vm_lifecycle) struct RuntimeProgress {
    enabled: bool,
    remaining: u16,
    reserved_evidence: u16,
    // crucible-lint: allow host-monotonic-time -- sampling state is excluded from checkpoint and wire formats.
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
        Self::with_report_limit(maximum)
    }

    fn with_report_limit(maximum: u16) -> Self {
        Self {
            enabled: maximum != 0,
            remaining: maximum,
            // Preserve part of the admitted total for decoded stages or errors
            // that arrive after periodic telemetry has exhausted its allowance.
            reserved_evidence: maximum.div_ceil(4).min(MAX_RESERVED_EVIDENCE_REPORTS),
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
        self.reserved_evidence = self.reserved_evidence.saturating_sub(1);
        true
    }

    pub(in crate::vm_lifecycle) fn begin(&mut self) -> bool {
        if self.remaining.saturating_sub(self.reserved_evidence) < 2 {
            return false;
        }
        self.begin_at(diagnostic_clock())
    }

    // crucible-lint: allow host-monotonic-time -- the host instant gates stderr notices only, with no scheduler or queue mutation.
    fn begin_at(&mut self, now: Instant) -> bool {
        if self.remaining.saturating_sub(self.reserved_evidence) < 2
            || self.next_report.is_some_and(|next| now < next)
        {
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
        let mut progress = RuntimeProgress::with_report_limit(6);

        assert!(progress.begin_at(now));
        assert!(!progress.begin_at(now + Duration::from_secs(4)));
        assert!(progress.begin_at(now + REPORT_INTERVAL));
        assert!(!progress.begin_at(now + REPORT_INTERVAL * 2));
        assert_eq!(progress.remaining, 2);
        assert_eq!(progress.reserved_evidence, 2);
    }

    #[test]
    fn disabled_and_exhausted_reporters_do_not_sample() {
        let mut disabled = RuntimeProgress::default();
        assert!(!disabled.begin());
        let mut exhausted = RuntimeProgress::with_report_limit(2);
        assert!(!exhausted.begin());
        assert_eq!(exhausted.remaining, 2);
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

        let mut budget = RuntimeProgress::with_report_limit(1);
        assert!(budget.reserve_evidence_report());
        assert!(!budget.reserve_evidence_report());
    }

    #[test]
    fn periodic_exhaustion_preserves_declared_boot_evidence_within_256_reports()
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

        let mut enabled = RuntimeProgress::with_report_limit(256);
        let now = diagnostic_clock();
        let mut periodic_notices = 0;
        for interval in 0..128 {
            if enabled.begin_at(now + REPORT_INTERVAL * interval) {
                periodic_notices += 2;
            }
        }
        assert_eq!(periodic_notices, 240);
        assert_eq!(enabled.remaining, 16);

        let mut ignored = outcome.clone();
        ignored.event_log_entries.truncate(1);
        ignored.event_log_entries.push(
            crucible::test_support::condition_observation_entry_for_test(
                1,
                &crucible::ObservableEvent::console_output(
                    crucible::VirtualTime { ticks: 41 },
                    node.clone(),
                    b"lifecycle.setup_complete".to_vec(),
                ),
            ),
        );
        assert!(!enabled.observe(&ignored, scenario.world().vm_nodes()));
        assert_eq!(enabled.remaining, 16);
        assert_eq!(
            enabled
                .guest_boot
                .get(&node.name)
                .ok_or("missing console node")?
                .setup_receipts,
            0
        );

        assert!(enabled.observe(&outcome, scenario.world().vm_nodes()));
        assert!(enabled.reserve_evidence_report());
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
        for _ in 0..15 {
            assert!(enabled.reserve_evidence_report());
        }
        assert!(!enabled.reserve_evidence_report());
        assert!(!enabled.begin_at(now + REPORT_INTERVAL * 128));
        assert_eq!(periodic_notices + 16, 256);
        assert_eq!(enabled.remaining, 0);
        assert_eq!(enabled.reserved_evidence, 0);
        Ok(())
    }

    #[test]
    fn evidence_reservations_preserve_total_caps_and_small_budget_pairs() {
        let now = diagnostic_clock();
        for maximum in [0, 1, 2, 3, 4, 5, 16, 255, 256, MAX_REPORTS] {
            let mut progress = RuntimeProgress::with_report_limit(maximum);
            let mut periodic_notices = 0;
            for interval in 0..MAX_REPORTS / 2 {
                if progress.begin_at(now + REPORT_INTERVAL * u32::from(interval)) {
                    periodic_notices += 2;
                }
            }
            let mut evidence_notices = 0;
            for _ in 0..=maximum {
                if progress.reserve_evidence_report() {
                    evidence_notices += 1;
                }
            }
            assert_eq!(periodic_notices + evidence_notices, maximum);
            assert_eq!(progress.remaining, 0);
            assert_eq!(progress.reserved_evidence, 0);
            assert!(!progress.begin_at(now + REPORT_INTERVAL * u32::from(MAX_REPORTS)));
            assert!(!progress.reserve_evidence_report());
            if maximum <= 2 {
                assert_eq!(periodic_notices, 0);
            } else if maximum == 3 {
                assert_eq!(periodic_notices, 2);
                assert_eq!(evidence_notices, 1);
            }
        }
    }
}
