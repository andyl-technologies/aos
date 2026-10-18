//! Latest owned-process evidence for a frozen-source/private-child fork assertion.
//!
//! Fork sampling retains at most 8192 bytes, 32 process rows and eight identities
//! per resource set. Omitted counts remain explicit. One failure report is allowed
//! for the audit's lifetime, including failed writes; its header adds at most
//! 512 bytes. These observations never participate in pair acceptance.

use super::*;

const MAX_SNAPSHOT_BYTES: usize = 8192;
const MAX_PROCESSES: usize = 32;
const MAX_IDENTITIES: usize = 8;

#[derive(Default)]
pub(super) struct ForkDiagnostics {
    rows: String,
    observed: usize,
    retained: usize,
    incomplete: usize,
    complete_resources: usize,
    reason: Option<&'static str>,
    reported: bool,
    enabled: bool,
}

impl ForkDiagnostics {
    pub(super) fn begin_sample(&mut self) {
        self.enabled = true;
        self.rows.clear();
        self.observed = 0;
        self.retained = 0;
        self.incomplete = 0;
        self.complete_resources = 0;
        self.reason = None;
    }

    pub(super) fn record(
        &mut self,
        pid: u32,
        resources: Option<&QemuResources>,
        incomplete: Option<&str>,
    ) {
        if !self.enabled {
            return;
        }
        self.observed = self.observed.saturating_add(1);
        self.incomplete = self
            .incomplete
            .saturating_add(usize::from(incomplete.is_some()));
        if self.retained == MAX_PROCESSES {
            return;
        }
        let complete = resources.is_some() && incomplete.is_none();
        let incomplete = incomplete.map(|reason| bounded_ascii(reason, 128));
        let row = match resources {
            Some(resources) => {
                let rings = resources
                    .rings
                    .iter()
                    .take(MAX_IDENTITIES)
                    .map(|(device, inode)| (bounded_ascii(device, 32), *inode))
                    .collect::<Vec<_>>();
                let overlays = resources
                    .overlays
                    .iter()
                    .take(MAX_IDENTITIES)
                    .collect::<Vec<_>>();
                let read_only_overlays = resources
                    .read_only_overlays
                    .iter()
                    .take(MAX_IDENTITIES)
                    .collect::<Vec<_>>();
                format!(
                    "CRUCIBLE-HOT-FORK-PAIR-RESOURCE-V1 pid={pid} parent={} start_time_ticks={:?} resource_complete={complete} ring_count={} rings={rings:?} omitted_rings={} writable_overlay_count={} writable_overlays={overlays:?} omitted_overlays={} read_only_overlay_count={} read_only_overlays={read_only_overlays:?} omitted_read_only_overlays={} incomplete={incomplete:?}\n",
                    resources.parent,
                    resources.start_time_ticks,
                    resources.rings.len(),
                    resources.rings.len().saturating_sub(MAX_IDENTITIES),
                    resources.overlays.len(),
                    resources.overlays.len().saturating_sub(MAX_IDENTITIES),
                    resources.read_only_overlays.len(),
                    resources
                        .read_only_overlays
                        .len()
                        .saturating_sub(MAX_IDENTITIES),
                )
            }
            None => format!(
                "CRUCIBLE-HOT-FORK-PAIR-RESOURCE-V1 pid={pid} parent=unavailable resource_complete=false resources=unavailable incomplete={incomplete:?}\n"
            ),
        };
        if self.rows.len().saturating_add(row.len()) <= MAX_SNAPSHOT_BYTES {
            self.rows.push_str(&row);
            self.retained += 1;
        }
    }

    pub(super) fn refusal(&mut self, reason: &'static str, complete_resources: usize) {
        if !self.enabled {
            return;
        }
        self.reason = Some(reason);
        self.complete_resources = complete_resources;
    }

    pub(super) fn report(&mut self, stage: &str, sink: &mut impl Write) {
        if self.reported {
            return;
        }
        self.reported = true;
        let stage = bounded_ascii(stage, 32);
        // A closed diagnostic sink cannot replace the original fixture failure.
        let _ = writeln!(
            sink,
            "CRUCIBLE-HOT-FORK-PAIR-REFUSAL-V1 stage={stage:?} reason={:?} observed_owned_qemu={} complete_resource_count={} incomplete_processes={} retained_processes={} omitted_processes={} snapshot_bytes={} snapshot=latest-owned-process-sample\n{}",
            self.reason.unwrap_or("no-owned-process-sample"),
            self.observed,
            self.complete_resources,
            self.incomplete,
            self.retained,
            self.observed.saturating_sub(self.retained),
            self.rows.len(),
            self.rows,
        );
    }
}

fn bounded_ascii(value: &str, maximum: usize) -> String {
    value
        .chars()
        .take(maximum)
        .map(|character| {
            if character == ' ' || character.is_ascii_graphic() {
                character
            } else {
                '?'
            }
        })
        .collect()
}

/// Names the first failed conjunct of the frozen-source/private-child predicate.
pub(super) fn pair_refusal(source: &QemuResources, child: &QemuResources) -> Option<&'static str> {
    if source.pid == child.pid || child.parent != source.pid {
        Some("source-child-process-parent-mismatch")
    } else if source.start_time_ticks.is_none() || child.start_time_ticks.is_none() {
        Some("source-child-process-start-time-unavailable")
    } else if source.rings.is_empty() {
        Some("source-ring-set-empty")
    } else if child.rings.is_empty() {
        Some("child-ring-set-empty")
    } else if source.read_only_overlays.is_empty() {
        Some("source-read-only-overlay-set-empty")
    } else if child.overlays.is_empty() {
        Some("child-writable-overlay-set-empty")
    } else if !source.rings.is_disjoint(&child.rings) {
        Some("source-child-ring-sets-overlap")
    } else if !source.read_only_overlays.is_disjoint(&source.overlays) {
        Some("source-read-only-basis-has-writable-alias")
    } else if !source.read_only_overlays.is_disjoint(&child.overlays) {
        Some("child-writable-overlay-aliases-source-read-only-basis")
    } else if !child.read_only_overlays.is_disjoint(&child.overlays) {
        Some("child-writable-overlay-has-read-only-alias")
    } else if !source.overlays.is_disjoint(&child.overlays) {
        Some("source-child-writable-overlay-sets-overlap")
    } else {
        None
    }
}

#[cfg(test)]
#[path = "fork_diagnostics/tests.rs"]
mod tests;
