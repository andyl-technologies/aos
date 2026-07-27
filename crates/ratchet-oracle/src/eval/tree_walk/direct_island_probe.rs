//! Inclusive coverage probe for a direct `lib/modules.nix` execution island.
//!
//! The module-system entry function returns a lazy result attrset, so timing
//! its outer application materially undercounts the demanded fixpoint. This
//! default-off probe instead recognizes the lowered `configWithFreeform`
//! conditional by source identity and exact source slice, then measures the
//! node force that recursively demands module collection and option merging.

use std::time::Instant;

use super::*;

/// Mutable state retained only when the explicit probe environment flag is set.
#[derive(Debug)]
pub(super) struct DirectIslandProbe {
    evaluation_start: Instant,
    active_depth: u32,
    entries: u64,
    island_nanos: u64,
    total_forces: u64,
    island_forces: u64,
}

impl DirectIslandProbe {
    /// Constructs probe state when explicitly requested.
    pub(super) fn from_env() -> Option<Self> {
        std::env::var_os("AOS_NIX_DIRECT_ISLAND_PROBE").map(|_| Self {
            evaluation_start: Instant::now(),
            active_depth: 0,
            entries: 0,
            island_nanos: 0,
            total_forces: 0,
            island_forces: 0,
        })
    }
}

/// One open outer target node.
pub(super) struct DirectIslandProbeToken {
    started: Instant,
}

/// Completed probe totals.
pub(super) struct DirectIslandProbeReport {
    pub(super) entries: u64,
    pub(super) total_ns: u64,
    pub(super) island_ns: u64,
    pub(super) total_forces: u64,
    pub(super) island_forces: u64,
}

impl TreeWalk {
    /// Counts one dynamic thunk body under the active inclusive wall.
    pub(super) fn note_direct_island_force(&mut self) {
        let Some(probe) = self.direct_island_probe.as_mut() else {
            return;
        };
        probe.total_forces = probe.total_forces.saturating_add(1);
        if probe.active_depth != 0 {
            probe.island_forces = probe.island_forces.saturating_add(1);
        }
    }

    /// Opens the wall when `body` is the source-validated config conditional.
    pub(super) fn begin_direct_island_node(
        &mut self,
        body: EvalNodeRef,
    ) -> Option<DirectIslandProbeToken> {
        self.direct_island_probe.as_ref()?;
        let module = self.modules.get(body.module().index())?;
        let source = module.source.as_ref()?;
        if !source.name.ends_with(b"/lib/modules.nix") {
            return None;
        }
        let node = module.ir.arena.node(body.id())?;
        let node_source = source
            .bytes
            .get(node.span.start as usize..node.span.end as usize)?;
        if node.kind != IrKind::If
            || !node_source.starts_with(b"if freeformType == null && !isStrict")
        {
            return None;
        }
        let probe = self.direct_island_probe.as_mut()?;
        probe.active_depth = probe.active_depth.saturating_add(1);
        probe.entries = probe.entries.saturating_add(1);
        probe.island_forces = probe.island_forces.saturating_add(1);
        Some(DirectIslandProbeToken {
            started: Instant::now(),
        })
    }

    /// Closes one recognized wall and accumulates only the outermost duration.
    pub(super) fn end_direct_island_node(&mut self, token: Option<DirectIslandProbeToken>) {
        let Some(token) = token else {
            return;
        };
        let Some(probe) = self.direct_island_probe.as_mut() else {
            return;
        };
        probe.active_depth = probe.active_depth.saturating_sub(1);
        if probe.active_depth == 0 {
            probe.island_nanos = probe
                .island_nanos
                .saturating_add(nanos_u64(token.started.elapsed()));
        }
    }

    /// Returns a stable snapshot at the successful evaluation boundary.
    pub(super) fn direct_island_probe_report(&self) -> Option<DirectIslandProbeReport> {
        let probe = self.direct_island_probe.as_ref()?;
        Some(DirectIslandProbeReport {
            entries: probe.entries,
            total_ns: nanos_u64(probe.evaluation_start.elapsed()),
            island_ns: probe.island_nanos,
            total_forces: probe.total_forces,
            island_forces: probe.island_forces,
        })
    }
}

fn nanos_u64(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
