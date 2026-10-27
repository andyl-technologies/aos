//! Fail-closed check of the attestation a settled gap carries.
//!
//! A node settled through `settled` with its actual clock at `counter`
//! carries the backend's attestation that no retirement and no exact event
//! remains in `(counter, settled]` (RFC-0010 SCHED-12), and an idle-parked
//! node's next output is not before `settled` (SCHED-28). The scheduler has
//! already published at that settled time: it resolved the node's deliveries
//! there and let peers advance against it. A later RUN that retires or emits
//! strictly inside the gap therefore contradicts evidence the log already
//! holds, and nothing it carries can be placed in canonical order. The
//! scheduler refuses it at once with a named row instead of admitting it and
//! diverging later.
//!
//! A stop exactly at the settled point is consistent: a time-only arrival or
//! a modeled wake there is the gap's own boundary.
//!
//! ```text
//! CRUCIBLE-SETTLED-GAP-VIOLATION-V1 node=router-a counter=10 settled=40 evidence=emit sequence=17 at=25
//! ```

use super::*;

/// Committed RUNs of the offending node quoted in a violation.
const RECENT_HOST_RUNS: usize = 4;

/// What a RUN reported inside its node's settled gap.
#[derive(Clone, Copy, Debug)]
pub(super) enum SettledGapEvidence {
    /// The RUN's physical stop, a retirement.
    Retirement,
    /// A frame the RUN emitted, with its producer sequence.
    Emit { sequence: u64 },
}

impl SingleScheduler {
    /// Refuses `at` when it lies strictly inside the node's attested gap.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] carrying a
    /// `CRUCIBLE-SETTLED-GAP-VIOLATION-V1` row and the node's latest
    /// committed host RUNs when `counter < at < settled`.
    pub(super) fn reject_inside_settled_gap(
        &self,
        index: usize,
        evidence: SettledGapEvidence,
        at: NodeCounter,
    ) -> Result<(), SchedulerError> {
        let node = &self.nodes[index];
        if at <= node.counter || at >= node.settled {
            return Ok(());
        }

        let (kind, sequence) = match evidence {
            SettledGapEvidence::Retirement => ("retirement", String::from("none")),
            SettledGapEvidence::Emit { sequence } => ("emit", sequence.to_string()),
        };
        let mut message = format!(
            "CRUCIBLE-SETTLED-GAP-VIOLATION-V1 node={} counter={} settled={} evidence={kind} sequence={sequence} at={}",
            node.id.node.name, node.counter.ticks, node.settled.ticks, at.ticks,
        );
        for committed in
            super::host_run_trace::recent_for_node(&node.id.node.name, RECENT_HOST_RUNS)
        {
            message.push_str("; ");
            message.push_str(&committed.row());
        }

        Err(SchedulerError::BoundaryViolation { message })
    }

    /// Refuses a frame emitted inside its source's attested settled gap.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the source is not a VM node, or a
    /// `CRUCIBLE-SETTLED-GAP-VIOLATION-V1` boundary violation when `emit`
    /// lies strictly between the source's clock and its settled clock.
    pub(super) fn reject_output_inside_settled_gap(
        &self,
        source: &NodeId,
        sequence: u64,
        emit: Icount,
    ) -> Result<(), SchedulerError> {
        let index = self.vm_node_index(source)?;
        self.reject_inside_settled_gap(
            index,
            SettledGapEvidence::Emit { sequence },
            NodeCounter {
                ticks: emit.retired,
            },
        )
    }
}
