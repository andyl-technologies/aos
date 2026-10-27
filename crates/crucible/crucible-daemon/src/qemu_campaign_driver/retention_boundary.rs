//! Retainable stop boundaries of modeled fresh attempts.
//!
//! A thin attempt that pauses at a published next-choice boundary can keep
//! its stopped world as a reusable source for later branches from that
//! boundary. This module decides, from the modeled stop alone, whether the
//! pending observation describes such a boundary, and seals the replay proof
//! that the prepared source must match before it may be reused.

use super::*;

impl QemuFreshPendingObservation {
    /// Returns the retainable boundary configuration and its replay proof.
    ///
    /// The stop must have reached a next-choice primary that continues the
    /// run, published at least one choice, and handed no live-network
    /// preselection to the observation. Terminal stops, timeouts, private
    /// replay boundaries, and observation-condition stops are never retained.
    /// A proof that cannot be sealed declines retention instead of failing
    /// the attempt. A declined stop reports the stable token of the first
    /// refused condition.
    pub(super) fn retention_boundary(
        &self,
    ) -> Result<(Configuration, QemuSavepointReplayProof), &'static str> {
        let next_choice_stop = match &self.stop {
            ModeledStop::Reached(stop) | ModeledStop::BoundedPrimaryReached { stop, .. } => {
                stop.accepts_next_choice()
            }
            ModeledStop::BoundedPrimaryTimeout { .. }
            | ModeledStop::PolicyTimeout { .. }
            | ModeledStop::ObservationReached { .. }
            | ModeledStop::ModeledTimeout(_)
            | ModeledStop::ReplayBoundary
            | ModeledStop::TerminalPassed
            | ModeledStop::TerminalFailed(_) => false,
        };
        let refusal = [
            (!next_choice_stop, "stop-not-next-choice"),
            (!self.stop.continues_run(), "stop-ends-run"),
            (self.discoveries.is_empty(), "no-discovered-choices"),
            (
                self.preselection.is_some(),
                "live-network-preselection-handoff",
            ),
        ]
        .into_iter()
        .find_map(|(refused, reason)| refused.then_some(reason));
        if let Some(reason) = refusal {
            return Err(reason);
        }

        let proof = QemuSavepointReplayProof::from_retained_boundary(
            &self.configuration,
            self.completed_quanta,
            self.terminal_at,
            &self.event_log,
        )
        .map_err(|_| "replay-proof-unsealed")?;
        Ok((self.configuration.clone(), proof))
    }
}
