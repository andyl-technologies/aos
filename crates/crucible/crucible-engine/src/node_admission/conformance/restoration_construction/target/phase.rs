//! Keeps failed and completed restoration phases distinct on the same target.
//!
//! Starting a phase is irreversible. Transport responses do not finish it; only
//! Core's evidence consumer may mark the already-started phase verified after
//! Source's private receipt and terminal currentness checks have completed.

use super::*;
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Reserved,
    PrepareStarted,
    PrepareVerified,
    InputsStarted,
    InputsVerified,
    CommitStarted,
    CommitVerified,
}

pub(super) struct OriginalRestorationTargetPhaseGate {
    phase: Cell<Phase>,
    mapping_started: Cell<bool>,
}

impl OriginalRestorationTargetPhaseGate {
    pub(super) fn new() -> Self {
        Self {
            phase: Cell::new(Phase::Reserved),
            mapping_started: Cell::new(false),
        }
    }

    pub(super) fn begin(
        &self,
        phase: &OriginalRestorationTransactionPhase,
    ) -> Result<(), RuntimeError> {
        let (required, started) = match phase {
            OriginalRestorationTransactionPhase::Prepare => {
                (Phase::Reserved, Phase::PrepareStarted)
            }
            OriginalRestorationTransactionPhase::Inputs => {
                (Phase::PrepareVerified, Phase::InputsStarted)
            }
            OriginalRestorationTransactionPhase::Commit => {
                (Phase::InputsVerified, Phase::CommitStarted)
            }
        };
        if self.phase.get() != required {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.phase.set(started);
        Ok(())
    }

    pub(super) fn authenticate_started(
        &self,
        phase: &OriginalRestorationTransactionPhase,
    ) -> Result<(), RuntimeError> {
        let required = match phase {
            OriginalRestorationTransactionPhase::Prepare => Phase::PrepareStarted,
            OriginalRestorationTransactionPhase::Inputs => Phase::InputsStarted,
            OriginalRestorationTransactionPhase::Commit => Phase::CommitStarted,
        };
        if self.phase.get() != required {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    // Only the installed window's opaque-evidence consumer calls this method.
    // There are no callbacks or allocations between its final evidence check
    // and this fixed Cell transition.
    pub(super) fn finish_verified(
        &self,
        phase: &OriginalRestorationTransactionPhase,
    ) -> Result<(), RuntimeError> {
        self.authenticate_started(phase)?;
        self.phase.set(match phase {
            OriginalRestorationTransactionPhase::Prepare => Phase::PrepareVerified,
            OriginalRestorationTransactionPhase::Inputs => Phase::InputsVerified,
            OriginalRestorationTransactionPhase::Commit => Phase::CommitVerified,
        });
        Ok(())
    }

    pub(super) fn begin_mapping(&self) -> Result<(), RuntimeError> {
        self.authenticate_started(&OriginalRestorationTransactionPhase::Prepare)?;
        if self.mapping_started.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn authenticate_mapping_started(&self) -> Result<(), RuntimeError> {
        self.authenticate_started(&OriginalRestorationTransactionPhase::Prepare)?;
        if !self.mapping_started.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn authenticate_completed(&self) -> Result<(), RuntimeError> {
        if self.phase.get() != Phase::CommitVerified {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_started_phase_cannot_retry_skip_or_complete_a_later_phase() {
        let gate = OriginalRestorationTargetPhaseGate::new();
        assert!(
            gate.begin(&OriginalRestorationTransactionPhase::Inputs)
                .is_err()
        );
        assert!(gate.begin_mapping().is_err());

        gate.begin(&OriginalRestorationTransactionPhase::Prepare)
            .unwrap();
        gate.begin_mapping().unwrap();

        assert!(gate.begin_mapping().is_err());
        assert!(
            gate.begin(&OriginalRestorationTransactionPhase::Prepare)
                .is_err()
        );
        assert!(
            gate.begin(&OriginalRestorationTransactionPhase::Inputs)
                .is_err()
        );
        assert!(
            gate.finish_verified(&OriginalRestorationTransactionPhase::Commit)
                .is_err()
        );
        assert!(gate.authenticate_completed().is_err());
        gate.authenticate_started(&OriginalRestorationTransactionPhase::Prepare)
            .unwrap();
    }

    #[test]
    fn ordered_verification_never_reopens_the_query_or_mapping_phase() {
        let gate = OriginalRestorationTargetPhaseGate::new();
        gate.begin(&OriginalRestorationTransactionPhase::Prepare)
            .unwrap();
        gate.begin_mapping().unwrap();
        gate.finish_verified(&OriginalRestorationTransactionPhase::Prepare)
            .unwrap();
        gate.begin(&OriginalRestorationTransactionPhase::Inputs)
            .unwrap();
        gate.finish_verified(&OriginalRestorationTransactionPhase::Inputs)
            .unwrap();
        gate.begin(&OriginalRestorationTransactionPhase::Commit)
            .unwrap();
        gate.finish_verified(&OriginalRestorationTransactionPhase::Commit)
            .unwrap();

        gate.authenticate_completed().unwrap();
        assert!(
            gate.begin(&OriginalRestorationTransactionPhase::Prepare)
                .is_err()
        );
        assert!(gate.begin_mapping().is_err());
        assert!(
            gate.begin(&OriginalRestorationTransactionPhase::Commit)
                .is_err()
        );
    }
}

impl OriginalRestorationTargetPhaseGate {
    pub(super) fn authenticate_before_prepare_data(&self) -> Result<(), RuntimeError> {
        if self.phase.get() != Phase::Reserved || self.mapping_started.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}
