//! Retains one ordinary Storage cold cutoff without physical-floor authority.
//!
//! Dormant Legacy sessions keep their previous behavior. A selected receiving
//! continuation binds its original cutoff once, checks the same cutoff through
//! opening/currentness, then retires it only at the outer completed handshake.
//! Deadline errors and interrupted phases stay resident; no retry renews time.

use std::error::Error;

use super::FloorErrorV1;
use crate::handshake::OriginalBrokerColdDeadlineV1;
use crate::DormantBrokerSessionHandshakeErrorV1;

static CLOSED: FloorErrorV1 = FloorErrorV1::Unavailable;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ColdPhase {
    Dormant,
    Checking,
    Active,
    Retired,
    Failed,
}

/// Keeps the original cutoff and complete refusal custody through retirement.
pub(super) struct LegacyColdIntervalV1 {
    phase: ColdPhase,
    original: Option<OriginalBrokerColdDeadlineV1>,
    binding_check: Option<Result<(), DormantBrokerSessionHandshakeErrorV1>>,
    first_deadline_failure: Option<DormantBrokerSessionHandshakeErrorV1>,
    retirement_check: Option<Result<(), DormantBrokerSessionHandshakeErrorV1>>,
}

impl LegacyColdIntervalV1 {
    pub(super) const fn new() -> Self {
        Self {
            phase: ColdPhase::Dormant,
            original: None,
            binding_check: None,
            first_deadline_failure: None,
            retirement_check: None,
        }
    }

    pub(super) fn bind(
        &mut self,
        original: OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != ColdPhase::Dormant || self.original.is_some() {
            self.fence();
            return Err(FloorErrorV1::Unavailable);
        }
        self.original = Some(original);
        self.phase = ColdPhase::Checking;
        self.binding_check = Some(original.check());
        if !matches!(self.binding_check, Some(Ok(()))) {
            self.phase = ColdPhase::Failed;
            return Err(FloorErrorV1::Unavailable);
        }
        self.phase = ColdPhase::Active;
        Ok(())
    }

    pub(super) fn check(&mut self) -> Result<(), FloorErrorV1> {
        if self.phase != ColdPhase::Active {
            self.fence();
            return Err(FloorErrorV1::Unavailable);
        }
        let Some(original) = self.original else {
            self.fence();
            return Err(FloorErrorV1::Unavailable);
        };
        // A caught unwind leaves Checking, which cannot resume or be retired.
        self.phase = ColdPhase::Checking;
        match original.check() {
            Ok(()) => {
                self.phase = ColdPhase::Active;
                Ok(())
            }
            Err(cause) => {
                self.first_deadline_failure = Some(cause);
                self.phase = ColdPhase::Failed;
                Err(FloorErrorV1::Unavailable)
            }
        }
    }

    pub(super) fn retire(
        &mut self,
        original: OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != ColdPhase::Active || self.original != Some(original) {
            self.fence();
            return Err(FloorErrorV1::Unavailable);
        }
        self.phase = ColdPhase::Checking;
        self.retirement_check = Some(original.check());
        if !matches!(self.retirement_check, Some(Ok(()))) {
            self.phase = ColdPhase::Failed;
            return Err(FloorErrorV1::Unavailable);
        }
        // The final same-D observation precedes this infallible transition.
        // Keep the original and Result: retirement cannot permit another bind.
        self.phase = ColdPhase::Retired;
        Ok(())
    }

    pub(super) fn is_bound(&self) -> bool {
        self.original.is_some()
    }

    // Successful outer retirement restores the original ordinary inverse.
    // Failed/interrupted attempts still retain their original until resolved.
    pub(super) fn requires_retention(&self) -> bool {
        self.is_bound() && !matches!(self.retirement_check, Some(Ok(())))
    }

    pub(super) fn fence(&mut self) {
        self.phase = ColdPhase::Failed;
    }

    pub(super) fn require_healthy(&self) -> Result<(), FloorErrorV1> {
        if matches!(self.phase, ColdPhase::Checking | ColdPhase::Failed) {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(super) fn require_current(&mut self) -> Result<(), FloorErrorV1> {
        self.require_healthy()?;
        if self.phase == ColdPhase::Active {
            self.check()?;
        }
        Ok(())
    }

    pub(super) fn require_reopen_allowed(&self) -> Result<(), FloorErrorV1> {
        if !matches!(self.phase, ColdPhase::Dormant | ColdPhase::Retired) {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.binding_check
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| {
                self.first_deadline_failure
                    .as_ref()
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| {
                self.retirement_check
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| {
                matches!(self.phase, ColdPhase::Checking | ColdPhase::Failed)
                    .then_some(&CLOSED as &(dyn Error + 'static))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future() -> OriginalBrokerColdDeadlineV1 {
        // DATA fixture only; no clock, floor or receiving authority is minted.
        OriginalBrokerColdDeadlineV1::storage_accept(u64::MAX)
    }

    #[test]
    fn dormant_legacy_currentness_keeps_the_ordinary_non_cold_path() {
        let mut interval = LegacyColdIntervalV1::new();

        assert!(!interval.is_bound());
        assert!(interval.require_current().is_ok());
        assert!(interval.require_reopen_allowed().is_ok());
        assert!(interval.failure().is_none());
    }

    #[test]
    fn original_cutoff_survives_checks_and_exact_retirement_without_renewal() {
        let mut interval = LegacyColdIntervalV1::new();
        let original = future();
        interval.bind(original).unwrap();

        assert!(interval.is_bound());
        assert!(interval.require_reopen_allowed().is_err());
        interval.check().unwrap();
        interval.retire(original).unwrap();
        interval.require_current().unwrap();
        assert!(interval.require_reopen_allowed().is_ok());
        assert_eq!(interval.original, Some(original));
        assert!(matches!(interval.binding_check, Some(Ok(()))));
        assert!(matches!(interval.retirement_check, Some(Ok(()))));
        assert!(interval.bind(original).is_err());
        assert!(interval.require_current().is_err());
    }

    #[test]
    fn wrong_retirement_and_repeated_bind_close_the_original_interval() {
        for repeated_bind in [false, true] {
            let mut interval = LegacyColdIntervalV1::new();
            let original = future();
            interval.bind(original).unwrap();

            let result = if repeated_bind {
                interval.bind(original)
            } else {
                interval.retire(OriginalBrokerColdDeadlineV1::storage_accept(u64::MAX - 1))
            };
            assert!(result.is_err());
            assert_eq!(interval.original, Some(original));
            assert!(interval.check().is_err());
            assert!(interval.retire(original).is_err());
            assert!(interval.failure().is_some());
        }
    }

    #[test]
    fn expired_bind_retains_its_complete_original_error_after_later_refusals() {
        let mut interval = LegacyColdIntervalV1::new();
        let original = OriginalBrokerColdDeadlineV1::storage_accept(0);

        assert!(interval.bind(original).is_err());
        assert!(matches!(interval.binding_check,
            Some(Err(DormantBrokerSessionHandshakeErrorV1::Deadline))));
        assert!(interval.bind(future()).is_err());
        assert!(interval.check().is_err());
        assert!(interval.retire(original).is_err());
        assert!(matches!(interval.failure().unwrap()
            .downcast_ref::<DormantBrokerSessionHandshakeErrorV1>(),
            Some(DormantBrokerSessionHandshakeErrorV1::Deadline)));
    }

    #[test]
    fn active_expiry_and_retirement_expiry_keep_their_original_cause_slots() {
        for retire in [false, true] {
            // Passive phase fixture isolates expiry at each reached boundary;
            // production never changes the bound original after admission.
            let original = OriginalBrokerColdDeadlineV1::storage_accept(0);
            let mut interval = LegacyColdIntervalV1::new();
            interval.original = Some(original);
            interval.binding_check = Some(Ok(()));
            interval.phase = ColdPhase::Active;

            let result = if retire {
                interval.retire(original)
            } else {
                interval.check()
            };
            assert!(result.is_err());
            assert_eq!(interval.original, Some(original));
            assert!(interval.require_current().is_err());
            assert!(interval.require_reopen_allowed().is_err());
            assert!(matches!(interval.failure().unwrap()
                .downcast_ref::<DormantBrokerSessionHandshakeErrorV1>(),
                Some(DormantBrokerSessionHandshakeErrorV1::Deadline)));
            interval.fence();
            assert!(matches!(interval.failure().unwrap()
                .downcast_ref::<DormantBrokerSessionHandshakeErrorV1>(),
                Some(DormantBrokerSessionHandshakeErrorV1::Deadline)));
        }
    }

    #[test]
    fn only_unfinished_cold_attempts_require_guard_retention() {
        let original = future();
        let mut failed = LegacyColdIntervalV1::new();

        assert!(!failed.requires_retention());
        failed.bind(original).unwrap();
        assert!(failed.requires_retention());
        failed.fence();
        assert!(failed.requires_retention());

        let mut completed = LegacyColdIntervalV1::new();
        completed.bind(original).unwrap();
        completed.retire(original).unwrap();

        assert!(completed.is_bound());
        assert!(!completed.requires_retention());
        assert_eq!(completed.original, Some(original));
        assert!(completed.require_current().is_ok());
        assert!(completed.require_reopen_allowed().is_ok());
        assert!(completed.failure().is_none());
    }

    #[test]
    fn caught_unwind_phase_cannot_check_retire_or_reopen() {
        let mut interval = LegacyColdIntervalV1::new();
        let original = future();
        interval.bind(original).unwrap();
        interval.phase = ColdPhase::Checking;

        assert!(interval.requires_retention());
        assert!(interval.require_current().is_err());
        assert!(interval.require_reopen_allowed().is_err());
        assert!(interval.retire(original).is_err());
        assert!(interval.check().is_err());
        assert!(interval.failure().is_some());
    }
}
