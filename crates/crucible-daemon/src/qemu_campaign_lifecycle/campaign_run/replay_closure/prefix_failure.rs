//! Prepaid typed error storage for admitted schedule-prefix copies.
//!
//! The prefix may return a large engine error. One slot is admitted and
//! reserved before the copy starts; moving its error performs no allocation.
//! The slot and its actual payload close before their external decode custody.

use std::error::Error;
use std::fmt;

use crucible::EngineError;
use crucible::owned_decode::{DecodeCustody, charge_array, current_custody};

use super::GuardedCampaignReplayClosureError;

/// Retains a schedule-copy failure in its original prepaid typed slot.
///
/// The error remains available through [`Error::source`]. Its storage is freed
/// before the saved original account is released; no model owner is exposed.
#[derive(Debug)]
pub struct SchedulePrefixFailure {
    error: Vec<EngineError>,
    _custody: DecodeCustody,
}

impl SchedulePrefixFailure {
    pub(super) fn prepare() -> Result<Self, GuardedCampaignReplayClosureError> {
        let custody = current_custody().unwrap_or_default();
        charge_array::<EngineError>(1)?;
        let mut error = Vec::new();
        error
            .try_reserve_exact(1)
            .map_err(GuardedCampaignReplayClosureError::Allocation)?;

        Ok(Self {
            error,
            _custody: custody,
        })
    }

    pub(super) fn retain(mut self, error: EngineError) -> Self {
        // Preparation admitted exactly this one slot before the prefix effect.
        // This private method is used once on the initiating copy failure.
        self.error.push(error);
        self
    }
}

impl Drop for SchedulePrefixFailure {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.error));
    }
}

impl fmt::Display for SchedulePrefixFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.error.first() {
            Some(error) => fmt::Display::fmt(error, formatter),
            None => formatter.write_str("prepared schedule-prefix failure slot"),
        }
    }
}

impl Error for SchedulePrefixFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        let error = self.error.first()?;
        Some(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use crucible::owned_decode::{
        DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, ResourceLoan,
    };

    struct Credit(Arc<AtomicU64>, u64);

    impl Drop for Credit {
        fn drop(&mut self) {
            self.0.fetch_sub(self.1, Ordering::SeqCst);
        }
    }

    struct Authority {
        used: Arc<AtomicU64>,
        calls: AtomicU64,
        refusing: AtomicBool,
        failure: DecodeAdmissionError,
    }

    impl DecodeResourceAuthority for Authority {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            Ok(())
        }

        fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.refusing.load(Ordering::SeqCst) {
                return Err(self.failure.clone());
            }
            self.used.fetch_add(bytes, Ordering::SeqCst);
            Ok(ResourceLoan::new(Credit(self.used.clone(), bytes)))
        }
    }

    fn original() -> Result<(DecodeBudget, Arc<Authority>), DecodeAdmissionError> {
        let authority = Arc::new(Authority {
            used: Arc::new(AtomicU64::new(0)),
            calls: AtomicU64::new(0),
            refusing: AtomicBool::new(false),
            failure: DecodeAdmissionError::new(fmt::Error),
        });
        let budget = DecodeBudget::new(authority.clone(), 1024 * 1024)?;
        Ok((budget, authority))
    }

    #[test]
    fn prefix_failure_moves_same_cause_without_later_reservation() -> Result<(), Box<dyn Error>> {
        let (budget, authority) = original()?;
        let scope = budget.enter();
        let prepared = SchedulePrefixFailure::prepare()?;
        authority.calls.store(0, Ordering::SeqCst);
        authority.refusing.store(true, Ordering::SeqCst);

        let failure = prepared.retain(EngineError::ArtifactDecodeAdmission {
            source: authority.failure.clone(),
        });
        let retained = failure
            .source()
            .and_then(|error| error.downcast_ref::<EngineError>());
        assert!(
            matches!(retained, Some(EngineError::ArtifactDecodeAdmission { source }) if source == &authority.failure)
        );
        assert_eq!(authority.calls.load(Ordering::SeqCst), 0);

        drop(scope);
        drop(budget);
        assert!(authority.used.load(Ordering::SeqCst) > 0);
        drop(failure);
        assert_eq!(authority.used.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn refused_prefix_slot_keeps_exact_original_before_copy() -> Result<(), Box<dyn Error>> {
        let (budget, authority) = original()?;
        let _scope = budget.enter();
        authority.refusing.store(true, Ordering::SeqCst);
        let failure = SchedulePrefixFailure::prepare().err();

        assert!(
            matches!(failure, Some(GuardedCampaignReplayClosureError::Metadata(ref source)) if source == &authority.failure)
        );
        assert_eq!(budget.check().err(), Some(authority.failure.clone()));
        Ok(())
    }

    #[test]
    fn prefix_error_storage_does_not_expand_outer_error_variants() {
        assert!(std::mem::size_of::<GuardedCampaignReplayClosureError>() < 128);
        assert!(std::mem::size_of::<SchedulePrefixFailure>() < std::mem::size_of::<EngineError>());
    }
}
