//! Finite original metadata authority for explicitly labeled component fixtures.
//!
//! The counter admits owned model copies and output storage. It grants no
//! native process, paging, kernel quota, or production capability qualification.

use crate::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, DecodeScope,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

struct FixtureAuthority {
    used: Arc<AtomicU64>,
    maximum: u64,
}

struct FixtureCredit {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for FixtureCredit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for FixtureAuthority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.used.load(Ordering::SeqCst) > self.maximum {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|total| *total <= self.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other(
                    "finite component fixture metadata authority exhausted",
                ))
            })?;
        Ok(Arc::new(FixtureCredit {
            used: Arc::clone(&self.used),
            bytes,
        }))
    }
}

/// Retains a component fixture's finite original metadata account and scope.
///
/// Evaluators and output owners keep credits from this same authority. Their
/// remaining credits survive the lexical scope until the last owner closes.
pub struct FixtureDecodeScope {
    _scope: DecodeScope,
    budget: DecodeBudget,
    used: Arc<AtomicU64>,
}

impl FixtureDecodeScope {
    /// Returns currently retained metadata bytes from this original authority.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.used.load(Ordering::SeqCst)
    }

    /// Checks that the original account has not refused an allocation.
    ///
    /// # Errors
    /// Returns the original typed refusal when the account is exhausted.
    pub fn check(&self) -> Result<(), DecodeAdmissionError> {
        self.budget.check()
    }
}

/// Enters one explicitly finite metadata account for a component fixture.
///
/// Callers create this once at fixture setup, before constructors or output
/// copies, and keep it until those owners close. It models metadata admission
/// only and cannot substitute for a real native resource owner.
///
/// # Errors
/// Refuses a zero allowance or failure to admit the original account.
pub fn fixture_decode_scope(
    maximum_bytes: u64,
) -> Result<FixtureDecodeScope, DecodeAdmissionError> {
    let used = Arc::new(AtomicU64::new(0));
    let budget = DecodeBudget::new(
        Arc::new(FixtureAuthority {
            used: Arc::clone(&used),
            maximum: maximum_bytes,
        }),
        maximum_bytes,
    )?;
    Ok(FixtureDecodeScope {
        _scope: budget.enter(),
        budget,
        used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn finite_fixture_preserves_original_refusal() -> Result<(), DecodeAdmissionError> {
        let scope = fixture_decode_scope(256)?;

        assert!(crate::owned_decode::charge_bytes(1024).is_err());
        assert!(scope.check().is_err());
        assert!(scope.retained_bytes() <= 256);
        assert!(fixture_decode_scope(0).is_err());
        Ok(())
    }

    #[test]
    fn evaluator_retains_original_credit_after_fixture_scope_closes() -> Result<(), Box<dyn Error>>
    {
        let scope = fixture_decode_scope(4096)?;
        let used = Arc::clone(&scope.used);
        let evaluator = crate::HostAssertionEvaluator::new(&crate::Properties::empty())?;
        scope.check()?;

        drop(scope);
        assert!(used.load(Ordering::SeqCst) > 0);

        drop(evaluator);
        assert_eq!(used.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
