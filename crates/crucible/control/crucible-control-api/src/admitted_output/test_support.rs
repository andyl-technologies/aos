//! Finite original decode accounts for cross-crate control component fixtures.

use crucible_engine::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct Authority {
    pub(super) used: Arc<AtomicU64>,
    pub(super) maximum: u64,
}

struct Credit {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.used.load(Ordering::SeqCst) > self.maximum {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(
        &self,
        bytes: u64,
    ) -> Result<crucible_store::owned_decode::ResourceLoan, DecodeAdmissionError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("finite output allowance"))
            })?;
        Ok(crucible_store::owned_decode::ResourceLoan::new(Credit {
            used: self.used.clone(),
            bytes,
        }))
    }
}

pub(super) fn authority(maximum: u64) -> Arc<Authority> {
    Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        maximum,
    })
}

/// Supplies the exact retained-byte counter of a finite fixture account.
///
/// # Errors
/// Refuses an invalid or unenforceable original fixture bound.
pub fn tracked_fixture_budget(
    maximum: u64,
) -> Result<(DecodeBudget, Arc<AtomicU64>), DecodeAdmissionError> {
    let authority = authority(maximum);
    let used = Arc::clone(&authority.used);
    Ok((DecodeBudget::new(authority, maximum)?, used))
}

/// Supplies a finite original account for API output component fixtures.
///
/// # Errors
/// Refuses the fixture's finite original allocation admission.
pub fn fixture_budget() -> Result<DecodeBudget, DecodeAdmissionError> {
    Ok(fixture_budget_with_counter()?.0)
}

/// Returns the original finite fixture authority's retained-byte counter.
///
/// # Errors
/// Refuses the fixture's finite original allocation admission.
pub fn fixture_budget_with_counter() -> Result<(DecodeBudget, Arc<AtomicU64>), DecodeAdmissionError>
{
    let owner = authority(1024 * 1024);
    let budget = DecodeBudget::new(owner.clone(), owner.maximum)?;
    Ok((budget, owner.used.clone()))
}

/// Supplies the existing finite account used by control integration fixtures.
///
/// The account retains the same 64 MiB component allowance. It establishes no
/// native process, filesystem, quota, or placement authority.
///
/// # Panics
/// Panics if the finite fixture account cannot be constructed or installed.
pub fn integration_budget() -> DecodeBudget {
    let scope = crucible_engine::test_support::fixture_decode_scope(64 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite API fixture metadata: {error}"));
    let budget = crucible_engine::owned_decode::current_budget()
        .unwrap_or_else(|| panic!("fixture must install its authored metadata account"));
    drop(scope);
    budget
}
