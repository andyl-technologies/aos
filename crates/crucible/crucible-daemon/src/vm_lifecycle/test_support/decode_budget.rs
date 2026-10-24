//! Finite decode-only component accounting retained by backend codec tests.

use crucible_engine::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

struct Authority {
    used: Arc<AtomicU64>,
    maximum: u64,
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

fn authority(maximum: u64) -> Arc<Authority> {
    Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        maximum,
    })
}

/// Returns the original finite fixture authority's retained-byte counter.
///
/// # Errors
/// Refuses the fixture's finite original allocation admission.
pub(crate) fn fixture_budget_with_counter()
-> Result<(DecodeBudget, Arc<AtomicU64>), DecodeAdmissionError> {
    let owner = authority(1024 * 1024);
    let budget = DecodeBudget::new(owner.clone(), owner.maximum)?;
    Ok((budget, owner.used.clone()))
}
