//! Finite portable resource loans for physical-quota component fixtures.
//!
//! These counters model an independently authored descriptor and resident
//! entitlement. A loan retains its original account until the last clone closes;
//! it makes no claim about kernel quotas, native memory or process accounting.

use std::sync::{Arc, Mutex};

use super::StoreError;

/// Owns exact finite credit counters for one portable component fixture.
pub(crate) struct FixtureResourceBudget {
    maximum_descriptors: u64,
    maximum_resident_bytes: u64,
    usage: Arc<Mutex<ResourceUsage>>,
}

#[derive(Default)]
struct ResourceUsage {
    descriptors: u64,
    resident_bytes: u64,
}

impl FixtureResourceBudget {
    /// Records independently authored descriptor and resident ceilings.
    pub(crate) fn new(maximum_descriptors: u64, maximum_resident_bytes: u64) -> Self {
        Self {
            maximum_descriptors,
            maximum_resident_bytes,
            usage: Arc::new(Mutex::new(ResourceUsage::default())),
        }
    }

    /// Reserves one clone-shared loan without changing usage on refusal.
    ///
    /// # Errors
    /// Refuses empty loans, exhausted ceilings, overflow or poisoned accounting.
    pub(crate) fn reserve(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        if descriptors == 0 && resident_bytes == 0 {
            return Err(StoreError::Quota);
        }
        let mut usage = self.usage.lock().map_err(|_| StoreError::Quota)?;
        let next_descriptors = usage
            .descriptors
            .checked_add(descriptors)
            .filter(|next| *next <= self.maximum_descriptors)
            .ok_or(StoreError::Quota)?;
        let next_resident = usage
            .resident_bytes
            .checked_add(resident_bytes)
            .filter(|next| *next <= self.maximum_resident_bytes)
            .ok_or(StoreError::Quota)?;

        usage.descriptors = next_descriptors;
        usage.resident_bytes = next_resident;
        Ok(crate::owned_decode::ResourceLoan::new(
            FixtureResourceLoan {
                usage: Arc::clone(&self.usage),
                descriptors,
                resident_bytes,
            },
        ))
    }

    /// Returns currently retained component credits for lifetime assertions.
    pub(crate) fn usage(&self) -> Result<(u64, u64), StoreError> {
        let usage = self.usage.lock().map_err(|_| StoreError::Quota)?;
        Ok((usage.descriptors, usage.resident_bytes))
    }
}

struct FixtureResourceLoan {
    usage: Arc<Mutex<ResourceUsage>>,
    descriptors: u64,
    resident_bytes: u64,
}

impl Drop for FixtureResourceLoan {
    fn drop(&mut self) {
        let Ok(mut usage) = self.usage.lock() else {
            return;
        };
        let (Some(descriptors), Some(resident_bytes)) = (
            usage.descriptors.checked_sub(self.descriptors),
            usage.resident_bytes.checked_sub(self.resident_bytes),
        ) else {
            return;
        };
        usage.descriptors = descriptors;
        usage.resident_bytes = resident_bytes;
    }
}

#[test]
fn finite_fixture_loans_refuse_excess_and_retain_until_last_clone() -> Result<(), StoreError> {
    let budget = FixtureResourceBudget::new(2, 4096);
    assert!(matches!(budget.reserve(0, 0), Err(StoreError::Quota)));
    let loan = budget.reserve(2, 4096)?;
    let retained = loan.clone();
    assert!(matches!(budget.reserve(1, 0), Err(StoreError::Quota)));
    assert!(matches!(budget.reserve(0, 1), Err(StoreError::Quota)));
    assert!(matches!(
        budget.reserve(u64::MAX, 1),
        Err(StoreError::Quota)
    ));

    drop(loan);
    assert!(matches!(budget.reserve(1, 0), Err(StoreError::Quota)));
    drop(retained);
    let restored = budget.reserve(2, 4096)?;
    drop(restored);
    Ok(())
}
