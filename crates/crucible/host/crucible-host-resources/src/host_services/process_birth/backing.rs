//! Owns the registered operator's original inline backing dimension.
//!
//! The required immutable Whole contract issues this dimension at authenticated
//! startup, before Parent inputs or shared account controls. Ext4 readbacks do
//! not create credit. The same process slot retains every debit through failed
//! close, unwind and physical retirement; this once-only route has no refund.

use std::num::NonZeroU64;

#[derive(Debug)]
pub(super) struct BackingAccount {
    capacity: Option<NonZeroU64>,
    used: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum BackingRefusal {
    Unavailable,
    Exhausted,
}

impl BackingAccount {
    pub(super) fn compiled_original() -> Result<Self, super::ServiceBirthError> {
        let capacity = super::parent_attempt::compiled_backing_capacity()?;
        Ok(Self {
            capacity: capacity.and_then(NonZeroU64::new),
            used: 0,
        })
    }

    #[cfg(test)]
    pub(super) fn mechanism(capacity: u64) -> Self {
        Self {
            capacity: NonZeroU64::new(capacity),
            used: 0,
        }
    }

    pub(super) fn debit(&mut self, bytes: u64) -> Result<NonZeroU64, BackingRefusal> {
        let capacity = self.capacity.ok_or(BackingRefusal::Unavailable)?;
        let debit = NonZeroU64::new(bytes).ok_or(BackingRefusal::Exhausted)?;
        let used = self
            .used
            .checked_add(bytes)
            .filter(|used| *used <= capacity.get())
            .ok_or(BackingRefusal::Exhausted)?;
        self.used = used;
        Ok(debit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_debits_exhaust_without_allocation_or_implicit_refund() {
        let mut account = BackingAccount {
            capacity: NonZeroU64::new(64),
            used: 0,
        };

        let (result, allocations) = crate::test_support::TestAllocationObserver::count(|| {
            let first = account.debit(40)?;
            let second = account.debit(24)?;
            Ok::<_, BackingRefusal>((first, second))
        });

        assert_eq!(
            result.unwrap(),
            (NonZeroU64::new(40).unwrap(), NonZeroU64::new(24).unwrap())
        );
        assert_eq!(allocations.allocations, 0);
        assert_eq!(allocations.reallocations, 0);
        assert!(!allocations.overflow);
        assert_eq!(account.used, 64);
        assert_eq!(account.debit(1), Err(BackingRefusal::Exhausted));
        assert_eq!(account.used, 64);
    }

    #[test]
    fn missing_capacity_zero_and_overflow_never_debit() {
        let mut unavailable = BackingAccount {
            capacity: None,
            used: 0,
        };
        assert_eq!(unavailable.debit(1), Err(BackingRefusal::Unavailable));
        assert_eq!(unavailable.used, 0);

        let mut full = BackingAccount {
            capacity: NonZeroU64::new(u64::MAX),
            used: u64::MAX,
        };
        assert_eq!(full.debit(1), Err(BackingRefusal::Exhausted));
        assert_eq!(full.debit(0), Err(BackingRefusal::Exhausted));
        assert_eq!(full.used, u64::MAX);
    }
}
