//! Debits an independently admitted suffix window without issuing an action.
//!
//! This fixed ledger is DATA. A live caller still needs the same selected boot,
//! published first observation, Source/Core issuer and current Control witness.
//! Debits precede allocations, never refund and poison interrupted work.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Idle,
    Ingress,
    Action,
    Failed,
}

/// Tracks original slots and persistent demand independently on both axes.
pub(crate) struct OriginalRestoredSuffixBudget {
    admitted: PacketRestoredSuffixReservationData,
    originals: u64,
    ingress_retained: u64,
    action_retained: u64,
    stage: Stage,
}

impl OriginalRestoredSuffixBudget {
    /// Initializes only a numeric ledger; matching DATA is not a native permit.
    pub(crate) fn new_data(
        admitted: PacketRestoredSuffixReservationData,
    ) -> Result<Self, ProviderError> {
        admitted.requested_bytes_data()?;
        Ok(Self {
            admitted,
            originals: 0,
            ingress_retained: 0,
            action_retained: 0,
            stage: Stage::Idle,
        })
    }

    /// Spends the next original and its full ingress debit before a read.
    pub(crate) fn begin_ingress_data(
        &mut self,
        actual: PacketNativeStartupAllocationRow,
    ) -> Result<u64, ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Idle || self.originals >= self.admitted.maximum_originals.get() {
            return Err(invalid());
        }
        let retained = debit(self.admitted.ingress, self.ingress_retained, actual)?;
        let ordinal = self.originals.checked_add(1).ok_or_else(invalid)?;
        self.originals = ordinal;
        self.ingress_retained = retained;
        self.stage = Stage::Ingress;
        Ok(ordinal)
    }

    /// Checks a fixed prospective visitor before walking actual action fields.
    ///
    /// This ingress-only negative bound does not spend or issue an action. The
    /// genuine caller must still independently quote and debit all three axes.
    ///
    /// # Errors
    /// Refuses another ledger phase or fixed scratch above the actual native
    /// action reservation; no unrelated phase lends its counter credit.
    pub(crate) fn authenticate_action_counter_scratch_data(
        &self,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        if self.stage != Stage::Ingress
            || u64::try_from(scratch).map_err(|_| invalid())?
                > self.admitted.actions.declared_counter_scratch_bytes.get()
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Spends current proof and callback work before any effect or allocation.
    pub(crate) fn begin_action_data(
        &mut self,
        actual: PacketNativeStartupAllocationRow,
    ) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Ingress {
            return Err(invalid());
        }
        self.action_retained = debit(self.admitted.actions, self.action_retained, actual)?;
        self.stage = Stage::Action;
        Ok(())
    }

    /// Reopens the numeric ledger after the caller authenticates publication.
    ///
    /// This helper alone grants no native dispatch or Source completion. Only
    /// the owning live route may call it after retaining and checking the same
    /// actual original, terminal, current proof and complete sent prefix.
    pub(crate) fn complete_publication_data(&mut self) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Action {
            return Err(invalid());
        }
        self.stage = Stage::Idle;
        Ok(())
    }

    /// Keeps a failed read, callback, error response or unwind permanently spent.
    pub(crate) fn interrupt_data(&mut self) {
        self.stage = Stage::Failed;
    }
}

fn debit(
    admitted: PacketNativeStartupAllocationRow,
    used: u64,
    actual: PacketNativeStartupAllocationRow,
) -> Result<u64, ProviderError> {
    admitted.authenticate_actual_data(&actual)?;
    let retained = used
        .checked_add(actual.retained_requested_bytes.get())
        .ok_or_else(invalid)?;
    if retained > admitted.retained_requested_bytes.get() {
        return Err(invalid());
    }
    Ok(retained)
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<Stage>() * 2
        + size_of::<&mut OriginalRestoredSuffixBudget>()
        + size_of::<PacketNativeStartupAllocationRow>() * 3
        + size_of::<Option<u64>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(retained: u64, transient: u64, scratch: u64) -> PacketNativeStartupAllocationRow {
        PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(retained),
            maximum_simultaneous_transient_bytes: U64::new(transient),
            declared_counter_scratch_bytes: U64::new(scratch),
        }
    }

    fn budget(count: u64, ingress: u64, actions: u64) -> OriginalRestoredSuffixBudget {
        OriginalRestoredSuffixBudget::new_data(PacketRestoredSuffixReservationData {
            maximum_originals: U64::new(count),
            ingress: row(ingress, 20, 30),
            actions: row(actions, 40, 50),
        })
        .unwrap()
    }

    #[test]
    fn fixed_counter_preflight_never_spends_or_advances_the_actual_ledger() {
        let mut ledger = budget(1, 10, 10);
        assert!(ledger.authenticate_action_counter_scratch_data(50).is_err());
        ledger.begin_ingress_data(row(10, 20, 30)).unwrap();
        ledger.authenticate_action_counter_scratch_data(50).unwrap();
        assert!(ledger.authenticate_action_counter_scratch_data(51).is_err());
        assert_eq!(ledger.originals, 1);
        assert_eq!(ledger.ingress_retained, 10);
        assert_eq!(ledger.action_retained, 0);
        assert_eq!(ledger.stage, Stage::Ingress);
        ledger.begin_action_data(row(10, 40, 50)).unwrap();
        assert!(ledger.authenticate_action_counter_scratch_data(50).is_err());
        ledger.complete_publication_data().unwrap();
        assert!(ledger.authenticate_action_counter_scratch_data(50).is_err());
        assert_eq!(ledger.action_retained, 10);
    }

    #[test]
    fn each_actual_axis_is_checked_before_a_numeric_action_can_start() {
        for changed in [row(11, 20, 30), row(10, 21, 30), row(10, 20, 31)] {
            let mut ledger = budget(1, 10, 10);
            assert!(ledger.begin_ingress_data(changed).is_err());
            assert_eq!(ledger.originals, 0);
            assert_eq!(ledger.ingress_retained, 0);
            assert!(ledger.begin_ingress_data(row(10, 20, 30)).is_err());
        }
        for changed in [row(11, 40, 50), row(10, 41, 50), row(10, 40, 51)] {
            let mut ledger = budget(1, 10, 10);
            ledger.begin_ingress_data(row(10, 20, 30)).unwrap();
            assert!(ledger.begin_action_data(changed).is_err());
            assert_eq!(ledger.action_retained, 0);
            assert!(ledger.complete_publication_data().is_err());
        }
    }

    #[test]
    fn completed_and_failed_attempts_never_refund_retained_or_original_debits() {
        let mut exact = budget(2, 20, 20);
        for ordinal in 1..=2 {
            assert_eq!(exact.begin_ingress_data(row(10, 20, 30)).unwrap(), ordinal);
            exact.begin_action_data(row(10, 40, 50)).unwrap();
            exact.complete_publication_data().unwrap();
        }
        assert_eq!(exact.ingress_retained, 20);
        assert_eq!(exact.action_retained, 20);
        assert!(exact.begin_ingress_data(row(1, 1, 1)).is_err());

        let mut short = budget(2, 19, 20);
        short.begin_ingress_data(row(10, 20, 30)).unwrap();
        short.begin_action_data(row(10, 40, 50)).unwrap();
        short.complete_publication_data().unwrap();
        assert!(short.begin_ingress_data(row(10, 20, 30)).is_err());
        assert_eq!(short.ingress_retained, 10);
        assert_eq!(short.action_retained, 10);
        assert!(short.begin_ingress_data(row(1, 1, 1)).is_err());
    }

    #[test]
    fn interrupted_and_reentered_work_stays_spent_without_a_fake_completion() {
        let mut ledger = budget(3, 30, 30);
        ledger.begin_ingress_data(row(10, 20, 30)).unwrap();
        ledger.interrupt_data();
        assert!(ledger.begin_action_data(row(10, 40, 50)).is_err());
        assert!(ledger.begin_ingress_data(row(10, 20, 30)).is_err());

        let mut reentered = budget(3, 30, 30);
        reentered.begin_ingress_data(row(10, 20, 30)).unwrap();
        assert!(reentered.begin_ingress_data(row(10, 20, 30)).is_err());
        assert!(reentered.complete_publication_data().is_err());
        assert_eq!(reentered.originals, 1);
    }
}

#[path = "budget/settled.rs"]
mod settled;
