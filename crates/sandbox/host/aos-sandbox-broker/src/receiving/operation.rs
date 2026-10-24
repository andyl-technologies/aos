//! Shares inert full-vector once-consumption and unfinished-loan closure.
//!
//! Actual original owners permanently reserve their finite operation capacity
//! on the same ledger before constructing a flight. This private arithmetic
//! owns no ledger, payer, original, native sample or service authority. Each
//! role alone checks its native/currentness/Joined/Ended results and disposes
//! that SAME sample before it may construct a later operation.

use aos_sandbox_model::{AccountingError, ResourceVector};

/// Holds whole arithmetic outcomes without granting any operation authority.
///
/// The genuine role separately reserves its capacity on its original ledger.
/// Constructing or completing this DATA cannot substitute for that reservation.
pub struct ComponentReceivingOperationV1 {
    preflight: Result<ResourceVector, AccountingError>,
    consumption: Option<Result<ResourceVector, AccountingError>>,
    required: ResourceVector,
    capacity: ResourceVector,
    positive: bool,
    closed: bool,
}

/// Borrows one inert flight until its real owner finishes all positive posts.
///
/// This non-Copy loan cannot construct an original or reserve capacity.
pub struct ComponentReceivingOperationLoanV1<'operation> {
    flight: &'operation mut ComponentReceivingOperationV1,
    finished: bool,
}

/// Reports that an arithmetic flight is refused, repeated or incomplete.
#[derive(Debug, thiserror::Error)]
#[error("component receiving operation is closed")]
pub struct ComponentReceivingOperationClosedV1;

impl ComponentReceivingOperationV1 {
    /// Constructs comparison arithmetic without reserving any resource.
    ///
    /// Neither vector comes from or becomes an original, budget or role loan.
    pub fn preflight(capacity: ResourceVector, required: ResourceVector) -> Self {
        Self {
            preflight: capacity.checked_sub(required),
            consumption: None,
            required,
            capacity,
            positive: false,
            closed: false,
        }
    }

    /// Borrows this once-consumption arithmetic until its caller disposition.
    ///
    /// # Errors
    /// Refuses failed preflight, consumed, positive or permanently closed state.
    pub fn borrow_once(
        &mut self,
    ) -> Result<ComponentReceivingOperationLoanV1<'_>, ComponentReceivingOperationClosedV1> {
        if self.closed || self.positive || self.consumption.is_some() || self.preflight.is_err() {
            self.closed = true;
            return Err(ComponentReceivingOperationClosedV1);
        }
        Ok(ComponentReceivingOperationLoanV1 { flight: self, finished: false })
    }

    fn consume_once(&mut self) -> Result<(), ComponentReceivingOperationClosedV1> {
        if self.closed || self.positive || self.consumption.is_some() || self.preflight.is_err() {
            self.closed = true;
            return Err(ComponentReceivingOperationClosedV1);
        }
        self.consumption = Some(self.capacity.checked_sub(self.required));
        if !matches!(self.consumption, Some(Ok(_))) {
            self.closed = true;
            return Err(ComponentReceivingOperationClosedV1);
        }
        Ok(())
    }

    fn finish_positive(&mut self) -> bool {
        if !self.closed && matches!(self.consumption, Some(Ok(_))) {
            self.positive = true;
            true
        } else {
            self.closed = true;
            false
        }
    }

    /// Borrows the original arithmetic refusal without copying or replacing it.
    pub fn failure(&self) -> Option<&AccountingError> {
        self.preflight.as_ref().err()
            .or_else(|| self.consumption.as_ref().and_then(|result| result.as_ref().err()))
    }

    /// Reports arithmetic completion without asserting native or role success.
    pub const fn is_positive(&self) -> bool {
        self.positive
    }

    /// Reports whether this arithmetic slot has permanently closed.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Reports successful once-consumption of the whole comparison vector.
    pub fn was_consumed(&self) -> bool {
        matches!(self.consumption, Some(Ok(_)))
    }
}

impl ComponentReceivingOperationLoanV1<'_> {
    /// Consumes the actual complete arithmetic vector once.
    ///
    /// # Errors
    /// Refuses reentry, failed preflight or closed/positive arithmetic state.
    pub fn consume_flight_once(&mut self) -> Result<(), ComponentReceivingOperationClosedV1> {
        self.flight.consume_once()
    }

    /// Finishes only this arithmetic observation after caller disposition.
    ///
    /// This creates no native disposal proof, resource refund, service phase
    /// transition or original. A real role independently owns and checks its
    /// native posts and disposes its carriers before reusing paid capacity.
    pub fn finish_positive_observation(mut self) {
        self.finished = self.flight.finish_positive();
    }
}

impl Drop for ComponentReceivingOperationLoanV1<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.flight.closed = true;
        }
    }
}

/// Owns the same inert operation engine across separately borrowed role stages.
///
/// A genuine role original retains this value through native work and posts.
/// No borrowed self-reference, ledger copy or second transition engine exists.
pub struct ComponentReceivingOwnedOperationV1 {
    operation: ComponentReceivingOperationV1,
}

impl ComponentReceivingOwnedOperationV1 {
    /// Constructs comparison arithmetic without reserving any resource.
    ///
    /// Neither vector comes from or becomes an original, budget or role loan.
    pub fn preflight(capacity: ResourceVector, required: ResourceVector) -> Self {
        Self { operation: ComponentReceivingOperationV1::preflight(capacity, required) }
    }

    /// Consumes the same shared arithmetic engine through an owning wrapper.
    ///
    /// # Errors
    /// Refuses failed preflight, repeated consumption or closed/positive state.
    pub fn consume_once(&mut self) -> Result<(), ComponentReceivingOperationClosedV1> {
        self.operation.consume_once()
    }

    /// Borrows the original arithmetic refusal without copying or replacing it.
    pub fn failure(&self) -> Option<&AccountingError> {
        self.operation.failure()
    }

    /// Reports consumed, unfinished arithmetic without asserting currentness.
    pub fn is_consumed_current(&self) -> bool {
        self.operation.was_consumed() && !self.operation.closed && !self.operation.positive
    }

    // The actual role's positive continuation invokes this only AFTER its own
    // complete native posts and actual upper carrier disposal. It performs no
    // IO, allocation, accounting reservation or new authority decision.
    /// Consumes completed arithmetic after the caller's independent disposal.
    ///
    /// The method checks no native proof, reserves no account and advances no
    /// role phase. Actual callers retain their own genuine gates. It aborts
    /// the process if the arithmetic was not successfully consumed.
    pub fn complete_after_disposal(mut self) {
        if !self.operation.finish_positive() {
            std::process::abort();
        }
    }
}

impl Drop for ComponentReceivingOwnedOperationV1 {
    fn drop(&mut self) {
        if !self.operation.positive {
            self.operation.closed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::ResourceDimension as D;

    #[test]
    fn every_operation_dimension_is_preflighted_before_a_loan_exists() {
        for dimension in D::ALL {
            let mut operation = ComponentReceivingOperationV1::preflight(
                ResourceVector::ZERO,
                ResourceVector::ZERO.with(dimension, 1),
            );

            assert!(operation.borrow_once().is_err());

            assert!(!operation.was_consumed());
            assert!(operation.is_closed());
            assert!(matches!(operation.failure(), Some(AccountingError::InsufficientAmount {
                dimension: actual, available: 0, requested: 1,
            }) if *actual == dimension));
        }
    }

    #[test]
    fn a_dropped_or_double_spent_operation_cannot_lend_again() {
        let capacity = ResourceVector::ZERO.with(D::NetworkBytes, 8192)
            .with(D::OutputBytes, 4096).with(D::ConcurrentOperations, 1);
        let mut operation = ComponentReceivingOperationV1::preflight(capacity, capacity);
        {
            let mut loan = operation.borrow_once().unwrap();
            loan.consume_flight_once().unwrap();
            assert!(loan.consume_flight_once().is_err());
        }

        assert!(operation.is_closed());
        assert!(operation.borrow_once().is_err());
        assert!(!operation.is_positive());
    }

    #[test]
    fn unfinished_borrow_permanently_closes_the_actual_slot() {
        let capacity = ResourceVector::ZERO.with(D::NetworkBytes, 8192);
        let mut operation = ComponentReceivingOperationV1::preflight(capacity, capacity);

        drop(operation.borrow_once().unwrap());

        assert!(operation.is_closed());
        assert!(!operation.was_consumed());
        assert!(operation.borrow_once().is_err());
    }

    #[test]
    fn positive_phase_requires_consumption_and_never_lends_a_second_flight() {
        let capacity = ResourceVector::ZERO.with(D::NetworkBytes, 8192);
        let mut unconsumed = ComponentReceivingOperationV1::preflight(capacity, capacity);
        unconsumed.borrow_once().unwrap().finish_positive_observation();
        assert!(!unconsumed.is_positive());
        assert!(unconsumed.is_closed());

        let mut consumed = ComponentReceivingOperationV1::preflight(capacity, capacity);
        let mut loan = consumed.borrow_once().unwrap();
        loan.consume_flight_once().unwrap();
        loan.finish_positive_observation();

        assert!(consumed.is_positive());
        assert!(consumed.was_consumed());
        assert!(consumed.borrow_once().is_err());
    }

    #[test]
    fn refused_reentry_keeps_the_same_original_full_vector_error() {
        let mut operation = ComponentReceivingOperationV1::preflight(
            ResourceVector::ZERO, ResourceVector::ZERO.with(D::MetadataEntries, 1),
        );
        let first = std::ptr::from_ref(operation.failure().unwrap());

        assert!(operation.borrow_once().is_err());
        assert!(operation.borrow_once().is_err());

        assert_eq!(first, std::ptr::from_ref(operation.failure().unwrap()));
        assert!(!operation.was_consumed());
    }

    #[test]
    fn consuming_a_flight_does_not_mutate_or_refund_its_original_reservation() {
        use aos_sandbox_model::component_receiving::ComponentServiceReceivingLedgerV1;

        let mut capacity = ResourceVector::ZERO;
        for dimension in D::ALL {
            capacity = capacity.with(dimension, 8);
        }
        let mut ledger = ComponentServiceReceivingLedgerV1::new(capacity);
        ledger.reserve(capacity).unwrap();
        let mut operation = ComponentReceivingOperationV1::preflight(capacity, capacity);
        let mut loan = operation.borrow_once().unwrap();

        loan.consume_flight_once().unwrap();
        loan.finish_positive_observation();

        assert_eq!(ledger.charged(), capacity);
        assert_eq!(ledger.remaining().unwrap(), ResourceVector::ZERO);
        assert!(operation.is_positive());
        assert!(ledger.reserve(ResourceVector::ZERO.with(D::NetworkBytes, 1)).is_err());
        assert_eq!(ledger.charged(), capacity);
    }

    #[test]
    fn owned_and_borrowed_flights_share_full_vector_refusal_and_once_consumption() {
        for dimension in D::ALL {
            let required = ResourceVector::ZERO.with(dimension, 1);
            let mut owned = ComponentReceivingOwnedOperationV1::preflight(ResourceVector::ZERO, required);
            let first = std::ptr::from_ref(owned.failure().unwrap());

            assert!(owned.consume_once().is_err());
            assert!(owned.consume_once().is_err());

            assert_eq!(first, std::ptr::from_ref(owned.failure().unwrap()));
            assert!(!owned.is_consumed_current());
            assert!(!owned.operation.was_consumed());
        }
        let capacity = ResourceVector::ZERO.with(D::NetworkBytes, 8192)
            .with(D::OutputBytes, 4096).with(D::ConcurrentOperations, 1);
        let mut owned = ComponentReceivingOwnedOperationV1::preflight(capacity, capacity);

        owned.consume_once().unwrap();
        assert!(owned.is_consumed_current());
        assert!(owned.consume_once().is_err());
        assert!(!owned.is_consumed_current());
    }

    #[test]
    fn owned_positive_disposal_does_not_refund_the_original_ledger() {
        use aos_sandbox_model::component_receiving::ComponentServiceReceivingLedgerV1;
        let capacity = ResourceVector::ZERO.with(D::NetworkBytes, 8192)
            .with(D::ConcurrentOperations, 1);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(capacity);
        ledger.reserve(capacity).unwrap();
        let mut operation = ComponentReceivingOwnedOperationV1::preflight(capacity, capacity);

        operation.consume_once().unwrap();
        operation.complete_after_disposal();

        assert_eq!(ledger.charged(), capacity);
        assert_eq!(ledger.remaining().unwrap(), ResourceVector::ZERO);
    }

}
