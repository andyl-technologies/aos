//! Projects the same lower Root financial refusal at upper semantic frontiers.
//!
//! The actual S/F/N sums, envelope check and failed financial operation belong
//! to the existing Broker original. Domain retains only its own typed error
//! projections; it neither owns a parallel ledger nor lends whole U to Journal.

use aos_sandbox_core::ResourceVector;

use super::{ResourceReservationErrorV1, RootReceivingOriginalV1};

impl RootReceivingOriginalV1 {
    /// Retains the same permanent denial fence without holding a lower lock.
    pub(crate) fn native_refusal_original_v1(
        &self,
    ) -> aos_sandbox_broker::receiving::RootUpperRefusalOriginalV1 {
        self.activation.upper_refusal_original_v1()
    }

    /// Lends only the healthy permanent financial owner of this receiver.
    ///
    /// # Errors
    /// Refuses an earlier upper failure or incomplete native handoff.
    pub(crate) fn native_journal_financial_original_v1(
        &self,
    ) -> Result<
        aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
        aos_sandbox_broker::receiving::RootFinancialClosedV1,
    > {
        if self.failure().is_some() {
            self.native_refusal_original_v1().refuse_v1();
            return Err(aos_sandbox_broker::receiving::RootFinancialClosedV1);
        }
        self.activation.journal_financial_original_v1()
    }

    /// Ends the original native lifetime before any upper field is released.
    pub(crate) fn end_native_journal_lifetime_v1(&self) {
        self.activation.end_serving_journal_lifetime_v1();
    }

    /// Checks cumulative stage demand against the complete original liability.
    ///
    /// # Errors
    /// Retains the actual lower prerequisite, overflow or exhaustion cause.
    pub(super) fn require_receiving_demand_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        self.activation
            .require_receiving_demand_v1(demand)
            .map_err(|_| self.retain_financial_refusal_v1())
    }

    /// Charges native representation on this same Root partition.
    ///
    /// # Errors
    /// Retains an earlier failure, overflow or complete-liability refusal.
    pub(crate) fn debit_native_journal_representation_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        self.activation
            .debit_native_representation_v1(demand)
            .map_err(|_| self.retain_financial_refusal_v1())
    }

    /// Charges finite observer traffic without resetting retained native debt.
    ///
    /// # Errors
    /// Refuses resident dimensions, earlier failure, overflow or exhaustion.
    pub(crate) fn debit_observer_traffic_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        self.activation
            .debit_observer_traffic_v1(demand)
            .map_err(|_| self.retain_financial_refusal_v1())
    }

    /// Borrows the lower financial cause before the upper retained projection.
    pub(crate) fn native_receiving_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.activation.financial_failure_v1().or_else(|| {
            self.native_receiving_refusal
                .as_ref()
                .map(|cause| cause.as_ref() as &(dyn std::error::Error + 'static))
        })
    }

    fn retain_financial_refusal_v1(&mut self) -> ResourceReservationErrorV1 {
        let returned = self.financial_refusal_projection_v1();
        if self.native_receiving_refusal.is_none() {
            let retained = self.financial_refusal_projection_v1();
            self.native_receiving_refusal = Some(std::sync::Arc::new(retained));
        }
        // The exact lower arithmetic/operation and this upper projection are
        // resident before any shared native entry can observe refusal.
        self.activation.latch_root_refusal_v1();
        returned
    }

    fn financial_refusal_projection_v1(&self) -> ResourceReservationErrorV1 {
        self.activation
            .financial_diagnostic_original_v1()
            .map(ResourceReservationErrorV1::RootReceiving)
            .unwrap_or(ResourceReservationErrorV1::EnrollmentUnavailable)
    }
}
