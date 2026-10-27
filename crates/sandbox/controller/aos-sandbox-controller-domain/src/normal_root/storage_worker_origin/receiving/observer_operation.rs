//! Exclusive recurring PID1 operations on the actual Storage receiving original.
//!
//! A finite operation capacity stays permanently charged beside all resident
//! debts in the original ledger. Each non-copyable loan consumes a distinct
//! full-shape flight. Only actual positive native, join, end and binding posts,
//! followed by disposal of that same sample, permit another operation. This is
//! neither a lifetime traffic counter nor a release/reset of resident charges.

use super::*;
use super::currentness::CurrentObservation;
use crate::controller_resource_reservation::component_receiving::ComponentReceivingOperationV1;

pub(super) fn independent_local_post_demand_v1() -> Result<ResourceVector, aos_sandbox_model::AccountingError> {
    let local = ReceivingContainmentCurrentnessV1::fixed_demand();
    local.checked_add(local)
        .and_then(|demand| demand.checked_add(local))
        .and_then(|demand| demand.checked_add(local))
        .map(|demand| demand.with(D::Pids, 1))
}

/// Owns one fixed recurring observer reservoir on the actual service original.
///
/// All constructors and admission methods are private to receiving. A numeric
/// vector cannot construct this owner or a service/operation loan.
pub(super) struct StorageObserverOperationOriginalV1 {
    capacity: Option<Result<ResourceVector, StorageReceivingClosedV1>>,
    reservation: Option<Result<(), StorageReceivingClosedV1>>,
    flight: Option<ComponentReceivingOperationV1>,
    sample: Option<CurrentObservation>,
    closed: bool,
    prepared: bool,
    repeated_fixed_names: bool,
}

impl StorageObserverOperationOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            capacity: None,
            reservation: None,
            flight: None,
            sample: None,
            closed: false,
            prepared: false,
            repeated_fixed_names: false,
        }
    }

    pub(super) const fn with_repeated_fixed_names_v1() -> Self {
        let mut original = Self::new();
        original.repeated_fixed_names = true;
        original
    }

    fn actual_demand_v1(&self) -> Result<ResourceVector, StorageReceivingClosedV1> {
        Self::demand().map(|demand| {
            if self.repeated_fixed_names { demand.with(D::MetadataEntries, 0) } else { demand }
        })
    }

    fn demand() -> Result<ResourceVector, StorageReceivingClosedV1> {
        let observer = service::fixed_property_observer_demand_v1(PROPERTY_BYTES)
            .map_err(|_| StorageReceivingClosedV1)?;
        let local = CurrentObservation::demand()?;
        // CPU is the already installed aggregate cgroup rate, not another
        // additive CPU reservation for the same service. The initial original
        // separately retains its process/control/CPU containment. This distinct
        // exclusive observer operation contributes one concurrency slot; the
        // original startup and current resident shapes contribute zero slots.
        observer.checked_add(local)
            .map(|demand| demand.with(D::ConcurrentOperations, 1))
            .map_err(|_| StorageReceivingClosedV1)
    }

    fn reserve_once(&mut self, ledger: &mut ComponentServiceReceivingLedgerV1)
        -> Result<(), StorageReceivingClosedV1>
    {
        if self.capacity.is_none() {
            self.capacity = Some(self.actual_demand_v1());
        }
        let Some(Ok(capacity)) = self.capacity.as_ref() else {
            self.closed = true;
            return Err(StorageReceivingClosedV1);
        };
        if self.reservation.is_none() {
            // The existing same ledger retains its whole arithmetic refusal.
            // No independent Core account or copied spending interval exists.
            self.reservation = Some(ledger.reserve(*capacity)
                .map_err(|_| StorageReceivingClosedV1));
        }
        if !matches!(self.reservation, Some(Ok(()))) {
            self.closed = true;
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    pub(super) fn observe(
        &mut self,
        ledger: &mut ComponentServiceReceivingLedgerV1,
        lifetime: &ObserverLifetime,
        custody: &StartupCustody,
        component: &StorageComponentEnvelopeOriginalV1,
        initial: &(StorageWorkerParentDataV3, [u8; 16]),
        limits: &ReceivingContainmentReadbackV1,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.prepare_once_v1(ledger, lifetime)?;
        self.observe_prepared_once_v1(lifetime, custody, component, initial, limits)
    }

    // Arms one already paid operation without issuing native or RPC work.
    // Its original caller retains this pending flight through later failures.
    pub(super) fn prepare_once_v1(
        &mut self,
        ledger: &mut ComponentServiceReceivingLedgerV1,
        lifetime: &ObserverLifetime,
    ) -> Result<(), StorageReceivingClosedV1> {
        if self.closed || self.prepared || !lifetime.is_open() {
            self.closed = true;
            return Err(StorageReceivingClosedV1);
        }
        self.reserve_once(ledger)?;

        if let Some(previous) = self.flight.as_ref() {
            if previous.is_closed() || !previous.is_positive()
                || !self.sample.as_ref().is_some_and(CurrentObservation::can_dispose)
            {
                self.closed = true;
                return Err(StorageReceivingClosedV1);
            }
            // The sample includes actual Joined/Ended/native results and the
            // completed same-original pair/control posts. Dispose THAT sample
            // before closing its operation and creating another loan. No
            // failed observation, uncertainty or unused currency is refunded.
            drop(self.sample.take());
            drop(self.flight.take());
        }
        let Some(Ok(capacity)) = self.capacity.as_ref() else {
            self.closed = true;
            return Err(StorageReceivingClosedV1);
        };
        let required = match self.actual_demand_v1() {
            Ok(required) => required,
            Err(_) => {
                self.closed = true;
                return Err(StorageReceivingClosedV1);
            }
        };
        self.flight = Some(ComponentReceivingOperationV1::preflight(*capacity, required));
        if self.flight.as_ref().and_then(ComponentReceivingOperationV1::failure).is_some() {
            self.closed = true;
            return Err(StorageReceivingClosedV1);
        }
        self.prepared = true;
        Ok(())
    }

    pub(super) fn observe_prepared_once_v1(
        &mut self,
        lifetime: &ObserverLifetime,
        custody: &StartupCustody,
        component: &StorageComponentEnvelopeOriginalV1,
        initial: &(StorageWorkerParentDataV3, [u8; 16]),
        limits: &ReceivingContainmentReadbackV1,
    ) -> Result<(), StorageReceivingClosedV1> {
        if self.closed || !self.prepared || !lifetime.is_open() {
            self.closed = true;
            return Err(StorageReceivingClosedV1);
        }
        self.prepared = false;
        let Some(flight) = self.flight.as_mut() else {
            self.closed = true;
            return Err(StorageReceivingClosedV1);
        };
        let mut operation = flight.borrow_once().map_err(|_| StorageReceivingClosedV1)?;
        self.sample = Some(CurrentObservation::new(lifetime.clone()));
        let Some(sample) = self.sample.as_mut() else {
            self.closed = true;
            return Err(StorageReceivingClosedV1);
        };
        sample.observe(custody, component, initial, limits, &mut operation);
        if !sample.can_dispose() {
            self.closed = true;
            return Err(StorageReceivingClosedV1);
        }
        operation.finish_positive_observation();
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(error)) = &self.capacity {
            return Some(error);
        }
        if let Some(Err(error)) = &self.reservation {
            return Some(error);
        }
        if let Some(flight) = &self.flight {
            if let Some(error) = flight.failure() {
                return Some(error);
            }
        }
        self.sample.as_ref().and_then(CurrentObservation::failure)
            .or_else(|| self.closed.then_some(&StorageReceivingClosedV1 as &dyn Error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepaid_pending_observer_flight_survives_later_ledger_refusal() {
        let capacity = StorageObserverOperationOriginalV1::demand().unwrap();
        let mut ledger = ComponentServiceReceivingLedgerV1::new(capacity);
        let lifetime = ObserverLifetime::begin();
        let mut original = StorageObserverOperationOriginalV1::new();

        original.prepare_once_v1(&mut ledger, &lifetime).unwrap();
        assert!(original.prepared);
        assert!(original.sample.is_none());
        assert!(!original.flight.as_ref().unwrap().was_consumed());
        assert!(ledger.reserve(ResourceVector::ZERO.with(D::MemoryBytes, 1)).is_err());
        let first = ledger.failure().unwrap() as *const aos_sandbox_model::AccountingError;

        // Only the existing actual flight is still available. This fixture
        // exercises accounting continuity, not a manufactured native sample.
        let mut operation = original.flight.as_mut().unwrap().borrow_once().unwrap();
        operation.consume_flight_once().unwrap();
        assert_eq!(first, ledger.failure().unwrap() as *const aos_sandbox_model::AccountingError);
        drop(operation);
        assert!(original.flight.as_ref().unwrap().is_closed());
        assert!(original.sample.is_none());
    }

    #[test]
    fn distinct_prearmed_output_post_keeps_its_paid_flight_after_primary_refusal() {
        let action_capacity = StorageObserverOperationOriginalV1::demand().unwrap();
        let mut after = StorageObserverOperationOriginalV1::with_repeated_fixed_names_v1();
        let after_capacity = after.actual_demand_v1().unwrap();
        assert_eq!(after_capacity.with(D::MetadataEntries, action_capacity.get(D::MetadataEntries)), action_capacity);

        let mut ledger = ComponentServiceReceivingLedgerV1::new(action_capacity.checked_add(after_capacity).unwrap());
        let lifetime = ObserverLifetime::begin();
        let mut action = StorageObserverOperationOriginalV1::new();
        action.prepare_once_v1(&mut ledger, &lifetime).unwrap();
        after.prepare_once_v1(&mut ledger, &lifetime).unwrap();
        assert!(action.prepared && after.prepared);

        assert!(ledger.reserve(ResourceVector::ZERO.with(D::MemoryBytes, 1)).is_err());
        let first = ledger.failure().unwrap() as *const aos_sandbox_model::AccountingError;
        // The final flight is its own noncopy paid original. Primary account
        // poison cannot replace it with a healthy reentry or prevent its debt
        // from being consumed by the already armed independent post.
        let mut owed = after.flight.as_mut().unwrap().borrow_once().unwrap();
        owed.consume_flight_once().unwrap();
        assert_eq!(first, ledger.failure().unwrap() as *const aos_sandbox_model::AccountingError);
        assert!(!action.flight.as_ref().unwrap().was_consumed());
        drop(owed);
        assert!(after.flight.as_ref().unwrap().was_consumed());
    }

    #[test]
    fn refused_operation_capacity_keeps_the_same_original_accounting_error() {
        let mut ledger = ComponentServiceReceivingLedgerV1::new(ResourceVector::ZERO);
        let mut original = StorageObserverOperationOriginalV1::new();

        assert!(original.reserve_once(&mut ledger).is_err());
        let first = ledger.failure().unwrap() as *const aos_sandbox_model::AccountingError;
        assert!(original.reserve_once(&mut ledger).is_err());

        assert_eq!(first, ledger.failure().unwrap() as *const aos_sandbox_model::AccountingError);
        assert_eq!(ledger.charged(), ResourceVector::ZERO);
        assert!(original.closed);
        assert!(original.sample.is_none());
        assert!(original.flight.is_none());
    }

    #[test]
    fn actual_shared_observer_shape_includes_auth_and_one_exclusive_operation() {
        use aos_systemd_client::ControllerPropertyObserverAttemptV1 as Observer;

        let demand = StorageObserverOperationOriginalV1::demand().unwrap();
        let framed = Observer::MESSAGE_BYTES
            * (Observer::INCOMING_MESSAGES + Observer::OUTGOING_MESSAGES);
        let auth = 2 * Observer::AUTH_BYTES;

        assert_eq!(demand.get(D::NetworkBytes), (framed + auth) as u64);
        assert!(demand.get(D::OutputBytes) > 0);
        assert!(demand.get(D::LogBytes) > 0);
        assert_eq!(demand.get(D::ConcurrentOperations), 1);
        assert_eq!(demand.get(D::CpuMicrosPerPeriod), 0);
    }

    #[test]
    fn financial_capacity_coexists_with_resident_debt_on_the_same_ledger() {
        let resident = ResourceVector::ZERO.with(D::MemoryBytes, 64);
        let operation = ResourceVector::ZERO.with(D::MemoryBytes, 32)
            .with(D::NetworkBytes, 8192).with(D::ConcurrentOperations, 1);
        let capacity = resident.checked_add(operation).unwrap();
        let mut ledger = ComponentServiceReceivingLedgerV1::new(capacity);
        ledger.reserve(resident).unwrap();

        ledger.reserve(operation).unwrap();

        assert_eq!(ledger.charged(), capacity);
        assert_eq!(ledger.remaining().unwrap(), ResourceVector::ZERO);
        // No positive native disposal path mutates this permanent accounting.
        assert!(ledger.reserve(ResourceVector::ZERO.with(D::NetworkBytes, 1)).is_err());
        assert_eq!(ledger.charged(), capacity);
    }
}
