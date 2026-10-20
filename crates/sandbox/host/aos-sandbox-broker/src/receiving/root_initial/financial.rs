//! Retains the original Root representation sums and transient financial flight.
//!
//! Initial moves this custody once into its existing permanent allocation.
//! Every serving mutation takes the native invocation fence before the sums
//! mutex. Upper intervals and shared fees additionally retain the same unit
//! exclusion mutex. Stable errors live outside the sums mutex so a diagnostic
//! never lends a reference through a dropped guard. No amount constructs this
//! owner.

use std::error::Error;
use std::sync::{Arc, Mutex, OnceLock};

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};

use super::super::root_permanent::RootPermanentNativeOriginalV1;
use super::super::{ComponentReceivingOwnedOperationV1, RootCoordinatorWriterV1};

mod exclusion;

pub use exclusion::RootUpperMutationGuardV1;

#[cfg(test)]
mod tests;

/// Reports refusal of the same original Root financial custody.
///
/// The actual prerequisite or arithmetic cause remains on that original;
/// this return marker neither owns a budget nor replaces the retained cause.
#[derive(Debug, thiserror::Error)]
#[error("original Root financial custody is closed")]
pub struct RootFinancialClosedV1;

#[derive(Debug, thiserror::Error)]
enum RootFinancialErrorV1 {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error("original Root financial prerequisite is closed")]
    Prerequisite,
    #[error("original Root financial sum custody is poisoned")]
    PoisonedSums,
    #[error("resident dimension {0} cannot enter the observer traffic debit")]
    ResidentTraffic(D),
}

struct RootFinancialFlightV1 {
    operation: Option<ComponentReceivingOwnedOperationV1>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FlightPhaseV1 {
    Idle,
    Entered,
    Disposing,
}

struct RootFinancialFailureV1 {
    cause: RootFinancialErrorV1,
    // A failed consumption retains its actual arithmetic engine, not merely
    // the projected closed marker. There can be no later financial flight.
    flight: Option<RootFinancialFlightV1>,
}

impl RootFinancialFailureV1 {
    fn cause(&self) -> &(dyn Error + 'static) {
        self.flight
            .as_ref()
            .and_then(|flight| flight.operation.as_ref())
            .and_then(ComponentReceivingOwnedOperationV1::failure)
            .map(|cause| cause as &(dyn Error + 'static))
            .unwrap_or(&self.cause)
    }
}

struct RootFinancialStateV1 {
    receiving_high_water: ResourceVector,
    flight_capacity: ResourceVector,
    native_debt: ResourceVector,
    flight: Option<RootFinancialFlightV1>,
    // This phase survives taking the positive flight into its consuming tail.
    // An empty Option is never sufficient to admit the next operation.
    flight_phase: FlightPhaseV1,
}

/// Owns the sole sums and first immutable financial failure inside Root.
pub(in crate::receiving) struct RootFinancialCustodyV1 {
    upper_mutation: Mutex<()>,
    state: Mutex<RootFinancialStateV1>,
    failure: OnceLock<RootFinancialFailureV1>,
}

enum MutationV1 {
    Stage(ResourceVector),
    Native(ResourceVector),
    Traffic(ResourceVector),
    BeginFlight(ResourceVector),
}

impl RootFinancialCustodyV1 {
    pub(in crate::receiving) fn new() -> Self {
        Self {
            upper_mutation: Mutex::new(()),
            state: Mutex::new(RootFinancialStateV1 {
                receiving_high_water: ResourceVector::ZERO,
                flight_capacity: ResourceVector::ZERO,
                native_debt: ResourceVector::ZERO,
                flight: None,
                flight_phase: FlightPhaseV1::Idle,
            }),
            failure: OnceLock::new(),
        }
    }

    pub(in crate::receiving) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.state.is_poisoned() && self.failure.get().is_none() {
            // The poisoned mutex still physically owns any entered flight.
            // No guard or its lifetime-bearing PoisonError escapes as a cause.
            self.failure.get_or_init(|| RootFinancialFailureV1 {
                cause: RootFinancialErrorV1::PoisonedSums,
                flight: None,
            });
        }
        self.failure.get().map(RootFinancialFailureV1::cause)
    }

    // Only the actual permanent original invokes this before ending its
    // native lifetime. Pure comparison arithmetic has no native Drop duty.
    pub(in crate::receiving) fn abort_if_unfinished_v1(&self) {
        if self.failure.get().is_some() {
            std::process::abort();
        }
        {
            let state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => std::process::abort(),
            };
            if state.flight_phase != FlightPhaseV1::Idle || state.flight.is_some() {
                std::process::abort();
            }
        }
        // M is released before the caller takes the ending N fence. Startup
        // holds its same L/U interval; no upper or physical field drops here.
    }

    fn mutate(
        &self,
        envelope: ResourceVector,
        mutation: MutationV1,
    ) -> Result<(), RootFinancialClosedV1> {
        if self.failure.get().is_some() {
            return Err(RootFinancialClosedV1);
        }
        let mut state = self.state.lock().map_err(|_| {
            self.retain_failure(RootFinancialErrorV1::PoisonedSums, None);
            RootFinancialClosedV1
        })?;
        let result = if state.flight_phase == FlightPhaseV1::Disposing {
            Err(RootFinancialErrorV1::Prerequisite)
        } else {
            match mutation {
                MutationV1::Stage(demand) => {
                    let cumulative = state.receiving_high_water.componentwise_max(demand);
                    require_complete(
                        envelope,
                        cumulative,
                        state.flight_capacity,
                        state.native_debt,
                    )
                    .map(|()| state.receiving_high_water = cumulative)
                }
                MutationV1::Native(demand) => Self::debit(&mut state, envelope, demand),
                MutationV1::Traffic(demand) => {
                    require_traffic(demand).and_then(|()| Self::debit(&mut state, envelope, demand))
                }
                MutationV1::BeginFlight(demand) => Self::begin_flight(&mut state, envelope, demand),
            }
        };
        if let Err(cause) = result {
            // Moving an actual failed operation into immutable custody does
            // not close it positively or release/refund any of the sums.
            let flight = state.flight.take();
            self.retain_failure(cause, flight);
            return Err(RootFinancialClosedV1);
        }
        Ok(())
    }

    fn retain_failure(&self, cause: RootFinancialErrorV1, flight: Option<RootFinancialFlightV1>) {
        let failure = RootFinancialFailureV1 { cause, flight };
        if let Err(failure) = self.failure.set(failure) {
            // Reentry never constructs another flight after first refusal.
            // Reaching two owning failures would otherwise discard custody.
            std::mem::forget(failure);
            std::process::abort();
        }
    }

    fn debit(
        state: &mut RootFinancialStateV1,
        envelope: ResourceVector,
        demand: ResourceVector,
    ) -> Result<(), RootFinancialErrorV1> {
        let debt = state.native_debt.checked_add(demand)?;
        require_complete(
            envelope,
            state.receiving_high_water,
            state.flight_capacity,
            debt,
        )?;
        state.native_debt = debt;
        Ok(())
    }

    fn begin_flight(
        state: &mut RootFinancialStateV1,
        envelope: ResourceVector,
        demand: ResourceVector,
    ) -> Result<(), RootFinancialErrorV1> {
        if state.flight.is_some() || state.flight_phase != FlightPhaseV1::Idle {
            return Err(RootFinancialErrorV1::Prerequisite);
        }
        state.flight = Some(RootFinancialFlightV1 { operation: None });
        state.flight_phase = FlightPhaseV1::Entered;
        let traffic = aos_sandbox_model::component_receiving::operation_traffic_demand_v1(demand);
        let capacity = demand
            .with(D::NetworkBytes, 0)
            .with(D::LogBytes, 0)
            .with(D::PublicationStagingBytes, 0)
            .with(D::OutputBytes, 0);
        let high_water = state.flight_capacity.componentwise_max(capacity);
        require_complete(
            envelope,
            state.receiving_high_water,
            high_water,
            state.native_debt,
        )?;
        state.flight_capacity = high_water;
        Self::debit(state, envelope, traffic)?;
        let flight = state
            .flight
            .as_mut()
            .ok_or(RootFinancialErrorV1::Prerequisite)?;
        flight.operation = Some(ComponentReceivingOwnedOperationV1::preflight(
            high_water, capacity,
        ));
        flight
            .operation
            .as_mut()
            .ok_or(RootFinancialErrorV1::Prerequisite)?
            .consume_once()
            .map_err(|_| RootFinancialErrorV1::Prerequisite)
    }

    fn require_active(&self) -> Result<(), RootFinancialClosedV1> {
        if self.failure.get().is_some() {
            return Err(RootFinancialClosedV1);
        }
        let state = self.state.lock().map_err(|_| RootFinancialClosedV1)?;
        match &state.flight {
            Some(flight)
                if state.flight_phase == FlightPhaseV1::Entered
                    && flight
                        .operation
                        .as_ref()
                        .is_some_and(ComponentReceivingOwnedOperationV1::is_consumed_current) =>
            {
                Ok(())
            }
            _ => Err(RootFinancialClosedV1),
        }
    }
}

fn require_complete(
    envelope: ResourceVector,
    stages: ResourceVector,
    flight: ResourceVector,
    debt: ResourceVector,
) -> Result<(), RootFinancialErrorV1> {
    let complete = stages.checked_add(flight)?.checked_add(debt)?;
    envelope.checked_sub(complete)?;
    Ok(())
}

fn require_traffic(demand: ResourceVector) -> Result<(), RootFinancialErrorV1> {
    for dimension in D::ALL {
        if !matches!(
            dimension,
            D::NetworkBytes | D::LogBytes | D::PublicationStagingBytes | D::OutputBytes
        ) && demand.get(dimension) != 0
        {
            return Err(RootFinancialErrorV1::ResidentTraffic(dimension));
        }
    }
    Ok(())
}

/// Retains financial custody on the same existing permanent native allocation.
///
/// Initial alone lends this handle after its actual one-way serving handoff.
/// A vector, parsed enrollment or provided native file cannot construct it.
pub struct RootJournalFinancialOriginalV1 {
    original: Arc<RootPermanentNativeOriginalV1>,
}

impl Clone for RootJournalFinancialOriginalV1 {
    fn clone(&self) -> Self {
        Self {
            original: Arc::clone(&self.original),
        }
    }
}

impl RootJournalFinancialOriginalV1 {
    // The sealed Q04 origin borrows this same association; it stores no second
    // Permanent Arc beside its already genuine financial original.
    pub(super) fn q04_permanent_v1(&self) -> &Arc<RootPermanentNativeOriginalV1> {
        &self.original
    }

    // Only the closed Q04 native origin calls this entry after actual Initial
    // arming. It reuses the consumed flight and Native term, with no writer or
    // supplied-parts constructor and no native IO under L/N/M.
    pub(super) fn debit_q04_transport_v1(
        &self,
        demand: ResourceVector,
    ) -> Result<(), RootFinancialClosedV1> {
        let _mutation = self.enter_upper_mutation_v1();
        let mut invocation = self
            .original
            .enter_native()
            .map_err(|_| RootFinancialClosedV1)?;
        let result = self.original.financial.require_active().and_then(|()| {
            self.envelope().and_then(|envelope| {
                self.original
                    .financial
                    .mutate(envelope, MutationV1::Native(demand))
            })
        });
        if result.is_err() {
            invocation.refuse();
        }
        result
    }

    /// Requires the writer's intrinsic permanent association without IO.
    ///
    /// # Errors
    /// Refuses another allocation, failed finance or ended/refused invocation.
    pub fn require_writer_v1<P>(
        &self,
        writer: &RootCoordinatorWriterV1<P>,
    ) -> Result<(), RootFinancialClosedV1> {
        let mut invocation = self
            .original
            .enter_native()
            .map_err(|_| RootFinancialClosedV1)?;
        if !writer.same_permanent_original_v1(&self.original) || self.failure_v1().is_some() {
            invocation.refuse();
            return Err(RootFinancialClosedV1);
        }
        Ok(())
    }

    /// Debits the actual writer's representation before its native append.
    ///
    /// # Errors
    /// Refuses a foreign writer, ended/refused invocation, poisoned sums,
    /// earlier financial error, overflow or exhaustion of the original R.
    pub fn debit_v1<P>(
        &self,
        writer: &RootCoordinatorWriterV1<P>,
        demand: ResourceVector,
    ) -> Result<(), RootFinancialClosedV1> {
        let _mutation = self.enter_upper_mutation_v1();
        self.debit_under_upper_exclusion_v1(writer, demand)
    }

    // Shared Journal entry holds L here. The separately sealed credential
    // loan borrows that same guard through its whole-upper factory instead.
    fn debit_under_upper_exclusion_v1<P>(
        &self,
        writer: &RootCoordinatorWriterV1<P>,
        demand: ResourceVector,
    ) -> Result<(), RootFinancialClosedV1> {
        let mut invocation = self
            .original
            .enter_native()
            .map_err(|_| RootFinancialClosedV1)?;
        if !writer.same_permanent_original_v1(&self.original) {
            invocation.refuse();
            return Err(RootFinancialClosedV1);
        }
        let result = self.envelope().and_then(|envelope| {
            self.original
                .financial
                .mutate(envelope, MutationV1::Native(demand))
        });
        if result.is_err() {
            invocation.refuse();
        }
        result
    }

    /// Compares two genuine handles without selecting or opening a writer.
    ///
    /// # Errors
    /// Refuses a different permanent allocation, earlier refusal or ended R.
    pub fn require_same_v1(&self, other: &Self) -> Result<(), RootFinancialClosedV1> {
        let mut invocation = self
            .original
            .enter_native()
            .map_err(|_| RootFinancialClosedV1)?;
        if !Arc::ptr_eq(&self.original, &other.original) || self.failure_v1().is_some() {
            invocation.refuse();
            return Err(RootFinancialClosedV1);
        }
        Ok(())
    }

    /// Compares intrinsic allocation identity without healthy entry or IO.
    ///
    /// This comparison is not currentness or permission to start work. Owed
    /// tails use it only to preserve their existing same-owner association
    /// after refusal; their actual native observation recipe remains required.
    #[must_use]
    pub fn same_original_data_v1(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.original, &other.original)
    }

    /// Borrows the immutable first financial cause on this same allocation.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.original.financial.failure().or_else(|| {
            self.original
                .invocation()
                .failure()
                .map(|cause| cause as &(dyn Error + 'static))
        })
    }

    fn envelope(&self) -> Result<ResourceVector, RootFinancialClosedV1> {
        self.original
            .enrollment()
            .enrollment_v1()
            .and_then(|enrollment| enrollment.policy.bootstrap_provisions().root_receiving)
            .ok_or(RootFinancialClosedV1)
    }
}

impl std::fmt::Debug for RootJournalFinancialOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("RootJournalFinancialOriginalV1")
            .field("failure", &self.failure_v1())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RootJournalFinancialOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure_v1() {
            Some(cause) => std::fmt::Display::fmt(cause, output),
            None => output.write_str("original Root financial custody is closed"),
        }
    }
}

impl Error for RootJournalFinancialOriginalV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.failure_v1()
    }
}

impl RootPermanentNativeOriginalV1 {
    // This closed native entry owns the same L/N/M ordering as the former
    // selected upper recheck. N remains held across its actual native IO;
    // M is released immediately after the existing traffic mutation.
    pub(in crate::receiving) fn recheck_selected_service_once_v1(
        &self,
        startup: &super::super::RootStartupNativeOriginalV1,
    ) -> Result<(), super::super::RootObservationErrorV1> {
        use super::super::RootObservationErrorV1 as Closed;

        let _mutation = self.financial.upper_mutation.lock().map_err(|_| {
            self.invocation().latch_refusal();
            Closed::Service
        })?;
        let mut invocation = self.enter_native()?;
        let checked = (|| {
            if !startup.initial_owner.as_ref().is_some_and(|identity| self.has_identity(identity))
                || self.enrollment().process_id_v1() != std::process::id()
                || self.financial.failure().is_some()
            {
                return Err(Closed::Service);
            }
            self.service.require_worker_idle_v1()?;
            let enrollment = self.enrollment().enrollment_v1().ok_or(Closed::Service)?;
            let envelope = enrollment.policy.bootstrap_provisions().root_receiving
                .ok_or(Closed::Service)?;
            let demand = super::super::root_selected_currentness::service_traffic_demand_v1()
                .ok_or(Closed::Service)?;
            self.financial.mutate(envelope, MutationV1::Traffic(demand))
                .map_err(|_| {
                    self.service.retain_financial_failure_v1();
                    Closed::Service
                })?;
            self.service.observe_prepaid_once_v1(startup, enrollment.recipient_invocation,
                enrollment.identity.native_fields().invocation)
        })();
        if checked.is_err() {
            invocation.refuse();
        }
        checked
    }
}

/// Freezes an actual Initial reborrow through one fixed credential admission.
///
/// The upper entered credential loan retains its complete original and the
/// same exclusion guard while lending this association. Shared Journal entry
/// uses the owned permanent handle instead and never takes the upper lock.
pub struct RootJournalFinancialBorrowV1<'original> {
    unwind: RootUpperRefusalOriginalV1,
    original: &'original super::RootInitialReceivingOriginalV1,
}

impl RootJournalFinancialBorrowV1<'_> {
    /// Requires the same still-healthy actual frozen lower original.
    ///
    /// # Errors
    /// Refuses a changed native lifetime, earlier failure or incomplete handoff.
    pub fn require_current_v1(&self) -> Result<(), RootFinancialClosedV1> {
        if self.original.failure().is_some() {
            self.unwind.refuse_v1();
            return Err(RootFinancialClosedV1);
        }
        let original = self.unwind.original.as_ref().ok_or(RootFinancialClosedV1)?;
        original.require_same_v1(original)
    }

    /// Retains a diagnostic link to the actual frozen credential original.
    #[must_use]
    pub fn diagnostic_original_v1(&self) -> Option<RootJournalFinancialOriginalV1> {
        self.unwind.original.clone()
    }

    /// Debits only the same actual writer under the existing entered borrow.
    ///
    /// # Errors
    /// Preserves the same writer-affinity, invocation and full-liability
    /// refusals as the owned permanent handle.
    pub fn debit_v1<P>(
        &self,
        writer: &RootCoordinatorWriterV1<P>,
        demand: ResourceVector,
    ) -> Result<(), RootFinancialClosedV1> {
        if self.original.failure().is_some() {
            self.unwind.refuse_v1();
            return Err(RootFinancialClosedV1);
        }
        self.unwind
            .original
            .as_ref()
            .ok_or(RootFinancialClosedV1)?
            .debit_under_upper_exclusion_v1(writer, demand)
    }
}

/// Denies shared native entry if its genuine upper mutation unwinds.
///
/// This retains only the existing permanent allocation. It holds no lock and
/// supplies no effect or healthy continuation; inner N/M guards unwind first.
pub struct RootUpperRefusalOriginalV1 {
    original: Option<RootJournalFinancialOriginalV1>,
}

impl RootUpperRefusalOriginalV1 {
    /// Parks an actual upper result and denies new entry atomically with N.
    ///
    /// The destination must be empty: replacing an owning upper value could
    /// run its destructor under N. The generic value is only moved; this method
    /// invokes no callback, decoder, allocation or successful role transition.
    /// An already poisoned/ended invocation is closed before parking proceeds.
    pub fn park_empty_result_v1<T, E>(
        &self,
        slot: &mut Option<Result<T, E>>,
        result: Result<T, E>,
    ) {
        if slot.is_some() {
            std::process::abort();
        }
        let mut parking = self.enter_failure_parking_v1().ok();
        let refused = result.is_err();
        *slot = Some(result);
        if refused {
            if let Some(parking) = &mut parking {
                parking.refuse_v1();
            }
            // No shared handle exists in the pre-handoff None branch. Native
            // startup's original failure/abort gate still protects that owner.
        }
    }

    /// Retains invocation exclusion while an upper owner parks a local result.
    ///
    /// The caller moves its exact result into its original field before using
    /// the returned denial method. No IO or upper owner Drop may occur while
    /// this guard is held; only an empty destination or inert marker is parked.
    ///
    /// # Errors
    /// Refuses ended or poisoned invocation custody. A refused invocation may
    /// still retain diagnostics but can never admit another shared debit.
    pub fn enter_failure_parking_v1(
        &self,
    ) -> Result<RootUpperFailureParkingV1<'_>, RootFinancialClosedV1> {
        let invocation = self
            .original
            .as_ref()
            .map(|original| {
                original
                    .original
                    .enter_observation()
                    .map_err(|_| RootFinancialClosedV1)
            })
            .transpose()?;
        Ok(RootUpperFailureParkingV1 { invocation })
    }

    /// Permanently denies entry after the caller retains its exact body cause.
    pub fn refuse_v1(&self) {
        if let Some(original) = &self.original {
            original.original.invocation().latch_refusal();
        }
    }
}

impl Drop for RootUpperRefusalOriginalV1 {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.refuse_v1();
        }
    }
}

/// Excludes shared entry only across exact upper error parking and denial.
#[must_use]
pub struct RootUpperFailureParkingV1<'original> {
    invocation: Option<super::super::root_invocation::RootNativeInvocationGuardV1<'original>>,
}

impl RootUpperFailureParkingV1<'_> {
    /// Refuses through the already-held N guard after the real cause is parked.
    pub fn refuse_v1(&mut self) {
        if let Some(invocation) = &mut self.invocation {
            invocation.refuse();
        }
    }
}

impl super::RootInitialReceivingOriginalV1 {
    /// Prices the exact lower financial constructors and borrowed carriers.
    ///
    /// Stored inline/mutex/OnceLock bytes are included by the actual Initial
    /// and Permanent Self suppliers. The metadata also names the new stored
    /// fields; the remaining rows are additional move, refusal, guard, demand
    /// and return construction carriers.
    #[must_use]
    pub fn financial_fixed_construction_demand_v1() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<RootFinancialFailureV1>().checked_mul(2)?
            .checked_add(std::mem::size_of::<RootFinancialErrorV1>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<MutationV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<std::sync::MutexGuard<'_, RootFinancialStateV1>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'_, RootFinancialStateV1>>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<RootJournalFinancialOriginalV1>().checked_mul(4)?)?
            .checked_add(std::mem::size_of::<Result<RootJournalFinancialOriginalV1, RootFinancialClosedV1>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<RootJournalFinancialBorrowV1<'_>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<RootJournalFinancialBorrowV1<'_>, RootFinancialClosedV1>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<RootUpperFailureParkingV1<'_>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<RootUpperFailureParkingV1<'_>, RootFinancialClosedV1>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<RootUpperMutationGuardV1<'_>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<RootUpperRefusalOriginalV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<std::sync::MutexGuard<'_, ()>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'_, ()>>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<ResourceVector>().checked_mul(18)?)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(
                    D::MetadataEntries,
                    // Initial and Permanent financial fields, three custody
                    // fields, and five sum/flight fields, each in its actual
                    // construction and retained destination.
                    2 + 2
                        + 3 * 2
                        + 5 * 2
                        + 2
                        + 3
                        + 2
                        + 2
                        + 2
                        + 4
                        + 2
                        + 2
                        + 2
                        + 2
                        + 2
                        + 2
                        + 2
                        + 2
                        + 2
                        + 18,
                ),
        )
    }

    fn financial_custody(&self) -> Option<&RootFinancialCustodyV1> {
        self.financial
            .as_ref()
            .or_else(|| self.permanent.as_ref().map(|original| &original.financial))
    }

    /// Borrows the actual immutable first cause without taking the sums lock.
    #[must_use]
    pub fn financial_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.financial_custody()
            .and_then(RootFinancialCustodyV1::failure)
    }

    /// Retains only a diagnostic link to the same already-existing allocation.
    ///
    /// This also works after refusal so an owning upper error can retain the
    /// actual lower cause. Healthy debit and writer entry still check N.
    #[must_use]
    pub fn financial_diagnostic_original_v1(&self) -> Option<RootJournalFinancialOriginalV1> {
        self.permanent
            .as_ref()
            .map(|original| RootJournalFinancialOriginalV1 {
                original: Arc::clone(original),
            })
    }

    /// Checks a cumulative stage against the same actual complete liability.
    ///
    /// # Errors
    /// Refuses missing or unhealthy original enrollment, earlier refusal,
    /// arithmetic overflow or exhaustion of the same Root R.
    pub fn require_receiving_demand_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), RootFinancialClosedV1> {
        self.mutate_financial(MutationV1::Stage(demand))
    }

    /// Charges one observer's finite traffic without refunding resident peaks.
    ///
    /// # Errors
    /// Refuses resident dimensions, unhealthy originals, overflow or exhaustion.
    pub fn debit_observer_traffic_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), RootFinancialClosedV1> {
        self.mutate_financial(MutationV1::Traffic(demand))
    }

    /// Charges additional representation on this same original partition.
    ///
    /// # Errors
    /// Refuses unhealthy originals, prior refusal, overflow or exhaustion.
    pub fn debit_native_representation_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), RootFinancialClosedV1> {
        self.mutate_financial(MutationV1::Native(demand))
    }

    /// Lends the same completed permanent allocation without another account.
    ///
    /// # Errors
    /// Refuses a missing handoff, failed original or ended native invocation.
    pub fn journal_financial_original_v1(
        &self,
    ) -> Result<RootJournalFinancialOriginalV1, RootFinancialClosedV1> {
        if self.failure().is_some() {
            return Err(RootFinancialClosedV1);
        }
        let original = self.permanent.as_ref().ok_or(RootFinancialClosedV1)?;
        let _invocation = original.enter_native().map_err(|_| RootFinancialClosedV1)?;
        Ok(RootJournalFinancialOriginalV1 {
            original: Arc::clone(original),
        })
    }

    /// Freezes this actual Initial reborrow through one fixed credential call.
    ///
    /// The upper private entered-credential factory borrows its whole original
    /// for this return lifetime before selecting the lower association. The
    /// same lifetime also borrows the actual held exclusion guard. This method
    /// checks native affinity, not a credential policy result.
    ///
    /// # Errors
    /// Refuses incomplete, unhealthy or ended original native custody.
    pub fn borrow_journal_financial_v1<'original>(
        &'original mut self,
        mutation: &'original RootUpperMutationGuardV1<'_>,
    ) -> Result<RootJournalFinancialBorrowV1<'original>, RootFinancialClosedV1> {
        if self.failure().is_some() {
            return Err(RootFinancialClosedV1);
        }
        mutation.require_initial_v1(self)?;
        Ok(RootJournalFinancialBorrowV1 {
            original: self,
            unwind: self.upper_refusal_original_v1(),
        })
    }

    /// Retains the same permanent allocation for an actual upper mutation.
    ///
    /// Before handoff there is no shared lender; the existing Initial abort
    /// and explicit startup-refusal paths protect its exclusively owned state.
    #[must_use]
    pub fn upper_refusal_original_v1(&self) -> RootUpperRefusalOriginalV1 {
        RootUpperRefusalOriginalV1 {
            original: self
                .permanent
                .as_ref()
                .map(|original| RootJournalFinancialOriginalV1 {
                    original: Arc::clone(original),
                }),
        }
    }

    fn mutate_financial(&mut self, mutation: MutationV1) -> Result<(), RootFinancialClosedV1> {
        if self.failure().is_some() {
            self.latch_root_refusal_v1();
            return Err(RootFinancialClosedV1);
        }
        let envelope = self
            .enrollment_v1()
            .filter(|_| matches!(self.root_shape_result_v1(), Some(Ok(()))))
            .and_then(|enrollment| enrollment.policy.bootstrap_provisions().root_receiving);
        let Some(envelope) = envelope else {
            self.latch_root_refusal_v1();
            return Err(RootFinancialClosedV1);
        };
        if let Some(permanent) = &self.permanent {
            // Native exclusion precedes the sum mutex. Refusal uses this
            // already-held guard, never recursively locks the invocation.
            let mut invocation = permanent
                .enter_native()
                .map_err(|_| RootFinancialClosedV1)?;
            let result = permanent.financial.mutate(envelope, mutation);
            if result.is_err() {
                invocation.refuse();
            }
            result
        } else {
            // Before the one-way handoff there is no shared financial lender.
            // The actual Initial is exclusively owned by its startup caller.
            let result = self
                .financial
                .as_ref()
                .ok_or(RootFinancialClosedV1)?
                .mutate(envelope, mutation);
            if result.is_err() {
                self.latch_root_refusal_v1();
            }
            result
        }
    }
}

/// Holds the same native and financial operation through actual upper disposal.
///
/// Abandoning this token aborts before releasing either field. Forgetting it
/// leaves the real financial phase Disposing and the native borrow occupied.
#[must_use]
pub struct RootPolicyFlightDisposalV2<'original> {
    native: Option<super::RootPolicyFlightNativeDisposalV1<'original>>,
    financial: Option<RootPolicyFlightFinancialDisposalV1>,
    completed: bool,
}

/// Retains the financial tail until the genuine upper peer has been dropped.
///
/// Only the combined actual native token returns this owner. The private upper
/// wrapper keeps its original peer and U borrow until this tail is consumed.
#[must_use]
pub struct RootPolicyFlightFinancialDisposalV1 {
    original: RootJournalFinancialOriginalV1,
    completed: bool,
}

impl RootPolicyFlightDisposalV2<'_> {
    /// Retires the actual native pair and retains the still-closed money tail.
    pub fn complete_native_after_disposal_v1(mut self) -> RootPolicyFlightFinancialDisposalV1 {
        let native = match self.native.take() {
            Some(native) => native,
            None => std::process::abort(),
        };
        native.complete_after_disposal_v1();
        let financial = match self.financial.take() {
            Some(financial) => financial,
            None => std::process::abort(),
        };
        self.completed = true;
        financial
    }
}

impl Drop for RootPolicyFlightDisposalV2<'_> {
    fn drop(&mut self) {
        if !self.completed {
            std::process::abort();
        }
    }
}

impl RootPolicyFlightFinancialDisposalV1 {
    /// Finishes this same financial operation after actual upper peer disposal.
    ///
    /// No IO, allocation, new admission or refund occurs. An impossible or
    /// refused custody transition aborts before the remaining fields release.
    pub fn complete_after_disposal_v1(mut self) {
        let mut flight = {
            let _invocation = match self.original.original.enter_native() {
                Ok(invocation) => invocation,
                Err(_) => std::process::abort(),
            };
            let mut state = match self.original.original.financial.state.lock() {
                Ok(state) => state,
                Err(_) => std::process::abort(),
            };
            if self.original.failure_v1().is_some()
                || state.flight_phase != FlightPhaseV1::Disposing
            {
                std::process::abort();
            }
            match state.flight.take() {
                Some(flight) => flight,
                None => std::process::abort(),
            }
        };
        let operation = match flight.operation.take() {
            Some(operation) => operation,
            None => std::process::abort(),
        };
        // No native/financial lock is held across actual owner destruction.
        // The Disposing tombstone survives both the take and positive finish.
        drop(flight);
        operation.complete_after_disposal();
        {
            let _invocation = match self.original.original.enter_native() {
                Ok(invocation) => invocation,
                Err(_) => std::process::abort(),
            };
            let mut state = match self.original.original.financial.state.lock() {
                Ok(state) => state,
                Err(_) => std::process::abort(),
            };
            if self.original.failure_v1().is_some()
                || state.flight_phase != FlightPhaseV1::Disposing
                || state.flight.is_some()
            {
                std::process::abort();
            }
            state.flight_phase = FlightPhaseV1::Idle;
        }
        self.completed = true;
    }
}

impl Drop for RootPolicyFlightFinancialDisposalV1 {
    fn drop(&mut self) {
        if !self.completed {
            std::process::abort();
        }
    }
}

impl super::RootInitialReceivingOriginalV1 {
    /// Prices the actual financial flight and consuming disposal carriers.
    #[must_use]
    pub fn policy_flight_financial_demand_v1() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<RootFinancialFlightV1>()
            .checked_mul(3)?
            .checked_add(std::mem::size_of::<RootFinancialFailureV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<RootPolicyFlightDisposalV2<'_>>().checked_mul(2)?)?
            .checked_add(
                std::mem::size_of::<RootPolicyFlightFinancialDisposalV1>().checked_mul(2)?,
            )?
            .checked_add(
                std::mem::size_of::<Result<RootPolicyFlightDisposalV2<'_>, RootFinancialClosedV1>>(
                )
                .checked_mul(2)?,
            )?
            .checked_add(
                std::mem::size_of::<Result<(), RootFinancialClosedV1>>().checked_mul(3)?,
            )?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::NetworkBytes, 112)
                .with(D::MetadataEntries, 3 + 2 + 2 + 2 + 2 + 3),
        )
    }

    /// Admits and consumes the real financial slot before native sample arming.
    ///
    /// # Errors
    /// Refuses earlier debt/refusal, an occupied slot, incomplete liability,
    /// missing actual enrollment or failed whole-vector once-consumption.
    pub fn begin_policy_flight_finance_once_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), RootFinancialClosedV1> {
        self.mutate_financial(MutationV1::BeginFlight(demand))
    }

    pub(super) fn require_financial_flight_consumed_v1(&self) -> Result<(), RootFinancialClosedV1> {
        let permanent = self.permanent.as_ref().ok_or(RootFinancialClosedV1)?;
        let mut invocation = permanent
            .enter_native()
            .map_err(|_| RootFinancialClosedV1)?;
        let result = permanent.financial.require_active();
        if result.is_err() {
            invocation.refuse();
        }
        result
    }

    /// Requires the same consumed financial slot and actual native primary.
    ///
    /// # Errors
    /// Refuses missing, failed, disposed or ended native/financial ownership.
    pub fn require_active_policy_flight_v1(&self) -> Result<(), RootFinancialClosedV1> {
        let original = self.permanent.as_ref().ok_or(RootFinancialClosedV1)?;
        let mut invocation = original.enter_native().map_err(|_| RootFinancialClosedV1)?;
        let result = original.financial.require_active().and_then(|()| {
            self.require_active_policy_flight_native_v1()
                .map_err(|_| RootFinancialClosedV1)
        });
        if result.is_err() {
            invocation.refuse();
        }
        result
    }

    /// Keeps the genuine positive native pair and consumed financial operation.
    ///
    /// # Errors
    /// Refuses foreign/incomplete native owners, earlier refusal, missing
    /// consumption or repeated preparation. Failed slots remain resident.
    pub fn prepare_policy_flight_disposal_v2(
        &mut self,
        startup: &super::super::RootStartupNativeOriginalV1,
    ) -> Result<RootPolicyFlightDisposalV2<'_>, RootFinancialClosedV1> {
        let financial = self.journal_financial_original_v1()?;
        {
            let mut invocation = financial
                .original
                .enter_native()
                .map_err(|_| RootFinancialClosedV1)?;
            let mut state = financial.original.financial.state.lock().map_err(|_| {
                invocation.refuse();
                RootFinancialClosedV1
            })?;
            let positive = state.flight.as_ref().is_some_and(|flight| {
                flight
                    .operation
                    .as_ref()
                    .is_some_and(ComponentReceivingOwnedOperationV1::is_consumed_current)
            });
            if !positive || state.flight_phase != FlightPhaseV1::Entered {
                invocation.refuse();
                return Err(RootFinancialClosedV1);
            }
            state.flight_phase = FlightPhaseV1::Disposing;
        }
        // No finance guard survives into native validation or upper disposal.
        // Native preparation retains the same positive samplers and startup.
        let native = self
            .prepare_policy_flight_disposal_v1(startup)
            .map_err(|_| RootFinancialClosedV1)?;
        Ok(RootPolicyFlightDisposalV2 {
            native: Some(native),
            financial: Some(RootPolicyFlightFinancialDisposalV1 {
                original: financial,
                completed: false,
            }),
            completed: false,
        })
    }
}
