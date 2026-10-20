//! Keeps the existing Publisher startup reservation inside the same C owner.
//!
//! Scope values are canonical passive Protocol DATA. Actual Publisher native
//! producers, Runtime sequencing and service custody stay with their owners.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use super::ControllerReceivingErrorV1;

const PROPERTY_BYTES: usize = 64 * 1024;
const ENVIRONMENT_BYTES: usize = 131_072;

pub(super) fn validate_scope(scope: aos_sandbox_protocol::publisher_session::PublisherSessionScope)
    -> Result<(), aos_sandbox_protocol::publisher_session::InvalidPublisherSessionScopeV1>
{
    scope.validate_v1()
}

/// Describes the actual protected Publisher credential selected by Runtime.
///
/// These identity DATA authorize no growth or service. Only the genuine
/// opening can construct a receiving original and join its admitted profile.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ControllerPublisherStartupDataV1 {
    /// Actual protected principal/node/project/cache binding.
    pub scope: aos_sandbox_protocol::publisher_session::PublisherSessionScope,
    /// Actual protected service user identifier.
    pub uid: u32,
    /// Actual protected service group identifier.
    pub gid: u32,
}

/// Keeps one private permanently charged capacity in the original C owner.
pub(super) struct PublisherOperationReservationV1 {
    capacity: Option<Result<ResourceVector, ControllerReceivingErrorV1>>,
    funding: Option<Result<(), ControllerReceivingErrorV1>>,
    claimed: bool,
    active: bool,
    closed: bool,
}

impl PublisherOperationReservationV1 {
    pub(super) const fn new() -> Self {
        Self {
            capacity: None,
            funding: None,
            claimed: false,
            active: false,
            closed: false,
        }
    }

    pub(super) fn claim_startup_capacity(
        &mut self,
        prepaid: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.claimed || self.closed {
            self.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.claimed = true;

        self.capacity = Some(operation_demand());
        if matches!(self.capacity, Some(Err(_))) {
            self.closed = true;
            // Move the SAME actual refusal to the receiving destination. The
            // original stays closed; no failed capacity is reconstructed.
            let cause = self.capacity.take()
                .and_then(Result::err)
                .ok_or(ControllerReceivingErrorV1::Conflict)?;
            return Err(cause);
        }
        self.funding = Some(match self.capacity.as_ref() {
            Some(Ok(capacity)) => prepaid.checked_sub(*capacity)
                .map(|_| ()).map_err(Into::into),
            _ => Err(ControllerReceivingErrorV1::EnrollmentUnavailable),
        });
        if !matches!(self.funding, Some(Ok(()))) {
            self.closed = true;
            // The permanent startup pool stays charged. This actual arithmetic
            // refusal moves to the prearmed joined receiver without retry.
            let cause = self.funding.take()
                .and_then(Result::err)
                .ok_or(ControllerReceivingErrorV1::Conflict)?;
            return Err(cause);
        }
        Ok(())
    }

    pub(super) fn begin(&mut self) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        if self.closed || self.active || !self.claimed || !matches!(self.funding, Some(Ok(()))) {
            self.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let capacity = self.capacity.as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        self.active = true;
        Ok(capacity)
    }

    pub(super) fn require_active(&self) -> Result<(), ControllerReceivingErrorV1> {
        if self.closed || !self.active || !self.claimed
            || !matches!(self.funding, Some(Ok(())))
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.closed || !self.active {
            self.closed = true;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.active = false;
        Ok(())
    }

    pub(super) fn close(&mut self) {
        self.closed = true;
    }
}

pub(in crate::controller_receiving) fn operation_demand() -> Result<ResourceVector, ControllerReceivingErrorV1> {
    let unavailable = || ControllerReceivingErrorV1::EnrollmentUnavailable;
    let observer = super::profile::fixed_property_observer_demand_v1(PROPERTY_BYTES)
        .map_err(|_| unavailable())?;
    let shared_files = observer.get(D::OpenFiles).checked_sub(5).ok_or_else(unavailable)?;
    // Actual live main driver is paid once by Runtime. Both native snapshots
    // run on that SAME Handle; no second reactor or property worker is built.
    let shared = observer.with(D::OpenFiles, shared_files).with(D::Pids, 0);
    let mut demand = shared.checked_add(shared).map_err(|_| unavailable())?;
    let membership = aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::
        dominant_requested_bytes_v1().ok_or_else(unavailable)?;
    // The stored actual native flight and its construction temporary use the
    // compiled shared type. Scalar/control fields are byte carriers, not
    // resident namespace entries. The two membership buffers coexist.
    let native_memory = membership.checked_mul(2)
        .and_then(|bytes| bytes.checked_add(
            2 * std::mem::size_of::<crate::fixed_service_identity::ServiceIdentityFlightV1>(),
        ))
        .and_then(|bytes| bytes.checked_add(2 * ENVIRONMENT_BYTES))
        .ok_or_else(unavailable)?;
    demand = demand.checked_add(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(native_memory).map_err(|_| unavailable())?)
        .with(D::OpenFiles, 6 + 1 + 2 * 2)
        .with(D::ConcurrentOperations, 1)).map_err(|_| unavailable())?;
    // Four actual original-profile property rows surround this operation.
    // Their resident scope capacity is already paid by SelectedProfile; traffic
    // belongs to THIS consumed flight, independently of permanent high waters.
    for dimension in [D::NetworkBytes, D::LogBytes, D::OutputBytes] {
        let bookends = observer.get(dimension).checked_mul(4).ok_or_else(unavailable)?;
        demand = demand.checked_add(ResourceVector::ZERO.with(dimension, bookends))
            .map_err(|_| unavailable())?;
    }
    Ok(demand)
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::budget::{BaselineDemand, BaselineOwner};

    #[test]
    fn publisher_flight_prices_auth_all_profile_traffic_and_one_exclusive_slot() {
        let observer = super::super::profile::fixed_property_observer_demand_v1(PROPERTY_BYTES).unwrap();
        let required = operation_demand().unwrap();

        for dimension in [D::NetworkBytes, D::LogBytes, D::OutputBytes] {
            assert_eq!(required.get(dimension), observer.get(dimension) * 6);
        }
        assert_eq!(required.get(D::OpenFiles), 2 * (7 - 5) + 6 + 1 + 2 * 2);
        assert_eq!(required.get(D::Pids), 0);
        assert_eq!(required.get(D::CpuMicrosPerPeriod), 0);
        assert_eq!(required.get(D::ConcurrentOperations), 1);
        assert!(required.get(D::MemoryBytes) >= (2 * ENVIRONMENT_BYTES) as u64);
    }

    #[test]
    fn insufficient_prepaid_capacity_moves_the_whole_error_and_stays_closed() {
        let mut original = PublisherOperationReservationV1::new();
        let refused = original.claim_startup_capacity(ResourceVector::ZERO);
        let first = std::ptr::from_ref(refused.as_ref().unwrap_err());

        assert!(original.claim_startup_capacity(ResourceVector::ZERO).is_err());
        assert!(original.begin().is_err());

        assert_eq!(first, std::ptr::from_ref(refused.as_ref().unwrap_err()));
        assert!(matches!(refused, Err(ControllerReceivingErrorV1::Accounting(_))));
        assert!(original.closed);
        assert!(!original.active);
    }

    #[test]
    fn an_overlapping_operation_closes_the_actual_reserved_slot() {
        let required = operation_demand().unwrap();
        let mut original = PublisherOperationReservationV1::new();
        original.claim_startup_capacity(required).unwrap();
        assert_eq!(original.begin().unwrap(), required);

        assert!(original.begin().is_err());

        assert!(original.closed);
        assert!(original.finish().is_err());
        assert!(original.begin().is_err());
    }

    #[test]
    fn finishing_a_financial_phase_never_refunds_its_permanent_reservation() {
        let required = operation_demand().unwrap();
        let mut ledger = BaselineDemand::new();
        ledger.begin().unwrap();
        ledger.raise(BaselineOwner::SelectedProfile, required, required).unwrap();
        let mut original = PublisherOperationReservationV1::new();
        original.claim_startup_capacity(required).unwrap();
        original.begin().unwrap();
        // This tests only private financial DATA. Actual Native consumers can
        // call finish only after their full posts and real sample disposal.
        original.finish().unwrap();
        assert_eq!(original.begin().unwrap(), required);
        ledger.begin().unwrap();

        let extra = ledger.raise(BaselineOwner::ControllerNative,
            ResourceVector::ZERO.with(D::MemoryBytes, 1), required);

        assert!(extra.is_err());
        assert!(ledger.is_closed());
        assert!(original.active);
    }
}
