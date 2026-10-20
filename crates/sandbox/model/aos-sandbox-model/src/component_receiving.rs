//! Portable monotone accounting of dominant receiving obligations.
//!
//! The ledger owns only checked resource DATA. Any caller may construct a
//! numeric ceiling; that creates no service original, process, descriptor,
//! grant, receiving lifetime or permission to allocate. Privileged consumers
//! must bind the same mutable ledger to their own independently established
//! original and admit each obligation before the corresponding growth.
//!
//! Accepted obligations remain charged after local disposal. The first whole
//! failed reservation stays borrowed, so later requests cannot reset usage,
//! replace the refusal or manufacture credit from observed resident memory.

use crate::{AccountingError, ResourceAccount, ResourceCeilings, ResourceVector};

/// Computes a complete owner's monotonic bound and only its positive growth.
///
/// The returned DATA does not establish an original, reserve the difference,
/// retire a resident object, or forgive earlier native/arithmetic failure.
/// The actual owner's ledger must accept the growth before its high water is
/// updated or any corresponding allocation/effect begins.
///
/// # Errors
///
/// Propagates Core's checked component-subtraction refusal.
pub fn complete_bound_delta_v1(
    previous: ResourceVector,
    requirement: ResourceVector,
) -> Result<(ResourceVector, ResourceVector), AccountingError> {
    let high_water = previous.componentwise_max(requirement);
    Ok((high_water, high_water.checked_sub(previous)?))
}

/// Projects cumulative operation traffic from a complete requirement.
///
/// Network, diagnostics, publication staging and returned output remain spent
/// across positive native disposal. The other dimensions describe reusable
/// resident/concurrency capacity. This pure DATA projection neither pays nor
/// authenticates an operation; the genuine original must retain its debit.
#[must_use]
pub fn operation_traffic_demand_v1(demand: ResourceVector) -> ResourceVector {
    let mut traffic = ResourceVector::ZERO;
    for dimension in crate::ResourceDimension::ALL {
        if is_operation_traffic_v1(dimension) {
            traffic = traffic.with(dimension, demand.get(dimension));
        }
    }
    traffic
}

/// Projects reusable capacity without refunding cumulative operation traffic.
///
/// The result is requirement DATA only. It does not establish positive native
/// disposal, release a reservation, reset a ledger or authorize another flight.
#[must_use]
pub fn without_operation_traffic_v1(mut demand: ResourceVector) -> ResourceVector {
    for dimension in crate::ResourceDimension::ALL {
        if is_operation_traffic_v1(dimension) {
            demand = demand.with(dimension, 0);
        }
    }
    demand
}

fn is_operation_traffic_v1(dimension: crate::ResourceDimension) -> bool {
    use crate::ResourceDimension as D;
    matches!(dimension, D::NetworkBytes | D::LogBytes | D::PublicationStagingBytes | D::OutputBytes)
}

/// Keeps charged obligations and the first whole rejected reservation.
///
/// Dominant retained capacities stay charged even if they are not resident or
/// a local handle is dropped. A native memory observation cannot add credit.
/// There is deliberately no release, refresh, resize, unlimited or reset path.
pub struct ComponentServiceReceivingLedgerV1 {
    ceiling: ResourceVector,
    account: ResourceAccount,
    reservation: Option<Result<ResourceAccount, AccountingError>>,
}

impl ComponentServiceReceivingLedgerV1 {
    /// Initializes accounting DATA with an explicit numeric ceiling.
    pub const fn new(ceiling: ResourceVector) -> Self {
        Self {
            ceiling,
            account: ResourceAccount::new(ResourceCeilings::bounded(ceiling)),
            reservation: None,
        }
    }

    /// Charges one additional shape before the corresponding allocation/effect.
    ///
    /// The role-specific original retains its own native objects and complete
    /// phase Results beside this ledger. Copying a Core account DATA value here
    /// never copies those originals or constructs another spending interval.
    ///
    /// # Errors
    /// Borrows the original arithmetic/ceiling refusal; later calls cannot
    /// replace that error, mutate usage, or heal it with a smaller request.
    pub fn reserve(&mut self, demand: ResourceVector) -> Result<(), &AccountingError> {
        if !matches!(self.reservation, Some(Err(_))) {
            let reservation = self.account.reserve(demand);
            if let Ok(account) = &reservation {
                self.account = *account;
            }
            self.reservation = Some(reservation);
        }
        match &self.reservation {
            Some(Err(error)) => Err(error),
            _ => Ok(()),
        }
    }

    /// Borrows the first refused reservation without releasing its predecessors.
    pub fn failure(&self) -> Option<&AccountingError> {
        self.reservation.as_ref().and_then(|result| result.as_ref().err())
    }

    /// Returns charged logical obligations as nonauthorizing comparison DATA.
    pub const fn charged(&self) -> ResourceVector {
        self.account.reserved()
    }

    /// Returns unpromised capacity DATA for a private original's shape planner.
    ///
    /// This calculation creates no new reservation or lifetime. Refused owners
    /// remain closed even when this numeric difference is positive.
    ///
    /// # Errors
    /// Refuses arithmetic inconsistent with the existing Core account invariant.
    pub fn remaining(&self) -> Result<ResourceVector, AccountingError> {
        self.ceiling.checked_sub(self.charged())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResourceDimension as D;

    #[test]
    fn traffic_and_reusable_planes_preserve_every_complete_dimension() {
        let demand = D::ALL.into_iter().enumerate().fold(ResourceVector::ZERO,
            |demand, (index, dimension)| demand.with(dimension, index as u64 + 1));

        let traffic = operation_traffic_demand_v1(demand);
        let reusable = without_operation_traffic_v1(demand);

        assert_eq!(traffic.checked_add(reusable).unwrap(), demand);
        assert_eq!(traffic.get(D::NetworkBytes), demand.get(D::NetworkBytes));
        assert_eq!(traffic.get(D::LogBytes), demand.get(D::LogBytes));
        assert_eq!(traffic.get(D::PublicationStagingBytes), demand.get(D::PublicationStagingBytes));
        assert_eq!(traffic.get(D::OutputBytes), demand.get(D::OutputBytes));
        assert_eq!(traffic.get(D::MemoryBytes), 0);
        assert_eq!(traffic.get(D::OpenFiles), 0);
        assert_eq!(reusable.get(D::MemoryBytes), demand.get(D::MemoryBytes));
        assert_eq!(reusable.get(D::OpenFiles), demand.get(D::OpenFiles));
    }

    #[test]
    fn actual_obligations_stay_charged_and_a_failed_later_shape_is_atomic() {
        let ceiling = ResourceVector::ZERO.with(D::MemoryBytes, 64).with(D::OpenFiles, 4);
        let first = ResourceVector::ZERO.with(D::MemoryBytes, 32).with(D::OpenFiles, 2);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(ceiling);
        ledger.reserve(first).unwrap();

        let refused = ResourceVector::ZERO.with(D::MemoryBytes, 16).with(D::OpenFiles, 3);
        assert!(matches!(ledger.reserve(refused), Err(AccountingError::LimitExceeded {
            dimension: D::OpenFiles, limit: 4, attempted: 5,
        })));

        assert_eq!(ledger.charged(), first);
        assert_eq!(ledger.remaining().unwrap(), ceiling.checked_sub(first).unwrap());
    }

    #[test]
    fn a_smaller_later_request_cannot_replace_the_actual_first_cause() {
        let mut ledger = ComponentServiceReceivingLedgerV1::new(
            ResourceVector::ZERO.with(D::MemoryBytes, 1),
        );
        assert!(ledger.reserve(ResourceVector::ZERO.with(D::MemoryBytes, 2)).is_err());
        let original = ledger.failure().unwrap() as *const AccountingError;

        assert!(ledger.reserve(ResourceVector::ZERO).is_err());

        assert_eq!(ledger.failure().unwrap() as *const AccountingError, original);
        assert_eq!(ledger.charged(), ResourceVector::ZERO);
    }

    #[test]
    fn overflow_preserves_prior_charge_and_is_not_wrapped_into_spare_capacity() {
        let mut ledger = ComponentServiceReceivingLedgerV1::new(
            ResourceVector::ZERO.with(D::MetadataEntries, u64::MAX),
        );
        let full = ResourceVector::ZERO.with(D::MetadataEntries, u64::MAX);
        ledger.reserve(full).unwrap();

        assert!(matches!(ledger.reserve(ResourceVector::ZERO.with(D::MetadataEntries, 1)),
            Err(AccountingError::ArithmeticOverflow { dimension: D::MetadataEntries })));

        assert_eq!(ledger.charged(), full);
        assert!(ledger.reserve(ResourceVector::ZERO).is_err());
    }
}
