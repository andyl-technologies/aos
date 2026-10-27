//! Preserves actual failed-World ownership and independent refusal history.

use super::*;

#[derive(Debug)]
pub(super) struct RetainedClaim {
    owner: PreparedRefusal,
    delivery: Option<ServiceBirthError>,
    receiver: Option<&'static str>,
}

/// Keeps mutually exclusive clean/refused postcuts in their original storage.
///
/// Assignment refusal is factual only after a clean independent postcut. A
/// negative postcut retains its actual cause and cannot acquire that fact.
pub(super) enum RefusalPostcut {
    Clean,
    AssignmentRefused,
    Refused(ServiceBirthError),
}

impl RefusalPostcut {
    pub(super) fn world_attempt(
        after: Option<ServiceBirthError>,
        assignment_refused: bool,
    ) -> Self {
        match after {
            Some(after) => Self::Refused(after),
            None if assignment_refused => Self::AssignmentRefused,
            None => Self::Clean,
        }
    }

    pub(super) fn as_ref(&self) -> Option<&ServiceBirthError> {
        match self {
            Self::Refused(after) => Some(after),
            Self::Clean | Self::AssignmentRefused => None,
        }
    }

    #[cfg(test)]
    pub(super) fn is_none(&self) -> bool {
        self.as_ref().is_none()
    }
}

impl From<Option<ServiceBirthError>> for RefusalPostcut {
    fn from(after: Option<ServiceBirthError>) -> Self {
        Self::world_attempt(after, false)
    }
}

impl std::fmt::Debug for RefusalPostcut {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(formatter)
    }
}

/// Owns the carrier allocated before an issuer can publish a child.
///
/// No Arc or Weak alias escapes. Final header destruction precedes the value's
/// owner and paired metadata destruction, including on a successful attempt.
#[derive(Debug)]
pub(in super::super) struct PreparedRefusal {
    allocation: Option<Arc<RefusalAllocation>>,
}

#[derive(Debug)]
struct RefusalAllocation {
    // The actual child closes before the same Main's carrier charge is refunded.
    owner: Option<RetainedOwner>,
    _metadata: super::super::HostServiceLeasePair,
}

#[derive(Debug)]
enum RetainedOwner {
    Pool {
        _pool: AuthenticatedNativePoolPurpose,
    },
    Source {
        _source: AuthenticatedSourceHostPurpose,
    },
    Dispatcher {
        _dispatcher: super::super::AuthenticatedTargetDispatcherPurpose,
    },
    World(Option<AuthenticatedNativeWorldClaim>),
    Window {
        _window: AuthenticatedNativeNodeHostWindow,
    },
}

impl PreparedRefusal {
    /// Prices both allocation construction overlap and its paired lease controls.
    fn metadata_bytes() -> Result<u64, ServiceBirthError> {
        let (allocation, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<RefusalAllocation>())
        .map_err(|_| ServiceBirthError::policy("native refusal layout overflows"))?;

        u64::try_from(allocation.pad_to_align().size())
            .ok()
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RefusalAllocation>() as u64))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>() as u64))
            .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
            .ok_or_else(|| ServiceBirthError::policy("native refusal extent overflows"))
    }

    /// Admits the complete carrier before child publication or kernel effects.
    pub(in super::super) fn reserve(
        main: &super::super::AuthenticatedNativeSlotPurpose,
    ) -> Result<Self, ServiceBirthError> {
        let metadata = main.owner.reserve_metadata(Self::metadata_bytes()?)?;
        Ok(Self::from_metadata(metadata))
    }

    fn from_metadata(metadata: super::super::HostServiceLeasePair) -> Self {
        Self {
            allocation: Some(Arc::new(RefusalAllocation {
                owner: None,
                _metadata: metadata,
            })),
        }
    }

    fn allocation_mut(&mut self) -> &mut RefusalAllocation {
        match self.allocation.as_mut().and_then(Arc::get_mut) {
            Some(allocation) => allocation,
            None => unreachable!("the private refusal carrier has exactly one owner"),
        }
    }

    fn retain(mut self, owner: RetainedOwner) -> RetainedClaim {
        self.allocation_mut().owner = Some(owner);
        RetainedClaim {
            owner: self,
            delivery: None,
            receiver: None,
        }
    }
}

impl Drop for PreparedRefusal {
    fn drop(&mut self) {
        if let Some(allocation) = self.allocation.take() {
            // No weak or strong aliases can keep an uncharged header alive.
            drop(Arc::into_inner(allocation));
        }
    }
}

impl RetainedClaim {
    pub(super) const fn empty() -> Self {
        Self {
            owner: PreparedRefusal { allocation: None },
            delivery: None,
            receiver: None,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.owner.allocation.is_none() && self.delivery.is_none() && self.receiver.is_none()
    }

    pub(super) fn source(
        source: AuthenticatedSourceHostPurpose,
        prepared: PreparedRefusal,
    ) -> Self {
        prepared.retain(RetainedOwner::Source { _source: source })
    }

    pub(super) fn pool(pool: AuthenticatedNativePoolPurpose, prepared: PreparedRefusal) -> Self {
        prepared.retain(RetainedOwner::Pool { _pool: pool })
    }

    pub(super) fn dispatcher(
        dispatcher: super::super::AuthenticatedTargetDispatcherPurpose,
        prepared: PreparedRefusal,
    ) -> Self {
        prepared.retain(RetainedOwner::Dispatcher {
            _dispatcher: dispatcher,
        })
    }

    pub(super) fn world(world: AuthenticatedNativeWorldClaim, prepared: PreparedRefusal) -> Self {
        prepared.retain(RetainedOwner::World(Some(world)))
    }

    pub(super) fn window(
        window: AuthenticatedNativeNodeHostWindow,
        prepared: PreparedRefusal,
    ) -> Self {
        prepared.retain(RetainedOwner::Window { _window: window })
    }
}

impl NativePoolRefusal {
    /// Moves only the actual committed World retained by this refusal.
    ///
    /// The original first cause and independent postcut remain in this report.
    /// This neither reclaims an assignment nor creates a loan or new authority.
    pub fn take_retained_world(&mut self) -> Option<AuthenticatedNativeWorldClaim> {
        let allocation = self._retained.owner.allocation.as_mut()?;
        match Arc::get_mut(allocation)?.owner.as_mut()? {
            RetainedOwner::World(world) => world.take(),
            _ => None,
        }
    }

    /// Borrows a later failure to deliver this World's genuine cleanup custody.
    #[must_use]
    pub fn world_delivery_error(&self) -> Option<&ServiceBirthError> {
        self._retained.delivery.as_ref()
    }

    /// Retains the first custody-delivery refusal beside the initiating report.
    ///
    /// This changes diagnostics only; it issues no World or cleanup permission.
    pub fn retain_world_delivery_error(&mut self, error: ServiceBirthError) {
        self._retained.delivery.get_or_insert(error);
    }

    /// Borrows the fixed receiving-stage refusal independently of first/post.
    #[must_use]
    pub fn world_receiver_refusal(&self) -> Option<&'static str> {
        self._retained.receiver
    }

    /// Retains the first receiving-stage refusal without allocating a carrier.
    pub fn retain_world_receiver_refusal(&mut self, operation: &'static str) {
        self._retained.receiver.get_or_insert(operation);
    }

    /// Reports a proven World admission refusal before any assignment published.
    ///
    /// This factual classification grants no retry authority. Callback refusal,
    /// poisoned synchronization, descriptor effects and negative postcuts never
    /// acquire it, even when no issued holder is present in this error.
    #[must_use]
    pub fn world_assignment_was_refused(&self) -> bool {
        matches!(self.after, RefusalPostcut::AssignmentRefused) && self._retained.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_services::{HostServiceAllocator, HostServiceLeasePair};
    use crate::test_support::TestAllocationObserver;

    #[test]
    fn admitted_carrier_holds_both_original_charges_until_close() {
        let extent = PreparedRefusal::metadata_bytes().unwrap();
        let resident = HostServiceAllocator::new(1, 1, extent).unwrap();
        let metadata = HostServiceAllocator::new(1, 1, extent).unwrap();
        let (metadata_charge, resident_charge) =
            metadata.reserve_paired_bytes(&resident, extent).unwrap();
        let header = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>();
        let (allocation, _) = header
            .extend(std::alloc::Layout::new::<RefusalAllocation>())
            .unwrap();
        let (carrier, identities) = TestAllocationObserver::capture_controls(
            [allocation.pad_to_align().size(), 0, 0],
            || {
                PreparedRefusal::from_metadata(HostServiceLeasePair::new(
                    metadata_charge,
                    resident_charge,
                ))
            },
        );
        assert!(identities[0].is_some());

        assert!(metadata.reserve_resources(0, 0, 1).is_err());
        assert!(resident.reserve_resources(0, 0, 1).is_err());
        assert!(carrier.allocation.as_ref().unwrap().owner.is_none());
        assert_eq!(Arc::strong_count(carrier.allocation.as_ref().unwrap()), 1);
        assert_eq!(Arc::weak_count(carrier.allocation.as_ref().unwrap()), 0);

        let (_, observations) = TestAllocationObserver::observe_controls(
            [&metadata, &resident],
            None,
            identities,
            || drop(carrier),
        );

        let observation = observations[0].as_ref().unwrap();
        assert_eq!(observation.before.original_bytes, [Some(extent); 2]);
        assert_eq!(observation.after.original_bytes, [Some(extent); 2]);
        assert!(metadata.reserve_resources(0, 0, extent).is_ok());
        assert!(resident.reserve_resources(0, 0, extent).is_ok());
    }

    #[test]
    fn refusal_recipe_covers_carrier_and_both_lease_allocations() {
        let extent = PreparedRefusal::metadata_bytes().unwrap();
        let resident = HostServiceAllocator::new(1, 1, extent).unwrap();
        let metadata = HostServiceAllocator::new(1, 1, extent).unwrap();

        let (carrier, events) = TestAllocationObserver::capture_allocation_events(|| {
            let (first, second) = metadata.reserve_paired_bytes(&resident, extent).unwrap();
            PreparedRefusal::from_metadata(HostServiceLeasePair::new(first, second))
        })
        .unwrap();

        assert!(!events.overflow);
        assert_eq!(events.reallocations, 0);
        assert_eq!(events.count, 3);
        assert!(events.entries().all(|event| event.allocated));
        let actual_bytes: usize = events.entries().map(|event| event.bytes).sum();
        assert!(extent as usize >= actual_bytes + std::mem::size_of::<RefusalAllocation>());
        drop(carrier);
    }

    #[test]
    fn complete_report_fits_inline_error_budget() {
        assert!(
            std::mem::size_of::<NativePoolRefusal>() < 128,
            "report={} cause={} optional_cause={} retained={}",
            std::mem::size_of::<NativePoolRefusal>(),
            std::mem::size_of::<ServiceBirthError>(),
            std::mem::size_of::<Option<ServiceBirthError>>(),
            std::mem::size_of::<RetainedClaim>(),
        );
        assert!(std::mem::size_of::<RefusalAllocation>() > std::mem::size_of::<PreparedRefusal>());
    }
}
