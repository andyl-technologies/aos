//! Retains same-actor decode authority outside its shared allocation.
//!
//! This adapter supplies existing original residency, metadata and descriptor
//! credit to the shared decoder. It pays its own authority and sticky original
//! refusal controls before publication. Decoder format adapters still have to
//! charge each actual input, parser, output and error allocation; a byte limit
//! alone does not establish that coverage.

use std::alloc::Layout;
use std::sync::{Arc, Mutex};

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceError, HostServiceLease, HostServiceLeasePair,
};
use crucible_linux_resource::host_supervision::HostOperationGuard;
use crucible_ram::ResourceLoan;

use super::OriginalActorAccountError;

struct OriginalDecodeAuthority {
    original: Arc<HostOperationGuard>,
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
    failure: Mutex<Option<DecodeAdmissionError>>,
}

#[derive(Debug, thiserror::Error)]
#[error("original decode admission refused: {source}; poisoned refusal storage: {poisoned}")]
struct OriginalDecodeRefusal {
    #[source]
    source: OriginalActorAccountError,
    poisoned: bool,
}

struct DecodeCredit {
    // The byte pair pays this descriptor control as well as its own controls.
    // Field destruction must close the descriptor before refunding that pair.
    _descriptors: Option<HostServiceLease>,
    _bytes: HostServiceLeasePair,
}

impl OriginalDecodeAuthority {
    fn remember(&self, source: OriginalActorAccountError) -> DecodeAdmissionError {
        let (mut slot, poisoned) = match self.failure.lock() {
            Ok(slot) => (slot, false),
            Err(poison) => (poison.into_inner(), true),
        };
        // One original refusal allocation was admitted before this authority.
        // Later callers borrow the same typed failure rather than allocating
        // repeated diagnostics or replacing its first sequential source.
        slot.get_or_insert_with(|| {
            DecodeAdmissionError::new(OriginalDecodeRefusal { source, poisoned })
        })
        .clone()
    }

    fn remembered(&self) -> Result<(), DecodeAdmissionError> {
        let recorded = match self.failure.lock() {
            Ok(slot) => return slot.as_ref().map_or(Ok(()), |error| Err(error.clone())),
            Err(poison) => poison.into_inner().as_ref().cloned(),
        };
        Err(recorded.unwrap_or_else(|| self.remember(OriginalActorAccountError::Unavailable)))
    }

    fn require_original(&self) -> Result<(), OriginalActorAccountError> {
        self.original.wait_slice()?;
        Ok(())
    }

    fn reserve_original(
        &self,
        bytes: u64,
        descriptors: u64,
    ) -> Result<ResourceLoan, OriginalActorAccountError> {
        self.require_original()?;
        let controls = HostServiceLease::metadata_bytes()
            .checked_mul(if descriptors == 0 { 2 } else { 3 })
            .and_then(|controls| {
                controls.checked_add(ResourceLoan::allocation_bytes::<DecodeCredit>())
            })
            .and_then(|controls| controls.checked_add(bytes))
            .ok_or(HostServiceError::CapacityExhausted)?;
        let (resident, metadata) = self
            .resident
            .reserve_paired_bytes(&self.metadata, controls)
            .map_err(|source| OriginalActorAccountError::NativeAccountBoundary {
                source,
                original: self.original.wait_slice().err(),
            })?;
        let pair = HostServiceLeasePair::new(resident, metadata);
        let descriptor_credit = if descriptors == 0 {
            None
        } else {
            Some(
                self.resident
                    .reserve_resources(0, descriptors, 0)
                    .map_err(|source| OriginalActorAccountError::NativeAccountBoundary {
                        source,
                        original: self.original.wait_slice().err(),
                    })?,
            )
        };
        let credit = ResourceLoan::new(DecodeCredit {
            _descriptors: descriptor_credit,
            _bytes: pair,
        });
        self.require_original()?;
        Ok(credit)
    }
}

impl DecodeResourceAuthority for OriginalDecodeAuthority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.remembered()?;
        self.require_original()
            .map_err(|source| self.remember(source))
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        self.reserve_original(bytes, 0)
            .map_err(|source| self.remember(source))
    }

    fn reserve_descriptors(&self, descriptors: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        self.reserve_original(0, descriptors)
            .map_err(|source| self.remember(source))
    }
}

/// Retains decoder authority and external paired control credit until closure.
///
/// Only the authenticated actor account owner constructs this type. Its budget
/// borrows the same original banks; it does not issue another account or clock.
/// Decoded outputs must retain their actual budget custody. Refused closure or
/// unwinding retains the authority and external credit, including outstanding
/// budget aliases. No alias count or decoded body drop certifies physical free.
#[must_use = "retain this external decode owner through every decoded owner and custody"]
pub struct OriginalActorDecodeOwner {
    budget: Option<DecodeBudget>,
    authority: Option<Arc<OriginalDecodeAuthority>>,
    controls: Option<HostServiceLeasePair>,
}

fn shared_extent<T>() -> Result<u64, HostServiceError> {
    let (layout, _) = Layout::new::<(usize, usize)>()
        .extend(Layout::new::<T>())
        .map_err(|_| HostServiceError::CapacityExhausted)?;
    u64::try_from(layout.pad_to_align().size()).map_err(|_| HostServiceError::CapacityExhausted)
}

impl OriginalActorDecodeOwner {
    pub(super) fn verify_original(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), OriginalActorAccountError> {
        let authority = self
            .authority
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if !Arc::ptr_eq(original, &authority.original) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        authority.require_original()
    }

    pub(super) fn prepare(
        original: &Arc<HostOperationGuard>,
        resident: &HostServiceAllocator,
        metadata: &HostServiceAllocator,
        maximum: u64,
    ) -> Result<Self, OriginalActorAccountError> {
        original.wait_slice()?;
        let bytes = shared_extent::<OriginalDecodeAuthority>()?
            .checked_add(shared_extent::<OriginalDecodeRefusal>()?)
            .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
            .ok_or(HostServiceError::CapacityExhausted)?;
        let (first, second) = resident
            .reserve_paired_bytes(metadata, bytes)
            .map_err(|source| OriginalActorAccountError::NativeAccountBoundary {
                source,
                original: original.wait_slice().err(),
            })?;
        let mut owner = Self {
            budget: None,
            controls: Some(HostServiceLeasePair::new(first, second)),
            authority: Some(Arc::new(OriginalDecodeAuthority {
                original: Arc::clone(original),
                resident: resident.clone(),
                metadata: metadata.clone(),
                failure: Mutex::new(None),
            })),
        };
        // The complete external record precedes constructor and original
        // postcuts. An error keeps controls outside every surviving alias.
        let authority = owner
            .authority
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let budget = DecodeBudget::new(
            Arc::clone(authority) as Arc<dyn DecodeResourceAuthority>,
            maximum,
        )
        .map_err(OriginalActorAccountError::Decode)?;
        owner.budget = Some(budget);
        original.wait_slice()?;
        Ok(owner)
    }

    /// Borrows the admitted budget for actual guarded decoding.
    ///
    /// # Errors
    /// Refuses consumed custody or the same original interval. The caller must
    /// retain every decoded owner's custody and charge format-specific work.
    pub fn budget(&self) -> Result<&DecodeBudget, OriginalActorAccountError> {
        let authority = self
            .authority
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        authority.require_original()?;
        self.budget
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)
    }

    /// Closes the budget and authority only after all external users release.
    ///
    /// # Errors
    /// Returns this same owner when the original refuses or any budget/authority
    /// alias survives, or a recorded refusal hides an error control. The returned
    /// owner retains external credit; failed decoding remains fail-sticky.
    /// closure neither marks a campaign complete nor retires native resources.
    pub fn try_close(mut self) -> Result<(), Self> {
        let Some(authority) = self.authority.as_mut() else {
            return Err(self);
        };
        if authority.require_original().is_err() {
            return Err(self);
        }
        // The budget also owns sticky refusals that precede authority entry,
        // including its local maximum. Their opaque error aliases cannot be
        // closed by proving that this separate authority is exclusive.
        if self
            .budget
            .as_ref()
            .is_some_and(|budget| budget.check().is_err())
        {
            return Err(self);
        }
        drop(self.budget.take());
        let Some(authority) = self.authority.as_mut() else {
            return Err(self);
        };
        let Some(exclusive) = Arc::get_mut(authority) else {
            return Err(self);
        };
        let error_survives = match exclusive.failure.get_mut() {
            Ok(slot) => slot.is_some(),
            Err(_) => true,
        };
        if error_survives {
            // The decoder error owns an opaque shared control and may have
            // escaped to the caller. No authority-alias proof can close it.
            // Keep its external credit until actual actor containment.
            return Err(self);
        }
        // The same private Arc has no strong/weak aliases. Its concrete value
        // and sticky error are destroyed after its control closes; both happen
        // before the external paired control credit is released.
        if let Some(authority) = self.authority.take() {
            drop(Arc::into_inner(authority));
        }
        drop(self.controls.take());
        Ok(())
    }
}

impl Drop for OriginalActorDecodeOwner {
    fn drop(&mut self) {
        if let Some(budget) = self.budget.take() {
            std::mem::forget(budget);
        }
        if let Some(authority) = self.authority.take() {
            std::mem::forget(authority);
        }
        if let Some(controls) = self.controls.take() {
            std::mem::forget(controls);
        }
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- these actual allocator/control custody tests panic on premature refunds, post-refusal allocation, or loss of the original typed cause; they supply no parent or physical launch certificate.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use crucible_linux_resource::test_support::TestAllocationObserver;

    fn preparation() -> (HostOperationSupervisor, Arc<HostOperationGuard>) {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let guard = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        (supervisor, guard)
    }

    #[test]
    fn second_original_refusal_allocates_no_shared_controls_and_refunds_first() {
        let (_supervisor, original) = preparation();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1).unwrap();

        let (result, counts) = TestAllocationObserver::count(|| {
            OriginalActorDecodeOwner::prepare(&original, &resident, &metadata, 1 << 20)
        });

        assert!(matches!(
            result,
            Err(OriginalActorAccountError::NativeAccountBoundary {
                source: HostServiceError::CapacityExhausted,
                original: None
            })
        ));
        assert_eq!(counts.allocations, 0);
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_ok());
        assert!(metadata.reserve_resources(1, 64, 1).is_ok());
    }

    #[test]
    fn live_budget_alias_prevents_external_credit_release_until_actual_control_close() {
        let (_supervisor, original) = preparation();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let owner =
            OriginalActorDecodeOwner::prepare(&original, &resident, &metadata, 1 << 20).unwrap();
        let alias = owner.budget().unwrap().clone();
        alias.charge_bytes(1024).unwrap();
        let descriptor = alias.reserve_descriptors(3).unwrap();

        let owner = match owner.try_close() {
            Err(owner) => owner,
            Ok(()) => panic!("live decoder authority closed"),
        };
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
        drop(descriptor);
        drop(alias);

        assert!(owner.try_close().is_ok());
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_ok());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_ok());
    }

    #[test]
    fn a_live_original_does_not_close_credit_while_a_refusal_error_alias_survives() {
        let (_supervisor, original) = preparation();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let owner =
            OriginalActorDecodeOwner::prepare(&original, &resident, &metadata, 1 << 20).unwrap();
        let error = owner
            .authority
            .as_ref()
            .unwrap()
            .reserve(2 << 20)
            .err()
            .unwrap();
        original.wait_slice().unwrap();

        let held = owner.try_close();

        assert!(
            held.is_err(),
            "a returned error still owns its prepaid control"
        );
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
        drop(error);
        // The shared decoder error hides its control. A recorded failure
        // therefore remains fail-sticky, even after this known alias closes.
        assert!(held.err().unwrap().try_close().is_err());
    }

    #[test]
    fn descriptor_control_closes_before_its_original_paired_purpose_refunds() {
        let (_supervisor, original) = preparation();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let authority = OriginalDecodeAuthority {
            original,
            resident: resident.clone(),
            metadata: metadata.clone(),
            failure: Mutex::new(None),
        };
        // The declared lease extent includes its inline handle. The selected
        // constructor requests are the two paired controls, then the actual
        // descriptor control; no identity is inferred from a pointer getter.
        let extent = usize::try_from(HostServiceLease::metadata_bytes()).unwrap()
            - std::mem::size_of::<HostServiceLease>();
        let expected = 3 * HostServiceLease::metadata_bytes()
            + ResourceLoan::allocation_bytes::<DecodeCredit>();
        let (loan, identities) = TestAllocationObserver::capture_controls([extent; 3], || {
            authority.reserve_original(0, 3).unwrap()
        });
        assert!(identities.iter().all(Option::is_some));

        let ((), observations) = TestAllocationObserver::observe_controls(
            [&resident, &metadata],
            None,
            identities,
            || drop(loan),
        );

        let descriptor = observations[2].unwrap();
        assert_eq!(descriptor.before.original_bytes, [Some(expected); 2]);
        assert_eq!(descriptor.after.original_bytes, [Some(expected); 2]);
        assert_eq!(descriptor.ordinal, 1);
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_ok());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_ok());
    }

    #[test]
    fn a_budget_local_refusal_keeps_the_same_owner_and_its_error_credit() {
        let (_supervisor, original) = preparation();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let owner =
            OriginalActorDecodeOwner::prepare(&original, &resident, &metadata, 1 << 20).unwrap();
        let error = owner
            .budget()
            .unwrap()
            .reserve_scratch_bytes((1 << 20) + 1)
            .err()
            .unwrap();
        assert!(
            owner
                .authority
                .as_ref()
                .unwrap()
                .failure
                .lock()
                .unwrap()
                .is_none()
        );
        original.wait_slice().unwrap();

        let held = owner.try_close();

        assert!(
            held.is_err(),
            "a budget-local refusal still owns its prepaid control"
        );
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
        drop(error);
        assert!(held.err().unwrap().try_close().is_err());
    }

    #[test]
    fn original_cancel_is_sticky_and_repeated_refusal_does_not_allocate() {
        let (_supervisor, original) = preparation();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let owner =
            OriginalActorDecodeOwner::prepare(&original, &resident, &metadata, 1 << 20).unwrap();
        let authority = owner.authority.as_ref().unwrap();
        _supervisor.cancel().unwrap();

        let first = authority.verify_live().err().unwrap();
        let (second, counts) = TestAllocationObserver::count(|| authority.reserve(128));

        assert_eq!(second.err().unwrap(), first);
        assert_eq!(counts.allocations, 0);
        assert!(owner.try_close().is_err());
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
    }
}
