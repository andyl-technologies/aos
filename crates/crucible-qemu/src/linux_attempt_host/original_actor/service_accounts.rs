//! Retains guest service accounting under the same authenticated actor banks.
//!
//! Native bootstrap and the reclaimable heap are separate original purposes.
//! This owner remains external to the issuer and every permanent bootstrap or
//! heap credit. It owns no SQLite issuer, store or filesystem. The daemon owns
//! native library and CAS implementations. ParentVM retains physical Source financing;
//! operator ceilings alone do not qualify native initialization's pre-limit
//! peak, installed images, thread stacks or service filesystem capacity.

use std::alloc::Layout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crucible::owned_decode::{DecodeAdmissionError, ResourceLoan};
use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceError, HostServiceLease, HostServiceLeasePair,
};
use crucible_linux_resource::host_supervision::HostOperationGuard;

use super::{
    OriginalActorAccountCustody, OriginalActorAccountError, OriginalActorDecodeOwner,
    OriginalActorServicePolicy,
};

struct ServiceActor {
    original: Arc<HostOperationGuard>,
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
    bootstrap_bytes: u64,
    main_stack_bytes: u64,
    bootstrap_digest: [u8; 32],
    heap_bytes: u64,
    issued: AtomicBool,
    first_failure: Mutex<Option<DecodeAdmissionError>>,
}

struct MetadataCredit {
    _actor: Arc<ServiceActor>,
    _pair: HostServiceLeasePair,
}

struct NativeCredit {
    // Metadata funds both this enclosing loan control and the native lease
    // control. Native custody must close before that metadata purpose refunds.
    _native: HostServiceLease,
    _actor: Arc<ServiceActor>,
    _metadata: ResourceLoan,
}

/// Retains the original guest service accounting outside its funded controls.
///
/// The closed service policy supplies required operator declarations. Only the
/// same actor account custody can construct this owner; there is no allocator,
/// scalar-limit or external campaign-process constructor. Permanent bootstrap
/// credit and uncertain close retain this owner for the actor process lifetime.
/// This owner cannot install a native library or construct storage.
#[must_use = "retain the guest issuer through process-lifetime SQLite custody"]
pub struct OriginalGuestServiceOwner {
    actor: Option<Arc<ServiceActor>>,
    controls: Option<HostServiceLeasePair>,
    connections: usize,
}

fn shared_extent<T>() -> Result<u64, HostServiceError> {
    let (layout, _) = Layout::new::<(usize, usize)>()
        .extend(Layout::new::<T>())
        .map_err(|_| HostServiceError::CapacityExhausted)?;
    u64::try_from(layout.pad_to_align().size()).map_err(|_| HostServiceError::CapacityExhausted)
}

impl OriginalActorAccountCustody {
    /// Prepays closed guest service accounting from these same published banks.
    ///
    /// The input can be obtained only by authenticating the parent's workflow.
    /// This reserves concrete local controls; it neither installs SQLite nor
    /// substitutes operator limits for physical native/source qualification.
    ///
    /// # Errors
    /// Refuses different or expired original custody, insufficient original
    /// resident/metadata credit, target overflow, or a separate original
    /// postcheck. The published owner retains its payment on post-refusal.
    pub fn prepare_guest_service_owner(
        &self,
        policy: OriginalActorServicePolicy,
    ) -> Result<OriginalGuestServiceOwner, OriginalActorAccountError> {
        let held = self
            .held
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        held.preparation.wait_slice()?;
        if !Arc::ptr_eq(&held.preparation, &policy.original) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        OriginalGuestServiceOwner::prepare(policy, &held.resident, &held.metadata)
    }
}

impl OriginalGuestServiceOwner {
    fn prepare(
        policy: OriginalActorServicePolicy,
        resident: &HostServiceAllocator,
        metadata: &HostServiceAllocator,
    ) -> Result<Self, OriginalActorAccountError> {
        policy.original.wait_slice()?;
        let bytes = shared_extent::<ServiceActor>()?
            .checked_add(shared_extent::<OriginalActorAccountError>()?)
            .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
            .ok_or(HostServiceError::CapacityExhausted)?;
        let (resident_credit, metadata_credit) = resident
            .reserve_paired_bytes(metadata, bytes)
            .map_err(|source| OriginalActorAccountError::NativeAccountBoundary {
                source,
                original: policy.original.wait_slice().err(),
            })?;
        let owner = OriginalGuestServiceOwner {
            actor: Some(Arc::new(ServiceActor {
                original: policy.original,
                resident: resident.clone(),
                metadata: metadata.clone(),
                bootstrap_bytes: policy.bootstrap_bytes,
                main_stack_bytes: policy.main_stack_bytes,
                bootstrap_digest: policy.bootstrap_digest,
                heap_bytes: policy.heap_bytes,
                issued: AtomicBool::new(false),
                first_failure: Mutex::new(None),
            })),
            controls: Some(HostServiceLeasePair::new(resident_credit, metadata_credit)),
            connections: policy.connections,
        };
        owner
            .actor
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .original
            .wait_slice()?;
        Ok(owner)
    }
}

impl ServiceActor {
    fn remember(&self, source: OriginalActorAccountError) -> DecodeAdmissionError {
        let mut slot = match self.first_failure.lock() {
            Ok(slot) => slot,
            Err(poison) => poison.into_inner(),
        };
        slot.get_or_insert_with(|| DecodeAdmissionError::new(source))
            .clone()
    }

    fn verify(&self) -> Result<(), DecodeAdmissionError> {
        let slot = match self.first_failure.lock() {
            Ok(slot) => slot,
            Err(poison) => {
                drop(poison.into_inner());
                return Err(self.remember(OriginalActorAccountError::Unavailable));
            }
        };
        if let Some(source) = slot.as_ref() {
            return Err(source.clone());
        }
        drop(slot);
        self.original
            .wait_slice()
            .map(|_| ())
            .map_err(|source| self.remember(source.into()))
    }

    fn metadata(self: &Arc<Self>, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify()?;
        let purpose = bytes
            .checked_add(ResourceLoan::allocation_bytes::<MetadataCredit>())
            .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
            .ok_or_else(|| self.remember(HostServiceError::CapacityExhausted.into()))?;
        let (resident, metadata) = self
            .resident
            .reserve_paired_bytes(&self.metadata, purpose)
            .map_err(|source| {
                self.remember(OriginalActorAccountError::NativeAccountBoundary {
                    source,
                    original: self.original.wait_slice().err(),
                })
            })?;
        let credit = ResourceLoan::new(MetadataCredit {
            _actor: Arc::clone(self),
            _pair: HostServiceLeasePair::new(resident, metadata),
        });
        self.verify()?;
        Ok(credit)
    }

    fn native(
        self: &Arc<Self>,
        bytes: u64,
        rust_bytes: u64,
    ) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify()?;
        let metadata = self.metadata(
            rust_bytes
                .checked_add(ResourceLoan::allocation_bytes::<NativeCredit>())
                .and_then(|bytes| bytes.checked_add(HostServiceLease::metadata_bytes()))
                .ok_or_else(|| self.remember(HostServiceError::CapacityExhausted.into()))?,
        )?;
        let native = self
            .resident
            .reserve_resources(0, 0, bytes)
            .map_err(|source| {
                self.remember(OriginalActorAccountError::NativeAccountBoundary {
                    source,
                    original: self.original.wait_slice().err(),
                })
            })?;
        let credit = ResourceLoan::new(NativeCredit {
            _native: native,
            _actor: Arc::clone(self),
            _metadata: metadata,
        });
        self.verify()?;
        Ok(credit)
    }
}

impl Drop for OriginalGuestServiceOwner {
    fn drop(&mut self) {
        // The actual permanent bootstrap and all independent heap/connection
        // aliases may remain. Field destruction cannot certify process closure.
        if let Some(actor) = self.actor.take() {
            std::mem::forget(actor);
        }
        if let Some(controls) = self.controls.take() {
            std::mem::forget(controls);
        }
    }
}

/// Shares the same funded account allocation with a daemon native issuer.
///
/// No field, constructor, allocator or original guard is exposed. Every loan
/// retains this same actor allocation and its existing counter custody.
pub struct OriginalGuestServiceHandle(Arc<ServiceActor>);

impl OriginalGuestServiceOwner {
    /// Shares only this owner's actual accounting identity with the daemon.
    ///
    /// # Errors
    /// Refuses missing custody or the original's retained first boundary.
    pub fn share_accounting(&self) -> Result<OriginalGuestServiceHandle, DecodeAdmissionError> {
        let actor = self
            .actor
            .as_ref()
            .ok_or_else(|| DecodeAdmissionError::new(OriginalActorAccountError::Unavailable))?;
        actor.verify()?;
        Ok(OriginalGuestServiceHandle(Arc::clone(actor)))
    }

    /// Authenticates a decoder against this exact original preparation.
    ///
    /// # Errors
    /// Refuses a different guard allocation or unavailable original custody.
    pub fn verify_decoder(
        &self,
        decoder: &OriginalActorDecodeOwner,
    ) -> Result<(), OriginalActorAccountError> {
        let actor = self
            .actor
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        decoder.verify_original(&actor.original)
    }

    /// Checks a supplied closed handle against this same account allocation.
    ///
    /// # Errors
    /// Refuses a foreign handle or the same original's sticky first refusal.
    pub fn verify_handle(
        &self,
        handle: &OriginalGuestServiceHandle,
    ) -> Result<(), DecodeAdmissionError> {
        let actor = self
            .actor
            .as_ref()
            .ok_or_else(|| DecodeAdmissionError::new(OriginalActorAccountError::Unavailable))?;
        if !Arc::ptr_eq(actor, &handle.0) {
            return Err(actor.remember(OriginalActorAccountError::Unavailable));
        }
        actor.verify()
    }

    /// Returns the immutable authenticated simultaneous connection ceiling.
    #[must_use]
    pub const fn connections(&self) -> usize {
        self.connections
    }
}

impl OriginalGuestServiceHandle {
    /// Checks the same original preparation without exposing its guard.
    ///
    /// # Errors
    /// Refuses the actual retained original cancellation or absolute end.
    pub fn original_check(
        &self,
    ) -> Result<(), crucible_linux_resource::host_supervision::HostSupervisionError> {
        self.0.original.wait_slice().map(|_| ())
    }

    /// Checks the retained first failure and this same original preparation.
    ///
    /// # Errors
    /// Refuses a sticky original account or supervision cause.
    pub fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.0.verify()
    }

    /// Reserves actual Rust controls from both original subset counters.
    ///
    /// # Errors
    /// Refuses actual capacity or original supervision before or after debit.
    pub fn reserve_metadata(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.0.metadata(bytes)
    }

    /// Reserves the full authenticated native bootstrap resident entitlement.
    ///
    /// The daemon separately qualifies actual Source and initialization peak.
    ///
    /// # Errors
    /// Refuses actual original capacity or its independent postcheck.
    pub fn reserve_bootstrap(&self, rust_bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.0.native(self.0.bootstrap_bytes, rust_bytes)
    }

    /// Reserves the exact authored SQLite heap once from the original bank.
    ///
    /// # Errors
    /// Refuses any different extent, repeated issuance or original capacity.
    pub fn reserve_heap(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.0.verify()?;
        if bytes != self.0.heap_bytes
            || self
                .0
                .issued
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(self.0.remember(OriginalActorAccountError::Unavailable));
        }
        self.0.native(bytes, 0)
    }

    /// Returns the full authored bootstrap declaration, not a peak certificate.
    #[must_use]
    pub fn bootstrap_bytes(&self) -> u64 {
        self.0.bootstrap_bytes
    }

    /// Returns the fixed native heap declaration authenticated by the workflow.
    #[must_use]
    pub fn heap_bytes(&self) -> u64 {
        self.0.heap_bytes
    }

    /// Returns the immutable stack declaration enforced by the trusted birth.
    #[must_use]
    pub fn main_stack_bytes(&self) -> u64 {
        self.0.main_stack_bytes
    }

    /// Borrows the installed proof identity bound by the same workflow.
    #[must_use]
    pub fn bootstrap_digest(&self) -> &[u8; 32] {
        &self.0.bootstrap_digest
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- these real paired-account and original-cancellation controls panic on premature publication or loss of typed custody; they perform no SQLite native entry and issue no parent grant.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use crucible_linux_resource::test_support::TestAllocationObserver;

    fn policy() -> (HostOperationSupervisor, OriginalActorServicePolicy) {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        (
            supervisor,
            OriginalActorServicePolicy {
                catalog: None,
                original,
                bootstrap_bytes: 4096,
                heap_bytes: 8192,
                connections: 1,
                main_stack_bytes: 8 << 20,
                bootstrap_digest: [0; 32],
                campaign_digest: [0; 32],
                campaign_projection_digest: [0; 32],
            },
        )
    }

    #[test]
    fn second_original_account_refusal_precedes_sqlite_actor_publication() {
        let (_supervisor, policy) = policy();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1).unwrap();

        let (result, counts) = TestAllocationObserver::count(|| {
            OriginalGuestServiceOwner::prepare(policy, &resident, &metadata)
        });

        assert!(matches!(
            result,
            Err(OriginalActorAccountError::NativeAccountBoundary {
                source: HostServiceError::CapacityExhausted,
                original: None,
            })
        ));
        assert_eq!(counts.allocations, 0);
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_ok());
        assert!(metadata.reserve_resources(1, 64, 1).is_ok());
    }

    #[test]
    fn canceled_sqlite_issuer_keeps_one_original_typed_cause_without_native_entry() {
        let (supervisor, policy) = policy();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let owner = OriginalGuestServiceOwner::prepare(policy, &resident, &metadata).unwrap();
        let actor = owner.actor.as_ref().unwrap();
        supervisor.cancel().unwrap();

        let first = actor.verify().err().unwrap();
        let (second, counts) = TestAllocationObserver::count(|| actor.metadata(1024));

        let second = second.err().unwrap();
        assert_eq!(first, second);
        assert_eq!(counts.allocations, 0);
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
        drop(owner);
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
    }

    #[test]
    fn closed_handle_reserves_only_the_exact_heap_once() {
        let (_root, policy) = policy();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let owner = OriginalGuestServiceOwner::prepare(policy, &resident, &metadata).unwrap();
        let handle = owner.share_accounting().unwrap();

        let actual = handle.reserve_heap(8192).unwrap();
        let first = handle.reserve_heap(8192).err().unwrap();
        let (second, counts) = TestAllocationObserver::count(|| handle.reserve_heap(8192));

        assert_eq!(first, second.err().unwrap());
        assert_eq!(counts.allocations, 0);
        drop(actual);
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
    }

    #[test]
    fn closed_handle_rejects_foreign_account_allocation_without_native_entry() {
        let (_first_root, first_policy) = policy();
        let (_second_root, second_policy) = policy();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let first = OriginalGuestServiceOwner::prepare(first_policy, &resident, &metadata).unwrap();
        let second =
            OriginalGuestServiceOwner::prepare(second_policy, &resident, &metadata).unwrap();
        let foreign = second.share_accounting().unwrap();

        let cause = first.verify_handle(&foreign).err().unwrap();
        let (again, counts) = TestAllocationObserver::count(|| first.verify_handle(&foreign));

        assert_eq!(cause, again.err().unwrap());
        assert_eq!(counts.allocations, 0);
        second.verify_handle(&foreign).unwrap();
    }

    #[test]
    fn raw_original_postcut_observes_cancel_after_sticky_account_refusal() {
        let (root, policy) = policy();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let owner = OriginalGuestServiceOwner::prepare(policy, &resident, &metadata).unwrap();
        let handle = owner.share_accounting().unwrap();

        let first = handle.reserve_metadata(2 << 20).err().unwrap();
        handle.original_check().unwrap();
        root.cancel().unwrap();

        assert_eq!(first, handle.verify_live().err().unwrap());
        assert!(matches!(
            handle.original_check(),
            Err(
                crucible_linux_resource::host_supervision::HostSupervisionError::Terminal {
                    state: crucible_linux_resource::host_supervision::HostOperationState::Canceled,
                }
            )
        ));
    }
}
