//! Retains the guest SQLite issuer under the same authenticated actor banks.
//!
//! Native bootstrap and the reclaimable heap are separate original purposes.
//! This owner remains external to the issuer and every permanent bootstrap or
//! heap credit. The enclosing ParentVM retains physical Source financing;
//! operator ceilings alone do not qualify native initialization's pre-limit
//! peak, installed images, thread stacks or service filesystem capacity.

use std::alloc::Layout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crucible::owned_decode::{DecodeAdmissionError, ResourceLoan};
use crucible_cas::content_store::{
    SqliteHeapAuthority, SqliteHeapIssuer, SqliteProcessBootstrapAuthority, SqliteProcessHeap,
    StoreError,
};
use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceError, HostServiceLease, HostServiceLeasePair,
};
use crucible_linux_resource::host_supervision::HostOperationGuard;

use super::{OriginalActorAccountCustody, OriginalActorAccountError, OriginalActorServicePolicy};

struct SqliteActor {
    original: Arc<HostOperationGuard>,
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
    bootstrap_bytes: u64,
    heap_bytes: u64,
    issued: AtomicBool,
    first_failure: Mutex<Option<DecodeAdmissionError>>,
}

struct MetadataCredit {
    _actor: Arc<SqliteActor>,
    _pair: HostServiceLeasePair,
}

struct NativeCredit {
    // Metadata funds both this enclosing loan control and the native lease
    // control. Native custody must close before that metadata purpose refunds.
    _native: HostServiceLease,
    _actor: Arc<SqliteActor>,
    _metadata: ResourceLoan,
}

struct HeapAuthority {
    actor: Arc<SqliteActor>,
}

/// Retains one authenticated guest SQLite issuer outside its funded controls.
///
/// The closed service policy supplies required operator declarations. Only the
/// same actor account custody can construct this owner; there is no allocator,
/// scalar-limit or external campaign-process constructor. Permanent bootstrap
/// credit and uncertain close retain this owner for the actor process lifetime.
/// Native/source qualification remains a prerequisite before invoking install.
#[must_use = "retain the guest issuer through process-lifetime SQLite custody"]
pub struct OriginalActorSqliteOwner {
    actor: Option<Arc<SqliteActor>>,
    controls: Option<HostServiceLeasePair>,
    connections: usize,
    installation_attempted: bool,
}

/// Preserves native installation and its independent original postcheck.
#[derive(Debug, thiserror::Error)]
#[error("original SQLite installation refused: {source}; original postcheck: {original_after:?}")]
pub struct OriginalActorSqliteInstallError {
    /// The first actual work or admission refusal.
    #[source]
    pub source: StoreError,
    /// The same original's independent post-native refusal, when present.
    pub original_after: Option<StoreError>,
}

fn shared_extent<T>() -> Result<u64, HostServiceError> {
    let (layout, _) = Layout::new::<(usize, usize)>()
        .extend(Layout::new::<T>())
        .map_err(|_| HostServiceError::CapacityExhausted)?;
    u64::try_from(layout.pad_to_align().size()).map_err(|_| HostServiceError::CapacityExhausted)
}

impl OriginalActorAccountCustody {
    /// Prepays a closed guest SQLite issuer from these same published banks.
    ///
    /// The input can be obtained only by authenticating the parent's workflow.
    /// This reserves concrete local controls; it neither installs SQLite nor
    /// substitutes operator limits for physical native/source qualification.
    ///
    /// # Errors
    /// Refuses different or expired original custody, insufficient original
    /// resident/metadata credit, target overflow, or a separate original
    /// postcheck. The published owner retains its payment on post-refusal.
    pub fn prepare_sqlite_owner(
        &self,
        policy: OriginalActorServicePolicy,
    ) -> Result<OriginalActorSqliteOwner, OriginalActorAccountError> {
        let held = self
            .held
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        held.preparation.wait_slice()?;
        if !Arc::ptr_eq(&held.preparation, &policy.original) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        OriginalActorSqliteOwner::prepare(policy, &held.resident, &held.metadata)
    }
}

impl OriginalActorSqliteOwner {
    fn prepare(
        policy: OriginalActorServicePolicy,
        resident: &HostServiceAllocator,
        metadata: &HostServiceAllocator,
    ) -> Result<Self, OriginalActorAccountError> {
        policy.original.wait_slice()?;
        let bytes = shared_extent::<SqliteActor>()?
            .checked_add(shared_extent::<OriginalActorAccountError>()?)
            .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
            .ok_or(HostServiceError::CapacityExhausted)?;
        let (resident_credit, metadata_credit) = resident
            .reserve_paired_bytes(metadata, bytes)
            .map_err(|source| OriginalActorAccountError::NativeAccountBoundary {
                source,
                original: policy.original.wait_slice().err(),
            })?;
        let owner = OriginalActorSqliteOwner {
            actor: Some(Arc::new(SqliteActor {
                original: policy.original,
                resident: resident.clone(),
                metadata: metadata.clone(),
                bootstrap_bytes: policy.bootstrap_bytes,
                heap_bytes: policy.heap_bytes,
                issued: AtomicBool::new(false),
                first_failure: Mutex::new(None),
            })),
            controls: Some(HostServiceLeasePair::new(resident_credit, metadata_credit)),
            connections: policy.connections,
            installation_attempted: false,
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

impl SqliteActor {
    fn remember(&self, source: OriginalActorAccountError) -> StoreError {
        let mut slot = match self.first_failure.lock() {
            Ok(slot) => slot,
            Err(poison) => poison.into_inner(),
        };
        let source = slot
            .get_or_insert_with(|| DecodeAdmissionError::new(source))
            .clone();
        StoreError::DecodeAdmission {
            source,
            custody: None,
        }
    }

    fn verify(&self) -> Result<(), StoreError> {
        let slot = match self.first_failure.lock() {
            Ok(slot) => slot,
            Err(poison) => {
                drop(poison.into_inner());
                return Err(self.remember(OriginalActorAccountError::Unavailable));
            }
        };
        if let Some(source) = slot.as_ref() {
            return Err(StoreError::DecodeAdmission {
                source: source.clone(),
                custody: None,
            });
        }
        drop(slot);
        self.original
            .wait_slice()
            .map(|_| ())
            .map_err(|source| self.remember(source.into()))
    }

    fn metadata(self: &Arc<Self>, bytes: u64) -> Result<ResourceLoan, StoreError> {
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

    fn native(self: &Arc<Self>, bytes: u64, rust_bytes: u64) -> Result<ResourceLoan, StoreError> {
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

impl SqliteHeapAuthority for HeapAuthority {
    fn verify_live(&self) -> Result<(), StoreError> {
        self.actor.verify()
    }

    fn reserve_heap(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.actor.verify()?;
        if bytes != self.actor.heap_bytes
            || self
                .actor
                .issued
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(self.actor.remember(OriginalActorAccountError::Unavailable));
        }
        self.actor.native(bytes, 0)
    }

    fn reserve_metadata(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.actor.metadata(bytes)
    }
}

impl SqliteProcessBootstrapAuthority for OriginalActorSqliteOwner {
    fn verify_live(&self) -> Result<(), StoreError> {
        self.actor
            .as_ref()
            .ok_or(StoreError::Unauthorized)?
            .verify()
    }

    fn reserve_bootstrap(&self, rust_metadata_bytes: u64) -> Result<ResourceLoan, StoreError> {
        let actor = self.actor.as_ref().ok_or(StoreError::Unauthorized)?;
        actor.native(actor.bootstrap_bytes, rust_metadata_bytes)
    }
}

impl OriginalActorSqliteOwner {
    /// Installs the genuine finite SQLite heap under its retained guest issuer.
    ///
    /// Caller deployment qualification must establish the exact linked native
    /// initialization peak against the authenticated bootstrap purpose before
    /// this native entry. It must also retain this owner and the original
    /// ParentVM through actual process retirement; a heap handle is not a
    /// physical Source or native-paging permission.
    ///
    /// # Errors
    /// Refuses repeated entry, original admission, occupied process bootstrap,
    /// native initialization or an uncertain existing heap. First original
    /// causes remain in the actor's prepaid slot across subsequent refusals.
    pub fn install(&mut self) -> Result<SqliteProcessHeap, OriginalActorSqliteInstallError> {
        let result = self.install_inner();
        let after = self
            .actor
            .as_ref()
            .map_or(Err(StoreError::Unauthorized), |actor| actor.verify());
        match (result, after) {
            (Err(source), after) => Err(OriginalActorSqliteInstallError {
                source,
                original_after: after.err(),
            }),
            (Ok(heap), Ok(())) => Ok(heap),
            (Ok(heap), Err(source)) => {
                std::mem::forget(heap);
                Err(OriginalActorSqliteInstallError {
                    source,
                    original_after: None,
                })
            }
        }
    }

    fn install_inner(&mut self) -> Result<SqliteProcessHeap, StoreError> {
        if self.installation_attempted {
            return Err(StoreError::Unauthorized);
        }
        self.installation_attempted = true;
        let actor = self.actor.as_ref().ok_or(StoreError::Unauthorized)?;
        actor.verify()?;
        SqliteProcessHeap::prepare_bootstrap(self)?;
        let controls = actor.metadata(SqliteHeapIssuer::control_bytes::<HeapAuthority>())?;
        let issuer = SqliteHeapIssuer::new(
            HeapAuthority {
                actor: Arc::clone(actor),
            },
            controls,
        );
        SqliteProcessHeap::install(issuer, actor.heap_bytes, self.connections)
    }
}

impl Drop for OriginalActorSqliteOwner {
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
                original,
                bootstrap_bytes: 4096,
                heap_bytes: 8192,
                connections: 1,
            },
        )
    }

    #[test]
    fn second_original_account_refusal_precedes_sqlite_actor_publication() {
        let (_supervisor, policy) = policy();
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1).unwrap();

        let (result, counts) = TestAllocationObserver::count(|| {
            OriginalActorSqliteOwner::prepare(policy, &resident, &metadata)
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
        let owner = OriginalActorSqliteOwner::prepare(policy, &resident, &metadata).unwrap();
        let actor = owner.actor.as_ref().unwrap();
        supervisor.cancel().unwrap();

        let first = actor.verify().err().unwrap();
        let (second, counts) = TestAllocationObserver::count(|| actor.metadata(1024));

        let first = match first {
            StoreError::DecodeAdmission { source, .. } => source,
            other => panic!("lost original first cause: {other}"),
        };
        let second = match second.err().unwrap() {
            StoreError::DecodeAdmission { source, .. } => source,
            other => panic!("lost original repeated cause: {other}"),
        };
        assert_eq!(first, second);
        assert_eq!(counts.allocations, 0);
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
        drop(owner);
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
    }
}
