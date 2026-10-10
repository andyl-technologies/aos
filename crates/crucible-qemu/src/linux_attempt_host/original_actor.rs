//! Retains certified original actor accounts outside native allocations.
//!
//! The sole constructor consumes the authenticated parent carrier, publishes
//! the same original stack accounts once and retains their returned guard.
//! Native account credit is narrower than a launch permission: physical domain,
//! Source, process and storage ownership must still be bound before birth.

use std::sync::Arc;

use super::original_roster::{OriginalNativeAccountFactoryBinding, OriginalNativeAccountRoster};

mod catalog_accounts;
pub use catalog_accounts::{
    OriginalActorCatalogAccounts, OriginalCatalogAuditError, OriginalCatalogPhysicalAudit,
};

mod decode;
pub use decode::OriginalActorDecodeOwner;

mod service_accounts;
pub use service_accounts::{OriginalGuestServiceHandle, OriginalGuestServiceOwner};

mod workflow;
pub use workflow::{OriginalActorCatalogPurpose, OriginalActorServicePolicy};

use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceBootstrap, HostServiceError, HostServiceLeasePair,
};
use crucible_linux_resource::host_supervision::{
    HostOperationGuard, HostOperationSupervisor, HostSupervisionBootstrap, HostSupervisionError,
};
use crucible_linux_resource::measurement_origin::{
    AuthenticatedParentInvocation, CertifiedNativeRoleEvidence, MeasurementOriginError,
};

/// Refuses certified account publication without substituting an original.
#[derive(Debug, thiserror::Error)]
pub enum OriginalActorAccountError {
    /// The authenticated workflow refused before a separate original postcheck.
    #[error("original workflow refused: {source}; original: {original:?}")]
    WorkflowBoundary {
        /// Actual first immutable-workflow or service-profile refusal.
        #[source]
        source: MeasurementOriginError,
        /// The same retained preparation's independent postcheck.
        original: Option<HostSupervisionError>,
    },
    /// The actual workflow parser failed before a separate original postcheck.
    #[error("original workflow decode refused: {source}; original: {original:?}")]
    WorkflowDecode {
        /// Actual parser syntax or typed admission marker.
        #[source]
        source: serde_json::Error,
        /// The same retained preparation's independent postcheck.
        original: Option<HostSupervisionError>,
    },
    /// The same authenticated invocation refused its identity or interval.
    #[error("original actor binding refused: {0}")]
    Origin(#[from] MeasurementOriginError),
    /// Either original account refused its unpublished or native charge.
    #[error("original actor account refused: {0}")]
    Account(#[from] HostServiceError),
    /// Account admission failed before a separate same-original refusal.
    #[error("original native account refused: {source}; original: {original:?}")]
    NativeAccountBoundary {
        /// The actual first original account refusal.
        #[source]
        source: HostServiceError,
        /// The same preparation's independent postcheck refusal.
        original: Option<HostSupervisionError>,
    },
    /// The same original supervisor or returned preparation refused.
    #[error("original actor supervision refused: {0}")]
    Supervision(#[from] HostSupervisionError),
    /// The same actual native state refused control closure.
    #[error("original native control refused: {source}; original: {original:?}")]
    NativeControlBoundary {
        /// The actual native control refusal precedes this postcheck.
        #[source]
        source: super::native_resources::LinuxQemuNativeResourceError,
        /// The same retained Cleanup's independent boundary refusal.
        original: Option<HostSupervisionError>,
    },
    /// Retains decode admission before the same original postcut.
    #[error("original actor decode refused: {source}; original: {original:?}")]
    DecodeBoundary {
        /// First actual sticky decoder refusal.
        #[source]
        source: crucible::owned_decode::DecodeAdmissionError,
        /// Separate same-original postcheck.
        original: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    },
    /// The same original decoder account refused constructor admission.
    #[error("original actor decode refused: {0}")]
    Decode(#[source] crucible::owned_decode::DecodeAdmissionError),
    /// Required retained custody has already been consumed.
    #[error("original actor custody is unavailable")]
    Unavailable,
}

/// Keeps the same original actor banks outside every allocation they fund.
///
/// There is no constructor accepting allocators or scalar ceilings. Parent
/// admission supplies the original fixed partition; publication charges actual
/// target structure before either shared bank or supervisor control exists.
/// Dropping unsettled custody retains the same accounts, origin and guard.
#[must_use = "retain original account custody through physical retirement"]
pub struct OriginalActorAccountCustody {
    held: Option<PublishedAccounts>,
}

struct PublishedAccounts {
    preparation: Arc<HostOperationGuard>,
    _supervisor: HostOperationSupervisor,
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
    evidence: CertifiedNativeRoleEvidence,
    native_roster_published: bool,
}

impl OriginalActorAccountCustody {
    /// Publishes one authenticated original and returns its same capture aliases.
    ///
    /// The accounts move once into this external owner. The returned aliases
    /// share the already admitted guard and supervisor; they create no guard,
    /// bank, clock or shared allocation. The daemon retains this custody outside
    /// the genuine shared factory and every native state allocation.
    ///
    /// # Errors
    /// Refuses original binding, expired original time, structural admission,
    /// target geometry overflow, or supervision before or after publication.
    pub fn publish_parent(
        invocation: AuthenticatedParentInvocation,
    ) -> Result<(Self, Arc<HostOperationGuard>, HostOperationSupervisor), OriginalActorAccountError>
    {
        let (origin, evidence) = invocation.split_for_actor()?;
        let partition = evidence.actor_partition();
        let accounts = HostServiceBootstrap::new(
            partition.tasks(),
            partition.descriptors(),
            partition.resident_bytes(),
            partition.metadata_bytes(),
        )?;
        let original = HostSupervisionBootstrap::from_measurement_origin(
            origin,
            partition.operation_budgets(),
        )?;

        let admitted = accounts.reserve_structure(Self::initial_structure_bytes()?)?;
        let (supervisor, preparation) = original.publish(&admitted)?;
        let (resident, metadata) = admitted.publish();
        let preparation = Arc::new(preparation);
        let capture_preparation = Arc::clone(&preparation);
        let capture_supervisor = supervisor.clone();
        let custody = Self {
            held: Some(PublishedAccounts {
                preparation,
                _supervisor: supervisor,
                resident,
                metadata,
                evidence,
                native_roster_published: false,
            }),
        };

        // The complete record owns both banks before this actual postcheck.
        // Its refusal cannot refund controls still retained by capture aliases.
        custody.require_original()?;
        Ok((custody, capture_preparation, capture_supervisor))
    }

    /// Returns this target's once-charged initial publication structure.
    ///
    /// Native, factory, Source-pool, watcher and quarantine extents are separate
    /// purposes. Metadata is a subset of physical residency, not extra memory.
    ///
    /// # Errors
    /// Refuses target layout or byte-count overflow.
    pub fn initial_structure_bytes() -> Result<u64, OriginalActorAccountError> {
        let (guard, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<HostOperationGuard>())
        .map_err(|_| HostServiceError::CapacityExhausted)?;
        let guard = u64::try_from(guard.pad_to_align().size())
            .map_err(|_| HostServiceError::CapacityExhausted)?;
        let roster = OriginalNativeAccountRoster::allocation_extent()?;
        HostSupervisionBootstrap::structure_bytes()?
            .checked_add(HostServiceBootstrap::control_bytes()?)
            .and_then(|bytes| bytes.checked_add(guard))
            .and_then(|bytes| bytes.checked_add(roster))
            .ok_or_else(|| HostServiceError::CapacityExhausted.into())
    }

    /// Checks the same retained original without exposing its owner or banks.
    ///
    /// # Errors
    /// Preserves original expiry, cancellation, terminal state and unavailable
    /// supervision. Missing consumed custody refuses without a replacement.
    pub fn require_original(&self) -> Result<(), OriginalActorAccountError> {
        let held = self
            .held
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        held.preparation.wait_slice()?;
        Ok(())
    }

    /// Opens a decode budget from the same published original actor banks.
    ///
    /// The authenticated metadata subset bounds this finite decode. Every
    /// actual parser/output allocation still requires an admitted charge;
    /// neither a format byte limit nor this owner certifies complete decoding.
    ///
    /// # Errors
    /// Refuses missing custody, original expiry/cancellation, target control
    /// geometry or either original account before any decode publication.
    pub fn prepare_decode_owner(
        &self,
    ) -> Result<OriginalActorDecodeOwner, OriginalActorAccountError> {
        self.require_original()?;
        let held = self
            .held
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        OriginalActorDecodeOwner::prepare(
            &held.preparation,
            &held.resident,
            &held.metadata,
            held.evidence.actor_partition().metadata_bytes(),
        )
    }

    /// Reserves the certified FULL residency and TOTAL metadata account pair.
    ///
    /// This external credit cannot authorize a process, backing or domain.
    /// The genuine used factory must retain it outside its native state through
    /// physical retirement and actual control deallocation. No caller amount
    /// selects the extents or creates a new account.
    ///
    /// # Errors
    /// Refuses either original counter or the same original before and after
    /// reservation. A post-refusal retains the newly admitted pair.
    fn reserve_native_account_credit(
        &self,
    ) -> Result<OriginalNativeAccountCredit, OriginalActorAccountError> {
        self.require_original()?;
        let held = self
            .held
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let partition = held.evidence.actor_partition();
        let native = partition.capture_stage();
        let reserved = held.resident.reserve_native_pair(
            &held.metadata,
            native.tasks(),
            native.descriptors(),
            native.resident_bytes(),
            native.metadata_bytes(),
        );
        let (resident, metadata) = match reserved {
            Ok(pair) => pair,
            Err(source) => {
                return Err(OriginalActorAccountError::NativeAccountBoundary {
                    source,
                    original: held.preparation.wait_slice().err(),
                });
            }
        };
        let credit = OriginalNativeAccountCredit {
            original: Some(RetainedNativeCredit {
                _pair: HostServiceLeasePair::new(resident, metadata),
                preparation: Arc::clone(&held.preparation),
            }),
            full_resident_bytes: native.resident_bytes(),
            full_backing_bytes: native.backing_bytes(),
            total_metadata_bytes: native.metadata_bytes(),
        };
        self.require_original()?;
        Ok(credit)
    }

    /// Retains the fixed native pairs outside the genuine factory allocation.
    ///
    /// The authenticated invocation selects one, two or four slots. The roster
    /// allocation was charged before actor publication, and every pair is
    /// admitted before that allocation is constructed. A partial refusal keeps
    /// admitted pairs and permanently consumes this once-only publication.
    /// This account binding supplies no backing, Source or birth permission.
    ///
    /// # Errors
    /// Refuses repeated publication, missing custody, any original pair, target
    /// geometry, or the same preparation before and after publication.
    pub fn prepare_native_account_roster(
        &mut self,
    ) -> Result<
        (
            OriginalNativeAccountRoster,
            OriginalNativeAccountFactoryBinding,
        ),
        OriginalActorAccountError,
    > {
        self.require_original()?;
        let held = self
            .held
            .as_mut()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if held.native_roster_published {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let width = usize::from(held.evidence.actor_partition().worker_stage().width());
        if !matches!(width, 1 | 2 | 4) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        held.native_roster_published = true;

        let mut credits = std::array::from_fn(|_| None);
        for slot in credits.iter_mut().take(width) {
            *slot = Some(self.reserve_native_account_credit()?);
        }
        let published = OriginalNativeAccountRoster::publish(credits, width)?;
        self.require_original()?;
        Ok(published)
    }
}

impl Drop for OriginalActorAccountCustody {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            std::mem::forget(held);
        }
    }
}

/// Retains the actual original native pair outside its future native allocation.
///
/// These immutable extents describe the pair; they do not certify Source,
/// domain installation, process birth, or a ResearchResident launch permission.
/// No numeric constructor or caller-supplied cleanup flag can release it.
#[must_use = "retain external paired native credit through actual control free"]
pub(super) struct OriginalNativeAccountCredit {
    original: Option<RetainedNativeCredit>,
    full_resident_bytes: u64,
    full_backing_bytes: u64,
    total_metadata_bytes: u64,
}

struct RetainedNativeCredit {
    _pair: HostServiceLeasePair,
    preparation: Arc<HostOperationGuard>,
}

impl OriginalNativeAccountCredit {
    pub(super) fn verify_preparation(
        &self,
        preparation: &Arc<HostOperationGuard>,
    ) -> Result<(), OriginalActorAccountError> {
        let retained = self
            .original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if !Arc::ptr_eq(&retained.preparation, preparation) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.require_original()
    }

    #[cfg(test)]
    pub(super) fn mechanism_credit(
        preparation: Arc<HostOperationGuard>,
    ) -> Result<(Self, HostServiceAllocator, HostServiceAllocator), HostServiceError> {
        let resident = HostServiceAllocator::new(69, 1056, 1536 << 20)?;
        let metadata = HostServiceAllocator::new(1, 1, 512 << 20)?;
        let (first, second) =
            resident.reserve_native_pair(&metadata, 69, 1056, 1536 << 20, 512 << 20)?;
        Ok((
            Self {
                original: Some(RetainedNativeCredit {
                    _pair: HostServiceLeasePair::new(first, second),
                    preparation,
                }),
                full_resident_bytes: 1536 << 20,
                full_backing_bytes: 4 << 30,
                total_metadata_bytes: 512 << 20,
            },
            resident,
            metadata,
        ))
    }

    pub(super) fn begin_cleanup(&self) -> Result<HostOperationGuard, OriginalActorAccountError> {
        Ok(self
            .original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .preparation
            .begin_original_cleanup_control()?)
    }

    /// Checks the same preparation retained with this external credit.
    ///
    /// # Errors
    /// Refuses missing consumed custody or the original operation's sticky
    /// cancellation, expiration, terminal state or unavailable synchronization.
    pub fn require_original(&self) -> Result<(), OriginalActorAccountError> {
        self.original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .preparation
            .wait_slice()?;
        Ok(())
    }

    /// Returns the original FULL resident extent.
    #[must_use]
    pub const fn full_resident_bytes(&self) -> u64 {
        self.full_resident_bytes
    }

    /// Returns the authored FULL backing requirement, not a backing grant.
    #[must_use]
    pub const fn full_backing_bytes(&self) -> u64 {
        self.full_backing_bytes
    }

    /// Returns TOTAL metadata before native control and allowance subtraction.
    #[must_use]
    pub const fn total_metadata_bytes(&self) -> u64 {
        self.total_metadata_bytes
    }
}

impl Drop for OriginalNativeAccountCredit {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            std::mem::forget(original);
        }
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- this real loan/drop mechanism control panics when unsettled external paired credit or its same guard is prematurely released; it creates no parent certificate or launch permission.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationClass};

    #[test]
    fn unsettled_drop_and_unwind_keep_both_original_charges_and_the_same_guard() {
        for unwind in [false, true] {
            let resident = HostServiceAllocator::new(69, 1056, 1536 << 20).unwrap();
            let metadata = HostServiceAllocator::new(1, 1, 512 << 20).unwrap();
            let supervisor =
                HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
            let preparation = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
            let witness = Arc::downgrade(&preparation);
            let (resident_lease, metadata_lease) = resident
                .reserve_native_pair(&metadata, 69, 1056, 1536 << 20, 512 << 20)
                .unwrap();
            let credit = OriginalNativeAccountCredit {
                original: Some(RetainedNativeCredit {
                    _pair: HostServiceLeasePair::new(resident_lease, metadata_lease),
                    preparation,
                }),
                full_resident_bytes: 1536 << 20,
                full_backing_bytes: 4 << 30,
                total_metadata_bytes: 512 << 20,
            };

            if unwind {
                let result = std::panic::catch_unwind(move || {
                    let _retained = credit;
                    panic!("actual unwind while native retirement is uncertain");
                });
                assert!(result.is_err());
            } else {
                drop(credit);
            }

            assert!(matches!(
                resident.reserve_resources(0, 0, 1),
                Err(HostServiceError::CapacityExhausted)
            ));
            assert!(matches!(
                metadata.reserve_resources(0, 0, 1),
                Err(HostServiceError::CapacityExhausted)
            ));
            assert!(witness.upgrade().is_some());
        }
    }
}
