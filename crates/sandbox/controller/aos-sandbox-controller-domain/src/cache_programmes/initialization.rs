//! Retains upper Cache programmes around the single native Cache initializer.
//!
//! The native owner keeps all five writers, physical state, Clock and exact
//! native first causes. This coordinator retains only Controller acquisition
//! results and the semantic Q04/CreateStorage programmes that also borrow the
//! genuine Controller, Source and Root owners.

use std::sync::{Arc, Mutex};

use aos_sandbox_cache::{
    CacheResidentInitializationV1 as NativeCacheInitializationV1,
    CacheResidentUnavailableV1, CacheResidencyProtectedOwnerV1, DormantCacheOwnerV1,
};
use aos_sandbox_model::{NodeId, ResourceVector};

use crate::Journal;
use crate::controller_resource_reservation::{
    ControllerResourceBankOpeningV1, ResourceReservationErrorV1,
};
use crate::normal_root::ProductionControllerNormalRootProfileV1;

pub(crate) mod original_q04;
pub(crate) mod q04_capture_pricing;
pub(crate) mod create_storage;
pub use create_storage::{CacheDeleteInventoryOriginalV1, CacheDeleteInventoryQueryV1};

/// Retains the actual upper programmes beside the sole native Cache owner.
///
/// This contains no Journal, descriptor, payer, native Clock or reconstructed
/// replacement owner. Native-only operations explicitly use the same native
/// original; Q04 and CreateStorage retain their upper semantic results here.
#[derive(Default)]
pub struct CacheResidentInitializationV1 {
    pub(crate) native: NativeCacheInitializationV1,
    pub(crate) construction_entries: [Option<Result<(), ResourceReservationErrorV1>>; 2],
    construction_supplement: Option<Result<ResourceVector, crate::JournalError>>,
    pub(crate) q04: original_q04::Q04UpperProgressV1,
    pub(crate) create_storage_held: create_storage::CacheHeldUpperProgressV1,
}

impl CacheResidentInitializationV1 {
    /// Creates empty programme destinations before any actual native entry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reports whether the single selected native initialization has started.
    #[must_use]
    pub fn started(&self) -> bool {
        self.native.started()
    }

    /// Borrows the sole native Cache original for native-only operations.
    ///
    /// The native owner has no public writer, descriptor, map, Clock-state or
    /// supplied-parts constructor. Upper semantic failures also fence their
    /// original native programme, so this cannot reset failed custody.
    #[doc(hidden)]
    pub fn native_original_v1(&mut self) -> &mut NativeCacheInitializationV1 {
        &mut self.native
    }

    /// Initializes the same selected Cache through the actual Bank/C interval.
    ///
    /// # Errors
    /// Retains the actual Bank acquisition refusal and all native body/posts.
    /// Occupied destinations refuse before the genuine Bank loan is armed.
    pub fn initialize_selected_once(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        owner_uid: u32,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.native.started() || self.construction_entries[0].is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.native.require_selected_initialization_entry_v1(destination)?;
        let bank = match bank.lock() {
            Ok(bank) => bank,
            Err(_) => {
                self.construction_entries[0] = Some(Err(ResourceReservationErrorV1::Conflict));
                self.native.refuse_controller_construction_v1();
                return Err(CacheResidentUnavailableV1);
            }
        };
        let mut loan = match bank.borrow_cache_current_v1(controller, profile) {
            Ok(loan) => loan,
            Err(cause) => {
                self.construction_entries[0] = Some(Err(cause));
                self.native.refuse_controller_construction_v1();
                return Err(CacheResidentUnavailableV1);
            }
        };
        self.construction_entries[0] = Some(Ok(()));
        // Quote evaluation has no effects. Its error remains upper and is
        // selected only if native entry reaches that original prefix frontier.
        self.construction_supplement = Some(crate::journal::cache_native_semantic_supplement_v1());
        let supplement = self.construction_supplement.as_ref()
            .and_then(|quote| quote.as_ref().ok()).copied();
        self.native.initialize_with_current_loan_once(destination, owner_uid, &mut loan, supplement, upper_cache_construction_control_bytes_v1())
    }

    /// Captures physical Cache under its same actual Bank/C conjunction.
    ///
    /// # Errors
    /// Retains upper acquisition errors and native capture, debit and owed posts.
    /// Refuses reentry before arming another independently owed C interval.
    pub fn prepare_existing_physical_owner_selected(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        destination: &mut Option<DormantCacheOwnerV1>,
        node: NodeId,
        maximum_memory_bytes: u64,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.construction_entries[1].is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.native.require_selected_physical_entry_v1()?;
        let bank = match bank.lock() {
            Ok(bank) => bank,
            Err(_) => {
                self.construction_entries[1] = Some(Err(ResourceReservationErrorV1::Conflict));
                self.native.refuse_controller_construction_v1();
                return Err(CacheResidentUnavailableV1);
            }
        };
        let mut loan = match bank.borrow_cache_current_v1(controller, profile) {
            Ok(loan) => loan,
            Err(cause) => {
                self.construction_entries[1] = Some(Err(cause));
                self.native.refuse_controller_construction_v1();
                return Err(CacheResidentUnavailableV1);
            }
        };
        self.construction_entries[1] = Some(Ok(()));
        self.native.prepare_existing_with_current_loan_once(
            owner, destination, node, maximum_memory_bytes, &mut loan,
        )
    }
}



impl CacheResidentInitializationV1 {
    /// Borrows the selected original cause without moving any owning result.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.construction_entries.iter()
            .find_map(|slot| slot.as_ref().and_then(|result| result.as_ref().err()))
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.q04.failure(&self.native))
            .or_else(|| self.create_storage_held.failure(&self.native))
            .or_else(|| {
                self.native.construction_semantic_supplement_failure_is_selected_v1()
                    .then(|| self.construction_supplement.as_ref()?.as_ref().err()
                        .map(|cause| cause as &(dyn std::error::Error + 'static)))
                    .flatten()
            })
            .or_else(|| self.native.failure())
    }
}

// Both C1 entry routes pass this same additional Memory-only control bound to
// the existing Bootstrap native highwater before its first actual acquisition.
// Resident wrapper fields remain in their original complete header invoice.
pub(crate) const fn upper_cache_construction_control_bytes_v1() -> usize {
    std::mem::size_of::<(
        // The actual upper supplement return and its assignment expression.
        // The retained field is in the complete upper header, separately.
        [Result<ResourceVector, crate::JournalError>; 2],
        // The two entry programmes have the same local/argument supplement
        // planes and pure bound return/caller argument; take their common max.
        (Option<ResourceVector>, Option<ResourceVector>),
        (usize, usize),
        // The selected import returns the canonical report directly. Its
        // native return and upper match retain the owning borrowed-error ABI;
        // the upper match and final branch each have an Option report plane.
        [Result<aos_sandbox_broker::canonical_journal::RecoveryReport,
            &(dyn std::error::Error + 'static)>; 2],
        [Option<aos_sandbox_broker::canonical_journal::RecoveryReport>; 2],
    )>()
}
