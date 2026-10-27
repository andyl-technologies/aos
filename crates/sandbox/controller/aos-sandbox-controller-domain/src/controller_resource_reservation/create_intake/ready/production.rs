//! Keeps the same private J and initialized Cache loans through upper Create work.
//!
//! Native cannot depend on Security. This opaque joined scope therefore lets
//! the actual installed upper coordinator retain both genuine borrowers while
//! Security retains its authenticated Sessions and complete flight results.
//! Private child purposes borrow this same scope; no raw writer, resource
//! amount, caller identity or decoded history can construct another original.

use std::error::Error;

use crate::cache_programmes::{CacheResidentInitializationV1, OriginalCreateStorageCacheLoanV1};
use aos_sandbox_cache::{CacheResidencyProtectedOwnerV1, DormantCacheOwnerV1};

use super::*;

/// Reports a closed original Ready stage while its actual owners remain resident.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("original Create Ready stage is closed; its actual custody remains resident")]
pub struct CreateStorageReadyClosedV1;

/// Borrows the actual original Create, Source and initialized Cache together.
///
/// This scope is neither Ready nor a policy/signing grant. Its actual upper
/// caller must retain it through every purpose-specific flight and all terminal
/// release posts. It exposes no Journal, resource account or raw-loan factory.
#[doc(hidden)]
#[must_use = "retain the genuine joined originals through the complete bounded Create exchange"]
pub struct OriginalCreateStorageReadyV1<'original, 'cache> {
    pub(super) original: CreateStorageOriginalLoanV1<'original>,
    pub(super) cache: OriginalCreateStorageCacheLoanV1<'cache>,
    association: Option<Result<(), ResourceReservationErrorV1>>,
    cache_production: Option<Result<(), aos_sandbox_cache::CacheHeldClosedV1>>,
}

impl CreateContinuationIntakeAttemptV1 {
    /// Borrows the same completed J and initialized Cache originals once.
    ///
    /// This fixed entrance performs allocation-free retained-cut validation;
    /// it performs no observation, allocation, variable decoding, signing or
    /// append. Capture and variable work remain behind the existing genuine
    /// J admissions of this same scope. It does not finish a Root exchange.
    ///
    /// # Errors
    /// Refuses incomplete or failed original J/Intent/SourceHeld, another
    /// Controller/Source/profile, uninitialized or foreign Cache, or reentry.
    /// Any earlier genuine owners remain in their existing destinations. A
    /// joined Q04 association refusal remains in the returned closed scope;
    /// [`OriginalCreateStorageReadyV1::failure`] exposes it before any capture.
    #[doc(hidden)]
    pub fn borrow_original_ready_once<'original, 'cache>(
        &'original mut self,
        controller: &'original mut Journal,
        source: &'original mut ProtectedSourceDomainJournalOwnerV1,
        profile: &'original ProductionControllerNormalRootProfileV1,
        initialization: &'cache mut CacheResidentInitializationV1,
        cache: &'cache mut CacheResidencyProtectedOwnerV1,
        physical: &'cache DormantCacheOwnerV1,
    ) -> Result<OriginalCreateStorageReadyV1<'original, 'cache>, CreateStorageReadyClosedV1> {
        let original = self.borrow_create_storage_original_once(controller, source, profile)
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let cache = initialization.borrow_create_storage_cache_once(cache, physical)
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let association = (|| {
            let identity = cache.original_q04_identity_data_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            if !original.owner.parent.matches_create_continuation_identity(&identity) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })();
        // Store the whole comparison beside both genuine borrowers before any
        // projection; a mismatch cannot drop an armed Cache loan on return.
        Ok(OriginalCreateStorageReadyV1 {
            original, cache, association: Some(association), cache_production: None,
        })
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Produces the actual same-J Cache Held stage once through its shared engine.
    ///
    /// # Errors
    /// Retains the actual fixed/captured/semantic admissions, Native audit,
    /// selection, encoding, append/readback and independent currentness failures.
    /// The caller must fence with this scope and upper native originals resident;
    /// a returned error does not permit dropping or replacing the failed loans.
    pub fn produce_cache_held_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.cache_production.is_some() || self.failure().is_some()
            || !matches!(self.association, Some(Ok(()))) {
            return Err(CreateStorageReadyClosedV1);
        }
        self.cache_production = Some(self.cache.produce_held_once(&mut self.original));
        if self.failure().is_none() && matches!(self.cache_production, Some(Ok(()))) {
            Ok(())
        } else {
            Err(CreateStorageReadyClosedV1)
        }
    }

    /// Commits the same original's first immutable AssignmentPlanned proposal.
    ///
    /// The method derives every manifest field from retained accepted inputs,
    /// the genuine enrolled Node, original child capacity and live held Cache.
    /// It issues neither an Ownership lease nor InputsReady or a signing grant.
    ///
    /// # Errors
    /// Refuses incomplete Cache/J association, reentry, existing assignment
    /// history, changed Source ancestry or failed admission, model, Native or
    /// independent after observations. All original results remain resident.
    pub fn produce_assignment_planned_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() || !matches!(self.cache_production, Some(Ok(())))
            || self.original.owner.assignment.started() {
            return Err(CreateStorageReadyClosedV1);
        }
        let identity = self.cache.original_q04_identity_data_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict);
        self.original.owner.assignment.retain_q04_association_once(identity, &self.original.owner.parent)
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let mut cache = self.cache.borrow_pre_root_cut_v1().map_err(|_| CreateStorageReadyClosedV1)?;
        let owner = &mut *self.original.owner;
        owner.assignment.produce_once(&owner.parent, &mut owner.intake, &owner.histories,
            self.original.controller, self.original.source, self.original.profile, &mut cache)
            .map_err(|_| CreateStorageReadyClosedV1)
    }

    /// Borrows the actual first retained Native cause without releasing originals.
    ///
    /// Upper diagnostics must also retain and project the actual Security flight
    /// at its chronological stage; this borrow supplies no currentness authority.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.association.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.original.owner.parent.failure())
            .or_else(|| self.original.owner.intake.failure())
            .or_else(|| self.original.owner.histories.failure())
            .or_else(|| self.original.owner.cache_capture.funding_failure())
            .or_else(|| if self.original.owner.storage_use.release.funding_failure_is_selected_v1() {
                self.original.owner.storage_use.failure()
            } else { None })
            .or_else(|| self.original.owner.storage_use.selected_terminal_control_failure_v1())
            .or_else(|| self.cache.failure())
            .or_else(|| self.original.owner.cache_capture.failure())
            .or_else(|| self.original.owner.assignment.failure())
            .or_else(|| self.original.owner.client_session.failure())
            .or_else(|| self.original.owner.inventory.failure())
            .or_else(|| self.original.owner.bundle.failure())
            .or_else(|| if self.original.owner.root_exchange.use_tail_funding_failure_is_selected_v1() {
                self.original.owner.storage_use.failure()
            } else { None })
            .or_else(|| self.original.owner.storage_use.release.selected_primary_failure_v1())
            .or_else(|| self.original.owner.storage_use.selected_handoff_primary_failure_v1())
            .or_else(|| self.original.owner.root_exchange.failure())
            .or_else(|| self.original.owner.storage_use.failure())
            .or_else(|| self.cache_production.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
    }
}
