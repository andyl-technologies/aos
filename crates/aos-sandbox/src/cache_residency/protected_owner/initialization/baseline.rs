//! Prices Cache construction through its real paired or confirmed C interval.
//!
//! The scoped adapter borrows only the two closed lower loans. Its permanent
//! companion keeps already-paid highwaters and an inert completed association;
//! it cannot enter a scope, increase a budget, or lend a Controller writer.

use super::*;
use std::cell::RefCell;
use std::sync::{Mutex, OnceLock};
use aos_sandbox_core::ResourceVector;
use aos_sandbox_broker::controller_receiving::{
    ControllerCachePreBankImportLoanV1,
    bank_launch::{ControllerBankLaunchErrorV1, ControllerCacheConstructionLoanV1,
        CacheControllerOriginalRefV1},
};
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::journal::ProtectedWriterOpenOriginalsV1;
use crate::cache_residency::recovery::{
    CacheReplayRepresentationPhaseV1, RecoveryError, general_replay_representation_bound_v1,
};
use crate::cache_residency::protected_owner::manifest_geometry::CacheReplayManifestGeometryV1;

/// Selects one fixed representation owner, never a grant or a native recipe.
#[derive(Clone, Copy)]
pub(in crate::cache_residency) enum CacheConstructionOwnerV1 {
    CacheBootstrapNative,
    CacheHoldNative,
    CacheClockNative,
    CacheAuthorityNative,
    CacheStateNative,
    ImportModels,
    CacheSourceModels,
    CacheAuthorityModels,
    CachePhysical,
}

pub(in crate::cache_residency) struct CacheConstructionOriginalsV1 {
    original: OnceLock<CacheControllerOriginalRefV1>,
    paid: Mutex<[ResourceVector; 9]>,
    failure: OnceLock<Result<(), ResourceReservationErrorV1>>,
    receiving_failure: OnceLock<Result<(), ControllerBankLaunchErrorV1>>,
    semantic_failure: OnceLock<Result<(), InitializationCauseV1>>,
}

impl CacheConstructionOriginalsV1 {
    pub(in crate::cache_residency) fn new() -> Self {
        Self {
            original: OnceLock::new(), paid: Mutex::new([ResourceVector::ZERO; 9]),
            failure: OnceLock::new(), receiving_failure: OnceLock::new(),
            semantic_failure: OnceLock::new(),
        }
    }

    // This is an existing-paid-bound comparison only. A larger peak must pass
    // the live closed loan below; a different active C purpose cannot fund it.
    pub(super) fn require(&self, owner: CacheConstructionOwnerV1, complete: ResourceVector)
        -> Result<(), InitializationCauseV1>
    {
        if self.failure().is_some() { return Err(InitializationCauseV1::Baseline); }
        let returned = self.paid.try_lock().map_err(|_| ResourceReservationErrorV1::Conflict)
            .and_then(|paid| paid[owner as usize].checked_sub(complete)
                .map(|_| ()).map_err(ResourceReservationErrorV1::from));
        if returned.is_err() {
            if self.failure.set(returned).is_err() { std::process::abort(); }
            return Err(InitializationCauseV1::Baseline);
        }
        Ok(())
    }

    pub(in crate::cache_residency) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        retained_error(self.failure.get())
            .or_else(|| retained_error(self.receiving_failure.get()))
            .or_else(|| retained_error(self.semantic_failure.get()))
    }

    pub(in crate::cache_residency) fn matches_original(
        &self,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
    ) -> bool {
        self.original.get().is_some_and(|held| profile.matches_cache_original_data_v1(held))
    }

    pub(in crate::cache_residency) fn require_import_complete(&self, complete: ResourceVector)
        -> Result<(), InitializationCauseV1>
    {
        self.require(CacheConstructionOwnerV1::ImportModels, complete)
    }

    pub(in crate::cache_residency) fn require_physical_complete(&self, complete: ResourceVector)
        -> Result<(), InitializationCauseV1>
    {
        self.require(CacheConstructionOwnerV1::CachePhysical, complete)
    }

    pub(in crate::cache_residency) fn require_manifest(&self, journal: &Journal, source: bool)
        -> Result<(), InitializationCauseV1>
    {
        let (owner, complete) = manifest_bound(journal, source)?;
        self.require(owner, complete)
    }

    pub(in crate::cache_residency) fn require_initial_inventory_protected(
        &self, authority: &Journal, state: &Journal,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        if self.failure().is_some() { return Err(ProtectedDomainJournalErrorV1::StaleAuthority); }
        let returned = inventory_bound(authority, state)
            .and_then(|complete| self.require(CacheConstructionOwnerV1::CacheAuthorityModels, complete));
        if returned.is_err() {
            if self.semantic_failure.set(returned).is_err() { std::process::abort(); }
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }
}

fn manifest_bound(journal: &Journal, source: bool)
    -> Result<(CacheConstructionOwnerV1, ResourceVector), InitializationCauseV1>
{
        let limits = CacheRecoveryLimitsV1::default();
        let geometry = if source {
            CacheReplayManifestGeometryV1::from_source_journal(journal, limits)
        } else {
            CacheReplayManifestGeometryV1::from_authority_journal(journal, limits)
        }.map_err(InitializationCauseV1::Recovery)?;
        let complete = match geometry.genesis_manifest_validation_bound()
            .map_err(InitializationCauseV1::Recovery)?
        {
            Some(complete) => complete,
            None => general_replay_representation_bound_v1(
                geometry.encoded_bytes(), geometry.partition_bound(),
                CacheReplayRepresentationPhaseV1::ManifestValidation,
            ).map_err(InitializationCauseV1::Recovery)?,
        };
        Ok((if source { CacheConstructionOwnerV1::CacheSourceModels } else { CacheConstructionOwnerV1::CacheAuthorityModels },
            complete.checked_add(additional_raw_owner_bound(journal)?).map_err(|_|
                InitializationCauseV1::Recovery(RecoveryError::Capacity))?))
}

fn inventory_bound(authority: &Journal, state: &Journal) -> Result<ResourceVector, InitializationCauseV1> {
        let geometry = CacheReplayManifestGeometryV1::from_initial_journals(
            authority, state, CacheRecoveryLimitsV1::default(),
        ).map_err(InitializationCauseV1::Recovery)?;
        let complete = match geometry.genesis_initial_inventory_bound()
            .map_err(InitializationCauseV1::Recovery)?
        {
            Some(complete) => complete,
            None => general_replay_representation_bound_v1(
                geometry.encoded_bytes(), geometry.partition_bound(),
                CacheReplayRepresentationPhaseV1::InitialInventory,
            ).map_err(InitializationCauseV1::Recovery)?,
        };
        complete.checked_add(additional_raw_owner_bound(authority)?).map_err(|_|
            InitializationCauseV1::Recovery(RecoveryError::Capacity))

}

// Both variants are actual closed lenders. No caller-defined payer, trait,
// account, provision vector or original Arc can construct this adapter.
enum ConstructionLender<'borrow, 'writer, 'launch, 'profile, P> {
    Confirmed(&'borrow mut ControllerCacheConstructionLoanV1<'writer, 'launch, 'profile, P>),
    Import(&'borrow mut ControllerCachePreBankImportLoanV1<'profile>),
}

pub(in crate::cache_residency) struct CacheConstructionReceivingV1<'borrow, 'writer, 'launch, 'profile, P> {
    originals: &'borrow CacheConstructionOriginalsV1,
    lender: RefCell<ConstructionLender<'borrow, 'writer, 'launch, 'profile, P>>,
}

impl<'borrow, 'writer, 'launch, 'profile, P> CacheConstructionReceivingV1<'borrow, 'writer, 'launch, 'profile, P> {
    fn confirmed(
        originals: &'borrow CacheConstructionOriginalsV1,
        loan: &'borrow mut ControllerCacheConstructionLoanV1<'writer, 'launch, 'profile, P>,
    ) -> Self {
        Self { originals, lender: RefCell::new(ConstructionLender::Confirmed(loan)) }
    }

    pub(in crate::cache_residency) fn import(
        originals: &'borrow CacheConstructionOriginalsV1,
        loan: &'borrow mut ControllerCachePreBankImportLoanV1<'profile>,
    ) -> Self {
        Self { originals, lender: RefCell::new(ConstructionLender::Import(loan)) }
    }

    pub(in crate::cache_residency) fn require(
        &self,
        owner: CacheConstructionOwnerV1,
        complete: ResourceVector,
    ) -> Result<(), InitializationCauseV1> {
        if self.originals.failure().is_some() { return Err(InitializationCauseV1::Baseline); }
        let returned = (|| {
            let mut lender = self.lender.try_borrow_mut()
                .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            match &mut *lender {
                ConstructionLender::Confirmed(loan) => match owner {
                    CacheConstructionOwnerV1::CacheBootstrapNative => loan.require_bootstrap_native_complete(complete),
                    CacheConstructionOwnerV1::CacheHoldNative => loan.require_hold_native_complete(complete),
                    CacheConstructionOwnerV1::CacheClockNative => loan.require_clock_native_complete(complete),
                    CacheConstructionOwnerV1::CacheAuthorityNative => loan.require_authority_native_complete(complete),
                    CacheConstructionOwnerV1::CacheStateNative => loan.require_state_native_complete(complete),
                    CacheConstructionOwnerV1::ImportModels => loan.require_import_models_complete(complete),
                    CacheConstructionOwnerV1::CacheSourceModels => loan.require_source_models_complete(complete),
                    CacheConstructionOwnerV1::CacheAuthorityModels => loan.require_authority_models_complete(complete),
                    CacheConstructionOwnerV1::CachePhysical => loan.require_physical_complete(complete),
                },
                ConstructionLender::Import(loan) => match owner {
                    CacheConstructionOwnerV1::CacheBootstrapNative => loan.require_bootstrap_native_complete(complete)
                        .map_err(ControllerBankLaunchErrorV1::from),
                    CacheConstructionOwnerV1::ImportModels => loan.require_import_models_complete(complete)
                        .map_err(ControllerBankLaunchErrorV1::from),
                    _ => Err(ControllerBankLaunchErrorV1::Conflict),
                },
            }?;
            let mut paid = self.originals.paid.try_lock()
                .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            // A monotone DATA mirror permits only later comparisons against an
            // amount that this exact genuine interval actually debited.
            paid[owner as usize] = paid[owner as usize].componentwise_max(complete);
            Ok(())
        })();
        if returned.is_err() {
            if self.originals.receiving_failure.set(returned).is_err() { std::process::abort(); }
            return Err(InitializationCauseV1::Baseline);
        }
        Ok(())
    }

    pub(in crate::cache_residency) fn require_import_complete(&self, complete: ResourceVector)
        -> Result<(), InitializationCauseV1>
    {
        self.require(CacheConstructionOwnerV1::ImportModels, complete)
    }

    pub(in crate::cache_residency) fn require_manifest(&self, journal: &Journal, source: bool)
        -> Result<(), InitializationCauseV1>
    {
        let (owner, complete) = manifest_bound(journal, source)?;
        self.require(owner, complete)
    }

    pub(in crate::cache_residency) fn require_initial_inventory_protected(&self, authority: &Journal, state: &Journal)
        -> Result<(), CacheResidencyProtectedJournalErrorV1>
    {
        if self.originals.failure().is_some() { return Err(ProtectedDomainJournalErrorV1::StaleAuthority); }
        let returned = self.require_initial_inventory(authority, state);
        if returned.is_err() {
            if self.originals.semantic_failure.set(returned).is_err() { std::process::abort(); }
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }

    pub(in crate::cache_residency) fn require_initial_inventory(&self, authority: &Journal, state: &Journal)
        -> Result<(), InitializationCauseV1>
    {
        self.require(CacheConstructionOwnerV1::CacheAuthorityModels, inventory_bound(authority, state)?)
    }

    pub(in crate::cache_residency) fn require_physical_complete(&self, complete: ResourceVector)
        -> Result<(), InitializationCauseV1>
    {
        self.require(CacheConstructionOwnerV1::CachePhysical, complete)
    }
}

pub(in crate::cache_residency) struct CacheNativeStageV1 {
    opening: ProtectedWriterOpenOriginalsV1,
    preparation: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    prefix: Option<Result<(), ResourceReservationErrorV1>>,
    names: Option<Result<(), JournalError>>,
    names_original: crate::journal::ProtectedJournalCurrentnessOriginalsV1,
}

impl CacheNativeStageV1 {
    pub(in crate::cache_residency) fn new() -> Self {
        Self { opening: ProtectedWriterOpenOriginalsV1::new(), preparation: None, prefix: None, names: None,
            names_original: crate::journal::ProtectedJournalCurrentnessOriginalsV1::new() }
    }

    pub(in crate::cache_residency) fn open_once<P>(
        &mut self,
        loan: &CacheConstructionReceivingV1<'_, '_, '_, '_, P>,
        owner: CacheConstructionOwnerV1,
        root: &Path,
        name: &'static str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
    ) -> Result<(Journal, RecoveryReport), InitializationCauseV1> {
        if self.preparation.is_some() {
            return Err(InitializationCauseV1::Closed);
        }
        self.preparation = Some((|| {
            let capacity = || ResourceReservationErrorV1::EnrollmentUnavailable;
            // The held hierarchy and independent reopened name hierarchy can
            // coexist on a negative post; include both before the first IO.
            let descriptors = root.components().count().checked_add(1)
                .and_then(|count| count.checked_mul(2))
                .and_then(|count| u16::try_from(count).ok()).ok_or_else(capacity)?;
            let bytes = root.as_os_str().as_encoded_bytes().len().checked_add(name.len())
                .and_then(|bytes| u16::try_from(bytes).ok()).ok_or_else(capacity)?;
            let fixed = ProtectedWriterOpenOriginalsV1::fixed_writable_preparation_demand_v1::<Self>(descriptors, bytes)?;
            loan.require(owner, fixed).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            Ok(fixed)
        })());
        let fixed = self.preparation.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(InitializationCauseV1::Baseline)?;
        let primary = (|| {
            self.opening.prepare_captured_for_uid_once(root, name, limits, uid, allow_create);
            if self.opening.failure().is_some() {
                return Err(InitializationCauseV1::Baseline);
            }
            self.prefix = Some((|| {
                let variable = self.opening.prepared_extent()
                    .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .dominant_native_receiving_demand_v1()?;
                loan.require(owner, fixed.checked_add(variable)?)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)
            })());
            if !matches!(self.prefix, Some(Ok(()))) {
                return Err(InitializationCauseV1::Baseline);
            }
            self.opening.replay_prepared_once();
            if !self.opening.captured_opened_ready() {
                return Err(InitializationCauseV1::Baseline);
            }
            Ok(())
        })();
        // Funding preceded this actual native operation, so its independent
        // name post still executes after primary failure without a new grant.
        self.names = Some(self.opening.check_named_currentness_retaining(root, name, limits, uid, &mut self.names_original));
        primary?;
        if !matches!(self.names, Some(Ok(()))) {
            return Err(InitializationCauseV1::Baseline);
        }
        self.opening.take_captured_opened().ok_or(InitializationCauseV1::Closed)
    }

    pub(in crate::cache_residency) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.preparation.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.opening.failure())
            .or_else(|| self.prefix.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.names_original.failure())
            .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}


pub(super) struct CacheSelectedInitializationV1 {
    pub(super) originals: CacheConstructionOriginalsV1,
    pub(super) stages: [CacheNativeStageV1; 5],
    entries: [Option<Result<(), ControllerBankLaunchErrorV1>>; 2],
    preparation: Option<Result<ResourceVector, InitializationCauseV1>>,
    posts: [Option<Result<(), ControllerBankLaunchErrorV1>>; 2],
    association: Option<Result<(), ControllerBankLaunchErrorV1>>,
}

impl CacheSelectedInitializationV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.entries.iter().find_map(|result| retained_error(result.as_ref()))
            .or_else(|| retained_error(self.preparation.as_ref()))
            .or_else(|| self.originals.failure())
            .or_else(|| self.stages.iter().find_map(CacheNativeStageV1::failure))
            .or_else(|| self.posts.iter().find_map(|result| retained_error(result.as_ref())))
            .or_else(|| retained_error(self.association.as_ref()))
    }

    fn new() -> Self {
        Self {
            originals: CacheConstructionOriginalsV1::new(),
            stages: std::array::from_fn(|_| CacheNativeStageV1::new()),
            entries: [None, None], preparation: None, posts: [None, None], association: None,
        }
    }
}

impl CacheResidentInitializationV1 {
    /// Initializes selected Cache through the actual held Bank and Controller.
    ///
    /// # Errors
    /// Refuses missing/failed native Bank state, a foreign live launch/profile,
    /// repeated initialization, or any retained body or independent post failure.
    pub fn initialize_selected_once(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        owner_uid: u32,
        bank: &std::sync::Arc<std::sync::Mutex<crate::controller_resource_reservation::ControllerResourceBankOpeningV1>>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.started || self.construction_entries[0].is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        // Validate caller-owned destinations before the actual Bank borrow
        // arms an independent native post. Refused inputs enter no interval.
        if destination.is_some() || self.selected_baseline.is_some() {
            self.started = true;
            self.first_failure.get_or_insert(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        }
        let bank = match bank.lock() {
            Ok(bank) => bank,
            Err(_) => {
                self.construction_entries[0] = Some(Err(ResourceReservationErrorV1::Conflict));
                self.started = true;
                self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
                return Err(CacheResidentUnavailableV1);
            }
        };
        let mut loan = match bank.borrow_cache_current_v1(controller, profile) {
            Ok(loan) => loan,
            Err(cause) => {
                self.construction_entries[0] = Some(Err(cause));
                self.started = true;
                self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
                return Err(CacheResidentUnavailableV1);
            }
        };
        self.construction_entries[0] = Some(Ok(()));
        self.initialize_with_current_loan_once(destination, owner_uid, &mut loan)
    }

    /// Captures physical Cache beside the actual same Bank/Controller/profile.
    ///
    /// # Errors
    /// Refuses failed or repeated construction, a changed live conjunction,
    /// unpaid growth, physical/native refusal, or any independent owed post.
    pub fn prepare_existing_physical_owner_selected(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        destination: &mut Option<super::super::super::DormantCacheOwnerV1>,
        node: aos_sandbox_core::NodeId,
        maximum_memory_bytes: u64,
        bank: &std::sync::Arc<std::sync::Mutex<crate::controller_resource_reservation::ControllerResourceBankOpeningV1>>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if !self.complete || self.first_failure.is_some() || self.postcheck.is_some()
            || self.selected_baseline.is_none() || self.construction_entries[1].is_some()
        {
            return Err(CacheResidentUnavailableV1);
        }
        let bank = match bank.lock() {
            Ok(bank) => bank,
            Err(_) => {
                self.construction_entries[1] = Some(Err(ResourceReservationErrorV1::Conflict));
                self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
                return Err(CacheResidentUnavailableV1);
            }
        };
        let mut loan = match bank.borrow_cache_current_v1(controller, profile) {
            Ok(loan) => loan,
            Err(cause) => {
                self.construction_entries[1] = Some(Err(cause));
                self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
                return Err(CacheResidentUnavailableV1);
            }
        };
        self.construction_entries[1] = Some(Ok(()));
        self.prepare_existing_with_current_loan_once(
            owner, destination, node, maximum_memory_bytes, &mut loan,
        )
    }

    /// Initializes fixed Cache originals through the actual confirmed C loan.
    ///
    /// The loan keeps the same writer, live launch and profile throughout the
    /// body. The initializer retains its body cause before independently owed
    /// native/profile/recipient posts; no body result is passed to C as proof.
    ///
    /// # Errors
    /// Retains native/model/debit failures and refuses reuse, foreign originals,
    /// occupied destinations or incomplete independent posts.
    fn initialize_with_current_loan_once<P>(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        owner_uid: u32,
        loan: &mut ControllerCacheConstructionLoanV1<'_, '_, '_, P>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.started { return Err(CacheResidentUnavailableV1); }
        self.started = true;
        if destination.is_some() || self.selected_baseline.is_some() {
            self.first_failure = Some(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        }
        let mut selected = CacheSelectedInitializationV1::new();
        selected.entries[0] = Some(loan.require_active());
        if matches!(selected.entries[0], Some(Ok(()))) {
            let receiving = CacheConstructionReceivingV1::confirmed(&selected.originals, loan);
            selected.preparation = Some(construction_data_demand::<P>());
            let admitted = match selected.preparation.as_ref() {
                Some(Ok(demand)) => receiving.require(CacheConstructionOwnerV1::ImportModels, *demand),
                _ => Err(InitializationCauseV1::Baseline),
            };
            if admitted.is_err() {
                self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
            } else if self.initialize_after_prearm_priced(
                destination, owner_uid, Some(&receiving), Some(&mut selected.stages),
            ).is_err() {
                self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
            }
        } else {
            self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
        }
        // The genuine outer loan owns every owed native/profile/launch post.
        selected.posts[0] = Some(loan.finish_native_once());
        if !matches!(selected.posts[0], Some(Ok(()))) {
            self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
        }
        if self.first_failure.is_none() && self.postcheck.is_none() && self.complete {
            selected.association = Some(loan.completed_original_ref().map(|original| {
                if selected.originals.original.set(original).is_err() { std::process::abort(); }
            }));
            if !matches!(selected.association, Some(Ok(()))) {
                self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
            }
        }
        self.selected_baseline = Some(selected);
        if self.first_failure.is_some() || self.postcheck.is_some() {
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    /// Captures the same physical Cache under a fresh genuine C interval.
    ///
    /// # Errors
    /// Refuses changed original association, prior failure, unpaid growth,
    /// changed limits or any independent owed native/profile/recipient failure.
    fn prepare_existing_with_current_loan_once<P>(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        destination: &mut Option<super::super::super::DormantCacheOwnerV1>,
        node: aos_sandbox_core::NodeId,
        maximum_memory_bytes: u64,
        loan: &mut ControllerCacheConstructionLoanV1<'_, '_, '_, P>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if !self.complete || self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        let Some(mut selected) = self.selected_baseline.take() else {
            return Err(CacheResidentUnavailableV1);
        };
        if selected.entries[1].is_some() || selected.posts[1].is_some() {
            self.selected_baseline = Some(selected);
            return Err(CacheResidentUnavailableV1);
        }
        selected.entries[1] = Some(match selected.originals.original.get() {
            Some(original) => loan.require_same_original_ref(original),
            None => Err(ControllerBankLaunchErrorV1::Conflict),
        });
        if matches!(selected.entries[1], Some(Ok(()))) {
            let receiving = CacheConstructionReceivingV1::confirmed(&selected.originals, loan);
            if self.prepare_existing_physical_owner_priced(
                owner, destination, node, maximum_memory_bytes, Some(&selected.originals), Some(&receiving),
            ).is_err() {
                self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
            }
        } else {
            self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
        }
        selected.posts[1] = Some(loan.finish_native_once());
        if !matches!(selected.posts[1], Some(Ok(()))) {
            self.first_failure.get_or_insert(InitializationCauseV1::Baseline);
        }
        self.selected_baseline = Some(selected);
        if self.first_failure.is_some() || self.postcheck.is_some() || !self.complete {
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }
}

fn construction_data_demand<P>() -> Result<ResourceVector, InitializationCauseV1> {
    use aos_sandbox_core::ResourceDimension as D;
    let bytes = std::mem::size_of::<CacheSelectedInitializationV1>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheConstructionReceivingV1<'_, '_, '_, '_, P>>()
            .checked_mul(2)?))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(InitializationCauseV1::Recovery(RecoveryError::Capacity))?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
}

// Additional source-map and authority-session clones are distinct from the
// already-live Native map. Include every reached row/key, even foreign or
// non-manifest authority data that semantic evidence recovery would ignore.
fn additional_raw_owner_bound(journal: &Journal) -> Result<ResourceVector, InitializationCauseV1> {
    use aos_sandbox_core::ResourceDimension as D;

    let capacity = || InitializationCauseV1::Recovery(RecoveryError::Capacity);
    let mut bytes = 0_usize;
    let mut rows = 0_usize;
    for (_, key, value) in journal.all_records() {
        bytes = bytes.checked_add(key.len()).and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or_else(capacity)?;
        rows = rows.checked_add(1).ok_or_else(capacity)?;
    }
    // One saved source/authority record set, a fresh equality/session clone,
    // current verified-owner views and old/new allocation overlap. General
    // semantic projection/canonical lanes are priced separately, as are the
    // retained Native map/replay and Runtime raw import credential.
    // A one-entry BTree root still allocates its fixed key/value array.
    // Three slots per later row plus the initial11-cell root cover sparse maps.
    let slots = if rows == 0 { 0 } else {
        rows.checked_mul(3).and_then(|slots| slots.checked_add(11)).ok_or_else(capacity)?
    };
    let memory = bytes.checked_mul(4)
        .and_then(|bytes| bytes.checked_add(slots.checked_mul(4)?.checked_mul(
            std::mem::size_of::<(Vec<u8>, Vec<u8>, [usize; 6])>(),
        )?)).ok_or_else(capacity)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| capacity())?)
        .with(D::MetadataEntries, u64::try_from(slots.checked_mul(8).ok_or_else(capacity)?)
            .map_err(|_| capacity())?))
}

fn retained_error<T, E: std::error::Error + 'static>(
    result: Option<&Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    result.and_then(|result| result.as_ref().err())
        .map(|cause| cause as &(dyn std::error::Error + 'static))
}

#[cfg(test)]
mod paid_comparison_tests {
    use super::*;
    use aos_sandbox_core::ResourceDimension as D;

    #[test]
    fn permanent_data_only_accepts_already_paid_peak_and_keeps_first_refusal() {
        let original = CacheConstructionOriginalsV1::new();
        let paid = ResourceVector::ZERO.with(D::MemoryBytes, 4096).with(D::OpenFiles, 3);
        original.paid.lock().unwrap()[CacheConstructionOwnerV1::CachePhysical as usize] = paid;

        assert!(original.require_physical_complete(paid).is_ok());
        assert!(original.require_physical_complete(
            ResourceVector::ZERO.with(D::MemoryBytes, 4097),
        ).is_err());
        let first = original.failure().unwrap() as *const (dyn std::error::Error + 'static);

        assert!(original.require_physical_complete(ResourceVector::ZERO).is_err());
        assert!(std::ptr::eq(original.failure().unwrap(), first));
        assert_eq!(original.paid.lock().unwrap()[CacheConstructionOwnerV1::CachePhysical as usize], paid);
        assert!(original.original.get().is_none());
    }
}
