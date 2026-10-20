//! Keeps the actual original Create-continuation J ledger and finite bounds.
//!
//! Only the same confirmed initial Controller writer/profile can claim this
//! owner from its genuine Reserved native J. The upper coordinator still owns
//! Source, admission, clocks, append/readback and independently owed posts.
//! A committed financial borrower neither establishes those joins nor grants
//! Cache, Journal, operation, native-effect or currentness authority.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_model::{
    ResourceVector,
    component_receiving::{ComponentServiceReceivingLedgerV1, complete_bound_delta_v1},
};
use aos_sandbox_protocol::domain_ledger::resource_bank::{self as bank, Claim};

use super::identity::ControllerWriterIdentityV1;
use super::original_observers::{ControllerReservedObserverOriginalV1, OriginalObserverPurposeV1};
use super::{
    CacheControllerOriginalRefV1, ControllerBankLaunchErrorV1, ControllerBankLaunchOriginalV1,
    ControllerCoordinatorWriterV1,
};
use crate::controller_receiving::{
    ControllerReceivingOriginalV1, profile::ControllerSelfProfileOriginalV1,
};

#[derive(Clone, Copy)]
enum CaptureOwner {
    ControllerIntent,
    SourceHeld,
    CacheHeld,
    Ownership,
    StorageInventory,
    RootExchange,
    Observers,
    HistoryNames,
    AssignmentPlanned,
    StorageClientSession,
    ReadyBundle,
}

impl CaptureOwner {
    const COUNT: usize = 11;
}

struct CaptureAccounting {
    ledger: ComponentServiceReceivingLedgerV1,
    bounds: [ResourceVector; CaptureOwner::COUNT],
    reservation: Option<Result<(), ControllerBankLaunchErrorV1>>,
}

impl CaptureAccounting {
    fn begin(provision: ResourceVector, fixed: ResourceVector, observers: ResourceVector) -> Self {
        let mut actual = Self {
            ledger: ComponentServiceReceivingLedgerV1::new(provision),
            bounds: [ResourceVector::ZERO; CaptureOwner::COUNT],
            reservation: None,
        };
        actual.reservation = Some((|| {
            actual
                .ledger
                .reserve(fixed.checked_add(observers)?)
                .map_err(|cause| ControllerBankLaunchErrorV1::Accounting(*cause))?;
            actual.bounds[CaptureOwner::Observers as usize] = observers;
            Ok(())
        })());
        actual
    }

    fn reserve_complete(
        &mut self,
        owner: CaptureOwner,
        complete: ResourceVector,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        if self.failure().is_some() {
            return Err(ControllerCreateContinuationClosedV1);
        }
        self.reservation = Some((|| {
            let (high_water, delta) =
                complete_bound_delta_v1(self.bounds[owner as usize], complete)?;
            self.ledger
                .reserve(delta)
                .map_err(|cause| ControllerBankLaunchErrorV1::Accounting(*cause))?;
            self.bounds[owner as usize] = high_water;
            Ok(())
        })());
        self.require_open()
    }

    fn require_open(&self) -> Result<(), ControllerCreateContinuationClosedV1> {
        if self.failure().is_some() {
            Err(ControllerCreateContinuationClosedV1)
        } else {
            Ok(())
        }
    }

    fn require_paid(
        &mut self,
        owner: CaptureOwner,
        required: ResourceVector,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.require_open()?;
        match self.bounds[owner as usize].checked_sub(required) {
            Ok(_) => Ok(()),
            Err(cause) => Err(self.refuse(ControllerBankLaunchErrorV1::Accounting(cause))),
        }
    }

    fn reserve_root_additional(
        &mut self,
        additional: ResourceVector,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.require_open()?;
        match self.bounds[CaptureOwner::RootExchange as usize].checked_add(additional) {
            Ok(complete) => self.reserve_complete(CaptureOwner::RootExchange, complete),
            Err(cause) => Err(self.refuse(ControllerBankLaunchErrorV1::Accounting(cause))),
        }
    }

    fn refuse(
        &mut self,
        cause: ControllerBankLaunchErrorV1,
    ) -> ControllerCreateContinuationClosedV1 {
        if self.failure().is_none() {
            self.reservation = Some(Err(cause));
        }
        ControllerCreateContinuationClosedV1
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.ledger.failure().map(|cause| cause as _).or_else(|| {
            self.reservation
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _)
        })
    }
}

/// Stops use of the same retained J; its owner preserves the actual cause.
#[derive(Debug, thiserror::Error)]
#[error("original Create-continuation receiving is closed")]
pub struct ControllerCreateContinuationClosedV1;

/// Owns the single native-claimed J and all eleven original capture highwaters.
///
/// The actual Controller writer alone constructs this owner. Dropping a loan
/// never releases a charge, refunds a bound or reopens a failed reservation.
#[must_use]
pub struct ControllerCreateContinuationLedgerOriginalV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    identity: Arc<ControllerWriterIdentityV1>,
    reserved_claim: Claim,
    committed_claim: Claim,
    observer_started: bool,
    observer_lifetime: Option<crate::receiving::ObservationLifetimeV1>,
    accounting: CaptureAccounting,
    commitment: Option<Result<(), ControllerBankLaunchErrorV1>>,
    source_currentness_claimed: bool,
}

/// Borrows only the same committed J's closed Cache financial highwater.
///
/// No mutable Controller writer is held across upper independent posts. Every
/// caller must still keep its original Source/profile/admission/native joins.
pub struct ControllerCreateContinuationFundingLoanV1<'funding, 'profile> {
    owner: &'funding mut ControllerCreateContinuationLedgerOriginalV1,
    profile: &'profile ControllerSelfProfileOriginalV1,
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Claims J once from this same initial native writer and confirmed launch.
    ///
    /// Fixed/observer widths are requirements, not a supplied paid ledger. The
    /// returned owner retains an initial debit refusal instead of dropping it.
    ///
    /// # Errors
    /// Refuses foreign/closed original custody, repeated claim, noninitial
    /// launch, missing Reserved J or an invalid actual native bank predecessor.
    pub fn begin_create_continuation_once_v1(
        &mut self,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        fixed: ResourceVector,
        observers: ResourceVector,
    ) -> Result<ControllerCreateContinuationLedgerOriginalV1, ControllerBankLaunchErrorV1> {
        let controls =
            ControllerCreateContinuationLedgerOriginalV1::receiving_construction_bytes_v1()
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        fixed.checked_sub(
            ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes, controls),
        )?;
        if !launch.is_initial_enrollment() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        launch.require_current_controller_v1(self)?;
        let original = self.fixed.original();
        let observed = original.claim_create_continuation_once_v1(profile)?;
        let provision = observed
            .policy
            .bootstrap_provisions()
            .create_continuation_intake
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let state = self.fixed.bank_state_v1()?;
        let claim = Claim::decode(
            bank::claim_bytes(
                state,
                observed
                    .identity
                    .account_id(b"controller-create-continuation-intake-v1"),
            )
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?,
        )?;
        let fields = claim.native_fields();
        if fields.enrollment != observed.identity
            || fields.account != observed.identity.account_id(b"controller")
            || fields.purpose != bank::ClaimPurpose::CreateContinuationIntake
            || fields.state != bank::ClaimState::Reserved
            || fields.cut != bank::ClaimCut::BootLifetime
            || fields.amount != provision
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        bank::require_exact_claim_record_v1(state, claim)?;
        let (_, committed_claim) =
            bank::settled_pair(bank::find_head(state, fields.account)?, claim, true)?;
        Ok(ControllerCreateContinuationLedgerOriginalV1 {
            original: Arc::clone(original),
            identity: Arc::clone(self.fixed.identity()),
            reserved_claim: claim,
            committed_claim,
            observer_started: false,
            observer_lifetime: None,
            accounting: CaptureAccounting::begin(provision, fixed, observers),
            commitment: None,
            source_currentness_claimed: false,
        })
    }
}

impl ControllerCreateContinuationLedgerOriginalV1 {
    /// Names the canonical eleven initial actual J observer rows.
    pub const INITIAL_OBSERVER_ROWS: usize = 2 + 2 * 4 + 1;

    /// Transfers this same Reserved J's actual observer origin once.
    ///
    /// The upper producer calls this at its existing point after fixed/eleven
    /// row admission, CPU and first clock, before attaching the exact same
    /// P/I/Q/J-exclusive archive and settling the native J. A lifetime is
    /// closure DATA only; the returned origin retains actual J native custody.
    /// The same ledger keeps its lifetime handle and all financial highwaters.
    ///
    /// # Errors
    /// Retains reentry, premature committed use, foreign C/profile, changed
    /// Reserved native claim or an insufficient initial Observer highwater.
    pub fn begin_reserved_observers_once_v1<P>(
        &mut self,
        writer: &ControllerCoordinatorWriterV1<P>,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerReservedObserverOriginalV1, ControllerCreateContinuationClosedV1> {
        if self.failure_v1().is_some() {
            return Err(ControllerCreateContinuationClosedV1);
        }
        if self.observer_started {
            return Err(self.accounting.refuse(ControllerBankLaunchErrorV1::Conflict));
        }
        self.observer_started = true;
        let result = (|| {
            self.require_initial_reserved_v1()?;
            if self.commitment.is_some() || self.observer_lifetime.is_some()
                || !Arc::ptr_eq(&self.identity, writer.fixed.identity())
            {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            self.require_profile(profile)?;
            bank::require_exact_claim_record_v1(
                writer.fixed.bank_state_v1()?, self.reserved_claim,
            )?;
            let required = initial_observer_demand_v1()?;
            self.accounting.bounds[CaptureOwner::Observers as usize].checked_sub(required)?;
            Ok(crate::receiving::ObservationLifetimeV1::begin())
        })();
        match result {
            Ok(lifetime) => {
                self.observer_lifetime = Some(lifetime.clone());
                Ok(ControllerReservedObserverOriginalV1 {
                    original: Arc::clone(&self.original),
                    identity: Arc::clone(&self.identity),
                    reserved: self.reserved_claim,
                    capacity: Self::INITIAL_OBSERVER_ROWS,
                    lifetime,
                    purpose: OriginalObserverPurposeV1::CreateIntake,
                })
            }
            Err(cause) => Err(self.accounting.refuse(cause)),
        }
    }

    /// Prices the actual factory locals, return and retained error controls.
    /// Returns `None` on checked representation overflow; creates no funding.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<Self, ControllerBankLaunchErrorV1>>())?
            .checked_add(std::mem::size_of::<Result<(), ControllerBankLaunchErrorV1>>())?
            // The actual Reserved-J producer transfers this origin, while
            // retaining the same closure handle and all financial bounds.
            .checked_add(std::mem::size_of::<ControllerReservedObserverOriginalV1>())?
            .checked_add(std::mem::size_of::<Result<
                ControllerReservedObserverOriginalV1, ControllerCreateContinuationClosedV1,
            >>())?
            .checked_add(
                std::mem::size_of::<(
                    crate::receiving::OriginalEnrollment,
                    ResourceVector,
                    ResourceVector,
                    ResourceVector,
                    Claim,
                    bank::ClaimFields,
                    Result<(bank::AccountHead, Claim), bank::ResourceBankDataError>,
                )>()
                .checked_mul(2)?,
            )?
            // Both genuine launch/current-claim bookends decode and normalize
            // their actual recipient row; each owns its fixed encode scratch.
            .checked_add(
                std::mem::size_of::<(
                    Option<bank::RecipientIncarnation>,
                    Result<Option<bank::RecipientIncarnation>, bank::ResourceBankDataError>,
                    Result<Vec<u8>, bank::ResourceBankDataError>,
                    Result<[u8; bank::CLAIM_BYTES_V1], bank::ResourceBankDataError>,
                    [u8; 96],
                    [u8; 176],
                    sha2::Sha256,
                )>()
                .checked_mul(2)?,
            )?
            .checked_add(bank::RECIPIENT_RANGE_INCARNATION_BYTES.checked_mul(2)?)?
            .checked_add(ControllerReservedObserverOriginalV1::attachment_construction_bytes_v1()?)
    }

    /// Requires successful initial J admission without lending future capacity.
    ///
    /// # Errors
    /// Preserves the retained initial arithmetic refusal or closed state.
    pub fn require_initial_reserved_v1(&self) -> Result<(), ControllerBankLaunchErrorV1> {
        if let Some(cause) = self.accounting.ledger.failure() {
            return Err(ControllerBankLaunchErrorV1::Accounting(*cause));
        }
        match &self.accounting.reservation {
            Some(Ok(())) => Ok(()),
            Some(Err(ControllerBankLaunchErrorV1::Accounting(cause))) => {
                Err(ControllerBankLaunchErrorV1::Accounting(*cause))
            }
            _ => Err(ControllerBankLaunchErrorV1::Conflict),
        }
    }

    /// Rejoins the actual same native committed J after the upper append/readback.
    ///
    /// This financial check does not replace the upper completed append or any
    /// independently owed Controller/Source/profile/CPU/clock post.
    ///
    /// # Errors
    /// Retains a foreign/closed original, reentry or missing exact native claim.
    pub fn require_committed_once_v1<P>(
        &mut self,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        if self.commitment.is_some() {
            if self.failure_v1().is_none() {
                self.accounting.reservation = Some(Err(ControllerBankLaunchErrorV1::Conflict));
            }
            return Err(ControllerCreateContinuationClosedV1);
        }
        self.commitment = Some((|| {
            self.require_initial_reserved_v1()?;
            self.require_profile(profile)?;
            if !Arc::ptr_eq(&self.identity, writer.fixed.identity()) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            launch.require_current_controller_v1(writer)?;
            bank::require_exact_claim_record_v1(
                writer.fixed.bank_state_v1()?,
                self.committed_claim,
            )?;
            Ok(())
        })());
        self.require_committed()
    }

    fn require_profile(
        &self,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !profile.has_same_baseline_original(&self.original)
            || self.original.is_closed()
            || !self.identity.has_original(&self.original)
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.original
            .require_create_continuation_profile_v1(profile)?;
        Ok(())
    }

    fn require_committed(&self) -> Result<(), ControllerCreateContinuationClosedV1> {
        require_committed_accounting(&self.accounting, &self.commitment)?;
        if self.observer_lifetime.as_ref().is_some_and(|lifetime| lifetime.is_open()) {
            Ok(())
        } else {
            Err(ControllerCreateContinuationClosedV1)
        }
    }

    fn require_profile_retained(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.require_committed()?;
        match self.require_profile(profile) {
            Ok(()) => Ok(()),
            Err(cause) => Err(self.accounting.refuse(cause)),
        }
    }

    fn reserve_complete(
        &mut self,
        owner: CaptureOwner,
        complete: ResourceVector,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.require_committed()?;
        self.accounting.reserve_complete(owner, complete)
    }

    /// Borrows the first actual retained financial or native-commitment cause.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.accounting.failure().or_else(|| {
            self.commitment
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _)
        })
    }

    /// Borrows the closed Cache financial port of this same committed original.
    ///
    /// # Errors
    /// Refuses incomplete native commitment, prior refusal or foreign profile.
    pub fn borrow_cache_funding_v1<'funding, 'profile>(
        &'funding mut self,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Result<
        ControllerCreateContinuationFundingLoanV1<'funding, 'profile>,
        ControllerCreateContinuationClosedV1,
    > {
        if self.require_committed().is_err() {
            if self.failure_v1().is_none() {
                self.accounting
                    .refuse(ControllerBankLaunchErrorV1::Conflict);
            }
            return Err(ControllerCreateContinuationClosedV1);
        }
        self.require_profile_retained(profile)?;
        Ok(ControllerCreateContinuationFundingLoanV1 {
            owner: self,
            profile,
        })
    }
}

impl ControllerCreateContinuationLedgerOriginalV1 {
    pub(in crate::controller_receiving) fn reserve_observer_archive_growth_v1(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        required: ResourceVector,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.require_profile_retained(profile)?;
        self.accounting.reserve_complete(CaptureOwner::Observers, required)
    }

    pub(super) fn require_storage_use_construction_v1<P>(
        &mut self,
        writer: &ControllerCoordinatorWriterV1<P>,
        profile: &ControllerSelfProfileOriginalV1,
        required: ResourceVector,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.require_profile_retained(profile)?;
        if !Arc::ptr_eq(&self.identity, writer.fixed.identity()) {
            return Err(self.accounting.refuse(ControllerBankLaunchErrorV1::Conflict));
        }
        self.accounting.require_paid(CaptureOwner::RootExchange, required)
    }
}

// The concrete original exposes only the eleven pre-existing capture owners.
// The Cache borrower below cannot select another role's financial bound.
macro_rules! reserve_capture_complete {
    ($($name:ident => $owner:ident),+ $(,)?) => {
        impl ControllerCreateContinuationLedgerOriginalV1 {
            $(
                /// Raises this named capture owner's same-J complete highwater.
                ///
                /// # Errors
                /// Refuses missing native commitment or the sticky J reservation.
                pub fn $name(&mut self, complete: ResourceVector)
                    -> Result<(), ControllerCreateContinuationClosedV1>
                {
                    self.reserve_complete(CaptureOwner::$owner, complete)
                }
            )+
        }
    };
}

reserve_capture_complete! {
    reserve_controller_intent_complete_v1 => ControllerIntent,
    reserve_source_held_complete_v1 => SourceHeld,
    reserve_cache_held_complete_v1 => CacheHeld,
    reserve_ownership_complete_v1 => Ownership,
    reserve_storage_inventory_complete_v1 => StorageInventory,
    reserve_root_exchange_complete_v1 => RootExchange,
    reserve_observers_complete_v1 => Observers,
    reserve_history_names_complete_v1 => HistoryNames,
    reserve_assignment_planned_complete_v1 => AssignmentPlanned,
    reserve_storage_client_session_complete_v1 => StorageClientSession,
    reserve_ready_bundle_complete_v1 => ReadyBundle,
}

impl ControllerCreateContinuationLedgerOriginalV1 {
    /// Adds an actual retained Root flight to the same cumulative Root bound.
    ///
    /// # Errors
    /// Refuses missing commitment, sticky debt or checked all-dimension overflow.
    pub fn reserve_root_additional_v1(
        &mut self,
        additional: ResourceVector,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.require_committed()?;
        self.accounting.reserve_root_additional(additional)
    }

    /// Requires the actual same-J paid names peak without renewing its grant.
    ///
    /// # Errors
    /// Refuses a closed/uncommitted original or an insufficient admitted bound.
    pub fn require_history_names_complete_v1(
        &self,
        required: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_committed()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        self.accounting.bounds[CaptureOwner::HistoryNames as usize].checked_sub(required)?;
        Ok(())
    }
}

impl ControllerCreateContinuationFundingLoanV1<'_, '_> {
    /// Raises the same Cache highwater before its actual complete-shape growth.
    ///
    /// # Errors
    /// Refuses foreign profile, missing commitment or the sticky J reservation.
    pub fn reserve_cache_complete_v1(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.owner.require_profile_retained(self.profile)?;
        self.owner
            .reserve_complete(CaptureOwner::CacheHeld, complete)
    }

    /// Compares a required Cache bound with this same original's paid highwater.
    ///
    /// # Errors
    /// Refuses a closed/foreign original or a bound not previously admitted.
    pub fn require_cache_complete_v1(
        &mut self,
        required: ResourceVector,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.owner.require_profile_retained(self.profile)?;
        self.owner
            .accounting
            .require_paid(CaptureOwner::CacheHeld, required)
    }

    /// Rejoins an existing Cache association to the actual Controller allocation.
    ///
    /// # Errors
    /// Refuses a foreign association/profile, missing commitment or prior cause.
    pub fn require_controller_original_v1(
        &mut self,
        actual: &CacheControllerOriginalRefV1,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.owner.require_profile_retained(self.profile)?;
        if !actual.matches_actual_original(&self.owner.identity, &self.owner.original) {
            return Err(self
                .owner
                .accounting
                .refuse(ControllerBankLaunchErrorV1::Conflict));
        }
        Ok(())
    }

    /// Borrows the actual original cause without changing custody or accounting.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.owner.failure_v1()
    }

    /// Claims one paid fixed-Source currentness group on this actual J.
    ///
    /// The actual Source constructor calls this before constructing its seven
    /// native destinations. The claim survives loan drops and all later J
    /// refusals; already-prearmed owed samples never reenter this gate.
    ///
    /// # Errors
    /// Retains prior debt, foreign Source/profile, missing native commitment,
    /// insufficient names funding or a previously consumed group claim.
    pub fn claim_cache_source_currentness_once_v1(
        &mut self,
        actual: &crate::controller_receiving::source_prebank::ControllerSourceOriginalRefV1,
        required_names: ResourceVector,
    ) -> Result<(), ControllerCreateContinuationClosedV1> {
        self.owner.require_profile_retained(self.profile)?;
        if self.owner.source_currentness_claimed
            || !actual.has_same_original_v1(&self.owner.original)
        {
            return Err(self
                .owner
                .accounting
                .refuse(ControllerBankLaunchErrorV1::Conflict));
        }
        self.owner
            .accounting
            .require_paid(CaptureOwner::HistoryNames, required_names)?;

        // Burn before the native group can be constructed, including a failed
        // construction. Dropping its scoped borrower never restores the claim.
        self.owner.source_currentness_claimed = true;
        Ok(())
    }
}

// The upper invoice and native origin use the sole same growing-row supplier.
// This is an all-dimension bound comparison, never an archive/role constructor.
fn initial_observer_demand_v1() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
    use aos_sandbox_model::ResourceDimension as D;

    let row = crate::receiving::growing_fixed_property_archive_demand_v1(64 * 1024)
        .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
    let mut required = ResourceVector::ZERO;
    for dimension in D::ALL {
        let amount = row.get(dimension)
            .checked_mul(ControllerCreateContinuationLedgerOriginalV1::INITIAL_OBSERVER_ROWS as u64)
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        required = required.with(dimension, amount);
    }
    Ok(required)
}

fn require_committed_accounting(
    accounting: &CaptureAccounting,
    commitment: &Option<Result<(), ControllerBankLaunchErrorV1>>,
) -> Result<(), ControllerCreateContinuationClosedV1> {
    if accounting.failure().is_none() && matches!(commitment, Some(Ok(()))) {
        Ok(())
    } else {
        Err(ControllerCreateContinuationClosedV1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::ResourceDimension as D;

    fn memory(bytes: u64) -> ResourceVector {
        ResourceVector::ZERO.with(D::MemoryBytes, bytes)
    }

    // These fixtures exercise private accounting/phase DATA only. They neither
    // construct a native J owner nor turn a successful model into a borrower.
    #[test]
    fn separate_highwaters_keep_initial_charge_and_smaller_bounds_never_refund() {
        let mut actual = CaptureAccounting::begin(memory(100), memory(10), memory(5));
        actual
            .reserve_complete(CaptureOwner::CacheHeld, memory(40))
            .unwrap();
        actual
            .reserve_complete(CaptureOwner::CacheHeld, memory(3))
            .unwrap();
        actual
            .reserve_complete(CaptureOwner::SourceHeld, memory(30))
            .unwrap();

        assert_eq!(actual.ledger.charged(), memory(85));
        assert_eq!(actual.bounds[CaptureOwner::CacheHeld as usize], memory(40));
        assert_eq!(actual.bounds[CaptureOwner::SourceHeld as usize], memory(30));
        assert_eq!(actual.bounds[CaptureOwner::Observers as usize], memory(5));

        assert!(
            actual
                .reserve_complete(CaptureOwner::CacheHeld, memory(60))
                .is_err()
        );
        let cause = actual.failure().unwrap() as *const dyn Error;
        assert_eq!(actual.ledger.charged(), memory(85));
        assert_eq!(actual.bounds[CaptureOwner::CacheHeld as usize], memory(40));
        assert!(
            actual
                .reserve_complete(CaptureOwner::Ownership, ResourceVector::ZERO)
                .is_err()
        );
        assert_eq!(actual.failure().unwrap() as *const dyn Error, cause);
    }

    #[test]
    fn initial_refusal_keeps_the_actual_ledger_and_cannot_gain_a_bound() {
        let mut actual = CaptureAccounting::begin(memory(10), memory(8), memory(3));
        let cause = actual.failure().unwrap() as *const dyn Error;

        assert!(
            actual
                .reserve_complete(CaptureOwner::CacheHeld, ResourceVector::ZERO)
                .is_err()
        );
        assert_eq!(actual.failure().unwrap() as *const dyn Error, cause);
        assert_eq!(
            actual.bounds[CaptureOwner::Observers as usize],
            ResourceVector::ZERO
        );
        assert_eq!(
            actual.bounds[CaptureOwner::CacheHeld as usize],
            ResourceVector::ZERO
        );
        assert!(require_committed_accounting(&actual, &Some(Ok(()))).is_err());
    }

    #[test]
    fn underpaid_cache_and_closed_refusal_keep_first_cause_across_later_attempts() {
        let mut actual = CaptureAccounting::begin(memory(100), memory(1), memory(1));
        actual
            .reserve_complete(CaptureOwner::CacheHeld, memory(10))
            .unwrap();

        assert!(
            actual
                .require_paid(CaptureOwner::CacheHeld, memory(11))
                .is_err()
        );
        assert!(
            actual
                .failure()
                .unwrap()
                .downcast_ref::<ControllerBankLaunchErrorV1>()
                .is_some()
        );
        let cause = actual.failure().unwrap() as *const dyn Error;
        actual.refuse(ControllerBankLaunchErrorV1::Conflict);
        assert!(
            actual
                .require_paid(CaptureOwner::CacheHeld, memory(1))
                .is_err()
        );
        assert_eq!(actual.failure().unwrap() as *const dyn Error, cause);

        let mut other = CaptureAccounting::begin(memory(100), memory(1), memory(1));
        other.refuse(ControllerBankLaunchErrorV1::Conflict);
        let affinity = other.failure().unwrap() as *const dyn Error;
        assert!(
            other
                .reserve_complete(CaptureOwner::CacheHeld, memory(1))
                .is_err()
        );
        assert_eq!(other.failure().unwrap() as *const dyn Error, affinity);
    }

    #[test]
    fn root_flights_accumulate_and_commitment_phase_cannot_substitute_for_admission() {
        let mut actual = CaptureAccounting::begin(memory(u64::MAX), memory(0), memory(0));
        assert!(require_committed_accounting(&actual, &None).is_err());
        assert!(
            require_committed_accounting(
                &actual,
                &Some(Err(ControllerBankLaunchErrorV1::Conflict))
            )
            .is_err()
        );
        actual.reserve_root_additional(memory(20)).unwrap();
        actual.reserve_root_additional(memory(30)).unwrap();
        assert_eq!(
            actual.bounds[CaptureOwner::RootExchange as usize],
            memory(50)
        );
        actual
            .reserve_root_additional(memory(u64::MAX - 50))
            .unwrap();

        assert!(actual.reserve_root_additional(memory(1)).is_err());
        let cause = actual.failure().unwrap() as *const dyn Error;
        assert!(
            actual
                .reserve_root_additional(ResourceVector::ZERO)
                .is_err()
        );
        assert_eq!(actual.failure().unwrap() as *const dyn Error, cause);
        assert!(require_committed_accounting(&actual, &Some(Ok(()))).is_err());
    }
}
