//! One permanently paid Native opening peak, reused only after actual disposal.
//!
//! Each returned Journal retains its original directory, main and lock (three
//! FDs). A complete positive upper consumer may move its consumed facade here;
//! the same genuine receiver rechecks currentness, then actually drops those
//! completed traversal originals before another fixed opener enters. Failure
//! returns the entire facade and closes reuse; no future drop or refund pays it.

use super::*;
use crate::controller_resource_reservation::component_receiving::complete_bound_delta_v1;
use crate::journal::{StorageStateCapturedJournalOpenV1, StorageWorkspaceCapturedJournalOpenV1,
    StorageNativeIssuanceCapturedJournalOpenV1, StorageRequestTrustCapturedJournalOpenV1,
    StorageBrokerCapturedJournalOpenV1, StorageOutputCapturedJournalOpenV1};

const RETAINED_JOURNAL_FILES: u64 = 3;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum NativeOpeningKindV1 {
    Output,
    State,
    Workspace,
    Issuance,
    Trust,
    Session,
}

pub(super) struct NativeOpeningPeakV1 {
    paid_peak: u64,
    pub(super) active: Option<NativeOpeningKindV1>,
    pub(super) owner_link: Option<crate::journal::StorageNativeOpeningOwnerLinkV1>,
}

impl NativeOpeningPeakV1 {
    pub(super) const fn new() -> Self {
        Self { paid_peak: 0, active: None, owner_link: None }
    }
}

enum CompletedOpeningV1 {
    Output(StorageOutputCapturedJournalOpenV1),
    State(StorageStateCapturedJournalOpenV1),
    Workspace(StorageWorkspaceCapturedJournalOpenV1),
    Issuance(StorageNativeIssuanceCapturedJournalOpenV1),
    Trust(StorageRequestTrustCapturedJournalOpenV1),
    Session(StorageBrokerCapturedJournalOpenV1),
}

impl CompletedOpeningV1 {
    fn owner_link(&self) -> Option<&crate::journal::StorageNativeOpeningOwnerLinkV1> {
        match self {
            Self::Output(opening) => opening.opening_owner_link_v1(),
            Self::State(opening) => opening.opening_owner_link_v1(),
            Self::Workspace(opening) => opening.opening_owner_link_v1(),
            Self::Issuance(opening) => opening.opening_owner_link_v1(),
            Self::Trust(opening) => opening.opening_owner_link_v1(),
            Self::Session(opening) => opening.opening_owner_link_v1(),
        }
    }

    fn kind(&self) -> NativeOpeningKindV1 {
        match self {
            Self::Output(_) => NativeOpeningKindV1::Output,
            Self::State(_) => NativeOpeningKindV1::State,
            Self::Workspace(_) => NativeOpeningKindV1::Workspace,
            Self::Issuance(_) => NativeOpeningKindV1::Issuance,
            Self::Trust(_) => NativeOpeningKindV1::Trust,
            Self::Session(_) => NativeOpeningKindV1::Session,
        }
    }

    fn positive(&self) -> bool {
        match self {
            Self::Output(opening) => opening.was_taken_positive_v1(),
            Self::State(opening) => opening.was_taken_positive_v1(),
            Self::Workspace(opening) => opening.was_taken_positive_v1(),
            Self::Issuance(opening) => opening.was_taken_positive_v1(),
            Self::Trust(opening) => opening.was_taken_positive_v1(),
            Self::Session(opening) => opening.was_taken_positive_v1(),
        }
    }
}

// Pure geometry, shared across the actual five closed opening variants. The
// common component helper is the sole complete-bound high-water arithmetic.
fn opening_reservation_v1(
    combined: ResourceVector,
    native_files: u64,
    previous_peak: u64,
) -> Result<(ResourceVector, u64), aos_sandbox_model::AccountingError> {
    use aos_sandbox_model::AccountingError;
    let invalid = || AccountingError::ArithmeticOverflow { dimension: D::OpenFiles };
    let peak = native_files.checked_sub(RETAINED_JOURNAL_FILES).ok_or_else(invalid)?;
    let (paid, delta) = complete_bound_delta_v1(
        ResourceVector::ZERO.with(D::OpenFiles, previous_peak),
        ResourceVector::ZERO.with(D::OpenFiles, peak),
    )?;
    let upper = combined.checked_sub(ResourceVector::ZERO.with(D::OpenFiles, native_files))?;
    let restricted = upper
        .checked_add(ResourceVector::ZERO.with(D::OpenFiles, RETAINED_JOURNAL_FILES))?
        .checked_add(delta)?;
    Ok((restricted, paid.get(D::OpenFiles)))
}

impl StorageReceivingOriginalV1 {
    // Called only by the closed guard still borrowing the actually replayed
    // facade, after its independent Native and original receiving posts.
    pub(super) fn bind_native_opening_owner_v1(
        &mut self,
        kind: NativeOpeningKindV1,
        owner: &crate::journal::StorageNativeOpeningOwnerLinkV1,
    ) -> Result<(), StorageReceivingClosedV1> {
        if self.native_opening_peak.active != Some(kind)
            || self.native_opening_peak.owner_link.is_some()
        {
            self.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        if kind == NativeOpeningKindV1::Session {
            if self.session_identity.is_some() || self.session_replayed {
                self.first.get_or_insert(Failure::Closed);
                return Err(StorageReceivingClosedV1);
            }
            // Persist only this SAME actual Journal's existing identity. The
            // disposable opening peak below has its own independent link.
            self.session_identity = Some(owner.clone());
        }
        self.native_opening_peak.owner_link = Some(owner.clone());
        Ok(())
    }

    pub(super) fn reserve_native_opening_v1(
        &mut self,
        kind: NativeOpeningKindV1,
        combined: ResourceVector,
        native_files: u64,
    ) -> Result<(), StorageReceivingClosedV1> {
        if self.native_opening_peak.active.is_some() || self.native_opening_peak.owner_link.is_some() {
            self.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let (restricted, paid_peak) = match opening_reservation_v1(
            combined, native_files, self.native_opening_peak.paid_peak,
        ) {
            Ok(reservation) => reservation,
            Err(cause) => {
                self.arithmetic = Some(cause);
                self.first.get_or_insert(Failure::Arithmetic);
                return Err(StorageReceivingClosedV1);
            }
        };
        self.reserve(restricted)?;
        self.native_opening_peak.paid_peak = paid_peak;
        self.native_opening_peak.active = Some(kind);
        Ok(())
    }
}

impl StoragePrepareReceivingLoanV1<'_> {
    pub(super) fn native_opening_ready_v1(
        &mut self,
        kind: NativeOpeningKindV1,
        positive: bool,
        owner: Option<&crate::journal::StorageNativeOpeningOwnerLinkV1>,
    ) -> bool {
        match self.receiving() {
            Ok(receiving) => {
                let domain = match kind {
                    NativeOpeningKindV1::Session => receiving.session_fixed
                        && receiving.session_prefix && receiving.session_schema
                        && receiving.session_replayed && receiving.session_initialization,
                    _ => receiving.startup.native_settlement_ready(kind),
                };
                positive && domain && receiving.native_opening_peak.active == Some(kind)
                    && receiving.native_opening_peak.owner_link.as_ref().zip(owner)
                        .is_some_and(|(actual, offered)| actual.same_owner(offered))
            }
            Err(_) => false,
        }
    }

    fn settle_native_opening_v1(
        &mut self,
        opening: CompletedOpeningV1,
    ) -> Result<(), CompletedOpeningV1> {
        if !opening.positive() {
            if let Ok(receiving) = self.receiving() {
                receiving.first.get_or_insert(Failure::Closed);
            }
            return Err(opening);
        }
        let ready = self.native_opening_ready_v1(opening.kind(), true, opening.owner_link());
        // Preserve existing domain settlement ordering: invalid offered facades
        // do not start another observation. Initial HELLO owes its separate
        // independent original post while all its controls remain resident.
        if !ready || self.require_startup_current_v1().is_err() {
            if let Ok(receiving) = self.receiving() {
                receiving.first.get_or_insert(Failure::Closed);
            }
            return Err(opening);
        }
        // Positive upper callers have already settled their actual semantic,
        // initialization and independent posts and parked the returned Journal.
        // The intrinsic Arc comparison above joins this owned facade to the
        // exact facade borrowed at the paid replay frontier. An older completed
        // facade of the same kind cannot settle the current opening.
        // This drop is the real release of the completed ancestor descriptors.
        drop(opening);
        if let Ok(receiving) = self.receiving() {
            receiving.native_opening_peak.active = None;
            receiving.native_opening_peak.owner_link = None;
            Ok(())
        } else {
            // No fallible operation separates disposal and this same-owner
            // update. A violation cannot continue to another opening.
            std::process::abort()
        }
    }

    /// Disposes this actual completed Native facade after positive State load, initialization and independent posts.
    ///
    /// Its returned Journal's original directory, lock and main remain on the
    /// upper owner. The upper consumer must settle all its domain posts before
    /// moving this same facade; this operation supplies no domain authority.
    ///
    /// # Errors
    /// Returns the entire original facade for retention on missing completion,
    /// wrong stage, original currentness failure or any prior receiving debt.
    pub fn settle_state_native_opening_once_v1(
        &mut self,
        opening: StorageStateCapturedJournalOpenV1,
    ) -> Result<(), StorageStateCapturedJournalOpenV1> {
        match self.settle_native_opening_v1(CompletedOpeningV1::State(opening)) {
            Ok(()) => Ok(()),
            Err(CompletedOpeningV1::State(opening)) => Err(opening),
            Err(_) => std::process::abort(),
        }
    }

    /// Disposes this actual completed Native facade after positive workspace semantic and authenticated-plan posts.
    ///
    /// Its returned Journal's original directory, lock and main remain on the
    /// upper owner. The upper consumer must settle all its domain posts before
    /// moving this same facade; this operation supplies no domain authority.
    ///
    /// # Errors
    /// Returns the entire original facade for retention on missing completion,
    /// wrong stage, original currentness failure or any prior receiving debt.
    pub fn settle_workspace_native_opening_once_v1(
        &mut self,
        opening: StorageWorkspaceCapturedJournalOpenV1,
    ) -> Result<(), StorageWorkspaceCapturedJournalOpenV1> {
        match self.settle_native_opening_v1(CompletedOpeningV1::Workspace(opening)) {
            Ok(()) => Ok(()),
            Err(CompletedOpeningV1::Workspace(opening)) => Err(opening),
            Err(_) => std::process::abort(),
        }
    }

    /// Disposes the same actual positive Output facade after credential/schema posts.
    ///
    /// # Errors
    /// Returns the entire facade if any actual owner/currentness join fails.
    pub fn settle_output_native_opening_once_v1(
        &mut self,
        opening: StorageOutputCapturedJournalOpenV1,
    ) -> Result<(), StorageOutputCapturedJournalOpenV1> {
        match self.settle_native_opening_v1(CompletedOpeningV1::Output(opening)) {
            Ok(()) => Ok(()),
            Err(CompletedOpeningV1::Output(opening)) => Err(opening),
            Err(_) => std::process::abort(),
        }
    }

    /// Disposes this actual completed Native facade after positive issuance schema, active interests and independent posts.
    ///
    /// Its returned Journal's original directory, lock and main remain on the
    /// upper owner. The upper consumer must settle all its domain posts before
    /// moving this same facade; this operation supplies no domain authority.
    ///
    /// # Errors
    /// Returns the entire original facade for retention on missing completion,
    /// wrong stage, original currentness failure or any prior receiving debt.
    pub fn settle_issuance_native_opening_once_v1(
        &mut self,
        opening: StorageNativeIssuanceCapturedJournalOpenV1,
    ) -> Result<(), StorageNativeIssuanceCapturedJournalOpenV1> {
        match self.settle_native_opening_v1(CompletedOpeningV1::Issuance(opening)) {
            Ok(()) => Ok(()),
            Err(CompletedOpeningV1::Issuance(opening)) => Err(opening),
            Err(_) => std::process::abort(),
        }
    }

    /// Disposes this actual completed Native facade after positive Trust configuration, reconciliation and currentness posts.
    ///
    /// Its returned Journal's original directory, lock and main remain on the
    /// upper owner. The upper consumer must settle all its domain posts before
    /// moving this same facade; this operation supplies no domain authority.
    ///
    /// # Errors
    /// Returns the entire original facade for retention on missing completion,
    /// wrong stage, original currentness failure or any prior receiving debt.
    pub fn settle_trust_native_opening_once_v1(
        &mut self,
        opening: StorageRequestTrustCapturedJournalOpenV1,
    ) -> Result<(), StorageRequestTrustCapturedJournalOpenV1> {
        match self.settle_native_opening_v1(CompletedOpeningV1::Trust(opening)) {
            Ok(()) => Ok(()),
            Err(CompletedOpeningV1::Trust(opening)) => Err(opening),
            Err(_) => std::process::abort(),
        }
    }

    /// Disposes this actual completed Native facade after positive Session schema, configured floor, initialization and pins.
    ///
    /// Its returned Journal's original directory, lock and main remain on the
    /// upper owner. The upper consumer must settle all its domain posts before
    /// moving this same facade; this operation supplies no domain authority.
    ///
    /// # Errors
    /// Returns the entire original facade for retention on missing completion,
    /// wrong stage, original currentness failure or any prior receiving debt.
    pub fn settle_session_native_opening_once_v1(
        &mut self,
        opening: StorageBrokerCapturedJournalOpenV1,
    ) -> Result<(), StorageBrokerCapturedJournalOpenV1> {
        match self.settle_native_opening_v1(CompletedOpeningV1::Session(opening)) {
            Ok(()) => Ok(()),
            Err(CompletedOpeningV1::Session(opening)) => Err(opening),
            Err(_) => std::process::abort(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_four_journals_preserve_security_and_all_persistent_files() {
        // Pure DATA scenario, not a genuine PID1 or positive disposal fixture.
        // The caller's actual settlement gates remain separately mandatory.
        let mut peak = 0;
        let mut total = ResourceVector::ZERO;
        for native_files in [11, 11, 11] {
            let (added, next) = opening_reservation_v1(
                ResourceVector::ZERO.with(D::OpenFiles, native_files), native_files, peak,
            ).unwrap();
            total = total.checked_add(added).unwrap();
            peak = next;
        }
        let security = ResourceVector::ZERO.with(D::OpenFiles, 55).with(D::MemoryBytes, 91);
        let native = ResourceVector::ZERO.with(D::OpenFiles, 12).with(D::MemoryBytes, 73);
        let (last, peak) = opening_reservation_v1(security.checked_add(native).unwrap(), 12, peak).unwrap();
        total = total.checked_add(last).unwrap();

        assert_eq!(peak, 9);
        assert_eq!(total.get(D::OpenFiles), 4 * RETAINED_JOURNAL_FILES + 9 + 55);
        assert_eq!(last.get(D::MemoryBytes), 91 + 73);
    }

    #[test]
    fn deeper_joined_trust_pays_only_actual_extra_peak_without_losing_its_journal() {
        let (added, paid) = opening_reservation_v1(
            ResourceVector::ZERO.with(D::OpenFiles, 18), 18, 9,
        ).unwrap();

        assert_eq!(paid, 15);
        assert_eq!(added.get(D::OpenFiles), 3 + 6);
    }

    #[test]
    fn impossible_native_or_upper_geometry_refuses_before_reservation() {
        assert!(opening_reservation_v1(ResourceVector::ZERO, 2, 9).is_err());
        assert!(opening_reservation_v1(ResourceVector::ZERO.with(D::OpenFiles, 10), 11, 9).is_err());
    }
}
