//! Genuine admitted Host inputs and two original existing journal owners.
//!
//! Journals are opened only at fixed root-owned roles, main first and sidecar
//! second, with no create, repair, seed or recovery fallback. Transient Core
//! guards reborrow these same owned fields; no self-borrowed guard is stored.
//! The whole owner and exact TX remain borrowed through native funding DATA.
//! The private physical borrow can lend only these same original locks and
//! compare this complete disk pair. No journal effect or activation is exposed.

use std::path::Path;

use aos_sandbox::{
    HostPhysicalInvocationErrorV1, HostPhysicalInvocationLeaseV1,
    Journal, JournalLimits, JournalTransaction, ProtectedJournalPreflight,
    ProtectedJournalSnapshot, ProtectedJournalLockCustodyV1,
    RecordNamespace, RuntimeDeploymentComparisonOriginsV1,
};

use super::{
    AdmittedHostTpmInputsV1, HostOwnedJournalErrorV1, JOURNAL_DIRECTORY,
    MAIN_JOURNAL_NAME, SIDECAR_JOURNAL_NAME,
};
use super::store::{HostDiskAssociationV1, StoredHostFloorV1, compare_original_state};
use crate::tpm_nv_custody::{
    FloorCutV1, HostFloorIntentDataV1, HostSidecarStoreV1, HostSuffixPreflightV1,
    sidecar_limits,
};

/// Carries only the genuine Host constructor's same original fixed sidecar.
///
/// Private construction/fields exclude raw Journal, DATA, default or callback
/// factories. This capsule owns no TPM, signer, secret or physical comparison.
pub(in crate::tpm_nv_custody) struct HostSidecarCustodyV1<'origin, 'startup> {
    journal: Journal,
    main_limits: JournalLimits,
    origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
}

impl HostSidecarCustodyV1<'_, '_> {
    pub(in crate::tpm_nv_custody) fn validate_held(&self) -> Result<(), HostOwnedJournalErrorV1> {
        self.origins.recheck()?;
        self.journal.validate_held_root_owned_at(
            Path::new(JOURNAL_DIRECTORY), SIDECAR_JOURNAL_NAME,
        )?;
        self.origins.recheck()?;
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn journal_mut(&mut self) -> &mut Journal {
        &mut self.journal
    }

    pub(in crate::tpm_nv_custody) const fn main_limits(&self) -> JournalLimits {
        self.main_limits
    }
}

/// Owns genuine admitted inputs and the actual existing full-state disk pair.
///
/// No raw writer, field, detach, clone, signer, secret or effect API escapes.
/// Failed/unwound work closes this same owner's usable latch before checks.
/// Ordinary drop releases files/borrows only; it is not a physical debt drain.
#[must_use = "genuine inputs and both original writers must stay retained"]
pub(super) struct HostOwnedJournalInputsV1<'origin, 'startup> {
    origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    inputs: AdmittedHostTpmInputsV1<'origin, 'startup>,
    main: Journal,
    store: HostSidecarStoreV1<'origin, 'startup>,
    usable: bool,
}

impl<'origin, 'startup> HostOwnedJournalInputsV1<'origin, 'startup> {
    /// Admits only independently existing originals under genuine Origins.
    ///
    /// # Errors
    /// Rejects input/origin drift, unsafe or absent originals, wrong limits,
    /// native/signed/canonical history disagreement or missing pending capacity.
    pub(super) fn admit(
        origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    ) -> Result<Self, HostOwnedJournalErrorV1> {
        origins.recheck()?;
        let inputs = AdmittedHostTpmInputsV1::admit(origins)?;
        let main_limits = origins.compared_main_limits()?;
        let (mut main, main_report) = Journal::open_existing_protected_at(
            Path::new(JOURNAL_DIRECTORY), MAIN_JOURNAL_NAME, main_limits,
        )?;
        if main_report.truncated_bytes != 0 {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        drop(origins.hold_main(&mut main)?);
        let limits = sidecar_limits(main_limits)?;
        let (journal, sidecar_report) = Journal::open_existing_protected_at(
            Path::new(JOURNAL_DIRECTORY), SIDECAR_JOURNAL_NAME, limits,
        )?;
        if sidecar_report.truncated_bytes != 0 {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        let custody = HostSidecarCustodyV1 { journal, main_limits, origins };
        let mut owner = Self {
            origins, inputs, main,
            store: HostSidecarStoreV1::from_host(custody),
            usable: true,
        };
        owner.recheck()?;
        Ok(owner)
    }

    /// Rechecks the same genuine inputs, full native pair and typed disk chain.
    ///
    /// # Errors
    /// Rejects previous failure, any original drift or unavailable cold suffix.
    pub(super) fn recheck(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        self.begin_operation()?;
        self.recheck_inner()?;
        self.usable = true;
        Ok(())
    }

    /// Returns rechecked disk-only associations, never fresh NV recovery rights.
    ///
    /// # Errors
    /// Rejects owner/input/pair/history drift, pending capacity or prior failure.
    pub(super) fn compare_cold_disk_state(
        &mut self,
    ) -> Result<StoredHostFloorV1, HostOwnedJournalErrorV1> {
        self.begin_operation()?;
        let stored = self.recheck_inner()?;
        self.usable = true;
        Ok(stored)
    }

    /// Funds one exact signed TX and ordered suffix while borrowing this owner.
    ///
    /// # Errors
    /// Rejects a substituted/past TX, signed/native/schema mismatch, stale
    /// originals or any of the actual eight main/sidecar native limit failures.
    pub(super) fn fund_exact_transition<'owner, 'tx>(
        &'owner mut self,
        transaction: &'tx JournalTransaction,
    ) -> Result<HostFundingCutV1<'owner, 'origin, 'startup, 'tx>, HostOwnedJournalErrorV1> {
        self.begin_operation()?;
        let stored = self.recheck_inner()?;
        let intent = match &stored.prepared {
            Some((intent, original)) => {
                if transaction != original {
                    return Err(HostOwnedJournalErrorV1::Changed);
                }
                *intent
            }
            None => {
                let target = self.compare_prospective(transaction, stored.current)?;
                HostFloorIntentDataV1::compare_successor(
                    self.origins_scope()?, stored.checkpoint, target, transaction,
                )?
            }
        };
        let main_token = if stored.association == HostDiskAssociationV1::PendingMainTarget {
            // The same original TX was authenticated at its historical native
            // predecessor/target above. It must never be preflighted again.
            None
        } else {
            let authority = self.main
                .claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?;
            let token = authority.preflight_transactions(std::slice::from_ref(transaction))?;
            authority.validate_preflight_for_effect(&token, std::slice::from_ref(transaction))?;
            Some(token)
        };
        let main_snapshot = self.main
            .claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?.snapshot()?;
        let suffix = self.store.fund_suffix(intent, transaction, stored.prepared.is_some())?;
        if self.recheck_inner()? != stored {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        self.usable = true;
        let mut funded = HostFundingCutV1 {
            owner: self, transaction, stored, intent, main_token, main_snapshot, suffix,
        };
        funded.recheck()?;
        Ok(funded)
    }

    fn begin_operation(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        close_owner_health(&mut self.usable)
    }

    fn origins_scope(&mut self) -> Result<[u8; 32], HostOwnedJournalErrorV1> {
        Ok(self.origins.hold_main(&mut self.main)?.compared_scope()?)
    }

    fn compare_prospective(
        &mut self,
        transaction: &JournalTransaction,
        current: FloorCutV1,
    ) -> Result<FloorCutV1, HostOwnedJournalErrorV1> {
        let mut held = self.origins.hold_main(&mut self.main)?.compare_append(transaction)?;
        let before = held.compared_current()?;
        if FloorCutV1::new(before.0, before.1)? != current {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        let target = held.compared_target()?;
        Ok(FloorCutV1::new(target.0, target.1)?)
    }

    fn recheck_inner(&mut self) -> Result<StoredHostFloorV1, HostOwnedJournalErrorV1> {
        self.origins.recheck()?;
        self.inputs.recheck()?;
        self.store.validate_held()?;
        let main_limits = self.origins.compared_main_limits()?;
        let expected_limits = sidecar_limits(main_limits)?;
        let stored = {
            let mut pair = self.origins.hold_pair(&mut self.main, self.store.original_mut())?;
            if pair.compared_sidecar_limits()? != expected_limits {
                return Err(HostOwnedJournalErrorV1::Changed);
            }
            let stored = compare_original_state(&mut pair, main_limits)?;
            if pair.compared_sidecar_sequence()? != stored.sidecar_sequence {
                return Err(HostOwnedJournalErrorV1::Changed);
            }
            stored
        };
        if let Some((intent, transaction)) = &stored.prepared {
            if stored.association == HostDiskAssociationV1::PendingMainOld {
                if self.compare_prospective(transaction, stored.current)? != intent.target().cut() {
                    return Err(HostOwnedJournalErrorV1::Changed);
                }
            }
            // Cold admission checks actual remaining final capacity without
            // retaining a fake future permit. The funding guard reacquires it.
            let suffix = self.store.fund_suffix(*intent, transaction, true)?;
            self.store.validate_suffix(&suffix)?;
        }
        self.store.require_projection(
            stored.checkpoint,
            stored.prepared.as_ref().map(|(intent, transaction)| (*intent, transaction)),
        )?;
        self.inputs.recheck()?;
        self.store.validate_held()?;
        self.origins.recheck()?;
        Ok(stored)
    }
}

/// Parks the SAME whole owner before any fallible physical invocation work.
///
/// No raw writer or configurable input escapes. The physical owner retains
/// this borrow; it alone may use these named original comparison/loan seams.
pub(in crate::tpm_nv_custody) struct HeldHostPhysicalJournalV1<'owner, 'origin, 'startup> {
    owner: &'owner mut HostOwnedJournalInputsV1<'origin, 'startup>,
    admitted_usable: bool,
}

impl<'owner, 'origin, 'startup> HeldHostPhysicalJournalV1<'owner, 'origin, 'startup> {
    pub(super) fn park(owner: &'owner mut HostOwnedJournalInputsV1<'origin, 'startup>) -> Self {
        let admitted_usable = owner.usable;
        owner.usable = false;
        Self { owner, admitted_usable }
    }

    pub(super) fn claim_invocation(
        &self,
    ) -> Result<HostPhysicalInvocationLeaseV1<'origin, 'startup>, HostPhysicalInvocationErrorV1> {
        self.owner.origins.claim_host_physical_invocation()
    }

    pub(super) fn close(&mut self) {
        self.admitted_usable = false;
        self.owner.usable = false;
    }

    pub(super) fn compare_state(
        &mut self,
    ) -> Result<(StoredHostFloorV1, [u8; 32]), HostOwnedJournalErrorV1> {
        if !self.admitted_usable {
            return Err(HostOwnedJournalErrorV1::Unusable);
        }
        let stored = self.owner.recheck_inner()?;
        let scope = self.owner.origins_scope()?;
        if self.owner.recheck_inner()? != stored {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        Ok((stored, scope))
    }

    pub(super) fn helper_path(&self) -> &Path {
        self.owner.inputs.helper_path()
    }

    pub(super) fn require_executed_helper(
        &mut self,
        pid: u32,
    ) -> Result<(), super::HostTpmAdmissionErrorV1> {
        self.owner.inputs.require_executed_helper(pid)
    }

    pub(super) fn current_auth(
        &mut self,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, super::HostTpmAdmissionErrorV1> {
        self.owner.inputs.current_auth()
    }

    pub(super) fn names(&self) -> ([u8; 34], [u8; 34]) {
        let claims = self.owner.origins.genesis_claims();
        (claims.nv_name, claims.salt_name)
    }

    pub(super) fn loan_main(
        &mut self,
    ) -> Result<ProtectedJournalLockCustodyV1, HostOwnedJournalErrorV1> {
        self.compare_state()?;
        let loan = self.owner.origins.hold_main(&mut self.owner.main)?.loan_main_lock()?;
        self.compare_state()?;
        Ok(loan)
    }

    pub(super) fn loan_sidecar(
        &mut self,
    ) -> Result<ProtectedJournalLockCustodyV1, HostOwnedJournalErrorV1> {
        self.compare_state()?;
        let loan = self.owner.store.loan_host_lock()?;
        self.compare_state()?;
        Ok(loan)
    }
}

/// Retains exact funding DATA plus the whole original owner and original TX.
///
/// No fields, raw tokens/writers, mutation or physical capability are exported.
/// Any future prepare invalidates a two-TX suffix: a later granted coordinator
/// must read actual pending state and reacquire its fresh final-only suffix.
#[must_use = "exact funding DATA must keep both actual originals borrowed"]
pub(super) struct HostFundingCutV1<'owner, 'origin, 'startup, 'tx> {
    owner: &'owner mut HostOwnedJournalInputsV1<'origin, 'startup>,
    transaction: &'tx JournalTransaction,
    stored: StoredHostFloorV1,
    intent: HostFloorIntentDataV1,
    main_token: Option<ProtectedJournalPreflight>,
    main_snapshot: ProtectedJournalSnapshot,
    suffix: HostSuffixPreflightV1,
}

impl HostFundingCutV1<'_, '_, '_, '_> {
    /// Rechecks full original state and exact instance/sequence/ordered funding.
    ///
    /// # Errors
    /// Rejects any input/history drift, substituted token/TX or previous failure.
    pub(super) fn recheck(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        self.owner.begin_operation()?;
        if self.owner.recheck_inner()? != self.stored {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        self.intent.require_transaction(self.transaction)?;
        let authority = self.owner.main
            .claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?;
        authority.validate_snapshot_for_effect(&self.main_snapshot)?;
        if let Some(token) = &self.main_token {
            authority.validate_preflight_for_effect(token, std::slice::from_ref(self.transaction))?;
        }
        drop(authority);
        self.owner.store.validate_suffix(&self.suffix)?;
        if self.owner.recheck_inner()? != self.stored {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        self.owner.usable = true;
        Ok(())
    }

    /// Returns only rechecked complete predecessor/target cut DATA.
    ///
    /// # Errors
    /// Rejects drift or an unusable owner/funding guard; grants no effect.
    pub(super) fn compared_cuts(&mut self) -> Result<(FloorCutV1, FloorCutV1), HostOwnedJournalErrorV1> {
        self.recheck()?;
        Ok((self.intent.predecessor().cut(), self.intent.target().cut()))
    }
}

fn close_owner_health(usable: &mut bool) -> Result<(), HostOwnedJournalErrorV1> {
    if !*usable {
        return Err(HostOwnedJournalErrorV1::Unusable);
    }
    *usable = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrun_whole_owner_health_refuses_closed_data_without_constructing_origins() {
        let mut usable = true;

        close_owner_health(&mut usable).unwrap();

        assert!(!usable);
        assert!(matches!(close_owner_health(&mut usable), Err(HostOwnedJournalErrorV1::Unusable)));
    }

    #[test]
    fn unrun_private_health_closes_before_unwind_without_fabricating_an_owner() {
        let mut usable = true;

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            close_owner_health(&mut usable).unwrap();
            panic!("inert private latch vector");
        }));

        assert!(result.is_err());
        assert!(!usable);
    }
}
