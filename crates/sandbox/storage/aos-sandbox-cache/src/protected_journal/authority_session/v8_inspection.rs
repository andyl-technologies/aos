//! Suspends the original ordinary V8 inspection within its actual authority claim.
//!
//! The same replay verifier, canonical state replay and inventory reconstruction
//! remain the only engines. An upper inspect runs before the original inner
//! refresh and independently owed outer currentness check. No supplied result
//! or DATA can construct a release proof or native writer.

use super::*;
use crate::domain::CacheAuthorityReadbackBindingV1;
use crate::physical::CacheOwnerHeldSnapshotV1;
use crate::protected_owner::CacheResidencyWriterReadbackV2;
use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;
use std::cell::Cell;
use std::sync::MutexGuard;

/// Holds the original authority Mutex through one finite ordinary inspection.
#[doc(hidden)]
pub struct CacheV8InspectionGuardV1<'capture> {
    journal: MutexGuard<'capture, Journal>,
    state: &'capture mut Journal,
    source: &'capture ProtectedCacheResidencyReplayAuthorityV1,
    physical: &'capture CacheOwnerHeldSnapshotV1<'capture>,
    quota: &'capture mut Option<ObjectDigest>,
    limits: crate::CacheOwnerLimitsV1,
    hold: CachePolicyHoldV1,
    now: u64,
    entered: bool,
    native_refused: &'capture Cell<bool>,
    inspection_complete: &'capture Cell<bool>,
}

/// Keeps the same claim, decoder models and currentness view across inspect.
#[doc(hidden)]
pub struct CacheV8InspectionContextV1<'capture> {
    readback: Option<CacheResidencyWriterReadbackV2>,
    inventories: Option<Vec<CacheRecoveryInventoryV1>>,
    projection: Option<CacheResidencyProtectedJournalProjectionV1>,
    validator: Option<CacheResidencyReplayValidatorV1>,
    failure: Option<CacheResidencyProtectedJournalErrorV1>,
    view: VerifiedCacheAuthorityViewV1,
    partitions: CacheReplayPartitionEvidenceMapV1,
    binding: CacheAuthorityReadbackBindingV1,
    authority: ProtectedJournalAuthority<'capture>,
    state: &'capture mut Journal,
    source: &'capture ProtectedCacheResidencyReplayAuthorityV1,
    physical: &'capture CacheOwnerHeldSnapshotV1<'capture>,
    quota: &'capture mut Option<ObjectDigest>,
    limits: crate::CacheOwnerLimitsV1,
    hold: CachePolicyHoldV1,
    refresh_entered: bool,
    outer_entered: bool,
    native_refused: &'capture Cell<bool>,
    inspection_complete: &'capture Cell<bool>,
}

impl ProtectedCacheResidencyReplayAuthorityV1 {
    pub(crate) fn borrow_v8_inspection_v1<'capture>(
        &'capture self,
        state: &'capture mut Journal,
        physical: &'capture CacheOwnerHeldSnapshotV1<'capture>,
        quota: &'capture mut Option<ObjectDigest>,
        limits: crate::CacheOwnerLimitsV1,
        hold: CachePolicyHoldV1,
        native_refused: &'capture Cell<bool>,
        inspection_complete: &'capture Cell<bool>,
    ) -> Result<CacheV8InspectionGuardV1<'capture>, CacheResidencyProtectedJournalErrorV1> {
        // These are the exact first two entries in while_authority_current.
        let now = self.current_time.current_unix_seconds()?;
        let journal = self
            .journal
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        Ok(CacheV8InspectionGuardV1 {
            journal,
            state,
            source: self,
            physical,
            quota,
            limits,
            hold,
            now,
            entered: false,
            native_refused,
            inspection_complete,
        })
    }
}

impl CacheV8InspectionGuardV1<'_> {
    /// Begins this guard's sole same-claim inspection context.
    ///
    /// # Errors
    /// Preserves the original authority, requested/replay verification and
    /// partition-model failures; refuses repeated context construction.
    pub fn borrow_context_once_v1(
        &mut self,
    ) -> Result<CacheV8InspectionContextV1<'_>, CacheResidencyProtectedJournalErrorV1> {
        if self.entered {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.entered = true;
        let authority = self
            .journal
            .claim_cache_authority_v1()
            .map_err(ProtectedDomainJournalErrorV1::from)?;
        let owner = CacheAuthorityOwner::new(
            &authority,
            self.source.owner_scope,
            self.source.maximum_record_bytes,
        )
        .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let capabilities = verify_requested(&owner, &[], self.now)?;
        let partitions = self
            .source
            .partitions
            .lock()
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?
            .clone();
        let view = verify_replay(
            &authority,
            &owner,
            self.source.owner_scope,
            self.source.limits,
            &partitions,
            capabilities,
            self.now,
        )?;
        // Moving this private header avoids a self-reference. Reborrowing
        // the SAME claim below does not rerun owner.new's snapshot observation.
        let binding = owner.into_readback_binding_v1();
        let validator = view.validator.clone();
        let mut context = CacheV8InspectionContextV1 {
            readback: None,
            inventories: None,
            projection: None,
            validator: Some(validator),
            view,
            partitions,
            binding,
            authority,
            state: &mut *self.state,
            source: self.source,
            physical: self.physical,
            quota: &mut *self.quota,
            limits: self.limits,
            hold: self.hold,
            failure: None,
            refresh_entered: false,
            outer_entered: false,
            native_refused: self.native_refused,
            inspection_complete: self.inspection_complete,
        };
        if let Err(cause) = context.capture_models() {
            context.native_refused.set(true);
            context.failure = Some(cause);
        }
        Ok(context)
    }
}

impl CacheV8InspectionContextV1<'_> {
    fn capture_models(&mut self) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let validator = self
            .validator
            .as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let projection =
            CacheResidencyProtectedJournalV1::claim(self.state, validator.clone())?.replay()?;
        self.projection = Some(projection);
        let projection = self
            .projection
            .as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        self.inventories = Some(reconstruct_cache_history(projection.records(), validator)?);
        let inventories = self
            .inventories
            .as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let readback =
            CacheResidencyWriterReadbackV2::from_current_inventories(self.hold, inventories)?;
        if !self.limits.matches_node_quotas(readback.node_quotas()) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.physical
            .revalidate()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        *self.quota = Some(readback.quota_digest());
        self.readback = Some(readback);
        Ok(())
    }

    /// Borrows the actual complete readback while its native claim stays held.
    ///
    /// A failed capture returns None and cannot enter an upper inspection.
    #[must_use]
    pub fn readback_v1(&self) -> Option<&CacheResidencyWriterReadbackV2> {
        if self.failure.is_some() {
            None
        } else {
            self.readback.as_ref()
        }
    }

    fn validate_current(&self) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let current = self.source.current_time.current_unix_seconds()?;
        let owner = self.binding.borrow_same_claim_v1(&self.authority);
        validate_current(&owner, &[], &self.view, current)?;
        Ok(())
    }

    // Readback/inventories lived inside select and ended before refresh. The
    // projection lived outside select and ended after refresh, before the
    // independently owed outer currentness. Keep those exact disposal slots.
    fn drop_selected_models(&mut self) {
        drop(self.readback.take());
        drop(self.inventories.take());
    }

    /// Retires failed capture models before the uncalled upper inspection drops.
    ///
    /// Completed reconstruction means select owned the inventories: its local
    /// readback/inventories end before the inspect capture, while projection
    /// and validator end afterward in the outer finish. A failure before that
    /// boundary ends projection/validator first. The original failure remains
    /// parked for the independently owed outer-currentness precedence.
    /// This negative-only retirement performs no observation or admission.
    pub fn retire_failed_capture_before_upper_drop_v1(&mut self) {
        self.native_refused.set(true);
        if self.failure.is_none() {
            return;
        }

        let entered_select = self.inventories.is_some();
        self.drop_selected_models();
        if !entered_select {
            drop(self.projection.take());
            drop(self.validator.take());
        }
    }

    /// Runs the original inner refresh after a successful upper inspection.
    ///
    /// # Errors
    /// Preserves the inner currentness refusal and rejects repeated refreshes.
    /// The caller must drop a prepared continuation on failure before borrowing
    /// this context for its independently owed outer post.
    pub fn refresh_after_inspect_once_v1(
        &mut self,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        if self.refresh_entered
            || self.outer_entered
            || self.failure.is_some()
            || self.native_refused.get()
        {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.refresh_entered = true;
        self.drop_selected_models();
        let returned = self.validate_current();
        if returned.is_err() {
            self.native_refused.set(true);
        }
        returned
    }

    /// Runs the independently owed outer post after the inner refresh boundary.
    ///
    /// # Errors
    /// Preserves the original outer-currentness precedence. The inner result
    /// remains owned by the caller, which disposes a failed continuation before
    /// this post. The claim stays borrowed so an outer refusal drops any
    /// successful continuation before the original authority view and claim.
    pub fn finish_after_inspect_v1(&mut self) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        if self.outer_entered {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.outer_entered = true;
        self.drop_selected_models();
        drop(self.projection.take());
        drop(self.validator.take());
        if let Err(cause) = self.validate_current() {
            self.native_refused.set(true);
            // The old failed action Result dropped before view/partitions.
            drop(self.failure.take());
            return Err(cause);
        }
        if let Some(cause) = self.failure.take() {
            self.native_refused.set(true);
            return Err(cause);
        }
        if self.refresh_entered && !self.native_refused.get() {
            self.inspection_complete.set(true);
        } else {
            self.native_refused.set(true);
        }
        Ok(())
    }

    /// Runs only the independently owed outer post after an upper refusal.
    ///
    /// # Errors
    /// Retains the original outer-post precedence and returns an earlier native
    /// capture cause when that post succeeds. This cannot release any owner.
    pub fn finish_after_upper_refusal_v1(
        &mut self,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.native_refused.set(true);
        self.finish_after_inspect_v1()
    }
}

impl Drop for CacheV8InspectionGuardV1<'_> {
    fn drop(&mut self) {
        if !self.inspection_complete.get() {
            self.native_refused.set(true);
        }
    }
}

impl Drop for CacheV8InspectionContextV1<'_> {
    fn drop(&mut self) {
        if !self.inspection_complete.get() {
            self.native_refused.set(true);
        }
    }
}
