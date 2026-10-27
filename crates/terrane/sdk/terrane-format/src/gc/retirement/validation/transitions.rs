//! Checks represented immutable ownership and nonterminal pass transitions.
//!
//! Actual winning chain selection, current lease/clock and fair future work
//! remain independent obligations; public history alone cannot dispatch effects.

use super::*;
use alloc::collections::BTreeMap;

impl PermanentDeleteAuthorization {
    /// Returns the exact original exclusion, without authenticating it.
    pub const fn exclusion(&self) -> &Exclusion {
        match self {
            Self::Sweep(value) => &value.exclusion,
            Self::Copied(value) => &value.exclusion,
        }
    }

    /// Returns the claimed actual physical backend binding.
    pub const fn backend(&self) -> &BackendBinding {
        match self {
            Self::Sweep(value) => &value.backend,
            Self::Copied(value) => &value.backend,
        }
    }

    /// Returns the immutable claimed secure operation nonce.
    pub const fn nonce(&self) -> &[u8; 32] {
        match self {
            Self::Sweep(value) => &value.nonce,
            Self::Copied(value) => &value.nonce,
        }
    }

    /// Checks exact operation-key association without establishing ownership.
    ///
    /// # Errors
    /// Rejects malformed authorization/key or mismatched pack, cycle or nonce.
    pub fn check_key(&self, key: &str) -> Result<(), RetirementError> {
        self.encode()?;
        let (cycle, pack, nonce) = operation_key(key)?;
        if cycle != self.exclusion().cycle
            || pack != self.exclusion().pack
            || &nonce != self.nonce()
        {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }

    /// Checks the authorization against its represented selecting predecessor state.
    ///
    /// This checks current stamp and burn relationships only, without authenticating
    /// the predecessor, current inputs, lease or completed wait.
    ///
    /// # Errors
    /// Rejects a future/wrong fence revision, changed backend, unknown owners,
    /// an already owned sweep or a copied retirement without visibility-only burn.
    pub fn check_predecessor(&self, state: &PublicationState) -> Result<(), RetirementError> {
        self.encode()?;
        state.encode()?;
        let pointer = match self {
            Self::Sweep(value) => &value.fence,
            Self::Copied(value) => &value.fence,
        };
        let (_, revision) = fence::fence_pointer(pointer)?;
        let owners = state
            .burn_owners
            .as_ref()
            .ok_or(RetirementError::Contradiction)?;
        if revision != state.revision || self.backend() != &state.binding || state.guard.is_none() {
            return Err(RetirementError::Contradiction);
        }
        let prior = owners
            .iter()
            .find(|owner| owner.pack == self.exclusion().pack);
        if let Self::Copied(value) = self
            && let Some(lineage) = &value.lineage_fence
            && fence::fence_pointer(lineage)?.1 != state.revision
        {
            return Err(RetirementError::Contradiction);
        }
        match self {
            Self::Sweep(_) if prior.is_some() => return Err(RetirementError::Contradiction),
            Self::Copied(value)
                if value.preparation.revision > state.revision
                    || prior.is_none_or(|owner| {
                        owner.selection != PermanentOwnerSelection::CopiedVisibility
                    }) =>
            {
                return Err(RetirementError::Contradiction);
            }
            _ => {}
        }
        Ok(())
    }

    /// Checks the represented first winning owner slot follows its final fence.
    ///
    /// The slot's actual selected chain and digest require independent resolution.
    ///
    /// # Errors
    /// Rejects revision overflow or a slot not immediately following the predecessor fence.
    pub fn check_owner_slot(&self, owner: &OwnershipSlot) -> Result<(), RetirementError> {
        self.encode()?;
        let pointer = match self {
            Self::Sweep(value) => &value.fence,
            Self::Copied(value) => &value.fence,
        };
        let (_, revision) = fence::fence_pointer(pointer)?;
        if revision.checked_add(1).ok_or(RetirementError::Exhausted)? != owner.revision {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }

    /// Checks represented G > enforced C without trusting either setting.
    ///
    /// The private factory must obtain C from actual enforced client settings
    /// and independently prove both live FULL completed observations.
    ///
    /// # Errors
    /// Rejects invalid authorization, overflow or a grace window not longer than C.
    pub fn check_commit_duration(&self, commit_seconds: u64) -> Result<(), RetirementError> {
        self.encode()?;
        let grace = match self {
            Self::Sweep(value) => value.grace_seconds,
            Self::Copied(value) => value.grace_seconds,
        };
        commit_seconds
            .checked_mul(1_000_000_000)
            .ok_or(RetirementError::Exhausted)?;
        if grace <= commit_seconds {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }

    /// Checks the exact represented current fence and initial physical exclusion.
    ///
    /// No pointed-to roots, actual placement, trust, clock or current lease is
    /// certified. The runtime must independently check those complete inputs.
    ///
    /// # Errors
    /// Rejects malformed or wrong-kind fence bytes, raw digest/backend disagreement,
    /// unknown catalog completeness, missing exact exclusion or incompatible burn.
    pub fn check_fence(&self, bytes: &[u8]) -> Result<(), RetirementError> {
        self.encode()?;
        let (state, manifest) = match self {
            Self::Sweep(value) => {
                let fence = CurrentCollectionFence::decode(bytes)?;
                fence.check_pointer(&value.fence)?;
                if fence.refs.iter().any(|row| {
                    matches!(
                        row.selection,
                        crate::gc::publication::CommittedSelection::Unknown
                    )
                }) {
                    return Err(RetirementError::Contradiction);
                }
                if fence.backend != value.backend {
                    return Err(RetirementError::Contradiction);
                }
                (
                    fence.state,
                    fence.manifest.ok_or(RetirementError::Contradiction)?,
                )
            }
            Self::Copied(value) => {
                let fence = CopiedPlacementFence::decode(bytes)?;
                fence.check_pointer(&value.fence)?;
                if fence.refs.iter().any(|row| {
                    matches!(
                        row.selection,
                        crate::gc::publication::CommittedSelection::Unknown
                    )
                }) {
                    return Err(RetirementError::Contradiction);
                }
                if fence.backend != value.backend
                    || fence.genesis != value.genesis
                    || value.preparation.revision > fence.state.revision
                {
                    return Err(RetirementError::Contradiction);
                }
                (fence.state, fence.manifest)
            }
        };
        let manifest = crate::bucket::GenerationManifest::decode(&manifest)?;
        let exclusions = manifest
            .exclusions
            .as_ref()
            .ok_or(RetirementError::Contradiction)?;
        let burns = manifest
            .burns
            .as_ref()
            .ok_or(RetirementError::Contradiction)?;
        if manifest.inventory.is_none()
            || state.burn_owners.is_none()
            || !exclusions.iter().any(|row| {
                row.pack_id == self.exclusion().pack
                    && row.cycle == self.exclusion().cycle
                    && row.epoch == self.exclusion().epoch
            })
        {
            return Err(RetirementError::Contradiction);
        }
        let burned = burns.binary_search(&self.exclusion().pack).is_ok();
        match self {
            Self::Sweep(_) if burned => return Err(RetirementError::Contradiction),
            Self::Copied(_)
                if !state.burn_owners.as_ref().is_some_and(|owners| {
                    owners.iter().any(|row| {
                        row.pack == self.exclusion().pack
                            && row.selection == PermanentOwnerSelection::CopiedVisibility
                    })
                }) =>
            {
                return Err(RetirementError::Contradiction);
            }
            _ => {}
        }
        Ok(())
    }
}

impl CopiedRetirementPlan {
    /// Checks exact plan-key association without creating barrier permission.
    ///
    /// # Errors
    /// Rejects malformed plans/keys or mismatched pack, cycle or nonce.
    pub fn check_key(&self, key: &str) -> Result<(), RetirementError> {
        self.encode()?;
        let (cycle, pack, nonce) = operation_key(key)?;
        if cycle != self.exclusion.cycle || pack != self.exclusion.pack || nonce != self.nonce {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }
}

impl CopiedRetirementPreparation {
    /// Checks immutable-plan preparation progress without claiming selection.
    ///
    /// # Errors
    /// Rejects invalid records, changed plans, nonconsecutive revisions or abandonment regression.
    pub fn check_successor(&self, next: &Self) -> Result<(), RetirementError> {
        self.encode()?;
        next.encode()?;
        if next.revision
            != self
                .revision
                .checked_add(1)
                .ok_or(RetirementError::Exhausted)?
            || self.plan != next.plan
            || self.phase == PreparationPhase::Abandoned
        {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }
}

impl CopiedRetirementAuthorization {
    /// Checks final authorization against its exact earlier selected preparation.
    ///
    /// Same-holder/epoch lease renewal may extend expiry without changing valid
    /// barrier age. Actual current whole lease and live continuity remain runtime checks.
    /// Final physical and optional lineage checkpoints may use fresh collection
    /// cycles; their current predecessor and complete inputs require independent
    /// qualification without replacing the preparation's barrier.
    ///
    /// # Errors
    /// Rejects malformed records, wrong preparation slot/plan, changed backend,
    /// nonce, barrier, settings, holder/epoch or regressed lease expiry.
    pub fn check_preparation(
        &self,
        preparing: &CopiedRetirementPreparation,
        slot: &OwnershipSlot,
    ) -> Result<(), RetirementError> {
        self.encode()?;
        preparing.encode()?;
        let plan = &preparing.plan;
        let (_, predecessor_revision) = fence::fence_pointer(&plan.fence)?;
        if predecessor_revision
            .checked_add(1)
            .ok_or(RetirementError::Exhausted)?
            != slot.revision
            || preparing.phase != PreparationPhase::Preparing
            || &self.preparation != slot
            || self.nonce != plan.nonce
            || self.backend != plan.backend
            || self.exclusion != plan.exclusion
            || self.genesis != plan.genesis
            || self.tombstone != plan.tombstone
            || self.grace_seconds != plan.grace_seconds
            || self.deletion_seconds != plan.deletion_seconds
            || self.lease.holder != plan.lease.holder
            || self.lease.epoch != plan.lease.epoch
            || self.lease.expiry < plan.lease.expiry
        {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }
}

impl PermanentDeleteOperation {
    /// Checks consecutive progress with immutable authorization and owner.
    ///
    /// Cancellation from Proposed is valid data only for an actually unselected
    /// proposal. The runtime must resolve authoritative ownership before cancelling;
    /// a stale Proposed/null cache never proves that ownership did not win.
    ///
    /// # Errors
    /// Rejects changed authorization, revision overflow/gaps, owner replacement,
    /// cancellation after Owned or any progress from Cancelled.
    pub fn check_successor(&self, next: &Self) -> Result<(), RetirementError> {
        self.encode()?;
        next.encode()?;
        if next.revision
            != self
                .revision
                .checked_add(1)
                .ok_or(RetirementError::Exhausted)?
            || self.authorization != next.authorization
        {
            return Err(RetirementError::Contradiction);
        }
        match (self.phase, next.phase) {
            (OperationPhase::Proposed, OperationPhase::Owned | OperationPhase::Cancelled) => {}
            (OperationPhase::Owned, OperationPhase::Owned) if self.owner == next.owner => {}
            _ => return Err(RetirementError::Contradiction),
        }
        Ok(())
    }

    /// Checks exact selected pass bytes and their immutable owner association.
    ///
    /// # Errors
    /// Rejects malformed records, a non-Owned operation, pointer/digest mismatch,
    /// wrong authorization/owner or operation revision disagreement.
    pub fn check_pass(&self, bytes: &[u8], operation_key: &str) -> Result<(), RetirementError> {
        self.encode()?;
        self.authorization.check_key(operation_key)?;
        let pointer = self.pass.as_ref().ok_or(RetirementError::Contradiction)?;
        let owner = self.owner.as_ref().ok_or(RetirementError::Contradiction)?;
        let pass = PermanentDeletePass::decode(bytes)?;
        pass.check_owner(&self.authorization, operation_key, owner)?;
        pass.check_key(&pointer.key, self.authorization.exclusion().cycle)?;
        if pointer.digest != *blake3::hash(bytes).as_bytes() || pass.revision != self.revision {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }
}

impl PermanentDeletePass {
    /// Checks original-owner associations against exact authorization and selected state.
    ///
    /// The selector and slot must independently come from the checked immutable
    /// chain. Equality alone never authenticates either or current progress permission.
    ///
    /// # Errors
    /// Rejects malformed records, authorization/key/slot/backend disagreement,
    /// missing permanent selector, malformed placement fence or wrong revision.
    pub fn check_owner(
        &self,
        authorization: &PermanentDeleteAuthorization,
        key: &str,
        owner: &OwnershipSlot,
    ) -> Result<(), RetirementError> {
        self.encode()?;
        authorization.check_key(key)?;
        authorization.check_owner_slot(owner)?;
        let digest = *blake3::hash(&authorization.encode()?).as_bytes();
        let expected = PermanentBurnOwner {
            pack: authorization.exclusion().pack,
            selection: PermanentOwnerSelection::Permanent(RecordPointer {
                key: key.into(),
                digest,
            }),
        };
        if self.nonce == *authorization.nonce()
            || self.authorization_digest != digest
            || &self.owner != owner
            || &self.backend != authorization.backend()
            || !self
                .state
                .burn_owners
                .as_ref()
                .is_some_and(|owners| owners.contains(&expected))
        {
            return Err(RetirementError::Contradiction);
        }
        if let Some(pointer) = &self.placement_fence {
            let (_, revision) = fence::fence_pointer(pointer)?;
            // A recurring pass may use a later current collection cycle while
            // its immutable owner and reconciliation key retain the old cycle.
            if revision != self.predecessor.revision {
                return Err(RetirementError::Contradiction);
            }
        }
        Ok(())
    }

    /// Checks exact immutable event-key cycle, fresh event nonce and revision.
    ///
    /// # Errors
    /// Rejects malformed keys, owner-cycle, event-nonce or revision mismatch.
    pub fn check_key(&self, key: &str, owner_cycle: u64) -> Result<(), RetirementError> {
        self.encode()?;
        let (cycle, nonce, revision) = pass_key(key)?;
        if cycle != owner_cycle || nonce != self.nonce || revision != self.revision {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }

    /// Checks the initial 0/0 pass following its selected ownership operation.
    ///
    /// # Errors
    /// Rejects noninitial counters, revision overflow/gaps or changed authorization.
    pub fn check_initial(
        &self,
        proposed: &PermanentDeleteOperation,
    ) -> Result<(), RetirementError> {
        self.encode()?;
        proposed.encode()?;
        if self.phase != PassPhase::Open
            || proposed.phase != OperationPhase::Proposed
            || self.pass != 0
            || self.event != 0
            || self.revision
                != proposed
                    .revision
                    .checked_add(1)
                    .ok_or(RetirementError::Exhausted)?
            || self.authorization_digest
                != *blake3::hash(&proposed.authorization.encode()?).as_bytes()
        {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }

    /// Checks event arithmetic and unchanged original permanent ownership.
    ///
    /// This checks two events only. Completed-pass validation across all deltas
    /// also requires [`Self::check_pass_history`] and actual selected history.
    ///
    /// # Errors
    /// Rejects changed owner/backend, revision/counter overflow or invalid pass progression.
    pub fn check_successor(&self, next: &Self) -> Result<(), RetirementError> {
        self.encode()?;
        next.encode()?;
        let counters = match self.phase {
            PassPhase::Open => (
                self.pass,
                self.event
                    .checked_add(1)
                    .ok_or(RetirementError::Exhausted)?,
            ),
            PassPhase::PassCompleted => (
                self.pass.checked_add(1).ok_or(RetirementError::Exhausted)?,
                0,
            ),
        };
        if next.revision
            != self
                .revision
                .checked_add(1)
                .ok_or(RetirementError::Exhausted)?
            || (next.pass, next.event) != counters
            || self.owner != next.owner
            || self.authorization_digest != next.authorization_digest
            || self.nonce == next.nonce
            || self.backend != next.backend
            || next.predecessor.revision <= self.predecessor.revision
        {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }

    /// Checks unresolved Planned duties across every represented event in one pass.
    ///
    /// The slice must independently be the complete selected pass history; omitted
    /// events or public deltas do not prove completeness. Indeterminate and Deferred
    /// remain duties after candidate traversal and do not establish all-version absence.
    ///
    /// # Errors
    /// Rejects empty/incomplete counters, inconsistent successors or completion
    /// while any accumulated target remains Planned.
    pub fn check_pass_history(events: &[Self]) -> Result<(), RetirementError> {
        let first = events.first().ok_or(RetirementError::Contradiction)?;
        if first.event != 0 {
            return Err(RetirementError::Contradiction);
        }
        let mut unresolved = BTreeMap::new();
        let mut previous: Option<&Self> = None;
        for event in events {
            event.encode()?;
            if event.pass != first.pass {
                return Err(RetirementError::Contradiction);
            }
            if let Some(prior) = previous {
                prior.check_successor(event)?;
            }
            for row in &event.observations {
                unresolved.insert((row.artifact, row.instance.clone()), row.state);
            }
            if event.phase == PassPhase::PassCompleted
                && unresolved
                    .values()
                    .any(|state| *state == ObservationState::Planned)
            {
                return Err(RetirementError::Contradiction);
            }
            previous = Some(event);
        }
        Ok(())
    }
}
