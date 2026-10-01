//! Protected preparation and reconciliation under two retained journal writers.
//!
//! The existing traffic writer is acquired first, this same-owner sidecar
//! second, and the sealed TPM transport last. The composition grants no
//! endpoint, method, readiness, or effect authority by itself.
//!
//! The separate sidecar owns namespace 47 and exactly these canonical keys:
//!
//! ```text
//! checkpoint = AOSBTF01 (156 bytes)
//! intent     = AOSBTI01 (324 bytes), present only with transaction
//! transaction = AOSJPT01, exact existing ordered JournalTransaction
//! ```

mod store;
pub(crate) use store::BrokerSidecarCustodyV1;
mod traffic;

use aos_sandbox::{JournalTransaction, ProtectedJournalLockCustodyV1};

use super::backend::{AuthenticatedTpmNvIoV1, FloorAdvanceV1, TpmNvExtendFloorBackendV1};
use super::{FloorErrorV1, FloorIntentV1, FloorProfileV1, FloorRecoveryV1, reconcile_floor_v1};
use store::{FinalSuffixPreflightV1, FloorStoreV1, StoredFloorV1};
use traffic::HeldTrafficWriterV1;

pub(super) fn attach_broker_floor_v1<Io: AuthenticatedTpmNvIoV1>(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    profile: FloorProfileV1,
    make_io: impl FnOnce([ProtectedJournalLockCustodyV1; 2]) -> Result<Io, FloorErrorV1>,
) -> Result<AttachedFloorV1<Io>, FloorErrorV1> {
    let mut floor = DurableTpmFloorV1::open_with_factory(
        traffic::BrokerTrafficWriterV1::borrow(owner),
        profile,
        make_io,
    )?;
    if floor.recover()? != FloorProgressV1::Current {
        return Err(FloorErrorV1::Diverged);
    }
    Ok(floor.detach())
}

pub(super) fn check_broker_floor_v1<Io: AuthenticatedTpmNvIoV1>(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    attached: AttachedFloorV1<Io>,
) -> Result<AttachedFloorV1<Io>, FloorErrorV1> {
    let mut floor =
        DurableTpmFloorV1::resume(traffic::BrokerTrafficWriterV1::borrow(owner), attached);
    floor.require_current()?;
    Ok(floor.detach())
}

pub(super) fn commit_broker_floor_v1<Io: AuthenticatedTpmNvIoV1>(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    attached: AttachedFloorV1<Io>,
    transaction: &JournalTransaction,
) -> Result<AttachedFloorV1<Io>, FloorErrorV1> {
    let mut floor =
        DurableTpmFloorV1::resume(traffic::BrokerTrafficWriterV1::borrow(owner), attached);
    floor.prepare(transaction)?;
    if floor.recover()? != FloorProgressV1::Current {
        return Err(FloorErrorV1::Diverged);
    }
    Ok(floor.detach())
}

pub(super) fn commit_unfloored_broker_v1(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    transaction: &JournalTransaction,
) -> Result<(), FloorErrorV1> {
    owner
        .endpoint
        .revalidate()
        .map_err(|_| FloorErrorV1::Unavailable)?;
    traffic::commit_traffic_transaction(
        owner.journal_mut().map_err(|_| FloorErrorV1::Unavailable)?,
        transaction,
    )?;
    owner
        .validate_schema_only()
        .map_err(|_| FloorErrorV1::Unavailable)?;
    owner
        .endpoint
        .revalidate()
        .map_err(|_| FloorErrorV1::Unavailable)
}

/// Retains the actual traffic writer, sidecar flock, and authenticated NV backend.
pub(super) struct DurableTpmFloorV1<Traffic, Io> {
    // Stop the TPM carrier before releasing either retained writer.
    backend: TpmNvExtendFloorBackendV1<Io>,
    store: FloorStoreV1,
    traffic: Traffic,
    profile: FloorProfileV1,
}

/// Describes a completed local check, never a public readiness/effect capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FloorProgressV1 {
    Current,
    NvNotAdvanced,
}

impl<Traffic: HeldTrafficWriterV1, Io: AuthenticatedTpmNvIoV1> DurableTpmFloorV1<Traffic, Io> {
    /// Opens existing names only after the real fixed endpoint writer has revalidated.
    pub(super) fn open(
        traffic: Traffic,
        profile: FloorProfileV1,
        io: Io,
    ) -> Result<Self, FloorErrorV1> {
        Self::open_with_factory(traffic, profile, |_| Ok(io))
    }

    fn open_with_factory(
        mut traffic: Traffic,
        profile: FloorProfileV1,
        make_io: impl FnOnce([ProtectedJournalLockCustodyV1; 2]) -> Result<Io, FloorErrorV1>,
    ) -> Result<Self, FloorErrorV1> {
        traffic.cuts(profile, None)?;
        let store = traffic.open_floor_store()?;
        let locks = [traffic.loan_lock_custody()?, store.loan_lock_custody()?];
        let backend = TpmNvExtendFloorBackendV1::open(profile, make_io(locks)?)?;
        let mut owner = Self {
            traffic,
            store,
            backend,
            profile,
        };
        owner.classify()?;
        Ok(owner)
    }

    /// Persists the full exact transaction before the first possible NV extension.
    ///
    /// A failure after the append requires dropping/reopening this composition;
    /// no I/O error is converted into a vacant preparation or retry authority.
    pub(super) fn prepare(&mut self, transaction: &JournalTransaction) -> Result<(), FloorErrorV1> {
        let stored = self.store.read(self.profile)?;
        if stored.prepared.is_some() {
            return Err(FloorErrorV1::Diverged);
        }
        let (current, target) = self.traffic.cuts(self.profile, Some(transaction))?;
        if current != stored.checkpoint.cut()
            || self.backend.read()? != stored.checkpoint.nv_value()
        {
            return Err(FloorErrorV1::Diverged);
        }
        let target = target.ok_or(FloorErrorV1::Successor)?;
        let intent = FloorIntentV1::new(self.profile, stored.checkpoint, target, transaction)?;
        self.store
            .prepare(self.profile, &stored, intent, transaction)?;

        // A changed traffic name/cut after durable prepare closes recovery. It
        // does not replace the retained target or roll the preparation back.
        let (after, prospective) = self.traffic.cuts(self.profile, Some(transaction))?;
        if after != current || prospective != Some(target) {
            return Err(FloorErrorV1::Diverged);
        }
        let retained = self.store.read(self.profile)?;
        if retained.checkpoint != stored.checkpoint
            || !retained
                .prepared
                .as_ref()
                .is_some_and(|(retained_intent, retained_transaction)| {
                    *retained_intent == intent && retained_transaction == transaction
                })
        {
            return Err(FloorErrorV1::Diverged);
        }
        self.store.require_same(&retained, self.profile)?;
        if self.backend.read()? != stored.checkpoint.nv_value() {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(())
    }

    /// Finishes only the exact persisted transaction; no new request/nonce is allocated.
    pub(super) fn recover(&mut self) -> Result<FloorProgressV1, FloorErrorV1> {
        let (stored, phase) = self.classify()?;
        let Some((intent, transaction)) = stored.prepared.as_ref() else {
            return if phase == FloorRecoveryV1::Current {
                Ok(FloorProgressV1::Current)
            } else {
                Err(FloorErrorV1::Diverged)
            };
        };
        intent.require_transaction(transaction)?;

        if phase == FloorRecoveryV1::ExtendPrepared {
            let suffix = self.require_prospective(&stored, *intent, transaction)?;
            let profile = self.profile;
            let traffic = &mut self.traffic;
            let store = &mut self.store;
            let advanced = self.backend.advance_with_held_cut(*intent, || {
                require_prospective_cut(traffic, profile, *intent, transaction)?;
                store.validate_final_preflight(&suffix, &stored, profile)
            })?;
            if advanced == FloorAdvanceV1::NotAdvanced {
                self.classify()?;
                return Ok(FloorProgressV1::NvNotAdvanced);
            }
        }
        let (stored, phase) = self.classify()?;
        let (intent, transaction) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        if phase == FloorRecoveryV1::CommitPrepared {
            let suffix = self.require_prospective(&stored, *intent, transaction)?;
            if self.backend.read()? != intent.target().nv_value() {
                return Err(FloorErrorV1::Diverged);
            }
            require_prospective_cut(&mut self.traffic, self.profile, *intent, transaction)?;
            self.store
                .validate_final_preflight(&suffix, &stored, self.profile)?;
            self.traffic
                .commit_exact(self.profile, *intent, transaction)?;
        }

        let (stored, phase) = self.classify()?;
        if phase != FloorRecoveryV1::FinalizePrepared {
            return Err(FloorErrorV1::Diverged);
        }
        let (intent, _) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        if self.backend.read()? != intent.target().nv_value() {
            return Err(FloorErrorV1::Diverged);
        }
        self.store.finalize(self.profile, &stored)?;
        let (_, phase) = self.classify()?;
        if phase != FloorRecoveryV1::Current {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(FloorProgressV1::Current)
    }

    /// Rejects pending recovery at ordinary read/use boundaries.
    pub(super) fn require_current(&mut self) -> Result<(), FloorErrorV1> {
        if self.classify()?.1 == FloorRecoveryV1::Current {
            Ok(())
        } else {
            Err(FloorErrorV1::Diverged)
        }
    }

    /// Releases only the temporary traffic borrow, retaining sidecar and TPM custody.
    pub(super) fn detach(self) -> AttachedFloorV1<Io> {
        AttachedFloorV1 {
            store: self.store,
            backend: self.backend,
            profile: self.profile,
        }
    }

    pub(super) fn resume(traffic: Traffic, attached: AttachedFloorV1<Io>) -> Self {
        Self {
            traffic,
            store: attached.store,
            backend: attached.backend,
            profile: attached.profile,
        }
    }

    fn classify(&mut self) -> Result<(StoredFloorV1, FloorRecoveryV1), FloorErrorV1> {
        let stored = self.store.read(self.profile)?;
        let (cut, _) = self.traffic.cuts(self.profile, None)?;
        let nv = self.backend.read()?;
        self.store.require_same(&stored, self.profile)?;
        let (after, _) = self.traffic.cuts(self.profile, None)?;
        if after != cut {
            return Err(FloorErrorV1::Diverged);
        }
        let phase = reconcile_floor_v1(
            self.profile,
            stored.checkpoint,
            stored.prepared.as_ref().map(|(intent, _)| *intent),
            cut,
            nv,
        )?;
        Ok((stored, phase))
    }

    fn require_prospective(
        &mut self,
        stored: &StoredFloorV1,
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
    ) -> Result<FinalSuffixPreflightV1, FloorErrorV1> {
        require_prospective_cut(&mut self.traffic, self.profile, intent, transaction)?;
        let suffix = self.store.preflight_final(stored, self.profile)?;
        self.store.require_same(stored, self.profile)?;
        Ok(suffix)
    }
}

fn require_prospective_cut(
    traffic: &mut impl HeldTrafficWriterV1,
    profile: FloorProfileV1,
    intent: FloorIntentV1,
    transaction: &JournalTransaction,
) -> Result<(), FloorErrorV1> {
    intent.require_transaction(transaction)?;
    let (current, target) = traffic.cuts(profile, Some(transaction))?;
    if current != intent.predecessor().cut() || target != Some(intent.target().cut()) {
        return Err(FloorErrorV1::Diverged);
    }
    Ok(())
}

/// Retains the two non-traffic owners between opaque reconciliation borrows.
pub(super) struct AttachedFloorV1<Io> {
    backend: TpmNvExtendFloorBackendV1<Io>,
    store: FloorStoreV1,
    profile: FloorProfileV1,
}

#[cfg(test)]
mod tests;
