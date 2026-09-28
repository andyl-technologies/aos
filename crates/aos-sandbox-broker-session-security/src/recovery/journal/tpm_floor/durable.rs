//! Protected preparation and reconciliation under two retained journal writers.
//!
//! The existing traffic writer is acquired first, this same-owner sidecar
//! second, and the sealed TPM transport last. No source implements the live
//! authenticated TPM producer yet, so this composition does not activate any
//! endpoint, method, readiness, or effect authority.
//!
//! The separate sidecar owns namespace 47 and exactly these canonical keys:
//!
//! ```text
//! checkpoint = AOSBTF01 (156 bytes)
//! intent     = AOSBTI01 (324 bytes), present only with transaction
//! transaction = AOSJPT01, exact existing ordered JournalTransaction
//! ```

mod store;
mod traffic;

use aos_sandbox::JournalTransaction;

use super::backend::{AuthenticatedTpmNvIoV1, FloorAdvanceV1, TpmNvExtendFloorBackendV1};
use super::{FloorErrorV1, FloorIntentV1, FloorProfileV1, FloorRecoveryV1, reconcile_floor_v1};
use store::{FloorStoreV1, StoredFloorV1};
use traffic::HeldTrafficWriterV1;

/// Composes the existing endpoint owner without creating a transport or provisioning state.
fn borrow_broker_floor_v1<Io: AuthenticatedTpmNvIoV1>(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    profile: FloorProfileV1,
    io: Io,
) -> Result<DurableTpmFloorV1<traffic::BrokerTrafficWriterV1<'_>, Io>, FloorErrorV1> {
    DurableTpmFloorV1::open(traffic::BrokerTrafficWriterV1::borrow(owner), profile, io)
}

/// Retains the actual traffic writer, sidecar flock, and authenticated NV backend.
struct DurableTpmFloorV1<Traffic, Io> {
    traffic: Traffic,
    store: FloorStoreV1,
    backend: TpmNvExtendFloorBackendV1<Io>,
    profile: FloorProfileV1,
}

/// Describes a completed local check, never a public readiness/effect capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FloorProgressV1 {
    Current,
    NvNotAdvanced,
}

impl<Traffic: HeldTrafficWriterV1, Io: AuthenticatedTpmNvIoV1> DurableTpmFloorV1<Traffic, Io> {
    /// Opens existing names only after the real fixed endpoint writer has revalidated.
    fn open(mut traffic: Traffic, profile: FloorProfileV1, io: Io) -> Result<Self, FloorErrorV1> {
        traffic.cuts(profile, None)?;
        let store = traffic.open_floor_store()?;
        let backend = TpmNvExtendFloorBackendV1::open(profile, io)?;
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
    fn prepare(&mut self, transaction: &JournalTransaction) -> Result<(), FloorErrorV1> {
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
    fn recover(&mut self) -> Result<FloorProgressV1, FloorErrorV1> {
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
            self.require_prospective(&stored, *intent, transaction)?;
            if self.backend.advance(*intent)? == FloorAdvanceV1::NotAdvanced {
                self.classify()?;
                return Ok(FloorProgressV1::NvNotAdvanced);
            }
        }
        let (stored, phase) = self.classify()?;
        let (intent, transaction) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        if phase == FloorRecoveryV1::CommitPrepared {
            self.require_prospective(&stored, *intent, transaction)?;
            if self.backend.read()? != intent.target().nv_value() {
                return Err(FloorErrorV1::Diverged);
            }
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
    ) -> Result<(), FloorErrorV1> {
        intent.require_transaction(transaction)?;
        let (current, target) = self.traffic.cuts(self.profile, Some(transaction))?;
        if current != intent.predecessor().cut() || target != Some(intent.target().cut()) {
            return Err(FloorErrorV1::Diverged);
        }
        self.store.preflight_final(stored, self.profile)?;
        self.store.require_same(stored, self.profile)
    }
}

#[cfg(test)]
mod tests;
