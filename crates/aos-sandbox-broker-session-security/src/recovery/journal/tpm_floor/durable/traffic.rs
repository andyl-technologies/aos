//! Fixed endpoint writer adapter and shared exact traffic commit ordering.
//!
//! Only the actual protected broker-session owner implements this boundary in
//! production. A test-only adapter uses the real protected Journal but does
//! not manufacture endpoint manifests, signatures, process custody, or readiness.

use aos_sandbox::{Journal, JournalTransaction, ProtectedJournalLockCustodyV1, RecordNamespace};

#[cfg(test)]
use aos_sandbox::JournalLimits;

use super::super::{FloorCutV1, FloorErrorV1, FloorIntentV1, FloorProfileV1};
use super::store::FloorStoreV1;
use crate::recovery::journal::ProtectedBrokerSessionJournalV1;
use crate::tpm_nv_custody::{FloorIntentDataV1, FloorProfileDataV1};

mod sealed {
    pub(super) trait Sealed {}
}

pub(super) trait HeldTrafficWriterV1: sealed::Sealed {
    fn purpose_cuts(
        &mut self,
        profile: FloorProfileDataV1,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1> {
        match profile {
            FloorProfileDataV1::Broker(profile) => self.cuts(profile, transaction),
            FloorProfileDataV1::Online(_) => Err(FloorErrorV1::Provisioning),
        }
    }

    fn commit_purpose_exact(
        &mut self,
        profile: FloorProfileDataV1,
        intent: FloorIntentDataV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        match (profile, intent) {
            (FloorProfileDataV1::Broker(profile), FloorIntentDataV1::Broker(intent)) => {
                self.commit_exact(profile, intent, transaction)
            }
            _ => Err(FloorErrorV1::Provisioning),
        }
    }

    fn cuts(
        &mut self,
        profile: FloorProfileV1,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1>;

    fn open_floor_store(&mut self) -> Result<FloorStoreV1, FloorErrorV1>;

    fn loan_lock_custody(&mut self) -> Result<ProtectedJournalLockCustodyV1, FloorErrorV1>;

    fn commit_exact(
        &mut self,
        profile: FloorProfileV1,
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1>;
}

pub(super) struct BrokerTrafficWriterV1<'owner> {
    owner: &'owner mut ProtectedBrokerSessionJournalV1,
}

impl<'owner> BrokerTrafficWriterV1<'owner> {
    pub(super) fn borrow(owner: &'owner mut ProtectedBrokerSessionJournalV1) -> Self {
        Self { owner }
    }
}

impl sealed::Sealed for BrokerTrafficWriterV1<'_> {}

impl HeldTrafficWriterV1 for BrokerTrafficWriterV1<'_> {
    fn cuts(
        &mut self,
        profile: FloorProfileV1,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1> {
        self.owner
            .tpm_floor_cuts(profile, transaction)
            .map_err(|_| FloorErrorV1::Unavailable)
    }

    fn open_floor_store(&mut self) -> Result<FloorStoreV1, FloorErrorV1> {
        self.owner
            .endpoint
            .revalidate()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let store = FloorStoreV1::open(self.owner.owner, &self.owner.directory, self.owner.limits)?;
        self.owner
            .endpoint
            .revalidate()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        Ok(store)
    }

    fn loan_lock_custody(&mut self) -> Result<ProtectedJournalLockCustodyV1, FloorErrorV1> {
        self.owner
            .endpoint
            .revalidate()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        self.owner
            .journal_mut()
            .map_err(|_| FloorErrorV1::Unavailable)?
            .loan_protected_lock_custody()
            .map_err(|_| FloorErrorV1::Unavailable)
    }

    fn commit_exact(
        &mut self,
        profile: FloorProfileV1,
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        require_exact_cuts(self.cuts(profile, Some(transaction))?, intent, transaction)?;
        commit_traffic_transaction(
            self.owner
                .journal_mut()
                .map_err(|_| FloorErrorV1::Unavailable)?,
            transaction,
        )?;
        self.owner
            .validate_schema_only()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        require_target(self.cuts(profile, None)?.0, intent)
    }
}

/// Borrows the exact selected owner; it cannot open a replacement main writer.
#[cfg(feature = "online-nix")]
pub(super) struct OnlineTrafficWriterV1<'owner> {
    owner: &'owner mut ProtectedBrokerSessionJournalV1,
    native_failure: &'owner mut Option<aos_sandbox::JournalError>,
}

#[cfg(feature = "online-nix")]
impl<'owner> OnlineTrafficWriterV1<'owner> {
    pub(super) fn borrow(
        owner: &'owner mut ProtectedBrokerSessionJournalV1,
        native_failure: &'owner mut Option<aos_sandbox::JournalError>,
    ) -> Self {
        Self { owner, native_failure }
    }
}

#[cfg(feature = "online-nix")]
impl sealed::Sealed for OnlineTrafficWriterV1<'_> {}

#[cfg(feature = "online-nix")]
impl HeldTrafficWriterV1 for OnlineTrafficWriterV1<'_> {
    fn purpose_cuts(&mut self, profile: FloorProfileDataV1, transaction: Option<&JournalTransaction>)
        -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1>
    {
        let FloorProfileDataV1::Online(profile) = profile else {
            return Err(FloorErrorV1::Provisioning);
        };
        self.owner.online_floor_cuts(profile, transaction).map_err(|_| FloorErrorV1::Unavailable)
    }

    fn commit_purpose_exact(
        &mut self, profile: FloorProfileDataV1, intent: FloorIntentDataV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        let (FloorProfileDataV1::Online(profile), FloorIntentDataV1::Online(intent)) = (profile, intent) else {
            return Err(FloorErrorV1::Provisioning);
        };
        intent.require_transaction(transaction)?;
        let cuts = self.purpose_cuts(FloorProfileDataV1::Online(profile), Some(transaction))?;
        if cuts.0 != intent.predecessor().cut() || cuts.1 != Some(intent.target().cut()) {
            return Err(FloorErrorV1::Diverged);
        }
        commit_traffic_transaction_with_disposition(
            self.owner.journal_mut().map_err(|_| FloorErrorV1::Unavailable)?,
            transaction, NativeCauseDispositionV1::Retained(self.native_failure),
        )?;
        self.owner.validate_schema_only().map_err(|_| FloorErrorV1::Unavailable)?;
        let after = self.purpose_cuts(FloorProfileDataV1::Online(profile), None)?.0;
        if after != intent.target().cut() {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(())
    }

    fn cuts(&mut self, _: FloorProfileV1, _: Option<&JournalTransaction>)
        -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1>
    {
        Err(FloorErrorV1::Provisioning)
    }

    fn open_floor_store(&mut self) -> Result<FloorStoreV1, FloorErrorV1> {
        // Production stages the actual retained sidecar opener before calling
        // any postcheck; this trait entry cannot invent consuming custody.
        Err(FloorErrorV1::Provisioning)
    }

    fn loan_lock_custody(&mut self) -> Result<ProtectedJournalLockCustodyV1, FloorErrorV1> {
        self.owner.endpoint.revalidate().map_err(|_| FloorErrorV1::Unavailable)?;
        let result = self.owner.journal_mut().map_err(|_| FloorErrorV1::Unavailable)?
            .loan_protected_lock_custody();
        NativeCauseDispositionV1::Retained(self.native_failure).project(result)
    }

    fn commit_exact(&mut self, _: FloorProfileV1, _: FloorIntentV1, _: &JournalTransaction)
        -> Result<(), FloorErrorV1>
    {
        Err(FloorErrorV1::Provisioning)
    }
}

fn require_exact_cuts(
    cuts: (FloorCutV1, Option<FloorCutV1>),
    intent: FloorIntentV1,
    transaction: &JournalTransaction,
) -> Result<(), FloorErrorV1> {
    intent.require_transaction(transaction)?;
    if cuts.0 != intent.predecessor().cut() || cuts.1 != Some(intent.target().cut()) {
        return Err(FloorErrorV1::Diverged);
    }
    Ok(())
}

fn require_target(cut: FloorCutV1, intent: FloorIntentV1) -> Result<(), FloorErrorV1> {
    if cut == intent.target().cut() {
        Ok(())
    } else {
        Err(FloorErrorV1::Diverged)
    }
}

pub(super) fn commit_traffic_transaction(
    journal: &mut Journal,
    transaction: &JournalTransaction,
) -> Result<(), FloorErrorV1> {
    commit_traffic_transaction_with_disposition(journal, transaction, NativeCauseDispositionV1::Legacy)
}

enum NativeCauseDispositionV1<'cause> {
    Legacy,
    Retained(&'cause mut Option<aos_sandbox::JournalError>),
}

impl NativeCauseDispositionV1<'_> {
    fn project<T>(&mut self, result: Result<T, aos_sandbox::JournalError>) -> Result<T, FloorErrorV1> {
        match result {
            Ok(value) => Ok(value),
            Err(cause) => {
                if let Self::Retained(first) = self {
                    first.get_or_insert(cause);
                    return Err(FloorErrorV1::Unavailable);
                }
                // Legacy disposes the same redacted provider error before the
                // authority local unwinds, rather than keeping a new owner.
                drop(cause);
                Err(FloorErrorV1::Unavailable)
            }
        }
    }
}

fn commit_traffic_transaction_with_disposition(
    journal: &mut Journal, transaction: &JournalTransaction,
    mut disposition: NativeCauseDispositionV1<'_>,
) -> Result<(), FloorErrorV1> {
    disposition.project(journal.validate_held_protected_names())?;
    let mut authority = disposition.project(journal.claim_protected_authority(RecordNamespace::BrokerSessionTraffic))?;
    let preflight = disposition.project(authority.preflight_transactions(core::slice::from_ref(transaction)))?;
    disposition.project(authority.validate_preflight_for_effect(&preflight, core::slice::from_ref(transaction)))?;
    disposition.project(authority.commit(transaction))?;
    drop(authority);
    disposition.project(journal.validate_held_protected_names())
}

#[cfg(test)]
pub(super) struct FixtureTrafficWriterV1 {
    pub(super) journal: Journal,
    pub(super) directory: std::path::PathBuf,
    pub(super) limits: JournalLimits,
    pub(super) uid: u32,
}

#[cfg(test)]
impl sealed::Sealed for FixtureTrafficWriterV1 {}

#[cfg(test)]
impl HeldTrafficWriterV1 for FixtureTrafficWriterV1 {
    fn cuts(
        &mut self,
        _: FloorProfileV1,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1> {
        self.journal
            .validate_held_protected_at_uid_for_test(&self.directory, "session.journal", self.uid)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        super::super::head::journal_floor_cuts_v1(&mut self.journal, transaction)
    }

    fn open_floor_store(&mut self) -> Result<FloorStoreV1, FloorErrorV1> {
        FloorStoreV1::open_fixture(&self.directory, self.limits, self.uid)
    }

    fn loan_lock_custody(&mut self) -> Result<ProtectedJournalLockCustodyV1, FloorErrorV1> {
        self.journal
            .loan_protected_lock_custody()
            .map_err(|_| FloorErrorV1::Unavailable)
    }

    fn commit_exact(
        &mut self,
        profile: FloorProfileV1,
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        require_exact_cuts(self.cuts(profile, Some(transaction))?, intent, transaction)?;
        commit_traffic_transaction(&mut self.journal, transaction)?;
        require_target(self.cuts(profile, None)?.0, intent)
    }
}
