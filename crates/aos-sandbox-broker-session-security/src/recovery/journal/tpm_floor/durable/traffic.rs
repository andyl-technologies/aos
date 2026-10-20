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
use super::super::storage_receiving::StorageFloorFinancialSourceV2;
use super::super::head::StorageFloorMainOriginalV3;

mod sealed {
    pub(super) trait Sealed {}
}

pub(super) trait HeldTrafficWriterV1: sealed::Sealed {
    fn require_storage_main_programme_v3(&self) -> Result<(), FloorErrorV1> {
        Err(FloorErrorV1::Unavailable)
    }

    fn cuts_storage_receiving_v3(&mut self, _profile: FloorProfileV1,
        _transaction: Option<&JournalTransaction>, _receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1> {
        Err(FloorErrorV1::Unavailable)
    }

    fn commit_storage_receiving_v3(&mut self, _profile: FloorProfileV1,
        _intent: FloorIntentV1, _transaction: &JournalTransaction,
        _receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(), FloorErrorV1> {
        Err(FloorErrorV1::Unavailable)
    }

    fn original_controller_pair_journal_v1(&self) -> Option<&Journal> {
        None
    }

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
    fn require_storage_main_programme_v3(&self) -> Result<(), FloorErrorV1> {
        self.owner.require_storage_floor_main_programme_v3()
    }

    fn cuts_storage_receiving_v3(&mut self, profile: FloorProfileV1,
        transaction: Option<&JournalTransaction>, receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1> {
        self.owner.tpm_floor_cuts_storage_receiving_v3(profile, transaction, receiving)
    }

    fn commit_storage_receiving_v3(&mut self, profile: FloorProfileV1,
        intent: FloorIntentV1, transaction: &JournalTransaction,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(), FloorErrorV1> {
        // The coordinator performs the intent/transaction binding through its
        // paid sidecar original before this private effect adapter is called.
        let cuts = self.cuts_storage_receiving_v3(profile, Some(transaction), receiving)?;
        require_exact_cut_values_v3(cuts, intent)?;
        self.owner.commit_storage_floor_main_receiving_v3(transaction, receiving)?;
        // This same post-append HEAD enters the canonical schema validation
        // first, retaining any changed schema/read prefix in its actual owner.
        require_target(self.cuts_storage_receiving_v3(profile, None, receiving)?.0, intent)
    }

    fn original_controller_pair_journal_v1(&self) -> Option<&Journal> {
        self.owner.journal.as_ref()
    }

    fn cuts(
        &mut self,
        profile: FloorProfileV1,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1> {
        self.owner
            .tpm_floor_cuts(profile, transaction)
            .map_err(crate::recovery::journal::floor_revalidation::floor_error)
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
        let currentness = self.owner.floor_currentness.clone();
        commit_owned_traffic_transaction_v1(self.owner, transaction, currentness)?;
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
            transaction, NativeCauseDispositionV1::Retained(self.native_failure), None,
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
    require_exact_cut_values_v3(cuts, intent)
}

fn require_exact_cut_values_v3(cuts: (FloorCutV1, Option<FloorCutV1>), intent: FloorIntentV1)
    -> Result<(), FloorErrorV1>
{
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
    commit_traffic_transaction_with_disposition(journal, transaction, NativeCauseDispositionV1::Legacy, None)
}

pub(super) enum NativeCauseDispositionV1<'cause> {
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

// Only this same actual owner's installed captured DATA mode selects retention.
// The ordinary disposition and sole commit algorithm below remain unchanged.
pub(super) fn commit_owned_traffic_transaction_v1(
    owner: &mut ProtectedBrokerSessionJournalV1, transaction: &JournalTransaction,
    currentness: Option<crate::recovery::journal::floor_revalidation::FloorCurrentnessSharedV1>,
) -> Result<(), FloorErrorV1> {
    if owner.journal.as_ref().is_some_and(Journal::has_captured_append_custody_v1) {
        let mut cause = None;
        let committed = commit_traffic_transaction_with_disposition(
            owner.journal.as_mut().ok_or(FloorErrorV1::Unavailable)?, transaction,
            NativeCauseDispositionV1::Retained(&mut cause), currentness.as_ref());
        if let Some(cause) = cause {
            owner.captured_native_failure.get_or_insert((*transaction.id(), cause));
        }
        committed
    } else {
        commit_traffic_transaction_with_disposition(
            owner.journal_mut().map_err(|_| FloorErrorV1::Unavailable)?, transaction,
            NativeCauseDispositionV1::Legacy, currentness.as_ref())
    }
}

macro_rules! commit_step_v3 {
    (Ordinary, names $original:ident, $journal:ident, $disposition:ident, $currentness:ident, $index:expr) => {
        validate_commit_names($journal, &mut $disposition, $currentness)?
    };
    (Retained, names $original:ident, $journal:ident, $disposition:ident, $currentness:ident, $index:expr) => {
        $original.validate_commit_names_v3($journal, $index)?
    };
    (Ordinary, claim $original:ident, $journal:ident, $disposition:ident) => {
        $disposition.project($journal.claim_protected_authority(RecordNamespace::BrokerSessionTraffic))?
    };
    (Retained, claim $original:ident, $journal:ident, $disposition:ident) => {{
        match $journal.claim_protected_authority_retaining_v1(
            RecordNamespace::BrokerSessionTraffic, &mut $original.capacity) {
            Ok(authority) => { $original.claim = Some(Ok(())); authority }
            Err(cause) => {
                $original.claim = Some(Err(cause));
                return Err(FloorErrorV1::Unavailable);
            }
        }
    }};
    (Ordinary, preflight $original:ident, $authority:ident, $transaction:ident, $disposition:ident, $token:ident) => {
        let $token = $disposition.project($authority.preflight_transactions(core::slice::from_ref($transaction)))?;
    };
    (Retained, preflight $original:ident, $authority:ident, $transaction:ident, $disposition:ident, $token:ident) => {
        $original.token = Some($authority.preflight_transactions_retaining_v2(
            core::slice::from_ref($transaction), &mut $original.preflight));
        let $token = $original.token.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(FloorErrorV1::Unavailable)?;
    };
    (Ordinary, effect $original:ident, $authority:ident, $transaction:ident, $disposition:ident, $token:ident) => {
        $disposition.project($authority.validate_preflight_for_effect(&$token, core::slice::from_ref($transaction)))?;
    };
    (Retained, effect $original:ident, $authority:ident, $transaction:ident, $disposition:ident, $token:ident) => {
        $original.effect = Some($authority.validate_preflight_for_effect($token, core::slice::from_ref($transaction)));
        if !matches!($original.effect, Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
    };
    (Ordinary, commit $original:ident, $authority:ident, $transaction:ident, $disposition:ident) => {
        $disposition.project($authority.commit($transaction))?;
    };
    (Retained, commit $original:ident, $authority:ident, $transaction:ident, $disposition:ident) => {
        $original.commit = Some($authority.commit($transaction).map(|_| ()));
        if !matches!($original.commit, Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
    };
}

macro_rules! commit_recipe_v3 {
    ($mode:ident, $original:ident, $journal:ident, $transaction:ident, $disposition:ident, $currentness:ident) => {{
        commit_step_v3!($mode, names $original, $journal, $disposition, $currentness, 0);
        let mut authority = commit_step_v3!($mode, claim $original, $journal, $disposition);
        commit_step_v3!($mode, preflight $original, authority, $transaction, $disposition, token);
        commit_step_v3!($mode, effect $original, authority, $transaction, $disposition, token);
        commit_step_v3!($mode, commit $original, authority, $transaction, $disposition);
        drop(authority);
        commit_step_v3!($mode, names $original, $journal, $disposition, $currentness, 1);
        Ok(())
    }};
}

pub(in crate::recovery::journal::tpm_floor) fn commit_traffic_transaction_retaining_v3(
    journal: &mut Journal, transaction: &JournalTransaction, original: &mut StorageFloorMainOriginalV3,
) -> Result<(), FloorErrorV1> {
    commit_recipe_v3!(Retained, original, journal, transaction, disposition, currentness)
}

pub(super) fn commit_traffic_transaction_with_disposition(
    journal: &mut Journal, transaction: &JournalTransaction,
    mut disposition: NativeCauseDispositionV1<'_>,
    currentness: Option<&crate::recovery::journal::floor_revalidation::FloorCurrentnessSharedV1>,
) -> Result<(), FloorErrorV1> {
    commit_recipe_v3!(Ordinary, unused, journal, transaction, disposition, currentness)
}

fn validate_commit_names(
    journal: &Journal,
    disposition: &mut NativeCauseDispositionV1<'_>,
    currentness: Option<&crate::recovery::journal::floor_revalidation::FloorCurrentnessSharedV1>,
) -> Result<(), FloorErrorV1> {
    if currentness.is_some() {
        return crate::recovery::journal::floor_revalidation::validate_names(currentness, journal);
    }
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
