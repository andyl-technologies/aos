//! Original Broker sidecar facade and its closed captured-custody capsule.
//!
//! Only this existing Broker open path constructs the opaque capsule consumed
//! by the one shared sidecar engine. Original owner/directory policy stays here;
//! no generic Journal factory, Host variant or widened JournalOwner is exposed.
//! Field/drop order and production/test construction checks stay unchanged.

use std::path::{Path, PathBuf};

use aos_sandbox::{
    Journal, JournalLimits, JournalTransaction, ProtectedJournalLockCustodyV1,
};

use super::super::{FloorErrorV1, FloorIntentV1, FloorProfileV1};
use crate::recovery::journal::owner::JournalOwnerV1;
use crate::tpm_nv_custody::{
    BrokerSidecarStoreV1, CHECKPOINT_KEY as SHARED_CHECKPOINT_KEY, sidecar_limits,
};
pub(super) use crate::tpm_nv_custody::{
    FinalSuffixPreflightV1, StoredBrokerFloorV1 as StoredFloorV1,
};

pub(super) const NAME: &str = "session-floor.journal";
pub(super) const CHECKPOINT_KEY: &[u8] = SHARED_CHECKPOINT_KEY;

/// Preserves the original private Broker store API and actual Storage callers.
pub(super) struct FloorStoreV1 {
    inner: BrokerSidecarStoreV1,
}

/// Carries only the original Broker constructor's actual journal and custody.
///
/// Private fields and constructors prevent DATA/default/injected ownership.
/// The shared engine can borrow only this same actual protected Journal. Its
/// three original fields retain their original order, including partial drops.
pub(crate) struct BrokerSidecarCustodyV1 {
    journal: Journal,
    main_limits: JournalLimits,
    custody: StoreCustodyV1,
}

enum StoreCustodyV1 {
    Production {
        owner: JournalOwnerV1,
        directory: PathBuf,
    },
    #[cfg(test)]
    Fixture { uid: u32, directory: PathBuf },
}

impl BrokerSidecarCustodyV1 {
    fn open(
        owner: JournalOwnerV1,
        directory: &Path,
        main_limits: JournalLimits,
    ) -> Result<Self, FloorErrorV1> {
        let limits = sidecar_limits(main_limits)?;
        let (journal, _) = owner
            .open_existing(directory, NAME, limits)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        owner
            .validate_held(&journal, directory, NAME)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        Ok(Self {
            journal,
            main_limits,
            custody: StoreCustodyV1::Production {
                owner,
                directory: directory.to_path_buf(),
            },
        })
    }

    #[cfg(test)]
    fn open_fixture(
        directory: &Path,
        main_limits: JournalLimits,
        uid: u32,
    ) -> Result<Self, FloorErrorV1> {
        let (journal, _) = Journal::open_existing_protected_at_uid(
            directory,
            NAME,
            sidecar_limits(main_limits)?,
            uid,
        )
        .map_err(|_| FloorErrorV1::Unavailable)?;
        Ok(Self {
            journal,
            main_limits,
            custody: StoreCustodyV1::Fixture {
                uid,
                directory: directory.to_path_buf(),
            },
        })
    }

    pub(crate) fn validate_held(&self) -> Result<(), FloorErrorV1> {
        let result = match &self.custody {
            StoreCustodyV1::Production { owner, directory } => {
                owner.validate_held(&self.journal, directory, NAME)
            }
            #[cfg(test)]
            StoreCustodyV1::Fixture { uid, directory } => self
                .journal
                .validate_held_protected_at_uid_for_test(directory, NAME, *uid),
        };
        result.map_err(|_| FloorErrorV1::Unavailable)
    }

    pub(crate) fn journal(&self) -> &Journal {
        &self.journal
    }

    pub(crate) fn journal_mut(&mut self) -> &mut Journal {
        &mut self.journal
    }

    pub(crate) const fn main_limits(&self) -> JournalLimits {
        self.main_limits
    }
}

impl FloorStoreV1 {
    pub(super) fn loan_lock_custody(&self) -> Result<ProtectedJournalLockCustodyV1, FloorErrorV1> {
        self.inner.loan_lock_custody()
    }

    pub(super) fn open(
        owner: JournalOwnerV1,
        directory: &Path,
        main_limits: JournalLimits,
    ) -> Result<Self, FloorErrorV1> {
        let custody = BrokerSidecarCustodyV1::open(owner, directory, main_limits)?;
        Ok(Self { inner: BrokerSidecarStoreV1::from_broker(custody) })
    }

    #[cfg(test)]
    pub(super) fn open_fixture(
        directory: &Path,
        main_limits: JournalLimits,
        uid: u32,
    ) -> Result<Self, FloorErrorV1> {
        let custody = BrokerSidecarCustodyV1::open_fixture(directory, main_limits, uid)?;
        Ok(Self { inner: BrokerSidecarStoreV1::from_broker(custody) })
    }

    #[cfg(test)]
    pub(super) fn fixture_limits(main_limits: JournalLimits) -> Result<JournalLimits, FloorErrorV1> {
        BrokerSidecarStoreV1::fixture_limits(main_limits)
    }

    #[cfg(test)]
    pub(super) fn fixture_preparation(
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> JournalTransaction {
        BrokerSidecarStoreV1::fixture_preparation(intent, transaction, limits)
    }

    #[cfg(test)]
    pub(super) fn fixture_finalization(intent: FloorIntentV1) -> JournalTransaction {
        BrokerSidecarStoreV1::fixture_finalization(intent)
    }

    #[cfg(test)]
    pub(super) fn fixture_preflight(
        &mut self,
        transactions: &[JournalTransaction],
    ) -> Result<(), FloorErrorV1> {
        self.inner.fixture_preflight(transactions)
    }

    pub(super) fn validate_held(&self) -> Result<(), FloorErrorV1> {
        self.inner.validate_held()
    }

    pub(super) fn read(&mut self, profile: FloorProfileV1) -> Result<StoredFloorV1, FloorErrorV1> {
        self.inner.read(profile)
    }

    pub(super) fn require_same(
        &mut self,
        stored: &StoredFloorV1,
        profile: FloorProfileV1,
    ) -> Result<(), FloorErrorV1> {
        self.inner.require_same(stored, profile)
    }

    pub(super) fn prepare(
        &mut self,
        profile: FloorProfileV1,
        old: &StoredFloorV1,
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        self.inner.prepare(profile, old, intent, transaction)
    }

    pub(super) fn preflight_final(
        &mut self,
        stored: &StoredFloorV1,
        profile: FloorProfileV1,
    ) -> Result<FinalSuffixPreflightV1, FloorErrorV1> {
        self.inner.preflight_final(stored, profile)
    }

    pub(super) fn validate_final_preflight(
        &mut self,
        suffix: &FinalSuffixPreflightV1,
        stored: &StoredFloorV1,
        profile: FloorProfileV1,
    ) -> Result<(), FloorErrorV1> {
        self.inner.validate_final_preflight(suffix, stored, profile)
    }

    pub(super) fn finalize(
        &mut self,
        profile: FloorProfileV1,
        stored: &StoredFloorV1,
    ) -> Result<(), FloorErrorV1> {
        self.inner.finalize(profile, stored)
    }
}
