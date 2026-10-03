//! Original Broker sidecar facade and its closed captured-custody capsule.
//!
//! Only this existing Broker open path constructs the opaque capsule consumed
//! by the one shared sidecar engine. Original owner/directory policy stays here;
//! no generic Journal factory, Host variant or widened JournalOwner is exposed.
//! The compatibility facade retains its checks and consuming error contract.
//! Required opening parks each returned Journal before further validation;
//! its shared-store field/drop order and test custody remain unchanged.

use std::path::{Path, PathBuf};

use aos_sandbox::{
    Journal, JournalError, JournalLimits, JournalTransaction, ProtectedJournalLockCustodyV1,
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

/// Keeps only an actual closed-owner opening attempt, not a Journal factory.
pub(super) struct BrokerSidecarOpenV1 {
    journal: Option<Journal>,
    owner: JournalOwnerV1,
    directory: PathBuf,
    main_limits: JournalLimits,
    limits: JournalLimits,
    started: bool,
    complete: bool,
}

#[derive(Debug)]
pub(super) enum BrokerSidecarOpenErrorV1 {
    Floor(FloorErrorV1),
    Journal(JournalError),
}

impl BrokerSidecarOpenErrorV1 {
    pub(super) fn projection(&self) -> FloorErrorV1 {
        match self {
            Self::Floor(error) => *error,
            Self::Journal(_) => FloorErrorV1::Unavailable,
        }
    }
}

// The consuming arm keeps the returned Journal local through validation;
// Required parks that same return before validation. Only storage differs.
macro_rules! sidecar_open_step {
    (Legacy, error $result:expr) => {
        $result.map_err(|_| FloorErrorV1::Unavailable)?
    };
    (Retained, error $result:expr) => {
        $result.map_err(BrokerSidecarOpenErrorV1::Journal)?
    };
    (Legacy, stage $original:ident, $journal:ident) => {};
    (Retained, stage $original:ident, $journal:ident) => {
        $original.journal = Some($journal);
    };
    (Legacy, journal $original:ident, $journal:ident) => { &$journal };
    (Retained, journal $original:ident, $journal:ident) => {
        $original.journal.as_ref().ok_or(
            BrokerSidecarOpenErrorV1::Floor(FloorErrorV1::Unavailable),
        )?
    };
}

macro_rules! sidecar_open_recipe {
    ($mode:ident, $original:ident, $owner:expr, $directory:expr, $limits:expr,
        $journal:ident) => {
        let ($journal, _) = sidecar_open_step!($mode, error
            $owner.open_existing($directory, NAME, $limits));
        sidecar_open_step!($mode, stage $original, $journal);
        sidecar_open_step!($mode, error $owner.validate_held(
            sidecar_open_step!($mode, journal $original, $journal),
            $directory,
            NAME,
        ));
    };
}

impl BrokerSidecarOpenV1 {
    pub(super) fn prepare(
        owner: JournalOwnerV1,
        directory: &Path,
        main_limits: JournalLimits,
    ) -> Result<Self, FloorErrorV1> {
        let limits = sidecar_limits(main_limits)?;
        Ok(Self {
            journal: None,
            owner,
            directory: directory.to_path_buf(),
            main_limits,
            limits,
            started: false,
            complete: false,
        })
    }

    pub(super) fn open(&mut self) -> Result<(), BrokerSidecarOpenErrorV1> {
        if self.started {
            return Err(BrokerSidecarOpenErrorV1::Floor(FloorErrorV1::Unavailable));
        }
        // First arm before Core effects. Its raw pre-return acquisition prefix
        // is not exposed by the unchanged Core API and remains a separate gap.
        self.started = true;
        sidecar_open_recipe!(Retained, self, self.owner, &self.directory, self.limits, journal);
        self.complete = true;
        Ok(())
    }

    pub(super) fn finish_into(
        &mut self,
        target: &mut Option<FloorStoreV1>,
    ) -> Result<(), FloorErrorV1> {
        if !self.complete || target.is_some() || self.journal.is_none() {
            return Err(FloorErrorV1::Unavailable);
        }
        // All guards precede these infallible moves into the same shared store.
        let directory = std::mem::take(&mut self.directory);
        if let Some(journal) = self.journal.take() {
            let custody = BrokerSidecarCustodyV1 {
                journal,
                main_limits: self.main_limits,
                custody: StoreCustodyV1::Production {
                    owner: self.owner,
                    directory,
                },
            };
            *target = Some(FloorStoreV1 {
                inner: BrokerSidecarStoreV1::from_broker(custody),
            });
        }
        Ok(())
    }

}

impl BrokerSidecarCustodyV1 {
    fn open(
        owner: JournalOwnerV1,
        directory: &Path,
        main_limits: JournalLimits,
    ) -> Result<Self, FloorErrorV1> {
        let limits = sidecar_limits(main_limits)?;
        sidecar_open_recipe!(Legacy, original, owner, directory, limits, journal);
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
