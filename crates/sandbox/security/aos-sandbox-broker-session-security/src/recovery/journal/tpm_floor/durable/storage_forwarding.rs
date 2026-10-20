//! Forwards actual borrowed floor steps to their original F and sidecar owner.
//!
//! The ordinary branches retain their established implementations. Selected
//! branches use the actual main/taken sidecar pair and retained native helpers;
//! no journal, financial source, decoder or completion receipt is reconstructed.
//! Outer prepare/recover validate the actual same-main/taken-sidecar originals.
//! The installed method46 qualification gate remains closed.

use super::*;
use crate::tpm_nv_custody::{FloorCheckpointDataV1, FloorCutV1, StorageFinalSuffixPreflightV2};

pub(super) enum BorrowedFinalSuffixV2 {
    Ordinary(FinalSuffixPreflightV1),
    Storage(StorageFinalSuffixPreflightV2),
}

impl<Traffic: HeldTrafficWriterV1, Io: AuthenticatedTpmNvIoV1>
    BorrowedDurableFloorV1<'_, '_, Traffic, Io>
{
    pub(super) fn main_cuts_v3(&mut self, transaction: Option<&JournalTransaction>)
        -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1>
    {
        match self.storage_receiving.as_mut() {
            Some(receiving) => {
                let FloorProfileDataV1::Broker(profile) = self.profile else {
                    return Err(FloorErrorV1::Provisioning);
                };
                self.traffic.cuts_storage_receiving_v3(profile, transaction, &mut **receiving)
            }
            None => self.traffic.purpose_cuts(self.profile, transaction),
        }
    }

    pub(super) fn commit_main_v3(&mut self, intent: FloorIntentDataV1,
        transaction: &JournalTransaction) -> Result<(), FloorErrorV1>
    {
        if self.storage_receiving.is_none() {
            return self.traffic.commit_purpose_exact(self.profile, intent, transaction);
        }
        self.require_sidecar_transaction_v2(intent, transaction)?;
        let (FloorProfileDataV1::Broker(profile), FloorIntentDataV1::Broker(intent)) = (self.profile, intent) else {
            return Err(FloorErrorV1::Provisioning);
        };
        self.traffic.commit_storage_receiving_v3(profile, intent, transaction,
            &mut **self.storage_receiving.as_mut().ok_or(FloorErrorV1::Unavailable)?)
    }

    pub(super) fn new_sidecar_intent_v2(&mut self, checkpoint: FloorCheckpointDataV1,
        target: FloorCutV1, transaction: &JournalTransaction) -> Result<FloorIntentDataV1, FloorErrorV1>
    {
        match self.storage_receiving.as_mut() {
            Some(receiving) => {
                let FloorProfileDataV1::Broker(profile) = self.profile else {
                    return Err(FloorErrorV1::Provisioning);
                };
                let main = self.traffic.original_controller_pair_journal_v1()
                    .ok_or(FloorErrorV1::Unavailable)?;
                self.store.new_storage_intent_receiving_v2(main, &mut **receiving,
                    profile, checkpoint, target, transaction)
            }
            None => FloorIntentDataV1::new(self.profile, checkpoint, target, transaction),
        }
    }

    pub(super) fn require_sidecar_transaction_v2(&mut self, intent: FloorIntentDataV1,
        transaction: &JournalTransaction) -> Result<(), FloorErrorV1>
    {
        match self.storage_receiving.as_mut() {
            Some(receiving) => {
                let main = self.traffic.original_controller_pair_journal_v1()
                    .ok_or(FloorErrorV1::Unavailable)?;
                self.store.require_transaction_storage_receiving_v2(main,
                    &mut **receiving, intent, transaction)
            }
            None => intent.require_transaction(transaction),
        }
    }

    pub(super) fn prepare_sidecar_v2(&mut self, stored: &StoredFloorDataV1,
        intent: FloorIntentDataV1, transaction: &JournalTransaction) -> Result<(), FloorErrorV1>
    {
        match self.storage_receiving.as_mut() {
            Some(receiving) => {
                let FloorProfileDataV1::Broker(profile) = self.profile else {
                    return Err(FloorErrorV1::Provisioning);
                };
                let main = self.traffic.original_controller_pair_journal_v1()
                    .ok_or(FloorErrorV1::Unavailable)?;
                self.store.prepare_storage_receiving_v2(main, &mut **receiving,
                    profile, stored, intent, transaction)
            }
            None => self.store.prepare_data(self.profile, stored, intent, transaction),
        }
    }

    pub(super) fn preflight_sidecar_final_v2(&mut self, stored: &StoredFloorDataV1)
        -> Result<BorrowedFinalSuffixV2, FloorErrorV1>
    {
        match self.storage_receiving.as_mut() {
            Some(receiving) => {
                let FloorProfileDataV1::Broker(profile) = self.profile else {
                    return Err(FloorErrorV1::Provisioning);
                };
                let main = self.traffic.original_controller_pair_journal_v1()
                    .ok_or(FloorErrorV1::Unavailable)?;
                self.store.preflight_final_storage_receiving_v2(main, &mut **receiving,
                    profile, stored).map(BorrowedFinalSuffixV2::Storage)
            }
            None => self.store.preflight_final_data(stored, self.profile)
                .map(BorrowedFinalSuffixV2::Ordinary),
        }
    }

    pub(super) fn validate_sidecar_preflight_v2(&mut self, suffix: &BorrowedFinalSuffixV2,
        stored: &StoredFloorDataV1) -> Result<(), FloorErrorV1>
    {
        match (suffix, self.storage_receiving.as_mut()) {
            (BorrowedFinalSuffixV2::Storage(suffix), Some(receiving)) => {
                let FloorProfileDataV1::Broker(profile) = self.profile else {
                    return Err(FloorErrorV1::Provisioning);
                };
                let main = self.traffic.original_controller_pair_journal_v1()
                    .ok_or(FloorErrorV1::Unavailable)?;
                self.store.validate_final_preflight_storage_receiving_v2(main,
                    &mut **receiving, suffix, stored, profile)
            }
            (BorrowedFinalSuffixV2::Ordinary(suffix), None) => {
                self.store.validate_final_preflight_data(suffix, stored, self.profile)
            }
            _ => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(super) fn finalize_sidecar_v2(&mut self, stored: &StoredFloorDataV1)
        -> Result<(), FloorErrorV1>
    {
        match self.storage_receiving.as_mut() {
            Some(receiving) => {
                let FloorProfileDataV1::Broker(profile) = self.profile else {
                    return Err(FloorErrorV1::Provisioning);
                };
                let main = self.traffic.original_controller_pair_journal_v1()
                    .ok_or(FloorErrorV1::Unavailable)?;
                self.store.finalize_storage_receiving_v2(main, &mut **receiving, profile, stored)
            }
            None => self.store.finalize_data(self.profile, stored),
        }
    }

    pub(super) fn require_prospective_cut_v2(&mut self, intent: FloorIntentDataV1,
        transaction: &JournalTransaction) -> Result<(), FloorErrorV1>
    {
        if self.storage_receiving.is_none() {
            return require_prospective_cut(&mut *self.traffic, self.profile, intent, transaction);
        }
        self.require_sidecar_transaction_v2(intent, transaction)?;
        let (current, target) = self.main_cuts_v3(Some(transaction))?;
        if current != intent.predecessor().cut() || target != Some(intent.target().cut()) {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(())
    }
}
