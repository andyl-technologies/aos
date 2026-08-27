//! Bounded duplicate-suppression history for completed block requests.

use std::collections::{BTreeMap, BTreeSet};

use crate::PluginStorageHistoryLimits;

use super::{BlockIoError, BlockRequestIdentity};

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct CompletedIdentityHistory {
    pub(super) epochs: BTreeMap<u64, CompletedEpochHistory>,
    pub(super) gaps: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct CompletedEpochHistory {
    pub(super) contiguous_exclusive: u64,
    pub(super) out_of_order: BTreeSet<u32>,
}

impl CompletedIdentityHistory {
    pub(super) fn contains(&self, identity: BlockRequestIdentity) -> bool {
        self.epochs.get(&identity.epoch).is_some_and(|epoch| {
            u64::from(identity.request_id) < epoch.contiguous_exclusive
                || epoch.out_of_order.contains(&identity.request_id)
        })
    }

    pub(super) fn ensure_record_capacity(
        &self,
        identity: BlockRequestIdentity,
        limits: PluginStorageHistoryLimits,
    ) -> Result<(), BlockIoError> {
        if self.contains(identity) {
            return Ok(());
        }
        if !self.epochs.contains_key(&identity.epoch) {
            reserve_history(
                "storage_completed_history_epochs",
                usize_to_u64(self.epochs.len()),
                1,
                limits.epochs(),
                crate::HARD_STORAGE_COMPLETED_HISTORY_EPOCHS,
            )?;
        }
        let fills_prefix = self
            .epochs
            .get(&identity.epoch)
            .is_none_or(|epoch| u64::from(identity.request_id) == epoch.contiguous_exclusive);
        if !fills_prefix {
            reserve_history(
                "storage_completed_history_gaps",
                usize_to_u64(self.gaps),
                1,
                limits.gaps(),
                crate::HARD_STORAGE_COMPLETED_HISTORY_GAPS,
            )?;
        }
        Ok(())
    }

    pub(super) fn record(&mut self, identity: BlockRequestIdentity) {
        let epoch = self.epochs.entry(identity.epoch).or_default();
        let request_id = u64::from(identity.request_id);
        if request_id < epoch.contiguous_exclusive {
            return;
        }
        if request_id > epoch.contiguous_exclusive {
            if epoch.out_of_order.insert(identity.request_id) {
                self.gaps += 1;
            }
            return;
        }
        epoch.contiguous_exclusive += 1;
        while epoch.contiguous_exclusive <= u64::from(u32::MAX) {
            let next = epoch.contiguous_exclusive as u32;
            if !epoch.out_of_order.remove(&next) {
                break;
            }
            self.gaps -= 1;
            epoch.contiguous_exclusive += 1;
        }
    }

    pub(super) fn clear(&mut self) {
        self.epochs.clear();
        self.gaps = 0;
    }
}

pub(super) fn reserve_history(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> Result<(), BlockIoError> {
    if current
        .checked_add(requested)
        .is_some_and(|total| total <= configured)
    {
        Ok(())
    } else {
        Err(BlockIoError::CompletedHistoryResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        })
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
