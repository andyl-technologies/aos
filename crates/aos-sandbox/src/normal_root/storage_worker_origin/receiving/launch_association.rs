//! Joins a caller-resident launch image to the same admitted Storage original.
//!
//! Only the actual receiving loan enters this once-only local observation.
//! The output is fixed path DATA for an independently paid service observer;
//! it grants no account, effect or currentness operation and exposes no FD.

use super::*;
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt as _;
use aos_sandbox_linux::cgroup::StorageCgroupLayoutV1;

pub(super) struct LaunchAssociationOriginalV1 {
    entered: bool,
    reservation: Option<Result<(), StorageReceivingClosedV1>>,
    offered: Option<Result<Metadata, std::io::Error>>,
    retained: Option<Result<Metadata, std::io::Error>>,
    binding: Option<Result<StorageCgroupLayoutV1, StorageReceivingClosedV1>>,
    closed: Option<StorageReceivingClosedV1>,
}

impl LaunchAssociationOriginalV1 {
    pub(super) const fn new() -> Self {
        Self { entered: false, reservation: None, offered: None, retained: None,
            binding: None, closed: None }
    }

    pub(super) fn completed_layout_v2(&self) -> Option<StorageCgroupLayoutV1> {
        if self.failure().is_some() { return None; }
        self.binding.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(result: &Option<Result<T, E>>)
            -> Option<&(dyn Error + 'static)>
        {
            result.as_ref()?.as_ref().err().map(|error| error as _)
        }
        cause(&self.reservation).or_else(|| cause(&self.offered))
            .or_else(|| cause(&self.retained)).or_else(|| cause(&self.binding))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

impl StoragePrepareReceivingLoanV1<'_> {
    /// Associates the actual launch image with this admitted aggregate recipe.
    ///
    /// The genuine upper launch-image owner must apply its own fixed endpoint,
    /// process and profile gate before borrowing its private file here. Its
    /// surrounding paid currentness and owed posts remain separate; this leaf
    /// performs no RPC and does not claim a fresh whole-service observation.
    ///
    /// # Errors
    /// Refuses closed or repeated entry, capacity refusal, a missing retained
    /// launch original, native metadata failure or a different pinned object.
    /// Every entered native Result remains on this same receiving original.
    pub fn associate_original_launch_image_layout_v1(
        &mut self,
        image: &File,
    ) -> Result<StorageCgroupLayoutV1, StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if receiving.launch_association.entered {
            receiving.launch_association.closed.get_or_insert(StorageReceivingClosedV1);
            receiving.first.get_or_insert(Failure::LaunchAssociation);
            return Err(StorageReceivingClosedV1);
        }
        receiving.launch_association.entered = true;
        // The inline destination is already in actual Self. These are its
        // two construction carriers and two native errors. Metadata calls on
        // these already-held files create no namespace or directory entry.
        let demand = ResourceVector::ZERO
            .with(D::MemoryBytes, (2 * std::mem::size_of::<Metadata>() + 2 * 256) as u64);
        let reservation = receiving.reserve(demand);
        let paid = reservation.is_ok();
        receiving.launch_association.reservation = Some(reservation);
        if !paid { return Err(StorageReceivingClosedV1); }

        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else { std::process::abort() };
        let association = &mut receiving.launch_association;
        let Some(retained) = self.original.custody.original_pid1.as_ref() else {
            association.binding = Some(Err(StorageReceivingClosedV1));
            receiving.first.get_or_insert(Failure::LaunchAssociation);
            return Err(StorageReceivingClosedV1);
        };
        association.offered = Some(image.metadata());
        // This independent original sample is not suppressed by offered Err.
        association.retained = Some(retained.metadata());
        association.binding = Some(match (&association.offered, &association.retained) {
            (Some(Ok(offered)), Some(Ok(retained)))
                if offered.is_file() && retained.is_file()
                    && offered.dev() == retained.dev() && offered.ino() == retained.ino()
                    && self.original.custody.aggregate.is_current() =>
                        Ok(StorageCgroupLayoutV1::ReceivingAggregate),
            _ => Err(StorageReceivingClosedV1),
        });
        match association.binding.as_ref() {
            Some(Ok(layout)) => Ok(*layout),
            _ => {
                receiving.first.get_or_insert(Failure::LaunchAssociation);
                Err(StorageReceivingClosedV1)
            }
        }
    }
}
