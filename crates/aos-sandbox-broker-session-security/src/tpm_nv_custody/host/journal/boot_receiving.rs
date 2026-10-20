//! Prepares fixed native name posts on the genuine normal journal Source.

use std::mem::size_of;

use aos_sandbox::journal::{
    RuntimeDeploymentJournalPostFailureV1, RuntimeDeploymentJournalPostOriginalV1,
};
use aos_sandbox::{Journal, JournalError, RuntimeDeploymentComparisonOriginsV1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::HostOwnedJournalErrorV1;

pub(super) struct BootNamePostsV1 {
    originals: [Option<Box<RuntimeDeploymentJournalPostOriginalV1>>; 2],
    failures: [Option<RuntimeDeploymentJournalPostFailureV1>; 2],
    complete: [bool; 2],
}

impl BootNamePostsV1 {
    pub(super) fn prepare(
        origins: &RuntimeDeploymentComparisonOriginsV1<'_>,
    ) -> Result<Self, HostOwnedJournalErrorV1> {
        let main = RuntimeDeploymentJournalPostOriginalV1::main_v1();
        let floor = RuntimeDeploymentJournalPostOriginalV1::floor_v1();
        let bytes = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes
                    .checked_add(size_of::<RuntimeDeploymentJournalPostFailureV1>().checked_mul(4)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let demand = main
            .receiving_demand_v1()?
            .checked_add(floor.receiving_demand_v1()?)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(JournalError::from)?;
        origins.admit_boot_publisher_representation_v1(Some(demand))?;
        Ok(Self {
            originals: [Some(Box::new(main)), Some(Box::new(floor))],
            failures: [None, None],
            complete: [false; 2],
        })
    }

    pub(super) fn observe_once(
        &mut self,
        lane: usize,
        journal: &Journal,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        if self
            .complete
            .get(lane)
            .copied()
            .ok_or(HostOwnedJournalErrorV1::Changed)?
        {
            return Ok(());
        }
        let original = self.originals[lane]
            .as_mut()
            .ok_or(HostOwnedJournalErrorV1::Changed)?;
        let result = original.observe_owed_once_v1(journal);
        self.complete[lane] = true;
        if result.is_err() {
            let original = self.originals[lane]
                .take()
                .ok_or(HostOwnedJournalErrorV1::Changed)?;
            let failure = original.into_failure_original_v1();
            self.failures[lane] = Some(failure.clone());
            Err(JournalError::BootJournalPostOriginal(failure).into())
        } else {
            Ok(())
        }
    }

    pub(super) fn complete(&self) -> bool {
        self.complete.iter().all(|complete| *complete)
    }
}
