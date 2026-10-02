//! Borrowed project quantities from the owner's sole complete Cache replay.
//!
//! Partition-local quantities are not a complete project ResourceAccount, a
//! reservation, or permission to cross a physical boundary.

use aos_sandbox_core::{ObjectDigest, ProjectId};

use super::{
    CACHE_AUTHORITY_JOURNAL, CACHE_STATE_JOURNAL, PROTECTED_CACHE_ROOT,
    CacheRecoveryInventoryV1, CacheResidencyProtectedJournalErrorV1,
    CacheResidencyProtectedJournalV1, CacheResidencyProtectedOwnerV1,
    PhysicalPartitionId, ProtectedDomainJournalErrorV1,
    cache_authority_journal_limits, cache_state_journal_limits, require_cache_named_writer,
};
use crate::cache_residency::{CacheUsageV1, ProjectCacheQuotaV1};

/// Retains the exact head and project quantities of one verified partition.
#[derive(Debug)]
pub struct CacheProjectUsagePartitionV1 {
    partition: PhysicalPartitionId,
    checkpoint: ObjectDigest,
    floor: ObjectDigest,
    head_sequence: u64,
    head_digest: ObjectDigest,
    replay_binding: ObjectDigest,
    authority_poisoned: bool,
    quota: Option<ProjectCacheQuotaV1>,
    usage: Option<CacheUsageV1>,
}

impl CacheProjectUsagePartitionV1 {
    pub(in crate::cache_residency) fn from_replay(
        partition: PhysicalPartitionId,
        inventory: &CacheRecoveryInventoryV1,
        quota: Option<ProjectCacheQuotaV1>,
        usage: Option<CacheUsageV1>,
    ) -> Self {
        Self {
            partition,
            checkpoint: inventory.checkpoint,
            floor: inventory.floor,
            head_sequence: inventory.head_sequence,
            head_digest: inventory.head_digest,
            replay_binding: inventory.protected_replay_binding(),
            authority_poisoned: inventory.authority_poisoned,
            quota,
            usage,
        }
    }

    /// Returns the independently charged physical partition.
    #[must_use]
    pub const fn partition(&self) -> PhysicalPartitionId {
        self.partition
    }

    /// Returns the exact checkpoint, floor, sequence and retained head.
    #[must_use]
    pub const fn head(&self) -> (ObjectDigest, ObjectDigest, u64, ObjectDigest) {
        (self.checkpoint, self.floor, self.head_sequence, self.head_digest)
    }

    /// Returns the checked local quota, or explicit absence of this project.
    #[must_use]
    pub const fn quota(&self) -> Option<ProjectCacheQuotaV1> {
        self.quota
    }

    /// Returns checked local debt; absence is not an inferred zero quota.
    #[must_use]
    pub const fn usage(&self) -> Option<CacheUsageV1> {
        self.usage
    }

    /// Returns the complete inventory's protected replay commitment.
    #[must_use]
    pub const fn replay_binding(&self) -> ObjectDigest {
        self.replay_binding
    }

    /// Reports poison without promoting readable quantities to admission.
    #[must_use]
    pub const fn authority_poisoned(&self) -> bool {
        self.authority_poisoned
    }
}

/// Classifies unavailable resident observations without replacing their cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheProjectUsageObservationErrorV1 {
    /// The original owner or complete replay is unavailable.
    Unavailable,
    /// A prior failure or unwind permanently closed this resident observation.
    Ended,
    /// No custodied partition has a protected quota for this project.
    ProjectAbsent,
}

impl std::fmt::Display for CacheProjectUsageObservationErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("resident Cache project observation is unavailable")
    }
}

impl std::error::Error for CacheProjectUsageObservationErrorV1 {}

#[derive(Default)]
pub(super) struct CacheProjectUsageProgressV1 {
    ended: bool,
    classification: Option<CacheProjectUsageObservationErrorV1>,
    result: Option<Result<Vec<CacheProjectUsagePartitionV1>, CacheResidencyProtectedJournalErrorV1>>,
    postcheck: Option<CacheResidencyProtectedJournalErrorV1>,
}

/// Keeps complete quantities borrowed from the same original protected owner.
pub struct CacheProjectUsageLoanV1<'owner> {
    owner: &'owner mut CacheResidencyProtectedOwnerV1,
    project: ProjectId,
}

impl CacheProjectUsageLoanV1<'_> {
    /// Returns the project observed under the original complete replay.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns every custodied partition, including checkpoint-only state.
    #[must_use]
    pub fn partitions(&self) -> Option<&[CacheProjectUsagePartitionV1]> {
        if self.owner.project_usage.ended || self.owner.project_usage.postcheck.is_some() {
            return None;
        }
        match self.owner.project_usage.result.as_ref() {
            Some(Ok(partitions)) => Some(partitions),
            _ => None,
        }
    }

    /// Repeats complete coverage and currentness beneath the same clock guard.
    ///
    /// # Errors
    /// Permanently closes on failed replay or original-name/time bookends.
    pub fn recheck(&mut self) -> Result<(), CacheProjectUsageObservationErrorV1> {
        self.owner.refresh_project_usage(self.project)
    }
}

impl CacheResidencyProtectedOwnerV1 {
    /// Borrows complete partition-local Cache quantities for one project.
    ///
    /// # Errors
    /// Rejects missing original custody, failed currentness, replay, or a prior
    /// ended observation. The actual typed cause remains in this owner.
    pub fn observe_project_usage(
        &mut self,
        project: ProjectId,
    ) -> Result<CacheProjectUsageLoanV1<'_>, CacheProjectUsageObservationErrorV1> {
        self.refresh_project_usage(project)?;
        Ok(CacheProjectUsageLoanV1 { owner: self, project })
    }

    /// Borrows the first actual observation cause and separate postcheck debt.
    #[must_use]
    pub fn project_usage_failure(
        &self,
    ) -> (Option<&CacheResidencyProtectedJournalErrorV1>, Option<&CacheResidencyProtectedJournalErrorV1>) {
        let first = match self.project_usage.result.as_ref() {
            Some(Err(cause)) => Some(cause),
            _ => None,
        };
        (first, self.project_usage.postcheck.as_ref())
    }

    /// Returns the truthful resident class without fabricating a native cause.
    #[must_use]
    pub fn project_usage_failure_class(&self) -> Option<CacheProjectUsageObservationErrorV1> {
        self.project_usage.classification.or_else(|| {
            self.project_usage.ended.then_some(CacheProjectUsageObservationErrorV1::Ended)
        })
    }

    fn refresh_project_usage(
        &mut self,
        project: ProjectId,
    ) -> Result<(), CacheProjectUsageObservationErrorV1> {
        let Self { state_journal, authority, clock, owner_uid, project_usage: progress } = self;
        let owner_uid = *owner_uid;
        if progress.ended {
            return Err(CacheProjectUsageObservationErrorV1::Ended);
        }
        // Prearm before clock/name/replay effects. Only complete success opens
        // the next short observation; an unwind cannot revive a partial result.
        progress.ended = true;
        progress.result = None;
        let attempted = (|| {
            let clock = clock.as_ref()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let held_clock = clock.hold_writer_for_readback()?;
            let journal = state_journal.as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            authority.while_authority_current_resident(
                &mut progress.result,
                &mut progress.postcheck,
                |_owner, _now, validator| {
                    require_cache_named_writer(
                        journal, std::path::Path::new(PROTECTED_CACHE_ROOT),
                        CACHE_STATE_JOURNAL, owner_uid, cache_state_journal_limits(),
                    )?;
                    let mut partitions = Vec::new();
                    CacheResidencyProtectedJournalV1::claim(journal, validator.clone())?
                        .replay_project_usage(project, &mut partitions)?;
                    Ok(partitions)
                },
            );
            // Keep the actual action result parked before this additional
            // name/clock check; do not replace it with postcheck debt.
            if let Err(cause) = require_cache_named_writer(
                journal, std::path::Path::new(PROTECTED_CACHE_ROOT),
                CACHE_STATE_JOURNAL, owner_uid, cache_state_journal_limits(),
            ) {
                progress.postcheck.get_or_insert(cause.into());
            }
            if let Err(cause) = authority.check_named_location(|authority| {
                require_cache_named_writer(
                    authority, std::path::Path::new(PROTECTED_CACHE_ROOT),
                    CACHE_AUTHORITY_JOURNAL, owner_uid, cache_authority_journal_limits(),
                )
            }) {
                progress.postcheck.get_or_insert(cause);
            }
            if let Err(cause) = held_clock.revalidate() {
                progress.postcheck.get_or_insert(cause);
            }
            Ok::<(), CacheResidencyProtectedJournalErrorV1>(())
        })();
        if let Err(cause) = attempted {
            progress.result = Some(Err(cause));
        }
        if !matches!(progress.result, Some(Ok(_))) || progress.postcheck.is_some() {
            progress.classification = Some(CacheProjectUsageObservationErrorV1::Unavailable);
            return Err(CacheProjectUsageObservationErrorV1::Unavailable);
        }
        if let Some(Ok(partitions)) = &progress.result {
            if !partitions.iter().any(|partition| partition.quota.is_some()) {
                progress.classification = Some(CacheProjectUsageObservationErrorV1::ProjectAbsent);
                return Err(CacheProjectUsageObservationErrorV1::ProjectAbsent);
            }
        }
        progress.ended = false;
        Ok(())
    }
}
