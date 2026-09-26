//! Trusted materialized Git history checkpoint model.

use aos_sandbox_core::{ObjectDigest, Revision};
use sha2::{Digest as _, Sha256};

use super::{
    GitCheapForkStatusV1, GitDurableHistoryV1, GitModelError, GitPackConsumerV1,
    GitPackLeaseStatusV1, GitRetiredPackSummaryV1, MAXIMUM_GIT_RETIRED_PACKS,
    MAXIMUM_GIT_TERMINAL_LEASE_TOMBSTONES,
};

/// Stores a fully validated Git history at an explicit replay floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHistoryCheckpointV1 {
    pub(super) floor: Revision,
    pub(super) digest: ObjectDigest,
    pub(super) history: GitDurableHistoryV1,
}

impl GitHistoryCheckpointV1 {
    /// Returns the exact replay floor committed by this checkpoint.
    #[must_use]
    pub const fn floor(&self) -> Revision {
        self.floor
    }

    /// Returns the canonical commitment to the materialized history.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

impl GitDurableHistoryV1 {
    /// Advances the trusted replay floor after a full checkpoint is retained.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for zero, MAX, or regression.
    pub(super) fn advance_replay_floor(&mut self, floor: Revision) -> Result<(), GitModelError> {
        if floor.get() == 0
            || floor.get() == u64::MAX
            || self
                .replay_floor
                .is_some_and(|old| floor.get() <= old.get())
        {
            return Err(GitModelError::InvalidModel);
        }
        self.replay_floor = Some(floor);
        Ok(())
    }

    /// Compacts superseded mutable and immutable history at the current floor.
    ///
    /// Exact repository predecessors needed by retained receives and exports,
    /// export generations needed by packs and forks, and packs needed by live
    /// leases or dependencies remain in the reconstructing baseline.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] unless `floor` is the already
    /// advanced current replay floor.
    pub(super) fn compact_at_floor(&mut self, floor: Revision) -> Result<(), GitModelError> {
        if self.replay_floor != Some(floor) {
            return Err(GitModelError::InvalidModel);
        }
        let receives = &self.receives;
        self.receive_records.retain(|(identity, revision), _| {
            receives
                .get(identity)
                .is_some_and(|latest| latest.revision() == *revision)
        });
        let repositories = &self.repositories;
        let receives = &self.receives;
        let exports = &self.export_generations;
        let cheap_forks = &self.cheap_forks;
        self.repository_revisions.retain(|(identity, revision), _| {
            repositories
                .get(identity)
                .is_some_and(|latest| latest.repository().revision() == *revision)
                || receives.values().any(|receive| {
                    receive.plan().repository().repository() == *identity
                        && (receive.plan().repository().revision() == *revision
                            || receive.phase() == super::GitReceivePhaseV1::Published
                                && receive.plan().successor_revision() == *revision)
                })
                || exports.values().any(|export| {
                    export.export().repository() == *identity
                        && export.export().repository_revision() == *revision
                })
                || cheap_forks.values().any(|fork| {
                    fork.source_repository() == *identity && fork.source_revision() == *revision
                })
        });
        let receives = &self.receives;
        self.publications
            .retain(|(repository, revision), publication| {
                receives.values().any(|receive| {
                    receive.phase() == super::GitReceivePhaseV1::Published
                        && receive.plan().repository().repository() == *repository
                        && receive.plan().successor_revision() == *revision
                        && receive.plan().atomic_cas() == publication.atomic_cas()
                })
            });
        let latest_exports = &self.exports;
        let packs = &self.packs;
        let cheap_forks = &self.cheap_forks;
        self.export_generations
            .retain(|(identity, generation), export| {
                latest_exports
                    .get(identity)
                    .is_some_and(|latest| latest.export().generation() == *generation)
                    || packs.values().any(|pack| {
                        pack.export() == *identity
                            && pack.export_generation() == *generation
                            && pack.export_digest() == export.export().generation_digest()
                    })
                    || cheap_forks
                        .values()
                        .any(|fork| fork.source_export() == export.export().generation_digest())
            });
        let pack_leases = &self.pack_leases;
        self.pack_lease_records.retain(|(identity, revision), _| {
            pack_leases
                .get(identity)
                .is_some_and(|latest| latest.lease_revision() == *revision)
        });
        Ok(())
    }

    pub(super) fn install_retired_pack_summaries(
        &mut self,
        summaries: &[GitRetiredPackSummaryV1],
        floor: Revision,
    ) -> Result<(), GitModelError> {
        let summary_count = self
            .retired_packs
            .len()
            .checked_add(summaries.len())
            .ok_or(GitModelError::InvalidModel)?;
        let tombstone_count = summaries
            .iter()
            .try_fold(self.terminal_lease_tombstones.len(), |count, summary| {
                count.checked_add(summary.leases.len())
            });
        let fork_tombstone_count = summaries
            .iter()
            .try_fold(self.terminal_fork_tombstones.len(), |count, summary| {
                count.checked_add(summary.forks.len())
            });
        if summary_count > MAXIMUM_GIT_RETIRED_PACKS
            || tombstone_count.is_none_or(|count| count > MAXIMUM_GIT_TERMINAL_LEASE_TOMBSTONES)
            || fork_tombstone_count.is_none_or(|count| count > super::MAXIMUM_GIT_HISTORY_RECORDS)
        {
            return Err(GitModelError::InvalidModel);
        }

        let mut next = self.clone();
        for summary in summaries {
            summary.validate(floor)?;
            let key = (summary.pack_generation, summary.generation);
            let pack = next.packs.get(&key).ok_or(GitModelError::InvalidModel)?;
            let mut leases = Vec::new();
            leases
                .try_reserve_exact(summary.leases.len())
                .map_err(|_| GitModelError::Allocation)?;
            leases.extend(
                next.pack_leases
                    .values()
                    .filter(|lease| {
                        lease.pack_generation() == summary.pack_generation
                            && lease.generation() == summary.generation
                    })
                    .copied(),
            );
            leases.sort_unstable_by_key(|lease| lease.lease());
            let exact_lease_set = leases.len() == summary.leases.len()
                && leases
                    .iter()
                    .zip(&summary.leases)
                    .all(|(lease, tombstone)| {
                        lease.lease() == tombstone.lease
                            && lease.lease_revision() == tombstone.revision
                            && lease.status() == tombstone.outcome
                            && lease.status() != GitPackLeaseStatusV1::Active
                    });
            let mut forks = Vec::new();
            forks
                .try_reserve_exact(summary.forks.len())
                .map_err(|_| GitModelError::Allocation)?;
            forks.extend(
                next.cheap_forks
                    .values()
                    .filter(|fork| fork.pack() == summary.generation_digest),
            );
            forks.sort_unstable_by_key(|fork| fork.target().repository().repository());
            let exact_fork_set = forks.len() == summary.forks.len()
                && forks.iter().zip(&summary.forks).all(|(fork, tombstone)| {
                    fork.target().repository().repository() == tombstone.target
                        && fork.record_revision() == tombstone.revision
                        && fork.status() == tombstone.outcome
                        && matches!(
                            fork.status(),
                            GitCheapForkStatusV1::Converted | GitCheapForkStatusV1::Tombstoned
                        )
                });
            let live_fork = next.cheap_forks.values().any(|fork| {
                fork.pack() == summary.generation_digest
                    && matches!(
                        fork.status(),
                        GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
                    )
            });
            if pack.project() != summary.project
                || pack.repository() != summary.repository
                || pack.generation_digest() != summary.generation_digest
                || !exact_lease_set
                || !exact_fork_set
                || live_fork
                || next.retired_packs.contains_key(&key)
                || summary
                    .leases
                    .iter()
                    .any(|lease| next.terminal_lease_tombstones.contains_key(&lease.lease))
                || summary
                    .forks
                    .iter()
                    .any(|fork| next.terminal_fork_tombstones.contains_key(&fork.target))
            {
                return Err(GitModelError::InvalidModel);
            }

            next.packs.remove(&key);
            for tombstone in &summary.leases {
                next.pack_leases.remove(&tombstone.lease);
                next.pack_lease_records
                    .retain(|(identity, _), _| identity != &tombstone.lease);
                next.terminal_lease_tombstones
                    .insert(tombstone.lease, *tombstone);
            }
            for tombstone in &summary.forks {
                next.terminal_fork_tombstones
                    .insert(tombstone.target, *tombstone);
            }
            next.cheap_forks.retain(|_, fork| {
                fork.pack() != summary.generation_digest
                    || matches!(
                        fork.status(),
                        GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
                    )
            });
            next.retired_packs.insert(key, summary.clone());
        }
        *self = next;
        Ok(())
    }

    /// Captures a trusted replay checkpoint at the current floor.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] until a replay floor is set.
    pub(super) fn checkpoint(&self) -> Result<GitHistoryCheckpointV1, GitModelError> {
        let floor = self.replay_floor.ok_or(GitModelError::InvalidModel)?;
        Ok(GitHistoryCheckpointV1 {
            floor,
            digest: self.complete_digest(),
            history: self.clone(),
        })
    }

    /// Restores a materialized history only from its matching trusted floor.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for an internally inconsistent
    /// checkpoint rather than replaying a suffix against the wrong floor.
    pub(super) fn from_checkpoint(
        checkpoint: &GitHistoryCheckpointV1,
    ) -> Result<Self, GitModelError> {
        if checkpoint.history.replay_floor != Some(checkpoint.floor)
            || checkpoint.history.complete_digest() != checkpoint.digest
        {
            Err(GitModelError::InvalidModel)
        } else {
            Ok(checkpoint.history.clone())
        }
    }

    fn complete_digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new().chain_update(b"aos.sandbox.git.history-checkpoint.v1\0");
        for ((identity, revision), state) in &self.repository_revisions {
            hasher = hasher
                .chain_update(identity.as_bytes())
                .chain_update(revision.get().to_be_bytes())
                .chain_update(state.complete_digest().as_bytes());
        }
        for ((identity, revision), receive) in &self.receive_records {
            hasher = hasher
                .chain_update(identity.as_bytes())
                .chain_update(revision.get().to_be_bytes())
                .chain_update(receive.complete_digest().as_bytes());
        }
        for ((identity, revision), publication) in &self.publications {
            hasher = hasher
                .chain_update(identity.as_bytes())
                .chain_update(revision.get().to_be_bytes())
                .chain_update(publication.atomic_cas().digest().as_bytes())
                .chain_update(publication.published_at().to_be_bytes());
        }
        for ((identity, generation), export) in &self.export_generations {
            let predecessor_generation = export.predecessor().map_or(0, |value| value.0.get());
            let predecessor_digest = export.predecessor().map_or_else(
                || ObjectDigest::from_bytes([0; 32]),
                |value| value.1.digest(),
            );
            hasher = hasher
                .chain_update(identity.as_bytes())
                .chain_update(generation.get().to_be_bytes())
                .chain_update(export.export().generation_digest().digest().as_bytes())
                .chain_update(predecessor_generation.to_be_bytes())
                .chain_update(predecessor_digest.as_bytes());
        }
        for ((identity, revision), pack) in &self.packs {
            hasher = hasher
                .chain_update(identity.as_bytes())
                .chain_update(revision.get().to_be_bytes())
                .chain_update(pack.generation_digest().digest().as_bytes());
        }
        for ((identity, revision), lease) in &self.pack_lease_records {
            let (consumer_kind, consumer) = match lease.consumer() {
                GitPackConsumerV1::Repository(identity) => (1_u8, identity),
                GitPackConsumerV1::Export(identity) => (2_u8, identity),
            };
            hasher = hasher
                .chain_update(identity.as_bytes())
                .chain_update(revision.get().to_be_bytes())
                .chain_update(lease.pack_generation().as_bytes())
                .chain_update(lease.generation().get().to_be_bytes())
                .chain_update(lease.generation_digest().digest().as_bytes())
                .chain_update(lease.project().as_bytes())
                .chain_update(lease.repository().as_bytes())
                .chain_update(lease.export().as_bytes())
                .chain_update(lease.export_generation().get().to_be_bytes())
                .chain_update(lease.export_digest().digest().as_bytes())
                .chain_update([consumer_kind])
                .chain_update(consumer.as_bytes())
                .chain_update(lease.principal().as_bytes())
                .chain_update(lease.boot().digest().as_bytes())
                .chain_update(lease.lease_revision().get().to_be_bytes())
                .chain_update(lease.observed_at().get().to_be_bytes())
                .chain_update(lease.expires_at().to_be_bytes())
                .chain_update(lease.pin_receipt().as_bytes())
                .chain_update([lease.status() as u8])
                .chain_update(lease.closed_at().unwrap_or(0).to_be_bytes());
        }
        for ((identity, generation), summary) in &self.retired_packs {
            hasher = hasher
                .chain_update([0x50])
                .chain_update(identity.as_bytes())
                .chain_update(generation.get().to_be_bytes())
                .chain_update(summary.project.as_bytes())
                .chain_update(summary.repository.as_bytes())
                .chain_update(summary.generation_digest.digest().as_bytes())
                .chain_update(summary.pack_payload_digest.as_bytes())
                .chain_update(summary.pack_record_head.as_bytes())
                .chain_update(summary.retired_at_floor.get().to_be_bytes());
            for lease in &summary.leases {
                hasher = hasher
                    .chain_update([0x4c])
                    .chain_update(lease.lease.as_bytes())
                    .chain_update(lease.revision.get().to_be_bytes())
                    .chain_update([lease.outcome as u8])
                    .chain_update(lease.payload_digest.as_bytes())
                    .chain_update(lease.record_head.as_bytes());
            }
            for fork in &summary.forks {
                hasher = hasher
                    .chain_update([0x46])
                    .chain_update(fork.target.as_bytes())
                    .chain_update(fork.revision.get().to_be_bytes())
                    .chain_update([fork.outcome as u8])
                    .chain_update(fork.payload_digest.as_bytes())
                    .chain_update(fork.record_head.as_bytes());
            }
        }
        for (identity, fork) in &self.cheap_forks {
            hasher = hasher
                .chain_update(identity.as_bytes())
                .chain_update(fork.complete_digest().as_bytes());
        }
        hasher = hasher.chain_update(
            self.replay_floor
                .map_or(0, |floor| floor.get())
                .to_be_bytes(),
        );
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}
