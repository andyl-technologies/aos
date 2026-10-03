//! Trusted reconstruction of compacted Git projection baselines.
//!
//! A baseline contains only currently materialized or immutably referenced
//! domain records. Its journal verifier, rather than missing historical
//! predecessors, authorizes the compaction boundary.

use aos_sandbox_core::Revision;

use super::{
    GitCheapForkStatusV1, GitDurableHistoryV1, GitDurablePayloadV1, GitModelError,
    GitPackConsumerV1, GitPackLeaseStatusV1, GitReceivePhaseV1, GitRetiredPackSummaryV1,
};

impl GitDurableHistoryV1 {
    /// Returns the protected compaction floor shared with projection replay.
    #[must_use]
    pub const fn replay_floor(&self) -> Option<Revision> {
        self.replay_floor
    }

    pub(super) fn validate_current_leases(
        &self,
        verifier: &super::GitJournalVerifierV1,
    ) -> Result<(), GitModelError> {
        let current_boottime = verifier.current_boottime();
        let current = current_boottime.observed().get();
        if self.pack_lease_records.values().any(|lease| {
            let recorded_is_authenticated = verifier.boot_rollover().authenticates(lease.boot());
            let invalidation_is_authenticated = lease.status() != GitPackLeaseStatusV1::Invalidated
                || lease.predecessor_boot().is_some_and(|boot| {
                    boot != lease.boot() && verifier.boot_rollover().authenticates(boot)
                });
            !recorded_is_authenticated || !invalidation_is_authenticated
        }) {
            return Err(GitModelError::InvalidModel);
        }
        if self.pack_leases.values().any(|lease| match lease.status() {
            GitPackLeaseStatusV1::Active => {
                lease.boot() != current_boottime.boot() || lease.expires_at() <= current
            }
            GitPackLeaseStatusV1::Invalidated
            | GitPackLeaseStatusV1::Released
            | GitPackLeaseStatusV1::Expired => false,
        }) {
            Err(GitModelError::InvalidModel)
        } else {
            Ok(())
        }
    }

    pub(super) fn contains_checkpoint_payload(&self, payload: &GitDurablePayloadV1) -> bool {
        match payload {
            GitDurablePayloadV1::Repository(value) => {
                self.repository_revisions.get(&(
                    value.repository().repository(),
                    value.repository().revision(),
                )) == Some(value)
            }
            GitDurablePayloadV1::Receive(value) => {
                self.receive_records
                    .get(&(value.plan().exchange(), value.revision()))
                    == Some(value)
            }
            GitDurablePayloadV1::Publication(value) => {
                self.publications
                    .get(&(value.repository(), value.successor_revision()))
                    == Some(value)
            }
            GitDurablePayloadV1::Export(value) => {
                self.export_generations
                    .get(&(value.export().export(), value.export().generation()))
                    == Some(value)
            }
            GitDurablePayloadV1::Pack(value) => {
                self.packs
                    .get(&(value.pack_generation(), value.generation()))
                    == Some(value)
            }
            GitDurablePayloadV1::PackLease(value) => {
                self.pack_lease_records
                    .get(&(value.lease(), value.lease_revision()))
                    == Some(value)
            }
            GitDurablePayloadV1::CheapFork(value) => {
                self.cheap_forks
                    .get(&value.target().repository().repository())
                    == Some(value)
            }
        }
    }

    pub(super) fn retired_lineage_head(
        &self,
        project: aos_sandbox_core::ProjectId,
        lineage: aos_sandbox_core::ResourceId,
        kind: super::GitDurableRecordKindV1,
    ) -> Option<(Revision, aos_sandbox_core::ObjectDigest)> {
        match kind {
            super::GitDurableRecordKindV1::Pack => self
                .latest_retired_pack(lineage)
                .filter(|summary| summary.project == project)
                .map(|summary| (summary.generation, summary.pack_record_head)),
            super::GitDurableRecordKindV1::PackLease => self
                .terminal_lease_tombstones
                .get(&lineage)
                .map(|lease| (lease.revision, lease.record_head)),
            super::GitDurableRecordKindV1::CheapFork => self
                .terminal_fork_tombstones
                .get(&lineage)
                .map(|fork| (fork.revision, fork.record_head)),
            _ => None,
        }
    }

    pub(super) fn from_compacted_payloads<'a>(
        payloads: impl IntoIterator<Item = &'a GitDurablePayloadV1>,
        retired_packs: Vec<GitRetiredPackSummaryV1>,
        floor: Revision,
        verifier: &super::GitJournalVerifierV1,
    ) -> Result<Self, GitModelError> {
        let mut history = Self {
            replay_floor: Some(floor),
            ..Self::default()
        };

        for payload in payloads {
            match payload {
                GitDurablePayloadV1::Repository(value) => {
                    let identity = value.repository().repository();
                    let revision = value.repository().revision();
                    if history
                        .repository_revisions
                        .insert((identity, revision), value.clone())
                        .is_some()
                    {
                        return Err(GitModelError::InvalidModel);
                    }
                    if history
                        .repositories
                        .get(&identity)
                        .is_none_or(|current| current.repository().revision() < revision)
                    {
                        history.repositories.insert(identity, value.clone());
                    }
                }
                GitDurablePayloadV1::Receive(value) => {
                    let identity = value.plan().exchange();
                    if history
                        .receive_records
                        .insert((identity, value.revision()), value.clone())
                        .is_some()
                    {
                        return Err(GitModelError::InvalidModel);
                    }
                    if history
                        .receives
                        .get(&identity)
                        .is_none_or(|current| current.revision() < value.revision())
                    {
                        history.receives.insert(identity, value.clone());
                    }
                }
                GitDurablePayloadV1::Publication(value) => {
                    if history
                        .publications
                        .insert((value.repository(), value.successor_revision()), *value)
                        .is_some()
                    {
                        return Err(GitModelError::InvalidModel);
                    }
                }
                GitDurablePayloadV1::Export(value) => {
                    let identity = value.export().export();
                    let generation = value.export().generation();
                    if history
                        .export_generations
                        .insert((identity, generation), value.clone())
                        .is_some()
                    {
                        return Err(GitModelError::InvalidModel);
                    }
                    if history
                        .exports
                        .get(&identity)
                        .is_none_or(|current| current.export().generation() < generation)
                    {
                        history.exports.insert(identity, value.clone());
                    }
                }
                GitDurablePayloadV1::Pack(value) => {
                    if history
                        .packs
                        .insert((value.pack_generation(), value.generation()), value.clone())
                        .is_some()
                    {
                        return Err(GitModelError::InvalidModel);
                    }
                }
                GitDurablePayloadV1::PackLease(value) => {
                    if history
                        .pack_lease_records
                        .insert((value.lease(), value.lease_revision()), *value)
                        .is_some()
                    {
                        return Err(GitModelError::InvalidModel);
                    }
                    if history
                        .pack_leases
                        .get(&value.lease())
                        .is_none_or(|current| current.lease_revision() < value.lease_revision())
                    {
                        history.pack_leases.insert(value.lease(), *value);
                    }
                }
                GitDurablePayloadV1::CheapFork(value) => {
                    let target = value.target().repository().repository();
                    if history.cheap_forks.insert(target, value.clone()).is_some() {
                        return Err(GitModelError::InvalidModel);
                    }
                }
            }
        }

        history.install_compacted_retired_packs(retired_packs, floor)?;
        history.ensure_record_capacity(0)?;

        history.validate_compacted_closure(verifier)?;
        Ok(history)
    }

    fn install_compacted_retired_packs(
        &mut self,
        retired_packs: Vec<GitRetiredPackSummaryV1>,
        floor: Revision,
    ) -> Result<(), GitModelError> {
        let mut tombstone_count = 0_usize;
        let mut fork_tombstone_count = 0_usize;
        for summary in retired_packs {
            summary
                .validate(floor)
                .map_err(|_| GitModelError::InvalidModel)?;
            tombstone_count = tombstone_count
                .checked_add(summary.leases.len())
                .filter(|count| *count <= super::MAXIMUM_GIT_TERMINAL_LEASE_TOMBSTONES)
                .ok_or(GitModelError::InvalidModel)?;
            fork_tombstone_count = fork_tombstone_count
                .checked_add(summary.forks.len())
                .filter(|count| *count <= super::MAXIMUM_GIT_HISTORY_RECORDS)
                .ok_or(GitModelError::InvalidModel)?;
            let key = (summary.pack_generation, summary.generation);
            if self.packs.contains_key(&key)
                || self.retired_packs.contains_key(&key)
                || summary.leases.iter().any(|lease| {
                    self.pack_leases.contains_key(&lease.lease)
                        || self.terminal_lease_tombstones.contains_key(&lease.lease)
                })
                || summary.forks.iter().any(|fork| {
                    self.cheap_forks.contains_key(&fork.target)
                        || self.terminal_fork_tombstones.contains_key(&fork.target)
                })
            {
                return Err(GitModelError::InvalidModel);
            }
            for lease in &summary.leases {
                self.terminal_lease_tombstones.insert(lease.lease, *lease);
            }
            for fork in &summary.forks {
                self.terminal_fork_tombstones.insert(fork.target, *fork);
            }
            self.retired_packs.insert(key, summary);
        }
        if self.retired_packs.len() > super::MAXIMUM_GIT_RETIRED_PACKS {
            return Err(GitModelError::InvalidModel);
        }
        Ok(())
    }

    fn validate_compacted_closure(
        &self,
        verifier: &super::GitJournalVerifierV1,
    ) -> Result<(), GitModelError> {
        let current_boottime = verifier.current_boottime();
        self.validate_current_leases(verifier)?;
        for receive in self.receive_records.values() {
            let repository = receive.plan().repository();
            if !self
                .repository_revisions
                .contains_key(&(repository.repository(), repository.revision()))
            {
                return Err(GitModelError::InvalidModel);
            }
            if receive.phase() == GitReceivePhaseV1::Published {
                let publication = self
                    .publications
                    .get(&(repository.repository(), receive.plan().successor_revision()));
                let predecessor = self
                    .repository_revisions
                    .get(&(repository.repository(), repository.revision()));
                let successor = self
                    .repository_revisions
                    .get(&(repository.repository(), receive.plan().successor_revision()));
                let publication_matches = publication.is_some_and(|publication| {
                    super::GitPublicationRecordV1::from_receive(
                        receive.plan(),
                        publication.published_at(),
                    )
                    .is_ok_and(|expected| expected == *publication)
                });
                let successor_matches =
                    predecessor
                        .zip(successor)
                        .is_some_and(|(predecessor, successor)| {
                            super::GitRepositoryStateV1::from_receive(
                                receive.plan(),
                                predecessor.complete_digest(),
                            )
                            .is_ok_and(|expected| expected == *successor)
                        });
                if !publication_matches || !successor_matches {
                    return Err(GitModelError::InvalidModel);
                }
            }
        }
        for publication in self.publications.values() {
            if !self.receives.values().any(|receive| {
                receive.phase() == GitReceivePhaseV1::Published
                    && receive.plan().repository().repository() == publication.repository()
                    && receive.plan().successor_revision() == publication.successor_revision()
                    && receive.plan().atomic_cas() == publication.atomic_cas()
            }) {
                return Err(GitModelError::InvalidModel);
            }
        }
        for export in self.export_generations.values() {
            let source = self.repository_revisions.get(&(
                export.export().repository(),
                export.export().repository_revision(),
            ));
            if source.is_none_or(|source| {
                source.ref_map() != export.export().ref_map()
                    || source.database() != export.export().database()
            }) {
                return Err(GitModelError::InvalidModel);
            }
        }
        for pack in self.packs.values() {
            if self
                .export_generations
                .get(&(pack.export(), pack.export_generation()))
                .is_none_or(|export| {
                    export.export().generation_digest() != pack.export_digest()
                        || export.export().database() != pack.database()
                })
            {
                return Err(GitModelError::InvalidModel);
            }
        }
        for summary in self.retired_packs.values() {
            summary.validate(self.replay_floor.ok_or(GitModelError::InvalidModel)?)?;
            if summary
                .leases
                .iter()
                .any(|lease| self.terminal_lease_tombstones.get(&lease.lease) != Some(lease))
                || summary
                    .forks
                    .iter()
                    .any(|fork| self.terminal_fork_tombstones.get(&fork.target) != Some(fork))
            {
                return Err(GitModelError::InvalidModel);
            }
        }
        let summarized_leases = self
            .retired_packs
            .values()
            .try_fold(0_usize, |count, summary| {
                count.checked_add(summary.leases.len())
            });
        if summarized_leases != Some(self.terminal_lease_tombstones.len()) {
            return Err(GitModelError::InvalidModel);
        }
        let summarized_forks = self
            .retired_packs
            .values()
            .try_fold(0_usize, |count, summary| {
                count.checked_add(summary.forks.len())
            });
        if summarized_forks != Some(self.terminal_fork_tombstones.len()) {
            return Err(GitModelError::InvalidModel);
        }
        for lease in self.pack_leases.values() {
            let Some(pack) = self
                .packs
                .get(&(lease.pack_generation(), lease.generation()))
            else {
                return Err(GitModelError::InvalidModel);
            };
            let current_lease = match lease.status() {
                GitPackLeaseStatusV1::Active => {
                    lease.boot() == current_boottime.boot()
                        && lease.expires_at() > current_boottime.observed().get()
                }
                GitPackLeaseStatusV1::Invalidated => lease.predecessor_boot().is_some_and(|boot| {
                    boot != lease.boot()
                        && verifier.boot_rollover().authenticates(lease.boot())
                        && verifier.boot_rollover().authenticates(boot)
                }),
                GitPackLeaseStatusV1::Released | GitPackLeaseStatusV1::Expired => {
                    verifier.boot_rollover().authenticates(lease.boot())
                }
            };
            if pack.generation_digest() != lease.generation_digest()
                || matches!(lease.consumer(), GitPackConsumerV1::Export(export) if export != pack.export())
                || !current_lease
            {
                return Err(GitModelError::InvalidModel);
            }
        }
        for fork in self.cheap_forks.values() {
            let lease = self.pack_leases.get(&fork.lease().lease());
            let depends_on_pack = matches!(
                fork.status(),
                GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
            );
            let terminal_lease_matches = !depends_on_pack
                && lease.is_some_and(|current| {
                    current == &fork.lease()
                        || pack_lease_is_terminal_successor(*current, fork.lease())
                });
            if (depends_on_pack && fork.observed_at() > current_boottime.observed())
                || (!depends_on_pack && !terminal_lease_matches)
                || depends_on_pack
                    && lease.is_none_or(|lease| {
                        lease != &fork.lease()
                            || lease.status() != GitPackLeaseStatusV1::Active
                            || lease.expires_at() <= current_boottime.observed().get()
                            || lease.consumer()
                                != GitPackConsumerV1::Repository(
                                    fork.target().repository().repository(),
                                )
                    })
            {
                return Err(GitModelError::InvalidModel);
            }
        }
        Ok(())
    }
}

fn pack_lease_is_terminal_successor(
    successor: super::GitPackLeaseV1,
    predecessor: super::GitPackLeaseV1,
) -> bool {
    predecessor.status() == GitPackLeaseStatusV1::Active
        && successor.status() != GitPackLeaseStatusV1::Active
        && predecessor
            .lease_revision()
            .checked_next()
            .is_ok_and(|revision| revision == successor.lease_revision())
        && successor.project() == predecessor.project()
        && successor.repository() == predecessor.repository()
        && successor.pack_generation() == predecessor.pack_generation()
        && successor.generation() == predecessor.generation()
        && successor.generation_digest() == predecessor.generation_digest()
        && successor.export() == predecessor.export()
        && successor.export_generation() == predecessor.export_generation()
        && successor.export_digest() == predecessor.export_digest()
        && successor.consumer() == predecessor.consumer()
        && successor.lease() == predecessor.lease()
        && successor.principal() == predecessor.principal()
        && successor.expires_at() == predecessor.expires_at()
        && successor.pin_receipt() == predecessor.pin_receipt()
        && successor.closed_at() == Some(successor.observed_at().get())
        && ((successor.boot() == predecessor.boot()
            && successor.predecessor_boot().is_none()
            && successor.observed_at() > predecessor.observed_at())
            || (successor.status() == GitPackLeaseStatusV1::Invalidated
                && successor.boot() != predecessor.boot()
                && successor.predecessor_boot() == Some(predecessor.boot())))
}
