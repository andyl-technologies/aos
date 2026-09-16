//! Cheap-fork admission and durable dependency-edge replay.

use super::{
    GitCheapForkStatusV1, GitCheapForkV1, GitDurableHistoryV1, GitModelError, GitPackLeaseStatusV1,
};

impl GitDurableHistoryV1 {
    /// Retains one exact cheap-fork dependency edge.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a conflicting target, an
    /// untrusted or expired observation, or an unknown pack generation lease.
    pub fn apply_cheap_fork(
        &mut self,
        fork: GitCheapForkV1,
        verifier: &super::GitJournalVerifierV1,
    ) -> Result<(), GitModelError> {
        let current_boottime = verifier.current_boottime();
        let current = current_boottime.observed();
        let lease = fork.lease();
        let live = matches!(
            fork.status(),
            GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
        );
        let current_live = !live
            || (lease.status() == GitPackLeaseStatusV1::Active
                && lease.boot() == current_boottime.boot()
                && fork.observed_at() <= current
                && lease.expires_at() > current.get());
        let authenticated_terminal = live
            || (verifier.boot_rollover().authenticates(lease.boot())
                && (lease.status() != GitPackLeaseStatusV1::Invalidated
                    || lease.predecessor_boot().is_some_and(|boot| {
                        boot != lease.boot() && verifier.boot_rollover().authenticates(boot)
                    })));
        if !current_live || !authenticated_terminal {
            return Err(GitModelError::InvalidModel);
        }
        self.apply_replayed_cheap_fork(fork)
    }

    pub(super) fn apply_replayed_cheap_fork(
        &mut self,
        fork: GitCheapForkV1,
    ) -> Result<(), GitModelError> {
        let target = fork.target().repository().repository();
        let source_export = self.export_generations.values().find(|record| {
            record.export().repository() == fork.source_repository()
                && record.export().repository_revision() == fork.source_revision()
                && record.export().generation_digest() == fork.source_export()
        });
        let source_matches = source_export.is_some_and(|record| {
            self.repository_revisions
                .get(&(fork.source_repository(), fork.source_revision()))
                .is_some_and(|repository| {
                    repository.repository().project() == fork.target().repository().project()
                        && repository.repository().revision() == fork.source_revision()
                })
                && fork.target().ref_map() == record.export().ref_map()
                && fork.target().database() == record.export().database()
                && self.packs.values().any(|pack| {
                    pack.generation_digest() == fork.pack()
                        && pack.export_digest() == record.export().generation_digest()
                        && pack.database() == record.export().database()
                })
        });
        if let Some(existing) = self.cheap_forks.get(&target) {
            let expected = if fork.status() == existing.status() {
                existing.rebind_lease_at(existing.record_revision(), fork.lease())?
            } else if fork.lease() != existing.lease()
                && fork.lease().status() != GitPackLeaseStatusV1::Active
            {
                existing.close_with_terminal_lease_at(
                    existing.record_revision(),
                    fork.status(),
                    fork.lease(),
                )?
            } else {
                let closed_at = fork.closed_at().ok_or(GitModelError::InvalidModel)?;
                existing.close_dependency_at(
                    existing.record_revision(),
                    fork.status(),
                    fork.lease().boot(),
                    closed_at,
                )?
            };
            if !source_matches
                || expected != fork
                || self.pack_leases.get(&fork.lease().lease()) != Some(&fork.lease())
            {
                return Err(GitModelError::InvalidModel);
            }
            self.ensure_record_capacity(1)?;
            self.cheap_forks.insert(target, fork);
            return Ok(());
        }
        if self.terminal_fork_tombstones.contains_key(&target)
            || !source_matches
            || fork.status() != GitCheapForkStatusV1::Attached
            || !self.pack_leases.values().any(|lease| {
                lease == &fork.lease() && lease.status() == GitPackLeaseStatusV1::Active
            })
        {
            return Err(GitModelError::InvalidModel);
        }
        self.ensure_record_capacity(2)?;
        let mut next = self.clone();
        next.apply_repository(fork.target().clone())?;
        next.cheap_forks.insert(target, fork);
        *self = next;
        Ok(())
    }
}
