//! Compact protected tombstones for retired immutable pack generations.
//!
//! A retired-pack summary is a checkpoint-only baseline. It preserves the
//! immutable pack lineage head and every terminal lease lineage head after the
//! corresponding full pack and lease records are removed. The accepted Git
//! checkpoint authenticates these bytes; the summary grants no runtime lease
//! or object access.

use std::collections::BTreeSet;

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId, Revision};

use super::{
    GitCheapForkStatusV1, GitDurableHistoryV1, GitDurablePayloadV1, GitDurableRecordKindV1,
    GitModelError, GitPackGenerationDigestV1, GitPackLeaseStatusV1, GitProjectionHistoryV1,
};

const SUMMARY_HEADER_BYTES: usize = 168;
const TOMBSTONE_BYTES: usize = 96;

pub(super) const fn encoded_retired_pack_length_minimum() -> usize {
    SUMMARY_HEADER_BYTES
}

/// Maximum retired pack generations retained by one compacted history.
pub const MAXIMUM_GIT_RETIRED_PACKS: usize = super::MAXIMUM_GIT_HISTORY_RECORDS;
/// Maximum terminal lease identities retained by one compacted history.
pub const MAXIMUM_GIT_TERMINAL_LEASE_TOMBSTONES: usize = super::MAXIMUM_GIT_PACK_LEASES;

/// Preserves one terminal lease identity and its exact durable lineage head.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GitTerminalLeaseTombstoneV1 {
    pub(super) lease: ResourceId,
    pub(super) revision: Revision,
    pub(super) outcome: GitPackLeaseStatusV1,
    pub(super) payload_digest: ObjectDigest,
    pub(super) record_head: ObjectDigest,
}

/// Preserves one closed cheap-fork identity and its durable lineage head.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GitTerminalForkTombstoneV1 {
    pub(super) target: ResourceId,
    pub(super) revision: Revision,
    pub(super) outcome: GitCheapForkStatusV1,
    pub(super) payload_digest: ObjectDigest,
    pub(super) record_head: ObjectDigest,
}

impl GitTerminalLeaseTombstoneV1 {
    /// Returns the permanently retired lease identity.
    #[must_use]
    pub const fn lease(self) -> ResourceId {
        self.lease
    }

    /// Returns the terminal lease revision.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }

    /// Returns the retained terminal outcome.
    #[must_use]
    pub const fn outcome(self) -> GitPackLeaseStatusV1 {
        self.outcome
    }

    /// Returns the canonical terminal lease payload commitment.
    #[must_use]
    pub const fn payload_digest(self) -> ObjectDigest {
        self.payload_digest
    }

    /// Returns the exact terminal durable-record lineage head.
    #[must_use]
    pub const fn record_head(self) -> ObjectDigest {
        self.record_head
    }
}

impl GitTerminalForkTombstoneV1 {
    /// Returns the permanently closed target repository identity.
    #[must_use]
    pub const fn target(self) -> ResourceId {
        self.target
    }

    /// Returns the terminal cheap-fork revision.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }

    /// Returns the retained conversion or tombstone outcome.
    #[must_use]
    pub const fn outcome(self) -> GitCheapForkStatusV1 {
        self.outcome
    }

    /// Returns the canonical terminal cheap-fork payload commitment.
    #[must_use]
    pub const fn payload_digest(self) -> ObjectDigest {
        self.payload_digest
    }

    /// Returns the exact terminal durable-record lineage head.
    #[must_use]
    pub const fn record_head(self) -> ObjectDigest {
        self.record_head
    }
}

/// Replaces one unreferenced pack and all of its terminal lease records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitRetiredPackSummaryV1 {
    pub(super) project: ProjectId,
    pub(super) repository: ResourceId,
    pub(super) pack_generation: ResourceId,
    pub(super) generation: Revision,
    pub(super) generation_digest: GitPackGenerationDigestV1,
    pub(super) pack_payload_digest: ObjectDigest,
    pub(super) pack_record_head: ObjectDigest,
    pub(super) retired_at_floor: Revision,
    pub(super) leases: Vec<GitTerminalLeaseTombstoneV1>,
    pub(super) forks: Vec<GitTerminalForkTombstoneV1>,
}

impl GitRetiredPackSummaryV1 {
    /// Returns the project owning the retired pack lineage.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the repository from which the retired pack was exported.
    #[must_use]
    pub const fn repository(&self) -> ResourceId {
        self.repository
    }

    /// Returns the immutable pack lineage identity.
    #[must_use]
    pub const fn pack_generation(&self) -> ResourceId {
        self.pack_generation
    }

    /// Returns the retired generation.
    #[must_use]
    pub const fn generation(&self) -> Revision {
        self.generation
    }

    /// Returns the exact retired generation commitment.
    #[must_use]
    pub const fn generation_digest(&self) -> GitPackGenerationDigestV1 {
        self.generation_digest
    }

    /// Returns the exact canonical pack payload commitment.
    #[must_use]
    pub const fn pack_payload_digest(&self) -> ObjectDigest {
        self.pack_payload_digest
    }

    /// Returns the exact durable pack-record lineage head.
    #[must_use]
    pub const fn pack_record_head(&self) -> ObjectDigest {
        self.pack_record_head
    }

    /// Returns the first protected floor containing this summary.
    #[must_use]
    pub const fn retired_at_floor(&self) -> Revision {
        self.retired_at_floor
    }

    /// Borrows the terminal lease nonreuse entries.
    #[must_use]
    pub fn leases(&self) -> &[GitTerminalLeaseTombstoneV1] {
        &self.leases
    }

    /// Borrows the closed dependent-fork nonreuse entries.
    #[must_use]
    pub fn forks(&self) -> &[GitTerminalForkTombstoneV1] {
        &self.forks
    }

    pub(super) fn validate(&self, floor: Revision) -> Result<(), GitModelError> {
        if self.project.as_bytes() == &[0; 16]
            || self.repository.as_bytes() == &[0; 16]
            || self.pack_generation.as_bytes() == &[0; 16]
            || self.generation.get() == 0
            || self.generation.get() == u64::MAX
            || self.generation_digest.digest().as_bytes() == &[0; 32]
            || self.pack_payload_digest.as_bytes() == &[0; 32]
            || self.pack_record_head.as_bytes() == &[0; 32]
            || self.retired_at_floor.get() == 0
            || self.retired_at_floor.get() == u64::MAX
            || self.retired_at_floor > floor
            || self.leases.len() > MAXIMUM_GIT_TERMINAL_LEASE_TOMBSTONES
            || self
                .leases
                .windows(2)
                .any(|pair| pair[0].lease >= pair[1].lease)
            || self.leases.iter().any(|lease| {
                lease.lease.as_bytes() == &[0; 16]
                    || lease.revision.get() < 2
                    || lease.revision.get() == u64::MAX
                    || lease.outcome == GitPackLeaseStatusV1::Active
                    || lease.payload_digest.as_bytes() == &[0; 32]
                    || lease.record_head.as_bytes() == &[0; 32]
            })
            || self.forks.len() > super::MAXIMUM_GIT_HISTORY_RECORDS
            || self
                .forks
                .windows(2)
                .any(|pair| pair[0].target >= pair[1].target)
            || self.forks.iter().any(|fork| {
                fork.target.as_bytes() == &[0; 16]
                    || fork.revision.get() < 2
                    || fork.revision.get() == u64::MAX
                    || !matches!(
                        fork.outcome,
                        GitCheapForkStatusV1::Converted | GitCheapForkStatusV1::Tombstoned
                    )
                    || fork.payload_digest.as_bytes() == &[0; 32]
                    || fork.record_head.as_bytes() == &[0; 32]
            })
        {
            Err(GitModelError::InvalidModel)
        } else {
            Ok(())
        }
    }
}

impl GitDurableHistoryV1 {
    pub(super) fn latest_retired_pack(
        &self,
        identity: ResourceId,
    ) -> Option<&GitRetiredPackSummaryV1> {
        self.retired_packs
            .range((identity, Revision::new(0))..=(identity, Revision::new(u64::MAX)))
            .next_back()
            .map(|(_, summary)| summary)
    }

    /// Returns one protected retired-pack summary at an exact generation.
    #[must_use]
    pub fn retired_pack_summary(
        &self,
        identity: ResourceId,
        generation: Revision,
    ) -> Option<&GitRetiredPackSummaryV1> {
        self.retired_packs.get(&(identity, generation))
    }

    /// Returns the protected terminal tombstone for one retired lease.
    #[must_use]
    pub fn terminal_lease_tombstone(
        &self,
        lease: ResourceId,
    ) -> Option<GitTerminalLeaseTombstoneV1> {
        self.terminal_lease_tombstones.get(&lease).copied()
    }

    /// Returns the protected terminal tombstone for one closed cheap fork.
    #[must_use]
    pub fn terminal_fork_tombstone(
        &self,
        target: ResourceId,
    ) -> Option<GitTerminalForkTombstoneV1> {
        self.terminal_fork_tombstones.get(&target).copied()
    }
}

impl GitProjectionHistoryV1 {
    pub(super) fn plan_pack_retirements(
        &self,
        floor: Revision,
    ) -> Result<
        (
            Vec<GitRetiredPackSummaryV1>,
            BTreeSet<(ProjectId, ResourceId)>,
        ),
        GitModelError,
    > {
        let mut summaries = Vec::new();
        summaries
            .try_reserve_exact(self.domain.packs.len())
            .map_err(|_| GitModelError::Allocation)?;
        let mut discarded_joins = BTreeSet::new();
        for pack in self.domain.packs.values() {
            let lease_count = self
                .domain
                .pack_leases
                .values()
                .filter(|lease| {
                    lease.pack_generation() == pack.pack_generation()
                        && lease.generation() == pack.generation()
                        && lease.generation_digest() == pack.generation_digest()
                })
                .count();
            let mut leases = Vec::new();
            leases
                .try_reserve_exact(lease_count)
                .map_err(|_| GitModelError::Allocation)?;
            leases.extend(
                self.domain
                    .pack_leases
                    .values()
                    .filter(|lease| {
                        lease.pack_generation() == pack.pack_generation()
                            && lease.generation() == pack.generation()
                            && lease.generation_digest() == pack.generation_digest()
                    })
                    .copied(),
            );
            let has_live_reference = leases
                .iter()
                .any(|lease| lease.status() == GitPackLeaseStatusV1::Active)
                || self.domain.cheap_forks.values().any(|fork| {
                    fork.pack() == pack.generation_digest()
                        && matches!(
                            fork.status(),
                            GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
                        )
                });
            if has_live_reference {
                continue;
            }

            let pack_key = (
                pack.project(),
                pack.pack_generation(),
                GitDurableRecordKindV1::Pack,
                pack.generation(),
            );
            let Some(pack_record) = self.records.get(&pack_key) else {
                continue;
            };
            let mut tombstones = Vec::new();
            tombstones
                .try_reserve_exact(leases.len())
                .map_err(|_| GitModelError::Allocation)?;
            let mut candidate_joins = BTreeSet::new();
            let mut fork_tombstones = Vec::new();
            fork_tombstones
                .try_reserve_exact(self.domain.cheap_forks.len())
                .map_err(|_| GitModelError::Allocation)?;
            candidate_joins.insert((pack_record.project(), pack_record.atomic_join()));
            let mut complete = true;
            for lease in leases {
                let key = (
                    lease.project(),
                    lease.lease(),
                    GitDurableRecordKindV1::PackLease,
                    lease.lease_revision(),
                );
                let Some(record) = self.records.get(&key) else {
                    complete = false;
                    break;
                };
                candidate_joins.insert((record.project(), record.atomic_join()));
                tombstones.push(GitTerminalLeaseTombstoneV1 {
                    lease: lease.lease(),
                    revision: lease.lease_revision(),
                    outcome: lease.status(),
                    payload_digest: record.payload_digest(),
                    record_head: record.complete_digest(),
                });
            }
            if !complete {
                continue;
            }
            for fork in self
                .domain
                .cheap_forks
                .values()
                .filter(|fork| fork.pack() == pack.generation_digest())
            {
                let key = (
                    fork.target().repository().project(),
                    fork.target().repository().repository(),
                    GitDurableRecordKindV1::CheapFork,
                    fork.record_revision(),
                );
                let Some(record) = self.records.get(&key) else {
                    complete = false;
                    break;
                };
                if !matches!(
                    fork.status(),
                    GitCheapForkStatusV1::Converted | GitCheapForkStatusV1::Tombstoned
                ) {
                    complete = false;
                    break;
                }
                fork_tombstones.push(GitTerminalForkTombstoneV1 {
                    target: fork.target().repository().repository(),
                    revision: fork.record_revision(),
                    outcome: fork.status(),
                    payload_digest: record.payload_digest(),
                    record_head: record.complete_digest(),
                });
            }
            if !complete {
                continue;
            }

            let mut lease_lineages = BTreeSet::new();
            lease_lineages.extend(tombstones.iter().map(|lease| lease.lease));
            let mut fork_lineages = BTreeSet::new();
            fork_lineages.extend(fork_tombstones.iter().map(|fork| fork.target));
            for record in self.records.values() {
                let belongs_to_retired_lineage = match record.payload() {
                    GitDurablePayloadV1::Pack(value) => {
                        value.pack_generation() == pack.pack_generation()
                            && value.generation() == pack.generation()
                    }
                    GitDurablePayloadV1::PackLease(value) => {
                        lease_lineages.contains(&value.lease())
                    }
                    GitDurablePayloadV1::CheapFork(value) => {
                        fork_lineages.contains(&value.target().repository().repository())
                    }
                    _ => false,
                };
                if belongs_to_retired_lineage {
                    candidate_joins.insert((record.project(), record.atomic_join()));
                }
            }
            let join_is_closed = self.records.values().all(|record| {
                !candidate_joins.contains(&(record.project(), record.atomic_join()))
                    || match record.payload() {
                        GitDurablePayloadV1::Pack(value) => {
                            value.pack_generation() == pack.pack_generation()
                                && value.generation() == pack.generation()
                        }
                        GitDurablePayloadV1::PackLease(value) => {
                            lease_lineages.contains(&value.lease())
                                && value.pack_generation() == pack.pack_generation()
                                && value.generation() == pack.generation()
                                && value.generation_digest() == pack.generation_digest()
                        }
                        GitDurablePayloadV1::CheapFork(value) => {
                            fork_lineages.contains(&value.target().repository().repository())
                                && value.pack() == pack.generation_digest()
                        }
                        _ => false,
                    }
            });
            if !join_is_closed {
                continue;
            }
            tombstones.sort_unstable_by_key(|lease| lease.lease);
            fork_tombstones.sort_unstable_by_key(|fork| fork.target);
            summaries.push(GitRetiredPackSummaryV1 {
                project: pack.project(),
                repository: pack.repository(),
                pack_generation: pack.pack_generation(),
                generation: pack.generation(),
                generation_digest: pack.generation_digest(),
                pack_payload_digest: pack_record.payload_digest(),
                pack_record_head: pack_record.complete_digest(),
                retired_at_floor: floor,
                leases: tombstones,
                forks: fork_tombstones,
            });
            discarded_joins.extend(candidate_joins);
        }
        Ok((summaries, discarded_joins))
    }
}

pub(super) fn encoded_retired_pack_length(
    summary: &GitRetiredPackSummaryV1,
) -> Result<usize, GitModelError> {
    SUMMARY_HEADER_BYTES
        .checked_add(
            summary
                .leases
                .len()
                .checked_mul(TOMBSTONE_BYTES)
                .ok_or(GitModelError::InvalidModel)?,
        )
        .and_then(|length| length.checked_add(summary.forks.len().checked_mul(TOMBSTONE_BYTES)?))
        .ok_or(GitModelError::InvalidModel)
}

pub(super) fn encode_retired_pack(
    bytes: &mut Vec<u8>,
    summary: &GitRetiredPackSummaryV1,
) -> Result<(), GitModelError> {
    summary.validate(summary.retired_at_floor)?;
    let lease_count =
        u32::try_from(summary.leases.len()).map_err(|_| GitModelError::InvalidModel)?;
    let fork_count = u32::try_from(summary.forks.len()).map_err(|_| GitModelError::InvalidModel)?;
    bytes.extend_from_slice(summary.project.as_bytes());
    bytes.extend_from_slice(summary.repository.as_bytes());
    bytes.extend_from_slice(summary.pack_generation.as_bytes());
    bytes.extend_from_slice(&summary.generation.get().to_be_bytes());
    bytes.extend_from_slice(summary.generation_digest.digest().as_bytes());
    bytes.extend_from_slice(summary.pack_payload_digest.as_bytes());
    bytes.extend_from_slice(summary.pack_record_head.as_bytes());
    bytes.extend_from_slice(&summary.retired_at_floor.get().to_be_bytes());
    bytes.extend_from_slice(&lease_count.to_be_bytes());
    bytes.extend_from_slice(&fork_count.to_be_bytes());
    for lease in &summary.leases {
        bytes.extend_from_slice(lease.lease.as_bytes());
        bytes.extend_from_slice(&lease.revision.get().to_be_bytes());
        bytes.push(lease.outcome as u8);
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(lease.payload_digest.as_bytes());
        bytes.extend_from_slice(lease.record_head.as_bytes());
    }
    for fork in &summary.forks {
        bytes.extend_from_slice(fork.target.as_bytes());
        bytes.extend_from_slice(&fork.revision.get().to_be_bytes());
        bytes.push(fork.outcome as u8);
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(fork.payload_digest.as_bytes());
        bytes.extend_from_slice(fork.record_head.as_bytes());
    }
    Ok(())
}

pub(super) fn decode_retired_pack(
    encoded: &[u8],
    floor: Revision,
) -> Result<GitRetiredPackSummaryV1, GitModelError> {
    let (lease_count, preflight_fork_count) = preflight_retired_pack(encoded)?;
    let mut bytes = encoded;
    let project = ProjectId::from_bytes(take(&mut bytes)?);
    let repository = ResourceId::from_bytes(take(&mut bytes)?);
    let pack_generation = ResourceId::from_bytes(take(&mut bytes)?);
    let generation = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let generation_digest =
        GitPackGenerationDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?;
    let pack_payload_digest = ObjectDigest::from_bytes(take(&mut bytes)?);
    let pack_record_head = ObjectDigest::from_bytes(take(&mut bytes)?);
    let retired_at_floor = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let encoded_lease_count = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
        .map_err(|_| GitModelError::CorruptEncoding)?;
    let fork_count = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
        .map_err(|_| GitModelError::CorruptEncoding)?;
    if encoded_lease_count != lease_count || fork_count != preflight_fork_count {
        return Err(GitModelError::CorruptEncoding);
    }
    let mut leases = Vec::new();
    leases
        .try_reserve_exact(lease_count)
        .map_err(|_| GitModelError::Allocation)?;
    for _ in 0..lease_count {
        let lease = ResourceId::from_bytes(take(&mut bytes)?);
        let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
        let outcome = match take::<1>(&mut bytes)?[0] {
            2 => GitPackLeaseStatusV1::Released,
            3 => GitPackLeaseStatusV1::Expired,
            4 => GitPackLeaseStatusV1::Invalidated,
            _ => return Err(GitModelError::CorruptEncoding),
        };
        if take::<7>(&mut bytes)? != [0; 7] {
            return Err(GitModelError::CorruptEncoding);
        }
        leases.push(GitTerminalLeaseTombstoneV1 {
            lease,
            revision,
            outcome,
            payload_digest: ObjectDigest::from_bytes(take(&mut bytes)?),
            record_head: ObjectDigest::from_bytes(take(&mut bytes)?),
        });
    }
    let mut forks = Vec::new();
    forks
        .try_reserve_exact(fork_count)
        .map_err(|_| GitModelError::Allocation)?;
    for _ in 0..fork_count {
        let target = ResourceId::from_bytes(take(&mut bytes)?);
        let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
        let outcome = match take::<1>(&mut bytes)?[0] {
            3 => GitCheapForkStatusV1::Converted,
            4 => GitCheapForkStatusV1::Tombstoned,
            _ => return Err(GitModelError::CorruptEncoding),
        };
        if take::<7>(&mut bytes)? != [0; 7] {
            return Err(GitModelError::CorruptEncoding);
        }
        forks.push(GitTerminalForkTombstoneV1 {
            target,
            revision,
            outcome,
            payload_digest: ObjectDigest::from_bytes(take(&mut bytes)?),
            record_head: ObjectDigest::from_bytes(take(&mut bytes)?),
        });
    }
    if !bytes.is_empty() {
        return Err(GitModelError::CorruptEncoding);
    }
    let summary = GitRetiredPackSummaryV1 {
        project,
        repository,
        pack_generation,
        generation,
        generation_digest,
        pack_payload_digest,
        pack_record_head,
        retired_at_floor,
        leases,
        forks,
    };
    summary
        .validate(floor)
        .map_err(|_| GitModelError::CorruptEncoding)?;
    Ok(summary)
}

pub(super) fn preflight_retired_pack(encoded: &[u8]) -> Result<(usize, usize), GitModelError> {
    if encoded.len() < SUMMARY_HEADER_BYTES {
        return Err(GitModelError::CorruptEncoding);
    }
    let count_offset = SUMMARY_HEADER_BYTES - 8;
    let lease_count = usize::try_from(u32::from_be_bytes(
        encoded[count_offset..count_offset + 4]
            .try_into()
            .map_err(|_| GitModelError::CorruptEncoding)?,
    ))
    .map_err(|_| GitModelError::CorruptEncoding)?;
    let fork_count = usize::try_from(u32::from_be_bytes(
        encoded[count_offset + 4..SUMMARY_HEADER_BYTES]
            .try_into()
            .map_err(|_| GitModelError::CorruptEncoding)?,
    ))
    .map_err(|_| GitModelError::CorruptEncoding)?;
    let expected = SUMMARY_HEADER_BYTES
        .checked_add(
            lease_count
                .checked_add(fork_count)
                .ok_or(GitModelError::CorruptEncoding)?
                .checked_mul(TOMBSTONE_BYTES)
                .ok_or(GitModelError::CorruptEncoding)?,
        )
        .ok_or(GitModelError::CorruptEncoding)?;
    if lease_count > MAXIMUM_GIT_TERMINAL_LEASE_TOMBSTONES
        || fork_count > super::MAXIMUM_GIT_HISTORY_RECORDS
        || encoded.len() != expected
    {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok((lease_count, fork_count))
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], GitModelError> {
    if bytes.len() < N {
        return Err(GitModelError::CorruptEncoding);
    }
    let (head, tail) = bytes.split_at(N);
    *bytes = tail;
    head.try_into().map_err(|_| GitModelError::CorruptEncoding)
}
