//! Applies actual read order and durable protection to reconstructible S3-FIFO.

use super::{super::invalid, activity::Registry, graph::Unit};
use crate::host_cache::owner::admission::eviction::EncodedAllocation;
use std::{collections::BTreeMap, io, time::Duration};
use terrane_sdk::host::cache::{CacheEntry, CachePolicy, PolicyConfig};

struct Entry {
    allocated: u64,
    pinned: bool,
    promoted: bool,
    latest: u64,
}

/// Keeps policy decisions separate from actual namespace and quota completion.
pub(super) struct Queue {
    policy: CachePolicy,
    entries: BTreeMap<String, Entry>,
    owner: String,
}

impl Queue {
    /// Starts policy whose protection deadlines come exclusively from durable rows.
    ///
    /// # Errors
    /// Refuses inconsistent configured policy bounds.
    pub(super) fn new(mut config: PolicyConfig, owner: String) -> io::Result<Self> {
        // Native policy already synchronizes release grace and sweeps its
        // original deadline. The reconstructible planner must not add it again.
        config.release_grace = Duration::ZERO;
        Ok(Self {
            policy: CachePolicy::new(config).map_err(io::Error::other)?,
            entries: BTreeMap::new(),
            owner,
        })
    }

    /// Reconciles original allocation order, current durable pins and actual reads.
    ///
    /// # Errors
    /// Refuses changed immutable allocation, exhausted policy storage or read clock.
    pub(super) fn refresh(
        &mut self,
        units: &[Unit],
        encoded: &[EncodedAllocation],
        activities: &Registry,
    ) -> io::Result<()> {
        let mut allocations = units
            .iter()
            .map(|unit| {
                (
                    unit.order,
                    unit.key.as_str(),
                    unit.allocated,
                    unit.protected || !unit.shared_chunks.is_empty(),
                )
            })
            .chain(
                encoded
                    .iter()
                    .map(|unit| (unit.order(), unit.key(), unit.allocated(), unit.protected())),
            )
            .collect::<Vec<_>>();
        allocations.sort_unstable_by_key(|(order, _, _, _)| *order);
        for (_, key, allocated, protected) in allocations {
            if !self.entries.contains_key(key) {
                self.policy
                    .reserve(key.to_owned(), self.owner.clone(), allocated)
                    .map_err(io::Error::other)?;
                self.policy
                    .admit(
                        key,
                        CacheEntry::new(key.to_owned(), allocated, self.owner.clone()),
                    )
                    .map_err(io::Error::other)?;
                self.entries.insert(
                    key.to_owned(),
                    Entry {
                        allocated,
                        pinned: false,
                        promoted: false,
                        latest: 0,
                    },
                );
            }
            let entry = self
                .entries
                .get_mut(key)
                .ok_or_else(|| invalid("native FIFO entry absent"))?;
            if entry.allocated != allocated {
                return Err(invalid("native FIFO immutable allocation changed"));
            }
            // Shared residence must be transferred before physical retirement.
            // Its extraction is a separate prerequisite, never a guessed delete.
            if protected && !entry.pinned {
                self.policy.pin(key).map_err(io::Error::other)?;
            } else if !protected && entry.pinned {
                self.policy
                    .release(key, Duration::ZERO)
                    .map_err(io::Error::other)?;
            }
            entry.pinned = protected;
        }

        let mut reads = activities.snapshot()?;
        reads.sort_unstable_by_key(|read| read.first);
        for read in reads {
            if read.first == 0 {
                continue;
            }
            let (device, inode) = read.inode;
            let key = format!("{device}:{inode}");
            let Some(entry) = self.entries.get_mut(&key) else {
                continue;
            };
            if !entry.promoted || read.latest > entry.latest {
                self.policy.touch(&key);
                entry.promoted = true;
                entry.latest = read.latest;
            }
        }
        Ok(())
    }

    /// Selects bounded candidates against actual complete-project pressure.
    pub(super) fn candidates(&mut self, required: u64) -> Vec<String> {
        self.policy
            .eviction_candidates_to_reclaim(required, Duration::ZERO)
    }

    /// Restores queue membership only after the actual pending name is restored.
    pub(super) fn restored(&mut self, key: &str) {
        self.policy.touch(key);
    }

    /// Removes the allocation unit only after actual final retirement completes.
    ///
    /// # Errors
    /// Refuses a read or pin that cancelled the planned retirement.
    pub(super) fn removed(&mut self, key: &str) -> io::Result<()> {
        self.policy
            .finish_retirement(key)
            .map_err(io::Error::other)?;
        self.entries.remove(key);
        Ok(())
    }
}
