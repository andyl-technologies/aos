//! Applies actual read order and durable protection to reconstructible S3-FIFO.

use super::{
    super::invalid,
    activity::{ReadOrigin, Registry},
    graph::Unit,
};
use crate::host_cache::owner::admission::eviction::EncodedAllocation;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    time::Duration,
};
use terrane_sdk::host::cache::{CacheEntry, CachePolicy, PolicyConfig};

/// Describes scheduling data without supplying native retirement authority.
pub(in crate::host_cache::owner) struct Allocation {
    /// Original physical executor admission sequence.
    pub(in crate::host_cache::owner) order: u64,
    /// Inspected device and inode scheduling key.
    pub(in crate::host_cache::owner) key: String,
    /// Actual synchronized allocation, never inferred released bytes.
    pub(in crate::host_cache::owner) allocated: u64,
    /// Current retained custody or unelapsed release grace.
    pub(in crate::host_cache::owner) protected: bool,
    /// Original registration matched against actual read activity.
    pub(in crate::host_cache::owner) origin: ReadOrigin,
}

struct Entry {
    origin: ReadOrigin,
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
        surface: &[super::surface::Unit],
        pending: &BTreeSet<String>,
        activities: &mut Registry,
    ) -> io::Result<()> {
        let mut allocations = units
            .iter()
            .map(|unit| {
                (
                    unit.order,
                    unit.key.as_str(),
                    unit.allocated,
                    unit.protected,
                    ReadOrigin::Sealed(*unit.body.incarnation()),
                )
            })
            .chain(encoded.iter().map(|unit| {
                (
                    unit.order(),
                    unit.key(),
                    unit.allocated(),
                    unit.protected(),
                    ReadOrigin::Admission(unit.order()),
                )
            }))
            .chain(surface.iter().map(|unit| {
                let allocation = &unit.allocation;
                (
                    allocation.order,
                    allocation.key.as_str(),
                    allocation.allocated,
                    allocation.protected,
                    allocation.origin,
                )
            }))
            .collect::<Vec<_>>();
        allocations.sort_unstable_by_key(|(order, _, _, _, _)| *order);

        // A successful complete native census has already refused unknown
        // missing names. Source transfers leave this scheduling inventory, but
        // actual cache retirements must retain their original queue entries
        // through restoration or final acknowledgment. Neither case changes Q.
        let current: BTreeSet<_> = allocations.iter().map(|(_, key, _, _, _)| *key).collect();
        self.entries.retain(|key, _| {
            if current.contains(key.as_str()) || pending.contains(key) {
                return true;
            }
            self.policy.forget_allocation(key);
            false
        });

        for (_, key, allocated, protected, origin) in allocations {
            if self
                .entries
                .get(key)
                .is_some_and(|entry| entry.origin != origin)
            {
                // A reused inode starts in probation with its new admission;
                // clearing a scheduler row neither frees Q nor releases a pin.
                self.policy.forget_allocation(key);
                self.entries.remove(key);
            }
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
                        origin,
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
            // Shared bodies can be selected for extraction. Actual retirement
            // separately refuses them until their residence transfer completes.
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
            let (device, inode) = read.inode;
            let key = format!("{device}:{inode}");
            let Some(entry) = self.entries.get_mut(&key) else {
                // A later native inode reuse must start with fresh activity.
                // Retained old read views may keep their own activity Arc.
                activities.remove(read.inode);
                continue;
            };
            if entry.origin != read.origin {
                activities.remove(read.inode);
                continue;
            }
            if read.first == 0 {
                continue;
            }
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
