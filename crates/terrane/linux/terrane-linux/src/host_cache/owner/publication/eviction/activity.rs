//! Orders successful verified reads independently of embedded-store progress.
//!
//! The short activity clock serializes promotion order only. It never holds
//! native descriptors, embedded custody or a publisher lock, and performs no IO.

use crate::publisher_local::client::PeerPublishedObject;
use std::{
    collections::BTreeMap,
    io,
    os::unix::fs::MetadataExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use terrane_sdk::host::cache::HostDomainLocation;

/// Records reads of one actual native allocation, shared by all its sources.
pub(in crate::host_cache::owner) struct ReadActivity {
    origin: ReadOrigin,
    clock: Arc<Mutex<u64>>,
    first: AtomicU64,
    latest: AtomicU64,
}

/// Distinguishes physical registrations within reconstructible scheduling state.
///
/// These values confer no native custody or deletion authority. Actual read
/// sources and allocation units independently verify their retained backing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::host_cache::owner) enum ReadOrigin {
    /// Uses this physical executor's original admission sequence.
    Admission(u64),
    /// Uses the authenticated publisher's original retained-inode token.
    Sealed([u8; 32]),
}

impl ReadActivity {
    /// Records a successful verified read without embedded policy or native IO.
    ///
    /// # Errors
    /// Refuses a poisoned activity clock or an exhausted ordering counter.
    pub(in crate::host_cache::owner) fn record(&self) -> io::Result<()> {
        let mut clock = self
            .clock
            .lock()
            .map_err(|_| invalid("read activity poisoned"))?;
        let next = clock
            .checked_add(1)
            .ok_or_else(|| invalid("read activity exhausted"))?;
        if self.first.load(Ordering::Relaxed) == 0 {
            self.first.store(next, Ordering::Relaxed);
        }
        self.latest.store(next, Ordering::Relaxed);
        *clock = next;
        Ok(())
    }
}

/// Groups the actual body and dictionary allocations consumed by one read.
pub(in crate::host_cache::owner) struct ReadActivities(Vec<Arc<ReadActivity>>);

impl ReadActivities {
    /// Records a complete verified read under one bounded activity-clock turn.
    ///
    /// The dictionary participates only after the actual body and dependency
    /// verification succeeds. Clock preflight prevents partially recording a
    /// multi-allocation read if the ordering counter is exhausted.
    ///
    /// # Errors
    /// Refuses empty or mixed-clock custody, a poisoned clock and counter overflow.
    pub(in crate::host_cache::owner) fn record(&self) -> io::Result<()> {
        let first = self
            .0
            .first()
            .ok_or_else(|| invalid("read activity group is empty"))?;
        if self
            .0
            .iter()
            .any(|activity| !Arc::ptr_eq(&activity.clock, &first.clock))
        {
            return Err(invalid("read activity group changed its clock"));
        }
        let mut clock = first
            .clock
            .lock()
            .map_err(|_| invalid("read activity poisoned"))?;
        let count = u64::try_from(self.0.len()).map_err(io::Error::other)?;
        let end = clock
            .checked_add(count)
            .ok_or_else(|| invalid("read activity exhausted"))?;

        let mut next = *clock;
        for activity in &self.0 {
            // The complete interval was checked before any atomic mutation.
            next += 1;
            if activity.first.load(Ordering::Relaxed) == 0 {
                activity.first.store(next, Ordering::Relaxed);
            }
            activity.latest.store(next, Ordering::Relaxed);
        }
        *clock = end;
        Ok(())
    }
}

/// Retains activity only for actual verified native bodies on the physical owner.
#[derive(Default)]
pub(in crate::host_cache::owner) struct Registry {
    clock: Arc<Mutex<u64>>,
    bodies: BTreeMap<(u64, u64), Arc<ReadActivity>>,
}

/// Describes one consistent activity observation without retaining body handles.
pub(super) struct ActivitySnapshot {
    /// Original allocation identity within this process's inspected root.
    pub(super) inode: (u64, u64),
    /// Physical registration that owned the recorded reads of this inode.
    pub(super) origin: ReadOrigin,
    /// First actual read's promotion order, or zero if no read completed.
    pub(super) first: u64,
    /// Latest actual read order at this captured activity-clock cut.
    pub(super) latest: u64,
}

impl Registry {
    /// Captures one consistent read-order cut without holding the clock during allocation.
    ///
    /// # Errors
    /// Refuses unavailable bounded snapshot storage or a poisoned clock.
    pub(super) fn snapshot(&self) -> io::Result<Vec<ActivitySnapshot>> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.bodies.len())
            .map_err(io::Error::other)?;
        let clock = self
            .clock
            .lock()
            .map_err(|_| invalid("read activity poisoned"))?;
        for (inode, activity) in &self.bodies {
            rows.push(ActivitySnapshot {
                inode: *inode,
                origin: activity.origin,
                first: activity.first.load(Ordering::Relaxed),
                latest: activity.latest.load(Ordering::Relaxed),
            });
        }
        drop(clock);
        Ok(rows)
    }

    /// Removes scheduling bookkeeping after the allocation leaves this inventory.
    pub(super) fn remove(&mut self, inode: (u64, u64)) {
        self.bodies.remove(&inode);
    }

    /// Shares one activity record across genuine receipts for the same inode.
    ///
    /// # Errors
    /// Refuses failed native metadata inspection or an exhausted finite registry.
    pub(in crate::host_cache::owner) fn for_body(
        &mut self,
        body: &PeerPublishedObject<HostDomainLocation>,
        limit: usize,
    ) -> io::Result<Arc<ReadActivity>> {
        let metadata = body.handle().metadata()?;
        self.for_inode(
            (metadata.dev(), metadata.ino()),
            ReadOrigin::Sealed(*body.incarnation()),
            limit,
        )
    }

    /// Shares activity through every actual allocation of an admitted read.
    ///
    /// # Errors
    /// Refuses absent original custody or exhausted finite registry storage.
    pub(in crate::host_cache::owner) fn for_admission(
        &mut self,
        source: &crate::host_cache::owner::admission::reads::AdmittedRead,
        limit: usize,
    ) -> io::Result<ReadActivities> {
        self.for_admission_allocations(source.original_allocations(), limit)
    }

    /// Shares scheduling state for both verified original metadata members.
    ///
    /// # Errors
    /// Refuses exhausted finite activity storage.
    pub(in crate::host_cache::owner) fn for_metadata(
        &mut self,
        source: &crate::host_cache::owner::admission::metadata_reads::AdmittedMetadataRead,
        limit: usize,
    ) -> io::Result<ReadActivities> {
        self.for_admission_allocations(source.original_allocations(), limit)
    }

    fn for_admission_allocations(
        &mut self,
        allocations: impl Iterator<Item = ((u64, u64), u64)>,
        limit: usize,
    ) -> io::Result<ReadActivities> {
        let mut activities = Vec::new();
        activities.try_reserve_exact(2).map_err(io::Error::other)?;
        for (inode, order) in allocations {
            let activity = self.for_inode(inode, ReadOrigin::Admission(order), limit)?;
            if !activities.iter().any(|old| Arc::ptr_eq(old, &activity)) {
                activities.push(activity);
            }
        }
        if activities.is_empty() || activities.len() > 2 {
            return Err(invalid(
                "admitted read activity exceeds its bounded closure",
            ));
        }
        Ok(ReadActivities(activities))
    }

    /// Shares one activity record for the actual metadata pack/index unit.
    ///
    /// # Errors
    /// Refuses unavailable native metadata or exhausted finite registry storage.
    pub(in crate::host_cache::owner) fn for_manifest(
        &mut self,
        source: &crate::host_cache::NativeManifestSource,
        order: u64,
        limit: usize,
    ) -> io::Result<Arc<ReadActivity>> {
        let metadata = source.files().0.metadata()?;
        self.for_inode(
            (metadata.dev(), metadata.ino()),
            ReadOrigin::Admission(order),
            limit,
        )
    }

    fn for_inode(
        &mut self,
        key: (u64, u64),
        origin: ReadOrigin,
        limit: usize,
    ) -> io::Result<Arc<ReadActivity>> {
        if let Some(activity) = self.bodies.get(&key)
            && activity.origin == origin
        {
            return Ok(Arc::clone(activity));
        }
        if !self.bodies.contains_key(&key) && self.bodies.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "read activity registry full",
            ));
        }
        let activity = Arc::new(ReadActivity {
            origin,
            clock: Arc::clone(&self.clock),
            first: AtomicU64::new(0),
            latest: AtomicU64::new(0),
        });
        self.bodies.insert(key, Arc::clone(&activity));
        Ok(activity)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, sync::Barrier, thread};

    fn activity(clock: &Arc<Mutex<u64>>) -> Arc<ReadActivity> {
        Arc::new(ReadActivity {
            origin: ReadOrigin::Admission(1),
            clock: Arc::clone(clock),
            first: AtomicU64::new(0),
            latest: AtomicU64::new(0),
        })
    }

    #[test]
    fn reused_inode_starts_fresh_activity_without_changing_other_allocations() -> io::Result<()> {
        let mut registry = Registry::default();
        let old = registry.for_inode((1, 2), ReadOrigin::Admission(1), 2)?;
        let other = registry.for_inode((1, 3), ReadOrigin::Admission(2), 2)?;
        old.record()?;
        other.record()?;

        // Replacement is allowed even at the finite registry limit. Retained
        // old activity can no longer promote the new physical registration.
        let new = registry.for_inode((1, 2), ReadOrigin::Admission(3), 2)?;
        assert!(!Arc::ptr_eq(&old, &new));
        old.record()?;
        let before = registry.snapshot()?;
        let replacement = before
            .iter()
            .find(|row| row.inode == (1, 2))
            .ok_or_else(|| invalid("replacement activity absent"))?;
        assert_eq!(replacement.origin, ReadOrigin::Admission(3));
        assert_eq!(replacement.first, 0);
        assert_eq!(replacement.latest, 0);

        new.record()?;

        assert_eq!(new.first.load(Ordering::Relaxed), 4);
        assert_eq!(new.latest.load(Ordering::Relaxed), 4);
        assert_eq!(other.first.load(Ordering::Relaxed), 2);
        assert_eq!(other.latest.load(Ordering::Relaxed), 2);
        assert_eq!(registry.snapshot()?.len(), 2);
        Ok(())
    }

    #[test]
    fn verified_read_order_keeps_first_promotion_separate_from_later_hits() -> io::Result<()> {
        let clock = Arc::new(Mutex::new(0));
        let first = activity(&clock);
        let second = activity(&clock);

        second.record()?;
        first.record()?;
        second.record()?;

        assert_eq!(second.first.load(Ordering::Relaxed), 1);
        assert_eq!(first.first.load(Ordering::Relaxed), 2);
        assert_eq!(second.latest.load(Ordering::Relaxed), 3);
        assert_eq!(first.latest.load(Ordering::Relaxed), 2);
        Ok(())
    }

    #[test]
    fn verified_read_group_overflow_preserves_body_and_dictionary_activity() -> io::Result<()> {
        let clock = Arc::new(Mutex::new(u64::MAX - 1));
        let body = activity(&clock);
        let dictionary = activity(&clock);
        let group = ReadActivities(vec![Arc::clone(&body), Arc::clone(&dictionary)]);

        assert!(group.record().is_err());

        for member in [&body, &dictionary] {
            assert_eq!(member.first.load(Ordering::Relaxed), 0);
            assert_eq!(member.latest.load(Ordering::Relaxed), 0);
        }
        let mut current = clock.lock().map_err(|_| invalid("test clock poisoned"))?;
        assert_eq!(*current, u64::MAX - 1);
        *current = u64::MAX - 2;
        drop(current);

        group.record()?;
        assert!(group.record().is_err());

        assert_eq!(body.first.load(Ordering::Relaxed), u64::MAX - 1);
        assert_eq!(body.latest.load(Ordering::Relaxed), u64::MAX - 1);
        assert_eq!(dictionary.first.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(dictionary.latest.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(
            *clock.lock().map_err(|_| invalid("test clock poisoned"))?,
            u64::MAX
        );
        Ok(())
    }

    #[test]
    fn concurrent_verified_read_groups_keep_dictionary_hits_in_the_same_clock_cut() -> io::Result<()>
    {
        let clock = Arc::new(Mutex::new(0));
        let dictionary = activity(&clock);
        let start = Arc::new(Barrier::new(8));
        let bodies: Vec<_> = (0..8).map(|_| activity(&clock)).collect();
        let workers: Vec<_> = bodies
            .iter()
            .map(|body| {
                let group = ReadActivities(vec![Arc::clone(body), Arc::clone(&dictionary)]);
                let start = Arc::clone(&start);
                thread::spawn(move || -> io::Result<()> {
                    start.wait();
                    for _ in 0..64 {
                        group.record()?;
                    }
                    Ok(())
                })
            })
            .collect();

        for worker in workers {
            worker
                .join()
                .map_err(|_| invalid("read group worker panicked"))??;
        }

        assert_eq!(
            *clock.lock().map_err(|_| invalid("test clock poisoned"))?,
            1024
        );
        assert_eq!(dictionary.first.load(Ordering::Relaxed), 2);
        assert_eq!(dictionary.latest.load(Ordering::Relaxed), 1024);
        let first: BTreeSet<_> = bodies
            .iter()
            .map(|body| body.first.load(Ordering::Relaxed))
            .collect();
        assert_eq!(first.len(), 8);
        assert!(bodies.iter().all(|body| {
            let first = body.first.load(Ordering::Relaxed);
            let latest = body.latest.load(Ordering::Relaxed);
            first > 0 && first % 2 == 1 && latest % 2 == 1 && first <= latest && latest < 1024
        }));
        Ok(())
    }

    #[test]
    fn concurrent_verified_reads_share_one_order_without_losing_first_hits() -> io::Result<()> {
        let clock = Arc::new(Mutex::new(0));
        let start = Arc::new(Barrier::new(8));
        let activities: Vec<_> = (0..8).map(|_| activity(&clock)).collect();
        let workers: Vec<_> = activities
            .iter()
            .map(|activity| {
                let activity = Arc::clone(activity);
                let start = Arc::clone(&start);
                thread::spawn(move || -> io::Result<()> {
                    start.wait();
                    for _ in 0..64 {
                        activity.record()?;
                    }
                    Ok(())
                })
            })
            .collect();

        for worker in workers {
            worker
                .join()
                .map_err(|_| invalid("activity worker panicked"))??;
        }

        assert_eq!(
            *clock
                .lock()
                .map_err(|_| invalid("activity clock poisoned"))?,
            512
        );
        let first: BTreeSet<_> = activities
            .iter()
            .map(|activity| activity.first.load(Ordering::Relaxed))
            .collect();
        assert_eq!(first.len(), 8);
        assert!(!first.contains(&0));
        assert!(activities.iter().all(|activity| {
            activity.first.load(Ordering::Relaxed) <= activity.latest.load(Ordering::Relaxed)
                && activity.latest.load(Ordering::Relaxed) <= 512
        }));
        Ok(())
    }
}
