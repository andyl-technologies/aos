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
    clock: Arc<Mutex<u64>>,
    first: AtomicU64,
    latest: AtomicU64,
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
                first: activity.first.load(Ordering::Relaxed),
                latest: activity.latest.load(Ordering::Relaxed),
            });
        }
        drop(clock);
        Ok(rows)
    }

    /// Removes bookkeeping after the actual native allocation is durably retired.
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
        let key = (metadata.dev(), metadata.ino());
        if let Some(activity) = self.bodies.get(&key) {
            return Ok(Arc::clone(activity));
        }
        if self.bodies.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "read activity registry full",
            ));
        }
        let activity = Arc::new(ReadActivity {
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
            clock: Arc::clone(clock),
            first: AtomicU64::new(0),
            latest: AtomicU64::new(0),
        })
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
