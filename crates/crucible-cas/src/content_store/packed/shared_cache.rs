//! Reclaimable service-owned rows with an explicitly paid selected-key index.
//!
//! A B-tree supplies logarithmic lookup and removal. Its values form an LRU
//! using scalar neighbor keys, so a hit allocates nothing. Directory credit
//! survives individual removals until the entire actual B-tree closes; row
//! credit returns only after its Vec closes. No node retains read authority.

use super::read_view::manifest::{Manifest, ManifestCopy};
use super::*;
use crate::content_store::checked_reader;
use crate::owned_decode::{DecodeBudget, btree_entry_bytes};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Mutex, MutexGuard, TryLockError};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    configuration: [u8; 32],
    generation: [u8; 32],
    pack: PackId,
}

struct Rows<Credit> {
    manifest: Option<Manifest>,
    previous: Option<Key>,
    next: Option<Key>,
    bytes: u64,
    // Only the Vec and row-loan controls are funded here. Directory credit
    // separately covers this value's inline extent in the B-tree allocation.
    _credit: Credit,
}

impl<Credit> Drop for Rows<Credit> {
    fn drop(&mut self) {
        drop(self.manifest.take());
    }
}

struct DirectoryCredit<Credit> {
    next: Option<DirectoryOwner<Credit>>,
}

struct DirectoryOwner<Credit> {
    body: Option<Box<DirectoryCredit<Credit>>>,
    _credit: Credit,
}

impl<Credit> DirectoryOwner<Credit> {
    fn body_mut(&mut self) -> &mut DirectoryCredit<Credit> {
        match &mut self.body {
            Some(body) => body,
            None => unreachable!("only a dropping directory credit has no body"),
        }
    }
}

impl<Credit> Drop for DirectoryOwner<Credit> {
    fn drop(&mut self) {
        drop(self.body.take());
    }
}

struct State<Credit> {
    entries: BTreeMap<Key, Rows<Credit>>,
    first: Option<Key>,
    last: Option<Key>,
    directory_credits: Option<DirectoryOwner<Credit>>,
    rows: u64,
    directory: u64,
}

impl<Credit> State<Credit> {
    fn touch(&mut self, key: Key) -> Result<(), StoreError> {
        if self.last == Some(key) {
            return Ok(());
        }
        let entry = self.entries.get(&key).ok_or(StoreError::Unauthorized)?;
        let previous = entry.previous;
        let next = entry.next;
        self.unlink(previous, next)?;
        if let Some(last) = self.last {
            self.entries
                .get_mut(&last)
                .ok_or(StoreError::Unauthorized)?
                .next = Some(key);
        } else {
            self.first = Some(key);
        }
        let entry = self.entries.get_mut(&key).ok_or(StoreError::Unauthorized)?;
        entry.previous = self.last;
        entry.next = None;
        self.last = Some(key);
        Ok(())
    }

    fn unlink(&mut self, previous: Option<Key>, next: Option<Key>) -> Result<(), StoreError> {
        if let Some(previous) = previous {
            self.entries
                .get_mut(&previous)
                .ok_or(StoreError::Unauthorized)?
                .next = next;
        } else {
            self.first = next;
        }
        if let Some(next) = next {
            self.entries
                .get_mut(&next)
                .ok_or(StoreError::Unauthorized)?
                .previous = previous;
        } else {
            self.last = previous;
        }
        Ok(())
    }

    fn evict(&mut self) -> Result<u64, StoreError> {
        let Some(first) = self.first else {
            return Ok(0);
        };
        let rows = self
            .entries
            .remove(&first)
            .ok_or(StoreError::Unauthorized)?;
        self.unlink(rows.previous, rows.next)?;
        let bytes = rows.bytes;
        drop(rows);
        self.rows = self
            .rows
            .checked_sub(bytes)
            .ok_or(StoreError::Unauthorized)?;
        Ok(bytes)
    }

    fn clear(&mut self) -> u64 {
        let freed = self.rows + self.directory;
        // The map may retain B-tree nodes after individual removals. Destroy
        // the real index before releasing any of its directory loans.
        drop(std::mem::take(&mut self.entries));
        self.first = None;
        self.last = None;
        while let Some(mut owner) = self.directory_credits.take() {
            self.directory_credits = owner.body_mut().next.take();
            drop(owner);
        }
        self.rows = 0;
        self.directory = 0;
        freed
    }
}

impl<Credit> Drop for State<Credit> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Retains one finite, reclaimable metadata budget across a physical service.
///
/// The provider admits each actual index/row allocation through its existing
/// paired accounts. `Credit` must release only bookkeeping and must not retain
/// this cache or call arbitrary application code. The containing service pays
/// this inline control and destroys it before releasing its original accounts.
pub struct PackedManifestCache<Credit> {
    maximum_bytes: u64,
    credit_bytes: u64,
    // Admissions increment under state; physical cleanup only decrements.
    pending_rows: AtomicU64,
    pending_directory: AtomicU64,
    state: Mutex<State<Credit>>,
}

impl<Credit> std::fmt::Debug for PackedManifestCache<Credit> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PackedManifestCache")
            .field("maximum_bytes", &self.maximum_bytes)
            .finish_non_exhaustive()
    }
}

impl<Credit> PackedManifestCache<Credit> {
    /// Creates an empty control with a finite retention ceiling.
    ///
    /// `credit_bytes` is the provider's exact additional loan-control geometry,
    /// not credit. No index or row allocation occurs here. A zero or sub-minimum
    /// ceiling selects the ordinary single-manifest path before admission.
    pub const fn new(maximum_bytes: u64, credit_bytes: u64) -> Self {
        Self {
            maximum_bytes,
            credit_bytes,
            pending_rows: AtomicU64::new(0),
            pending_directory: AtomicU64::new(0),
            state: Mutex::new(State {
                entries: BTreeMap::new(),
                first: None,
                last: None,
                directory_credits: None,
                rows: 0,
                directory: 0,
            }),
        }
    }

    /// Destroys retained rows and their real index before reporting refunds.
    ///
    /// Returns `None` on brief mutex contention. Pending fills remain charged
    /// and cannot be reclaimed until their actual bodies return. The caller
    /// may wait only under its existing operation, without a new clock.
    ///
    /// # Errors
    /// Refuses poisoned cache accounting.
    pub fn reclaim(&self, requested: u64) -> Result<Option<u64>, StoreError> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Poisoned(_)) => return Err(StoreError::Unauthorized),
        };
        // Clearing the finite index also makes its conservative directory
        // credits physically refundable. A zero request changes no retention.
        Ok(Some(if requested == 0 { 0 } else { state.clear() }))
    }

    fn directory_bytes(&self) -> Result<u64, StoreError> {
        btree_entry_bytes::<Key, Rows<Credit>>()
            .map_err(|source| StoreError::DecodeAdmission {
                source,
                custody: None,
            })?
            .checked_add(std::mem::size_of::<DirectoryCredit<Credit>>() as u64)
            .and_then(|bytes| bytes.checked_add(self.credit_bytes))
            .ok_or(StoreError::Quota)
    }

    fn retention_is_proportionate(&self, rows: usize) -> Result<bool, StoreError> {
        let index_payload = std::mem::size_of::<Key>()
            .checked_add(std::mem::size_of::<Rows<Credit>>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<DirectoryCredit<Credit>>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| self.credit_bytes.checked_mul(2)?.checked_add(bytes))
            .ok_or(StoreError::Quota)?;
        let row_payload = (rows as u64)
            .checked_mul(std::mem::size_of::<PackManifestEntry>() as u64)
            .ok_or(StoreError::Quota)?;

        // Avoid retaining an index payload larger than its actual row vector.
        // Smaller manifests remain under the current Original's normal loader.
        // This is selection before admission, never recovery from a refusal.
        Ok(row_payload >= index_payload)
    }

    fn row_bytes(&self, rows: usize) -> Result<u64, StoreError> {
        (rows as u64)
            .checked_mul(std::mem::size_of::<PackManifestEntry>() as u64)
            .and_then(|bytes| bytes.checked_add(self.credit_bytes))
            .ok_or(StoreError::Quota)
    }

    fn lock<'cache>(
        &'cache self,
        read: &mut PackedManifestRead<'_>,
    ) -> Result<MutexGuard<'cache, State<Credit>>, StoreError> {
        loop {
            read.check()?;
            match self.state.try_lock() {
                Ok(state) => return Ok(state),
                Err(TryLockError::WouldBlock) => read.wait()?,
                Err(TryLockError::Poisoned(_)) => return Err(StoreError::Unauthorized),
            }
        }
    }
}

struct PendingFill<'cache, Credit> {
    cache: &'cache PackedManifestCache<Credit>,
    rows: u64,
    directory: u64,
    active: bool,
}

impl<Credit> Drop for PendingFill<'_, Credit> {
    fn drop(&mut self) {
        if self.active {
            // Fill locals close their actual bodies and leases first. Returning
            // this nominal lane must not wait for another thread's cache lock.
            // Only serialized admissions increment; cleanup only subtracts its
            // own already-reserved amounts, with no CAS/retry or renewed clock.
            self.cache
                .pending_rows
                .fetch_sub(self.rows, AtomicOrdering::AcqRel);
            self.cache
                .pending_directory
                .fetch_sub(self.directory, AtomicOrdering::AcqRel);
        }
    }
}

/// Borrows one genuine checked Packed read; callers cannot fabricate its fields.
///
/// The request retains no cache alias and lends no rows to its caller. Every
/// callback and filesystem operation runs outside the cache mutex. Metadata
/// reuse does not replace the selected object's full ContentId/schema/EOF check.
pub struct PackedManifestRead<'read> {
    file: &'read File,
    backend: &'read PackedBlobBackend,
    original: &'read DecodeBudget,
    id: ContentId,
    entry: IndexEntry,
    generation: [u8; 32],
    boundary: &'read mut dyn FnMut() -> Result<(), StoreError>,
    complete: bool,
    #[cfg(test)]
    authenticated: bool,
    ordinary: Option<Manifest>,
}

impl<'read> PackedManifestRead<'read> {
    pub(super) fn new(
        file: &'read File,
        backend: &'read PackedBlobBackend,
        original: &'read DecodeBudget,
        id: ContentId,
        entry: IndexEntry,
        generation: [u8; 32],
        boundary: &'read mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Self {
        Self {
            file,
            backend,
            original,
            id,
            entry,
            generation,
            boundary,
            complete: false,
            #[cfg(test)]
            authenticated: false,
            ordinary: None,
        }
    }

    fn check(&mut self) -> Result<(), StoreError> {
        checked_reader::check(self.original, self.boundary)
    }

    fn wait(&mut self) -> Result<(), StoreError> {
        self.check()?;
        // Same polling slice as the existing nonblocking Packed file locks.
        std::thread::sleep(std::time::Duration::from_millis(1));
        self.check()
    }

    fn complete_copy(&mut self, copy: ManifestCopy) -> Result<(), StoreError> {
        let manifest = copy.finish()?;
        manifest.verify(self.file, self.original, self.id, self.entry, self.boundary)?;
        self.ordinary = Some(manifest);
        self.complete = true;
        Ok(())
    }

    /// Executes the existing original-paid single-manifest read.
    ///
    /// # Errors
    /// Refuses request reuse or the unchanged integrity/resource/original checks.
    pub fn without_retention(&mut self) -> Result<(), StoreError> {
        if self.complete {
            return Err(StoreError::Incompatible);
        }
        let count = Manifest::row_count(self.file, self.backend, self.original, self.boundary)?;
        self.without_retention_with_count(count)
    }

    fn without_retention_with_count(&mut self, count: usize) -> Result<(), StoreError> {
        self.ordinary = Some(Manifest::load_with_count(
            self.file,
            self.backend,
            self.original,
            self.id,
            self.entry,
            self.boundary,
            count,
        )?);
        #[cfg(test)]
        {
            self.authenticated = true;
        }
        self.complete = true;
        Ok(())
    }

    /// Uses the provider's shared cache and real before-allocation admission.
    ///
    /// Two calls to `reserve` pay the exact rows and index separately. Each
    /// provider adds its declared loan-control bytes in that same account.
    /// Its wait paths must poll the lent SAME request boundary as well as its
    /// existing service guard; the boundary creates no new Original or clock.
    /// Credits must not retain the service/cache itself. No Original or row
    /// reference escapes into cached metadata. The Original prepays an active
    /// copy outside the cache lock; copying under that lock neither allocates
    /// nor invokes a boundary. Later same-pack reads use that independent copy.
    /// Tiny manifests whose row vector cannot cover one actual index payload use
    /// the Original-paid path before any shared admission or lock.
    ///
    /// # Errors
    /// Refuses reuse, original cancellation, corrupt metadata, poisoned state,
    /// admission/allocation failure, or checked arithmetic overflow.
    pub fn retain_in<Credit>(
        &mut self,
        cache: &PackedManifestCache<Credit>,
        mut reserve: impl FnMut(
            u64,
            &mut dyn FnMut() -> Result<(), StoreError>,
        ) -> Result<Credit, StoreError>,
    ) -> Result<(), StoreError> {
        if self.complete {
            return Err(StoreError::Incompatible);
        }
        let directory_bytes = cache.directory_bytes()?;
        let maximum_rows = cache.row_bytes(MAX_PACK_ENTRIES)?;
        if directory_bytes
            .checked_add(maximum_rows)
            .is_none_or(|bytes| bytes > cache.maximum_bytes)
        {
            return self.without_retention();
        }
        let count = Manifest::row_count(self.file, self.backend, self.original, self.boundary)?;
        if !cache.retention_is_proportionate(count)? {
            return self.without_retention_with_count(count);
        }
        let row_bytes = cache.row_bytes(count)?;
        self.check()?;
        // Original admission may reclaim service metadata, so both its grant
        // and Vec allocation must finish before borrowing the cache state.
        let mut active_copy = Manifest::prepare_copy(self.original, count, self.boundary)?;
        let key = Key {
            configuration: self.backend.configuration,
            generation: self.generation,
            pack: self.entry.pack,
        };

        loop {
            let mut state = cache.lock(self)?;
            if let Some(rows) = state.entries.get(&key) {
                let manifest = rows.manifest.as_ref().ok_or(StoreError::Unauthorized)?;
                manifest.verify_selection(self.id, self.entry)?;
                active_copy.copy_from(manifest, self.id)?;
                state.touch(key)?;
                drop(state);
                return self.complete_copy(active_copy);
            }
            let pending_rows = cache.pending_rows.load(AtomicOrdering::Acquire);
            let pending_directory = cache.pending_directory.load(AtomicOrdering::Acquire);
            // Rows, conservative directory grants and pending fills share one
            // ceiling. Retired index nodes remain charged until the actual map
            // closes; a separate directory fraction would evict useful rows
            // even when their entire paid working set fits this same ceiling.
            while state
                .rows
                .checked_add(state.directory)
                .and_then(|bytes| bytes.checked_add(pending_rows))
                .and_then(|bytes| bytes.checked_add(pending_directory))
                .and_then(|bytes| bytes.checked_add(row_bytes))
                .and_then(|bytes| bytes.checked_add(directory_bytes))
                .is_none_or(|bytes| bytes > cache.maximum_bytes)
                && state.first.is_some()
            {
                state.evict()?;
            }
            if state.first.is_none()
                && state
                    .directory
                    .checked_add(pending_rows)
                    .and_then(|bytes| bytes.checked_add(pending_directory))
                    .and_then(|bytes| bytes.checked_add(row_bytes))
                    .and_then(|bytes| bytes.checked_add(directory_bytes))
                    .is_none_or(|bytes| bytes > cache.maximum_bytes)
            {
                state.clear();
            }
            if pending_rows
                .checked_add(pending_directory)
                .and_then(|bytes| bytes.checked_add(row_bytes))
                .and_then(|bytes| bytes.checked_add(directory_bytes))
                .is_none_or(|bytes| bytes > cache.maximum_bytes)
            {
                drop(state);
                self.wait()?;
                continue;
            }
            cache
                .pending_rows
                .fetch_add(row_bytes, AtomicOrdering::AcqRel);
            cache
                .pending_directory
                .fetch_add(directory_bytes, AtomicOrdering::AcqRel);
            drop(state);
            break;
        }

        let mut pending = PendingFill {
            cache,
            rows: row_bytes,
            directory: directory_bytes,
            active: true,
        };
        self.check()?;
        let directory_credit = reserve(
            directory_bytes
                .checked_sub(cache.credit_bytes)
                .ok_or(StoreError::Quota)?,
            &mut || self.check(),
        )?;
        self.check()?;
        let row_credit = reserve(
            row_bytes
                .checked_sub(cache.credit_bytes)
                .ok_or(StoreError::Quota)?,
            &mut || self.check(),
        )?;
        self.check()?;
        let manifest = Manifest::load_shared(
            self.file,
            self.backend,
            self.original,
            self.id,
            self.entry,
            self.boundary,
            count,
        )?;
        #[cfg(test)]
        {
            self.authenticated = true;
        }
        // Authentication uses the actual image after resource admission:
        // load_shared checks its paid row count before allocation, then the
        // complete manifest identity and before/after file stamps. Publication
        // below still checks this authenticated stamp after releasing the lock.
        let stamp = manifest.stamp;
        active_copy.copy_from(&manifest, self.id)?;
        self.check()?;
        let mut rows = Rows {
            manifest: Some(manifest),
            previous: None,
            next: None,
            bytes: row_bytes,
            _credit: row_credit,
        };
        let mut directory = DirectoryOwner {
            body: Some(Box::new(DirectoryCredit { next: None })),
            _credit: directory_credit,
        };
        let mut state = cache.lock(self)?;
        // Concurrent fills may authenticate the same key. Do not retain a
        // duplicate; its arrays and real loans close before its lane returns.
        if let Some(existing) = state.entries.get(&key) {
            let existing = existing.manifest.as_ref().ok_or(StoreError::Unauthorized)?;
            if existing.stamp != stamp {
                return Err(StoreError::Corrupt { id: self.id });
            }
            existing.verify_selection(self.id, self.entry)?;
            state.touch(key)?;
            drop(state);
            drop(rows);
            drop(directory);
            drop(pending);
            return self.complete_copy(active_copy);
        }
        let retained_rows = state.rows.checked_add(row_bytes).ok_or(StoreError::Quota)?;
        let retained_directory = state
            .directory
            .checked_add(directory_bytes)
            .ok_or(StoreError::Quota)?;
        rows.previous = state.last;
        if let Some(last) = state.last {
            state
                .entries
                .get_mut(&last)
                .ok_or(StoreError::Unauthorized)?
                .next = Some(key);
        } else {
            state.first = Some(key);
        }
        state.last = Some(key);
        state.entries.insert(key, rows);
        directory.body_mut().next = state.directory_credits.take();
        state.directory_credits = Some(directory);
        state.rows = retained_rows;
        state.directory = retained_directory;
        cache
            .pending_rows
            .fetch_sub(row_bytes, AtomicOrdering::AcqRel);
        cache
            .pending_directory
            .fetch_sub(directory_bytes, AtomicOrdering::AcqRel);
        pending.active = false;
        drop(state);
        self.complete_copy(active_copy)
    }

    #[cfg(test)]
    pub(super) fn authenticated(&self) -> bool {
        self.authenticated
    }

    pub(super) fn finish(self) -> Result<Option<Manifest>, StoreError> {
        if self.complete {
            Ok(self.ordinary)
        } else {
            Err(StoreError::Unsupported {
                capability: "packed-manifest-request-not-completed",
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_cleanup_never_waits_for_a_held_cache_mutex() {
        // This accounting-only control constructs no request, rows or credit.
        let cache = PackedManifestCache::<()>::new(1024, 0);
        cache.pending_rows.store(48, AtomicOrdering::Release);
        cache.pending_directory.store(96, AtomicOrdering::Release);
        let token = PendingFill {
            cache: &cache,
            rows: 48,
            directory: 96,
            active: true,
        };
        let held = cache.state.lock().unwrap();
        drop(token);
        assert_eq!(cache.pending_rows.load(AtomicOrdering::Acquire), 0);
        assert_eq!(cache.pending_directory.load(AtomicOrdering::Acquire), 0);
        drop(held);
    }
}
