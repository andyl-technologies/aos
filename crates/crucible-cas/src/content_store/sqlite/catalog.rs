//! Bounded rollback-journal catalog staging under original operational authority.
//!
//! Private catalogs use DELETE journals and FULL durability. Writer staging and
//! read chunks have separate process-wide gates; waits repeatedly check the same
//! original operation rather than restarting its deadline.

use std::cell::Cell;
use std::sync::{Mutex, MutexGuard, TryLockError};

#[cfg(test)]
use std::sync::Arc;

use crate::content_store::{ContentId, PlacementReceipt, PutReceipt, StoreError};

pub(super) const MAX_BACKEND_NAME_BYTES: usize = 512;

static WRITE_STAGING: Mutex<()> = Mutex::new(());
static READ_STAGING: Mutex<()> = Mutex::new(());

thread_local! {
    static WRITE_HELD: Cell<bool> = const { Cell::new(false) };
}

// The original mutex remains the sole staging fence. This thread-local flag
// rejects only its impossible same-thread reacquisition, before waiting.
pub(super) struct WriteStagingGuard {
    guard: Option<MutexGuard<'static, ()>>,
}

impl Drop for WriteStagingGuard {
    fn drop(&mut self) {
        drop(self.guard.take());
        WRITE_HELD.set(false);
    }
}

pub(super) fn write_available() -> Result<(), StoreError> {
    if WRITE_HELD.get() {
        Err(StoreError::Unsupported {
            capability: "paired-sql-inventory-fences",
        })
    } else {
        Ok(())
    }
}

fn own_write(guard: MutexGuard<'static, ()>) -> WriteStagingGuard {
    WRITE_HELD.set(true);
    WriteStagingGuard { guard: Some(guard) }
}

/// Selects the original operational budget for a private catalog operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqliteCatalogOperationKind {
    /// An authenticated source chunk or presence check.
    Read,
    /// A durable object mutation or administrative inventory fence.
    Write,
}

/// Owns one original-start, cancellation-aware catalog operation.
pub trait SqliteCatalogOperation: Send {
    /// Checks the retained original budget and cancellation state.
    ///
    /// # Errors
    /// Returns the typed operational failure when this scope loses authority.
    fn check(&self) -> Result<(), StoreError>;

    /// Completes the original scope before acknowledging its result.
    ///
    /// # Errors
    /// Refuses completion after cancellation or deadline expiration.
    fn complete(self: Box<Self>) -> Result<(), StoreError>;
}

/// Creates genuinely owned scopes for private catalog I/O and staging waits.
pub trait SqliteCatalogSupervisor: Send + Sync {
    /// Retains admitted resident memory until the returned allocation loan drops.
    ///
    /// Source and reader loans are independent of staging and SQLite's shared
    /// allocator limit. The owner additionally charges its own receipt layout.
    ///
    /// # Errors
    /// Refuses exhausted resident entitlement or unavailable ownership.
    fn reserve_resident_bytes(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError>;

    /// Begins an original-start scope in the selected live operation class.
    ///
    /// # Errors
    /// Refuses missing ownership, expired budgets, cancellation or admission.
    fn begin(
        &self,
        kind: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError>;
}

/// Bounds process-wide private catalog source and publication staging.
///
/// The gate permits one 4 MiB authenticated write candidate and one 64 KiB
/// read chunk. Batch tuple storage is charged using its actual Rust layout.
/// SQLite allocator memory and retained backend metadata are separate.
#[must_use]
pub const fn minimum_sqlite_catalog_staging_bytes() -> u64 {
    super::MAX_BATCH_BYTES
        + super::MAX_CHUNK_BYTES as u64
        + (super::MAX_BATCH_OBJECTS
            * (std::mem::size_of::<(ContentId, Vec<u8>)>()
                + std::mem::size_of::<PutReceipt>()
                + std::mem::size_of::<PlacementReceipt>()
                + 2 * MAX_BACKEND_NAME_BYTES)) as u64
}

pub(super) fn write_gate(
    operation: &dyn SqliteCatalogOperation,
) -> Result<WriteStagingGuard, StoreError> {
    write_gate_with_boundary(&mut || operation.check())
}

pub(super) fn write_gate_with_boundary(
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<WriteStagingGuard, StoreError> {
    loop {
        write_available()?;
        boundary()?;
        write_available()?;
        match WRITE_STAGING.try_lock() {
            Ok(guard) => {
                // Publish ownership before invoking the terminal callback;
                // callback reentry must not wait on this thread's own mutex.
                let guard = own_write(guard);
                boundary()?;
                return Ok(guard);
            }
            Err(TryLockError::WouldBlock) => std::thread::yield_now(),
            Err(TryLockError::Poisoned(_)) => {
                return Err(StoreError::Poisoned {
                    operation: "lock-private-sqlite-staging",
                });
            }
        }
    }
}

pub(super) fn read_gate_with_boundary(
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<MutexGuard<'static, ()>, StoreError> {
    acquire_with_boundary(&READ_STAGING, boundary)
}

fn acquire_with_boundary(
    gate: &'static Mutex<()>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<MutexGuard<'static, ()>, StoreError> {
    loop {
        boundary()?;
        match gate.try_lock() {
            Ok(guard) => {
                boundary()?;
                return Ok(guard);
            }
            Err(TryLockError::WouldBlock) => std::thread::yield_now(),
            Err(TryLockError::Poisoned(_)) => {
                return Err(StoreError::Poisoned {
                    operation: "lock-private-sqlite-staging",
                });
            }
        }
    }
}

pub(super) fn read_gate(
    operation: &dyn SqliteCatalogOperation,
) -> Result<MutexGuard<'static, ()>, StoreError> {
    acquire(&READ_STAGING, operation)
}

fn acquire(
    gate: &'static Mutex<()>,
    operation: &dyn SqliteCatalogOperation,
) -> Result<MutexGuard<'static, ()>, StoreError> {
    loop {
        operation.check()?;
        match gate.try_lock() {
            Ok(guard) => {
                operation.check()?;
                return Ok(guard);
            }
            Err(TryLockError::WouldBlock) => std::thread::yield_now(),
            Err(TryLockError::Poisoned(_)) => {
                return Err(StoreError::Poisoned {
                    operation: "lock-private-sqlite-staging",
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use super::*;

    struct CancelledOperation {
        checks: AtomicUsize,
        cancel_at: usize,
    }

    impl SqliteCatalogOperation for CancelledOperation {
        fn check(&self) -> Result<(), StoreError> {
            let count = self.checks.fetch_add(1, Ordering::Relaxed) + 1;
            if count >= self.cancel_at {
                return Err(StoreError::Supervision {
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "original catalog operation cancelled",
                    )),
                });
            }
            Ok(())
        }

        fn complete(self: Box<Self>) -> Result<(), StoreError> {
            self.check()
        }
    }

    #[test]
    fn held_staging_gate_checks_the_original_operation_until_cancellation() {
        static HELD_GATE: Mutex<()> = Mutex::new(());
        let retained = HELD_GATE
            .lock()
            .unwrap_or_else(|error| panic!("held catalog staging fixture: {error}"));
        let original = CancelledOperation {
            checks: AtomicUsize::new(0),
            cancel_at: 4,
        };

        let error = acquire(&HELD_GATE, &original)
            .err()
            .unwrap_or_else(|| panic!("cancelled catalog operation acquired held gate"));

        assert!(matches!(error, StoreError::Supervision { .. }));
        assert_eq!(original.checks.load(Ordering::Relaxed), 4);
        assert!(matches!(
            HELD_GATE.try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        drop(retained);
    }

    #[test]
    fn acquired_staging_gate_rechecks_authority_before_returning_a_loan() {
        static FREE_GATE: Mutex<()> = Mutex::new(());
        let original = CancelledOperation {
            checks: AtomicUsize::new(0),
            cancel_at: 2,
        };

        let error = acquire(&FREE_GATE, &original)
            .err()
            .unwrap_or_else(|| panic!("cancelled catalog operation returned a staging loan"));

        assert!(matches!(error, StoreError::Supervision { .. }));
        assert_eq!(original.checks.load(Ordering::Relaxed), 2);
        assert!(FREE_GATE.try_lock().is_ok());
    }

    struct ResidentBudget {
        used: AtomicU64,
        limit: AtomicU64,
    }

    struct ResidentLoan {
        budget: Arc<ResidentBudget>,
        bytes: u64,
    }

    impl Drop for ResidentLoan {
        fn drop(&mut self) {
            self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }

    struct BoundedSupervisor(Arc<ResidentBudget>);

    impl SqliteCatalogSupervisor for BoundedSupervisor {
        fn reserve_resident_bytes(
            &self,
            bytes: u64,
        ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
            let limit = self.0.limit.load(Ordering::Acquire);
            self.0
                .used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes).filter(|next| *next <= limit)
                })
                .map_err(|_| StoreError::Quota)?;
            Ok(crate::owned_decode::ResourceLoan::new(ResidentLoan {
                budget: self.0.clone(),
                bytes,
            }))
        }

        fn begin(
            &self,
            _kind: SqliteCatalogOperationKind,
        ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
            Ok(Box::new(CancelledOperation {
                checks: AtomicUsize::new(0),
                cancel_at: usize::MAX,
            }))
        }
    }

    struct FixtureQuota(crate::content_store::test_resources::FixtureResourceBudget);

    impl crate::content_store::StorePhysicalQuotaGuard for FixtureQuota {
        fn reserve_resources(
            &self,
            descriptors: u64,
            resident_bytes: u64,
        ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
            self.0.reserve(descriptors, resident_bytes)
        }

        fn verify(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[test]
    fn deferred_source_and_reader_loans_refuse_exhaustion_and_outlive_the_backend() {
        use crate::content_store::{BlobHandle, ObjectKind};

        let root =
            tempfile::tempdir().unwrap_or_else(|error| panic!("resident catalog fixture: {error}"));
        let budget = Arc::new(ResidentBudget {
            used: AtomicU64::new(0),
            limit: AtomicU64::new(u64::MAX),
        });
        let backend = super::super::SqliteBlobBackend::open_with_physical_quota(
            "resident-fixture",
            root.path(),
            Arc::new(FixtureQuota(
                crate::content_store::test_resources::FixtureResourceBudget::new(128, 256 << 20),
            )),
            i64::MAX as u64,
            Arc::new(BoundedSupervisor(budget.clone())),
        )
        .unwrap_or_else(|error| panic!("resident catalog open: {error}"));
        let cached = budget.used.load(Ordering::Acquire);
        let bytes = b"retained reader allocation";
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .unwrap_or_else(|error| panic!("resident catalog put: {error}"));

        let source = backend
            .read(id, None)
            .unwrap_or_else(|error| panic!("resident catalog source: {error}"));
        let with_source = budget.used.load(Ordering::Acquire);
        assert!(with_source > cached);
        budget.limit.store(with_source, Ordering::Release);
        assert!(matches!(backend.read(id, None), Err(StoreError::Quota)));
        assert!(matches!(source.open(), Err(StoreError::Quota)));
        assert_eq!(budget.used.load(Ordering::Acquire), with_source);

        budget.limit.store(u64::MAX, Ordering::Release);
        let reader = source
            .open()
            .unwrap_or_else(|error| panic!("resident catalog reader: {error}"));
        let with_reader = budget.used.load(Ordering::Acquire);
        assert!(with_reader > with_source);
        drop(backend);
        assert_eq!(budget.used.load(Ordering::Acquire), with_reader);
        drop(source);
        let reader_only = budget.used.load(Ordering::Acquire);
        assert!(reader_only > cached);
        assert!(reader_only < with_reader);
        drop(reader);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }
}
