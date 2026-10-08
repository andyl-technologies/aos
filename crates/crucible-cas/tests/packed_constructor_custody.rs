//! Actual managed Packed controls and source/pin credits through System free.
//!
//! The same finite HostServiceAllocator pays all selected loans. This component
//! model does not install project quotas or fund its allocator, graph maps,
//! test infrastructure, incoming errors, or enclosing authority controls.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible_cas::content_store::*;
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};
use crucible_linux_resource::test_support::{
    AllocationTrace, OriginalControlSelection, OriginalControlSlot, OriginalControlSnapshot,
    OriginalControlsOutcome, OriginalStaticCounters, TestAllocationObserver,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;
static SERIAL: Mutex<()> = Mutex::new(());
static TRACE: AllocationTrace<512> = AllocationTrace::new();
static SOURCE_PAID: AtomicU64 = AtomicU64::new(0);

const RESIDENT: u64 = 4 * 1024 * 1024;
const TARGET: u64 = 64 * 1024;

struct Loan {
    _lease: HostServiceLease,
    watched: Option<&'static AtomicU64>,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if let Some(counter) = self.watched {
            counter.store(0, Ordering::SeqCst);
        }
    }
}

struct Quota {
    allocator: HostServiceAllocator,
    source_bytes: AtomicU64,
}

impl StorePhysicalQuotaGuard for Quota {
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(RESIDENT)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        let lease = self
            .allocator
            .reserve_resources(0, descriptors, bytes)
            .map_err(|_| StoreError::Quota)?;
        let watched = if descriptors == 0
            && bytes != 0
            && bytes == self.source_bytes.load(Ordering::SeqCst)
        {
            Some(&SOURCE_PAID)
        } else {
            None
        };
        if let Some(counter) = watched {
            counter.store(bytes, Ordering::SeqCst);
        }
        Ok(ResourceLoan::new(Loan {
            _lease: lease,
            watched,
        }))
    }
}

#[test]
fn packed_source_and_file_pin_keep_one_paid_original_through_last_reader_alias_normal_unwind_and_concurrent()
 {
    let _serial = SERIAL.lock().unwrap();
    for mode in [3, 0, 1, 2] {
        SOURCE_PAID.store(0, Ordering::SeqCst);
        let temp = tempfile::TempDir::new().unwrap();
        let backend = PackedBlobBackend::open("source", temp.path(), TARGET).unwrap();
        let bytes = b"source and actual pin control lifetime";
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .unwrap();
        let quota = Arc::new(Quota {
            allocator: HostServiceAllocator::new(1, 16, RESIDENT).unwrap(),
            source_bytes: AtomicU64::new(0),
        });
        let original = DecodeBudget::for_store(quota.clone()).unwrap();
        let handle = TRACE
            .capture(|| backend.read_with_boundary(&original, id, None, &mut || Ok(())))
            .unwrap()
            .unwrap();
        assert!(!TRACE.overflowed());
        assert_eq!(TRACE.reallocations(), 0);
        let entries: Vec<_> = TRACE.entries().collect();
        let first_extents = [
            entries[entries.len() - 2].bytes(),
            entries[entries.len() - 1].bytes(),
        ];
        let paid = first_extents.iter().sum::<usize>() as u64;
        drop(handle);
        quota.source_bytes.store(paid, Ordering::SeqCst);
        let handle = TRACE
            .capture(|| backend.read_with_boundary(&original, id, None, &mut || Ok(())))
            .unwrap()
            .unwrap();
        let entries: Vec<_> = TRACE.entries().collect();
        assert!(!TRACE.overflowed());
        assert_eq!(TRACE.reallocations(), 0);
        let pin = entries[entries.len() - 2];
        let source = entries[entries.len() - 1];
        assert_eq!([pin.bytes(), source.bytes()], first_extents);
        assert_eq!(SOURCE_PAID.load(Ordering::SeqCst), paid);
        assert!(paid > 0);
        let alias = handle.clone();
        let reader = BlobSource::open_with_boundary(&handle, &original, &mut || Ok(())).unwrap();
        let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
            for (slot, identity) in [
                (OriginalControlSlot::First, source.identity()),
                (OriginalControlSlot::Second, pin.identity()),
            ] {
                session
                    .arm(
                        slot,
                        OriginalControlSelection::Explicit(identity),
                        OriginalStaticCounters::U64(&SOURCE_PAID),
                        true,
                    )
                    .unwrap();
            }
            if mode == 2 {
                std::thread::scope(|scope| {
                    scope.spawn(move || drop(handle));
                    scope.spawn(move || drop(alias));
                    scope.spawn(move || drop(reader));
                });
            } else if mode == 3 {
                // The reader closes first, leaving the final pin inside Source.
                // This deterministically detects ordinary Arc<Source> Drop
                // refunding the pin credit before its own control deallocation.
                drop(reader);
                drop(handle);
                drop(alias);
            } else if mode == 1 {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        let _owners = (handle, alias, reader);
                        panic!("intentional source/pin reader unwind");
                    }))
                    .is_err()
                );
            } else {
                drop(handle);
                drop(alias);
                let intermediate = session.report().unwrap();
                assert!(intermediate.controls[0].is_some());
                assert!(intermediate.controls[1].is_none());
                assert_eq!(SOURCE_PAID.load(Ordering::SeqCst), paid);
                drop(reader);
            }
        })
        .unwrap();
        assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
        for (index, observed) in report.controls.into_iter().enumerate() {
            let observed = observed.unwrap();
            assert_eq!(observed.before, OriginalControlSnapshot::U64(paid));
            assert_eq!(observed.after, Some(OriginalControlSnapshot::U64(paid)));
            assert_eq!(usize::from(observed.ordinal), index + 1);
        }
        assert_eq!(SOURCE_PAID.load(Ordering::SeqCst), 0);
        drop(original);
        let recovered = quota.allocator.reserve_resources(0, 16, RESIDENT).unwrap();
        drop(recovered);
    }
}
