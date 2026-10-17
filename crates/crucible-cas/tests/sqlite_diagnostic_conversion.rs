//! Observes prepaid Rust diagnostic conversions under the unchanged finite bank.
//!
//! Lossy invalid-byte conversion is a pinned binding conversion witness, not a
//! fabricated SQLite stage. Separate real SQLite errors retain their native
//! category. Allocation counts and capacities do not measure timing or prove
//! the source-derived old/new overlap of every native cleanup execution.

use crucible_cas::content_store::{StoreError, StorePhysicalQuotaGuard, fixture_sqlite_connection};
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};
use crucible_linux_resource::test_support::{
    AllocationIdentity, BeforeFreeMarkerOutcome, TestAllocationObserver,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const HEAP: usize = 8 * 1024 * 1024;
const MESSAGE_BOUND: usize = 18 * HEAP;
const LIMIT: usize = 256 * 1024 * 1024;
static CLOSED: AtomicBool = AtomicBool::new(false);
static SERIAL: Mutex<()> = Mutex::new(());

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct Loan {
    used: Arc<AtomicUsize>,
    charged: usize,
    message_credit: bool,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if self.message_credit {
            CLOSED.store(true, Ordering::SeqCst);
        }
        self.used.fetch_sub(self.charged, Ordering::SeqCst);
    }
}

struct Quota {
    used: Arc<AtomicUsize>,
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(LIMIT as u64)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn reserve_resources(&self, _descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        let requested = usize::try_from(bytes).map_err(|_| StoreError::Quota)?;
        let charged = requested
            .checked_add(ResourceLoan::allocation_bytes::<Loan>() as usize)
            .ok_or(StoreError::Quota)?;
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(charged).filter(|next| *next <= LIMIT)
            })
            .map_err(|_| StoreError::Quota)?;
        Ok(ResourceLoan::new(Loan {
            used: self.used.clone(),
            charged,
            message_credit: requested == MESSAGE_BOUND,
        }))
    }
}

fn original() -> Result<(DecodeBudget, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
    let used = Arc::new(AtomicUsize::new(0));
    CLOSED.store(false, Ordering::SeqCst);
    let original = DecodeBudget::for_store(Arc::new(Quota { used: used.clone() }))?;
    Ok((original, used))
}

#[test]
fn lossy_conversion_retains_three_messages_during_fourth_growth_and_physical_close()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL
        .lock()
        .map_err(|_| "diagnostic observer is poisoned")?;
    let (original, used) = original()?;
    let input_credit = original.reserve_scratch_bytes(HEAP as u64)?;
    let input = vec![0xff; HEAP];
    let message_credit = original.reserve_scratch_bytes(MESSAGE_BOUND as u64)?;
    let ((retained, transient_capacity), counts) = TestAllocationObserver::count(|| {
        let retained =
            std::array::from_fn::<_, 3, _>(|_| String::from_utf8_lossy(&input).into_owned());
        let transient = String::from_utf8_lossy(&input).into_owned();
        let capacity = transient.capacity();
        assert_eq!(transient.len(), 3 * HEAP);
        drop(transient);
        (retained, capacity)
    });

    assert!(!counts.overflow);
    assert_eq!(counts.allocations, 4);
    assert!(counts.reallocations > 0);
    assert!(retained.iter().all(|message| message.len() == 3 * HEAP));
    assert!(
        retained
            .iter()
            .all(|message| message.capacity() <= 4 * HEAP)
    );
    assert!(transient_capacity <= 4 * HEAP);
    // The extra 2m is the pinned growth algorithm's simultaneous old buffer;
    // observer counts disclose reallocations rather than inventing its extent.
    let retained_capacity: usize = retained.iter().map(String::capacity).sum();
    assert!(retained_capacity + 2 * HEAP + transient_capacity <= MESSAGE_BOUND);
    let identity = AllocationIdentity::from_address(
        std::num::NonZeroUsize::new(retained[0].as_ptr().addr()).ok_or("missing message buffer")?,
    );
    assert!(!CLOSED.load(Ordering::SeqCst));
    let ((), outcome) =
        TestAllocationObserver::observe_close_marker_before_free(&CLOSED, identity, || {
            drop(retained)
        })?;
    assert_eq!(outcome, BeforeFreeMarkerOutcome::Open);
    drop(message_credit);
    assert!(CLOSED.load(Ordering::SeqCst));
    drop(input);
    drop(input_credit);
    drop(original);
    assert_eq!(used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn real_native_diagnostics_keep_distinct_messages_under_prepaid_original_custody()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let connection = fixture_sqlite_connection(directory.path().join("native.sqlite3"))?;
    let _serial = SERIAL
        .lock()
        .map_err(|_| "diagnostic observer is poisoned")?;
    let (original, used) = original()?;
    let query_length = 128 * 1024;
    // These test-only SQL inputs and fixed error wrappers have independent
    // credit; the native message envelope does not donate to arbitrary inputs.
    let fixed_wrappers = 4
        * (std::mem::size_of::<StoreError>()
            + std::mem::size_of::<rusqlite::Error>()
            + 8 * std::mem::size_of::<usize>());
    let input_credit = original.reserve_scratch_bytes((query_length + fixed_wrappers) as u64)?;
    let mut query = String::with_capacity(query_length);
    query.push_str("SELECT ");
    query.extend(std::iter::repeat_n('x', query_length - 7));
    let message_credit = original.reserve_scratch_bytes(MESSAGE_BOUND as u64)?;
    let errors = std::array::from_fn::<_, 3, _>(|_| {
        connection
            .query_row(&query, [], |row| row.get::<_, u64>(0))
            .unwrap_err()
    });

    for error in &errors {
        let StoreError::StreamIo { source, .. } = error else {
            return Err(format!("expected actual native diagnostic: {error:?}").into());
        };
        let Some(rusqlite::Error::SqliteFailure(_, Some(message))) = source
            .get_ref()
            .and_then(|source| source.downcast_ref::<rusqlite::Error>())
        else {
            return Err("missing actual SQLite message".into());
        };
        assert!(message.starts_with("no such column: "));
        assert!(message.len() >= query_length);
        assert!(message.capacity() <= 4 * HEAP);
    }
    assert!(!CLOSED.load(Ordering::SeqCst));
    drop(errors);
    drop(message_credit);
    assert!(CLOSED.load(Ordering::SeqCst));
    drop(query);
    drop(input_credit);
    drop(original);
    assert_eq!(used.load(Ordering::SeqCst), 0);
    Ok(())
}
