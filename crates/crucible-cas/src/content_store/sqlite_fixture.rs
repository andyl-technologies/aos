//! Owns the explicitly authored native SQLite heap of one fixture process.
//!
//! The ordinary process has one 8 MiB native ceiling; the isolated small-heap
//! profile has one 512 KiB ceiling. Both have a finite 256 MiB model entitlement
//! and the original 128-descriptor roster. Each case retains its separate
//! storage and Rust allocation budgets. These portable counters do not prove
//! payment for loaded native globals or the complete initialization peak.

use std::sync::OnceLock;

use super::test_resources::FixtureResourceBudget;
use super::{
    SqliteHeapAuthority, SqliteHeapIssuer, SqliteProcessBootstrapAuthority, SqliteProcessHeap,
    StoreError,
};
use crate::owned_decode::ResourceLoan;

const NATIVE_HEAP_BYTES: u64 = 8 << 20;
const SMALL_NATIVE_HEAP_BYTES: u64 = 512 << 10;
const PROCESS_MODEL_BYTES: u64 = 256 << 20;
const CONNECTION_ROSTER: usize = 128;

struct FixtureProcessAuthority<const HEAP_BYTES: u64> {
    resources: FixtureResourceBudget,
}

impl<const HEAP_BYTES: u64> SqliteHeapAuthority for FixtureProcessAuthority<HEAP_BYTES> {
    fn verify_live(&self) -> Result<(), StoreError> {
        self.resources.usage().map(|_| ())
    }

    fn reserve_heap(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        if bytes != HEAP_BYTES {
            return Err(StoreError::Quota);
        }
        self.resources.reserve_with_control(bytes)
    }

    fn reserve_metadata(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.resources.reserve_with_control(bytes)
    }
}

impl<const HEAP_BYTES: u64> SqliteProcessBootstrapAuthority
    for FixtureProcessAuthority<HEAP_BYTES>
{
    fn verify_live(&self) -> Result<(), StoreError> {
        SqliteHeapAuthority::verify_live(self)
    }

    fn reserve_bootstrap(&self, rust_metadata_bytes: u64) -> Result<ResourceLoan, StoreError> {
        // This finite model covers the actual Rust process fence and its loan.
        // Native fixed-state and first-entry payment remain separately unqualified.
        self.resources.reserve_with_control(rust_metadata_bytes)
    }
}

static FIXTURE_PROCESS: OnceLock<Result<SqliteProcessHeap, StoreError>> = OnceLock::new();

/// Borrows the one explicitly authored SQLite heap of this fixture process.
///
/// The first call constructs the process policy independently of every case's
/// budget. Later callers receive the same nominal scope. The original 8 MiB
/// native ceiling and per-case budgets do not grow with concurrency.
///
/// The retained model bootstrap credit covers Rust lifecycle storage only.
/// This helper does not qualify native globals, initialization peak, physical
/// descriptors or production process ownership.
///
/// # Errors
/// Returns the retained first admission failure without retrying installation.
pub fn fixture_sqlite_heap() -> Result<SqliteProcessHeap, &'static StoreError> {
    FIXTURE_PROCESS
        .get_or_init(install_fixture_heap::<NATIVE_HEAP_BYTES>)
        .as_ref()
        .cloned()
}

static SMALL_FIXTURE_PROCESS: OnceLock<Result<SqliteProcessHeap, StoreError>> = OnceLock::new();

/// Borrows the fixed 512 KiB SQLite heap of an isolated small-heap test process.
///
/// This purpose preserves the original small-heap profile independently of case
/// budgets. It must run in its own process; an already installed ordinary fixture
/// scope is incompatible. Its finite model bootstrap has the same native and
/// physical qualification limits as [`fixture_sqlite_heap`].
///
/// # Errors
/// Returns the retained first admission failure, including an incompatible
/// process bootstrap, without retrying installation.
pub fn isolated_small_fixture_sqlite_heap() -> Result<SqliteProcessHeap, &'static StoreError> {
    SMALL_FIXTURE_PROCESS
        .get_or_init(install_fixture_heap::<SMALL_NATIVE_HEAP_BYTES>)
        .as_ref()
        .cloned()
}

fn install_fixture_heap<const HEAP_BYTES: u64>() -> Result<SqliteProcessHeap, StoreError> {
    let authority = FixtureProcessAuthority::<HEAP_BYTES> {
        resources: FixtureResourceBudget::new(CONNECTION_ROSTER as u64, PROCESS_MODEL_BYTES),
    };
    SqliteProcessHeap::prepare_bootstrap(&authority)?;
    let credit = authority
        .resources
        .reserve_with_control(SqliteHeapIssuer::control_bytes::<
            FixtureProcessAuthority<HEAP_BYTES>,
        >())?;
    SqliteProcessHeap::install(
        SqliteHeapIssuer::new(authority, credit),
        HEAP_BYTES,
        CONNECTION_ROSTER,
    )
}
