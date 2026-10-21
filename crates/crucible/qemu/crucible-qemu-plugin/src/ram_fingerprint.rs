//! Owns the GPL process's coherent, incremental logical RAM identity.
//!
//! QEMU lends bounded capture pages through private native entry points. The
//! observer retains immutable Merkle snapshots, never guest addresses. Logical
//! publication and native fingerprint dirty retirement remain separate; checkpoint,
//! eviction and transfer have independent ownership. Capture entry points and
//! claim cleanup live in `native`; held and ordinary ownership have separate
//! adapters. The pager uses pure page digests and never enters this observer.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::os::raw::{c_int, c_void};
use std::sync::{Arc, Mutex, OnceLock};

use crate::ram_error::RamError;

use crucible_ram::{
    LOGICAL_PAGE_SIZE, Limits, MetadataBudget, MetadataReservation, PageDigest, RamRootDigest,
    RamSnapshot, RegionClass, RegionDescriptor, RegionTree, Scope, Topology,
};

mod admission;
mod candidate;
mod held;
mod native;
mod ordinary;
pub(crate) use ordinary::pending_sample_class;
mod original;
pub(crate) use admission::admitted_inventory;
pub(crate) use candidate::CaptureClose;
pub(crate) use held::{cleanup_held_claim, observe_held, retire_held_cache};
use native::{CaptureClaim, NativeApis, symbol};
pub(crate) use original::with_read_exchange as with_native_original_read;
pub(crate) use original::{
    FingerprintPlacement, Owner as NativeOriginalOwner, OwnerRef as NativeOriginalOwnerRef,
    borrowed_original_class, retirement_api, synchronize,
};
pub(crate) use original::{borrow_retirement, check_retirement, end_retirement, rearm_retirement};
mod mutation;
use mutation::observe_transaction;
mod restore;
pub(crate) use restore::{
    PreparedRestoreCache, RamProofSource, capture_restore_inventory, prepare_restore,
    rebind_proof_source,
};

const CAPTURE_SCHEMA: u32 = 1;
const MAX_REGIONS: usize = 4096;
const UPDATE_BATCH: usize = 128;
const MAX_PREPARED_PAGES: usize = 65_536;
const SCOPES: [Scope; 3] = [Scope::Execution, Scope::Exact, Scope::Lifecycle];

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct CaptureHeader {
    schema: u32,
    region_count: u32,
    topology_generation: u64,
    capture_generation: u64,
    metadata_budget_bytes: u64,
}

#[repr(C)]
pub(crate) struct CaptureRegion {
    id_length: u32,
    class: u32,
    mask: u32,
    reserved: u32,
    logical_length: u64,
    id: [u8; 256],
}

impl Default for CaptureRegion {
    fn default() -> Self {
        Self {
            id_length: 0,
            class: 0,
            mask: 0,
            reserved: 0,
            logical_length: 0,
            id: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct CapturePage {
    region_index: u32,
    valid_length: u32,
    page_index: u64,
    page_version: u64,
}

type RootObserver = extern "C" fn(u32, u64, *mut u8, *mut u64, *mut CaptureClose) -> c_int;
type RegisterObserver = extern "C" fn(Option<RootObserver>) -> c_int;
type RecordObserver = extern "C" fn(u32, *mut u8, usize, *mut usize, *mut u8, *mut u64) -> c_int;
type RegisterRecordObserver = extern "C" fn(Option<RecordObserver>) -> c_int;
type TransactionObserver =
    extern "C" fn(u32, u64, u64, *const PreparedPage, usize, *mut u8, *mut u64) -> c_int;
type RegisterTransactionObserver = extern "C" fn(Option<TransactionObserver>) -> c_int;
type BeginCapture = extern "C" fn(u32, u64, *mut CaptureHeader) -> c_int;
type ReadRegion = extern "C" fn(u64, u32, *mut CaptureRegion) -> c_int;
type CaptureReadRegion = extern "C" fn(u64, u64, u32, *mut CaptureRegion) -> c_int;
type NextPage = extern "C" fn(u64, u64, *mut u64, *mut CapturePage, *mut u8, usize) -> c_int;
type FinishCapture = extern "C" fn(u64, u64, u32) -> c_int;
type ObservationOnly = extern "C" fn(u64, u64, *mut u32) -> c_int;
type AdmissionObserver = extern "C" fn(*const admission::AdmissionHeader, u64) -> c_int;
type RegisterAdmissionObserver = extern "C" fn(Option<AdmissionObserver>) -> c_int;

struct CachedView {
    topology_generation: u64,
    budget: MetadataBudget,
    snapshot: RamSnapshot,
    roots: [RamRootDigest; 3],
    logical_bytes: [u64; 3],
    native_regions: Vec<RegionDescriptor>,
    records: Vec<CachedRecord>,
    source: Option<Arc<dyn RamProofSource>>,
    _inventory_reservation: MetadataReservation,
}

struct CachedRecord {
    bytes: Vec<u8>,
    _reservation: MetadataReservation,
}

struct PendingMutation {
    transaction: u64,
    topology_generation: u64,
    snapshot: RamSnapshot,
    roots: [RamRootDigest; 3],
    records: Vec<CachedRecord>,
}

#[repr(C)]
struct PreparedPage {
    region_index: u32,
    valid_length: u32,
    page_index: u64,
    page_version: u64,
    bytes: *const u8,
}

#[derive(Default)]
struct RootCache {
    frozen: bool,
    ordinary_active: bool,
    held_publication: Option<u64>,
    budget: Option<MetadataBudget>,
    view: Option<CachedView>,
    pending: Option<PendingMutation>,
    restore: Option<restore::PendingRestore>,
    held: Option<held::StagedView>,
    held_accepted: Option<crate::runtime::HeldReaderIdentity>,
}

struct Observer {
    apis: NativeApis,
    cache: Mutex<RootCache>,
    original: Option<original::OwnerRef>,
}

static OBSERVER: OnceLock<Observer> = OnceLock::new();
static INSTALL_RESULT: OnceLock<Result<(), RamError>> = OnceLock::new();

/// Checks native RAM observation capabilities before callback admission begins.
///
/// # Errors
///
/// Returns an error if a mandatory capture or registration export is missing.
pub(crate) fn preflight() -> Result<(), RamError> {
    NativeApis::resolve()?;
    original::Apis::resolve().map(|_| ())
}

/// Registers the process-lifetime observer before guest execution is admitted.
///
/// # Errors
///
/// Returns an error for missing native exports or rejected registration. A
/// partially installed observer never authorizes execution with stale roots.
pub(crate) fn install(original: Option<original::OwnerRef>) -> Result<(), RamError> {
    INSTALL_RESULT
        .get_or_init(|| {
            let apis = NativeApis::resolve()?;
            OBSERVER
                .set(Observer {
                    apis,
                    cache: Mutex::new(RootCache::default()),
                    original,
                })
                .map_err(|_| RamError::Invariant("RAM observer already initialized"))?;
            status(
                (apis.register_record)(Some(observe_record)),
                "register RAM record observer",
            )?;
            if let Err(error) = status(
                (apis.register_transaction)(Some(observe_transaction)),
                "register RAM transaction observer",
            ) {
                status(
                    (apis.register_record)(None),
                    "rollback RAM record registration",
                )?;
                return Err(error);
            }
            if let Err(error) = status(
                (apis.register)(Some(root_callback())),
                "register RAM observer",
            ) {
                let transaction = status(
                    (apis.register_transaction)(None),
                    "rollback RAM transaction registration",
                );
                let record = status(
                    (apis.register_record)(None),
                    "rollback RAM record registration",
                );
                transaction?;
                record?;
                return Err(error);
            }
            if let Err(error) = status(
                (apis.register_admission)(Some(admission::observe_admission)),
                "register RAM admission observer",
            ) {
                status((apis.register)(None), "rollback RAM observer")?;
                status(
                    (apis.register_transaction)(None),
                    "rollback RAM transaction observer",
                )?;
                status((apis.register_record)(None), "rollback RAM record observer")?;
                return Err(error);
            }
            if let Some(original) = original {
                original.owner().enroll()?;
            }
            Ok(())
        })
        .clone()
}

fn root_callback() -> RootObserver {
    #[cfg(feature = "native-conformance")]
    {
        crate::native_conformance::observe_root
    }
    #[cfg(not(feature = "native-conformance"))]
    {
        observe_root
    }
}

pub(crate) extern "C" fn observe_root(
    scope: u32,
    owner_token: u64,
    root: *mut u8,
    logical_bytes: *mut u64,
    cleanup: *mut CaptureClose,
) -> c_int {
    if root.is_null()
        || logical_bytes.is_null()
        || scope >= SCOPES.len() as u32
        || (owner_token != 0 && cleanup.is_null())
    {
        return -libc::EINVAL;
    }
    // SAFETY: the native caller lends writable outputs of 32 and 8 bytes for
    // this call. Zeroing them prevents partial evidence escaping on failure.
    unsafe {
        std::ptr::write_bytes(root, 0, 32);
        logical_bytes.write(0);
    }
    let mut capture_close = CaptureClose::default();

    // Close evidence contains only initialized scalars. The candidate retains
    // its claim outside its own unwind boundary and closes it before returning.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<([u8; 32], u64), RamError> {
            original::synchronize_root()?;
            let observer = OBSERVER.get().ok_or("RAM observer is not installed")?;
            if owner_token == 0 {
                return ordinary::observe_ordinary(observer, SCOPES[scope as usize])
                    .map(|(root, bytes)| (*root.as_bytes(), bytes));
            }
            let mut cache = observer
                .cache
                .try_lock()
                .map_err(|_| "RAM observer is busy or poisoned")?;
            if cache.frozen
                || cache.ordinary_active
                || cache.held.is_some()
                || cache.held_accepted.is_some()
            {
                return Err(RamError::Invariant(
                    "RAM observer admission is frozen for fork",
                ));
            }
            cache
                .observe_candidate(
                    observer.apis,
                    SCOPES[scope as usize],
                    owner_token,
                    &mut capture_close,
                )
                .map(|(digest, bytes)| (*digest.as_bytes(), bytes))
        },
    ));

    if owner_token != 0 {
        // SAFETY: the diagnostic lends initialized close-evidence storage for
        // the same synchronous callback. It remains independent of root output.
        unsafe { cleanup.write(capture_close) };
    }

    match result {
        Ok(Ok((digest, bytes))) => {
            // SAFETY: the same native output loan remains valid until return.
            unsafe {
                std::ptr::copy_nonoverlapping(digest.as_ptr(), root, digest.len());
                logical_bytes.write(bytes);
            }
            0
        }
        Ok(Err(RamError::Native { status, .. })) if owner_token != 0 => status,
        Ok(Err(_)) | Err(_) => -libc::EIO,
    }
}

impl RootCache {
    fn refresh(
        &mut self,
        apis: NativeApis,
        outer: &mut impl ordinary::RefreshAuthority,
    ) -> Result<(), RamError> {
        if self.ordinary_active
            || self.held.is_some()
            || self.held_accepted.is_some()
            || self.pending.is_some()
            || self.restore.is_some()
        {
            return Err(RamError::Invariant(
                "RAM mutation candidate owns observer admission",
            ));
        }
        let mut full = outer.require_full(self.view.is_none())?;
        let mut claim = outer.open(apis, full)?;
        claim.validate_header()?;
        if !full
            && self
                .view
                .as_ref()
                .is_some_and(|view| view.topology_generation != claim.header.topology_generation)
        {
            // Native returns the exact old borrower and rebinds the other slot
            // on this same Original, keeping its total start and progress.
            claim = outer.restart(claim)?;
            claim.validate_header()?;
            full = true;
        }

        let mut observation_only = 0;
        status(
            (apis.observation_only)(claim.header.capture_generation, 0, &mut observation_only),
            "query ordinary observation mode",
        )?;
        if observation_only > 1 {
            return Err(RamError::Invariant("invalid ordinary observation mode"));
        }
        outer.check_mode(observation_only == 1)?;
        let admitted = self.metadata_budget(claim.header.metadata_budget_bytes)?;
        let inventory_reservation = admitted
            .reserve_bytes(
                (claim.header.region_count as u64)
                    .checked_mul((std::mem::size_of::<RegionDescriptor>() + 255 + 32) as u64)
                    .ok_or("RAM inventory metadata overflow")?,
            )
            .map_err(display_error)?;
        let regions = read_regions(&claim)?;
        let topology = Topology::new(regions.clone(), Limits::default()).map_err(display_error)?;
        let budget = match self.view.as_ref() {
            Some(view) => {
                if view.budget.limit_bytes() != claim.header.metadata_budget_bytes {
                    return Err(RamError::Invariant(
                        "native RAM metadata allowance changed without re-admission",
                    ));
                }
                if !full && view.snapshot.topology() != &topology {
                    return Err(RamError::Invariant(
                        "RAM topology changed without a new topology generation",
                    ));
                }
                view.budget.clone()
            }
            None => self.metadata_budget(claim.header.metadata_budget_bytes)?,
        };

        let snapshot = if full {
            let mut trees = Vec::new();
            trees
                .try_reserve_exact(topology.regions().len())
                .map_err(display_error)?;
            for region in topology.regions() {
                trees.push(
                    RegionTree::zeroed(region.logical_length(), &budget).map_err(display_error)?,
                );
            }
            RamSnapshot::new(topology, trees, &budget).map_err(display_error)?
        } else {
            self.view
                .as_ref()
                .ok_or("missing incremental RAM baseline")?
                .snapshot
                .clone()
        };
        let source = self.view.as_ref().and_then(|view| view.source.clone());
        let (snapshot, changed) =
            consume_ordinary_pages(&claim, &regions, snapshot, full, source.as_deref(), outer)?;
        if !full && !changed {
            let _ = outer.stage(claim, None)?;
            return Ok(());
        }
        let roots = [
            snapshot
                .scoped_root(Scope::Execution)
                .map_err(display_error)?,
            snapshot.scoped_root(Scope::Exact).map_err(display_error)?,
            snapshot
                .scoped_root(Scope::Lifecycle)
                .map_err(display_error)?,
        ];
        let records = encode_records(&snapshot, &budget)?;
        let mut logical_bytes = [0_u64; 3];
        for (scope, bytes) in SCOPES.iter().zip(&mut logical_bytes) {
            for region in snapshot.topology().regions() {
                if scope.includes(region.class()) {
                    *bytes = bytes
                        .checked_add(region.logical_length())
                        .ok_or("RAM byte count overflow")?;
                }
            }
        }
        let topology_generation = claim.header.topology_generation;

        let view = CachedView {
            topology_generation,
            budget,
            snapshot,
            roots,
            logical_bytes,
            native_regions: regions,
            records,
            source: if full { None } else { source },
            _inventory_reservation: inventory_reservation,
        };
        // The production driver keeps the view in its prepaid runtime lane.
        // Only the real later native publication journal may promote it.
        if let Some(view) = outer.stage(claim, Some(view))? {
            self.view = Some(view);
        }
        Ok(())
    }
}

fn read_regions(claim: &CaptureClaim) -> Result<Vec<RegionDescriptor>, RamError> {
    read_region_inventory(
        claim.header.region_count,
        claim.header.capture_generation,
        |generation, index, output| {
            (claim.apis.region)(generation, claim.owner_token, index, output)
        },
    )
}

fn read_region_inventory(
    count: u32,
    generation: u64,
    read: impl Fn(u64, u32, *mut CaptureRegion) -> c_int,
) -> Result<Vec<RegionDescriptor>, RamError> {
    let mut regions = Vec::new();
    regions
        .try_reserve_exact(count as usize)
        .map_err(display_error)?;
    for index in 0..count {
        let mut native = CaptureRegion::default();
        status(read(generation, index, &mut native), "read RAM region")?;
        let class = match native.class {
            1 => RegionClass::MutableMain,
            2 => RegionClass::MutableDevice,
            3 => RegionClass::ImmutableImage,
            4 => RegionClass::ContinuationPrivate,
            _ => return Err(RamError::Invariant("unknown RAM region classification")),
        };
        if native.id_length == 0
            || native.id_length > 255
            || native.reserved != 0
            || native.mask != u32::from(class.coverage_mask())
        {
            return Err(RamError::Invariant("invalid native RAM region metadata"));
        }
        let id =
            std::str::from_utf8(&native.id[..native.id_length as usize]).map_err(display_error)?;
        regions
            .push(RegionDescriptor::new(id, class, native.logical_length).map_err(display_error)?);
    }
    Ok(regions)
}

fn consume_pages(
    claim: &CaptureClaim,
    regions: &[RegionDescriptor],
    snapshot: RamSnapshot,
    full: bool,
    source: Option<&dyn RamProofSource>,
) -> Result<(RamSnapshot, bool), RamError> {
    consume_pages_with(regions, snapshot, full, source, |cursor, page, bytes| {
        (claim.apis.next)(
            claim.header.capture_generation,
            claim.owner_token,
            cursor,
            page,
            bytes.as_mut_ptr(),
            bytes.len(),
        )
    })
}

fn consume_ordinary_pages(
    claim: &CaptureClaim,
    regions: &[RegionDescriptor],
    snapshot: RamSnapshot,
    full: bool,
    source: Option<&dyn RamProofSource>,
    outer: &impl ordinary::RefreshAuthority,
) -> Result<(RamSnapshot, bool), RamError> {
    consume_pages_with_progress(
        regions,
        snapshot,
        full,
        source,
        |cursor, page, bytes| {
            (claim.apis.next)(
                claim.header.capture_generation,
                claim.owner_token,
                cursor,
                page,
                bytes.as_mut_ptr(),
                bytes.len(),
            )
        },
        |units| outer.progress(units),
    )
}

fn consume_pages_with(
    regions: &[RegionDescriptor],
    snapshot: RamSnapshot,
    full: bool,
    source: Option<&dyn RamProofSource>,
    next: impl FnMut(&mut u64, &mut CapturePage, &mut [u8; LOGICAL_PAGE_SIZE as usize]) -> c_int,
) -> Result<(RamSnapshot, bool), RamError> {
    consume_pages_with_progress(regions, snapshot, full, source, next, |_| Ok(()))
}

fn consume_pages_with_progress(
    regions: &[RegionDescriptor],
    mut snapshot: RamSnapshot,
    full: bool,
    source: Option<&dyn RamProofSource>,
    mut next: impl FnMut(&mut u64, &mut CapturePage, &mut [u8; LOGICAL_PAGE_SIZE as usize]) -> c_int,
    mut completed: impl FnMut(u64) -> Result<(), RamError>,
) -> Result<(RamSnapshot, bool), RamError> {
    let mut cursor = 0_u64;
    let mut previous = None;
    let mut expected = (0_usize, 0_u64);
    let mut batch_region = None;
    let _batch_reservation = snapshot
        .metadata_budget()
        .reserve_bytes((UPDATE_BATCH * std::mem::size_of::<(u64, PageDigest)>()) as u64)
        .map_err(display_error)?;
    let mut batch = Vec::new();
    batch
        .try_reserve_exact(UPDATE_BATCH)
        .map_err(display_error)?;
    let mut bytes = [0_u8; LOGICAL_PAGE_SIZE as usize];

    loop {
        let before = cursor;
        let mut page = CapturePage::default();
        let result = next(&mut cursor, &mut page, &mut bytes);
        if result == 1 {
            break;
        }
        status(result, "read RAM page")?;
        let region_index = page.region_index as usize;
        let region = regions
            .get(region_index)
            .ok_or("RAM page references an absent region")?;
        let coordinate = (region_index, page.page_index);
        if cursor <= before
            || previous.is_some_and(|last| coordinate <= last)
            || (full && coordinate != expected)
            || page.valid_length
                != region
                    .geometry()
                    .valid_length(page.page_index)
                    .map_err(display_error)?
            || page.page_version == 0
        {
            return Err(RamError::Invariant(
                "invalid, incomplete or duplicate RAM page stream",
            ));
        }

        if batch_region.is_some_and(|index| index != region_index) || batch.len() == UPDATE_BATCH {
            let units = batch.len() as u64;
            snapshot = apply_batch(snapshot, regions, batch_region, &mut batch, source)?;
            completed(units)?;
        }
        batch_region = Some(region_index);
        batch.push((
            page.page_index,
            PageDigest::hash(&bytes[..page.valid_length as usize]).map_err(display_error)?,
        ));
        previous = Some(coordinate);
        if full {
            expected.1 += 1;
            if expected.1 == region.geometry().page_count() {
                expected = (region_index + 1, 0);
            }
        }
    }

    if full && expected != (regions.len(), 0) {
        return Err(RamError::Invariant(
            "initial RAM capture omitted logical pages",
        ));
    }
    let changed = previous.is_some();
    let units = batch.len() as u64;
    let snapshot = apply_batch(snapshot, regions, batch_region, &mut batch, source)?;
    if units != 0 {
        completed(units)?;
    }
    Ok((snapshot, changed))
}

fn apply_batch(
    mut snapshot: RamSnapshot,
    regions: &[RegionDescriptor],
    index: Option<usize>,
    batch: &mut Vec<(u64, PageDigest)>,
    source: Option<&dyn RamProofSource>,
) -> Result<RamSnapshot, RamError> {
    if batch.is_empty() {
        return Ok(snapshot);
    }
    let region = index
        .and_then(|index| regions.get(index))
        .ok_or("missing RAM batch region")?;
    for (page, _) in batch.iter() {
        let tree = snapshot
            .region_tree(region.id())
            .ok_or("missing RAM tree")?;
        match tree.page_digest(*page) {
            Ok(_) => {}
            Err(crucible_ram::RamError::MissingProof) => {
                let source = source.ok_or("opaque RAM path lacks retained source authority")?;
                let proof = source.proof(region.id(), *page)?;
                if proof.region_id() != region.id() || proof.page_index() != *page {
                    return Err(RamError::Invariant(
                        "RAM source proof has a different coordinate",
                    ));
                }
                snapshot = snapshot
                    .hydrated(&proof, source.source_record(), source.source_root())
                    .map_err(display_error)?;
            }
            Err(error) => return Err(display_error(error)),
        }
    }
    let updated = snapshot
        .updated(region.id(), batch)
        .map_err(display_error)?;
    batch.clear();
    Ok(updated)
}

fn status(value: c_int, operation: &'static str) -> Result<(), RamError> {
    if value == 0 {
        Ok(())
    } else {
        Err(RamError::Native {
            operation,
            status: value,
        })
    }
}

fn display_error(error: impl Into<RamError>) -> RamError {
    error.into()
}

fn encode_records(
    snapshot: &RamSnapshot,
    budget: &MetadataBudget,
) -> Result<Vec<CachedRecord>, RamError> {
    let mut records = Vec::new();
    records
        .try_reserve_exact(SCOPES.len())
        .map_err(display_error)?;
    for scope in SCOPES {
        let transient_bytes = snapshot
            .topology()
            .metadata_bytes()
            .map_err(display_error)?
            .checked_add((snapshot.topology().regions().len() as u64) * 32)
            .and_then(|bytes| {
                bytes.checked_add((std::mem::size_of::<crucible_ram::RootRecord>() + 512) as u64)
            })
            .ok_or("RAM record metadata overflow")?;
        let _transient = budget
            .reserve_bytes(transient_bytes)
            .map_err(display_error)?;
        let record = snapshot.root_record(scope).map_err(display_error)?;
        let reservation = budget
            .reserve_bytes(record.encoded_len() as u64)
            .map_err(display_error)?;
        let bytes = record.try_encode().map_err(display_error)?;
        records.push(CachedRecord {
            bytes,
            _reservation: reservation,
        });
    }
    Ok(records)
}

extern "C" fn observe_record(
    scope: u32,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
    root: *mut u8,
    logical_bytes: *mut u64,
) -> c_int {
    if scope >= SCOPES.len() as u32
        || written.is_null()
        || root.is_null()
        || logical_bytes.is_null()
        || (capacity != 0 && buffer.is_null())
    {
        return -libc::EINVAL;
    }
    // SAFETY: QEMU lends these complete scalar and digest outputs for this call.
    unsafe {
        written.write(0);
        logical_bytes.write(0);
        std::ptr::write_bytes(root, 0, 32);
    }
    let result = std::panic::catch_unwind(|| -> Result<(), c_int> {
        synchronize().map_err(|_| -libc::EBUSY)?;
        let observer = OBSERVER.get().ok_or(-libc::ENODEV)?;
        let cache = observer.cache.try_lock().map_err(|_| -libc::EBUSY)?;
        if cache.ordinary_active
            || cache.held.is_some()
            || cache.held_accepted.is_some()
            || cache.pending.is_some()
            || cache.restore.is_some()
        {
            return Err(-libc::EBUSY);
        }
        let view = cache.view.as_ref().ok_or(-libc::ENODATA)?;
        let record = &view.records[scope as usize];
        // SAFETY: QEMU lends scalar and digest output storage for this call.
        unsafe {
            written.write(record.bytes.len());
            logical_bytes.write(view.logical_bytes[scope as usize]);
            std::ptr::copy_nonoverlapping(view.roots[scope as usize].as_bytes().as_ptr(), root, 32);
        }
        if capacity == 0 {
            return Ok(());
        }
        if capacity < record.bytes.len() {
            return Err(-libc::ENOSPC);
        }
        // SAFETY: the checked capacity covers the complete immutable record.
        unsafe {
            std::ptr::copy_nonoverlapping(record.bytes.as_ptr(), buffer, record.bytes.len());
        }
        Ok(())
    });
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(status)) => status,
        Err(_) => -libc::EIO,
    }
}

fn observer() -> Result<&'static Observer, RamError> {
    OBSERVER
        .get()
        .ok_or(RamError::Invariant("RAM observer is not installed"))
}

/// Shares the existing admitted account with a staged child handoff.
///
/// The native caller retains its paused writer fence while decoding and
/// reserving the handoff. This getter neither enters native capture nor creates
/// a replacement account, and it inspects no RAM bytes or backing source.
///
/// # Errors
///
/// Refuses competing observer admission, an active mutation or restore, or a
/// missing sealed metadata account.
pub(crate) fn fork_metadata_budget() -> Result<MetadataBudget, RamError> {
    synchronize()?;
    let cache = observer()?
        .cache
        .try_lock()
        .map_err(|_| RamError::Invariant("RAM fork budget observer unavailable"))?;
    if cache.ordinary_active
        || cache.held.is_some()
        || cache.held_accepted.is_some()
        || cache.pending.is_some()
        || cache.restore.is_some()
    {
        return Err(RamError::Invariant(
            "RAM fork budget admission belongs to another transaction",
        ));
    }
    cache.budget.clone().ok_or(RamError::Invariant(
        "RAM fork metadata account is not admitted",
    ))
}

/// Captures a final coherent view, then excludes observers before registry freeze.
///
/// # Errors
///
/// Returns an error if another observer is active, capture fails or admission is
/// already frozen. The native caller must hold the proved writer fence.
pub(crate) fn prepare_fork() -> Result<(), RamError> {
    let observer = observer()?;
    ordinary::observe_ordinary(observer, Scope::Exact)?;
    synchronize()?;
    let mut cache = observer
        .cache
        .try_lock()
        .map_err(|_| "RAM fork cache busy")?;
    if cache.frozen
        || cache.ordinary_active
        || cache.held.is_some()
        || cache.held_accepted.is_some()
        || cache.pending.is_some()
        || cache.restore.is_some()
    {
        return Err(RamError::Invariant(
            "RAM fork admission changed after observation",
        ));
    }
    cache.frozen = true;
    Ok(())
}

/// Checks the retained source seal without reading RAM or allocating a root.
///
/// # Errors
///
/// Returns an error unless preparation froze a complete immutable view.
pub(crate) fn final_seal() -> Result<(), RamError> {
    synchronize()?;
    let cache = observer()?
        .cache
        .try_lock()
        .map_err(|_| "RAM observer is active at final seal")?;
    if cache.frozen
        && !cache.ordinary_active
        && cache.view.is_some()
        && cache.pending.is_none()
        && cache.restore.is_none()
    {
        Ok(())
    } else {
        Err(RamError::Invariant(
            "RAM observer final seal lacks a prepared immutable view",
        ))
    }
}

/// Reopens observer admission after the parent's native tracker resumes.
///
/// # Errors
///
/// Returns an error for an active or poisoned observer mutex.
pub(crate) fn resume_parent() -> Result<(), RamError> {
    synchronize()?;
    let mut cache = observer()?
        .cache
        .try_lock()
        .map_err(|_| "RAM observer is active during resume")?;
    cache.frozen = false;
    Ok(())
}

/// Retains immutable tree sharing after the native child installs fresh tracking.
///
/// # Errors
///
/// Returns an error if the fork inherited an unprepared view or locked mutex.
pub(crate) fn rebind_child() -> Result<(), RamError> {
    final_seal()?;
    resume_parent()
}

/// Reopens observer admission after native fork rollback has retained dirty state.
///
/// # Errors
///
/// Returns an error for an active or poisoned observer mutex.
pub(crate) fn abort_fork() -> Result<(), RamError> {
    synchronize()?;
    resume_parent()
}

#[cfg(test)]
#[path = "ram_fingerprint/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ram_fingerprint/capture_claim_tests.rs"]
mod capture_claim_tests;

#[cfg(test)]
#[path = "ram_fingerprint/candidate_tests.rs"]
mod candidate_tests;
