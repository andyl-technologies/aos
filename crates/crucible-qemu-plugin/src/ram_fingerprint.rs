//! Owns the GPL process's coherent, incremental logical RAM identity.
//!
//! QEMU lends a bounded page stream while its native writer fence is held.
//! This observer retains immutable Merkle snapshots, never guest addresses.
//! Capture completion acknowledges only the native root consumer; checkpoint,
//! eviction and transfer obligations have independent ownership. The pager
//! must use the pure page digest primitive and never enter this observer.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::os::raw::{c_int, c_void};
use std::sync::{Arc, Mutex, OnceLock};

use crate::ram_error::RamError;

use crucible_ram::{
    LOGICAL_PAGE_SIZE, Limits, MetadataBudget, MetadataReservation, PageDigest, RamRootDigest,
    RamSnapshot, RegionClass, RegionDescriptor, RegionTree, Scope, Topology,
};

mod admission;
pub(crate) use admission::admitted_inventory;
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
#[derive(Default)]
struct CaptureHeader {
    schema: u32,
    region_count: u32,
    topology_generation: u64,
    capture_generation: u64,
    metadata_budget_bytes: u64,
}

#[repr(C)]
struct CaptureRegion {
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
struct CapturePage {
    region_index: u32,
    valid_length: u32,
    page_index: u64,
    page_version: u64,
}

type RootObserver = extern "C" fn(u32, *mut u8, *mut u64) -> c_int;
type RegisterObserver = extern "C" fn(Option<RootObserver>) -> c_int;
type RecordObserver = extern "C" fn(u32, *mut u8, usize, *mut usize, *mut u8, *mut u64) -> c_int;
type RegisterRecordObserver = extern "C" fn(Option<RecordObserver>) -> c_int;
type TransactionObserver =
    extern "C" fn(u32, u64, u64, *const PreparedPage, usize, *mut u8, *mut u64) -> c_int;
type RegisterTransactionObserver = extern "C" fn(Option<TransactionObserver>) -> c_int;
type BeginCapture = extern "C" fn(u32, *mut CaptureHeader) -> c_int;
type ReadRegion = extern "C" fn(u64, u32, *mut CaptureRegion) -> c_int;
type NextPage = extern "C" fn(u64, *mut u64, *mut CapturePage, *mut u8, usize) -> c_int;
type FinishCapture = extern "C" fn(u64, u32) -> c_int;
type AdmissionObserver = extern "C" fn(*const admission::AdmissionHeader, u64) -> c_int;
type RegisterAdmissionObserver = extern "C" fn(Option<AdmissionObserver>) -> c_int;

#[derive(Clone, Copy)]
struct NativeApis {
    begin: BeginCapture,
    region: ReadRegion,
    next: NextPage,
    finish: FinishCapture,
    register: RegisterObserver,
    register_record: RegisterRecordObserver,
    register_transaction: RegisterTransactionObserver,
    admission_region: ReadRegion,
    register_admission: RegisterAdmissionObserver,
}

impl NativeApis {
    fn resolve() -> Result<Self, RamError> {
        // SAFETY: these symbols belong to the versioned GPL-private ABI, whose
        // native declarations have precisely the repr(C) layouts above. All
        // borrowed output pointers expire before each synchronous call returns.
        unsafe {
            Ok(Self {
                begin: std::mem::transmute::<*mut c_void, BeginCapture>(symbol(
                    b"qemu_plugin_crucible_ram_capture_begin_v1\0",
                )?),
                region: std::mem::transmute::<*mut c_void, ReadRegion>(symbol(
                    b"qemu_plugin_crucible_ram_capture_region_v1\0",
                )?),
                next: std::mem::transmute::<*mut c_void, NextPage>(symbol(
                    b"qemu_plugin_crucible_ram_capture_next_page_v1\0",
                )?),
                finish: std::mem::transmute::<*mut c_void, FinishCapture>(symbol(
                    b"qemu_plugin_crucible_ram_capture_finish_v1\0",
                )?),
                register: std::mem::transmute::<*mut c_void, RegisterObserver>(symbol(
                    b"qemu_plugin_crucible_register_ram_root_observer_v1\0",
                )?),
                register_record: std::mem::transmute::<*mut c_void, RegisterRecordObserver>(
                    symbol(b"qemu_plugin_crucible_register_ram_root_record_observer_v1\0")?,
                ),
                register_transaction: std::mem::transmute::<*mut c_void, RegisterTransactionObserver>(
                    symbol(b"qemu_plugin_crucible_register_ram_root_transaction_v1\0")?,
                ),
                admission_region: std::mem::transmute::<*mut c_void, ReadRegion>(symbol(
                    b"qemu_plugin_crucible_ram_admission_region_v1\0",
                )?),
                register_admission: std::mem::transmute::<*mut c_void, RegisterAdmissionObserver>(
                    symbol(b"qemu_plugin_crucible_register_ram_admission_v1\0")?,
                ),
            })
        }
    }
}

fn symbol(name: &'static [u8]) -> Result<*mut c_void, RamError> {
    // SAFETY: every caller supplies a static NUL-terminated symbol name.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) };
    if address.is_null() {
        return Err(RamError::MissingSymbol(name));
    }
    Ok(address)
}

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
    budget: Option<MetadataBudget>,
    view: Option<CachedView>,
    pending: Option<PendingMutation>,
    restore: Option<restore::PendingRestore>,
}

struct Observer {
    apis: NativeApis,
    cache: Mutex<RootCache>,
}

static OBSERVER: OnceLock<Observer> = OnceLock::new();
static INSTALL_RESULT: OnceLock<Result<(), RamError>> = OnceLock::new();

/// Checks native RAM observation capabilities before callback admission begins.
///
/// # Errors
///
/// Returns an error if a mandatory capture or registration export is missing.
pub(crate) fn preflight() -> Result<(), RamError> {
    NativeApis::resolve().map(|_| ())
}

/// Registers the process-lifetime observer before guest execution is admitted.
///
/// # Errors
///
/// Returns an error for missing native exports or rejected registration. A
/// partially installed observer never authorizes execution with stale roots.
pub(crate) fn install() -> Result<(), RamError> {
    INSTALL_RESULT
        .get_or_init(|| {
            let apis = NativeApis::resolve()?;
            OBSERVER
                .set(Observer {
                    apis,
                    cache: Mutex::new(RootCache::default()),
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

pub(crate) extern "C" fn observe_root(scope: u32, root: *mut u8, logical_bytes: *mut u64) -> c_int {
    if root.is_null() || logical_bytes.is_null() || scope >= SCOPES.len() as u32 {
        return -libc::EINVAL;
    }
    // SAFETY: the native caller lends writable outputs of 32 and 8 bytes for
    // this call. Zeroing them prevents partial evidence escaping on failure.
    unsafe {
        std::ptr::write_bytes(root, 0, 32);
        logical_bytes.write(0);
    }

    let result = std::panic::catch_unwind(|| -> Result<([u8; 32], u64), RamError> {
        let observer = OBSERVER.get().ok_or("RAM observer is not installed")?;
        let mut cache = observer
            .cache
            .try_lock()
            .map_err(|_| "RAM observer is busy or poisoned")?;
        if cache.frozen {
            return Err(RamError::Invariant(
                "RAM observer admission is frozen for fork",
            ));
        }
        cache.refresh(observer.apis)?;
        let view = cache
            .view
            .as_ref()
            .ok_or("RAM observer has no committed snapshot")?;
        Ok((
            *view.roots[scope as usize].as_bytes(),
            view.logical_bytes[scope as usize],
        ))
    });

    match result {
        Ok(Ok((digest, bytes))) => {
            // SAFETY: the same native output loan remains valid until return.
            unsafe {
                std::ptr::copy_nonoverlapping(digest.as_ptr(), root, digest.len());
                logical_bytes.write(bytes);
            }
            0
        }
        Ok(Err(_)) | Err(_) => -libc::EIO,
    }
}

/// A native dirty claim is aborted on every unwinding or validation path.
struct CaptureClaim {
    apis: NativeApis,
    header: CaptureHeader,
    finished: bool,
}

impl CaptureClaim {
    fn begin(apis: NativeApis, full: bool) -> Result<Self, RamError> {
        let mut header = CaptureHeader::default();
        status(
            (apis.begin)(u32::from(full), &mut header),
            "begin RAM capture",
        )?;
        let claim = Self {
            apis,
            header,
            finished: false,
        };
        if claim.header.schema != CAPTURE_SCHEMA
            || claim.header.region_count == 0
            || claim.header.region_count as usize > MAX_REGIONS
            || claim.header.topology_generation == 0
            || claim.header.capture_generation == 0
            || claim.header.metadata_budget_bytes == 0
        {
            return Err(RamError::Invariant("invalid native RAM capture header"));
        }
        Ok(claim)
    }

    fn commit(mut self) -> Result<(), RamError> {
        status(
            (self.apis.finish)(self.header.capture_generation, 1),
            "commit RAM capture",
        )?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for CaptureClaim {
    fn drop(&mut self) {
        if !self.finished {
            (self.apis.finish)(self.header.capture_generation, 0);
        }
    }
}

impl RootCache {
    fn refresh(&mut self, apis: NativeApis) -> Result<(), RamError> {
        if self.pending.is_some() || self.restore.is_some() {
            return Err(RamError::Invariant(
                "RAM mutation candidate owns observer admission",
            ));
        }
        let mut full = self.view.is_none();
        let mut claim = CaptureClaim::begin(apis, full)?;
        if self
            .view
            .as_ref()
            .is_some_and(|view| view.topology_generation != claim.header.topology_generation)
        {
            drop(claim);
            full = true;
            claim = CaptureClaim::begin(apis, true)?;
        }

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
            consume_pages(&claim, &regions, snapshot, full, source.as_deref())?;
        if !full && !changed {
            claim.commit()?;
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

        // Publish the complete immutable view before retiring its independent
        // native dirty obligation. Observer exclusion retains the prior view
        // until acknowledgment succeeds, permitting infallible rollback if the
        // native source lost coherence; no reader can see the provisional view.
        let prior = self.view.replace(CachedView {
            topology_generation,
            budget,
            snapshot,
            roots,
            logical_bytes,
            native_regions: regions,
            records,
            source: if full { None } else { source },
            _inventory_reservation: inventory_reservation,
        });
        if let Err(error) = claim.commit() {
            self.view = prior;
            return Err(error);
        }
        Ok(())
    }
}

fn read_regions(claim: &CaptureClaim) -> Result<Vec<RegionDescriptor>, RamError> {
    read_region_inventory(
        claim.header.region_count,
        claim.header.capture_generation,
        claim.apis.region,
    )
}

fn read_region_inventory(
    count: u32,
    generation: u64,
    read: ReadRegion,
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
    mut snapshot: RamSnapshot,
    full: bool,
    source: Option<&dyn RamProofSource>,
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
        let result = (claim.apis.next)(
            claim.header.capture_generation,
            &mut cursor,
            &mut page,
            bytes.as_mut_ptr(),
            bytes.len(),
        );
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
            snapshot = apply_batch(snapshot, regions, batch_region, &mut batch, source)?;
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
    Ok((
        apply_batch(snapshot, regions, batch_region, &mut batch, source)?,
        changed,
    ))
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
        let observer = OBSERVER.get().ok_or(-libc::ENODEV)?;
        let cache = observer.cache.try_lock().map_err(|_| -libc::EBUSY)?;
        if cache.pending.is_some() || cache.restore.is_some() {
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
    let cache = observer()?
        .cache
        .try_lock()
        .map_err(|_| RamError::Invariant("RAM fork budget observer unavailable"))?;
    if cache.pending.is_some() || cache.restore.is_some() {
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
    let mut cache = observer
        .cache
        .try_lock()
        .map_err(|_| "RAM observer has an active capture")?;
    if cache.frozen || cache.pending.is_some() || cache.restore.is_some() {
        return Err(RamError::Invariant(
            "RAM observer already frozen or preparing a mutation",
        ));
    }
    cache.refresh(observer.apis)?;
    cache.frozen = true;
    Ok(())
}

/// Checks the retained source seal without reading RAM or allocating a root.
///
/// # Errors
///
/// Returns an error unless preparation froze a complete immutable view.
pub(crate) fn final_seal() -> Result<(), RamError> {
    let cache = observer()?
        .cache
        .try_lock()
        .map_err(|_| "RAM observer is active at final seal")?;
    if cache.frozen && cache.view.is_some() && cache.pending.is_none() && cache.restore.is_none() {
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
    resume_parent()
}

#[cfg(test)]
#[path = "ram_fingerprint/tests.rs"]
mod tests;
