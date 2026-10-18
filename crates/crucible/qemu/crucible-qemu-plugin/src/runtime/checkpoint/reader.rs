//! Borrows the authentic stopped candidate and its original through held reads.
//!
//! Identity is observed before Slot/State acquisition. Those guards end before
//! source I/O or native calls; neither this observer nor its page exchange starts
//! an ordinary operation, deadline, event or new page/source authority.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::paged_ram::source::{ObservationOperationError, SourceOperation};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

#[repr(C)]
pub(crate) struct CandidateLoan {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct CaptureLoan {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Default)]
struct ReadStatus {
    schema_version: u32,
    struct_size: u32,
    request_generation: u64,
    native_transaction_generation: u64,
    process_generation: u64,
    connection_epoch: u64,
    stopped_generation: u64,
    collector_token: u64,
    collector_topology: u64,
    provider_owner: *mut c_void,
    original: *const u8,
    original_bytes: usize,
    first_status: i32,
    post_status: i32,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct CaptureStatus {
    pub(crate) schema_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) capture_generation: u64,
    pub(crate) topology_generation: u64,
    pub(crate) dirty_generation: u64,
    pub(crate) full: u32,
    pub(crate) claim_closed: u32,
    pub(crate) publication_capture_generation: u64,
    pub(crate) publication_pending: u32,
    pub(crate) publication_accepted: u32,
    pub(crate) rearm_deferred: u32,
    pub(crate) fingerprint_acknowledged: u32,
    pub(crate) first_status: i32,
    pub(crate) post_status: i32,
}

type Read = extern "C" fn(u64, *mut CandidateLoan, u64, *mut u8, u32, *mut c_void) -> i32;
type Observe = extern "C" fn(
    u64,
    *mut CandidateLoan,
    u32,
    u32,
    *mut u8,
    usize,
    *mut usize,
    *mut u8,
    *mut u64,
    *mut c_void,
) -> i32;
type Register = extern "C" fn(u64, Option<Read>, Option<Observe>, *mut c_void) -> i32;
type Cleanup = extern "C" fn(u64, *mut CandidateLoan, *mut c_void, *mut c_void) -> i32;
type RegisterCleanup = extern "C" fn(u64, Option<Cleanup>, *mut c_void) -> i32;
type Identity = extern "C" fn(u64, *mut CandidateLoan, *mut ReadStatus) -> i32;
type Slice = extern "C" fn(u64, *mut CandidateLoan, *mut u64) -> i32;
type Begin = extern "C" fn(
    *mut CandidateLoan,
    u32,
    *mut *mut CaptureLoan,
    *mut crate::ram_fingerprint::CaptureHeader,
) -> i32;
type Region =
    extern "C" fn(*mut CaptureLoan, u32, *mut crate::ram_fingerprint::CaptureRegion) -> i32;
type Next = extern "C" fn(*mut CaptureLoan, *mut crate::ram_fingerprint::CapturePage) -> i32;
type Finish = extern "C" fn(*mut *mut CaptureLoan, u32) -> i32;
type Publication = extern "C" fn(*mut CandidateLoan, *mut CaptureStatus) -> i32;
type Page = extern "C" fn(
    *mut CandidateLoan,
    u64,
    u32,
    u64,
    *mut crate::ram_fingerprint::CapturePage,
    *mut u8,
    usize,
) -> i32;

#[derive(Clone, Copy)]
pub(crate) struct ReaderApi {
    register: Register,
    register_cleanup: RegisterCleanup,
    identity: Identity,
    slice: Slice,
    pub(crate) begin: Begin,
    pub(crate) region: Region,
    pub(crate) next: Next,
    pub(crate) finish: Finish,
    publication: Publication,
    pub(crate) page: Page,
}

impl ReaderApi {
    pub(super) fn resolve() -> Result<Self, i32> {
        macro_rules! resolve {
            ($name:literal, $signature:ty) => {{
                // SAFETY: the complete co-retained SDK defines these exact
                // static names and layouts. Resolution issues no loan or proof.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(-libc::ENOSYS);
                }
                // SAFETY: the non-null symbol has the literal matched declaration.
                unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
            }};
        }
        Ok(Self {
            register: resolve!(
                c"qemu_plugin_crucible_register_checkpoint_candidate_readers_v1",
                Register
            ),
            register_cleanup: resolve!(
                c"qemu_plugin_crucible_register_checkpoint_candidate_cleanup_v1",
                RegisterCleanup
            ),
            identity: resolve!(
                c"qemu_plugin_crucible_checkpoint_candidate_read_observe_v1",
                Identity
            ),
            slice: resolve!(
                c"qemu_plugin_crucible_checkpoint_candidate_original_slice_v1",
                Slice
            ),
            begin: resolve!(
                c"qemu_plugin_crucible_checkpoint_candidate_capture_begin_v1",
                Begin
            ),
            region: resolve!(
                c"qemu_plugin_crucible_checkpoint_candidate_capture_region_v1",
                Region
            ),
            next: resolve!(
                c"qemu_plugin_crucible_checkpoint_candidate_capture_next_v1",
                Next
            ),
            finish: resolve!(
                c"qemu_plugin_crucible_checkpoint_candidate_capture_finish_v1",
                Finish
            ),
            publication: resolve!(
                c"qemu_plugin_crucible_checkpoint_candidate_capture_publication_observe_v1",
                Publication
            ),
            page: resolve!(
                c"qemu_plugin_crucible_checkpoint_candidate_capture_page_v1",
                Page
            ),
        })
    }

    pub(super) fn register(self, id: u64, userdata: *mut c_void) -> Result<(), i32> {
        let status = (self.register)(id, Some(read), Some(observe), userdata);
        if status != 0 {
            return Err(if status < 0 { status } else { -libc::EPROTO });
        }
        let status = (self.register_cleanup)(id, Some(cleanup), userdata);
        if status == 0 {
            Ok(())
        } else {
            Err(if status < 0 { status } else { -libc::EPROTO })
        }
    }
}

/// Records only rejection coordinates copied from a real native read invocation.
/// It supplies no constructor for native read, execution or page authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeldReaderIdentity {
    loan: usize,
    provider_owner: usize,
    pub(super) request_generation: u64,
    pub(super) transaction: u64,
    pub(super) process_generation: u64,
    pub(super) connection_epoch: u64,
    pub(super) original: [u8; 80],
    stopped_generation: u64,
    collector_token: u64,
    topology_generation: u64,
}

/// Returns only an issued claim through authentic creating-owner cleanup.
///
/// This capability exposes no Original query, RAM read, publication or dirty
/// acknowledgment. Copied identity coordinates only reject a foreign holder.
pub(crate) struct HeldClaimCleanup {
    finish: Finish,
    pub(crate) identity: HeldReaderIdentity,
}

impl HeldClaimCleanup {
    /// Restricts an authentic read callback to its independent physical return.
    pub(crate) fn from_reader(context: &HeldReadContext) -> Self {
        Self {
            finish: context.api.finish,
            identity: context.identity,
        }
    }

    /// Returns the saved handle only after native proves its physical close.
    ///
    /// # Errors
    /// Preserves the actual returned handle on every signed refusal or unknown
    /// result. An expired semantic Original does not enter this physical path.
    pub(crate) fn close_no_ack(&self, saved: &mut usize) -> Result<(), i32> {
        if *saved == 0 {
            return Ok(());
        }
        let mut handle = *saved as *mut CaptureLoan;
        let status = (self.finish)(&mut handle, 0);
        *saved = handle as usize;
        if status != 0 {
            return Err(if status < 0 { status } else { -libc::EPROTO });
        }
        if *saved != 0 {
            return Err(-libc::EBUSY);
        }
        Ok(())
    }
}

/// Borrows native functions only through their genuine callback-scoped loan.
pub(crate) struct HeldReadContext {
    pub(crate) api: ReaderApi,
    loan: usize,
    pub(crate) identity: HeldReaderIdentity,
    id: u64,
}

impl HeldReadContext {
    pub(crate) fn loan(&self) -> *mut CandidateLoan {
        self.loan as *mut CandidateLoan
    }

    pub(crate) fn topology_generation(&self) -> u64 {
        self.identity.topology_generation
    }

    pub(crate) fn slice(&self) -> Result<Duration, i32> {
        let mut ns = 0;
        let status = (self.api.slice)(self.id, self.loan(), &mut ns);
        if status != 0 {
            return Err(if status < 0 { status } else { -libc::EPROTO });
        }
        if ns == 0 {
            return Err(-libc::ETIMEDOUT);
        }
        Ok(Duration::from_nanos(ns).min(Duration::from_millis(10)))
    }

    pub(crate) fn publication(&self) -> Result<CaptureStatus, i32> {
        let mut output = CaptureStatus::default();
        let status = (self.api.publication)(self.loan(), &mut output);
        if status != 0 {
            return Err(if status < 0 { status } else { -libc::EPROTO });
        }
        if output.schema_version != 1
            || output.struct_size as usize != std::mem::size_of::<CaptureStatus>()
            || output.capture_generation == 0
            || output.topology_generation != self.identity.topology_generation
            || output.dirty_generation == 0
            || output.full > 1
            || output.claim_closed > 1
            || output.publication_pending > 1
            || output.publication_accepted > 1
            || output.rearm_deferred > 1
            || output.fingerprint_acknowledged != 0
            || output.first_status > 0
            || output.post_status > 0
        {
            return Err(-libc::EPROTO);
        }
        Ok(output)
    }
}

fn observe_identity(
    id: u64,
    loan: *mut CandidateLoan,
    runtime: &OwnedCallbackRuntimeState,
    api: ReaderApi,
) -> Result<(HeldReaderIdentity, i32, i32), i32> {
    let mut status = ReadStatus::default();
    let observed = (api.identity)(id, loan, &mut status);
    if observed != 0 {
        return Err(if observed < 0 {
            observed
        } else {
            -libc::EPROTO
        });
    }
    if status.schema_version != 1
        || status.struct_size as usize != std::mem::size_of::<ReadStatus>()
        || status.request_generation == 0
        || status.native_transaction_generation == 0
        || status.process_generation != runtime.process_generation
        || status.connection_epoch == 0
        || status.stopped_generation == 0
        || status.collector_token == 0
        || status.collector_topology == 0
        || status.provider_owner.is_null()
        || status.original.is_null()
        || status.original_bytes != 80
        || status.first_status > 0
        || status.post_status > 0
    {
        return Err(-libc::EPROTO);
    }
    // SAFETY: the identity accessor lends exactly this immutable Original through
    // the current synchronous native callback. No event/descriptor escapes.
    let original = unsafe { *status.original.cast::<[u8; 80]>() };
    let identity = HeldReaderIdentity {
        loan: loan as usize,
        provider_owner: status.provider_owner as usize,
        request_generation: status.request_generation,
        transaction: status.native_transaction_generation,
        process_generation: status.process_generation,
        connection_epoch: status.connection_epoch,
        original,
        stopped_generation: status.stopped_generation,
        collector_token: status.collector_token,
        topology_generation: status.collector_topology,
    };
    Ok((identity, status.first_status, status.post_status))
}

fn with_reader(
    id: u64,
    loan: *mut CandidateLoan,
    userdata: *mut c_void,
    callback: impl FnOnce(&HeldReadContext, &crate::paged_ram::engine::HeldCheckpointRead) -> i32,
) -> i32 {
    if loan.is_null() || userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: the real native registrar retains this same pinned Runtime. Its
    // callback starts only after installer mutation ended; the borrow is scoped.
    let runtime = unsafe { &*userdata.cast::<OwnedCallbackRuntimeState>() };
    if runtime.plugin_id != Some(id) || runtime.owner_process != std::process::id() {
        return -libc::ESTALE;
    }
    let Some(api) = runtime.checkpoint_api.map(|api| api.reader) else {
        return -libc::ENOSYS;
    };
    let (identity, first, post) = match observe_identity(id, loan, runtime, api) {
        Ok(identity) => identity,
        Err(status) => return status,
    };
    if first != 0 {
        return first;
    }
    if post != 0 {
        return post;
    }
    let read = {
        let Ok(slot) = runtime.checkpoint.try_lock() else {
            return -libc::EBUSY;
        };
        if std::ptr::from_ref(&*slot).cast_mut().cast::<c_void>() as usize
            != identity.provider_owner
            || slot
                .provider
                .as_ref()
                .is_none_or(|binding| !binding.matches_reader(&identity))
            || slot
                .binding
                .as_ref()
                .is_none_or(|binding| binding.native_transaction_generation != identity.transaction)
            || slot.root.is_some()
        {
            return -libc::ESTALE;
        }
        match slot.owner.as_ref().map(|owner| owner.retain_held_read()) {
            Some(Ok(read)) => read,
            _ => return -libc::EBUSY,
        }
    };
    let context = HeldReadContext {
        api,
        loan: loan as usize,
        identity,
        id,
    };
    if let Err(status) = context.slice() {
        return status;
    }
    callback(&context, &read)
}

impl HeldReadContext {
    pub(crate) fn with_page_operation<T>(
        &self,
        exchange: impl FnOnce(&dyn SourceOperation) -> T,
    ) -> T {
        let operation = PageOperation {
            context: self,
            completed: AtomicBool::new(false),
        };
        exchange(&operation)
    }
}

/// Specializes one source exchange without starting or ending its native Original.
struct PageOperation<'a> {
    context: &'a HeldReadContext,
    completed: AtomicBool,
}

fn operation_io_error(error: ObservationOperationError) -> std::io::Error {
    match error {
        ObservationOperationError::Io(error) => error,
        ObservationOperationError::Static { kind, .. } => std::io::Error::from(kind),
    }
}

impl SourceOperation for PageOperation<'_> {
    fn wait_slice(&self) -> std::io::Result<Duration> {
        self.wait_slice_for_observation()
            .map_err(operation_io_error)
    }

    fn complete(&self) -> std::io::Result<()> {
        self.complete_observation().map_err(operation_io_error)
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        if self.completed.load(Ordering::Acquire) {
            return Err(ObservationOperationError::Static {
                kind: std::io::ErrorKind::Other,
                message: "held page exchange already completed",
            });
        }
        self.context.slice().map_err(|status| {
            ObservationOperationError::Io(std::io::Error::from_raw_os_error(-status))
        })
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        self.wait_slice_for_observation()?;
        self.completed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ObservationOperationError::Static {
                kind: std::io::ErrorKind::Other,
                message: "held page exchange already completed",
            })?;
        Ok(())
    }
}

extern "C" fn read(
    id: u64,
    loan: *mut CandidateLoan,
    address: u64,
    output: *mut u8,
    valid: u32,
    userdata: *mut c_void,
) -> i32 {
    if output.is_null() || valid == 0 || valid as usize > crate::paged_ram::PAGE_BYTES {
        return -libc::EINVAL;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_reader(id, loan, userdata, |context, reader| {
            let operation = PageOperation {
                context,
                completed: AtomicBool::new(false),
            };
            // SAFETY: the actual native reader invokes this callback with its own
            // prepaid initialized 4096-byte private page_scratch, not caller output.
            // No bytes escape native staging until its independent original post.
            let scratch = unsafe { &mut *output.cast::<[u8; crate::paged_ram::PAGE_BYTES]>() };
            let result = reader.read_page(address, valid as usize, &operation, scratch);
            let post = context.slice();
            match (result, post) {
                (Ok(()), Ok(_)) => 0,
                (Err(crate::ram_error::RamError::Native { status, .. }), _) if status < 0 => status,
                (Err(_), _) => -libc::EIO,
                (_, Err(status)) => status,
            }
        })
    }))
    .unwrap_or(-libc::EIO)
}

extern "C" fn observe(
    id: u64,
    loan: *mut CandidateLoan,
    scope: u32,
    refresh: u32,
    record: *mut u8,
    capacity: usize,
    written: *mut usize,
    root: *mut u8,
    logical_bytes: *mut u64,
    userdata: *mut c_void,
) -> i32 {
    if scope > 2
        || refresh > 1
        || written.is_null()
        || root.is_null()
        || logical_bytes.is_null()
        || (record.is_null() && capacity != 0)
    {
        return -libc::EINVAL;
    }
    with_reader(id, loan, userdata, |context, reader| {
        crate::ram_fingerprint::observe_held(
            context,
            reader,
            scope,
            refresh,
            record,
            capacity,
            written,
            root,
            logical_bytes,
        )
    })
}

extern "C" fn cleanup(
    id: u64,
    loan: *mut CandidateLoan,
    provider_owner: *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if loan.is_null() || provider_owner.is_null() || userdata.is_null() {
            return -libc::EINVAL;
        }
        // SAFETY: the same real native cleanup registrar pins this allocation;
        // the synchronous creating-Main invocation begins after installer exit.
        let runtime = unsafe { &*userdata.cast::<OwnedCallbackRuntimeState>() };
        if runtime.plugin_id != Some(id) || runtime.owner_process != std::process::id() {
            return -libc::ESTALE;
        }
        let Some(api) = runtime.checkpoint_api.map(|api| api.reader) else {
            return -libc::ENOSYS;
        };
        let (identity, _semantic_first, _semantic_post) =
            match observe_identity(id, loan, runtime, api) {
                Ok(identity) => identity,
                Err(status) => return status,
            };
        if identity.provider_owner != provider_owner as usize {
            return -libc::ESTALE;
        }
        {
            let Ok(slot) = runtime.checkpoint.try_lock() else {
                return -libc::EBUSY;
            };
            if std::ptr::from_ref(&*slot) as usize != identity.provider_owner
                || slot
                    .provider
                    .as_ref()
                    .is_none_or(|binding| !binding.matches_reader(&identity))
                || slot.binding.as_ref().is_none_or(|binding| {
                    binding.native_transaction_generation != identity.transaction
                })
                || slot.root.is_some()
            {
                return -libc::ESTALE;
            }
            if !matches!(
                slot.owner
                    .as_ref()
                    .map(|owner| owner.check_held_cleanup_identity()),
                Some(Ok(()))
            ) {
                return -libc::EBUSY;
            }
        }
        // The signed initiating cause remains in the native/local journals.
        // Only identity survives expiry here; no semantic reader is constructed.
        crate::ram_fingerprint::cleanup_held_claim(&HeldClaimCleanup {
            finish: api.finish,
            identity,
        })
    }))
    .unwrap_or(-libc::EIO)
}
