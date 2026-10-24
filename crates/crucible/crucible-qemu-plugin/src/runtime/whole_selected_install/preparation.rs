//! One-shot source-authenticated construction on the original stopped RR thread.
//!
//! The 128-byte native tuple is a GPL-local ABI, never a public wire body. The
//! getter runs before source guards. Construction borrows the same retained
//! mapping briefly; native binding and endpoint setters run after that borrow
//! ends. Enrollment does not authorize HOLD, delivery, execution or Ready.

use std::cell::RefCell;
use std::ffi::{c_int, c_void};
use std::sync::OnceLock;

mod mapping_hold;
mod return_observation;

use super::{Arc, Ordering, SharedCallbackCustody, callback_process_current, current_tid};
use crate::runtime::live_callbacks::LiveDirectedRingPair;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativePreparation {
    version: u32,
    size: u32,
    phase: u32,
    cpu_index: u32,
    plugin_id: u64,
    process: u64,
    actual_tid: u64,
    loader_tid: u64,
    deadline_ns: u64,
    callback: usize,
    userdata: *mut c_void,
    constructor: *const c_void,
    cpu: *const c_void,
    permit: *const c_void,
    setup_digest: [u8; 32],
}

impl Default for NativePreparation {
    fn default() -> Self {
        Self {
            version: 1,
            size: 128,
            phase: 0,
            cpu_index: 0,
            plugin_id: 0,
            process: 0,
            actual_tid: 0,
            loader_tid: 0,
            deadline_ns: 0,
            callback: 0,
            userdata: std::ptr::null_mut(),
            constructor: std::ptr::null(),
            cpu: std::ptr::null(),
            permit: std::ptr::null(),
            setup_digest: [0; 32],
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativePreparation>() == 128);
    assert!(std::mem::offset_of!(NativePreparation, plugin_id) == 16);
    assert!(std::mem::offset_of!(NativePreparation, callback) == 56);
    assert!(std::mem::offset_of!(NativePreparation, userdata) == 64);
    assert!(std::mem::offset_of!(NativePreparation, setup_digest) == 96);
};

type PreparationCallback = extern "C" fn(*mut c_void) -> c_int;
type RegisterPreparation = extern "C" fn(u64, PreparationCallback, *mut c_void) -> c_int;
type ReadPreparation = extern "C" fn(*mut NativePreparation) -> c_int;
type BindPrepared = extern "C" fn(*mut c_void) -> c_int;

#[derive(Clone, Copy)]
pub(super) struct PreparationApis {
    register: RegisterPreparation,
    read: ReadPreparation,
    bind: BindPrepared,
    read_return: return_observation::ReadPreparationReturn,
    mapping_hold: Option<mapping_hold::MappingHoldApis>,
    network: crate::QemuRegisterNetTxCbFn,
    block: crate::QemuRegisterBlkCbFn,
    block_event: crate::QemuRegisterBlkEventCbFn,
    block_wait: crate::QemuRegisterBlkWaitCbFn,
    ninep: crate::QemuRegisterNinePCbFn,
}

static APIS: OnceLock<PreparationApis> = OnceLock::new();

thread_local! {
    // This !Send engine is born and retained on the original RR thread. The
    // shared callback owner never stores it or dereferences its opaque address.
    static ENGINE: RefCell<Option<Box<EndpointEngine>>> = const { RefCell::new(None) };
}

impl PreparationApis {
    pub(super) fn resolve(capabilities: super::LiveInstallCapabilities) -> Option<Self> {
        let resolve = |name: &'static std::ffi::CStr| {
            // SAFETY: These names identify only the frozen GPL-local SDK. Each
            // call is separately authorized by its literal native context.
            unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) }
        };
        let register = resolve(c"qemu_plugin_crucible_register_whole_preparation_v1");
        let read = resolve(c"qemu_plugin_crucible_whole_read_preparation_v1");
        let bind = resolve(c"qemu_plugin_crucible_whole_bind_prepared_userdata_v1");
        let read_return = resolve(c"qemu_plugin_crucible_whole_read_preparation_return_v1");
        if register.is_null() || read.is_null() || bind.is_null() || read_return.is_null() {
            return None;
        }
        Some(Self {
            // SAFETY: The frozen native header declares these exact signatures.
            register: unsafe { std::mem::transmute::<*mut c_void, RegisterPreparation>(register) },
            // SAFETY: The edition/size-initialized destination matches tuple128.
            read: unsafe { std::mem::transmute::<*mut c_void, ReadPreparation>(read) },
            // SAFETY: Binding retains only the opaque subordinate address.
            bind: unsafe { std::mem::transmute::<*mut c_void, BindPrepared>(bind) },
            // SAFETY: The frozen source declares the exact initialized tuple144 ABI.
            read_return: unsafe {
                std::mem::transmute::<*mut c_void, return_observation::ReadPreparationReturn>(
                    read_return,
                )
            },
            mapping_hold: mapping_hold::MappingHoldApis::resolve(),
            network: capabilities.register_net_tx?,
            block: capabilities.register_block?,
            block_event: capabilities.register_block_event?,
            block_wait: capabilities.register_block_wait?,
            ninep: capabilities.register_ninep?,
        })
    }

    fn capture(&self) -> Result<NativePreparation, c_int> {
        let mut tuple = NativePreparation::default();
        let status = (self.read)(&mut tuple);
        if status != 0 {
            return Err(status);
        }
        let now = super::monotonic_ns().map_err(|_| -libc::ESTALE)?;
        if tuple.version != 1
            || tuple.size != 128
            || tuple.phase != 1
            || tuple.cpu_index != 0
            || tuple.process != u64::from(std::process::id())
            || tuple.actual_tid != current_tid()?
            || tuple.loader_tid == 0
            || tuple.plugin_id == 0
            || tuple.callback != prepare_on_rr as *const () as usize
            || tuple.userdata.is_null()
            || tuple.constructor.is_null()
            || tuple.cpu.is_null()
            || tuple.permit.is_null()
            || now >= tuple.deadline_ns
        {
            return Err(-libc::ESTALE);
        }
        Ok(tuple)
    }
}

/// Charges fixed engine/TLS/API backing before the original socket is claimed.
pub(super) const fn required_bytes() -> usize {
    std::mem::size_of::<EndpointEngine>()
        + std::mem::size_of::<RefCell<Option<Box<EndpointEngine>>>>()
        + std::mem::size_of::<OnceLock<PreparationApis>>()
}

pub(super) fn register(original: &Arc<SharedCallbackCustody>, apis: PreparationApis) -> c_int {
    if APIS.set(apis).is_err() {
        return -libc::ESTALE;
    }
    (apis.register)(
        original.plugin_id,
        prepare_on_rr,
        Arc::as_ptr(original).cast_mut().cast(),
    )
}

fn tuple_matches(tuple: &NativePreparation, original: &SharedCallbackCustody) -> bool {
    !original.failed.load(Ordering::Acquire)
        && original.observed_vcpus.load(Ordering::Acquire) == 15
        && tuple.plugin_id == original.plugin_id
        && tuple.process == u64::from(original.process)
        && tuple.loader_tid == original.loader_tid
        && tuple.setup_digest == original.setup_digest
        && tuple.constructor as usize == original.constructor_identity.load(Ordering::Acquire)
        && tuple.cpu as usize == original.cpu_identities[0].load(Ordering::Acquire)
}

extern "C" fn prepare_on_rr(userdata: *mut c_void) -> c_int {
    if !callback_process_current() {
        return -libc::ESTALE;
    }
    // The source getter precedes Arc lookup, RR TLS, mapping and journal guards.
    let captured = APIS
        .get()
        .ok_or(-libc::ESTALE)
        .and_then(PreparationApis::capture);
    let Some(original) = super::ORIGINAL_CALLBACK.get() else {
        return -libc::ESTALE;
    };
    let result = captured.and_then(|tuple| {
        if tuple.userdata != userdata
            || userdata != Arc::as_ptr(original).cast_mut().cast()
            || !tuple_matches(&tuple, original)
            || original.preparation_attempted.swap(true, Ordering::AcqRel)
        {
            return Err(-libc::ESTALE);
        }
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prepare_engine(original, tuple)
        }))
        .map_err(|_| -libc::EFAULT)?
    });
    match result {
        Ok(()) => 0,
        Err(status) => {
            // A missing/changed native context permits only this scalar fence.
            // Mapping construction's own helper retains any partial failure.
            original.refuse_callback();
            status
        }
    }
}

fn prepare_engine(
    original: &Arc<SharedCallbackCustody>,
    tuple: NativePreparation,
) -> Result<(), c_int> {
    let setup = original.setup.get().ok_or(-libc::ESTALE)?;
    let pointer = ENGINE
        .try_with(|cell| {
            let mut slot = cell.try_borrow_mut().map_err(|_| -libc::EBUSY)?;
            if slot.is_some() {
                return Err(-libc::ESTALE);
            }
            let engine = setup
                .with_whole_ordinary_preparation(|mapping| {
                    EndpointEngine::new(original, tuple, mapping)
                })
                .map_err(|_| -libc::ESTALE)??;
            *slot = Some(Box::new(engine));
            Ok(slot.as_mut().ok_or(-libc::ESTALE)?.as_mut() as *mut EndpointEngine)
        })
        .map_err(|_| -libc::ESTALE)??;

    // No Rust mapping/TLS borrow crosses any native getter, bind or setter.
    let apis = APIS.get().ok_or(-libc::ESTALE)?;
    if apis.capture()? != tuple || !tuple_matches(&tuple, original) {
        return Err(-libc::ESTALE);
    }
    ENGINE
        .try_with(|cell| {
            let mut slot = cell.try_borrow_mut().map_err(|_| -libc::EBUSY)?;
            slot.as_mut().ok_or(-libc::ESTALE)?.native_visible = true;
            Ok::<(), c_int>(())
        })
        .map_err(|_| -libc::ESTALE)??;
    let status = (apis.bind)(pointer.cast());
    if status != 0 {
        return Err(status);
    }
    (apis.network)(Some(closed_network), pointer.cast());
    (apis.block)(
        Some(closed_block_submit),
        Some(closed_block_poll),
        pointer.cast(),
    );
    (apis.block_event)(
        Some(closed_event_poll),
        Some(closed_event_commit),
        Some(closed_save),
        Some(closed_restore),
        pointer.cast(),
    );
    (apis.block_wait)(Some(closed_wait), pointer.cast());
    (apis.ninep)(
        Some(closed_burst),
        Some(closed_ninep_submit),
        Some(closed_ninep_poll),
        Some(closed_burst),
        pointer.cast(),
    );
    ENGINE
        .try_with(|cell| {
            let mut slot = cell.try_borrow_mut().map_err(|_| -libc::EBUSY)?;
            // This records completed Rust setter calls. The post-return source
            // getter independently checks the actual native retained tables.
            slot.as_mut().ok_or(-libc::ESTALE)?.registered_families = 31;
            Ok::<(), c_int>(())
        })
        .map_err(|_| -libc::ESTALE)??;
    Ok(())
}

/// Dispatches only the separate source-authenticated original mapping HOLD.
pub(super) fn hold_on_rr(
    action: u32,
    status: *mut crate::QemuPluginHotForkBarrierStatus,
    userdata: *mut c_void,
) -> c_int {
    mapping_hold::hold_on_rr(action, status, userdata)
}

#[cfg(test)]
pub(super) fn mapping_failure_control_requested() -> bool {
    mapping_hold::tests::failure_control_requested()
}

/// Retains real original queue adapters and stable handles, without service permission.
struct EndpointEngine {
    native_visible: bool,
    registered_families: u32,
    _original: Arc<SharedCallbackCustody>,
    _birth: NativePreparation,
    mapping_roster: crucible_qemu_shmem::PreparedDirectedRingRoster,
    mapping_hold_journal: mapping_hold::MappingHoldJournal,
    _network_tx: crate::PluginNetworkTx,
    _network_rx: crate::PluginNetworkRx,
    _network_rings: LiveDirectedRingPair,
    _block: crate::PluginBlockIo,
    _block_rings: LiveDirectedRingPair,
    _ninep: crate::PluginNinePIo,
    _ninep_rings: LiveDirectedRingPair,
}

impl EndpointEngine {
    fn new(
        original: &Arc<SharedCallbackCustody>,
        birth: NativePreparation,
        mapping: &mut crucible_qemu_shmem::OrdinaryPreparationView<'_>,
    ) -> Result<Self, c_int> {
        let slot = original.args.slot();
        let network_peer = crucible_qemu_shmem::SLOT_NET_ROUTER as u32;
        let block_peer = crucible_qemu_shmem::SLOT_BLK_IO as u32;
        let ninep_peer = crucible_qemu_shmem::SLOT_9P_IO as u32;

        // The restricted view checks the same six headers and performs actual
        // DONTFORK while the original owner's retention ticket is already armed.
        // The owned exclusion/identity proof is retained until a distinct native
        // HOLD window authorizes its one-shot library transition.
        let mapping_roster = mapping
            .prepare_directed_ring_hold_roster(
                slot,
                [
                    (slot, network_peer),
                    (network_peer, slot),
                    (slot, block_peer),
                    (block_peer, slot),
                    (slot, ninep_peer),
                    (ninep_peer, slot),
                ],
            )
            .map_err(|_| -libc::ESTALE)?;

        let mut pair = |peer| {
            let rings = mapping
                .node_directed_ring_pair_mut(slot, slot, peer, peer, slot)
                .map_err(|_| -libc::EPROTO)?;
            LiveDirectedRingPair::new(rings.first, rings.second).map_err(|_| -libc::EPROTO)
        };
        let network = pair(network_peer)?;
        let block = pair(block_peer)?;
        let ninep = pair(ninep_peer)?;
        let (network_out, _) = network.descriptors();
        let (block_out, block_in) = block.descriptors();
        let (ninep_out, ninep_in) = ninep.descriptors();
        Ok(Self {
            native_visible: false,
            registered_families: 0,
            _original: Arc::clone(original),
            _birth: birth,
            mapping_roster,
            mapping_hold_journal: mapping_hold::MappingHoldJournal::default(),
            _network_tx: crate::PluginNetworkTx::from_directed_ring_with_sequence(
                slot,
                network_out,
                original.args.network_tx_next_seq(),
            )
            .map_err(|_| -libc::EPROTO)?,
            _network_rx: crate::PluginNetworkRx::new(),
            _network_rings: network,
            _block: crate::PluginBlockIo::from_directed_rings_with_history_limits(
                slot,
                block_out,
                block_in,
                original.args.storage_history_limits(),
            )
            .map_err(|_| -libc::EPROTO)?,
            _block_rings: block,
            _ninep: crate::PluginNinePIo::from_directed_rings(slot, ninep_out, ninep_in)
                .map_err(|_| -libc::EPROTO)?,
            _ninep_rings: ninep,
        })
    }
}

impl Drop for EndpointEngine {
    fn drop(&mut self) {
        // Native tables have no unregister operation. An RR thread exit cannot
        // free subordinate userdata while original native tables retain it.
        #[cfg(not(test))]
        if self.native_visible {
            std::process::abort();
        }
    }
}

fn refuse_endpoint() {
    if callback_process_current()
        && let Some(original) = super::ORIGINAL_CALLBACK.get()
    {
        original.refuse_callback();
    }
}

// Enrollment is preparation only. Until genuine source endpoint dispatch and
// exact staged membership are installed, callbacks neither dereference buffers
// nor borrow RR TLS/rings/tokens, publish time or pump ordinary due inputs.
extern "C" fn closed_network(_: *const u8, _: usize, _: u64, _: *mut c_void) -> c_int {
    refuse_endpoint();
    -libc::ENOTSUP
}

extern "C" fn closed_block_submit(
    _: u64,
    _: u32,
    _: u32,
    _: u64,
    _: *const u8,
    _: usize,
    _: *mut c_void,
) -> c_int {
    refuse_endpoint();
    -libc::ENOTSUP
}

extern "C" fn closed_block_poll(_: u64, _: u32, _: *mut u8, _: usize, _: *mut c_void) -> i64 {
    refuse_endpoint();
    -i64::from(libc::ENOTSUP)
}

extern "C" fn closed_event_poll(_: *mut u8, _: usize, _: *mut c_void) -> i64 {
    refuse_endpoint();
    -i64::from(libc::ENOTSUP)
}

extern "C" fn closed_event_commit(_: *mut c_void) -> c_int {
    refuse_endpoint();
    -libc::ENOTSUP
}

extern "C" fn closed_save(_: *mut u8, _: usize, _: *mut c_void) -> i64 {
    refuse_endpoint();
    -i64::from(libc::ENOTSUP)
}

extern "C" fn closed_restore(_: *const u8, _: usize, _: u64, _: u32, _: *mut c_void) -> c_int {
    refuse_endpoint();
    -libc::ENOTSUP
}

extern "C" fn closed_wait(_: u32, _: *mut c_void) {
    refuse_endpoint();
}

extern "C" fn closed_burst(_: *mut c_void) {
    refuse_endpoint();
}

extern "C" fn closed_ninep_submit(
    _: u32,
    _: *const u8,
    _: usize,
    _: usize,
    _: *mut c_void,
) -> c_int {
    refuse_endpoint();
    -libc::ENOTSUP
}

extern "C" fn closed_ninep_poll(_: u32, _: *mut u8, _: usize, _: *mut c_void) -> i64 {
    refuse_endpoint();
    -i64::from(libc::ENOTSUP)
}

#[cfg(test)]
#[path = "preparation_tests.rs"]
mod tests;

#[cfg(test)]
impl PreparationApis {
    pub(super) fn modeled() -> Self {
        tests::modeled_apis()
    }
}

#[cfg(test)]
pub(super) fn exercise_preparation(original: Arc<SharedCallbackCustody>) {
    tests::exercise_preparation(original);
}

#[cfg(test)]
pub(super) fn exercise_refusal(original: &Arc<SharedCallbackCustody>) {
    tests::exercise_refusal(original);
}
