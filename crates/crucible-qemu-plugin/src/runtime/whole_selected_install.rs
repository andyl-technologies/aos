//! Held selected installation on the original constructor socket.
//!
//! The stopped loader prepares finite journals before taking close custody of
//! native FD3. Setup completion returns to machine construction without a RUN
//! wait. The native controller is registered with explicitly unavailable
//! execution callbacks until genuine source binding and services are installed;
//! none of these callbacks can acknowledge adoption or source readiness.

use std::cell::RefCell;
use std::ffi::{c_int, c_void};
use std::os::fd::AsRawFd;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use crucible_protocol::whole_control::staged::StagedControlProfile;
use thiserror::Error;

use crate::{PluginArgs, PluginSetupCompletion, QemuPluginId};

use super::whole_initial_setup::OriginalWholeInitialSetup;
use super::whole_journals::WholeJournals;
use super::whole_native_abi::*;
use super::whole_original_socket::OriginalWholeSocket;
use super::whole_source_ready::OriginalWholeReadyExchange;
use super::{
    LiveInstallCapabilities, PluginRuntimeInstallError, PluginRuntimeReservation,
    PostRegistrationFatalPolicy,
};

// The original birth PID is published before callback registration. Callback
// entry checks this lock-free scalar before any copied TLS or userdata access.
static ORIGINAL_PROCESS: AtomicU32 = AtomicU32::new(0);

thread_local! {
    // The native API authenticates the original loader/RR thread. This owning
    // slot is published before FD claim, and is never replaced on failure.
    static ORIGINAL: RefCell<Option<Rc<SelectedCustody>>> = const { RefCell::new(None) };
}

/// Identifies a refusal retained by the original selected installation.
#[derive(Debug, Error)]
pub enum SelectedInstallError {
    /// The complete native descriptor has an unsupported or malformed shape.
    #[error("original selected constructor geometry was refused")]
    Geometry,
    /// Original finite backing cannot cover this preparation.
    #[error("original selected preparation backing was refused")]
    Capacity,
    /// This process/thread already owns another selected preparation.
    #[error("original selected preparation owner is unavailable")]
    Owner,
    /// The actual native stopped-installer API refused an operation.
    #[error("original selected native operation was refused with status {0}")]
    Native(i32),
    /// An original retained initial cursor or descriptor transfer failed.
    #[error("original selected initial transfer was refused")]
    Initial,
    /// The authentic SCM setup descriptor or original mapping failed validation.
    #[error("original selected setup authentication failed: {0}")]
    Setup(#[from] crate::PluginSetupError),
    /// Selected preparation panicked while retaining its original owner.
    #[error("original selected preparation panicked")]
    Panic,
    /// The original monotonic clock/deadline or bounded readiness wait failed.
    #[error("original selected initial readiness wait was refused")]
    Wait,
}

#[derive(Clone, Copy, Default)]
struct WaitAttempt {
    observed_ns: u64,
    interest: i16,
    returned: i16,
    status: c_int,
}

struct SelectedCustody {
    process: u32,
    plugin_id: QemuPluginId,
    args: PluginArgs,
    profile: StagedControlProfile,
    apis: NativeWholeApis,
    original_body: Box<[u8]>,
    socket: Arc<OriginalWholeSocket>,
    initial: RefCell<OriginalWholeInitialSetup>,
    journals: Arc<WholeJournals>,
    ready: RefCell<OriginalWholeReadyExchange>,
    setup: OnceLock<PluginSetupCompletion>,
    waits: RefCell<Box<[WaitAttempt]>>,
    wait_count: RefCell<usize>,
    failed: AtomicBool,
    callback_entry: AtomicBool,
    observed_vcpus: AtomicU8,
}

impl Drop for SelectedCustody {
    fn drop(&mut self) {
        // Native registration has no unregister/close transfer. A thread exit
        // cannot destroy callback userdata or the original socket while QEMU
        // may still call it. Process termination is the closed lifetime limit.
        #[cfg(not(test))]
        if self.socket.descriptor().is_ok() {
            std::process::abort();
        }
    }
}

/// Owns installed-held preparation without boot release or a Ready proof.
pub(super) struct SelectedRuntimeOwner {
    original: Rc<SelectedCustody>,
}

impl SelectedRuntimeOwner {
    pub(super) fn retain_preparing(self) {
        // The constructor already installed the same strong owner in ORIGINAL.
        // Dropping this additional reference cannot release any source object.
        let _same_original = self.original;
    }
}

/// Resolves the genuine prerequisite setters for the same native userdata.
struct SelectedRegistrationApis {
    vcpu_init: crate::QemuRegisterVcpuInitCbFn,
    barrier: crate::QemuRegisterHotForkBarrierFn,
    control: crate::QemuRegisterControlBoundaryCbFn,
}

/// Installs the bounded original Setup/ACK and a closed native controller.
///
/// The complete source interpreter remains unavailable. Registration is an
/// ownership operation, not successful adoption: every effect-bearing callback
/// returns ENOTSUP and fences the same original owner. No ordinary callback,
/// worker, boot release or RUN lifecycle transition is installed here.
pub(super) fn install(
    plugin_id: QemuPluginId,
    args: PluginArgs,
    descriptor: NativeEarlySetup<'_>,
    capabilities: LiveInstallCapabilities,
    reservation: &mut PluginRuntimeReservation,
) -> Result<SelectedRuntimeOwner, PluginRuntimeInstallError> {
    install_inner(plugin_id, args, descriptor, capabilities, reservation)
        .map_err(|source| PluginRuntimeInstallError::SelectedPreparation { source })
}

fn install_inner(
    plugin_id: QemuPluginId,
    args: PluginArgs,
    descriptor: NativeEarlySetup<'_>,
    capabilities: LiveInstallCapabilities,
    reservation: &mut PluginRuntimeReservation,
) -> Result<SelectedRuntimeOwner, SelectedInstallError> {
    let apis = NativeWholeApis::resolve().ok_or(SelectedInstallError::Native(-libc::ENOTSUP))?;
    let callbacks = SelectedRegistrationApis {
        vcpu_init: capabilities
            .register_vcpu_init
            .ok_or(SelectedInstallError::Native(-libc::ENOTSUP))?,
        barrier: capabilities.register_hot_fork_barrier,
        control: capabilities
            .register_control_boundary
            .ok_or(SelectedInstallError::Native(-libc::ENOTSUP))?,
    };
    install_preowned(plugin_id, args, descriptor, reservation, apis, callbacks)
}

fn install_preowned(
    plugin_id: QemuPluginId,
    args: PluginArgs,
    descriptor: NativeEarlySetup<'_>,
    reservation: &mut PluginRuntimeReservation,
    apis: NativeWholeApis,
    callbacks: SelectedRegistrationApis,
) -> Result<SelectedRuntimeOwner, SelectedInstallError> {
    let (profile, selection_bytes) = original_geometry(descriptor.body)?;
    let policy =
        NativeWholePolicy::from_profile(&profile).map_err(|_| SelectedInstallError::Geometry)?;
    let budget =
        NativeWholeBudget::from_profile(&profile).map_err(|_| SelectedInstallError::Geometry)?;
    let waits = profile
        .compute
        .administrative_read_attempt_limit
        .checked_add(profile.compute.administrative_write_attempt_limit)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(SelectedInstallError::Capacity)?;
    let wait_bytes = waits
        .checked_mul(std::mem::size_of::<WaitAttempt>())
        .ok_or(SelectedInstallError::Capacity)?;
    let other = [
        2 * descriptor.body.len(),
        selection_bytes,
        wait_bytes,
        std::mem::size_of::<SelectedCustody>(),
        std::mem::size_of::<PluginSetupCompletion>(),
        std::mem::size_of::<OriginalWholeInitialSetup>(),
        std::mem::size_of::<OriginalWholeReadyExchange>(),
        // Three constructor-owned Rc/Arc allocations retain their control words.
        6 * std::mem::size_of::<usize>(),
    ]
    .into_iter()
    .try_fold(0u64, |sum, size| sum.checked_add(size as u64))
    .ok_or(SelectedInstallError::Capacity)?;
    let socket_bytes = OriginalWholeSocket::required_bytes(&profile)
        .map_err(|_| SelectedInstallError::Capacity)?;
    let journals = Arc::new(
        WholeJournals::new(
            &profile,
            other
                .checked_add(socket_bytes)
                .ok_or(SelectedInstallError::Capacity)?,
        )
        .map_err(|_| SelectedInstallError::Capacity)?,
    );
    let socket = Arc::new(
        OriginalWholeSocket::prepare(
            &profile,
            journals
                .retained_byte_count()
                .checked_sub(socket_bytes)
                .ok_or(SelectedInstallError::Capacity)?,
        )
        .map_err(|_| SelectedInstallError::Capacity)?,
    );
    let ready = OriginalWholeReadyExchange::prepare(Arc::clone(&socket), &profile)
        .map_err(|_| SelectedInstallError::Capacity)?;
    let mut wait_backing = Vec::new();
    wait_backing
        .try_reserve_exact(waits)
        .map_err(|_| SelectedInstallError::Capacity)?;
    wait_backing.resize(waits, WaitAttempt::default());
    let mut full_body = Vec::new();
    full_body
        .try_reserve_exact(descriptor.body.len())
        .map_err(|_| SelectedInstallError::Capacity)?;
    full_body.extend_from_slice(descriptor.body);
    let original = Rc::new(SelectedCustody {
        process: std::process::id(),
        plugin_id,
        args,
        profile,
        apis,
        original_body: descriptor.body.into(),
        initial: RefCell::new(OriginalWholeInitialSetup::new(Arc::clone(&socket))),
        socket,
        journals,
        ready: RefCell::new(ready),
        setup: OnceLock::new(),
        waits: RefCell::new(wait_backing.into_boxed_slice()),
        wait_count: RefCell::new(0),
        failed: AtomicBool::new(false),
        callback_entry: AtomicBool::new(false),
        observed_vcpus: AtomicU8::new(0),
    });
    let process = std::process::id();
    if ORIGINAL_PROCESS
        .compare_exchange(0, process, Ordering::AcqRel, Ordering::Acquire)
        .is_err_and(|original_process| original_process != process)
    {
        return Err(SelectedInstallError::Owner);
    }
    ORIGINAL.with(|slot| {
        let mut slot = slot
            .try_borrow_mut()
            .map_err(|_| SelectedInstallError::Owner)?;
        if slot.is_some() {
            return Err(SelectedInstallError::Owner);
        }
        *slot = Some(Rc::clone(&original));
        Ok(())
    })?;

    // The reachable owning slot precedes the literal native FD transfer. There
    // is no dup, interrupt stream, replacement actor or post-HELLO constructor.
    reservation.mark_irreversible();
    let stream = match original
        .apis
        .claim_control_socket(plugin_id, original.args.sim_fd())
    {
        Ok(stream) => stream,
        Err(status) => {
            original.refuse(0, std::ptr::null_mut());
            return Err(SelectedInstallError::Native(status));
        }
    };
    if original.socket.install_original_socket(stream).is_err() {
        // The literal one-shot transfer cannot race a second original install.
        // Terminate before an unowned returned stream could close native FD3.
        std::process::abort();
    }
    let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        loop {
            original.wait_initial()?;
            let now = monotonic_ns()?;
            if original
                .initial
                .try_borrow_mut()
                .map_err(|_| SelectedInstallError::Owner)?
                .poll_setup(&original.args, now)
                .map_err(|_| SelectedInstallError::Initial)?
            {
                break;
            }
        }
        let handshake = original
            .initial
            .try_borrow()
            .map_err(|_| SelectedInstallError::Owner)?
            .handshake()
            .map_err(|_| SelectedInstallError::Initial)?;
        // No initial cursor, mapping or device guard spans native authentication.
        let setup = crate::setup::prepare_selected_setup_completion(
            plugin_id,
            &original.apis,
            Arc::clone(&original.socket),
            full_body.into_boxed_slice(),
            handshake,
        )?;
        if setup.original_setup_body() != original.original_body.as_ref()
            || setup.whole_constructor().is_none_or(|selection| {
                selection.profile() != &original.profile || selection.launch_version() != 2
            })
        {
            return Err(SelectedInstallError::Geometry);
        }
        setup
            .prepare_whole_mapping_intent_retention()
            .map_err(|_| SelectedInstallError::Capacity)?;
        original
            .setup
            .set(setup)
            .map_err(|_| SelectedInstallError::Owner)?;
        let userdata = Rc::as_ptr(&original).cast_mut().cast();
        // A setter may retain a Rust callback before returning. Every
        // subsequent error terminates instead of allowing the loader to unload
        // this cdylib; the owning slot remains reachable throughout entry.
        original.callback_entry.store(true, Ordering::Release);
        // The literal native vCPU registration records this plugin identity.
        // Observation remains preparation-only and cannot issue source Ready.
        (callbacks.vcpu_init)(plugin_id, observe_preparing_vcpu, userdata);
        (callbacks.control)(Some(closed_control_boundary), userdata);
        let status = (callbacks.barrier)(plugin_id, Some(closed_barrier), userdata);
        if status != 0 {
            return Err(SelectedInstallError::Native(status));
        }
        let status = (original.apis.register)(
            plugin_id,
            &policy,
            &budget,
            &CLOSED_OPS,
            Rc::as_ptr(&original).cast_mut().cast(),
        );
        if status != 0 {
            return Err(SelectedInstallError::Native(status));
        }
        loop {
            original.wait_initial()?;
            let now = monotonic_ns()?;
            if original
                .initial
                .try_borrow_mut()
                .map_err(|_| SelectedInstallError::Owner)?
                .poll_setup_ack(0, now)
                .map_err(|_| SelectedInstallError::Initial)?
            {
                break;
            }
        }
        Ok(())
    }));
    let prepared = match prepared {
        Ok(result) => result,
        Err(_) => Err(SelectedInstallError::Panic),
    };
    if let Err(error) = prepared {
        original.refuse(0, std::ptr::null_mut());
        if original.callback_entry.load(Ordering::Acquire) {
            super::AbortPostRegistrationFailure
                .terminate(PluginRuntimeInstallError::SelectedPreparation { source: error });
        }
        return Err(error);
    }
    Ok(SelectedRuntimeOwner { original })
}

impl SelectedCustody {
    fn wait_initial(&self) -> Result<(), SelectedInstallError> {
        if self.process != std::process::id() || self.failed.load(Ordering::Acquire) {
            return Err(SelectedInstallError::Owner);
        }
        let now = monotonic_ns()?;
        let remaining = self
            .profile
            .compute
            .deadline_monotonic_ns
            .checked_sub(now)
            .filter(|remaining| *remaining != 0)
            .ok_or(SelectedInstallError::Wait)?;
        let interest = self
            .initial
            .try_borrow()
            .map_err(|_| SelectedInstallError::Owner)?
            .readiness_interest()
            .map_err(|_| SelectedInstallError::Initial)?;
        let mut count = self
            .wait_count
            .try_borrow_mut()
            .map_err(|_| SelectedInstallError::Owner)?;
        let mut waits = self
            .waits
            .try_borrow_mut()
            .map_err(|_| SelectedInstallError::Owner)?;
        let attempt = waits.get_mut(*count).ok_or(SelectedInstallError::Wait)?;
        *count += 1;
        attempt.observed_ns = now;
        attempt.interest = interest;
        let timeout = remaining.div_ceil(1_000_000).min(c_int::MAX as u64) as c_int;
        let mut poll = libc::pollfd {
            fd: self
                .socket
                .descriptor()
                .map_err(|_| SelectedInstallError::Owner)?
                .as_raw_fd(),
            events: interest,
            revents: 0,
        };
        // SAFETY: One original borrowed FD and fixed local poll record remain
        // live. This kernel wait cannot invoke any QEMU/plugin callback.
        let status = unsafe { libc::poll(&mut poll, 1, timeout) };
        attempt.status = status;
        attempt.returned = poll.revents;
        // A readable final prefix must reach the original byte/FD journal
        // even when the peer has closed. The following bounded read records
        // buffered bytes or actual EOF before the cursor interprets failure.
        let readable_close = interest == libc::POLLIN && poll.revents & libc::POLLHUP != 0;
        if status <= 0
            || poll.revents & libc::POLLNVAL != 0
            || (!readable_close && poll.revents & interest == 0)
        {
            return Err(SelectedInstallError::Wait);
        }
        Ok(())
    }

    fn refuse(&self, sequence: u64, allocation: *mut c_void) {
        self.failed.store(true, Ordering::Release);
        super::whole_compute_scope::refuse_native_compute_input_scope();
        if self.process != std::process::id() {
            return;
        }
        if let Some(setup) = self.setup.get() {
            setup.refuse_whole_mapping_control();
        }
        if let Ok(compute) = self.journals.compute_allocation(sequence, allocation) {
            compute.refuse();
        }
    }
}

fn monotonic_ns() -> Result<u64, SelectedInstallError> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: CLOCK_MONOTONIC writes exactly one live local timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(SelectedInstallError::Wait);
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|ns| {
            u64::try_from(time.tv_nsec)
                .ok()
                .filter(|part| *part < 1_000_000_000)
                .and_then(|part| ns.checked_add(part))
        })
        .ok_or(SelectedInstallError::Wait)
}

fn original_geometry(body: &[u8]) -> Result<(StagedControlProfile, usize), SelectedInstallError> {
    let u32_at = |bytes: &[u8], offset: usize| -> Result<u32, SelectedInstallError> {
        let raw: [u8; 4] = bytes
            .get(offset..offset + 4)
            .ok_or(SelectedInstallError::Geometry)?
            .try_into()
            .map_err(|_| SelectedInstallError::Geometry)?;
        Ok(u32::from_be_bytes(raw))
    };
    if body.get(..8) != Some(b"CRUCSUP2")
        || u32_at(body, 8)? != 3
        || u32_at(body, 12)? != 36
        || u32_at(body, 16)? as usize != body.len()
        || u32_at(body, 32)? != 0
    {
        return Err(SelectedInstallError::Geometry);
    }
    let app = u32_at(body, 20)? as usize;
    let catalog = u32_at(body, 24)? as usize;
    // The actual native selected interpreter currently admits only cold empty
    // application/catalog cohorts. This restriction is explicit ENOTSUP;
    // future nonempty cohorts need their own complete constructor accounting.
    if app != 16 || catalog != 112 {
        return Err(SelectedInstallError::Native(-libc::ENOTSUP));
    }
    let app_body = body.get(36..52).ok_or(SelectedInstallError::Geometry)?;
    let catalog_body = body.get(52..164).ok_or(SelectedInstallError::Geometry)?;
    if u32_at(app_body, 12)? != 0
        || [20, 28, 32, 36, 92]
            .into_iter()
            .any(|offset| !matches!(u32_at(catalog_body, offset), Ok(0)))
    {
        return Err(SelectedInstallError::Native(-libc::ENOTSUP));
    }
    let selection = body.get(164..).ok_or(SelectedInstallError::Geometry)?;
    if selection.len() != u32_at(body, 28)? as usize
        || selection.get(..8) != Some(b"CWHLSEL\0")
        || u32_at(selection, 8)? != 3
        || u32_at(selection, 12)? as usize != selection.len()
        || !(1..=6).contains(&u32_at(selection, 184)?)
        || u32_at(selection, 188)? != 0
        || u32_at(selection, 196)? != 2
        || !(200..=crucible_protocol::whole_control::staged::selection::WHOLE_SELECTION_MAX_BYTES)
            .contains(&selection.len())
    {
        return Err(SelectedInstallError::Geometry);
    }
    let profile = StagedControlProfile::decode(
        selection
            .get(16..184)
            .ok_or(SelectedInstallError::Geometry)?,
    )
    .map_err(|_| SelectedInstallError::Geometry)?;
    profile
        .validate_ready_exchange_capacity()
        .map_err(|_| SelectedInstallError::Geometry)?;
    Ok((profile, selection.len()))
}

fn callback_process_current() -> bool {
    let process = ORIGINAL_PROCESS.load(Ordering::Acquire);
    if process == 0 {
        return false;
    }
    if process != std::process::id() {
        // SAFETY: A selected fork child must terminate before entering copied
        // TLS, guards, userdata, native objects or logging. _exit performs no
        // Rust unwinding or destructor execution on inherited source custody.
        unsafe { libc::_exit(70) };
    }
    true
}

fn refuse_original(userdata: *mut c_void, sequence: u64, allocation: *mut c_void) {
    if !callback_process_current() {
        return;
    }
    let _available = ORIGINAL.try_with(|slot| {
        if let Ok(slot) = slot.try_borrow()
            && let Some(original) = slot.as_ref()
            && Rc::as_ptr(original).cast_mut().cast::<c_void>() == userdata
        {
            original.refuse(sequence, allocation);
        }
    });
}

/// Records actual vCPU-init callbacks without granting execution or Ready.
extern "C" fn observe_preparing_vcpu(cpu: u32, userdata: *mut c_void) {
    if !callback_process_current() {
        return;
    }
    let _available = ORIGINAL.try_with(|slot| {
        if let Ok(slot) = slot.try_borrow()
            && let Some(original) = slot.as_ref()
            && Rc::as_ptr(original).cast_mut().cast::<c_void>() == userdata
        {
            if original.process != std::process::id()
                || original.failed.load(Ordering::Acquire)
                || cpu >= 4
            {
                original.refuse(0, std::ptr::null_mut());
                return;
            }

            let bit = 1u8 << cpu;
            if original.observed_vcpus.fetch_or(bit, Ordering::AcqRel) & bit != 0 {
                // An initializer cannot replace an original CPU incarnation.
                original.refuse(0, std::ptr::null_mut());
            }
        }
    });
}

/// Refuses the exact selected control path before any legacy publication.
extern "C" fn closed_control_boundary(_cpu: u32, _raw: u64, userdata: *mut c_void) {
    refuse_original(userdata, 0, std::ptr::null_mut());
}

/// Retains the same setup owner while genuine whole HOLD remains unavailable.
extern "C" fn closed_barrier(
    _action: u32,
    _status: *mut crate::QemuPluginHotForkBarrierStatus,
    userdata: *mut c_void,
) -> c_int {
    refuse_original(userdata, 0, std::ptr::null_mut());
    -libc::ENOTSUP
}

// This installed preparation table has no positive execution implementation.
// Even matching public metadata cannot enter native source adoption or effects.
macro_rules! unavailable {
    ($name:ident($userdata:ident $(, $argument:ident: $ty:ty)*)) => {
        extern "C" fn $name($userdata: *mut c_void $(, $argument: $ty)*) -> c_int {
            $(let _ = $argument;)*
            refuse_original($userdata, 0, std::ptr::null_mut());
            -libc::ENOTSUP
        }
    };
}

unavailable!(adopt(userdata, epoch:u64, process:u64, barrier:u64));
unavailable!(control(userdata, kind:u32, epoch:u64));
unavailable!(get_body(userdata, body:*mut u8, capacity:usize, extent:*mut usize));
unavailable!(reserve(userdata, request:*const u8, extent:usize, result:usize, bytes:u64, records:u64, allocation:*mut *mut c_void));
unavailable!(scope(userdata, epoch:u64, sequence:u64, allocation:*mut c_void));
unavailable!(retain_result(userdata, allocation:*mut c_void, body:*const u8, extent:usize));
unavailable!(retain_ack(userdata, body:*const u8, extent:usize));
unavailable!(prepare_inputs(userdata, epoch:u64, sequence:u64, allocation:*mut c_void, body:*const u8, extent:usize, start:u64, limit:u64));
unavailable!(service(userdata, epoch:u64, sequence:u64, allocation:*mut c_void, time:u64));
unavailable!(collect(userdata, epoch:u64, sequence:u64, allocation:*mut c_void, time:u64, body:*mut u8, capacity:usize, extent:*mut usize, totals:*mut NativeWholeIoTotals));
unavailable!(retire(userdata, epoch:u64, sequence:u64, allocation:*mut c_void, cut:u64, ps:u64, raw:u64, request:*const u8, request_extent:usize, result:*const u8, result_extent:usize, ack:*const u8, ack_extent:usize));
unavailable!(binding(userdata, process:u64, barrier:u64, epoch:u64, body:*mut u8, capacity:usize, extent:*mut usize));
unavailable!(reserve_stage(userdata, epoch:u64, stage:u64, body:*const u8, extent:usize, allocation:*mut *mut c_void, actual:*mut NativeWholeIoTotals, digest:*mut u8));
unavailable!(stage_body(userdata, epoch:u64, stage:u64, allocation:*mut c_void, body:*const u8, extent:usize));
unavailable!(get_commit(userdata, epoch:u64, stage:u64, allocation:*mut c_void, body:*mut u8, capacity:usize, extent:*mut usize));
unavailable!(next_input(userdata, epoch:u64, sequence:u64, allocation:*mut c_void, now:u64, limit:u64, next:*mut u64));

extern "C" fn refuse(userdata: *mut c_void, _epoch: u64, sequence: u64, allocation: *mut c_void) {
    refuse_original(userdata, sequence, allocation);
}

static CLOSED_OPS: NativeWholeOps = NativeWholeOps {
    history: NativeWholeOpsHistory {
        service: NativeWholeOpsService {
            retained: NativeWholeOpsRetained {
                version: 5,
                size: std::mem::size_of::<NativeWholeOps>() as u32,
                adopt_held: adopt,
                control_boundary: control,
                get_request: get_body,
                reserve_result: reserve,
                scope_begin: scope,
                scope_end: scope,
                retain_result,
                get_acknowledgement: get_body,
                retain_consumed_acknowledgement: retain_ack,
            },
            prepare_inputs,
            service_inputs_at: service,
            collect_stopped: collect,
            collect_uncertain: collect,
        },
        retire_stopped: retire,
    },
    read_original_binding: binding,
    reserve_stage,
    validate_stage_current: stage_body,
    retain_stage_receipt: stage_body,
    get_stage_commit: get_commit,
    retain_consumed_stage_commit: stage_body,
    validate_stage_references: stage_body,
    refuse_local_scope: refuse,
    publish_retired: retire,
    next_inputs_at: next_input,
    settle_outputs_at: service,
    offer_source_ready: retain_ack,
    get_source_ready_ack: get_body,
    publish_consumed_source_ready_ack: retain_ack,
};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    // crucible-lint: allow panic-shortcut -- Actual Unix setup controls model only the private native API peers.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_protocol::bounded_setup::SetupSendJournal;
    use crucible_protocol::whole_control::staged::administrative::AdministrativeIoBudget;
    use crucible_protocol::{
        CONTROL_PROTOCOL_VERSION, HostHandshakeConfig, PluginMsg, control_decode_plugin_msg,
        host_accept_handshake, read_control_frame,
    };
    use crucible_shmem::{RegionAllocation, RegionConfig};
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    const PUBLIC_SETUP: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crucible-protocol/src/whole_control/testdata/host-setup-launch2-complete.bin"
    ));
    thread_local! {
        static REGISTERED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static VCPU_PLUGIN_ID: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static VCPU_USERDATA: std::cell::Cell<*mut c_void> = const { std::cell::Cell::new(std::ptr::null_mut()) };
        static CONTROL_USERDATA: std::cell::Cell<*mut c_void> = const { std::cell::Cell::new(std::ptr::null_mut()) };
        static BARRIER_USERDATA: std::cell::Cell<*mut c_void> = const { std::cell::Cell::new(std::ptr::null_mut()) };
    }

    // These functions model the literal source's authorization results. Native
    // loader/BQL/source-cut checks are not executed by this Unix actor control.
    extern "C" fn claim(_id: u64, expected: c_int, owned: *mut c_int) -> c_int {
        // SAFETY: The claim helper provides one live output integer; the test
        // transferred the same original stream into its simulated native owner.
        unsafe { owned.write(expected) };
        0
    }
    extern "C" fn read_setup(
        _id: u64,
        _body: *mut *const u8,
        _extent: *mut usize,
        _digest: *mut u8,
    ) -> c_int {
        -libc::ENOTSUP
    }
    extern "C" fn authenticate(_id: u64, _fd: c_int, _digest: *const u8) -> c_int {
        0
    }
    extern "C" fn observe(_body: *mut NativeWholeBinding) -> c_int {
        -libc::ENOTSUP
    }
    extern "C" fn stage(_body: *const u8, _extent: usize) -> c_int {
        -libc::ENOTSUP
    }
    extern "C" fn register(
        id: u64,
        policy: *const NativeWholePolicy,
        budget: *const NativeWholeBudget,
        ops: *const NativeWholeOps,
        userdata: *mut c_void,
    ) -> c_int {
        assert!(!policy.is_null() && !budget.is_null() && !ops.is_null() && !userdata.is_null());
        // SAFETY: The stopped constructor supplies these live process-local ABI records.
        let ops = unsafe { &*ops };
        assert_eq!(ops.history.service.retained.version, 5);
        assert_eq!(ops.history.service.retained.size, 232);
        assert_eq!(VCPU_PLUGIN_ID.get(), id);
        assert_eq!(VCPU_USERDATA.get(), userdata);
        assert_eq!(CONTROL_USERDATA.get(), userdata);
        assert_eq!(BARRIER_USERDATA.get(), userdata);
        REGISTERED.set(true);
        0
    }

    extern "C" fn register_vcpu_init(
        id: u64,
        callback: crate::abi::QemuVcpuSimpleCbFn,
        userdata: *mut c_void,
    ) {
        VCPU_PLUGIN_ID.set(id);
        VCPU_USERDATA.set(userdata);
        // This models literal callback delivery, not native CPU construction.
        callback(0, userdata);
    }

    extern "C" fn register_control(
        callback: Option<crate::QemuVcpuIdleResumeCbFn>,
        userdata: *mut c_void,
    ) {
        assert!(callback.is_some());
        CONTROL_USERDATA.set(userdata);
    }

    extern "C" fn register_barrier(
        _id: u64,
        callback: Option<crate::QemuPluginHotForkBarrierCbFn>,
        userdata: *mut c_void,
    ) -> c_int {
        assert!(callback.is_some());
        assert_eq!(CONTROL_USERDATA.get(), userdata);
        BARRIER_USERDATA.set(userdata);
        0
    }

    fn modeled_apis() -> NativeWholeApis {
        NativeWholeApis {
            claim_control: claim,
            read_early_setup: read_setup,
            authenticate_setup: authenticate,
            read_native_binding: observe,
            register,
            offer_stage: stage,
            retirement:
                super::super::whole_native_retirement::NativeRetirementApi::unavailable_for_test(),
        }
    }

    #[test]
    fn selected_geometry_refuses_unsupported_cohorts_and_changed_reserved_extents() {
        original_geometry(PUBLIC_SETUP).unwrap();
        for offset in [8, 12, 16, 28, 32, 164 + 8, 164 + 12, 164 + 188, 164 + 196] {
            let mut changed = PUBLIC_SETUP.to_vec();
            changed[offset + 3] ^= 1;
            assert!(original_geometry(&changed).is_err(), "offset {offset}");
        }
        let mut nonempty = PUBLIC_SETUP.to_vec();
        nonempty[36 + 15] = 1;
        assert!(
            matches!(original_geometry(&nonempty),Err(SelectedInstallError::Native(error)) if error == -libc::ENOTSUP)
        );
        assert!(!REGISTERED.get());
    }

    #[test]
    fn closed_selected_table_never_acknowledges_an_effect_from_metadata_or_foreign_pointers() {
        let foreign = 1usize as *mut c_void;
        let untouched = 1usize as *mut u8;
        assert_eq!(
            (CLOSED_OPS.history.service.retained.adopt_held)(foreign, 1, 1, 1),
            -libc::ENOTSUP
        );
        assert_eq!(
            (CLOSED_OPS.history.service.retained.get_request)(
                foreign,
                untouched,
                65536,
                1usize as *mut usize
            ),
            -libc::ENOTSUP
        );
        assert_eq!(
            (CLOSED_OPS.offer_source_ready)(foreign, untouched, 344),
            -libc::ENOTSUP
        );
        assert_eq!(
            (CLOSED_OPS.publish_consumed_source_ready_ack)(foreign, untouched, 128),
            -libc::ENOTSUP
        );
        assert!(!REGISTERED.get());
    }

    #[test]
    fn original_selected_setup_returns_before_machine_init_run_or_source_ready() {
        let _runtime = super::super::isolate_runtime_state_for_test();
        let mut body = PUBLIC_SETUP.to_vec();
        // The public fixture's provider floor is intentionally not a Rust
        // constructor qualification. This modeled selection admits the actual
        // complete actor/journal backing and one fixed initial deadline.
        let profile_offset = 164 + 16;
        body[profile_offset + 64..profile_offset + 72]
            .copy_from_slice(&(16u64 * 1024 * 1024).to_be_bytes());
        body[profile_offset + 104..profile_offset + 112]
            .copy_from_slice(&(monotonic_ns().unwrap() + 5_000_000_000).to_be_bytes());
        let (profile, _) = original_geometry(&body).unwrap();
        let digest: [u8; 32] = Sha256::digest(&body).into();
        let (source, mut host) = UnixStream::pair().unwrap();
        let original_fd = source.into_raw_fd();
        let args = PluginArgs::parse(&format!("simfd={original_fd},slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576")).unwrap();
        let region = RegionAllocation::new_model(RegionConfig::new(1, 16)).unwrap();
        let region_bytes = region.setup_region_bytes().unwrap();
        let node_count = region.layout().node_count;
        let path = std::env::temp_dir().join(format!(
            "selected-original-{}-{}.region",
            std::process::id(),
            original_fd
        ));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&region_bytes).unwrap();
        let length = region_bytes.len() as u64;
        // This memfd is the public protocol's sealed setup descriptor, not a
        // build directory or a substitute for disk-backed scratch storage.
        let setup = crate::setup::test_sealed_setup_plan_fd(&body);
        // SAFETY: Linux returns a fresh owned eventfd, checked before adoption.
        let wake_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(wake_raw >= 0);
        // SAFETY: The successful eventfd call returned unique close custody.
        let wake = unsafe { OwnedFd::from_raw_fd(wake_raw) };
        let host_thread = std::thread::spawn(move || {
            host_accept_handshake(
                &mut host,
                HostHandshakeConfig {
                    proto_version: CONTROL_PROTOCOL_VERSION,
                    abi_version: crucible_shmem::ABI_VERSION,
                    slot_index: 0,
                    node_count,
                },
            )
            .unwrap();
            let mut sender = SetupSendJournal::new(length, [file.into(), wake, setup]);
            let mut budget = AdministrativeIoBudget::new(&profile).unwrap();
            assert!(
                sender
                    .try_send_step(host.as_fd(), &mut budget, monotonic_ns().unwrap())
                    .unwrap()
                    .complete
            );
            let frame = read_control_frame(&mut host).unwrap();
            assert!(matches!(
                control_decode_plugin_msg(&frame).unwrap(),
                PluginMsg::SetupAck { status: 0 }
            ));
            host.set_nonblocking(true).unwrap();
            let mut unexpected = [0];
            assert!(
                matches!(host.read(&mut unexpected),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
            );
            (host, sender)
        });
        let mut reservation = super::super::reserve_runtime().unwrap();
        let owner = install_preowned(
            7,
            args,
            NativeEarlySetup {
                body: &body,
                digest,
            },
            &mut reservation,
            modeled_apis(),
            SelectedRegistrationApis {
                vcpu_init: register_vcpu_init,
                barrier: register_barrier,
                control: register_control,
            },
        )
        .unwrap();
        assert!(REGISTERED.get());
        assert_eq!(owner.original.observed_vcpus.load(Ordering::Acquire), 1);
        assert_eq!(
            owner.original.socket.descriptor().unwrap().as_raw_fd(),
            original_fd
        );
        assert_eq!(owner.original.original_body.as_ref(), body);
        let counters = owner.original.socket.counters().unwrap();
        assert_eq!(counters.read_bytes, 34);
        assert_eq!(counters.offered_write_bytes, 19);
        assert!(!owner.original.failed.load(Ordering::Acquire));
        let userdata = Rc::as_ptr(&owner.original).cast_mut().cast();
        reservation.publish_installation(super::super::RuntimeInstallation::Selected(owner));
        assert!(!super::super::active_runtime_is_published());
        assert_eq!(
            super::super::RUNTIME_STATE.load(Ordering::Acquire),
            super::super::RUNTIME_PREPARING
        );
        let (host, sender) = host_thread.join().unwrap();

        // Actual fork controls hold the inherited TLS borrow while callbacks
        // receive invalid userdata. The birth-PID fence must terminate before
        // even attempting that borrow, without invoking native peers or logs.
        for callback_kind in 0..3 {
            ORIGINAL.with(|slot| {
                let _borrow = slot.borrow_mut();
                // SAFETY: The child performs only the selected callback's PID
                // fence followed by _exit. It cannot unwind into inherited
                // guards, allocate, log or call a modeled native service.
                let child = unsafe { libc::fork() };
                assert!(child >= 0);
                if child == 0 {
                    let invalid = std::ptr::dangling_mut::<c_void>();
                    match callback_kind {
                        0 => observe_preparing_vcpu(0, invalid),
                        1 => closed_control_boundary(0, 0, invalid),
                        _ => refuse(invalid, 1, 1, invalid),
                    }
                    // SAFETY: Returning would make the control fail without
                    // running Rust destructors over inherited parent objects.
                    unsafe { libc::_exit(71) };
                }

                let mut status = 0;
                // SAFETY: This is our exact child PID and one live status slot.
                assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 70);
            });
        }

        // Only literal callbacks on the same original userdata are recorded.
        // Neither four observations nor an arbitrary foreign pointer grants
        // execution, source adoption or readiness.
        observe_preparing_vcpu(1, userdata);
        observe_preparing_vcpu(2, userdata);
        observe_preparing_vcpu(3, userdata);
        observe_preparing_vcpu(0, 1usize as *mut c_void);
        ORIGINAL.with(|slot| {
            let slot = slot.borrow();
            let original = slot.as_ref().unwrap();
            assert_eq!(original.observed_vcpus.load(Ordering::Acquire), 15);
            assert!(!original.failed.load(Ordering::Acquire));
        });
        observe_preparing_vcpu(4, userdata);
        ORIGINAL.with(|slot| {
            let slot = slot.borrow();
            let original = slot.as_ref().unwrap();
            assert!(original.failed.load(Ordering::Acquire));
            assert_eq!(original.observed_vcpus.load(Ordering::Acquire), 15);
        });

        // An unavailable real source join closes the same retained preparation.
        // SetupACK and the parsed plan never create a Ready or compute permit.
        assert_eq!(
            (CLOSED_OPS.history.service.retained.adopt_held)(userdata, 1, 1, 1),
            -libc::ENOTSUP
        );
        ORIGINAL.with(|slot| {
            let slot = slot.borrow();
            let original = slot.as_ref().unwrap();
            assert!(original.failed.load(Ordering::Acquire));
            assert_eq!(original.socket.counters().unwrap(), counters);
            assert!(
                original
                    .socket
                    .received_setup()
                    .unwrap()
                    .descriptors()
                    .is_ok()
            );
        });
        drop(host);
        drop(sender);
        ORIGINAL.with(|slot| {
            let _original = slot.borrow_mut().take();
        });
        std::fs::remove_file(path).unwrap();
    }
}
