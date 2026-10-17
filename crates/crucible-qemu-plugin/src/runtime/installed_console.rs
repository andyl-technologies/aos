//! Setup-owned native UART installation and committed READY/Cold lifetime.
//!
//! The private C descriptor borrows views from the original checked mapping.
//! Actual QOM/CPU resolution precedes capability Release and original READY.
//! Native addresses stay inside this GPL process; the host sees only the
//! versioned capability and record tables. Restore cannot reuse this fresh
//! constructor or derive a canonical generation from physical restore ACKs.

use std::ffi::c_void;

use crucible_protocol::native_console::{
    NativeConsoleCapability, NativeConsoleError, NativeConsoleSetupPlan,
};
use thiserror::Error;

use super::live_callbacks::console_effect::{
    ConsoleControlDisposition, ConsoleControlPreparation, NativeConsoleControlOwner,
    SettledConsoleControl,
};
use super::ready_owner::CommittedRuntimeReady;
use crate::{BootBarrierError, PluginSetupCompletion, QemuPluginResourceManifest};
use crucible_shmem::{NodeBoundaryPublication, SchedulerAdvancePublication};

/// Installs checked mapping views in the selected native node owner.
///
/// # Safety
///
/// The descriptor and result byte must be valid for the call; every borrowed
/// view must remain live through the installed owner's original READY lifetime.
type Install = unsafe extern "C" fn(*const InstallViews, *mut u8) -> *mut c_void;

/// Queries the original installed node's READY state.
///
/// # Safety
///
/// The address must come from the matching successful native installation and
/// remain live in this process; a copied or restored address is not authority.
type Ready = unsafe extern "C" fn(*mut c_void) -> bool;

/// Stages the original private-fork child against checked installation views.
///
/// # Safety
///
/// The source node, descriptor and child must belong to the same retained native
/// owner; all pointers remain live while native staging validates their custody.
type StageChild = unsafe extern "C" fn(*mut c_void, *const InstallViews, *mut c_void) -> u32;

/// Reads the installed owner's boot advance into a private result buffer.
///
/// # Safety
///
/// The installed address must remain live and the output must be writable with
/// exactly the source-bound `AdvanceRead` C layout for the duration of the call.
type BootRead = unsafe extern "C" fn(*mut c_void, *mut AdvanceRead) -> u32;

/// Borrows the pinned runtime for one original native RR dispatch result.
///
/// # Safety
///
/// Callback userdata must retain its pinned runtime allocation, and the result
/// must be a writable `DispatchResult` supplied by the original native callback.
type DispatchCallback = unsafe extern "C" fn(*mut c_void, *mut DispatchResult) -> bool;

/// Registers dispatch userdata in this same committed native READY owner.
///
/// # Safety
///
/// The installed address must remain live; callback userdata must outlive all
/// invocations by this node and obey the source-bound callback signature.
type InstallDispatch = unsafe extern "C" fn(*mut c_void, DispatchCallback, *mut c_void) -> i32;

/// Borrows the pinned runtime for an original accounted output-stop callback.
///
/// # Safety
///
/// Userdata must remain pinned throughout native callback custody. The scalar
/// arguments describe that occurrence and never manufacture a stopped owner.
type StoppedCallback = unsafe extern "C" fn(*mut c_void, u64, u64, u64, u64, u32) -> u32;

/// Registers output-stop userdata in the same committed native READY owner.
///
/// # Safety
///
/// The native address and pinned callback userdata must remain live through all
/// registered invocations, using the exact selected native callback signature.
type InstallStopped = unsafe extern "C" fn(*mut c_void, StoppedCallback, *mut c_void) -> i32;

/// Publishes one accounted boundary under the original stopped callback owner.
///
/// # Safety
///
/// The installed address must remain live. Native code authenticates its active
/// lexical stopped callback and inventory; scalar coordinates cannot replace it.
type PublishStopped = unsafe extern "C" fn(*mut c_void, u64, u64, u64, u64, u32, u32) -> u32;

/// Reads one original RR budget into the source-bound private result buffer.
///
/// # Safety
///
/// The installed address must remain live and the `AdvanceRead` output must be
/// writable for the call; native validation owns the same-read authorization.
type DispatchRead = unsafe extern "C" fn(*mut c_void, *mut AdvanceRead) -> u32;

/// Restores the authenticated prefix through the current closed control owner.
///
/// # Safety
///
/// The installed address must retain the same committed READY lifetime. Native
/// code authenticates whole-load success, stopped custody and the Restore body.
type RestorePrefix = unsafe extern "C" fn(*mut c_void, u32, u64, u64) -> u32;

/// Opens invocation-owned native control custody before any publication.
///
/// # Safety
///
/// The installed address must remain live in this process. A nonnull returned
/// provider must be retained until its matching clear/close cleanup completes.
type ControlOpen = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

/// Binds the actual settled request pair to an invocation-owned provider.
///
/// # Safety
///
/// The provider must come from `ControlOpen` and remain exclusively owned until
/// cleanup; the pair must be the original authenticated control settlement.
type ControlBind = unsafe extern "C" fn(*mut c_void, u32, u64) -> u32;

/// Prepares native control effects under original closed/inventory custody.
///
/// # Safety
///
/// The live provider must retain the original settled request pair. Arguments
/// must describe that settlement; native owners supply the phase and resources.
type ControlPrepare = unsafe extern "C" fn(*mut c_void, u32, u64, u64, u64) -> u32;

/// Commits the same prepared control occurrence through its retained provider.
///
/// # Safety
///
/// The live provider and coordinates must match the successful preparation.
/// Neither another request nor a copied latest publication may replace them.
type ControlCommit = unsafe extern "C" fn(*mut c_void, u32, u64, u64, u64) -> bool;

/// Clears or closes the original invocation-owned native control provider.
///
/// # Safety
///
/// The pointer must be the still-live provider returned by `ControlOpen`, with
/// clear-before-close ordering and no access after the matching close call.
type ControlRelease = unsafe extern "C" fn(*mut c_void);

/// Matches the emulator-private descriptor, not any public IPC representation.
#[repr(C)]
struct InstallViews {
    mapping: *const c_void,
    slot_view: *const c_void,
    authorization: *const c_void,
    ring: *const c_void,
    records: *const c_void,
    frontier: *const c_void,
    clamp: *const c_void,
    operation_stop: *const c_void,
    device: u64,
    inode: u64,
    length: u64,
    process_generation: u64,
    logical_generation: u64,
    owner_mask: u64,
    sequence_base: u64,
    slot: u32,
    kind: u32,
    allowance: u32,
    reserved: u32,
    device_identity: [u8; 32],
    plan_hash: [u8; 32],
}

#[repr(C)]
struct AdvanceRead {
    advance: u64,
    ceiling: u64,
    stop: u8,
    authorization: [u8; 128],
}

/// One original native RR read/result; never a shared-memory representation.
#[repr(C)]
pub(in crate::runtime) struct DispatchResult {
    pub(in crate::runtime) raw_ceiling: u64,
    pub(in crate::runtime) raw_start: u64,
    pub(in crate::runtime) logical_start: u64,
    pub(in crate::runtime) logical_ceiling: u64,
    pub(in crate::runtime) authorization: [u8; 128],
    pub(in crate::runtime) publication_unavailable: bool,
}

impl DispatchResult {
    pub(in crate::runtime) fn unavailable(&mut self) {
        self.raw_ceiling = self.raw_start;
        self.logical_ceiling = self.logical_start;
        self.authorization = [0; 128];
        self.publication_unavailable = true;
    }
}

pub(in crate::runtime) enum DispatchAdvance {
    Unavailable,
    Unowned {
        ceiling: u64,
    },
    Owned {
        ceiling: u64,
        authorization: [u8; 128],
    },
}

const _: () = {
    assert!(size_of::<DispatchResult>() == 168);
    assert!(std::mem::offset_of!(DispatchResult, authorization) == 32);
    assert!(std::mem::offset_of!(DispatchResult, publication_unavailable) == 160);
    assert!(size_of::<InstallViews>() == 200);
    assert!(align_of::<InstallViews>() == 8);
    assert!(std::mem::offset_of!(InstallViews, device) == 64);
    assert!(std::mem::offset_of!(InstallViews, slot) == 120);
    assert!(std::mem::offset_of!(InstallViews, device_identity) == 136);
    assert!(std::mem::offset_of!(InstallViews, plan_hash) == 168);
    assert!(size_of::<AdvanceRead>() == 152);
    assert!(std::mem::offset_of!(AdvanceRead, authorization) == 17);
};

#[derive(Clone, Copy)]
struct Apis {
    ready: Ready,
    stage_child: StageChild,
    boot_read: BootRead,
    install_dispatch: InstallDispatch,
    install_stopped: InstallStopped,
    publish_stopped: PublishStopped,
    dispatch_read: DispatchRead,
    restore_prefix: RestorePrefix,
    control_open: ControlOpen,
    control_bind: ControlBind,
    control_prepare: ControlPrepare,
    control_commit: ControlCommit,
    control_clear: ControlRelease,
    control_close: ControlRelease,
}

/// A nonowning callback view minted only by the committed setup/READY join.
///
/// The pinned original runtime retains the installed node and mapping. This
/// view never supplies phase authority: native preparation authenticates the
/// actual lexical closed owner, exact pair and resources on each invocation.
#[derive(Clone, Copy)]
pub(super) struct InstalledConsoleCallbacks {
    address: usize,
    apis: Apis,
}

impl InstalledConsoleCallbacks {
    /// Registers the retained callback allocation after this same committed READY.
    ///
    /// # Errors
    ///
    /// Refuses a missing native resource/READY owner or duplicate registration.
    pub(super) fn register_dispatch(
        self,
        callback: DispatchCallback,
        userdata: *mut c_void,
    ) -> Result<(), InstalledConsoleError> {
        // SAFETY: the pinned original runtime retains userdata for this process
        // lifetime. Native registration authenticates this installed READY owner
        // under BQL before exposing the callback to the original RR budget read.
        let status = unsafe {
            (self.apis.install_dispatch)(self.address as *mut c_void, callback, userdata)
        };
        if status == 0 {
            Ok(())
        } else {
            Err(InstalledConsoleError::NativeRefused)
        }
    }

    /// Registers the same pinned READY owner for accounted native output stops.
    ///
    /// # Errors
    ///
    /// Refuses absent resources, duplicate registration or a foreign READY owner.
    pub(super) fn register_stopped(
        self,
        callback: StoppedCallback,
        userdata: *mut c_void,
    ) -> Result<(), InstalledConsoleError> {
        // SAFETY: the original pinned runtime retains userdata. The native
        // entry authenticates its installed READY before storing the callback.
        if unsafe { (self.apis.install_stopped)(self.address as *mut c_void, callback, userdata) }
            == 0
        {
            Ok(())
        } else {
            Err(InstalledConsoleError::NativeRefused)
        }
    }

    /// Borrows native stopped custody inside this same original node writer.
    pub(super) fn publish_stopped(
        self,
        generation: u64,
        advance: u64,
        ack: u32,
        publication: NodeBoundaryPublication,
    ) -> u32 {
        // SAFETY: native code accepts only its active lexical stopped callback,
        // retained inventory lock and exact private original occurrence. These
        // framing scalars do not create that scope or any execution permission.
        unsafe {
            (self.apis.publish_stopped)(
                self.address as *mut c_void,
                generation,
                publication.raw(),
                publication.logical(),
                advance,
                ack,
                publication.closed_generation(),
            )
        }
    }

    /// Copies and admits the body from the same original advance transaction.
    ///
    /// # Errors
    ///
    /// Refuses an unknown private endpoint disposition. A missing or invalid
    /// phase remains unowned; the caller must never execute a positive budget.
    pub(super) fn dispatch_advance(self) -> Result<DispatchAdvance, NativeConsoleError> {
        let mut read = AdvanceRead {
            advance: 0,
            ceiling: 0,
            stop: 0,
            authorization: [0; 128],
        };
        // SAFETY: this same-READY native object and its original checked mapping
        // remain resident. The exact C/Rust result layout is asserted on both
        // sides; no second scalar callback reconstructs the returned body.
        match unsafe { (self.apis.dispatch_read)(self.address as *mut c_void, &mut read) } {
            0 => Ok(DispatchAdvance::Unavailable),
            1 => Ok(DispatchAdvance::Unowned {
                ceiling: read.ceiling,
            }),
            2 => Ok(DispatchAdvance::Owned {
                ceiling: read.ceiling,
                authorization: read.authorization,
            }),
            _ => Err(NativeConsoleError::Binding),
        }
    }

    pub(super) fn control_owner(self) -> InstalledControlOwner {
        InstalledControlOwner {
            installed: self,
            provider: std::ptr::null_mut(),
            settled: None,
            prepared: None,
        }
    }
}

/// Releases invocation storage without unbinding the process-resident UART.
pub(super) struct InstalledControlOwner {
    installed: InstalledConsoleCallbacks,
    provider: *mut c_void,
    settled: Option<SettledConsoleControl>,
    prepared: Option<ConsoleControlDisposition>,
}

impl NativeConsoleControlOwner for InstalledControlOwner {
    fn restore_prefix(
        &mut self,
        generation: u32,
        raw: u64,
        logical: u64,
    ) -> Result<bool, NativeConsoleError> {
        if !self.provider.is_null() || self.settled.is_some() {
            return Err(NativeConsoleError::Binding);
        }
        // SAFETY: the same committed READY owner retains this installed node.
        // Native code joins the whole-loader success, loaded canonical state,
        // actual stopped CLOSED scope and full paired Restore body. Scalars
        // identify the original transaction; they do not create its authority.
        // The temporary native inventory lease is cleared before this returns.
        match unsafe {
            (self.installed.apis.restore_prefix)(
                self.installed.address as *mut c_void,
                generation,
                raw,
                logical,
            )
        } {
            2 => Ok(true),
            1 => Ok(false),
            _ => Err(NativeConsoleError::Binding),
        }
    }

    fn prepare(
        &mut self,
        settled: SettledConsoleControl,
        logical: u64,
    ) -> Result<ConsoleControlPreparation, NativeConsoleError> {
        if !self.provider.is_null() || self.settled.is_some() {
            return Err(NativeConsoleError::Binding);
        }
        let address = self.installed.address as *mut c_void;
        // SAFETY: this same-READY view points to the process-resident native
        // installed owner. Allocation occurs before publish_gen, and the
        // returned provider stays invocation-owned until Drop.
        self.provider = unsafe { (self.installed.apis.control_open)(address) };
        if self.provider.is_null() {
            return Err(control_binding_failure("open", 0, settled, logical));
        }
        // SAFETY: private declarations use primitive arguments and one owned
        // provider. Native bind copies the actual same-request paired body;
        // prepare performs authentic closed/inventory/clock checks, not a
        // caller status or copied tuple substitute for those original owners.
        let bound = unsafe {
            (self.installed.apis.control_bind)(self.provider, settled.request, settled.advance)
        };
        match bound {
            2 => {}
            1 => return Ok(ConsoleControlPreparation::Pending),
            _ => return Err(control_binding_failure("bind", bound, settled, logical)),
        }
        // SAFETY: the bound provider remains invocation-owned; this bounded
        // preparation owns or releases actual native custody before return.
        let status = unsafe {
            (self.installed.apis.control_prepare)(
                self.provider,
                settled.request,
                settled.advance,
                settled.raw,
                logical,
            )
        };
        self.settled = Some(settled);
        let disposition = match status {
            2 => ConsoleControlDisposition::Accepted,
            3 => ConsoleControlDisposition::Observed,
            // One raw mutex/read contention observation retains the original
            // pending request. It holds no custody and performs no writer/ACK.
            1 => return Ok(ConsoleControlPreparation::Pending),
            _ => return Err(control_binding_failure("prepare", status, settled, logical)),
        };
        self.prepared = Some(disposition);
        Ok(ConsoleControlPreparation::Prepared(disposition))
    }

    fn commit(
        &mut self,
        fields: NodeBoundaryPublication,
        advance: SchedulerAdvancePublication,
    ) -> Result<ConsoleControlDisposition, NativeConsoleError> {
        let settled = self.settled.ok_or(NativeConsoleError::Binding)?;
        let disposition = self.prepared.ok_or(NativeConsoleError::Binding)?;
        // SAFETY: successful prepare owns the native lock and lexical scope;
        // this primitive recheck/commit runs inside the unchanged slot writer.
        // Native refusal precedes all accepted mutation; its suffix is infallible.
        let committed = unsafe {
            (self.installed.apis.control_commit)(
                self.provider,
                settled.request,
                advance.sequence(),
                fields.raw(),
                fields.logical(),
            )
        };
        if committed {
            Ok(disposition)
        } else {
            Err(control_binding_failure(
                "commit",
                0,
                settled,
                fields.logical(),
            ))
        }
    }

    fn clear(&mut self) {
        // SAFETY: clear is idempotent on this invocation's live provider and
        // releases its actual custody after coherent writer-close, before ACK.
        unsafe { (self.installed.apis.control_clear)(self.provider) };
    }
}

/// Reports one bounded primitive refusal before the existing fatal path.
fn control_binding_failure(
    phase: &str,
    status: u32,
    settled: SettledConsoleControl,
    logical: u64,
) -> NativeConsoleError {
    // crucible-lint: allow direct-diagnostic -- Reports bounded primitive refusal fields before the existing fatal Binding path; this process-local diagnostic grants no control or execution authority.
    eprintln!(
        "crucible-console-control-refused phase={phase} status={status} request={} advance={} capture={} frontier={} raw={} logical={logical}",
        settled.request,
        settled.advance,
        settled.capture_request,
        settled.command_frontier,
        settled.raw,
    );
    NativeConsoleError::Binding
}

impl Drop for InstalledControlOwner {
    fn drop(&mut self) {
        // SAFETY: native close releases any partial preparation and frees only
        // this provider storage. The installed QOM/frontend/mapping stay live.
        unsafe { (self.installed.apis.control_close)(self.provider) };
    }
}

/// Retains one native node beside the pinned original setup mapping.
///
/// Its QOM references and bound frontend remain process-resident, like the
/// original callback allocation. No independent Rust drop may unbind a UART
/// while QEMU still owns that frontend. Stop/restore teardown is a separate
/// original lifecycle join; this fresh owner is not copied into a new process.
pub(super) struct InstalledConsole {
    address: usize,
    manifest: QemuPluginResourceManifest,
    policy: NativeConsoleSetupPlan,
    apis: Apis,
}

impl InstalledConsole {
    /// Resolves and binds the sole producer before publishing capability/READY.
    ///
    /// # Errors
    ///
    /// Refuses a missing native API, unsupported plan, foreign physical owner,
    /// invalid mapped view, native resolution/binding, or prior capability.
    pub(super) fn install(
        setup: &PluginSetupCompletion,
        manifest: QemuPluginResourceManifest,
        policy: NativeConsoleSetupPlan,
    ) -> Result<Self, InstalledConsoleError> {
        let (views, expected_resolved) = checked_install_views(setup, manifest, &policy)?;
        let segment = setup
            .mapped_region()
            .native_console_segment(manifest.slot_index)?;
        let (install, apis) = resolve_apis()?;
        let mut actual_resolved = [0; 32];
        // SAFETY: the exact private C declaration matches InstallViews. All
        // views come from the checked ABI31 accessor and remain resident in the
        // original pinned callback owner; no reference crosses the process ABI.
        let address = unsafe { install(&views, actual_resolved.as_mut_ptr()) };
        if address.is_null() || actual_resolved != expected_resolved {
            return Err(InstalledConsoleError::NativeRefused);
        }
        let mut transport_region = [0; 16];
        transport_region[..8].copy_from_slice(&manifest.shmem_device.to_le_bytes());
        transport_region[8..].copy_from_slice(&manifest.shmem_inode.to_le_bytes());
        // Digest or capability refusal after native binding is process-fatal.
        // Original CallbackStateRetention preserves the registered callback
        // allocation/mapping on that path; no rollback or early unbind occurs.
        segment.capability.publish(NativeConsoleCapability {
            slot: views.slot,
            region: transport_region,
            process: manifest.process_generation,
            plan_hash: views.plan_hash,
            resolved_streams: actual_resolved,
        })?;
        Ok(Self {
            address: address as usize,
            manifest,
            policy,
            apis,
        })
    }

    /// Stages the original mapping replacement while native INITIALIZE is live.
    ///
    /// # Errors
    ///
    /// Refuses mismatched mapped backing/closed plan or absent native child
    /// custody. Native status validation later commits resources and capability;
    /// this method supplies no READY, Restore or executable permission.
    pub(super) fn stage_hot_fork_child(
        &self,
        setup: &PluginSetupCompletion,
        child_process_generation: u64,
    ) -> Result<(), InstalledConsoleError> {
        // The installation owner retains the same admitted plan across the
        // original child mapping replacement; no descriptor is decoded again.
        let policy = &self.policy;
        let mut manifest = self.manifest;
        manifest.process_generation = child_process_generation;
        manifest.shmem_device = setup.shared_memory_device();
        manifest.shmem_inode = setup.shared_memory_inode();
        manifest.shmem_length = setup.mapped_region().region_len();
        let (views, _expected_resolved) = checked_install_views(setup, manifest, policy)?;
        let segment = setup
            .mapped_region()
            .native_console_segment(manifest.slot_index)?;
        // SAFETY: the real runtime calls this only after its original checked
        // replacement mapping and before worker reset. Native validates the
        // retained original INITIALIZE stack owner and original child plan.
        // All views are resident; no descriptor or native pointer enters IPC.
        let staged = unsafe {
            (self.apis.stage_child)(
                self.address as *mut c_void,
                &views,
                std::ptr::from_ref(segment.capability).cast_mut().cast(),
            )
        };
        if staged != 1 {
            return Err(InstalledConsoleError::NativeRefused);
        }
        Ok(())
    }

    /// Joins the same installed resources to the original successful READY.
    ///
    /// # Errors
    ///
    /// Refuses a foreign committed setup owner or native resource drift.
    pub(super) fn commit_ready(
        &mut self,
        ready: &CommittedRuntimeReady,
    ) -> Result<InstalledConsoleCallbacks, InstalledConsoleError> {
        let manifest = ready.manifest();
        if manifest != &self.manifest {
            return Err(NativeConsoleError::Binding.into());
        }
        // SAFETY: only this retained, same-setup owner receives the native
        // installed pointer. The original lifecycle already committed READY.
        if !unsafe { (self.apis.ready)(self.address as *mut c_void) } {
            return Err(InstalledConsoleError::NativeRefused);
        }
        Ok(InstalledConsoleCallbacks {
            address: self.address,
            apis: self.apis,
        })
    }

    /// Reads the actual boot grant at the original barrier's scheduler seam.
    ///
    /// # Errors
    ///
    /// Refuses an observed release without an authentic owned Cold body.
    pub(super) fn boot_ceiling(&mut self) -> Result<Option<u64>, BootBarrierError> {
        let mut read = AdvanceRead {
            advance: 0,
            ceiling: 0,
            stop: 0,
            authorization: [0; 128],
        };
        // SAFETY: the native object and original setup mapping remain retained;
        // the result layout matches the exact GPL-side C declaration.
        match unsafe { (self.apis.boot_read)(self.address as *mut c_void, &mut read) } {
            0 => Ok(None),
            1 if read.ceiling == 0 => Ok(Some(0)),
            2 => Ok(Some(read.ceiling)),
            _ => Err(BootBarrierError::NativeConsoleRelease),
        }
    }
}

/// Derives private mapped views from the same sealed setup descriptor/backing.
/// Canonical child prefix comes from native barrier custody, never these fields.
fn checked_install_views(
    setup: &PluginSetupCompletion,
    manifest: QemuPluginResourceManifest,
    policy: &NativeConsoleSetupPlan,
) -> Result<(InstallViews, [u8; 32]), InstalledConsoleError> {
    let plan = policy.plan();
    let [row] = plan.streams.as_slice() else {
        return Err(NativeConsoleError::Plan.into());
    };
    if row.stream != 1
        || row.sequence_base != 0
        || plan.logical_generation != 0
        || plan.slot != manifest.slot_index
        || manifest.shmem_device != setup.shared_memory_device()
        || manifest.shmem_inode != setup.shared_memory_inode()
        || manifest.shmem_length != setup.mapped_region().region_len()
    {
        return Err(NativeConsoleError::Binding.into());
    }
    let plan_hash = plan.digest()?;
    let expected_resolved = plan.resolved_streams_digest()?;
    let region = setup.mapped_region();
    let segment = region.native_console_segment(plan.slot)?;
    let slot = region
        .node_slot(plan.slot)
        .map_err(|_| NativeConsoleError::Binding)?;
    let views = InstallViews {
        mapping: region.mapping_start() as *const c_void,
        slot_view: std::ptr::from_ref(slot).cast(),
        authorization: std::ptr::from_ref(segment.authorization).cast(),
        ring: std::ptr::from_ref(segment.ring).cast(),
        records: segment.records.as_ptr().cast(),
        frontier: std::ptr::from_ref(segment.frontier).cast(),
        clamp: std::ptr::from_ref(segment.clamp).cast(),
        operation_stop: std::ptr::from_ref(segment.operation_stop).cast(),
        device: manifest.shmem_device,
        inode: manifest.shmem_inode,
        length: manifest.shmem_length,
        process_generation: manifest.process_generation,
        logical_generation: plan.logical_generation,
        owner_mask: row.owner_mask,
        sequence_base: row.sequence_base,
        slot: plan.slot,
        kind: u32::from(row.device as u16),
        allowance: policy.authorization_allowance(),
        reserved: 0,
        device_identity: row.device_identity,
        plan_hash,
    };
    Ok((views, expected_resolved))
}

fn resolve_apis() -> Result<(Install, Apis), InstalledConsoleError> {
    macro_rules! symbol {
        ($name:literal, $signature:ty) => {{
            let name = concat!($name, "\0").as_ptr().cast();
            // SAFETY: the static NUL-terminated name identifies the exact
            // selected native declaration. Missing exports refuse installation.
            let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name) };
            if address.is_null() {
                return Err(InstalledConsoleError::MissingSymbol($name));
            }
            // SAFETY: the source-bound C and Rust declarations have the same
            // private GPL ABI. This pointer is never stored in shared memory.
            unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
        }};
    }
    Ok((
        symbol!("qemu_plugin_crucible_console_install", Install),
        Apis {
            ready: symbol!("qemu_plugin_crucible_console_ready_committed", Ready),
            stage_child: symbol!("qemu_plugin_crucible_console_stage_child", StageChild),
            boot_read: symbol!("qemu_plugin_crucible_console_boot_read", BootRead),
            install_dispatch: symbol!(
                "qemu_plugin_crucible_console_install_dispatch",
                InstallDispatch
            ),
            install_stopped: symbol!(
                "qemu_plugin_crucible_console_install_stopped",
                InstallStopped
            ),
            publish_stopped: symbol!(
                "qemu_plugin_crucible_console_stopped_publish",
                PublishStopped
            ),
            dispatch_read: symbol!("qemu_plugin_crucible_console_dispatch_read", DispatchRead),
            restore_prefix: symbol!("qemu_plugin_crucible_console_restore_prefix", RestorePrefix),
            control_open: symbol!("qemu_plugin_crucible_console_control_open", ControlOpen),
            control_bind: symbol!("qemu_plugin_crucible_console_control_bind", ControlBind),
            control_prepare: symbol!(
                "qemu_plugin_crucible_console_control_prepare_effect",
                ControlPrepare
            ),
            control_commit: symbol!(
                "qemu_plugin_crucible_console_control_commit_effect",
                ControlCommit
            ),
            control_clear: symbol!(
                "qemu_plugin_crucible_console_control_clear_effect",
                ControlRelease
            ),
            control_close: symbol!("qemu_plugin_crucible_console_control_close", ControlRelease),
        },
    ))
}

/// Fail-stop installation errors before original READY or boot release.
#[derive(Debug, Error)]
pub(super) enum InstalledConsoleError {
    #[error(transparent)]
    Boundary(#[from] NativeConsoleError),
    #[error("native console installation requires {0}")]
    MissingSymbol(&'static str),
    #[error("native console owner refused installation or READY")]
    NativeRefused,
}
