//! Stages portable child plans and transfers real process-private paging custody.
//!
//! SPDX-License-Identifier: GPL-2.0-or-later
//!
//! Native callbacks authenticate immediate-child lineage and immutable stage
//! generation. Rust preallocates portable metadata before fork, joins parent
//! actors before registry freeze, and installs fresh child authority before the
//! native descriptor plan closes any inherited role.

use std::fs::File;
use std::os::fd::{BorrowedFd, RawFd};
use std::os::raw::{c_int, c_void};
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};

use crucible_protocol::ram_control::{RamControlMessage, RamControlRequest};
use crucible_protocol::ram_fork::{RAM_FORK_MAX_BYTES, RamForkPlan};
use crucible_ram::MetadataReservation;

use super::controller::{self, PreparedChildControl};
use super::engine::{ChildPagingCustody, PausedPagingOwner, PreparedChildArenas};
use super::restore::ValidatedRestoreSource;
use crate::ram_error::RamError;

const MAX_DESCRIPTORS: usize = 32;

type Prepare =
    extern "C" fn(*const u8, usize, c_int, c_int, c_int, c_int, u64, *mut c_void) -> c_int;
type Resources =
    extern "C" fn(u64, *mut c_int, u32, *mut u32, *mut c_int, u32, *mut u32, *mut c_void) -> c_int;
type Release = extern "C" fn(u64, *mut c_void) -> c_int;
type Register = extern "C" fn(u64, Prepare, Resources, Release, *mut c_void) -> c_int;

static STAGE: Mutex<Option<Stage>> = Mutex::new(None);
static REGISTERED: OnceLock<()> = OnceLock::new();

struct Stage {
    generation: u64,
    template_generation: u64,
    source_process: u32,
    control: Option<PreparedChildControl>,
    cold: Option<PreparedChildArenas>,
    spill: Option<File>,
    spill_quota: u64,
    resources: crucible_protocol::ram_control::RamControlResources,
    topology_generation: u64,
    logical_bytes: u64,
    captured: bool,
    rebound: bool,
    child: Option<ChildPagingCustody>,
    retained: [RawFd; MAX_DESCRIPTORS],
    closed: [RawFd; MAX_DESCRIPTORS],
    retained_count: usize,
    closed_count: usize,
    _metadata: MetadataReservation,
}

/// Registers only the actual managed fork custody callbacks.
///
/// # Errors
/// Refuses absent native APIs, duplicate installation or rejected registration.
pub(crate) fn install(plugin_id: u64) -> Result<(), RamError> {
    // SAFETY: the matching private native symbol has this exact callback ABI.
    let pointer = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_register_ram_fork_v1".as_ptr(),
        )
    };
    if pointer.is_null() {
        return Err(RamError::MissingSymbol(
            b"qemu_plugin_crucible_register_ram_fork_v1\0",
        ));
    }
    // SAFETY: callbacks and context are process-private, never portable records.
    let register = unsafe { std::mem::transmute::<*mut c_void, Register>(pointer) };
    REGISTERED
        .set(())
        .map_err(|_| RamError::Invariant("RAM fork callbacks already installed"))?;
    let status = register(plugin_id, prepare, resources, release, std::ptr::null_mut());
    if status != 0 {
        return Err(RamError::Native {
            operation: "register independent RAM fork custody",
            status,
        });
    }
    Ok(())
}

/// Reports actual preallocated cold custody before parent control quiescence.
///
/// # Errors
/// Refuses uncertain stage ownership.
pub(crate) fn has_prepared_cold() -> Result<bool, RamError> {
    Ok(STAGE
        .try_lock()
        .map_err(|_| RamError::Invariant("RAM fork stage active"))?
        .as_ref()
        .is_some_and(|stage| stage.cold.is_some() && stage.source_process == std::process::id()))
}

/// Captures parent paging state only after the root has closed observer admission.
///
/// # Errors
/// Refuses mismatched stages or incomplete actor join; the stage remains owned.
pub(crate) fn capture_parent(template_generation: u64) -> Result<(), RamError> {
    let mut current = STAGE
        .try_lock()
        .map_err(|_| RamError::Invariant("RAM fork stage active"))?;
    let Some(stage) = current.as_mut() else {
        return Ok(());
    };
    if stage.template_generation != template_generation
        || stage.source_process != std::process::id()
        || stage.captured
    {
        return Err(RamError::Invariant("RAM fork capture generation mismatch"));
    }
    // Abort must repair or refuse any attempted actor stop, including failures
    // after a complete join but before private child spill staging completes.
    stage.captured = true;
    if let Some(cold) = stage.cold.as_mut() {
        cold.capture_parent()?;
    }
    Ok(())
}

/// Restarts the parent's original fault actor after complete native disposition.
///
/// # Errors
/// Refuses absent or failed retained parent authority.
pub(crate) fn resume_parent() -> Result<(), RamError> {
    let mut current = STAGE
        .try_lock()
        .map_err(|_| RamError::Invariant("RAM fork stage active"))?;
    let Some(stage) = current.as_mut() else {
        return Ok(());
    };
    if stage.source_process != std::process::id() {
        return Err(RamError::Invariant("child cannot resume parent paging"));
    }
    if stage.captured && stage.cold.is_some() {
        controller::current_owner()?
            .ok_or("parent RAM owner absent")?
            .resume_cold_parent()?;
    }
    stage.captured = false;
    Ok(())
}

extern "C" fn prepare(
    plan: *const u8,
    length: usize,
    control_fd: c_int,
    source_fd: c_int,
    spill_fd: c_int,
    cancellation_fd: c_int,
    generation: u64,
    _context: *mut c_void,
) -> c_int {
    callback(|| {
        if plan.is_null()
            || length == 0
            || length > RAM_FORK_MAX_BYTES
            || generation == 0
            || control_fd < 0
            || spill_fd < 0
            || cancellation_fd < 0
            || source_fd == control_fd
            || cancellation_fd == control_fd
            || spill_fd == control_fd
            || spill_fd == source_fd
            || spill_fd == cancellation_fd
            || (source_fd >= 0 && source_fd == cancellation_fd)
        {
            return Err(RamError::Invariant("RAM fork stage arguments invalid"));
        }
        if STAGE
            .try_lock()
            .map_err(|_| RamError::Invariant("RAM fork stage active"))?
            .is_some()
        {
            return Err(RamError::Invariant("RAM fork stage already retained"));
        }
        let budget = crate::ram_fingerprint::fork_metadata_budget()?;
        let metadata = length
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Stage>()))
            .ok_or("RAM fork plan metadata overflow")?;
        let reservation = budget.reserve_bytes(metadata as u64)?;
        // SAFETY: the native stage lends the sealed bounded immutable buffer
        // through this synchronous callback and authenticates descriptor roles.
        let bytes = unsafe { std::slice::from_raw_parts(plan, length) };
        let plan = RamForkPlan::decode(bytes)?;
        let RamControlMessage::Request(RamControlRequest::Apply { policy, .. }) =
            plan.control.message
        else {
            return Err(RamError::Invariant("RAM fork initial policy absent"));
        };
        let owner = controller::current_owner()?.ok_or("RAM fork actual owner absent")?;
        let geometry = owner.authority_snapshot()?;
        let child_control = controller::prepare_child(
            control_fd,
            plan.control.session,
            plan.control.target,
            plan.resources,
            policy,
            plan.spill_quota_bytes,
            plan.outer_cap,
        )?;
        let source = match plan.source {
            Some(source) => {
                if source_fd < 0 {
                    return Err(RamError::Invariant("fork cold source role mismatch"));
                }
                let stream = UnixStream::from(duplicate(source_fd)?);
                let cancellation = duplicate(cancellation_fd)?;
                Some(ValidatedRestoreSource::bind_fork_source(
                    geometry.topology_generation,
                    budget,
                    stream,
                    cancellation,
                    source.binding,
                    &source.root_record,
                    child_control.operations(),
                )?)
            }
            None if source_fd >= 0 => {
                return Err(RamError::Invariant(
                    "fork source role lacks authenticated root",
                ));
            }
            None => None,
        };
        let spill = File::from(duplicate(spill_fd)?);
        let (cold, spill) = if geometry.activated {
            (
                Some(owner.prepare_child(super::engine::ChildArenaConfiguration {
                    generation,
                    resources: plan.resources,
                    operations: child_control.operations(),
                    source,
                    spill_file: spill,
                    spill_quota: plan.spill_quota_bytes,
                    policy,
                })?),
                None,
            )
        } else {
            if source.is_some() {
                return Err(RamError::Invariant(
                    "unactivated parent cannot stage cold source",
                ));
            }
            (None, Some(spill))
        };
        let stage = Stage {
            generation,
            template_generation: plan.template_generation,
            source_process: std::process::id(),
            control: Some(child_control),
            cold,
            spill,
            spill_quota: plan.spill_quota_bytes,
            resources: plan.resources,
            topology_generation: geometry.topology_generation,
            logical_bytes: geometry.logical_bytes,
            captured: false,
            rebound: false,
            child: None,
            retained: [-1; MAX_DESCRIPTORS],
            closed: [-1; MAX_DESCRIPTORS],
            retained_count: 0,
            closed_count: 0,
            _metadata: reservation,
        };
        let mut current = STAGE
            .try_lock()
            .map_err(|_| RamError::Invariant("RAM fork stage active"))?;
        if current.is_some() {
            return Err(RamError::Invariant("RAM fork stage publication changed"));
        }
        *current = Some(stage);
        Ok(())
    })
}

extern "C" fn resources(
    generation: u64,
    retained: *mut c_int,
    capacity: u32,
    retained_count: *mut u32,
    closed: *mut c_int,
    close_capacity: u32,
    closed_count: *mut u32,
    _context: *mut c_void,
) -> c_int {
    callback(|| {
        if retained.is_null()
            || closed.is_null()
            || retained_count.is_null()
            || closed_count.is_null()
            || capacity as usize > MAX_DESCRIPTORS
            || close_capacity as usize > MAX_DESCRIPTORS
        {
            return Err(RamError::Invariant("RAM child descriptor outputs invalid"));
        }
        let current = STAGE
            .try_lock()
            .map_err(|_| RamError::Invariant("RAM child FD custody active"))?;
        let stage = current.as_ref().ok_or("RAM child FD custody absent")?;
        if stage.generation != generation
            || stage.source_process == std::process::id()
            || !stage.captured
            || !stage.rebound
            || stage.control.is_some()
            || stage.cold.is_some()
        {
            return Err(RamError::Invariant("RAM child authority was not rebound"));
        }
        if stage.retained_count > capacity as usize || stage.closed_count > close_capacity as usize
        {
            return Err(RamError::Invariant(
                "RAM child descriptor capacity insufficient",
            ));
        }
        // SAFETY: native lends distinct checked output arrays with advertised
        // capacities; all counts were admitted before any child activation.
        unsafe {
            std::ptr::copy_nonoverlapping(stage.retained.as_ptr(), retained, stage.retained_count);
            std::ptr::copy_nonoverlapping(stage.closed.as_ptr(), closed, stage.closed_count);
            retained_count.write(stage.retained_count as u32);
            closed_count.write(stage.closed_count as u32);
        }
        Ok(())
    })
}

/// Arms fresh child paging and control before native reconstruction can read RAM.
///
/// The native caller has already applied the independently authored kernel
/// contract. Proof-source replacement remains inside the frozen root-cache
/// interval; the later resource callback only exposes this completed custody.
///
/// # Errors
/// Refuses stale lineage, a repeated rebind, or failed child activation. A
/// partially consumed stage remains retained until process containment/reap.
pub(crate) fn rebind_child(template_generation: u64) -> Result<(), RamError> {
    let mut stage = {
        let mut current = STAGE
            .try_lock()
            .map_err(|_| RamError::Invariant("RAM child rebind custody active"))?;
        let stage = current.as_ref().ok_or("RAM child stage absent")?;
        RebindIdentity {
            template_generation: stage.template_generation,
            source_process: stage.source_process,
            captured: stage.captured,
            rebound: stage.rebound,
        }
        .validate(template_generation, std::process::id())?;
        if stage.control.is_none() {
            return Err(RamError::Invariant(
                "RAM child control custody already consumed",
            ));
        }
        current.take().ok_or("RAM child stage disappeared")?
    };
    let result = activate_child(&mut stage);
    if result.is_ok() {
        stage.rebound = true;
    }
    let mut current = STAGE
        .try_lock()
        .map_err(|_| RamError::Invariant("RAM child stage publication active"))?;
    if current.is_some() {
        std::mem::forget(stage);
        return Err(RamError::Invariant("RAM child stage publication changed"));
    }
    // Successful activation owns every ready descriptor. Failed activation
    // retains partial registrations and endpoints; neither path drops custody.
    *current = Some(stage);
    result
}

#[derive(Clone, Copy)]
struct RebindIdentity {
    template_generation: u64,
    source_process: u32,
    captured: bool,
    rebound: bool,
}

impl RebindIdentity {
    fn validate(self, template_generation: u64, process: u32) -> Result<(), RamError> {
        if template_generation == 0
            || self.template_generation != template_generation
            || self.source_process == process
            || !self.captured
            || self.rebound
        {
            return Err(RamError::Invariant(
                "RAM child lacks captured rebind lineage",
            ));
        }
        Ok(())
    }
}

fn activate_child(stage: &mut Stage) -> Result<(), RamError> {
    let control = stage
        .control
        .take()
        .ok_or("RAM child control already consumed")?;
    stage.retained[0] = control.descriptor();
    stage.retained_count = 1;
    let owner = if let Some(cold) = stage.cold.take() {
        let custody = cold.activate_child()?;
        if custody.generation() != stage.generation {
            return Err(RamError::Invariant("child paging custody epoch mismatch"));
        }
        stage.retained[1..1 + custody.retained_count]
            .copy_from_slice(&custody.retained[..custody.retained_count]);
        stage.closed[..custody.closed_count]
            .copy_from_slice(&custody.closed[..custody.closed_count]);
        stage.retained_count = 1 + custody.retained_count;
        stage.closed_count = custody.closed_count;
        let owner = custody.owner.clone();
        super::restore::rebind_cold_child(&custody)?;
        stage.child = Some(custody);
        owner
    } else {
        let owner = PausedPagingOwner::rebind_resident(
            stage.resources,
            control.operations(),
            stage.topology_generation,
            stage.logical_bytes,
        )?;
        let spill = stage.spill.take().ok_or("child spill custody missing")?;
        stage.retained[1] = std::os::fd::AsRawFd::as_raw_fd(&spill);
        stage.retained_count = 2;
        owner.install_spill(spill, stage.spill_quota)?;
        owner
    };
    stage.closed[stage.closed_count] = controller::disarm_parent_control()?;
    stage.closed_count += 1;
    for alias in controller::disarm_inherited_aliases()?
        .into_iter()
        .flatten()
    {
        if stage.closed[..stage.closed_count].contains(&alias) {
            return Err(RamError::Invariant("inherited close custody aliases"));
        }
        stage.closed[stage.closed_count] = alias;
        stage.closed_count += 1;
    }
    controller::rebind_child(control, owner)
}

extern "C" fn release(generation: u64, _context: *mut c_void) -> c_int {
    callback(|| {
        let mut current = STAGE
            .try_lock()
            .map_err(|_| RamError::Invariant("RAM fork release custody active"))?;
        let Some(stage) = current.as_ref() else {
            return Ok(());
        };
        let parent_release = stage.source_process == std::process::id() && !stage.captured;
        let child_release = stage.source_process != std::process::id()
            && stage.captured
            && stage.rebound
            && stage.control.is_none()
            && stage.cold.is_none()
            && stage.retained_count > 0;
        if stage.generation != generation || (!parent_release && !child_release) {
            return Err(RamError::Invariant(
                "RAM fork release lacks completed parent disposition",
            ));
        }
        let stage = current.take();
        drop(current);
        // Dropping private duplicate endpoints closes only this parent's copy;
        // shutdown would also affect the independent child's file description.
        drop(stage);
        Ok(())
    })
}

fn duplicate(descriptor: RawFd) -> Result<std::os::fd::OwnedFd, RamError> {
    // SAFETY: authenticated native stage retains this borrowed descriptor role.
    Ok(unsafe { BorrowedFd::borrow_raw(descriptor) }.try_clone_to_owned()?)
}

fn callback(operation: impl FnOnce() -> Result<(), RamError>) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            crate::ram_diagnostics::emit(crate::ram_diagnostics::RamDiagnostic::LifecycleFailed(
                &error,
            ));
            -libc::EIO
        }
        Err(_) => -libc::EIO,
    }
}

#[cfg(test)]
mod tests {
    use super::RebindIdentity;

    #[test]
    fn child_rebind_requires_exact_captured_lineage_and_single_consumption() {
        let ready = RebindIdentity {
            template_generation: 7,
            source_process: 11,
            captured: true,
            rebound: false,
        };
        assert!(ready.validate(7, 12).is_ok());
        assert!(ready.validate(7, 11).is_err());
        assert!(ready.validate(8, 12).is_err());
        assert!(ready.validate(0, 12).is_err());
        assert!(
            RebindIdentity {
                captured: false,
                ..ready
            }
            .validate(7, 12)
            .is_err()
        );
        assert!(
            RebindIdentity {
                rebound: true,
                ..ready
            }
            .validate(7, 12)
            .is_err()
        );
    }
}
