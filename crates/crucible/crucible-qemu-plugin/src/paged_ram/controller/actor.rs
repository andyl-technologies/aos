//! Owns the sole native RAM actor and its inline original record operation.
//!
//! The native installer registers against actual control/runtime purposes before
//! birth. Worker entry treats runtime userdata as an opaque coordinate and uses
//! the separately retained controller. Record callbacks retain the original
//! operation through real reply/cursor disposition and native bank return.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use std::ffi::c_void;

mod native;
mod reader;

use native::{Actor, EndStatus, Receive};

#[derive(Default)]
pub(super) struct ActorState {
    api: Option<native::Api>,
    plugin_id: u64,
    userdata: usize,
    registered: bool,
    address: usize,
    constructor_address: usize,
    sequence: u64,
    record: RecordState,
}

#[derive(Default)]
struct RecordState {
    actor: usize,
    loan: usize,
    acquire_attempted: bool,
    operation: Option<LiveOperation>,
    end_attempted: bool,
    end_result: i32,
    terminal_journal: u32,
    failure: Option<ObservationOperationError>,
}

impl RecordState {
    // This local journal is necessary but never proves physical bank return.
    // Only the genuine native release callback supplies that separate cut.
    fn completion_known(&self) -> bool {
        self.end_attempted
            && self.end_result <= 0
            && self.terminal_journal == 2
            && self
                .operation
                .as_ref()
                .is_some_and(|operation| operation.terminal.load(Ordering::Acquire) == 1)
    }
}

impl ActorState {
    pub(super) fn source_plugin_id(&self) -> u64 {
        self.plugin_id
    }

    pub(super) fn matches_runtime(&self, id: u64, userdata: *mut c_void) -> bool {
        self.plugin_id == id && self.userdata == userdata as usize
    }

    pub(super) fn new(plugin_id: u64, userdata: *mut c_void) -> Result<Self, RamError> {
        let api = native::Api::resolve().map_err(|status| RamError::Native {
            operation: "native RAM actor SDK unavailable",
            status,
        })?;
        if userdata.is_null() {
            return Err(RamError::Invariant("native RAM actor binding absent"));
        }
        Ok(Self {
            api: Some(api),
            plugin_id,
            userdata: userdata as usize,
            registered: false,
            address: 0,
            constructor_address: 0,
            sequence: 0,
            record: RecordState::default(),
        })
    }
}

pub(super) fn install(
    controller: &Arc<LivePagerController>,
    setup: &crate::PluginSetupCompletion,
    descriptor: i32,
) -> Result<(), RamError> {
    setup
        .with_ram_actor_purposes(|id, control, runtime| {
            let (api, userdata) = {
                let Ok(state) = controller.actor.lock() else {
                    return -libc::EOWNERDEAD;
                };
                if state.plugin_id != id || state.registered || state.address != 0 {
                    return -libc::ESTALE;
                }
                (
                    match state.api {
                        Some(api) => api,
                        None => return -libc::ENOSYS,
                    },
                    state.userdata as *mut c_void,
                )
            };
            let mut endpoint = native::Endpoint::default();
            let status = (api.endpoint)(id, runtime, &mut endpoint);
            if status != 0 {
                return status;
            }
            if !endpoint_matches(&endpoint, controller, descriptor) {
                return -libc::EPROTO;
            }
            let status = (api.register)(
                id,
                control,
                runtime,
                Some(acquire),
                Some(query),
                Some(end),
                Some(release),
                userdata,
            );
            if status != 0 {
                return status;
            }
            {
                let Ok(mut state) = controller.actor.lock() else {
                    return -libc::EOWNERDEAD;
                };
                state.registered = true;
            }
            let mut born = std::ptr::null_mut();
            let status = (api.start)(id, runtime, 256 * 1024, Some(entry), userdata, &mut born);
            // Constructor output is retained before any separate postcut. Entry may
            // already have recorded its authentic actor argument; they must agree.
            let Ok(mut state) = controller.actor.lock() else {
                return -libc::EOWNERDEAD;
            };
            state.constructor_address = born as usize;
            if !born.is_null() {
                if state.address != 0 && state.address != born as usize {
                    return -libc::ESTALE;
                }
                state.address = born as usize;
            }
            if status != 0 {
                return status;
            }
            if born.is_null() {
                return -libc::EPROTO;
            }
            0
        })
        .map_err(RamError::InstallerSource)
}

fn endpoint_matches(
    endpoint: &native::Endpoint,
    controller: &LivePagerController,
    fd: i32,
) -> bool {
    if endpoint.schema_version != 1
        || endpoint.struct_size as usize != size_of::<native::Endpoint>()
        || endpoint.purpose.is_null()
        || endpoint.descriptor != fd
        || fd < 0
        || endpoint.reserved != 0
        || endpoint.reserved2 != 0
        || endpoint.template > 1
        || endpoint.session.is_null()
        || endpoint.target_daemon.is_null()
        || endpoint.target_owner.is_null()
        || endpoint.target_node.is_null()
    {
        return false;
    }
    // SAFETY: the successful genuine endpoint borrow lends four immutable exact
    // 32-byte identifiers through this installing invocation. They do not escape.
    let identifiers = unsafe {
        (
            *endpoint.session.cast::<[u8; 32]>(),
            *endpoint.target_daemon.cast::<[u8; 32]>(),
            *endpoint.target_owner.cast::<[u8; 32]>(),
            *endpoint.target_node.cast::<[u8; 32]>(),
        )
    };
    identifiers
        == (
            controller.session,
            controller.target.daemon_epoch,
            controller.target.owner_id,
            controller.target.node_id,
        )
        && endpoint.owner_generation == controller.target.owner_generation
        && endpoint.arena_generation == controller.target.arena_generation
        && endpoint.template == u32::from(controller.target.retained_template)
}

fn bound_controller(id: u64, userdata: *mut c_void) -> Result<Arc<LivePagerController>, i32> {
    let owner = controller()
        .map_err(|_| -libc::EOWNERDEAD)?
        .ok_or(-libc::ENOKEY)?;
    {
        let state = owner.actor.lock().map_err(|_| -libc::EOWNERDEAD)?;
        if !state.registered
            || state.plugin_id != id
            || state.userdata != userdata as usize
            || userdata.is_null()
            || (state.constructor_address != 0 && state.constructor_address != state.address)
        {
            return Err(-libc::ESTALE);
        }
    }
    Ok(owner)
}

extern "C" fn entry(id: u64, actor: *mut Actor, fd: i32, userdata: *mut c_void) -> i32 {
    let Ok(owner) = bound_controller(id, userdata) else {
        return -libc::ESTALE;
    };
    if actor.is_null() || fd < 0 {
        return -libc::EINVAL;
    }
    let api = {
        let Ok(mut state) = owner.actor.lock() else {
            return -libc::EOWNERDEAD;
        };
        if state.address != 0 && state.address != actor as usize {
            return -libc::ESTALE;
        }
        state.address = actor as usize;
        match state.api {
            Some(api) => api,
            None => return -libc::ENOSYS,
        }
    };
    // Runtime userdata is never dereferenced by this concurrent entry. The
    // genuine native actor retains its borrowed endpoint until entry returns.
    reader::run(&owner, id, actor, fd, api)
}

fn record_matches(
    state: &ActorState,
    actor: *mut Actor,
    loan: *mut Receive,
    actual: *mut c_void,
) -> bool {
    !actor.is_null()
        && !loan.is_null()
        && !actual.is_null()
        && state.address == actor as usize
        && state.record.actor == actor as usize
        && state.record.loan == loan as usize
        && actual == std::ptr::from_ref(&state.record).cast_mut().cast()
        && state.record.operation.is_some()
}

fn observation_status(error: &ObservationOperationError) -> i32 {
    match error {
        ObservationOperationError::Io(error) => -error.raw_os_error().unwrap_or(libc::EIO),
        ObservationOperationError::Static { kind, .. } => -match kind {
            io::ErrorKind::TimedOut => libc::ETIMEDOUT,
            io::ErrorKind::Interrupted => libc::ECANCELED,
            io::ErrorKind::WouldBlock => libc::EBUSY,
            io::ErrorKind::InvalidInput => libc::EINVAL,
            _ => libc::EIO,
        },
    }
}

extern "C" fn acquire(
    id: u64,
    actor: *mut Actor,
    loan: *mut Receive,
    userdata: *mut c_void,
    output: *mut *mut c_void,
) -> i32 {
    if actor.is_null() || loan.is_null() || output.is_null() {
        return -libc::EINVAL;
    }
    let owner = match bound_controller(id, userdata) {
        Ok(owner) => owner,
        Err(status) => return status,
    };
    let Ok(mut state) = owner.actor.lock() else {
        return -libc::EOWNERDEAD;
    };
    if state.address != actor as usize
        || state.record.acquire_attempted
        || state.record.operation.is_some()
    {
        return -libc::EBUSY;
    }
    state.record.actor = actor as usize;
    state.record.loan = loan as usize;
    state.record.acquire_attempted = true;
    match owner.begin_inline::<true>(SourceOperationClass::Cleanup) {
        Ok(operation) => state.record.operation = Some(operation),
        Err(error) => {
            let status = observation_status(&error);
            state.record.failure = Some(error);
            return status;
        }
    }
    let actual = std::ptr::from_mut(&mut state.record).cast();
    // SAFETY: native registered acquisition lends its output slot for this
    // call. Only this actual controller-inline owner is returned; no input
    // coordinate supplies an allocation or nominal native record lease.
    unsafe {
        *output = actual;
    }
    let Some(operation) = state.record.operation.as_ref() else {
        return -libc::ENOKEY;
    };
    // Native records a returned actual owner even when acquisition reports a
    // negative. Keep the born clock and its terminal refusal through that
    // uncertain first-byte bank instead of dropping it at the first postcut.
    match operation.wait_slice_for_observation() {
        Ok(_) => 0,
        Err(error) => {
            let status = observation_status(&error);
            state.record.failure = Some(error);
            status
        }
    }
}

extern "C" fn query(
    id: u64,
    actor: *mut Actor,
    loan: *mut Receive,
    actual: *mut c_void,
    userdata: *mut c_void,
    output: *mut u64,
) -> i32 {
    if output.is_null() {
        return -libc::EINVAL;
    }
    let owner = match bound_controller(id, userdata) {
        Ok(owner) => owner,
        Err(status) => return status,
    };
    let mut state = match owner.actor.lock() {
        Ok(state) => state,
        Err(_) => return -libc::EOWNERDEAD,
    };
    if !record_matches(&state, actor, loan, actual) || state.record.end_attempted {
        return -libc::ESTALE;
    }
    let result = match state.record.operation.as_ref() {
        Some(operation) => operation.wait_slice_for_observation(),
        None => return -libc::ENOKEY,
    };
    let result = result.map_err(|error| {
        let status = observation_status(&error);
        state.record.failure = Some(error);
        status
    });
    match result.and_then(|slice| u64::try_from(slice.as_nanos()).map_err(|_| -libc::EOVERFLOW)) {
        Ok(ns) if ns > 0 => {
            // SAFETY: native lends this scalar only through its same lease query.
            unsafe {
                *output = ns;
            }
            0
        }
        Ok(_) => -libc::ETIMEDOUT,
        Err(status) => status,
    }
}

extern "C" fn end(
    id: u64,
    actor: *mut Actor,
    loan: *mut Receive,
    actual: *mut c_void,
    userdata: *mut c_void,
    output: *mut EndStatus,
) -> i32 {
    if output.is_null() {
        return -libc::EINVAL;
    }
    let owner = match bound_controller(id, userdata) {
        Ok(owner) => owner,
        Err(status) => return status,
    };
    let Ok(mut state) = owner.actor.lock() else {
        return -libc::EOWNERDEAD;
    };
    if !record_matches(&state, actor, loan, actual) || state.record.end_attempted {
        return -libc::ESTALE;
    }
    state.record.end_attempted = true;
    let Some(operation) = state.record.operation.as_ref() else {
        return -libc::ENOKEY;
    };
    let completed = operation.complete_observation();
    let journal = match operation.terminal.load(Ordering::Acquire) {
        0 => 1,
        1 => 2,
        _ => 0,
    };
    let status = match completed {
        Ok(()) => 0,
        Err(error) => {
            let status = observation_status(&error);
            state.record.failure = Some(error);
            status
        }
    };
    state.record.end_result = status;
    state.record.terminal_journal = journal;
    // SAFETY: native lends its independent completion journal output for this
    // registered invocation. Actual completion is observed even after failure.
    unsafe {
        *output = EndStatus {
            terminal_journal: journal,
            completion_result: status,
        };
    }
    status
}

extern "C" fn release(
    id: u64,
    actor: *mut Actor,
    loan: *mut Receive,
    actual: *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    let owner = match bound_controller(id, userdata) {
        Ok(owner) => owner,
        Err(status) => return status,
    };
    let Ok(mut state) = owner.actor.lock() else {
        return -libc::EOWNERDEAD;
    };
    if !record_matches(&state, actor, loan, actual) || !state.record.completion_known() {
        return -libc::ESTALE;
    }
    // Native invokes release only after actual bank confirmation and keeps
    // admission closed until zero. A negative semantic end result remains in
    // native first/post journals; it does not undo actual Completed custody.
    // Dropping this inline operation releases its registry slot without another
    // completion call or access to the already returned native bank.
    state.record = RecordState::default();
    0
}

pub(super) fn prepare_fork(owner: &LivePagerController) -> Result<(), RamError> {
    let (api, id, address) = {
        let state = owner
            .actor
            .lock()
            .map_err(|_| RamError::Invariant("RAM actor owner poisoned"))?;
        (
            state
                .api
                .ok_or(RamError::Invariant("native RAM SDK absent"))?,
            state.plugin_id,
            state.address,
        )
    };
    if address == 0 {
        return Err(RamError::Invariant("RAM native actor absent"));
    }
    let status = (api.quiesce)(id, address as *mut Actor);
    if status != 0 {
        return Err(RamError::Native {
            operation: "native RAM actor parent quiescence",
            status,
        });
    }
    let status = (api.quiesce_join)(id, address as *mut Actor);
    if status != 0 {
        return Err(RamError::Native {
            operation: "native RAM actor parent join",
            status,
        });
    }
    final_seal(owner)
}

pub(super) fn final_seal(owner: &LivePagerController) -> Result<(), RamError> {
    let state = owner
        .actor
        .lock()
        .map_err(|_| RamError::Invariant("RAM actor owner poisoned"))?;
    let mut output = native::ActorStatus::default();
    let api = state
        .api
        .ok_or(RamError::Invariant("native RAM SDK absent"))?;
    let status = (api.observe)(state.plugin_id, state.address as *mut Actor, &mut output);
    if status != 0 {
        return Err(RamError::Native {
            operation: "native RAM actor join observation",
            status,
        });
    }
    if state.address == 0
        || state.constructor_address != state.address
        || output.schema_version != 1
        || output.struct_size as usize != size_of::<native::ActorStatus>()
        || output.born != 1
        || output.returned != 1
        || output.joined != 1
        || output.join_attempted != 1
        || output.join_result != 0
        || output.join_errno != 0
        || output.entry_status != 0
        || output.first_status != 0
        || output.post_status != 0
        || state.record.acquire_attempted
        || state.record.operation.is_some()
    {
        return Err(RamError::Invariant(
            "native RAM actor clean join not observed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
