//! Runs registered read callbacks beneath the actual retained Root subloan.
//!
//! Source authenticates every entered phase before Module touches a child.
//! Callback status and independent posts occupy different paid journal fields;
//! factual physical return never samples an Original or a replacement clock.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use abi::{Callbacks, Disposition, Observation};

mod completion;
mod physical;

pub(super) static CALLBACKS: Callbacks = Callbacks {
    schema_version: 1,
    struct_size: std::mem::size_of::<Callbacks>() as u32,
    ordinary,
    root_scratch,
    post,
    return_read: physical::return_read,
    returned_current: physical::returned_current,
    completed: completion::completed,
};

/// Contains unwinding at the FFI boundary; paid custody survives a panic.
fn entered(body: impl FnOnce() -> Result<c_int, c_int>) -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body))
        .unwrap_or(Err(-libc::EIO))
        .unwrap_or_else(|status| status)
}

fn owner() -> Result<(&'static Owner, Api), c_int> {
    let owner = active_owner().ok_or(-libc::ENODEV)?;
    if owner.owner_process != std::process::id() {
        return Err(-libc::ESTALE);
    }
    Ok((owner, owner.reader.api.ok_or(-libc::ENOTSUP)?))
}

fn clean(status: c_int) -> Result<(), c_int> {
    if status == 0 {
        Ok(())
    } else {
        Err(signed(status))
    }
}

fn signed(status: c_int) -> c_int {
    if status <= 0 { status } else { -libc::EPROTO }
}

fn error_status(error: &ObservationOperationError) -> c_int {
    match error {
        ObservationOperationError::Io(error) => error
            .raw_os_error()
            .filter(|errno| *errno > 0)
            .map_or(-libc::EIO, |errno| -errno),
        ObservationOperationError::Static { .. } => -libc::EIO,
    }
}

fn selected(state: &ReaderState, source: *mut SourceChild, epoch: u64) -> bool {
    state
        .child
        .as_ref()
        .is_some_and(|child| child.source == source as usize && child.epoch == epoch)
}

extern "C" fn ordinary(
    source: *mut SourceChild,
    epoch: u64,
    address: u64,
    output: *mut u8,
    valid: u32,
) -> c_int {
    entered(|| {
        read(source, epoch, || {
            crate::paged_ram::engine::operational_read(address, output, valid)
        })
    })
}

extern "C" fn root_scratch(
    source: *mut SourceChild,
    epoch: u64,
    address: u64,
    scratch: *mut crate::paged_ram::engine::NativeRootScratch,
    valid: u32,
    hasher: *const crate::paged_ram::source::NativePageHasher,
) -> c_int {
    entered(|| {
        read(source, epoch, || {
            crate::paged_ram::engine::root_scratch_read(address, scratch, valid, hasher)
        })
    })
}

fn read(
    source: *mut SourceChild,
    epoch: u64,
    body: impl FnOnce() -> c_int,
) -> Result<c_int, c_int> {
    let (owner, api) = owner()?;
    clean((api.child_identity)(source, epoch))?;
    owner
        .reader
        .corroborate_completion(owner.plugin_id)
        .map_err(|_| -libc::EIO)?;
    let selector = owner.selector();
    let mut state = owner.reader.state.try_lock().map_err(|_| -libc::EBUSY)?;
    if state.completion_pending
        || state
            .child
            .as_ref()
            .is_some_and(|child| child.loan.is_some())
    {
        return Err(-libc::EBUSY);
    }
    state.journal = Journal {
        observation: Observation {
            schema_version: 1,
            struct_size: std::mem::size_of::<Observation>() as u32,
            source_epoch: epoch,
            birth_attempted: 1,
            ..Observation::default()
        },
        disposition: Disposition::default(),
    };
    state.completion_pending = true;

    // Publish the actual Loan into its stable paid field before fallible
    // Source/Original posts. Failure retains the very same nominal child.
    let loan = selector.and_then(|selector| read::Loan::retain(&owner.state, selector));
    let loan = match loan {
        Ok(loan) => loan,
        Err(error) => {
            let status = error_status(&error);
            state.first_error = Some(error);
            state.journal.observation.first_status = status;
            return Ok(status);
        }
    };
    let module_epoch = loan.serial();
    state.child = Some(Child {
        source: source as usize,
        epoch,
        loan: Some(loan),
    });
    let module_child = state
        .child
        .as_ref()
        .map_or(0, |child| std::ptr::from_ref(child) as usize);
    state.journal.observation.module_epoch = module_epoch;
    state.journal.observation.module_child = module_child;
    state.journal.observation.born = 1;
    drop(state);

    let source_status = signed((api.child_current)(source, epoch));
    // The independent observation of the same Root is mandatory even when
    // Source's child post refused. Neither observation issues another clock.
    let root_post = owner.sample();
    let mut state = owner.reader.state.try_lock().map_err(|_| -libc::EBUSY)?;
    if !selected(&state, source, epoch) {
        return Err(-libc::ESTALE);
    }
    let root_status = match root_post {
        Ok(_) => 0,
        Err(error) => {
            let status = error_status(&error);
            state.first_error = Some(error);
            status
        }
    };
    let first = if source_status != 0 {
        source_status
    } else {
        root_status
    };
    if first != 0 {
        state.journal.observation.first_status = first;
        return Ok(first);
    }
    state.journal.observation.callback_entered = 1;
    drop(state);

    let status = signed(body());

    let mut state = owner.reader.state.try_lock().map_err(|_| -libc::EBUSY)?;
    if !selected(&state, source, epoch) {
        return Err(-libc::ESTALE);
    }
    state.journal.observation.callback_returned = 1;
    state.journal.observation.first_status = status;
    Ok(status)
}

extern "C" fn post(source: *mut SourceChild, epoch: u64, out: *mut Observation) -> c_int {
    entered(|| {
        let (owner, api) = owner()?;
        clean((api.child_identity)(source, epoch))?;
        if out.is_null() {
            return Err(-libc::EINVAL);
        }
        let born = {
            let state = owner.reader.state.try_lock().map_err(|_| -libc::EBUSY)?;
            if state.journal.observation.source_epoch != epoch {
                return Err(-libc::ESTALE);
            }
            state.journal.observation.born == 1
        };
        // No-birth is a factual post only; never query a nonexistent child.
        let source_status = if born {
            signed((api.child_current)(source, epoch))
        } else {
            0
        };
        let root_post = if born {
            owner.sample().map(|_| ())
        } else {
            Ok(())
        };
        let mut state = owner.reader.state.try_lock().map_err(|_| -libc::EBUSY)?;
        if state.journal.observation.source_epoch != epoch
            || (born && !selected(&state, source, epoch))
        {
            return Err(-libc::ESTALE);
        }
        let local_post = if born {
            state
                .child
                .as_ref()
                .and_then(|child| child.loan.as_ref())
                .ok_or(-libc::ESTALE)?
                .current()
        } else {
            Ok(())
        };
        let root_status = match root_post.and(local_post) {
            Ok(()) => 0,
            Err(error) => {
                let status = error_status(&error);
                state.post_error = Some(error);
                status
            }
        };
        let status = if source_status != 0 {
            source_status
        } else {
            root_status
        };
        state.source_post_status = Some(source_status);
        state.journal.observation.post_recorded = 1;
        state.journal.observation.post_status = status;
        // SAFETY: the authenticated Source post lends its exclusively writable
        // observation for this synchronous callback; no pointer escapes.
        unsafe {
            out.write(state.journal.observation);
        }
        Ok(status)
    })
}
