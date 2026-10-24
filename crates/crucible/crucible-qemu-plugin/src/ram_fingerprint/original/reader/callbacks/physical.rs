//! Returns the actual Module read subloan using factual identity alone.
//!
//! A refused local return retains the same Loan in the paid Runtime field.
//! Known consumption remains recorded even if its independent Source post
//! refuses, and no path retries a consumed loan or queries a dead Original.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

pub(super) extern "C" fn return_read(
    source: *mut SourceChild,
    epoch: u64,
    out: *mut Disposition,
) -> c_int {
    entered(|| {
        let (owner, api) = owner()?;
        clean((api.child_return_identity)(source, epoch))?;
        if out.is_null() {
            return Err(-libc::EINVAL);
        }
        let mut state = owner.reader.state.try_lock().map_err(|_| -libc::EBUSY)?;
        let observation = state.journal.observation;
        if observation.source_epoch != epoch || state.journal.disposition.schema_version != 0 {
            return Err(-libc::ESTALE);
        }
        let mut disposition = Disposition {
            schema_version: 1,
            struct_size: std::mem::size_of::<Disposition>() as u32,
            source_epoch: epoch,
            module_epoch: observation.module_epoch,
            module_child: observation.module_child,
            ..Disposition::default()
        };
        if observation.born == 1 {
            if !selected(&state, source, epoch) {
                return Err(-libc::ESTALE);
            }
            disposition.attempted = 1;
            // Keep the canonical child protected across this callback-free,
            // nonwaiting local return. No Source function is called under it.
            let result = state
                .child
                .as_mut()
                .and_then(|child| child.loan.as_mut())
                .ok_or(-libc::ESTALE)?
                .return_physical();
            disposition.returned = 1;
            match result {
                Ok(()) => {
                    let child = state.child.as_mut().ok_or(-libc::ESTALE)?;
                    // This Loan's release bit is already set. Its destructor
                    // cannot retry consumption after leaving the paid field.
                    child.loan.take();
                    disposition.consumed = 1;
                }
                Err(error) => {
                    disposition.first_status = error_status(&error);
                    disposition.uncertain = 1;
                    state.return_error = Some(error);
                }
            }
        } else if observation.born != 0
            || observation.module_child != 0
            || observation.module_epoch != 0
        {
            return Err(-libc::EPROTO);
        }
        state.journal.disposition = disposition;
        drop(state);

        let post = signed((api.child_return_identity)(source, epoch));

        let mut state = owner.reader.state.try_lock().map_err(|_| -libc::EBUSY)?;
        if state.journal.disposition.source_epoch != epoch {
            return Err(-libc::ESTALE);
        }
        state.journal.disposition.post_status = post;
        state.journal.disposition.post_recorded = 1;
        let disposition = state.journal.disposition;
        // SAFETY: Source's authenticated return phase lends this exclusively
        // writable disposition for the synchronous call; no pointer escapes.
        unsafe {
            out.write(disposition);
        }
        // The independent post stays in its own field. A known consumed child
        // remains consumed even when that post is negative.
        Ok(disposition.first_status)
    })
}

pub(super) extern "C" fn returned_current(
    source: *mut SourceChild,
    epoch: u64,
    out: *const Disposition,
) -> c_int {
    entered(|| {
        let (owner, api) = owner()?;
        clean((api.child_return_identity)(source, epoch))?;
        if out.is_null() {
            return Err(-libc::EINVAL);
        }
        // SAFETY: the authenticated factual Source return-post phase lends
        // this initialized immutable copy. It never contains a Rust pointer.
        let observed = unsafe { out.read() };
        let state = owner.reader.state.try_lock().map_err(|_| -libc::EBUSY)?;
        let expected = state.journal.disposition;
        if observed != expected
            || expected.source_epoch != epoch
            || expected.post_recorded != 1
            || expected.uncertain != 0
            || expected.reserved != 0
        {
            return Err(-libc::ESTALE);
        }
        if state.journal.observation.born == 1 {
            if !selected(&state, source, epoch)
                || state
                    .child
                    .as_ref()
                    .is_none_or(|child| child.loan.is_some())
                || expected.attempted != 1
                || expected.returned != 1
                || expected.consumed != 1
            {
                return Err(-libc::EOWNERDEAD);
            }
        } else if expected.attempted != 0 || expected.returned != 0 || expected.consumed != 0 {
            return Err(-libc::EPROTO);
        }
        Ok(0)
    })
}
