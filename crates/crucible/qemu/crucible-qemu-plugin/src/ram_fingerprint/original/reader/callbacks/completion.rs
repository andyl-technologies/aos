//! Saves actual read receipts before acknowledging their completed handoff.
//!
//! Delivery remains pending until Source independently records the callback's
//! real return and its factual post. The next constructor or Root view return
//! corroborates that final record before reusing the enrolled receipt fields.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use abi::SourceRead;

pub(super) extern "C" fn completed(
    source: *mut SourceOwner,
    owner_epoch: u64,
    read_epoch: u64,
    receipt: *const SourceRead,
) -> c_int {
    entered(|| {
        let (owner, api) = owner()?;
        clean((api.completion_identity)(
            owner.plugin_id,
            source,
            owner_epoch,
            read_epoch,
            receipt,
        ))?;
        if receipt.is_null()
            || source != owner.reader.holder.load(Ordering::Acquire)
            || owner_epoch != owner.reader.epoch.load(Ordering::Acquire)
        {
            return Err(-libc::ESTALE);
        }
        owner
            .reader
            .corroborate_completion(owner)
            .map_err(|_| -libc::EIO)?;
        // SAFETY: Source authenticated this exact initialized callback argument
        // and its retained delivery phase above. The copy carries facts only.
        let source_read = unsafe { receipt.read() };
        if source_read.owner_epoch != owner_epoch
            || source_read.source_epoch != read_epoch
            || source_read.held != 0
            || source_read.consumed != 1
            || source_read.uncertain != 0
            || source_read.source_post_recorded != 1
        {
            return Err(-libc::EPROTO);
        }
        let mut state = owner.reader.state.try_lock().map_err(|_| -libc::EBUSY)?;
        if state.owner_epoch != owner_epoch
            || state
                .child
                .as_ref()
                .is_some_and(|child| child.loan.is_some())
        {
            return Err(-libc::EOWNERDEAD);
        }
        if source_read.callback_entered == 1 {
            if state.journal.observation.source_epoch != read_epoch
                || source_read.module_epoch != state.journal.observation.module_epoch
                || source_read.module_born != state.journal.observation.born
                || source_read.module_consumed != state.journal.disposition.consumed
            {
                return Err(-libc::ESTALE);
            }
        } else if source_read.callback_entered != 0
            || source_read.callback_returned != 0
            || source_read.module_epoch != 0
            || source_read.module_born != 0
            || source_read.module_consumed != 0
        {
            return Err(-libc::EPROTO);
        }
        // Source no-call may follow a prior Module birth. Preserve that prior
        // Module journal byte-for-byte; the new Source receipt says no call.
        state.receipt = CompletedReceipt {
            module: state.journal,
            source: source_read,
        };
        state.completion_pending = true;
        drop(state);

        // The real Source acknowledgement compares both complete enrolled
        // copies and the unchanged canonical journal against its own snapshot.
        let status = signed((api.acknowledge_completion)(
            owner.plugin_id,
            source,
            owner_epoch,
            read_epoch,
            receipt,
        ));
        owner
            .reader
            .state
            .try_lock()
            .map_err(|_| -libc::EBUSY)?
            .acknowledgement_status = Some(status);
        Ok(status)
    })
}
