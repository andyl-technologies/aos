//! Retains local Park journal writes in the actual mapped-slot child.
//!
//! The first-bound Source member must independently authenticate the writer,
//! its received Park request and the same retained setup mapping. These bounded
//! mechanics only publish Source-produced bytes; neither decoded records nor
//! local writer release supply operation or physical-return authority.
// SPDX-License-Identifier: GPL-2.0-only

use crucible_qemu_protocol::parent_park_return::{PARENT_PARK_RETURN_BYTES, ParentParkReturn};
use crucible_qemu_shmem::NodeSlot;
use std::sync::{Mutex, TryLockError};

/// Reports local effects independently of the canonical Park return statuses.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::runtime) struct WriteProgress {
    pub(in crate::runtime) first_status: i32,
    pub(in crate::runtime) post_status: i32,
    pub(in crate::runtime) write_attempted: u32,
    pub(in crate::runtime) return_published: u32,
    pub(in crate::runtime) writer_released: u32,
    pub(in crate::runtime) publication_uncertain: u32,
}

const _: () = assert!(std::mem::size_of::<WriteProgress>() == 24);
const _: () = assert!(std::mem::align_of::<WriteProgress>() == 4);

impl WriteProgress {
    pub(in crate::runtime) fn status(self) -> i32 {
        if self.first_status != 0 {
            self.first_status
        } else {
            self.post_status
        }
    }

    fn refused(status: i32) -> Self {
        Self {
            first_status: status,
            ..Self::default()
        }
    }
}

/// Publishes only through the genuine member's first-bound mapped child.
///
/// Source supplies the same retained child userdata as its reader, exactly one
/// canonical return record and an aligned, disjoint progress output. The
/// callback returns local write facts before signed status; it does not return
/// a Park, material, Source or Runtime owner.
pub(in crate::runtime) extern "C" fn protected_park_return_writer(
    source_wire: *const u8,
    bytes: usize,
    progress: *mut WriteProgress,
    userdata: *mut std::ffi::c_void,
) -> i32 {
    if progress.is_null() {
        return -libc::EINVAL;
    }
    let state = std::ptr::NonNull::new(userdata.cast::<super::LiveVcpuTimeCallbackState>());
    let outcome = if let Some(state) = state
        && !source_wire.is_null()
        && bytes == PARENT_PARK_RETURN_BYTES
    {
        // SAFETY: the genuine Source member retains this complete child, its
        // mapped slot and the exact immutable input for the whole invocation.
        // Neither pointer comes from the shared-memory return record.
        let state = unsafe { state.as_ref() };
        // SAFETY: Source supplies exactly the checked 184 readable bytes. The
        // bounded writer copies them into its own journal before decoding.
        let wire = unsafe { &*source_wire.cast::<[u8; PARENT_PARK_RETURN_BYTES]>() };
        state.slot.park_writer.write(state.slot.get(), wire)
    } else {
        WriteProgress::refused(-libc::EINVAL)
    };
    // SAFETY: the first-bound Source call supplies the aligned exclusive output,
    // distinct from the retained child, input record and mapped journal.
    unsafe {
        progress.write(outcome);
    }
    outcome.status()
}

struct WriteJournal {
    sequence: u64,
    bytes: [u8; PARENT_PARK_RETURN_BYTES],
    received: bool,
    progress: WriteProgress,
}

/// Lives inline in the complete child allocation before Source member birth.
pub(in crate::runtime) struct ProtectedWriter {
    journal: Mutex<WriteJournal>,
}

impl ProtectedWriter {
    pub(in crate::runtime) const fn new() -> Self {
        Self {
            journal: Mutex::new(WriteJournal {
                sequence: 0,
                bytes: [0; PARENT_PARK_RETURN_BYTES],
                received: false,
                progress: WriteProgress {
                    first_status: 0,
                    post_status: 0,
                    write_attempted: 0,
                    return_published: 0,
                    writer_released: 0,
                    publication_uncertain: 0,
                },
            }),
        }
    }

    /// Writes only inside the genuine first-bound Source writer invocation.
    pub(in crate::runtime) fn write(
        &self,
        slot: &NodeSlot,
        bytes: &[u8; PARENT_PARK_RETURN_BYTES],
    ) -> WriteProgress {
        self.write_with_post(slot, bytes, || {})
    }

    fn write_with_post(
        &self,
        slot: &NodeSlot,
        bytes: &[u8; PARENT_PARK_RETURN_BYTES],
        interleave: impl FnOnce(),
    ) -> WriteProgress {
        let mut journal = match self.journal.try_lock() {
            Ok(journal) => journal,
            Err(TryLockError::WouldBlock) => return WriteProgress::refused(-libc::EBUSY),
            Err(TryLockError::Poisoned(_)) => return WriteProgress::refused(-libc::EOWNERDEAD),
        };
        if journal.received {
            if journal.progress.status() != 0
                || journal.progress.publication_uncertain != 0
                || journal.progress.writer_released == 0
            {
                // A negative outcome never rolls back the previous write or
                // authorizes replay, even if the mapped bytes are now visible.
                return WriteProgress::refused(-libc::EALREADY);
            }
            if journal.bytes == *bytes {
                return WriteProgress::refused(-libc::EALREADY);
            }
        }

        // Keep the actual input before decoding or any mapped write. Source
        // retains this same child on every negative/unknown callback result.
        journal.bytes = *bytes;
        journal.received = true;
        journal.progress = WriteProgress::default();
        let returned = match ParentParkReturn::decode(bytes) {
            Ok(returned) => returned,
            _ => {
                journal.progress.first_status = -libc::EPROTO;
                journal.progress.writer_released = 1;
                return journal.progress;
            }
        };

        journal.progress.write_attempted = 1;
        match slot.publish_parent_park_return(journal.sequence, returned) {
            Ok(sequence) => {
                journal.sequence = sequence;
                journal.progress.return_published = 1;
            }
            Err(_) => {
                // A failed seqlock publication may have crossed its opening
                // store. Retain the real bytes and never retry that write.
                journal.progress.first_status = -libc::EIO;
                journal.progress.publication_uncertain = 1;
            }
        }

        interleave();
        if journal.progress.return_published != 0 {
            match slot.observe_parent_park_return() {
                Ok(Some(observed)) if observed == returned => {}
                _ => {
                    journal.progress.post_status = -libc::EAGAIN;
                    journal.progress.publication_uncertain = 1;
                }
            }
        }
        journal.progress.writer_released = 1;
        let progress = journal.progress;
        drop(journal);
        progress
    }
}

#[cfg(test)]
mod tests;
