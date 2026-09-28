//! Scoped dormant V2 regular-file callbacks over the existing typed reducers.
//!
//! The C-owned reply buffer is not published until the complete READ succeeds.
//! No raw handle, deadline or byte-layout descriptor grants backing disclosure.

use aos_filesystem_view::{ObjectReadRequest, ObjectReadResult, VerifiedObjectReader};

use super::*;
use crate::dormant_libfuse::{DormantOpenCompletionV2, ProtectedFuseRegistrationCommitResultV2};
use crate::file_callbacks::{OpenReplyPlan, OpenReplySelection};
use crate::operations::{FileHandleRequest, ReadRequest, ReleaseRequest};

impl From<OperationError> for Failure {
    fn from(error: OperationError) -> Self {
        if matches!(error, OperationError::Integrity) {
            Self::Fatal
        } else {
            Self::Errno(error.errno())
        }
    }
}

struct ReaderBorrow<'reader>(&'reader mut dyn VerifiedObjectReader);

impl VerifiedObjectReader for ReaderBorrow<'_> {
    fn read_verified(
        &mut self,
        request: ObjectReadRequest<'_>,
        destination: &mut [u8],
    ) -> Result<ObjectReadResult, aos_filesystem_view::DataError> {
        self.0.read_verified(request, destination)
    }
}

unsafe extern "C" fn open(
    raw: *mut c_void,
    node: u64,
    flags: i32,
    deadline_ns: u64,
    responder: *mut c_void,
    reply: abi::ReplyOpen,
) -> c_int {
    // SAFETY: The runner supplies the unique scoped Context, and the one-shot
    // responder belongs to C's current stack. Neither escapes this invocation.
    unsafe {
        dispatch(raw, |context| {
            if responder.is_null() {
                return Err(Failure::Fatal);
            }
            let state = context.fallback.as_mut().ok_or(Failure::Fatal)?;
            state
                .adapter
                .bind_transport_deadline(&context.connection, deadline_ns)?;
            let pending = state.adapter.prepare_open(
                &mut context.connection,
                &state.data,
                node,
                flags,
                None,
                context.budget,
            )?;
            let persisted = state
                .adapter
                .persist_registration_snapshot(
                    &context.connection,
                    state.durable,
                    state.owner,
                    pending.registration_persistence_authority(),
                )
                .map_err(|_| Failure::Fatal)?;
            let ProtectedFuseRegistrationCommitResultV2::Confirmed(current) = persisted else {
                return Err(Failure::Fatal);
            };
            let authorization = state
                .adapter
                .authorize_open_plan(&context.connection, state.durable, &pending, current)
                .map_err(|_| Failure::Fatal)?;
            let OpenReplyPlan::Fallback { handle } = authorization.plan() else {
                return Err(Failure::Fatal);
            };
            let control = Control::from_absolute_deadline(context.cancellation, deadline_ns)
                .map_err(|_| Failure::Fatal)?;
            require_continue(&control).map_err(|_| Failure::Fatal)?;

            let publication = if reply(responder, handle) == 0 {
                OpenPublication::Published {
                    raw_handle: handle,
                    selection: OpenReplySelection::Fallback,
                }
            } else {
                // A failed write may have exposed an OPEN prefix. Retain the
                // worker pin for terminal teardown, never claim definite abort.
                OpenPublication::Ambiguous
            };
            let receipt = state
                .adapter
                .observe_open_publication(&context.connection, &pending, publication, authorization)
                .map_err(|_| Failure::Fatal)?;
            match state
                .adapter
                .finish_open(&mut context.connection, pending, receipt)
            {
                Ok(Ok(DormantOpenCompletionV2::Published { handle: actual }))
                    if actual == handle =>
                {
                    Ok(())
                }
                _ => Err(Failure::Fatal),
            }
        })
    }
}

unsafe extern "C" fn read(
    raw: *mut c_void,
    node: u64,
    handle: u64,
    offset: i64,
    size: u32,
    deadline_ns: u64,
    target: *mut u8,
    capacity: u64,
    length: *mut u64,
) -> c_int {
    // SAFETY: C supplies unique nonoverlapping output buffers. No byte is
    // copied from Rust's private staging until the complete typed READ succeeds.
    unsafe {
        dispatch(raw, |context| {
            let length = output(length)?;
            *length = 0;
            let capacity = checked_length(
                target,
                capacity,
                u64::from(context.limits.maximum_write_bytes),
            )?;
            if u64::from(size) > capacity as u64 {
                return Err(Failure::Errno(libc::ENOMEM));
            }
            let state = context.fallback.as_mut().ok_or(Failure::Fatal)?;
            state
                .adapter
                .bind_transport_deadline(&context.connection, deadline_ns)?;
            let current = state
                .adapter
                .current_registration_readback(&context.connection, state.durable, state.owner)
                .map_err(|_| Failure::Fatal)?;
            let result = state.adapter.read(
                &context.connection,
                &state.data,
                ReadRequest {
                    file: FileHandleRequest {
                        node_id: node,
                        handle,
                    },
                    offset,
                    size,
                    deadline_ns,
                },
                &mut state.scratch,
                &mut ReaderBorrow(state.reader),
                state.durable,
                current,
            )?;
            // Backend work may take time. Rejoin the same protected names and
            // exact reducer snapshot before any private bytes leave Rust.
            let final_current = state
                .adapter
                .current_registration_readback(&context.connection, state.durable, state.owner)
                .map_err(|_| Failure::Fatal)?;
            let control = Control::from_absolute_deadline(context.cancellation, deadline_ns)
                .map_err(|_| Failure::Fatal)?;
            require_continue(&control)?;
            let bytes = result.bytes();
            if bytes.len() > capacity {
                return Err(Failure::Fatal);
            }
            if !bytes.is_empty() {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), target, bytes.len());
            }
            *length = bytes.len() as u64;
            drop(final_current);
            Ok(())
        })
    }
}

unsafe extern "C" fn release(
    raw: *mut c_void,
    node: u64,
    handle: u64,
    flags: i32,
    release_flags: u32,
    lock_owner: u64,
    deadline_ns: u64,
) -> c_int {
    // SAFETY: Only synchronous scalar inputs and the unique Context cross C.
    unsafe {
        dispatch(raw, |context| {
            let state = context.fallback.as_mut().ok_or(Failure::Fatal)?;
            state
                .adapter
                .bind_transport_deadline(&context.connection, deadline_ns)?;
            let mut pending = state.adapter.prepare_release(
                &context.connection,
                &state.data,
                ReleaseRequest {
                    file: FileHandleRequest {
                        node_id: node,
                        handle,
                    },
                    flags,
                    release_flags,
                    lock_owner,
                },
            )?;
            if pending.disposition() != aos_filesystem_view::ReleaseDisposition::FallbackComplete {
                return Err(Failure::Fatal);
            }
            let persisted = state
                .adapter
                .persist_registration_snapshot(
                    &context.connection,
                    state.durable,
                    state.owner,
                    pending.registration_persistence_authority(),
                )
                .map_err(|_| Failure::Fatal)?;
            let ProtectedFuseRegistrationCommitResultV2::Confirmed(current) = persisted else {
                return Err(Failure::Fatal);
            };
            let authorization = state
                .adapter
                .authorize_release_plan(&context.connection, state.durable, &mut pending, current)
                .map_err(|_| Failure::Fatal)?;
            state
                .adapter
                .finish_release(&mut context.connection, pending, authorization)
                .map_err(|_| Failure::Fatal)
        })
    }
}

fn require_continue(control: &Control) -> Result<(), Failure> {
    match control.state(RequestCheckpoint::AfterReadOnlyWork) {
        RequestControlState::Continue => Ok(()),
        RequestControlState::Cancelled => Err(Failure::Errno(libc::EINTR)),
        RequestControlState::DeadlineExpired => Err(Failure::Errno(libc::ETIMEDOUT)),
    }
}

pub(crate) static FALLBACK_OPERATIONS_V2: abi::FallbackOperationsV2 = abi::FallbackOperationsV2 {
    abi_major: 2,
    abi_minor: 0,
    struct_size: size_of::<abi::FallbackOperationsV2>() as u32,
    profile: 1,
    reserved: 0,
    metadata: super::OPERATIONS,
    open,
    read,
    release,
};

#[cfg(all(test, debug_assertions))]
mod tests;
