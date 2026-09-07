//! Synchronous callback conversion and panic containment for the private C ABI.
//!
//! The trusted transport supplies nonoverlapping, valid buffers with the declared
//! capacities. Explicit checks reject null, misaligned, oversized, or inconsistent
//! arguments before creating references; they cannot validate arbitrary addresses.
//! No reference or callback token escapes the current invocation.

use std::any::Any;
use std::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

use aos_filesystem_view::{
    ForgetRequest, IndexNodeKind, LookupReply, MetadataConnection, ReplyScratch, RequestBudget,
    RequestCheckpoint, RequestControl, RequestControlState, WorkerAttributes, WorkerError,
};

use crate::{TransportLimits, abi, control::Control};

const FATAL: c_int = -1;

pub(crate) struct Context<'scratch, 'prepared, 'index, 'bytes, 'plan> {
    pub connection: MetadataConnection<'prepared, 'index, 'bytes, 'plan>,
    scratch: &'scratch mut ReplyScratch,
    cancellation: c_int,
    limits: TransportLimits,
    budget: RequestBudget,
    poisoned: bool,
    pub destroyed: bool,
    panic: Option<Box<dyn Any + Send>>,
}

impl<'scratch, 'prepared, 'index, 'bytes, 'plan>
    Context<'scratch, 'prepared, 'index, 'bytes, 'plan>
{
    pub fn new(
        connection: MetadataConnection<'prepared, 'index, 'bytes, 'plan>,
        scratch: &'scratch mut ReplyScratch,
        cancellation: c_int,
        limits: TransportLimits,
        budget: RequestBudget,
    ) -> Self {
        Self {
            connection,
            scratch,
            cancellation,
            limits,
            budget,
            poisoned: false,
            destroyed: false,
            panic: None,
        }
    }

    pub fn failed(&self) -> bool {
        self.poisoned
    }

    pub fn dispose_panic(&mut self) {
        if let Some(payload) = self.panic.take() {
            // Catch a malicious payload destructor independently of the callback
            // unwind. Aborting on a second panic avoids leaking unbounded payloads.
            if let Err(second_payload) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
                // No second payload destructor may run on this abort path.
                std::mem::forget(second_payload);
                std::process::abort();
            }
        }
    }

    fn control(&self) -> Result<Control, Failure> {
        Control::new(self.cancellation, self.limits.request_timeout_seconds)
            .map_err(|_| Failure::Fatal)
    }
}

enum Failure {
    Errno(c_int),
    Fatal,
}

impl From<WorkerError> for Failure {
    fn from(error: WorkerError) -> Self {
        Self::Errno(match error {
            WorkerError::InvalidArgument => libc::EINVAL,
            WorkerError::Stale => libc::ESTALE,
            WorkerError::NotDirectory => libc::ENOTDIR,
            WorkerError::NotSymlink => libc::EINVAL,
            WorkerError::ResourceExhausted | WorkerError::AllocationRefused => libc::ENOMEM,
            WorkerError::Interrupted => libc::EINTR,
            WorkerError::TimedOut => libc::ETIMEDOUT,
            WorkerError::ReadOnlyFilesystem => libc::EROFS,
            WorkerError::OperationNotSupported => libc::EOPNOTSUPP,
            WorkerError::IntegrityFailure => return Self::Fatal,
        })
    }
}

unsafe fn dispatch(
    raw: *mut c_void,
    action: impl FnOnce(&mut Context<'_, '_, '_, '_, '_>) -> Result<(), Failure>,
) -> c_int {
    if raw.is_null() || !(raw as usize).is_multiple_of(align_of::<Context<'_, '_, '_, '_, '_>>()) {
        return FATAL;
    }
    // SAFETY: The scoped runner supplies this unique, live stack Context. The C
    // transport serializes callbacks and never invokes them after run returns.
    let context = unsafe { &mut *raw.cast::<Context<'_, '_, '_, '_, '_>>() };
    if context.poisoned || context.destroyed {
        return FATAL;
    }
    match catch_unwind(AssertUnwindSafe(|| action(context))) {
        Ok(Ok(())) => 0,
        Ok(Err(Failure::Errno(error))) => error,
        Ok(Err(Failure::Fatal)) => {
            context.poisoned = true;
            FATAL
        }
        Err(payload) => {
            context.poisoned = true;
            context.panic = Some(payload);
            FATAL
        }
    }
}

fn checked_length<T>(pointer: *const T, length: u64, maximum: u64) -> Result<usize, Failure> {
    let count = usize::try_from(length).map_err(|_| Failure::Fatal)?;
    if length > maximum
        || count
            .checked_mul(size_of::<T>())
            .is_none_or(|n| n > isize::MAX as usize)
        || (count != 0
            && (pointer.is_null() || !(pointer as usize).is_multiple_of(align_of::<T>())))
    {
        return Err(Failure::Fatal);
    }
    Ok(count)
}

unsafe fn output<'a, T>(pointer: *mut T) -> Result<&'a mut T, Failure> {
    checked_length(pointer, 1, 1)?;
    // SAFETY: The trusted callback ABI guarantees a unique writable output of T;
    // null/alignment checks above precede reference formation. It stays local.
    Ok(unsafe { &mut *pointer })
}

fn attributes(value: WorkerAttributes) -> abi::Attributes {
    abi::Attributes {
        node_id: value.node_id,
        size: value.size,
        mtime_seconds: value.mtime_seconds,
        mtime_nanos: value.mtime_nanos,
        uid: value.uid,
        gid: value.gid,
        nlink: value.nlink,
        mode: value.mode,
        kind: kind(value.kind),
        reserved: 0,
    }
}

fn kind(value: IndexNodeKind) -> u8 {
    match value {
        IndexNodeKind::File => 1,
        IndexNodeKind::Directory => 2,
        IndexNodeKind::Symlink => 3,
    }
}

unsafe extern "C" fn lookup(
    raw: *mut c_void,
    parent: u64,
    name: *const u8,
    length: u64,
    result: *mut abi::Attributes,
) -> c_int {
    // SAFETY: All pointer borrows below are bounded by this synchronous callback.
    unsafe {
        dispatch(raw, |context| {
            let result = output(result)?;
            *result = abi::Attributes::default();
            let length =
                checked_length(name, length, u64::from(context.limits.maximum_name_bytes))?;
            if length == 0 {
                return Err(Failure::Errno(libc::EINVAL));
            }
            let name = std::slice::from_raw_parts(name, length);
            if name.contains(&0) || name.contains(&b'/') {
                return Err(Failure::Errno(libc::EINVAL));
            }
            let control = context.control()?;
            match context
                .connection
                .lookup(parent, name, context.budget, &control)?
            {
                LookupReply::Negative => Err(Failure::Errno(libc::ENOENT)),
                LookupReply::Positive {
                    attributes: value, ..
                } => {
                    *result = attributes(value);
                    Ok(())
                }
            }
        })
    }
}

unsafe extern "C" fn getattr(raw: *mut c_void, node: u64, result: *mut abi::Attributes) -> c_int {
    // SAFETY: The transport provides one unique attribute output for this call.
    unsafe {
        dispatch(raw, |context| {
            let result = output(result)?;
            *result = abi::Attributes::default();
            *result = attributes(context.connection.getattr(
                node,
                context.budget,
                &context.control()?,
            )?);
            Ok(())
        })
    }
}

unsafe extern "C" fn forget(raw: *mut c_void, node: u64, count: u64) -> c_int {
    // SAFETY: Only the scoped context pointer crosses this scalar-only callback.
    unsafe {
        dispatch(raw, |context| {
            context
                .connection
                .forget_one(
                    ForgetRequest::new(node, count),
                    context.budget,
                    &context.control()?,
                )
                .map_err(|_| Failure::Fatal)?;
            Ok(())
        })
    }
}

unsafe extern "C" fn readlink(
    raw: *mut c_void,
    node: u64,
    target: *mut u8,
    capacity: u64,
    length: *mut u64,
) -> c_int {
    // SAFETY: The C-owned target buffer and scalar length output do not overlap
    // each other or Rust scratch; both expire when this callback returns.
    unsafe {
        dispatch(raw, |context| {
            let length = output(length)?;
            *length = 0;
            let capacity = checked_length(
                target,
                capacity,
                u64::from(context.limits.maximum_symlink_bytes),
            )?;
            let control = context.control()?;
            let reply =
                context
                    .connection
                    .readlink(node, context.budget, context.scratch, &control)?;
            let bytes = reply.target();
            if bytes.len() > capacity {
                return Err(Failure::Errno(libc::ENOMEM));
            }
            if !bytes.is_empty() {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), target, bytes.len());
            }
            *length = bytes.len() as u64;
            Ok(())
        })
    }
}

unsafe extern "C" fn opendir(
    raw: *mut c_void,
    node: u64,
    responder: *mut c_void,
    reply: abi::ReplyOpen,
) -> c_int {
    // SAFETY: The responder is the transport's stack object and reply calls no
    // Rust callback recursively. No responder or pending reservation is retained.
    unsafe {
        dispatch(raw, |context| {
            if responder.is_null() {
                return Err(Failure::Fatal);
            }
            let control = context.control()?;
            let mut pending = context
                .connection
                .prepare_opendir(node, context.budget, &control)?;
            let result = reply(responder, pending.raw_handle());
            if result != 0 {
                context
                    .connection
                    .abort_opendir(&mut pending)
                    .map_err(|_| Failure::Fatal)?;
                return Err(Failure::Fatal);
            }
            context
                .connection
                .commit_opendir_after_reply(&mut pending)
                .map_err(|_| Failure::Fatal)?;
            Ok(())
        })
    }
}

unsafe extern "C" fn readdir(
    raw: *mut c_void,
    node: u64,
    handle: u64,
    cookie: u64,
    wire_bytes: u64,
    entries: *mut abi::DirectoryEntry,
    capacity: u64,
    count: *mut u64,
    names: *mut u8,
    names_capacity: u64,
    names_length: *mut u64,
) -> c_int {
    // SAFETY: C supplies distinct valid entries/names/count buffers, bounded by
    // the configured allocations. Copies never overlap borrowed Rust scratch.
    unsafe {
        dispatch(raw, |context| {
            let count = output(count)?;
            let names_length = output(names_length)?;
            *count = 0;
            *names_length = 0;
            let capacity = checked_length(
                entries,
                capacity,
                u64::from(context.limits.maximum_readdir_entries),
            )?;
            let names_capacity = checked_length(
                names,
                names_capacity,
                u64::from(context.limits.maximum_readdir_bytes),
            )?;
            if wire_bytes > u64::from(context.limits.maximum_readdir_bytes) {
                return Err(Failure::Fatal);
            }
            let mut budget = context.budget;
            budget.directory_entries = budget.directory_entries.min(capacity);
            budget.variable_bytes = budget.variable_bytes.min(names_capacity);
            // Rust output_bytes remains its typed-storage ceiling. C alone applies
            // wire_bytes via fuse_add_direntry, preserving complete-entry cookies.
            let control = context.control()?;
            let page = context.connection.readdir_for_node(
                node,
                handle,
                cookie,
                budget,
                context.scratch,
                &control,
            )?;
            if page.is_empty() && !page.is_eof() {
                return Err(Failure::Errno(libc::ENOMEM));
            }
            let mut offset = 0_usize;
            for (index, entry) in page.entries().enumerate() {
                match control.state(RequestCheckpoint::DuringReadOnlyWork) {
                    RequestControlState::Continue => (),
                    RequestControlState::Cancelled => return Err(Failure::Errno(libc::EINTR)),
                    RequestControlState::DeadlineExpired => {
                        return Err(Failure::Errno(libc::ETIMEDOUT));
                    }
                }
                let end = offset.checked_add(entry.name.len()).ok_or(Failure::Fatal)?;
                if index >= capacity || end > names_capacity {
                    return Err(Failure::Fatal);
                }
                let encoded = abi::DirectoryEntry {
                    node_id: entry.node_id.unwrap_or(0),
                    next_cookie: entry.next_cookie,
                    name_offset: u32::try_from(offset).map_err(|_| Failure::Fatal)?,
                    name_length: u16::try_from(entry.name.len()).map_err(|_| Failure::Fatal)?,
                    kind: kind(entry.node_kind),
                    reserved: 0,
                };
                std::ptr::copy_nonoverlapping(
                    entry.name.as_ptr(),
                    names.add(offset),
                    entry.name.len(),
                );
                entries.add(index).write(encoded);
                offset = end;
            }
            *count = page.len() as u64;
            *names_length = offset as u64;
            Ok(())
        })
    }
}

unsafe extern "C" fn releasedir(raw: *mut c_void, node: u64, handle: u64) -> c_int {
    // SAFETY: Only the scoped context pointer crosses this scalar-only callback.
    unsafe {
        dispatch(raw, |context| {
            // The kernel sends RELEASEDIR only once and cannot retry cleanup.
            // Any failure would retain an unreachable pin, so discard the whole
            // connection exactly as for an unacknowledgeable FORGET failure.
            context
                .connection
                .releasedir_for_node(node, handle, &context.control()?)
                .map_err(|_| Failure::Fatal)?;
            Ok(())
        })
    }
}

unsafe extern "C" fn destroy(raw: *mut c_void) {
    // SAFETY: C invokes destroy at most once while the scoped context is live.
    // Even after poisoning this callback must record teardown without unwinding.
    unsafe {
        if raw.is_null() {
            return;
        }
        let context = &mut *raw.cast::<Context<'_, '_, '_, '_, '_>>();
        match catch_unwind(AssertUnwindSafe(|| {
            if context.destroyed {
                context.poisoned = true;
            }
            context.destroyed = true;
        })) {
            Ok(()) => (),
            Err(payload) => {
                context.poisoned = true;
                if context.panic.is_some() {
                    std::process::abort();
                }
                context.panic = Some(payload);
            }
        }
    }
}

pub(crate) static OPERATIONS: abi::Operations = abi::Operations {
    abi_major: 1,
    abi_minor: 0,
    struct_size: size_of::<abi::Operations>() as u32,
    attributes_size: size_of::<abi::Attributes>() as u32,
    directory_entry_size: size_of::<abi::DirectoryEntry>() as u32,
    limits_size: size_of::<abi::Limits>() as u32,
    flags: 0,
    reserved: 0,
    lookup,
    forget,
    getattr,
    readlink,
    opendir,
    readdir,
    releasedir,
    destroy,
};

#[cfg(test)]
pub(crate) unsafe fn inject_panic(raw: *mut c_void) -> c_int {
    // SAFETY: The fixture supplies the same scoped context as normal dispatch.
    unsafe { dispatch(raw, |_| panic!("callback panic fixture")) }
}
