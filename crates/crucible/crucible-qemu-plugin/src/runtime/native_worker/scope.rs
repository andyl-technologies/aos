//! Runs a statically typed action inside a real synchronous native control user.
//!
//! The private thunk and input live on the caller's stack. Native supplies the
//! retained Arc owner only during the callback. Successful results are Copy and
//! static; role-specific failures retain their own actual custody and journals.
// SPDX-License-Identifier: GPL-2.0-only

use std::any::Any;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::sync::Arc;

struct InputHeader {
    /// Invokes only the thunk paired with this live synchronous payload.
    ///
    /// # Safety
    /// Source must retain the exact Arc body expected by the thunk. The payload
    /// must point to its same live monomorphized ScopedInput; neither pointer
    /// may be retained after this synchronous call or invoked more than once.
    invoke: unsafe fn(*mut c_void, *mut c_void) -> i32,
    payload: *mut c_void,
}

struct ScopedInput<B, F, R, E, RetainError, RetainPanic> {
    body: PhantomData<fn() -> B>,
    action: Option<F>,
    retain_error: RetainError,
    retain_panic: RetainPanic,
    output: MaybeUninit<Result<R, E>>,
    completed: bool,
}

/// Preserves the callback output independently of Native's signed scope return.
pub(in crate::runtime) struct ScopeOutcome<R, E> {
    /// Stores the actual owned result only after the callback wrote it fully.
    pub(in crate::runtime) output: Option<Result<R, E>>,
    /// Preserves the independent signed return even when the action failed.
    pub(in crate::runtime) status: i32,
}

/// Borrows one typed control through the caller's genuine synchronous entry.
///
/// Native status never replaces the independently retained callback result.
/// The caller interprets both outcomes using its role-specific custody policy.
///
/// # Panics
/// Propagates a panic from entry or a retention handler. Action panics are passed
/// to the supplied panic handler while Source still protects the control owner.
pub(in crate::runtime) fn with_control<B, F, R, E, RetainError, RetainPanic>(
    action: F,
    retain_error: RetainError,
    retain_panic: RetainPanic,
    enter: impl FnOnce(*mut c_void) -> i32,
) -> ScopeOutcome<R, E>
where
    F: for<'a> FnOnce(&'a Arc<B>) -> Result<R, E>,
    R: Copy + 'static,
    E: 'static,
    RetainError: Fn(&Arc<B>, E) -> E,
    RetainPanic: Fn(&Arc<B>, Box<dyn Any + Send>),
{
    let mut input: ScopedInput<B, F, R, E, RetainError, RetainPanic> = ScopedInput {
        body: PhantomData,
        action: Some(action),
        retain_error,
        retain_panic,
        output: MaybeUninit::uninit(),
        completed: false,
    };
    let mut header = InputHeader {
        invoke: invoke::<B, F, R, E, RetainError, RetainPanic>,
        payload: std::ptr::from_mut(&mut input).cast(),
    };
    let status = enter(std::ptr::from_mut(&mut header).cast());
    let output = if input.completed {
        // SAFETY: the matched synchronous thunk sets completed only after
        // writing the complete owned result. No body-derived borrow can escape.
        Some(unsafe { input.output.assume_init() })
    } else {
        None
    };
    ScopeOutcome { output, status }
}

/// Dispatches only after the role-specific export validates its retained owner.
///
/// # Safety
/// Native must retain the exact initialized Arc owner through callback return.
/// `input` must be the unchanged live header supplied by `with_control`; Native
/// must neither retain the header nor invoke it asynchronously or more than once.
///
/// # Panics
/// Propagates a panic from a caller-provided retention handler.
pub(in crate::runtime) unsafe fn dispatch(owner: *mut c_void, input: *mut c_void) -> i32 {
    // SAFETY: the caller supplies this module's live synchronous header.
    let input = unsafe { &mut *input.cast::<InputHeader>() };
    // SAFETY: the header pairs the monomorphized thunk with its exact live input.
    unsafe { (input.invoke)(owner, input.payload) }
}

/// Borrows the retained raw Arc without consuming its one owning alias.
///
/// # Safety
/// Source must retain the exact initialized B owner through return. Input must
/// point to the same live ScopedInput paired with this monomorphized thunk;
/// invocation is synchronous and once-only, and neither pointer may escape.
unsafe fn invoke<B, F, R, E, RetainError, RetainPanic>(
    owner: *mut c_void,
    input: *mut c_void,
) -> i32
where
    F: for<'a> FnOnce(&'a Arc<B>) -> Result<R, E>,
    R: Copy + 'static,
    E: 'static,
    RetainError: Fn(&Arc<B>, E) -> E,
    RetainPanic: Fn(&Arc<B>, Box<dyn Any + Send>),
{
    // SAFETY: the private header pairs this thunk with its live stack input.
    let input = unsafe { &mut *input.cast::<ScopedInput<B, F, R, E, RetainError, RetainPanic>>() };
    let Some(action) = input.action.take() else {
        return -libc::EALREADY;
    };
    // SAFETY: Source's actual control user protects the one raw Arc owner.
    // ManuallyDrop borrows that alias without decrementing its strong count.
    let control = ManuallyDrop::new(unsafe { Arc::from_raw(owner.cast::<B>()) });
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(&control))) {
        Ok(output) => {
            let output = output.map_err(|error| (input.retain_error)(&control, error));
            input.output.write(output);
            input.completed = true;
            0
        }
        Err(payload) => {
            (input.retain_panic)(&control, payload);
            -libc::EFAULT
        }
    }
}
