//! Shared runtime context decoded by native helper wrappers.
//!
//! Native tier-1 thunk bodies receive one opaque `rt` pointer and may call
//! helpers from multiple runtime families. This module owns the single pinned
//! context layout that force, apply, and attrset-access wrappers decode from
//! that pointer so mixed-helper CLIF bodies do not rely on family-specific
//! context layouts accidentally matching.

use std::{
    ffi::c_void,
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
    process,
    ptr::NonNull,
};

use ratchet_oracle::{compile::IrId, eval::tree_walk::TreeWalk, syntax::Span};

/// Scoped tree-walk evaluator context decoded by native runtime helpers.
///
/// Native runtime helpers receive an opaque runtime pointer in their frozen C
/// ABI. This context is the current explicit Rust-side representation for that
/// pointer: it ties one live [`TreeWalk`] evaluator to the IR node id and
/// source span used when safe oracle helpers report failures. It is pinned so a
/// raw pointer derived from it stays stable across a native helper call.
pub struct RuntimeJitContext<'eval> {
    eval: NonNull<TreeWalk>,
    id: IrId,
    span: Span,
    _marker: PhantomData<&'eval mut TreeWalk>,
    _pinned: PhantomPinned,
}

impl<'eval> RuntimeJitContext<'eval> {
    /// Creates a scoped runtime context for native wrapper calls.
    pub fn new(eval: &'eval mut TreeWalk, id: IrId, span: Span) -> Self {
        Self {
            eval: NonNull::from(eval),
            id,
            span,
            _marker: PhantomData,
            _pinned: PhantomPinned,
        }
    }

    /// Returns an opaque runtime pointer suitable for native helper calls.
    ///
    /// The returned pointer is only valid while this pinned context value and
    /// its borrowed evaluator remain live. Callers must not move or drop the
    /// pinned context, and must uphold exclusive mutable access to the
    /// evaluator while a native wrapper call uses the pointer.
    pub fn as_mut_ptr(self: Pin<&mut Self>) -> *mut c_void {
        self.as_ref().get_ref() as *const Self as *mut c_void
    }
}

// SAFETY: Callers must pass a live pinned RuntimeJitContext pointer and uphold
// exclusive evaluator access for the duration of the callback.
pub(crate) unsafe fn with_native_runtime_context<R>(
    rt: *mut c_void,
    call: impl FnOnce(&mut TreeWalk, IrId, Span) -> R,
) -> R {
    let Some(rt) = NonNull::new(rt) else {
        process::abort();
    };
    // SAFETY: The caller must provide a live RuntimeJitContext pointer with
    // exclusive evaluator access covering this call.
    let context = unsafe { rt.cast::<RuntimeJitContext<'static>>().as_mut() };
    let id = context.id;
    let span = context.span;
    // SAFETY: RuntimeJitContext::new stores a live TreeWalk pointer, and the
    // native wrapper contract requires exclusive evaluator access.
    call(unsafe { context.eval.as_mut() }, id, span)
}
