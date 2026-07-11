//! Shared runtime context decoded by native helper wrappers.
//!
//! Native tier-1 thunk bodies receive one opaque `rt` pointer and may call
//! helpers from multiple runtime families. This module owns the single pinned
//! context layout that force, apply, attrset-access, and hybrid-environment
//! wrappers decode so mixed-helper CLIF bodies do not rely on family-specific
//! context layouts accidentally matching.

use std::{
    ffi::c_void,
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
    process,
    ptr::NonNull,
};

use ratchet_oracle::{
    compile::IrId,
    eval::{EvalEnv, tree_walk::TreeWalk},
    syntax::Span,
};
use ratchet_jit::JitCraneliftUserStackMap;

use crate::stack_map::RuntimeJitStackMapBindingHeader;

/// Scoped tree-walk evaluator context decoded by native runtime helpers.
///
/// Native runtime helpers receive an opaque runtime pointer in their frozen C
/// ABI. This context is the current explicit Rust-side representation for that
/// pointer: it ties one live [`TreeWalk`] evaluator to the IR node id and
/// source span used when safe oracle helpers report failures. Native calls may
/// also attach the dispatched [`EvalEnv`], allowing environment helpers to
/// resolve both linked frames and FV-5 flat captures through the evaluator. It
/// is pinned so a raw pointer derived from it stays stable across a native call.
pub struct RuntimeJitContext<'eval> {
    eval: NonNull<TreeWalk>,
    env: Option<NonNull<EvalEnv>>,
    stack_maps: &'eval [JitCraneliftUserStackMap],
    stack_map_head: Option<NonNull<RuntimeJitStackMapBindingHeader>>,
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
            env: None,
            stack_maps: &[],
            stack_map_head: None,
            id,
            span,
            _marker: PhantomData,
            _pinned: PhantomPinned,
        }
    }

    /// Creates a scoped runtime context carrying a hybrid captured environment.
    pub fn new_with_env(
        eval: &'eval mut TreeWalk,
        id: IrId,
        span: Span,
        env: &'eval EvalEnv,
    ) -> Self {
        Self {
            eval: NonNull::from(eval),
            env: Some(NonNull::from(env)),
            stack_maps: &[],
            stack_map_head: None,
            id,
            span,
            _marker: PhantomData,
            _pinned: PhantomPinned,
        }
    }

    /// Creates a scoped context carrying finalized compiled stack-map layouts.
    pub fn new_with_env_and_stack_maps(
        eval: &'eval mut TreeWalk,
        id: IrId,
        span: Span,
        env: &'eval EvalEnv,
        stack_maps: &'eval [JitCraneliftUserStackMap],
    ) -> Self {
        Self {
            eval: NonNull::from(eval),
            env: Some(NonNull::from(env)),
            stack_maps,
            stack_map_head: None,
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

    pub(crate) const fn stack_map_head(
        &self,
    ) -> Option<NonNull<RuntimeJitStackMapBindingHeader>> {
        self.stack_map_head
    }

    pub(crate) const fn has_active_stack_map_binding(&self) -> bool {
        self.stack_map_head.is_some()
    }

    pub(crate) fn finalized_stack_map(
        &self,
        safepoint: u32,
    ) -> Option<&JitCraneliftUserStackMap> {
        self.stack_maps.get(safepoint as usize)
    }

    pub(crate) const fn has_finalized_stack_maps(&self) -> bool {
        !self.stack_maps.is_empty()
    }

    pub(crate) fn set_stack_map_head(
        &mut self,
        head: Option<NonNull<RuntimeJitStackMapBindingHeader>>,
    ) {
        self.stack_map_head = head;
    }
}

// SAFETY: Callers must pass a live pinned RuntimeJitContext pointer and keep
// exclusive access to it for the callback.
pub(crate) unsafe fn with_native_jit_context<R>(
    rt: *mut c_void,
    call: impl FnOnce(&mut RuntimeJitContext<'static>) -> R,
) -> R {
    let Some(rt) = NonNull::new(rt) else {
        process::abort();
    };
    // SAFETY: The caller provides the live pinned context described above.
    call(unsafe { rt.cast::<RuntimeJitContext<'static>>().as_mut() })
}

// SAFETY: Callers must pass a live pinned RuntimeJitContext pointer and keep
// exclusive access to both it and its evaluator for the callback.
pub(crate) unsafe fn with_native_jit_evaluator_context<R>(
    rt: *mut c_void,
    call: impl FnOnce(&mut RuntimeJitContext<'static>, &mut TreeWalk, IrId, Span) -> R,
) -> R {
    let Some(rt) = NonNull::new(rt) else {
        process::abort();
    };
    // SAFETY: The caller provides the live pinned context described above.
    let jit_context = unsafe { rt.cast::<RuntimeJitContext<'static>>().as_mut() };
    let id = jit_context.id;
    let span = jit_context.span;
    // SAFETY: RuntimeJitContext owns the exclusive evaluator pointer for the
    // native call; the callback cannot outlive this scoped mutable borrow.
    let eval = unsafe { jit_context.eval.as_mut() };
    call(jit_context, eval, id, span)
}

// SAFETY: Callers must pass a live pinned RuntimeJitContext carrying an env and
// uphold exclusive evaluator access for the duration of the callback.
pub(crate) unsafe fn with_native_runtime_env_context<R>(
    rt: *mut c_void,
    call: impl FnOnce(&mut TreeWalk, &EvalEnv, IrId, Span) -> R,
) -> R {
    let Some(rt) = NonNull::new(rt) else {
        process::abort();
    };
    // SAFETY: The caller provides the live pinned context described above.
    let env_context = unsafe { rt.cast::<RuntimeJitContext<'static>>().as_mut() };
    let Some(env) = env_context.env else {
        process::abort();
    };
    // SAFETY: Both pointers were captured by `new_with_env` for this call.
    call(
        unsafe { env_context.eval.as_mut() },
        unsafe { env.as_ref() },
        env_context.id,
        env_context.span,
    )
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
