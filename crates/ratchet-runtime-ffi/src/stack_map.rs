//! Intrusive live bindings for compiled-frame stack-map slots.
//!
//! Generated code reserves one header followed by `Value` slots in its own
//! frame. Enter links that storage into the pinned runtime context; exit
//! validates strict LIFO ownership and restores the previous compiled frame.
//! No allocator is touched while native code is active.

use std::{ffi::c_void, process, ptr::NonNull};

use ratchet_oracle::eval::heap::{EvalRootSet, EvalRootSetError, StackMapSlot};
use ratchet_oracle::value::Value;

use crate::context::{RuntimeJitContext, with_native_jit_context};

/// Header stored at the start of a generated compiled-frame binding region.
#[repr(C)]
pub(crate) struct RuntimeJitStackMapBindingHeader {
    previous: *mut RuntimeJitStackMapBindingHeader,
    frame: u64,
    safepoint: u32,
    values: u32,
}

impl RuntimeJitContext<'_> {
    /// Snapshots heap roots from every currently bound compiled frame.
    ///
    /// Frames are visited from the innermost binding outward, and values retain
    /// their order within each generated binding region.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if root-set length or allocation fails.
    pub fn active_stack_map_roots(&self) -> Result<EvalRootSet, EvalRootSetError> {
        let mut roots = EvalRootSet::new();
        let mut current = self.stack_map_head();
        while let Some(binding) = current {
            // SAFETY: Enter's ABI contract keeps every linked header and its
            // trailing Value slots live until the matching LIFO exit.
            let header = unsafe { binding.as_ref() };
            if header.values > (i32::MAX as u32) / 16 {
                process::abort();
            }
            // SAFETY: The generated region places its first Value immediately
            // after the aligned 24-byte header.
            let values = unsafe {
                binding
                    .as_ptr()
                    .cast::<u8>()
                    .add(std::mem::size_of::<RuntimeJitStackMapBindingHeader>())
                    .cast::<Value>()
            };
            for index in 0..header.values {
                // SAFETY: `index` is below the value count installed by enter.
                let value = unsafe { values.add(index as usize).read() };
                roots.try_push_stack_map(
                    header.frame,
                    header.safepoint,
                    StackMapSlot::Stack {
                        offset: (index as i32) * 16,
                    },
                    value,
                )?;
            }
            current = NonNull::new(header.previous);
        }
        Ok(roots)
    }
}

/// Native ABI for entering a compiled stack-map binding.
///
/// # Safety
///
/// Callers must satisfy [`aos_jit_stack_map_enter`]'s pointer and lifetime
/// contract.
pub type RuntimeJitStackMapEnterNativeFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u32);

/// Native ABI for exiting a compiled stack-map binding.
///
/// # Safety
///
/// Callers must satisfy [`aos_jit_stack_map_exit`]'s LIFO pointer contract.
pub type RuntimeJitStackMapExitNativeFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

/// Links caller-owned compiled-frame storage into the runtime context.
///
/// # Safety
///
/// `rt` must point to the live pinned runtime context for this native call.
/// `binding` must point to writable, eight-byte-aligned storage large enough
/// for [`RuntimeJitStackMapBindingHeader`] followed by `values` runtime values,
/// and that storage must remain live until the matching exit call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_jit_stack_map_enter(
    rt: *mut c_void,
    binding: *mut c_void,
    safepoint: u32,
    values: u32,
) {
    let Some(mut binding) = NonNull::new(binding.cast::<RuntimeJitStackMapBindingHeader>()) else {
        process::abort();
    };
    // SAFETY: The native caller supplies the writable binding region and pinned
    // context described by this function's contract.
    unsafe { // aos_jit_stack_map_enter runtime-context decode
        with_native_jit_context(rt, |context| {
            let header = binding.as_mut();
            header.previous = context
                .stack_map_head()
                .map_or(std::ptr::null_mut(), NonNull::as_ptr);
            header.frame = binding.as_ptr().addr() as u64;
            header.safepoint = safepoint;
            header.values = values;
            context.set_stack_map_head(Some(binding));
        });
    }
}

/// Removes the current compiled-frame binding from the runtime context.
///
/// # Safety
///
/// `rt` and `binding` must be the same pointers passed to the most recent
/// unmatched [`aos_jit_stack_map_enter`] call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_jit_stack_map_exit(rt: *mut c_void, binding: *mut c_void) {
    let Some(binding) = NonNull::new(binding.cast::<RuntimeJitStackMapBindingHeader>()) else {
        process::abort();
    };
    // SAFETY: The native caller supplies the active LIFO binding and pinned
    // context described by this function's contract.
    unsafe { // aos_jit_stack_map_exit runtime-context decode
        with_native_jit_context(rt, |context| {
            if context.stack_map_head() != Some(binding) {
                process::abort();
            }
            // SAFETY: The matching enter initialized this live header.
            let previous = NonNull::new(binding.as_ref().previous);
            context.set_stack_map_head(previous);
        });
    }
}

/// Returns the process-local enter-wrapper address.
pub fn aos_jit_stack_map_enter_native_wrapper_address() -> *mut c_void {
    aos_jit_stack_map_enter as RuntimeJitStackMapEnterNativeFn as *const () as *mut c_void
}

/// Returns the process-local exit-wrapper address.
pub fn aos_jit_stack_map_exit_native_wrapper_address() -> *mut c_void {
    aos_jit_stack_map_exit as RuntimeJitStackMapExitNativeFn as *const () as *mut c_void
}

#[cfg(test)]
mod tests {
    use ratchet_oracle::{
        eval::tree_walk::TreeWalk,
        syntax::{Span, parse_str},
        value::HeapObject,
    };

    use super::*;

    #[test]
    fn bindings_nest_without_allocating_runtime_storage() {
        let parsed = parse_str("null").expect("source parses");
        let resolved = ratchet_oracle::compile::resolve(parsed).expect("source resolves");
        let ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
        let mut eval = TreeWalk::new(&ir);
        let mut context = std::pin::pin!(RuntimeJitContext::new(
            &mut eval,
            ir.root,
            Span::new(0, 0),
        ));
        let rt = context.as_mut().as_mut_ptr();
        let mut outer = [0_u64; 5];
        let mut inner = [0_u64; 5];

        // SAFETY: Both aligned stack buffers outlive their balanced calls.
        unsafe { // balanced stack-map binding exercise
            aos_jit_stack_map_enter(rt, outer.as_mut_ptr().cast(), 2, 1);
            aos_jit_stack_map_enter(rt, inner.as_mut_ptr().cast(), 4, 1);
            let outer_value = Value::thunk(
                NonNull::new(0x1000_usize as *mut HeapObject).expect("pointer is non-null"),
            )
            .expect("pointer is aligned");
            let inner_value = Value::thunk(
                NonNull::new(0x2000_usize as *mut HeapObject).expect("pointer is non-null"),
            )
            .expect("pointer is aligned");
            outer.as_mut_ptr().add(3).cast::<Value>().write(outer_value);
            inner.as_mut_ptr().add(3).cast::<Value>().write(inner_value);

            let roots = context.active_stack_map_roots().expect("roots snapshot");
            assert_eq!(roots.len(), 2);
            assert!(roots.roots()[0].value().raw_eq(inner_value));
            assert!(roots.roots()[1].value().raw_eq(outer_value));
            aos_jit_stack_map_exit(rt, inner.as_mut_ptr().cast());
            aos_jit_stack_map_exit(rt, outer.as_mut_ptr().cast());
        }

        assert!(context.stack_map_head().is_none());
    }
}
