//! Intrusive live bindings for compiled-frame stack-map slots.
//!
//! Generated code reserves one header followed by `Value` slots in its own
//! frame. Enter links that storage into the pinned runtime context; exit
//! validates strict LIFO ownership and restores the previous compiled frame.
//! No allocator is touched while native code is active.

use std::{error::Error, ffi::c_void, fmt, process, ptr::NonNull};

use ratchet_oracle::eval::heap::{
    AllocationCollectorPollRootValueWritebackSlot, AllocationCollectorPollRootWritebackPlan,
    AllocationCollectorPollRootWritebackReport, EvalHeapError, EvalRootSet, EvalRootSetError,
    EvalRootSource, StackMapSlot,
};
use ratchet_oracle::value::Value;

use crate::context::{RuntimeJitContext, with_native_jit_context};

/// Byte stride of one runtime value inside a generated binding region.
///
/// Generated code stores complete by-value `Value`s, so the stride tracks the
/// active carrier: 16 bytes on the two-word baseline, 8 bytes under the
/// one-word `candidate_c_value` variant.
const VALUE_SLOT_BYTES: usize = std::mem::size_of::<Value>();

/// Header stored at the start of a generated compiled-frame binding region.
#[repr(C)]
pub(crate) struct RuntimeJitStackMapBindingHeader {
    previous: *mut RuntimeJitStackMapBindingHeader,
    frame: u64,
    safepoint: u32,
    values: u32,
    identity: u32,
    padding: u32,
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
            if header.values > (i32::MAX as u32) / VALUE_SLOT_BYTES as u32 {
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
                        offset: self.stack_map_slot_offset(header.safepoint, index),
                    },
                    value,
                )?;
            }
            current = NonNull::new(header.previous);
        }
        Ok(roots)
    }

    /// Applies relocated root values to the currently bound compiled slots.
    ///
    /// The complete stack-map partition is resolved and validated before the
    /// first live slot is changed. Finalized stack-pointer offsets, dynamic
    /// frame identity, safepoint identity, and the expected from-space value
    /// must all still match the collector plan.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeJitStackMapWritebackError`] if temporary binding
    /// storage cannot be reserved, a planned source is no longer bound, or the
    /// collector writeback plan rejects a source or value.
    pub fn apply_active_stack_map_writebacks(
        &mut self,
        plan: &AllocationCollectorPollRootWritebackPlan,
    ) -> Result<AllocationCollectorPollRootWritebackReport, RuntimeJitStackMapWritebackError> {
        let count = plan.stack_map_writeback_count();
        let mut pointers = Vec::new();
        let mut slots = Vec::new();
        pointers
            .try_reserve_exact(count)
            .map_err(|_| RuntimeJitStackMapWritebackError::AllocationFailed { slots: count })?;
        slots
            .try_reserve_exact(count)
            .map_err(|_| RuntimeJitStackMapWritebackError::AllocationFailed { slots: count })?;

        for writeback in plan.stack_map_writebacks() {
            let source = writeback.source();
            let pointer = self.bound_stack_map_value(source).ok_or_else(|| {
                RuntimeJitStackMapWritebackError::MissingBinding {
                    source: source.clone(),
                }
            })?;
            // SAFETY: The binding remains linked for this method's exclusive
            // context borrow, and `bound_stack_map_value` checked its index.
            let value = unsafe { pointer.as_ptr().read() };
            pointers.push(pointer);
            slots.push(AllocationCollectorPollRootValueWritebackSlot::new(
                source.clone(),
                value,
            ));
        }

        let report = plan.apply_to_stack_map_value_slots(&mut slots)?;
        for (pointer, slot) in pointers.into_iter().zip(slots) {
            // SAFETY: Every pointer was resolved from a still-linked binding,
            // and the complete temporary slot partition validated above.
            unsafe { pointer.as_ptr().write(slot.value()) };
        }
        Ok(report)
    }

    fn stack_map_slot_offset(&self, safepoint: u32, index: u32) -> i32 {
        if let Some(stack_map) = self.finalized_stack_map(safepoint) {
            let Some(entry) = stack_map.entries().get(index as usize) else {
                process::abort();
            };
            let offset = entry.sp_offset();
            if offset > i32::MAX as u32 {
                process::abort();
            }
            return offset as i32;
        }
        if self.has_finalized_stack_maps() {
            process::abort();
        }
        let header = std::mem::size_of::<RuntimeJitStackMapBindingHeader>() as u32;
        let Some(offset) = header.checked_add(index.saturating_mul(VALUE_SLOT_BYTES as u32)) else {
            process::abort();
        };
        if offset > i32::MAX as u32 {
            process::abort();
        }
        offset as i32
    }

    fn bound_stack_map_value(&self, source: &EvalRootSource) -> Option<NonNull<Value>> {
        let mut current = self.stack_map_head();
        while let Some(binding) = current {
            // SAFETY: Every linked header stays live until its matching exit.
            let bound_header = unsafe { binding.as_ref() };
            for index in 0..bound_header.values {
                let candidate = EvalRootSource::StackMap {
                    frame: bound_header.frame,
                    safepoint: bound_header.safepoint,
                    slot: StackMapSlot::Stack {
                        offset: self.stack_map_slot_offset(bound_header.safepoint, index),
                    },
                };
                if &candidate == source {
                    // SAFETY: The generated binding region stores `values`
                    // complete Values immediately after its 24-byte header.
                    let pointer = unsafe {
                        binding
                            .as_ptr()
                            .cast::<u8>()
                            .add(
                                std::mem::size_of::<RuntimeJitStackMapBindingHeader>()
                                    + index as usize * VALUE_SLOT_BYTES,
                            )
                            .cast::<Value>()
                    };
                    return NonNull::new(pointer);
                }
            }
            current = NonNull::new(bound_header.previous);
        }
        None
    }

    fn compiled_frame_base_and_safepoint(
        &self,
        binding: NonNull<RuntimeJitStackMapBindingHeader>,
        identity: NonNull<u8>,
        safepoint: u32,
        values: u32,
    ) -> (u64, u32) {
        if !self.has_finalized_stack_maps() {
            return (binding.as_ptr().addr() as u64, safepoint);
        }
        if values == 0 {
            process::abort();
        }
        let value_offset = std::mem::size_of::<RuntimeJitStackMapBindingHeader>();
        for (index, stack_map) in self.finalized_stack_maps().iter().enumerate() {
            if stack_map.entries().len() != values as usize {
                continue;
            }
            let Some(identity_offset) = stack_map.identity_sp_offset() else {
                continue;
            };
            let mut frame_base = None;
            for (value_index, entry) in stack_map.entries().iter().enumerate() {
                let Some(tag_address) = binding
                    .as_ptr()
                    .addr()
                    .checked_add(value_offset + value_index.saturating_mul(VALUE_SLOT_BYTES))
                else {
                    process::abort();
                };
                let Some(candidate) = tag_address.checked_sub(entry.sp_offset() as usize) else {
                    process::abort();
                };
                if frame_base.is_some_and(|frame_base| frame_base != candidate) {
                    process::abort();
                }
                frame_base = Some(candidate);
            }
            let frame_base = frame_base.unwrap_or_else(|| process::abort());
            let Some(expected_identity) = frame_base.checked_add(identity_offset as usize) else {
                process::abort();
            };
            if expected_identity != identity.as_ptr().addr() {
                continue;
            }
            let Ok(safepoint) = u32::try_from(index) else {
                process::abort();
            };
            return (frame_base as u64, safepoint);
        }
        process::abort()
    }
}

/// Failure while binding a collector writeback plan to live compiled slots.
#[derive(Debug)]
pub enum RuntimeJitStackMapWritebackError {
    /// Temporary pointer or typed-slot storage could not be reserved.
    AllocationFailed {
        /// The requested stack-map writeback count.
        slots: usize,
    },
    /// A planned physical compiled-frame source is no longer bound.
    MissingBinding {
        /// The source that could not be resolved to a live slot.
        source: EvalRootSource,
    },
    /// The collector rejected the current stack-map source or value partition.
    Heap(EvalHeapError),
}

impl From<EvalHeapError> for RuntimeJitStackMapWritebackError {
    fn from(source: EvalHeapError) -> Self {
        Self::Heap(source)
    }
}

impl fmt::Display for RuntimeJitStackMapWritebackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationFailed { slots } => {
                write!(
                    formatter,
                    "failed to reserve {slots} compiled root bindings"
                )
            }
            Self::MissingBinding { source } => {
                write!(
                    formatter,
                    "compiled root source is no longer bound: {source:?}"
                )
            }
            Self::Heap(source) => source.fmt(formatter),
        }
    }
}

impl Error for RuntimeJitStackMapWritebackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Heap(source) => Some(source),
            Self::AllocationFailed { .. } | Self::MissingBinding { .. } => None,
        }
    }
}

/// Native ABI for entering a compiled stack-map binding.
///
/// # Safety
///
/// Callers must satisfy [`aos_jit_stack_map_enter`]'s pointer and lifetime
/// contract.
pub type RuntimeJitStackMapEnterNativeFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, u32, u32);

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
/// `identity` must point at the binding's mapped identity word, and that storage
/// must remain live until the matching exit call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aos_jit_stack_map_enter(
    rt: *mut c_void,
    binding: *mut c_void,
    identity: *mut c_void,
    safepoint: u32,
    values: u32,
) {
    let Some(mut binding) = NonNull::new(binding.cast::<RuntimeJitStackMapBindingHeader>()) else {
        process::abort();
    };
    let Some(identity) = NonNull::new(identity.cast::<u8>()) else {
        process::abort();
    };
    // SAFETY: The native caller supplies the writable binding region and pinned
    // context described by this function's contract.
    unsafe {
        // aos_jit_stack_map_enter runtime-context decode
        with_native_jit_context(rt, |context| {
            let (frame, selected_safepoint) =
                context.compiled_frame_base_and_safepoint(binding, identity, safepoint, values);
            let previous = context
                .stack_map_head()
                .map_or(std::ptr::null_mut(), NonNull::as_ptr);
            let header = binding.as_mut();
            header.previous = previous;
            header.frame = frame;
            header.safepoint = selected_safepoint;
            header.values = values;
            header.identity = safepoint;
            header.padding = 0;
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
    unsafe {
        // aos_jit_stack_map_exit runtime-context decode
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

    // Exercises the JIT stack-map enter/leave path with a synthetic runtime
    // pointer (address 4096), which the Candidate-C carrier rejects as outside
    // any live reservation, so this synthetic-pointer exercise stays
    // baseline-only.
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn bindings_nest_without_allocating_runtime_storage() {
        let parsed = parse_str("null").expect("source parses");
        let resolved = ratchet_oracle::compile::resolve(parsed).expect("source resolves");
        let ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
        let mut eval = TreeWalk::new(&ir);
        let mut context =
            std::pin::pin!(RuntimeJitContext::new(&mut eval, ir.root, Span::new(0, 0),));
        let rt = context.as_mut().as_mut_ptr();
        let mut outer = [0_u64; 6];
        let mut inner = [0_u64; 6];

        // SAFETY: Both aligned stack buffers outlive their balanced calls.
        unsafe {
            // balanced stack-map binding exercise
            aos_jit_stack_map_enter(
                rt,
                outer.as_mut_ptr().cast(),
                outer.as_mut_ptr().wrapping_add(3).cast(),
                2,
                1,
            );
            aos_jit_stack_map_enter(
                rt,
                inner.as_mut_ptr().cast(),
                inner.as_mut_ptr().wrapping_add(3).cast(),
                4,
                1,
            );
            let outer_value = Value::thunk(
                NonNull::new(0x1000_usize as *mut HeapObject).expect("pointer is non-null"),
            )
            .expect("pointer is aligned");
            let inner_value = Value::thunk(
                NonNull::new(0x2000_usize as *mut HeapObject).expect("pointer is non-null"),
            )
            .expect("pointer is aligned");
            outer.as_mut_ptr().add(4).cast::<Value>().write(outer_value);
            inner.as_mut_ptr().add(4).cast::<Value>().write(inner_value);

            let roots = context.active_stack_map_roots().expect("roots snapshot");
            assert_eq!(roots.len(), 2);
            assert!(roots.roots()[0].value().raw_eq(inner_value));
            assert!(roots.roots()[1].value().raw_eq(outer_value));
            assert_eq!(
                roots.roots()[0].source(),
                &EvalRootSource::StackMap {
                    frame: inner.as_ptr().addr() as u64,
                    safepoint: 4,
                    slot: StackMapSlot::Stack { offset: 32 },
                }
            );
            let bound = context
                .bound_stack_map_value(roots.roots()[0].source())
                .expect("typed physical root resolves to its live slot");
            bound.as_ptr().write(Value::int(9));
            assert!(
                inner
                    .as_ptr()
                    .add(4)
                    .cast::<Value>()
                    .read()
                    .raw_eq(Value::int(9))
            );
            aos_jit_stack_map_exit(rt, inner.as_mut_ptr().cast());
            aos_jit_stack_map_exit(rt, outer.as_mut_ptr().cast());
        }

        assert!(context.stack_map_head().is_none());
    }
}
