//! Segmented-stack protection for recursive tree-walk evaluation.
//!
//! Nix exposes a configurable semantic `max-call-depth` (10,000 by default),
//! but one Nix call expands into several Rust evaluator frames. A fixed native
//! thread stack can therefore overflow before [`TreeWalk::enter_call`] gets a
//! chance to report the configured Nix error. Every recursive node entry passes
//! this boundary, so it is the single place where the evaluator asks for a
//! temporary stack segment when the current stack approaches its guard page.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use std::cell::Cell;

use super::*;

/// Native-stack headroom retained before switching to a temporary segment.
///
/// This is intentionally much larger than `stacker`'s example red zone: an
/// evaluator node can enter force, coercion, builtin, and diagnostic helpers
/// before it recursively evaluates another node.
const EVAL_STACK_RED_ZONE_BYTES: usize = 256 * 1024;

/// Size of each temporary evaluator stack segment.
///
/// Segments are allocated only on deep recursive paths and are released while
/// unwinding. Two MiB amortizes switches without reserving a large stack for
/// ordinary package evaluation.
const EVAL_STACK_SEGMENT_BYTES: usize = 2 * 1024 * 1024;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
thread_local! {
    /// Stack floor cached beside `stacker`'s private thread-local limit.
    ///
    /// Zero means uninitialized. A process stack cannot begin at address zero,
    /// so the sentinel keeps the hot TLS state to one machine word.
    static EVAL_STACK_FLOOR: Cell<usize> = const { Cell::new(0) };
}

/// Restores the caller stack's cached floor after a temporary-stack callback.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
struct StackFloorRestore(usize);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl Drop for StackFloorRestore {
    fn drop(&mut self) {
        EVAL_STACK_FLOOR.with(|floor| floor.set(self.0));
    }
}

impl TreeWalk {
    /// Evaluates one node with enough native-stack headroom for recursive work.
    ///
    /// The callback stays on the current thread and switches stacks only when
    /// less than [`EVAL_STACK_RED_ZONE_BYTES`] remains. The semantic call-depth
    /// counter remains authoritative; stack growth merely ensures evaluation
    /// reaches that check instead of aborting in the host runtime.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] under the same conditions as the underlying
    /// node evaluator, including `MaxCallDepthExceeded` when a Nix call crosses
    /// the configured limit.
    pub fn eval_node(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let stack_pointer = current_stack_pointer();
            let enough_space = EVAL_STACK_FLOOR.with(|floor| {
                let mut floor_value = floor.get();
                if floor_value == 0 {
                    floor_value = stacker::remaining_stack()
                        .and_then(|remaining| stack_pointer.checked_sub(remaining))
                        .unwrap_or(0);
                    floor.set(floor_value);
                }
                floor_value != 0
                    && stack_pointer.saturating_sub(floor_value) >= EVAL_STACK_RED_ZONE_BYTES
            });
            if enough_space {
                return self.eval_node_on_current_stack(id);
            }

            // `stacker::grow` updates its private stack limit for the callback.
            // Clear our matching cache while on that temporary stack and
            // restore the caller's floor on every ordinary return. `stacker`
            // catches a panic inside the callback and resumes it only after
            // returning to the original stack; the guard restores our cache
            // during either ordinary return or panic unwinding.
            let previous_floor = EVAL_STACK_FLOOR.with(|floor| floor.replace(0));
            let _restore = StackFloorRestore(previous_floor);
            stacker::grow(EVAL_STACK_SEGMENT_BYTES, || {
                self.eval_node_on_current_stack(id)
            })
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            stacker::maybe_grow(EVAL_STACK_RED_ZONE_BYTES, EVAL_STACK_SEGMENT_BYTES, || {
                self.eval_node_on_current_stack(id)
            })
        }
    }
}

/// Reads the native stack pointer without changing memory or machine state.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(unsafe_code)]
fn current_stack_pointer() -> usize {
    let pointer: usize;
    // SAFETY: `mov` only copies the current `rsp` value into a general-purpose
    // output register. It does not dereference or modify the stack pointer.
    unsafe {
        std::arch::asm!(
            "mov {}, rsp",
            out(reg) pointer,
            options(nomem, nostack, preserves_flags)
        );
    }
    pointer
}

/// Reads the native stack pointer without changing memory or machine state.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
#[allow(unsafe_code)]
fn current_stack_pointer() -> usize {
    let pointer: usize;
    // SAFETY: `mov` only copies the current `sp` value into a general-purpose
    // output register. It does not dereference or modify the stack pointer.
    unsafe {
        std::arch::asm!(
            "mov {}, sp",
            out(reg) pointer,
            options(nomem, nostack, preserves_flags)
        );
    }
    pointer
}
