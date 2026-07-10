//! Segmented-stack protection for recursive tree-walk evaluation.
//!
//! Nix exposes a configurable semantic `max-call-depth` (10,000 by default),
//! but one Nix call expands into several Rust evaluator frames. A fixed native
//! thread stack can therefore overflow before [`TreeWalk::enter_call`] gets a
//! chance to report the configured Nix error. Every recursive node entry passes
//! this boundary, so it is the single place where the evaluator asks for a
//! temporary stack segment when the current stack approaches its guard page.

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
        stacker::maybe_grow(EVAL_STACK_RED_ZONE_BYTES, EVAL_STACK_SEGMENT_BYTES, || {
            self.eval_node_on_current_stack(id)
        })
    }
}
