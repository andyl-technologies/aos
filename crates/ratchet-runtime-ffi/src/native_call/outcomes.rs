//! Native-call loop and thunk-call outcome types (split from native_call.rs, §2 cap).

use super::*;

/// The value and optional trap observed from one native thunk execution.
///
/// `value` is the raw runtime value the compiled body returned. When `trap` is
/// `Some`, a forcing or environment-access wrapper transferred an evaluator
/// error out of the call and `value` is the meaningless trap sentinel.
#[derive(Clone, Debug)]
pub struct NativeThunkCallOutcome {
    pub(crate) value: Value,
    pub(crate) trap: Option<RuntimeTrap>,
}

impl NativeThunkCallOutcome {
    /// Returns the raw runtime value returned by the compiled thunk body.
    ///
    /// The value is only meaningful when [`Self::trap`] is `None`.
    pub const fn value(&self) -> Value {
        self.value
    }

    /// Returns the trap transferred out of the call, if any.
    pub const fn trap(&self) -> Option<&RuntimeTrap> {
        self.trap.as_ref()
    }

    /// Returns true when a wrapper transferred a trap out of the call.
    pub const fn is_trap(&self) -> bool {
        self.trap.is_some()
    }

    /// Consumes the outcome and returns the transferred trap, if any.
    pub fn into_trap(self) -> Option<RuntimeTrap> {
        self.trap
    }
}

/// The result of one native strict-fold loop over an element run.
///
/// `consumed` leading elements of the caller's run were folded natively and
/// `accumulator` is the accumulator value after them. When `deopted` is true
/// the loop stopped early — a guard failed or a forcing evaluator error was
/// transferred while folding element `consumed` — and the caller must re-run
/// that element (and everything after it) through the interpreted fold loop,
/// which reproduces the exact tree-walk result or error.
#[derive(Clone, Copy, Debug)]
pub struct NativeFoldLoopOutcome {
    pub(crate) consumed: usize,
    pub(crate) accumulator: Value,
    pub(crate) deopted: bool,
}

impl NativeFoldLoopOutcome {
    /// Returns how many leading elements were folded natively.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Returns the accumulator value after the consumed elements.
    pub const fn accumulator(&self) -> Value {
        self.accumulator
    }

    /// Returns true when the loop stopped early on a deopt or error trap.
    pub const fn deopted(&self) -> bool {
        self.deopted
    }
}

/// The result of one native decoded-`i64`-accumulator fold loop.
///
/// `consumed` leading elements of the caller's run were folded natively and
/// `accumulator` is the decoded running accumulator after them. When `deopted`
/// is true the loop stopped early — a guard failed, a forcing evaluator error
/// was transferred, or a generated index exceeded `i64` — and the caller must
/// re-run element `consumed` (and everything after it) interpreted, seeding the
/// interpreted fold with `accumulator` re-encoded to a runtime value.
#[derive(Clone, Copy, Debug)]
pub struct NativeFoldI64AccLoopOutcome {
    pub(crate) consumed: usize,
    pub(crate) accumulator: i64,
    pub(crate) deopted: bool,
}

impl NativeFoldI64AccLoopOutcome {
    /// Returns how many leading elements were folded natively.
    pub const fn consumed(self) -> usize {
        self.consumed
    }

    /// Returns the decoded running accumulator after the consumed prefix.
    pub const fn accumulator(self) -> i64 {
        self.accumulator
    }

    /// Returns true when the loop stopped early on a deopt or error trap.
    pub const fn deopted(self) -> bool {
        self.deopted
    }
}

/// The result of one native strict-filter loop over an element run.
///
/// `consumed` leading elements of the caller's run were decided natively and
/// `kept` is the kept subsequence of that prefix, in element order. When
/// `deopted` is true the loop stopped early — a guard failed, a forcing
/// evaluator error was transferred, or the compiled predicate produced a
/// non-boolean while deciding element `consumed` — and the caller must re-run
/// that element (and everything after it) through the interpreted filter
/// loop, which reproduces the exact tree-walk result or error.
#[derive(Clone, Debug)]
pub struct NativeFilterLoopOutcome {
    pub(crate) consumed: usize,
    pub(crate) kept: Vec<Value>,
    pub(crate) deopted: bool,
}

impl NativeFilterLoopOutcome {
    /// Returns how many leading elements were decided natively.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Returns the kept elements of the decided prefix, in element order.
    pub fn kept(&self) -> &[Value] {
        &self.kept
    }

    /// Consumes the outcome and returns the kept elements.
    pub fn into_kept(self) -> Vec<Value> {
        self.kept
    }

    /// Returns true when the loop stopped early on a deopt or error trap.
    pub const fn deopted(&self) -> bool {
        self.deopted
    }
}

/// The result of one native strict `all`/`any` predicate loop.
#[derive(Clone, Copy, Debug)]
pub struct NativeAllAnyLoopOutcome {
    pub(crate) consumed: usize,
    pub(crate) short_circuited: bool,
    pub(crate) deopted: bool,
}

impl NativeAllAnyLoopOutcome {
    /// Returns how many leading elements were decided natively.
    pub const fn consumed(self) -> usize {
        self.consumed
    }

    /// Returns whether the predicate reached the requested short-circuit value.
    pub const fn short_circuited(self) -> bool {
        self.short_circuited
    }

    /// Returns whether the next element must be retried interpreted.
    pub const fn deopted(self) -> bool {
        self.deopted
    }
}
