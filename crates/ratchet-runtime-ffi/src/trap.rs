//! Scoped trap transfer for runtime FFI wrappers.
//!
//! Native tier-1 code calls forcing and environment-access wrappers through
//! frozen C ABI signatures that cannot return a `Result`. Before this module,
//! the only failure behavior those wrappers had was [`std::process::abort`]:
//! an evaluator error inside a compiled thunk would terminate the whole
//! process, which is unusable for a differential conformance harness that must
//! observe failing evaluations.
//!
//! This module adds a per-thread, scoped trap sink so a wrapper can transfer an
//! evaluator error back to the caller that entered the compiled code instead of
//! aborting. The mechanism is deliberately narrow:
//!
//! ```text
//! caller installs RuntimeTrapScope        (arms the thread-local sink)
//!   -> calls compiled thunk entry
//!        -> aos_force / aos_env_get / ... hits an evaluator error
//!             -> record_runtime_trap(trap)  (stores the first trap, armed)
//!             -> wrapper returns runtime_trap_sentinel_value()
//!   <- compiled thunk returns the sentinel Value
//! caller reads RuntimeTrapScope::take_trap()  (Some(trap) => surface as error)
//! ```
//!
//! The sink is only *armed* while a [`RuntimeTrapScope`] is live. Outside a
//! scope, [`record_runtime_trap`] falls back to [`std::process::abort`], so an
//! evaluator error in code that forgot to install a scope fails fast rather than
//! silently yielding the sentinel. Nested scopes save and restore the prior
//! cell, so re-entrant native calls each observe their own trap state.
//!
//! # Safepoint invariant
//!
//! The sink stores only owned error values ([`RuntimeTrap`]), never a runtime
//! [`Value`] or any heap pointer. Compiled force safepoints may run the Tier-B
//! non-moving sweep, but the raw runtime-context and environment pointers stay
//! stable and the trap cell never needs tracing or relocation. A future moving
//! collector must finish live compiled-slot writeback before recording a trap.

use std::cell::RefCell;
use std::process;

use ratchet_oracle::eval::tree_walk::TreeWalkError;
use ratchet_oracle::eval::{EvalEnvError, heap::EvalRootSetError};
use ratchet_oracle::value::Value;

thread_local! {
    /// Per-thread trap cell shared by every runtime FFI wrapper on this thread.
    static RUNTIME_TRAP_SINK: RefCell<RuntimeTrapCell> =
        const { RefCell::new(RuntimeTrapCell::inactive()) };
}

/// An evaluator failure transferred out of a native wrapper without aborting.
///
/// Each variant preserves the safe evaluator error the wrapper would otherwise
/// have aborted on, so a caller can inspect the exact failure that a compiled
/// thunk hit after crossing back from native code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeTrap {
    /// A forcing wrapper (`aos_force`, `aos_force_deep`, `aos_blackhole_check`)
    /// reported a tree-walk evaluator error.
    Force(TreeWalkError),
    /// Finalized compiled roots could not be materialized for a collector poll.
    StackMap(EvalRootSetError),
    /// The environment-access wrapper (`aos_env_get`) reported a frame error.
    Env(EvalEnvError),
    /// The call-control wrapper (`aos_apply`) reported a tree-walk evaluator error.
    Apply(TreeWalkError),
    /// The primop-dispatch wrapper (`aos_primop_call`) reported a tree-walk
    /// evaluator error while forcing a lowered builtin-call body.
    Primop(TreeWalkError),
    /// An attrset-access wrapper (`aos_has_attr`, `aos_select_ic`, `aos_update`)
    /// reported a tree-walk evaluator error.
    Attr(TreeWalkError),
    /// A semantic allocation wrapper reported a tree-walk evaluator error.
    Allocation(TreeWalkError),
    /// A compiled body requested deoptimization through `aos_deopt`.
    ///
    /// This carries no evaluator error: it is a control signal a compiled tier-1
    /// body raises when an inline fast-path guard fails (a non-integer operand,
    /// a zero divisor, or another case the body cannot handle). The engine
    /// observes it as a silent deopt and re-runs the body through the tree walk,
    /// which produces the exact value or error.
    Deopt,
}

/// Per-thread trap state guarded by [`RuntimeTrapScope`].
///
/// `armed` is true only while a scope is live. `trap` holds the first recorded
/// trap within the current armed window; later traps in the same window are
/// dropped so the earliest failure is the one surfaced.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeTrapCell {
    armed: bool,
    trap: Option<RuntimeTrap>,
}

impl RuntimeTrapCell {
    /// Returns the disarmed, empty trap cell used before any scope is installed.
    const fn inactive() -> Self {
        Self {
            armed: false,
            trap: None,
        }
    }
}

/// Returns the placeholder runtime [`Value`] a wrapper returns after a trap.
///
/// The value is a valid, payload-checked `null` so the value-return validation
/// on the native-call boundary accepts it. Callers must treat it as meaningless
/// whenever [`RuntimeTrapScope::take_trap`] reports a recorded trap.
pub const fn runtime_trap_sentinel_value() -> Value {
    Value::null()
}

/// Records `trap` for the active [`RuntimeTrapScope`], or aborts if none is live.
///
/// When a scope is armed on the current thread, the first trap in the current
/// window is stored and later traps are ignored. When no scope is armed, the
/// caller entered native code without opting into trap transfer, so this aborts
/// the process to preserve the previous fail-fast behavior instead of silently
/// yielding [`runtime_trap_sentinel_value`].
///
/// # Panics
///
/// Never panics. Aborts the process (does not unwind) when no scope is armed.
pub(crate) fn record_runtime_trap(trap: RuntimeTrap) {
    let armed = RUNTIME_TRAP_SINK.with(|sink| {
        let mut cell = sink.borrow_mut();
        if !cell.armed {
            return false;
        }
        if cell.trap.is_none() {
            cell.trap = Some(trap);
        }
        true
    });
    if !armed {
        process::abort();
    }
}

/// A live opt-in to trap transfer for native wrapper calls on this thread.
///
/// Installing a scope arms the thread-local trap sink so forcing and
/// environment-access wrappers record evaluator errors instead of aborting.
/// The scope must outlive the native call it guards; read the recorded trap
/// with [`Self::take_trap`] after the call returns. Dropping the scope restores
/// whatever trap state was in effect when it was installed, so nested native
/// calls compose.
#[derive(Debug)]
#[must_use = "the trap scope must stay live across the guarded native call"]
pub struct RuntimeTrapScope {
    previous: RuntimeTrapCell,
}

impl RuntimeTrapScope {
    /// Installs an armed, empty trap scope on the current thread.
    ///
    /// The previously installed trap cell is saved and restored when the scope
    /// is dropped, so scopes can nest without losing an outer trap.
    pub fn new() -> Self {
        let previous = RUNTIME_TRAP_SINK.with(|sink| {
            sink.replace(RuntimeTrapCell {
                armed: true,
                trap: None,
            })
        });
        Self { previous }
    }

    /// Removes and returns the trap recorded during this scope, if any.
    ///
    /// Calling this consumes the current window's trap; a later native call
    /// under the same scope starts from an empty trap again.
    pub fn take_trap(&self) -> Option<RuntimeTrap> {
        RUNTIME_TRAP_SINK.with(|sink| sink.borrow_mut().trap.take())
    }
}

impl Default for RuntimeTrapScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RuntimeTrapScope {
    fn drop(&mut self) {
        RUNTIME_TRAP_SINK.with(|sink| {
            *sink.borrow_mut() = self.previous.clone();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_without_scope_is_not_stored() {
        // No scope is armed here, so recording would abort in the wrapper path.
        // The cell stays disarmed and empty, which is what the take API reports
        // once a scope is later installed.
        let scope = RuntimeTrapScope::new();
        assert!(scope.take_trap().is_none());
    }

    #[test]
    fn armed_scope_records_first_trap_only() {
        let scope = RuntimeTrapScope::new();
        record_runtime_trap(RuntimeTrap::Env(EvalEnvError::SlotOutOfBounds {
            slot: 3,
            slots: 1,
        }));
        record_runtime_trap(RuntimeTrap::Env(EvalEnvError::BorrowConflict));

        let trap = scope.take_trap().expect("armed scope records a trap");
        assert_eq!(
            trap,
            RuntimeTrap::Env(EvalEnvError::SlotOutOfBounds { slot: 3, slots: 1 })
        );
        assert!(scope.take_trap().is_none());
    }

    #[test]
    fn nested_scope_restores_outer_trap_state() {
        let outer = RuntimeTrapScope::new();
        record_runtime_trap(RuntimeTrap::Env(EvalEnvError::BorrowConflict));
        {
            let inner = RuntimeTrapScope::new();
            assert!(inner.take_trap().is_none());
            record_runtime_trap(RuntimeTrap::Env(EvalEnvError::SlotOutOfBounds {
                slot: 9,
                slots: 2,
            }));
            assert_eq!(
                inner.take_trap(),
                Some(RuntimeTrap::Env(EvalEnvError::SlotOutOfBounds {
                    slot: 9,
                    slots: 2
                }))
            );
        }
        assert_eq!(
            outer.take_trap(),
            Some(RuntimeTrap::Env(EvalEnvError::BorrowConflict))
        );
    }

    #[test]
    fn sentinel_value_is_valid_null() {
        let sentinel = runtime_trap_sentinel_value();
        assert!(sentinel.validate_payload().is_ok());
        assert!(sentinel.raw_eq(Value::null()));
    }
}
