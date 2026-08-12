//! Tier-1 dispatch guards and native-inline admission policy.

use ratchet_oracle::eval::{EvalNodeRef, tree_walk::TreeWalk};
use ratchet_value::value::Value;

use super::body_is_primop;

/// Returns true when a primop thunk captured unsupported dynamic scopes.
pub(super) fn primop_dispatch_needs_dynamic_scopes(
    eval: &TreeWalk,
    thunk: Value,
    body: EvalNodeRef,
) -> bool {
    if !body_is_primop(eval, body) {
        return false;
    }
    let Ok(heap_thunk) = eval.heap().get_thunk(thunk) else {
        return false;
    };
    let with_nonempty = heap_thunk
        .with_scope_env()
        .is_some_and(|env| !env.scopes().is_empty());
    let scoped_nonempty = heap_thunk
        .scoped_global_env()
        .is_some_and(|env| !env.scopes().is_empty());
    with_nonempty || scoped_nonempty
}

/// Returns whether a pure builtin has a native tier-1 inline lowering.
pub(super) fn primop_has_native_inline(name: &[u8]) -> bool {
    // `stringLength` is pure and deterministic: its inline body forces the
    // argument and returns its byte length, deoptimizing to the tree walk for a
    // non-string (coercible) argument.
    name == b"stringLength"
}
