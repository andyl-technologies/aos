//! Re-entry point for tier-1 native code that delegates a lowered builtin call.
//!
//! The tier-1 JIT lowers an [`IrKind::PrimOp`] thunk body to a single native
//! call to the `aos_primop_call` trampoline. Rather than re-implement any
//! builtin in machine code, that trampoline hands the primop node straight back
//! to this evaluator through [`TreeWalk::run_lowered_primop_body`], which forces
//! the primop exactly as an ordinary thunk force would. Keeping the primop's
//! real implementation on the tree walk is what preserves force-cache cutoff
//! soundness: every impure observation a builtin records still lands on the same
//! [`impure_input_trace`](TreeWalk) it would during a tree-walk force.
//!
//! # Dynamic-scope contract
//!
//! Dispatch hands this method only the thunk's captured lexical [`EvalEnv`]; it
//! does not carry the thunk's `with` scopes or scoped-import globals. The method
//! therefore installs an empty dynamic-scope context, which reproduces the tree
//! walk exactly only when the dispatched thunk captured no such scopes. The
//! engine enforces that precondition before dispatching a primop body, so a
//! thunk with live dynamic scopes deoptimizes to the tree walk instead.

use super::*;

impl TreeWalk {
    /// Forces a lowered primop `node` against a dispatched lexical environment.
    ///
    /// This is the safe evaluator body behind the `aos_primop_call` native
    /// trampoline. It installs `env` as the active lexical environment with
    /// empty `with`/scoped-import scopes (mirroring the thunk force path in
    /// [`eval_thunk_body`](TreeWalk)), evaluates the primop `node` in its owning
    /// module, and restores the caller's environment on every return path. The
    /// previously active environment is rooted across the call so builtin
    /// argument evaluation can allocate without collecting it.
    ///
    /// The caller must guarantee that the dispatched thunk captured no dynamic
    /// `with` or scoped-import scopes; otherwise the empty dynamic-scope context
    /// installed here would diverge from a tree-walk force. The tier-1 engine
    /// upholds this by deoptimizing such thunks.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] when the dispatched environment cannot be
    /// cloned into the evaluator, when `node` does not resolve in its module, or
    /// when evaluating the primop body fails for any reason the tree walk would
    /// also surface (bad arity, a trapping builtin, a type error, and so on).
    pub fn run_lowered_primop_body(
        &mut self,
        env: &EvalEnv,
        node: EvalNodeRef,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let id = node.id();
        let thunk_env = self.clone_env_frames(id, env, span)?;
        self.reserve_suspended_env_root_frame(id, span)?;
        let saved_env = self.swap_env_frames(thunk_env);
        let saved_with_scopes = std::mem::take(&mut self.with_scopes);
        let saved_scoped_globals = std::mem::take(&mut self.scoped_globals);
        self.push_suspended_env_roots(saved_env, saved_with_scopes, saved_scoped_globals);
        let result = self.with_current_module(node.module(), |eval| eval.eval_node(id));
        if let Some(saved) = self.pop_suspended_env_roots() {
            self.restore_env_frames(saved.env);
            self.with_scopes = saved.with_scopes;
            self.scoped_globals = saved.scoped_globals;
        } else {
            debug_assert!(false, "suspended env root stack is unbalanced");
        }
        result
    }
}
