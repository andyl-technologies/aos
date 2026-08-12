//! Capture-on-demand elision for dynamic environments (RFC-0007 §P1 STEP 2).
//!
//! Every tree-walk thunk and lambda allocation snapshots the ambient `with`
//! scopes and scoped-import globals, yet most bodies can reach neither. The
//! attribution probe ([`super::capture_probe`]) measures how many of those
//! captures are provably dead; this module acts on that same static fact by
//! substituting an empty environment for the snapshot at any allocation site
//! whose body cannot read the corresponding dynamic variable.
//!
//! # Soundness
//!
//! Skipping a capture is one-way safe: over-capturing is always correct, and
//! only a false *clean* verdict (skipping where a body could observe the
//! ambient scope) would corrupt evaluation. The static predicate
//! ([`analyze_dynamic_scope_reach`]) is conservative and transitive — it
//! descends into inner `Lambda`/`Let`/thunk bodies, so a body reported clean
//! has no `with`-var or scoped-global read anywhere in its subtree. An inner
//! allocation performed while forcing a clean body is itself a subtree node and
//! therefore also clean, so the empty scope it inherits is never observed.
//! Dynamic `with` binds at capture time, not call time, so a callee lambda
//! carries its own captured scope and is unaffected by the caller's elision.
//!
//! The reachability is computed once per module and cached for the lifetime of
//! the evaluator, keyed by dense module index; a per-instance cache (rather than
//! a thread-local) keeps module 0 of one evaluator from colliding with module 0
//! of the next on the same thread.
//!
//! Opt-in through `AOS_NIX_CAPTURE_ON_DEMAND` (default off, pending the builder
//! byte-parity battery), mirroring the default-off discipline of the other
//! RFC-0007 evaluation levers.

use super::*;
use crate::compile::analysis::dynamic_scope::{DynamicScopeReach, analyze_dynamic_scope_reach};

/// Per-evaluator opt-in state for eliding provably-dead dynamic-environment
/// captures.
#[derive(Debug, Default)]
pub(crate) struct CaptureOnDemand {
    /// Whether the `AOS_NIX_CAPTURE_ON_DEMAND` opt-in was set at construction.
    enabled: bool,
    /// Per-module dynamic-scope reachability, filled lazily and indexed by the
    /// dense [`EvalModuleId`] index.
    reach: Vec<Option<DynamicScopeReach>>,
}

impl CaptureOnDemand {
    /// Builds the state, reading the `AOS_NIX_CAPTURE_ON_DEMAND` opt-in once.
    pub(crate) fn from_env() -> Self {
        Self {
            enabled: capture_on_demand_enabled(),
            reach: Vec::new(),
        }
    }
}

/// Returns whether capture-on-demand elision is opted in.
///
/// **Default off.** The elision is byte-parity-neutral by construction (it only
/// drops captures a conservative static analysis proves dead), but it stays
/// behind an opt-in until the 546-derivation builder battery confirms parity,
/// matching the other RFC-0007 evaluation levers.
fn capture_on_demand_enabled() -> bool {
    matches!(
        std::env::var("AOS_NIX_CAPTURE_ON_DEMAND").ok().as_deref(),
        Some("1") | Some("true") | Some("on") | Some("yes")
    )
}

impl TreeWalk {
    /// Captures the ambient `with` and scoped-global environments for `body`,
    /// substituting an empty environment wherever the body provably cannot read
    /// the corresponding dynamic variable.
    ///
    /// Falls back to the unconditional snapshot for every site when the
    /// `AOS_NIX_CAPTURE_ON_DEMAND` opt-in is off, so the default build is
    /// unchanged.
    ///
    /// # Errors
    ///
    /// Propagates the capture-allocation errors of
    /// [`capture_with_env`](Self::capture_with_env) and
    /// [`capture_scoped_global_env`](Self::capture_scoped_global_env).
    pub(in crate::eval::tree_walk) fn capture_dynamic_envs(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<(EvalWithEnv, EvalScopedGlobalEnv), TreeWalkError> {
        let (with_clean, global_clean) = self.dynamic_capture_clean(body);
        let with_env = if with_clean {
            EvalWithEnv::default()
        } else {
            self.capture_with_env(id, span)?
        };
        let scoped_globals = if global_clean {
            EvalScopedGlobalEnv::default()
        } else {
            self.capture_scoped_global_env(id, span)?
        };
        Ok((with_env, scoped_globals))
    }

    /// Returns `(with_clean, scoped_global_clean)` for the current module's
    /// `body`: whether its transitive subtree provably cannot read a `with` var
    /// / scoped global.
    ///
    /// Answers `(false, false)` — never elide — when the opt-in is off or the
    /// analysis is unavailable, so an unknown answer only ever over-captures.
    fn dynamic_capture_clean(&mut self, body: IrId) -> (bool, bool) {
        if !self.capture_on_demand.enabled {
            return (false, false);
        }
        let module_index = self.current_module.index();
        let ready = self
            .capture_on_demand
            .reach
            .get(module_index)
            .is_some_and(Option::is_some);
        if !ready {
            let reach = analyze_dynamic_scope_reach(self.current_ir());
            let cache = &mut self.capture_on_demand.reach;
            if module_index >= cache.len() {
                cache.resize_with(module_index + 1, || None);
            }
            cache[module_index] = Some(reach);
        }
        match self
            .capture_on_demand
            .reach
            .get(module_index)
            .and_then(Option::as_ref)
        {
            Some(reach) => (
                !reach.reaches_with_var(body),
                !reach.reaches_scoped_global(body),
            ),
            None => (false, false),
        }
    }
}
