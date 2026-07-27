//! MEMO-2 boundary probe/admission apply-seam helpers for [`TreeWalk`].
//!
//! Split from `eval_primop_apply.rs` (RFC-0007 §2 line cap). These are the
//! read-only methods the lambda apply seam calls when a formal-set (package
//! boundary) application is seen: the M2-measure-1 economics probe classifier
//! and the M2-record boundary-admission recognizer. Neither forces or mutates
//! evaluation state; both are gated off by default at the call site.

use super::*;

impl TreeWalk {
    /// Dereferences an already-forced thunk chain to its underlying value
    /// without forcing.
    ///
    /// Returns the first non-thunk value reachable through cached thunk results,
    /// or `None` if a thunk in the chain is not yet forced — reading that would
    /// require forcing, which the probe must never do. Bounded against a
    /// pathological cached-thunk cycle.
    fn peek_forced_value(&self, value: Value) -> Option<Value> {
        const PEEK_DEPTH: usize = 64;
        let mut current = value;
        for _ in 0..PEEK_DEPTH {
            if current.tag() != ValueTag::Thunk {
                return Some(current);
            }
            match self.heap.get_thunk(current).ok()?.cell().cached_value() {
                Ok(Some(cached)) => current = cached,
                _ => return None,
            }
        }
        None
    }

    /// Recognizes and counts a keyed package-boundary application for MEMO-2
    /// M2-record increment 2 (measurement only; see
    /// [`boundary_admission`](super::boundary_admission)).
    ///
    /// The applied lambda's module names its source file; when that file is a
    /// keyed package boundary in the source-Merkle map, this counts one boundary
    /// application (and its distinct def-site and module). Reads only, never
    /// evaluates or forces.
    pub(super) fn record_boundary_admission(&self, lambda: &EvalLambda) {
        let Some(map) = super::boundary_admission::boundary_map(
            self.options.boundary_memo(),
            self.options.parse_cache_root.as_deref(),
        ) else {
            return;
        };
        let module_index = lambda.module().index();
        let Some(module) = self.modules.get(module_index) else {
            return;
        };
        let Some(source) = module.source.as_ref() else {
            return;
        };
        let path = String::from_utf8_lossy(&source.name).into_owned();
        if map
            .identity_for_source_path(std::path::Path::new(&path))
            .is_none()
        {
            return;
        }
        let module_index = u32::try_from(module_index).unwrap_or(u32::MAX);
        let def_site = (u64::from(module_index) << 32) | u64::from(lambda.pattern().as_u32());
        super::boundary_admission::note_boundary_application(module_index, def_site);
    }

    /// Classifies one package-boundary application's argument members for the
    /// MEMO-2 economics probe (measurement only; see
    /// [`pkg_boundary_probe`](super::pkg_boundary_probe)).
    ///
    /// A formal-set-pattern lambda destructures a single attrset argument, so
    /// its members are the dependency values a boundary record would key on.
    /// Each member is hashable iff a durable value hash is derivable without
    /// forcing ([`Self::force_cache_free_var_value_hash`]); an unforced thunk or
    /// closure is not, and one such member makes the boundary decline under
    /// MEMO-1 rules. This is a read-only classification and never forces.
    pub(super) fn record_pkg_boundary_probe(&self, lambda: &EvalLambda, argument: Value) {
        // The formal-set binder already forced the argument to destructure it,
        // so resolving the (now-forced) thunk to its attrs is a non-forcing read
        // that cannot perturb demand order. A still-unforced or non-attrs
        // argument records a zero-member boundary.
        let attrs = self
            .peek_forced_value(argument)
            .and_then(|value| self.heap.get_attrs_view(value).ok());
        let members: Vec<Value> = match attrs {
            Some(attrs) => attrs.iter_by_symbol().map(|entry| entry.value).collect(),
            None => Vec::new(),
        };
        let total = u32::try_from(members.len()).unwrap_or(u32::MAX);
        let mut hashable = 0u32;
        for value in members {
            if self.force_cache_free_var_value_hash(value).is_some() {
                hashable = hashable.saturating_add(1);
            }
        }
        let def_site =
            (u64::from(lambda.module().as_u32()) << 32) | u64::from(lambda.body().as_u32());
        super::pkg_boundary_probe::note_pkg_boundary_apply(def_site, total, hashable);
    }
}
