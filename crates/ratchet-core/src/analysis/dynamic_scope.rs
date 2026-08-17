//! Dynamic-scope reachability: which nodes' subtrees can read a `with` var or a
//! scoped global.
//!
//! A tree-walk thunk or lambda captures the ambient dynamic environments
//! (`with` scopes and scoped-import globals) at allocation, yet most bodies can
//! reach neither. This analysis proves, per node, whether the node's *entire
//! lowered subtree* — descending through inner `Lambda`/`Let`/`ThunkAlloc`
//! bodies, since dynamic scope flows through them — can read the `with` env or
//! the scoped-global env. A `with`-var read ([`IrData::DialectScopeVar`])
//! reaches the `with` env; a scoped-global read ([`IrData::GlobalVar`]) reaches
//! the scoped-global env; and because a `with`-var read that misses every
//! active `with` scope falls back to the scoped-global env, a `DialectScopeVar`
//! reaches *both*. `with` never crosses a file/import boundary (an import resets
//! the ambient scopes), so a within-module subtree walk is complete.
//!
//! The reachability is conservative for a capture-elision consumer: a body may
//! be treated as reaching a dynamic var when it does not (over-capture is always
//! sound), but a body that can reach one is never reported clean. Out-of-range
//! ids answer `true` (dirty) for the same reason.
//!
//! # Invariant for the capture-elision consumer
//!
//! If [`reaches_with_var`](DynamicScopeReach::reaches_with_var) is `false` for an
//! allocation site's body, the site may skip capturing the ambient `with` scope:
//! forcing it installs an empty `with` scope, and because no node in the
//! transitive subtree reads a `with` var, no inner allocation performed during
//! that force needs the ambient scope either. The same holds for
//! [`reaches_scoped_global`](DynamicScopeReach::reaches_scoped_global) and the
//! scoped-global environment.

use crate::ir::{Ir, IrData, IrId, all_child_ids};

/// Per-node dynamic-scope reachability bitsets for one lowered module.
#[derive(Clone, Debug, Default)]
pub struct DynamicScopeReach {
    reaches_with_var: Vec<bool>,
    reaches_scoped_global: Vec<bool>,
}

impl DynamicScopeReach {
    /// Returns whether `id`'s subtree can read a `with` var.
    ///
    /// Answers `true` (conservatively dirty) for an id outside the analyzed
    /// arena, so an out-of-range query never elides a needed capture.
    pub fn reaches_with_var(&self, id: IrId) -> bool {
        self.reaches_with_var
            .get(id.as_u32() as usize)
            .copied()
            .unwrap_or(true)
    }

    /// Returns whether `id`'s subtree can read a scoped global.
    ///
    /// Answers `true` (conservatively dirty) for an id outside the analyzed
    /// arena, so an out-of-range query never elides a needed capture.
    pub fn reaches_scoped_global(&self, id: IrId) -> bool {
        self.reaches_scoped_global
            .get(id.as_u32() as usize)
            .copied()
            .unwrap_or(true)
    }
}

/// Computes [`DynamicScopeReach`] for every node of `ir`.
///
/// Runs one iterative post-order pass over the arena (each node's reachability
/// is the union of its own op class and its children's reachability), so the
/// cost is `O(nodes + edges)`. The lowered IR is acyclic, so the post-order
/// terminates; a shared subexpression (DAG child) is computed once.
pub fn analyze_dynamic_scope_reach(ir: &Ir) -> DynamicScopeReach {
    let count = ir.arena.nodes().len();
    let mut reaches_with_var = vec![false; count];
    let mut reaches_scoped_global = vec![false; count];
    let mut done = vec![false; count];

    for start in 0..count {
        if done[start] {
            continue;
        }
        // (node index, children already expanded) post-order stack.
        let mut stack: Vec<(usize, bool)> = vec![(start, false)];
        while let Some((idx, expanded)) = stack.pop() {
            if done[idx] {
                continue;
            }
            let Some(node) = ir.arena.node(IrId::new(idx as u32)) else {
                done[idx] = true;
                continue;
            };
            if expanded {
                let is_with_var = matches!(node.data, IrData::DialectScopeVar { .. });
                let mut with = is_with_var;
                // A `with`-var read that misses every active `with` scope falls
                // back to the scoped-global environment (see the evaluator's
                // `eval_global_fallback`), so a `DialectScopeVar` reaches the
                // scoped-global env in addition to the `with` env.
                let mut global = is_with_var || matches!(node.data, IrData::GlobalVar { .. });
                for child in all_child_ids(ir, node) {
                    let c = child.as_u32() as usize;
                    if c < count {
                        with |= reaches_with_var[c];
                        global |= reaches_scoped_global[c];
                    }
                }
                reaches_with_var[idx] = with;
                reaches_scoped_global[idx] = global;
                done[idx] = true;
            } else {
                stack.push((idx, true));
                for child in all_child_ids(ir, node) {
                    let c = child.as_u32() as usize;
                    if c < count && !done[c] {
                        stack.push((c, false));
                    }
                }
            }
        }
    }

    DynamicScopeReach {
        reaches_with_var,
        reaches_scoped_global,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrDialectOp, IrLowerOptions, lower, lower_with_options};
    use crate::resolve;
    use crate::syntax::parse_str;

    const TEST_WITH_VAR_OP: IrDialectOp = IrDialectOp::new(1);

    fn lower_plain(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("IR lowers")
    }

    fn lower_with_dyn(source: &str) -> Ir {
        let resolved = resolve(parse_str(source).expect("source parses")).expect("source resolves");
        lower_with_options(
            resolved,
            IrLowerOptions::new().with_dynamic_scope_var_op(|| Some(TEST_WITH_VAR_OP)),
        )
        .expect("IR lowers")
    }

    #[test]
    fn pure_arithmetic_reaches_neither_dynamic_scope() {
        let ir = lower_plain("1 + 2");
        let reach = analyze_dynamic_scope_reach(&ir);
        assert!(!reach.reaches_with_var(ir.root));
        assert!(!reach.reaches_scoped_global(ir.root));
    }

    #[test]
    fn with_var_read_reaches_with_var() {
        let ir = lower_with_dyn("with { a = 1; }; a");
        let reach = analyze_dynamic_scope_reach(&ir);
        assert!(reach.reaches_with_var(ir.root));
    }

    #[test]
    fn with_var_under_lambda_body_reaches_transitively() {
        // The `with` var is read only inside a lambda body; because dynamic
        // scope flows into lambda bodies, the enclosing node must still be
        // reported as reaching a `with` var (the descend-into-body invariant
        // that a binder-respecting walk would miss).
        let ir = lower_with_dyn("with { a = 1; }; (arg: a)");
        let reach = analyze_dynamic_scope_reach(&ir);
        assert!(reach.reaches_with_var(ir.root));
    }

    #[test]
    fn with_var_read_also_reaches_scoped_global_via_fallback() {
        // A `with`-var read that misses the active `with` scopes falls back to
        // the scoped-global env at runtime, so a body containing a `with`-var
        // read must be reported as reaching the scoped-global env too — even
        // though it has no `GlobalVar` node. Eliding the scoped-global capture
        // here would break `with { y = 0; }; x` under `scopedImport { x = ...; }`.
        let ir = lower_with_dyn("with { a = 1; }; a");
        let reach = analyze_dynamic_scope_reach(&ir);
        assert!(reach.reaches_with_var(ir.root));
        assert!(reach.reaches_scoped_global(ir.root));
    }

    #[test]
    fn global_probe_reaches_scoped_global() {
        // A free global identifier lowers to a `GlobalVar` probe.
        let ir = lower_plain("builtins");
        let reach = analyze_dynamic_scope_reach(&ir);
        assert!(reach.reaches_scoped_global(ir.root));
        assert!(!reach.reaches_with_var(ir.root));
    }
}
