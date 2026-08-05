//! Compiled-root publication and Tier-B dispatch around forcing helpers.

use ratchet_oracle::{
    compile::IrId,
    eval::{
        heap::EvalRootSetError,
        tree_walk::{TreeWalk, TreeWalkError},
    },
    syntax::Span,
    value::Value,
};

use crate::{
    context::RuntimeJitContext,
    trap::{RuntimeTrap, record_runtime_trap, runtime_trap_sentinel_value},
};

pub(super) fn run_force_at_compiled_safepoint(
    context: &mut RuntimeJitContext<'_>,
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    body: impl FnOnce(&mut TreeWalk) -> Result<Value, TreeWalkError>,
) -> Value {
    let roots =
        if eval.compiled_safepoint_roots_required() && context.has_active_stack_map_binding() {
            match context.active_stack_map_roots() {
                Ok(roots) => Some(roots),
                Err(error) => return record_stack_map_error(error),
            }
        } else {
            None
        };
    let result = if let Some(roots) = roots.as_ref() {
        let mut values = Vec::new();
        if values.try_reserve_exact(roots.len()).is_err() {
            return record_stack_map_error(EvalRootSetError::AllocationFailed {
                roots: roots.len(),
            });
        }
        values.extend(roots.roots().iter().map(|root| root.value()));
        eval.with_transient_value_stack_roots(id, span, &mut values, body)
    } else {
        body(eval)
    };

    match result {
        Ok(value) if roots.is_none() || !eval.compiled_safepoint_sweep_requested() => value,
        Ok(value) => {
            let Some(roots) = roots else {
                return value;
            };
            match eval.maybe_sweep_heap_at_compiled_safepoint(&roots, &[value]) {
                Ok(_) => value,
                Err(error) => record_force_error(error),
            }
        }
        Err(error) => record_force_error(error),
    }
}

fn record_stack_map_error(error: EvalRootSetError) -> Value {
    record_runtime_trap(RuntimeTrap::StackMap(error));
    runtime_trap_sentinel_value()
}

fn record_force_error(error: TreeWalkError) -> Value {
    record_runtime_trap(RuntimeTrap::Force(error));
    runtime_trap_sentinel_value()
}

#[cfg(test)]
mod tests {
    use ratchet_oracle::{
        eval::{
            heap::EvalGcMode,
            tree_walk::{TreeWalk, TreeWalkOptions},
        },
        syntax::{Span, parse_str},
    };

    use super::*;

    #[test]
    fn unmapped_force_site_does_not_dispatch_sweep() {
        let parsed = parse_str("null").expect("source parses");
        let resolved = ratchet_oracle::compile::resolve(parsed).expect("source resolves");
        let ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
        let mut context_eval = TreeWalk::new(&ir);
        let mut context = RuntimeJitContext::new(&mut context_eval, ir.root, Span::default());
        let mut options = TreeWalkOptions::default();
        options.set_gc_mode(EvalGcMode::Sweep);
        options.set_gc_sweep_threshold(0);
        let mut sweep_eval = TreeWalk::with_options(&ir, options);

        let value = run_force_at_compiled_safepoint(
            &mut context,
            &mut sweep_eval,
            ir.root,
            Span::default(),
            |_| Ok(Value::int(42)),
        );

        assert!(value.raw_eq(Value::int(42)));
        assert_eq!(sweep_eval.stats().gc_sweeps(), 0);
        assert!(sweep_eval.last_gc_sweep_report().is_none());
    }
}
