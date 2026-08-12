//! Cross-module lambda-summary consumption at application sites.
//!
//! A closure carries its defining module and pattern id. Those two stable
//! coordinates select the persisted demand/escape summary without cloning it.
//! The caller's static argument shape is then matched to formal names and
//! derivation alias-key rules while the argument is assembled.

use super::*;
use crate::compile::{Cardinality, IrFacts, Strictness};

#[derive(Clone, Debug)]
pub(super) struct CallArgumentPlan {
    module: EvalModuleId,
    eager: Vec<IrId>,
    single_entry: Vec<IrId>,
}

impl TreeWalk {
    pub(super) fn eval_call_argument(
        &mut self,
        call: IrId,
        function_id: IrId,
        function_span: Span,
        function: Value,
        argument: IrId,
    ) -> Result<Value, TreeWalkError> {
        let Some(plan) =
            self.call_argument_plan(call, function_id, function_span, function, argument)?
        else {
            return self.eval_lazy_node(argument);
        };
        self.active_call_argument_plans.push(plan);
        let result = self.eval_lazy_node(argument);
        let popped = self.active_call_argument_plans.pop();
        debug_assert!(popped.is_some(), "call argument plan stack is unbalanced");
        result
    }

    fn call_argument_plan(
        &self,
        call: IrId,
        function_id: IrId,
        function_span: Span,
        function: Value,
        argument: IrId,
    ) -> Result<Option<CallArgumentPlan>, TreeWalkError> {
        let caller_module = self.current_module;
        let caller_ir = self.current_ir();
        // Chunk E transfers attribute-value facts across module boundaries.
        // Decline ordinary scalar/list arguments before touching the closure
        // heap, and let the existing intra-module annotation drive local calls.
        let Some(bindings) = static_argument_bindings(caller_ir, argument, 0) else {
            return Ok(None);
        };
        if function.tag() != ValueTag::Lambda {
            return Ok(None);
        }
        let lambda = self.heap.get_lambda(function).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: function_id,
                    source,
                },
                function_span,
            )
        })?;
        let callee_module = lambda.module();
        if callee_module == caller_module {
            return Ok(None);
        }
        let pattern = lambda.pattern();
        let Some(summary) = self
            .module_ir(callee_module)?
            .facts
            .lambda_call_summary(pattern)
        else {
            return Ok(None);
        };
        let result_demand = caller_ir
            .facts
            .get(call)
            .map_or(Strictness::Unknown, |facts| facts.strictness);
        let mut eager = Vec::new();
        let mut single_entry = Vec::new();
        if summary
            .argument_demand
            .at_call(result_demand)
            .is_demanded_before_effect()
            && caller_ir
                .arena
                .node(argument)
                .is_some_and(|node| node.kind == IrKind::ThunkAlloc)
        {
            eager.push(argument);
        }
        let Some(pattern) = static_formal_pattern(self.module_ir(callee_module)?, pattern) else {
            return Ok(Some(CallArgumentPlan {
                module: caller_module,
                eager,
                single_entry,
            }));
        };
        let pattern_safe = pattern.accepts(&bindings);
        for binding in bindings {
            let mut demand = Strictness::Unknown;
            let mut escape = Escape::NoEscape;
            let mut matched = false;
            if let Some(index) = pattern.names.iter().position(|name| *name == binding.key)
                && let Some(formal) = summary.formals.get(index)
            {
                demand = demand.max(formal.demand.at_call(result_demand));
                if formal.escape == Escape::Escapes {
                    escape = Escape::Escapes;
                }
                matched = true;
            }
            for attr in summary
                .attr_values
                .iter()
                .filter(|attr| attr.keys.contains(binding.key))
            {
                demand = demand.max(attr.demand.at_call(result_demand));
                if attr.escape == Escape::Escapes {
                    escape = Escape::Escapes;
                }
                matched = true;
            }
            if !matched || !demand.is_demanded() {
                continue;
            }
            let total = caller_ir.facts.structurally_total(binding.value);
            if total || (pattern_safe && demand.is_demanded_before_effect()) {
                eager.push(binding.value);
            } else if escape == Escape::NoEscape
                && caller_ir
                    .facts
                    .get(binding.value)
                    .is_some_and(|facts| facts.cardinality == Cardinality::Once)
            {
                single_entry.push(binding.value);
            }
        }
        Ok(Some(CallArgumentPlan {
            module: caller_module,
            eager,
            single_entry,
        }))
    }

    pub(super) fn eval_call_summary_planned_thunk(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Option<Value>, TreeWalkError> {
        let Some(plan) = self.active_call_argument_plans.iter().rev().find(|plan| {
            plan.module == self.current_module
                && (plan.eager.contains(&id) || plan.single_entry.contains(&id))
        }) else {
            return Ok(None);
        };
        let eager = plan.eager.contains(&id);
        let single_entry = plan.single_entry.contains(&id);
        if !eager && !single_entry {
            return Ok(None);
        }
        let IrData::Node(body) = node.data else {
            return Err(self.invalid_payload(id, node, "thunk body"));
        };
        if single_entry {
            return self
                .alloc_single_entry_thunk_from_plan(id, body, node.span)
                .map(Some);
        }
        self.increment_thunks_elided();
        if self.order_sensitive_binding_allocation_is_active() {
            self.increment_binding_assembly_elisions();
            return self
                .with_order_sensitive_binding_planning_suspended(|eval| eval.eval_node(body))
                .map(Some);
        }
        self.eval_node(body).map(Some)
    }

    pub(super) fn remap_call_summary_symbols(
        argument: IrId,
        argument_span: Span,
        path: &[u8],
        symbol_map: &[Symbol],
        facts: &mut IrFacts,
    ) -> Result<(), TreeWalkError> {
        for summary in facts.lambda_call_summaries_mut() {
            for attr in summary.attr_values.iter_mut() {
                let mut symbols = Vec::new();
                symbols
                    .try_reserve_exact(attr.keys.symbols().len())
                    .map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ImportScope {
                                id: argument,
                                path: path.to_vec(),
                                message: "failed to allocate call-summary symbol remap".to_owned(),
                            },
                            argument_span,
                        )
                    })?;
                for symbol in attr.keys.symbols() {
                    symbols.push(Self::remap_cached_symbol(
                        argument,
                        argument_span,
                        path,
                        symbol_map,
                        *symbol,
                    )?);
                }
                attr.keys.replace_symbols(symbols.into_boxed_slice());
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct StaticBinding {
    key: Symbol,
    value: IrId,
}

fn static_argument_bindings(ir: &Ir, id: IrId, depth: usize) -> Option<Vec<StaticBinding>> {
    if depth >= 64 {
        return None;
    }
    let node = ir.arena.node(id)?;
    match node.data {
        IrData::Node(body) if node.kind == IrKind::ThunkAlloc => {
            static_argument_bindings(ir, body, depth + 1)
        }
        IrData::AttrSet {
            bindings,
            recursive: false,
            has_dynamic: false,
            ..
        } => {
            let start = bindings.start as usize;
            let entries = ir.bindings.get(start..start.checked_add(bindings.len())?)?;
            entries
                .iter()
                .map(|binding| match binding.key {
                    IrAttrPathSegment::Static(key) => Some(StaticBinding {
                        key,
                        value: binding.value,
                    }),
                    IrAttrPathSegment::Dynamic(_) => None,
                })
                .collect()
        }
        IrData::Binary {
            op: BinOpKind::Update,
            lhs,
            rhs,
        } if node.kind == IrKind::BinOp => {
            let mut left = static_argument_bindings(ir, lhs, depth + 1)?;
            for binding in static_argument_bindings(ir, rhs, depth + 1)? {
                left.retain(|entry| entry.key != binding.key);
                left.push(binding);
            }
            Some(left)
        }
        _ => None,
    }
}

struct StaticFormalPattern {
    names: Vec<Symbol>,
    required: Vec<Symbol>,
    ellipsis: bool,
}

impl StaticFormalPattern {
    fn accepts(&self, bindings: &[StaticBinding]) -> bool {
        self.required
            .iter()
            .all(|name| bindings.iter().any(|binding| binding.key == *name))
            && (self.ellipsis
                || bindings
                    .iter()
                    .all(|binding| self.names.contains(&binding.key)))
    }
}

fn static_formal_pattern(ir: &Ir, pattern: IrId) -> Option<StaticFormalPattern> {
    let node = ir.arena.node(pattern)?;
    let IrData::FormalSet {
        formals, ellipsis, ..
    } = node.data
    else {
        return None;
    };
    let children = ir.arena.child_slice(formals)?;
    let mut names = Vec::with_capacity(children.len());
    let mut required = Vec::new();
    for formal in children {
        let IrData::Formal { name, default } = ir.arena.node(*formal)?.data else {
            return None;
        };
        names.push(name);
        if default.is_none() {
            required.push(name);
        }
    }
    Some(StaticFormalPattern {
        names,
        required,
        ellipsis,
    })
}
