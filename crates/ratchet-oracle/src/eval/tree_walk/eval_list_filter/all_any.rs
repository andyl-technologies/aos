//! Strict `builtins.all` and `builtins.any` evaluation loops.

use super::super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn eval_all_any_primop(
        &mut self,
        op: AllAnyOp,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let predicate_span = self.node(predicate_id)?.span;
        let predicate = self.eval_node(predicate_id)?;
        let predicate = self.force_callable_value(predicate_id, predicate_span, predicate)?;

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list_view(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_view_elements(list_id, list_span, list)?
        };

        self.eval_all_any_elements(
            op,
            id,
            span,
            predicate_id,
            predicate_span,
            predicate,
            list_id,
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::eval::tree_walk) fn eval_all_any_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        op: AllAnyOp,
        predicate: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let predicate_value =
            self.force_callable_value(predicate.id(), predicate.span(), predicate.value())?;
        let list_value = self.force_value(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list_view(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_view_elements(list.id(), list.span(), list_value)?
        };

        self.eval_all_any_elements(
            op,
            id,
            span,
            predicate.id(),
            predicate.span(),
            predicate_value,
            list.id(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_all_any_elements(
        &mut self,
        op: AllAnyOp,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        predicate_span: Span,
        predicate: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        if let Some(island) = self.prepare_any_equality_island(op, predicate, !elements.is_empty())
        {
            // Generic lambda preparation resolves the argument span before
            // counting or applying the first call.
            self.node(list_id)?;
            return self.eval_any_equality_island(id, span, island, elements);
        }
        let mut index = 0usize;
        let mut tier2_consults = 0u32;
        let mut reused_lambda = self.prepare_reused_lambda_call(
            predicate_id,
            predicate,
            predicate_span,
            list_id,
            !elements.is_empty(),
        )?;
        while index < elements.len() {
            if tier2_consults < 2 && self.tier1_engine.is_some() {
                tier2_consults += 1;
                if let Some((consumed, short_circuited)) = self.try_tier2_all_any(
                    id,
                    span,
                    predicate,
                    &elements[index..],
                    op.short_circuit_value(),
                ) {
                    index += consumed;
                    if short_circuited {
                        return Ok(Value::bool(op.short_circuit_value()));
                    }
                    continue;
                }
            }
            let element = elements[index];
            let result = match reused_lambda.as_mut() {
                Some(call) => self.apply_prepared_reused_lambda_call(
                    id, span, predicate, call, list_id, element,
                )?,
                None => self.apply_lambda_value(
                    id,
                    span,
                    predicate_id,
                    predicate,
                    predicate_span,
                    list_id,
                    element,
                )?,
            };
            let result = self.force_value(predicate_id, predicate_span, result)?;
            let actual = result.tag();
            let ValueTag::Bool = actual else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: predicate_id,
                        expected: "bool",
                        actual,
                    },
                    predicate_span,
                ));
            };
            let result = self.expect_bool(predicate_id, result, predicate_span)?;
            if op.short_circuits(result) {
                return Ok(Value::bool(op.short_circuit_value()));
            }
            index += 1;
        }
        Ok(Value::bool(op.empty_or_exhausted_value()))
    }
}
