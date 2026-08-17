//! Stats-only classification of synthetic Apply force spines.

use super::*;

impl TreeWalk {
    /// Classifies a stats-only synthetic Apply force without affecting evaluation.
    pub(in crate::eval::tree_walk) fn apply_spine_descriptor(
        &self,
        thunk: &EvalThunk,
    ) -> Option<force_shape_census::ApplySpineDescriptor> {
        let (EvalThunkKind::Apply {
            function,
            function_value,
            argument,
            argument_value,
            ..
        }
        | EvalThunkKind::GenListElemAtAddOne {
            function,
            function_value,
            argument,
            argument_value,
            ..
        }) = thunk.kind()
        else {
            return None;
        };
        let origin = force_shape_census::synthetic_apply_origin(
            function.module().as_u32(),
            function.id().as_u32(),
            argument.module().as_u32(),
            argument.id().as_u32(),
        );
        let argument_class = if argument_value.tag() != ValueTag::Thunk {
            "whnf"
        } else {
            match self
                .heap
                .get_thunk(*argument_value)
                .map(|thunk| thunk.kind())
            {
                Ok(EvalThunkKind::Node { .. }) => "node-thunk",
                Ok(EvalThunkKind::Apply { .. } | EvalThunkKind::GenListElemAtAddOne { .. }) => {
                    "apply-thunk"
                }
                Ok(EvalThunkKind::Apply2(_)) => "apply2-thunk",
                Ok(_) => "other-thunk",
                Err(_) => "unresolved-thunk",
            }
        };
        let (callee, pattern, body) = match function_value.tag() {
            ValueTag::Lambda => match self.heap.get_lambda(*function_value) {
                Ok(lambda) => {
                    let module = lambda.module();
                    let pattern_id = lambda.pattern();
                    let body_id = lambda.body();
                    let has_one_frame_slot = self
                        .module_ir(module)
                        .ok()
                        .and_then(|ir| ir.frames.get(lambda.frame().index()))
                        .is_some_and(|frame| frame.slot_count == 1);
                    let pattern = match self.node_in_module(module, pattern_id) {
                        Ok(node)
                            if has_one_frame_slot
                                && node.kind == IrKind::Formal
                                && matches!(node.data, IrData::Formal { default: None, .. }) =>
                        {
                            "simple-formal"
                        }
                        Ok(node) if node.kind == IrKind::FormalSet => "formal-set",
                        Ok(_) => "other",
                        Err(_) => "unresolved",
                    };
                    let body = self.apply_spine_lambda_body_class(module, body_id);
                    ("lambda", pattern, body)
                }
                Err(_) => ("lambda", "unresolved", "unresolved"),
            },
            ValueTag::Primop => ("primop", "not-lambda", "not-lambda"),
            ValueTag::Attrs => ("attrs", "not-lambda", "not-lambda"),
            _ => ("other", "not-lambda", "not-lambda"),
        };
        Some(force_shape_census::ApplySpineDescriptor {
            origin,
            callee,
            pattern,
            body,
            argument: argument_class,
        })
    }

    /// Classifies one lambda body after its ordinary lazy-position wrapper.
    fn apply_spine_lambda_body_class(&self, module: EvalModuleId, body: IrId) -> &'static str {
        let Some(ir) = self.tier1_module_ir(module) else {
            return "unresolved";
        };
        let Some(node) = ir.arena.node(body).copied() else {
            return "unresolved";
        };
        let (kind, data) = match (node.kind, node.data) {
            (IrKind::ThunkAlloc, IrData::Node(inner)) => match ir.arena.node(inner).copied() {
                Some(inner) => (inner.kind, inner.data),
                None => return "unresolved",
            },
            _ => (node.kind, node.data),
        };
        match (kind, data) {
            (IrKind::LocalVar, IrData::Local { slot: 0 }) => "local-argument",
            (IrKind::LocalVar, _) => "local-other",
            (IrKind::UpvalVar, _) => "upvalue",
            (IrKind::Apply, _) => "apply",
            (IrKind::PrimOp, IrData::PrimOp { symbol, args }) => {
                let builtin = self.symbols.resolve(symbol).and_then(lookup_builtin);
                if builtin.is_some_and(|builtin| builtin.name() == b"elemAt")
                    && let Some(args) = ir.arena.child_slice(args)
                    && let [receiver, index] = args
                {
                    let operand_class = |id: &IrId| {
                        let node = ir.arena.node(*id).copied()?;
                        let (kind, data) = match (node.kind, node.data) {
                            (IrKind::ThunkAlloc, IrData::Node(inner)) => {
                                let inner = ir.arena.node(inner).copied()?;
                                (inner.kind, inner.data)
                            }
                            _ => (node.kind, node.data),
                        };
                        Some(match (kind, data) {
                            (IrKind::LocalVar, IrData::Local { slot: 0 }) => "argument",
                            (IrKind::LocalVar, _) => "local",
                            (IrKind::UpvalVar, _) => "upvalue",
                            (IrKind::Int, IrData::Int(1)) => "int-one",
                            (IrKind::Int, IrData::Int(-1)) => "int-minus-one",
                            (IrKind::Int, IrData::Int(0)) => "int-zero",
                            (IrKind::Int, IrData::Int(_)) => "int-other",
                            (IrKind::Apply, _) => "apply",
                            (IrKind::Select, _) => "select",
                            (IrKind::PrimOp, _) => "primop",
                            (IrKind::Let, _) => "let",
                            (IrKind::List, _) => "list",
                            (
                                IrKind::BinOp,
                                IrData::Binary {
                                    op: BinOpKind::Add, ..
                                },
                            ) => "add",
                            (
                                IrKind::BinOp,
                                IrData::Binary {
                                    op: BinOpKind::Sub, ..
                                },
                            ) => "sub",
                            _ => "other",
                        })
                    };
                    return match (operand_class(receiver), operand_class(index)) {
                        (Some("upvalue"), Some("argument")) => "elemAt:upvalue-argument",
                        (Some("upvalue"), Some("add")) => {
                            let Some(index_node) = ir.arena.node(*index).copied() else {
                                return "unresolved";
                            };
                            let IrData::Binary { lhs, rhs, .. } = index_node.data else {
                                return "elemAt:upvalue-add";
                            };
                            match (operand_class(&lhs), operand_class(&rhs)) {
                                (Some("argument"), Some("int-one")) => {
                                    "elemAt:upvalue-add:argument-int-one"
                                }
                                (Some("int-one"), Some("argument")) => {
                                    "elemAt:upvalue-add:int-one-argument"
                                }
                                (Some("argument"), Some("int-zero")) => {
                                    "elemAt:upvalue-add:argument-int-zero"
                                }
                                (Some("argument"), Some("int-minus-one")) => {
                                    "elemAt:upvalue-add:argument-int-minus-one"
                                }
                                (Some("argument"), Some("int-other")) => {
                                    "elemAt:upvalue-add:argument-int-other"
                                }
                                _ => "elemAt:upvalue-add:other",
                            }
                        }
                        (Some("upvalue"), Some("sub")) => "elemAt:upvalue-sub",
                        (Some("local"), Some("argument")) => "elemAt:local-argument",
                        (Some("apply"), Some("argument")) => "elemAt:apply-argument",
                        (Some("apply"), Some("add")) => "elemAt:apply-add",
                        (Some("select"), Some("argument")) => "elemAt:select-argument",
                        (Some("select"), Some("add")) => "elemAt:select-add",
                        (Some("primop"), Some("argument")) => "elemAt:primop-argument",
                        (Some("let"), Some("argument")) => "elemAt:let-argument",
                        (Some("list"), Some("argument")) => "elemAt:list-argument",
                        (Some("argument"), Some("upvalue")) => "elemAt:argument-upvalue",
                        _ => "elemAt:other",
                    };
                }
                builtin
                    .and_then(|builtin| std::str::from_utf8(builtin.name()).ok())
                    .unwrap_or("PrimOp")
            }
            (IrKind::BinOp, IrData::Binary { op, .. }) => binop_shape_class(op),
            _ => irkind_shape_class(kind),
        }
    }
}
