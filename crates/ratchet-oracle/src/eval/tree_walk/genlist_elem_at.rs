//! Guarded forcing for the modal `genList` elemAt generator.
//!
//! The Nix library frequently builds tails with
//! `genList (index: elemAt list (index + 1))`. Each generated element is still
//! an ordinary memoizing thunk, but an admitted marker can bypass the
//! one-slot lambda frame and the immediately forced body wrapper in the
//! default serial evaluator.

use super::*;

/// The exact lowered nodes needed by the fused force path.
#[derive(Clone, Copy, Debug)]
pub(super) struct GenListElemAtAddOnePlan {
    receiver_id: IrId,
    receiver_span: Span,
    receiver_depth: u32,
    receiver_slot: u32,
    local_id: IrId,
    local_span: Span,
    index_id: IrId,
    index_span: Span,
    add_id: IrId,
    add_node: IrNode,
    primop_id: IrId,
    primop_span: Span,
}

/// Cached immutable recipe shared by every marker from one generator.
#[derive(Clone, Copy, Debug)]
pub(super) struct GenListElemAtAddOneRecipe {
    plan: GenListElemAtAddOnePlan,
    module: EvalModuleId,
    receiver: Value,
}

/// One exact marker step's unforced selected child and forcing coordinate.
#[derive(Clone, Copy)]
pub(super) struct GenListElemAtSelected {
    pub(super) value: Value,
    pub(super) force_id: IrId,
    pub(super) force_span: Span,
}

impl TreeWalk {
    /// Returns whether a generator has the exact modal elemAt body.
    pub(super) fn is_genlist_elem_at_add_one_generator(&mut self, generator: Value) -> bool {
        self.genlist_elem_at_add_one_recipe(generator).is_some()
    }

    /// Attempts the marker's serial fast path before falling back to Apply.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_force_genlist_elem_at_add_one(
        &mut self,
        id: IrId,
        span: Span,
        function_value: Value,
        argument_value: Value,
    ) -> Option<Result<Value, TreeWalkError>> {
        let selected_child_census = self.options.genlist_selected_child_census_enabled();
        let selected = self.try_eval_genlist_elem_at_add_one_selected(
            id,
            span,
            function_value,
            argument_value,
        )?;
        Some(selected.and_then(|selected| {
            if selected_child_census {
                self.record_genlist_selected_child_if_enabled(selected.value);
            }
            if self.options.stg_session_enabled()
                && !self.options.eval_stats_dump()
                && !self.stg_session_active
            {
                self.force_genlist_selected_session(selected)
            } else {
                self.force_node_result(selected.force_id, selected.force_span, selected.value)
            }
        }))
    }

    /// Executes one exact marker step without forcing its selected child.
    pub(super) fn try_eval_genlist_elem_at_add_one_selected(
        &mut self,
        id: IrId,
        span: Span,
        function_value: Value,
        argument_value: Value,
    ) -> Option<Result<GenListElemAtSelected, TreeWalkError>> {
        if !self.genlist_elem_at_add_one_fast_path_admitted() {
            return None;
        }
        let recipe = self.genlist_elem_at_add_one_recipe(function_value)?;
        let plan = recipe.plan;
        let receiver = recipe.receiver;
        let index = self
            .heap
            .decode_int_value(argument_value)
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: plan.local_id,
                        source,
                    },
                    plan.local_span,
                )
            });
        let module = recipe.module;
        Some(index.and_then(|index| {
            let run = |eval: &mut Self| {
                eval.with_current_module(module, |eval| {
                    eval.increment_function_calls();
                    eval.enter_call(id, span)?;
                    let result = (|| {
                        let index_value = eval.eval_integer_binary(
                            plan.add_id,
                            &plan.add_node,
                            BinaryArithmeticOp::Add,
                            index,
                            1,
                        )?;
                        let selected = eval.eval_elem_at_primop_value(
                            EvalPrimOpArg::new_in_module(
                                module,
                                plan.receiver_id,
                                plan.receiver_span,
                                receiver,
                            ),
                            EvalPrimOpArg::new_in_module(
                                module,
                                plan.index_id,
                                plan.index_span,
                                index_value,
                            ),
                        )?;
                        Ok(GenListElemAtSelected {
                            value: selected,
                            force_id: plan.primop_id,
                            force_span: plan.primop_span,
                        })
                    })();
                    eval.leave_call();
                    result
                })
            };
            if self.options.stg_session_enabled() {
                run(self)
            } else {
                self.with_eval_stack_headroom(run)
            }
        }))
    }

    /// Executes one admitted marker step with its cached recipe.
    ///
    /// This is the session machine's `EnterMarker` opcode. The exact lowering
    /// has already proved the index expression to be `argument + 1`, so the
    /// opcode performs the wrapping addition and list selection directly
    /// while preserving the ordinary call-depth and diagnostic coordinates.
    pub(super) fn try_eval_genlist_elem_at_add_one_session_step(
        &mut self,
        id: IrId,
        span: Span,
        function_value: Value,
        argument_value: Value,
    ) -> Option<Result<GenListElemAtSelected, TreeWalkError>> {
        if !self.genlist_elem_at_add_one_fast_path_admitted() {
            return None;
        }
        let recipe = self.genlist_elem_at_add_one_recipe(function_value)?;
        let plan = recipe.plan;
        let index = self
            .heap
            .decode_int_value(argument_value)
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: plan.local_id,
                        source,
                    },
                    plan.local_span,
                )
            });
        self.heap.observe_value_identity(function_value);
        let key = function_value.relocation_sensitive_identity_bits();
        Some(index.and_then(|index| {
            self.with_current_module(recipe.module, |eval| {
                eval.increment_function_calls();
                eval.enter_call(id, span)?;
                let result = (|| {
                    let selected_index = index.wrapping_add(1);
                    let receiver =
                        eval.force_value(plan.receiver_id, plan.receiver_span, recipe.receiver)?;
                    if receiver.tag() != ValueTag::List {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::Type {
                                id: plan.receiver_id,
                                expected: "list",
                                actual: receiver.tag(),
                            },
                            plan.receiver_span,
                        ));
                    }
                    let selected = {
                        let list = eval.heap.get_list_view(receiver).map_err(|source| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::Heap {
                                    id: plan.receiver_id,
                                    source,
                                },
                                plan.receiver_span,
                            )
                        })?;
                        usize::try_from(selected_index)
                            .ok()
                            .and_then(|index| list.get(index))
                            .ok_or_else(|| {
                                TreeWalkError::new(
                                    TreeWalkErrorKind::ListIndexOutOfBounds {
                                        id: plan.index_id,
                                        index: selected_index,
                                        len: list.len(),
                                    },
                                    plan.index_span,
                                )
                            })?
                    };
                    eval.heap.observe_value_identity(receiver);
                    eval.heap.observe_value_identity(recipe.receiver);
                    if !receiver.raw_eq(recipe.receiver)
                        && let Some(cached) = eval.genlist_elem_at_add_one_plans.get_mut(&key)
                    {
                        cached.receiver = receiver;
                    }
                    Ok(GenListElemAtSelected {
                        value: selected,
                        force_id: plan.primop_id,
                        force_span: plan.primop_span,
                    })
                })();
                eval.leave_call();
                result
            })
        }))
    }

    /// Returns the cached exact recipe for one immutable generator closure.
    fn genlist_elem_at_add_one_recipe(
        &mut self,
        function_value: Value,
    ) -> Option<GenListElemAtAddOneRecipe> {
        self.heap.observe_value_identity(function_value);
        let key = function_value.relocation_sensitive_identity_bits();
        if let Some(recipe) = self.genlist_elem_at_add_one_plans.get(&key).copied() {
            return Some(recipe);
        }
        let lambda = self.heap.clone_lambda(function_value).ok()?;
        let plan = self.genlist_elem_at_add_one_plan(&lambda)?;
        let receiver_depth = usize::try_from(plan.receiver_depth.checked_sub(1)?).ok()?;
        let receiver =
            self.captured_env_value_at_depth(lambda.env(), receiver_depth, plan.receiver_slot)?;
        let recipe = GenListElemAtAddOneRecipe {
            plan,
            module: lambda.module(),
            receiver,
        };
        self.genlist_elem_at_add_one_plans.insert(key, recipe);
        Some(recipe)
    }

    /// Returns whether the exact marker may elide its ordinary Apply body.
    pub(super) fn genlist_elem_at_add_one_fast_path_admitted(&self) -> bool {
        let selected_child_census = self.options.genlist_selected_child_census_enabled();
        // These modes make the elided body wrapper, its roots, or its
        // force-cache/tier hooks observable. The marker retains every ordinary
        // Apply field, so declining here is lossless. The explicit selected-
        // child census intentionally admits this path under eval stats because
        // its subject exists only after the wrapper has been elided.
        !self.gc_mode.is_enabled()
            && self.tier1_engine.is_none()
            && !self.force_cache_active
            && self.shared.is_none()
            && (!self.options.eval_stats_dump() || selected_child_census)
    }

    /// Evaluates a marker through its retained ordinary Apply payload.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_genlist_elem_at_add_one_oracle_body(
        &mut self,
        id: IrId,
        span: Span,
        function: EvalNodeRef,
        function_span: Span,
        function_value: Value,
        argument: EvalNodeRef,
        argument_value: Value,
    ) -> Result<Value, TreeWalkError> {
        self.with_current_module(function.module(), |eval| {
            eval.apply_lambda_value(
                id,
                span,
                function.id(),
                function_value,
                function_span,
                argument.id(),
                argument_value,
            )
        })
    }

    /// Revalidates and extracts the exact lowering recognized by the marker.
    fn genlist_elem_at_add_one_plan(&self, lambda: &EvalLambda) -> Option<GenListElemAtAddOnePlan> {
        if !lambda.with_scope_env().is_empty() || !lambda.scoped_global_env().is_empty() {
            return None;
        }
        let ir = self.module_ir(lambda.module()).ok()?;
        if ir.frames.get(lambda.frame().index())?.slot_count != 1 {
            return None;
        }
        let pattern = ir.arena.node(lambda.pattern())?;
        if pattern.kind != IrKind::Formal
            || !matches!(pattern.data, IrData::Formal { default: None, .. })
        {
            return None;
        }
        let body = ir.arena.node(lambda.body())?;
        let primop_id = match (body.kind, body.data) {
            (IrKind::ThunkAlloc, IrData::Node(inner)) => inner,
            (IrKind::PrimOp, _) => lambda.body(),
            _ => return None,
        };
        let primop = *ir.arena.node(primop_id)?;
        let IrData::PrimOp { symbol, args } = primop.data else {
            return None;
        };
        if primop.kind != IrKind::PrimOp || self.symbols.resolve(symbol) != Some(b"elemAt") {
            return None;
        }
        let [receiver_id, index_id] = *ir.arena.child_slice(args)? else {
            return None;
        };
        let receiver_outer = *ir.arena.node(receiver_id)?;
        let receiver_inner = match (receiver_outer.kind, receiver_outer.data) {
            (IrKind::ThunkAlloc, IrData::Node(inner)) => *ir.arena.node(inner)?,
            _ => receiver_outer,
        };
        let IrData::Upval {
            depth: receiver_depth,
            slot: receiver_slot,
        } = receiver_inner.data
        else {
            return None;
        };
        if receiver_inner.kind != IrKind::UpvalVar || receiver_depth == 0 {
            return None;
        }
        let index_outer = *ir.arena.node(index_id)?;
        let (add_id, add_node) = match (index_outer.kind, index_outer.data) {
            (IrKind::ThunkAlloc, IrData::Node(inner)) => (inner, *ir.arena.node(inner)?),
            _ => (index_id, index_outer),
        };
        let IrData::Binary {
            op: BinOpKind::Add,
            lhs,
            rhs,
        } = add_node.data
        else {
            return None;
        };
        if add_node.kind != IrKind::BinOp {
            return None;
        }
        let local_outer = *ir.arena.node(lhs)?;
        let local_inner = match (local_outer.kind, local_outer.data) {
            (IrKind::ThunkAlloc, IrData::Node(inner)) => *ir.arena.node(inner)?,
            _ => local_outer,
        };
        if local_inner.kind != IrKind::LocalVar
            || !matches!(local_inner.data, IrData::Local { slot: 0 })
        {
            return None;
        }
        let one_outer = *ir.arena.node(rhs)?;
        let one_inner = match (one_outer.kind, one_outer.data) {
            (IrKind::ThunkAlloc, IrData::Node(inner)) => *ir.arena.node(inner)?,
            _ => one_outer,
        };
        if one_inner.kind != IrKind::Int || one_inner.data != IrData::Int(1) {
            return None;
        }
        Some(GenListElemAtAddOnePlan {
            receiver_id,
            receiver_span: receiver_outer.span,
            receiver_depth,
            receiver_slot,
            local_id: lhs,
            local_span: local_outer.span,
            index_id,
            index_span: index_outer.span,
            add_id,
            add_node,
            primop_id,
            primop_span: primop.span,
        })
    }

    /// Classifies the direct `elemAt` result before the exact path forces it.
    pub(super) fn record_genlist_selected_child_if_enabled(&mut self, value: Value) {
        if !self.options.genlist_selected_child_census_enabled() {
            return;
        }
        let descriptor = self.genlist_selected_child_descriptor(value);
        super::force_shape_census::record_genlist_selected_child(descriptor);
    }

    /// Classifies one direct selected child without forcing it.
    pub(super) fn genlist_selected_child_descriptor(
        &mut self,
        value: Value,
    ) -> super::force_shape_census::SelectedChildDescriptor {
        use super::force_shape_census::SelectedChildDescriptor;

        let runtime_kind = match value.tag() {
            ValueTag::Int => "int",
            ValueTag::Float => "float",
            ValueTag::Bool => "bool",
            ValueTag::Null => "null",
            ValueTag::String => "string",
            ValueTag::Path => "path",
            ValueTag::List => "list",
            ValueTag::Attrs => "attrs",
            ValueTag::Lambda => "lambda",
            ValueTag::Primop => "primop",
            ValueTag::External => "external",
            ValueTag::Thunk => "thunk",
        };
        if value.tag() != ValueTag::Thunk {
            return SelectedChildDescriptor {
                runtime_kind,
                thunk_kind: "not-thunk",
                thunk_state: "not-thunk",
                body: "not-node",
                apply: None,
                selected_apply: None,
            };
        }
        let Ok(thunk) = self.heap.get_thunk(value) else {
            return SelectedChildDescriptor {
                runtime_kind,
                thunk_kind: "unresolved",
                thunk_state: "unresolved",
                body: "not-node",
                apply: None,
                selected_apply: None,
            };
        };
        let thunk_state = match thunk.cell().state() {
            Ok(ThunkState::Suspended) => "suspended",
            Ok(ThunkState::Blackhole) => "blackhole",
            Ok(ThunkState::Forced) => "forced",
            Err(_) => "unresolved",
        };
        match thunk.kind() {
            EvalThunkKind::Node { .. } => SelectedChildDescriptor {
                runtime_kind,
                thunk_kind: "node",
                thunk_state,
                body: self.force_shape_class(thunk),
                apply: None,
                selected_apply: None,
            },
            EvalThunkKind::Apply { function_value, .. } => {
                let function_value = *function_value;
                let apply = self.apply_spine_descriptor(thunk);
                let selected_apply = self.genlist_selected_apply_descriptor(function_value);
                SelectedChildDescriptor {
                    runtime_kind,
                    thunk_kind: "apply",
                    thunk_state,
                    body: "not-node",
                    apply,
                    selected_apply: Some(selected_apply),
                }
            }
            EvalThunkKind::GenListElemAtAddOne { function_value, .. } => {
                let function_value = *function_value;
                let apply = self.apply_spine_descriptor(thunk);
                let selected_apply = self.genlist_selected_apply_descriptor(function_value);
                SelectedChildDescriptor {
                    runtime_kind,
                    thunk_kind: "genlist-elem-at-add-one",
                    thunk_state,
                    body: "not-node",
                    apply,
                    selected_apply: Some(selected_apply),
                }
            }
            EvalThunkKind::Apply2(_) => SelectedChildDescriptor {
                runtime_kind,
                thunk_kind: "apply2",
                thunk_state,
                body: "not-node",
                apply: None,
                selected_apply: None,
            },
            EvalThunkKind::Select { .. } => SelectedChildDescriptor {
                runtime_kind,
                thunk_kind: "select",
                thunk_state,
                body: "not-node",
                apply: None,
                selected_apply: None,
            },
            EvalThunkKind::BuiltinAttr { .. } => SelectedChildDescriptor {
                runtime_kind,
                thunk_kind: "builtin-attr",
                thunk_state,
                body: "not-node",
                apply: None,
                selected_apply: None,
            },
            EvalThunkKind::Released => SelectedChildDescriptor {
                runtime_kind,
                thunk_kind: "released",
                thunk_state,
                body: "not-node",
                apply: None,
                selected_apply: None,
            },
        }
    }

    /// Classifies the selected Apply's callee without forcing or cloning it.
    fn genlist_selected_apply_descriptor(
        &mut self,
        function_value: Value,
    ) -> super::force_shape_census::SelectedApplyDescriptor {
        use super::force_shape_census::{SelectedApplyBodyDescriptor, SelectedApplyDescriptor};

        let not_lambda = SelectedApplyBodyDescriptor {
            root_kind: "not-lambda",
            grammar: "not-lambda",
            features: 0,
            nodes: 0,
            depth: 0,
        };
        if function_value.tag() != ValueTag::Lambda {
            return SelectedApplyDescriptor {
                callee_kind: self.genlist_selected_callee_kind(function_value),
                lambda_module: "not-lambda",
                lexical_frames: 0,
                with_scopes: 0,
                scoped_globals: 0,
                body: not_lambda,
            };
        }
        let Ok(lambda) = self.heap.get_lambda(function_value) else {
            return SelectedApplyDescriptor {
                callee_kind: "lambda-unresolved",
                lambda_module: "unresolved",
                lexical_frames: 0,
                with_scopes: 0,
                scoped_globals: 0,
                body: SelectedApplyBodyDescriptor {
                    root_kind: "unresolved",
                    grammar: "unresolved",
                    ..not_lambda
                },
            };
        };
        let module = lambda.module();
        let body = lambda.body();
        let lexical_frames = saturating_u32(lambda.env().frame_count());
        let with_scopes = saturating_u32(lambda.with_scope_env().len());
        let scoped_globals = saturating_u32(lambda.scoped_global_env().len());
        let body = self.genlist_selected_apply_body_descriptor(module, body);
        SelectedApplyDescriptor {
            callee_kind: "lambda",
            lambda_module: if module == EvalModuleId::ROOT {
                "root"
            } else {
                "imported"
            },
            lexical_frames,
            with_scopes,
            scoped_globals,
            body,
        }
    }

    /// Returns a non-mutating runtime callee class for a selected Apply.
    fn genlist_selected_callee_kind(&self, value: Value) -> &'static str {
        match value.tag() {
            ValueTag::Primop => "primop",
            ValueTag::Attrs => "attrs",
            ValueTag::Thunk => match self.heap.get_thunk(value).map(EvalThunk::kind) {
                Ok(EvalThunkKind::Node { .. }) => "node-thunk",
                Ok(EvalThunkKind::Apply { .. }) => "apply-thunk",
                Ok(EvalThunkKind::GenListElemAtAddOne { .. }) => "genlist-thunk",
                Ok(EvalThunkKind::Apply2(_)) => "apply2-thunk",
                Ok(EvalThunkKind::Select { .. }) => "select-thunk",
                Ok(EvalThunkKind::BuiltinAttr { .. }) => "builtin-attr-thunk",
                Ok(EvalThunkKind::Released) => "released-thunk",
                Err(_) => "unresolved-thunk",
            },
            ValueTag::Lambda => "lambda",
            ValueTag::Int => "int",
            ValueTag::Float => "float",
            ValueTag::Bool => "bool",
            ValueTag::Null => "null",
            ValueTag::String => "string",
            ValueTag::Path => "path",
            ValueTag::List => "list",
            ValueTag::External => "external",
        }
    }

    /// Returns a cached bounded grammar summary for immutable lambda code.
    fn genlist_selected_apply_body_descriptor(
        &mut self,
        module: EvalModuleId,
        body: IrId,
    ) -> super::force_shape_census::SelectedApplyBodyDescriptor {
        let key = EvalNodeRef::new(module, body);
        if let Some(descriptor) = self.genlist_selected_child_body_plans.get(&key).copied() {
            return descriptor;
        }
        let descriptor = self
            .module_ir(module)
            .ok()
            .map_or_else(selected_apply_unresolved_body, |ir| {
                selected_apply_body_grammar(ir, body)
            });
        self.genlist_selected_child_body_plans
            .insert(key, descriptor);
        descriptor
    }
}

/// Saturates a platform-sized capture count for stable census output.
fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Returns the failed static-body descriptor used for missing module IR.
fn selected_apply_unresolved_body() -> super::force_shape_census::SelectedApplyBodyDescriptor {
    super::force_shape_census::SelectedApplyBodyDescriptor {
        root_kind: "unresolved",
        grammar: "unresolved",
        features: 0,
        nodes: 0,
        depth: 0,
    }
}

/// Performs a bounded, non-evaluating walk of reducer-relevant lambda syntax.
fn selected_apply_body_grammar(
    ir: &Ir,
    body: IrId,
) -> super::force_shape_census::SelectedApplyBodyDescriptor {
    use super::force_shape_census::SelectedApplyBodyDescriptor;

    const MAX_NODES: usize = 128;
    const MAX_DEPTH: u8 = 32;
    const LITERAL: u16 = 1 << 0;
    const LEXICAL: u16 = 1 << 1;
    const SELECT: u16 = 1 << 2;
    const PRIMOP: u16 = 1 << 3;
    const APPLY: u16 = 1 << 4;
    const LET: u16 = 1 << 5;
    const ATTRS: u16 = 1 << 6;
    const LIST: u16 = 1 << 7;
    const OPERATOR: u16 = 1 << 8;
    const THUNK: u16 = 1 << 9;
    const BUILTIN: u16 = 1 << 10;

    let Some(body_node) = ir.arena.node(body).copied() else {
        return selected_apply_unresolved_body();
    };
    let root = match body_node.data {
        IrData::Node(inner) if body_node.kind == IrKind::ThunkAlloc => inner,
        _ => body,
    };
    let Some(root_node) = ir.arena.node(root).copied() else {
        return selected_apply_unresolved_body();
    };
    let mut descriptor = SelectedApplyBodyDescriptor {
        root_kind: match root_node.data {
            IrData::Binary { op, .. } if root_node.kind == IrKind::BinOp => {
                super::eval_stats::binop_shape_class(op)
            }
            _ => super::eval_stats::irkind_shape_class(root_node.kind),
        },
        grammar: "supported",
        features: 0,
        nodes: 0,
        depth: 0,
    };
    let mut stack = vec![(body, 0u8)];
    let mut visited = HashSet::new();
    while let Some((id, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            descriptor.grammar = "depth-limit";
            break;
        }
        if !visited.insert(id.as_u32()) {
            continue;
        }
        if visited.len() > MAX_NODES {
            descriptor.grammar = "node-limit";
            break;
        }
        descriptor.nodes = visited.len() as u16;
        descriptor.depth = descriptor.depth.max(depth);
        let Some(node) = ir.arena.node(id).copied() else {
            descriptor.grammar = "malformed";
            break;
        };
        let feature = match node.kind {
            IrKind::Int
            | IrKind::Float
            | IrKind::Bool
            | IrKind::Null
            | IrKind::Str
            | IrKind::Path
            | IrKind::Uri => LITERAL,
            IrKind::LocalVar | IrKind::UpvalVar => LEXICAL,
            IrKind::BuiltinAttr => BUILTIN,
            IrKind::List => LIST,
            IrKind::AttrSet => ATTRS,
            IrKind::Apply => APPLY,
            IrKind::Select => SELECT,
            IrKind::Let => LET,
            IrKind::PrimOp => PRIMOP,
            IrKind::BinOp | IrKind::UnaryOp => OPERATOR,
            IrKind::ThunkAlloc => THUNK,
            _ => {
                descriptor.grammar = "unsupported";
                break;
            }
        };
        descriptor.features |= feature;
        let next_depth = depth.saturating_add(1);
        if !push_selected_apply_body_children(ir, node, next_depth, &mut stack) {
            descriptor.grammar = "malformed";
            break;
        }
    }
    descriptor
}

/// Pushes children for the bounded selected-Apply grammar walk.
fn push_selected_apply_body_children(
    ir: &Ir,
    node: IrNode,
    depth: u8,
    stack: &mut Vec<(IrId, u8)>,
) -> bool {
    let mut push = |id| stack.push((id, depth));
    match node.data {
        IrData::None
        | IrData::Int(_)
        | IrData::Float(_)
        | IrData::Bool(_)
        | IrData::Symbol(_)
        | IrData::Local { .. }
        | IrData::Upval { .. } => {}
        IrData::Node(child) => push(child),
        IrData::Pair { first, second } => {
            push(first);
            push(second);
        }
        IrData::Children(children) | IrData::PrimOp { args: children, .. } => {
            let Some(children) = ir.arena.child_slice(children) else {
                return false;
            };
            for child in children {
                push(*child);
            }
        }
        IrData::Binary { lhs, rhs, .. } => {
            push(lhs);
            push(rhs);
        }
        IrData::Unary { operand, .. } => push(operand),
        IrData::Select {
            receiver,
            path,
            default,
            ..
        } => {
            push(receiver);
            if let Some(default) = default {
                push(default);
            }
            let Some(segments) = ir.attr_paths.get(path.index()) else {
                return false;
            };
            for segment in segments.as_ref() {
                if let IrAttrPathSegment::Dynamic(segment) = segment {
                    push(*segment);
                }
            }
        }
        IrData::Let { bindings, body, .. } => {
            push(body);
            if !push_selected_apply_bindings(ir, bindings, depth, stack) {
                return false;
            }
        }
        IrData::AttrSet { bindings, .. } | IrData::Bindings(bindings) => {
            if !push_selected_apply_bindings(ir, bindings, depth, stack) {
                return false;
            }
        }
        _ => return false,
    }
    true
}

/// Pushes binding values and dynamic attribute-name expressions.
fn push_selected_apply_bindings(
    ir: &Ir,
    bindings: IrBindingSlice,
    depth: u8,
    stack: &mut Vec<(IrId, u8)>,
) -> bool {
    let start = bindings.start as usize;
    let Some(end) = start.checked_add(bindings.len()) else {
        return false;
    };
    let Some(bindings) = ir.bindings.get(start..end) else {
        return false;
    };
    for binding in bindings {
        stack.push((binding.value, depth));
        if let IrAttrPathSegment::Dynamic(segment) = binding.key {
            stack.push((segment, depth));
        }
    }
    true
}
