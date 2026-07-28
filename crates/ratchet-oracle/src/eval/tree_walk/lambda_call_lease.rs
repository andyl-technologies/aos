//! Evaluator-owned continuation state for interpreted simple lambda calls.
//!
//! This is a default-unused proving substrate for a future explicit demand
//! machine. It installs the same module, lexical environment, dynamic scopes,
//! call-depth entry, and lazy argument binding as the recursive oracle, but
//! records ownership in [`TreeWalk`] rather than a borrowing Rust stack frame.

use super::*;

impl TreeWalk {
    /// Begins an evaluator-owned interpreted simple-formal lambda call.
    ///
    /// A successful call leaves the lambda's module and call environment
    /// installed. The lazy argument is held by the new active frame, while the
    /// displaced evaluator context remains in the existing scanned suspended
    /// environment stack. The returned work therefore contains only copyable
    /// coordinates and can cross allocating explicit-continuation steps.
    ///
    /// Primops, functors, formal-set lambdas, tiered execution, force/content
    /// memoization, and package-boundary memo mode decline before call counters,
    /// call depth, module state, or environments are mutated. The default-off
    /// mixed ready-call corridor may retain an installed tier-1 engine because
    /// it prepares the exact native target before requesting this lease.
    ///
    /// # Errors
    ///
    /// Returns the same heap, module, frame, environment, call-depth, or simple
    /// formal binding diagnostics as the interpreted lambda path. Lease-stack
    /// allocation and generation failures are reported before observable
    /// evaluator state is mutated.
    ///
    /// # Panics
    ///
    /// Resumes a panic raised while binding the argument after first restoring
    /// the displaced call context.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_lambda_call_lease(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument_id: IrId,
        argument_span: Span,
        argument: Value,
    ) -> Result<BeginLambdaCallLease, TreeWalkError> {
        let mixed_ready_call =
            self.options.mixed_ready_call_enabled() && self.tier1_engine.is_some();
        if function.tag() != ValueTag::Lambda
            || (self.tier1_engine.is_some() && !mixed_ready_call)
            || (self.options.jit_tier1_publish_enabled() && !mixed_ready_call)
            || self.force_cache_active
            || self.options.memo_active()
            || self.options.boundary_memo_active()
        {
            return Ok(BeginLambdaCallLease::Declined);
        }

        let lambda = match self.heap.clone_lambda(function) {
            Ok(lambda) => lambda,
            Err(source) => {
                self.increment_function_calls();
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: function_id,
                        source,
                    },
                    function_span,
                ));
            }
        };
        let pattern_node = match self.node_in_module(lambda.module(), lambda.pattern()) {
            Ok(node) => *node,
            Err(error) => {
                self.increment_function_calls();
                return Err(error);
            }
        };
        if pattern_node.kind != IrKind::Formal
            || !matches!(
                pattern_node.data,
                IrData::Formal {
                    name: _,
                    default: None
                }
            )
        {
            return Ok(BeginLambdaCallLease::Declined);
        }

        let lease_count = self
            .active_lambda_call_leases
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::LambdaCallLeaseAllocationFailed {
                        id,
                        leases: usize::MAX,
                    },
                    span,
                )
            })?;
        self.active_lambda_call_leases.try_reserve(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::LambdaCallLeaseAllocationFailed {
                    id,
                    leases: lease_count,
                },
                span,
            )
        })?;
        self.reserve_suspended_env_root_frame(id, span)?;
        let generation = self
            .next_lambda_call_lease_generation
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::LambdaCallLeaseGenerationExhausted { id },
                    span,
                )
            })?;

        // From this point the recursive apply path has committed to a lambda
        // application and counts it even if frame preparation or call-depth
        // checking produces an error.
        self.increment_function_calls();

        let slot_count = self
            .module_ir(lambda.module())?
            .frames
            .get(lambda.frame().index())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidFrameId {
                        id,
                        frame: lambda.frame().as_u32(),
                    },
                    span,
                )
            })?
            .slot_count as usize;
        let mut call_env = self.clone_env_frames(id, lambda.env(), span)?;
        let call_frame = EvalFrame::new_linked(slot_count, call_env.frames.last().cloned())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))?;
        #[cfg(feature = "demand_region_shadow_probe")]
        self.note_demand_region_frame_allocation(id, slot_count);
        call_env.frames.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::CaptureAllocationFailed {
                        frames: call_env.frame_count() + 1,
                    },
                },
                span,
            )
        })?;
        call_env.frames.push(call_frame.clone());

        // Clone rare dynamic captures before switching any active state. This
        // is the slow branch inside `push_env_scope`, hoisted so every fallible
        // operation precedes the owned context installation.
        let captured_dynamic_scopes = if self.with_scopes.is_empty()
            && lambda.with_scope_env().is_empty()
            && self.scoped_globals.is_empty()
            && lambda.scoped_global_env().is_empty()
        {
            None
        } else {
            Some((
                self.clone_with_scopes(id, lambda.with_scope_env(), span)?,
                self.clone_scoped_globals(id, lambda.scoped_global_env(), span)?,
            ))
        };
        self.check_call_depth(id, span)?;

        let saved_module = self.current_module;
        let saved_call_depth = self.call_depth;
        let suspended_env_depth = self.suspended_env_roots.len();
        self.current_module = lambda.module();
        if let Err(error) = self.enter_call(id, span) {
            self.current_module = saved_module;
            return Err(error);
        }
        let saved_env = self.swap_env_frames(call_env);
        match captured_dynamic_scopes {
            None => self.push_suspended_env_roots(
                saved_env,
                EvalWithEnv::default(),
                EvalScopedGlobalEnv::default(),
            ),
            Some((captured_with, captured_scoped)) => {
                let saved_with = std::mem::replace(&mut self.with_scopes, captured_with);
                let saved_scoped = std::mem::replace(&mut self.scoped_globals, captured_scoped);
                self.push_suspended_env_roots(saved_env, saved_with, saved_scoped);
            }
        }

        self.next_lambda_call_lease_generation = generation;
        let token = LambdaCallLeaseToken::new(self.active_lambda_call_leases.len(), generation);
        self.active_lambda_call_leases.push(ActiveLambdaCallLease {
            token,
            module: lambda.module(),
            saved_module,
            suspended_env_depth,
            saved_call_depth,
        });

        let bind_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.begin_order_sensitive_binding_assembly();
            let result = self.bind_lambda_argument(
                id,
                lambda.pattern(),
                slot_count,
                &call_frame,
                argument_id,
                argument_span,
                argument,
                span,
            );
            self.end_order_sensitive_binding_assembly(result.is_ok());
            result
        }));
        match bind_result {
            Ok(Ok(())) => Ok(BeginLambdaCallLease::Ready(LambdaCallWork {
                token,
                module: lambda.module(),
                body: lambda.body(),
            })),
            Ok(Err(error)) => {
                self.abort_lambda_call_lease(token);
                Err(error)
            }
            Err(payload) => {
                self.end_order_sensitive_binding_assembly(false);
                self.abort_lambda_call_lease(token);
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// Runs one lambda-call continuation with result and panic cleanup.
    ///
    /// This proving helper is not wired into the production apply path.
    ///
    /// # Errors
    ///
    /// Returns the continuation error after restoring the displaced module,
    /// lexical environment, dynamic scopes, and call depth.
    ///
    /// # Panics
    ///
    /// Resumes a continuation panic after restoring the call context. Panics
    /// if the work token is stale or is not the innermost active call lease.
    pub(crate) fn run_lambda_call_lease_with(
        &mut self,
        work: LambdaCallWork,
        run: impl FnOnce(&mut Self, LambdaCallWork) -> Result<Value, TreeWalkError>,
    ) -> Result<Value, TreeWalkError> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(self, work)));
        match result {
            Ok(result) => self.finish_lambda_call_lease(work.token, result),
            Err(payload) => {
                self.abort_lambda_call_lease(work.token);
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// Finishes the innermost evaluator-owned lambda-call lease.
    ///
    /// # Errors
    ///
    /// Returns the continuation error supplied in `result` after restoring the
    /// displaced call context.
    ///
    /// # Panics
    ///
    /// Panics if `token` is stale or is not the innermost active call lease.
    pub(crate) fn finish_lambda_call_lease(
        &mut self,
        token: LambdaCallLeaseToken,
        result: Result<Value, TreeWalkError>,
    ) -> Result<Value, TreeWalkError> {
        self.restore_lambda_call_context(token);
        result
    }

    /// Aborts the innermost evaluator-owned lambda-call lease.
    ///
    /// # Panics
    ///
    /// Panics if `token` is stale or is not the innermost active call lease.
    pub(crate) fn abort_lambda_call_lease(&mut self, token: LambdaCallLeaseToken) {
        self.restore_lambda_call_context(token);
    }

    /// Restores the context recorded by the innermost lambda-call lease.
    fn restore_lambda_call_context(&mut self, token: LambdaCallLeaseToken) {
        let Some(active) = self.active_lambda_call_leases.last().copied() else {
            unreachable!("active lambda-call lease stack is unbalanced");
        };
        assert_eq!(
            active.token, token,
            "lambda-call lease token is stale or out of order"
        );
        debug_assert_eq!(active.module, self.current_module);
        debug_assert_eq!(token.depth(), self.active_lambda_call_leases.len() - 1);
        debug_assert_eq!(token.generation(), active.token.generation());
        assert_eq!(
            self.suspended_env_roots.len(),
            active.suspended_env_depth + 1,
            "lambda-call suspended environment stack is unbalanced"
        );
        assert_eq!(
            self.call_depth,
            active.saved_call_depth.saturating_add(1),
            "lambda-call depth is unbalanced"
        );

        // Match the recursive wrapper: restore the environment, then leave the
        // semantic call, then restore `with_current_module`'s module switch.
        self.pop_env_scope();
        self.leave_call();
        self.current_module = active.saved_module;
        let Some(popped) = self.active_lambda_call_leases.pop() else {
            unreachable!("checked lambda-call lease disappeared");
        };
        debug_assert_eq!(popped.token, token);
    }
}
