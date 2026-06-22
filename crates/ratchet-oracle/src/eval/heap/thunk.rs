//! Constructors and accessors for [`EvalThunk`] suspended-work records.

use super::*;

impl EvalThunk {
    /// Creates a suspended environment-free thunk record for `body`.
    pub fn new(body: IrId) -> Self {
        Self::with_env(EvalModuleId::ROOT, body, EvalEnv::default())
    }

    /// Creates a suspended thunk record for `body` and `env`.
    pub fn with_env(module: EvalModuleId, body: IrId, env: EvalEnv) -> Self {
        Self::with_captures(
            module,
            body,
            env,
            EvalWithEnv::default(),
            EvalScopedGlobalEnv::default(),
        )
    }

    /// Creates a suspended thunk record with lexical and dynamic captures.
    pub fn with_captures(
        module: EvalModuleId,
        body: IrId,
        env: EvalEnv,
        with_env: EvalWithEnv,
        scoped_globals: EvalScopedGlobalEnv,
    ) -> Self {
        Self {
            kind: EvalThunkKind::Node {
                body: EvalNodeRef::new(module, body),
                env,
                with_env,
                scoped_globals,
            },
            cell: ThunkCell::new(),
        }
    }

    /// Creates a suspended function-application thunk record.
    pub const fn apply(
        function_module: EvalModuleId,
        function_id: IrId,
        function_span: Span,
        function_value: Value,
        argument_module: EvalModuleId,
        argument_id: IrId,
        argument_value: Value,
    ) -> Self {
        Self {
            kind: EvalThunkKind::Apply {
                function: EvalNodeRef::new(function_module, function_id),
                function_span,
                function_value,
                argument: EvalNodeRef::new(argument_module, argument_id),
                argument_value,
            },
            cell: ThunkCell::new(),
        }
    }

    /// Creates a suspended two-argument function-application thunk record.
    #[allow(clippy::too_many_arguments)]
    pub const fn apply2(
        function_module: EvalModuleId,
        function_id: IrId,
        function_span: Span,
        function_value: Value,
        first_argument_module: EvalModuleId,
        first_argument_id: IrId,
        first_argument_span: Span,
        first_argument_value: Value,
        second_argument_module: EvalModuleId,
        second_argument_id: IrId,
        second_argument_value: Value,
    ) -> Self {
        Self {
            kind: EvalThunkKind::Apply2 {
                function: EvalNodeRef::new(function_module, function_id),
                function_span,
                function_value,
                first_argument: EvalNodeRef::new(first_argument_module, first_argument_id),
                first_argument_span,
                first_argument_value,
                second_argument: EvalNodeRef::new(second_argument_module, second_argument_id),
                second_argument_value,
            },
            cell: ThunkCell::new(),
        }
    }

    /// Creates a suspended static attribute selection thunk record.
    pub const fn select(
        module: EvalModuleId,
        select_id: IrId,
        receiver: Value,
        path: IrAttrPathId,
    ) -> Self {
        Self {
            kind: EvalThunkKind::Select {
                select: EvalNodeRef::new(module, select_id),
                receiver,
                path,
            },
            cell: ThunkCell::new(),
        }
    }

    /// Creates a suspended builtin attribute value thunk record.
    pub(crate) const fn builtin_attr(symbol: Symbol, builtin: Builtin) -> Self {
        Self {
            kind: EvalThunkKind::BuiltinAttr { symbol, builtin },
            cell: ThunkCell::new(),
        }
    }

    /// Returns the deferred work this thunk performs when forced.
    pub(crate) const fn kind(&self) -> &EvalThunkKind {
        &self.kind
    }

    /// Returns the lowered body this thunk will evaluate when forced, if any.
    pub const fn body(&self) -> Option<IrId> {
        match &self.kind {
            EvalThunkKind::Node { body, .. } => Some(body.id()),
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2 { .. }
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::BuiltinAttr { .. } => None,
        }
    }

    /// Returns the module-qualified lowered body this thunk will evaluate.
    pub const fn body_ref(&self) -> Option<EvalNodeRef> {
        match &self.kind {
            EvalThunkKind::Node { body, .. } => Some(*body),
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2 { .. }
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::BuiltinAttr { .. } => None,
        }
    }

    /// Returns the lexical environment captured when this thunk was allocated, if any.
    pub const fn env(&self) -> Option<&EvalEnv> {
        match &self.kind {
            EvalThunkKind::Node { env, .. } => Some(env),
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2 { .. }
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::BuiltinAttr { .. } => None,
        }
    }

    /// Returns the captured dynamic `with` environment, if any.
    pub const fn with_scope_env(&self) -> Option<&EvalWithEnv> {
        match &self.kind {
            EvalThunkKind::Node { with_env, .. } => Some(with_env),
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2 { .. }
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::BuiltinAttr { .. } => None,
        }
    }

    /// Returns the captured scoped-import global environment, if any.
    pub const fn scoped_global_env(&self) -> Option<&EvalScopedGlobalEnv> {
        match &self.kind {
            EvalThunkKind::Node { scoped_globals, .. } => Some(scoped_globals),
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2 { .. }
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::BuiltinAttr { .. } => None,
        }
    }

    /// Returns the serial state/result cell for this thunk.
    pub const fn cell(&self) -> &ThunkCell {
        &self.cell
    }
}
