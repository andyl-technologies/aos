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
            force_storage_mode: EvalThunkForceStorageMode::Serial,
            parallel_cell: None,
        }
    }

    /// Marks this node thunk as single-entry storage.
    ///
    /// Single-entry storage is admitted only after the C-8 frame-local
    /// analysis proves that the thunk is used once and cannot escape. It keeps
    /// the serial cell present for heap metadata compatibility, but the force
    /// path evaluates the body directly without publishing a cached result.
    pub(crate) fn into_single_entry(mut self) -> Self {
        self.force_storage_mode = EvalThunkForceStorageMode::SingleEntry;
        self.parallel_cell = None;
        self
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
            force_storage_mode: EvalThunkForceStorageMode::Serial,
            parallel_cell: None,
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
        second_argument_span: Span,
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
                second_argument_span,
                second_argument_value,
            },
            cell: ThunkCell::new(),
            force_storage_mode: EvalThunkForceStorageMode::Serial,
            parallel_cell: None,
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
            force_storage_mode: EvalThunkForceStorageMode::Serial,
            parallel_cell: None,
        }
    }

    /// Creates a suspended builtin attribute value thunk record.
    pub(crate) const fn builtin_attr(symbol: Symbol, builtin: Builtin) -> Self {
        Self {
            kind: EvalThunkKind::BuiltinAttr { symbol, builtin },
            cell: ThunkCell::new(),
            force_storage_mode: EvalThunkForceStorageMode::Serial,
            parallel_cell: None,
        }
    }

    /// Rebuilds a forced thunk record with the same deferred-work metadata.
    pub(crate) fn with_forced_cached_result_from(thunk: &Self, value: Value) -> Self {
        Self {
            kind: thunk.kind.clone(),
            cell: ThunkCell::forced(value),
            force_storage_mode: EvalThunkForceStorageMode::Serial,
            parallel_cell: None,
        }
    }

    /// Attaches an evaluator-native parallel payload cell to this thunk record.
    ///
    /// The current serial [`ThunkCell`] remains present for the existing
    /// tree-walk force path. The parallel payload cell is a storage-admission
    /// boundary for future scheduler wiring and starts in the suspended state.
    /// It is intentionally crate-internal while serial `ThunkCell` forcing
    /// remains authoritative and scheduler integration is incomplete.
    pub(crate) fn with_parallel_payload_cell(mut self, dropped_claim_error: TreeWalkError) -> Self {
        if self.force_storage_mode == EvalThunkForceStorageMode::Serial {
            self.force_storage_mode = EvalThunkForceStorageMode::SerialWithParallelPayload;
            self.parallel_cell = Some(Box::new(TreeWalkParallelThunkCell::new(dropped_claim_error)));
        }
        self
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

    /// Returns the currently attached force-storage mode.
    #[allow(dead_code)]
    pub(crate) const fn force_storage_mode(&self) -> EvalThunkForceStorageMode {
        self.force_storage_mode
    }

    /// Returns whether this thunk uses the single-entry direct force path.
    pub(crate) const fn is_single_entry_force_storage(&self) -> bool {
        matches!(
            self.force_storage_mode,
            EvalThunkForceStorageMode::SingleEntry
        )
    }

    /// Returns the evaluator-native parallel payload cell, if one is attached.
    ///
    /// This accessor is crate-internal so heap scanning, relocation, and future
    /// scheduler wiring can preserve the serial-cell authority boundary.
    pub(crate) fn parallel_payload_cell(&self) -> Option<&TreeWalkParallelThunkCell> {
        self.parallel_cell.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use crate::compile::IrId;
    use crate::eval::ThunkState;
    use crate::eval::thunk_cas::ParallelThunkWorkerId;
    use crate::eval::thunk_payload::TreeWalkParallelThunkWait;
    use crate::eval::tree_walk::TreeWalkErrorKind;
    use crate::syntax::Span;
    use crate::value::Value;

    use super::*;

    fn worker(raw: u64) -> ParallelThunkWorkerId {
        ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
    }

    fn tree_walk_error(raw: u32) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::DivisionByZero { id: IrId::new(raw) },
            Span::new(raw, raw.saturating_add(1)),
        )
    }

    fn ready_result(wait: TreeWalkParallelThunkWait<'_>) -> Result<Value, TreeWalkError> {
        match wait {
            TreeWalkParallelThunkWait::Ready(result) => result,
            TreeWalkParallelThunkWait::Claimed(_) => {
                panic!("expected ready tree-walk result, found claim guard");
            }
            TreeWalkParallelThunkWait::SelfCycle { owner } => {
                panic!("expected ready tree-walk result, found self-cycle owned by {owner:?}");
            }
        }
    }

    fn assert_serial_storage(thunk: &EvalThunk) {
        assert_eq!(
            thunk.force_storage_mode(),
            EvalThunkForceStorageMode::Serial
        );
        assert!(thunk.parallel_payload_cell().is_none());
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    }

    #[test]
    fn eval_thunk_default_constructors_use_serial_force_storage() {
        let thunk = EvalThunk::new(IrId::new(7));
        assert_serial_storage(&thunk);
        assert_eq!(thunk.body(), Some(IrId::new(7)));

        let apply = EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(1),
            Span::new(1, 2),
            Value::int(1),
            EvalModuleId::ROOT,
            IrId::new(2),
            Value::int(2),
        );
        assert_serial_storage(&apply);

        let apply2 = EvalThunk::apply2(
            EvalModuleId::ROOT,
            IrId::new(1),
            Span::new(1, 2),
            Value::int(1),
            EvalModuleId::ROOT,
            IrId::new(2),
            Span::new(2, 3),
            Value::int(2),
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(3, 4),
            Value::int(3),
        );
        assert_serial_storage(&apply2);

        let select = EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(4),
            Value::int(5),
            IrAttrPathId::new(0),
        );
        assert_serial_storage(&select);
    }

    #[test]
    fn eval_thunk_forced_cached_result_remains_serial_storage() {
        let thunk = EvalThunk::new(IrId::new(7)).with_parallel_payload_cell(tree_walk_error(99));
        let forced = EvalThunk::with_forced_cached_result_from(&thunk, Value::int(42));

        assert_eq!(
            forced.force_storage_mode(),
            EvalThunkForceStorageMode::Serial
        );
        assert!(forced.parallel_payload_cell().is_none());
        assert_eq!(
            forced
                .cell()
                .cached_value()
                .expect("forced serial cached value is readable")
                .expect("forced serial cached value is stored")
                .as_int(),
            Ok(42)
        );
        assert_eq!(forced.body(), Some(IrId::new(7)));
    }

    #[test]
    fn eval_thunk_single_entry_storage_skips_parallel_payload_cell() {
        let thunk = EvalThunk::new(IrId::new(7))
            .into_single_entry()
            .with_parallel_payload_cell(tree_walk_error(99));

        assert_eq!(
            thunk.force_storage_mode(),
            EvalThunkForceStorageMode::SingleEntry
        );
        assert!(thunk.parallel_payload_cell().is_none());
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(thunk.body(), Some(IrId::new(7)));
    }

    #[test]
    fn eval_thunk_parallel_payload_cell_preserves_metadata_and_replays_result() {
        let thunk = EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(11), EvalEnv::default())
            .with_parallel_payload_cell(tree_walk_error(99));

        assert_eq!(
            thunk.force_storage_mode(),
            EvalThunkForceStorageMode::SerialWithParallelPayload
        );
        assert_eq!(
            thunk.body_ref(),
            Some(EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(11)))
        );
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));

        let parallel = thunk
            .parallel_payload_cell()
            .expect("parallel payload cell is attached");
        let TreeWalkParallelThunkWait::Claimed(guard) = parallel
            .claim_or_wait_for_result(worker(1))
            .expect("parallel payload cell can be claimed")
        else {
            panic!("attached parallel payload cell should start suspended");
        };
        guard
            .publish_value(Value::int(89))
            .expect("parallel payload value publishes");

        assert_eq!(
            ready_result(
                parallel
                    .claim_or_wait_for_result(worker(2))
                    .expect("parallel payload value replays")
            )
            .expect("parallel payload result is Ok")
            .as_int(),
            Ok(89)
        );
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    }
}
