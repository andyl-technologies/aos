//! Constructors and accessors for [`EvalThunk`] suspended-work records.

use super::*;

impl EvalThunk {
    /// Rebuilds a thunk from collector-relocated storage components.
    pub(in crate::eval::heap) fn from_relocated_parts(
        kind: EvalThunkKind,
        dynamic_env: Option<EvalClosureDynamicEnv>,
        shared_cell: Arc<ThunkCell>,
        mode: EvalThunkForceStorageMode,
        parallel_cell: Option<Arc<TreeWalkParallelThunkCell>>,
    ) -> Option<Self> {
        let mode = match mode {
            EvalThunkForceStorageMode::Serial if parallel_cell.is_none() => {
                EvalThunkStorageExtensionMode::Serial
            }
            EvalThunkForceStorageMode::SingleEntry => {
                if parallel_cell.is_some() {
                    return None;
                }
                EvalThunkStorageExtensionMode::SingleEntry
            }
            EvalThunkForceStorageMode::SerialWithParallelPayload => {
                EvalThunkStorageExtensionMode::Parallel(parallel_cell?)
            }
            EvalThunkForceStorageMode::Serial => return None,
        };
        Some(Self {
            kind,
            cell: ThunkCell::new(),
            storage_extension: Some(Box::new(EvalThunkStorageExtension {
                shared_cell: Some(shared_cell),
                dynamic_env,
                mode,
            })),
        })
    }

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
        let storage_extension =
            EvalClosureDynamicEnv::new(with_env, scoped_globals).map(|dynamic_env| {
                Box::new(EvalThunkStorageExtension {
                    shared_cell: None,
                    dynamic_env: Some(dynamic_env),
                    mode: EvalThunkStorageExtensionMode::Serial,
                })
            });
        Self {
            kind: EvalThunkKind::Node {
                body: EvalNodeRef::new(module, body),
                env,
            },
            cell: ThunkCell::new(),
            storage_extension,
        }
    }

    /// Creates a forced thunk record whose deferred work has been released.
    ///
    /// This is the Tier-B capture-shedding replacement installed by
    /// [`EvalHeap::shed_forced_thunk_captures`](super::EvalHeap::shed_forced_thunk_captures)
    /// once a serial thunk publishes its WHNF result: the cell is already
    /// `Forced` with `result`, and the released kind carries no captured
    /// environments, so dropping the original record payload frees its closure
    /// graph. Only serial-storage thunks are shed, so the replacement never
    /// carries a parallel payload cell.
    pub(crate) fn released_forced(result: Value) -> Self {
        Self {
            kind: EvalThunkKind::Released,
            cell: ThunkCell::forced(result),
            storage_extension: None,
        }
    }

    /// Marks this node thunk as single-entry storage.
    ///
    /// Single-entry storage is admitted only after the C-8 frame-local
    /// analysis proves that the thunk is used once and cannot escape. It keeps
    /// the serial cell present for heap metadata compatibility, but the force
    /// path evaluates the body directly without publishing a cached result.
    pub(crate) fn into_single_entry(mut self) -> Self {
        match self.storage_extension.as_deref_mut() {
            Some(extension) => extension.mode = EvalThunkStorageExtensionMode::SingleEntry,
            None => {
                self.storage_extension = Some(Box::new(EvalThunkStorageExtension {
                    shared_cell: None,
                    dynamic_env: None,
                    mode: EvalThunkStorageExtensionMode::SingleEntry,
                }));
            }
        }
        self
    }

    /// Creates a suspended function-application thunk record.
    pub fn apply(
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
            storage_extension: None,
        }
    }

    /// Creates a suspended two-argument function-application thunk record.
    #[allow(clippy::too_many_arguments)]
    pub fn apply2(
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
            kind: EvalThunkKind::Apply2(Box::new(EvalApply2Thunk {
                function: EvalNodeRef::new(function_module, function_id),
                function_span,
                function_value,
                first_argument: EvalNodeRef::new(first_argument_module, first_argument_id),
                first_argument_span,
                first_argument_value,
                second_argument: EvalNodeRef::new(second_argument_module, second_argument_id),
                second_argument_span,
                second_argument_value,
            })),
            cell: ThunkCell::new(),
            storage_extension: None,
        }
    }

    /// Creates a suspended static attribute selection thunk record.
    pub fn select(
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
            storage_extension: None,
        }
    }

    /// Creates a suspended builtin attribute value thunk record.
    pub(crate) fn builtin_attr(symbol: Symbol, builtin: Builtin) -> Self {
        Self {
            kind: EvalThunkKind::BuiltinAttr {
                symbol,
                builtin: builtin.kind(),
            },
            cell: ThunkCell::new(),
            storage_extension: None,
        }
    }

    /// Rebuilds a forced thunk record with the same deferred-work metadata.
    pub(crate) fn with_forced_cached_result_from(thunk: &Self, value: Value) -> Self {
        let storage_extension = thunk.dynamic_env().cloned().map(|dynamic_env| {
            Box::new(EvalThunkStorageExtension {
                shared_cell: None,
                dynamic_env: Some(dynamic_env),
                mode: EvalThunkStorageExtensionMode::Serial,
            })
        });
        Self {
            kind: thunk.kind.clone(),
            cell: ThunkCell::forced(value),
            storage_extension,
        }
    }

    /// Attaches an evaluator-native parallel payload cell to this thunk record.
    ///
    /// The current serial [`ThunkCell`] remains present for the existing
    /// tree-walk force path. The parallel payload cell is a storage-admission
    /// boundary for future scheduler wiring and starts in the suspended state.
    /// It is intentionally crate-internal while serial `ThunkCell` forcing
    /// remains authoritative and scheduler integration is incomplete.
    ///
    /// `cycle_registry` binds the cell to the evaluator's shared cross-worker
    /// wait registry so waiters detect deadlock cycles before parking; all
    /// cells of one shared demand graph must share the same registry.
    pub(crate) fn with_parallel_payload_cell(
        mut self,
        dropped_claim_error: TreeWalkError,
        cycle_registry: Option<Arc<ParallelForceCycleRegistry>>,
    ) -> Self {
        let cell = || {
            EvalThunkStorageExtensionMode::Parallel(Arc::new(
                TreeWalkParallelThunkCell::with_cycle_registry(dropped_claim_error, cycle_registry),
            ))
        };
        match self.storage_extension.as_deref_mut() {
            Some(extension) if matches!(extension.mode, EvalThunkStorageExtensionMode::Serial) => {
                extension.mode = cell();
            }
            None => {
                self.storage_extension = Some(Box::new(EvalThunkStorageExtension {
                    shared_cell: None,
                    dynamic_env: None,
                    mode: cell(),
                }));
            }
            Some(_) => {}
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
            | EvalThunkKind::Apply2(_)
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::BuiltinAttr { .. }
            | EvalThunkKind::Released => None,
        }
    }

    /// Returns the module-qualified lowered body this thunk will evaluate.
    pub const fn body_ref(&self) -> Option<EvalNodeRef> {
        match &self.kind {
            EvalThunkKind::Node { body, .. } => Some(*body),
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2(_)
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::BuiltinAttr { .. }
            | EvalThunkKind::Released => None,
        }
    }

    /// Returns the source module whose lowered code this thunk evaluates.
    ///
    /// Unlike [`Self::body_ref`], this resolves the executing module for every
    /// source-backed kind: `Apply`/`Apply2` run the applied function's module,
    /// and `Select` runs the selecting expression's module. Builtin-attribute
    /// and released thunks have no source module and return `None`. This is the
    /// provenance used to attribute a force to prelude (`lib`/`stdenv`) versus
    /// package code for the `AOS_NIX_EVAL_STATS` prelude-force-share counters.
    pub const fn code_module(&self) -> Option<EvalModuleId> {
        match &self.kind {
            EvalThunkKind::Node { body, .. } => Some(body.module()),
            EvalThunkKind::Apply { function, .. } => Some(function.module()),
            EvalThunkKind::Apply2(apply) => Some(apply.function.module()),
            EvalThunkKind::Select { select, .. } => Some(select.module()),
            EvalThunkKind::BuiltinAttr { .. } | EvalThunkKind::Released => None,
        }
    }

    /// Returns the lexical environment captured when this thunk was allocated, if any.
    pub const fn env(&self) -> Option<&EvalEnv> {
        match &self.kind {
            EvalThunkKind::Node { env, .. } => Some(env),
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2(_)
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::BuiltinAttr { .. }
            | EvalThunkKind::Released => None,
        }
    }

    /// Replaces a suspended node thunk's lexical environment before publish.
    ///
    /// Returns `false` for synthetic thunks, which carry no lexical capture.
    pub(crate) fn replace_node_env(&mut self, replacement: EvalEnv) -> bool {
        let EvalThunkKind::Node { env, .. } = &mut self.kind else {
            return false;
        };
        *env = replacement;
        true
    }

    /// Returns the captured dynamic `with` environment, if any.
    pub const fn with_scope_env(&self) -> Option<&EvalWithEnv> {
        match &self.kind {
            EvalThunkKind::Node { .. } => Some(match self.dynamic_env() {
                Some(dynamic) => &dynamic.with_env,
                None => EvalWithEnv::empty_ref(),
            }),
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2(_)
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::BuiltinAttr { .. }
            | EvalThunkKind::Released => None,
        }
    }

    /// Returns the captured scoped-import global environment, if any.
    pub const fn scoped_global_env(&self) -> Option<&EvalScopedGlobalEnv> {
        match &self.kind {
            EvalThunkKind::Node { .. } => Some(match self.dynamic_env() {
                Some(dynamic) => &dynamic.scoped_globals,
                None => EvalScopedGlobalEnv::empty_ref(),
            }),
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2(_)
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::BuiltinAttr { .. }
            | EvalThunkKind::Released => None,
        }
    }

    /// Returns the rare non-empty dynamic capture attached to this thunk.
    pub(crate) const fn dynamic_env(&self) -> Option<&EvalClosureDynamicEnv> {
        match &self.storage_extension {
            Some(extension) => extension.dynamic_env.as_ref(),
            None => None,
        }
    }

    /// Returns the rare non-empty dynamic capture mutably.
    pub(in crate::eval::heap) fn dynamic_env_mut(&mut self) -> Option<&mut EvalClosureDynamicEnv> {
        self.storage_extension
            .as_deref_mut()
            .and_then(|extension| extension.dynamic_env.as_mut())
    }

    /// Returns the serial state/result cell for this thunk.
    pub fn cell(&self) -> &ThunkCell {
        self.storage_extension
            .as_deref()
            .and_then(|extension| extension.shared_cell.as_deref())
            .unwrap_or(&self.cell)
    }

    /// Promotes this thunk's serial cell to a shared `Arc`, returning the handle.
    ///
    /// Record-table and shared-backend placements call this at allocation so the
    /// deep-clones their force paths take share one cell; flat thunks stay inline
    /// and share through the record `Arc` instead. Idempotent on an already
    /// shared cell.
    pub(crate) fn share_cell(&mut self) -> Arc<ThunkCell> {
        if let Some(shared) = self
            .storage_extension
            .as_deref()
            .and_then(|extension| extension.shared_cell.as_ref())
        {
            return Arc::clone(shared);
        }

        let shared = Arc::new(std::mem::take(&mut self.cell));
        match self.storage_extension.as_deref_mut() {
            Some(extension) => extension.shared_cell = Some(Arc::clone(&shared)),
            None => {
                self.storage_extension = Some(Box::new(EvalThunkStorageExtension {
                    shared_cell: Some(Arc::clone(&shared)),
                    dynamic_env: None,
                    mode: EvalThunkStorageExtensionMode::Serial,
                }));
            }
        }
        shared
    }

    /// Returns whether two payload snapshots share the same force-state
    /// identity and storage sidecars.
    pub(crate) fn raw_eq(&self, other: &Self) -> bool {
        // Force-state identity is the cell's address: two records share force
        // state iff they resolve to the same `ThunkCell` — the same `Arc`
        // allocation for shared cells, or literally the same inline cell for a
        // record compared with itself. `std::ptr::eq` captures both uniformly
        // and matches the previous `Arc::ptr_eq` on the shared path.
        std::ptr::eq(self.cell(), other.cell())
            && match (&self.storage_extension, &other.storage_extension) {
                (None, None) => true,
                (Some(left), Some(right)) => match (&left.mode, &right.mode) {
                    (
                        EvalThunkStorageExtensionMode::Parallel(left),
                        EvalThunkStorageExtensionMode::Parallel(right),
                    ) => Arc::ptr_eq(left, right),
                    (
                        EvalThunkStorageExtensionMode::SingleEntry,
                        EvalThunkStorageExtensionMode::SingleEntry,
                    ) => true,
                    (
                        EvalThunkStorageExtensionMode::Serial,
                        EvalThunkStorageExtensionMode::Serial,
                    ) => true,
                    _ => false,
                },
                _ => false,
            }
    }

    /// Returns the force-state sidecar `Arc` clones made by [`Clone`].
    ///
    /// A shared serial cell and an attached parallel payload cell each cost one
    /// `Arc::clone` per record clone; an inline serial cell is deep-copied and
    /// costs none.
    pub(crate) fn state_arc_clone_count(&self) -> u64 {
        let serial = if self
            .storage_extension
            .as_deref()
            .is_some_and(|extension| extension.shared_cell.is_some())
        {
            1
        } else {
            0
        };
        let parallel = if matches!(
            self.storage_extension
                .as_deref()
                .map(|extension| &extension.mode),
            Some(EvalThunkStorageExtensionMode::Parallel(_))
        ) {
            1
        } else {
            0
        };
        serial + parallel
    }

    /// Returns the currently attached force-storage mode.
    #[allow(dead_code)]
    pub(crate) fn force_storage_mode(&self) -> EvalThunkForceStorageMode {
        match self.storage_extension.as_deref() {
            None => EvalThunkForceStorageMode::Serial,
            Some(EvalThunkStorageExtension {
                mode: EvalThunkStorageExtensionMode::Serial,
                ..
            }) => EvalThunkForceStorageMode::Serial,
            Some(EvalThunkStorageExtension {
                mode: EvalThunkStorageExtensionMode::SingleEntry,
                ..
            }) => EvalThunkForceStorageMode::SingleEntry,
            Some(EvalThunkStorageExtension {
                mode: EvalThunkStorageExtensionMode::Parallel(_),
                ..
            }) => EvalThunkForceStorageMode::SerialWithParallelPayload,
        }
    }

    /// Returns whether this thunk stores its force state only in the serial cell.
    ///
    /// This is the shed-eligibility predicate for Tier-B capture shedding:
    /// single-entry thunks re-evaluate their body on each force (no published
    /// result to stand in for the captures), and thunks with a parallel
    /// payload cell are shared across workers, so only plain serial-storage
    /// thunks qualify.
    pub(crate) fn has_serial_only_force_storage(&self) -> bool {
        match self.storage_extension.as_deref() {
            None => true,
            Some(extension) => matches!(extension.mode, EvalThunkStorageExtensionMode::Serial),
        }
    }

    /// Returns whether this thunk uses the single-entry direct force path.
    pub(crate) fn is_single_entry_force_storage(&self) -> bool {
        matches!(
            self.storage_extension
                .as_deref()
                .map(|extension| &extension.mode),
            Some(EvalThunkStorageExtensionMode::SingleEntry)
        )
    }

    /// Returns the evaluator-native parallel payload cell, if one is attached.
    ///
    /// This accessor is crate-internal so heap scanning, relocation, and future
    /// scheduler wiring can preserve the serial-cell authority boundary.
    pub(crate) fn parallel_payload_cell(&self) -> Option<&TreeWalkParallelThunkCell> {
        match self
            .storage_extension
            .as_deref()
            .map(|extension| &extension.mode)
        {
            Some(EvalThunkStorageExtensionMode::Parallel(cell)) => Some(cell),
            None
            | Some(EvalThunkStorageExtensionMode::Serial)
            | Some(EvalThunkStorageExtensionMode::SingleEntry) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::compile::IrId;
    use crate::eval::thunk_cas::ParallelThunkWorkerId;
    use crate::eval::thunk_payload::TreeWalkParallelThunkWait;
    use crate::eval::tree_walk::TreeWalkErrorKind;
    use crate::eval::{EvalWithScope, ThunkState};
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
    fn eval_thunk_omits_empty_dynamic_captures_and_preserves_nonempty_captures() {
        let empty = EvalThunk::new(IrId::new(7));
        assert!(matches!(empty.kind(), EvalThunkKind::Node { .. }));
        assert!(empty.dynamic_env().is_none());
        assert!(
            empty
                .with_scope_env()
                .expect("node thunks expose a with-scope capture")
                .scopes()
                .is_empty()
        );
        assert!(
            empty
                .scoped_global_env()
                .expect("node thunks expose a scoped-global capture")
                .scopes()
                .is_empty()
        );

        let with_scope = EvalWithScope::new(EvalModuleId::ROOT, IrId::new(8), Value::int(11));
        let dynamic = EvalThunk::with_captures(
            EvalModuleId::ROOT,
            IrId::new(7),
            EvalEnv::default(),
            vec![with_scope].into(),
            vec![Value::int(13)].into(),
        );
        assert!(matches!(dynamic.kind(), EvalThunkKind::Node { .. }));
        assert!(dynamic.dynamic_env().is_some());
        assert_eq!(
            dynamic
                .with_scope_env()
                .expect("node thunks expose a with-scope capture")
                .scopes()[0]
                .value()
                .as_int(),
            Ok(11)
        );
        assert_eq!(
            dynamic
                .scoped_global_env()
                .expect("node thunks expose a scoped-global capture")
                .scopes()[0]
                .as_int(),
            Ok(13)
        );
    }

    #[cfg(all(feature = "candidate_c_value", target_pointer_width = "64"))]
    #[test]
    fn candidate_c_common_closure_layout_stays_compact() {
        assert_eq!(std::mem::size_of::<EvalEnv>(), 6 * 8);
        assert_eq!(std::mem::size_of::<EvalThunk>(), 9 * 8);
        assert_eq!(std::mem::size_of::<EvalLambda>(), 9 * 8);
        assert_eq!(std::mem::size_of::<FlatClosurePayload>(), 10 * 8);
    }

    #[test]
    fn eval_thunk_forced_cached_result_remains_serial_storage() {
        let thunk =
            EvalThunk::new(IrId::new(7)).with_parallel_payload_cell(tree_walk_error(99), None);
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
            .with_parallel_payload_cell(tree_walk_error(99), None);

        assert_eq!(
            thunk.force_storage_mode(),
            EvalThunkForceStorageMode::SingleEntry
        );
        assert!(thunk.parallel_payload_cell().is_none());
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(thunk.body(), Some(IrId::new(7)));
    }

    /// The graph-shared heap payload types must be [`Send`] and [`Sync`] so a
    /// later parallel scheduler can force thunks in one shared demand graph.
    /// This covers every by-value payload behind [`HeapObjectValue`] plus the
    /// side-owned serial [`ThunkCell`] and parallel
    /// [`TreeWalkParallelThunkCell`] state held by an [`EvalThunk`].
    #[test]
    fn heap_payload_graph_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<EvalThunk>();
        assert_send_sync::<EvalThunkKind>();
        assert_send_sync::<EvalLambda>();
        assert_send_sync::<EvalPrimOp>();
        assert_send_sync::<EvalPrimOpArg>();
        assert_send_sync::<ThunkCell>();
        assert_send_sync::<TreeWalkParallelThunkCell>();
        assert_send_sync::<crate::eval::env::EvalFrame>();
        assert_send_sync::<EvalEnv>();
        assert_send_sync::<EvalWithEnv>();
        assert_send_sync::<EvalScopedGlobalEnv>();
        assert_send_sync::<HeapObjectValue>();
        assert_send_sync::<Arc<ThunkCell>>();
        assert_send_sync::<Arc<TreeWalkParallelThunkCell>>();
    }

    #[test]
    fn eval_thunk_parallel_payload_cell_preserves_metadata_and_replays_result() {
        let thunk = EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(11), EvalEnv::default())
            .with_parallel_payload_cell(tree_walk_error(99), None);

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
