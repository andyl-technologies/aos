//! Target-directed outer attr-path dispatcher ownership probe.
//!
//! The default-off dispatcher substitutes only the outer instantiation
//! attr-path loop. Root evaluation, formal-set auto-call, force, selection, and
//! final forcing remain synchronous semantic-oracle leaves. Between leaves the
//! current value is retained only in a transient evaluator root slot, while
//! controls contain value-free segment coordinates.

use super::*;

const ENABLE_ENV: &str = "AOS_NIX_WHOLE_DEMAND_DISPATCHER_PROBE";
const PACKED_ROOT_CENSUS_ENV: &str = "AOS_NIX_PACKED_ROOT_CENSUS";
const STORAGE_CAP_BYTES: usize = 64 * 1024;
static PACKED_ROOT_CENSUS_ORDINAL: AtomicU64 = AtomicU64::new(0);

/// One value-free continuation retained by the future dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WholeDemandControl {
    /// Evaluates the requested IR root.
    RootEval { segment: usize },
    /// Performs formal-set lambda auto-call for one segment.
    AutoCall { segment: usize },
    /// Forces the current receiver before selection.
    ForceReceiver { segment: usize },
    /// Selects an attribute from the current receiver.
    SelectAttrs { segment: usize },
    /// Selects a numeric list element from the current receiver.
    SelectList { segment: usize },
    /// Forces the selected terminal result.
    FinalForce { segment: usize },
}

/// Default-off ownership and coverage state for one whole demand.
#[derive(Debug, Default)]
pub(super) struct WholeDemandDispatcherRuntime {
    pub(super) active: bool,
    pub(super) suspended_loop_head: bool,
    pub(super) generic_oracle_depth: usize,
    pub(super) oracle_calls: u64,
    pub(super) proof_accepts: u64,
    pub(super) proof_declines: u64,
    pub(super) structural_proof_attempts: u64,
    pub(super) rooted_proof_attempts: u64,
    pub(super) max_control_depth: usize,
    pub(super) max_value_slots: usize,
    pub(super) control: Vec<WholeDemandControl>,
    pub(super) value_slots: Vec<usize>,
    pub(super) force_tokens: Vec<ForceLeaseToken>,
    pub(super) lambda_tokens: Vec<LambdaCallLeaseToken>,
    pub(super) import_tokens: Vec<ImportModuleLeaseToken>,
}

impl WholeDemandDispatcherRuntime {
    fn enabled() -> bool {
        std::env::var(ENABLE_ENV).is_ok_and(|value| value == "1")
    }

    pub(super) fn modeled_storage_bytes(&self) -> usize {
        self.control
            .capacity()
            .saturating_mul(std::mem::size_of::<WholeDemandControl>())
            .saturating_add(
                self.value_slots
                    .capacity()
                    .saturating_mul(std::mem::size_of::<usize>()),
            )
            .saturating_add(
                self.force_tokens
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ForceLeaseToken>()),
            )
            .saturating_add(
                self.lambda_tokens
                    .capacity()
                    .saturating_mul(std::mem::size_of::<LambdaCallLeaseToken>()),
            )
            .saturating_add(
                self.import_tokens
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ImportModuleLeaseToken>()),
            )
    }

    pub(super) fn ownership_matches(
        &self,
        force: &[ActiveForceLease],
        lambda: &[ActiveLambdaCallLease],
        import: &[ActiveImportModuleLease],
    ) -> bool {
        self.force_tokens
            .iter()
            .copied()
            .eq(force.iter().map(|lease| lease.token))
            && self
                .lambda_tokens
                .iter()
                .copied()
                .eq(lambda.iter().map(|lease| lease.token))
            && self
                .import_tokens
                .iter()
                .copied()
                .eq(import.iter().map(|lease| lease.token))
    }

    pub(super) fn loop_head_structure_matches(&self, transient_roots: usize) -> bool {
        self.active
            && self.suspended_loop_head
            && self.generic_oracle_depth == 0
            && self.control.is_empty()
            && self.value_slots.iter().all(|slot| *slot < transient_roots)
            && self.value_slots.windows(2).all(|slots| slots[0] < slots[1])
    }
}

impl TreeWalk {
    /// Opens the target-directed outer attr-path dispatcher boundary.
    ///
    /// # Errors
    ///
    /// Returns an allocation diagnostic when the value-free control stack
    /// cannot reserve its initial oracle continuation.
    pub(super) fn begin_whole_demand_dispatcher_probe(
        &mut self,
        root: IrId,
        _attr_path_len: usize,
    ) -> Result<bool, TreeWalkError> {
        if !WholeDemandDispatcherRuntime::enabled() {
            return Ok(false);
        }
        let runtime = &mut self.whole_demand_dispatcher;
        if runtime.active || self.shared.is_some() {
            return Ok(false);
        }
        runtime.control.try_reserve(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed { id: root, len: 1 },
                Span::default(),
            )
        })?;
        runtime.active = true;
        runtime.suspended_loop_head = true;
        self.note_whole_demand_loop_head(true);
        Ok(true)
    }

    /// Marks entry into one synchronous attr-path semantic leaf.
    fn enter_whole_demand_oracle(&mut self, control: WholeDemandControl) {
        let runtime = &mut self.whole_demand_dispatcher;
        if !runtime.active {
            return;
        }
        runtime.suspended_loop_head = false;
        runtime.generic_oracle_depth = runtime.generic_oracle_depth.saturating_add(1);
        runtime.oracle_calls = runtime.oracle_calls.saturating_add(1);
        runtime.control.push(control);
        runtime.max_control_depth = runtime.max_control_depth.max(runtime.control.len());
    }

    /// Stores one leaf result in the dispatcher slot and proves its loop head.
    fn finish_whole_demand_oracle_leaf(
        &mut self,
        result: &mut Result<Value, TreeWalkError>,
        value_slot: Option<usize>,
    ) {
        if !self.whole_demand_dispatcher.active {
            return;
        }
        self.whole_demand_dispatcher.generic_oracle_depth = self
            .whole_demand_dispatcher
            .generic_oracle_depth
            .saturating_sub(1);
        if self.whole_demand_dispatcher.generic_oracle_depth != 0 {
            return;
        }
        if let Ok(value) = result.as_mut() {
            let slot = match value_slot {
                Some(slot) => {
                    if let Some(root) = self.transient_value_stack_roots.get_mut(slot) {
                        *root = *value;
                    }
                    slot
                }
                None => {
                    let slot = self.transient_value_stack_roots.len();
                    self.transient_value_stack_roots.push(*value);
                    self.whole_demand_dispatcher.value_slots.push(slot);
                    slot
                }
            };
            self.whole_demand_dispatcher.max_value_slots = self
                .whole_demand_dispatcher
                .max_value_slots
                .max(self.whole_demand_dispatcher.value_slots.len());
            debug_assert!(
                self.transient_value_stack_roots
                    .get(slot)
                    .is_some_and(|root| root.raw_eq(*value))
            );
            *value = Value::null();
        }
        self.whole_demand_dispatcher.control.pop();
        self.whole_demand_dispatcher.suspended_loop_head = true;
        self.note_whole_demand_loop_head(result.is_ok());
    }

    /// Reads the current value back from its relocation-aware transient slot.
    fn whole_demand_slot_value(
        &self,
        id: IrId,
        span: Span,
        slot: usize,
    ) -> Result<Value, TreeWalkError> {
        self.transient_value_stack_roots
            .get(slot)
            .copied()
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })
    }

    /// Reads a dispatcher slot and closes the active session on invariant failure.
    fn whole_demand_slot_value_or_cleanup(
        &mut self,
        id: IrId,
        span: Span,
        slot: usize,
        base: usize,
    ) -> Result<Value, TreeWalkError> {
        match self.whole_demand_slot_value(id, span, slot) {
            Ok(value) => Ok(value),
            Err(error) => {
                let mut result = Err(error);
                self.finish_whole_demand_dispatcher(&mut result, base);
                result
            }
        }
    }

    /// Runs one FinalForce attempt from the relocation-aware dispatcher slot.
    ///
    /// Keeping the copied subject inside this non-inlined semantic leaf means
    /// the suspended caller owns no heap value outside explicit root storage
    /// after an internal unwind returns.
    #[inline(never)]
    fn run_rooted_final_force_attempt(
        &mut self,
        id: IrId,
        span: Span,
        slot: usize,
    ) -> Result<Value, TreeWalkError> {
        let subject = self.whole_demand_slot_value(id, span, slot)?;
        self.force_node_result(id, span, subject)
    }

    /// Closes the dispatcher after copying its terminal rooted value.
    fn finish_whole_demand_dispatcher(
        &mut self,
        result: &mut Result<Value, TreeWalkError>,
        base: usize,
    ) {
        if let (Ok(value), Some(slot)) = (
            result.as_mut(),
            self.whole_demand_dispatcher.value_slots.last().copied(),
        ) && let Some(relocated) = self.transient_value_stack_roots.get(slot).copied()
        {
            *value = relocated;
        }
        self.transient_value_stack_roots.truncate(base);
        self.whole_demand_dispatcher.value_slots.clear();
        self.whole_demand_dispatcher.control.clear();
        self.whole_demand_dispatcher.active = false;
        self.whole_demand_dispatcher.suspended_loop_head = false;
    }

    /// Runs the outer attr-path driver with every semantic operation as a leaf.
    pub(super) fn eval_instantiation_attr_path_dispatcher(
        &mut self,
        id: IrId,
        attr_path: &[Vec<u8>],
    ) -> Result<Value, TreeWalkError> {
        let base = self.transient_value_stack_roots.len();
        let span = match self.node(id) {
            Ok(node) => node.span,
            Err(error) => {
                let mut result = Err(error);
                self.finish_whole_demand_dispatcher(&mut result, base);
                return result;
            }
        };
        self.enter_whole_demand_oracle(WholeDemandControl::RootEval { segment: 0 });
        let mut result = self.eval_root();
        self.finish_whole_demand_oracle_leaf(&mut result, None);
        if result.is_err() {
            self.finish_whole_demand_dispatcher(&mut result, base);
            return result;
        }
        let slot = base;
        if attr_path.is_empty() {
            let current = self.whole_demand_slot_value_or_cleanup(id, span, slot, base)?;
            let mut result = Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "non-empty attr path",
                    actual: current.tag(),
                },
                span,
            ));
            self.finish_whole_demand_dispatcher(&mut result, base);
            return result;
        }

        for (segment_index, segment) in attr_path.iter().enumerate() {
            let current = self.whole_demand_slot_value_or_cleanup(id, span, slot, base)?;
            self.enter_whole_demand_oracle(WholeDemandControl::AutoCall {
                segment: segment_index,
            });
            let mut result = self.auto_call_formal_set_lambda(id, span, current);
            self.finish_whole_demand_oracle_leaf(&mut result, Some(slot));
            if result.is_err() {
                self.finish_whole_demand_dispatcher(&mut result, base);
                return result;
            }

            let current = self.whole_demand_slot_value_or_cleanup(id, span, slot, base)?;
            self.enter_whole_demand_oracle(WholeDemandControl::ForceReceiver {
                segment: segment_index,
            });
            let mut result = self.force_value(id, span, current);
            self.finish_whole_demand_oracle_leaf(&mut result, Some(slot));
            if result.is_err() {
                self.finish_whole_demand_dispatcher(&mut result, base);
                return result;
            }

            let control = if attr_path_segment_is_list_index(segment) {
                WholeDemandControl::SelectList {
                    segment: segment_index,
                }
            } else {
                WholeDemandControl::SelectAttrs {
                    segment: segment_index,
                }
            };
            let current = self.whole_demand_slot_value_or_cleanup(id, span, slot, base)?;
            self.enter_whole_demand_oracle(control);
            let mut result =
                self.eval_instantiation_attr_segment_selection(id, span, current, segment);
            self.finish_whole_demand_oracle_leaf(&mut result, Some(slot));
            if result.is_err() {
                self.finish_whole_demand_dispatcher(&mut result, base);
                return result;
            }
        }

        let final_force_control = WholeDemandControl::FinalForce {
            segment: attr_path.len(),
        };
        self.enter_whole_demand_oracle(final_force_control);
        let mut result = self.run_rooted_final_force_attempt(id, span, slot);
        self.finish_whole_demand_oracle_leaf(&mut result, Some(slot));
        self.finish_whole_demand_dispatcher(&mut result, base);
        result
    }

    fn note_whole_demand_loop_head(&mut self, _succeeded: bool) {
        let proof_succeeded = if self.whole_demand_dispatcher.value_slots.is_empty() {
            self.whole_demand_dispatcher.structural_proof_attempts = self
                .whole_demand_dispatcher
                .structural_proof_attempts
                .saturating_add(1);
            let structural = self
                .dispatcher_collection_poll_structure_preflight()
                .is_ok();
            if structural && std::env::var_os(PACKED_ROOT_CENSUS_ENV).is_some() {
                if let Ok(guard) = self.dispatcher_collection_poll_preflight() {
                    emit_packed_root_census(guard.roots());
                }
            }
            structural
        } else {
            self.whole_demand_dispatcher.rooted_proof_attempts = self
                .whole_demand_dispatcher
                .rooted_proof_attempts
                .saturating_add(1);
            match self.dispatcher_collection_poll_preflight() {
                Ok(guard) => {
                    emit_packed_root_census(guard.roots());
                    true
                }
                Err(_) => false,
            }
        };
        if proof_succeeded
            && self.whole_demand_dispatcher.modeled_storage_bytes() <= STORAGE_CAP_BYTES
        {
            self.whole_demand_dispatcher.proof_accepts =
                self.whole_demand_dispatcher.proof_accepts.saturating_add(1);
        } else {
            self.whole_demand_dispatcher.proof_declines = self
                .whole_demand_dispatcher
                .proof_declines
                .saturating_add(1);
        }
    }

    /// Emits coverage, ownership, and modeled-storage results.
    pub(super) fn emit_whole_demand_dispatcher_probe_report(&self) {
        let runtime = &self.whole_demand_dispatcher;
        if runtime.oracle_calls == 0 {
            return;
        }
        eprintln!(
            "aos_nix_whole_demand_dispatcher_probe \
             oracle_calls={} proof_accepts={} proof_declines={} \
             structural_proof_attempts={} rooted_proof_attempts={} \
             max_control_depth={} max_value_slots={} modeled_storage_bytes={} \
             storage_cap_bytes={} execution_substitution=attr_path_outer_loop \
             collection=false",
            runtime.oracle_calls,
            runtime.proof_accepts,
            runtime.proof_declines,
            runtime.structural_proof_attempts,
            runtime.rooted_proof_attempts,
            runtime.max_control_depth,
            runtime.max_value_slots,
            runtime.modeled_storage_bytes(),
            STORAGE_CAP_BYTES,
        );
    }
}

fn emit_packed_root_census(roots: &EvalRootSet) {
    const NAMES: [&str; 22] = [
        "value_stack",
        "frame",
        "flat_capture",
        "flat_owner",
        "suspended_frame",
        "suspended_flat_capture",
        "suspended_flat_owner",
        "with",
        "suspended_with",
        "scoped_global",
        "suspended_scoped_global",
        "force",
        "stg_value",
        "stg_argument",
        "node_work",
        "typed_work",
        "typed_head",
        "primop_argument",
        "tree_walk_primop_argument",
        "interned",
        "import_cache",
        "stack_map",
    ];
    let mut counts = [0usize; NAMES.len()];
    for root in roots.roots() {
        let bucket = match root.source() {
            EvalRootSource::ValueStack { .. } => 0,
            EvalRootSource::TreeWalkFrame { .. } => 1,
            EvalRootSource::TreeWalkFlatCapture { .. } => 2,
            EvalRootSource::TreeWalkFlatCaptureOwner => 3,
            EvalRootSource::SuspendedTreeWalkFrame { .. } => 4,
            EvalRootSource::SuspendedTreeWalkFlatCapture { .. } => 5,
            EvalRootSource::SuspendedTreeWalkFlatCaptureOwner { .. } => 6,
            EvalRootSource::WithScope { .. } => 7,
            EvalRootSource::SuspendedWithScope { .. } => 8,
            EvalRootSource::ScopedGlobal { .. } => 9,
            EvalRootSource::SuspendedScopedGlobal { .. } => 10,
            EvalRootSource::ForceContinuation { .. } => 11,
            EvalRootSource::StgValue { .. } => 12,
            EvalRootSource::StgArgument { .. } => 13,
            EvalRootSource::DetachedNodeThunkWork { .. } => 14,
            EvalRootSource::DetachedTypedThunkWork { .. } => 15,
            EvalRootSource::DetachedTypedThunkHead { .. } => 16,
            EvalRootSource::PrimopArgument { .. } => 17,
            EvalRootSource::TreeWalkPrimopArgument { .. } => 18,
            EvalRootSource::Interned { .. } => 19,
            EvalRootSource::ImportCache { .. } => 20,
            EvalRootSource::StackMap { .. } => 21,
        };
        counts[bucket] = counts[bucket].saturating_add(1);
    }
    let ordinal = PACKED_ROOT_CENSUS_ORDINAL.fetch_add(1, Ordering::Relaxed);
    let rss = ProcessResidentMemorySample::current()
        .ok()
        .flatten()
        .map_or(0, ProcessResidentMemorySample::resident_bytes);
    let mut populations = String::new();
    for (name, count) in NAMES.into_iter().zip(counts) {
        if count != 0 {
            populations.push_str(&format!(" {name}={count}"));
        }
    }
    eprintln!(
        "aos_nix_packed_root_census ordinal={ordinal} rss_bytes={rss} roots={}{}",
        roots.len(),
        populations
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::syntax::parse_str;

    fn lower(source: &str) -> Ir {
        nix_lower(resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("source lowers")
    }

    fn run_dispatcher(source: &str, attr_path: &[&[u8]]) -> Result<Value, TreeWalkError> {
        let ir = lower(source);
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.whole_demand_dispatcher.active = true;
        evaluator.whole_demand_dispatcher.suspended_loop_head = true;
        let path = attr_path
            .iter()
            .map(|segment| segment.to_vec())
            .collect::<Vec<_>>();
        evaluator.eval_instantiation_attr_path_dispatcher(ir.root, &path)
    }

    #[test]
    fn ownership_bijection_accepts_matching_tokens() {
        let mut runtime = WholeDemandDispatcherRuntime::default();
        let force = ActiveForceLease {
            token: ForceLeaseToken::new(0, 7),
            id: IrId::new(0),
            span: Span::default(),
            source_root_index: 0,
            result_root_index: 1,
        };
        runtime.force_tokens.push(force.token);
        assert!(runtime.ownership_matches(&[force], &[], &[]));
    }

    #[test]
    fn ownership_bijection_rejects_stale_or_missing_tokens() {
        let mut runtime = WholeDemandDispatcherRuntime::default();
        runtime.force_tokens.push(ForceLeaseToken::new(0, 8));
        let active = ActiveForceLease {
            token: ForceLeaseToken::new(0, 7),
            id: IrId::new(0),
            span: Span::default(),
            source_root_index: 0,
            result_root_index: 1,
        };
        assert!(!runtime.ownership_matches(&[active], &[], &[]));
        assert!(!WholeDemandDispatcherRuntime::default().ownership_matches(&[active], &[], &[]));
    }

    #[test]
    fn ownership_bijection_covers_lambda_and_import_order() {
        let lambda_a = ActiveLambdaCallLease {
            token: LambdaCallLeaseToken::new(0, 11),
            module: EvalModuleId::ROOT,
            saved_module: EvalModuleId::ROOT,
            suspended_env_depth: 0,
            saved_call_depth: 0,
        };
        let lambda_b = ActiveLambdaCallLease {
            token: LambdaCallLeaseToken::new(1, 12),
            module: EvalModuleId::ROOT,
            saved_module: EvalModuleId::ROOT,
            suspended_env_depth: 1,
            saved_call_depth: 1,
        };
        let import = ActiveImportModuleLease {
            token: ImportModuleLeaseToken::new(0, 13),
            module: EvalModuleId::ROOT,
            saved_module: EvalModuleId::ROOT,
            suspended_env_depth: 2,
        };
        let mut runtime = WholeDemandDispatcherRuntime::default();
        runtime
            .lambda_tokens
            .extend([lambda_a.token, lambda_b.token]);
        runtime.import_tokens.push(import.token);
        assert!(runtime.ownership_matches(&[], &[lambda_a, lambda_b], &[import]));

        runtime.lambda_tokens.swap(0, 1);
        assert!(!runtime.ownership_matches(&[], &[lambda_a, lambda_b], &[import]));
        runtime.lambda_tokens.clear();
        assert!(!runtime.ownership_matches(&[], &[lambda_a, lambda_b], &[import]));
        runtime
            .lambda_tokens
            .extend([lambda_a.token, lambda_b.token]);
        runtime.import_tokens[0] = ImportModuleLeaseToken::new(0, 14);
        assert!(!runtime.ownership_matches(&[], &[lambda_a, lambda_b], &[import]));
        runtime.import_tokens.clear();
        assert!(!runtime.ownership_matches(&[], &[lambda_a, lambda_b], &[import]));
    }

    #[test]
    fn loop_head_requires_valid_strictly_ordered_value_slots() {
        let mut runtime = WholeDemandDispatcherRuntime {
            active: true,
            suspended_loop_head: true,
            ..WholeDemandDispatcherRuntime::default()
        };
        runtime.value_slots.extend([2, 4]);
        assert!(runtime.loop_head_structure_matches(5));
        runtime.value_slots.push(4);
        assert!(!runtime.loop_head_structure_matches(5));
        runtime.value_slots.pop();
        runtime.value_slots.push(5);
        assert!(!runtime.loop_head_structure_matches(5));
        runtime.value_slots.pop();
        runtime.generic_oracle_depth = 1;
        assert!(!runtime.loop_head_structure_matches(5));
    }

    #[test]
    fn modeled_storage_stays_below_the_strict_cap() {
        let mut runtime = WholeDemandDispatcherRuntime::default();
        runtime.control.reserve(400);
        runtime.value_slots.reserve(400);
        runtime.force_tokens.reserve(109);
        runtime.lambda_tokens.reserve(102);
        runtime.import_tokens.reserve(151);
        assert!(runtime.modeled_storage_bytes() < STORAGE_CAP_BYTES);
    }

    #[test]
    fn dispatcher_selects_nested_attrs_and_forces_terminal_value() {
        let value = run_dispatcher("{ a = { b = 42; }; }", &[b"a", b"b"]).expect("attrs select");
        assert_eq!(value.as_int().expect("integer result"), 42);
    }

    #[test]
    fn dispatcher_selects_list_index_segment() {
        let value = run_dispatcher("{ a = [ 10 20 ]; }", &[b"a", b"1"]).expect("list select");
        assert_eq!(value.as_int().expect("integer result"), 20);
    }

    #[test]
    fn dispatcher_preserves_missing_attribute_error() {
        let error = run_dispatcher("{ a = 1; }", &[b"missing"]).expect_err("missing attr");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::MissingAttribute { .. }
        ));
    }

    #[test]
    fn dispatcher_preserves_receiver_type_error() {
        let error = run_dispatcher("{ a = 1; }", &[b"a", b"b"]).expect_err("type mismatch");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "attrs",
                ..
            }
        ));
    }

    #[test]
    fn dispatcher_preserves_formal_set_error() {
        let error = run_dispatcher("{ required }: { result = required; }", &[b"result"])
            .expect_err("required formal is absent");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::MissingFormalAttribute { .. }
        ));
    }

    #[test]
    fn dispatcher_reads_relocated_value_from_transient_slot() {
        let ir = lower("null");
        let mut evaluator = TreeWalk::new(&ir);
        let original = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(ir.root))
            .expect("original thunk allocates");
        let relocated = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(ir.root))
            .expect("relocated thunk allocates");
        let slot = evaluator.transient_value_stack_roots.len();
        evaluator.transient_value_stack_roots.push(original);
        evaluator.transient_value_stack_roots[slot] = relocated;

        let readback = evaluator
            .whole_demand_slot_value(ir.root, Span::default(), slot)
            .expect("slot remains present");

        assert!(readback.raw_eq(relocated));
        assert!(!readback.raw_eq(original));
    }

    #[test]
    fn dispatcher_root_bijection_reads_relocated_transient_slot() {
        let ir = lower("null");
        let mut evaluator = TreeWalk::new(&ir);
        let original = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(ir.root))
            .expect("original thunk allocates");
        let relocated = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(ir.root))
            .expect("relocated thunk allocates");
        evaluator.transient_value_stack_roots.push(original);
        evaluator.transient_value_stack_roots[0] = relocated;
        evaluator.whole_demand_dispatcher.active = true;
        evaluator.whole_demand_dispatcher.suspended_loop_head = true;
        evaluator.whole_demand_dispatcher.value_slots.push(0);

        let guard = evaluator
            .dispatcher_collection_poll_preflight()
            .expect("relocated transient root has a bijective writeback slot");

        assert_eq!(guard.root_count(), 1);
        assert_eq!(guard.into_roots().len(), 1);
    }

    #[test]
    fn loop_head_proof_materializes_roots_only_when_values_are_live() {
        let ir = lower("null");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.whole_demand_dispatcher.active = true;
        evaluator.whole_demand_dispatcher.suspended_loop_head = true;

        evaluator.note_whole_demand_loop_head(true);
        assert_eq!(
            evaluator.whole_demand_dispatcher.structural_proof_attempts,
            1
        );
        assert_eq!(evaluator.whole_demand_dispatcher.rooted_proof_attempts, 0);

        let value = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(ir.root))
            .expect("rooted candidate allocates");
        evaluator.transient_value_stack_roots.push(value);
        evaluator.whole_demand_dispatcher.value_slots.push(0);
        evaluator.note_whole_demand_loop_head(true);

        assert_eq!(
            evaluator.whole_demand_dispatcher.structural_proof_attempts,
            1
        );
        assert_eq!(evaluator.whole_demand_dispatcher.rooted_proof_attempts, 1);
        assert_eq!(evaluator.whole_demand_dispatcher.proof_accepts, 2);
        assert_eq!(evaluator.whole_demand_dispatcher.proof_declines, 0);
    }

    #[test]
    fn missing_dispatcher_slot_closes_the_active_session() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.whole_demand_dispatcher.active = true;
        evaluator.whole_demand_dispatcher.value_slots.push(0);

        let error = evaluator
            .whole_demand_slot_value_or_cleanup(ir.root, Span::default(), 0, 0)
            .expect_err("the missing slot is an invariant failure");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::SafepointRootStackLengthOverflow { .. }
        ));
        assert!(!evaluator.whole_demand_dispatcher.active);
        assert!(evaluator.whole_demand_dispatcher.value_slots.is_empty());
    }
}
