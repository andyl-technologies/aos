//! Target-directed outer attr-path dispatcher ownership probe.
//!
//! The default-off dispatcher substitutes only the outer instantiation
//! attr-path loop. Root evaluation, formal-set auto-call, force, selection, and
//! final forcing remain synchronous semantic-oracle leaves. Between leaves the
//! current value is retained only in a transient evaluator root slot, while
//! controls contain value-free segment coordinates.
//! `AOS_NIX_WHOLE_DEMAND_CORRIDOR_CENSUS=0` leaves identified PMU windows
//! active while disabling every mixed-corridor census allocation, counter,
//! phase cursor, and census report. The census remains enabled by default.

use super::*;

const ENABLE_ENV: &str = "AOS_NIX_WHOLE_DEMAND_DISPATCHER_PROBE";
const CENSUS_ENV: &str = "AOS_NIX_WHOLE_DEMAND_CORRIDOR_CENSUS";
const PACKED_ROOT_CENSUS_ENV: &str = "AOS_NIX_PACKED_ROOT_CENSUS";
const FINAL_FORCE_RESUME_ORDINAL_ENV: &str = "AOS_NIX_FINAL_FORCE_RESUME_ORDINAL";
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

impl WholeDemandControl {
    const fn kind(self) -> &'static str {
        match self {
            Self::RootEval { .. } => "root_eval",
            Self::AutoCall { .. } => "auto_call",
            Self::ForceReceiver { .. } => "force_receiver",
            Self::SelectAttrs { .. } => "select_attrs",
            Self::SelectList { .. } => "select_list",
            Self::FinalForce { .. } => "final_force",
        }
    }

    const fn segment(self) -> usize {
        match self {
            Self::RootEval { segment }
            | Self::AutoCall { segment }
            | Self::ForceReceiver { segment }
            | Self::SelectAttrs { segment }
            | Self::SelectList { segment }
            | Self::FinalForce { segment } => segment,
        }
    }
}

/// Hidden completion count for one exact semantic leaf coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HiddenCompletionAttribution {
    control: WholeDemandControl,
    completions: u64,
}

/// Explicit state of the bounded FinalForce suspension experiment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FinalForceResumeState {
    /// No selected completion is waiting to return to the dispatcher.
    #[default]
    Running,
    /// The selected completion awaits the next successful thunk publication.
    PublicationRequested { ordinal: u64 },
    /// A committed thunk publication requested an error-channel unwind.
    UnwindRequested { ordinal: u64 },
    /// The unwind reached the rooted dispatcher loop head.
    Suspended { ordinal: u64 },
}

/// Observable-effect cursor for one replayable FinalForce attempt.
#[cfg(feature = "collection_poll_probe")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FinalForceEffectCursor {
    ifd_realizations: u64,
    trace_events: usize,
    warning_events: usize,
    impure_input_events: usize,
    impure_input_complete: bool,
    text_store_realizations: usize,
    source_store_realizations: usize,
    import_cache_entries: usize,
    known_derivations: usize,
    memo_events: u64,
}

#[cfg(feature = "collection_poll_probe")]
impl FinalForceEffectCursor {
    /// Returns the number of independently changed effect classes.
    fn changed_classes(self, other: Self) -> usize {
        usize::from(self.ifd_realizations != other.ifd_realizations)
            .saturating_add(usize::from(self.trace_events != other.trace_events))
            .saturating_add(usize::from(self.warning_events != other.warning_events))
            .saturating_add(usize::from(
                self.impure_input_events != other.impure_input_events,
            ))
            .saturating_add(usize::from(
                self.impure_input_complete != other.impure_input_complete,
            ))
            .saturating_add(usize::from(
                self.text_store_realizations != other.text_store_realizations,
            ))
            .saturating_add(usize::from(
                self.source_store_realizations != other.source_store_realizations,
            ))
            .saturating_add(usize::from(
                self.import_cache_entries != other.import_cache_entries,
            ))
            .saturating_add(usize::from(
                self.known_derivations != other.known_derivations,
            ))
            .saturating_add(usize::from(self.memo_events != other.memo_events))
    }
}

/// Default-off ownership and coverage state for one whole demand.
#[derive(Debug, Default)]
pub(super) struct WholeDemandDispatcherRuntime {
    pub(super) active: bool,
    pub(super) suspended_loop_head: bool,
    pub(super) generic_oracle_depth: usize,
    pub(super) pending_completions: u64,
    pub(super) pending_hidden_completions: u64,
    pub(super) completions: u64,
    pub(super) hidden_completions: u64,
    pub(super) safe_loop_head_completions: u64,
    pub(super) returned_loop_head_completions: u64,
    pub(super) abandoned_completions: u64,
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
    hidden_attribution: Vec<HiddenCompletionAttribution>,
    final_force_resume_ordinal: Option<u64>,
    final_force_resume_state: FinalForceResumeState,
    final_force_resume_suspensions: u64,
    final_force_resume_resumptions: u64,
    final_force_resume_declines: u64,
    final_force_resume_publish_site: Option<IrId>,
    final_force_resume_publish_depth: usize,
    final_force_resume_publish_shape: Option<&'static str>,
    final_force_resume_publish_lag: u64,
    #[cfg(feature = "collection_poll_probe")]
    final_force_effect_epoch: Option<FinalForceEffectCursor>,
    #[cfg(feature = "collection_poll_probe")]
    final_force_effect_checks: u64,
    #[cfg(feature = "collection_poll_probe")]
    final_force_effect_clean: u64,
    #[cfg(feature = "collection_poll_probe")]
    final_force_effect_dirty: u64,
    #[cfg(feature = "collection_poll_probe")]
    final_force_effect_last_changed_classes: usize,
    pub(super) corridor_census: super::whole_demand_corridor_census::WholeDemandCorridorCensus,
    speed_pmu_windows: Option<super::demand_epoch_probe::DemandWindowController>,
}

impl WholeDemandDispatcherRuntime {
    /// Returns whether the selected portal is unwinding to its rooted loop head.
    pub(super) const fn final_force_portal_unwind_requested(&self) -> bool {
        matches!(
            self.final_force_resume_state,
            FinalForceResumeState::UnwindRequested { .. }
        )
    }

    fn enabled() -> bool {
        std::env::var(ENABLE_ENV).is_ok_and(|value| value == "1")
    }

    fn census_enabled() -> bool {
        Self::census_enabled_for(std::env::var_os(CENSUS_ENV).as_deref())
    }

    fn census_enabled_for(value: Option<&std::ffi::OsStr>) -> bool {
        value != Some(std::ffi::OsStr::new("0"))
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
            .saturating_add(
                self.hidden_attribution
                    .capacity()
                    .saturating_mul(std::mem::size_of::<HiddenCompletionAttribution>()),
            )
            .saturating_add(self.corridor_census.modeled_storage_bytes())
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

    fn record_hidden_completion(&mut self, control: WholeDemandControl) {
        if let Some(attribution) = self
            .hidden_attribution
            .iter_mut()
            .find(|attribution| attribution.control == control)
        {
            attribution.completions = attribution.completions.saturating_add(1);
        } else {
            self.hidden_attribution.push(HiddenCompletionAttribution {
                control,
                completions: 1,
            });
        }
    }

    fn attributed_hidden_completions(&self) -> u64 {
        self.hidden_attribution
            .iter()
            .map(|attribution| attribution.completions)
            .sum()
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
        attr_path_len: usize,
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
        runtime
            .hidden_attribution
            .try_reserve(attr_path_len.saturating_mul(3).saturating_add(2))
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: root,
                        len: attr_path_len.saturating_mul(3).saturating_add(2),
                    },
                    Span::default(),
                )
            })?;
        runtime.active = true;
        runtime.suspended_loop_head = true;
        runtime.final_force_resume_ordinal = std::env::var(FINAL_FORCE_RESUME_ORDINAL_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|ordinal| *ordinal != 0);
        runtime.final_force_resume_state = FinalForceResumeState::Running;
        runtime
            .corridor_census
            .begin_session(WholeDemandDispatcherRuntime::census_enabled());
        runtime.speed_pmu_windows = super::demand_epoch_probe::DemandWindowController::connect();
        self.note_whole_demand_loop_head(true);
        Ok(true)
    }

    /// Marks entry into one synchronous attr-path semantic leaf.
    fn enter_whole_demand_oracle(&mut self, control: WholeDemandControl) {
        #[cfg(feature = "collection_poll_probe")]
        let final_force_effect_epoch = (self.whole_demand_dispatcher.active
            && matches!(control, WholeDemandControl::FinalForce { segment: 5 }))
        .then(|| self.final_force_effect_cursor());
        let census_enabled = self.whole_demand_dispatcher.corridor_census.is_enabled();
        let allocation_cursor = census_enabled.then(|| {
            (
                self.heap.arena_stats().used_bytes,
                self.heap.permanent_arena_stats().used_bytes,
            )
        });
        let runtime = &mut self.whole_demand_dispatcher;
        if !runtime.active {
            return;
        }
        runtime.suspended_loop_head = false;
        runtime.generic_oracle_depth = runtime.generic_oracle_depth.saturating_add(1);
        runtime.oracle_calls = runtime.oracle_calls.saturating_add(1);
        runtime.control.push(control);
        #[cfg(feature = "collection_poll_probe")]
        if final_force_effect_epoch.is_some() {
            runtime.final_force_effect_epoch = final_force_effect_epoch;
        }
        if census_enabled {
            runtime.corridor_census.enter_outer(control);
        }
        let window_kind = match control {
            WholeDemandControl::AutoCall { segment: 4 } => {
                Some(super::demand_epoch_probe::DemandWindowKind::AutoCall4)
            }
            WholeDemandControl::FinalForce { segment: 5 } => {
                Some(super::demand_epoch_probe::DemandWindowKind::FinalForce5)
            }
            _ => None,
        };
        if let (Some(kind), Some(controller)) = (window_kind, runtime.speed_pmu_windows.as_mut())
            && controller.begin_window(kind)
            && kind == super::demand_epoch_probe::DemandWindowKind::FinalForce5
        {
            runtime.corridor_census.begin_final_force_leaf_pmu();
        }
        if let Some(allocation_cursor) = allocation_cursor {
            runtime
                .corridor_census
                .begin_speed_opportunity_outer(allocation_cursor);
        }
        runtime.max_control_depth = runtime.max_control_depth.max(runtime.control.len());
    }

    /// Records one final-config completion at its nested production site.
    pub(super) fn note_whole_demand_final_config_completion(&mut self) {
        let census_enabled = self.whole_demand_dispatcher.corridor_census.is_enabled();
        let active_force_counts = census_enabled.then(|| {
            (
                self.active_force_roots.len(),
                self.active_force_leases.len(),
                self.active_typed_thunk_work_leases.len(),
            )
        });
        let runtime = &mut self.whole_demand_dispatcher;
        if !runtime.active {
            return;
        }
        runtime.completions = runtime.completions.saturating_add(1);
        runtime.pending_completions = runtime.pending_completions.saturating_add(1);
        if let Some((active_force_roots, active_force_leases, active_typed_work)) =
            active_force_counts
        {
            runtime.corridor_census.note_target_completion(
                active_force_roots,
                active_force_leases,
                active_typed_work,
            );
        }
        if runtime.generic_oracle_depth != 0 {
            runtime.hidden_completions = runtime.hidden_completions.saturating_add(1);
            runtime.pending_hidden_completions =
                runtime.pending_hidden_completions.saturating_add(1);
            if let Some(control) = runtime.control.last().copied() {
                runtime.record_hidden_completion(control);
            }
        }
        if runtime.final_force_resume_ordinal == Some(runtime.completions)
            && runtime.control.last() == Some(&WholeDemandControl::FinalForce { segment: 5 })
            && runtime.final_force_resume_state == FinalForceResumeState::Running
        {
            runtime.final_force_resume_state = FinalForceResumeState::PublicationRequested {
                ordinal: runtime.completions,
            };
        }
    }

    /// Converts the next committed thunk publication into a private unwind.
    ///
    /// The thunk cell is already `Ready` when this hook runs. Therefore replay
    /// observes the committed result instead of evaluating that body twice.
    pub(super) fn suspend_final_force_after_published_thunk(
        &mut self,
        id: IrId,
        span: Span,
        shape: &'static str,
    ) -> Result<(), TreeWalkError> {
        let FinalForceResumeState::PublicationRequested { ordinal } =
            self.whole_demand_dispatcher.final_force_resume_state
        else {
            return Ok(());
        };
        #[cfg(feature = "collection_poll_probe")]
        {
            let current = self.final_force_effect_cursor();
            let changed_classes = self
                .whole_demand_dispatcher
                .final_force_effect_epoch
                .map_or(usize::MAX, |epoch| epoch.changed_classes(current));
            let runtime = &mut self.whole_demand_dispatcher;
            runtime.final_force_effect_checks = runtime.final_force_effect_checks.saturating_add(1);
            runtime.final_force_effect_last_changed_classes = changed_classes;
            if changed_classes == 0 {
                runtime.final_force_effect_clean =
                    runtime.final_force_effect_clean.saturating_add(1);
            } else {
                runtime.final_force_effect_dirty =
                    runtime.final_force_effect_dirty.saturating_add(1);
            }
        }
        if !self.final_force_replay_is_effect_clean() {
            self.whole_demand_dispatcher.final_force_resume_state = FinalForceResumeState::Running;
            self.whole_demand_dispatcher.final_force_resume_declines = self
                .whole_demand_dispatcher
                .final_force_resume_declines
                .saturating_add(1);
            return Ok(());
        }
        self.whole_demand_dispatcher.final_force_resume_publish_site = Some(id);
        self.whole_demand_dispatcher
            .final_force_resume_publish_depth = self.active_force_leases.len();
        self.whole_demand_dispatcher
            .final_force_resume_publish_shape = Some(shape);
        self.whole_demand_dispatcher.final_force_resume_publish_lag = self
            .whole_demand_dispatcher
            .completions
            .saturating_sub(ordinal);
        self.whole_demand_dispatcher.final_force_resume_state =
            FinalForceResumeState::UnwindRequested { ordinal };
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FinalForcePortalSuspend { id, ordinal },
            span,
        ))
    }

    /// Returns whether replay cannot duplicate any configured or observed effect.
    fn final_force_replay_is_effect_clean(&self) -> bool {
        let parallel_capable_or_active = self.options.parallel_workers().is_some()
            || self.options.parallel_thunk_payloads_enabled()
            || self.shared.is_some();
        let memo_or_persist_capable_or_active = self.options.memo_active()
            || !self.options.memo_disk_locations().is_empty()
            || self.options.memo_net().is_some()
            || self.options.persist_cache_root().is_some()
            || self.force_cache_active
            || self.persist_cache.is_some()
            || !self.persist_secondary_caches.is_empty();
        self.options.eval_mode() == EvalMode::Pure
            && self.ifd_realizer.is_none()
            && !parallel_capable_or_active
            && !memo_or_persist_capable_or_active
            && self.trace_output.is_empty()
            && self.warning_output.is_empty()
            && self.impure_input_trace.is_empty()
            && self.text_store.is_empty()
            && self.source_store_string_cache.is_empty()
    }

    /// Captures the observable effect classes owned by one FinalForce attempt.
    #[cfg(feature = "collection_poll_probe")]
    fn final_force_effect_cursor(&self) -> FinalForceEffectCursor {
        let stats = &self.stats;
        let memo_events = stats
            .memo_l0_hits
            .saturating_add(stats.memo_l0_misses)
            .saturating_add(stats.memo_l0_admissions)
            .saturating_add(stats.memo_l0_declines)
            .saturating_add(stats.memo_l1_hits)
            .saturating_add(stats.memo_l1_misses)
            .saturating_add(stats.memo_l1_admissions)
            .saturating_add(stats.memo_l1_declines)
            .saturating_add(stats.memo_l2_secondary_hits)
            .saturating_add(stats.memo_l2_secondary_misses)
            .saturating_add(stats.memo_l2_promotions)
            .saturating_add(stats.memo_l2_reval_failures)
            .saturating_add(stats.memo_net_hits)
            .saturating_add(stats.memo_net_misses)
            .saturating_add(stats.memo_net_errors)
            .saturating_add(stats.memo_net_reval_failures);
        FinalForceEffectCursor {
            ifd_realizations: self.final_force_ifd_realizations.get(),
            trace_events: self.trace_output.len(),
            warning_events: self.warning_output.len(),
            impure_input_events: self.impure_input_trace.len(),
            impure_input_complete: self.impure_input_trace_complete,
            text_store_realizations: self.text_store.len(),
            source_store_realizations: self.source_store_string_cache.len(),
            import_cache_entries: self.import_cache.len(),
            known_derivations: self.known_derivations.len(),
            memo_events,
        }
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
        if let Some(control) = self.whole_demand_dispatcher.control.pop() {
            if self.whole_demand_dispatcher.corridor_census.is_enabled() {
                let allocation_cursor = (
                    self.heap.arena_stats().used_bytes,
                    self.heap.permanent_arena_stats().used_bytes,
                );
                self.whole_demand_dispatcher
                    .corridor_census
                    .end_speed_opportunity_outer(allocation_cursor);
            }
            if matches!(control, WholeDemandControl::FinalForce { segment: 5 }) {
                self.whole_demand_dispatcher
                    .corridor_census
                    .end_final_force_leaf_pmu();
            }
            if matches!(
                control,
                WholeDemandControl::AutoCall { segment: 4 }
                    | WholeDemandControl::FinalForce { segment: 5 }
            ) && let Some(controller) = self.whole_demand_dispatcher.speed_pmu_windows.as_mut()
            {
                controller.end_window();
            }
            if self.whole_demand_dispatcher.corridor_census.is_enabled() {
                self.whole_demand_dispatcher
                    .corridor_census
                    .leave_outer(control);
            }
        }
        self.whole_demand_dispatcher.suspended_loop_head = true;
        self.note_whole_demand_loop_head(result.is_ok());
        #[cfg(feature = "young_increment_projection_probe")]
        self.note_young_increment_returned_outer_loop_head();
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

    /// Restores and proves the explicit loop head after a private unwind.
    fn establish_final_force_resume_portal(
        &mut self,
        id: IrId,
        span: Span,
        slot: usize,
        ordinal: u64,
    ) -> Result<(), TreeWalkError> {
        let mut suspended = Ok(self.whole_demand_slot_value(id, span, slot)?);
        self.finish_whole_demand_oracle_leaf(&mut suspended, Some(slot));
        self.whole_demand_dispatcher.final_force_resume_state =
            FinalForceResumeState::Suspended { ordinal };
        self.whole_demand_dispatcher.final_force_resume_suspensions = self
            .whole_demand_dispatcher
            .final_force_resume_suspensions
            .saturating_add(1);
        let guard = match self.dispatcher_collection_poll_preflight() {
            Ok(guard) => guard,
            Err(_) => {
                self.whole_demand_dispatcher.final_force_resume_declines = self
                    .whole_demand_dispatcher
                    .final_force_resume_declines
                    .saturating_add(1);
                // This is a default-off optimization probe. Failure to prove a
                // collection seam must resume the already-published computation,
                // not turn a valid Nix evaluation into an internal error.
                return Ok(());
            }
        };
        #[cfg(feature = "young_increment_projection_probe")]
        self.note_young_increment_final_force_portal(ordinal, &guard);
        #[cfg(feature = "packed_portal_cutover")]
        {
            self.maybe_publish_packed_final_force_portal(ordinal, guard);
        }
        Ok(())
    }

    /// Closes the dispatcher after copying its terminal rooted value.
    fn finish_whole_demand_dispatcher(
        &mut self,
        result: &mut Result<Value, TreeWalkError>,
        base: usize,
    ) {
        if matches!(
            self.whole_demand_dispatcher.final_force_resume_state,
            FinalForceResumeState::PublicationRequested { .. }
        ) {
            self.whole_demand_dispatcher.final_force_resume_declines = self
                .whole_demand_dispatcher
                .final_force_resume_declines
                .saturating_add(1);
        }
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
        self.whole_demand_dispatcher.final_force_resume_state = FinalForceResumeState::Running;
        if self.whole_demand_dispatcher.corridor_census.is_enabled() {
            self.whole_demand_dispatcher.corridor_census.end_session();
        }
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
        #[cfg(feature = "packed_portal_cutover")]
        self.maybe_publish_packed_prefinal_cutover();
        self.enter_whole_demand_oracle(final_force_control);
        let mut result = self.run_rooted_final_force_attempt(id, span, slot);
        while let Err(error) = &result {
            let TreeWalkErrorKind::FinalForcePortalSuspend { id: _, ordinal } = error.kind() else {
                break;
            };
            if self.whole_demand_dispatcher.final_force_resume_state
                != (FinalForceResumeState::UnwindRequested { ordinal })
            {
                break;
            }

            // The semantic leaf has unwound through its normal Result cleanup.
            // Reinstall its rooted input as the loop-head value before proving
            // that no recursive owner escaped the unwind.
            if let Err(error) = self.establish_final_force_resume_portal(id, span, slot, ordinal) {
                result = Err(error);
                break;
            }

            // A future collector runs at this exact seam. Resume today by
            // replaying the same rooted FinalForce input; already-published
            // thunk results make the replay incremental.
            self.whole_demand_dispatcher.final_force_resume_state = FinalForceResumeState::Running;
            self.whole_demand_dispatcher.final_force_resume_resumptions = self
                .whole_demand_dispatcher
                .final_force_resume_resumptions
                .saturating_add(1);
            self.enter_whole_demand_oracle(final_force_control);
            result = self.run_rooted_final_force_attempt(id, span, slot);
        }
        self.finish_whole_demand_oracle_leaf(&mut result, Some(slot));
        self.finish_whole_demand_dispatcher(&mut result, base);
        result
    }

    fn note_whole_demand_loop_head(&mut self, succeeded: bool) {
        let hidden = self.whole_demand_dispatcher.pending_hidden_completions;
        let pending = self.whole_demand_dispatcher.pending_completions;
        if succeeded {
            self.whole_demand_dispatcher.returned_loop_head_completions = self
                .whole_demand_dispatcher
                .returned_loop_head_completions
                .saturating_add(pending);
            self.whole_demand_dispatcher.safe_loop_head_completions = self
                .whole_demand_dispatcher
                .safe_loop_head_completions
                .saturating_add(pending.saturating_sub(hidden));
        } else {
            self.whole_demand_dispatcher.abandoned_completions = self
                .whole_demand_dispatcher
                .abandoned_completions
                .saturating_add(pending);
        }
        self.whole_demand_dispatcher.pending_completions = 0;
        self.whole_demand_dispatcher.pending_hidden_completions = 0;
        let proof_succeeded = if pending == 0 {
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
        let attributed_hidden_completions = runtime.attributed_hidden_completions();
        for attribution in &runtime.hidden_attribution {
            eprintln!(
                "aos_nix_whole_demand_hidden control={} segment={} completions={}",
                attribution.control.kind(),
                attribution.control.segment(),
                attribution.completions,
            );
        }
        let pmu_evidence = runtime
            .speed_pmu_windows
            .as_ref()
            .map(super::demand_epoch_probe::DemandWindowController::counter_evidence);
        let census_enabled = runtime.corridor_census.is_enabled();
        if census_enabled {
            runtime.corridor_census.emit_report(pmu_evidence);
        }
        let (
            pmu_connected,
            pmu_begin_commands,
            pmu_end_commands,
            pmu_failures,
            pmu_balanced,
            pmu_provenance_available,
        ) = runtime.speed_pmu_windows.as_ref().map_or(
            (false, 0, 0, 0, false, false),
            |controller| {
                (
                    true,
                    controller.begin_commands(),
                    controller.end_commands(),
                    controller.failures(),
                    controller.balanced(),
                    controller.provenance_available(),
                )
            },
        );
        let evidence = pmu_evidence
            .unwrap_or_else(|| super::demand_epoch_probe::DemandCounterEvidence::unavailable());
        for kind in [
            super::demand_epoch_probe::DemandWindowKind::AutoCall4,
            super::demand_epoch_probe::DemandWindowKind::FinalForce5,
        ] {
            eprintln!(
                "aos_nix_whole_demand_pmu_window kind={} windows={} \
                 instructions={} cycles={} authoritative={} census_enabled={}",
                kind.name(),
                evidence.windows(kind),
                evidence.instructions(kind),
                evidence.cycles(kind),
                evidence.authoritative(),
                census_enabled,
            );
        }
        if runtime.final_force_resume_ordinal.is_some() {
            eprintln!(
                "aos_nix_final_force_resume_portal selected={:?} suspensions={} \
                 resumptions={} declines={} state={:?} publish_site={:?} \
                 publish_depth={} publish_shape={} publish_lag={}",
                runtime.final_force_resume_ordinal,
                runtime.final_force_resume_suspensions,
                runtime.final_force_resume_resumptions,
                runtime.final_force_resume_declines,
                runtime.final_force_resume_state,
                runtime.final_force_resume_publish_site,
                runtime.final_force_resume_publish_depth,
                runtime.final_force_resume_publish_shape.unwrap_or("none"),
                runtime.final_force_resume_publish_lag,
            );
            #[cfg(feature = "collection_poll_probe")]
            eprintln!(
                "aos_nix_final_force_effect_epoch checks={} clean={} dirty={} \
                 last_changed_classes={} report_only=true",
                runtime.final_force_effect_checks,
                runtime.final_force_effect_clean,
                runtime.final_force_effect_dirty,
                runtime.final_force_effect_last_changed_classes,
            );
        }
        eprintln!(
            "aos_nix_whole_demand_dispatcher_probe \
             oracle_calls={} completions={} hidden_completions={} \
             attributed_hidden_completions={} hidden_conserved={} \
             safe_loop_head_completions={} returned_loop_head_completions={} \
             abandoned_completions={} pending_completions={} \
             proof_accepts={} proof_declines={} \
             structural_proof_attempts={} rooted_proof_attempts={} \
             max_control_depth={} max_value_slots={} modeled_storage_bytes={} \
             storage_cap_bytes={} execution_substitution=attr_path_outer_loop \
             speed_pmu_connected={} speed_pmu_begin_commands={} \
             speed_pmu_end_commands={} speed_pmu_failures={} \
             speed_pmu_balanced={} speed_pmu_process_owner=true \
             speed_pmu_evaluator_session_window_provenance_available={} \
             speed_pmu_session_id={} speed_pmu_null_instructions={} \
             speed_pmu_null_cycles={} speed_pmu_authoritative={} census_enabled={} \
             collection=false",
            runtime.oracle_calls,
            runtime.completions,
            runtime.hidden_completions,
            attributed_hidden_completions,
            attributed_hidden_completions == runtime.hidden_completions,
            runtime.safe_loop_head_completions,
            runtime.returned_loop_head_completions,
            runtime.abandoned_completions,
            runtime.pending_completions,
            runtime.proof_accepts,
            runtime.proof_declines,
            runtime.structural_proof_attempts,
            runtime.rooted_proof_attempts,
            runtime.max_control_depth,
            runtime.max_value_slots,
            runtime.modeled_storage_bytes(),
            STORAGE_CAP_BYTES,
            pmu_connected,
            pmu_begin_commands,
            pmu_end_commands,
            pmu_failures,
            pmu_balanced,
            pmu_provenance_available,
            evidence.session_id(),
            evidence.null_instructions(),
            evidence.null_cycles(),
            evidence.authoritative(),
            census_enabled,
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

    #[test]
    fn corridor_census_is_default_on_and_explicitly_disabled_by_zero() {
        assert!(WholeDemandDispatcherRuntime::census_enabled_for(None));
        assert!(WholeDemandDispatcherRuntime::census_enabled_for(Some(
            std::ffi::OsStr::new("1"),
        )));
        assert!(!WholeDemandDispatcherRuntime::census_enabled_for(Some(
            std::ffi::OsStr::new("0"),
        )));
    }

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
    fn hidden_completion_attribution_conserves_exact_control_coordinate() {
        let mut runtime = WholeDemandDispatcherRuntime::default();
        let control = WholeDemandControl::AutoCall { segment: 2 };
        runtime.record_hidden_completion(control);
        runtime.record_hidden_completion(control);
        runtime.record_hidden_completion(WholeDemandControl::FinalForce { segment: 3 });

        assert_eq!(runtime.attributed_hidden_completions(), 3);
        assert_eq!(
            runtime.hidden_attribution,
            [
                HiddenCompletionAttribution {
                    control,
                    completions: 2,
                },
                HiddenCompletionAttribution {
                    control: WholeDemandControl::FinalForce { segment: 3 },
                    completions: 1,
                },
            ]
        );
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

    #[cfg(feature = "collection_poll_probe")]
    #[test]
    fn final_force_effect_cursor_counts_independent_changed_classes() {
        let baseline = FinalForceEffectCursor::default();
        let changed = FinalForceEffectCursor {
            ifd_realizations: 1,
            impure_input_events: 2,
            import_cache_entries: 3,
            ..baseline
        };

        assert_eq!(baseline.changed_classes(changed), 3);
        assert_eq!(changed.changed_classes(changed), 0);
    }

    #[test]
    fn active_corridor_and_dispatcher_storage_stay_below_the_shared_cap() {
        let mut runtime = WholeDemandDispatcherRuntime::default();
        runtime.control.reserve(1);
        runtime.value_slots.reserve(1);
        runtime.hidden_attribution.reserve(17);
        runtime.corridor_census.begin_session(true);
        assert!(runtime.corridor_census.modeled_storage_bytes() > 60_928);
        assert!(runtime.modeled_storage_bytes() < STORAGE_CAP_BYTES);
        runtime.corridor_census.end_session();
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
    fn loop_head_proof_materializes_roots_only_for_pending_completion() {
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
        evaluator.whole_demand_dispatcher.pending_completions = 1;
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
    fn final_force_portal_requests_only_the_exact_segment_five_ordinal() {
        let ir = lower("1");
        let mut evaluator =
            TreeWalk::with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Pure));
        evaluator.whole_demand_dispatcher.active = true;
        evaluator.whole_demand_dispatcher.generic_oracle_depth = 1;
        evaluator.whole_demand_dispatcher.final_force_resume_ordinal = Some(160);
        evaluator
            .whole_demand_dispatcher
            .control
            .push(WholeDemandControl::FinalForce { segment: 5 });
        evaluator.whole_demand_dispatcher.completions = 159;

        evaluator.note_whole_demand_final_config_completion();

        assert_eq!(
            evaluator.whole_demand_dispatcher.final_force_resume_state,
            FinalForceResumeState::PublicationRequested { ordinal: 160 }
        );
        let error = evaluator
            .suspend_final_force_after_published_thunk(ir.root, Span::default(), "node")
            .expect_err("next committed publication requests a private unwind");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::FinalForcePortalSuspend { ordinal: 160, .. }
        ));
        assert_eq!(
            evaluator.whole_demand_dispatcher.final_force_resume_state,
            FinalForceResumeState::UnwindRequested { ordinal: 160 }
        );
        assert_eq!(
            evaluator
                .whole_demand_dispatcher
                .final_force_resume_publish_shape,
            Some("node")
        );

        evaluator.whole_demand_dispatcher.final_force_resume_state = FinalForceResumeState::Running;
        evaluator.whole_demand_dispatcher.completions = 159;
        evaluator.whole_demand_dispatcher.control[0] =
            WholeDemandControl::FinalForce { segment: 4 };
        evaluator.note_whole_demand_final_config_completion();
        assert_eq!(
            evaluator.whole_demand_dispatcher.final_force_resume_state,
            FinalForceResumeState::Running
        );
    }

    #[test]
    fn final_force_portal_declines_replay_in_an_impure_session() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.whole_demand_dispatcher.final_force_resume_state =
            FinalForceResumeState::PublicationRequested { ordinal: 160 };

        evaluator
            .suspend_final_force_after_published_thunk(ir.root, Span::default(), "node")
            .expect("an effect-capable session must continue without replay");

        assert_eq!(
            evaluator.whole_demand_dispatcher.final_force_resume_state,
            FinalForceResumeState::Running
        );
        assert_eq!(
            evaluator
                .whole_demand_dispatcher
                .final_force_resume_declines,
            1
        );
    }

    #[test]
    fn final_force_portal_reestablishes_a_bijective_rooted_loop_head() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.whole_demand_dispatcher.active = true;
        evaluator.whole_demand_dispatcher.generic_oracle_depth = 1;
        evaluator.whole_demand_dispatcher.final_force_resume_state =
            FinalForceResumeState::UnwindRequested { ordinal: 160 };
        evaluator
            .whole_demand_dispatcher
            .control
            .push(WholeDemandControl::FinalForce { segment: 5 });
        evaluator.transient_value_stack_roots.push(Value::int(1));
        evaluator.whole_demand_dispatcher.value_slots.push(0);

        evaluator
            .establish_final_force_resume_portal(ir.root, Span::default(), 0, 160)
            .expect("normal Result cleanup reaches a bijective rooted loop head");

        assert!(evaluator.whole_demand_dispatcher.suspended_loop_head);
        assert_eq!(evaluator.whole_demand_dispatcher.generic_oracle_depth, 0);
        assert!(evaluator.whole_demand_dispatcher.control.is_empty());
        assert_eq!(
            evaluator.whole_demand_dispatcher.final_force_resume_state,
            FinalForceResumeState::Suspended { ordinal: 160 }
        );
        assert_eq!(
            evaluator
                .whole_demand_dispatcher
                .final_force_resume_suspensions,
            1
        );
        assert!(evaluator.dispatcher_collection_poll_preflight().is_ok());
    }

    #[test]
    fn final_force_portal_preflight_decline_resumes_without_semantic_error() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.whole_demand_dispatcher.active = true;
        evaluator.whole_demand_dispatcher.generic_oracle_depth = 1;
        evaluator.whole_demand_dispatcher.final_force_resume_state =
            FinalForceResumeState::UnwindRequested { ordinal: 160 };
        evaluator
            .whole_demand_dispatcher
            .control
            .push(WholeDemandControl::FinalForce { segment: 5 });
        evaluator.transient_value_stack_roots.push(Value::int(1));
        evaluator.whole_demand_dispatcher.value_slots.push(0);
        evaluator.active_force_roots.push(Value::int(2));

        evaluator
            .establish_final_force_resume_portal(ir.root, Span::default(), 0, 160)
            .expect("an optimization preflight decline must preserve evaluation");

        assert_eq!(
            evaluator
                .whole_demand_dispatcher
                .final_force_resume_declines,
            1
        );
        assert_eq!(
            evaluator.whole_demand_dispatcher.final_force_resume_state,
            FinalForceResumeState::Suspended { ordinal: 160 }
        );
    }

    #[test]
    fn terminal_cleanup_counts_an_unconsumed_publication_request_as_declined() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.whole_demand_dispatcher.active = true;
        evaluator.whole_demand_dispatcher.final_force_resume_state =
            FinalForceResumeState::PublicationRequested { ordinal: 160 };
        let mut result = Ok(Value::int(1));

        evaluator.finish_whole_demand_dispatcher(&mut result, 0);

        assert_eq!(
            evaluator
                .whole_demand_dispatcher
                .final_force_resume_declines,
            1
        );
        assert!(!evaluator.whole_demand_dispatcher.active);
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

    #[test]
    fn final_force_portal_bypasses_error_context_and_try_eval_catches() {
        let ir = lower(r#""context must not run""#);
        let mut evaluator = TreeWalk::new(&ir);
        let span = evaluator.node(ir.root).expect("root exists").span;
        let portal = TreeWalkError::new(
            TreeWalkErrorKind::FinalForcePortalSuspend {
                id: ir.root,
                ordinal: 160,
            },
            span,
        );

        let after_context = evaluator
            .add_error_context_node_to_error(ir.root, span, ir.root, portal)
            .expect_err("nonsemantic suspension bypasses addErrorContext");
        assert!(after_context.contexts().is_empty());
        let after_try_eval = evaluator
            .handle_try_eval_error(ir.root, span, after_context)
            .expect_err("nonsemantic suspension bypasses tryEval");

        assert!(after_try_eval.contexts().is_empty());
        assert!(matches!(
            after_try_eval.kind(),
            TreeWalkErrorKind::FinalForcePortalSuspend { ordinal: 160, .. }
        ));
    }
}
