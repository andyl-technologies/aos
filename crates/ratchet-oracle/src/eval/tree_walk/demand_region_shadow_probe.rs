//! Allocation-byte and statepoint shadow census for whole-demand regions.
//!
//! This compile-time-only probe observes the requested-attribute demand epoch.
//! It does not retain [`Value`]s, alter evaluation, or claim that planner
//! candidates are executable. Instead it combines exact serial arena movement,
//! a typed allocation-suffix scan, process-wide serial frame/capture counters,
//! and runtime-weighted Promise-region plans.

use super::*;
use crate::compile::VirtualAllocationKind;

const MAX_ENTRY_KEYS: usize = 65_536;
const MAX_GUARD_SITES: usize = 65_536;
const MAX_TARGETS_PER_GUARD: usize = 16;
const MAX_ALLOCATION_SITES: usize = 65_536;
const TRACE_ROOT_FRONTIERS: [usize; 4] = [4, 8, 12, 20];
const TRACE_GUARD_TARGET_CAP: usize = 4;
const TRACE_MAX_ENTRIES: usize = 4_096;

// Exact post-master lean final-config profile used only by the report-only
// projection. The shadow emits both the constants and its derivation, so a
// later source refresh cannot silently pass these figures off as fresh
// counters.
const PROFILE_BASELINE_INSTRUCTIONS: u64 = 14_030_054_434;
const PROFILE_BASELINE_CYCLES: u64 = 5_826_183_736;
const PROFILE_VIRTUALIZABLE_INSTRUCTION_PPM: u64 = 596_500;
const PROFILE_VIRTUALIZABLE_CYCLE_PPM: u64 = 554_000;
const PROFILE_TARGET_INSTRUCTIONS: u64 = 10_523_952_238;
const PROFILE_TARGET_CYCLES: u64 = 3_858_165_127;
const TRACE_PROJECTED_ELIMINATION_PPM: u64 = 700_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum EntryKind {
    Apply,
    Force,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct EntryKey {
    kind: EntryKind,
    module: EvalModuleId,
    body: IrId,
    frame: Option<FrameId>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct GuardSite {
    module: EvalModuleId,
    apply: IrId,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct GuardTarget {
    module: EvalModuleId,
    body: IrId,
    frame: FrameId,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CallerGuardSite {
    caller: EntryKey,
    site: GuardSite,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AllocationKind {
    Promise,
    Frame,
    Closure,
    List,
    Attrs,
}

impl From<VirtualAllocationKind> for AllocationKind {
    fn from(kind: VirtualAllocationKind) -> Self {
        match kind {
            VirtualAllocationKind::Promise => Self::Promise,
            VirtualAllocationKind::Frame => Self::Frame,
            VirtualAllocationKind::Closure => Self::Closure,
            VirtualAllocationKind::List => Self::List,
            VirtualAllocationKind::Attrs => Self::Attrs,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AllocationSite {
    module: EvalModuleId,
    node: IrId,
    kind: AllocationKind,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AllocationSiteTally {
    events: u64,
    arena_bytes_exact: u64,
    external_bytes_lower_bound: u64,
}

#[derive(Clone, Copy, Debug)]
struct DemandFence {
    heap: crate::eval::heap::DemandRegionAllocationFence,
    env: super::super::env::capture_stats::EnvCaptureStats,
}

/// Default-off runtime state for one evaluator.
#[derive(Debug)]
pub(super) struct DemandRegionShadowProbe {
    fence: Option<DemandFence>,
    entries: HashMap<EntryKey, u64>,
    guard_targets: HashMap<GuardSite, HashMap<GuardTarget, u64>>,
    caller_guard_targets: HashMap<CallerGuardSite, HashMap<GuardTarget, u64>>,
    active_entries: Vec<EntryKey>,
    allocation_sites: HashMap<AllocationSite, AllocationSiteTally>,
    trace_shadow_enabled: bool,
    apply_events: u64,
    force_events: u64,
    dropped_entry_keys: u64,
    dropped_guard_sites: u64,
    dropped_guard_targets: u64,
    dropped_caller_guard_events: u64,
    dropped_allocation_sites: u64,
}

impl DemandRegionShadowProbe {
    /// Admits only the serial, nonmoving, cache/JIT/memo-off primary mode.
    pub(super) fn from_env(options: &TreeWalkOptions, force_cache_active: bool) -> Option<Self> {
        let demand_shadow_enabled =
            std::env::var("AOS_NIX_DEMAND_REGION_SHADOW_PROBE").is_ok_and(|value| value == "1");
        #[cfg(feature = "whole_demand_trace_shadow_probe")]
        let trace_shadow_enabled =
            std::env::var("AOS_NIX_WHOLE_DEMAND_TRACE_SHADOW").is_ok_and(|value| value == "1");
        #[cfg(not(feature = "whole_demand_trace_shadow_probe"))]
        let trace_shadow_enabled = false;
        if !demand_shadow_enabled && !trace_shadow_enabled {
            return None;
        }
        let admitted = options.parallel_workers().is_none()
            && !options.parallel_thunk_payloads_enabled()
            && options.gc_mode() == EvalGcMode::Off
            && options.gc_stress_policy() == GcStressPolicy::disabled()
            && options.thunk_resolve_barrier_tier() == GenerationalGcTier::OneShotArena
            && !options.record_worker_closures_for_gc_scaffolding()
            && !options.eval_cache_enabled()
            && options.persist_cache_root().is_none()
            && !force_cache_active
            && !options.jit_tier1_publish_enabled()
            && !options.memo_active()
            && !options.boundary_memo_active();
        if !admitted {
            eprintln!(
                "aos_nix_demand_region_shadow_refused \
                 {{\"reason\":\"requires serial nonmoving cache/JIT/memo-off mode\"}}"
            );
            return None;
        }
        Some(Self {
            fence: None,
            entries: HashMap::new(),
            guard_targets: HashMap::new(),
            caller_guard_targets: HashMap::new(),
            active_entries: Vec::new(),
            allocation_sites: HashMap::new(),
            trace_shadow_enabled,
            apply_events: 0,
            force_events: 0,
            dropped_entry_keys: 0,
            dropped_guard_sites: 0,
            dropped_guard_targets: 0,
            dropped_caller_guard_events: 0,
            dropped_allocation_sites: 0,
        })
    }

    fn active(&self) -> bool {
        self.fence.is_some()
    }

    fn note_entry(&mut self, key: EntryKey) {
        if !self.active() {
            return;
        }
        if let Some(events) = self.entries.get_mut(&key) {
            *events = events.saturating_add(1);
        } else if self.entries.len() < MAX_ENTRY_KEYS {
            self.entries.insert(key, 1);
        } else {
            self.dropped_entry_keys = self.dropped_entry_keys.saturating_add(1);
        }
    }

    fn enter_entry(&mut self, key: EntryKey) {
        self.note_entry(key);
        if self.trace_shadow_enabled && self.active() {
            self.active_entries.push(key);
        }
    }

    fn leave_entry(&mut self) {
        if self.trace_shadow_enabled && self.active() {
            let _ = self.active_entries.pop();
        }
    }

    fn note_guard(&mut self, site: GuardSite, target: GuardTarget) {
        if !self.active() {
            return;
        }
        if !self.guard_targets.contains_key(&site) {
            if self.guard_targets.len() >= MAX_GUARD_SITES {
                self.dropped_guard_sites = self.dropped_guard_sites.saturating_add(1);
                return;
            }
            self.guard_targets.insert(site, HashMap::new());
        }
        let Some(targets) = self.guard_targets.get_mut(&site) else {
            return;
        };
        if let Some(events) = targets.get_mut(&target) {
            *events = events.saturating_add(1);
        } else if targets.len() < MAX_TARGETS_PER_GUARD {
            targets.insert(target, 1);
        } else {
            self.dropped_guard_targets = self.dropped_guard_targets.saturating_add(1);
            return;
        }
        let Some(caller) = self.active_entries.last().copied() else {
            return;
        };
        let caller_site = CallerGuardSite { caller, site };
        if !self.caller_guard_targets.contains_key(&caller_site)
            && self.caller_guard_targets.len() >= MAX_GUARD_SITES
        {
            self.dropped_caller_guard_events = self.dropped_caller_guard_events.saturating_add(1);
            return;
        }
        let caller_targets = self.caller_guard_targets.entry(caller_site).or_default();
        let caller_events = caller_targets.entry(target).or_default();
        *caller_events = caller_events.saturating_add(1);
    }

    fn note_allocation(
        &mut self,
        site: AllocationSite,
        arena_bytes_exact: u64,
        external_bytes_lower_bound: u64,
    ) {
        if !self.active() {
            return;
        }
        if let Some(tally) = self.allocation_sites.get_mut(&site) {
            tally.events = tally.events.saturating_add(1);
            tally.arena_bytes_exact = tally.arena_bytes_exact.saturating_add(arena_bytes_exact);
            tally.external_bytes_lower_bound = tally
                .external_bytes_lower_bound
                .saturating_add(external_bytes_lower_bound);
        } else if self.allocation_sites.len() < MAX_ALLOCATION_SITES {
            self.allocation_sites.insert(
                site,
                AllocationSiteTally {
                    events: 1,
                    arena_bytes_exact,
                    external_bytes_lower_bound,
                },
            );
        } else {
            self.dropped_allocation_sites = self.dropped_allocation_sites.saturating_add(1);
        }
    }
}

#[derive(Default)]
struct PlanTotals {
    planned_entries: u64,
    failed_entries: u64,
    planned_events: u64,
    failed_events: u64,
    virtual_promises: u64,
    virtual_frames: u64,
    virtual_closures: u64,
    virtual_lists: u64,
    virtual_attrs: u64,
    statepoints: [u64; 11],
    virtual_sites: HashSet<AllocationSite>,
}

#[derive(Default)]
struct TraceProjection {
    roots: Vec<(EntryKey, u64)>,
    linked_entries: usize,
    selected_operation_weight: u64,
    global_operation_weight: u64,
    guard_events: u64,
    guard_hits: u64,
    effect_exit_events_upper: u64,
    oracle_exit_events_upper: u64,
    virtual_sites: HashSet<AllocationSite>,
    plan_failures: u64,
    global_plan_failures: u64,
    grin_fragments: u64,
    grin_operations: u64,
    grin_failures: u64,
}

impl TreeWalk {
    /// Starts the allocation fence at the requested-attribute demand boundary.
    pub(super) fn begin_demand_region_shadow_epoch(&mut self) {
        let Some(probe) = self.demand_region_shadow_probe.as_mut() else {
            return;
        };
        if self.tier1_engine.is_some() {
            eprintln!(
                "aos_nix_demand_region_shadow_refused \
                 {{\"reason\":\"a tier-1 engine was installed after construction\"}}"
            );
            self.demand_region_shadow_probe = None;
            return;
        }
        let Some(heap) = self.heap.demand_region_allocation_fence() else {
            eprintln!(
                "aos_nix_demand_region_shadow_refused \
                 {{\"reason\":\"heap has no single serial allocation suffix\"}}"
            );
            self.demand_region_shadow_probe = None;
            return;
        };
        probe.fence = Some(DemandFence {
            heap,
            env: super::super::env::capture_stats::snapshot(),
        });
    }

    /// Records one user-lambda application inside the fenced demand epoch.
    pub(super) fn note_demand_region_apply(&mut self, lambda: &EvalLambda) {
        let Some(probe) = self.demand_region_shadow_probe.as_mut() else {
            return;
        };
        if !probe.active() {
            return;
        }
        probe.apply_events = probe.apply_events.saturating_add(1);
        probe.enter_entry(EntryKey {
            kind: EntryKind::Apply,
            module: lambda.module(),
            body: lambda.body(),
            frame: Some(lambda.frame()),
        });
    }

    /// Records one claimed source-backed thunk force in the demand epoch.
    pub(super) fn note_demand_region_force(&mut self, thunk: &EvalThunk) {
        let Some(body) = thunk.body_ref() else {
            return;
        };
        let Some(probe) = self.demand_region_shadow_probe.as_mut() else {
            return;
        };
        if !probe.active() {
            return;
        }
        probe.force_events = probe.force_events.saturating_add(1);
        probe.enter_entry(EntryKey {
            kind: EntryKind::Force,
            module: body.module(),
            body: body.id(),
            frame: None,
        });
    }

    /// Leaves the innermost report-only whole-demand trace entry.
    pub(super) fn leave_demand_region_entry(&mut self) {
        let Some(probe) = self.demand_region_shadow_probe.as_mut() else {
            return;
        };
        probe.leave_entry();
    }

    /// Records the concrete population behind one syntactically unknown call.
    pub(super) fn note_demand_region_guard_target(
        &mut self,
        caller_module: EvalModuleId,
        apply: IrId,
        lambda: &EvalLambda,
    ) {
        let Some(probe) = self.demand_region_shadow_probe.as_mut() else {
            return;
        };
        probe.note_guard(
            GuardSite {
                module: caller_module,
                apply,
            },
            GuardTarget {
                module: lambda.module(),
                body: lambda.body(),
                frame: lambda.frame(),
            },
        );
    }

    /// Captures exact serial evaluator-arena positions around one wrapper.
    pub(super) fn demand_region_allocation_cursor(&self) -> (usize, usize) {
        (
            self.heap.arena_stats().used_bytes,
            self.heap.permanent_arena_stats().used_bytes,
        )
    }

    /// Attributes one successful wrapper allocation to its source IR node.
    pub(super) fn note_demand_region_source_allocation(
        &mut self,
        node: IrId,
        kind: VirtualAllocationKind,
        before: (usize, usize),
        external_bytes_lower_bound: usize,
    ) {
        let after = self.demand_region_allocation_cursor();
        let arena_bytes_exact = after
            .0
            .saturating_sub(before.0)
            .saturating_add(after.1.saturating_sub(before.1))
            as u64;
        let site = AllocationSite {
            module: self.current_module,
            node,
            kind: kind.into(),
        };
        let Some(probe) = self.demand_region_shadow_probe.as_mut() else {
            return;
        };
        probe.note_allocation(site, arena_bytes_exact, external_bytes_lower_bound as u64);
    }

    /// Attributes a lexical frame's conservative storage lower bound.
    pub(super) fn note_demand_region_frame_allocation(&mut self, node: IrId, slot_count: usize) {
        let frame_lower = std::mem::size_of::<EvalFrame>()
            .max(slot_count.saturating_mul(std::mem::size_of::<Value>()));
        let site = AllocationSite {
            module: self.current_module,
            node,
            kind: AllocationKind::Frame,
        };
        let Some(probe) = self.demand_region_shadow_probe.as_mut() else {
            return;
        };
        probe.note_allocation(site, 0, frame_lower as u64);
    }

    /// Ends and reports the epoch before derivation/store materialization.
    pub(super) fn emit_demand_region_shadow_report(&mut self) {
        let Some(mut probe) = self.demand_region_shadow_probe.take() else {
            return;
        };
        let Some(fence) = probe.fence.take() else {
            self.demand_region_shadow_probe = Some(probe);
            return;
        };
        let heap = self.heap.demand_region_allocation_census(fence.heap);
        let env = super::super::env::capture_stats::snapshot().delta_since(fence.env);
        let plans = self.demand_region_plan_totals(&probe.entries);
        if probe.trace_shadow_enabled {
            for (root_limit, roots) in trace_root_frontiers(&probe) {
                let trace = self.demand_region_trace_projection(&probe, roots);
                emit_trace_report(&probe, root_limit, &trace);
            }
        }
        emit_report(&probe, heap, env, plans);
        self.demand_region_shadow_probe = Some(probe);
    }

    fn demand_region_plan_totals(&self, entries: &HashMap<EntryKey, u64>) -> PlanTotals {
        let mut totals = PlanTotals::default();
        for (key, events) in entries {
            let Some(module) = self.modules.get(key.module.index()) else {
                totals.failed_entries = totals.failed_entries.saturating_add(1);
                totals.failed_events = totals.failed_events.saturating_add(*events);
                continue;
            };
            let plan = match plan_promise_region(
                &module.ir,
                key.body,
                key.frame,
                PromiseRegionOptions {
                    symbol_validation: PromiseRegionSymbolValidation::ExternallyRemapped,
                    ..PromiseRegionOptions::default()
                },
            ) {
                Ok(plan) => plan,
                Err(_) => {
                    totals.failed_entries = totals.failed_entries.saturating_add(1);
                    totals.failed_events = totals.failed_events.saturating_add(*events);
                    continue;
                }
            };
            totals.planned_entries = totals.planned_entries.saturating_add(1);
            totals.planned_events = totals.planned_events.saturating_add(*events);
            totals.virtual_promises = totals
                .virtual_promises
                .saturating_add(events.saturating_mul(plan.virtual_allocations.promises as u64));
            totals.virtual_frames = totals
                .virtual_frames
                .saturating_add(events.saturating_mul(plan.virtual_allocations.frames as u64));
            totals.virtual_closures = totals
                .virtual_closures
                .saturating_add(events.saturating_mul(plan.virtual_allocations.closures as u64));
            totals.virtual_lists = totals
                .virtual_lists
                .saturating_add(events.saturating_mul(plan.virtual_allocations.lists as u64));
            totals.virtual_attrs = totals
                .virtual_attrs
                .saturating_add(events.saturating_mul(plan.virtual_allocations.attrs as u64));
            for statepoint in plan.statepoints {
                let index = statepoint_index(statepoint.kind);
                totals.statepoints[index] = totals.statepoints[index].saturating_add(*events);
            }
            for allocation in plan.virtual_allocation_sites {
                totals.virtual_sites.insert(AllocationSite {
                    module: key.module,
                    node: allocation.key.node,
                    kind: allocation.kind.into(),
                });
            }
        }
        totals
    }

    fn demand_region_trace_projection(
        &self,
        probe: &DemandRegionShadowProbe,
        roots: Vec<(EntryKey, u64)>,
    ) -> TraceProjection {
        let selected = linked_trace_entries(probe, &roots);
        let mut trace = TraceProjection {
            roots,
            linked_entries: selected.len(),
            ..TraceProjection::default()
        };

        for (key, events) in &probe.entries {
            match self.plan_trace_entry(*key) {
                Some(plan) => {
                    trace.global_operation_weight = trace
                        .global_operation_weight
                        .saturating_add(events.saturating_mul(plan.nodes.len() as u64));
                }
                None => {
                    trace.global_plan_failures = trace.global_plan_failures.saturating_add(1);
                }
            }
        }

        for (key, events) in &selected {
            let Some(plan) = self.plan_trace_entry(*key) else {
                trace.plan_failures = trace.plan_failures.saturating_add(1);
                continue;
            };
            match self.lower_trace_fragment(*key) {
                Some(region) => {
                    trace.grin_fragments = trace.grin_fragments.saturating_add(1);
                    trace.grin_operations = trace
                        .grin_operations
                        .saturating_add(region.accounting.operations as u64);
                }
                None => trace.grin_failures = trace.grin_failures.saturating_add(1),
            }
            trace.selected_operation_weight = trace
                .selected_operation_weight
                .saturating_add(events.saturating_mul(plan.nodes.len() as u64));
            for allocation in plan.virtual_allocation_sites {
                trace.virtual_sites.insert(AllocationSite {
                    module: key.module,
                    node: allocation.key.node,
                    kind: allocation.kind.into(),
                });
            }
            for statepoint in plan.statepoints {
                if statepoint.kind == PromiseStatepointKind::UnknownCall
                    && selected_guard_is_bounded(probe, *key, statepoint.key.node)
                {
                    continue;
                }
                trace.oracle_exit_events_upper =
                    trace.oracle_exit_events_upper.saturating_add(*events);
                if statepoint.kind == PromiseStatepointKind::Effect {
                    trace.effect_exit_events_upper =
                        trace.effect_exit_events_upper.saturating_add(*events);
                }
            }
        }

        for (caller_site, targets) in &probe.caller_guard_targets {
            if !selected.contains_key(&caller_site.caller) {
                continue;
            }
            let events = targets.values().copied().sum::<u64>();
            trace.guard_events = trace.guard_events.saturating_add(events);
            if targets.len() <= TRACE_GUARD_TARGET_CAP {
                trace.guard_hits = trace.guard_hits.saturating_add(events);
            }
        }
        trace
    }

    fn plan_trace_entry(&self, key: EntryKey) -> Option<crate::compile::PromiseRegionPlan> {
        let module = self.modules.get(key.module.index())?;
        plan_promise_region(
            &module.ir,
            key.body,
            key.frame,
            PromiseRegionOptions {
                symbol_validation: PromiseRegionSymbolValidation::ExternallyRemapped,
                ..PromiseRegionOptions::default()
            },
        )
        .ok()
    }

    fn lower_trace_fragment(
        &self,
        key: EntryKey,
    ) -> Option<crate::compile::grin_region::GrinRegion> {
        let module = self.modules.get(key.module.index())?;
        let fingerprint = lowered_ir_fingerprint(&module.ir).ok()?;
        crate::compile::grin_region::lower_grin_region(
            &module.ir,
            crate::compile::grin_region::GrinFragmentKey::new(
                crate::compile::grin_region::GrinDemandEpochId::new(0),
                crate::compile::grin_region::GrinModuleId::from_content_digest(
                    fingerprint.as_bytes(),
                ),
                key.body,
                key.frame,
            ),
            &[],
            crate::compile::grin_region::GrinRegionOptions {
                symbol_validation: PromiseRegionSymbolValidation::ExternallyRemapped,
                ..crate::compile::grin_region::GrinRegionOptions::default()
            },
        )
        .ok()
    }
}

fn trace_root_frontiers(probe: &DemandRegionShadowProbe) -> Vec<(usize, Vec<(EntryKey, u64)>)> {
    let ranked = hottest_trace_roots(probe, TRACE_ROOT_FRONTIERS[3]);
    TRACE_ROOT_FRONTIERS
        .into_iter()
        .map(|limit| (limit, ranked.iter().copied().take(limit).collect()))
        .collect()
}

fn hottest_trace_roots(probe: &DemandRegionShadowProbe, root_limit: usize) -> Vec<(EntryKey, u64)> {
    let mut caller_events = HashMap::<EntryKey, u64>::new();
    for (site, targets) in &probe.caller_guard_targets {
        let events = targets.values().copied().sum::<u64>();
        let total = caller_events.entry(site.caller).or_default();
        *total = total.saturating_add(events);
    }
    let mut roots = caller_events.into_iter().collect::<Vec<_>>();
    roots.sort_unstable_by(|(left_key, left_events), (right_key, right_events)| {
        right_events
            .cmp(left_events)
            .then_with(|| left_key.module.as_u32().cmp(&right_key.module.as_u32()))
            .then_with(|| left_key.body.as_u32().cmp(&right_key.body.as_u32()))
            .then_with(|| {
                left_key
                    .frame
                    .map(FrameId::as_u32)
                    .cmp(&right_key.frame.map(FrameId::as_u32))
            })
    });
    roots.truncate(root_limit);
    roots
        .into_iter()
        .map(|(key, _)| {
            let events = match probe.entries.get(&key).copied() {
                Some(events) => events,
                None => 0,
            };
            (key, events)
        })
        .collect()
}

fn linked_trace_entries(
    probe: &DemandRegionShadowProbe,
    roots: &[(EntryKey, u64)],
) -> HashMap<EntryKey, u64> {
    let mut selected = roots.iter().copied().collect::<HashMap<_, _>>();
    let mut pending = roots.iter().map(|(key, _)| *key).collect::<Vec<_>>();
    let mut expanded = HashSet::new();
    while let Some(caller) = pending.pop() {
        if !expanded.insert(caller) || selected.len() >= TRACE_MAX_ENTRIES {
            continue;
        }
        for (site, targets) in &probe.caller_guard_targets {
            if site.caller != caller || targets.len() > TRACE_GUARD_TARGET_CAP {
                continue;
            }
            for (target, events) in targets {
                let key = EntryKey {
                    kind: EntryKind::Apply,
                    module: target.module,
                    body: target.body,
                    frame: Some(target.frame),
                };
                let is_new = !selected.contains_key(&key);
                let total = selected.entry(key).or_default();
                *total = total.saturating_add(*events);
                if is_new {
                    pending.push(key);
                }
            }
        }
    }
    selected.retain(|key, events| {
        let Some(observed) = probe.entries.get(key).copied() else {
            return false;
        };
        *events = (*events).min(observed);
        *events != 0
    });
    selected
}

fn selected_guard_is_bounded(
    probe: &DemandRegionShadowProbe,
    caller: EntryKey,
    apply: IrId,
) -> bool {
    probe.caller_guard_targets.iter().any(|(site, targets)| {
        site.caller == caller && site.site.apply == apply && targets.len() <= TRACE_GUARD_TARGET_CAP
    })
}

fn statepoint_index(kind: PromiseStatepointKind) -> usize {
    match kind {
        PromiseStatepointKind::Effect => 0,
        PromiseStatepointKind::Global => 1,
        PromiseStatepointKind::DynamicScope => 2,
        PromiseStatepointKind::Dialect => 3,
        PromiseStatepointKind::RecursiveAttrSet => 4,
        PromiseStatepointKind::DynamicAttrSet => 5,
        PromiseStatepointKind::FormalSetLambda => 6,
        PromiseStatepointKind::DynamicSelect => 7,
        PromiseStatepointKind::DefaultSelect => 8,
        PromiseStatepointKind::UnknownCall => 9,
        PromiseStatepointKind::Unsupported => 10,
    }
}

fn emit_trace_report(probe: &DemandRegionShadowProbe, root_limit: usize, trace: &TraceProjection) {
    let selected_operation_weight = trace
        .selected_operation_weight
        .min(trace.global_operation_weight);
    let selected_operation_ppm =
        ratio_ppm(selected_operation_weight, trace.global_operation_weight);
    let virtualizable_instructions = mul_div(
        PROFILE_BASELINE_INSTRUCTIONS,
        PROFILE_VIRTUALIZABLE_INSTRUCTION_PPM,
        1_000_000,
    );
    let virtualizable_cycles = mul_div(
        PROFILE_BASELINE_CYCLES,
        PROFILE_VIRTUALIZABLE_CYCLE_PPM,
        1_000_000,
    );
    let covered_instructions = mul_div(
        virtualizable_instructions,
        selected_operation_ppm,
        1_000_000,
    );
    let covered_cycles = mul_div(virtualizable_cycles, selected_operation_ppm, 1_000_000);
    let ideal_instruction_floor =
        PROFILE_BASELINE_INSTRUCTIONS.saturating_sub(covered_instructions);
    let ideal_cycle_floor = PROFILE_BASELINE_CYCLES.saturating_sub(covered_cycles);
    let projected_instructions = PROFILE_BASELINE_INSTRUCTIONS.saturating_sub(mul_div(
        covered_instructions,
        TRACE_PROJECTED_ELIMINATION_PPM,
        1_000_000,
    ));
    let projected_cycles = PROFILE_BASELINE_CYCLES.saturating_sub(mul_div(
        covered_cycles,
        TRACE_PROJECTED_ELIMINATION_PPM,
        1_000_000,
    ));
    let instruction_coverage_ppm = ratio_ppm(covered_instructions, PROFILE_BASELINE_INSTRUCTIONS);
    let cycle_coverage_ppm = ratio_ppm(covered_cycles, PROFILE_BASELINE_CYCLES);
    let guard_denominator = trace
        .guard_events
        .saturating_add(probe.dropped_guard_sites)
        .saturating_add(probe.dropped_guard_targets)
        .saturating_add(probe.dropped_caller_guard_events);
    let guard_hit_ppm = ratio_ppm(trace.guard_hits, guard_denominator);
    let oracle_exit_ppm = ratio_ppm(trace.oracle_exit_events_upper, selected_operation_weight);
    let source_total = sum_source_tallies(probe.allocation_sites.values().copied());
    let source_matched = matched_source_tallies(&probe.allocation_sites, &trace.virtual_sites);
    let virtualized_bytes = source_matched
        .arena_bytes_exact
        .saturating_add(source_matched.external_bytes_lower_bound);
    let attributed_bytes = source_total
        .arena_bytes_exact
        .saturating_add(source_total.external_bytes_lower_bound);
    let virtualized_byte_ppm = ratio_ppm(virtualized_bytes, attributed_bytes);
    let roots = trace
        .roots
        .iter()
        .map(|(key, events)| {
            format!(
                "[{},{},{},{}]",
                key.module.as_u32(),
                key.body.as_u32(),
                key.frame.map(FrameId::as_u32).map_or(-1_i64, i64::from),
                events
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    eprintln!(
        "aos_nix_whole_demand_trace_shadow \
         {{\"mode\":\"report-only\",\"root_frontier_limit\":{},\"roots\":[{}],\
         \"static_plan\":{{\"root_count\":{},\"linked_entries\":{},\
         \"guard_target_cap\":{},\"plan_failures\":{},\
         \"global_plan_failures\":{},\
         \"grin_fragments\":{},\"grin_operations\":{},\"grin_failures\":{},\
         \"selected_operation_weight\":{},\"global_operation_weight\":{},\
         \"operation_weighted_coverage_ppm\":{}}},\
         \"guards\":{{\"events\":{},\"hits\":{},\"hit_ratio_ppm\":{},\
         \"dropped_sites\":{},\"dropped_targets\":{},\
         \"dropped_caller_events\":{}}},\
         \"exits\":{{\"effect_events_upper_bound\":{},\
         \"effect_or_oracle_events_upper_bound\":{},\"ratio_ppm\":{}}},\
         \"virtualized_allocations\":{{\"events\":{},\
         \"bytes_lower_bound\":{},\"attributed_bytes_lower_bound\":{},\
         \"byte_coverage_ppm\":{},\"sites\":{}}},\
         \"profile_projection\":{{\"source\":\"post-master-final-config-lean-2026-07-26\",\
         \"baseline_instructions\":{},\"baseline_cycles\":{},\
         \"profile_virtualizable_instruction_ppm\":{},\
         \"profile_virtualizable_cycle_ppm\":{},\
         \"instruction_weighted_coverage\":{},\
         \"instruction_weighted_coverage_ppm\":{},\
         \"cycle_weighted_coverage\":{},\"cycle_weighted_coverage_ppm\":{},\
         \"ideal_global_instruction_floor\":{},\"ideal_global_cycle_floor\":{},\
         \"assumed_elimination_ppm\":{},\
         \"projected_global_instructions\":{},\"projected_global_cycles\":{},\
         \"target_instructions\":{},\"target_cycles\":{},\
         \"ideal_instruction_floor_passes\":{},\"ideal_cycle_floor_passes\":{},\
         \"projected_instructions_pass\":{},\"projected_cycles_pass\":{}}},\
         \"contracts\":{{\"executes_regions\":false,\"widens_dispatch\":false,\
         \"retains_values\":false,\"uses_runtime_values_in_trace_key\":false,\
         \"unknown_calls_require_at_most_four_observed_code_identities\":true,\
         \"instruction_weights_are_external_profile_projection\":true}}}}",
        root_limit,
        roots,
        trace.roots.len(),
        trace.linked_entries,
        TRACE_GUARD_TARGET_CAP,
        trace.plan_failures,
        trace.global_plan_failures,
        trace.grin_fragments,
        trace.grin_operations,
        trace.grin_failures,
        selected_operation_weight,
        trace.global_operation_weight,
        selected_operation_ppm,
        trace.guard_events,
        trace.guard_hits,
        guard_hit_ppm,
        probe.dropped_guard_sites,
        probe.dropped_guard_targets,
        probe.dropped_caller_guard_events,
        trace.effect_exit_events_upper,
        trace.oracle_exit_events_upper,
        oracle_exit_ppm,
        source_matched.events,
        virtualized_bytes,
        attributed_bytes,
        virtualized_byte_ppm,
        trace.virtual_sites.len(),
        PROFILE_BASELINE_INSTRUCTIONS,
        PROFILE_BASELINE_CYCLES,
        PROFILE_VIRTUALIZABLE_INSTRUCTION_PPM,
        PROFILE_VIRTUALIZABLE_CYCLE_PPM,
        covered_instructions,
        instruction_coverage_ppm,
        covered_cycles,
        cycle_coverage_ppm,
        ideal_instruction_floor,
        ideal_cycle_floor,
        TRACE_PROJECTED_ELIMINATION_PPM,
        projected_instructions,
        projected_cycles,
        PROFILE_TARGET_INSTRUCTIONS,
        PROFILE_TARGET_CYCLES,
        ideal_instruction_floor < PROFILE_TARGET_INSTRUCTIONS,
        ideal_cycle_floor < PROFILE_TARGET_CYCLES,
        projected_instructions < PROFILE_TARGET_INSTRUCTIONS,
        projected_cycles < PROFILE_TARGET_CYCLES,
    );
}

fn ratio_ppm(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    mul_div(numerator, 1_000_000, denominator).min(1_000_000)
}

fn mul_div(value: u64, multiplier: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    let product = u128::from(value).saturating_mul(u128::from(multiplier));
    match u64::try_from(product / u128::from(divisor)) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    }
}

fn emit_report(
    probe: &DemandRegionShadowProbe,
    heap: crate::eval::heap::DemandRegionAllocationCensus,
    env: super::super::env::capture_stats::EnvCaptureStats,
    plans: PlanTotals,
) {
    let frame_struct_lower = env
        .env_frame_allocs
        .saturating_mul(std::mem::size_of::<EvalFrame>() as u64);
    let frame_bytes_lower = frame_struct_lower.max(env.env_frame_slot_bytes);
    let capture_bytes_lower = env
        .env_capture_frame_handles
        .saturating_mul(std::mem::size_of::<Arc<EvalFrame>>() as u64)
        .saturating_add(
            env.flat_env_capture_values
                .saturating_mul(std::mem::size_of::<Value>() as u64),
        )
        .saturating_add(
            env.with_env_capture_scopes
                .saturating_mul(std::mem::size_of::<EvalWithScope>() as u64),
        )
        .saturating_add(
            env.scoped_global_env_capture_scopes
                .saturating_mul(std::mem::size_of::<Value>() as u64),
        );
    let known_external_lower = heap
        .known_external_bytes()
        .saturating_add(frame_bytes_lower)
        .saturating_add(capture_bytes_lower);
    let all_known_lower = heap.arena_used_bytes().saturating_add(known_external_lower);

    let promise_class = heap.promises.requested_bytes;
    let closure_class = heap.closures.requested_bytes;
    let list_class = heap
        .lists
        .requested_bytes
        .saturating_add(heap.list_spine_bytes);
    let attrs_class = heap.attrs.requested_bytes;
    let frame_class = frame_bytes_lower;
    // This is deliberately a ceiling only within the classified requested-byte
    // mass: any class with at least one projected candidate grants the future
    // region every actual byte of that class, never more.
    let virtualizable_requested_ceiling = if plans.virtual_promises == 0 {
        0
    } else {
        promise_class
    }
    .saturating_add(if plans.virtual_closures == 0 {
        0
    } else {
        closure_class
    })
    .saturating_add(if plans.virtual_lists == 0 {
        0
    } else {
        list_class
    })
    .saturating_add(if plans.virtual_attrs == 0 {
        0
    } else {
        attrs_class
    })
    .saturating_add(if plans.virtual_frames == 0 {
        0
    } else {
        frame_class
    });
    let classified_requested = heap
        .requested_inline_bytes()
        .saturating_add(heap.list_spine_bytes)
        .saturating_add(frame_bytes_lower);
    let mandatory_oracle_requested_lower =
        classified_requested.saturating_sub(virtualizable_requested_ceiling);

    let guard_sites = probe.guard_targets.len() as u64;
    let guard_targets = probe
        .guard_targets
        .values()
        .map(|targets| targets.len() as u64)
        .sum::<u64>();
    let guard_events = probe
        .guard_targets
        .values()
        .flat_map(HashMap::values)
        .copied()
        .sum::<u64>();
    let best_four_guard_hits = probe
        .guard_targets
        .values()
        .map(|targets| {
            let mut events = targets.values().copied().collect::<Vec<_>>();
            events.sort_unstable_by(|left, right| right.cmp(left));
            events.into_iter().take(4).sum::<u64>()
        })
        .sum::<u64>();
    let guard_event_denominator = guard_events
        .saturating_add(probe.dropped_guard_sites)
        .saturating_add(probe.dropped_guard_targets);
    let monomorphic_guard_sites = probe
        .guard_targets
        .values()
        .filter(|targets| targets.len() == 1)
        .count() as u64;
    let max_guard_targets = probe
        .guard_targets
        .values()
        .map(HashMap::len)
        .max()
        .unwrap_or(0);
    let statepoint_total = plans.statepoints.iter().copied().sum::<u64>();
    let source_total = sum_source_tallies(probe.allocation_sites.values().copied());
    let source_matched = matched_source_tallies(&probe.allocation_sites, &plans.virtual_sites);

    eprintln!(
        "aos_nix_demand_region_shadow \
         {{\"fence_valid\":{},\
         \"global_denominators\":{{\"arena_used_bytes_exact\":{},\
         \"known_external_bytes_lower_bound\":{},\
         \"all_known_allocation_bytes_lower_bound\":{},\
         \"requested_inline_bytes_lower_bound\":{},\
         \"classified_requested_bytes_lower_bound\":{}}},\
         \"allocations\":{{\
         \"promises\":[{},{}],\"closures\":[{},{}],\"frames\":[{},{}],\
         \"lists\":[{},{},{}],\"attrs\":[{},{}],\"primops\":[{},{}],\
         \"strings_paths\":[{},{}],\"other\":[{},{}],\
         \"boxed_scalar_payload_bytes\":{},\"capture_payload_bytes_lower_bound\":{}}},\
         \"events\":{{\"force_source_body\":{},\"apply_user_lambda\":{},\
         \"entry_keys\":{},\"dropped_entry_events\":{}}},\
         \"guards\":{{\"sites\":{},\"targets\":{},\"events\":{},\
         \"monomorphic_sites\":{},\"max_targets_per_site\":{},\
         \"best_four_target_hits_lower_bound\":{},\
         \"event_denominator\":{},\
         \"dropped_sites\":{},\"dropped_targets\":{}}},\
         \"plans\":{{\"planned_entries\":{},\"failed_entries\":{},\
         \"planned_events\":{},\"failed_events\":{},\
         \"virtual_counts\":{{\"promises\":{},\"frames\":{},\"closures\":{},\
         \"lists\":{},\"attrs\":{}}},\
         \"statepoint_event_upper_bound\":{{\"total\":{},\"effect\":{},\
         \"global\":{},\"dynamic_scope\":{},\"dialect\":{},\
         \"recursive_attrset\":{},\"dynamic_attrset\":{},\
         \"formal_set_lambda\":{},\"dynamic_select\":{},\"default_select\":{},\
         \"unknown_call\":{},\"unsupported\":{}}}}},\
         \"materialization_bounds\":{{\
         \"source_attributed_allocation_events\":{},\
         \"source_attributed_bytes\":[{},{}],\
         \"planned_site_matched_events\":{},\
         \"planned_site_matched_bytes_lower_bound\":{},\
         \"planned_site_matched_arena_bytes_exact\":{},\
         \"virtualizable_requested_bytes_ceiling\":{},\
         \"mandatory_oracle_requested_bytes_lower_bound\":{}}},\
         \"map_caps\":{{\"entries\":{},\"guard_sites\":{},\
         \"targets_per_guard\":{},\"allocation_sites\":{},\
         \"dropped_allocation_sites\":{}}},\
         \"bounds\":{{\"arena_used_includes_padding\":true,\
         \"kind_bytes_are_requested_without_padding\":true,\
         \"list_spine_capacity_is_exact\":true,\
         \"frame_and_capture_bytes_are_lower_bounds\":true,\
         \"statepoint_events_are_runtime_entry_weighted_upper_bounds\":true,\
         \"virtualizable_ceiling_grants_all_bytes_of_each_candidate_class\":true,\
         \"planned_site_match_joins_module_node_and_kind\":true,\
         \"source_attr_bytes_cover_tree_walk_thunk_lambda_list_attrs_wrappers\":true,\
         \"excluded_from_external_lower_bound\":[\"hash_indexes\",\
         \"oversized_attr_vec_capacity\",\"allocator_metadata\",\"module_ir\",\
         \"derivation_store_materialization\"]}}}}",
        heap.fence_valid,
        heap.arena_used_bytes(),
        known_external_lower,
        all_known_lower,
        heap.requested_inline_bytes(),
        classified_requested,
        heap.promises.count,
        heap.promises.requested_bytes,
        heap.closures.count,
        heap.closures.requested_bytes,
        env.env_frame_allocs,
        frame_bytes_lower,
        heap.lists.count,
        heap.lists.requested_bytes,
        heap.list_spine_bytes,
        heap.attrs.count,
        heap.attrs.requested_bytes,
        heap.primops.count,
        heap.primops.requested_bytes,
        heap.strings_and_paths.count,
        heap.strings_and_paths.requested_bytes,
        heap.other.count,
        heap.other.requested_bytes,
        heap.boxed_scalar_payload_bytes,
        capture_bytes_lower,
        probe.force_events,
        probe.apply_events,
        probe.entries.len(),
        probe.dropped_entry_keys,
        guard_sites,
        guard_targets,
        guard_events,
        monomorphic_guard_sites,
        max_guard_targets,
        best_four_guard_hits,
        guard_event_denominator,
        probe.dropped_guard_sites,
        probe.dropped_guard_targets,
        plans.planned_entries,
        plans.failed_entries,
        plans.planned_events,
        plans.failed_events,
        plans.virtual_promises,
        plans.virtual_frames,
        plans.virtual_closures,
        plans.virtual_lists,
        plans.virtual_attrs,
        statepoint_total,
        plans.statepoints[0],
        plans.statepoints[1],
        plans.statepoints[2],
        plans.statepoints[3],
        plans.statepoints[4],
        plans.statepoints[5],
        plans.statepoints[6],
        plans.statepoints[7],
        plans.statepoints[8],
        plans.statepoints[9],
        plans.statepoints[10],
        source_total.events,
        source_total.arena_bytes_exact,
        source_total.external_bytes_lower_bound,
        source_matched.events,
        source_matched
            .arena_bytes_exact
            .saturating_add(source_matched.external_bytes_lower_bound),
        source_matched.arena_bytes_exact,
        virtualizable_requested_ceiling,
        mandatory_oracle_requested_lower,
        MAX_ENTRY_KEYS,
        MAX_GUARD_SITES,
        MAX_TARGETS_PER_GUARD,
        MAX_ALLOCATION_SITES,
        probe.dropped_allocation_sites,
    );
}

fn sum_source_tallies(tallies: impl Iterator<Item = AllocationSiteTally>) -> AllocationSiteTally {
    tallies.fold(AllocationSiteTally::default(), |mut sum, tally| {
        sum.events = sum.events.saturating_add(tally.events);
        sum.arena_bytes_exact = sum
            .arena_bytes_exact
            .saturating_add(tally.arena_bytes_exact);
        sum.external_bytes_lower_bound = sum
            .external_bytes_lower_bound
            .saturating_add(tally.external_bytes_lower_bound);
        sum
    })
}

fn matched_source_tallies(
    allocations: &HashMap<AllocationSite, AllocationSiteTally>,
    planned: &HashSet<AllocationSite>,
) -> AllocationSiteTally {
    sum_source_tallies(
        allocations
            .iter()
            .filter(|(site, _)| planned.contains(site))
            .map(|(_, tally)| *tally),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_entry_map_counts_repeats_without_retaining_values() {
        let mut probe = DemandRegionShadowProbe {
            fence: Some(DemandFence {
                heap: EvalHeap::new()
                    .demand_region_allocation_fence()
                    .expect("serial fence"),
                env: super::super::super::env::capture_stats::snapshot(),
            }),
            entries: HashMap::new(),
            guard_targets: HashMap::new(),
            caller_guard_targets: HashMap::new(),
            active_entries: Vec::new(),
            allocation_sites: HashMap::new(),
            trace_shadow_enabled: false,
            apply_events: 0,
            force_events: 0,
            dropped_entry_keys: 0,
            dropped_guard_sites: 0,
            dropped_guard_targets: 0,
            dropped_caller_guard_events: 0,
            dropped_allocation_sites: 0,
        };
        let key = EntryKey {
            kind: EntryKind::Force,
            module: EvalModuleId::ROOT,
            body: IrId::new(1),
            frame: None,
        };
        probe.note_entry(key);
        probe.note_entry(key);
        assert_eq!(probe.entries.get(&key), Some(&2));
        assert_eq!(probe.entries.len(), 1);
    }

    #[test]
    fn guard_population_counts_distinct_targets_and_events() {
        let heap = EvalHeap::new();
        let mut probe = DemandRegionShadowProbe {
            fence: Some(DemandFence {
                heap: heap.demand_region_allocation_fence().expect("serial fence"),
                env: super::super::super::env::capture_stats::snapshot(),
            }),
            entries: HashMap::new(),
            guard_targets: HashMap::new(),
            caller_guard_targets: HashMap::new(),
            active_entries: Vec::new(),
            allocation_sites: HashMap::new(),
            trace_shadow_enabled: false,
            apply_events: 0,
            force_events: 0,
            dropped_entry_keys: 0,
            dropped_guard_sites: 0,
            dropped_guard_targets: 0,
            dropped_caller_guard_events: 0,
            dropped_allocation_sites: 0,
        };
        let site = GuardSite {
            module: EvalModuleId::ROOT,
            apply: IrId::new(4),
        };
        let target = GuardTarget {
            module: EvalModuleId::ROOT,
            body: IrId::new(5),
            frame: FrameId::new(6),
        };
        probe.note_guard(site, target);
        probe.note_guard(site, target);
        assert_eq!(
            probe
                .guard_targets
                .get(&site)
                .and_then(|targets| targets.get(&target)),
            Some(&2)
        );
    }

    #[test]
    fn source_join_does_not_grant_unplanned_same_class_sites() {
        let planned_site = AllocationSite {
            module: EvalModuleId::ROOT,
            node: IrId::new(10),
            kind: AllocationKind::List,
        };
        let unplanned_site = AllocationSite {
            module: EvalModuleId::ROOT,
            node: IrId::new(11),
            kind: AllocationKind::List,
        };
        let allocations = HashMap::from([
            (
                planned_site,
                AllocationSiteTally {
                    events: 2,
                    arena_bytes_exact: 64,
                    external_bytes_lower_bound: 32,
                },
            ),
            (
                unplanned_site,
                AllocationSiteTally {
                    events: 20,
                    arena_bytes_exact: 640,
                    external_bytes_lower_bound: 320,
                },
            ),
        ]);
        let matched = matched_source_tallies(&allocations, &HashSet::from([planned_site]));
        assert_eq!(
            matched,
            AllocationSiteTally {
                events: 2,
                arena_bytes_exact: 64,
                external_bytes_lower_bound: 32,
            }
        );
    }

    #[test]
    fn trace_root_ranking_selects_four_guard_heaviest_callers() {
        let heap = EvalHeap::new();
        let mut probe = DemandRegionShadowProbe {
            fence: Some(DemandFence {
                heap: heap.demand_region_allocation_fence().expect("serial fence"),
                env: super::super::super::env::capture_stats::snapshot(),
            }),
            entries: HashMap::new(),
            guard_targets: HashMap::new(),
            caller_guard_targets: HashMap::new(),
            active_entries: Vec::new(),
            allocation_sites: HashMap::new(),
            trace_shadow_enabled: true,
            apply_events: 0,
            force_events: 0,
            dropped_entry_keys: 0,
            dropped_guard_sites: 0,
            dropped_guard_targets: 0,
            dropped_caller_guard_events: 0,
            dropped_allocation_sites: 0,
        };
        for body in 1_u32..=5 {
            let caller = EntryKey {
                kind: EntryKind::Apply,
                module: EvalModuleId::ROOT,
                body: IrId::new(body),
                frame: Some(FrameId::new(body)),
            };
            probe.entries.insert(caller, u64::from(body + 10));
            let site = GuardSite {
                module: EvalModuleId::ROOT,
                apply: IrId::new(body + 20),
            };
            probe.caller_guard_targets.insert(
                CallerGuardSite { caller, site },
                HashMap::from([(
                    GuardTarget {
                        module: EvalModuleId::ROOT,
                        body: IrId::new(99),
                        frame: FrameId::new(99),
                    },
                    u64::from(body),
                )]),
            );
        }
        let roots = hottest_trace_roots(&probe, 4);
        assert_eq!(roots.len(), 4);
        assert_eq!(
            roots
                .iter()
                .map(|(key, _)| key.body.as_u32())
                .collect::<Vec<_>>(),
            vec![5, 4, 3, 2]
        );
        assert_eq!(roots[0].1, 15);
    }

    #[test]
    fn trace_root_weight_uses_entry_executions_not_summed_guard_traffic() {
        let mut probe = test_trace_probe();
        let caller = EntryKey {
            kind: EntryKind::Apply,
            module: EvalModuleId::ROOT,
            body: IrId::new(60),
            frame: Some(FrameId::new(61)),
        };
        probe.entries.insert(caller, 3);
        for (apply, events) in [(70, 11), (71, 13)] {
            probe.caller_guard_targets.insert(
                CallerGuardSite {
                    caller,
                    site: GuardSite {
                        module: EvalModuleId::ROOT,
                        apply: IrId::new(apply),
                    },
                },
                HashMap::from([(
                    GuardTarget {
                        module: EvalModuleId::ROOT,
                        body: IrId::new(80),
                        frame: FrameId::new(81),
                    },
                    events,
                )]),
            );
        }
        let roots = hottest_trace_roots(&probe, 4);
        assert_eq!(roots, vec![(caller, 3)]);
    }

    #[test]
    fn trace_frontier_selected_sets_are_monotonic() {
        let mut probe = test_trace_probe();
        for body in 1_u32..=20 {
            let caller = EntryKey {
                kind: EntryKind::Apply,
                module: EvalModuleId::ROOT,
                body: IrId::new(body),
                frame: Some(FrameId::new(body)),
            };
            probe.entries.insert(caller, u64::from(body));
            probe.caller_guard_targets.insert(
                CallerGuardSite {
                    caller,
                    site: GuardSite {
                        module: EvalModuleId::ROOT,
                        apply: IrId::new(100 + body),
                    },
                },
                HashMap::from([(
                    GuardTarget {
                        module: EvalModuleId::ROOT,
                        body: IrId::new(body),
                        frame: FrameId::new(body),
                    },
                    u64::from(body),
                )]),
            );
        }
        let frontiers = trace_root_frontiers(&probe);
        for pair in frontiers.windows(2) {
            let left = linked_trace_entries(&probe, &pair[0].1)
                .into_keys()
                .collect::<HashSet<_>>();
            let right = linked_trace_entries(&probe, &pair[1].1)
                .into_keys()
                .collect::<HashSet<_>>();
            assert!(left.is_subset(&right));
        }
    }

    #[test]
    fn trace_frontier_weights_never_exceed_actual_entry_executions() {
        let mut probe = test_trace_probe();
        let target = EntryKey {
            kind: EntryKind::Apply,
            module: EvalModuleId::ROOT,
            body: IrId::new(90),
            frame: Some(FrameId::new(91)),
        };
        probe.entries.insert(target, 3);
        for body in 1_u32..=20 {
            let caller = EntryKey {
                kind: EntryKind::Apply,
                module: EvalModuleId::ROOT,
                body: IrId::new(body),
                frame: Some(FrameId::new(body)),
            };
            probe.entries.insert(caller, 2);
            probe.caller_guard_targets.insert(
                CallerGuardSite {
                    caller,
                    site: GuardSite {
                        module: EvalModuleId::ROOT,
                        apply: IrId::new(100 + body),
                    },
                },
                HashMap::from([(
                    GuardTarget {
                        module: target.module,
                        body: target.body,
                        frame: target.frame.expect("target frame"),
                    },
                    50,
                )]),
            );
        }
        for (_, roots) in trace_root_frontiers(&probe) {
            let selected = linked_trace_entries(&probe, &roots);
            assert_eq!(selected.get(&target), Some(&3));
            assert!(
                selected
                    .iter()
                    .all(|(key, events)| *events <= probe.entries[key])
            );
        }
    }

    #[test]
    fn trace_linker_follows_only_bounded_guard_target_sets() {
        let root = EntryKey {
            kind: EntryKind::Apply,
            module: EvalModuleId::ROOT,
            body: IrId::new(1),
            frame: Some(FrameId::new(1)),
        };
        let bounded_target = GuardTarget {
            module: EvalModuleId::ROOT,
            body: IrId::new(2),
            frame: FrameId::new(2),
        };
        let bounded_key = EntryKey {
            kind: EntryKind::Apply,
            module: bounded_target.module,
            body: bounded_target.body,
            frame: Some(bounded_target.frame),
        };
        let mut probe = test_trace_probe();
        probe.entries.insert(root, 10);
        probe.entries.insert(bounded_key, 7);
        probe.caller_guard_targets.insert(
            CallerGuardSite {
                caller: root,
                site: GuardSite {
                    module: EvalModuleId::ROOT,
                    apply: IrId::new(10),
                },
            },
            HashMap::from([(bounded_target, 7)]),
        );
        let overfull = (0_u32..=TRACE_GUARD_TARGET_CAP as u32)
            .map(|index| {
                (
                    GuardTarget {
                        module: EvalModuleId::ROOT,
                        body: IrId::new(30 + index),
                        frame: FrameId::new(30 + index),
                    },
                    1,
                )
            })
            .collect::<HashMap<_, _>>();
        probe.caller_guard_targets.insert(
            CallerGuardSite {
                caller: bounded_key,
                site: GuardSite {
                    module: EvalModuleId::ROOT,
                    apply: IrId::new(11),
                },
            },
            overfull,
        );

        let linked = linked_trace_entries(&probe, &[(root, 10)]);
        assert_eq!(linked.get(&root), Some(&10));
        assert_eq!(linked.get(&bounded_key), Some(&7));
        assert_eq!(linked.len(), 2);
    }

    #[test]
    fn trace_projection_math_is_saturating_and_zero_safe() {
        assert_eq!(ratio_ppm(1, 4), 250_000);
        assert_eq!(ratio_ppm(1, 0), 0);
        assert_eq!(ratio_ppm(u64::MAX, 1), 1_000_000);
        assert_eq!(mul_div(14_000_000_000, 700_000, 1_000_000), 9_800_000_000);
    }

    #[test]
    fn trace_guard_observation_is_owned_by_the_active_caller() {
        let mut probe = test_trace_probe();
        let caller = EntryKey {
            kind: EntryKind::Force,
            module: EvalModuleId::ROOT,
            body: IrId::new(40),
            frame: None,
        };
        let site = GuardSite {
            module: EvalModuleId::ROOT,
            apply: IrId::new(41),
        };
        let target = GuardTarget {
            module: EvalModuleId::ROOT,
            body: IrId::new(42),
            frame: FrameId::new(43),
        };
        probe.enter_entry(caller);
        probe.note_guard(site, target);
        probe.leave_entry();
        assert_eq!(
            probe
                .caller_guard_targets
                .get(&CallerGuardSite { caller, site })
                .and_then(|targets| targets.get(&target)),
            Some(&1)
        );
        assert!(probe.active_entries.is_empty());
    }

    fn test_trace_probe() -> DemandRegionShadowProbe {
        let heap = EvalHeap::new();
        DemandRegionShadowProbe {
            fence: Some(DemandFence {
                heap: heap.demand_region_allocation_fence().expect("serial fence"),
                env: super::super::super::env::capture_stats::snapshot(),
            }),
            entries: HashMap::new(),
            guard_targets: HashMap::new(),
            caller_guard_targets: HashMap::new(),
            active_entries: Vec::new(),
            allocation_sites: HashMap::new(),
            trace_shadow_enabled: true,
            apply_events: 0,
            force_events: 0,
            dropped_entry_keys: 0,
            dropped_guard_sites: 0,
            dropped_guard_targets: 0,
            dropped_caller_guard_events: 0,
            dropped_allocation_sites: 0,
        }
    }
}
