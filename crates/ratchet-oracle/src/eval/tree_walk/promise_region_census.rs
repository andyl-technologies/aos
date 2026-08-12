//! Runtime-weighted Promise/PIR entry admission census.
//!
//! Module roots are usually formal-set lambdas, so a structural root walk
//! measures wrapper syntax rather than executed demand. This default-off probe
//! records the module-qualified bodies that actually run, together with the
//! exact resolver frame for lambda calls, and plans each distinct entry only
//! after evaluation has finished.

use super::*;

/// The runtime seam that demanded a Promise/PIR entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RuntimeEntryKind {
    /// A user lambda body entered through the ordinary application seam.
    Lambda,
    /// A source-backed thunk body entered after a successful force claim.
    Thunk,
}

/// One module-qualified, frame-specialized runtime entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct RuntimeEntryKey {
    kind: RuntimeEntryKind,
    module: EvalModuleId,
    body: IrId,
    frame: Option<FrameId>,
}

/// One source application whose callee syntax is not a literal lambda.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct UnknownCallSiteKey {
    module: EvalModuleId,
    apply: IrId,
}

/// One concrete lambda target observed at an unknown source call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct RuntimeLambdaTarget {
    module: EvalModuleId,
    body: IrId,
    frame: FrameId,
}

/// Dynamic execution counts for distinct Promise/PIR entry candidates.
#[derive(Debug, Default)]
pub(super) struct PromiseRegionRuntimeCensus {
    entries: HashMap<RuntimeEntryKey, u64>,
    unknown_call_targets: HashMap<UnknownCallSiteKey, HashMap<RuntimeLambdaTarget, u64>>,
    active_entries: Vec<RuntimeEntryKey>,
    call_edges: HashMap<(RuntimeEntryKey, RuntimeEntryKey), u64>,
}

impl PromiseRegionRuntimeCensus {
    /// Allocates census state only for an explicitly requested diagnostic run.
    pub(super) fn from_env() -> Option<Self> {
        std::env::var("AOS_NIX_PROMISE_REGION_CENSUS")
            .is_ok_and(|value| value == "1")
            .then(Self::default)
    }

    fn note(&mut self, key: RuntimeEntryKey) {
        let count = self.entries.entry(key).or_default();
        *count = count.saturating_add(1);
    }
}

/// Aggregate counters for one terminal runtime-weighted report.
#[derive(Default)]
struct RuntimeReport {
    lambda_entries: u64,
    thunk_entries: u64,
    lambda_events: u64,
    thunk_events: u64,
    planned_entries: u64,
    failed_entries: u64,
    planned_events: u64,
    failed_events: u64,
    entry_only_events: u64,
    useful_virtual_events: u64,
    statepoint_free_events: u64,
    projected_region_nodes: u64,
    projected_virtual_promises: u64,
    projected_virtual_frames: u64,
    projected_virtual_closures: u64,
    projected_virtual_lists: u64,
    projected_virtual_attrs: u64,
    projected_statepoints: [u64; 11],
}

/// Summary retained for ranking the hottest distinct runtime entries.
struct RuntimeEntrySummary {
    key: RuntimeEntryKey,
    source: String,
    kinds: String,
    statepoint_kinds: String,
    events: u64,
    nodes: usize,
    virtual_allocations: usize,
    statepoints: usize,
    entry_only: bool,
}

impl TreeWalk {
    /// Records and enters an ordinary user-lambda body.
    pub(super) fn enter_promise_region_lambda_entry(&mut self, lambda: &EvalLambda) {
        #[cfg(feature = "demand_region_shadow_probe")]
        self.note_demand_region_apply(lambda);
        let Some(census) = self.promise_region_census.as_mut() else {
            return;
        };
        let key = RuntimeEntryKey {
            kind: RuntimeEntryKind::Lambda,
            module: lambda.module(),
            body: lambda.body(),
            frame: Some(lambda.frame()),
        };
        census.note(key);
        census.active_entries.push(key);
    }

    /// Leaves the innermost diagnostic Promise/PIR entry.
    pub(super) fn leave_promise_region_entry(&mut self) {
        #[cfg(feature = "demand_region_shadow_probe")]
        self.leave_demand_region_entry();
        let Some(census) = self.promise_region_census.as_mut() else {
            return;
        };
        let _ = census.active_entries.pop();
    }

    /// Records the concrete target of a syntactically unknown source Apply.
    pub(super) fn note_promise_region_unknown_call(
        &mut self,
        caller_module: EvalModuleId,
        apply: IrId,
        lambda: &EvalLambda,
    ) {
        let Some(module) = self.modules.get(caller_module.index()) else {
            return;
        };
        let Some(node) = module.ir.arena.node(apply) else {
            return;
        };
        let IrData::Pair { first, .. } = node.data else {
            return;
        };
        if node.kind != IrKind::Apply || syntactically_known_lambda(&module.ir, first) {
            return;
        }
        #[cfg(feature = "demand_region_shadow_probe")]
        self.note_demand_region_guard_target(caller_module, apply, lambda);
        let Some(census) = self.promise_region_census.as_mut() else {
            return;
        };
        let site = census
            .unknown_call_targets
            .entry(UnknownCallSiteKey {
                module: caller_module,
                apply,
            })
            .or_default();
        let count = site
            .entry(RuntimeLambdaTarget {
                module: lambda.module(),
                body: lambda.body(),
                frame: lambda.frame(),
            })
            .or_default();
        *count = count.saturating_add(1);
        if let Some(caller) = census.active_entries.last().copied() {
            let target = RuntimeEntryKey {
                kind: RuntimeEntryKind::Lambda,
                module: lambda.module(),
                body: lambda.body(),
                frame: Some(lambda.frame()),
            };
            let count = census.call_edges.entry((caller, target)).or_default();
            *count = count.saturating_add(1);
        }
    }

    /// Records a claimed source-backed thunk body entry.
    ///
    /// Thunk records retain runtime frames but not their resolver `FrameId`.
    /// The structural diagnostic therefore uses an unknown initial frame and
    /// reports thunk and exact-frame lambda populations separately. Executable
    /// admission must recover the thunk's lexical frame at its allocation site.
    pub(super) fn enter_promise_region_thunk_entry(&mut self, thunk: &EvalThunk) {
        #[cfg(feature = "demand_region_shadow_probe")]
        self.note_demand_region_force(thunk);
        let Some(body) = thunk.body_ref() else {
            return;
        };
        let Some(census) = self.promise_region_census.as_mut() else {
            return;
        };
        let key = RuntimeEntryKey {
            kind: RuntimeEntryKind::Thunk,
            module: body.module(),
            body: body.id(),
            frame: None,
        };
        census.note(key);
        census.active_entries.push(key);
    }

    /// Plans every distinct demanded entry and emits one runtime-weighted report.
    pub(super) fn emit_runtime_promise_region_census(&self) {
        let Some(census) = self.promise_region_census.as_ref() else {
            return;
        };
        self.emit_unknown_call_target_census(census);
        self.emit_runtime_call_graph(census);
        let mut report = RuntimeReport::default();
        let mut hottest = Vec::new();

        for (key, events) in &census.entries {
            match key.kind {
                RuntimeEntryKind::Lambda => {
                    report.lambda_entries = report.lambda_entries.saturating_add(1);
                    report.lambda_events = report.lambda_events.saturating_add(*events);
                }
                RuntimeEntryKind::Thunk => {
                    report.thunk_entries = report.thunk_entries.saturating_add(1);
                    report.thunk_events = report.thunk_events.saturating_add(*events);
                }
            }

            let Some(module) = self.modules.get(key.module.index()) else {
                report.failed_entries = report.failed_entries.saturating_add(1);
                report.failed_events = report.failed_events.saturating_add(*events);
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
                Err(error) => {
                    report.failed_entries = report.failed_entries.saturating_add(1);
                    report.failed_events = report.failed_events.saturating_add(*events);
                    eprintln!(
                        "aos_nix_promise_region_runtime_error \
                         {{\"kind\":{:?},\"module\":{},\"body\":{},\"events\":{},\
                         \"error\":{:?}}}",
                        key.kind,
                        key.module.as_u32(),
                        key.body.as_u32(),
                        events,
                        error.to_string(),
                    );
                    continue;
                }
            };

            report.planned_entries = report.planned_entries.saturating_add(1);
            report.planned_events = report.planned_events.saturating_add(*events);
            if plan.entry_is_only_statepoint {
                report.entry_only_events = report.entry_only_events.saturating_add(*events);
            }
            if !plan.entry_is_only_statepoint && plan.virtual_allocations.total() != 0 {
                report.useful_virtual_events = report.useful_virtual_events.saturating_add(*events);
            }
            if plan.statepoints.is_empty() {
                report.statepoint_free_events =
                    report.statepoint_free_events.saturating_add(*events);
            }
            report.projected_region_nodes = report
                .projected_region_nodes
                .saturating_add((*events).saturating_mul(plan.specialization_count as u64));
            report.projected_virtual_promises = report
                .projected_virtual_promises
                .saturating_add((*events).saturating_mul(plan.virtual_allocations.promises as u64));
            report.projected_virtual_frames = report
                .projected_virtual_frames
                .saturating_add((*events).saturating_mul(plan.virtual_allocations.frames as u64));
            report.projected_virtual_closures = report
                .projected_virtual_closures
                .saturating_add((*events).saturating_mul(plan.virtual_allocations.closures as u64));
            report.projected_virtual_lists = report
                .projected_virtual_lists
                .saturating_add((*events).saturating_mul(plan.virtual_allocations.lists as u64));
            report.projected_virtual_attrs = report
                .projected_virtual_attrs
                .saturating_add((*events).saturating_mul(plan.virtual_allocations.attrs as u64));
            for statepoint in &plan.statepoints {
                let index = statepoint_index(statepoint.kind);
                report.projected_statepoints[index] =
                    report.projected_statepoints[index].saturating_add(*events);
            }
            let source = module.source.as_ref().map_or_else(
                || "<source-less>".to_owned(),
                |source| String::from_utf8_lossy(&source.name).into_owned(),
            );
            let kinds = plan
                .nodes
                .iter()
                .filter_map(|planned| module.ir.arena.node(planned.key.node))
                .map(|node| format!("{:?}", node.kind))
                .collect::<Vec<_>>()
                .join(",");
            let statepoint_kinds = plan
                .statepoints
                .iter()
                .map(|statepoint| format!("{:?}", statepoint.kind))
                .collect::<Vec<_>>()
                .join(",");
            hottest.push(RuntimeEntrySummary {
                key: *key,
                source,
                kinds,
                statepoint_kinds,
                events: *events,
                nodes: plan.specialization_count,
                virtual_allocations: plan.virtual_allocations.total(),
                statepoints: plan.statepoints.len(),
                entry_only: plan.entry_is_only_statepoint,
            });
        }

        hottest.sort_unstable_by(|left, right| {
            right
                .events
                .cmp(&left.events)
                .then_with(|| left.key.module.as_u32().cmp(&right.key.module.as_u32()))
                .then_with(|| left.key.body.as_u32().cmp(&right.key.body.as_u32()))
        });
        for entry in hottest.iter().take(20) {
            eprintln!(
                "aos_nix_promise_region_runtime_hot \
                 {{\"kind\":{:?},\"module\":{},\"body\":{},\"frame\":{:?},\
                 \"source\":{:?},\"kinds\":{:?},\"statepoint_kinds\":{:?},\
                 \"events\":{},\"nodes\":{},\"virtual_allocations\":{},\
                 \"statepoints\":{},\"entry_only\":{}}}",
                entry.key.kind,
                entry.key.module.as_u32(),
                entry.key.body.as_u32(),
                entry.key.frame.map(FrameId::as_u32),
                entry.source,
                entry.kinds,
                entry.statepoint_kinds,
                entry.events,
                entry.nodes,
                entry.virtual_allocations,
                entry.statepoints,
                entry.entry_only,
            );
        }

        let entry_events = report.lambda_events.saturating_add(report.thunk_events);
        let projected_virtual_total = report
            .projected_virtual_promises
            .saturating_add(report.projected_virtual_frames)
            .saturating_add(report.projected_virtual_closures)
            .saturating_add(report.projected_virtual_lists)
            .saturating_add(report.projected_virtual_attrs);
        let projected_statepoint_total = report.projected_statepoints.iter().copied().sum::<u64>();
        eprintln!(
            "aos_nix_promise_region_runtime_census \
             {{\"entries\":{},\"events\":{entry_events},\
             \"lambda\":{{\"entries\":{},\"events\":{}}},\
             \"thunk\":{{\"entries\":{},\"events\":{}}},\
             \"planned\":{{\"entries\":{},\"events\":{}}},\
             \"failed\":{{\"entries\":{},\"events\":{}}},\
             \"entry_only_events\":{},\"useful_virtual_events\":{},\
             \"statepoint_free_events\":{},\
             \"projected_region_nodes\":{},\
             \"projected_virtual_allocations\":{{\"total\":{projected_virtual_total},\
             \"promises\":{},\"frames\":{},\"closures\":{},\"lists\":{},\"attrs\":{}}},\
             \"projected_statepoints\":{{\"total\":{projected_statepoint_total},\
             \"effect\":{},\"global\":{},\"dynamic_scope\":{},\"dialect\":{},\
             \"recursive_attrset\":{},\"dynamic_attrset\":{},\
             \"formal_set_lambda\":{},\"dynamic_select\":{},\
             \"default_select\":{},\"unknown_call\":{},\"unsupported\":{}}}}}",
            census.entries.len(),
            report.lambda_entries,
            report.lambda_events,
            report.thunk_entries,
            report.thunk_events,
            report.planned_entries,
            report.planned_events,
            report.failed_entries,
            report.failed_events,
            report.entry_only_events,
            report.useful_virtual_events,
            report.statepoint_free_events,
            report.projected_region_nodes,
            report.projected_virtual_promises,
            report.projected_virtual_frames,
            report.projected_virtual_closures,
            report.projected_virtual_lists,
            report.projected_virtual_attrs,
            report.projected_statepoints[0],
            report.projected_statepoints[1],
            report.projected_statepoints[2],
            report.projected_statepoints[3],
            report.projected_statepoints[4],
            report.projected_statepoints[5],
            report.projected_statepoints[6],
            report.projected_statepoints[7],
            report.projected_statepoints[8],
            report.projected_statepoints[9],
            report.projected_statepoints[10],
        );
    }

    fn emit_runtime_call_graph(&self, census: &PromiseRegionRuntimeCensus) {
        let mut callers = HashMap::<RuntimeEntryKey, (u64, HashSet<RuntimeEntryKey>)>::new();
        let mut edges = census
            .call_edges
            .iter()
            .map(|(edge, events)| (*edge, *events))
            .collect::<Vec<_>>();
        edges.sort_unstable_by(|left, right| right.1.cmp(&left.1));
        let mut total_events = 0_u64;
        for ((caller, target), events) in &census.call_edges {
            total_events = total_events.saturating_add(*events);
            let entry = callers.entry(*caller).or_default();
            entry.0 = entry.0.saturating_add(*events);
            entry.1.insert(*target);
        }
        let mut hottest = callers.into_iter().collect::<Vec<_>>();
        hottest.sort_unstable_by(|left, right| right.1.0.cmp(&left.1.0));
        let mut top_twenty_events = 0_u64;
        for (caller, (events, targets)) in hottest.iter().take(20) {
            top_twenty_events = top_twenty_events.saturating_add(*events);
            let source = self
                .modules
                .get(caller.module.index())
                .and_then(|module| module.source.as_ref())
                .map_or_else(
                    || "<source-less>".to_owned(),
                    |source| String::from_utf8_lossy(&source.name).into_owned(),
                );
            let span = self
                .modules
                .get(caller.module.index())
                .and_then(|module| module.ir.arena.node(caller.body))
                .map(|node| format!("{:?}", node.span))
                .unwrap_or_else(|| "Invalid".to_owned());
            eprintln!(
                "aos_nix_promise_call_graph_hot \
                 {{\"kind\":{:?},\"module\":{},\"body\":{},\"frame\":{:?},\
                 \"source\":{:?},\"span\":{:?},\"events\":{},\"targets\":{}}}",
                caller.kind,
                caller.module.as_u32(),
                caller.body.as_u32(),
                caller.frame.map(FrameId::as_u32),
                source,
                span,
                events,
                targets.len(),
            );
        }
        for ((caller, target), events) in edges.iter().take(30) {
            eprintln!(
                "aos_nix_promise_call_graph_edge \
                 {{\"caller_kind\":{:?},\"caller_module\":{},\"caller_body\":{},\
                 \"target_module\":{},\"target_body\":{},\"target_frame\":{:?},\
                 \"events\":{}}}",
                caller.kind,
                caller.module.as_u32(),
                caller.body.as_u32(),
                target.module.as_u32(),
                target.body.as_u32(),
                target.frame.map(FrameId::as_u32),
                events,
            );
        }
        eprintln!(
            "aos_nix_promise_call_graph_census \
             {{\"callers\":{},\"edges\":{},\"events\":{total_events},\
             \"top_twenty_events\":{top_twenty_events}}}",
            hottest.len(),
            census.call_edges.len(),
        );
    }

    fn emit_unknown_call_target_census(&self, census: &PromiseRegionRuntimeCensus) {
        let mut static_targets_by_module = HashMap::new();
        let mut flow_targets_by_module = HashMap::new();
        let mut static_analysis_errors = 0_u64;
        let mut flow_analysis_errors = 0_u64;
        let mut flow_inclusion_edges = 0_u64;
        let mut flow_activated_call_edges = 0_u64;
        let mut flow_worklist_pops = 0_u64;
        for site in census.unknown_call_targets.keys() {
            if static_targets_by_module.contains_key(&site.module) {
                continue;
            }
            let Some(module) = self.modules.get(site.module.index()) else {
                static_analysis_errors = static_analysis_errors.saturating_add(1);
                static_targets_by_module.insert(site.module, HashMap::new());
                continue;
            };
            let targets = match analyze_known_call_targets(&module.ir) {
                Ok(targets) => targets
                    .into_iter()
                    .map(|target| (target.apply, target.lambda))
                    .collect(),
                Err(error) => {
                    static_analysis_errors = static_analysis_errors.saturating_add(1);
                    eprintln!(
                        "aos_nix_promise_static_call_error \
                         {{\"module\":{},\"error\":{:?}}}",
                        site.module.as_u32(),
                        error.to_string(),
                    );
                    HashMap::new()
                }
            };
            static_targets_by_module.insert(site.module, targets);
            let targets = match analyze_call_target_candidates(&module.ir) {
                Ok(report) => {
                    flow_inclusion_edges =
                        flow_inclusion_edges.saturating_add(report.inclusion_edges as u64);
                    flow_activated_call_edges = flow_activated_call_edges
                        .saturating_add(report.activated_call_edges as u64);
                    flow_worklist_pops =
                        flow_worklist_pops.saturating_add(report.worklist_pops as u64);
                    report
                        .calls
                        .into_iter()
                        .map(|call| (call.apply, call))
                        .collect()
                }
                Err(error) => {
                    flow_analysis_errors = flow_analysis_errors.saturating_add(1);
                    eprintln!(
                        "aos_nix_promise_closure_flow_error \
                         {{\"module\":{},\"error\":{:?}}}",
                        site.module.as_u32(),
                        error.to_string(),
                    );
                    HashMap::new()
                }
            };
            flow_targets_by_module.insert(site.module, targets);
        }

        let mut total_events = 0_u64;
        let mut monomorphic_sites = 0_u64;
        let mut monomorphic_events = 0_u64;
        let mut small_polymorphic_sites = 0_u64;
        let mut small_polymorphic_events = 0_u64;
        let mut megamorphic_sites = 0_u64;
        let mut megamorphic_events = 0_u64;
        let mut statically_resolved_sites = 0_u64;
        let mut statically_resolved_events = 0_u64;
        let mut statically_matched_sites = 0_u64;
        let mut statically_matched_events = 0_u64;
        let mut static_mismatch_sites = 0_u64;
        let mut static_mismatch_events = 0_u64;
        let mut flow_candidate_sites = 0_u64;
        let mut flow_candidate_events = 0_u64;
        let mut flow_guard_hit_events = 0_u64;
        let mut flow_singleton_sites = 0_u64;
        let mut flow_singleton_events = 0_u64;
        let mut flow_singleton_guard_hit_events = 0_u64;
        let mut flow_small_set_sites = 0_u64;
        let mut flow_small_set_events = 0_u64;
        let mut flow_overflow_sites = 0_u64;
        let mut flow_overflow_events = 0_u64;
        let mut function_kind_counts = HashMap::<String, (u64, u64, u64, u64)>::new();
        let mut hottest = Vec::new();

        for (site, targets) in &census.unknown_call_targets {
            let events = targets.values().copied().fold(0_u64, u64::saturating_add);
            total_events = total_events.saturating_add(events);
            match targets.len() {
                0 => {}
                1 => {
                    monomorphic_sites = monomorphic_sites.saturating_add(1);
                    monomorphic_events = monomorphic_events.saturating_add(events);
                }
                2..=4 => {
                    small_polymorphic_sites = small_polymorphic_sites.saturating_add(1);
                    small_polymorphic_events = small_polymorphic_events.saturating_add(events);
                }
                _ => {
                    megamorphic_sites = megamorphic_sites.saturating_add(1);
                    megamorphic_events = megamorphic_events.saturating_add(events);
                }
            }
            if let Some(candidates) = flow_targets_by_module
                .get(&site.module)
                .and_then(|targets| targets.get(&site.apply))
            {
                if !candidates.lambdas.is_empty() {
                    flow_candidate_sites = flow_candidate_sites.saturating_add(1);
                    flow_candidate_events = flow_candidate_events.saturating_add(events);
                }
                match (candidates.lambdas.len(), candidates.overflow) {
                    (1, false) => {
                        flow_singleton_sites = flow_singleton_sites.saturating_add(1);
                        flow_singleton_events = flow_singleton_events.saturating_add(events);
                    }
                    (2..=4, false) => {
                        flow_small_set_sites = flow_small_set_sites.saturating_add(1);
                        flow_small_set_events = flow_small_set_events.saturating_add(events);
                    }
                    (_, true) => {
                        flow_overflow_sites = flow_overflow_sites.saturating_add(1);
                        flow_overflow_events = flow_overflow_events.saturating_add(events);
                    }
                    _ => {}
                }
                let mut matched_events = 0_u64;
                for lambda in &candidates.lambdas {
                    let Some(expected) = self
                        .modules
                        .get(site.module.index())
                        .and_then(|module| module.ir.arena.node(*lambda))
                        .and_then(|node| match node.data {
                            IrData::Lambda {
                                body,
                                frame: Some(frame),
                                ..
                            } => Some(RuntimeLambdaTarget {
                                module: site.module,
                                body,
                                frame,
                            }),
                            _ => None,
                        })
                    else {
                        continue;
                    };
                    matched_events =
                        matched_events.saturating_add(targets.get(&expected).copied().unwrap_or(0));
                }
                flow_guard_hit_events = flow_guard_hit_events.saturating_add(matched_events);
                if candidates.lambdas.len() == 1 && !candidates.overflow {
                    flow_singleton_guard_hit_events =
                        flow_singleton_guard_hit_events.saturating_add(matched_events);
                }
            }
            let static_lambda = static_targets_by_module
                .get(&site.module)
                .and_then(|targets| targets.get(&site.apply));
            if let Some(lambda) = static_lambda {
                statically_resolved_sites = statically_resolved_sites.saturating_add(1);
                statically_resolved_events = statically_resolved_events.saturating_add(events);
                let expected = self
                    .modules
                    .get(site.module.index())
                    .and_then(|module| module.ir.arena.node(*lambda))
                    .and_then(|node| match node.data {
                        IrData::Lambda {
                            body,
                            frame: Some(frame),
                            ..
                        } => Some(RuntimeLambdaTarget {
                            module: site.module,
                            body,
                            frame,
                        }),
                        _ => None,
                    });
                let matched_events = expected
                    .and_then(|target| targets.get(&target).copied())
                    .unwrap_or(0);
                statically_matched_events =
                    statically_matched_events.saturating_add(matched_events);
                if matched_events == events {
                    statically_matched_sites = statically_matched_sites.saturating_add(1);
                } else {
                    static_mismatch_sites = static_mismatch_sites.saturating_add(1);
                    static_mismatch_events = static_mismatch_events
                        .saturating_add(events.saturating_sub(matched_events));
                }
            }
            let (function_kind, function_data) = self
                .modules
                .get(site.module.index())
                .and_then(|module| module.ir.arena.node(site.apply).map(|node| (module, node)))
                .and_then(|(module, node)| match node.data {
                    IrData::Pair { first, .. } if node.kind == IrKind::Apply => {
                        module.ir.arena.node(first).map(|function| {
                            (
                                format!("{:?}", function.kind),
                                format!("{:?}", function.data),
                            )
                        })
                    }
                    _ => None,
                })
                .unwrap_or_else(|| ("Invalid".to_owned(), "Invalid".to_owned()));
            let kind_counts = function_kind_counts
                .entry(function_kind.clone())
                .or_default();
            kind_counts.0 = kind_counts.0.saturating_add(1);
            kind_counts.1 = kind_counts.1.saturating_add(events);
            if static_lambda.is_some() {
                kind_counts.2 = kind_counts.2.saturating_add(1);
                kind_counts.3 = kind_counts.3.saturating_add(events);
            }
            let mut target_counts = targets.iter().collect::<Vec<_>>();
            target_counts.sort_unstable_by(|left, right| right.1.cmp(left.1));
            let target_summary = target_counts
                .iter()
                .take(8)
                .map(|(target, count)| {
                    format!(
                        "{}:{}/{}={count}",
                        target.module.as_u32(),
                        target.body.as_u32(),
                        target.frame.as_u32()
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            hottest.push((
                *site,
                events,
                targets.len(),
                target_summary,
                function_kind,
                function_data,
            ));
        }
        hottest.sort_unstable_by(|left, right| right.1.cmp(&left.1));
        for (site, events, targets, target_summary, function_kind, function_data) in
            hottest.iter().take(20)
        {
            let source = self
                .modules
                .get(site.module.index())
                .and_then(|module| module.source.as_ref())
                .map_or_else(
                    || "<source-less>".to_owned(),
                    |source| String::from_utf8_lossy(&source.name).into_owned(),
                );
            eprintln!(
                "aos_nix_promise_unknown_call_hot \
                 {{\"module\":{},\"apply\":{},\"source\":{:?},\"events\":{},\
                 \"function_kind\":{:?},\"function_data\":{:?},\
                 \"target_count\":{},\"targets\":{:?}}}",
                site.module.as_u32(),
                site.apply.as_u32(),
                source,
                events,
                function_kind,
                function_data,
                targets,
                target_summary,
            );
        }
        let mut function_kinds = function_kind_counts.into_iter().collect::<Vec<_>>();
        function_kinds.sort_unstable_by(|left, right| right.1.1.cmp(&left.1.1));
        for (kind, (sites, events, resolved_sites, resolved_events)) in function_kinds {
            eprintln!(
                "aos_nix_promise_unknown_call_kind \
                 {{\"kind\":{kind:?},\"sites\":{sites},\"events\":{events},\
                 \"resolved_sites\":{resolved_sites},\
                 \"resolved_events\":{resolved_events}}}"
            );
        }
        eprintln!(
            "aos_nix_promise_unknown_call_census \
             {{\"sites\":{},\"events\":{total_events},\
             \"monomorphic\":{{\"sites\":{monomorphic_sites},\
             \"events\":{monomorphic_events}}},\
             \"small_polymorphic\":{{\"sites\":{small_polymorphic_sites},\
             \"events\":{small_polymorphic_events}}},\
             \"megamorphic\":{{\"sites\":{megamorphic_sites},\
             \"events\":{megamorphic_events}}}}}",
            census.unknown_call_targets.len(),
        );
        eprintln!(
            "aos_nix_promise_static_call_census \
             {{\"observed_sites\":{},\"observed_events\":{total_events},\
             \"resolved\":{{\"sites\":{statically_resolved_sites},\
             \"events\":{statically_resolved_events}}},\
             \"matched\":{{\"sites\":{statically_matched_sites},\
             \"events\":{statically_matched_events}}},\
             \"mismatch\":{{\"sites\":{static_mismatch_sites},\
             \"events\":{static_mismatch_events}}},\
             \"analysis_errors\":{static_analysis_errors}}}",
            census.unknown_call_targets.len(),
        );
        eprintln!(
            "aos_nix_promise_closure_flow_census \
             {{\"observed_sites\":{},\"observed_events\":{total_events},\
             \"candidates\":{{\"sites\":{flow_candidate_sites},\
             \"events\":{flow_candidate_events},\
             \"guard_hit_events\":{flow_guard_hit_events}}},\
             \"singleton\":{{\"sites\":{flow_singleton_sites},\
             \"events\":{flow_singleton_events},\
             \"guard_hit_events\":{flow_singleton_guard_hit_events}}},\
             \"small_set\":{{\"sites\":{flow_small_set_sites},\
             \"events\":{flow_small_set_events}}},\
             \"overflow\":{{\"sites\":{flow_overflow_sites},\
             \"events\":{flow_overflow_events}}},\
             \"solver\":{{\"inclusion_edges\":{flow_inclusion_edges},\
             \"activated_call_edges\":{flow_activated_call_edges},\
             \"worklist_pops\":{flow_worklist_pops}}},\
             \"analysis_errors\":{flow_analysis_errors}}}",
            census.unknown_call_targets.len(),
        );
    }
}

fn syntactically_known_lambda(ir: &Ir, mut node: IrId) -> bool {
    for depth in 0..=1 {
        let Some(current) = ir.arena.node(node) else {
            return false;
        };
        if current.kind == IrKind::Lambda {
            return true;
        }
        let IrData::Node(body) = current.data else {
            return false;
        };
        if current.kind != IrKind::ThunkAlloc || depth != 0 {
            return false;
        }
        node = body;
    }
    false
}

const fn statepoint_index(kind: PromiseStatepointKind) -> usize {
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
