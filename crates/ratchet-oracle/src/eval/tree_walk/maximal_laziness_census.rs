//! Projected duplicate-work census for maximal-laziness experiments.
//!
//! The probe records a sound lower bound: two executions match only when they
//! have the same module-qualified body and the exact raw identities of every
//! captured slot read by that body. It is compiled out unless the
//! `maximal_laziness_probe` feature is enabled and remains inactive unless
//! `AOS_NIX_MAXIMAL_LAZINESS_CENSUS=1` is set.

use std::cell::Cell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::*;

const MAX_KEYS: usize = 65_536;
const MAX_CONFIGURED_KEYS: usize = 1_048_576;
const MAX_TOP_SITES: usize = 32;

/// One exact representation identity in a projected lexical environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ProjectedValue {
    tag: ValueTag,
    bits: u64,
}

impl ProjectedValue {
    fn from_value(value: Value) -> Self {
        Self {
            tag: value.tag(),
            bits: value.transient_identity_bits(),
        }
    }
}

/// An exact body plus the raw identities of the captured values it reads.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct DuplicateWorkKey {
    body: EvalNodeRef,
    projected: Box<[ProjectedValue]>,
}

#[derive(Clone, Debug)]
enum SitePlan {
    Eligible(Box<[(usize, u32)]>),
    Rejected(DeclineKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeclineKind {
    DynamicScope,
    Effect,
    UnsupportedShape,
    Dependency,
    MissingSlot,
}

#[derive(Clone, Copy, Debug, Default)]
struct KeyStats {
    allocations: u64,
    force_attempts: u64,
    successful_forces: u64,
    error_forces: u64,
    successful_nanos: u64,
    repeat_successful_forces: u64,
    repeat_successful_nanos: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct SiteStats {
    allocations: u64,
    force_attempts: u64,
    successful_forces: u64,
    error_forces: u64,
    successful_nanos: u64,
    repeat_successful_forces: u64,
    repeat_successful_nanos: u64,
}

/// A token spanning one admitted body execution.
pub(super) struct DuplicateWorkToken {
    key: Option<DuplicateWorkKey>,
    started: Instant,
}

/// Per-evaluator state for the compile-time-only census.
#[derive(Debug)]
pub(super) struct MaximalLazinessRuntimeCensus {
    active: bool,
    refusal: Option<&'static str>,
    reported: Cell<bool>,
    key_limit: usize,
    keys: HashMap<DuplicateWorkKey, KeyStats>,
    sites: HashMap<EvalNodeRef, SiteStats>,
    plans: HashMap<(EvalNodeRef, usize), SitePlan>,
    allocations: u64,
    force_attempts: u64,
    successful_forces: u64,
    error_forces: u64,
    successful_nanos: u64,
    repeat_successful_forces: u64,
    repeat_successful_nanos: u64,
    avoidable_record_bytes: u64,
    total_node_allocations: u64,
    total_node_record_bytes: u64,
    total_node_force_attempts: u64,
    total_node_successful_forces: u64,
    total_node_successful_nanos: u64,
    overflow_keys: u64,
    declined_dynamic_scope: u64,
    declined_effect: u64,
    declined_unsupported_shape: u64,
    declined_dependency: u64,
    declined_missing_slot: u64,
}

impl MaximalLazinessRuntimeCensus {
    /// Constructs the census only for an explicit, collector-free serial run.
    pub(super) fn from_env(options: &TreeWalkOptions) -> Option<Self> {
        if !std::env::var("AOS_NIX_MAXIMAL_LAZINESS_CENSUS").is_ok_and(|value| value == "1") {
            return None;
        }
        let refusal =
            if options.parallel_workers().is_some() || options.parallel_thunk_payloads_enabled() {
                Some("parallel")
            } else if options.gc_mode() != EvalGcMode::Off
                || options.gc_stress_policy() != GcStressPolicy::disabled()
                || options.thunk_resolve_barrier_tier() != GenerationalGcTier::OneShotArena
            {
                Some("non-tier-a")
            } else if options.memo_active() || options.memo_options().stats_enabled {
                Some("memo")
            } else if options.jit_tier1_publish_enabled() {
                Some("jit")
            } else if options.eval_cache_enabled() || options.persist_cache_root().is_some() {
                Some("force-cache")
            } else {
                None
            };
        let key_limit = std::env::var("AOS_NIX_MAXIMAL_LAZINESS_MAX_KEYS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|limit| (1..=MAX_CONFIGURED_KEYS).contains(limit))
            .unwrap_or(MAX_KEYS);
        Some(Self::new(refusal, key_limit))
    }

    fn new(refusal: Option<&'static str>, key_limit: usize) -> Self {
        Self {
            active: refusal.is_none(),
            refusal,
            reported: Cell::new(false),
            key_limit,
            keys: HashMap::new(),
            sites: HashMap::new(),
            plans: HashMap::new(),
            allocations: 0,
            force_attempts: 0,
            successful_forces: 0,
            error_forces: 0,
            successful_nanos: 0,
            repeat_successful_forces: 0,
            repeat_successful_nanos: 0,
            avoidable_record_bytes: 0,
            total_node_allocations: 0,
            total_node_record_bytes: 0,
            total_node_force_attempts: 0,
            total_node_successful_forces: 0,
            total_node_successful_nanos: 0,
            overflow_keys: 0,
            declined_dynamic_scope: 0,
            declined_effect: 0,
            declined_unsupported_shape: 0,
            declined_dependency: 0,
            declined_missing_slot: 0,
        }
    }

    pub(super) const fn is_active(&self) -> bool {
        self.active
    }

    pub(super) fn disable_for_jit(&mut self) {
        self.active = false;
        self.refusal = Some("jit-engine-installed");
    }

    fn record_decline(&mut self, kind: DeclineKind) {
        let counter = match kind {
            DeclineKind::DynamicScope => &mut self.declined_dynamic_scope,
            DeclineKind::Effect => &mut self.declined_effect,
            DeclineKind::UnsupportedShape => &mut self.declined_unsupported_shape,
            DeclineKind::Dependency => &mut self.declined_dependency,
            DeclineKind::MissingSlot => &mut self.declined_missing_slot,
        };
        *counter = counter.saturating_add(1);
    }

    fn admit_key(&mut self, key: DuplicateWorkKey) -> Option<&mut KeyStats> {
        if self.keys.contains_key(&key) {
            return self.keys.get_mut(&key);
        }
        if self.keys.len() >= self.key_limit {
            self.overflow_keys = self.overflow_keys.saturating_add(1);
            return None;
        }
        Some(self.keys.entry(key).or_default())
    }

    fn observe_allocation(&mut self, key: DuplicateWorkKey) {
        let body = key.body;
        let duplicate = {
            let Some(stats) = self.admit_key(key) else {
                return;
            };
            let duplicate = stats.allocations > 0;
            stats.allocations = stats.allocations.saturating_add(1);
            duplicate
        };
        self.allocations = self.allocations.saturating_add(1);
        let site = self.sites.entry(body).or_default();
        site.allocations = site.allocations.saturating_add(1);
        if duplicate {
            self.avoidable_record_bytes = self
                .avoidable_record_bytes
                .saturating_add(std::mem::size_of::<EvalThunk>() as u64);
        }
    }

    fn observe_node_allocation(&mut self) {
        self.total_node_allocations = self.total_node_allocations.saturating_add(1);
        self.total_node_record_bytes = self
            .total_node_record_bytes
            .saturating_add(std::mem::size_of::<EvalThunk>() as u64);
    }

    fn begin_node_force(&mut self, key: Option<DuplicateWorkKey>) -> DuplicateWorkToken {
        self.total_node_force_attempts = self.total_node_force_attempts.saturating_add(1);
        let key = key.and_then(|key| {
            let body = key.body;
            let stats = self.admit_key(key.clone())?;
            stats.force_attempts = stats.force_attempts.saturating_add(1);
            self.force_attempts = self.force_attempts.saturating_add(1);
            let site = self.sites.entry(body).or_default();
            site.force_attempts = site.force_attempts.saturating_add(1);
            Some(key)
        });
        DuplicateWorkToken {
            key,
            started: Instant::now(),
        }
    }

    fn finish_force(&mut self, token: DuplicateWorkToken, succeeded: bool) {
        let elapsed = elapsed_nanos(token.started.elapsed());
        if succeeded {
            self.total_node_successful_forces = self.total_node_successful_forces.saturating_add(1);
            self.total_node_successful_nanos =
                self.total_node_successful_nanos.saturating_add(elapsed);
        }
        let Some(key) = token.key else {
            return;
        };
        let body = key.body;
        let Some(stats) = self.keys.get_mut(&key) else {
            return;
        };
        let site = self.sites.entry(body).or_default();
        if succeeded {
            let repeated = stats.successful_forces > 0;
            stats.successful_forces = stats.successful_forces.saturating_add(1);
            stats.successful_nanos = stats.successful_nanos.saturating_add(elapsed);
            site.successful_forces = site.successful_forces.saturating_add(1);
            site.successful_nanos = site.successful_nanos.saturating_add(elapsed);
            self.successful_forces = self.successful_forces.saturating_add(1);
            self.successful_nanos = self.successful_nanos.saturating_add(elapsed);
            if repeated {
                stats.repeat_successful_forces = stats.repeat_successful_forces.saturating_add(1);
                stats.repeat_successful_nanos =
                    stats.repeat_successful_nanos.saturating_add(elapsed);
                site.repeat_successful_forces = site.repeat_successful_forces.saturating_add(1);
                site.repeat_successful_nanos = site.repeat_successful_nanos.saturating_add(elapsed);
                self.repeat_successful_forces = self.repeat_successful_forces.saturating_add(1);
                self.repeat_successful_nanos = self.repeat_successful_nanos.saturating_add(elapsed);
            }
        } else {
            stats.error_forces = stats.error_forces.saturating_add(1);
            site.error_forces = site.error_forces.saturating_add(1);
            self.error_forces = self.error_forces.saturating_add(1);
        }
    }
}

fn elapsed_nanos(elapsed: Duration) -> u64 {
    elapsed.as_nanos().min(u128::from(u64::MAX)) as u64
}

impl TreeWalk {
    fn maximal_laziness_key_for_thunk(&mut self, thunk: &EvalThunk) -> Option<DuplicateWorkKey> {
        if !self
            .maximal_laziness_census
            .as_ref()
            .is_some_and(MaximalLazinessRuntimeCensus::is_active)
        {
            return None;
        }
        let EvalThunkKind::Node { body, env } = thunk.kind() else {
            return None;
        };
        if thunk.dynamic_env().is_some() {
            if let Some(census) = self.maximal_laziness_census.as_mut() {
                census.record_decline(DeclineKind::DynamicScope);
            }
            return None;
        }
        let plan_key = (*body, env.frame_count());
        let cached = self
            .maximal_laziness_census
            .as_ref()
            .and_then(|census| census.plans.get(&plan_key))
            .cloned();
        let plan = match cached {
            Some(plan) => plan,
            None => {
                let plan = self.maximal_laziness_site_plan(*body, env.frame_count());
                if let Some(census) = self.maximal_laziness_census.as_mut() {
                    census.plans.insert(plan_key, plan.clone());
                }
                plan
            }
        };
        let slots = match plan {
            SitePlan::Eligible(slots) => slots,
            SitePlan::Rejected(kind) => {
                if let Some(census) = self.maximal_laziness_census.as_mut() {
                    census.record_decline(kind);
                }
                return None;
            }
        };
        let mut projected = Vec::new();
        if projected.try_reserve_exact(slots.len()).is_err() {
            if let Some(census) = self.maximal_laziness_census.as_mut() {
                census.record_decline(DeclineKind::Dependency);
            }
            return None;
        }
        for (frame_index, slot) in slots.iter().copied() {
            let Some(value) = self.captured_env_value_at_index(env, frame_index, slot) else {
                if let Some(census) = self.maximal_laziness_census.as_mut() {
                    census.record_decline(DeclineKind::MissingSlot);
                }
                return None;
            };
            projected.push(ProjectedValue::from_value(value));
        }
        Some(DuplicateWorkKey {
            body: *body,
            projected: projected.into_boxed_slice(),
        })
    }

    fn maximal_laziness_site_plan(&self, body: EvalNodeRef, frames: usize) -> SitePlan {
        let Some(module) = self.modules.get(body.module().index()) else {
            return SitePlan::Rejected(DeclineKind::UnsupportedShape);
        };
        if let Err(kind) = maximal_laziness_subtree_is_safe(&module.ir, body.id()) {
            return SitePlan::Rejected(kind);
        }
        match Self::captured_free_variable_slots(&module.ir, body.id(), frames) {
            Some(slots) => SitePlan::Eligible(slots.into_iter().collect()),
            None => SitePlan::Rejected(DeclineKind::Dependency),
        }
    }

    pub(super) fn note_maximal_laziness_allocation(&mut self, thunk: &EvalThunk) {
        if !self
            .maximal_laziness_census
            .as_ref()
            .is_some_and(MaximalLazinessRuntimeCensus::is_active)
            || !matches!(thunk.kind(), EvalThunkKind::Node { .. })
        {
            return;
        }
        if let Some(census) = self.maximal_laziness_census.as_mut() {
            census.observe_node_allocation();
        }
        let key = self.maximal_laziness_key_for_thunk(thunk);
        let Some(key) = key else { return };
        if let Some(census) = self.maximal_laziness_census.as_mut() {
            census.observe_allocation(key);
        }
    }

    pub(super) fn begin_maximal_laziness_force(
        &mut self,
        thunk: &EvalThunk,
    ) -> Option<DuplicateWorkToken> {
        if !self
            .maximal_laziness_census
            .as_ref()
            .is_some_and(MaximalLazinessRuntimeCensus::is_active)
            || !matches!(thunk.kind(), EvalThunkKind::Node { .. })
        {
            return None;
        }
        let key = self.maximal_laziness_key_for_thunk(thunk);
        Some(self.maximal_laziness_census.as_mut()?.begin_node_force(key))
    }

    pub(super) fn finish_maximal_laziness_force(
        &mut self,
        token: Option<DuplicateWorkToken>,
        succeeded: bool,
    ) {
        if let (Some(census), Some(token)) = (self.maximal_laziness_census.as_mut(), token) {
            census.finish_force(token, succeeded);
        }
    }

    pub(super) fn disable_maximal_laziness_for_jit(&mut self) {
        if let Some(census) = self.maximal_laziness_census.as_mut() {
            census.disable_for_jit();
        }
    }

    pub(super) fn emit_maximal_laziness_census_once(&self) {
        let Some(census) = self.maximal_laziness_census.as_ref() else {
            return;
        };
        if census.reported.replace(true) {
            return;
        }
        if let Some(refusal) = census.refusal {
            eprintln!(
                "aos_nix_maximal_laziness_census {{\"active\":false,\"refusal\":\"{refusal}\"}}"
            );
            return;
        }
        let repeat_successful_nanos_share_ppm = if census.total_node_successful_nanos == 0 {
            0
        } else {
            census.repeat_successful_nanos.saturating_mul(1_000_000)
                / census.total_node_successful_nanos
        };
        eprintln!(
            "aos_nix_maximal_laziness_census {{\"active\":true,\
             \"key_limit\":{},\"keys\":{},\"overflow_keys\":{},\
             \"total_node_allocations\":{},\"total_node_record_bytes\":{},\
             \"total_node_force_attempts\":{},\"total_node_successful_forces\":{},\
             \"total_node_successful_nanos\":{},\
             \"allocations\":{},\"force_attempts\":{},\
             \"successful_forces\":{},\"error_forces\":{},\
             \"successful_nanos\":{},\"repeat_successful_forces\":{},\
             \"repeat_successful_nanos\":{},\"repeat_successful_nanos_share_ppm\":{},\
             \"avoidable_node_record_bytes_lower_bound\":{},\
             \"declined_dynamic_scope\":{},\"declined_effect\":{},\
             \"declined_unsupported_shape\":{},\"declined_dependency\":{},\
             \"declined_missing_slot\":{}}}",
            census.key_limit,
            census.keys.len(),
            census.overflow_keys,
            census.total_node_allocations,
            census.total_node_record_bytes,
            census.total_node_force_attempts,
            census.total_node_successful_forces,
            census.total_node_successful_nanos,
            census.allocations,
            census.force_attempts,
            census.successful_forces,
            census.error_forces,
            census.successful_nanos,
            census.repeat_successful_forces,
            census.repeat_successful_nanos,
            repeat_successful_nanos_share_ppm,
            census.avoidable_record_bytes,
            census.declined_dynamic_scope,
            census.declined_effect,
            census.declined_unsupported_shape,
            census.declined_dependency,
            census.declined_missing_slot,
        );
        let mut sites = census.sites.iter().collect::<Vec<_>>();
        sites.sort_unstable_by(|left, right| {
            right
                .1
                .repeat_successful_nanos
                .cmp(&left.1.repeat_successful_nanos)
        });
        for (body, stats) in sites.into_iter().take(MAX_TOP_SITES) {
            let span = self
                .modules
                .get(body.module().index())
                .and_then(|module| module.ir.arena.node(body.id()))
                .map_or(Span::default(), |node| node.span);
            eprintln!(
                "aos_nix_maximal_laziness_site {{\"module\":{},\"body\":{},\
                 \"span_start\":{},\"span_end\":{},\"allocations\":{},\
                 \"force_attempts\":{},\"successful_forces\":{},\"error_forces\":{},\
                 \"successful_nanos\":{},\"repeat_successful_forces\":{},\
                 \"repeat_successful_nanos\":{}}}",
                body.module().as_u32(),
                body.id().as_u32(),
                span.start,
                span.end,
                stats.allocations,
                stats.force_attempts,
                stats.successful_forces,
                stats.error_forces,
                stats.successful_nanos,
                stats.repeat_successful_forces,
                stats.repeat_successful_nanos,
            );
        }
    }
}

/// Accepts only operations whose evaluation cannot invoke an unknown function,
/// observe dynamic state, emit output, import, or allocate nested lazy work.
fn maximal_laziness_subtree_is_safe(ir: &Ir, root: IrId) -> Result<(), DeclineKind> {
    let mut visited = Vec::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if visited.contains(&id.as_u32()) {
            continue;
        }
        visited.push(id.as_u32());
        let node = ir.arena.node(id).ok_or(DeclineKind::UnsupportedShape)?;
        if !node.effect.is_speculable() {
            return Err(DeclineKind::Effect);
        }
        match (node.kind, node.data) {
            (
                IrKind::Int
                | IrKind::Float
                | IrKind::Bool
                | IrKind::Null
                | IrKind::Str
                | IrKind::Uri
                | IrKind::Path
                | IrKind::LocalVar
                | IrKind::UpvalVar,
                _,
            ) => {}
            (IrKind::Assert, IrData::Pair { first, second }) => {
                stack.push(first);
                stack.push(second);
            }
            (
                IrKind::If,
                IrData::Triple {
                    first,
                    second,
                    third,
                },
            ) => {
                stack.push(first);
                stack.push(second);
                stack.push(third);
            }
            (IrKind::BinOp, IrData::Binary { op, lhs, rhs })
                if !matches!(op, BinOpKind::PipeLeft | BinOpKind::PipeRight) =>
            {
                stack.push(lhs);
                stack.push(rhs);
            }
            (IrKind::UnaryOp, IrData::Unary { operand, .. }) => stack.push(operand),
            (
                IrKind::Select,
                IrData::Select {
                    receiver,
                    path,
                    default,
                    ..
                },
            ) => {
                let segments = ir
                    .attr_paths
                    .get(path.index())
                    .ok_or(DeclineKind::UnsupportedShape)?;
                if segments
                    .iter()
                    .any(|segment| !matches!(segment, IrAttrPathSegment::Static(_)))
                {
                    return Err(DeclineKind::UnsupportedShape);
                }
                stack.push(receiver);
                stack.extend(default);
            }
            (IrKind::HasAttr, IrData::HasAttr { receiver, path, .. }) => {
                let segments = ir
                    .attr_paths
                    .get(path.index())
                    .ok_or(DeclineKind::UnsupportedShape)?;
                if segments
                    .iter()
                    .any(|segment| !matches!(segment, IrAttrPathSegment::Static(_)))
                {
                    return Err(DeclineKind::UnsupportedShape);
                }
                stack.push(receiver);
            }
            _ => return Err(DeclineKind::UnsupportedShape),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(body: u32, projected: &[ProjectedValue]) -> DuplicateWorkKey {
        DuplicateWorkKey {
            body: EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(body)),
            projected: projected.into(),
        }
    }

    #[test]
    fn successful_repeats_exclude_prior_errors() {
        let mut census = MaximalLazinessRuntimeCensus::new(None, 8);
        let key = key(1, &[]);
        let first = census.begin_node_force(Some(key.clone()));
        census.finish_force(first, false);
        let second = census.begin_node_force(Some(key.clone()));
        census.finish_force(second, true);
        assert_eq!(census.repeat_successful_forces, 0);
        let third = census.begin_node_force(Some(key));
        census.finish_force(third, true);
        assert_eq!(census.repeat_successful_forces, 1);
        assert_eq!(census.total_node_force_attempts, 3);
        assert_eq!(census.total_node_successful_forces, 2);
    }

    #[test]
    fn duplicate_allocations_count_only_the_record_lower_bound() {
        let mut census = MaximalLazinessRuntimeCensus::new(None, 8);
        let key = key(2, &[]);
        census.observe_allocation(key.clone());
        census.observe_allocation(key);
        assert_eq!(census.allocations, 2);
        assert_eq!(
            census.avoidable_record_bytes,
            std::mem::size_of::<EvalThunk>() as u64
        );
    }

    #[test]
    fn bounded_map_keeps_updating_resident_keys() {
        let mut census = MaximalLazinessRuntimeCensus::new(None, 1);
        let resident = key(3, &[]);
        census.observe_allocation(resident.clone());
        census.observe_allocation(key(4, &[]));
        census.observe_allocation(resident);
        assert_eq!(census.keys.len(), 1);
        assert_eq!(census.overflow_keys, 1);
        assert_eq!(census.allocations, 2);
    }
}
