//! Content-memo probe, record, and CHECK logic on the claimed-force path
//! (RFC-0007 MEMO-1).
//!
//! During one cold evaluation, distinct-but-content-identical subtrees should
//! evaluate once: at eligible force sites this module derives a content key —
//! the def-site's stable [`CacheExprIdentity`] combined with the captured
//! free-variable [`ValueHash`]es through the ordered, length-prefixed
//! [`DemandCacheKey::for_free_vars`] combiner — probes the L0 (per-worker)
//! and L1 (in-process shared) tables, and on a hit replays the memoized
//! payload instead of evaluating the body. On a miss it evaluates through the
//! existing force path and admits the result when eligible.
//!
//! # Admission and economics
//!
//! The memo never probes on the bare force path. Admission is decided per
//! def-site from a static lowered-IR cost estimate (an early-exiting subtree
//! walk in the `ratchet-jit` cost-model mold) against the
//! `AOS_NIX_MEMO_MIN_COST` floor, cached in `TreeWalk::memo_def_sites` so a
//! non-admitted def-site pays only an indexed lookup per force. Per-force
//! (environment-dependent) eligibility additionally requires every captured
//! free variable to have a durable value hash: environments capturing
//! unforced thunks decline admission in MEMO-1 (the recursive thunk-keying
//! extension is a measured follow-up).
//!
//! # Correctness regime
//!
//! Every entry carries its canonicalized per-subtree impure-observation
//! slice, captured with the same trace-cursor seam the force cache uses; a
//! hit revalidates every slice entry against the current world or misses.
//! Heap-backed payloads are the force cache's closed replayable encoding, so a
//! hit re-allocates the value in the consuming worker's heap — no heap handles
//! cross tiers. L0 stores self-contained immediate words directly; Candidate-C
//! boxed scalars remain payload-backed because their words name arena cells.
//! `AOS_NIX_MEMO_CHECK` shadows every hit at a checked tier with a fresh
//! evaluation and asserts canonical-hash identity, mirroring
//! `AOS_NIX_ROOT_CUTOFF_CHECK`.
//!
//! The independent GC-off local Ready mode normally keys a weak source-thunk
//! directory by exact raw capture recipes. Its `EMPTY_ONLY` specialization
//! retains capture-free results directly in the cached def-site plan, so a
//! warm hit needs neither recipe construction nor a source-cell load.
//!
//! [`CacheExprIdentity`]: crate::cache::CacheExprIdentity
//! [`ValueHash`]: crate::cache::ValueHash

use std::time::Instant;

use super::force_identity::CapturedFreeVariableDependency;
use super::*;
use crate::cache::{CacheableInputFingerprint, DemandCacheKey};
use crate::eval::tree_walk::memo::{
    MemoDefSiteDecision, MemoDefSiteState, MemoDirectValue, MemoEntry, MemoL0Entry,
    ReadyCellCandidate, ReadyCellCapturePlan, ReadyCellCaptures, ReadyCellEmptyProbe,
    ReadyCellHitRepresentation, ReadyCellPlanDecision, ReadyCellRecipe, SharedMemoTable,
};

/// Consecutive per-force derivation declines before a def-site is gated.
///
/// A def-site whose captured environments fail durable hashing pays the
/// free-variable dependency walk (and partial value hashing) on every force
/// with no chance of a hit; after this many consecutive declines (with no
/// successful derivation in between) the site flips to
/// [`MemoDefSiteDecision::Skipped`] permanently, bounding the decline tax at
/// one derivation attempt per def-site — the same first-decision gating the
/// tier-1 skipped-def-site set uses. The cost is that a def-site whose first
/// instance captures an unhashable environment loses later hit
/// opportunities; the serial non-regression gate is what this buys.
const MEMO_DECLINE_GATE: u32 = 1;

/// A fully derived memo candidate for one claimed thunk force.
///
/// Carries the content key and the replay subject (position-remap module and
/// allocation node) needed to capture or rehydrate payloads for this force.
pub(in crate::eval::tree_walk) struct MemoCandidate {
    key: DemandCacheKey,
    subject: ForceCacheSubject,
    static_cost_units: u32,
}

/// Static per-node recompute-cost units for the memo admission floor.
///
/// Mirrors the `ratchet-jit` cost-model approach: coarse per-kind unit costs
/// summed over the lowered subtree, used only to compare against the
/// `AOS_NIX_MEMO_MIN_COST` floor (placement in the in-memory tiers needs no
/// finer resolution). Applications and primops carry the bulk weight because
/// they dominate real recompute time.
const fn memo_node_cost(kind: IrKind) -> u32 {
    match kind {
        IrKind::Int
        | IrKind::Float
        | IrKind::Bool
        | IrKind::Null
        | IrKind::LocalVar
        | IrKind::UpvalVar
        | IrKind::GlobalVar => 1,
        IrKind::Str
        | IrKind::Uri
        | IrKind::Path
        | IrKind::BinOp
        | IrKind::UnaryOp
        | IrKind::Interp
        | IrKind::If
        | IrKind::Assert
        | IrKind::Let
        | IrKind::With
        | IrKind::ThunkAlloc
        | IrKind::Lambda
        | IrKind::FormalSet
        | IrKind::Formal => 2,
        IrKind::List | IrKind::AttrSet | IrKind::Select | IrKind::HasAttr | IrKind::SearchPath => 4,
        IrKind::Apply | IrKind::PrimOp | IrKind::BuiltinAttr => 16,
    }
}

fn elapsed_nanos(started: Instant) -> u64 {
    let nanos = started.elapsed().as_nanos();
    if nanos > u128::from(u64::MAX) {
        u64::MAX
    } else {
        nanos as u64
    }
}

impl TreeWalk {
    /// Runs the content-memo probe/record protocol around a claimed force.
    ///
    /// When no memo tier is active (or the thunk is not an eligible node
    /// body), this delegates directly to the existing memoized force path and
    /// is byte-for-byte identical to it. On an L0/L1 hit the memoized payload
    /// is replayed, published through the normal
    /// [`finish_forced_value`](Self::finish_forced_value) claim-completion
    /// path (so the thunk cell, cycle bookkeeping, and parallel publication
    /// see one mechanism), and the recorded impure observations are re-fed
    /// into the evaluation trace. On a miss the body evaluates normally and
    /// the result is admitted when its observation slice is complete and its
    /// value has a closed replayable encoding.
    pub(in crate::eval::tree_walk) fn force_claimed_thunk_with_memo(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        thunk: &EvalThunk,
        guard: ForceGuard<'_>,
    ) -> Result<Value, TreeWalkError> {
        let tiers_active = self.memo_l0.is_some() || self.shared_memo_table().is_some();
        let stats_enabled = self.options.memo_options().stats_enabled;
        let local_ready_active = self.ready_cell_directory.is_some();
        let empty_ready_only =
            local_ready_active && self.options.memo_options().local_ready_empty_only;
        if !tiers_active && !stats_enabled && !local_ready_active {
            return self.force_memoized_claimed_thunk(id, span, source_thunk, thunk, guard);
        }
        if empty_ready_only
            && let Some((def_site, captured_frame_count, probe)) =
                self.probe_empty_ready_cell_plan(thunk)
        {
            match probe {
                ReadyCellEmptyProbe::Hit(value) => {
                    return match self.finish_forced_value(id, span, source_thunk, guard, value) {
                        Ok(value) => Ok(value),
                        Err(error) => {
                            if let Some(plans) = self.ready_cell_plans.as_mut() {
                                plans.clear_empty(def_site);
                            }
                            Err(error)
                        }
                    };
                }
                ReadyCellEmptyProbe::Miss => {
                    return match self.force_memoized_claimed_thunk(
                        id,
                        span,
                        source_thunk,
                        thunk,
                        guard,
                    ) {
                        Ok(value) => {
                            if let Some(plans) = self.ready_cell_plans.as_mut() {
                                plans.publish_empty(def_site, captured_frame_count, value);
                            }
                            Ok(value)
                        }
                        Err(error) => Err(error),
                    };
                }
                ReadyCellEmptyProbe::Unknown => {}
                ReadyCellEmptyProbe::Ineligible => {}
            }
        }
        let ready_cell_candidate = if empty_ready_only && !stats_enabled {
            None
        } else {
            self.ready_cell_candidate_for_thunk(thunk)
        };
        if !empty_ready_only
            && let Some(candidate) = ready_cell_candidate.as_ref()
            && let Some(value) = self.probe_ready_cell_directory(candidate)
        {
            return match self.finish_forced_value(id, span, source_thunk, guard, value) {
                Ok(value) => {
                    self.mark_ready_cell_candidate_ready(Some(candidate));
                    Ok(value)
                }
                Err(error) => {
                    self.mark_ready_cell_candidate_failed(Some(candidate));
                    Err(error)
                }
            };
        }
        if local_ready_active && !empty_ready_only && ready_cell_candidate.is_some() {
            return match self.force_memoized_claimed_thunk(id, span, source_thunk, thunk, guard) {
                Ok(value) => {
                    self.mark_ready_cell_candidate_ready(ready_cell_candidate.as_ref());
                    self.publish_ready_cell_candidate(ready_cell_candidate.as_ref(), source_thunk);
                    Ok(value)
                }
                Err(error) => {
                    self.mark_ready_cell_candidate_failed(ready_cell_candidate.as_ref());
                    Err(error)
                }
            };
        }
        let key_started = stats_enabled.then(Instant::now);
        let candidate = self.memo_candidate_for_thunk(thunk);
        self.record_memo_key_timing(key_started);
        let Some(candidate) = candidate else {
            return match self.force_memoized_claimed_thunk(id, span, source_thunk, thunk, guard) {
                Ok(value) => {
                    self.mark_ready_cell_candidate_ready(ready_cell_candidate.as_ref());
                    self.publish_ready_cell_candidate(ready_cell_candidate.as_ref(), source_thunk);
                    Ok(value)
                }
                Err(error) => {
                    self.mark_ready_cell_candidate_failed(ready_cell_candidate.as_ref());
                    Err(error)
                }
            };
        };
        self.observe_memo_potential_hit(&candidate);
        if !tiers_active {
            return match self.force_memoized_claimed_thunk(id, span, source_thunk, thunk, guard) {
                Ok(value) => {
                    self.mark_memo_recipe_ready(&candidate);
                    self.mark_ready_cell_candidate_ready(ready_cell_candidate.as_ref());
                    self.publish_ready_cell_candidate(ready_cell_candidate.as_ref(), source_thunk);
                    Ok(value)
                }
                Err(error) => {
                    self.mark_memo_recipe_failed(&candidate);
                    self.mark_ready_cell_candidate_failed(ready_cell_candidate.as_ref());
                    Err(error)
                }
            };
        }
        let probe = match self.memo_probe(id, span, thunk, &candidate) {
            Ok(probe) => probe,
            Err(error) => {
                if stats_enabled {
                    self.mark_memo_recipe_failed(&candidate);
                }
                self.mark_ready_cell_candidate_failed(ready_cell_candidate.as_ref());
                return Err(error);
            }
        };
        if let Some(value) = probe {
            let value = match self.finish_forced_value(id, span, source_thunk, guard, value) {
                Ok(value) => value,
                Err(error) => {
                    if stats_enabled {
                        self.mark_memo_recipe_failed(&candidate);
                    }
                    self.mark_ready_cell_candidate_failed(ready_cell_candidate.as_ref());
                    return Err(error);
                }
            };
            if stats_enabled {
                self.mark_memo_recipe_ready(&candidate);
            }
            self.mark_ready_cell_candidate_ready(ready_cell_candidate.as_ref());
            return Ok(value);
        }
        let cursor = self.impure_input_trace_cursor();
        let value = match self.force_memoized_claimed_thunk(id, span, source_thunk, thunk, guard) {
            Ok(value) => value,
            Err(error) => {
                if stats_enabled {
                    self.mark_memo_recipe_failed(&candidate);
                }
                self.mark_ready_cell_candidate_failed(ready_cell_candidate.as_ref());
                return Err(error);
            }
        };
        if stats_enabled {
            self.mark_memo_recipe_ready(&candidate);
        }
        self.mark_ready_cell_candidate_ready(ready_cell_candidate.as_ref());
        self.publish_ready_cell_candidate(ready_cell_candidate.as_ref(), source_thunk);
        let record_started = stats_enabled.then(Instant::now);
        self.memo_admit(&candidate, value, cursor);
        self.record_memo_record_timing(record_started);
        Ok(value)
    }

    /// Probes the direct capture-free Ready plan without constructing a recipe.
    fn probe_empty_ready_cell_plan(
        &mut self,
        thunk: &EvalThunk,
    ) -> Option<(EvalNodeRef, usize, ReadyCellEmptyProbe)> {
        let EvalThunkKind::Node { body, env, .. } = thunk.kind() else {
            return None;
        };
        if !thunk.with_scope_env()?.scopes().is_empty()
            || !thunk.scoped_global_env()?.scopes().is_empty()
        {
            return None;
        }
        let captured_frame_count = self.captured_env_ref(env).frame_count();
        let probe = self
            .ready_cell_plans
            .as_mut()?
            .probe_empty(*body, captured_frame_count);
        if !matches!(probe, ReadyCellEmptyProbe::Unknown) {
            return Some((*body, captured_frame_count, probe));
        }
        let plan = self.compute_ready_cell_plan(*body, captured_frame_count);
        let plans = self.ready_cell_plans.as_mut()?;
        plans.insert(*body, plan);
        Some((
            *body,
            captured_frame_count,
            plans.probe_empty(*body, captured_frame_count),
        ))
    }

    /// Derives a cheap worker-local recipe from direct static slot captures.
    ///
    /// The recipe intentionally uses relocation-sensitive raw words. It
    /// declines dynamic scopes, effectful or lookup-unsafe bodies, and static
    /// select/has-attr projections: those cases need a stronger equivalence
    /// proof than pointer identity of the projection receiver.
    fn ready_cell_candidate_for_thunk(&mut self, thunk: &EvalThunk) -> Option<ReadyCellCandidate> {
        let EvalThunkKind::Node { body, env, .. } = thunk.kind() else {
            return None;
        };
        if self.ready_cell_census.is_none() && self.ready_cell_directory.is_none() {
            return None;
        }
        if !thunk.with_scope_env()?.scopes().is_empty()
            || !thunk.scoped_global_env()?.scopes().is_empty()
        {
            self.stats.memo_economics.ready_cell_dynamic_scope_declines = self
                .stats
                .memo_economics
                .ready_cell_dynamic_scope_declines
                .saturating_add(1);
            return None;
        }

        let env = self.captured_env_ref(env);
        if self
            .ready_cell_plans
            .as_ref()
            .and_then(|plans| plans.get(*body))
            .is_none()
        {
            let plan = self.compute_ready_cell_plan(*body, env.frame_count());
            self.ready_cell_plans.as_mut()?.insert(*body, plan);
        }
        let plan = self.ready_cell_plans.as_ref()?.get(*body)?;
        let (capture_plan, static_cost_units) = match plan {
            ReadyCellPlanDecision::Eligible {
                captured_frame_count,
                captures,
                static_cost_units,
                ..
            } if *captured_frame_count == env.frame_count() => (captures, *static_cost_units),
            ReadyCellPlanDecision::Eligible { .. } | ReadyCellPlanDecision::Unavailable => {
                return None;
            }
            ReadyCellPlanDecision::BelowFloor => return None,
            ReadyCellPlanDecision::EffectOrUnsafe => {
                self.stats
                    .memo_economics
                    .ready_cell_effect_or_unsafe_declines = self
                    .stats
                    .memo_economics
                    .ready_cell_effect_or_unsafe_declines
                    .saturating_add(1);
                return None;
            }
            ReadyCellPlanDecision::NonSlot => {
                self.stats.memo_economics.ready_cell_non_slot_declines = self
                    .stats
                    .memo_economics
                    .ready_cell_non_slot_declines
                    .saturating_add(1);
                return None;
            }
        };

        let capture_identity = |(frame_index, slot): (usize, u32)| {
            self.env_ref_value_at_index(env, frame_index, slot)
                .map(Value::relocation_sensitive_identity_bits)
        };
        let captures = match capture_plan {
            ReadyCellCapturePlan::Empty => ReadyCellCaptures::Empty,
            ReadyCellCapturePlan::One(capture) => {
                ReadyCellCaptures::One(capture_identity(*capture)?)
            }
            ReadyCellCapturePlan::Two(captures) => ReadyCellCaptures::Two([
                capture_identity(captures[0])?,
                capture_identity(captures[1])?,
            ]),
            ReadyCellCapturePlan::Many(plan) => {
                let mut captures = Vec::new();
                captures.try_reserve_exact(plan.len()).ok()?;
                for capture in plan.iter().copied() {
                    captures.push(capture_identity(capture)?);
                }
                ReadyCellCaptures::Many(captures.into_boxed_slice())
            }
        };
        let candidate = ReadyCellCandidate {
            recipe: ReadyCellRecipe::new(*body, captures),
            static_cost_units,
        };
        if self.ready_cell_census.is_some() {
            let representation = ReadyCellHitRepresentation::classify(
                candidate.recipe.arity(),
                env.flat_base.is_some(),
                !env.frames.is_empty(),
            );
            self.observe_ready_cell_candidate(&candidate, representation);
        }
        Some(candidate)
    }

    /// Classifies one Ready-cell def-site and validates its direct-slot plan.
    fn compute_ready_cell_plan(
        &self,
        body: EvalNodeRef,
        captured_frame_count: usize,
    ) -> ReadyCellPlanDecision {
        let Some(module) = self.modules.get(body.module().index()) else {
            return ReadyCellPlanDecision::Unavailable;
        };
        let Some(static_cost_units) =
            Self::subtree_is_speculable(&module.ir, &self.symbols, body.id())
                .then(|| self.memo_static_cost(body))
                .flatten()
        else {
            return ReadyCellPlanDecision::EffectOrUnsafe;
        };
        if static_cost_units < self.options.memo_options().local_ready_min_cost {
            return ReadyCellPlanDecision::BelowFloor;
        }
        let Some(dependencies) =
            Self::captured_free_variable_dependencies(&module.ir, body.id(), captured_frame_count)
        else {
            return ReadyCellPlanDecision::Unavailable;
        };
        if dependencies
            .iter()
            .any(|dependency| !matches!(dependency, CapturedFreeVariableDependency::Slot { .. }))
        {
            return ReadyCellPlanDecision::NonSlot;
        }
        let coordinate = |dependency: &CapturedFreeVariableDependency| {
            let CapturedFreeVariableDependency::Slot { frame_index, slot } = dependency else {
                return None;
            };
            Some((*frame_index, *slot))
        };
        let captures = match dependencies.len() {
            0 => ReadyCellCapturePlan::Empty,
            1 => {
                let Some(dependency) = dependencies.iter().next() else {
                    return ReadyCellPlanDecision::Unavailable;
                };
                let Some(capture) = coordinate(dependency) else {
                    return ReadyCellPlanDecision::NonSlot;
                };
                ReadyCellCapturePlan::One(capture)
            }
            2 => {
                let mut dependencies = dependencies.iter();
                let Some(first) = dependencies.next().and_then(coordinate) else {
                    return ReadyCellPlanDecision::NonSlot;
                };
                let Some(second) = dependencies.next().and_then(coordinate) else {
                    return ReadyCellPlanDecision::NonSlot;
                };
                ReadyCellCapturePlan::Two([first, second])
            }
            _ => {
                let mut captures = Vec::new();
                if captures.try_reserve_exact(dependencies.len()).is_err() {
                    return ReadyCellPlanDecision::Unavailable;
                }
                for dependency in &dependencies {
                    let Some(capture) = coordinate(dependency) else {
                        return ReadyCellPlanDecision::NonSlot;
                    };
                    captures.push(capture);
                }
                ReadyCellCapturePlan::Many(captures.into_boxed_slice())
            }
        };
        ReadyCellPlanDecision::Eligible {
            captured_frame_count,
            captures,
            static_cost_units,
            empty_ready_value: None,
        }
    }

    /// Serves an exact local recipe only from a still-Ready source thunk.
    fn probe_ready_cell_directory(&mut self, candidate: &ReadyCellCandidate) -> Option<Value> {
        let value =
            self.ready_cell_directory
                .as_ref()?
                .probe_ready(&candidate.recipe, |source| {
                    self.heap
                        .get_thunk(source)
                        .ok()?
                        .cell()
                        .cached_value()
                        .ok()?
                })?;
        if let Some(directory) = self.ready_cell_directory.as_mut() {
            directory.note_served_hit();
        }
        Some(value)
    }

    /// Publishes one source only after its normal force installed a cached value.
    fn publish_ready_cell_candidate(
        &mut self,
        candidate: Option<&ReadyCellCandidate>,
        source_thunk: Value,
    ) {
        let Some(candidate) = candidate else {
            return;
        };
        let source_is_ready = self
            .heap
            .get_thunk(source_thunk)
            .ok()
            .and_then(|thunk| thunk.cell().cached_value().ok())
            .flatten()
            .is_some();
        if !source_is_ready {
            return;
        }
        if let Some(directory) = self.ready_cell_directory.as_mut() {
            directory.publish(&candidate.recipe, source_thunk);
        }
    }

    /// Records one exact recipe observation and bounded-directory projections.
    fn observe_ready_cell_candidate(
        &mut self,
        candidate: &ReadyCellCandidate,
        representation: ReadyCellHitRepresentation,
    ) {
        let Some(census) = self.ready_cell_census.as_mut() else {
            return;
        };
        let observation = census.observe(&candidate.recipe);
        let arity = u64::try_from(candidate.recipe.arity()).unwrap_or(u64::MAX);
        let cost = u64::from(candidate.static_cost_units);
        let stats = &mut self.stats.memo_economics;
        stats.ready_cell_candidates = stats.ready_cell_candidates.saturating_add(1);
        stats.ready_cell_unique_recipes = stats
            .ready_cell_unique_recipes
            .saturating_add(u64::from(observation.unique_recipe));
        stats.ready_cell_ready_hits = stats
            .ready_cell_ready_hits
            .saturating_add(u64::from(observation.ready_hit));
        stats.ready_cell_pending_overlaps = stats
            .ready_cell_pending_overlaps
            .saturating_add(u64::from(observation.pending_overlap));
        stats.ready_cell_recipe_slots = stats.ready_cell_recipe_slots.saturating_add(arity);
        if observation.unique_recipe {
            stats.ready_cell_unique_recipe_slots =
                stats.ready_cell_unique_recipe_slots.saturating_add(arity);
        }
        stats.ready_cell_max_recipe_arity = stats.ready_cell_max_recipe_arity.max(arity);
        stats.ready_cell_one_way_hits = stats
            .ready_cell_one_way_hits
            .saturating_add(u64::from(observation.one_way_hit));
        stats.ready_cell_two_way_hits = stats
            .ready_cell_two_way_hits
            .saturating_add(u64::from(observation.two_way_hit));
        if observation.ready_hit {
            let counter = match representation {
                ReadyCellHitRepresentation::Empty => &mut stats.ready_cell_ready_hits_empty,
                ReadyCellHitRepresentation::FlatOne => &mut stats.ready_cell_ready_hits_flat_one,
                ReadyCellHitRepresentation::FlatTwo => &mut stats.ready_cell_ready_hits_flat_two,
                ReadyCellHitRepresentation::FlatMany => &mut stats.ready_cell_ready_hits_flat_many,
                ReadyCellHitRepresentation::LinkedOrHybrid => {
                    &mut stats.ready_cell_ready_hits_linked_or_hybrid
                }
            };
            *counter = counter.saturating_add(1);
        }
        if observation.one_way_hit {
            let counter = match representation {
                ReadyCellHitRepresentation::Empty => &mut stats.ready_cell_one_way_hits_empty,
                ReadyCellHitRepresentation::FlatOne => &mut stats.ready_cell_one_way_hits_flat_one,
                ReadyCellHitRepresentation::FlatTwo => &mut stats.ready_cell_one_way_hits_flat_two,
                ReadyCellHitRepresentation::FlatMany => {
                    &mut stats.ready_cell_one_way_hits_flat_many
                }
                ReadyCellHitRepresentation::LinkedOrHybrid => {
                    &mut stats.ready_cell_one_way_hits_linked_or_hybrid
                }
            };
            *counter = counter.saturating_add(1);
        }
        if observation.ready_hit {
            stats.ready_cell_ready_static_cost_units = stats
                .ready_cell_ready_static_cost_units
                .saturating_add(cost);
        }
        if observation.one_way_hit {
            stats.ready_cell_one_way_static_cost_units = stats
                .ready_cell_one_way_static_cost_units
                .saturating_add(cost);
        }
        if observation.two_way_hit {
            stats.ready_cell_two_way_static_cost_units = stats
                .ready_cell_two_way_static_cost_units
                .saturating_add(cost);
        }
    }

    /// Marks a shadow Ready-cell candidate reusable after successful force publication.
    fn mark_ready_cell_candidate_ready(&mut self, candidate: Option<&ReadyCellCandidate>) {
        let (Some(census), Some(candidate)) = (self.ready_cell_census.as_mut(), candidate) else {
            return;
        };
        census.mark_ready(&candidate.recipe);
    }

    /// Closes a failed shadow Ready-cell force without publishing a result.
    fn mark_ready_cell_candidate_failed(&mut self, candidate: Option<&ReadyCellCandidate>) {
        let (Some(census), Some(candidate)) = (self.ready_cell_census.as_mut(), candidate) else {
            return;
        };
        census.mark_failed(&candidate.recipe);
    }

    /// Returns the shared L1 table when this evaluation carries one.
    fn shared_memo_table(&self) -> Option<Arc<SharedMemoTable>> {
        self.shared.as_ref()?.memo.as_ref().map(Arc::clone)
    }

    /// Records one admitted key in the stats-only potential-hit census.
    fn observe_memo_potential_hit(&mut self, candidate: &MemoCandidate) {
        let Some(census) = self.memo_economics.as_ref() else {
            return;
        };
        let observation = census.observe(candidate.key);
        let stats = &mut self.stats.memo_economics;
        stats.potential_candidates = stats.potential_candidates.saturating_add(1);
        stats.potential_unique_keys = stats
            .potential_unique_keys
            .saturating_add(u64::from(observation.unique_key));
        stats.potential_hit_keys = stats
            .potential_hit_keys
            .saturating_add(u64::from(observation.first_hit_for_key));
        if observation.potential_hit {
            stats.potential_hits = stats.potential_hits.saturating_add(1);
            stats.potential_hit_static_cost_units = stats
                .potential_hit_static_cost_units
                .saturating_add(u64::from(candidate.static_cost_units));
        }
        stats.ready_structural_hits = stats
            .ready_structural_hits
            .saturating_add(u64::from(observation.earlier_ready));
        stats.recursive_structural_repeats = stats
            .recursive_structural_repeats
            .saturating_add(u64::from(observation.earlier_pending));
        if observation.earlier_ready {
            let work_bytes =
                u64::try_from(std::mem::size_of::<EvalThunk>()).map_or(u64::MAX, |bytes| bytes);
            stats.ready_structural_work_bytes =
                stats.ready_structural_work_bytes.saturating_add(work_bytes);
        }
    }

    /// Marks a shadow structural recipe Ready after successful publication.
    fn mark_memo_recipe_ready(&self, candidate: &MemoCandidate) {
        if let Some(census) = self.memo_economics.as_ref() {
            census.mark_ready(candidate.key);
        }
    }

    /// Closes a failed shadow force without making its recipe reusable.
    fn mark_memo_recipe_failed(&self, candidate: &MemoCandidate) {
        if let Some(census) = self.memo_economics.as_ref() {
            census.mark_failed(candidate.key);
        }
    }

    fn record_memo_key_timing(&mut self, started: Option<Instant>) {
        let Some(started) = started else { return };
        let stats = &mut self.stats.memo_economics;
        stats.key_samples = stats.key_samples.saturating_add(1);
        stats.key_nanos = stats.key_nanos.saturating_add(elapsed_nanos(started));
    }

    fn record_memo_probe_timing(&mut self, started: Option<Instant>) {
        let Some(started) = started else { return };
        let stats = &mut self.stats.memo_economics;
        stats.probe_samples = stats.probe_samples.saturating_add(1);
        stats.probe_nanos = stats.probe_nanos.saturating_add(elapsed_nanos(started));
    }

    fn record_memo_hit_timing(&mut self, started: Option<Instant>) {
        let Some(started) = started else { return };
        let stats = &mut self.stats.memo_economics;
        stats.hit_samples = stats.hit_samples.saturating_add(1);
        stats.hit_nanos = stats.hit_nanos.saturating_add(elapsed_nanos(started));
    }

    fn record_memo_record_timing(&mut self, started: Option<Instant>) {
        let Some(started) = started else { return };
        let stats = &mut self.stats.memo_economics;
        stats.record_samples = stats.record_samples.saturating_add(1);
        stats.record_nanos = stats.record_nanos.saturating_add(elapsed_nanos(started));
    }

    /// Derives the memo key and replay subject for one claimed thunk.
    ///
    /// Returns `None` (and the force proceeds unmemoized) for non-node
    /// thunks, statically skipped def-sites, scoped environments, and
    /// environments whose captured free variables have no durable value hash
    /// (MEMO-1's declined-admission rule for thunk-capturing environments).
    fn memo_candidate_for_thunk(&mut self, thunk: &EvalThunk) -> Option<MemoCandidate> {
        let EvalThunkKind::Node { body, env, .. } = thunk.kind() else {
            return None;
        };
        let stats_enabled = self.options.memo_options().stats_enabled;
        let decision = self.memo_def_site_decision(*body);
        if decision == MemoDefSiteDecision::Skipped {
            return None;
        }
        let static_cost_units = self
            .memo_def_sites
            .get(*body)
            .map_or(0, |state| state.static_cost_units);
        // Environment component first: def-sites whose captured environments
        // never hash never pay identity derivation (the expensive safety walk
        // plus module content hash) at all.
        if !thunk.with_scope_env()?.scopes().is_empty()
            || !thunk.scoped_global_env()?.scopes().is_empty()
        {
            if stats_enabled {
                self.stats.memo_economics.dynamic_scope_declines = self
                    .stats
                    .memo_economics
                    .dynamic_scope_declines
                    .saturating_add(1);
            }
            self.memo_decline_def_site_derivation(*body);
            return None;
        }
        let Some(hashes) = self.memo_free_var_hashes(*body, env) else {
            if stats_enabled {
                self.stats.memo_economics.unknown_capture_declines = self
                    .stats
                    .memo_economics
                    .unknown_capture_declines
                    .saturating_add(1);
            }
            self.memo_decline_def_site_derivation(*body);
            return None;
        };
        let identity = match decision {
            MemoDefSiteDecision::Admitted { identity } => identity,
            MemoDefSiteDecision::CostAdmitted => {
                match self.cache_lookup_identity_for_node(*body) {
                    Some(identity) => {
                        if let Some(state) = self.memo_def_sites.get_mut(*body) {
                            state.decision = MemoDefSiteDecision::Admitted { identity };
                        }
                        identity
                    }
                    None => {
                        if stats_enabled {
                            self.stats.memo_economics.effect_or_unsafe_declines = self
                                .stats
                                .memo_economics
                                .effect_or_unsafe_declines
                                .saturating_add(1);
                        }
                        // Not lookup-safe: permanently skip the def-site.
                        if let Some(state) = self.memo_def_sites.get_mut(*body) {
                            state.decision = MemoDefSiteDecision::Skipped;
                        }
                        self.increment_memo_declines();
                        return None;
                    }
                }
            }
            MemoDefSiteDecision::Skipped => return None,
        };
        if let Some(state) = self.memo_def_sites.get_mut(*body) {
            state.consecutive_declines = 0;
        }
        let key = match DemandCacheKey::for_free_vars(identity, hashes.iter().copied()) {
            Ok(key) => key,
            Err(_) => {
                self.memo_decline_def_site_derivation(*body);
                return None;
            }
        };
        let subject = ForceCacheSubject {
            lookup_identity: Some(identity),
            pure_observation_identity: None,
            impure_observation_identity: None,
            metadata_identity: None,
            persistent_clear_identity: None,
            free_var_value_hashes: hashes,
            replay_position_module: Some(body.module()),
            replay_allocation_node: Some(*body),
            memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
        };
        Some(MemoCandidate {
            key,
            subject,
            static_cost_units,
        })
    }

    /// Feeds one derivation decline into a def-site's consecutive-decline
    /// gate (see [`MEMO_DECLINE_GATE`]) and counts the decline.
    fn memo_decline_def_site_derivation(&mut self, def_site: EvalNodeRef) {
        self.increment_memo_declines();
        let Some(state) = self.memo_def_sites.get_mut(def_site) else {
            return;
        };
        state.consecutive_declines = state.consecutive_declines.saturating_add(1);
        if state.consecutive_declines >= MEMO_DECLINE_GATE {
            state.decision = MemoDefSiteDecision::Skipped;
        }
    }

    /// Computes the environment component: one durable [`ValueHash`] per
    /// captured free-variable dependency of the def-site body, in canonical
    /// slot order.
    ///
    /// Mirrors the force cache's free-variable hashing but threads the
    /// per-eval unhashable-value memo through the slot hashers: many
    /// def-sites capture the same large environment values (whole package
    /// and library attrsets), and an unhashable value would otherwise be
    /// re-walked to its first closure once per def-site. Static selects with
    /// default expressions decline in MEMO-1 (a rarely captured shape whose
    /// hashing recurses through nested scopes).
    fn memo_free_var_hashes(&mut self, body: EvalNodeRef, env: &EvalEnv) -> Option<Vec<ValueHash>> {
        let env = self.captured_env_ref(env);
        if env.is_empty() {
            return Some(Vec::new());
        }
        let module_id = body.module();
        let dependencies = {
            let module = self.modules.get(module_id.index())?;
            Self::captured_free_variable_dependencies(&module.ir, body.id(), env.frame_count())?
        };
        let mut unhashable = std::mem::take(&mut self.memo_unhashable_values);
        let hashes =
            self.memo_free_var_hashes_with_memo(module_id, env, &dependencies, &mut unhashable);
        self.memo_unhashable_values = unhashable;
        hashes
    }

    /// The dependency-hash loop behind [`Self::memo_free_var_hashes`].
    fn memo_free_var_hashes_with_memo(
        &self,
        module_id: EvalModuleId,
        env: EvalEnvRef<'_>,
        dependencies: &BTreeSet<CapturedFreeVariableDependency>,
        unhashable: &mut HashSet<u64>,
    ) -> Option<Vec<ValueHash>> {
        let mut hashes = Vec::new();
        hashes.try_reserve_exact(dependencies.len()).ok()?;
        for dependency in dependencies {
            let hash = match dependency {
                CapturedFreeVariableDependency::Slot { frame_index, slot } => {
                    let value = self.env_ref_value_at_index(env, *frame_index, *slot)?;
                    self.memo_hash_captured_value(value, unhashable)?
                }
                CapturedFreeVariableDependency::StaticHasAttr {
                    frame_index,
                    slot,
                    path,
                } => {
                    let receiver = self.env_ref_value_at_index(env, *frame_index, *slot)?;
                    match self.force_cache_static_has_attr_value_hash(
                        module_id,
                        receiver,
                        IrAttrPathId::new(*path),
                    ) {
                        Some(hash) => hash,
                        None => self.memo_hash_captured_value(receiver, unhashable)?,
                    }
                }
                CapturedFreeVariableDependency::StaticSelect {
                    default: Some(_), ..
                } => {
                    return None;
                }
                CapturedFreeVariableDependency::StaticSelect {
                    frame_index,
                    slot,
                    path,
                    default: None,
                } => {
                    let receiver = self.env_ref_value_at_index(env, *frame_index, *slot)?;
                    match self.force_cache_static_select_value_hash(
                        module_id,
                        receiver,
                        IrAttrPathId::new(*path),
                    ) {
                        Some(hash) => hash,
                        None => self.memo_hash_captured_value(receiver, unhashable)?,
                    }
                }
            };
            hashes.push(hash);
        }
        Some(hashes)
    }

    /// Hashes one captured value, consulting and feeding the per-eval
    /// unhashable-value memo.
    ///
    /// The memo is advisory: entries key on the value word's payload bits, so
    /// a stale entry (a forwarded record) can only cause a spurious decline —
    /// a missed hit, never a wrong one.
    fn memo_hash_captured_value(
        &self,
        value: Value,
        unhashable: &mut HashSet<u64>,
    ) -> Option<ValueHash> {
        let bits = value.relocation_sensitive_identity_bits();
        if unhashable.contains(&bits) {
            return None;
        }
        match self.force_cache_free_var_value_hash(value) {
            Some(hash) => Some(hash),
            None => {
                unhashable.insert(bits);
                None
            }
        }
    }

    /// Returns (computing and caching on first demand) the def-site decision.
    fn memo_def_site_decision(&mut self, def_site: EvalNodeRef) -> MemoDefSiteDecision {
        if let Some(state) = self.memo_def_sites.get(def_site) {
            return state.decision;
        }
        let (decision, static_cost_units) = self.compute_memo_def_site_decision(def_site);
        let _ = self
            .memo_def_sites
            .insert(def_site, MemoDefSiteState::new(decision, static_cost_units));
        decision
    }

    /// Computes the static admission decision for one def-site.
    ///
    /// Admission requires the subtree's static cost estimate to reach the
    /// configured floor; the expression identity (a full subtree safety walk
    /// plus a module content hash) is derived lazily on the first force whose
    /// environment hashes successfully.
    fn compute_memo_def_site_decision(&self, def_site: EvalNodeRef) -> (MemoDefSiteDecision, u32) {
        let floor = self.options.memo_options().min_cost;
        if self.options.memo_options().stats_enabled {
            let Some(cost) = self.memo_static_cost(def_site) else {
                return (MemoDefSiteDecision::Skipped, 0);
            };
            let decision = if cost >= floor {
                MemoDefSiteDecision::CostAdmitted
            } else {
                MemoDefSiteDecision::Skipped
            };
            (decision, cost)
        } else if self.memo_static_cost_reaches(def_site, floor) {
            (MemoDefSiteDecision::CostAdmitted, floor)
        } else {
            (MemoDefSiteDecision::Skipped, 0)
        }
    }

    /// Returns the full safe-subtree cost used by the opt-in economics census.
    fn memo_static_cost(&self, def_site: EvalNodeRef) -> Option<u32> {
        let module = self.modules.get(def_site.module().index())?;
        let ir = &module.ir;
        let mut total = 0u32;
        let mut visited = BTreeSet::new();
        let mut stack = vec![def_site.id()];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let node = ir.arena.node(id)?;
            if !Self::node_is_force_lookup_safe(ir, &self.symbols, node) {
                return None;
            }
            total = total.saturating_add(memo_node_cost(node.kind));
            if !Self::push_ir_children(ir, node, &mut stack) {
                return None;
            }
        }
        Some(total)
    }

    /// Returns whether the def-site subtree's static cost estimate reaches
    /// `floor`, walking lowered children with early exit at the floor.
    ///
    /// The walk doubles as a truncated lookup-safety probe: any visited node
    /// failing the per-node force-lookup-safety predicate skips the def-site
    /// immediately. This is not authoritative (the walk stops at the cost
    /// floor; the full safety walk runs inside identity derivation on the
    /// first successful environment hash), but it filters the common
    /// application-bearing subtrees before any per-force environment hashing
    /// is attempted.
    fn memo_static_cost_reaches(&self, def_site: EvalNodeRef, floor: u32) -> bool {
        let Some(module) = self.modules.get(def_site.module().index()) else {
            return false;
        };
        let ir = &module.ir;
        let mut total = 0u32;
        let mut visited = BTreeSet::new();
        let mut stack = vec![def_site.id()];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let Some(node) = ir.arena.node(id) else {
                return false;
            };
            if !Self::node_is_force_lookup_safe(ir, &self.symbols, node) {
                return false;
            }
            total = total.saturating_add(memo_node_cost(node.kind));
            if total >= floor {
                return true;
            }
            if !Self::push_ir_children(ir, node, &mut stack) {
                return false;
            }
        }
        floor == 0
    }

    /// Probes L0 then L1 for `candidate`, replaying the first legal hit.
    ///
    /// A resident entry whose slice fails revalidation (or whose payload can
    /// no longer be replayed under this subject) is removed from its tier and
    /// treated as a miss. An L1 hit that has reached the promote threshold is
    /// also installed at L0.
    fn memo_probe(
        &mut self,
        id: IrId,
        span: Span,
        thunk: &EvalThunk,
        candidate: &MemoCandidate,
    ) -> Result<Option<Value>, TreeWalkError> {
        let stats_enabled = self.options.memo_options().stats_enabled;
        if self.memo_l0.is_some() {
            let probe_started = stats_enabled.then(Instant::now);
            let entry = self
                .memo_l0
                .as_ref()
                .and_then(|table| table.get(&candidate.key).cloned());
            self.record_memo_probe_timing(probe_started);
            match entry {
                Some(entry) => {
                    let check = self.options.memo_options().check_l0;
                    let hit_started = stats_enabled.then(Instant::now);
                    let replay =
                        self.memo_replay_l0_entry(id, span, thunk, candidate, &entry, check);
                    self.record_memo_hit_timing(hit_started);
                    match replay? {
                        Some(value) => {
                            self.stats.memo_l0_hits = self.stats.memo_l0_hits.saturating_add(1);
                            return Ok(Some(value));
                        }
                        None => {
                            if let Some(table) = self.memo_l0.as_mut() {
                                table.remove(&candidate.key);
                            }
                            self.stats.memo_l0_misses = self.stats.memo_l0_misses.saturating_add(1);
                        }
                    }
                }
                None => {
                    self.stats.memo_l0_misses = self.stats.memo_l0_misses.saturating_add(1);
                }
            }
        }
        if let Some(table) = self.shared_memo_table() {
            let probe_started = stats_enabled.then(Instant::now);
            let entry = table.get_and_count_hit(&candidate.key);
            self.record_memo_probe_timing(probe_started);
            match entry {
                Some((entry, hits)) => {
                    let check = self.options.memo_options().check_l1;
                    let hit_started = stats_enabled.then(Instant::now);
                    let replay = self.memo_replay_entry(id, span, thunk, candidate, &entry, check);
                    self.record_memo_hit_timing(hit_started);
                    match replay? {
                        Some(value) => {
                            self.stats.memo_l1_hits = self.stats.memo_l1_hits.saturating_add(1);
                            if hits >= self.options.memo_options().promote_hits
                                && let Some(l0) = self.memo_l0.as_mut()
                            {
                                let _ = l0.insert(candidate.key, entry.into());
                            }
                            return Ok(Some(value));
                        }
                        None => {
                            table.remove(&candidate.key);
                            self.stats.memo_l1_misses = self.stats.memo_l1_misses.saturating_add(1);
                        }
                    }
                }
                None => {
                    self.stats.memo_l1_misses = self.stats.memo_l1_misses.saturating_add(1);
                }
            }
        }
        Ok(None)
    }

    /// Replays one L0 entry through its representation-specific fast path.
    ///
    /// Direct values still revalidate and replay their observation slice and
    /// still participate in CHECK mode, but require no position remap or
    /// force-cache payload rehydration. Immediate runtime words cannot carry
    /// Nix attribute positions; position-bearing composites remain payload
    /// entries and follow [`Self::memo_replay_entry`].
    ///
    /// # Errors
    ///
    /// Propagates fresh-evaluation errors raised by CHECK mode, including
    /// [`TreeWalkErrorKind::MemoCheckDivergence`] on a mismatched direct hit.
    fn memo_replay_l0_entry(
        &mut self,
        id: IrId,
        span: Span,
        thunk: &EvalThunk,
        candidate: &MemoCandidate,
        entry: &MemoL0Entry,
        check: bool,
    ) -> Result<Option<Value>, TreeWalkError> {
        let value = match entry {
            MemoL0Entry::Direct { value, .. } => *value,
            MemoL0Entry::Payload(entry) => {
                return self.memo_replay_entry(id, span, thunk, candidate, entry, check);
            }
        };
        let replayed = if entry.slice().is_empty() {
            Vec::new()
        } else {
            match self.memo_revalidate_slice(entry.slice()) {
                Some(replayed) => replayed,
                None => return Ok(None),
            }
        };
        let value = value.value();
        if check {
            self.memo_check_hit(id, span, thunk, candidate, value)?;
        }
        for fingerprint in replayed {
            self.record_impure_input(fingerprint);
        }
        Ok(Some(value))
    }

    /// Replays one resident entry: revalidate its slice, guard the payload's
    /// position provenance, optionally shadow-check, rehydrate, and re-record
    /// the revalidated observations into the evaluation trace.
    ///
    /// Returns `Ok(None)` when the entry is no longer legal (the caller
    /// treats this as a miss and evicts the entry).
    ///
    /// # Errors
    ///
    /// Propagates fresh-evaluation errors raised by CHECK mode, including
    /// [`TreeWalkErrorKind::MemoCheckDivergence`] when the memoized payload
    /// disagrees with a fresh evaluation of the same body.
    fn memo_replay_entry(
        &mut self,
        id: IrId,
        span: Span,
        thunk: &EvalThunk,
        candidate: &MemoCandidate,
        entry: &MemoEntry,
        check: bool,
    ) -> Result<Option<Value>, TreeWalkError> {
        let replayed = if entry.slice.is_empty() {
            Vec::new()
        } else {
            match self.memo_revalidate_slice(&entry.slice) {
                Some(replayed) => replayed,
                None => return Ok(None),
            }
        };
        let payload = (*entry.payload).clone();
        if self
            .payload_position_remap_for_subject(&payload, &candidate.subject)
            .is_none()
        {
            return Ok(None);
        }
        let Some(value) =
            self.value_for_cached_expression_payload_for_subject(payload, &candidate.subject)
        else {
            return Ok(None);
        };
        if check {
            self.memo_check_hit(id, span, thunk, candidate, value)?;
        }
        for fingerprint in replayed {
            self.record_impure_input(fingerprint);
        }
        Ok(Some(value))
    }

    /// Re-observes a recorded slice against the current world.
    ///
    /// Returns the freshly observed fingerprints (for trace replay) when
    /// every recorded observation still holds, `None` on any mismatch.
    fn memo_revalidate_slice(
        &self,
        slice: &[CacheableInputFingerprint],
    ) -> Option<Vec<ImpureInputFingerprint>> {
        let mut revalidator = TreeWalkImpureInputRevalidator::new(&self.options);
        for recorded in slice {
            let observed = revalidator.revalidate_impure_input(recorded.identity())?;
            if observed.as_cacheable()?.observation_hash() != recorded.observation_hash() {
                return None;
            }
        }
        Some(revalidator.into_revalidated_trace())
    }

    /// CHECK mode: shadows a memo hit with a fresh evaluation of the body and
    /// asserts the canonical value hashes agree.
    ///
    /// Both the replayed hit value and the fresh value are captured through
    /// the identical payload pipeline before hashing, so both carry positions
    /// in the *subject's* module. Comparing the stored payload directly would
    /// be unsound under parallel evaluation: two workers may register
    /// content-identical copies of one imported file under different module
    /// ids, and raw `AttrPosition` module ids participate in the payload
    /// hash even though the position remap makes the replay itself
    /// module-copy-insensitive.
    ///
    /// # Errors
    ///
    /// Propagates fresh-evaluation errors, and returns
    /// [`TreeWalkErrorKind::MemoCheckDivergence`] when the fresh value's
    /// canonical payload hash differs from the replayed hit's (or either
    /// side has no closed payload at all — an equally fatal disagreement,
    /// since the memoized entry was captured from an identically keyed
    /// computation).
    fn memo_check_hit(
        &mut self,
        id: IrId,
        span: Span,
        thunk: &EvalThunk,
        candidate: &MemoCandidate,
        hit: Value,
    ) -> Result<(), TreeWalkError> {
        let fresh = self.eval_thunk_body(id, span, thunk)?;
        let fresh_hash = self.memo_check_value_hash(fresh, candidate);
        let hit_hash = self.memo_check_value_hash(hit, candidate);
        let matches = match (&fresh_hash, &hit_hash) {
            (Some(fresh_hash), Some(hit_hash)) => fresh_hash == hit_hash,
            _ => false,
        };
        if !matches {
            tracing::error!(
                target: "aos_nix::cache",
                node = id.as_u32(),
                "content-memo CHECK: memoized payload diverged from a fresh evaluation"
            );
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MemoCheckDivergence { id },
                span,
            ));
        }
        Ok(())
    }

    /// Captures `value` through the admission payload pipeline and returns
    /// its canonical hash, for CHECK comparisons.
    fn memo_check_value_hash(
        &mut self,
        value: Value,
        candidate: &MemoCandidate,
    ) -> Option<ValueHash> {
        let payload = self.force_cache_payload_for_value(value)?;
        let payload = self.prepare_observable_payload_for_subject(payload, &candidate.subject)?;
        payload.value_hash().ok()
    }

    /// Admits a freshly evaluated value into the active memo tiers.
    ///
    /// Declines (with a per-tier decline counter) when the subtree's
    /// observation slice is incomplete or conflicted, when any observation is
    /// not cacheable, or when the value has no closed replayable payload
    /// (closures and thunk-bearing composites in MEMO-1).
    fn memo_admit(
        &mut self,
        candidate: &MemoCandidate,
        value: Value,
        cursor: ImpureInputTraceCursor,
    ) {
        let l0_active = self.memo_l0.is_some();
        let shared = self.shared_memo_table();
        if !l0_active && shared.is_none() {
            return;
        }
        let segment = self.force_cache_impure_input_trace_segment(cursor);
        if !segment.complete {
            self.increment_memo_declines();
            return;
        }
        let mut cacheable = Vec::new();
        if cacheable.try_reserve_exact(segment.trace.len()).is_err() {
            self.increment_memo_declines();
            return;
        }
        for fingerprint in &segment.trace {
            match fingerprint.as_cacheable() {
                Some(recorded) => cacheable.push(recorded.clone()),
                None => {
                    self.increment_memo_declines();
                    return;
                }
            }
        }
        let Some(slice) = canonicalize_cacheable_input_trace(cacheable) else {
            self.increment_memo_declines();
            return;
        };
        let slice: Arc<[CacheableInputFingerprint]> = Arc::from(slice);
        let direct = MemoDirectValue::new(value);
        if l0_active && let Some(value) = direct {
            let admitted = self.memo_l0.as_mut().is_some_and(|table| {
                table.insert(
                    candidate.key,
                    MemoL0Entry::Direct {
                        value,
                        slice: Arc::clone(&slice),
                    },
                )
            });
            if admitted {
                self.stats.memo_l0_admissions = self.stats.memo_l0_admissions.saturating_add(1);
            } else {
                self.stats.memo_l0_declines = self.stats.memo_l0_declines.saturating_add(1);
            }
        }

        // L1 always keeps the closed, cross-worker payload representation.
        // L0 needs that representation only when the value is not immediate.
        if shared.is_none() && (direct.is_some() || !l0_active) {
            return;
        }
        let Some(payload) = self.force_cache_payload_for_value(value) else {
            if direct.is_some() {
                self.stats.memo_l1_declines = self.stats.memo_l1_declines.saturating_add(1);
            } else {
                self.increment_memo_declines();
            }
            return;
        };
        let Some(payload) =
            self.prepare_observable_payload_for_subject(payload, &candidate.subject)
        else {
            if direct.is_some() {
                self.stats.memo_l1_declines = self.stats.memo_l1_declines.saturating_add(1);
            } else {
                self.increment_memo_declines();
            }
            return;
        };
        let entry = MemoEntry {
            payload: Arc::new(payload),
            slice,
        };
        if l0_active && direct.is_none() {
            let admitted = self
                .memo_l0
                .as_mut()
                .is_some_and(|table| table.insert(candidate.key, entry.clone().into()));
            if admitted {
                self.stats.memo_l0_admissions = self.stats.memo_l0_admissions.saturating_add(1);
            } else {
                self.stats.memo_l0_declines = self.stats.memo_l0_declines.saturating_add(1);
            }
        }
        if let Some(table) = shared {
            if table.publish(candidate.key, entry) {
                self.stats.memo_l1_admissions = self.stats.memo_l1_admissions.saturating_add(1);
            } else {
                self.stats.memo_l1_declines = self.stats.memo_l1_declines.saturating_add(1);
            }
        }
    }

    /// Counts one per-force eligibility or record decline against the tier
    /// the force would have recorded into.
    fn increment_memo_declines(&mut self) {
        if self.memo_l0.is_some() {
            self.stats.memo_l0_declines = self.stats.memo_l0_declines.saturating_add(1);
        } else if self.shared_memo_table().is_some() {
            self.stats.memo_l1_declines = self.stats.memo_l1_declines.saturating_add(1);
        }
    }

    /// Derives the content-memo key for a suspended thunk value, for tests.
    #[cfg(test)]
    pub(crate) fn test_memo_candidate_key(&mut self, value: Value) -> Option<DemandCacheKey> {
        let thunk = self.heap.clone_thunk(value).ok()?;
        self.memo_candidate_for_thunk(&thunk)
            .map(|candidate| candidate.key)
    }

    /// Returns every key resident in the L0 table, for tests.
    #[cfg(test)]
    pub(crate) fn test_memo_l0_keys(&self) -> Vec<DemandCacheKey> {
        self.memo_l0
            .as_ref()
            .map(super::super::memo::MemoL0Table::keys)
            .unwrap_or_default()
    }

    /// Returns direct and closed-payload L0 entry counts, for tests.
    #[cfg(test)]
    pub(crate) fn test_memo_l0_representation_counts(&self) -> (usize, usize) {
        self.memo_l0.as_ref().map_or((0, 0), |table| {
            (table.direct_entry_count(), table.payload_entry_count())
        })
    }

    /// Returns resident entries and served hits in the local Ready directory.
    #[cfg(test)]
    pub(crate) fn test_ready_cell_directory_counts(&self) -> (usize, u64) {
        self.ready_cell_directory
            .as_ref()
            .map_or((0, 0), |directory| {
                (directory.len(), directory.served_hits())
            })
    }

    /// Returns the number of cached Ready-cell def-site plans, for tests.
    #[cfg(test)]
    pub(crate) fn test_ready_cell_plan_count(&self) -> usize {
        self.ready_cell_plans
            .as_ref()
            .map_or(0, super::super::memo::ReadyCellPlanCache::len)
    }

    /// Returns resident capture-free direct results and served hits.
    #[cfg(test)]
    pub(crate) fn test_empty_ready_cell_counts(&self) -> (usize, u64) {
        self.ready_cell_plans
            .as_ref()
            .map_or((0, 0), super::super::memo::ReadyCellPlanCache::empty_counts)
    }

    /// Poisons a resident L0 entry's payload under `key`, for CHECK tests.
    #[cfg(test)]
    pub(crate) fn test_memo_poison_l0_payload(
        &mut self,
        key: DemandCacheKey,
        payload: CachedExpressionValue,
    ) -> bool {
        let Some(table) = self.memo_l0.as_mut() else {
            return false;
        };
        let Some(entry) = table.get(&key).cloned() else {
            return false;
        };
        table.insert(
            key,
            MemoL0Entry::Payload(MemoEntry {
                payload: Arc::new(payload),
                slice: Arc::from(entry.slice()),
            }),
        )
    }
}
