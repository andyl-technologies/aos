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
//! non-admitted def-site pays exactly one hash-map probe per force. Per-force
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
//! Payloads are the force cache's closed replayable encoding, so a hit
//! re-allocates the value in the consuming worker's heap — no heap handles
//! cross tiers, which keeps L0 free of GC-root obligations and makes L1
//! entries trivially shareable across parallel workers. `AOS_NIX_MEMO_CHECK`
//! shadows every hit at a checked tier with a fresh evaluation and asserts
//! canonical-hash identity, mirroring `AOS_NIX_ROOT_CUTOFF_CHECK`.
//!
//! [`CacheExprIdentity`]: crate::cache::CacheExprIdentity
//! [`ValueHash`]: crate::cache::ValueHash

use super::*;
use super::force_identity::CapturedFreeVariableDependency;
use crate::cache::{CacheableInputFingerprint, DemandCacheKey};
use crate::eval::tree_walk::memo::{
    MemoDefSiteDecision, MemoDefSiteState, MemoEntry, SharedMemoTable,
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
        forced_payload: u64,
        thunk: &EvalThunk,
        guard: ForceGuard<'_>,
    ) -> Result<Value, TreeWalkError> {
        if self.memo_l0.is_none() && self.shared_memo_table().is_none() {
            return self
                .force_memoized_claimed_thunk(id, span, source_thunk, forced_payload, thunk, guard);
        }
        let Some(candidate) = self.memo_candidate_for_thunk(thunk) else {
            return self
                .force_memoized_claimed_thunk(id, span, source_thunk, forced_payload, thunk, guard);
        };
        if let Some(value) = self.memo_probe(id, span, thunk, &candidate)? {
            let value = self.finish_forced_value(id, span, source_thunk, guard, value)?;
            self.unmark_lazy_identity_thunk_payload(forced_payload);
            return Ok(value);
        }
        let cursor = self.impure_input_trace_cursor();
        let value =
            self.force_memoized_claimed_thunk(id, span, source_thunk, forced_payload, thunk, guard)?;
        self.memo_admit(&candidate, value, cursor);
        Ok(value)
    }

    /// Returns the shared L1 table when this evaluation carries one.
    fn shared_memo_table(&self) -> Option<Arc<SharedMemoTable>> {
        self.shared.as_ref()?.memo.as_ref().map(Arc::clone)
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
        let decision = self.memo_def_site_decision(*body);
        if decision == MemoDefSiteDecision::Skipped {
            return None;
        }
        // Environment component first: def-sites whose captured environments
        // never hash never pay identity derivation (the expensive safety walk
        // plus module content hash) at all.
        if !thunk.with_scope_env()?.scopes().is_empty()
            || !thunk.scoped_global_env()?.scopes().is_empty()
        {
            self.memo_decline_def_site_derivation(*body);
            return None;
        }
        let Some(hashes) = self.memo_free_var_hashes(*body, env) else {
            self.memo_decline_def_site_derivation(*body);
            return None;
        };
        let identity = match decision {
            MemoDefSiteDecision::Admitted { identity } => identity,
            MemoDefSiteDecision::CostAdmitted => {
                match self.cache_lookup_identity_for_node(*body) {
                    Some(identity) => {
                        if let Some(state) = self.memo_def_sites.get_mut(&*body) {
                            state.decision = MemoDefSiteDecision::Admitted { identity };
                        }
                        identity
                    }
                    None => {
                        // Not lookup-safe: permanently skip the def-site.
                        if let Some(state) = self.memo_def_sites.get_mut(&*body) {
                            state.decision = MemoDefSiteDecision::Skipped;
                        }
                        self.increment_memo_declines();
                        return None;
                    }
                }
            }
            MemoDefSiteDecision::Skipped => return None,
        };
        if let Some(state) = self.memo_def_sites.get_mut(&*body) {
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
        Some(MemoCandidate { key, subject })
    }

    /// Feeds one derivation decline into a def-site's consecutive-decline
    /// gate (see [`MEMO_DECLINE_GATE`]) and counts the decline.
    fn memo_decline_def_site_derivation(&mut self, def_site: EvalNodeRef) {
        self.increment_memo_declines();
        let Some(state) = self.memo_def_sites.get_mut(&def_site) else {
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
        let frames = env.frames();
        if frames.is_empty() {
            return Some(Vec::new());
        }
        let module_id = body.module();
        let dependencies = {
            let module = self.modules.get(module_id.index())?;
            Self::captured_free_variable_dependencies(&module.ir, body.id(), frames.len())?
        };
        let mut unhashable = std::mem::take(&mut self.memo_unhashable_values);
        let hashes = self.memo_free_var_hashes_with_memo(
            module_id,
            frames,
            &dependencies,
            &mut unhashable,
        );
        self.memo_unhashable_values = unhashable;
        hashes
    }

    /// The dependency-hash loop behind [`Self::memo_free_var_hashes`].
    fn memo_free_var_hashes_with_memo(
        &self,
        module_id: EvalModuleId,
        frames: &[Arc<EvalFrame>],
        dependencies: &BTreeSet<CapturedFreeVariableDependency>,
        unhashable: &mut HashSet<u64>,
    ) -> Option<Vec<ValueHash>> {
        let mut hashes = Vec::new();
        hashes.try_reserve_exact(dependencies.len()).ok()?;
        for dependency in dependencies {
            let hash = match dependency {
                CapturedFreeVariableDependency::Slot { frame_index, slot } => {
                    let value = frames.get(*frame_index)?.get(*slot).ok()?;
                    self.memo_hash_captured_value(value, unhashable)?
                }
                CapturedFreeVariableDependency::StaticHasAttr {
                    frame_index,
                    slot,
                    path,
                } => {
                    let receiver = frames.get(*frame_index)?.get(*slot).ok()?;
                    match self.force_cache_static_has_attr_value_hash(
                        module_id,
                        receiver,
                        IrAttrPathId::new(*path),
                    ) {
                        Some(hash) => hash,
                        None => self.memo_hash_captured_value(receiver, unhashable)?,
                    }
                }
                CapturedFreeVariableDependency::StaticSelect { default: Some(_), .. } => {
                    return None;
                }
                CapturedFreeVariableDependency::StaticSelect {
                    frame_index,
                    slot,
                    path,
                    default: None,
                } => {
                    let receiver = frames.get(*frame_index)?.get(*slot).ok()?;
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
        let bits = value.payload_bits();
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
        if let Some(state) = self.memo_def_sites.get(&def_site) {
            return state.decision;
        }
        let decision = self.compute_memo_def_site_decision(def_site);
        self.memo_def_sites
            .insert(def_site, MemoDefSiteState::new(decision));
        decision
    }

    /// Computes the static admission decision for one def-site.
    ///
    /// Admission requires the subtree's static cost estimate to reach the
    /// configured floor; the expression identity (a full subtree safety walk
    /// plus a module content hash) is derived lazily on the first force whose
    /// environment hashes successfully.
    fn compute_memo_def_site_decision(&self, def_site: EvalNodeRef) -> MemoDefSiteDecision {
        let floor = self.options.memo_options().min_cost;
        if self.memo_static_cost_reaches(def_site, floor) {
            MemoDefSiteDecision::CostAdmitted
        } else {
            MemoDefSiteDecision::Skipped
        }
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
        if self.memo_l0.is_some() {
            let entry = self
                .memo_l0
                .as_ref()
                .and_then(|table| table.get(&candidate.key).cloned());
            match entry {
                Some(entry) => {
                    let check = self.options.memo_options().check_l0;
                    match self.memo_replay_entry(id, span, thunk, candidate, &entry, check)? {
                        Some(value) => {
                            self.stats.memo_l0_hits = self.stats.memo_l0_hits.saturating_add(1);
                            return Ok(Some(value));
                        }
                        None => {
                            if let Some(table) = self.memo_l0.as_mut() {
                                table.remove(&candidate.key);
                            }
                            self.stats.memo_l0_misses =
                                self.stats.memo_l0_misses.saturating_add(1);
                        }
                    }
                }
                None => {
                    self.stats.memo_l0_misses = self.stats.memo_l0_misses.saturating_add(1);
                }
            }
        }
        if let Some(table) = self.shared_memo_table() {
            match table.get_and_count_hit(&candidate.key) {
                Some((entry, hits)) => {
                    let check = self.options.memo_options().check_l1;
                    match self.memo_replay_entry(id, span, thunk, candidate, &entry, check)? {
                        Some(value) => {
                            self.stats.memo_l1_hits = self.stats.memo_l1_hits.saturating_add(1);
                            if hits >= self.options.memo_options().promote_hits
                                && let Some(l0) = self.memo_l0.as_mut()
                            {
                                let _ = l0.insert(candidate.key, entry);
                            }
                            return Ok(Some(value));
                        }
                        None => {
                            table.remove(&candidate.key);
                            self.stats.memo_l1_misses =
                                self.stats.memo_l1_misses.saturating_add(1);
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
    fn memo_check_value_hash(&mut self, value: Value, candidate: &MemoCandidate) -> Option<ValueHash> {
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
    fn memo_admit(&mut self, candidate: &MemoCandidate, value: Value, cursor: ImpureInputTraceCursor) {
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
        let Some(payload) = self.force_cache_payload_for_value(value) else {
            self.increment_memo_declines();
            return;
        };
        let Some(payload) = self.prepare_observable_payload_for_subject(payload, &candidate.subject)
        else {
            self.increment_memo_declines();
            return;
        };
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
        let entry = MemoEntry {
            payload: Arc::new(payload),
            slice: Arc::from(slice),
        };
        if l0_active {
            let admitted = self
                .memo_l0
                .as_mut()
                .is_some_and(|table| table.insert(candidate.key, entry.clone()));
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
        } else {
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
            MemoEntry {
                payload: Arc::new(payload),
                slice: entry.slice,
            },
        )
    }
}
