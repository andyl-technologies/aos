//! Tier-2 compiled-lambda apply seam for the tree-walk oracle.
//!
//! Tier-1 dispatches compiled *thunk* bodies at the serial force seam
//! (see [`tier1_publish`](super::tier1_publish)). Tier-2 compiles *lambda*
//! bodies — self-recursive arithmetic like `fib = n: if n < 2 then n else
//! fib (n - 1) + fib (n - 2)` — and dispatches them at the serial lambda
//! *application* seam instead, because a hot recursion is made of applies, not
//! forces. This module owns that seam: the def-site side-table of published
//! tier-2 entries, the per-def-site skip set that bounds the hook tax, and the
//! consult helper the apply path calls.
//!
//! The publish and dispatch protocol mirrors tier-1 exactly:
//!
//! - A def-site is keyed by its lambda *body* (`(module_index << 32) |
//!   body_ir_id`), so one published entry serves every closure instance of the
//!   same source lambda.
//! - The engine is consulted once per application of an undecided def-site.
//!   A `gated` outcome records the def-site in the skip set so its later
//!   applications skip the hook entirely with one set probe (the same hook-tax
//!   bound the tier-1 force seam uses).
//! - A dispatched value replaces the interpreted call; a deopt falls through to
//!   the interpreted call, which re-runs the body from scratch. Tier-2 bodies
//!   are pure (no traces, no allocation on the hot path), so abandoning a
//!   native execution and re-running interpreted is sound.
//!
//! An engine of `None` — the default — leaves the apply path byte-for-byte
//! unchanged behind one branch.

use super::*;

impl TreeWalk {
    /// Installs and publishes a tier-2 lambda entry shared across a def-site.
    ///
    /// `def_site` is the caller's `(module_index << 32) | body_ir_id` encoding
    /// of the lambda body. Like
    /// [`install_and_publish_tier1_def_site_slot`](Self::install_and_publish_tier1_def_site_slot),
    /// publication is unconditional: the entry is compiled from the IR body and
    /// is valid for every closure instance of that body, so the slot is
    /// transitioned straight to `Published`.
    ///
    /// Returns true when the entry was newly installed and published, and false
    /// when an entry already exists for `def_site` (the existing entry is kept
    /// and `slot` is dropped).
    pub fn install_and_publish_tier2_def_site_slot(
        &mut self,
        def_site: u64,
        slot: OpaqueTier1Slot,
    ) -> bool {
        if self.tier2_def_site_slots.contains_key(&def_site) {
            return false;
        }
        // A fresh slot is `Empty`, so this always publishes; publish before
        // inserting so a later reader observes the recorded entry.
        let _ = slot.publish_def_site_slot();
        self.tier2_def_site_slots.insert(def_site, slot);
        true
    }

    /// Returns the published tier-2 entry for `def_site`, if one is installed.
    pub fn tier2_def_site_slot(&self, def_site: u64) -> Option<&OpaqueTier1Slot> {
        self.tier2_def_site_slots.get(&def_site)
    }

    /// Returns the number of lambda def-sites the engine has permanently gated
    /// out of the tier-2 apply seam.
    pub fn tier2_skipped_def_site_count(&self) -> usize {
        self.tier2_skipped_def_site_total
    }

    /// Returns whether a lambda def-site has been permanently decided.
    ///
    /// This is the apply-path fast check, so it must not hash: two indexed
    /// loads and a bit test against the per-module decided bit vector.
    #[inline]
    fn tier2_def_site_is_skipped(&self, module: usize, body: u32) -> bool {
        let Some(bits) = self.tier2_skipped_def_sites.get(module) else {
            return false;
        };
        let word = (body / 64) as usize;
        bits.get(word)
            .is_some_and(|bits| bits & (1_u64 << (body % 64)) != 0)
    }

    /// Marks a lambda def-site as permanently decided, growing the per-module
    /// bit vector on demand.
    fn tier2_mark_def_site_skipped(&mut self, module: usize, body: u32) {
        if self.tier2_skipped_def_sites.len() <= module {
            self.tier2_skipped_def_sites
                .resize_with(module + 1, || Box::from([]));
        }
        let bits = &mut self.tier2_skipped_def_sites[module];
        let word = (body / 64) as usize;
        if bits.len() <= word {
            let mut grown = vec![0_u64; word + 1];
            grown[..bits.len()].copy_from_slice(bits);
            *bits = grown.into_boxed_slice();
        }
        let mask = 1_u64 << (body % 64);
        if bits[word] & mask == 0 {
            bits[word] |= mask;
            self.tier2_skipped_def_site_total += 1;
        }
    }

    /// Returns how many additional nested calls the depth guard still allows.
    ///
    /// A tier-2 compiled body performs direct native self-calls that bypass
    /// [`enter_call`](Self::enter_call), so its dispatcher must prove up front
    /// that the native recursion budget fits inside the interpreter's remaining
    /// `max_call_depth` headroom: a native execution that succeeds within a
    /// budget no larger than this headroom is one the interpreter would also
    /// have completed without a max-call-depth error.
    pub fn tier2_call_depth_headroom(&self) -> usize {
        self.options.max_call_depth().saturating_sub(self.call_depth)
    }

    /// Returns the memoized WHNF value behind `value` without forcing anything.
    ///
    /// A non-thunk value is already WHNF and is returned as-is. A thunk that a
    /// previous force has already memoized yields its forced value. A suspended
    /// (or blackholed, or invalid) thunk yields `None`: peeking must never
    /// evaluate a body, because the caller uses this to check a *guard* (e.g.
    /// "does this upvalue resolve to the applied closure itself?") whose
    /// evaluation the interpreted program may never perform.
    pub fn tier2_peek_forced(&self, value: Value) -> Option<Value> {
        if !value.is_thunk() {
            return Some(value);
        }
        let heap_thunk = self.heap.get_thunk(value).ok()?;
        match heap_thunk.cell().begin_force() {
            Ok(ForceClaim::AlreadyForced(forced)) => Some(forced),
            // A claimed guard is dropped immediately, resetting the cell to
            // suspended; the peek observed an unforced thunk and reports none.
            Ok(ForceClaim::Claimed(_guard)) => None,
            Err(_) => None,
        }
    }

    /// Consults the tier-2 engine for one serial lambda application.
    ///
    /// Called by the apply path after the callee closure is cloned and before
    /// any interpreted call state (frame, environment, call depth) is built.
    /// Returns `Some(value)` when published tier-2 native code produced the
    /// call's value, and `None` when the apply path must run the interpreted
    /// call (no engine, a skipped def-site, a deopt, or no dispatch).
    pub(super) fn try_tier2_lambda_apply(
        &mut self,
        id: IrId,
        span: Span,
        function: Value,
        lambda: &EvalLambda,
        argument: Value,
    ) -> Option<Value> {
        let module = lambda.module().index();
        let body = lambda.body().as_u32();
        if self.tier2_def_site_is_skipped(module, body) {
            return None;
        }
        let engine = self.tier1_engine.clone()?;
        match engine.on_lambda_apply(self, function, lambda, argument, id, span) {
            Tier2ApplyHook::Dispatched(value) => {
                self.increment_tier2_dispatched();
                Some(value)
            }
            Tier2ApplyHook::Deopted => {
                self.increment_tier2_deopted();
                None
            }
            Tier2ApplyHook::Continued {
                promoted,
                blacklisted,
                gated,
            } => {
                if promoted {
                    self.increment_tier2_promoted();
                }
                if blacklisted {
                    self.increment_tier2_blacklisted();
                }
                if gated {
                    self.tier2_mark_def_site_skipped(module, body);
                }
                None
            }
        }
    }
}
