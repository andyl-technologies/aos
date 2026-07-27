//! Type-erased tier-1 native-entry publish side-table for the tree-walk oracle.
//!
//! RFC-0007's JIT promotes a hot thunk to a compiled tier-1 native entry so a
//! later force can dispatch machine code instead of re-walking the body. The
//! dispatch owner (a finalized Cranelift artifact) lives in `ratchet-jit`, which
//! this safe crate must not depend on, so the entry is stored *type-erased*: a
//! raw entry address, a [`Box<dyn Any>`](std::any::Any) owner that keeps the
//! finalized code and its module alive, and a published-once state word. The
//! `aos-nix` conformance layer installs the concrete `ratchet-jit`-backed entry
//! as the owner and downcasts it back at dispatch time.
//!
//! The publish protocol leaves the force path completely untouched:
//!
//! - Force uses only the thunk cell's own `Suspended -> Blackhole -> Forced`
//!   state machine and never inspects this side-table.
//! - Publish installs a slot, then transitions it `Empty -> Published` (release)
//!   only after observing the thunk cell still [`Suspended`](ThunkState::Suspended)
//!   (acquire). A thunk that a prior or racing force already advanced past
//!   `Suspended` is never published over, so publish always loses to force.
//!
//! ```text
//! install:  side_table[thunk identity] = OpaqueTier1Slot{ entry, owner, Empty }
//! publish:  if cell.state() == Suspended (Acquire) { slot: Empty -> Published (Release) }
//! dispatch: if slot.is_published() { downcast owner -> finalization -> native call }
//! ```

use std::any::Any;
use std::fmt;
use std::rc::Rc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::compile::{Ir, IrId};
use crate::eval::module::EvalModuleId;
use crate::eval::thunk::{ForceError, ThunkState};
use crate::syntax::Span;
use crate::value::Value;

use super::TreeWalk;

/// The outcome of consulting a [`Tier1Engine`] at the top of a serial force.
///
/// The engine is consulted once when a suspended thunk is claimed for forcing.
/// It either dispatches published tier-1 native code (whose value replaces the
/// tree-walk body evaluation), reports a deopt (native code ran but trapped or
/// errored, so the tree walk must run the body), or reports that it did not
/// dispatch at all (optionally having promoted and published the thunk for a
/// later force).
#[derive(Debug)]
pub enum Tier1ForceHook {
    /// Published tier-1 native code produced this forced value; skip the body.
    Dispatched(Value),
    /// Native code ran but trapped or errored; deoptimize to the tree-walk body.
    Deopted,
    /// No dispatch happened; run the tree-walk body as usual.
    Continued {
        /// True when this force compiled and published a tier-1 entry for reuse.
        promoted: bool,
        /// True when this force newly blacklisted the def-site after a failed
        /// tier-1 lowering (the shape is not lowerable and is never retried).
        blacklisted: bool,
        /// True when the engine has permanently decided not to dispatch this
        /// def-site (it was blacklisted, or gated as a delegate-only trampoline).
        ///
        /// The tree walk records the def-site and stops consulting the engine on
        /// later forces of its other thunk instances, so a decided cold def-site
        /// pays the per-force hook cost only until it is decided rather than on
        /// every force for the rest of the evaluation.
        gated: bool,
    },
}

/// The outcome of consulting a [`Tier1Engine`] at a serial lambda application.
///
/// The engine is consulted once per lambda application of an undecided def-site
/// (the tier-2 seam). It either dispatches a published tier-2 compiled lambda
/// body (whose value replaces the interpreted call), reports a deopt (native
/// code ran but trapped, so the tree walk must run the call), or reports that it
/// did not dispatch (optionally having promoted the def-site for a later call).
#[derive(Debug)]
pub enum Tier2ApplyHook {
    /// Published tier-2 native code produced this call's value; skip the body.
    Dispatched(Value),
    /// Native code ran but trapped; deoptimize to the interpreted call.
    Deopted,
    /// No dispatch happened; run the interpreted call as usual.
    Continued {
        /// True when this call compiled and published a tier-2 entry for reuse.
        promoted: bool,
        /// True when this call newly blacklisted the def-site after a failed
        /// tier-2 lowering (the shape is not compilable and is never retried).
        blacklisted: bool,
        /// True when the engine has permanently decided not to dispatch this
        /// def-site, so the apply path should stop consulting the engine for it.
        gated: bool,
    },
}

/// The outcome of consulting a [`Tier1Engine`] at a strict left fold.
///
/// The engine is consulted at most twice per `builtins.foldl'` call (once
/// before the first element and once after one interpreted iteration, which
/// forces the operator's callee bindings and lets transient promotion guards
/// pass). A `Ran` outcome reports that published tier-2 native code folded a
/// prefix of the remaining elements; the interpreted loop resumes after that
/// prefix. `Continued` leaves the loop untouched.
#[derive(Debug)]
pub enum Tier2FoldHook {
    /// Native code folded `consumed` leading elements of the remaining slice.
    Ran {
        /// The number of leading elements the native loop consumed.
        consumed: usize,
        /// The accumulator value after the consumed elements (WHNF).
        accumulator: Value,
        /// True when the native loop stopped early on a deopt; the element at
        /// `consumed` (and everything after it) must run interpreted.
        deopted: bool,
        /// True when this consult compiled and published a fold entry.
        promoted: bool,
    },
    /// No native fold ran; the interpreted loop proceeds unchanged.
    Continued {
        /// True when this consult compiled and published a fold entry (whose
        /// dispatch guard did not pass yet).
        promoted: bool,
        /// True when this consult permanently blacklisted the operator's
        /// def-site for fold compilation.
        blacklisted: bool,
    },
}

/// The outcome of consulting a [`Tier1Engine`] at a strict `builtins.filter`.
///
/// The engine is consulted at most twice per `filter` call (once before the
/// first element and once after one interpreted iteration, which forces the
/// predicate's callee bindings and lets transient promotion guards pass). A
/// `Ran` outcome reports that published tier-2 native code decided a prefix
/// of the remaining elements, returning the kept subsequence of that prefix;
/// the interpreted loop resumes after the prefix. `Continued` leaves the loop
/// untouched.
#[derive(Debug)]
pub enum Tier2FilterHook {
    /// Native code decided `consumed` leading elements of the remaining run.
    Ran {
        /// The number of leading elements the native loop decided.
        consumed: usize,
        /// The kept elements of the decided prefix, in element order.
        kept: Vec<Value>,
        /// True when the native loop stopped early on a deopt; the element at
        /// `consumed` (and everything after it) must run interpreted.
        deopted: bool,
        /// True when this consult compiled and published a filter entry.
        promoted: bool,
    },
    /// No native filter ran; the interpreted loop proceeds unchanged.
    Continued {
        /// True when this consult compiled and published a filter entry
        /// (whose dispatch guard did not pass yet).
        promoted: bool,
        /// True when this consult permanently blacklisted the predicate's
        /// def-site for filter compilation.
        blacklisted: bool,
    },
}

/// The outcome of consulting a [`Tier1Engine`] at strict `all`/`any`.
///
/// A native run decides a leading element prefix and either reaches the
/// operation's short-circuit value or leaves the interpreted loop to resume at
/// the first element that deoptimized. Exhausting the supplied run without a
/// short circuit is also a complete native result.
#[derive(Debug)]
pub enum Tier2AllAnyHook {
    /// Native code decided `consumed` leading elements.
    Ran {
        /// The number of leading elements decided by native code.
        consumed: usize,
        /// Whether the decided prefix reached the operation's short circuit.
        short_circuited: bool,
        /// Whether element `consumed` must be retried interpreted.
        deopted: bool,
        /// Whether this consult compiled and published the predicate.
        promoted: bool,
    },
    /// No native predicate loop ran.
    Continued {
        /// Whether this consult compiled and published the predicate.
        promoted: bool,
        /// Whether the predicate def-site was permanently rejected.
        blacklisted: bool,
    },
}

/// A pluggable tier-1 JIT engine consulted by the serial force path.
///
/// The tree-walk evaluator owns no JIT machinery — the Cranelift lowerer,
/// finalizer, and native-call boundary live in crates that depend on this one.
/// Instead the evaluator holds an optional `dyn Tier1Engine` and consults it once
/// per claimed serial force through [`on_serial_force`](Self::on_serial_force).
/// A `None` engine (the default) leaves the force path byte-for-byte unchanged.
///
/// The engine receives `&mut TreeWalk`, so it may read the thunk's captured
/// environment, install and publish [`OpaqueTier1Slot`] entries, and re-enter
/// forcing while dispatching native code. Its counters are surfaced through
/// [`EvalStats`](crate::eval::EvalStats) by the force path, not the engine.
pub trait Tier1Engine: fmt::Debug {
    /// Consulted once when the thunk behind `thunk` is claimed for forcing.
    ///
    /// `id` and `span` identify the forced expression for diagnostics. The engine
    /// returns a [`Tier1ForceHook`] describing whether it produced the forced
    /// value, deoptimized, or declined to dispatch.
    fn on_serial_force(
        &self,
        eval: &mut TreeWalk,
        thunk: Value,
        id: IrId,
        span: Span,
    ) -> Tier1ForceHook;

    /// Consulted once per serial lambda application of an undecided def-site.
    ///
    /// This is the tier-2 seam: `function` is the applied [`Value::is_lambda`]
    /// closure, `lambda` is its cloned heap record (module, body, pattern, and
    /// captured environments), and `argument` is the raw — possibly still
    /// suspended — call argument. `id` and `span` identify the application
    /// expression for diagnostics. The default implementation gates the def-site
    /// so an engine without tier-2 support pays the hook at most once per
    /// def-site.
    fn on_lambda_apply(
        &self,
        eval: &mut TreeWalk,
        function: Value,
        lambda: &crate::eval::heap::EvalLambda,
        argument: Value,
        id: IrId,
        span: Span,
    ) -> Tier2ApplyHook {
        let _ = (eval, function, lambda, argument, id, span);
        Tier2ApplyHook::Continued {
            promoted: false,
            blacklisted: false,
            gated: true,
        }
    }

    /// Consulted by the strict left-fold loop for one run of elements.
    ///
    /// This is the tier-2 fold seam: `op` is the fold operator (a
    /// [`Value::is_lambda`] closure), `lambda` its cloned heap record,
    /// `accumulator` the current (possibly still suspended) accumulator, and
    /// `elements` the remaining raw element run. The loop consults at most
    /// twice per fold call, so an engine pays no per-element hook tax; a
    /// compiled fold operator returns [`Tier2FoldHook::Ran`] after natively
    /// folding a prefix of `elements`. The default implementation leaves the
    /// loop untouched.
    fn on_foldl_strict(
        &self,
        eval: &mut TreeWalk,
        op: Value,
        lambda: &crate::eval::heap::EvalLambda,
        accumulator: Value,
        elements: &[Value],
        id: IrId,
        span: Span,
    ) -> Tier2FoldHook {
        let _ = (eval, op, lambda, accumulator, elements, id, span);
        Tier2FoldHook::Continued {
            promoted: false,
            blacklisted: false,
        }
    }

    /// Consulted by the strict `builtins.filter` loop for one element run.
    ///
    /// This is the tier-2 filter seam: `predicate` is the filter predicate (a
    /// [`Value::is_lambda`] closure), `lambda` its cloned heap record, and
    /// `elements` the remaining raw element run. Like the fold seam, the loop
    /// consults at most twice per filter call, so an engine pays no
    /// per-element hook tax; a compiled predicate returns
    /// [`Tier2FilterHook::Ran`] after natively deciding a prefix of
    /// `elements`, carrying the kept subsequence of that prefix. The default
    /// implementation leaves the loop untouched.
    fn on_filter_strict(
        &self,
        eval: &mut TreeWalk,
        predicate: Value,
        lambda: &crate::eval::heap::EvalLambda,
        elements: &[Value],
        id: IrId,
        span: Span,
    ) -> Tier2FilterHook {
        let _ = (eval, predicate, lambda, elements, id, span);
        Tier2FilterHook::Continued {
            promoted: false,
            blacklisted: false,
        }
    }

    /// Consulted by a strict `builtins.all` or `builtins.any` element run.
    ///
    /// `short_circuit_on` is false for `all` and true for `any`. The default
    /// implementation preserves the interpreted loop unchanged.
    fn on_all_any_strict(
        &self,
        eval: &mut TreeWalk,
        predicate: Value,
        lambda: &crate::eval::heap::EvalLambda,
        elements: &[Value],
        short_circuit_on: bool,
        id: IrId,
        span: Span,
    ) -> Tier2AllAnyHook {
        let _ = (
            eval,
            predicate,
            lambda,
            elements,
            short_circuit_on,
            id,
            span,
        );
        Tier2AllAnyHook::Continued {
            promoted: false,
            blacklisted: false,
        }
    }

    /// Consulted by a strict left fold whose list is a direct `genList` call.
    ///
    /// This is the fused-list-generation seam: the fold's list operand is a
    /// direct `builtins.genList generator length` application, so no element
    /// list exists yet. `op` is the fold operator and `op_lambda` its cloned
    /// heap record; `generator` is the forced generator closure and
    /// `generator_lambda` its cloned record; `accumulator` is the current
    /// (possibly still suspended) accumulator; and the remaining run covers
    /// indices `next_index .. length`. A compiled fused entry returns
    /// [`Tier2FoldHook::Ran`] whose `consumed` counts *generated* elements
    /// (the index loop resumes at `next_index + consumed`). The default
    /// implementation leaves the loop untouched.
    #[allow(clippy::too_many_arguments)]
    fn on_foldl_strict_genlist(
        &self,
        eval: &mut TreeWalk,
        op: Value,
        op_lambda: &crate::eval::heap::EvalLambda,
        generator: Value,
        generator_lambda: &crate::eval::heap::EvalLambda,
        accumulator: Value,
        next_index: usize,
        length: usize,
        id: IrId,
        span: Span,
    ) -> Tier2FoldHook {
        let _ = (
            eval,
            op,
            op_lambda,
            generator,
            generator_lambda,
            accumulator,
            next_index,
            length,
            id,
            span,
        );
        Tier2FoldHook::Continued {
            promoted: false,
            blacklisted: false,
        }
    }
}

/// The `Empty` state: an entry is installed but not published for dispatch.
const TIER1_SLOT_EMPTY: u8 = 0;
/// The `Published` state: the entry may be dispatched by the force path.
const TIER1_SLOT_PUBLISHED: u8 = 1;

/// A type-erased, published-once tier-1 native entry for a single thunk.
///
/// The slot keeps the compiled dispatch owner alive without naming its type: the
/// owner is a [`Box<dyn Any>`](std::any::Any) that the installing layer downcasts
/// back to its concrete finalized-artifact handle at dispatch time. This crate
/// never dereferences [`entry_addr`](Self::entry_addr) or inspects the owner; it
/// only records them and gates the `Empty -> Published` transition.
pub struct OpaqueTier1Slot {
    /// The finalized native entry address, recorded for the caller's no-moving
    /// invariant check (the address must be identical before and after publish).
    entry_addr: usize,
    /// The retained, type-erased dispatch owner that keeps the finalized code and
    /// its owning module alive. Never inspected by this crate.
    owner: Box<dyn Any>,
    /// The published-once state word: [`TIER1_SLOT_EMPTY`] or [`TIER1_SLOT_PUBLISHED`].
    state: AtomicU8,
}

impl fmt::Debug for OpaqueTier1Slot {
    /// Formats the slot without inspecting the type-erased owner.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueTier1Slot")
            .field("entry_addr", &self.entry_addr)
            .field("published", &self.is_published())
            .finish_non_exhaustive()
    }
}

impl OpaqueTier1Slot {
    /// Creates an unpublished slot owning a type-erased tier-1 dispatch entry.
    ///
    /// `entry_addr` is the finalized native entry address the caller will
    /// dispatch through; it is stored for the no-moving-code invariant check and
    /// is never dereferenced here. `owner` keeps the finalized code and its
    /// module alive for as long as the slot lives and is retained opaquely.
    pub fn new(entry_addr: usize, owner: Box<dyn Any>) -> Self {
        Self {
            entry_addr,
            owner,
            state: AtomicU8::new(TIER1_SLOT_EMPTY),
        }
    }

    /// Returns the finalized native entry address recorded at installation.
    pub fn entry_addr(&self) -> usize {
        self.entry_addr
    }

    /// Returns the retained type-erased dispatch owner for downcasting.
    ///
    /// The installing layer downcasts this back to its concrete finalized
    /// artifact handle to dispatch the published entry.
    pub fn owner(&self) -> &dyn Any {
        self.owner.as_ref()
    }

    /// Returns true when the slot has been published for dispatch.
    ///
    /// Uses an acquire load so a reader that observes `Published` also observes
    /// the finalized entry the publisher recorded.
    pub fn is_published(&self) -> bool {
        self.state.load(Ordering::Acquire) == TIER1_SLOT_PUBLISHED
    }

    /// Publishes a freshly installed def-site entry.
    ///
    /// Def-site entries (tier-1 and tier-2 alike) are compiled per IR body and
    /// are valid for every instance of that body, so their install paths
    /// publish unconditionally. This is the sibling-module face of
    /// [`try_publish`](Self::try_publish) used by the tier-2 apply seam.
    pub(super) fn publish_def_site_slot(&self) -> bool {
        self.try_publish()
    }

    /// Transitions the slot `Empty -> Published` at most once.
    ///
    /// Returns true when this call performed the transition and false when the
    /// slot was already published. The success ordering is release so a later
    /// acquire reader of [`is_published`](Self::is_published) observes the
    /// recorded entry.
    fn try_publish(&self) -> bool {
        self.state
            .compare_exchange(
                TIER1_SLOT_EMPTY,
                TIER1_SLOT_PUBLISHED,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_ok()
    }
}

impl TreeWalk {
    /// Installs the pluggable tier-1 JIT engine consulted during serial forcing.
    ///
    /// The engine is consulted once per claimed serial force through
    /// [`Tier1Engine::on_serial_force`]. Installing an engine does not by itself
    /// change results: dispatch only occurs for thunks whose slots the engine
    /// has published, and the force path always deoptimizes to the tree-walk
    /// body when native dispatch traps or errors. Passing a fresh engine
    /// replaces any previously installed one.
    ///
    /// Parallel evaluation mode refuses the engine: tier-1 state is `Rc`-held
    /// and worker-affine, so when [`TreeWalkOptions::parallel_workers`] is
    /// configured the install is ignored and forcing stays on the tree-walk
    /// body path (`AOS_NIX_JIT` is ignored under `AOS_NIX_PARALLEL`).
    pub fn set_tier1_engine(&mut self, engine: Rc<dyn Tier1Engine>) {
        if self.options.parallel_workers().is_some() {
            debug_assert!(
                self.tier1_engine.is_none(),
                "parallel evaluation mode must not carry a tier-1 engine"
            );
            return;
        }
        #[cfg(feature = "maximal_laziness_probe")]
        self.disable_maximal_laziness_for_jit();
        #[cfg(feature = "lifetime_cohort_probe")]
        if self.lifetime_cohort_probe.take().is_some() {
            self.heap.clear_lifetime_quarantine();
            eprintln!(
                "aos_nix_lifetime_cohort_refused \
                 {{\"reason\":\"tier-1 engine installed after probe admission\"}}"
            );
            self.heap.set_epoch_tracking_enabled(
                self.options
                    .heap_cheap_memory_advice_min_idle_epochs()
                    .is_some(),
            );
        }
        self.tier1_engine = Some(engine);
    }

    /// Returns the installed tier-1 JIT engine, if any.
    pub fn tier1_engine(&self) -> Option<&Rc<dyn Tier1Engine>> {
        self.tier1_engine.as_ref()
    }

    /// Returns the lowered IR for `module`, if that module is loaded.
    ///
    /// A tier-1 engine uses this to recover the lowered body of a thunk it is
    /// considering for promotion: the thunk's
    /// [`body_ref`](crate::eval::EvalThunk::body_ref) names a
    /// `(module, root)` pair, and the engine lowers `root` against the returned
    /// IR. Returns `None` when the module index is out of range.
    pub fn tier1_module_ir(&self, module: EvalModuleId) -> Option<&Ir> {
        self.modules.get(module.index()).map(|module| &module.ir)
    }

    /// Installs a type-erased tier-1 publish slot for `thunk` without publishing.
    ///
    /// The slot is keyed by the thunk's payload bits and starts `Empty`; it is
    /// not visible to dispatch until [`publish_tier1_slot`](Self::publish_tier1_slot)
    /// transitions it to `Published`. Installation is unconditional (it does not
    /// consult the publish flag) so a caller can stage entries and gate only the
    /// publish step.
    ///
    /// Returns true when the slot was installed. Returns false when `thunk` is
    /// not a thunk value or a slot is already installed for it (the existing slot
    /// is left untouched and `slot` is dropped).
    pub fn install_tier1_slot(&mut self, thunk: Value, slot: OpaqueTier1Slot) -> bool {
        if !thunk.is_thunk() {
            return false;
        }
        let key = thunk.relocation_sensitive_identity_bits();
        if self.tier1_publish_slots.contains_key(&key) {
            return false;
        }
        self.tier1_publish_slots.insert(key, slot);
        true
    }

    /// Installs and publishes a tier-1 native entry shared across a def-site.
    ///
    /// Unlike the per-instance [`install_tier1_slot`](Self::install_tier1_slot) /
    /// [`publish_tier1_slot`](Self::publish_tier1_slot) pair — which gate on a
    /// single thunk still being suspended — a def-site entry is compiled from an
    /// IR body and is valid for every thunk instance of that body. The engine
    /// installs it while promoting one (already-claimed) instance, so publication
    /// is unconditional: the slot is transitioned straight to `Published`.
    ///
    /// `def_site` is the caller's `(module, root)` encoding. Returns true when the
    /// entry was newly installed and published, and false when an entry already
    /// exists for `def_site` (the existing entry is kept and `slot` is dropped).
    pub fn install_and_publish_tier1_def_site_slot(
        &mut self,
        def_site: u64,
        slot: OpaqueTier1Slot,
    ) -> bool {
        if self.tier1_def_site_slots.contains_key(&def_site) {
            return false;
        }
        // A fresh slot is `Empty`, so this CAS always succeeds; publish before
        // inserting so a later acquire reader observes the recorded entry.
        slot.try_publish();
        self.tier1_def_site_slots.insert(def_site, slot);
        true
    }

    /// Returns the published tier-1 entry for `def_site`, if one is installed.
    ///
    /// Dispatch consults this for every claimed force whose thunk body names
    /// `def_site`; the returned slot is always `Published`.
    pub fn tier1_def_site_slot(&self, def_site: u64) -> Option<&OpaqueTier1Slot> {
        self.tier1_def_site_slots.get(&def_site)
    }

    /// Returns the number of def-sites the tier-1 engine has permanently gated.
    ///
    /// A gated def-site is one the engine decided never to dispatch (a blacklisted
    /// unlowerable shape, or a delegate-only trampoline). The serial force path
    /// records it and stops consulting the engine for that def-site's later thunk
    /// instances, so this count grows as cold def-sites are decided.
    pub fn tier1_skipped_def_site_count(&self) -> usize {
        self.tier1_skipped_def_sites.len()
    }

    /// Returns the installed tier-1 publish slot for `thunk`, if any.
    ///
    /// Returns `None` when `thunk` is not a thunk value or no slot is installed.
    /// The returned slot may be `Empty` or `Published`; dispatch must check
    /// [`OpaqueTier1Slot::is_published`] before using it.
    pub fn tier1_slot(&self, thunk: Value) -> Option<&OpaqueTier1Slot> {
        if !thunk.is_thunk() {
            return None;
        }
        self.tier1_publish_slots
            .get(&thunk.relocation_sensitive_identity_bits())
    }

    /// Publishes the installed tier-1 slot for `thunk`, behind the publish flag.
    ///
    /// Publishing transitions an installed slot `Empty -> Published` only after
    /// acquire-loading the thunk cell's own state and confirming it is still
    /// [`Suspended`](ThunkState::Suspended). Because force advances the same cell
    /// past `Suspended` before this crate ever consults the side-table, a prior
    /// or racing force always wins and this call becomes a no-op — the force path
    /// itself never reads or writes the slot.
    ///
    /// Returns `Ok(true)` only when this call performed the `Empty -> Published`
    /// transition. Returns `Ok(false)` when publishing is disabled, `thunk` is
    /// not a thunk, no slot is installed, the thunk cell has already advanced
    /// past `Suspended`, or the slot was already published.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::InvalidStateWord`] if the thunk cell's atomic state
    /// word holds an unsupported encoding.
    pub fn publish_tier1_slot(&self, thunk: Value) -> Result<bool, ForceError> {
        if !self.options.jit_tier1_publish_enabled() {
            return Ok(false);
        }
        if !thunk.is_thunk() {
            return Ok(false);
        }
        let Some(slot) = self
            .tier1_publish_slots
            .get(&thunk.relocation_sensitive_identity_bits())
        else {
            return Ok(false);
        };
        // Acquire-load the thunk's own state and publish only over a still
        // suspended thunk, so a prior or racing force always wins the thunk.
        let cell = match self.heap().get_thunk(thunk) {
            Ok(heap_thunk) => heap_thunk.cell(),
            Err(_) => return Ok(false),
        };
        if cell.state()? != ThunkState::Suspended {
            return Ok(false);
        }
        Ok(slot.try_publish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_records_entry_and_owner_without_publishing() {
        let slot = OpaqueTier1Slot::new(0xdead_beef, Box::new(7_u32));
        assert_eq!(slot.entry_addr(), 0xdead_beef);
        assert!(!slot.is_published());
        assert_eq!(slot.owner().downcast_ref::<u32>(), Some(&7));
    }

    #[test]
    fn slot_publishes_exactly_once() {
        let slot = OpaqueTier1Slot::new(1, Box::new(()));
        assert!(
            slot.try_publish(),
            "first publish transitions Empty -> Published"
        );
        assert!(slot.is_published());
        assert!(
            !slot.try_publish(),
            "a second publish over an already-published slot is a no-op"
        );
        assert!(slot.is_published());
    }
}
