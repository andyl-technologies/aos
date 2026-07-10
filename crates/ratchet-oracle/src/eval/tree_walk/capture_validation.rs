//! Test-mode runtime validation of FV-5 capture plans.
//!
//! The capture analysis promises: a thunk allocation site with a
//! [`CapturePlan::Flat`] plan reads at most the planned `(depth, slot)`
//! coordinates from the environment captured at allocation. This module
//! checks that promise against the tree walk itself — every environment slot
//! read that resolves *into the captured prefix* of an actively validated
//! thunk body is checked for membership in the site's plan.
//!
//! The machinery is `cfg(test)`-only and off by default; a test opts in with
//! [`super::TreeWalk::enable_capture_plan_validation`] and asserts
//! [`super::TreeWalk::capture_plan_violations`] stays empty. Attribution
//! works through the evaluator's environment swap discipline:
//!
//! - allocating a `Node` thunk whose site carries a flat plan records the
//!   plan under the thunk's value identity;
//! - forcing such a thunk arms a pending record; the body's
//!   `swap_env_frames` converts it into an active scope whose captured
//!   prefix length is the swapped-in frame count;
//! - every other swap pushes an opaque barrier, so reads under foreign
//!   environments (lambda calls, imports, other thunk kinds) are never
//!   misattributed;
//! - `Local`/`Upval` reads check against the innermost scope only.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::compile::{CapturePlan, IrId};
use crate::eval::EvalModuleId;
use crate::value::Value;

use super::TreeWalk;
use crate::eval::heap::EvalThunkKind;

/// A `(depth, slot)` coordinate pair relative to a captured environment.
type Coordinate = (u16, u16);

/// One recorded violation: a read outside the site's planned coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CapturePlanViolation {
    /// The thunk allocation site whose plan was violated.
    pub(super) site: IrId,
    /// The module owning the site.
    pub(super) module: EvalModuleId,
    /// The offending read, relative to the captured environment.
    pub(super) read: Coordinate,
}

/// A planned thunk recorded at allocation time.
#[derive(Clone, Debug)]
struct PlannedThunk {
    site: IrId,
    module: EvalModuleId,
    slots: Box<[Coordinate]>,
}

/// One entry of the environment-scope attribution stack.
#[derive(Clone, Debug)]
enum Scope {
    /// An environment swap this validator does not attribute reads to.
    Barrier,
    /// An actively validated thunk body.
    Site {
        plan: PlannedThunk,
        captured_len: usize,
    },
}

/// Mutable validation state owned by one evaluator.
#[derive(Debug, Default)]
pub(super) struct CaptureValidationState {
    /// Planned thunks keyed by value payload bits.
    plans: HashMap<u64, PlannedThunk>,
    /// Attribution stack aligned with env swap/restore pairs.
    scopes: Vec<Scope>,
    /// Armed by the force path immediately before a `Node` body swap.
    pending: Option<PlannedThunk>,
    /// Reads that resolved into a validated captured prefix.
    reads_checked: u64,
    /// Reads outside their site's planned coordinate set.
    violations: Vec<CapturePlanViolation>,
}

impl CaptureValidationState {
    /// Records a freshly allocated `Node` thunk with a flat capture plan.
    pub(super) fn record_alloc(
        &mut self,
        payload_bits: u64,
        site: IrId,
        module: EvalModuleId,
        plan: &CapturePlan,
    ) {
        let CapturePlan::Flat(slots) = plan else {
            return;
        };
        let slots: Box<[Coordinate]> = slots
            .iter()
            .map(|capture| (capture.depth, capture.slot))
            .collect();
        self.plans.insert(
            payload_bits,
            PlannedThunk {
                site,
                module,
                slots,
            },
        );
    }

    /// Arms validation for a forced thunk value, if it was recorded.
    pub(super) fn arm_force(&mut self, payload_bits: u64) {
        self.pending = self.plans.get(&payload_bits).cloned();
    }

    /// Disarms a pending record whose body never swapped (error paths).
    pub(super) fn disarm(&mut self) {
        self.pending = None;
    }

    /// Notes an environment swap, consuming any armed site record.
    pub(super) fn on_swap(&mut self, swapped_in_len: usize) {
        let scope = match self.pending.take() {
            Some(plan) => Scope::Site {
                plan,
                captured_len: swapped_in_len,
            },
            None => Scope::Barrier,
        };
        self.scopes.push(scope);
    }

    /// Notes an environment restore.
    pub(super) fn on_restore(&mut self) {
        let _ = self.scopes.pop();
    }

    /// Checks one slot read against the innermost validated scope.
    ///
    /// `env_len` is the current frame-stack length, `depth` the read's
    /// parent-frame walk (0 for `Local`), and `slot` the frame slot.
    pub(super) fn on_slot_read(&mut self, env_len: usize, depth: usize, slot: u32) {
        let Some(Scope::Site { plan, captured_len }) = self.scopes.last() else {
            return;
        };
        let Some(frame_index) = env_len.checked_sub(1 + depth) else {
            return;
        };
        if frame_index >= *captured_len {
            // The read resolves into a body-introduced frame, not a capture.
            return;
        }
        self.reads_checked += 1;
        let capture_depth = (*captured_len - 1 - frame_index) as u16;
        let Ok(slot) = u16::try_from(slot) else {
            self.violations.push(CapturePlanViolation {
                site: plan.site,
                module: plan.module,
                read: (capture_depth, u16::MAX),
            });
            return;
        };
        if !plan.slots.contains(&(capture_depth, slot)) {
            self.violations.push(CapturePlanViolation {
                site: plan.site,
                module: plan.module,
                read: (capture_depth, slot),
            });
        }
    }

    /// Returns the recorded violations.
    pub(super) fn violations(&self) -> &[CapturePlanViolation] {
        &self.violations
    }

    /// Returns how many captured-prefix reads were checked.
    pub(super) fn reads_checked(&self) -> u64 {
        self.reads_checked
    }
}

impl TreeWalk {
    /// Enables FV-5 capture-plan validation for this evaluator.
    ///
    /// Intended for serial, default-option evaluations (no persistent cache,
    /// no JIT engine, no GC stress): those knobs interleave extra environment
    /// swaps or relocate records, which only weakens attribution (reads stop
    /// being checked) but keeps the harness silent rather than wrong.
    pub(crate) fn enable_capture_plan_validation(&mut self) {
        self.capture_plan_validation =
            Some(Box::new(RefCell::new(CaptureValidationState::default())));
    }

    /// Returns the capture-plan violations recorded so far.
    pub(super) fn capture_plan_violations(&self) -> Vec<CapturePlanViolation> {
        self.capture_plan_validation
            .as_ref()
            .map(|state| state.borrow().violations().to_vec())
            .unwrap_or_default()
    }

    /// Returns how many captured-prefix slot reads were checked.
    pub(crate) fn capture_plan_reads_checked(&self) -> u64 {
        self.capture_plan_validation
            .as_ref()
            .map(|state| state.borrow().reads_checked())
            .unwrap_or(0)
    }

    /// Alloc hook: records a `Node` thunk whose site has a flat plan.
    pub(super) fn capture_validation_record_alloc(
        &self,
        site: IrId,
        value: Value,
        kind_is_node: bool,
    ) {
        let Some(state) = self.capture_plan_validation.as_ref() else {
            return;
        };
        if !kind_is_node {
            return;
        }
        let Some(plan) = self.current_ir().facts.capture_plan(site) else {
            return;
        };
        state
            .borrow_mut()
            .record_alloc(value.payload_bits(), site, self.current_module, plan);
    }

    /// Force hook: arms validation before a `Node` thunk body runs.
    pub(super) fn capture_validation_arm_force(&self, source_thunk: Value, kind: &EvalThunkKind) {
        let Some(state) = self.capture_plan_validation.as_ref() else {
            return;
        };
        if matches!(kind, EvalThunkKind::Node { .. }) {
            state.borrow_mut().arm_force(source_thunk.payload_bits());
        }
    }

    /// Force hook: disarms any un-consumed pending record.
    pub(super) fn capture_validation_disarm(&self) {
        if let Some(state) = self.capture_plan_validation.as_ref() {
            state.borrow_mut().disarm();
        }
    }

    /// Env hook: notes a frame-stack swap installing `swapped_in_len` frames.
    pub(super) fn capture_validation_on_swap(&self, swapped_in_len: usize) {
        if let Some(state) = self.capture_plan_validation.as_ref() {
            state.borrow_mut().on_swap(swapped_in_len);
        }
    }

    /// Env hook: notes a frame-stack restore.
    pub(super) fn capture_validation_on_restore(&self) {
        if let Some(state) = self.capture_plan_validation.as_ref() {
            state.borrow_mut().on_restore();
        }
    }

    /// Read hook: checks one `Local`/`Upval` resolution.
    pub(super) fn capture_validation_on_slot_read(&self, depth: usize, slot: u32) {
        if let Some(state) = self.capture_plan_validation.as_ref() {
            state
                .borrow_mut()
                .on_slot_read(self.active_env_frame_count(), depth, slot);
        }
    }
}
