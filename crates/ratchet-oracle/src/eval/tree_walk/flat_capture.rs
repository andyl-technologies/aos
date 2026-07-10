//! Post-assembly publication of flat lexical captures.
//!
//! Recursive binding frames are filled and may be rewritten by
//! `__overrides` after their closures are allocated. Eligible closures
//! therefore retain the shared frame graph during assembly and are converted
//! only when the outermost binding form reaches its publication boundary.

use super::*;

/// One closure waiting for its enclosing binding frames to become immutable.
#[derive(Clone, Debug)]
pub(super) struct PendingFlatCapture {
    site: EvalNodeRef,
    value: Value,
    tail: crate::heap::flat::FlatValueTailHandle,
    env: EvalEnv,
}

impl PendingFlatCapture {
    const fn new(
        site: EvalNodeRef,
        value: Value,
        tail: crate::heap::flat::FlatValueTailHandle,
        env: EvalEnv,
    ) -> Self {
        Self {
            site,
            value,
            tail,
            env,
        }
    }
}

impl TreeWalk {
    /// Records a flat-plan closure allocated inside binding assembly.
    pub(super) fn defer_flat_capture_if_assembling(
        &mut self,
        id: IrId,
        value: Value,
        tail: Option<crate::heap::flat::FlatValueTailHandle>,
        env: Option<EvalEnv>,
    ) {
        #[cfg(test)]
        let runtime_conversion_enabled = self.capture_plan_validation.is_none();
        #[cfg(not(test))]
        let runtime_conversion_enabled = true;
        if !runtime_conversion_enabled
            || self.order_sensitive_binding_depth == 0
            || !self.heap.supports_post_assembly_flat_capture()
            || !matches!(
                self.current_ir().facts.capture_plan(id),
                Some(CapturePlan::Flat(slots)) if !slots.is_empty()
            )
            || self.pending_flat_captures.try_reserve_exact(1).is_err()
        {
            return;
        }
        let Some(env) = env else {
            return;
        };
        let Some(tail) = tail else {
            return;
        };
        self.pending_flat_captures.push(PendingFlatCapture::new(
            EvalNodeRef::new(self.current_module, id),
            value,
            tail,
            env,
        ));
    }

    /// Closes one binding-assembly scope and publishes eligible captures.
    pub(super) fn finish_order_sensitive_binding_assembly(&mut self, succeeded: bool) {
        debug_assert!(self.order_sensitive_binding_depth > 0);
        if !succeeded {
            self.order_sensitive_binding_failed = true;
        }
        self.order_sensitive_binding_depth = self.order_sensitive_binding_depth.saturating_sub(1);
        self.end_gc_stress_composite_accumulator();
        if self.order_sensitive_binding_depth != 0 {
            return;
        }

        let pending = std::mem::take(&mut self.pending_flat_captures);
        if !self.order_sensitive_binding_failed {
            for capture in pending {
                self.publish_pending_flat_capture(capture);
            }
        }
        self.order_sensitive_binding_failed = false;
    }

    fn publish_pending_flat_capture(&mut self, pending: PendingFlatCapture) {
        let Some(module) = self.modules.get(pending.site.module().index()) else {
            return;
        };
        let Some(CapturePlan::Flat(slots)) = module.ir.facts.capture_plan(pending.site.id()) else {
            return;
        };
        let env = &pending.env;
        let frame_count = env.frame_count();
        let mut buffer = EvalFlatCaptureBuffer::new(pending.site, frame_count);
        for slot in slots {
            let Some(value) = self.captured_env_value_at_depth(
                env,
                usize::from(slot.depth),
                u32::from(slot.slot),
            ) else {
                return;
            };
            if buffer.push(value).is_err() {
                return;
            }
        }

        let replaced = self
            .heap
            .publish_unique_flat_closure_capture(pending.value, pending.tail, buffer.finish())
            .unwrap_or(false);
        debug_assert!(replaced, "unique pending closure must remain replaceable");
    }
}
