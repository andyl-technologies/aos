//! Observes the same inactive collecting runtime after its genuine transfer.
//!
//! This is an owning-data loan, not a mutable runtime escape, graph conversion,
//! activation or permission. Unknown node/slot or authority leaves still refuse.

use super::*;
use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
use std::mem::size_of;

impl ConformanceRuntime {
    /// Observes the actual complete inactive wrapper and its retained graph.
    ///
    /// Fixed counter storage is admitted separately before this owning walk.
    /// Source/node/authority observations use their typed precredit paths only.
    /// Retained graph/authority aliases are conservatively charged again across
    /// the independent runtime and graph counters; equal data earns no refund.
    ///
    /// # Errors
    /// Refuses a restored/activated owner, unknown node, authority or custody
    /// slot, foreign scheduling origin, busy ownership or insufficient credit.
    pub fn original_inactive_retained_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_initial_origin()?;
        if self.activation.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.retained_inactive_wrapper_storage_data(maximum)
    }

    fn retained_inactive_wrapper_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let runtime = self
            .runtime
            .original_retained_requested_storage_precredit_data(maximum)?;
        let mut counter = RetainedRuntimeCounter::new(maximum);
        counter.add(size_of::<Self>())?;
        counter.add(runtime)?;
        if counter.rc(&self.graph)? {
            self.graph
                .charge_original_retained_storage_precredit_data(&mut counter)?;
        }
        if let Some(source) = &self.exact_inputs
            && counter.rc(source)?
        {
            counter.add(
                source
                    .retained_original_metadata_bytes_excluding_runtime_precredit_data(maximum)?,
            )?;
        }
        Ok(counter.bytes())
    }

    /// Counts simultaneous Core and nested typed owning-data counter banks.
    ///
    /// Concrete installed-authority scratch remains a named enclosing caller
    /// term, as do compiler/recursive frames and allocator/kernel ownership.
    ///
    /// # Errors
    /// Refuses unsupported child counters, foreign origins or checked overflow.
    pub fn original_inactive_retained_storage_counter_scratch_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.runtime
            .original_retained_requested_storage_precredit_scratch_data()?
            .checked_add(size_of::<RetainedRuntimeCounter>())
            .ok_or(RuntimeError::ResourceLimit)
    }
}

impl ConformanceRuntime {
    /// Observes actual same-node and original-slot descriptor views while inactive.
    ///
    /// # Errors
    /// Refuses activated/restored/unknown owners or a checked overflow.
    pub fn original_inactive_descriptor_views_precredit_data(&self) -> Result<usize, RuntimeError> {
        self.authenticate_initial_origin()?;
        if self.activation.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.runtime
            .original_inactive_descriptor_views_precredit_data()
    }
}

impl ConformanceRuntime {
    /// Names the closed four-node inactive owning-observer counter composition.
    ///
    /// The runtime counter remains live beside the largest sequential child:
    /// three known CNP nodes, the original Host node, the original QueueSlot,
    /// or an opaque Core owner view. The Host branch explicitly has three
    /// runtime counters: one parent plus its two nested counters. The queue's
    /// public static row includes the exact QueueSlot counter/borrow fields and
    /// its additional Result view. Unknown actual leaves still refuse.
    ///
    /// The wrapper walk starts after NodeRuntime's owning walk finishes. Their
    /// counters are conservatively summed here, matching the existing instance
    /// getter; no unrelated graph/constructor scratch supplies implicit credit.
    /// The enclosing authority's own callback counters remain caller-funded.
    ///
    /// # Errors
    /// Refuses checked layout overflow before any owning observation.
    pub fn original_fixed_four_inactive_observer_counter_scratch_data()
    -> Result<usize, RuntimeError> {
        use crate::node_adapters::cnp::CnpSemanticPreparation;
        use crate::node_contract::{PreparedHostSchedulingNode, RuntimeCustodyQueue};
        let cnp =
            CnpSemanticPreparation::original_conformance_node_retained_counter_scratch_data()?;
        let host = PreparedHostSchedulingNode::original_inactive_node_counter_scratch_data();
        let slot = RuntimeCustodyQueue::retained_requested_storage_counter_scratch_data()?;
        let opaque = crate::node_contract::runtime::opaque_owner_counter_scratch_data();
        let child = cnp.max(host).max(slot).max(opaque);
        let runtime = size_of::<RetainedRuntimeCounter>()
            .checked_add(child)
            .ok_or(RuntimeError::ResourceLimit)?;
        runtime
            .checked_add(size_of::<RetainedRuntimeCounter>())
            .ok_or(RuntimeError::ResourceLimit)
    }
}

impl ConformanceRuntime {
    /// Observes the actual inactive restoration owner without an initial-origin escape.
    ///
    /// This separate raw path authenticates the same archive/plan/activation and
    /// live scheduler before and after the complete original owning walk. The
    /// old initial-only observation retains its original origin guard. Equal
    /// archive or world labels cannot substitute another runtime allocation.
    ///
    /// # Errors
    /// Refuses another runtime purpose/plan/activation, live scheduler revocation,
    /// unsupported node/slot/authority leaves, busy owners, overflow or the bound.
    pub(crate) fn original_restoration_retained_storage_precredit_data(
        &self,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_restoration_target_data(archive, plan, activation)?;
        let runtime = self
            .runtime
            .original_retained_requested_storage_precredit_data(maximum)?;
        let mut counter = RetainedRuntimeCounter::new(maximum);
        counter.add(size_of::<Self>())?;
        counter.add(runtime)?;
        if counter.rc(&self.graph)? {
            self.graph
                .charge_original_retained_storage_precredit_data(&mut counter)?;
        }
        if let Some(source) = &self.exact_inputs
            && counter.rc(source)?
        {
            counter.add(
                source.retained_restoration_metadata_bytes_excluding_runtime_precredit_data(
                    archive, maximum,
                )?,
            )?;
        }
        self.authenticate_original_restoration_target_data(archive, plan, activation)?;
        Ok(counter.bytes())
    }

    pub(crate) fn original_restoration_descriptor_views_precredit_data(
        &self,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_restoration_target_data(archive, plan, activation)?;
        let count = self
            .runtime
            .original_inactive_descriptor_views_precredit_data()?;
        self.authenticate_original_restoration_target_data(archive, plan, activation)?;
        Ok(count)
    }
}
