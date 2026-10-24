//! Lends actual inactive initial runtime members to moved-preparation observation.

use super::*;
use crate::node_adapters::cnp::PacketCompleteSemanticSource;
use crate::node_admission::{CompleteOriginalFreshRestoreHostWindow, InstalledConformancePlan};

impl ConformanceRuntime {
    /// Matches a retained host ticket to this actual inactive initial node.
    ///
    /// This follows the same erased node and its concrete Source/SDK witnesses.
    /// It does not reissue the consumed pre-node Query or grant runtime access.
    ///
    /// # Errors
    /// Refuses restored/activated or foreign-plan custody, an absent node,
    /// another original ticket/Source, or unsupported concrete ownership.
    pub fn inspect_original_initial_preparation_data(
        &self,
        ticket: &CompleteOriginalFreshRestoreHostWindow,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        self.authenticate_initial_origin()?;
        if self.activation.is_some() || !self.graph.plan().same_original(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.runtime
            .inspect_original_initial_preparation_data(ticket, source, plan)
    }

    /// Inspects an actual initial node with a consumed Admit and unissued Query.
    ///
    /// # Errors
    /// Refuses restored/active or foreign-plan custody and changed node owners.
    pub fn inspect_original_admitted_preparation_data(
        &self,
        destination: &crucible_node_format::Id,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        self.authenticate_initial_origin()?;
        if self.activation.is_some() || !self.graph.plan().same_original(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.runtime
            .inspect_original_admitted_preparation_data(destination, source, plan)
    }

    /// Counts the actual initial runtime using each node's same original Source.
    ///
    /// The ordinary inactive observer and ordinary Input/Capture Source walks
    /// retain their strict behavior. This distinct observation retains every
    /// present initial owner, including moved preparations and SDK witnesses.
    ///
    /// # Errors
    /// Refuses restored/activated/foreign-plan custody, missing or duplicate
    /// Sources, unsupported owners, or any ordinary complete-census refusal.
    pub fn retained_original_initial_requested_storage_precredit_data(
        &self,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_initial_origin()?;
        if self.activation.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let runtime = self
            .runtime
            .retained_original_initial_requested_storage_precredit_data(
                sources,
                self.graph.plan(),
                maximum,
            )?;
        let mut counter =
            crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter::new(maximum);
        counter.add(std::mem::size_of::<Self>())?;
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

    /// Names additional actual initial Source/member inspection controls.
    pub fn original_initial_preparation_counter_scratch_data() -> usize {
        NodeRuntime::original_initial_preparation_counter_scratch_data()
            + std::mem::size_of::<&Self>()
            + std::mem::size_of::<&crucible_node_format::Id>()
            + std::mem::size_of::<crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter>(
            )
    }
}
