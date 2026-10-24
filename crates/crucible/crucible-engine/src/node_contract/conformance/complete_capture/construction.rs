//! Quotes genuine archived Host construction and observes its existing source.
//!
//! The immutable archive remains an actual issued source allocation. These DATA
//! loans retain no new right, graph, native proof or scheduler authority.

use super::*;
use std::mem::size_of;

impl CollectingCompleteRestorationSource {
    /// Quotes the new Host node from this actual archived source and owner.
    ///
    /// This projection checks the same archive ticket before and after reading
    /// original capacities. Graph binding and node construction remain separate
    /// owning operations; the returned data grants neither.
    ///
    /// # Errors
    /// Refuses another archive Host, a spent node phase, changed activation,
    /// unknown storage or demand above the supplied bound.
    pub fn original_archived_host_node_construction_storage_data(
        &self,
        host: &Rc<super::super::HostSchedulingSource>,
        target: &ActivationRecord,
        maximum: usize,
    ) -> Result<super::super::HostCollectionNodeConstructionStorageData, RuntimeError> {
        self.original.inner.authenticate_birth()?;
        host.original_archived_collection_node_construction_storage_data(
            &self.original.inner,
            target,
            maximum,
        )
    }

    /// Names the archived Host quote's defining borrowed and result views.
    pub fn original_archived_host_node_construction_counter_scratch_data() -> usize {
        use std::mem::size_of;
        super::super::HostSchedulingSource::original_collection_node_construction_counter_scratch_data()
            + super::super::HostSchedulingSource::original_archived_collection_node_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Result<(), RuntimeError>>()
    }

    /// Checks the same bound graph allocation without invoking graph callbacks.
    ///
    /// This origin/identity check is suitable for a prepaid storage walk. Full
    /// graph, Source and current native validation remain separate caller work.
    ///
    /// # Errors
    /// Refuses a foreign creator, unbound source or another original plan.
    pub fn authenticate_original_construction_plan_data(
        &self,
        graph: &ConformanceGraph,
    ) -> Result<(), RuntimeError> {
        self.original.inner.authenticate_birth()?;
        if !self
            .original
            .inner
            .collecting_plan()?
            .is_some_and(|plan| plan.same_original(graph.plan()))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.original.inner.authenticate_birth()
    }

    /// Borrows this same archive after a raw original target-plan check.
    ///
    /// This loan invokes no graph/currentness callback and issues no restoration
    /// permission. The caller separately authenticates full graph currency.
    ///
    /// # Errors
    /// Refuses another creator, unbound source or a different original graph plan.
    pub fn original_construction_source_data(
        &self,
        graph: &ConformanceGraph,
    ) -> Result<&crate::node_state::CompleteOriginalRestorationSource, RuntimeError> {
        self.authenticate_original_construction_plan_data(graph)?;
        Ok(&self.original)
    }

    /// Counts the actual inactive restoration runtime under this same source.
    ///
    /// The runtime retains its genuine bound graph, ticketed Host and original
    /// scheduling allocation. This does not create a context or renew a phase.
    ///
    /// # Errors
    /// Refuses another source/plan/activation, unknown child ownership, busy
    /// storage, arithmetic overflow or backing above the supplied maximum.
    pub fn retained_original_construction_runtime_storage_data(
        &self,
        runtime: &ConformanceRuntime,
        graph: &ConformanceGraph,
        target: &ActivationRecord,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_construction_plan_data(graph)?;
        runtime.original_restoration_retained_storage_precredit_data(
            &self.original,
            graph.plan(),
            target,
            maximum,
        )
    }

    /// Counts this same inactive restoration runtime's actual descriptor views.
    ///
    /// # Errors
    /// Refuses another original source/plan/activation or unknown descriptor custody.
    pub fn retained_original_construction_runtime_descriptor_data(
        &self,
        runtime: &ConformanceRuntime,
        graph: &ConformanceGraph,
        target: &ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_construction_plan_data(graph)?;
        runtime.original_restoration_descriptor_views_precredit_data(
            &self.original,
            graph.plan(),
            target,
        )
    }

    /// Counts the actual archive and Host metadata through graph/runtime construction.
    ///
    /// The supplied Host must own this same issued archive ticket. Existing
    /// runtime backing is excluded and must be counted by its actual owner;
    /// the Host's shared root also remains the caller's independent term.
    /// Revocation or a spent node phase never erases retained storage.
    ///
    /// # Errors
    /// Refuses another creator/archive, unknown shapes, busy ownership loans,
    /// arithmetic overflow or actual backing above the supplied maximum.
    pub fn retained_original_construction_source_storage_data(
        &self,
        host: &Rc<super::super::HostSchedulingSource>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.original.inner.authenticate_birth()?;
        let bytes = host.retained_restoration_metadata_bytes_excluding_runtime_precredit_data(
            &self.original,
            maximum,
        )?;
        self.original.inner.authenticate_birth()?;
        Ok(bytes)
    }

    /// Names explicit archived source/Host construction observer views.
    pub fn original_construction_source_counter_scratch_data() -> usize {
        super::super::HostSchedulingSource::retained_restoration_metadata_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&ConformanceGraph>()
            + size_of::<&Rc<super::super::HostSchedulingSource>>()
            + size_of::<Option<InstalledConformancePlan>>()
            + size_of::<Result<Option<InstalledConformancePlan>, RuntimeError>>()
            + size_of::<&crate::node_state::CompleteOriginalRestorationSource>()
            + size_of::<Result<&crate::node_state::CompleteOriginalRestorationSource, RuntimeError>>(
            )
            + size_of::<&ConformanceRuntime>()
            + size_of::<&ActivationRecord>()
            + ConformanceRuntime::original_restoration_target_counter_scratch_data()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + 2 * size_of::<usize>()
    }
}

impl CollectingCompleteRestorationSource {
    /// Counts the same completed archive before creating its distinct Host17 source.
    ///
    /// No fresh source, native owner, node, runtime or World is created by this
    /// independently admitted census. Actual external code/holder backing and
    /// source-constructor demand remain separate terms in the caller's action.
    ///
    /// # Errors
    /// Refuses another actual ticket, a non-current17 or bound archive, missing
    /// original issuance, busy ownership, overflow or the supplied bound.
    pub fn retained_original_host17_preconstruction_storage_data(
        &self,
        ticket: &crate::node_state::CompleteOriginalHostTicket,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.original
            .retained_original_host17_preconstruction_storage_data(ticket, maximum)
    }

    /// Names the complete archived Source and actual preconstruction loan views.
    pub fn original_host17_preconstruction_counter_scratch_data() -> usize {
        crate::node_state::CompleteOriginalRestorationSource::original_host17_preconstruction_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&crate::node_state::CompleteOriginalHostTicket>()
            + size_of::<Result<usize, RuntimeError>>()
    }
}

impl CollectingCompleteRestorationSource {
    /// Counts the actual current17 Source retained before a prebirth completes.
    ///
    /// The caller keeps this output through loader guards and ticket transfers.
    /// This observes complete backing and once state without requiring every
    /// ticket to have been issued; it grants no target or native permission.
    /// Its wrapper header is already part of the caller's owning slot.
    ///
    /// # Errors
    /// Refuses another creator/family, busy backing, overflow or the supplied
    /// finite retained-storage bound.
    pub fn retained_restored_settled_prebirth_output_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.original
            .retained_restored_settled_prebirth_output_storage_data(maximum)
    }
}
