//! Validation of reference writebacks against root storage and heap fields.

use super::*;

impl TreeWalk {
    /// Validates complete reference writebacks for roots and live heap fields.
    ///
    /// This is the read-only companion to
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    /// It validates the complete root+heap-field partition against
    /// caller-owned typed root slots and live heap-field slots, validates that
    /// the live remembered set and card table still match the source state
    /// consumed by the plan, then stages the existing-destination object
    /// body/generation writes, live heap-field writes, and
    /// remembered/card-table barriers without committing any of those staged
    /// changes to the evaluator.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read, if current root or
    /// heap-field validation fails, if the live remembered set or card table no
    /// longer matches the plan's source state, if object-copy request metadata
    /// is inconsistent, if a destination heap record is missing or rejects
    /// paired body/generation staging, if a supported live heap-field write
    /// cannot be staged, or if live-field staging disagrees with the
    /// prevalidated buffer writeback count.
    pub fn validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            plan,
            value_stack,
            &[],
        )
    }

    /// Validates reference writebacks for roots, primop slots, and heap fields.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields`].
    /// It validates generic primop argument root writebacks against
    /// `primop_arguments` before staging live heap-field writes.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read, if current root or
    /// heap-field validation fails, if the live remembered set or card table no
    /// longer matches the plan's source state, if object-copy request metadata
    /// is inconsistent, if a destination heap record is missing or rejects
    /// paired body/generation staging, if a supported live heap-field write
    /// cannot be staged, or if live-field staging disagrees with the
    /// prevalidated buffer writeback count.
    pub fn validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments_and_poll_validation(
            plan,
            value_stack,
            primop_arguments,
            true,
        )
    }

    pub(super) fn validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments_and_poll_validation(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
        primop_arguments: &[Value],
        validate_poll: bool,
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        let application = self
            .apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments_and_poll_validation(
                plan,
                value_stack,
                primop_arguments,
                validate_poll,
            )?;
        self.validate_safepoint_reference_writeback_source_gc_state(plan)?;
        let (copied_writes, direct_writes) = self
            .heap
            .collector_poll_minor_gc_live_heap_field_write_inputs(
                plan.object_body_plan(),
                plan.writebacks().heap_field_writebacks(),
            )?;
        let (object_body_and_generation_write_report, copied_report, direct_report) = self
            .heap
            .validate_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
                plan.object_body_plan(),
                &copied_writes,
                &direct_writes,
                &self.thunk_resolve_remembered_set,
                &self.thunk_resolve_card_table,
            )?;
        let live_heap_field_writebacks = copied_report
            .fields()
            .saturating_add(direct_report.fields());
        validate_live_heap_field_writeback_count(
            live_heap_field_writebacks,
            application.applied_heap_field_writebacks(),
        )?;

        Ok(
            TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight::new(
                application,
                object_body_and_generation_write_report,
                live_heap_field_writebacks,
            ),
        )
    }

    /// Derives and validates complete live reference writebacks from a poll.
    ///
    /// This derives the complete current root+heap-field reference writeback
    /// partition and object-copy plan, then runs the read-only existing
    /// destination live reference preflight in
    /// [`Self::validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// current root or heap-field validation fails, if existing destination
    /// records are missing or reject paired body/generation staging, if live
    /// heap-field barrier staging fails, or if live-field staging disagrees with
    /// the prevalidated buffer writeback count.
    pub fn validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            bases,
            value_stack,
        )?;
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            &plan,
            value_stack,
        )
    }

    /// Derives and validates live reference writebacks with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// current root or heap-field validation fails, if existing destination
    /// records are missing or reject paired body/generation staging, if live
    /// heap-field barrier staging fails, or if live-field staging disagrees with
    /// the prevalidated buffer writeback count.
    pub fn validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self
            .collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
                poll,
                promotion_policy,
                bases,
                value_stack,
                primop_arguments,
            )?;
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            &plan,
            value_stack,
            primop_arguments,
        )
    }

    /// Reserves destinations and validates live reference writebacks.
    ///
    /// This is the reserved-destination counterpart to
    /// [`Self::validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields`].
    /// It validates the supplied poll, reserves placeholder destination records
    /// for current young worker records, derives the live reference plan from
    /// those reservations, then runs the existing read-only live-reference
    /// preflight. The preflight does not publish roots, heap fields,
    /// object-body writes, remembered-set state, or card-table state, but the
    /// destination reservation itself does allocate scratch heap records.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if reserved destination
    /// records reject paired body/generation staging, if live heap-field barrier
    /// staging fails, or if live-field staging disagrees with the prevalidated
    /// buffer writeback count.
    pub fn validate_collector_poll_minor_gc_reserved_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            value_stack,
        )?;
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments_and_poll_validation(
            &plan,
            value_stack,
            &[],
            false,
        )
    }

    /// Reserves destinations and validates live writebacks with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::validate_collector_poll_minor_gc_reserved_reference_writebacks_for_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if reserved destination
    /// records reject paired body/generation staging, if live heap-field barrier
    /// staging fails, or if live-field staging disagrees with the prevalidated
    /// buffer writeback count.
    pub fn validate_collector_poll_minor_gc_reserved_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            primop_arguments,
        )?;
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments_and_poll_validation(
            &plan,
            value_stack,
            primop_arguments,
            false,
        )
    }
}
