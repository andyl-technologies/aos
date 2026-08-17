//! Reference-writeback application to root storage and live heap fields.

use super::*;

impl TreeWalk {
    /// Applies complete reference writebacks to roots and live heap fields.
    ///
    /// This is a narrow existing-destination live-reference bridge for
    /// tree-walk allocation safepoints. It first runs the read-only
    /// existing-destination live-reference preflight, validating the complete
    /// root+heap-field partition, the plan's source remembered-set/card-table
    /// state, paired object body/generation staging, live heap-field writes,
    /// and remembered/card-table barrier staging. It also validates that
    /// supported root writeback targets can be written and clones the planned
    /// next remembered set before committing heap state. It then binds the
    /// plan's paired object body/generation writes to already-existing
    /// destination records, applies supported record-owned heap-field writes,
    /// writes the prevalidated root slots back to supported tree-walk root
    /// storage, publishes the planned next remembered set, and clears the live
    /// card table.
    ///
    /// This still requires destination heap records to pre-exist and does not
    /// allocate semispace storage, install forwarding headers, consume JIT
    /// stack maps, or dispatch Tier B from allocation sites. The remembered-set
    /// and card-table publication is limited to this existing-destination
    /// tree-walk bridge.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if current
    /// root or heap-field validation fails, if the live remembered set or card
    /// table no longer matches the plan's source state, if object-copy request
    /// metadata is inconsistent, if a destination heap record is missing or
    /// rejects paired body/generation writes, if a supported live heap-field
    /// write cannot be staged, if the next remembered set cannot be cloned
    /// before mutation, or if live-field staging disagrees with the
    /// prevalidated buffer writeback count.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            plan,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Applies complete reference writebacks to roots, primop slots, and heap fields.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    /// It rewrites generic primop argument roots through `primop_arguments`
    /// after the same full root/heap-field preflight used by the value-stack
    /// path.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if current
    /// root or heap-field validation fails, if the live remembered set or card
    /// table no longer matches the plan's source state, if object-copy request
    /// metadata is inconsistent, if a destination heap record is missing or
    /// rejects paired body/generation writes, if a supported live heap-field
    /// write cannot be staged, if the next remembered set cannot be cloned
    /// before mutation, or if live-field staging disagrees with the
    /// prevalidated buffer writeback count.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let (application, _) = self
            .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
                plan,
                value_stack,
                primop_arguments,
                None,
                true,
            )?;
        Ok(application)
    }

    /// Installs forwarding slots and applies live reference writebacks.
    ///
    /// This is the side-table-forwarding companion to
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    /// It runs the same full root/heap-field preflight, validates the plan's
    /// filled forwarding slots and heap publication work without mutating them,
    /// writes supported roots before forwarding cells are installed, and then
    /// commits the staged forwarding, destination body/generation, heap-field,
    /// remembered-set, and card-table state without further fallible staging.
    ///
    /// This remains side-table forwarding only: it does not write real ABI
    /// object headers, reserve semispace storage, consume JIT stack maps, or
    /// dispatch Tier B from allocation sites.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if current
    /// root or heap-field validation fails, if live forwarding-slot validation
    /// fails, if paired body/generation writes fail, or if live root or
    /// heap-field mutation fails.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            plan,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Installs forwarding slots and applies writebacks with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if current
    /// root or heap-field validation fails, if live forwarding-slot validation
    /// fails, if paired body/generation writes fail, or if live root or
    /// heap-field mutation fails.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let (reference_application, forwarding_install_report) = self
            .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
                plan,
                value_stack,
                primop_arguments,
                Some(plan.forwarding_slots()),
                true,
            )?;
        Ok(
            TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication::new(
                reference_application,
                forwarding_install_report,
            ),
        )
    }

    fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
        forwarding_slots: Option<&[MinorGcForwardingSlot]>,
        validate_poll: bool,
    ) -> Result<
        (
            TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
            AllocationCollectorPollForwardingInstallReport,
        ),
        TreeWalkSafepointRootWritebackError,
    > {
        let preflight = self
            .validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments_and_poll_validation(
                plan,
                value_stack,
                primop_arguments,
                validate_poll,
            )?;
        let TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight {
            buffers: application,
            live_heap_field_writebacks: preflight_live_heap_field_writebacks,
            ..
        } = preflight;
        self.validate_safepoint_root_writeback_targets(
            application.root_value_writeback_slots(),
            value_stack,
            primop_arguments,
        )?;
        let forwarding_install_stage = match forwarding_slots {
            Some(forwarding_slots) => Some(
                self.heap
                    .stage_collector_poll_minor_gc_forwarding_slots(forwarding_slots)?,
            ),
            None => None,
        };
        let next_remembered_set = plan
            .next_remembered_set()
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let remembered_set_published_edges = next_remembered_set.len();
        let (copied_writes, direct_writes) = self
            .heap
            .collector_poll_minor_gc_live_heap_field_write_inputs(
                plan.object_body_plan(),
                plan.writebacks().heap_field_writebacks(),
            )?;
        let planned_live_heap_field_writebacks =
            copied_writes.len().saturating_add(direct_writes.len());
        validate_live_heap_field_writeback_count(
            planned_live_heap_field_writebacks,
            application.applied_heap_field_writebacks(),
        )?;
        let staged_live_heap_field_writes = self
            .heap
            .stage_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
                plan.object_body_plan(),
                &copied_writes,
                &direct_writes,
                &self.thunk_resolve_remembered_set,
                &self.thunk_resolve_card_table,
            )?;
        let live_heap_field_writebacks = staged_live_heap_field_writes.live_heap_field_writebacks();
        let relocation_identity_repair =
            self.stage_relocation_identity_repair(plan.forwarding_slots())?;
        debug_assert_eq!(
            live_heap_field_writebacks,
            preflight_live_heap_field_writebacks
        );
        debug_assert_eq!(
            live_heap_field_writebacks,
            planned_live_heap_field_writebacks
        );
        let (
            forwarding_install_report,
            object_body_and_generation_write_report,
            copied_report,
            direct_report,
        ) = if let Some(forwarding_install_stage) = forwarding_install_stage {
            // Root writes are the final fallible operation in the forwarding
            // path. Do them before installing side-table forwarding cells so a
            // rejected target cannot poison a retry with an occupied forwarding
            // slot.
            for slot in application.root_value_writeback_slots() {
                self.write_safepoint_root_writeback_value(
                    slot.source(),
                    slot.value(),
                    value_stack,
                    primop_arguments,
                )?;
            }
            let forwarding_install_report = self
                .heap
                .commit_collector_poll_minor_gc_staged_forwarding_slots(forwarding_install_stage);
            let (object_body_and_generation_write_report, copied_report, direct_report) = self
                .heap
                .commit_collector_poll_minor_gc_staged_live_heap_field_writes_with_card_table(
                    staged_live_heap_field_writes,
                    &mut self.thunk_resolve_remembered_set,
                    &mut self.thunk_resolve_card_table,
                );
            (
                forwarding_install_report,
                object_body_and_generation_write_report,
                copied_report,
                direct_report,
            )
        } else {
            let (object_body_and_generation_write_report, copied_report, direct_report) = self
                .heap
                .commit_collector_poll_minor_gc_staged_live_heap_field_writes_with_card_table(
                    staged_live_heap_field_writes,
                    &mut self.thunk_resolve_remembered_set,
                    &mut self.thunk_resolve_card_table,
                );
            for slot in application.root_value_writeback_slots() {
                self.write_safepoint_root_writeback_value(
                    slot.source(),
                    slot.value(),
                    value_stack,
                    primop_arguments,
                )?;
            }
            (
                AllocationCollectorPollForwardingInstallReport::default(),
                object_body_and_generation_write_report,
                copied_report,
                direct_report,
            )
        };
        debug_assert_eq!(
            live_heap_field_writebacks,
            copied_report
                .fields()
                .saturating_add(direct_report.fields())
        );
        self.thunk_resolve_remembered_set = next_remembered_set;
        let card_table_clear_report = self.thunk_resolve_card_table.clear_dirty_cards();
        self.commit_relocation_identity_repair(relocation_identity_repair);
        Ok((
            TreeWalkSafepointMinorGcLiveReferenceWritebackApplication::new(
                TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication::new(application),
                object_body_and_generation_write_report,
                live_heap_field_writebacks,
                remembered_set_published_edges,
                card_table_clear_report,
            ),
            forwarding_install_report,
        ))
    }

    /// Derives and applies complete live reference writebacks from a current poll.
    ///
    /// This derives the complete current root+heap-field reference writeback
    /// partition and object-copy plan, then applies the existing-destination live
    /// reference bridge in
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// current root or heap-field validation fails, if existing destination
    /// records are missing or reject paired body/generation writes, or if live
    /// root or heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            bases,
            value_stack,
        )?;
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            &plan,
            value_stack,
        )
    }

    /// Derives and applies live reference writebacks with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// current root or heap-field validation fails, if existing destination
    /// records are missing or reject paired body/generation writes, or if live
    /// root or heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
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
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            &plan,
            value_stack,
            primop_arguments,
        )
    }

    /// Reserves destinations and applies complete live reference writebacks.
    ///
    /// This is the reserved-destination counterpart to
    /// [`Self::apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    /// It validates the current poll, reserves placeholder destination records
    /// for current young worker records, derives the survivor relocation plan
    /// from those reservations, then reuses the existing live-reference
    /// applicator to bind object bodies/generations, rewrite supported
    /// tree-walk roots and live heap fields, publish the rebuilt remembered
    /// set, and clear the card table.
    ///
    /// This still does not reserve semispace pages, install forwarding headers,
    /// consume JIT stack maps, mutate interned roots, or dispatch Tier B from
    /// allocation sites automatically.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if reserved destination
    /// records reject paired body/generation writes, or if live root or
    /// heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            value_stack,
        )?;
        let mut primop_arguments: [Value; 0] = [];
        let (application, _) = self
            .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
                &plan,
                value_stack,
                &mut primop_arguments,
                None,
                false,
            )?;
        Ok(application)
    }

    /// Reserves destinations and applies live writebacks with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if reserved destination
    /// records reject paired body/generation writes, or if live root or
    /// heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            primop_arguments,
        )?;
        let (application, _) = self
            .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
            &plan,
            value_stack,
            primop_arguments,
                None,
                false,
            )?;
        Ok(application)
    }

    /// Reserves destinations, installs forwarding slots, and applies writebacks.
    ///
    /// This is the side-table-forwarding counterpart to
    /// [`Self::apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    /// It derives the reserved-destination plan from the supplied poll and then
    /// applies the plan through
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots`].
    ///
    /// This remains side-table forwarding only: it does not write real ABI
    /// object headers, reserve semispace storage, consume JIT stack maps, or
    /// dispatch Tier B from allocation sites.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if forwarding-slot
    /// validation fails, if reserved destination records reject paired
    /// body/generation writes, or if live root or heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Reserves destinations and applies forwarding writebacks with primop roots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if forwarding-slot
    /// validation fails, if reserved destination records reject paired
    /// body/generation writes, or if live root or heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            primop_arguments,
        )?;
        let (reference_application, forwarding_install_report) = self
            .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
            &plan,
            value_stack,
            primop_arguments,
                Some(plan.forwarding_slots()),
                false,
            )?;
        Ok(
            TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication::new(
                reference_application,
                forwarding_install_report,
            ),
        )
    }

    /// Applies the current tier poll through the reserved forwarding bridge.
    ///
    /// This is the current-poll convenience form of
    /// [`Self::apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots`].
    /// It reads the latest collector poll for `tier` immediately before
    /// reservation, so callers do not have to preserve an
    /// [`AllocationCollectorPoll`] handle across intervening code.
    ///
    /// This remains an explicit tree-walk bridge outside the current tree-walk
    /// allocation precursors: it does not run for arbitrary allocation sites,
    /// write real ABI object headers, reserve semispace storage, consume JIT
    /// stack maps, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if no current poll exists
    /// for `tier`, if destination reservation or planning fails, if current root
    /// or heap-field validation fails, if forwarding-slot validation fails, if
    /// reserved destination records reject paired body/generation writes, or if
    /// live root or heap-field mutation fails.
    pub fn apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
        &mut self,
        tier: RuntimeAllocatorTier,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            tier,
            promotion_policy,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Applies current-poll reserved forwarding writebacks with primop roots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if no current poll exists
    /// for `tier`, if destination reservation or planning fails, if current root
    /// or heap-field validation fails, if forwarding-slot validation fails, if
    /// reserved destination records reject paired body/generation writes, or if
    /// live root or heap-field mutation fails.
    pub fn apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
        &mut self,
        tier: RuntimeAllocatorTier,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let poll = self
            .current_collector_poll_for_tier(tier)
            .ok_or(TreeWalkSafepointScanError::NoCurrentCollectorPoll { tier })?;
        self.apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            primop_arguments,
        )
    }
}
