//! Root-writeback appliers, reference-writeback planning, and buffer appliers.

use super::*;

impl TreeWalk {
    /// Applies typed root writebacks to explicit tree-walk safepoint roots.
    ///
    /// The supplied `value_stack` represents caller-owned transient slots in the
    /// same order passed to [`Self::safepoint_collector_poll_scan`]. This method
    /// reads every planned root source into a temporary typed slot buffer,
    /// validates that buffer with the existing root-writeback plan, and only
    /// then writes relocated values back to the matching tree-walk root storage.
    ///
    /// This precursor supports mutable tree-walk roots: value-stack slots,
    /// active and suspended lexical frames, active and suspended dynamic
    /// `with` scopes, active and suspended scoped-import globals, active force
    /// continuations, active first-class primop arguments, and ready import-cache
    /// entries. It deliberately does not mutate interned roots,
    /// caller-owned [`EvalRootSource::PrimopArgument`] slots, or JIT stack-map
    /// slots; use
    /// [`Self::apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments`]
    /// when generic primop argument roots are present.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if a planned root source
    /// is unsupported, is not currently live, cannot be read or written, if the
    /// temporary slot buffer cannot be reserved, or if the root writeback plan
    /// rejects the current root values. Validation happens before any real
    /// tree-walk root storage is changed.
    pub fn apply_root_value_writebacks_to_safepoint_roots(
        &mut self,
        plan: &AllocationCollectorPollRootWritebackPlan,
        value_stack: &mut [Value],
    ) -> Result<AllocationCollectorPollRootWritebackReport, TreeWalkSafepointRootWritebackError>
    {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments(
            plan,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Applies typed root writebacks with caller-owned primop argument slots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_root_value_writebacks_to_safepoint_roots`]. It supports the
    /// same evaluator-owned root storage plus generic
    /// [`EvalRootSource::PrimopArgument`] roots backed by `primop_arguments`.
    /// Interned roots and JIT stack-map slots remain unsupported here.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if a planned root source
    /// is unsupported, is not currently live in either caller-owned buffer or
    /// evaluator storage, cannot be read or written, if the temporary slot
    /// buffer cannot be reserved, or if the root writeback plan rejects the
    /// current root values. Validation happens before any root storage is
    /// changed.
    pub fn apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments(
        &mut self,
        plan: &AllocationCollectorPollRootWritebackPlan,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<AllocationCollectorPollRootWritebackReport, TreeWalkSafepointRootWritebackError>
    {
        let mut slots =
            self.safepoint_root_value_writeback_slots(plan, value_stack, primop_arguments)?;
        let report = plan.apply_to_value_slots(&mut slots)?;
        self.validate_safepoint_root_writeback_targets(&slots, value_stack, primop_arguments)?;
        for slot in &slots {
            self.write_safepoint_root_writeback_value(
                slot.source(),
                slot.value(),
                value_stack,
                primop_arguments,
            )?;
        }
        Ok(report)
    }

    /// Derives and applies root writebacks from a current minor-GC poll.
    ///
    /// This is a narrow live-root bridge for tree-walk allocation safepoints. It
    /// scans the current explicit tree-walk roots plus the supplied transient
    /// `value_stack`, builds a card-table-aware minor-GC plan from the
    /// evaluator's live remembered-set and card-table state, materializes
    /// relocation destinations from `bases`, derives the commit reference
    /// writebacks, and applies only the root-backed partition through
    /// [`Self::apply_root_value_writebacks_to_safepoint_roots`].
    ///
    /// Plans with heap-field writebacks are rejected before any root mutation,
    /// because applying only roots would publish a partial live collection. This
    /// helper still does not allocate destination records, copy object bodies,
    /// update heap fields, install forwarding headers, clear card-table state,
    /// publish a remembered-set refresh, reserve semispace storage, consume JIT
    /// stack maps, or dispatch Tier B automatically from allocation sites.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale, if safepoint scanning or minor-GC planning fails, if relocation or
    /// commit metadata cannot be derived, if the commit contains heap-field
    /// writebacks, or if live root validation rejects the current root storage.
    pub fn apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
    ) -> Result<TreeWalkSafepointMinorGcRootWritebackReport, TreeWalkSafepointRootWritebackError>
    {
        let reference_plan = self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            bases,
            value_stack,
        )?;
        let root_writebacks = reference_plan.root_writebacks();
        let heap_field_writebacks = reference_plan.heap_field_writebacks();
        if heap_field_writebacks != 0 {
            return Err(
                TreeWalkSafepointRootWritebackError::UnsupportedHeapFieldWritebacks {
                    heap_field_writebacks,
                },
            );
        }

        let applied = self.apply_root_value_writebacks_to_safepoint_roots(
            reference_plan.writebacks().root_writebacks(),
            value_stack,
        )?;
        Ok(TreeWalkSafepointMinorGcRootWritebackReport::new(
            reference_plan.poll(),
            reference_plan.scanned_roots(),
            reference_plan.scanned_objects(),
            reference_plan.survivors(),
            reference_plan.reference_slots(),
            root_writebacks,
            heap_field_writebacks,
            applied.writebacks(),
        ))
    }

    /// Derives and applies root writebacks with caller-owned primop slots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots`].
    /// It includes generic [`EvalRootSource::PrimopArgument`] roots from
    /// `primop_arguments` in the current safepoint scan and rewrites them only
    /// after the complete root-only partition validates.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale, if safepoint scanning or minor-GC planning fails, if relocation or
    /// commit metadata cannot be derived, if the commit contains heap-field
    /// writebacks, or if live root validation rejects the current root storage.
    pub fn apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<TreeWalkSafepointMinorGcRootWritebackReport, TreeWalkSafepointRootWritebackError>
    {
        let reference_plan = self
            .collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
                poll,
                promotion_policy,
                bases,
                value_stack,
                primop_arguments,
            )?;
        let root_writebacks = reference_plan.root_writebacks();
        let heap_field_writebacks = reference_plan.heap_field_writebacks();
        if heap_field_writebacks != 0 {
            return Err(
                TreeWalkSafepointRootWritebackError::UnsupportedHeapFieldWritebacks {
                    heap_field_writebacks,
                },
            );
        }

        let applied = self.apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments(
            reference_plan.writebacks().root_writebacks(),
            value_stack,
            primop_arguments,
        )?;
        Ok(TreeWalkSafepointMinorGcRootWritebackReport::new(
            reference_plan.poll(),
            reference_plan.scanned_roots(),
            reference_plan.scanned_objects(),
            reference_plan.survivors(),
            reference_plan.reference_slots(),
            root_writebacks,
            heap_field_writebacks,
            applied.writebacks(),
        ))
    }

    /// Derives complete reference writebacks from a current minor-GC poll.
    ///
    /// This helper runs the current tree-walk safepoint scan, card-table-aware
    /// minor-GC planning, destination materialization, commit-plan derivation,
    /// and reference-writeback extraction without mutating roots, heap fields,
    /// object bytes, forwarding headers, remembered sets, or card tables. It is
    /// the shared planning bridge for root-only, existing-destination, and
    /// future broader live-reference safepoint applicators.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale, if safepoint scanning or minor-GC planning fails, or if relocation,
    /// commit, or reference-writeback metadata cannot be derived.
    pub fn collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
    ) -> Result<TreeWalkSafepointMinorGcReferenceWritebackPlan, TreeWalkSafepointRootWritebackError>
    {
        self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            promotion_policy,
            bases,
            value_stack,
            &[],
        )
    }

    /// Derives complete reference writebacks from a poll with spilled primop roots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::collector_poll_minor_gc_reference_writeback_plan_for_safepoint`].
    /// It includes generic [`EvalRootSource::PrimopArgument`] entries from
    /// `primop_arguments` in the precise safepoint scan and later root
    /// writeback partition.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale, if safepoint scanning or minor-GC planning fails, or if relocation,
    /// commit, or reference-writeback metadata cannot be derived.
    pub fn collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<TreeWalkSafepointMinorGcReferenceWritebackPlan, TreeWalkSafepointRootWritebackError>
    {
        let scan = self.safepoint_collector_poll_scan_with_primop_arguments(
            poll,
            value_stack.iter().copied(),
            primop_arguments.iter().copied(),
        )?;
        let scanned_roots = scan.scan().roots().len();
        let scanned_objects = scan.scan().objects().len();
        let source_remembered_set = self
            .thunk_resolve_remembered_set
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let source_card_table = self
            .thunk_resolve_card_table
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let collection_epoch = source_remembered_set.epoch();
        let minor_gc = self.heap.plan_collector_poll_minor_gc_with_card_table(
            &scan,
            source_remembered_set.snapshot(),
            source_card_table.snapshot(),
            collection_epoch,
            promotion_policy,
        )?;
        let survivors = minor_gc.plan().survivors().len();
        let reference_slots = minor_gc.reference_slots().len();
        let destinations = self
            .heap
            .plan_collector_poll_minor_gc_relocation_destinations(&minor_gc, bases)?;
        let commit_plan = minor_gc
            .commit_plan(&destinations)
            .map_err(EvalHeapError::from)?;
        let remembered_set_refreshes = commit_plan.commit_plan().remembered_set_refresh().len();
        let next_remembered_set = commit_plan
            .commit_plan()
            .next_remembered_set()
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let mut forwarding_slots = commit_plan.forwarding_slot_buffer()?;
        commit_plan
            .commit_plan()
            .forwarding_pointers()
            .install_into_slots(&mut forwarding_slots)
            .map_err(EvalHeapError::from)?;
        let object_body_plan = self
            .heap
            .collector_poll_minor_gc_object_byte_copy_plan(&commit_plan)?;
        let writebacks = self
            .heap
            .collector_poll_minor_gc_reference_writeback_plan(&commit_plan)?;
        let placement_plan = destinations.into_placement_plan();
        Ok(TreeWalkSafepointMinorGcReferenceWritebackPlan::new(
            poll,
            scanned_roots,
            scanned_objects,
            survivors,
            reference_slots,
            source_remembered_set,
            source_card_table,
            remembered_set_refreshes,
            next_remembered_set,
            placement_plan,
            forwarding_slots,
            object_body_plan,
            writebacks,
        ))
    }

    /// Derives reference writebacks using reserved destination records.
    ///
    /// This validates `poll`, reserves placeholder destination records for the
    /// current young worker heap records, scans the post-reservation safepoint
    /// roots, and maps the minor-GC survivor frontier onto those reservations.
    /// The returned plan is suitable for the existing live-reference preflight
    /// and applicator paths, which still validate and bind object
    /// body/generation writes before any root or field publication.
    ///
    /// If reserving destination records also produces a collector poll for the
    /// same allocator tier, the plan records that post-reservation poll.
    /// Otherwise, it records the already-validated poll that triggered
    /// reservation. Permanent-shared polls remain current while worker
    /// destination records are reserved.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if `poll` is stale before
    /// reservation, if reservation or scanning fails, if minor-GC planning
    /// fails, or if reserved relocation, commit, object-copy, or
    /// reference-writeback metadata cannot be derived.
    pub fn collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &[Value],
    ) -> Result<TreeWalkSafepointMinorGcReferenceWritebackPlan, TreeWalkSafepointRootWritebackError>
    {
        self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            &[],
        )
    }

    /// Derives reserved-destination writebacks with spilled primop roots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint`].
    /// It includes generic [`EvalRootSource::PrimopArgument`] entries from
    /// `primop_arguments` in the post-reservation safepoint scan.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if `poll` is stale before
    /// reservation, if reservation or scanning fails, if minor-GC planning
    /// fails, or if reserved relocation, commit, object-copy, or
    /// reference-writeback metadata cannot be derived.
    pub fn collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<TreeWalkSafepointMinorGcReferenceWritebackPlan, TreeWalkSafepointRootWritebackError>
    {
        self.validate_current_collector_poll(poll)?;
        let poll_tier = poll.tier();
        let reservations = self
            .heap
            .reserve_current_young_minor_gc_destination_records()?;
        let scan_poll = self
            .current_collector_poll_for_tier(poll_tier)
            .unwrap_or(poll);
        let scan = self.safepoint_collector_poll_scan_with_primop_arguments_for_validated_poll(
            scan_poll,
            value_stack.iter().copied(),
            primop_arguments.iter().copied(),
        )?;
        let scanned_roots = scan.scan().roots().len();
        let scanned_objects = scan.scan().objects().len();
        let source_remembered_set = self
            .thunk_resolve_remembered_set
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let source_card_table = self
            .thunk_resolve_card_table
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let collection_epoch = source_remembered_set.epoch();
        let minor_gc = self.heap.plan_collector_poll_minor_gc_with_card_table(
            &scan,
            source_remembered_set.snapshot(),
            source_card_table.snapshot(),
            collection_epoch,
            promotion_policy,
        )?;
        let survivors = minor_gc.plan().survivors().len();
        let reference_slots = minor_gc.reference_slots().len();
        let destinations = self
            .heap
            .plan_collector_poll_minor_gc_reserved_relocation_destinations(
                &minor_gc,
                &reservations,
            )?;
        let commit_plan = minor_gc
            .commit_plan(&destinations)
            .map_err(EvalHeapError::from)?;
        let remembered_set_refreshes = commit_plan.commit_plan().remembered_set_refresh().len();
        let next_remembered_set = commit_plan
            .commit_plan()
            .next_remembered_set()
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let mut forwarding_slots = commit_plan.forwarding_slot_buffer()?;
        commit_plan
            .commit_plan()
            .forwarding_pointers()
            .install_into_slots(&mut forwarding_slots)
            .map_err(EvalHeapError::from)?;
        let object_body_plan = self
            .heap
            .collector_poll_minor_gc_object_byte_copy_plan(&commit_plan)?;
        let writebacks = self
            .heap
            .collector_poll_minor_gc_reference_writeback_plan(&commit_plan)?;
        let placement_plan = destinations.into_placement_plan();
        Ok(TreeWalkSafepointMinorGcReferenceWritebackPlan::new(
            scan_poll,
            scanned_roots,
            scanned_objects,
            survivors,
            reference_slots,
            source_remembered_set,
            source_card_table,
            remembered_set_refreshes,
            next_remembered_set,
            placement_plan,
            forwarding_slots,
            object_body_plan,
            writebacks,
        ))
    }

    /// Applies complete reference writebacks to caller-owned safepoint buffers.
    ///
    /// This validates a previously derived current-poll reference plan against
    /// the explicit tree-walk roots visible through `value_stack`, reads
    /// caller-owned typed root slots and live heap-field slots, and applies the
    /// planned replacements into those buffers. It does not write the mutated
    /// buffers back to evaluator roots or heap records.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read, if caller-owned buffer
    /// storage cannot be reserved, or if the plan rejects the current root or
    /// live heap-field slots.
    pub fn apply_reference_writebacks_to_safepoint_buffers(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        self.apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
            plan,
            value_stack,
            &[],
        )
    }

    /// Applies complete reference writebacks to buffers with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_reference_writebacks_to_safepoint_buffers`]. It validates
    /// generic [`EvalRootSource::PrimopArgument`] roots against
    /// `primop_arguments` while leaving all mutated roots and heap fields in
    /// caller-owned buffers.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read, if caller-owned buffer
    /// storage cannot be reserved, or if the plan rejects the current root or
    /// live heap-field slots.
    pub fn apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        self.apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments_and_poll_validation(
            plan,
            value_stack,
            primop_arguments,
            true,
        )
    }

    pub(super) fn apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments_and_poll_validation(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
        primop_arguments: &[Value],
        validate_poll: bool,
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        if validate_poll {
            self.validate_current_collector_poll(plan.poll())?;
        }
        let mut root_value_writeback_slots = self.safepoint_root_value_writeback_slots(
            plan.writebacks().root_writebacks(),
            value_stack,
            primop_arguments,
        )?;
        let mut heap_field_writeback_slots = self
            .heap
            .collector_poll_minor_gc_heap_field_writeback_slots(
                plan.writebacks().heap_field_writebacks(),
            )?;
        let report = plan.writebacks().apply_to_value_and_heap_field_slots(
            &mut root_value_writeback_slots,
            &mut heap_field_writeback_slots,
        )?;

        Ok(
            TreeWalkSafepointMinorGcReferenceWritebackBufferApplication::new(
                plan,
                report,
                root_value_writeback_slots,
                heap_field_writeback_slots,
            ),
        )
    }

    /// Derives and applies complete reference writebacks to owned buffers.
    ///
    /// This is the full-partition buffer counterpart to
    /// [`Self::apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots`].
    /// It derives the current root+heap-field reference writeback plan and
    /// applies both partitions to caller-owned buffers only. The evaluator's
    /// roots, heap records, object bodies, forwarding headers, remembered set,
    /// card table, and semispace storage are not mutated.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// the derived writebacks cannot be represented as caller-owned buffers, or
    /// if buffer validation rejects the derived current root or heap-field
    /// slots.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            bases,
            value_stack,
        )?;
        self.apply_reference_writebacks_to_safepoint_buffers(&plan, value_stack)
    }

    /// Derives and applies reference writebacks to buffers with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers`].
    /// It includes `primop_arguments` in the current-poll root scan and applies
    /// resulting generic primop-argument root writebacks into that same buffer.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// the derived writebacks cannot be represented as caller-owned buffers, or
    /// if buffer validation rejects the derived current root or heap-field
    /// slots.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
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
        self.apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
            &plan,
            value_stack,
            primop_arguments,
        )
    }

    /// Applies complete reference writebacks to tree-walk roots and field buffers.
    ///
    /// This is a mixed live-root/buffer bridge for tree-walk allocation
    /// safepoints. It first validates and applies the complete root+heap-field
    /// partition to caller-owned typed root slots and live heap-field slots.
    /// Only after both partitions validate does it write the relocated root
    /// values back to supported tree-walk root storage. Heap-field rewrites stay
    /// in caller-owned buffers; this helper does not mutate evaluator object
    /// fields or bind destination storage.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if
    /// caller-owned buffer storage cannot be reserved, or if the plan rejects
    /// the current root or live heap-field slots. Heap-field and root-target
    /// validation happen before any tree-walk root is rewritten.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers_with_primop_arguments(
            plan,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Applies complete reference writebacks to roots, primop slots, and field buffers.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers`].
    /// Generic primop argument root writebacks are applied to
    /// `primop_arguments`; evaluator-owned roots are written to their existing
    /// tree-walk storage, and heap-field rewrites stay in caller-owned buffers.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if
    /// caller-owned buffer storage cannot be reserved, or if the plan rejects
    /// the current root or live heap-field slots. Heap-field and root-target
    /// validation happen before any tree-walk root is rewritten.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers_with_primop_arguments(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let application = self
            .apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
                plan,
                value_stack,
                primop_arguments,
            )?;
        self.validate_safepoint_root_writeback_targets(
            application.root_value_writeback_slots(),
            value_stack,
            primop_arguments,
        )?;
        for slot in application.root_value_writeback_slots() {
            self.write_safepoint_root_writeback_value(
                slot.source(),
                slot.value(),
                value_stack,
                primop_arguments,
            )?;
        }

        Ok(TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication::new(application))
    }

    /// Derives reference writebacks and applies root storage plus field buffers.
    ///
    /// This derives the complete current root+heap-field reference writeback
    /// partition, prevalidates both partitions, writes supported tree-walk root
    /// storage, and leaves heap-field rewrites in caller-owned buffers.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// buffers cannot be represented, if current root or heap-field validation
    /// fails, or if supported tree-walk root storage cannot be written.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            bases,
            value_stack,
        )?;
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
            &plan,
            value_stack,
        )
    }

    /// Derives reference writebacks for roots, primop slots, and field buffers.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// buffers cannot be represented, if current root or heap-field validation
    /// fails, or if supported root storage cannot be written.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication,
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
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers_with_primop_arguments(
            &plan,
            value_stack,
            primop_arguments,
        )
    }
}
