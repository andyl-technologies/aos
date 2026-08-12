//! GC-stress boundary accessors and plan/apply/validate operations on [`EvalOutcome`].

use super::*;

impl EvalOutcome {
    /// Returns GC-stress scans recorded at the successful evaluation boundary.
    pub const fn gc_stress_boundary_scans(&self) -> &EvalGcStressBoundaryScans {
        &self.gc_stress_boundary_scans
    }

    /// Returns outcome-owned reference-writeback metadata installed by live dry runs.
    ///
    /// The installed slots are GC-stress bridge metadata. They are not live
    /// evaluator root storage or heap object fields and are not read by ordinary
    /// evaluation.
    pub const fn gc_stress_boundary_minor_gc_reference_writebacks(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
        &self.gc_stress_boundary_minor_gc_reference_writebacks
    }

    /// Returns outcome-owned forwarding destination bindings installed by live dry runs.
    ///
    /// These records are GC-stress bridge metadata. They bind planned
    /// forwarding values to destination-byte snapshots, but they are not ABI
    /// object headers and ordinary evaluation does not read them.
    pub const fn gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings {
        &self.gc_stress_boundary_minor_gc_forwarding_destination_bindings
    }

    /// Returns outcome-owned destination byte snapshots installed by live dry runs.
    ///
    /// These snapshots are GC-stress bridge metadata. They are not live
    /// semispace object bodies and are not read by ordinary evaluation.
    pub const fn gc_stress_boundary_minor_gc_destination_storage(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcLiveDestinationStorage {
        &self.gc_stress_boundary_minor_gc_destination_storage
    }

    /// Returns outcome-owned object-generation metadata installed by live dry runs.
    ///
    /// These records are GC-stress bridge metadata. They are not evaluator heap
    /// record generation fields, old-generation semispace ownership, or object
    /// headers, and ordinary evaluation does not read them.
    pub const fn gc_stress_boundary_minor_gc_object_generations(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcLiveObjectGenerations {
        &self.gc_stress_boundary_minor_gc_object_generations
    }

    /// Returns outcome-owned writeback destination bindings installed by live dry runs.
    ///
    /// These records are GC-stress bridge metadata. They bind installed
    /// root/heap-field writeback snapshots to destination-byte snapshots, but
    /// they are not live evaluator root slots or heap object fields and
    /// ordinary evaluation does not read them.
    pub const fn gc_stress_boundary_minor_gc_writeback_destination_bindings(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
        &self.gc_stress_boundary_minor_gc_writeback_destination_bindings
    }

    /// Matches installed destination-byte snapshots to object generations.
    ///
    /// This validates outcome-owned GC-stress bridge metadata only. Each
    /// returned binding proves that an installed destination payload's
    /// copy/promote action, destination generation, and byte length agree with
    /// its object-copy request. It does not bind bytes to heap-object storage,
    /// mutate object-generation metadata, or validate object liveness.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if an installed destination request disagrees
    /// with its copy action, if the installed byte snapshot length differs from
    /// the request size, if duplicate destination snapshots are present, or if
    /// the binding report cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_destination_object_generation_bindings(
        &self,
    ) -> Result<Vec<EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding>, EvalHeapError>
    {
        boundary_minor_gc_destination_object_generation_bindings(
            &self.gc_stress_boundary_minor_gc_destination_storage,
        )
    }

    /// Plans live object-generation writes from installed live metadata.
    ///
    /// This validates installed live object-generation metadata against
    /// installed destination-byte snapshots. The returned plan is an immutable
    /// input set for a future heap-record generation writer; it does not mutate
    /// heap records, bind destination bytes to heap-object storage, validate
    /// semispace ownership, or publish old-generation metadata.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if an installed object-generation record has
    /// no installed destination snapshot, if an installed destination snapshot
    /// has no installed object-generation record, if object-generation metadata
    /// disagrees with its byte-copy request or destination snapshot, if either
    /// installed table contains duplicate identities, if destination generation
    /// or payload-size validation fails, or if the plan cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_object_generation_write_plan(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcObjectGenerationWritePlan, EvalHeapError> {
        boundary_minor_gc_object_generation_write_plan(
            &self.gc_stress_boundary_minor_gc_destination_storage,
            &self.gc_stress_boundary_minor_gc_object_generations,
        )
    }

    /// Binds relocated destination bodies to live heap records.
    ///
    /// This consumes the installed boundary object-generation write plan,
    /// revalidates the installed destination-byte and generation metadata,
    /// lowers its object-copy requests to the heap-level body writer, and
    /// mutates only existing destination heap records by cloning current source
    /// record bodies. It still does not write installed byte buffers directly,
    /// write destination generation metadata, allocate synthetic destination
    /// records, reserve semispace storage, mutate roots or heap fields, write
    /// ABI object headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed destination/object-generation
    /// metadata is inconsistent, if a source is no longer a young survivor, if a
    /// source or destination layout no longer matches the request, if a
    /// destination address does not belong to the evaluator heap, if a request's
    /// action and generation disagree, or if the heap-level body write plan
    /// cannot reserve storage. When an error is returned, destination heap-record
    /// bodies are left unchanged.
    pub fn apply_gc_stress_boundary_minor_gc_live_object_bodies(
        &mut self,
    ) -> Result<AllocationCollectorPollObjectBodyWriteReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_object_generation_write_plan()?;
        apply_boundary_minor_gc_live_object_bodies(&mut self.heap, &plan)
    }

    /// Applies installed object-generation metadata to live heap records.
    ///
    /// This consumes the installed boundary object-generation write plan,
    /// lowers it to the heap-level generation writer, and mutates only existing
    /// destination heap records. It still does not bind destination object
    /// bodies, allocate synthetic destination records, reserve semispace
    /// storage, mutate roots or heap fields, write ABI object headers, or
    /// invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed object-generation metadata is
    /// inconsistent, if a source is no longer a young survivor, if a destination
    /// address does not belong to the evaluator heap, if a request's action and
    /// generation disagree, or if the heap-level generation write plan cannot
    /// reserve storage. When an error is returned, heap-record generation
    /// metadata is left unchanged.
    pub fn apply_gc_stress_boundary_minor_gc_live_object_generations(
        &mut self,
    ) -> Result<AllocationCollectorPollObjectGenerationWriteReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_object_generation_write_plan()?;
        apply_boundary_minor_gc_live_object_generations(&mut self.heap, &plan)
    }

    /// Validates relocated destination bodies and generations against live heap records.
    ///
    /// This consumes the installed boundary object-generation write plan,
    /// revalidates the installed destination-byte and generation metadata, and
    /// stages the heap-level paired body/generation writes without committing
    /// them. It is a read-only preflight for existing destination records only:
    /// it does not write object bodies, mutate generation metadata, allocate
    /// synthetic destination records, reserve semispace storage, mutate roots or
    /// heap fields, write ABI object headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed destination/object-generation
    /// metadata is inconsistent, if a source is no longer a young survivor, if a
    /// source or destination layout no longer matches the request, if a
    /// destination address does not belong to the evaluator heap, if a request's
    /// action and generation disagree, or if paired heap-level write planning
    /// cannot reserve storage. Whether this returns `Ok` or `Err`, destination
    /// heap-record bodies and generations are left unchanged.
    pub fn validate_gc_stress_boundary_minor_gc_live_object_bodies_and_generations(
        &self,
    ) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_object_generation_write_plan()?;
        validate_boundary_minor_gc_live_object_bodies_and_generations(&self.heap, &plan)
    }

    /// Binds relocated destination bodies and generations to live heap records.
    ///
    /// This consumes the installed boundary object-generation write plan,
    /// revalidates the installed destination-byte and generation metadata, and
    /// lowers its object-copy requests to the heap-level paired body/generation
    /// writer. Only existing destination heap records are mutated, and body and
    /// generation writes are staged together before either side is committed. It
    /// still does not write installed byte buffers directly, allocate synthetic
    /// destination records, reserve semispace storage, mutate roots or heap
    /// fields, write ABI object headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed destination/object-generation
    /// metadata is inconsistent, if a source is no longer a young survivor, if a
    /// source or destination layout no longer matches the request, if a
    /// destination address does not belong to the evaluator heap, if a request's
    /// action and generation disagree, or if paired heap-level write planning
    /// cannot reserve storage. When an error is returned, destination heap-record
    /// bodies and generations are left unchanged.
    pub fn apply_gc_stress_boundary_minor_gc_live_object_bodies_and_generations(
        &mut self,
    ) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_object_generation_write_plan()?;
        apply_boundary_minor_gc_live_object_bodies_and_generations(&mut self.heap, &plan)
    }

    /// Matches installed forwarding values to destination-byte snapshots.
    ///
    /// This validates outcome-owned GC-stress bridge metadata only. Each
    /// returned binding proves that an installed source forwarding value points
    /// at the destination payload and action-implied generation produced for the
    /// same source. It does not write ABI object headers, bind bytes to
    /// heap-object storage, mutate object-generation state, or validate object
    /// liveness.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if an installed destination snapshot has no
    /// matching forwarding value, if an installed forwarding value has no
    /// destination snapshot, if forwarding metadata is not heap-backed, if the
    /// forwarding destination or generation disagrees with its destination
    /// snapshot, if destination generation or payload-size validation fails, or
    /// if the binding report cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_forwarding_destination_bindings(
        &self,
    ) -> Result<Vec<EvalGcStressBoundaryMinorGcForwardingDestinationBinding>, EvalHeapError> {
        boundary_minor_gc_forwarding_destination_bindings(
            &self.heap,
            &self.gc_stress_boundary_minor_gc_destination_storage,
        )
    }

    /// Plans ABI forwarding-header writes from installed live metadata.
    ///
    /// This validates the installed live forwarding cells against the
    /// outcome-owned forwarding-destination binding side table. The returned
    /// plan is an immutable input set for a future ABI object-header writer; it
    /// does not write headers, bind destination bytes to heap-object storage,
    /// mutate object-generation state, or validate semispace ownership.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if an installed forwarding value has no
    /// installed forwarding-destination binding, if an installed binding has no
    /// matching live forwarding value, if the live forwarding value disagrees
    /// with the installed binding, if a binding source no longer belongs to the
    /// evaluator heap, or if the plan cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_forwarding_header_write_plan(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan, EvalHeapError> {
        boundary_minor_gc_forwarding_header_write_plan(
            &self.heap,
            &self.gc_stress_boundary_minor_gc_forwarding_destination_bindings,
        )
    }

    /// Matches installed root writebacks to installed destination-byte snapshots.
    ///
    /// This validates outcome-owned GC-stress bridge metadata only. Each
    /// returned binding proves that an installed typed root replacement, its
    /// generation-style root slot, and an installed destination-byte snapshot
    /// agree on the same destination object. It does not mutate live evaluator
    /// roots, bind destination bytes to heap-object storage, or validate object
    /// liveness.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root writeback metadata is
    /// internally inconsistent, if a typed root value is not heap-backed, if a
    /// root replacement points at no installed destination-byte snapshot, if the
    /// destination generation disagrees with the matched copy action, if an
    /// installed destination request disagrees with its copy action, or if the
    /// binding report cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_root_writeback_destination_bindings(
        &self,
    ) -> Result<Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>, EvalHeapError>
    {
        boundary_minor_gc_root_writeback_destination_bindings(
            &self.gc_stress_boundary_minor_gc_reference_writebacks,
            &self.gc_stress_boundary_minor_gc_destination_storage,
        )
    }

    /// Plans live root writes from installed live metadata.
    ///
    /// This validates installed live root writeback metadata against installed
    /// root destination-binding metadata. The returned plan is an immutable
    /// input set for a future live root writer; it does not mutate evaluator
    /// roots, bind destination bytes to heap-object storage, or validate
    /// semispace ownership.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root writeback metadata is
    /// internally inconsistent, if a root writeback has no installed
    /// destination binding, if an installed destination binding disagrees with
    /// the root writeback, if an installed root destination binding has no
    /// installed live writeback, if installed writebacks or bindings contain
    /// duplicate root identities, if a binding's byte-copy request disagrees
    /// with its destination, generation, or payload bytes, or if the plan
    /// cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_root_writeback_write_plan(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcRootWritebackWritePlan, EvalHeapError> {
        boundary_minor_gc_root_writeback_write_plan(
            &self.gc_stress_boundary_minor_gc_reference_writebacks,
            &self.gc_stress_boundary_minor_gc_writeback_destination_bindings,
        )
    }

    /// Applies supported boundary root writes to this outcome's returned value.
    ///
    /// This is a narrow live-root precursor for the synthetic boundary
    /// value-stack root published by
    /// `TreeWalk::gc_stress_boundary_scans`. It accepts only
    /// `ValueStack { slot: 0 }`, validates that [`Self::value`] still contains
    /// the expected young from-space object, and validates that the replacement
    /// destination already belongs to this outcome's heap with the generation
    /// carried by the write plan. It also requires the destination object body to
    /// be bound to the planned source by
    /// [`EvalHeap::validate_collector_poll_minor_gc_object_body_binding`] before
    /// mutating the returned value. It does not bind destination bodies itself,
    /// allocate destination records, mutate active evaluator frames, rewrite
    /// import caches, update JIT stack maps, or commit semispace state.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root-writeback metadata is
    /// inconsistent, if the write plan contains a root source other than the
    /// outcome-owned value-stack slot 0, if more than one write targets that
    /// physical outcome slot, if the returned value no longer holds the expected
    /// from-space source, if the source/destination heap records are missing or
    /// have the wrong generation, or if the destination object body is not bound
    /// to the planned source.
    pub fn apply_gc_stress_boundary_minor_gc_outcome_root_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_root_writeback_write_plan()?;
        apply_boundary_minor_gc_outcome_root_writebacks(&mut self.value, &self.heap, &plan)
    }

    /// Binds root replacement bodies and applies supported outcome root writes.
    ///
    /// This consumes the installed live root-writeback metadata and installed
    /// root writeback-destination bindings for the outcome-owned
    /// `ValueStack { slot: 0 }` root. It first validates that the current returned
    /// value still holds the expected young from-space object. It then applies
    /// paired object-body/generation writes only for the replacement requests
    /// named by that outcome-root write plan, and finally rewrites
    /// [`Self::value`] through
    /// [`Self::apply_gc_stress_boundary_minor_gc_outcome_root_writebacks`]'s
    /// binding checks.
    ///
    /// This is a narrow live-root bridge for GC-stress experiments. It does not
    /// install live metadata, allocate destination records, reserve semispace
    /// storage, mutate active evaluator frames or import caches, update JIT stack
    /// maps, mutate heap fields, write ABI forwarding headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root-writeback metadata is
    /// inconsistent, if the write plan contains an unsupported root source, if the
    /// returned value no longer holds the expected from-space source, if a source
    /// heap record is missing or has the wrong generation, if a destination heap
    /// record is missing or rejects the paired body/generation write, or if the
    /// final outcome-root binding check fails. Root prevalidation happens before
    /// destination object bodies or generations are written; when a paired-write
    /// error is returned, the paired writer leaves destination bodies and
    /// generations unchanged.
    pub fn apply_gc_stress_boundary_minor_gc_live_outcome_root_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveOutcomeRootWritebackReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_root_writeback_write_plan()?;
        apply_boundary_minor_gc_live_outcome_root_writebacks(&mut self.value, &mut self.heap, &plan)
    }

    /// Preflights supported live reference writebacks without mutation.
    ///
    /// This consumes the installed live root and heap-field writeback metadata
    /// plus installed writeback-destination bindings. It validates the
    /// outcome-owned `ValueStack { slot: 0 }` root source, current record-owned
    /// heap fields, paired object-body/generation staging for every replacement
    /// or copied writeback object, staged field mutations, and staged
    /// remembered-set/card-table barriers. It returns the same object/root/
    /// field counts the live-reference applicator would cover, but does not
    /// commit any of those staged writes.
    ///
    /// This is a read-only live-reference bridge for GC-stress experiments. It
    /// still requires destination heap records to pre-exist, and it does not
    /// allocate destination records, reserve semispace storage, mutate active
    /// evaluator frames or import caches, update JIT stack maps, rewrite shared
    /// lexical frame slots, blackholed thunk deferred-work/capture fields, or
    /// write ABI forwarding headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root or heap-field writeback
    /// metadata is inconsistent, if the outcome value no longer holds the
    /// expected root source, if a current source field no longer holds its
    /// expected young from-space value, if field or barrier staging fails, if a
    /// destination heap record aliases a direct in-place heap-field write owner,
    /// if a destination heap record is missing or rejects paired
    /// body/generation staging, or if a supported field write cannot be staged.
    /// Whether this returns `Ok` or `Err`, destination object bodies,
    /// generations, heap fields, remembered-set/card-table state, and the
    /// outcome value are left unchanged.
    pub fn validate_gc_stress_boundary_minor_gc_live_reference_writebacks(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport, EvalHeapError>
    {
        let root_plan = self.gc_stress_boundary_minor_gc_root_writeback_write_plan()?;
        let heap_field_plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        validate_boundary_minor_gc_live_reference_writebacks(
            &self.value,
            &self.heap,
            &self.thunk_resolve_remembered_set,
            &self.thunk_resolve_card_table,
            &root_plan,
            &heap_field_plan,
        )
    }

    /// Preflights the existing-destination live commit bridge without mutation.
    ///
    /// This validates installed live forwarding cells against installed
    /// forwarding-destination bindings, verifies that prior live metadata
    /// publication left the card table clean, then validates the installed live
    /// root/heap-field writeback metadata through the read-only reference
    /// writeback preflight. It covers the currently modeled live commit
    /// projections for existing destination records: forwarding-header metadata,
    /// paired object-body/generation staging, outcome-owned value-stack root
    /// writeback, supported record-owned heap-field writes, direct
    /// owner/destination alias rejection, exact published remembered-set
    /// coherence for the writeback-destination metadata, direct
    /// old/permanent-to-young edge coverage, and remembered-set/card-table
    /// barrier staging against side-table clones.
    ///
    /// This is a read-only GC-stress orchestration bridge. It does not write ABI
    /// object headers, commit destination bodies or generations, mutate roots or
    /// heap fields, publish remembered/card state, allocate synthetic
    /// destinations, reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if forwarding-header metadata is missing,
    /// absent for installed reference writebacks, or stale, if installed
    /// root/heap-field writeback metadata is inconsistent, if live roots or
    /// fields no longer hold the expected from-space values, if the card table
    /// is dirty after live metadata publication, if the already-published
    /// remembered set does not match the publication recorded with installed
    /// writeback metadata, if it is missing a direct old/permanent-to-young edge
    /// required by that metadata, if a destination heap record aliases a direct
    /// in-place heap-field write owner, or if existing destination records
    /// reject paired body/generation staging.
    /// Whether this returns `Ok` or `Err`, live forwarding cells, destination
    /// object bodies/generations, roots, heap fields, remembered-set/card-table
    /// state, and the outcome value are left unchanged.
    /// The forwarding-header coverage gate is intentionally a zero-coverage
    /// guard for independently installed reference metadata; future per-source
    /// header coverage belongs with the eventual header writer.
    pub fn validate_gc_stress_boundary_minor_gc_live_existing_destination_commit(
        &self,
    ) -> Result<
        EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitPreflightReport,
        EvalHeapError,
    > {
        let forwarding_header_write_plan =
            self.gc_stress_boundary_minor_gc_forwarding_header_write_plan()?;
        let installed_references = self
            .gc_stress_boundary_minor_gc_reference_writebacks
            .install_report()
            .writebacks();
        validate_boundary_minor_gc_existing_destination_commit_forwarding_header_coverage(
            forwarding_header_write_plan.report(),
            installed_references,
        )?;
        if !self.thunk_resolve_card_table.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcExistingDestinationCommitDirtyCardTable {
                    dirty_cards: self.thunk_resolve_card_table.len(),
                },
            );
        }
        validate_boundary_minor_gc_existing_destination_commit_published_remembered_set(
            &self.thunk_resolve_remembered_set,
            &self.gc_stress_boundary_minor_gc_writeback_destination_bindings,
        )?;
        let reference_writeback_preflight =
            self.validate_gc_stress_boundary_minor_gc_live_reference_writebacks()?;
        Ok(
            EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitPreflightReport::new(
                forwarding_header_write_plan.report(),
                reference_writeback_preflight,
            ),
        )
    }

    /// Validates forwarding metadata and applies supported live reference writes.
    ///
    /// This is the mutating counterpart to
    /// [`Self::validate_gc_stress_boundary_minor_gc_live_existing_destination_commit`].
    /// It first validates installed live forwarding cells against installed
    /// forwarding-destination bindings, including the zero-coverage guard for
    /// independently installed reference metadata, verifies that prior live
    /// metadata publication left the card table clean, checks that the
    /// already-published remembered set exactly matches the publication recorded
    /// with the installed writeback-destination metadata and covers its direct
    /// old/permanent-to-young edges, and clones that remembered set before
    /// mutation. It then consumes installed root and heap-field writeback
    /// metadata plus installed writeback destination bindings through the
    /// live-reference applicator, binding destination object bodies/generations,
    /// rewriting supported record-owned heap fields, updating the prevalidated
    /// outcome root, restoring the published remembered set, and clearing the
    /// card table dirt introduced by the apply-time direct barriers.
    ///
    /// This is a narrow GC-stress orchestration bridge for existing destination
    /// records. It validates forwarding-header metadata but does not write ABI
    /// object headers, allocate synthetic destinations, reserve semispace
    /// storage, mutate active evaluator frames or import caches, update JIT
    /// stack maps, rewrite blackholed thunk
    /// deferred-work/capture fields, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if forwarding-header metadata is missing,
    /// absent for installed reference writebacks, or stale, if installed
    /// root/heap-field writeback metadata is inconsistent, if live roots or
    /// fields no longer hold the expected from-space values, if a destination
    /// heap record aliases a direct in-place heap-field write owner, if existing
    /// destination records reject paired body/generation writes, or if supported
    /// field or remembered/card-table writes cannot be staged, if the card table
    /// is dirty after live metadata publication, if the already-published
    /// remembered set does not match the publication recorded with installed
    /// writeback metadata, if it is missing a direct old/permanent-to-young edge
    /// required by that metadata, or if the published remembered set cannot be
    /// cloned before mutation. Forwarding metadata, card-table, and
    /// remembered-set coherence validation happen before destination object
    /// bodies, generations, roots, heap fields, remembered-set/card-table state,
    /// or the outcome value are changed.
    pub fn apply_gc_stress_boundary_minor_gc_live_existing_destination_commit(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport, EvalHeapError>
    {
        let forwarding_header_write_plan =
            self.gc_stress_boundary_minor_gc_forwarding_header_write_plan()?;
        let installed_references = self
            .gc_stress_boundary_minor_gc_reference_writebacks
            .install_report()
            .writebacks();
        validate_boundary_minor_gc_existing_destination_commit_forwarding_header_coverage(
            forwarding_header_write_plan.report(),
            installed_references,
        )?;
        if !self.thunk_resolve_card_table.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcExistingDestinationCommitDirtyCardTable {
                    dirty_cards: self.thunk_resolve_card_table.len(),
                },
            );
        }
        validate_boundary_minor_gc_existing_destination_commit_published_remembered_set(
            &self.thunk_resolve_remembered_set,
            &self.gc_stress_boundary_minor_gc_writeback_destination_bindings,
        )?;
        let published_remembered_set = self.thunk_resolve_remembered_set.try_clone()?;
        let remembered_set_published_edges = published_remembered_set.len();
        let root_plan = self.gc_stress_boundary_minor_gc_root_writeback_write_plan()?;
        let heap_field_plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        let reference_writeback_apply_report = apply_boundary_minor_gc_live_reference_writebacks(
            &mut self.value,
            &mut self.heap,
            &mut self.thunk_resolve_remembered_set,
            &mut self.thunk_resolve_card_table,
            &root_plan,
            &heap_field_plan,
        )?;
        self.thunk_resolve_remembered_set = published_remembered_set;
        let card_table_clear_report = self.thunk_resolve_card_table.clear_dirty_cards();

        Ok(
            EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport::new(
                forwarding_header_write_plan.report(),
                reference_writeback_apply_report,
                remembered_set_published_edges,
                card_table_clear_report,
            ),
        )
    }

    /// Applies supported boundary heap-field writebacks to live records.
    ///
    /// This consumes the installed heap-field writeback write plan and delegates
    /// relocated nursery-object fields to the copied-object field writer while
    /// applying in-place writes for old-generation worker records or
    /// permanent-shared records whose replacement is promoted to old directly or
    /// copied to young with a remembered-set/card-table barrier published
    /// atomically with the field mutation. The writeback object body for copied
    /// fields and every replacement body must already be bound by
    /// [`EvalHeap::apply_collector_poll_minor_gc_object_body_writes`], and their
    /// destination generations must already be installed. It revalidates the
    /// combined copied/direct object-copy request set before staging any record
    /// mutation. The applicator rewrites record-owned list elements, attrset
    /// bindings, primop arguments, lambda dynamic/global capture arrays,
    /// suspended thunk deferred-work fields, and suspended thunk dynamic/global
    /// capture arrays, and forced thunk cached-result fields.
    /// Direct old/permanent-to-young write barriers are staged against cloned
    /// outcome-owned remembered/card side tables before live side-table
    /// publication and heap mutation. Copied destinations still assume unaliased
    /// collector-owned scratch records because the side table cannot prove
    /// semispace ownership yet. Shared lexical frame slots, blackholed thunk
    /// deferred-work/capture fields, ABI headers, semispace storage, and Tier-B
    /// dispatch remain unsupported.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed heap-field writeback metadata is
    /// inconsistent, if a direct writeback object is not an old worker or
    /// permanent-shared record, if remembered/card side-table staging fails for
    /// a direct old/permanent-to-young replacement, if a copied writeback or
    /// replacement body/generation is not already bound, if the field no longer
    /// contains the expected from-space value, or if the field source is not a
    /// supported record-owned list element, attrset binding, primop argument,
    /// lambda dynamic/global capture array slot, suspended thunk deferred-work
    /// field, suspended thunk dynamic/global capture array slot, or forced thunk
    /// cached-result field.
    pub fn apply_gc_stress_boundary_minor_gc_heap_field_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        apply_boundary_minor_gc_heap_field_writebacks(
            &mut self.heap,
            &mut self.thunk_resolve_remembered_set,
            &mut self.thunk_resolve_card_table,
            &plan,
        )
    }

    /// Preflights supported boundary heap-field writebacks without mutation.
    ///
    /// This consumes the installed heap-field writeback write plan, validates
    /// paired object-body/generation staging for replacement objects and copied
    /// writeback-object destinations, validates current record-owned source
    /// fields, rejects direct in-place field owners that alias those object-copy
    /// destinations, and stages remembered-set/card-table barriers against local
    /// side-table clones. It returns the same object and field counts the
    /// live-field applicator would cover, but does not commit any staged writes.
    ///
    /// This is a read-only live-field bridge for GC-stress experiments. It still
    /// requires destination heap records to pre-exist, and it does not allocate
    /// destination records, reserve semispace storage, mutate shared lexical
    /// frame slots, rewrite blackholed thunk deferred-work/capture fields, write
    /// ABI forwarding headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed heap-field writeback metadata is
    /// inconsistent, if a current source field no longer holds the expected
    /// young from-space value, if field or barrier staging fails, if a
    /// destination heap record aliases a direct in-place heap-field write owner,
    /// or if a destination heap record is missing or rejects paired
    /// body/generation staging. Whether this returns `Ok` or `Err`, destination
    /// object bodies, generations, heap fields, remembered-set/card-table state,
    /// and the outcome value are left unchanged.
    pub fn validate_gc_stress_boundary_minor_gc_live_heap_field_writebacks(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackPreflightReport, EvalHeapError>
    {
        let plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        validate_boundary_minor_gc_live_heap_field_writebacks(
            &self.heap,
            &self.thunk_resolve_remembered_set,
            &self.thunk_resolve_card_table,
            &plan,
        )
    }

    /// Binds heap-field replacement bodies and applies supported field writes.
    ///
    /// This consumes the installed live heap-field writeback metadata and
    /// installed writeback-destination bindings. It first validates request
    /// identities, current source fields, staged field mutations, and staged
    /// remembered-set/card-table publication before mutating destination records.
    /// It then applies paired object-body/generation writes for replacement
    /// objects and copied writeback-object destinations named by the heap-field
    /// write plan, and finally rewrites record-owned heap fields through
    /// [`Self::apply_gc_stress_boundary_minor_gc_heap_field_writebacks`]'s
    /// binding checks.
    ///
    /// This is a narrow live-field bridge for GC-stress experiments. It still
    /// requires destination heap records to pre-exist, and it does not allocate
    /// destination records, reserve semispace storage, mutate shared lexical
    /// frame slots, rewrite blackholed thunk deferred-work/capture fields, write
    /// ABI forwarding headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed heap-field writeback metadata is
    /// inconsistent, if a current source field no longer holds the expected
    /// young from-space value, if field or barrier staging fails, if a
    /// destination heap record aliases a direct in-place heap-field write owner,
    /// if a destination heap record is missing or rejects the paired
    /// body/generation write, or if the final heap-field writeback applicator
    /// fails. Source-field and final field/barrier prevalidation happen before
    /// destination object bodies or generations are written; when a paired-write
    /// error is returned, the paired writer leaves destination bodies and
    /// generations unchanged.
    pub fn apply_gc_stress_boundary_minor_gc_live_heap_field_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        apply_boundary_minor_gc_live_heap_field_writebacks(
            &mut self.heap,
            &mut self.thunk_resolve_remembered_set,
            &mut self.thunk_resolve_card_table,
            &plan,
        )
    }

    /// Binds replacement bodies and applies supported live reference writes.
    ///
    /// This consumes the installed live root and heap-field writeback metadata
    /// plus installed writeback-destination bindings. It validates the
    /// outcome-owned `ValueStack { slot: 0 }` root source, current record-owned
    /// heap fields, staged field mutations, and staged remembered-set/card-table
    /// publication before mutating destination records. It then applies paired
    /// object-body/generation writes for every replacement or copied writeback
    /// object named by the root and heap-field write plans, rewrites supported
    /// record-owned heap fields, and finally writes the already prevalidated
    /// outcome value.
    ///
    /// This is a narrow live-reference bridge for GC-stress experiments. It
    /// still requires destination heap records to pre-exist, and it does not
    /// allocate destination records, reserve semispace storage, mutate active
    /// evaluator frames or import caches, update JIT stack maps, rewrite shared
    /// lexical frame slots, blackholed thunk deferred-work/capture fields, write
    /// ABI forwarding headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root or heap-field writeback
    /// metadata is inconsistent, if the outcome value no longer holds the
    /// expected root source, if a current source field no longer holds its
    /// expected young from-space value, if field or barrier staging fails, if a
    /// destination heap record aliases a direct in-place heap-field write owner,
    /// if a destination heap record is missing or rejects a paired
    /// body/generation write, or if a supported field write cannot be staged.
    /// Root and source-field prevalidation happens before destination object
    /// bodies, generations, heap fields, remembered-set/card-table state, or the
    /// outcome value are changed.
    pub fn apply_gc_stress_boundary_minor_gc_live_reference_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport, EvalHeapError> {
        let root_plan = self.gc_stress_boundary_minor_gc_root_writeback_write_plan()?;
        let heap_field_plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        apply_boundary_minor_gc_live_reference_writebacks(
            &mut self.value,
            &mut self.heap,
            &mut self.thunk_resolve_remembered_set,
            &mut self.thunk_resolve_card_table,
            &root_plan,
            &heap_field_plan,
        )
    }

    /// Applies supported boundary heap-field writebacks to live records.
    ///
    /// This compatibility wrapper preserves the copied-field precursor method
    /// name while delegating to
    /// [`Self::apply_gc_stress_boundary_minor_gc_heap_field_writebacks`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::apply_gc_stress_boundary_minor_gc_heap_field_writebacks`].
    pub fn apply_gc_stress_boundary_minor_gc_copied_heap_field_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport, EvalHeapError> {
        self.apply_gc_stress_boundary_minor_gc_heap_field_writebacks()
    }

    /// Matches installed heap-field writebacks to destination-byte snapshots.
    ///
    /// This validates outcome-owned GC-stress bridge metadata only. Each
    /// returned binding proves that an installed heap-field replacement points
    /// at an installed destination-byte snapshot. For copied nursery-field
    /// writebacks, it also proves that the relocated writeback object has an
    /// installed destination-byte snapshot. It does not mutate live evaluator
    /// object fields, bind destination bytes to heap-object storage, or validate
    /// semispace ownership of destination objects.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed heap-field writeback metadata is
    /// internally inconsistent, if a replacement value is not heap-backed, if a
    /// replacement or copied writeback object points at no installed
    /// destination-byte snapshot, if a copied writeback object snapshot belongs
    /// to another source, if the replacement generation disagrees with the
    /// matched copy action, if an installed destination request disagrees with
    /// its copy action, or if the binding report cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_heap_field_writeback_destination_bindings(
        &self,
    ) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError>
    {
        boundary_minor_gc_heap_field_writeback_destination_bindings_for_heap(
            &self.heap,
            &self.gc_stress_boundary_minor_gc_reference_writebacks,
            &self.gc_stress_boundary_minor_gc_destination_storage,
        )
    }

    /// Plans live heap-field writes from installed live metadata.
    ///
    /// This validates installed live heap-field writeback metadata against
    /// installed heap-field destination-binding metadata. The returned plan is
    /// an immutable input set for the live heap-field bridge or a future
    /// broader live object-field writer; it does not mutate evaluator object
    /// fields, bind destination bytes to heap-object storage, or validate
    /// semispace ownership.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed heap-field writeback metadata is
    /// internally inconsistent, if a heap-field writeback has no installed
    /// destination binding, if an installed destination binding disagrees with
    /// the heap-field writeback, if an installed heap-field destination binding
    /// has no installed live writeback, if installed writebacks or bindings
    /// contain conflicting duplicate field identities after exact duplicate
    /// live entries have been canonicalized, if a binding's byte-copy request
    /// disagrees with its replacement destination, generation, or payload bytes,
    /// or if the plan cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_heap_field_writeback_write_plan(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan, EvalHeapError> {
        boundary_minor_gc_heap_field_writeback_write_plan_for_heap(
            &self.heap,
            &self.gc_stress_boundary_minor_gc_reference_writebacks,
            &self.gc_stress_boundary_minor_gc_writeback_destination_bindings,
        )
    }
}
