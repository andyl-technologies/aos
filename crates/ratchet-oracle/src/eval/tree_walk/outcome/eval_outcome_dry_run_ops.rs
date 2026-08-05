//! Boundary minor-GC plan, commit-preflight, and dry-run operations on [`EvalOutcome`].

use super::*;

impl EvalOutcome {
    /// Builds minor-GC plans from the recorded GC-stress boundary scans.
    ///
    /// This uses the outcome's remembered-set snapshot, dirty-card snapshot, and
    /// the caller-supplied promotion policy. It is planning metadata only: it
    /// does not choose semispace destinations, install forwarding pointers,
    /// rewrite roots or fields, publish remembered sets, clear card-table
    /// storage, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if a recorded boundary scan is stale relative
    /// to the outcome heap, if the remembered set or dirty-card snapshot is
    /// incomplete or invalid for the current heap graph, or if minor-GC planning
    /// fails.
    pub fn gc_stress_boundary_minor_gc_plans(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<EvalGcStressBoundaryMinorGcPlans, EvalHeapError> {
        let remembered_set = self.thunk_resolve_remembered_set.snapshot();
        let card_table = self.thunk_resolve_card_table.snapshot();
        let collection_epoch = self.thunk_resolve_remembered_set.epoch();
        let worker = match self.gc_stress_boundary_scans.worker() {
            Some(scan) => Some(self.heap.plan_collector_poll_minor_gc_with_card_table(
                scan,
                remembered_set,
                card_table,
                collection_epoch,
                promotion_policy,
            )?),
            None => None,
        };
        let permanent_shared = match self.gc_stress_boundary_scans.permanent_shared() {
            Some(scan) => Some(self.heap.plan_collector_poll_minor_gc_with_card_table(
                scan,
                remembered_set,
                card_table,
                collection_epoch,
                promotion_policy,
            )?),
            None => None,
        };
        Ok(EvalGcStressBoundaryMinorGcPlans::new(
            worker,
            permanent_shared,
        ))
    }

    /// Builds relocation destinations from recorded GC-stress boundary scans.
    ///
    /// This derives minor-GC plans with the supplied promotion policy, reads the
    /// outcome heap's current layout metadata for planned survivors, and
    /// materializes relocation destinations from `bases`. It is planning
    /// metadata only: it does not reserve semispace storage, copy object bytes,
    /// install forwarding pointers, rewrite roots or fields, publish remembered
    /// sets, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary minor-GC planning fails, if the
    /// outcome heap changed since planning, if survivor layout metadata cannot be
    /// derived, or if relocation-destination planning rejects the supplied bases.
    pub fn gc_stress_boundary_minor_gc_relocation_destinations(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcRelocationDestinations, EvalHeapError> {
        Ok(self
            .gc_stress_boundary_minor_gc_relocation_plans(promotion_policy, bases)?
            .into_relocation_destinations())
    }

    /// Builds paired minor-GC plans and relocation destinations from boundary scans.
    ///
    /// This derives minor-GC plans with the supplied promotion policy, reads the
    /// outcome heap's current layout metadata for planned survivors, and stores
    /// each plan next to the relocation destinations materialized from `bases`.
    /// The paired report can build commit metadata without recomputing or
    /// mismatching those pieces, but it still does not reserve semispace storage,
    /// copy object bytes, install forwarding pointers, rewrite roots or fields,
    /// publish remembered sets, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary minor-GC planning fails, if the
    /// outcome heap changed since planning, if survivor layout metadata cannot be
    /// derived, or if relocation-destination planning rejects the supplied bases.
    pub fn gc_stress_boundary_minor_gc_relocation_plans(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcRelocationPlans, EvalHeapError> {
        let plans = self.gc_stress_boundary_minor_gc_plans(promotion_policy)?;
        let EvalGcStressBoundaryMinorGcPlans {
            worker,
            permanent_shared,
        } = plans;
        let worker = match worker {
            Some(plan) => {
                let destinations = self
                    .heap
                    .plan_collector_poll_minor_gc_relocation_destinations(&plan, bases)?;
                Some(EvalGcStressBoundaryMinorGcRelocationPlan::new(
                    plan,
                    destinations,
                ))
            }
            None => None,
        };
        let permanent_shared = match permanent_shared {
            Some(plan) => {
                let destinations = self
                    .heap
                    .plan_collector_poll_minor_gc_relocation_destinations(&plan, bases)?;
                Some(EvalGcStressBoundaryMinorGcRelocationPlan::new(
                    plan,
                    destinations,
                ))
            }
            None => None,
        };
        Ok(EvalGcStressBoundaryMinorGcRelocationPlans::new(
            worker,
            permanent_shared,
        ))
    }

    /// Builds owned commit-preflight metadata from GC-stress boundary scans.
    ///
    /// This derives paired boundary relocation plans, builds the borrowed commit
    /// metadata long enough to validate and extract owned object byte-copy
    /// requests, empty forwarding slots, copied reference buffers, daemon-wide
    /// card-table snapshot clones, and reference writeback metadata plus
    /// caller-owned writeback slot buffers, then returns those artifacts beside
    /// the paired relocation plan. It still does not bind object byte buffers,
    /// mutate forwarding slots, rewrite live roots or heap fields, publish
    /// remembered sets, clear the live daemon card table, reserve semispace
    /// storage, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary relocation planning fails, if commit
    /// metadata cannot be built, if heap-backed byte-copy or writeback
    /// validation fails, or if forwarding-slot or card-table snapshot storage
    /// cannot be reserved.
    pub fn gc_stress_boundary_minor_gc_commit_preflights(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitPreflights, EvalHeapError> {
        let plans = self.gc_stress_boundary_minor_gc_relocation_plans(promotion_policy, bases)?;
        let EvalGcStressBoundaryMinorGcRelocationPlans {
            worker,
            permanent_shared,
        } = plans;
        let worker = worker
            .map(|plan| self.gc_stress_boundary_minor_gc_commit_preflight(plan))
            .transpose()?;
        let permanent_shared = permanent_shared
            .map(|plan| self.gc_stress_boundary_minor_gc_commit_preflight(plan))
            .transpose()?;

        Ok(EvalGcStressBoundaryMinorGcCommitPreflights::new(
            worker,
            permanent_shared,
        ))
    }

    /// Runs boundary minor-GC commit preflights against owned dry-run buffers.
    ///
    /// This derives boundary commit preflight metadata from the recorded
    /// GC-stress scans, applies reference writebacks into owned slot copies, and
    /// applies commit plans into owned synthetic byte, owned destination-storage,
    /// forwarding, reference, remembered-set, and card-table buffers. The
    /// returned report carries preflights, writebacks, synthetic commit
    /// applications, and direct owned-storage commit applications for the exact
    /// same worker/permanent-shared partition. It still does not mutate live
    /// evaluator roots, live heap fields, object headers, remembered-set
    /// storage, card-table storage, or semispace pages.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit preflight derivation fails,
    /// if any owned dry-run buffer or destination storage cannot be allocated,
    /// if storage-derived relocation metadata cannot be rebuilt, or if any
    /// owned buffer fails validation against the lower-level commit or writeback
    /// plans.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitDryRun, EvalHeapError> {
        self.gc_stress_boundary_minor_gc_commit_preflights(promotion_policy, bases)?
            .apply_owned_commit_dry_run()
    }

    /// Runs a boundary dry run and installs live side-table forwarding values.
    ///
    /// The method first derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`]. It then validates
    /// that sibling worker/permanent applications form one coherent survivor
    /// relocation map, deduplicates overlapping forwarding sources that agree,
    /// and installs the resulting forwarding values into this outcome's
    /// evaluator heap side table. Empty boundaries, or non-empty boundaries
    /// with no copied/promoted survivors, leave the heap forwarding cells
    /// unchanged.
    ///
    /// This is a live forwarding-metadata bridge for GC-stress experiments, not
    /// a full collector commit. It does not write ABI object headers, bind live
    /// object-byte buffers, mutate roots or heap fields, publish remembered
    /// sets, clear card-table storage, mutate heap-record object generations, reserve
    /// semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling forwarding applications do not form
    /// one coherent survivor relocation map, or if any target heap record is no
    /// longer a young unforwarded survivor. When an error is returned, live heap
    /// forwarding cells are left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveForwardingCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let forwarding_slots =
            boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let forwarding_install_report = self
            .heap
            .install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)?;

        Ok(EvalGcStressBoundaryMinorGcLiveForwardingCommitDryRun::new(
            dry_run,
            forwarding_install_report,
        ))
    }

    /// Runs a boundary dry run and installs forwarding destination bindings.
    ///
    /// The method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`], validates sibling
    /// survivor relocations, merges destination-byte snapshots, matches the
    /// planned forwarding values to those snapshots, and installs the resulting
    /// binding records into outcome-owned metadata. Empty boundaries, or
    /// non-empty boundaries with no copied/promoted survivors, leave the side
    /// table unchanged.
    ///
    /// This is a live forwarding destination-binding metadata bridge for
    /// GC-stress experiments, not a full collector commit. It does not install
    /// forwarding slots, write ABI object headers, bind bytes to live object
    /// bodies, mutate heap-record object generations, reserve semispace storage,
    /// or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if forwarding values do not match the
    /// merged destination snapshots, or if forwarding destination-binding
    /// metadata has already been installed for this outcome. When an error is
    /// returned, the forwarding destination-binding side table is left
    /// unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_destination_bindings(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<
        EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingCommitDryRun,
        EvalHeapError,
    > {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let forwarding_slots =
            boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let forwarding_destination_bindings =
            boundary_minor_gc_forwarding_destination_bindings_from_slots(
                &forwarding_slots,
                &object_bytes,
            )?;
        let forwarding_destination_binding_install_report = self
            .gc_stress_boundary_minor_gc_forwarding_destination_bindings
            .install(forwarding_destination_bindings)?;

        Ok(
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingCommitDryRun::new(
                dry_run,
                forwarding_destination_binding_install_report,
            ),
        )
    }

    /// Runs a boundary dry run and installs outcome-owned destination bytes.
    ///
    /// The method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`]. It validates sibling
    /// worker/permanent applications with the same raw relocation-map coherence
    /// checks used by live remembered-set publication, then merges overlapping
    /// object-copy snapshots that agree before publishing them into this
    /// outcome's destination-byte side table. Empty boundaries, or non-empty
    /// boundaries with no copied/promoted survivors, leave the side table
    /// unchanged.
    ///
    /// This is a live metadata bridge for GC-stress experiments, not a full
    /// collector commit. It does not bind bytes to live heap objects, write ABI
    /// object headers, mutate roots or heap fields, install forwarding headers,
    /// publish remembered sets, clear card-table storage, mutate object
    /// generations, reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if overlapping object-copy snapshots
    /// disagree, or if destination-byte snapshots have already been installed
    /// for this outcome. When an error is returned, the destination-byte side
    /// table is left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveDestinationStorageCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let destination_storage_install_report = self
            .gc_stress_boundary_minor_gc_destination_storage
            .install(object_bytes)?;

        Ok(
            EvalGcStressBoundaryMinorGcLiveDestinationStorageCommitDryRun::new(
                dry_run,
                destination_storage_install_report,
            ),
        )
    }

    /// Runs a boundary dry run and installs outcome-owned object generations.
    ///
    /// The method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`]. It validates sibling
    /// survivor relocations, merges the destination object-copy snapshots, and
    /// installs destination-to-generation metadata derived from each copy action.
    /// Empty boundaries, or non-empty boundaries with no copied/promoted
    /// survivors, leave the side table unchanged.
    ///
    /// This is a live object-generation metadata bridge for GC-stress
    /// experiments, not a full collector commit. It does not mutate evaluator
    /// heap records, allocate old-generation storage, bind bytes to live object
    /// bodies, write object headers, mutate roots or fields, publish remembered
    /// sets, clear card-table storage, reserve semispace storage, or invoke Tier
    /// B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if destination snapshots fail
    /// generation validation, or if object-generation metadata has already been
    /// installed for this outcome. When an error is returned, the
    /// object-generation side table is left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_object_generations(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveObjectGenerationCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let object_generations =
            boundary_minor_gc_live_object_generations_from_objects(&object_bytes)?;
        let object_generation_install_report = self
            .gc_stress_boundary_minor_gc_object_generations
            .install(object_generations)?;

        Ok(
            EvalGcStressBoundaryMinorGcLiveObjectGenerationCommitDryRun::new(
                dry_run,
                object_generation_install_report,
            ),
        )
    }

    /// Runs a boundary dry run and installs writeback destination bindings.
    ///
    /// The method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`], validates sibling
    /// survivor relocations, merges destination-byte snapshots, clones the root
    /// and heap-field writeback snapshots, validates each writeback against the
    /// merged destinations, records the remembered-set publication expected from
    /// the same dry run, and installs the resulting binding records into
    /// outcome-owned metadata. Empty boundaries, or non-empty boundaries with no
    /// writebacks, leave the side table unchanged.
    ///
    /// This is a live writeback destination-binding metadata bridge for
    /// GC-stress experiments, not a full collector commit. It does not mutate
    /// evaluator roots, heap object fields, object bytes, forwarding headers,
    /// remembered-set storage, semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if writeback metadata cannot be
    /// cloned, if root/heap-field destination binding validation fails, or if
    /// writeback destination-binding metadata has already been installed for
    /// this outcome. When an error is returned, the writeback destination-binding
    /// side table is left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_writeback_destination_bindings(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingCommitDryRun, EvalHeapError>
    {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let writebacks =
            clone_boundary_reference_writeback_applications(dry_run.reference_writebacks())?;
        let root_writeback_destination_bindings =
            boundary_minor_gc_root_writeback_destination_bindings_from_applications(
                &writebacks,
                &object_bytes,
            )?;
        let heap_field_writeback_destination_bindings =
            boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications_for_heap(
                &self.heap,
                &writebacks,
                &object_bytes,
            )?;
        let expected_remembered_set = boundary_minor_gc_merged_remembered_set(
            dry_run.commit_applications(),
            self.thunk_resolve_remembered_set.epoch(),
        )?;
        let writeback_destination_binding_install_report = self
            .gc_stress_boundary_minor_gc_writeback_destination_bindings
            .install(
                root_writeback_destination_bindings,
                heap_field_writeback_destination_bindings,
                expected_remembered_set,
            )?;

        Ok(
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingCommitDryRun::new(
                dry_run,
                writeback_destination_binding_install_report,
            ),
        )
    }

    /// Runs a boundary dry run and installs outcome-owned writeback metadata.
    ///
    /// The method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`], validates sibling
    /// survivor relocations with the same raw relocation-map coherence checks
    /// used by the other live side-table bridges, clones the applied root and
    /// heap-field writeback slot buffers, and installs those copies into this
    /// outcome's metadata. Empty boundaries, or non-empty boundaries with no
    /// reference writebacks, leave the side table unchanged.
    ///
    /// This is a live metadata bridge for GC-stress experiments, not a full
    /// collector commit. It does not mutate live root variables, heap fields,
    /// object bytes, forwarding headers, remembered sets, card-table storage,
    /// heap-record object generations, reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling survivor relocations do not form one
    /// coherent map, if writeback metadata cannot be cloned, or if writeback
    /// metadata has already been installed for this outcome. When an error is
    /// returned, the reference-writeback side table is left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let writebacks =
            clone_boundary_reference_writeback_applications(dry_run.reference_writebacks())?;
        let reference_writeback_install_report = self
            .gc_stress_boundary_minor_gc_reference_writebacks
            .install(writebacks)?;

        Ok(
            EvalGcStressBoundaryMinorGcLiveReferenceWritebackCommitDryRun::new(
                dry_run,
                reference_writeback_install_report,
            ),
        )
    }

    /// Runs a boundary dry run and installs all outcome-owned GC metadata.
    ///
    /// The method derives one owned commit dry run, then validates every live
    /// metadata payload derived from it before mutating the outcome: sibling
    /// survivor relocations, destination-byte snapshots, destination
    /// object-generation bindings, forwarding-destination bindings over the
    /// combined installed and planned forwarding cells, reference-writeback
    /// metadata, root/heap-field destination bindings, remembered-set
    /// publication, and live forwarding slots. After those checks pass, it
    /// installs evaluator side-table forwarding values, forwarding-destination
    /// binding metadata, destination-byte snapshots, object-generation metadata,
    /// reference-writeback metadata, writeback destination-binding metadata, the
    /// merged next remembered set, and clears the daemon card table. Empty
    /// boundaries leave the outcome unchanged.
    ///
    /// This is a staged live-metadata bridge for GC-stress experiments, not a
    /// full collector commit. It does not mutate live root variables, heap
    /// fields, object bytes, ABI forwarding headers, evaluator heap-record
    /// generations, reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if destination-byte snapshots or
    /// forwarding-destination, object-generation, reference-writeback, or
    /// writeback destination-binding metadata have already been installed, if
    /// remembered set publication cannot be merged, if destination generation or
    /// writeback destination bindings do not match the dry-run destination
    /// snapshots, if the combined installed and planned forwarding cells do not
    /// match the final destination snapshot view, or if forwarding installation
    /// fails.
    /// All installable side-table payloads are validated before the first live
    /// mutation; if forwarding installation fails, forwarding-destination
    /// binding metadata, destination storage, object-generation metadata,
    /// reference-writeback metadata, writeback destination-binding metadata,
    /// remembered-set state, and card-table state are left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun, EvalHeapError> {
        let (live_metadata, _) = self
            .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata_inner(
                promotion_policy,
                bases,
                false,
            )?;
        Ok(live_metadata)
    }

    /// Runs a boundary dry run, preflights existing destinations, and installs metadata.
    ///
    /// This is the strict existing-destination variant of
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata`].
    /// It derives the same owned dry run and validates the same side-table
    /// payloads, then stages paired heap-record object-body/generation writes
    /// for the merged destination plan before any live forwarding slots,
    /// outcome-owned metadata, remembered-set state, or card-table state are
    /// mutated. Only after that no-mutation preflight succeeds does it install
    /// the same live metadata as the ordinary installer.
    ///
    /// This remains a metadata bridge: it does not commit the staged object-body
    /// or generation writes, allocate synthetic destination records, reserve
    /// semispace storage, mutate roots or heap fields, write ABI object headers,
    /// or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata`],
    /// and also if any copied/promoted destination address does not already
    /// belong to this evaluator heap or if the paired body/generation preflight
    /// cannot be staged. When an error is returned before forwarding
    /// installation, live metadata and heap-record state are left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun, EvalHeapError>
    {
        let (live_metadata, object_body_and_generation_write_report) = self
            .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata_inner(
                promotion_policy,
                bases,
                true,
            )?;
        Ok(
            EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun::new(
                live_metadata,
                object_body_and_generation_write_report,
            ),
        )
    }

    /// Runs the existing-destination boundary commit bridge end to end.
    ///
    /// This composes
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata`]
    /// with
    /// [`Self::apply_gc_stress_boundary_minor_gc_live_existing_destination_commit`]
    /// without exposing a caller interleaving point between metadata
    /// installation and live reference publication. The first phase derives the
    /// boundary dry run, validates installable metadata, and preflights paired
    /// destination body/generation writes for already-bound destination records
    /// before any metadata mutation. The second phase validates installed
    /// forwarding metadata, remembered-set publication, card-table state, roots,
    /// fields, and destination body/generation staging before committing
    /// existing destination bodies/generations, supported heap fields, and the
    /// outcome-owned root.
    ///
    /// This remains a narrow GC-stress bridge for existing destination records.
    /// It does not allocate synthetic destinations, reserve semispace storage,
    /// mutate active evaluator frames or import caches, update JIT stack maps,
    /// write ABI forwarding headers, or invoke Tier B.
    /// It is not an all-or-nothing transaction across both phases: if the first
    /// phase installs forwarding cells, outcome-owned metadata, remembered-set
    /// state, or card-table state and the second phase later returns an error,
    /// those first-phase mutations remain installed. The second phase still
    /// keeps its own validation-before-live-reference-mutation contract.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the metadata dry run or existing-destination
    /// preflight fails, if live metadata cannot be installed, or if the
    /// subsequent existing-destination live commit rejects installed metadata,
    /// roots, heap fields, remembered-set/card-table state, or paired
    /// body/generation writes. Errors from the subsequent live commit are
    /// returned after the metadata phase has already installed its side effects.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_commit(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcExistingDestinationLiveCommit, EvalHeapError> {
        let live_metadata = self
            .gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata(
                promotion_policy,
                bases,
            )?;
        let live_commit =
            self.apply_gc_stress_boundary_minor_gc_live_existing_destination_commit()?;
        Ok(
            EvalGcStressBoundaryMinorGcExistingDestinationLiveCommit::new(
                live_metadata,
                live_commit,
            ),
        )
    }

    fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata_inner(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        preflight_existing_destinations: bool,
    ) -> Result<
        (
            EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun,
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        ),
        EvalHeapError,
    > {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let forwarding_slots =
            boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let destination_storage_install_report =
            live_destination_storage_install_report(&object_bytes);
        self.gc_stress_boundary_minor_gc_destination_storage
            .can_install(destination_storage_install_report)?;
        let object_generations =
            boundary_minor_gc_live_object_generations_from_objects(&object_bytes)?;
        let object_generation_install_report =
            live_object_generation_install_report(&object_generations);
        self.gc_stress_boundary_minor_gc_object_generations
            .can_install(object_generation_install_report)?;
        let forwarding_destination_objects = if object_bytes.is_empty() {
            self.gc_stress_boundary_minor_gc_destination_storage
                .object_bytes()
        } else {
            object_bytes.as_slice()
        };
        let _forwarding_destination_bindings =
            boundary_minor_gc_forwarding_destination_bindings_from_heap_and_slots(
                &self.heap,
                &forwarding_slots,
                forwarding_destination_objects,
            )?;
        let forwarding_destination_bindings =
            boundary_minor_gc_forwarding_destination_bindings_from_slots(
                &forwarding_slots,
                &object_bytes,
            )?;
        let forwarding_destination_binding_install_report =
            live_forwarding_destination_binding_install_report(&forwarding_destination_bindings);
        self.gc_stress_boundary_minor_gc_forwarding_destination_bindings
            .can_install(forwarding_destination_binding_install_report)?;
        let writebacks =
            clone_boundary_reference_writeback_applications(dry_run.reference_writebacks())?;
        let reference_writeback_install_report =
            live_reference_writeback_install_report(&writebacks);
        self.gc_stress_boundary_minor_gc_reference_writebacks
            .can_install(reference_writeback_install_report)?;
        let root_writeback_destination_bindings =
            boundary_minor_gc_root_writeback_destination_bindings_from_applications(
                &writebacks,
                &object_bytes,
            )?;
        let heap_field_writeback_destination_bindings =
            boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications_for_heap(
                &self.heap,
                &writebacks,
                &object_bytes,
            )?;
        let writeback_destination_binding_install_report =
            live_writeback_destination_binding_install_report(
                &root_writeback_destination_bindings,
                &heap_field_writeback_destination_bindings,
            );
        self.gc_stress_boundary_minor_gc_writeback_destination_bindings
            .can_install(writeback_destination_binding_install_report)?;
        let remembered_set = boundary_minor_gc_merged_remembered_set(
            dry_run.commit_applications(),
            self.thunk_resolve_remembered_set.epoch(),
        )?;
        let writeback_expected_remembered_set = remembered_set
            .as_ref()
            .map(clone_boundary_remembered_set)
            .transpose()?;
        let object_body_and_generation_write_report = if preflight_existing_destinations {
            let object_body_plan =
                boundary_minor_gc_object_body_generation_preflight_plan_from_generations(
                    &object_generations,
                )?;
            self.heap
                .validate_collector_poll_minor_gc_object_body_and_generation_writes(
                    &object_body_plan,
                )?
        } else {
            AllocationCollectorPollObjectBodyAndGenerationWriteReport::default()
        };

        let forwarding_install_report = self
            .heap
            .install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)?;

        self.gc_stress_boundary_minor_gc_destination_storage
            .install_prevalidated(object_bytes, destination_storage_install_report);
        self.gc_stress_boundary_minor_gc_forwarding_destination_bindings
            .install_prevalidated(
                forwarding_destination_bindings,
                forwarding_destination_binding_install_report,
            );
        self.gc_stress_boundary_minor_gc_object_generations
            .install_prevalidated(object_generations, object_generation_install_report);
        self.gc_stress_boundary_minor_gc_reference_writebacks
            .install_prevalidated(writebacks, reference_writeback_install_report);
        self.gc_stress_boundary_minor_gc_writeback_destination_bindings
            .install_prevalidated(
                root_writeback_destination_bindings,
                heap_field_writeback_destination_bindings,
                writeback_expected_remembered_set,
                writeback_destination_binding_install_report,
            );
        let remembered_set_published = remembered_set.is_some();
        let card_table_clear_report = if let Some(remembered_set) = remembered_set {
            self.thunk_resolve_remembered_set = remembered_set;
            self.thunk_resolve_card_table.clear_dirty_cards()
        } else {
            GcCardTableClearReport::default()
        };

        Ok((
            EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun::new(
                dry_run,
                forwarding_install_report,
                forwarding_destination_binding_install_report,
                destination_storage_install_report,
                object_generation_install_report,
                reference_writeback_install_report,
                writeback_destination_binding_install_report,
                remembered_set_published,
                card_table_clear_report,
            ),
            object_body_and_generation_write_report,
        ))
    }

    /// Runs a boundary minor-GC dry run and clears the outcome-owned card table.
    ///
    /// The method first derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`]. Only after every
    /// recorded allocator tier has validated and applied its owned synthetic
    /// commit buffers does it clear this outcome's daemon card table. Empty
    /// boundary scans do not clear the table.
    ///
    /// This is a live card-table clearing bridge for GC-stress boundary
    /// experiments, not a full collector commit. It still does not bind live
    /// object-byte buffers, mutate live roots or heap fields, publish the
    /// outcome-owned remembered set, install forwarding pointers, mutate object
    /// generations, reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails. When an error is returned, this outcome's card
    /// table is left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveCardTableCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let card_table_clear_report = if dry_run.is_empty() {
            GcCardTableClearReport::default()
        } else {
            self.thunk_resolve_card_table.clear_dirty_cards()
        };

        Ok(EvalGcStressBoundaryMinorGcLiveCardTableCommitDryRun::new(
            dry_run,
            card_table_clear_report,
        ))
    }

    /// Runs a boundary dry run and publishes outcome-owned GC state.
    ///
    /// This method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`]. When one or more
    /// allocator tiers produced commit applications, it validates that sibling
    /// survivor relocations form one coherent merged map, merges their
    /// validated next remembered sets, replaces this outcome's remembered set
    /// with the merged next-epoch set, and then clears this outcome's daemon
    /// card table. Empty boundary scans leave both live structures unchanged.
    ///
    /// This is still a live metadata bridge, not a full collector commit. It
    /// does not bind live object-byte buffers, mutate roots or heap fields,
    /// install forwarding pointers, mutate heap-record object generations, reserve
    /// semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling commit applications do not consume
    /// the outcome-owned source epoch, publish the same next epoch, or agree on
    /// one coherent survivor relocation map, or if the merged remembered set
    /// cannot reserve storage. When an error is returned, this outcome's
    /// remembered set and card table are left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveRememberedSetCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let remembered_set = boundary_minor_gc_merged_remembered_set(
            dry_run.commit_applications(),
            self.thunk_resolve_remembered_set.epoch(),
        )?;

        let remembered_set_published = remembered_set.is_some();
        let card_table_clear_report = if let Some(remembered_set) = remembered_set {
            self.thunk_resolve_remembered_set = remembered_set;
            self.thunk_resolve_card_table.clear_dirty_cards()
        } else {
            GcCardTableClearReport::default()
        };

        Ok(
            EvalGcStressBoundaryMinorGcLiveRememberedSetCommitDryRun::new(
                dry_run,
                remembered_set_published,
                card_table_clear_report,
            ),
        )
    }

    fn gc_stress_boundary_minor_gc_commit_preflight(
        &self,
        relocation_plan: EvalGcStressBoundaryMinorGcRelocationPlan,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitPreflight, EvalHeapError> {
        let root_values = boundary_minor_gc_root_reference_values(
            relocation_plan.minor_gc_plan().reference_slots(),
        )?;
        let (
            object_byte_copy_plan,
            forwarding_slots,
            reference_buffer,
            reference_writeback_plan,
            root_writeback_slots,
            root_value_writeback_slots,
            heap_field_writeback_slots,
        ) = {
            let commit_plan = relocation_plan.commit_plan()?;
            let object_byte_copy_plan = self
                .heap
                .collector_poll_minor_gc_object_byte_copy_plan(&commit_plan)?;
            let forwarding_slots = commit_plan.forwarding_slot_buffer()?;
            let reference_buffer = self
                .heap
                .collector_poll_minor_gc_reference_buffer(&commit_plan, &root_values)?;
            let reference_writeback_plan = self
                .heap
                .collector_poll_minor_gc_reference_writeback_plan(&commit_plan)?;
            let root_writeback_slots =
                boundary_minor_gc_root_writeback_slots(&reference_writeback_plan)?;
            let root_value_writeback_slots =
                boundary_minor_gc_root_value_writeback_slots(&reference_writeback_plan)?;
            let heap_field_writeback_slots =
                boundary_minor_gc_heap_field_writeback_slots(&reference_writeback_plan)?;
            (
                object_byte_copy_plan,
                forwarding_slots,
                reference_buffer,
                reference_writeback_plan,
                root_writeback_slots,
                root_value_writeback_slots,
                heap_field_writeback_slots,
            )
        };

        Ok(EvalGcStressBoundaryMinorGcCommitPreflight::new(
            relocation_plan,
            object_byte_copy_plan,
            forwarding_slots,
            reference_buffer,
            reference_writeback_plan,
            root_writeback_slots,
            root_value_writeback_slots,
            heap_field_writeback_slots,
            self.thunk_resolve_card_table.try_clone()?,
        ))
    }
}
