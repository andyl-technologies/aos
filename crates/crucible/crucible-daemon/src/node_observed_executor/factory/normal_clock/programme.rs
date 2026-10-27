//! Retains the Clock programme on the service actor before native preparation.

use super::*;

mod whole_storage;

/// Owns the source-selected Clock programme before its first model construction.
///
/// The actor retains this owner before calling preparation or any installed
/// collection callback. Failure never removes its original runtime or renews
/// its attempt. Complete normal acceptance is a separate later enrollment step.
#[must_use = "retain this original programme on its service actor"]
pub struct NormalClockProgramme {
    profile: InstalledNormalClockProfile,
    execution: ExecutionId,
    prepared: bool,
    run_attempted: bool,
    original: Option<OriginalClockQualificationRun>,
    state: Option<OriginalClockStateProgramme>,
    state_attempted: bool,
    aggregate_resources: Option<std::rc::Rc<OriginalClockAggregateResources>>,
    bounded_attempted: bool,
    bounded_valid: bool,
    bounded_publications: Option<publications::ClockPublications>,
    bounded_case_publication: bool,
    bounded_state_publication: bool,
    normal_source: Option<std::rc::Rc<super::source::OriginalNormalClockSource>>,
    normal_attempted: bool,
    normal_acceptance:
        Option<std::rc::Rc<crate::node_qualification::InstalledOriginalConformanceAcceptance>>,
    normal_enrollment_failure:
        Option<crate::node_qualification::OriginalConformanceEnrollmentFailure>,
    normal_collection: Option<crate::node_qualification::CollectedConformance>,
    normal_source_failure: Option<QualificationError>,
    normal_operation_failure: Option<NodeObservedError>,
    normal_panic: Option<Box<dyn std::any::Any + Send>>,
    adverse: Option<super::adverse::OriginalClockAdverseProgramme>,
    adverse_observation: Option<InputPayload>,
    failures: Option<super::failures::OriginalClockFailureProgramme>,
}

impl NormalClockProgramme {
    /// Resolves immutable source data without constructing a native Clock.
    ///
    /// # Errors
    /// Refuses an unavailable or changed installed public Clock source profile.
    pub fn new(
        catalog: &InstalledNodeCatalog,
        execution: ExecutionId,
    ) -> Result<Self, NodeObservedError> {
        Ok(Self {
            profile: catalog.installed_normal_clock()?,
            execution,
            prepared: false,
            run_attempted: false,
            original: None,
            state: None,
            state_attempted: false,
            aggregate_resources: None,
            bounded_attempted: false,
            bounded_valid: false,
            bounded_publications: None,
            bounded_case_publication: false,
            bounded_state_publication: false,
            normal_source: None,
            normal_attempted: false,
            normal_acceptance: None,
            normal_enrollment_failure: None,
            normal_collection: None,
            normal_source_failure: None,
            normal_operation_failure: None,
            normal_panic: None,
            adverse: None,
            adverse_observation: None,
            failures: None,
        })
    }

    /// Retains real aggregate enforcement before constructing the original Clock.
    ///
    /// Normal source enrollment requires this path. Legacy collection remains
    /// separate and cannot turn an unbounded programme into normal acceptance.
    /// The actor stores the supplied original guard before any callback or
    /// construction and retains it together with every partial native owner.
    ///
    /// # Errors
    /// Refuses previous preparation, stale real enforcement, insufficient
    /// operation ceiling, construction or actual complete owning observation.
    pub fn prepare_original_bounded(
        &mut self,
        catalog: &mut InstalledNodeCatalog,
        aggregate: OriginalClockAggregateResources,
    ) -> Result<(), NodeObservedError> {
        if self.prepared || self.bounded_attempted || self.aggregate_resources.is_some() {
            return Err(refused("Clock aggregate preparation already attempted"));
        }
        self.bounded_attempted = true;
        self.aggregate_resources = Some(std::rc::Rc::new(aggregate));
        if catalog.runtime_wake.is_none() {
            return Err(refused(
                "Clock bounded preparation requires original concrete runtime wake owner",
            ));
        }
        self.check_aggregate_resources()?;
        let aggregate = self
            .aggregate_resources
            .as_mut()
            .ok_or_else(|| refused("Clock aggregate owner absent"))?;
        std::rc::Rc::get_mut(aggregate)
            .ok_or_else(|| refused("Clock initial aggregate guard already aliased"))?
            .prepare_state_directories_once()
            .map_err(super::super::native)?;
        self.bounded_publications = Some(publications::ClockPublications::new(aggregate.as_ref())?);
        // The unchanged catalog currently fixes this actual runtime tombstone
        // ceiling. Reject a smaller supplied policy; do not silently enlarge it.
        if self
            .aggregate_resources
            .as_ref()
            .ok_or_else(|| refused("Clock aggregate owner absent"))?
            .limits_data()
            .maximum_operations
            .get()
            < 65_536
        {
            return Err(refused(
                "Clock aggregate operation policy below actual runtime limit",
            ));
        }
        self.prepare_original_inner(catalog)?;
        self.check_aggregate_resources()?;
        self.bounded_valid = true;
        Ok(())
    }

    fn check_aggregate_resources(&self) -> Result<(), NodeObservedError> {
        if let Some(aggregate) = &self.aggregate_resources {
            aggregate
                .authenticate_current()
                .map_err(super::super::native)?;
            if let Some(runtime) = self
                .original
                .as_ref()
                .and_then(|original| original.runtime.as_ref())
            {
                aggregate
                    .authenticate_runtime_data(runtime)
                    .map_err(super::super::native)?;
            }
        }
        Ok(())
    }

    /// Borrows actual aggregate enforcement for independent source conjunction.
    ///
    /// Absence means legacy collection only. This loan cannot grant classes or
    /// replace normal source/behavioral enrollment and exact resource planning.
    pub fn aggregate_resources_data(&self) -> Option<&OriginalClockAggregateResources> {
        self.aggregate_resources.as_deref()
    }

    /// Retains the actual same-source runtime before Arm or collection callbacks.
    ///
    /// The service actor must already own this programme and the supplied catalog.
    /// Partial preparation remains in the catalog's existing reserved supervisor.
    ///
    /// # Errors
    /// Refuses a duplicate attempt, changed source or actual native preparation.
    pub fn prepare_original(
        &mut self,
        catalog: &mut InstalledNodeCatalog,
    ) -> Result<(), NodeObservedError> {
        if self.bounded_attempted {
            return Err(refused(
                "Clock bounded preparation cannot fall back to legacy",
            ));
        }
        self.prepare_original_inner(catalog)
    }

    fn prepare_original_inner(
        &mut self,
        catalog: &mut InstalledNodeCatalog,
    ) -> Result<(), NodeObservedError> {
        if self.prepared {
            return Err(refused(
                "normal Clock original preparation already attempted",
            ));
        }
        self.prepared = true;
        self.check_aggregate_resources()?;
        self.original =
            Some(catalog.prepare_original_clock_qualification(&self.profile, self.execution)?);
        Ok(())
    }

    /// Executes and collects every fixed Clock case on the same owning actor.
    ///
    /// The runner independently authenticates the original complete population,
    /// source, unit and case oracles. This method cannot manufacture a missing
    /// SourceInspection, state-restoration or normal acceptance observation.
    ///
    /// # Errors
    /// Refuses a duplicate run, missing original preparation, changed authority,
    /// publication failure, any actual oracle mismatch or collection refusal.
    /// Errors and callback unwinds leave this same programme retained.
    pub fn execute_original_cases(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
        runner: &mut ProductionConformanceRunner<'_>,
    ) -> Result<(), NodeObservedError> {
        if self.bounded_attempted {
            return Err(refused(
                "bounded Clock requires its original quota-owned publisher",
            ));
        }
        if self.run_attempted {
            return Err(refused("normal Clock original programme already attempted"));
        }
        self.run_attempted = true;
        let original = self
            .original
            .as_mut()
            .ok_or_else(|| refused("normal Clock original runtime absent"))?;
        original.activate(publisher)?;
        for (name, _, _) in CASES {
            if original.execute_next()? != name {
                return Err(refused("normal Clock case order changed"));
            }
            original
                .collect_completed(name, runner)
                .map_err(super::super::native)?;
        }
        original.execute_original_pause()?;
        Ok(())
    }

    /// Executes the actual bounded programme using its retained durable publisher.
    ///
    /// The same concrete CAS/ref owner is stored before the first callback. This
    /// does not install a normal source or manufacture any missing class result.
    ///
    /// # Errors
    /// Refuses absent/failed original enforcement, duplicate attempt, real native
    /// or publication failure, any oracle mismatch or runner collection refusal.
    pub fn execute_bounded_original_cases(
        &mut self,
        runner: &mut ProductionConformanceRunner<'_>,
    ) -> Result<(), NodeObservedError> {
        if !self.bounded_valid || self.run_attempted {
            return Err(refused(
                "Clock bounded cases unavailable or already attempted",
            ));
        }
        self.run_attempted = true;
        self.check_aggregate_resources()?;
        let aggregate = self
            .aggregate_resources
            .as_ref()
            .ok_or_else(|| refused("Clock aggregate owner absent"))?;
        let original = self
            .original
            .as_mut()
            .ok_or_else(|| refused("Clock runtime absent"))?;
        let publisher = &mut self
            .bounded_publications
            .as_mut()
            .ok_or_else(|| refused("Clock original publications absent"))?
            .original;
        original.activate(publisher)?;
        if let Some(source) = &self.normal_source {
            source
                .retain_original_activation(original)
                .map_err(super::super::native)?;
        }
        for (name, _, _) in CASES {
            aggregate
                .authenticate_current()
                .map_err(super::super::native)?;
            aggregate
                .authenticate_runtime_data(
                    original
                        .runtime
                        .as_ref()
                        .ok_or_else(|| refused("Clock runtime absent"))?,
                )
                .map_err(super::super::native)?;
            if original.execute_next()? != name {
                return Err(refused("Clock bounded case order changed"));
            }
            original
                .collect_completed(name, runner)
                .map_err(super::super::native)?;
        }
        original.execute_original_pause()?;
        self.check_aggregate_resources()?;
        self.bounded_case_publication = true;
        Ok(())
    }

    /// Constructs state ownership only beneath the actual retained quota root.
    ///
    /// The guard retains partial fixed-directory creation before the real
    /// NativeArchive and branch catalogs open them. Legacy caller paths cannot
    /// replace any directory in this bounded production route.
    ///
    /// # Errors
    /// Refuses absent/failed bounded preparation, duplicate directory attempts,
    /// quota/inheritance failure or real state-holder construction.
    pub fn prepare_original_state_bounded(
        &mut self,
        catalog: &InstalledNodeCatalog,
        executions: [ExecutionId; 2],
    ) -> Result<(), NodeObservedError> {
        if !self.bounded_valid {
            return Err(refused("Clock bounded original preparation absent"));
        }
        let aggregate = self
            .aggregate_resources
            .as_mut()
            .ok_or_else(|| refused("Clock aggregate owner absent"))?;
        let archive = aggregate
            .archive_path_data()
            .map_err(super::super::native)?;
        let branches = aggregate
            .branch_paths_data()
            .map_err(super::super::native)?;
        self.prepare_original_state(catalog, archive, branches, executions)
    }

    /// Retains real archive and branch holders before any state capture.
    ///
    /// # Errors
    /// Refuses a second attempt, changed installation or unavailable storage.
    pub fn prepare_original_state(
        &mut self,
        catalog: &InstalledNodeCatalog,
        archive_path: PathBuf,
        namespaces: [PathBuf; 2],
        executions: [ExecutionId; 2],
    ) -> Result<(), NodeObservedError> {
        if self.state_attempted || (self.bounded_attempted && !self.bounded_valid) {
            return Err(refused("Clock state owner already prepared or refused"));
        }
        self.state_attempted = true;
        if let Some(aggregate) = &self.aggregate_resources {
            if archive_path
                != aggregate
                    .archive_path_data()
                    .map_err(super::super::native)?
                || namespaces
                    != aggregate
                        .branch_paths_data()
                        .map_err(super::super::native)?
            {
                return Err(refused(
                    "Clock state paths escape original aggregate writable root",
                ));
            }
        }
        self.state = Some(OriginalClockStateProgramme::new(
            catalog,
            archive_path,
            namespaces,
            executions,
        )?);
        Ok(())
    }

    /// Executes actual capture, original retirement and both fresh continuations.
    ///
    /// The same service actor owns all originals before each callback. The two
    /// publishers perform separate complete-world commits; no singleton runtime
    /// or readiness authority is transferred into the mixed ordinary world.
    ///
    /// # Errors
    /// Refuses missing original operations, prior attempts, source/retirement,
    /// publication, complete history, native suffix or repeatability mismatch.
    pub fn execute_original_state(
        &mut self,
        catalog: &InstalledNodeCatalog,
        left: &mut dyn ActivationPublisher,
        right: &mut dyn ActivationPublisher,
    ) -> Result<(), NodeObservedError> {
        if self.bounded_attempted {
            return Err(refused(
                "bounded Clock state requires its original quota-owned publishers",
            ));
        }
        self.check_aggregate_resources()?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| refused("Clock original state owner absent"))?;
        let original = self
            .original
            .as_mut()
            .ok_or_else(|| refused("Clock original runtime absent"))?;
        state.capture_and_retire_original(original, catalog)?;
        state.execute_branch(0, left)?;
        state.execute_branch(1, right)?;
        state.authenticate_repeatable_continuations()?;
        self.check_aggregate_resources()
    }

    /// Executes and collects real state originals under a pre-reserved case.
    ///
    /// The actual installed source authenticates this fixed state case before
    /// capture or restoration. Collection borrows the real original retired
    /// capsule and both independently running Clock owners, never passed DTOs.
    ///
    /// # Errors
    /// Refuses changed case/source/credit, partial state, native or currentness
    /// failures, or missing independently installed original-state authentication.
    pub fn execute_original_state_collected(
        &mut self,
        catalog: &InstalledNodeCatalog,
        left: &mut dyn ActivationPublisher,
        right: &mut dyn ActivationPublisher,
        runner: &mut ProductionConformanceRunner<'_>,
        case: &str,
        oracle: &ContentRef,
    ) -> Result<(), NodeObservedError> {
        if self.bounded_attempted {
            return Err(refused(
                "bounded Clock state uses its retained private publishers",
            ));
        }
        let original_reservation = runner
            .reserve_clock_state(
                case,
                oracle,
                super::state_witness::MAXIMUM_STATE_BYTES as u64,
            )
            .map_err(super::super::native)?;
        self.execute_original_state(catalog, left, right)?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| refused("Clock state owner absent"))?;
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| refused("Clock original owner absent"))?;
        let witness = state.original_state_witness(original)?;
        runner
            .collect_clock_state_reserved(
                original_reservation,
                case,
                oracle,
                super::state_witness::MAXIMUM_STATE_BYTES as u64,
                &witness,
            )
            .map_err(super::super::native)?;
        self.check_aggregate_resources()
    }

    /// Collects both actual fresh continuations through the retained publishers.
    ///
    /// Original runner reservation precedes capture. Each original/fresh owner,
    /// partial publication and report remains held by this same programme on
    /// failure. No calibration runtime is installed into an ordinary world.
    ///
    /// # Errors
    /// Refuses incomplete original cases, source/guard/credit, capture, retirement,
    /// restoration/publication, native suffix or independent collection mismatch.
    pub fn execute_bounded_original_state_collected(
        &mut self,
        catalog: &InstalledNodeCatalog,
        runner: &mut ProductionConformanceRunner<'_>,
        case: &str,
        oracle: &ContentRef,
    ) -> Result<(), NodeObservedError> {
        if !self.bounded_valid || !self.bounded_case_publication || self.bounded_state_publication {
            return Err(refused("Clock bounded state frontier unavailable"));
        }
        self.check_aggregate_resources()?;
        let reservation = runner
            .reserve_clock_state(
                case,
                oracle,
                super::state_witness::MAXIMUM_STATE_BYTES as u64,
            )
            .map_err(super::super::native)?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| refused("Clock state owner absent"))?;
        let original = self
            .original
            .as_mut()
            .ok_or_else(|| refused("Clock original owner absent"))?;
        let publications = self
            .bounded_publications
            .as_mut()
            .ok_or_else(|| refused("Clock original publications absent"))?;
        state.capture_and_retire_original(original, catalog)?;
        state.execute_branch(0, &mut publications.left)?;
        state.execute_branch(1, &mut publications.right)?;
        state.authenticate_repeatable_continuations()?;
        state.authenticate_live_requested_storage_data(
            self.aggregate_resources
                .as_ref()
                .ok_or_else(|| refused("Clock aggregate owner absent"))?,
        )?;
        let witness = state.original_state_witness(original)?;
        runner
            .collect_clock_state_reserved(
                reservation,
                case,
                oracle,
                super::state_witness::MAXIMUM_STATE_BYTES as u64,
                &witness,
            )
            .map_err(super::super::native)?;
        self.check_aggregate_resources()?;
        self.bounded_state_publication = true;
        Ok(())
    }

    /// Borrows the retained real state programme without a mutable runtime loan.
    pub fn original_state_data(&self) -> Option<&OriginalClockStateProgramme> {
        self.state.as_ref()
    }

    /// Borrows the exact immutable source selection without granting installation.
    pub fn profile_data(&self) -> &InstalledNormalClockProfile {
        &self.profile
    }

    /// Borrows retained originals after preparation, including failed attempts.
    ///
    /// The borrow permits evidence inspection only; no mutable runtime escapes.
    pub fn original_data(&self) -> Option<&OriginalClockQualificationRun> {
        self.original.as_ref()
    }
}

#[path = "source_programme.rs"]
mod source_programme;
