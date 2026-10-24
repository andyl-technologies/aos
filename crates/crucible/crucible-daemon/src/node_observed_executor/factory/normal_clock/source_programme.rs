//! Runs normal enrollment while the service actor retains all original owners.

use std::rc::Rc;

use crate::node_qualification::{
    AcceptanceLimits, InstalledConformanceAuthority, InstalledOriginalConformanceAcceptance,
    QualificationLimits,
};
use crucible_engine::node_contract::ProviderPlanningRequest;

use super::super::source::OriginalNormalClockSource;
use super::*;

impl NormalClockProgramme {
    /// Executes this same bounded Clock's complete original normal population.
    ///
    /// The actual Source is retained before the runner or any original Arm.
    /// All exact, native admission, pause, capture and fresh continuation owners
    /// remain in this programme. Missing adverse originals remain NotExecuted
    /// and make the ordinary enrollment gate refuse; no successful subset or
    /// decoded report can install classes. A failed attempt cannot be renewed.
    /// The two publication execution IDs are distinct from the original, both
    /// adverse worlds and both restore branches, and enter the plan before Arm.
    ///
    /// # Errors
    /// Refuses missing original enforcement/state preparation, an earlier
    /// attempt, source withdrawal, any actual operation or callback failure, or
    /// incomplete six-class qualification. The original failure and every
    /// available runner observation remain owned by this programme.
    pub fn execute_normal_enrollment(
        &mut self,
        catalog: &mut InstalledNodeCatalog,
        adverse_executions: [crucible_campaign::ExecutionId; 2],
        publication_executions: [ExecutionId; 2],
    ) -> Result<(), NodeObservedError> {
        if self.normal_attempted
            || !self.bounded_valid
            || self.run_attempted
            || self.state.is_none()
        {
            return Err(refused("Clock normal enrollment frontier unavailable"));
        }
        self.original
            .as_ref()
            .ok_or_else(|| refused("Clock normal original absent"))?
            .current()?;
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| refused("Clock state owner absent"))?;
        let executions = [
            self.execution,
            adverse_executions[0],
            adverse_executions[1],
            publication_executions[0],
            publication_executions[1],
            state.branches[0].execution,
            state.branches[1].execution,
        ];
        if executions
            .iter()
            .enumerate()
            .any(|(index, execution)| executions[..index].contains(execution))
        {
            return Err(refused("Clock original experiment executions overlap"));
        }
        self.normal_attempted = true;
        let aggregate = Rc::clone(
            self.aggregate_resources
                .as_ref()
                .ok_or_else(|| refused("Clock normal aggregate absent"))?,
        );
        if self.state.as_ref().is_some_and(|state| {
            state
                .branches
                .iter()
                .any(|branch| adverse_executions.contains(&branch.execution))
        }) {
            return Err(refused("Clock adverse and continuation executions overlap"));
        }
        // The same whole-process policy is already kernel-enforced. Recheck
        // its original limits/mappings before the next retained constructor;
        // this is not a grant derived from a requested-layout observation.
        self.check_aggregate_resources()?;
        self.adverse = Some(super::super::adverse::OriginalClockAdverseProgramme::new(
            catalog,
            aggregate.as_ref(),
            self.execution,
            adverse_executions,
        )?);
        self.failures = Some(super::super::failures::OriginalClockFailureProgramme::new(
            catalog,
            &aggregate,
            publication_executions,
        )?);
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| refused("Clock normal original runtime absent"))?;
        let source = match OriginalNormalClockSource::new(
            &self.profile,
            original,
            Rc::clone(&aggregate),
            self.adverse
                .as_ref()
                .ok_or_else(|| refused("Clock original adverse programme absent"))?,
            publication_executions,
        ) {
            Ok(source) => Rc::new(source),
            Err(original) => {
                self.normal_source_failure = Some(original);
                return Err(refused("Clock normal source construction refused"));
            }
        };
        self.normal_source = Some(Rc::clone(&source));
        if let Err(original) = aggregate.authenticate_current() {
            source.withdraw();
            self.normal_operation_failure = Some(super::super::super::native(original));
            return Err(refused(
                "Clock aggregate changed before runner construction",
            ));
        }
        let mut runner = match ProductionConformanceRunner::new(
            source.as_ref(),
            self.profile.selection.node.clone(),
            self.profile.scenario.compatibility[0].identity()?,
            source.original_plan_data().0,
            source.original_plan_data().1,
            QualificationLimits::default(),
        ) {
            Ok(runner) => runner,
            Err(original) => {
                self.normal_source_failure = Some(original);
                return Err(refused("Clock normal runner construction refused"));
            }
        };

        // The actual complete retained graph and named scratch are checked
        // before the first Arm; serialized case credits are independent.
        if let Err(original) = self.check_whole_original_storage_data(catalog, Some(&runner), None)
        {
            source.withdraw();
            self.normal_source_failure = Some(original);
            self.normal_collection = Some(runner.finish());
            return Err(refused(
                "Clock whole original requested storage unavailable",
            ));
        }

        let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runner
                .run_source_inspection(
                    OriginalNormalClockSource::source_inspection_case_data(),
                    128 * 1024,
                )
                .map_err(super::super::super::native)?;
            self.execute_bounded_original_cases(&mut runner)?;
            let activation = self
                .original
                .as_ref()
                .and_then(|original| original.activation.as_ref())
                .ok_or_else(|| refused("Clock original complete activation absent"))?;
            let adverse = self
                .adverse
                .as_mut()
                .ok_or_else(|| refused("Clock original adverse owner absent"))?;
            let publisher = &mut self
                .bounded_publications
                .as_mut()
                .ok_or_else(|| refused("Clock original publishers absent"))?
                .adverse;
            let (case, oracle) = source
                .adverse_case_data()
                .map_err(super::super::super::native)?;
            let reservation = runner
                .reserve_clock_adverse(case, oracle, 512 * 1024)
                .map_err(super::super::super::native)?;
            adverse.execute(activation, aggregate.as_ref(), publisher)?;
            self.adverse_observation = Some(adverse.original_data()?);
            let witness = super::super::adverse::OriginalClockAdverseWitness::new(
                adverse,
                self.original
                    .as_ref()
                    .ok_or_else(|| refused("Clock original adverse source absent"))?,
                publisher,
                self.adverse_observation
                    .as_ref()
                    .ok_or_else(|| refused("Clock original adverse output absent"))?,
            )?;
            runner
                .collect_clock_adverse_reserved(reservation, case, oracle, 512 * 1024, &witness)
                .map_err(super::super::super::native)?;
            drop(witness);
            self.execute_bounded_original_state_collected(
                catalog,
                &mut runner,
                source.state_case_data().0,
                source.state_case_data().1,
            )?;
            self.execute_original_failure_cases(catalog, &source, &mut runner)
        }));
        match execution {
            Ok(Ok(())) => {}
            Ok(Err(original)) => {
                source.withdraw();
                self.normal_operation_failure = Some(original);
            }
            Err(original) => {
                source.withdraw();
                self.normal_panic = Some(original);
            }
        }
        // Source failure and partial population are preserved, not reissued as
        // a fresh attempt. The runner is consumed exactly once into an owned
        // collection even when sealing or plan construction cannot proceed.
        if let Err(original) = self.check_whole_original_storage_data(catalog, Some(&runner), None)
        {
            source.withdraw();
            self.normal_source_failure = Some(original);
            self.normal_collection = Some(runner.finish());
            return Err(refused(
                "Clock whole original requested storage unavailable",
            ));
        }
        if let Err(original) = source.seal_original_population() {
            self.normal_source_failure = Some(original);
            self.normal_collection = Some(runner.finish());
            return Err(refused("Clock actual normal population did not seal"));
        }
        let (profile, plan) = match source.future_plan() {
            Ok(plan) => plan,
            Err(original) => {
                self.normal_source_failure = Some(original);
                self.normal_collection = Some(runner.finish());
                return Err(refused("Clock future ordinary plan refused"));
            }
        };
        // Sealing/future planning own new report and policy banks. The runner
        // and its population are still live at this cut, before enrollment
        // consumes them into an accepted owner or an owned failure.
        if let Err(original) =
            self.check_whole_original_storage_data(catalog, Some(&runner), Some((&profile, &plan)))
        {
            source.withdraw();
            self.normal_source_failure = Some(original);
            self.normal_collection = Some(runner.finish());
            return Err(refused("Clock sealed requested storage unavailable"));
        }
        let selection = ProviderPlanningRequest {
            profile: &profile,
            configuration: &plan.bindings[0].configuration_ref,
            nodes: std::slice::from_ref(&self.profile.selection.node),
            resources: source.resources_data(),
            limits: OriginalNormalClockSource::metadata_limits(),
        };
        let same_source: Rc<dyn InstalledConformanceAuthority> = source.clone();
        let enrollment = match runner.finish_for_installation(
            same_source,
            selection,
            &plan,
            AcceptanceLimits::default(),
        ) {
            Ok(accepted) => {
                self.normal_acceptance = Some(Rc::new(accepted));
                Ok(())
            }
            Err(original) => {
                self.normal_enrollment_failure = Some(original);
                Err(refused(
                    "Clock normal population has unresolved original requirements",
                ))
            }
        };
        // Enrollment has retained its own immutable plan. Release only these
        // independent inert local copies before the final custody census.
        drop(profile);
        drop(plan);
        // Keep the same accepted/failure original before the final observation.
        // Retirement never removes a still-owned runtime/history from the walk.
        if let Err(original) = self.check_whole_original_storage_data(catalog, None, None) {
            source.withdraw();
            self.normal_source_failure = Some(original);
            return Err(refused("Clock enrolled requested storage unavailable"));
        }
        self.check_aggregate_resources()?;
        enrollment
    }

    /// Borrows the actual normal acceptance owner after full original enrollment.
    ///
    /// Absence preserves an unexecuted or refused qualification. This owner is
    /// behavioral class evidence only; a normal factory still requires genuine
    /// source/native/full-world admission for each future ordinary birth.
    ///
    /// # Errors
    /// Refuses a foreign creator, missing original programme or withdrawn source.
    pub fn normal_acceptance_data(
        &self,
    ) -> Result<Option<&Rc<InstalledOriginalConformanceAcceptance>>, NodeObservedError> {
        self.original
            .as_ref()
            .ok_or_else(|| refused("Clock normal original absent"))?
            .current()?;
        if let Some(source) = &self.normal_source {
            source
                .authenticate_current()
                .map_err(super::super::super::native)?;
        }
        Ok(self.normal_acceptance.as_ref())
    }
}

impl NormalClockProgramme {
    fn execute_original_failure_cases(
        &mut self,
        catalog: &InstalledNodeCatalog,
        source: &OriginalNormalClockSource,
        runner: &mut ProductionConformanceRunner<'_>,
    ) -> Result<(), NodeObservedError> {
        use super::super::failures::{AFTER, BEFORE, DAMAGED, MAXIMUM_REPORT_BYTES};
        for (index, case) in [BEFORE, AFTER, DAMAGED].into_iter().enumerate() {
            self.check_aggregate_resources()?;
            self.check_whole_original_storage_data(catalog, Some(runner), None)
                .map_err(super::super::super::native)?;
            let oracle = source
                .failure_case_data(case)
                .map_err(super::super::super::native)?;
            let reservation = runner
                .reserve_clock_failure(case, oracle, MAXIMUM_REPORT_BYTES)
                .map_err(super::super::super::native)?;
            let failures = self
                .failures
                .as_mut()
                .ok_or_else(|| refused("Clock original failure owner absent"))?;
            let original = self
                .original
                .as_ref()
                .ok_or_else(|| refused("Clock source original absent"))?;
            let state = self
                .state
                .as_ref()
                .ok_or_else(|| refused("Clock source state absent"))?;
            let aggregate = self
                .aggregate_resources
                .as_ref()
                .ok_or_else(|| refused("Clock aggregate absent"))?;
            if case == DAMAGED {
                failures.execute_damage(state, original, aggregate)?;
            } else {
                failures.execute_publication(index, &self.profile, original, aggregate)?;
            }
            let witness = failures.witness(case, original, state)?;
            runner
                .collect_clock_failure_reserved(
                    reservation,
                    case,
                    oracle,
                    MAXIMUM_REPORT_BYTES,
                    &witness,
                )
                .map_err(super::super::super::native)?;
            drop(witness);
            self.check_whole_original_storage_data(catalog, Some(runner), None)
                .map_err(super::super::super::native)?;
        }
        Ok(())
    }
}
