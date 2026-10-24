//! Counts retained requested layouts at the original programme custody cuts.
//!
//! This is requested userspace layout, including named root slots and actual
//! independently owned capacities. It is not serialized evidence credit,
//! allocator residency, a native allocation grant or another class witness.
//! The real whole-process AS guard bounds mapped resident/reserved memory before
//! constructors and throughout callbacks. These separate snapshots do not
//! promise a cumulative requested-growth quota between observation cuts.
//! Unknown retained owners refuse; no failure drops or refunds their storage.

use super::*;
use crate::node_qualification::{
    ProductionConformanceRunner, RetainedMetadataCounter as Counter, RetainedMetadataOwned as Owned,
};
use std::mem::size_of;

impl NormalClockProgramme {
    pub(in super::super) fn charge_whole_original_storage_data(
        &self,
        catalog: &InstalledNodeCatalog,
        runner: Option<&ProductionConformanceRunner<'_>>,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        let Self {
            profile,
            execution: _,
            prepared: _,
            run_attempted: _,
            original,
            state,
            state_attempted: _,
            aggregate_resources,
            bounded_attempted: _,
            bounded_valid: _,
            bounded_publications,
            bounded_case_publication: _,
            bounded_state_publication: _,
            normal_source,
            normal_attempted: _,
            normal_acceptance,
            normal_enrollment_failure,
            normal_collection,
            normal_source_failure,
            normal_operation_failure,
            normal_panic,
            adverse,
            adverse_observation,
            failures,
        } = self;
        let aggregate = aggregate_resources
            .as_ref()
            .ok_or(QualificationError::Refused(
                "Clock original aggregate storage owner absent",
            ))?;
        // Authenticate raw creator before Source RefCells or any child observer.
        // The full quota/executable/currentness checks remain separate gates.
        aggregate.charge_origin_storage_data()?;
        if normal_panic.is_some() {
            return Err(QualificationError::Refused(
                "opaque retained Clock panic storage",
            ));
        }
        counter.add(size_of::<Self>())?;
        counter.add(size_of::<InstalledNodeCatalog>())?;
        counter.charge(catalog)?;
        counter.charge(profile)?;
        if counter.rc(aggregate)? {
            counter.charge(aggregate.as_ref())?;
        }
        counter.charge(original)?;
        counter.charge(state)?;
        counter.charge(bounded_publications)?;
        counter.charge(adverse)?;
        counter.charge(adverse_observation)?;
        counter.charge(failures)?;
        counter.charge(normal_collection)?;
        counter.charge(normal_source_failure)?;
        if let Some(error) = normal_operation_failure {
            match error {
                NodeObservedError::Native(reason) => counter.charge(reason)?,
                NodeObservedError::Contract(error) => counter.charge(error)?,
                // These wrappers may retain private library/OS error backing.
                // Preserve the actual failure; do not inspect it by formatting.
                NodeObservedError::Scenario(_)
                | NodeObservedError::Campaign(_)
                | NodeObservedError::Store(_)
                | NodeObservedError::Json(_) => {
                    return Err(QualificationError::Refused(
                        "unsupported retained Clock operational error storage",
                    ));
                }
            }
        }
        if let Some(source) = normal_source {
            if counter.rc(source)? {
                counter.charge(source.as_ref())?;
            }
            if let Some(runner) = runner {
                counter.add(size_of::<ProductionConformanceRunner<'_>>())?;
                runner.charge_original_clock_storage_data(source.as_ref(), counter)?;
            }
            if let Some(accepted) = normal_acceptance {
                if counter.rc(accepted)? {
                    accepted.charge_original_clock_storage_data(source.as_ref(), counter)?;
                }
            }
            if let Some(failure) = normal_enrollment_failure {
                failure.charge_original_clock_storage_data(source.as_ref(), counter)?;
            }
        } else if runner.is_some()
            || normal_acceptance.is_some()
            || normal_enrollment_failure.is_some()
        {
            return Err(QualificationError::Refused(
                "Clock original Source custody absent",
            ));
        }
        Ok(())
    }

    pub(in super::super) fn whole_original_requested_storage_data(
        &self,
        catalog: &InstalledNodeCatalog,
        runner: Option<&ProductionConformanceRunner<'_>>,
        future_plan: Option<(
            &Id,
            &crucible_engine::node_contract::ProviderPreparationPlan,
        )>,
        maximum: usize,
    ) -> Result<usize, QualificationError> {
        let mut counter = Counter::new(maximum);
        self.charge_whole_original_storage_data(catalog, runner, &mut counter)?;
        if let Some((profile, plan)) = future_plan {
            // These are independent local clones still live while enrollment
            // borrows them; the Source's equal values are different owners.
            counter.add(size_of::<Id>())?;
            counter.add(size_of::<
                crucible_engine::node_contract::ProviderPreparationPlan,
            >())?;
            counter.charge(profile)?;
            counter.charge(plan)?;
        }
        Ok(counter.bytes())
    }
}

impl NormalClockProgramme {
    pub(in super::super) fn whole_original_storage_scratch_data(
        &self,
    ) -> Result<usize, QualificationError> {
        let aggregate = self
            .aggregate_resources
            .as_ref()
            .ok_or(QualificationError::Refused(
                "Clock original aggregate absent",
            ))?;
        aggregate.charge_origin_storage_data()?;
        let mut native = crucible_engine::node_admission::AdmittedGraph::original_retained_requested_storage_precredit_scratch_data();
        let unavailable =
            |_| QualificationError::Refused("Clock actual owning scratch unavailable");
        if let Some(original) = &self.original {
            if let Some(runtime) = &original.runtime {
                native = native.max(
                    runtime
                        .original_retained_requested_storage_precredit_scratch_data()
                        .map_err(unavailable)?,
                );
            }
            if let Some(retired) = &original.retired {
                native = native.max(
                    retired
                        .original_retained_requested_storage_precredit_scratch_data()
                        .map_err(unavailable)?,
                );
            }
        }
        if let Some(adverse) = &self.adverse {
            native = native.max(adverse.original_storage_scratch_data()?);
        }
        if let Some(failures) = &self.failures {
            native = native.max(failures.original_storage_scratch_data()?);
        }
        if let Some(state) = &self.state {
            native = native.max(state.original_storage_scratch_data()?);
        }
        let source =
            super::super::source::OriginalNormalClockSource::original_storage_scratch_data();
        // The root counter remains live while child observers execute. These
        // are the observation's explicit named counter/borrow headers, not a
        // cumulative allocation quota or a callback's transient heap estimate.
        // The same real aggregate AS limit independently bounds those mappings.
        size_of::<Counter>()
            .checked_add(native)
            .and_then(|bytes| bytes.checked_add(source))
            .and_then(|bytes| bytes.checked_add(size_of::<Result<(), QualificationError>>()))
            .ok_or(QualificationError::Refused(
                "Clock whole scratch layout overflow",
            ))
    }

    pub(in super::super) fn check_whole_original_storage_data(
        &self,
        catalog: &InstalledNodeCatalog,
        runner: Option<&ProductionConformanceRunner<'_>>,
        future_plan: Option<(
            &Id,
            &crucible_engine::node_contract::ProviderPreparationPlan,
        )>,
    ) -> Result<(), QualificationError> {
        let aggregate = self
            .aggregate_resources
            .as_ref()
            .ok_or(QualificationError::Refused(
                "Clock original aggregate absent",
            ))?;
        aggregate.charge_origin_storage_data()?;
        let maximum = usize::try_from(aggregate.limits_data().memory_bytes.get())
            .map_err(|_| QualificationError::Refused("Clock memory policy is not addressable"))?;
        let scratch = self.whole_original_storage_scratch_data()?;
        let available = maximum
            .checked_sub(scratch)
            .ok_or(QualificationError::Refused(
                "Clock whole owning scratch exceeds policy",
            ))?;
        self.whole_original_requested_storage_data(catalog, runner, future_plan, available)?;
        Ok(())
    }
}
