//! Admits explicit invocation report phases on the same installed Source roster.
//!
//! This separate entry preserves old report admission and its numeric path.
//! Its actual callbacks authenticate the private registered holder before the
//! complete outer14 shapes are quoted. No public purpose label is accepted.

use super::*;
use crucible_node_transport::reference_packet::service::report_startup::{
    original_invocation_report_startup_counter_scratch_data,
    original_invocation_report_startup_storage_data,
};

impl InstalledConformancePlan {
    /// Admits both report phases for the explicitly installed invocation format.
    ///
    /// The same genuine installed policy/holder/Source callbacks run before
    /// counting. Private invocation purpose is issued separately before Child.
    ///
    /// # Errors
    /// Refuses foreign or spent owners, incomplete full outer14 declarations,
    /// unsupported shapes, changed currentness or actual policy budget excess.
    pub fn reserve_original_invocation_report_startup<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
    ) -> Result<CompleteOriginalReportStartupAdmission<'a>, EvidenceError> {
        let scope = OriginalReportStartupScope {
            plan: self,
            sources,
            launches,
        };
        let policy = self
            .0
            .authority
            .original_report_startup_policy(self.evidence(), &scope)?;
        let fixed = add(
            fixed_scratch(&policy)?,
            original_invocation_report_startup_counter_scratch_data(),
        )?;
        let mut budget = Budget::new(policy.maximum_requested_bytes, fixed)?;
        let storage = self.0.authority.authenticate_original_report_startup(
            self.evidence(),
            &scope,
            &policy,
        )?;
        budget.insert(storage.retained_holder_bytes)?;
        budget.insert(storage.maximum_simultaneous_transient_bytes)?;
        let mut rows = [StartupRows::default(); 3];
        let mut finalization_bytes = [0usize; 3];
        let mut source_bytes = [0usize; 3];
        for index in 0..3 {
            for earlier in 0..index {
                if Rc::ptr_eq(&sources[index], &sources[earlier]) {
                    return Err(failure("startup Source roster aliases a different member"));
                }
            }
            let source = &sources[index];
            source
                .authenticate_original_report_startup_launch_data(&launches[index])
                .map_err(|_| failure("original startup Source launch differs"))?;
            source_bytes[index] = source
                .original_complete_report_startup_retained_storage_data(
                    policy.maximum_requested_bytes,
                )
                .map_err(|_| failure("original startup Source owners are unavailable"))?;
            budget.insert(source_bytes[index])?;
            rows[index] = compiled_invocation_rows(&launches[index])?;
            budget.insert(rows[index].peak()?)?;
            finalization_bytes[index] = source
                .original_report_startup_finalization_storage_data(
                    &launches[index],
                    rows[index],
                    policy.maximum_requested_bytes,
                )
                .map_err(|_| failure("original birth finalization demand is unavailable"))?;
            // Summing all members is deliberately conservative: successful new
            // birth banks can coexist while a later member is being finalized.
            budget.insert(finalization_bytes[index])?;
        }
        recheck(&scope, &policy, &storage)?;
        Ok(CompleteOriginalReportStartupAdmission {
            scope,
            process: std::process::id(),
            thread: std::thread::current().id(),
            policy,
            storage,
            rows,
            finalization_bytes,
            source_bytes,
            spent: [false; 3],
            requested_peak: budget.used,
        })
    }
}

fn compiled_invocation_rows(
    launch: &PacketNative5SourceLaunch,
) -> Result<StartupRows, EvidenceError> {
    let mut rows = StartupRows::default();
    for (selected, purpose, slot) in [
        (
            launch.capture_allocation_selection.is_some(),
            PacketNativeReportStartupPurpose::OriginalObserve12,
            &mut rows.original_observe12,
        ),
        (
            launch.fresh_restore_allocation_selection.is_some(),
            PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
            &mut rows.fresh_completed_admit13,
        ),
    ] {
        if selected {
            let data = original_invocation_report_startup_storage_data(launch, purpose)
                .map_err(|_| failure("compiled original startup projection refused"))?;
            if data.declared_counter_scratch_bytes()
                > original_invocation_report_startup_counter_scratch_data()
            {
                return Err(failure(
                    "compiled startup counter exceeded preadmitted scratch",
                ));
            }
            *slot = Some(PacketNativeReportStartupAllocationRow {
                raw_report_capacity: U64::new(data.raw_report_capacity() as u64),
                retained_growth_bytes: U64::new(data.retained_growth_bytes() as u64),
                maximum_simultaneous_transient_bytes: U64::new(
                    data.maximum_simultaneous_transient_bytes() as u64,
                ),
                declared_counter_scratch_bytes: U64::new(
                    data.declared_counter_scratch_bytes() as u64
                ),
            });
        }
    }
    rows.peak()?;
    Ok(rows)
}
