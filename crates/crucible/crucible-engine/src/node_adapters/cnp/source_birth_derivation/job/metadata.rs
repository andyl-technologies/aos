//! Observes the original Job's closed field roster and known retained capacities.
//!
//! Strong mechanism and program views repeat their actual backing rows. Native
//! attempt/completion internals and opaque error/runtime backing remain under
//! the genuine deployment obligation; this census supplies no lifecycle grant.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts,
    records::{MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank},
};
use std::{alloc::Layout, mem::size_of};

impl SourceBirthDerivationJob {
    /// Observes known capacities and fixed fields of the actual retained Job.
    ///
    /// The enclosing owner separately counts this Job's inline header. Actual
    /// shared views repeat their rows without alias discounts. Workspace history
    /// does not represent a bank after the writer consumed it. Opaque native
    /// resources and private errors still require the original deployment.
    ///
    /// # Errors
    /// Refuses foreign launch custody, exhausted rows, unavailable physical
    /// backing or checked geometry/work overflow, retaining emitted prefixes.
    pub fn known_capacity_data(
        &self,
        maximum_rows: usize,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        let Self {
            mechanism,
            attempt,
            attempt_identity,
            program_identity,
            binding,
            context,
            receipt,
            original_launch,
            original_metadata,
            completion,
            failed_outcome,
            failure,
            phase,
            workspace_reserved,
            workspace_requested,
            workspace_observed,
        } = self;
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum_rows, bank);
        census.observe_work_data(1)?;
        record_shared(Layout::for_value(mechanism.as_ref()), &mut census)?;
        census.observe_component_capacity_data(|remaining, bank| {
            mechanism.known_capacity_data(remaining, bank)
        })?;

        census.observe_inline_data(&attempt_identity.is_some())?;
        if let Some(identity) = attempt_identity {
            record_shared(identity.retained_payload_layout_data(), &mut census)?;
        }
        census.observe_inline_data(&program_identity.is_some())?;
        if let Some(identity) = program_identity {
            record_shared(identity.retained_payload_layout_data(), &mut census)?;
            identity.observe_direct_buffers(&mut |buffer| {
                super::storage::record_buffer(buffer, &mut census)
            })?;
        }
        census.observe_inline_data(&attempt.is_some())?;
        if let Some(attempt) = attempt {
            attempt.observe_direct_buffers(&mut |buffer| {
                super::storage::record_buffer(buffer, &mut census)
            })?;
        }
        census.observe_inline_data(&completion.is_some())?;
        if let Some(completion) = completion {
            completion.observe_direct_buffers(&mut |buffer| {
                super::storage::record_buffer(buffer, &mut census)
            })?;
        }
        census.observe_inline_data(&original_launch.is_some())?;
        if let Some(original) = original_launch {
            original.record_capacity_metadata_data(&mut census)?;
        }
        census.observe_inline_data(&original_metadata.is_some())?;
        if let Some(history) = original_metadata {
            census.observe_work_data(history.retained_inline_field_visits_data())?;
        }
        census.observe_inline_data(&failed_outcome.is_some())?;
        if let Some(outcome) = failed_outcome {
            record_failed_outcome(outcome, &mut census)?;
        }
        census.observe_inline_data(&failure.is_some())?;
        if let Some(failure) = failure {
            record_failure(failure, &mut census)?;
        }

        census.observe_inline_data(binding)?;
        census.observe_inline_data(context)?;
        census.observe_inline_data(receipt)?;
        census.observe_inline_data(phase)?;
        census.observe_inline_data(workspace_reserved)?;
        census.observe_inline_data(workspace_requested)?;
        census.observe_inline_data(workspace_observed)?;
        Ok(census.finish())
    }

    /// Names the closed roster, nested views and aggregate census controls.
    ///
    /// This excludes opaque runtime controls retained by the original deployment.
    pub fn known_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + VerifiedSourceBirthMechanism::known_capacity_counter_scratch_data()
            + OriginalSourceBirthLaunches::counter_scratch_data()
            + OriginalLaunchMetadataObservation::retained_inline_counter_scratch_data()
            + crucible_host_resources::LinuxPureWorkerProgram::retained_capacity_counter_scratch_data()
            + crucible_host_resources::LinuxPureWorkerBufferCapacityData::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<(
                &Rc<VerifiedSourceBirthMechanism>,
                &Option<LinuxPureWorkerAttempt>,
                &Option<LinuxPureWorkerAttemptIdentity>,
                &Option<LinuxPureWorkerProgramIdentity>,
                &Option<SourceBinding>,
                &Option<JobContext>,
                &Option<RequestReceipt>,
                &Option<OriginalSourceBirthLaunch>,
                &Option<OriginalLaunchMetadataObservation>,
                &Option<LinuxPureWorkerCompletion>,
                &Option<LinuxPureWorkerOutcome>,
                &Option<SourceBirthJobFailure>,
                &Phase,
                &bool,
                &Option<[usize; 2]>,
                &Option<[usize; 2]>,
            )>()
            + size_of::<(
                &Option<u32>,
                &Option<u64>,
                &Option<std::process::ExitStatus>,
                &Vec<u8>,
                &Vec<u8>,
                &Option<crucible_host_resources::LinuxPureWorkerFailure>,
            )>()
            + size_of::<&SourceBirthJobFailure>()
            + size_of::<&RuntimeError>()
            + size_of::<&LinuxPureWorkerProgramIdentity>()
            + size_of::<&LinuxPureWorkerAttemptIdentity>()
            + size_of::<&LinuxPureWorkerAttempt>()
            + size_of::<&LinuxPureWorkerCompletion>()
            + size_of::<&OriginalLaunchMetadataObservation>()
            + size_of::<&LinuxPureWorkerOutcome>()
            + size_of::<&OriginalSourceBirthLaunch>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'static>>() * 2
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Layout>()
            + size_of::<bool>() * 8
            + size_of::<usize>() * 2
    }
}

fn record_shared(
    layout: Layout,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), RuntimeError> {
    census.record(MetadataCapacityRecord {
        kind: MetadataRecordKind::Shared,
        extent: layout.size(),
        element_bytes: 1,
        alignment: layout.align(),
    })
}

fn record_failed_outcome(
    outcome: &LinuxPureWorkerOutcome,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), RuntimeError> {
    let LinuxPureWorkerOutcome {
        child_id,
        memory_oom_kills,
        status,
        stdout,
        stderr,
        failure,
    } = outcome;
    census.observe_inline_data(child_id)?;
    census.observe_inline_data(memory_oom_kills)?;
    census.observe_inline_data(status)?;
    census.observe(stdout)?;
    census.observe(stderr)?;
    census.observe_inline_data(failure)
}

fn record_failure(
    failure: &SourceBirthJobFailure,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), RuntimeError> {
    census.observe_work_data(1)?;
    match failure {
        SourceBirthJobFailure::Runtime(error) => match error {
            RuntimeError::SchedulerRefused(message) => census.observe(message),
            RuntimeError::ResourceLimit
            | RuntimeError::ThreadAffinity
            | RuntimeError::UnknownNode
            | RuntimeError::InvalidRoute
            | RuntimeError::DuplicateOperation
            | RuntimeError::OwnerBusy
            | RuntimeError::OwnerUnavailable
            | RuntimeError::NotActivated
            | RuntimeError::ForeignAuthority
            | RuntimeError::UnsupportedFacet
            | RuntimeError::InvalidTiming
            | RuntimeError::InvalidReceipt
            | RuntimeError::OutstandingObligations
            | RuntimeError::PublicationFailed => census.observe_work_data(1),
        },
        SourceBirthJobFailure::Result(error) => census.observe_inline_data(error),
        // These retained originals are not rendered, cloned, queried or priced
        // as zero-byte native errors. Their opaque backing stays deployment-owned.
        SourceBirthJobFailure::Linux(_)
        | SourceBirthJobFailure::Export { error: _, input: _ }
        | SourceBirthJobFailure::Worker(_)
        | SourceBirthJobFailure::Workspace(_)
        | SourceBirthJobFailure::OriginalMetadata(_) => Ok(()),
    }
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
