//! Observes the original job's explicit userspace buffers, not opaque runtime.
//!
//! Attempt/program Arc payloads, native descriptors, private errors, Command and
//! std/glibc/thread backing remain with the actual whole-parent reservation.
//! That reservation is a separate conjunction, never an added byte quantity.

use super::*;
use crate::node_adapters::cnp::source_birth_derivation::deployment::SourceDeploymentStorageRead;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_host_resources::{DeploymentResourceReadContext, LinuxPureWorkerBufferCapacityData};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts,
    records::{MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank},
};
use std::mem::size_of;

impl SourceBirthDerivationJob {
    /// Reports known original job capacities with their same deployment obligation.
    ///
    /// The caller owns this job's inline header. Shared program buffers are
    /// conservatively repeated, not deduplicated by digest or equal contents.
    /// No retained workspace is counted after the writer consumed its bank.
    ///
    /// # Errors
    /// Refuses another/revoked deployment, unavailable original buffer facts,
    /// arithmetic overflow or the supplied known-component restriction.
    pub fn deployment_storage_read<'a>(
        &'a self,
        context: &DeploymentResourceReadContext<'_>,
        maximum: usize,
    ) -> Result<SourceDeploymentStorageRead<'a>, RuntimeError> {
        let lease = self.mechanism.deployment_lease()?;
        lease
            .authenticate_in(context)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let facts = self.known_capacity_data(usize::MAX, None)?;
        let bytes =
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &facts,
                usize::MAX,
            )?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        lease
            .authenticate_in(context)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        Ok(SourceDeploymentStorageRead::from_original(bytes, lease))
    }

    /// Observes the original selected direct buffers with their defining geometry.
    ///
    /// This compatibility view selects direct buffers only. The enclosing
    /// deployment read additionally includes known identities and mechanism
    /// payloads through [`Self::known_capacity_data`]. It excludes opaque runtime and native
    /// resources, which still require the original deployment lease. Shared
    /// attempt/completion views repeat their rows without alias subtraction.
    /// Physical rows append without clearing earlier components or failed prefixes.
    ///
    /// # Errors
    /// Refuses foreign original launch custody, exhausted rows, unavailable
    /// physical backing or checked geometry/work overflow.
    pub fn direct_buffer_capacity_data(
        &self,
        maximum_rows: usize,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum_rows, bank);
        census.observe_inline_data(&self.original_launch.is_some())?;
        if let Some(original) = &self.original_launch {
            original.record_capacity_metadata_data(&mut census)?;
        }
        census.observe_inline_data(&self.attempt.is_some())?;
        if let Some(attempt) = &self.attempt {
            attempt.observe_direct_buffers(&mut |buffer| record_buffer(buffer, &mut census))?;
        }
        census.observe_inline_data(&self.completion.is_some())?;
        if let Some(completion) = &self.completion {
            completion.observe_direct_buffers(&mut |buffer| record_buffer(buffer, &mut census))?;
        }
        census.observe_inline_data(&self.failed_outcome.is_some())?;
        if let Some(outcome) = &self.failed_outcome {
            census.observe(&outcome.stdout)?;
            census.observe(&outcome.stderr)?;
        }
        census.observe_inline_data(&self.failure.is_some())?;
        if let Some(SourceBirthJobFailure::Runtime(RuntimeError::SchedulerRefused(message))) =
            &self.failure
        {
            census.observe(message)?;
        }
        Ok(census.finish())
    }

    /// Names only this explicit-buffer visitor's new fixed wrapper headers.
    ///
    /// L2/private error/runtime authentication is independently contained by the
    /// original deployment. This is neither their logical row nor a complete
    /// allocation/physical-memory claim.
    pub fn deployment_storage_counter_scratch_data() -> usize {
        Self::known_capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<usize>() * 2
            + size_of::<Option<&LinuxPureWorkerAttempt>>()
            + size_of::<Option<&LinuxPureWorkerCompletion>>()
            + size_of::<Option<&LinuxPureWorkerOutcome>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<SourceDeploymentStorageRead<'static>>() * 2
            + size_of::<Result<SourceDeploymentStorageRead<'static>, RuntimeError>>()
            + size_of::<&DeploymentResourceReadContext<'static>>()
            + OriginalSourceBirthLaunches::counter_scratch_data()
            + OriginalLaunchMetadataObservation::counter_scratch_data()
            + OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + LinuxPureWorkerBufferCapacityData::counter_scratch_data()
            + size_of::<LinuxPureWorkerBufferCapacityData>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
    }
}

/// Preserves one defining host allocation without inventing rows from byte sums.
pub(super) fn record_buffer(
    buffer: LinuxPureWorkerBufferCapacityData,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), RuntimeError> {
    census.observe_work_data(1)?;
    census.record(MetadataCapacityRecord {
        kind: MetadataRecordKind::Vector,
        extent: buffer.capacity,
        element_bytes: buffer.element_bytes,
        alignment: buffer.alignment,
    })
}
