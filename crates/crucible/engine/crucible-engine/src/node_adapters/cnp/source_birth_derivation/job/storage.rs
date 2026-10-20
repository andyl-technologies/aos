//! Observes the original job's explicit userspace buffers, not opaque runtime.
//!
//! Attempt/program Arc payloads, native descriptors, private errors, Command and
//! std/glibc/thread backing remain with the actual whole-parent reservation.
//! That reservation is a separate conjunction, never an added byte quantity.

use super::*;
use crate::node_adapters::cnp::source_birth_derivation::deployment::SourceDeploymentStorageRead;
use crucible_host_resources::DeploymentResourceReadContext;
use std::mem::size_of;

impl SourceBirthDerivationJob {
    /// Reports known original job buffers with their same deployment obligation.
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
        let bytes = self.known_direct_backing_data()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(SourceDeploymentStorageRead::from_original(bytes, lease))
    }

    pub(in crate::node_adapters::cnp) fn known_direct_backing_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let mut bytes = 0usize;
        if let Some(attempt) = &self.attempt {
            bytes = attempt
                .direct_buffer_census()
                .map_err(|_| RuntimeError::OwnerUnavailable)?
                .checked_sum()
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(completion) = &self.completion {
            // Keep both original reports. No alias subtraction from equal paths.
            bytes = bytes
                .checked_add(
                    completion
                        .direct_buffer_census()
                        .map_err(|_| RuntimeError::OwnerUnavailable)?
                        .checked_sum()
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(outcome) = &self.failed_outcome {
            bytes = bytes
                .checked_add(outcome.stdout.capacity())
                .and_then(|sum| sum.checked_add(outcome.stderr.capacity()))
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(SourceBirthJobFailure::Runtime(RuntimeError::SchedulerRefused(message))) =
            &self.failure
        {
            bytes = bytes
                .checked_add(message.capacity())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(bytes)
    }

    /// Names only this explicit-buffer visitor's new fixed wrapper headers.
    ///
    /// L2/private error/runtime authentication is independently contained by the
    /// original deployment. This is neither their logical row nor a complete
    /// allocation/physical-memory claim.
    pub const fn deployment_storage_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<usize>() * 2
            + size_of::<Option<&LinuxPureWorkerAttempt>>()
            + size_of::<Option<&LinuxPureWorkerCompletion>>()
            + size_of::<Option<&LinuxPureWorkerOutcome>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<SourceDeploymentStorageRead<'static>>() * 2
            + size_of::<Result<SourceDeploymentStorageRead<'static>, RuntimeError>>()
            + size_of::<&DeploymentResourceReadContext<'static>>()
    }
}
