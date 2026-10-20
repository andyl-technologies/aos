//! Joins original selected Source operands to one supervised occurrence.
//!
//! The association spends export once and owns transferred planned operands.
//! Result acceptance owns the same sealed completion before inspecting it;
//! accepted banks are ranges in that completion, never reconstructed summaries.
//! This owner issues neither Birth nor Initial, Recipe or native permission.

use super::*;
use crate::node_adapters::cnp::source_birth_derivation::original_launch::OriginalSourceBirthLaunch;
use crate::node_adapters::cnp::source_birth_derivation::{
    job::SourceBirthDerivationJob,
    request_wire::{ExportWorkspace, RequestReceipt},
    result_wire::{self, Identity as ResultIdentity, Status},
};
use crucible_host_resources::LinuxPureWorkerAttemptIdentity;
use std::ops::Range;

#[path = "derivation/private_seed.rs"]
mod private_seed;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DerivationStage {
    Exporting,
    Deriving,
    DerivedBanks,
    Failed,
}

pub(in crate::node_adapters::cnp::semantic) struct NativeImport18DerivationState {
    source: usize,
    process: u32,
    thread: ThreadId,
    attempt: Option<LinuxPureWorkerAttemptIdentity>,
    private_launch: Option<Id>,
    original_launch: Option<OriginalSourceBirthLaunch>,
    registration: Option<PacketCompleteAckHostRegistrationPlan>,
    receipt: Option<RequestReceipt>,
    host_reference: Option<[u8; 32]>,
    private_seed: Option<birth::OriginalImport18PrivateSeed>,
    job: Option<SourceBirthDerivationJob>,
    banks: Option<[Range<usize>; 2]>,
    stage: DerivationStage,
}

impl PacketCompleteSemanticSource {
    /// Exports original selected operands into the same concrete prepared input.
    ///
    /// The caller reserves the real job and workspace before taking this loan.
    /// The workspace is consumed synchronously and no Source reference survives
    /// return. Start, polling and whole-holder observation occur after the loan.
    /// Planned inputs remain here even if the actual writer refuses partway.
    ///
    /// # Errors
    /// Refuses a foreign creator/mechanism, ordinary or already-spent Source,
    /// incompatible original declaration, missing planned operands or real
    /// export failure. Once installed, the failed association cannot be reset.
    pub fn export_native_import18_derivation_into<'a>(
        &'a mut self,
        launch: &'a PacketNative5SourceLaunch,
        private_launch: &mut Option<Id>,
        registration: &mut Option<PacketCompleteAckHostRegistrationPlan>,
        job: &mut SourceBirthDerivationJob,
        workspace: ExportWorkspace<'a>,
    ) -> Result<(), RuntimeError> {
        self.export_derivation_into(launch, None, private_launch, registration, job, workspace)
    }

    /// Exports through the same original retained by Prepared and this fresh job.
    ///
    /// The parent admits actual observation/holder windows before this Source
    /// loan. No independently supplied launch, hash or capacity can replace it.
    ///
    /// # Errors
    /// Preserves original Source/export errors and refuses a different holder.
    pub fn export_fresh_native_import18_derivation_into<'a>(
        &'a mut self,
        original: &'a OriginalSourceBirthLaunch,
        private_launch: &mut Option<Id>,
        registration: &mut Option<PacketCompleteAckHostRegistrationPlan>,
        job: &mut SourceBirthDerivationJob,
        workspace: ExportWorkspace<'a>,
    ) -> Result<(), RuntimeError> {
        if !job.same_original(original) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.export_derivation_into(
            original.original(),
            Some(original),
            private_launch,
            registration,
            job,
            workspace,
        )
    }

    fn export_derivation_into<'a>(
        &'a mut self,
        launch: &'a PacketNative5SourceLaunch,
        original: Option<&'a OriginalSourceBirthLaunch>,
        private_launch: &mut Option<Id>,
        registration: &mut Option<PacketCompleteAckHostRegistrationPlan>,
        job: &mut SourceBirthDerivationJob,
        workspace: ExportWorkspace<'a>,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let mechanism = self
            .native_import18_derivation_mechanism
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if !job.same_mechanism(mechanism) {
            return Err(RuntimeError::ForeignAuthority);
        }
        mechanism.authenticate_current()?;
        if self.native_import18_derivation.is_some()
            || self.ack_birth_attempted
            || self.native_import18_birth_construction.is_some()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.authenticate_import18_birth_source_data(launch)?;
        self.native_import18_derivation = Some(NativeImport18DerivationState {
            source: self as *const Self as usize,
            process: self.process,
            thread: self.thread,
            attempt: None,
            private_launch: None,
            original_launch: original.cloned(),
            registration: None,
            receipt: None,
            host_reference: None,
            private_seed: None,
            job: None,
            banks: None,
            stage: DerivationStage::Failed,
        });
        let attempt = match job.associate(self) {
            Ok(attempt) => attempt,
            Err(error) => {
                job.refuse_runtime(error);
                return Err(RuntimeError::OwnerUnavailable);
            }
        };
        let state = self
            .native_import18_derivation
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        state.attempt = Some(attempt);
        state.private_launch = private_launch.take();
        state.registration = registration.take();
        let (Some(private_launch), Some(registration)) =
            (&state.private_launch, &state.registration)
        else {
            job.refuse_runtime(RuntimeError::OwnerUnavailable);
            return Err(RuntimeError::OwnerUnavailable);
        };
        state.stage = DerivationStage::Exporting;
        let expected = match &self.original {
            CompletePacketOriginal::Producer(source) => source.isolated_expected_coordinator_data(),
            CompletePacketOriginal::Reactive(source) => source.isolated_expected_coordinator_data(),
        };
        let exported = match original {
            Some(original) => job.export_fresh_original(
                private_launch,
                original,
                expected,
                registration,
                workspace,
            ),
            None => {
                let projection = crucible_node_transport::reference_packet::service::PacketNative5LaunchValidationProjection::from_launch_data(launch);
                job.export(
                    private_launch,
                    &projection,
                    expected,
                    registration,
                    workspace,
                )
            }
        };
        match exported {
            Ok(receipt) => {
                state.receipt = Some(receipt);
                state.host_reference =
                    match private_seed::host_reference_identity(&launch.controller_executable) {
                        Ok(identity) => Some(identity),
                        Err(error) => {
                            state.stage = DerivationStage::Failed;
                            job.refuse_runtime(error);
                            return Err(RuntimeError::OwnerUnavailable);
                        }
                    };
                state.stage = DerivationStage::Deriving;
                Ok(())
            }
            Err(error) => {
                state.stage = DerivationStage::Failed;
                Err(error)
            }
        }
    }

    /// Retains one physically completed original job before inspecting its result.
    ///
    /// An active incoming job stays in the caller's slot. An occupied Source
    /// never replaces its old job or removes the incoming one. After transfer,
    /// every identity, wire, failure and success outcome stays owned here.
    ///
    /// # Errors
    /// Refuses missing/premature/repeated custody, a foreign original occurrence,
    /// revoked deployment, malformed result or valid failed worker output.
    /// Failure never erases the consumed completion or its bounded diagnostic.
    pub fn retain_native_import18_derivation_result_into(
        &mut self,
        incoming: &mut Option<SourceBirthDerivationJob>,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let state = self
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.job.is_some() || state.stage != DerivationStage::Deriving {
            return Err(RuntimeError::DuplicateOperation);
        }
        if !incoming
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .physical_output_present()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        // This is an owning move, before original identity or result validation.
        self.native_import18_derivation
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .job = incoming.take();
        let result = self.authenticate_derivation_result();
        if let Err(error) = result {
            let state = self
                .native_import18_derivation
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            state.stage = DerivationStage::Failed;
            if let Some(job) = &mut state.job {
                job.refuse_runtime(error);
            }
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }

    fn authenticate_derivation_result(&mut self) -> Result<(), RuntimeError> {
        self.authenticate_isolated_derivation_storage_custody()?;
        let state = self
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let job = state.job.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        job.verify_for_source(
            self,
            state
                .attempt
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            self.native_import18_derivation_mechanism
                .as_ref()
                .ok_or(RuntimeError::ForeignAuthority)?,
        )?;
        let receipt = state.receipt.ok_or(RuntimeError::OwnerUnavailable)?;
        let actual_receipt = job.receipt()?;
        if receipt.context != actual_receipt.context
            || receipt.input_digest != actual_receipt.input_digest
            || receipt.wire_bytes != actual_receipt.wire_bytes
            || receipt.elements != actual_receipt.elements
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // Actual physical/currentness and input-receipt checks above precede
        // the fresh same-original walk. Failure stays in this consumed Job.
        self.native_import18_derivation
            .as_mut()
            .and_then(|state| state.job.as_mut())
            .ok_or(RuntimeError::OwnerUnavailable)?
            .remeasure_original_metadata()?;
        let job = self
            .native_import18_derivation
            .as_ref()
            .and_then(|state| state.job.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let result = result_wire::verify_stdout(
            job.stdout()?,
            ResultIdentity {
                task_digest: receipt.context.task_digest,
                input_digest: receipt.input_digest,
            },
            job.result_limits()?,
        );
        let ranges = match result {
            Ok(result) if result.header().status() == Status::Success => {
                verified_bank_ranges(&result)?
            }
            Ok(result) => {
                let header = result.header().clone();
                self.native_import18_derivation
                    .as_mut()
                    .and_then(|state| state.job.as_mut())
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .refuse_worker(header);
                return Err(RuntimeError::OwnerUnavailable);
            }
            Err(error) => {
                self.native_import18_derivation
                    .as_mut()
                    .and_then(|state| state.job.as_mut())
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .refuse_result(error);
                return Err(RuntimeError::OwnerUnavailable);
            }
        };
        let state = self
            .native_import18_derivation
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        state.banks = Some(ranges);
        state.stage = DerivationStage::DerivedBanks;
        Ok(())
    }

    /// Borrows accepted bytes only from the still-current original completion.
    ///
    /// This supplies no Birth, typed validation, Initial or native authority.
    ///
    /// # Errors
    /// Refuses absent/failed/cancelled banks or changed original custody.
    pub fn native_import18_derived_banks_data(&self) -> Result<(&[u8], &[u8]), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_isolated_derivation_storage_custody()?;
        let state = self
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.stage != DerivationStage::DerivedBanks {
            return Err(RuntimeError::OutstandingObligations);
        }
        let job = state.job.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        job.verify_for_source(
            self,
            state
                .attempt
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            self.native_import18_derivation_mechanism
                .as_ref()
                .ok_or(RuntimeError::ForeignAuthority)?,
        )?;
        let [source, registration] = state.banks.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let stdout = job.stdout()?;
        Ok((
            stdout
                .get(source.clone())
                .ok_or(RuntimeError::OwnerUnavailable)?,
            stdout
                .get(registration.clone())
                .ok_or(RuntimeError::OwnerUnavailable)?,
        ))
    }

    /// Revokes an already-owned result without polling an active child under a loan.
    ///
    /// # Errors
    /// Retains and refuses a foreign creator or mismatched original association.
    /// Actual owned jobs are cancelled even when that custody check refuses.
    pub fn cancel_native_import18_derivation(&mut self) -> Result<(), RuntimeError> {
        if let Some(state) = &mut self.native_import18_derivation {
            state.stage = DerivationStage::Failed;
            if let Some(job) = &mut state.job {
                job.cancel();
            }
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.native_import18_derivation.is_some() {
            self.authenticate_isolated_derivation_storage_custody()?;
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn isolated_derivation_counter_scratch_data()
    -> usize {
        // New association/direct-buffer wrapper headers only. Actual private
        // runtime/authentication remains under its original deployment owner.
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&NativeImport18DerivationState>()
            + std::mem::size_of::<Option<&NativeImport18DerivationState>>()
            + std::mem::size_of::<&Id>()
            + std::mem::size_of::<&PacketCompleteAckHostRegistrationPlan>()
            + std::mem::size_of::<usize>() * 2
            + std::mem::size_of::<Result<usize, RuntimeError>>()
            + SourceBirthDerivationJob::deployment_storage_counter_scratch_data()
            + SourceBirthDerivationJob::fresh_export_counter_scratch_data()
            + Self::native_import18_private_seed_counter_scratch_data()
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_isolated_derivation_storage_custody(
        &self,
    ) -> Result<(), RuntimeError> {
        let state = self
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.source != self as *const Self as usize
            || state.process != self.process
            || state.thread != self.thread
            || self.native_import18_derivation_mechanism.is_none()
            || self.ack_birth_attempted
            || self.native_import18_birth_construction.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if let Some(job) = &state.job {
            if !job.matches_original(state.original_launch.as_ref()) {
                return Err(RuntimeError::ForeignAuthority);
            }
            if !job.owns_source_binding(
                self,
                state
                    .attempt
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            ) || !job.same_mechanism(
                self.native_import18_derivation_mechanism
                    .as_ref()
                    .ok_or(RuntimeError::ForeignAuthority)?,
            ) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn isolated_derivation_known_backing_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Some(state) = &self.native_import18_derivation else {
            return Ok(0);
        };
        self.authenticate_isolated_derivation_storage_custody()?;
        let mut bytes = state
            .private_launch
            .as_ref()
            .map_or(0, Id::allocated_capacity);
        if let Some(original) = &state.original_launch {
            bytes = storage::sum(&[bytes, original.known_backing_data()?])?;
        }
        if let Some(plan) = &state.registration {
            bytes = storage::sum(&[bytes, storage::registration_storage(plan)?])?;
        }
        if let Some(job) = &state.job {
            bytes = storage::sum(&[bytes, job.known_direct_backing_data()?])?;
        }
        if let Some(seed) = &state.private_seed {
            bytes = storage::sum(&[bytes, seed.known_backing()?])?;
        }
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
}

fn verified_bank_ranges(
    result: &result_wire::VerifiedResult<'_>,
) -> Result<[Range<usize>; 2], RuntimeError> {
    if result.header().status() != Status::Success {
        return Err(RuntimeError::OwnerUnavailable);
    }
    let source_start = result_wire::HEADER_BYTES;
    let source_end = source_start
        .checked_add(result.source_bytes().len())
        .ok_or(RuntimeError::ResourceLimit)?;
    let registration_end = source_end
        .checked_add(result.registration_bytes().len())
        .ok_or(RuntimeError::ResourceLimit)?;
    Ok([source_start..source_end, source_end..registration_end])
}

#[cfg(test)]
#[path = "derivation/tests.rs"]
mod tests;
