//! Retains one fresh paid Root entropy/paired-clock challenge and its owed post.
//!
//! The actual D accepted flight supplies this private entry. The fixed opening
//! remains comparison DATA; no completion here can accept Delete, publish a
//! floor, validate six domains or lift a lifecycle guard.

use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1, fresh_root_nonce};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::{
    delete_batch::DeleteBatchViewV1,
    delete_root::{
        source_current::SourceDeleteCurrentQueryDataV1,
        transport::{
            DELETE_ROOT_CHALLENGE_BYTES_V2, DeleteRootChallengeDataV2, DeleteRootOpenDataV2,
            DeleteRootWireErrorV2,
        },
    },
};
use std::error::Error as StdError;
use std::io;

#[derive(Default)]
pub(crate) struct RootDeleteChallengeOriginalsV1 {
    entered: bool,
    open: Option<DeleteRootOpenDataV2>,
    permit: Option<Result<(), ResourceReservationErrorV1>>,
    before_original: RetainedKernelPairedClockAttemptV1,
    before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    nonce: Option<io::Result<[u8; 16]>>,
    cutoff: Option<Result<u64, DeleteRootWireErrorV2>>,
    source: Option<Result<SourceDeleteCurrentQueryDataV1, DeleteRootWireErrorV2>>,
    challenge: Option<Result<[u8; DELETE_ROOT_CHALLENGE_BYTES_V2], DeleteRootWireErrorV2>>,
    returned: Option<Result<(), NormalRootStartupErrorV1>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), DeleteRootWireErrorV2>>,
    closed: Option<NormalRootStartupErrorV1>,
}

impl RootDeleteChallengeOriginalsV1 {
    pub(crate) fn receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.permit.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.receiving_recipe_v1()
    }

    pub(crate) fn retained_receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.require_paid_chunk_peak_v1()?;
        self.receiving_recipe_v1()
    }

    fn receiving_recipe_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let open = self.open.ok_or_else(invalid)?;
        let length = usize::try_from(open.batch_bytes).map_err(|_| invalid())?;
        let graph = DeleteBatchViewV1::decode_receiving_bytes_v1(length).ok_or_else(invalid)?;
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let bytes = std::mem::size_of::<super::RootDeletePendingReceivingV1<'_, '_, '_>>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(pair.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(length))
            .and_then(|bytes| bytes.checked_add(graph))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<u8>>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        // The fixed opening's extra96 bytes were already debited by this
        // same actual receiver before reading them. This next stage pays only
        // the complete batch and challenge before their growth/native IO.
        let network = length
            .checked_add(DELETE_ROOT_CHALLENGE_BYTES_V2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let native_chunk = crate::policy_compiler::root_subject_chunk::RootSubjectChunkReceivingV1::delete_receiving_demand_v1()
            .map_err(|_| invalid())?;
        ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .with(
                D::OpenFiles,
                2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64,
            )
            .with(D::NetworkBytes, network)
            .with(D::OutputBytes, DELETE_ROOT_CHALLENGE_BYTES_V2 as u64)
            .checked_add(native_chunk)
            .map_err(Into::into)
    }

    pub(crate) fn require_paid_chunk_peak_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.permit, Some(Ok(())))
            || !matches!(self.returned, Some(Ok(())))
            || self.failure().is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn current_cutoff_v1(&self) -> Result<u64, NormalRootStartupErrorV1> {
        self.require_paid_chunk_peak_v1()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        self.source_query_v1().map(|query| query.cutoff)
    }

    pub(crate) fn continuation_horizon_v2(&self) -> Result<
        crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1, crate::journal::JournalError> {
        self.require_paid_chunk_peak_v1().map_err(|_| crate::journal::JournalError::ProtectedBoundary)?;
        let original = *positive(&self.before).map_err(|_| crate::journal::JournalError::ProtectedBoundary)?;
        let cutoff = *positive(&self.cutoff).map_err(|_| crate::journal::JournalError::ProtectedBoundary)?;
        let open = self.open.ok_or(crate::journal::JournalError::ProtectedBoundary)?;
        Ok(crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1::from_original_data_v1(original, cutoff)?
            .with_wall_expiry_data_v1(open.authorization_expires))
    }

    pub(crate) fn require_current_clock_v1(
        &self,
        now: RawPairedClockSample,
    ) -> Result<(), crate::journal::JournalError> {
        let invalid = || crate::journal::JournalError::ProtectedBoundary;
        let before = *positive(&self.before).map_err(|_| invalid())?;
        before.validate_later_sample(now).map_err(|_| invalid())?;
        let open = self.open.ok_or_else(invalid)?;
        open.authorization_clock
            .validate_later_sample(now)
            .map_err(|_| invalid())?;
        let cutoff = *positive(&self.cutoff).map_err(|_| invalid())?;
        if now.boottime_nanoseconds() >= cutoff || now.wall_seconds() >= open.authorization_expires
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn prepare_once_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        open: DeleteRootOpenDataV2,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.entered || self.closed.is_some() {
            self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.entered = true;
        self.open = Some(open);
        self.returned = Some(self.prepare_inner(flight, open));
        if self.failure().is_none() && matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Service)
        }
    }

    fn prepare_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        open: DeleteRootOpenDataV2,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.permit = Some(flight.admit_delete_challenge_once_v1(self));
        positive(&self.permit)?;
        self.before = Some(self.before_original.observe_once(None));
        let before = *positive(&self.before)?;
        self.nonce = Some(fresh_root_nonce());
        let nonce = *positive(&self.nonce)?;
        self.cutoff = Some(open.cutoff_for_root_sample_v1(before));
        let cutoff = *positive(&self.cutoff)?;
        self.source = Some((|| {
            let query = SourceDeleteCurrentQueryDataV1 {
                nonce,
                project: open.project,
                operation: open.operation,
                batch: open.batch,
                boot: before.host_boot_id(),
                started: before.boottime_nanoseconds(),
                cutoff,
            };
            query.encode()?;
            Ok(query)
        })());
        let source = *positive(&self.source)?;
        self.challenge = Some((|| {
            let challenge = DeleteRootChallengeDataV2 {
                open: open.digest_v2()?,
                clock: before,
                source,
            };
            challenge.require_open_v2(open)?;
            challenge.encode_v2()
        })());
        positive(&self.challenge).map(|_| ())
    }

    pub(super) fn challenge_bytes_v1(
        &self,
    ) -> Result<&[u8; DELETE_ROOT_CHALLENGE_BYTES_V2], NormalRootStartupErrorV1> {
        if !matches!(self.returned, Some(Ok(()))) || self.failure().is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        positive(&self.challenge)
    }

    pub(super) fn source_query_v1(
        &self,
    ) -> Result<SourceDeleteCurrentQueryDataV1, NormalRootStartupErrorV1> {
        self.challenge_bytes_v1()?;
        positive(&self.source).copied()
    }

    pub(super) fn finish_clock_once_v1(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if self.after.is_some() || !matches!(self.permit, Some(Ok(()))) {
            self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
            return Err(NormalRootStartupErrorV1::Service);
        }
        // This native post is owed after every funded primary result, without
        // consulting healthy peer/protocol accessors or sampling a new origin.
        self.after = Some(self.after_original.observe_once(None));
        self.after_binding = Some((|| {
            let before = *positive(&self.before).map_err(|_| DeleteRootWireErrorV2::Clock)?;
            let after = *positive(&self.after).map_err(|_| DeleteRootWireErrorV2::Clock)?;
            before
                .validate_later_sample(after)
                .map_err(|_| DeleteRootWireErrorV2::Clock)?;
            let open = self.open.ok_or(DeleteRootWireErrorV2::Association)?;
            open.authorization_clock
                .validate_later_sample(after)
                .map_err(|_| DeleteRootWireErrorV2::Clock)?;
            let cutoff = *positive(&self.cutoff).map_err(|_| DeleteRootWireErrorV2::Clock)?;
            if after.wall_seconds() >= open.authorization_expires
                || after.boottime_nanoseconds() >= cutoff
            {
                return Err(DeleteRootWireErrorV2::Clock);
            }
            Ok(())
        })());
        positive(&self.after_binding).map(|_| ())
    }

    pub(super) fn funding_failed_v1(&self) -> bool {
        matches!(self.permit, Some(Err(_)))
    }

    pub(super) fn funded_v1(&self) -> bool {
        matches!(self.permit, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.permit)
            .or_else(|| self.before_original.failure())
            .or_else(|| cause(&self.before))
            .or_else(|| cause(&self.nonce))
            .or_else(|| cause(&self.cutoff))
            .or_else(|| cause(&self.source))
            .or_else(|| cause(&self.challenge))
            .or_else(|| cause(&self.returned))
            .or_else(|| self.after_original.failure())
            .or_else(|| cause(&self.after))
            .or_else(|| cause(&self.after_binding))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, NormalRootStartupErrorV1> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(NormalRootStartupErrorV1::Service)
}

fn cause<T, E: StdError + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
