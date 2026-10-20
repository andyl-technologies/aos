//! Prices the reached D client native/byte peak and cumulative property traffic.

use super::opening::RootDeleteClientOpeningV1;
use super::super::strict_chunk::RootStrictChunkOriginalV1 as ChunkV1;
use super::{
    CreateStorageRootPeerReceivingOriginalsV1, ProductionControllerNormalRootProfileV1,
    RootDeleteClientOriginalV1,
};
use crate::journal::JournalError;
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1, RootSubjectReadinessV1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1;
use aos_sandbox_protocol::domain_ledger::delete_root::controller_cut::DELETE_ROOT_CONTROLLER_CUT_BYTES_V3;
use std::mem::size_of;

impl RootDeleteClientOriginalV1<'_> {
    pub(super) fn fixed_demand_v1(
        profile: &ProductionControllerNormalRootProfileV1,
        batch_bytes: usize,
        authorization_input_bytes: usize,
    ) -> Result<ResourceVector, JournalError> {
        let overflow = || JournalError::ProtectedBoundary;
        use aos_sandbox_protocol::domain_ledger::delete_root::authorization::{
            DELETE_ROOT_AUTHORIZATION_INPUT_MAXIMUM_BYTES_V2,
            DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2,
            DELETE_ROOT_AUTHORIZATION_CHECKSUM_BYTES_V2,
        };
        if !(1..=DELETE_ROOT_AUTHORIZATION_INPUT_MAXIMUM_BYTES_V2).contains(&authorization_input_bytes) {
            return Err(overflow());
        }
        let authorization_bytes = authorization_input_bytes.checked_add(DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2)
            .and_then(|bytes| bytes.checked_add(DELETE_ROOT_AUTHORIZATION_CHECKSUM_BYTES_V2)).ok_or_else(overflow)?;
        let authorization_wire = u64::try_from(authorization_bytes).map_err(|_| overflow())?;
        let native = CreateStorageRootPeerReceivingOriginalsV1::delete_native_peak_v1(profile)
            .ok_or_else(overflow)?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let (subject_bytes, subject_files) = geometry.receive_obligations_v1();
        let clock_bytes = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(overflow)?;
        let parser =
            DeleteBatchViewV1::decode_receiving_bytes_v1(batch_bytes).ok_or_else(overflow)?;
        let framing = size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(size_of::<RootDeleteClientOpeningV1>().checked_mul(3)?)
            })
            .and_then(|bytes| bytes.checked_add(size_of::<ChunkV1>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(subject_bytes.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(clock_bytes.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(batch_bytes.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(parser))
            .and_then(|bytes| bytes.checked_add(authorization_bytes.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<sha2::Sha256>()))
            .and_then(|bytes| bytes.checked_add(3 * 224 + 3 * aos_sandbox_protocol::domain_ledger::resource_bank::OPERATION_INTAKE_FUNDING_BYTES_V1 + 3 * 4096))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let readiness =
            RootSubjectReadinessV1::receiving_construction_bytes_v1().ok_or_else(overflow)?;
        // The shared supplier names the first held sample, failed chunk and
        // independent after together, without old Rust-field metadata fees.
        let resident = native.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, framing.checked_add(readiness).ok_or_else(overflow)?)
                .with(D::OpenFiles, u64::try_from(subject_files).ok()
                    .and_then(|files| files.checked_add(3))
                    .and_then(|files| files.checked_add(2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64))
                    .ok_or_else(overflow)?)
                .with(D::Pids, 1)).map_err(|_| JournalError::ProtectedBoundary)?;
        let controller_cut_bytes = u64::try_from(DELETE_ROOT_CONTROLLER_CUT_BYTES_V3)
            .map_err(|_| overflow())?;
        let batch_wire_bytes = u64::try_from(batch_bytes).map_err(|_| overflow())?;
        let network = batch_wire_bytes.checked_add(208 + 224)
            .and_then(|bytes| bytes.checked_add(controller_cut_bytes))
            .and_then(|bytes| bytes.checked_add(authorization_wire))
            .ok_or_else(overflow)?;
        resident
            .checked_add(
                ResourceVector::ZERO.with(D::NetworkBytes, network).with(
                    D::OutputBytes,
                    batch_wire_bytes.checked_add(208)
                        .and_then(|bytes| bytes.checked_add(controller_cut_bytes))
                        .and_then(|bytes| bytes.checked_add(authorization_wire))
                        .ok_or_else(overflow)?,
                ),
            )
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(super) fn peer_traffic_v1(samples: usize) -> Result<ResourceVector, JournalError> {
        let (network, log) = CreateStorageRootPeerReceivingOriginalsV1::query_traffic_v1(samples)
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(ResourceVector::ZERO
            .with(D::NetworkBytes, network)
            .with(D::LogBytes, log))
    }
}
