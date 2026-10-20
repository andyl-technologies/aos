//! Derives the closed Source serving lanes from their actual resident types.
//!
//! The same original reserves these finite capacities once. Each actual stage
//! then consumes its complete noncopy loan; positive disposal permits reuse,
//! while a failed sample keeps the lane and its native custody closed.

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, SubjectStreamReceiveGeometryV1};

use crate::signer::SourceReceivingGeometryErrorV1 as ResourceReservationErrorV1;
use crate::signer::root_observation::{SourceRootChunkReadbackV1, SourceRootPeerStageV1};

use super::super::currentness::SourceCurrentnessSampleV1;
use super::{SourceConnectionV1, SourceServingV1};
use super::connection::MAXIMUM_REPLY_FRAME;
use aos_sandbox_ledger_replay::source_signer_data::source_signer_wire::REQUEST_RESOURCE_SUCCESSOR_BYTES;

pub(super) struct SourceServingGeometryV1 {
    pub(super) resident: ResourceVector,
    pub(super) stage: ResourceVector,
    pub(super) chunk: ResourceVector,
    pub(super) physical_files: u64,
}

impl SourceServingGeometryV1 {
    pub(super) fn derive(
        geometry: &SubjectStreamReceiveGeometryV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let sample = SourceCurrentnessSampleV1::dynamic_demand()?;
        let samples = sample.checked_add(sample)?;
        let (chunk_bytes, chunk_files) = geometry.receive_obligations_v1();
        let (eof_bytes, eof_files) = geometry.eof_receive_obligations_v1();
        let (adoption_bytes, adoption_files) = RetainedUnixStream::retained_admission_obligations_v1();
        // Two exact buffers coexist with the decoded maximum 1496-byte context.
        // Sixteen encoded copies cover those matching context/approval carriers,
        // canonical round trips and framing, never an unrelated model per byte.
        let current_pair_bytes = 2_usize.checked_mul(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>())
            .and_then(|bytes| bytes.checked_add(2 * aos_sandbox_protocol::domain_ledger::create_storage_history::KEY_BYTES))
            .and_then(|bytes| bytes.checked_add(aos_sandbox_protocol::domain_ledger::create_storage_history::source_held::SOURCE_HELD_RECORD_BYTES_V1))
            .and_then(|bytes| bytes.checked_add(aos_sandbox_protocol::domain_ledger::create_storage_history::HEAD_BYTES))
            .ok_or(overflow)?;
        let resident_bytes = std::mem::size_of::<SourceServingV1>()
            .checked_add(std::mem::size_of::<SourceConnectionV1>())
            .and_then(|bytes| bytes.checked_add(16 * REQUEST_RESOURCE_SUCCESSOR_BYTES + 4 * MAXIMUM_REPLY_FRAME))
            .and_then(|bytes| bytes.checked_add(MAXIMUM_REPLY_FRAME * std::mem::size_of::<Result<usize, rustix::io::Errno>>()))
            .and_then(|bytes| bytes.checked_add(adoption_bytes))
            .and_then(|bytes| bytes.checked_add(eof_bytes))
            .and_then(|bytes| bytes.checked_add(current_pair_bytes))
            .ok_or(overflow)?;
        let resident = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(resident_bytes).map_err(|_| overflow)?)
            .with(D::OpenFiles, u64::try_from(adoption_files + eof_files).map_err(|_| overflow)?)
            .with(D::MetadataEntries, MAXIMUM_REPLY_FRAME as u64 + 32 + 4 + 2 + 2 * 3 + 5 + 8);
        let stage = SourceRootPeerStageV1::demand()?
            .checked_add(samples)?
            .checked_add(ResourceVector::ZERO
                .with(D::NetworkBytes, 4 * 64 * 1024 + MAXIMUM_REPLY_FRAME as u64)
                .with(D::OutputBytes, 4 * 64 * 1024 + MAXIMUM_REPLY_FRAME as u64)
                .with(D::ConcurrentOperations, 1))?;
        let chunk = SourceRootChunkReadbackV1::demand()?
            .checked_add(samples)?
            .checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(chunk_bytes).map_err(|_| overflow)?)
                .with(D::OpenFiles, u64::try_from(chunk_files).map_err(|_| overflow)?)
                .with(D::NetworkBytes, 4096)
                .with(D::OutputBytes, 4096)
                .with(D::ConcurrentOperations, 1))?;
        let physical_files = resident.checked_add(stage)?.checked_add(chunk)?.get(D::OpenFiles);
        Ok(Self { resident, stage, chunk, physical_files })
    }

    pub(super) fn financial(&self) -> Result<ResourceVector, AccountingError> {
        // This projection is called only inside the same genuine Original,
        // after complete F3/profile/executable/current hard-N coverage checks.
        // Keep the full physical sum above for the cumulative descriptor proof.
        self.resident.checked_add(self.stage)?.checked_add(self.chunk)
            .map(|demand| demand.with(D::OpenFiles, 0))
    }
}
