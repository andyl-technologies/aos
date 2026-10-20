//! Forwards the sole historical Cache representation supplier to Protocol.
//!
//! Native wrappers and their current capability frontiers remain unchanged.
//! Width equalities below prove that the canonical DATA recipe prices the same
//! concrete carrier layouts used by the existing Native callers.

use super::*;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::cache_state::recovery::representation as data_geometry;

pub(in crate::cache_residency) use data_geometry::CacheReplayRepresentationPhaseV1;

pub(in crate::cache_residency) fn general_replay_representation_bound_v1(
    encoded_bytes: usize,
    partitions: usize,
    phase: CacheReplayRepresentationPhaseV1,
) -> Result<ResourceVector, RecoveryError> {
    data_geometry::general_replay_representation_bound_v1(encoded_bytes, partitions, phase)
        .map_err(RecoveryError::from)
}

const _: [(); std::mem::size_of::<CacheRecoveryInventoryV1>()] =
    [(); std::mem::size_of::<data::CacheRecoveryInventoryDataV1>()];
const _: [(); std::mem::size_of::<
    aos_sandbox_protocol::domain_ledger::records::DurableDomainMemberV1<
        crate::cache_residency::protected_journal::CacheResidencyProtectedJournalSchemaV1,
    >,
>()] = [(); std::mem::size_of::<
    aos_sandbox_protocol::domain_ledger::records::DurableDomainMemberV1<
        aos_sandbox_protocol::cache_state::protected_replay::CacheResidencyHistoricalSchemaDataV1,
    >,
>()];
const _: [(); std::mem::size_of::<
    aos_sandbox_protocol::domain_ledger::records::ProtectedDomainEnvelopeV1<
        crate::cache_residency::protected_journal::CacheResidencyProtectedJournalSchemaV1,
    >,
>()] = [(); std::mem::size_of::<
    aos_sandbox_protocol::domain_ledger::records::ProtectedDomainEnvelopeV1<
        aos_sandbox_protocol::cache_state::protected_replay::CacheResidencyHistoricalSchemaDataV1,
    >,
>()];
const _: [(); std::mem::size_of::<
    aos_sandbox_protocol::domain_ledger::records::ProtectedDomainReplayTransactionV1<
        crate::cache_residency::protected_journal::CacheResidencyProtectedJournalSchemaV1,
    >,
>()] = [(); std::mem::size_of::<
    aos_sandbox_protocol::domain_ledger::records::ProtectedDomainReplayTransactionV1<
        aos_sandbox_protocol::cache_state::protected_replay::CacheResidencyHistoricalSchemaDataV1,
    >,
>()];
