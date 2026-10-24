//! Compares actual completed Producer work with immutable restoration ancestry.
//!
//! These borrowed inputs and report bytes are correspondence DATA. The Source
//! authenticates the real Controller, child, current read fence and same pending
//! Core operation before and after validation. Neither a successful comparison
//! nor a report creates execution, publication or retirement permission.

use crate::ProviderError;
use crate::bodies::{BeginKind, ExactRunArguments};
use crate::client::OriginalRestoredSuffixHostAttempt;
use crate::reference_packet::control::PacketNativeRecord;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crucible_node_format::{ContentRef, Id, Position};

use super::{PacketNativeRestoredCommitHold, PacketNativeRestoredRecord};

mod completed;
mod historical;
mod lineage;
mod pair_views;
mod report;
pub(crate) mod report_storage;
mod retired;
mod typed_owners;

pub use completed::authenticate_restored_producer_completed_data;
pub use historical::{
    PacketRestoredProducerHistoricalCompletedData, PacketRestoredProducerHistoricalRetiredData,
    authenticate_restored_producer_historical_completed_data,
    authenticate_restored_producer_historical_retired_data,
};
pub use report::PacketRestoredProducerOperationReportData;
pub use report_storage::{
    PacketRestoredProducerReportStorageData,
    original_restored_producer_report_counter_scratch_data,
    original_restored_producer_report_storage_data,
};
pub use retired::authenticate_restored_producer_retired_data;
pub use typed_owners::{
    PacketRestoredProducerTypedOwnerData,
    original_restored_producer_typed_owner_counter_scratch_data,
};

/// Borrows the genuine caller's intended closed Producer operation.
#[derive(Clone, Copy)]
pub struct PacketRestoredProducerOperationData<'a> {
    /// Names the actual pending Core operation, without fabricating its grant.
    pub operation: &'a Id,
    /// Selects exact work or same-time settlement; other kinds refuse.
    pub kind: BeginKind,
    /// Gives the latest verified post-retirement cursor.
    pub start: Position,
    /// Gives the genuine exclusive ceiling supplied by the common scheduler.
    pub limit: Position,
}

/// Borrows complete Source-retained evidence before durable publication and ACK.
pub struct PacketRestoredProducerCompletedData<'a> {
    /// Borrows the actual installed typed launch paired with its retained raw bank.
    pub launch: &'a PacketNative5SourceLaunch,
    /// Keeps immutable original Commit ancestry separate from current progress.
    pub held: &'a PacketNativeRestoredCommitHold,
    /// Borrows the latest independently verified, fully retired checkpoint.
    pub checkpoint: &'a PacketNativeRestoredRecord,
    /// Borrows its complete underlying Producer2 record.
    pub checkpoint_producer: &'a PacketNativeRecord,
    /// Borrows the completed Begin proof in the unchanged restored12 grammar.
    pub restored: &'a PacketNativeRestoredRecord,
    /// Borrows the complete actual native Producer2 record with its real grant.
    pub producer: &'a PacketNativeRecord,
    /// Names the full canonical restored12 bytes authenticated by the Source.
    pub measurement: &'a ContentRef,
    /// Borrows the actual SDK-retained Begin original and completed terminal.
    pub begin: &'a OriginalRestoredSuffixHostAttempt,
    /// Borrows the actual later SDK Poll and its complete cached Begin outcome.
    pub poll: &'a OriginalRestoredSuffixHostAttempt,
    /// Borrows the exact intended operation independently of decoded wire claims.
    pub operation: PacketRestoredProducerOperationData<'a>,
    /// Borrows the actual common grant authorization uploaded before Begin.
    pub arguments: &'a ExactRunArguments,
}

/// Borrows actual post-durability retirement and a fresh current checkpoint.
pub struct PacketRestoredProducerRetiredData<'a> {
    /// Borrows the previously validated prepublication evidence without rewriting it.
    pub completed: &'a PacketRestoredProducerCompletedData<'a>,
    /// Names the durable custody object uploaded for the exact retained outputs.
    pub consumption: &'a ContentRef,
    /// Borrows its complete actual canonical bytes; these do not contain the durable root.
    pub canonical_consumption: &'a [u8],
    /// Names the separately committed root verified through the actual publisher loan.
    pub durable_root: &'a ContentRef,
    /// Borrows the actual SDK-retained Consumed Retire pair.
    pub retire: &'a OriginalRestoredSuffixHostAttempt,
    /// Borrows the later fresh SDK Observe pair at the current read frontier.
    pub observe: &'a OriginalRestoredSuffixHostAttempt,
    /// Borrows the fresh restored12 proof after the actual native retirement.
    pub restored: &'a PacketNativeRestoredRecord,
    /// Borrows its full underlying Producer2 record, with no current grant.
    pub producer: &'a PacketNativeRecord,
    /// Names the full authenticated canonical fresh restored12 body.
    pub measurement: &'a ContentRef,
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("restored Producer progress correspondence differs")
}

/// Names full borrowed evidence, raw decoders and validation result layouts.
pub fn original_restored_producer_progress_counter_scratch_data() -> usize {
    use crate::bodies::{
        BeginArguments, BeginRequest, ObserveRequest, PollRequest, RequestBody, ResponseBody,
        RetireRequest,
    };
    use crate::envelope::Envelope;
    use std::mem::size_of;
    pair_views::counter_scratch_data()
        + size_of::<PacketRestoredProducerHistoricalCompletedData<'static>>()
        + size_of::<PacketRestoredProducerHistoricalRetiredData<'static>>()
        + size_of::<retired::Consumption>()
        + size_of::<Result<retired::Consumption, serde_json::Error>>()
        + size_of::<PacketRestoredProducerCompletedData<'static>>()
        + size_of::<PacketRestoredProducerRetiredData<'static>>()
        + size_of::<PacketRestoredProducerOperationData<'static>>()
        + size_of::<PacketRestoredProducerOperationReportData<'static>>()
        + size_of::<(&Envelope, &Envelope, &ResponseBody)>()
        + size_of::<Result<(&Envelope, &Envelope, &ResponseBody), ProviderError>>()
        + size_of::<Result<RequestBody, ProviderError>>()
        + size_of::<Result<ResponseBody, ProviderError>>()
        + size_of::<Result<BeginArguments, ProviderError>>()
        + size_of::<Result<BeginArguments, crucible_node_format::ContractError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<Result<crucible_node_format::HashRef, crucible_node_format::ContractError>>()
        + size_of::<Option<&crate::reference_packet::PacketGrant>>()
        + size_of::<Result<&crate::reference_packet::PacketGrant, ProviderError>>()
        + size_of::<&BeginRequest>()
        + size_of::<&PollRequest>()
        + size_of::<&RetireRequest>()
        + size_of::<&ObserveRequest>()
        + size_of::<std::slice::Iter<'static, crate::reference_packet::PacketEvent>>() * 3
        + size_of::<std::slice::Iter<'static, crate::reference_packet::PacketPublication>>()
        + size_of::<std::ops::Range<usize>>() * 2
        + size_of::<Result<crucible_node_format::HashRef, ProviderError>>()
        + original_restored_producer_typed_owner_counter_scratch_data()
        + original_restored_producer_report_counter_scratch_data()
        + crate::connection::original_serialized_credit_counter_scratch_data()
}

#[cfg(test)]
mod tests;
