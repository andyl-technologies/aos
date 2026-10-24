//! Shares Producer proof correspondence with strict inert SDK pair loans.
//!
//! A historical pair is parsed DATA. These adapters never reconstruct an SDK
//! attempt or substitute historical validity for live Source/Window authority.

use super::*;
use crate::protocol_snapshot::current_controller17::ValidatedHistoricalRestoredSuffixPair;

/// Borrows inert, validated historical Producer evidence for correspondence checks.
///
/// This input creates no live SDK attempt, currentness, publication or execution
/// permission. The caller separately authenticates its signed archive and Source
/// history; every pair comes from the defining strict historical SDK reader.
pub struct PacketRestoredProducerHistoricalCompletedData<'a> {
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
    /// Borrows the validated historical Begin original and completed terminal.
    pub begin: &'a ValidatedHistoricalRestoredSuffixPair,
    /// Borrows the validated historical Poll and its complete cached Begin outcome.
    pub poll: &'a ValidatedHistoricalRestoredSuffixPair,
    /// Borrows the exact intended operation independently of decoded wire claims.
    pub operation: PacketRestoredProducerOperationData<'a>,
    /// Borrows the actual common grant authorization uploaded before Begin.
    pub arguments: &'a ExactRunArguments,
}

/// Borrows inert historical retirement evidence without reviving SDK authority.
///
/// The same native ancestry, transition and retirement predicates as the live
/// validator apply. Historical pair validation alone proves no current frontier
/// or actual durable publication.
pub struct PacketRestoredProducerHistoricalRetiredData<'a> {
    /// Borrows the previously validated prepublication evidence without rewriting it.
    pub completed: &'a PacketRestoredProducerHistoricalCompletedData<'a>,
    /// Names the durable custody object uploaded for the exact retained outputs.
    pub consumption: &'a ContentRef,
    /// Borrows its complete actual canonical bytes; these do not contain the durable root.
    pub canonical_consumption: &'a [u8],
    /// Names the separately committed root verified through the actual publisher loan.
    pub durable_root: &'a ContentRef,
    /// Borrows the validated historical Consumed Retire pair.
    pub retire: &'a ValidatedHistoricalRestoredSuffixPair,
    /// Borrows the later historical Observe pair at its recorded frontier.
    pub observe: &'a ValidatedHistoricalRestoredSuffixPair,
    /// Borrows the fresh restored12 proof after the actual native retirement.
    pub restored: &'a PacketNativeRestoredRecord,
    /// Borrows its full underlying Producer2 record, with no current grant.
    pub producer: &'a PacketNativeRecord,
    /// Names the full authenticated canonical fresh restored12 body.
    pub measurement: &'a ContentRef,
}

/// Compares complete historical Begin/Poll evidence using the live proof rules.
///
/// # Errors
/// Refuses invalid pair loans or any ancestry, operation, argument, transition,
/// response or model correspondence rejected by the live completed validator.
pub fn authenticate_restored_producer_historical_completed_data(
    input: &PacketRestoredProducerHistoricalCompletedData<'_>,
) -> Result<(), ProviderError> {
    let view = super::pair_views::Completed::from_historical(input);
    super::completed::authenticate_completed_view_data(&view)
}

/// Compares historical Retire/Observe evidence using the live proof rules.
///
/// # Errors
/// Refuses an invalid completed proof, consumption object, immutable lineage,
/// pair, retired output set or post-retirement model/observation correspondence.
pub fn authenticate_restored_producer_historical_retired_data(
    input: &PacketRestoredProducerHistoricalRetiredData<'_>,
) -> Result<(), ProviderError> {
    let completed = super::pair_views::Completed::from_historical(input.completed);
    let view = super::pair_views::Retired::from_historical(input, &completed);
    super::retired::authenticate_retired_view_data(&view)
}
