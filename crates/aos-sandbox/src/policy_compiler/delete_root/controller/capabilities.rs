//! Captures Root's complete registry census from its actual disposed C reader.
//!
//! All original native/service/clock afters precede the completed-holder borrow.
//! The same R admits the additional model peak before canonical JSON or Runtime
//! replay. Failed models/errors stay on the enclosing Root owner; no native
//! Journal, protected location or live capability is reconstructed from rows.

use super::*;
use crate::publisher_admin::{PublisherReadDataV2, capabilities::{
    PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityCensusDataV2,
    publisher_capability_census_from_rows_v2, publisher_capability_census_receiving_bytes_v2,
}};

#[derive(Default)]
pub(super) struct RootDeleteCapabilityCensusOriginalV2 {
    pub(super) geometry: Option<Result<ResourceVector, JournalError>>,
    pub(super) census: Option<Result<PublisherCapabilityCensusDataV2, PublisherAuthorityError>>,
}

impl RootDeleteCapabilityCensusOriginalV2 {
    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.geometry).or_else(|| cause(&self.census))
    }
}

impl RootDeleteControllerCurrentOriginalV1 {
    /// Lends the real independently completed census for graph recomputation.
    ///
    /// # Errors
    /// Refuses incomplete original posts, model failure or absent complete census.
    pub(crate) fn verified_capability_census_data_v2(&self)
        -> Result<&[aos_sandbox_ledger_replay::delete_graph::DeleteGraphCapabilityDataV2], RootDeleteErrorV1>
    {
        if !self.complete || self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Original);
        }
        self.capabilities.census.as_ref().and_then(|value| value.as_ref().ok())
            .map(|census| census.records.as_slice()).ok_or(RootDeleteErrorV1::Original)
    }

    /// Borrows only this completed C holder's actual canonical map.
    ///
    /// The borrow is used for synchronous comparison/geometry; it cannot reopen
    /// a Journal or adopt native authority from these historical rows.
    pub(crate) fn graph_controller_rows_v2(&self)
        -> Result<&std::collections::BTreeMap<
            (aos_sandbox_core::RecordNamespace, Vec<u8>), Vec<u8>>, RootDeleteErrorV1>
    {
        if !self.complete || self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Original);
        }
        self.completed_reader.as_ref().ok_or(RootDeleteErrorV1::Original)?
            .readback_v2().map(|view| view.state).map_err(|_| RootDeleteErrorV1::Original)
    }

    /// Moves the same positive census beside a short actual completed-C borrow.
    ///
    /// The Source observer owns the census from this point through its graph
    /// capture and later metadata join; no decoded rows create another census.
    pub(crate) fn take_graph_inputs_v2(&mut self)
        -> Result<(&std::collections::BTreeMap<
            (aos_sandbox_core::RecordNamespace, Vec<u8>), Vec<u8>>,
            Vec<aos_sandbox_ledger_replay::delete_graph::DeleteGraphCapabilityDataV2>), RootDeleteErrorV1>
    {
        if !self.complete || self.first.is_some() || self.failure().is_some()
            || !matches!(self.capabilities.census, Some(Ok(_)))
        {
            return Err(RootDeleteErrorV1::Original);
        }
        let state = self.completed_reader.as_ref().ok_or(RootDeleteErrorV1::Original)?
            .readback_v2().map_err(|_| RootDeleteErrorV1::Original)?.state;
        match self.capabilities.census.take() {
            Some(Ok(census)) => Ok((state, census.records)),
            _ => Err(RootDeleteErrorV1::Original),
        }
    }

    pub(super) fn capability_census_demand_v2(&self) -> Result<ResourceVector, JournalError> {
        let state = self.completed_reader.as_ref().ok_or(JournalError::ProtectedBoundary)?
            .readback_v2()?.state;
        let bytes = publisher_capability_census_receiving_bytes_v2(
            PublisherReadDataV2::from_state_v2(state))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        // The Runtime/full-publication crosscheck is an additional simultaneous
        // semantic parse beside the retained cold maps, not a fresh native read.
        let (encoded, rows) = state.iter().try_fold((0usize, 0usize), |(bytes, rows), ((_, key), value)| {
            Some((bytes.checked_add(key.len())?.checked_add(value.len())?, rows.checked_add(1)?))
        }).ok_or(JournalError::JournalTooLarge)?;
        aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(encoded, rows)
            .map_err(JournalError::from)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(super) fn capture_capability_census_v2(&self)
        -> Result<PublisherCapabilityCensusDataV2, PublisherAuthorityError>
    {
        let reader = self.completed_reader.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let state = reader.readback_v2()?.state;
        publisher_capability_census_from_rows_v2(PublisherReadDataV2::from_state_v2(state),
            reader.historical_rows_data_v2()?, PublisherAuthorityLimits::default())
    }
}
