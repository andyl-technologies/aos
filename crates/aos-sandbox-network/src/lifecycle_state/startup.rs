//! Retains the sole lifecycle replay and its actual captured writer.

use super::*;
use crate::journal::NetworkLifecycleCapturedJournalOpenV4;
use aos_sandbox_broker::receiving::{FixedServiceOperationClosedV4 as Closed,
    FixedServiceReceivingCaptureV1 as Common};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use crate::service_original::journal::{NetworkJournalOriginalV4,
    NetworkJournalStartupErrorV4, reached_rows_v4};

type Models = (BTreeMap<[u8; 16], DurableNetworkLifecycleRecord>, BTreeMap<[u8; 32], [u8; 16]>);

pub(crate) struct NetworkLifecycleOpeningOriginalV4 {
    native: NetworkJournalOriginalV4<NetworkLifecycleCapturedJournalOpenV4>,
    model: Option<Result<Models, NetworkLifecycleStateError>>,
    returned: Option<Result<(), NetworkJournalStartupErrorV4>>,
    entered: bool,
}

impl NetworkLifecycleOpeningOriginalV4 {
    pub(crate) fn new() -> Self {
        Self { native: NetworkJournalOriginalV4::new(), model: None, returned: None, entered: false }
    }

    pub(crate) fn capture_once_v4(&mut self, common: &mut Common<Closed>,
        authority: &NetworkAuthorityV1) -> Result<(), NetworkJournalStartupErrorV4> {
        if self.entered { return Err(NetworkJournalStartupErrorV4::Closed); }
        self.entered = true;
        self.returned = Some(self.native.open_once_v4(common, journal_limits(), model_demand_v4));
        if !matches!(self.returned, Some(Ok(()))) { return Err(NetworkJournalStartupErrorV4::Closed); }
        let journal = self.native.journal_v4().ok_or(NetworkJournalStartupErrorV4::Closed)?;
        self.model = Some(replay_models_v4(journal, authority));
        if matches!(self.model, Some(Ok(_))) { Ok(()) }
        else { Err(NetworkJournalStartupErrorV4::Closed) }
    }

    pub(crate) fn take_completed_once_v4(&mut self) -> Option<NetworkLifecycleStateStore> {
        if !matches!(self.returned, Some(Ok(()))) || !matches!(self.model, Some(Ok(_))) { return None; }
        let journal = self.native.take_journal_v4()?;
        let Some(Ok((records, heads))) = self.model.take() else { std::process::abort() };
        Some(NetworkLifecycleStateStore { journal, records, heads })
    }

    pub(crate) fn original_failure_selected_v4(&self) -> bool {
        self.native.original_failure_selected_v4()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.failure().or_else(|| self.model.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

fn model_demand_v4(extent: &crate::journal::ProtectedJournalPreopenReplayExtentV1)
    -> Result<ResourceVector, NetworkJournalStartupErrorV4> {
    let closed = || NetworkJournalStartupErrorV4::Closed;
    let rows = reached_rows_v4(extent)?;
    use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
    let maps = nodes::<[u8; 16], DurableNetworkLifecycleRecord>(rows)
        .and_then(|bytes| bytes.checked_add(nodes::<[u8; 32], [u8; 16]>(rows)?))
        .ok_or_else(closed)?;
    // Binary blob copies and their current/operation/effect comparisons remain
    // co-live with both maps. The configured record scratch is independent of
    // absent advertised payload; these are bytes, not protocol-field entries.
    let bytes = extent.native_bytes.checked_mul(16)
        .and_then(|bytes| bytes.checked_add((MAXIMUM_RECORD_BYTES * 8) as u64))
        .and_then(|bytes| bytes.checked_add(u64::try_from(maps).ok()?)).ok_or_else(closed)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
        .with(D::MetadataEntries, u64::try_from(rows.checked_mul(2).ok_or_else(closed)?)
            .map_err(|_| closed())?))
}

impl NetworkLifecycleOpeningOriginalV4 {
    pub(crate) fn inventory_currentness_demand_v2(&self)
        -> std::result::Result<ResourceVector, crate::journal::JournalError>
    {
        self.native.inventory_currentness_demand_v2()
    }

    pub(crate) fn inventory_currentness_before_v2(&self, journal: &Journal,
        original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> std::result::Result<(), crate::journal::JournalError> {
        self.native.inventory_currentness_before_v2(journal, original)
    }

    pub(crate) fn inventory_currentness_after_owed_v2(&self, journal: &Journal,
        original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> std::result::Result<(), crate::journal::JournalError> {
        self.native.inventory_currentness_after_owed_v2(journal, original)
    }
}
