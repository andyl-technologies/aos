//! Retains actual held Session shape and the whole canonical validation debit.
//!
//! Closed Inventory and B callers supply their actual held Journal only after
//! their genuine fixed/currentness entry. This private sampler opens no writer,
//! parses no model and exposes no resource account or grant. Each caller adds
//! its complete result to its own original highwater before decoder growth.

use aos_sandbox_core::{ResourceDimension, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::
    AuthenticatedBrokerMethodOutcomeCaptureV1;

use crate::journal::broker_session_receiving::{
    StorageSessionGeometryRefusalV1, storage_retained_current_replay_demand_v1,
    storage_retained_traffic_reconstruction_demand_v1,
};
use crate::journal::{Journal, JournalError, ProtectedJournalPreopenReplayExtentV1};

use super::ResourceReservationErrorV1;

#[derive(Clone, Copy)]
pub(super) enum OutcomeReplayRosterV1 {
    InventoryTerminal,
    CreateSigning,
    BundleBeforeAndAfter,
}

impl OutcomeReplayRosterV1 {
    fn destinations(self) -> u64 {
        match self {
            Self::InventoryTerminal | Self::CreateSigning => 1,
            Self::BundleBeforeAndAfter => 2,
        }
    }
}

#[derive(Default)]
pub(super) struct OutcomeReplayReceivingOriginalsV1 {
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    resident_width: Option<Result<u64, JournalError>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    replay: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    prior_traffic: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    terminal: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    complete: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
}

impl OutcomeReplayReceivingOriginalsV1 {
    pub(super) fn captured_extent_v1(&self) -> Result<&ProtectedJournalPreopenReplayExtentV1, ResourceReservationErrorV1> {
        self.extent.as_ref().and_then(|r| r.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn capture_once(
        &mut self,
        journal: &Journal,
        roster: OutcomeReplayRosterV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.metadata.is_some() || self.admission.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let (metadata, limits) = journal.held_native_receiving_metadata_v1();
        self.metadata = Some(metadata);
        self.resident_width = Some(journal.held_materialized_encoding_bytes_v1());
        if let (Some(Ok(metadata)), Some(Ok(resident_width))) =
            (self.metadata.as_ref(), self.resident_width.as_ref())
        {
            // Both native reads consume the same held map. A damaged smaller
            // physical length cannot conceal its still-resident value bytes.
            let prefix = metadata.len().max(*resident_width);
            self.extent = Some(crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                limits,
                prefix,
            ));
        }
        if let Some(Ok(extent)) = self.extent.as_ref() {
            self.replay = Some(storage_retained_current_replay_demand_v1(extent));
            self.prior_traffic = Some(storage_retained_traffic_reconstruction_demand_v1(extent));
            self.terminal = Some((|| {
                let prefix = usize::try_from(extent.native_bytes)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?;
                AuthenticatedBrokerMethodOutcomeCaptureV1::dynamic_receiving_demand_v1(prefix)
                    .ok_or(ResourceReservationErrorV1::Conflict)
            })());
        }
        self.complete = Some((|| {
            let replay = self.replay.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let prior_traffic = self.prior_traffic.as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let terminal = self.terminal.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let one = replay.checked_add(prior_traffic)?.checked_add(terminal)?;
            let mut complete = ResourceVector::ZERO;
            for _ in 0..roster.destinations() {
                complete = complete.checked_add(one)?;
            }
            Ok(complete)
        })());
        self.demand_v1().map(|_| ())
    }

    pub(super) fn demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.complete.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn retain_admission_once(
        &mut self,
        admission: Result<(), ResourceReservationErrorV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.admission.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.admission = Some(admission);
        if matches!(self.admission, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        }
    }

    pub(super) fn require_admitted_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() || !matches!(self.admission, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(
            result: &Option<Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            result.as_ref()?.as_ref().err().map(|cause| cause as _)
        }

        cause(&self.metadata)
            .or_else(|| cause(&self.resident_width))
            .or_else(|| cause(&self.extent))
            .or_else(|| cause(&self.replay))
            .or_else(|| cause(&self.prior_traffic))
            .or_else(|| cause(&self.terminal))
            .or_else(|| cause(&self.complete))
            .or_else(|| cause(&self.admission))
    }

    pub(super) fn fixed_receiving_demand_v1()
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        // Resident fields are already in the actual worker/parent sizeof.
        // This adds only new sampler return/construction carriers and fixed
        // OS-error backing before the first actual fstat. Fixed Rust result
        // cells add no resident namespace entries.
        let bytes = std::mem::size_of::<(std::io::Result<std::fs::Metadata>, crate::journal::JournalLimits)>()
            .checked_add(std::mem::size_of::<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>())
            .and_then(|bytes| bytes.checked_add(6 * std::mem::size_of::<ResourceVector>()))
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO
            .with(ResourceDimension::MemoryBytes, u64::try_from(bytes)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?))
    }
}
