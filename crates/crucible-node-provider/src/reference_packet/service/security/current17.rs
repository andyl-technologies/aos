//! Preserves the actual reconstruction-only empty supervisor bank allocations.

use super::*;
use crate::protocol_snapshot::owned11::typed::{Fields, Ledger, invalid};
use crate::protocol_snapshot::restored_settled17::current_import17::Import17;
use crate::retained_metadata::{MetadataObserver, records::MetadataRecordKind};
use serde::{Serialize, Serializer};
use std::mem::{align_of, size_of};

// These banks are constructed only by reconstruct_empty_into and have no
// population mutator. Their spare allocations remain independent owners.
pub(crate) struct EmptyHistoricalIncident17([u8; size_of::<ConnectionIncident>()]);
pub(crate) struct EmptyHistoricalQuarantine17([u8; size_of::<BlobQuarantine>()]);
pub(crate) struct HistoricalNativeSupervisorBanksCurrent17 {
    pub(crate) incidents: Vec<EmptyHistoricalIncident17>,
    pub(crate) blobs: Vec<EmptyHistoricalQuarantine17>,
}
impl Import17 for HistoricalNativeSupervisorBanks {
    type Data = HistoricalNativeSupervisorBanksCurrent17;
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if !self.incidents.is_empty() || !self.blobs.is_empty() {
            return Err(serde::ser::Error::custom(
                "reconstruction-only historical supervisor bank populated",
            ));
        }
        (self.incidents.capacity(), self.blobs.capacity()).serialize(s)
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, crate::ProviderError> {
        let mut f = Fields::array(input)?;
        let incidents = l
            .read::<usize>(f.next()?.ok_or_else(invalid)?, true)?
            .ok_or_else(invalid)?;
        let blobs = l
            .read::<usize>(f.next()?.ok_or_else(invalid)?, true)?
            .ok_or_else(invalid)?;
        f.finish()?;
        if l.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<ConnectionIncident>(),
            align_of::<ConnectionIncident>(),
        )? != incidents
            || l.row_aligned(
                MetadataRecordKind::Vector,
                size_of::<BlobQuarantine>(),
                align_of::<BlobQuarantine>(),
            )? != blobs
        {
            return Err(invalid());
        }
        l.native17_target_vector_data::<EmptyHistoricalIncident17>(incidents)?;
        l.native17_target_vector_data::<EmptyHistoricalQuarantine17>(blobs)?;
        if !build {
            return Ok(None);
        }
        let mut incident_bank = Vec::new();
        let mut blob_bank = Vec::new();
        incident_bank
            .try_reserve_exact(incidents)
            .map_err(|_| invalid())?;
        blob_bank.try_reserve_exact(blobs).map_err(|_| invalid())?;
        if incident_bank.capacity() != incidents || blob_bank.capacity() != blobs {
            return Err(invalid());
        }
        Ok(Some(HistoricalNativeSupervisorBanksCurrent17 {
            incidents: incident_bank,
            blobs: blob_bank,
        }))
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), crate::ProviderError> {
        self.observe_historical_retained_metadata(o)
    }
}

/// Names the two actual empty bank headers and inert output header.
pub(crate) fn counter_scratch_data() -> usize {
    size_of::<HistoricalNativeSupervisorBanks>()
        + size_of::<HistoricalNativeSupervisorBanksCurrent17>()
        + size_of::<Result<Option<HistoricalNativeSupervisorBanksCurrent17>, crate::ProviderError>>(
        )
}

impl HistoricalNativeSupervisorBanks {
    /// Names this actual imported owner and its current17 output layout.
    pub(crate) fn current_import17_counter_scratch_data() -> usize {
        counter_scratch_data()
    }
}
