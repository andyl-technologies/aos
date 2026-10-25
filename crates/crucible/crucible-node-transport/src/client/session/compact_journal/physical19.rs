//! Preserves independent journal and content ceilings in compact custody DATA.
//!
//! ```text
//! ["source-private.compact-custody/19", capacity_format,
//!  [maximum_requests,maximum_journal_bytes,retained_journal_bytes,maximum_bank_bytes,
//!   controller_originals,provider_originals,content8,pending,unexpected], rows]
//! ```
//!
//! The complete field and capacity grammars are shared with physical18. Only
//! this explicit edition permits the journal ceiling to differ from content8's
//! own byte ceiling. Neither counter is renewed or derived from the other.
//! This custody DATA edition does not select a native lifecycle or supply a
//! conversion from historical data into live custody or Source authority.

use super::CompactClientCustody;
use super::physical18::{Edition, HistoricalCompactCustody18};
use crate::ProviderError;
use crate::retained_metadata::records::MetadataRecordBank;
use serde::Serialize;

/// Restricts the same complete history populations as physical18.
///
/// These independent input, capacity, JSON and content restrictions do not
/// equate journal and content ceilings or grant allocation permission.
pub type CompactCustody19Limits = super::physical18::CompactCustody18Limits;

impl CompactClientCustody {
    /// Records and borrows complete custody with independent byte ceilings.
    ///
    /// The caller preowns and funds `records`, including failed capture. The
    /// immutable view preserves both ceilings, consumed journal/content credit,
    /// complete banks, content aliases and independent failure owners. Walking
    /// never grows the record bank. Output, controls and temporary work require
    /// separate funding.
    ///
    /// # Errors
    /// Refuses unsupported banks or retained frame variants, census overflow,
    /// or insufficient actual capacity-record storage.
    pub fn physical_custody19_data<'a>(
        &'a self,
        records: &'a mut MetadataRecordBank,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.physical_custody_data(records, Edition::Independent19)
    }
}

/// Owns complete independent-ceiling history without a live installation API.
///
/// The physical18 field decoder and defining census remain shared, while each
/// public reader accepts only its own exact edition. Decoding changes neither
/// quota and authenticates no request identity, receipt or native meaning.
pub struct HistoricalCompactCustody19 {
    history: HistoricalCompactCustody18,
}

impl HistoricalCompactCustody19 {
    /// Reconstructs complete historical DATA under independent restrictions.
    ///
    /// The caller separately funds input, final and failed-prefix owners,
    /// capacity/tree/control-block geometry and preflight's one temporary bank.
    /// No conversion to a mutable SDK owner or Source authority is exposed.
    ///
    /// # Errors
    /// Refuses another edition, incomplete/extra fields, mismatched capacity
    /// rows, exhausted restrictions, invalid banks or content aliases, or failed
    /// exact allocation.
    pub fn decode(input: &[u8], limits: CompactCustody19Limits) -> Result<Self, ProviderError> {
        HistoricalCompactCustody18::decode_edition(input, limits, Edition::Independent19)
            .map(|history| Self { history })
    }

    /// Reports request, journal-byte, consumed-byte and bank ceilings as DATA.
    pub fn journal_limits_data(&self) -> [usize; 4] {
        self.history.journal_limits_data()
    }

    /// Borrows a complete original from its explicit endpoint namespace.
    pub fn original_data(
        &self,
        origin: crate::envelope::RequestOrigin,
        id: &crucible_node_format::Id,
    ) -> Option<&super::CompactClientOriginal> {
        self.history.original_data(origin, id)
    }

    /// Borrows complete content8 DATA without a mutable store handle.
    pub fn content_data(&self) -> &crate::client::ClientContent {
        self.history.content_data()
    }

    /// Borrows a failed received original and its original namespace.
    pub fn pending_envelope_data(
        &self,
    ) -> Option<(crate::envelope::RequestOrigin, &crate::envelope::Envelope)> {
        self.history.pending_envelope_data()
    }

    /// Borrows the independently retained envelope and typed failure body.
    pub fn unexpected_frame_data(&self) -> Option<&crate::connection::ReceivedFrame> {
        self.history.unexpected_frame_data()
    }

    /// Records and borrows the same complete physical19 history.
    ///
    /// # Errors
    /// Refuses an insufficient record bank or unsupported defining census.
    pub fn physical_data<'a>(
        &'a self,
        records: &'a mut MetadataRecordBank,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.history.custody.physical_custody19_data(records)
    }

    /// Counts all independent owners through the original defining census.
    ///
    /// # Errors
    /// Refuses checked overflow or unsupported retained metadata.
    pub fn retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        self.history.retained_metadata_facts()
    }
}

#[cfg(test)]
mod tests;
