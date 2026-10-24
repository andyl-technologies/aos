//! Reconstructs source-installed supervisor data without a live callback object.

use super::{
    state::{next, tag},
    typed::{Fields, HistoricalType, Ledger, invalid, plain_string},
};
use crate::{
    ProviderError,
    connection::{ConnectionFailure, ConnectionIncident},
    envelope::Envelope,
    retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind},
};
use crucible_node_format::Id;

/// Retains the entire original supervisor state as inert historical data.
pub struct HistoricalOriginalSupervisor {
    /// Retains the measured original concrete supervisor payload layout.
    pub owner_layout: usize,
    /// Retains the historical creator PID without enrolling a process.
    pub creator: u32,
    /// Retains the actual inspection phase at the captured borrowed cut.
    pub inspection_in_progress: bool,
    /// Retains the original quarantine callback phase, required quiescent here.
    pub callback_in_progress: bool,
    /// Retains every original incident and the actual preallocated Vec capacity.
    pub incidents: Vec<ConnectionIncident>,
}

impl HistoricalType for ConnectionIncident {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let session = ledger.read::<Id>(next(&mut fields)?, build)?;
        let incarnation = ledger.read::<Id>(next(&mut fields)?, build)?;
        let connection = ledger.read::<Id>(next(&mut fields)?, build)?;
        let failure = match plain_string(next(&mut fields)?)? {
            "read" => ConnectionFailure::Read,
            "write" => ConnectionFailure::Write,
            "protocol" => ConnectionFailure::Protocol,
            "authority" => ConnectionFailure::Authority,
            "closed" => ConnectionFailure::Closed,
            _ => return Err(invalid()),
        };
        let transport_fenced = ledger.read::<bool>(next(&mut fields)?, build)?;
        let outgoing = ledger.read::<Vec<Envelope>>(next(&mut fields)?, build)?;
        let incoming = ledger.read::<Vec<Envelope>>(next(&mut fields)?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            session: session.ok_or_else(invalid)?,
            incarnation: incarnation.ok_or_else(invalid)?,
            connection: connection.ok_or_else(invalid)?,
            failure,
            transport_fenced: transport_fenced.ok_or_else(invalid)?,
            outgoing: outgoing.ok_or_else(invalid)?,
            incoming: incoming.ok_or_else(invalid)?,
        }))
    }
}

impl HistoricalType for HistoricalOriginalSupervisor {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let start = ledger.rows.encoded_position();
        let owner_layout = ledger.row(MetadataRecordKind::Shared, 1)?;
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.original-supervisor/11")?;
        let creator = ledger.read::<u32>(next(&mut fields)?, build)?;
        tag(&mut fields, "same-original-thread")?;
        let inspection = next(&mut fields)?;
        let callback = next(&mut fields)?;
        if inspection != b"true" || callback != b"false" {
            return Err(invalid());
        }
        let mut bank = Fields::array(next(&mut fields)?)?;
        let original_capacity = ledger
            .read::<usize>(next(&mut bank)?, true)?
            .ok_or_else(invalid)?;
        let incident_bytes = next(&mut bank)?;
        bank.finish()?;
        let before = ledger.rows.clone();
        let capacity = ledger.row(
            MetadataRecordKind::Vector,
            std::mem::size_of::<ConnectionIncident>(),
        )?;
        if capacity != original_capacity {
            return Err(invalid());
        }
        ledger.rows = before;
        let incidents = ledger.read::<Vec<ConnectionIncident>>(incident_bytes, build)?;
        fields.finish()?;
        let capacity_rows = ledger.rows.encoded_between(start)?;
        ledger.shared(
            MetadataSharedKind::HostSupervisor,
            owner_layout,
            input,
            capacity_rows,
        )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            owner_layout,
            creator: creator.ok_or_else(invalid)?,
            inspection_in_progress: true,
            callback_in_progress: false,
            incidents: incidents.ok_or_else(invalid)?,
        }))
    }
}

// The closed owning walk fails to compile if a historical field is added.
super::retained_storage::fields!(
    HistoricalOriginalSupervisor,
    owner_layout,
    creator,
    inspection_in_progress,
    callback_in_progress,
    incidents
);
