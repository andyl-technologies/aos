//! Borrows every actual native supervisor incident and quarantined ledger.
//!
//! ```text
//! {schema:"source-private.native-supervisor-history/17",
//!  incidents_capacity,incidents:[complete_incident...],
//!  quarantines_capacity,quarantines:[complete_quarantine...]}
//! ```
//!
//! The actual service authenticates this concrete Rc against both erased
//! Connection and Blob supervisor fields before serialization. This view owns
//! only immutable loans and cannot reconcile, clear or retry a failed owner.

use super::*;
use crate::retained_metadata::MetadataObserver;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

pub(in crate::reference_packet::service) struct NativeSupervisorHistory<'a> {
    incidents: std::cell::Ref<'a, Vec<ConnectionIncident>>,
    blobs: std::cell::Ref<'a, Vec<BlobQuarantine>>,
}

impl Supervisor {
    pub(in crate::reference_packet::service) fn borrowed_settled_history_data(
        &self,
    ) -> Result<NativeSupervisorHistory<'_>, ProviderError> {
        let Self { incidents, blobs } = self;
        Ok(NativeSupervisorHistory {
            incidents: incidents
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("native17 supervisor incidents borrowed"))?,
            blobs: blobs.try_borrow().map_err(|_| {
                ProviderError::Conflict("native17 supervisor Blob quarantine borrowed")
            })?,
        })
    }

    pub(in crate::reference_packet::service) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let owner = self.borrowed_settled_history_data()?;
        observer.vector::<ConnectionIncident>(owner.incidents.capacity())?;
        for incident in &*owner.incidents {
            crate::connection::observe_settled_connection_incident_metadata_data(
                incident, observer,
            )?;
        }
        observer.vector::<BlobQuarantine>(owner.blobs.capacity())?;
        for quarantine in &*owner.blobs {
            quarantine.observe_settled_history_metadata_data(observer)?;
        }
        Ok(())
    }

    pub(in crate::reference_packet::service) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<NativeSupervisorHistory<'static>>()
            + size_of::<Result<NativeSupervisorHistory<'static>, ProviderError>>()
            + size_of::<std::cell::Ref<'static, Vec<ConnectionIncident>>>()
            + size_of::<std::cell::Ref<'static, Vec<BlobQuarantine>>>()
            + size_of::<IncidentRows<'static>>()
            + size_of::<QuarantineRows<'static>>()
            + size_of::<std::slice::Iter<'static, ConnectionIncident>>()
            + size_of::<std::slice::Iter<'static, BlobQuarantine>>()
            + size_of::<Option<&'static ConnectionIncident>>()
            + size_of::<Option<&'static BlobQuarantine>>()
            + size_of::<crate::connection::ConnectionIncidentHistoryData<'static>>()
            + BlobQuarantine::settled_history_counter_scratch_data()
            + size_of::<Result<(), ProviderError>>()
    }
}

struct IncidentRows<'a>(&'a [ConnectionIncident]);

impl Serialize for IncidentRows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for incident in self.0 {
            rows.serialize_element(
                &crate::connection::connection_incident_settled_history_data(incident),
            )?;
        }
        rows.end()
    }
}

struct QuarantineRows<'a>(&'a [BlobQuarantine]);

impl Serialize for QuarantineRows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for quarantine in self.0 {
            rows.serialize_element(
                &quarantine
                    .borrowed_settled_history_data()
                    .map_err(serde::ser::Error::custom)?,
            )?;
        }
        rows.end()
    }
}

impl Serialize for NativeSupervisorHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("NativeSupervisorHistory17", 5)?;
        state.serialize_field("schema", "source-private.native-supervisor-history/17")?;
        state.serialize_field("incidents_capacity", &self.incidents.capacity())?;
        state.serialize_field("incidents", &IncidentRows(&self.incidents))?;
        state.serialize_field("quarantines_capacity", &self.blobs.capacity())?;
        state.serialize_field("quarantines", &QuarantineRows(&self.blobs))?;
        state.end()
    }
}
