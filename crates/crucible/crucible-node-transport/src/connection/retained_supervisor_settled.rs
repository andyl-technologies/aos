//! Borrows complete retained supervisor data, including a failed pending incident.
//!
//! ```text
//! {schema, phase, incidents:[...actual incidents...], pending:null|incident}
//! ```
//!
//! Unlike the old guarded callback view, this inert DATA view does not require
//! idle flags or an empty pending slot. Original Source/currentness/capture
//! authority and actual same-parent association remain separate requirements.

use super::*;
use serde::{
    Serialize,
    ser::{SerializeSeq, SerializeStruct},
};
use std::cell::Ref;
use std::mem::size_of;

/// Borrows the same concrete incident and pending banks without a live decoder.
pub struct RetainedSupervisorHistoricalData<'a> {
    owner: &'a OriginalRetainedSupervisor,
    incidents: Ref<'a, Vec<ConnectionIncident>>,
    pending: Ref<'a, Option<ConnectionIncident>>,
}

pub(crate) struct ConnectionIncidentHistoryData<'a>(&'a ConnectionIncident);
struct IncidentsData<'a>(&'a [ConnectionIncident]);

impl OriginalRetainedSupervisor {
    /// Borrows every initialized incident and the independent pending owner.
    ///
    /// This never flips callback/inspection flags or invokes an erased callback.
    /// It remains available after a completed callback unwinds or fencing fails.
    ///
    /// # Errors
    /// Refuses an actual conflicting loan of either retained bank.
    pub fn borrowed_settled_history_data(
        &self,
    ) -> Result<RetainedSupervisorHistoricalData<'_>, ProviderError> {
        let incidents = self
            .supervisor
            .incidents
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("historical supervisor incidents borrowed"))?;
        let pending = self
            .supervisor
            .pending
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("historical supervisor pending borrowed"))?;
        Ok(RetainedSupervisorHistoricalData {
            owner: self,
            incidents,
            pending,
        })
    }

    pub(crate) fn authenticate_settled_history_parent_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        if !std::ptr::addr_eq(
            Rc::as_ptr(&self.supervisor),
            Rc::as_ptr(&connection.supervisor),
        ) {
            return Err(ProviderError::Correlation(
                "historical retained supervisor parent differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let value = self.borrowed_settled_history_data()?;
        observer.shared_original(MetadataSharedKind::HostSupervisor, self.supervisor.as_ref())?;
        observer.vector::<ConnectionIncident>(value.incidents.capacity())?;
        for incident in value.incidents.iter() {
            observe_incident(incident, observer)?;
        }
        if let Some(pending) = value.pending.as_ref() {
            observe_incident(pending, observer)?;
        }
        Ok(())
    }

    /// Names the exact concrete owner, both bank loans and borrowed projection.
    pub fn settled_history_counter_scratch_data() -> usize {
        size_of::<RetainedSupervisorHistoricalData<'static>>()
            + size_of::<Result<RetainedSupervisorHistoricalData<'static>, ProviderError>>()
            + size_of::<Ref<'static, Vec<ConnectionIncident>>>()
            + size_of::<Ref<'static, Option<ConnectionIncident>>>()
            + size_of::<Result<Ref<'static, Vec<ConnectionIncident>>, std::cell::BorrowError>>()
            + size_of::<Result<Ref<'static, Vec<ConnectionIncident>>, ProviderError>>()
            + size_of::<Result<Ref<'static, Option<ConnectionIncident>>, std::cell::BorrowError>>()
            + size_of::<Result<Ref<'static, Option<ConnectionIncident>>, ProviderError>>()
            + size_of::<ConnectionIncidentHistoryData<'static>>()
            + size_of::<Option<ConnectionIncidentHistoryData<'static>>>()
            + size_of::<IncidentsData<'static>>()
            + size_of::<&Self>()
            + size_of::<&ConnectionIncident>()
            + size_of::<Option<&ConnectionIncident>>()
            + size_of::<std::slice::Iter<'static, ConnectionIncident>>()
            + size_of::<(
                &Id,
                &Id,
                &Id,
                &ConnectionFailure,
                &bool,
                &Vec<Envelope>,
                &Vec<Envelope>,
            )>()
            + size_of::<(
                &RefCell<Vec<ConnectionIncident>>,
                &OriginalSupervisorState,
                &RefCell<Option<ConnectionIncident>>,
            )>()
            + size_of::<&Rc<RetainedSupervisor>>()
            + size_of::<&Rc<dyn ConnectionSupervisor>>()
            + size_of::<&Rc<crate::protocol_snapshot::ProtocolCaptureOwner>>()
            + size_of::<(&str, &str)>()
            + size_of::<bool>()
            + size_of::<usize>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<&mut MetadataObserver<'static>>()
            + OriginalSupervisorState::settled_history_counter_scratch_data()
    }
}

pub(crate) fn observe_incident(
    value: &ConnectionIncident,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let ConnectionIncident {
        session,
        incarnation,
        connection,
        failure: _,
        transport_fenced,
        outgoing,
        incoming,
    } = value;
    observer.observe(session)?;
    observer.observe(incarnation)?;
    observer.observe(connection)?;
    observer.observe(transport_fenced)?;
    observer.observe(outgoing)?;
    observer.observe(incoming)
}

impl Serialize for RetainedSupervisorHistoricalData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("RetainedSupervisorHistory", 4)?;
        fields.serialize_field(
            "schema",
            "source-private.retained-supervisor-restored-settled/17",
        )?;
        fields.serialize_field(
            "phase",
            &self.owner.supervisor.state.borrowed_settled_history_data(),
        )?;
        fields.serialize_field("incidents", &IncidentsData(&self.incidents))?;
        fields.serialize_field(
            "pending",
            &self.pending.as_ref().map(ConnectionIncidentHistoryData),
        )?;
        fields.end()
    }
}

impl Serialize for IncidentsData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut values = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            values.serialize_element(&ConnectionIncidentHistoryData(value))?;
        }
        values.end()
    }
}

impl Serialize for ConnectionIncidentHistoryData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ConnectionIncident {
            session,
            incarnation,
            connection,
            failure,
            transport_fenced,
            outgoing,
            incoming,
        } = self.0;
        let mut fields = serializer.serialize_struct("ConnectionIncidentHistory", 7)?;
        fields.serialize_field("session", session)?;
        fields.serialize_field("incarnation", incarnation)?;
        fields.serialize_field("connection", connection)?;
        fields.serialize_field(
            "failure",
            &match failure {
                ConnectionFailure::Read => "read",
                ConnectionFailure::Write => "write",
                ConnectionFailure::Protocol => "protocol",
                ConnectionFailure::Authority => "authority",
                ConnectionFailure::Closed => "closed",
            },
        )?;
        fields.serialize_field("transport_fenced", transport_fenced)?;
        fields.serialize_field("outgoing", outgoing)?;
        fields.serialize_field("incoming", incoming)?;
        fields.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_supervisor_history_keeps_pending_owner_after_real_callback_refusal() {
        let (operational, retained) = OriginalRetainedSupervisor::reserve().unwrap();
        retained.supervisor.state.inspection_in_progress.set(true);
        let outgoing = Vec::with_capacity(7);
        let capacity = outgoing.capacity();
        let incident = ConnectionIncident {
            session: Id::new("historical-session").unwrap(),
            incarnation: Id::new("historical-incarnation").unwrap(),
            connection: Id::new("historical-connection").unwrap(),
            failure: ConnectionFailure::Write,
            transport_fenced: false,
            outgoing,
            incoming: Vec::new(),
        };
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            operational.quarantine(incident)
        }));
        assert!(failed.is_err());

        let value = retained.borrowed_settled_history_data().unwrap();
        let encoded = serde_json::to_value(&value).unwrap();
        assert_eq!(encoded["pending"]["failure"], "write");
        assert_eq!(encoded["pending"]["session"], "historical-session");
        assert_eq!(encoded["phase"][3], true);
        assert!(encoded["incidents"].as_array().unwrap().is_empty());
        let mut observer = MetadataObserver::new();
        retained
            .observe_settled_history_metadata_data(&mut observer)
            .unwrap();
        let facts = observer.finish();
        assert!(facts.vector_capacity_bytes >= capacity * size_of::<Envelope>());
        assert!(value.pending.is_some());
        assert!(retained.original_retained_metadata_facts().is_err());
    }
}

/// Borrows every actual field of an inert incident without invoking a supervisor.
pub(crate) fn connection_incident_settled_history_data(
    value: &ConnectionIncident,
) -> ConnectionIncidentHistoryData<'_> {
    ConnectionIncidentHistoryData(value)
}

pub(crate) fn observe_settled_connection_incident_metadata_data(
    value: &ConnectionIncident,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    observe_incident(value, observer)
}
