//! Supplies the actual compiled private headers to shared query arithmetic.

use super::*;

pub(super) const FIXED: shared::ReportQueryFixedLayoutData = shared::ReportQueryFixedLayoutData {
    fresh_query_bytes: size_of::<PacketNativeFreshRestoreAllocationQuery>(),
    envelope_bytes: size_of::<Envelope>(),
    connection_incident_bytes: size_of::<ConnectionIncident>(),
    request_body_bytes: size_of::<RequestBody>(),
    observe_request_bytes: size_of::<crate::bodies::ObserveRequest>(),
    correlation_key_value_bytes: size_of::<Id>() + size_of::<Envelope>(),
    correlation_entry_alignment: {
        let key = align_of::<Id>();
        let value = align_of::<Envelope>();
        if key > value { key } else { value }
    },
};
