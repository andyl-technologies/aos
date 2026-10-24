//! Adds actual private Security carrier layouts to shared passive geometry.
//!
//! The existing Domain-owned geometry supplies the same schema/initialization,
//! outcome/replay and finite framing calculations to both genuine role payers.
//! Protected Session producers, private request state and actual sender custody
//! remain Security-owned; no role grant or native observation moves here.

use std::mem::size_of;

use aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use super::{BrokerSessionSecurityError, StoredProtocolHistoryV1};

pub(super) use aos_sandbox_controller_domain::journal::broker_session_receiving::{
    initialization_demand, operation_flight_demand, outcome_demand, replay_demand, schema_demand,
};

// The existing Security producer model has exactly the canonical passive
// owner's fields. Geometry uses that shared model; this backstop rejects a
// future layout change before it could silently underprice the private wrapper.
const _: () = assert!(size_of::<StoredProtocolHistoryV1>() ==
    size_of::<aos_sandbox_protocol::authenticated_session::stored_history::StoredBrokerSessionHistoryV1>());

impl From<aos_sandbox_controller_domain::journal::broker_session_receiving::StorageSessionGeometryRefusalV1>
    for BrokerSessionSecurityError
{
    fn from(_: aos_sandbox_controller_domain::journal::broker_session_receiving::StorageSessionGeometryRefusalV1) -> Self {
        Self::Currentness
    }
}

/// Adds the actual private retained-send layout to shared request geometry.
///
/// # Errors
/// Preserves the original fixed currentness refusal for geometry overflow.
pub(super) fn request_demand(
    extent: &ProtectedJournalPreopenReplayExtentV1,
) -> Result<ResourceVector, BrokerSessionSecurityError> {
    let (bytes, cells) = crate::handshake::StorageResponseSendAttemptV1::retained_cycle_obligations_v1()
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    aos_sandbox_controller_domain::journal::broker_session_receiving::request_demand(extent, bytes, cells)
        .map_err(Into::into)
}

/// Prices current held-history replay plus one reached request decoder lane.
///
/// The continuously borrowed Native guard supplies the actual current file
/// extent. The existing schema recipe covers full checkpoint/signed outer
/// history replay, including retired-predecessor qualification. Its original
/// domain semantics are preserved by the exact terminal head and are not
/// decoded again. StorageApply's reached portable metadata is a later debit
/// after canonical outer authentication and before semantic body admission.
///
/// # Errors
/// Refuses unrepresentable demand or an invalid actual extent.
pub(super) fn retained_request_demand(
    extent: &ProtectedJournalPreopenReplayExtentV1,
) -> Result<ResourceVector, BrokerSessionSecurityError> {
    let inline = u64::try_from(size_of::<
        crate::handshake::storage_lifecycle_request::StorageLifecycleRequestOriginalV1,
    >()).map_err(|_| BrokerSessionSecurityError::Currentness)?;
    schema_demand(extent)?.checked_add(request_demand(extent)?)
        .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, inline)))
        .map_err(|_| BrokerSessionSecurityError::Currentness)
}
