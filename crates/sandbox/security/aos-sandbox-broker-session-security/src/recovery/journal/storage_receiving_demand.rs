//! Bounds fixed Storage endpoint and hello materialization before cold opening.
//!
//! These are representation demands for the actual receiving owner. They do
//! not issue a resource grant, choose a floor, or authorize Session effects.
//! The selected caller reserves them before loading fixed endpoint custody or
//! decoding hello packets. Native opening, contacted wire bodies, main replay
//! and any selected physical sidecar have separate actual receiving stages.

use std::mem::size_of;

use aos_sandbox_broker_session_protocol::{
    hello_message::{BrokerClientHello, BrokerServerHello},
};
use aos_sandbox_model::{ResourceDimension as Dimension, ResourceVector};

use crate::BrokerSessionSecurityError;
use crate::handshake::{DormantAuthenticatedBrokerSessionV1, RetainedStorageColdOpenV1};
use crate::production_activation::ProductionBrokerSessionActivationV1;
use crate::recovery::ProtectedBrokerSessionFixedCustodyV1;

use super::{BrokerMainOpenV1, ProtectedBrokerSessionJournalV1};

/// Computes conservative fixed endpoint/hello demand for one actual flight.
///
/// Repeated feature/method entries and unknown fields each consume wire bytes.
/// The unknown-field cell also contains a nested-group owner; charging one
/// such cell plus an enum cell per wire byte covers the admitted schema's
/// carrier arrays. Twofold growth provision covers reached Vec capacities;
/// decoder limits and the service cgroup backstop allocator metadata and
/// parser/runtime overhead. This does not multiply unrelated method models
/// by the generic request or outcome packet ceiling.
///
/// # Errors
/// Returns the ordinary currentness projection if checked arithmetic overflows.
pub(super) fn fixed_security_demand() -> Result<ResourceVector, BrokerSessionSecurityError> {
    let refused = || BrokerSessionSecurityError::Currentness;
    let inline_bytes = size_of::<BrokerMainOpenV1>()
        .checked_add(size_of::<ProtectedBrokerSessionJournalV1>())
        .and_then(|bytes| bytes.checked_add(crate::production_activation::retained_storage_session_carrier_bytes_v1()?))
        .and_then(|bytes| bytes.checked_add(size_of::<RetainedStorageColdOpenV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<DormantAuthenticatedBrokerSessionV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ProtectedBrokerSessionFixedCustodyV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ProductionBrokerSessionActivationV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<BrokerClientHello>()))
        .and_then(|bytes| bytes.checked_add(size_of::<BrokerServerHello>()))
        .ok_or_else(refused)?;
    let (failure_bytes, failure_cells) =
        crate::handshake::storage_preparation_handshake_failure_obligations_v1()
            .ok_or_else(refused)?;
    let common = aos_sandbox_controller_domain::journal::broker_session_receiving::fixed_handshake_receiving_demand(
        aos_sandbox_controller_domain::journal::broker_session_receiving::StorageHandshakePrivateFootprintV1 {
            actual_inline_bytes: inline_bytes,
            actual_failure_bytes: failure_bytes,
            actual_failure_cells: failure_cells,
        },
    ).map_err(BrokerSessionSecurityError::from)?;
    let endpoint = crate::endpoint::endpoint_revalidation_footprint_v1()
        .and_then(|shape| shape.checked_demand_v1()).ok_or_else(refused)?;
    let initial = crate::handshake::StorageInitialSessionHandshakeV1::receiving_footprint_v1()
        .and_then(|shape| shape.checked_demand_v1()).ok_or_else(refused)?;
    let floor = super::floor_initial_capture_shape_v1(
        aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1::Storage,
    ).ok_or_else(refused)?;
    let floor_bytes = floor.inline_bytes.checked_add(floor.heap_bytes)
        .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>()))
        .ok_or_else(refused)?;
    let floor = ResourceVector::ZERO
        .with(Dimension::MemoryBytes, u64::try_from(floor_bytes).map_err(|_| refused())?)
        .with(Dimension::OpenFiles, u64::try_from(floor.open_files).map_err(|_| refused())?)
        .with(Dimension::MetadataEntries, u64::try_from(floor.metadata_cells).map_err(|_| refused())?);

    common.checked_add(endpoint)
        .and_then(|demand| demand.checked_add(initial))
        .and_then(|demand| demand.checked_add(floor))
        .map_err(|_| refused())
}

/// Prices the three actual HELLO records as one finite operation.
///
/// The genuine initial or retained Native producer consumes this shape before
/// publication send. It is separate from the fixed resident model/FD demand.
/// CPU remains under the same installed aggregate service rate; this framing
/// creates no helper task, mount, writable object, fetch or execution. A fresh
/// HELLO never authorizes resetting the original cold cutoff or Session head.
///
/// # Errors
/// Refuses unrepresentable checked wire geometry.
pub(super) fn handshake_flight_demand() -> Result<ResourceVector, BrokerSessionSecurityError> {
    aos_sandbox_controller_domain::journal::broker_session_receiving::handshake_flight_demand(
        aos_sandbox_controller_domain::journal::broker_session_receiving::StorageHandshakeEndpointV1::Broker,
    ).map_err(BrokerSessionSecurityError::from)
}
