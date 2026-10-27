//! Owns one same-F Storage-to-Host native opening and independent service post.
//!
//! The common selected Client driver performs endpoint, connect, peer, HELLO,
//! poll and cold work exactly once. This closed purpose supplies the genuine
//! Storage lifecycle payer and immutable current request horizon. Every partial
//! native owner stays resident until the enclosing authenticated operation's
//! actual positive successor disposition.

use super::*;
use super::selected_client_open::{SelectedClientCaptureV1, SelectedClientReceivingV1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

#[derive(Clone, Copy)]
enum Failure { Arm, Demand, Payment, Capture, Coordinates, Post, Deadline }

pub(crate) struct StorageHostSessionOpenV1 {
    capture: SelectedClientCaptureV1,
    demand: Option<Result<ResourceVector, aos_sandbox_controller_domain::journal::broker_session_receiving::StorageSessionGeometryRefusalV1>>,
    arm: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    result: Option<Result<(), super::controller_initial::ControllerInitialClientClosedV1>>,
    post: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    deadline: Option<Result<(), super::controller_initial::ControllerInitialClientClosedV1>>,
    first: Option<Failure>,
    taken: bool,
    cutoff: u64,
}

impl StorageHostSessionOpenV1 {
    pub(crate) fn new(cutoff: u64) -> Self {
        Self { capture: SelectedClientCaptureV1::storage_host(OriginalBrokerColdDeadlineV1::storage_accept(cutoff)),
            demand: None, arm: None, payment: None, result: None,
            post: None, deadline: None, first: None, taken: false, cutoff }
    }

    fn receiving_demand_v1() -> Result<ResourceVector, aos_sandbox_controller_domain::journal::broker_session_receiving::StorageSessionGeometryRefusalV1> {
        use aos_sandbox_controller_domain::journal::broker_session_receiving::{self as geometry, StorageSessionGeometryRefusalV1 as Refused};
        let (failure, _) = storage_preparation_handshake_failure_obligations_v1().ok_or(Refused)?;
        let hello = CLIENT_HELLO_MAXIMUM_BYTES.checked_add(SERVER_HELLO_MAXIMUM_BYTES).ok_or(Refused)?;
        let checkpoint = HistoricalSessionCheckpointConstructionCaptureV1::receiving_nonprojection_heap_bytes_v1(hello)
            .ok_or(Refused)?.checked_add(HistoricalSessionCheckpointConstructionCaptureV1::construction_bytes_v1()).ok_or(Refused)?;
        let process = storage_process_evidence_footprint_v1().ok_or(Refused)?;
        let memory = process.inline_bytes.checked_add(process.heap_bytes)
            .and_then(|bytes| bytes.checked_add(failure)).and_then(|bytes| bytes.checked_add(checkpoint)).ok_or(Refused)?;
        let demand = geometry::fixed_controller_client_handshake_receiving_demand(geometry::StorageHandshakePrivateFootprintV1 {
            actual_inline_bytes: std::mem::size_of::<Self>().checked_mul(2).ok_or(Refused)?,
            actual_failure_bytes: memory,
            // Result, parser and carrier fields are Memory, never namespaces.
            actual_failure_cells: 0,
        })?.with(D::MetadataEntries, 0);
        let process_files = u64::try_from(process.file_descriptors).map_err(|_| Refused)?;
        let client = u64::try_from(CLIENT_HELLO_MAXIMUM_BYTES).map_err(|_| Refused)?;
        let wire = u64::try_from(hello.checked_add(BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES).ok_or(Refused)?)
            .map_err(|_| Refused)?;
        // The closed connection observes run/aos/sandbox-host/storage.sock
        // (four additional rooted names) and at most three actual peer PID/stat
        // pairs (six names). Its own custody/proc names are paid by the endpoint.
        demand.checked_add(ResourceVector::ZERO.with(D::OpenFiles, process_files)
            .with(D::MetadataEntries, 10).with(D::NetworkBytes, wire).with(D::OutputBytes, client))
            .map_err(|_| Refused)
    }

    pub(crate) fn open_once(&mut self, receiving: &mut crate::recovery::StorageHostClientReceivingV1<'_, '_, '_>,
        flight: &mut output_registration_continuation::OriginalOutputClientFlightV1) {
        if self.arm.is_some() || self.first.is_some() || self.taken { return; }
        self.arm = Some(receiving.lifecycle.arm_operation_observation_post_v1(receiving.session, receiving.socket));
        if !matches!(self.arm, Some(Ok(()))) { self.first = Some(Failure::Arm); return; }
        self.open_inner_v1(receiving, flight);
        // This direct owed post runs after every reached financial, endpoint,
        // transport, parser, protected or cold refusal, with all originals held.
        self.post = Some(receiving.lifecycle.finish_operation_observation_post_v1(receiving.session, receiving.socket));
        if !matches!(self.post, Some(Ok(()))) { self.first.get_or_insert(Failure::Post); }
        if self.first.is_none() {
            self.deadline = Some(self.capture.deadline_v1().map(|_| ()));
            if !matches!(self.deadline, Some(Ok(()))) { self.first = Some(Failure::Deadline); }
        }
    }

    fn open_inner_v1(&mut self, receiving: &mut crate::recovery::StorageHostClientReceivingV1<'_, '_, '_>,
        flight: &mut output_registration_continuation::OriginalOutputClientFlightV1) {
        self.demand = Some(Self::receiving_demand_v1());
        let Some(Ok(demand)) = self.demand.as_ref() else { self.first = Some(Failure::Demand); return; };
        self.payment = Some(receiving.lifecycle.reserve_domain_additional_v1(receiving.session, receiving.socket, *demand));
        if !matches!(self.payment, Some(Ok(()))) { self.first = Some(Failure::Payment); return; }
        self.result = Some(self.capture.drive_once(SelectedClientReceivingV1::StorageHost(receiving)));
        if !matches!(self.result, Some(Ok(()))) { self.first = Some(Failure::Capture); return; }
        let Some(Ok(session)) = self.capture.completed.as_mut() else { std::process::abort(); };
        session.park_output_client_coordinates_v1(BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT, self.cutoff, flight);
        if !matches!(flight.coordinates, Some(Ok(_))) { self.first = Some(Failure::Coordinates); return; }
        if flight.select_storage_host_once_v1().is_err() { self.first = Some(Failure::Coordinates); }
    }

    pub(crate) fn take_completed_v1(&mut self) -> Option<DormantAuthenticatedBrokerSessionV1> {
        if self.taken || self.first.is_some() || !matches!(self.post, Some(Ok(())))
            || !matches!(self.deadline, Some(Ok(()))) { return None; }
        let Some(Ok(session)) = self.capture.completed.take() else { return None; };
        self.taken = true;
        Some(session)
    }

    pub(crate) fn failure<'cause>(&'cause self, flight: &'cause output_registration_continuation::OriginalOutputClientFlightV1)
        -> Option<&'cause (dyn std::error::Error + 'static)> {
        fn native(slot: &Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            Failure::Arm => native(&self.arm),
            Failure::Demand => self.demand.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Payment => native(&self.payment),
            Failure::Capture | Failure::Deadline => self.capture.failure(),
            Failure::Coordinates => flight.coordinates.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Post => native(&self.post),
        }
    }
}
