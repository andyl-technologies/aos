//! Owns initial fixed Storage acquisition before the same retained HELLO reducer.
//!
//! Acceptance, partial endpoint/pidfd/files, actual socket, publication building
//! and raw-reducer failure all stay on this one selected original. The genuine
//! receiving loan pays fixed resident capture before acceptance, then consumes
//! HELLO traffic only after an actual socket exists. There is no retry factory.

use super::*;
use super::storage_broker_start::StorageBrokerHandshakeStartV1;
use crate::production_activation::StorageRetainedSocketAcceptanceV1;
use aos_sandbox::{StoragePrepareReceivingLoanV1, StorageReceivingClosedV1};
use aos_sandbox_core::ResourceVector;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Fresh,
    Checking,
    Ready,
    HandedOff,
    Failed,
}

#[derive(Clone, Copy)]
enum Failure {
    Deadline,
    Demand,
    Wire,
    Fixed,
    Launch,
    Start,
    Native(usize),
    Socket(usize),
    Preparation(usize),
    Handshake,
}

pub(crate) struct StorageInitialSessionHandshakeV1 {
    _acceptance: StorageRetainedSocketAcceptanceV1,
    socket: Option<SeqpacketSocket>,
    lower: crate::endpoint::ProtectedBrokerSessionBrokerOpeningV1,
    fixed: Option<Result<ProtectedBrokerSessionFixedCustodyV1, BrokerSessionSecurityError>>,
    launch: Option<Result<(), BrokerSessionSecurityError>>,
    start: Option<StorageBrokerHandshakeStartV1>,
    native: [Option<Result<(), StorageReceivingClosedV1>>; 3],
    preparation: [Option<Result<(), StorageReceivingClosedV1>>; 3],
    socket_post: [Option<Result<(), StorageReceivingClosedV1>>; 3],
    wire_demand: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    wire: Option<Result<(), StorageReceivingClosedV1>>,
    deadline: OriginalBrokerColdDeadlineV1,
    cutoff: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    poll: Option<Result<usize, rustix::io::Errno>>,
    completed: Option<Result<crate::DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1>>,
    first: Option<Failure>,
    phase: Phase,
}

impl StorageInitialSessionHandshakeV1 {
    /// Bounds the actual additional initial acquisition carriers before entry.
    ///
    /// Activation's existing private sizeof term counts the inline owner once.
    /// Each named owner supplies its complete bound. This conservative sum
    /// credits no earlier positive stage disposal against later work and infers
    /// no native/heap coverage from the shared recipe's generic carriers.
    pub(crate) fn receiving_footprint_v1() -> Option<aos_sandbox::CreateStorageEndpointRevalidationShapeDataV1> {
        use aos_sandbox_linux::self_execution::{
            RetainedSelfExecutionGuard as NativeGuard,
            SelfExecutionObservationV1 as NativeObservation,
        };
        use crate::protected_files::{
            ProtectedEndpointFilesOpeningV1 as FilesOpening,
            ProtectedEndpointFilesRevalidationV1 as FilesPost,
        };

        let heap_bytes = FilesOpening::secret_heap_bytes_v1()
            .checked_add(FilesPost::secret_heap_bytes_v1())?
            .checked_add(NativeGuard::selected_capture_heap_bytes_v1())?
            .checked_add(NativeObservation::receiving_heap_bytes_v1())?;
        let file_descriptors = FilesOpening::opened_file_bound_v1()
            .checked_add(FilesPost::opened_file_bound_v1())?
            .checked_add(NativeGuard::selected_capture_opened_file_bound_v1())?
            .checked_add(NativeObservation::opened_file_bound_v1())?;
        let metadata_cells = FilesOpening::metadata_cell_bound_v1()
            .checked_add(FilesPost::metadata_cell_bound_v1())?
            .checked_add(NativeGuard::selected_capture_metadata_cell_bound_v1())?
            .checked_add(NativeObservation::metadata_cell_bound_v1())?;
        let process = super::process_evidence::receiving_failure_footprint_v1()?;
        Some(aos_sandbox::CreateStorageEndpointRevalidationShapeDataV1 {
            inline_bytes: process.inline_bytes,
            heap_bytes: heap_bytes.checked_add(process.heap_bytes)?,
            file_descriptors: file_descriptors.checked_add(process.file_descriptors)?,
            metadata_cells: metadata_cells.checked_add(process.metadata_cells)?,
        })
    }

    pub(crate) fn new(
        socket: SeqpacketSocket,
        acceptance: StorageRetainedSocketAcceptanceV1,
        deadline: OriginalBrokerColdDeadlineV1,
    ) -> Self {
        Self {
            _acceptance: acceptance,
            socket: Some(socket),
            lower: crate::endpoint::ProtectedBrokerSessionBrokerOpeningV1::new(),
            fixed: None,
            launch: None,
            start: None,
            native: [None, None, None],
            preparation: [None, None, None],
            socket_post: [None, None, None],
            wire_demand: None,
            wire: None,
            deadline,
            cutoff: None,
            poll: None,
            completed: None,
            first: None,
            phase: Phase::Fresh,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Deadline => self.cutoff.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            Failure::Demand => self.wire_demand.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            Failure::Wire => self.wire.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            Failure::Fixed => self.lower.failure().or_else(|| self.fixed.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error)),
            Failure::Launch => self.launch.as_ref()?.as_ref().err().map(|cause| {
                self.fixed.as_ref().and_then(|result| result.as_ref().ok())
                    .and_then(|custody| custody.retained_revalidation_failure_for(cause))
                    .unwrap_or(cause as &dyn std::error::Error)
            }),
            Failure::Start => self.start.as_ref()?.failure(),
            Failure::Native(index) => self.native[index].as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            Failure::Socket(index) => self.socket_post[index].as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Preparation(index) => self.preparation[index].as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            // The shared readiness classifier treats EINTR as successful
            // pending progress. Its raw Result stays parked, but cannot hide a
            // later reducer/semantic/deadline refusal.
            Failure::Handshake => self.poll.as_ref().and_then(|result| result.as_ref().err())
                .filter(|cause| **cause != rustix::io::Errno::INTR)
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.completed.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error)),
        }
    }

    fn require_deadline(&mut self) {
        self.cutoff = Some(self.deadline.check());
        if !matches!(self.cutoff, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Deadline);
        }
    }

    fn prepare_post(
        &mut self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
        index: usize,
    ) -> bool {
        self.preparation[index] = Some(receiving.arm_initial_observation_post_v1());
        if !matches!(self.preparation[index], Some(Ok(()))) {
            self.first.get_or_insert(Failure::Preparation(index));
            return false;
        }
        true
    }

    fn observe_native(
        &mut self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
        cold: &Option<RetainedStorageColdOpenV1>,
        index: usize,
    ) {
        // Preserve the original purpose/SAME-socket checkpoint separately.
        // Its refusal must never suppress the already paid independent sample.
        self.socket_post[index] = Some(if let Some(socket) = self.socket.as_ref()
            .or_else(|| self.start.as_ref().and_then(StorageBrokerHandshakeStartV1::socket))
        {
            receiving.require_initial_session_socket_current_v1(socket)
        } else if let Some(Ok(session)) = self.completed.as_ref() {
            session.require_initial_storage_socket_current_v1(receiving)
        } else if let Some(Err(crate::DormantBrokerSessionHandshakeErrorV1::StoragePreparation(failure))) = self.completed.as_ref() {
            match &failure._owner.carrier().transport {
                HandshakeTransport::Ordinary(socket) => receiving.require_initial_session_socket_current_v1(socket),
                _ => Err(StorageReceivingClosedV1),
            }
        } else if let Some(socket) = cold.as_ref().and_then(RetainedStorageColdOpenV1::initial_socket_v1) {
            receiving.require_initial_session_socket_current_v1(socket)
        } else {
            Err(StorageReceivingClosedV1)
        });
        if !matches!(self.socket_post[index], Some(Ok(()))) {
            self.first.get_or_insert(Failure::Socket(index));
        }
        // This actual pending flight was paid before the interval. It samples
        // the SAME genuine original even if the primary already closed normal
        // admission; its native/RPC owners remain on the receiving original.
        self.native[index] = Some(receiving.finish_initial_observation_post_v1());
        if !matches!(self.native[index], Some(Ok(()))) {
            self.first.get_or_insert(Failure::Native(index));
        }
    }

    pub(crate) fn drive_once(
        &mut self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
        image: Option<crate::production_startup::Pid1LaunchImageV1>,
        cold: &mut Option<RetainedStorageColdOpenV1>,
    ) {
        if self.phase != Phase::Fresh {
            return;
        }
        self.phase = Phase::Checking;
        self.require_deadline();
        if self.first.is_some() {
            self.phase = Phase::Failed;
            return;
        }
        if !self.prepare_post(receiving, 0) {
            self.phase = Phase::Failed;
            return;
        }
        self.wire_demand = Some(crate::recovery::BrokerMainOpenV1::storage_hello_flight_demand_v1());
        let Some(Ok(demand)) = self.wire_demand.as_ref() else {
            self.first = Some(Failure::Demand);
            self.observe_native(receiving, cold, 0);
            self.phase = Phase::Failed;
            return;
        };
        let Some(socket) = self.socket.as_ref() else {
            std::process::abort()
        };
        self.wire = Some(receiving.reserve_initial_session_hello_once_v1(socket, *demand));
        if !matches!(self.wire, Some(Ok(()))) {
            self.first = Some(Failure::Wire);
            self.observe_native(receiving, cold, 0);
            self.phase = Phase::Failed;
            return;
        }

        // The actual lower owner already lives here when it acquires its first
        // self pidfd/directory/manifest lock/secret. No outer Result substitutes
        // for retaining that partial original on a later load refusal.
        self.fixed = Some(ProtectedBrokerSessionFixedCustodyV1::open_storage_broker_retaining_v1(
            &mut self.lower,
            receiving,
        ));
        if !matches!(self.fixed, Some(Ok(_))) {
            self.first = Some(Failure::Fixed);
        }
        self.observe_native(receiving, cold, 0);
        self.require_deadline();
        if self.first.is_some() {
            self.phase = Phase::Failed;
            return;
        }
        if !self.prepare_post(receiving, 1) {
            self.phase = Phase::Failed;
            return;
        }
        let Some(Ok(fixed)) = self.fixed.as_mut() else {
            std::process::abort()
        };
        self.launch = Some(fixed.attach_launch_image_retaining_v1(image));
        if !matches!(self.launch, Some(Ok(()))) {
            self.first = Some(Failure::Launch);
        }
        if self.first.is_none() {
            let Some(Ok(fixed)) = self.fixed.take() else {
                std::process::abort()
            };
            let (root, _, _, _, custody) = fixed.into_handshake_parts();
            let FixedEndpointCustodyV1::Broker(custody) = custody else {
                std::process::abort()
            };
            let Some(socket) = self.socket.take() else {
                std::process::abort()
            };
            self.start = Some(StorageBrokerHandshakeStartV1::new(root, BrokerHandshakeCustodyV1::Fresh(custody), socket));
            let Some(start) = self.start.as_mut() else {
                std::process::abort()
            };
            start.initialize_once();
            if start.failure().is_some() {
                self.first = Some(Failure::Start);
            }
        }
        // The original post is independently owed on launch, peer or builder
        // refusal too; those actual owners and first causes are still resident.
        self.observe_native(receiving, cold, 1);
        self.require_deadline();
        if self.first.is_some() {
            self.phase = Phase::Failed;
            return;
        }
        if !self.prepare_post(receiving, 2) {
            self.phase = Phase::Failed;
            return;
        }
        let Some(start) = self.start.as_mut() else {
            std::process::abort()
        };
        let Some(handshake) = start.take_ready() else {
            std::process::abort()
        };
        self.start = None;
        self.completed = Some(crate::dormant_handshake::complete_retained_storage_from_prepared_v1(
            handshake, self.deadline, cold, Some(&mut *receiving), Some(&mut self.poll),
        ));
        if !matches!(self.completed, Some(Ok(_))) {
            self.first = Some(Failure::Handshake);
        }
        // The cold owner already retired its original cutoff on success.
        // This is cleanup currentness, not a new admission under that old D.
        self.observe_native(receiving, cold, 2);
        self.phase = if self.first.is_some() { Phase::Failed } else { Phase::Ready };
    }

    pub(crate) fn take_completed(&mut self) -> Option<crate::DormantAuthenticatedBrokerSessionV1> {
        if self.phase != Phase::Ready || self.first.is_some() {
            return None;
        }
        let Some(Ok(session)) = self.completed.take() else {
            std::process::abort()
        };
        self.phase = Phase::HandedOff;
        Some(session)
    }

    pub(super) fn controls_may_dispose(&self) -> bool {
        self.phase == Phase::HandedOff && self.first.is_none()
            && self.native.iter().all(|post| matches!(post, Some(Ok(()))))
            && self.preparation.iter().all(|post| matches!(post, Some(Ok(()))))
            && self.socket_post.iter().all(|post| matches!(post, Some(Ok(()))))
            && matches!(self.wire, Some(Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_readiness_does_not_replace_later_actual_semantic_refusal() {
        let (local, _peer) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX, rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC, None,
        ).unwrap();
        let socket = SeqpacketSocket::from_owned(local).unwrap();
        // Custody and returned-result mechanics only: this constructs no
        // receiving loan, paid Native original or positive Session authority.
        let mut owner = StorageInitialSessionHandshakeV1::new(
            socket, StorageRetainedSocketAcceptanceV1::new(),
            OriginalBrokerColdDeadlineV1::storage_accept(u64::MAX),
        );
        owner.poll = Some(Err(rustix::io::Errno::INTR));
        owner.completed = Some(Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole));
        owner.first = Some(Failure::Handshake);

        let returned = match owner.completed.as_ref().unwrap() {
            Err(error) => error,
            Ok(_) => panic!("the fixture must retain the semantic refusal"),
        };
        let cause = owner.failure().unwrap()
            .downcast_ref::<crate::DormantBrokerSessionHandshakeErrorV1>().unwrap();
        assert!(std::ptr::eq(returned, cause));
        assert!(matches!(owner.poll, Some(Err(rustix::io::Errno::INTR))));
        assert!(owner.socket.is_some());
    }
}
