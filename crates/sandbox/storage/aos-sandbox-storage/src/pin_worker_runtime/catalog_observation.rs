//! Retained original connection, catalog exchange and exact worker cleanup.
//!
//! This is the existing fixed observer recipe. Its owner keeps every completed
//! stage on failure; only a positive natural exit permits moving its result.

use super::*;
use aos_sandbox_linux::seqpacket::RetainedSeqpacketAdmissionErrorV1;
use aos_sandbox_linux::seqpacket::bounded::{
    receive_worker_observer_record_v1, WorkerObserverReceiveErrorV1,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::WorkerObserverRecordKindV1;

type CatalogResult = (WorkspaceCatalogObservationResultV1, Option<OwnedFd>);

#[derive(Clone, Copy)]
enum FirstFailure {
    Connection,
    Peer,
    Ready,
    ReadyPath,
    Cgroup,
    Population,
    Request,
    Response,
    Validation,
    Acknowledgment,
    NaturalExit,
}

pub(super) struct CatalogObservationAttemptV1 {
    connection: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    peer: Option<Result<(), ZfsWorkerError>>,
    ready: Option<Result<ReceivedDescriptorRecord, WorkerObserverReceiveErrorV1>>,
    ready_path: Option<Result<String, ZfsWorkerError>>,
    cgroup: Option<Result<RetainedCgroupAnchor, ZfsWorkerError>>,
    population: Option<Result<CgroupPopulationMonitor, ZfsWorkerError>>,
    request_wire: Option<Vec<u8>>,
    request_send: Option<Result<(), ZfsWorkerError>>,
    response: Option<Result<ReceivedDescriptorRecord, WorkerObserverReceiveErrorV1>>,
    validation: Option<Result<WorkspaceCatalogObservationResultV1, ZfsWorkerError>>,
    acknowledgment: Option<Result<(), ZfsWorkerError>>,
    natural_exit: Option<Result<(), ZfsWorkerError>>,
    cancellation: Option<Result<(), ZfsWorkerError>>,
    first: Option<FirstFailure>,
    entered: bool,
    taken_positive: bool,
}

impl CatalogObservationAttemptV1 {
    pub(super) const fn new() -> Self {
        Self { connection: None, peer: None, ready: None, ready_path: None,
            cgroup: None, population: None, request_wire: None, request_send: None, response: None,
            validation: None, acknowledgment: None, natural_exit: None,
            cancellation: None, first: None, entered: false, taken_positive: false }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn run(
        &mut self, path: &Path, manager: &RetainedCgroupAnchor,
        parent: &RetainedCgroupAnchor, role: WorkspacePinServiceRole,
        request_bytes: &[u8], request: &WorkspaceCatalogObservationRequestV1,
        custody: &WorkspacePinHostCustody, deadline: u64,
    ) {
        if self.entered { return; }
        self.entered = true;
        self.request_wire = Some(request_bytes.to_vec());
        self.capture_connection_once(path);
        let Some(Ok(socket)) = self.connection.as_mut() else {
            self.first = Some(FirstFailure::Connection); return;
        };
        socket.begin_original_retention_v1();
        self.peer = Some(verify_systemd_peer(socket.peer(), manager));
        if !matches!(self.peer, Some(Ok(()))) {
            self.first = Some(FirstFailure::Peer); return;
        }
        self.ready = Some(receive_worker_observer_record_v1(
            socket, WorkerObserverRecordKindV1::ReadyOrResult, deadline));
        let Some(Ok(ready)) = self.ready.as_ref() else {
            self.first = Some(FirstFailure::Ready); return;
        };
        self.ready_path = Some(decode_ready(ready.payload(), role).map(str::to_owned));
        let Some(Ok(path)) = self.ready_path.as_ref() else {
            self.first = Some(FirstFailure::ReadyPath); return;
        };
        self.cgroup = Some(verify_worker_subject(ready.subject(), parent, Path::new(path), role));
        let Some(Ok(cgroup)) = self.cgroup.as_ref() else {
            self.first = Some(FirstFailure::Cgroup); return;
        };
        self.population = Some(cgroup.population_monitor().map_err(Into::into));
        let Some(Ok(population)) = self.population.as_ref() else {
            self.first = Some(FirstFailure::Population); return;
        };

        let Some(request_wire) = self.request_wire.as_ref() else { return; };
        self.request_send = Some(send_catalog_observation_request_before(socket,
            request_wire, [custody.mount_namespace().as_fd(), custody.pin_root().as_fd()], deadline));
        if matches!(self.request_send, Some(Err(_))) {
            self.first = Some(FirstFailure::Request);
        } else {
            let kind = if request.exports_mount() {
                WorkerObserverRecordKindV1::ExportReply
            } else {
                WorkerObserverRecordKindV1::ReadyOrResult
            };
            self.response = Some(receive_worker_observer_record_v1(socket, kind, deadline));
            match self.response.as_ref() {
                Some(Ok(response)) => {
                    self.validation = Some(validate_catalog_observation_response_v1(
                        response, ready.subject(), request, cgroup));
                    if matches!(self.validation, Some(Err(_))) {
                        self.first = Some(FirstFailure::Validation);
                    } else {
                        self.acknowledgment = Some(send_packet_before(socket, ACK, deadline));
                        if matches!(self.acknowledgment, Some(Err(_))) {
                            self.first = Some(FirstFailure::Acknowledgment);
                        }
                    }
                }
                _ => self.first = Some(FirstFailure::Response),
            }
        }
        if self.first.is_some() {
            self.cancellation = Some(quiesce_worker(ready.subject(), cgroup, population));
            return;
        }
        self.natural_exit = Some(wait_for_worker_quiescence(
            ready.subject(), population, NATURAL_EXIT_TIMEOUT));
        if !matches!(self.natural_exit, Some(Ok(()))) {
            self.first = Some(FirstFailure::NaturalExit);
            self.cancellation = Some(quiesce_worker(ready.subject(), cgroup, population));
        }
    }

    fn capture_connection_once(&mut self, path: &Path) {
        if self.connection.is_some() { return; }
        self.connection = Some(DescriptorSubjectSocket::connect_retaining(path));
        if matches!(self.connection, Some(Err(_))) {
            self.first.get_or_insert(FirstFailure::Connection);
        }
    }

    pub(super) fn take_positive(&mut self) -> Option<CatalogResult> {
        if self.first.is_some() || self.taken_positive
            || !matches!(self.natural_exit, Some(Ok(())))
        {
            return None;
        }
        if !matches!(self.response, Some(Ok(_)))
            || !matches!(self.validation, Some(Ok(_)))
            || !matches!(self.acknowledgment, Some(Ok(())))
        {
            return None;
        }
        let Some(Ok(result)) = self.validation.take() else { return None; };
        let Some(Ok(response)) = self.response.take() else {
            self.validation = Some(Ok(result));
            return None;
        };
        // The original response stays intact through validation, ACK and
        // exact natural exit. Only now can its optional exported FD move out.
        let (_payload, _subject, descriptors) = response.into_parts();
        self.taken_positive = true;
        Some((result, descriptors.into_iter().next()))
    }

    pub(super) fn was_taken_positive(&self) -> bool {
        self.taken_positive && self.first.is_none()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        {
            slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)
        }
        match self.first? {
            FirstFailure::Connection => error(&self.connection),
            FirstFailure::Peer => error(&self.peer),
            FirstFailure::Ready => error(&self.ready),
            FirstFailure::ReadyPath => error(&self.ready_path),
            FirstFailure::Cgroup => error(&self.cgroup),
            FirstFailure::Population => error(&self.population),
            FirstFailure::Request => error(&self.request_send),
            FirstFailure::Response => error(&self.response),
            FirstFailure::Validation => error(&self.validation),
            FirstFailure::Acknowledgment => error(&self.acknowledgment),
            FirstFailure::NaturalExit => error(&self.natural_exit),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_failed_connect_stays_owned_and_cannot_be_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let mut attempt = CatalogObservationAttemptV1::new();
        attempt.capture_connection_once(&directory.path().join("absent.sock"));
        assert!(matches!(attempt.connection, Some(Err(_))));
        let original = attempt.failure().unwrap() as *const dyn std::error::Error;

        attempt.capture_connection_once(&directory.path().join("different.sock"));

        assert!(std::ptr::eq(attempt.failure().unwrap() as *const dyn std::error::Error, original));
        assert!(attempt.take_positive().is_none());
        assert!(!attempt.was_taken_positive());
    }

    #[test]
    fn incomplete_original_cannot_release_a_worker_result() {
        let mut attempt = CatalogObservationAttemptV1::new();
        assert!(attempt.take_positive().is_none());
        attempt.entered = true;
        assert!(attempt.take_positive().is_none());
        assert!(!attempt.was_taken_positive());
    }
}
