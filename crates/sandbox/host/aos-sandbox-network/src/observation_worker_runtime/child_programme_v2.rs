//! Owns the actual observer's Source-first startup and retained native prefix.
//!
//! This private owner is the startup portion of the one O programme. It sends
//! no READY and grants no read authority. The enclosing actor must join the
//! prepaid whole programme before using its socket or readers.

mod actor;
mod disposition;
mod programme;
mod ready;

pub use actor::run_inherited_network_observation_worker_entry_v2;
pub(crate) use programme::{ObserverWholeProgrammeDataV2, observer_whole_programme_data_v2};
mod terminal;

pub(crate) use ready::observer_ready_obligations_data_v2;

pub(crate) use terminal::observer_terminal_send_obligations_data_v2;
mod execution;

pub(crate) use disposition::observer_input_disposition_obligations_data_v3;
mod handoff;

pub(crate) use execution::observer_execution_obligations_data_v2;

pub(crate) use handoff::observer_handoff_obligations_data_v3;

use super::{NetworkObservationWorkerConfiguration, NetworkObservationWorkerError};
use crate::kernel_reader::observation_helpers_v2::NetworkObservationReadersOriginalV2;
use crate::worker_arguments_v2::{
    NetworkWorkerArgumentsClosedV2, NetworkWorkerArgumentsOriginalV2,
};
use aos_sandbox_broker::receiving::{
    NetworkChildOriginClosedV2, NetworkChildSourceLoanV2, NetworkChildSourceProbeOriginalV2,
    NetworkChildSourceRecordOriginalV2, NetworkWorkerBirthPurposeV2,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::pidfd::{SingleThreadedProcess, SingleThreadedProcessOriginalV2};
use aos_sandbox_linux::seqpacket::RetainedSeqpacketAdmissionErrorV1;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use std::error::Error;
use std::os::fd::{AsFd as _, OwnedFd};

#[derive(Clone, Copy)]
enum StartupFirst {
    Order,
    SourceBefore,
    Guard,
    Identity,
    Thread,
    Core,
    Arguments,
    Readers,
    Duplicate,
    Socket,
    Peer,
    SourceAfter,
    PeerRetirement,
}

/// Retains startup failures until the actual terminal handback or process exit.
struct ObserverStartupOriginalV2 {
    entered: bool,
    first: Option<StartupFirst>,
    before: NetworkChildSourceProbeOriginalV2,
    before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    guard: Option<Result<(), aos_linux_descriptors::Error>>,
    identity: Option<Result<(), NetworkObservationWorkerError>>,
    thread: SingleThreadedProcessOriginalV2,
    thread_result: Option<Result<(), aos_linux_descriptors::Error>>,
    worker: Option<SingleThreadedProcess>,
    core: Option<Result<(), aos_linux_descriptors::Error>>,
    arguments: NetworkWorkerArgumentsOriginalV2,
    arguments_result: Option<Result<(), NetworkWorkerArgumentsClosedV2>>,
    readers: NetworkObservationReadersOriginalV2,
    readers_result: Option<Result<(), crate::kernel_reader::NetworkKernelReaderError>>,
    duplicate: Option<Result<OwnedFd, rustix::io::Errno>>,
    socket: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    peer: NetworkChildSourceRecordOriginalV2,
    peer_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    peer_retirement: Option<Result<(), NetworkChildOriginClosedV2>>,
    after: NetworkChildSourceProbeOriginalV2,
    after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    closed: NetworkObservationWorkerError,
}

impl ObserverStartupOriginalV2 {
    fn new() -> Self {
        Self {
            entered: false,
            first: None,
            before: NetworkChildSourceProbeOriginalV2::new(),
            before_result: None,
            guard: None,
            identity: None,
            thread: SingleThreadedProcessOriginalV2::new(),
            thread_result: None,
            worker: None,
            core: None,
            arguments: NetworkWorkerArgumentsOriginalV2::new(),
            arguments_result: None,
            readers: NetworkObservationReadersOriginalV2::new(),
            readers_result: None,
            duplicate: None,
            socket: None,
            peer: NetworkChildSourceRecordOriginalV2::new(),
            peer_result: None,
            peer_retirement: None,
            after: NetworkChildSourceProbeOriginalV2::new(),
            after_result: None,
            closed: NetworkObservationWorkerError::Protocol("observer startup is closed"),
        }
    }

    fn capture_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
    ) -> Result<(), NetworkObservationWorkerError> {
        if self.entered || self.first.is_some() {
            self.first.get_or_insert(StartupFirst::Order);
            return Err(NetworkObservationWorkerError::Protocol(
                "observer startup was reused",
            ));
        }
        self.entered = true;
        self.before_result = Some(source.require_live_before_once_v2(&mut self.before, None));
        if !matches!(self.before_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::SourceBefore);
        }

        let local = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.first.is_none() {
                self.capture_local_once_v2(source);
            }
        }));

        // This is independently owed even after a local/native startup error.
        self.after_result = Some(if source.operation_binding_data_v2().is_some() {
            source.require_live_before_once_v2(&mut self.after, None)
        } else {
            source.observe_owed_native_after_once_v2(&mut self.after)
        });
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(StartupFirst::SourceAfter);
        }
        if let Err(payload) = local {
            std::panic::resume_unwind(payload);
        }
        if self.first.is_none() {
            // All actual startup and Source posts passed. Keep the identity
            // observations while closing only their completed stat proof.
            self.peer_retirement = Some(self.peer.retire_positive_stat_proof_once_v2());
            if !matches!(self.peer_retirement, Some(Ok(()))) {
                self.first = Some(StartupFirst::PeerRetirement);
            }
        }
        if self.first.is_some() {
            Err(NetworkObservationWorkerError::Protocol(
                "observer startup failed",
            ))
        } else {
            Ok(())
        }
    }

    fn capture_local_once_v2(&mut self, source: &mut NetworkChildSourceLoanV2<'_>) {
        self.guard = Some(aos_sandbox_linux::no_setid::require_guarded_startup());
        if !matches!(self.guard, Some(Ok(()))) {
            self.first = Some(StartupFirst::Guard);
            return;
        }
        self.identity = Some(
            if rustix::process::getuid().is_root()
                && rustix::process::geteuid().is_root()
                && source
                    .operation_binding_data_v2()
                    .is_some_and(|binding| binding.purpose == 2)
            {
                Ok(())
            } else {
                Err(NetworkObservationWorkerError::Protocol(
                    "observer Source identity is invalid",
                ))
            },
        );
        if !matches!(self.identity, Some(Ok(()))) {
            self.first = Some(StartupFirst::Identity);
            return;
        }

        self.thread_result = Some(self.thread.capture_once_v2());
        if !matches!(self.thread_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::Thread);
            return;
        }
        self.worker = self.thread.take_completed_once_v2();
        let Some(worker) = self.worker.as_ref() else {
            self.first = Some(StartupFirst::Thread);
            return;
        };
        self.core = Some(worker.disable_core_dumps());
        if !matches!(self.core, Some(Ok(()))) {
            self.first = Some(StartupFirst::Core);
            return;
        }
        self.arguments_result = Some(self.arguments.capture_once_v2(
            NetworkWorkerBirthPurposeV2::Observation,
            source,
            worker,
        ));
        if !matches!(self.arguments_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::Arguments);
            return;
        }
        let Some([ip, nft, enforcement_loader, bpf_observer, lease_gate_object]) =
            self.arguments.take_observation_paths_once_v2()
        else {
            self.first = Some(StartupFirst::Arguments);
            return;
        };
        self.readers_result = Some(self.readers.open_once_v2(
            source,
            NetworkObservationWorkerConfiguration {
                ip,
                nft,
                enforcement_loader,
                bpf_observer,
                lease_gate_object,
            },
        ));
        if !matches!(self.readers_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::Readers);
            return;
        }

        self.duplicate = Some(rustix::io::dup(std::io::stdin().as_fd()));
        let descriptor = match self.duplicate.take() {
            Some(Ok(descriptor)) => descriptor,
            error => {
                self.duplicate = error;
                self.first = Some(StartupFirst::Duplicate);
                return;
            }
        };
        self.socket = Some(DescriptorSubjectSocket::from_owned_retaining(descriptor));
        let Some(Ok(socket)) = self.socket.as_ref() else {
            self.first = Some(StartupFirst::Socket);
            return;
        };
        self.peer_result = Some(source.require_same_netd_peer_once_v2(socket, &mut self.peer));
        if !matches!(self.peer_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::Peer);
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first? {
            StartupFirst::Order => None,
            StartupFirst::SourceBefore => self.before.failure(),
            StartupFirst::Guard => error(&self.guard),
            StartupFirst::Identity => error(&self.identity),
            StartupFirst::Thread => self.thread.failure(),
            StartupFirst::Core => error(&self.core),
            StartupFirst::Arguments => self.arguments.failure(),
            StartupFirst::Readers => self.readers.failure(),
            StartupFirst::Duplicate => error(&self.duplicate),
            StartupFirst::Socket => error(&self.socket),
            StartupFirst::Peer => self.peer.failure(),
            StartupFirst::SourceAfter => self.after.failure(),
            StartupFirst::PeerRetirement => {
                self.peer.failure().or_else(|| error(&self.peer_retirement))
            }
        };
        selected.or(Some(&self.closed))
    }
}

/// Quotes this exact startup owner beyond the separately priced O5 read recipe.
/// The authentic initial840/first Source query and whole transport/read actor
/// remain enclosing terms. This DATA cannot create Source or financial credit.
pub(crate) fn observer_startup_obligations_data_v2() -> Option<ResourceVector> {
    let mut demand = NetworkWorkerArgumentsOriginalV2::receiving_obligations_data_v2(
        NetworkWorkerBirthPurposeV2::Observation,
    )?;
    demand = demand
        .checked_add(NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(2)?)
        .ok()?;
    demand = demand
        .checked_add(NetworkChildSourceRecordOriginalV2::receiving_obligations_data_v2()?)
        .ok()?;
    let (thread_bytes, thread_files) =
        SingleThreadedProcessOriginalV2::receiving_obligations_data_v2()?;
    let (socket_bytes, socket_files) =
        DescriptorSubjectSocket::retaining_raw_admission_obligations_v2()?;
    let bytes = std::mem::size_of::<ObserverStartupOriginalV2>()
        .checked_mul(2)?
        .checked_add(thread_bytes)?
        .checked_add(socket_bytes)?;
    let files = thread_files.checked_add(socket_files)?;
    demand
        .checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, u64::try_from(files).ok()?),
        )
        .ok()
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|error| error as _)
}
