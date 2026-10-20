//! Owns the real P worker's Source-first startup and finite native programme.
//!
//! Empty originals create no worker, financial capacity or signed operation.
//! The protected parent must fund this complete startup, intake, admission and
//! typed63/9 effect programme before native birth. This module retains the
//! actual prefix through terminal handback; it contains no DATA Source adopter.

mod actor;
mod disposition;
mod execution;
mod programme;
mod signed_admission;
mod terminal;

pub use actor::run_inherited_network_prepare_worker_entry_v2;
pub(crate) use programme::{PreparationWholeProgrammeDataV2, preparation_whole_programme_data_v2};

use super::NetworkWorkerRuntimeError;
use crate::NetworkWorkerReplayLedger;
use crate::authorization::NetworkAuthorityV1;
use crate::kernel_mutator::{FixedNetworkKernelMutator, NetworkMutatorOpeningOriginalV4};
use crate::worker_arguments_v2::{
    NetworkWorkerArgumentsClosedV2, NetworkWorkerArgumentsOriginalV2,
};
use crate::worker_cgroup_v2::{NetworkWorkerCgroupClosedV2, NetworkWorkerCgroupOriginalV2};
use crate::worker_replay::NetworkWorkerReplayOpeningOriginalV4;
use aos_sandbox_broker::receiving::{
    NetworkChildOriginClosedV2, NetworkChildSourceLoanV2, NetworkChildSourceProbeOriginalV2,
    NetworkChildSourceRecordOriginalV2, NetworkWorkerBirthPurposeV2,
};
use aos_sandbox_broker::{
    BrokerAuthorityConfigError, ProtectedBrokerAuthorityConfiguration,
    ProtectedBrokerPublicCredentials, ProtectedNetworkBrokerConfigurationOriginalV4,
};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::kernel_clone::ConfiguredKernelCloneOriginalV1;
use aos_sandbox_linux::pidfd::{
    CurrentNetworkNamespaceOriginalV4, NamespaceFd, SingleThreadedProcess,
    SingleThreadedProcessOriginalV2,
};
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
    Configuration,
    Replay,
    Mutator,
    KernelNotes,
    Namespace,
    Cgroup,
    Duplicate,
    Socket,
    Peer,
    PeerRetirement,
    Body,
    SourceAfter,
}

/// Retains all actual startup objects beside their original native failures.
struct PreparationStartupOriginalV2 {
    entered: bool,
    first: Option<StartupFirst>,
    before: NetworkChildSourceProbeOriginalV2,
    before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    guard: Option<Result<(), aos_sandbox_linux::Error>>,
    identity: Option<Result<(), NetworkWorkerRuntimeError>>,
    thread: SingleThreadedProcessOriginalV2,
    thread_result: Option<Result<(), aos_sandbox_linux::Error>>,
    worker: Option<SingleThreadedProcess>,
    core: Option<Result<(), aos_sandbox_linux::Error>>,
    arguments: NetworkWorkerArgumentsOriginalV2,
    arguments_result: Option<Result<(), NetworkWorkerArgumentsClosedV2>>,
    configuration: ProtectedNetworkBrokerConfigurationOriginalV4,
    configuration_result: Option<Result<(), BrokerAuthorityConfigError>>,
    authority: Option<NetworkAuthorityV1>,
    public_credentials: Option<ProtectedBrokerPublicCredentials>,
    replay_opening: NetworkWorkerReplayOpeningOriginalV4,
    replay: Option<NetworkWorkerReplayLedger>,
    mutator_opening: NetworkMutatorOpeningOriginalV4,
    mutator_result: Option<Result<(), crate::kernel_mutator::NetworkKernelMutationError>>,
    mutator: Option<FixedNetworkKernelMutator>,
    kernel: ConfiguredKernelCloneOriginalV1,
    kernel_result: Option<Result<(), aos_sandbox_linux::Error>>,
    namespace_original: CurrentNetworkNamespaceOriginalV4,
    namespace_result: Option<Result<(), aos_sandbox_linux::Error>>,
    namespace: Option<NamespaceFd>,
    cgroup_original: NetworkWorkerCgroupOriginalV2,
    cgroup_result: Option<Result<(), NetworkWorkerCgroupClosedV2>>,
    cgroup: Option<String>,
    duplicate: Option<Result<OwnedFd, rustix::io::Errno>>,
    socket: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    peer: NetworkChildSourceRecordOriginalV2,
    peer_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    peer_retirement: Option<Result<(), NetworkChildOriginClosedV2>>,
    after: NetworkChildSourceProbeOriginalV2,
    after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    closed: NetworkWorkerRuntimeError,
}

impl PreparationStartupOriginalV2 {
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
            configuration: ProtectedNetworkBrokerConfigurationOriginalV4::new(),
            configuration_result: None,
            authority: None,
            public_credentials: None,
            replay_opening: NetworkWorkerReplayOpeningOriginalV4::new(),
            replay: None,
            mutator_opening: NetworkMutatorOpeningOriginalV4::new(),
            mutator_result: None,
            mutator: None,
            kernel: ConfiguredKernelCloneOriginalV1::new(),
            kernel_result: None,
            namespace_original: CurrentNetworkNamespaceOriginalV4::new(),
            namespace_result: None,
            namespace: None,
            cgroup_original: NetworkWorkerCgroupOriginalV2::new(),
            cgroup_result: None,
            cgroup: None,
            duplicate: None,
            socket: None,
            peer: NetworkChildSourceRecordOriginalV2::new(),
            peer_result: None,
            peer_retirement: None,
            after: NetworkChildSourceProbeOriginalV2::new(),
            after_result: None,
            closed: NetworkWorkerRuntimeError::Protocol("preparation startup is closed"),
        }
    }

    fn capture_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.entered || self.first.is_some() {
            self.first.get_or_insert(StartupFirst::Order);
            return Err(NetworkWorkerRuntimeError::Protocol(
                "preparation startup was reused",
            ));
        }
        self.entered = true;
        self.before_result = Some(source.require_live_before_once_v2(&mut self.before, None));
        if !matches!(self.before_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::SourceBefore);
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.first.is_none() {
                self.capture_local_once_v2(source);
            }
        }));
        if body.is_err() {
            self.first.get_or_insert(StartupFirst::Body);
        }

        // This actual independently owed post runs even after any local
        // native/configuration failure or panic. It cannot heal an old cause.
        self.after_result = Some(if source.operation_binding_data_v2().is_some() {
            source.require_live_before_once_v2(&mut self.after, None)
        } else {
            source.observe_owed_native_after_once_v2(&mut self.after)
        });
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(StartupFirst::SourceAfter);
        }
        if self.first.is_none() {
            self.peer_retirement = Some(self.peer.retire_positive_stat_proof_once_v2());
            if !matches!(self.peer_retirement, Some(Ok(()))) {
                self.first = Some(StartupFirst::PeerRetirement);
            }
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if self.first.is_some() {
            Err(NetworkWorkerRuntimeError::Protocol(
                "preparation startup failed",
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
                    .is_some_and(|binding| binding.purpose == 1)
            {
                Ok(())
            } else {
                Err(NetworkWorkerRuntimeError::Authority)
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
            NetworkWorkerBirthPurposeV2::Preparation,
            source,
            worker,
        ));
        if !matches!(self.arguments_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::Arguments);
            return;
        }
        let Some([authority, replay, ip, nft, enforcement, loader, object]) =
            self.arguments.take_preparation_paths_once_v2()
        else {
            self.first = Some(StartupFirst::Arguments);
            return;
        };

        self.configuration_result = Some(self.configuration.capture_network_once_v4(&authority));
        if !matches!(self.configuration_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::Configuration);
            return;
        }
        let Some(configuration) = self.configuration.take_configuration_once() else {
            self.first = Some(StartupFirst::Configuration);
            return;
        };
        let (authority, public) =
            NetworkAuthorityV1::from_captured_network_configuration_v4(configuration);
        self.authority = Some(authority);
        self.public_credentials = Some(public);

        self.replay_opening.prepare_once_v4(&replay);
        self.replay_opening.replay_once();
        self.replay = self.replay_opening.take_completed_once_v4();
        if self.replay.is_none() {
            self.first = Some(StartupFirst::Replay);
            return;
        }
        self.mutator_result =
            Some(
                self.mutator_opening
                    .prepare_once_v4(ip, nft, enforcement, loader, object),
            );
        if !matches!(self.mutator_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::Mutator);
            return;
        }
        self.mutator = self.mutator_opening.take_completed_once_v4();
        if self.mutator.is_none() {
            self.first = Some(StartupFirst::Mutator);
            return;
        }
        self.kernel_result = Some(self.kernel.capture_once_v1());
        if !matches!(self.kernel_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::KernelNotes);
            return;
        }
        self.namespace_result = Some(self.namespace_original.capture_once_v4());
        if !matches!(self.namespace_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::Namespace);
            return;
        }
        self.namespace = self.namespace_original.take_completed_once_v4();
        if self.namespace.is_none() {
            self.first = Some(StartupFirst::Namespace);
            return;
        }
        self.cgroup_result = Some(self.cgroup_original.capture_once_v2(source));
        if !matches!(self.cgroup_result, Some(Ok(()))) {
            self.first = Some(StartupFirst::Cgroup);
            return;
        }
        self.cgroup = self.cgroup_original.take_completed_once_v2();
        if self.cgroup.is_none() {
            self.first = Some(StartupFirst::Cgroup);
            return;
        }

        self.duplicate = Some(rustix::io::dup(std::io::stdin().as_fd()));
        let descriptor = match self.duplicate.take() {
            Some(Ok(descriptor)) => descriptor,
            other => {
                self.duplicate = other;
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
        let cause = match self.first? {
            StartupFirst::SourceBefore => self.before.failure(),
            StartupFirst::Guard => failed(&self.guard),
            StartupFirst::Identity => failed(&self.identity),
            StartupFirst::Thread => self.thread.failure(),
            StartupFirst::Core => failed(&self.core),
            StartupFirst::Arguments => self.arguments.failure(),
            StartupFirst::Configuration => self.configuration.failure(),
            StartupFirst::Replay => self.replay_opening.failure(),
            StartupFirst::Mutator => self.mutator_opening.failure(),
            StartupFirst::KernelNotes => self.kernel.failure().map(|cause| cause as _),
            StartupFirst::Namespace => self.namespace_original.failure().map(|cause| cause as _),
            StartupFirst::Cgroup => self.cgroup_original.failure(),
            StartupFirst::Duplicate => failed(&self.duplicate),
            StartupFirst::Socket => failed(&self.socket),
            StartupFirst::Peer | StartupFirst::PeerRetirement => self.peer.failure(),
            StartupFirst::SourceAfter => self.after.failure(),
            StartupFirst::Order | StartupFirst::Body => None,
        };
        cause.or(Some(&self.closed))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PreparationStartupQuoteErrorV2 {
    #[error(transparent)]
    Accounting(#[from] aos_sandbox_core::AccountingError),
    #[error("the fixed preparation startup supplier is unavailable")]
    Unavailable,
}

/// Quotes exact startup aside from replay's separately retained typed demand.
///
/// The enclosing owner also adds real840/initialSource, replay's complete-child
/// supplier, intake, signedcrypto, effects and all terminal/ACK obligations.
/// This DATA alone funds or admits none of them.
pub(crate) fn preparation_startup_obligations_data_v2()
-> Result<ResourceVector, PreparationStartupQuoteErrorV2> {
    let mut demand = ProtectedBrokerAuthorityConfiguration::receiving_demand_v1()?;
    let terms = (|| {
        Some([
            NetworkWorkerArgumentsOriginalV2::receiving_obligations_data_v2(
                NetworkWorkerBirthPurposeV2::Preparation,
            )?,
            NetworkWorkerCgroupOriginalV2::receiving_obligations_data_v2()?,
            NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(2)?,
            NetworkChildSourceRecordOriginalV2::receiving_obligations_data_v2()?,
        ])
    })()
    .ok_or(PreparationStartupQuoteErrorV2::Unavailable)?;
    for term in terms {
        demand = demand.checked_add(term)?;
    }
    let (thread, socket, mutator, kernel, namespace) = (|| {
        Some((
            SingleThreadedProcessOriginalV2::receiving_obligations_data_v2()?,
            DescriptorSubjectSocket::retaining_raw_admission_obligations_v2()?,
            NetworkMutatorOpeningOriginalV4::receiving_obligations_v4()?,
            ConfiguredKernelCloneOriginalV1::receiving_obligations_v1()?,
            CurrentNetworkNamespaceOriginalV4::receiving_obligations_v4()?,
        ))
    })()
    .ok_or(PreparationStartupQuoteErrorV2::Unavailable)?;
    let additional = (|| {
        let bytes = std::mem::size_of::<PreparationStartupOriginalV2>()
            .checked_mul(2)?
            .checked_add(thread.0)?
            .checked_add(socket.0)?
            .checked_add(mutator.0)?
            .checked_add(kernel.0)?
            .checked_add(namespace.0)?;
        let files = thread
            .1
            .checked_add(socket.1)?
            .checked_add(mutator.1)?
            .checked_add(kernel.1)?
            .checked_add(namespace.1)?;
        let names = mutator.2.checked_add(kernel.2)?.checked_add(namespace.2)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, u64::try_from(files).ok()?)
                .with(D::MetadataEntries, u64::try_from(names).ok()?),
        )
    })()
    .ok_or(PreparationStartupQuoteErrorV2::Unavailable)?;
    Ok(demand.checked_add(additional)?)
}

fn failed<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
