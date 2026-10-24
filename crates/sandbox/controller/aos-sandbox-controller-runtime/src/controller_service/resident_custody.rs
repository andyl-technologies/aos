//! Partial Controller parent/worker custody and fixed negative terminal handling.
//!
//! The original startup slots and completed worker loans stay together with
//! their first native causes and abort-before-drop fences. This private module
//! does not manufacture readiness, proof, or replacement startup authority.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};


use super::activation::SystemdReadyNotifier;
use super::worker::WorkerEvent;
use super::{
    CapabilityState, ControllerAttachCredentialsV1, ControllerBrokerPlanSignerV1,
    ControllerCommand, ControllerNixStartRecipeSelectorV2, ControllerOwnershipConfigurationV1,
    ControllerRequestScopeV1, ControllerRuntimeError, ControllerServerAssembly,
    ControllerServerTerminal, NodeControllerLimits, ProductionController,
    ProvisionedControllerSourceGenesisInputV1, SharedControllerBrokerSessions,
    SnapshotOwnershipDonationV3, git_read_inspection, publisher_ingress, publisher_policy_source,
};

// These slots are a fixed destination for actual returned startup inputs, not
// an authority tuple. Outer None is unobserved; Some(None) is the same producer's
// observed optional absence. The worker only borrows a completed destination.
#[derive(Default)]
pub(super) struct ControllerWorkerOriginalsV1 {
    pub(super) resource_bank: Option<Arc<Mutex<aos_sandbox_controller_domain::ControllerResourceBankOpeningV1>>>,
    pub(super) shared_runtime: Option<Arc<tokio::runtime::Runtime>>,
    pub(super) foundations: Option<Arc<ControllerFoundationOriginalsV1>>,

    // A deny-only startup disposition selected from the confirmed native
    // successor. Every recovery request still needs its own admitted owner.
    pub(super) operator_recover_only: bool,

    pub(super) git_coverage_enabled: bool,
    pub(super) git_read: Option<git_read_inspection::GitReadWorkerInputsV1>,
    pub(super) publisher_attempt: Option<publisher_ingress::PublisherStartupAttemptV1>,
    pub(super) publisher_registration: Option<Option<publisher_ingress::PublisherRegistrationOwnerV1>>,
    pub(super) publisher_policy_bootstrap: Option<publisher_policy_source::PublisherPolicyBootstrapAttemptV1>,
    pub(super) node: Option<[u8; 16]>,
    pub(super) profile: Option<
        Option<Arc<aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1>>,
    >,
    pub(super) nix_selector: Option<Option<Arc<ControllerNixStartRecipeSelectorV2>>>,
    pub(super) genesis: Option<Option<ProvisionedControllerSourceGenesisInputV1>>,
    pub(super) cache_bundle: Option<Option<Vec<u8>>>,
    pub(super) ownership: Option<Option<SnapshotOwnershipDonationV3>>,
    pub(super) snapshot_ownership: Option<SnapshotOwnershipDonationV3>,
    pub(super) snapshot_ownership_refused: Option<ControllerOwnershipConfigurationV1>,
    pub(super) attach: Option<Option<ControllerAttachCredentialsV1>>,
    pub(super) signer: Option<Option<ControllerBrokerPlanSignerV1>>,
    pub(super) pins: Option<Option<aos_sandbox_controller_domain::guest_root_publication::GuestRootTemplatePinsV1>>,
    pub(super) sessions: Option<SharedControllerBrokerSessions>,
    pub(super) controller: Option<ProductionController>,
    pub(super) capabilities: Option<Arc<Mutex<CapabilityState>>>,
    pub(super) commands: Option<mpsc::Receiver<ControllerCommand>>,
    pub(super) events: Option<mpsc::Sender<WorkerEvent>>,
    worker_stage: ControllerWorkerStageV1,
}

// The sole installed assembly moves these SAME producer originals here only
// after their actual output anchors have moved into this owner's Controller.
// Failed optional producers move too: inspecting them never retires errors.
pub(super) struct ControllerFoundationOriginalsV1 {
    host: super::attachment_target::startup_identity::ControllerAttachmentStartupV1,
    mount: super::attachment_target::startup_identity::ControllerAttachmentStartupV1,
}

impl ControllerFoundationOriginalsV1 {
    pub(super) fn new(
        host: super::attachment_target::startup_identity::ControllerAttachmentStartupV1,
        mount: super::attachment_target::startup_identity::ControllerAttachmentStartupV1,
    ) -> Self {
        Self { host, mount }
    }

    pub(super) const fn receiving_bytes_v1() -> usize {
        // Arc destination and its pre-allocation temporary can coexist.
        2 * std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>()
    }

    pub(super) fn completed_anchor_files_v1(&self) -> Option<usize> {
        if self.host.native_temporaries_disposed_v1()
            && self.mount.native_temporaries_disposed_v1()
        {
            // The actual private assembly moved precisely one output cgroup
            // anchor from each original into the co-owned Controller.
            Some(2)
        } else {
            None
        }
    }
}

// Consecutive values constrain this private, single execution recipe. They are
// negative bookkeeping, never a currentness, floor, or detached Ready witness.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum ControllerParentStepV1 {
    Publisher = 1,
    Node,
    Nix,
    GenesisInput,
    RuntimePreparation,
    PublisherRegistration,
    Cache,
    Ownership,
    Attach,
    Signer,
    Pins,
    Diagnostic,
    Sessions,
    Runtime,
    Host,
    Mount,
    Controller,
    ControllerStartup,
    AsyncDiagnostic,
    Public,
    Capabilities,
    Events,
    Commands,
    Spawn,
    Readiness,
    Profile,
    Notifier,
    Notify,
    Applications,
    Monitor,
}

#[derive(Default)]
pub(super) enum ControllerParentStageV1 {
    #[default]
    Prepared,
    Checking(ControllerParentStepV1),
    Completed(ControllerParentStepV1),
    Ended,
}

impl ControllerParentStageV1 {
    pub(super) fn begin(&mut self, step: ControllerParentStepV1) -> bool {
        let previous = match *self {
            ControllerParentStageV1::Prepared => 0,
            ControllerParentStageV1::Completed(previous) => previous as u8,
            ControllerParentStageV1::Checking(_) | ControllerParentStageV1::Ended => {
                *self = ControllerParentStageV1::Ended;
                return false;
            }
        };
        if previous.checked_add(1) != Some(step as u8) {
            *self = ControllerParentStageV1::Ended;
            return false;
        }
        *self = ControllerParentStageV1::Checking(step);
        true
    }

    pub(super) fn complete(&mut self, step: ControllerParentStepV1) -> bool {
        if !matches!(*self, ControllerParentStageV1::Checking(actual) if actual == step) {
            *self = ControllerParentStageV1::Ended;
            return false;
        }
        *self = ControllerParentStageV1::Completed(step);
        true
    }
}

#[derive(Default)]
enum ControllerWorkerStageV1 {
    #[default]
    Building,
    Ready,
    Ended,
}

impl ControllerWorkerOriginalsV1 {
    pub(super) fn complete_worker_inputs(&mut self, stage: &ControllerParentStageV1) -> bool {
        if !matches!(self.worker_stage, ControllerWorkerStageV1::Building)
            || !matches!(
                stage,
                ControllerParentStageV1::Completed(ControllerParentStepV1::Commands)
            )
        {
            self.worker_stage = ControllerWorkerStageV1::Ended;
            return false;
        }
        self.worker_stage = ControllerWorkerStageV1::Ready;
        if self.ready_loan().is_none() {
            self.worker_stage = ControllerWorkerStageV1::Ended;
            return false;
        }
        true
    }

    pub(super) fn ready_loan(&mut self) -> Option<ControllerWorkerLoanV1<'_>> {
        if !matches!(self.worker_stage, ControllerWorkerStageV1::Ready)
            || self.nix_selector.is_none()
            || self.cache_bundle.is_none()
            || self.publisher_registration.is_none()
        {
            return None;
        }
        Some(ControllerWorkerLoanV1 {
            controller: self.controller.as_mut()?,
            profile: self.profile.as_ref()?.as_deref(),
            profile_original: self.profile.as_ref()?.as_ref(),
            resource_bank: self.resource_bank.as_ref(),
            shared_runtime: self.shared_runtime.as_ref(),
            foundations: self.foundations.as_ref(),
            node: self.node?,
            ownership: self.ownership.as_ref()?.as_ref().and_then(|donation| donation.get()),
            attach: self.attach.as_ref()?.as_ref(),
            signer: self.signer.as_ref()?.as_ref(),
            pins: *self.pins.as_ref()?,
            genesis: self.genesis.as_ref()?.as_ref(),
            publisher: self.publisher_registration.as_mut()?.as_mut(),
            cache_bootstrap: self.publisher_policy_bootstrap.as_mut(),
            git_coverage_enabled: self.git_coverage_enabled,
            operator_recover_only: self.operator_recover_only,
            git_read: self.git_read.as_mut(),
            capabilities: self.capabilities.as_ref()?,
            sessions: self.sessions.as_ref()?,
            commands: self.commands.as_ref()?,
            events: self.events.as_ref()?,
        })
    }
}

/// Borrows the actual stored fields for the sole reconciliation loop.
pub(super) struct ControllerWorkerLoanV1<'owner> {
    pub(super) controller: &'owner mut ProductionController,
    pub(super) profile: Option<&'owner aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1>,
    pub(super) profile_original: Option<&'owner Arc<aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1>>,
    pub(super) resource_bank: Option<&'owner Arc<Mutex<aos_sandbox_controller_domain::ControllerResourceBankOpeningV1>>>,
    pub(super) shared_runtime: Option<&'owner Arc<tokio::runtime::Runtime>>,
    pub(super) foundations: Option<&'owner Arc<ControllerFoundationOriginalsV1>>,
    pub(super) node: [u8; 16],
    pub(super) ownership: Option<&'owner ControllerOwnershipConfigurationV1>,
    pub(super) attach: Option<&'owner ControllerAttachCredentialsV1>,
    pub(super) signer: Option<&'owner ControllerBrokerPlanSignerV1>,
    pub(super) pins: Option<aos_sandbox_controller_domain::guest_root_publication::GuestRootTemplatePinsV1>,
    pub(super) genesis: Option<&'owner ProvisionedControllerSourceGenesisInputV1>,
    pub(super) publisher: Option<&'owner mut publisher_ingress::PublisherRegistrationOwnerV1>,
    pub(super) cache_bootstrap: Option<&'owner mut publisher_policy_source::PublisherPolicyBootstrapAttemptV1>,
    pub(super) git_coverage_enabled: bool,
    pub(super) operator_recover_only: bool,
    pub(super) git_read: Option<&'owner mut git_read_inspection::GitReadWorkerInputsV1>,
    pub(super) capabilities: &'owner Arc<Mutex<CapabilityState>>,
    pub(super) sessions: &'owner SharedControllerBrokerSessions,
    pub(super) commands: &'owner mpsc::Receiver<ControllerCommand>,
    pub(super) events: &'owner mpsc::Sender<WorkerEvent>,
}

pub(super) enum ControllerResidentCauseV1 {
    #[cfg(feature = "online-nix")]
    NixResolve,
    #[cfg(feature = "online-nix")]
    NixGeneration,
    // The real native cause and channel/Journal outcomes remain in fixed slots.
    GitRead,
    Runtime(ControllerRuntimeError),
    Worker(String),
    ReadySend(mpsc::SendError<WorkerEvent>),
    Receive(mpsc::RecvError),
    // The actual typed cause remains in SAME pending Publisher attempt.
    Publisher,
    // Actual original lower/verification/Journal cause stays in the SAME slot.
    PublisherPolicyBootstrap,
    // Actual Cache initialization/replay causes stay in the SAME Controller.
    CacheUsage,
    // The local selected child retains its actual Root/Session/native causes.
    GitCoverage,
    // Typed cause and every partial owner remain in SAME sessions' cold slot.
    StorageCold,
    // The first native cause stays with the SAME Storage pending-session slot.
    OutputRegistration,
    // Whole issuer/native/source causes remain beside the SAME Storage Session.
    CaptureCandidate,
    Closed(&'static str),
}

impl ControllerResidentCauseV1 {
    fn diagnostic(&self) -> &'static str {
        match self {
            #[cfg(feature = "online-nix")]
            Self::NixResolve => "resident original Nix Resolve50 failure",
            #[cfg(feature = "online-nix")]
            Self::NixGeneration => "resident original Nix Storage Prepare failure",
            Self::GitRead => "resident original Git read inspection failure",
            Self::Runtime(_) => "resident Controller startup/server failure",
            Self::Worker(_) => "resident Controller worker failure",
            Self::ReadySend(_) => "resident Controller readiness delivery failure",
            Self::Receive(_) => "resident Controller event receiver disconnected",
            Self::Publisher => "resident original Publisher startup failure",
            Self::PublisherPolicyBootstrap => "resident original Publisher policy bootstrap failure",
            Self::CacheUsage => "resident original Cache project observation failure",
            Self::GitCoverage => "resident original Git cohort enrollment failure",
            Self::StorageCold => "resident original Storage cold admission failure",
            Self::OutputRegistration => "resident original output registration failure",
            Self::CaptureCandidate => "resident original capture candidate failure",
            Self::Closed(label) => label,
        }
    }
}

// Neither terminal handling nor event reception needs the worker's long owner
// loan. In particular diagnostics must never wait on owner under terminal.
pub(super) struct ControllerWorkerCustodyV1 {
    pub(super) originals: Mutex<ControllerWorkerOriginalsV1>,
    terminal: Mutex<Option<ControllerResidentCauseV1>>,
    pub(super) receiver: Mutex<Option<mpsc::Receiver<WorkerEvent>>>,
    // Private activity scheduling; true only immediately before main driving.
    pub(super) serving: AtomicBool,
    pub(super) ended: AtomicBool,
}

impl ControllerWorkerCustodyV1 {
    pub(super) fn close(&self, cause: ControllerResidentCauseV1) {
        self.ended.store(true, Ordering::Release);
        let Ok(mut terminal) = self.terminal.lock() else {
            std::process::abort();
        };
        if terminal.is_none() {
            *terminal = Some(cause);
        }
    }

    pub(super) fn terminate(&self, cause: ControllerResidentCauseV1) -> ! {
        self.close(cause);
        let Ok(terminal) = self.terminal.lock() else {
            std::process::abort();
        };
        let label = terminal.as_ref().map(ControllerResidentCauseV1::diagnostic);
        eprintln!("aos-sandboxd: {}", label.unwrap_or("resident Controller closed"));
        std::process::exit(1)
    }

    pub(super) fn receive(&self) -> ControllerMonitorOutcomeV1 {
        let Ok(receiver) = self.receiver.lock() else {
            self.close(ControllerResidentCauseV1::Closed("Controller receiver lock poisoned"));
            return ControllerMonitorOutcomeV1::Ended;
        };
        let Some(receiver) = receiver.as_ref() else {
            self.close(ControllerResidentCauseV1::Closed("Controller receiver unavailable"));
            return ControllerMonitorOutcomeV1::Ended;
        };
        match receiver.recv() {
            Ok(event) => ControllerMonitorOutcomeV1::Event(event),
            Err(cause) => {
                self.close(ControllerResidentCauseV1::Receive(cause));
                ControllerMonitorOutcomeV1::Ended
            }
        }
    }
}

pub(super) enum ControllerMonitorOutcomeV1 {
    Event(WorkerEvent),
    Ended,
}

// Ordinary startup retains its original Runtime value and disposal. Selected
// startup shares the exact admitted reactor with its physical readers; this
// carrier provides mechanics only and never substitutes for C/B admission.
pub(super) enum ControllerParentRuntimeV1 {
    Ordinary(tokio::runtime::Runtime),
    Shared(Arc<tokio::runtime::Runtime>),
}

impl std::ops::Deref for ControllerParentRuntimeV1 {
    type Target = tokio::runtime::Runtime;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Ordinary(runtime) => runtime,
            Self::Shared(runtime) => runtime,
        }
    }
}

// Same parent frame owns these partial I/O returns independently of the worker
// mutex. Selected termination intentionally precedes every normal field Drop.
pub(super) struct ControllerParentCustodyV1<A: ControllerServerAssembly> {
    pub(super) worker: Arc<ControllerWorkerCustodyV1>,
    pub(super) stage: ControllerParentStageV1,
    pub(super) launch: Option<Option<aos_sandbox_broker_session_security::controller_composition::Pid1LaunchImageV1>>,
    pub(super) runtime_receiving: bool,
    pub(super) node_read: aos_sandbox_linux::credential::FixedRoleCredentialReadV1,
    pub(super) cache_bundle_read: aos_sandbox_linux::credential::FixedRoleCredentialReadV1,
    pub(super) ownership_credentials: super::credential_receiving::CredentialAttemptV1<
        ControllerOwnershipConfigurationV1, super::ownership::ControllerOwnershipCredentialErrorV1,
    >,
    pub(super) attach_credentials: super::credential_receiving::CredentialAttemptV1<
        ControllerAttachCredentialsV1, super::attach_credentials::ControllerAttachCredentialErrorV1,
    >,
    pub(super) worker_signer_credentials: super::credential_receiving::CredentialAttemptV1<
        ControllerBrokerPlanSignerV1, super::plan_signer::ControllerBrokerPlanSignerError,
    >,
    pub(super) executor_signer_credentials: super::credential_receiving::CredentialAttemptV1<
        ControllerBrokerPlanSignerV1, super::plan_signer::ControllerBrokerPlanSignerError, 7,
    >,
    pub(super) pins_credentials: super::credential_receiving::CredentialAttemptV1<
        aos_sandbox_controller_domain::guest_root_publication::GuestRootTemplatePinsV1, super::guest_root_credentials::ControllerGuestRootCredentialErrorV1,
    >,
    pub(super) cache_readback_credentials: super::credential_receiving::CredentialAttemptV1<
        (), super::cache_readback_credential::CacheReadbackCredentialErrorV1,
    >,
    pub(super) hold_credentials: super::credential_receiving::CredentialAttemptV1<
        (), super::hold_credential::ControllerHoldCredentialErrorV1,
    >,
    pub(super) genesis_startup: Option<aos_sandbox_controller_domain::ControllerSourceGenesisReceivingV1>,
    pub(super) genesis_capture: Option<Result<(), ()>>,
    pub(super) runtime: Option<ControllerParentRuntimeV1>,
    pub(super) diagnostic_registration: Option<tokio::net::UnixListenerRegistrationAttempt>,
    pub(super) diagnostic: Option<A::DiagnosticListener>,
    pub(super) public_startup: A::PublicStartup,
    pub(super) public_credentials: Option<aos_sandbox_controller_domain::ControllerPublicTlsReceivingV1>,
    pub(super) public: Option<Option<A::PublicListener>>,
    pub(super) host_startup: Option<super::attachment_target::startup_identity::ControllerAttachmentStartupV1>,
    pub(super) mount_startup: Option<super::attachment_target::startup_identity::ControllerAttachmentStartupV1>,
    pub(super) host: Option<Option<aos_sandbox_controller_domain::runtime_scope::HostServiceIdentity>>,
    pub(super) mount: Option<Option<aos_sandbox_controller_domain::mount_preparation::MountServiceIdentity>>,
    pub(super) resource_opening: Option<aos_sandbox_controller_domain::ControllerResourceBankOpeningV1>,
    pub(super) controller_journal: aos_sandbox_controller_domain::journal::controller::ControllerJournalConstructionV1,
    pub(super) source_journal: aos_sandbox_controller_domain::source_domain::ControllerSourceJournalConstructionV1,
    pub(super) executor_signer: Option<Result<Option<ControllerBrokerPlanSignerV1>, ControllerRuntimeError>>,
    pub(super) lifecycle_replay: Option<Result<aos_sandbox_controller_domain::lifecycle::protected_journal::LifecycleProtectedJournalProjectionV1, ControllerRuntimeError>>,
    pub(super) project_recovery: Option<std::io::Result<()>>,
    pub(super) construction: Option<Result<(ControllerRequestScopeV1, NodeControllerLimits), ControllerRuntimeError>>,
    pub(super) notifier: Option<SystemdReadyNotifier>,
    pub(super) thread: Option<std::thread::JoinHandle<()>>,
    pub(super) monitor: Option<tokio::task::JoinHandle<ControllerMonitorOutcomeV1>>,
    pub(super) commands: Option<mpsc::SyncSender<ControllerCommand>>,
    pub(super) git_read_commands: Option<mpsc::SyncSender<ControllerCommand>>,
    pub(super) git_read: git_read_inspection::GitReadIngressV1,
}

impl<A: ControllerServerAssembly> ControllerParentCustodyV1<A> {
    pub(super) fn new(
        profile: Option<Arc<aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1>>,
        launch: Option<aos_sandbox_broker_session_security::controller_composition::Pid1LaunchImageV1>,
        resource_opening: Option<aos_sandbox_controller_domain::ControllerResourceBankOpeningV1>,
    ) -> Self {
        let runtime_receiving = resource_opening.is_some();
        Self {
            worker: Arc::new(ControllerWorkerCustodyV1 {
                originals: Mutex::new(ControllerWorkerOriginalsV1 {
                    profile: Some(profile),
                    ..ControllerWorkerOriginalsV1::default()
                }),
                terminal: Mutex::new(None),
                receiver: Mutex::new(None),
                serving: AtomicBool::new(false),
                ended: AtomicBool::new(false),
            }),
            stage: ControllerParentStageV1::Prepared,
            launch: Some(launch),
            runtime_receiving,
            node_read: aos_sandbox_linux::credential::FixedRoleCredentialReadV1::prearmed(),
            cache_bundle_read: aos_sandbox_linux::credential::FixedRoleCredentialReadV1::prearmed(),
            ownership_credentials: super::credential_receiving::CredentialAttemptV1::new(),
            attach_credentials: super::credential_receiving::CredentialAttemptV1::new(),
            worker_signer_credentials: super::credential_receiving::CredentialAttemptV1::new(),
            executor_signer_credentials: super::credential_receiving::CredentialAttemptV1::new_start_signer_v2(),
            pins_credentials: super::credential_receiving::CredentialAttemptV1::new(),
            cache_readback_credentials: super::credential_receiving::CredentialAttemptV1::new(),
            hold_credentials: super::credential_receiving::CredentialAttemptV1::new(),
            genesis_startup: None,
            genesis_capture: None,
            runtime: None,
            diagnostic_registration: None,
            diagnostic: None,
            public_startup: A::public_startup(),
            public_credentials: None,
            public: None,
            host_startup: None,
            mount_startup: None,
            host: None,
            mount: None,
            resource_opening,
            controller_journal: aos_sandbox_controller_domain::journal::controller::ControllerJournalConstructionV1::new(),
            source_journal: aos_sandbox_controller_domain::source_domain::ControllerSourceJournalConstructionV1::new(),
            executor_signer: None,
            lifecycle_replay: None,
            project_recovery: None,
            construction: None,
            notifier: None,
            thread: None,
            monitor: None,
            commands: None,
            git_read_commands: None,
            git_read: git_read_inspection::GitReadIngressV1::new(),
        }
    }
}

impl<A: ControllerServerAssembly> Drop for ControllerParentCustodyV1<A> {
    fn drop(&mut self) {
        self.worker.ended.store(true, Ordering::Release);
        std::process::abort();
    }
}

// This fence is placed AFTER newly pinned futures or a worker owner loan so it
// fires before their Drop. It cannot rescue already-unwound callee-local frames.
impl ControllerServerTerminal for ControllerWorkerCustodyV1 {
    fn runtime(&self, cause: ControllerRuntimeError) -> ! {
        self.terminate(ControllerResidentCauseV1::Runtime(cause))
    }

    fn closed(&self, cause: &'static str) -> ! {
        self.terminate(ControllerResidentCauseV1::Closed(cause))
    }
}

pub(super) struct AbortControllerCustodyUnwindV1;

impl Drop for AbortControllerCustodyUnwindV1 {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

pub(super) fn report_controller_worker_failure(
    events: &mpsc::Sender<WorkerEvent>,
    custody: Option<&ControllerWorkerCustodyV1>,
    cause: ControllerResidentCauseV1,
) {
    if let Some(owner) = custody {
        // Store the actual cause before allocating diagnostics or notifying.
        // The parent resolves a fixed marker without waiting on this owner loan.
        owner.close(cause);
        if let Err(cause) = events.send(WorkerEvent::ResidentFailure) {
            owner.close(ControllerResidentCauseV1::ReadySend(cause));
        }
    } else {
        let message = match cause {
            ControllerResidentCauseV1::Worker(message) => message,
            ControllerResidentCauseV1::Runtime(ControllerRuntimeError::SourceGenesisInput(cause)) => {
                cause.to_string()
            }
            ControllerResidentCauseV1::Runtime(ControllerRuntimeError::NormalRootProfile(cause)) => {
                cause.to_string()
            }
            _ => "controller worker closed".to_owned(),
        };
        let _ = events.send(WorkerEvent::Fatal(message));
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "Fixture construction and regression assertions intentionally panic."
    )]

    use super::*;

    // These vectors exercise DATA/negative bookkeeping and actual std channel
    // errors only. They do not construct a positive original startup owner.
    #[test]
    fn partial_controller_stage_cannot_skip_or_repeat_a_crossing() {
        let mut skipped = ControllerParentStageV1::Prepared;
        let mut repeated = ControllerParentStageV1::Prepared;
        let mut mismatched = ControllerParentStageV1::Prepared;
        let mut completed = ControllerParentStageV1::Prepared;

        assert!(!skipped.begin(ControllerParentStepV1::Node));
        assert!(!skipped.begin(ControllerParentStepV1::Publisher));

        assert!(repeated.begin(ControllerParentStepV1::Publisher));
        assert!(!repeated.begin(ControllerParentStepV1::Publisher));
        assert!(!repeated.complete(ControllerParentStepV1::Publisher));

        assert!(mismatched.begin(ControllerParentStepV1::Publisher));
        assert!(!mismatched.complete(ControllerParentStepV1::Node));
        assert!(!mismatched.complete(ControllerParentStepV1::Publisher));

        assert!(completed.begin(ControllerParentStepV1::Publisher));
        assert!(completed.complete(ControllerParentStepV1::Publisher));
        assert!(completed.begin(ControllerParentStepV1::Node));
        assert!(completed.complete(ControllerParentStepV1::Node));
        assert!(!completed.complete(ControllerParentStepV1::Node));
    }

    #[test]
    fn partial_optional_absence_does_not_create_a_worker_loan() {
        with_controller_fixture_stack(|| {
            let mut originals = ControllerWorkerOriginalsV1::default();
            assert!(originals.genesis.is_none());

            originals.genesis = Some(None);
            originals.nix_selector = Some(None);
            originals.cache_bundle = Some(None);
            originals.publisher_registration = Some(None);

            assert!(matches!(originals.genesis, Some(None)));
            assert!(originals.ready_loan().is_none());
            assert!(!originals.complete_worker_inputs(&ControllerParentStageV1::Prepared));
            assert!(!originals.complete_worker_inputs(&ControllerParentStageV1::Completed(
                ControllerParentStepV1::Commands,
            )));
        });
    }

    fn with_controller_fixture_stack(test: impl FnOnce() + Send + 'static) {
        // This test scaffold constructs an inline empty owner, returns it by
        // value through a helper, then stores it in a test local. The retained
        // production worker instead borrows the already allocated Arc owner.
        // Cover each fixture construction/move plane using its compiled size;
        // this is not evidence that production startup fits its stack budget.
        let fixture_planes = [
            std::mem::size_of::<ControllerWorkerOriginalsV1>(),
            std::mem::size_of::<Mutex<ControllerWorkerOriginalsV1>>(),
            std::mem::size_of::<ControllerWorkerCustodyV1>(),
            std::mem::size_of::<ControllerWorkerCustodyV1>(),
        ];
        let stack = fixture_planes
            .into_iter()
            .try_fold(
                aos_sandbox_controller_domain::CONTROLLER_RUNTIME_STACK_BYTES_V1,
                usize::checked_add,
            )
            .expect("Controller test fixture stack bound overflowed");

        std::thread::Builder::new()
            .name("controller-custody-fixture".to_owned())
            .stack_size(stack)
            .spawn(test)
            .unwrap()
            .join()
            .unwrap();
    }

    fn empty_controller_test_custody() -> ControllerWorkerCustodyV1 {
        ControllerWorkerCustodyV1 {
            originals: Mutex::new(ControllerWorkerOriginalsV1::default()),
            terminal: Mutex::new(None),
            receiver: Mutex::new(None),
            serving: AtomicBool::new(false),
            ended: AtomicBool::new(false),
        }
    }

    #[test]
    fn terminal_close_does_not_wait_on_the_worker_owner_loan() {
        with_controller_fixture_stack(|| {
            let custody = empty_controller_test_custody();
            let _owner_loan = custody.originals.lock().unwrap();
            let message = "original worker cause".to_owned();
            let original_buffer = message.as_ptr();

            custody.close(ControllerResidentCauseV1::Worker(message));
            custody.close(ControllerResidentCauseV1::Closed("later failure"));

            assert!(custody.ended.load(Ordering::Acquire));
            let terminal = custody.terminal.lock().unwrap();
            assert!(matches!(
                terminal.as_ref(),
                Some(ControllerResidentCauseV1::Worker(message))
                    if message.as_ptr() == original_buffer && message == "original worker cause"
            ));
        });
    }

    #[test]
    fn ready_send_failure_retains_the_actual_returned_send_error() {
        with_controller_fixture_stack(|| {
            let custody = empty_controller_test_custody();
            let (sender, receiver) = mpsc::channel();
            drop(receiver);
            let cause = match sender.send(WorkerEvent::Ready) {
                Err(cause) => cause,
                Ok(()) => panic!("disconnected actual channel unexpectedly accepted readiness"),
            };

            custody.close(ControllerResidentCauseV1::ReadySend(cause));

            let terminal = custody.terminal.lock().unwrap();
            assert!(matches!(
                terminal.as_ref(),
                Some(ControllerResidentCauseV1::ReadySend(mpsc::SendError(WorkerEvent::Ready)))
            ));
        });
    }

    #[test]
    fn original_event_receiver_stays_in_its_slot_after_reception() {
        with_controller_fixture_stack(|| {
            let custody = empty_controller_test_custody();
            let (sender, receiver) = mpsc::channel();
            *custody.receiver.lock().unwrap() = Some(receiver);
            assert!(sender.send(WorkerEvent::Ready).is_ok());

            let observed = custody.receive();

            assert!(matches!(
                observed,
                ControllerMonitorOutcomeV1::Event(WorkerEvent::Ready)
            ));
            assert!(custody.receiver.lock().unwrap().is_some());
            assert!(!custody.ended.load(Ordering::Acquire));
        });
    }

    #[test]
    fn selected_worker_failure_parks_cause_before_marker_notification() {
        with_controller_fixture_stack(|| {
            let custody = empty_controller_test_custody();
            let (sender, receiver) = mpsc::channel();
            let original = "original returned worker failure".to_owned();
            let original_buffer = original.as_ptr();

            report_controller_worker_failure(
                &sender,
                Some(&custody),
                ControllerResidentCauseV1::Worker(original),
            );

            assert!(matches!(receiver.recv(), Ok(WorkerEvent::ResidentFailure)));
            let terminal = custody.terminal.lock().unwrap();
            assert!(matches!(
                terminal.as_ref(),
                Some(ControllerResidentCauseV1::Worker(cause)) if cause.as_ptr() == original_buffer
            ));
            assert!(custody.ended.load(Ordering::Acquire));
        });
    }

    #[test]
    fn actual_partial_destination_types_are_send_and_shared_holder_is_sync() {
        fn require_send<T: Send>() {}
        fn require_sync<T: Sync>() {}

        require_send::<ControllerWorkerOriginalsV1>();
        require_send::<ControllerResidentCauseV1>();
        require_sync::<ControllerWorkerCustodyV1>();
    }

}
