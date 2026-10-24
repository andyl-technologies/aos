//! Receives the normal launch's donated startup objects through one engine.
//!
//! A real Component scope is issued from the same authenticated Host1, sealed
//! ordinary Agent record and canonical Guardian binding. Report bytes alone
//! cannot construct that scope, a workload loan, or backend readiness.

use super::*;
use crate::broker::component_startup::ComponentStartupReportScopeV2;
use aos_sandbox_linux::seqpacket::{RecordSubjectSeqpacketPairOriginalV2, StorageSeqpacketSendAttemptV1};

pub(super) enum StartupReportReceivingV2<'scope, 'call, 'original> {
    Canary(&'scope mut crate::broker::canary_job::HostCanaryJobOwnerV1),
    Component(&'scope ComponentStartupReportScopeV2,
        &'scope launch::HostLaunchWorkerReceivingV2<'call, 'original>),
}

impl StartupReportReceivingV2<'_, '_, '_> {
    pub(super) fn is_component_v2(&self) -> bool { matches!(self, Self::Component(..)) }

    pub(super) fn require_current_v2(&mut self) -> std::result::Result<(), CanaryPayloadFailureV1> {
        match self {
            Self::Canary(job) => job.recheck().map(|_| ()),
            Self::Component(scope, receiving) => receiving.require_component_startup_report_v2(scope),
        }.map_err(CanaryPayloadFailureV1::from)
    }

    pub(super) fn require_deadline_v2(&self) -> std::result::Result<(), CanaryPayloadFailureV1> {
        match self {
            Self::Canary(job) => super::systemd::require_canary_deadline(job),
            Self::Component(scope, _) => scope.require_deadline_v2().map_err(CanaryPayloadFailureV1::from),
        }
    }
}

impl HostCanaryPayloadReadbackV1 {
    // A loaded-filter failure prevents Guest creation. Diagnose that real
    // consumed report now rather than wait for bootstrap roles that cannot
    // exist. This is a negative-only branch of the same canonical parser.
    pub(super) fn require_component_program_error_prefix_v2(
        &mut self,
        scope: &ComponentStartupReportScopeV2,
    ) -> std::result::Result<(), CanaryPayloadFailureV1> {
        let program = self.program_report.as_ref().ok_or(CanaryPayloadFailureV1::Mismatch)?;
        if program.payload().len() != 184
            || program.payload()[..12] != *b"AOSNHR01\0\x01\0\x09"
        {
            return Ok(());
        }
        let supervisor = self.reports[0].as_ref().ok_or(CanaryPayloadFailureV1::Mismatch)?;
        let original = supervisor.payload();
        let socket = self.report_socket.as_mut().ok_or(CanaryPayloadFailureV1::Mismatch)?;
        socket.require_host_canary_report_original_v1(supervisor)?;
        socket.require_host_canary_response_original_v1(program)?;
        if original.len() != 176 || original[..12] != *b"AOSNHR01\0\x01\0\x01"
            || original[12..16] != 176_u32.to_be_bytes()
            || original[16..160] != scope.challenge_v2()[16..160]
            || original[160..176] != [0; 16]
            || supervisor.subject().initial_info() != program.subject().initial_info()
        {
            return Err(CanaryPayloadFailureV1::Mismatch);
        }
        super::systemd::require_reported_program_error_v2(program.payload(), original, *b"AOSNHR01")
    }
}

/// Retains one actual normal report channel, native reports and image opens.
pub(crate) struct HostComponentStartupReportOriginalV2 {
    readback: HostCanaryPayloadReadbackV1,
    pair: RecordSubjectSeqpacketPairOriginalV2,
    pin: Option<std::io::Result<aos_systemd_client::SandboxDescriptorPath>>,
    spec_pin: Option<std::result::Result<(), aos_systemd_client::Error>>,
    root_duplicate: Option<std::io::Result<OwnedFd>>,
    root: aos_sandbox_linux::path::BeneathRootOwnedOriginalV2,
    scope: Option<ComponentStartupReportScopeV2>,
    sends: [Option<StorageSeqpacketSendAttemptV1>; 3],
    send_gates: [Option<HostError>; 3],
    clock_refused: bool,
    original_selected: bool,
    preparation: Option<Result<()>>,
    agent_binding: Option<std::result::Result<(), crate::live_agent::CanaryAgentFailureV1>>,
    challenges: Option<Result<()>>,
    verification: Option<std::result::Result<RuntimeProofSnapshot, CanaryPayloadFailureV1>>,
}

impl HostComponentStartupReportOriginalV2 {
    pub(crate) fn new() -> Self {
        let mut readback = HostCanaryPayloadReadbackV1::new();
        readback.component_report = true;
        readback.originals = aos_sandbox_linux::pidfd::HostCanaryReceivedChildOriginalsV1::component_startup_v2();
        Self {
            readback,
            pair: RecordSubjectSeqpacketPairOriginalV2::new(),
            pin: None,
            spec_pin: None,
            root_duplicate: None,
            root: aos_sandbox_linux::path::BeneathRootOwnedOriginalV2::new(),
            scope: None,
            sends: std::array::from_fn(|_| None),
            send_gates: std::array::from_fn(|_| None),
            clock_refused: false,
            original_selected: false,
            preparation: None,
            agent_binding: None,
            challenges: None,
            verification: None,
        }
    }

    pub(crate) fn prepare_channel_once_v2(&mut self, payload: &mut crate::plan::PreparedLaunch) -> Result<()> {
        if self.preparation.is_some() {
            return Err(closed("component startup channel is already entered"));
        }
        self.preparation = Some((|| {
            self.pair.prepare_retaining_v2().map_err(|_| closed("component report pair failed; cause retained"))?;
            self.readback.report_socket = Some(self.pair.take_parent_socket()
                .map_err(|_| closed("component report parent transfer refused; pair retained"))?);
            self.readback.child_channel = Some(self.pair.take_child_endpoint()
                .map_err(|_| closed("component report child transfer refused; pair retained"))?);
            let report = self.readback.child_channel.as_ref()
                .ok_or(closed("component report child endpoint is absent"))?;
            self.spec_pin = Some(payload.pin_component_startup_report_v2(report.as_fd(), &mut self.pin));
            if !matches!(self.spec_pin, Some(Ok(()))) {
                return Err(closed("component report role pin refused; original retained"));
            }
            Ok(())
        })());
        if matches!(self.preparation, Some(Ok(()))) { Ok(()) }
        else { Err(closed("component startup preparation failed; originals retained")) }
    }

    pub(crate) fn send_challenges_once_v2(
        &mut self,
        scope: ComponentStartupReportScopeV2,
        receiving: &crate::plan::HostExecutionReceivingLoanV2<'_>,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        clock: &mut crate::broker::ArgumentClockV2,
    ) -> Result<()> {
        if !matches!(self.preparation, Some(Ok(()))) || self.challenges.is_some() || self.scope.is_some() {
            return Err(closed("component startup challenge was already entered or lacks its channel"));
        }
        self.scope = Some(scope);
        self.challenges = Some((|| {
            let scope = self.scope.as_ref().ok_or(closed("component report scope is absent"))?;
            scope.require_request_v2(request)?;
            let socket = self.readback.report_socket.as_mut().ok_or(closed("component report socket is absent"))?;
            for index in 0..3 {
                let mut gate = || {
                    if let Err(cause) = receiving.require_launch_request_v2(request) {
                        self.original_selected = receiving.component_report_original_failure_entered_v2();
                        return Err(cause);
                    }
                    scope.require_deadline_v2()?;
                    let result = clock.sample_component_report_write_v2();
                    if result.is_err() { self.clock_refused = true; }
                    result
                };
                let (attempt, refused) = socket.send_agent_handshake_retaining_v3(scope.challenge_v2(), &mut gate);
                self.sends[index] = Some(attempt);
                self.send_gates[index] = refused;
                if self.send_gates[index].is_some()
                    || !self.sends[index].as_ref().is_some_and(StorageSeqpacketSendAttemptV1::is_sent)
                {
                    return Err(closed("component report challenge refused; native receipts retained"));
                }
            }
            Ok(())
        })());
        if matches!(self.challenges, Some(Ok(()))) { Ok(()) }
        else { Err(closed("component report challenge failed; originals retained")) }
    }

    pub(crate) async fn verify_once_v2(
        &mut self,
        payload: &crate::plan::PreparedLaunch,
        proof: &BoundPayloadVerification,
        programs: &[u8],
        receiving: &launch::HostLaunchWorkerReceivingV2<'_, '_>,
    ) -> Result<()> {
        if self.verification.is_some() || !matches!(self.challenges, Some(Ok(()))) {
            return Err(closed("component report verification is already entered or lacks its challenge"));
        }
        self.verification = Some(self.verify_inner_v2(payload, proof, programs, receiving).await);
        if self.verification.as_ref().is_some_and(|result| result.is_err()) {
            self.original_selected = receiving.component_report_original_failure_entered_v2();
        }
        if matches!(self.verification, Some(Ok(_))) { Ok(()) }
        else { Err(closed("component startup proof refused; originals retained")) }
    }

    async fn verify_inner_v2(
        &mut self,
        payload: &crate::plan::PreparedLaunch,
        proof: &BoundPayloadVerification,
        programs: &[u8],
        receiving: &launch::HostLaunchWorkerReceivingV2<'_, '_>,
    ) -> std::result::Result<RuntimeProofSnapshot, CanaryPayloadFailureV1> {
        let scope = self.scope.as_ref().ok_or(CanaryPayloadFailureV1::Mismatch)?;
        receiving.require_component_startup_report_v2(scope)?;
        self.readback.receive_original_reports_engine_v2(
            StartupReportReceivingV2::Component(scope, receiving),
        ).await?;
        self.readback.capture_received_originals()?;
        let header = self.readback.originals.original_report_header()?;
        if header[..10] != scope.challenge_v2()[..10]
            || header[16..160] != scope.challenge_v2()[16..160]
            || header[12..16] != 176_u32.to_be_bytes()
            || proof.binding != payload.spec().launch_binding()
        { return Err(CanaryPayloadFailureV1::Mismatch); }
        let boot = scope.boot_v2();
        self.readback.require_loaded_programs_engine_v2(programs, *b"AOSNHR01")?;
        self.readback.require_supervisor_and_root_engine_v2(payload.pins(), &proof.observation)?;
        self.capture_images_v2(payload.pins())?;
        self.readback.require_original_images()?;
        let observed = self.readback.original_proof_engine_v2(payload.pins(), boot)?;
        if observed != proof.proof { return Err(CanaryPayloadFailureV1::Mismatch); }
        let socket = self.readback.report_socket.as_mut().ok_or(CanaryPayloadFailureV1::Mismatch)?;
        self.readback.originals.recheck_original(socket)?;
        self.readback.require_original_images()?;
        let scope = self.scope.as_ref().ok_or(CanaryPayloadFailureV1::Mismatch)?;
        receiving.require_component_startup_report_v2(scope)?;
        scope.require_deadline_v2()?;
        Ok(observed)
    }

    fn capture_images_v2(&mut self, pins: &LaunchPins) -> std::result::Result<(), CanaryPayloadFailureV1> {
        self.root_duplicate = Some(pins.workspace().try_clone_to_owned());
        let descriptor = match self.root_duplicate.take() {
            Some(Ok(descriptor)) => descriptor,
            Some(Err(cause)) => {
                self.root_duplicate = Some(Err(cause));
                return Err(CanaryPayloadFailureV1::Mismatch);
            }
            None => return Err(CanaryPayloadFailureV1::Mismatch),
        };
        self.root.from_owned_once(descriptor)?;
        self.readback.workspace = self.root.take_completed_once();
        let root = self.readback.workspace.as_ref().ok_or(CanaryPayloadFailureV1::Mismatch)?;
        for (original, path) in self.readback.component_images.iter_mut().zip([
            "usr/libexec/aos-sandbox-guest-init", "usr/libexec/aos-sandbox-guest-agent", "usr/lib/systemd/systemd",
        ]) {
            original.open_regular_once_v1(root, Path::new(path))?;
        }
        Ok(())
    }

    pub(crate) fn bind_actual_agent_once_v2(
        &mut self,
        agent: &crate::live_agent::launch_original::HostAgentLaunchOriginalV2,
    ) -> Result<()> {
        if !matches!(self.verification, Some(Ok(_))) || self.agent_binding.is_some() {
            return Err(closed("component report Agent join is already entered or lacks its native proof"));
        }
        let socket = self.readback.report_socket.as_mut().ok_or(closed("component report socket is absent"))?;
        self.agent_binding = Some(agent.require_component_report_agent_v2(&mut self.readback.originals, socket));
        if !matches!(self.agent_binding, Some(Ok(()))) {
            return Err(closed("component report Agent differs from the actual handshake; cause retained"));
        }
        Ok(())
    }

    pub(crate) fn receiving_demand_v2() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_linux::seqpacket::SeqpacketSocket;
        let (pair_bytes, pair_files) = RecordSubjectSeqpacketPairOriginalV2::receiving_obligations_v2()?;
        let (program_bytes, program_files) = SeqpacketSocket::component_startup_program_receive_obligations_v2(98_504)?;
        let mut report_bytes = 0_usize;
        let mut receive_files = program_files;
        for rights in [3, 5, 5, 1, 5, 5, 1] {
            let (bytes, files) = SeqpacketSocket::component_startup_report_receive_obligations_v2(176, rights)?;
            report_bytes = report_bytes.checked_add(bytes)?;
            receive_files = receive_files.max(files);
        }
        let donated_bytes = aos_sandbox_linux::pidfd::HostCanaryReceivedChildOriginalsV1::component_receiving_bytes_v2()?;
        let mut path_bytes = 0_usize;
        for path in ["usr/libexec/aos-sandbox-guest-init", "usr/libexec/aos-sandbox-guest-agent", "usr/lib/systemd/systemd"] {
            let quote = aos_sandbox_linux::path::BeneathRegularFileOpenOriginalV2::receiving_obligations_v2(path.len())?;
            path_bytes = path_bytes.checked_add(quote.0)?;
        }
        let root = aos_sandbox_linux::path::BeneathRootOwnedOriginalV2::receiving_obligations_v2()?;
        let guest = aos_sandbox_linux::guest_startup_report::GuestStartupReportOriginalV1::receiving_obligations_v1()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(pair_bytes)?.checked_add(program_bytes)?.checked_add(report_bytes)?
            .checked_add(donated_bytes)?.checked_add(path_bytes)?.checked_add(root.0)?
            .checked_add(aos_systemd_client::SandboxDescriptorPath::construction_receiving_bytes_v2()?)?
            .checked_add(SeqpacketSocket::agent_effect_send_receiving_bytes_v4()?.checked_mul(3)?)?
            .checked_add(guest.0)?;
        // Seven successful records retain25 rights and7 subject pidfds. A
        // later hostile native envelope, its exact preview and original socket
        // may coexist; only the native envelope peak is shared across flights.
        let files = 25_usize.checked_add(7)?.checked_add(receive_files)?
            .checked_add(pair_files)?.checked_add(1)?.checked_add(4)?.checked_add(guest.1)?;
        let traffic = 3_usize.checked_mul(200)?.checked_add(7 * 176)?.checked_add(98_504)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            // Host opens three actual rooted image names and one proc FD alias.
            // Donated proc descriptors add no new Host namespace entries.
            .with(D::MetadataEntries, u64::try_from(guest.2.checked_add(4)?).ok()?)
            .with(D::NetworkBytes, u64::try_from(traffic).ok()?)
            .with(D::OutputBytes, 600))
    }

    pub(crate) fn require_verified_v2(&self, proof: &BoundPayloadVerification) -> Result<()> {
        if !matches!(self.agent_binding, Some(Ok(())))
            || !self.verification.as_ref().is_some_and(|result| result.as_ref().is_ok_and(|actual| *actual == proof.proof)) {
            return Err(closed("component donated startup proof is incomplete"));
        }
        Ok(())
    }

    pub(crate) fn require_completed_for_disposal_v2(&self) -> Result<()> {
        if !matches!(self.preparation, Some(Ok(())))
            || !matches!(self.challenges, Some(Ok(())))
            || !matches!(self.verification, Some(Ok(_)))
            || !matches!(self.agent_binding, Some(Ok(())))
            || self.send_gates.iter().any(Option::is_some)
            || self.sends.iter().any(|attempt| !attempt.as_ref().is_some_and(StorageSeqpacketSendAttemptV1::is_sent))
        {
            return Err(closed("component report acquisition lacks whole positive completion"));
        }
        Ok(())
    }

    pub(crate) fn challenge_clock_failed_v2(&self) -> bool {
        self.clock_refused
    }

    pub(crate) fn selected_original_failure_v2(&self) -> bool { self.original_selected }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.pair.failure().map(|cause| cause as _)
            .or_else(|| self.pin.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.spec_pin.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.preparation.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.sends.iter().enumerate().find_map(|(index, attempt)| {
                self.send_gates[index].as_ref().map(|cause| cause as _)
                    .or_else(|| attempt.as_ref()?.failure())
            }))
            .or_else(|| self.challenges.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.readback.receive_failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.root_duplicate.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.root.failure().map(|cause| cause as _))
            .or_else(|| self.verification.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.agent_binding.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

fn closed(message: &'static str) -> HostError { HostError::Fence(message) }
