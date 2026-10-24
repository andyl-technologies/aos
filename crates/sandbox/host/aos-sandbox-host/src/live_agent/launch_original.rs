//! Retains the native and signed handshake of the actual paid Host launch.
//!
//! These destinations carry no launch authority. Their only production caller
//! borrows the same admitted HostLaunch phase and keeps the actual pending
//! channel until Guardian completion and the authenticated Guest proof agree.

use std::error::Error;

use super::{AgentHandshakeRequestV1, AgentHandshakeResponseV1,
    AgentOperationSequenceV1, AgentSessionBindingV1, HostAgentLiveErrorV1};
use super::execution_original::AgentExecutionOriginalV2;

pub(super) struct AuthenticatedHandshakeV2 {
    pub(super) handshake: AgentHandshakeRequestV1,
    pub(super) response: AgentHandshakeResponseV1,
    pub(super) binding: AgentSessionBindingV1,
    pub(super) next_sequence: AgentOperationSequenceV1,
}

pub(crate) struct HostAgentHandshakeOriginalV2 {
    pub(super) io: AgentExecutionOriginalV2,
    pub(super) handshake: Option<AgentHandshakeRequestV1>,
    pub(super) response: Option<AgentHandshakeResponseV1>,
    pub(super) send_bytes: Vec<u8>,
    pub(super) send_attempts: [Option<super::send_original::AgentSendAttemptV4>;
        super::MAXIMUM_HANDSHAKE_WRITE_ATTEMPTS_V3],
    returned: Option<Result<AuthenticatedHandshakeV2, HostAgentLiveErrorV1>>,
    entered: bool,
}

impl HostAgentHandshakeOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            io: AgentExecutionOriginalV2::new(),
            handshake: None, response: None, send_bytes: Vec::new(),
            send_attempts: std::array::from_fn(|_| None),
            returned: None, entered: false,
        }
    }

    // The authenticated response has sixteen fixed feature octets at most;
    // this bounds the actual raw receiver before allocation, not a role grant.
    pub(crate) fn receiving_demand_v2() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_guest_protocol::protocol::{AGENT_HANDSHAKE_REQUEST_BYTES_V2,
            MAX_AGENT_HANDSHAKE_RESPONSE_BYTES_V2};
        let (native_bytes, files) = aos_sandbox_linux::seqpacket::SeqpacketSocket
            ::closed_zero_rights_receive_obligations_v1(MAX_AGENT_HANDSHAKE_RESPONSE_BYTES_V2)?;
        let (guest_native_bytes, guest_files) = aos_sandbox_linux::seqpacket::SeqpacketSocket
            ::guest_initial_handshake_receive_obligations_v2(AGENT_HANDSHAKE_REQUEST_BYTES_V2)?;
        // The normal7/8 profile enters this native receive immediately after
        // handshake, before a future paid Accept20 can exist. Launch pays the
        // actual receiver and inert argument helper before Guest construction.
        let (operation_receive, operation_files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::
            agent_authorize_receive_obligations_v2(aos_sandbox_guest_protocol::protocol::MAX_AGENT_FRAME_BYTES)?;
        let argument_controls = aos_sandbox_guest_protocol::argument_receiving::argument_guest_receiving_bytes_v1()?;
        let guest_startup = aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1
            ::whole_guest_startup_obligations_v1(guest_files)?;
        // This selected parent was native descriptor-free before exposure;
        // the child direction keeps its real descriptor-bearing Authorize path.
        // The two inline receipts own the same socket on refusal, rather than
        // another duplicate. Three owner planes cover resident, return and
        // construction carriers, including both raw cookie Results per send.
        let bytes = native_bytes
            .checked_add(operation_receive)?.checked_add(argument_controls)?
            .checked_add(6 * std::mem::size_of::<Option<(usize, usize)>>())?
            .checked_add(6 * std::mem::size_of::<Option<usize>>())?
            .checked_add(8 * std::mem::size_of::<usize>())?
            .checked_add(guest_native_bytes)?
            // The actual Guest control-header assertion includes the complete
            // selected handshake original. This is prospective source payment
            // before Guest launch, independent of later Authorize residency.
            .checked_add(aos_sandbox_guest_protocol::capture_receiving::CAPTURE_GUEST_CONTROL_BYTES_V2)?
            .checked_add(std::mem::size_of::<Self>().checked_mul(3)?)?
            .checked_add(AGENT_HANDSHAKE_REQUEST_BYTES_V2.checked_mul(4)?)?
            .checked_add(MAX_AGENT_HANDSHAKE_RESPONSE_BYTES_V2.checked_mul(4)?)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files.checked_add(guest_startup.1)?.checked_add(operation_files)?).ok()?)
            .with(D::NetworkBytes, u64::try_from(AGENT_HANDSHAKE_REQUEST_BYTES_V2
                .checked_add(MAX_AGENT_HANDSHAKE_RESPONSE_BYTES_V2)?).ok()?)
            .with(D::OutputBytes, u64::try_from(AGENT_HANDSHAKE_REQUEST_BYTES_V2).ok()?))
    }

    pub(crate) fn authenticate_once(
        &mut self,
        pending: &mut super::HostAgentPendingSessionV1,
        claim: &super::DormantRuntimeExecutionClaimV1<'_>,
        deadline: std::time::Instant,
        before_native_write: &mut dyn FnMut() -> Result<(), HostAgentLiveErrorV1>,
    ) -> Result<(), HostAgentLiveErrorV1> {
        if self.entered {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        self.entered = true;
        self.returned = Some(pending.authenticate_engine(claim, deadline, Some(&mut *self), Some(before_native_write)));
        if matches!(self.returned, Some(Ok(_))) {
            Ok(())
        } else {
            Err(HostAgentLiveErrorV1::RecoveryRequired)
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.send_attempts.iter().flatten()
            .filter(|attempt| !attempt.native.is_nonconsuming()
                || !matches!(self.io.sent, Some(Ok(()))))
            .find_map(super::send_original::AgentSendAttemptV4::failure)
            .or_else(|| self.io.failure())
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

// The seed/private-key policy stays the existing root-owned directory/leaf
// recipe. This owner adds no path, key, validation or Session constructor.
pub(super) struct CredentialOriginalV2 {
    // Zeroize secret input before closing the actual leaf and directory.
    pub(super) bytes: zeroize::Zeroizing<Vec<u8>>,
    pub(super) read: Option<std::io::Result<()>>,
    pub(super) metadata: Option<std::io::Result<std::fs::Metadata>>,
    pub(super) file: Option<Result<std::fs::File, rustix::io::Errno>>,
    pub(super) directory_metadata: Option<std::io::Result<std::fs::Metadata>>,
    pub(super) directory: Option<Result<std::fs::File, rustix::io::Errno>>,
}

impl CredentialOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            bytes: zeroize::Zeroizing::new(Vec::new()), read: None,
            metadata: None, file: None, directory_metadata: None, directory: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.directory).or_else(|| error(&self.directory_metadata))
            .or_else(|| error(&self.file)).or_else(|| error(&self.metadata))
            .or_else(|| error(&self.read))
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

/// Owns the real pre-Guardian Agent setup until the same launch completes.
///
/// Construction requires the actual consumed HostLaunch borrower. It is an
/// owning destination, never a reusable permission or a key/socket factory.
pub(crate) struct HostAgentLaunchOriginalV2 {
    pub(crate) prepared: Option<crate::plan::PreparedLaunch>,
    seed_read: CredentialOriginalV2,
    seed: Option<super::HostAgentProtectedSeedV1>,
    trust_reads: [crate::attach_route::HostLaunchTrustOriginalV2; 2],
    trust_pins: [Option<crate::attach_route::HostOpenSshStaticTrustV1>; 2],
    private_read: CredentialOriginalV2,
    attach_trust: Option<super::HostAgentProtectedAttachTrustV1>,
    record: Option<super::GuestAgentLaunchRecordV1>,
    pair: aos_sandbox_linux::seqpacket::RecordSubjectSeqpacketPairOriginalV2,
    provisioning_bytes: zeroize::Zeroizing<Vec<u8>>,
    attach_bytes: zeroize::Zeroizing<Vec<u8>>,
    seal: [aos_linux_descriptors::credential::SealedReadOnlyCredentialCreateOriginalsV1; 2],
    guest: Option<super::HostAgentGuestLaunchDescriptorsV1>,
    pub(crate) pending: Option<super::HostAgentPendingSessionV1>,
    pins: aos_systemd_client::SandboxGuestAgentPinOriginalV2,
    pub(crate) handshake: HostAgentHandshakeOriginalV2,
    pub(crate) authenticated: Option<super::HostAgentLiveSessionV1>,
    setup_result: Option<Result<(), HostAgentLiveErrorV1>>,
    setup_entered: bool,
    frontier: SetupFrontierV2,
    first: Option<SetupFrontierV2>,
}

#[derive(Clone, Copy)]
enum SetupFrontierV2 { Seed, Trust, Private, Pair, Provisioning, TrustSeal, Pins, Handshake }

impl HostAgentLaunchOriginalV2 {
    pub(crate) fn new(receiving: &crate::plan::HostExecutionReceivingLoanV2<'_>)
        -> Result<Self, HostAgentLiveErrorV1>
    {
        receiving.require_launch_current_v2()
            .map_err(|_| HostAgentLiveErrorV1::RecoveryRequired)?;
        Ok(Self {
            prepared: None, seed_read: CredentialOriginalV2::new(), seed: None,
            trust_reads: std::array::from_fn(|_| crate::attach_route::HostLaunchTrustOriginalV2::new()),
            trust_pins: [None, None], private_read: CredentialOriginalV2::new(),
            attach_trust: None, record: None,
            pair: aos_sandbox_linux::seqpacket::RecordSubjectSeqpacketPairOriginalV2::zero_rights_parent_v1(),
            provisioning_bytes: zeroize::Zeroizing::new(Vec::new()),
            attach_bytes: zeroize::Zeroizing::new(Vec::new()),
            seal: std::array::from_fn(|_| aos_linux_descriptors::credential::SealedReadOnlyCredentialCreateOriginalsV1::new()),
            guest: None, pending: None, pins: aos_systemd_client::SandboxGuestAgentPinOriginalV2::new(),
            handshake: HostAgentHandshakeOriginalV2::new(), authenticated: None,
            setup_result: None, setup_entered: false, frontier: SetupFrontierV2::Seed, first: None,
        })
    }

    pub(crate) fn receiving_demand_v2() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let (pair_bytes, pair_files) = aos_sandbox_linux::seqpacket::RecordSubjectSeqpacketPairOriginalV2
            ::receiving_obligations_v2()?;
        let (pin_bytes, pin_files) = aos_systemd_client::SandboxGuestAgentPinOriginalV2::receiving_footprint_v2()?;
        let mut demand = HostAgentHandshakeOriginalV2::receiving_demand_v2()?;
        let (_, guest_initial_files) = aos_sandbox_linux::seqpacket::SeqpacketSocket
            ::guest_initial_handshake_receive_obligations_v2(
                aos_sandbox_guest_protocol::protocol::AGENT_HANDSHAKE_REQUEST_BYTES_V2)?;
        let topology = aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1
            ::whole_guest_startup_obligations_v1(guest_initial_files)?;
        // The same Launch pays before any Guest exists. This is a fixed native
        // startup/whole-Guest source, separate from each later Accept's SSH
        // subtree. A failed topology keeps its original occupied to Guest death.
        demand = demand.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(topology.0).ok()?)
            // Whole Guest startup native files join the same handshake phase
            // above, once; these two actual tasks are PID1 and its Agent.
            .with(D::Pids, 2)
            .with(D::TmpfsBytes, 64)
            // One fixed eight-byte completion flight, with one native write
            // and no retry. The matching parent read creates no second flight.
            .with(D::NetworkBytes, 8)
            .with(D::OutputBytes, 8)
            .with(D::MetadataEntries, u64::try_from(topology.2).ok()?)).ok()?;
        let credentials = super::SEED_CREDENTIAL_BYTES.checked_add(
            usize::try_from(super::MAX_ATTACH_PRIVATE_KEY_BYTES).ok()?)?.checked_add(2 * 2049)?;
        // Actual native inputs, decoded trust/key and encoded provisioning/trust
        // planes coexist. The original buffers and dominant models are paid
        // independently of transient descriptor and seal construction carriers.
        let bytes = std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(pair_bytes)?.checked_add(pin_bytes)?
            .checked_add(credentials.checked_mul(4)?)?
            .checked_add(super::PROVISIONING_BYTES.checked_mul(2)?)?
            .checked_add(super::MAX_GUEST_ATTACH_TRUST_BYTES.checked_mul(2)?)?;
        demand = demand.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            // Seed and private-key directory/leaf pairs plus two trust leaves.
            .with(D::OpenFiles, u64::try_from(pair_files.checked_add(pin_files)?.checked_add(6)?).ok()?))
            .ok()?;
        for (name, maximum) in [
            ("aos-sandbox-agent-provisioning-v1", super::PROVISIONING_BYTES),
            ("aos-sandbox-guest-attach-trust-v1", super::MAX_GUEST_ATTACH_TRUST_BYTES),
        ] {
            let seal = aos_linux_descriptors::credential::SealedReadOnlyCredentialCreateOriginalsV1
                ::receiving_footprint_v1(name.len(), maximum)?;
            demand = demand.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(seal.memory_bytes).ok()?)
                .with(D::OpenFiles, u64::try_from(seal.open_files).ok()?)).ok()?;
        }
        Some(demand)
    }

    pub(crate) fn guest_runtime_baseline_files_v1() -> usize {
        aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1::agent_resident_files_v1()
    }

    pub(crate) fn guest_startup_retained_files_v1() -> Option<usize> {
        use aos_sandbox_guest_protocol::protocol::AGENT_HANDSHAKE_REQUEST_BYTES_V2;
        let (_, initial) = aos_sandbox_linux::seqpacket::SeqpacketSocket
            ::guest_initial_handshake_receive_obligations_v2(AGENT_HANDSHAKE_REQUEST_BYTES_V2)?;
        // The signed handshake is sent before the Guest drops its initial
        // receipt. Sent alone cannot establish that physical drop; keep its
        // complete source until a later genuine same-Agent disposal proof.
        Self::guest_runtime_baseline_files_v1()
            .checked_add(aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1::pid1_resident_files_v1())?
            .checked_add(aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1::pid1_completion_files_v1()?)?
            // There is no remote proof at Sent that the parent's fixed null
            // stdio/exec-error pipe prefix already retired after child exec.
            .checked_add(3 + 2)?.checked_add(initial)
    }

    pub(crate) fn prepare_once(
        &mut self,
        claim: &super::DormantRuntimeExecutionClaimV1<'_>,
        assignment: &aos_sandbox_protocol::ValidatedAssignmentFence,
        prepared: &mut Option<crate::plan::PreparedLaunch>,
        features: aos_sandbox_guest_protocol::AgentFeatureSetV1,
        receiving: &crate::plan::HostExecutionReceivingLoanV2<'_>,
    ) -> Result<(), HostAgentLiveErrorV1> {
        // A refused reentry leaves the incoming payload on its parent. Once
        // accepted, only an owning move precedes the first fallible check.
        if self.setup_entered || self.prepared.is_some() || prepared.is_none() {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        self.setup_entered = true;
        self.prepared = prepared.take();
        self.setup_result = Some(self.prepare_engine(claim, assignment, features, receiving));
        if self.setup_result.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(self.frontier);
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        Ok(())
    }

    fn prepare_engine(
        &mut self,
        claim: &super::DormantRuntimeExecutionClaimV1<'_>,
        assignment: &aos_sandbox_protocol::ValidatedAssignmentFence,
        features: aos_sandbox_guest_protocol::AgentFeatureSetV1,
        receiving: &crate::plan::HostExecutionReceivingLoanV2<'_>,
    ) -> Result<(), HostAgentLiveErrorV1> {
        use super::*;
        receiving.require_launch_current_v2().map_err(|_| HostAgentLiveErrorV1::RecoveryRequired)?;
        let package = self.prepared.as_ref().and_then(PreparedLaunch::guest_package_binding)
            .ok_or(HostAgentLiveErrorV1::Binding)?;
        if self.prepared.as_ref().and_then(PreparedLaunch::guest_feature_mask)
            != Some(aos_sandbox_guest_protocol::guest_root_publication::CONCRETE_GUEST_FEATURE_MASK_V1)
        { return Err(HostAgentLiveErrorV1::Binding); }

        self.frontier = SetupFrontierV2::Seed;
        self.seed = Some(HostAgentProtectedSeedV1::open_receiving_v2(claim, &mut self.seed_read, receiving)?);
        self.frontier = SetupFrontierV2::Trust;
        claim.revalidate()?;
        let runtime = agent_runtime(claim.currentness())?;
        self.trust_pins[0] = Some(HostOpenSshStaticTrustV1::load_receiving_v2(&mut self.trust_reads[0], receiving)
            .map_err(|_| HostAgentLiveErrorV1::AttachTrustUnavailable)?);
        self.frontier = SetupFrontierV2::Private;
        read_root_owned_credential_engine(ATTACH_PRIVATE_KEY_FILE, 1, MAX_ATTACH_PRIVATE_KEY_BYTES,
            Some(&mut self.private_read)).map_err(|()| HostAgentLiveErrorV1::AttachTrustUnavailable)?;
        let pins = self.trust_pins[0].as_ref().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?;
        let record = GuestAttachTrustRecordV1::new(runtime,
            std::mem::take(&mut *self.private_read.bytes),
            pins.host_public_key().as_bytes().to_vec(), pins.trusted_user_ca_public_key().as_bytes().to_vec())?;
        claim.revalidate()?;
        self.attach_trust = Some(HostAgentProtectedAttachTrustV1 {
            record, trust_digest: pins.credential_digest(), runtime,
        });
        self.frontier = SetupFrontierV2::Seed;
        self.record = Some(self.seed.as_ref().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?
            .launch_record_engine(features, aos_sandbox_model::ObjectDigest::from_bytes(package))?);
        claim.revalidate()?;
        if !matches_assignment(claim, assignment) { return Err(HostAgentLiveErrorV1::Binding); }
        let currentness = *claim.currentness();
        let peer = claim.agent_peer();
        let record = self.record.as_ref().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?;
        require_launch_record_v2(claim, record)?;

        self.frontier = SetupFrontierV2::Pair;
        self.pair.prepare_retaining_v2().map_err(|_| HostAgentLiveErrorV1::RecoveryRequired)?;
        self.frontier = SetupFrontierV2::Provisioning;
        self.provisioning_bytes = Zeroizing::new(record.encode());
        self.seal[0].create_once("aos-sandbox-agent-provisioning-v1", &self.provisioning_bytes, PROVISIONING_BYTES)
            .map_err(|_| HostAgentLiveErrorV1::RecoveryRequired)?;
        self.frontier = SetupFrontierV2::TrustSeal;
        claim.revalidate()?;
        self.trust_pins[1] = Some(HostOpenSshStaticTrustV1::load_receiving_v2(&mut self.trust_reads[1], receiving)
            .map_err(|_| HostAgentLiveErrorV1::AttachTrustUnavailable)?);
        let trust = self.attach_trust.as_ref().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?;
        require_attach_trust_pins_v2(claim, trust,
            self.trust_pins[1].as_ref().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?)?;
        self.attach_bytes = trust.record.encode();
        self.seal[1].create_once("aos-sandbox-guest-attach-trust-v1", &self.attach_bytes, MAX_GUEST_ATTACH_TRUST_BYTES)
            .map_err(|_| HostAgentLiveErrorV1::RecoveryRequired)?;
        claim.revalidate()?;
        let provisioning = self.seal[0].take_completed_once().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?;
        let attach_trust = self.seal[1].take_completed_once().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?;
        let channel = self.pair.take_child_endpoint()?;
        self.guest = Some(HostAgentGuestLaunchDescriptorsV1 { channel, provisioning, attach_trust, currentness });
        self.pending = Some(HostAgentPendingSessionV1 {
            socket: self.pair.take_parent_socket()?, currentness, runtime,
            public_key: peer.public_key(), channel_binding: peer.channel_binding(),
            agent_instance: record.agent_instance(), features: record.features().clone(),
        });
        claim.revalidate()?;
        self.frontier = SetupFrontierV2::Pins;
        let prepared = self.prepared.as_mut().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?;
        let guest = self.guest.as_ref().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?;
        prepared.bind_guest_agent_descriptors_receiving_v2(claim, assignment, guest, &mut self.pins)?;
        Ok(())
    }

    pub(crate) fn take_prepared_once(&mut self) -> Result<crate::plan::PreparedLaunch, HostAgentLiveErrorV1> {
        if !matches!(self.setup_result, Some(Ok(()))) { return Err(HostAgentLiveErrorV1::RecoveryRequired); }
        self.prepared.take().ok_or(HostAgentLiveErrorV1::RecoveryRequired)
    }

    pub(crate) fn authenticate_once(
        &mut self, claim: &super::DormantRuntimeExecutionClaimV1<'_>, deadline: std::time::Instant,
        before_native_write: &mut dyn FnMut() -> Result<(), HostAgentLiveErrorV1>,
    ) -> Result<(), HostAgentLiveErrorV1> {
        self.frontier = SetupFrontierV2::Handshake;
        let pending = self.pending.as_mut().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?;
        if let Err(error) = self.handshake.authenticate_once(pending, claim, deadline, before_native_write) {
            self.first.get_or_insert(SetupFrontierV2::Handshake);
            return Err(error);
        }
        if self.pending.is_none() || !matches!(self.handshake.returned, Some(Ok(_))) {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        let (Some(pending), Some(Ok(authenticated))) =
            (self.pending.take(), self.handshake.returned.take())
        else { std::process::abort(); };
        self.authenticated = Some(super::HostAgentLiveSessionV1 {
            socket: pending.socket, currentness: pending.currentness,
            public_key: pending.public_key, handshake: authenticated.handshake,
            response: authenticated.response, binding: authenticated.binding,
            next_sequence: authenticated.next_sequence, poisoned: false,
        });
        Ok(())
    }

    pub(crate) fn component_report_channel_v2(&self) -> crate::Result<[u8; 32]> {
        if self.first.is_some() || !matches!(self.setup_result, Some(Ok(()))) {
            return Err(crate::HostError::AgentLaunchQuarantined);
        }
        self.record.as_ref().map(|record| *record.channel_binding().as_bytes())
            .ok_or(crate::HostError::AgentLaunchQuarantined)
    }

    pub(crate) fn require_component_report_agent_v2(
        &self,
        child: &mut aos_sandbox_linux::pidfd::HostCanaryReceivedChildOriginalsV1,
        report_socket: &mut aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<(), super::CanaryAgentFailureV1> {
        self.require_completed_backend_handshake_v2()?;
        super::require_original_agent_subject_data_v2(
            self.handshake.io.record.as_ref(), self.authenticated.as_ref().map(|session| &session.socket),
            child, report_socket,
        )
    }

    pub(crate) fn require_completed_backend_handshake_v2(&self) -> crate::Result<()> {
        if self.first.is_some() || !matches!(self.setup_result, Some(Ok(())))
            || self.pending.is_some() || self.authenticated.is_none()
        {
            return Err(crate::HostError::AgentLaunchQuarantined);
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let native = match self.first? {
            SetupFrontierV2::Seed => self.seed_read.failure(),
            SetupFrontierV2::Trust => self.trust_reads[0].failure(),
            SetupFrontierV2::Private => self.private_read.failure(),
            SetupFrontierV2::Pair => self.pair.failure().map(|cause| cause as _),
            SetupFrontierV2::Provisioning => self.seal[0].failure(),
            SetupFrontierV2::TrustSeal => self.trust_reads[1].failure().or_else(|| self.seal[1].failure()),
            SetupFrontierV2::Pins => self.pins.failure().map(|cause| cause as _),
            SetupFrontierV2::Handshake => self.handshake.failure(),
        };
        native.or_else(|| self.setup_result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}
