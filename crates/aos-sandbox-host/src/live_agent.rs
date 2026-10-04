//! Retained Host custody for one explicitly provisioned AOSAGE guest channel.
//!
//! A launch owner supplies a one-time signing record already matching the
//! protected runtime peer. This module creates the private socket pair and
//! sealed guest credentials, then retains the Host endpoint across a signed
//! handshake and bounded stop-and-wait exchanges. It never discovers an
//! inherited descriptor, reconnects to a path, or activates nspawn.

pub mod argument_attempt;
pub mod argument_readback;

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionClaimV1, DormantRuntimeExecutionOwnerErrorV1,
    RuntimeExecutionEvidenceError, agent_handshake_signing_message_v1,
    completion_from_backend_observation_v1,
};
use aos_sandbox_agent::guest_attach_trust::{
    GuestAttachTrustErrorV1, GuestAttachTrustRecordV1, MAX_GUEST_ATTACH_TRUST_BYTES,
};
use aos_sandbox_agent::protected_entry::GuestAgentLaunchRecordV1;
use aos_sandbox_agent::signed_outcome_packet::{
    MAX_SIGNED_AGENT_OUTCOME_PACKET_BYTES, SignedAgentOutcomePacketErrorV1,
};
use aos_sandbox_agent::{
    AgentExecutionOperationV1, AgentExecutionPhaseV1, AgentFeatureV1, AgentFrameV1,
    AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentNonceV1, AgentOperationIdV1,
    AgentOperationRequestV1, AgentOperationSequenceV1, AgentProtocolError, AgentRuntimeBindingV1,
    AgentSealedAuthorizeReferenceV1, AgentSessionBindingV1, AgentSessionIdV1, InvalidAgentModel,
    MAX_AGENT_SEALED_SPEC_BYTES_V1, decode_frame_v1, decode_signed_agent_outcome_packet_v1,
    encode_frame_v1,
};
use aos_sandbox_core::runtime_backend::{
    AdmissionCurrentnessV1, BackendEvidenceVerifierV1, BackendExecutionInspectionInputV1,
    BackendExecutionInspectionRequestV1, BackendExecutionPhaseV1, DurableExecutionEffectV1,
    EffectCommitError, EffectOperationV1, EffectPhaseV1, ExecutionEffectTransitionV1,
    SignedBackendExecutionInspectionV1, backend_execution_inspection_binding_v1,
    reserve_effect_issue,
};
use aos_sandbox_core::{DecodeLimits, ObjectDigest, decode_execution_spec_v1};
use aos_sandbox_linux::immutable_file::{ImmutableFileError, SealedReadOnlyCredential};
use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};
use aos_sandbox_protocol::ValidatedAssignmentFence;
use aos_systemd::{SandboxUnitName, SandboxUnitSpec};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::{TryRngCore as _, rngs::OsRng};
use rustix::fs::{Mode, OFlags, open, openat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::attach_route::{HostOpenSshStaticTrustV1, OpenSshGateAgentExchangeV1};
use crate::plan::PreparedLaunch;

const PROVISIONING_BYTES: usize = 258;
const RETRY_INTERVAL: Duration = Duration::from_millis(2);
const GATE_TIMEOUT: Duration = Duration::from_secs(30);
const SEED_DIRECTORY: &str = "/run/credentials/aos-sandbox-hostd.service";
const SEED_FILE: &str = "guest-agent-signing-seed-v1";
const SEED_MAGIC: &[u8; 8] = b"AOSGSK01";
const SEED_CREDENTIAL_BYTES: usize = 72;
const ATTACH_PRIVATE_KEY_FILE: &str = "openssh-attach-host-private-key-v1";
const MAX_ATTACH_PRIVATE_KEY_BYTES: u64 = 16 * 1024;

const CANARY_CREDENTIAL_NAMES: [&str; 4] = [
    SEED_FILE,
    ATTACH_PRIVATE_KEY_FILE,
    "openssh-attach-trust.json",
    "openssh-attach-grant-public-key",
];
const CANARY_CREDENTIAL_BOUNDS: [(usize, usize); 4] = [
    (SEED_CREDENTIAL_BYTES, SEED_CREDENTIAL_BYTES),
    (1, MAX_ATTACH_PRIVATE_KEY_BYTES as usize),
    (1, 2_048),
    (32, 32),
];

#[derive(Clone, Copy, Eq, PartialEq)]
struct CanaryCredentialIdentityV1 {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    length: u64,
    modified: (u64, u64),
    changed: (u64, u64),
}

#[derive(Debug, thiserror::Error)]
enum CanaryAgentFailureV1 {
    #[error(transparent)]
    Native(#[from] rustix::io::Errno),
    #[error(transparent)]
    Read(#[from] aos_sandbox_linux::protected_file::ExactReadFailure),
    #[error(transparent)]
    Inspection(#[from] aos_sandbox_linux::Error),
    #[error(transparent)]
    ChildOriginal(#[from] aos_sandbox_linux::pidfd::HostCanaryReceivedChildErrorV1),
    #[error(transparent)]
    ResponseOriginal(#[from] aos_sandbox_linux::seqpacket::RecordBindingError),
    #[error(transparent)]
    Agent(#[from] HostAgentLiveErrorV1),
    #[error(transparent)]
    Host(#[from] crate::HostError),
    #[error("Host canary credential originals differ")]
    Original,
    #[error("Host canary credential allocation failed")]
    Allocation,
}

// This owner is selected only by the genuine installed canary coordinator.
// The original seed, private key and partial reads survive every later gate;
// neither a decoded key nor a job digest stands in for their fixed custody.
pub(crate) struct HostCanaryAgentOwnerV1 {
    bytes: [Zeroizing<Vec<u8>>; 4],
    readback: [Zeroizing<Vec<u8>>; 4],
    files: [Option<File>; 4],
    directory: Option<File>,
    identities: [Option<CanaryCredentialIdentityV1>; 5],
    seed: Option<Zeroizing<[u8; 32]>>,
    trust: Option<HostOpenSshStaticTrustV1>,
    attach: Option<GuestAttachTrustRecordV1>,
    record: Option<GuestAgentLaunchRecordV1>,
    provisioning_bytes: Zeroizing<Vec<u8>>,
    attach_bytes: Zeroizing<Vec<u8>>,
    socket: Option<SeqpacketSocket>,
    guest_channel: Option<OwnedFd>,
    provisioning: Option<SealedReadOnlyCredential>,
    attach_provisioning: Option<SealedReadOnlyCredential>,
    instance: [u8; 16],
    handshake_session: [u8; 16],
    handshake_challenge: [u8; 32],
    handshake: Option<AgentHandshakeRequestV1>,
    response: Option<AgentHandshakeResponseV1>,
    original_challenge: [u8; 200],
    handshake_frame: Vec<u8>,
    response_record: Option<aos_sandbox_linux::seqpacket::ReceivedRecord>,
    receive_failure: Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>,
    report_challenges_attempted: bool,
    report_challenges_sent: u8,
    handshake_attempted: bool,
    attempted: bool,
    closed: bool,
    first_failure: Option<CanaryAgentFailureV1>,
}

impl HostCanaryAgentOwnerV1 {
    pub(crate) fn new() -> Self {
        Self {
            bytes: std::array::from_fn(|_| Zeroizing::new(Vec::new())),
            readback: std::array::from_fn(|_| Zeroizing::new(Vec::new())),
            files: std::array::from_fn(|_| None),
            directory: None,
            identities: [None; 5],
            seed: None,
            trust: None,
            attach: None,
            record: None,
            provisioning_bytes: Zeroizing::new(Vec::new()),
            attach_bytes: Zeroizing::new(Vec::new()),
            socket: None,
            guest_channel: None,
            provisioning: None,
            attach_provisioning: None,
            instance: [0; 16],
            handshake_session: [0; 16],
            handshake_challenge: [0; 32],
            handshake: None,
            response: None,
            original_challenge: [0; 200],
            handshake_frame: Vec::new(),
            response_record: None,
            receive_failure: None,
            report_challenges_attempted: false,
            report_challenges_sent: 0,
            handshake_attempted: false,
            attempted: false,
            closed: false,
            first_failure: None,
        }
    }

    pub(crate) fn prepare_original(
        &mut self,
        job: &mut crate::broker::canary_job::HostCanaryJobOwnerV1,
        payload: &PreparedLaunch,
        execution: &crate::state::transition::DurableExecution,
    ) -> Result<(), HostAgentLiveErrorV1> {
        if self.attempted {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        self.attempted = true;
        self.closed = true;
        let result = self.prepare_inner(job, payload, execution);
        match result {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.first_failure = Some(cause);
                Err(HostAgentLiveErrorV1::RecoveryRequired)
            }
        }
    }

    fn prepare_inner(
        &mut self,
        job: &mut crate::broker::canary_job::HostCanaryJobOwnerV1,
        payload: &PreparedLaunch,
        execution: &crate::state::transition::DurableExecution,
    ) -> Result<(), CanaryAgentFailureV1> {
        use aos_sandbox_core::{
            AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, SandboxId,
        };
        use aos_sandbox_linux::protected_file::{
            open_nofollow_child, read_exact_positioned_retaining_cause,
        };

        job.recheck()?;
        let original = job.originals()?;
        if payload.guest_package_binding() != Some(original.pins[7])
            || payload.guest_feature_mask()
                != Some(aos_sandbox_agent::guest_root_publication::CONCRETE_GUEST_FEATURE_MASK_V1)
        {
            return Err(CanaryAgentFailureV1::Original);
        }
        let fence = original.launch.fence();
        let runtime = AgentRuntimeBindingV1::new(
            SandboxId::from_bytes(*fence.sandbox_id()),
            IncarnationId::from_bytes(*fence.incarnation_id()),
            AssignmentEpoch::new(fence.assignment_epoch()),
            ObjectDigest::from_bytes(*fence.assignment_digest()),
            DesiredGeneration::new(fence.desired_generation()),
            NamespaceGeneration::new(original.namespace_generation),
            original.payload_boot_id,
        ).map_err(HostAgentLiveErrorV1::from)?;
        let mut channel = Sha256::new();
        channel.update(b"aos.sandbox.host.canary-agent-channel.v1\0");
        channel.update(original.digest);
        channel.update(execution.guardian_binding().ok_or(CanaryAgentFailureV1::Original)?);
        channel.update(original.boot_id);
        channel.update(original.nonce);
        let channel_binding = ObjectDigest::from_bytes(channel.finalize().into());

        // This transport binds the inherited channel to the original approved
        // job and D. It supplies no physical measurement or execution claim.
        self.original_challenge[..8].copy_from_slice(b"AOSHCR01");
        self.original_challenge[8..10].copy_from_slice(&1_u16.to_be_bytes());
        self.original_challenge[12..16].copy_from_slice(&200_u32.to_be_bytes());
        self.original_challenge[16..48].copy_from_slice(&original.nonce);
        self.original_challenge[48..80].copy_from_slice(&original.digest);
        self.original_challenge[80..112].copy_from_slice(
            &execution.guardian_binding().ok_or(CanaryAgentFailureV1::Original)?,
        );
        self.original_challenge[112..128].copy_from_slice(fence.sandbox_id());
        self.original_challenge[128..144].copy_from_slice(fence.incarnation_id());
        self.original_challenge[144..152]
            .copy_from_slice(&fence.assignment_epoch().to_be_bytes());
        self.original_challenge[152..160]
            .copy_from_slice(&fence.desired_generation().to_be_bytes());
        self.original_challenge[176..192].copy_from_slice(&original.boot_id);
        self.original_challenge[192..200].copy_from_slice(&original.deadline.to_be_bytes());

        let descriptor = open(
            SEED_DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        self.directory = Some(File::from(descriptor));
        let directory = self.directory.as_ref().ok_or(CanaryAgentFailureV1::Original)?;
        let metadata = rustix::fs::fstat(directory)?;
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Directory
            || metadata.st_uid != 0 || metadata.st_mode & 0o022 != 0
        {
            return Err(CanaryAgentFailureV1::Original);
        }
        self.identities[0] = Some(canary_credential_identity(directory)?);

        for slot in 0..4 {
            let descriptor = open_nofollow_child(
                self.directory.as_ref().ok_or(CanaryAgentFailureV1::Original)?,
                CANARY_CREDENTIAL_NAMES[slot],
            )?;
            self.files[slot] = Some(File::from(descriptor));
            let file = self.files[slot].as_ref().ok_or(CanaryAgentFailureV1::Original)?;
            let identity = canary_credential_identity(file)?;
            let length = usize::try_from(identity.length)
                .map_err(|_| CanaryAgentFailureV1::Original)?;
            let (minimum, maximum) = CANARY_CREDENTIAL_BOUNDS[slot];
            if rustix::fs::FileType::from_raw_mode(identity.mode) != rustix::fs::FileType::RegularFile
                || identity.uid != 0 || identity.links != 1
                || identity.mode & 0o277 != 0 || identity.mode & 0o400 == 0
                || !(minimum..=maximum).contains(&length)
            {
                return Err(CanaryAgentFailureV1::Original);
            }
            self.identities[slot + 1] = Some(identity);
            self.bytes[slot].try_reserve_exact(length)
                .map_err(|_| CanaryAgentFailureV1::Allocation)?;
            self.bytes[slot].resize(length, 0);
            self.readback[slot].try_reserve_exact(length)
                .map_err(|_| CanaryAgentFailureV1::Allocation)?;
            self.readback[slot].resize(length, 0);
            read_exact_positioned_retaining_cause(file, &mut self.bytes[slot])?;
            self.require_original_credentials()?;
        }

        self.seed = Some(decode_seed_credential(&self.bytes[0])?);
        if SigningKey::from_bytes(self.seed.as_ref().ok_or(CanaryAgentFailureV1::Original)?)
            .verifying_key().to_bytes() != original.guest_public_key
            || self.bytes[3].as_slice() != original.attach_public_key
        {
            return Err(CanaryAgentFailureV1::Original);
        }
        self.trust = Some(HostOpenSshStaticTrustV1::decode_original_canary(&self.bytes[2])
            .map_err(|_| CanaryAgentFailureV1::Original)?);
        let trust = self.trust.as_ref().ok_or(CanaryAgentFailureV1::Original)?;
        if trust.credential_digest() != original.pins[8] {
            return Err(CanaryAgentFailureV1::Original);
        }
        self.attach = Some(GuestAttachTrustRecordV1::new(
            runtime,
            self.bytes[1].to_vec(),
            trust.host_public_key().as_bytes().to_vec(),
            trust.trusted_user_ca_public_key().as_bytes().to_vec(),
        ).map_err(HostAgentLiveErrorV1::from)?);

        OsRng.try_fill_bytes(&mut self.instance)
            .map_err(|_| HostAgentLiveErrorV1::Entropy)?;
        self.record = Some(GuestAgentLaunchRecordV1::new(
            runtime,
            channel_binding,
            self.instance,
            **self.seed.as_ref().ok_or(CanaryAgentFailureV1::Original)?,
            crate::broker::agent_launch::fixed_guest_features()
                .map_err(CanaryAgentFailureV1::Host)?,
            ObjectDigest::from_bytes(original.pins[7]),
        ).map_err(|_| HostAgentLiveErrorV1::Binding)?);

        // The lower pair/sealing constructors still have pre-return prefixes.
        // Every value they actually return enters this resident owner first.
        let (socket, channel) = SeqpacketSocket::pair_with_record_subjects()
            .map_err(HostAgentLiveErrorV1::from)?;
        self.socket = Some(socket);
        self.guest_channel = Some(channel);
        let record = self.record.as_ref().ok_or(CanaryAgentFailureV1::Original)?;
        self.provisioning_bytes = Zeroizing::new(record.encode());
        self.provisioning = Some(SealedReadOnlyCredential::create(
            "aos-sandbox-agent-provisioning-v1",
            &self.provisioning_bytes,
            PROVISIONING_BYTES,
        ).map_err(HostAgentLiveErrorV1::from)?);
        self.attach_bytes = self.attach.as_ref().ok_or(CanaryAgentFailureV1::Original)?.encode();
        self.attach_provisioning = Some(SealedReadOnlyCredential::create(
            "aos-sandbox-guest-attach-trust-v1",
            &self.attach_bytes,
            MAX_GUEST_ATTACH_TRUST_BYTES,
        ).map_err(HostAgentLiveErrorV1::from)?);
        self.recheck_credentials_inner()?;
        job.recheck()?;
        Ok(())
    }

    fn require_original_credentials(&self) -> Result<(), CanaryAgentFailureV1> {
        use rustix::fs::AtFlags;

        let directory = self.directory.as_ref().ok_or(CanaryAgentFailureV1::Original)?;
        if Some(canary_credential_identity(directory)?) != self.identities[0] {
            return Err(CanaryAgentFailureV1::Original);
        }
        let named = rustix::fs::statat(rustix::fs::CWD, SEED_DIRECTORY, AtFlags::SYMLINK_NOFOLLOW)?;
        let held = self.identities[0].ok_or(CanaryAgentFailureV1::Original)?;
        if named.st_dev != held.device || named.st_ino != held.inode {
            return Err(CanaryAgentFailureV1::Original);
        }
        for slot in 0..4 {
            let Some(expected) = self.identities[slot + 1] else { continue };
            let file = self.files[slot].as_ref().ok_or(CanaryAgentFailureV1::Original)?;
            let named = rustix::fs::statat(directory, CANARY_CREDENTIAL_NAMES[slot], AtFlags::SYMLINK_NOFOLLOW)?;
            if canary_credential_identity(file)? != expected
                || named.st_dev != expected.device || named.st_ino != expected.inode
            {
                return Err(CanaryAgentFailureV1::Original);
            }
        }
        Ok(())
    }

    fn recheck_credentials_inner(&mut self) -> Result<(), CanaryAgentFailureV1> {
        self.require_original_credentials()?;
        for slot in 0..4 {
            aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
                self.files[slot].as_ref().ok_or(CanaryAgentFailureV1::Original)?,
                &mut self.readback[slot],
            )?;
            if self.readback[slot] != self.bytes[slot] {
                return Err(CanaryAgentFailureV1::Original);
            }
        }
        self.require_original_credentials()
    }

    pub(crate) fn pin_original_spec(
        &self,
        spec: SandboxUnitSpec,
        report: BorrowedFd<'_>,
    ) -> Result<SandboxUnitSpec, HostAgentLiveErrorV1> {
        use std::os::fd::AsFd as _;

        if self.closed || self.record.is_none() {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        spec.with_host_canary_descriptors_v1(
            self.guest_channel.as_ref().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?.as_fd(),
            self.provisioning.as_ref().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?.as_fd(),
            self.attach_provisioning.as_ref().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?.as_fd(),
            report,
        ).map_err(HostAgentLiveErrorV1::from)
    }

    // Queue the three fixed report challenges before guarded start. The native
    // supervisor, Guest bootstrap and final Guest manager each consume one on
    // the same inherited endpoint. Partial sends stay charged to this attempt;
    // neither a retry nor a later Agent handshake may renew the original D.
    pub(crate) fn send_original_report_challenges(
        &mut self,
        job: &mut crate::broker::canary_job::HostCanaryJobOwnerV1,
        report_socket: &mut SeqpacketSocket,
        deadline: Instant,
    ) -> Result<(), HostAgentLiveErrorV1> {
        if self.closed || self.report_challenges_attempted || self.record.is_none() {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        self.report_challenges_attempted = true;
        self.closed = true;
        let result = self.send_report_challenges_inner(job, report_socket, deadline);
        match result {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.first_failure = Some(cause);
                Err(HostAgentLiveErrorV1::RecoveryRequired)
            }
        }
    }

    fn send_report_challenges_inner(
        &mut self,
        job: &mut crate::broker::canary_job::HostCanaryJobOwnerV1,
        report_socket: &mut SeqpacketSocket,
        deadline: Instant,
    ) -> Result<(), CanaryAgentFailureV1> {
        job.recheck()?;
        self.recheck_credentials_inner()?;
        let original = job.originals()?;
        for _ in 0..3 {
            send_frame(
                report_socket,
                &self.original_challenge,
                deadline,
                Some(original.deadline),
            )?;
            self.report_challenges_sent += 1;
        }
        check_deadline(deadline, Some(original.deadline))?;
        self.recheck_credentials_inner()?;
        job.recheck()?;
        Ok(())
    }

    // This proves only the actual private channel's signed readiness handshake.
    // The coordinator still joins its nominated subject to the same measured
    // payload/Agent and completes cleanup before producing backend readiness.
    pub(crate) fn authenticate_original(
        &mut self,
        job: &mut crate::broker::canary_job::HostCanaryJobOwnerV1,
        child: &mut aos_sandbox_linux::pidfd::HostCanaryReceivedChildOriginalsV1,
        report_socket: &mut SeqpacketSocket,
        deadline: Instant,
    ) -> Result<(), HostAgentLiveErrorV1> {
        if self.closed || self.handshake_attempted || self.record.is_none()
            || self.report_challenges_sent != 3
        {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        self.handshake_attempted = true;
        self.closed = true;
        match self.authenticate_inner(job, child, report_socket, deadline) {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.first_failure = Some(cause);
                Err(HostAgentLiveErrorV1::RecoveryRequired)
            }
        }
    }

    fn authenticate_inner(
        &mut self,
        job: &mut crate::broker::canary_job::HostCanaryJobOwnerV1,
        child: &mut aos_sandbox_linux::pidfd::HostCanaryReceivedChildOriginalsV1,
        report_socket: &mut SeqpacketSocket,
        deadline: Instant,
    ) -> Result<(), CanaryAgentFailureV1> {
        job.recheck()?;
        self.recheck_credentials_inner()?;
        let original = job.originals()?;
        let record = self.record.as_ref().ok_or(CanaryAgentFailureV1::Original)?;
        let socket = self.socket.as_mut().ok_or(CanaryAgentFailureV1::Original)?;
        send_frame(
            socket,
            &self.original_challenge,
            deadline,
            Some(original.deadline),
        )?;

        self.handshake = Some(fresh_handshake(
            *record.runtime(),
            record.channel_binding(),
            &mut self.handshake_session,
            &mut self.handshake_challenge,
        )?);
        let handshake = self.handshake.as_ref().ok_or(CanaryAgentFailureV1::Original)?;
        self.handshake_frame = encode_frame_v1(&AgentFrameV1::HandshakeRequest(handshake.clone()));
        let socket = self.socket.as_mut().ok_or(CanaryAgentFailureV1::Original)?;
        send_frame(socket, &self.handshake_frame, deadline, Some(original.deadline))?;
        receive_record_into(
            socket,
            512,
            deadline,
            Some(original.deadline),
            AgentReceiveDispositionV1::Canary {
                record: &mut self.response_record,
                failure: &mut self.receive_failure,
            },
        )?;
        self.require_original_agent_subject(child, report_socket)?;
        let bytes = self.response_record.as_ref().ok_or(CanaryAgentFailureV1::Original)?.payload();
        self.response = Some(match decode_frame_v1(bytes).map_err(HostAgentLiveErrorV1::from)? {
            AgentFrameV1::HandshakeResponse(response) => response,
            _ => return Err(HostAgentLiveErrorV1::Unauthenticated.into()),
        });
        verify_original_handshake(
            handshake,
            self.response.as_ref().ok_or(CanaryAgentFailureV1::Original)?,
            &self.instance,
            record.features(),
            original.guest_public_key,
        )?;
        check_deadline(deadline, Some(original.deadline))?;
        self.require_original_agent_subject(child, report_socket)?;
        self.recheck_credentials_inner()?;
        job.recheck()?;
        Ok(())
    }

    pub(crate) fn require_completed_canary_handshake(&mut self) -> Result<(), HostAgentLiveErrorV1> {
        if self.closed || self.first_failure.is_some() || !self.handshake_attempted
            || self.response_record.is_none() || self.response.is_none()
            || self.handshake.is_none() || self.report_challenges_sent != 3
        {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        // This checks retained completion of the genuine earlier exchange.
        // After exact Stop it intentionally makes no same-child liveness
        // claim and does not create a public Agent execution session.
        // A failed or unwinding readback must not leave completion usable.
        self.closed = true;
        match self.recheck_credentials_inner() {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.first_failure.get_or_insert(cause);
                Err(HostAgentLiveErrorV1::RecoveryRequired)
            }
        }
    }

    fn require_original_agent_subject(
        &self,
        child: &mut aos_sandbox_linux::pidfd::HostCanaryReceivedChildOriginalsV1,
        report_socket: &mut SeqpacketSocket,
    ) -> Result<(), CanaryAgentFailureV1> {
        use std::os::fd::AsFd as _;

        // The signature authenticates bytes, not execution provenance. Join the
        // actual response's SCM_PIDFD to the same child donated by the measured
        // Guest bootstrap. The coordinator still checks that bootstrap, its
        // root/package/mapping and its invocation before this exchange.
        child.recheck_original(report_socket)?;
        let response = self.response_record.as_ref().ok_or(CanaryAgentFailureV1::Original)?;
        self.socket.as_ref().ok_or(CanaryAgentFailureV1::Original)?
            .require_host_canary_response_original_v1(response)?;
        let actual = response.subject();
        let nominated = child.child()?;
        let before = nominated.info()?;
        let nominee_inode = rustix::fs::fstat(nominated.as_fd())?;
        let actual_inode = rustix::fs::fstat(actual.pidfd().as_fd())?;
        if actual.initial_info() != before
            || actual.pidfd().info()? != before
            || (actual_inode.st_dev, actual_inode.st_ino)
                != (nominee_inode.st_dev, nominee_inode.st_ino)
            || !actual.is_alive()?
            || !nominated.is_alive()?
            || nominated.info()? != before
        {
            return Err(CanaryAgentFailureV1::Original);
        }
        child.recheck_original(report_socket)?;
        Ok(())
    }
}

fn canary_credential_identity(file: &File) -> Result<CanaryCredentialIdentityV1, rustix::io::Errno> {
    let metadata = rustix::fs::fstat(file)?;
    Ok(CanaryCredentialIdentityV1 {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        mode: metadata.st_mode,
        uid: metadata.st_uid,
        gid: metadata.st_gid,
        links: u64::from(metadata.st_nlink),
        length: u64::try_from(metadata.st_size).map_err(|_| rustix::io::Errno::INVAL)?,
        modified: (metadata.st_mtime as u64, metadata.st_mtime_nsec as u64),
        changed: (metadata.st_ctime as u64, metadata.st_ctime_nsec as u64),
    })
}

/// Reports a stale launch binding or a failed authenticated channel exchange.
#[derive(Debug, thiserror::Error)]
pub enum HostAgentLiveErrorV1 {
    /// The launch record or current claim differs from the protected peer.
    #[error("guest launch is not bound to the protected runtime peer")]
    Binding,
    /// Kernel entropy could not supply a fresh session and challenge.
    #[error("guest handshake entropy is unavailable")]
    Entropy,
    /// The bounded channel operation exceeded its deadline.
    #[error("guest channel deadline expired")]
    Deadline,
    /// The agent answered with an unexpected frame or invalid signature.
    #[error("guest channel returned unauthenticated traffic")]
    Unauthenticated,
    /// The fixed protected launch seed is absent or insecure.
    #[error("protected guest signing seed is unavailable")]
    SeedUnavailable,
    /// The dedicated protected OpenSSH private key or public pins are absent.
    #[error("protected guest attach trust is unavailable")]
    AttachTrustUnavailable,
    /// The sealed guest attach-trust record is invalid.
    #[error(transparent)]
    AttachTrust(#[from] GuestAttachTrustErrorV1),
    /// The fixed transient unit could not retain the exact guest descriptors.
    #[error(transparent)]
    LaunchSpec(#[from] aos_systemd::Error),
    /// Protected runtime ownership changed or became unavailable.
    #[error(transparent)]
    Owner(#[from] DormantRuntimeExecutionOwnerErrorV1),
    /// Guest-channel kernel custody failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// The guest provisioning credential could not be sealed.
    #[error(transparent)]
    Credential(#[from] ImmutableFileError),
    /// An exact AOSAGE value or frame was malformed.
    #[error(transparent)]
    Model(#[from] InvalidAgentModel),
    /// A received frame was malformed.
    #[error(transparent)]
    Frame(#[from] AgentProtocolError),
    /// The guest returned a malformed signed packet.
    #[error(transparent)]
    Packet(#[from] SignedAgentOutcomePacketErrorV1),
    /// Protected effect issuance was rejected or ambiguous.
    #[error(transparent)]
    Effect(#[from] EffectCommitError),
    /// The signed outcome did not establish a valid backend observation.
    #[error(transparent)]
    Evidence(#[from] RuntimeExecutionEvidenceError),
    /// One effect route or outcome requires cold protected recovery.
    #[error("guest effect requires protected cold recovery")]
    RecoveryRequired,
}

/// Retains private attach trust checked against independent protected Host pins.
///
/// The private key is supplied through the fixed systemd credential
/// `openssh-attach-host-private-key-v1`; it is never generated from or copied
/// into the public Host attach-trust pin. The material is consumed only by an
/// exact current launch and delivered through fully sealed FD 5.
pub struct HostAgentProtectedAttachTrustV1 {
    record: GuestAttachTrustRecordV1,
    trust_digest: [u8; 32],
    runtime: AgentRuntimeBindingV1,
}

impl HostAgentProtectedAttachTrustV1 {
    /// Opens and verifies the dedicated private key against protected pins.
    ///
    /// # Errors
    ///
    /// Rejects stale runtime ownership, absent or insecure credentials,
    /// malformed OpenSSH keys, or a mismatch with independently pinned keys.
    pub fn open_for_claim(
        claim: &DormantRuntimeExecutionClaimV1<'_>,
    ) -> Result<Self, HostAgentLiveErrorV1> {
        claim.revalidate()?;
        let runtime = agent_runtime(claim.currentness())?;
        let pins = HostOpenSshStaticTrustV1::load_protected()
            .map_err(|_| HostAgentLiveErrorV1::AttachTrustUnavailable)?;
        let private_key = read_protected_attach_private_key()?;
        let record = GuestAttachTrustRecordV1::new(
            runtime,
            private_key,
            pins.host_public_key().as_bytes().to_vec(),
            pins.trusted_user_ca_public_key().as_bytes().to_vec(),
        )?;
        claim.revalidate()?;
        Ok(Self {
            record,
            trust_digest: pins.credential_digest(),
            runtime,
        })
    }

    fn seal_for_claim(
        self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
    ) -> Result<SealedReadOnlyCredential, HostAgentLiveErrorV1> {
        claim.revalidate()?;
        let pins = HostOpenSshStaticTrustV1::load_protected()
            .map_err(|_| HostAgentLiveErrorV1::AttachTrustUnavailable)?;
        if self.runtime != agent_runtime(claim.currentness())?
            || self.trust_digest != pins.credential_digest()
            || self.record.host_public_key_bytes() != pins.host_public_key().as_bytes()
            || self.record.trusted_ca_public_key_bytes()
                != pins.trusted_user_ca_public_key().as_bytes()
        {
            return Err(HostAgentLiveErrorV1::Binding);
        }

        let bytes = self.record.encode();
        let credential = SealedReadOnlyCredential::create(
            "aos-sandbox-guest-attach-trust-v1",
            &bytes,
            MAX_GUEST_ATTACH_TRUST_BYTES,
        )?;
        claim.revalidate()?;
        Ok(credential)
    }
}

fn read_protected_attach_private_key() -> Result<Vec<u8>, HostAgentLiveErrorV1> {
    let mut bytes =
        read_root_owned_credential(ATTACH_PRIVATE_KEY_FILE, 1, MAX_ATTACH_PRIVATE_KEY_BYTES)
            .map_err(|()| HostAgentLiveErrorV1::AttachTrustUnavailable)?;
    Ok(std::mem::take(&mut *bytes))
}

pub(crate) fn read_root_owned_credential(
    file_name: &str,
    minimum_bytes: u64,
    maximum_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let directory = open(
        SEED_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let directory = File::from(directory);
    let directory_metadata = directory.metadata().map_err(|_| ())?;
    if !directory_metadata.is_dir()
        || directory_metadata.uid() != 0
        || directory_metadata.mode() & 0o022 != 0
    {
        return Err(());
    }

    let descriptor = openat(
        &directory,
        Path::new(file_name),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o277 != 0
        || metadata.mode() & 0o400 == 0
        || metadata.len() < minimum_bytes
        || metadata.len() > maximum_bytes
    {
        return Err(());
    }

    let length = usize::try_from(metadata.len()).map_err(|_| ())?;
    let mut bytes = Zeroizing::new(vec![0; length]);
    file.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

/// Retains a zeroizing seed verified against the fixed protected agent peer.
///
/// The versioned credential is installed by trusted node provisioning, not
/// derived from the public bootstrap manifest or supplied by a broker client:
///
/// ```text
/// /run/credentials/aos-sandbox-hostd.service/guest-agent-signing-seed-v1
/// AOSGSK01 || seed[32] || SHA256(magic || seed)[32]
/// ```
pub struct HostAgentProtectedSeedV1 {
    seed: Zeroizing<[u8; 32]>,
    runtime: AgentRuntimeBindingV1,
    channel_binding: ObjectDigest,
}

impl HostAgentProtectedSeedV1 {
    /// Opens the fixed root-protected credential and matches its public key.
    ///
    /// # Errors
    ///
    /// Rejects an absent, symlinked, non-root-owned, writable, multiply linked,
    /// malformed, or mismatched credential and stale protected currentness.
    pub fn open_for_claim(
        claim: &DormantRuntimeExecutionClaimV1<'_>,
    ) -> Result<Self, HostAgentLiveErrorV1> {
        claim.revalidate()?;
        let bytes = read_root_owned_credential(
            SEED_FILE,
            SEED_CREDENTIAL_BYTES as u64,
            SEED_CREDENTIAL_BYTES as u64,
        )
        .map_err(|()| HostAgentLiveErrorV1::SeedUnavailable)?;
        let seed = decode_seed_credential(&bytes)?;
        if SigningKey::from_bytes(&seed).verifying_key().to_bytes()
            != claim.agent_peer().public_key()
        {
            return Err(HostAgentLiveErrorV1::Binding);
        }
        let runtime = agent_runtime(claim.currentness())?;
        let channel_binding = claim.agent_peer().channel_binding();
        claim.revalidate()?;
        Ok(Self {
            seed,
            runtime,
            channel_binding,
        })
    }

    /// Mints a transient launch record from the verified protected seed.
    ///
    /// The package commitment and advertised features must come from the
    /// trusted launch plan. The caller still has to pass this record through
    /// [`HostAgentLaunchHandoffV1::prepare`] under a current protected claim.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable entropy or invalid launch parameters.
    pub fn launch_record(
        self,
        features: aos_sandbox_agent::AgentFeatureSetV1,
        package_binding: ObjectDigest,
    ) -> Result<GuestAgentLaunchRecordV1, HostAgentLiveErrorV1> {
        let mut instance = [0; 16];
        OsRng
            .try_fill_bytes(&mut instance)
            .map_err(|_| HostAgentLiveErrorV1::Entropy)?;
        GuestAgentLaunchRecordV1::new(
            self.runtime,
            self.channel_binding,
            instance,
            *self.seed,
            features,
            package_binding,
        )
        .map_err(|_| HostAgentLiveErrorV1::Binding)
    }
}

/// Owns all three launch descriptors before their explicit transfer to the guest.
pub struct HostAgentGuestLaunchDescriptorsV1 {
    channel: OwnedFd,
    provisioning: SealedReadOnlyCredential,
    attach_trust: SealedReadOnlyCredential,
    currentness: AdmissionCurrentnessV1,
}

impl HostAgentGuestLaunchDescriptorsV1 {
    /// Borrows the private connected endpoint to install as guest FD 3.
    #[must_use]
    pub fn channel_fd3(&self) -> BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.channel.as_fd()
    }

    /// Borrows the fully sealed read-only credential to install as guest FD 4.
    #[must_use]
    pub fn provisioning_fd4(&self) -> BorrowedFd<'_> {
        self.provisioning.as_fd()
    }

    /// Borrows the fully sealed attach trust to install as guest FD 5.
    #[must_use]
    pub fn attach_trust_fd5(&self) -> BorrowedFd<'_> {
        self.attach_trust.as_fd()
    }

    /// Pins the fixed three roles into an unbound transient nspawn unit.
    ///
    /// # Errors
    ///
    /// Rejects changed protected currentness, a bound unit, or descriptor
    /// duplication failure before a launch transaction may be committed.
    pub(crate) fn bind_unit_spec(
        &self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        assignment: &ValidatedAssignmentFence,
        spec: SandboxUnitSpec,
    ) -> Result<SandboxUnitSpec, HostAgentLiveErrorV1> {
        claim.revalidate()?;
        if claim.currentness() != &self.currentness
            || !matches_assignment(claim, assignment)
            || spec.name() != &SandboxUnitName::from_incarnation(*assignment.incarnation_id())
        {
            return Err(HostAgentLiveErrorV1::Binding);
        }
        let spec = spec.with_guest_agent_descriptors(
            self.channel_fd3(),
            self.provisioning_fd4(),
            self.attach_trust_fd5(),
        )?;
        claim.revalidate()?;
        Ok(spec)
    }
}

/// Prepares an exact launch without allowing a socket or signer substitution.
pub struct HostAgentLaunchHandoffV1 {
    pending: HostAgentPendingSessionV1,
    guest: HostAgentGuestLaunchDescriptorsV1,
    package_binding: ObjectDigest,
}

impl HostAgentLaunchHandoffV1 {
    /// Creates a private channel and mandatory sealed FD 4 and FD 5 credentials.
    ///
    /// The record must come from the trusted runtime launch owner. This method
    /// never synthesizes a signing seed from protected public information.
    ///
    /// # Errors
    ///
    /// Rejects stale currentness, a mismatched launch signer/runtime/channel,
    /// or failure to create and seal the private descriptors.
    pub fn prepare(
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        assignment: &ValidatedAssignmentFence,
        record: GuestAgentLaunchRecordV1,
        attach_trust: HostAgentProtectedAttachTrustV1,
    ) -> Result<Self, HostAgentLiveErrorV1> {
        claim.revalidate()?;
        if !matches_assignment(claim, assignment) {
            return Err(HostAgentLiveErrorV1::Binding);
        }
        let currentness = *claim.currentness();
        let peer = claim.agent_peer();
        let runtime = agent_runtime(&currentness)?;
        if record.runtime() != &runtime
            || record.channel_binding() != peer.channel_binding()
            || record.verifying_key_bytes() != peer.public_key()
        {
            return Err(HostAgentLiveErrorV1::Binding);
        }

        let (socket, channel) = SeqpacketSocket::pair_with_record_subjects()?;
        let provisioning_bytes = Zeroizing::new(record.encode());
        let provisioning = SealedReadOnlyCredential::create(
            "aos-sandbox-agent-provisioning-v1",
            &provisioning_bytes,
            PROVISIONING_BYTES,
        )?;
        let attach_trust = attach_trust.seal_for_claim(claim)?;
        let guest = HostAgentGuestLaunchDescriptorsV1 {
            channel,
            provisioning,
            attach_trust,
            currentness,
        };
        let pending = HostAgentPendingSessionV1 {
            socket,
            currentness,
            runtime,
            public_key: peer.public_key(),
            channel_binding: peer.channel_binding(),
            agent_instance: record.agent_instance(),
            features: record.features().clone(),
        };
        claim.revalidate()?;
        Ok(Self {
            pending,
            guest,
            package_binding: record.package_binding(),
        })
    }

    /// Pins the sealed guest descriptors into the exact unbound payload spec.
    ///
    /// The package identity must be the Storage-authenticated guest root
    /// publication, and the updated spec digest becomes the durable payload
    /// snapshot before Guardian can authorize a launch. The returned Host
    /// endpoint must stay alive through the later guest handshake.
    ///
    /// # Errors
    ///
    /// Rejects an absent or different guest package publication, changed
    /// protected runtime currentness, assignment mismatch, or FD pin failure.
    pub fn bind_prepared_launch(
        self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        assignment: &ValidatedAssignmentFence,
        prepared: PreparedLaunch,
    ) -> Result<(PreparedLaunch, HostAgentPendingSessionV1), HostAgentLiveErrorV1> {
        if !matches_guest_package_binding(prepared.guest_package_binding(), self.package_binding) {
            return Err(HostAgentLiveErrorV1::Binding);
        }
        let (pending, guest) = self.into_parts();
        let prepared = prepared.with_guest_agent_descriptors(claim, assignment, &guest)?;
        Ok((prepared, pending))
    }

    fn into_parts(self) -> (HostAgentPendingSessionV1, HostAgentGuestLaunchDescriptorsV1) {
        (self.pending, self.guest)
    }
}

fn matches_guest_package_binding(published: Option<[u8; 32]>, provisioned: ObjectDigest) -> bool {
    published == Some(*provisioned.as_bytes())
}

fn matches_assignment(
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    assignment: &ValidatedAssignmentFence,
) -> bool {
    let current = claim.currentness().runtime().currentness();
    current.sandbox().as_bytes() == assignment.sandbox_id()
        && current.incarnation().as_bytes() == assignment.incarnation_id()
        && current.assignment_epoch().get() == assignment.assignment_epoch()
        && current.assignment_digest().as_bytes() == assignment.assignment_digest()
        && current.desired_generation().get() == assignment.desired_generation()
}

/// Retains the Host endpoint until the launched guest proves its secret.
pub struct HostAgentPendingSessionV1 {
    socket: SeqpacketSocket,
    currentness: AdmissionCurrentnessV1,
    runtime: AgentRuntimeBindingV1,
    public_key: [u8; 32],
    channel_binding: ObjectDigest,
    agent_instance: [u8; 16],
    features: aos_sandbox_agent::AgentFeatureSetV1,
}

impl HostAgentPendingSessionV1 {
    /// Authenticates the launched guest over the retained private socket.
    ///
    /// # Errors
    ///
    /// Rejects changed protected currentness, missing entropy, deadline,
    /// malformed framing, or an invalid exact peer signature.
    pub fn authenticate(
        mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        deadline: Instant,
    ) -> Result<HostAgentLiveSessionV1, HostAgentLiveErrorV1> {
        self.validate_claim(claim)?;
        let mut session = [0; 16];
        let mut challenge = [0; 32];
        let handshake = fresh_handshake(self.runtime, self.channel_binding, &mut session, &mut challenge)?;

        send_frame(
            &mut self.socket,
            &encode_frame_v1(&AgentFrameV1::HandshakeRequest(handshake.clone())),
            deadline,
            None,
        )?;
        let response = match decode_frame_v1(&receive_record(
            &mut self.socket,
            aos_sandbox_agent::protocol::MAX_AGENT_FRAME_BYTES,
            deadline,
            None,
        )?)? {
            AgentFrameV1::HandshakeResponse(response) => response,
            _ => return Err(HostAgentLiveErrorV1::Unauthenticated),
        };
        let binding = verify_original_handshake(
            &handshake,
            &response,
            &self.agent_instance,
            &self.features,
            self.public_key,
        )?;
        self.validate_claim(claim)?;

        Ok(HostAgentLiveSessionV1 {
            socket: self.socket,
            currentness: self.currentness,
            public_key: self.public_key,
            handshake,
            response,
            binding,
            next_sequence: AgentOperationSequenceV1::new(1)?,
            poisoned: false,
        })
    }

    fn validate_claim(
        &self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
    ) -> Result<(), HostAgentLiveErrorV1> {
        claim.revalidate()?;
        let peer = claim.agent_peer();
        if claim.currentness() != &self.currentness
            || peer.public_key() != self.public_key
            || peer.channel_binding() != self.channel_binding
        {
            return Err(HostAgentLiveErrorV1::Binding);
        }
        Ok(())
    }
}

/// Owns one signed, stop-and-wait AOSAGE channel after exact handshake.
pub struct HostAgentLiveSessionV1 {
    socket: SeqpacketSocket,
    currentness: AdmissionCurrentnessV1,
    public_key: [u8; 32],
    handshake: AgentHandshakeRequestV1,
    response: AgentHandshakeResponseV1,
    binding: AgentSessionBindingV1,
    next_sequence: AgentOperationSequenceV1,
    poisoned: bool,
}

impl HostAgentLiveSessionV1 {
    /// Returns the binding proven by the guest's exact signed handshake.
    #[must_use]
    pub const fn session_binding(&self) -> AgentSessionBindingV1 {
        self.binding
    }

    /// Revalidates the protected runtime and agent peer before any exchange.
    ///
    /// # Errors
    ///
    /// Rejects a changed runtime, payload boot, channel, or signer.
    pub fn validate_claim(
        &self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
    ) -> Result<(), HostAgentLiveErrorV1> {
        claim.revalidate()?;
        if claim.currentness() != &self.currentness
            || claim.agent_peer().public_key() != self.public_key
            || self.handshake.host_channel_binding() != claim.agent_peer().channel_binding()
            || self.handshake.runtime() != &agent_runtime(claim.currentness())?
        {
            return Err(HostAgentLiveErrorV1::Binding);
        }
        Ok(())
    }

    /// Borrows the authenticated handshake for exact route authorization.
    #[must_use]
    pub const fn handshake(&self) -> &AgentHandshakeRequestV1 {
        &self.handshake
    }

    /// Borrows the signed handshake reply for exact route authorization.
    #[must_use]
    pub const fn response(&self) -> &AgentHandshakeResponseV1 {
        &self.response
    }

    /// Issues one Pending effect exactly once and settles its signed result.
    ///
    /// The request projection is nonauthorizing. The protected claim verifies
    /// its exact action, specification, currentness, signed handshake, and
    /// route before consuming dispatch in the journal. The socket is touched
    /// only after the Issued transition and route consumption are durable.
    /// Any subsequent failure poisons this session; recovery is read-only.
    ///
    /// # Errors
    ///
    /// Rejects stale currentness, an occupied session, invalid effect or guest
    /// evidence, deadline, transport loss, or any ambiguous protected append.
    pub fn issue_pending_effect(
        &mut self,
        claim: &mut DormantRuntimeExecutionClaimV1<'_>,
        pending: &DurableExecutionEffectV1,
        deadline: Instant,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<DurableExecutionEffectV1, HostAgentLiveErrorV1> {
        if self.poisoned {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        check_deadline(deadline, Some(deadline_boottime_nanoseconds))?;
        self.validate_claim(claim)?;
        if pending.phase() != EffectPhaseV1::Pending
            || pending.admission().currentness() != claim.currentness()
            || claim.has_unsettled_host_agent_route()?
        {
            return Err(HostAgentLiveErrorV1::Binding);
        }
        let required_feature = match pending.issue().operation() {
            EffectOperationV1::AuthorizeExecution => Some(AgentFeatureV1::ExecutionHandoff),
            EffectOperationV1::ResizeTerminal { .. } => Some(AgentFeatureV1::TerminalResize),
            EffectOperationV1::Signal { .. } => Some(AgentFeatureV1::ExecutionSignal),
            EffectOperationV1::Observe => Some(AgentFeatureV1::ExecutionObservation),
            EffectOperationV1::Cancel => None,
        };
        if required_feature.is_some_and(|feature| !self.response.features().contains(feature)) {
            return Err(HostAgentLiveErrorV1::Binding);
        }
        let next_sequence = self.next_sequence.checked_next()?;
        let request = project_agent_request(pending, self.binding, self.next_sequence, claim)?;
        let sealed_specification = match request.operation() {
            AgentExecutionOperationV1::Authorize {
                specification_bytes,
                ..
            } => Some(SealedReadOnlyCredential::create(
                "aos-agent-execution-spec-v1",
                specification_bytes,
                MAX_AGENT_SEALED_SPEC_BYTES_V1,
            )?),
            _ => None,
        };
        let frame = if sealed_specification.is_some() {
            let reference = AgentSealedAuthorizeReferenceV1::from_request(&request)?;
            encode_frame_v1(&AgentFrameV1::SealedAuthorizeRequest(reference))
        } else {
            encode_frame_v1(&AgentFrameV1::OperationRequest(request.clone()))
        };
        let verifier = BackendEvidenceVerifierV1::new(
            claim.agent_peer().public_key(),
            claim.agent_peer().trust_context(),
            claim.agent_peer().channel_binding(),
        )
        .map_err(|_| HostAgentLiveErrorV1::Binding)?;
        if verifier.authority_binding() != claim.agent_peer().authority_binding() {
            return Err(HostAgentLiveErrorV1::Binding);
        }
        let observation_sequence = claim.next_observation_sequence();
        if observation_sequence.get() == u64::MAX
            || claim.committed_host_agent_outcome_at_observation_sequence(observation_sequence)?
        {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }

        self.poisoned = true;
        let issued = match reserve_effect_issue(claim, pending)? {
            ExecutionEffectTransitionV1::Committed(effect) => effect,
            ExecutionEffectTransitionV1::RecoveryRequired(_)
            | ExecutionEffectTransitionV1::NotCommitted => {
                return Err(HostAgentLiveErrorV1::RecoveryRequired);
            }
        };
        claim.consume_fresh_execution_for_authenticated_agent_route(
            &self.handshake,
            &self.response,
            &request,
            &issued,
        )?;
        let operation = *issued.issue().idempotency().operation().as_bytes();
        // Retain this exact sealed descriptor through signed outcome custody;
        // an uncertain send poisons the session rather than rebuilding a retry.
        if let Some(specification) = &sealed_specification {
            send_descriptor_frame(
                &mut self.socket,
                &frame,
                specification.as_fd(),
                deadline,
                Some(deadline_boottime_nanoseconds),
            )?;
        } else {
            send_frame(
                &mut self.socket,
                &frame,
                deadline,
                Some(deadline_boottime_nanoseconds),
            )?;
        }
        let bytes = receive_record(
            &mut self.socket,
            MAX_SIGNED_AGENT_OUTCOME_PACKET_BYTES,
            deadline,
            Some(deadline_boottime_nanoseconds),
        )?;
        let packet = decode_signed_agent_outcome_packet_v1(&bytes)?;
        let authenticated = claim.authenticate_recovered_agent_outcome_packet(
            &operation,
            aos_sandbox_agent::SignedAgentOutcomePacketV1::new(
                packet.outcome().clone(),
                *packet.signature(),
            )?,
        )?;
        let inspection_request = inspection_request(&issued, claim)?;
        let outcome = authenticated.outcome();
        let input = BackendExecutionInspectionInputV1 {
            authority_binding: ObjectDigest::from_bytes([0; 32]),
            operation: inspection_request.operation(),
            operation_sequence: inspection_request.operation_sequence(),
            effect_request_digest: inspection_request.effect_request_digest(),
            execution: inspection_request.execution(),
            specification_digest: inspection_request.specification_digest(),
            admission_commitment: inspection_request.admission_commitment(),
            runtime: *inspection_request.runtime(),
            payload_boot_id: inspection_request.payload_boot_id(),
            phase: core_phase(outcome.phase())?,
            sequence: observation_sequence,
            observation_commitment: ObjectDigest::from_bytes([0; 32]),
        };
        let signed = SignedBackendExecutionInspectionV1::new(
            input,
            outcome.session().digest(),
            outcome.sequence().get(),
            *outcome.operation_id().as_bytes(),
            outcome.request_commitment(),
            outcome.outcome_commitment(),
            outcome.result_bytes().to_vec(),
            outcome.result_digest(),
            *authenticated.signature(),
        );
        let observation = verifier
            .verify_execution_inspection(&inspection_request, observation_sequence, signed)
            .map_err(|_| HostAgentLiveErrorV1::Unauthenticated)?;
        let observation_commitment = observation.observation_commitment();
        let completion = completion_from_backend_observation_v1(&issued, observation)?;

        claim.commit_signed_host_agent_outcome_packet(
            &operation,
            &packet,
            observation_sequence,
            observation_commitment,
        )?;
        claim.consume_execution_observation(&observation)?;
        let complete = match claim.commit_verified_completion(&issued, &completion)? {
            ExecutionEffectTransitionV1::Committed(effect) => effect,
            ExecutionEffectTransitionV1::RecoveryRequired(_)
            | ExecutionEffectTransitionV1::NotCommitted => {
                return Err(HostAgentLiveErrorV1::RecoveryRequired);
            }
        };
        self.next_sequence = next_sequence;
        self.poisoned = false;
        Ok(complete)
    }

    // Only a checked gate frame reaches this helper. Effect-bearing operations
    // need their own durable route consumption before sharing this socket.
    fn exchange_frame(
        &mut self,
        request: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, HostAgentLiveErrorV1> {
        // A timed-out gate reply may still be queued on this stop-and-wait
        // socket. Never send a later effect into an ambiguous frame stream.
        self.poisoned = true;
        send_frame(&mut self.socket, request, deadline, None)?;
        let response = receive_record(
            &mut self.socket,
            aos_sandbox_agent::protocol::MAX_AGENT_FRAME_BYTES,
            deadline,
            None,
        )?;
        if !matches!(
            (decode_frame_v1(request), decode_frame_v1(&response)),
            (
                Ok(AgentFrameV1::OpenSshGateObserveRequest(_)),
                Ok(AgentFrameV1::OpenSshGateReadback(_))
            ) | (
                Ok(AgentFrameV1::OpenSshTicketBindRequestV2(_)),
                Ok(AgentFrameV1::OpenSshTicketReadbackV2(_))
            ) | (
                Ok(AgentFrameV1::OriginalAttachRequestV3(_)),
                Ok(AgentFrameV1::OriginalAttachResponseV3(_))
            ) | (
                Ok(AgentFrameV1::OriginalControlRequestV5(_)),
                Ok(AgentFrameV1::OriginalControlResponseV5(_))
            )
        ) {
            return Err(HostAgentLiveErrorV1::Unauthenticated);
        }
        self.poisoned = false;
        Ok(response)
    }
}

impl OpenSshGateAgentExchangeV1 for HostAgentLiveSessionV1 {
    fn exchange(&mut self, request: &[u8]) -> std::io::Result<Vec<u8>> {
        if self.poisoned
            || !matches!(
                decode_frame_v1(request),
                Ok(AgentFrameV1::OpenSshGateObserveRequest(_)
                    | AgentFrameV1::OpenSshTicketBindRequestV2(_)
                    | AgentFrameV1::OriginalAttachRequestV3(_)
                    | AgentFrameV1::OriginalControlRequestV5(_))
            )
        {
            return Err(std::io::Error::other(
                "only exact gate observations or original ticket actions use this exchange",
            ));
        }
        let deadline = Instant::now() + GATE_TIMEOUT;
        self.exchange_frame(request, deadline)
            .map_err(std::io::Error::other)
    }
}

fn agent_runtime(
    currentness: &AdmissionCurrentnessV1,
) -> Result<AgentRuntimeBindingV1, HostAgentLiveErrorV1> {
    let runtime = currentness.runtime().currentness();
    Ok(AgentRuntimeBindingV1::new(
        runtime.sandbox(),
        runtime.incarnation(),
        runtime.assignment_epoch(),
        runtime.assignment_digest(),
        runtime.desired_generation(),
        runtime.namespace_generation(),
        *currentness.payload_boot_id().as_bytes(),
    )?)
}

fn fresh_handshake(
    runtime: AgentRuntimeBindingV1,
    channel_binding: ObjectDigest,
    session: &mut [u8; 16],
    challenge: &mut [u8; 32],
) -> Result<AgentHandshakeRequestV1, HostAgentLiveErrorV1> {
    OsRng.try_fill_bytes(session).map_err(|_| HostAgentLiveErrorV1::Entropy)?;
    OsRng.try_fill_bytes(challenge).map_err(|_| HostAgentLiveErrorV1::Entropy)?;
    Ok(AgentHandshakeRequestV1::new(
        AgentSessionIdV1::new(*session)?,
        runtime,
        AgentNonceV1::new(*challenge)?,
        channel_binding,
    )?)
}

fn verify_original_handshake(
    handshake: &AgentHandshakeRequestV1,
    response: &AgentHandshakeResponseV1,
    agent_instance: &[u8; 16],
    features: &aos_sandbox_agent::AgentFeatureSetV1,
    public_key: [u8; 32],
) -> Result<AgentSessionBindingV1, HostAgentLiveErrorV1> {
    let binding = AgentSessionBindingV1::derive(handshake, response.agent_instance())?;
    if response.session_binding() != binding
        || response.agent_instance() != agent_instance
        || response.features() != features
    {
        return Err(HostAgentLiveErrorV1::Unauthenticated);
    }
    let message = agent_handshake_signing_message_v1(
        handshake,
        binding,
        response.agent_instance(),
        response.features(),
    );
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| HostAgentLiveErrorV1::Unauthenticated)?;
    key.verify_strict(&message, &Signature::from_bytes(response.challenge_signature()))
        .map_err(|_| HostAgentLiveErrorV1::Unauthenticated)?;
    Ok(binding)
}

fn decode_seed_credential(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, HostAgentLiveErrorV1> {
    if bytes.len() != SEED_CREDENTIAL_BYTES {
        return Err(HostAgentLiveErrorV1::SeedUnavailable);
    }
    let checksum: [u8; 32] = Sha256::digest(&bytes[..40]).into();
    if &bytes[..8] != SEED_MAGIC || bytes[40..] != checksum {
        return Err(HostAgentLiveErrorV1::SeedUnavailable);
    }
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&bytes[8..40]);
    if *seed == [0; 32] {
        return Err(HostAgentLiveErrorV1::SeedUnavailable);
    }
    Ok(seed)
}

fn inspection_request(
    effect: &DurableExecutionEffectV1,
    claim: &DormantRuntimeExecutionClaimV1<'_>,
) -> Result<BackendExecutionInspectionRequestV1, HostAgentLiveErrorV1> {
    let admission = effect.admission();
    BackendExecutionInspectionRequestV1::new(
        claim.agent_peer().authority_binding(),
        effect.issue().idempotency().operation(),
        effect.issue().sequence(),
        effect.issue().idempotency().request_digest(),
        admission.execution(),
        admission.specification_digest(),
        admission.admission_commitment(),
        *claim.currentness().runtime(),
        claim.currentness().payload_boot_id(),
    )
    .map_err(|_| HostAgentLiveErrorV1::Binding)
}

fn project_agent_request(
    effect: &DurableExecutionEffectV1,
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    claim: &DormantRuntimeExecutionClaimV1<'_>,
) -> Result<AgentOperationRequestV1, HostAgentLiveErrorV1> {
    let admission = effect.admission();
    let operation = match effect.issue().operation() {
        EffectOperationV1::AuthorizeExecution => {
            let bytes = admission.specification_bytes();
            let specification = decode_execution_spec_v1(
                bytes,
                DecodeLimits {
                    maximum_bytes: bytes.len(),
                    maximum_collection_items: 65_536,
                    maximum_total_items: 262_144,
                    maximum_byte_string_bytes: 15 * 1_048_576,
                    maximum_text_bytes: 1_048_576,
                    maximum_depth: 128,
                },
            )
            .map_err(|_| HostAgentLiveErrorV1::Binding)?;
            AgentExecutionOperationV1::Authorize {
                execution: admission.execution(),
                specification_bytes: bytes.to_vec(),
                specification_digest: admission.specification_digest(),
                admission_commitment: admission.admission_commitment(),
                principal: specification.principal(),
                audit: specification.audit(),
            }
        }
        EffectOperationV1::ResizeTerminal { rows, columns } => {
            AgentExecutionOperationV1::ResizeTerminal {
                execution: admission.execution(),
                rows,
                columns,
            }
        }
        EffectOperationV1::Signal { signal_code } => AgentExecutionOperationV1::Signal {
            execution: admission.execution(),
            signal_code,
        },
        EffectOperationV1::Cancel => AgentExecutionOperationV1::Cancel {
            execution: admission.execution(),
        },
        EffectOperationV1::Observe => AgentExecutionOperationV1::Observe {
            execution: admission.execution(),
        },
    };
    let inspection = inspection_request(effect, claim)?;
    Ok(AgentOperationRequestV1::new(
        session,
        sequence,
        AgentOperationIdV1::new(*effect.issue().idempotency().operation().as_bytes())?,
        backend_execution_inspection_binding_v1(&inspection),
        operation,
    )?)
}

fn core_phase(
    phase: AgentExecutionPhaseV1,
) -> Result<BackendExecutionPhaseV1, HostAgentLiveErrorV1> {
    match phase {
        AgentExecutionPhaseV1::Authorized => Ok(BackendExecutionPhaseV1::Authorized),
        AgentExecutionPhaseV1::Starting => Ok(BackendExecutionPhaseV1::Starting),
        AgentExecutionPhaseV1::Running => Ok(BackendExecutionPhaseV1::Running),
        AgentExecutionPhaseV1::Exited => Ok(BackendExecutionPhaseV1::Exited),
        AgentExecutionPhaseV1::Canceled => Ok(BackendExecutionPhaseV1::Canceled),
        AgentExecutionPhaseV1::Failed => Ok(BackendExecutionPhaseV1::Failed),
        AgentExecutionPhaseV1::Lost => Ok(BackendExecutionPhaseV1::Lost),
        AgentExecutionPhaseV1::Quiesced | AgentExecutionPhaseV1::Ready => {
            Err(HostAgentLiveErrorV1::Unauthenticated)
        }
    }
}

fn send_frame(
    socket: &mut SeqpacketSocket,
    bytes: &[u8],
    deadline: Instant,
    deadline_boottime_nanoseconds: Option<u64>,
) -> Result<(), HostAgentLiveErrorV1> {
    loop {
        check_deadline(deadline, deadline_boottime_nanoseconds)?;
        match socket.send(bytes) {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn send_descriptor_frame(
    socket: &mut SeqpacketSocket,
    bytes: &[u8],
    descriptor: BorrowedFd<'_>,
    deadline: Instant,
    deadline_boottime_nanoseconds: Option<u64>,
) -> Result<(), HostAgentLiveErrorV1> {
    loop {
        check_deadline(deadline, deadline_boottime_nanoseconds)?;
        match socket.send_with_descriptors(bytes, &[descriptor]) {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_record(
    socket: &mut SeqpacketSocket,
    maximum_bytes: usize,
    deadline: Instant,
    deadline_boottime_nanoseconds: Option<u64>,
) -> Result<Vec<u8>, HostAgentLiveErrorV1> {
    receive_record_into(socket, maximum_bytes, deadline, deadline_boottime_nanoseconds,
        AgentReceiveDispositionV1::Legacy)?
        .ok_or(HostAgentLiveErrorV1::RecoveryRequired)
}

enum AgentReceiveDispositionV1<'a> {
    Legacy,
    Canary {
        record: &'a mut Option<aos_sandbox_linux::seqpacket::ReceivedRecord>,
        failure: &'a mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>,
    },
}

fn receive_record_into(
    socket: &mut SeqpacketSocket,
    maximum_bytes: usize,
    deadline: Instant,
    deadline_boottime_nanoseconds: Option<u64>,
    mut disposition: AgentReceiveDispositionV1<'_>,
) -> Result<Option<Vec<u8>>, HostAgentLiveErrorV1> {
    loop {
        check_deadline(deadline, deadline_boottime_nanoseconds)?;
        match &mut disposition {
            AgentReceiveDispositionV1::Legacy => match socket.receive(maximum_bytes) {
                Ok(record) => return Ok(Some(record.payload().to_vec())),
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    std::thread::sleep(RETRY_INTERVAL);
                }
                Err(error) => return Err(error.into()),
            },
            AgentReceiveDispositionV1::Canary { record, failure } => {
                match socket.receive_retaining(maximum_bytes) {
                    Ok(original) => {
                        **record = Some(original);
                        return Ok(None);
                    }
                    Err(error) if error.is_nonconsuming_would_block()
                        || error.is_nonconsuming_interrupted() => {
                        std::thread::sleep(RETRY_INTERVAL);
                    }
                    Err(error) => {
                        **failure = Some(error);
                        return Err(HostAgentLiveErrorV1::RecoveryRequired);
                    }
                }
            }
        }
    }
}

fn check_deadline(
    deadline: Instant,
    deadline_boottime_nanoseconds: Option<u64>,
) -> Result<(), HostAgentLiveErrorV1> {
    if Instant::now() >= deadline {
        return Err(HostAgentLiveErrorV1::Deadline);
    }
    if let Some(deadline) = deadline_boottime_nanoseconds {
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let seconds = u64::try_from(now.tv_sec).map_err(|_| HostAgentLiveErrorV1::Deadline)?;
        let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| HostAgentLiveErrorV1::Deadline)?;
        let now = seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanoseconds))
            .ok_or(HostAgentLiveErrorV1::Deadline)?;
        if now >= deadline {
            return Err(HostAgentLiveErrorV1::Deadline);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(seed: [u8; 32]) -> [u8; SEED_CREDENTIAL_BYTES] {
        let mut bytes = [0; SEED_CREDENTIAL_BYTES];
        bytes[..8].copy_from_slice(SEED_MAGIC);
        bytes[8..40].copy_from_slice(&seed);
        let checksum: [u8; 32] = Sha256::digest(&bytes[..40]).into();
        bytes[40..].copy_from_slice(&checksum);
        bytes
    }

    #[test]
    fn launch_seed_requires_exact_version_checksum_and_nonzero_secret() {
        let valid = credential([7; 32]);
        assert_eq!(*decode_seed_credential(&valid).unwrap(), [7; 32]);

        let mut wrong_version = valid;
        wrong_version[0] ^= 1;
        assert!(decode_seed_credential(&wrong_version).is_err());

        let mut wrong_checksum = valid;
        wrong_checksum[40] ^= 1;
        assert!(decode_seed_credential(&wrong_checksum).is_err());

        assert!(decode_seed_credential(&credential([0; 32])).is_err());
    }

    #[test]
    fn guest_handoff_requires_the_storage_authenticated_package_binding() {
        let provisioned = ObjectDigest::from_bytes([7; 32]);

        assert!(!matches_guest_package_binding(None, provisioned));
        assert!(!matches_guest_package_binding(Some([8; 32]), provisioned));
        assert!(matches_guest_package_binding(Some([7; 32]), provisioned));
    }
}
