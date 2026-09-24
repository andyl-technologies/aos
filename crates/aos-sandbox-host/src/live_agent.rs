//! Retained Host custody for one explicitly provisioned AOSAGE guest channel.
//!
//! A launch owner supplies a one-time signing record already matching the
//! protected runtime peer. This module creates the private socket pair and
//! sealed guest credentials, then retains the Host endpoint across a signed
//! handshake and bounded stop-and-wait exchanges. It never discovers an
//! inherited descriptor, reconnects to a path, or activates nspawn.

pub(crate) mod argument_attempt;
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
        OsRng
            .try_fill_bytes(&mut session)
            .map_err(|_| HostAgentLiveErrorV1::Entropy)?;
        OsRng
            .try_fill_bytes(&mut challenge)
            .map_err(|_| HostAgentLiveErrorV1::Entropy)?;
        let handshake = AgentHandshakeRequestV1::new(
            AgentSessionIdV1::new(session)?,
            self.runtime,
            AgentNonceV1::new(challenge)?,
            self.channel_binding,
        )?;

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
        let binding = AgentSessionBindingV1::derive(&handshake, response.agent_instance())?;
        if response.session_binding() != binding
            || response.agent_instance() != &self.agent_instance
            || response.features() != &self.features
        {
            return Err(HostAgentLiveErrorV1::Unauthenticated);
        }
        let message = agent_handshake_signing_message_v1(
            &handshake,
            binding,
            response.agent_instance(),
            response.features(),
        );
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| HostAgentLiveErrorV1::Unauthenticated)?;
        key.verify_strict(
            &message,
            &Signature::from_bytes(response.challenge_signature()),
        )
        .map_err(|_| HostAgentLiveErrorV1::Unauthenticated)?;
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
            decode_frame_v1(&response),
            Ok(AgentFrameV1::OpenSshGateReadback(_))
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
                Ok(AgentFrameV1::OpenSshGateObserveRequest(_))
            )
        {
            return Err(std::io::Error::other(
                "only gate observations use this exchange",
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
    loop {
        check_deadline(deadline, deadline_boottime_nanoseconds)?;
        match socket.receive(maximum_bytes) {
            Ok(record) => return Ok(record.payload().to_vec()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(error) => return Err(error.into()),
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
