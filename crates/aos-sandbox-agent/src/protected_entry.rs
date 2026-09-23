//! Fixed inherited channel and sealed provisioning for the Linux guest agent.
//!
//! ```text
//! FD 3: connected SOCK_SEQPACKET channel with record subjects enabled
//! FD 4: fully sealed 258-byte AOSAGP01 provisioning memfd
//! AOSAGP01 = magic[8] || runtime[104] || channel[32] || instance[16]
//!          || Ed25519 seed[32] || feature_mask:u16be || package_binding[32]
//!          || SHA256(previous bytes)[32]
//! ```
//!
//! The host must bind the corresponding public key and channel to its protected
//! execution record. A sealed record alone is not a host authentication token;
//! launch confinement and descriptor custody establish that boundary.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::time::{Duration, Instant};

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, ExecutionId, IncarnationId, NamespaceGeneration,
    ObjectDigest, SandboxId,
};
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_linux::inherited_fd::{
    duplicate_inherited_descriptor, mark_inherited_descriptor_close_on_exec,
};
use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::DormantGuestAgentServiceV1;
use crate::model::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFeatureSetV1,
    AgentFeatureV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentOperationRequestV1,
    AgentOperationSequenceV1, AgentRuntimeBindingV1, AgentSessionBindingV1, InvalidAgentModel,
};
use crate::protocol::{
    AgentFrameV1, AgentProtocolError, MAX_AGENT_FRAME_BYTES, decode_frame_v1, encode_frame_v1,
};
use crate::signed_outcome_packet::{
    SignedAgentOutcomePacketErrorV1, SignedAgentOutcomePacketV1,
    encode_signed_agent_outcome_packet_v1,
};

const CHANNEL_DESCRIPTOR: i32 = 3;
const PROVISIONING_DESCRIPTOR: i32 = 4;
const PROVISIONING_BYTES: usize = 258;
const PROVISIONING_MAGIC: &[u8; 8] = b"AOSAGP01";
const CREDENTIAL_PATH: &str = "/run/credentials/aos-sandbox-agent/guest-executable-v1";
const CREDENTIAL_MAGIC: &[u8; 8] = b"AOSGEX01";
const CREDENTIAL_BYTES: usize = 104;
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1_048_576;
const O_CLOEXEC: i32 = 0o2_000_000;
const O_NOFOLLOW: i32 = 0o400_000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_millis(2);
const MAX_OPERATIONS: usize = 4_096;
const HANDSHAKE_SIGNATURE_DOMAIN: &[u8] = b"aos-sandbox-agent-handshake-signature-v1\0";

struct Provisioning {
    runtime: AgentRuntimeBindingV1,
    channel: ObjectDigest,
    instance: [u8; 16],
    signing_key: SigningKey,
    features: AgentFeatureSetV1,
    package_binding: ObjectDigest,
}

/// Builds the exact sealed launch record supplied to inherited FD 4.
///
/// The Host must publish the returned verifying key in its protected peer
/// binding and deliver the encoded bytes through a fully sealed memfd.
pub struct GuestAgentLaunchRecordV1 {
    runtime: AgentRuntimeBindingV1,
    channel: ObjectDigest,
    instance: [u8; 16],
    signing_key: SigningKey,
    features: AgentFeatureSetV1,
    package_binding: ObjectDigest,
}

impl GuestAgentLaunchRecordV1 {
    /// Constructs one non-sentinel launch record for a protected Host owner.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedGuestAgentErrorV1::InvalidProvisioning`] for a zero
    /// channel, instance, signing seed, or package binding.
    pub fn new(
        runtime: AgentRuntimeBindingV1,
        channel: ObjectDigest,
        instance: [u8; 16],
        signing_seed: [u8; 32],
        features: AgentFeatureSetV1,
        package_binding: ObjectDigest,
    ) -> Result<Self, ProtectedGuestAgentErrorV1> {
        if channel.as_bytes() == &[0; 32]
            || instance == [0; 16]
            || signing_seed == [0; 32]
            || package_binding.as_bytes() == &[0; 32]
        {
            return Err(ProtectedGuestAgentErrorV1::InvalidProvisioning);
        }
        Ok(Self {
            runtime,
            channel,
            instance,
            signing_key: SigningKey::from_bytes(&signing_seed),
            features,
            package_binding,
        })
    }

    /// Returns the public key the Host must bind to this exact channel.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Encodes the canonical 258-byte `AOSAGP01` sealed-memfd payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let runtime = &self.runtime;
        let mut bytes = Vec::with_capacity(PROVISIONING_BYTES);
        bytes.extend_from_slice(PROVISIONING_MAGIC);
        bytes.extend_from_slice(runtime.sandbox().as_bytes());
        bytes.extend_from_slice(runtime.incarnation().as_bytes());
        bytes.extend_from_slice(&runtime.assignment_epoch().get().to_be_bytes());
        bytes.extend_from_slice(runtime.assignment_digest().as_bytes());
        bytes.extend_from_slice(&runtime.desired_generation().get().to_be_bytes());
        bytes.extend_from_slice(&runtime.namespace_generation().get().to_be_bytes());
        bytes.extend_from_slice(runtime.payload_boot_id());
        bytes.extend_from_slice(self.channel.as_bytes());
        bytes.extend_from_slice(&self.instance);
        bytes.extend_from_slice(&self.signing_key.to_bytes());
        let feature_mask = self
            .features
            .as_slice()
            .iter()
            .fold(0_u16, |mask, feature| {
                mask | (1_u16 << (*feature as u8 - 1))
            });
        bytes.extend_from_slice(&feature_mask.to_be_bytes());
        bytes.extend_from_slice(self.package_binding.as_bytes());
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&checksum);
        bytes
    }
}

/// Applies a previously decoded operation within the guest-local effect owner.
///
/// An implementation must durably resolve a side effect before returning an
/// outcome. The protocol loop exits on any handler error and does not retry an
/// ambiguous effect.
pub trait GuestOperationEffectsV1 {
    /// Reports whether this effect owner implements an advertised feature.
    fn supports(&self, feature: AgentFeatureV1) -> bool;

    /// Applies one exact operation and returns its phase and bounded result.
    ///
    /// # Errors
    ///
    /// Returns an error if the effect or its observation cannot be established.
    fn apply(
        &mut self,
        request: &AgentOperationRequestV1,
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        deadline: Instant,
    ) -> Result<(AgentExecutionPhaseV1, Vec<u8>), ProtectedGuestAgentErrorV1>;
}

/// Conservatively handles the source-only guest without launching a process.
///
/// Authorize returns a signed terminal failure. Quiesce succeeds only because
/// this implementation cannot create guest processes. Unsupported controls
/// terminate the channel instead of inventing process observations.
#[derive(Default)]
pub struct RejectingGuestEffectsV1 {
    failed: BTreeMap<ExecutionId, AgentExecutionPhaseV1>,
    quiesced: bool,
}

impl GuestOperationEffectsV1 for RejectingGuestEffectsV1 {
    fn supports(&self, feature: AgentFeatureV1) -> bool {
        matches!(
            feature,
            AgentFeatureV1::Readiness
                | AgentFeatureV1::ExecutionHandoff
                | AgentFeatureV1::ExecutionObservation
                | AgentFeatureV1::Quiesce
        )
    }

    fn apply(
        &mut self,
        request: &AgentOperationRequestV1,
        _runtime: &AgentRuntimeBindingV1,
        _channel: ObjectDigest,
        _deadline: Instant,
    ) -> Result<(AgentExecutionPhaseV1, Vec<u8>), ProtectedGuestAgentErrorV1> {
        match request.operation() {
            AgentExecutionOperationV1::Authorize { execution, .. } if !self.quiesced => {
                self.failed
                    .insert(*execution, AgentExecutionPhaseV1::Failed);
                Ok((
                    AgentExecutionPhaseV1::Failed,
                    b"guest process effects unavailable".to_vec(),
                ))
            }
            AgentExecutionOperationV1::Observe { execution } => {
                let phase = self
                    .failed
                    .get(execution)
                    .ok_or(ProtectedGuestAgentErrorV1::EffectUnavailable)?;
                Ok((*phase, b"guest process was not started".to_vec()))
            }
            AgentExecutionOperationV1::BeginQuiesce if !self.quiesced => {
                self.quiesced = true;
                Ok((AgentExecutionPhaseV1::Quiesced, b"quiesced".to_vec()))
            }
            AgentExecutionOperationV1::EndQuiesce if self.quiesced => {
                self.quiesced = false;
                Ok((AgentExecutionPhaseV1::Ready, b"ready".to_vec()))
            }
            _ => Err(ProtectedGuestAgentErrorV1::EffectUnavailable),
        }
    }
}

/// Runs one provisioned guest-agent session on the fixed inherited channel.
pub struct ProtectedGuestAgentV1<Effects> {
    effects: Effects,
}

impl<Effects> ProtectedGuestAgentV1<Effects> {
    /// Creates an entry owner with its guest-local effect implementation.
    #[must_use]
    pub const fn new(effects: Effects) -> Self {
        Self { effects }
    }
}

impl<Effects: GuestOperationEffectsV1> DormantGuestAgentServiceV1
    for ProtectedGuestAgentV1<Effects>
{
    type Error = ProtectedGuestAgentErrorV1;

    fn run(&mut self) -> Result<(), Self::Error> {
        let channel = duplicate_inherited_descriptor(CHANNEL_DESCRIPTOR)?;
        let provisioning_fd = duplicate_inherited_descriptor(PROVISIONING_DESCRIPTOR)?;
        mark_inherited_descriptor_close_on_exec(CHANNEL_DESCRIPTOR)?;
        mark_inherited_descriptor_close_on_exec(PROVISIONING_DESCRIPTOR)?;
        let mut socket = SeqpacketSocket::from_owned(channel)?;
        let provisioning = SealedMemfdMapping::run(
            provisioning_fd,
            PROVISIONING_BYTES as u64,
            PROVISIONING_BYTES as u64,
            |bytes, _identity| decode_provisioning(bytes),
        )??;
        verify_package_credential(provisioning.package_binding)?;
        if provisioning
            .features
            .as_slice()
            .iter()
            .any(|feature| !self.effects.supports(*feature))
        {
            return Err(ProtectedGuestAgentErrorV1::UnsupportedFeature);
        }

        let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let request = match decode_frame_v1(&receive(&mut socket, handshake_deadline)?)? {
            AgentFrameV1::HandshakeRequest(request) => request,
            _ => return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame),
        };
        if request.runtime() != &provisioning.runtime
            || request.host_channel_binding() != provisioning.channel
        {
            return Err(ProtectedGuestAgentErrorV1::ProvisioningMismatch);
        }

        let binding = AgentSessionBindingV1::derive(&request, &provisioning.instance)?;
        let response = sign_handshake(&request, binding, &provisioning)?;
        send(
            &mut socket,
            &encode_frame_v1(&AgentFrameV1::HandshakeResponse(response)),
            handshake_deadline,
        )?;

        let mut next_sequence = AgentOperationSequenceV1::new(1)?;
        let mut last: Option<(AgentOperationRequestV1, Vec<u8>)> = None;
        for _ in 0..MAX_OPERATIONS {
            let deadline = Instant::now() + OPERATION_TIMEOUT;
            let request = match decode_frame_v1(&receive(&mut socket, deadline)?)? {
                AgentFrameV1::OperationRequest(request) => request,
                _ => return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame),
            };
            if request.session() != binding {
                return Err(ProtectedGuestAgentErrorV1::SessionMismatch);
            }
            if let Some((previous, packet)) = &last {
                if request.sequence() == previous.sequence() {
                    if request != *previous {
                        return Err(ProtectedGuestAgentErrorV1::Equivocation);
                    }
                    send(&mut socket, packet, deadline)?;
                    continue;
                }
            }
            if request.sequence() != next_sequence {
                return Err(ProtectedGuestAgentErrorV1::SequenceMismatch);
            }
            validate_operation(&request, &provisioning)?;
            check_deadline(deadline)?;

            let (phase, result) = self.effects.apply(
                &request,
                &provisioning.runtime,
                provisioning.channel,
                deadline,
            )?;
            // A late durable effect is recovered from its owner; it cannot
            // become a fresh response on an expired exchange.
            check_deadline(deadline)?;
            validate_outcome_phase(request.operation(), phase)?;
            let outcome = AgentExecutionOutcomeV1::new(&request, phase, result)?;
            let message =
                aos_sandbox_core::runtime_backend::backend_agent_outcome_signing_message_v1(
                    provisioning.channel,
                    request.backend_request_binding(),
                    binding.digest(),
                    request.sequence().get(),
                    *request.operation_id().as_bytes(),
                    request.request_commitment(),
                    outcome.outcome_commitment(),
                );
            let signature = provisioning.signing_key.sign(&message).to_bytes();
            let packet = SignedAgentOutcomePacketV1::new(outcome, signature)?;
            let bytes = encode_signed_agent_outcome_packet_v1(&packet)?;
            send(&mut socket, &bytes, deadline)?;

            next_sequence = next_sequence.checked_next()?;
            last = Some((request, bytes));
        }
        Err(ProtectedGuestAgentErrorV1::OperationLimit)
    }
}

fn validate_operation(
    request: &AgentOperationRequestV1,
    provisioning: &Provisioning,
) -> Result<(), ProtectedGuestAgentErrorV1> {
    let required = match request.operation() {
        AgentExecutionOperationV1::Authorize {
            specification_bytes,
            ..
        } => {
            let specification = aos_sandbox_core::decode_execution_spec_v1(
                specification_bytes,
                aos_sandbox_core::DecodeLimits {
                    maximum_bytes: specification_bytes.len(),
                    maximum_collection_items: 65_536,
                    maximum_total_items: 262_144,
                    maximum_byte_string_bytes: 15 * 1_048_576,
                    maximum_text_bytes: 1_048_576,
                    maximum_depth: 128,
                },
            )
            .map_err(|_| ProtectedGuestAgentErrorV1::OperationMismatch)?;
            let target = specification.target();
            let runtime = &provisioning.runtime;
            if target.sandbox() != runtime.sandbox()
                || target.incarnation() != runtime.incarnation()
                || target.assignment_epoch() != runtime.assignment_epoch()
                || target.assignment_digest() != runtime.assignment_digest()
                || target.namespace_generation() != runtime.namespace_generation()
                || target.payload_boot_id().as_bytes() != runtime.payload_boot_id()
            {
                return Err(ProtectedGuestAgentErrorV1::OperationMismatch);
            }
            Some(AgentFeatureV1::ExecutionHandoff)
        }
        AgentExecutionOperationV1::ResizeTerminal { .. } => Some(AgentFeatureV1::TerminalResize),
        AgentExecutionOperationV1::Signal { .. } => Some(AgentFeatureV1::ExecutionSignal),
        AgentExecutionOperationV1::Observe { .. } => Some(AgentFeatureV1::ExecutionObservation),
        AgentExecutionOperationV1::BeginQuiesce | AgentExecutionOperationV1::EndQuiesce => {
            Some(AgentFeatureV1::Quiesce)
        }
        AgentExecutionOperationV1::Cancel { .. } => None,
    };
    if required.is_some_and(|feature| !provisioning.features.contains(feature)) {
        return Err(ProtectedGuestAgentErrorV1::UnsupportedFeature);
    }
    Ok(())
}

fn validate_outcome_phase(
    operation: &AgentExecutionOperationV1,
    phase: AgentExecutionPhaseV1,
) -> Result<(), ProtectedGuestAgentErrorV1> {
    let valid = match operation {
        AgentExecutionOperationV1::Authorize { .. } => matches!(
            phase,
            AgentExecutionPhaseV1::Authorized
                | AgentExecutionPhaseV1::Starting
                | AgentExecutionPhaseV1::Running
                | AgentExecutionPhaseV1::Failed
        ),
        AgentExecutionOperationV1::Cancel { .. } => matches!(
            phase,
            AgentExecutionPhaseV1::Canceled
                | AgentExecutionPhaseV1::Exited
                | AgentExecutionPhaseV1::Failed
                | AgentExecutionPhaseV1::Lost
        ),
        AgentExecutionOperationV1::BeginQuiesce => phase == AgentExecutionPhaseV1::Quiesced,
        AgentExecutionOperationV1::EndQuiesce => phase == AgentExecutionPhaseV1::Ready,
        AgentExecutionOperationV1::ResizeTerminal { .. }
        | AgentExecutionOperationV1::Signal { .. }
        | AgentExecutionOperationV1::Observe { .. } => !matches!(
            phase,
            AgentExecutionPhaseV1::Quiesced | AgentExecutionPhaseV1::Ready
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(ProtectedGuestAgentErrorV1::InvalidOutcomePhase)
    }
}

fn sign_handshake(
    request: &AgentHandshakeRequestV1,
    binding: AgentSessionBindingV1,
    provisioning: &Provisioning,
) -> Result<AgentHandshakeResponseV1, ProtectedGuestAgentErrorV1> {
    let mut digest = Sha256::new();
    digest.update(HANDSHAKE_SIGNATURE_DOMAIN);
    digest.update(binding.digest().as_bytes());
    digest.update(request.challenge().as_bytes());
    digest.update(request.host_channel_binding().as_bytes());
    digest.update(provisioning.instance);
    digest.update((provisioning.features.as_slice().len() as u16).to_be_bytes());
    for feature in provisioning.features.as_slice() {
        digest.update([*feature as u8]);
    }
    let message: [u8; 32] = digest.finalize().into();
    let signature = provisioning.signing_key.sign(&message).to_bytes();
    Ok(AgentHandshakeResponseV1::new(
        binding,
        provisioning.instance,
        provisioning.features.clone(),
        signature,
    )?)
}

fn decode_provisioning(bytes: &[u8]) -> Result<Provisioning, ProtectedGuestAgentErrorV1> {
    if bytes.len() != PROVISIONING_BYTES || bytes.get(..8) != Some(PROVISIONING_MAGIC.as_slice()) {
        return Err(ProtectedGuestAgentErrorV1::InvalidProvisioning);
    }
    let expected: [u8; 32] = Sha256::digest(&bytes[..226]).into();
    if bytes[226..] != expected {
        return Err(ProtectedGuestAgentErrorV1::InvalidProvisioning);
    }
    let mut cursor = ProvisioningCursor::new(&bytes[8..226]);
    let runtime = AgentRuntimeBindingV1::new(
        SandboxId::from_bytes(cursor.array()?),
        IncarnationId::from_bytes(cursor.array()?),
        AssignmentEpoch::new(cursor.u64()?),
        ObjectDigest::from_bytes(cursor.array()?),
        DesiredGeneration::new(cursor.u64()?),
        NamespaceGeneration::new(cursor.u64()?),
        cursor.array()?,
    )?;
    let channel = ObjectDigest::from_bytes(cursor.array()?);
    let instance = cursor.array()?;
    let seed: [u8; 32] = cursor.array()?;
    let mask = cursor.u16()?;
    let package_binding = ObjectDigest::from_bytes(cursor.array()?);
    if !cursor.complete()
        || channel.as_bytes() == &[0; 32]
        || instance == [0; 16]
        || seed == [0; 32]
        || package_binding.as_bytes() == &[0; 32]
        || mask & !0x003f != 0
    {
        return Err(ProtectedGuestAgentErrorV1::InvalidProvisioning);
    }
    let features = [
        AgentFeatureV1::Readiness,
        AgentFeatureV1::ExecutionHandoff,
        AgentFeatureV1::ExecutionObservation,
        AgentFeatureV1::TerminalResize,
        AgentFeatureV1::ExecutionSignal,
        AgentFeatureV1::Quiesce,
    ]
    .into_iter()
    .filter(|feature| mask & (1_u16 << (*feature as u8 - 1)) != 0)
    .collect();
    Ok(Provisioning {
        runtime,
        channel,
        instance,
        signing_key: SigningKey::from_bytes(&seed),
        features: AgentFeatureSetV1::new(features)?,
        package_binding,
    })
}

fn verify_package_credential(binding: ObjectDigest) -> Result<(), ProtectedGuestAgentErrorV1> {
    let credential = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW)
        .open(CREDENTIAL_PATH)?;
    let metadata = credential.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(ProtectedGuestAgentErrorV1::InvalidCredential);
    }
    let mut bytes = Vec::new();
    credential
        .take((CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != CREDENTIAL_BYTES || bytes.get(..8) != Some(CREDENTIAL_MAGIC.as_slice()) {
        return Err(ProtectedGuestAgentErrorV1::InvalidCredential);
    }
    let expected: [u8; 32] = Sha256::digest(&bytes[..72]).into();
    if bytes[72..] != expected || bytes[40..72] != *binding.as_bytes() {
        return Err(ProtectedGuestAgentErrorV1::InvalidCredential);
    }

    let executable = File::open("/proc/self/exe")?;
    let metadata = executable.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(ProtectedGuestAgentErrorV1::InvalidCredential);
    }
    let mut hash = Sha256::new();
    let mut reader = executable.take(MAX_EXECUTABLE_BYTES + 1);
    let mut buffer = [0_u8; 8192];
    let mut copied = 0_u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        copied += count as u64;
    }
    let actual: [u8; 32] = hash.finalize().into();
    if copied != metadata.len() || bytes[8..40] != actual {
        return Err(ProtectedGuestAgentErrorV1::InvalidCredential);
    }
    Ok(())
}

fn receive(
    socket: &mut SeqpacketSocket,
    deadline: Instant,
) -> Result<Vec<u8>, ProtectedGuestAgentErrorV1> {
    loop {
        check_deadline(deadline)?;
        match socket.receive(MAX_AGENT_FRAME_BYTES) {
            Ok(record) => return Ok(record.payload().to_vec()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted)
                if Instant::now() < deadline =>
            {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return Err(ProtectedGuestAgentErrorV1::Deadline);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn send(
    socket: &mut SeqpacketSocket,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), ProtectedGuestAgentErrorV1> {
    loop {
        check_deadline(deadline)?;
        match socket.send(bytes) {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted)
                if Instant::now() < deadline =>
            {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return Err(ProtectedGuestAgentErrorV1::Deadline);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn check_deadline(deadline: Instant) -> Result<(), ProtectedGuestAgentErrorV1> {
    if Instant::now() >= deadline {
        Err(ProtectedGuestAgentErrorV1::Deadline)
    } else {
        Ok(())
    }
}

struct ProvisioningCursor<'a> {
    bytes: &'a [u8],
}

impl<'a> ProvisioningCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtectedGuestAgentErrorV1> {
        let (head, tail) = self
            .bytes
            .split_at_checked(N)
            .ok_or(ProtectedGuestAgentErrorV1::InvalidProvisioning)?;
        self.bytes = tail;
        head.try_into()
            .map_err(|_| ProtectedGuestAgentErrorV1::InvalidProvisioning)
    }

    fn u64(&mut self) -> Result<u64, ProtectedGuestAgentErrorV1> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16, ProtectedGuestAgentErrorV1> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn complete(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Reports a failure at the protected guest-agent startup or session boundary.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedGuestAgentErrorV1 {
    /// A fixed inherited descriptor is unavailable or invalid.
    #[error("guest-agent descriptor boundary failed: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The connected channel is unavailable or malformed.
    #[error("guest-agent channel failed: {0}")]
    Transport(#[from] SeqpacketError),
    /// The provisioning descriptor is not a fully sealed immutable memfd.
    #[error("guest-agent provisioning seal failed: {0}")]
    Immutable(#[from] aos_sandbox_linux::immutable_file::ImmutableFileError),
    /// The fixed package credential cannot be read or the executable cannot be measured.
    #[error("guest-agent package credential read failed: {0}")]
    Io(#[from] std::io::Error),
    /// The sealed provisioning bytes or values are malformed.
    #[error("guest-agent provisioning record is invalid")]
    InvalidProvisioning,
    /// The fixed root credential or running executable does not match provisioning.
    #[error("guest-agent package credential is invalid")]
    InvalidCredential,
    /// Provisioning advertises a feature the concrete guest effect owner lacks.
    #[error("guest-agent provisioned feature is unavailable")]
    UnsupportedFeature,
    /// The request does not match the exact provisioned runtime and channel.
    #[error("guest-agent handshake does not match provisioning")]
    ProvisioningMismatch,
    /// A frame arrived in the wrong direction or phase.
    #[error("guest-agent received an unexpected frame")]
    UnexpectedFrame,
    /// An operation belongs to another session.
    #[error("guest-agent operation session differs from handshake")]
    SessionMismatch,
    /// The operation target differs from the provisioned runtime.
    #[error("guest-agent operation target differs from provisioning")]
    OperationMismatch,
    /// An operation skipped, rolled back, or repeated an unexpected sequence.
    #[error("guest-agent operation sequence is invalid")]
    SequenceMismatch,
    /// An operation repeats the latest sequence with different arguments.
    #[error("guest-agent operation equivocation detected")]
    Equivocation,
    /// A bounded exchange exceeded its deadline.
    #[error("guest-agent exchange deadline exceeded")]
    Deadline,
    /// The maximum operations for this channel have been processed.
    #[error("guest-agent operation limit reached")]
    OperationLimit,
    /// Guest-local process effect or observation is unavailable.
    #[error("guest-agent process effect is unavailable")]
    EffectUnavailable,
    /// Guest-local effect or protected ledger processing failed.
    #[error("guest-agent protected effect failed: {0}")]
    EffectFailed(String),
    /// The effect owner returned a phase invalid for this operation.
    #[error("guest-agent effect returned an invalid phase")]
    InvalidOutcomePhase,
    /// A model value is semantically invalid.
    #[error("guest-agent model is invalid: {0}")]
    Model(#[from] InvalidAgentModel),
    /// A canonical frame is malformed.
    #[error("guest-agent frame is invalid: {0}")]
    Protocol(#[from] AgentProtocolError),
    /// A signed outcome packet cannot be encoded.
    #[error("guest-agent signed outcome is invalid: {0}")]
    SignedOutcome(#[from] SignedAgentOutcomePacketErrorV1),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_record_round_trips_the_exact_sealed_layout() {
        let runtime = AgentRuntimeBindingV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            ObjectDigest::from_bytes([4; 32]),
            DesiredGeneration::new(5),
            NamespaceGeneration::new(6),
            [7; 16],
        )
        .expect("valid runtime");
        let features = AgentFeatureSetV1::new(vec![
            AgentFeatureV1::Readiness,
            AgentFeatureV1::ExecutionHandoff,
            AgentFeatureV1::Quiesce,
        ])
        .expect("valid features");
        let launch = GuestAgentLaunchRecordV1::new(
            runtime,
            ObjectDigest::from_bytes([8; 32]),
            [9; 16],
            [10; 32],
            features.clone(),
            ObjectDigest::from_bytes([11; 32]),
        )
        .expect("valid launch record");

        let bytes = launch.encode();
        assert_eq!(bytes.len(), PROVISIONING_BYTES);
        let decoded = decode_provisioning(&bytes).expect("canonical provisioning");
        assert_eq!(decoded.runtime, runtime);
        assert_eq!(decoded.channel, ObjectDigest::from_bytes([8; 32]));
        assert_eq!(decoded.instance, [9; 16]);
        assert_eq!(decoded.features, features);
        assert_eq!(
            decoded.signing_key.verifying_key().to_bytes(),
            launch.verifying_key_bytes()
        );
        assert_eq!(decoded.package_binding, ObjectDigest::from_bytes([11; 32]));

        let mut malformed = bytes;
        malformed[193] |= 0x40;
        let checksum: [u8; 32] = Sha256::digest(&malformed[..226]).into();
        malformed[226..].copy_from_slice(&checksum);
        assert!(matches!(
            decode_provisioning(&malformed),
            Err(ProtectedGuestAgentErrorV1::InvalidProvisioning)
        ));
    }

    #[test]
    fn expired_exchange_is_rejected_before_io() {
        assert!(matches!(
            check_deadline(Instant::now() - Duration::from_millis(1)),
            Err(ProtectedGuestAgentErrorV1::Deadline)
        ));
    }
}
