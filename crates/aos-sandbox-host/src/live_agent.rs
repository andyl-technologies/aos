//! Retained Host custody for one explicitly provisioned AOSAGE guest channel.
//!
//! A launch owner supplies a one-time signing record already matching the
//! protected runtime peer. This module creates the private socket pair and
//! sealed guest credential, then retains the Host endpoint across a signed
//! handshake and bounded stop-and-wait exchanges. It never discovers an
//! inherited descriptor, reconnects to a path, or activates nspawn.

use std::os::fd::{BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionClaimV1, DormantRuntimeExecutionOwnerErrorV1,
    agent_handshake_signing_message_v1,
};
use aos_sandbox_agent::protected_entry::GuestAgentLaunchRecordV1;
use aos_sandbox_agent::{
    AgentFrameV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentNonceV1,
    AgentProtocolError, AgentRuntimeBindingV1, AgentSessionBindingV1, AgentSessionIdV1,
    InvalidAgentModel, decode_frame_v1, encode_frame_v1,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::runtime_backend::AdmissionCurrentnessV1;
use aos_sandbox_linux::immutable_file::{ImmutableFileError, SealedReadOnlyCredential};
use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{TryRngCore as _, rngs::OsRng};
use zeroize::Zeroizing;

use crate::attach_route::OpenSshGateAgentExchangeV1;

const PROVISIONING_BYTES: usize = 258;
const RETRY_INTERVAL: Duration = Duration::from_millis(2);
const GATE_TIMEOUT: Duration = Duration::from_secs(30);

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
}

/// Owns both launch descriptors before their explicit transfer to the guest.
pub struct HostAgentGuestLaunchDescriptorsV1 {
    channel: OwnedFd,
    provisioning: SealedReadOnlyCredential,
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
}

/// Prepares an exact launch without allowing a socket or signer substitution.
pub struct HostAgentLaunchHandoffV1 {
    pending: HostAgentPendingSessionV1,
    guest: HostAgentGuestLaunchDescriptorsV1,
}

impl HostAgentLaunchHandoffV1 {
    /// Creates a private channel and sealed FD 4 from a matching launch record.
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
        record: GuestAgentLaunchRecordV1,
    ) -> Result<Self, HostAgentLiveErrorV1> {
        claim.revalidate()?;
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
        let guest = HostAgentGuestLaunchDescriptorsV1 {
            channel,
            provisioning,
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
        Ok(Self { pending, guest })
    }

    /// Splits the still-private Host endpoint from the two guest descriptors.
    #[must_use]
    pub fn into_parts(self) -> (HostAgentPendingSessionV1, HostAgentGuestLaunchDescriptorsV1) {
        (self.pending, self.guest)
    }
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
        )?;
        let response = match decode_frame_v1(&receive_frame(&mut self.socket, deadline)?)? {
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

    // Only a checked gate frame reaches this helper. Effect-bearing operations
    // need their own durable route consumption before sharing this socket.
    fn exchange_frame(
        &mut self,
        request: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, HostAgentLiveErrorV1> {
        send_frame(&mut self.socket, request, deadline)?;
        receive_frame(&mut self.socket, deadline)
    }
}

impl OpenSshGateAgentExchangeV1 for HostAgentLiveSessionV1 {
    fn exchange(&mut self, request: &[u8]) -> std::io::Result<Vec<u8>> {
        if !matches!(
            decode_frame_v1(request),
            Ok(AgentFrameV1::OpenSshGateObserveRequest(_))
        ) {
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

fn send_frame(
    socket: &mut SeqpacketSocket,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), HostAgentLiveErrorV1> {
    loop {
        if Instant::now() >= deadline {
            return Err(HostAgentLiveErrorV1::Deadline);
        }
        match socket.send(bytes) {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_frame(
    socket: &mut SeqpacketSocket,
    deadline: Instant,
) -> Result<Vec<u8>, HostAgentLiveErrorV1> {
    loop {
        if Instant::now() >= deadline {
            return Err(HostAgentLiveErrorV1::Deadline);
        }
        match socket.receive(aos_sandbox_agent::protocol::MAX_AGENT_FRAME_BYTES) {
            Ok(record) => return Ok(record.payload().to_vec()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }
}
