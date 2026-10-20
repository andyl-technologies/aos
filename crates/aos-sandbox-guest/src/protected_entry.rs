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

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::time::{Duration, Instant};

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration,
    ObjectDigest, SandboxId,
};
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_linux::inherited_fd::{
    duplicate_inherited_descriptor, mark_inherited_descriptor_close_on_exec,
};
use aos_sandbox_linux::seqpacket::{
    GuestAncestorHostChannelV1, GuestAncestorHostRecordV1,
    RetainedSeqpacketReceiveErrorV1, SeqpacketError, SeqpacketSocket,
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::DormantGuestAgentServiceV1;
mod active_control;
mod handshake;
use crate::runtime_argument_observation::sign_current_guest_argument_readback_v1;
#[cfg(test)]
use aos_sandbox_agent::launch::GuestAgentLaunchRecordV1;
use aos_sandbox_agent::launch::{
    GUEST_AGENT_PROVISIONING_BYTES_V1, GUEST_AGENT_PROVISIONING_MAGIC_V1 as PROVISIONING_MAGIC,
    encode_agent_runtime_binding_v1,
};
use aos_sandbox_agent::model::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFeatureSetV1,
    AgentFeatureV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentOperationRequestV1,
    AgentOperationSequenceV1, AgentRuntimeBindingV1, AgentSessionBindingV1, InvalidAgentModel,
};
use aos_sandbox_agent::openssh_gate::{
    OpenSshGateObserveRequestV1, OpenSshGateReadbackV1, sign_openssh_gate_readback_v1,
};
use aos_sandbox_agent::protocol::{
    AgentFrameV1, AgentProtocolError, MAX_AGENT_FRAME_BYTES, MAX_AGENT_SEALED_SPEC_BYTES_V1,
    decode_frame_v1, encode_frame_v1,
};
use aos_sandbox_agent::runtime_argument_observation::{
    ARGUMENT_OBSERVE_REQUEST_MAGIC_V1, GuestRuntimeArgumentObservationErrorV1,
    GuestRuntimeArgumentObserveRequestV1,
};
use aos_sandbox_agent::signed_outcome_packet::{
    SignedAgentOutcomePacketErrorV1, SignedAgentOutcomePacketV1,
    encode_signed_agent_outcome_packet_v1,
};

const CHANNEL_DESCRIPTOR: i32 = 3;
const PROVISIONING_DESCRIPTOR: i32 = 4;
const CREDENTIAL_PATH: &str = "/etc/aos/sandbox-agent/guest-executable-v1";
const CREDENTIAL_MAGIC: &[u8; 8] = b"AOSGEX01";
const CREDENTIAL_BYTES: usize = 104;
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1_048_576;
const O_CLOEXEC: i32 = 0o2_000_000;
const O_NOFOLLOW: i32 = 0o400_000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

mod operation_deadline;
pub use operation_deadline::GuestOperationDeadlineOriginalV1;
const RETRY_INTERVAL: Duration = Duration::from_millis(2);
const MAX_OPERATIONS: usize = 4_096;
const HANDSHAKE_SIGNATURE_DOMAIN: &[u8] = b"aos-sandbox-agent-handshake-signature-v1\0";

/// Compares private canary challenge DATA with the canonical sealed launch tuple.
///
/// The result is only the supplied original deadline. It is not a job approval,
/// a visible Host identity, a current session or permission to perform effects.
/// The selected caller must retain its genuine inherited channel and canonical
/// provisioning originals; Host independently checks the supplied deadline.
///
/// # Errors
/// Refuses any width, framing, runtime, channel-binding or deadline mismatch.
pub fn require_host_canary_challenge_v1(
    bytes: &[u8],
    runtime: &[u8; 104],
    channel: [u8; 32],
) -> Result<u64, ProtectedGuestAgentErrorV1> {
    use aos_sandbox_linux::guest_startup_report::{HostStartupReportChallengeErrorV1,
        HostStartupReportKindV1, require_host_startup_report_challenge_v1};
    let (kind, deadline) = require_host_startup_report_challenge_v1(bytes, runtime, channel)
        .map_err(|cause| match cause {
            HostStartupReportChallengeErrorV1::Mismatch => ProtectedGuestAgentErrorV1::ProvisioningMismatch,
            HostStartupReportChallengeErrorV1::Deadline => ProtectedGuestAgentErrorV1::InvalidProvisioning,
        })?;
    if kind != HostStartupReportKindV1::Canary {
        return Err(ProtectedGuestAgentErrorV1::ProvisioningMismatch);
    }
    Ok(deadline)
}

// No effect owner is created for this selected entry. Its actual channel,
// secret, received records and first failure stay resident until Host Stop or
// the original D. Error/unwind terminates before releasing those originals.
struct HostCanaryAgentReadinessV1 {
    channel: GuestAncestorHostChannelV1,
    original_provisioning: Option<OwnedFd>,
    provisioning_bytes: [u8; GUEST_AGENT_PROVISIONING_BYTES_V1],
    provisioning: Option<Provisioning>,
    records: [Option<GuestAncestorHostRecordV1>; 3],
    receive_failure: Option<RetainedSeqpacketReceiveErrorV1>,
    response: Vec<u8>,
    deadline: u64,
    armed: bool,
    first_failure: Option<Box<dyn std::error::Error>>,
}

impl HostCanaryAgentReadinessV1 {
    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.channel.capture_agent_original()
            .map_err(|_| "selected Agent channel capture failed; original cause remains resident")?;
        self.original_provisioning = Some(duplicate_inherited_descriptor(PROVISIONING_DESCRIPTOR)?);
        mark_inherited_descriptor_close_on_exec(CHANNEL_DESCRIPTOR)?;
        mark_inherited_descriptor_close_on_exec(PROVISIONING_DESCRIPTOR)?;
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;

        let duplicate = self.original_provisioning.as_ref()
            .ok_or("selected Agent provisioning is absent")?.as_fd().try_clone_to_owned()?;
        SealedMemfdMapping::run(
            duplicate,
            GUEST_AGENT_PROVISIONING_BYTES_V1 as u64,
            GUEST_AGENT_PROVISIONING_BYTES_V1 as u64,
            |bytes, _identity| self.provisioning_bytes.copy_from_slice(bytes),
        )?;
        self.provisioning = Some(decode_provisioning(&self.provisioning_bytes)?);
        let provisioning = self.provisioning.as_ref().ok_or("selected Agent provisioning is absent")?;
        verify_package_credential(provisioning.package_binding)?;
        let mask = provisioning.features.as_slice().iter().fold(0_u16, |mask, feature| {
            mask | (1_u16 << (*feature as u8 - 1))
        });
        if mask != aos_sandbox_agent::guest_root_publication::CONCRETE_GUEST_FEATURE_MASK_V1 {
            return Err(ProtectedGuestAgentErrorV1::UnsupportedFeature.into());
        }
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;

        let prechallenge = aos_sandbox_linux::seqpacket::bounded::boottime()?
            .checked_add(30_000_000_000).ok_or(ProtectedGuestAgentErrorV1::Deadline)?;
        self.receive_original(0, 200, prechallenge)?;
        let challenge = self.records[0].as_ref().ok_or("selected Agent challenge is absent")?;
        let provisioning = self.provisioning.as_ref().ok_or("selected Agent provisioning is absent")?;
        self.deadline = require_host_canary_challenge_v1(
            challenge.payload(),
            &encode_agent_runtime_binding_v1(provisioning.runtime),
            *provisioning.channel.as_bytes(),
        )?;
        self.require_before(self.deadline)?;
        self.receive_original(1, MAX_AGENT_FRAME_BYTES, self.deadline)?;

        let record = self.records[1].as_ref().ok_or("selected Agent handshake is absent")?;
        let request = match decode_frame_v1(record.payload())? {
            AgentFrameV1::HandshakeRequest(request) => request,
            _ => return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame.into()),
        };
        let provisioning = self.provisioning.as_ref().ok_or("selected Agent provisioning is absent")?;
        if request.runtime() != &provisioning.runtime
            || request.host_channel_binding() != provisioning.channel
        {
            return Err(ProtectedGuestAgentErrorV1::ProvisioningMismatch.into());
        }
        let binding = AgentSessionBindingV1::derive(&request, &provisioning.instance)?;
        let response = sign_handshake(&request, binding, provisioning)?;
        self.response = encode_frame_v1(&AgentFrameV1::HandshakeResponse(response));
        loop {
            self.require_before(self.deadline)?;
            match self.channel.send(&self.response) {
                Ok(()) => break,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    std::thread::sleep(RETRY_INTERVAL);
                }
                Err(cause) => return Err(cause.into()),
            }
        }
        self.require_before(self.deadline)?;

        // The actual signing process must remain live for Host physical
        // postchecks. No operations, attach, renewal or execution loop exists.
        self.receive_original(2, MAX_AGENT_FRAME_BYTES, self.deadline)?;
        Err(ProtectedGuestAgentErrorV1::UnexpectedFrame.into())
    }

    fn receive_original(&mut self, slot: usize, maximum: usize, deadline: u64) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            self.require_before(deadline)?;
            match self.channel.receive_retaining(maximum) {
                Ok(record) => {
                    self.records[slot] = Some(record);
                    self.require_before(deadline)?;
                    self.channel.require_record_original(
                        self.records[slot].as_ref().ok_or("selected Agent record is absent")?,
                    )?;
                    return Ok(());
                }
                Err(cause) if cause.is_nonconsuming_would_block() || cause.is_nonconsuming_interrupted() => {
                    std::thread::sleep(RETRY_INTERVAL);
                }
                Err(cause) => {
                    self.receive_failure = Some(cause);
                    return Err("selected Agent receive failed; original cause remains resident".into());
                }
            }
        }
    }

    fn require_before(&self, deadline: u64) -> Result<(), Box<dyn std::error::Error>> {
        if aos_sandbox_linux::seqpacket::bounded::boottime()? >= deadline {
            return Err(ProtectedGuestAgentErrorV1::Deadline.into());
        }
        Ok(())
    }
}

impl Drop for HostCanaryAgentReadinessV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
        self.provisioning_bytes.fill(0);
    }
}

/// Runs the fixed selected Host-canary handshake without a Guest effect owner.
///
/// This consumes only genuine inherited slots 3/4, the sealed canonical launch
/// record and fixed package credential. It remains alive until actual Host Stop
/// or original D; neither a signature nor the private challenge yields runtime
/// execution authority, currentness, teardown or Drain.
///
/// # Errors
/// Captured first failures remain resident before process termination. No
/// failed or interrupted owner can be reused, and the deadline is never renewed.
pub fn run_host_canary_readiness_v1() -> Result<(), Box<dyn std::error::Error>> {
    let mut owner = HostCanaryAgentReadinessV1 {
        channel: GuestAncestorHostChannelV1::new(),
        original_provisioning: None,
        provisioning_bytes: [0; GUEST_AGENT_PROVISIONING_BYTES_V1],
        provisioning: None,
        records: std::array::from_fn(|_| None),
        receive_failure: None,
        response: Vec::new(),
        deadline: 0,
        armed: true,
        first_failure: None,
    };
    match owner.run() {
        Ok(()) => {
            owner.armed = false;
            Ok(())
        }
        Err(cause) => {
            owner.first_failure = Some(cause);
            Err("selected Host canary Agent failed; original cause remains resident".into())
        }
    }
}

struct Provisioning {
    runtime: AgentRuntimeBindingV1,
    channel: ObjectDigest,
    instance: [u8; 16],
    signing_key: SigningKey,
    features: AgentFeatureSetV1,
    package_binding: ObjectDigest,
}


/// Applies a previously decoded operation within the guest-local effect owner.
///
/// An implementation must durably resolve a side effect before returning an
/// outcome. The protocol loop exits on any handler error and does not retry an
/// ambiguous effect.
pub trait GuestOperationEffectsV1 {
    /// Borrows the actual failed selected SSH startup original for diagnostics.
    ///
    /// This performs no sampling or live-authority check and cannot recover an
    /// operation. Adapters without that native owner return no such cause.
    fn selected_openssh_startup_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
    /// Borrows actual completed native/IO retirement, never historical absence.
    ///
    /// The default has no original process custody and cannot supply this
    /// constructor-closed token. It authorizes no effect or cancellation.
    fn original_transport_retirement_v2(&self) -> Option<&crate::OriginalExecutionTransportRetirementV2> { None }
    /// Services already-owned execution deadlines without authorizing an operation.
    ///
    /// The default preserves adapters with no native child custody. The process
    /// owner publishes only actual reaped outcomes; failures stay on its original.
    fn service_original_deadlines_v1(&mut self) {}

    /// Reports actual retained child/startup custody, never a historical PID row.
    fn has_original_execution_custody_v1(&self) -> bool { false }

    /// Reports whether this effect owner implements an advertised feature.
    fn supports(&self, feature: AgentFeatureV1) -> bool;

    /// Fences a Running/started reply against its actual original child lifetime.
    ///
    /// # Errors
    /// The native process owner refuses an expired, failed or foreign original.
    fn require_original_start_reply_current_v1(&mut self, _request: &AgentOperationRequestV1,
        _runtime: &AgentRuntimeBindingV1) -> Result<(), ProtectedGuestAgentErrorV1> { Ok(()) }

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

    /// Applies the same operation with its actual received Capture pipe owner.
    ///
    /// The default refuses without ordinary fallback. The fixed process owner
    /// shares its existing durable reducer and spawn kernel with Stream/PTY.
    ///
    /// # Errors
    /// Retains failed received/spec/pipe/launch custody on the supplied original.
    fn apply_capture_v2(
        &mut self,
        _request: &AgentOperationRequestV1,
        _runtime: &AgentRuntimeBindingV1,
        _channel: ObjectDigest,
        _deadline: Instant,
        _capture: &mut crate::capture::GuestCaptureAuthorizeOriginalV2,
    ) -> Result<(AgentExecutionPhaseV1, Vec<u8>), ProtectedGuestAgentErrorV1> {
        Err(ProtectedGuestAgentErrorV1::CaptureRefused)
    }

    /// Applies the explicit SSH Authorize through the same live process owner.
    ///
    /// The plan is comparison DATA from the authenticated, fully reconstructed
    /// request. It supplies no financial reservation or adopted process scope.
    ///
    /// # Errors
    /// Refuses adapters without the actual original process/native owner or a
    /// mismatched request, execution shape, durable reservation or effect.
    fn apply_ssh_authorize_v1(
        &mut self,
        _request: &AgentOperationRequestV1,
        _runtime: &AgentRuntimeBindingV1,
        _channel: ObjectDigest,
        _deadline: Instant,
        _plan: &aos_sandbox_agent::openssh_receiving::OpenSshDescendantPlanDataV1,
    ) -> Result<(AgentExecutionPhaseV1, Vec<u8>), ProtectedGuestAgentErrorV1> {
        Err(ProtectedGuestAgentErrorV1::EffectUnavailable)
    }

    /// Installs or rechecks one gate and returns a fresh physical measurement.
    ///
    /// Implementations must bind the requested attach to a protected admitted
    /// execution and root-owned process ledger before launching sshd or writing
    /// the fixed claim. The default preserves fail-closed behavior.
    ///
    /// # Errors
    ///
    /// Returns an error when installation, ownership, or readback is unavailable.
    fn observe_openssh_gate(
        &mut self,
        _request: &OpenSshGateObserveRequestV1,
        _runtime: &AgentRuntimeBindingV1,
        _channel: ObjectDigest,
        _deadline: Instant,
    ) -> Result<OpenSshGateReadbackV1, ProtectedGuestAgentErrorV1> {
        Err(ProtectedGuestAgentErrorV1::EffectUnavailable)
    }

    /// Installs a selected gate against the original pre-receive interval.
    ///
    /// # Errors
    /// Refuses adapters without the same original process and native custody.
    fn observe_openssh_gate_original_v1(
        &mut self,
        _request: &OpenSshGateObserveRequestV1,
        _runtime: &AgentRuntimeBindingV1,
        _channel: ObjectDigest,
        _deadline: Instant,
        _original: &GuestOperationDeadlineOriginalV1,
    ) -> Result<OpenSshGateReadbackV1, ProtectedGuestAgentErrorV1> {
        Err(ProtectedGuestAgentErrorV1::EffectUnavailable)
    }

    /// Binds original ticket data and freshly measures its protected installation.
    ///
    /// # Errors
    /// Rejects unsupported effects, substitution, stale runtime, or failed readback.
    /// The result is physical evidence only, never authenticated SSH custody.
    fn bind_openssh_ticket_v2(
        &mut self,
        _request: &OpenSshGateObserveRequestV1,
        _ticket: &[u8],
        _runtime: &AgentRuntimeBindingV1,
        _channel: ObjectDigest,
        _deadline: Instant,
    ) -> Result<(OpenSshGateReadbackV1, [u8; 32]), ProtectedGuestAgentErrorV1> {
        Err(ProtectedGuestAgentErrorV1::EffectUnavailable)
    }

    /// Polls or consumes an immutable ticket under the Guest's shared owner cut.
    ///
    /// # Errors
    /// Rejects unsupported effects or missing exact live custody/current process.
    fn original_attach_v3(
        &mut self,
        _action: aos_sandbox_agent::openssh_consume::OriginalAttachActionV3,
        _binding: [u8; 32],
        _authority_expires_at: i64,
        _effect_deadline_boottime_nanoseconds: u64,
        _request: &OpenSshGateObserveRequestV1,
        _ticket: &[u8],
        _runtime: &AgentRuntimeBindingV1,
        _channel: ObjectDigest,
        _deadline: Instant,
    ) -> Result<
        (
            OpenSshGateReadbackV1,
            aos_sandbox_agent::openssh_consume::OriginalAttachObservationV3,
        ),
        ProtectedGuestAgentErrorV1,
    > {
        Err(ProtectedGuestAgentErrorV1::EffectUnavailable)
    }

    /// Observes or applies an original-monitor control under current owner cuts.
    ///
    /// # Errors
    /// Rejects unsupported effects, foreign custody, expiry, unsupported original
    /// topology, replay or ambiguous effects. Parsing supplies no permission.
    fn original_control_v5(
        &mut self,
        _action: aos_sandbox_agent::openssh_control_channel::OriginalControlActionV5,
        _binding: [u8; 32],
        _control: &[u8],
        _authority_expires_at: i64,
        _effect_deadline_boottime_nanoseconds: u64,
        _request: &OpenSshGateObserveRequestV1,
        _ticket: &[u8],
        _runtime: &AgentRuntimeBindingV1,
        _channel: ObjectDigest,
        _deadline: Instant,
    ) -> Result<
        (
            OpenSshGateReadbackV1,
            aos_sandbox_agent::openssh_control_channel::OriginalControlObservationV5,
        ),
        ProtectedGuestAgentErrorV1,
    > {
        Err(ProtectedGuestAgentErrorV1::EffectUnavailable)
    }
}

// Only the installed concrete process owner holds failed protocol originals
// until its original Guardian exits. Generic adapters retain their returning API.
enum ProtocolFailureDispositionV1 {
    Return,
    HoldWithOriginalProcess,
}

/// Runs one provisioned guest-agent session on the fixed inherited channel.
pub struct ProtectedGuestAgentV1<Effects> {
    effects: Effects,
    capture: Option<crate::capture::GuestCaptureAuthorizeOriginalV2>,
    ssh_authorize: Option<crate::ssh_authorize::GuestSshAuthorizeOriginalV1>,
    operation_deadline: Option<GuestOperationDeadlineOriginalV1>,
    capture_receive_failure: Option<RetainedSeqpacketReceiveErrorV1>,
    active_control: Option<active_control::ActiveControlOriginalV2>,
    session_socket: Option<SeqpacketSocket>,
    protocol_send_failure: Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>,
    initial_handshake: Option<handshake::InitialHandshakeOriginalV2>,
    protocol_failure_disposition: ProtocolFailureDispositionV1,
}

impl<Effects> ProtectedGuestAgentV1<Effects> {
    /// Creates an entry owner with its guest-local effect implementation.
    #[must_use]
    pub const fn new(effects: Effects) -> Self {
        Self {
            effects,
            capture: None,
            ssh_authorize: None,
            operation_deadline: None,
            capture_receive_failure: None,
            active_control: None, session_socket: None, protocol_send_failure: None,
            initial_handshake: None,
            protocol_failure_disposition: ProtocolFailureDispositionV1::Return,
        }
    }

    /// Borrows an actual retained Capture, protocol or native mode failure.
    #[must_use]
    pub fn capture_failure(&self) -> Option<&(dyn std::error::Error + 'static)>
    where Effects: GuestOperationEffectsV1 {
        self.active_control.as_ref().and_then(|original| original.native_failure())
            .or_else(|| self.initial_handshake.as_ref().and_then(|original| original.native_failure()))
            .or_else(|| self.capture_receive_failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.protocol_send_failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.initial_handshake.as_ref()?.body.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.capture.as_ref().and_then(|original| original.failure()))
            .or_else(|| self.ssh_authorize.as_ref().and_then(|original| original.failure()))
            .or_else(|| self.operation_deadline.as_ref().and_then(|original| original.failure()))
            .or_else(|| self.effects.selected_openssh_startup_failure_v1())
            .or_else(|| self.active_control.as_ref()?.protocol_failure.as_ref().map(|cause| cause as _))
    }
}

impl ProtectedGuestAgentV1<crate::GuestProcessEffectsV1> {
    /// Retains failed protocol originals beside the installed native process owner.
    ///
    /// This negative disposition creates no execution or cancellation permission.
    /// Existing child deadlines continue after transport closure; failed Capture
    /// owners remain occupied until the original Guardian terminates the Agent.
    #[doc(hidden)]
    #[must_use]
    pub const fn with_original_process_owner_v1(effects: crate::GuestProcessEffectsV1) -> Self {
        Self {
            effects,
            capture: None,
            ssh_authorize: None,
            operation_deadline: None,
            capture_receive_failure: None,
            active_control: None, session_socket: None, protocol_send_failure: None,
            initial_handshake: None,
            protocol_failure_disposition: ProtocolFailureDispositionV1::HoldWithOriginalProcess,
        }
    }
}

impl<Effects: GuestOperationEffectsV1> DormantGuestAgentServiceV1
    for ProtectedGuestAgentV1<Effects>
{
    type Error = ProtectedGuestAgentErrorV1;

    fn run(&mut self) -> Result<(), Self::Error> {
        if self.capture.is_some() || self.capture_receive_failure.is_some() || self.session_socket.is_some() {
            return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
        }
        let result = match self.run_session() {
            Err(cause) if self.capture.is_some() => {
                if let Some(capture) = self.capture.as_mut() {
                    capture.protocol_failure = Some(cause);
                }
                Err(ProtectedGuestAgentErrorV1::CaptureRefused)
            }
            Err(cause) if self.active_control.is_some() => {
                if let Some(original) = self.active_control.as_mut() {
                    original.protocol_failure = Some(cause);
                }
                Err(ProtectedGuestAgentErrorV1::CaptureRefused)
            }
            result => result,
        };
        // Transport closure is not a Continue cancellation. Keep the SAME
        // actual child/tree and failed Capture prefix in this process until
        // their original timeout/native disposition or original Guardian exit.
        // No new session, parsed PID, deadline, worker or authorization enters.
        while self.effects.has_original_execution_custody_v1()
            || (matches!(self.protocol_failure_disposition,
                ProtocolFailureDispositionV1::HoldWithOriginalProcess)
                && self.capture_failure().is_some())
        {
            self.effects.service_original_deadlines_v1();
            std::thread::sleep(RETRY_INTERVAL);
        }
        result
    }
}

impl<Effects: GuestOperationEffectsV1> ProtectedGuestAgentV1<Effects> {
    fn run_session(&mut self) -> Result<(), ProtectedGuestAgentErrorV1> {
        let channel = duplicate_inherited_descriptor(CHANNEL_DESCRIPTOR)?;
        let provisioning_fd = duplicate_inherited_descriptor(PROVISIONING_DESCRIPTOR)?;
        mark_inherited_descriptor_close_on_exec(CHANNEL_DESCRIPTOR)?;
        mark_inherited_descriptor_close_on_exec(PROVISIONING_DESCRIPTOR)?;
        let mut socket = SeqpacketSocket::from_owned(channel)?;
        let result = self.run_session_on_original_v2(&mut socket, provisioning_fd);
        // A failed selected protocol keeps the SAME endpoint even after its
        // last child retired. No FD duplication, reconnect or repair enters.
        if matches!(self.protocol_failure_disposition, ProtocolFailureDispositionV1::HoldWithOriginalProcess) {
            self.session_socket = Some(socket);
        }
        result
    }

    fn run_session_on_original_v2(&mut self, socket: &mut SeqpacketSocket,
        provisioning_fd: OwnedFd) -> Result<(), ProtectedGuestAgentErrorV1>
    {
        let provisioning = SealedMemfdMapping::run(
            provisioning_fd,
            GUEST_AGENT_PROVISIONING_BYTES_V1 as u64,
            GUEST_AGENT_PROVISIONING_BYTES_V1 as u64,
            |bytes, _identity| decode_provisioning(bytes),
        )??;
        verify_package_credential(provisioning.package_binding)?;
        if provisioning.features.as_slice().iter().any(|feature| {
            *feature != AgentFeatureV1::RuntimeArgumentObservation
                && !self.effects.supports(*feature)
        }) {
            return Err(ProtectedGuestAgentErrorV1::UnsupportedFeature);
        }

        let capture_transport = provisioning.features.contains(AgentFeatureV1::CapturePipeHandoffV2);
        let selected_original_owner = matches!(self.protocol_failure_disposition,
            ProtocolFailureDispositionV1::HoldWithOriginalProcess);
        let selected_control_transport = capture_transport && selected_original_owner;
        let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let binding = if selected_original_owner {
            self.initial_handshake = Some(handshake::InitialHandshakeOriginalV2::default());
            let result = authenticate_initial_handshake_v2(socket, &provisioning, handshake_deadline,
                self.initial_handshake.as_mut(), Some(&mut self.protocol_send_failure),
                &mut || self.effects.service_original_deadlines_v1());
            let original = self.initial_handshake.as_mut()
                .ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?;
            original.body = Some(result);
            let binding = match original.body.as_ref() {
                Some(Ok(binding)) => *binding,
                _ => return Err(ProtectedGuestAgentErrorV1::CaptureRefused),
            };
            // All receive, binding and retained native send posts completed.
            // Session binding DATA is the only surviving handshake result.
            self.initial_handshake.take();
            binding
        } else {
            authenticate_initial_handshake_v2(socket, &provisioning, handshake_deadline,
                None, None, &mut || {})?
        };

        let mut next_sequence = AgentOperationSequenceV1::new(1)?;
        let mut last: Option<(AgentOperationRequestV1, Vec<u8>, AgentExecutionPhaseV1)> = None;
        for _ in 0..MAX_OPERATIONS {
            // This sample precedes every selected receive. SSH startup borrows
            // this same interval; it never starts a fresh duration after IO.
            self.operation_deadline = selected_control_transport
                .then(GuestOperationDeadlineOriginalV1::start);
            if let Some(original) = self.operation_deadline.as_ref() {
                original.cutoff_data_v1()?;
            }
            let deadline = Instant::now() + OPERATION_TIMEOUT;
            let active_restriction = self.active_control.as_ref().filter(|original| !original.is_restored());
            let (mut received, subject, mut descriptors) = if capture_transport && active_restriction.is_some() {
                let original = active_restriction.ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?;
                let record = receive_active_control_v2(socket, deadline, &original.restriction,
                    &mut self.capture_receive_failure, &mut || self.effects.service_original_deadlines_v1())?;
                let (bytes, subject) = record.into_parts();
                (bytes, Some(subject), Vec::new())
            } else if capture_transport {
                let record = receive_authorize_descriptors_v2(
                    socket, deadline, &mut self.capture_receive_failure,
                    &mut || self.effects.service_original_deadlines_v1(),
                )?;
                let (bytes, subject, rights) = record.into_parts();
                (bytes, Some(subject), rights)
            } else {
                let (bytes, rights) = receive_optional_descriptor_with_progress(
                    socket, deadline, &mut || self.effects.service_original_deadlines_v1())?;
                (bytes, None, rights)
            };
            let capture_candidate = capture_transport && (descriptors.len() == 3
                || received.get(..9) == Some(b"AOSAGE01\x0e".as_slice()));
            let ssh_candidate = selected_control_transport
                && received.get(..9) == Some(b"AOSAGE01\x0f".as_slice());
            let mut capture_frame = false;
            let mut ssh_frame = false;
            if !capture_candidate && received.starts_with(ARGUMENT_OBSERVE_REQUEST_MAGIC_V1) {
                if !descriptors.is_empty() {
                    return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
                }
                if !provisioning
                    .features
                    .contains(AgentFeatureV1::RuntimeArgumentObservation)
                {
                    return Err(ProtectedGuestAgentErrorV1::UnsupportedFeature);
                }
                let observe = GuestRuntimeArgumentObserveRequestV1::decode(&received)?;
                if observe.session() != binding
                    || observe.runtime() != &provisioning.runtime
                    || observe.channel() != provisioning.channel
                {
                    return Err(ProtectedGuestAgentErrorV1::OperationMismatch);
                }
                check_deadline(deadline)?;
                let packet =
                    sign_current_guest_argument_readback_v1(&observe, &provisioning.signing_key)?;
                check_deadline(deadline)?;
                send_selected_v2(socket, selected_control_transport.then_some(&mut self.protocol_send_failure), &packet, deadline)?;
                continue;
            }
            let frame = if capture_candidate {
                if self.capture.is_some() {
                    return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
                }
                self.capture = Some(crate::capture::GuestCaptureAuthorizeOriginalV2::new(
                    std::mem::take(&mut received), std::mem::take(&mut descriptors),
                    subject.ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?,
                ));
                let capture = self.capture.as_mut().ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?;
                capture.decode_frame_once()?
            } else if ssh_candidate {
                if self.ssh_authorize.is_some() {
                    return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
                }
                self.ssh_authorize = Some(crate::ssh_authorize::GuestSshAuthorizeOriginalV1::new(
                    std::mem::take(&mut received), std::mem::take(&mut descriptors),
                    subject.ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?,
                ));
                self.ssh_authorize.as_mut().ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?
                    .decode_frame_once()?
            } else {
                decode_frame_v1(&received)?
            };
            if capture_candidate && !matches!(frame, AgentFrameV1::SealedCaptureAuthorizeRequestV2(_)) {
                return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
            }
            let request = match frame {
                AgentFrameV1::OperationRequest(request) => {
                    // The protected Authorize path must never expand a large
                    // specification into a seqpacket datagram.
                    if !descriptors.is_empty()
                        || matches!(
                            request.operation(),
                            AgentExecutionOperationV1::Authorize { .. }
                        )
                    {
                        return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
                    }
                    request
                }
                AgentFrameV1::SealedAuthorizeRequest(reference) => {
                    if descriptors.len() != 1 {
                        return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
                    }
                    let descriptor = descriptors
                        .pop()
                        .ok_or(ProtectedGuestAgentErrorV1::UnexpectedFrame)?;
                    SealedMemfdMapping::run(
                        descriptor,
                        reference.content_bytes(),
                        MAX_AGENT_SEALED_SPEC_BYTES_V1 as u64,
                        |bytes, _| reference.reconstruct(bytes),
                    )??
                }
                AgentFrameV1::SealedCaptureAuthorizeRequestV2(reference) => {
                    if !capture_transport { return Err(ProtectedGuestAgentErrorV1::UnsupportedFeature); }
                    capture_frame = true;
                    self.capture.as_mut().ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?
                        .reconstruct_once(reference)?
                }
                AgentFrameV1::SealedSshAuthorizeRequestV1(reference) => {
                    if !ssh_candidate || capture_candidate {
                        return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
                    }
                    ssh_frame = true;
                    self.ssh_authorize.as_mut().ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?
                        .reconstruct_once(reference, &provisioning.runtime)?
                }
                AgentFrameV1::OriginalControlRequestV5(bytes) => {
                    if !descriptors.is_empty() {
                        return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
                    }
                    let (action, custody, control, expiry, boottime_deadline, observe, ticket) =
                        aos_sandbox_agent::openssh_control_channel::decode_original_control_request_v5(&bytes)
                            .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    if observe.session_binding != *binding.digest().as_bytes()
                        || observe.binding.incarnation_id
                            != *provisioning.runtime.incarnation().as_bytes()
                        || observe.binding.assignment_epoch
                            != provisioning.runtime.assignment_epoch().get()
                    {
                        return Err(ProtectedGuestAgentErrorV1::SessionMismatch);
                    }
                    let (readback, observation) = self.effects.original_control_v5(
                        action,
                        custody,
                        control,
                        expiry,
                        boottime_deadline,
                        &observe,
                        ticket,
                        &provisioning.runtime,
                        provisioning.channel,
                        deadline,
                    )?;
                    check_deadline(deadline)?;
                    if readback.challenge != observe.challenge
                        || readback.route_digest != observe.route_digest
                        || readback.channel_binding != *provisioning.channel.as_bytes()
                        || readback.binding != observe.binding
                        || (action
                            == aos_sandbox_agent::openssh_control_channel::OriginalControlActionV5::Apply
                            && (observation.phase
                                != aos_sandbox_agent::openssh_control_channel::OriginalControlPhaseV5::Applied
                                || observation.binding != custody
                                || observation.request != control))
                    {
                        return Err(ProtectedGuestAgentErrorV1::InvalidGateRequest);
                    }
                    let physical = aos_sandbox_agent::openssh_ticket::sign_ticket_gate_readback_v2(
                        &readback,
                        aos_sandbox_agent::openssh_ticket::ticket_digest_v2(ticket),
                        &provisioning.signing_key,
                    )
                    .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    let response =
                        aos_sandbox_agent::openssh_control_channel::sign_original_control_response_v5(
                            &observation,
                            &physical,
                            &provisioning.signing_key,
                        )
                        .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    send_selected_v2(socket, selected_control_transport.then_some(&mut self.protocol_send_failure),
                        &encode_frame_v1(&AgentFrameV1::OriginalControlResponseV5(response)),
                        deadline,
                    )?;
                    continue;
                }
                AgentFrameV1::OriginalAttachRequestV3(bytes) => {
                    if !descriptors.is_empty() {
                        return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
                    }
                    let (
                        action,
                        custody,
                        authority_expires_at,
                        effect_deadline_boottime_nanoseconds,
                        observe,
                        ticket,
                    ) = aos_sandbox_agent::openssh_consume::decode_original_attach_request_v3(&bytes)
                        .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    if observe.session_binding != *binding.digest().as_bytes()
                        || observe.binding.incarnation_id
                            != *provisioning.runtime.incarnation().as_bytes()
                        || observe.binding.assignment_epoch
                            != provisioning.runtime.assignment_epoch().get()
                    {
                        return Err(ProtectedGuestAgentErrorV1::SessionMismatch);
                    }
                    let (readback, observation) = self.effects.original_attach_v3(
                        action,
                        custody,
                        authority_expires_at,
                        effect_deadline_boottime_nanoseconds,
                        &observe,
                        ticket,
                        &provisioning.runtime,
                        provisioning.channel,
                        deadline,
                    )?;
                    check_deadline(deadline)?;
                    if readback.challenge != observe.challenge
                        || readback.route_digest != observe.route_digest
                        || readback.channel_binding != *provisioning.channel.as_bytes()
                        || readback.binding != observe.binding
                        || (action == aos_sandbox_agent::openssh_consume::OriginalAttachActionV3::Consume
                            && (observation.binding != custody
                                || observation.phase
                                    != aos_sandbox_agent::openssh_consume::OriginalAttachPhaseV3::Transferred))
                    {
                        return Err(ProtectedGuestAgentErrorV1::InvalidGateRequest);
                    }
                    let physical = aos_sandbox_agent::openssh_ticket::sign_ticket_gate_readback_v2(
                        &readback,
                        aos_sandbox_agent::openssh_ticket::ticket_digest_v2(ticket),
                        &provisioning.signing_key,
                    )
                    .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    let response = aos_sandbox_agent::openssh_consume::encode_original_attach_response_v3(
                        &observation,
                        &physical,
                    )
                    .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    send_selected_v2(socket, selected_control_transport.then_some(&mut self.protocol_send_failure),
                        &encode_frame_v1(&AgentFrameV1::OriginalAttachResponseV3(response)),
                        deadline,
                    )?;
                    continue;
                }
                AgentFrameV1::OpenSshTicketBindRequestV2(bytes) => {
                    if !descriptors.is_empty() {
                        return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
                    }
                    let (observe, ticket) =
                        aos_sandbox_agent::openssh_ticket::decode_ticket_gate_request_v2(&bytes)
                            .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    if observe.session_binding != *binding.digest().as_bytes()
                        || observe.binding.incarnation_id
                            != *provisioning.runtime.incarnation().as_bytes()
                        || observe.binding.assignment_epoch
                            != provisioning.runtime.assignment_epoch().get()
                    {
                        return Err(ProtectedGuestAgentErrorV1::SessionMismatch);
                    }
                    let (readback, digest) = self.effects.bind_openssh_ticket_v2(
                        &observe,
                        ticket,
                        &provisioning.runtime,
                        provisioning.channel,
                        deadline,
                    )?;
                    check_deadline(deadline)?;
                    if readback.challenge != observe.challenge
                        || readback.route_digest != observe.route_digest
                        || readback.channel_binding != *provisioning.channel.as_bytes()
                        || readback.binding != observe.binding
                        || digest != aos_sandbox_agent::openssh_ticket::ticket_digest_v2(ticket)
                    {
                        return Err(ProtectedGuestAgentErrorV1::InvalidGateRequest);
                    }
                    let packet = aos_sandbox_agent::openssh_ticket::sign_ticket_gate_readback_v2(
                        &readback,
                        digest,
                        &provisioning.signing_key,
                    )
                    .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    send_selected_v2(socket, selected_control_transport.then_some(&mut self.protocol_send_failure),
                        &encode_frame_v1(&AgentFrameV1::OpenSshTicketReadbackV2(packet)),
                        deadline,
                    )?;
                    continue;
                }
                AgentFrameV1::OpenSshGateObserveRequest(bytes) => {
                    if !descriptors.is_empty() {
                        return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
                    }
                    let observe: OpenSshGateObserveRequestV1 = serde_json::from_slice(&bytes)
                        .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    observe
                        .validate()
                        .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    if serde_json::to_vec(&observe)
                        .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?
                        != bytes
                    {
                        return Err(ProtectedGuestAgentErrorV1::InvalidGateRequest);
                    }
                    if observe.session_binding != *binding.digest().as_bytes() {
                        return Err(ProtectedGuestAgentErrorV1::SessionMismatch);
                    }
                    if observe.binding.incarnation_id
                        != *provisioning.runtime.incarnation().as_bytes()
                        || observe.binding.assignment_epoch
                            != provisioning.runtime.assignment_epoch().get()
                    {
                        return Err(ProtectedGuestAgentErrorV1::OperationMismatch);
                    }
                    let readback = if let Some(original) = self.operation_deadline.as_ref() {
                        self.effects.observe_openssh_gate_original_v1(&observe,
                            &provisioning.runtime, provisioning.channel, deadline, original)?
                    } else {
                        self.effects.observe_openssh_gate(&observe, &provisioning.runtime,
                            provisioning.channel, deadline)?
                    };
                    check_deadline(deadline)?;
                    if readback.challenge != observe.challenge
                        || readback.route_digest != observe.route_digest
                        || readback.channel_binding != *provisioning.channel.as_bytes()
                        || readback.binding != observe.binding
                    {
                        return Err(ProtectedGuestAgentErrorV1::InvalidGateRequest);
                    }
                    let packet =
                        sign_openssh_gate_readback_v1(&readback, &provisioning.signing_key)
                            .map_err(|_| ProtectedGuestAgentErrorV1::InvalidGateRequest)?;
                    let frame = encode_frame_v1(&AgentFrameV1::OpenSshGateReadback(packet));
                    send_selected_v2(socket, selected_control_transport.then_some(&mut self.protocol_send_failure), &frame, deadline)?;
                    continue;
                }
                _ => return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame),
            };
            if request.session() != binding {
                return Err(ProtectedGuestAgentErrorV1::SessionMismatch);
            }
            if let Some((previous, packet, phase)) = &last {
                if request.sequence() == previous.sequence() {
                    // A new pipe table cannot replay an earlier Capture launch.
                    // The actual failed table stays on the selected original.
                    if capture_frame || ssh_frame { return Err(ProtectedGuestAgentErrorV1::CaptureRefused); }
                    if request != *previous {
                        return Err(ProtectedGuestAgentErrorV1::Equivocation);
                    }
                    send_with_original_gate_selected_v2(socket, selected_control_transport.then_some(&mut self.protocol_send_failure), packet, deadline, &mut || {
                        if *phase == AgentExecutionPhaseV1::Running {
                            self.effects.require_original_start_reply_current_v1(&request, &provisioning.runtime)?;
                        }
                        Ok(())
                    })?;
                    continue;
                }
            }
            if request.sequence() != next_sequence {
                return Err(ProtectedGuestAgentErrorV1::SequenceMismatch);
            }
            validate_operation_transport_v2(&request, &provisioning, capture_frame)?;
            check_deadline(deadline)?;

            if selected_control_transport {
                if let AgentExecutionOperationV1::Authorize { execution, .. } = request.operation() {
                    if self.active_control.as_ref().is_some_and(|original| !original.is_restored()) {
                        return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
                    }
                    self.active_control = Some(active_control::ActiveControlOriginalV2::new(*execution));
                    // Actual descriptor delivery, frame/session/sequence and
                    // transport validation precede this native transition.
                    // No Process/Child effect has entered yet, and no ACK lets
                    // the Host start another request before the empty-queue
                    // and independently owed cookie/mode checks complete.
                    self.active_control.as_mut().ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?
                        .enter(socket)?;
                }
            }

            let (phase, result) = if capture_frame {
                let capture = self.capture.as_mut().ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?;
                self.effects.apply_capture_v2(
                    &request, &provisioning.runtime, provisioning.channel, deadline, capture,
                )?
            } else if ssh_frame {
                let original = self.ssh_authorize.as_mut()
                    .ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?;
                let effect = self.effects.apply_ssh_authorize_v1(
                    &request, &provisioning.runtime, provisioning.channel, deadline, original.plan()?,
                );
                match effect {
                    Ok(outcome) => {
                        original.effect = Some(Ok(()));
                        outcome
                    }
                    Err(cause) => {
                        original.effect = Some(Err(cause));
                        return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
                    }
                }
            } else {
                self.effects.apply(
                    &request, &provisioning.runtime, provisioning.channel, deadline,
                )?
            };
            // A late durable effect is recovered from its owner; it cannot
            // become a fresh response on an expired exchange.
            check_deadline(deadline)?;
            validate_outcome_phase(request.operation(), phase)?;
            if selected_control_transport && matches!(phase, AgentExecutionPhaseV1::Exited
                | AgentExecutionPhaseV1::Canceled | AgentExecutionPhaseV1::Failed)
            {
                let execution = match request.operation() {
                    AgentExecutionOperationV1::Observe { execution }
                        | AgentExecutionOperationV1::Cancel { execution }
                        | AgentExecutionOperationV1::Authorize { execution, .. } => *execution,
                    _ => return Err(ProtectedGuestAgentErrorV1::CaptureRefused),
                };
                let retirement = self.effects.original_transport_retirement_v2()
                    .ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?;
                self.active_control.as_mut().ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?
                    .restore_after_retirement(socket, execution, &provisioning.runtime, retirement)?;
            }
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
            if capture_frame {
                let capture = self.capture.as_mut().ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?;
                if !capture.effect_completed() {
                    return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
                }
                capture.response = Some(send_with_original_gate_selected_v2(socket, selected_control_transport.then_some(&mut self.protocol_send_failure), &bytes, deadline, &mut || {
                    if phase == AgentExecutionPhaseV1::Running {
                        self.effects.require_original_start_reply_current_v1(&request, &provisioning.runtime)?;
                    }
                    Ok(())
                }));
                if !matches!(capture.response, Some(Ok(()))) {
                    return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
                }
                capture.complete_after_sent();
                // The request cache below owns pure canonical DATA. There is
                // no further required Capture native post after this disposal.
                drop(self.capture.take());
            } else if ssh_frame {
                let original = self.ssh_authorize.as_mut()
                    .ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?;
                original.response = Some(send_with_original_gate_selected_v2(socket,
                    selected_control_transport.then_some(&mut self.protocol_send_failure),
                    &bytes, deadline, &mut || {
                        if phase == AgentExecutionPhaseV1::Running {
                            self.effects.require_original_start_reply_current_v1(&request,
                                &provisioning.runtime)?;
                        }
                        Ok(())
                    }));
                if !matches!(original.response, Some(Ok(()))) {
                    return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
                }
                // The signed start reply and actual native current gate are
                // complete. Only pure plan DATA survives in the live Process.
                drop(self.ssh_authorize.take());
            } else {
                send_with_original_gate_selected_v2(socket, selected_control_transport.then_some(&mut self.protocol_send_failure), &bytes, deadline, &mut || {
                    if phase == AgentExecutionPhaseV1::Running {
                        self.effects.require_original_start_reply_current_v1(&request, &provisioning.runtime)?;
                    }
                    Ok(())
                })?;
            }

            next_sequence = next_sequence.checked_next()?;
            last = Some((request, bytes, phase));
        }
        Err(ProtectedGuestAgentErrorV1::OperationLimit)
    }
}

fn authenticate_initial_handshake_v2(
    socket: &mut SeqpacketSocket,
    provisioning: &Provisioning,
    deadline: Instant,
    original: Option<&mut handshake::InitialHandshakeOriginalV2>,
    retained_send: Option<&mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>>,
    progress: &mut impl FnMut(),
) -> Result<AgentSessionBindingV1, ProtectedGuestAgentErrorV1> {
    let ordinary;
    let payload = if let Some(original) = original {
        original.receive(socket, deadline, progress)?;
        original.payload()?
    } else {
        ordinary = receive(socket, deadline)?;
        ordinary.as_slice()
    };
    let request = match decode_frame_v1(payload)? {
        AgentFrameV1::HandshakeRequest(request) => request,
        _ => return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame),
    };
    if request.runtime() != &provisioning.runtime
        || request.host_channel_binding() != provisioning.channel
    {
        return Err(ProtectedGuestAgentErrorV1::ProvisioningMismatch);
    }

    let binding = AgentSessionBindingV1::derive(&request, &provisioning.instance)?;
    let response = sign_handshake(&request, binding, provisioning)?;
    send_selected_v2(
        socket,
        retained_send,
        &encode_frame_v1(&AgentFrameV1::HandshakeResponse(response)),
        deadline,
    )?;

    Ok(binding)
}

fn validate_operation(
    request: &AgentOperationRequestV1,
    provisioning: &Provisioning,
) -> Result<(), ProtectedGuestAgentErrorV1> {
    validate_operation_transport_v2(request, provisioning, false)
}

fn validate_operation_transport_v2(
    request: &AgentOperationRequestV1,
    provisioning: &Provisioning,
    capture: bool,
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
            crate::capture::require_capture_shape(
                specification.io().output_mode(), specification.io().terminal_mode(), capture,
            ).map_err(|_| ProtectedGuestAgentErrorV1::CaptureRefused)?;
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
    let runtime_prefix = validated_guest_agent_runtime_prefix_v1(bytes)?;
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
    if encode_agent_runtime_binding_v1(runtime) != runtime_prefix {
        return Err(ProtectedGuestAgentErrorV1::InvalidProvisioning);
    }
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
        || mask & !0x00ff != 0
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
        AgentFeatureV1::RuntimeArgumentObservation,
        AgentFeatureV1::CapturePipeHandoffV2,
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

/// Validates sealed launch framing and returns only its non-secret runtime prefix.
///
/// The caller must still authenticate FD custody and decode the full record;
/// this helper never copies or returns its signing seed.
///
/// # Errors
///
/// Returns an error for wrong length, magic, or checksum.
pub fn validated_guest_agent_runtime_prefix_v1(
    bytes: &[u8],
) -> Result<[u8; 104], ProtectedGuestAgentErrorV1> {
    if bytes.len() != GUEST_AGENT_PROVISIONING_BYTES_V1
        || bytes.get(..8) != Some(PROVISIONING_MAGIC.as_slice())
    {
        return Err(ProtectedGuestAgentErrorV1::InvalidProvisioning);
    }
    let expected: [u8; 32] = Sha256::digest(&bytes[..226]).into();
    if bytes[226..] != expected {
        return Err(ProtectedGuestAgentErrorV1::InvalidProvisioning);
    }
    bytes[8..112]
        .try_into()
        .map_err(|_| ProtectedGuestAgentErrorV1::InvalidProvisioning)
}

fn verify_package_credential(binding: ObjectDigest) -> Result<(), ProtectedGuestAgentErrorV1> {
    for directory in ["/etc", "/etc/aos", "/etc/aos/sandbox-agent"] {
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(ProtectedGuestAgentErrorV1::InvalidCredential);
        }
    }
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

fn receive_optional_descriptor_with_progress(
    socket: &mut SeqpacketSocket,
    deadline: Instant,
    progress: &mut impl FnMut(),
) -> Result<(Vec<u8>, Vec<OwnedFd>), ProtectedGuestAgentErrorV1> {
    loop {
        progress();
        check_deadline(deadline)?;
        match socket.receive_with_optional_descriptor(MAX_AGENT_FRAME_BYTES) {
            Ok(record) => {
                let (payload, _, descriptors) = record.into_parts();
                return Ok((payload, descriptors));
            }
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


fn receive_authorize_descriptors_v2(
    socket: &mut SeqpacketSocket,
    deadline: Instant,
    failure: &mut Option<RetainedSeqpacketReceiveErrorV1>,
    progress: &mut impl FnMut(),
) -> Result<aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord, ProtectedGuestAgentErrorV1> {
    loop {
        progress();
        check_deadline(deadline)?;
        match socket.receive_agent_authorize_retaining_v2(MAX_AGENT_FRAME_BYTES) {
            Ok(record) => return Ok(record),
            Err(cause) if (cause.is_nonconsuming_would_block()
                || cause.is_nonconsuming_interrupted()) && Instant::now() < deadline => {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(cause) => {
                *failure = Some(cause);
                return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
            }
        }
    }
}

fn receive_active_control_v2(
    socket: &mut SeqpacketSocket, deadline: Instant,
    restriction: &aos_sandbox_linux::seqpacket::SeqpacketRightsRestrictionOriginalV6,
    failure: &mut Option<RetainedSeqpacketReceiveErrorV1>, progress: &mut impl FnMut(),
) -> Result<aos_sandbox_linux::seqpacket::ReceivedRecord, ProtectedGuestAgentErrorV1> {
    loop {
        progress();
        check_deadline(deadline)?;
        match socket.receive_agent_active_control_retaining_v2(MAX_AGENT_FRAME_BYTES, restriction) {
            Ok(record) => return Ok(record),
            Err(cause) if (cause.is_nonconsuming_would_block()
                || cause.is_nonconsuming_interrupted()) && Instant::now() < deadline => {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(cause) => {
                *failure = Some(cause);
                return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
            }
        }
    }
}

fn send(
    socket: &mut SeqpacketSocket,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), ProtectedGuestAgentErrorV1> {
    send_with_original_gate_v1(socket, bytes, deadline, &mut || Ok(()))
}

fn send_with_original_gate_v1(
    socket: &mut SeqpacketSocket, bytes: &[u8], deadline: Instant,
    current: &mut impl FnMut() -> Result<(), ProtectedGuestAgentErrorV1>,
) -> Result<(), ProtectedGuestAgentErrorV1> {
    send_with_original_gate_selected_v2(socket, None, bytes, deadline, current)
}

fn send_selected_v2(socket: &mut SeqpacketSocket,
    retained: Option<&mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>>,
    bytes: &[u8], deadline: Instant,
) -> Result<(), ProtectedGuestAgentErrorV1> {
    send_with_original_gate_selected_v2(socket, retained, bytes, deadline, &mut || Ok(()))
}

fn send_with_original_gate_selected_v2(
    socket: &mut SeqpacketSocket,
    mut retained: Option<&mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>>,
    bytes: &[u8], deadline: Instant,
    current: &mut impl FnMut() -> Result<(), ProtectedGuestAgentErrorV1>,
) -> Result<(), ProtectedGuestAgentErrorV1> {
    loop {
        check_deadline(deadline)?;
        current()?;
        if let Some(slot) = retained.as_deref_mut() {
            match socket.send_retaining(bytes) {
                Ok(()) => return Ok(()),
                Err(cause) => {
                    let nonconsuming = matches!(cause.cause(),
                        SeqpacketError::WouldBlock | SeqpacketError::Interrupted);
                    if nonconsuming && Instant::now() < deadline {
                        std::thread::sleep(RETRY_INTERVAL);
                        continue;
                    }
                    *slot = Some(cause);
                    return Err(if nonconsuming { ProtectedGuestAgentErrorV1::Deadline }
                        else { ProtectedGuestAgentErrorV1::CaptureRefused });
                }
            }
        }
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

#[cfg(test)]
mod retained_active_send_tests {
    use super::*;
    use std::os::fd::AsRawFd as _;

    #[test]
    fn selected_failed_reply_keeps_the_same_native_socket() {
        let (mut sender, peer) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let path = format!("/proc/self/fd/{}", sender.as_fd().unwrap().as_raw_fd());
        drop(peer);
        let mut failure = None;

        assert!(send_selected_v2(&mut sender, Some(&mut failure), b"reply",
            Instant::now() + Duration::from_secs(1)).is_err());

        assert!(failure.as_ref().is_some_and(|cause| cause.retains_descriptor()));
        assert!(std::fs::read_link(&path).is_ok());
        drop(sender);
        assert!(std::fs::read_link(&path).is_ok());
        drop(failure);
        assert!(std::fs::read_link(path).is_err());
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
    /// An OpenSSH installation request is malformed or mismatched after readback.
    #[error("guest-agent OpenSSH gate request is invalid")]
    InvalidGateRequest,
    /// A signed Guest runtime-argument observation is unavailable or invalid.
    #[error("guest-agent runtime argument observation is invalid: {0}")]
    RuntimeArgumentObservation(#[from] GuestRuntimeArgumentObservationErrorV1),
    /// The actual Capture originals or strict receive failure remain resident.
    #[error("guest-agent Capture refused; actual original remains resident")]
    CaptureRefused,
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

    fn canary_challenge_data() -> ([u8; 200], [u8; 104], [u8; 32]) {
        let mut runtime = [0; 104];
        runtime[..16].fill(1);
        runtime[16..32].fill(2);
        runtime[32..40].copy_from_slice(&3_u64.to_be_bytes());
        runtime[72..80].copy_from_slice(&4_u64.to_be_bytes());

        let mut bytes = [0; 200];
        bytes[..8].copy_from_slice(b"AOSHCR01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[12..16].copy_from_slice(&200_u32.to_be_bytes());
        bytes[16..48].fill(5);
        bytes[48..80].fill(6);
        bytes[80..112].fill(7);
        bytes[112..144].copy_from_slice(&runtime[..32]);
        bytes[144..152].copy_from_slice(&runtime[32..40]);
        bytes[152..160].copy_from_slice(&runtime[72..80]);
        bytes[176..192].fill(8);
        bytes[192..200].copy_from_slice(&9_u64.to_be_bytes());

        let mut binding = Sha256::new();
        binding.update(b"aos.sandbox.host.canary-agent-channel.v1\0");
        binding.update(&bytes[48..80]);
        binding.update(&bytes[80..112]);
        binding.update(&bytes[176..192]);
        binding.update(&bytes[16..48]);
        (bytes, runtime, binding.finalize().into())
    }

    #[test]
    fn canary_challenge_returns_only_the_exact_supplied_deadline_data() {
        let (bytes, runtime, channel) = canary_challenge_data();

        assert_eq!(
            require_host_canary_challenge_v1(&bytes, &runtime, channel).unwrap(),
            9,
        );
        assert!(require_host_canary_challenge_v1(&bytes[..199], &runtime, channel).is_err());
    }

    #[test]
    fn canary_challenge_rejects_changed_framing_runtime_binding_and_zero_deadline() {
        let (bytes, runtime, channel) = canary_challenge_data();
        let offsets = [8, 10, 12, 16, 48, 80, 112, 128, 144, 152, 160, 168, 176];

        for offset in offsets {
            let mut changed = bytes;
            changed[offset] ^= 1;

            assert!(
                require_host_canary_challenge_v1(&changed, &runtime, channel).is_err(),
                "changed challenge byte {offset} must refuse",
            );
        }

        let mut changed_channel = channel;
        changed_channel[0] ^= 1;
        assert!(require_host_canary_challenge_v1(&bytes, &runtime, changed_channel).is_err());

        let mut zero_deadline = bytes;
        zero_deadline[192..200].fill(0);
        assert!(matches!(
            require_host_canary_challenge_v1(&zero_deadline, &runtime, channel),
            Err(ProtectedGuestAgentErrorV1::InvalidProvisioning),
        ));
    }

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
            AgentFeatureV1::RuntimeArgumentObservation,
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
        assert_eq!(bytes.len(), GUEST_AGENT_PROVISIONING_BYTES_V1);
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
        assert_eq!(launch.package_binding(), decoded.package_binding);

        let mut malformed = bytes;
        // Bit 8 is the first unknown flag after Capture uses bit 7.
        malformed[192] |= 0x01;
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
