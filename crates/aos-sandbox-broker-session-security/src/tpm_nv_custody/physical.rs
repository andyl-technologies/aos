//! Owns one persistent fixed-helper TPM carrier for closed Broker/Host purposes.
//!
//! The single lifecycle/exchange/send/receive engine retains genuine purpose
//! bindings. A closed Broker recipe preserves the consuming path's original
//! local/drop intervals while Required alone stages returned originals and
//! bounded first-cause/debt. Broker admission and cleanup keep their original
//! ordering. Host
//! admission parks the real whole journal owner and retains partial carrier,
//! child, original lock and frame debt across errors or caught operation unwind.
//! No injected transport, generic policy callback or naked I/O factory exists.

use std::num::NonZeroU32;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aos_sandbox::ProtectedJournalLockCustodyV1;
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcObservationsV1, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::{ReceivedRecord, SeqpacketError, SeqpacketSocket};
use rustix::event::PollFlags;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::recovery::{
    AuthenticatedNvObservationV1, BrokerPhysicalOpenV1, FloorErrorV1, FloorProfileV1,
    HelperObservationV1, HelperOperationV1, LOCK_ACK_BYTES, MeasuredHelperImageV1,
    NV_ATTRIBUTES_WRITTEN, RESPONSE_BYTES, RetainedFloorServicePolicyV1, decode_response_v2,
    encode_auth_v2, encode_hello_v2, encode_request_v2, require_broker_floor_helper_v1,
    require_broker_floor_owner_v1, require_lock_ack_v2,
};
use super::child::{OwnedHelperChildV1, wait_channel};
use super::host::physical::{
    HostAttemptPhaseV1, HostFrameV1, HostPhysicalReadErrorV1, HostReplyV1,
    PhysicalTpmFailureV1, RetainedHostPhysicalBindingV1,
};
use super::{FloorRecoveryV1, NvCustodyEndpointV1, framing};

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// The selected one-shot adapter shares the actual fixed supervisor and the
/// same strict sequenced-packet receiver. It performs no image hashing,
/// startup/RPC observation, disk persistence or application authorization in
/// a callback. Every actual completed record moves directly into the run.
pub(crate) struct NixOfflineExchangeV5<'resources> {
    socket: &'resources mut SeqpacketSocket,
    hello: &'resources [u8],
    request: &'resources [u8],
    locks: [std::os::fd::BorrowedFd<'resources>; 2],
    result_phase: bool,
    sent: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NixOfflineExchangeErrorV5 {
    #[error("offline helper original send failed")]
    Send(#[from] SeqpacketError),
    #[error("offline helper original receive failed")]
    Receive(#[from] aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1),
    #[error("offline helper transport phase is fenced")]
    Fenced,
}

impl<'resources> NixOfflineExchangeV5<'resources> {
    pub(crate) fn new(
        socket: &'resources mut SeqpacketSocket,
        hello: &'resources [u8], request: &'resources [u8],
        locks: [std::os::fd::BorrowedFd<'resources>; 2],
    ) -> Self {
        Self { socket, hello, request, locks, result_phase: false, sent: false }
    }

    pub(crate) fn socket(&mut self) -> &mut SeqpacketSocket {
        self.socket
    }

    pub(crate) fn select_result_phase(&mut self) -> Result<(), NixOfflineExchangeErrorV5> {
        if self.result_phase || !self.sent {
            return Err(NixOfflineExchangeErrorV5::Fenced);
        }
        self.result_phase = true;
        self.sent = false;
        Ok(())
    }

    fn send_or_wait(&mut self) -> Result<
        aos_sandbox_linux::process::ExchangeStep<ReceivedRecord>, NixOfflineExchangeErrorV5,
    > {
        use aos_sandbox_linux::process::{ExchangeStep, FixedProcessControlInterest};
        if !self.sent {
            let sent = if self.result_phase {
                self.socket.send(self.request)
            } else {
                self.socket.send_with_descriptors(self.hello, &self.locks)
            };
            match sent {
                Ok(()) => self.sent = true,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Writable));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
    }
}

impl aos_sandbox_linux::process::FixedProcessSessionExchange for NixOfflineExchangeV5<'_> {
    type Output = ReceivedRecord;
    type Error = NixOfflineExchangeErrorV5;

    fn start(
        &mut self, _child: &aos_sandbox_linux::process::FixedLiveChild<'_>,
        _control: std::os::fd::BorrowedFd<'_>,
    ) -> Result<aos_sandbox_linux::process::ExchangeStep<ReceivedRecord>, Self::Error> {
        self.send_or_wait()
    }

    fn advance(
        &mut self, _child: &aos_sandbox_linux::process::FixedLiveChild<'_>,
        _control: std::os::fd::BorrowedFd<'_>,
        readiness: aos_sandbox_linux::process::FixedProcessControlReadiness,
    ) -> Result<aos_sandbox_linux::process::ExchangeStep<ReceivedRecord>, Self::Error> {
        use aos_sandbox_linux::process::{ExchangeStep, FixedProcessControlInterest};
        if !self.sent {
            return self.send_or_wait();
        }
        if !readiness.is_readable() {
            return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable));
        }
        match self.socket.receive_retaining(2360) {
            Ok(record) => Ok(ExchangeStep::Complete(record)),
            Err(error) if error.is_nonconsuming_would_block() || error.is_nonconsuming_interrupted() => {
                Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
            }
            Err(error) => Err(error.into()),
        }
    }
}

enum RetainedPhysicalBindingV1<'owner, 'origin, 'startup> {
    // Preserve the original image -> service -> profile owning/drop order.
    Broker {
        image: Option<MeasuredHelperImageV1>,
        service: Option<RetainedFloorServicePolicyV1>,
        profile: FloorProfileV1,
        attempt: Option<BrokerPhysicalAttemptV1>,
    },
    Host(RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup>),
}

/// Retains one actual carrier and its complete purpose-local owning binding.
pub(crate) struct RetainedPhysicalTpmOwnerV1<'owner, 'origin, 'startup> {
    // Legacy supplies these fields only at the original construction gate.
    // Retained purposes park each returned original before the next gate;
    // neither disposition exposes a from-fields owner factory.
    child: Option<OwnedHelperChildV1>,
    channel: Option<SeqpacketSocket>,
    pidfd: Option<PidFd>,
    identity: Option<PidFdProcessIdentity>,
    binding: RetainedPhysicalBindingV1<'owner, 'origin, 'startup>,
    nonce: [u8; 32],
    sequence: u64,
    poisoned: bool,
}

enum SentLocksV1<'locks> {
    None,
    Broker(&'locks [ProtectedJournalLockCustodyV1; 2]),
    BrokerRetained,
    Host,
}

enum ReceivedFrameV1 {
    Broker(ReceivedRecord),
    BrokerRetained(HostReplyV1),
    Host(HostReplyV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerPhysicalPhaseV1 {
    Fresh,
    Checking,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerHelperPhaseV1 {
    AwaitingMeasurement,
    Measured,
}

/// Retains originals and bounded diagnostic debt, not a physical authority DTO.
struct BrokerPhysicalAttemptV1 {
    salt_name: [u8; 34],
    auth: Zeroizing<[u8; 32]>,
    locks: [ProtectedJournalLockCustodyV1; 2],
    launch_image: crate::production_startup::Pid1LaunchImageV1,
    observations: Option<PidFdProcObservationsV1>,
    helper_phase: BrokerHelperPhaseV1,
    phase: BrokerPhysicalPhaseV1,
    first_failure: Option<BrokerPhysicalFailureV1>,
    // Kill and wait are the existing ambiguous-command cleanup, not a retry
    // or drain proof. Their causes do not replace the original operation cause.
    kill_debt: Option<std::io::Error>,
    wait_debt: Option<std::io::Error>,
    hello: Option<Zeroizing<[u8; framing::HELLO_BYTES]>>,
    authentication: Option<Zeroizing<[u8; framing::AUTH_BYTES]>>,
    request: Option<[u8; framing::REQUEST_BYTES]>,
    hello_attempted: bool,
    authentication_attempted: bool,
    request_attempted: bool,
    acknowledgment: Option<ReceivedRecord>,
    observation: Option<ReceivedRecord>,
    cold_deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    // Socketpair's child half is resident before the new cutoff bookend.
    // Its later pure move into Command stdin still enters the existing raw
    // consuming spawn prefix; this does not claim custody inside that provider.
    child_channel: Option<SeqpacketSocket>,
}

enum BrokerPhysicalFailureV1 {
    Carrier(PhysicalTpmFailureV1),
    Lock(aos_sandbox::JournalError),
    Deadline(crate::DormantBrokerSessionHandshakeErrorV1),
}

impl BrokerPhysicalAttemptV1 {
    fn close(&mut self, cause: PhysicalTpmFailureV1) -> FloorErrorV1 {
        let projected = broker_projection(&cause);
        if self.first_failure.is_none() {
            self.first_failure = Some(BrokerPhysicalFailureV1::Carrier(cause));
        }
        self.phase = BrokerPhysicalPhaseV1::Failed;
        projected
    }

    fn failure(&self) -> FloorErrorV1 {
        match self.first_failure.as_ref() {
            Some(BrokerPhysicalFailureV1::Carrier(cause)) => broker_projection(cause),
            Some(BrokerPhysicalFailureV1::Lock(_) | BrokerPhysicalFailureV1::Deadline(_)) | None => {
                FloorErrorV1::Unavailable
            }
        }
    }

    fn reply(&self, kind: HostReplyV1) -> Result<&ReceivedRecord, PhysicalTpmFailureV1> {
        let record = match kind {
            HostReplyV1::Acknowledgment => &self.acknowledgment,
            HostReplyV1::Observation => &self.observation,
        };
        record.as_ref().ok_or_else(|| FloorErrorV1::Unavailable.into())
    }

    fn stage_reply(&mut self, kind: HostReplyV1, record: ReceivedRecord) {
        match kind {
            HostReplyV1::Acknowledgment => self.acknowledgment = Some(record),
            HostReplyV1::Observation => self.observation = Some(record),
        }
    }
}

fn broker_projection(cause: &PhysicalTpmFailureV1) -> FloorErrorV1 {
    match cause {
        PhysicalTpmFailureV1::Floor(error) => *error,
        _ => FloorErrorV1::Unavailable,
    }
}

// The two literal dispositions share this one admission recipe. Legacy lets
// retain their original lexical lifetimes; only Retained writes resident slots.
// These macros have no caller-selected policy, effect callback or owner factory.
macro_rules! broker_admission_step {
    (Legacy, deadline $owner:ident) => {};
    (Retained, deadline $owner:ident) => { $owner.check_broker_cold_deadline()?; };
    // Legacy projects at the original call site; Retained keeps typed causes.
    (Legacy, provisioning) => { return Err(FloorErrorV1::Provisioning) };
    (Retained, provisioning) => { return Err(FloorErrorV1::Provisioning.into()) };
    (Legacy, error $kind:ident, $value:expr) => {
        $value.map_err(|_| FloorErrorV1::Unavailable)?
    };
    (Retained, error $kind:ident, $value:expr) => {
        $value.map_err(PhysicalTpmFailureV1::$kind)?
    };
    (Legacy, result $value:expr) => {
        $value.map_err(PhysicalTpmFailureV1::broker_error)?
    };
    (Retained, result $value:expr) => { $value? };

    // Acquisition keeps Legacy locals or parks each actual Retained return.
    (Legacy, image $owner:ident, $image:ident) => {
        let mut $image = MeasuredHelperImageV1::open()?;
    };
    (Retained, image $owner:ident, $image:ident) => {
        let $image = MeasuredHelperImageV1::open()?;
        if let RetainedPhysicalBindingV1::Broker { image, .. } = &mut $owner.binding {
            *image = Some($image);
        }
    };
    (Legacy, service $owner:ident, $service:ident, $profile:ident, $launch:ident) => {
        let $service = RetainedFloorServicePolicyV1::open($profile.endpoint(), $launch)?;
    };
    (Retained, service $owner:ident, $service:ident, $profile:ident, $launch:ident) => {
        let $service = RetainedFloorServicePolicyV1::open(
            $profile.endpoint(),
            &$owner.broker()?.launch_image,
        )?;
        if let RetainedPhysicalBindingV1::Broker { service, .. } = &mut $owner.binding {
            *service = Some($service);
        }
    };
    (Legacy, nonce $owner:ident, $nonce:ident) => {};
    (Retained, nonce $owner:ident, $nonce:ident) => { $owner.nonce = $nonce; };

    (Legacy, identities $owner:ident, $locks:ident, $identities:ident) => {
        let $identities = [
            $locks[0].identity().map_err(|_| FloorErrorV1::Unavailable)?,
            $locks[1].identity().map_err(|_| FloorErrorV1::Unavailable)?,
        ];
    };
    (Retained, identities $owner:ident, $locks:ident, $identities:ident) => {
        let main = $owner.broker()?.locks[0].identity();
        let main = $owner.retain_lock_result(main)?;
        let sidecar = $owner.broker()?.locks[1].identity();
        let sidecar = $owner.retain_lock_result(sidecar)?;
        let $identities = [main, sidecar];
    };
    (Legacy, hello $owner:ident, $hello:ident) => {};
    (Retained, hello $owner:ident, $hello:ident) => {
        $owner.broker_mut()?.hello = Some($hello.clone());
    };

    (Legacy, channel $owner:ident, $channel:ident, $child_channel:ident) => {};
    (Retained, channel $owner:ident, $channel:ident, $child_channel:ident) => {
        $owner.channel = Some($channel);
        match &mut $owner.binding {
            RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } => {
                attempt.child_channel = Some($child_channel);
            }
            _ => std::process::abort(),
        }
    };
    (Legacy, stdin $owner:ident, $child_channel:ident) => { Stdio::from($child_channel) };
    (Retained, stdin $owner:ident, $child_channel:ident) => {
        Stdio::from(match &mut $owner.binding {
            RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } => {
                match attempt.child_channel.take() {
                    Some(channel) => channel,
                    None => std::process::abort(),
                }
            }
            _ => std::process::abort(),
        })
    };
    (Legacy, image_ref $owner:ident, $image:ident) => { $image };
    (Retained, image_ref $owner:ident, $image:ident) => { $owner.broker_image()? };
    (Legacy, image_mut $owner:ident, $image:ident) => { $image };
    (Retained, image_mut $owner:ident, $image:ident) => { $owner.broker_image_mut()? };
    (Legacy, child $owner:ident, $child:ident) => {};
    (Retained, child $owner:ident, $child:ident) => { $owner.child = Some($child); };
    (Legacy, child_ref $owner:ident, $child:ident) => { $child };
    (Retained, child_ref $owner:ident, $child:ident) => { $owner.child()? };
    (Legacy, pidfd $owner:ident, $pidfd:ident) => {};
    (Retained, pidfd $owner:ident, $pidfd:ident) => {
        $owner.pidfd = Some($pidfd);
        let observations = $owner.pidfd()?.prepare_proc_observations_v1();
        $owner.broker_mut()?.observations = Some(observations);
    };

    (Legacy, identity $owner:ident, $pidfd:ident, $process:ident) => {
        let $process = $pidfd.process_identity().map_err(|_| FloorErrorV1::Unavailable)?;
    };
    (Retained, identity $owner:ident, $pidfd:ident, $process:ident) => {
        $owner.identity = Some($owner.capture_broker_identity()?);
    };
    (Legacy, helper $owner:ident, $profile:ident, $pid:ident) => {
        require_broker_floor_helper_v1($profile.endpoint(), $pid.get())?;
    };
    (Retained, helper $owner:ident, $profile:ident, $pid:ident) => {
        BrokerPhysicalOpenV1::require_helper_preamble($profile, $pid.get())?;
        $owner.capture_broker_context($profile)?;
    };

    // Legacy constructs only after the original process/image/context gates.
    (Legacy, construct $owner:ident, $profile:ident, $image:ident, $service:ident,
        $nonce:ident, $channel:ident, $child:ident, $pidfd:ident, $process:ident) => {
        let mut $owner = Self {
            child: Some($child),
            channel: Some($channel),
            pidfd: Some($pidfd),
            identity: Some($process),
            binding: RetainedPhysicalBindingV1::Broker {
                image: Some($image),
                service: Some($service),
                profile: $profile,
                attempt: None,
            },
            nonce: $nonce,
            sequence: 1,
            poisoned: false,
        };
    };
    (Retained, construct $owner:ident, $profile:ident, $image:ident, $service:ident,
        $nonce:ident, $channel:ident, $child:ident, $pidfd:ident, $process:ident) => {};
    (Legacy, measured $owner:ident) => {};
    (Retained, measured $owner:ident) => {
        $owner.broker_mut()?.helper_phase = BrokerHelperPhaseV1::Measured;
    };

    (Legacy, locks $owner:ident, $locks:ident) => { SentLocksV1::Broker(&$locks) };
    (Retained, locks $owner:ident, $locks:ident) => { SentLocksV1::BrokerRetained };
    (Legacy, auth $owner:ident, $auth:ident) => { $auth };
    (Retained, auth $owner:ident, $auth:ident) => { &$owner.broker()?.auth };
    (Legacy, authentication $owner:ident, $authentication:ident) => {};
    (Retained, authentication $owner:ident, $authentication:ident) => {
        $owner.broker_mut()?.authentication = Some($authentication.clone());
    };
    (Legacy, read $owner:ident, $profile:ident) => {
        $owner.read($profile.endpoint().nv_index())?;
    };
    (Retained, read $owner:ident, $profile:ident) => {
        $owner.read_broker_inner($profile, $profile.endpoint().nv_index())?;
    };
    (Legacy, finish $owner:ident) => { Ok($owner) };
    (Retained, finish $owner:ident) => { Ok(()) };
}

macro_rules! broker_admission_recipe {
    ($mode:ident, $owner:ident, $profile:ident, $salt:ident, $auth:ident,
        $locks:ident, $launch:ident) => {{
        broker_admission_step!($mode, deadline $owner);
        require_broker_floor_owner_v1($profile.endpoint())?;
        if Sha256::digest($salt).as_slice() != $profile.salt_key_name_digest() {
            broker_admission_step!($mode, provisioning);
        }
        broker_admission_step!($mode, deadline $owner);
        broker_admission_step!($mode, image $owner, image);
        broker_admission_step!($mode, deadline $owner);
        broker_admission_step!($mode, service $owner, service, $profile, $launch);

        let nonce = broker_admission_step!($mode, error Entropy,
            crate::entropy::nonzero_random::<32, _>(&mut crate::entropy::KernelEntropy));
        broker_admission_step!($mode, nonce $owner, nonce);
        broker_admission_step!($mode, deadline $owner);
        broker_admission_step!($mode, identities $owner, $locks, identities);
        broker_admission_step!($mode, deadline $owner);
        let hello = encode_hello_v2($profile.endpoint(), nonce, $salt, identities)?;
        broker_admission_step!($mode, hello $owner, hello);
        let (channel, child_channel) = broker_admission_step!($mode, error Send,
            SeqpacketSocket::pair_with_record_subjects());
        broker_admission_step!($mode, channel $owner, channel, child_channel);
        broker_admission_step!($mode, deadline $owner);
        let child = OwnedHelperChildV1(broker_admission_step!($mode, error Child,
            Command::new(broker_admission_step!($mode, image_ref $owner, image).path())
                .env_clear()
                .stdin(broker_admission_step!($mode, stdin $owner, child_channel))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()));
        broker_admission_step!($mode, child $owner, child);
        broker_admission_step!($mode, deadline $owner);
        let pid = NonZeroU32::new(
            broker_admission_step!($mode, child_ref $owner, child).0.id(),
        ).ok_or(FloorErrorV1::Unavailable)?;
        let pidfd = broker_admission_step!($mode, error Linux, PidFd::open(pid));
        broker_admission_step!($mode, pidfd $owner, pidfd);
        broker_admission_step!($mode, deadline $owner);
        broker_admission_step!($mode, identity $owner, pidfd, process);
        broker_admission_step!($mode, image_mut $owner, image).require_executed(pid.get())?;
        broker_admission_step!($mode, helper $owner, $profile, pid);
        broker_admission_step!($mode, image_mut $owner, image).revalidate()?;

        broker_admission_step!($mode, construct $owner, $profile, image, service,
            nonce, channel, child, pidfd, process);
        broker_admission_step!($mode, result $owner.require_custody());
        $owner.require_broker_child()?;
        broker_admission_step!($mode, deadline $owner);
        broker_admission_step!($mode, measured $owner);
        broker_admission_step!($mode, result $owner.send_frame(
            &hello[..], broker_admission_step!($mode, locks $owner, $locks), None));
        let acknowledgment = broker_admission_step!($mode, result $owner.receive_frame(
            LOCK_ACK_BYTES, HostReplyV1::Acknowledgment));
        require_lock_ack_v2(
            broker_admission_step!($mode, result $owner.received_payload(&acknowledgment)),
            nonce,
        )?;
        // The actual image and ACK still precede AUTH/device access.
        broker_admission_step!($mode, result $owner.require_custody());
        let authentication = encode_auth_v2(
            $profile.endpoint(), nonce, broker_admission_step!($mode, auth $owner, $auth),
        )?;
        broker_admission_step!($mode, authentication $owner, authentication);
        broker_admission_step!($mode, deadline $owner);
        broker_admission_step!($mode, result $owner.send_frame(
            &authentication[..], SentLocksV1::None, None));
        drop(authentication);
        broker_admission_step!($mode, read $owner, $profile);
        broker_admission_step!($mode, deadline $owner);
        broker_admission_step!($mode, finish $owner)
    }};
}

impl RetainedPhysicalTpmOwnerV1<'static, 'static, 'static> {
    /// Binds comparison DATA only on the actual fresh retained Broker attempt.
    ///
    /// # Errors
    /// Refuses replacement, a non-Broker/unfinished owner or an expired cutoff.
    pub(crate) fn bind_broker_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        let attempt = self.broker_mut().map_err(PhysicalTpmFailureV1::broker_error)?;
        if attempt.phase != BrokerPhysicalPhaseV1::Fresh || attempt.cold_deadline.is_some() {
            return Err(attempt.close(PhysicalTpmFailureV1::State));
        }
        attempt.cold_deadline = Some(deadline);
        self.check_broker_cold_deadline().map_err(PhysicalTpmFailureV1::broker_error)
    }

    /// Checks original child custody and the same cutoff before retirement.
    ///
    /// # Errors
    /// Fences a changed, unfinished, replaced or expired retained Broker phase.
    pub(crate) fn require_broker_cold_retirement(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        let operation = BrokerPhysicalOperationV1::begin(self, BrokerPhysicalPhaseV1::Ready)?;
        let result = (|| {
            if operation.owner.broker()?.cold_deadline != Some(deadline) {
                return Err(PhysicalTpmFailureV1::State);
            }
            operation.owner.require_custody()?;
            operation.owner.check_broker_cold_deadline()
        })();
        operation.finish(result)
    }

    /// Removes only temporary comparison DATA after all outer final bookends.
    pub(crate) fn clear_broker_cold_deadline(&mut self) {
        if let RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } = &mut self.binding {
            attempt.cold_deadline = None;
        }
    }

    /// Opens the same fixed Broker child from its restricted actual inputs.
    ///
    /// # Errors
    /// Preserves original provisioning, custody, framing and I/O failures.
    pub(crate) fn open(binding: BrokerPhysicalOpenV1<'_>) -> Result<Self, FloorErrorV1> {
        let (profile, salt_name, auth, locks, launch_image) = binding.into_parts();
        broker_admission_recipe!(Legacy, owner, profile, salt_name, auth, locks, launch_image)
    }

    /// Parks the actual restricted inputs before the first fallible admission.
    pub(crate) fn retain_broker(binding: BrokerPhysicalOpenV1<'_>) -> Self {
        let (profile, salt_name, auth, locks, launch_image) = binding.into_parts();
        Self {
            child: None,
            channel: None,
            pidfd: None,
            identity: None,
            binding: RetainedPhysicalBindingV1::Broker {
                image: None,
                service: None,
                profile,
                attempt: Some(BrokerPhysicalAttemptV1 {
                    salt_name,
                    auth: Zeroizing::new(*auth),
                    locks,
                    launch_image: launch_image.clone(),
                    observations: None,
                    helper_phase: BrokerHelperPhaseV1::AwaitingMeasurement,
                    phase: BrokerPhysicalPhaseV1::Fresh,
                    first_failure: None,
                    kill_debt: None,
                    wait_debt: None,
                    hello: None,
                    authentication: None,
                    request: None,
                    hello_attempted: false,
                    authentication_attempted: false,
                    request_attempted: false,
                    acknowledgment: None,
                    observation: None,
                    cold_deadline: None,
                    child_channel: None,
                }),
            },
            nonce: [0; 32],
            sequence: 1,
            poisoned: false,
        }
    }

    /// Admits only this resident original; failure or unwind closes it forever.
    ///
    /// # Errors
    /// Preserves the Broker facade's existing error cases while retaining the
    /// first available provider cause and every returned owner privately.
    pub(crate) fn admit_broker(&mut self) -> Result<(), FloorErrorV1> {
        let operation = BrokerPhysicalOperationV1::begin(self, BrokerPhysicalPhaseV1::Fresh)?;
        let result = operation.owner.admit_broker_inner();
        operation.finish(result)
    }

    fn admit_broker_inner(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        let profile = self.broker_profile()?;
        let salt_name = self.broker()?.salt_name;
        broker_admission_recipe!(Retained, self, profile, salt_name, auth, locks, launch_image)
    }
}

impl<'owner, 'origin, 'startup> RetainedPhysicalTpmOwnerV1<'owner, 'origin, 'startup> {
    fn check_broker_cold_deadline(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        if let RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } = &mut self.binding {
            if let Some(deadline) = attempt.cold_deadline {
                if let Err(cause) = deadline.check() {
                    if attempt.first_failure.is_none() {
                        attempt.first_failure = Some(BrokerPhysicalFailureV1::Deadline(cause));
                    }
                    attempt.phase = BrokerPhysicalPhaseV1::Failed;
                    return Err(FloorErrorV1::Unavailable.into());
                }
            }
        }
        Ok(())
    }

    fn broker_wait_deadline(&mut self, frame_limit: Instant) -> Result<Instant, PhysicalTpmFailureV1> {
        self.check_broker_cold_deadline()?;
        let original = match &self.binding {
            RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } => attempt.cold_deadline,
            _ => None,
        };
        if let Some(original) = original {
            let remaining = original.remaining();
            let remaining = match remaining {
                Ok(remaining) => remaining,
                Err(cause) => {
                    let attempt = self.broker_mut()?;
                    if attempt.first_failure.is_none() {
                        attempt.first_failure = Some(BrokerPhysicalFailureV1::Deadline(cause));
                    }
                    attempt.phase = BrokerPhysicalPhaseV1::Failed;
                    return Err(FloorErrorV1::Unavailable.into());
                }
            };
            // BOOTTIME remains the authority for expiry (including suspension).
            // Instant supplies only the existing poll helper's bounded wait.
            return Ok(frame_limit.min(Instant::now() + Duration::from_nanos(remaining)));
        }
        Ok(frame_limit)
    }

    pub(in crate::tpm_nv_custody) fn retain_host(
        binding: RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup>,
    ) -> Self {
        Self {
            child: None,
            channel: None,
            pidfd: None,
            identity: None,
            binding: RetainedPhysicalBindingV1::Host(binding),
            nonce: [0; 32],
            sequence: 1,
            poisoned: false,
        }
    }

    pub(in crate::tpm_nv_custody) fn admit_host(
        &mut self,
    ) -> Result<FloorRecoveryV1, HostPhysicalReadErrorV1> {
        let operation = HostPhysicalOperationV1::begin(self, HostAttemptPhaseV1::Fresh)?;
        let result = operation.owner.admit_host_inner();
        operation.finish(result)
    }

    pub(in crate::tpm_nv_custody) fn classify_host(
        &mut self,
    ) -> Result<FloorRecoveryV1, HostPhysicalReadErrorV1> {
        let operation = HostPhysicalOperationV1::begin(self, HostAttemptPhaseV1::Ready)?;
        let result = operation.owner.classify_host_inner();
        operation.finish(result)
    }

    fn admit_host_inner(&mut self) -> Result<FloorRecoveryV1, PhysicalTpmFailureV1> {
        self.host_mut()?.claim_invocation()?;
        self.host_mut()?.retain_locks()?;
        self.nonce = crate::entropy::nonzero_random::<32, _>(&mut crate::entropy::KernelEntropy)
            .map_err(PhysicalTpmFailureV1::Entropy)?;
        let (_, salt_name) = self.host()?.names();
        let identities = self.host()?.lock_identities()?;
        let hello = framing::encode_hello_v2(
            NvCustodyEndpointV1::RuntimeDeployment,
            self.nonce,
            salt_name,
            identities,
        )
        .map_err(PhysicalTpmFailureV1::Carrier)?;
        self.host_mut()?.stage_hello(hello.clone());

        let (channel, child_channel) = SeqpacketSocket::pair_with_record_subjects()
            .map_err(PhysicalTpmFailureV1::Send)?;
        self.channel = Some(channel);
        let child = Command::new(self.host()?.helper_path())
            .env_clear()
            .stdin(Stdio::from(child_channel))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(PhysicalTpmFailureV1::Child)?;
        // Stage each real owner BEFORE later pidfd/identity/image admission.
        self.child = Some(OwnedHelperChildV1(child));
        let pid = NonZeroU32::new(self.child()?.0.id()).ok_or(FloorErrorV1::Unavailable)?;
        self.pidfd = Some(PidFd::open(pid).map_err(PhysicalTpmFailureV1::Linux)?);
        self.identity = Some(
            self.pidfd()?.process_identity()
                .map_err(PhysicalTpmFailureV1::Linux)?,
        );
        self.measure_host_helper_before_hello()?;

        self.send_frame(&hello[..], SentLocksV1::Host, Some(HostFrameV1::Hello))?;
        let acknowledgment = self.receive_frame(LOCK_ACK_BYTES, HostReplyV1::Acknowledgment)?;
        framing::require_lock_ack_v2(self.received_payload(&acknowledgment)?, self.nonce)
            .map_err(PhysicalTpmFailureV1::Carrier)?;
        self.require_custody()?;

        let auth = self.host_mut()?.current_auth()?;
        let authentication = framing::encode_auth_v2(
            NvCustodyEndpointV1::RuntimeDeployment,
            self.nonce,
            &auth,
        )
        .map_err(PhysicalTpmFailureV1::Carrier)?;
        self.host_mut()?.stage_auth(authentication.clone());
        self.send_frame(&authentication[..], SentLocksV1::None, Some(HostFrameV1::Auth))?;
        drop(authentication);
        drop(auth);
        self.classify_host_inner()
    }

    fn classify_host_inner(&mut self) -> Result<FloorRecoveryV1, PhysicalTpmFailureV1> {
        self.host_mut()?.capture_disk_cut()?;
        let observation = self.exchange(HelperOperationV1::Read, [0; 32])?;
        let classification = self.host_mut()?.classify_observation(observation)?;
        self.require_custody()?;
        // Include the final helper/currentness check in the same disk cut's
        // bookend, then sample the retained child again after native readback.
        self.host_mut()?.require_disk_cut()?;
        if !self.pidfd()?.is_alive().map_err(PhysicalTpmFailureV1::Linux)? {
            return Err(FloorErrorV1::Unavailable.into());
        }
        Ok(classification)
    }

    // This is the only initial Host image crossing. The actual carrier,
    // child, pidfd and identity are already resident, and no HELLO was sent.
    fn measure_host_helper_before_hello(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        self.require_original_child_process()?;
        let pidfd = self.pidfd.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        let pid = self.child.as_ref().ok_or(FloorErrorV1::Unavailable)?.0.id();
        match &mut self.binding {
            RetainedPhysicalBindingV1::Host(host) => {
                host.measure_helper_before_hello(pidfd, pid)
            }
            RetainedPhysicalBindingV1::Broker { .. } => Err(PhysicalTpmFailureV1::State),
        }
    }

    fn require_custody(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        self.require_original_child_process()?;

        let pidfd = self.pidfd.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        let pid = self.child.as_ref().ok_or(FloorErrorV1::Unavailable)?.0.id();
        match &mut self.binding {
            RetainedPhysicalBindingV1::Broker {
                image,
                service,
                profile,
                attempt,
            } => {
                image.as_mut().ok_or(FloorErrorV1::Unavailable)?.revalidate()?;
                if let Some(attempt) = attempt {
                    BrokerPhysicalOpenV1::require_helper_preamble(*profile, pid)?;
                    let context = attempt.observations
                        .as_mut()
                        .ok_or(FloorErrorV1::Unavailable)?
                        .observe_context(pidfd)
                        .map_err(PhysicalTpmFailureV1::Linux)?;
                    BrokerPhysicalOpenV1::require_helper_context(*profile, context)?;
                } else {
                    require_broker_floor_helper_v1(profile.endpoint(), pid)?;
                }
                let service = service.as_mut().ok_or(FloorErrorV1::Unavailable)?;
                service.revalidate()?;
                service.require_child(pidfd)?;
            }
            RetainedPhysicalBindingV1::Host(host) => host.require_measured_helper(pidfd)?,
        }
        if !self.pidfd()?.is_alive().map_err(|error| self.linux_error(error))? {
            return Err(FloorErrorV1::Unavailable.into());
        }
        Ok(())
    }

    // Both closed purposes use these same original process checks. Extracting
    // this prefix preserves Broker's exact check/error order without copying it
    // into the one-time Host executed-image admission path.
    fn require_original_child_process(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        let info = self.pidfd()?.info().map_err(|error| self.linux_error(error))?;
        let credentials = info.credentials().ok_or(FloorErrorV1::Unavailable)?;
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        if self.poisoned
            || !self.pidfd()?.is_alive().map_err(|error| self.linux_error(error))?
            || self.observe_child_exit()?
            || info.parent_pid() != std::process::id()
            || info.pid() != self.child()?.0.id()
            || [
                credentials.real_user_id(),
                credentials.effective_user_id(),
                credentials.saved_user_id(),
                credentials.filesystem_user_id(),
            ] != [uid; 4]
            || [
                credentials.real_group_id(),
                credentials.effective_group_id(),
                credentials.saved_group_id(),
                credentials.filesystem_group_id(),
            ] != [gid; 4]
            || self.observe_original_identity()? != self.identity.ok_or(FloorErrorV1::Unavailable)?
        {
            return Err(FloorErrorV1::Unavailable.into());
        }

        Ok(())
    }

    fn exchange(
        &mut self,
        operation: HelperOperationV1,
        input: [u8; 32],
    ) -> Result<HelperObservationV1, PhysicalTpmFailureV1> {
        self.require_custody()?;
        let request = if self.is_host() {
            framing::encode_request_v2(operation, self.nonce, self.sequence, input)
                .map_err(PhysicalTpmFailureV1::Carrier)?
        } else {
            encode_request_v2(operation, self.nonce, self.sequence, input)?
        };
        let frame = if self.is_host() {
            if operation != HelperOperationV1::Read {
                return Err(FloorErrorV1::Provisioning.into());
            }
            self.host_mut()?.stage_request(request);
            Some(HostFrameV1::Request)
        } else if self.is_retained_broker() {
            self.broker_mut()?.request = Some(request);
            None
        } else {
            None
        };
        let result = (|| {
            self.send_frame(&request, SentLocksV1::None, frame)?;
            let response = self.receive_frame(RESPONSE_BYTES, HostReplyV1::Observation)?;
            let payload = self.received_payload(&response)?;
            let observation = if self.is_host() {
                framing::decode_response_v2(payload, operation, self.nonce, self.sequence)
                    .map_err(PhysicalTpmFailureV1::Carrier)?
            } else {
                decode_response_v2(payload, operation, self.nonce, self.sequence)?
            };
            self.require_custody()?;
            self.sequence = self.sequence
                .checked_add(1)
                .filter(|value| *value != u64::MAX)
                .ok_or(FloorErrorV1::Unavailable)?;
            Ok(observation)
        })();
        if result.is_err() {
            self.poisoned = true;
            match &mut self.binding {
                RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } => {
                    // Park the original owning error BEFORE ambiguous cleanup;
                    // cleanup failure/unwind cannot replace that first cause.
                    return match result {
                        Err(cause) => {
                            let projected = attempt.close(cause);
                            if let Some(child) = &mut self.child {
                                if let Err(error) = child.0.kill() {
                                    attempt.kill_debt = Some(error);
                                }
                                if let Err(error) = child.0.wait() {
                                    attempt.wait_debt = Some(error);
                                }
                            }
                            Err(projected.into())
                        }
                        Ok(observation) => Ok(observation),
                    };
                }
                RetainedPhysicalBindingV1::Broker { attempt: None, .. } => {
                    // Legacy disposes redacted causes and cleanup errors at
                    // the original sites; none enters resident debt storage.
                    if let Some(child) = &mut self.child {
                        let _ = child.0.kill();
                        let _ = child.0.wait();
                    }
                }
                RetainedPhysicalBindingV1::Host(host) => {
                    // No replacement read/helper may overtake this failure.
                    // Carrier/child/loans/frames stay owned; close BEFORE return.
                    host.close();
                }
            }
        }
        result
    }

    fn send_frame(
        &mut self,
        bytes: &[u8],
        locks: SentLocksV1<'_>,
        frame: Option<HostFrameV1>,
    ) -> Result<(), PhysicalTpmFailureV1> {
        if self.is_retained_broker() {
            let attempt = self.broker_mut()?;
            if attempt.helper_phase != BrokerHelperPhaseV1::Measured {
                return Err(PhysicalTpmFailureV1::State);
            }
            // A marker means an attempt may dispatch; it never proves delivery.
            match &locks {
                SentLocksV1::BrokerRetained => attempt.hello_attempted = true,
                SentLocksV1::None if attempt.authentication_attempted => {
                    attempt.request_attempted = true;
                }
                SentLocksV1::None => attempt.authentication_attempted = true,
                SentLocksV1::Broker(_) | SentLocksV1::Host => {
                    return Err(PhysicalTpmFailureV1::State);
                }
            }
        }
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        loop {
            let wait_deadline = self.broker_wait_deadline(deadline)?;
            wait_channel(
                self.channel()?.as_fd().map_err(|error| self.send_error(error))?,
                PollFlags::OUT,
                wait_deadline,
            )
            .map_err(|error| self.wait_error(error))?;
            self.check_broker_cold_deadline()?;
            if let Some(frame) = frame {
                self.require_custody()?;
                if Instant::now() >= deadline {
                    return Err(FloorErrorV1::Unavailable.into());
                }
                self.host_mut()?.note_attempt(frame);
            }
            let channel = self.channel()?;
            let sent = match &locks {
                SentLocksV1::Broker(locks) => channel
                    .send_with_descriptors(bytes, &[locks[0].as_fd(), locks[1].as_fd()]),
                SentLocksV1::BrokerRetained => {
                    let locks = &self.broker()?.locks;
                    channel.send_with_descriptors(bytes, &[locks[0].as_fd(), locks[1].as_fd()])
                }
                SentLocksV1::Host => channel
                    .send_with_descriptors(bytes, &self.host()?.lock_fds()?),
                SentLocksV1::None => channel.send(bytes),
            };
            match sent {
                Ok(()) => {
                    self.check_broker_cold_deadline()?;
                    return Ok(());
                }
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {}
                Err(error) => return Err(self.send_error(error)),
            }
        }
    }

    fn receive_frame(
        &mut self,
        maximum: usize,
        host_reply: HostReplyV1,
    ) -> Result<ReceivedFrameV1, PhysicalTpmFailureV1> {
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        loop {
            let wait_deadline = self.broker_wait_deadline(deadline)?;
            wait_channel(
                self.channel()?.as_fd().map_err(|error| self.send_error(error))?,
                PollFlags::IN,
                wait_deadline,
            )
            .map_err(|error| self.wait_error(error))?;
            self.check_broker_cold_deadline()?;
            let frame = if self.is_host() {
                self.require_custody()?;
                if Instant::now() >= deadline {
                    return Err(FloorErrorV1::Unavailable.into());
                }
                let received = match self.channel_mut()?.receive_retaining(maximum) {
                    Ok(received) => received,
                    Err(error) if error.is_nonconsuming_would_block()
                        || error.is_nonconsuming_interrupted() =>
                    {
                        continue;
                    }
                    Err(error) => return Err(PhysicalTpmFailureV1::Receive(error)),
                };
                // Actual returned record is staged BEFORE any admission check.
                self.host_mut()?.stage_reply(host_reply, received);
                ReceivedFrameV1::Host(host_reply)
            } else if self.is_retained_broker() {
                let received = match self.channel_mut()?.receive_retaining(maximum) {
                    Ok(received) => received,
                    Err(error)
                        if error.is_nonconsuming_would_block()
                            || error.is_nonconsuming_interrupted() =>
                    {
                        continue;
                    }
                    Err(error) => return Err(PhysicalTpmFailureV1::Receive(error)),
                };
                if let RetainedPhysicalBindingV1::Broker {
                    attempt: Some(attempt),
                    ..
                } = &mut self.binding {
                    attempt.stage_reply(host_reply, received);
                }
                ReceivedFrameV1::BrokerRetained(host_reply)
            } else {
                let received = match self.channel_mut()?.receive(maximum) {
                    Ok(received) => received,
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => continue,
                    Err(_) => return Err(FloorErrorV1::Unavailable.into()),
                };
                ReceivedFrameV1::Broker(received)
            };
            self.check_broker_cold_deadline()?;
            let credentials = self.received_record(&frame)?.subject().credentials();
            if credentials.pid().get() != self.child()?.0.id()
                || credentials.uid() != rustix::process::geteuid().as_raw()
                || credentials.gid() != rustix::process::getegid().as_raw()
            {
                return Err(FloorErrorV1::Unavailable.into());
            }
            if self.received_subject_identity_changed(&frame)?
                || !self.received_record(&frame)?
                    .subject()
                    .is_alive()
                    .map_err(|error| self.linux_error(error))?
            {
                return Err(FloorErrorV1::Unavailable.into());
            }
            return Ok(frame);
        }
    }

    fn received_record<'record>(
        &'record self,
        frame: &'record ReceivedFrameV1,
    ) -> Result<&'record ReceivedRecord, PhysicalTpmFailureV1> {
        match frame {
            ReceivedFrameV1::Broker(record) => Ok(record),
            ReceivedFrameV1::BrokerRetained(kind) => self.broker()?.reply(*kind),
            ReceivedFrameV1::Host(kind) => self.host()?.reply(*kind),
        }
    }

    fn received_payload<'record>(
        &'record self,
        frame: &'record ReceivedFrameV1,
    ) -> Result<&'record [u8], PhysicalTpmFailureV1> {
        Ok(self.received_record(frame)?.payload())
    }

    fn is_host(&self) -> bool {
        matches!(&self.binding, RetainedPhysicalBindingV1::Host(_))
    }

    fn is_retained_broker(&self) -> bool {
        matches!(
            &self.binding,
            RetainedPhysicalBindingV1::Broker { attempt: Some(_), .. },
        )
    }

    fn broker(&self) -> Result<&BrokerPhysicalAttemptV1, PhysicalTpmFailureV1> {
        match &self.binding {
            RetainedPhysicalBindingV1::Broker { attempt, .. } => {
                attempt.as_ref().ok_or(PhysicalTpmFailureV1::State)
            }
            RetainedPhysicalBindingV1::Host(_) => Err(PhysicalTpmFailureV1::State),
        }
    }

    fn broker_mut(&mut self) -> Result<&mut BrokerPhysicalAttemptV1, PhysicalTpmFailureV1> {
        match &mut self.binding {
            RetainedPhysicalBindingV1::Broker { attempt, .. } => {
                attempt.as_mut().ok_or(PhysicalTpmFailureV1::State)
            }
            RetainedPhysicalBindingV1::Host(_) => Err(PhysicalTpmFailureV1::State),
        }
    }

    fn broker_image(&self) -> Result<&MeasuredHelperImageV1, PhysicalTpmFailureV1> {
        match &self.binding {
            RetainedPhysicalBindingV1::Broker { image, .. } => {
                image.as_ref().ok_or_else(|| FloorErrorV1::Unavailable.into())
            }
            RetainedPhysicalBindingV1::Host(_) => Err(PhysicalTpmFailureV1::State),
        }
    }

    fn broker_image_mut(&mut self) -> Result<&mut MeasuredHelperImageV1, PhysicalTpmFailureV1> {
        match &mut self.binding {
            RetainedPhysicalBindingV1::Broker { image, .. } => {
                image.as_mut().ok_or_else(|| FloorErrorV1::Unavailable.into())
            }
            RetainedPhysicalBindingV1::Host(_) => Err(PhysicalTpmFailureV1::State),
        }
    }

    fn retain_lock_result(
        &mut self,
        result: Result<(u64, u64, u32), aos_sandbox::JournalError>,
    ) -> Result<(u64, u64, u32), PhysicalTpmFailureV1> {
        match result {
            Ok(identity) => Ok(identity),
            Err(cause) => {
                let attempt = self.broker_mut()?;
                if attempt.first_failure.is_none() {
                    attempt.first_failure = Some(BrokerPhysicalFailureV1::Lock(cause));
                }
                attempt.phase = BrokerPhysicalPhaseV1::Failed;
                Err(FloorErrorV1::Unavailable.into())
            }
        }
    }

    fn capture_broker_identity(&mut self) -> Result<PidFdProcessIdentity, PhysicalTpmFailureV1> {
        let pidfd = self.pidfd.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        match &mut self.binding {
            RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } => {
                attempt.observations
                    .as_mut()
                    .ok_or(FloorErrorV1::Unavailable)?
                    .capture_stat(pidfd)
                    .map_err(PhysicalTpmFailureV1::Linux)
            }
            _ => Err(PhysicalTpmFailureV1::State),
        }
    }

    fn capture_broker_context(
        &mut self,
        profile: FloorProfileV1,
    ) -> Result<(), PhysicalTpmFailureV1> {
        let pidfd = self.pidfd.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        match &mut self.binding {
            RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } => {
                let context = attempt.observations
                    .as_mut()
                    .ok_or(FloorErrorV1::Unavailable)?
                    .capture_context(pidfd)
                    .map_err(PhysicalTpmFailureV1::Linux)?;
                BrokerPhysicalOpenV1::require_helper_context(profile, context)?;
                Ok(())
            }
            _ => Err(PhysicalTpmFailureV1::State),
        }
    }

    fn observe_original_identity(&mut self) -> Result<PidFdProcessIdentity, PhysicalTpmFailureV1> {
        let pidfd = self.pidfd.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        match &mut self.binding {
            RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } => {
                attempt.observations
                    .as_mut()
                    .ok_or(FloorErrorV1::Unavailable)?
                    .observe_identity(pidfd)
                    .map_err(PhysicalTpmFailureV1::Linux)
            }
            _ => {
                pidfd.process_identity().map_err(|error| self.linux_error(error))
            }
        }
    }

    fn received_subject_identity_changed(
        &mut self,
        frame: &ReceivedFrameV1,
    ) -> Result<bool, PhysicalTpmFailureV1> {
        if !self.is_retained_broker() {
            // Host and Legacy retain the original pathname identity call.
            return Ok(
                self.received_record(frame)?
                    .subject()
                    .pidfd()
                    .process_identity()
                    .map_err(|error| self.linux_error(error))?
                    != self.identity.ok_or(FloorErrorV1::Unavailable)?,
            );
        }
        // Record subjects are real SCM pidfds. Compare their fresh kernel
        // identity with the original pin, whose stat descriptor is retained.
        // GET_INFO credentials/parent checks precede this same-process join.
        let observed = self.received_record(frame)?
            .subject()
            .pidfd()
            .info()
            .map_err(PhysicalTpmFailureV1::Linux)?;
        let original = self.pidfd()?.info().map_err(PhysicalTpmFailureV1::Linux)?;
        if observed != original {
            return Ok(true);
        }
        Ok(self.observe_original_identity()? != self.identity.ok_or(FloorErrorV1::Unavailable)?)
    }

    fn host(
        &self,
    ) -> Result<&RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup>, PhysicalTpmFailureV1> {
        match &self.binding {
            RetainedPhysicalBindingV1::Host(host) => Ok(host),
            RetainedPhysicalBindingV1::Broker { .. } => Err(PhysicalTpmFailureV1::State),
        }
    }

    fn host_mut(
        &mut self,
    ) -> Result<&mut RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup>, PhysicalTpmFailureV1> {
        match &mut self.binding {
            RetainedPhysicalBindingV1::Host(host) => Ok(host),
            RetainedPhysicalBindingV1::Broker { .. } => Err(PhysicalTpmFailureV1::State),
        }
    }

    fn broker_profile(&self) -> Result<FloorProfileV1, FloorErrorV1> {
        match &self.binding {
            RetainedPhysicalBindingV1::Broker { profile, .. } => Ok(*profile),
            RetainedPhysicalBindingV1::Host(_) => Err(FloorErrorV1::Provisioning),
        }
    }

    fn require_broker_child(&self) -> Result<(), FloorErrorV1> {
        match &self.binding {
            RetainedPhysicalBindingV1::Broker { service, .. } => {
                service.as_ref()
                    .ok_or(FloorErrorV1::Unavailable)?
                    .require_child(self.pidfd.as_ref().ok_or(FloorErrorV1::Unavailable)?)
            }
            RetainedPhysicalBindingV1::Host(_) => Err(FloorErrorV1::Provisioning),
        }
    }

    fn child(&self) -> Result<&OwnedHelperChildV1, PhysicalTpmFailureV1> {
        self.child.as_ref().ok_or_else(|| FloorErrorV1::Unavailable.into())
    }

    fn child_mut(&mut self) -> Result<&mut OwnedHelperChildV1, PhysicalTpmFailureV1> {
        self.child.as_mut().ok_or_else(|| FloorErrorV1::Unavailable.into())
    }

    fn observe_child_exit(&mut self) -> Result<bool, PhysicalTpmFailureV1> {
        let observed = self.child_mut()?.0.try_wait();
        observed.map(|status| status.is_some())
            .map_err(|error| self.child_error(error))
    }

    fn pidfd(&self) -> Result<&PidFd, PhysicalTpmFailureV1> {
        self.pidfd.as_ref().ok_or_else(|| FloorErrorV1::Unavailable.into())
    }

    fn channel(&self) -> Result<&SeqpacketSocket, PhysicalTpmFailureV1> {
        self.channel.as_ref().ok_or_else(|| FloorErrorV1::Unavailable.into())
    }

    fn channel_mut(&mut self) -> Result<&mut SeqpacketSocket, PhysicalTpmFailureV1> {
        self.channel.as_mut().ok_or_else(|| FloorErrorV1::Unavailable.into())
    }

    fn linux_error(&self, error: aos_sandbox_linux::Error) -> PhysicalTpmFailureV1 {
        if self.is_host() || self.is_retained_broker() {
            PhysicalTpmFailureV1::Linux(error)
        } else {
            FloorErrorV1::Unavailable.into()
        }
    }

    fn child_error(&self, error: std::io::Error) -> PhysicalTpmFailureV1 {
        if self.is_host() || self.is_retained_broker() {
            PhysicalTpmFailureV1::Child(error)
        } else {
            FloorErrorV1::Unavailable.into()
        }
    }

    fn send_error(&self, error: SeqpacketError) -> PhysicalTpmFailureV1 {
        if self.is_host() || self.is_retained_broker() {
            PhysicalTpmFailureV1::Send(error)
        } else {
            FloorErrorV1::Unavailable.into()
        }
    }

    fn wait_error(&self, error: super::NvCustodyErrorV1) -> PhysicalTpmFailureV1 {
        if self.is_host() || self.is_retained_broker() {
            PhysicalTpmFailureV1::Carrier(error)
        } else {
            FloorErrorV1::Unavailable.into()
        }
    }

    /// Reads only the retained Broker index through the original sealed facade.
    ///
    /// # Errors
    /// Preserves fixed-index, custody, framing and carrier failures.
    pub(crate) fn read(&mut self, index: u32) -> Result<AuthenticatedNvObservationV1, FloorErrorV1> {
        let profile = self.broker_profile()?;
        if index != profile.endpoint().nv_index() {
            return Err(FloorErrorV1::Provisioning);
        }
        if !self.is_retained_broker() {
            return self.read_broker_inner(profile, index)
                .map_err(PhysicalTpmFailureV1::broker_error);
        }
        let operation = BrokerPhysicalOperationV1::begin(self, BrokerPhysicalPhaseV1::Ready)?;
        let result = operation.owner.read_broker_inner(profile, index);
        operation.finish(result)
    }

    fn read_broker_inner(
        &mut self,
        profile: FloorProfileV1,
        index: u32,
    ) -> Result<AuthenticatedNvObservationV1, PhysicalTpmFailureV1> {
        let observed = self.exchange(HelperOperationV1::Read, [0; 32])?;
        Ok(AuthenticatedNvObservationV1 {
            salt_key_name_digest: profile.salt_key_name_digest(),
            index,
            name: observed.name,
            name_algorithm: observed.name_algorithm,
            attributes: observed.attributes,
            size: observed.size,
            empty_auth_policy: observed.policy_length == 0,
            value: observed.value,
        })
    }

    /// Extends only the retained Broker index; the Host arm is always refused.
    ///
    /// # Errors
    /// Preserves original fixed-index, custody, framing and observation failures.
    pub(crate) fn extend(&mut self, index: u32, input: &[u8; 32]) -> Result<(), FloorErrorV1> {
        let profile = self.broker_profile()?;
        if index != profile.endpoint().nv_index() {
            return Err(FloorErrorV1::Provisioning);
        }
        if !self.is_retained_broker() {
            return self.extend_broker_inner(profile, input)
                .map_err(PhysicalTpmFailureV1::broker_error);
        }
        let operation = BrokerPhysicalOperationV1::begin(self, BrokerPhysicalPhaseV1::Ready)?;
        let result = operation.owner.extend_broker_inner(profile, input);
        operation.finish(result)
    }

    fn extend_broker_inner(
        &mut self,
        profile: FloorProfileV1,
        input: &[u8; 32],
    ) -> Result<(), PhysicalTpmFailureV1> {
        let observed = self.exchange(HelperOperationV1::Extend, *input)?;
        if observed.name != profile.nv_name()
            || observed.name_algorithm != 0x000b
            || observed.attributes != NV_ATTRIBUTES_WRITTEN
            || observed.size != 32
            || observed.policy_length != 0
            || observed.value == [0; 32]
        {
            self.poisoned = true;
            return Err(FloorErrorV1::Provisioning.into());
        }
        Ok(())
    }
}

/// Pre-arms the resident attempt before all actual admission/exchange work.
struct BrokerPhysicalOperationV1<'operation, 'owner, 'origin, 'startup> {
    owner: &'operation mut RetainedPhysicalTpmOwnerV1<'owner, 'origin, 'startup>,
    complete: bool,
}

impl<'operation, 'owner, 'origin, 'startup>
    BrokerPhysicalOperationV1<'operation, 'owner, 'origin, 'startup>
{
    fn begin(
        owner: &'operation mut RetainedPhysicalTpmOwnerV1<'owner, 'origin, 'startup>,
        expected: BrokerPhysicalPhaseV1,
    ) -> Result<Self, FloorErrorV1> {
        let attempt = match &mut owner.binding {
            RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } => attempt,
            _ => return Err(FloorErrorV1::Provisioning),
        };
        if attempt.phase != expected || attempt.first_failure.is_some() {
            owner.poisoned = true;
            let cause = attempt.failure();
            attempt.close(PhysicalTpmFailureV1::Unfinished);
            return Err(cause);
        }
        attempt.phase = BrokerPhysicalPhaseV1::Checking;
        Ok(Self {
            owner,
            complete: false,
        })
    }

    fn finish<T>(mut self, result: Result<T, PhysicalTpmFailureV1>) -> Result<T, FloorErrorV1> {
        let result = match result {
            Ok(value) => self.owner.check_broker_cold_deadline().map(|()| value),
            Err(cause) => Err(cause),
        };
        let result = match &mut self.owner.binding {
            RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } => match result {
                Ok(value)
                    if attempt.phase == BrokerPhysicalPhaseV1::Checking
                        && attempt.first_failure.is_none() =>
                {
                    attempt.phase = BrokerPhysicalPhaseV1::Ready;
                    Ok(value)
                }
                Ok(_) => Err(attempt.close(PhysicalTpmFailureV1::Unfinished)),
                Err(cause) => Err(attempt.close(cause)),
            },
            _ => Err(FloorErrorV1::Provisioning),
        };
        if result.is_err() {
            self.owner.poisoned = true;
        }
        self.complete = true;
        result
    }
}

impl Drop for BrokerPhysicalOperationV1<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner.poisoned = true;
            if let RetainedPhysicalBindingV1::Broker {
                attempt: Some(attempt),
                ..
            } = &mut self.owner.binding {
                attempt.close(PhysicalTpmFailureV1::Unfinished);
            }
        }
    }
}

impl Drop for RetainedPhysicalTpmOwnerV1<'_, '_, '_> {
    fn drop(&mut self) {
        if let RetainedPhysicalBindingV1::Host(host) = &mut self.binding {
            self.poisoned = true;
            host.close();
        }
        // Broker adds no destructor effect. All original fields drop in order:
        // child -> channel -> pidfd -> identity -> image -> service -> profile.
    }
}

struct HostPhysicalOperationV1<'operation, 'owner, 'origin, 'startup> {
    owner: &'operation mut RetainedPhysicalTpmOwnerV1<'owner, 'origin, 'startup>,
    complete: bool,
}

impl<'operation, 'owner, 'origin, 'startup>
    HostPhysicalOperationV1<'operation, 'owner, 'origin, 'startup>
{
    fn begin(
        owner: &'operation mut RetainedPhysicalTpmOwnerV1<'owner, 'origin, 'startup>,
        expected: HostAttemptPhaseV1,
    ) -> Result<Self, HostPhysicalReadErrorV1> {
        match &mut owner.binding {
            RetainedPhysicalBindingV1::Host(host) => {
                if let Err(error) = host.begin(expected) {
                    owner.poisoned = true;
                    return Err(error);
                }
            }
            RetainedPhysicalBindingV1::Broker { .. } => {
                return Err(HostPhysicalReadErrorV1::wrong_owner());
            }
        }
        Ok(Self {
            owner,
            complete: false,
        })
    }

    fn finish(
        mut self,
        result: Result<FloorRecoveryV1, PhysicalTpmFailureV1>,
    ) -> Result<FloorRecoveryV1, HostPhysicalReadErrorV1> {
        let result = match &mut self.owner.binding {
            RetainedPhysicalBindingV1::Host(host) => match result {
                Ok(classification) => {
                    host.complete().map(|()| classification)
                }
                Err(cause) => {
                    self.owner.poisoned = true;
                    Err(host.fail(cause))
                }
            },
            RetainedPhysicalBindingV1::Broker { .. } => Err(HostPhysicalReadErrorV1::wrong_owner()),
        };
        if result.is_err() {
            self.owner.poisoned = true;
        }
        self.complete = true;
        result
    }
}

impl Drop for HostPhysicalOperationV1<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner.poisoned = true;
            if let RetainedPhysicalBindingV1::Host(host) = &mut self.owner.binding {
                host.fail(PhysicalTpmFailureV1::Unfinished);
            }
        }
    }
}

#[cfg(test)]
mod broker_projection_tests {
    use super::*;

    #[test]
    fn typed_provider_custody_keeps_the_original_redacted_cases() {
        for error in [
            FloorErrorV1::Encoding,
            FloorErrorV1::Provisioning,
            FloorErrorV1::Unavailable,
            FloorErrorV1::Diverged,
            FloorErrorV1::Successor,
        ] {
            assert_eq!(broker_projection(&PhysicalTpmFailureV1::Floor(error)), error);
        }

        let cause = PhysicalTpmFailureV1::Child(std::io::Error::from_raw_os_error(5));
        assert_eq!(broker_projection(&cause), FloorErrorV1::Unavailable);
        assert!(matches!(cause, PhysicalTpmFailureV1::Child(error) if error.raw_os_error() == Some(5)));
    }
}
