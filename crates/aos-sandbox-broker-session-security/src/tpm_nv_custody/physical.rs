//! Owns one persistent fixed-helper TPM carrier for closed Broker/Host purposes.
//!
//! The single lifecycle/exchange/send/receive engine retains genuine purpose
//! bindings. Broker admission and cleanup keep their original ordering. Host
//! admission parks the real whole journal owner and retains partial carrier,
//! child, original lock and frame debt across errors or caught operation unwind.
//! No injected transport, generic policy callback or naked I/O factory exists.

use std::num::NonZeroU32;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aos_sandbox::ProtectedJournalLockCustodyV1;
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::{ReceivedRecord, SeqpacketError, SeqpacketSocket};
use rustix::event::PollFlags;
use sha2::{Digest as _, Sha256};

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

enum RetainedPhysicalBindingV1<'owner, 'origin, 'startup> {
    // Preserve the original image -> service -> profile owning/drop order.
    Broker {
        image: MeasuredHelperImageV1,
        service: RetainedFloorServicePolicyV1,
        profile: FloorProfileV1,
    },
    Host(RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup>),
}

/// Retains one actual carrier and its complete purpose-local owning binding.
pub(crate) struct RetainedPhysicalTpmOwnerV1<'owner, 'origin, 'startup> {
    // Options stage real partial Host admission, not a from-fields factory.
    // Broker always supplies all four originals at its original construction.
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
    Host,
}

enum ReceivedFrameV1 {
    Broker(ReceivedRecord),
    Host(HostReplyV1),
}

impl RetainedPhysicalTpmOwnerV1<'static, 'static, 'static> {
    /// Opens the same fixed Broker child from its restricted actual inputs.
    ///
    /// # Errors
    /// Preserves original provisioning, custody, framing and I/O failures.
    pub(crate) fn open(binding: BrokerPhysicalOpenV1<'_>) -> Result<Self, FloorErrorV1> {
        let (profile, salt_name, auth, locks, launch_image) = binding.into_parts();
        require_broker_floor_owner_v1(profile.endpoint())?;
        if Sha256::digest(salt_name).as_slice() != profile.salt_key_name_digest() {
            return Err(FloorErrorV1::Provisioning);
        }
        let mut image = MeasuredHelperImageV1::open()?;
        let service = RetainedFloorServicePolicyV1::open(profile.endpoint(), launch_image)?;

        let nonce = crate::entropy::nonzero_random::<32, _>(&mut crate::entropy::KernelEntropy)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let identities = [
            locks[0].identity().map_err(|_| FloorErrorV1::Unavailable)?,
            locks[1].identity().map_err(|_| FloorErrorV1::Unavailable)?,
        ];
        let hello = encode_hello_v2(profile.endpoint(), nonce, salt_name, identities)?;
        let (channel, child_channel) =
            SeqpacketSocket::pair_with_record_subjects().map_err(|_| FloorErrorV1::Unavailable)?;
        let child = OwnedHelperChildV1(
            Command::new(image.path())
                .env_clear()
                .stdin(Stdio::from(child_channel))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| FloorErrorV1::Unavailable)?,
        );
        let pid = NonZeroU32::new(child.0.id()).ok_or(FloorErrorV1::Unavailable)?;
        let pidfd = PidFd::open(pid).map_err(|_| FloorErrorV1::Unavailable)?;
        let process = pidfd
            .process_identity()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        image.require_executed(pid.get())?;
        require_broker_floor_helper_v1(profile.endpoint(), pid.get())?;
        image.revalidate()?;

        let mut owner = Self {
            child: Some(child),
            channel: Some(channel),
            pidfd: Some(pidfd),
            identity: Some(process),
            binding: RetainedPhysicalBindingV1::Broker {
                image,
                service,
                profile,
            },
            nonce,
            sequence: 1,
            poisoned: false,
        };
        owner.require_custody()
            .map_err(PhysicalTpmFailureV1::broker_error)?;
        owner.require_broker_child()?;
        owner.send_frame(&hello[..], SentLocksV1::Broker(&locks), None)
            .map_err(PhysicalTpmFailureV1::broker_error)?;
        let acknowledgment = owner
            .receive_frame(LOCK_ACK_BYTES, HostReplyV1::Acknowledgment)
            .map_err(PhysicalTpmFailureV1::broker_error)?;
        require_lock_ack_v2(
            owner.received_payload(&acknowledgment)
                .map_err(PhysicalTpmFailureV1::broker_error)?,
            nonce,
        )?;
        // The actual image and ACK still precede AUTH/device access.
        owner.require_custody()
            .map_err(PhysicalTpmFailureV1::broker_error)?;
        let authentication = encode_auth_v2(profile.endpoint(), nonce, auth)?;
        owner.send_frame(&authentication[..], SentLocksV1::None, None)
            .map_err(PhysicalTpmFailureV1::broker_error)?;
        drop(authentication);
        owner.read(profile.endpoint().nv_index())?;
        Ok(owner)
    }
}

impl<'owner, 'origin, 'startup> RetainedPhysicalTpmOwnerV1<'owner, 'origin, 'startup> {
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
            RetainedPhysicalBindingV1::Broker { image, service, profile } => {
                image.revalidate()?;
                require_broker_floor_helper_v1(profile.endpoint(), pid)?;
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
            || self.pidfd()?.process_identity().map_err(|error| self.linux_error(error))?
                != self.identity.ok_or(FloorErrorV1::Unavailable)?
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
                RetainedPhysicalBindingV1::Broker { .. } => {
                    // Preserve the original Broker ambiguous-command cleanup.
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
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        loop {
            wait_channel(
                self.channel()?.as_fd().map_err(|error| self.send_error(error))?,
                PollFlags::OUT,
                deadline,
            )
            .map_err(|error| self.wait_error(error))?;
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
                SentLocksV1::Host => channel
                    .send_with_descriptors(bytes, &self.host()?.lock_fds()?),
                SentLocksV1::None => channel.send(bytes),
            };
            match sent {
                Ok(()) => return Ok(()),
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
            wait_channel(
                self.channel()?.as_fd().map_err(|error| self.send_error(error))?,
                PollFlags::IN,
                deadline,
            )
            .map_err(|error| self.wait_error(error))?;
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
            } else {
                let received = match self.channel_mut()?.receive(maximum) {
                    Ok(received) => received,
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => continue,
                    Err(_) => return Err(FloorErrorV1::Unavailable.into()),
                };
                ReceivedFrameV1::Broker(received)
            };
            let received = self.received_record(&frame)?;
            let subject = received.subject();
            let credentials = subject.credentials();
            if credentials.pid().get() != self.child()?.0.id()
                || credentials.uid() != rustix::process::geteuid().as_raw()
                || credentials.gid() != rustix::process::getegid().as_raw()
                || subject.pidfd().process_identity().map_err(|error| self.linux_error(error))?
                    != self.identity.ok_or(FloorErrorV1::Unavailable)?
                || !subject.is_alive().map_err(|error| self.linux_error(error))?
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
                service.require_child(self.pidfd.as_ref().ok_or(FloorErrorV1::Unavailable)?)
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
        if self.is_host() {
            PhysicalTpmFailureV1::Linux(error)
        } else {
            FloorErrorV1::Unavailable.into()
        }
    }

    fn child_error(&self, error: std::io::Error) -> PhysicalTpmFailureV1 {
        if self.is_host() {
            PhysicalTpmFailureV1::Child(error)
        } else {
            FloorErrorV1::Unavailable.into()
        }
    }

    fn send_error(&self, error: SeqpacketError) -> PhysicalTpmFailureV1 {
        if self.is_host() {
            PhysicalTpmFailureV1::Send(error)
        } else {
            FloorErrorV1::Unavailable.into()
        }
    }

    fn wait_error(&self, error: super::NvCustodyErrorV1) -> PhysicalTpmFailureV1 {
        if self.is_host() {
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
        let observed = self.exchange(HelperOperationV1::Read, [0; 32])
            .map_err(PhysicalTpmFailureV1::broker_error)?;
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
        let observed = self.exchange(HelperOperationV1::Extend, *input)
            .map_err(PhysicalTpmFailureV1::broker_error)?;
        if observed.name != profile.nv_name()
            || observed.name_algorithm != 0x000b
            || observed.attributes != NV_ATTRIBUTES_WRITTEN
            || observed.size != 32
            || observed.policy_length != 0
            || observed.value == [0; 32]
        {
            self.poisoned = true;
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(())
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
