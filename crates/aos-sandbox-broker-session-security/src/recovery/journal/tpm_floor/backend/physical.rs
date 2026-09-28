//! Safe ownership of one private fixed-image, persistent ESYS helper child.
//!
//! The stable upstream safe Rust ESYS API does not expose NV_Extend. The
//! source-built helper owns TPM layouts and one retained Device-TCTI/ESYS
//! session; Rust owns only bounded private framing, image custody, pidfd and
//! child cleanup. No raw FFI, shell, tool-output authority, public factory,
//! alternate device, or environment-selected TCTI crosses this boundary.

use std::num::NonZeroU32;
use std::os::fd::BorrowedFd;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use aos_sandbox::ProtectedJournalLockCustodyV1;
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::{ReceivedRecord, SeqpacketError, SeqpacketSocket};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use sha2::{Digest as _, Sha256};

use super::super::{FloorErrorV1, FloorProfileV1};
use super::helper_protocol::{
    HelperObservationV1, HelperOperationV1, LOCK_ACK_BYTES, RESPONSE_BYTES, decode_response_v1,
    encode_hello_v1, encode_request_v1, require_lock_ack_v1,
};
use super::image::MeasuredHelperImageV1;
use super::service_policy::RetainedFloorServicePolicyV1;
use super::{AuthenticatedNvObservationV1, AuthenticatedTpmNvIoV1, sealed};

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Owns the child immediately, so every failed constructor stops/reaps it.
struct OwnedHelperChildV1(Child);

impl Drop for OwnedHelperChildV1 {
    fn drop(&mut self) {
        // Child is the exact spawned process, not a numeric-PID discovery.
        // Closing/killing this carrier cannot clear, reset, or undefine NV.
        // A successful wait fences this owned child's kernel-release work.
        // Daemon-crash restart additionally needs the actual unit population
        // barrier; shared flock descriptions alone do not order __fput.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(in crate::recovery::journal::tpm_floor) struct PhysicalTpmNvIoV1 {
    child: OwnedHelperChildV1,
    channel: SeqpacketSocket,
    pidfd: PidFd,
    identity: PidFdProcessIdentity,
    image: MeasuredHelperImageV1,
    service: RetainedFloorServicePolicyV1,
    profile: FloorProfileV1,
    nonce: [u8; 32],
    sequence: u64,
    poisoned: bool,
}

impl PhysicalTpmNvIoV1 {
    pub(in crate::recovery::journal::tpm_floor) fn open(
        profile: FloorProfileV1,
        salt_name: [u8; 34],
        auth: &[u8; 32],
        locks: [ProtectedJournalLockCustodyV1; 2],
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<Self, FloorErrorV1> {
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
        let hello = encode_hello_v1(profile.endpoint(), nonce, salt_name, auth, identities)?;
        let (channel, child_channel) =
            SeqpacketSocket::pair_with_record_subjects().map_err(|_| FloorErrorV1::Unavailable)?;
        let child = OwnedHelperChildV1(
            Command::new(image.path())
                .env_clear()
                // Safe child-local mapping; parent descriptors retain CLOEXEC.
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
        image.revalidate()?;

        let mut owner = Self {
            child,
            channel,
            pidfd,
            identity: process,
            image,
            service,
            profile,
            nonce,
            sequence: 1,
            poisoned: false,
        };
        owner.require_custody()?;
        owner.service.require_child(&owner.pidfd)?;
        owner.send_frame(&hello[..], Some(&locks))?;
        let acknowledgment = owner.receive_frame(LOCK_ACK_BYTES)?;
        require_lock_ack_v1(acknowledgment.payload(), nonce)?;
        // Child acknowledges both validated lock-only OFDs before opening the
        // TPM. It receives no journal data/writer API; later frames carry no FD.
        owner.read(profile.endpoint().nv_index())?;
        Ok(owner)
    }

    fn require_custody(&mut self) -> Result<(), FloorErrorV1> {
        let info = self.pidfd.info().map_err(|_| FloorErrorV1::Unavailable)?;
        let credentials = info.credentials().ok_or(FloorErrorV1::Unavailable)?;
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        if self.poisoned
            || !self
                .pidfd
                .is_alive()
                .map_err(|_| FloorErrorV1::Unavailable)?
            || self
                .child
                .0
                .try_wait()
                .map_err(|_| FloorErrorV1::Unavailable)?
                .is_some()
            || info.parent_pid() != std::process::id()
            || info.pid() != self.child.0.id()
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
            || self
                .pidfd
                .process_identity()
                .map_err(|_| FloorErrorV1::Unavailable)?
                != self.identity
        {
            return Err(FloorErrorV1::Unavailable);
        }
        self.image.revalidate()?;
        self.service.revalidate()?;
        self.service.require_child(&self.pidfd)?;
        if !self
            .pidfd
            .is_alive()
            .map_err(|_| FloorErrorV1::Unavailable)?
        {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    fn exchange(
        &mut self,
        operation: HelperOperationV1,
        input: [u8; 32],
    ) -> Result<HelperObservationV1, FloorErrorV1> {
        self.require_custody()?;
        let request = encode_request_v1(operation, self.nonce, self.sequence, input)?;
        let result = (|| {
            self.send_frame(&request, None)?;
            let response = self.receive_frame(RESPONSE_BYTES)?;
            let observation =
                decode_response_v1(response.payload(), operation, self.nonce, self.sequence)?;
            self.require_custody()?;
            self.sequence = self
                .sequence
                .checked_add(1)
                .filter(|value| *value != u64::MAX)
                .ok_or(FloorErrorV1::Unavailable)?;
            Ok(observation)
        })();
        if result.is_err() {
            // No read or retry can overtake an ambiguous command on this
            // carrier. Cold reconciliation needs a fresh child and session.
            self.poisoned = true;
            let _ = self.child.0.kill();
            let _ = self.child.0.wait();
        }
        result
    }

    fn send_frame(
        &mut self,
        bytes: &[u8],
        locks: Option<&[ProtectedJournalLockCustodyV1; 2]>,
    ) -> Result<(), FloorErrorV1> {
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        loop {
            wait_channel(
                self.channel
                    .as_fd()
                    .map_err(|_| FloorErrorV1::Unavailable)?,
                PollFlags::OUT,
                deadline,
            )?;
            let sent = match locks {
                Some(locks) => self
                    .channel
                    .send_with_descriptors(bytes, &[locks[0].as_fd(), locks[1].as_fd()]),
                None => self.channel.send(bytes),
            };
            match sent {
                Ok(()) => return Ok(()),
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {}
                Err(_) => return Err(FloorErrorV1::Unavailable),
            }
        }
    }

    fn receive_frame(&mut self, maximum: usize) -> Result<ReceivedRecord, FloorErrorV1> {
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        loop {
            wait_channel(
                self.channel
                    .as_fd()
                    .map_err(|_| FloorErrorV1::Unavailable)?,
                PollFlags::IN,
                deadline,
            )?;
            let received = match self.channel.receive(maximum) {
                Ok(received) => received,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => continue,
                Err(_) => return Err(FloorErrorV1::Unavailable),
            };
            let subject = received.subject();
            let credentials = subject.credentials();
            if credentials.pid().get() != self.child.0.id()
                || credentials.uid() != rustix::process::geteuid().as_raw()
                || credentials.gid() != rustix::process::getegid().as_raw()
                || subject
                    .pidfd()
                    .process_identity()
                    .map_err(|_| FloorErrorV1::Unavailable)?
                    != self.identity
                || !subject.is_alive().map_err(|_| FloorErrorV1::Unavailable)?
            {
                return Err(FloorErrorV1::Unavailable);
            }
            return Ok(received);
        }
    }
}

impl sealed::Sealed for PhysicalTpmNvIoV1 {}

impl AuthenticatedTpmNvIoV1 for PhysicalTpmNvIoV1 {
    fn read(&mut self, index: u32) -> Result<AuthenticatedNvObservationV1, FloorErrorV1> {
        if index != self.profile.endpoint().nv_index() {
            return Err(FloorErrorV1::Provisioning);
        }
        let observed = self.exchange(HelperOperationV1::Read, [0; 32])?;
        Ok(AuthenticatedNvObservationV1 {
            salt_key_name_digest: self.profile.salt_key_name_digest(),
            index,
            name: observed.name,
            name_algorithm: observed.name_algorithm,
            attributes: observed.attributes,
            size: observed.size,
            empty_auth_policy: observed.policy_length == 0,
            value: observed.value,
        })
    }

    fn extend(&mut self, index: u32, input: &[u8; 32]) -> Result<(), FloorErrorV1> {
        if index != self.profile.endpoint().nv_index() {
            return Err(FloorErrorV1::Provisioning);
        }
        let observed = self.exchange(HelperOperationV1::Extend, *input)?;
        if observed.name != self.profile.nv_name()
            || observed.name_algorithm != 0x000b
            || observed.attributes != super::NV_ATTRIBUTES_WRITTEN
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

fn wait_channel(
    fd: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), FloorErrorV1> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(FloorErrorV1::Unavailable)?;
    let timeout = Timespec::try_from(remaining).map_err(|_| FloorErrorV1::Unavailable)?;
    let mut descriptors = [PollFd::new(&fd, interest)];
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(_) if descriptors[0].revents().contains(interest) => Ok(()),
        Err(rustix::io::Errno::INTR) => Ok(()),
        _ => Err(FloorErrorV1::Unavailable),
    }
}
