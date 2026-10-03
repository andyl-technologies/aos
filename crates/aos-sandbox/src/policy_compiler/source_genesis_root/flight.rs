//! Non-detachable Root proofs backed by the same actual authenticated stream.
//!
//! The conditional producer invariant is normal Root's exact immutable code
//! and enforcing policy: no accepted-FD fork/transfer, out-of-role endpoint
//! fd-use/write, task-file theft/ptrace, role escape or SYS_ADMIN nomination.
//! Every received fragment must additionally nominate the exact still-live
//! original daemon TGID. SCM_SECURITY is the socket SID, not the task SID.
//! Endpoint credentials, a Boolean, cached bytes, or a raw floor cannot mint
//! these proofs. The normal Root role and canonical loaded-policy comparison
//! must be genuinely installed; the old init_t endpoint necessarily refuses.

use std::cell::{Cell, RefCell};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};

use crate::hierarchy::genesis_profile::{SourceGenesisErrorV1, take};

use super::records::{RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1};
use super::transport;
use super::wire::{
    ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1, ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1,
    ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1, RootSourceGenesisFrameKindV1 as Phase,
    decode_root_source_genesis_frame_v1, encode_root_source_genesis_frame_v1,
};

use crate::hierarchy::controller_genesis::HeldControllerSourceGenesisV1;
use crate::normal_root::{OriginalNormalRootPeerV1, ProductionControllerNormalRootProfileV1};
use crate::policy_compiler::controller_readback_session::fresh_root_nonce;
const MAXIMUM_FLIGHT: Duration = Duration::from_secs(60);

/// Borrows one actual Root prepare flight; decoding an intent cannot create it.
pub struct HeldRootSourceGenesisIntentV1<'flight> {
    origin: &'flight OriginalRootGenesisFlightV1<'flight>,
    record: RootSourceGenesisIntentRecordV1,
    deadline: u64,
    expires: i64,
}

impl HeldRootSourceGenesisIntentV1<'_> {
    /// Borrows the exact Root-owned prepare record from this original flight.
    #[must_use]
    pub const fn record(&self) -> &RootSourceGenesisIntentRecordV1 {
        &self.record
    }

    /// Rechecks the actual Root role, original endpoint, process and held flight.
    ///
    /// # Errors
    /// Rejects lost or changed original peer/cgroup/policy, poisoned transport,
    /// or a different privileged Source UID. This is historical custody only.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.recheck()?;
        if self.record.source_uid() != self.origin.source_uid {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }

    /// Separately checks the unchanged initial paired-clock admission deadline.
    ///
    /// # Errors
    /// Rejects expiry or clock/boot discontinuity before genuinely new Source
    /// mutation. Historical prepared readback/ACK does not grant this condition.
    pub fn recheck_current_admission(&self) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let later = kernel_pair()?;
        self.origin
            .clock
            .validate_later_sample(later)
            .map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?;
        if later.wall_seconds() >= self.expires || later.boottime_nanoseconds() >= self.deadline {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        Ok(())
    }
}

/// Borrows the actual original Root flight through Controller and Source ACK.
pub struct RootSourceGenesisFloorProofV1<'flight> {
    origin: &'flight OriginalRootGenesisFlightV1<'flight>,
    floor: SourceHierarchyFloorRecordV1,
}

impl RootSourceGenesisFloorProofV1<'_> {
    /// Borrows the exact Root-owned floor, whose raw bytes remain data only.
    #[must_use]
    pub const fn floor(&self) -> &SourceHierarchyFloorRecordV1 {
        &self.floor
    }

    /// Returns the privileged Source UID bound by the actual Root flight hello.
    ///
    /// This comes from normal Root's protected service configuration, never
    /// decoded floor data, Source journal ownership, or a caller assertion.
    #[must_use]
    pub const fn source_uid(&self) -> u32 {
        self.origin.source_uid
    }

    /// Rechecks actual original live Root custody without granting fresh genesis.
    ///
    /// # Errors
    /// Rejects changed endpoint/process/cgroup, unenforcing or changed exact
    /// deployed policy, failed subject receive, or a completed/lost flight.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.recheck()
    }
}

// Only receipt of Completed on the original held stream constructs this loan.
// Its floor remains borrowed; a decoded floor or earlier Anchored reply cannot
// select the current-ancestry consumer.
pub(in crate::policy_compiler) struct CompletedRootSourceGenesisFloorV1<'completed, 'flight> {
    proof: &'completed RootSourceGenesisFloorProofV1<'flight>,
}

impl CompletedRootSourceGenesisFloorV1<'_, '_> {
    pub(in crate::policy_compiler) fn floor(&self) -> &SourceHierarchyFloorRecordV1 {
        self.proof.floor()
    }

    pub(in crate::policy_compiler) fn source_uid(&self) -> u32 {
        self.proof.source_uid()
    }

    pub(in crate::policy_compiler) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.proof.recheck()
    }

    pub(in crate::policy_compiler) fn signing_boundary_clock(
        &self,
    ) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.proof.origin.signing_boundary_clock()
    }
}

// Private to the same-flight coordinator. There is no adoption constructor
// accepting caller-supplied peers, subjects, floor bytes, or ready flags.
pub(super) struct OriginalRootGenesisFlightV1<'profile> {
    stream: RefCell<RetainedUnixStream>,
    peer: OriginalNormalRootPeerV1<'profile>,
    clock: RawPairedClockSample,
    started: Instant,
    poisoned: Cell<bool>,
    nonce: [u8; 16],
    source_uid: u32,
}

pub(super) enum OriginalRootGenesisReplyV1<'flight> {
    Prepared(HeldRootSourceGenesisIntentV1<'flight>),
    Anchored(RootSourceGenesisFloorProofV1<'flight>),
}

impl<'profile> OriginalRootGenesisFlightV1<'profile> {
    // Only the actual coordinator calls this after retaining both named
    // Controller and Source writers. No supplied policy path/peer/proof enters.
    pub(super) fn connect(
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Result<Self, SourceGenesisErrorV1> {
        let started = Instant::now();
        let clock = kernel_pair()?;
        let deadline = started + MAXIMUM_FLIGHT;
        profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale)?;
        let mut stream = transport::connect_fixed(deadline)?;
        stream.enable_subject_reporting()?;
        let peer = profile
            .observe_original_peer(&stream)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let source_uid = peer.source_uid();
        let client_nonce = fresh_root_nonce()?;
        let mut origin = Self {
            stream: RefCell::new(stream),
            peer,
            clock,
            started,
            poisoned: Cell::new(false),
            nonce: [0; 16],
            source_uid,
        };
        origin.establish_hello(client_nonce)?;
        Ok(origin)
    }

    // The issuer owns both slots before this method starts. In particular,
    // peer/adoption errors cannot release the retained original raw socket.
    pub(super) fn connect_parked(
        profile: &'profile ProductionControllerNormalRootProfileV1,
        raw: &mut Option<OwnedFd>,
        adopted: &mut Option<RetainedUnixStream>,
        parked: &mut Option<Self>,
    ) -> Result<(), SourceGenesisErrorV1> {
        if parked.is_some() || adopted.is_some() || raw.is_some() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let started = Instant::now();
        let clock = kernel_pair()?;
        profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale)?;
        *adopted = Some(transport::connect_parked(raw, started + MAXIMUM_FLIGHT)?);
        let stream = adopted.as_mut().ok_or(SourceGenesisErrorV1::Stale)?;
        stream.enable_subject_reporting()?;
        let peer = profile.observe_original_peer(&stream)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let source_uid = peer.source_uid();
        let client_nonce = fresh_root_nonce()?;
        let stream = adopted.take().ok_or(SourceGenesisErrorV1::Stale)?;
        *parked = Some(Self {
            stream: RefCell::new(stream),
            peer,
            clock,
            started,
            poisoned: Cell::new(false),
            nonce: [0; 16],
            source_uid,
        });

        let origin = parked.as_mut().ok_or(SourceGenesisErrorV1::Stale)?;
        origin.establish_hello(client_nonce)
    }

    fn establish_hello(&mut self, client_nonce: [u8; 16]) -> Result<(), SourceGenesisErrorV1> {
        let mut request = [0; 32];
        request[..8].copy_from_slice(ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1);
        request[8..24].copy_from_slice(&client_nonce);
        self.write(&request)?;
        let hello = self.receive_exact(56)?;
        if hello.get(..8) != Some(ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1.as_slice())
            || hello[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
            || take::<16>(&hello, 16)? != client_nonce
            || take::<16>(&hello, 32)? == [0; 16]
            || u32::from_be_bytes(take(&hello, 48)?) != self.source_uid
            || u32::from_be_bytes(take(&hello, 52)?) != self.source_uid
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        self.nonce = take(&hello, 32)?;
        self.recheck()
    }

    pub(super) fn issuance_clock(&self) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.recheck()?;
        let now = kernel_pair()?;
        self.clock.validate_later_sample(now).map_err(|_| SourceGenesisErrorV1::Stale)?;
        self.recheck()?;
        Ok(now)
    }

    // Unlike the general observation above, signing needs its genuine pair
    // after the potentially slow original-flight observations. Only continuity
    // and the unchanged original deadline are checked after this sample.
    fn signing_boundary_clock(&self) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.recheck()?;

        let now = kernel_pair()?;
        self.clock.validate_later_sample(now)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        if self.poisoned.get() || self.started.elapsed() >= MAXIMUM_FLIGHT {
            return Err(SourceGenesisErrorV1::Stale);
        }

        Ok(now)
    }

    pub(super) fn end_failed(&self) -> Result<(), SourceGenesisErrorV1> {
        self.poisoned.set(true);
        let stream = self.stream.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
        rustix::net::shutdown(stream.as_fd(), rustix::net::Shutdown::Both)
            .map_err(std::io::Error::from)?;
        Ok(())
    }

    pub(super) const fn nonce(&self) -> [u8; 16] {
        self.nonce
    }

    pub(super) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        if self.poisoned.get() || self.started.elapsed() >= MAXIMUM_FLIGHT {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let stream = self
            .stream
            .try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        stream.revalidate_original()?;
        require_open_receive_queue(stream.as_fd())?;
        self.peer
            .recheck_stream(&stream)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        if self.source_uid != self.peer.source_uid() {
            return Err(SourceGenesisErrorV1::Stale);
        }
        // Genuine PID1/property and immutable-image reads are bounded too,
        // but their completion may cross the original flight's deadline.
        transport::require_remaining(self.started + MAXIMUM_FLIGHT).map(|_| ())
    }

    pub(super) fn write(&self, bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
        let result = self.write_remaining(bytes);
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    fn write_remaining(&self, bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let mut sent = 0;
        while sent < bytes.len() {
            self.recheck()?;
            let stream = self
                .stream
                .try_borrow()
                .map_err(|_| SourceGenesisErrorV1::Stale)?;
            match rustix::net::send(
                stream.as_fd(),
                &bytes[sent..],
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
            ) {
                Ok(0) => return Err(SourceGenesisErrorV1::Stale),
                Ok(count) => sent += count,
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => transport::wait(
                    stream.as_fd(),
                    rustix::event::PollFlags::OUT,
                    self.started + MAXIMUM_FLIGHT,
                )?,
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
        transport::require_remaining(self.started + MAXIMUM_FLIGHT).map(|_| ())
    }

    pub(super) fn send_phase(
        &self,
        phase: Phase,
        payload: &[u8],
    ) -> Result<(), SourceGenesisErrorV1> {
        self.write(&encode_root_source_genesis_frame_v1(
            phase, self.nonce, payload,
        )?)
    }

    pub(super) fn receive_reply<'flight>(
        &'flight self,
        controller: &HeldControllerSourceGenesisV1<'_>,
    ) -> Result<OriginalRootGenesisReplyV1<'flight>, SourceGenesisErrorV1> {
        let (phase, payload) = self.receive_phase(&[Phase::Prepared, Phase::Anchored])?;
        if phase == Phase::Anchored {
            return self
                .floor_from_original_payload(controller, &payload)
                .map(OriginalRootGenesisReplyV1::Anchored);
        }
        let expires = i64::from_be_bytes(take(&payload, 0)?);
        let record = RootSourceGenesisIntentRecordV1::from_record_bytes(&payload[8..])?;
        if record.accepted_input() != controller.acceptance()
            || record.source_uid() != self.source_uid
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let deadline = self
            .clock
            .boottime_nanoseconds()
            .checked_add(
                MAXIMUM_FLIGHT
                    .as_nanos()
                    .try_into()
                    .map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
            )
            .ok_or(SourceGenesisErrorV1::NonCanonical)?;
        self.recheck()?;
        Ok(OriginalRootGenesisReplyV1::Prepared(
            HeldRootSourceGenesisIntentV1 {
                origin: self,
                record,
                deadline,
                expires,
            },
        ))
    }

    pub(super) fn receive_floor<'flight>(
        &'flight self,
        controller: &HeldControllerSourceGenesisV1<'_>,
    ) -> Result<RootSourceGenesisFloorProofV1<'flight>, SourceGenesisErrorV1> {
        let (_, payload) = self.receive_phase(&[Phase::Anchored])?;
        self.floor_from_original_payload(controller, &payload)
    }

    fn floor_from_original_payload<'flight>(
        &'flight self,
        controller: &HeldControllerSourceGenesisV1<'_>,
        payload: &[u8],
    ) -> Result<RootSourceGenesisFloorProofV1<'flight>, SourceGenesisErrorV1> {
        let floor = SourceHierarchyFloorRecordV1::from_record_bytes(payload)?;
        let receipt = floor.receipt();
        let accepted = controller.acceptance();
        if floor.project() != accepted.project()
            || receipt.acceptance_digest() != accepted.digest()
            || &receipt.seed_packet() != accepted.seed_packet()
            || &receipt.auth_packet() != accepted.auth_packet()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        self.recheck()?;
        controller.recheck()?;
        Ok(RootSourceGenesisFloorProofV1 {
            origin: self,
            floor,
        })
    }

    pub(super) fn receive_completed<'completed, 'flight>(
        &self,
        proof: &'completed RootSourceGenesisFloorProofV1<'flight>,
    ) -> Result<CompletedRootSourceGenesisFloorV1<'completed, 'flight>, SourceGenesisErrorV1> {
        if !std::ptr::eq(self, proof.origin) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        proof.recheck()?;
        let (_, completed) = self.receive_phase(&[Phase::Completed])?;
        require_completed_digest(&completed, proof.floor().digest().as_bytes())?;
        proof.recheck()?;
        Ok(CompletedRootSourceGenesisFloorV1 { proof })
    }

    pub(super) fn finish(
        &self,
        completed: CompletedRootSourceGenesisFloorV1<'_, '_>,
    ) -> Result<(), SourceGenesisErrorV1> {
        if !std::ptr::eq(self, completed.proof.origin) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        completed.recheck()?;
        // Completed was received on the original held stream. Finish may make
        // Root close immediately, so no later open-queue predicate is asserted.
        self.send_phase(Phase::Finish, completed.floor().digest().as_bytes())
    }

    fn receive_phase(&self, allowed: &[Phase]) -> Result<(Phase, Vec<u8>), SourceGenesisErrorV1> {
        let result = (|| {
            let mut frame = self.receive_exact(ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1)?;
            let phase = select_reply_phase(&frame, allowed, self.nonce)?;
            frame.extend_from_slice(&self.receive_exact(phase.payload_bytes())?);
            let payload = decode_root_source_genesis_frame_v1(&frame, phase, self.nonce)?.to_vec();
            Ok((phase, payload))
        })();
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    pub(super) fn receive_exact(&self, length: usize) -> Result<Vec<u8>, SourceGenesisErrorV1> {
        if length == 0 || length > 4096 {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let result = self.receive_fragments(length);
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    fn receive_fragments(&self, length: usize) -> Result<Vec<u8>, SourceGenesisErrorV1> {
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            self.recheck()?;
            let chunk = self
                .stream
                .try_borrow_mut()
                .map_err(|_| SourceGenesisErrorV1::Stale)?
                .try_receive_subject_chunk(length - bytes.len());
            match chunk {
                Ok(chunk) => {
                    self.require_root_chunk(&chunk)?;
                    bytes.extend_from_slice(chunk.payload());
                }
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    let stream = self
                        .stream
                        .try_borrow()
                        .map_err(|_| SourceGenesisErrorV1::Stale)?;
                    transport::wait(
                        stream.as_fd(),
                        rustix::event::PollFlags::IN,
                        self.started + MAXIMUM_FLIGHT,
                    )?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.recheck()?;
        Ok(bytes)
    }

    fn require_root_chunk(
        &self,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let stream = self
            .stream
            .try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        self.peer
            .require_chunk(&stream, chunk)
            .map_err(|_| SourceGenesisErrorV1::Stale)
    }
}

// Pure framing checks never adopt a stream or return authorizing owner types.
fn select_reply_phase(
    header: &[u8],
    allowed: &[Phase],
    nonce: [u8; 16],
) -> Result<Phase, SourceGenesisErrorV1> {
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
        || header[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
        || nonce == [0; 16]
        || header[16..32] != nonce
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    allowed
        .iter()
        .copied()
        .find(|phase| header.get(..8) == Some(phase.magic().as_slice()))
        .ok_or(SourceGenesisErrorV1::NonCanonical)
}

fn require_completed_digest(
    completed: &[u8],
    expected: &[u8; 32],
) -> Result<(), SourceGenesisErrorV1> {
    if completed != expected.as_slice() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(())
}

impl Drop for OriginalRootGenesisFlightV1<'_> {
    fn drop(&mut self) {
        // Shutdown precedes releasing either enclosing writer. It also tells
        // Root to close its accepted queue before releasing its own writer.
        let _ = rustix::net::shutdown(self.stream.get_mut().as_fd(), rustix::net::Shutdown::Both);
    }
}

// Creator pidfd liveness does not imply the daemon still retains this writer:
// the server shuts down its original endpoint before releasing the journal.
fn require_open_receive_queue(descriptor: BorrowedFd<'_>) -> Result<(), SourceGenesisErrorV1> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    let mut descriptors = [PollFd::new(&descriptor, PollFlags::RDHUP)];
    poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(std::io::Error::from)?;
    if descriptors[0]
        .revents()
        .intersects(PollFlags::RDHUP | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    Ok(())
}

fn kernel_pair() -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
    let before = KernelBootId::current()?.into_bytes();
    let boot = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    let after = KernelBootId::current()?.into_bytes();
    if before != after {
        return Err(SourceGenesisErrorV1::Stale);
    }
    let boot = u64::try_from(boot.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(boot.tv_nsec)
                .ok()
                .and_then(|fraction| seconds.checked_add(fraction))
        })
        .ok_or(SourceGenesisErrorV1::Stale)?;
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
            .map_err(|_| SourceGenesisErrorV1::Stale)?,
        before,
        wall,
        boot,
    )
    .map_err(|_| SourceGenesisErrorV1::Stale)
}

#[cfg(test)]
mod tests {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn completed_window_accepts_only_original_completed_phase_and_nonce_data() {
        let nonce = [31; 16];
        let floor = [32; 32];
        let frame = encode_root_source_genesis_frame_v1(Phase::Completed, nonce, &floor).unwrap();

        assert_eq!(
            select_reply_phase(&frame[..32], &[Phase::Completed], nonce).unwrap(),
            Phase::Completed,
        );
        assert!(select_reply_phase(&frame[..32], &[Phase::Completed], [33; 16]).is_err());
        for phase in [Phase::Anchored, Phase::Complete, Phase::Finish] {
            let substituted =
                encode_root_source_genesis_frame_v1(phase, nonce, &vec![0; phase.payload_bytes()])
                    .unwrap();
            assert!(
                select_reply_phase(&substituted[..32], &[Phase::Completed], nonce).is_err(),
            );
        }
    }

    #[test]
    fn live_creator_does_not_hide_original_queue_shutdown() {
        let (client, server) = UnixStream::pair().unwrap();
        require_open_receive_queue(client.as_fd()).unwrap();

        server.shutdown(Shutdown::Both).unwrap();

        assert!(matches!(
            require_open_receive_queue(client.as_fd()),
            Err(SourceGenesisErrorV1::Stale)
        ));
    }

    #[test]
    fn initial_reply_allows_only_prepared_or_exact_anchored_recovery() {
        // These are DATA-only frames, not fake Root peers or live proofs.
        let nonce = [11; 16];
        for phase in [Phase::Prepared, Phase::Anchored] {
            let frame =
                encode_root_source_genesis_frame_v1(phase, nonce, &vec![0; phase.payload_bytes()])
                    .unwrap();
            assert_eq!(
                select_reply_phase(&frame[..32], &[Phase::Prepared, Phase::Anchored], nonce)
                    .unwrap(),
                phase
            );
        }
        for phase in [
            Phase::Prepare,
            Phase::Anchor,
            Phase::Complete,
            Phase::Completed,
            Phase::Finish,
        ] {
            let frame =
                encode_root_source_genesis_frame_v1(phase, nonce, &vec![0; phase.payload_bytes()])
                    .unwrap();
            assert!(
                select_reply_phase(&frame[..32], &[Phase::Prepared, Phase::Anchored], nonce)
                    .is_err()
            );
        }
    }

    #[test]
    fn every_reply_rejects_wrong_nonce_version_reserved_or_width() {
        let nonce = [12; 16];
        let frame =
            encode_root_source_genesis_frame_v1(Phase::Completed, nonce, &[13; 32]).unwrap();
        let header = &frame[..32];
        assert!(select_reply_phase(header, &[Phase::Completed], [14; 16]).is_err());
        assert!(select_reply_phase(header, &[Phase::Completed], [0; 16]).is_err());
        assert!(select_reply_phase(&header[..31], &[Phase::Completed], nonce).is_err());
        for offset in [8, 9, 10, 15, 16, 31] {
            let mut changed = header.to_vec();
            changed[offset] ^= 1;
            assert!(select_reply_phase(&changed, &[Phase::Completed], nonce).is_err());
        }
    }

    #[test]
    fn finish_never_acknowledges_another_or_incomplete_floor() {
        let floor = [15; 32];
        require_completed_digest(&floor, &floor).unwrap();
        assert!(require_completed_digest(&[16; 32], &floor).is_err());
        assert!(require_completed_digest(&floor[..31], &floor).is_err());
        assert!(require_completed_digest(&[], &floor).is_err());
    }
}
