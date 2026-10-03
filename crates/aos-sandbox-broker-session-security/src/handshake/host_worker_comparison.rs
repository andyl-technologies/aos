//! Nonterminal comparison reply on the original method-49 Host/Mount flight.
//!
//! ```text
//! AOSFWR01 | version:u16be=1 | method:u16be=49 | purpose:u32be=56 |
//! Host1.0:u16be/u16be | RootMount:u16be=5 | roles:u16be[2]=17,18 |
//! deadline:u64be | request-id[16] | session[32] | signed-request[32] |
//! semantics[32] | body-size:u32be | exact comparison response body
//! SCM_RIGHTS = [Host worker pidfd copy, Host worker cgroup copy]
//! ```
//!
//! Both directions retain their actual locked session owner, original socket
//! and nonterminal head. Neither the frame nor returned descriptors creates a
//! live worker lease, copy-close barrier or Root resource grant. The private
//! rendezvous child composes the real owners for a subsequent fresh exchange;
//! it never treats the comparison objects themselves as that authority.

use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;

use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;
use aos_sandbox_host::peer::ControllerPeerVerifier;
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_mount::broker::PreparedMountFuseWorkerHandoffV1;
use aos_sandbox_mount::worker::MountWorker;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::host_fuse_worker_session::{
    HOST_FUSE_WORKER_SESSION_BODY_MAXIMUM_BYTES_V1, decode_host_fuse_worker_session_request_v1,
    decode_host_fuse_worker_session_response_v1,
};

use super::DormantAuthenticatedBrokerSessionV1;
use super::DormantBrokerSessionHandshakeErrorV1 as TransportError;
use crate::BrokerSessionSecurityError;
use crate::dormant_handshake::DormantBrokerSessionHandshakeErrorV1;

const MAGIC: &[u8; 8] = b"AOSFWR01";
const CONTRACT: &[u8; 18] = &[0, 1, 0, 49, 0, 0, 0, 56, 0, 1, 0, 0, 0, 5, 0, 17, 0, 18];
const HEADER_BYTES: usize = 150;
// This is the same fixed service used by Mount's actual Host-scope client.
// A future installed unit change must qualify this exact role, not a reply hint.
const HOST_CGROUP: &str = "system.slice/aos-sandbox-hostd.service";

mod rendezvous;
use rendezvous::RendezvousStage;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Binding {
    deadline: u64,
    request: [u8; 16],
    session: [u8; 32],
    signed_request: [u8; 32],
    semantics: [u8; 32],
}

enum FixedPeer {
    Mount(ControllerPeerVerifier),
    Host(RetainedCgroupAnchor),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReplyStage {
    Pending,
    InFlight,
    Compared,
    ReconciliationRequired,
}

/// Retains actual original transport custody, never copy-absence/read authority.
///
/// The exclusive session borrow continuously retains the same locked journal
/// owner and original socket. Temporary pending readback tokens end before
/// mutable socket I/O; no owning lock is released or reopened. Every syscall
/// and readiness wait is sandwiched by exact original-head/peer readback.
pub(crate) struct HeldOriginalHostWorkerComparisonV1<'owner> {
    session: &'owner mut DormantAuthenticatedBrokerSessionV1,
    request: &'owner AuthenticatedBrokerMethodRequestV1,
    head: [u8; 32],
    binding: Binding,
    peer: FixedPeer,
    stage: ReplyStage,
    rendezvous_stage: RendezvousStage,
    fresh_challenge:
        Option<aos_sandbox_protocol::fuse_worker_preparation::WorkerRendezvousChallengeV2>,
}

/// Co-owns received comparison data without adopting it as a live worker.
pub(crate) struct OriginalHostWorkerComparisonV1 {
    body: Vec<u8>,
    process: PidFd,
    cgroup: CgroupV2Root,
}

impl OriginalHostWorkerComparisonV1 {
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn descriptors(&self) -> [BorrowedFd<'_>; 2] {
        [self.process.as_fd(), self.cgroup.as_fd()]
    }
}

impl<'owner> HeldOriginalHostWorkerComparisonV1<'owner> {
    pub(crate) fn capture(
        session: &'owner mut DormantAuthenticatedBrokerSessionV1,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        if session.transcript.protocol() != BrokerSessionProtocolV1::Host
            || request.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        let peer = match request.direction() {
            AuthenticatedBrokerRequestDirectionV1::ServerReceive => {
                FixedPeer::Mount(super::fixed_mount_peer_verifier()?)
            }
            AuthenticatedBrokerRequestDirectionV1::ClientSend => {
                let root = super::fixed_worker_cgroup_root()?;
                FixedPeer::Host(
                    root.resolve(Path::new(HOST_CGROUP))
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?,
                )
            }
        };
        let head = session
            .owner
            .hold_host_worker_comparison(request, &session.transcript, session.socket.peer())?
            .head_commitment();
        let mut held = Self {
            session,
            request,
            head,
            binding: Binding {
                deadline: request.deadline_boottime_nanoseconds(),
                request: request.request_id(),
                session: request.session_binding(),
                signed_request: request.signed_request_digest(),
                semantics: request.semantic_commitment(),
            },
            peer,
            stage: ReplyStage::Pending,
            rendezvous_stage: RendezvousStage::Pending,
            fresh_challenge: None,
        };
        held.recheck()?;
        Ok(held)
    }

    pub(crate) fn recheck(&mut self) -> Result<(), BrokerSessionSecurityError> {
        let checked = (|| {
            if self.stage == ReplyStage::ReconciliationRequired {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let mut pending = self.session.owner.hold_host_worker_comparison(
                self.request,
                &self.session.transcript,
                self.session.socket.peer(),
            )?;
            match &self.peer {
                FixedPeer::Mount(verifier) => pending.recheck_mount_worker_peer(verifier)?,
                FixedPeer::Host(anchor) => {
                    pending.recheck()?;
                    let peer = self.session.socket.peer();
                    let credentials = peer.credentials();
                    if credentials.uid() != 0 || credentials.gid() != 0 {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    let info = anchor
                        .verify_exact_membership(peer.pidfd())
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    if info.pid() != credentials.pid().get()
                        || info.thread_group_id() != credentials.pid().get()
                    {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    pending.recheck()?;
                }
            }
            if pending.head_commitment() != self.head {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })();
        if checked.is_err() {
            self.stage = ReplyStage::ReconciliationRequired;
        }
        checked
    }

    pub(crate) fn send(
        &mut self,
        body: &[u8],
        descriptors: [BorrowedFd<'_>; 2],
    ) -> Result<
        aos_sandbox_host::OriginalHostFuseWorkerTransportProgressV1,
        DormantBrokerSessionHandshakeErrorV1,
    > {
        use aos_sandbox_host::OriginalHostFuseWorkerTransportProgressV1 as Progress;
        if self.request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || self.stage != ReplyStage::Pending
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        self.recheck()?;
        self.validate_body(body)?;
        let frame = encode(self.binding, body, self.request.maximum_response_bytes())?;
        self.stage = ReplyStage::InFlight;
        let sent = self
            .session
            .send_host_worker_comparison_packet(&frame, descriptors);
        self.recheck()?;
        match sent {
            Ok(()) => {
                self.stage = ReplyStage::Compared;
                Ok(Progress::Sent)
            }
            Err(TransportError::Transport) => {
                self.stage = ReplyStage::Pending;
                self.wait(true)?;
                Ok(Progress::Backpressure)
            }
            Err(error) => {
                self.stage = ReplyStage::ReconciliationRequired;
                Err(error.into())
            }
        }
    }

    pub(crate) fn receive<W: MountWorker>(
        &mut self,
        handoff: &mut PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        original: &mut super::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
    ) -> Result<OriginalHostWorkerComparisonV1, DormantBrokerSessionHandshakeErrorV1> {
        if self.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || self.stage != ReplyStage::Pending
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        loop {
            original.recheck()?;
            handoff
                .recheck()
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            self.recheck()?;
            let maximum = usize::try_from(self.request.maximum_response_bytes())
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            let record = self.session.receive_response_packet_with_descriptors(
                maximum.min(HOST_FUSE_WORKER_SESSION_BODY_MAXIMUM_BYTES_V1),
                2,
            );
            self.recheck()?;
            handoff
                .recheck()
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            original.recheck()?;
            match record {
                Ok((frame, descriptors)) => {
                    self.stage = ReplyStage::InFlight;
                    let body = decode(&frame, self.binding, self.request.maximum_response_bytes())?;
                    let request = decode_host_fuse_worker_session_request_v1(
                        self.request.exact_body(),
                        self.request.peer(),
                        self.request.peer_policy(),
                        super::protected_boottime_nanoseconds()?,
                    )
                    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                    let plan = handoff.plan();
                    if request.worker_instance() != plan.worker_instance
                        || request.plan_digest()
                            != plan
                                .digest()
                                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?
                        || request.reservation_commitment() != plan.mount_reservation
                        || *request.fence().assignment_digest() != plan.assignment
                        || self.binding.deadline > plan.preparation_deadline_boottime_ns
                    {
                        return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
                    }
                    let response = decode_host_fuse_worker_session_response_v1(body, &request)
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                    if response.boot_id() != plan.kernel_boot {
                        return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
                    }
                    let [process, cgroup]: [OwnedFd; 2] = descriptors
                        .try_into()
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                    // Kernel shape/membership comparisons do not reconstruct
                    // Host launch, invocation, original FUSE OFD or a lease.
                    let process = PidFd::from_owned(process)
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
                    let cgroup = CgroupV2Root::from_owned(cgroup)
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
                    let returned = cgroup
                        .resolve(Path::new("."))
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
                    let info = returned
                        .verify_exact_membership(&process)
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
                    let root = super::fixed_worker_cgroup_root()?;
                    let relative = response
                        .cgroup()
                        .strip_prefix('/')
                        .ok_or(DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
                    let expected = root
                        .resolve(Path::new(relative))
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
                    if expected.kernel_id() != returned.kernel_id()
                        || info.pid() != response.pid()
                        || info.thread_group_id() != response.pid()
                    {
                        return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
                    }
                    expected
                        .verify_exact_membership(&process)
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
                    self.recheck()?;
                    handoff
                        .recheck()
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                    original.recheck()?;
                    self.stage = ReplyStage::Compared;
                    return Ok(OriginalHostWorkerComparisonV1 {
                        body: body.to_vec(),
                        process,
                        cgroup,
                    });
                }
                Err(TransportError::Transport) => {
                    original.recheck()?;
                    self.wait(false)?;
                    handoff
                        .recheck()
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                    original.recheck()?;
                }
                Err(error) => {
                    self.stage = ReplyStage::ReconciliationRequired;
                    return Err(error.into());
                }
            }
        }
    }

    fn wait(&mut self, write: bool) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.recheck()?;
        let waited = crate::dormant_handshake::wait_for_handshake_readiness(
            self.session.as_fd()?,
            write,
            self.binding.deadline,
        );
        self.recheck()?;
        if waited.is_err() {
            self.stage = ReplyStage::ReconciliationRequired;
        }
        waited
    }

    fn validate_body(&self, body: &[u8]) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        let now = super::protected_boottime_nanoseconds()?;
        let request = decode_host_fuse_worker_session_request_v1(
            self.request.exact_body(),
            self.request.peer(),
            self.request.peer_policy(),
            now,
        )
        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        decode_host_fuse_worker_session_response_v1(body, &request)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        Ok(())
    }
}

fn encode(
    binding: Binding,
    body: &[u8],
    maximum: u32,
) -> Result<Vec<u8>, DormantBrokerSessionHandshakeErrorV1> {
    encode_profile(MAGIC, CONTRACT, binding, body, maximum)
}

// Mechanical fixed-header reuse for the privately enumerated phase profiles.
// No caller-selected contract is exposed through an owner or public transport.
fn encode_profile(
    magic: &[u8; 8],
    contract: &[u8; 18],
    binding: Binding,
    body: &[u8],
    maximum: u32,
) -> Result<Vec<u8>, DormantBrokerSessionHandshakeErrorV1> {
    let size = body
        .len()
        .checked_add(HEADER_BYTES)
        .ok_or(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
    if body.is_empty()
        || size > HOST_FUSE_WORKER_SESSION_BODY_MAXIMUM_BYTES_V1
        || size > maximum as usize
    {
        return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
    }
    let mut frame = Vec::with_capacity(size);
    frame.extend_from_slice(magic);
    frame.extend_from_slice(contract);
    frame.extend_from_slice(&binding.deadline.to_be_bytes());
    frame.extend_from_slice(&binding.request);
    frame.extend_from_slice(&binding.session);
    frame.extend_from_slice(&binding.signed_request);
    frame.extend_from_slice(&binding.semantics);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

fn decode(
    frame: &[u8],
    binding: Binding,
    maximum: u32,
) -> Result<&[u8], DormantBrokerSessionHandshakeErrorV1> {
    if frame.len() <= HEADER_BYTES
        || frame.len() > HOST_FUSE_WORKER_SESSION_BODY_MAXIMUM_BYTES_V1
        || frame.len() > maximum as usize
    {
        return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
    }
    let body = &frame[HEADER_BYTES..];
    if encode(binding, body, maximum)? != frame {
        return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn binding() -> Binding {
        Binding {
            deadline: 100,
            request: [1; 16],
            session: [2; 32],
            signed_request: [3; 32],
            semantics: [4; 32],
        }
    }

    #[test]
    fn comparison_frame_has_a_distinct_nonterminal_exact_contract() {
        // Framing only: these bytes are not a validated Host response or grant.
        let body = b"comparison-only";
        let frame = encode(binding(), body, 4096).unwrap();

        assert_eq!(frame.len(), HEADER_BYTES + body.len());
        assert_eq!(&frame[..8], b"AOSFWR01");
        assert_eq!(&frame[8..26], CONTRACT);
        assert_eq!(decode(&frame, binding(), 4096).unwrap(), body);
        for old_magic in [b"AOSFWH01", b"AOSFWH02", b"AOSFIC01"] {
            let mut substituted = frame.clone();
            substituted[..8].copy_from_slice(old_magic);
            assert!(decode(&substituted, binding(), 4096).is_err());
        }
    }

    #[test]
    fn comparison_frame_rejects_each_original_coordinate_and_role_substitution() {
        let frame = encode(binding(), b"comparison-only", 4096).unwrap();

        for index in [8, 11, 15, 17, 21, 23, 25, 33, 34, 50, 82, 114, 149] {
            let mut substituted = frame.clone();
            substituted[index] ^= 1;
            assert!(
                decode(&substituted, binding(), 4096).is_err(),
                "offset {index}"
            );
        }
        let mut appended = frame.clone();
        appended.push(1);
        assert!(decode(&appended, binding(), 4096).is_err());
        assert!(decode(&frame[..HEADER_BYTES], binding(), 4096).is_err());
    }

    #[test]
    fn comparison_record_respects_the_original_complete_record_ceiling() {
        let body = vec![1; 4096 - HEADER_BYTES];

        assert!(encode(binding(), &body, 4096).is_ok());
        assert!(encode(binding(), &body, 4095).is_err());
        assert!(encode(binding(), &[1; 4096], 8192).is_err());
        assert!(encode(binding(), &[], 4096).is_err());
    }
}
