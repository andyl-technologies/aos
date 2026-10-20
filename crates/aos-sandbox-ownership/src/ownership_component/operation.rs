//! Drives the protected Ownership listener under its sole original F ledger.
//!
//! Socket records, MAC state and the local handler never leave this owner.
//! Positive transient reuse follows actual send/currentness and disposal. A
//! failed connection remains resident with its paid peak; another connection
//! must reserve a distinct peak before querying/resuming the durable intent.

use std::error::Error;
use std::fs::File;
use std::io::Read as _;
use std::mem::size_of;
use std::path::Path;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::credential::{CredentialOwnerPolicyV1, FixedRoleCredentialReadV1};
use aos_sandbox_linux::seqpacket::{LocalOwnershipSeqpacketEndAttemptV1,
    RecordSubjectListener, RecordSubjectListenerAdmissionAttemptV1,
    RetainedSeqpacketAdmissionErrorV1, SeqpacketError, SeqpacketSocket};
use aos_sandbox_ownership_protocol::authority_records::{AuthorityRecordErrorV1, AuthorityRecordStateV1};
use aos_sandbox_ownership_protocol::carrier::{MAXIMUM_OWNERSHIP_HELLO_BYTES, decode_client_hello_v1};
use aos_sandbox_ownership_protocol::protocol::{MAXIMUM_OWNERSHIP_REQUEST_BYTES,
    OwnershipClientHelloV1, OwnershipRequestEnvelopeV1, OwnershipResponseOutcomeV1,
    OwnershipTransactionStatusV1};
use rustix::event::{PollFd, PollFlags, poll};
use zeroize::Zeroizing;

use aos_sandbox_broker::ownership_record_io::{OwnershipRecordIoV1, receive, send};

use super::funding::{OperationPayment, OwnershipOperationFundingLoanV1, grow_peak};
use super::{CLOSED, OwnershipReceivingClosedV1, OwnershipServiceReceivingOriginalV1,
    FixedServiceCurrentnessSampleV1, observe_same_original};

const SOCKET_PATH: &str = "/run/aos/sandbox-ownership/control.sock";
const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-ownershipd.service";
const CREDENTIAL_NAME: &str = "ownership-session-key";
const ARGUMENT_BYTES: usize = 4096 + 2 * 11 + 1;

#[derive(Default)]
pub(super) struct OwnershipServiceOperationsV1 {
    entered: bool,
    pub(super) closed: bool,
    startup: OperationPayment,
    credential: Option<FixedRoleCredentialReadV1>,
    secret: Option<Zeroizing<[u8; 32]>>,
    arguments_file: Option<Result<File, rustix::io::Errno>>,
    arguments: Vec<u8>,
    arguments_read: Option<std::io::Result<usize>>,
    controller: Option<Result<(u32, u32), OwnershipReceivingClosedV1>>,
    admission: Option<RecordSubjectListenerAdmissionAttemptV1>,
    listener: Option<RecordSubjectListener>,
    listener_poll: Option<Result<usize, rustix::io::Errno>>,
    listener_revents: Option<PollFlags>,
    growth: Option<Result<(), std::collections::TryReserveError>>,
    current: Option<Box<Connection>>,
    failed: Vec<Box<Connection>>,
    reusable: ResourceVector,
    before: FixedServiceCurrentnessSampleV1<OwnershipReceivingClosedV1>,
    before_result: Option<Result<(), OwnershipReceivingClosedV1>>,
    after: FixedServiceCurrentnessSampleV1<OwnershipReceivingClosedV1>,
    after_result: Option<Result<(), OwnershipReceivingClosedV1>>,
    prepared: Option<Result<(), OwnershipReceivingClosedV1>>,
}

struct Connection {
    payment: OperationPayment,
    accepted: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    peer: Option<Result<(), OwnershipReceivingClosedV1>>,
    hello: Exchange,
    parsed_hello: Option<Result<OwnershipClientHelloV1, aos_sandbox_ownership_protocol::carrier::OwnershipCarrierErrorV1>>,
    nonce: [u8; 32],
    entropy: Option<Result<usize, rustix::io::Errno>>,
    records: Option<AuthorityRecordStateV1>,
    negotiation: Option<Result<(), AuthorityRecordErrorV1>>,
    handshake: Option<Result<(), OwnershipReceivingClosedV1>>,
    served: Option<Result<(), OwnershipReceivingClosedV1>>,
    request: Option<Box<Request>>,
    ending: Option<LocalOwnershipSeqpacketEndAttemptV1>,
    final_post: FixedServiceCurrentnessSampleV1<OwnershipReceivingClosedV1>,
    final_result: Option<Result<(), OwnershipReceivingClosedV1>>,
}

#[derive(Default)]
struct Exchange {
    before: FixedServiceCurrentnessSampleV1<OwnershipReceivingClosedV1>,
    before_result: Option<Result<(), OwnershipReceivingClosedV1>>,
    io: OwnershipRecordIoV1,
    after: FixedServiceCurrentnessSampleV1<OwnershipReceivingClosedV1>,
    after_result: Option<Result<(), OwnershipReceivingClosedV1>>,
}

#[derive(Default)]
struct Request {
    exchange: Exchange,
    parsed: Option<Result<OwnershipRequestEnvelopeV1, AuthorityRecordErrorV1>>,
    handled: Option<crate::local_ownership::LocalOwnershipProtocolAttemptV1>,
    encoding: Option<Result<(), AuthorityRecordErrorV1>>,
    io_charge: Option<Result<(), OwnershipReceivingClosedV1>>,
    advanced: Option<Result<(), AuthorityRecordErrorV1>>,
    execution: Option<Result<bool, OwnershipReceivingClosedV1>>,
}

impl Connection {
    fn new(peak: ResourceVector, fixed: ResourceVector) -> Self {
        Self {
            payment: OperationPayment::new(peak, fixed),
            accepted: None, peer: None, hello: Default::default(), parsed_hello: None,
            nonce: [0; 32], entropy: None, records: None, negotiation: None, handshake: None, served: None,
            request: None, ending: None, final_post: Default::default(), final_result: None,
        }
    }

    fn socket(&mut self) -> Result<&mut SeqpacketSocket, OwnershipReceivingClosedV1> {
        self.accepted.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.accepted).or_else(|| error(&self.peer))
            .or_else(|| self.hello.early_failure()).or_else(|| error(&self.parsed_hello))
            .or_else(|| error(&self.entropy)).or_else(|| error(&self.negotiation))
            .or_else(|| self.hello.send_failure()).or_else(|| error(&self.handshake))
            .or_else(|| self.hello.post_failure())
            .or_else(|| self.request.as_ref().and_then(|request| request.failure(&self.payment)))
            .or_else(|| self.payment.failure())
            .or_else(|| error(&self.served))
            .or_else(|| self.ending.as_ref().and_then(|ending| ending.failure()))
            .or_else(|| self.final_post.failure()).or_else(|| error(&self.final_result))
    }
}

impl Exchange {
    fn early_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before.failure().or_else(|| error(&self.before_result))
            .or_else(|| self.io.receive_failure())
    }

    fn send_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.io.send_failure()
    }

    fn post_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.after.failure().or_else(|| error(&self.after_result))
    }
}

impl Request {
    fn failure<'a>(&'a self, payment: &'a OperationPayment) -> Option<&'a (dyn Error + 'static)> {
        error(&self.io_charge).or_else(|| self.exchange.early_failure()).or_else(|| error(&self.parsed))
            .or_else(|| payment.failure())
            .or_else(|| self.handled.as_ref().and_then(|attempt| attempt.failure()))
            .or_else(|| error(&self.encoding)).or_else(|| self.exchange.send_failure())
            .or_else(|| error(&self.execution)).or_else(|| self.exchange.post_failure())
            .or_else(|| error(&self.advanced))
    }
}

impl OwnershipServiceReceivingOriginalV1 {
    /// Runs the fixed authenticated service using this same retained original.
    ///
    /// The method adopts only the listener already authenticated by role2 PID1
    /// capture. It loads the fixed MAC credential after admission and dispatches
    /// only records decoded under that credential and exact socket/subject.
    ///
    /// # Errors
    /// Retains startup, funding, native and failed connection originals. A
    /// financial or local journal-integrity refusal permanently closes service.
    pub fn run_local_authority_v1(&mut self) -> Result<(), OwnershipReceivingClosedV1> {
        if self.first.is_some() || !matches!(self.startup, Some(Ok(_)))
            || self.operations.entered || self.operations.closed {
            return Err(self.fail(super::Failure::Operation));
        }
        self.operations.entered = true;
        self.operations.prepared = Some(self.prepare_protocol_once());
        // The before/after samples were admitted as one fixed closed prefix;
        // after is independent even when credentials/listener capture refused.
        if self.operations.before_result.is_some() {
            self.operations.after_result = Some(observe_same_original(&mut self.common, &mut self.operations.after));
        }
        if !matches!(self.operations.prepared, Some(Ok(())))
            || !matches!(self.operations.after_result, Some(Ok(()))) {
            self.operations.closed = true;
            return Err(self.fail(super::Failure::Operation));
        }
        loop {
            if self.next_connection().is_err() {
                self.operations.closed = true;
                return Err(self.fail(super::Failure::Operation));
            }
        }
    }

    fn prepare_protocol_once(&mut self) -> Result<(), OwnershipReceivingClosedV1> {
        // Read this process's selected immutable command through one bounded
        // proc file. Constructing env::args_os would first copy every argument
        // before its count could be checked. No arbitrary argv grows here.
        let joined_path = FixedRoleCredentialReadV1::joined_path_receiving_bytes_v1(
            Path::new(CREDENTIAL_DIRECTORY), CREDENTIAL_NAME,
        ).ok_or(CLOSED)?;
        let memory = ARGUMENT_BYTES.checked_mul(2)
            .and_then(|bytes| bytes.checked_add(32 + 80 + 4096))
            .and_then(|bytes| bytes.checked_add(joined_path)).ok_or(CLOSED)?;
        let sample = FixedServiceCurrentnessSampleV1::<OwnershipReceivingClosedV1>::dynamic_demand().map_err(|_| CLOSED)?;
        let fixed = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| CLOSED)?)
            .with(D::OpenFiles, 2).with(D::MetadataEntries, 2)
            .checked_add(sample).and_then(|bound| bound.checked_add(sample)).map_err(|_| CLOSED)?;
        grow_peak(&mut self.common, &mut self.descriptor_bound, &mut self.descriptor_refusal,
            &mut self.operations.startup, fixed)?;
        self.operations.before_result = Some(observe_same_original(&mut self.common, &mut self.operations.before));
        self.operations.before_result.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        self.operations.arguments_file = Some(rustix::fs::open("/proc/self/cmdline",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty()).map(File::from));
        let file = self.operations.arguments_file.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
        self.operations.arguments = Vec::with_capacity(ARGUMENT_BYTES);
        self.operations.arguments_read = Some(file.take(ARGUMENT_BYTES as u64)
            .read_to_end(&mut self.operations.arguments));
        self.operations.controller = Some((|| {
            self.operations.arguments_read.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
            let bytes = self.operations.arguments.as_slice();
            if bytes.len() >= ARGUMENT_BYTES || !bytes.ends_with(&[0]) { return Err(CLOSED); }
            let mut values = bytes[..bytes.len() - 1].split(|byte| *byte == 0);
            let executable = values.next().ok_or(CLOSED)?;
            if executable.is_empty() || executable.len() > 4096 { return Err(CLOSED); }
            let parse = |bytes: &[u8]| {
                if bytes.is_empty() || bytes.len() > 10 || !bytes.iter().all(u8::is_ascii_digit) {
                    return Err(CLOSED);
                }
                std::str::from_utf8(bytes).map_err(|_| CLOSED)?.parse::<u32>().map_err(|_| CLOSED)
            };
            let uid = parse(values.next().ok_or(CLOSED)?)?;
            let gid = parse(values.next().ok_or(CLOSED)?)?;
            if values.next().is_some() { return Err(CLOSED); }
            Ok((uid, gid))
        })());
        self.operations.controller.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        self.operations.credential = Some(FixedRoleCredentialReadV1::prearmed());
        let credential = self.operations.credential.as_mut().ok_or(CLOSED)?;
        credential.read_once(Path::new(CREDENTIAL_DIRECTORY), CREDENTIAL_NAME, 32, 32,
            true, CredentialOwnerPolicyV1::Root);
        let bytes = match credential.outcome() { Some(Ok(Some(bytes))) => bytes, _ => return Err(CLOSED) };
        let secret: [u8; 32] = bytes.as_slice().try_into().map_err(|_| CLOSED)?;
        if secret == [0; 32] { return Err(CLOSED); }
        self.operations.secret = Some(Zeroizing::new(secret));

        let original = self.common.root_profile.take().ok_or(CLOSED)?;
        self.operations.admission = Some(RecordSubjectListenerAdmissionAttemptV1::new(original.into()));
        let admission = self.operations.admission.as_mut().ok_or(CLOSED)?;
        admission.admit_once(Path::new(SOCKET_PATH)).map_err(|_| CLOSED)?;
        self.operations.listener = admission.take_completed_listener();
        self.operations.listener.as_ref().ok_or(CLOSED)?;
        Ok(())
    }

    fn next_connection(&mut self) -> Result<(), OwnershipReceivingClosedV1> {
        let required = connection_demand(self.operations.failed.len().checked_add(1).ok_or(CLOSED)?)?;
        let mut payment = OperationPayment::new(self.operations.reusable, required);
        grow_peak(&mut self.common, &mut self.descriptor_bound, &mut self.descriptor_refusal,
            &mut payment, required)?;
        self.operations.growth = Some(self.operations.failed.try_reserve_exact(1));
        if !matches!(self.operations.growth, Some(Ok(()))) { return Err(CLOSED); }
        self.operations.current = Some(Box::new(Connection::new(payment.peak, required)));
        // Handshake traffic is a consumed byte obligation, never reusable
        // scratch or credit inferred from closing a connection.
        self.common.representation.as_mut().ok_or(CLOSED)?.reserve(ResourceVector::ZERO
            .with(D::NetworkBytes, (2 * MAXIMUM_OWNERSHIP_HELLO_BYTES) as u64)
            .with(D::OutputBytes, MAXIMUM_OWNERSHIP_HELLO_BYTES as u64)).map_err(|_| CLOSED)?;
        loop {
            let accepted = self.operations.listener.as_mut().ok_or(CLOSED)?.accept_retaining();
            if matches!(&accepted, Err(error) if !error.retains_descriptor()
                && matches!(error.cause(), SeqpacketError::WouldBlock | SeqpacketError::Interrupted)) {
                // The actual no-acquisition attempt is complete and disposed;
                // the paid fixed accept peak can be reused for the next wait.
                drop(accepted);
                let listener = self.operations.listener.as_ref().ok_or(CLOSED)?;
                let mut descriptors = [PollFd::from_borrowed_fd(listener.as_fd(), PollFlags::IN)];
                self.operations.listener_poll = Some(poll(&mut descriptors, None));
                self.operations.listener_revents = Some(descriptors[0].revents());
                match self.operations.listener_poll.as_ref() {
                    Some(Ok(_)) if descriptors[0].revents().contains(PollFlags::IN) => continue,
                    Some(Err(rustix::io::Errno::INTR)) => continue,
                    _ => return Err(CLOSED),
                }
            }
            self.operations.current.as_mut().ok_or(CLOSED)?.accepted = Some(accepted);
            break;
        }
        let mut current = self.operations.current.take().ok_or(CLOSED)?;
        let result = self.serve_connection(&mut current);
        current.served = Some(result);
        // End the same accepted endpoint and observe the service independently
        // on every entered outcome, including MAC, native, send and late errors.
        if let Some(Ok(socket)) = current.accepted.as_mut() {
            current.ending = Some(socket.end_local_ownership_session_retaining_v1());
        }
        current.final_result = Some(observe_same_original(&mut self.common, &mut current.final_post));
        let positive = matches!(current.served, Some(Ok(()))) && current.ending.as_ref().is_some_and(|ending| ending.is_complete())
            && matches!(current.final_result, Some(Ok(())));
        let own_currentness_failed = [&current.hello.before_result, &current.hello.after_result, &current.final_result]
            .into_iter().any(|slot| matches!(slot, Some(Err(_))))
            || current.request.as_ref().is_some_and(|request| {
                [&request.exchange.before_result, &request.exchange.after_result]
                    .into_iter().any(|slot| matches!(slot, Some(Err(_))))
            });
        self.operations.current = Some(current);
        let current = self.operations.current.as_ref().ok_or(CLOSED)?;
        let financial_closed = current.payment.closed || self.common.representation.as_ref()
            .is_none_or(|ledger| ledger.failure().is_some());
        let native_closed = self.startup.as_ref().and_then(|result| result.as_ref().ok())
            .is_none_or(|owner| owner.retained_failure().is_some());
        if positive {
            // serve_connection ended the actual socket and completed all posts.
            // Dispose its complete positive originals before publishing reuse.
            let peak = current.payment.peak;
            drop(self.operations.current.take());
            self.operations.reusable = peak;
        } else {
            // The same paid peak now belongs permanently to this retained
            // failed lane. A later accept cannot reuse it or its originals.
            let failed = self.operations.current.take().ok_or(CLOSED)?;
            self.operations.failed.push(failed);
            self.operations.reusable = ResourceVector::ZERO;
        }
        if financial_closed || native_closed || own_currentness_failed { Err(CLOSED) } else { Ok(()) }
    }

    fn serve_connection(&mut self, current: &mut Connection) -> Result<(), OwnershipReceivingClosedV1> {
        let (uid, gid) = self.operations.controller.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(CLOSED)?;
        current.peer = Some((|| {
            let peer = current.socket()?.peer().credentials();
            if peer.uid() == uid && peer.gid() == gid { Ok(()) } else { Err(CLOSED) }
        })());
        current.peer.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        current.hello.io.arm_deadline_once().map_err(|_| CLOSED)?;
        current.hello.before_result = Some(observe_same_original(&mut self.common, &mut current.hello.before));
        current.handshake = Some((|| {
            current.hello.before_result.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
            let socket = current.accepted.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
            receive(socket, &mut current.hello.io, MAXIMUM_OWNERSHIP_HELLO_BYTES, uid, gid).map_err(|_| CLOSED)?;
            let record = current.hello.io.received.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
            current.parsed_hello = Some(decode_client_hello_v1(record.payload()));
            let hello = current.parsed_hello.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
            current.entropy = Some(rustix::rand::getrandom(&mut current.nonce, rustix::rand::GetRandomFlags::empty()));
            if !matches!(current.entropy, Some(Ok(32))) || current.nonce == [0; 32] { return Err(CLOSED); }
            let owner = self.startup.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
            let negotiated = AuthorityRecordStateV1::negotiate(hello, current.nonce, owner.authority().clone(),
                self.operations.secret.as_ref().ok_or(CLOSED)?.clone());
            match negotiated {
                Ok((records, outgoing)) => {
                    current.records = Some(records);
                    current.hello.io.outgoing = Some(outgoing);
                    current.negotiation = Some(Ok(()));
                }
                Err(cause) => { current.negotiation = Some(Err(cause)); return Err(CLOSED); }
            }
            send(socket, &mut current.hello.io).map_err(|_| CLOSED)?;
            Ok(())
        })());
        current.hello.after_result = Some(observe_same_original(&mut self.common, &mut current.hello.after));
        current.handshake.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        current.hello.after_result.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        // The positive HELLO carries no lasting domain effect. All its actual
        // records/native samples are disposed before the request peak is reused.
        current.hello = Exchange::default();
        current.parsed_hello = None;
        loop {
            current.records.as_ref().ok_or(CLOSED)?.require_request_slot().map_err(|_| CLOSED)?;
            current.request = Some(Box::new(Request::default()));
            let bytes = crate::local_ownership::request_io_demand_v1().ok_or(CLOSED)?;
            let charge = self.common.representation.as_mut().ok_or(CLOSED)?.reserve(bytes).map_err(|_| CLOSED);
            current.request.as_mut().ok_or(CLOSED)?.io_charge = Some(charge);
            current.request.as_ref().and_then(|request| request.io_charge.as_ref())
                .and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
            let result = self.serve_request(current, uid, gid);
            if result.is_err() { return Err(CLOSED); }
            let terminal = result?;
            if self.startup.as_ref().and_then(|result| result.as_ref().ok())
                .is_none_or(|owner| owner.retained_failure().is_some()) { return Err(CLOSED); }
            // Only successful send, native/domain publication and all same-
            // original posts reach here. Preserve the charged highwater while
            // disposing the actual positive transient request and demand rows.
            drop(current.request.take());
            let peak = current.payment.peak;
            current.payment = OperationPayment::new(peak, current.payment.fixed);
            if terminal { break; }
        }
        Ok(())
    }

    fn serve_request(&mut self, current: &mut Connection, uid: u32, gid: u32) -> Result<bool, OwnershipReceivingClosedV1> {
        let request = current.request.as_mut().ok_or(CLOSED)?;
        request.exchange.io.arm_deadline_once().map_err(|_| CLOSED)?;
        request.exchange.before_result = Some(observe_same_original(&mut self.common, &mut request.exchange.before));
        let result = if matches!(request.exchange.before_result, Some(Ok(()))) {
            self.serve_request_body(current, uid, gid)
        } else { Err(CLOSED) };
        let request = current.request.as_mut().ok_or(CLOSED)?;
        request.execution = Some(result);
        request.exchange.after_result = Some(observe_same_original(&mut self.common, &mut request.exchange.after));
        let terminal = request.execution.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
        request.exchange.after_result.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        request.advanced = Some(current.records.as_mut().ok_or(CLOSED)?.response_sent());
        request.advanced.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        Ok(terminal)
    }

    fn serve_request_body(&mut self, current: &mut Connection, uid: u32, gid: u32) -> Result<bool, OwnershipReceivingClosedV1> {
        let socket = current.accepted.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
        let request = current.request.as_mut().ok_or(CLOSED)?;
        receive(socket, &mut request.exchange.io, MAXIMUM_OWNERSHIP_REQUEST_BYTES as usize, uid, gid).map_err(|_| CLOSED)?;
        let record = request.exchange.io.received.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        let records = current.records.as_mut().ok_or(CLOSED)?;
        request.parsed = Some(records.open_request(record.payload()));
        let parsed = request.parsed.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        let owner = self.startup.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
        let mut funding = OwnershipOperationFundingLoanV1 {
            common: &mut self.common, opening: &self.opening,
            descriptor_bound: &mut self.descriptor_bound,
            descriptor_refusal: &mut self.descriptor_refusal, payment: &mut current.payment,
        };
        request.handled = Some(owner.handle_paid_v1(&mut funding, records.session(), parsed));
        // A refusal is retained before any response can mask its payer/native
        // cause. The durable intent, if committed, remains queryable on reopen.
        if funding.payment.closed { return Err(CLOSED); }
        let response = request.handled.as_ref().and_then(|attempt| attempt.response.as_ref())
            .and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        let terminal = matches!(response.outcome(), OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Completed(_)));
        match records.encode_response(parsed, response) {
            Ok(bytes) => { request.exchange.io.outgoing = Some(bytes); request.encoding = Some(Ok(())); }
            Err(cause) => { request.encoding = Some(Err(cause)); return Err(CLOSED); }
        }
        send(socket, &mut request.exchange.io).map_err(|_| CLOSED)?;
        Ok(terminal)
    }
}

fn connection_demand(failure_slots: usize) -> Result<ResourceVector, OwnershipReceivingClosedV1> {
    let request = crate::local_ownership::fixed_request_demand_v1().ok_or(CLOSED)?;
    let (receive_bytes, receive_fds) = SeqpacketSocket::local_ownership_receive_obligations_v1(
        MAXIMUM_OWNERSHIP_REQUEST_BYTES as usize).ok_or(CLOSED)?;
    let (accept_bytes, accept_fds) = SeqpacketSocket::retained_accept_obligations_v1();
    let sample = FixedServiceCurrentnessSampleV1::<OwnershipReceivingClosedV1>::dynamic_demand().map_err(|_| CLOSED)?;
    let memory = size_of::<Connection>().checked_add(size_of::<Request>())
        .and_then(|bytes| bytes.checked_add(receive_bytes))
        .and_then(|bytes| bytes.checked_add(accept_bytes))
        .and_then(|bytes| bytes.checked_add(failure_slots.checked_mul(size_of::<Box<Connection>>())?))
        .and_then(|bytes| bytes.checked_add(MAXIMUM_OWNERSHIP_HELLO_BYTES.checked_mul(4)?)).ok_or(CLOSED)?;
    let native = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| CLOSED)?)
        .with(D::OpenFiles, u64::try_from(receive_fds.checked_add(accept_fds).ok_or(CLOSED)?).map_err(|_| CLOSED)?)
        .with(D::MetadataEntries, 3);
    // On a failed request its two samples remain beside the independent final
    // socket-ending post. All three peaks are paid before the first receive.
    request.checked_add(native).and_then(|bound| bound.checked_add(sample))
        .and_then(|bound| bound.checked_add(sample))
        .and_then(|bound| bound.checked_add(sample)).map_err(|_| CLOSED)
}


impl OwnershipServiceOperationsV1 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.startup.refusal.as_ref().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.before.failure()).or_else(|| error(&self.before_result))
            .or_else(|| error(&self.arguments_file)).or_else(|| error(&self.arguments_read))
            .or_else(|| error(&self.controller))
            .or_else(|| self.credential.as_ref().and_then(|read| read.failure()))
            .or_else(|| self.admission.as_ref().and_then(|admission| match admission.first_failure() {
                Some(aos_sandbox_linux::seqpacket::ListenerAdmissionFailureRefV1::Cause(cause)) => Some(cause as &(dyn Error + 'static)),
                _ => None,
            }))
            .or_else(|| error(&self.prepared))
            .or_else(|| self.after.failure()).or_else(|| error(&self.after_result))
            .or_else(|| error(&self.listener_poll))
            .or_else(|| error(&self.growth))
            .or_else(|| self.current.as_ref().and_then(|current| current.failure()))
            .or_else(|| self.failed.iter().find_map(|current| current.failure()))
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use aos_sandbox_broker::ownership_record_io::TIMEOUT;

    #[test]
    fn actual_send_timeout_precedes_independent_request_post() {
        let (mut socket, _endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut request = Request::default();
        request.exchange.io.receive_wait.outcome = Some(Ok(()));
        request.exchange.io.received_timely = Some(Ok(()));

        request.exchange.io.deadline = Some(Instant::now());
        request.exchange.io.outgoing = Some(vec![0]);
        assert!(send(&mut socket, &mut request.exchange.io).is_err());
        request.execution = Some(Err(CLOSED));
        request.exchange.after_result = Some(Err(CLOSED));

        let payment = OperationPayment::default();
        let first = request.failure(&payment).unwrap()
            .downcast_ref::<aos_sandbox_broker::ownership_record_io::OwnershipRecordIoClosedV1>().unwrap();
        let timeout = error(&request.exchange.io.send_wait.outcome).unwrap()
            .downcast_ref::<aos_sandbox_broker::ownership_record_io::OwnershipRecordIoClosedV1>().unwrap();
        assert!(std::ptr::eq(first, timeout));
        assert!(request.exchange.io.send_wait.poll.is_none());
    }

    #[test]
    fn actual_closed_socket_source_precedes_handshake_and_post_markers() {
        let (mut socket, _endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        socket.close();
        let mut connection = Connection::new(ResourceVector::ZERO, ResourceVector::ZERO);

        connection.hello.io.deadline = Some(Instant::now() + TIMEOUT);
        connection.hello.io.outgoing = Some(vec![0]);
        assert!(send(&mut socket, &mut connection.hello.io).is_err());
        connection.handshake = Some(Err(CLOSED));
        connection.hello.after_result = Some(Err(CLOSED));

        let first = connection.failure().unwrap();
        assert!(first.downcast_ref::<SeqpacketError>().is_some());
        assert!(connection.hello.io.send_wait.outcome.as_ref().unwrap().is_err());
    }
}

use aos_sandbox_broker::receiving::RepresentationDemandDebitV1;
