//! Retains the actual fixed SSH child's private listener-bootstrap channel.
//!
//! This native original creates its own pair. Only the parent endpoint enables
//! record subjects; the child's stdin keeps the C provider's zero-ancillary
//! request and ACK grammar. No external socket, listener or PID is adopted.

use super::*;
use crate::guest_cgroup::GuestSshScopeOriginalV1;
use crate::process::FixedProcessCaptureCutV3;
use crate::process::capture_cut::CaptureProcessCutOriginalV3;
use crate::{Error, Result as NativeResult};

mod listeners;

pub use listeners::GuestSshListenerCustodyV1;

#[derive(Default)]
struct ListenerOriginal {
    accepting: Option<rustix::io::Result<bool>>,
    kind: Option<rustix::io::Result<rustix::net::SocketType>>,
    protocol: Option<rustix::io::Result<Option<rustix::net::Protocol>>>,
    address: Option<rustix::io::Result<rustix::net::SocketAddrAny>>,
    cookie: Option<NativeResult<u64>>,
}

impl ListenerOriginal {
    fn capture(
        &mut self,
        fd: BorrowedFd<'_>,
        port: u16,
        cookie: u64,
    ) -> NativeResult<rustix::net::AddressFamily> {
        self.accepting = Some(rustix::net::sockopt::socket_acceptconn(fd));
        self.kind = Some(rustix::net::sockopt::socket_type(fd));
        self.protocol = Some(rustix::net::sockopt::socket_protocol(fd));
        self.address = Some(rustix::net::getsockname(fd));
        self.cookie = Some(uapi::socket_cookie(fd));
        if !matches!(self.accepting, Some(Ok(true)))
            || !matches!(self.kind, Some(Ok(rustix::net::SocketType::STREAM)))
            || !matches!(self.protocol, Some(Ok(Some(rustix::net::ipproto::TCP))))
            || !matches!(self.cookie, Some(Ok(value)) if value != 0 && value == cookie)
        {
            return Err(closed());
        }
        let address = self
            .address
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(closed)?;
        match address.address_family() {
            rustix::net::AddressFamily::INET => {
                let address =
                    rustix::net::SocketAddrV4::try_from(address.clone()).map_err(|_| closed())?;
                if !address.ip().is_unspecified() || address.port() != port {
                    return Err(closed());
                }
            }
            rustix::net::AddressFamily::INET6 => {
                let address =
                    rustix::net::SocketAddrV6::try_from(address.clone()).map_err(|_| closed())?;
                if !address.ip().is_unspecified() || address.port() != port {
                    return Err(closed());
                }
            }
            _ => return Err(closed()),
        }
        Ok(address.address_family())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.accepting
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.kind.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.protocol
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.address
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.cookie.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

/// Keeps one actual SSH pair, original listener receipt and release boundary.
///
/// Construction is inert. A genuine selected Guest execution independently
/// prepays this source and the complete child source before native entry. The
/// fixed plan bytes are comparison DATA, never a financial or native grant.
/// Every failed prefix remains on this original and its same scope owner.
pub struct GuestSshBootstrapOriginalV1 {
    anchor: Option<std::sync::Arc<crate::cgroup::RetainedCgroupAnchor>>,
    plan: [u8; 144],
    port: u16,
    cut: Option<FixedProcessCaptureCutV3>,
    clock: CaptureProcessCutOriginalV3,
    after_clock: CaptureProcessCutOriginalV3,
    pair: Option<NativeResult<()>>,
    child_endpoint: Option<OwnedFd>,
    parent: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    cookies: [Option<NativeResult<u64>>; 2],
    request: [u8; 192],
    request_send: Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
    request_gate_failure: Option<Error>,
    prepare: Option<NativeResult<()>>,
    prepare_after: Option<NativeResult<std::time::Duration>>,
    spawned: Option<NativeResult<()>>,
    receipt: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    child_info: Option<NativeResult<crate::pidfd::PidFdInfo>>,
    subject_info: Option<NativeResult<crate::pidfd::PidFdInfo>>,
    listeners: [ListenerOriginal; 2],
    verified: Option<NativeResult<()>>,
    verified_after: Option<NativeResult<std::time::Duration>>,
    ack: [u8; 40],
    ack_send: Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
    ack_gate_failure: Option<Error>,
    ack_after: Option<NativeResult<std::time::Duration>>,
    eof: Option<std::result::Result<usize, uapi::RawReceiveFailureV1>>,
    eof_native: uapi::RawReceiveObservationV1,
    eof_byte: [u8; 1],
    alive: Option<NativeResult<bool>>,
    completion_after: Option<NativeResult<std::time::Duration>>,
    operation_after: Option<NativeResult<std::time::Duration>>,
    failure: Option<Error>,
    completed: bool,
    listeners_taken: bool,
}

impl Default for GuestSshBootstrapOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestSshBootstrapOriginalV1 {
    /// Creates fixed empty destinations without allocating or entering IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            anchor: None,
            plan: [0; 144],
            port: 0,
            cut: None,
            clock: Default::default(),
            after_clock: Default::default(),
            pair: None,
            child_endpoint: None,
            parent: None,
            cookies: [None, None],
            request: [0; 192],
            request_send: None,
            request_gate_failure: None,
            prepare: None,
            prepare_after: None,
            spawned: None,
            receipt: None,
            child_info: None,
            subject_info: None,
            listeners: std::array::from_fn(|_| ListenerOriginal::default()),
            verified: None,
            verified_after: None,
            ack: [0; 40],
            ack_send: None,
            ack_gate_failure: None,
            ack_after: None,
            eof: None,
            eof_native: uapi::RawReceiveObservationV1::with_control(uapi::ReceiveControlProfileV1::ZeroAncillary),
            eof_byte: [0],
            alive: None,
            completion_after: None,
            operation_after: None,
            failure: None,
            completed: false,
            listeners_taken: false,
        }
    }

    /// Creates the private pair and queues its exact fixed bootstrap request.
    ///
    /// The plan's execution and enforced limits must match the same prepared
    /// scope. Correlation uses the two actual fresh socket cookies, without a
    /// new random reader or a caller-supplied nonce. Native sends use the sole
    /// existing retained descriptor-channel sender and original-cut gate.
    ///
    /// # Errors
    /// Retains repeated entry, foreign plan/scope, pair/admission/send refusal
    /// and the independently owed cutoff sample. No child starts on refusal.
    pub fn prepare_once_v1(
        &mut self,
        scope: &GuestSshScopeOriginalV1,
        plan: &[u8; 144],
        port: u16,
    ) -> NativeResult<()> {
        if self.prepare.is_some() || self.parent.is_some() {
            self.refuse();
            return Err(closed());
        }
        self.prepare = Some(self.prepare_inner(scope, plan, port));
        if let Some(cut) = self.cut {
            self.prepare_after = Some(self.after_clock.observe(cut));
        }
        if !matches!(self.prepare, Some(Ok(()))) || !matches!(self.prepare_after, Some(Ok(_))) {
            self.refuse();
            return Err(closed());
        }
        Ok(())
    }

    fn prepare_inner(
        &mut self,
        scope: &GuestSshScopeOriginalV1,
        plan: &[u8; 144],
        port: u16,
    ) -> NativeResult<()> {
        scope.require_bootstrap_plan_v1(plan)?;
        if port == 0 {
            return Err(closed());
        }
        self.anchor = Some(std::sync::Arc::clone(scope.bootstrap_anchor_v1()?));
        self.plan = *plan;
        self.port = port;
        let (deadline, wall) = scope.bootstrap_horizon_v1();
        let cut = FixedProcessCaptureCutV3::new(deadline, wall)?;
        self.cut = Some(cut);
        self.clock.observe(cut)?;
        match uapi::seqpacket_pair() {
            Ok((parent, child)) => {
                // Both descriptors have owning destinations before admission
                // can fail. Subject options are enabled only on the parent.
                self.child_endpoint = Some(child);
                self.parent = Some(DescriptorSubjectSocket::from_pending_retaining_raw_v2(
                    PendingSocketAdmissionV1::new(parent),
                ));
                self.pair = Some(Ok(()));
            }
            Err(cause) => {
                self.pair = Some(Err(cause));
                return Err(closed());
            }
        }
        let parent = self
            .parent
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(closed)?;
        let parent_fd = parent.fd.as_ref().ok_or_else(closed)?;
        self.cookies[0] = Some(uapi::socket_cookie(parent_fd.as_fd()));
        self.cookies[1] = Some(uapi::socket_cookie(
            self.child_endpoint.as_ref().ok_or_else(closed)?.as_fd(),
        ));
        self.request[..8].copy_from_slice(b"AOSSLB01");
        self.request[8..152].copy_from_slice(plan);
        self.request[152..160].copy_from_slice(&deadline.to_be_bytes());
        self.request[160..168].copy_from_slice(&wall.to_be_bytes());
        self.request[168..170].copy_from_slice(&port.to_be_bytes());
        for index in 0..2 {
            let cookie = self.cookies[index]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .filter(|value| *value != 0)
                .ok_or_else(closed)?;
            self.request[176 + 8 * index..184 + 8 * index].copy_from_slice(&cookie.to_be_bytes());
        }
        let parent = self
            .parent
            .as_mut()
            .and_then(|value| value.as_mut().ok())
            .ok_or_else(closed)?;
        let clock = &mut self.clock;
        let mut gate = || clock.observe(cut).map(|_| ());
        let (send, failure) =
            parent.send_worker_record_with_gate_v4(&self.request, &[], Some(&mut gate));
        self.request_send = Some(send);
        self.request_gate_failure = failure;
        if !self.request_send.as_ref().is_some_and(|value| {
            value
                .as_ref()
                .is_ok_and(DescriptorWorkerNativeSendAttemptV1::is_sent)
        }) {
            self.refuse();
            return Err(closed());
        }
        Ok(())
    }

    /// Starts only this scope's fixed helper with its actual child endpoint.
    ///
    /// # Errors
    /// Retains a foreign scope, incomplete request, repeated spawn or actual
    /// child failure. The matching scope separately retains every birth owner.
    pub fn spawn_once_v1(&mut self, scope: &mut GuestSshScopeOriginalV1) -> NativeResult<()> {
        if self.spawned.is_some()
            || self.failure.is_some()
            || !matches!(self.prepare, Some(Ok(())))
            || !self.same_scope(scope)
        {
            self.refuse();
            return Err(closed());
        }
        let input = self.child_endpoint.as_ref().ok_or_else(closed)?;
        self.spawned = Some(scope.spawn_helper_once_v1(input.as_fd()));
        if !matches!(self.spawned, Some(Ok(()))) {
            self.refuse();
            return Err(closed());
        }
        // Only complete native birth and its actual after permit this parent
        // copy to close. EOF can then originate only from the actual child.
        drop(self.child_endpoint.take());
        Ok(())
    }

    fn same_scope(&self, scope: &GuestSshScopeOriginalV1) -> bool {
        match (self.anchor.as_ref(), scope.bootstrap_anchor_v1()) {
            (Some(actual), Ok(expected)) => {
                std::sync::Arc::ptr_eq(actual, expected)
                    && scope.require_bootstrap_plan_v1(&self.plan).is_ok()
            }
            _ => false,
        }
    }

    /// Advances the original listener receipt, release ACK and physical EOF.
    ///
    /// The same retained80 receive kernel owns every preview/consume prefix.
    /// A complete initial EAGAIN is pending only after its independent clock
    /// post succeeds. The same original cutoff applies on every later call;
    /// there is no new retry window or accumulating native destination.
    ///
    /// The ACK is sent once. Completion additionally requires actual EOF on
    /// this private pair, a still-live same child and the independent after.
    /// No socket/pipe EOF is interpreted as recursive-empty or process reap.
    ///
    /// # Errors
    /// Retains foreign scope, malformed/foreign receipt, listener or subject
    /// native refusal, failed send, exited child or uncertain after. Errors
    /// are sticky; later observations cannot publish success from this prefix.
    pub fn advance_once_v1(&mut self, scope: &GuestSshScopeOriginalV1) -> NativeResult<bool> {
        if self.failure.is_some() {
            return Err(closed());
        }
        if !matches!(self.spawned, Some(Ok(()))) || !self.same_scope(scope) {
            self.refuse();
            return Err(closed());
        }
        if self.completed {
            return Ok(true);
        }
        let result = self.advance_inner(scope);
        // This independent owner still samples after an early primary-clock
        // or pre-receive refusal. No `?` inside the native phase can suppress
        // the actual operation's owed BOOTTIME/WALL boundary.
        self.operation_after = self.cut.map(|cut| self.after_clock.observe(cut));
        if result.is_err() || !matches!(self.operation_after, Some(Ok(_))) {
            self.completed = false;
            self.refuse();
            return Err(closed());
        }
        result
    }

    fn advance_inner(&mut self, scope: &GuestSshScopeOriginalV1) -> NativeResult<bool> {
        let cut = self.cut.ok_or_else(closed)?;
        if self.verified.is_none() {
            self.clock.observe(cut)?;
            let cutoff = self.clock.retained_native_cutoff_v1(cut)?;
            let parent = self
                .parent
                .as_mut()
                .and_then(|value| value.as_mut().ok())
                .ok_or_else(closed)?;
            self.receipt = Some(parent.receive_guest_ssh_listeners_retaining_v1(cutoff));
            self.verified_after = Some(self.after_clock.observe(cut));
            if !matches!(self.verified_after, Some(Ok(_))) {
                return Err(closed());
            }
            match self.receipt.as_ref() {
                Some(Err(cause))
                    if cause.is_nonconsuming_would_block()
                        || cause.is_nonconsuming_interrupted() =>
                {
                    return Ok(false);
                }
                Some(Ok(_)) => {}
                _ => return Err(closed()),
            }
            self.verified = Some(self.verify_receipt(scope));
            // Subject/listener native observations have their own post after
            // their original results have reached retained destinations.
            self.verified_after = Some(self.after_clock.observe(cut));
            if !matches!(self.verified, Some(Ok(()))) || !matches!(self.verified_after, Some(Ok(_)))
            {
                return Err(closed());
            }
        }

        if self.ack_send.is_none() {
            self.ack[..8].copy_from_slice(b"AOSSLA01");
            self.ack[8..24].copy_from_slice(&self.plan[72..88]);
            self.ack[24..40].copy_from_slice(&self.request[176..192]);
            let parent = self
                .parent
                .as_mut()
                .and_then(|value| value.as_mut().ok())
                .ok_or_else(closed)?;
            let clock = &mut self.clock;
            let mut gate = || clock.observe(cut).map(|_| ());
            let (send, failure) =
                parent.send_worker_record_with_gate_v4(&self.ack, &[], Some(&mut gate));
            self.ack_send = Some(send);
            self.ack_gate_failure = failure;
            self.ack_after = Some(self.after_clock.observe(cut));
            if !self.ack_send.as_ref().is_some_and(|value| {
                value
                    .as_ref()
                    .is_ok_and(DescriptorWorkerNativeSendAttemptV1::is_sent)
            }) || !matches!(self.ack_after, Some(Ok(_)))
            {
                return Err(closed());
            }
        }

        self.clock.observe(cut)?;
        let parent = self
            .parent
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(closed)?;
        let fd = parent.fd.as_ref().ok_or_else(closed)?;
        // This zero-ancillary peek cannot create a rights reservoir. Positive
        // one-byte data is refusal, not a drained receipt or a new packet.
        self.eof = Some(uapi::recv_seqpacket_staged(
            fd.as_fd(),
            &mut self.eof_byte,
            libc::MSG_PEEK,
            &mut self.eof_native,
            uapi::ReceiveCustodyPolicyV1::Retaining,
        ));
        self.alive = Some(scope.child_pidfd_v1()?.is_alive());
        self.completion_after = Some(self.after_clock.observe(cut));
        if !matches!(self.completion_after, Some(Ok(_))) || !matches!(self.alive, Some(Ok(true))) {
            return Err(closed());
        }
        match self.eof.as_ref() {
            Some(Ok(0)) if self.eof_native.received && self.eof_native.used == 0
                && self.eof_native.flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC | libc::MSG_EOR) == 0
                && self.eof_native.ancillary.is_empty() => self.completed = true,
            Some(Err(cause)) if eof_pending(cause) => {}
            _ => return Err(closed()),
        }
        Ok(self.completed)
    }

    fn verify_receipt(&mut self, scope: &GuestSshScopeOriginalV1) -> NativeResult<()> {
        let record = self
            .receipt
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(closed)?;
        let parent = self
            .parent
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(closed)?;
        record
            .require_origin(parent.peer.binding)
            .map_err(|_| closed())?;
        let bytes = record.payload();
        if bytes.len() != 88
            || &bytes[..8] != b"AOSSLR01"
            || bytes[8..24] != self.plan[72..88]
            || bytes[24..40] != self.request[176..192]
            || bytes[41..48] != [0; 7]
            || bytes[68..72] != [0; 4]
            || bytes[72..80] != self.plan[120..128]
            || bytes[80..84] != self.plan[132..136]
            || bytes[84..88] != self.plan[128..132]
        {
            return Err(closed());
        }
        let count = usize::from(bytes[40]);
        if !(1..=2).contains(&count)
            || record.descriptors().len() != count
            || (count == 1 && bytes[56..64] != [0; 8])
        {
            return Err(closed());
        }
        let child = scope.child_id_data_v1().ok_or_else(closed)?;
        if bytes[64..68] != child.to_be_bytes()
            || record.subject().credentials().pid().get() != child
            || record.subject().credentials().uid() != 0
        {
            return Err(closed());
        }
        self.child_info = Some(scope.child_pidfd_v1()?.info());
        self.subject_info = Some(record.subject().pidfd().info());
        let actual = self
            .child_info
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(closed)?;
        let subject = self
            .subject_info
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(closed)?;
        if actual != subject
            || actual.pid() != child
            || actual.thread_group_id() != child
            || actual.parent_pid() != std::process::id()
            || actual.cgroup_id() != Some(scope.bootstrap_anchor_v1()?.kernel_id())
        {
            return Err(closed());
        }
        let mut family = None;
        let mut previous_cookie = None;
        for index in 0..count {
            let cookie = u64::from_be_bytes(
                bytes[48 + 8 * index..56 + 8 * index]
                    .try_into()
                    .map_err(|_| closed())?,
            );
            if previous_cookie == Some(cookie) {
                return Err(closed());
            }
            let actual = self.listeners[index].capture(
                record.descriptors()[index].as_fd(),
                self.port,
                cookie,
            )?;
            if family == Some(actual) {
                return Err(closed());
            }
            family = Some(actual);
            previous_cookie = Some(cookie);
        }
        Ok(())
    }

    /// Reports the completed same-child listener and physical channel boundary.
    #[must_use]
    pub fn completed_v1(&self) -> bool {
        self.completed && self.failure.is_none() && matches!(self.operation_after, Some(Ok(_)))
    }

    /// Moves the verified listener descriptors after the complete release boundary.
    ///
    /// Only this same scope's successful receipt, ACK, physical EOF, live child
    /// and independent after can produce custody. The completed transient pair,
    /// record subject and send captures then physically retire. The scope keeps
    /// the unreaped child; its original execution cutoff governs later reads.
    ///
    /// # Errors
    /// Refuses an incomplete, foreign, failed or already transferred bootstrap.
    /// Every fallible gate borrows the original before any descriptor moves.
    pub fn take_listener_custody_once_v1(
        &mut self,
        scope: &GuestSshScopeOriginalV1,
    ) -> NativeResult<GuestSshListenerCustodyV1> {
        if self.listeners_taken || !self.same_scope(scope) {
            self.refuse();
            return Err(closed());
        }
        self.require_completed_scope_v1(
            scope.bootstrap_anchor_v1()?,
            self.plan[72..88].try_into().map_err(|_| closed())?,
        )?;
        let receipt = self
            .receipt
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(closed)?;
        if !(1..=2).contains(&receipt.descriptors().len()) {
            self.refuse();
            return Err(closed());
        }
        let cut = scope.execution_horizon_v1()?;
        let anchor = std::sync::Arc::clone(scope.bootstrap_anchor_v1()?);
        let execution = self.plan[72..88].try_into().map_err(|_| closed())?;
        let cookies = std::array::from_fn(|index| match self.listeners[index].cookie.as_ref() {
            Some(Ok(cookie)) => *cookie,
            _ => 0,
        });

        // The verified successful record is the sole source of these FDs.
        // No caller descriptor or persisted address can construct custody.
        let receipt = match self.receipt.take() {
            Some(Ok(receipt)) => receipt,
            other => {
                self.receipt = other;
                self.refuse();
                return Err(closed());
            }
        };
        let (_body, _subject, rights) = receipt.into_parts();
        self.listeners_taken = true;
        drop(self.parent.take());
        drop(self.request_send.take());
        drop(self.ack_send.take());
        Ok(GuestSshListenerCustodyV1::from_completed(
            anchor, execution, self.port, cookies, cut, rights,
        ))
    }

    pub(crate) fn require_completed_scope_v1(
        &self,
        anchor: &std::sync::Arc<crate::cgroup::RetainedCgroupAnchor>,
        execution: [u8; 16],
    ) -> NativeResult<()> {
        if !self.completed
            || self.failure.is_some()
            || self.plan[72..88] != execution
            || !self
                .anchor
                .as_ref()
                .is_some_and(|held| std::sync::Arc::ptr_eq(held, anchor))
        {
            return Err(closed());
        }
        Ok(())
    }

    /// Fences this same private endpoint after its immediate owner refuses.
    ///
    /// Shutdown remains a retained native obligation. It proves neither child
    /// exit nor recursive empty and cannot replace standing containment/reap.
    pub fn fence_failed_owner_once_v1(&mut self) {
        self.refuse();
    }

    fn refuse(&mut self) {
        self.failure.get_or_insert_with(closed);
        if let Some(Ok(parent)) = self.parent.as_mut() {
            // This exact private endpoint remains owned. The existing fence
            // attempts shutdown once and retains its independent native debt.
            parent.retention.end(&parent.fd);
        }
    }

    /// Prices this actual fixed private-pair, receive and retained send source.
    ///
    /// The scope/standing owner, child resource envelope and selected-kernel
    /// prebirth source are separate simultaneous contributions. No quote or
    /// successful helper handshake substitutes for their genuine payment.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let admission = DescriptorSubjectSocket::retaining_raw_admission_obligations_v2()?;
        let control = uapi::ReceiveControlProfileV1::WorkerObserver;
        let receive = super::super::SeqpacketSocket::requested_receive_bytes(88, control, 2)
            .checked_add(std::mem::size_of::<OriginalObservationV1<'_>>())?;
        let send = DescriptorWorkerNativeSendAttemptV1::requested_bytes_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(GuestSshListenerCustodyV1::receiving_bytes_v1()?)?
            .checked_add(admission.0)?
            .checked_add(receive)?
            .checked_add(send.checked_mul(2)?)?
            .checked_add(super::super::NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?)?
            .checked_add(
                2 * ("Guest SSH bootstrap original".len()
                    + "native prefix is incomplete or refused".len()),
            )?
            .checked_add(3 * "kernel returned an unexpected cookie length".len())?
            .checked_add(2 * std::mem::size_of::<rustix::net::SocketAddrAny>())?;
        // Parent socket/peer stay beside the retained raw80 receive prefix.
        // Initial pair/admission has at most its two sockets + one peer pin.
        let raw = control.bytes() / std::mem::size_of::<std::os::fd::RawFd>();
        let receive_files = raw.checked_add(2 + 3)?.checked_add(2)?;
        Some((bytes, receive_files.max(admission.1.checked_add(1)?), 0))
    }

    /// Borrows the chronological original native refusal without new IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = self.pair.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.parent.as_ref() {
            return Some(cause);
        }
        self.cookies
            .iter()
            .find_map(|value| value.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.request_gate_failure.as_ref().map(|cause| {
                    self.clock
                        .failure()
                        .map_or(cause as _, |original| original as _)
                })
            })
            .or_else(|| self.request_send.as_ref().and_then(send_failure))
            .or_else(|| {
                self.prepare
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| clock_cause(cause, &self.clock))
            })
            .or_else(|| {
                self.prepare_after
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| clock_cause(cause, &self.after_clock))
            })
            .or_else(|| {
                self.spawned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.receipt.as_ref()?.as_ref().err().and_then(|cause| {
                    (!(cause.is_nonconsuming_would_block() || cause.is_nonconsuming_interrupted()))
                        .then_some(cause as &(dyn std::error::Error + 'static))
                })
            })
            .or_else(|| {
                self.child_info
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.subject_info
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.listeners.iter().find_map(ListenerOriginal::failure))
            .or_else(|| {
                self.verified
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.verified_after
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| clock_cause(cause, &self.after_clock))
            })
            .or_else(|| {
                self.ack_gate_failure.as_ref().map(|cause| {
                    self.clock
                        .failure()
                        .map_or(cause as _, |original| original as _)
                })
            })
            .or_else(|| self.ack_send.as_ref().and_then(send_failure))
            .or_else(|| {
                self.ack_after
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| clock_cause(cause, &self.after_clock))
            })
            .or_else(|| {
                self.eof
                    .as_ref()?
                    .as_ref()
                    .err()
                    .filter(|cause| !eof_pending(cause))
                    .map(|cause| &cause.source as _)
            })
            .or_else(|| self.alive.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.completion_after
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| clock_cause(cause, &self.after_clock))
            })
            .or_else(|| self.clock.failure().map(|cause| cause as _))
            .or_else(|| self.operation_after.as_ref()?.as_ref().err()
                .map(|cause| clock_cause(cause, &self.after_clock)))
            .or_else(|| self.after_clock.failure().map(|cause| cause as _))
            .or_else(|| self.failure.as_ref().map(|cause| cause as _))
    }
}

fn eof_pending(cause: &uapi::RawReceiveFailureV1) -> bool {
    cause.nonconsuming_syscall && matches!(&cause.source,
        Error::Syscall { source, .. }
            if matches!(source.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)))
}

fn send_failure(
    value: &Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>,
) -> Option<&(dyn std::error::Error + 'static)> {
    match value {
        Ok(receipt) => receipt.failure(),
        Err(cause) => Some(cause),
    }
}

fn clock_cause<'held>(
    cause: &'held Error,
    clock: &'held CaptureProcessCutOriginalV3,
) -> &'held (dyn std::error::Error + 'static) {
    if crate::process::capture_cut::is_marker(cause) {
        clock.failure().map_or(cause as _, |original| original as _)
    } else {
        cause
    }
}

fn closed() -> Error {
    Error::invalid(
        "Guest SSH bootstrap original",
        "native prefix is incomplete or refused",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_length_subject_record_cannot_counterfeit_zero_ancillary_eof() {
        let (parent, child) = uapi::seqpacket_pair().unwrap();
        let parent = DescriptorSubjectSocket::from_pending_retaining_raw_v2(
            PendingSocketAdmissionV1::new(parent),
        ).unwrap();
        rustix::net::send(&child, &[], rustix::net::SendFlags::empty()).unwrap();
        let mut byte = [0_u8; 1];
        let mut native = uapi::RawReceiveObservationV1::with_control(
            uapi::ReceiveControlProfileV1::ZeroAncillary,
        );

        let result = uapi::recv_seqpacket_staged(parent.fd.as_ref().unwrap().as_fd(),
            &mut byte, libc::MSG_PEEK, &mut native, uapi::ReceiveCustodyPolicyV1::Retaining);

        assert!(matches!(result, Ok(0)));
        assert_ne!(native.flags & libc::MSG_CTRUNC, 0);
        assert_eq!(native.used, 0);
        assert!(native.ancillary.is_empty());
    }

    #[test]
    fn actual_private_peer_close_has_no_record_ancillary() {
        let (parent, child) = uapi::seqpacket_pair().unwrap();
        let parent = DescriptorSubjectSocket::from_pending_retaining_raw_v2(
            PendingSocketAdmissionV1::new(parent),
        ).unwrap();
        drop(child);
        let mut byte = [0_u8; 1];
        let mut native = uapi::RawReceiveObservationV1::with_control(
            uapi::ReceiveControlProfileV1::ZeroAncillary,
        );

        let result = uapi::recv_seqpacket_staged(parent.fd.as_ref().unwrap().as_fd(),
            &mut byte, libc::MSG_PEEK, &mut native, uapi::ReceiveCustodyPolicyV1::Retaining);

        assert!(matches!(result, Ok(0)));
        assert!(native.received);
        assert_eq!(native.flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC | libc::MSG_EOR), 0);
        assert_eq!(native.used, 0);
        assert!(native.ancillary.is_empty());
    }

    #[test]
    fn same_native_tcp_listener_requires_its_actual_port_and_cookie() {
        let listener = rustix::net::socket_with(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            Some(rustix::net::ipproto::TCP),
        )
        .unwrap();
        rustix::net::bind(
            &listener,
            &rustix::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
        )
        .unwrap();
        rustix::net::listen(&listener, 1).unwrap();
        let address =
            rustix::net::SocketAddrV4::try_from(rustix::net::getsockname(&listener).unwrap())
                .unwrap();
        let cookie = uapi::socket_cookie(listener.as_fd()).unwrap();

        let mut positive = ListenerOriginal::default();
        assert_eq!(
            positive
                .capture(listener.as_fd(), address.port(), cookie)
                .unwrap(),
            rustix::net::AddressFamily::INET
        );

        let mut foreign = ListenerOriginal::default();
        assert!(
            foreign
                .capture(listener.as_fd(), address.port(), cookie ^ 1)
                .is_err()
        );
        assert!(matches!(foreign.cookie, Some(Ok(actual)) if actual == cookie));
    }

    #[test]
    fn nonsocket_reply_retains_actual_probe_errors() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let mut original = ListenerOriginal::default();

        assert!(original.capture(file.as_fd(), 22, 1).is_err());

        assert!(matches!(
            original.accepting,
            Some(Err(rustix::io::Errno::NOTSOCK))
        ));
        assert!(matches!(original.cookie, Some(Err(_))));
        assert!(original.failure().is_some());
    }
}
