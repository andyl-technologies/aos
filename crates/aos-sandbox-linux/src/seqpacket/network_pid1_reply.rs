//! Retains credentials-only replies on Network's authenticated PID1 channel.
//!
//! The initial child-origin packet retains its real PID1 subject and nine
//! rights. Later bounded Source-currentness replies use the same endpoint and
//! that held pidfd, so they do not install another manager pidfd per probe.
//! This transport profile cannot construct a Source or admit packet DATA.

use super::*;
use descriptor_subject::ReceivedDescriptorRecord;
use std::error::Error as StdError;

#[derive(Clone, Copy)]
enum ProfileFirst {
    Closed,
    Binding,
    Before,
    RightsSet,
    PidfdSet,
    RightsRead,
    PidfdRead,
    CredentialsRead,
    After,
    BorrowBinding,
    BorrowAfter,
}

/// Retains the exact native transition after a real PID1 child-origin packet.
///
/// This fixed destination must be prepaid beside the initial receive. It
/// neither owns a financial bank nor interprets the child-origin authority.
#[derive(Default)]
pub struct NetworkPid1ReplyProfileOriginalV2 {
    entered: bool,
    binding: Option<Result<(), RecordBindingError>>,
    binding_cookie: Option<crate::Result<u64>>,
    before: Option<crate::Result<bool>>,
    rights_set: Option<crate::Result<()>>,
    pidfd_set: Option<crate::Result<()>>,
    rights_read: Option<crate::Result<i32>>,
    pidfd_read: Option<crate::Result<i32>>,
    credentials_read: Option<crate::Result<i32>>,
    after: Option<crate::Result<bool>>,
    first: Option<ProfileFirst>,
    closed: Option<SeqpacketError>,
    initial_packet: Option<[u8; 840]>,
    original_cookie: Option<u64>,
    channel_lent: bool,
    borrow_binding: Option<Result<(), RecordBindingError>>,
    borrow_cookie: Option<crate::Result<u64>>,
    borrow_after: Option<crate::Result<bool>>,
}

impl NetworkPid1ReplyProfileOriginalV2 {
    /// Creates inert destinations without native observations or allocations.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Prices the exact finite reply programme before its caller allocates it.
    ///
    /// The caller supplies the count from its actual prepared programme, then
    /// binds that same count to the authenticated child-origin packet. Zero
    /// and arithmetic overflow refuse; no maximum or fallback count is invented.
    /// Each reply's fixed destination and each request/response buffer remain
    /// resident. Only one failed attempt can retain its extra endpoint pin,
    /// because every refusal permanently fences the channel.
    #[must_use]
    pub fn programme_obligations_data_v2(count: u64) -> Option<(usize, usize)> {
        let count = usize::try_from(count).ok().filter(|count| *count != 0)?;
        let (receive, files) = NetworkPid1ReplyOriginalV2::receive_obligations_data_v2()?;
        let request = std::mem::size_of::<NetworkPid1RequestOriginalV2>()
            .checked_mul(2)?.checked_add(2 * 64)?;
        let bytes = receive.checked_add(request)?.checked_mul(count)?
            .checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<NetworkPid1ReplyChannelV2<'_>>())?;
        Some((bytes, files))
    }

    /// Disables fresh rights and pidfds on the same authenticated PID1 socket.
    ///
    /// The returned borrow retains the initial subject throughout every later
    /// reply. Neither the socket nor the packet can be replaced while it lives.
    /// Setter results, all readbacks and the independently owed final liveness
    /// observation stay on this original even when an earlier step refuses.
    ///
    /// # Errors
    /// Retains the first native or binding failure; refuses foreign records,
    /// non-PID1 peers, changed options, a dead held manager or repeated entry.
    pub fn restrict_once_v2<'native>(
        &'native mut self,
        socket: &'native mut SeqpacketSocket,
        initial: &'native ReceivedDescriptorRecord,
    ) -> Result<NetworkPid1ReplyChannelV2<'native>, SeqpacketError> {
        self.configure_once_v2(socket, initial)?;
        self.borrow_completed_channel_once_v2(socket, initial)
    }

    /// Retains the native receive-profile transition before donations move.
    ///
    /// The genuine child can validate and move its nine donated roles after
    /// this call, then borrow this same configured transport once. Configuration
    /// alone creates no Source, fee allowance or effect permission.
    ///
    /// # Errors
    /// Refuses foreign native custody, inexact initial geometry, failed native
    /// options or repeated entry; the held-manager after runs independently.
    pub fn configure_once_v2(&mut self, socket: &mut SeqpacketSocket,
        initial: &ReceivedDescriptorRecord) -> Result<(), SeqpacketError>
    {
        if self.entered {
            self.first.get_or_insert(ProfileFirst::Closed);
            self.closed.get_or_insert(SeqpacketError::Closed);
            return Err(SeqpacketError::Closed);
        }
        self.entered = true;
        let _ = self.configure_inner(socket, initial);
        self.after = Some(initial.subject().is_alive());
        if !matches!(self.after, Some(Ok(true))) { self.first.get_or_insert(ProfileFirst::After); }
        if self.first.is_some() {
            self.closed.get_or_insert(SeqpacketError::PeerIdentity("Network PID1 receive options changed"));
            Err(SeqpacketError::Closed)
        } else { Ok(()) }
    }

    fn configure_inner(&mut self, socket: &mut SeqpacketSocket,
        initial: &ReceivedDescriptorRecord) -> Result<(), SeqpacketError>
    {
        self.binding = Some(socket.require_network_child_origin_retaining_v2(initial, &mut self.binding_cookie));
        if !matches!(self.binding, Some(Ok(()))) {
            self.first = Some(ProfileFirst::Binding);
            return Err(SeqpacketError::Closed);
        }
        let peer = socket.peer.credentials();
        let subject = initial.subject();
        let credentials = subject.credentials();
        let packet = initial.payload();
        if peer.pid().get() != 1 || peer.uid() != 0 || peer.gid() != 0
            || credentials.pid().get() != 1 || credentials.uid() != 0 || credentials.gid() != 0
            || subject.initial_info() != socket.peer.initial_info()
            || packet.len() != 840 || packet.get(..8) != Some(b"AOSNFB02".as_slice())
            || packet.get(8..10) != Some(2_u16.to_be_bytes().as_slice())
            || !matches!(packet.get(10), Some(1 | 2)) || packet.get(11) != Some(&0)
            || packet.get(12..16) != Some(840_u32.to_be_bytes().as_slice())
            || initial.descriptors().len() != 9
        {
            self.first = Some(ProfileFirst::Closed);
            self.closed = Some(SeqpacketError::PeerIdentity("inexact PID1 Network child origin"));
            return Err(SeqpacketError::Closed);
        }
        self.initial_packet = packet.try_into().ok();
        self.original_cookie = Some(socket.peer.socket_cookie().get());
        self.before = Some(subject.is_alive());
        if !matches!(self.before, Some(Ok(true))) {
            self.first = Some(ProfileFirst::Before);
            self.closed = Some(SeqpacketError::PeerIdentity("held PID1 manager is no longer live"));
            return Err(SeqpacketError::Closed);
        }
        let fd = match socket.borrow_fd() {
            Ok(fd) => fd,
            Err(cause) => {
                self.closed = Some(cause);
                self.first = Some(ProfileFirst::Closed);
                return Err(SeqpacketError::Closed);
            }
        };

        self.rights_set = Some(uapi::set_seqpacket_passrights(fd, false));
        if !matches!(self.rights_set, Some(Ok(()))) { self.first = Some(ProfileFirst::RightsSet); }
        self.pidfd_set = Some(uapi::set_seqpacket_passpidfd(fd, false));
        if !matches!(self.pidfd_set, Some(Ok(()))) { self.first.get_or_insert(ProfileFirst::PidfdSet); }
        self.rights_read = Some(uapi::socket_integer_option(fd, uapi::SO_PASSRIGHTS,
            "getsockopt(Network Source SO_PASSRIGHTS)"));
        if !matches!(self.rights_read, Some(Ok(0))) { self.first.get_or_insert(ProfileFirst::RightsRead); }
        self.pidfd_read = Some(uapi::socket_integer_option(fd, uapi::SO_PASSPIDFD,
            "getsockopt(Network Source SO_PASSPIDFD)"));
        if !matches!(self.pidfd_read, Some(Ok(0))) { self.first.get_or_insert(ProfileFirst::PidfdRead); }
        self.credentials_read = Some(uapi::socket_integer_option(fd, libc::SO_PASSCRED,
            "getsockopt(Network Source SO_PASSCRED)"));
        if !matches!(self.credentials_read, Some(Ok(1))) { self.first.get_or_insert(ProfileFirst::CredentialsRead); }
        if self.first.is_some() { Err(SeqpacketError::Closed) } else { Ok(()) }
    }

    /// Borrows the configured original once after native role donations move.
    ///
    /// The record keeps its original payload, subject and carrier when its
    /// nine owned rights move into the child's native role originals. This
    /// checks that same record and native socket again without adopting DATA.
    /// A dropped borrow cannot reset its finite sequence programme.
    ///
    /// # Errors
    /// Retains native cookie/manager failure; refuses changed original payload,
    /// subject, endpoint, incomplete configuration or a second channel loan.
    pub fn borrow_completed_channel_once_v2<'native>(
        &'native mut self, socket: &'native mut SeqpacketSocket,
        initial: &'native ReceivedDescriptorRecord,
    ) -> Result<NetworkPid1ReplyChannelV2<'native>, SeqpacketError> {
        if self.first.is_some() || !matches!(self.after, Some(Ok(true))) || self.channel_lent
            || self.initial_packet.as_ref().map(|packet| packet.as_slice()) != Some(initial.payload())
            || self.original_cookie != Some(socket.peer.socket_cookie().get())
            || initial.subject().initial_info() != socket.peer.initial_info()
        {
            self.first.get_or_insert(ProfileFirst::Closed);
            self.closed.get_or_insert(SeqpacketError::Closed);
            return Err(SeqpacketError::Closed);
        }
        self.channel_lent = true;
        self.borrow_binding = Some(socket.require_network_child_origin_retaining_v2(initial, &mut self.borrow_cookie));
        if !matches!(self.borrow_binding, Some(Ok(()))) { self.first = Some(ProfileFirst::BorrowBinding); }
        self.borrow_after = Some(initial.subject().is_alive());
        if !matches!(self.borrow_after, Some(Ok(true))) { self.first.get_or_insert(ProfileFirst::BorrowAfter); }
        if self.first.is_some() {
            self.closed.get_or_insert(SeqpacketError::Closed);
            return Err(SeqpacketError::Closed);
        }

        Ok(NetworkPid1ReplyChannelV2 {
            socket, manager: initial.subject(), initial, _profile: self,
            sequence: 0, waiting: false, closed: false,
        })
    }

    /// Borrows the first actual native refusal, or the closed comparison marker.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        let native: Option<&(dyn StdError + 'static)> = match self.first? {
            ProfileFirst::Binding => self.binding_cookie.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn StdError + 'static))
                .or_else(|| self.binding.as_ref()?.as_ref().err().map(|error| error as _)),
            ProfileFirst::Before => self.before.as_ref()?.as_ref().err().map(|error| error as _),
            ProfileFirst::RightsSet => self.rights_set.as_ref()?.as_ref().err().map(|error| error as _),
            ProfileFirst::PidfdSet => self.pidfd_set.as_ref()?.as_ref().err().map(|error| error as _),
            ProfileFirst::RightsRead => self.rights_read.as_ref()?.as_ref().err().map(|error| error as _),
            ProfileFirst::PidfdRead => self.pidfd_read.as_ref()?.as_ref().err().map(|error| error as _),
            ProfileFirst::CredentialsRead => self.credentials_read.as_ref()?.as_ref().err().map(|error| error as _),
            ProfileFirst::After => self.after.as_ref()?.as_ref().err().map(|error| error as _),
            ProfileFirst::Closed => None,
            ProfileFirst::BorrowBinding => self.borrow_cookie.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn StdError + 'static))
                .or_else(|| self.borrow_binding.as_ref()?.as_ref().err().map(|error| error as _)),
            ProfileFirst::BorrowAfter => self.borrow_after.as_ref()?.as_ref().err().map(|error| error as _),
        };
        native.or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

/// Borrows the same native PID1 endpoint and its original authenticated subject.
///
/// This grants only transport access. The Network owner must retain and check
/// its actual Source, child F, BOOT, sequence, challenge and original operation.
pub struct NetworkPid1ReplyChannelV2<'native> {
    socket: &'native mut SeqpacketSocket,
    manager: &'native KernelAuthorizedRecordSubject,
    initial: &'native ReceivedDescriptorRecord,
    _profile: &'native NetworkPid1ReplyProfileOriginalV2,
    sequence: u64,
    waiting: bool,
    closed: bool,
}

/// Borrows the actual once-lent PID1 profile and authenticated initial record.
///
/// Its fields are private original references, not copied packet coordinates.
/// It cannot construct a transport, Source or new epoch; it only permits exact
/// affinity comparison while those same native owners remain borrowed.
pub struct NetworkPid1ReplyAffinityOriginalV2<'native> {
    profile: &'native NetworkPid1ReplyProfileOriginalV2,
    initial: &'native ReceivedDescriptorRecord,
    cookie: std::num::NonZeroU64,
}

#[derive(Clone, Copy)]
enum ReplyFirst { Before, Rights, Pidfd, Credentials, Poll, Receive, Binding, After, Reentry }

/// Retains one actual fixed Source-probe send and its independent final check.
#[derive(Default)]
pub struct NetworkPid1RequestOriginalV2 {
    entered: bool,
    before: Option<crate::Result<bool>>,
    send: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    after: Option<crate::Result<bool>>,
    first: Option<RequestFirst>,
    closed: Option<SeqpacketError>,
}

#[derive(Clone, Copy)]
enum RequestFirst { Closed, Before, Send, After }

impl NetworkPid1RequestOriginalV2 {
    /// Creates inert destinations before the actual paid native send.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Borrows the first actual native send, liveness or comparison failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        let native: Option<&(dyn StdError + 'static)> = match self.first? {
            RequestFirst::Before => self.before.as_ref()?.as_ref().err().map(|error| error as _),
            RequestFirst::Send => self.send.as_ref()?.as_ref().err().map(|error| error as _),
            RequestFirst::After => self.after.as_ref()?.as_ref().err().map(|error| error as _),
            RequestFirst::Closed => None,
        };
        native.or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

/// Retains one exact native reply attempt and its independent final observation.
#[derive(Default)]
pub struct NetworkPid1ReplyOriginalV2 {
    entered: bool,
    before: Option<crate::Result<bool>>,
    rights: Option<crate::Result<i32>>,
    pidfd: Option<crate::Result<i32>>,
    credentials: Option<crate::Result<i32>>,
    poll: Option<Result<usize, rustix::io::Errno>>,
    poll_events: Option<rustix::event::PollFlags>,
    receive: Option<Result<Vec<u8>, RetainedSeqpacketReceiveErrorV1>>,
    after: Option<crate::Result<bool>>,
    first: Option<ReplyFirst>,
    closed: Option<SeqpacketError>,
}

impl NetworkPid1ReplyOriginalV2 {
    /// Creates a fixed empty destination before the caller's paid receive.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Borrows complete payload DATA only after the native observations succeed.
    #[must_use]
    pub fn payload_data_v2(&self) -> Option<&[u8]> {
        if self.first.is_some() { return None; }
        self.receive.as_ref()?.as_ref().ok().map(Vec::as_slice)
    }

    /// Borrows an actual native receive or kernel failure without replacing it.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        let native: Option<&(dyn StdError + 'static)> = match self.first? {
            ReplyFirst::Before => self.before.as_ref()?.as_ref().err().map(|error| error as _),
            ReplyFirst::Rights => self.rights.as_ref()?.as_ref().err().map(|error| error as _),
            ReplyFirst::Pidfd => self.pidfd.as_ref()?.as_ref().err().map(|error| error as _),
            ReplyFirst::Credentials => self.credentials.as_ref()?.as_ref().err().map(|error| error as _),
            ReplyFirst::Poll => self.poll.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _),
            ReplyFirst::Receive => self.receive.as_ref()?.as_ref().err().map(|error| error as _),
            ReplyFirst::Binding => None,
            ReplyFirst::After => self.after.as_ref()?.as_ref().err().map(|error| error as _),
            ReplyFirst::Reentry => None,
        };
        native.or_else(|| self.closed.as_ref().map(|error| error as _))
    }

    /// Prices this exact reply's native samples and fixed destination backing.
    ///
    /// The rights-off profile installs no new manager pin or SCM_RIGHTS table.
    /// One duplicate of the original endpoint remains owed on receive failure.
    #[must_use]
    pub fn receive_obligations_data_v2() -> Option<(usize, usize)> {
        let bytes = SeqpacketSocket::requested_receive_bytes(
            0, uapi::ReceiveControlProfileV1::NetworkPid1CredentialsOnly, 2)
            .checked_add(128)?.checked_add(std::mem::size_of::<Self>())?
            .checked_add(2 * std::mem::size_of::<rustix::event::PollFd<'_>>())?
            .checked_add(2 * std::mem::size_of::<rustix::event::Timespec>())?;
        Some((bytes, 1))
    }
}

impl<'native> NetworkPid1ReplyChannelV2<'native> {
    /// Borrows this actual original channel's immutable once-only epoch.
    ///
    /// The borrow refers to the retained profile and original initial record,
    /// independently of this mutable transport wrapper's borrow lifetime.
    ///
    /// # Errors
    /// Refuses closed, pending, unconfigured or different native socket custody.
    pub fn lend_affinity_original_v2(&self)
        -> Result<NetworkPid1ReplyAffinityOriginalV2<'native>, SeqpacketError>
    {
        let cookie = self.socket.peer.socket_cookie();
        if self.closed || self.waiting || !self._profile.channel_lent
            || self._profile.first.is_some()
            || self._profile.original_cookie != Some(cookie.get())
        { return Err(SeqpacketError::Closed); }
        Ok(NetworkPid1ReplyAffinityOriginalV2 {
            profile: self._profile, initial: self.initial, cookie,
        })
    }

    /// Compares the exact original native channel and immutable lending epoch.
    ///
    /// # Errors
    /// Refuses another profile/initial record, changed actual socket cookie,
    /// failed original or closed/pending transport without admitting DATA.
    pub fn require_same_affinity_original_v2(&self,
        original: &NetworkPid1ReplyAffinityOriginalV2<'_>) -> Result<(), SeqpacketError>
    {
        if self.closed || self.waiting || !self._profile.channel_lent
            || self._profile.first.is_some()
            || !std::ptr::eq(self._profile, original.profile)
            || !std::ptr::eq(self.initial, original.initial)
            || self.socket.peer.socket_cookie() != original.cookie
            || self._profile.original_cookie != Some(original.cookie.get())
        { return Err(SeqpacketError::Closed); }
        Ok(())
    }

    /// Returns the next finite native sequence without renewing the programme.
    #[must_use]
    pub fn next_sequence_data_v2(&self) -> Option<u64> {
        let next = self.sequence.checked_add(1)?;
        let maximum = self.initial.payload().get(832..840)
            .and_then(|bytes| bytes.try_into().ok()).map(u64::from_be_bytes)?;
        (!self.closed && !self.waiting && next <= maximum).then_some(next)
    }

    /// Sends the next exact Source probe on the same original PID1 endpoint.
    ///
    /// The authenticated bootstrap packet bounds the sequence. Challenge and
    /// invocation come from that packet, with no renewed deadline or account.
    ///
    /// # Errors
    /// Retains the first native failure and owed final observation. Refuses a
    /// foreign frame, exhausted programme, pending response, closed channel or
    /// reentry; a failed send permanently fences this borrowed channel.
    pub fn send_once_v2(&mut self, original: &mut NetworkPid1RequestOriginalV2,
        request: &[u8; 64]) -> Result<(), SeqpacketError>
    {
        let packet = self.initial.payload();
        let maximum = packet.get(832..840).and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes).ok_or(SeqpacketError::Closed)?;
        let next = self.sequence.checked_add(1).ok_or(SeqpacketError::Closed)?;
        let valid = !self.closed && !self.waiting && !original.entered && next <= maximum
            && request[..8] == *b"AOSNFP02" && request[8..10] == 2_u16.to_be_bytes()
            && request[10] == packet[10] && request[11] == 0
            && request[12..16] == 64_u32.to_be_bytes()
            && request[16..32] == packet[160..176]
            && request[32..48] == packet[48..64]
            && request[48..56] == next.to_be_bytes() && request[56..64] == [0; 8];
        if !valid {
            original.first.get_or_insert(RequestFirst::Closed);
            original.closed.get_or_insert(SeqpacketError::Closed);
            self.closed = true;
            return Err(SeqpacketError::Closed);
        }
        original.entered = true;
        self.sequence = next;
        original.before = Some(self.manager.is_alive());
        if !matches!(original.before, Some(Ok(true))) { original.first = Some(RequestFirst::Before); }
        if original.first.is_none() {
            original.send = Some(self.socket.send_retaining(request));
            if !matches!(original.send, Some(Ok(()))) { original.first = Some(RequestFirst::Send); }
        }
        original.after = Some(self.manager.is_alive());
        if !matches!(original.after, Some(Ok(true))) { original.first.get_or_insert(RequestFirst::After); }
        if original.first.is_some() {
            original.closed.get_or_insert(SeqpacketError::Closed);
            self.closed = true;
            Err(SeqpacketError::Closed)
        } else {
            self.waiting = true;
            Ok(())
        }
    }

    /// Receives one credentials-only response on the held original endpoint.
    ///
    /// A receive failure does not suppress the independently owed final check
    /// of the retained manager pidfd. The response is DATA, never a Source.
    ///
    /// # Errors
    /// Retains every reached native result and the first failure. Refuses dead
    /// manager, changed options, wrong framing, extra ancillary data or reentry.
    pub fn receive_once_v2(&mut self, original: &mut NetworkPid1ReplyOriginalV2)
        -> Result<(), SeqpacketError>
    {
        self.receive_before_once_v2(original, None)
    }

    /// Waits once for the exact reply under the owner's unchanged time bound.
    ///
    /// Bootstrap supplies no operation deadline yet and uses `None`. Later
    /// owners derive the remaining wait from their actual original D; this
    /// transport never manufactures a timeout or retries a native refusal.
    ///
    /// # Errors
    /// Retains poll, option, receive, binding and independent manager after.
    pub fn receive_before_once_v2(&mut self, original: &mut NetworkPid1ReplyOriginalV2,
        timeout: Option<&rustix::event::Timespec>) -> Result<(), SeqpacketError>
    {
        if original.entered || self.closed || !self.waiting {
            original.first.get_or_insert(ReplyFirst::Reentry);
            original.closed.get_or_insert(SeqpacketError::Closed);
            self.closed = true;
            return Err(SeqpacketError::Closed);
        }
        original.entered = true;
        original.before = Some(self.manager.is_alive());
        if !matches!(original.before, Some(Ok(true))) { original.first = Some(ReplyFirst::Before); }
        if let Ok(fd) = self.socket.borrow_fd() {
            original.rights = Some(uapi::socket_integer_option(fd, uapi::SO_PASSRIGHTS,
                "getsockopt(Network reply SO_PASSRIGHTS)"));
            if !matches!(original.rights, Some(Ok(0))) { original.first.get_or_insert(ReplyFirst::Rights); }
            original.pidfd = Some(uapi::socket_integer_option(fd, uapi::SO_PASSPIDFD,
                "getsockopt(Network reply SO_PASSPIDFD)"));
            if !matches!(original.pidfd, Some(Ok(0))) { original.first.get_or_insert(ReplyFirst::Pidfd); }
            original.credentials = Some(uapi::socket_integer_option(fd, libc::SO_PASSCRED,
                "getsockopt(Network reply SO_PASSCRED)"));
            if !matches!(original.credentials, Some(Ok(1))) { original.first.get_or_insert(ReplyFirst::Credentials); }
        } else {
            original.first.get_or_insert(ReplyFirst::Receive);
            original.receive = Some(Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed)));
        }
        if original.first.is_none() {
            match self.socket.borrow_fd() {
                Ok(fd) => {
                    let mut descriptors = [rustix::event::PollFd::new(&fd, rustix::event::PollFlags::IN)];
                    original.poll = Some(rustix::event::poll(&mut descriptors, timeout));
                    original.poll_events = Some(descriptors[0].revents());
                    if !matches!(original.poll, Some(Ok(1)))
                        || !original.poll_events.is_some_and(|events| events.contains(rustix::event::PollFlags::IN))
                    { original.first = Some(ReplyFirst::Poll); }
                }
                Err(cause) => {
                    original.closed = Some(cause);
                    original.first = Some(ReplyFirst::Poll);
                }
            }
        }
        if original.first.is_none() {
            original.receive = Some(self.socket.receive_network_pid1_reply_data_v2());
            if !matches!(original.receive, Some(Ok(_))) { original.first = Some(ReplyFirst::Receive); }
        }
        if original.first.is_none() {
            let packet = self.initial.payload();
            let response = original.receive.as_ref().and_then(|value| value.as_ref().ok());
            let bound = response.is_some_and(|reply| reply_is_bound(packet, self.sequence, reply));
            if !bound { original.first = Some(ReplyFirst::Binding); }
        }
        original.after = Some(self.manager.is_alive());
        if !matches!(original.after, Some(Ok(true))) { original.first.get_or_insert(ReplyFirst::After); }
        self.waiting = false;
        if original.first.is_some() {
            original.closed.get_or_insert(SeqpacketError::Closed);
            self.closed = true;
            Err(SeqpacketError::Closed)
        } else { Ok(()) }
    }
}

fn reply_is_bound(packet: &[u8], sequence: u64, reply: &[u8]) -> bool {
    packet.len() == 840 && reply.len() == 128
        && reply[..8] == *b"AOSNFQ02" && reply[8..10] == 2_u16.to_be_bytes()
        && reply[10] == packet[10] && reply[11] == 0
        && reply[12..16] == 128_u32.to_be_bytes()
        && reply[16..32] == packet[160..176]
        && reply[32..48] == packet[48..64]
        && reply[48..56] == sequence.to_be_bytes()
        && reply[56..88] == packet[64..96]
        && reply[88..104] == packet[32..48]
        && reply[104..120] == packet[16..32]
        && reply[120..128] == [0; 8]
}

#[cfg(test)]
mod tests {
    use super::reply_is_bound;

    #[test]
    fn source_reply_cannot_change_any_prepared_identity_or_retire_another_query() {
        let mut initial = [0; 840];
        initial[10] = 1;
        initial[16..32].fill(11);
        initial[32..48].fill(12);
        initial[48..64].fill(13);
        initial[64..96].fill(14);
        initial[160..176].fill(15);
        let mut reply = [0; 128];
        reply[..8].copy_from_slice(b"AOSNFQ02");
        reply[8..10].copy_from_slice(&2_u16.to_be_bytes());
        reply[10] = 1;
        reply[12..16].copy_from_slice(&128_u32.to_be_bytes());
        reply[16..32].copy_from_slice(&initial[160..176]);
        reply[32..48].copy_from_slice(&initial[48..64]);
        reply[48..56].copy_from_slice(&3_u64.to_be_bytes());
        reply[56..88].copy_from_slice(&initial[64..96]);
        reply[88..104].copy_from_slice(&initial[32..48]);
        reply[104..120].copy_from_slice(&initial[16..32]);

        assert!(reply_is_bound(&initial, 3, &reply));
        assert!(!reply_is_bound(&initial, 2, &reply));
        assert!(!reply_is_bound(&initial[..832], 3, &reply));
        for offset in 0..reply.len() {
            let mut foreign = reply;
            foreign[offset] ^= 1;
            assert!(!reply_is_bound(&initial, 3, &foreign), "accepted byte {offset}");
        }
        for width in 0..128 { assert!(!reply_is_bound(&initial, 3, &reply[..width])); }
        let mut extended = reply.to_vec();
        extended.push(0);
        assert!(!reply_is_bound(&initial, 3, &extended));
    }
}

impl SeqpacketSocket {
    /// Captures the original child bootstrap endpoint through native admission.
    ///
    /// This uses the canonical pending/raw-peer engine and retains every
    /// rejected input prefix. It grants no Source, role, payer or effect.
    ///
    /// # Errors
    /// Retains the actual input socket, peer PIDFD and native validation cause.
    pub fn from_owned_network_child_retaining_v2(fd: OwnedFd)
        -> Result<Self, RetainedSeqpacketAdmissionErrorV1>
    {
        Self::from_pending_raw_peer_retaining_v1(PendingSocketAdmissionV1::new(fd))
    }

    /// Prices this exact native endpoint and its retained raw-peer failure.
    #[must_use]
    pub fn network_child_admission_obligations_data_v2() -> Option<(usize, usize)> {
        raw_admission_obligations_v3::<Self>()
    }

    /// Compares the child-origin record with the actual retained PID1 socket.
    ///
    /// Native cookie results remain on the caller's original. This checks
    /// carrier continuity only and constructs no Source or financial grant.
    ///
    /// # Errors
    /// Retains a native cookie failure and refuses a missing original endpoint,
    /// changed socket or record from another actual carrier.
    pub fn require_network_child_origin_retaining_v2(
        &self, record: &ReceivedDescriptorRecord,
        native: &mut Option<crate::Result<u64>>,
    ) -> Result<(), RecordBindingError> {
        let fd = self.fd.as_ref().map(AsFd::as_fd)
            .ok_or_else(RecordBindingError::closed)?;
        self.peer.binding.require_current_with_originals_v1(fd, Some(native))?;
        record.require_origin(self.peer.binding)
    }

    /// Compares the actual birth donation with this retained Source endpoint.
    ///
    /// The caller retains the native cookie result beside the complete record.
    /// Carrier continuity supplies no child, Source, payer or disposition grant.
    ///
    /// # Errors
    /// Retains the cookie syscall failure and refuses a changed native socket,
    /// absent retained endpoint or record from another carrier.
    pub fn require_network_birth_handoff_origin_retaining_v2(
        &self,
        record: &ReceivedDescriptorRecord,
        native: &mut Option<crate::Result<u64>>,
    ) -> Result<(), RecordBindingError> {
        let fd = self.fd.as_ref().map(AsFd::as_fd)
            .ok_or_else(RecordBindingError::closed)?;
        self.peer.binding.require_current_with_originals_v1(fd, Some(native))?;
        record.require_origin(self.peer.binding)
    }

    /// Compares a prebirth acknowledgement with this original Source channel.
    ///
    /// The caller retains the actual cookie syscall separately from its closed
    /// binding result. This supplies carrier continuity only, never a Source,
    /// child, financial allowance, effect or cleanup proof.
    ///
    /// # Errors
    /// Retains the actual native cookie failure and refuses a foreign record,
    /// changed socket or missing original endpoint.
    pub fn require_network_prebirth_prepared_origin_retaining_v2(
        &self,
        record: &ReceivedRecord,
        native: &mut Option<crate::Result<u64>>,
    ) -> Result<(), RecordBindingError> {
        self.require_record_origin_with_originals_v4(record, Some(native))
    }

    fn receive_network_pid1_reply_data_v2(&mut self)
        -> Result<Vec<u8>, RetainedSeqpacketReceiveErrorV1>
    {
        let mut attempt = self.receive_retaining_with_disposition(128,
            receive_custody::SubjectProfileV1::NetworkPid1CredentialsOnly,
            uapi::ReceiveControlProfileV1::NetworkPid1CredentialsOnly,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal)?;
        if attempt.messages[1].payload.len() != 128 {
            return Err(attempt.reject(SeqpacketError::Ancillary("inexact Network Source reply width")));
        }
        let payload = std::mem::take(&mut attempt.messages[1].payload);
        attempt.disarm();
        Ok(payload)
    }
}
