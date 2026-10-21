//! Retains one mechanical record-subject socket pair and its failed prefixes.
//!
//! The original ordinary recipe and the closed parent-only zero-rights recipe
//! share the same creation, identity, peer capture and owning transfer engine.
//! Neither constructor claims a service role, payer or authenticated Session.

use super::*;

/// Retains one actual helper pair and every partial admission original.
///
/// The closed parent-only recipe disables rights before exposing either end;
/// the ordinary constructor preserves the existing offline mechanical recipe.
pub struct RecordSubjectSeqpacketPairOriginalV2 {
    attempted: bool,
    ready: bool,
    pending: Option<PendingSocketAdmissionV1>,
    socket: Option<SeqpacketSocket>,
    endpoint: Option<OwnedFd>,
    first_failure: Option<SeqpacketError>,
    zero_rights: bool,
}

impl RecordSubjectSeqpacketPairOriginalV2 {
    /// Moves only a failed cause while the actual unsuccessful pair stays held.
    ///
    /// The original remains irreversibly attempted and cannot prepare or
    /// transfer a positive endpoint after extraction. Rich failed causes may
    /// themselves retain native prefixes, so their enclosing owner retains the
    /// returned error alongside this pair through its independent posts.
    #[must_use]
    pub fn take_failure_closed_v3(&mut self) -> Option<SeqpacketError> {
        if !self.attempted || self.ready { return None; }
        self.first_failure.take()
    }

    /// Parks empty fixed pair slots without creating or admitting a descriptor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempted: false,
            ready: false,
            pending: None,
            socket: None,
            endpoint: None,
            first_failure: None,
            zero_rights: false,
        }
    }

    /// Describes the pair's requested carrier bytes and three native originals.
    ///
    /// The fixed recipe owns the two socket endpoints and one SO_PEERPIDFD;
    /// raw-to-typed adoption and later parent/child moves never duplicate them.
    /// It performs scalar socket operations and pidfs ioctls, with no proc-file
    /// reads, path traversal or dynamic receive buffer. The enclosing caller
    /// separately supplies its actual execution stack and subsequent handshake.
    /// No resident namespace rows or receiving permission come from this DATA.
    /// Returns `None` on checked representation overflow.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize)> {
        // Actual native/result carriers and their construction overlap. The
        // pair already embeds its pending peer capture and successful socket.
        type NativeCarriers = (
            Result<(OwnedFd, OwnedFd), aos_linux_descriptors::Error>,
            Result<(), aos_linux_descriptors::Error>,
            libc::sockaddr_storage,
            libc::socklen_t,
            libc::ucred,
            aos_linux_descriptors::native::RawPidfdInfo,
            PidFdInfo,
            u64,
            libc::c_int,
        );
        // These are the reached kernel-response error texts, including the
        // longest fixed getsockopt operation in the scalar formatter. Double
        // their total requested text for formatting/construction overlap.
        let text = "kernel omitted mandatory PID information".len()
            .checked_add("getpeername returned a missing or non-Unix peer".len())?
            .checked_add("kernel returned an unexpected cookie length".len())?
            .checked_add("kernel returned an unexpected credential length".len())?
            .checked_add("kernel returned a negative descriptor".len())?
            .checked_add("kernel returned an unexpected descriptor length".len())?
            .checked_add("getsockopt(SO_ACCEPTCONN) returned an unexpected length".len())?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<NativeCarriers>().checked_mul(2)?)?
            .checked_add(text.checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Option<uapi::RawAncillary>>().checked_mul(2)?)?;
        Some((bytes, 3))
    }

    /// Creates an inert parent-only zero-rights pair destination.
    ///
    /// The child direction keeps its normal descriptor-bearing admission.
    /// This mechanical selector is neither a role nor a receiving permit.
    pub fn zero_rights_parent_v1() -> Self {
        Self { zero_rights: true, ..Self::new() }
    }

    /// Creates and admits one fixed nonblocking pair with record subjects.
    ///
    /// # Errors
    /// Retains the first actual creation, option or connected-peer cause and
    /// every returned original. Reuse and caught interruption remain closed.
    pub fn prepare(&mut self) -> Result<(), &SeqpacketError> {
        let retaining = self.zero_rights;
        self.prepare_observed_v2(retaining)
    }

    /// Prepares the same pair while retaining a partial kernel peer pidfd.
    ///
    /// The ordinary descriptor-capable direction is unchanged. This mechanical
    /// retention option supplies no role, endpoint authority or native success.
    ///
    /// # Errors
    /// Retains the first setup/peer error and raw pidfd before later validation.
    pub fn prepare_retaining_v2(&mut self) -> Result<(), &SeqpacketError> {
        self.prepare_observed_v2(true)
    }

    fn prepare_observed_v2(&mut self, retain_raw: bool) -> Result<(), &SeqpacketError> {
        if self.attempted {
            self.ready = false;
            return Err(self.first_failure.get_or_insert(SeqpacketError::Closed));
        }
        self.attempted = true;
        match self.prepare_inner(retain_raw) {
            Ok(()) => {
                self.ready = true;
                Ok(())
            }
            Err(error) => {
                if let Some(pending) = self.pending.as_mut() {
                    pending.end_transport();
                }
                self.first_failure.get_or_insert(error);
                Err(self.first_failure.get_or_insert(SeqpacketError::Closed))
            }
        }
    }

    fn prepare_inner(&mut self, retain_raw: bool) -> Result<(), SeqpacketError> {
        let (receiver, endpoint) = aos_linux_descriptors::native::seqpacket_pair()?;
        self.pending = Some(PendingSocketAdmissionV1::new(receiver));
        self.endpoint = Some(endpoint);
        let pending = self.pending.as_mut().ok_or(SeqpacketError::Closed)?;
        pending.enable_subjects()?;
        aos_linux_descriptors::native::enable_seqpacket_identity(
            self.endpoint.as_ref().ok_or(SeqpacketError::Closed)?.as_fd(),
        )?;
        if self.zero_rights {
            uapi::set_seqpacket_passrights(pending.borrow_fd()?, false)?;
        }
        if retain_raw { pending.admit_peer_retaining_raw_v1()?; }
        else { pending.admit_peer()?; }

        // Admission has completed. Move both receiver owners infallibly before
        // disarming; no post-return check drops either acquired original.
        let originals = (pending.fd.take(), pending.peer.take());
        let (fd, peer) = match originals {
            (Some(fd), Some(peer)) => (fd, peer),
            (fd, peer) => {
                pending.fd = fd;
                pending.peer = peer;
                return Err(SeqpacketError::Closed);
            }
        };
        pending.armed = false;
        self.socket = Some(SeqpacketSocket {
            fd: Some(fd),
            peer,
            retained_send_flight: None,
            zero_rights: self.zero_rights.then_some(ZeroRightsNativeV1 { restore: None, epoch: 0 }),
        });
        Ok(())
    }

    /// Moves only the actual fully admitted parent socket once.
    ///
    /// # Errors
    /// Refuses incomplete, failed or previously transferred native custody.
    pub fn take_parent_socket(&mut self) -> Result<SeqpacketSocket, SeqpacketError> {
        if !self.ready { return Err(SeqpacketError::Closed); }
        self.socket.take().ok_or(SeqpacketError::Closed)
    }

    /// Transfers only the fully admitted child endpoint into the fixed launcher.
    ///
    /// # Errors
    /// Refuses a failed, incomplete, interrupted or previously transferred pair.
    pub fn take_child_endpoint(&mut self) -> Result<OwnedFd, SeqpacketError> {
        if !self.ready {
            return Err(SeqpacketError::Closed);
        }
        self.endpoint.take().ok_or(SeqpacketError::Closed)
    }

    /// Borrows the actual admitted parent socket without releasing pair custody.
    ///
    /// # Errors
    /// Refuses an incomplete or fenced pair.
    pub fn socket(&mut self) -> Result<&mut SeqpacketSocket, SeqpacketError> {
        if !self.ready {
            return Err(SeqpacketError::Closed);
        }
        self.socket.as_mut().ok_or(SeqpacketError::Closed)
    }

    /// Borrows the original first returned failure without cloning it.
    pub fn failure(&self) -> Option<&SeqpacketError> {
        self.first_failure.as_ref()
    }
}

impl Default for RecordSubjectSeqpacketPairOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}
