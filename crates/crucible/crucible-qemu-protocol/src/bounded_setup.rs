//! Fixed Linux descriptor handover with retained original setup custody.
//!
//! ```text
//! Setup13 = length9:u32be, tag:u8, region_extent:u64be
//! SCM_RIGHTS = exactly [shared_memory, wake, original_sealed_setup]
//! ```
//!
//! Every step performs at most one nonblocking syscall under the same original
//! actor's administrative budget. No hidden EINTR retry, frame allocation or
//! descriptor duplication occurs. Failed and partial journals retain their bytes
//! and received descriptor ownership; callers keep them in owning quarantine.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::whole_control::staged::administrative::{AdministrativeIoBudget, AdministrativeIoError};
use crate::{
    AncillaryBuffer, ControlLifecycleEvent, ControlLifecycleState, ControlLifecycleStream, HostMsg,
    TAG_SETUP,
};

/// Counts the entire fixed ordinary setup frame including its length prefix.
pub const SETUP_JOURNAL_BYTES: usize = 13;

/// Reports the first fixed setup transfer refusal while its journal stays owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BoundedSetupError {
    /// The original actor's finite administrative allowance refused an offer.
    #[error("setup administrative allowance refused: {0}")]
    Budget(#[from] AdministrativeIoError),
    /// The caller no longer belongs to the original journal process.
    #[error("setup original process changed")]
    Process,
    /// The original protocol lifecycle does not permit this setup transition.
    #[error("setup original lifecycle does not permit handover")]
    Lifecycle,
    /// The original socket closed before the complete setup transfer.
    #[error("setup original socket closed")]
    Closed,
    /// One physical syscall failed with the retained errno.
    #[error("setup socket syscall failed with errno {0}")]
    Syscall(i32),
    /// The complete frame or bounded ancillary grammar is malformed.
    #[error("setup frame or descriptors are malformed")]
    Malformed,
    /// Complete original setup bytes and all three descriptors are not present.
    #[error("setup original handover is incomplete")]
    Incomplete,
}

/// Reports one physical attempt without interpreting source readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupTransferProgress {
    /// Counts bytes actually transferred by this one physical syscall.
    pub actual_bytes: usize,
    /// Reports complete fixed setup bytes and descriptor transfer.
    pub complete: bool,
}

/// Reports one original nonblocking byte I/O attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdministrativeIoProgress {
    /// Counts actual bytes in caller-owned retained backing.
    pub actual_bytes: usize,
    /// Reports EINTR or EAGAIN without performing a hidden retry.
    pub retryable: bool,
    /// Reports a physical zero-length receive or send.
    pub peer_closed: bool,
}

/// Receives once into the actor's preowned original byte journal.
///
/// # Errors
/// Rejects finite credit exhaustion or one failed syscall. The caller retains
/// destination backing and the same budget through all setup and RUN phases.
pub fn read_once(
    socket: BorrowedFd<'_>,
    destination: &mut [u8],
    budget: &mut AdministrativeIoBudget,
    now_monotonic_ns: u64,
) -> Result<AdministrativeIoProgress, BoundedSetupError> {
    let offered = budget.offer_read(destination.len(), now_monotonic_ns)?;
    // SAFETY: The borrowed socket and bounded writable retained destination are
    // live for this single nonblocking call; no descriptor ownership is changed.
    let result = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            destination.as_mut_ptr().cast(),
            offered,
            libc::MSG_DONTWAIT,
        )
    };
    let errno = if result < 0 {
        Some(crate::last_errno_value())
    } else {
        None
    };
    budget.finish_read(if result < 0 { 0 } else { result as usize })?;
    byte_io_progress(result, errno)
}

/// Sends once from the actor's preowned complete original byte journal.
///
/// # Errors
/// Rejects finite credit exhaustion or one failed syscall. Every offered byte is
/// permanently charged before the call, including partial or interrupted sends.
pub fn write_once(
    socket: BorrowedFd<'_>,
    source: &[u8],
    budget: &mut AdministrativeIoBudget,
    now_monotonic_ns: u64,
) -> Result<AdministrativeIoProgress, BoundedSetupError> {
    let offered = budget.offer_write(source.len(), now_monotonic_ns)?;
    // SAFETY: The borrowed socket and bounded retained source remain live for
    // this single nonblocking call; MSG_NOSIGNAL preserves ordinary error flow.
    let result = unsafe {
        libc::send(
            socket.as_raw_fd(),
            source.as_ptr().cast(),
            offered,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    byte_io_progress(
        result,
        if result < 0 {
            Some(crate::last_errno_value())
        } else {
            None
        },
    )
}

fn byte_io_progress(
    result: isize,
    errno: Option<i32>,
) -> Result<AdministrativeIoProgress, BoundedSetupError> {
    if let Some(errno) = errno {
        if matches!(errno, libc::EINTR | libc::EAGAIN) {
            return Ok(AdministrativeIoProgress {
                actual_bytes: 0,
                retryable: true,
                peer_closed: false,
            });
        }
        return Err(BoundedSetupError::Syscall(errno));
    }
    Ok(AdministrativeIoProgress {
        actual_bytes: result as usize,
        retryable: false,
        peer_closed: result == 0,
    })
}

/// Owns the exact original outbound setup bytes and its three offered descriptors.
pub struct SetupSendJournal {
    body: [u8; SETUP_JOURNAL_BYTES],
    descriptors: [OwnedFd; 3],
    written: usize,
    process: u32,
    refusal: Option<BoundedSetupError>,
    socket_identity: Option<(u64, u64)>,
}

impl SetupSendJournal {
    /// Moves original descriptor custody into a fixed preowned setup journal.
    pub fn new(region_len: u64, descriptors: [OwnedFd; 3]) -> Self {
        let mut body = [0; SETUP_JOURNAL_BYTES];
        body[..4].copy_from_slice(&9u32.to_be_bytes());
        body[4] = TAG_SETUP;
        body[5..].copy_from_slice(&region_len.to_be_bytes());
        Self {
            body,
            descriptors,
            written: 0,
            process: std::process::id(),
            refusal: None,
            socket_identity: None,
        }
    }

    /// Borrows all complete original offered bytes, including an unwritten suffix.
    pub const fn body(&self) -> &[u8; SETUP_JOURNAL_BYTES] {
        &self.body
    }

    /// Borrows the same offered descriptors without cloning or relinquishing them.
    pub fn descriptors(&self) -> [BorrowedFd<'_>; 3] {
        self.descriptors.each_ref().map(AsFd::as_fd)
    }

    /// Counts the actual physical prefix written without resetting its history.
    pub const fn written(&self) -> usize {
        self.written
    }

    /// Performs one nonblocking physical send under the actor's original budget.
    ///
    /// # Errors
    /// Retains the first process, budget or syscall refusal. Partial transfers
    /// keep the complete original frame; continuation never resends SCM_RIGHTS.
    pub fn try_send_step(
        &mut self,
        socket: BorrowedFd<'_>,
        budget: &mut AdministrativeIoBudget,
        now_monotonic_ns: u64,
    ) -> Result<SetupTransferProgress, BoundedSetupError> {
        self.check()?;
        if let Err(error) = check_socket_identity(socket, &mut self.socket_identity) {
            return self.refuse(error);
        }
        if self.written == SETUP_JOURNAL_BYTES {
            return Ok(SetupTransferProgress {
                actual_bytes: 0,
                complete: true,
            });
        }
        let offered = match budget.offer_write(SETUP_JOURNAL_BYTES - self.written, now_monotonic_ns)
        {
            Ok(offered) => offered,
            Err(error) => return self.refuse(error.into()),
        };
        let mut iov = libc::iovec {
            iov_base: self.body[self.written..].as_ptr().cast_mut().cast(),
            iov_len: offered,
        };
        let mut control = AncillaryBuffer::for_single_cmsg_fd_capacity(3)
            .map_err(|_| BoundedSetupError::Malformed)?;
        let mut message = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        if self.written == 0 {
            message.msg_control = control.as_mut_ptr();
            message.msg_controllen = control.len;
            let fds = self.descriptors.each_ref().map(AsRawFd::as_raw_fd);
            // SAFETY: The fixed aligned control allocation is live and sized
            // for exactly three retained descriptors through this one syscall.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                if header.is_null() {
                    return self.refuse(BoundedSetupError::Malformed);
                }
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len =
                    libc::CMSG_LEN((3 * std::mem::size_of::<libc::c_int>()) as u32) as usize;
                std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), 3);
            }
        }
        // SAFETY: The original borrowed socket, fixed frame and aligned control
        // storage remain live. Nonblocking flags prevent hidden wait/retry.
        let sent = unsafe {
            libc::sendmsg(
                socket.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            let errno = crate::last_errno_value();
            if matches!(errno, libc::EINTR | libc::EAGAIN) {
                return Ok(SetupTransferProgress {
                    actual_bytes: 0,
                    complete: false,
                });
            }
            return self.refuse(BoundedSetupError::Syscall(errno));
        }
        if sent == 0 {
            return self.refuse(BoundedSetupError::Closed);
        }
        self.written += sent as usize;
        Ok(SetupTransferProgress {
            actual_bytes: sent as usize,
            complete: self.written == SETUP_JOURNAL_BYTES,
        })
    }

    fn check(&mut self) -> Result<(), BoundedSetupError> {
        if let Some(error) = self.refusal {
            return Err(error);
        }
        if self.process != std::process::id() {
            return self.refuse(BoundedSetupError::Process);
        }
        Ok(())
    }

    fn refuse<T>(&mut self, error: BoundedSetupError) -> Result<T, BoundedSetupError> {
        Err(*self.refusal.get_or_insert(error))
    }
}

/// Owns all original setup bytes and up to four actually received descriptors.
///
/// The fourth descriptor is retained on a malformed excess offer. No received
/// descriptor is silently dropped while reporting transfer failure.
pub struct SetupReceiveJournal {
    body: [u8; SETUP_JOURNAL_BYTES],
    received: usize,
    descriptors: [Option<OwnedFd>; 4],
    descriptor_count: usize,
    process: u32,
    complete: bool,
    refusal: Option<BoundedSetupError>,
    socket_identity: Option<(u64, u64)>,
}

impl Default for SetupReceiveJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl SetupReceiveJournal {
    /// Creates fixed retained storage before the first physical descriptor read.
    pub fn new() -> Self {
        Self {
            body: [0; SETUP_JOURNAL_BYTES],
            received: 0,
            descriptors: std::array::from_fn(|_| None),
            descriptor_count: 0,
            process: std::process::id(),
            complete: false,
            refusal: None,
            socket_identity: None,
        }
    }

    /// Borrows every actual retained prefix byte, including malformed material.
    pub fn retained_prefix(&self) -> &[u8] {
        &self.body[..self.received]
    }

    /// Borrows an original received descriptor even after a later refusal.
    pub fn retained_descriptor(&self, index: usize) -> Option<BorrowedFd<'_>> {
        self.descriptors
            .get(index)
            .and_then(Option::as_ref)
            .map(AsFd::as_fd)
    }

    /// Borrows the exact successful descriptor list without cloning custody.
    ///
    /// # Errors
    /// Refuses incomplete or failed transfers without dropping their originals.
    pub fn descriptors(&self) -> Result<[BorrowedFd<'_>; 3], BoundedSetupError> {
        if !self.complete || self.refusal.is_some() {
            return Err(BoundedSetupError::Incomplete);
        }
        Ok([
            self.retained_descriptor(0)
                .ok_or(BoundedSetupError::Incomplete)?,
            self.retained_descriptor(1)
                .ok_or(BoundedSetupError::Incomplete)?,
            self.retained_descriptor(2)
                .ok_or(BoundedSetupError::Incomplete)?,
        ])
    }

    /// Returns the original complete frame's region extent.
    ///
    /// # Errors
    /// Refuses incomplete or failed transfers without interpreting their bytes.
    pub fn region_len(&self) -> Result<u64, BoundedSetupError> {
        if !self.complete || self.refusal.is_some() {
            return Err(BoundedSetupError::Incomplete);
        }
        match crate::control_decode_host_msg(&self.body)
            .map_err(|_| BoundedSetupError::Malformed)?
        {
            HostMsg::Setup { region_len } => Ok(region_len),
            _ => Err(BoundedSetupError::Malformed),
        }
    }

    /// Performs one nonblocking physical receive with original retained custody.
    ///
    /// # Errors
    /// Retains the first process, budget, closure or malformed ancillary refusal.
    /// Every actual returned prefix and received descriptor stays in this journal.
    pub fn try_receive_step(
        &mut self,
        socket: BorrowedFd<'_>,
        budget: &mut AdministrativeIoBudget,
        now_monotonic_ns: u64,
    ) -> Result<SetupTransferProgress, BoundedSetupError> {
        if let Some(error) = self.refusal {
            return Err(error);
        }
        if self.process != std::process::id() {
            return self.refuse(BoundedSetupError::Process);
        }
        if let Err(error) = check_socket_identity(socket, &mut self.socket_identity) {
            return self.refuse(error);
        }
        if self.complete {
            return Ok(SetupTransferProgress {
                actual_bytes: 0,
                complete: true,
            });
        }
        let target = if self.received < 4 {
            4
        } else {
            SETUP_JOURNAL_BYTES
        };
        let offered = match budget.offer_read(target - self.received, now_monotonic_ns) {
            Ok(offered) => offered,
            Err(error) => return self.refuse(error.into()),
        };
        let mut iov = libc::iovec {
            iov_base: self.body[self.received..].as_mut_ptr().cast(),
            iov_len: offered,
        };
        let mut control = AncillaryBuffer::for_single_cmsg_fd_capacity(4 - self.descriptor_count)
            .map_err(|_| BoundedSetupError::Malformed)?;
        let mut message = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr(),
            // CMSG_LEN excludes alignment padding which could otherwise fit
            // a second extra FD when only one quarantine slot remains.
            // SAFETY: The payload count is bounded by four original FD slots.
            msg_controllen: unsafe {
                libc::CMSG_LEN(
                    ((4 - self.descriptor_count) * std::mem::size_of::<libc::c_int>()) as u32,
                ) as usize
            },
            msg_flags: 0,
        };
        // SAFETY: The original borrowed socket and all fixed writable buffers
        // remain live. Linux marks every received descriptor CLOEXEC atomically.
        let received = unsafe {
            libc::recvmsg(
                socket.as_raw_fd(),
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if received < 0 {
            budget.finish_read(0)?;
            let errno = crate::last_errno_value();
            if matches!(errno, libc::EINTR | libc::EAGAIN) {
                return Ok(SetupTransferProgress {
                    actual_bytes: 0,
                    complete: false,
                });
            }
            return self.refuse(BoundedSetupError::Syscall(errno));
        }
        self.received += received as usize;
        budget.finish_read(received as usize)?;
        let malformed = self.retain_rights(&message);
        if malformed || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            return self.refuse(BoundedSetupError::Malformed);
        }
        if received == 0 {
            return self.refuse(BoundedSetupError::Closed);
        }
        if self.received >= 4 && self.body[..4] != 9u32.to_be_bytes() {
            return self.refuse(BoundedSetupError::Malformed);
        }
        if self.received == SETUP_JOURNAL_BYTES {
            if self.descriptor_count != 3
                || !matches!(
                    crate::control_decode_host_msg(&self.body),
                    Ok(HostMsg::Setup { .. })
                )
            {
                return self.refuse(BoundedSetupError::Malformed);
            }
            self.complete = true;
        }
        Ok(SetupTransferProgress {
            actual_bytes: received as usize,
            complete: self.complete,
        })
    }

    fn retain_rights(&mut self, message: &libc::msghdr) -> bool {
        let mut malformed = false;
        // SAFETY: recvmsg initialized the live aligned ancillary buffer. Every
        // header span is checked against the returned extent before payload use.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(message);
            let start = message.msg_control as usize;
            let Some(end) = start.checked_add(message.msg_controllen) else {
                return true;
            };
            while !header.is_null() {
                let base = header as usize;
                if base < start
                    || base
                        .checked_add(std::mem::size_of::<libc::cmsghdr>())
                        .is_none_or(|limit| limit > end)
                {
                    return true;
                }
                let length = (*header).cmsg_len;
                let minimum = libc::CMSG_LEN(0) as usize;
                if length < minimum || base.checked_add(length).is_none_or(|limit| limit > end) {
                    return true;
                }
                if (*header).cmsg_level != libc::SOL_SOCKET
                    || (*header).cmsg_type != libc::SCM_RIGHTS
                {
                    malformed = true;
                } else {
                    let bytes = length - minimum;
                    malformed |= !bytes.is_multiple_of(std::mem::size_of::<libc::c_int>());
                    for index in 0..bytes / std::mem::size_of::<libc::c_int>() {
                        let descriptor = libc::CMSG_DATA(header)
                            .cast::<libc::c_int>()
                            .add(index)
                            .read_unaligned();
                        if self.descriptor_count == self.descriptors.len() {
                            // The receive control buffer can represent at most
                            // four rights; excess descriptors are kernel-closed
                            // with MSG_CTRUNC and never exposed as source custody.
                            libc::close(descriptor);
                            malformed = true;
                        } else {
                            self.descriptors[self.descriptor_count] =
                                Some(OwnedFd::from_raw_fd(descriptor));
                            self.descriptor_count += 1;
                        }
                    }
                }
                header = libc::CMSG_NXTHDR(message, header);
            }
        }
        malformed || self.descriptor_count > 3
    }

    fn refuse<T>(&mut self, error: BoundedSetupError) -> Result<T, BoundedSetupError> {
        Err(*self.refusal.get_or_insert(error))
    }
}

fn check_socket_identity(
    socket: BorrowedFd<'_>,
    original: &mut Option<(u64, u64)>,
) -> Result<(), BoundedSetupError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes the entire writable stat on success while the
    // actual borrowed descriptor remains live; no socket byte I/O occurs here.
    if unsafe { libc::fstat(socket.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(BoundedSetupError::Syscall(crate::last_errno_value()));
    }
    // SAFETY: The successful preceding fstat initialized this metadata.
    let metadata = unsafe { metadata.assume_init() };
    let identity = (metadata.st_dev, metadata.st_ino);
    if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || original.is_some_and(|original| original != identity)
    {
        return Err(BoundedSetupError::Malformed);
    }
    *original = Some(identity);
    Ok(())
}

impl<S: AsFd> ControlLifecycleStream<S> {
    /// Sends one original fixed setup step and transitions only after completion.
    ///
    /// # Errors
    /// Rejects an invalid original lifecycle or a journal/budget transfer refusal.
    pub fn host_send_setup_journal_step(
        &mut self,
        journal: &mut SetupSendJournal,
        budget: &mut AdministrativeIoBudget,
        now_monotonic_ns: u64,
    ) -> Result<SetupTransferProgress, BoundedSetupError> {
        if self.lifecycle.state() == ControlLifecycleState::SetupSent
            && journal.written == SETUP_JOURNAL_BYTES
        {
            return journal.try_send_step(self.stream.as_fd(), budget, now_monotonic_ns);
        }
        let mut lifecycle = self.lifecycle.clone();
        if lifecycle.observe(ControlLifecycleEvent::HostSetup).is_err() {
            return journal.refuse(BoundedSetupError::Lifecycle);
        }
        let progress = journal.try_send_step(self.stream.as_fd(), budget, now_monotonic_ns)?;
        if progress.complete {
            self.lifecycle = lifecycle;
        }
        Ok(progress)
    }

    /// Receives one original fixed setup step and transitions only after completion.
    ///
    /// # Errors
    /// Rejects an invalid original lifecycle or a journal/budget transfer refusal.
    pub fn plugin_recv_setup_journal_step(
        &mut self,
        journal: &mut SetupReceiveJournal,
        budget: &mut AdministrativeIoBudget,
        now_monotonic_ns: u64,
    ) -> Result<SetupTransferProgress, BoundedSetupError> {
        if self.lifecycle.state() == ControlLifecycleState::SetupSent && journal.complete {
            return journal.try_receive_step(self.stream.as_fd(), budget, now_monotonic_ns);
        }
        let mut lifecycle = self.lifecycle.clone();
        if lifecycle.observe(ControlLifecycleEvent::HostSetup).is_err() {
            return journal.refuse(BoundedSetupError::Lifecycle);
        }
        let progress = journal.try_receive_step(self.stream.as_fd(), budget, now_monotonic_ns)?;
        if progress.complete {
            self.lifecycle = lifecycle;
        }
        Ok(progress)
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Real Linux descriptor custody controls fail on invariant violations.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    fn images<const N: usize>() -> [OwnedFd; N] {
        std::array::from_fn(|_| {
            // SAFETY: The fixed NUL-terminated name is live during this call;
            // each successful new descriptor is immediately uniquely owned.
            let raw = unsafe {
                libc::memfd_create(
                    c"setup-test".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                )
            };
            assert!(raw >= 0);
            // SAFETY: A successful memfd_create yielded a fresh owned descriptor.
            let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
            // SAFETY: These scalar operations name that retained original FD.
            assert_eq!(unsafe { libc::ftruncate(raw, 4096) }, 0);
            assert_eq!(
                unsafe {
                    // SAFETY: descriptor uniquely owns this live memfd. F_ADD_SEALS
                    // takes the following scalar c_int mask, not a pointer argument.
                    libc::fcntl(
                        raw,
                        libc::F_ADD_SEALS,
                        libc::F_SEAL_SHRINK
                            | libc::F_SEAL_GROW
                            | libc::F_SEAL_WRITE
                            | libc::F_SEAL_SEAL,
                    )
                },
                0
            );
            descriptor
        })
    }

    fn budget() -> AdministrativeIoBudget {
        AdministrativeIoBudget::new(&crate::whole_control::staged::tests::profile()).unwrap()
    }

    #[test]
    fn original_fully_sealed_memfds_and_complete_bytes_survive_two_receive_steps() {
        let (sender_socket, receiver_socket) = UnixStream::pair().unwrap();
        let offered = images::<3>();
        let identities = offered.each_ref().map(|fd| {
            // Compare actual file metadata below, rather than metadata readiness.
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            assert_eq!(
                unsafe {
                    // SAFETY: fd retains the original memfd and metadata is an
                    // aligned writable stat allocation for this synchronous call.
                    libc::fstat(fd.as_raw_fd(), metadata.as_mut_ptr())
                },
                0
            );
            // SAFETY: The preceding successful fstat initialized every field.
            let metadata = unsafe { metadata.assume_init() };
            (metadata.st_dev, metadata.st_ino)
        });
        let mut sender = SetupSendJournal::new(4096, offered);
        let mut receiver = SetupReceiveJournal::new();
        let mut send_budget = budget();
        let mut receive_budget = budget();
        assert!(
            sender
                .try_send_step(sender_socket.as_fd(), &mut send_budget, 0)
                .unwrap()
                .complete
        );
        assert_eq!(
            sender.body().as_slice(),
            crate::control_encode_host_msg(&HostMsg::Setup { region_len: 4096 })
        );
        assert!(
            !receiver
                .try_receive_step(receiver_socket.as_fd(), &mut receive_budget, 0)
                .unwrap()
                .complete
        );
        assert_eq!(receiver.retained_prefix(), &sender.body()[..4]);
        assert!(
            receiver
                .try_receive_step(receiver_socket.as_fd(), &mut receive_budget, 0)
                .unwrap()
                .complete
        );
        assert_eq!(receiver.region_len(), Ok(4096));
        assert_eq!(receiver.retained_prefix(), sender.body());
        for (index, descriptor) in receiver.descriptors().unwrap().iter().enumerate() {
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            assert_eq!(
                unsafe {
                    // SAFETY: the journal retains this received descriptor, and
                    // metadata is an aligned writable stat allocation until return.
                    libc::fstat(descriptor.as_raw_fd(), metadata.as_mut_ptr())
                },
                0
            );
            // SAFETY: The preceding fstat initialized the full metadata.
            let metadata = unsafe { metadata.assume_init() };
            assert_eq!((metadata.st_dev, metadata.st_ino), identities[index]);
            assert_ne!(
                unsafe {
                    // SAFETY: the journal retains this descriptor. F_GETFD reads
                    // scalar flags and takes no variadic pointer or third argument.
                    libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD)
                } & libc::FD_CLOEXEC,
                0
            );
        }
        assert_eq!(send_budget.counters().offered_write_bytes, 13);
        assert_eq!(receive_budget.counters().read_attempts, 2);
        assert_eq!(receive_budget.counters().read_bytes, 13);
    }

    #[test]
    fn exact_partial_sender_prefix_keeps_fds_and_full_unwritten_original() {
        let (sender_socket, mut receiver_socket) = UnixStream::pair().unwrap();
        let mut profile = crate::whole_control::staged::tests::profile();
        profile.compute.administrative_write_byte_limit = 6154;
        let mut budget = AdministrativeIoBudget::new(&profile).unwrap();
        let retained_prior = vec![0x70; 6149];
        assert_eq!(
            write_once(sender_socket.as_fd(), &retained_prior, &mut budget, 0)
                .unwrap()
                .actual_bytes,
            retained_prior.len()
        );
        let mut prior = vec![0; 6149];
        receiver_socket.read_exact(&mut prior).unwrap();
        assert_eq!(prior, retained_prior);

        let mut sender = SetupSendJournal::new(4096, images::<3>());
        let mut receiver = SetupReceiveJournal::new();
        let progress = sender
            .try_send_step(sender_socket.as_fd(), &mut budget, 0)
            .unwrap();
        assert_eq!(
            progress,
            SetupTransferProgress {
                actual_bytes: 5,
                complete: false
            }
        );
        assert_eq!(sender.written(), 5);
        let mut read_budget = self::budget();
        receiver
            .try_receive_step(receiver_socket.as_fd(), &mut read_budget, 0)
            .unwrap();
        receiver
            .try_receive_step(receiver_socket.as_fd(), &mut read_budget, 0)
            .unwrap();
        assert_eq!(receiver.retained_prefix(), &sender.body()[..5]);
        assert!(receiver.retained_descriptor(2).is_some());
        assert_eq!(
            sender.try_send_step(sender_socket.as_fd(), &mut budget, 0),
            Err(BoundedSetupError::Budget(AdministrativeIoError::Bytes))
        );
        assert_eq!(sender.body().len(), 13);
        assert_eq!(sender.descriptors().len(), 3);
    }

    #[test]
    fn changed_original_socket_refuses_before_any_second_endpoint_io() {
        let (original_socket, _original_peer) = UnixStream::pair().unwrap();
        let (foreign_socket, mut foreign_peer) = UnixStream::pair().unwrap();
        foreign_peer.set_nonblocking(true).unwrap();
        let mut journal = SetupSendJournal::new(4096, images::<3>());
        let mut budget = budget();
        journal
            .try_send_step(original_socket.as_fd(), &mut budget, 0)
            .unwrap();
        assert_eq!(
            journal.try_send_step(foreign_socket.as_fd(), &mut budget, 0),
            Err(BoundedSetupError::Malformed)
        );
        assert_eq!(budget.counters().write_attempts, 1);
        assert_eq!(
            foreign_peer.read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn empty_read_is_one_charged_attempt_without_a_hidden_retry() {
        let (_sender, receiver) = UnixStream::pair().unwrap();
        let mut budget = budget();
        let mut retained = [0; 13];
        assert_eq!(
            read_once(receiver.as_fd(), &mut retained, &mut budget, 0).unwrap(),
            AdministrativeIoProgress {
                actual_bytes: 0,
                retryable: true,
                peer_closed: false
            }
        );
        assert_eq!(budget.counters().read_attempts, 1);
        assert_eq!(budget.counters().read_bytes, 0);
        assert_eq!(retained, [0; 13]);
    }

    fn send_rights(socket: BorrowedFd<'_>, descriptors: &[OwnedFd], body: &[u8]) {
        let mut control = AncillaryBuffer::for_single_cmsg_fd_capacity(descriptors.len()).unwrap();
        let mut iov = libc::iovec {
            iov_base: body.as_ptr().cast_mut().cast(),
            iov_len: body.len(),
        };
        let message = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr(),
            msg_controllen: control.len,
            msg_flags: 0,
        };
        // SAFETY: Fixed aligned control storage and every offered original FD
        // remain live throughout this literal malformed-peer fixture syscall.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN((descriptors.len() * std::mem::size_of::<libc::c_int>()) as u32)
                    as usize;
            for (index, descriptor) in descriptors.iter().enumerate() {
                libc::CMSG_DATA(header)
                    .cast::<libc::c_int>()
                    .add(index)
                    .write(descriptor.as_raw_fd());
            }
            assert_eq!(
                libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                body.len() as isize
            );
        }
    }

    #[test]
    fn malformed_fourth_descriptor_stays_owned_with_its_original_prefix() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let offered = images::<4>();
        let body = crate::control_encode_host_msg(&HostMsg::Setup { region_len: 4096 });
        send_rights(sender.as_fd(), &offered, &body);
        let mut journal = SetupReceiveJournal::new();
        let mut budget = budget();

        assert_eq!(
            journal.try_receive_step(receiver.as_fd(), &mut budget, 0),
            Err(BoundedSetupError::Malformed)
        );
        assert_eq!(journal.retained_prefix(), &body[..4]);
        for index in 0..4 {
            let descriptor = journal.retained_descriptor(index).unwrap();
            // SAFETY: The failed journal retains this actual received FD.
            assert!(unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } >= 0);
        }
        assert_eq!(
            journal.try_receive_step(receiver.as_fd(), &mut budget, 0),
            Err(BoundedSetupError::Malformed)
        );
        assert_eq!(budget.counters().read_attempts, 1);
        assert_eq!(budget.counters().read_bytes, 4);
    }

    #[test]
    fn late_extra_rights_cannot_use_control_padding_to_escape_fixed_quarantine() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let body = crate::control_encode_host_msg(&HostMsg::Setup { region_len: 4096 });
        send_rights(sender.as_fd(), &images::<3>(), &body[..5]);
        let mut journal = SetupReceiveJournal::new();
        let mut budget = budget();
        journal
            .try_receive_step(receiver.as_fd(), &mut budget, 0)
            .unwrap();
        journal
            .try_receive_step(receiver.as_fd(), &mut budget, 0)
            .unwrap();
        assert_eq!(journal.descriptor_count, 3);

        send_rights(sender.as_fd(), &images::<2>(), &body[5..6]);
        assert_eq!(
            journal.try_receive_step(receiver.as_fd(), &mut budget, 0),
            Err(BoundedSetupError::Malformed)
        );
        assert_eq!(journal.retained_prefix(), &body[..6]);
        assert_eq!(journal.descriptor_count, 4);
        assert!(journal.retained_descriptor(3).is_some());
        assert!(journal.retained_descriptor(4).is_none());
        assert_eq!(budget.counters().read_bytes, 6);
    }

    #[test]
    fn lifecycle_observes_setup_only_after_complete_original_descriptor_receive() {
        let (host_socket, plugin_socket) = UnixStream::pair().unwrap();
        let plugin = std::thread::spawn(move || {
            let mut plugin = ControlLifecycleStream::connected_unix_stream(plugin_socket).unwrap();
            plugin
                .plugin_start_handshake(crate::PluginHandshakeConfig {
                    proto_version: 3,
                    abi_version: 25,
                })
                .unwrap();
            plugin
        });
        let mut host = ControlLifecycleStream::connected_unix_stream(host_socket).unwrap();
        host.host_accept_handshake(crate::HostHandshakeConfig {
            proto_version: 3,
            abi_version: 25,
            slot_index: 0,
            node_count: 1,
        })
        .unwrap();
        let mut plugin = plugin.join().unwrap();
        let mut sent = SetupSendJournal::new(4096, images::<3>());
        let mut received = SetupReceiveJournal::new();
        let mut sender_budget = budget();
        let mut receiver_budget = budget();

        assert!(
            host.host_send_setup_journal_step(&mut sent, &mut sender_budget, 0)
                .unwrap()
                .complete
        );
        assert_eq!(host.state(), ControlLifecycleState::SetupSent);
        assert!(
            !plugin
                .plugin_recv_setup_journal_step(&mut received, &mut receiver_budget, 0)
                .unwrap()
                .complete
        );
        assert_eq!(plugin.state(), ControlLifecycleState::HelloAcknowledged);
        assert!(
            plugin
                .plugin_recv_setup_journal_step(&mut received, &mut receiver_budget, 0)
                .unwrap()
                .complete
        );
        assert_eq!(plugin.state(), ControlLifecycleState::SetupSent);
        assert_eq!(received.region_len(), Ok(4096));
        assert!(
            plugin
                .plugin_recv_setup_journal_step(&mut received, &mut receiver_budget, 0)
                .unwrap()
                .complete
        );
        assert_eq!(receiver_budget.counters().read_attempts, 2);
    }

    #[test]
    fn early_lifecycle_refusal_consumes_no_socket_prefix_or_administrative_credit() {
        let (mut peer, socket) = UnixStream::pair().unwrap();
        use std::io::Write;
        peer.write_all(&crate::control_encode_host_msg(&HostMsg::Setup {
            region_len: 4096,
        }))
        .unwrap();
        let mut lifecycle = ControlLifecycleStream::connected_unix_stream(socket).unwrap();
        let mut received = SetupReceiveJournal::new();
        let mut budget = budget();

        assert_eq!(
            lifecycle.plugin_recv_setup_journal_step(&mut received, &mut budget, 0),
            Err(BoundedSetupError::Lifecycle)
        );
        assert!(received.retained_prefix().is_empty());
        assert_eq!(budget.counters().read_attempts, 0);
        assert_eq!(lifecycle.state(), ControlLifecycleState::Connected);
    }
}
