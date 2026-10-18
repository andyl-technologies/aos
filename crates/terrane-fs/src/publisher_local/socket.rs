//! Owns Linux authenticated sequenced-packet sockets and ancillary descriptors.
//!
//! No raw descriptor is exposed before kernel peer authentication. Rejected
//! packets drop every received descriptor, including on ancillary truncation.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::File,
    io::{self, IoSlice},
    mem::{self, MaybeUninit},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    path::{Component, Path},
    sync::Mutex,
    time::Duration,
};

use prost::Message;
use rustix::{
    fs::{AtFlags, Mode, OFlags},
    net::{self, AddressFamily, SocketFlags, SocketType},
};

use super::{
    Error,
    validation::{MAX_PACKET, ValidationPolicy, decode_envelope, validate_packet},
    wire::Packet,
};

/// Configured, distinct Unix role identities.
#[derive(Clone, Copy, Debug)]
pub struct RoleIdentities {
    /// The request-sending cache owner.
    pub serve_uid: u32,
    /// The sole native publication owner.
    pub publish_uid: u32,
}

impl RoleIdentities {
    fn check(self) -> Result<(), Error> {
        if self.serve_uid == self.publish_uid {
            return Err(Error::Invalid("roles must use distinct identities"));
        }
        Ok(())
    }
}

/// An owned packet whose descriptors remain in transport custody until dispatch.
pub struct ReceivedPacket {
    /// The validated registered command or reply.
    pub packet: Packet,
    /// The operation's ordered, close-on-exec, read-only regular files.
    pub files: Vec<File>,
}

/// An authenticated connected local socket; it cannot be cloned or exported.
pub struct Connection {
    descriptor: OwnedFd,
    receives_responses: bool,
    active: Mutex<BTreeMap<u64, Packet>>,
}

/// A publisher listener bound beneath a protected configured parent directory.
pub struct Listener {
    descriptor: OwnedFd,
    identities: RoleIdentities,
    // Retaining every ancestor prevents configuration from losing custody.
    _directories: Vec<OwnedFd>,
    _socket_node: OwnedFd,
}

/// Retains checked socket ancestry before native startup can allocate.
///
/// The listener independently rechecks this ancestry at actual bind. This
/// custody permits whole-service startup checks without creating a socket.
///
/// # Errors
///
/// Rejects invalid identities, another process identity, an invalid Unix address
/// or any unsafe/missing ancestor directory.
pub(crate) fn retain_listener_parent(
    path: &Path,
    identities: RoleIdentities,
) -> Result<Vec<OwnedFd>, Error> {
    identities.check()?;
    if rustix::process::geteuid().as_raw() != identities.publish_uid {
        return Err(Error::Denied);
    }
    net::SocketAddrUnix::new(path)?;
    protect_parent(path, identities.publish_uid)
}

impl Listener {
    /// Binds the configured socket as the publisher identity.
    ///
    /// The parent and ancestors must be real directories owned by root or the
    /// publisher and writable by neither groups nor other users. Existing
    /// socket names are never removed or replaced by this constructor. The
    /// newly bound socket inode receives mode 0660; its protected setgid
    /// parent selects the configured shared peer group.
    ///
    /// # Errors
    ///
    /// Rejects role collisions, the wrong process identity, unsafe ancestors,
    /// invalid socket paths and kernel bind/listen failures. Retained-inode
    /// permission changes require kernel fchmodat2 support and the audited
    /// x86/x86_64 syscall binding; other architectures return Unsupported.
    pub fn bind(path: &Path, identities: RoleIdentities) -> Result<Self, Error> {
        let directories = retain_listener_parent(path, identities)?;
        let descriptor = new_socket()?;
        net::bind(&descriptor, &net::SocketAddrUnix::new(path)?)?;
        let parent = directories.last().ok_or(Error::Invalid("socket parent"))?;
        let name = path.file_name().ok_or(Error::Invalid("socket name"))?;
        let socket_node = rustix::fs::openat(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        set_bound_socket_mode(parent, name, &socket_node, identities.publish_uid)?;
        net::listen(&descriptor, 32)?;
        Ok(Self {
            descriptor,
            identities,
            _directories: directories,
            _socket_node: socket_node,
        })
    }

    /// Accepts and authenticates a serve-role connection before receiving data.
    ///
    /// # Errors
    ///
    /// Returns an error for kernel accept failures or a peer outside the
    /// configured serve identity. Unauthorized connections close immediately.
    pub fn accept(&self) -> Result<Connection, Error> {
        let descriptor = net::accept_with(&self.descriptor, SocketFlags::CLOEXEC)?;
        authenticate(&descriptor, self.identities.serve_uid)?;
        Ok(Connection {
            descriptor,
            receives_responses: false,
            active: Mutex::new(BTreeMap::new()),
        })
    }
}

/// Changes only the retained bound inode, then verifies its configured name.
fn set_bound_socket_mode(
    parent: &OwnedFd,
    name: &OsStr,
    node: &OwnedFd,
    publisher_uid: u32,
) -> Result<(), Error> {
    let parent_stat = rustix::fs::fstat(parent)?;
    // Linux inherits the parent's group under setgid; otherwise bind uses the
    // process group. Do not silently accept a substituted socket's group.
    let expected_gid = if parent_stat.st_mode & 0o2000 != 0 {
        parent_stat.st_gid
    } else {
        rustix::process::getegid().as_raw()
    };
    let before = rustix::fs::fstat(node)?;
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::Socket
        || before.st_uid != publisher_uid
        || before.st_gid != expected_gid
        || before.st_nlink != 1
    {
        return Err(Error::Invalid("bound socket custody"));
    }
    let named_before = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    check_bound_socket(&before, &named_before, publisher_uid, expected_gid, false)?;

    // Pinned rustix's linux_raw chmodat rejects EMPTY_PATH before entering the
    // kernel. fchmodat2 supports it for this O_PATH socket inode; pathname chmod
    // would reintroduce a replacement race. Keep private-file umask unchanged.
    chmod_retained_socket(node.as_fd())?;

    let retained = rustix::fs::fstat(node)?;
    let named = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    check_bound_socket(&before, &retained, publisher_uid, expected_gid, true)?;
    check_bound_socket(&before, &named, publisher_uid, expected_gid, true)?;
    Ok(())
}

fn check_bound_socket(
    original: &rustix::fs::Stat,
    actual: &rustix::fs::Stat,
    publisher_uid: u32,
    expected_gid: u32,
    require_mode: bool,
) -> Result<(), Error> {
    if actual.st_dev != original.st_dev
        || actual.st_ino != original.st_ino
        || actual.st_uid != publisher_uid
        || actual.st_gid != expected_gid
        || rustix::fs::FileType::from_raw_mode(actual.st_mode) != rustix::fs::FileType::Socket
        || actual.st_nlink != 1
        || require_mode && actual.st_mode & 0o7777 != 0o660
    {
        return Err(Error::Invalid("bound socket replaced or custody changed"));
    }
    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn chmod_retained_socket(node: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: SYS_fchmodat2 fixes the native Linux ABI. The borrowed descriptor
    // remains live and refers to the checked original socket inode. c"" is a
    // static NUL-terminated empty pathname, AT_EMPTY_PATH selects that inode,
    // and mode_t(0660) contains only fixed permission bits. No memory is written.
    let result = unsafe {
        libc::syscall(
            libc::SYS_fchmodat2,
            node.as_raw_fd(),
            c"".as_ptr(),
            0o660 as libc::mode_t,
            libc::AT_EMPTY_PATH,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn chmod_retained_socket(_node: BorrowedFd<'_>) -> io::Result<()> {
    // Pinned libc does not expose SYS_fchmodat2 uniformly across Linux targets.
    // Only x86/x86_64 are audited here. Preserve compilation elsewhere without
    // guessing a native ABI or using a pathname fallback.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "retained socket chmod requires an audited fchmodat2 syscall binding",
    ))
}

impl Connection {
    /// Connects as serve and independently authenticates the publisher peer.
    ///
    /// # Errors
    ///
    /// Rejects the wrong local identity, unsafe socket ancestors, a mismatched
    /// publisher peer and kernel connection failures.
    pub fn connect(path: &Path, identities: RoleIdentities) -> Result<Self, Error> {
        Self::connect_with_timeout(path, identities, None)
    }

    pub(super) fn connect_timed(
        path: &Path,
        identities: RoleIdentities,
        timeout: Duration,
    ) -> Result<Self, Error> {
        if timeout.is_zero() {
            return Err(Error::Invalid("zero socket timeout"));
        }
        Self::connect_with_timeout(path, identities, Some(timeout))
    }

    fn connect_with_timeout(
        path: &Path,
        identities: RoleIdentities,
        timeout: Option<Duration>,
    ) -> Result<Self, Error> {
        identities.check()?;
        if rustix::process::geteuid().as_raw() != identities.serve_uid {
            return Err(Error::Denied);
        }
        let _directories = protect_parent(path, identities.publish_uid)?;
        let descriptor = new_socket()?;
        if let Some(timeout) = timeout {
            net::sockopt::set_socket_timeout(
                &descriptor,
                net::sockopt::Timeout::Recv,
                Some(timeout),
            )?;
            net::sockopt::set_socket_timeout(
                &descriptor,
                net::sockopt::Timeout::Send,
                Some(timeout),
            )?;
        }
        net::connect(&descriptor, &net::SocketAddrUnix::new(path)?)?;
        authenticate(&descriptor, identities.publish_uid)?;
        Ok(Self {
            descriptor,
            receives_responses: true,
            active: Mutex::new(BTreeMap::new()),
        })
    }

    /// Receives one bounded, strictly validated packet and its ordered files.
    ///
    /// # Errors
    ///
    /// Rejects disconnects, truncated payloads or ancillary data, unregistered
    /// ancillary types, excess descriptors, writable/nonregular sources and
    /// any protocol validation failure. Rejected files are always closed.
    pub fn receive(&self, policy: &ValidationPolicy<'_>) -> Result<ReceivedPacket, Error> {
        self.receive_selected(std::slice::from_ref(policy))
    }

    /// Receives a packet for exactly one configured domain, without fallback.
    ///
    /// # Errors
    ///
    /// Rejects unknown or duplicate domain policies, malformed packets and
    /// invalid descriptors. Every rejected received descriptor closes before
    /// any native command can be selected or executed.
    pub fn receive_selected(
        &self,
        policies: &[ValidationPolicy<'_>],
    ) -> Result<ReceivedPacket, Error> {
        let (bytes, descriptors) = receive_record(&self.descriptor)?;
        let packet = decode_envelope(&bytes)?;
        let mut matching = policies
            .iter()
            .filter(|policy| policy.domain == packet.domain);
        let policy = matching.next().ok_or(Error::Denied)?;
        if matching.next().is_some() {
            return Err(Error::Invalid("duplicate domain policy"));
        }
        validate_packet(&packet, descriptors.len(), self.receives_responses, policy)?;
        let mut files = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            validate_source(&descriptor)?;
            files.push(File::from(descriptor));
        }
        if self.receives_responses {
            self.finish_response(&packet)?;
        } else {
            self.register_request(&packet)?;
        }
        Ok(ReceivedPacket { packet, files })
    }

    /// Sends one bounded packet without transferring local descriptor ownership.
    ///
    /// # Errors
    ///
    /// Rejects invalid direction, packet combinations, writable/nonregular
    /// descriptors, excess payload and kernel send failures.
    pub fn send(
        &self,
        packet: &Packet,
        files: &[BorrowedFd<'_>],
        policy: &ValidationPolicy<'_>,
    ) -> Result<(), Error> {
        validate_packet(packet, files.len(), !self.receives_responses, policy)?;
        for descriptor in files {
            validate_source(descriptor)?;
        }
        let bytes = packet.encode_to_vec();
        if bytes.len() > MAX_PACKET {
            return Err(Error::Invalid("packet length"));
        }
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = net::SendAncillaryBuffer::new(&mut space);
        if !files.is_empty() && !ancillary.push(net::SendAncillaryMessage::ScmRights(files)) {
            return Err(Error::Invalid("outgoing ancillary size"));
        }
        if self.receives_responses {
            self.register_request(packet)?;
        } else {
            self.finish_response(packet)?;
        }
        let sent = net::sendmsg(
            &self.descriptor,
            &[IoSlice::new(&bytes)],
            &mut ancillary,
            net::SendFlags::NOSIGNAL,
        );
        if sent.as_ref().is_err() && self.receives_responses {
            self.active
                .lock()
                .map_err(|_| Error::Invalid("poisoned request registry"))?
                .remove(&packet.request_id);
        }
        if sent? != bytes.len() {
            return Err(Error::Invalid("partial sequenced packet"));
        }
        Ok(())
    }
    fn register_request(&self, packet: &Packet) -> Result<(), Error> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::Invalid("poisoned request registry"))?;
        if active.contains_key(&packet.request_id) || active.len() >= 64 {
            return Err(Error::Invalid("duplicate or excessive active requests"));
        }
        active.insert(packet.request_id, packet.clone());
        Ok(())
    }

    fn finish_response(&self, packet: &Packet) -> Result<(), Error> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::Invalid("poisoned request registry"))?;
        let request = active
            .get(&packet.request_id)
            .ok_or(Error::Invalid("unsolicited response"))?;
        if packet.operation != request.operation
            || packet.domain != request.domain
            || packet.cache_incarnation != request.cache_incarnation
            || packet.version != request.version
        {
            return Err(Error::Invalid("response correlation"));
        }
        if packet.result == 0 && packet.operation == super::wire::Operation::InspectBody as i32 {
            let sealed = request
                .body
                .as_ref()
                .is_some_and(|body| body.kind == super::wire::BodyKind::Sealed as i32);
            if sealed != (packet.verity_algorithm != 0) {
                return Err(Error::Invalid("inspect response binding"));
            }
        }
        active.remove(&packet.request_id);
        Ok(())
    }
}

fn new_socket() -> Result<OwnedFd, Error> {
    Ok(net::socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

fn authenticate(descriptor: &OwnedFd, expected_uid: u32) -> Result<(), Error> {
    let peer = net::sockopt::socket_peercred(descriptor)?;
    if peer.uid.as_raw() != expected_uid {
        return Err(Error::Denied);
    }
    Ok(())
}

fn protect_parent(path: &Path, publisher_uid: u32) -> Result<Vec<OwnedFd>, Error> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(Error::Invalid("socket path"));
    }
    let parent = path.parent().ok_or(Error::Invalid("socket parent"))?;
    let mut directories = vec![rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?];
    for component in parent.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let previous = directories
                    .last()
                    .ok_or(Error::Invalid("socket ancestor"))?;
                let directory = rustix::fs::openat(
                    previous,
                    name,
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                directories.push(directory);
            }
            _ => return Err(Error::Invalid("socket parent component")),
        }
    }
    for directory in &directories {
        let stat = rustix::fs::fstat(directory)?;
        if stat.st_uid != 0 && stat.st_uid != publisher_uid || stat.st_mode & 0o022 != 0 {
            return Err(Error::Invalid("unprotected socket parent"));
        }
    }
    Ok(directories)
}

fn validate_source(descriptor: impl AsFd) -> Result<(), Error> {
    let flags = rustix::fs::fcntl_getfl(&descriptor)?;
    let stat = rustix::fs::fstat(&descriptor)?;
    if flags.contains(OFlags::PATH)
        || flags.intersects(OFlags::WRONLY | OFlags::RDWR)
        || rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
    {
        return Err(Error::Invalid("descriptor must be read-only regular file"));
    }
    Ok(())
}

fn receive_record(descriptor: &OwnedFd) -> Result<(Vec<u8>, Vec<OwnedFd>), Error> {
    receive_record_with_space::<136>(descriptor)
}

fn receive_record_with_space<const WORDS: usize>(
    descriptor: &OwnedFd,
) -> Result<(Vec<u8>, Vec<OwnedFd>), Error> {
    let mut bytes = vec![0u8; MAX_PACKET];
    // Linux accepts at most 253 rights per sendmsg. Receive all of them so a
    // malformed count still has explicit RAII custody before rejection.
    let mut ancillary = [0usize; WORDS];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: msghdr is a C structure for which all-zero is a valid empty state.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = mem::size_of_val(&ancillary);

    // SAFETY: all msghdr pointers reference live writable buffers of the declared
    // lengths; the socket remains owned throughout this blocking syscall.
    let count =
        unsafe { libc::recvmsg(descriptor.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if count < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut descriptors = Vec::new();
    let mut invalid_ancillary = false;
    // SAFETY: recvmsg initialized the ancillary bytes and its header length;
    // CMSG traversal checks boundaries against that returned length.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        // SAFETY: CMSG_FIRSTHDR/CMSG_NXTHDR return aligned in-buffer headers.
        let value = unsafe { &*header };
        // SAFETY: CMSG_LEN(0) only computes the platform header alignment.
        let header_length = unsafe { libc::CMSG_LEN(0) } as usize;
        if value.cmsg_len < header_length {
            invalid_ancillary = true;
            break;
        }
        if value.cmsg_level == libc::SOL_SOCKET && value.cmsg_type == libc::SCM_RIGHTS {
            let length = value.cmsg_len - header_length;
            if !length.is_multiple_of(mem::size_of::<libc::c_int>()) {
                invalid_ancillary = true;
            }
            for index in 0..length / mem::size_of::<libc::c_int>() {
                // SAFETY: SCM_RIGHTS contains kernel-installed integer file
                // descriptors, each transferred exactly once into OwnedFd.
                let raw = unsafe {
                    libc::CMSG_DATA(header)
                        .cast::<libc::c_int>()
                        .add(index)
                        .read_unaligned()
                };
                // SAFETY: each received SCM_RIGHTS descriptor is new owned custody.
                descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        } else {
            invalid_ancillary = true;
        }
        // SAFETY: the current header belongs to message's returned control range.
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if count == 0 {
        return Err(
            io::Error::new(io::ErrorKind::UnexpectedEof, "publisher peer disconnected").into(),
        );
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || invalid_ancillary
        || descriptors.len() > 2
    {
        return Err(Error::Invalid("truncated or invalid ancillary packet"));
    }
    bytes.truncate(count as usize);
    Ok((bytes, descriptors))
}

#[cfg(test)]
#[path = "socket_tests.rs"]
mod tests;
