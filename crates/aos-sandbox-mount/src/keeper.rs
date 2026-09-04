//! Restart-safe custody for detached mount descriptors.
//!
//! [`SystemdFdStore`] implements the systemd file-descriptor-store protocol
//! directly over `NOTIFY_SOCKET`. A successful mutation includes a systemd
//! barrier, so callers may durably record the mutation only after PID 1 has
//! consumed the preceding notification. Descriptors returned through socket
//! activation are adopted into [`ImportedKernelMount`] values with strict
//! names and close-on-exec semantics.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix,
    SocketFlags, SocketType, recv, sendmsg_addr, socket_with, socketpair,
};

use crate::{MountError, Result};

const ACTIVATION_FD_BASE: RawFd = 3;
const NAME_PREFIX: &str = "aos-mount-v1-";
const DIGEST_HEX_LENGTH: usize = 64;
const MAXIMUM_IMPORTED_DESCRIPTORS: usize = 1_024;
const BARRIER_TIMEOUT: Duration = Duration::from_secs(5);

/// An opaque, versioned name used to associate a descriptor with durable state.
///
/// Names have the exact form `aos-mount-v1-` followed by 64 lowercase
/// hexadecimal digits. Keeping the accepted language this narrow makes names
/// safe both in systemd's newline protocol and in colon-separated
/// `LISTEN_FDNAMES`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KernelMountName(String);

impl KernelMountName {
    /// Constructs a stable opaque name from a 256-bit resource digest.
    #[must_use]
    pub fn from_digest(digest: [u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity(NAME_PREFIX.len() + DIGEST_HEX_LENGTH);
        name.push_str(NAME_PREFIX);
        for byte in digest {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self(name)
    }

    /// Parses an exact systemd descriptor-store name.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown version, wrong length, uppercase digit,
    /// delimiter, control byte, or any non-hexadecimal suffix byte.
    pub fn parse(value: &str) -> Result<Self> {
        let suffix = value
            .strip_prefix(NAME_PREFIX)
            .ok_or_else(|| state_error("descriptor-store name has an unknown prefix"))?;
        if suffix.len() != DIGEST_HEX_LENGTH
            || !suffix
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(state_error("descriptor-store name is not canonical"));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact name transmitted to and restored by systemd.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Owns one mount descriptor returned by the configured kernel descriptor keeper.
#[derive(Debug)]
pub struct ImportedKernelMount {
    name: KernelMountName,
    descriptor: OwnedFd,
}

impl ImportedKernelMount {
    /// Returns the durable name associated with this descriptor.
    #[must_use]
    pub fn name(&self) -> &KernelMountName {
        &self.name
    }

    /// Borrows the close-on-exec kernel descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }

    /// Splits the typed value into its durable name and owned descriptor.
    #[must_use]
    pub fn into_parts(self) -> (KernelMountName, OwnedFd) {
        (self.name, self.descriptor)
    }
}

/// Provides synchronous restart-safe custody for kernel mount descriptors.
pub trait KernelMountStore {
    /// Stores a duplicate of `descriptor` under `name` and waits for acceptance.
    ///
    /// Implementations must not consume the caller's descriptor. Returning
    /// success means the keeper acknowledged all notifications issued before
    /// the operation's barrier.
    ///
    /// # Errors
    ///
    /// Returns an error when the keeper cannot accept or acknowledge the
    /// descriptor.
    fn store(&self, name: &KernelMountName, descriptor: BorrowedFd<'_>) -> Result<()>;

    /// Removes all descriptors stored under `name` and waits for acceptance.
    ///
    /// # Errors
    ///
    /// Returns an error when the keeper cannot accept or acknowledge removal.
    fn remove(&self, name: &KernelMountName) -> Result<()>;
}

/// Uses systemd's service-manager descriptor store as restart-safe custody.
#[derive(Debug)]
pub struct SystemdFdStore {
    socket: OwnedFd,
    notify_address: SocketAddrUnix,
}

impl SystemdFdStore {
    /// Connects a keeper to the `NOTIFY_SOCKET` supplied by systemd.
    ///
    /// Filesystem and Linux abstract-namespace notification sockets are
    /// accepted. This does not adopt activation descriptors; call
    /// [`Self::adopt_activation`] during single-threaded process startup.
    ///
    /// # Errors
    ///
    /// Returns an error if `NOTIFY_SOCKET` is absent, non-Unicode, empty,
    /// malformed, too long, or a notification datagram socket cannot be made.
    pub fn from_environment() -> Result<Self> {
        let value = std::env::var_os("NOTIFY_SOCKET")
            .ok_or_else(|| state_error("NOTIFY_SOCKET is absent"))?;
        Self::from_notify_socket(&value)
    }

    /// Adopts systemd file-descriptor-store entries after caller-owned sockets.
    ///
    /// `reserved_descriptors` is the count of leading activation descriptors
    /// consumed by other subsystems, normally the service's listening socket.
    /// `LISTEN_PID`, `LISTEN_FDS`, and `LISTEN_FDNAMES` must describe this exact
    /// process and every inherited descriptor. The imported tail is limited to
    /// `maximum_imported`, and names must be unique canonical mount names.
    ///
    /// This function must run before threads are created and before any code
    /// closes or reallocates descriptors beginning at FD 3. It deliberately
    /// leaves the activation environment intact; child processes must receive
    /// an explicitly sanitized environment.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched activation metadata, a count above the
    /// configured or hard ceiling, duplicate/invalid names, descriptor-number
    /// overflow, or inability to set close-on-exec.
    pub fn adopt_activation(
        reserved_descriptors: usize,
        maximum_imported: usize,
    ) -> Result<Vec<ImportedKernelMount>> {
        if maximum_imported > MAXIMUM_IMPORTED_DESCRIPTORS {
            return Err(state_error("descriptor import ceiling exceeds hard limit"));
        }
        let listen_pid = environment_u32("LISTEN_PID")?;
        let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
            .map_err(|_| state_error("current PID does not fit u32"))?;
        if listen_pid != current_pid {
            return Err(state_error("LISTEN_PID does not name this process"));
        }

        let descriptor_count = environment_usize("LISTEN_FDS")?;
        if descriptor_count < reserved_descriptors {
            return Err(state_error("LISTEN_FDS omits reserved descriptors"));
        }
        let imported_count = descriptor_count - reserved_descriptors;
        if imported_count > maximum_imported {
            return Err(state_error("too many descriptor-store entries"));
        }

        let names = std::env::var("LISTEN_FDNAMES")
            .map_err(|_| state_error("LISTEN_FDNAMES is absent or non-Unicode"))?;
        let names: Vec<&str> = names.split(':').collect();
        if names.len() != descriptor_count {
            return Err(state_error("LISTEN_FDNAMES count differs from LISTEN_FDS"));
        }
        let imported_names = names
            .into_iter()
            .skip(reserved_descriptors)
            .map(KernelMountName::parse)
            .collect::<Result<Vec<_>>>()?;
        let unique_names: BTreeSet<_> = imported_names.iter().collect();
        if unique_names.len() != imported_names.len() {
            return Err(state_error("duplicate descriptor-store name"));
        }

        let first_index = ACTIVATION_FD_BASE
            .checked_add(raw_fd_from_usize(reserved_descriptors)?)
            .ok_or_else(|| state_error("activation descriptor number overflow"))?;
        let mut descriptors = Vec::with_capacity(imported_count);
        for offset in 0..imported_count {
            let raw = first_index
                .checked_add(raw_fd_from_usize(offset)?)
                .ok_or_else(|| state_error("activation descriptor number overflow"))?;
            // SAFETY: the validated systemd activation contract transfers each
            // descriptor in the contiguous FD 3 range exactly once. The loop
            // visits each imported tail descriptor once and immediately stores
            // it in an `OwnedFd`.
            descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
        }

        let mut imported = Vec::with_capacity(imported_count);
        for (name, descriptor) in imported_names.into_iter().zip(descriptors) {
            ensure_cloexec(descriptor.as_fd())?;
            imported.push(ImportedKernelMount { name, descriptor });
        }
        Ok(imported)
    }

    fn from_notify_socket(value: &OsStr) -> Result<Self> {
        let value = value
            .to_str()
            .ok_or_else(|| state_error("NOTIFY_SOCKET is not Unicode"))?;
        if value.is_empty() {
            return Err(state_error("NOTIFY_SOCKET is empty"));
        }
        let notify_address = if let Some(abstract_name) = value.strip_prefix('@') {
            if abstract_name.is_empty() {
                return Err(state_error("NOTIFY_SOCKET abstract name is empty"));
            }
            SocketAddrUnix::new_abstract_name(abstract_name.as_bytes())
        } else {
            SocketAddrUnix::new(Path::new(value))
        }
        .map_err(notify_error)?;
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(notify_error)?;
        Ok(Self {
            socket,
            notify_address,
        })
    }

    fn notify(&self, payload: &[u8], descriptor: Option<BorrowedFd<'_>>) -> Result<()> {
        let iov = [IoSlice::new(payload)];
        let borrowed = descriptor.into_iter().collect::<Vec<_>>();
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        if !borrowed.is_empty() && !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
            return Err(state_error("notification ancillary buffer is exhausted"));
        }
        let written = sendmsg_addr(
            &self.socket,
            &self.notify_address,
            &iov,
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .map_err(notify_error)?;
        if written != payload.len() {
            return Err(state_error("systemd notification was partially written"));
        }
        Ok(())
    }

    fn barrier(&self) -> Result<()> {
        let (waiter, manager_end) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(notify_error)?;
        set_socket_timeout(&waiter, Timeout::Recv, Some(BARRIER_TIMEOUT)).map_err(notify_error)?;
        self.notify(b"BARRIER=1", Some(manager_end.as_fd()))?;
        drop(manager_end);

        let mut byte = [0_u8; 1];
        let (received, _) = recv(&waiter, &mut byte, RecvFlags::empty()).map_err(notify_error)?;
        if received != 0 {
            return Err(state_error("systemd barrier descriptor carried data"));
        }
        Ok(())
    }
}

impl KernelMountStore for SystemdFdStore {
    fn store(&self, name: &KernelMountName, descriptor: BorrowedFd<'_>) -> Result<()> {
        let payload = format!("FDSTORE=1\nFDPOLL=0\nFDNAME={}", name.as_str());
        self.notify(payload.as_bytes(), Some(descriptor))?;
        self.barrier()
    }

    fn remove(&self, name: &KernelMountName) -> Result<()> {
        let payload = format!("FDSTOREREMOVE=1\nFDNAME={}", name.as_str());
        self.notify(payload.as_bytes(), None)?;
        self.barrier()
    }
}

fn environment_u32(name: &'static str) -> Result<u32> {
    std::env::var(name)
        .map_err(|_| state_error(format!("{name} is absent or non-Unicode")))?
        .parse()
        .map_err(|_| state_error(format!("{name} is not a decimal u32")))
}

fn environment_usize(name: &'static str) -> Result<usize> {
    std::env::var(name)
        .map_err(|_| state_error(format!("{name} is absent or non-Unicode")))?
        .parse()
        .map_err(|_| state_error(format!("{name} is not a decimal usize")))
}

fn raw_fd_from_usize(value: usize) -> Result<RawFd> {
    RawFd::try_from(value).map_err(|_| state_error("activation descriptor number overflow"))
}

fn ensure_cloexec(fd: BorrowedFd<'_>) -> Result<()> {
    let flags = fcntl_getfd(fd).map_err(notify_error)?;
    fcntl_setfd(fd, flags | FdFlags::CLOEXEC).map_err(notify_error)
}

fn notify_error(error: rustix::io::Errno) -> MountError {
    state_error(format!("systemd descriptor store failed: {error}"))
}

fn state_error(message: impl Into<String>) -> MountError {
    MountError::State(message.into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::File;
    use std::io::IoSliceMut;
    use std::sync::mpsc;

    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, bind, recvmsg};

    use super::*;

    #[test]
    fn opaque_names_are_canonical_and_round_trip() {
        let name = KernelMountName::from_digest([0xab; 32]);
        assert_eq!(
            name.as_str(),
            "aos-mount-v1-abababababababababababababababababababababababababababababababab"
        );
        assert_eq!(KernelMountName::parse(name.as_str()).unwrap(), name);

        for invalid in [
            "aos-mount-v2-abababababababababababababababababababababababababababababababab",
            "aos-mount-v1-ABababababababababababababababababababababababababababababababab",
            "aos-mount-v1-abababababababababababababababababababababababababababababababag",
            "aos-mount-v1-abab",
            "aos-mount-v1-abababababababababababababababababababababababababababababababa:",
        ] {
            assert!(
                KernelMountName::parse(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn store_and_remove_are_barrier_ordered() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.sock");
        let server = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        bind(&server, &SocketAddrUnix::new(&path).unwrap()).unwrap();
        let keeper = SystemdFdStore::from_notify_socket(path.as_os_str()).unwrap();
        let descriptor: OwnedFd = File::open(directory.path()).unwrap().into();
        let name = KernelMountName::from_digest([7; 32]);
        let (sender, receiver) = mpsc::channel();

        let manager = std::thread::spawn(move || {
            let mut observed = Vec::new();
            for _ in 0..4 {
                let (payload, descriptors) = receive_notification(&server);
                observed.push((payload, descriptors.len()));
                drop(descriptors);
            }
            sender.send(observed).unwrap();
        });

        keeper.store(&name, descriptor.as_fd()).unwrap();
        keeper.remove(&name).unwrap();
        manager.join().unwrap();
        let observed = receiver.recv().unwrap();
        assert_eq!(
            observed,
            vec![
                (format!("FDSTORE=1\nFDPOLL=0\nFDNAME={}", name.as_str()), 1),
                ("BARRIER=1".to_owned(), 1),
                (format!("FDSTOREREMOVE=1\nFDNAME={}", name.as_str()), 0),
                ("BARRIER=1".to_owned(), 1),
            ]
        );
        assert!(fcntl_getfd(&descriptor).unwrap().contains(FdFlags::CLOEXEC));
    }

    fn receive_notification(socket: &OwnedFd) -> (String, Vec<OwnedFd>) {
        let mut payload = [0_u8; 256];
        let mut iov = [IoSliceMut::new(&mut payload)];
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut control_space);
        let message = recvmsg(socket, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC).unwrap();
        let bytes = message.bytes;
        let mut descriptors = Vec::new();
        for ancillary in control.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = ancillary {
                descriptors.extend(received);
            }
        }
        let payload = String::from_utf8(payload[..bytes].to_vec()).unwrap();
        for descriptor in &descriptors {
            assert!(fcntl_getfd(descriptor).unwrap().contains(FdFlags::CLOEXEC));
        }
        (payload, descriptors)
    }
}
