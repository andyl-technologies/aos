//! Binds maintenance connections beneath a retained protected operator path.

use super::{MaintenanceClient, MaintenanceRoles, MaintenanceServer, wire::invalid};
use crate::publisher_local::socket::{protect_parent, set_bound_socket_mode};
use rustix::{
    fs::{AtFlags, FileType, Mode, OFlags},
    net::{self, AddressFamily, SocketFlags, SocketType},
};
use std::{
    ffi::OsString,
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
};

/// Owns a protected nonblocking GC listener as the configured serving identity.
///
/// The operator creates the protected parent before startup. Its setgid group
/// permits the configured GC role to reach the mode-0660 socket; private cache
/// state permissions remain independent. Binding never replaces existing names.
/// Dropping the listener closes it without deleting its pathname; orderly
/// shutdown uses [`Self::retire`] after joining every borrowed service future.
pub struct MaintenanceListener {
    socket: OwnedFd,
    roles: MaintenanceRoles,
    directories: Vec<OwnedFd>,
    node: OwnedFd,
    name: OsString,
    group: u32,
}

impl MaintenanceListener {
    pub(super) fn descriptor(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }

    pub(super) fn check_current(&self) -> io::Result<()> {
        self.roles.check(self.roles.serve_uid)
    }

    /// Binds the configured path while retaining and checking its original inode.
    ///
    /// Reuses the publisher listener's audited ancestor and retained-inode mode
    /// checks. This creates no publisher session, owner or repository authority.
    /// Kernel credentials are enabled before connections can queue requests.
    ///
    /// # Errors
    /// Refuses incorrect or colliding role identities, unsafe ancestors, existing
    /// names, unsupported retained-inode chmod, substituted socket custody and
    /// native bind, option or listen failures.
    pub fn bind(path: &Path, roles: MaintenanceRoles) -> io::Result<Self> {
        roles.check(roles.serve_uid)?;
        let directories = protect_parent(path, roles.serve_uid).map_err(io::Error::other)?;
        let socket = new_socket()?;
        net::bind(&socket, &net::SocketAddrUnix::new(path)?)?;
        let parent = directories
            .last()
            .ok_or_else(|| invalid("maintenance socket parent absent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("maintenance socket name absent"))?;
        let node = rustix::fs::openat(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        set_bound_socket_mode(parent, name, &node, roles.serve_uid).map_err(io::Error::other)?;
        let group = rustix::fs::fstat(&node)?.st_gid;
        net::listen(&socket, 32)?;
        Ok(Self {
            socket,
            roles,
            directories,
            node,
            name: name.to_owned(),
            group,
        })
    }

    /// Closes the listener and removes its checked original socket name.
    ///
    /// Callers first stop and join all borrowed accept/request futures. Connected
    /// endpoints retain their own custody; unlinking grants no cache release
    /// authority. The retained parent anchors removal even if an ancestor moves.
    /// Only root and the configured serving UID may write that protected parent;
    /// another process using that UID shares the service's administrative trust.
    /// Failed startup and ordinary drop deliberately leave names for diagnosis.
    ///
    /// # Errors
    /// Refuses changed credentials, unsafe retained ancestors, a missing or
    /// substituted socket, changed type, ownership, links or mode, and native
    /// metadata or removal failures.
    /// A refusal closes the listener and leaves the named replacement untouched.
    pub fn retire(self) -> io::Result<()> {
        let Self {
            socket,
            roles,
            directories,
            node,
            name,
            group,
        } = self;
        drop(socket);
        roles.check(roles.serve_uid)?;

        for directory in &directories {
            let metadata = rustix::fs::fstat(directory)?;
            if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
                || ![0, roles.serve_uid].contains(&metadata.st_uid)
                || metadata.st_mode & 0o022 != 0
                || metadata.st_nlink == 0
            {
                return Err(invalid("maintenance socket ancestor custody changed"));
            }
        }

        let parent = directories
            .last()
            .ok_or_else(|| invalid("maintenance socket parent absent"))?;
        let original = rustix::fs::fstat(&node)?;
        let named = rustix::fs::statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(original.st_mode) != FileType::Socket
            || original.st_uid != roles.serve_uid
            || original.st_gid != group
            || original.st_nlink != 1
            || original.st_mode & 0o7777 != 0o660
            || original.st_dev != named.st_dev
            || original.st_ino != named.st_ino
            || original.st_mode != named.st_mode
            || original.st_uid != named.st_uid
            || original.st_gid != named.st_gid
            || original.st_nlink != named.st_nlink
        {
            return Err(invalid("maintenance socket retirement custody changed"));
        }
        rustix::fs::unlinkat(parent, &name, AtFlags::empty())?;
        Ok(())
    }

    /// Accepts an actual GC connection without blocking or reading request data.
    ///
    /// Returns `None` when the accept queue is empty. Every accepted endpoint
    /// checks the connected kernel UID before constructing a maintenance server;
    /// subsequent packets independently check their sending kernel credentials.
    /// Callers separately bound their total active connections and deadlines.
    ///
    /// # Errors
    /// Refuses another peer identity, changed serving identity and native accept
    /// or socket-option failures. Refused endpoints close immediately.
    pub fn accept(&self) -> io::Result<Option<MaintenanceServer>> {
        self.roles.check(self.roles.serve_uid)?;
        let socket =
            match net::accept_with(&self.socket, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
                Err(error) if error == rustix::io::Errno::WOULDBLOCK => return Ok(None),
                result => result?,
            };
        authenticate(&socket, self.roles.gc_uid)?;
        MaintenanceServer::bind(socket, self.roles).map(Some)
    }
}

impl MaintenanceClient {
    /// Connects to the configured serving identity beneath protected ancestors.
    ///
    /// This method performs no maintenance or private cache-state access. The
    /// connected peer's kernel UID is checked before the client can send a
    /// request. A full listener backlog returns an error without retaining an
    /// incomplete connection; the caller supplies a finite retry policy.
    ///
    /// # Errors
    /// Refuses incorrect or colliding role identities, unsafe ancestors, a
    /// disconnected or foreign listener and native socket or connect failures.
    pub fn connect(path: &Path, roles: MaintenanceRoles) -> io::Result<Self> {
        roles.check(roles.gc_uid)?;
        let _directories = protect_parent(path, roles.serve_uid).map_err(io::Error::other)?;
        let socket = new_socket()?;
        net::connect(&socket, &net::SocketAddrUnix::new(path)?)?;
        authenticate(&socket, roles.serve_uid)?;
        Self::bind(socket, roles)
    }
}

fn new_socket() -> io::Result<OwnedFd> {
    let socket = net::socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    net::sockopt::set_socket_passcred(&socket, true)?;
    Ok(socket)
}

fn authenticate(socket: &OwnedFd, expected_uid: u32) -> io::Result<()> {
    if net::sockopt::socket_peercred(socket)?.uid.as_raw() != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "maintenance connected role identity refused",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
