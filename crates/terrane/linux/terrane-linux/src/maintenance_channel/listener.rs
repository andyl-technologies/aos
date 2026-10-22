//! Binds maintenance connections beneath a retained protected operator path.

use super::{MaintenanceClient, MaintenanceRoles, MaintenanceServer, wire::invalid};
use crate::publisher_local::socket::{protect_parent, set_bound_socket_mode};
use rustix::{
    fs::{Mode, OFlags},
    net::{self, AddressFamily, SocketFlags, SocketType},
};
use std::{io, os::fd::OwnedFd, path::Path};

/// Owns a protected nonblocking GC listener as the configured serving identity.
///
/// The operator creates the protected parent before startup. Its setgid group
/// permits the configured GC role to reach the mode-0660 socket; private cache
/// state permissions remain independent. Existing names are never replaced or
/// removed. Dropping the listener closes it without deleting its pathname.
pub struct MaintenanceListener {
    socket: OwnedFd,
    roles: MaintenanceRoles,
    _directories: Vec<OwnedFd>,
    _node: OwnedFd,
}

impl MaintenanceListener {
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
        net::listen(&socket, 32)?;
        Ok(Self {
            socket,
            roles,
            _directories: directories,
            _node: node,
        })
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
