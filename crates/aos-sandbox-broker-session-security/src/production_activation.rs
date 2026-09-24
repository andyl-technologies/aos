//! Exact systemd activation ownership for authenticated broker sessions.
//!
//! The activation owner admits only the repository's fixed service profiles.
//! Storage, Mount, and Network each require one specifically named listener;
//! Host requires distinct controller and RootMount listeners so their signed
//! audiences, journals, and key custody cannot be confused. Accepted sockets
//! complete the fixed protected handshake before leaving this module.

mod host;

pub use host::{ProductionHostBrokerServiceErrorV1, ProductionHostBrokerServiceV1};

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_linux::inherited_fd::claim_systemd_activation_descriptor_range;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1,
    ProtectedBrokerSessionFixedCustodyV1, ProtectedBrokerSessionFixedEndpointV1,
};

const HOST_CONTROLLER_FD_NAME: &str = "aos-sandbox-host";
const HOST_ROOT_MOUNT_FD_NAME: &str = "aos-sandbox-host-root-mount";
const STORAGE_FD_NAME: &str = "aos-storaged";
const MOUNT_FD_NAME: &str = "aos-sandbox-mount";
const NETWORK_FD_NAME: &str = "aos-netd";

/// Reports rejection while adopting or accepting a fixed broker activation.
#[derive(Debug, thiserror::Error)]
pub enum ProductionBrokerSessionActivationErrorV1 {
    /// systemd did not supply the exact fixed descriptor table.
    #[error("broker-session systemd activation is invalid: {0}")]
    Activation(&'static str),
    /// Descriptor adoption or listener validation failed.
    #[error("broker-session listener is invalid: {0}")]
    Listener(#[from] SeqpacketError),
    /// The protected handshake rejected an accepted peer or local custody.
    #[error("broker-session handshake failed: {0}")]
    Handshake(#[from] DormantBrokerSessionHandshakeErrorV1),
    /// The next authenticated session did not arrive before its boot-time deadline.
    #[error("broker-session acceptance deadline expired")]
    Deadline,
    /// A kernel clock, poll, or activation-descriptor operation failed.
    #[error("broker-session activation kernel operation failed")]
    Kernel,
}

struct FixedListenerV1 {
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    listener: RecordSubjectListener,
}

/// Owns the complete fixed listener set for one production broker service.
///
/// Construction consumes systemd's descriptor table once during the
/// single-threaded startup interval. The owner is non-cloneable and keeps every
/// listener exclusively retained while accepting one authenticated session at
/// a time.
#[must_use = "retain the activation owner while accepting broker sessions"]
pub struct ProductionBrokerSessionActivationV1 {
    listeners: Vec<FixedListenerV1>,
}

impl core::fmt::Debug for ProductionBrokerSessionActivationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionBrokerSessionActivationV1")
            .field("listener_count", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

impl ProductionBrokerSessionActivationV1 {
    /// Adopts the controller-facing and RootMount-facing Host listeners.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded startup owner of systemd FDs 3
    /// and 4. No Rust owner, thread, signal handler, or concurrent operation may
    /// open, close, duplicate, or replace either descriptor until this returns.
    ///
    /// # Errors
    ///
    /// Returns an error unless systemd supplies exactly the two fixed named
    /// listeners with record-subject reporting enabled.
    pub unsafe fn adopt_host() -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        // SAFETY: forwarded from this method's exact startup ownership contract.
        unsafe {
            Self::adopt(&[
                (
                    HOST_CONTROLLER_FD_NAME,
                    ProtectedBrokerSessionFixedEndpointV1::HostBroker,
                ),
                (
                    HOST_ROOT_MOUNT_FD_NAME,
                    ProtectedBrokerSessionFixedEndpointV1::RootMountHostBroker,
                ),
            ])
        }
    }

    /// Adopts the sole fixed Storage listener.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded startup owner of systemd FD 3.
    /// No other owner or concurrent descriptor-table mutation may exist.
    ///
    /// # Errors
    ///
    /// Returns an error unless the exact named record-subject listener is present.
    pub unsafe fn adopt_storage() -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        // SAFETY: forwarded from this method's exact startup ownership contract.
        unsafe {
            Self::adopt(&[(
                STORAGE_FD_NAME,
                ProtectedBrokerSessionFixedEndpointV1::StorageBroker,
            )])
        }
    }

    /// Adopts the sole fixed Mount listener.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded startup owner of systemd FD 3.
    /// No other owner or concurrent descriptor-table mutation may exist.
    ///
    /// # Errors
    ///
    /// Returns an error unless the exact named record-subject listener is present.
    pub unsafe fn adopt_mount() -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        // SAFETY: forwarded from this method's exact startup ownership contract.
        unsafe {
            Self::adopt(&[(
                MOUNT_FD_NAME,
                ProtectedBrokerSessionFixedEndpointV1::MountBroker,
            )])
        }
    }

    /// Adopts the fixed Mount listener after the Mount FD store claims activation.
    ///
    /// The Mount service receives retained mount and source descriptors beside
    /// its listener. Its FD-store owner must claim and classify that complete
    /// systemd table first, then transfer only the named listener here. This
    /// constructor still requires the fixed pathname and record-subject socket
    /// options and cannot select another endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error unless `listener` is the fixed Mount filesystem
    /// listener with record-subject reporting enabled.
    pub fn adopt_mount_listener(
        listener: OwnedFd,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        Self::from_owned_listener(ProtectedBrokerSessionFixedEndpointV1::MountBroker, listener)
    }

    /// Adopts the fixed Network listener after the Network FD store claims activation.
    ///
    /// The Network service receives retained namespace descriptors beside its
    /// listener. Its FD-store owner must claim and classify that complete table
    /// first, then transfer only the typed listener here.
    ///
    /// # Errors
    ///
    /// Returns an error unless `listener` is the fixed Network filesystem
    /// listener with record-subject reporting enabled.
    pub fn adopt_network_listener(
        listener: RecordSubjectListener,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        let endpoint = ProtectedBrokerSessionFixedEndpointV1::NetworkBroker;
        listener.require_local_filesystem_path(Path::new(endpoint.production_socket_path()))?;
        Ok(Self {
            listeners: vec![FixedListenerV1 { endpoint, listener }],
        })
    }

    /// Adopts the sole fixed Network listener.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded startup owner of systemd FD 3.
    /// No other owner or concurrent descriptor-table mutation may exist.
    ///
    /// # Errors
    ///
    /// Returns an error unless the exact named record-subject listener is present.
    pub unsafe fn adopt_network() -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        // SAFETY: forwarded from this method's exact startup ownership contract.
        unsafe {
            Self::adopt(&[(
                NETWORK_FD_NAME,
                ProtectedBrokerSessionFixedEndpointV1::NetworkBroker,
            )])
        }
    }

    /// Accepts and authenticates the next session before a boot-time deadline.
    ///
    /// Host polls both audience-specific listeners and selects protected custody
    /// solely from the ready listener's fixed descriptor name. Callers cannot
    /// substitute an audience, protocol, socket path, journal, or key root.
    ///
    /// # Errors
    ///
    /// Returns an error for changed listener configuration, failed acceptance,
    /// expired polling, or any protected-handshake rejection.
    pub fn accept_authenticated(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1> {
        loop {
            self.wait_until_ready(deadline_boottime_nanoseconds)?;

            for fixed in &mut self.listeners {
                fixed.listener.validate_current()?;
                let socket = match fixed.listener.accept() {
                    Ok(socket) => socket,
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => continue,
                    Err(error) => return Err(error.into()),
                };
                let custody =
                    ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(fixed.endpoint)
                        .map_err(DormantBrokerSessionHandshakeErrorV1::Protected)?;
                return custody
                    .complete_production_broker_handshake(socket, deadline_boottime_nanoseconds)
                    .map_err(Into::into);
            }
        }
    }

    unsafe fn adopt(
        expected: &[(&'static str, ProtectedBrokerSessionFixedEndpointV1)],
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        validate_activation_process(expected.len())?;
        let names = activation_names(expected.len())?;
        // SAFETY: forwarded from each public constructor's exact ownership
        // contract after validating the complete systemd activation envelope.
        let descriptors = unsafe { claim_systemd_activation_descriptor_range(0, expected.len()) }
            .map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?
            .into_descriptors();
        let supplied = names
            .into_iter()
            .zip(descriptors)
            .collect::<BTreeMap<_, _>>();
        if supplied.len() != expected.len() {
            return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "descriptor names are duplicated",
            ));
        }

        let mut supplied = supplied;
        let mut listeners = Vec::with_capacity(expected.len());
        for (name, endpoint) in expected {
            let descriptor = supplied.remove(*name).ok_or(
                ProductionBrokerSessionActivationErrorV1::Activation(
                    "a fixed descriptor name is absent",
                ),
            )?;
            let listener = RecordSubjectListener::from_owned(descriptor)?;
            listener.require_local_filesystem_path(Path::new(endpoint.production_socket_path()))?;
            listeners.push(FixedListenerV1 {
                endpoint: *endpoint,
                listener,
            });
        }
        if !supplied.is_empty() {
            return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "an unexpected descriptor name is present",
            ));
        }

        Ok(Self { listeners })
    }

    fn from_owned_listener(
        endpoint: ProtectedBrokerSessionFixedEndpointV1,
        descriptor: OwnedFd,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        let listener = RecordSubjectListener::from_owned(descriptor)?;
        listener.require_local_filesystem_path(Path::new(endpoint.production_socket_path()))?;
        Ok(Self {
            listeners: vec![FixedListenerV1 { endpoint, listener }],
        })
    }

    fn wait_until_ready(
        &self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
        let remaining = remaining_duration(deadline_boottime_nanoseconds)?;
        let timeout = Timespec {
            tv_sec: i64::try_from(remaining / 1_000_000_000)
                .map_err(|_| ProductionBrokerSessionActivationErrorV1::Deadline)?,
            tv_nsec: i64::try_from(remaining % 1_000_000_000)
                .map_err(|_| ProductionBrokerSessionActivationErrorV1::Deadline)?,
        };
        let mut descriptors = self
            .listeners
            .iter()
            .map(|fixed| PollFd::from_borrowed_fd(fixed.listener.as_fd(), PollFlags::IN))
            .collect::<Vec<_>>();

        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => Err(ProductionBrokerSessionActivationErrorV1::Deadline),
            Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
            Err(_) => Err(ProductionBrokerSessionActivationErrorV1::Kernel),
        }
    }
}

pub(crate) fn validate_activation_process(
    expected_descriptors: usize,
) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
    let listen_pid = environment_u32("LISTEN_PID")?;
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?;
    if listen_pid != current_pid {
        return Err(ProductionBrokerSessionActivationErrorV1::Activation(
            "LISTEN_PID does not name this process",
        ));
    }
    if usize::try_from(environment_u32("LISTEN_FDS")?)
        .map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?
        != expected_descriptors
    {
        return Err(ProductionBrokerSessionActivationErrorV1::Activation(
            "LISTEN_FDS has the wrong fixed count",
        ));
    }
    Ok(())
}

pub(crate) fn activation_names(
    expected_descriptors: usize,
) -> Result<Vec<String>, ProductionBrokerSessionActivationErrorV1> {
    let names = std::env::var("LISTEN_FDNAMES").map_err(|_| {
        ProductionBrokerSessionActivationErrorV1::Activation("LISTEN_FDNAMES is absent")
    })?;
    let names = names.split(':').map(str::to_owned).collect::<Vec<_>>();
    if names.len() != expected_descriptors || names.iter().any(String::is_empty) {
        return Err(ProductionBrokerSessionActivationErrorV1::Activation(
            "LISTEN_FDNAMES has the wrong fixed shape",
        ));
    }
    Ok(names)
}

fn environment_u32(name: &'static str) -> Result<u32, ProductionBrokerSessionActivationErrorV1> {
    std::env::var(name)
        .map_err(|_| {
            ProductionBrokerSessionActivationErrorV1::Activation("activation variable is absent")
        })?
        .parse()
        .map_err(|_| {
            ProductionBrokerSessionActivationErrorV1::Activation(
                "activation variable is not a decimal u32",
            )
        })
}

pub(crate) fn remaining_duration(
    deadline_boottime_nanoseconds: u64,
) -> Result<u64, ProductionBrokerSessionActivationErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds =
        u64::try_from(now.tv_sec).map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?;
    let nanoseconds =
        u64::try_from(now.tv_nsec).map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?;
    let now = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(ProductionBrokerSessionActivationErrorV1::Kernel)?;
    deadline_boottime_nanoseconds
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(ProductionBrokerSessionActivationErrorV1::Deadline)
}
