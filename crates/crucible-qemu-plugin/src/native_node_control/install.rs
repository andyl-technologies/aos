//! Independent prepared-socket verification before registering native callbacks.

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};

use super::NativeNodeControl;

static REGISTERED_OWNER: std::sync::OnceLock<&'static NativeNodeControl> =
    std::sync::OnceLock::new();

/// Returns actual registered callback custody, never an execution grant.
pub(crate) fn registered_owner() -> Option<&'static NativeNodeControl> {
    REGISTERED_OWNER.get().copied()
}
use crate::args::NativeNodeControlConfig;

/// Reports an independently negotiated controller preparation failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeControlInstallError {
    #[error("native node-control callback edition is unavailable")]
    MissingCapability,
    #[error("native node-control requires an inherited Unix datagram endpoint")]
    InvalidDescriptor,
    #[error("native node-control requires its complete inactive prepared scope before install")]
    MissingPreparation,
    #[error("native prepared scope disagrees with the immutable launch commitment")]
    ScopeMismatch,
    #[error(transparent)]
    Transport(#[from] crucible_protocol::node_control::NativeChannelError),
    #[error(transparent)]
    Protocol(#[from] crucible_protocol::node_control::NativeCommandError),
}

/// Registers one independently prepared controller for this process incarnation.
#[cfg(unix)]
pub(crate) fn install(
    config: NativeNodeControlConfig,
) -> Result<&'static NativeNodeControl, NativeControlInstallError> {
    use crucible_protocol::node_control::{NativeChannel, NativeFrame};
    let register = super::resolve_register_node_control()
        .ok_or(NativeControlInstallError::MissingCapability)?;
    let notify = super::abi::resolve_notify_node_control()
        .ok_or(NativeControlInstallError::MissingCapability)?;
    validate_descriptor(config.descriptor())?;
    // SAFETY: The opt-in launch profile transfers unique ownership of this
    // distinct inherited descriptor. Argument validation forbids aliases with
    // existing setup/control descriptors; socket metadata was checked above.
    let socket = unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(config.descriptor()) };
    let writer_query = match config.edition() {
        crucible_protocol::node_control::NativeControlEdition::Original => None,
        crucible_protocol::node_control::NativeControlEdition::OwnedCustody => Some(
            super::writer_abi::resolve_query_writers()
                .ok_or(NativeControlInstallError::MissingCapability)?,
        ),
    };
    let channel = NativeChannel::from_prepared_socket_for_edition(socket, config.edition())?;
    let cpu_query = super::abi::resolve_query_cpu_park();
    if writer_query.is_some() && cpu_query.is_none() {
        return Err(NativeControlInstallError::MissingCapability);
    }
    let Some(NativeFrame::Prepare(plan)) = channel.receive()? else {
        return Err(NativeControlInstallError::MissingPreparation);
    };
    if plan.scope.identity_digest()? != config.scope_digest() {
        return Err(NativeControlInstallError::ScopeMismatch);
    }
    let maximum_commands = usize::try_from(plan.maximum_commands.get())
        .map_err(|_| crucible_protocol::node_control::NativeCommandError::ResourceLimit)?;
    let control = NativeNodeControl::new(plan.scope, plan.boundary, maximum_commands)?
        .with_prepared_channel(channel)
        .with_cpu_park_query(cpu_query)
        .with_timer_query(super::abi::resolve_query_timers());
    let control = control
        .with_writer_query(writer_query)
        .with_protocol_notify(notify);
    let source_fault_query = if config.edition()
        == crucible_protocol::node_control::NativeControlEdition::OwnedCustody
    {
        super::source_fault_abi::resolve_query_source_fault()
    } else {
        None
    };
    let control = control.with_source_fault_query(source_fault_query);
    // Callback ownership lasts until process termination. A leaked transport
    // token cannot drop this controller or its unresolved native journal.
    // Registration is limited to one controller per process by the native API.
    let control = Box::leak(Box::new(control));
    control.register(register)?;
    if REGISTERED_OWNER.set(control).is_err() {
        // Native callbacks may already reference this library. Returning an
        // ordinary install error could unload their code while QEMU retains it.
        std::process::abort();
    }
    Ok(control)
}

#[cfg(unix)]
fn validate_descriptor(descriptor: i32) -> Result<(), NativeControlInstallError> {
    let mut kind = 0i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: getsockopt validates the inherited descriptor; kind/length point
    // to appropriately sized writable scalars and no ownership is transferred.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),
            &mut length,
        )
    };
    if result != 0 || kind != libc::SOCK_DGRAM || length as usize != std::mem::size_of::<i32>() {
        return Err(NativeControlInstallError::InvalidDescriptor);
    }
    // SAFETY: The non-owning borrowed view lives only during this metadata query;
    // the prepared inherited descriptor remains valid until ownership is taken.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(descriptor) };
    if borrowed.as_raw_fd() < 0 {
        return Err(NativeControlInstallError::InvalidDescriptor);
    }
    let mut address = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut address_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: The storage and length are writable and correctly sized. A successful
    // call writes at least the address family before the following read.
    let result =
        unsafe { libc::getpeername(descriptor, address.as_mut_ptr().cast(), &mut address_length) };
    if result != 0 || address_length < std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t {
        return Err(NativeControlInstallError::InvalidDescriptor);
    }
    // SAFETY: Successful getpeername initialized the reported address prefix; the
    // zero-initialized remainder is valid scalar storage and only ss_family is read.
    let address = unsafe { address.assume_init() };
    if address.ss_family as i32 != libc::AF_UNIX {
        return Err(NativeControlInstallError::InvalidDescriptor);
    }
    Ok(())
}
