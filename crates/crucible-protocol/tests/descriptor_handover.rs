//! Checks Unix `Setup` descriptor handover over `SCM_RIGHTS`.

#![cfg(unix)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use crucible_protocol::{
    DescriptorHandoverError, HostMsg, ReceivedSetup, ReceivedSetupDescriptors, SetupDescriptorFds,
    control_encode_host_msg, recv_setup_with_descriptors, send_setup_with_descriptors,
};

#[test]
fn setup_handover_transfers_three_descriptors_in_fixed_order() -> Result<(), Box<dyn Error>> {
    let (host, plugin) = UnixStream::pair()?;
    let shmem = File::open("/dev/null")?;
    let wake = File::open("/dev/zero")?;
    let branch_plan = File::open("/dev/null")?;

    send_setup_with_descriptors(
        host.as_raw_fd(),
        450_560,
        SetupDescriptorFds {
            shmem_fd: shmem.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
            plugin_setup_plan_fd: branch_plan.as_raw_fd(),
        },
    )?;

    let ReceivedSetup {
        region_len,
        descriptors:
            ReceivedSetupDescriptors {
                shmem_fd,
                wake_fd,
                plugin_setup_plan_fd,
            },
    } = recv_setup_with_descriptors(plugin.as_raw_fd())?;
    assert_eq!(region_len, 450_560);
    assert_close_on_exec(shmem_fd.as_raw_fd())?;
    assert_close_on_exec(wake_fd.as_raw_fd())?;
    assert_close_on_exec(plugin_setup_plan_fd.as_raw_fd())?;

    assert_received_fd_order(shmem_fd, wake_fd, plugin_setup_plan_fd)?;

    Ok(())
}

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn setup_handover_accepts_split_descriptor_control_messages() -> Result<(), Box<dyn Error>> {
    let (host, plugin) = UnixStream::pair()?;
    let shmem = File::open("/dev/null")?;
    let wake = File::open("/dev/zero")?;
    let branch_plan = File::open("/dev/null")?;
    let frame = control_encode_host_msg(&HostMsg::Setup { region_len: 8192 });

    send_setup_with_split_descriptor_cmsgs(
        host.as_raw_fd(),
        &frame,
        [shmem.as_raw_fd(), wake.as_raw_fd(), branch_plan.as_raw_fd()],
    )?;

    let ReceivedSetup {
        region_len,
        descriptors:
            ReceivedSetupDescriptors {
                shmem_fd,
                wake_fd,
                plugin_setup_plan_fd,
            },
    } = recv_setup_with_descriptors(plugin.as_raw_fd())?;
    assert_eq!(region_len, 8192);
    assert_received_fd_order(shmem_fd, wake_fd, plugin_setup_plan_fd)?;

    Ok(())
}

#[test]
fn setup_handover_reports_closed_peer_on_send() -> Result<(), Box<dyn Error>> {
    let (host, plugin) = UnixStream::pair()?;
    drop(plugin);

    let shmem = File::open("/dev/null")?;
    let wake = File::open("/dev/zero")?;
    let branch_plan = File::open("/dev/null")?;
    let error = send_setup_with_descriptors(
        host.as_raw_fd(),
        4096,
        SetupDescriptorFds {
            shmem_fd: shmem.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
            plugin_setup_plan_fd: branch_plan.as_raw_fd(),
        },
    );

    assert!(matches!(error, Err(DescriptorHandoverError::Io { .. })));

    Ok(())
}

fn assert_received_fd_order(
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
    branch_plan_fd: OwnedFd,
) -> Result<(), Box<dyn Error>> {
    let mut received_shmem = File::from(shmem_fd);
    let mut received_wake = File::from(wake_fd);
    let mut received_branch_plan = File::from(branch_plan_fd);
    let mut shmem_byte = [0xAA];
    let mut wake_byte = [0xAA];
    let mut branch_plan_byte = [0xAA];

    assert_eq!(received_shmem.read(&mut shmem_byte)?, 0);
    assert_eq!(shmem_byte, [0xAA]);
    assert_eq!(received_wake.read(&mut wake_byte)?, 1);
    assert_eq!(wake_byte, [0]);
    assert_eq!(received_branch_plan.read(&mut branch_plan_byte)?, 0);
    assert_eq!(branch_plan_byte, [0xAA]);

    Ok(())
}

#[test]
fn setup_handover_rejects_wrong_descriptor_count() -> Result<(), Box<dyn Error>> {
    let (mut host, plugin) = UnixStream::pair()?;
    let frame = control_encode_host_msg(&HostMsg::Setup { region_len: 4096 });
    host.write_all(&frame)?;

    assert!(matches!(
        recv_setup_with_descriptors(plugin.as_raw_fd()),
        Err(DescriptorHandoverError::WrongDescriptorCount { count: 0 })
    ));

    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn send_setup_with_split_descriptor_cmsgs(
    socket_fd: RawFd,
    frame: &[u8],
    fds: [RawFd; 3],
) -> Result<(), Box<dyn Error>> {
    let mut iov = libc::iovec {
        iov_base: frame.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: frame.len(),
    };
    let fd_payload_len = std::mem::size_of::<RawFd>();
    let cmsg_space = cmsg_space(fd_payload_len)?;
    let mut storage: [libc::cmsghdr; 8] = std::array::from_fn(|_| empty_cmsghdr());
    let message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: storage.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: (cmsg_space * fds.len()) as _,
        msg_flags: 0,
    };

    // SAFETY: `message` points to live ancillary storage with room for the first header.
    let first = unsafe { libc::CMSG_FIRSTHDR(&message) };
    assert!(!first.is_null());
    write_single_fd_cmsg(first, fds[0])?;

    // SAFETY: `first` is the first header in `message`; `message` has space for another one.
    let second = unsafe { libc::CMSG_NXTHDR(&message, first) };
    assert!(!second.is_null());
    write_single_fd_cmsg(second, fds[1])?;

    // SAFETY: `second` is a valid header and `message` has space for a third one.
    let third = unsafe { libc::CMSG_NXTHDR(&message, second) };
    assert!(!third.is_null());
    write_single_fd_cmsg(third, fds[2])?;

    // SAFETY: `message` references live frame and ancillary buffers for this syscall.
    let sent = unsafe { libc::sendmsg(socket_fd, &message, send_flags()) };
    if sent < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }
    assert_eq!(usize::try_from(sent)?, frame.len());

    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn write_single_fd_cmsg(cmsg: *mut libc::cmsghdr, fd: RawFd) -> Result<(), Box<dyn Error>> {
    assert!(!cmsg.is_null());
    let payload_len = std::mem::size_of::<RawFd>();
    let cmsg_len = cmsg_len(payload_len)?;
    // SAFETY: the caller provides a non-null `cmsghdr` with space for one RawFd payload.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = cmsg_len as _;
        std::ptr::copy_nonoverlapping(&fd, libc::CMSG_DATA(cmsg).cast::<RawFd>(), 1);
    }

    Ok(())
}

fn assert_close_on_exec(fd: RawFd) -> Result<(), Box<dyn Error>> {
    // SAFETY: `fcntl(F_GETFD)` reads descriptor flags for a live fd owned by the test.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn empty_cmsghdr() -> libc::cmsghdr {
    libc::cmsghdr {
        cmsg_len: 0,
        cmsg_level: 0,
        cmsg_type: 0,
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn cmsg_space(payload_len: usize) -> Result<usize, Box<dyn Error>> {
    let payload_len = u32::try_from(payload_len)?;
    // SAFETY: `payload_len` is a byte count converted to the libc CMSG width.
    Ok(unsafe { libc::CMSG_SPACE(payload_len) as usize })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn cmsg_len(payload_len: usize) -> Result<usize, Box<dyn Error>> {
    let payload_len = u32::try_from(payload_len)?;
    // SAFETY: `payload_len` is a byte count converted to the libc CMSG width.
    Ok(unsafe { libc::CMSG_LEN(payload_len) as usize })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn send_flags() -> libc::c_int {
    libc::MSG_NOSIGNAL
}
