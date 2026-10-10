//! Checks Unix `Setup` descriptor handover over `SCM_RIGHTS`.

#![cfg(unix)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;

use crucible_protocol::{
    DescriptorHandoverError, DeviceDigestWorkspaceBinding, HostMsg, ReceivedSetup,
    ReceivedSetupDescriptors, SetupDescriptorFds, SetupDeviceDigestWorkspaceFd,
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
            process_generation: 1,
            device_digest_workspace: None,
            shmem_fd: shmem.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
            plugin_setup_plan_fd: branch_plan.as_raw_fd(),
        },
    )?;

    let ReceivedSetup {
        process_generation: _,
        device_digest_workspace: _,
        region_len,
        descriptors:
            ReceivedSetupDescriptors {
                device_digest_workspace: _,
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
    let frame = control_encode_host_msg(&HostMsg::Setup {
        process_generation: 1,
        device_digest_workspace: None,
        region_len: 8192,
    });

    send_setup_with_split_descriptor_cmsgs(
        host.as_raw_fd(),
        &frame,
        [shmem.as_raw_fd(), wake.as_raw_fd(), branch_plan.as_raw_fd()],
    )?;

    let ReceivedSetup {
        process_generation: _,
        device_digest_workspace: _,
        region_len,
        descriptors:
            ReceivedSetupDescriptors {
                device_digest_workspace: _,
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
            process_generation: 1,
            device_digest_workspace: None,
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
    let frame = control_encode_host_msg(&HostMsg::Setup {
        process_generation: 1,
        device_digest_workspace: None,
        region_len: 4096,
    });
    host.write_all(&frame)?;

    assert!(matches!(
        recv_setup_with_descriptors(plugin.as_raw_fd()),
        Err(DescriptorHandoverError::WrongDescriptorCount { count: 0 })
    ));

    Ok(())
}

#[test]
fn setup_handover_transfers_workspace_as_the_fourth_owned_cloexec_descriptor()
-> Result<(), Box<dyn Error>> {
    let (host, plugin) = UnixStream::pair()?;
    let shmem = File::open("/dev/null")?;
    let wake = File::open("/dev/zero")?;
    let plan = File::open("/dev/full")?;
    let workspace = File::open("/dev/urandom")?;
    let identity = workspace.metadata()?;
    let binding = DeviceDigestWorkspaceBinding {
        account_generation: 2,
        workspace_generation: 3,
        device: identity.dev(),
        inode: identity.ino(),
    };

    // This observes socket ordering only; native backing/purpose validation is separate.
    send_setup_with_descriptors(
        host.as_raw_fd(),
        4096,
        SetupDescriptorFds {
            shmem_fd: shmem.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
            plugin_setup_plan_fd: plan.as_raw_fd(),
            process_generation: 1,
            device_digest_workspace: Some(SetupDeviceDigestWorkspaceFd {
                fd: workspace.as_raw_fd(),
                binding,
            }),
        },
    )?;
    let received = recv_setup_with_descriptors(plugin.as_raw_fd())?;

    assert_eq!(received.process_generation, 1);
    assert_eq!(received.device_digest_workspace, Some(binding));
    let received_workspace = File::from(received.descriptors.device_digest_workspace.unwrap());
    for (actual, expected) in [
        (File::from(received.descriptors.shmem_fd), &shmem),
        (File::from(received.descriptors.wake_fd), &wake),
        (File::from(received.descriptors.plugin_setup_plan_fd), &plan),
        (received_workspace, &workspace),
    ] {
        assert_close_on_exec(actual.as_raw_fd())?;
        assert_eq!(actual.metadata()?.dev(), expected.metadata()?.dev());
        assert_eq!(actual.metadata()?.ino(), expected.metadata()?.ino());
    }
    Ok(())
}

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn setup_handover_refuses_a_fifth_descriptor_under_the_fixed_cap() -> Result<(), Box<dyn Error>> {
    let (host, plugin) = UnixStream::pair()?;
    let descriptor = File::open("/dev/null")?;
    let frame = control_encode_host_msg(&HostMsg::Setup {
        region_len: 4096,
        process_generation: 1,
        device_digest_workspace: Some(DeviceDigestWorkspaceBinding {
            account_generation: 2,
            workspace_generation: 3,
            device: 0,
            inode: 0,
        }),
    });
    send_setup_with_split_descriptor_cmsgs(host.as_raw_fd(), &frame, [descriptor.as_raw_fd(); 5])?;

    assert!(matches!(
        recv_setup_with_descriptors(plugin.as_raw_fd()),
        Err(DescriptorHandoverError::WrongDescriptorCount { count: 5 })
    ));
    Ok(())
}

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn setup_handover_refuses_workspace_presence_with_only_three_descriptors()
-> Result<(), Box<dyn Error>> {
    let (host, plugin) = UnixStream::pair()?;
    let descriptor = File::open("/dev/null")?;
    let frame = control_encode_host_msg(&HostMsg::Setup {
        region_len: 4096,
        process_generation: 1,
        device_digest_workspace: Some(DeviceDigestWorkspaceBinding {
            account_generation: 2,
            workspace_generation: 3,
            device: 0,
            inode: 0,
        }),
    });
    send_setup_with_split_descriptor_cmsgs(host.as_raw_fd(), &frame, [descriptor.as_raw_fd(); 3])?;

    assert!(matches!(
        recv_setup_with_descriptors(plugin.as_raw_fd()),
        Err(DescriptorHandoverError::WrongDescriptorCount { count: 3 })
    ));
    Ok(())
}

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn setup_handover_refuses_a_fourth_descriptor_when_workspace_is_absent()
-> Result<(), Box<dyn Error>> {
    let (host, plugin) = UnixStream::pair()?;
    let descriptor = File::open("/dev/null")?;
    let frame = control_encode_host_msg(&HostMsg::Setup {
        region_len: 4096,
        process_generation: 1,
        device_digest_workspace: None,
    });
    send_setup_with_split_descriptor_cmsgs(host.as_raw_fd(), &frame, [descriptor.as_raw_fd(); 4])?;

    assert!(matches!(
        recv_setup_with_descriptors(plugin.as_raw_fd()),
        Err(DescriptorHandoverError::WrongDescriptorCount { count: 4 })
    ));
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn send_setup_with_split_descriptor_cmsgs<const N: usize>(
    socket_fd: RawFd,
    frame: &[u8],
    fds: [RawFd; N],
) -> Result<(), Box<dyn Error>> {
    assert!((3..=5).contains(&N));
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

    // SAFETY: the fixed storage holds at least five split one-FD headers.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    for (index, fd) in fds.iter().enumerate() {
        assert!(!cmsg.is_null());
        write_single_fd_cmsg(cmsg, *fd)?;
        if index + 1 < N {
            // SAFETY: the validated count and control extent retain another header.
            cmsg = unsafe { libc::CMSG_NXTHDR(&message, cmsg) };
        }
    }

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
