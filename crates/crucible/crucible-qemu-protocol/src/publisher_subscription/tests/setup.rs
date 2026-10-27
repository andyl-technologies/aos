//! Literal publisher setup framing and actual Unix ancillary transport controls.

use super::*;
use crate::DeviceDigestWorkspaceBinding;

const SETUP: &str = "
0000007916000000000000100000000000000000000000000000000007
0000000000000000000000000000000000000000000000000000000000000000
0000000000000003000000000000100000000000000000000000000000000000
000000000000000b000000000000000d00000001000000010000000000000000";

fn setup() -> PublisherSetup {
    PublisherSetup {
        region_len: 4096,
        process_generation: 7,
        device_digest_workspace: None,
        lender_generation: 3,
        device: 0,
        inode: 0,
        producer_event: 11,
        receiver_event: 13,
    }
}

#[test]
fn publisher_setup_matches_independent_literal_and_legacy_prefix()
-> Result<(), PublisherDecodeError> {
    let bytes = vector::<125>(SETUP);

    assert_eq!(setup().encode()?, bytes);
    assert_eq!(PublisherSetup::decode(&bytes)?, setup());
    let ordinary = crate::control_encode_host_msg(&crate::HostMsg::Setup {
        region_len: 4096,
        process_generation: 7,
        device_digest_workspace: None,
    });
    assert_eq!(bytes[5..61], ordinary[5..]);
    assert!(crate::control_decode_host_msg(&bytes).is_err());
    assert!(PublisherSetup::decode(&ordinary).is_err());

    Ok(())
}

#[test]
fn publisher_setup_refuses_truncation_geometry_padding_and_mixed_workspace() {
    let original = vector::<125>(SETUP);
    for length in 0..125 {
        assert_eq!(
            PublisherSetup::decode(&original[..length]),
            Err(PublisherDecodeError)
        );
    }
    let mut trailing = original.to_vec();
    trailing.push(0);
    assert_eq!(PublisherSetup::decode(&trailing), Err(PublisherDecodeError));

    for offset in (0..5)
        .chain(13..21)
        .chain(29..61)
        .chain(69..77)
        .chain(109..125)
    {
        let mut bytes = original;
        bytes[offset] ^= 1;
        assert_eq!(
            PublisherSetup::decode(&bytes),
            Err(PublisherDecodeError),
            "offset {offset}"
        );
    }
    for offset in [5, 21, 61, 93, 101] {
        let mut bytes = original;
        bytes[offset..offset + 8].fill(0);
        assert_eq!(PublisherSetup::decode(&bytes), Err(PublisherDecodeError));
    }
    for offset in [61, 93, 101] {
        let mut bytes = original;
        bytes[offset..offset + 8].fill(255);
        assert_eq!(PublisherSetup::decode(&bytes), Err(PublisherDecodeError));
    }
    let mut bytes = original;
    bytes[101..109].copy_from_slice(&11_u64.to_be_bytes());
    assert_eq!(PublisherSetup::decode(&bytes), Err(PublisherDecodeError));

    let mut invalid = setup();
    invalid.producer_event = invalid.receiver_event;
    assert_eq!(invalid.encode(), Err(PublisherDecodeError));
}

#[test]
fn publisher_setup_preserves_workspace_binding_and_fixed_role_order()
-> Result<(), PublisherDecodeError> {
    let binding = DeviceDigestWorkspaceBinding {
        account_generation: 5,
        workspace_generation: 17,
        device: 0,
        inode: 0,
    };
    let mut value = setup();
    value.device_digest_workspace = Some(binding);
    let bytes = value.encode()?;

    assert_eq!(PublisherSetup::decode(&bytes)?, value);
    let ordinary = crate::control_encode_host_msg(&crate::HostMsg::Setup {
        region_len: value.region_len,
        process_generation: value.process_generation,
        device_digest_workspace: Some(binding),
    });
    assert_eq!(bytes[5..61], ordinary[5..]);
    assert_eq!(bytes[61..], vector::<125>(SETUP)[61..]);
    for offset in [29, 37] {
        let mut invalid = bytes;
        invalid[offset..offset + 8].fill(0);
        assert_eq!(PublisherSetup::decode(&invalid), Err(PublisherDecodeError));
    }

    Ok(())
}

#[cfg(unix)]
mod transport {
    use super::*;
    use crate::deferred_cleanup::{
        DeferredCleanupSetup, send_deferred_cleanup_setup_frame_with_descriptors,
    };
    use crate::native_transfer::setup::send_native_profile_setup_frame_with_descriptors;
    use crate::publisher_subscription::quantum::{
        QuantumPublisherSetup, QuantumStackPublisherSetup,
        send_quantum_publisher_setup_frame_with_descriptors,
        send_quantum_stack_setup_frame_with_descriptors,
    };
    use crate::runtime_artifact::{
        RuntimeArtifactSetup, send_runtime_artifact_setup_frame_with_descriptors,
    };
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;

    fn identity(descriptor: &OwnedFd) -> std::io::Result<(u64, u64)> {
        let metadata = std::fs::File::from(descriptor.try_clone()?).metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn receive(socket: &UnixStream, expected: &[u8; 125]) -> std::io::Result<Vec<OwnedFd>> {
        let mut bytes = [0; 125];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut control = crate::AncillaryBuffer::for_single_cmsg_fd_capacity(14).unwrap();
        // SAFETY: all-zero msghdr has null optional pointers; live buffers below
        // supply their matching writable extents for this synchronous recvmsg.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr();
        message.msg_controllen = control.len as _;
        // SAFETY: the message references only live writable buffers.
        let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
        if received < 0 {
            return Err(std::io::Error::last_os_error());
        }
        assert_eq!(received, 125);
        assert_eq!(&bytes, expected);
        assert_eq!(message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC), 0);
        // SAFETY: recvmsg initialized the aligned control buffer; the sender
        // creates one SCM_RIGHTS header with a packed descriptor array.
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        assert!(!header.is_null());
        // SAFETY: the nonnull header lies in the live returned control buffer.
        let (length, level, kind) = unsafe {
            (
                (*header).cmsg_len as usize,
                (*header).cmsg_level,
                (*header).cmsg_type,
            )
        };
        assert_eq!((level, kind), (libc::SOL_SOCKET, libc::SCM_RIGHTS));
        // SAFETY: CMSG_LEN computes the fixed header extent without dereferencing.
        let fixed = unsafe { libc::CMSG_LEN(0) } as usize;
        let count = (length - fixed) / std::mem::size_of::<libc::c_int>();
        assert!(count <= 14);
        let mut descriptors = Vec::new();
        for index in 0..count {
            // SAFETY: the returned SCM_RIGHTS payload contains count fresh owned
            // descriptors, each transferred into exactly one RAII owner here.
            let descriptor = unsafe {
                let raw = libc::CMSG_DATA(header)
                    .cast::<libc::c_int>()
                    .add(index)
                    .read_unaligned();
                OwnedFd::from_raw_fd(raw)
            };
            descriptors.push(descriptor);
        }
        Ok(descriptors)
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SetupEdition {
        Publisher,
        Quantum,
        Stack,
        DeferredCleanup,
        RuntimeArtifact,
        NativeProfile,
    }

    type Sender = fn(
        std::os::fd::RawFd,
        &[u8; 125],
        &[std::os::fd::RawFd],
    ) -> Result<crate::PreexecSetupHandover, crate::DescriptorHandoverError>;

    impl SetupEdition {
        fn descriptor_count(self, workspace: bool) -> usize {
            let appended = match self {
                Self::RuntimeArtifact => 2,
                Self::NativeProfile => 5,
                _ => 0,
            };
            8 + usize::from(workspace) + appended
        }

        fn sender(self) -> Sender {
            match self {
                Self::Publisher => send_publisher_setup_frame_with_descriptors,
                Self::Quantum => send_quantum_publisher_setup_frame_with_descriptors,
                Self::Stack => send_quantum_stack_setup_frame_with_descriptors,
                Self::DeferredCleanup => send_deferred_cleanup_setup_frame_with_descriptors,
                Self::RuntimeArtifact => send_runtime_artifact_setup_frame_with_descriptors,
                Self::NativeProfile => send_native_profile_setup_frame_with_descriptors,
            }
        }

        fn encode(self, value: PublisherSetup) -> Result<[u8; 125], PublisherDecodeError> {
            let publisher = QuantumPublisherSetup { transport: value };
            match self {
                Self::Publisher => value.encode(),
                Self::RuntimeArtifact | Self::NativeProfile => RuntimeArtifactSetup {
                    cleanup: DeferredCleanupSetup {
                        publisher: value,
                        delegation_incarnation: 17,
                    },
                }
                .encode()
                .map_err(|_| PublisherDecodeError),
                Self::DeferredCleanup => DeferredCleanupSetup {
                    publisher: value,
                    delegation_incarnation: 17,
                }
                .encode()
                .map_err(|_| PublisherDecodeError),
                Self::Quantum => publisher.encode(),
                Self::Stack => QuantumStackPublisherSetup {
                    publisher,
                    grant_set_generation: 17,
                }
                .encode(),
            }
        }
    }

    fn exercise_transfer(edition: SetupEdition) -> Result<(), Box<dyn std::error::Error>> {
        let send = edition.sender();
        for workspace in [false, true] {
            let (host, peer) = UnixStream::pair()?;
            let mut value = setup();
            if workspace {
                value.device_digest_workspace = Some(DeviceDigestWorkspaceBinding {
                    account_generation: 5,
                    workspace_generation: 17,
                    device: 0,
                    inode: 0,
                });
            }
            let frame = edition.encode(value)?;
            let pairs = (0..edition.descriptor_count(workspace))
                .map(|_| UnixStream::pair())
                .collect::<std::io::Result<Vec<_>>>()?;
            let descriptors = pairs
                .iter()
                .map(|(socket, _)| socket.as_raw_fd())
                .collect::<Vec<_>>();

            let _receipt = send(host.as_raw_fd(), &frame, &descriptors)?;
            let received = receive(&peer, &frame)?;

            assert_eq!(received.len(), pairs.len());
            for (index, ((source, mut remote), actual)) in
                pairs.into_iter().zip(received).enumerate()
            {
                assert_eq!(
                    identity(&actual)?,
                    identity(&source.as_fd().try_clone_to_owned()?)?
                );
                let mut alias = UnixStream::from(actual);
                remote.write_all(&[index as u8])?;
                let mut byte = [255];
                alias.read_exact(&mut byte)?;
                assert_eq!(byte, [index as u8]);
            }
        }
        Ok(())
    }

    #[test]
    fn publisher_setup_sends_exact_eight_and_nine_actual_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_transfer(SetupEdition::Publisher)
    }

    #[test]
    fn quantum_setup_sends_exact_eight_and_nine_actual_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_transfer(SetupEdition::Quantum)
    }

    #[test]
    fn stack_setup_sends_exact_eight_and_nine_actual_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_transfer(SetupEdition::Stack)
    }

    #[test]
    fn deferred_cleanup_setup_sends_exact_eight_and_nine_actual_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_transfer(SetupEdition::DeferredCleanup)
    }

    fn exercise_refusal(edition: SetupEdition) -> Result<(), Box<dyn std::error::Error>> {
        let send = edition.sender();
        let encode = |value| edition.encode(value);
        let (host, mut peer) = UnixStream::pair()?;
        let frame = encode(setup())?;
        let ordinary_count = edition.descriptor_count(false);
        for count in 0..=15 {
            if count != ordinary_count {
                assert!(send(host.as_raw_fd(), &frame, &vec![host.as_raw_fd(); count]).is_err());
            }
        }
        let mut descriptors = vec![host.as_raw_fd(); ordinary_count];
        for index in 0..ordinary_count {
            descriptors[index] = -1;
            assert!(send(host.as_raw_fd(), &frame, &descriptors).is_err());
            descriptors[index] = host.as_raw_fd();
        }
        let mut malformed = frame;
        malformed[113] ^= 1;
        assert!(send(host.as_raw_fd(), &malformed, &descriptors).is_err());
        if matches!(edition, SetupEdition::Publisher | SetupEdition::Quantum) {
            let mut padding = frame;
            padding[124] = 1;
            assert!(send(host.as_raw_fd(), &padding, &descriptors).is_err());
        }

        if matches!(
            edition,
            SetupEdition::DeferredCleanup
                | SetupEdition::RuntimeArtifact
                | SetupEdition::NativeProfile
        ) {
            for invalid in [0, u64::MAX] {
                let mut malformed = frame;
                malformed[117..125].copy_from_slice(&invalid.to_be_bytes());
                assert!(send(host.as_raw_fd(), &malformed, &descriptors).is_err());
            }
        }

        let mut with_workspace = setup();
        with_workspace.device_digest_workspace = Some(DeviceDigestWorkspaceBinding {
            account_generation: 5,
            workspace_generation: 17,
            device: 0,
            inode: 0,
        });
        assert!(send(host.as_raw_fd(), &encode(with_workspace)?, &descriptors,).is_err());
        let workspace_frame = encode(with_workspace)?;
        let workspace_count = edition.descriptor_count(true);
        for count in 0..=15 {
            if count != workspace_count {
                assert!(
                    send(
                        host.as_raw_fd(),
                        &workspace_frame,
                        &vec![host.as_raw_fd(); count]
                    )
                    .is_err()
                );
            }
        }
        let mut workspace_descriptors = vec![host.as_raw_fd(); workspace_count];
        for index in 0..workspace_count {
            workspace_descriptors[index] = -1;
            assert!(send(host.as_raw_fd(), &workspace_frame, &workspace_descriptors).is_err());
            workspace_descriptors[index] = host.as_raw_fd();
        }

        for other in [
            SetupEdition::Publisher,
            SetupEdition::Quantum,
            SetupEdition::Stack,
            SetupEdition::DeferredCleanup,
            SetupEdition::RuntimeArtifact,
        ] {
            let other_frame = other.encode(setup())?;
            // Setup ten and twelve share bytes; their distinct negotiated
            // selectors cannot be inferred from this framing-only operation.
            if other != edition && other_frame != frame {
                assert!(send(host.as_raw_fd(), &other_frame, &descriptors).is_err());
            }
        }
        peer.set_nonblocking(true)?;
        assert_eq!(
            peer.read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );

        Ok(())
    }

    #[test]
    fn publisher_setup_refuses_malformed_or_wrong_roster_before_send()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_refusal(SetupEdition::Publisher)
    }

    #[test]
    fn quantum_setup_refuses_malformed_mixed_or_wrong_roster_before_send()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_refusal(SetupEdition::Quantum)
    }

    #[test]
    fn deferred_cleanup_setup_refuses_malformed_mixed_or_wrong_roster_before_send()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_refusal(SetupEdition::DeferredCleanup)
    }

    #[test]
    fn runtime_artifact_setup_sends_exact_ten_and_eleven_actual_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_transfer(SetupEdition::RuntimeArtifact)
    }

    #[test]
    fn runtime_artifact_setup_refuses_malformed_mixed_or_wrong_roster_before_send()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_refusal(SetupEdition::RuntimeArtifact)
    }

    #[test]
    fn native_profile_setup_sends_exact_thirteen_and_fourteen_actual_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_transfer(SetupEdition::NativeProfile)
    }

    #[test]
    fn native_profile_setup_refuses_malformed_mixed_or_wrong_roster_before_send()
    -> Result<(), Box<dyn std::error::Error>> {
        // Setup ten intentionally shares this frame. Its smaller roster must
        // refuse before any byte is sent under the separately selected sender.
        exercise_refusal(SetupEdition::NativeProfile)
    }

    #[test]
    fn native_profile_setup_refuses_every_repeated_descriptor_pair_before_send()
    -> Result<(), Box<dyn std::error::Error>> {
        for workspace in [false, true] {
            let (host, mut peer) = UnixStream::pair()?;
            let mut value = setup();
            if workspace {
                value.device_digest_workspace = Some(DeviceDigestWorkspaceBinding {
                    account_generation: 5,
                    workspace_generation: 17,
                    device: 0,
                    inode: 0,
                });
            }
            let frame = SetupEdition::NativeProfile.encode(value)?;
            let pairs = (0..SetupEdition::NativeProfile.descriptor_count(workspace))
                .map(|_| UnixStream::pair())
                .collect::<std::io::Result<Vec<_>>>()?;
            let descriptors = pairs
                .iter()
                .map(|(socket, _)| socket.as_raw_fd())
                .collect::<Vec<_>>();

            for first in 0..descriptors.len() {
                for second in first + 1..descriptors.len() {
                    let mut repeated = descriptors.clone();
                    repeated[second] = repeated[first];
                    let result = send_native_profile_setup_frame_with_descriptors(
                        host.as_raw_fd(),
                        &frame,
                        &repeated,
                    );
                    assert!(matches!(
                        result,
                        Err(crate::DescriptorHandoverError::MalformedAncillary { .. })
                    ));
                }
            }

            peer.set_nonblocking(true)?;
            assert_eq!(
                peer.read(&mut [0; 1]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        Ok(())
    }

    #[test]
    fn stack_setup_refuses_malformed_mixed_or_wrong_roster_before_send()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_refusal(SetupEdition::Stack)
    }
}
