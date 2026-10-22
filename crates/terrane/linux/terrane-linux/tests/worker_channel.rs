//! Exercises canonical worker packets and actual supervised process incarnations.

#![cfg(all(feature = "surface-fuse", feature = "tokio"))]

use std::{
    error::Error,
    io::{BufRead, Read, Write},
    process::{Command, Stdio},
};
use terrane_format::tree_format::ContentRef;
use terrane_linux::worker_channel::{
    BackingRequest, ExposureContext, RequestedBacking, WorkerIdentity, channel_pair,
};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn context() -> Result<ExposureContext> {
    Ok(ExposureContext::new(
        "0123456789abcdef0123456789abcdef",
        7,
        [19; 32],
    )?)
}

#[test]
fn prelaunch_pair_authenticates_the_first_already_queued_packet() -> Result {
    use rustix::net::{self, RecvAncillaryBuffer, RecvAncillaryMessage};
    use std::{io::IoSliceMut, mem::MaybeUninit};

    let (server, worker) = channel_pair()?;
    net::send(&worker, b"first", net::SendFlags::NOSIGNAL)?;
    let mut bytes = [0; 16];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = net::recvmsg(
        &server,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        net::RecvFlags::CMSG_CLOEXEC,
    )?;

    assert_eq!(&bytes[..received.bytes], b"first");
    assert!(
        !received
            .flags
            .intersects(net::ReturnFlags::TRUNC | net::ReturnFlags::CTRUNC)
    );
    let credentials: Vec<_> = ancillary.drain().collect();
    assert!(
        matches!(credentials.as_slice(), [RecvAncillaryMessage::ScmCredentials(value)]
        if value.pid == rustix::process::getpid() && value.uid == rustix::process::getuid())
    );
    Ok(())
}

#[test]
fn canonical_packets_preserve_typed_identity_and_raw_relative_paths() -> Result {
    for backing in [
        RequestedBacking::Index,
        RequestedBacking::File {
            path: b"nested/non-utf8-\xff".to_vec(),
            content: ContentRef::Inline([31; 32]),
        },
        RequestedBacking::File {
            path: b"manifest".to_vec(),
            content: ContentRef::Manifest([31; 32]),
        },
    ] {
        let request = BackingRequest::new(context()?, 1, backing)?;
        let encoded = request.encode();

        assert_eq!(BackingRequest::decode(&encoded, &context()?)?, request);
        for length in 0..encoded.len() {
            assert!(BackingRequest::decode(&encoded[..length], &context()?).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(BackingRequest::decode(&trailing, &context()?).is_err());
    }
    Ok(())
}

#[test]
fn foreign_context_reserved_fields_and_unknown_kinds_are_refused() -> Result {
    let request = BackingRequest::new(context()?, 1, RequestedBacking::Index)?;
    let encoded = request.encode();
    // Each mutation targets a separately interpreted contract field.
    for offset in [0, 4, 5, 6, 7, 8, 24, 40, 72] {
        let mut invalid = encoded.clone();
        invalid[offset] ^= 0xff;
        assert!(BackingRequest::decode(&invalid, &context()?).is_err());
    }
    let mut zero_sequence = encoded;
    zero_sequence[32..40].fill(0);
    assert!(BackingRequest::decode(&zero_sequence, &context()?).is_err());
    assert!(BackingRequest::new(context()?, 0, RequestedBacking::Index).is_err());
    Ok(())
}

#[test]
fn paths_and_context_are_bounded_before_packet_allocation() -> Result {
    for path in [
        vec![],
        b"/absolute".to_vec(),
        b"trailing/".to_vec(),
        b"double//slash".to_vec(),
        b"dot/./entry".to_vec(),
        b"parent/../entry".to_vec(),
        b"nul\0entry".to_vec(),
        vec![b'a'; 4097],
    ] {
        assert!(
            BackingRequest::new(
                context()?,
                1,
                RequestedBacking::File {
                    path,
                    content: ContentRef::Inline([1; 32]),
                },
            )
            .is_err()
        );
    }
    let request = BackingRequest::new(
        context()?,
        u64::MAX,
        RequestedBacking::File {
            path: vec![b'a'; 4096],
            content: ContentRef::Manifest([1; 32]),
        },
    )?;
    assert_eq!(
        BackingRequest::decode(&request.encode(), &context()?)?,
        request
    );
    for id in [
        "",
        "0123456789ABCDEF0123456789ABCDEF",
        "g123456789abcdef0123456789abcdef",
    ] {
        assert!(ExposureContext::new(id, 1, [1; 32]).is_err());
    }
    assert!(ExposureContext::new("0123456789abcdef0123456789abcdef", 0, [1; 32]).is_err());
    Ok(())
}

#[test]
fn original_child_pidfd_refuses_exit_and_cannot_be_recreated_from_reaped_child() -> Result {
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "supervised_child_actor",
            "--ignored",
            "--nocapture",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let result = (|| -> Result {
        let output = child.stdout.take().ok_or("missing child stdout")?;
        let mut reader = std::io::BufReader::new(output);
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Err("child exited before readiness".into());
            }
            if line.trim() == "WORKER_READY" {
                break;
            }
        }
        let identity = WorkerIdentity::from_child(&mut child, rustix::process::geteuid().as_raw())?;
        identity.check_current()?;

        child
            .stdin
            .take()
            .ok_or("missing child stdin")?
            .write_all(b"x")?;
        assert!(child.wait()?.success());
        assert_eq!(
            identity
                .check_current()
                .err()
                .ok_or("exited worker accepted")?
                .kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert!(
            WorkerIdentity::from_child(&mut child, rustix::process::geteuid().as_raw()).is_err()
        );
        Ok(())
    })();
    if child.try_wait()?.is_none() {
        child.kill()?;
        child.wait()?;
    }
    result
}

#[test]
#[ignore = "Invoked explicitly as the isolated process in the pidfd test"]
fn supervised_child_actor() -> Result {
    println!("\nWORKER_READY");
    std::io::stdout().flush()?;
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte)?;
    Ok(())
}
