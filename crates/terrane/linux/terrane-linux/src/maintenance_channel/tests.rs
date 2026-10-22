//! Checks closed maintenance messages, native credentials and cancellation.

#![allow(clippy::unwrap_used)]

use super::{MaintenanceClient, MaintenanceRoles, MaintenanceServer, socket, wire};
use crate::host_cache::NativeExposureReconciliation;
use rustix::net;
use std::{io, os::fd::AsFd};

#[test]
fn closed_request_rejects_version_operation_sequence_and_trailing_bytes() {
    let canonical = wire::encode_request(1);
    wire::request(&canonical, 1).unwrap();
    for offset in [0, 8, 16] {
        let mut changed = canonical;
        changed[offset] ^= 1;
        assert!(wire::request(&changed, 1).is_err());
    }
    assert!(wire::request(&canonical[..23], 1).is_err());
    assert!(wire::request(&[canonical.as_slice(), &[0]].concat(), 1).is_err());
    assert!(wire::request(&wire::encode_request(0), 0).is_err());
}

#[test]
fn reply_checks_exact_sequence_complete_counts_and_registered_errors() {
    let report = NativeExposureReconciliation {
        checked: 3,
        completed: 1,
        blocked: 2,
    };
    let packet = wire::reply(7, &Ok(report)).unwrap();
    assert_eq!(wire::decode_reply(&packet, 7).unwrap().unwrap(), report);
    assert!(wire::decode_reply(&packet, 8).is_err());
    for offset in [0, 8, 24, 32, 40] {
        let mut changed = packet;
        changed[offset] ^= 1;
        assert!(wire::decode_reply(&changed, 7).is_err());
    }
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::Unsupported,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::Other,
    ] {
        let packet = wire::reply(7, &Err(io::Error::new(kind, "private diagnostic"))).unwrap();
        let error = wire::decode_reply(&packet, 7).unwrap().unwrap_err();
        assert_eq!(error.kind(), kind);
        assert!(!error.to_string().contains("private diagnostic"));
        let mut invalid = packet;
        invalid[24] = 1;
        assert!(wire::decode_reply(&invalid, 7).is_err());
    }
}

#[test]
fn reply_rejects_count_overflow_and_unknown_outcomes() {
    let packet = wire::reply(1, &Ok(NativeExposureReconciliation::default())).unwrap();
    let mut overflow = packet;
    overflow[24..40].fill(255);
    overflow[40] = 1;
    assert!(wire::decode_reply(&overflow, 1).is_err());
    for outcome in [1_u64, 7, u64::MAX] {
        let mut changed = packet;
        changed[8..16].copy_from_slice(&outcome.to_le_bytes());
        assert!(wire::decode_reply(&changed, 1).is_err());
    }
    assert!(wire::decode_reply(&packet[..47], 1).is_err());
}

#[test]
fn public_binding_refuses_colliding_and_incorrect_role_identities() {
    let uid = rustix::process::geteuid().as_raw();
    let (serve, gc) = super::channel_pair().unwrap();
    let roles = MaintenanceRoles {
        serve_uid: uid,
        gc_uid: uid,
    };
    assert!(MaintenanceServer::bind(serve, roles).is_err());
    assert!(MaintenanceClient::bind(gc, roles).is_err());
    let (serve, gc) = super::channel_pair().unwrap();
    let roles = MaintenanceRoles {
        serve_uid: uid.wrapping_add(1),
        gc_uid: uid.wrapping_add(2),
    };
    assert!(MaintenanceServer::bind(serve, roles).is_err());
    assert!(MaintenanceClient::bind(gc, roles).is_err());
}

#[test]
fn endpoint_authenticates_each_kernel_message_and_faults_wrong_uid() {
    let (receiver, sender) = super::channel_pair().unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let mut endpoint = socket::Endpoint::new(receiver, uid.wrapping_add(1)).unwrap();
    assert!(endpoint.receive().unwrap().is_none());
    net::send(&sender, b"packet", net::SendFlags::NOSIGNAL).unwrap();
    assert_eq!(
        endpoint.receive().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        endpoint.receive().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn endpoint_refuses_received_rights_and_truncated_records() {
    use net::{SendAncillaryBuffer, SendAncillaryMessage};
    use std::{io::IoSlice, mem::MaybeUninit};

    for rights in [false, true] {
        let (receiver, sender) = super::channel_pair().unwrap();
        let mut endpoint =
            socket::Endpoint::new(receiver, rustix::process::geteuid().as_raw()).unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let borrowed = [file.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        let bytes = vec![0; if rights { 24 } else { wire::MAX_PACKET + 1 }];
        if rights {
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&borrowed)));
        }
        net::sendmsg(
            &sender,
            &[IoSlice::new(&bytes)],
            &mut ancillary,
            net::SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert_eq!(
            endpoint.receive().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            endpoint.receive().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}

#[test]
fn incomplete_exchange_disconnects_and_complete_exchange_preserves_channel() {
    for completed in [false, true] {
        let (receiver, sender) = super::channel_pair().unwrap();
        let mut endpoint =
            socket::Endpoint::new(receiver, rustix::process::geteuid().as_raw()).unwrap();
        let mut exchange = socket::Exchange::start(&mut endpoint);
        if completed {
            exchange.complete();
        }
        drop(exchange);
        if completed {
            net::send(&sender, b"original", net::SendFlags::NOSIGNAL).unwrap();
            assert_eq!(endpoint.receive().unwrap().unwrap(), b"original");
        } else {
            assert_eq!(
                endpoint.receive().unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert!(net::send(&sender, b"late", net::SendFlags::NOSIGNAL).is_err());
        }
    }
}

#[test]
fn cancelled_client_request_faults_the_original_connection() {
    let (mut client, peer) = client_endpoint();
    let pending = client.reconcile_draining().unwrap();
    receive_request(&peer, 1);
    drop(pending);

    assert!(matches!(client.reconcile_draining(), Err(error)
        if error.kind() == io::ErrorKind::BrokenPipe));
    assert!(net::send(&peer, b"late", net::SendFlags::NOSIGNAL).is_err());
}

#[test]
fn malformed_reply_faults_before_the_pending_request_is_dropped() {
    let (mut client, peer) = client_endpoint();
    let mut pending = client.reconcile_draining().unwrap();
    receive_request(&peer, 1);
    assert!(pending.try_receive().unwrap().is_none());
    let malformed = wire::reply(2, &Ok(NativeExposureReconciliation::default())).unwrap();
    net::send(&peer, &malformed, net::SendFlags::NOSIGNAL).unwrap();

    assert_eq!(
        pending.try_receive().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(net::send(&peer, b"late", net::SendFlags::NOSIGNAL).is_err());
    assert_eq!(
        pending.try_receive().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn authenticated_remote_refusal_preserves_the_next_exact_sequence() {
    let (mut client, peer) = client_endpoint();
    let mut pending = client.reconcile_draining().unwrap();
    receive_request(&peer, 1);
    let refusal = wire::reply(1, &Err(io::ErrorKind::WouldBlock.into())).unwrap();
    net::send(&peer, &refusal, net::SendFlags::NOSIGNAL).unwrap();
    assert_eq!(
        pending.try_receive().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        pending.try_receive().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    drop(pending);

    let mut pending = client.reconcile_draining().unwrap();
    receive_request(&peer, 2);
    let report = NativeExposureReconciliation {
        checked: 1,
        completed: 0,
        blocked: 1,
    };
    let reply = wire::reply(2, &Ok(report)).unwrap();
    net::send(&peer, &reply, net::SendFlags::NOSIGNAL).unwrap();
    assert_eq!(pending.try_receive().unwrap(), Some(report));
}

#[test]
fn bounded_client_receives_authenticated_counts_and_remote_refusals() {
    let report = NativeExposureReconciliation {
        checked: 3,
        completed: 1,
        blocked: 2,
    };
    runtime().block_on(async {
        for result in [Ok(report), Err(io::ErrorKind::WouldBlock.into())] {
            let (client, peer) = client_endpoint();
            let request = client.reconcile_draining_once(std::time::Duration::from_secs(1));
            let responder = async {
                wait_for_request(&peer).await;
                let packet = wire::reply(1, &result).unwrap();
                net::send(&peer, &packet, net::SendFlags::NOSIGNAL).unwrap();
            };

            let (received, ()) = tokio::join!(request, responder);

            match result {
                Ok(expected) => assert_eq!(received.unwrap(), expected),
                Err(expected) => assert_eq!(received.unwrap_err().kind(), expected.kind()),
            }
            assert!(net::send(&peer, b"late", net::SendFlags::NOSIGNAL).is_err());
        }
    });
}

#[test]
fn bounded_client_timeout_and_cancellation_close_the_actual_connection() {
    use std::time::Duration;

    runtime().block_on(async {
        let (client, peer) = client_endpoint();
        let _retained_alias = client.endpoint.descriptor().try_clone_to_owned().unwrap();

        let error = client
            .reconcile_draining_once(Duration::from_millis(20))
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        receive_request(&peer, 1);
        assert!(net::send(&peer, b"late", net::SendFlags::NOSIGNAL).is_err());

        let (client, peer) = client_endpoint();
        let _retained_cancelled_alias = client.endpoint.descriptor().try_clone_to_owned().unwrap();
        let mut request = Box::pin(client.reconcile_draining_once(Duration::from_secs(1)));
        tokio::select! {
            result = &mut request => panic!("unserved request completed: {result:?}"),
            () = wait_for_request(&peer) => {},
        }

        drop(request);

        assert!(net::send(&peer, b"late", net::SendFlags::NOSIGNAL).is_err());
    });
}

#[test]
fn bounded_client_refuses_forged_reply_without_returning_counts() {
    runtime().block_on(async {
        let (client, peer) = client_endpoint();
        let request = client.reconcile_draining_once(std::time::Duration::from_secs(1));
        let responder = async {
            wait_for_request(&peer).await;
            let packet = wire::reply(2, &Ok(NativeExposureReconciliation::default())).unwrap();
            net::send(&peer, &packet, net::SendFlags::NOSIGNAL).unwrap();
        };

        let (received, ()) = tokio::join!(request, responder);

        assert_eq!(received.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(net::send(&peer, b"late", net::SendFlags::NOSIGNAL).is_err());
    });
}

#[test]
fn bounded_client_refuses_invalid_limits_before_sending() {
    use std::time::Duration;

    runtime().block_on(async {
        for timeout in [Duration::ZERO, Duration::from_secs(301)] {
            let (client, peer) = client_endpoint();

            let error = client.reconcile_draining_once(timeout).await.unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            let mut bytes = [0; 24];
            assert_eq!(
                net::recv(&peer, &mut bytes, net::RecvFlags::DONTWAIT)
                    .unwrap()
                    .0,
                0
            );
        }
    });
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

async fn wait_for_request(peer: impl AsFd) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let mut bytes = [0; 24];
            match net::recv(&peer, &mut bytes, net::RecvFlags::DONTWAIT) {
                Ok((length, _)) => {
                    wire::request(&bytes[..length], 1).unwrap();
                    return;
                }
                Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("actual request failed: {error}"),
            }
        }
    })
    .await
    .unwrap();
}

/// Exercises client state below the separately checked public role binding.
fn client_endpoint() -> (MaintenanceClient, std::os::fd::OwnedFd) {
    let (receiver, peer) = super::channel_pair().unwrap();
    let client = MaintenanceClient {
        endpoint: socket::Endpoint::new(receiver, rustix::process::geteuid().as_raw()).unwrap(),
        sequence: 1,
    };
    (client, peer)
}

fn receive_request(peer: impl AsFd, sequence: u64) {
    let mut packet = [0; wire::MAX_PACKET];
    let (length, _) = net::recv(peer, &mut packet, net::RecvFlags::DONTWAIT).unwrap();
    wire::request(&packet[..length], sequence).unwrap();
}
