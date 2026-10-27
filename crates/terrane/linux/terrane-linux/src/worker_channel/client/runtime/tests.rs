//! Exercises actual socket backpressure, cancellation and transport refusal.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::worker_channel::{ExposureContext, channel_pair};
use rustix::net::{self, RecvFlags, SendFlags};
use std::{future::Future, os::fd::AsFd, task::Poll};

fn connection() -> (WorkerClient, std::os::fd::OwnedFd) {
    let (peer, socket) = channel_pair().unwrap();
    let context = ExposureContext::new("0123456789abcdef0123456789abcdef", 1, [3; 32]).unwrap();
    let current = rustix::process::geteuid().as_raw();
    let client = WorkerClient::bind(socket, context, if current == 0 { 1 } else { 0 }).unwrap();
    (client, peer)
}

fn assert_disconnected(client: &mut WorkerClient, peer: &std::os::fd::OwnedFd) {
    assert!(client.request(RequestedBacking::Index).is_err());
    let mut bytes = [0; 8192];
    // A queued request may precede the shutdown. Drain only actual queued bytes.
    loop {
        match net::recv(peer, &mut bytes, RecvFlags::DONTWAIT) {
            Ok((0, _)) => break,
            Ok(_) => continue,
            Err(error) => panic!("channel did not disconnect: {error}"),
        }
    }
}

#[tokio::test]
async fn invalid_limits_and_paths_refuse_before_send_without_faulting_connection() {
    let (mut client, peer) = connection();

    for max_bytes in [0, isize::MAX as usize + 1] {
        let error = client
            .request_index_bounded(max_bytes, Duration::from_secs(1))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    for timeout in [Duration::ZERO, Duration::from_secs(301)] {
        let error = client
            .request_bounded(RequestedBacking::Index, timeout)
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = client
            .request_index_bounded(65536, timeout)
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    let malformed = RequestedBacking::File {
        path: b"../foreign".to_vec(),
        content: terrane_format::tree_format::ContentRef::Inline([4; 32]),
    };
    assert!(
        client
            .request_bounded(malformed, Duration::from_secs(1))
            .await
            .is_err()
    );

    let mut bytes = [0; 8192];
    assert_eq!(
        net::recv(&peer, &mut bytes, RecvFlags::DONTWAIT).unwrap_err(),
        rustix::io::Errno::WOULDBLOCK
    );
    let pending = client.request(RequestedBacking::Index).unwrap();
    assert!(net::recv(&peer, &mut bytes, RecvFlags::DONTWAIT).unwrap().0 > 0);
    drop(pending);
}

#[tokio::test]
async fn reply_timeout_and_cancellation_shutdown_retained_descriptor_aliases() {
    for cancel in [false, true] {
        let (mut client, peer) = connection();
        let alias = client.as_fd().try_clone_to_owned().unwrap();
        let timeout = if cancel {
            Duration::from_secs(1)
        } else {
            Duration::from_millis(20)
        };
        let mut exchange = Box::pin(client.request_bounded(RequestedBacking::Index, timeout));

        if cancel {
            std::future::poll_fn(|context| {
                assert!(matches!(exchange.as_mut().poll(context), Poll::Pending));
                let mut bytes = [0; 8192];
                match net::recv(&peer, &mut bytes, RecvFlags::DONTWAIT) {
                    Ok((count, _)) => {
                        assert!(count > 0);
                        Poll::Ready(())
                    }
                    Err(error) if error == rustix::io::Errno::WOULDBLOCK => Poll::Pending,
                    Err(error) => panic!("request did not reach peer: {error}"),
                }
            })
            .await;
        } else {
            assert_eq!(
                exchange.as_mut().await.err().unwrap().kind(),
                io::ErrorKind::TimedOut
            );
        }
        drop(exchange);

        assert_disconnected(&mut client, &peer);
        drop(alias);
    }
}

#[tokio::test]
async fn send_backpressure_is_included_in_the_whole_exchange_deadline() {
    let (mut client, peer) = connection();
    let alias = client.as_fd().try_clone_to_owned().unwrap();
    loop {
        match net::send(&alias, &[0; 76], SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
            Ok(_) => continue,
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => break,
            Err(error) => panic!("unexpected backpressure setup failure: {error}"),
        }
    }

    let error = client
        .request_bounded(RequestedBacking::Index, Duration::from_millis(20))
        .await
        .err()
        .unwrap();

    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(client.next_sequence, 1);
    assert_disconnected(&mut client, &peer);
    drop(alias);
}
