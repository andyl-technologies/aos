//! Source-authored original-flight vectors, all UNRUN.
//!
//! Kernel vectors deliberately use the actual fixed credential loader. They
//! require independently provisioned systemd public credentials and explicit
//! isolated-kernel execution; no unchecked acceptor/peer fixture is introduced.

use super::*;

#[test]
fn failure_marker_is_copy_and_carries_no_error_or_transport() {
    fn require_copy<T: Copy>() {}
    require_copy::<GitHttpHandshakeFailedV1>();

    assert_eq!(std::mem::size_of::<GitHttpHandshakeFailedV1>(), 0);
}

#[cfg(feature = "kernel-tests")]
mod original_tcp {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    async fn flight() -> (GitHttpHandshakeOwnerV1, TcpStream) {
        let acceptor = Arc::new(PublicApiSessionAcceptor::from_systemd_credentials().unwrap());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();

        (GitHttpHandshakeOwnerV1::begin(socket, acceptor), client)
    }

    #[tokio::test]
    #[ignore = "requires actual independently provisioned systemd public credentials"]
    async fn unpolled_drive_retains_the_original_owner_and_latches_cancellation() {
        let (mut owner, _client) = flight().await;
        let drive = owner.drive();

        drop(drive);

        assert!(owner.ended);
        assert!(matches!(owner.phase, PhaseV1::Tls));
        assert!(matches!(
            owner.failure(),
            Some(GitHttpHandshakeCauseV1::Tls(RetainedPublicTcpCauseV1::Interrupted(
                HandshakeInterruptionV1::Cancelled,
            ))),
        ));
        assert!(owner.drive().await.is_err());
    }

    #[tokio::test]
    #[ignore = "requires actual independently provisioned systemd public credentials"]
    async fn pending_drive_cancellation_does_not_replace_or_drop_resident_tls() {
        let (mut owner, _client) = flight().await;
        let mut drive = Box::pin(owner.drive());
        poll_fn(|context| {
            assert!(drive.as_mut().poll(context).is_pending());
            Poll::Ready(())
        }).await;

        drop(drive);

        assert!(owner.ended);
        assert!(matches!(owner.phase, PhaseV1::Tls));
        assert!(matches!(
            owner.failure(),
            Some(GitHttpHandshakeCauseV1::Tls(RetainedPublicTcpCauseV1::Interrupted(
                HandshakeInterruptionV1::Cancelled,
            ))),
        ));
        let capsule = match owner.try_into_formed() {
            Err(capsule) => capsule,
            Ok(_) => panic!("cancelled TLS became a formed connection"),
        };
        assert!(capsule.failure().is_some());
    }

    #[tokio::test]
    #[ignore = "requires actual independently provisioned systemd public credentials"]
    async fn real_tls_error_remains_the_same_borrowed_first_cause_after_failed_repoll() {
        let (mut owner, mut client) = flight().await;
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();

        assert!(owner.drive().await.is_err());
        let original = match owner.failure() {
            Some(GitHttpHandshakeCauseV1::Tls(RetainedPublicTcpCauseV1::Tls(cause))) => {
                cause as *const std::io::Error
            }
            _ => panic!("invalid TLS record did not retain the real provider cause"),
        };
        assert!(owner.drive().await.is_err());

        let repeated = match owner.failure() {
            Some(GitHttpHandshakeCauseV1::Tls(RetainedPublicTcpCauseV1::Tls(cause))) => {
                cause as *const std::io::Error
            }
            _ => panic!("terminal re-drive replaced the original cause"),
        };
        assert_eq!(original, repeated);
        assert!(matches!(owner.phase, PhaseV1::Tls));
    }

    #[tokio::test]
    #[ignore = "requires actual independently provisioned systemd public credentials"]
    async fn original_tls_deadline_is_not_renewed_by_late_first_poll() {
        let (mut owner, _client) = flight().await;
        // The real owner captured the ten-second cut synchronously at begin.
        tokio::time::sleep(Duration::from_millis(10_010)).await;

        assert!(owner.drive().await.is_err());
        assert!(matches!(
            owner.failure(),
            Some(GitHttpHandshakeCauseV1::Tls(RetainedPublicTcpCauseV1::Timeout(_))),
        ));
        assert!(owner.drive().await.is_err());
        assert!(matches!(
            owner.failure(),
            Some(GitHttpHandshakeCauseV1::Tls(RetainedPublicTcpCauseV1::Timeout(_))),
        ));
    }

    #[tokio::test]
    #[ignore = "requires actual independently provisioned systemd public credentials"]
    async fn incomplete_consuming_handoff_keeps_ended_original_custody() {
        let (owner, _client) = flight().await;

        let capsule = match owner.try_into_formed() {
            Err(capsule) => capsule,
            Ok(_) => panic!("unpolled handshake became a formed owner"),
        };

        assert!(capsule.owner.ended);
        assert!(matches!(capsule.owner.phase, PhaseV1::Tls));
        assert!(matches!(
            capsule.failure(),
            Some(GitHttpHandshakeCauseV1::Tls(RetainedPublicTcpCauseV1::Interrupted(
                HandshakeInterruptionV1::Abandoned,
            ))),
        ));
    }
}
