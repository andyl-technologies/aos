//! Registry vectors, authored and UNRUN; no peer or effect authority fixture.

use super::*;

#[test]
fn terminal_marker_contains_no_original_or_authority() {
    fn copy<T: Copy>() {}
    copy::<GatewayTransportFailedV1>();

    assert_eq!(std::mem::size_of::<GatewayTransportFailedV1>(), 0);
}

#[cfg(feature = "kernel-tests")]
mod original_tcp {
    use std::future::poll_fn;
    use std::task::Poll;

    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpStream;

    use super::*;
    use crate::public_api_session::{
        HandshakeInterruptionV1, RetainedPublicTcpCauseV1,
    };

    async fn accepted() -> (GatewayTransportRegistryV1, TcpStream) {
        let mut registry = GatewayTransportRegistryV1::from_systemd_credentials().unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();

        registry.accept_original(&listener).await.unwrap();
        assert!(registry.failure().is_none());
        (registry, client)
    }

    #[tokio::test]
    #[ignore = "requires actual independently provisioned systemd public credentials"]
    async fn unpolled_accept_releases_only_empty_original_funding() {
        let mut registry = GatewayTransportRegistryV1::from_systemd_credentials().unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let accept = registry.accept_original(&listener);

        drop(accept);

        assert!(registry.entry.is_none());
        assert!(registry.funding.is_vacant());
        assert!(registry.retirement_debt().is_none());
    }

    #[tokio::test]
    #[ignore = "requires actual independently provisioned systemd public credentials"]
    async fn unpolled_handshake_keeps_original_and_funding_until_explicit_disposal() {
        let (mut registry, _client) = accepted().await;
        let drive = registry.drive_handshake();

        drop(drive);

        assert!(matches!(registry.entry, Some(EntryV1::EndedHandshake(_))));
        assert!(!registry.funding.is_vacant());
        assert!(matches!(
            registry.failure(),
            Some(GatewayTransportCauseV1::Handshake(GitHttpHandshakeCauseV1::Tls(
                RetainedPublicTcpCauseV1::Interrupted(HandshakeInterruptionV1::Cancelled),
            ))),
        ));

        registry.dispose_local().unwrap();

        assert!(registry.entry.is_none());
        assert!(registry.funding.is_vacant());
    }

    #[tokio::test]
    #[ignore = "requires actual independently provisioned systemd public credentials"]
    async fn pending_driver_loss_keeps_actual_original_but_blocks_second_acceptance() {
        let (mut registry, _client) = accepted().await;
        let mut drive = Box::pin(registry.drive_handshake());
        poll_fn(|context| {
            assert!(drive.as_mut().poll(context).is_pending());
            Poll::Ready(())
        }).await;

        drop(drive);

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        assert!(registry.accept_original(&listener).await.is_err());
        assert!(matches!(registry.entry, Some(EntryV1::EndedHandshake(_))));
        assert!(!registry.funding.is_vacant());
    }

    #[tokio::test]
    #[ignore = "requires actual independently provisioned systemd public credentials"]
    async fn tls_failure_borrows_same_real_cause_until_disposal_then_allows_second_transport() {
        let (mut registry, mut client) = accepted().await;
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(registry.drive_handshake().await.is_err());
        let first = match registry.failure() {
            Some(GatewayTransportCauseV1::Handshake(GitHttpHandshakeCauseV1::Tls(
                RetainedPublicTcpCauseV1::Tls(cause),
            ))) => cause as *const io::Error,
            _ => panic!("real rejected TLS record lost its provider cause"),
        };

        assert!(registry.drive_handshake().await.is_err());

        let repeated = match registry.failure() {
            Some(GatewayTransportCauseV1::Handshake(GitHttpHandshakeCauseV1::Tls(
                RetainedPublicTcpCauseV1::Tls(cause),
            ))) => cause as *const io::Error,
            _ => panic!("terminal re-drive replaced original provider cause"),
        };
        assert_eq!(first, repeated);
        assert!(!registry.funding.is_vacant());

        let _local_data = registry.dispose_local().unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let _second_client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();

        registry.accept_original(&listener).await.unwrap();

        assert!(matches!(registry.entry, Some(EntryV1::Handshake(_))));
        assert!(!registry.funding.is_vacant());
    }
}
