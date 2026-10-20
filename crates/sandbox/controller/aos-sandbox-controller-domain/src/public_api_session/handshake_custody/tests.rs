//! Inert completed-slot vectors; no peer or authority is fabricated.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use tokio::io::DuplexStream;

use super::*;

async fn completed_stream(alpn: bool) -> tokio_rustls::server::TlsStream<DuplexStream> {
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["sandbox.test".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.der().clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if alpn {
        server.alpn_protocols = vec![b"h2".to_vec()];
        client.alpn_protocols = vec![b"h2".to_vec()];
    }
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let (server, client) = tokio::join!(
        acceptor.accept(server_io),
        connector.connect(ServerName::try_from("sandbox.test").unwrap(), client_io),
    );
    let server = server.unwrap();
    // This fixture constructs genuine TLS only, never a PublicApiPeer.
    drop(client.unwrap());
    server
}

#[tokio::test]
async fn missing_admitted_peer_keeps_the_original_completed_tls_session() {
    let stream = completed_stream(true).await;
    let binding = stream.get_ref().1
        .export_keying_material([0; 32], b"slot-test", None)
        .unwrap();
    let mut admission = CompletedAdmissionV1::new(stream, None);

    assert!(matches!(admission.authenticate(), Err(PublicApiSessionError::Authentication)));

    let CompletedAdmissionStateV1::Pending { stream, peer, .. } = &admission.state else {
        panic!("rejection lost the original pending slot");
    };
    assert!(peer.is_none());
    let retained_binding = stream.get_ref().1
        .export_keying_material([0; 32], b"slot-test", None)
        .unwrap();
    assert_eq!(retained_binding, binding);
}

#[tokio::test]
async fn pending_tls_cannot_be_drained_as_an_authenticated_public_stream() {
    let stream = completed_stream(true).await;
    let admission = CompletedAdmissionV1::new(stream, None);

    assert!(matches!(
        admission.into_authenticated(),
        Err(PublicApiSessionError::Authentication),
    ));
}

#[tokio::test]
async fn actual_non_http2_tls_rejects_without_constructing_peer_evidence() {
    let stream = completed_stream(false).await;
    let admission = CompletedAdmissionV1::new(stream, None);
    let CompletedAdmissionStateV1::Pending { stream, peer, .. } = &admission.state else {
        panic!("fixture did not park TLS");
    };

    assert!(matches!(
        crate::public_api_session::require_public_protocol(stream.get_ref().1),
        Err(PublicApiSessionError::Authentication),
    ));
    assert!(peer.is_none());
}

#[test]
fn transferred_slot_cannot_manufacture_an_authenticated_variant() {
    let mut admission = CompletedAdmissionV1::<DuplexStream> {
        state: CompletedAdmissionStateV1::Transferred,
    };

    assert!(matches!(admission.authenticate(), Err(PublicApiSessionError::Authentication)));
    assert!(matches!(admission.state, CompletedAdmissionStateV1::Transferred));
}
