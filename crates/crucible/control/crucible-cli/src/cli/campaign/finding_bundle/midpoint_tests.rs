//! Private midpoint mutual-TLS transport regression fixtures.

// crucible-lint: allow panic-shortcut -- midpoint fixtures use expect for precise failure localization.
#![allow(clippy::expect_used)]

use std::time::Duration;

use super::*;

async fn handshake_is_accepted(
    acceptor: tokio_rustls::TlsAcceptor,
    ca_pem: String,
    client_identity_pem: String,
) -> bool {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind private TLS test listener");
    let address = listener.local_addr().expect("private TLS test address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept TLS test peer");
        acceptor.accept(stream).await.is_ok()
    });
    let client = RpcControlClient::new_mtls(
        RpcEndpoint::http2(format!("https://{address}")),
        RpcMutualTlsConfig::from_pem(ca_pem, client_identity_pem),
    )
    .expect("construct TLS test client");

    let _ = tokio::time::timeout(Duration::from_secs(5), client.list_sessions()).await;
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("TLS handshake completed")
        .expect("TLS test server completed")
}

#[tokio::test]
async fn private_midpoint_transport_denies_an_unrelated_local_certificate() {
    use std::os::unix::fs::PermissionsExt;

    let directory = private_bundle_tempdir().expect("private TLS directory");
    assert_eq!(
        std::fs::metadata(directory.path())
            .expect("private TLS directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let transport = private_midpoint_transport(directory.path()).expect("private TLS setup");
    let unrelated = rcgen::generate_simple_self_signed(vec![String::from("unrelated-client")])
        .expect("unrelated identity");

    assert!(
        handshake_is_accepted(
            transport.acceptor.clone(),
            transport.ca_pem.clone(),
            transport.client_identity_pem,
        )
        .await
    );
    assert!(
        !handshake_is_accepted(
            transport.acceptor,
            transport.ca_pem,
            format!(
                "{}{}",
                unrelated.cert.pem(),
                unrelated.signing_key.serialize_pem()
            ),
        )
        .await
    );
}
