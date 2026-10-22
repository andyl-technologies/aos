//! Certificate-chain checks for the build client's bundled TLS trust fallback.

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use connectrpc::rustls;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

const CHECK_TIME: UnixTime = UnixTime::since_unix_epoch(Duration::from_secs(1_792_584_000));

fn bundled_verifier() -> Arc<rustls::client::WebPkiServerVerifier> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .unwrap()
}

fn certificate_chain(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn assert_chain_is_distrusted(hostname: &str, pem: &[u8]) {
    let chain = certificate_chain(pem);
    let server_name = ServerName::try_from(hostname.to_string()).unwrap();
    let error = bundled_verifier()
        .verify_server_cert(&chain[0], &chain[1..], &server_name, &[], CHECK_TIME)
        .unwrap_err();

    let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other)) = error else {
        panic!("expected an explicit certificate distrust error, got {error:?}");
    };
    assert_eq!(
        other.0.downcast_ref::<webpki::Error>(),
        Some(&webpki::Error::CertDistrusted)
    );
}

#[test]
fn bundled_verifier_rejects_retired_intermediate_through_cross_sign() {
    assert_chain_is_distrusted(
        "dv-g3b-aaa-emudhra.we-have-a-problem.com",
        include_bytes!("data/retired-intermediate-aaa-chain.pem"),
    );
}

#[test]
fn bundled_verifier_rejects_retired_intermediate_through_removed_root() {
    assert_chain_is_distrusted(
        "dv-g3b-emudhra.we-have-a-problem.com",
        include_bytes!("data/retired-intermediate-emsign-chain.pem"),
    );
}
