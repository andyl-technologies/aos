//! Exercises the protected loader and registered listener with real TLS and HTTP/2.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aos_proto::aos::sandbox::v1::{DiscoveryServiceExt, GetPublicFeatureRegistryResponse};
use aos_sandbox_core::{PrincipalId, ProjectId};
use buffa::Message as _;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use sha2::{Digest as _, Sha256};

use super::super::{CapabilityService, CapabilityState};
use super::{PublicApiPeer, bind_at, serve};

const CHILD: &str = "AOS_PUBLIC_LISTENER_TEST_CHILD";
const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([2; 16]);
const PROJECT: ProjectId = ProjectId::from_bytes([3; 16]);
const REGISTRY_PATH: &str =
    "https://sandbox.test/aos.sandbox.v1.DiscoveryService/GetPublicFeatureRegistry";

struct Authority {
    certificate: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

struct Leaf {
    certificate: Certificate,
    key: KeyPair,
}

impl Authority {
    fn new() -> Self {
        let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = parameters.self_signed(&key).unwrap();
        Self {
            certificate,
            issuer: Issuer::new(parameters, key),
        }
    }

    fn leaf(&self, usage: ExtendedKeyUsagePurpose) -> Leaf {
        let mut parameters = CertificateParams::new(vec!["sandbox.test".to_owned()]).unwrap();
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let certificate = parameters.signed_by(&key, &self.issuer).unwrap();
        Leaf { certificate, key }
    }

    fn client(&self, socket: &Path, identity: Option<&Leaf>) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .unix_socket(socket.to_owned())
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_der(self.certificate.der()).unwrap())
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .http2_prior_knowledge()
            .timeout(Duration::from_secs(3));
        if let Some(identity) = identity {
            let pem = identity.certificate.pem() + &identity.key.serialize_pem();
            builder = builder.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
        }
        builder.build().unwrap()
    }
}

fn credential(directory: &Path, name: &str, bytes: &[u8]) {
    let path = directory.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
}

fn registry_request(client: &reqwest::Client) -> reqwest::RequestBuilder {
    client
        .post(REGISTRY_PATH)
        .header("content-type", "application/proto")
        .header("connect-protocol-version", "1")
        .body(Vec::new())
}

#[test]
fn registered_public_listener_uses_protected_credentials_and_real_http2() {
    // The build sandbox root is not root-owned. Only the VM supplies the
    // production root-to-service ownership chain; do not relax the loader.
    assert_eq!(rustix::process::geteuid().as_raw(), 811);
    let root = std::env::var_os("AOS_PUBLIC_API_TEST_ROOT")
        .expect("VM supplies the protected service-owned fixture directory");
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(root)
        .unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "controller_service::public_api::qualification_tests::registered_public_listener_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env("CREDENTIALS_DIRECTORY", directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("REGISTERED_PUBLIC_RPC_PASS"));
}

#[test]
fn registered_public_listener_child() {
    if std::env::var(CHILD).as_deref() != Ok("1") {
        return;
    }
    let directory = std::path::PathBuf::from(std::env::var_os("CREDENTIALS_DIRECTORY").unwrap());
    let authority = Authority::new();
    let server_identity = authority.leaf(ExtendedKeyUsagePurpose::ServerAuth);
    let client_identity = authority.leaf(ExtendedKeyUsagePurpose::ClientAuth);
    let unregistered_identity = authority.leaf(ExtendedKeyUsagePurpose::ClientAuth);
    credential(
        &directory,
        "public-api-server-cert",
        server_identity.certificate.pem().as_bytes(),
    );
    credential(
        &directory,
        "public-api-server-key",
        server_identity.key.serialize_pem().as_bytes(),
    );
    credential(
        &directory,
        "public-api-client-ca",
        authority.certificate.pem().as_bytes(),
    );
    let digest: [u8; 32] = Sha256::digest(client_identity.certificate.der()).into();
    let registration = format!(
        r#"{{"version":1,"peers":[{{"certificate_sha256":{digest:?},"principal":"{PRINCIPAL}","project":"{PROJECT}"}}]}}"#,
    );
    credential(&directory, "public-api-principals", registration.as_bytes());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            let socket = directory.join("public.sock");
            let listener = bind_at(rustix::process::geteuid().as_raw(), &socket)
                .await
                .unwrap();
            let service = Arc::new(CapabilityService {
                capabilities: Arc::new(Mutex::new(CapabilityState::starting([7; 16]))),
            });
            let observed_peer = Arc::new(Mutex::new(None));
            let capture_peer = Arc::clone(&observed_peer);
            let application = axum::Router::new()
                .route(
                    "/peer",
                    axum::routing::get(
                        move |axum::Extension(peer): axum::Extension<PublicApiPeer>| {
                            let capture_peer = Arc::clone(&capture_peer);
                            async move {
                                capture_peer.lock().unwrap().replace(peer.clone());
                                format!("{} {}", peer.principal(), peer.project())
                            }
                        },
                    ),
                )
                .fallback_service(
                    DiscoveryServiceExt::register(service, connectrpc::Router::new())
                        .into_axum_service(),
                );
            let server = tokio::spawn(serve(Some(listener), application));

            let client = authority.client(&socket, Some(&client_identity));
            let response = registry_request(&client).send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert_eq!(response.version(), reqwest::Version::HTTP_2);
            let mut body = response.bytes().await.unwrap();
            let response = GetPublicFeatureRegistryResponse::decode(&mut body).unwrap();
            assert_eq!(
                response.registry.as_option().unwrap(),
                &aos_sandbox::controller_query::public_feature_registry_v1()
            );
            let peer = client
                .get("https://sandbox.test/peer")
                .header("x-aos-principal", "forged")
                .header("x-aos-project", "forged")
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert_eq!(peer, format!("{PRINCIPAL} {PROJECT}"));
            let retained_peer = observed_peer.lock().unwrap().clone().unwrap();
            retained_peer.recheck().unwrap();

            let unregistered = authority.client(&socket, Some(&unregistered_identity));
            assert!(registry_request(&unregistered).send().await.is_err());
            let anonymous = authority.client(&socket, None);
            assert!(registry_request(&anonymous).send().await.is_err());
            assert_eq!(
                registry_request(&client).send().await.unwrap().status(),
                reqwest::StatusCode::OK
            );

            // A protected rotation invalidates an existing HTTP/2 connection,
            // and new connections cannot silently use the old cached acceptor.
            std::fs::remove_file(directory.join("public-api-principals")).unwrap();
            credential(
                &directory,
                "public-api-principals",
                b"{\"version\":1,\"peers\":[]}",
            );
            if let Ok(response) = registry_request(&client).send().await {
                assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
            }
            assert!(retained_peer.recheck().is_err());
            let fresh = authority.client(&socket, Some(&client_identity));
            assert!(registry_request(&fresh).send().await.is_err());

            // Restoring the exact original configuration permits a new TLS
            // session, but cannot revive evidence that already failed recheck.
            std::fs::remove_file(directory.join("public-api-principals")).unwrap();
            credential(&directory, "public-api-principals", registration.as_bytes());
            assert!(retained_peer.recheck().is_err());
            let restored = authority.client(&socket, Some(&client_identity));
            assert_eq!(
                registry_request(&restored).send().await.unwrap().status(),
                reqwest::StatusCode::OK
            );

            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
            println!("REGISTERED_PUBLIC_RPC_PASS");
        })
        .await
        .expect("public RPC qualification exceeded its deadline");
    });
}
