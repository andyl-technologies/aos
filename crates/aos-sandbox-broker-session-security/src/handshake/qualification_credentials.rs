//! VM-only external credential seed for Controller-facing broker sessions.
//!
//! The fixture writes fresh secrets after boot, never into the Nix store. It
//! proves canonical BSA role separation and one protected Host authority, but
//! does not claim that all four production brokers can yet reconcile.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use aos_sandbox_broker_session_protocol::{
    BrokerSessionKeyUsageV1, BrokerSessionProtocolV1, BrokerSessionSignerReferenceV1,
    supported_broker_session_version_v1,
};
use aos_sandbox_core::format::encode_trust_policy;
use aos_sandbox_core::model::{KeyReference, KeyUsage, SignaturePurpose, StableKeyId, TrustPolicy};
use aos_sandbox_core::{ObjectDigest, TrustScopeId};
use aos_sandbox_host::authorization::HostAuthorityV1;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::entropy::{KernelEntropy, nonzero_random};
use crate::manifest::{
    BrokerSessionSecurityAudienceV1, BrokerSessionSecurityKeyPinV1, BrokerSessionSecurityManifestV1,
};
use crate::protected_files::{EndpointRole, ProtectedEndpointFiles};

const KEY_USAGES: [BrokerSessionKeyUsageV1; 4] = [
    BrokerSessionKeyUsageV1::ClientHello,
    BrokerSessionKeyUsageV1::BrokerHello,
    BrokerSessionKeyUsageV1::ClientRecord,
    BrokerSessionKeyUsageV1::BrokerOutcome,
];

fn random<const N: usize>() -> [u8; N] {
    nonzero_random(&mut KernelEntropy).unwrap()
}

fn directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn credential_pair(root: &Path, name: &str, protocol: BrokerSessionProtocolV1, node: [u8; 16]) {
    let pair = root.join(name);
    let client = pair.join("client");
    let broker = pair.join("broker");
    directory(&pair);
    directory(&client);
    directory(&broker);

    let mut secrets = [[0u8; 48]; 4];
    let pins = std::array::from_fn(|index| {
        let key_id = random::<16>();
        let seed = random::<32>();
        secrets[index][..16].copy_from_slice(&key_id);
        secrets[index][16..].copy_from_slice(&seed);
        let key = SigningKey::from_bytes(&seed);
        let signer = BrokerSessionSignerReferenceV1::for_signing_key(
            random(),
            1,
            random(),
            key_id,
            1,
            KEY_USAGES[index],
            &key,
        )
        .unwrap();
        BrokerSessionSecurityKeyPinV1::new(
            signer,
            key.verifying_key().to_bytes(),
            1,
            1,
            false,
            None,
        )
        .unwrap()
    });
    let (major, minor) = supported_broker_session_version_v1(protocol);
    let manifest = BrokerSessionSecurityManifestV1::new(
        protocol,
        BrokerSessionSecurityAudienceV1::NodeController,
        major,
        minor,
        random(),
        random(),
        1,
        random(),
        1,
        random(),
        1,
        random(),
        node,
        pins,
    )
    .unwrap();
    write_new(&client.join("broker-session-manifest"), &manifest.encode());
    write_new(&broker.join("broker-session-manifest"), &manifest.encode());
    write_new(&client.join("client-hello-signing-key"), &secrets[0]);
    write_new(&broker.join("broker-hello-signing-key"), &secrets[1]);
    write_new(&client.join("client-record-signing-key"), &secrets[2]);
    write_new(&broker.join("broker-outcome-signing-key"), &secrets[3]);
    fs::set_permissions(&client, fs::Permissions::from_mode(0o500)).unwrap();
    fs::set_permissions(&broker, fs::Permissions::from_mode(0o500)).unwrap();

    let client_files = ProtectedEndpointFiles::load(&client, EndpointRole::Client).unwrap();
    let broker_files = ProtectedEndpointFiles::load(&broker, EndpointRole::Broker).unwrap();
    assert_eq!(client_files.manifest(), broker_files.manifest());
}

fn policy(
    name: &str,
    purpose: SignaturePurpose,
    usage: KeyUsage,
    signing_key: &SigningKey,
) -> Vec<u8> {
    let public_key = signing_key.verifying_key().to_bytes();
    let key = KeyReference::new(
        StableKeyId::new(name.to_owned()).unwrap(),
        1,
        ObjectDigest::from_bytes(Sha256::digest(public_key).into()),
        usage,
    );
    encode_trust_policy(
        &TrustPolicy::new(
            TrustScopeId::from_bytes(random()),
            purpose,
            vec![key],
            vec![],
        )
        .unwrap(),
    )
}

fn host_authority(root: &Path, node: [u8; 16]) {
    let directory_path = root.join("host-authority");
    directory(&directory_path);
    let plan_key = SigningKey::from_bytes(&random());
    let lease_key = SigningKey::from_bytes(&random());
    let mut journal_key = [0u8; 48];
    journal_key[..16].copy_from_slice(&random::<16>());
    journal_key[16..].copy_from_slice(&random::<32>());

    write_new(
        &directory_path.join("broker-plan-policy.cbor"),
        &policy(
            "qualification-host-plan",
            SignaturePurpose::BrokerAuthorization,
            KeyUsage::BrokerAuthorization,
            &plan_key,
        ),
    );
    write_new(
        &directory_path.join("broker-plan-public-key"),
        &plan_key.verifying_key().to_bytes(),
    );
    write_new(
        &directory_path.join("broker-revocation-scope"),
        &random::<16>(),
    );
    write_new(
        &directory_path.join("ownership-lease-policy.cbor"),
        &policy(
            "qualification-host-lease",
            SignaturePurpose::OwnershipLease,
            KeyUsage::OwnershipLease,
            &lease_key,
        ),
    );
    write_new(
        &directory_path.join("ownership-lease-public-key"),
        &lease_key.verifying_key().to_bytes(),
    );
    write_new(&directory_path.join("node-id"), &node);
    write_new(&directory_path.join("journal-mac-key"), &journal_key);
    assert!(HostAuthorityV1::from_protected_directory(&directory_path).is_ok());
}

#[test]
fn generated_controller_sessions_open_under_both_protected_roles() {
    let root = tempfile::tempdir().unwrap();
    let node = random::<16>();
    for (name, protocol) in [
        ("host", BrokerSessionProtocolV1::Host),
        ("storage", BrokerSessionProtocolV1::Storage),
        ("mount", BrokerSessionProtocolV1::Mount),
        ("network", BrokerSessionProtocolV1::Network),
    ] {
        credential_pair(root.path(), name, protocol, node);
    }
}

#[test]
#[ignore = "root VM stages external broker credentials after boot"]
fn provision_controller_broker_credentials_after_boot() {
    assert!(rustix::process::geteuid().is_root());
    let root = std::path::PathBuf::from(
        std::env::var_os("AOS_BSA_QUALIFICATION_ROOT")
            .expect("VM supplies the root-private credential directory"),
    );
    directory(&root);
    let sessions = root.join("sessions");
    directory(&sessions);
    let node = random::<16>();
    write_new(&root.join("node-id"), &node);

    for (name, protocol) in [
        ("host", BrokerSessionProtocolV1::Host),
        ("storage", BrokerSessionProtocolV1::Storage),
        ("mount", BrokerSessionProtocolV1::Mount),
        ("network", BrokerSessionProtocolV1::Network),
    ] {
        credential_pair(&sessions, name, protocol, node);
    }
    host_authority(&root, node);
    println!("CONTROLLER_BROKER_CREDENTIALS_STAGED");
}
