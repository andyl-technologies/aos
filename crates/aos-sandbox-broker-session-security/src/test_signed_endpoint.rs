//! Signed protected endpoint material shared by crate-local tests.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use aos_sandbox_broker_session_protocol::{
    BrokerSessionKeyUsageV1, BrokerSessionProtocolV1, BrokerSessionSignerReferenceV1,
};
use ed25519_dalek::SigningKey;

use crate::manifest::{
    BrokerSessionSecurityAudienceV1, BrokerSessionSecurityKeyPinV1, BrokerSessionSecurityManifestV1,
};

pub(super) fn manifest_and_secrets(
    protocol: BrokerSessionProtocolV1,
) -> (BrokerSessionSecurityManifestV1, [[u8; 48]; 4]) {
    manifest_and_secrets_for_audience(protocol, BrokerSessionSecurityAudienceV1::NodeController)
}

pub(super) fn manifest_and_secrets_for_audience(
    protocol: BrokerSessionProtocolV1,
    audience: BrokerSessionSecurityAudienceV1,
) -> (BrokerSessionSecurityManifestV1, [[u8; 48]; 4]) {
    let usages = [
        BrokerSessionKeyUsageV1::ClientHello,
        BrokerSessionKeyUsageV1::BrokerHello,
        BrokerSessionKeyUsageV1::ClientRecord,
        BrokerSessionKeyUsageV1::BrokerOutcome,
    ];
    let mut secrets = [[0_u8; 48]; 4];
    let pins = core::array::from_fn(|index| {
        let byte = u8::try_from(index).expect("four signing keys");
        let seed = [byte + 1; 32];
        let key_id = [0x50 + byte; 16];
        secrets[index][..16].copy_from_slice(&key_id);
        secrets[index][16..].copy_from_slice(&seed);
        let key = SigningKey::from_bytes(&seed);
        let signer = BrokerSessionSignerReferenceV1::for_signing_key(
            [0x30 + byte; 16],
            10 + index as u64,
            [0x40 + byte; 32],
            key_id,
            20 + index as u64,
            usages[index],
            &key,
        )
        .expect("signed test endpoint reference");
        BrokerSessionSecurityKeyPinV1::new(
            signer,
            key.verifying_key().to_bytes(),
            1,
            1,
            false,
            None,
        )
        .expect("signed test endpoint pin")
    });
    let manifest = BrokerSessionSecurityManifestV1::new(
        protocol, audience, 1, 0, [1; 16], [2; 16], 1, [3; 32], 1, [4; 32], 1, [5; 32], [6; 16],
        pins,
    )
    .expect("signed test endpoint manifest");
    (manifest, secrets)
}

pub(super) fn write_protected(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("protected test file write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).expect("protected test file mode");
}

pub(super) enum TestEndpointRole {
    Client,
    Broker,
}

pub(super) fn install_endpoint(
    directory: &Path,
    manifest: &BrokerSessionSecurityManifestV1,
    secrets: &[[u8; 48]; 4],
    role: TestEndpointRole,
) {
    write_protected(
        &directory.join("broker-session-manifest"),
        &manifest.encode(),
    );
    let files = match role {
        TestEndpointRole::Client => [
            ("client-hello-signing-key", 0),
            ("client-record-signing-key", 2),
        ],
        TestEndpointRole::Broker => [
            ("broker-hello-signing-key", 1),
            ("broker-outcome-signing-key", 3),
        ],
    };
    for (name, index) in files {
        write_protected(&directory.join(name), &secrets[index]);
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o500))
        .expect("protected test endpoint mode");
}
