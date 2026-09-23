//! Portable signature and canonical-input checks for deployment policy heads.

use aos_sandbox::policy_compiler::{
    PolicyDeploymentHeadErrorV1, PolicyDeploymentInputsV1, verify_policy_deployment_head_v1,
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

const SIGNING_DOMAIN: &[u8] = b"aos.sandbox.policy-deployment-head.v1\0";
const NODE: &[u8] = br#"{"generation":1,"input":{"layer":"node"},"magic":"AOSPNI01"}"#;
const SITE: &[u8] = br#"{"generation":1,"input":{"layer":"site"},"magic":"AOSPSI01"}"#;
const BACKEND: &[u8] = br#"{"generation":1,"input":{"features":[]},"magic":"AOSPBI01"}"#;
const CATALOGS: &[u8] = br#"{"generation":1,"input":{"entries":[]},"magic":"AOSPCI01"}"#;

fn inputs() -> PolicyDeploymentInputsV1<'static> {
    PolicyDeploymentInputsV1 {
        node: NODE,
        site: SITE,
        backend: BACKEND,
        catalogs: CATALOGS,
    }
}

fn signed_packet(key: &SigningKey) -> Vec<u8> {
    let mut payload = Vec::with_capacity(160);
    payload.extend_from_slice(b"AOSPDH01");
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&10_i64.to_be_bytes());
    payload.extend_from_slice(&30_i64.to_be_bytes());
    for input in [NODE, SITE, BACKEND, CATALOGS] {
        payload.extend_from_slice(&Sha256::digest(input));
    }
    assert_eq!(payload.len(), 160);

    let mut signed = SIGNING_DOMAIN.to_vec();
    signed.extend_from_slice(&payload);
    payload.extend_from_slice(&key.sign(&signed).to_bytes());
    payload
}

#[test]
fn signed_head_binds_exact_inputs_and_expiry() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let packet = signed_packet(&key);
    let verified = verify_policy_deployment_head_v1(&packet, &inputs(), &key.verifying_key(), 20)
        .expect("signed head");
    assert_eq!(verified.generation(), 1);
    assert_eq!(verified.expires_at(), 30);

    assert!(matches!(
        verify_policy_deployment_head_v1(&packet, &inputs(), &key.verifying_key(), 30),
        Err(PolicyDeploymentHeadErrorV1::InvalidHead)
    ));
    let changed = PolicyDeploymentInputsV1 {
        node: br#"{"generation":2,"input":{"layer":"node"},"magic":"AOSPNI01"}"#,
        ..inputs()
    };
    assert!(matches!(
        verify_policy_deployment_head_v1(&packet, &changed, &key.verifying_key(), 20),
        Err(PolicyDeploymentHeadErrorV1::InvalidHead)
    ));

    let mut tampered = packet;
    tampered[160] ^= 1;
    assert!(matches!(
        verify_policy_deployment_head_v1(&tampered, &inputs(), &key.verifying_key(), 20),
        Err(PolicyDeploymentHeadErrorV1::InvalidSignature)
    ));
}

#[test]
fn noncanonical_json_cannot_be_signed_as_deployment_input() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let packet = signed_packet(&key);
    let changed = PolicyDeploymentInputsV1 {
        node: br#"{ "generation":1,"input":{"layer":"node"},"magic":"AOSPNI01"}"#,
        ..inputs()
    };
    assert!(matches!(
        verify_policy_deployment_head_v1(&packet, &changed, &key.verifying_key(), 20),
        Err(PolicyDeploymentHeadErrorV1::InvalidHead)
    ));
}
