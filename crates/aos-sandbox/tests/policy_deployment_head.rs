//! Portable signature and canonical-input checks for deployment policy heads.

use aos_sandbox::policy_compiler::{
    PolicyDeploymentHeadErrorV1, PolicyDeploymentInputsV1, decode_policy_deployment_sources_v1,
    verify_policy_deployment_head_v1,
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
    signed_packet_for(key, &inputs())
}

fn signed_packet_for(key: &SigningKey, inputs: &PolicyDeploymentInputsV1<'_>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(160);
    payload.extend_from_slice(b"AOSPDH01");
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&10_i64.to_be_bytes());
    payload.extend_from_slice(&30_i64.to_be_bytes());
    for input in [inputs.node, inputs.site, inputs.backend, inputs.catalogs] {
        payload.extend_from_slice(&Sha256::digest(input));
    }
    assert_eq!(payload.len(), 160);

    let mut signed = SIGNING_DOMAIN.to_vec();
    signed.extend_from_slice(&payload);
    payload.extend_from_slice(&key.sign(&signed).to_bytes());
    payload
}

#[test]
fn signed_bounded_resource_sources_decode_without_fabricated_limits() {
    let portable_enforcements = [
        "zfs-quota",
        "zfs-quota",
        "cgroup-v2",
        "cgroup-v2",
        "cgroup-v2",
        "cgroup-v2",
        "cgroup-v2",
        "cgroup-v2",
        "broker-ledger",
        "combined-file-descriptor",
        "broker-ledger",
        "combined-memory-accounting",
        "node-bounded-shared-residency",
        "zfs-quota",
        "broker-ledger",
        "broker-ledger",
    ];
    let portable = portable_enforcements.map(|enforcement| {
        serde_json::json!({
            "kind": "bounded",
            "amount": 4096,
            "enforcement": enforcement,
        })
    });
    let accounting = (0..22)
        .map(|_| {
            serde_json::json!({
                "kind": "bounded",
                "amount": 4096,
                "enforcement": "broker-ledger",
            })
        })
        .collect::<Vec<_>>();
    let layer = serde_json::json!({"portable": portable, "accounting": accounting});
    let node = serde_json::to_vec(&serde_json::json!({
        "generation": 1,
        "input": layer,
        "magic": "AOSPNI01",
    }))
    .expect("canonical node input");
    let site = serde_json::to_vec(&serde_json::json!({
        "generation": 1,
        "input": layer,
        "magic": "AOSPSI01",
    }))
    .expect("canonical site input");
    let backend = serde_json::to_vec(&serde_json::json!({
        "generation": 1,
        "input": {"enforcement": [
            "cgroup-v2", "broker-ledger", "zfs-quota",
            "node-bounded-shared-residency", "combined-file-descriptor",
            "combined-memory-accounting"
        ]},
        "magic": "AOSPBI01",
    }))
    .expect("canonical backend input");
    let catalogs = serde_json::to_vec(&serde_json::json!({
        "generation": 1,
        "input": {"destinations": [], "endpoints": []},
        "magic": "AOSPCI01",
    }))
    .expect("canonical catalog input");
    let inputs = PolicyDeploymentInputsV1 {
        node: &node,
        site: &site,
        backend: &backend,
        catalogs: &catalogs,
    };
    let key = SigningKey::from_bytes(&[9; 32]);
    let packet = signed_packet_for(&key, &inputs);
    let head = verify_policy_deployment_head_v1(&packet, &inputs, &key.verifying_key(), 20)
        .expect("signed typed head");
    let sources = decode_policy_deployment_sources_v1(&inputs, head).expect("typed sources");
    assert_eq!(sources.node().layer().resources().portable().len(), 16);
    assert_eq!(sources.site().layer().resources().accounting().len(), 22);
    assert!(
        sources
            .backend()
            .enforcement()
            .contains(aos_sandbox::policy_compiler::HardEnforcementV1::ZfsQuota)
    );
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
