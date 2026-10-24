//! Exercises the composed full-map validator with actual canonical rows.

use super::*;
use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, SandboxId};
use std::collections::BTreeMap;

fn fixture() -> ClosedPolicyRootBindingV2 {
    ClosedPolicyRootBindingV2 {
        issuer_owner: [1; 16],
        project: ProjectId::from_bytes([2; 16]),
        sandbox: SandboxId::from_bytes([3; 16]),
        operation: OperationId::from_bytes([4; 16]),
        operation_revision: ObjectDigest::from_bytes([5; 32]),
        accepted_generation: 6,
        projection_revision: ObjectDigest::from_bytes([7; 32]),
        publisher_generation: 8,
        publisher_head: ObjectDigest::from_bytes([9; 32]),
        project_policy_head: ObjectDigest::from_bytes([10; 32]),
        project_policy_input: ObjectDigest::from_bytes([11; 32]),
        ancestry_head: ObjectDigest::from_bytes([12; 32]),
        compiler_head: ObjectDigest::from_bytes([13; 32]),
        cache_domain_head: ObjectDigest::from_bytes([14; 32]),
        revocation_head: ObjectDigest::from_bytes([15; 32]),
        physical_partition: ObjectDigest::from_bytes([16; 32]),
        physical_cache_head: ObjectDigest::from_bytes([17; 32]),
        normalized_input: ObjectDigest::from_bytes([18; 32]),
        candidate: ObjectDigest::from_bytes([19; 32]),
        project_signer_generation: 20,
        deployment_signer_generation: 21,
        barrier_epoch: 1,
        barrier_head: ObjectDigest::from_bytes([23; 32]),
        root_predecessor: ObjectDigest::from_bytes([0; 32]),
        root_generation: 1,
        effect_transaction: [24; 16],
        handoff_epoch: 1,
    }
}

fn observe(
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<(ObjectDigest, u64, usize), BindingDataErrorV1> {
    current_root_binding_chain_v2(
        rows.iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
}

fn bound_rows() -> (BTreeMap<Vec<u8>, Vec<u8>>, ObjectDigest) {
    let binding = fixture();
    let encoded = binding.encode().unwrap();
    let head = closed_policy_binding_digest_v2(&encoded).unwrap();
    let hold = RootBindingHoldV1 {
        issuer_owner: binding.issuer_owner,
        binding: head,
        epoch: 1,
        held: true,
    };
    let rows = BTreeMap::from([
        (binding.key().unwrap(), encoded),
        (ROOT_BINDING_HEAD_KEY.to_vec(), head.as_bytes().to_vec()),
        (HOLD_KEY.to_vec(), hold.encode().unwrap().to_vec()),
    ]);
    (rows, head)
}

#[test]
fn canonical_proof_must_belong_to_the_actual_chain_and_hold_issuer() {
    let (mut rows, head) = bound_rows();
    let proof = RootQualifiedProofV1 {
        binding: head,
        epoch: 1,
        source_generation: 1,
        cache_generation: 2,
        challenge: [3; 16],
        cut: ObjectDigest::from_bytes([4; 32]),
        source_packet: ObjectDigest::from_bytes([5; 32]),
        cache_packet: ObjectDigest::from_bytes([6; 32]),
        source_pin: ObjectDigest::from_bytes([7; 32]),
        cache_pin: ObjectDigest::from_bytes([8; 32]),
    };
    rows.insert(proof_key(head), proof.encode().unwrap().to_vec());
    assert_eq!(observe(&rows).unwrap(), (head, 2, 1));

    // Both altered records remain canonical on their own. Full-map affinity,
    // rather than codec framing alone, must refuse them.
    rows.insert(
        proof_key(head),
        RootQualifiedProofV1 { epoch: 2, ..proof }
            .encode()
            .unwrap()
            .to_vec(),
    );
    assert!(observe(&rows).is_err());
    rows.insert(proof_key(head), proof.encode().unwrap().to_vec());
    rows.insert(
        HOLD_KEY.to_vec(),
        RootBindingHoldV1 {
            issuer_owner: [9; 16],
            binding: head,
            epoch: 1,
            held: true,
        }
        .encode()
        .unwrap()
        .to_vec(),
    );
    assert!(observe(&rows).is_err());
}

#[test]
fn an_empty_map_does_not_hide_retired_binding_or_ack_rows() {
    let mut rows = BTreeMap::new();
    assert_eq!(
        observe(&rows).unwrap(),
        (ObjectDigest::from_bytes([0; 32]), 1, 0)
    );
    rows.insert(RETIRED_EFFECT_ACK_KEY.to_vec(), Vec::new());
    assert!(observe(&rows).is_err());
    rows.clear();
    rows.insert(POLICY_BINDING_KEY_PREFIX.to_vec(), Vec::new());
    assert!(observe(&rows).is_err());
}
