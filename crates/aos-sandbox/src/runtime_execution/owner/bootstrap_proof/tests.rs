//! Adversarial checks for dormant deployment-bootstrap proof decoding.

use aos_sandbox_core::runtime_backend::{
    BackendCapabilitiesV1, BackendProbeCurrentnessV1, RequiredBackendCapabilitiesV1,
    ResolvedRuntimePlanV1, RuntimeCurrentnessV1, RuntimeHandleCommitmentV1,
};
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, NodeId, ObjectDigest,
    ObservationSequence, PayloadBootId, Revision, SandboxId,
};
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::runtime_execution::owner::{
    DormantRuntimeExecutionProvisioningV1, encode_runtime_owner_peer_records,
};

struct Fixture {
    manifest: Vec<u8>,
    proof: [u8; PROOF_BYTES],
    pin: [u8; PIN_BYTES],
    expected: RuntimeBootstrapExpectationV1,
    signer: SigningKey,
    measurement: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let currentness = RuntimeCurrentnessV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            NodeId::from_bytes([3; 16]),
            AssignmentEpoch::new(4),
            ObjectDigest::from_bytes([5; 32]),
            DesiredGeneration::new(6),
            NamespaceGeneration::new(7),
        )
        .unwrap();
        let plan = ResolvedRuntimePlanV1::new(
            currentness,
            RequiredBackendCapabilitiesV1::new(Vec::new()).unwrap(),
            ObjectDigest::from_bytes([20; 32]),
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
        )
        .unwrap();
        let runtime = RuntimeHandleCommitmentV1::new(
            currentness,
            plan.plan_commitment(),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let backend_probe = BackendProbeCurrentnessV1::new(
            NodeId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([10; 32]),
            Revision::new(11),
            ObjectDigest::from_bytes([12; 32]),
        )
        .unwrap();
        let host_boot_id = [14; 16];
        let provisioning = DormantRuntimeExecutionProvisioningV1::new(
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
            ObjectDigest::from_bytes([13; 32]),
            ObservationSequence::new(14),
            runtime,
            PayloadBootId::new([15; 16]).unwrap(),
            backend_probe,
            BackendCapabilitiesV1::new(Vec::new()).unwrap(),
            ObjectDigest::from_bytes([16; 32]),
            ObjectDigest::from_bytes([17; 32]),
            SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
            ObjectDigest::from_bytes([18; 32]),
            ObjectDigest::from_bytes([19; 32]),
            host_boot_id,
            plan,
        )
        .unwrap();
        let records = encode_runtime_owner_peer_records(&provisioning).unwrap();
        let mut manifest = Vec::with_capacity(BOOTSTRAP_MANIFEST_BYTES);
        manifest.extend_from_slice(BOOTSTRAP_MANIFEST_MAGIC);
        manifest.extend_from_slice(&records.peer);
        manifest.extend_from_slice(&records.currentness);
        manifest.extend_from_slice(&records.capabilities);
        manifest.extend_from_slice(&records.host_evidence);
        manifest.extend_from_slice(&records.plan_catalog);
        let checksum = Sha256::digest(&manifest);
        manifest.extend_from_slice(&checksum);
        assert_eq!(manifest.len(), BOOTSTRAP_MANIFEST_BYTES);

        let signer = SigningKey::from_bytes(&[9; 32]);
        let measurement = [11; 32];
        let mut pin = [0; PIN_BYTES];
        pin[..8].copy_from_slice(PIN_MAGIC);
        pin[8..16].copy_from_slice(&3_u64.to_be_bytes());
        pin[16..24].copy_from_slice(&7_u64.to_be_bytes());
        pin[24..].copy_from_slice(&signer.verifying_key().to_bytes());

        let mut proof = [0; PROOF_BYTES];
        proof[..8].copy_from_slice(PROOF_MAGIC);
        proof[8..10].copy_from_slice(&PROOF_VERSION.to_be_bytes());
        proof[16..24].copy_from_slice(&3_u64.to_be_bytes());
        proof[24..32].copy_from_slice(&7_u64.to_be_bytes());
        proof[32..48].copy_from_slice(&host_boot_id);
        proof[48..64].copy_from_slice(currentness.sandbox().as_bytes());
        proof[64..80].copy_from_slice(currentness.incarnation().as_bytes());
        proof[80..96].copy_from_slice(currentness.node().as_bytes());
        proof[96..104].copy_from_slice(&currentness.assignment_epoch().get().to_be_bytes());
        proof[104..136].copy_from_slice(currentness.assignment_digest().as_bytes());
        proof[136..144].copy_from_slice(&currentness.desired_generation().get().to_be_bytes());
        proof[144..152].copy_from_slice(&currentness.namespace_generation().get().to_be_bytes());
        proof[152..184].copy_from_slice(&Sha256::digest(&manifest));
        proof[184..216].copy_from_slice(&measurement);
        sign(&mut proof, &signer, SIGNATURE_DOMAIN);

        Self {
            manifest,
            proof,
            pin,
            expected: RuntimeBootstrapExpectationV1::new(host_boot_id, currentness).unwrap(),
            signer,
            measurement,
        }
    }

    fn verify(&self) -> Result<(), RuntimeBootstrapProofErrorV1> {
        let pin = RuntimeBootstrapSignerPinV1::decode(&self.pin)?;
        RuntimeBootstrapProofV1::decode(&self.proof)?.verify(
            &self.manifest,
            self.measurement,
            &pin,
            &self.expected,
        )
    }
}

fn sign(proof: &mut [u8; PROOF_BYTES], signer: &SigningKey, domain: &[u8]) {
    let mut message = Vec::from(domain);
    message.extend_from_slice(&proof[..SIGNED_BYTES]);
    proof[SIGNED_BYTES..].copy_from_slice(&signer.sign(&message).to_bytes());
}

#[test]
fn exact_signed_tuple_and_floor_verify_without_minting_authority() {
    let fixture = Fixture::new();
    fixture.verify().unwrap();
}

#[test]
fn unknown_version_reserved_bytes_and_noncanonical_lengths_fail() {
    let fixture = Fixture::new();
    for offset in [0, 8, 10] {
        let mut changed = fixture.proof;
        changed[offset] ^= 1;
        assert_eq!(
            RuntimeBootstrapProofV1::decode(&changed).unwrap_err(),
            RuntimeBootstrapProofErrorV1::Proof
        );
    }
    assert_eq!(
        RuntimeBootstrapProofV1::decode(&fixture.proof[..PROOF_BYTES - 1]).unwrap_err(),
        RuntimeBootstrapProofErrorV1::Proof
    );
    assert_eq!(
        RuntimeBootstrapProofV1::decode(&[fixture.proof.as_slice(), &[0]].concat()).unwrap_err(),
        RuntimeBootstrapProofErrorV1::Proof
    );

    let mut wrong_pin = fixture.pin;
    wrong_pin[0] ^= 1;
    assert!(matches!(
        RuntimeBootstrapSignerPinV1::decode(&wrong_pin),
        Err(RuntimeBootstrapProofErrorV1::Pin)
    ));
    assert!(matches!(
        RuntimeBootstrapSignerPinV1::decode(&fixture.pin[..PIN_BYTES - 1]),
        Err(RuntimeBootstrapProofErrorV1::Pin)
    ));
}

#[test]
fn replay_and_signer_rotation_require_external_pin_advance() {
    let mut fixture = Fixture::new();
    fixture.pin[16..24].copy_from_slice(&8_u64.to_be_bytes());
    assert_eq!(fixture.verify(), Err(RuntimeBootstrapProofErrorV1::Replay));

    let mut fixture = Fixture::new();
    fixture.pin[8..16].copy_from_slice(&4_u64.to_be_bytes());
    assert_eq!(fixture.verify(), Err(RuntimeBootstrapProofErrorV1::Replay));

    let mut fixture = Fixture::new();
    fixture.proof[24..32].copy_from_slice(&6_u64.to_be_bytes());
    sign(&mut fixture.proof, &fixture.signer, SIGNATURE_DOMAIN);
    assert_eq!(fixture.verify(), Err(RuntimeBootstrapProofErrorV1::Replay));
}

#[test]
fn boot_and_every_assignment_cut_field_require_independent_currentness() {
    for offset in [32, 48, 64, 80, 96, 104, 136, 144] {
        let mut fixture = Fixture::new();
        fixture.proof[offset] ^= 1;
        sign(&mut fixture.proof, &fixture.signer, SIGNATURE_DOMAIN);
        assert_eq!(
            fixture.verify(),
            Err(RuntimeBootstrapProofErrorV1::Currentness),
            "changed proof offset {offset}"
        );
    }
}

#[test]
fn exact_manifest_and_kernel_measurement_are_separately_bound() {
    let mut fixture = Fixture::new();
    fixture.manifest[17] ^= 1;
    assert_eq!(
        fixture.verify(),
        Err(RuntimeBootstrapProofErrorV1::Manifest)
    );

    let mut fixture = Fixture::new();
    fixture.measurement[0] ^= 1;
    assert_eq!(
        fixture.verify(),
        Err(RuntimeBootstrapProofErrorV1::Measurement)
    );

    let mut fixture = Fixture::new();
    fixture.proof[152] ^= 1;
    sign(&mut fixture.proof, &fixture.signer, SIGNATURE_DOMAIN);
    assert_eq!(
        fixture.verify(),
        Err(RuntimeBootstrapProofErrorV1::Manifest)
    );
}

#[test]
fn resigned_manifest_cannot_substitute_assignment_or_host_boot() {
    let peer_start = 8;
    let host_evidence_start = peer_start + PEER_BYTES + CURRENTNESS_BYTES + CAPABILITIES_BYTES;
    for (record_start, record_length, changed_offset) in [
        (peer_start, PEER_BYTES, peer_start + 95),
        (
            host_evidence_start,
            HOST_EVIDENCE_BYTES,
            host_evidence_start + 104,
        ),
    ] {
        let mut fixture = Fixture::new();
        fixture.manifest[changed_offset] ^= 1;

        let record_end = record_start + record_length;
        let record_checksum = Sha256::digest(&fixture.manifest[record_start..record_end - 32]);
        fixture.manifest[record_end - 32..record_end].copy_from_slice(&record_checksum);
        let checksum_start = BOOTSTRAP_MANIFEST_BYTES - 32;
        let manifest_checksum = Sha256::digest(&fixture.manifest[..checksum_start]);
        fixture.manifest[checksum_start..].copy_from_slice(&manifest_checksum);
        fixture.proof[152..184].copy_from_slice(&Sha256::digest(&fixture.manifest));
        sign(&mut fixture.proof, &fixture.signer, SIGNATURE_DOMAIN);

        assert_eq!(
            fixture.verify(),
            Err(RuntimeBootstrapProofErrorV1::Manifest),
            "changed manifest offset {changed_offset}"
        );
    }
}

#[test]
fn cross_purpose_and_wrong_pinned_signer_fail() {
    let mut fixture = Fixture::new();
    sign(
        &mut fixture.proof,
        &fixture.signer,
        b"aos.sandbox.runtime-bootstrap.other-purpose.v1\0",
    );
    assert_eq!(
        fixture.verify(),
        Err(RuntimeBootstrapProofErrorV1::Signature)
    );

    let mut fixture = Fixture::new();
    fixture.pin[24..]
        .copy_from_slice(&SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes());
    assert_eq!(
        fixture.verify(),
        Err(RuntimeBootstrapProofErrorV1::Signature)
    );
}
