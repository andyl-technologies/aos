//! Packet-delivery regressions, not installed Root/Controller authority.
//!
//! Existing signed Source fixtures exercise the signature-only delivery leaf.
//! No test creates a provisioned input token from scalars, changes the process
//! credential environment, fabricates a fixed Controller owner or opens Create.

use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::hierarchy::source_genesis::tests as source_fixture;
use crate::hierarchy::source_seed::encode_controller_source_tree_seed_credential_v1;
use crate::publisher_policy::encode_project_authorization_issuer_credential_v2;

struct Pair {
    seed: [u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
    authorization: [u8; PROJECT_AUTHORIZATION_SOURCE_BYTES_V2],
    seed_pin: [u8; 80],
    authorization_pin: [u8; 80],
}

impl Pair {
    fn new() -> Self {
        let accepted = source_fixture::acceptance(ProjectId::from_bytes([1; 16]));
        Self {
            seed: *accepted.seed_packet(),
            authorization: *accepted.auth_packet(),
            seed_pin: encode_controller_source_tree_seed_credential_v1(
                7,
                &SigningKey::from_bytes(&[41; 32]).verifying_key(),
            )
            .unwrap(),
            authorization_pin: encode_project_authorization_issuer_credential_v2(
                8,
                &SigningKey::from_bytes(&[42; 32]).verifying_key(),
            )
            .unwrap(),
        }
    }

    fn validate(&self) -> Result<ProjectId, ControllerSourceGenesisInputErrorV1> {
        validate_pair(
            &self.seed,
            &self.authorization,
            &self.seed_pin,
            &self.authorization_pin,
        )
    }

    fn resign_authorization(&mut self) {
        let mut preimage = b"aos.sandbox.publisher-project-authorization-source.v2\0/var/lib/aos/sandboxd/controller.journal\0".to_vec();
        preimage.extend_from_slice(&self.authorization[..160]);
        self.authorization[160..]
            .copy_from_slice(&SigningKey::from_bytes(&[42; 32]).sign(&preimage).to_bytes());
    }
}

#[test]
fn source_genesis_packet_delivery_is_data_and_does_not_adopt_another_writer() {
    let pair = Pair::new();
    let directory = source_fixture::directory();
    let journal = Journal::open_protected_at_uid(
        directory.path(),
        "controller.journal",
        crate::controller_service::journal::production_journal_limits(),
        rustix::process::geteuid().as_raw(),
    )
    .unwrap()
    .0;
    let before = journal.snapshot_sequence();

    assert_eq!(pair.validate().unwrap(), ProjectId::from_bytes([1; 16]));
    assert!(require_controller(&journal, journal.protected_owner_uid().unwrap()).is_err());
    assert_eq!(journal.snapshot_sequence(), before);
}

#[test]
fn source_genesis_packet_delivery_rejects_signature_substitution_and_wrong_role_pins() {
    let pair = Pair::new();
    for (seed, authorization, seed_pin, authorization_pin) in [
        (
            {
                let mut seed = pair.seed;
                seed[223] ^= 1;
                seed
            },
            pair.authorization,
            pair.seed_pin,
            pair.authorization_pin,
        ),
        (
            pair.seed,
            {
                let mut authorization = pair.authorization;
                authorization[223] ^= 1;
                authorization
            },
            pair.seed_pin,
            pair.authorization_pin,
        ),
        (
            pair.seed,
            pair.authorization,
            pair.authorization_pin,
            pair.seed_pin,
        ),
    ] {
        assert!(validate_pair(&seed, &authorization, &seed_pin, &authorization_pin).is_err());
    }
}

#[test]
fn source_genesis_packet_delivery_rejects_shared_key_and_rotated_issuer_generation() {
    let mut pair = Pair::new();
    pair.authorization_pin = encode_project_authorization_issuer_credential_v2(
        8,
        &SigningKey::from_bytes(&[41; 32]).verifying_key(),
    )
    .unwrap();
    assert!(matches!(
        pair.validate(),
        Err(ControllerSourceGenesisInputErrorV1::Pair)
    ));

    let mut pair = Pair::new();
    pair.seed_pin = encode_controller_source_tree_seed_credential_v1(
        9,
        &SigningKey::from_bytes(&[41; 32]).verifying_key(),
    )
    .unwrap();
    assert!(pair.validate().is_err());

    let mut pair = Pair::new();
    pair.authorization_pin = encode_project_authorization_issuer_credential_v2(
        10,
        &SigningKey::from_bytes(&[42; 32]).verifying_key(),
    )
    .unwrap();
    assert!(pair.validate().is_err());
}

#[test]
fn source_genesis_packet_delivery_rejects_signed_cross_role_claim_mismatches() {
    for (name, offset) in [
        ("project", 20),
        ("publisher generation", 43),
        ("publisher pointer", 44),
        ("request", 108),
        ("administrative epoch", 131),
        ("explicit limits", 139),
    ] {
        let mut pair = Pair::new();
        pair.authorization[offset] ^= 1;
        pair.resign_authorization();
        assert!(pair.validate().is_err(), "{name}");
    }
}

#[test]
fn source_genesis_packet_delivery_rejects_legacy_padding_and_reserved_framing() {
    let pair = Pair::new();
    let mut legacy = pair.authorization;
    legacy[..8].copy_from_slice(b"AOSPSC01");
    assert!(validate_pair(&pair.seed, &legacy, &pair.seed_pin, &pair.authorization_pin).is_err());
    for width in [0, 223, 225, 272] {
        let mut authorization = pair.authorization.to_vec();
        authorization.resize(width, 0);
        assert!(
            validate_pair(
                &pair.seed,
                &authorization,
                &pair.seed_pin,
                &pair.authorization_pin
            )
            .is_err()
        );
    }
    let mut reserved = pair.seed;
    reserved[10] = 1;
    assert!(
        validate_pair(
            &reserved,
            &pair.authorization,
            &pair.seed_pin,
            &pair.authorization_pin
        )
        .is_err()
    );
}

#[test]
fn source_genesis_packet_delivery_does_not_claim_signed_authorization_head_is_current() {
    let mut pair = Pair::new();
    pair.seed[76] ^= 1;
    let mut preimage = b"aos.sandbox.controller-source-tree-seed.signature.v1\0/var/lib/aos/sandbox/source-domains/source-domains-v1.journal\0".to_vec();
    preimage.extend_from_slice(&pair.seed[..160]);
    pair.seed[160..].copy_from_slice(&SigningKey::from_bytes(&[41; 32]).sign(&preimage).to_bytes());

    // Only the actual current AOSPAUH2 read can reject this signed stale head.
    // Successful delivery returns a selector, never current admission authority.
    assert_eq!(pair.validate().unwrap(), ProjectId::from_bytes([1; 16]));
}
