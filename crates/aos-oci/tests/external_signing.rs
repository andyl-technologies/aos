//! External signer preparation and atomic finalized-bundle integration.

#![allow(clippy::expect_used)]

mod support;

use aos_oci::{
    container_signature_pae, finalize_container_publication, prepare_layout,
    write_container_signature_pae,
};
use aos_oci_types::{CONTAINER_DSSE_SIGNATURE_NAMESPACE, to_canonical_json};
use ed25519_dalek::SigningKey;
use std::fs;

#[test]
fn external_signing_verifies_and_atomically_assembles_complete_bundle() {
    let fixture = support::fixture();
    let release = support::add_signed_release_graph(&fixture);
    let input = support::publication_signature_input(&release);
    let workspace = tempfile::tempdir().expect("workspace");
    let inputs = workspace.path().join("publication-inputs");
    support::write_publication_inputs(&inputs, fixture.root(), &input);

    let pae_path = workspace.path().join("container-signature.pae");
    let expected_pae = container_signature_pae(&inputs).expect("PAE");
    let written = write_container_signature_pae(&inputs, &pae_path).expect("write PAE");
    assert_eq!(written, expected_pae);
    assert_eq!(fs::read(&pae_path).expect("read PAE"), expected_pae);
    assert!(write_container_signature_pae(&inputs, &pae_path).is_err());

    let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
    let signer = aos_registry_surface::sshsig::trusted_key_line(
        "qualification",
        &signing_key.verifying_key(),
    );
    let signature = aos_registry_surface::sshsig::sign_armored_namespace(
        &expected_pae,
        &signing_key,
        CONTAINER_DSSE_SIGNATURE_NAMESPACE,
    );
    let signature_path = workspace.path().join("container-signature.pae.sig");
    fs::write(&signature_path, signature).expect("signature");
    let output = workspace.path().join("final-bundle");
    let finalized = finalize_container_publication(&inputs, &signer, &signature_path, &output)
        .expect("finalize publication");

    assert_eq!(finalized.bundle, output);
    assert!(finalized.layout.join("oci-layout").is_file());
    assert!(finalized.archive.is_file());
    assert!(finalized.release.is_file());
    assert_eq!(
        fs::read(&finalized.signature_input).expect("final signature input"),
        to_canonical_json(&input).expect("canonical input")
    );
    input
        .validate_final_release(&finalized.declaration)
        .expect("final release binding");
    assert_eq!(
        prepare_layout(&finalized.archive)
            .expect("extract finalized archive")
            .root()
            .join("index.json")
            .is_file(),
        true
    );
    assert!(
        finalize_container_publication(&inputs, &signer, &signature_path, &output).is_err(),
        "finalization must never overwrite an existing bundle"
    );
}

#[test]
fn wrong_namespace_or_key_never_exposes_a_partial_bundle() {
    let fixture = support::fixture();
    let release = support::add_signed_release_graph(&fixture);
    let input = support::publication_signature_input(&release);
    let workspace = tempfile::tempdir().expect("workspace");
    let inputs = workspace.path().join("publication-inputs");
    support::write_publication_inputs(&inputs, fixture.root(), &input);
    let pae = container_signature_pae(&inputs).expect("PAE");

    let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
    let signer = aos_registry_surface::sshsig::trusted_key_line(
        "qualification",
        &signing_key.verifying_key(),
    );
    let wrong_namespace = aos_registry_surface::sshsig::sign_armored_namespace(
        &pae,
        &signing_key,
        "wrong-container-namespace",
    );
    let signature = workspace.path().join("wrong.sig");
    fs::write(&signature, wrong_namespace).expect("wrong signature");
    let output = workspace.path().join("must-not-exist");
    assert!(finalize_container_publication(&inputs, &signer, &signature, &output).is_err());
    assert!(!output.exists());

    let other = SigningKey::from_bytes(&[43_u8; 32]);
    let valid_wrong_key = aos_registry_surface::sshsig::sign_armored_namespace(
        &pae,
        &other,
        CONTAINER_DSSE_SIGNATURE_NAMESPACE,
    );
    fs::write(&signature, valid_wrong_key).expect("wrong-key signature");
    assert!(finalize_container_publication(&inputs, &signer, &signature, &output).is_err());
    assert!(!output.exists());
}
