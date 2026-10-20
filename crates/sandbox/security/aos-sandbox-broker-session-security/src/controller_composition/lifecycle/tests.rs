//! Native terminal custody checks at the fixed lifecycle attestation seam.

use ed25519_dalek::{Signature, SigningKey};

use super::*;
use crate::recovery::LifecycleTerminalFixture;

#[test]
fn exact_signed_terminal_and_live_peer_allow_attestation() {
    let mut fixture = LifecycleTerminalFixture::new();
    let expected = fixture
        .currentness
        .as_ref()
        .unwrap()
        .authenticated_outcome()
        .clone();
    let mut held = fixture.current();
    require_current_inventory(&held, &expected).unwrap();

    let message = [42; 32];
    let signature = held.sign_lifecycle_bootstrap_attestation(&message).unwrap();
    let signature = finish_current_attestation(&mut held, Ok(signature)).unwrap();

    SigningKey::from_bytes(&[3; 32])
        .verifying_key()
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .unwrap();
}

#[test]
fn another_authenticated_inventory_cannot_replace_the_held_terminal() {
    let mut fixture = LifecycleTerminalFixture::new();
    let other = LifecycleTerminalFixture::new();
    let foreign = other.currentness.as_ref().unwrap().authenticated_outcome();
    let held = fixture.current();

    assert!(matches!(
        require_current_inventory(&held, foreign),
        Err(LifecyclePhase6ErrorV1::StaleAuthority)
    ));
}

#[test]
fn successful_signature_cannot_escape_after_key_replacement() {
    let mut fixture = LifecycleTerminalFixture::new();
    let path = fixture.client_path.clone();
    let mut held = fixture.current();
    let signed = held
        .sign_lifecycle_bootstrap_attestation(&[42; 32])
        .unwrap();

    LifecycleTerminalFixture::replace_client_key(&path);
    let completed = finish_current_attestation(&mut held, Ok(signed));

    assert!(matches!(
        completed,
        Err(LifecyclePhase6ErrorV1::StaleAuthority)
    ));
}

#[test]
fn failed_construction_keeps_its_error_when_the_final_key_check_also_fails() {
    let mut fixture = LifecycleTerminalFixture::new();
    let path = fixture.client_path.clone();
    let mut held = fixture.current();
    held.sign_lifecycle_bootstrap_attestation(&[42; 32])
        .unwrap();
    let completed: Result<(), _> = Err(LifecyclePhase6ErrorV1::InvalidInput);

    LifecycleTerminalFixture::replace_client_key(&path);
    let completed = finish_current_attestation(&mut held, completed);

    assert!(matches!(
        completed,
        Err(LifecyclePhase6ErrorV1::InvalidInput)
    ));
    assert!(held.revalidate_lifecycle_attestation().is_err());
}

#[test]
fn stale_key_cannot_obtain_a_current_terminal_loan() {
    let mut fixture = LifecycleTerminalFixture::new();
    let original = fixture.currentness.take().unwrap();

    LifecycleTerminalFixture::replace_client_key(&fixture.client_path);
    let current = fixture
        .journal
        .revalidate_broker_outcome(original, fixture.socket.peer());

    assert!(current.is_err());
}
