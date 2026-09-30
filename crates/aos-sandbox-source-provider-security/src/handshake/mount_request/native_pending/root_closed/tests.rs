//! UNRUN private effect-latch refusal vectors, without live token factories.
//!
//! These check persistent attempt debt. They do not exercise crypto, current
//! guards, the actual carrier or post-effect failure retention under a Session.

use super::*;

#[test]
fn attempted_signature_cannot_be_rearmed_after_a_lost_result() {
    let mut progress = RootClosedProgressV5::new();

    progress.arm_signature().unwrap();
    let repeated = progress.arm_signature();

    assert!(repeated.is_err());
    assert!(matches!(progress.signature, SignatureState::Attempted));
    assert!(progress.signed().is_none());
}

#[test]
fn send_attempt_debt_refuses_retry_until_a_known_zero_send_result() {
    let mut progress = RootClosedProgressV5::new();

    progress.arm_send().unwrap();
    assert!(progress.arm_send().is_err());
    assert!(progress.send == SendState::Attempted);

    // Only carrier Retryable resolves this attempt as a known zero-send.
    progress.send = SendState::Retryable;
    progress.arm_send().unwrap();

    assert!(progress.send == SendState::Attempted);
    progress.send = SendState::Sent;
    assert!(progress.arm_send().is_err());
    assert!(progress.send == SendState::Sent);
}
