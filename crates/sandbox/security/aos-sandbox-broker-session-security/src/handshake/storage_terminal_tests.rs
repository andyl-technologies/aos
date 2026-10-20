//! Checks the actual nonconsuming sender classification used by Storage.

use super::*;

#[test]
fn real_backpressure_keeps_a_pending_terminal_without_hiding_its_errno() {
    let (mut sender, _peer) = SeqpacketSocket::pair_with_record_subjects().unwrap();
    rustix::net::sockopt::set_socket_send_buffer_size(sender.as_fd().unwrap(), 4096).unwrap();
    let packet = [7; 1024];
    let mut attempts = 0;
    let native = loop {
        attempts += 1;
        assert!(attempts <= 64, "bounded unread queue must refuse");
        let attempt = sender.send_storage_session_retaining_v1(&packet);
        if !attempt.is_sent() {
            break attempt;
        }
    };

    assert!(native.is_nonconsuming());
    assert!(native.failure().is_some());
    // These local bookend values exercise only the private wrapper predicate.
    // They construct no authenticated Session, Native original or effect grant.
    let mut returned = StorageResponseSendAttemptV1 {
        before: Ok(()), native: Some(native), after: Ok(()),
    };
    assert!(!returned.refuses_terminal_progress_v1());
    assert!(returned.failure().is_some());
    assert!(returned.take_native_sent_v1().is_none());

    returned.after = Err(BrokerSessionSecurityError::Currentness);
    assert!(returned.refuses_terminal_progress_v1());
    assert!(returned.native.is_some());
}
