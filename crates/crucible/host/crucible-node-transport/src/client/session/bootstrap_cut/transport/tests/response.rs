//! Exercises retained raw receipt and SDK settlement under the same Hello cut.

use super::*;

#[test]
fn retained_raw_response_uses_the_published_original_cut_and_separate_literal_bank() {
    use std::io::Write;
    let (_lease, mut session, mut peer) = scope();
    let sealed = seal(&mut session);
    publish(&mut session, &mut peer, &sealed);
    let value = response(&sealed);
    let body = serde_json::to_vec_pretty(&value).unwrap();
    peer.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    peer.write_all(&body).unwrap();
    let row = Connection::<DeadlineStream>::original_bootstrap_raw_response_construction_data(
        65536,
        usize::MAX,
    )
    .unwrap();
    let mut output = None;

    session
        .receive_original_bootstrap_response_into_data(
            &sealed.original,
            sealed.cut,
            &row,
            usize::MAX,
            &mut output,
        )
        .unwrap();

    let raw = output.as_ref().unwrap();
    let history = raw.borrowed_history_data().unwrap();
    assert!(history.complete && history.preflighted && history.parsed && !history.failed);
    assert_eq!(history.body, body);
    assert_eq!(history.value, Some(&value));
    assert_eq!(session.sequence.get(), 3);
    assert_eq!(session.deadline.original_cut(), sealed.cut);
    session
        .authenticate_original_bootstrap_effect_cut_data(sealed.cut, 3)
        .unwrap();
    let pointer = history.body.as_ptr();
    assert!(
        session
            .receive_original_bootstrap_response_into_data(
                &sealed.original,
                sealed.cut,
                &row,
                usize::MAX,
                &mut output
            )
            .is_err()
    );
    assert_eq!(
        output
            .as_ref()
            .unwrap()
            .borrowed_history_data()
            .unwrap()
            .body
            .as_ptr(),
        pointer
    );
}

#[test]
fn renewed_cut_before_retained_raw_receipt_preserves_sdk_and_the_unread_bank() {
    let (_lease, mut session, mut peer) = scope();
    let sealed = seal(&mut session);
    publish(&mut session, &mut peer, &sealed);
    let before = session
        .connection
        .original_bootstrap_model_registered_state_data(sealed.slot.unwrap());
    let storage = session.connection.original_bootstrap_model_storage_data();
    session.deadline.reset(Duration::from_secs(60)).unwrap();
    let row = Connection::<DeadlineStream>::original_bootstrap_raw_response_construction_data(
        65536,
        usize::MAX,
    )
    .unwrap();
    let mut output = None;

    assert!(
        session
            .receive_original_bootstrap_response_into_data(
                &sealed.original,
                sealed.cut,
                &row,
                usize::MAX,
                &mut output
            )
            .is_err()
    );

    assert!(output.is_none());
    assert_eq!(session.sequence.get(), 3);
    assert_eq!(
        session
            .connection
            .original_bootstrap_model_registered_state_data(sealed.slot.unwrap()),
        before
    );
    assert_eq!(
        session.connection.original_bootstrap_model_storage_data(),
        storage
    );
}

#[test]
fn settled_sdk_guard_preserves_actual_moved_request_and_raw_banks_after_clock_renewal() {
    use std::io::Write;
    let (_lease, mut session, mut peer) = scope();
    let sealed = seal(&mut session);
    publish(&mut session, &mut peer, &sealed);
    let body = serde_json::to_vec(&response(&sealed)).unwrap();
    peer.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    peer.write_all(&body).unwrap();
    let row = Connection::<DeadlineStream>::original_bootstrap_raw_response_construction_data(
        65536,
        usize::MAX,
    )
    .unwrap();
    let mut raw = None;
    session
        .receive_original_bootstrap_response_into_data(
            &sealed.original,
            sealed.cut,
            &row,
            usize::MAX,
            &mut raw,
        )
        .unwrap();
    let raw = raw.as_ref().unwrap();
    let mut decoded = None;
    let mut moved = None;
    session
        .decode_original_bootstrap_raw_into_data(
            &sealed.original,
            sealed.cut,
            raw.frame.as_ref().unwrap(),
            &native_import18_bootstrap_response_decode_quote_data(usize::MAX).unwrap(),
            usize::MAX,
            (&mut decoded, &mut moved),
        )
        .unwrap();
    let decoded = decoded.as_ref().unwrap();
    let moved = moved.as_ref().unwrap();
    session
        .authenticate_original_bootstrap_sdk_settlement_data(
            &sealed.original,
            sealed.cut,
            raw,
            moved,
            decoded,
        )
        .unwrap();
    let pointer = moved.request_id.0.as_ref().unwrap().as_str().as_ptr();
    let raw_pointer = raw.borrowed_history_data().unwrap().body.as_ptr();

    session.deadline.reset(Duration::from_secs(60)).unwrap();

    assert!(
        session
            .authenticate_original_bootstrap_sdk_settlement_data(
                &sealed.original,
                sealed.cut,
                raw,
                moved,
                decoded
            )
            .is_err()
    );
    assert_eq!(session.sequence.get(), 3);
    assert_eq!(
        moved.request_id.0.as_ref().unwrap().as_str().as_ptr(),
        pointer
    );
    assert_eq!(
        raw.borrowed_history_data().unwrap().body.as_ptr(),
        raw_pointer
    );
    assert!(decoded.borrowed_history_data().decoded);
}
