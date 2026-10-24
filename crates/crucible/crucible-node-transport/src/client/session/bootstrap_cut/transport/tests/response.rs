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

fn receive_and_settle(
    session: &mut ClientSession,
    peer: &mut UnixStream,
    sealed: &Sealed,
) -> (
    PacketNativeImport18BootstrapRawResponseData,
    PacketNativeImport18BootstrapResponseDecodeData,
    Envelope,
) {
    use std::io::Write;

    let body = serde_json::to_vec(&response(sealed)).unwrap();
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
    let raw = raw.unwrap();
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
    (raw, decoded.unwrap(), moved.unwrap())
}

#[test]
fn settled_receipt_loan_borrows_actual_outputs_without_repeating_read_decode_or_sdk_move() {
    let (_lease, mut session, mut peer) = scope();
    let sealed = seal(&mut session);
    publish(&mut session, &mut peer, &sealed);
    let (raw, decoded, moved) = receive_and_settle(&mut session, &mut peer, &sealed);
    let storage = session.connection.original_bootstrap_model_storage_data();
    let cut = session.deadline.original_cut();
    let calls = std::cell::Cell::new(0);

    let result = session
        .with_original_bootstrap_settled_data(
            &sealed.original,
            sealed.cut,
            &raw,
            &moved,
            &decoded,
            |original, response| {
                calls.set(calls.get() + 1);
                assert!(std::ptr::eq(original, &moved));
                assert!(std::ptr::eq(response, &decoded));
                let history = response.borrowed_history_data();
                assert!(history.decoded && !history.failed);
                assert!(history.request.is_some() && history.receipt.is_some());
                Ok(history.envelope.unwrap().sequence)
            },
        )
        .unwrap();

    assert_eq!(result, U64::new(2));
    assert_eq!(calls.get(), 1);
    assert_eq!(session.sequence.get(), 3);
    assert_eq!(session.deadline.original_cut(), cut);
    assert_eq!(
        session.connection.original_bootstrap_model_storage_data(),
        storage
    );
    assert_eq!(moved, sealed.original);
}

#[test]
fn settled_receipt_loan_keeps_callback_prefix_and_first_failure_after_clock_or_lease_changes() {
    for revoke in [false, true] {
        for callback_failed in [false, true] {
            let (mut lease, mut session, mut peer) = scope();
            let sealed = seal(&mut session);
            publish(&mut session, &mut peer, &sealed);
            let (raw, decoded, moved) = receive_and_settle(&mut session, &mut peer, &sealed);
            let storage = session.connection.original_bootstrap_model_storage_data();
            let moved_pointer = moved.request_id.0.as_ref().unwrap().as_str().as_ptr();
            let raw_pointer = raw.borrowed_history_data().unwrap().body.as_ptr();
            let retained_prefix = std::cell::Cell::new(None);
            let calls = std::cell::Cell::new(0);

            let result = session.with_original_bootstrap_settled_data(
                &sealed.original,
                sealed.cut,
                &raw,
                &moved,
                &decoded,
                |original, response| {
                    calls.set(calls.get() + 1);
                    retained_prefix.set(Some((
                        original.sequence,
                        response.borrowed_history_data().decoded,
                    )));
                    if revoke {
                        lease.contain();
                    } else {
                        session.deadline.reset(Duration::from_secs(60)).unwrap();
                    }
                    if callback_failed {
                        Err(ProviderError::Correlation(
                            "retained Bootstrap receipt verifier failure",
                        ))
                    } else {
                        Ok(true)
                    }
                },
            );

            assert!(result.is_err());
            if callback_failed {
                assert!(matches!(
                    result,
                    Err(ProviderError::Correlation(
                        "retained Bootstrap receipt verifier failure"
                    ))
                ));
            }
            assert_eq!(calls.get(), 1);
            assert_eq!(retained_prefix.get(), Some((U64::new(2), true)));
            assert_eq!(
                moved.request_id.0.as_ref().unwrap().as_str().as_ptr(),
                moved_pointer
            );
            assert_eq!(
                raw.borrowed_history_data().unwrap().body.as_ptr(),
                raw_pointer
            );
            assert_eq!(session.sequence.get(), 3);
            assert_eq!(
                session.connection.original_bootstrap_model_storage_data(),
                storage
            );
            assert!(decoded.borrowed_history_data().decoded);

            assert!(
                session
                    .with_original_bootstrap_settled_data(
                        &sealed.original,
                        sealed.cut,
                        &raw,
                        &moved,
                        &decoded,
                        |_, _| {
                            calls.set(calls.get() + 1);
                            Ok(())
                        },
                    )
                    .is_err()
            );
            assert_eq!(calls.get(), 1);
        }
    }
}

#[test]
fn settled_receipt_callback_failure_keeps_unchanged_terminal_custody_and_outputs() {
    let (_lease, mut session, mut peer) = scope();
    let sealed = seal(&mut session);
    publish(&mut session, &mut peer, &sealed);
    let (raw, decoded, moved) = receive_and_settle(&mut session, &mut peer, &sealed);
    let prefix = std::cell::Cell::new(None);
    let storage = session.connection.original_bootstrap_model_storage_data();

    let result: Result<(), ProviderError> = session.with_original_bootstrap_settled_data(
        &sealed.original,
        sealed.cut,
        &raw,
        &moved,
        &decoded,
        |request, response| {
            prefix.set(Some((
                request.sequence,
                response.borrowed_history_data().decoded,
            )));
            Err(ProviderError::Correlation(
                "retained Bootstrap receipt verifier failure",
            ))
        },
    );

    assert!(matches!(
        result,
        Err(ProviderError::Correlation(
            "retained Bootstrap receipt verifier failure"
        ))
    ));
    assert_eq!(prefix.get(), Some((U64::new(2), true)));
    session
        .authenticate_original_bootstrap_sdk_settlement_data(
            &sealed.original,
            sealed.cut,
            &raw,
            &moved,
            &decoded,
        )
        .unwrap();
    assert_eq!(
        session.connection.original_bootstrap_model_storage_data(),
        storage
    );
    assert_eq!(session.sequence.get(), 3);
}
